//! Hermetic integration tests for M5 exit rights and re-basing (control format
//! 4).
//!
//! Every node binds an IPv4-loopback endpoint with relays disabled; every
//! neighbor address is an explicit hint in a shared [`MemoryLookup`], so no
//! external address lookup is involved.
//!
//! Re-base *notices* are applied in-process via [`ControlNode::receive_at`] so
//! the test controls exactly which children receive them (an "offline" child is
//! one whose notice is withheld). The parts that must exercise the real
//! transport — the old parent's `NotNeighbor` rejection, the retry sweep, the
//! startup `RebasePull`, internal/external message routing, and the re-attach
//! join — go over the bound endpoints.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cawala_control::{
    CONTROL_REQUEST_TTL_SECS, ChildKind, ControlReply, ControlRequest, DetachChild, JoinApproval,
    JoinRequest, MoveChild, NodeId, OperatorSecretKey, RebaseNotice, RejectCode, SignedControl,
};
use cawala_ledger::{LedgerPubKey, LedgerSecretKey, PeerKeys, PeerRegistry, PeerRole};
use cawala_msg::{AckStatus, Envelope, MSG_LEDGER_V1, RejectReason};
use cawala_node::AdminStore;
use cawala_node::control::{
    ControlNode, pull_rebase_from_parent, spawn_control_node_live_on, sweep_pending_rebase,
};
use cawala_node::control_store::ControlStore;
use cawala_node::msg::{MsgConfig, NeighborSource, RoutableSnapshot, build_envelope, send_envelope};
use cawala_node::record::{NodeRecord, RecordStore};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

/// Per-exchange deadline for loopback tests.
fn timeout() -> Duration {
    Duration::from_secs(3)
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A process-unique request nonce, so distinct requests are never conflated by
/// the engine's replay guard.
fn fresh_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

fn node(id: &str) -> NodeId {
    NodeId::from(id)
}

/// The operator key derived from an iroh node key (node id == operator key).
fn operator(secret: &SecretKey) -> OperatorSecretKey {
    OperatorSecretKey::from_bytes(secret.to_bytes())
}

fn ledger(seed: u8) -> LedgerPubKey {
    LedgerSecretKey::from_bytes([seed; 32]).public()
}

fn node_row(id: &str, op: &OperatorSecretKey, ledger_seed: u8) -> PeerKeys {
    PeerKeys {
        node_id: node(id),
        operator: op.public(),
        ledger: Some(ledger(ledger_seed)),
        role: PeerRole::Node,
    }
}

/// Sign `request` as `origin` at the current wall clock.
fn authorize(origin: &str, op: &OperatorSecretKey, request: ControlRequest) -> SignedControl {
    SignedControl::authorize(
        node(origin),
        op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        request,
    )
    .expect("sign control request")
}

/// An arbitrary authenticated-remote id; `receive_at` ignores it.
fn any_remote() -> EndpointId {
    EndpointId::from(SecretKey::generate().public())
}

/// Bind a hermetic loopback endpoint with relays disabled and an optional
/// shared address lookup.
async fn bind(secret: &SecretKey, lookup: Option<MemoryLookup>) -> Endpoint {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret.clone())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind address");
    if let Some(lookup) = lookup {
        builder = builder.address_lookup(lookup);
    }
    builder.bind().await.expect("bind endpoint")
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A declarative node description for [`build`].
struct NodeDef {
    key: SecretKey,
    address: Option<String>,
    parent: Option<(String, u8)>,
    children: Vec<(String, ChildKind, u8)>,
    peers: Vec<PeerKeys>,
}

impl NodeDef {
    fn operator(&self) -> OperatorSecretKey {
        operator(&self.key)
    }
}

/// A running node: its control engine, live routing view, endpoint, and the
/// envelopes its drain loop observed.
struct TestNode {
    _dir: tempfile::TempDir,
    endpoint: Endpoint,
    addr: EndpointAddr,
    control: Arc<Mutex<ControlNode>>,
    obs: mpsc::UnboundedReceiver<Envelope>,
    _router: Router,
    _drain: tokio::task::JoinHandle<()>,
}

impl TestNode {
    /// Reload the on-disk routing snapshot with every peer's explicit hint.
    async fn live_snapshot(&self, addrs: &HashMap<String, EndpointAddr>) -> RoutableSnapshot {
        let record = self.control.lock().await.record().clone();
        snapshot_from_record(&record, addrs)
    }
}

/// Build one live routing snapshot from `record`, filling hints from `addrs`.
fn snapshot_from_record(
    record: &NodeRecord,
    addrs: &HashMap<String, EndpointAddr>,
) -> RoutableSnapshot {
    let mut snapshot = RoutableSnapshot::from_record(record).expect("derive routing snapshot");
    for (id, addr) in addrs {
        if let Ok(id) = id.parse::<EndpointId>() {
            snapshot.hints.insert(id.to_string(), addr.clone());
        }
    }
    snapshot
}

/// Bind every node, persist its record, spawn control + msg, and drain locally
/// delivered envelopes into a per-node observation channel.
async fn build(defs: Vec<NodeDef>) -> (HashMap<String, TestNode>, HashMap<String, EndpointAddr>) {
    let lookup = MemoryLookup::new();
    let mut endpoints = Vec::with_capacity(defs.len());
    let mut addrs: HashMap<String, EndpointAddr> = HashMap::new();
    for def in &defs {
        let id = def.key.public().to_string();
        let endpoint = bind(&def.key, Some(lookup.clone())).await;
        lookup.add_endpoint_info(endpoint.addr());
        addrs.insert(id, endpoint.addr());
        endpoints.push(endpoint);
    }

    let mut nodes = HashMap::new();
    for (def, endpoint) in defs.into_iter().zip(endpoints) {
        let id = def.key.public().to_string();
        let operator = def.operator();
        let dir = tempfile::tempdir().expect("tempdir");
        let mut record = RecordStore::open(dir.path(), &id).expect("open record");
        if let Some((parent, slot)) = &def.parent {
            record.set_parent(parent, *slot).expect("set parent");
        }
        if let Some(address) = &def.address {
            record
                .set_address(address.parse().expect("valid address"))
                .expect("set address");
        }
        for (child, kind, slot) in &def.children {
            record
                .attach_child(child, *kind, Some(*slot), u64::from(*slot))
                .expect("attach child");
        }
        record.save().expect("save record");

        let mut registry = PeerRegistry::new();
        for row in def.peers {
            registry.insert(row).expect("insert peer");
        }
        let store = ControlStore::open(dir.path()).expect("open control store");
        let engine = ControlNode::new(
            dir.path().to_path_buf(),
            &id,
            operator.clone(),
            record,
            registry,
            store,
            AdminStore::empty(),
        );
        let control = Arc::new(Mutex::new(engine));

        let source =
            NeighborSource::live(dir.path(), &id, addrs.clone()).expect("live neighbor source");
        let (router, mut rx) = spawn_control_node_live_on(
            endpoint.clone(),
            source,
            MsgConfig::default(),
            Arc::clone(&control),
        );

        let (obs_tx, obs_rx) = mpsc::unbounded_channel();
        let drain = tokio::spawn(async move {
            while let Some(env) = rx.recv().await {
                let _ = obs_tx.send(env);
            }
        });

        let addr = endpoint.addr();
        nodes.insert(
            id,
            TestNode {
                _dir: dir,
                endpoint,
                addr,
                control,
                obs: obs_rx,
                _router: router,
                _drain: drain,
            },
        );
    }
    (nodes, addrs)
}

/// Deliver an already-signed frame to `target`'s engine in-process and return
/// its reply. Used for notices whose transport delivery the test controls.
async fn deliver(target: &Arc<Mutex<ControlNode>>, signed: &SignedControl) -> ControlReply {
    target
        .lock()
        .await
        .receive_at(any_remote(), signed.clone(), now_unix_seconds())
        .await
}

/// Recursively apply every queued outbound notice starting at `source`.
///
/// Each notice is handed to its target engine (which may queue notices of its
/// own), so a re-base propagates down the whole subtree synchronously.
async fn propagate_from(nodes: &HashMap<String, TestNode>, source: &str) {
    let mut queue = vec![source.to_string()];
    while let Some(id) = queue.pop() {
        let outbound = {
            let mut engine = nodes[&id].control.lock().await;
            engine.take_outbound()
        };
        for item in outbound {
            let target = nodes
                .get(item.target.as_str())
                .unwrap_or_else(|| panic!("no node '{}' to receive a notice", item.target));
            assert_eq!(
                deliver(&target.control, &item.signed).await,
                ControlReply::Accepted,
                "delivering {:?} to {}",
                item.kind,
                item.target
            );
            queue.push(item.target.to_string());
        }
    }
}

/// Send `signed` to `target` over the real direct-control transport.
async fn send_direct(
    source: &Endpoint,
    target: &EndpointAddr,
    signed: &SignedControl,
) -> ControlReply {
    ControlNode::send_direct_addr(source, target.clone(), signed, timeout())
        .await
        .expect("control exchange")
}

/// Wait until `node`'s record has `parent`/`address`.
async fn wait_record(
    control: &Arc<Mutex<ControlNode>>,
    parent: Option<&str>,
    address: &str,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let engine = control.lock().await;
            let record = engine.record();
            let parent_ok = record.parent.as_ref().map(|p| p.parent_id.as_str()) == parent;
            let address_ok =
                record.address.as_ref().map(|a| a.to_string()).as_deref() == Some(address);
            if parent_ok && address_ok {
                return;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "record never reached parent={parent:?} address={address}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// ---------------------------------------------------------------------------
// World: P(0) { A(0.1) { C1(0.1.0) { D(0.1.0.0) { E } }, C2(0.1.1) }, B(0.2) }
// ---------------------------------------------------------------------------

struct World {
    p_key: SecretKey,
    a_key: SecretKey,
    c1_key: SecretKey,
    c2_key: SecretKey,
    d_key: SecretKey,
    e_key: SecretKey,
    b_key: SecretKey,
    p_id: String,
    a_id: String,
    c1_id: String,
    c2_id: String,
    d_id: String,
    e_id: String,
    b_id: String,
    p_op: OperatorSecretKey,
    a_op: OperatorSecretKey,
    c1_op: OperatorSecretKey,
    c2_op: OperatorSecretKey,
    d_op: OperatorSecretKey,
    e_op: OperatorSecretKey,
    b_op: OperatorSecretKey,
}

impl World {
    fn new() -> Self {
        let p_key = SecretKey::generate();
        let a_key = SecretKey::generate();
        let c1_key = SecretKey::generate();
        let c2_key = SecretKey::generate();
        let d_key = SecretKey::generate();
        let e_key = SecretKey::generate();
        let b_key = SecretKey::generate();
        let p_id = p_key.public().to_string();
        let a_id = a_key.public().to_string();
        let c1_id = c1_key.public().to_string();
        let c2_id = c2_key.public().to_string();
        let d_id = d_key.public().to_string();
        let e_id = e_key.public().to_string();
        let b_id = b_key.public().to_string();
        World {
            p_op: operator(&p_key),
            a_op: operator(&a_key),
            c1_op: operator(&c1_key),
            c2_op: operator(&c2_key),
            d_op: operator(&d_key),
            e_op: operator(&e_key),
            b_op: operator(&b_key),
            p_key,
            a_key,
            c1_key,
            c2_key,
            d_key,
            e_key,
            b_key,
            p_id,
            a_id,
            c1_id,
            c2_id,
            d_id,
            e_id,
            b_id,
        }
    }

    fn defs(&self) -> Vec<NodeDef> {
        vec![
            NodeDef {
                key: self.p_key.clone(),
                address: Some("0".to_string()),
                parent: None,
                children: vec![
                    (self.a_id.clone(), ChildKind::Node, 1),
                    (self.b_id.clone(), ChildKind::Node, 2),
                ],
                peers: vec![
                    node_row(&self.a_id, &self.a_op, 1),
                    node_row(&self.b_id, &self.b_op, 2),
                ],
            },
            NodeDef {
                key: self.a_key.clone(),
                address: Some("0.1".to_string()),
                parent: Some((self.p_id.clone(), 1)),
                children: vec![
                    (self.c1_id.clone(), ChildKind::Node, 0),
                    (self.c2_id.clone(), ChildKind::Node, 1),
                ],
                peers: vec![
                    node_row(&self.p_id, &self.p_op, 0),
                    node_row(&self.c1_id, &self.c1_op, 3),
                    node_row(&self.c2_id, &self.c2_op, 4),
                ],
            },
            NodeDef {
                key: self.c1_key.clone(),
                address: Some("0.1.0".to_string()),
                parent: Some((self.a_id.clone(), 0)),
                children: vec![(self.d_id.clone(), ChildKind::Node, 0)],
                peers: vec![
                    node_row(&self.a_id, &self.a_op, 1),
                    node_row(&self.d_id, &self.d_op, 5),
                ],
            },
            NodeDef {
                key: self.c2_key.clone(),
                address: Some("0.1.1".to_string()),
                parent: Some((self.a_id.clone(), 1)),
                children: vec![],
                peers: vec![node_row(&self.a_id, &self.a_op, 1)],
            },
            NodeDef {
                key: self.d_key.clone(),
                address: Some("0.1.0.0".to_string()),
                parent: Some((self.c1_id.clone(), 0)),
                children: vec![(self.e_id.clone(), ChildKind::Node, 0)],
                peers: vec![
                    node_row(&self.c1_id, &self.c1_op, 3),
                    node_row(&self.e_id, &self.e_op, 6),
                ],
            },
            NodeDef {
                key: self.e_key.clone(),
                address: Some("0.1.0.0.0".to_string()),
                parent: Some((self.d_id.clone(), 0)),
                children: vec![],
                peers: vec![node_row(&self.d_id, &self.d_op, 5)],
            },
            NodeDef {
                key: self.b_key.clone(),
                address: Some("0.2".to_string()),
                parent: Some((self.p_id.clone(), 2)),
                children: vec![],
                peers: vec![node_row(&self.p_id, &self.p_op, 0)],
            },
        ]
    }
}

/// `A` exits from `P` (A is re-rooted at `0` and its children are re-based),
/// without delivering any notice to `D`.
///
/// Returns the world plus the now-root `A`.
struct ExitedWorld {
    world: World,
    nodes: HashMap<String, TestNode>,
    addrs: HashMap<String, EndpointAddr>,
}

/// Build the world, have `A` exit from `P`, and re-base `A`'s direct children
/// (`C1`, `C2`) but deliberately withhold the notice from `D`.
async fn exited_world() -> ExitedWorld {
    let world = World::new();
    let (nodes, addrs) = build(world.defs()).await;

    // A tells P to drop the link.
    let now = now_unix_seconds();
    let exit = {
        let engine = nodes[&world.a_id].control.lock().await;
        engine.sign_exit_request(now).expect("sign exit")
    };
    assert_eq!(
        deliver(&nodes[&world.p_id].control, &exit).await,
        ControlReply::Accepted
    );
    // A applies locally: root `0`, and a Rebase queued for each child.
    nodes[&world.a_id]
        .control
        .lock()
        .await
        .apply_exit(now)
        .expect("apply exit");
    assert!(
        !nodes[&world.p_id]
            .control
            .lock()
            .await
            .record()
            .children
            .iter()
            .any(|c| c.child_id == world.a_id),
        "the old parent must have dropped A"
    );
    // Deliver A's notices to C1 and C2 only; D's is withheld (it is the
    // "offline descendant").
    let outbound = { nodes[&world.a_id].control.lock().await.take_outbound() };
    assert_eq!(outbound.len(), 2, "one Rebase per direct child");
    for item in outbound {
        assert_ne!(item.target.as_str(), world.d_id, "D must not be reached");
        let target = nodes.get(item.target.as_str()).expect("child node");
        assert_eq!(
            deliver(&target.control, &item.signed).await,
            ControlReply::Accepted
        );
    }
    // C1 was re-based; discard the notice it queued for D.
    let _ = nodes[&world.c1_id].control.lock().await.take_outbound();

    wait_record(&nodes[&world.a_id].control, None, "0").await;
    wait_record(&nodes[&world.c1_id].control, Some(&world.a_id), "0.0").await;
    wait_record(&nodes[&world.c2_id].control, Some(&world.a_id), "0.1").await;
    wait_record(&nodes[&world.d_id].control, Some(&world.c1_id), "0.1.0.0").await;

    ExitedWorld { world, nodes, addrs }
}

// ---------------------------------------------------------------------------
// (1) Childless exit + the old parent's envelope is refused `NotNeighbor`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn childless_exit_roots_node_and_old_parent_is_not_a_neighbor() {
    let world = World::new();
    let (mut nodes, addrs) = build(world.defs()).await;

    // Snapshot C1 *before* D exits, so it still lists D as a child and can
    // forward an envelope straight to it.
    let stale_c1 = {
        let record = nodes[&world.c1_id].control.lock().await.record().clone();
        snapshot_from_record(&record, &addrs)
    };

    let now = now_unix_seconds();
    // D exits from C1.
    let exit = {
        let engine = nodes[&world.d_id].control.lock().await;
        engine.sign_exit_request(now).expect("sign exit")
    };
    assert_eq!(
        deliver(&nodes[&world.c1_id].control, &exit).await,
        ControlReply::Accepted
    );
    nodes[&world.d_id]
        .control
        .lock()
        .await
        .apply_exit(now)
        .expect("apply exit");

    wait_record(&nodes[&world.d_id].control, None, "0").await;
    assert!(
        !nodes[&world.c1_id]
            .control
            .lock()
            .await
            .record()
            .children
            .iter()
            .any(|c| c.child_id == world.d_id),
        "the old parent must have dropped D"
    );

    // C1 (with the stale view) forwards to D's old address; D's live view no
    // longer has C1 as its parent, so the last hop is refused `NotNeighbor`.
    let env = build_envelope(
        &stale_c1.routable.this,
        "0.1.0.0".parse().expect("old address"),
        MSG_LEDGER_V1,
        b"after-exit".to_vec(),
        8,
    )
    .expect("build envelope");
    let ack = send_envelope(&nodes[&world.c1_id].endpoint, &stale_c1, &env, timeout())
        .await
        .expect("send envelope");
    assert_eq!(ack.status, AckStatus::Rejected(RejectReason::NotNeighbor));
    assert!(
        nodes
            .get_mut(&world.d_id)
            .expect("d")
            .obs
            .try_recv()
            .is_err(),
        "a NotNeighbor envelope must not be delivered"
    );
}

// ---------------------------------------------------------------------------
// (2) Subtree exit: internal routing works, an external destination drops
// ---------------------------------------------------------------------------

#[tokio::test]
async fn subtree_exit_rebases_whole_tree_and_routes_internally() {
    let exited = exited_world().await;
    let world = &exited.world;
    let mut nodes = exited.nodes;
    let addrs = exited.addrs;

    // `D` is re-based by `C1` (C1's notice was withheld by `exited_world`), so
    // deliver the equivalent notice now and let D recurse to `E`.
    let notice = authorize(
        &world.c1_id,
        &world.c1_op,
        ControlRequest::Rebase(RebaseNotice {
            node: node(&world.d_id),
            parent_address: "0.0".parse().unwrap(),
            address: "0.0.0".parse().unwrap(),
            generation: 1,
        }),
    );
    assert_eq!(
        deliver(&nodes[&world.d_id].control, &notice).await,
        ControlReply::Accepted
    );
    propagate_from(&nodes, &world.d_id).await;
    // Every record in the independent network is now root-`0`-prefixed.
    for (id, address) in [
        (&world.a_id, "0"),
        (&world.c1_id, "0.0"),
        (&world.c2_id, "0.1"),
        (&world.d_id, "0.0.0"),
        (&world.e_id, "0.0.0.0"),
    ] {
        let engine = nodes[id].control.lock().await;
        assert_eq!(
            engine.record().address.as_ref().map(|a| a.to_string()).as_deref(),
            Some(address),
            "record {id}"
        );
    }

    // Internal routing: C1 -> C2 ascends to the new root A(0) and descends.
    let c1_snapshot = nodes[&world.c1_id].live_snapshot(&addrs).await;
    let env = build_envelope(
        &c1_snapshot.routable.this,
        "0.1".parse().unwrap(),
        MSG_LEDGER_V1,
        b"sibling".to_vec(),
        8,
    )
    .unwrap();
    let ack = send_envelope(&nodes[&world.c1_id].endpoint, &c1_snapshot, &env, timeout())
        .await
        .expect("send envelope");
    assert_eq!(ack.status, AckStatus::Delivered);
    let got = nodes
        .get_mut(&world.c2_id)
        .expect("c2")
        .obs
        .recv()
        .await
        .expect("c2 delivered");
    assert_eq!(got.payload, b"sibling");

    // An external destination (outside the independent network) is dropped by
    // the new root itself. Under the addressing law a re-based root is `0`, the
    // ancestor of every valid address, so the concrete drop is `NoSuchChild`;
    // `RootCannotRoute` is only reachable for a parentless node that retained a
    // non-root address, a shape the rebase law forbids.
    let a_snapshot = nodes[&world.a_id].live_snapshot(&addrs).await;
    let external = build_envelope(
        &a_snapshot.routable.this,
        "0.7".parse().unwrap(),
        MSG_LEDGER_V1,
        b"external".to_vec(),
        8,
    )
    .unwrap();
    let err = send_envelope(&nodes[&world.a_id].endpoint, &a_snapshot, &external, timeout())
        .await
        .expect_err("external destination must drop");
    assert!(
        matches!(
            err,
            cawala_node::msg::MsgSendError::NoRoute(cawala_msg::RouteError::NoSuchChild { .. })
        ),
        "unexpected external drop: {err}"
    );

    // The routing primitive's `RootCannotRoute` drop remains reachable only for
    // the superseded "retained-address island" shape (parentless, non-root).
    // Pin it here so the drop reason is covered even though the rebase law no
    // longer produces that shape.
    let detached = cawala_msg::Routable {
        this: cawala_msg::PeerRef {
            addr: "0.1".parse().unwrap(),
            node: "detached".to_string(),
        },
        parent: None,
        children: vec![],
    };
    assert_eq!(
        cawala_msg::route(&detached, &"0.7".parse().unwrap()),
        cawala_msg::RouteDecision::Drop(cawala_msg::RouteError::RootCannotRoute {
            dst: "0.7".parse().unwrap()
        })
    );
}

// ---------------------------------------------------------------------------
// (3) Offline descendant: it pulls the new prefix and re-bases its children
// ---------------------------------------------------------------------------

#[tokio::test]
async fn offline_descendant_pulls_new_prefix_and_propagates() {
    let exited = exited_world().await;
    let world = &exited.world;
    let nodes = exited.nodes;

    // D (and E) missed the re-base and still hold their old addresses.
    assert_eq!(
        nodes[&world.d_id]
            .control
            .lock()
            .await
            .record()
            .address
            .as_ref()
            .map(|a| a.to_string())
            .as_deref(),
        Some("0.1.0.0")
    );

    // D comes online and pulls: it verifies C1's snapshot, applies `0.0.0`, and
    // re-bases E (`0.0.0.0`).
    let applied = pull_rebase_from_parent(
        &nodes[&world.d_id].endpoint,
        &nodes[&world.d_id].control,
        timeout(),
        now_unix_seconds(),
    )
    .await
    .expect("pull");
    assert!(applied, "the pull must apply a new address");
    wait_record(&nodes[&world.d_id].control, Some(&world.c1_id), "0.0.0").await;
    wait_record(&nodes[&world.e_id].control, Some(&world.d_id), "0.0.0.0").await;
}

// ---------------------------------------------------------------------------
// (4) Partial rename retry: a missed notice is retried; a duplicate is a noop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missed_notice_is_retried_and_duplicate_is_idempotent() {
    let exited = exited_world().await;
    let world = &exited.world;
    let nodes = exited.nodes;

    // C1 re-based and queued a notice for D, but its delivery failed: capture it
    // as pending (exactly what `deliver_outbound_decisions` + the handler do).
    let stale_notice = {
        // Re-sign the notice C1 would have sent (withheld by `exited_world`).
        authorize(
            &world.c1_id,
            &world.c1_op,
            ControlRequest::Rebase(RebaseNotice {
                node: node(&world.d_id),
                parent_address: "0.0".parse().unwrap(),
                address: "0.0.0".parse().unwrap(),
                generation: 1,
            }),
        )
    };
    {
        let mut engine = nodes[&world.c1_id].control.lock().await;
        engine.requeue_pending_rebase(vec![cawala_node::OutboundControl {
            target: node(&world.d_id),
            signed: stale_notice.clone(),
            kind: cawala_node::OutboundKind::Rebase,
        }]);
    }

    // The bounded sweep retries over the real transport and D applies.
    sweep_pending_rebase(
        &nodes[&world.c1_id].endpoint,
        &nodes[&world.c1_id].control,
    )
    .await;
    wait_record(&nodes[&world.d_id].control, Some(&world.c1_id), "0.0.0").await;
    assert!(
        nodes[&world.c1_id]
            .control
            .lock()
            .await
            .take_pending_rebase()
            .is_empty(),
        "a delivered notice is dropped from the pending queue"
    );

    // A duplicate notice (same address, fresh frame) is an idempotent
    // `Accepted` and does not re-propagate.
    let duplicate = authorize(
        &world.c1_id,
        &world.c1_op,
        ControlRequest::Rebase(RebaseNotice {
            node: node(&world.d_id),
            parent_address: "0.0".parse().unwrap(),
            address: "0.0.0".parse().unwrap(),
            generation: 1,
        }),
    );
    assert_eq!(
        deliver(&nodes[&world.d_id].control, &duplicate).await,
        ControlReply::Accepted
    );
    assert!(
        nodes[&world.d_id]
            .control
            .lock()
            .await
            .take_outbound()
            .is_empty(),
        "an idempotent re-apply must not re-propagate"
    );
}

// ---------------------------------------------------------------------------
// (5) Parent-initiated detach of a non-leaf child re-bases its subtree
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parent_detach_of_non_leaf_child_rebases_whole_subtree() {
    let world = World::new();
    let (nodes, _addrs) = build(world.defs()).await;

    // P (self-admin) detaches A, which has children of its own.
    let detach = authorize(
        &world.p_id,
        &world.p_op,
        ControlRequest::DetachChild(DetachChild {
            child: node(&world.a_id),
        }),
    );
    assert_eq!(
        deliver(&nodes[&world.p_id].control, &detach).await,
        ControlReply::Accepted
    );
    // P queued a DetachNotice; apply it (and recurse) in-process.
    propagate_from(&nodes, &world.p_id).await;

    wait_record(&nodes[&world.a_id].control, None, "0").await;
    wait_record(&nodes[&world.c1_id].control, Some(&world.a_id), "0.0").await;
    wait_record(&nodes[&world.c2_id].control, Some(&world.a_id), "0.1").await;
    wait_record(&nodes[&world.d_id].control, Some(&world.c1_id), "0.0.0").await;
    wait_record(&nodes[&world.e_id].control, Some(&world.d_id), "0.0.0.0").await;
    assert!(
        !nodes[&world.p_id]
            .control
            .lock()
            .await
            .record()
            .children
            .iter()
            .any(|c| c.child_id == world.a_id),
        "the parent dropped the detached child"
    );
}

// ---------------------------------------------------------------------------
// (6) Re-attach of a root-`0` leaf: join approval installs parent + address
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reattach_of_root_zero_leaf_installs_parent_and_address() {
    let world = World::new();
    let (nodes, _addrs) = build(world.defs()).await;
    let now = now_unix_seconds();

    // C2 exits and becomes an independent root `0`.
    let exit = {
        let engine = nodes[&world.c2_id].control.lock().await;
        engine.sign_exit_request(now).expect("sign exit")
    };
    assert_eq!(
        deliver(&nodes[&world.a_id].control, &exit).await,
        ControlReply::Accepted
    );
    nodes[&world.c2_id]
        .control
        .lock()
        .await
        .apply_exit(now)
        .expect("apply exit");
    wait_record(&nodes[&world.c2_id].control, None, "0").await;

    // C2 re-joins its **former** parent `A`. A's `Exit` handling retained C2's
    // peer row, so this exercises G2's identical-retained-row reconciliation:
    // the approval must succeed (not `DuplicateKey`) and install the parent +
    // new address.
    let join = JoinRequest {
        node: node(&world.c2_id),
        kind: ChildKind::Node,
        operator: world.c2_op.public(),
        ledger: Some(ledger(4)),
        desired_slot: Some(1),
        location_hint: None,
        nonce: fresh_nonce(),
        expiry: now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
    };
    nodes[&world.c2_id]
        .control
        .lock()
        .await
        .begin_outbound_join(join.clone(), node(&world.a_id), None)
        .expect("record outbound join");
    let signed_join = authorize(&world.c2_id, &world.c2_op, ControlRequest::Join(join));
    assert_eq!(
        send_direct(
            &nodes[&world.c2_id].endpoint,
            &nodes[&world.a_id].addr,
            &signed_join
        )
        .await,
        ControlReply::Pending
    );

    // A approves and sends the `JoinApproved` back over direct control.
    let approval: JoinApproval = {
        let mut engine = nodes[&world.a_id].control.lock().await;
        engine
            .approve_pending(&world.c2_id, Some(1), now, ledger(1))
            .expect("approve pending")
    };
    assert_eq!(approval.address.to_string(), "0.1.1");
    let signed_approval = authorize(
        &world.a_id,
        &world.a_op,
        ControlRequest::JoinApproved(approval),
    );
    assert_eq!(
        send_direct(
            &nodes[&world.a_id].endpoint,
            &nodes[&world.c2_id].addr,
            &signed_approval
        )
        .await,
        ControlReply::Accepted
    );

    wait_record(&nodes[&world.c2_id].control, Some(&world.a_id), "0.1.1").await;
}

// ---------------------------------------------------------------------------
// (G2) Stale-row re-join: the parent never processed the Exit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stale_row_rejoin_of_unprocessed_exit_succeeds() {
    let world = World::new();
    let (nodes, _addrs) = build(world.defs()).await;
    let now = now_unix_seconds();

    // C2 exits **locally only**: `A` never processes the `ExitRequest`, so its
    // record still lists C2 at slot 1 and it retains C2's peer row.
    nodes[&world.c2_id]
        .control
        .lock()
        .await
        .apply_exit(now)
        .expect("apply exit");
    wait_record(&nodes[&world.c2_id].control, None, "0").await;
    assert!(
        nodes[&world.a_id]
            .control
            .lock()
            .await
            .record()
            .children
            .iter()
            .any(|c| c.child_id == world.c2_id),
        "A must still list C2 (it never saw the exit)"
    );

    // C2 re-joins A asking for its own existing slot.
    let join = JoinRequest {
        node: node(&world.c2_id),
        kind: ChildKind::Node,
        operator: world.c2_op.public(),
        ledger: Some(ledger(4)),
        desired_slot: Some(1),
        location_hint: None,
        nonce: fresh_nonce(),
        expiry: now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
    };
    nodes[&world.c2_id]
        .control
        .lock()
        .await
        .begin_outbound_join(join.clone(), node(&world.a_id), None)
        .expect("record outbound join");
    let signed_join = authorize(&world.c2_id, &world.c2_op, ControlRequest::Join(join));
    assert_eq!(
        send_direct(
            &nodes[&world.c2_id].endpoint,
            &nodes[&world.a_id].addr,
            &signed_join
        )
        .await,
        ControlReply::Pending,
        "A must queue the re-join rather than refuse its own slot"
    );

    // A re-approves idempotently: C2 keeps its slot/address.
    let approval: JoinApproval = {
        let mut engine = nodes[&world.a_id].control.lock().await;
        engine
            .approve_pending(&world.c2_id, Some(1), now, ledger(1))
            .expect("idempotent re-approval")
    };
    assert_eq!(approval.slot, 1);
    assert_eq!(approval.address.to_string(), "0.1.1");
    let signed_approval = authorize(
        &world.a_id,
        &world.a_op,
        ControlRequest::JoinApproved(approval),
    );
    assert_eq!(
        send_direct(
            &nodes[&world.a_id].endpoint,
            &nodes[&world.c2_id].addr,
            &signed_approval
        )
        .await,
        ControlReply::Accepted
    );

    wait_record(&nodes[&world.c2_id].control, Some(&world.a_id), "0.1.1").await;
    assert_eq!(
        nodes[&world.a_id]
            .control
            .lock()
            .await
            .record()
            .children
            .len(),
        2,
        "no duplicate child entry"
    );
}

// ---------------------------------------------------------------------------
// (E) Stale Rebase from a former parent after a re-home
// ---------------------------------------------------------------------------

/// A node that exited, re-rooted, and then re-joined a **new** parent must
/// refuse an old parent's `Rebase` for its old prefix: authority is the current
/// parent link, and a stale former parent cannot move the node back. The
/// address is unchanged by the refusal.
#[tokio::test]
async fn stale_rebase_from_former_parent_is_refused_after_rehome() {
    let world = World::new();
    let (nodes, _addrs) = build(world.defs()).await;
    let now = now_unix_seconds();

    // A exits from P and becomes an independent root `0`.
    let exit = {
        let engine = nodes[&world.a_id].control.lock().await;
        engine.sign_exit_request(now).expect("sign exit")
    };
    assert_eq!(
        deliver(&nodes[&world.p_id].control, &exit).await,
        ControlReply::Accepted
    );
    nodes[&world.a_id]
        .control
        .lock()
        .await
        .apply_exit(now)
        .expect("apply exit");
    wait_record(&nodes[&world.a_id].control, None, "0").await;

    // A re-joins its former sibling B (now a root-`0.2` node) as a new parent.
    let join = JoinRequest {
        node: node(&world.a_id),
        kind: ChildKind::Node,
        operator: world.a_op.public(),
        ledger: Some(ledger(1)),
        desired_slot: Some(0),
        location_hint: None,
        nonce: fresh_nonce(),
        expiry: now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
    };
    nodes[&world.a_id]
        .control
        .lock()
        .await
        .begin_outbound_join(join.clone(), node(&world.b_id), None)
        .expect("record outbound join");
    let signed_join = authorize(&world.a_id, &world.a_op, ControlRequest::Join(join));
    assert_eq!(
        send_direct(
            &nodes[&world.a_id].endpoint,
            &nodes[&world.b_id].addr,
            &signed_join
        )
        .await,
        ControlReply::Pending
    );

    // B approves A at slot 0; A installs parent B and address `0.2.0`.
    let approval: JoinApproval = {
        let mut engine = nodes[&world.b_id].control.lock().await;
        engine
            .approve_pending(&world.a_id, Some(0), now, ledger(2))
            .expect("approve pending")
    };
    let signed_approval = authorize(
        &world.b_id,
        &world.b_op,
        ControlRequest::JoinApproved(approval),
    );
    assert_eq!(
        send_direct(
            &nodes[&world.b_id].endpoint,
            &nodes[&world.a_id].addr,
            &signed_approval
        )
        .await,
        ControlReply::Accepted
    );
    wait_record(&nodes[&world.a_id].control, Some(&world.b_id), "0.2.0").await;

    // The old parent P signs a `Rebase` for A's *old* prefix (`0` -> `0.1`).
    // A's current parent is B, so the origin check refuses it.
    let stale = authorize(
        &world.p_id,
        &world.p_op,
        ControlRequest::Rebase(RebaseNotice {
            node: node(&world.a_id),
            parent_address: "0".parse().unwrap(),
            address: "0.1".parse().unwrap(),
            generation: 2,
        }),
    );
    assert_eq!(
        deliver(&nodes[&world.a_id].control, &stale).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );

    // The refusal did not move A: still re-homed under B at `0.2.0`.
    let record = nodes[&world.a_id].control.lock().await.record().clone();
    assert_eq!(
        record.parent.as_ref().map(|p| p.parent_id.as_str()),
        Some(world.b_id.as_str())
    );
    assert_eq!(
        record.address.as_ref().map(|a| a.to_string()).as_deref(),
        Some("0.2.0"),
        "a stale former parent must not change the address"
    );
}

// ---------------------------------------------------------------------------
// (F) A joining node with children pushes the new prefix down immediately
// ---------------------------------------------------------------------------

/// A node that re-joins a new parent while it already has a subtree must
/// re-base its children **at once**, not wait for the ~30s healing pull. After
/// the `JoinApproved` is answered, A's children (and their descendants) reflect
/// the new `0.2.0.*` prefix.
#[tokio::test]
async fn node_with_children_rebases_children_immediately_on_join() {
    let world = World::new();
    let (nodes, _addrs) = build(world.defs()).await;
    let now = now_unix_seconds();

    // A exits from P and becomes root `0`. The exit-driven notices are withheld
    // so C1/C2 still hold the old `0.1.*` prefix: only the join may move them.
    let exit = {
        let engine = nodes[&world.a_id].control.lock().await;
        engine.sign_exit_request(now).expect("sign exit")
    };
    assert_eq!(
        deliver(&nodes[&world.p_id].control, &exit).await,
        ControlReply::Accepted
    );
    nodes[&world.a_id]
        .control
        .lock()
        .await
        .apply_exit(now)
        .expect("apply exit");
    let _ = nodes[&world.a_id].control.lock().await.take_outbound();
    assert_eq!(
        nodes[&world.c1_id]
            .control
            .lock()
            .await
            .record()
            .address
            .as_ref()
            .map(|a| a.to_string())
            .as_deref(),
        Some("0.1.0"),
        "the withheld exit notice must leave C1 on the old prefix"
    );

    // A re-joins its former sibling B (a root-`0.2` node) as a new parent.
    let join = JoinRequest {
        node: node(&world.a_id),
        kind: ChildKind::Node,
        operator: world.a_op.public(),
        ledger: Some(ledger(1)),
        desired_slot: Some(0),
        location_hint: None,
        nonce: fresh_nonce(),
        expiry: now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
    };
    nodes[&world.a_id]
        .control
        .lock()
        .await
        .begin_outbound_join(join.clone(), node(&world.b_id), None)
        .expect("record outbound join");
    let signed_join = authorize(&world.a_id, &world.a_op, ControlRequest::Join(join));
    assert_eq!(
        send_direct(
            &nodes[&world.a_id].endpoint,
            &nodes[&world.b_id].addr,
            &signed_join
        )
        .await,
        ControlReply::Pending
    );

    // B approves A at slot 0; A installs parent B and address `0.2.0`.
    let approval: JoinApproval = {
        let mut engine = nodes[&world.b_id].control.lock().await;
        engine
            .approve_pending(&world.a_id, Some(0), now, ledger(2))
            .expect("approve pending")
    };
    let signed_approval = authorize(
        &world.b_id,
        &world.b_op,
        ControlRequest::JoinApproved(approval),
    );
    assert_eq!(
        send_direct(
            &nodes[&world.b_id].endpoint,
            &nodes[&world.a_id].addr,
            &signed_approval
        )
        .await,
        ControlReply::Accepted
    );
    wait_record(&nodes[&world.a_id].control, Some(&world.b_id), "0.2.0").await;

    // `handle_join_approved` queued a Rebase for each of A's children before it
    // answered; the live handler delivers them, and each child recurses. No
    // pull runs, so this is the join-driven push alone.
    wait_record(&nodes[&world.c1_id].control, Some(&world.a_id), "0.2.0.0").await;
    wait_record(&nodes[&world.c2_id].control, Some(&world.a_id), "0.2.0.1").await;
    wait_record(&nodes[&world.d_id].control, Some(&world.c1_id), "0.2.0.0.0").await;
    wait_record(
        &nodes[&world.e_id].control,
        Some(&world.d_id),
        "0.2.0.0.0.0",
    )
    .await;
}

// ---------------------------------------------------------------------------
// (G) A stale Rebase from the *current* parent is ignored by generation
// ---------------------------------------------------------------------------

/// A node's stored per-parent generation high-water mark orders notices from
/// the parent itself: a lower generation that still satisfies the address
/// derivation is ignored, so an older prefix cannot move the node back.
#[tokio::test]
async fn stale_rebase_from_current_parent_is_ignored() {
    let world = World::new();
    let (nodes, _addrs) = build(world.defs()).await;

    // A sits at `0.1` under P (slot 1). A newer re-base moves it to `0.6.1`.
    let newer = authorize(
        &world.p_id,
        &world.p_op,
        ControlRequest::Rebase(RebaseNotice {
            node: node(&world.a_id),
            parent_address: "0.6".parse().unwrap(),
            address: "0.6.1".parse().unwrap(),
            generation: 2,
        }),
    );
    assert_eq!(
        deliver(&nodes[&world.a_id].control, &newer).await,
        ControlReply::Accepted
    );
    wait_record(&nodes[&world.a_id].control, Some(&world.p_id), "0.6.1").await;

    // The same current parent now sends an older generation for a different
    // prefix: it is ignored (accepted so the parent stops retrying).
    let stale = authorize(
        &world.p_id,
        &world.p_op,
        ControlRequest::Rebase(RebaseNotice {
            node: node(&world.a_id),
            parent_address: "0.7".parse().unwrap(),
            address: "0.7.1".parse().unwrap(),
            generation: 1,
        }),
    );
    assert_eq!(
        deliver(&nodes[&world.a_id].control, &stale).await,
        ControlReply::Accepted
    );
    let record = nodes[&world.a_id].control.lock().await.record().clone();
    assert_eq!(
        record.address.as_ref().map(|a| a.to_string()).as_deref(),
        Some("0.6.1"),
        "a stale same-parent re-base must not change the address"
    );
    assert_eq!(
        record.parent_generation(),
        2,
        "the high-water mark is unchanged by a stale notice"
    );
}

// ---------------------------------------------------------------------------
// (H) Rolled-back parent: an ignored push stalls only until the healing pull
// ---------------------------------------------------------------------------

/// The guarantee the ordering rules rest on: when a parent's persisted
/// `address_epoch` regresses below a child's stored `ParentLink.generation`
/// (here, A applied a pre-rollback generation 5, while P's live generation is
/// 1), P's pushed notice is ignored — but the generation-agnostic
/// `apply_pull_snapshot` path still reads P's real current snapshot and heals A
/// (and re-propagates to A's children). The stall is therefore bounded to one
/// probe interval, never permanent.
///
/// Chosen over a unit test because the healing path is `pull_rebase_from_parent`
/// over the real transport: this asserts the full push-ignored → pull-healed
/// sequence with the same live harness the other re-base tests use.
#[tokio::test]
async fn rolled_back_parent_stalls_child_until_pull_heals() {
    let world = World::new();
    let (nodes, _addrs) = build(world.defs()).await;

    // A sits under P at slot 1. A notice from P's pre-rollback incarnation
    // (epoch 5) moves A to `0.6.1` and stores generation 5.
    let pre_rollback = authorize(
        &world.p_id,
        &world.p_op,
        ControlRequest::Rebase(RebaseNotice {
            node: node(&world.a_id),
            parent_address: "0.6".parse().unwrap(),
            address: "0.6.1".parse().unwrap(),
            generation: 5,
        }),
    );
    assert_eq!(
        deliver(&nodes[&world.a_id].control, &pre_rollback).await,
        ControlReply::Accepted
    );
    wait_record(&nodes[&world.a_id].control, Some(&world.p_id), "0.6.1").await;
    assert_eq!(
        nodes[&world.a_id]
            .control
            .lock()
            .await
            .record()
            .parent_generation(),
        5
    );
    // Discard the notice A queued for C1/C2 so the healing pull below is the
    // only thing that moves them.
    let _ = nodes[&world.a_id].control.lock().await.take_outbound();

    // P has since rolled back: its persisted epoch is 1, below A's stored mark.
    // Its freshly pushed notice is ignored (but accepted so it stops retrying).
    let rolled_back = authorize(
        &world.p_id,
        &world.p_op,
        ControlRequest::Rebase(RebaseNotice {
            node: node(&world.a_id),
            parent_address: "0.7".parse().unwrap(),
            address: "0.7.1".parse().unwrap(),
            generation: 1,
        }),
    );
    assert_eq!(
        deliver(&nodes[&world.a_id].control, &rolled_back).await,
        ControlReply::Accepted
    );
    let record = nodes[&world.a_id].control.lock().await.record().clone();
    assert_eq!(
        record.address.as_ref().map(|a| a.to_string()).as_deref(),
        Some("0.6.1"),
        "a rolled-back older generation must not move the child"
    );
    assert_eq!(record.parent_generation(), 5);

    // The ignore is audited with both generations.
    let audit = std::fs::read_to_string(
        nodes[&world.a_id]
            ._dir
            .path()
            .join(cawala_node::audit::CONTROL_AUDIT_FILE),
    )
    .expect("audit log");
    assert!(
        audit.contains("\"event\":\"rebase-stale-ignored\""),
        "{audit}"
    );
    assert!(audit.contains("\"generation\":1"), "{audit}");
    assert!(audit.contains("\"stored_generation\":5"), "{audit}");

    // The generation-agnostic pull is still authoritative: A reads P's real
    // current snapshot (`0`), applies the derived `0.1` (ignoring no
    // generation), and re-propagates `0.1.0` to its child C1.
    let applied = pull_rebase_from_parent(
        &nodes[&world.a_id].endpoint,
        &nodes[&world.a_id].control,
        timeout(),
        now_unix_seconds(),
    )
    .await
    .expect("pull");
    assert!(applied, "the pull must heal the stalled address");
    wait_record(&nodes[&world.a_id].control, Some(&world.p_id), "0.1").await;
    wait_record(&nodes[&world.c1_id].control, Some(&world.a_id), "0.1.0").await;
}

// ---------------------------------------------------------------------------
// (I) MoveChild re-slot: push heals the child and its subtree; pull heals when
//     the push is missed; the old address is intentionally dead
// ---------------------------------------------------------------------------

/// A same-parent `MoveChild` (re-slot) must heal the moved child **and its own
/// child**. `P` re-slots `B` from slot 2 to slot 5; the single targeted `Rebase`
/// moves `B` to `0.5` and `B` re-propagates `0.5.0` to `C`.
///
/// Then an envelope to the new address delivers locally, while the old address
/// still fails `NoSuchChild` - this failure is **intended** (no moved pointers:
/// a sender holding a stale address retries with a fresh one discovered out of
/// band). Finally a second re-slot is pushed but its notice is dropped, and
/// `B`'s own healing `RebasePull` still converges `B` (and `C`) on the new
/// prefix.
#[tokio::test]
async fn move_child_reslots_child_and_heals_subtree_then_pull() {
    let p_key = SecretKey::generate();
    let b_key = SecretKey::generate();
    let c_key = SecretKey::generate();
    let p_id = p_key.public().to_string();
    let b_id = b_key.public().to_string();
    let c_id = c_key.public().to_string();
    let p_op = operator(&p_key);
    let b_op = operator(&b_key);
    let c_op = operator(&c_key);

    let defs = vec![
        NodeDef {
            key: p_key,
            address: Some("0".to_string()),
            parent: None,
            children: vec![(b_id.clone(), ChildKind::Node, 2)],
            peers: vec![node_row(&b_id, &b_op, 2)],
        },
        NodeDef {
            key: b_key,
            address: Some("0.2".to_string()),
            parent: Some((p_id.clone(), 2)),
            children: vec![(c_id.clone(), ChildKind::Node, 0)],
            peers: vec![node_row(&p_id, &p_op, 0), node_row(&c_id, &c_op, 3)],
        },
        NodeDef {
            key: c_key,
            address: Some("0.2.0".to_string()),
            parent: Some((b_id.clone(), 0)),
            children: vec![],
            peers: vec![node_row(&b_id, &b_op, 2)],
        },
    ];
    let (mut nodes, addrs) = build(defs).await;

    // P (self-admin) re-slots B from slot 2 to slot 5.
    let move_child = authorize(
        &p_id,
        &p_op,
        ControlRequest::MoveChild(MoveChild {
            child: node(&b_id),
            new_parent: node(&p_id),
            slot: Some(5),
        }),
    );
    assert_eq!(
        deliver(&nodes[&p_id].control, &move_child).await,
        ControlReply::Accepted
    );
    // The push heals B (`0.5`) and, recursively, B's child C (`0.5.0`).
    propagate_from(&nodes, &p_id).await;
    wait_record(&nodes[&b_id].control, Some(&p_id), "0.5").await;
    wait_record(&nodes[&c_id].control, Some(&b_id), "0.5.0").await;

    // An envelope to the new address is delivered locally to B.
    let p_snapshot = nodes[&p_id].live_snapshot(&addrs).await;
    let env = build_envelope(
        &p_snapshot.routable.this,
        "0.5".parse().unwrap(),
        MSG_LEDGER_V1,
        b"new-slot".to_vec(),
        8,
    )
    .unwrap();
    let ack = send_envelope(&nodes[&p_id].endpoint, &p_snapshot, &env, timeout())
        .await
        .expect("send to the new address");
    assert_eq!(ack.status, AckStatus::Delivered);
    let got = nodes
        .get_mut(&b_id)
        .expect("b")
        .obs
        .recv()
        .await
        .expect("B delivered locally");
    assert_eq!(got.payload, b"new-slot");

    // The old address fails `NoSuchChild`. This failure is intended: there are
    // no moved pointers, so a stale sender must retry with a fresh address.
    let stale = build_envelope(
        &p_snapshot.routable.this,
        "0.2".parse().unwrap(),
        MSG_LEDGER_V1,
        b"stale".to_vec(),
        8,
    )
    .unwrap();
    let err = send_envelope(&nodes[&p_id].endpoint, &p_snapshot, &stale, timeout())
        .await
        .expect_err("the old address must not route");
    assert!(
        matches!(
            err,
            cawala_node::msg::MsgSendError::NoRoute(cawala_msg::RouteError::NoSuchChild { .. })
        ),
        "unexpected old-address drop: {err}"
    );

    // Offline healing: P re-slots B again (slot 6) but the targeted notice is
    // dropped, so B is still at `0.5`. B's own pull reads P's current snapshot
    // and converges B (and, by re-propagation, C) on `0.6`.
    let reslot = authorize(
        &p_id,
        &p_op,
        ControlRequest::MoveChild(MoveChild {
            child: node(&b_id),
            new_parent: node(&p_id),
            slot: Some(6),
        }),
    );
    assert_eq!(
        deliver(&nodes[&p_id].control, &reslot).await,
        ControlReply::Accepted
    );
    let dropped = nodes[&p_id].control.lock().await.take_outbound();
    assert_eq!(dropped.len(), 1, "exactly one targeted notice");
    assert_eq!(
        nodes[&b_id]
            .control
            .lock()
            .await
            .record()
            .address
            .as_ref()
            .map(|a| a.to_string())
            .as_deref(),
        Some("0.5"),
        "the missed notice must leave B on the previous prefix"
    );
    let applied = pull_rebase_from_parent(
        &nodes[&b_id].endpoint,
        &nodes[&b_id].control,
        timeout(),
        now_unix_seconds(),
    )
    .await
    .expect("pull");
    assert!(applied, "the pull must heal the missed re-slot");
    wait_record(&nodes[&b_id].control, Some(&p_id), "0.6").await;
    wait_record(&nodes[&c_id].control, Some(&b_id), "0.6.0").await;
}

