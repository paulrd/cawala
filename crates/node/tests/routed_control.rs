//! Hermetic integration tests for tree-routed control over `cawala/msg/0`.
//!
//! A routed request carries a [`RoutedControlV1`] payload in a `MSG_CONTROL_V1`
//! envelope. It ascends the octal tree hop by hop: each hop verifies its
//! predecessor's forward, appends (and signs) its own, then forwards with a
//! normal `cawala/msg/0` hop. The destination answers with a `SignedRoutedReply`
//! travelling back down.
//!
//! Everything is loopback: relays are disabled and every neighbor address is an
//! explicit routing hint, so no external address lookup is involved. The
//! destination still reverse-dials a queued `JoinApproved` directly, so the
//! applicant case populates the destination's iroh [`MemoryLookup`].

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cawala_control::{
    ADMIN_GRANT_VERSION, AdminGrant, AdminJoinApprove, AdminScope, CONTROL_REQUEST_TTL_SECS,
    ChildKind, ControlReply, ControlRequest, DEFAULT_ADMIN_TTL_SECS, DeliveryStatus, JoinApproval,
    JoinRejection, JoinRequest, MAX_CONTROL_FRAME, NodeId, OperatorSecretKey, ROUTED_CONTROL_VERSION,
    RejectCode, RoutedControlV1, RoutedForward, SignedAdminGrant, SignedControl, SignedRoutedReply,
};
use cawala_ledger::{LedgerPubKey, LedgerSecretKey, PeerKeys, PeerRegistry, PeerRole};
use cawala_msg::{AckStatus, Envelope, MSG_CONTROL_V1, MsgId, PeerRef, RejectReason};
use cawala_node::control::{ControlNode, spawn_control_node_live_on, spawn_control_only_on};
use cawala_node::control_store::ControlStore;
use cawala_node::msg::{
    MsgConfig, NeighborSource, RoutableSnapshot, build_envelope, dispatch_control_envelope,
    send_envelope,
};
use cawala_node::record::RecordStore;
use cawala_node::AdminStore;
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

/// Generous per-hop deadline for routed exchanges (several hops).
fn config() -> MsgConfig {
    MsgConfig {
        hop_timeout: Duration::from_secs(3),
        ..MsgConfig::default()
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A process-unique nonce, so distinct requests are never conflated by a replay
/// guard.
fn fresh_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

fn node(id: &str) -> NodeId {
    NodeId::from(id)
}

/// The operator key derived from an iroh node key (node operator == node id).
fn operator(secret: &SecretKey) -> OperatorSecretKey {
    OperatorSecretKey::from_bytes(secret.to_bytes())
}

fn ledger(seed: u8) -> LedgerPubKey {
    LedgerSecretKey::from_bytes([seed; 32]).public()
}

fn user_row(id: &str, op: &OperatorSecretKey) -> PeerKeys {
    PeerKeys {
        node_id: node(id),
        operator: op.public(),
        ledger: None,
        role: PeerRole::User,
    }
}

fn node_row(id: &str, op: &OperatorSecretKey, ledger_seed: u8) -> PeerKeys {
    PeerKeys {
        node_id: node(id),
        operator: op.public(),
        ledger: Some(ledger(ledger_seed)),
        role: PeerRole::Node,
    }
}

/// Bind a hermetic endpoint on IPv4 loopback with relays disabled.
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
// Node harness
// ---------------------------------------------------------------------------

/// A declarative node description for [`build`].
struct NodeDef {
    secret: SecretKey,
    operator: OperatorSecretKey,
    id: String,
    dir: tempfile::TempDir,
    address: String,
    parent: Option<(String, u8)>,
    children: Vec<(String, u8, ChildKind)>,
    peers: Vec<PeerKeys>,
    /// Whether this node's drain loop dispatches local `MSG_CONTROL_V1`
    /// requests (i.e. it is the routed target in this test).
    dispatch: bool,
}

impl NodeDef {
    fn new(
        secret: SecretKey,
        address: &str,
        parent: Option<(&str, u8)>,
        children: &[(&str, u8, ChildKind)],
        peers: Vec<PeerKeys>,
        dispatch: bool,
    ) -> Self {
        let operator = operator(&secret);
        NodeDef {
            id: secret.public().to_string(),
            secret,
            operator,
            dir: tempfile::tempdir().unwrap(),
            address: address.to_string(),
            parent: parent.map(|(id, slot)| (id.to_string(), slot)),
            children: children
                .iter()
                .map(|(id, slot, kind)| (id.to_string(), *slot, *kind))
                .collect(),
            peers,
            dispatch,
        }
    }
}

/// A running routed node: its handler, engine, routing view, and the envelopes
/// its `cawala/msg/0` sink received.
struct TestNode {
    endpoint: Endpoint,
    addr: EndpointAddr,
    control: Arc<Mutex<ControlNode>>,
    snapshot: RoutableSnapshot,
    obs: mpsc::UnboundedReceiver<Envelope>,
    _router: Router,
    _dir: tempfile::TempDir,
}

impl TestNode {
    fn this(&self) -> PeerRef {
        self.snapshot.routable.this.clone()
    }
}

/// Bind every node, persist its record, spawn its control+msg handler, and
/// drain locally delivered envelopes into an observation channel.
///
/// Only a node with `dispatch = true` feeds local `MSG_CONTROL_V1` envelopes to
/// [`dispatch_control_envelope`]; the requester and relays merely observe.
async fn build(defs: Vec<NodeDef>, lookup: &MemoryLookup, config: &MsgConfig) -> Vec<TestNode> {
    let mut endpoints = Vec::with_capacity(defs.len());
    let mut addrs: HashMap<EndpointId, EndpointAddr> = HashMap::new();
    for def in &defs {
        let endpoint = bind(&def.secret, Some(lookup.clone())).await;
        addrs.insert(def.secret.public(), endpoint.addr());
        lookup.add_endpoint_info(endpoint.addr());
        endpoints.push(endpoint);
    }

    let mut nodes = Vec::with_capacity(defs.len());
    for (def, endpoint) in defs.into_iter().zip(endpoints) {
        let mut record = RecordStore::open(def.dir.path(), &def.id).expect("open record");
        if let Some((parent_id, slot)) = &def.parent {
            record.set_parent(parent_id, *slot).expect("set parent");
        }
        record
            .set_address(def.address.parse().expect("valid address"))
            .expect("set address");
        for (child_id, slot, kind) in &def.children {
            // `date_joined = slot` keeps the senior child deterministic:
            // lower slot == earlier join.
            record
                .attach_child(child_id, *kind, Some(*slot), *slot as u64)
                .expect("attach child");
        }
        record.save().expect("save record");

        let mut snapshot = RoutableSnapshot::from_record(record.record()).expect("snapshot");
        if let Some((parent_id, _)) = &def.parent
            && let Ok(id) = parent_id.parse::<EndpointId>()
            && let Some(addr) = addrs.get(&id)
        {
            snapshot.hints.insert(id.to_string(), addr.clone());
        }
        for (child_id, _, _) in &def.children {
            if let Ok(id) = child_id.parse::<EndpointId>()
                && let Some(addr) = addrs.get(&id)
            {
                snapshot.hints.insert(id.to_string(), addr.clone());
            }
        }

        let mut registry = PeerRegistry::new();
        for row in &def.peers {
            registry.insert(row.clone()).expect("insert peer");
        }
        let store = ControlStore::open(def.dir.path()).expect("open control store");
        let engine = ControlNode::new(
            def.dir.path().to_path_buf(),
            &def.id,
            def.operator,
            record,
            registry,
            store,
            AdminStore::empty(),
        );
        let control = Arc::new(Mutex::new(engine));

        let source = NeighborSource::Static(snapshot.clone());
        let (router, mut rx) =
            spawn_control_node_live_on(endpoint.clone(), source.clone(), config.clone(), {
                Arc::clone(&control)
            });

        let (obs_tx, obs_rx) = mpsc::unbounded_channel();
        let dispatch = def.dispatch;
        let dispatch_endpoint = endpoint.clone();
        let dispatch_source = source.clone();
        let dispatch_config = config.clone();
        let dispatch_control = Arc::clone(&control);
        tokio::spawn(async move {
            while let Some(env) = rx.recv().await {
                let _ = obs_tx.send(env.clone());
                if dispatch && env.msg_type == MSG_CONTROL_V1 {
                    dispatch_control_envelope(
                        &dispatch_endpoint,
                        &dispatch_source,
                        &dispatch_config,
                        &dispatch_control,
                        env,
                    )
                    .await;
                }
            }
        });

        let addr = endpoint.addr();
        nodes.push(TestNode {
            endpoint,
            addr,
            control,
            snapshot,
            obs: obs_rx,
            _router: router,
            _dir: def.dir,
        });
    }
    nodes
}

// ---------------------------------------------------------------------------
// The root(0) / A(0.1) / B(0.2) / U(0.1.3) world
// ---------------------------------------------------------------------------

/// Fixed identities and ids for the shared test world.
struct World {
    root_key: SecretKey,
    a_key: SecretKey,
    b_key: SecretKey,
    u_key: SecretKey,
    root_id: String,
    a_id: String,
    b_id: String,
    u_id: String,
    root_op: OperatorSecretKey,
    a_op: OperatorSecretKey,
    b_op: OperatorSecretKey,
    u_op: OperatorSecretKey,
    admin_op: OperatorSecretKey,
}

/// `root = 0`, `A = 0.1` (senior child), `B = 0.2`, `U = 0.1.3` (A's user).
fn world() -> World {
    let root_key = SecretKey::generate();
    let a_key = SecretKey::generate();
    let b_key = SecretKey::generate();
    let u_key = SecretKey::generate();
    let root_id = root_key.public().to_string();
    let a_id = a_key.public().to_string();
    let b_id = b_key.public().to_string();
    let u_id = u_key.public().to_string();
    let root_op = operator(&root_key);
    let a_op = operator(&a_key);
    let b_op = operator(&b_key);
    let u_op = operator(&u_key);
    World {
        root_key,
        a_key,
        b_key,
        u_key,
        root_id,
        a_id,
        b_id,
        u_id,
        root_op,
        a_op,
        b_op,
        u_op,
        admin_op: OperatorSecretKey::from_bytes([0x5a; 32]),
    }
}

fn world_defs(w: &World) -> Vec<NodeDef> {
    let root = NodeDef::new(
        w.root_key.clone(),
        "0",
        None,
        &[
            (w.a_id.as_str(), 1, ChildKind::Node),
            (w.b_id.as_str(), 2, ChildKind::Node),
        ],
        vec![
            node_row(&w.a_id, &w.a_op, 1),
            node_row(&w.b_id, &w.b_op, 2),
        ],
        true,
    );
    let a = NodeDef::new(
        w.a_key.clone(),
        "0.1",
        Some((w.root_id.as_str(), 1)),
        &[(w.u_id.as_str(), 3, ChildKind::User)],
        vec![
            user_row(&w.u_id, &w.u_op),
            node_row(&w.root_id, &w.root_op, 0),
        ],
        false,
    );
    let b = NodeDef::new(
        w.b_key.clone(),
        "0.2",
        Some((w.root_id.as_str(), 2)),
        &[],
        vec![node_row(&w.root_id, &w.root_op, 0)],
        false,
    );
    let u = NodeDef::new(
        w.u_key.clone(),
        "0.1.3",
        Some((w.a_id.as_str(), 3)),
        &[],
        vec![],
        false,
    );
    vec![root, a, b, u]
}

/// Build the world and return `[root, a, b, u]`.
async fn build_world(w: &World, lookup: &MemoryLookup) -> Vec<TestNode> {
    build(world_defs(w), lookup, &config()).await
}

// ---------------------------------------------------------------------------
// Routed helpers
// ---------------------------------------------------------------------------

fn peer(addr: &str, id: &str) -> PeerRef {
    PeerRef {
        addr: addr.parse().expect("valid address"),
        node: id.to_string(),
    }
}

fn admin_grant(root_id: &str, root_op: &OperatorSecretKey, admin_op: &OperatorSecretKey) -> SignedAdminGrant {
    let now = now_unix_seconds();
    SignedAdminGrant::authorize(
        AdminGrant {
            version: ADMIN_GRANT_VERSION,
            node: node(root_id),
            admin: admin_op.public(),
            scope: AdminScope::Admin,
            granted_at: now.saturating_sub(1),
            expiry: now + DEFAULT_ADMIN_TTL_SECS,
            label: Some("routed-test".to_string()),
        },
        root_op,
    )
    .expect("sign admin grant")
}

/// An admin intent addressed to `root_id` and signed by `admin_op`.
fn admin_intent(
    root_id: &str,
    admin_op: &OperatorSecretKey,
    request: ControlRequest,
) -> SignedControl {
    SignedControl::authorize(
        node(root_id),
        admin_op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        request,
    )
    .expect("sign admin intent")
}

/// A routed control request payload with the frozen version.
fn routed(
    target: PeerRef,
    requester: PeerRef,
    intent: SignedControl,
    grant: Option<SignedAdminGrant>,
    forwards: Vec<RoutedForward>,
) -> RoutedControlV1 {
    RoutedControlV1 {
        version: ROUTED_CONTROL_VERSION,
        target,
        requester,
        intent,
        grant,
        forwards,
    }
}

/// Sign `request` as `node`'s own routed forward.
async fn own_forward(node: &TestNode, request: &ControlRequest) -> RoutedForward {
    node.control
        .lock()
        .await
        .sign_forward(request)
        .expect("sign own forward")
}

/// Send a routed request from `source` towards `dst`, returning the request
/// envelope's [`MsgId`] (the reply's sole correlation key) and the transport ack.
async fn send_routed(source: &TestNode, dst: &str, routed: RoutedControlV1) -> (MsgId, AckStatus) {
    send_raw_with_id(source, dst, routed.to_bytes().expect("encode routed")).await
}

/// Send raw bytes as a `MSG_CONTROL_V1` payload and return the transport ack.
async fn send_raw(source: &TestNode, dst: &str, payload: Vec<u8>) -> AckStatus {
    send_raw_with_id(source, dst, payload).await.1
}

/// Send raw bytes and return the request envelope's `msg_id` plus the ack.
async fn send_raw_with_id(source: &TestNode, dst: &str, payload: Vec<u8>) -> (MsgId, AckStatus) {
    let env = build_envelope(
        &source.this(),
        dst.parse().expect("valid dst"),
        MSG_CONTROL_V1,
        payload,
        8,
    )
    .expect("build envelope");
    let ack = send_envelope(&source.endpoint, &source.snapshot, &env, config().hop_timeout)
        .await
        .expect("send envelope");
    (env.msg_id, ack.status)
}

/// Await the next decoded routed reply in `node`'s observation channel.
async fn recv_signed_reply(node: &mut TestNode) -> SignedRoutedReply {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("no routed reply within the deadline");
        }
        match tokio::time::timeout(remaining, node.obs.recv()).await {
            Ok(Some(env)) => {
                if env.msg_type == MSG_CONTROL_V1
                    && let Ok(signed) = SignedRoutedReply::from_bytes(&env.payload)
                {
                    return signed;
                }
            }
            Ok(None) => panic!("observation channel closed before a reply"),
            Err(_) => panic!("no routed reply within the deadline"),
        }
    }
}

/// Await the next decoded routed reply's [`ControlReply`].
async fn recv_reply(node: &mut TestNode) -> ControlReply {
    recv_signed_reply(node).await.reply.reply
}

/// Wait until the applicant engine has installed `parent_id` / `address`.
async fn wait_joined(control: &Arc<Mutex<ControlNode>>, parent_id: &str, address: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        {
            let engine = control.lock().await;
            let record = engine.record();
            let parent_ok = record.parent.as_ref().map(|p| p.parent_id.as_str()) == Some(parent_id);
            let address_ok =
                record.address.as_ref().map(|a| a.to_string()).as_deref() == Some(address);
            if parent_ok && address_ok {
                return;
            }
        }
        if Instant::now() >= deadline {
            panic!("applicant never installed parent link {parent_id} / address {address}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// (1) A user's routed admin query reaches the root through its parent, and the
/// reply verifies under the root's operator key.
#[tokio::test]
async fn routed_admin_query_reaches_ancestor_and_reply_verifies() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [root, _a, _b, u] = &mut nodes[..] else {
        panic!("world shape")
    };

    root.control
        .lock()
        .await
        .grant_admin(admin_grant(&w.root_id, &w.root_op, &w.admin_op))
        .expect("grant admin");

    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    let forward = own_forward(u, &intent.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1.3", &w.u_id),
        intent,
        Some(admin_grant(&w.root_id, &w.root_op, &w.admin_op)),
        vec![forward],
    );

    let (msg_id, status) = send_routed(u, "0", request).await;
    assert_eq!(status, AckStatus::Delivered);

    let signed = recv_signed_reply(u).await;
    assert_eq!(
        signed.reply.reply_to, msg_id,
        "the reply must correlate with the request envelope's msg_id"
    );
    signed
        .verify(&w.root_op.public())
        .expect("reply must verify under the root operator key");
    assert_eq!(signed.reply.responder.node, w.root_id);
    assert_eq!(signed.reply.requester.node, w.u_id);
    assert!(
        matches!(&signed.reply.reply, ControlReply::AdminSnapshot(snapshot) if snapshot.node.node_id == node(&w.root_id)),
        "expected an AdminSnapshot from the root, got {:?}",
        signed.reply.reply
    );
}

/// (2) A routed admin approval applies at the root and the resulting
/// `JoinApproved` is reverse-dialed to the applicant; the reply reports
/// `Delivered`.
#[tokio::test]
async fn routed_admin_approve_applies_and_delivers_to_applicant() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [root, _a, _b, u] = &mut nodes[..] else {
        panic!("world shape")
    };

    root.control
        .lock()
        .await
        .grant_admin(admin_grant(&w.root_id, &w.root_op, &w.admin_op))
        .expect("grant admin");

    // A control-only applicant starts an outbound join and delivers it directly
    // (join traffic is refused on the routed path).
    let x_key = SecretKey::generate();
    let x_id = x_key.public().to_string();
    let x_op = operator(&x_key);
    let x_dir = tempfile::tempdir().unwrap();
    let x_record = RecordStore::open(x_dir.path(), &x_id).unwrap();
    x_record.save().unwrap();
    let x_engine = ControlNode::new(
        x_dir.path().to_path_buf(),
        &x_id,
        x_op.clone(),
        x_record,
        PeerRegistry::new(),
        ControlStore::open(x_dir.path()).unwrap(),
        AdminStore::empty(),
    );
    let x_control = Arc::new(Mutex::new(x_engine));
    let x_endpoint = bind(&x_key, None).await;
    let _x_router = spawn_control_only_on(x_endpoint.clone(), Arc::clone(&x_control));
    lookup.add_endpoint_info(x_endpoint.addr());

    let join = JoinRequest {
        node: node(&x_id),
        kind: ChildKind::User,
        operator: x_op.public(),
        ledger: None,
        desired_slot: Some(3),
        location_hint: None,
        nonce: 7,
        expiry: now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
    };
    x_control
        .lock()
        .await
        .begin_outbound_join(join.clone(), node(&w.root_id), None)
        .expect("record outbound join");
    let signed_join = SignedControl::authorize(
        node(&x_id),
        &x_op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        ControlRequest::Join(join),
    )
    .unwrap();
    assert_eq!(
        ControlNode::send_direct_addr(&x_endpoint, root.addr.clone(), &signed_join, timeout())
            .await
            .expect("direct join"),
        ControlReply::Pending
    );

    let intent = admin_intent(
        &w.root_id,
        &w.admin_op,
        ControlRequest::AdminApproveJoin(AdminJoinApprove {
            child: node(&x_id),
            slot: Some(3),
        }),
    );
    let forward = own_forward(u, &intent.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1.3", &w.u_id),
        intent,
        None,
        vec![forward],
    );
    assert_eq!(send_routed(u, "0", request).await.1, AckStatus::Delivered);

    let reply = recv_reply(u).await;
    let ControlReply::AdminApproved(approved) = reply else {
        panic!("expected AdminApproved, got {reply:?}");
    };
    assert_eq!(approved.child, node(&x_id));
    assert_eq!(approved.address, "0.3".parse().unwrap());
    assert_eq!(
        approved.delivery,
        DeliveryStatus::Delivered,
        "the root must reverse-dial the applicant via the MemoryLookup"
    );
    wait_joined(&x_control, &w.root_id, "0.3").await;

    x_endpoint.close().await;
}

/// (3) Revoking the grant wins over a well-formed carried grant: the routed
/// admin request is refused and the audit records the missing store entry.
#[tokio::test]
async fn routed_admin_revoked_grant_is_refused_despite_carried_evidence() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [root, _a, _b, u] = &mut nodes[..] else {
        panic!("world shape")
    };

    let grant = admin_grant(&w.root_id, &w.root_op, &w.admin_op);
    root.control
        .lock()
        .await
        .grant_admin(grant.clone())
        .expect("grant admin");
    assert!(
        root.control
            .lock()
            .await
            .revoke_admin(&w.admin_op.public())
            .unwrap(),
        "grant must be present before revoke"
    );

    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    let forward = own_forward(u, &intent.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1.3", &w.u_id),
        intent,
        Some(grant),
        vec![forward],
    );
    assert_eq!(send_routed(u, "0", request).await.1, AckStatus::Delivered);

    assert_eq!(
        recv_reply(u).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );

    let audit_path = root.control.lock().await.data_dir().join("control_audit.jsonl");
    let audit = std::fs::read_to_string(audit_path).expect("audit log");
    assert!(
        audit.contains("grant_store_missing"),
        "carried-but-unstored grant must be audited: {audit}"
    );
}

/// (4) A request whose `target.node` or `requester` disagrees with the envelope
/// is refused rather than dispatched. Sent directly from a neighbor so the
/// relay-level coherence check does not mask the destination's refusal.
#[tokio::test]
async fn routed_target_and_requester_mismatch_are_refused() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [root, a, _b, _u] = &mut nodes[..] else {
        panic!("world shape")
    };

    root.control
        .lock()
        .await
        .grant_admin(admin_grant(&w.root_id, &w.root_op, &w.admin_op))
        .expect("grant admin");

    // `target.node` names someone else though the address is the root's.
    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    let forward = own_forward(a, &intent.request).await;
    let bad_target = routed(
        peer("0", "not-the-root"),
        peer("0.1", &w.a_id),
        intent,
        None,
        vec![forward],
    );
    assert_eq!(send_routed(a, "0", bad_target).await.1, AckStatus::Delivered);
    assert_eq!(
        recv_reply(a).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );

    // `requester.node` disagrees with the authenticated envelope source.
    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    let forward = own_forward(a, &intent.request).await;
    let bad_requester = routed(
        peer("0", &w.root_id),
        peer("0.1", "not-a"),
        intent,
        None,
        vec![forward],
    );
    assert_eq!(send_routed(a, "0", bad_requester).await.1, AckStatus::Delivered);
    assert_eq!(
        recv_reply(a).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
}

/// (5) An expired intent is refused as `Expired`; re-sending an already-applied
/// intent nonce (fresh envelope and forward) is refused as `Replay`.
#[tokio::test]
async fn routed_expired_intent_and_intent_replay() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [root, a, _b, _u] = &mut nodes[..] else {
        panic!("world shape")
    };

    root.control
        .lock()
        .await
        .grant_admin(admin_grant(&w.root_id, &w.root_op, &w.admin_op))
        .expect("grant admin");

    // Expired intent (sent directly, so no relay drops it first).
    let expired = SignedControl::authorize(
        node(&w.root_id),
        &w.admin_op,
        fresh_nonce(),
        now_unix_seconds().saturating_sub(1),
        ControlRequest::AdminQuery,
    )
    .unwrap();
    let forward = own_forward(a, &expired.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1", &w.a_id),
        expired,
        None,
        vec![forward],
    );
    assert_eq!(send_routed(a, "0", request).await.1, AckStatus::Delivered);
    assert_eq!(
        recv_reply(a).await,
        ControlReply::Rejected(RejectCode::Expired)
    );

    // Fresh intent: the first application succeeds...
    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    let forward = own_forward(a, &intent.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1", &w.a_id),
        intent.clone(),
        None,
        vec![forward],
    );
    assert_eq!(send_routed(a, "0", request).await.1, AckStatus::Delivered);
    assert!(matches!(recv_reply(a).await, ControlReply::AdminSnapshot(_)));

    // ...and replaying the same intent nonce (fresh envelope + forward) is Replay.
    let forward = own_forward(a, &intent.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1", &w.a_id),
        intent,
        None,
        vec![forward],
    );
    assert_eq!(send_routed(a, "0", request).await.1, AckStatus::Delivered);
    assert_eq!(
        recv_reply(a).await,
        ControlReply::Rejected(RejectCode::Replay)
    );
}

/// (6) A forged predecessor forward is refused at the relay.
#[tokio::test]
async fn routed_forged_last_forward_is_refused() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [root, _a, _b, u] = &mut nodes[..] else {
        panic!("world shape")
    };
    root.control
        .lock()
        .await
        .grant_admin(admin_grant(&w.root_id, &w.root_op, &w.admin_op))
        .expect("grant admin");

    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    // A forward whose hop names U but whose signature is by an unrelated key.
    let attacker = OperatorSecretKey::from_bytes([0x11; 32]);
    let forged = SignedControl::authorize(
        node(&w.u_id),
        &attacker,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        intent.request.clone(),
    )
    .unwrap();
    let forward = RoutedForward::new(peer("0.1.3", &w.u_id), forged);
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1.3", &w.u_id),
        intent,
        None,
        vec![forward],
    );
    assert_eq!(
        send_routed(u, "0", request).await.1,
        AckStatus::Rejected(RejectReason::BadPayload)
    );

    // A missing predecessor forward is refused too.
    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1.3", &w.u_id),
        intent,
        None,
        vec![],
    );
    assert_eq!(
        send_routed(u, "0", request).await.1,
        AckStatus::Rejected(RejectReason::BadPayload)
    );
}

/// (7) H1 teeth: a topology request from the senior child is applied, while the
/// same request from a non-senior child is refused.
#[tokio::test]
async fn routed_topology_senior_allowed_nonsenior_denied() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [root, a, b, _u] = &mut nodes[..] else {
        panic!("world shape")
    };

    // Senior child A: its own signed Query is dispatched.
    let query = SignedControl::authorize(
        node(&w.a_id),
        &w.a_op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        ControlRequest::Query,
    )
    .unwrap();
    let forward = own_forward(a, &query.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1", &w.a_id),
        query,
        None,
        vec![forward],
    );
    assert_eq!(send_routed(a, "0", request).await.1, AckStatus::Delivered);
    assert!(
        matches!(recv_reply(a).await, ControlReply::Snapshot(_)),
        "the senior child's topology request must be applied"
    );

    // A2: the dispatched routed topology request records its routing context.
    let audit_path = root.control.lock().await.data_dir().join("control_audit.jsonl");
    let audit = std::fs::read_to_string(audit_path).expect("audit log");
    assert!(audit.contains("\"event\":\"routed\""), "{audit}");
    assert!(audit.contains("\"routed\":true"), "{audit}");
    assert!(audit.contains("\"outcome\":\"snapshot\""), "{audit}");
    assert!(
        audit.contains(&format!("\"forwarder\":\"{}\"", w.a_id)),
        "{audit}"
    );
    assert!(audit.contains("\"hops\":1"), "{audit}");
    assert!(
        audit.contains(&format!("\"requester\":\"{}\"", w.a_id)),
        "{audit}"
    );

    // Non-senior child B: structurally valid, but not the senior child.
    let query = SignedControl::authorize(
        node(&w.b_id),
        &w.b_op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        ControlRequest::Query,
    )
    .unwrap();
    let forward = own_forward(b, &query.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.2", &w.b_id),
        query,
        None,
        vec![forward],
    );
    assert_eq!(send_routed(b, "0", request).await.1, AckStatus::Delivered);
    assert_eq!(
        recv_reply(b).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
}

/// (8) `Join`, `JoinApproved`, and `JoinRejected` are refused on the routed
/// path regardless of signer.
#[tokio::test]
async fn routed_join_variants_are_refused() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [_root, a, _b, _u] = &mut nodes[..] else {
        panic!("world shape")
    };

    let join = JoinRequest {
        node: node(&w.a_id),
        kind: ChildKind::User,
        operator: w.a_op.public(),
        ledger: None,
        desired_slot: None,
        location_hint: None,
        nonce: 1,
        expiry: now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
    };
    let approval = JoinApproval {
        child: node(&w.a_id),
        child_operator: w.a_op.public(),
        child_ledger: None,
        kind: ChildKind::User,
        slot: 3,
        address: "0.1.3".parse().unwrap(),
        date_joined: 1,
        nonce: 1,
        parent_ledger: ledger(42),
    };
    let rejection = JoinRejection {
        child: node(&w.a_id),
        reason: "no".to_string(),
        nonce: 1,
    };

    for request in [
        ControlRequest::Join(join),
        ControlRequest::JoinApproved(approval),
        ControlRequest::JoinRejected(rejection),
    ] {
        let intent = SignedControl::authorize(
            node(&w.a_id),
            &w.a_op,
            fresh_nonce(),
            now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
            request,
        )
        .unwrap();
        let forward = own_forward(a, &intent.request).await;
        let request = routed(
            peer("0", &w.root_id),
            peer("0.1", &w.a_id),
            intent,
            None,
            vec![forward],
        );
        assert_eq!(send_routed(a, "0", request).await.1, AckStatus::Delivered);
        assert_eq!(
            recv_reply(a).await,
            ControlReply::Rejected(RejectCode::Unauthorized),
            "join traffic must be refused on the routed path"
        );
    }
}

/// (9) A control payload larger than `MAX_CONTROL_FRAME` is refused before any
/// decode work.
#[tokio::test]
async fn routed_oversize_payload_rejected_before_decode() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [_root, _a, _b, u] = &mut nodes[..] else {
        panic!("world shape")
    };

    let oversize = vec![1u8; MAX_CONTROL_FRAME as usize + 1];
    assert_eq!(
        send_raw(u, "0", oversize).await,
        AckStatus::Rejected(RejectReason::BadPayload)
    );
}

/// (10) A reply travels back through a relay (disambiguation by full decode),
/// and a payload that decodes as neither routed type is refused.
#[tokio::test]
async fn routed_reply_passes_through_relay_and_undecodable_payload_is_refused() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [root, _a, _b, u] = &mut nodes[..] else {
        panic!("world shape")
    };
    root.control
        .lock()
        .await
        .grant_admin(admin_grant(&w.root_id, &w.root_op, &w.admin_op))
        .expect("grant admin");

    // The reply from test (1)'s request has to traverse A to reach U.
    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    let forward = own_forward(u, &intent.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1.3", &w.u_id),
        intent,
        None,
        vec![forward],
    );
    let (msg_id, status) = send_routed(u, "0", request).await;
    assert_eq!(status, AckStatus::Delivered);
    let signed = recv_signed_reply(u).await;
    assert_eq!(
        signed.reply.reply_to, msg_id,
        "the relayed reply must correlate with the request envelope's msg_id"
    );
    signed.verify(&w.root_op.public()).expect("relayed reply verifies");

    // A payload that decodes as neither `RoutedControlV1` nor
    // `SignedRoutedReply` is refused at the relay (both routes start with the
    // same version byte, so this is the fallback arm).
    let garbage = vec![ROUTED_CONTROL_VERSION, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(
        send_raw(u, "0", garbage).await,
        AckStatus::Rejected(RejectReason::NoRoute)
    );
}

/// (11) A forward vector that is not parallel to the hop chain (including the
/// empty vector) is refused.
#[tokio::test]
async fn routed_forward_hop_count_mismatch_rejected() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [root, _a, _b, u] = &mut nodes[..] else {
        panic!("world shape")
    };
    root.control
        .lock()
        .await
        .grant_admin(admin_grant(&w.root_id, &w.root_op, &w.admin_op))
        .expect("grant admin");

    // Empty forwards against a one-hop chain.
    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1.3", &w.u_id),
        intent,
        None,
        vec![],
    );
    assert_eq!(
        send_routed(u, "0", request).await.1,
        AckStatus::Rejected(RejectReason::BadPayload)
    );

    // Too many forwards against a one-hop chain.
    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    let forward = own_forward(u, &intent.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1.3", &w.u_id),
        intent,
        None,
        vec![forward.clone(), forward],
    );
    assert_eq!(
        send_routed(u, "0", request).await.1,
        AckStatus::Rejected(RejectReason::BadPayload)
    );
}

/// (A5) Destination-side forged predecessor: a direct neighbor that relays a
/// forged last forward is refused by the destination itself, not only by a
/// relay.
#[tokio::test]
async fn routed_destination_rejects_forged_predecessor_forward() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [_root, a, _b, _u] = &mut nodes[..] else {
        panic!("world shape")
    };

    let intent = admin_intent(&w.root_id, &w.admin_op, ControlRequest::AdminQuery);
    // The forward names A as its hop, but is signed by an unrelated key.
    let attacker = OperatorSecretKey::from_bytes([0x22; 32]);
    let forged = SignedControl::authorize(
        node(&w.a_id),
        &attacker,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        intent.request.clone(),
    )
    .unwrap();
    let forward = RoutedForward::new(peer("0.1", &w.a_id), forged);
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1", &w.a_id),
        intent,
        None,
        vec![forward],
    );
    assert_eq!(send_routed(a, "0", request).await.1, AckStatus::Delivered);
    assert_eq!(
        recv_reply(a).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
}

/// (A7) A two-hop topology request from a user is answered by the *predecessor's*
/// control: U's intent alone is not authority, but the relaying senior child A's
/// signed control is.
#[tokio::test]
async fn routed_topology_dispatches_last_hop_control_not_intent() {
    let w = world();
    let lookup = MemoryLookup::new();
    let mut nodes = build_world(&w, &lookup).await;
    let [_root, _a, _b, u] = &mut nodes[..] else {
        panic!("world shape")
    };

    let intent = SignedControl::authorize(
        node(&w.u_id),
        &w.u_op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        ControlRequest::Query,
    )
    .unwrap();
    let forward = own_forward(u, &intent.request).await;
    let request = routed(
        peer("0", &w.root_id),
        peer("0.1.3", &w.u_id),
        intent,
        None,
        vec![forward],
    );
    assert_eq!(send_routed(u, "0", request).await.1, AckStatus::Delivered);
    assert!(
        matches!(recv_reply(u).await, ControlReply::Snapshot(_)),
        "the root must dispatch the senior predecessor's control, not the user intent"
    );
}
