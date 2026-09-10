//! Hermetic integration tests for the direct `cawala/control/0` protocol.
//!
//! No relay and no external address lookup are used: every endpoint binds to
//! IPv4 loopback with relay mode disabled, and control requests are dialed by
//! an explicit [`EndpointAddr`] hint taken from `Endpoint::addr()`.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cawala_control::{
    ChildKind, ControlReply, ControlRequest, CreateChild, JoinRequest, NodeId, OperatorPubKey,
    OperatorSecretKey, RejectCode, SetAddress, SignedControl,
};
use cawala_ledger::{LedgerPubKey, LedgerSecretKey, PeerKeys, PeerRegistry, PeerRole};
use cawala_node::control::{ControlNode, spawn_control_only_on};
use cawala_node::control_store::ControlStore;
use cawala_node::record::RecordStore;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use tokio::sync::Mutex;

/// Per-exchange deadline for loopback tests.
fn timeout() -> Duration {
    Duration::from_secs(3)
}

/// Bind a hermetic endpoint on IPv4 loopback with relays disabled.
async fn bind(secret: &SecretKey) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(secret.clone())
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr((Ipv4Addr::LOCALHOST, 0))
        .expect("valid loopback bind address")
        .bind()
        .await
        .expect("bind endpoint")
}

/// The operator key derived from an iroh node key (the node's operator key is
/// its iroh key, per `identity`/`ledger_keys` docs).
fn operator(secret: &SecretKey) -> OperatorSecretKey {
    OperatorSecretKey::from_bytes(secret.to_bytes())
}

fn node(id: &str) -> NodeId {
    NodeId::from(id)
}

fn ledger(seed: u8) -> LedgerSecretKey {
    LedgerSecretKey::from_bytes([seed; 32])
}

fn peer(
    node_id: &str,
    op: &OperatorSecretKey,
    ledger_key: Option<&LedgerSecretKey>,
    role: PeerRole,
) -> PeerKeys {
    PeerKeys {
        node_id: node(node_id),
        operator: op.public(),
        ledger: ledger_key.map(LedgerSecretKey::public),
        role,
    }
}

/// A child to install in a node record.
struct ChildSpec<'a> {
    id: &'a str,
    kind: ChildKind,
    slot: u8,
    date_joined: u64,
}

/// Everything needed to stand up one hermetic control node.
struct NodeSpec<'a> {
    secret: &'a SecretKey,
    operator: OperatorSecretKey,
    dir: &'a Path,
    node_id: &'a str,
    address: Option<&'a str>,
    parent: Option<(&'a str, u8)>,
    children: &'a [ChildSpec<'a>],
    peers: Vec<PeerKeys>,
}

/// A running node: router + shared engine + endpoint/address.
struct TestNode {
    router: Router,
    engine: Arc<Mutex<ControlNode>>,
    endpoint: Endpoint,
    addr: EndpointAddr,
}

impl TestNode {
    async fn shutdown(self) {
        self.router.shutdown().await.expect("router shutdown");
    }

    async fn engine(&self) -> tokio::sync::MutexGuard<'_, ControlNode> {
        self.engine.lock().await
    }
}

async fn spawn_node(spec: NodeSpec<'_>) -> TestNode {
    let endpoint = bind(spec.secret).await;
    let addr = endpoint.addr();

    let mut record = RecordStore::open(spec.dir, spec.node_id).expect("open record");
    if let Some((parent_id, slot)) = spec.parent {
        record.set_parent(parent_id, slot).expect("set parent");
    }
    if let Some(address) = spec.address {
        record
            .set_address(address.parse().expect("valid octal address"))
            .expect("set address");
    }
    for child in spec.children {
        record
            .attach_child(child.id, child.kind, Some(child.slot), child.date_joined)
            .expect("attach child");
    }
    record.save().expect("save record");

    let mut registry = PeerRegistry::new();
    for keys in spec.peers {
        registry.insert(keys).expect("insert peer");
    }
    let store = ControlStore::open(spec.dir).expect("open control store");
    let engine = ControlNode::new(
        spec.dir.to_path_buf(),
        spec.node_id,
        spec.operator,
        record,
        registry,
        store,
    );
    let shared = Arc::new(Mutex::new(engine));
    let router = spawn_control_only_on(endpoint.clone(), shared.clone());
    TestNode {
        router,
        engine: shared,
        endpoint,
        addr,
    }
}

/// Send one signed request to `target` and return the reply.
async fn send(sender: &Endpoint, target: &EndpointAddr, signed: &SignedControl) -> ControlReply {
    ControlNode::send_direct_addr(sender, target.clone(), signed, timeout())
        .await
        .expect("control exchange")
}

fn join_request(
    applicant_id: &str,
    op: &OperatorSecretKey,
    ledger: Option<LedgerPubKey>,
    desired_slot: Option<u8>,
    expiry: u64,
) -> JoinRequest {
    JoinRequest {
        node: node(applicant_id),
        kind: if ledger.is_some() {
            ChildKind::Node
        } else {
            ChildKind::User
        },
        operator: op.public(),
        ledger,
        desired_slot,
        location_hint: None,
        nonce: 7,
        expiry,
    }
}

#[tokio::test]
async fn join_request_then_approve_assigns_address() {
    let parent_key = SecretKey::generate();
    let applicant_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let applicant_id = applicant_key.public().to_string();
    let parent_op = operator(&parent_key);
    let applicant_op = operator(&applicant_key);
    let applicant_ledger = ledger(9);

    let parent_dir = tempfile::tempdir().unwrap();
    let applicant_dir = tempfile::tempdir().unwrap();

    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op.clone(),
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        parent: None,
        children: &[],
        peers: vec![],
    })
    .await;
    let applicant = spawn_node(NodeSpec {
        secret: &applicant_key,
        operator: applicant_op.clone(),
        dir: applicant_dir.path(),
        node_id: &applicant_id,
        address: None,
        parent: None,
        children: &[],
        peers: vec![],
    })
    .await;

    let join = join_request(
        &applicant_id,
        &applicant_op,
        Some(applicant_ledger.public()),
        None,
        u64::MAX,
    );
    applicant
        .engine()
        .await
        .begin_outbound_join(join.clone(), node(&parent_id))
        .expect("record outbound join");

    let signed_join = SignedControl::authorize(
        node(&applicant_id),
        &applicant_op,
        ControlRequest::Join(join),
    )
    .unwrap();
    let reply = send(&applicant.endpoint, &parent.addr, &signed_join).await;
    assert_eq!(reply, ControlReply::Pending);
    assert_eq!(parent.engine().await.pending().pending().len(), 1);

    let approval = parent
        .engine()
        .await
        .approve_pending(&applicant_id, None, 1_000)
        .expect("approve");
    assert_eq!(approval.slot, 0);
    assert_eq!(approval.address.to_string(), "0.0");

    let signed_approval = SignedControl::authorize(
        node(&parent_id),
        &parent_op,
        ControlRequest::JoinApproved(approval),
    )
    .unwrap();
    let reply = send(&parent.endpoint, &applicant.addr, &signed_approval).await;
    assert_eq!(reply, ControlReply::Accepted);

    {
        let engine = applicant.engine().await;
        let record = engine.record();
        let parent_link = record.parent.as_ref().expect("parent link");
        assert_eq!(parent_link.parent_id, parent_id);
        assert_eq!(parent_link.slot, 0);
        assert_eq!(record.address, Some("0.0".parse().unwrap()));
        record.validate().unwrap();
    }
    {
        let engine = parent.engine().await;
        let record = engine.record();
        assert_eq!(record.children.len(), 1);
        assert_eq!(record.children[0].child_id, applicant_id);
        record.validate().unwrap();
        // The applicant is now a registered peer.
        assert_eq!(
            engine.peers().operator_of(&node(&applicant_id)),
            Some(&applicant_op.public())
        );
    }

    parent.shutdown().await;
    applicant.shutdown().await;
}

#[tokio::test]
async fn join_idempotent() {
    let parent_key = SecretKey::generate();
    let applicant_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let applicant_id = applicant_key.public().to_string();
    let parent_op = operator(&parent_key);
    let applicant_op = operator(&applicant_key);

    let parent_dir = tempfile::tempdir().unwrap();
    let applicant_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        parent: None,
        children: &[],
        peers: vec![],
    })
    .await;
    let applicant = spawn_node(NodeSpec {
        secret: &applicant_key,
        operator: applicant_op.clone(),
        dir: applicant_dir.path(),
        node_id: &applicant_id,
        address: None,
        parent: None,
        children: &[],
        peers: vec![],
    })
    .await;

    let join = join_request(
        &applicant_id,
        &applicant_op,
        Some(ledger(9).public()),
        Some(3),
        u64::MAX,
    );
    let signed = SignedControl::authorize(
        node(&applicant_id),
        &applicant_op,
        ControlRequest::Join(join),
    )
    .unwrap();

    assert_eq!(
        send(&applicant.endpoint, &parent.addr, &signed).await,
        ControlReply::Pending
    );
    assert_eq!(
        send(&applicant.endpoint, &parent.addr, &signed).await,
        ControlReply::Pending
    );
    assert_eq!(parent.engine().await.pending().pending().len(), 1);

    parent.shutdown().await;
    applicant.shutdown().await;
}

#[tokio::test]
async fn non_senior_child_control_rejected() {
    let parent_key = SecretKey::generate();
    let senior_key = SecretKey::generate();
    let junior_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let senior_id = senior_key.public().to_string();
    let junior_id = junior_key.public().to_string();
    let parent_op = operator(&parent_key);
    let senior_op = operator(&senior_key);
    let junior_op = operator(&junior_key);

    let children = [
        ChildSpec {
            id: &senior_id,
            kind: ChildKind::Node,
            slot: 0,
            date_joined: 10,
        },
        ChildSpec {
            id: &junior_id,
            kind: ChildKind::Node,
            slot: 1,
            date_joined: 20,
        },
    ];
    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        parent: None,
        children: &children,
        peers: vec![
            peer(&senior_id, &senior_op, Some(&ledger(11)), PeerRole::Node),
            peer(&junior_id, &junior_op, Some(&ledger(12)), PeerRole::Node),
        ],
    })
    .await;

    let sender_key = SecretKey::generate();
    let sender = bind(&sender_key).await;

    // The junior child (later date_joined) tries to clear the parent's address.
    let signed = SignedControl::authorize(
        node(&junior_id),
        &junior_op,
        ControlRequest::SetAddress(SetAddress { address: None }),
    )
    .unwrap();
    let reply = send(&sender, &parent.addr, &signed).await;
    assert_eq!(reply, ControlReply::Rejected(RejectCode::Unauthorized));

    // Nothing changed.
    let engine = parent.engine().await;
    assert_eq!(engine.record().address, Some("0".parse().unwrap()));
    assert_eq!(engine.record().children.len(), 2);

    sender.close().await;
    drop(engine);
    parent.shutdown().await;
}

#[tokio::test]
async fn senior_child_can_control_parent() {
    let parent_key = SecretKey::generate();
    let senior_key = SecretKey::generate();
    let junior_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let senior_id = senior_key.public().to_string();
    let junior_id = junior_key.public().to_string();
    let parent_op = operator(&parent_key);
    let senior_op = operator(&senior_key);
    let junior_op = operator(&junior_key);

    let children = [
        ChildSpec {
            id: &senior_id,
            kind: ChildKind::Node,
            slot: 0,
            date_joined: 10,
        },
        ChildSpec {
            id: &junior_id,
            kind: ChildKind::Node,
            slot: 1,
            date_joined: 20,
        },
    ];
    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0"),
        parent: None,
        children: &children,
        peers: vec![
            peer(&senior_id, &senior_op, Some(&ledger(11)), PeerRole::Node),
            peer(&junior_id, &junior_op, Some(&ledger(12)), PeerRole::Node),
        ],
    })
    .await;

    let sender = bind(&SecretKey::generate()).await;

    // Clear, then re-assert, the parent's address.
    let clear = SignedControl::authorize(
        node(&senior_id),
        &senior_op,
        ControlRequest::SetAddress(SetAddress { address: None }),
    )
    .unwrap();
    assert_eq!(
        send(&sender, &parent.addr, &clear).await,
        ControlReply::Accepted
    );
    {
        let engine = parent.engine().await;
        assert_eq!(engine.record().address, None);
    }

    let set = SignedControl::authorize(
        node(&senior_id),
        &senior_op,
        ControlRequest::SetAddress(SetAddress {
            address: Some("0".parse().unwrap()),
        }),
    )
    .unwrap();
    assert_eq!(
        send(&sender, &parent.addr, &set).await,
        ControlReply::Accepted
    );
    {
        let engine = parent.engine().await;
        assert_eq!(engine.record().address, Some("0".parse().unwrap()));
    }

    // Create a new child under the parent.
    let grandchild_key = SecretKey::generate();
    let grandchild_id = grandchild_key.public().to_string();
    let grandchild_op = operator(&grandchild_key);
    let grandchild_op_pub: OperatorPubKey = grandchild_op.public();
    let grandchild_ledger = ledger(21);
    let create = SignedControl::authorize(
        node(&senior_id),
        &senior_op,
        ControlRequest::CreateChild(CreateChild {
            child: node(&grandchild_id),
            operator: grandchild_op_pub,
            ledger: Some(grandchild_ledger.public()),
            kind: ChildKind::Node,
            slot: Some(5),
            date_joined: 30,
        }),
    )
    .unwrap();
    assert_eq!(
        send(&sender, &parent.addr, &create).await,
        ControlReply::Accepted
    );
    {
        let engine = parent.engine().await;
        let record = engine.record();
        assert_eq!(record.children.len(), 3);
        let created = record
            .children
            .iter()
            .find(|child| child.child_id == grandchild_id)
            .expect("grandchild attached");
        assert_eq!(created.slot, 5);
        record.validate().unwrap();
        assert_eq!(
            engine.peers().operator_of(&node(&grandchild_id)),
            Some(&grandchild_op_pub)
        );
    }

    sender.close().await;
    parent.shutdown().await;
}

#[tokio::test]
async fn query_returns_snapshot() {
    let node_key = SecretKey::generate();
    let child_key = SecretKey::generate();
    let node_id = node_key.public().to_string();
    let child_id = child_key.public().to_string();
    let node_op = operator(&node_key);

    let children = [ChildSpec {
        id: &child_id,
        kind: ChildKind::Node,
        slot: 1,
        date_joined: 42,
    }];
    let dir = tempfile::tempdir().unwrap();
    let test_node = spawn_node(NodeSpec {
        secret: &node_key,
        operator: node_op.clone(),
        dir: dir.path(),
        node_id: &node_id,
        address: Some("0.3"),
        parent: Some(("grandparent", 3)),
        children: &children,
        peers: vec![],
    })
    .await;

    // Self-admin query: the node's own operator is authorized.
    let signed = SignedControl::authorize(node(&node_id), &node_op, ControlRequest::Query).unwrap();
    let reply = test_node
        .engine()
        .await
        .receive_at(EndpointId::from(node_key.public()), signed, 0)
        .await;

    let ControlReply::Snapshot(snapshot) = reply else {
        panic!("expected snapshot, got {reply:?}");
    };
    assert_eq!(snapshot.node_id, node(&node_id));
    assert_eq!(snapshot.address, Some("0.3".parse().unwrap()));
    let parent = snapshot.parent.expect("parent snapshot");
    assert_eq!(parent.node_id, node("grandparent"));
    assert_eq!(parent.slot, 3);
    assert_eq!(parent.address, "0".parse().unwrap());
    assert_eq!(snapshot.children.len(), 1);
    let child = &snapshot.children[0];
    assert_eq!(child.child_id, node(&child_id));
    assert_eq!(child.slot, 1);
    assert_eq!(child.address, Some("0.3.1".parse().unwrap()));
    assert_eq!(child.date_joined, 42);

    test_node.shutdown().await;
}

#[tokio::test]
async fn join_capacity_overflow_rejected() {
    let parent_key = SecretKey::generate();
    let applicant_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let applicant_id = applicant_key.public().to_string();
    let parent_op = operator(&parent_key);
    let applicant_op = operator(&applicant_key);

    // Full parent: all 8 slots taken.
    let child_ids: Vec<String> = (0..8)
        .map(|_| SecretKey::generate().public().to_string())
        .collect();
    let children: Vec<ChildSpec<'_>> = child_ids
        .iter()
        .enumerate()
        .map(|(slot, id)| ChildSpec {
            id,
            kind: ChildKind::Node,
            slot: slot as u8,
            date_joined: 1,
        })
        .collect();

    let parent_dir = tempfile::tempdir().unwrap();
    let applicant_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op,
        dir: parent_dir.path(),
        node_id: &parent_id,
        address: Some("0.3"),
        parent: Some(("grandparent", 3)),
        children: &children,
        peers: vec![],
    })
    .await;
    let applicant = spawn_node(NodeSpec {
        secret: &applicant_key,
        operator: applicant_op.clone(),
        dir: applicant_dir.path(),
        node_id: &applicant_id,
        address: None,
        parent: None,
        children: &[],
        peers: vec![],
    })
    .await;

    let join = join_request(
        &applicant_id,
        &applicant_op,
        Some(ledger(9).public()),
        None,
        u64::MAX,
    );
    let signed = SignedControl::authorize(
        node(&applicant_id),
        &applicant_op,
        ControlRequest::Join(join),
    )
    .unwrap();
    assert_eq!(
        send(&applicant.endpoint, &parent.addr, &signed).await,
        ControlReply::Rejected(RejectCode::Capacity)
    );
    assert!(parent.engine().await.pending().pending().is_empty());

    parent.shutdown().await;
    applicant.shutdown().await;
}
