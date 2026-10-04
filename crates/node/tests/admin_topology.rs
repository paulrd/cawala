//! Hermetic integration tests for delegated topology administration (P4) over
//! the real `cawala/control/0` protocol.
//!
//! A `topology`-scoped v2 grant (or the node's own operator) may detach and
//! re-slot a direct child; the mutation is the same authority-free helper the
//! senior path uses, so validation parity is structural. Joins-only, value-only,
//! and legacy v1 grants are `Unauthorized` on both variants.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cawala_control::{
    AdminDetachChild, AdminMoveChild, CONTROL_REQUEST_TTL_SECS, ChildKind, ControlReply,
    ControlRequest, NodeId, OperatorSecretKey, RejectCode, SignedControl,
};
use cawala_ledger::{PeerKeys, PeerRegistry};
use cawala_node::control::{ControlNode, OutboundControl, OutboundKind, spawn_control_only_on};
use cawala_node::control_store::ControlStore;
use cawala_node::record::RecordStore;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use tokio::sync::Mutex;

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

/// A process-unique request nonce, so distinct requests never collide in the
/// engine's replay guard.
fn fresh_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

fn node(id: &str) -> NodeId {
    NodeId::from(id)
}

fn operator(secret: &SecretKey) -> OperatorSecretKey {
    OperatorSecretKey::from_bytes(secret.to_bytes())
}

/// Sign a control request at the current wall clock with `op`.
fn authorize(origin: NodeId, op: &OperatorSecretKey, request: ControlRequest) -> SignedControl {
    SignedControl::authorize(
        origin,
        op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        request,
    )
    .expect("sign control request")
}

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

struct ChildSpec<'a> {
    id: &'a str,
    kind: ChildKind,
    slot: u8,
    date_joined: u64,
}

struct NodeSpec<'a> {
    secret: &'a SecretKey,
    operator: OperatorSecretKey,
    dir: &'a Path,
    node_id: &'a str,
    address: Option<&'a str>,
    children: &'a [ChildSpec<'a>],
    peers: Vec<PeerKeys>,
}

struct TestNode {
    router: Router,
    engine: Arc<Mutex<ControlNode>>,
    addr: EndpointAddr,
}

impl TestNode {
    async fn engine(&self) -> tokio::sync::MutexGuard<'_, ControlNode> {
        self.engine.lock().await
    }

    async fn shutdown(self) {
        self.router.shutdown().await.expect("router shutdown");
    }
}

async fn spawn_node(spec: NodeSpec<'_>) -> TestNode {
    let endpoint = bind(spec.secret).await;
    let addr = endpoint.addr();

    let mut record = RecordStore::open(spec.dir, spec.node_id).expect("open record");
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
        addr,
    }
}

async fn send(target: &Endpoint, addr: &EndpointAddr, signed: &SignedControl) -> ControlReply {
    ControlNode::send_direct_addr(target, addr.clone(), signed, timeout())
        .await
        .expect("control exchange")
}

/// A parent with children; mutations are driven by the node's own operator
/// (`SelfOperator`), the direct-path authority under the topology model.
struct TopologyFixture {
    parent: TestNode,
    node_op: OperatorSecretKey,
    admin_endpoint: Endpoint,
    parent_id: String,
    _dir: tempfile::TempDir,
}

impl TopologyFixture {
    async fn send_admin(&self, request: ControlRequest) -> ControlReply {
        let signed = authorize(node(&self.parent_id), &self.node_op, request);
        send(&self.admin_endpoint, &self.parent.addr, &signed).await
    }

    async fn send_signed(&self, signed: &SignedControl) -> ControlReply {
        send(&self.admin_endpoint, &self.parent.addr, signed).await
    }

    async fn pending(&self) -> Vec<OutboundControl> {
        self.parent.engine().await.take_pending_rebase()
    }

    async fn child_slot(&self, id: &str) -> Option<u8> {
        self.parent
            .engine()
            .await
            .record()
            .children
            .iter()
            .find(|child| child.child_id == id)
            .map(|child| child.slot)
    }

    async fn has_child(&self, id: &str) -> bool {
        self.parent
            .engine()
            .await
            .record()
            .children
            .iter()
            .any(|child| child.child_id == id)
    }

    /// Count `delivery` audit lines for `kind` (e.g. `"detach-notice"`).
    async fn delivery_lines(&self, kind: &str) -> usize {
        let dir = self.parent.engine().await.data_dir().to_path_buf();
        std::fs::read_to_string(dir.join("control_audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|line| line.contains(&format!("\"kind\":\"{kind}\"")))
            .count()
    }

    /// The most recent `admin-topology` audit object for `action`.
    async fn topology_audit(&self, action: &str) -> serde_json::Value {
        let dir = self.parent.engine().await.data_dir().to_path_buf();
        let text = std::fs::read_to_string(dir.join("control_audit.jsonl")).unwrap_or_default();
        text.lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .rfind(|value| {
                value.get("event").and_then(|v| v.as_str()) == Some("admin-topology")
                    && value.get("action").and_then(|v| v.as_str()) == Some(action)
            })
            .unwrap_or_else(|| panic!("no admin-topology '{action}' audit line"))
    }

    async fn shutdown(self) {
        self.admin_endpoint.close().await;
        self.parent.shutdown().await;
    }
}

async fn topology_fixture(
    address: Option<&str>,
    children: &[(&str, ChildKind, u8)],
) -> TopologyFixture {
    let parent_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let parent_op = operator(&parent_key);
    let dir = tempfile::tempdir().unwrap();
    let specs: Vec<ChildSpec> = children
        .iter()
        .map(|(id, kind, slot)| ChildSpec {
            id,
            kind: *kind,
            slot: *slot,
            date_joined: 0,
        })
        .collect();
    let parent = spawn_node(NodeSpec {
        secret: &parent_key,
        operator: parent_op.clone(),
        dir: dir.path(),
        node_id: &parent_id,
        address,
        children: &specs,
        peers: vec![],
    })
    .await;
    let admin_endpoint = bind(&SecretKey::generate()).await;
    TopologyFixture {
        parent,
        node_op: parent_op,
        admin_endpoint,
        parent_id,
        _dir: dir,
    }
}

#[tokio::test]
async fn admin_detaches_node_child_and_queues_notice() {
    let f = topology_fixture(
        Some("0"),
        &[
            ("node-child", ChildKind::Node, 1),
            ("user-leaf", ChildKind::User, 5),
        ],
    )
    .await;

    assert_eq!(
        f.send_admin(ControlRequest::AdminDetachChild(AdminDetachChild {
            child: node("node-child"),
        }))
        .await,
        ControlReply::Accepted
    );
    assert!(!f.has_child("node-child").await);
    assert!(f.has_child("user-leaf").await);

    // A detach removes the child, so a failed notice is not retained in the
    // retry queue; the delivery audit line proves exactly one was emitted.
    assert_eq!(f.delivery_lines("detach-notice").await, 1);

    // The `admin-topology` audit line is shape-uniform with the move line.
    let audit = f.topology_audit("detach").await;
    assert_eq!(audit["event"].as_str(), Some("admin-topology"));
    assert_eq!(audit["action"].as_str(), Some("detach"));
    assert_eq!(
        audit["actor"].as_str(),
        Some(f.node_op.public().to_string().as_str())
    );
    assert_eq!(audit["child"].as_str(), Some("node-child"));
    assert!(audit["requested_slot"].is_null());
    assert_eq!(audit["outcome"].as_str(), Some("accepted"));

    f.shutdown().await;
}

#[tokio::test]
async fn admin_moves_node_child_and_queues_rebase() {
    let f = topology_fixture(
        Some("0"),
        &[
            ("node-child", ChildKind::Node, 1),
            ("user-leaf", ChildKind::User, 5),
        ],
    )
    .await;

    assert_eq!(
        f.send_admin(ControlRequest::AdminMoveChild(AdminMoveChild {
            child: node("node-child"),
            slot: Some(0),
        }))
        .await,
        ControlReply::Accepted
    );
    assert_eq!(f.child_slot("node-child").await, Some(0));

    let epoch = f.parent.engine().await.record().address_epoch;
    assert!(epoch >= 1, "the re-slot bumped the routing epoch");
    let pending = f.pending().await;
    assert_eq!(pending.len(), 1, "exactly one Rebase");
    assert_eq!(pending[0].kind, OutboundKind::Rebase);
    let ControlRequest::Rebase(notice) = &pending[0].signed.request else {
        panic!("expected a Rebase notice");
    };
    assert_eq!(notice.node, node("node-child"));
    assert_eq!(notice.generation, epoch);
    assert_eq!(notice.address, "0.0".parse().unwrap());

    // The additive `admin-topology` audit line records the actor and the
    // before/after slots.
    let audit = f.topology_audit("move").await;
    assert_eq!(audit["event"].as_str(), Some("admin-topology"));
    assert_eq!(audit["action"].as_str(), Some("move"));
    assert_eq!(
        audit["actor"].as_str(),
        Some(f.node_op.public().to_string().as_str())
    );
    assert_eq!(audit["child"].as_str(), Some("node-child"));
    assert_eq!(audit["requested_slot"].as_u64(), Some(0));
    assert_eq!(audit["outcome"].as_str(), Some("accepted"));
    assert_eq!(audit["old_slot"].as_u64(), Some(1));
    assert_eq!(audit["new_slot"].as_u64(), Some(0));

    f.shutdown().await;
}

#[tokio::test]
async fn self_operator_uses_topology_admin_actions() {
    let f = topology_fixture(
        Some("0"),
        &[
            ("node-child", ChildKind::Node, 1),
            ("user-leaf", ChildKind::User, 5),
        ],
    )
    .await;

    let detach = authorize(
        node(&f.parent_id),
        &f.node_op,
        ControlRequest::AdminDetachChild(AdminDetachChild {
            child: node("node-child"),
        }),
    );
    assert_eq!(f.send_signed(&detach).await, ControlReply::Accepted);
    assert!(!f.has_child("node-child").await);

    // A user-leaf move is refused even for self-operator (shared helper parity).
    let move_child = authorize(
        node(&f.parent_id),
        &f.node_op,
        ControlRequest::AdminMoveChild(AdminMoveChild {
            child: node("user-leaf"),
            slot: None,
        }),
    );
    assert_eq!(
        f.send_signed(&move_child).await,
        ControlReply::Rejected(RejectCode::BadRequest)
    );

    f.shutdown().await;
}

#[tokio::test]
async fn admin_detach_user_child_is_accepted_and_noticed() {
    let f = topology_fixture(
        Some("0"),
        &[("user-leaf", ChildKind::User, 5)],
    )
    .await;
    assert_eq!(
        f.send_admin(ControlRequest::AdminDetachChild(AdminDetachChild {
            child: node("user-leaf"),
        }))
        .await,
        ControlReply::Accepted
    );
    assert!(!f.has_child("user-leaf").await);
    assert_eq!(f.delivery_lines("detach-notice").await, 1);
    f.shutdown().await;
}

#[tokio::test]
async fn admin_move_user_child_is_bad_request() {
    let f = topology_fixture(
        Some("0"),
        &[("user-leaf", ChildKind::User, 5)],
    )
    .await;
    assert_eq!(
        f.send_admin(ControlRequest::AdminMoveChild(AdminMoveChild {
            child: node("user-leaf"),
            slot: Some(0),
        }))
        .await,
        ControlReply::Rejected(RejectCode::BadRequest)
    );
    assert_eq!(f.child_slot("user-leaf").await, Some(5));
    assert!(f.pending().await.is_empty());
    f.shutdown().await;
}

#[tokio::test]
async fn admin_topology_not_a_child_is_not_found() {
    let f = topology_fixture(
        Some("0"),
        &[("node-child", ChildKind::Node, 1)],
    )
    .await;
    assert_eq!(
        f.send_admin(ControlRequest::AdminDetachChild(AdminDetachChild {
            child: node("ghost"),
        }))
        .await,
        ControlReply::Rejected(RejectCode::NotFound)
    );
    assert_eq!(
        f.send_admin(ControlRequest::AdminMoveChild(AdminMoveChild {
            child: node("ghost"),
            slot: None,
        }))
        .await,
        ControlReply::Rejected(RejectCode::NotFound)
    );
    f.shutdown().await;
}

#[tokio::test]
async fn admin_move_occupied_slot_is_slot_taken() {
    let f = topology_fixture(
        Some("0"),
        &[
            ("node-child", ChildKind::Node, 1),
            ("user-leaf", ChildKind::User, 5),
        ],
    )
    .await;
    assert_eq!(
        f.send_admin(ControlRequest::AdminMoveChild(AdminMoveChild {
            child: node("node-child"),
            slot: Some(5),
        }))
        .await,
        ControlReply::Rejected(RejectCode::SlotTaken)
    );
    assert_eq!(f.child_slot("node-child").await, Some(1));
    f.shutdown().await;
}

#[tokio::test]
async fn admin_move_slot_eight_is_slot_out_of_range() {
    let f = topology_fixture(
        Some("0"),
        &[("node-child", ChildKind::Node, 1)],
    )
    .await;
    assert_eq!(
        f.send_admin(ControlRequest::AdminMoveChild(AdminMoveChild {
            child: node("node-child"),
            slot: Some(8),
        }))
        .await,
        ControlReply::Rejected(RejectCode::SlotOutOfRange)
    );
    assert_eq!(f.child_slot("node-child").await, Some(1));
    f.shutdown().await;
}

#[tokio::test]
async fn admin_move_none_picks_lowest_free_and_same_slot_is_noop() {
    let f = topology_fixture(
        Some("0"),
        &[
            ("node-child", ChildKind::Node, 1),
            ("user-leaf", ChildKind::User, 5),
        ],
    )
    .await;

    // `None` picks the lowest slot free for this child: slot 0.
    assert_eq!(
        f.send_admin(ControlRequest::AdminMoveChild(AdminMoveChild {
            child: node("node-child"),
            slot: None,
        }))
        .await,
        ControlReply::Accepted
    );
    assert_eq!(f.child_slot("node-child").await, Some(0));
    assert_eq!(f.pending().await.len(), 1, "the real move queued one Rebase");

    // Same-slot move: idempotent `Accepted`, no notice.
    assert_eq!(
        f.send_admin(ControlRequest::AdminMoveChild(AdminMoveChild {
            child: node("node-child"),
            slot: Some(0),
        }))
        .await,
        ControlReply::Accepted
    );
    assert!(f.pending().await.is_empty(), "no-op move queues no notice");
    f.shutdown().await;
}

#[tokio::test]
async fn admin_move_without_address_succeeds_without_notice() {
    let f = topology_fixture(
        None,
        &[("node-child", ChildKind::Node, 1)],
    )
    .await;
    assert_eq!(
        f.send_admin(ControlRequest::AdminMoveChild(AdminMoveChild {
            child: node("node-child"),
            slot: Some(0),
        }))
        .await,
        ControlReply::Accepted
    );
    assert_eq!(f.child_slot("node-child").await, Some(0));
    assert!(
        f.pending().await.is_empty(),
        "no asserted address -> no Rebase notice (parity)"
    );
    f.shutdown().await;
}

#[tokio::test]
async fn admin_topology_replay_is_rejected() {
    let f = topology_fixture(
        Some("0"),
        &[
            ("node-child", ChildKind::Node, 1),
            ("user-leaf", ChildKind::User, 5),
        ],
    )
    .await;

    // Replay: the byte-identical frame is refused after the first detach.
    let signed = authorize(
        node(&f.parent_id),
        &f.node_op,
        ControlRequest::AdminDetachChild(AdminDetachChild {
            child: node("node-child"),
        }),
    );
    assert_eq!(f.send_signed(&signed).await, ControlReply::Accepted);
    assert_eq!(
        f.send_signed(&signed).await,
        ControlReply::Rejected(RejectCode::Replay)
    );

    f.shutdown().await;
}
