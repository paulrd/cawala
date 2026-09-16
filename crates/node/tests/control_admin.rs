//! Hermetic integration tests for the delegated-admin control surface.
//!
//! These drive the native node engine directly over `cawala/control/0` with
//! loopback endpoints and relays disabled, mirroring `tests/control.rs`. The
//! point is the *authority* model: a delegated admin (an operator key that is
//! neither the node's own operator nor a senior child) may use the admin
//! requests but can never touch the topology surface, while a peer cannot use
//! the admin surface at all.
//!
//! Delivery is exercised with an iroh [`MemoryLookup`] populated with each
//! applicant's bound [`EndpointAddr`], because `presets::Minimal` has no address
//! lookup and the node dials an applicant by id only. One test also documents
//! the no-lookup fallback (`Unreachable`).

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cawala_control::{
    ADMIN_GRANT_VERSION, AdminGrant, AdminJoinApprove, AdminJoinReject, AdminRedeliverJoin,
    AdminScope, CONTROL_REQUEST_MAX_TTL_SECS, CONTROL_REQUEST_TTL_SECS, ChildKind, ControlReply,
    ControlRequest, CreateChild, DEFAULT_ADMIN_TTL_SECS, DeliveryStatus, JoinRequest, NodeId,
    OperatorSecretKey, RejectCode, SetAddress, SignedAdminGrant, SignedControl,
};
use cawala_ledger::{LedgerSecretKey, PeerKeys, PeerRegistry, PeerRole};
use cawala_node::AdminStore;
use cawala_node::control::{ControlNode, spawn_control_only_on};
use cawala_node::control_store::ControlStore;
use cawala_node::record::RecordStore;
use iroh::address_lookup::memory::MemoryLookup;
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

/// A process-unique request nonce, so distinct requests are never conflated by
/// the engine's replay guard.
fn fresh_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

fn node(id: &str) -> NodeId {
    NodeId::from(id)
}

/// The operator key derived from an iroh node key (the node's operator key is
/// its iroh key, per `identity`/`ledger_keys` docs).
fn operator(secret: &SecretKey) -> OperatorSecretKey {
    OperatorSecretKey::from_bytes(secret.to_bytes())
}

fn ledger(seed: u8) -> LedgerSecretKey {
    LedgerSecretKey::from_bytes([seed; 32])
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

/// Sign an admin request addressed to `parent_id` with the delegated key.
fn admin_request(
    parent_id: &str,
    admin_op: &OperatorSecretKey,
    request: ControlRequest,
) -> SignedControl {
    authorize(node(parent_id), admin_op, request)
}

/// A node-signed admin grant scoped to `parent_id`.
fn admin_grant(
    parent_id: &str,
    parent_op: &OperatorSecretKey,
    admin_op: &OperatorSecretKey,
) -> SignedAdminGrant {
    let now = now_unix_seconds();
    let grant = AdminGrant {
        version: ADMIN_GRANT_VERSION,
        node: node(parent_id),
        admin: admin_op.public(),
        scope: AdminScope::Admin,
        granted_at: now,
        expiry: now + DEFAULT_ADMIN_TTL_SECS,
        label: Some("hermetic-admin".to_string()),
    };
    SignedAdminGrant::authorize(grant, parent_op).expect("sign admin grant")
}

// ---------------------------------------------------------------------------
// Harness (mirrors tests/control.rs)
// ---------------------------------------------------------------------------

/// Bind a hermetic endpoint on IPv4 loopback with relays disabled, optionally
/// with a shared [`MemoryLookup`] so a node can resolve an applicant by id.
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
    parent: Option<(&'a str, u8)>,
    children: &'a [ChildSpec<'a>],
    peers: Vec<PeerKeys>,
}

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

async fn spawn_node(spec: NodeSpec<'_>, lookup: Option<MemoryLookup>) -> TestNode {
    let endpoint = bind(spec.secret, lookup).await;
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
        AdminStore::empty(),
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

/// A `ChildKind::User` join request (browsers are always leaves).
fn user_join(applicant_id: &str, op: &OperatorSecretKey, desired_slot: Option<u8>) -> JoinRequest {
    JoinRequest {
        node: node(applicant_id),
        kind: ChildKind::User,
        operator: op.public(),
        ledger: None,
        desired_slot,
        location_hint: None,
        nonce: 7,
        expiry: u64::MAX,
    }
}

async fn send(sender: &Endpoint, target: &EndpointAddr, signed: &SignedControl) -> ControlReply {
    ControlNode::send_direct_addr(sender, target.clone(), signed, timeout())
        .await
        .expect("control exchange")
}

async fn wait_joined(applicant: &TestNode, parent_id: &str, address: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        {
            let engine = applicant.engine().await;
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
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A parent node with an asserted root address, a granted admin key, and a
/// separate transport endpoint for the admin. The temp dir is kept alive.
struct AdminFixture {
    parent: TestNode,
    parent_op: OperatorSecretKey,
    admin_op: OperatorSecretKey,
    admin_endpoint: Endpoint,
    _parent_dir: tempfile::TempDir,
}

/// Build the fixture, optionally binding the parent endpoint with `lookup`.
async fn admin_fixture(lookup: Option<MemoryLookup>) -> AdminFixture {
    let parent_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let parent_op = operator(&parent_key);
    let admin_op = OperatorSecretKey::from_bytes([0x5a; 32]);

    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(
        NodeSpec {
            secret: &parent_key,
            operator: parent_op.clone(),
            dir: parent_dir.path(),
            node_id: &parent_id,
            address: Some("0"),
            parent: None,
            children: &[],
            peers: vec![],
        },
        lookup,
    )
    .await;
    {
        let mut engine = parent.engine().await;
        engine
            .grant_admin(admin_grant(&parent_id, &parent_op, &admin_op))
            .expect("grant admin");
    }
    let admin_endpoint = bind(&SecretKey::generate(), None).await;
    AdminFixture {
        parent,
        parent_op,
        admin_op,
        admin_endpoint,
        _parent_dir: parent_dir,
    }
}

/// Spawn a fresh browser-like applicant (a leaf engine with no address) and
/// register its address in `lookup` so the node can dial it back.
async fn spawn_applicant(lookup: &MemoryLookup) -> (TestNode, tempfile::TempDir, SecretKey) {
    let key = SecretKey::generate();
    let op = operator(&key);
    let id = key.public().to_string();
    let dir = tempfile::tempdir().unwrap();
    let applicant = spawn_node(
        NodeSpec {
            secret: &key,
            operator: op,
            dir: dir.path(),
            node_id: &id,
            address: None,
            parent: None,
            children: &[],
            peers: vec![],
        },
        None,
    )
    .await;
    lookup.add_endpoint_info(applicant.endpoint.addr());
    (applicant, dir, key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The full delegated-admin flow: query pending joins, approve one (the
/// applicant learns its address over a MemoryLookup-resolved reverse dial),
/// reject another, and 404 an unknown redelivery.
#[tokio::test]
async fn delegated_admin_flow_approve_reject_and_applicant_joins() {
    let lookup = MemoryLookup::new();
    let fixture = admin_fixture(Some(lookup.clone())).await;
    let parent_id = fixture.parent.endpoint.id().to_string();

    // Applicant A: drives a full outbound join.
    let (applicant, _a_dir, a_key) = spawn_applicant(&lookup).await;
    let a_id = a_key.public().to_string();
    let a_op = operator(&a_key);

    let join = user_join(&a_id, &a_op, Some(3));
    applicant
        .engine()
        .await
        .begin_outbound_join(join.clone(), node(&parent_id), None)
        .expect("record outbound join");
    let signed_join = authorize(node(&a_id), &a_op, ControlRequest::Join(join));
    assert_eq!(
        send(&applicant.endpoint, &fixture.parent.addr, &signed_join).await,
        ControlReply::Pending
    );

    // Admin query lists the pending applicant.
    let query = admin_request(&parent_id, &fixture.admin_op, ControlRequest::AdminQuery);
    let reply = send(&fixture.admin_endpoint, &fixture.parent.addr, &query).await;
    let ControlReply::AdminSnapshot(snapshot) = reply else {
        panic!("expected AdminSnapshot, got {reply:?}");
    };
    assert_eq!(snapshot.node.node_id, node(&parent_id));
    assert!(
        snapshot.pending.iter().any(|p| p.child == node(&a_id)),
        "pending list must contain the applicant: {snapshot:?}"
    );

    // Admin approve assigns slot 3 / address 0.3 and reverse-dials the approval.
    let approve = admin_request(
        &parent_id,
        &fixture.admin_op,
        ControlRequest::AdminApproveJoin(AdminJoinApprove {
            child: node(&a_id),
            slot: Some(3),
        }),
    );
    let reply = send(&fixture.admin_endpoint, &fixture.parent.addr, &approve).await;
    let ControlReply::AdminApproved(approved) = reply else {
        panic!("expected AdminApproved, got {reply:?}");
    };
    assert_eq!(approved.child, node(&a_id));
    assert_eq!(approved.slot, 3);
    assert_eq!(approved.address, "0.3".parse().unwrap());
    assert_eq!(
        approved.delivery,
        DeliveryStatus::Delivered,
        "the MemoryLookup must let the node dial the applicant"
    );

    // Applicant A learned its parent link and address.
    wait_joined(&applicant, &parent_id, "0.3").await;

    // Applicant B: rejected; it also learns nothing and clears its outbound.
    let (applicant_b, _b_dir, b_key) = spawn_applicant(&lookup).await;
    let b_id = b_key.public().to_string();
    let b_op = operator(&b_key);
    let join_b = user_join(&b_id, &b_op, None);
    applicant_b
        .engine()
        .await
        .begin_outbound_join(join_b.clone(), node(&parent_id), None)
        .expect("record outbound join b");
    let signed_b = authorize(node(&b_id), &b_op, ControlRequest::Join(join_b));
    assert_eq!(
        send(&applicant_b.endpoint, &fixture.parent.addr, &signed_b).await,
        ControlReply::Pending
    );
    let reject = admin_request(
        &parent_id,
        &fixture.admin_op,
        ControlRequest::AdminRejectJoin(AdminJoinReject {
            child: node(&b_id),
            reason: Some("hermetic reject".to_string()),
        }),
    );
    let reply = send(&fixture.admin_endpoint, &fixture.parent.addr, &reject).await;
    let ControlReply::AdminRejected(rejected) = reply else {
        panic!("expected AdminRejected, got {reply:?}");
    };
    assert_eq!(rejected.child, node(&b_id));
    assert_eq!(rejected.delivery, DeliveryStatus::Delivered);
    assert!(
        applicant_b.engine().await.pending().outbound().is_none(),
        "the reverse-dialed rejection clears the applicant's outbound join"
    );

    // Redelivering an unknown child is NotFound.
    let redeliver = admin_request(
        &parent_id,
        &fixture.admin_op,
        ControlRequest::AdminRedeliverJoin(AdminRedeliverJoin {
            child: node("ghost"),
        }),
    );
    assert_eq!(
        send(&fixture.admin_endpoint, &fixture.parent.addr, &redeliver).await,
        ControlReply::Rejected(RejectCode::NotFound)
    );

    // Audit records the admin request and the delivery attempt.
    let audit_path = fixture
        .parent
        .engine()
        .await
        .data_dir()
        .join("control_audit.jsonl");
    let audit = std::fs::read_to_string(audit_path).expect("audit log");
    assert!(audit.contains("\"event\":\"request\""), "{audit}");
    assert!(audit.contains("\"event\":\"delivery\""), "{audit}");
    assert!(audit.contains("admin-query"), "{audit}");

    fixture.admin_endpoint.close().await;
    applicant.shutdown().await;
    applicant_b.shutdown().await;
    fixture.parent.shutdown().await;
}

/// Without an address lookup the node cannot dial an applicant by id, so the
/// reply's delivery is the documented `Unreachable` fallback (the authority
/// decision still stands).
#[tokio::test]
async fn approve_without_address_lookup_reports_unreachable() {
    let fixture = admin_fixture(None).await;
    let parent_id = fixture.parent.endpoint.id().to_string();

    // A pending applicant, driven by a bare transport endpoint (no engine).
    let a_key = SecretKey::generate();
    let a_id = a_key.public().to_string();
    let a_op = operator(&a_key);
    let transport = bind(&SecretKey::generate(), None).await;
    let join = user_join(&a_id, &a_op, None);
    let signed = authorize(node(&a_id), &a_op, ControlRequest::Join(join));
    assert_eq!(
        send(&transport, &fixture.parent.addr, &signed).await,
        ControlReply::Pending
    );

    let approve = admin_request(
        &parent_id,
        &fixture.admin_op,
        ControlRequest::AdminApproveJoin(AdminJoinApprove {
            child: node(&a_id),
            slot: None,
        }),
    );
    let reply = send(&fixture.admin_endpoint, &fixture.parent.addr, &approve).await;
    let ControlReply::AdminApproved(approved) = reply else {
        panic!("expected AdminApproved, got {reply:?}");
    };
    assert_eq!(approved.delivery, DeliveryStatus::Unreachable);

    transport.close().await;
    fixture.admin_endpoint.close().await;
    fixture.parent.shutdown().await;
}

/// A delegated admin can use the admin surface but not the topology surface.
#[tokio::test]
async fn delegated_admin_cannot_use_topology_surface() {
    let fixture = admin_fixture(None).await;
    let parent_id = fixture.parent.endpoint.id().to_string();

    let requests = [
        ControlRequest::Query,
        ControlRequest::SetAddress(SetAddress {
            address: Some("0".parse().unwrap()),
        }),
        ControlRequest::CreateChild(CreateChild {
            child: node("new-child"),
            operator: OperatorSecretKey::from_bytes([9u8; 32]).public(),
            ledger: Some(ledger(9).public()),
            kind: ChildKind::Node,
            slot: Some(1),
            date_joined: 1,
        }),
    ];
    for request in requests {
        let signed = admin_request(&parent_id, &fixture.admin_op, request);
        assert_eq!(
            send(&fixture.admin_endpoint, &fixture.parent.addr, &signed).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
    }

    fixture.admin_endpoint.close().await;
    fixture.parent.shutdown().await;
}

/// A senior child (peer path) cannot use the admin surface.
#[tokio::test]
async fn senior_child_cannot_use_admin_surface() {
    let parent_key = SecretKey::generate();
    let child_key = SecretKey::generate();
    let parent_id = parent_key.public().to_string();
    let child_id = child_key.public().to_string();
    let parent_op = operator(&parent_key);
    let child_op = operator(&child_key);

    let children = [ChildSpec {
        id: &child_id,
        kind: ChildKind::Node,
        slot: 0,
        date_joined: 1,
    }];
    let parent_dir = tempfile::tempdir().unwrap();
    let parent = spawn_node(
        NodeSpec {
            secret: &parent_key,
            operator: parent_op,
            dir: parent_dir.path(),
            node_id: &parent_id,
            address: Some("0"),
            parent: None,
            children: &children,
            peers: vec![PeerKeys {
                node_id: node(&child_id),
                operator: child_op.public(),
                ledger: Some(ledger(11).public()),
                role: PeerRole::Node,
            }],
        },
        None,
    )
    .await;

    // A peer signs with its own origin, as the peer path does.
    let transport = bind(&SecretKey::generate(), None).await;
    let signed = authorize(node(&child_id), &child_op, ControlRequest::AdminQuery);
    assert_eq!(
        send(&transport, &parent.addr, &signed).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );

    transport.close().await;
    parent.shutdown().await;
}

/// Expiry: a past `expiry` is `Expired`; an over-long TTL is `BadRequest`.
#[tokio::test]
async fn expiry_window_is_enforced() {
    let fixture = admin_fixture(None).await;
    let parent_id = fixture.parent.endpoint.id().to_string();
    let now = now_unix_seconds();

    let expired = SignedControl::authorize(
        node(&parent_id),
        &fixture.admin_op,
        fresh_nonce(),
        now.saturating_sub(1),
        ControlRequest::AdminQuery,
    )
    .unwrap();
    assert_eq!(
        send(&fixture.admin_endpoint, &fixture.parent.addr, &expired).await,
        ControlReply::Rejected(RejectCode::Expired)
    );

    let too_long = SignedControl::authorize(
        node(&parent_id),
        &fixture.admin_op,
        fresh_nonce(),
        now + CONTROL_REQUEST_MAX_TTL_SECS + 1,
        ControlRequest::AdminQuery,
    )
    .unwrap();
    assert_eq!(
        send(&fixture.admin_endpoint, &fixture.parent.addr, &too_long).await,
        ControlReply::Rejected(RejectCode::BadRequest)
    );

    fixture.admin_endpoint.close().await;
    fixture.parent.shutdown().await;
}

/// The byte-identical frame cannot be replayed.
#[tokio::test]
async fn replay_of_identical_frame_is_rejected() {
    let fixture = admin_fixture(None).await;
    let parent_id = fixture.parent.endpoint.id().to_string();

    let signed = admin_request(&parent_id, &fixture.admin_op, ControlRequest::AdminQuery);
    assert!(matches!(
        send(&fixture.admin_endpoint, &fixture.parent.addr, &signed).await,
        ControlReply::AdminSnapshot(_)
    ));
    assert_eq!(
        send(&fixture.admin_endpoint, &fixture.parent.addr, &signed).await,
        ControlReply::Rejected(RejectCode::Replay)
    );

    fixture.admin_endpoint.close().await;
    fixture.parent.shutdown().await;
}

/// Revoking the grant removes the delegated authority.
#[tokio::test]
async fn revoked_admin_is_unauthorized() {
    let fixture = admin_fixture(None).await;
    let parent_id = fixture.parent.endpoint.id().to_string();

    // Sanity: the grant is live.
    let query = admin_request(&parent_id, &fixture.admin_op, ControlRequest::AdminQuery);
    assert!(matches!(
        send(&fixture.admin_endpoint, &fixture.parent.addr, &query).await,
        ControlReply::AdminSnapshot(_)
    ));

    let removed = fixture
        .parent
        .engine()
        .await
        .revoke_admin(&fixture.admin_op.public())
        .unwrap();
    assert!(removed, "grant should have been present");

    let after = admin_request(&parent_id, &fixture.admin_op, ControlRequest::AdminQuery);
    assert_eq!(
        send(&fixture.admin_endpoint, &fixture.parent.addr, &after).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );

    fixture.admin_endpoint.close().await;
    fixture.parent.shutdown().await;
}

/// The node's own operator still works (self-admin is unaffected).
#[tokio::test]
async fn self_operator_still_authorized() {
    let fixture = admin_fixture(None).await;
    let parent_id = fixture.parent.endpoint.id().to_string();

    let signed = authorize(node(&parent_id), &fixture.parent_op, ControlRequest::Query);
    assert!(matches!(
        send(&fixture.admin_endpoint, &fixture.parent.addr, &signed).await,
        ControlReply::Snapshot(_)
    ));

    fixture.admin_endpoint.close().await;
    fixture.parent.shutdown().await;
}
