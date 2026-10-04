//! Hermetic integration tests for the read-only `AdminLedgerQuery` over the
//! real `cawala/control/0` protocol.
//!
//! Under topology authority the direct admin surface accepts only the node's
//! own operator (`Authority::SelfOperator`); remote child-admin authority is
//! proven in `admin_authority.rs`/`routed_control.rs`. A missing ledger handle
//! fails closed (`Internal`). Read-only: nothing here mutates the ledger or the
//! record.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cawala_control::{
    CONTROL_REQUEST_MAX_TTL_SECS, CONTROL_REQUEST_TTL_SECS, ChildKind, ControlReply,
    ControlRequest, NodeId, OperatorSecretKey, RejectCode, SignedControl,
};
use cawala_ledger::{LedgerPubKey, PeerRegistry};
use cawala_node::control::{ControlNode, spawn_control_only_on};
use cawala_node::control_store::ControlStore;
use cawala_node::ledger_service::LedgerService;
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

fn fresh_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}

fn node(id: &str) -> NodeId {
    NodeId::from(id)
}

fn operator(secret: &SecretKey) -> OperatorSecretKey {
    OperatorSecretKey::from_bytes(secret.to_bytes())
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

struct Fixture {
    router: Router,
    _engine: Arc<Mutex<ControlNode>>,
    addr: EndpointAddr,
    node_id: String,
    node_op: OperatorSecretKey,
    admin_endpoint: Endpoint,
    ledger_id: LedgerPubKey,
    _dir: tempfile::TempDir,
}

/// Build a node with a running ledger (50 to `user-a`, `user-b` listed but
/// unopened), a record at address `0`, and an optional attached ledger handle.
async fn fixture(with_ledger: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let secret = cawala_node::identity::load_or_create_secret_key(dir.path()).unwrap();
    let node_id = secret.public().to_string();
    let node_op = operator(&secret);
    let now = now_unix_seconds();

    let mut ledger = LedgerService::open(dir.path(), &node_id).unwrap();
    let ledger_id = ledger.ledger_key_public();
    ledger
        .ensure_account_open(&node("user-a"), ChildKind::User)
        .unwrap();
    ledger
        .fund(&node("user-a"), ChildKind::User, 50, &node_op, 1, now)
        .unwrap();

    let mut record = RecordStore::open(dir.path(), &node_id).unwrap();
    record.set_address("0".parse().unwrap()).unwrap();
    record
        .attach_child("user-a", ChildKind::User, Some(5), now)
        .unwrap();
    // Listed in the record but never opened in the ledger: a zero row.
    record
        .attach_child("user-b", ChildKind::User, Some(6), now)
        .unwrap();
    record.save().unwrap();

    let mut engine = ControlNode::new(
        dir.path().to_path_buf(),
        &node_id,
        node_op.clone(),
        record,
        PeerRegistry::new(),
        ControlStore::open(dir.path()).unwrap(),
        cawala_node::AdminStore::empty(),
    );
    if with_ledger {
        engine.attach_ledger(Arc::new(Mutex::new(ledger)));
    }
    let engine = Arc::new(Mutex::new(engine));

    let endpoint = bind(&secret).await;
    let addr = endpoint.addr();
    let router = spawn_control_only_on(endpoint.clone(), Arc::clone(&engine));
    let admin_endpoint = bind(&SecretKey::generate()).await;

    Fixture {
        router,
        _engine: engine,
        addr,
        node_id,
        node_op,
        admin_endpoint,
        ledger_id,
        _dir: dir,
    }
}

impl Fixture {
    async fn shutdown(self) {
        self.admin_endpoint.close().await;
        self.router.shutdown().await.expect("router shutdown");
    }

    /// An `AdminLedgerQuery` signed by `op` as this node's own origin,
    /// optionally declaring a different wire `version` (re-signed so the
    /// version byte is inside the signed preimage).
    fn query(&self, op: &OperatorSecretKey, version: Option<u8>) -> SignedControl {
        let nonce = fresh_nonce();
        let expiry = now_unix_seconds() + CONTROL_REQUEST_TTL_SECS;
        let mut signed = SignedControl::authorize(
            node(&self.node_id),
            op,
            nonce,
            expiry,
            ControlRequest::AdminLedgerQuery,
        )
        .unwrap();
        if let Some(version) = version {
            signed.version = version;
            signed.signature = op.sign(signed.signing_hash().as_bytes());
        }
        signed
    }
}

async fn send(sender: &Endpoint, target: &EndpointAddr, signed: &SignedControl) -> ControlReply {
    ControlNode::send_direct_addr(sender, target.clone(), signed, timeout())
        .await
        .expect("control exchange")
}

#[tokio::test]
async fn self_operator_reads_the_snapshot() {
    let fixture = fixture(true).await;
    let reply = send(
        &fixture.admin_endpoint,
        &fixture.addr,
        &fixture.query(&fixture.node_op, None),
    )
    .await;

    let ControlReply::AdminLedgerSnapshot(snapshot) = reply else {
        panic!("expected AdminLedgerSnapshot, got {reply:?}");
    };
    assert_eq!(snapshot.node_id, node(&fixture.node_id));
    assert_eq!(snapshot.ledger_id, fixture.ledger_id);
    assert_eq!(snapshot.parent_balance, 0);
    assert_eq!(snapshot.equity, -50, "issue-funded liability, no parent asset");
    assert!(snapshot.height >= 1, "height = {}", snapshot.height);
    assert!(snapshot.root);
    assert!(!snapshot.truncated);

    let a = snapshot
        .accounts
        .iter()
        .find(|row| row.id == node("user-a"))
        .expect("user-a row");
    assert_eq!(a.kind, Some(ChildKind::User));
    assert_eq!(a.slot, Some(5));
    assert_eq!(a.address, Some("0.5".parse().unwrap()));
    assert_eq!(a.balance, 50);

    let b = snapshot
        .accounts
        .iter()
        .find(|row| row.id == node("user-b"))
        .expect("user-b listed-unopened row");
    assert_eq!(b.balance, 0);
    assert_eq!(b.slot, Some(6));

    fixture.shutdown().await;
}

#[tokio::test]
async fn missing_ledger_handle_is_internal() {
    let fixture = fixture(false).await;
    assert_eq!(
        send(
            &fixture.admin_endpoint,
            &fixture.addr,
            &fixture.query(&fixture.node_op, None),
        )
        .await,
        ControlReply::Rejected(RejectCode::Internal)
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn v4_declared_ledger_query_is_bad_version() {
    let fixture = fixture(true).await;
    // A v4 frame cannot carry the v5-only `AdminLedgerQuery`; v4 is also below
    // the accepted window (7|8) entirely.
    assert_eq!(
        send(
            &fixture.admin_endpoint,
            &fixture.addr,
            &fixture.query(&fixture.node_op, Some(4)),
        )
        .await,
        ControlReply::Rejected(RejectCode::BadVersion)
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn replay_and_expiry_are_enforced() {
    let fixture = fixture(true).await;

    // Replay: the byte-identical frame is refused after the first read.
    let query = fixture.query(&fixture.node_op, None);
    assert!(matches!(
        send(&fixture.admin_endpoint, &fixture.addr, &query).await,
        ControlReply::AdminLedgerSnapshot(_)
    ));
    assert_eq!(
        send(&fixture.admin_endpoint, &fixture.addr, &query).await,
        ControlReply::Rejected(RejectCode::Replay)
    );

    // Expired frame.
    let expired = SignedControl::authorize(
        node(&fixture.node_id),
        &fixture.node_op,
        fresh_nonce(),
        now_unix_seconds().saturating_sub(60),
        ControlRequest::AdminLedgerQuery,
    )
    .unwrap();
    assert_eq!(
        send(&fixture.admin_endpoint, &fixture.addr, &expired).await,
        ControlReply::Rejected(RejectCode::Expired)
    );

    // Over-TTL frame.
    let too_long = SignedControl::authorize(
        node(&fixture.node_id),
        &fixture.node_op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_MAX_TTL_SECS + 60,
        ControlRequest::AdminLedgerQuery,
    )
    .unwrap();
    assert_eq!(
        send(&fixture.admin_endpoint, &fixture.addr, &too_long).await,
        ControlReply::Rejected(RejectCode::BadRequest)
    );

    fixture.shutdown().await;
}
