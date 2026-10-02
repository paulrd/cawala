//! Hermetic integration tests for the read-only `AdminLedgerQuery` (P3) over
//! the real `cawala/control/0` protocol.
//!
//! A value-scoped v2 grant (or the node's own operator) reads the node's books
//! from a temp ledger; joins-only/v1 grants and a missing ledger handle fail
//! closed. Read-only: nothing here mutates the ledger or the record.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cawala_control::{
    ADMIN_GRANT_V1_VERSION, ADMIN_GRANT_VERSION, AdminGrant, AdminGrantV2, AdminScope, AdminScopes,
    CONTROL_REQUEST_MAX_TTL_SECS, CONTROL_REQUEST_TTL_SECS, ChildKind, ControlReply,
    ControlRequest, DEFAULT_ADMIN_TTL_SECS, MAX_VALUE_ADMIN_TTL_SECS, NodeId, OperatorSecretKey,
    RejectCode, SignedAdminGrant, SignedAdminGrantV2, SignedControl,
};
use cawala_ledger::{LedgerPubKey, PeerRegistry};
use cawala_node::admin_store::StoredGrant;
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

/// Which grant form the fixture installs.
#[derive(Clone, Copy, Debug)]
enum GrantForm {
    Value,
    JoinsOnly,
    LegacyV1,
}

struct Fixture {
    router: Router,
    engine: Arc<Mutex<ControlNode>>,
    addr: EndpointAddr,
    node_id: String,
    node_op: OperatorSecretKey,
    admin_op: OperatorSecretKey,
    admin_endpoint: Endpoint,
    ledger_id: LedgerPubKey,
    _dir: tempfile::TempDir,
}

fn v2_grant(
    node_id: &str,
    admin: cawala_ledger::OperatorPubKey,
    scopes: AdminScopes,
    now: u64,
) -> AdminGrantV2 {
    let ttl = if scopes.value {
        DEFAULT_ADMIN_TTL_SECS.min(MAX_VALUE_ADMIN_TTL_SECS)
    } else {
        DEFAULT_ADMIN_TTL_SECS
    };
    AdminGrantV2 {
        version: ADMIN_GRANT_VERSION,
        node: node(node_id),
        admin,
        scopes,
        granted_at: now,
        expiry: now + ttl,
        label: Some("p3-hermetic".to_string()),
    }
}

/// Build a node with a running ledger (50 to `user-a`, `user-b` listed but
/// unopened), a record at address `0`, and an optional attached ledger handle.
async fn fixture(form: GrantForm, with_ledger: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let secret = cawala_node::identity::load_or_create_secret_key(dir.path()).unwrap();
    let node_id = secret.public().to_string();
    let node_op = operator(&secret);
    let admin_op = OperatorSecretKey::from_bytes([0x5a; 32]);
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

    {
        let mut e = engine.lock().await;
        match form {
            GrantForm::Value => {
                let grant = v2_grant(
                    &node_id,
                    admin_op.public(),
                    AdminScopes {
                        joins: false,
                        topology: false,
                        value: true,
                    },
                    now,
                );
                e.grant_admin(StoredGrant::V2(
                    SignedAdminGrantV2::authorize(grant, &node_op).unwrap(),
                ))
                .unwrap();
            }
            GrantForm::JoinsOnly => {
                let grant = v2_grant(&node_id, admin_op.public(), AdminScopes::v1(), now);
                e.grant_admin(StoredGrant::V2(
                    SignedAdminGrantV2::authorize(grant, &node_op).unwrap(),
                ))
                .unwrap();
            }
            GrantForm::LegacyV1 => {
                let grant = AdminGrant {
                    version: ADMIN_GRANT_V1_VERSION,
                    node: node(&node_id),
                    admin: admin_op.public(),
                    scope: AdminScope::Admin,
                    granted_at: now.saturating_sub(1),
                    expiry: now + DEFAULT_ADMIN_TTL_SECS,
                    label: Some("p3-v1".to_string()),
                };
                e.grant_admin(StoredGrant::V1(
                    SignedAdminGrant::authorize(grant, &node_op).unwrap(),
                ))
                .unwrap();
            }
        }
    }

    let endpoint = bind(&secret).await;
    let addr = endpoint.addr();
    let router = spawn_control_only_on(endpoint.clone(), Arc::clone(&engine));
    let admin_endpoint = bind(&SecretKey::generate()).await;

    Fixture {
        router,
        engine,
        addr,
        node_id,
        node_op,
        admin_op,
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
async fn value_grant_reads_the_snapshot() {
    let fixture = fixture(GrantForm::Value, true).await;
    let reply = send(
        &fixture.admin_endpoint,
        &fixture.addr,
        &fixture.query(&fixture.admin_op, None),
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
async fn joins_only_and_legacy_v1_grants_are_unauthorized() {
    for form in [GrantForm::JoinsOnly, GrantForm::LegacyV1] {
        let fixture = fixture(form, true).await;
        assert_eq!(
            send(
                &fixture.admin_endpoint,
                &fixture.addr,
                &fixture.query(&fixture.admin_op, None),
            )
            .await,
            ControlReply::Rejected(RejectCode::Unauthorized),
            "{form:?} must not read the ledger"
        );
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn missing_ledger_handle_is_internal() {
    let fixture = fixture(GrantForm::Value, false).await;
    assert_eq!(
        send(
            &fixture.admin_endpoint,
            &fixture.addr,
            &fixture.query(&fixture.admin_op, None),
        )
        .await,
        ControlReply::Rejected(RejectCode::Internal)
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn self_operator_reads_the_snapshot() {
    let fixture = fixture(GrantForm::JoinsOnly, true).await;
    // The node's own operator does not need a delegated grant.
    let reply = send(
        &fixture.admin_endpoint,
        &fixture.addr,
        &fixture.query(&fixture.node_op.clone(), None),
    )
    .await;
    assert!(
        matches!(reply, ControlReply::AdminLedgerSnapshot(_)),
        "self-operator must read the ledger, got {reply:?}"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn v4_declared_ledger_query_is_bad_version() {
    let fixture = fixture(GrantForm::Value, true).await;
    // A v4 frame cannot carry the v5-only `AdminLedgerQuery`.
    assert_eq!(
        send(
            &fixture.admin_endpoint,
            &fixture.addr,
            &fixture.query(&fixture.admin_op, Some(4)),
        )
        .await,
        ControlReply::Rejected(RejectCode::BadVersion)
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn replay_revoke_expiry_and_over_ttl() {
    let fixture = fixture(GrantForm::Value, true).await;

    // Replay: the byte-identical frame is refused after the first read.
    let query = fixture.query(&fixture.admin_op, None);
    assert!(matches!(
        send(&fixture.admin_endpoint, &fixture.addr, &query).await,
        ControlReply::AdminLedgerSnapshot(_)
    ));
    assert_eq!(
        send(&fixture.admin_endpoint, &fixture.addr, &query).await,
        ControlReply::Rejected(RejectCode::Replay)
    );

    // Revoke: the delegated authority is gone; self-operator would still work.
    assert!(
        fixture
            .engine
            .lock()
            .await
            .revoke_admin(&fixture.admin_op.public())
            .unwrap()
    );
    assert_eq!(
        send(
            &fixture.admin_endpoint,
            &fixture.addr,
            &fixture.query(&fixture.admin_op, None),
        )
        .await,
        ControlReply::Rejected(RejectCode::Unauthorized)
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
