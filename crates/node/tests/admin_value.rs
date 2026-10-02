//! Hermetic integration tests for delegated value administration (P5) over the
//! real `cawala/control/0` protocol.
//!
//! A value-scoped v2 grant (or the node's own operator) issues and burns value
//! on a child account; the node executes with its own operator/ledger keys. The
//! tests cover idempotency (including after reopen), operator caps,
//! deny-by-default policy, audit lines, and the failure modes.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cawala_control::{
    ADMIN_GRANT_V1_VERSION, ADMIN_GRANT_VERSION, AdminGrant, AdminGrantV2, AdminScope, AdminScopes,
    AdminValueDirection, AdminValueRequest, CONTROL_REQUEST_MAX_TTL_SECS, CONTROL_REQUEST_TTL_SECS,
    ChildKind, ControlReply, ControlRequest, DEFAULT_ADMIN_TTL_SECS, MAX_VALUE_ADMIN_TTL_SECS,
    NodeId, OperatorSecretKey, RejectCode, SignedAdminGrant, SignedAdminGrantV2, SignedControl,
    ValueRequestId,
};
use cawala_ledger::PeerRegistry;
use cawala_node::admin_store::StoredGrant;
use cawala_node::control::{ControlNode, spawn_control_only_on};
use cawala_node::control_store::ControlStore;
use cawala_node::ledger_service::LedgerService;
use cawala_node::record::RecordStore;
use cawala_node::{VALUE_POLICY_VERSION, ValueLimits, ValuePolicy};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use tokio::sync::Mutex;

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

#[derive(Clone, Copy, Debug)]
enum GrantForm {
    Value,
    JoinsOnly,
    TopologyOnly,
    LegacyV1,
}

fn generous_limits() -> ValueLimits {
    ValueLimits {
        per_request_max: 1_000_000,
        window_secs: 86_400,
        window_max: 1_000_000,
        per_account_max: 1_000_000,
    }
}

fn write_policy(dir: &Path, limits: ValueLimits) {
    ValuePolicy {
        version: VALUE_POLICY_VERSION,
        defaults: limits,
        admins: std::collections::BTreeMap::new(),
    }
    .save(dir)
    .unwrap();
}

struct Fixture {
    router: Router,
    engine: Arc<Mutex<ControlNode>>,
    addr: EndpointAddr,
    dir: tempfile::TempDir,
    node_id: String,
    node_op: OperatorSecretKey,
    admin_op: OperatorSecretKey,
    admin_endpoint: Endpoint,
}

fn v2_grant(node_id: &str, admin: cawala_ledger::OperatorPubKey, scopes: AdminScopes, now: u64) -> AdminGrantV2 {
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
        label: Some("p5-hermetic".to_string()),
    }
}

/// Build a node with a running ledger, a policy (unless `policy` is `None`),
/// a record that lists `user-a`, and the given grant form.
async fn fixture(form: GrantForm, policy: Option<ValueLimits>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let secret = cawala_node::identity::load_or_create_secret_key(dir.path()).unwrap();
    let node_id = secret.public().to_string();
    let node_op = operator(&secret);
    let admin_op = OperatorSecretKey::from_bytes([0x5a; 32]);
    let now = now_unix_seconds();

    if let Some(limits) = policy {
        write_policy(dir.path(), limits);
    }

    let mut ledger = LedgerService::open(dir.path(), &node_id).unwrap();
    ledger
        .ensure_account_open(&node("user-a"), ChildKind::User)
        .unwrap();

    let mut record = RecordStore::open(dir.path(), &node_id).unwrap();
    record.set_address("0".parse().unwrap()).unwrap();
    record
        .attach_child("user-a", ChildKind::User, Some(5), now)
        .unwrap();
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
    engine.attach_ledger(Arc::new(Mutex::new(ledger)));
    let engine = Arc::new(Mutex::new(engine));

    {
        let mut e = engine.lock().await;
        let grant = match form {
            GrantForm::Value => StoredGrant::V2(SignedAdminGrantV2::authorize(
                v2_grant(
                    &node_id,
                    admin_op.public(),
                    AdminScopes {
                        joins: false,
                        topology: false,
                        value: true,
                    },
                    now,
                ),
                &node_op,
            )
            .unwrap()),
            GrantForm::JoinsOnly => StoredGrant::V2(SignedAdminGrantV2::authorize(
                v2_grant(&node_id, admin_op.public(), AdminScopes::v1(), now),
                &node_op,
            )
            .unwrap()),
            GrantForm::TopologyOnly => StoredGrant::V2(SignedAdminGrantV2::authorize(
                v2_grant(
                    &node_id,
                    admin_op.public(),
                    AdminScopes {
                        joins: false,
                        topology: true,
                        value: false,
                    },
                    now,
                ),
                &node_op,
            )
            .unwrap()),
            GrantForm::LegacyV1 => StoredGrant::V1(
                SignedAdminGrant::authorize(
                    AdminGrant {
                        version: ADMIN_GRANT_V1_VERSION,
                        node: node(&node_id),
                        admin: admin_op.public(),
                        scope: AdminScope::Admin,
                        granted_at: now,
                        expiry: now + DEFAULT_ADMIN_TTL_SECS,
                        label: Some("p5-v1".to_string()),
                    },
                    &node_op,
                )
                .unwrap(),
            ),
        };
        e.grant_admin(grant).unwrap();
    }

    let endpoint = bind(&secret).await;
    let addr = endpoint.addr();
    let router = spawn_control_only_on(endpoint.clone(), Arc::clone(&engine));
    let admin_endpoint = bind(&SecretKey::generate()).await;

    Fixture {
        router,
        engine,
        addr,
        dir,
        node_id,
        node_op,
        admin_op,
        admin_endpoint,
    }
}

impl Fixture {
    async fn shutdown(self) {
        self.admin_endpoint.close().await;
        self.router.shutdown().await.expect("router shutdown");
    }

    async fn send(&self, request: ControlRequest) -> ControlReply {
        let signed = SignedControl::authorize(
            node(&self.node_id),
            &self.admin_op,
            fresh_nonce(),
            now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
            request,
        )
        .unwrap();
        self.send_signed(&signed).await
    }

    async fn send_signed(&self, signed: &SignedControl) -> ControlReply {
        ControlNode::send_direct_addr(&self.admin_endpoint, self.addr.clone(), signed, timeout())
            .await
            .expect("control exchange")
    }

    async fn height(&self) -> u64 {
        let handle = self.engine.lock().await.ledger_handle().unwrap();
        let service = handle.lock().await;
        service.ledger().height()
    }

    async fn balance(&self, id: &str) -> u64 {
        let handle = self.engine.lock().await.ledger_handle().unwrap();
        let service = handle.lock().await;
        service.balance_of(&node(id)).get()
    }
}

fn issue_request(request_id: ValueRequestId, account: &str, amount: u64) -> ControlRequest {
    ControlRequest::AdminIssue(AdminValueRequest {
        request_id,
        account: node(account),
        amount,
        reason: "integration test".to_string(),
    })
}

fn burn_request(request_id: ValueRequestId, account: &str, amount: u64) -> ControlRequest {
    ControlRequest::AdminBurn(AdminValueRequest {
        request_id,
        account: node(account),
        amount,
        reason: "integration test".to_string(),
    })
}

fn request_id(seed: u8) -> ValueRequestId {
    ValueRequestId::from_bytes([seed; 16])
}

#[tokio::test]
async fn value_grant_issues_burns_and_snapshot_reflects_it() {
    let f = fixture(GrantForm::Value, Some(generous_limits())).await;

    let reply = f
        .send(issue_request(request_id(1), "user-a", 25))
        .await;
    let ControlReply::AdminValueApplied(applied) = reply else {
        panic!("expected AdminValueApplied, got {reply:?}");
    };
    assert_eq!(applied.direction, AdminValueDirection::Issue);
    assert_eq!(applied.amount, 25);
    assert_eq!(applied.balance_after, 25);
    assert!(!applied.duplicate);
    assert_eq!(f.balance("user-a").await, 25);

    let reply = f.send(burn_request(request_id(2), "user-a", 10)).await;
    let ControlReply::AdminValueApplied(applied) = reply else {
        panic!("expected AdminValueApplied, got {reply:?}");
    };
    assert_eq!(applied.direction, AdminValueDirection::Burn);
    assert_eq!(applied.balance_after, 15);
    assert_eq!(f.balance("user-a").await, 15);

    // The read-only P3 view agrees (equity is negative: a 15 liability).
    let snapshot = f
        .send(ControlRequest::AdminLedgerQuery)
        .await;
    let ControlReply::AdminLedgerSnapshot(snapshot) = snapshot else {
        panic!("expected AdminLedgerSnapshot");
    };
    let row = snapshot
        .accounts
        .iter()
        .find(|row| row.id == node("user-a"))
        .unwrap();
    assert_eq!(row.balance, 15);
    assert_eq!(snapshot.equity, -15);

    // Audit: intent + applied lines are present.
    let audit = std::fs::read_to_string(f.dir.path().join("control_audit.jsonl")).unwrap();
    assert!(audit.contains("\"event\":\"admin-value\""), "{audit}");
    assert!(audit.contains("\"phase\":\"intent\""), "{audit}");
    assert!(audit.contains("\"phase\":\"applied\""), "{audit}");
    assert!(audit.contains("\"order_hash\""), "{audit}");
    assert!(audit.contains("\"entry_hash\""), "{audit}");

    f.shutdown().await;
}

#[tokio::test]
async fn duplicate_request_id_dedupes_including_after_reopen() {
    let f = fixture(GrantForm::Value, Some(generous_limits())).await;
    let id = request_id(7);

    let first = f.send(issue_request(id, "user-a", 40)).await;
    let ControlReply::AdminValueApplied(first) = first else {
        panic!("expected AdminValueApplied");
    };
    assert!(!first.duplicate);
    let height = f.height().await;
    assert_eq!(first.seq, height);

    // A fresh control nonce, same request id/params -> duplicate, same entry.
    let second = f.send(issue_request(id, "user-a", 40)).await;
    let ControlReply::AdminValueApplied(second) = second else {
        panic!("expected AdminValueApplied");
    };
    assert!(second.duplicate);
    assert_eq!(second.seq, first.seq);
    assert_eq!(second.entry_hash, first.entry_hash);
    assert_eq!(f.height().await, height, "duplicate appends nothing");

    // Conflict: same id, different amount -> BadRequest.
    assert_eq!(
        f.send(issue_request(id, "user-a", 41)).await,
        ControlReply::Rejected(RejectCode::BadRequest)
    );

    // Reopen the ledger from disk: the derived index still dedupes.
    {
        let mut reopened = LedgerService::open(f.dir.path(), &f.node_id).unwrap();
        let dup = reopened
            .admin_value_apply(
                AdminValueDirection::Issue,
                &node("user-a"),
                ChildKind::User,
                40,
                &f.admin_op.public(),
                id,
                generous_limits(),
                now_unix_seconds(),
            )
            .unwrap();
        assert!(dup.duplicate);
        assert_eq!(dup.entry_hash, first.entry_hash);
    }
    let third = f.send(issue_request(id, "user-a", 40)).await;
    let ControlReply::AdminValueApplied(third) = third else {
        panic!("expected AdminValueApplied");
    };
    assert!(third.duplicate);
    assert_eq!(third.entry_hash, first.entry_hash);
    assert_eq!(f.height().await, height);

    f.shutdown().await;
}

#[tokio::test]
async fn absent_and_corrupt_policy_fail_closed_internal() {
    // No policy file at all: every value op is Internal.
    let f = fixture(GrantForm::Value, None).await;
    assert_eq!(
        f.send(issue_request(request_id(1), "user-a", 1)).await,
        ControlReply::Rejected(RejectCode::Internal)
    );
    assert_eq!(f.height().await, 0, "no ledger call without a valid policy");
    f.shutdown().await;

    // Corrupt policy file: same refusal.
    let f = fixture(GrantForm::Value, Some(generous_limits())).await;
    std::fs::write(f.dir.path().join(cawala_node::VALUE_POLICY_FILE), b"{ not json").unwrap();
    assert_eq!(
        f.send(issue_request(request_id(2), "user-a", 1)).await,
        ControlReply::Rejected(RejectCode::Internal)
    );
    assert_eq!(f.height().await, 0);
    f.shutdown().await;
}

#[tokio::test]
async fn caps_and_overdraw_are_mapped() {
    // per_request_max 10, issue 11 -> LimitExceeded.
    let f = fixture(
        GrantForm::Value,
        Some(ValueLimits {
            per_request_max: 10,
            window_secs: 86_400,
            window_max: 1_000,
            per_account_max: 1_000,
        }),
    )
    .await;
    assert_eq!(
        f.send(issue_request(request_id(1), "user-a", 11)).await,
        ControlReply::Rejected(RejectCode::LimitExceeded)
    );
    assert_eq!(f.height().await, 0);
    f.shutdown().await;

    // Burn over balance -> InsufficientBalance (unopened user-b -> 0).
    let f = fixture(GrantForm::Value, Some(generous_limits())).await;
    assert_eq!(
        f.send(burn_request(request_id(2), "user-b", 1)).await,
        ControlReply::Rejected(RejectCode::InsufficientBalance)
    );
    f.shutdown().await;
}

#[tokio::test]
async fn non_value_grants_are_unauthorized_and_self_operator_works() {
    for form in [GrantForm::JoinsOnly, GrantForm::TopologyOnly, GrantForm::LegacyV1] {
        let f = fixture(form, Some(generous_limits())).await;
        assert_eq!(
            f.send(issue_request(request_id(1), "user-a", 1)).await,
            ControlReply::Rejected(RejectCode::Unauthorized),
            "{form:?} must not issue"
        );
        assert_eq!(
            f.send(burn_request(request_id(2), "user-a", 1)).await,
            ControlReply::Rejected(RejectCode::Unauthorized),
            "{form:?} must not burn"
        );
        f.shutdown().await;
    }

    // The node's own operator bypasses the grant requirement.
    let f = fixture(GrantForm::JoinsOnly, Some(generous_limits())).await;
    let signed = SignedControl::authorize(
        node(&f.node_id),
        &f.node_op.clone(),
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        issue_request(request_id(3), "user-a", 5),
    )
    .unwrap();
    let reply = f.send_signed(&signed).await;
    assert!(
        matches!(reply, ControlReply::AdminValueApplied(_)),
        "self-operator must issue, got {reply:?}"
    );
    f.shutdown().await;
}

#[tokio::test]
async fn not_a_child_is_not_found_and_bad_request_bounds() {
    let f = fixture(GrantForm::Value, Some(generous_limits())).await;
    assert_eq!(
        f.send(issue_request(request_id(1), "ghost", 1)).await,
        ControlReply::Rejected(RejectCode::NotFound)
    );

    // Zero amount -> BadRequest.
    assert_eq!(
        f.send(issue_request(request_id(2), "user-a", 0)).await,
        ControlReply::Rejected(RejectCode::BadRequest)
    );
    // Zero request id -> BadRequest.
    assert_eq!(
        f.send(issue_request(ValueRequestId::from_bytes([0u8; 16]), "user-a", 1))
            .await,
        ControlReply::Rejected(RejectCode::BadRequest)
    );
    // Empty reason -> BadRequest.
    let empty_reason = ControlRequest::AdminIssue(AdminValueRequest {
        request_id: request_id(3),
        account: node("user-a"),
        amount: 1,
        reason: String::new(),
    });
    assert_eq!(
        f.send(empty_reason).await,
        ControlReply::Rejected(RejectCode::BadRequest)
    );
    f.shutdown().await;
}

#[tokio::test]
async fn replay_expiry_and_revoke_are_unchanged() {
    let f = fixture(GrantForm::Value, Some(generous_limits())).await;

    // Frame replay: the byte-identical control frame.
    let signed = SignedControl::authorize(
        node(&f.node_id),
        &f.admin_op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        issue_request(request_id(1), "user-a", 5),
    )
    .unwrap();
    assert!(matches!(
        f.send_signed(&signed).await,
        ControlReply::AdminValueApplied(_)
    ));
    assert_eq!(
        f.send_signed(&signed).await,
        ControlReply::Rejected(RejectCode::Replay)
    );

    // Over-TTL frame.
    let too_long = SignedControl::authorize(
        node(&f.node_id),
        &f.node_op.clone(),
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_MAX_TTL_SECS + 60,
        issue_request(request_id(2), "user-a", 5),
    )
    .unwrap();
    assert_eq!(
        f.send_signed(&too_long).await,
        ControlReply::Rejected(RejectCode::BadRequest)
    );

    // Revoke: the delegated authority is gone.
    assert!(
        f.engine
            .lock()
            .await
            .revoke_admin(&f.admin_op.public())
            .unwrap()
    );
    assert_eq!(
        f.send(issue_request(request_id(3), "user-a", 5)).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
    f.shutdown().await;
}

#[tokio::test]
async fn audit_intent_failure_refuses_without_appending() {
    let f = fixture(GrantForm::Value, Some(generous_limits())).await;
    // Make the audit path unwritable: replace the file with a directory so the
    // fail-closed intent append cannot open it.
    let audit_path = f.dir.path().join("control_audit.jsonl");
    let _ = std::fs::remove_file(&audit_path);
    std::fs::create_dir(&audit_path).unwrap();

    assert_eq!(
        f.send(issue_request(request_id(1), "user-a", 5)).await,
        ControlReply::Rejected(RejectCode::Internal)
    );
    assert_eq!(f.height().await, 0, "no ledger call after a failed intent audit");
    f.shutdown().await;
}

#[tokio::test]
async fn missing_ledger_handle_is_internal() {
    // Build the fixture, then detach the ledger by swapping in an empty engine?
    // Simpler: a value request on an engine without a handle is Internal. The
    // fixture always attaches; use the no-handle path via `spawn_control_only`
    // is covered in admin_ledger. Here assert NotFound/Internal ordering holds:
    // an unknown child is NotFound even without a handle would be wrong, so use
    // a real child but no ledger by rebuilding without attach.
    let dir = tempfile::tempdir().unwrap();
    let secret = cawala_node::identity::load_or_create_secret_key(dir.path()).unwrap();
    let node_id = secret.public().to_string();
    let node_op = operator(&secret);
    write_policy(dir.path(), generous_limits());
    let mut record = RecordStore::open(dir.path(), &node_id).unwrap();
    record.set_address("0".parse().unwrap()).unwrap();
    record
        .attach_child("user-a", ChildKind::User, Some(5), now_unix_seconds())
        .unwrap();
    record.save().unwrap();
    let engine = ControlNode::new(
        dir.path().to_path_buf(),
        &node_id,
        node_op.clone(),
        record,
        PeerRegistry::new(),
        ControlStore::open(dir.path()).unwrap(),
        cawala_node::AdminStore::empty(),
    );
    let engine = Arc::new(Mutex::new(engine));
    let signed = SignedControl::authorize(
        node(&node_id),
        &node_op,
        fresh_nonce(),
        now_unix_seconds() + CONTROL_REQUEST_TTL_SECS,
        issue_request(request_id(1), "user-a", 1),
    )
    .unwrap();
    let endpoint = bind(&secret).await;
    let addr = endpoint.addr();
    let router = spawn_control_only_on(endpoint, Arc::clone(&engine));
    let admin_endpoint = bind(&SecretKey::generate()).await;
    let reply =
        ControlNode::send_direct_addr(&admin_endpoint, addr, &signed, timeout())
            .await
            .unwrap();
    assert_eq!(reply, ControlReply::Rejected(RejectCode::Internal));
    admin_endpoint.close().await;
    router.shutdown().await.unwrap();
}
