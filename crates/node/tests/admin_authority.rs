//! Offline topology-authority tests (spec §2, §8.2).
//!
//! Everything runs on the in-process engine with injected time: `receive_at`
//! for direct requests, `receive_routed_at`/`receive_routed_at_handled` for
//! tree-routed ones. There is no transport and no wall clock.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use cawala_control::{
    AdminDetachChild, AdminValueRequest, ChildKind, ControlReply, ControlRequest, CreateChild,
    NodeId, OperatorSecretKey, ROUTED_CONTROL_VERSION, RejectCode, RoutedControlV1, RoutedForward,
    SignedControl, ValueRequestId,
};
use cawala_ledger::{LedgerSecretKey, PeerKeys, PeerRegistry, PeerRole};
use cawala_msg::PeerRef;
use cawala_node::control_store::ControlStore;
use cawala_node::record::RecordStore;
use cawala_node::{
    AdminState, AdminStore, ControlNode, Handled, LedgerService, VALUE_POLICY_VERSION, ValueLimits,
    ValuePolicy,
};
use iroh::{EndpointId, SecretKey};
use tokio::sync::Mutex;

const NOW: u64 = 1_000;
const LEASED: u64 = 2_000;

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

fn ledger(seed: u8) -> cawala_ledger::LedgerPubKey {
    LedgerSecretKey::from_bytes([seed; 32]).public()
}

fn node_peer(id: &str, op: &OperatorSecretKey, seed: u8) -> PeerKeys {
    PeerKeys {
        node_id: node(id),
        operator: op.public(),
        ledger: Some(ledger(seed)),
        role: PeerRole::Node,
    }
}

fn user_peer(id: &str, op: &OperatorSecretKey) -> PeerKeys {
    PeerKeys {
        node_id: node(id),
        operator: op.public(),
        ledger: None,
        role: PeerRole::User,
    }
}

/// Sign one request at `NOW` with an expiry inside the TTL cap.
fn sign(origin: &str, op: &OperatorSecretKey, request: ControlRequest) -> SignedControl {
    SignedControl::authorize(
        node(origin),
        op,
        fresh_nonce(),
        NOW + 120,
        request,
    )
    .unwrap()
}

/// Persist an explicit priority/lease seed. `receive*` reloads
/// `admin_state.json` per request, so the seed is observed without a restart.
fn seed(dir: &Path, priority: &[&str], current: i32, lease_until: u64, epoch: u64) {
    let mut state = AdminState::empty();
    state.set_priority(priority.iter().map(|id| id.to_string()).collect());
    state.set_current(current);
    for _ in 0..epoch {
        state.bump_epoch();
    }
    state.set_lease_until(lease_until);
    state.save(dir).unwrap();
}

/// Build an offline engine from a record and a registry.
fn build(
    node_id: &str,
    address: &str,
    children: &[(&str, ChildKind, u8)],
    peers: Vec<PeerKeys>,
    op: OperatorSecretKey,
) -> (ControlNode, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut record = RecordStore::open(dir.path(), node_id).unwrap();
    record.set_address(address.parse().unwrap()).unwrap();
    for (id, kind, slot) in children {
        record.attach_child(*id, *kind, Some(*slot), 1).unwrap();
    }
    record.save().unwrap();
    let mut registry = PeerRegistry::new();
    for row in peers {
        registry.insert(row).unwrap();
    }
    let engine = ControlNode::new(
        dir.path().to_path_buf(),
        node_id,
        op,
        record,
        registry,
        ControlStore::open(dir.path()).unwrap(),
        AdminStore::empty(),
    );
    (engine, dir)
}

fn peer_ref(addr: &str, id: &str) -> PeerRef {
    PeerRef {
        addr: addr.parse().unwrap(),
        node: id.to_string(),
    }
}

/// A one-hop routed request where `authority` signs both the intent and the
/// last-hop forward.
fn routed_from(
    target_id: &str,
    authority: &SignedControl,
    authority_node: &str,
) -> RoutedControlV1 {
    let forward = RoutedForward::new(peer_ref("0.0", authority_node), authority.clone());
    RoutedControlV1 {
        version: ROUTED_CONTROL_VERSION,
        target: peer_ref("0", target_id),
        requester: peer_ref("0.0", authority_node),
        intent: authority.clone(),
        forwards: vec![forward],
    }
}

#[tokio::test]
async fn non_admin_child_denied_on_admin_and_topology() {
    let parent_key = SecretKey::generate();
    let child_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let child_op = operator(&child_key);
    let child_id = child_key.public().to_string();

    let (mut engine, _dir) = build(
        "parent",
        "0",
        &[(&child_id, ChildKind::Node, 0)],
        vec![node_peer(&child_id, &child_op, 3)],
        parent_op,
    );
    let remote = EndpointId::from(child_key.public());

    // No priority/lease seed: the child is not an administrator.
    let query = sign(&child_id, &child_op, ControlRequest::AdminQuery);
    assert_eq!(
        engine.receive_at(remote, query, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );

    let create = sign(
        &child_id,
        &child_op,
        ControlRequest::CreateChild(CreateChild {
            child: node("grandchild"),
            operator: OperatorSecretKey::from_bytes([0x77; 32]).public(),
            ledger: Some(ledger(9)),
            kind: ChildKind::Node,
            slot: Some(1),
            date_joined: 2,
        }),
    );
    assert_eq!(
        engine.receive_at(remote, create, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
    assert_eq!(engine.record().children.len(), 1, "nothing was attached");
}

#[tokio::test]
async fn browser_child_has_full_admin_over_parent() {
    let parent_key = SecretKey::generate();
    let browser_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let browser_op = operator(&browser_key);
    let browser_id = browser_key.public().to_string();

    let (mut engine, _dir) = build(
        "parent",
        "0",
        &[(&browser_id, ChildKind::User, 0)],
        vec![user_peer(&browser_id, &browser_op)],
        parent_op,
    );
    let remote = EndpointId::from(browser_key.public());

    // R4: a User child is a full administrator without any priority seed.
    let query = sign(&browser_id, &browser_op, ControlRequest::AdminQuery);
    let routed = routed_from("parent", &query, &browser_id);
    assert!(
        matches!(
            engine.receive_routed_at(remote, routed, NOW).await,
            ControlReply::AdminSnapshot(_)
        ),
        "a User child must administer its parent"
    );
}

#[tokio::test]
async fn priority_child_is_admin_only_when_current_and_leased() {
    let parent_key = SecretKey::generate();
    let admin_key = SecretKey::generate();
    let other_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let admin_op = operator(&admin_key);
    let other_op = operator(&other_key);
    let admin_id = admin_key.public().to_string();
    let other_id = other_key.public().to_string();

    let (mut engine, dir) = build(
        "parent",
        "0",
        &[
            (&admin_id, ChildKind::Node, 0),
            (&other_id, ChildKind::Node, 1),
        ],
        vec![
            node_peer(&admin_id, &admin_op, 3),
            node_peer(&other_id, &other_op, 4),
        ],
        parent_op,
    );
    let remote = EndpointId::from(admin_key.public());

    // Current + leased: the priority child is an administrator.
    seed(dir.path(), &[&admin_id], 0, LEASED, 1);
    let query = sign(&admin_id, &admin_op, ControlRequest::AdminQuery);
    let routed = routed_from("parent", &query, &admin_id);
    assert!(matches!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::AdminSnapshot(_)
    ));

    // Priority names the child but a *different* entry is current: denied.
    seed(dir.path(), &[&other_id, &admin_id], 0, LEASED, 2);
    let query = sign(&admin_id, &admin_op, ControlRequest::AdminQuery);
    let routed = routed_from("parent", &query, &admin_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );

    // Current but the lease has expired (no live probe): failover clears it.
    seed(dir.path(), &[&admin_id], 0, 0, 3);
    let query = sign(&admin_id, &admin_op, ControlRequest::AdminQuery);
    let routed = routed_from("parent", &query, &admin_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
    assert_eq!(engine.admin_state().current_index(), -1);
}

#[tokio::test]
async fn self_operator_still_authorized() {
    let parent_key = SecretKey::generate();
    let parent_op = operator(&parent_key);

    let (mut engine, _dir) = build("parent", "0", &[], vec![], parent_op.clone());
    let remote = EndpointId::from(parent_key.public());

    let query = sign("parent", &parent_op, ControlRequest::Query);
    assert!(matches!(
        engine.receive_at(remote, query, NOW).await,
        ControlReply::Snapshot(_)
    ));
    let admin_query = sign("parent", &parent_op, ControlRequest::AdminQuery);
    assert!(matches!(
        engine.receive_at(remote, admin_query, NOW).await,
        ControlReply::AdminSnapshot(_)
    ));
}

#[tokio::test]
async fn routed_admin_from_direct_parent_applies() {
    let parent_key = SecretKey::generate();
    let admin_key = SecretKey::generate();
    let victim_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let admin_op = operator(&admin_key);
    let victim_op = operator(&victim_key);
    let admin_id = admin_key.public().to_string();
    let victim_id = victim_key.public().to_string();

    let (mut engine, dir) = build(
        "parent",
        "0",
        &[
            (&admin_id, ChildKind::Node, 0),
            (&victim_id, ChildKind::Node, 1),
        ],
        vec![
            node_peer(&admin_id, &admin_op, 3),
            node_peer(&victim_id, &victim_op, 4),
        ],
        parent_op,
    );
    seed(dir.path(), &[&admin_id], 0, LEASED, 1);
    let remote = EndpointId::from(admin_key.public());

    // The last hop (the priority child) is the authority; its topology mutation
    // is applied.
    let detach = sign(
        &admin_id,
        &admin_op,
        ControlRequest::AdminDetachChild(AdminDetachChild {
            child: node(&victim_id),
        }),
    );
    let routed = routed_from("parent", &detach, &admin_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Accepted
    );
    assert!(
        !engine
            .record()
            .children
            .iter()
            .any(|c| c.child_id == victim_id)
    );
}

#[tokio::test]
async fn value_policy_keys_on_end_to_end_requester_not_relay() {
    let parent_key = SecretKey::generate();
    let relay_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let relay_op = operator(&relay_key);
    let relay_id = relay_key.public().to_string();
    // The end-to-end requester is a browser/other operator that is *not* the
    // signing relay.
    let requester_op = OperatorSecretKey::from_bytes([0x33; 32]);

    let (mut engine, dir) = build(
        "parent",
        "0",
        &[
            (&relay_id, ChildKind::Node, 0),
            // A Node child, so R4 (browser-only) does not pre-empt R5 here.
            ("account", ChildKind::Node, 1),
        ],
        vec![node_peer(&relay_id, &relay_op, 3)],
        parent_op,
    );
    seed(dir.path(), &[&relay_id], 0, LEASED, 1);

    // A real ledger handle is required for `prepare_admin_value` to run.
    let ledger_service = LedgerService::open(dir.path(), "parent").unwrap();
    engine.attach_ledger(Arc::new(Mutex::new(ledger_service)));

    // Deny-by-default defaults (max 5), with a loose override for the *requester*
    // only. The relay has no override.
    let requester_limits = ValueLimits {
        per_request_max: 1_000,
        window_secs: 86_400,
        window_max: 1_000,
        per_account_max: 1_000,
    };
    let mut admins = BTreeMap::new();
    admins.insert(
        requester_op.public().to_string().to_lowercase(),
        requester_limits,
    );
    let policy = ValuePolicy {
        version: VALUE_POLICY_VERSION,
        defaults: ValueLimits {
            per_request_max: 5,
            window_secs: 86_400,
            window_max: 5,
            per_account_max: 5,
        },
        admins,
    };
    policy.save(dir.path()).unwrap();

    let remote = EndpointId::from(relay_key.public());
    let issue = |amount: u64| {
        ControlRequest::AdminIssue(AdminValueRequest {
            request_id: ValueRequestId::from_bytes([nonce_byte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            account: node("account"),
            amount,
            reason: "e2e-requester policy".to_string(),
        })
    };

    // Under the *relay's* limits this would be refused; under the requester's
    // override it is admitted, proving policy keying on the e2e requester.
    let intent = sign("requester", &requester_op, issue(50));
    let forward = {
        let mut f = intent.clone();
        f.origin = node(&relay_id);
        f.controller = relay_op.public();
        f.signature = relay_op.sign(f.signing_hash().as_bytes());
        f
    };
    let routed = RoutedControlV1 {
        version: ROUTED_CONTROL_VERSION,
        target: peer_ref("0", "parent"),
        requester: peer_ref("0.1", "requester"),
        intent,
        forwards: vec![RoutedForward::new(peer_ref("0.1", &relay_id), forward)],
    };

    match engine.receive_routed_at_handled(remote, routed, NOW).await {
        Handled::LedgerMutation(pending) => {
            assert_eq!(pending.controller, requester_op.public());
            assert_eq!(pending.limits.per_request_max, 1_000);
            assert_eq!(pending.amount, 50);
        }
        other => panic!("expected a deferred value mutation, got {other:?}"),
    }

    // Above even the requester's override -> refused before the ledger.
    let intent = sign("requester", &requester_op, issue(2_000));
    let forward = {
        let mut f = intent.clone();
        f.origin = node(&relay_id);
        f.controller = relay_op.public();
        f.signature = relay_op.sign(f.signing_hash().as_bytes());
        f
    };
    let routed = RoutedControlV1 {
        version: ROUTED_CONTROL_VERSION,
        target: peer_ref("0", "parent"),
        requester: peer_ref("0.1", "requester"),
        intent,
        forwards: vec![RoutedForward::new(peer_ref("0.1", &relay_id), forward)],
    };
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Rejected(RejectCode::LimitExceeded)
    );
}

fn nonce_byte() -> u8 {
    static N: AtomicU64 = AtomicU64::new(1);
    (N.fetch_add(1, Ordering::Relaxed) % 255 + 1) as u8
}

#[tokio::test]
async fn direct_remote_admin_is_refused() {
    let parent_key = SecretKey::generate();
    let admin_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let admin_op = operator(&admin_key);
    let admin_id = admin_key.public().to_string();

    let (mut engine, dir) = build(
        "parent",
        "0",
        &[(&admin_id, ChildKind::Node, 0)],
        vec![node_peer(&admin_id, &admin_op, 3)],
        parent_op,
    );
    // The child *is* the current, leased administrator...
    seed(dir.path(), &[&admin_id], 0, LEASED, 1);
    let remote = EndpointId::from(admin_key.public());

    // ...but a direct admin request must still be `SelfOperator` (R1): remote
    // administration has to be tree-routed.
    let query = sign(&admin_id, &admin_op, ControlRequest::AdminQuery);
    assert_eq!(
        engine.receive_at(remote, query, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
}
