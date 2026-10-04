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
    DesignationChange, NodeId, OperatorSecretKey, ROUTED_CONTROL_VERSION, RejectCode,
    RoutedControlV1, RoutedForward, SignedControl, ValueRequestId,
};
use cawala_ledger::{LedgerSecretKey, PeerKeys, PeerRegistry, PeerRole};
use cawala_msg::PeerRef;
use cawala_node::control_store::ControlStore;
use cawala_node::record::RecordStore;
use cawala_node::{
    AdminState, ControlNode, Handled, LedgerService, VALUE_POLICY_VERSION, ValueLimits,
    ValuePolicy,
};
use iroh::{EndpointId, SecretKey};
use tokio::sync::Mutex;

const NOW: u64 = 1_000;

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

/// Persist an explicit designation set. `receive*` reloads `admin_state.json`
/// per request, so the seed is observed without a restart.
fn designate(dir: &Path, admins: &[&str]) {
    let mut state = AdminState::empty();
    for id in admins {
        assert!(state.add(id));
    }
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
async fn designated_node_child_allowed() {
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
    designate(dir.path(), &[&admin_id]);

    let remote = EndpointId::from(admin_key.public());
    let query = sign(&admin_id, &admin_op, ControlRequest::AdminQuery);
    let routed = routed_from("parent", &query, &admin_id);
    assert!(matches!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::AdminSnapshot(_)
    ));
}

#[tokio::test]
async fn designated_leaf_child_allowed() {
    let parent_key = SecretKey::generate();
    let browser_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let browser_op = operator(&browser_key);
    let browser_id = browser_key.public().to_string();

    let (mut engine, dir) = build(
        "parent",
        "0",
        &[(&browser_id, ChildKind::User, 0)],
        vec![user_peer(&browser_id, &browser_op)],
        parent_op,
    );
    designate(dir.path(), &[&browser_id]);
    let remote = EndpointId::from(browser_key.public());

    let query = sign(&browser_id, &browser_op, ControlRequest::AdminQuery);
    let routed = routed_from("parent", &query, &browser_id);
    assert!(
        matches!(
            engine.receive_routed_at(remote, routed, NOW).await,
            ControlReply::AdminSnapshot(_)
        ),
        "a designated leaf child must administer its parent"
    );
}

#[tokio::test]
async fn non_designated_child_denied_on_admin_and_topology() {
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

    // No designation: the child is not an administrator.
    let query = sign(&child_id, &child_op, ControlRequest::AdminQuery);
    let routed = routed_from("parent", &query, &child_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
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
    let routed = routed_from("parent", &create, &child_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
    assert_eq!(engine.record().children.len(), 1, "nothing was attached");
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
async fn non_designated_leaf_child_denied_on_admin() {
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

    // The leaf is a current child but is *not* designated: it has no authority.
    let query = sign(&browser_id, &browser_op, ControlRequest::AdminQuery);
    let routed = routed_from("parent", &query, &browser_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
}

#[tokio::test]
async fn routed_admin_from_direct_child_applies() {
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
    designate(dir.path(), &[&admin_id]);
    let remote = EndpointId::from(admin_key.public());

    // The last hop (the designated child) is the authority; its topology
    // mutation is applied.
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
async fn value_policy_keys_on_last_hop_admin_child() {
    let parent_key = SecretKey::generate();
    let relay_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let relay_op = operator(&relay_key);
    let relay_id = relay_key.public().to_string();
    // The end-to-end requester is a browser/other operator that is *not* the
    // signing relay and whose key must not govern the policy.
    let requester_op = OperatorSecretKey::from_bytes([0x33; 32]);

    let (mut engine, dir) = build(
        "parent",
        "0",
        &[(&relay_id, ChildKind::Node, 0), ("account", ChildKind::Node, 1)],
        vec![node_peer(&relay_id, &relay_op, 3)],
        parent_op,
    );
    designate(dir.path(), &[&relay_id]);

    // A real ledger handle is required for `prepare_admin_value` to run.
    let ledger_service = LedgerService::open(dir.path(), "parent").unwrap();
    engine.attach_ledger(Arc::new(Mutex::new(ledger_service)));

    let strict = ValueLimits {
        per_request_max: 5,
        window_secs: 86_400,
        window_max: 5,
        per_account_max: 5,
    };
    let loose = ValueLimits {
        per_request_max: 1_000,
        window_secs: 86_400,
        window_max: 1_000,
        per_account_max: 1_000,
    };
    // A relayed issue: the intent is signed by the browser (`requester`) and the
    // applied forward by the relaying admin child (the last hop).
    let relayed = |amount: u64, seed: u8| {
        let intent = sign(
            "requester",
            &requester_op,
            ControlRequest::AdminIssue(AdminValueRequest {
                request_id: ValueRequestId::from_bytes([seed; 16]),
                account: node("account"),
                amount,
                reason: "last-hop admin child policy".to_string(),
            }),
        );
        let forward = {
            let mut f = intent.clone();
            f.origin = node(&relay_id);
            f.controller = relay_op.public();
            f.signature = relay_op.sign(f.signing_hash().as_bytes());
            f
        };
        RoutedControlV1 {
            version: ROUTED_CONTROL_VERSION,
            target: peer_ref("0", "parent"),
            requester: peer_ref("0.1", "requester"),
            intent,
            forwards: vec![RoutedForward::new(peer_ref("0.1", &relay_id), forward)],
        }
    };

    // Phase 1: the relaying admin child's own entry (loose) governs, and the
    // *stricter* end-to-end browser entry is ignored.
    let mut admins = BTreeMap::new();
    admins.insert(relay_op.public().to_string().to_lowercase(), loose);
    admins.insert(requester_op.public().to_string().to_lowercase(), strict);
    ValuePolicy {
        version: VALUE_POLICY_VERSION,
        defaults: strict,
        admins,
    }
    .save(dir.path())
    .unwrap();

    let remote = EndpointId::from(relay_key.public());
    match engine.receive_routed_at_handled(remote, relayed(50, 1), NOW).await {
        Handled::LedgerMutation(pending) => {
            assert_eq!(
                pending.controller,
                relay_op.public(),
                "policy/idempotency must key on the last-hop admin child, not the browser"
            );
            assert_eq!(pending.limits.per_request_max, 1_000);
            assert_eq!(pending.amount, 50);
        }
        other => panic!("expected a deferred value mutation, got {other:?}"),
    }

    // Phase 2: an issue denied for the last hop's key is refused even though the
    // browser's end-to-end key would be allowed.
    let mut admins = BTreeMap::new();
    admins.insert(relay_op.public().to_string().to_lowercase(), strict);
    admins.insert(requester_op.public().to_string().to_lowercase(), loose);
    ValuePolicy {
        version: VALUE_POLICY_VERSION,
        defaults: loose,
        admins,
    }
    .save(dir.path())
    .unwrap();

    assert_eq!(
        engine
            .receive_routed_at(remote, relayed(50, 2), NOW)
            .await,
        ControlReply::Rejected(RejectCode::LimitExceeded),
        "the last-hop admin child's denial must govern, over any other key"
    );
}

/// A value request whose last hop *is* the requester (the browser is the
/// designated direct child): the policy still keys on that browser.
#[tokio::test]
async fn direct_value_policy_keys_on_browser_last_hop() {
    let parent_key = SecretKey::generate();
    let browser_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let browser_op = operator(&browser_key);
    let browser_id = browser_key.public().to_string();

    let (mut engine, dir) = build(
        "parent",
        "0",
        &[(&browser_id, ChildKind::User, 0), ("account", ChildKind::Node, 1)],
        vec![user_peer(&browser_id, &browser_op)],
        parent_op,
    );
    designate(dir.path(), &[&browser_id]);

    let ledger_service = LedgerService::open(dir.path(), "parent").unwrap();
    engine.attach_ledger(Arc::new(Mutex::new(ledger_service)));

    // Strict defaults; only the browser's own operator key is loosened.
    let mut admins = BTreeMap::new();
    admins.insert(
        browser_op.public().to_string().to_lowercase(),
        ValueLimits {
            per_request_max: 1_000,
            window_secs: 86_400,
            window_max: 1_000,
            per_account_max: 1_000,
        },
    );
    ValuePolicy {
        version: VALUE_POLICY_VERSION,
        defaults: ValueLimits {
            per_request_max: 5,
            window_secs: 86_400,
            window_max: 5,
            per_account_max: 5,
        },
        admins,
    }
    .save(dir.path())
    .unwrap();

    let remote = EndpointId::from(browser_key.public());
    let issue = sign(
        &browser_id,
        &browser_op,
        ControlRequest::AdminIssue(AdminValueRequest {
            request_id: ValueRequestId::from_bytes([0x44; 16]),
            account: node("account"),
            amount: 50,
            reason: "direct-parent policy".to_string(),
        }),
    );
    let routed = routed_from("parent", &issue, &browser_id);
    match engine.receive_routed_at_handled(remote, routed, NOW).await {
        Handled::LedgerMutation(pending) => {
            assert_eq!(pending.controller, browser_op.public());
            assert_eq!(pending.limits.per_request_max, 1_000);
            assert_eq!(pending.amount, 50);
        }
        other => panic!("expected a deferred value mutation, got {other:?}"),
    }
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
    // The child *is* a designated administrator...
    designate(dir.path(), &[&admin_id]);
    let remote = EndpointId::from(admin_key.public());

    // ...but a direct admin request must still be `SelfOperator` (R1): remote
    // administration has to be tree-routed.
    let query = sign(&admin_id, &admin_op, ControlRequest::AdminQuery);
    assert_eq!(
        engine.receive_at(remote, query, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
}

/// A designated administrator may add a current child to the designation set
/// remotely (routed); the change is persisted.
#[tokio::test]
async fn routed_designated_admin_can_designate_child() {
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
    designate(dir.path(), &[&admin_id]);
    let remote = EndpointId::from(admin_key.public());

    let designate_child = sign(
        &admin_id,
        &admin_op,
        ControlRequest::AdminDesignate(DesignationChange {
            child: victim_id.clone(),
        }),
    );
    let routed = routed_from("parent", &designate_child, &admin_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Accepted
    );
    assert!(engine.admin_state().has(&victim_id));
    assert!(
        AdminState::load(dir.path()).unwrap().has(&victim_id),
        "the designation must be persisted"
    );
}

/// A non-designated child cannot change the designation set.
#[tokio::test]
async fn routed_non_admin_cannot_designate() {
    let parent_key = SecretKey::generate();
    let child_key = SecretKey::generate();
    let victim_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let child_op = operator(&child_key);
    let child_id = child_key.public().to_string();
    let victim_id = victim_key.public().to_string();

    let (mut engine, _dir) = build(
        "parent",
        "0",
        &[
            (&child_id, ChildKind::Node, 0),
            (&victim_id, ChildKind::Node, 1),
        ],
        vec![node_peer(&child_id, &child_op, 3)],
        parent_op,
    );
    let remote = EndpointId::from(child_key.public());

    let designate_child = sign(
        &child_id,
        &child_op,
        ControlRequest::AdminDesignate(DesignationChange { child: victim_id }),
    );
    let routed = routed_from("parent", &designate_child, &child_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
    assert!(!engine.admin_state().has(&victim_key.public().to_string()));
}

/// Designating an id that is not a current child is rejected.
#[tokio::test]
async fn routed_designate_non_child_is_rejected() {
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
    designate(dir.path(), &[&admin_id]);
    let remote = EndpointId::from(admin_key.public());

    let designate_ghost = sign(
        &admin_id,
        &admin_op,
        ControlRequest::AdminDesignate(DesignationChange {
            child: "ghost".to_string(),
        }),
    );
    let routed = routed_from("parent", &designate_ghost, &admin_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Rejected(RejectCode::NotFound)
    );
    assert!(!engine.admin_state().has("ghost"));
}

/// `AdminRevoke` removes a current child and idempotently clears a stale
/// non-child designation.
#[tokio::test]
async fn routed_revoke_removes_child_and_clears_stale() {
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
    // `ghost` is designated but is not (and never was) a current child.
    designate(dir.path(), &[&admin_id, &victim_id, "ghost"]);
    let remote = EndpointId::from(admin_key.public());

    // Revoke a current child.
    let revoke_victim = sign(
        &admin_id,
        &admin_op,
        ControlRequest::AdminRevoke(DesignationChange {
            child: victim_id.clone(),
        }),
    );
    let routed = routed_from("parent", &revoke_victim, &admin_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Accepted
    );
    assert!(!engine.admin_state().has(&victim_id));
    assert!(!AdminState::load(dir.path()).unwrap().has(&victim_id));

    // Revoke a stale non-child designation: still idempotently accepted, and it
    // is gone from the persisted set.
    let revoke_ghost = sign(
        &admin_id,
        &admin_op,
        ControlRequest::AdminRevoke(DesignationChange {
            child: "ghost".to_string(),
        }),
    );
    let routed = routed_from("parent", &revoke_ghost, &admin_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Accepted
    );
    assert!(!engine.admin_state().has("ghost"));
    assert!(!AdminState::load(dir.path()).unwrap().has("ghost"));
}

/// A prune triggered by the per-request reload revokes the stale designation's
/// authority **and persists** the pruned set, so later reloads are no-ops.
#[tokio::test]
async fn prune_on_reload_revokes_authority_and_persists() {
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
    designate(dir.path(), &[&admin_id]);

    // A separate process detaches the child from `node.json`.
    {
        let mut record = RecordStore::open(dir.path(), "parent").unwrap();
        record.detach_child(&admin_id).unwrap();
        record.save().unwrap();
    }

    // The routed request from the now-detached child is refused, and the reload
    // has pruned the designation from disk.
    let remote = EndpointId::from(admin_key.public());
    let query = sign(&admin_id, &admin_op, ControlRequest::AdminQuery);
    let routed = routed_from("parent", &query, &admin_id);
    assert_eq!(
        engine.receive_routed_at(remote, routed, NOW).await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
    assert!(!engine.admin_state().has(&admin_id));
    assert!(
        !AdminState::load(dir.path()).unwrap().has(&admin_id),
        "the prune must be persisted so it is not repeated per request"
    );
}
