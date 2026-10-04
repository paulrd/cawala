//! Offline lease / failover tests (spec §5, §8.2).
//!
//! Time is injected and candidate liveness is made deterministic with
//! [`ControlNode::set_admin_probe_alive`]; there is no transport and no wall
//! clock.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use cawala_control::{
    AdminLeaseRequest, ControlReply, ControlRequest, ChildKind, NodeId, OperatorSecretKey,
    ROUTED_CONTROL_VERSION, RejectCode, RoutedControlV1, RoutedForward, SignedControl,
};
use cawala_ledger::{LedgerSecretKey, PeerKeys, PeerRegistry, PeerRole};
use cawala_msg::PeerRef;
use cawala_node::control_store::ControlStore;
use cawala_node::record::RecordStore;
use cawala_node::{AdminState, ControlNode};
use iroh::{EndpointId, SecretKey};

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

fn sign(origin: &str, op: &OperatorSecretKey, request: ControlRequest) -> SignedControl {
    SignedControl::authorize(node(origin), op, fresh_nonce(), NOW + 120, request).unwrap()
}

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

fn build(
    children: &[(&str, ChildKind, u8)],
    peers: Vec<PeerKeys>,
    op: OperatorSecretKey,
) -> (ControlNode, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut record = RecordStore::open(dir.path(), "parent").unwrap();
    record.set_address("0".parse().unwrap()).unwrap();
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
        "parent",
        op,
        record,
        registry,
        ControlStore::open(dir.path()).unwrap(),
    );
    (engine, dir)
}

fn lease_op(epoch: u64, ttl_secs: u64) -> ControlRequest {
    ControlRequest::AdminLease(AdminLeaseRequest { epoch, ttl_secs })
}

fn peer_ref(addr: &str, id: &str) -> PeerRef {
    PeerRef {
        addr: addr.parse().unwrap(),
        node: id.to_string(),
    }
}

fn routed_from(control: &SignedControl, authority_node: &str) -> RoutedControlV1 {
    let forward = RoutedForward::new(peer_ref("0.0", authority_node), control.clone());
    RoutedControlV1 {
        version: ROUTED_CONTROL_VERSION,
        target: peer_ref("0", "parent"),
        requester: peer_ref("0.0", authority_node),
        intent: control.clone(),
        forwards: vec![forward],
    }
}

#[tokio::test]
async fn lease_renew_requires_current_epoch_and_priority() {
    let parent_key = SecretKey::generate();
    let a_key = SecretKey::generate();
    let b_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let a_op = operator(&a_key);
    let b_op = operator(&b_key);
    let a_id = a_key.public().to_string();
    let b_id = b_key.public().to_string();

    let (mut engine, dir) = build(
        &[(&a_id, ChildKind::Node, 0), (&b_id, ChildKind::Node, 1)],
        vec![node_peer(&a_id, &a_op, 3), node_peer(&b_id, &b_op, 4)],
        parent_op,
    );

    // Equal epoch + current priority + a valid lease: the lease is refreshed to
    // `NOW + ttl`.
    seed(dir.path(), &[&a_id], 0, LEASED, 3);
    let renew = sign(&a_id, &a_op, lease_op(3, 300));
    let reply = engine.receive_at(EndpointId::from(a_key.public()), renew, NOW).await;
    let ControlReply::LeaseState(state) = reply else {
        panic!("expected LeaseState, got {reply:?}");
    };
    assert_eq!(state.current, 0);
    assert_eq!(state.lease_until, NOW + 300);
    assert_eq!(engine.admin_state().lease_until(), NOW + 300);

    // A valid lease held by a *different* current entry is not refreshed.
    seed(dir.path(), &[&b_id], 0, LEASED, 4);
    let renew = sign(&a_id, &a_op, lease_op(4, 300));
    let reply = engine.receive_at(EndpointId::from(a_key.public()), renew, NOW).await;
    let ControlReply::LeaseState(state) = reply else {
        panic!("expected LeaseState, got {reply:?}");
    };
    assert_eq!(state.current, 0);
    assert_eq!(state.lease_until, LEASED, "a non-current child cannot renew");
    assert_eq!(engine.admin_state().lease_until(), LEASED);
}

#[tokio::test]
async fn stale_epoch_renew_is_rejected_and_reports_state() {
    let parent_key = SecretKey::generate();
    let a_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let a_op = operator(&a_key);
    let a_id = a_key.public().to_string();

    let (mut engine, dir) = build(
        &[(&a_id, ChildKind::Node, 0)],
        vec![node_peer(&a_id, &a_op, 3)],
        parent_op,
    );
    seed(dir.path(), &[&a_id], 0, LEASED, 5);

    // A stale former-admin epoch is not refreshed; the reply reports the current
    // state so the sender resyncs.
    let renew = sign(&a_id, &a_op, lease_op(4, 300));
    let reply = engine.receive_at(EndpointId::from(a_key.public()), renew, NOW).await;
    let ControlReply::LeaseState(state) = reply else {
        panic!("expected LeaseState, got {reply:?}");
    };
    assert_eq!(state.epoch, 5);
    assert_eq!(state.lease_until, LEASED, "stale epoch must not extend the lease");
    assert_eq!(engine.admin_state().lease_until(), LEASED);
}

#[tokio::test]
async fn lease_expiry_fails_over_to_next_priority() {
    let parent_key = SecretKey::generate();
    let a_key = SecretKey::generate();
    let b_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let a_op = operator(&a_key);
    let b_op = operator(&b_key);
    let a_id = a_key.public().to_string();
    let b_id = b_key.public().to_string();

    let (mut engine, dir) = build(
        &[(&a_id, ChildKind::Node, 0), (&b_id, ChildKind::Node, 1)],
        vec![node_peer(&a_id, &a_op, 3), node_peer(&b_id, &b_op, 4)],
        parent_op.clone(),
    );
    seed(dir.path(), &[&a_id, &b_id], 0, 0, 1);
    engine.set_admin_probe_alive(vec![b_id.clone()]);

    // Any request resolves the expired lease deterministically to the first
    // responsive candidate after the stalled current entry.
    let query = sign("parent", &parent_op, ControlRequest::Query);
    assert!(matches!(
        engine.receive_at(EndpointId::from(parent_key.public()), query, NOW).await,
        ControlReply::Snapshot(_)
    ));
    assert_eq!(engine.admin_state().current_id().unwrap().as_str(), b_id);
    assert_eq!(engine.admin_state().epoch(), 2, "failover bumps the epoch");
    assert!(engine.admin_state().lease_valid(NOW));
}

#[tokio::test]
async fn failover_bumps_epoch_and_old_admin_renew_rejected() {
    let parent_key = SecretKey::generate();
    let a_key = SecretKey::generate();
    let b_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let a_op = operator(&a_key);
    let b_op = operator(&b_key);
    let a_id = a_key.public().to_string();
    let b_id = b_key.public().to_string();

    let (mut engine, dir) = build(
        &[(&a_id, ChildKind::Node, 0), (&b_id, ChildKind::Node, 1)],
        vec![node_peer(&a_id, &a_op, 3), node_peer(&b_id, &b_op, 4)],
        parent_op.clone(),
    );
    seed(dir.path(), &[&a_id, &b_id], 0, 0, 1);
    engine.set_admin_probe_alive(vec![b_id.clone()]);

    // Trigger failover, then capture the new lease.
    let query = sign("parent", &parent_op, ControlRequest::Query);
    let _ = engine
        .receive_at(EndpointId::from(parent_key.public()), query, NOW)
        .await;
    let epoch = engine.admin_state().epoch();
    let lease_until = engine.admin_state().lease_until();
    assert_eq!(engine.admin_state().current_id().unwrap().as_str(), b_id);

    // The old admin's renewal under the pre-failover epoch is refused.
    let renew = sign(&a_id, &a_op, lease_op(1, 300));
    let reply = engine.receive_at(EndpointId::from(a_key.public()), renew, NOW).await;
    let ControlReply::LeaseState(state) = reply else {
        panic!("expected LeaseState, got {reply:?}");
    };
    assert_eq!(state.epoch, epoch);
    assert_eq!(state.lease_until, lease_until);
    assert_eq!(engine.admin_state().lease_until(), lease_until);
}

#[tokio::test]
async fn no_candidate_leaves_remote_admin_unavailable() {
    let parent_key = SecretKey::generate();
    let a_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let a_op = operator(&a_key);
    let a_id = a_key.public().to_string();

    let (mut engine, dir) = build(
        &[(&a_id, ChildKind::Node, 0)],
        vec![node_peer(&a_id, &a_op, 3)],
        parent_op.clone(),
    );
    seed(dir.path(), &[&a_id], 0, 0, 1);
    // No candidate confirmed alive.
    engine.set_admin_probe_alive(Vec::new());

    let query = sign("parent", &parent_op, ControlRequest::Query);
    let _ = engine
        .receive_at(EndpointId::from(parent_key.public()), query, NOW)
        .await;
    assert_eq!(engine.admin_state().current_index(), -1);
    assert_eq!(engine.admin_state().lease_until(), 0);

    // With no administrator, a routed admin request from the former admin is
    // refused (fail closed).
    let admin_query = sign(&a_id, &a_op, ControlRequest::AdminQuery);
    let routed = routed_from(&admin_query, &a_id);
    assert_eq!(
        engine
            .receive_routed_at(EndpointId::from(a_key.public()), routed, NOW)
            .await,
        ControlReply::Rejected(RejectCode::Unauthorized)
    );
}

#[tokio::test]
async fn admin_request_refreshes_lease() {
    let parent_key = SecretKey::generate();
    let a_key = SecretKey::generate();
    let parent_op = operator(&parent_key);
    let a_op = operator(&a_key);
    let a_id = a_key.public().to_string();

    let (mut engine, dir) = build(
        &[(&a_id, ChildKind::Node, 0)],
        vec![node_peer(&a_id, &a_op, 3)],
        parent_op,
    );
    // Valid but nearly expired; a valid admin request resets it to now + ttl.
    seed(dir.path(), &[&a_id], 0, NOW + 100, 1);

    let admin_query = sign(&a_id, &a_op, ControlRequest::AdminQuery);
    let routed = routed_from(&admin_query, &a_id);
    assert!(matches!(
        engine
            .receive_routed_at(EndpointId::from(a_key.public()), routed, NOW)
            .await,
        ControlReply::AdminSnapshot(_)
    ));
    assert_eq!(
        engine.admin_state().lease_until(),
        NOW + engine.admin_state().ttl_secs(),
        "a valid admin request refreshes the lease"
    );
}
