//! Offline tests for the local `control admin priority|state` CLI logic
//! (spec §6, §8.2). No network and no running node: the commands edit
//! `admin_state.json` directly.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use cawala_control::{ChildKind, ControlRequest, SignedControl};
use cawala_ledger::OperatorSecretKey;
use cawala_node::record::RecordStore;
use cawala_node::{AdminState, CONTROL_AUDIT_FILE, ControlNode, admin_cli};
use iroh::{EndpointId, SecretKey};

fn operator(secret: &SecretKey) -> OperatorSecretKey {
    OperatorSecretKey::from_bytes(secret.to_bytes())
}

/// Persist a node record listing `children` so the CLI's child checks pass.
fn setup(dir: &Path, node_id: &str, children: &[(&str, u8)]) {
    let mut record = RecordStore::open(dir, node_id).unwrap();
    record.set_address("0".parse().unwrap()).unwrap();
    for (id, slot) in children {
        record
            .attach_child(*id, ChildKind::Node, Some(*slot), 1)
            .unwrap();
    }
    record.save().unwrap();
}

#[test]
fn priority_add_seeds_first_admin() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let op = operator(&key);
    let node_id = key.public().to_string();
    setup(dir.path(), &node_id, &[("child", 0)]);

    let state = admin_cli::priority_add(dir.path(), &node_id, &op, "child", false, 100).unwrap();
    assert_eq!(state.current_id().unwrap().as_str(), "child");
    assert_eq!(state.epoch(), 1, "the first seed bumps the anti-downgrade epoch");
    assert!(state.lease_valid(100), "the first admin gets a lease window");
}

#[test]
fn priority_remove_demotes_and_bumps_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let op = operator(&key);
    let node_id = key.public().to_string();
    setup(dir.path(), &node_id, &[("a", 0), ("b", 1)]);

    admin_cli::priority_add(dir.path(), &node_id, &op, "a", false, 100).unwrap();
    admin_cli::priority_add(dir.path(), &node_id, &op, "b", false, 100).unwrap();
    let state = admin_cli::priority_remove(dir.path(), &node_id, &op, "a", 200).unwrap();
    assert_eq!(state.current_id().unwrap().as_str(), "b");
    assert!(state.epoch() >= 3, "demoting the current admin bumps the epoch");

    // Removing the last entry clears current/lease.
    let state = admin_cli::priority_remove(dir.path(), &node_id, &op, "b", 300).unwrap();
    assert!(state.priority().is_empty());
    assert_eq!(state.current_index(), -1);
    assert_eq!(state.lease_until(), 0);
}

#[test]
fn state_set_current_bumps_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let op = operator(&key);
    let node_id = key.public().to_string();
    setup(dir.path(), &node_id, &[("a", 0), ("b", 1)]);

    admin_cli::priority_add(dir.path(), &node_id, &op, "a", false, 100).unwrap();
    admin_cli::priority_add(dir.path(), &node_id, &op, "b", false, 100).unwrap();
    let before = AdminState::load(dir.path()).unwrap().epoch();

    let state = admin_cli::state_set_current(dir.path(), &node_id, &op, Some("b"), 200).unwrap();
    assert_eq!(state.current_id().unwrap().as_str(), "b");
    assert_eq!(state.epoch(), before + 1, "changing current bumps the epoch");
}

/// An out-of-process `admin_state.json` edit is observed by a running engine
/// through its per-request reload, without a restart.
#[tokio::test]
async fn offline_edit_observed_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let op = operator(&key);
    let node_id = key.public().to_string();
    setup(dir.path(), &node_id, &[("admin", 0)]);

    let mut engine = ControlNode::open(dir.path(), &node_id, op.clone()).unwrap();
    assert!(engine.admin_state().current_id().is_none());

    // A separate process (the CLI) seeds the first administrator on disk.
    admin_cli::priority_add(dir.path(), &node_id, &op, "admin", false, 500).unwrap();

    // A self-operator query reloads the state file per request.
    let signed = SignedControl::authorize(
        cawala_control::NodeId::from(node_id.clone()),
        &op,
        fresh_nonce(),
        700,
        ControlRequest::Query,
    )
    .unwrap();
    let _ = engine
        .receive_at(EndpointId::from(key.public()), signed, 500)
        .await;
    assert_eq!(
        engine.admin_state().current_id().unwrap().as_str(),
        "admin",
        "the engine must adopt the out-of-process seed"
    );
}

#[test]
fn local_audit_marker_via_local() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let op = operator(&key);
    let node_id = key.public().to_string();
    setup(dir.path(), &node_id, &[("child", 0)]);

    admin_cli::priority_add(dir.path(), &node_id, &op, "child", false, 100).unwrap();

    let audit = std::fs::read_to_string(dir.path().join(CONTROL_AUDIT_FILE)).unwrap();
    assert!(audit.contains("\"event\":\"admin-state\""), "{audit}");
    assert!(audit.contains("\"action\":\"priority-add\""), "{audit}");
    assert!(audit.contains("\"via\":\"local\""), "{audit}");
    assert!(audit.contains("\"actor\":\"operator\""), "{audit}");
}

fn fresh_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}
