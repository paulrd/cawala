//! Offline tests for the local `control admin add|remove|list` CLI logic
//! (spec §6, §8.2). No network and no running node: the commands edit
//! `admin_state.json` directly.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use cawala_control::{ChildKind, ControlRequest, SignedControl};
use cawala_ledger::OperatorSecretKey;
use cawala_node::record::RecordStore;
use cawala_node::{AdminCliError, CONTROL_AUDIT_FILE, ControlNode, admin_cli};
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
fn admin_add_designates() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let op = operator(&key);
    let node_id = key.public().to_string();
    setup(dir.path(), &node_id, &[("child", 0)]);

    let state = admin_cli::admin_add(dir.path(), &node_id, &op, "child", 100).unwrap();
    assert!(state.has("child"));
    assert_eq!(state.list(), &["child".to_string()]);
    assert_eq!(state.updated_at(), 100);
    assert_eq!(state.updated_by(), "local");
}

#[test]
fn admin_remove_revokes() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let op = operator(&key);
    let node_id = key.public().to_string();
    setup(dir.path(), &node_id, &[("a", 0), ("b", 1)]);

    admin_cli::admin_add(dir.path(), &node_id, &op, "a", 100).unwrap();
    admin_cli::admin_add(dir.path(), &node_id, &op, "b", 100).unwrap();
    let state = admin_cli::admin_remove(dir.path(), &node_id, &op, "a", 200).unwrap();
    assert!(!state.has("a"));
    assert_eq!(state.list(), &["b".to_string()]);
    assert_eq!(state.updated_at(), 200);

    // Removing the last entry leaves an empty set.
    let state = admin_cli::admin_remove(dir.path(), &node_id, &op, "b", 300).unwrap();
    assert!(state.list().is_empty());
}

#[test]
fn non_child_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let op = operator(&key);
    let node_id = key.public().to_string();
    setup(dir.path(), &node_id, &[("child", 0)]);

    let err = admin_cli::admin_add(dir.path(), &node_id, &op, "ghost", 100).unwrap_err();
    assert!(matches!(err, AdminCliError::NotChild(ref id) if id == "ghost"), "{err}");

    // A non-designated `remove` is also refused.
    let err = admin_cli::admin_remove(dir.path(), &node_id, &op, "child", 100).unwrap_err();
    assert!(
        matches!(err, AdminCliError::NotAdmin(ref id) if id == "child"),
        "{err}"
    );
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
    assert!(!engine.admin_state().has("admin"));

    // A separate process (the CLI) designates the first administrator on disk.
    admin_cli::admin_add(dir.path(), &node_id, &op, "admin", 500).unwrap();

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
    assert!(
        engine.admin_state().has("admin"),
        "the engine must adopt the out-of-process designation"
    );
}

#[test]
fn local_audit_marker_via_local() {
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let op = operator(&key);
    let node_id = key.public().to_string();
    setup(dir.path(), &node_id, &[("child", 0)]);

    admin_cli::admin_add(dir.path(), &node_id, &op, "child", 100).unwrap();

    let audit = std::fs::read_to_string(dir.path().join(CONTROL_AUDIT_FILE)).unwrap();
    assert!(audit.contains("\"event\":\"admin-state\""), "{audit}");
    assert!(audit.contains("\"action\":\"admin-add\""), "{audit}");
    assert!(audit.contains("\"via\":\"local\""), "{audit}");
    assert!(audit.contains("\"actor\":\"operator\""), "{audit}");
}

fn fresh_nonce() -> u64 {
    static NONCE: AtomicU64 = AtomicU64::new(1);
    NONCE.fetch_add(1, Ordering::Relaxed)
}
