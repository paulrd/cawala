//! Integration tests for `admin_state.json`: schema round-trip, fail-closed
//! load, validation, and the pruning/epoch guarantees (spec §4, §8.2).
//!
//! Everything here is offline filesystem + the pure [`AdminState`] helpers; no
//! network and no wall clock.

use cawala_node::{ADMIN_STATE_FILE, ADMIN_STATE_VERSION, AdminState, AdminStateError};

fn write_json(dir: &std::path::Path, value: &serde_json::Value) {
    std::fs::write(
        dir.join(ADMIN_STATE_FILE),
        serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
}

#[test]
fn absent_file_defaults_empty() {
    let dir = tempfile::tempdir().unwrap();
    let state = AdminState::load(dir.path()).unwrap();
    assert_eq!(state, AdminState::empty());
    assert_eq!(state.current_index(), -1);
    assert!(!state.lease_valid(0));
    assert_eq!(state.lease_until(), 0);
    assert!(state.priority().is_empty());
}

#[test]
fn explicit_seed_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = AdminState::empty();
    state.set_priority(vec!["admin-a".to_string(), "admin-b".to_string()]);
    state.set_current(0);
    state.bump_epoch();
    state.record_lease(1_000);
    state.mark_updated(1_000, "local");
    state.save(dir.path()).unwrap();

    let loaded = AdminState::load(dir.path()).unwrap();
    assert_eq!(loaded, state);
    assert_eq!(loaded.current_id().unwrap().as_str(), "admin-a");
    assert_eq!(loaded.priority_len(), 2);
    assert!(loaded.lease_valid(1_000 + state.ttl_secs()));
}

/// A present-but-corrupt document is a hard load error; `ControlNode::open`
/// maps that to the empty (fail-closed, no remote admin) state.
#[test]
fn corrupt_file_fails_closed_to_none() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(ADMIN_STATE_FILE), b"{ not json").unwrap();
    assert!(matches!(
        AdminState::load(dir.path()).unwrap_err(),
        AdminStateError::Json { .. }
    ));

    // `open` serves no remote administrator when the file cannot be read.
    let secret = iroh::SecretKey::generate();
    let node_id = secret.public().to_string();
    let operator = cawala_ledger::OperatorSecretKey::from_bytes(secret.to_bytes());
    let engine = cawala_node::ControlNode::open(dir.path(), &node_id, operator).unwrap();
    assert_eq!(engine.admin_state(), &AdminState::empty());
    assert!(engine.admin_state().current_id().is_none());
}

#[test]
fn current_out_of_range_rejected() {
    let dir = tempfile::tempdir().unwrap();
    write_json(
        dir.path(),
        &serde_json::json!({
            "version": ADMIN_STATE_VERSION,
            "priority": ["admin-a"],
            "current": 1,
        }),
    );
    assert!(matches!(
        AdminState::load(dir.path()).unwrap_err(),
        AdminStateError::CurrentOutOfRange(1)
    ));
}

#[test]
fn priority_pruned_when_child_missing() {
    // A missing non-current entry is dropped, keeping the current index valid.
    let mut state = AdminState::empty();
    state.set_priority(vec!["keep".to_string(), "gone".to_string()]);
    state.set_current(0);
    assert!(state.prune_missing_children(|id| id == "keep"));
    assert_eq!(state.priority(), &["keep".to_string()]);
    assert_eq!(state.current_index(), 0);

    // Pruning the current entry clamps `current` and clears the lease.
    let mut state = AdminState::empty();
    state.set_priority(vec!["gone".to_string()]);
    state.set_current(0);
    state.record_lease(500);
    assert!(state.prune_missing_children(|_| false));
    assert!(state.priority().is_empty());
    assert_eq!(state.current_index(), -1);
    assert_eq!(state.lease_until(), 0);
}

#[test]
fn epoch_monotonic_across_reload() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = AdminState::empty();
    state.set_priority(vec!["admin-a".to_string()]);
    state.set_current(0);
    state.bump_epoch();
    state.bump_epoch();
    state.save(dir.path()).unwrap();

    let mut reloaded = AdminState::load(dir.path()).unwrap();
    assert_eq!(reloaded.epoch(), 2);
    reloaded.bump_epoch();
    assert_eq!(reloaded.epoch(), 3);
    reloaded.save(dir.path()).unwrap();

    let again = AdminState::load(dir.path()).unwrap();
    assert_eq!(again.epoch(), 3, "the epoch never decreases across reload");
}
