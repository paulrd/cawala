//! Integration tests for `admin_state.json`: schema round-trip, fail-closed
//! load, validation, and the designation-pruning guarantees (spec §4, §8.2).
//!
//! Everything here is offline filesystem + the pure [`AdminState`] helpers; no
//! network and no wall clock.

use cawala_node::{
    ADMIN_STATE_FILE, ADMIN_STATE_VERSION, MAX_DESIGNATED_ADMINS, AdminState, AdminStateError,
};

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
    assert!(state.list().is_empty());
    assert!(!state.has("admin-a"));
}

#[test]
fn explicit_seed_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = AdminState::empty();
    assert!(state.add("admin-a"));
    assert!(state.add("admin-b"));
    // Re-adding an existing entry is a no-op.
    assert!(!state.add("admin-a"));
    assert!(state.remove("admin-a"));
    assert!(!state.remove("admin-a"));
    state.mark_updated(1_000, "local");
    state.save(dir.path()).unwrap();

    let loaded = AdminState::load(dir.path()).unwrap();
    assert_eq!(loaded, state);
    assert_eq!(loaded.list(), &["admin-b".to_string()]);
    assert!(loaded.has("admin-b"));
    assert!(!loaded.has("admin-a"));
    assert_eq!(loaded.updated_at(), 1_000);
    assert_eq!(loaded.updated_by(), "local");
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
    assert!(engine.admin_state().list().is_empty());
}

#[test]
fn invalid_duplicate_and_overbound_rejected() {
    // Unknown version.
    let dir = tempfile::tempdir().unwrap();
    write_json(
        dir.path(),
        &serde_json::json!({ "version": ADMIN_STATE_VERSION + 1, "admins": [] }),
    );
    assert!(matches!(
        AdminState::load(dir.path()).unwrap_err(),
        AdminStateError::UnsupportedVersion(_)
    ));

    // Duplicate ids.
    let dir = tempfile::tempdir().unwrap();
    write_json(
        dir.path(),
        &serde_json::json!({
            "version": ADMIN_STATE_VERSION,
            "admins": ["dup", "dup"],
        }),
    );
    assert!(matches!(
        AdminState::load(dir.path()).unwrap_err(),
        AdminStateError::DuplicateAdmin(_)
    ));

    // Empty id.
    let dir = tempfile::tempdir().unwrap();
    write_json(
        dir.path(),
        &serde_json::json!({ "version": ADMIN_STATE_VERSION, "admins": [""] }),
    );
    assert!(matches!(
        AdminState::load(dir.path()).unwrap_err(),
        AdminStateError::EmptyAdminId(0)
    ));

    // Over the bound.
    let dir = tempfile::tempdir().unwrap();
    let admins: Vec<String> = (0..=MAX_DESIGNATED_ADMINS)
        .map(|i| format!("admin-{i}"))
        .collect();
    write_json(
        dir.path(),
        &serde_json::json!({ "version": ADMIN_STATE_VERSION, "admins": admins }),
    );
    assert!(matches!(
        AdminState::load(dir.path()).unwrap_err(),
        AdminStateError::TooManyAdmins { .. }
    ));
}

#[test]
fn prune_non_child() {
    let mut state = AdminState::empty();
    state.add("keep");
    state.add("gone");
    let children = vec!["keep".to_string()];
    assert!(state.prune(&children));
    assert_eq!(state.list(), &["keep".to_string()]);
    // A second prune with no change reports false.
    assert!(!state.prune(&children));
}

/// `add` enforces [`MAX_DESIGNATED_ADMINS`]: the ninth entry is refused and the
/// set is left unchanged.
#[test]
fn max_designated_admins_enforced_by_add() {
    let mut state = AdminState::empty();
    for i in 0..MAX_DESIGNATED_ADMINS {
        assert!(state.add(&format!("admin-{i}")), "entry {i} fits");
    }
    assert_eq!(state.list().len(), MAX_DESIGNATED_ADMINS);
    assert!(!state.add("overflow"), "the set is full");
    assert_eq!(state.list().len(), MAX_DESIGNATED_ADMINS);
    // A duplicate of an existing entry is also refused.
    assert!(!state.add("admin-0"));
    assert_eq!(state.list().len(), MAX_DESIGNATED_ADMINS);
}
