//! Operator-CLI logic for `control admin add|remove|list`.
//!
//! The clap layer in `main.rs` is a thin shell over these functions so the
//! behaviour (validation, state mutation, audit) is unit-testable without a
//! process. Everything is pure filesystem + `cawala_control`; no network and no
//! running engine.
//!
//! Authority under the topology refactor is derived from `node.json` + the
//! persisted [`AdminState`](crate::admin_state::AdminState) designation set.
//! These commands are the **explicit operator designation**: the operator names
//! the current children (of any [`ChildKind`]) that may administer this node.
//! `admin add` bootstraps the first administrator and recovers a lockout.
//!
//! All mutations are offline-capable: they edit `<data-dir>/admin_state.json`
//! directly, and a running node observes an out-of-process edit through its
//! per-request `reload_admin_state`.
//!
//! # Semantics
//!
//! - `admin add` designates a current child; `admin remove` revokes it. Every
//!   command fails closed when the target child is not a current child of this
//!   node.
//! - `updated_by = "local"`, `updated_at = now`; an `admin-state` audit line is
//!   appended with `via: "local"`, `actor: "operator"`.
//!
//! # Audit
//!
//! Every successful mutation appends through the shared [`crate::audit::append`]
//! writer. An audit append failure is ignored (best-effort), never a command
//! failure.

use std::path::Path;

use thiserror::Error;

use cawala_ledger::OperatorSecretKey;

use crate::admin_state::{AdminState, AdminStateError};
use crate::control::ControlNode;

/// Designate `child` as an administrator of this node.
///
/// The child must be a current child of this node (of any kind). The
/// designation is idempotent-refused: re-adding an existing entry is an error.
pub fn admin_add(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    child: &str,
    now: u64,
) -> Result<AdminState, AdminCliError> {
    let mut state = AdminState::load(data_dir)?;
    if state.has(child) {
        return Err(AdminCliError::AlreadyAdmin(child.to_string()));
    }
    let engine = open_engine(data_dir, node_id, operator)?;
    if !is_child(engine.record(), child) {
        return Err(AdminCliError::NotChild(child.to_string()));
    }
    if !state.add(child) {
        // The designation set is full or the id is invalid.
        return Err(AdminCliError::AlreadyAdmin(child.to_string()));
    }
    state.mark_updated(now, "local");
    state.save(data_dir)?;

    audit(
        data_dir,
        "admin-add",
        serde_json::json!({ "node": node_id, "child": child }),
        &state,
    );
    Ok(state)
}

/// Revoke `child`'s administrator designation.
///
/// The child must be a current child of this node (of any kind). Removing a
/// non-designated child is an error.
pub fn admin_remove(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    child: &str,
    now: u64,
) -> Result<AdminState, AdminCliError> {
    let mut state = AdminState::load(data_dir)?;
    if !state.has(child) {
        return Err(AdminCliError::NotAdmin(child.to_string()));
    }
    let engine = open_engine(data_dir, node_id, operator)?;
    if !is_child(engine.record(), child) {
        return Err(AdminCliError::NotChild(child.to_string()));
    }
    state.remove(child);
    state.mark_updated(now, "local");
    state.save(data_dir)?;

    audit(
        data_dir,
        "admin-remove",
        serde_json::json!({ "node": node_id, "child": child }),
        &state,
    );
    Ok(state)
}

/// The persisted administrator designation set.
pub fn admin_list(data_dir: &Path) -> Result<AdminState, AdminCliError> {
    Ok(AdminState::load(data_dir)?)
}

/// Open a control engine to read this node's record.
fn open_engine(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
) -> Result<ControlNode, AdminCliError> {
    ControlNode::open(data_dir, node_id, operator.clone()).map_err(AdminCliError::Control)
}

/// Whether `child` is a current child of this node (of any [`ChildKind`]).
fn is_child(record: &crate::record::NodeRecord, child: &str) -> bool {
    record
        .children
        .iter()
        .any(|candidate| candidate.child_id == child)
}

/// Append the shared `admin-state` audit line (best-effort).
fn audit(data_dir: &Path, action: &str, extra: serde_json::Value, state: &AdminState) {
    let mut line = serde_json::json!({
        "event": "admin-state",
        "action": action,
        "via": "local",
        "actor": "operator",
        "admins": state.list(),
        "updated_by": state.updated_by(),
        "updated_at": state.updated_at(),
    });
    if let (Some(object), Some(extra)) = (line.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            object.insert(key.clone(), value.clone());
        }
    }
    crate::audit::append(data_dir, line);
}

/// Errors a CLI admin action can surface (mapped to a non-zero exit).
#[derive(Debug, Error)]
pub enum AdminCliError {
    /// The target is not a current child of this node.
    #[error("'{0}' is not a current child of this node")]
    NotChild(String),
    /// The target is not designated as an administrator.
    #[error("'{0}' is not a designated administrator")]
    NotAdmin(String),
    /// The target is already designated as an administrator (or the set is
    /// full).
    #[error("'{0}' is already a designated administrator (or the set is full)")]
    AlreadyAdmin(String),
    /// The persisted admin state could not be loaded or saved.
    #[error("admin state: {0}")]
    State(#[from] AdminStateError),
    /// The control engine could not be opened.
    #[error("control engine: {0}")]
    Control(#[from] cawala_control::ControlError),
}
