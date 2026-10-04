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
//! - `admin add` designates a **current** child (of any [`ChildKind`]); a
//!   non-child is refused. `admin remove` revokes **any** designated id,
//!   current child or not, so stale entries can always be cleared.
//! - `admin list` lists the designated ids and marks entries that are no longer
//!   current children as stale.
//! - `updated_by = "local"`, `updated_at = now`; an `admin-state` audit line is
//!   appended with `via: "local"`, `actor: "operator"`.
//!
//! # Recovery
//!
//! The CLI reads `admin_state.json` **leniently**: a corrupt or over-cap file
//! starts from [`AdminState::empty`] with a warning and an
//! `admin-state-load-failed` audit instead of blocking the command. The local
//! operator is therefore never permanently locked out and can re-seed/repair the
//! file with `admin add`.
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
use crate::record::RecordStore;

/// Designate `child` as an administrator of this node.
///
/// The child must be a current child of this node (of any kind). The
/// designation is idempotent-refused: re-adding an existing entry is an error.
pub fn admin_add(
    data_dir: &Path,
    node_id: &str,
    _operator: &OperatorSecretKey,
    child: &str,
    now: u64,
) -> Result<AdminState, AdminCliError> {
    let mut state = load_for_repair(data_dir);
    if state.has(child) {
        return Err(AdminCliError::AlreadyAdmin(child.to_string()));
    }
    if !is_child(&current_children(data_dir, node_id)?, child) {
        return Err(AdminCliError::NotChild(child.to_string()));
    }
    if !state.add(child) {
        // The id was checked above and is not present, so the set is full (or
        // the id is empty/oversized).
        return Err(AdminCliError::SetFull(child.to_string()));
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
/// Removes `child` regardless of whether it is still a current child, so a
/// stale (non-child) designation can always be cleared. Revoking a
/// non-designated id is an error.
pub fn admin_remove(
    data_dir: &Path,
    node_id: &str,
    _operator: &OperatorSecretKey,
    child: &str,
    now: u64,
) -> Result<AdminState, AdminCliError> {
    let mut state = load_for_repair(data_dir);
    if !state.has(child) {
        return Err(AdminCliError::NotAdmin(child.to_string()));
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

/// List the persisted administrator designation set, marking entries that are no
/// longer current children of this node as stale.
pub fn admin_list(data_dir: &Path, node_id: &str) -> Result<AdminListing, AdminCliError> {
    let state = load_for_repair(data_dir);
    let children = current_children(data_dir, node_id)?;
    let stale = state
        .list()
        .iter()
        .filter(|id| !is_child(&children, id))
        .cloned()
        .collect();
    Ok(AdminListing { state, stale })
}

/// The persisted designation set plus the ids that are no longer current
/// children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminListing {
    /// The persisted administrator designation set.
    pub state: AdminState,
    /// Designated ids that are no longer current children of this node.
    pub stale: Vec<String>,
}

impl AdminListing {
    /// Whether `id` is a stale designation (no longer a current child).
    pub fn is_stale(&self, id: &str) -> bool {
        self.stale.iter().any(|stale| stale == id)
    }
}

/// Load the designation set for a **repair** CLI, starting from
/// [`AdminState::empty`] with a warning/audit when the persisted file is corrupt
/// or over-cap.
///
/// This is the local operator's escape hatch: a malformed `admin_state.json`
/// must not prevent `admin add`/`admin remove` from running, and the next
/// successful write replaces it with a valid document.
fn load_for_repair(data_dir: &Path) -> AdminState {
    match AdminState::load(data_dir) {
        Ok(state) => state,
        Err(err) => {
            // Best-effort audit, mirroring the engine's `admin-state-load-failed`.
            crate::audit::append(
                data_dir,
                serde_json::json!({
                    "event": "admin-state-load-failed",
                    "error": err.to_string(),
                }),
            );
            eprintln!(
                "warning: admin state could not be loaded ({err}); \
                 starting from an empty designation set"
            );
            AdminState::empty()
        }
    }
}

/// The current child node ids of this node, or an empty list when no readable
/// `node.json` exists (all designations are then stale).
fn current_children(data_dir: &Path, node_id: &str) -> Result<Vec<String>, AdminCliError> {
    match RecordStore::open(data_dir, node_id) {
        Ok(record) => Ok(record
            .record()
            .children
            .iter()
            .map(|child| child.child_id.clone())
            .collect()),
        Err(_) => Ok(Vec::new()),
    }
}

/// Whether `child` is a current child of this node (of any [`ChildKind`]).
fn is_child(children: &[String], child: &str) -> bool {
    children.iter().any(|candidate| candidate == child)
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
    /// The designation set already holds
    /// [`MAX_DESIGNATED_ADMINS`](crate::MAX_DESIGNATED_ADMINS) entries.
    #[error("cannot designate '{0}': the administrator set is full")]
    SetFull(String),
    /// The persisted admin state could not be loaded or saved.
    #[error("admin state: {0}")]
    State(#[from] AdminStateError),
}
