//! Operator-CLI logic for `control admin priority|state`.
//!
//! The clap layer in `main.rs` is a thin shell over these functions so the
//! behaviour (validation, state mutation, audit) is unit-testable without a
//! process. Everything is pure filesystem + `cawala_control`; no network and no
//! running engine.
//!
//! Authority under the topology refactor is derived from `node.json` + the
//! persisted [`AdminState`](crate::admin_state::AdminState) priority list. These
//! commands are the **explicit operator seed**: the operator names the node
//! children that may administer this node, in priority order, and selects the
//! current administrator. `priority add` bootstraps the first admin.
//!
//! All mutations are offline-capable: they edit `<data-dir>/admin_state.json`
//! directly, and a running node observes an out-of-process edit through its
//! per-request `reload_admin_state`.
//!
//! # Semantics
//!
//! - `priority add` appends (or, with `--by-join-order`, inserts at the
//!   `(date_joined, id)` position computed from
//!   [`ControlNode::seniority`](crate::control::ControlNode::seniority) — an
//!   ordering helper only, never authority). When it makes a candidate current
//!   (the first admin, or any add under an empty current) it seeds a lease
//!   window so that admin can begin renewing.
//! - `move`, `remove` (demotion), `set-current`, and `reset` bump the monotone
//!   `epoch` whenever they change who is current. `remove` emptying the list
//!   clears `current`/`lease_until`.
//! - Every command fails closed when the target child is not a current
//!   `ChildKind::Node` child, except `state reset` (which is the repair path).
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

use cawala_control::{ChildKind, NodeId};
use cawala_ledger::OperatorSecretKey;

use crate::admin_state::{AdminState, AdminStateError};
use crate::control::ControlNode;

/// Add `child` to the priority list.
///
/// `by_join_order` inserts at the `(date_joined, id)` position; otherwise the
/// entry is appended. The child must be a current `ChildKind::Node` child of
/// this node. When the add makes a candidate current (no current was set, or
/// the list was empty) the new entry becomes current and a lease window is
/// seeded; the epoch is bumped on every add (an authority-list change) and the
/// current admin's lease is refreshed so it can renew under the new epoch.
pub fn priority_add(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    child: &str,
    by_join_order: bool,
    now: u64,
) -> Result<AdminState, AdminCliError> {
    let mut state = AdminState::load(data_dir)?;
    if state.priority().iter().any(|id| id == child) {
        return Err(AdminCliError::AlreadyPriority(child.to_string()));
    }
    let engine = open_engine(data_dir, node_id, operator)?;
    if !is_node_child(engine.record(), child) {
        return Err(AdminCliError::NotChild(child.to_string()));
    }

    let insert_at = if by_join_order {
        join_order_insert_index(&engine.seniority(), state.priority(), child)
    } else {
        state.priority().len()
    };
    let previous_current = state.current_id();

    let mut priority = state.priority().to_vec();
    priority.insert(insert_at, child.to_string());
    state.set_priority(priority);

    // Re-point `current` at the same node if one was set; otherwise the new
    // seed becomes the current administrator.
    let new_current = match previous_current {
        Some(node) => current_index_of(&state, node.as_str()),
        None => Some(insert_at as i32),
    };
    state.bump_epoch();
    state.set_current(new_current.unwrap_or(-1));
    if new_current.is_some() {
        state.record_lease(now);
    }
    state.mark_updated(now, "local");
    state.save(data_dir)?;

    audit(
        data_dir,
        "priority-add",
        serde_json::json!({
            "node": node_id,
            "child": child,
            "to": insert_at,
            "by_join_order": by_join_order,
        }),
        &state,
    );
    Ok(state)
}

/// Remove `child` from the priority list (demotion).
///
/// Removing the current administrator promotes the entry that shifts into its
/// index (the next in priority order) and bumps the epoch; removing the last
/// entry clears `current`/`lease_until`. Removing a non-current entry before
/// `current` merely shifts its index.
pub fn priority_remove(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    child: &str,
    now: u64,
) -> Result<AdminState, AdminCliError> {
    let mut state = AdminState::load(data_dir)?;
    let Some(removed_at) = state.priority().iter().position(|id| id == child) else {
        return Err(AdminCliError::NotPriority(child.to_string()));
    };
    let engine = open_engine(data_dir, node_id, operator)?;
    if !is_node_child(engine.record(), child) {
        return Err(AdminCliError::NotChild(child.to_string()));
    }

    let previous_current = state.current_id();
    let mut priority = state.priority().to_vec();
    priority.remove(removed_at);
    state.set_priority(priority);

    match previous_current {
        None => {
            // No current node; removing the last entry is still an
            // authority-list demotion, so bump the anti-downgrade epoch.
            if state.priority().is_empty() {
                state.bump_epoch();
            }
        }
        Some(node) => match current_index_of(&state, node.as_str()) {
            Some(index) => {
                // The (still-present) current node may simply have shifted.
                state.set_current(index);
            }
            None => {
                // The current node was removed: promote the next priority
                // entry at the vacated index.
                let promote = removed_at.min(state.priority().len().saturating_sub(1));
                state.bump_epoch();
                state.set_current(promote as i32);
                state.record_lease(now);
            }
        },
    }
    state.mark_updated(now, "local");
    state.save(data_dir)?;

    audit(
        data_dir,
        "priority-remove",
        serde_json::json!({
            "node": node_id,
            "child": child,
            "from": removed_at,
        }),
        &state,
    );
    Ok(state)
}

/// Move the priority entry `child` to zero-based index `to`.
///
/// Bumps the epoch when the move changes the current index/position. A `to`
/// equal to the current index is a no-op; an out-of-range `to` is refused.
pub fn priority_move(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    child: &str,
    to: usize,
    now: u64,
) -> Result<AdminState, AdminCliError> {
    let mut state = AdminState::load(data_dir)?;
    let Some(from) = state.priority().iter().position(|id| id == child) else {
        return Err(AdminCliError::NotPriority(child.to_string()));
    };
    if to >= state.priority().len() {
        return Err(AdminCliError::IndexOutOfRange {
            index: to,
            len: state.priority().len(),
        });
    }
    let engine = open_engine(data_dir, node_id, operator)?;
    if !is_node_child(engine.record(), child) {
        return Err(AdminCliError::NotChild(child.to_string()));
    }
    if from == to {
        return Ok(state);
    }

    let previous_current_index = state.current_index();
    let previous_current = state.current_id();
    let mut priority = state.priority().to_vec();
    let entry = priority.remove(from);
    priority.insert(to, entry);
    state.set_priority(priority);

    let new_current_index = match previous_current {
        Some(node) => current_index_of(&state, node.as_str()).unwrap_or(-1),
        None => -1,
    };
    state.set_current(new_current_index);
    if new_current_index != previous_current_index {
        state.bump_epoch();
        if new_current_index >= 0 {
            state.record_lease(now);
        }
    }
    state.mark_updated(now, "local");
    state.save(data_dir)?;

    audit(
        data_dir,
        "priority-move",
        serde_json::json!({
            "node": node_id,
            "child": child,
            "from": from,
            "to": to,
        }),
        &state,
    );
    Ok(state)
}

/// The persisted priority/lease state.
pub fn state_show(data_dir: &Path) -> Result<AdminState, AdminCliError> {
    Ok(AdminState::load(data_dir)?)
}

/// Set the current administrator to `child`, or clear it with `None`.
///
/// `Some(child)` must be a current priority entry and a `ChildKind::Node`
/// child; it becomes current with a seeded lease window and a bumped epoch.
/// `None` clears `current`/`lease_until` and bumps the epoch.
pub fn state_set_current(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    child: Option<&str>,
    now: u64,
) -> Result<AdminState, AdminCliError> {
    let mut state = AdminState::load(data_dir)?;
    match child {
        Some(child) => {
            let Some(index) = state.priority().iter().position(|id| id == child) else {
                return Err(AdminCliError::NotPriority(child.to_string()));
            };
            let engine = open_engine(data_dir, node_id, operator)?;
            if !is_node_child(engine.record(), child) {
                return Err(AdminCliError::NotChild(child.to_string()));
            }
            let changed = state.current_index() != index as i32;
            state.set_current(index as i32);
            if changed {
                state.bump_epoch();
            }
            state.record_lease(now);
        }
        None => {
            if state.current_index() != -1 {
                state.bump_epoch();
            }
            state.set_current(-1);
            state.set_lease_until(0);
        }
    }
    state.mark_updated(now, "local");
    state.save(data_dir)?;

    audit(
        data_dir,
        "state-set-current",
        serde_json::json!({
            "node": node_id,
            "child": child,
        }),
        &state,
    );
    Ok(state)
}

/// Clear the priority list and current administrator (bumps the epoch).
///
/// This is the repair path and the one command that does **not** require the
/// target to be a current child. A corrupt on-disk state is treated as empty so
/// the operator can always reset.
pub fn state_reset(data_dir: &Path, now: u64) -> Result<AdminState, AdminCliError> {
    let mut state = AdminState::load(data_dir).unwrap_or_else(|_| AdminState::empty());
    state.set_priority(Vec::new());
    state.set_current(-1);
    state.set_lease_until(0);
    state.bump_epoch();
    state.mark_updated(now, "local");
    state.save(data_dir)?;

    audit(data_dir, "state-reset", serde_json::json!({}), &state);
    Ok(state)
}

/// Open a control engine to read this node's record and seniority ordering.
fn open_engine(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
) -> Result<ControlNode, AdminCliError> {
    ControlNode::open(data_dir, node_id, operator.clone()).map_err(AdminCliError::Control)
}

/// Whether `child` is a current `ChildKind::Node` child of this node.
fn is_node_child(record: &crate::record::NodeRecord, child: &str) -> bool {
    record
        .children
        .iter()
        .any(|candidate| candidate.child_id == child && candidate.kind == ChildKind::Node)
}

/// The index of the priority entry naming `child`, if present.
fn current_index_of(state: &AdminState, child: &str) -> Option<i32> {
    state
        .priority()
        .iter()
        .position(|id| id == child)
        .map(|index| index as i32)
}

/// The insert position for `child` at its `(date_joined, id)` seniority rank.
///
/// `seniority` is [`ControlNode::seniority`](crate::control::ControlNode::seniority)
/// (`(id, date_joined)` in record order); `priority` is the existing list. The
/// new entry is placed before the first existing priority entry that sorts
/// after it, matching join order for the priority subset.
fn join_order_insert_index(
    seniority: &[(NodeId, u64)],
    priority: &[String],
    child: &str,
) -> usize {
    let new_key = join_key(seniority, child);
    for (index, existing) in priority.iter().enumerate() {
        if join_key(seniority, existing) > new_key {
            return index;
        }
    }
    priority.len()
}

/// The `(date_joined, id)` ordering key for `child`.
///
/// A missing child sorts last (`u64::MAX`), which cannot happen for the
/// validated target but keeps the ordering total for stale priority entries.
fn join_key<'a>(seniority: &'a [(NodeId, u64)], child: &'a str) -> (u64, &'a str) {
    seniority
        .iter()
        .find(|(id, _)| id.as_str() == child)
        .map(|(id, joined)| (*joined, id.as_str()))
        .unwrap_or((u64::MAX, child))
}

/// Append the shared `admin-state` audit line (best-effort).
fn audit(data_dir: &Path, action: &str, extra: serde_json::Value, state: &AdminState) {
    let mut line = serde_json::json!({
        "event": "admin-state",
        "action": action,
        "via": "local",
        "actor": "operator",
        "priority": state.priority(),
        "current": state.current_index(),
        "lease_until": state.lease_until(),
        "epoch": state.epoch(),
        "updated_by": state.updated_by(),
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
    /// The target is not a current `ChildKind::Node` child of this node.
    #[error("'{0}' is not a current node child of this node")]
    NotChild(String),
    /// The target is not in the priority list.
    #[error("'{0}' is not in the priority list")]
    NotPriority(String),
    /// The target is already in the priority list.
    #[error("'{0}' is already in the priority list")]
    AlreadyPriority(String),
    /// A `--to` index did not address a priority entry.
    #[error("priority index {index} is out of range (length {len})")]
    IndexOutOfRange {
        /// The requested index.
        index: usize,
        /// The current priority length.
        len: usize,
    },
    /// The persisted admin state could not be loaded or saved.
    #[error("admin state: {0}")]
    State(#[from] AdminStateError),
    /// The control engine could not be opened.
    #[error("control engine: {0}")]
    Control(#[from] cawala_control::ControlError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seniority() -> Vec<(NodeId, u64)> {
        vec![
            (NodeId::from("a"), 100),
            (NodeId::from("b"), 100),
            (NodeId::from("c"), 200),
        ]
    }

    #[test]
    fn plain_add_appends() {
        let priority = vec!["b".to_string()];
        assert_eq!(join_order_insert_index(&seniority(), &priority, "c"), 1);
    }

    #[test]
    fn join_order_inserts_by_date_then_id() {
        // `c` joined last, so it goes to the end.
        assert_eq!(join_order_insert_index(&seniority(), &[], "c"), 0);
        // `a` ties `b` on date and sorts first.
        let priority = vec!["b".to_string()];
        assert_eq!(join_order_insert_index(&seniority(), &priority, "a"), 0);
        // `b` inserted into `[a, c]` lands between them (same date, id order).
        let priority = vec!["a".to_string(), "c".to_string()];
        assert_eq!(join_order_insert_index(&seniority(), &priority, "b"), 1);
    }
}
