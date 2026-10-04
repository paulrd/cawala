//! Persisted topology-admin state for this node: `<data-dir>/admin_state.json`.
//!
//! Authority under the topology refactor is a property of `node.json`
//! (R4/R5), the msg-layer authenticated last hop, and this file:
//!
//! ```jsonc
//! {
//!   "version": 1,
//!   "priority": ["<child_node_id>", "..."], // R5 node children, highest first
//!   "current": 0,                            // i32: -1 = none, else index
//!   "lease_until": 1730000300,               // unix secs; 0 = no lease
//!   "epoch": 42,                             // monotonic
//!   "ttl_secs": 300,                         // default 5 min
//!   "updated_at": 1729999999,
//!   "updated_by": "local"                    // "local" | "<admin_node_id>"
//! }
//! ```
//!
//! The file is operator-managed and **fail closed**: an absent file is an empty
//! state, but a present file that is malformed, has an unknown version, or fails
//! validation is rejected. The engine's `reload_admin_state` maps that rejection
//! to an empty in-memory state (remote admin unavailable; the local CLI still
//! works) and audits `admin-state-load-failed`.
//!
//! # Crash safety
//!
//! Mutations are written with an atomic temp-file + rename, matching
//! [`AdminStore::save`](crate::admin_store::AdminStore::save) and
//! [`ValuePolicy::save`](crate::value_policy::ValuePolicy::save). Authority
//! changes persist before memory is updated; lease renewals persist first but
//! must not deny service on a write failure.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use cawala_control::{MAX_NODE_ID_LEN, NodeId};

/// Name of the admin-state file inside the data dir.
pub const ADMIN_STATE_FILE: &str = "admin_state.json";

/// On-disk format version for the admin-state document.
pub const ADMIN_STATE_VERSION: u32 = 1;

/// Default lease duration when an operator has not configured one.
pub const DEFAULT_ADMIN_TTL_SECS: u64 = 300;

/// Upper clamp for a configured lease TTL (30 days), mirroring
/// [`cawala_control::MAX_ADMIN_TTL_SECS`](cawala_control::MAX_ADMIN_TTL_SECS).
pub const MAX_ADMIN_STATE_TTL_SECS: u64 = 30 * 24 * 3600;

/// Maximum number of priority entries (`cawala_topology::MAX_SLOT + 1`).
pub const MAX_PRIORITY: usize = cawala_topology::MAX_SLOT as usize + 1;

/// The on-disk admin-state document. Distinct from [`AdminState`] because the
/// wire form carries a `version` and applies serde defaults that the in-memory
/// type does not need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdminStateDocument {
    /// [`ADMIN_STATE_VERSION`].
    version: u32,
    /// R5 node children eligible for priority administration, highest first.
    #[serde(default)]
    priority: Vec<String>,
    /// Index into `priority`, or `-1` when none.
    #[serde(default = "default_current")]
    current: i32,
    /// Unix seconds until which the current lease is held; `0` means none.
    #[serde(default)]
    lease_until: u64,
    /// Monotone lease epoch.
    #[serde(default)]
    epoch: u64,
    /// Lease duration granted on a renewal.
    #[serde(default = "default_ttl_secs")]
    ttl_secs: u64,
    /// Unix seconds the document was last changed.
    #[serde(default)]
    updated_at: u64,
    /// Who last changed the document (`"local"` or an admin node id).
    #[serde(default = "default_updated_by")]
    updated_by: String,
}

fn default_current() -> i32 {
    -1
}

fn default_ttl_secs() -> u64 {
    DEFAULT_ADMIN_TTL_SECS
}

fn default_updated_by() -> String {
    "local".to_string()
}

/// The in-memory topology-admin state.
///
/// All fields are private; mutations go through the pure helpers below so the
/// callers (the engine, the local CLI) cannot leave the document inconsistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminState {
    priority: Vec<String>,
    current: i32,
    lease_until: u64,
    epoch: u64,
    ttl_secs: u64,
    updated_at: u64,
    updated_by: String,
}

impl AdminState {
    /// The empty, fail-closed state: no priority, no current, no lease, epoch 0.
    pub fn empty() -> Self {
        AdminState {
            priority: Vec::new(),
            current: -1,
            lease_until: 0,
            epoch: 0,
            ttl_secs: DEFAULT_ADMIN_TTL_SECS,
            updated_at: 0,
            updated_by: "local".to_string(),
        }
    }

    /// Load and validate `<data-dir>/admin_state.json`.
    ///
    /// A missing file is [`AdminState::empty`]. A present file is rejected as a
    /// hard error on a read/parse failure, an unknown version, or a validation
    /// failure; the caller must fail closed. An overlarge `ttl_secs` is clamped
    /// rather than rejected.
    pub fn load(data_dir: impl AsRef<Path>) -> Result<Self, AdminStateError> {
        let path = data_dir.as_ref().join(ADMIN_STATE_FILE);
        if !path.exists() {
            return Ok(AdminState::empty());
        }
        let bytes = std::fs::read(&path).map_err(|source| AdminStateError::Read {
            path: path.clone(),
            source,
        })?;
        let document: AdminStateDocument =
            serde_json::from_slice(&bytes).map_err(|source| AdminStateError::Json {
                path: path.clone(),
                source,
            })?;
        if document.version != ADMIN_STATE_VERSION {
            return Err(AdminStateError::UnsupportedVersion(document.version));
        }
        if document.ttl_secs < 1 {
            return Err(AdminStateError::InvalidTtl(document.ttl_secs));
        }
        let state = AdminState {
            priority: document.priority,
            current: document.current,
            lease_until: document.lease_until,
            epoch: document.epoch,
            ttl_secs: document.ttl_secs.min(MAX_ADMIN_STATE_TTL_SECS),
            updated_at: document.updated_at,
            updated_by: document.updated_by,
        };
        state.validate()?;
        Ok(state)
    }

    /// Replace this state with a fresh, validated load from `data_dir`.
    pub fn reload(&mut self, data_dir: impl AsRef<Path>) -> Result<(), AdminStateError> {
        *self = Self::load(data_dir)?;
        Ok(())
    }

    /// Persist via a temp file + atomic rename.
    pub fn save(&self, data_dir: impl AsRef<Path>) -> Result<(), AdminStateError> {
        let path = data_dir.as_ref().join(ADMIN_STATE_FILE);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| AdminStateError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let document = AdminStateDocument {
            version: ADMIN_STATE_VERSION,
            priority: self.priority.clone(),
            current: self.current,
            lease_until: self.lease_until,
            epoch: self.epoch,
            ttl_secs: self.ttl_secs,
            updated_at: self.updated_at,
            updated_by: self.updated_by.clone(),
        };
        let json =
            serde_json::to_string_pretty(&document).map_err(|source| AdminStateError::Json {
                path: path.clone(),
                source,
            })?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, json).map_err(|source| AdminStateError::Write {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, &path).map_err(|source| AdminStateError::Write {
            path: path.clone(),
            source,
        })?;
        Ok(())
    }

    /// Validate the invariants the on-disk form must satisfy.
    fn validate(&self) -> Result<(), AdminStateError> {
        if self.priority.len() > MAX_PRIORITY {
            return Err(AdminStateError::TooManyPriority {
                len: self.priority.len(),
                max: MAX_PRIORITY,
            });
        }
        for (index, id) in self.priority.iter().enumerate() {
            if id.is_empty() {
                return Err(AdminStateError::EmptyPriorityId(index));
            }
            if id.len() > MAX_NODE_ID_LEN {
                return Err(AdminStateError::PriorityIdTooLong {
                    index,
                    len: id.len(),
                    max: MAX_NODE_ID_LEN,
                });
            }
            if self.priority[..index].contains(id) {
                return Err(AdminStateError::DuplicatePriority(id.clone()));
            }
        }
        if self.current < -1 {
            return Err(AdminStateError::CurrentOutOfRange(self.current));
        }
        if self.current >= 0 && self.current as usize >= self.priority.len() {
            return Err(AdminStateError::CurrentOutOfRange(self.current));
        }
        if self.ttl_secs < 1 {
            return Err(AdminStateError::InvalidTtl(self.ttl_secs));
        }
        Ok(())
    }

    /// The current priority child id, if `current` names one.
    pub fn current_id(&self) -> Option<NodeId> {
        if self.current < 0 {
            return None;
        }
        self.priority
            .get(self.current as usize)
            .map(|id| NodeId::from(id.clone()))
    }

    /// The current priority index (`-1` for none).
    pub fn current_index(&self) -> i32 {
        self.current
    }

    /// Whether a lease is held at unix-seconds `now` (a `lease_until` of `0`
    /// means no lease). The boundary is inclusive.
    pub fn lease_valid(&self, now: u64) -> bool {
        self.lease_until != 0 && now <= self.lease_until
    }

    /// The `priority` list, highest first.
    pub fn priority(&self) -> &[String] {
        &self.priority
    }

    /// Number of priority entries, saturating at `u8::MAX`.
    pub fn priority_len(&self) -> u8 {
        self.priority.len().min(u8::MAX as usize) as u8
    }

    /// Unix seconds until which the current lease is held (`0` = none).
    pub fn lease_until(&self) -> u64 {
        self.lease_until
    }

    /// The monotone lease epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The configured lease duration in seconds.
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Unix seconds the document was last changed.
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Who last changed the document (`"local"` or an admin node id).
    pub fn updated_by(&self) -> &str {
        &self.updated_by
    }

    /// Set the current priority index, clamping an out-of-range value to `-1`.
    ///
    /// Does **not** bump the epoch; callers that change the current admin must
    /// call [`AdminState::bump_epoch`] first (anti-downgrade, spec §5.4).
    pub fn set_current(&mut self, current: i32) {
        if current >= 0 && (current as usize) < self.priority.len() {
            self.current = current;
        } else {
            self.current = -1;
        }
    }

    /// Replace the priority list, clamping `current` to `-1` when it no longer
    /// points at an entry. Does not bump the epoch; the caller composes that.
    pub fn set_priority(&mut self, priority: Vec<String>) {
        self.priority = priority;
        if self.current >= self.priority.len() as i32 {
            self.current = -1;
        }
        if self.priority.is_empty() {
            self.current = -1;
            self.lease_until = 0;
        }
    }

    /// Set the lease duration (seconds). Clamped to `1..=MAX_ADMIN_STATE_TTL_SECS`.
    pub fn set_ttl_secs(&mut self, ttl_secs: u64) {
        self.ttl_secs = ttl_secs.clamp(1, MAX_ADMIN_STATE_TTL_SECS);
    }

    /// Set `lease_until` directly (`0` clears the lease).
    pub fn set_lease_until(&mut self, lease_until: u64) {
        self.lease_until = lease_until;
    }

    /// Bump the monotone epoch. Never decrements (anti-downgrade).
    pub fn bump_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
    }

    /// Grant a lease until `now + ttl_secs` to the current priority entry.
    pub fn record_lease(&mut self, now: u64) {
        self.lease_until = now.saturating_add(self.ttl_secs);
    }

    /// Record who changed the document and when.
    pub fn mark_updated(&mut self, now: u64, by: &str) {
        self.updated_at = now;
        self.updated_by = by.to_string();
    }

    /// Drop `priority` entries for which `is_child` is false, clamping `current`
    /// (and clearing the lease) when it pointed at a pruned entry.
    ///
    /// Returns whether anything was pruned. Spec §4.5: pruned in memory on
    /// reload and written back on the next mutation.
    pub fn prune_missing_children(&mut self, is_child: impl Fn(&str) -> bool) -> bool {
        let before = self.priority.len();
        self.priority.retain(|id| is_child(id));
        if self.priority.len() == before {
            return false;
        }
        if self.priority.is_empty() || self.current >= self.priority.len() as i32 {
            self.current = -1;
            self.lease_until = 0;
        }
        true
    }
}

/// Errors raised while loading or saving [`AdminState`].
#[derive(Debug, Error)]
pub enum AdminStateError {
    /// The document could not be read.
    #[error("failed to read {path}: {source}")]
    Read {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The document could not be written.
    #[error("failed to write {path}: {source}")]
    Write {
        /// The file that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The document was not valid JSON.
    #[error("{path} is not a valid admin state: {source}")]
    Json {
        /// The offending file.
        path: PathBuf,
        /// The serde error.
        source: serde_json::Error,
    },
    /// The document's `version` is not [`ADMIN_STATE_VERSION`].
    #[error("unsupported admin state version {0}")]
    UnsupportedVersion(u32),
    /// The document held more than [`MAX_PRIORITY`] entries.
    #[error("admin state holds {len} priority entries, max {max}")]
    TooManyPriority {
        /// The observed entry count.
        len: usize,
        /// The permitted maximum.
        max: usize,
    },
    /// A priority entry was the empty string.
    #[error("admin state priority entry {0} is empty")]
    EmptyPriorityId(usize),
    /// A priority entry exceeded [`MAX_NODE_ID_LEN`].
    #[error("admin state priority entry {index} is {len} bytes, max {max}")]
    PriorityIdTooLong {
        /// The offending index.
        index: usize,
        /// The observed length.
        len: usize,
        /// The permitted maximum.
        max: usize,
    },
    /// Two priority entries named the same node id.
    #[error("admin state contains duplicate priority entry '{0}'")]
    DuplicatePriority(String),
    /// `current` did not index `priority` (or was below `-1`).
    #[error("admin state current index {0} out of range")]
    CurrentOutOfRange(i32),
    /// `ttl_secs` was less than 1.
    #[error("admin state ttl_secs {0} is below the minimum of 1")]
    InvalidTtl(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_file_defaults_empty() {
        let dir = tempfile::tempdir().unwrap();
        let state = AdminState::load(dir.path()).unwrap();
        assert_eq!(state, AdminState::empty());
        assert_eq!(state.current_index(), -1);
        assert!(!state.lease_valid(0));
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
        assert!(loaded.lease_valid(1_000 + DEFAULT_ADMIN_TTL_SECS));
    }

    #[test]
    fn corrupt_file_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ADMIN_STATE_FILE), b"{ not json").unwrap();
        let err = AdminState::load(dir.path()).unwrap_err();
        assert!(matches!(err, AdminStateError::Json { .. }), "{err}");
    }

    #[test]
    fn current_out_of_range_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let document = serde_json::json!({
            "version": ADMIN_STATE_VERSION,
            "priority": ["admin-a"],
            "current": 1,
        });
        std::fs::write(
            dir.path().join(ADMIN_STATE_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let err = AdminState::load(dir.path()).unwrap_err();
        assert!(
            matches!(err, AdminStateError::CurrentOutOfRange(1)),
            "{err}"
        );
    }

    #[test]
    fn priority_pruned_when_child_missing() {
        let mut state = AdminState::empty();
        state.set_priority(vec!["keep".to_string(), "gone".to_string()]);
        state.set_current(0);
        assert!(state.prune_missing_children(|id| id == "keep"));
        assert_eq!(state.priority(), &["keep".to_string()]);
        assert_eq!(state.current_index(), 0);

        // Pruning the current entry clamps current and clears the lease.
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

    #[test]
    fn large_ttl_is_clamped_not_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let document = serde_json::json!({
            "version": ADMIN_STATE_VERSION,
            "priority": [],
            "current": -1,
            "ttl_secs": u64::MAX,
        });
        std::fs::write(
            dir.path().join(ADMIN_STATE_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let loaded = AdminState::load(dir.path()).unwrap();
        assert_eq!(loaded.ttl_secs(), MAX_ADMIN_STATE_TTL_SECS);
    }

    #[test]
    fn duplicate_priority_entry_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let document = serde_json::json!({
            "version": ADMIN_STATE_VERSION,
            "priority": ["dup", "dup"],
            "current": -1,
        });
        std::fs::write(
            dir.path().join(ADMIN_STATE_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let err = AdminState::load(dir.path()).unwrap_err();
        assert!(matches!(err, AdminStateError::DuplicatePriority(_)), "{err}");
    }
}
