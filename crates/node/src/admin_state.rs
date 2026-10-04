//! Persisted topology-admin state for this node: `<data-dir>/admin_state.json`.
//!
//! Authority under the topology refactor is a property of `node.json` and the
//! msg-layer authenticated last hop, plus this file: the explicit set of
//! **designated administrator children**.
//!
//! ```jsonc
//! {
//!   "version": 1,
//!   "admins": ["<child_id>", "..."], // current children, any ChildKind
//!   "updated_at": 0,
//!   "updated_by": "local"            // "local" | "<admin_node_id>"
//! }
//! ```
//!
//! A child of **any** kind (child node or browser leaf) may be designated. There
//! is no ordering, expiry, or refresh: authority is set membership.
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
//! [`ValuePolicy::save`](crate::value_policy::ValuePolicy::save). The caller
//! persists before updating memory.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use cawala_control::MAX_NODE_ID_LEN;

/// Name of the admin-state file inside the data dir.
pub const ADMIN_STATE_FILE: &str = "admin_state.json";

/// On-disk format version for the admin-state document.
pub const ADMIN_STATE_VERSION: u32 = 1;

/// Maximum number of designated administrators.
pub const MAX_DESIGNATED_ADMINS: usize = 8;

fn default_updated_by() -> String {
    "local".to_string()
}

/// The on-disk admin-state document. Distinct from [`AdminState`] because the
/// wire form carries a `version` and applies serde defaults that the in-memory
/// type does not need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdminStateDocument {
    /// [`ADMIN_STATE_VERSION`].
    version: u32,
    /// Designated administrator child ids (unique, non-empty).
    #[serde(default)]
    admins: Vec<String>,
    /// Unix seconds the document was last changed.
    #[serde(default)]
    updated_at: u64,
    /// Who last changed the document (`"local"` or an admin node id).
    #[serde(default = "default_updated_by")]
    updated_by: String,
}

/// The in-memory topology-admin designation set.
///
/// All fields are private; mutations go through the pure helpers below so the
/// callers (the engine, the local CLI) cannot leave the document inconsistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminState {
    admins: Vec<String>,
    updated_at: u64,
    updated_by: String,
}

impl AdminState {
    /// The empty, fail-closed state: no designated administrators.
    pub fn empty() -> Self {
        AdminState {
            admins: Vec::new(),
            updated_at: 0,
            updated_by: "local".to_string(),
        }
    }

    /// Load and validate `<data-dir>/admin_state.json`.
    ///
    /// A missing file is [`AdminState::empty`]. A present file is rejected as a
    /// hard error on a read/parse failure, an unknown version, or a validation
    /// failure; the caller must fail closed.
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
        let state = AdminState {
            admins: document.admins,
            updated_at: document.updated_at,
            updated_by: document.updated_by,
        };
        state.validate()?;
        Ok(state)
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
            admins: self.admins.clone(),
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
        if self.admins.len() > MAX_DESIGNATED_ADMINS {
            return Err(AdminStateError::TooManyAdmins {
                len: self.admins.len(),
                max: MAX_DESIGNATED_ADMINS,
            });
        }
        for (index, id) in self.admins.iter().enumerate() {
            if id.is_empty() {
                return Err(AdminStateError::EmptyAdminId(index));
            }
            if id.len() > MAX_NODE_ID_LEN {
                return Err(AdminStateError::AdminIdTooLong {
                    index,
                    len: id.len(),
                    max: MAX_NODE_ID_LEN,
                });
            }
            if self.admins[..index].contains(id) {
                return Err(AdminStateError::DuplicateAdmin(id.clone()));
            }
        }
        Ok(())
    }

    /// Whether `id` is a designated administrator.
    pub fn has(&self, id: &str) -> bool {
        self.admins.iter().any(|admin| admin == id)
    }

    /// Designate `id`. Returns whether the set changed.
    ///
    /// Empty ids, already-present ids, and entries beyond
    /// [`MAX_DESIGNATED_ADMINS`] are rejected (the set is left unchanged).
    pub fn add(&mut self, id: &str) -> bool {
        if id.is_empty() || id.len() > MAX_NODE_ID_LEN {
            return false;
        }
        if self.admins.len() >= MAX_DESIGNATED_ADMINS || self.has(id) {
            return false;
        }
        self.admins.push(id.to_string());
        true
    }

    /// Revoke `id`. Returns whether the set changed.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.admins.len();
        self.admins.retain(|admin| admin != id);
        self.admins.len() != before
    }

    /// The designated administrator ids, in insertion order.
    pub fn list(&self) -> &[String] {
        &self.admins
    }

    /// Drop designations for children not in `children`. Returns whether
    /// anything was pruned.
    pub fn prune(&mut self, children: &[String]) -> bool {
        let before = self.admins.len();
        self.admins
            .retain(|admin| children.iter().any(|child| child == admin));
        self.admins.len() != before
    }

    /// Unix seconds the document was last changed.
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Who last changed the document (`"local"` or an admin node id).
    pub fn updated_by(&self) -> &str {
        &self.updated_by
    }

    /// Record who changed the document and when.
    pub fn mark_updated(&mut self, now: u64, by: &str) {
        self.updated_at = now;
        self.updated_by = by.to_string();
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
    /// The document held more than [`MAX_DESIGNATED_ADMINS`] entries.
    #[error("admin state holds {len} admins, max {max}")]
    TooManyAdmins {
        /// The observed entry count.
        len: usize,
        /// The permitted maximum.
        max: usize,
    },
    /// A designated entry was the empty string.
    #[error("admin state entry {0} is empty")]
    EmptyAdminId(usize),
    /// A designated entry exceeded [`MAX_NODE_ID_LEN`].
    #[error("admin state entry {index} is {len} bytes, max {max}")]
    AdminIdTooLong {
        /// The offending index.
        index: usize,
        /// The observed length.
        len: usize,
        /// The permitted maximum.
        max: usize,
    },
    /// Two designated entries named the same node id.
    #[error("admin state contains duplicate entry '{0}'")]
    DuplicateAdmin(String),
}
