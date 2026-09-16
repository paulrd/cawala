//! Persisted admin grants for this node: `<data-dir>/admins.json`.
//!
//! The document is
//! `{ "version": 1, "admins": [ { "grant": <AdminGrant>, "signature": <Signature> } ] }`.
//! It holds only public data: each row is an operator-signed
//! [`SignedAdminGrant`] attesting that some *other* operator key may administer
//! this node. The granting operator key is always this node's own key, which
//! [`AdminStore::load`] enforces.
//!
//! # Fail closed on load
//!
//! A missing file is an empty store, but a present file that is malformed,
//! has the wrong version, carries a grant that does not verify under this
//! node's operator key, is scoped to another node, is structurally invalid, or
//! duplicates an admin key is a **hard error**. Expired grants are retained
//! (visible/auditable) but [`AdminStore::active_scope`] never reports them.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use cawala_control::{AdminScope, NodeId, SignedAdminGrant};
use cawala_ledger::OperatorPubKey;

/// Name of the admin-grants file inside the data dir.
pub const ADMINS_FILE: &str = "admins.json";

/// On-disk format version for the admin-grants document.
pub const ADMIN_STORE_VERSION: u32 = 1;

/// Defensive cap on the number of stored grants, so a large local document
/// cannot force an unbounded allocation on load.
pub const MAX_ADMIN_ENTRIES: usize = 256;

/// The on-disk admin-grants document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdminStoreDocument {
    /// [`ADMIN_STORE_VERSION`].
    version: u32,
    /// Operator-signed grants, oldest first.
    admins: Vec<SignedAdminGrant>,
}

/// An in-memory handle to the persisted admin grants.
///
/// Every mutating method updates memory only; the caller persists with
/// [`AdminStore::save`]. Validation happens on load and on grant.
#[derive(Debug, Clone, Default)]
pub struct AdminStore {
    admins: Vec<SignedAdminGrant>,
}

impl AdminStore {
    /// An empty store (no grants). Used when reloading fails, to fail closed.
    pub fn empty() -> Self {
        AdminStore { admins: Vec::new() }
    }

    /// Load and validate `<data-dir>/admins.json`.
    ///
    /// A missing file yields an empty store. Every present entry must verify
    /// under `node_operator` and be scoped to `node_id`; otherwise the whole
    /// document is rejected. `granted_at`/`expiry` bounds are checked, but an
    /// expired grant is not an error (it is simply inactive).
    pub fn load(
        data_dir: impl AsRef<Path>,
        node_id: &str,
        node_operator: &OperatorPubKey,
    ) -> Result<Self, AdminStoreError> {
        let data_dir = data_dir.as_ref();
        let path = data_dir.join(ADMINS_FILE);
        if !path.exists() {
            return Ok(AdminStore::empty());
        }
        let bytes = std::fs::read(&path).map_err(|source| AdminStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let document: AdminStoreDocument =
            serde_json::from_slice(&bytes).map_err(|source| AdminStoreError::Json {
                path: path.clone(),
                source,
            })?;
        if document.version != ADMIN_STORE_VERSION {
            return Err(AdminStoreError::UnsupportedVersion(document.version));
        }
        if document.admins.len() > MAX_ADMIN_ENTRIES {
            return Err(AdminStoreError::TooManyEntries {
                len: document.admins.len(),
                max: MAX_ADMIN_ENTRIES,
            });
        }
        for entry in &document.admins {
            entry
                .grant
                .validate()
                .map_err(AdminStoreError::InvalidGrant)?;
            if entry.grant.node.as_str() != node_id {
                return Err(AdminStoreError::NodeMismatch {
                    found: entry.grant.node.clone(),
                    expected: node_id.to_string(),
                });
            }
            entry
                .verify(node_operator)
                .map_err(|_| AdminStoreError::InvalidSignature)?;
            if document
                .admins
                .iter()
                .filter(|other| other.grant.admin == entry.grant.admin)
                .count()
                > 1
            {
                return Err(AdminStoreError::DuplicateAdmin);
            }
        }
        Ok(AdminStore {
            admins: document.admins,
        })
    }

    /// Replace the in-memory state with a fresh, fully validated load from
    /// `data_dir`.
    ///
    /// This is the engine's fail-closed refresh point: a caller that sees an
    /// error should empty the store rather than keep serving stale grants.
    pub fn reload(
        &mut self,
        data_dir: impl AsRef<Path>,
        node_id: &str,
        node_operator: &OperatorPubKey,
    ) -> Result<(), AdminStoreError> {
        *self = Self::load(data_dir, node_id, node_operator)?;
        Ok(())
    }

    /// Persist to `<data-dir>/admins.json` via a temp file + rename.
    pub fn save(&self, data_dir: impl AsRef<Path>) -> Result<(), AdminStoreError> {
        let path = data_dir.as_ref().join(ADMINS_FILE);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| AdminStoreError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let document = AdminStoreDocument {
            version: ADMIN_STORE_VERSION,
            admins: self.admins.clone(),
        };
        let json =
            serde_json::to_string_pretty(&document).map_err(|source| AdminStoreError::Json {
                path: path.clone(),
                source,
            })?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, json).map_err(|source| AdminStoreError::Write {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, &path).map_err(|source| AdminStoreError::Write {
            path: path.clone(),
            source,
        })?;
        Ok(())
    }

    /// Insert or replace the grant for `signed.grant.admin`.
    ///
    /// The caller validates and persists; see [`AdminStore::save`].
    pub fn grant(&mut self, signed: SignedAdminGrant) {
        let admin = signed.grant.admin;
        if let Some(existing) = self
            .admins
            .iter_mut()
            .find(|entry| entry.grant.admin == admin)
        {
            *existing = signed;
        } else {
            self.admins.push(signed);
        }
    }

    /// Remove the grant for `admin`, returning whether one was present.
    pub fn revoke(&mut self, admin: &OperatorPubKey) -> bool {
        let before = self.admins.len();
        self.admins.retain(|entry| &entry.grant.admin != admin);
        self.admins.len() != before
    }

    /// The active scope held by `admin` at unix-seconds `now`, if any.
    ///
    /// An expired grant (or one for a different key) is `None`; expired entries
    /// are retained in [`AdminStore::entries`] for visibility.
    pub fn active_scope(&self, admin: &OperatorPubKey, now: u64) -> Option<AdminScope> {
        self.admins
            .iter()
            .find(|entry| &entry.grant.admin == admin && now <= entry.grant.expiry)
            .map(|entry| entry.grant.scope)
    }

    /// All stored grants, oldest first (including expired ones).
    pub fn entries(&self) -> &[SignedAdminGrant] {
        &self.admins
    }

    /// Number of stored grants (including expired).
    pub fn len(&self) -> usize {
        self.admins.len()
    }

    /// Whether no grants are stored.
    pub fn is_empty(&self) -> bool {
        self.admins.is_empty()
    }
}

/// Errors raised while loading or saving [`AdminStore`].
#[derive(Debug, Error)]
pub enum AdminStoreError {
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
    #[error("{path} is not a valid admin store: {source}")]
    Json {
        /// The offending file.
        path: PathBuf,
        /// The serde error.
        source: serde_json::Error,
    },
    /// The document's `version` is not [`ADMIN_STORE_VERSION`].
    #[error("unsupported admin store version {0}")]
    UnsupportedVersion(u32),
    /// The document held more than [`MAX_ADMIN_ENTRIES`] grants.
    #[error("admin store holds {len} grants, max {max}")]
    TooManyEntries {
        /// The observed entry count.
        len: usize,
        /// The permitted maximum.
        max: usize,
    },
    /// A stored grant failed structural validation (version/label/TTL).
    #[error("stored admin grant is invalid: {0}")]
    InvalidGrant(cawala_control::ControlError),
    /// A stored grant is scoped to a different node than this one.
    #[error("admin grant is scoped to node '{found}', expected '{expected}'")]
    NodeMismatch {
        /// The node named by the grant.
        found: NodeId,
        /// This node's id.
        expected: String,
    },
    /// A stored grant's signature does not verify under this node's operator
    /// key.
    #[error("stored admin grant does not verify under this node's operator key")]
    InvalidSignature,
    /// Two stored grants name the same admin key.
    #[error("admin store contains a duplicate admin key")]
    DuplicateAdmin,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_control::{
        ADMIN_GRANT_VERSION, AdminGrant, DEFAULT_ADMIN_TTL_SECS, MAX_ADMIN_TTL_SECS,
    };
    use cawala_ledger::OperatorSecretKey;

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn grant(node_id: &str, admin_seed: u8, granted_at: u64, expiry: u64) -> AdminGrant {
        AdminGrant {
            version: ADMIN_GRANT_VERSION,
            node: node(node_id),
            admin: operator(admin_seed).public(),
            scope: AdminScope::Admin,
            granted_at,
            expiry,
            label: Some("audit".to_string()),
        }
    }

    /// A grant signed by the node operator `node_seed`, scoped to `node_id`.
    fn signed(node_id: &str, node_seed: u8, admin_seed: u8) -> SignedAdminGrant {
        SignedAdminGrant::authorize(
            grant(node_id, admin_seed, 1_000, 1_000 + DEFAULT_ADMIN_TTL_SECS),
            &operator(node_seed),
        )
        .unwrap()
    }

    #[test]
    fn absent_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn round_trip_and_active_scope() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AdminStore::empty();
        store.grant(signed("node-a", 1, 3));
        store.grant(signed("node-a", 1, 4));
        store.save(dir.path()).unwrap();

        let loaded = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded.active_scope(&operator(3).public(), 1_500),
            Some(AdminScope::Admin)
        );
        // At/after expiry the grant is inactive but still retained.
        let expiry = 1_000 + DEFAULT_ADMIN_TTL_SECS;
        assert_eq!(
            loaded.active_scope(&operator(3).public(), expiry),
            Some(AdminScope::Admin)
        );
        assert_eq!(loaded.active_scope(&operator(3).public(), expiry + 1), None);
        assert_eq!(loaded.len(), 2, "expired grants are retained");
    }

    #[test]
    fn grant_replaces_same_admin() {
        let mut store = AdminStore::empty();
        store.grant(signed("node-a", 1, 3));
        let newer = SignedAdminGrant::authorize(
            grant("node-a", 3, 2_000, 2_000 + MAX_ADMIN_TTL_SECS),
            &operator(1),
        )
        .unwrap();
        store.grant(newer.clone());
        assert_eq!(store.len(), 1);
        assert_eq!(store.entries()[0], newer);
    }

    #[test]
    fn revoke_returns_whether_present() {
        let mut store = AdminStore::empty();
        store.grant(signed("node-a", 1, 3));
        assert!(store.revoke(&operator(3).public()));
        assert!(!store.revoke(&operator(3).public()));
        assert!(store.is_empty());
    }

    #[test]
    fn wrong_operator_signature_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = {
            let mut store = AdminStore::empty();
            store.grant(signed("node-a", 1, 3));
            store
        };
        store.save(dir.path()).unwrap();

        // This node's operator is seed 2, not the signer's seed 1.
        let err = AdminStore::load(dir.path(), "node-a", &operator(2).public()).unwrap_err();
        assert!(matches!(err, AdminStoreError::InvalidSignature), "{err}");
    }

    #[test]
    fn node_mismatch_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AdminStore::empty();
        store.grant(signed("node-a", 1, 3));
        store.save(dir.path()).unwrap();

        let err = AdminStore::load(dir.path(), "node-b", &operator(1).public()).unwrap_err();
        assert!(matches!(err, AdminStoreError::NodeMismatch { .. }), "{err}");
    }

    #[test]
    fn malformed_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(ADMINS_FILE), b"{ not json").unwrap();
        let err = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap_err();
        assert!(matches!(err, AdminStoreError::Json { .. }), "{err}");
    }

    #[test]
    fn unsupported_version_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let document = serde_json::json!({
            "version": ADMIN_STORE_VERSION + 1,
            "admins": [],
        });
        std::fs::write(
            dir.path().join(ADMINS_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let err = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap_err();
        assert!(
            matches!(err, AdminStoreError::UnsupportedVersion(_)),
            "{err}"
        );
    }

    #[test]
    fn duplicate_admin_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let entry = signed("node-a", 1, 3);
        let document = serde_json::json!({
            "version": ADMIN_STORE_VERSION,
            "admins": [entry, entry],
        });
        std::fs::write(
            dir.path().join(ADMINS_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let err = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap_err();
        assert!(matches!(err, AdminStoreError::DuplicateAdmin), "{err}");
    }

    #[test]
    fn invalid_ttl_rejected() {
        let dir = tempfile::tempdir().unwrap();
        // A grant with `expiry == granted_at` is structurally invalid.
        // `SignedAdminGrant::authorize` refuses to produce one, so build the
        // document by hand; validation runs before signature verification, so
        // the zero signature does not mask the TTL error.
        let unvalidated = SignedAdminGrant {
            grant: AdminGrant {
                version: ADMIN_GRANT_VERSION,
                node: node("node-a"),
                admin: operator(3).public(),
                scope: AdminScope::Admin,
                granted_at: 1_000,
                expiry: 1_000,
                label: None,
            },
            signature: cawala_ledger::Signature::from_bytes(&[0u8; 64]),
        };
        let document = serde_json::json!({
            "version": ADMIN_STORE_VERSION,
            "admins": [unvalidated],
        });
        std::fs::write(
            dir.path().join(ADMINS_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let err = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap_err();
        assert!(matches!(err, AdminStoreError::InvalidGrant(_)), "{err}");
    }

    #[test]
    fn authorize_surfaces_ttl_error() {
        // `AdminGrant::validate` is surfaced through `authorize` too.
        let bad = AdminGrant {
            version: ADMIN_GRANT_VERSION,
            node: node("node-a"),
            admin: operator(3).public(),
            scope: AdminScope::Admin,
            granted_at: 5,
            expiry: 5 + MAX_ADMIN_TTL_SECS + 1,
            label: None,
        };
        let err = SignedAdminGrant::authorize(bad, &operator(1)).unwrap_err();
        assert!(
            matches!(err, cawala_control::ControlError::GrantTtlTooLong { .. }),
            "{err}"
        );
    }
}
