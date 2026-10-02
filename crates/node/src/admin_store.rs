//! Persisted admin grants for this node: `<data-dir>/admins.json`.
//!
//! The document is
//! `{ "version": 1, "admins": [ <SignedAdminGrantV2 | SignedAdminGrant> ] }`.
//! It holds only public data: each row is an operator-signed grant attesting
//! that some *other* operator key may administer this node. The granting
//! operator key is always this node's own key, which [`AdminStore::load`]
//! enforces.
//!
//! # Dual-accept, fail closed
//!
//! A row is either a v2 [`SignedAdminGrantV2`] (explicit [`AdminScopes`]) or a
//! legacy v1 [`SignedAdminGrant`] (interpreted as joins-only, never widened).
//! The two are distinguished structurally and untagged, so each row's original
//! form is preserved across a save/load cycle (a v1 signature stays
//! verifiable). Per-type version validation makes a shape/version mismatch
//! (`version` says one thing, the fields say another) a **hard load error**: it
//! is never coerced from one form to the other.
//!
//! A missing file is an empty store, but a present file that is malformed, has
//! the wrong envelope version, carries a grant that does not verify under this
//! node's operator key, is scoped to another node, is structurally invalid, or
//! duplicates an admin key is a **hard error**. Expired grants are retained
//! (visible/auditable) but [`AdminStore::active_scopes`] never reports them.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use cawala_control::{
    AdminScopes, ControlError, NodeId, SignedAdminGrant, SignedAdminGrantV2,
};
use cawala_ledger::OperatorPubKey;

/// Name of the admin-grants file inside the data dir.
pub const ADMINS_FILE: &str = "admins.json";

/// On-disk format version for the admin-grants document.
pub const ADMIN_STORE_VERSION: u32 = 1;

/// Defensive cap on the number of stored grants, so a large local document
/// cannot force an unbounded allocation on load.
pub const MAX_ADMIN_ENTRIES: usize = 256;

/// One persisted grant row, in either its v2 or legacy v1 form.
///
/// `#[serde(untagged)]` tries [`StoredGrant::V2`] first, then
/// [`StoredGrant::V1`]. The v2 and v1 grant shapes are structurally distinct
/// (`scopes` vs `scope`), so the correct form is selected by shape; a
/// shape/version mismatch is caught by [`StoredGrant::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StoredGrant {
    /// A v2 grant with explicit scopes.
    V2(SignedAdminGrantV2),
    /// A legacy v1 grant, interpreted as joins-only.
    V1(SignedAdminGrant),
}

impl StoredGrant {
    /// The admin operator key this row grants.
    pub fn admin(&self) -> OperatorPubKey {
        match self {
            StoredGrant::V2(signed) => signed.grant.admin,
            StoredGrant::V1(signed) => signed.grant.admin,
        }
    }

    /// The node this grant is scoped to.
    pub fn node(&self) -> &NodeId {
        match self {
            StoredGrant::V2(signed) => &signed.grant.node,
            StoredGrant::V1(signed) => &signed.grant.node,
        }
    }

    /// The grant's wire version (2 for [`StoredGrant::V2`], 1 for
    /// [`StoredGrant::V1`]).
    pub fn version(&self) -> u8 {
        match self {
            StoredGrant::V2(signed) => signed.grant.version,
            StoredGrant::V1(signed) => signed.grant.version,
        }
    }

    /// Unix seconds when the grant was issued.
    pub fn granted_at(&self) -> u64 {
        match self {
            StoredGrant::V2(signed) => signed.grant.granted_at,
            StoredGrant::V1(signed) => signed.grant.granted_at,
        }
    }

    /// Unix seconds after which the grant is inactive.
    pub fn expiry(&self) -> u64 {
        match self {
            StoredGrant::V2(signed) => signed.grant.expiry,
            StoredGrant::V1(signed) => signed.grant.expiry,
        }
    }

    /// Optional human-readable label.
    pub fn label(&self) -> Option<&str> {
        match self {
            StoredGrant::V2(signed) => signed.grant.label.as_deref(),
            StoredGrant::V1(signed) => signed.grant.label.as_deref(),
        }
    }

    /// The effective scope set: a v2 row's explicit scopes, or exactly
    /// `{ joins }` for a legacy v1 row.
    pub fn scopes(&self) -> AdminScopes {
        match self {
            StoredGrant::V2(signed) => signed.grant.scopes,
            StoredGrant::V1(_) => AdminScopes::v1(),
        }
    }

    /// Validate the row against its **own** declared version.
    ///
    /// A v2 row runs [`AdminGrantV2::validate`](cawala_control::AdminGrantV2::validate)
    /// (which checks `version == ADMIN_GRANT_VERSION`); a v1 row runs
    /// [`AdminGrant::validate`](cawala_control::AdminGrant::validate) (which
    /// checks `version == ADMIN_GRANT_V1_VERSION`). Either mismatch is a hard
    /// error, so a shape/version mismatch is rejected rather than coerced.
    pub fn validate(&self) -> Result<(), ControlError> {
        match self {
            StoredGrant::V2(signed) => signed.grant.validate(),
            StoredGrant::V1(signed) => signed.grant.validate(),
        }
    }

    /// Verify the row's signature under the granting node's operator key.
    pub fn verify(&self, node_operator: &OperatorPubKey) -> Result<(), ControlError> {
        match self {
            StoredGrant::V2(signed) => signed.verify(node_operator),
            StoredGrant::V1(signed) => signed.verify(node_operator),
        }
    }

    /// Whether the grant is active at unix-seconds `now` (boundary inclusive).
    pub fn is_active(&self, now: u64) -> bool {
        now <= self.expiry()
    }
}

impl From<SignedAdminGrantV2> for StoredGrant {
    fn from(signed: SignedAdminGrantV2) -> Self {
        StoredGrant::V2(signed)
    }
}

impl From<SignedAdminGrant> for StoredGrant {
    fn from(signed: SignedAdminGrant) -> Self {
        StoredGrant::V1(signed)
    }
}

/// The on-disk admin-grants document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdminStoreDocument {
    /// [`ADMIN_STORE_VERSION`].
    version: u32,
    /// Operator-signed grants, oldest first.
    admins: Vec<StoredGrant>,
}

/// An in-memory handle to the persisted admin grants.
///
/// Every mutating method updates memory only; the caller persists with
/// [`AdminStore::save`]. Validation happens on load and on grant.
#[derive(Debug, Clone, Default)]
pub struct AdminStore {
    admins: Vec<StoredGrant>,
}

impl AdminStore {
    /// An empty store (no grants). Used when reloading fails, to fail closed.
    pub fn empty() -> Self {
        AdminStore { admins: Vec::new() }
    }

    /// Load and validate `<data-dir>/admins.json`.
    ///
    /// A missing file yields an empty store. Every present row must validate
    /// against its own version, verify under `node_operator`, and be scoped to
    /// `node_id`; otherwise the whole document is rejected. `granted_at`/
    /// `expiry` bounds are checked, but an expired grant is not an error (it is
    /// simply inactive).
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
            entry.validate().map_err(AdminStoreError::InvalidGrant)?;
            if entry.node().as_str() != node_id {
                return Err(AdminStoreError::NodeMismatch {
                    found: entry.node().clone(),
                    expected: node_id.to_string(),
                });
            }
            entry
                .verify(node_operator)
                .map_err(|_| AdminStoreError::InvalidSignature)?;
            if document
                .admins
                .iter()
                .filter(|other| other.admin() == entry.admin())
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
    ///
    /// Each row is written back in its original form (v2 rows keep their
    /// `scopes`, v1 rows stay a legacy grant), so a v1 signature remains
    /// verifiable across a save/load cycle.
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

    /// Insert or replace the grant for `stored.admin()`.
    ///
    /// The caller validates and persists; see [`AdminStore::save`].
    pub fn grant(&mut self, stored: StoredGrant) {
        let admin = stored.admin();
        if let Some(existing) = self
            .admins
            .iter_mut()
            .find(|entry| entry.admin() == admin)
        {
            *existing = stored;
        } else {
            self.admins.push(stored);
        }
    }

    /// Remove the grant for `admin`, returning whether one was present.
    pub fn revoke(&mut self, admin: &OperatorPubKey) -> bool {
        let before = self.admins.len();
        self.admins.retain(|entry| &entry.admin() != admin);
        self.admins.len() != before
    }

    /// The active scope set held by `admin` at unix-seconds `now`, if any.
    ///
    /// A legacy v1 grant maps to exactly `AdminScopes::v1()` (joins-only); a v2
    /// grant reports its explicit scopes. An expired grant (or one for a
    /// different key) is `None`; expired entries are retained in
    /// [`AdminStore::entries`] for visibility.
    pub fn active_scopes(&self, admin: &OperatorPubKey, now: u64) -> Option<AdminScopes> {
        self.admins
            .iter()
            .find(|entry| &entry.admin() == admin && entry.is_active(now))
            .map(StoredGrant::scopes)
    }

    /// All stored grants, oldest first (including expired ones).
    pub fn entries(&self) -> &[StoredGrant] {
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
    /// A stored grant failed structural validation (version/label/TTL/scopes).
    #[error("stored admin grant is invalid: {0}")]
    InvalidGrant(ControlError),
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
        ADMIN_GRANT_V1_VERSION, ADMIN_GRANT_VERSION, AdminGrant, AdminScope,
        DEFAULT_ADMIN_TTL_SECS, MAX_ADMIN_TTL_SECS,
    };
    use cawala_ledger::{OperatorSecretKey, Signature};

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn v1_grant(node_id: &str, admin_seed: u8, granted_at: u64, expiry: u64) -> AdminGrant {
        AdminGrant {
            version: ADMIN_GRANT_V1_VERSION,
            node: node(node_id),
            admin: operator(admin_seed).public(),
            scope: AdminScope::Admin,
            granted_at,
            expiry,
            label: Some("v1".to_string()),
        }
    }

    fn v2_grant(node_id: &str, admin_seed: u8, granted_at: u64, expiry: u64) -> cawala_control::AdminGrantV2 {
        cawala_control::AdminGrantV2 {
            version: ADMIN_GRANT_VERSION,
            node: node(node_id),
            admin: operator(admin_seed).public(),
            scopes: AdminScopes {
                joins: true,
                topology: true,
                value: false,
            },
            granted_at,
            expiry,
            label: Some("v2".to_string()),
        }
    }

    /// A legacy v1 grant signed by the node operator `node_seed`.
    fn signed_v1(node_id: &str, node_seed: u8, admin_seed: u8) -> SignedAdminGrant {
        SignedAdminGrant::authorize(
            v1_grant(node_id, admin_seed, 1_000, 1_000 + DEFAULT_ADMIN_TTL_SECS),
            &operator(node_seed),
        )
        .unwrap()
    }

    /// A v2 grant signed by the node operator `node_seed`.
    fn signed_v2(node_id: &str, node_seed: u8, admin_seed: u8) -> SignedAdminGrantV2 {
        SignedAdminGrantV2::authorize(
            v2_grant(node_id, admin_seed, 1_000, 1_000 + DEFAULT_ADMIN_TTL_SECS),
            &operator(node_seed),
        )
        .unwrap()
    }

    fn zero_sig() -> Signature {
        Signature::from_bytes(&[0u8; Signature::LENGTH])
    }

    #[test]
    fn absent_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn v1_grant_maps_to_joins_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AdminStore::empty();
        store.grant(StoredGrant::V1(signed_v1("node-a", 1, 3)));
        store.save(dir.path()).unwrap();

        let loaded = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.entries()[0].version(), ADMIN_GRANT_V1_VERSION);
        assert_eq!(
            loaded.active_scopes(&operator(3).public(), 1_500),
            Some(AdminScopes::v1())
        );
        // At/after expiry the grant is inactive but still retained.
        let expiry = 1_000 + DEFAULT_ADMIN_TTL_SECS;
        assert_eq!(
            loaded.active_scopes(&operator(3).public(), expiry),
            Some(AdminScopes::v1())
        );
        assert_eq!(loaded.active_scopes(&operator(3).public(), expiry + 1), None);
        assert_eq!(loaded.len(), 1, "expired grants are retained");
    }

    #[test]
    fn v2_round_trip_preserves_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AdminStore::empty();
        store.grant(StoredGrant::V2(signed_v2("node-a", 1, 3)));
        store.save(dir.path()).unwrap();

        let loaded = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap();
        assert_eq!(loaded.entries()[0].version(), ADMIN_GRANT_VERSION);
        assert_eq!(
            loaded.active_scopes(&operator(3).public(), 1_500),
            Some(AdminScopes {
                joins: true,
                topology: true,
                value: false,
            })
        );
    }

    #[test]
    fn mixed_v1_and_v2_rows_round_trip_in_form() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AdminStore::empty();
        store.grant(StoredGrant::V1(signed_v1("node-a", 1, 3)));
        store.grant(StoredGrant::V2(signed_v2("node-a", 1, 4)));
        store.save(dir.path()).unwrap();

        let raw = std::fs::read_to_string(dir.path().join(ADMINS_FILE)).unwrap();
        assert!(raw.contains("\"scope\""), "v1 row keeps its legacy shape");
        assert!(raw.contains("\"scopes\""), "v2 row keeps its new shape");

        let loaded = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded.active_scopes(&operator(3).public(), 1_500),
            Some(AdminScopes::v1())
        );
        assert_eq!(
            loaded.active_scopes(&operator(4).public(), 1_500),
            Some(AdminScopes {
                joins: true,
                topology: true,
                value: false,
            })
        );
    }

    #[test]
    fn v1_save_keeps_signature_verifiable() {
        let dir = tempfile::tempdir().unwrap();
        let original = signed_v1("node-a", 1, 3);
        let mut store = AdminStore::empty();
        store.grant(StoredGrant::V1(original.clone()));
        store.save(dir.path()).unwrap();

        let loaded = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap();
        let StoredGrant::V1(reloaded) = &loaded.entries()[0] else {
            panic!("a v1 row must stay a V1 row");
        };
        assert_eq!(reloaded.grant.version, ADMIN_GRANT_V1_VERSION);
        assert_eq!(reloaded, &original);
        // The signature is unchanged and still verifies under the node key.
        assert_eq!(reloaded.verify(&operator(1).public()), Ok(()));

        // A second save/load cycle also preserves it.
        loaded.save(dir.path()).unwrap();
        let again = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap();
        assert_eq!(again.entries()[0], StoredGrant::V1(original));
    }

    #[test]
    fn grant_replaces_same_admin() {
        let mut store = AdminStore::empty();
        store.grant(StoredGrant::V1(signed_v1("node-a", 1, 3)));
        let newer = SignedAdminGrantV2::authorize(
            v2_grant("node-a", 3, 2_000, 2_000 + MAX_ADMIN_TTL_SECS),
            &operator(1),
        )
        .unwrap();
        store.grant(StoredGrant::V2(newer.clone()));
        assert_eq!(store.len(), 1, "the same admin key replaces, not appends");
        assert_eq!(store.entries()[0], StoredGrant::V2(newer));
    }

    #[test]
    fn revoke_returns_whether_present() {
        let mut store = AdminStore::empty();
        store.grant(StoredGrant::V1(signed_v1("node-a", 1, 3)));
        assert!(store.revoke(&operator(3).public()));
        assert!(!store.revoke(&operator(3).public()));
        assert!(store.is_empty());
    }

    #[test]
    fn wrong_operator_signature_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = {
            let mut store = AdminStore::empty();
            store.grant(StoredGrant::V2(signed_v2("node-a", 1, 3)));
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
        store.grant(StoredGrant::V1(signed_v1("node-a", 1, 3)));
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
    fn unsupported_envelope_version_rejected() {
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
    fn v2_shape_with_v1_version_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        // Fields declare a v2 grant (`scopes`) but the version is 1.
        let document = serde_json::json!({
            "version": ADMIN_STORE_VERSION,
            "admins": [{
                "grant": {
                    "version": ADMIN_GRANT_V1_VERSION,
                    "node": "node-a",
                    "admin": operator(3).public(),
                    "scopes": {"joins": true, "topology": false, "value": false},
                    "granted_at": 1_000u64,
                    "expiry": 2_000u64,
                    "label": null,
                },
                "signature": zero_sig(),
            }],
        });
        std::fs::write(
            dir.path().join(ADMINS_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let err = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap_err();
        assert!(
            matches!(
                err,
                AdminStoreError::InvalidGrant(ControlError::UnsupportedVersion(_))
            ),
            "{err}"
        );
    }

    #[test]
    fn v1_shape_with_v2_version_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        // Fields declare a legacy v1 grant (`scope`) but the version is 2.
        let document = serde_json::json!({
            "version": ADMIN_STORE_VERSION,
            "admins": [{
                "grant": {
                    "version": ADMIN_GRANT_VERSION,
                    "node": "node-a",
                    "admin": operator(3).public(),
                    "scope": "admin",
                    "granted_at": 1_000u64,
                    "expiry": 2_000u64,
                    "label": null,
                },
                "signature": zero_sig(),
            }],
        });
        std::fs::write(
            dir.path().join(ADMINS_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let err = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap_err();
        assert!(
            matches!(
                err,
                AdminStoreError::InvalidGrant(ControlError::UnsupportedVersion(_))
            ),
            "{err}"
        );
    }

    #[test]
    fn unknown_version_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let document = serde_json::json!({
            "version": ADMIN_STORE_VERSION,
            "admins": [{
                "grant": {
                    "version": 9u8,
                    "node": "node-a",
                    "admin": operator(3).public(),
                    "scope": "admin",
                    "granted_at": 1_000u64,
                    "expiry": 2_000u64,
                    "label": null,
                },
                "signature": zero_sig(),
            }],
        });
        std::fs::write(
            dir.path().join(ADMINS_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let err = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap_err();
        assert!(
            matches!(
                err,
                AdminStoreError::InvalidGrant(ControlError::UnsupportedVersion(9))
            ),
            "{err}"
        );
    }

    #[test]
    fn duplicate_admin_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let entry = StoredGrant::V2(signed_v2("node-a", 1, 3));
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
    fn v2_empty_scopes_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let document = serde_json::json!({
            "version": ADMIN_STORE_VERSION,
            "admins": [{
                "grant": {
                    "version": ADMIN_GRANT_VERSION,
                    "node": "node-a",
                    "admin": operator(3).public(),
                    "scopes": {"joins": false, "topology": false, "value": false},
                    "granted_at": 1_000u64,
                    "expiry": 2_000u64,
                    "label": null,
                },
                "signature": zero_sig(),
            }],
        });
        std::fs::write(
            dir.path().join(ADMINS_FILE),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let err = AdminStore::load(dir.path(), "node-a", &operator(1).public()).unwrap_err();
        assert!(
            matches!(
                err,
                AdminStoreError::InvalidGrant(ControlError::EmptyAdminScopes)
            ),
            "{err}"
        );
    }

    #[test]
    fn v1_invalid_ttl_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let unvalidated = SignedAdminGrant {
            grant: v1_grant("node-a", 3, 1_000, 1_000),
            signature: zero_sig(),
        };
        let document = serde_json::json!({
            "version": ADMIN_STORE_VERSION,
            "admins": [StoredGrant::V1(unvalidated)],
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
    fn expiry_boundary_is_inclusive() {
        let mut store = AdminStore::empty();
        store.grant(StoredGrant::V2(signed_v2("node-a", 1, 3)));
        let expiry = 1_000 + DEFAULT_ADMIN_TTL_SECS;
        assert_eq!(
            store.active_scopes(&operator(3).public(), expiry),
            Some(AdminScopes {
                joins: true,
                topology: true,
                value: false,
            })
        );
        assert_eq!(store.active_scopes(&operator(3).public(), expiry + 1), None);
    }
}
