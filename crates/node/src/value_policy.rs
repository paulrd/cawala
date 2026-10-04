//! Operator-configured caps for value issue/burn operations.
//!
//! `AdminIssue`/`AdminBurn` are the only operations with monetary blast radius,
//! so they are bounded by an unsigned, operator-managed policy file at
//! `<data-dir>/value_policy.json`. The file is **deny-by-default**: if it is
//! absent, corrupt, has an unknown version, or is missing a required limit, the
//! engine serves no value authority (the request is refused `Internal`). File
//! permissions are the trust boundary; the node never accepts limits from the
//! browser.
//!
//! ```json
//! { "version": 1,
//!   "defaults": { "per_request_max": 1000, "window_secs": 86400,
//!                 "window_max": 10000, "per_account_max": 5000 },
//!   "admins": { "<controller-pub-hex>": { <same four> } } }
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use cawala_ledger::OperatorPubKey;

/// Name of the value-policy file inside the data dir.
pub const VALUE_POLICY_FILE: &str = "value_policy.json";

/// On-disk format version for the value-policy document.
pub const VALUE_POLICY_VERSION: u32 = 1;

/// The four limits applied to a value operation.
///
/// All four fields are **required** in a policy document: a partially specified
/// limit set is rejected (deny-by-default), never defaulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueLimits {
    /// Maximum amount for a single issue/burn. `0` denies every operation.
    pub per_request_max: u64,
    /// Length, in seconds, of the node-wide issuance window.
    pub window_secs: u64,
    /// Maximum total issued amount within `window_secs` (Issue only).
    pub window_max: u64,
    /// Maximum post-issue balance of an account (Issue only).
    pub per_account_max: u64,
}

impl ValueLimits {
    /// The all-zero limits: every operation is refused (but the policy is
    /// structurally valid, so the refusal is `LimitExceeded`, not `Internal`).
    pub const fn deny_all() -> Self {
        ValueLimits {
            per_request_max: 0,
            window_secs: 0,
            window_max: 0,
            per_account_max: 0,
        }
    }
}

/// The operator-managed value policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValuePolicy {
    /// [`VALUE_POLICY_VERSION`].
    pub version: u32,
    /// Limits applied unless a controller-specific override exists.
    pub defaults: ValueLimits,
    /// Per-controller overrides keyed by 64-hex operator public key.
    #[serde(default)]
    pub admins: BTreeMap<String, ValueLimits>,
}

impl ValuePolicy {
    /// A structurally valid policy that denies every operation.
    pub fn deny_all() -> Self {
        ValuePolicy {
            version: VALUE_POLICY_VERSION,
            defaults: ValueLimits::deny_all(),
            admins: BTreeMap::new(),
        }
    }

    /// The limits for `controller`: its override when present, else `defaults`.
    ///
    /// Keys are normalized to lowercase at load, so a controller hex written in
    /// either case matches its override (an operator cannot silently fall back
    /// to the looser `defaults` through a case mismatch).
    pub fn limits_for(&self, controller: &OperatorPubKey) -> ValueLimits {
        self.admins
            .get(&controller.to_string().to_lowercase())
            .copied()
            .unwrap_or(self.defaults)
    }

    /// Lowercase every `admins` key so lookups are case-insensitive.
    fn normalize_admin_keys(&mut self) {
        let mut normalized = BTreeMap::new();
        for (key, limits) in std::mem::take(&mut self.admins) {
            normalized.insert(key.to_lowercase(), limits);
        }
        self.admins = normalized;
    }

    /// Load and validate `<data-dir>/value_policy.json`.
    ///
    /// Absent, unreadable, malformed, partially specified (a missing limit
    /// field), or unknown-version documents are errors; the caller must fail
    /// closed.
    pub fn load(data_dir: impl AsRef<Path>) -> Result<Self, ValuePolicyError> {
        let path = data_dir.as_ref().join(VALUE_POLICY_FILE);
        if !path.exists() {
            return Err(ValuePolicyError::Absent);
        }
        let bytes = std::fs::read(&path).map_err(|source| ValuePolicyError::Read {
            path: path.clone(),
            source,
        })?;
        let mut policy: ValuePolicy =
            serde_json::from_slice(&bytes).map_err(|source| ValuePolicyError::Json {
                path: path.clone(),
                source,
            })?;
        if policy.version != VALUE_POLICY_VERSION {
            return Err(ValuePolicyError::UnsupportedVersion(policy.version));
        }
        policy.normalize_admin_keys();
        Ok(policy)
    }

    /// Persist via a temp file + rename.
    pub fn save(&self, data_dir: impl AsRef<Path>) -> Result<(), ValuePolicyError> {
        let path = data_dir.as_ref().join(VALUE_POLICY_FILE);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ValuePolicyError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let json =
            serde_json::to_string_pretty(self).map_err(|source| ValuePolicyError::Json {
                path: path.clone(),
                source,
            })?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, json).map_err(|source| ValuePolicyError::Write {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, &path).map_err(|source| ValuePolicyError::Write {
            path: path.clone(),
            source,
        })?;
        Ok(())
    }
}

/// Errors raised while loading or saving a [`ValuePolicy`].
#[derive(Debug, Error)]
pub enum ValuePolicyError {
    /// The policy file does not exist.
    #[error("value policy is absent")]
    Absent,
    /// The policy file could not be read.
    #[error("failed to read {path}: {source}")]
    Read {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The policy file could not be written.
    #[error("failed to write {path}: {source}")]
    Write {
        /// The file that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The policy file was not valid JSON or was partially specified.
    #[error("{path} is not a valid value policy: {source}")]
    Json {
        /// The offending file.
        path: PathBuf,
        /// The serde error.
        source: serde_json::Error,
    },
    /// The document's `version` is not [`VALUE_POLICY_VERSION`].
    #[error("unsupported value policy version {0}")]
    UnsupportedVersion(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(per_request_max: u64) -> ValueLimits {
        ValueLimits {
            per_request_max,
            window_secs: 60,
            window_max: 100,
            per_account_max: 200,
        }
    }

    #[test]
    fn absent_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            ValuePolicy::load(dir.path()),
            Err(ValuePolicyError::Absent)
        ));
    }

    #[test]
    fn corrupt_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(VALUE_POLICY_FILE), b"{ not json").unwrap();
        assert!(matches!(
            ValuePolicy::load(dir.path()),
            Err(ValuePolicyError::Json { .. })
        ));
    }

    #[test]
    fn unknown_version_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let doc = serde_json::json!({
            "version": VALUE_POLICY_VERSION + 1,
            "defaults": limits(10),
            "admins": {},
        });
        std::fs::write(
            dir.path().join(VALUE_POLICY_FILE),
            serde_json::to_vec(&doc).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            ValuePolicy::load(dir.path()),
            Err(ValuePolicyError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn partial_defaults_are_denied() {
        let dir = tempfile::tempdir().unwrap();
        // `window_max` is missing: deny-by-default, never a partial accept.
        let doc = serde_json::json!({
            "version": VALUE_POLICY_VERSION,
            "defaults": { "per_request_max": 10, "window_secs": 60, "per_account_max": 5 },
            "admins": {},
        });
        std::fs::write(
            dir.path().join(VALUE_POLICY_FILE),
            serde_json::to_vec(&doc).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            ValuePolicy::load(dir.path()),
            Err(ValuePolicyError::Json { .. })
        ));
    }

    #[test]
    fn round_trips_and_applies_per_admin_override() {
        let dir = tempfile::tempdir().unwrap();
        let controller = cawala_ledger::OperatorSecretKey::from_bytes([7u8; 32]).public();
        let other = cawala_ledger::OperatorSecretKey::from_bytes([8u8; 32]).public();
        let policy = ValuePolicy {
            version: VALUE_POLICY_VERSION,
            defaults: limits(10),
            admins: BTreeMap::from([(controller.to_string(), limits(99))]),
        };
        policy.save(dir.path()).unwrap();

        let loaded = ValuePolicy::load(dir.path()).unwrap();
        assert_eq!(loaded, policy);
        assert_eq!(loaded.limits_for(&controller).per_request_max, 99);
        assert_eq!(loaded.limits_for(&other).per_request_max, 10);
    }

    #[test]
    fn admin_override_keys_are_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let controller = cawala_ledger::OperatorSecretKey::from_bytes([7u8; 32]).public();
        // Write the override key in uppercase.
        let doc = serde_json::json!({
            "version": VALUE_POLICY_VERSION,
            "defaults": limits(10),
            "admins": { controller.to_string().to_uppercase(): limits(99) },
        });
        std::fs::write(
            dir.path().join(VALUE_POLICY_FILE),
            serde_json::to_vec(&doc).unwrap(),
        )
        .unwrap();

        let loaded = ValuePolicy::load(dir.path()).unwrap();
        // Both the exact and the opposite case resolve to the override.
        assert_eq!(loaded.limits_for(&controller).per_request_max, 99);
        assert_eq!(
            loaded
                .admins
                .get(&controller.to_string().to_lowercase())
                .map(|limits| limits.per_request_max),
            Some(99),
            "keys are normalized to lowercase at load"
        );
    }

    #[test]
    fn deny_all_denies_every_operation_structurally() {
        let policy = ValuePolicy::deny_all();
        let controller = cawala_ledger::OperatorSecretKey::from_bytes([1u8; 32]).public();
        let limits = policy.limits_for(&controller);
        assert_eq!(limits, ValueLimits::deny_all());
        assert_eq!(limits.per_request_max, 0);
    }
}
