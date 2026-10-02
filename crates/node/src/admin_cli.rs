//! Operator-CLI logic for `control admin grant|revoke|list`.
//!
//! The clap layer in `main.rs` is a thin shell over these functions so the
//! behaviour (validation, store mutation, audit) is unit-testable without a
//! process. Everything is pure filesystem + `cawala_control`; no network and no
//! running engine.
//!
//! `grant` mints a v2 [`cawala_control::AdminGrantV2`] with explicit scopes,
//! signs it with this node's operator key, stores it, and emits a
//! `cawala://admin` bundle URI the operator can hand to a browser.
//!
//! # Audit
//!
//! Grant and revoke append the same event shape as the running engine's
//! [`ControlNode::grant_admin`](crate::control::ControlNode::grant_admin) /
//! `revoke_admin`, through the shared [`crate::audit::append`] writer. An audit
//! append failure is ignored (best-effort), never a command failure.

use std::path::Path;

use thiserror::Error;

use cawala_control::{
    ADMIN_BUNDLE_VERSION, ADMIN_GRANT_VERSION, AdminGrantBundleV1, AdminGrantV2, AdminScope,
    AdminScopes, DEFAULT_ADMIN_TTL_SECS, MAX_VALUE_ADMIN_TTL_SECS, NodeId, SignedAdminGrantV2,
};
use cawala_ledger::{OperatorPubKey, OperatorSecretKey};

use crate::admin_store::{AdminStore, AdminStoreError, StoredGrant};

/// Outcome of a successful [`grant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantOutcome {
    /// The admin key that was granted.
    pub admin: OperatorPubKey,
    /// The granted scope set.
    pub scopes: AdminScopes,
    /// The grant's wire version ([`ADMIN_GRANT_VERSION`]).
    pub version: u8,
    /// The grant's expiry (unix seconds).
    pub expiry: u64,
    /// The `cawala://admin` bundle URI carrying the signed grant.
    pub bundle: String,
}

/// One row of `control admin list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminListEntry {
    /// The admin operator key.
    pub admin: OperatorPubKey,
    /// The effective scope set (v1 rows report `{ joins }`).
    pub scopes: AdminScopes,
    /// The grant's wire version.
    pub version: u8,
    /// Unix seconds when the grant was issued.
    pub granted_at: u64,
    /// Unix seconds after which the grant is inactive.
    pub expiry: u64,
    /// Optional human-readable label.
    pub label: Option<String>,
}

impl AdminListEntry {
    /// Render the frozen `list` line for this entry at unix-seconds `now`.
    pub fn render(&self, now: u64) -> String {
        format!(
            "{} scopes={} version={} granted={} expires={} label={} status={}",
            self.admin,
            self.scopes.label(),
            self.version,
            self.granted_at,
            self.expiry,
            self.label.as_deref().unwrap_or("-"),
            if now <= self.expiry {
                "active"
            } else {
                "expired"
            },
        )
    }
}

/// Parse a `--scope` value. `admin` is the legacy v1 scope and is rejected.
pub fn parse_scope(raw: &str) -> Result<AdminScope, AdminCliError> {
    match raw {
        "joins" => Ok(AdminScope::Joins),
        "topology" => Ok(AdminScope::Topology),
        "value" => Ok(AdminScope::Value),
        "admin" => Err(AdminCliError::ScopeNotAllowed(raw.to_string())),
        other => Err(AdminCliError::UnknownScope(other.to_string())),
    }
}

/// Build the [`AdminScopes`] set from a scope list, deduping in order and
/// rejecting an empty list or the legacy `Admin` scope.
fn scopes_from(scopes: &[AdminScope]) -> Result<AdminScopes, AdminCliError> {
    let mut deduped: Vec<AdminScope> = Vec::new();
    for scope in scopes {
        if !deduped.contains(scope) {
            deduped.push(*scope);
        }
    }
    if deduped.is_empty() {
        return Err(AdminCliError::NoScopes);
    }
    let mut set = AdminScopes::default();
    for scope in deduped {
        let singleton = AdminScopes::from_scope(scope)
            .ok_or_else(|| AdminCliError::ScopeNotAllowed("admin".to_string()))?;
        set.joins |= singleton.joins;
        set.topology |= singleton.topology;
        set.value |= singleton.value;
    }
    Ok(set)
}

/// Grant `admin` administrative authority over this node.
///
/// `scopes` is deduped and must be non-empty; `expiry` defaults to
/// `now + DEFAULT_ADMIN_TTL_SECS`, or `now + min(DEFAULT, MAX_VALUE)` when the
/// grant carries the value scope. The v2 grant is validated (version, label
/// bound, TTL window, value cap, non-empty scopes) before signing, then
/// persisted and audited; the returned [`GrantOutcome::bundle`] is the
/// `cawala://admin` URI carrying the signed grant.
#[allow(clippy::too_many_arguments)]
pub fn grant(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    admin: OperatorPubKey,
    scopes: Vec<AdminScope>,
    expiry: Option<u64>,
    label: Option<String>,
    now: u64,
) -> Result<GrantOutcome, AdminCliError> {
    if admin == operator.public() {
        return Err(AdminCliError::SelfAdmin);
    }
    let scopes = scopes_from(&scopes)?;
    let granted_at = now;
    let default_ttl = if scopes.value {
        DEFAULT_ADMIN_TTL_SECS.min(MAX_VALUE_ADMIN_TTL_SECS)
    } else {
        DEFAULT_ADMIN_TTL_SECS
    };
    let expiry = expiry.unwrap_or_else(|| granted_at.saturating_add(default_ttl));
    let grant = AdminGrantV2 {
        version: ADMIN_GRANT_VERSION,
        node: NodeId::from(node_id),
        admin,
        scopes,
        granted_at,
        expiry,
        label,
    };
    grant.validate().map_err(AdminCliError::InvalidGrant)?;
    let signed =
        SignedAdminGrantV2::authorize(grant, operator).map_err(AdminCliError::InvalidGrant)?;
    let bundle = AdminGrantBundleV1 {
        version: ADMIN_BUNDLE_VERSION,
        grant: signed.clone(),
    }
    .encode();

    let mut store = AdminStore::load(data_dir, node_id, &operator.public())?;
    store.grant(StoredGrant::V2(signed));
    store.save(data_dir)?;
    crate::audit::append(
        data_dir,
        serde_json::json!({
            "event": "grant",
            "admin": admin.to_string(),
            "node": node_id,
            "expiry": expiry,
            "version": ADMIN_GRANT_VERSION,
            "scopes": scopes.label(),
        }),
    );
    Ok(GrantOutcome {
        admin,
        scopes,
        version: ADMIN_GRANT_VERSION,
        expiry,
        bundle,
    })
}

/// Revoke `admin`'s authority. Errors with [`AdminCliError::UnknownAdmin`] when
/// no grant is stored for that key.
pub fn revoke(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    admin: &OperatorPubKey,
) -> Result<(), AdminCliError> {
    let mut store = AdminStore::load(data_dir, node_id, &operator.public())?;
    if !store.revoke(admin) {
        return Err(AdminCliError::UnknownAdmin(admin.to_string()));
    }
    store.save(data_dir)?;
    crate::audit::append(
        data_dir,
        serde_json::json!({
            "event": "revoke",
            "admin": admin.to_string(),
            "node": node_id,
            "removed": true,
        }),
    );
    Ok(())
}

/// List stored admin grants (including expired ones), oldest first.
///
/// A legacy v1 row reports `scopes={joins} version=1`; a v2 row reports its
/// explicit scopes and `version=2`.
pub fn list(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
) -> Result<Vec<AdminListEntry>, AdminCliError> {
    let store = AdminStore::load(data_dir, node_id, &operator.public())?;
    Ok(store
        .entries()
        .iter()
        .map(|entry| AdminListEntry {
            admin: entry.admin(),
            scopes: entry.scopes(),
            version: entry.version(),
            granted_at: entry.granted_at(),
            expiry: entry.expiry(),
            label: entry.label().map(str::to_string),
        })
        .collect())
}

/// Errors a CLI admin action can surface (mapped to a non-zero exit).
#[derive(Debug, Error)]
pub enum AdminCliError {
    /// The requested admin key is this node's own operator key.
    #[error("admin key equals this node's own operator key; refusing to grant self-administration")]
    SelfAdmin,
    /// The grant failed structural validation (TTL window, label, version).
    #[error("invalid admin grant: {0}")]
    InvalidGrant(cawala_control::ControlError),
    /// No scopes were supplied (at least one is required).
    #[error("at least one --scope is required")]
    NoScopes,
    /// The legacy `admin` scope cannot be granted explicitly.
    #[error("scope '{0}' is not grantable; choose joins, topology, or value")]
    ScopeNotAllowed(String),
    /// A `--scope` value was not recognised.
    #[error("unknown scope '{0}' (expected joins, topology, or value)")]
    UnknownScope(String),
    /// The persisted store could not be loaded or saved.
    #[error("admin store: {0}")]
    Store(#[from] AdminStoreError),
    /// No grant is stored for the requested key.
    #[error("admin '{0}' is not registered")]
    UnknownAdmin(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_control::{
        ADMIN_GRANT_V1_VERSION, AdminGrant, DEFAULT_ADMIN_TTL_SECS, MAX_ADMIN_TTL_SECS,
        MAX_VALUE_ADMIN_TTL_SECS, SignedAdminGrant,
    };
    use cawala_ledger::OperatorSecretKey;

    const NODE: &str = "node-a";

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn signed_v1(
        signer: &OperatorSecretKey,
        admin_seed: u8,
        granted_at: u64,
        expiry: u64,
    ) -> SignedAdminGrant {
        let grant = AdminGrant {
            version: ADMIN_GRANT_V1_VERSION,
            node: NodeId::from(NODE),
            admin: operator(admin_seed).public(),
            scope: AdminScope::Admin,
            granted_at,
            expiry,
            label: None,
        };
        SignedAdminGrant::authorize(grant, signer).unwrap()
    }

    fn signed_v2(
        signer: &OperatorSecretKey,
        admin_seed: u8,
        granted_at: u64,
        expiry: u64,
        scopes: AdminScopes,
    ) -> SignedAdminGrantV2 {
        SignedAdminGrantV2::authorize(
            AdminGrantV2 {
                version: ADMIN_GRANT_VERSION,
                node: NodeId::from(NODE),
                admin: operator(admin_seed).public(),
                scopes,
                granted_at,
                expiry,
                label: None,
            },
            signer,
        )
        .unwrap()
    }

    #[test]
    fn grant_round_trips_through_store_and_emits_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        let outcome = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
            vec![AdminScope::Joins],
            None,
            Some("phone".to_string()),
            1_000,
        )
        .unwrap();
        assert_eq!(outcome.admin, operator(3).public());
        assert_eq!(outcome.version, ADMIN_GRANT_VERSION);
        assert_eq!(outcome.scopes, AdminScopes::v1());
        assert_eq!(outcome.expiry, 1_000 + DEFAULT_ADMIN_TTL_SECS);
        assert!(
            outcome.bundle.starts_with("cawala://admin?node=node-a&grant="),
            "{}",
            outcome.bundle
        );
        assert_eq!(
            AdminGrantBundleV1::parse(&outcome.bundle).unwrap().grant.grant.admin,
            operator(3).public()
        );

        // Persisted and reloadable.
        let entries = list(dir.path(), NODE, &node_op).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].admin, operator(3).public());
        assert_eq!(entries[0].version, ADMIN_GRANT_VERSION);
        assert_eq!(entries[0].scopes, AdminScopes::v1());
        assert_eq!(entries[0].label.as_deref(), Some("phone"));
        assert_eq!(entries[0].expiry, outcome.expiry);
        assert!(entries[0].render(1_500).contains("scopes=joins version=2"));
        assert!(entries[0].render(1_500).ends_with("label=phone status=active"));

        // The audit line was appended with the shared event shape.
        let audit = std::fs::read_to_string(dir.path().join("control_audit.jsonl")).unwrap();
        assert!(audit.contains("\"event\":\"grant\""), "{audit}");
        assert!(audit.contains("\"scopes\":\"joins\""), "{audit}");
        assert!(
            audit.contains(&format!("\"admin\":\"{}\"", operator(3).public())),
            "{audit}"
        );
    }

    #[test]
    fn grant_dedupes_scopes_and_unions() {
        let dir = tempfile::tempdir().unwrap();
        let outcome = grant(
            dir.path(),
            NODE,
            &operator(1),
            operator(3).public(),
            vec![
                AdminScope::Topology,
                AdminScope::Joins,
                AdminScope::Topology,
            ],
            None,
            None,
            1_000,
        )
        .unwrap();
        assert_eq!(
            outcome.scopes,
            AdminScopes {
                joins: true,
                topology: true,
                value: false,
            }
        );
    }

    #[test]
    fn grant_rejects_self_admin() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        let err = grant(
            dir.path(),
            NODE,
            &node_op,
            node_op.public(),
            vec![AdminScope::Joins],
            None,
            None,
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, AdminCliError::SelfAdmin), "{err}");
        // Nothing was written.
        assert!(!dir.path().join("admins.json").exists());
    }

    #[test]
    fn grant_rejects_empty_and_legacy_admin_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        let err = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
            vec![],
            None,
            None,
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, AdminCliError::NoScopes), "{err}");

        let err = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
            vec![AdminScope::Admin],
            None,
            None,
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, AdminCliError::ScopeNotAllowed(_)), "{err}");
        assert!(!dir.path().join("admins.json").exists());
    }

    #[test]
    fn grant_rejects_out_of_range_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);

        // Expiry at/before `granted_at`.
        let err = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
            vec![AdminScope::Joins],
            Some(1_000),
            None,
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, AdminCliError::InvalidGrant(_)), "{err}");

        // Lifetime beyond the maximum.
        let err = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
            vec![AdminScope::Joins],
            Some(1_000 + MAX_ADMIN_TTL_SECS + 1),
            None,
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, AdminCliError::InvalidGrant(_)), "{err}");
        assert!(!dir.path().join("admins.json").exists());
    }

    #[test]
    fn grant_value_scope_defaults_to_value_ttl_and_enforces_cap() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        let outcome = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
            vec![AdminScope::Value],
            None,
            None,
            1_000,
        )
        .unwrap();
        assert_eq!(outcome.expiry, 1_000 + MAX_VALUE_ADMIN_TTL_SECS);

        // An explicit value-scope TTL beyond the value cap is rejected even
        // though it is under the general cap.
        let err = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(4).public(),
            vec![AdminScope::Value],
            Some(1_000 + MAX_VALUE_ADMIN_TTL_SECS + 1),
            None,
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, AdminCliError::InvalidGrant(_)), "{err}");
    }

    #[test]
    fn grant_rejects_oversized_label() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        let err = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
            vec![AdminScope::Joins],
            None,
            Some("x".repeat(65)),
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, AdminCliError::InvalidGrant(_)), "{err}");
    }

    #[test]
    fn parse_scope_rejects_admin_and_unknown() {
        assert_eq!(parse_scope("joins").unwrap(), AdminScope::Joins);
        assert_eq!(parse_scope("topology").unwrap(), AdminScope::Topology);
        assert_eq!(parse_scope("value").unwrap(), AdminScope::Value);
        assert!(matches!(
            parse_scope("admin"),
            Err(AdminCliError::ScopeNotAllowed(_))
        ));
        assert!(matches!(
            parse_scope("nope"),
            Err(AdminCliError::UnknownScope(_))
        ));
    }

    #[test]
    fn revoke_unknown_key_errors() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        let err = revoke(dir.path(), NODE, &node_op, &operator(9).public()).unwrap_err();
        assert!(matches!(err, AdminCliError::UnknownAdmin(_)), "{err}");
    }

    #[test]
    fn revoke_existing_removes_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
            vec![AdminScope::Joins],
            None,
            None,
            1_000,
        )
        .unwrap();

        revoke(dir.path(), NODE, &node_op, &operator(3).public()).unwrap();
        assert!(list(dir.path(), NODE, &node_op).unwrap().is_empty());

        let audit = std::fs::read_to_string(dir.path().join("control_audit.jsonl")).unwrap();
        assert!(audit.contains("\"event\":\"revoke\""), "{audit}");
    }

    #[test]
    fn list_is_empty_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(list(dir.path(), NODE, &operator(1)).unwrap().is_empty());
    }

    #[test]
    fn list_renders_active_expired_and_legacy_v1() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        // `now = 300`: grant 3 is active (expiry 1000), grant 4 expired, and
        // grant 5 is a legacy v1 row rendered joins-only.
        let mut store = AdminStore::empty();
        store.grant(StoredGrant::V2(signed_v2(
            &node_op,
            3,
            100,
            1_000,
            AdminScopes {
                joins: true,
                topology: true,
                value: false,
            },
        )));
        store.grant(StoredGrant::V2(signed_v2(
            &node_op,
            4,
            100,
            200,
            AdminScopes::v1(),
        )));
        store.grant(StoredGrant::V1(signed_v1(&node_op, 5, 100, 1_000)));
        store.save(dir.path()).unwrap();

        let entries = list(dir.path(), NODE, &node_op).unwrap();
        assert_eq!(entries.len(), 3);
        let active = entries
            .iter()
            .find(|entry| entry.admin == operator(3).public())
            .unwrap();
        let expired = entries
            .iter()
            .find(|entry| entry.admin == operator(4).public())
            .unwrap();
        let legacy = entries
            .iter()
            .find(|entry| entry.admin == operator(5).public())
            .unwrap();
        assert!(
            active
                .render(300)
                .contains("scopes=joins,topology version=2")
        );
        assert!(expired.render(300).ends_with("label=- status=expired"));
        assert!(legacy.render(300).contains("scopes=joins version=1"));
        // Exactly at expiry is still active.
        assert!(expired.render(200).ends_with("status=active"));
    }
}
