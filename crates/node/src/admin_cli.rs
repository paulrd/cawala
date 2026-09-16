//! Operator-CLI logic for `control admin grant|revoke|list`.
//!
//! The clap layer in `main.rs` is a thin shell over these functions so the
//! behaviour (validation, store mutation, audit) is unit-testable without a
//! process. Everything is pure filesystem + `cawala_control`; no network and no
//! running engine.
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
    ADMIN_GRANT_VERSION, AdminGrant, AdminScope, DEFAULT_ADMIN_TTL_SECS, NodeId, SignedAdminGrant,
};
use cawala_ledger::{OperatorPubKey, OperatorSecretKey};

use crate::admin_store::{AdminStore, AdminStoreError};

/// Outcome of a successful [`grant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantOutcome {
    /// The admin key that was granted.
    pub admin: OperatorPubKey,
    /// The grant's expiry (unix seconds).
    pub expiry: u64,
}

/// One row of `control admin list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminListEntry {
    /// The admin operator key.
    pub admin: OperatorPubKey,
    /// What was granted.
    pub scope: AdminScope,
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
            "{} scope={} granted={} expires={} label={} status={}",
            self.admin,
            scope_label(self.scope),
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

/// Stable label for an [`AdminScope`] (mirrors its `snake_case` serde name).
fn scope_label(scope: AdminScope) -> &'static str {
    match scope {
        AdminScope::Admin => "admin",
    }
}

/// Grant `admin` administrative authority over this node.
///
/// `expiry` defaults to `now + DEFAULT_ADMIN_TTL_SECS`. The grant is validated
/// (TTL window and label bound) before signing, then persisted and audited.
pub fn grant(
    data_dir: &Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    admin: OperatorPubKey,
    expiry: Option<u64>,
    label: Option<String>,
    now: u64,
) -> Result<GrantOutcome, AdminCliError> {
    if admin == operator.public() {
        return Err(AdminCliError::SelfAdmin);
    }
    let granted_at = now;
    let expiry = expiry.unwrap_or_else(|| granted_at.saturating_add(DEFAULT_ADMIN_TTL_SECS));
    let grant = AdminGrant {
        version: ADMIN_GRANT_VERSION,
        node: NodeId::from(node_id),
        admin,
        scope: AdminScope::Admin,
        granted_at,
        expiry,
        label,
    };
    grant.validate().map_err(AdminCliError::InvalidGrant)?;
    let signed =
        SignedAdminGrant::authorize(grant, operator).map_err(AdminCliError::InvalidGrant)?;

    let mut store = AdminStore::load(data_dir, node_id, &operator.public())?;
    store.grant(signed);
    store.save(data_dir)?;
    crate::audit::append(
        data_dir,
        serde_json::json!({
            "event": "grant",
            "admin": admin.to_string(),
            "node": node_id,
            "expiry": expiry,
        }),
    );
    Ok(GrantOutcome { admin, expiry })
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
            admin: entry.grant.admin,
            scope: entry.grant.scope,
            granted_at: entry.grant.granted_at,
            expiry: entry.grant.expiry,
            label: entry.grant.label.clone(),
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
    use cawala_control::MAX_ADMIN_TTL_SECS;
    use cawala_ledger::OperatorSecretKey;

    const NODE: &str = "node-a";

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn signed_grant(
        signer: &OperatorSecretKey,
        admin_seed: u8,
        granted_at: u64,
        expiry: u64,
    ) -> SignedAdminGrant {
        let grant = AdminGrant {
            version: ADMIN_GRANT_VERSION,
            node: NodeId::from(NODE),
            admin: operator(admin_seed).public(),
            scope: AdminScope::Admin,
            granted_at,
            expiry,
            label: None,
        };
        SignedAdminGrant::authorize(grant, signer).unwrap()
    }

    #[test]
    fn grant_round_trips_through_store() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        let outcome = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
            None,
            Some("phone".to_string()),
            1_000,
        )
        .unwrap();
        assert_eq!(outcome.admin, operator(3).public());
        assert_eq!(outcome.expiry, 1_000 + DEFAULT_ADMIN_TTL_SECS);

        // Persisted and reloadable.
        let entries = list(dir.path(), NODE, &node_op).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].admin, operator(3).public());
        assert_eq!(entries[0].label.as_deref(), Some("phone"));
        assert_eq!(entries[0].expiry, outcome.expiry);
        assert_eq!(
            entries[0].render(1_500),
            format!(
                "{} scope=admin granted=1000 expires={} label=phone status=active",
                operator(3).public(),
                outcome.expiry
            )
        );

        // The audit line was appended with the shared event shape.
        let audit = std::fs::read_to_string(dir.path().join("control_audit.jsonl")).unwrap();
        assert!(audit.contains("\"event\":\"grant\""), "{audit}");
        assert!(
            audit.contains(&format!("\"admin\":\"{}\"", operator(3).public())),
            "{audit}"
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
    fn grant_rejects_out_of_range_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);

        // Expiry at/before `granted_at`.
        let err = grant(
            dir.path(),
            NODE,
            &node_op,
            operator(3).public(),
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
            Some(1_000 + MAX_ADMIN_TTL_SECS + 1),
            None,
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, AdminCliError::InvalidGrant(_)), "{err}");
        assert!(!dir.path().join("admins.json").exists());
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
            None,
            Some("x".repeat(65)),
            1_000,
        )
        .unwrap_err();
        assert!(matches!(err, AdminCliError::InvalidGrant(_)), "{err}");
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
    fn list_renders_active_and_expired() {
        let dir = tempfile::tempdir().unwrap();
        let node_op = operator(1);
        // `now = 300`: grant 3 is active (expiry 1000), grant 4 is expired.
        let mut store = AdminStore::empty();
        store.grant(signed_grant(&node_op, 3, 100, 1_000));
        store.grant(signed_grant(&node_op, 4, 100, 200));
        store.save(dir.path()).unwrap();

        let entries = list(dir.path(), NODE, &node_op).unwrap();
        assert_eq!(entries.len(), 2);
        let active = entries
            .iter()
            .find(|entry| entry.admin == operator(3).public())
            .unwrap();
        let expired = entries
            .iter()
            .find(|entry| entry.admin == operator(4).public())
            .unwrap();
        assert!(active.render(300).ends_with("label=- status=active"));
        assert!(expired.render(300).ends_with("label=- status=expired"));
        // Exactly at expiry is still active.
        assert!(expired.render(200).ends_with("status=active"));
    }
}
