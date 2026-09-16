//! Node-signed admin grants.
//!
//! A [`SignedAdminGrant`] is the node operator's statement that a specific
//! operator key (`admin`, K_admin) may act as an administrator scoped to that
//! node. It is issued out-of-band (operator-to-admin) and presented alongside
//! admin control requests such as
//! [`AdminQuery`](crate::ControlRequest::AdminQuery): the request proves *who*
//! is asking, the grant proves the asker is *allowed* to.
//!
//! The wire format is versioned independently of
//! [`SignedControl`](crate::SignedControl): [`ADMIN_GRANT_VERSION`] and a
//! distinct BLAKE3 derive-key domain ([`ADMIN_GRANT_CONTEXT`]) keep an admin
//! grant from ever being replayed as a control request, or vice versa.
//!
//! # Trust boundary
//!
//! [`SignedAdminGrant::verify`] proves only that `node`'s operator key signed
//! *this* grant. It does not check that the signer is the operator of the node
//! the caller believes; the caller must bind `grant.node` to that node (and
//! `grant.admin` to the request's controller) before treating the grant as
//! authority. [`SignedAdminGrant::is_active`] is the caller's
//! `now <= expiry` check; this crate has no clock.

use serde::{Deserialize, Serialize};

use cawala_ledger::{Hash, NodeId, OperatorPubKey, OperatorSecretKey, Signature};

use crate::invite::MAX_LABEL_LEN;
use crate::sign::ControlError;

/// Wire format version for [`AdminGrant`].
pub const ADMIN_GRANT_VERSION: u8 = 1;

/// BLAKE3 derive-key context for the admin-grant signing hash.
///
/// Distinct from [`CONTROL_CONTEXT`](crate::CONTROL_CONTEXT), so the two
/// signature domains can never be confused.
pub const ADMIN_GRANT_CONTEXT: &str = "cawala-control/admin-grant/v1";

/// Recommended lifetime, in seconds, of an admin grant (7 days).
pub const DEFAULT_ADMIN_TTL_SECS: u64 = 7 * 24 * 3600;

/// Absolute upper bound, in seconds, accepted for an admin grant's lifetime
/// (30 days).
pub const MAX_ADMIN_TTL_SECS: u64 = 30 * 24 * 3600;

/// What an [`AdminGrant`] authorises.
///
/// Only one scope exists today; the enum is versioned (`ADMIN_GRANT_VERSION`)
/// so a future scope can be added without changing the meaning of `Admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminScope {
    /// Full administration of the granting node.
    Admin,
}

/// A node operator's grant of administrative authority.
///
/// Field order is frozen: the signing preimage is the postcard encoding of the
/// grant in declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminGrant {
    /// Wire format version ([`ADMIN_GRANT_VERSION`]).
    pub version: u8,
    /// The granting node id (scope binding).
    pub node: NodeId,
    /// The operator key being granted admin authority (K_admin).
    pub admin: OperatorPubKey,
    /// What is granted.
    pub scope: AdminScope,
    /// Unix seconds when the grant was issued.
    pub granted_at: u64,
    /// Unix seconds; the grant is active while `now <= expiry`.
    pub expiry: u64,
    /// Optional human-readable label, at most [`MAX_LABEL_LEN`] bytes.
    pub label: Option<String>,
}

impl AdminGrant {
    /// Check the version, the label bound, and the expiry window.
    ///
    /// `version` must equal [`ADMIN_GRANT_VERSION`]; `label`, when present,
    /// must be at most [`MAX_LABEL_LEN`] bytes; `expiry` must be strictly
    /// greater than `granted_at` and the lifetime must not exceed
    /// [`MAX_ADMIN_TTL_SECS`]. Clock reading is the caller's concern.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.version != ADMIN_GRANT_VERSION {
            return Err(ControlError::UnsupportedVersion(self.version));
        }
        if let Some(label) = &self.label
            && label.len() > MAX_LABEL_LEN
        {
            return Err(ControlError::FieldTooLong {
                field: "label",
                len: label.len(),
                max: MAX_LABEL_LEN,
            });
        }
        if self.expiry <= self.granted_at {
            return Err(ControlError::GrantExpiryNotAfterGrant {
                granted_at: self.granted_at,
                expiry: self.expiry,
            });
        }
        let ttl = self.expiry - self.granted_at;
        if ttl > MAX_ADMIN_TTL_SECS {
            return Err(ControlError::GrantTtlTooLong {
                ttl,
                max: MAX_ADMIN_TTL_SECS,
            });
        }
        Ok(())
    }
}

/// A node-signed [`AdminGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAdminGrant {
    /// The grant being attested.
    pub grant: AdminGrant,
    /// The granting node's operator signature over
    /// [`SignedAdminGrant::signing_hash`].
    pub signature: Signature,
}

impl SignedAdminGrant {
    /// Build a signed grant, validating it first and signing with the node's
    /// operator secret key.
    ///
    /// The caller supplies the key; this crate never generates key material.
    pub fn authorize(
        grant: AdminGrant,
        node_operator: &OperatorSecretKey,
    ) -> Result<Self, ControlError> {
        grant.validate()?;
        let mut signed = SignedAdminGrant {
            grant,
            // Placeholder; replaced below. The signing hash does not cover the
            // signature field.
            signature: Signature::from_bytes(&[0u8; Signature::LENGTH]),
        };
        signed.signature = node_operator.sign(signed.signing_hash().as_bytes());
        Ok(signed)
    }

    /// The signed preimage hash: BLAKE3 derive-key([`ADMIN_GRANT_CONTEXT`])
    /// over the canonical postcard encoding of the whole [`AdminGrant`].
    ///
    /// Unlike [`SignedControl::signing_hash`](crate::SignedControl::signing_hash),
    /// no field is excluded: the grant is signed in full, and its declaration
    /// order is frozen.
    pub fn signing_hash(&self) -> Hash {
        // The derived serde impls used here never fail to encode; the only
        // fallible component would be a custom serializer, and none are
        // involved.
        let bytes =
            postcard::to_allocvec(&self.grant).expect("admin grant is always postcard-encodable");
        let mut hasher = blake3::Hasher::new_derive_key(ADMIN_GRANT_CONTEXT);
        hasher.update(&bytes);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Verify [`Self::signature`] under `node_operator` over
    /// [`Self::signing_hash`].
    ///
    /// `node_operator` must be the operator public key of the node named in
    /// `grant.node`; a mismatch (or any tampering) fails as
    /// [`ControlError::InvalidSignature`].
    pub fn verify(&self, node_operator: &OperatorPubKey) -> Result<(), ControlError> {
        node_operator
            .verify(self.signing_hash().as_bytes(), &self.signature)
            .map_err(|_| ControlError::InvalidSignature)
    }

    /// Whether the grant is active at unix-seconds `now`.
    pub fn is_active(&self, now: u64) -> bool {
        now <= self.grant.expiry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::OperatorSecretKey;

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn grant() -> AdminGrant {
        AdminGrant {
            version: ADMIN_GRANT_VERSION,
            node: node("node-a"),
            admin: operator(3).public(),
            scope: AdminScope::Admin,
            granted_at: 1_000,
            expiry: 1_000 + DEFAULT_ADMIN_TTL_SECS,
            label: Some("lab".to_string()),
        }
    }

    fn signed_with(seed: u8) -> SignedAdminGrant {
        SignedAdminGrant::authorize(grant(), &operator(seed)).unwrap()
    }

    #[test]
    fn authorize_then_verify_round_trip() {
        let signed = signed_with(1);
        assert_eq!(signed.grant, grant());
        assert_eq!(signed.verify(&operator(1).public()), Ok(()));
    }

    #[test]
    fn signing_hash_is_stable() {
        // Golden vector. Pins the frozen grant field order and the
        // `admin-grant/v1` domain: a reordered, added, or removed field changes
        // this hash, so the pinned value must only change as part of a
        // deliberate protocol version bump.
        let signed = signed_with(7);
        assert_eq!(
            signed.signing_hash().to_hex(),
            "85917747427350ea05c3fd475a7e0c3049346459829e7a1c7eac5ee6f86889ed"
        );
    }

    #[test]
    fn wrong_operator_signature_rejected() {
        let signed = signed_with(1);
        // Signed by operator 1, verified against operator 2.
        assert_eq!(
            signed.verify(&operator(2).public()),
            Err(ControlError::InvalidSignature)
        );
    }

    #[test]
    fn node_mismatch_rejected() {
        let mut signed = signed_with(1);
        // `node` is inside the signed preimage: re-binding the grant to a
        // different node invalidates the signature.
        signed.grant.node = node("node-b");
        assert_eq!(
            signed.verify(&operator(1).public()),
            Err(ControlError::InvalidSignature)
        );
    }

    #[test]
    fn is_active_boundary() {
        let signed = signed_with(1);
        let expiry = grant().expiry;
        assert!(signed.is_active(expiry - 1));
        assert!(signed.is_active(expiry));
        assert!(!signed.is_active(expiry + 1));
    }

    #[test]
    fn validate_enforces_label_bound() {
        let mut grant = grant();
        grant.label = Some("x".repeat(MAX_LABEL_LEN));
        assert_eq!(grant.validate(), Ok(()));

        grant.label = Some("x".repeat(MAX_LABEL_LEN + 1));
        assert_eq!(
            grant.validate(),
            Err(ControlError::FieldTooLong {
                field: "label",
                len: MAX_LABEL_LEN + 1,
                max: MAX_LABEL_LEN,
            })
        );
    }

    #[test]
    fn validate_enforces_expiry_window() {
        // Expiry must be strictly after `granted_at`.
        let mut bad = grant();
        bad.expiry = bad.granted_at;
        assert_eq!(
            bad.validate(),
            Err(ControlError::GrantExpiryNotAfterGrant {
                granted_at: 1_000,
                expiry: 1_000,
            })
        );

        // Lifetime must not exceed the maximum.
        let mut too_long = grant();
        too_long.expiry = too_long.granted_at + MAX_ADMIN_TTL_SECS + 1;
        assert_eq!(
            too_long.validate(),
            Err(ControlError::GrantTtlTooLong {
                ttl: MAX_ADMIN_TTL_SECS + 1,
                max: MAX_ADMIN_TTL_SECS,
            })
        );

        // The default TTL is within bounds.
        assert_eq!(grant().validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_bad_version() {
        let mut grant = grant();
        grant.version = ADMIN_GRANT_VERSION + 1;
        assert_eq!(
            grant.validate(),
            Err(ControlError::UnsupportedVersion(ADMIN_GRANT_VERSION + 1))
        );
    }

    #[test]
    fn authorize_rejects_invalid_grant() {
        let mut grant = grant();
        grant.label = Some("x".repeat(MAX_LABEL_LEN + 1));
        assert_eq!(
            SignedAdminGrant::authorize(grant, &operator(1)),
            Err(ControlError::FieldTooLong {
                field: "label",
                len: MAX_LABEL_LEN + 1,
                max: MAX_LABEL_LEN,
            })
        );
    }

    #[test]
    fn scope_serde_is_snake_case() {
        let json = serde_json::to_string(&AdminScope::Admin).unwrap();
        assert_eq!(json, "\"admin\"");
        let back: AdminScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AdminScope::Admin);
    }

    #[test]
    fn grant_round_trips_postcard() {
        let signed = signed_with(1);
        let bytes = postcard::to_allocvec(&signed).unwrap();
        let back: SignedAdminGrant = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, signed);
    }
}
