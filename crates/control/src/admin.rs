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

/// Wire format version this build **mints** for [`AdminGrantV2`].
pub const ADMIN_GRANT_VERSION: u8 = 2;

/// Wire format version of the legacy [`AdminGrant`] document.
///
/// v1 grants are read-only in a v2 build: they dual-accept on load and are
/// interpreted as joins-only, but a new grant is always minted as v2.
pub const ADMIN_GRANT_V1_VERSION: u8 = 1;

/// BLAKE3 derive-key context for the legacy [`AdminGrant`] signing hash.
///
/// Distinct from [`CONTROL_CONTEXT`](crate::CONTROL_CONTEXT) and from
/// [`ADMIN_GRANT_V2_CONTEXT`], so the signature domains can never be confused.
pub const ADMIN_GRANT_CONTEXT: &str = "cawala-control/admin-grant/v1";

/// BLAKE3 derive-key context for the [`AdminGrantV2`] signing hash.
///
/// The v2 grant is signed in the `admin-grant/v2` domain so a v1 verifier
/// (which uses [`ADMIN_GRANT_CONTEXT`]) can never accept a v2 document, and
/// vice versa.
pub const ADMIN_GRANT_V2_CONTEXT: &str = "cawala-control/admin-grant/v2";

/// Recommended lifetime, in seconds, of an admin grant (7 days).
pub const DEFAULT_ADMIN_TTL_SECS: u64 = 7 * 24 * 3600;

/// Absolute upper bound, in seconds, accepted for an admin grant's lifetime
/// (30 days).
pub const MAX_ADMIN_TTL_SECS: u64 = 30 * 24 * 3600;

/// Absolute upper bound, in seconds, accepted for the lifetime of a grant that
/// carries the [`AdminScope::Value`] scope (24 hours).
///
/// Value operations have monetary blast radius, so a value-capable grant is
/// deliberately short-lived.
pub const MAX_VALUE_ADMIN_TTL_SECS: u64 = 24 * 3600;

/// What an admin grant authorises.
///
/// Discriminants are **append-only** and frozen:
/// `Admin = 0`, `Joins = 1`, `Topology = 2`, `Value = 3`. `Admin` is the
/// legacy v1 scope and is never representable by [`AdminScopes`]; it is
/// interpreted as joins-only (see [`AdminScopes::v1`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminScope {
    /// Legacy v1 scope: full administration, interpreted as joins-only.
    Admin,
    /// Read pending joins and approve/reject/redeliver them.
    Joins,
    /// Topology administration (future P4).
    Topology,
    /// Value administration (future P5).
    Value,
}

/// The explicit scope set carried by an [`AdminGrantV2`].
///
/// This is a fixed struct, **not** a `Vec`: postcard encodes exactly three
/// bytes in the frozen order `joins`, `topology`, `value`. It structurally
/// cannot represent the legacy [`AdminScope::Admin`], and at least one field
/// must be `true` (enforced by [`AdminGrantV2::validate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AdminScopes {
    /// Read/approve/reject/redeliver pending joins.
    #[serde(default)]
    pub joins: bool,
    /// Topology administration (future P4).
    #[serde(default)]
    pub topology: bool,
    /// Value administration (future P5).
    #[serde(default)]
    pub value: bool,
}

impl AdminScopes {
    /// The scope set a legacy v1 grant maps to: exactly `{ joins }`.
    ///
    /// This is the **only** place [`AdminScope::Admin`] is interpreted, and it
    /// is deliberately never widened.
    pub fn v1() -> Self {
        AdminScopes {
            joins: true,
            topology: false,
            value: false,
        }
    }

    /// The singleton set for a non-legacy scope, or `None` for
    /// [`AdminScope::Admin`] (which [`AdminScopes`] cannot represent).
    pub fn from_scope(scope: AdminScope) -> Option<Self> {
        match scope {
            AdminScope::Admin => None,
            AdminScope::Joins => Some(AdminScopes {
                joins: true,
                ..Self::default()
            }),
            AdminScope::Topology => Some(AdminScopes {
                topology: true,
                ..Self::default()
            }),
            AdminScope::Value => Some(AdminScopes {
                value: true,
                ..Self::default()
            }),
        }
    }

    /// Whether `scope` is a member of this set.
    pub fn contains(&self, scope: AdminScope) -> bool {
        match scope {
            AdminScope::Admin => false,
            AdminScope::Joins => self.joins,
            AdminScope::Topology => self.topology,
            AdminScope::Value => self.value,
        }
    }

    /// Whether this set satisfies a [`RequiredScope`].
    ///
    /// [`RequiredScope::AnyActive`] is satisfied by any non-empty set (any
    /// scope implies read).
    pub fn allows(&self, required: RequiredScope) -> bool {
        match required {
            RequiredScope::AnyActive => !self.is_empty(),
            RequiredScope::Joins => self.joins,
            RequiredScope::Topology => self.topology,
            RequiredScope::Value => self.value,
        }
    }

    /// Whether no scope is set (invalid for a stored grant).
    pub fn is_empty(&self) -> bool {
        !self.joins && !self.topology && !self.value
    }

    /// Stable, comma-separated label in the frozen order `joins,topology,value`.
    pub fn label(&self) -> String {
        let mut parts = Vec::new();
        if self.joins {
            parts.push("joins");
        }
        if self.topology {
            parts.push("topology");
        }
        if self.value {
            parts.push("value");
        }
        parts.join(",")
    }
}

/// The scope a control request needs to be authorised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredScope {
    /// Any active scope (read-only surface): [`ControlRequest::AdminQuery`].
    AnyActive,
    /// Join administration: approve/reject/redeliver.
    Joins,
    /// Topology administration (future P4).
    Topology,
    /// Value administration (future P5).
    Value,
}

/// A node operator's legacy (v1) grant of administrative authority.
///
/// Field order is frozen: the signing preimage is the postcard encoding of the
/// grant in declaration order. This struct is **read-only** in a v2 build; new
/// grants are minted as [`AdminGrantV2`]. A v1 grant is interpreted as
/// joins-only (see [`AdminScopes::v1`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminGrant {
    /// Wire format version ([`ADMIN_GRANT_V1_VERSION`]).
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
    /// `version` must equal [`ADMIN_GRANT_V1_VERSION`]; `label`, when present,
    /// must be at most [`MAX_LABEL_LEN`] bytes; `expiry` must be strictly
    /// greater than `granted_at` and the lifetime must not exceed
    /// [`MAX_ADMIN_TTL_SECS`]. Clock reading is the caller's concern.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.version != ADMIN_GRANT_V1_VERSION {
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

/// A node operator's v2 grant of administrative authority, carrying explicit
/// [`AdminScopes`].
///
/// Field order is frozen: the signing preimage is the postcard encoding of the
/// grant in declaration order. Signed in the [`ADMIN_GRANT_V2_CONTEXT`] domain,
/// so it can never be confused with a legacy [`AdminGrant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminGrantV2 {
    /// Wire format version ([`ADMIN_GRANT_VERSION`], 2).
    pub version: u8,
    /// The granting node id (scope binding).
    pub node: NodeId,
    /// The operator key being granted admin authority (K_admin).
    pub admin: OperatorPubKey,
    /// What is granted (at least one scope; never the legacy `Admin`).
    pub scopes: AdminScopes,
    /// Unix seconds when the grant was issued.
    pub granted_at: u64,
    /// Unix seconds; the grant is active while `now <= expiry`.
    pub expiry: u64,
    /// Optional human-readable label, at most [`MAX_LABEL_LEN`] bytes.
    pub label: Option<String>,
}

impl AdminGrantV2 {
    /// Check the version, the label bound, the expiry window, the scope set,
    /// and the value TTL cap.
    ///
    /// `version` must equal [`ADMIN_GRANT_VERSION`]; `label`, when present,
    /// must be at most [`MAX_LABEL_LEN`] bytes; `expiry` must be strictly
    /// greater than `granted_at` and the lifetime must not exceed
    /// [`MAX_ADMIN_TTL_SECS`]. The scope set must be non-empty, and when it
    /// contains [`AdminScope::Value`] the lifetime must not exceed
    /// [`MAX_VALUE_ADMIN_TTL_SECS`]. Clock reading is the caller's concern.
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
        if self.scopes.is_empty() {
            return Err(ControlError::EmptyAdminScopes);
        }
        let ttl = self.expiry - self.granted_at;
        if ttl > MAX_ADMIN_TTL_SECS {
            return Err(ControlError::GrantTtlTooLong {
                ttl,
                max: MAX_ADMIN_TTL_SECS,
            });
        }
        if self.scopes.value && ttl > MAX_VALUE_ADMIN_TTL_SECS {
            return Err(ControlError::GrantTtlTooLong {
                ttl,
                max: MAX_VALUE_ADMIN_TTL_SECS,
            });
        }
        Ok(())
    }
}

/// A node-signed v2 [`AdminGrantV2`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAdminGrantV2 {
    /// The grant being attested.
    pub grant: AdminGrantV2,
    /// The granting node's operator signature over
    /// [`SignedAdminGrantV2::signing_hash`].
    pub signature: Signature,
}

impl SignedAdminGrantV2 {
    /// Build a signed v2 grant, validating it first and signing with the
    /// node's operator secret key.
    ///
    /// The caller supplies the key; this crate never generates key material.
    pub fn authorize(
        grant: AdminGrantV2,
        node_operator: &OperatorSecretKey,
    ) -> Result<Self, ControlError> {
        grant.validate()?;
        let mut signed = SignedAdminGrantV2 {
            grant,
            // Placeholder; replaced below. The signing hash does not cover the
            // signature field.
            signature: Signature::from_bytes(&[0u8; Signature::LENGTH]),
        };
        signed.signature = node_operator.sign(signed.signing_hash().as_bytes());
        Ok(signed)
    }

    /// The signed preimage hash: BLAKE3
    /// derive-key([`ADMIN_GRANT_V2_CONTEXT`]) over the canonical postcard
    /// encoding of the whole [`AdminGrantV2`].
    pub fn signing_hash(&self) -> Hash {
        let bytes = postcard::to_allocvec(&self.grant)
            .expect("admin grant v2 is always postcard-encodable");
        let mut hasher = blake3::Hasher::new_derive_key(ADMIN_GRANT_V2_CONTEXT);
        hasher.update(&bytes);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Verify [`Self::signature`] under `node_operator` over
    /// [`Self::signing_hash`].
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
            version: ADMIN_GRANT_V1_VERSION,
            node: node("node-a"),
            admin: operator(3).public(),
            scope: AdminScope::Admin,
            granted_at: 1_000,
            expiry: 1_000 + DEFAULT_ADMIN_TTL_SECS,
            label: Some("lab".to_string()),
        }
    }

    fn grant_v2() -> AdminGrantV2 {
        AdminGrantV2 {
            version: ADMIN_GRANT_VERSION,
            node: node("node-a"),
            admin: operator(3).public(),
            scopes: AdminScopes {
                joins: true,
                topology: true,
                value: false,
            },
            granted_at: 1_000,
            expiry: 1_000 + DEFAULT_ADMIN_TTL_SECS,
            label: Some("lab".to_string()),
        }
    }

    fn signed_v2_with(seed: u8) -> SignedAdminGrantV2 {
        SignedAdminGrantV2::authorize(grant_v2(), &operator(seed)).unwrap()
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
        grant.version = ADMIN_GRANT_VERSION;
        assert_eq!(
            grant.validate(),
            Err(ControlError::UnsupportedVersion(ADMIN_GRANT_VERSION))
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

    #[test]
    fn admin_scope_discriminants_are_frozen() {
        // Postcard encodes the variant index positionally. Appending is safe;
        // reordering is a protocol break (v1 bytes may still be decoded).
        assert_eq!(postcard::to_allocvec(&AdminScope::Admin).unwrap(), vec![0]);
        assert_eq!(postcard::to_allocvec(&AdminScope::Joins).unwrap(), vec![1]);
        assert_eq!(
            postcard::to_allocvec(&AdminScope::Topology).unwrap(),
            vec![2]
        );
        assert_eq!(postcard::to_allocvec(&AdminScope::Value).unwrap(), vec![3]);
    }

    #[test]
    fn scope_serde_covers_all_variants() {
        for (scope, json) in [
            (AdminScope::Admin, "\"admin\""),
            (AdminScope::Joins, "\"joins\""),
            (AdminScope::Topology, "\"topology\""),
            (AdminScope::Value, "\"value\""),
        ] {
            assert_eq!(serde_json::to_string(&scope).unwrap(), json);
            let back: AdminScope = serde_json::from_str(json).unwrap();
            assert_eq!(back, scope);
        }
    }

    #[test]
    fn admin_scopes_postcard_is_three_bytes_frozen_order() {
        let scopes = AdminScopes {
            joins: true,
            topology: false,
            value: true,
        };
        // Frozen order: joins, topology, value.
        assert_eq!(postcard::to_allocvec(&scopes).unwrap(), vec![1, 0, 1]);
        let back: AdminScopes = postcard::from_bytes(&[0, 1, 1]).unwrap();
        assert_eq!(
            back,
            AdminScopes {
                joins: false,
                topology: true,
                value: true,
            }
        );
    }

    #[test]
    fn admin_scopes_json_defaults_missing_fields_false() {
        let scopes: AdminScopes = serde_json::from_str("{\"joins\":true}").unwrap();
        assert_eq!(scopes, AdminScopes::v1());
        let empty: AdminScopes = serde_json::from_str("{}").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn admin_scopes_helpers() {
        assert_eq!(AdminScopes::v1().label(), "joins");
        assert!(AdminScopes::v1().contains(AdminScope::Joins));
        assert!(!AdminScopes::v1().contains(AdminScope::Topology));
        assert!(!AdminScopes::v1().contains(AdminScope::Admin));
        assert_eq!(AdminScopes::from_scope(AdminScope::Admin), None);
        assert_eq!(
            AdminScopes::from_scope(AdminScope::Value),
            Some(AdminScopes {
                joins: false,
                topology: false,
                value: true,
            })
        );

        let all = AdminScopes {
            joins: true,
            topology: true,
            value: true,
        };
        assert_eq!(all.label(), "joins,topology,value");
        assert!(all.allows(RequiredScope::Joins));
        assert!(all.allows(RequiredScope::Topology));
        assert!(all.allows(RequiredScope::Value));
        assert!(all.allows(RequiredScope::AnyActive));
        assert!(!AdminScopes::default().allows(RequiredScope::AnyActive));
        // A value-only grant does not satisfy joins.
        assert!(!AdminScopes::from_scope(AdminScope::Value)
            .unwrap()
            .allows(RequiredScope::Joins));
    }

    #[test]
    fn v2_signing_hash_is_stable() {
        // Golden vector. Pins the frozen `AdminGrantV2` field order, the
        // `AdminScopes` three-byte layout, and the `admin-grant/v2` domain.
        let signed = signed_v2_with(7);
        assert_eq!(
            signed.signing_hash().to_hex(),
            "f84e76def512306057ca333fc8439ac8d4c9946f54d3926571bb4f48cbfcc99a"
        );
    }

    #[test]
    fn v2_authorize_verify_round_trip() {
        let signed = signed_v2_with(1);
        assert_eq!(signed.grant, grant_v2());
        assert_eq!(signed.verify(&operator(1).public()), Ok(()));
        assert_eq!(
            signed.verify(&operator(2).public()),
            Err(ControlError::InvalidSignature)
        );
    }

    #[test]
    fn v1_and_v2_domains_do_not_cross_verify() {
        // The two signed containers are distinct Rust types, so a v2 grant
        // cannot be passed to `SignedAdminGrant::verify` (or vice versa). The
        // cross-domain rejection is therefore driven by splicing one domain's
        // signature onto the other typed container and running that container's
        // own verifier: each must fail closed with `InvalidSignature` rather
        // than accepting a signature produced in the other signing domain.
        let op = operator(1);
        let v1 = signed_with(1);
        let v2 = signed_v2_with(1);

        let v1_with_v2_signature = SignedAdminGrant {
            grant: v1.grant.clone(),
            signature: v2.signature,
        };
        assert_eq!(
            v1_with_v2_signature.verify(&op.public()),
            Err(ControlError::InvalidSignature),
            "a v2-domain signature must not verify as a v1 grant"
        );

        let v2_with_v1_signature = SignedAdminGrantV2 {
            grant: v2.grant.clone(),
            signature: v1.signature,
        };
        assert_eq!(
            v2_with_v1_signature.verify(&op.public()),
            Err(ControlError::InvalidSignature),
            "a v1-domain signature must not verify as a v2 grant"
        );

        // Sanity: the untampered containers still verify under the same key.
        assert_eq!(v1.verify(&op.public()), Ok(()));
        assert_eq!(v2.verify(&op.public()), Ok(()));
    }

    #[test]
    fn v2_validate_rejects_empty_scopes() {
        let mut grant = grant_v2();
        grant.scopes = AdminScopes::default();
        assert_eq!(grant.validate(), Err(ControlError::EmptyAdminScopes));
    }

    #[test]
    fn v2_validate_rejects_legacy_admin_scope() {
        // `AdminScopes` cannot represent `Admin`; the singleton conversion is
        // `None`, and every representable scope is accepted.
        assert_eq!(AdminScopes::from_scope(AdminScope::Admin), None);
        assert!(AdminGrantV2 {
            scopes: AdminScopes::from_scope(AdminScope::Joins).unwrap(),
            ..grant_v2()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn v2_validate_enforces_value_ttl_cap() {
        let mut grant = grant_v2();
        grant.scopes = AdminScopes {
            joins: false,
            topology: false,
            value: true,
        };
        // Exactly the value cap is accepted.
        grant.expiry = grant.granted_at + MAX_VALUE_ADMIN_TTL_SECS;
        assert_eq!(grant.validate(), Ok(()));
        // One second over is rejected, even though it is under the general cap.
        grant.expiry = grant.granted_at + MAX_VALUE_ADMIN_TTL_SECS + 1;
        assert_eq!(
            grant.validate(),
            Err(ControlError::GrantTtlTooLong {
                ttl: MAX_VALUE_ADMIN_TTL_SECS + 1,
                max: MAX_VALUE_ADMIN_TTL_SECS,
            })
        );
        // A non-value grant may use the full general TTL.
        let mut joins = grant_v2();
        joins.scopes = AdminScopes::v1();
        joins.expiry = joins.granted_at + MAX_ADMIN_TTL_SECS;
        assert_eq!(joins.validate(), Ok(()));
    }

    #[test]
    fn v2_validate_enforces_version_label_and_window() {
        let mut bad = grant_v2();
        bad.version = ADMIN_GRANT_V1_VERSION;
        assert_eq!(
            bad.validate(),
            Err(ControlError::UnsupportedVersion(ADMIN_GRANT_V1_VERSION))
        );

        let mut label = grant_v2();
        label.label = Some("x".repeat(MAX_LABEL_LEN + 1));
        assert!(matches!(
            label.validate(),
            Err(ControlError::FieldTooLong { field: "label", .. })
        ));

        let mut window = grant_v2();
        window.expiry = window.granted_at;
        assert!(matches!(
            window.validate(),
            Err(ControlError::GrantExpiryNotAfterGrant { .. })
        ));

        let mut too_long = grant_v2();
        too_long.scopes = AdminScopes::v1();
        too_long.expiry = too_long.granted_at + MAX_ADMIN_TTL_SECS + 1;
        assert_eq!(
            too_long.validate(),
            Err(ControlError::GrantTtlTooLong {
                ttl: MAX_ADMIN_TTL_SECS + 1,
                max: MAX_ADMIN_TTL_SECS,
            })
        );
    }

    #[test]
    fn v2_is_active_boundary() {
        let signed = signed_v2_with(1);
        let expiry = grant_v2().expiry;
        assert!(signed.is_active(expiry - 1));
        assert!(signed.is_active(expiry));
        assert!(!signed.is_active(expiry + 1));
    }

    #[test]
    fn v2_round_trips_postcard() {
        let signed = signed_v2_with(1);
        let bytes = postcard::to_allocvec(&signed).unwrap();
        let back: SignedAdminGrantV2 = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, signed);
    }
}
