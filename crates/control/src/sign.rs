//! Signing and verification of control requests.
//!
//! A [`SignedControl`] binds a [`ControlRequest`] to an origin node and the
//! operator key that signed it. The signature is over a **domain-separated
//! hash** of the canonical postcard encoding of `(version, origin, controller,
//! nonce, expiry, request)`, mirroring the ledger's `auth` module. Because the
//! hash domain (`cawala-control/request/v1`) differs from every ledger domain,
//! a control signature can never be replayed as a ledger authorisation, or vice
//! versa.
//!
//! `nonce` and `expiry` are carried inside the signature so a replayer cannot
//! swap or refresh them: replay/staleness checks belong to the node, but the
//! values themselves are bound to the request.
//!
//! # Trust boundary
//!
//! [`verify_control`] proves that the `controller` key signed the request and
//! that the registry binds that key to the `origin` node. It does **not**
//! authorize the request: senior-child, target, and topology rules are applied
//! by the node afterwards. Envelope metadata is never consulted here.

use serde::{Deserialize, Serialize};

use cawala_ledger::{
    Hash, NodeId, OperatorPubKey, OperatorSecretKey, PeerKeys, PeerRegistry, Signature,
};

use crate::request::ControlRequest;

/// Wire format version for [`SignedControl`].
///
/// Bumped to 2 when [`JoinApproval`](crate::JoinApproval) gained
/// `parent_ledger`: the signed preimage changed, so a v1 verifier must reject a
/// v2 message rather than misparse it.
///
/// Bumped to 3 when [`SignedControl`] gained `nonce` and `expiry`: the signed
/// preimage changed again, so a v2 verifier must likewise reject a v3 message
/// rather than misparse it.
pub const CONTROL_FORMAT_VERSION: u8 = 3;

/// Recommended lifetime, in seconds, of a control request (`nonce`/`expiry`).
///
/// This crate has no clock: callers stamp `expiry = now + TTL` and the node
/// enforces `now <= expiry` plus the replay `nonce`.
pub const CONTROL_REQUEST_TTL_SECS: u64 = 120;

/// Absolute upper bound, in seconds, accepted for a control request's
/// `expiry - now`. A node rejects anything larger; this is the ceiling
/// [`CONTROL_REQUEST_TTL_SECS`] must stay under.
pub const CONTROL_REQUEST_MAX_TTL_SECS: u64 = 300;

/// BLAKE3 derive-key context for the control signing hash.
pub const CONTROL_CONTEXT: &str = "cawala-control/request/v1";

/// An operator-signed control request.
///
/// Field order is frozen: the signing preimage is the postcard encoding of
/// `(version, origin, controller, nonce, expiry, request)` in declaration
/// order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedControl {
    /// Wire format version ([`CONTROL_FORMAT_VERSION`]).
    pub version: u8,
    /// The controller's node id.
    pub origin: NodeId,
    /// The operator key that produced `signature`.
    pub controller: OperatorPubKey,
    /// Fresh per-request nonce. The node tracks seen nonces per origin to
    /// reject replays; it is signed here so a relay cannot alter it.
    pub nonce: u64,
    /// Unix seconds; the request is valid while `now <= expiry`. Signed here
    /// so a relay cannot extend its lifetime.
    pub expiry: u64,
    /// The request being authorised.
    pub request: ControlRequest,
    /// Operator signature over [`SignedControl::signing_hash`].
    pub signature: Signature,
}

/// Private canonical preimage for the signing hash.
///
/// This exists (rather than hashing the struct fields directly) so the signed
/// field order is explicit and cannot drift from the `SignedControl`
/// declaration.
#[derive(Serialize)]
struct SigningPreimage<'a> {
    version: u8,
    origin: &'a NodeId,
    controller: &'a OperatorPubKey,
    nonce: u64,
    expiry: u64,
    request: &'a ControlRequest,
}

impl SignedControl {
    /// Build a signed control message, setting
    /// `version = CONTROL_FORMAT_VERSION`.
    ///
    /// `nonce` must be fresh per request and `expiry` is unix seconds; both are
    /// covered by the signature. The caller supplies the operator secret key;
    /// this crate never generates key material.
    pub fn authorize(
        origin: NodeId,
        controller: &OperatorSecretKey,
        nonce: u64,
        expiry: u64,
        request: ControlRequest,
    ) -> Result<Self, ControlError> {
        let mut signed = SignedControl {
            version: CONTROL_FORMAT_VERSION,
            origin,
            controller: controller.public(),
            nonce,
            expiry,
            request,
            // Placeholder; replaced below. The signing hash does not cover the
            // signature field.
            signature: Signature::from_bytes(&[0u8; Signature::LENGTH]),
        };
        let hash = signed.signing_hash();
        signed.signature = controller.sign(hash.as_bytes());
        Ok(signed)
    }

    /// The signed preimage hash: BLAKE3 derive-key([`CONTROL_CONTEXT`]) over
    /// the canonical postcard encoding of
    /// `(version, origin, controller, nonce, expiry, request)`.
    pub fn signing_hash(&self) -> Hash {
        let preimage = SigningPreimage {
            version: self.version,
            origin: &self.origin,
            controller: &self.controller,
            nonce: self.nonce,
            expiry: self.expiry,
            request: &self.request,
        };
        // The derived serde impls used here never fail to encode; the only
        // fallible component would be a custom serializer, and none are
        // involved.
        let bytes = postcard::to_allocvec(&preimage)
            .expect("control signing preimage is always postcard-encodable");
        let mut hasher = blake3::Hasher::new_derive_key(CONTROL_CONTEXT);
        hasher.update(&bytes);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Verify [`Self::signature`] under [`Self::controller`] over
    /// [`Self::signing_hash`].
    pub fn verify_signature(&self) -> Result<(), ControlError> {
        self.controller
            .verify(self.signing_hash().as_bytes(), &self.signature)
            .map_err(|_| ControlError::InvalidSignature)
    }
}

/// Verify a signed control request against the peer registry.
///
/// Steps, in order:
/// 1. `signed.version == CONTROL_FORMAT_VERSION`, else
///    [`ControlError::UnsupportedVersion`];
/// 2. `origin` is registered, else [`ControlError::UnknownOrigin`];
/// 3. the registered operator equals `signed.controller`, else
///    [`ControlError::OperatorMismatch`];
/// 4. the signature verifies, else [`ControlError::InvalidSignature`].
///
/// On success the origin's [`PeerKeys`] are returned. This is authentication
/// only; the caller still applies the authorization rules.
pub fn verify_control<'a>(
    signed: &SignedControl,
    registry: &'a PeerRegistry,
) -> Result<&'a PeerKeys, ControlError> {
    if signed.version != CONTROL_FORMAT_VERSION {
        return Err(ControlError::UnsupportedVersion(signed.version));
    }
    let peer = registry
        .get(&signed.origin)
        .ok_or_else(|| ControlError::UnknownOrigin(signed.origin.clone()))?;
    if peer.operator != signed.controller {
        return Err(ControlError::OperatorMismatch);
    }
    signed.verify_signature()?;
    Ok(peer)
}

/// Errors raised by control signing, validation, and verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlError {
    /// The wire version is not [`CONTROL_FORMAT_VERSION`].
    #[error("unsupported control version {0}")]
    UnsupportedVersion(u8),
    /// The origin node is absent from the registry.
    #[error("origin '{0}' is not registered")]
    UnknownOrigin(NodeId),
    /// The signed controller key is not the origin's registered operator key.
    #[error("controller key does not match the origin's registered operator key")]
    OperatorMismatch,
    /// The signature does not verify under the controller key.
    #[error("invalid control signature")]
    InvalidSignature,
    /// A node-kind join omitted its ledger key.
    #[error("join node kind requires a ledger key")]
    MissingLedgerForNode,
    /// A user-kind join carried a ledger key.
    #[error("user join must not carry a ledger key")]
    UnexpectedLedgerForUser,
    /// A requested slot is outside `0..=7`.
    #[error("slot {0} out of range (must be 0..=7)")]
    SlotOutOfRange(u8),
    /// A bounded free-form field exceeded its maximum length.
    #[error("{field} is {len} bytes, max {max}")]
    FieldTooLong {
        /// The field name, for diagnostics.
        field: &'static str,
        /// The observed length in bytes.
        len: usize,
        /// The permitted maximum length in bytes.
        max: usize,
    },
    /// Canonical postcard encoding/decoding failed.
    #[error("postcard encode/decode: {0}")]
    Codec(String),
    /// An admin grant's expiry is not strictly after its `granted_at`.
    #[error("admin grant expiry {expiry} is not after granted_at {granted_at}")]
    GrantExpiryNotAfterGrant {
        /// Unix-seconds time the grant was issued.
        granted_at: u64,
        /// Unix-seconds expiry that must be greater than `granted_at`.
        expiry: u64,
    },
    /// An admin grant's lifetime exceeds [`MAX_ADMIN_TTL_SECS`](crate::MAX_ADMIN_TTL_SECS).
    #[error("admin grant ttl {ttl}s exceeds max {max}s")]
    GrantTtlTooLong {
        /// The requested lifetime (`expiry - granted_at`) in seconds.
        ttl: u64,
        /// The permitted maximum lifetime in seconds.
        max: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{LedgerSecretKey, PeerRole};
    use cawala_topology::ChildKind;

    use crate::request::JoinRequest;

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn ledger(seed: u8) -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([seed; 32])
    }

    fn peer(id: &str, op: &OperatorSecretKey, ledger_key: &LedgerSecretKey) -> PeerKeys {
        PeerKeys {
            node_id: node(id),
            operator: op.public(),
            ledger: Some(ledger_key.public()),
            role: PeerRole::Node,
        }
    }

    fn registry_with(peers: &[(&str, &OperatorSecretKey, &LedgerSecretKey)]) -> PeerRegistry {
        let mut registry = PeerRegistry::new();
        for (id, op, ledger_key) in peers {
            registry.insert(peer(id, op, ledger_key)).unwrap();
        }
        registry
    }

    fn sample_request() -> ControlRequest {
        ControlRequest::Join(JoinRequest {
            node: node("applicant"),
            kind: ChildKind::Node,
            operator: operator(9).public(),
            ledger: Some(ledger(5).public()),
            desired_slot: Some(3),
            location_hint: Some("0.3".to_string()),
            nonce: 42,
            expiry: 1000,
        })
    }

    fn signed_with(op: &OperatorSecretKey) -> SignedControl {
        SignedControl::authorize(node("origin"), op, 7, 1_000, sample_request()).unwrap()
    }

    #[test]
    fn authorize_then_verify_control_round_trip() {
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);
        let signed = signed_with(&op);

        assert_eq!(signed.version, CONTROL_FORMAT_VERSION);
        assert_eq!(signed.origin, node("origin"));
        assert_eq!(signed.controller, op.public());
        assert_eq!(signed.nonce, 7);
        assert_eq!(signed.expiry, 1_000);
        assert_eq!(signed.verify_signature(), Ok(()));

        let verified = verify_control(&signed, &registry).unwrap();
        assert_eq!(verified.node_id, node("origin"));
        assert_eq!(verified.operator, op.public());
    }

    #[test]
    fn verify_control_rejects_unknown_origin() {
        let registry = PeerRegistry::new();
        let signed = signed_with(&operator(1));
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::UnknownOrigin(node("origin")))
        );
    }

    #[test]
    fn verify_control_rejects_operator_mismatch() {
        // The registry binds `origin` to a different operator key than the one
        // that signed.
        let registry = registry_with(&[("origin", &operator(2), &ledger(11))]);
        let signed = signed_with(&operator(1));
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::OperatorMismatch)
        );
    }

    #[test]
    fn verify_control_rejects_tampered_request() {
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);
        let mut signed = signed_with(&op);

        // Mutate the request after signing: the signature no longer matches.
        if let ControlRequest::Join(join) = &mut signed.request {
            join.nonce += 1;
        } else {
            unreachable!("sample request is a join");
        }
        assert_eq!(
            signed.verify_signature(),
            Err(ControlError::InvalidSignature)
        );
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::InvalidSignature)
        );
    }

    #[test]
    fn verify_control_rejects_tampered_nonce() {
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);
        let mut signed = signed_with(&op);

        // The nonce is inside the signed preimage: a relay cannot swap it.
        signed.nonce += 1;
        assert_eq!(
            signed.verify_signature(),
            Err(ControlError::InvalidSignature)
        );
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::InvalidSignature)
        );
    }

    #[test]
    fn verify_control_rejects_tampered_expiry() {
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);
        let mut signed = signed_with(&op);

        // The expiry is inside the signed preimage: a relay cannot extend it.
        signed.expiry += 1;
        assert_eq!(
            signed.verify_signature(),
            Err(ControlError::InvalidSignature)
        );
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::InvalidSignature)
        );
    }

    #[test]
    fn verify_control_rejects_bad_version() {
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);
        let mut signed = signed_with(&op);
        signed.version = CONTROL_FORMAT_VERSION + 1;
        // Version is checked before the registry lookup or signature.
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::UnsupportedVersion(CONTROL_FORMAT_VERSION + 1))
        );
        assert_eq!(
            verify_control(&signed, &PeerRegistry::new()),
            Err(ControlError::UnsupportedVersion(CONTROL_FORMAT_VERSION + 1))
        );
    }

    #[test]
    fn verify_control_rejects_v1_version() {
        // The format is now 3 (v1 predates `JoinApproval::parent_ledger`). A v1
        // envelope must be rejected up front rather than parsed with the new
        // shape; the check is version-exact, not `>=`.
        assert_ne!(CONTROL_FORMAT_VERSION, 1, "this test assumes format 3");
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);
        let mut signed = signed_with(&op);
        signed.version = 1;
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::UnsupportedVersion(1))
        );
        assert_eq!(
            verify_control(&signed, &PeerRegistry::new()),
            Err(ControlError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn verify_control_rejects_v2_version() {
        // v2 predates `SignedControl::nonce`/`expiry`; a v2 envelope must be
        // rejected rather than parsed with the v3 shape.
        assert_ne!(CONTROL_FORMAT_VERSION, 2, "this test assumes format 3");
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);
        let mut signed = signed_with(&op);
        signed.version = 2;
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::UnsupportedVersion(2))
        );
        assert_eq!(
            verify_control(&signed, &PeerRegistry::new()),
            Err(ControlError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn signing_hash_is_stable() {
        // Golden vector. This pins the frozen field order and domain-separated
        // encoding of `(version, origin, controller, nonce, expiry, request)`: a
        // reordered, added, or removed field changes this hash, so the pinned
        // value must only ever change as part of a deliberate protocol version
        // bump. It changed at version 2 when `JoinApproval` gained
        // `parent_ledger`, and again at version 3 when `SignedControl` gained
        // `nonce` and `expiry`.
        let signed = signed_with(&operator(7));
        assert_eq!(
            signed.signing_hash().to_hex(),
            "467b9187602e4441c8da24021d858826a4e915426155987cb3b4e47c06b83978"
        );
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let mut signed = signed_with(&operator(1));
        // Same controller key in the message, but the signature was produced
        // by a different key.
        signed.signature = operator(2).sign(signed.signing_hash().as_bytes());
        assert_eq!(
            signed.verify_signature(),
            Err(ControlError::InvalidSignature)
        );
    }
}
