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
///
/// Bumped to 4 when the four exit-rights variants ([`ControlRequest::Exit`],
/// [`ControlRequest::DetachNotice`], [`ControlRequest::Rebase`],
/// [`ControlRequest::RebasePull`]) were appended.
///
/// Bumped to 5 when [`ControlRequest::AdminLedgerQuery`] was appended, to 6
/// when [`ControlRequest::AdminDetachChild`] /
/// [`ControlRequest::AdminMoveChild`] were appended, and to 7 when
/// [`ControlRequest::AdminIssue`] / [`ControlRequest::AdminBurn`] were
/// appended. Variants are only *additive*, so a v6 verifier parses every
/// pre-existing variant identically; [`is_supported_control_version`] therefore
/// accepts both 6 and 7 for rolling upgrades, and [`min_control_version`] is the
/// per-request shape gate (a v7-only variant on a v6 declaration is
/// `BadVersion`).
///
/// # Dual-accept is inbound-only
///
/// This build always **mints** frames at [`CONTROL_FORMAT_VERSION`] (7):
/// `sign_decision`/`sign_forward` in the node and
/// [`SignedControl::authorize`] everywhere stamp v7. A v6 peer therefore cannot
/// consume a v7 value variant (unknown postcard discriminant) or a routed
/// forward carrying it, and a v7 node emits only v7. The upgrade is effectively
/// **lockstep for node-to-child and routed frames**; version negotiation is a
/// v2 item. Accepting v6 here keeps a v6 peer's *pre-existing* requests readable
/// during a rolling upgrade, nothing more.
pub const CONTROL_FORMAT_VERSION: u8 = 7;

/// Whether `version` is a [`SignedControl`] wire version this build accepts
/// **inbound**.
///
/// Accepts [`CONTROL_FORMAT_VERSION`] (7) and the immediately preceding
/// version 6. Versions only *appended* request variants, so every pre-existing
/// variant is byte-identical in both; [`min_control_version`] is the per-request
/// shape gate. Anything else (including v5) is rejected up front.
///
/// This does **not** mean minted frames are ever v6: see the inbound-only note
/// on [`CONTROL_FORMAT_VERSION`].
pub fn is_supported_control_version(version: u8) -> bool {
    matches!(version, 6 | CONTROL_FORMAT_VERSION)
}

/// The minimum [`SignedControl`] wire version that can carry `request`.
///
/// Variants are append-only, so each variant has a monotone introduction
/// version. A sender's declared `version` must be `>= min_control_version` for
/// the carried request; otherwise the frame is malformed and must be rejected
/// as [`RejectCode::BadVersion`](crate::RejectCode::BadVersion) rather than
/// dispatched (a v4 peer cannot be expected to decode a v5 variant).
///
/// Mapping (frozen). The match is **exhaustive** on purpose: a future
/// `ControlRequest` variant must explicitly declare its introduction version
/// (normally [`CONTROL_FORMAT_VERSION`]) rather than silently defaulting.
pub fn min_control_version(request: &ControlRequest) -> u8 {
    match request {
        // Pre-v4 variants: the accepted window's lower bound.
        ControlRequest::Join(_)
        | ControlRequest::JoinApproved(_)
        | ControlRequest::JoinRejected(_)
        | ControlRequest::CreateChild(_)
        | ControlRequest::DetachChild(_)
        | ControlRequest::MoveChild(_)
        | ControlRequest::SetAddress(_)
        | ControlRequest::Query
        | ControlRequest::AdminQuery
        | ControlRequest::AdminApproveJoin(_)
        | ControlRequest::AdminRejectJoin(_)
        | ControlRequest::AdminRedeliverJoin(_) => 3,
        // Appended in control format 4.
        ControlRequest::Exit(_)
        | ControlRequest::DetachNotice(_)
        | ControlRequest::Rebase(_)
        | ControlRequest::RebasePull(_) => 4,
        // Appended in control format 5.
        ControlRequest::AdminLedgerQuery => 5,
        // Appended in control format 6.
        ControlRequest::AdminDetachChild(_) | ControlRequest::AdminMoveChild(_) => 6,
        // Appended in control format 7.
        ControlRequest::AdminIssue(_) | ControlRequest::AdminBurn(_) => 7,
    }
}

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
/// 1. [`is_supported_control_version`]`(signed.version)`, else
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
    if !is_supported_control_version(signed.version) {
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
    /// A numeric field is below its permitted minimum.
    #[error("{field} is {value}, minimum is {min}")]
    FieldBelowMinimum {
        /// The field name, for diagnostics.
        field: &'static str,
        /// The observed value.
        value: u64,
        /// The minimum permitted value.
        min: u64,
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
    /// An [`AdminGrantV2`](crate::AdminGrantV2) carried an empty scope set.
    #[error("admin grant must carry at least one scope")]
    EmptyAdminScopes,
    /// A value request carried an all-zero idempotency key.
    #[error("value request_id must not be all-zero")]
    ZeroValueRequestId,
    /// A value request carried an empty reason.
    #[error("value request reason must not be empty")]
    EmptyValueReason,
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
        // v1 predates `JoinApproval::parent_ledger`, so it is never a supported
        // inbound version regardless of the current `CONTROL_FORMAT_VERSION`. A
        // v1 envelope must be rejected up front rather than parsed with the new
        // shape; the check is version-exact, not `>=`.
        assert_ne!(CONTROL_FORMAT_VERSION, 1);
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
        // v2 predates `SignedControl::nonce`/`expiry`, so it is never a
        // supported inbound version. A v2 envelope must be rejected rather than
        // parsed with the newer shape.
        assert_ne!(CONTROL_FORMAT_VERSION, 2);
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
    fn verify_control_rejects_v3_version() {
        // v3 is now below the accepted window (4|5); a v3 envelope must be
        // rejected up front rather than parsed with a newer shape.
        assert_ne!(CONTROL_FORMAT_VERSION, 3);
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);
        let mut signed = signed_with(&op);
        signed.version = 3;
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::UnsupportedVersion(3))
        );
        assert_eq!(
            verify_control(&signed, &PeerRegistry::new()),
            Err(ControlError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn is_supported_control_version_accepts_6_and_7_only() {
        assert!(is_supported_control_version(6));
        assert!(is_supported_control_version(7));
        assert_eq!(CONTROL_FORMAT_VERSION, 7);
        for version in [0, 1, 2, 3, 4, 5, 8, u8::MAX] {
            assert!(
                !is_supported_control_version(version),
                "version {version} must be unsupported"
            );
        }
    }

    #[test]
    fn verify_control_rejects_v5_version() {
        // v5 is below the accepted window (6|7) after the P5 bump.
        assert_ne!(CONTROL_FORMAT_VERSION, 5);
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);
        let mut signed = signed_with(&op);
        signed.version = 5;
        assert_eq!(
            verify_control(&signed, &registry),
            Err(ControlError::UnsupportedVersion(5))
        );
        assert_eq!(
            verify_control(&signed, &PeerRegistry::new()),
            Err(ControlError::UnsupportedVersion(5))
        );
    }

    /// Build a frame that declares `version`, re-signing so the version byte is
    /// inside the signed preimage exactly as a real peer would have produced it.
    fn signed_version(op: &OperatorSecretKey, version: u8) -> SignedControl {
        let mut signed = signed_with(op);
        signed.version = version;
        signed.signature = op.sign(signed.signing_hash().as_bytes());
        signed
    }

    #[test]
    fn verify_control_accepts_v6_and_v7_frames() {
        let op = operator(1);
        let registry = registry_with(&[("origin", &op, &ledger(11))]);

        // The current (v7) frame.
        let v7 = signed_version(&op, CONTROL_FORMAT_VERSION);
        assert_eq!(v7.verify_signature(), Ok(()));
        assert!(verify_control(&v7, &registry).is_ok());

        // A real v6 frame: the version byte is covered by the signature, so it
        // must be re-signed after the downgrade.
        let v6 = signed_version(&op, 6);
        assert_eq!(v6.verify_signature(), Ok(()));
        assert!(verify_control(&v6, &registry).is_ok());

        // A v6 frame whose signature was produced over the v7 preimage fails.
        let mut tampered = signed_with(&op);
        tampered.version = 6;
        assert_eq!(
            verify_control(&tampered, &registry),
            Err(ControlError::InvalidSignature)
        );
    }

    #[test]
    fn min_control_version_is_frozen_for_every_variant() {
        use crate::request::{
            AdminJoinApprove, AdminJoinReject, AdminRedeliverJoin, CreateChild, DetachChild,
            DetachNotice, ExitRequest, JoinApproval, JoinRejection, MoveChild, RebaseNotice,
            RebasePull, SetAddress,
        };
        let child = || node("c");
        let request = |request: ControlRequest, expected: u8| {
            assert_eq!(min_control_version(&request), expected, "{request:?}");
        };

        // Every pre-v4 variant needs only v3.
        request(
            ControlRequest::Join(JoinRequest {
                node: child(),
                kind: ChildKind::Node,
                operator: operator(1).public(),
                ledger: Some(ledger(11).public()),
                desired_slot: Some(3),
                location_hint: None,
                nonce: 1,
                expiry: 100,
            }),
            3,
        );
        request(
            ControlRequest::JoinApproved(JoinApproval {
                child: child(),
                child_operator: operator(1).public(),
                child_ledger: Some(ledger(11).public()),
                kind: ChildKind::Node,
                slot: 3,
                address: "0.3".parse().unwrap(),
                date_joined: 50,
                nonce: 1,
                parent_ledger: ledger(12).public(),
            }),
            3,
        );
        request(
            ControlRequest::JoinRejected(JoinRejection {
                child: child(),
                reason: "no".to_string(),
                nonce: 1,
            }),
            3,
        );
        request(
            ControlRequest::CreateChild(CreateChild {
                child: child(),
                operator: operator(1).public(),
                ledger: Some(ledger(11).public()),
                kind: ChildKind::Node,
                slot: Some(3),
                date_joined: 50,
            }),
            3,
        );
        request(ControlRequest::DetachChild(DetachChild { child: child() }), 3);
        request(
            ControlRequest::MoveChild(MoveChild {
                child: child(),
                new_parent: node("parent"),
                slot: Some(4),
            }),
            3,
        );
        request(ControlRequest::SetAddress(SetAddress { address: None }), 3);
        request(ControlRequest::Query, 3);
        request(ControlRequest::AdminQuery, 3);
        request(
            ControlRequest::AdminApproveJoin(AdminJoinApprove {
                child: child(),
                slot: None,
            }),
            3,
        );
        request(
            ControlRequest::AdminRejectJoin(AdminJoinReject {
                child: child(),
                reason: None,
            }),
            3,
        );
        request(
            ControlRequest::AdminRedeliverJoin(AdminRedeliverJoin { child: child() }),
            3,
        );

        // The four exit-rights variants were introduced in v4.
        request(
            ControlRequest::Exit(ExitRequest {
                node: child(),
                subtree_nodes: 1,
            }),
            4,
        );
        request(ControlRequest::DetachNotice(DetachNotice { node: child() }), 4);
        request(
            ControlRequest::Rebase(RebaseNotice {
                node: child(),
                parent_address: "0".parse().unwrap(),
                address: "0.3".parse().unwrap(),
                generation: 1,
            }),
            4,
        );
        request(ControlRequest::RebasePull(RebasePull { node: child() }), 4);

        // The ledger view was introduced in v5.
        request(ControlRequest::AdminLedgerQuery, 5);

        // The topology-admin variants were introduced in v6.
        request(
            ControlRequest::AdminDetachChild(crate::request::AdminDetachChild { child: child() }),
            6,
        );
        request(
            ControlRequest::AdminMoveChild(crate::request::AdminMoveChild {
                child: child(),
                slot: None,
            }),
            6,
        );

        // The value-admin variants were introduced in v7.
        let value = || crate::request::AdminValueRequest {
            request_id: crate::request::ValueRequestId::from_bytes([3u8; 16]),
            account: child(),
            amount: 5,
            reason: "test".to_string(),
        };
        request(ControlRequest::AdminIssue(value()), 7);
        request(ControlRequest::AdminBurn(value()), 7);
    }

    #[test]
    fn signing_hash_is_stable() {
        // Golden vector. This pins the frozen field order and domain-separated
        // encoding of `(version, origin, controller, nonce, expiry, request)`: a
        // reordered, added, or removed field changes this hash, so the pinned
        // value must only ever change as part of a deliberate protocol version
        // bump. It changed at version 2 when `JoinApproval` gained
        // `parent_ledger`, at version 3 when `SignedControl` gained
        // `nonce` and `expiry`, at version 4 when the exit-rights variants were
        // appended, at version 5 when `AdminLedgerQuery` was appended, at
        // version 6 when the topology-admin variants were appended, and at
        // version 7 when the value-admin variants were appended (the version
        // byte is inside the preimage).
        let signed = signed_with(&operator(7));
        assert_eq!(
            signed.signing_hash().to_hex(),
            "310b5498d403a97ced10b832015c4d64df835cabf4360bcbe24b6b58b8db73d3"
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
