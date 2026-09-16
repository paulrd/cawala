//! Tree-routed control payloads carried inside `cawala/msg/0` envelopes.
//!
//! Direct control ([`CONTROL_ALPN`](crate::CONTROL_ALPN)) assumes the caller can
//! dial the target node. Tree-routed control instead rides the existing
//! `MSG_CONTROL_V1` envelope: a browser/operator hands a [`RoutedControlV1`] to
//! its parent, which forwards it hop-by-hop along the octal tree to the target
//! node, which answers with a [`SignedRoutedReply`] travelling back down.
//!
//! # Wire format
//!
//! Both routed payloads are postcard-encoded and their declaration order is
//! **frozen**. Each carries a leading `version` byte field, so a bare postcard
//! encoding is already version-prefixed: the first byte of
//! [`RoutedControlV1::to_bytes`] / [`SignedRoutedReply::to_bytes`] is the wire
//! version. A future field reorder or addition is a protocol break.
//!
//! # Trust boundary
//!
//! The intermediate forwards in [`RoutedControlV1::forwards`] are best-effort
//! **evidence**, not authority: each is a real [`SignedControl`] but only the
//! last hop's signature is verified cryptographically by the destination (see
//! the M5 design). [`RoutedControlV1::validate`] checks structural coherence
//! only; it proves nothing about who sent the message.
//!
//! The reply half is fully end-to-end signed under the destination node's
//! operator key with a dedicated BLAKE3 derive-key domain
//! ([`ROUTED_REPLY_CONTEXT`]), so it can never be replayed as a control request
//! or an admin grant.
//!
//! # Bounds
//!
//! Decoding happens before any validation, so every wire-controlled length is
//! capped: [`RoutedControlV1::from_bytes`] rejects frames larger than
//! [`MAX_CONTROL_FRAME`](crate::MAX_CONTROL_FRAME) *before* decoding, and the
//! `forwards` field uses a bounded deserializer
//! ([`deserialize_forwards`]) that rejects more than [`MAX_ROUTED_FORWARDS`]
//! entries without materializing them. This stops a hostile frame from forcing
//! a large allocation before authentication runs.

use std::fmt;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use cawala_ledger::{Hash, OperatorPubKey, OperatorSecretKey, Signature};
use cawala_msg::{MAX_HOPS, MsgId, PeerRef};

use crate::admin::SignedAdminGrant;
use crate::reply::ControlReply;
use crate::sign::{SignedControl, is_supported_control_version};

/// Wire format version for [`RoutedControlV1`].
pub const ROUTED_CONTROL_VERSION: u8 = 1;

/// Wire format version for [`RoutedReplyV1`].
pub const ROUTED_REPLY_VERSION: u8 = 1;

/// BLAKE3 derive-key context for the routed-reply signing hash.
///
/// Distinct from
/// [`CONTROL_CONTEXT`](crate::CONTROL_CONTEXT) and
/// [`ADMIN_GRANT_CONTEXT`](crate::ADMIN_GRANT_CONTEXT), so a routed reply
/// signature can never be replayed as a control request or an admin grant, or
/// vice versa.
pub const ROUTED_REPLY_CONTEXT: &str = "cawala-control/routed-reply/v1";

/// Maximum number of per-hop forwards carried by a [`RoutedControlV1`].
///
/// There is one forward per transmitting hop, so this is bounded by the
/// envelope hop chain cap ([`cawala_msg::MAX_HOPS`]).
pub const MAX_ROUTED_FORWARDS: usize = MAX_HOPS;

/// A tree-routed control request travelling towards its target node.
///
/// Field order is frozen: postcard is positional, and the leading `version`
/// byte is the wire discriminator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutedControlV1 {
    /// Wire format version ([`ROUTED_CONTROL_VERSION`]).
    pub version: u8,
    /// The destination node id plus its asserted [`OctAddr`](cawala_msg::OctAddr).
    pub target: PeerRef,
    /// Who asked (must equal the envelope `src`; checked at the destination).
    pub requester: PeerRef,
    /// The end-to-end human request (a v3/v4 [`SignedControl`], advisory for
    /// non-admin classes).
    pub intent: SignedControl,
    /// Carried admin evidence, if any. It is audit evidence only: a
    /// carried-but-unstored grant never authorises at the destination.
    pub grant: Option<SignedAdminGrant>,
    /// One entry per transmitting hop, in path order.
    ///
    /// Deserialization is bounded to [`MAX_ROUTED_FORWARDS`] entries (see
    /// [`deserialize_forwards`]) so a hostile length cannot allocate an
    /// unbounded `Vec` before validation runs.
    #[serde(deserialize_with = "deserialize_forwards")]
    pub forwards: Vec<RoutedForward>,
}

/// One transmitting hop's re-signing of the carried control request.
///
/// Field order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutedForward {
    /// The hop that produced `signed` (id + address).
    pub hop: PeerRef,
    /// The hop's own v3/v4 [`SignedControl`] over the same request.
    pub signed: SignedControl,
}

impl RoutedForward {
    /// Build a forward from a hop reference and its re-signed control.
    ///
    /// Dependency-free and non-validating: callers still run
    /// [`RoutedControlV1::validate`] on the assembled payload.
    pub fn new(hop: PeerRef, signed: SignedControl) -> Self {
        RoutedForward { hop, signed }
    }
}

impl RoutedControlV1 {
    /// Structural coherence checks for a routed control request.
    ///
    /// Checks, in order:
    /// 1. `version == `[`ROUTED_CONTROL_VERSION`];
    /// 2. `forwards.len() <= `[`MAX_ROUTED_FORWARDS`] (an origin-only payload
    ///    need not carry a forward here; empty is accepted);
    /// 3. [`is_supported_control_version`]`(intent.version)`, i.e. the intent is
    ///    v3 or v4;
    /// 4. for every forward `i`: [`is_supported_control_version`]`(signed.version)`,
    ///    `signed.request == intent.request`, and `hop.node` equals the signed
    ///    `origin` node string.
    ///
    /// This is structural only. Signatures are verified by intermediate hops
    /// (each against its own registry) and by the destination node; the
    /// intermediate forwards are evidence, not authority.
    pub fn validate(&self) -> Result<(), RoutedError> {
        if self.version != ROUTED_CONTROL_VERSION {
            return Err(RoutedError::UnsupportedVersion(self.version));
        }
        if self.forwards.len() > MAX_ROUTED_FORWARDS {
            return Err(RoutedError::TooManyForwards {
                len: self.forwards.len(),
                max: MAX_ROUTED_FORWARDS,
            });
        }
        if !is_supported_control_version(self.intent.version) {
            return Err(RoutedError::UnsupportedVersion(self.intent.version));
        }
        for (index, forward) in self.forwards.iter().enumerate() {
            if !is_supported_control_version(forward.signed.version) {
                return Err(RoutedError::UnsupportedVersion(forward.signed.version));
            }
            if forward.signed.request != self.intent.request {
                return Err(RoutedError::ForwardRequestMismatch { index });
            }
            let origin = forward.signed.origin.as_str();
            if forward.hop.node != origin {
                return Err(RoutedError::ForwardHopMismatch {
                    index,
                    hop: forward.hop.node.clone(),
                    origin: origin.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Postcard-encode the request (the leading byte is
    /// [`ROUTED_CONTROL_VERSION`]).
    ///
    /// Rejects an encoding larger than
    /// [`MAX_CONTROL_FRAME`](crate::MAX_CONTROL_FRAME); a valid payload is far
    /// smaller.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RoutedError> {
        let bytes = postcard::to_allocvec(self).map_err(codec_error)?;
        if bytes.len() > crate::MAX_CONTROL_FRAME as usize {
            return Err(RoutedError::FrameTooLarge {
                actual: bytes.len(),
                max: crate::MAX_CONTROL_FRAME as usize,
            });
        }
        Ok(bytes)
    }

    /// Postcard-decode a routed control request.
    ///
    /// Rejects an empty buffer, a buffer larger than
    /// [`MAX_CONTROL_FRAME`](crate::MAX_CONTROL_FRAME) *before* decoding, an
    /// unsupported leading version byte, a truncated/invalid body, and any
    /// trailing bytes after the body. Never panics on arbitrary input.
    ///
    /// Decoding does not validate the payload; callers must invoke
    /// [`RoutedControlV1::validate`] before trusting it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RoutedError> {
        check_frame_len(bytes.len())?;
        let version = peek_version(bytes)?;
        if version != ROUTED_CONTROL_VERSION {
            return Err(RoutedError::UnsupportedVersion(version));
        }
        decode_exact::<Self>(bytes)
    }
}

/// A tree-routed reply travelling back from the target node.
///
/// Field order is frozen: postcard is positional, and the leading `version`
/// byte is the wire discriminator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutedReplyV1 {
    /// Wire format version ([`ROUTED_REPLY_VERSION`]).
    pub version: u8,
    /// Correlation: the `msg_id` of the request envelope.
    pub reply_to: MsgId,
    /// Who asked (the reply travels back towards this peer).
    pub requester: PeerRef,
    /// The answering node id plus its asserted
    /// [`OctAddr`](cawala_msg::OctAddr).
    pub responder: PeerRef,
    /// The direct-control reply being carried.
    pub reply: ControlReply,
}

impl RoutedReplyV1 {
    /// Check `version == `[`ROUTED_REPLY_VERSION`].
    pub fn validate(&self) -> Result<(), RoutedError> {
        if self.version != ROUTED_REPLY_VERSION {
            return Err(RoutedError::UnsupportedVersion(self.version));
        }
        Ok(())
    }
}

/// A node-operator-signed [`RoutedReplyV1`].
///
/// The signature is over a BLAKE3 derive-key([`ROUTED_REPLY_CONTEXT`]) hash of
/// the **full** postcard encoding of the reply, mirroring
/// [`SignedAdminGrant::signing_hash`](crate::SignedAdminGrant::signing_hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRoutedReply {
    /// The reply being attested.
    pub reply: RoutedReplyV1,
    /// The responder operator's signature over
    /// [`SignedRoutedReply::signing_hash`].
    pub signature: Signature,
}

impl SignedRoutedReply {
    /// Build a signed routed reply, validating it and signing with the
    /// responder node's operator secret key.
    ///
    /// The caller supplies the key; this crate never generates key material.
    pub fn authorize(
        reply: RoutedReplyV1,
        signer: &OperatorSecretKey,
    ) -> Result<Self, RoutedError> {
        reply.validate()?;
        let mut signed = SignedRoutedReply {
            reply,
            // Placeholder; replaced below. The signing hash does not cover the
            // signature field.
            signature: Signature::from_bytes(&[0u8; Signature::LENGTH]),
        };
        signed.signature = signer.sign(signed.signing_hash().as_bytes());
        Ok(signed)
    }

    /// The signed preimage hash: BLAKE3
    /// derive-key([`ROUTED_REPLY_CONTEXT`]) over the canonical postcard
    /// encoding of the whole [`RoutedReplyV1`].
    pub fn signing_hash(&self) -> Hash {
        // The derived serde impls used here never fail to encode; the only
        // fallible component would be a custom serializer, and none are
        // involved.
        let bytes = postcard::to_allocvec(&self.reply)
            .expect("routed reply is always postcard-encodable");
        let mut hasher = blake3::Hasher::new_derive_key(ROUTED_REPLY_CONTEXT);
        hasher.update(&bytes);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Verify [`Self::signature`] under `signer` over [`Self::signing_hash`].
    ///
    /// `signer` must be the responder node's operator public key; a mismatch
    /// (or any tampering, or a signature produced under a different domain)
    /// fails as [`RoutedError::InvalidSignature`].
    pub fn verify(&self, signer: &OperatorPubKey) -> Result<(), RoutedError> {
        self.reply.validate()?;
        signer
            .verify(self.signing_hash().as_bytes(), &self.signature)
            .map_err(|_| RoutedError::InvalidSignature)
    }

    /// Postcard-encode the reply (the leading byte is
    /// [`ROUTED_REPLY_VERSION`]).
    ///
    /// Rejects an encoding larger than
    /// [`MAX_CONTROL_FRAME`](crate::MAX_CONTROL_FRAME); a valid payload is far
    /// smaller.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RoutedError> {
        let bytes = postcard::to_allocvec(self).map_err(codec_error)?;
        if bytes.len() > crate::MAX_CONTROL_FRAME as usize {
            return Err(RoutedError::FrameTooLarge {
                actual: bytes.len(),
                max: crate::MAX_CONTROL_FRAME as usize,
            });
        }
        Ok(bytes)
    }

    /// Postcard-decode a signed routed reply.
    ///
    /// Rejects an empty buffer, a buffer larger than
    /// [`MAX_CONTROL_FRAME`](crate::MAX_CONTROL_FRAME) *before* decoding, an
    /// unsupported leading version byte, a truncated/invalid body, and any
    /// trailing bytes after the body.
    ///
    /// Decoding does not verify the signature; callers must invoke
    /// [`SignedRoutedReply::verify`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RoutedError> {
        check_frame_len(bytes.len())?;
        let version = peek_version(bytes)?;
        if version != ROUTED_REPLY_VERSION {
            return Err(RoutedError::UnsupportedVersion(version));
        }
        decode_exact::<Self>(bytes)
    }
}

/// Errors raised by routed-control validation, encoding, and verification.
///
/// A dedicated enum (rather than new variants on
/// [`ControlError`](crate::ControlError)) keeps the existing direct-control
/// error surface unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoutedError {
    /// The wire version is not the expected routed version.
    #[error("unsupported routed control version {0}")]
    UnsupportedVersion(u8),
    /// The encoded frame exceeds [`MAX_CONTROL_FRAME`](crate::MAX_CONTROL_FRAME).
    #[error("routed frame is {actual} bytes, max {max}")]
    FrameTooLarge {
        /// Observed encoded/decoded length in bytes.
        actual: usize,
        /// Permitted maximum length in bytes.
        max: usize,
    },
    /// The buffer was empty.
    #[error("routed payload is empty")]
    Empty,
    /// Bytes remained after the postcard body.
    #[error("{n} trailing byte(s) after routed payload")]
    TrailingBytes {
        /// Number of unconsumed trailing bytes.
        n: usize,
    },
    /// More forwards than [`MAX_ROUTED_FORWARDS`].
    #[error("too many routed forwards: {len}, max {max}")]
    TooManyForwards {
        /// Observed forward count.
        len: usize,
        /// Permitted maximum.
        max: usize,
    },
    /// A forward's hop id does not match its signed control's origin.
    #[error("routed forward {index} hop '{hop}' does not match signed origin '{origin}'")]
    ForwardHopMismatch {
        /// Index of the offending forward.
        index: usize,
        /// The hop's node id.
        hop: String,
        /// The signed control's origin node id.
        origin: String,
    },
    /// A forward's signed request differs from the carried intent request.
    #[error("routed forward {index} request does not match the intent request")]
    ForwardRequestMismatch {
        /// Index of the offending forward.
        index: usize,
    },
    /// The routed reply signature does not verify.
    #[error("invalid routed reply signature")]
    InvalidSignature,
    /// Canonical postcard encoding/decoding failed.
    #[error("postcard encode/decode: {0}")]
    Codec(String),
}

fn codec_error(err: postcard::Error) -> RoutedError {
    RoutedError::Codec(err.to_string())
}

/// Reject a frame larger than [`MAX_CONTROL_FRAME`](crate::MAX_CONTROL_FRAME)
/// before any decode work.
fn check_frame_len(len: usize) -> Result<(), RoutedError> {
    if len > crate::MAX_CONTROL_FRAME as usize {
        return Err(RoutedError::FrameTooLarge {
            actual: len,
            max: crate::MAX_CONTROL_FRAME as usize,
        });
    }
    Ok(())
}

/// Peek the leading version byte, rejecting an empty buffer.
///
/// Both routed payloads declare their unit `version` as the first field, so the
/// first encoded byte is the wire version and can be checked before the
/// (bounded) body decode.
fn peek_version(bytes: &[u8]) -> Result<u8, RoutedError> {
    bytes.first().copied().ok_or(RoutedError::Empty)
}

/// Decode exactly one postcard value, rejecting trailing bytes.
fn decode_exact<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, RoutedError> {
    match postcard::take_from_bytes::<T>(body) {
        Ok((value, [])) => Ok(value),
        Ok((_, rest)) => Err(RoutedError::TrailingBytes { n: rest.len() }),
        Err(err) => Err(codec_error(err)),
    }
}

/// Deserialize a forward vector with a hard cap of [`MAX_ROUTED_FORWARDS`]
/// elements.
///
/// Postcard's `Vec` encoding is a varint length followed by the elements, so a
/// hostile length would otherwise allocate an unbounded `Vec` before
/// [`RoutedControlV1::validate`] can reject it. This visitor rejects an
/// oversized `size_hint` immediately and also counts elements, erroring as soon
/// as the cap is exceeded (covering formats whose `size_hint` is `None`).
fn deserialize_forwards<'de, D>(deserializer: D) -> Result<Vec<RoutedForward>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ForwardsVisitor;

    impl<'de> Visitor<'de> for ForwardsVisitor {
        type Value = Vec<RoutedForward>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "at most {MAX_ROUTED_FORWARDS} routed forward entries"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if let Some(hint) = seq.size_hint()
                && hint > MAX_ROUTED_FORWARDS
            {
                return Err(de::Error::invalid_length(hint, &self));
            }
            let cap = seq.size_hint().unwrap_or(0).min(MAX_ROUTED_FORWARDS);
            let mut forwards = Vec::with_capacity(cap);
            while let Some(forward) = seq.next_element::<RoutedForward>()? {
                if forwards.len() >= MAX_ROUTED_FORWARDS {
                    return Err(de::Error::invalid_length(forwards.len() + 1, &self));
                }
                forwards.push(forward);
            }
            Ok(forwards)
        }
    }

    deserializer.deserialize_seq(ForwardsVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    use cawala_ledger::{NodeId, OperatorSecretKey};
    use cawala_msg::OctAddr;

    use crate::admin::{ADMIN_GRANT_CONTEXT, ADMIN_GRANT_VERSION, AdminGrant, AdminScope};
    use crate::request::ControlRequest;
    use crate::sign::{CONTROL_CONTEXT, CONTROL_FORMAT_VERSION};

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn peer(addr: &str, node: &str) -> PeerRef {
        let addr: OctAddr = addr.parse().expect("sample address parses");
        PeerRef {
            addr,
            node: node.to_string(),
        }
    }

    fn sample_control() -> RoutedControlV1 {
        let request = ControlRequest::Query;
        let intent =
            SignedControl::authorize(node("node-d"), &operator(1), 7, 1_000, request.clone())
                .unwrap();
        let signed =
            SignedControl::authorize(node("node-d"), &operator(1), 11, 2_000, request).unwrap();
        RoutedControlV1 {
            version: ROUTED_CONTROL_VERSION,
            target: peer("0.3", "node-d"),
            requester: peer("0.1", "browser"),
            intent,
            grant: None,
            forwards: vec![RoutedForward::new(peer("0.3", "node-d"), signed)],
        }
    }

    fn sample_reply() -> RoutedReplyV1 {
        RoutedReplyV1 {
            version: ROUTED_REPLY_VERSION,
            reply_to: MsgId([0xab; 16]),
            requester: peer("0.1", "browser"),
            responder: peer("0.3", "node-d"),
            reply: ControlReply::Accepted,
        }
    }

    fn sample_grant() -> AdminGrant {
        AdminGrant {
            version: ADMIN_GRANT_VERSION,
            node: node("node-d"),
            admin: operator(3).public(),
            scope: AdminScope::Admin,
            granted_at: 1_000,
            expiry: 1_000 + crate::DEFAULT_ADMIN_TTL_SECS,
            label: Some("lab".to_string()),
        }
    }

    #[test]
    fn routed_control_round_trips_postcard() {
        let control = sample_control();
        assert_eq!(control.validate(), Ok(()));

        let bytes = control.to_bytes().unwrap();
        assert_eq!(bytes[0], ROUTED_CONTROL_VERSION);
        let back = RoutedControlV1::from_bytes(&bytes).unwrap();
        assert_eq!(back, control);
    }

    #[test]
    fn routed_control_round_trips_with_grant_and_forwards() {
        let mut control = sample_control();
        control.grant = Some(SignedAdminGrant::authorize(sample_grant(), &operator(1)).unwrap());
        control.forwards.push(RoutedForward::new(
            peer("0.3.7", "mid-c"),
            SignedControl::authorize(
                node("mid-c"),
                &operator(4),
                12,
                2_000,
                ControlRequest::Query,
            )
            .unwrap(),
        ));
        assert_eq!(control.validate(), Ok(()));

        let bytes = control.to_bytes().unwrap();
        let back = RoutedControlV1::from_bytes(&bytes).unwrap();
        assert_eq!(back, control);
    }

    #[test]
    fn signed_routed_reply_round_trips_postcard() {
        let signed = SignedRoutedReply::authorize(sample_reply(), &operator(7)).unwrap();
        let bytes = signed.to_bytes().unwrap();
        assert_eq!(bytes[0], ROUTED_REPLY_VERSION);
        let back = SignedRoutedReply::from_bytes(&bytes).unwrap();
        assert_eq!(back, signed);
    }

    #[test]
    fn authorize_then_verify_round_trip() {
        let signed = SignedRoutedReply::authorize(sample_reply(), &operator(7)).unwrap();
        assert_eq!(signed.verify(&operator(7).public()), Ok(()));
    }

    #[test]
    fn routed_control_golden_field_order() {
        // Golden vector. Pins the frozen field order of `RoutedControlV1` and
        // its bounded forwards. The byte hash (not just the length) is pinned:
        // `target` and `requester` are both `PeerRef`, so swapping them keeps
        // the length and still round-trips, but changes these bytes. A
        // reordered, added, or removed field changes this hash, so the pinned
        // value must only change as part of a deliberate protocol version bump.
        let control = sample_control();
        let bytes = control.to_bytes().unwrap();
        assert_eq!(bytes.len(), 253);
        assert_eq!(
            blake3::hash(&bytes).to_hex().as_str(),
            "d491100d9e8461af0cd164df56cbb873be9f6973882ec5df12258768ee325ebf"
        );
    }

    #[test]
    fn routed_reply_signing_hash_is_stable() {
        // Golden vector. Pins the frozen field order of `RoutedReplyV1` and the
        // `routed-reply/v1` domain: a reordered, added, or removed field (or a
        // changed domain) changes this hash, so the pinned value must only
        // change as part of a deliberate protocol version bump.
        let signed = SignedRoutedReply::authorize(sample_reply(), &operator(7)).unwrap();
        let preimage = postcard::to_allocvec(&sample_reply()).unwrap();
        assert_eq!(preimage.len(), 41);
        assert_eq!(
            signed.signing_hash().to_hex(),
            "3d08ef811b22cf00827d8ab1d1b07f32921c2ef3b37fd277d726e5fe01c7437f"
        );
    }

    #[test]
    fn validate_rejects_bad_version() {
        let mut control = sample_control();
        control.version = ROUTED_CONTROL_VERSION + 1;
        assert_eq!(
            control.validate(),
            Err(RoutedError::UnsupportedVersion(ROUTED_CONTROL_VERSION + 1))
        );

        let mut bad_intent = sample_control();
        bad_intent.intent.version = CONTROL_FORMAT_VERSION + 1;
        assert_eq!(
            bad_intent.validate(),
            Err(RoutedError::UnsupportedVersion(CONTROL_FORMAT_VERSION + 1))
        );

        let mut bad_forward = sample_control();
        bad_forward.forwards[0].signed.version = CONTROL_FORMAT_VERSION + 1;
        assert_eq!(
            bad_forward.validate(),
            Err(RoutedError::UnsupportedVersion(CONTROL_FORMAT_VERSION + 1))
        );
    }

    #[test]
    fn validate_accepts_v3_intent_and_forward() {
        // A rolling-upgrade peer may still stamp v3: every pre-existing variant
        // is wire-compatible, so `validate` must accept it. The version byte is
        // inside the signed preimage, so re-sign after downgrading.
        let mut control = sample_control();
        control.intent.version = 3;
        control.intent.signature = operator(1).sign(control.intent.signing_hash().as_bytes());
        control.forwards[0].signed.version = 3;
        control.forwards[0].signed.signature =
            operator(1).sign(control.forwards[0].signed.signing_hash().as_bytes());
        assert_eq!(control.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_tampered_forward_request() {
        let mut control = sample_control();
        control.forwards[0].signed.request = ControlRequest::AdminQuery;
        assert_eq!(
            control.validate(),
            Err(RoutedError::ForwardRequestMismatch { index: 0 })
        );
    }

    #[test]
    fn validate_rejects_forward_hop_mismatch() {
        let mut control = sample_control();
        control.forwards[0].hop.node = "impostor".to_string();
        assert_eq!(
            control.validate(),
            Err(RoutedError::ForwardHopMismatch {
                index: 0,
                hop: "impostor".to_string(),
                origin: "node-d".to_string(),
            })
        );
    }

    #[test]
    fn validate_rejects_too_many_forwards() {
        let mut control = sample_control();
        let forward = control.forwards[0].clone();
        control.forwards = vec![forward; MAX_ROUTED_FORWARDS + 1];
        // Bypass the decode bound by assigning directly; `validate` must still
        // reject the over-long vector.
        assert_eq!(
            control.validate(),
            Err(RoutedError::TooManyForwards {
                len: MAX_ROUTED_FORWARDS + 1,
                max: MAX_ROUTED_FORWARDS,
            })
        );
    }

    #[test]
    fn oversized_forwards_rejected_on_decode_without_allocating() {
        // Hand-build a routed request: postcard struct encoding is the
        // concatenation of its fields' encodings, so append an oversize
        // `Vec<RoutedForward>` in place of `forwards`. The bounded deserializer
        // must reject it without materializing the entries.
        let control = sample_control();
        let oversized: Vec<RoutedForward> = std::iter::repeat_n(
            control.forwards[0].clone(),
            MAX_ROUTED_FORWARDS + 1,
        )
        .collect();

        let mut bytes = Vec::new();
        for field in [
            postcard::to_allocvec(&ROUTED_CONTROL_VERSION).unwrap(),
            postcard::to_allocvec(&control.target).unwrap(),
            postcard::to_allocvec(&control.requester).unwrap(),
            postcard::to_allocvec(&control.intent).unwrap(),
            postcard::to_allocvec(&control.grant).unwrap(),
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&postcard::to_allocvec(&oversized).unwrap());

        assert!(matches!(
            RoutedControlV1::from_bytes(&bytes),
            Err(RoutedError::Codec(_))
        ));
    }

    #[test]
    fn from_bytes_rejects_oversized_buffer_before_decode() {
        let oversize = vec![ROUTED_CONTROL_VERSION; crate::MAX_CONTROL_FRAME as usize + 1];
        assert_eq!(
            RoutedControlV1::from_bytes(&oversize),
            Err(RoutedError::FrameTooLarge {
                actual: crate::MAX_CONTROL_FRAME as usize + 1,
                max: crate::MAX_CONTROL_FRAME as usize,
            })
        );

        let oversize_reply = vec![ROUTED_REPLY_VERSION; crate::MAX_CONTROL_FRAME as usize + 1];
        assert_eq!(
            SignedRoutedReply::from_bytes(&oversize_reply),
            Err(RoutedError::FrameTooLarge {
                actual: crate::MAX_CONTROL_FRAME as usize + 1,
                max: crate::MAX_CONTROL_FRAME as usize,
            })
        );
    }

    #[test]
    fn from_bytes_rejects_trailing_garbage() {
        let mut bytes = sample_control().to_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            RoutedControlV1::from_bytes(&bytes),
            Err(RoutedError::TrailingBytes { n: 1 })
        );

        let mut reply_bytes = SignedRoutedReply::authorize(sample_reply(), &operator(7))
            .unwrap()
            .to_bytes()
            .unwrap();
        reply_bytes.push(0);
        assert_eq!(
            SignedRoutedReply::from_bytes(&reply_bytes),
            Err(RoutedError::TrailingBytes { n: 1 })
        );
    }

    #[test]
    fn from_bytes_rejects_empty_and_wrong_version() {
        assert_eq!(RoutedControlV1::from_bytes(&[]), Err(RoutedError::Empty));
        assert_eq!(
            SignedRoutedReply::from_bytes(&[]),
            Err(RoutedError::Empty)
        );

        let mut bytes = sample_control().to_bytes().unwrap();
        bytes[0] = ROUTED_CONTROL_VERSION + 1;
        assert_eq!(
            RoutedControlV1::from_bytes(&bytes),
            Err(RoutedError::UnsupportedVersion(ROUTED_CONTROL_VERSION + 1))
        );

        let mut reply_bytes = SignedRoutedReply::authorize(sample_reply(), &operator(7))
            .unwrap()
            .to_bytes()
            .unwrap();
        reply_bytes[0] = ROUTED_REPLY_VERSION + 1;
        assert_eq!(
            SignedRoutedReply::from_bytes(&reply_bytes),
            Err(RoutedError::UnsupportedVersion(ROUTED_REPLY_VERSION + 1))
        );
    }

    #[test]
    fn from_bytes_rejects_truncated_payloads() {
        // A frame cut short must fail with a codec error, never panic or be
        // silently accepted as a shorter-but-valid value.
        let control_bytes = sample_control().to_bytes().unwrap();
        assert!(matches!(
            RoutedControlV1::from_bytes(&control_bytes[..control_bytes.len() - 1]),
            Err(RoutedError::Codec(_))
        ));
        // Version byte only: the leading version passes the peek, but the body
        // is truncated.
        assert!(matches!(
            RoutedControlV1::from_bytes(&control_bytes[..1]),
            Err(RoutedError::Codec(_))
        ));

        let reply_bytes = SignedRoutedReply::authorize(sample_reply(), &operator(7))
            .unwrap()
            .to_bytes()
            .unwrap();
        assert!(matches!(
            SignedRoutedReply::from_bytes(&reply_bytes[..reply_bytes.len() - 1]),
            Err(RoutedError::Codec(_))
        ));
        assert!(matches!(
            SignedRoutedReply::from_bytes(&reply_bytes[..1]),
            Err(RoutedError::Codec(_))
        ));
    }

    #[test]
    fn reply_bytes_do_not_decode_as_routed_control() {
        // Both payloads share the same leading version byte
        // (`ROUTED_CONTROL_VERSION == ROUTED_REPLY_VERSION == 1`), so the
        // leading byte alone cannot tell them apart. Disambiguation must be by
        // full decode: the reply body does not parse as a `RoutedControlV1`
        // (P2 selects the type by `msg_type`/direction, not by this byte).
        let reply_bytes = SignedRoutedReply::authorize(sample_reply(), &operator(7))
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(reply_bytes[0], ROUTED_CONTROL_VERSION);
        assert!(matches!(
            RoutedControlV1::from_bytes(&reply_bytes),
            Err(RoutedError::Codec(_))
        ));
    }

    #[test]
    fn reply_signature_rejects_tampered_reply_to() {
        let mut signed = SignedRoutedReply::authorize(sample_reply(), &operator(7)).unwrap();
        signed.reply.reply_to = MsgId([0xcd; 16]);
        assert_eq!(
            signed.verify(&operator(7).public()),
            Err(RoutedError::InvalidSignature)
        );
    }

    #[test]
    fn reply_signature_rejects_tampered_requester() {
        let mut signed = SignedRoutedReply::authorize(sample_reply(), &operator(7)).unwrap();
        signed.reply.requester = peer("0.2", "attacker");
        assert_eq!(
            signed.verify(&operator(7).public()),
            Err(RoutedError::InvalidSignature)
        );
    }

    #[test]
    fn reply_signature_rejects_wrong_operator_key() {
        let signed = SignedRoutedReply::authorize(sample_reply(), &operator(7)).unwrap();
        // Signed by operator 7, verified against operator 8.
        assert_eq!(
            signed.verify(&operator(8).public()),
            Err(RoutedError::InvalidSignature)
        );
    }

    #[test]
    fn reply_signature_domain_is_distinct() {
        let reply = sample_reply();
        let preimage = postcard::to_allocvec(&reply).unwrap();

        let sign_under = |context: &str| {
            let mut hasher = blake3::Hasher::new_derive_key(context);
            hasher.update(&preimage);
            operator(7).sign(hasher.finalize().as_bytes())
        };

        // A signature produced under the direct-control domain must not verify
        // as a routed reply, and likewise for the admin-grant domain.
        for context in [CONTROL_CONTEXT, ADMIN_GRANT_CONTEXT] {
            let forged = SignedRoutedReply {
                reply: reply.clone(),
                signature: sign_under(context),
            };
            assert_eq!(
                forged.verify(&operator(7).public()),
                Err(RoutedError::InvalidSignature),
                "signature under {context} must not verify as a routed reply"
            );
        }
    }

    #[test]
    fn authorize_rejects_bad_reply_version() {
        let mut reply = sample_reply();
        reply.version = ROUTED_REPLY_VERSION + 1;
        assert_eq!(
            SignedRoutedReply::authorize(reply, &operator(7)),
            Err(RoutedError::UnsupportedVersion(ROUTED_REPLY_VERSION + 1))
        );
    }
}
