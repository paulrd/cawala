//! Message envelope: wire types, framing-agnostic encode/decode, and structural
//! validation.
//!
//! The envelope is positional (postcard) and its field order is frozen; adding
//! or reordering fields is a protocol break. Never treat a decoded envelope as
//! authenticated — see the crate docs for the trust boundary.

use std::fmt;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::route::HopChainError;
use crate::{MAX_HOPS, MAX_NODE_ID_LEN, MAX_PAYLOAD};
use proto::OctAddr;

/// Wire protocol version carried by every [`Envelope`].
pub const PROTOCOL_VERSION: u8 = 1;

/// Application-defined payload discriminator.
pub type MessageType = u16;

/// Ledger payloads (signed entries and related messages).
pub const MSG_LEDGER_V1: MessageType = 1;

/// Control payloads; reserved for M4.
pub const MSG_CONTROL_V1: MessageType = 2;

/// Stable identifier for a message, independent of any relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MsgId(pub [u8; 16]);

impl MsgId {
    /// Fixed wire length of a [`MsgId`] in bytes.
    pub const LEN: usize = 16;

    /// Wrap a fixed 16-byte identifier.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        MsgId(bytes)
    }

    /// The raw 16 bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase hex rendering (32 characters).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A peer endpoint: its hierarchical address and node identity string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerRef {
    pub addr: OctAddr,
    pub node: String,
}

/// One entry in an [`Envelope`]'s path: the address and node identity of a hop.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hop {
    pub addr: OctAddr,
    pub node: String,
}

/// A routable message envelope.
///
/// Field order is frozen: postcard is positional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u8,
    pub src: PeerRef,
    pub dst: OctAddr,
    pub msg_id: MsgId,
    pub msg_type: MessageType,
    /// Random, immutable; retries reuse it so receivers can de-duplicate.
    pub nonce: u64,
    /// Remaining authorized forwards.
    pub ttl: u8,
    /// Opaque payload, typed by `msg_type`.
    pub payload: Vec<u8>,
    /// Visited hops, starting with `src`.
    ///
    /// Deserialization is bounded to [`MAX_HOPS`] entries (see
    /// [`deserialize_hop_chain`]) so a hostile length cannot allocate an
    /// unbounded `Vec` before [`Envelope::validate`] runs.
    #[serde(deserialize_with = "deserialize_hop_chain")]
    pub hop_chain: Vec<Hop>,
}

impl Envelope {
    /// Build a fresh envelope: `version = PROTOCOL_VERSION`,
    /// `ttl = MAX_HOPS`, and `hop_chain = [src]`.
    pub fn new(
        src: PeerRef,
        dst: OctAddr,
        msg_id: MsgId,
        msg_type: MessageType,
        nonce: u64,
        payload: Vec<u8>,
    ) -> Self {
        let origin = Hop {
            addr: src.addr.clone(),
            node: src.node.clone(),
        };
        Envelope {
            version: PROTOCOL_VERSION,
            src,
            dst,
            msg_id,
            msg_type,
            nonce,
            ttl: MAX_HOPS as u8,
            payload,
            hop_chain: vec![origin],
        }
    }

    /// Structural validation only.
    ///
    /// Checks, in order: `src.node` and every `hop_chain[*].node` are at most
    /// [`MAX_NODE_ID_LEN`] bytes (rejected before anything is recorded or
    /// keyed on them, e.g. in [`crate::replay::SeenSet`]); `version ==
    /// PROTOCOL_VERSION`; `payload.len() <= MAX_PAYLOAD`; the hop chain is
    /// non-empty and starts at `src` (address and node); `hop_chain.len() <=
    /// MAX_HOPS`; `ttl <= MAX_HOPS`; and `hop_chain.len() + ttl <= MAX_HOPS + 1`
    /// (each hop consumes one TTL).
    ///
    /// This proves nothing about the sender: on-path shape is checked
    /// separately by [`crate::route::validate_hop_chain`], and even a valid
    /// chain can be forged by a relay.
    pub fn validate(&self) -> Result<(), MsgError> {
        if self.src.node.len() > MAX_NODE_ID_LEN {
            return Err(MsgError::NodeIdTooLong {
                len: self.src.node.len(),
                max: MAX_NODE_ID_LEN,
            });
        }
        for hop in &self.hop_chain {
            if hop.node.len() > MAX_NODE_ID_LEN {
                return Err(MsgError::NodeIdTooLong {
                    len: hop.node.len(),
                    max: MAX_NODE_ID_LEN,
                });
            }
        }
        if self.version != PROTOCOL_VERSION {
            return Err(MsgError::UnsupportedVersion(self.version));
        }
        if self.payload.len() > MAX_PAYLOAD {
            return Err(MsgError::PayloadTooLarge {
                actual: self.payload.len(),
                max: MAX_PAYLOAD,
            });
        }
        let origin = self
            .hop_chain
            .first()
            .ok_or(MsgError::HopChain(HopChainError::Empty))?;
        if origin.addr != self.src.addr {
            return Err(MsgError::HopChain(HopChainError::OriginMismatch {
                expected: self.src.addr.clone(),
                found: origin.addr.clone(),
            }));
        }
        if origin.node != self.src.node {
            return Err(MsgError::HopChain(HopChainError::OriginNodeMismatch {
                expected: self.src.node.clone(),
                found: origin.node.clone(),
            }));
        }
        if self.hop_chain.len() > MAX_HOPS {
            return Err(MsgError::HopChain(HopChainError::TooLong {
                len: self.hop_chain.len(),
                max: MAX_HOPS,
            }));
        }
        if self.ttl as usize > MAX_HOPS {
            return Err(MsgError::BadTtl { ttl: self.ttl });
        }
        if self.hop_chain.len() + self.ttl as usize > MAX_HOPS + 1 {
            return Err(MsgError::BadTtl { ttl: self.ttl });
        }
        Ok(())
    }

    /// Postcard-encode the envelope.
    pub fn encode(&self) -> Result<Vec<u8>, MsgError> {
        encode_postcard(self)
    }

    /// Postcard-decode an envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, MsgError> {
        decode_postcard(bytes)
    }
}

/// Delivery acknowledgement for a specific [`MsgId`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub msg_id: MsgId,
    pub status: AckStatus,
}

impl Ack {
    /// Human-readable status bucket: `"delivered"`, `"duplicate"`, or
    /// `"rejected"` (the specific [`RejectReason`] is not surfaced here).
    pub fn status_str(&self) -> &'static str {
        match self.status {
            AckStatus::Delivered => "delivered",
            AckStatus::Duplicate => "duplicate",
            AckStatus::Rejected(_) => "rejected",
        }
    }

    /// Postcard-encode the acknowledgement.
    pub fn encode(&self) -> Result<Vec<u8>, MsgError> {
        encode_postcard(self)
    }

    /// Postcard-decode an acknowledgement.
    pub fn decode(bytes: &[u8]) -> Result<Self, MsgError> {
        decode_postcard(bytes)
    }
}

/// Whether a message was delivered, seen before, or refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckStatus {
    Delivered,
    Duplicate,
    Rejected(RejectReason),
}

/// Why a message was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    BadVersion,
    BadPayload,
    BadHopChain,
    TtlExpired,
    NoRoute,
    NoAddress,
    NotNeighbor,
    Busy,
    Unreachable,
    Internal,
}

/// Errors raised by envelope validation and postcard codec operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MsgError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("payload is {actual} bytes, max {max}")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("node id is {len} bytes, max {max}")]
    NodeIdTooLong { len: usize, max: usize },
    #[error("ttl {ttl} is out of range")]
    BadTtl { ttl: u8 },
    #[error("hop chain: {0}")]
    HopChain(#[from] HopChainError),
    #[error("postcard encode/decode: {0}")]
    Codec(String),
}

/// Deserialize a hop chain with a hard cap of [`MAX_HOPS`] elements.
///
/// Postcard's `Vec` encoding is a varint length followed by the elements, so a
/// hostile length would otherwise allocate an unbounded `Vec` before
/// [`Envelope::validate`] can reject it. This visitor rejects an oversized
/// `size_hint` immediately and also counts elements, erroring as soon as the
/// cap is exceeded (covering formats whose `size_hint` is `None`).
fn deserialize_hop_chain<'de, D>(deserializer: D) -> Result<Vec<Hop>, D::Error>
where
    D: Deserializer<'de>,
{
    struct HopChainVisitor;

    impl<'de> Visitor<'de> for HopChainVisitor {
        type Value = Vec<Hop>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a hop chain of at most {MAX_HOPS} entries")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if let Some(hint) = seq.size_hint()
                && hint > MAX_HOPS
            {
                return Err(de::Error::invalid_length(hint, &self));
            }
            let cap = seq.size_hint().unwrap_or(0).min(MAX_HOPS);
            let mut hops = Vec::with_capacity(cap);
            while let Some(hop) = seq.next_element::<Hop>()? {
                if hops.len() >= MAX_HOPS {
                    return Err(de::Error::invalid_length(hops.len() + 1, &self));
                }
                hops.push(hop);
            }
            Ok(hops)
        }
    }

    deserializer.deserialize_seq(HopChainVisitor)
}

fn encode_postcard<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, MsgError> {
    postcard::to_allocvec(value).map_err(|err| MsgError::Codec(err.to_string()))
}

fn decode_postcard<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, MsgError> {
    postcard::from_bytes(bytes).map_err(|err| MsgError::Codec(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::append_hop;

    fn addr(s: &str) -> OctAddr {
        s.parse()
            .unwrap_or_else(|e| panic!("parse of {s:?} failed: {e}"))
    }

    fn peer(a: &str, node: &str) -> PeerRef {
        PeerRef {
            addr: addr(a),
            node: node.to_string(),
        }
    }

    #[test]
    fn envelope_roundtrip_preserves_all_fields() {
        // Root origin, deep leaf destination, empty payload, multi-hop chain.
        let src = peer("0", "root-node");
        let dst = addr("0.3.5.2");
        let msg_id = MsgId([0xab; 16]);
        let mut env = Envelope::new(
            src.clone(),
            dst.clone(),
            msg_id,
            MSG_LEDGER_V1,
            0xdead_beef,
            vec![],
        );
        append_hop(&mut env, &peer("0.3", "mid-a")).unwrap();
        append_hop(&mut env, &peer("0.3.5", "mid-b")).unwrap();
        append_hop(&mut env, &peer("0.3.5.2", "leaf-node")).unwrap();
        // Each appended hop consumes one TTL; keep the invariant valid.
        env.ttl -= 3;
        assert_eq!(env.hop_chain.len(), 4);
        env.validate().unwrap();

        let bytes = env.encode().unwrap();
        let back = Envelope::decode(&bytes).unwrap();
        assert_eq!(back, env);
        assert_eq!(back.version, PROTOCOL_VERSION);
        assert_eq!(back.src, src);
        assert_eq!(back.dst, dst);
        assert_eq!(back.msg_id, msg_id);
        assert_eq!(back.msg_type, MSG_LEDGER_V1);
        assert_eq!(back.nonce, 0xdead_beef);
        assert_eq!(back.ttl, MAX_HOPS as u8 - 3);
        assert!(back.payload.is_empty());
        assert_eq!(back.hop_chain.len(), 4);
    }

    #[test]
    fn envelope_rejects_bad_version_and_oversize_payload() {
        let mut env = Envelope::new(
            peer("0", "root"),
            addr("0.3"),
            MsgId([1; 16]),
            MSG_LEDGER_V1,
            1,
            vec![],
        );
        env.version = 2;
        assert_eq!(env.validate(), Err(MsgError::UnsupportedVersion(2)));

        env.version = PROTOCOL_VERSION;
        env.payload = vec![0u8; MAX_PAYLOAD + 1];
        assert!(matches!(
            env.validate(),
            Err(MsgError::PayloadTooLarge { actual, max })
                if actual == MAX_PAYLOAD + 1 && max == MAX_PAYLOAD
        ));
    }

    #[test]
    fn envelope_rejects_ttl_hop_invariant() {
        let mut env = Envelope::new(
            peer("0.1.2", "origin"),
            addr("0.4.5"),
            MsgId([2; 16]),
            MSG_LEDGER_V1,
            5,
            vec![],
        );
        // Fresh envelope: 1 hop + 32 ttl == MAX_HOPS + 1, valid.
        assert!(env.validate().is_ok());

        // TTL alone out of range.
        env.ttl = MAX_HOPS as u8 + 1;
        assert!(matches!(
            env.validate(),
            Err(MsgError::BadTtl { ttl }) if ttl == MAX_HOPS as u8 + 1
        ));

        // hopped + ttl over budget: ttl is in range but the sum exceeds it.
        env.ttl = MAX_HOPS as u8;
        append_hop(&mut env, &peer("0.1", "mid")).unwrap();
        assert!(matches!(
            env.validate(),
            Err(MsgError::BadTtl { ttl }) if ttl == MAX_HOPS as u8
        ));
    }

    #[test]
    fn envelope_rejects_origin_hop_mismatch() {
        let mut env = Envelope::new(
            peer("0.1.2", "origin"),
            addr("0.4.5"),
            MsgId([3; 16]),
            MSG_LEDGER_V1,
            1,
            vec![],
        );

        // Address mismatch.
        env.hop_chain[0].addr = addr("0.1");
        assert!(matches!(
            env.validate(),
            Err(MsgError::HopChain(HopChainError::OriginMismatch { .. }))
        ));

        // Node mismatches with the address matching: a dedicated diagnostic.
        env.hop_chain[0].addr = addr("0.1.2");
        env.hop_chain[0].node = "impostor".to_string();
        assert!(matches!(
            env.validate(),
            Err(MsgError::HopChain(HopChainError::OriginNodeMismatch {
                ref expected,
                ref found,
            })) if expected == "origin" && found == "impostor"
        ));

        // Empty hop chain.
        env.hop_chain.clear();
        assert!(matches!(
            env.validate(),
            Err(MsgError::HopChain(HopChainError::Empty))
        ));
    }

    #[test]
    fn msg_id_wire_is_fixed_16_bytes() {
        let id = MsgId([0xab; 16]);
        let bytes = postcard::to_allocvec(&id).unwrap();
        assert_eq!(bytes.len(), MsgId::LEN);
        assert_eq!(bytes, vec![0xab; 16]);
        let back: MsgId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, id);
        assert_eq!(MsgId::from_bytes([0xab; 16]), id);
        assert_eq!(id.as_bytes(), &[0xab; 16]);
        assert_eq!(id.to_hex(), "abababababababababababababababab");
    }

    #[test]
    fn ack_roundtrip_all_statuses() {
        for (status, expected) in [
            (AckStatus::Delivered, "delivered"),
            (AckStatus::Duplicate, "duplicate"),
            (AckStatus::Rejected(RejectReason::NoRoute), "rejected"),
            (AckStatus::Rejected(RejectReason::Busy), "rejected"),
        ] {
            let ack = Ack {
                msg_id: MsgId([4; 16]),
                status,
            };
            let bytes = ack.encode().unwrap();
            let back = Ack::decode(&bytes).unwrap();
            assert_eq!(back, ack);
            assert_eq!(back.status_str(), expected);
        }
    }

    #[test]
    fn envelope_rejects_long_origin_node_id() {
        let long = "a".repeat(MAX_NODE_ID_LEN + 1);
        let env = Envelope::new(
            peer("0.1.2", &long),
            addr("0.4.5"),
            MsgId([5; 16]),
            MSG_LEDGER_V1,
            1,
            vec![],
        );
        assert_eq!(
            env.validate(),
            Err(MsgError::NodeIdTooLong {
                len: MAX_NODE_ID_LEN + 1,
                max: MAX_NODE_ID_LEN,
            })
        );
    }

    #[test]
    fn envelope_rejects_long_hop_node_id() {
        let mut env = Envelope::new(
            peer("0.1.2", "origin"),
            addr("0.4.5"),
            MsgId([6; 16]),
            MSG_LEDGER_V1,
            1,
            vec![],
        );
        env.hop_chain.push(Hop {
            addr: addr("0.1"),
            node: "b".repeat(MAX_NODE_ID_LEN + 1),
        });
        assert_eq!(
            env.validate(),
            Err(MsgError::NodeIdTooLong {
                len: MAX_NODE_ID_LEN + 1,
                max: MAX_NODE_ID_LEN,
            })
        );
    }

    #[test]
    fn envelope_rejects_oversized_hop_chain_on_decode() {
        // Hand-build an envelope: postcard struct encoding is the concatenation
        // of its fields' encodings, so append an oversize `Vec<Hop>` in place of
        // `hop_chain`. The bounded deserializer must reject it without
        // materializing the entries.
        let src = peer("0", "root");
        let dst = addr("0");
        let msg_id = MsgId([0; 16]);
        let msg_type: MessageType = MSG_LEDGER_V1;
        let nonce = 0u64;
        let ttl = MAX_HOPS as u8;
        let payload: Vec<u8> = vec![];

        let oversized: Vec<Hop> = (0..MAX_HOPS + 1)
            .map(|_| Hop {
                addr: addr("0"),
                node: String::new(),
            })
            .collect();

        let mut bytes = Vec::new();
        for field in [
            postcard::to_allocvec(&PROTOCOL_VERSION).unwrap(),
            postcard::to_allocvec(&src).unwrap(),
            postcard::to_allocvec(&dst).unwrap(),
            postcard::to_allocvec(&msg_id).unwrap(),
            postcard::to_allocvec(&msg_type).unwrap(),
            postcard::to_allocvec(&nonce).unwrap(),
            postcard::to_allocvec(&ttl).unwrap(),
            postcard::to_allocvec(&payload).unwrap(),
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&postcard::to_allocvec(&oversized).unwrap());

        assert!(matches!(Envelope::decode(&bytes), Err(MsgError::Codec(_))));
    }
}
