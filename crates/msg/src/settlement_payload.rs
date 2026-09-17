//! Versioned cross-subtree settlement payloads carried inside
//! `MSG_SETTLE_V1` envelopes (P3).
//!
//! The [`crate::Envelope`] `msg_type` field ([`crate::MSG_SETTLE_V1`]) is the
//! **outer** discriminator. The types here define the versioned body, turning
//! the opaque [`Envelope::payload`](crate::Envelope) into a typed node-to-node
//! settlement message.
//!
//! # Frozen wire format
//!
//! Variant order and every struct field order are positional postcard: adding,
//! removing, or reordering anything is a protocol break. Never reorder fields
//! or enum variants.
//!
//! # Versioning
//!
//! Variants do not carry a version field. The version lives at the codec layer:
//! [`SettlePayloadV3::to_bytes`] prefixes [`SETTLE_PAYLOAD_VERSION`] to the
//! postcard body, and [`SettlePayloadV3::from_bytes`] rejects any other version.
//!
//! The v1 result shape carried a bare `terminal_entry`; v2 replaces it with a
//! full [`EntryProofV1`]. v3 adds an optional [`EntryProofV1`] to each carried
//! [`SettleHopV3`] (so the origin can audit any intermediate hop) and echoes the
//! intermediate hops between origin and terminal in
//! [`SettleOutcomeV3::Applied::intermediates`]. Because the hop and outcome
//! shapes change, the whole payload is re-versioned: v1 and v2 frames are
//! refused with [`SettlePayloadError::UnsupportedVersion`].
//!
//! # Bounds
//!
//! [`SettleForwardV3::hops`] and the applied outcome's `intermediates` are
//! wire-controlled `Vec`s; decoding does **not** truncate them (silently
//! dropping hops would be a correctness bug). Callers bound them at the use
//! site: every forward checks [`SettleForwardV3::hops_within_bound`], and the
//! settlement origin rejects a `Result` whose
//! [`SettleResultV3::intermediates_within_bound`] is false before auditing it
//! (it returns `true` for `Rejected`, which carries no intermediates). Likewise,
//! an [`EntryProofV1`]'s audit path is only bounded by
//! [`EntryProofV1::validate`], which callers must run after decoding.

use serde::{Deserialize, Serialize};

use cawala_ledger::{
    AuthRef, EntryInclusionProof, Hash, NodeId, PaymentOrder, PeerKeys, PeerRole, SignedCommitment,
    SignedEntry,
};
use proto::OctAddr;

use crate::envelope::MsgError;
use crate::ledger_payload::OrderRejectV1;

/// Wire version of the settlement payload, prefixed to every
/// [`SettlePayloadV3::to_bytes`] encoding.
///
/// Bumped 2 -> 3: each carried hop now optionally carries an [`EntryProofV1`],
/// and an applied outcome echoes the intermediate hops between origin and
/// terminal. A v1 or v2 frame is rejected with
/// [`SettlePayloadError::UnsupportedVersion`].
pub const SETTLE_PAYLOAD_VERSION: u8 = 3;

/// Maximum number of carried settlement hops a caller should accept. This is a
/// use-site bound (the v1 route is depth-1: `Ascend`/`Lca`/`Descend`); decoding
/// never truncates.
pub const MAX_SETTLE_HOPS: usize = 3;

/// A versioned settlement payload.
///
/// Variant order is frozen: postcard encodes the discriminant positionally
/// (`Forward = 0`, `Result = 1`).
// `SettleForwardV3` carries a full signed-entry vector, so the `Forward`
// variant is much larger than `Result`. Boxing would change the in-memory type;
// the wire layout is frozen, so keep the declared shape.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlePayloadV3 {
    /// Origin -> next hop: the order, the payer's authorisation and keys, the
    /// payer/payee addresses, and the evidence hops gathered so far.
    Forward(SettleForwardV3),
    /// Terminal -> origin: the outcome of the cascade.
    Result(SettleResultV3),
}

impl SettlePayloadV3 {
    /// Encode with the [`SETTLE_PAYLOAD_VERSION`] prefix followed by the
    /// postcard body.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SettlePayloadError> {
        let body = postcard::to_allocvec(self).map_err(codec_error)?;
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(SETTLE_PAYLOAD_VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a version-prefixed payload.
    ///
    /// Rejects an empty buffer, an unsupported version (including v1 and v2), a
    /// truncated or invalid body, and any trailing bytes after the body. Never
    /// panics on arbitrary input.
    ///
    /// Decoding does not validate an [`EntryProofV1`]; callers must invoke
    /// [`EntryProofV1::validate`] before trusting a `Result` payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SettlePayloadError> {
        let (version, body) = bytes
            .split_first()
            .ok_or_else(|| SettlePayloadError::Codec("empty settle payload".to_string()))?;
        if *version != SETTLE_PAYLOAD_VERSION {
            return Err(SettlePayloadError::UnsupportedVersion(*version));
        }
        match postcard::take_from_bytes::<Self>(body) {
            Ok((value, [])) => Ok(value),
            Ok((_, rest)) => Err(SettlePayloadError::Codec(format!(
                "{} trailing byte(s) after settle payload",
                rest.len()
            ))),
            Err(err) => Err(codec_error(err)),
        }
    }
}

/// Origin -> next hop: a cross-subtree settlement cascade in flight.
///
/// Field order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleForwardV3 {
    /// The payer's operator-signed order.
    pub order: PaymentOrder,
    /// The operator binding that travels with the order.
    pub auth: AuthRef,
    /// The payer's public keys, validated against `auth`/`order.from`.
    pub payer_key: PeerKeys,
    /// The payer's user address (used to derive each hop's role).
    pub payer_addr: OctAddr,
    /// The payee's user address (used to derive each hop's role).
    pub payee_addr: OctAddr,
    /// Hops signed so far, in cascade order (evidence, not route input).
    pub hops: Vec<SettleHopV3>,
}

impl SettleForwardV3 {
    /// Whether [`hops`](Self::hops) fits the [`MAX_SETTLE_HOPS`] bound.
    /// Decoding never truncates; callers decide what to do on overflow.
    pub fn hops_within_bound(&self) -> bool {
        self.hops.len() <= MAX_SETTLE_HOPS
    }
}

/// One signed settlement hop carried as evidence.
///
/// The route (`role`/`first`/`second`) is always re-derived per hop from
/// `classify_hop` + the node record, never read from this entry.
///
/// `proof` is the signer's own [`EntryProofV1`] for its hop, when it was able to
/// build one. The origin's own seeded hop carries `None` (it has nothing to
/// prove to itself); every subsequent hop is expected to carry `Some` so the
/// origin can audit it.
///
/// Field order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleHopV3 {
    /// The asserting node address.
    pub signer_addr: OctAddr,
    /// The hop's signed ledger entry.
    pub entry: SignedEntry,
    /// The hop's inclusion proof, when the signer built one.
    pub proof: Option<EntryProofV1>,
}

/// Terminal -> origin: the cascade outcome.
///
/// Field order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleResultV3 {
    /// The cascade's shared `payment_id`.
    pub payment_id: Hash,
    /// Whether the cascade applied or was rejected.
    pub outcome: SettleOutcomeV3,
}

impl SettleResultV3 {
    /// Whether the echoed `intermediates` fit the depth-1 bound.
    ///
    /// A depth-1 route has exactly three signers, leaving at most one hop
    /// strictly between origin and terminal
    /// ([`MAX_SETTLE_HOPS`].saturating_sub(2)). Decoding never truncates; the
    /// origin decides what to do on overflow (a `Rejected` outcome carries no
    /// intermediates, so it is always within bound).
    pub fn intermediates_within_bound(&self) -> bool {
        match &self.outcome {
            SettleOutcomeV3::Applied { intermediates, .. } => {
                intermediates.len() <= MAX_SETTLE_HOPS.saturating_sub(2)
            }
            SettleOutcomeV3::Rejected { .. } => true,
        }
    }
}

/// Terminal status of a settlement cascade.
///
/// Variant order is frozen.
// `Applied` carries a full signed entry plus proof; the wire layout is frozen,
// so keep the declared shape rather than boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettleOutcomeV3 {
    /// The terminal hop applied, carrying verifiable inclusion evidence.
    Applied {
        /// The terminal hop's ledger `seq`.
        terminal_seq: u64,
        /// The terminal hop's entry hash.
        terminal_hash: Hash,
        /// The terminal leaf's signed entry, signer row, commitment, and
        /// inclusion proof.
        proof: EntryProofV1,
        /// The hops strictly between the origin and the terminal, in cascade
        /// order (the origin's own seeded hop and the terminal's own hop are
        /// excluded). Each normally carries its own inclusion proof.
        intermediates: Vec<SettleHopV3>,
    },
    /// The cascade was refused; see [`SettleRejectV1`].
    Rejected {
        /// The refusal reason.
        reason: SettleRejectV1,
    },
}

/// Evidence that an applied hop is committed by a leaf's log.
///
/// Shared by the node-to-node result path ([`SettleOutcomeV3::Applied`]) and the
/// leaf-to-browser result path
/// ([`crate::ledger_payload::OrderResultV3::proof`]).
///
/// Field order is frozen.
///
/// # Validation
///
/// Decoding does **not** bound [`inclusion`](Self::inclusion)'s audit path
/// (postcard has no `Vec` limit) and does not check the proof against
/// [`commitment`](Self::commitment). Callers **must** invoke
/// [`EntryProofV1::validate`] before verifying [`inclusion`](Self::inclusion)
/// with [`cawala_ledger::verify_entry_inclusion`], mirroring how callers bound
/// `BalanceAttestation::proof` at the use site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryProofV1 {
    /// The applied hop.
    pub entry: SignedEntry,
    /// The signer's self row: role [`PeerRole::Node`], with a ledger key.
    pub signer: PeerKeys,
    /// The asserted signer address; must equal the hop's `signer_addr`.
    pub leaf_addr: OctAddr,
    /// The commitment the inclusion proof is against; its `entry_count` must
    /// equal [`inclusion.tree_size`](EntryInclusionProof::tree_size).
    pub commitment: SignedCommitment,
    /// The RFC 6962 inclusion proof for [`entry`](Self::entry).
    pub inclusion: EntryInclusionProof,
}

impl EntryProofV1 {
    /// Structurally validate the proof envelope before cryptographic
    /// verification.
    ///
    /// Enforces, in order:
    ///
    /// - `inclusion.proof.len() <=` [`cawala_ledger::MAX_ENTRY_PROOF`];
    /// - `inclusion.index < inclusion.tree_size`;
    /// - `inclusion.tree_size == commitment.entry_count`;
    /// - `entry.entry.seq < inclusion.tree_size`;
    /// - `signer.role ==` [`PeerRole::Node`] and a ledger key is present.
    ///
    /// Purely structural: it does not verify signatures, the commitment, or the
    /// Merkle path. [`cawala_ledger::verify_entry_inclusion`] checks the latter
    /// against `commitment.entry_root`.
    pub fn validate(&self) -> Result<(), MsgError> {
        if self.inclusion.proof.len() > cawala_ledger::MAX_ENTRY_PROOF {
            return Err(MsgError::InvalidEntryProof("audit path too long"));
        }
        if self.inclusion.index >= self.inclusion.tree_size {
            return Err(MsgError::InvalidEntryProof("index is not below tree_size"));
        }
        if u64::from(self.inclusion.tree_size) != self.commitment.commitment.entry_count {
            return Err(MsgError::InvalidEntryProof(
                "tree_size does not match commitment entry_count",
            ));
        }
        if self.entry.entry.seq >= u64::from(self.inclusion.tree_size) {
            return Err(MsgError::InvalidEntryProof(
                "entry seq is not below tree_size",
            ));
        }
        if self.signer.role != PeerRole::Node || self.signer.ledger.is_none() {
            return Err(MsgError::InvalidEntryProof(
                "signer is not a ledger-bearing node",
            ));
        }
        Ok(())
    }
}

/// Why a settlement cascade was rejected.
///
/// Variant order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettleRejectV1 {
    /// The origin/payer leaf refused the order.
    PayerRejected,
    /// An intermediate (or terminal) hop refused; names the node and reason.
    IntermediateRejected {
        /// The node whose hop was refused.
        at: NodeId,
        /// The per-hop refusal reason.
        reason: OrderRejectV1,
    },
    /// The route is deeper than the v1 depth-1 scope.
    RouteTooDeep,
    /// The message was structurally malformed (bad route, missing child, ...).
    Malformed,
}

/// Errors raised by settlement-payload postcard framing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettlePayloadError {
    /// The first byte is not [`SETTLE_PAYLOAD_VERSION`].
    #[error("unsupported settle payload version {0}")]
    UnsupportedVersion(u8),
    /// The postcard body could not be encoded or decoded.
    #[error("postcard encode/decode: {0}")]
    Codec(String),
}

fn codec_error(err: postcard::Error) -> SettlePayloadError {
    SettlePayloadError::Codec(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{
        Amount, Commitment, Entry, EntryBody, EntryInclusionProof, LedgerSecretKey,
        OperatorSecretKey, PeerRole, SignedCommitment, SignedEntry,
    };

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn addr(s: &str) -> OctAddr {
        s.parse().expect("valid octal address")
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn ledger(seed: u8) -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([seed; 32])
    }

    fn auth() -> AuthRef {
        let op = operator(0x33);
        AuthRef {
            operator: op.public(),
            nonce: 5,
            order_hash: Hash::from_bytes([0x44; 32]),
            signature: op.sign(b"order"),
        }
    }

    fn order() -> PaymentOrder {
        PaymentOrder {
            from: node("alice"),
            to: node("bob"),
            amount: Amount::new(7),
            nonce: 5,
            expiry: 100,
        }
    }

    fn payer_key() -> PeerKeys {
        PeerKeys {
            node_id: node("alice"),
            operator: operator(0x33).public(),
            ledger: None,
            role: PeerRole::User,
        }
    }

    fn signed_entry() -> SignedEntry {
        let key = ledger(0x11);
        let entry = Entry {
            ledger_id: key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 1234,
            body: EntryBody::Issue {
                child: node("child"),
                amount: Amount::new(7),
            },
            postings: vec![],
            auth: None,
        };
        SignedEntry::sign(entry, &key).unwrap()
    }

    fn hop(i: usize) -> SettleHopV3 {
        SettleHopV3 {
            signer_addr: addr(&format!("0.{}", i + 1)),
            entry: signed_entry(),
            proof: None,
        }
    }

    fn full_forward(hops: usize) -> SettleForwardV3 {
        SettleForwardV3 {
            order: order(),
            auth: auth(),
            payer_key: payer_key(),
            payer_addr: addr("0.1.3"),
            payee_addr: addr("0.2.4"),
            hops: (0..hops).map(hop).collect(),
        }
    }

    fn sample_commitment() -> SignedCommitment {
        let key = ledger(0x11);
        SignedCommitment {
            commitment: Commitment {
                ledger_id: key.public(),
                ledger_pubkey: key.public(),
                height: 1,
                entry_count: 1,
                entry_root: Hash::from_bytes([0x66; 32]),
                state_root: Hash::from_bytes([0x77; 32]),
                prev_commitment_hash: Hash::from_bytes([0x88; 32]),
                issued_at: 1234,
            },
            signature: key.sign(b"commitment"),
        }
    }

    /// A structurally valid [`EntryProofV1`] for [`signed_entry`] (seq 0,
    /// `tree_size` 1, `entry_count` 1).
    fn sample_entry_proof() -> EntryProofV1 {
        EntryProofV1 {
            entry: signed_entry(),
            signer: PeerKeys {
                node_id: node("leaf"),
                operator: operator(0x33).public(),
                ledger: Some(ledger(0x11).public()),
                role: PeerRole::Node,
            },
            leaf_addr: addr("0.1.3"),
            commitment: sample_commitment(),
            inclusion: EntryInclusionProof {
                index: 0,
                tree_size: 1,
                proof: vec![],
            },
        }
    }

    fn applied(intermediates: Vec<SettleHopV3>) -> SettleOutcomeV3 {
        SettleOutcomeV3::Applied {
            terminal_seq: 9,
            terminal_hash: Hash::from_bytes([0x55; 32]),
            proof: sample_entry_proof(),
            intermediates,
        }
    }

    fn result(outcome: SettleOutcomeV3) -> SettleResultV3 {
        SettleResultV3 {
            payment_id: Hash::from_bytes([0x22; 32]),
            outcome,
        }
    }

    fn round_trip(payload: &SettlePayloadV3) {
        let bytes = payload.to_bytes().unwrap();
        assert_eq!(bytes[0], SETTLE_PAYLOAD_VERSION);
        let back = SettlePayloadV3::from_bytes(&bytes).unwrap();
        assert_eq!(&back, payload);
    }

    #[test]
    fn round_trip_every_variant() {
        round_trip(&SettlePayloadV3::Forward(full_forward(0)));
        round_trip(&SettlePayloadV3::Forward(full_forward(2)));
        // Every hop built by `hop` carries `proof: None`; also round-trip a hop
        // that carries a real proof.
        let mut forward = full_forward(2);
        forward.hops[0].proof = Some(sample_entry_proof());
        round_trip(&SettlePayloadV3::Forward(forward));
        round_trip(&SettlePayloadV3::Result(result(applied(vec![]))));
        round_trip(&SettlePayloadV3::Result(result(applied(vec![hop(0)]))));
        let mut proven = hop(0);
        proven.proof = Some(sample_entry_proof());
        round_trip(&SettlePayloadV3::Result(result(applied(vec![proven]))));
        for reason in [
            SettleRejectV1::PayerRejected,
            SettleRejectV1::IntermediateRejected {
                at: node("leaf"),
                reason: OrderRejectV1::InsufficientBalance,
            },
            SettleRejectV1::RouteTooDeep,
            SettleRejectV1::Malformed,
        ] {
            round_trip(&SettlePayloadV3::Result(result(
                SettleOutcomeV3::Rejected { reason },
            )));
        }
    }

    #[test]
    fn enum_discriminant_order_is_frozen() {
        let cases = [
            (SettlePayloadV3::Forward(full_forward(0)), 0u8),
            (
                SettlePayloadV3::Result(result(applied(vec![]))),
                1,
            ),
        ];
        for (payload, expected) in cases {
            let bytes = payload.to_bytes().unwrap();
            assert_eq!(
                bytes[1], expected,
                "variant discriminant for {payload:?} changed"
            );
        }

        // Outcome discriminants are frozen too.
        let applied_bytes = postcard::to_allocvec(&applied(vec![])).unwrap();
        assert_eq!(applied_bytes[0], 0);
        let rejected = postcard::to_allocvec(&SettleOutcomeV3::Rejected {
            reason: SettleRejectV1::Malformed,
        })
        .unwrap();
        assert_eq!(rejected[0], 1);

        // Reject discriminants are frozen.
        for (reason, expected) in [
            (SettleRejectV1::PayerRejected, 0u8),
            (
                SettleRejectV1::IntermediateRejected {
                    at: node("n"),
                    reason: OrderRejectV1::Internal,
                },
                1,
            ),
            (SettleRejectV1::RouteTooDeep, 2),
            (SettleRejectV1::Malformed, 3),
        ] {
            let bytes = postcard::to_allocvec(&reason).unwrap();
            assert_eq!(bytes[0], expected, "reject discriminant changed");
        }
    }

    #[test]
    fn malformed_and_truncated_bytes_are_errors() {
        // Empty buffer.
        assert!(SettlePayloadV3::from_bytes(&[]).is_err());

        // Version byte only, no body.
        assert!(SettlePayloadV3::from_bytes(&[SETTLE_PAYLOAD_VERSION]).is_err());

        // A v1 frame is rejected cleanly.
        assert_eq!(
            SettlePayloadV3::from_bytes(&[1]),
            Err(SettlePayloadError::UnsupportedVersion(1))
        );

        // A v2 frame is rejected cleanly.
        assert_eq!(
            SettlePayloadV3::from_bytes(&[2]),
            Err(SettlePayloadError::UnsupportedVersion(2))
        );

        // A future version is rejected cleanly.
        assert_eq!(
            SettlePayloadV3::from_bytes(&[SETTLE_PAYLOAD_VERSION + 1]),
            Err(SettlePayloadError::UnsupportedVersion(4))
        );

        // Every strict prefix of a valid payload fails to decode; no panic.
        let valid = SettlePayloadV3::Forward(full_forward(3)).to_bytes().unwrap();
        for cut in 0..valid.len() {
            assert!(
                SettlePayloadV3::from_bytes(&valid[..cut]).is_err(),
                "prefix of length {cut} unexpectedly decoded"
            );
        }

        // Trailing garbage after an otherwise valid body is rejected.
        let mut trailing = valid.clone();
        trailing.push(0x00);
        assert!(SettlePayloadV3::from_bytes(&trailing).is_err());

        // Arbitrary bytes never panic.
        for byte in 0u8..=255 {
            let _ = SettlePayloadV3::from_bytes(&[byte, byte, byte, byte]);
        }
    }

    #[test]
    fn entry_proof_validate_enforces_bounds_and_shape() {
        let proof = sample_entry_proof();
        assert!(proof.validate().is_ok());

        // Over-long audit path.
        let mut long = proof.clone();
        long.inclusion.proof = vec![Hash::ZERO; cawala_ledger::MAX_ENTRY_PROOF + 1];
        assert!(long.validate().is_err());

        // `index >= tree_size`.
        let mut bad_index = proof.clone();
        bad_index.inclusion.index = 1;
        assert!(bad_index.validate().is_err());

        // `tree_size != commitment.entry_count`.
        let mut bad_size = proof.clone();
        bad_size.inclusion.tree_size = 2;
        assert!(bad_size.validate().is_err());

        // `entry.seq >= tree_size`.
        let seq_key = ledger(0x77);
        let seq_entry = Entry {
            ledger_id: seq_key.public(),
            seq: 1,
            height: 1,
            prev_hash: Hash::ZERO,
            issued_at: 1234,
            body: EntryBody::Issue {
                child: node("child"),
                amount: Amount::new(7),
            },
            postings: vec![],
            auth: None,
        };
        let mut bad_seq = proof.clone();
        bad_seq.entry = SignedEntry::sign(seq_entry, &seq_key).unwrap();
        assert!(bad_seq.validate().is_err());

        // Signer must be a ledger-bearing node.
        let mut bad_role = proof.clone();
        bad_role.signer.role = PeerRole::User;
        assert!(bad_role.validate().is_err());

        let mut no_ledger = proof.clone();
        no_ledger.signer.ledger = None;
        assert!(no_ledger.validate().is_err());
    }

    #[test]
    fn over_bound_hops_are_rejected_at_the_use_site() {
        assert!(full_forward(0).hops_within_bound());
        assert!(full_forward(MAX_SETTLE_HOPS).hops_within_bound());
        assert!(!full_forward(MAX_SETTLE_HOPS + 1).hops_within_bound());
    }

    #[test]
    fn intermediates_bound_is_enforced_at_the_use_site() {
        assert!(result(applied(vec![])).intermediates_within_bound());
        assert!(result(applied(vec![hop(0)])).intermediates_within_bound());
        assert!(
            !result(applied((0..MAX_SETTLE_HOPS).map(hop).collect()))
                .intermediates_within_bound()
        );
        // A rejection carries no intermediates and is always within bound.
        assert!(
            result(SettleOutcomeV3::Rejected {
                reason: SettleRejectV1::Malformed,
            })
            .intermediates_within_bound()
        );
    }
}
