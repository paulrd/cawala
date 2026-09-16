//! Stranded-claim evidence bundles.
//!
//! A node that left (or was stranded by) its parent may still carry a non-zero
//! [`AccountRef::Parent`] asset on its own ledger — value its old parent
//! prefunded it with that the new parent would have to mirror to keep netting
//! sound. This module produces and verifies an out-of-band, **self-attested**
//! evidence bundle for that magnitude, so a prospective new parent's operator
//! can review it before deciding (discretionarily) to `prefund`/`fund` the
//! child.
//!
//! A [`StrandedClaimBundle`] carries:
//!
//! - a dated [`StrandedClaim`], self-signed by the child's operator
//!   ([`SignedStrandedClaim`]), naming the child and (optionally) the parent it
//!   detached from;
//! - the child's operator and ledger public keys;
//! - a signed ledger [`SignedCommitment`] head, optionally with an ancestor
//!   `chain` back to genesis;
//! - the self-asserted `parent_balance` and, when non-zero (or whenever
//!   carried), a Merkle [`StateProof`] binding that balance to the head
//!   commitment's `state_root`;
//! - an optional [`PeerKeys`] row for the failed edge, carried as review
//!   context only.
//!
//! [`StrandedClaimBundle::verify_bundle`] proves the internal consistency of
//! that bundle. It is deliberately **not** an authority token: it is review
//! evidence, and the new parent's operator decides on it.
//!
//! # What the bundle does not prove
//!
//! The child authors its own ledger, so the amount is **self-attested**.
//! Verification does **not** prove:
//!
//! - that the carried `edge` [`PeerKeys`] row is genuine (it is unverified
//!   evidence, not authority);
//! - that the old parent ever owed, prefunded, or agreed to the amount (the
//!   balance is simply what the child's own ledger says);
//! - that the committed head is the child's latest state (the child can present
//!   any signed head it holds, and commitments are not equivocation-proof from
//!   a single chain).
//!
//! Callers must treat a verified bundle as input to a discretionary funding
//! decision, never as a guarantee of value or of the child's honesty.
//!
//! # Purity
//!
//! Like the rest of this crate, this module is pure, synchronous, and
//! wasm-safe: no clock, no RNG, no I/O. Signing keys are supplied as raw bytes
//! and the caller passes `now` explicitly (the crate never reads a clock).

use serde::{Deserialize, Serialize};

use cawala_ledger::{
    AccountRef, Hash, LedgerError, LedgerPubKey, NodeId, OperatorPubKey, OperatorSecretKey,
    PeerKeys, Signature, SignedCommitment, commitment_hash, verify_chain, verify_state_inclusion,
};

/// Wire format version for both [`StrandedClaim`] and [`StrandedClaimBundle`].
///
/// The claim and the bundle it sits in share one version line: a reordered,
/// added, or removed field (or a changed signing domain) is a protocol break
/// and must bump this constant.
pub const STRANDED_CLAIM_VERSION: u8 = 1;

/// BLAKE3 derive-key context for the stranded-claim signing hash.
///
/// Distinct from [`CONTROL_CONTEXT`](crate::CONTROL_CONTEXT),
/// [`ADMIN_GRANT_CONTEXT`](crate::ADMIN_GRANT_CONTEXT), and
/// [`ROUTED_REPLY_CONTEXT`](crate::ROUTED_REPLY_CONTEXT), so a claim signature
/// can never be replayed as (or confused with) any other control signature.
pub const STRANDED_CLAIM_CONTEXT: &str = "cawala-control/stranded-claim/v1";

/// Clock-skew tolerance, in seconds, for a claim's `issued_at` at review time.
///
/// The reviewer's clock may trail the presenter's (unsynchronised clocks, a
/// bundle delivered promptly after signing), so [`StrandedClaimBundle::verify_bundle`]
/// accepts a claim dated up to `now + STRANDED_CLAIM_CLOCK_SKEW_SECS` rather
/// than rejecting any future date outright. This is a plausibility bound, not
/// an expiry: a claim carries no validity window.
pub const STRANDED_CLAIM_CLOCK_SKEW_SECS: u64 = 300;

/// A node's dated, self-authored statement that it is stranded.
///
/// Field order is frozen: the signing preimage is the postcard encoding of the
/// claim in declaration order. The claim carries **no** authority, expiry,
/// nonce, or grace semantics — it is a dated assertion for an operator to
/// review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrandedClaim {
    /// Wire format version ([`STRANDED_CLAIM_VERSION`]).
    pub version: u8,
    /// The stranded node making the claim.
    pub node: NodeId,
    /// The parent the node detached from, if it named one.
    pub detached_from: Option<NodeId>,
    /// Unix seconds when the node authored the claim.
    pub issued_at: u64,
}

/// A [`StrandedClaim`] self-signed by the stranded node's operator key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStrandedClaim {
    /// The claim being attested.
    pub claim: StrandedClaim,
    /// The node operator's signature over
    /// [`SignedStrandedClaim::signing_hash`].
    pub signature: Signature,
}

impl SignedStrandedClaim {
    /// Build a signed claim, validating its version and signing with the
    /// stranded node's operator secret key.
    ///
    /// The caller supplies the key; this crate never generates key material.
    pub fn authorize(
        claim: StrandedClaim,
        node_operator: &OperatorSecretKey,
    ) -> Result<Self, ClaimError> {
        if claim.version != STRANDED_CLAIM_VERSION {
            return Err(ClaimError::UnsupportedVersion(claim.version));
        }
        let mut signed = SignedStrandedClaim {
            claim,
            // Placeholder; replaced below. The signing hash does not cover the
            // signature field.
            signature: Signature::from_bytes(&[0u8; Signature::LENGTH]),
        };
        signed.signature = node_operator.sign(signed.signing_hash().as_bytes());
        Ok(signed)
    }

    /// The signed preimage hash: BLAKE3
    /// derive-key([`STRANDED_CLAIM_CONTEXT`]) over the canonical postcard
    /// encoding of the whole [`StrandedClaim`].
    ///
    /// Unlike [`SignedControl::signing_hash`](crate::SignedControl::signing_hash),
    /// no field is excluded: the claim is signed in full, and its declaration
    /// order is frozen.
    pub fn signing_hash(&self) -> Hash {
        // The derived serde impls used here never fail to encode; the only
        // fallible component would be a custom serializer, and none are
        // involved.
        let bytes = postcard::to_allocvec(&self.claim)
            .expect("stranded claim is always postcard-encodable");
        let mut hasher = blake3::Hasher::new_derive_key(STRANDED_CLAIM_CONTEXT);
        hasher.update(&bytes);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Verify [`Self::signature`] under `node_operator` over
    /// [`Self::signing_hash`].
    ///
    /// The claim's version is checked first; a mismatch (or any tampering, or a
    /// signature produced under a different domain) fails as
    /// [`ClaimError::InvalidClaimSignature`].
    pub fn verify(&self, node_operator: &OperatorPubKey) -> Result<(), ClaimError> {
        if self.claim.version != STRANDED_CLAIM_VERSION {
            return Err(ClaimError::UnsupportedVersion(self.claim.version));
        }
        node_operator
            .verify(self.signing_hash().as_bytes(), &self.signature)
            .map_err(|_| ClaimError::InvalidClaimSignature)
    }
}

/// A Merkle inclusion proof for one account leaf in a commitment's state tree.
///
/// Mirrors the arguments of
/// [`verify_state_inclusion`]: `index` is the leaf position in
/// [`cawala_ledger::merkle::state_root`] order, `tree_size` the number of state
/// leaves, and `proof` the RFC 6962 audit path from the leaf toward the root.
/// It is carried inside [`StrandedClaimBundle`] and bound to the head
/// commitment's signed `state_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProof {
    /// Leaf position of the account in the state tree.
    pub index: usize,
    /// Number of state leaves the proof is for.
    pub tree_size: usize,
    /// RFC 6962 audit path, ordered from the leaf toward the root.
    pub proof: Vec<Hash>,
}

/// A self-attested evidence bundle for a stranded node's `Parent` asset.
///
/// Field order is frozen (postcard is positional). The bundle is serialized as
/// JSON for the operator-facing CLI and as postcard for compact storage; see
/// [`StrandedClaimBundle::to_bytes`] / [`StrandedClaimBundle::from_bytes`].
///
/// See the [module docs](self) for what verification does and does **not**
/// prove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrandedClaimBundle {
    /// Wire format version ([`STRANDED_CLAIM_VERSION`]).
    pub version: u8,
    /// The child presenting the evidence.
    pub child: NodeId,
    /// The child's operator key; must equal the key named by `child`.
    pub child_operator: OperatorPubKey,
    /// The ledger key that signs the child's entries and commitments.
    pub child_ledger: LedgerPubKey,
    /// The child's self-signed stranded claim.
    pub claim: SignedStrandedClaim,
    /// The failed edge's registry row, if carried. Review context only: it is
    /// never verified and never authoritative.
    pub edge: Option<PeerKeys>,
    /// The child's signed commitment head the evidence is against.
    pub commitment: SignedCommitment,
    /// The `Parent` balance the child attests at `commitment`. Self-attested.
    pub parent_balance: i128,
    /// Inclusion proof binding `parent_balance` to `commitment.state_root`.
    ///
    /// Required when `parent_balance != 0`; optional when it is zero. When
    /// present it is **always** verified — including at a zero balance — so no
    /// caller can read "a proof is present" as "a proof was checked" without
    /// the check having happened.
    pub parent_proof: Option<StateProof>,
    /// Optional ancestor commitments, in ascending height order, **not**
    /// including `commitment`. When non-empty the last element must link to
    /// `commitment` by `prev_commitment_hash`, and a chain that reaches genesis
    /// is verified with the ledger's genesis-anchored
    /// [`verify_chain`].
    pub chain: Vec<SignedCommitment>,
}

impl StrandedClaimBundle {
    /// Verify the bundle's internal consistency against an explicit `now`.
    ///
    /// Steps, in order:
    /// 1. `version == `[`STRANDED_CLAIM_VERSION`];
    /// 2. `child_operator` equals the operator key named by `child` (the
    ///    node-id == operator-key invariant);
    /// 3. `claim` verifies under `child_operator`, `claim.claim.node == child`,
    ///    and `claim.claim.issued_at <= now + `[`STRANDED_CLAIM_CLOCK_SKEW_SECS`]
    ///    (a small skew-tolerant plausibility bound, not an expiry);
    /// 4. `commitment` verifies under `child_ledger`;
    /// 5. when `chain` is non-empty, prev-link/height continuity ending at
    ///    `commitment`, using genesis-anchored [`verify_chain`] when the chain
    ///    reaches genesis;
    /// 6. `parent_balance` is non-negative (a `Balances` balance can never be
    ///    negative);
    /// 7. when `parent_balance != 0`, `parent_proof` is present and
    ///    [`verify_state_inclusion`] binds [`AccountRef::Parent`] with that
    ///    balance to `commitment.state_root`; when the balance is zero the
    ///    proof is optional, but if it is present it is still verified.
    ///
    /// On success the display-only [`VerifiedClaim`] is returned. This is
    /// review evidence only; see the [module docs](self) for what is not
    /// proven.
    pub fn verify_bundle(&self, now: u64) -> Result<VerifiedClaim, ClaimError> {
        // 1. Bundle version.
        if self.version != STRANDED_CLAIM_VERSION {
            return Err(ClaimError::UnsupportedVersion(self.version));
        }

        // 2. The node id and the operator key are one key.
        if operator_named_by(&self.child)? != self.child_operator {
            return Err(ClaimError::ChildOperatorMismatch);
        }

        // 3. The claim is self-signed by that operator, names this child, and is
        //    dated plausibly.
        self.claim.verify(&self.child_operator)?;
        if self.claim.claim.node != self.child {
            return Err(ClaimError::ClaimNodeMismatch);
        }
        if self.claim.claim.issued_at > now.saturating_add(STRANDED_CLAIM_CLOCK_SKEW_SECS) {
            return Err(ClaimError::ClaimIssuedInFuture {
                issued_at: self.claim.claim.issued_at,
                now,
            });
        }

        // 4. The head commitment is signed by the child's ledger key.
        self.commitment
            .verify(&self.child_ledger)
            .map_err(|_| ClaimError::InvalidCommitmentSignature)?;

        // 5. Optional ancestor chain, ending at the head.
        verify_chain_continuity(&self.chain, &self.commitment, &self.child_ledger)?;

        // 6. A `Balances` balance can never be negative, so a negative
        //    attested amount is implausible.
        if self.parent_balance < 0 {
            return Err(ClaimError::NegativeParentBalance(self.parent_balance));
        }

        // 7. Verify the Parent balance proof whenever it is present (so a
        //    present proof is always a checked proof), and require it to be
        //    present when the balance is non-zero.
        match self.parent_proof.as_ref() {
            Some(proof) => {
                if !verify_state_inclusion(
                    &AccountRef::Parent,
                    self.parent_balance,
                    proof.index,
                    proof.tree_size,
                    &proof.proof,
                    &self.commitment.commitment.state_root,
                ) {
                    return Err(ClaimError::InvalidParentProof);
                }
            }
            None if self.parent_balance != 0 => {
                return Err(ClaimError::MissingParentProof);
            }
            None => {}
        }

        Ok(VerifiedClaim {
            child: self.child.clone(),
            child_operator: self.child_operator,
            detached_from: self.claim.claim.detached_from.clone(),
            issued_at: self.claim.claim.issued_at,
            parent_balance: self.parent_balance,
            commitment_height: self.commitment.commitment.height,
        })
    }

    /// Postcard-encode the bundle.
    ///
    /// Unlike the control frame types this is an out-of-band artifact, so no
    /// [`MAX_CONTROL_FRAME`](crate::MAX_CONTROL_FRAME) cap is applied; a
    /// supplied `chain` may legitimately be long.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ClaimError> {
        postcard::to_allocvec(self).map_err(codec_error)
    }

    /// Postcard-decode a bundle.
    ///
    /// Rejects truncated/invalid bodies and any trailing bytes after the body.
    /// Decoding does not verify anything; callers must invoke
    /// [`StrandedClaimBundle::verify_bundle`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClaimError> {
        match postcard::take_from_bytes::<Self>(bytes) {
            Ok((value, [])) => Ok(value),
            Ok((_, rest)) => Err(ClaimError::Codec(format!(
                "{} trailing byte(s) after stranded claim bundle",
                rest.len()
            ))),
            Err(err) => Err(codec_error(err)),
        }
    }
}

/// The display-only result of a successful
/// [`StrandedClaimBundle::verify_bundle`].
///
/// Every field is copied from the verified bundle for an operator-facing
/// report; none of them is an obligation, an authority token, or a guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaim {
    /// The child that presented the evidence.
    pub child: NodeId,
    /// The child's operator key (bound to `child` by the node-id == key rule).
    pub child_operator: OperatorPubKey,
    /// The parent the claim says the child detached from, if named.
    pub detached_from: Option<NodeId>,
    /// Unix seconds when the claim was issued.
    pub issued_at: u64,
    /// The self-attested `Parent` balance.
    pub parent_balance: i128,
    /// Height of the verified commitment head.
    pub commitment_height: u64,
}

/// Derive the operator public key from a node id string.
///
/// Node ids and operator keys are the same Ed25519 key, so a canonical node id
/// is the lowercase hex encoding of the key. This reuses the control crate's
/// existing hex key parser ([`crate::invite::parse_operator_hex`]).
///
/// # Assumption: child ids are canonical hex
///
/// A live node's id is always the canonical `Display` form of its iroh
/// `PublicKey`, which is `data_encoding::HEXLOWER` (64 lowercase hex
/// characters); the transport's `EndpointId` `FromStr` is broader and also
/// accepts z-base-32, but that is for wire ids, not for the `child` named in a
/// bundle. A bundle child therefore **must** be canonical hex: anything that
/// is not exactly 64 hex characters (e.g. a z-base-32 spelling of the same
/// key) fails closed as [`ClaimError::ChildOperatorMismatch`] rather than being
/// silently coerced to a key.
fn operator_named_by(node: &NodeId) -> Result<OperatorPubKey, ClaimError> {
    crate::invite::parse_operator_hex(node.as_str()).ok_or(ClaimError::ChildOperatorMismatch)
}

/// Verify an optional ancestor chain and its link to the bundle head.
///
/// `chain` is in ascending height order and does not include `head`. Every
/// element is verified under `ledger`; when the chain reaches genesis
/// (`chain[0].prev_commitment_hash == Hash::ZERO`) it is verified with the
/// ledger's genesis-anchored [`verify_chain`] over `chain + head`. Otherwise
/// the same prev-link/height rules are applied manually from the first element
/// to `head`.
fn verify_chain_continuity(
    chain: &[SignedCommitment],
    head: &SignedCommitment,
    ledger: &LedgerPubKey,
) -> Result<(), ClaimError> {
    if chain.is_empty() {
        return Ok(());
    }

    for element in chain {
        element.verify(ledger).map_err(chain_error)?;
        if element.commitment.height != element.commitment.entry_count {
            return Err(ClaimError::BrokenChain);
        }
    }

    if chain[0].commitment.prev_commitment_hash == Hash::ZERO {
        // Genesis-anchored: the crate's `verify_chain` enforces the anchor,
        // height ordering, prev hashes, and the link into `head`.
        let mut full = chain.to_vec();
        full.push(head.clone());
        verify_chain(&full, ledger).map_err(chain_error)?;
        return Ok(());
    }

    let mut prev = &chain[0];
    for current in &chain[1..] {
        if current.commitment.height <= prev.commitment.height
            || current.commitment.prev_commitment_hash != commitment_hash(&prev.commitment)
        {
            return Err(ClaimError::BrokenChain);
        }
        prev = current;
    }
    if head.commitment.height <= prev.commitment.height
        || head.commitment.prev_commitment_hash != commitment_hash(&prev.commitment)
    {
        return Err(ClaimError::BrokenChain);
    }
    Ok(())
}

/// Map a ledger error from chain verification onto the claim error surface.
///
/// A signature/identity failure is attributable to the commitment key; any
/// other failure (height or prev-link) is a broken chain.
fn chain_error(err: LedgerError) -> ClaimError {
    match err {
        LedgerError::LedgerMismatch | LedgerError::InvalidSignature => {
            ClaimError::InvalidCommitmentSignature
        }
        _ => ClaimError::BrokenChain,
    }
}

fn codec_error(err: postcard::Error) -> ClaimError {
    ClaimError::Codec(err.to_string())
}

/// Errors raised by stranded-claim verification and codec operations.
///
/// A dedicated enum (rather than new variants on
/// [`ControlError`](crate::ControlError)) keeps the existing control error
/// surface unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
    /// The version is not [`STRANDED_CLAIM_VERSION`].
    #[error("unsupported stranded claim version {0}")]
    UnsupportedVersion(u8),
    /// `child_operator` is not the operator key named by `child`.
    #[error("child operator key does not match the node id")]
    ChildOperatorMismatch,
    /// The signed claim names a different node than the bundle's `child`.
    #[error("claim node does not match the bundle child")]
    ClaimNodeMismatch,
    /// The claim's operator signature does not verify.
    #[error("invalid stranded claim signature")]
    InvalidClaimSignature,
    /// The commitment does not verify under the child ledger key.
    #[error("invalid commitment signature under the child ledger key")]
    InvalidCommitmentSignature,
    /// The supplied ancestor chain is not continuous into the head commitment.
    #[error("broken commitment chain")]
    BrokenChain,
    /// A non-zero `parent_balance` carried no inclusion proof.
    #[error("non-zero parent balance requires a state proof")]
    MissingParentProof,
    /// The `parent_balance` inclusion proof did not verify.
    #[error("invalid parent balance state proof")]
    InvalidParentProof,
    /// `parent_balance` is negative, which no honest ledger state can produce.
    #[error("negative parent balance {0} is not a plausible ledger state")]
    NegativeParentBalance(i128),
    /// The claim is dated beyond the caller-supplied `now` plus the
    /// [`STRANDED_CLAIM_CLOCK_SKEW_SECS`] tolerance.
    #[error(
        "claim issued at {issued_at} is after now {now} (skew tolerance {STRANDED_CLAIM_CLOCK_SKEW_SECS}s)"
    )]
    ClaimIssuedInFuture {
        /// Unix seconds the claim says it was issued.
        issued_at: u64,
        /// Unix seconds the caller supplied as the current time.
        now: u64,
    },
    /// Canonical postcard encoding/decoding failed.
    #[error("postcard encode/decode: {0}")]
    Codec(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    use cawala_ledger::{
        Balances, Commitment, LedgerSecretKey, PeerRole, Posting, SignedAmount, merkle,
    };

    use crate::CONTROL_CONTEXT;

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn ledger(seed: u8) -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([seed; 32])
    }

    /// The canonical node id for an operator key (the node-id == key identity).
    fn child_id(op: &OperatorSecretKey) -> NodeId {
        NodeId::from(op.public().to_string())
    }

    /// z-base-32 alphabet iroh uses for the non-canonical wire spelling of an
    /// `EndpointId` (see `iroh_base::key::Z_BASE_32`).
    const Z_BASE_32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

    /// Minimal MSB-first z-base-32 encoder, used only to prove that the
    /// broader wire spelling is rejected for bundle children.
    fn z_base_32_encode(bytes: &[u8]) -> String {
        let mut out = String::new();
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &byte in bytes {
            acc = (acc << 8) | byte as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(Z_BASE_32[((acc >> bits) & 0x1f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(Z_BASE_32[((acc << (5 - bits)) & 0x1f) as usize] as char);
        }
        out
    }

    /// A real balances tree whose `Parent` account holds `amount`, mirrored by
    /// one child liability (the balanced-`Transfer` shape a prefund produces).
    fn balances_with_parent(amount: i64) -> Balances {
        let mut balances = Balances::new_root();
        let leaf = node("leaf");
        balances.open_account(&leaf).unwrap();
        balances
            .apply(&[
                Posting {
                    account: AccountRef::Parent,
                    delta: SignedAmount::new(amount),
                },
                Posting {
                    account: AccountRef::Child(leaf),
                    delta: SignedAmount::new(amount),
                },
            ])
            .unwrap();
        balances
    }

    fn signed_commitment(
        key: &LedgerSecretKey,
        height: u64,
        entry_root_byte: u8,
        state_root: Hash,
        prev: Hash,
    ) -> SignedCommitment {
        let commitment = Commitment {
            ledger_id: key.public(),
            ledger_pubkey: key.public(),
            height,
            entry_count: height,
            entry_root: Hash::from_bytes([entry_root_byte; 32]),
            state_root,
            prev_commitment_hash: prev,
            issued_at: height,
        };
        SignedCommitment::sign(commitment, key).unwrap()
    }

    fn sample_claim() -> StrandedClaim {
        StrandedClaim {
            version: STRANDED_CLAIM_VERSION,
            node: child_id(&operator(1)),
            detached_from: Some(node("old-parent")),
            issued_at: 1_000,
        }
    }

    /// A fully valid bundle: a real `Parent == 100` proof, a genesis-anchored
    /// two-element ancestor chain, and a detached-from edge row.
    fn sample_bundle() -> StrandedClaimBundle {
        let child_op = operator(1);
        let child = child_id(&child_op);
        let ledger_key = ledger(9);

        let balances = balances_with_parent(100);
        let (index, proof) = merkle::state_inclusion_proof(&balances, &AccountRef::Parent).unwrap();
        let tree_size = balances.accounts().count();
        let real_state_root = merkle::state_root(&balances);

        let genesis = signed_commitment(&ledger_key, 1, 1, Hash::from_bytes([2u8; 32]), Hash::ZERO);
        let mid = signed_commitment(
            &ledger_key,
            2,
            3,
            Hash::from_bytes([4u8; 32]),
            commitment_hash(&genesis.commitment),
        );
        let head = signed_commitment(
            &ledger_key,
            3,
            5,
            real_state_root,
            commitment_hash(&mid.commitment),
        );

        StrandedClaimBundle {
            version: STRANDED_CLAIM_VERSION,
            child,
            child_operator: child_op.public(),
            child_ledger: ledger_key.public(),
            claim: SignedStrandedClaim::authorize(sample_claim(), &child_op).unwrap(),
            edge: Some(PeerKeys {
                node_id: node("old-parent"),
                operator: operator(2).public(),
                ledger: Some(ledger(7).public()),
                role: PeerRole::Node,
            }),
            commitment: head,
            parent_balance: 100,
            parent_proof: Some(StateProof {
                index,
                tree_size,
                proof,
            }),
            chain: vec![genesis, mid],
        }
    }

    #[test]
    fn bundle_round_trips_postcard_and_json() {
        let bundle = sample_bundle();

        let bytes = bundle.to_bytes().unwrap();
        assert_eq!(StrandedClaimBundle::from_bytes(&bytes).unwrap(), bundle);

        let json = serde_json::to_string(&bundle).unwrap();
        let back: StrandedClaimBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bundle);
    }

    #[test]
    fn bundle_field_order_is_frozen() {
        // The postcard encoding must be exactly the concatenation of the fields
        // in declaration order. This pins the frozen field order: a reordered,
        // added, or removed field changes these bytes, so the vector must only
        // change as part of a deliberate protocol version bump.
        let bundle = sample_bundle();
        let mut expected = Vec::new();
        for part in [
            postcard::to_allocvec(&bundle.version).unwrap(),
            postcard::to_allocvec(&bundle.child).unwrap(),
            postcard::to_allocvec(&bundle.child_operator).unwrap(),
            postcard::to_allocvec(&bundle.child_ledger).unwrap(),
            postcard::to_allocvec(&bundle.claim).unwrap(),
            postcard::to_allocvec(&bundle.edge).unwrap(),
            postcard::to_allocvec(&bundle.commitment).unwrap(),
            postcard::to_allocvec(&bundle.parent_balance).unwrap(),
            postcard::to_allocvec(&bundle.parent_proof).unwrap(),
            postcard::to_allocvec(&bundle.chain).unwrap(),
        ] {
            expected.extend_from_slice(&part);
        }

        let bytes = bundle.to_bytes().unwrap();
        assert_eq!(bytes.len(), expected.len());
        assert_eq!(bytes, expected);
        assert_eq!(bytes[0], STRANDED_CLAIM_VERSION);
        // Golden vector over the frozen field order. The bundle carries
        // deterministic Ed25519 signatures, so this is stable.
        assert_eq!(
            blake3::hash(&bytes).to_hex().as_str(),
            "7c81d56f6feb63f5554b84348f123034add415aca5d9648beb0a5755beaa5e6d"
        );
    }

    #[test]
    fn happy_path_verifies_and_reports() {
        let bundle = sample_bundle();
        let verified = bundle.verify_bundle(2_000).unwrap();
        assert_eq!(verified.child, bundle.child);
        assert_eq!(verified.child_operator, bundle.child_operator);
        assert_eq!(verified.detached_from, Some(node("old-parent")));
        assert_eq!(verified.issued_at, 1_000);
        assert_eq!(verified.parent_balance, 100);
        assert_eq!(verified.commitment_height, 3);
    }

    #[test]
    fn tampered_claim_rejected() {
        let mut bundle = sample_bundle();
        bundle.claim.claim.issued_at += 1;
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::InvalidClaimSignature)
        );
    }

    #[test]
    fn claim_beyond_clock_skew_rejected() {
        let bundle = sample_bundle();
        // `issued_at == 1_000`; the tolerance is 300s, so a reviewer clock at
        // or below 699 is too far behind and rejects.
        assert_eq!(
            bundle.verify_bundle(699),
            Err(ClaimError::ClaimIssuedInFuture {
                issued_at: 1_000,
                now: 699,
            })
        );
        // Exactly at the tolerance edge is accepted (1000 <= 700 + 300).
        assert!(bundle.verify_bundle(700).is_ok());
    }

    #[test]
    fn issued_at_equals_now_verifies() {
        let bundle = sample_bundle();
        assert_eq!(bundle.claim.claim.issued_at, 1_000);
        assert!(bundle.verify_bundle(1_000).is_ok());
    }

    #[test]
    fn wrong_signing_domain_rejected() {
        // A signature over the same claim but under the direct-control domain
        // must not verify as a stranded claim.
        let claim = sample_claim();
        let preimage = postcard::to_allocvec(&claim).unwrap();
        let mut hasher = blake3::Hasher::new_derive_key(CONTROL_CONTEXT);
        hasher.update(&preimage);
        let forged = SignedStrandedClaim {
            claim,
            signature: operator(1).sign(hasher.finalize().as_bytes()),
        };
        assert_eq!(
            forged.verify(&operator(1).public()),
            Err(ClaimError::InvalidClaimSignature)
        );
    }

    #[test]
    fn wrong_child_operator_binding_rejected() {
        let mut bundle = sample_bundle();
        // `child` still names operator 1, but the bundle claims operator 2.
        bundle.child_operator = operator(2).public();
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::ChildOperatorMismatch)
        );
    }

    #[test]
    fn base32_child_id_fails_closed() {
        let op = operator(1);
        let hex_id = child_id(&op);
        // The canonical hex id derives the operator key.
        assert_eq!(operator_named_by(&hex_id).unwrap(), op.public());

        // The same key spelled in the transport's broader z-base-32 encoding is
        // not a canonical bundle child and must fail closed.
        let base32_id = NodeId::from(z_base_32_encode(&op.public().to_bytes()));
        assert_ne!(base32_id.as_str(), hex_id.as_str());
        assert_ne!(base32_id.as_str().len(), hex_id.as_str().len());
        assert_eq!(
            operator_named_by(&base32_id),
            Err(ClaimError::ChildOperatorMismatch)
        );

        // And through the public bundle surface: a base32 child fails closed.
        let mut bundle = sample_bundle();
        bundle.child = base32_id;
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::ChildOperatorMismatch)
        );
    }

    #[test]
    fn claim_node_mismatch_rejected() {
        let mut bundle = sample_bundle();
        // Re-sign a claim for a different node so only the binding fails.
        let mut claim = sample_claim();
        claim.node = node("someone-else");
        bundle.claim = SignedStrandedClaim::authorize(claim, &operator(1)).unwrap();
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::ClaimNodeMismatch)
        );
    }

    #[test]
    fn commitment_signed_by_wrong_ledger_key_rejected() {
        let mut bundle = sample_bundle();
        let wrong = ledger(8);
        let commitment = bundle.commitment.commitment.clone();
        let rebuilt = Commitment {
            ledger_id: wrong.public(),
            ledger_pubkey: wrong.public(),
            ..commitment
        };
        bundle.commitment = SignedCommitment::sign(rebuilt, &wrong).unwrap();
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::InvalidCommitmentSignature)
        );
    }

    #[test]
    fn broken_chain_continuity_rejected() {
        let mut bundle = sample_bundle();
        // Re-link the mid commitment to a wrong (but re-signed) prev hash so
        // the chain, not the signature, is what fails.
        let mid = bundle.chain[1].commitment.clone();
        let rebuilt = Commitment {
            prev_commitment_hash: Hash::from_bytes([0xaa; 32]),
            ..mid
        };
        bundle.chain[1] = SignedCommitment::sign(rebuilt, &ledger(9)).unwrap();
        assert_eq!(bundle.verify_bundle(2_000), Err(ClaimError::BrokenChain));
    }

    #[test]
    fn non_genesis_suffix_chain_verifies() {
        // A chain that does not reach genesis (its first element has a non-zero
        // prev hash) still verifies by the manual continuity branch. The head
        // keeps the real state root, so the Parent proof still binds.
        let mut bundle = sample_bundle();
        let key = ledger(9);
        let real_state_root = bundle.commitment.commitment.state_root;

        let pre = signed_commitment(
            &key,
            5,
            11,
            Hash::from_bytes([0x21; 32]),
            Hash::from_bytes([0xaa; 32]),
        );
        let mid = signed_commitment(
            &key,
            6,
            12,
            Hash::from_bytes([0x22; 32]),
            commitment_hash(&pre.commitment),
        );
        let head = signed_commitment(
            &key,
            7,
            13,
            real_state_root,
            commitment_hash(&mid.commitment),
        );

        bundle.chain = vec![pre, mid];
        bundle.commitment = head;

        let verified = bundle.verify_bundle(2_000).unwrap();
        assert_eq!(verified.commitment_height, 7);
        assert_eq!(verified.parent_balance, 100);
    }

    #[test]
    fn edge_none_still_verifies() {
        // `edge` is unverified review context; absent is fine.
        let mut bundle = sample_bundle();
        bundle.edge = None;
        assert!(bundle.verify_bundle(2_000).is_ok());
    }

    #[test]
    fn non_zero_balance_without_proof_rejected() {
        let mut bundle = sample_bundle();
        bundle.parent_proof = None;
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::MissingParentProof)
        );
    }

    #[test]
    fn valid_parent_proof_passes_and_tampered_fails() {
        // The happy-path bundle's proof is a real `verify_state_inclusion`
        // proof for the Parent leaf.
        let bundle = sample_bundle();
        let verified = bundle.verify_bundle(2_000).unwrap();
        assert_eq!(verified.parent_balance, 100);

        let mut tampered = sample_bundle();
        let proof = tampered.parent_proof.as_mut().unwrap();
        proof.proof[0] = Hash::from_bytes([0xbb; 32]);
        assert_eq!(
            tampered.verify_bundle(2_000),
            Err(ClaimError::InvalidParentProof)
        );

        // Tampering the claimed balance (leaving the proof for 100) also fails.
        let mut wrong_balance = sample_bundle();
        wrong_balance.parent_balance = 101;
        assert_eq!(
            wrong_balance.verify_bundle(2_000),
            Err(ClaimError::InvalidParentProof)
        );
    }

    #[test]
    fn zero_parent_balance_proof_is_optional() {
        let mut bundle = sample_bundle();
        bundle.parent_balance = 0;
        bundle.parent_proof = None;
        let verified = bundle.verify_bundle(2_000).unwrap();
        assert_eq!(verified.parent_balance, 0);
    }

    #[test]
    fn zero_balance_with_present_invalid_proof_rejected() {
        // A proof present at a zero balance must still be checked: presenting
        // the Parent==100 proof while asserting a zero balance fails.
        let mut bundle = sample_bundle();
        bundle.parent_balance = 0;
        assert!(bundle.parent_proof.is_some());
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::InvalidParentProof)
        );

        // Also tamper the present proof explicitly.
        let mut tampered = sample_bundle();
        tampered.parent_balance = 0;
        tampered.parent_proof.as_mut().unwrap().proof[0] = Hash::from_bytes([0xcc; 32]);
        assert_eq!(
            tampered.verify_bundle(2_000),
            Err(ClaimError::InvalidParentProof)
        );
    }

    #[test]
    fn negative_parent_balance_rejected() {
        let mut bundle = sample_bundle();
        bundle.parent_balance = -1;
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::NegativeParentBalance(-1))
        );
    }

    #[test]
    fn unsupported_versions_rejected() {
        let mut bundle = sample_bundle();
        bundle.version = STRANDED_CLAIM_VERSION + 1;
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::UnsupportedVersion(STRANDED_CLAIM_VERSION + 1))
        );

        // The claim's own version is checked before its signature.
        let mut bundle = sample_bundle();
        bundle.claim.claim.version = STRANDED_CLAIM_VERSION + 1;
        assert_eq!(
            bundle.verify_bundle(2_000),
            Err(ClaimError::UnsupportedVersion(STRANDED_CLAIM_VERSION + 1))
        );
    }

    #[test]
    fn authorize_rejects_bad_claim_version() {
        let mut claim = sample_claim();
        claim.version = STRANDED_CLAIM_VERSION + 1;
        assert_eq!(
            SignedStrandedClaim::authorize(claim, &operator(1)),
            Err(ClaimError::UnsupportedVersion(STRANDED_CLAIM_VERSION + 1))
        );
    }

    #[test]
    fn from_bytes_rejects_trailing_garbage_and_truncation() {
        let bundle = sample_bundle();
        let mut bytes = bundle.to_bytes().unwrap();
        bytes.push(0);
        assert!(matches!(
            StrandedClaimBundle::from_bytes(&bytes),
            Err(ClaimError::Codec(_))
        ));

        let bytes = bundle.to_bytes().unwrap();
        assert!(matches!(
            StrandedClaimBundle::from_bytes(&bytes[..bytes.len() - 1]),
            Err(ClaimError::Codec(_))
        ));
    }

    #[test]
    fn signing_hash_is_stable() {
        // Golden vector. Pins the frozen claim field order and the
        // `stranded-claim/v1` domain: a reordered, added, or removed field (or a
        // changed domain) changes this hash, so the pinned value must only
        // change as part of a deliberate protocol version bump.
        let signed = SignedStrandedClaim::authorize(sample_claim(), &operator(1)).unwrap();
        assert_eq!(
            signed.signing_hash().to_hex(),
            "98cbdc9e16f72f826fe263fcfe0d73cb00b647e0f26e1263f4641a9c59269cd0"
        );
    }

    #[test]
    fn balances_amount_is_non_degenerate() {
        // Guards the sample: the Parent leaf really is non-zero, so the proof
        // test above is meaningful.
        let balances = balances_with_parent(100);
        assert_eq!(balances.balance(&AccountRef::Parent), 100);
        assert_eq!(balances.balance(&AccountRef::Child(node("leaf"))), 100);
        assert_eq!(balances.accounts().count(), 2);
    }
}
