//! Versioned ledger payloads carried inside `MSG_LEDGER_V1` envelopes.
//!
//! The [`crate::Envelope`] `msg_type` field ([`crate::MSG_LEDGER_V1`]) is the
//! **outer** discriminator: it says "this is a ledger payload". The types here
//! define the v1 body, turning the otherwise opaque
//! [`Envelope::payload`](crate::Envelope) into a typed message for the
//! browser <-> leaf ledger protocol.
//!
//! # Frozen wire format
//!
//! Variant order and every struct field order are positional postcard: adding,
//! removing, or reordering anything is a protocol break. Never reorder fields
//! or enum variants.
//!
//! # Versioning decision
//!
//! [`LedgerPayloadV1`] does **not** carry a version field or variant, so the
//! specified payload shape is exactly preserved. The version lives at the codec
//! layer instead: [`LedgerPayloadV1::to_bytes`] prefixes
//! [`LEDGER_PAYLOAD_VERSION`] to the postcard body, and
//! [`LedgerPayloadV1::from_bytes`] rejects any other version. This mirrors
//! [`cawala_ledger::Entry::canonical_bytes`], which prefixes
//! `ENTRY_FORMAT_VERSION`. A future `LedgerPayloadV2` bumps the prefix byte.
//!
//! # Bounds
//!
//! [`BalanceReceiptV1::history`] is a wire-controlled `Vec`; decoding does
//! **not** truncate it (silently dropping notices would be a correctness bug).
//! Callers use [`BalanceReceiptV1::history_within_bound`] /
//! [`MAX_RECEIPT_HISTORY`] to reject an over-long receipt at the use site.

use serde::{Deserialize, Serialize};

use cawala_ledger::{
    Amount, AuthRef, BalanceAttestation, Hash, HopRole, LedgerPubKey, NodeId, PaymentOrder,
    SignedCommitment,
};
use proto::OctAddr;

use crate::MsgId;
use crate::settlement_payload::EntryProofV1;

/// Wire version of the ledger payload, prefixed to every
/// [`LedgerPayloadV1::to_bytes`] encoding.
pub const LEDGER_PAYLOAD_VERSION: u8 = 1;

/// Wire version of the v2 ledger payload, prefixed to every
/// [`LedgerPayloadV2::to_bytes`] encoding.
///
/// A separate constant (and prefix byte) keeps the frozen v1 bytes and
/// [`LEDGER_PAYLOAD_VERSION`] untouched: an old client reads a v2 frame's first
/// byte and cleanly rejects it with
/// [`LedgerPayloadError::UnsupportedVersion`].
pub const LEDGER_PAYLOAD_V2_VERSION: u8 = 2;

/// Wire version of the v3 ledger payload, prefixed to every
/// [`LedgerPayloadV3::to_bytes`] encoding.
///
/// A separate constant (and prefix byte) keeps the frozen v1/v2 bytes
/// untouched: an old client reads a v3 frame's first byte and cleanly rejects it
/// with [`LedgerPayloadError::UnsupportedVersion`].
pub const LEDGER_PAYLOAD_V3_VERSION: u8 = 3;

/// Maximum receipt history length a caller should accept, in `ValueNoticeV1`
/// entries. This is a use-site bound; decoding never truncates.
pub const MAX_RECEIPT_HISTORY: usize = 64;

/// A versioned ledger payload.
///
/// Variant order is frozen: postcard encodes the discriminant positionally
/// (`Order = 0`, `OrderResult = 1`, `BalanceQuery = 2`, `BalanceReceipt = 3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerPayloadV1 {
    /// Browser -> leaf: submit an operator-signed payment order.
    Order(OrderV1),
    /// Leaf -> browser: the outcome of an [`OrderV1`].
    OrderResult(OrderResultV1),
    /// Browser -> leaf: request a signed balance receipt.
    BalanceQuery(BalanceQueryV1),
    /// Leaf -> browser: a signed balance receipt.
    BalanceReceipt(BalanceReceiptV1),
}

impl LedgerPayloadV1 {
    /// Encode with the [`LEDGER_PAYLOAD_VERSION`] prefix followed by the
    /// postcard body.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LedgerPayloadError> {
        let body = postcard::to_allocvec(self).map_err(codec_error)?;
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(LEDGER_PAYLOAD_VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a version-prefixed payload.
    ///
    /// Rejects an empty buffer, an unsupported version, a truncated or invalid
    /// body, and any trailing bytes after the body. Never panics on arbitrary
    /// input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LedgerPayloadError> {
        let (version, body) = bytes
            .split_first()
            .ok_or_else(|| LedgerPayloadError::Codec("empty ledger payload".to_string()))?;
        if *version != LEDGER_PAYLOAD_VERSION {
            return Err(LedgerPayloadError::UnsupportedVersion(*version));
        }
        match postcard::take_from_bytes::<Self>(body) {
            Ok((value, [])) => Ok(value),
            Ok((_, rest)) => Err(LedgerPayloadError::Codec(format!(
                "{} trailing byte(s) after ledger payload",
                rest.len()
            ))),
            Err(err) => Err(codec_error(err)),
        }
    }
}

/// Browser -> leaf: an operator-signed order plus its authorisation reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderV1 {
    /// The order the payer's operator signed.
    pub order: PaymentOrder,
    /// The operator binding that travels with the order.
    pub auth: AuthRef,
}

/// Terminal status of an [`OrderV1`].
///
/// Variant order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderStatusV1 {
    /// The order produced a ledger entry.
    Applied,
    /// The order was already consumed (replay); no new entry.
    Duplicate,
    /// The order was refused; see [`OrderResultV1::reason`].
    Rejected,
}

/// Why an [`OrderV1`] was rejected.
///
/// Variant order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderRejectV1 {
    /// Authorisation missing, malformed, or not the payer's operator.
    Unauthorized,
    /// The order failed structural validation.
    BadRequest,
    /// The order was past its expiry.
    Expired,
    /// The account lacks the funds to debit.
    InsufficientBalance,
    /// The debited account has not been opened.
    AccountNotOpened,
    /// The recipient is not a descendant of the routing leaf.
    NotAChild,
    /// An internal error on the leaf.
    Internal,
}

/// Leaf -> browser: the result of an [`OrderV1`].
///
/// Field order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderResultV1 {
    /// The [`MsgId`] of the triggering order envelope.
    pub reply_to: MsgId,
    /// The order's domain-separated hash.
    pub order_hash: Hash,
    /// Whether the order applied, was a duplicate, or was rejected.
    pub status: OrderStatusV1,
    /// The ledger `seq` of the applied entry, when there is one.
    pub entry_seq: Option<u64>,
    /// The hash of the applied entry, when there is one.
    pub entry_hash: Option<Hash>,
    /// The rejection reason, when `status == Rejected`.
    pub reason: Option<OrderRejectV1>,
    /// A fresh balance receipt for the payer, when the leaf offers one.
    pub balance: Option<BalanceReceiptV1>,
}

/// Browser -> leaf: request a signed balance receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceQueryV1 {
    /// Caller-chosen correlation id, echoed in the receipt.
    pub query_id: u64,
}

/// Leaf -> browser: a signed, verifiable balance receipt.
///
/// Field order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceReceiptV1 {
    /// The [`MsgId`] of the triggering query, when this is a reply.
    pub reply_to: Option<MsgId>,
    /// The echoed [`BalanceQueryV1::query_id`], when this is a reply.
    pub query_id: Option<u64>,
    /// The attesting ledger's public key.
    pub ledger_pubkey: LedgerPubKey,
    /// The inclusion proof binding the balance to `commitment`.
    pub attestation: BalanceAttestation,
    /// The signed commitment the attestation is against.
    pub commitment: SignedCommitment,
    /// Recent value notices for the account, oldest first.
    pub history: Vec<ValueNoticeV1>,
    /// A single new notice, when this receipt was triggered by a value event.
    pub notice: Option<ValueNoticeV1>,
}

impl BalanceReceiptV1 {
    /// Whether [`history`](Self::history) fits the [`MAX_RECEIPT_HISTORY`]
    /// bound. Decoding never truncates; callers decide what to do on overflow.
    pub fn history_within_bound(&self) -> bool {
        self.history.len() <= MAX_RECEIPT_HISTORY
    }
}

/// One value movement in a [`BalanceReceiptV1`]'s history.
///
/// Field order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueNoticeV1 {
    /// The ledger `seq` of the entry that moved value.
    pub entry_seq: u64,
    /// The hash of that entry.
    pub entry_hash: Hash,
    /// The cascade `payment_id` shared by every hop.
    pub payment_id: Hash,
    /// The payer node.
    pub from: NodeId,
    /// The payee node.
    pub to: NodeId,
    /// The amount moved.
    pub amount: Amount,
    /// The hop's position in the settlement cascade.
    pub role: HopRole,
    /// Coarse issuance timestamp.
    pub issued_at: u64,
}

/// Errors raised by ledger-payload postcard framing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerPayloadError {
    /// The first byte is not [`LEDGER_PAYLOAD_VERSION`].
    #[error("unsupported ledger payload version {0}")]
    UnsupportedVersion(u8),
    /// The postcard body could not be encoded or decoded.
    #[error("postcard encode/decode: {0}")]
    Codec(String),
}

fn codec_error(err: postcard::Error) -> LedgerPayloadError {
    LedgerPayloadError::Codec(err.to_string())
}

/// A versioned **v2** ledger payload.
///
/// Variant order is frozen. v2 exists because [`LedgerPayloadV1`] cannot be
/// extended in place (positional postcard): a new variant requires a new
/// version-prefixed type. v2 also carries settlement-specific results.
// `OrderResult` embeds an optional full balance receipt, so variant sizes differ;
// the wire layout is frozen, so keep the declared shape rather than boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerPayloadV2 {
    /// Browser -> leaf: submit an operator-signed order with the payee's
    /// address, so the leaf can route a cross-subtree settlement.
    Order(OrderV2),
    /// Leaf -> browser: the outcome of an [`OrderV2`], including a settlement's
    /// `Partial` state that names the failing hop.
    OrderResult(OrderResultV2),
}

impl LedgerPayloadV2 {
    /// Encode with the [`LEDGER_PAYLOAD_V2_VERSION`] prefix followed by the
    /// postcard body.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LedgerPayloadError> {
        let body = postcard::to_allocvec(self).map_err(codec_error)?;
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(LEDGER_PAYLOAD_V2_VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a version-prefixed v2 payload.
    ///
    /// Rejects an empty buffer, a non-v2 version, a truncated or invalid body,
    /// and any trailing bytes after the body. Never panics on arbitrary input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LedgerPayloadError> {
        let (version, body) = bytes
            .split_first()
            .ok_or_else(|| LedgerPayloadError::Codec("empty ledger payload".to_string()))?;
        if *version != LEDGER_PAYLOAD_V2_VERSION {
            return Err(LedgerPayloadError::UnsupportedVersion(*version));
        }
        decode_body(body)
    }
}

/// A versioned **v3** ledger payload.
///
/// Variant order is frozen. v3 exists because the v2 result
/// ([`OrderResultV2`]) carries only advisory status; v3 adds an optional
/// [`EntryProofV1`] so a browser can independently verify the applied terminal
/// hop. The browser still sends orders as [`LedgerPayloadV2::Order`] /
/// [`OrderV2`]; v3 is currently result-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerPayloadV3 {
    /// Leaf -> browser: the outcome of an [`OrderV2`], with a proof of the
    /// applied terminal hop.
    OrderResult(OrderResultV3),
}

impl LedgerPayloadV3 {
    /// Encode with the [`LEDGER_PAYLOAD_V3_VERSION`] prefix followed by the
    /// postcard body.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LedgerPayloadError> {
        let body = postcard::to_allocvec(self).map_err(codec_error)?;
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(LEDGER_PAYLOAD_V3_VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a version-prefixed v3 payload.
    ///
    /// Rejects an empty buffer, a non-v3 version, a truncated or invalid body,
    /// and any trailing bytes after the body. Never panics on arbitrary input.
    ///
    /// Decoding does not validate an [`EntryProofV1`]; callers must invoke
    /// [`EntryProofV1::validate`] before trusting the proof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LedgerPayloadError> {
        let (version, body) = bytes
            .split_first()
            .ok_or_else(|| LedgerPayloadError::Codec("empty ledger payload".to_string()))?;
        if *version != LEDGER_PAYLOAD_V3_VERSION {
            return Err(LedgerPayloadError::UnsupportedVersion(*version));
        }
        decode_body(body)
    }
}

/// Browser -> leaf: an operator-signed order plus the payee's address.
///
/// Field order is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderV2 {
    /// The order the payer's operator signed.
    pub order: PaymentOrder,
    /// The operator binding that travels with the order.
    pub auth: AuthRef,
    /// The payee's user `OctAddr`, needed to derive the settlement route.
    pub payee_addr: OctAddr,
}

/// Leaf -> browser: the outcome of an [`OrderV2`].
///
/// Field order is frozen. `balance` is the payer's own signed receipt, when the
/// leaf offers one; the result itself is **advisory**, and the receipt is the
/// payer's signed ground truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderResultV2 {
    /// The [`MsgId`] of the triggering order envelope.
    pub reply_to: MsgId,
    /// The order's domain-separated hash.
    pub order_hash: Hash,
    /// The settlement outcome.
    pub status: SettlementStatusV2,
    /// A fresh balance receipt for the payer, when the leaf offers one.
    pub balance: Option<BalanceReceiptV1>,
}

/// Leaf -> browser: the outcome of an [`OrderV2`], with verifiable proof.
///
/// Field order is frozen. `balance` is the payer's own signed receipt, when the
/// leaf offers one; `proof` is the applied terminal hop's inclusion evidence,
/// which clients require for `Applied`/`Duplicate` outcomes.
///
/// Decoding does not validate `proof`; callers must invoke
/// [`EntryProofV1::validate`] before trusting it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderResultV3 {
    /// The [`MsgId`] of the triggering order envelope.
    pub reply_to: MsgId,
    /// The order's domain-separated hash.
    pub order_hash: Hash,
    /// The settlement outcome (same semantics as [`SettlementStatusV2`]).
    pub status: SettlementStatusV2,
    /// A fresh balance receipt for the payer, when the leaf offers one.
    pub balance: Option<BalanceReceiptV1>,
    /// The applied terminal hop's inclusion proof, when there is one.
    pub proof: Option<EntryProofV1>,
}

/// The terminal state of an [`OrderV2`] and its settlement.
///
/// Variant order is frozen. `Partial` is the partial-cascade case: the payer's
/// own hop applied (so the payer was debited) but a downstream hop failed, so
/// the payee was not credited. It names the failing hop so the browser never
/// reports an unproven "paid".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementStatusV2 {
    /// The payment applied in full.
    Applied {
        /// The terminal hop's ledger `seq`.
        entry_seq: u64,
        /// The terminal hop's entry hash.
        entry_hash: Hash,
    },
    /// The order was already consumed (replay); no new entry.
    Duplicate {
        /// The previously applied entry's ledger `seq`.
        entry_seq: u64,
        /// The previously applied entry's hash.
        entry_hash: Hash,
    },
    /// The payer's hop applied but a downstream hop failed.
    Partial {
        /// The hop whose hop was refused.
        failed_at: NodeId,
        /// The per-hop refusal reason.
        reason: OrderRejectV1,
    },
    /// The payment was refused before the payer's hop applied.
    Rejected {
        /// The refusal reason.
        reason: OrderRejectV1,
    },
    /// The outcome is unknown but the payer's hop applied (a debit is
    /// committed): a timeout, an eviction, or a post-reservation malformed
    /// terminal. The payer must not assume the funds were returned.
    Indeterminate {
        /// The reason the outcome could not be determined.
        reason: OrderRejectV1,
    },
}

/// A ledger payload of any known version, for version-dispatching callers.
// Non-wire Rust wrapper; variant sizes differ, so allow the sized-difference lint.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionedLedgerPayload {
    /// A [`LEDGER_PAYLOAD_VERSION`] payload.
    V1(LedgerPayloadV1),
    /// A [`LEDGER_PAYLOAD_V2_VERSION`] payload.
    V2(LedgerPayloadV2),
    /// A [`LEDGER_PAYLOAD_V3_VERSION`] payload.
    V3(LedgerPayloadV3),
}

/// Decode a version-prefixed ledger payload of any known version.
///
/// An unknown version (including a future one) is rejected with
/// [`LedgerPayloadError::UnsupportedVersion`], so an old client never
/// misinterprets a newer frame.
pub fn decode_versioned(bytes: &[u8]) -> Result<VersionedLedgerPayload, LedgerPayloadError> {
    let (version, body) = bytes
        .split_first()
        .ok_or_else(|| LedgerPayloadError::Codec("empty ledger payload".to_string()))?;
    match *version {
        LEDGER_PAYLOAD_VERSION => Ok(VersionedLedgerPayload::V1(decode_body(body)?)),
        LEDGER_PAYLOAD_V2_VERSION => Ok(VersionedLedgerPayload::V2(decode_body(body)?)),
        LEDGER_PAYLOAD_V3_VERSION => Ok(VersionedLedgerPayload::V3(decode_body(body)?)),
        other => Err(LedgerPayloadError::UnsupportedVersion(other)),
    }
}

/// Decode a postcard body, rejecting trailing bytes.
fn decode_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, LedgerPayloadError> {
    match postcard::take_from_bytes::<T>(body) {
        Ok((value, [])) => Ok(value),
        Ok((_, rest)) => Err(LedgerPayloadError::Codec(format!(
            "{} trailing byte(s) after ledger payload",
            rest.len()
        ))),
        Err(err) => Err(codec_error(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{
        Commitment, EdgeAccount, Entry, EntryBody, EntryInclusionProof, LedgerSecretKey,
        OperatorSecretKey, PeerKeys, PeerRole, SignedCommitment, SignedEntry,
    };

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
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

    fn sample_order() -> OrderV1 {
        OrderV1 {
            order: PaymentOrder {
                from: node("alice"),
                to: node("bob"),
                amount: Amount::new(7),
                nonce: 5,
                expiry: 100,
            },
            auth: auth(),
        }
    }

    fn sample_order_v2() -> OrderV2 {
        OrderV2 {
            order: PaymentOrder {
                from: node("alice"),
                to: node("bob"),
                amount: Amount::new(7),
                nonce: 5,
                expiry: 100,
            },
            auth: auth(),
            payee_addr: "0.2.4".parse().expect("valid octal address"),
        }
    }

    fn sample_order_result_v2(status: SettlementStatusV2) -> OrderResultV2 {
        OrderResultV2 {
            reply_to: MsgId([0x11; 16]),
            order_hash: Hash::from_bytes([0x22; 32]),
            status,
            balance: None,
        }
    }

    fn sample_signed_entry() -> SignedEntry {
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

    /// A structurally valid [`EntryProofV1`] against [`sample_commitment`]
    /// (`entry_count`/`tree_size` 3, entry at seq 0).
    fn sample_entry_proof() -> EntryProofV1 {
        EntryProofV1 {
            entry: sample_signed_entry(),
            signer: PeerKeys {
                node_id: node("leaf"),
                operator: operator(0x33).public(),
                ledger: Some(ledger(0x11).public()),
                role: PeerRole::Node,
            },
            leaf_addr: "0.1.3".parse().expect("valid octal address"),
            commitment: sample_commitment(),
            inclusion: EntryInclusionProof {
                index: 0,
                tree_size: 3,
                proof: vec![Hash::from_bytes([0x99; 32])],
            },
        }
    }

    fn sample_order_result_v3(
        status: SettlementStatusV2,
        proof: Option<EntryProofV1>,
    ) -> OrderResultV3 {
        OrderResultV3 {
            reply_to: MsgId([0x11; 16]),
            order_hash: Hash::from_bytes([0x22; 32]),
            status,
            balance: None,
            proof,
        }
    }

    fn sample_notice() -> ValueNoticeV1 {
        ValueNoticeV1 {
            entry_seq: 3,
            entry_hash: Hash::from_bytes([0x55; 32]),
            payment_id: Hash::from_bytes([0x22; 32]),
            from: node("alice"),
            to: node("bob"),
            amount: Amount::new(7),
            role: HopRole::Direct,
            issued_at: 1234,
        }
    }

    fn sample_commitment() -> SignedCommitment {
        let key = ledger(0x11);
        SignedCommitment {
            commitment: Commitment {
                ledger_id: key.public(),
                ledger_pubkey: key.public(),
                height: 3,
                entry_count: 3,
                entry_root: Hash::from_bytes([0x66; 32]),
                state_root: Hash::from_bytes([0x77; 32]),
                prev_commitment_hash: Hash::from_bytes([0x88; 32]),
                issued_at: 1234,
            },
            signature: key.sign(b"commitment"),
        }
    }

    fn sample_attestation() -> BalanceAttestation {
        BalanceAttestation {
            edge: EdgeAccount {
                parent: node("root"),
                child: node("bob"),
            },
            ledger_pubkey: ledger(0x11).public(),
            balance: Amount::new(7),
            height: 3,
            state_root: Hash::from_bytes([0x77; 32]),
            index: 1,
            tree_size: 2,
            proof: vec![Hash::from_bytes([0x99; 32])],
        }
    }

    fn sample_receipt(
        history: Vec<ValueNoticeV1>,
        notice: Option<ValueNoticeV1>,
    ) -> BalanceReceiptV1 {
        BalanceReceiptV1 {
            reply_to: Some(MsgId([0x11; 16])),
            query_id: Some(9),
            ledger_pubkey: ledger(0x11).public(),
            attestation: sample_attestation(),
            commitment: sample_commitment(),
            history,
            notice,
        }
    }

    fn result(status: OrderStatusV1, reason: Option<OrderRejectV1>) -> OrderResultV1 {
        OrderResultV1 {
            reply_to: MsgId([0x11; 16]),
            order_hash: Hash::from_bytes([0x22; 32]),
            status,
            entry_seq: Some(3),
            entry_hash: Some(Hash::from_bytes([0x55; 32])),
            reason,
            balance: None,
        }
    }

    fn round_trip(payload: &LedgerPayloadV1) {
        let bytes = payload.to_bytes().unwrap();
        assert_eq!(bytes[0], LEDGER_PAYLOAD_VERSION);
        let back = LedgerPayloadV1::from_bytes(&bytes).unwrap();
        assert_eq!(&back, payload);
    }

    #[test]
    fn round_trip_every_variant() {
        round_trip(&LedgerPayloadV1::Order(sample_order()));
        round_trip(&LedgerPayloadV1::BalanceQuery(BalanceQueryV1 {
            query_id: 9,
        }));
        round_trip(&LedgerPayloadV1::BalanceReceipt(sample_receipt(
            vec![],
            None,
        )));
        round_trip(&LedgerPayloadV1::BalanceReceipt(sample_receipt(
            vec![sample_notice()],
            Some(sample_notice()),
        )));

        // Every status, and every reject reason under `Rejected`.
        for status in [
            OrderStatusV1::Applied,
            OrderStatusV1::Duplicate,
            OrderStatusV1::Rejected,
        ] {
            round_trip(&LedgerPayloadV1::OrderResult(result(status, None)));
        }
        for reason in [
            OrderRejectV1::Unauthorized,
            OrderRejectV1::BadRequest,
            OrderRejectV1::Expired,
            OrderRejectV1::InsufficientBalance,
            OrderRejectV1::AccountNotOpened,
            OrderRejectV1::NotAChild,
            OrderRejectV1::Internal,
        ] {
            round_trip(&LedgerPayloadV1::OrderResult(result(
                OrderStatusV1::Rejected,
                Some(reason),
            )));
        }
    }

    #[test]
    fn enum_discriminant_order_is_frozen() {
        // Postcard encodes the enum discriminant as a varint immediately after
        // the version prefix; all four indices are single-byte varints.
        let cases = [
            (LedgerPayloadV1::Order(sample_order()), 0u8),
            (
                LedgerPayloadV1::OrderResult(result(OrderStatusV1::Applied, None)),
                1,
            ),
            (
                LedgerPayloadV1::BalanceQuery(BalanceQueryV1 { query_id: 1 }),
                2,
            ),
            (
                LedgerPayloadV1::BalanceReceipt(sample_receipt(vec![], None)),
                3,
            ),
        ];
        for (payload, expected) in cases {
            let bytes = payload.to_bytes().unwrap();
            assert_eq!(
                bytes[1], expected,
                "variant discriminant for {payload:?} changed"
            );
        }
    }

    #[test]
    fn malformed_and_truncated_bytes_are_errors() {
        // Empty buffer.
        assert!(LedgerPayloadV1::from_bytes(&[]).is_err());

        // Version byte only, no body.
        assert!(LedgerPayloadV1::from_bytes(&[LEDGER_PAYLOAD_VERSION]).is_err());

        // Wrong version.
        assert_eq!(
            LedgerPayloadV1::from_bytes(&[LEDGER_PAYLOAD_VERSION + 1]),
            Err(LedgerPayloadError::UnsupportedVersion(2))
        );

        // Every strict prefix of a valid payload fails to decode; no panic.
        let valid = LedgerPayloadV1::Order(sample_order()).to_bytes().unwrap();
        for cut in 0..valid.len() {
            assert!(
                LedgerPayloadV1::from_bytes(&valid[..cut]).is_err(),
                "prefix of length {cut} unexpectedly decoded"
            );
        }

        // Trailing garbage after an otherwise valid body is rejected.
        let mut trailing = valid.clone();
        trailing.push(0x00);
        assert!(LedgerPayloadV1::from_bytes(&trailing).is_err());

        // Arbitrary bytes never panic.
        for byte in 0u8..=255 {
            let _ = LedgerPayloadV1::from_bytes(&[byte, byte, byte, byte]);
        }
    }

    #[test]
    fn golden_order_bytes_are_frozen() {
        let payload = LedgerPayloadV1::Order(sample_order());
        assert_eq!(to_hex(&payload.to_bytes().unwrap()), GOLDEN_ORDER);
    }

    #[test]
    fn golden_order_result_bytes_are_frozen() {
        let payload = LedgerPayloadV1::OrderResult(result(OrderStatusV1::Applied, None));
        assert_eq!(to_hex(&payload.to_bytes().unwrap()), GOLDEN_ORDER_RESULT);
    }

    #[test]
    fn golden_balance_receipt_bytes_are_frozen() {
        let payload = LedgerPayloadV1::BalanceReceipt(sample_receipt(
            vec![sample_notice()],
            Some(sample_notice()),
        ));
        assert_eq!(to_hex(&payload.to_bytes().unwrap()), GOLDEN_BALANCE_RECEIPT);
    }

    // Frozen wire-format vectors. If these fail after an intentional format
    // change, bump `LEDGER_PAYLOAD_VERSION` and update the constants.
    const GOLDEN_ORDER: &str = "010005616c69636503626f6207056417cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce0544444444444444444444444444444444444444444444444444444444444444444ef0de24d928dfa8740dcc7e9f7012b52d0d51026858a05447c7ce0bcdfa47f072cdfd611cd4eb96dbdf103aa3cad2a3c9f259810b5705501518f6bebf739101";
    const GOLDEN_ORDER_RESULT: &str = "01011111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220001030155555555555555555555555555555555555555555555555555555555555555550000";
    const GOLDEN_BALANCE_RECEIPT: &str = "010301111111111111111111111111111111110109d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873704726f6f7403626f62d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737070377777777777777777777777777777777777777777777777777777777777777770102019999999999999999999999999999999999999999999999999999999999999999d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370303666666666666666666666666666666666666666666666666666666666666666677777777777777777777777777777777777777777777777777777777777777778888888888888888888888888888888888888888888888888888888888888888d209b5f3b3be6445c4b4e4e8f2e91e8850065645823451661488532ae7c8910024087d553915e793a513d50e59857e5a2c5df02de5111360835f659fba46095a670f01035555555555555555555555555555555555555555555555555555555555555555222222222222222222222222222222222222222222222222222222222222222205616c69636503626f620703d20901035555555555555555555555555555555555555555555555555555555555555555222222222222222222222222222222222222222222222222222222222222222205616c69636503626f620703d209";

    #[test]
    fn v2_order_round_trips_and_is_versioned_separately() {
        let payload = LedgerPayloadV2::Order(sample_order_v2());
        let bytes = payload.to_bytes().unwrap();
        assert_eq!(bytes[0], LEDGER_PAYLOAD_V2_VERSION);
        assert_ne!(LEDGER_PAYLOAD_V2_VERSION, LEDGER_PAYLOAD_VERSION);
        assert_eq!(LedgerPayloadV2::from_bytes(&bytes).unwrap(), payload);

        // An old v1 reader rejects a v2 frame cleanly.
        assert_eq!(
            LedgerPayloadV1::from_bytes(&bytes),
            Err(LedgerPayloadError::UnsupportedVersion(LEDGER_PAYLOAD_V2_VERSION))
        );
        // A v2 reader rejects a v1 frame cleanly.
        let v1 = LedgerPayloadV1::Order(sample_order()).to_bytes().unwrap();
        assert_eq!(
            LedgerPayloadV2::from_bytes(&v1),
            Err(LedgerPayloadError::UnsupportedVersion(LEDGER_PAYLOAD_VERSION))
        );
    }

    #[test]
    fn decode_versioned_dispatches_all_versions() {
        let v1 = LedgerPayloadV1::Order(sample_order());
        let v1_bytes = v1.to_bytes().unwrap();
        assert_eq!(
            decode_versioned(&v1_bytes).unwrap(),
            VersionedLedgerPayload::V1(v1)
        );

        let v2 = LedgerPayloadV2::Order(sample_order_v2());
        let v2_bytes = v2.to_bytes().unwrap();
        assert_eq!(
            decode_versioned(&v2_bytes).unwrap(),
            VersionedLedgerPayload::V2(v2)
        );

        let v3 = LedgerPayloadV3::OrderResult(sample_order_result_v3(
            SettlementStatusV2::Applied {
                entry_seq: 0,
                entry_hash: Hash::from_bytes([0x55; 32]),
            },
            Some(sample_entry_proof()),
        ));
        let v3_bytes = v3.to_bytes().unwrap();
        assert_eq!(
            decode_versioned(&v3_bytes).unwrap(),
            VersionedLedgerPayload::V3(v3)
        );

        // Unknown / future version and empty buffer are rejected.
        assert_eq!(
            decode_versioned(&[LEDGER_PAYLOAD_V3_VERSION + 1]),
            Err(LedgerPayloadError::UnsupportedVersion(4))
        );
        assert!(decode_versioned(&[]).is_err());

        // Truncated and trailing bytes are rejected for each version.
        for valid in [&v1_bytes, &v2_bytes, &v3_bytes] {
            for cut in 0..valid.len() {
                assert!(decode_versioned(&valid[..cut]).is_err());
            }
            let mut trailing = valid.clone();
            trailing.push(0);
            assert!(decode_versioned(&trailing).is_err());
        }
    }

    #[test]
    fn v3_order_result_round_trips_with_and_without_proof() {
        let with_proof = LedgerPayloadV3::OrderResult(sample_order_result_v3(
            SettlementStatusV2::Applied {
                entry_seq: 0,
                entry_hash: Hash::from_bytes([0x55; 32]),
            },
            Some(sample_entry_proof()),
        ));
        let bytes = with_proof.to_bytes().unwrap();
        assert_eq!(bytes[0], LEDGER_PAYLOAD_V3_VERSION);
        assert_eq!(LedgerPayloadV3::from_bytes(&bytes).unwrap(), with_proof);
        // The proof survives the round trip and still validates.
        let LedgerPayloadV3::OrderResult(decoded) =
            LedgerPayloadV3::from_bytes(&bytes).unwrap();
        assert!(decoded.proof.unwrap().validate().is_ok());

        let without_proof = LedgerPayloadV3::OrderResult(sample_order_result_v3(
            SettlementStatusV2::Rejected {
                reason: OrderRejectV1::BadRequest,
            },
            None,
        ));
        let bytes = without_proof.to_bytes().unwrap();
        assert_eq!(bytes[0], LEDGER_PAYLOAD_V3_VERSION);
        assert_eq!(LedgerPayloadV3::from_bytes(&bytes).unwrap(), without_proof);

        // Every strict prefix fails; trailing bytes are rejected.
        for cut in 0..bytes.len() {
            assert!(
                LedgerPayloadV3::from_bytes(&bytes[..cut]).is_err(),
                "prefix of length {cut} unexpectedly decoded"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(LedgerPayloadV3::from_bytes(&trailing).is_err());
    }

    #[test]
    fn v3_rejects_other_versions_exactly() {
        // A v3 reader rejects v1 and v2 frames cleanly.
        let v1 = LedgerPayloadV1::Order(sample_order()).to_bytes().unwrap();
        assert_eq!(
            LedgerPayloadV3::from_bytes(&v1),
            Err(LedgerPayloadError::UnsupportedVersion(
                LEDGER_PAYLOAD_VERSION
            ))
        );
        let v2 = LedgerPayloadV2::Order(sample_order_v2()).to_bytes().unwrap();
        assert_eq!(
            LedgerPayloadV3::from_bytes(&v2),
            Err(LedgerPayloadError::UnsupportedVersion(
                LEDGER_PAYLOAD_V2_VERSION
            ))
        );

        // Old readers reject a v3 frame cleanly.
        let v3 = LedgerPayloadV3::OrderResult(sample_order_result_v3(
            SettlementStatusV2::Rejected {
                reason: OrderRejectV1::Internal,
            },
            None,
        ))
        .to_bytes()
        .unwrap();
        assert_eq!(
            LedgerPayloadV2::from_bytes(&v3),
            Err(LedgerPayloadError::UnsupportedVersion(
                LEDGER_PAYLOAD_V3_VERSION
            ))
        );
        assert_eq!(
            LedgerPayloadV1::from_bytes(&v3),
            Err(LedgerPayloadError::UnsupportedVersion(
                LEDGER_PAYLOAD_V3_VERSION
            ))
        );
    }

    #[test]
    fn v3_discriminant_order_is_frozen() {
        let result = LedgerPayloadV3::OrderResult(sample_order_result_v3(
            SettlementStatusV2::Rejected {
                reason: OrderRejectV1::BadRequest,
            },
            None,
        ));
        assert_eq!(result.to_bytes().unwrap()[1], 0);
    }

    #[test]
    fn v2_order_result_round_trips_every_status() {
        let statuses = [
            SettlementStatusV2::Applied {
                entry_seq: 7,
                entry_hash: Hash::from_bytes([0x55; 32]),
            },
            SettlementStatusV2::Duplicate {
                entry_seq: 7,
                entry_hash: Hash::from_bytes([0x55; 32]),
            },
            SettlementStatusV2::Partial {
                failed_at: node("leaf"),
                reason: OrderRejectV1::InsufficientBalance,
            },
            SettlementStatusV2::Rejected {
                reason: OrderRejectV1::BadRequest,
            },
            SettlementStatusV2::Indeterminate {
                reason: OrderRejectV1::Internal,
            },
        ];
        for status in statuses {
            let payload = LedgerPayloadV2::OrderResult(sample_order_result_v2(status));
            let bytes = payload.to_bytes().unwrap();
            assert_eq!(bytes[0], LEDGER_PAYLOAD_V2_VERSION);
            assert_eq!(LedgerPayloadV2::from_bytes(&bytes).unwrap(), payload);

            for cut in 0..bytes.len() {
                assert!(
                    LedgerPayloadV2::from_bytes(&bytes[..cut]).is_err(),
                    "prefix of length {cut} unexpectedly decoded"
                );
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(LedgerPayloadV2::from_bytes(&trailing).is_err());
        }
    }

    #[test]
    fn v2_discriminant_order_is_frozen() {
        let order = LedgerPayloadV2::Order(sample_order_v2());
        let result = LedgerPayloadV2::OrderResult(sample_order_result_v2(
            SettlementStatusV2::Rejected {
                reason: OrderRejectV1::BadRequest,
            },
        ));
        assert_eq!(order.to_bytes().unwrap()[1], 0);
        assert_eq!(result.to_bytes().unwrap()[1], 1);

        for (status, expected) in [
            (
                SettlementStatusV2::Applied {
                    entry_seq: 0,
                    entry_hash: Hash::ZERO,
                },
                0u8,
            ),
            (
                SettlementStatusV2::Duplicate {
                    entry_seq: 0,
                    entry_hash: Hash::ZERO,
                },
                1,
            ),
            (
                SettlementStatusV2::Partial {
                    failed_at: node("n"),
                    reason: OrderRejectV1::Internal,
                },
                2,
            ),
            (
                SettlementStatusV2::Rejected {
                    reason: OrderRejectV1::Internal,
                },
                3,
            ),
            (
                SettlementStatusV2::Indeterminate {
                    reason: OrderRejectV1::Internal,
                },
                4,
            ),
        ] {
            assert_eq!(
                postcard::to_allocvec(&status).unwrap()[0],
                expected,
                "status discriminant changed"
            );
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}
