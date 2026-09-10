//! The [`LedgerError`] type shared by every ledger module.
//!
//! Later phases add variants here; the variants defined now are the ones the
//! core (amounts, balances, entries, signatures, and the append chain) can
//! raise.

use crate::account::{AccountRef, NodeId};
use crate::hash::Hash;

/// Errors produced by ledger operations.
///
/// This is deliberately a plain `thiserror` enum (no `anyhow`): the ledger is
/// security-critical, so every failure mode is explicit and matchable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// An arithmetic operation would overflow (or underflow below zero).
    #[error("arithmetic overflow")]
    Overflow,

    /// The posting set does not satisfy the double-entry conservation rule, or
    /// the body's equity delta does not match its declared amount.
    #[error("value conservation violated")]
    ConservationViolation,

    /// Applying the postings would make a `Parent` or `Child` balance
    /// negative. Transfers are prefunded-only: no overdraw is permitted.
    #[error("insufficient balance")]
    InsufficientBalance,

    /// A [`crate::account::AccountRef::Parent`] posting was applied to a root
    /// ledger, which has no parent account.
    #[error("account has no parent")]
    NoParentAccount,

    /// An entry could not be serialized to its canonical bytes.
    #[error("entry encoding failed: {0}")]
    Encode(String),

    /// A signature did not verify under the expected key.
    #[error("invalid signature")]
    InvalidSignature,

    /// A public key could not be parsed from its byte representation.
    #[error("invalid key")]
    InvalidKey,

    /// The postings do not match the canonical shape declared by the entry
    /// body (wrong accounts, wrong signs, wrong magnitude, extra/duplicate
    /// legs, or a zero amount).
    #[error("invalid entry shape")]
    InvalidEntryShape,

    /// The entry requires an operator authorisation but carries none.
    #[error("missing operator authorization")]
    MissingAuthorization,

    /// The entry uses a feature that Phase A does not implement yet.
    #[error("unsupported entry")]
    Unsupported,

    /// For now `height` must equal `seq` (dense from 0). Commitments may later
    /// redefine `height`.
    #[error("invalid height: expected {expected}, found {found}")]
    InvalidHeight {
        /// The required height.
        expected: u64,
        /// The height carried by the entry.
        found: u64,
    },

    /// The entry was signed for a different ledger than the one appending it.
    #[error("entry ledger id does not match this ledger")]
    LedgerMismatch,

    /// The entry's sequence number is not the next one in the chain. A valid
    /// chain starts at `seq == 0` and increments by exactly one.
    #[error("entry sequence out of order: expected {expected}, found {found}")]
    SeqOutOfOrder {
        /// The sequence number the ledger expected next.
        expected: u64,
        /// The sequence number carried by the entry.
        found: u64,
    },

    /// The entry's `prev_hash` does not match the hash of the previous entry
    /// (`Hash::ZERO` for a genesis entry).
    #[error("previous hash mismatch: expected {expected}, found {found}")]
    PrevHashMismatch {
        /// The hash the chain expected.
        expected: Hash,
        /// The hash carried by the entry.
        found: Hash,
    },

    /// `Balances::open_account` was called for a child account that already
    /// exists. Opening an account is idempotent-free: replaying an
    /// `OpenAccount` entry is rejected.
    #[error("account already exists")]
    AccountExists,

    /// The registry already contains a peer with this node id.
    #[error("duplicate peer")]
    DuplicatePeer,

    /// The operator authorising an entry is not the operator the registry
    /// associates with the order's node, or the node is unregistered.
    #[error("unauthorized operator")]
    Unauthorized,

    /// The entry's `AuthRef` does not match the presented order
    /// (`order_hash` or `nonce` differs).
    #[error("order does not match authorization")]
    OrderMismatch,

    /// The order's expiry has passed.
    #[error("order expired")]
    OrderExpired,

    /// A Merkle proof was requested for an out-of-range leaf index.
    #[error("index out of range")]
    IndexOutOfRange,

    /// A log backend reported a gap while a commitment was being built.
    #[error("log entry missing at index {index}")]
    MissingEntry {
        /// The index that should have contained an entry.
        index: usize,
    },

    /// The registry already contains this operator or ledger key under another
    /// node id.
    #[error("duplicate key")]
    DuplicateKey,

    /// A `Child` posting referenced an account that was never opened with
    /// [`crate::account::Balances::open_account`]. Only opening materializes a
    /// child account.
    #[error("account not opened")]
    AccountNotOpened {
        /// The account that is missing.
        account: AccountRef,
    },

    /// A balance attestation's `state_root` does not match the commitment's
    /// signed `state_root`.
    #[error("state root mismatch")]
    StateRootMismatch,

    /// A balance attestation's inclusion proof did not verify.
    #[error("invalid inclusion proof")]
    InvalidProof,

    /// A settlement endpoint is not a user account held by a leaf node (v1
    /// scope), or a settlement path could not be resolved.
    #[error("unsupported settlement endpoint")]
    UnsupportedEndpoint,

    /// A settlement hop named a node with no ledger in the [`crate::settlement::LedgerSet`]
    /// (planning) or no signing key at execution time.
    #[error("missing ledger or signing key for node")]
    MissingLedger {
        /// The node whose ledger/key is missing.
        node: NodeId,
    },

    /// A [`crate::registry::PeerKeys`] violates the role/ledger invariant: a
    /// `User` must have no ledger key, and a `Node` must have one.
    #[error("invalid peer keys for role")]
    InvalidPeerKeys,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_stable() {
        assert_eq!(LedgerError::Overflow.to_string(), "arithmetic overflow");
        assert_eq!(
            LedgerError::SeqOutOfOrder {
                expected: 2,
                found: 5
            }
            .to_string(),
            "entry sequence out of order: expected 2, found 5"
        );
    }
}
