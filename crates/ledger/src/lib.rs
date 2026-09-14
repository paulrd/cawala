//! Cawala ledger core: a pure, synchronous, wasm-safe double-entry ledger.
//!
//! This crate has **no** `tokio`, `iroh`, filesystem, or RNG dependency. It is
//! compiled for `wasm32-unknown-unknown` (browser clients need to verify
//! ledgers) and for native nodes. Key material is always supplied by the
//! caller as raw bytes, so the crate itself never needs randomness.
//!
//! # Model
//!
//! The ledger stores only two account classes per node:
//!
//! - an asset account with its parent ([`AccountRef::Parent`], structurally
//!   universal: present on every ledger, and a stranded claim — normally zero —
//!   on a top-level/detached node),
//! - one liability account per child ([`AccountRef::Child`]).
//!
//! There is **no** equity account and equity is never posted: a node's equity is
//! **derived** as `Parent − ΣChild` ([`Balances::equity`]), externally backed
//! (goodwill, land, materials, ... out of scope). The per-entry rule is a pure
//! function of the entry body, so it is deterministic under dynamic rootness:
//!
//! - `Transfer`/`OpenAccount` are **balanced**: `ΔParent == ΔΣChild`;
//! - `Issue`/`Burn` are **boundary** operations on one child account
//!   (`{Child:+amount}` / `{Child:−amount}`), exempt from the balance equation.
//!
//! `E < 0` is normal and is never an overdraw; only `Parent`/`Child`
//! non-negativity is enforced.
//!
//! Entries are appended to a [`Ledger`] through [`Ledger::append`], which
//! verifies the ledger signature, the dense `seq` starting at 0, `height ==
//! seq`, the `prev_hash` chain, the per-entry rule, the canonical body-shape
//! binding, and non-negativity before mutating any state. The signed
//! entry format is versioned by [`ENTRY_FORMAT_VERSION`]; field/variant order
//! must not be reordered.

pub mod account;
pub mod amount;
pub mod auth;
pub mod commit;
pub mod entry;
pub mod error;
pub mod hash;
pub mod keys;
pub mod log;
pub mod merkle;
pub mod netting;
pub mod registry;
pub mod settlement;

pub use account::{AccountRef, Balances, NodeId, Posting};
pub use amount::{Amount, SignedAmount};
pub use auth::{
    BURN_CONTEXT, BurnRequest, ISSUE_CONTEXT, IssueRequest, ORDER_CONTEXT, PREFUND_CONTEXT,
    PaymentOrder, PrefundRequest, verify_burn, verify_issue, verify_prefund, verify_transfer,
};
pub use commit::{
    BalanceAttestation, COMMITMENT_CONTEXT, Commitment, EdgeAccount, SignedCommitment,
    attest_balance, build_commitment, commitment_hash, verify_balance_attestation, verify_chain,
};
pub use entry::{AuthRef, ENTRY_FORMAT_VERSION, Entry, EntryBody, HopRole, SignedEntry};
pub use error::LedgerError;
pub use hash::{Hash, empty_tree_root, entry_hash, leaf_hash, node_hash, state_leaf_hash};
pub use keys::{
    LedgerId, LedgerPubKey, LedgerSecretKey, OperatorPubKey, OperatorSecretKey, Signature,
};
pub use log::{Ledger, LedgerLog, MemLog};
pub use merkle::{
    entry_root, inclusion_proof, root as merkle_root, state_inclusion_proof, state_root,
    verify_inclusion, verify_state_inclusion,
};
pub use netting::{Finding, NetTransfer, NettingReport, net, verify_cascade};
pub use registry::{PeerKeys, PeerRegistry, PeerRole};
pub use settlement::{
    ExpectedHop, LedgerSet, PlannedHop, SettlementPlan, classify_hop, execute_plan, expected_hops,
    hop_postings, plan_transfer,
};
