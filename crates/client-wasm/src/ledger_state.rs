//! Pure, native-testable ledger state for the browser WASM client.
//!
//! This module is the value-transfer counterpart of [`crate::state`]: it holds
//! the durable, secret-free state a joined browser leaf needs to send payment
//! orders and track a cryptographically verified balance, and it contains all
//! of the pure verification logic. It has no `iroh`, RNG, clocks, or I/O, so
//! the state machine and every attestation check can be exercised natively.
//!
//! # Trust model
//!
//! A [`BalanceReceiptV1`] is only trusted after
//! [`verify_balance_attestation`] accepts it under a pinned ledger key. The
//! first verified receipt is **trust-on-first-use** pinned
//! ([`LedgerStateV1::pinned_ledger`]); every later receipt must be signed by
//! that same ledger or it is rejected without touching any state. v1 does not
//! attempt to chain `prev_commitment_hash`; each receipt stands alone against
//! the pinned key.
//!
//! An `Applied`/`Duplicate` settlement is only trusted after its terminal
//! [`EntryProofV1`] verifies against the pending order and a pinned leaf ledger
//! key. Leaf keys are pinned trust-on-first-use in
//! [`LedgerStateV1::pinned_leaf_keys`], or out-of-band from a receive URI; a
//! missing or failed proof is recorded as [`SettlementStateV1::Unverified`]
//! and is never reported as a completed payment.
//!
//! # Bounds
//!
//! `pending` is a bounded ring of at most [`MAX_PENDING_ORDERS`] in-flight
//! orders, `activity` at most [`MAX_ACTIVITY_ENTRIES`] entries, and
//! `pinned_leaf_keys` at most [`MAX_PINNED_LEAF_KEYS`] pins; all evict the
//! oldest entry when over capacity. Decoding never silently truncates:
//! [`LedgerStateV1::from_bytes`] rejects an over-long vector outright, and the
//! wire-controlled attestation and terminal-entry proof lengths are capped at
//! [`MAX_ATTESTATION_PROOF`] and [`MAX_ENTRY_PROOF`] before any Merkle
//! verification.

use cawala_ledger::{
    Amount, AuthRef, Hash, HopRole, LedgerPubKey, MAX_ENTRY_PROOF, NodeId, PaymentOrder, PeerRole,
    verify_applied_entry, verify_balance_attestation, verify_entry_inclusion,
};
use cawala_msg::{
    BalanceReceiptV1, EntryProofV1, OctAddr, OrderRejectV1, OrderResultV1, OrderResultV2,
    OrderResultV3, OrderStatusV1, SettlementStatusV2, ValueNoticeV1,
};
use serde::{Deserialize, Serialize};

/// Wire version of [`LedgerStateV1`].
///
/// Bump only for a deliberate, documented change to the exported blob; it is
/// checked by [`LedgerStateV1::from_bytes`]. v2 adds the bounded `settlements`
/// list (v2 settlement outcomes). v3 adds the bounded `pinned_leaf_keys`
/// mini-registry and the per-order payee/leaf binding the browser needs to
/// verify a terminal inclusion proof. A version bump discards previously
/// persisted state on import: the TOFU ledger pin, verified balance, activity,
/// and pending orders are not migrated across versions.
pub const LEDGER_STATE_VERSION: u8 = 3;

/// Maximum number of in-flight orders retained; older ones are evicted.
pub const MAX_PENDING_ORDERS: usize = 32;

/// Maximum number of recent settlement outcomes retained; older ones are
/// evicted.
pub const MAX_SETTLEMENT_RECORDS: usize = 64;

/// Maximum number of activity entries retained; older ones are evicted.
pub const MAX_ACTIVITY_ENTRIES: usize = 200;

/// Maximum number of pinned leaf ledger keys retained; older pins are evicted.
pub const MAX_PINNED_LEAF_KEYS: usize = 128;

/// Maximum accepted length of a balance-attestation Merkle proof.
///
/// This is a use-site bound on a wire-controlled `Vec`; a receipt with a longer
/// proof is refused before any hashing happens.
pub const MAX_ATTESTATION_PROOF: usize = 64;

/// How long a freshly-built payment order stays valid, in seconds.
pub const ORDER_TTL_SECS: u64 = 3600;

/// Largest integral amount representable exactly as an IEEE-754 `f64` (2^53−1).
pub const MAX_SAFE_AMOUNT: u64 = 9_007_199_254_740_991;

/// A balance that has been cryptographically verified against the pinned ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBalanceV1 {
    /// The attested balance, in the single Cawala nominal unit.
    pub amount: u64,
    /// Ledger height the balance was attested at.
    pub height: u64,
    /// The ledger state root the attestation is against.
    pub state_root: Hash,
}

/// One value movement recorded in the local activity log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityEntryV1 {
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
    pub amount: u64,
    /// The hop's position in the settlement cascade.
    pub role: HopRole,
    /// Coarse issuance timestamp.
    pub issued_at: u64,
}

/// An order sent to the routing leaf that has not yet been resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOrderV1 {
    /// The operator-signed order.
    pub order: PaymentOrder,
    /// The operator binding that travels with the order.
    pub auth: AuthRef,
    /// Unix seconds when the order envelope was sent.
    pub sent_at: u64,
    /// The payee's user `OctAddr` (from the receive URI), when known.
    ///
    /// The terminal leaf address is its parent, derived at verification time
    /// (`payee_addr.parent()`); this is the *user* address, e.g. `0.2.4`, whose
    /// leaf is `0.2`. `None` for orders remembered before the payee address was
    /// known.
    pub payee_addr: Option<OctAddr>,
    /// Whether the payer and payee share a leaf, so the terminal hop is a
    /// same-leaf `Direct` (`true`) rather than a cross-leaf `Descend` (`false`).
    pub payer_leaf: bool,
    /// An out-of-band (receive URI) leaf key pin: the payee leaf's node id and
    /// the ledger key the terminal proof must verify under.
    pub pinned_leaf: Option<(NodeId, LedgerPubKey)>,
}

/// The terminal state of a settlement payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementStateV1 {
    /// The payment applied in full.
    Applied,
    /// The order was already consumed (replay); no new entry.
    Duplicate,
    /// The payer's hop applied but a downstream hop failed; the payee was not
    /// credited.
    Partial {
        /// The hop whose hop was refused.
        failed_at: NodeId,
    },
    /// The payment was refused before the payer's hop applied.
    Rejected {
        /// Stable rejection reason.
        reason: String,
    },
    /// The outcome is unknown but the payer's hop applied (a debit is
    /// committed): a timeout or post-reservation malformed terminal. The pending
    /// order is retained so a later true terminal can still resolve it.
    Indeterminate {
        /// Stable reason the outcome could not be determined.
        reason: String,
    },
    /// A terminal `Applied`/`Duplicate` result whose inclusion proof was
    /// missing, malformed, or failed verification. The client must never report
    /// this as a completed payment.
    Unverified {
        /// Stable reason the proof was not accepted.
        reason: String,
    },
}

/// A remembered settlement outcome, keyed by the order hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRecordV1 {
    /// The order's domain-separated hash.
    pub order_hash: Hash,
    /// The terminal settlement state.
    pub state: SettlementStateV1,
}

/// The versioned, postcard-serializable ledger state blob.
///
/// This is exactly what [`crate::ClientNode::export_ledger_state`] emits and
/// [`crate::ClientNode::import_ledger_state`] consumes. It holds no secret
/// material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerStateV1 {
    /// [`LEDGER_STATE_VERSION`].
    pub version: u8,
    /// The ledger key pinned by the first verified receipt, if any.
    pub pinned_ledger: Option<LedgerPubKey>,
    /// The last cryptographically verified balance, if any.
    pub balance: Option<VerifiedBalanceV1>,
    /// Bounded activity log, oldest first.
    pub activity: Vec<ActivityEntryV1>,
    /// Bounded in-flight orders, oldest first.
    pub pending: Vec<PendingOrderV1>,
    /// Bounded recent settlement outcomes, oldest first.
    pub settlements: Vec<SettlementRecordV1>,
    /// Bounded mini key registry for leaf ledger keys, oldest first.
    ///
    /// Maps a leaf node id to the ledger key its terminal proofs must verify
    /// under. Entries are installed by TOFU on the first verified terminal
    /// proof, or out-of-band from a receive URI.
    pub pinned_leaf_keys: Vec<(NodeId, LedgerPubKey)>,
}

impl Default for LedgerStateV1 {
    fn default() -> Self {
        LedgerStateV1 {
            version: LEDGER_STATE_VERSION,
            pinned_ledger: None,
            balance: None,
            activity: Vec::new(),
            pending: Vec::new(),
            settlements: Vec::new(),
            pinned_leaf_keys: Vec::new(),
        }
    }
}

/// The result of applying one `OrderResult` to the local ledger state.
///
/// This is a plain summary; the wasm layer copies it into a [`crate::dto`]
/// event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderResultApplication {
    /// `"applied"`, `"duplicate"`, or `"rejected"`.
    pub status: &'static str,
    /// Stable rejection reason, when `status == "rejected"`.
    pub reason: Option<&'static str>,
    /// The order's domain-separated hash.
    pub order_hash: Hash,
    /// The amount the order moved.
    pub amount: u64,
    /// The payee node.
    pub counterparty: NodeId,
    /// The applied entry's ledger `seq`, when there is one.
    pub entry_seq: Option<u64>,
    /// The verified balance accompanying the result, when the leaf offered one.
    pub balance: Option<VerifiedBalanceV1>,
}

/// Validate a JavaScript-facing amount and convert it to a ledger `u64`.
///
/// Rejects non-finite values, non-positive values, fractional values, and
/// anything above [`MAX_SAFE_AMOUNT`] (which could not survive a round trip
/// through `f64`).
pub fn validate_amount(amount: f64) -> Result<u64, String> {
    if !amount.is_finite() {
        return Err("amount must be a finite number".to_string());
    }
    if amount <= 0.0 {
        return Err("amount must be greater than zero".to_string());
    }
    if amount.fract() != 0.0 {
        return Err("amount must be a whole number".to_string());
    }
    if amount > MAX_SAFE_AMOUNT as f64 {
        return Err(format!(
            "amount exceeds the maximum safe value {MAX_SAFE_AMOUNT}"
        ));
    }
    Ok(amount as u64)
}

/// Build a payment order from already-validated parts.
///
/// Kept pure so order construction can be unit-tested without an endpoint.
pub fn build_payment_order(
    from: NodeId,
    to: NodeId,
    amount: u64,
    nonce: u64,
    expiry: u64,
) -> PaymentOrder {
    PaymentOrder {
        from,
        to,
        amount: Amount::new(amount),
        nonce,
        expiry,
    }
}

/// Stable JS string for an [`OrderStatusV1`].
pub fn order_status_str(status: &OrderStatusV1) -> &'static str {
    match status {
        OrderStatusV1::Applied => "applied",
        OrderStatusV1::Duplicate => "duplicate",
        OrderStatusV1::Rejected => "rejected",
    }
}

/// Stable JS string for an [`OrderRejectV1`] (never a `Debug` rendering).
pub fn order_reject_str(reason: &OrderRejectV1) -> &'static str {
    match reason {
        OrderRejectV1::Unauthorized => "unauthorized",
        OrderRejectV1::BadRequest => "bad_request",
        OrderRejectV1::Expired => "expired",
        OrderRejectV1::InsufficientBalance => "insufficient_balance",
        OrderRejectV1::AccountNotOpened => "account_not_opened",
        OrderRejectV1::NotAChild => "not_a_child",
        OrderRejectV1::Internal => "internal",
    }
}

/// Stable JS string for a [`HopRole`].
pub fn hop_role_str(role: HopRole) -> &'static str {
    match role {
        HopRole::Ascend => "ascend",
        HopRole::Lca => "lca",
        HopRole::Descend => "descend",
        HopRole::Direct => "direct",
    }
}

/// Convert one verified [`ValueNoticeV1`] into an activity entry.
pub fn activity_from_notice(notice: &ValueNoticeV1) -> ActivityEntryV1 {
    ActivityEntryV1 {
        entry_seq: notice.entry_seq,
        entry_hash: notice.entry_hash,
        payment_id: notice.payment_id,
        from: notice.from.clone(),
        to: notice.to.clone(),
        amount: notice.amount.get(),
        role: notice.role,
        issued_at: notice.issued_at,
    }
}

impl LedgerStateV1 {
    /// A fresh, empty state at [`LEDGER_STATE_VERSION`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode as postcard bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("ledger state is always postcard-encodable")
    }

    /// Decode postcard bytes, rejecting an unsupported version, trailing
    /// bytes, or a vector that exceeds its bound.
    ///
    /// Over-long vectors are rejected rather than truncated, so a corrupted or
    /// hostile blob cannot silently lose entries.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (state, rest) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|err| format!("invalid ledger state: {err}"))?;
        if !rest.is_empty() {
            return Err(format!(
                "{} trailing byte(s) after ledger state",
                rest.len()
            ));
        }
        if state.version != LEDGER_STATE_VERSION {
            return Err(format!(
                "unsupported ledger state version {} (expected {LEDGER_STATE_VERSION})",
                state.version
            ));
        }
        if state.pending.len() > MAX_PENDING_ORDERS {
            return Err(format!(
                "ledger state has {} pending orders (max {MAX_PENDING_ORDERS})",
                state.pending.len()
            ));
        }
        if state.activity.len() > MAX_ACTIVITY_ENTRIES {
            return Err(format!(
                "ledger state has {} activity entries (max {MAX_ACTIVITY_ENTRIES})",
                state.activity.len()
            ));
        }
        if state.settlements.len() > MAX_SETTLEMENT_RECORDS {
            return Err(format!(
                "ledger state has {} settlement records (max {MAX_SETTLEMENT_RECORDS})",
                state.settlements.len()
            ));
        }
        if state.pinned_leaf_keys.len() > MAX_PINNED_LEAF_KEYS {
            return Err(format!(
                "ledger state has {} pinned leaf keys (max {MAX_PINNED_LEAF_KEYS})",
                state.pinned_leaf_keys.len()
            ));
        }
        Ok(state)
    }

    /// Retain one more in-flight order, evicting the oldest beyond
    /// [`MAX_PENDING_ORDERS`].
    ///
    /// This is the legacy shape (no payee/leaf binding); use
    /// [`LedgerStateV1::push_pending_with`] when the payee address is known.
    pub fn push_pending(&mut self, order: PaymentOrder, auth: AuthRef, sent_at: u64) {
        self.push_pending_with(order, auth, sent_at, None, false, None);
    }

    /// Retain one more in-flight order with its terminal-verification binding.
    ///
    /// `payee_addr` is the payee's *user* address (its parent is the terminal
    /// payee leaf address used to bind `proof.leaf_addr`), `payer_leaf` records
    /// whether the terminal hop is same-leaf `Direct` (`true`) or cross-leaf
    /// `Descend` (`false`), and `pinned_leaf` is an optional out-of-band
    /// receive-URI pin the terminal proof must match. Evicts the oldest beyond
    /// [`MAX_PENDING_ORDERS`].
    pub fn push_pending_with(
        &mut self,
        order: PaymentOrder,
        auth: AuthRef,
        sent_at: u64,
        payee_addr: Option<OctAddr>,
        payer_leaf: bool,
        pinned_leaf: Option<(NodeId, LedgerPubKey)>,
    ) {
        self.pending.push(PendingOrderV1 {
            order,
            auth,
            sent_at,
            payee_addr,
            payer_leaf,
            pinned_leaf,
        });
        while self.pending.len() > MAX_PENDING_ORDERS {
            self.pending.remove(0);
        }
    }

    /// Pin (or replace) the ledger key expected for a leaf node's terminal
    /// proofs, evicting the oldest beyond [`MAX_PINNED_LEAF_KEYS`].
    pub fn pin_leaf_key(&mut self, node_id: NodeId, ledger: LedgerPubKey) {
        if let Some(existing) = self
            .pinned_leaf_keys
            .iter_mut()
            .find(|(id, _)| id == &node_id)
        {
            existing.1 = ledger;
            return;
        }
        self.pinned_leaf_keys.push((node_id, ledger));
        while self.pinned_leaf_keys.len() > MAX_PINNED_LEAF_KEYS {
            self.pinned_leaf_keys.remove(0);
        }
    }

    /// The pinned ledger key for `node_id`, if any.
    pub fn pinned_leaf_key(&self, node_id: &NodeId) -> Option<LedgerPubKey> {
        self.pinned_leaf_keys
            .iter()
            .find(|(id, _)| id == node_id)
            .map(|(_, key)| *key)
    }

    /// Remove and return the pending order whose hash equals `order_hash`.
    pub fn remove_pending_by_hash(&mut self, order_hash: &Hash) -> Option<PendingOrderV1> {
        let index = self
            .pending
            .iter()
            .position(|pending| &pending.order.hash() == order_hash)?;
        Some(self.pending.remove(index))
    }

    /// Record an activity entry, dropping duplicates by `entry_hash` and
    /// evicting the oldest beyond [`MAX_ACTIVITY_ENTRIES`].
    ///
    /// Returns `false` when the entry was already present (nothing changed).
    pub fn record_activity(&mut self, entry: ActivityEntryV1) -> bool {
        if self
            .activity
            .iter()
            .any(|existing| existing.entry_hash == entry.entry_hash)
        {
            return false;
        }
        self.activity.push(entry);
        while self.activity.len() > MAX_ACTIVITY_ENTRIES {
            self.activity.remove(0);
        }
        true
    }

    /// Record a terminal settlement outcome, replacing any existing record for
    /// the same order and evicting the oldest beyond
    /// [`MAX_SETTLEMENT_RECORDS`].
    pub fn record_settlement(&mut self, order_hash: Hash, state: SettlementStateV1) {
        if let Some(existing) = self
            .settlements
            .iter_mut()
            .find(|record| record.order_hash == order_hash)
        {
            existing.state = state;
            return;
        }
        self.settlements.push(SettlementRecordV1 { order_hash, state });
        while self.settlements.len() > MAX_SETTLEMENT_RECORDS {
            self.settlements.remove(0);
        }
    }
}

/// Verify a [`BalanceReceiptV1`] and install the trust-on-first-use pin.
///
/// Steps, in order:
///
/// 1. Reject unless `attestation.edge.parent == expected_parent` and
///    `attestation.edge.child == self_node`.
/// 2. Reject unless `commitment.ledger_pubkey == attestation.ledger_pubkey ==
///    receipt.ledger_pubkey` (and `commitment.ledger_id` agrees).
/// 3. Reject an absurdly long `attestation.proof` before hashing it.
/// 4. If a ledger key is already pinned, require equality and verify under it.
///    Otherwise TOFU-pin `receipt.ledger_pubkey`, verify, and roll the pin
///    back on failure.
///
/// On success the pin stays installed and a [`VerifiedBalanceV1`] is returned;
/// on failure `state.pinned_ledger` is left exactly as it was.
pub fn verify_receipt(
    state: &mut LedgerStateV1,
    receipt: &BalanceReceiptV1,
    self_node: &str,
    expected_parent: &NodeId,
) -> Result<VerifiedBalanceV1, String> {
    if &receipt.attestation.edge.parent != expected_parent {
        return Err("wrong_edge_parent".to_string());
    }
    if receipt.attestation.edge.child.as_str() != self_node {
        return Err("wrong_edge_child".to_string());
    }

    let receipt_key = receipt.ledger_pubkey;
    if receipt.attestation.ledger_pubkey != receipt_key
        || receipt.commitment.commitment.ledger_pubkey != receipt_key
        || receipt.commitment.commitment.ledger_id != receipt_key
    {
        return Err("ledger_key_mismatch".to_string());
    }

    if receipt.attestation.proof.len() > MAX_ATTESTATION_PROOF {
        return Err("proof_too_long".to_string());
    }

    let verified = |receipt: &BalanceReceiptV1| VerifiedBalanceV1 {
        amount: receipt.attestation.balance.get(),
        height: receipt.commitment.commitment.height,
        state_root: receipt.commitment.commitment.state_root,
    };

    match state.pinned_ledger {
        Some(pinned) => {
            if pinned != receipt_key {
                return Err("ledger_key_mismatch".to_string());
            }
            verify_balance_attestation(&receipt.attestation, &receipt.commitment, &pinned)
                .map_err(|err| format!("attestation_invalid: {err}"))?;
            Ok(verified(receipt))
        }
        None => {
            state.pinned_ledger = Some(receipt_key);
            if let Err(err) =
                verify_balance_attestation(&receipt.attestation, &receipt.commitment, &receipt_key)
            {
                state.pinned_ledger = None;
                return Err(format!("attestation_invalid: {err}"));
            }
            Ok(verified(receipt))
        }
    }
}

/// Verify and apply an inbound `BalanceReceipt`, replacing the balance and
/// merging its history (plus any single `notice`) into the activity log.
///
/// The receipt is verified before any mutation, so a bad receipt leaves the
/// balance and activity untouched (aside from the pin rules in
/// [`verify_receipt`]).
pub fn apply_balance_receipt(
    state: &mut LedgerStateV1,
    receipt: &BalanceReceiptV1,
    self_node: &str,
    expected_parent: &NodeId,
) -> Result<VerifiedBalanceV1, String> {
    if !receipt.history_within_bound() {
        return Err("history_too_long".to_string());
    }
    let verified = verify_receipt(state, receipt, self_node, expected_parent)?;
    if let Some(notice) = &receipt.notice {
        state.record_activity(activity_from_notice(notice));
    }
    for notice in &receipt.history {
        state.record_activity(activity_from_notice(notice));
    }
    state.balance = Some(verified.clone());
    Ok(verified)
}

/// Match an inbound `OrderResult` against the pending set and apply it
/// atomically.
///
/// The order is found by its domain-separated hash. Any accompanying balance
/// receipt is verified *before* any mutation, so a verification failure leaves
/// the balance and pending set unchanged. On success the pending order is
/// removed; for non-rejected outcomes with an entry, an activity entry is
/// recorded and the (optional) verified balance installed.
pub fn apply_order_result(
    state: &mut LedgerStateV1,
    result: &OrderResultV1,
    self_node: &str,
    expected_parent: &NodeId,
    now: u64,
) -> Result<OrderResultApplication, String> {
    let index = state
        .pending
        .iter()
        .position(|pending| pending.order.hash() == result.order_hash)
        .ok_or_else(|| "unknown_order".to_string())?;

    // Verify any offered balance before mutating anything.
    let verified_balance = match &result.balance {
        Some(receipt) => Some(verify_receipt(state, receipt, self_node, expected_parent)?),
        None => None,
    };

    let pending = state.pending.remove(index);
    let status = order_status_str(&result.status);
    let reason = result.reason.as_ref().map(order_reject_str);

    if status != "rejected"
        && let (Some(entry_seq), Some(entry_hash)) = (result.entry_seq, result.entry_hash)
    {
        state.record_activity(ActivityEntryV1 {
            entry_seq,
            entry_hash,
            payment_id: pending.order.hash(),
            from: pending.order.from.clone(),
            to: pending.order.to.clone(),
            amount: pending.order.amount.get(),
            role: HopRole::Direct,
            issued_at: now,
        });
    }

    if let Some(balance) = &verified_balance {
        state.balance = Some(balance.clone());
    }

    Ok(OrderResultApplication {
        status,
        reason,
        order_hash: result.order_hash,
        amount: pending.order.amount.get(),
        counterparty: pending.order.to.clone(),
        entry_seq: result.entry_seq,
        balance: verified_balance,
    })
}

/// The result of applying one settlement `OrderResultV2`/`OrderResultV3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementApplication {
    /// `"applied"`, `"duplicate"`, `"partial"`, `"rejected"`,
    /// `"indeterminate"`, or `"unverified"`.
    pub status: &'static str,
    /// Stable reason, when the outcome is `"partial"`, `"rejected"`,
    /// `"indeterminate"`, or `"unverified"`.
    pub reason: Option<String>,
    /// The failing hop, when the outcome is `"partial"`.
    pub failed_at: Option<NodeId>,
    /// The order's domain-separated hash.
    pub order_hash: Hash,
    /// The amount the order moved.
    pub amount: u64,
    /// The payee node.
    pub counterparty: NodeId,
    /// The terminal ledger `seq`, when the outcome carries a verified one.
    pub entry_seq: Option<u64>,
    /// The verified balance accompanying the result, when the leaf offered one.
    pub balance: Option<VerifiedBalanceV1>,
}

/// Fully verify a terminal inclusion proof for an `Applied`/`Duplicate`
/// settlement before the client treats it as success.
///
/// Read-only: the caller installs the trust-on-first-use leaf pin only after
/// this returns `Ok`. All of the following must hold, in order:
///
/// 1. the proof structurally validates ([`EntryProofV1::validate`]) and its
///    audit path is within [`MAX_ENTRY_PROOF`] (redundant with `validate`, kept
///    as an explicit use-site bound);
/// 2. `proof.leaf_addr` equals the pending order's payee **leaf** address (the
///    payee user address's parent, e.g. `0.2` for `0.2.4`), when a payee
///    address is known — the node signs the terminal proof with the terminal
///    leaf's own asserted address, not the payee user address;
/// 3. `order_hash` is the pending order's hash and the entry is the terminal
///    `Direct`/`Descend` hop for the order and payer role
///    ([`verify_applied_entry`]);
/// 4. the entry verifies under a [`PeerRole::Node`] signer's ledger key, the
///    commitment names that same key, and the RFC 6962 inclusion proof verifies
///    against the committed entry root;
/// 5. the signer's leaf key matches any pinned key, or the pending out-of-band
///    receive-URI pin, and would otherwise be eligible for TOFU pinning.
fn verify_settlement_proof(
    state: &LedgerStateV1,
    pending: &PendingOrderV1,
    order_hash: &Hash,
    proof: &EntryProofV1,
) -> Result<(), String> {
    // 1. Structural validation.
    proof
        .validate()
        .map_err(|err| format!("proof invalid: {err}"))?;
    if proof.inclusion.proof.len() > MAX_ENTRY_PROOF {
        return Err("proof too long".to_string());
    }

    // 2. Bind the proof to the payee's terminal leaf. The node builds
    //    `proof.leaf_addr` from the terminal leaf's own asserted address, so
    //    compare it to the payee *user* address's parent, not the user address
    //    itself. (For a same-leaf payment payer and payee share a leaf, so this
    //    is that shared leaf's address.)
    if let Some(payee) = &pending.payee_addr
        && payee.parent().as_ref() != Some(&proof.leaf_addr)
    {
        return Err("proof leaf address mismatch".to_string());
    }

    // 3. The claimed terminal entry must be this order's applied hop.
    if order_hash != &pending.order.hash() {
        return Err("proof order hash mismatch".to_string());
    }
    verify_applied_entry(&proof.entry, &pending.order, pending.payer_leaf)
        .map_err(|err| format!("terminal entry shape: {err}"))?;

    // 4. Signature, signer role, commitment binding, and Merkle inclusion.
    if proof.signer.role != PeerRole::Node {
        return Err("proof signer is not a node".to_string());
    }
    let signer_ledger = proof
        .signer
        .ledger
        .ok_or_else(|| "proof signer has no ledger key".to_string())?;
    proof
        .entry
        .verify(&signer_ledger)
        .map_err(|err| format!("terminal entry signature: {err}"))?;
    if proof.commitment.commitment.ledger_pubkey != signer_ledger {
        return Err("proof commitment key mismatch".to_string());
    }
    if proof.commitment.commitment.entry_count != u64::from(proof.inclusion.tree_size) {
        return Err("proof entry count mismatch".to_string());
    }
    if proof.inclusion.index >= proof.inclusion.tree_size {
        return Err("proof index out of range".to_string());
    }
    if proof.entry.entry.seq >= u64::from(proof.inclusion.tree_size) {
        return Err("proof entry seq out of range".to_string());
    }
    if !verify_entry_inclusion(
        &proof.entry,
        &proof.inclusion,
        &proof.commitment.commitment.entry_root,
    ) {
        return Err("proof inclusion failed".to_string());
    }

    // 5. Key pin: an existing pin must match, and a pending out-of-band pin
    //    must match before the key may be TOFU-pinned.
    let node_id = proof.signer.node_id.clone();
    match state.pinned_leaf_key(&node_id) {
        Some(pinned) => {
            if pinned != signer_ledger {
                return Err("pinned leaf key mismatch".to_string());
            }
        }
        None => {
            if let Some((pin_node, pin_key)) = &pending.pinned_leaf
                && (pin_node != &node_id || pin_key != &signer_ledger)
            {
                return Err("receive uri pin mismatch".to_string());
            }
        }
    }
    Ok(())
}

/// The terminal settlement state for an `Applied`/`Duplicate` result.
///
/// Requires and verifies the terminal inclusion proof. On success it installs
/// (or confirms) the leaf key pin and returns the `success` state; on a missing
/// or rejected proof it returns [`SettlementStateV1::Unverified`] and installs
/// nothing.
fn terminal_settlement_state(
    state: &mut LedgerStateV1,
    pending: &PendingOrderV1,
    order_hash: &Hash,
    proof: Option<&EntryProofV1>,
    success: SettlementStateV1,
) -> SettlementStateV1 {
    let Some(proof) = proof else {
        return SettlementStateV1::Unverified {
            reason: "missing proof".to_string(),
        };
    };
    if let Err(reason) = verify_settlement_proof(state, pending, order_hash, proof) {
        return SettlementStateV1::Unverified { reason };
    }
    if let Some(ledger) = proof.signer.ledger {
        state.pin_leaf_key(proof.signer.node_id.clone(), ledger);
    }
    success
}

/// The shared implementation behind [`apply_settlement_result`] (v3, with a
/// proof) and [`apply_settlement_result_v2`] (v2, no proof).
fn apply_settlement_result_inner(
    state: &mut LedgerStateV1,
    order_hash: Hash,
    status: &SettlementStatusV2,
    balance: Option<&BalanceReceiptV1>,
    proof: Option<&EntryProofV1>,
    self_node: &str,
    expected_parent: &NodeId,
) -> Result<SettlementApplication, String> {
    let index = state
        .pending
        .iter()
        .position(|pending| pending.order.hash() == order_hash)
        .ok_or_else(|| "unknown_order".to_string())?;
    let pending = state.pending[index].clone();

    // Verify any offered balance before mutating anything.
    let verified_balance = match balance {
        Some(receipt) => Some(verify_receipt(state, receipt, self_node, expected_parent)?),
        None => None,
    };

    // Every outcome is terminal client-side (see the doc on
    // [`apply_settlement_result`]).
    let (status_str, reason, failed_at, entry_seq, settlement_state) = match status {
        SettlementStatusV2::Applied { entry_seq, .. } => {
            let settlement_state = terminal_settlement_state(
                state,
                &pending,
                &order_hash,
                proof,
                SettlementStateV1::Applied,
            );
            match &settlement_state {
                SettlementStateV1::Applied => {
                    ("applied", None, None, Some(*entry_seq), settlement_state.clone())
                }
                SettlementStateV1::Unverified { reason } => (
                    "unverified",
                    Some(reason.clone()),
                    None,
                    None,
                    settlement_state.clone(),
                ),
                _ => unreachable!("applied settles only as applied or unverified"),
            }
        }
        SettlementStatusV2::Duplicate { entry_seq, .. } => {
            let settlement_state = terminal_settlement_state(
                state,
                &pending,
                &order_hash,
                proof,
                SettlementStateV1::Duplicate,
            );
            match &settlement_state {
                SettlementStateV1::Duplicate => (
                    "duplicate",
                    None,
                    None,
                    Some(*entry_seq),
                    settlement_state.clone(),
                ),
                SettlementStateV1::Unverified { reason } => (
                    "unverified",
                    Some(reason.clone()),
                    None,
                    None,
                    settlement_state.clone(),
                ),
                _ => unreachable!("duplicate settles only as duplicate or unverified"),
            }
        }
        SettlementStatusV2::Partial { failed_at, reason } => (
            "partial",
            Some(order_reject_str(reason).to_string()),
            Some(failed_at.clone()),
            None,
            SettlementStateV1::Partial {
                failed_at: failed_at.clone(),
            },
        ),
        SettlementStatusV2::Rejected { reason } => (
            "rejected",
            Some(order_reject_str(reason).to_string()),
            None,
            None,
            SettlementStateV1::Rejected {
                reason: order_reject_str(reason).to_string(),
            },
        ),
        SettlementStatusV2::Indeterminate { reason } => (
            "indeterminate",
            Some(order_reject_str(reason).to_string()),
            None,
            None,
            SettlementStateV1::Indeterminate {
                reason: order_reject_str(reason).to_string(),
            },
        ),
    };

    state.pending.remove(index);
    if let Some(balance) = &verified_balance {
        state.balance = Some(balance.clone());
    }
    state.record_settlement(order_hash, settlement_state);

    Ok(SettlementApplication {
        status: status_str,
        reason,
        failed_at,
        order_hash,
        amount: pending.order.amount.get(),
        counterparty: pending.order.to.clone(),
        entry_seq,
        balance: verified_balance,
    })
}

/// Match an inbound v3 settlement result against the pending set and apply it
/// atomically.
///
/// The order is found by its domain-separated hash. Any accompanying balance is
/// verified *before* any mutation, so a verification failure leaves the balance,
/// pending set, and settlement log unchanged. For `Applied`/`Duplicate` the
/// terminal inclusion proof is **required** and fully verified (see
/// [`verify_settlement_proof`]); a missing or invalid proof records
/// [`SettlementStateV1::Unverified`] and never reports success.
///
/// Every outcome is terminal client-side: the pending order is removed for all
/// statuses (including `Indeterminate` and `Unverified`), because the origin's
/// timeout sweep drops its own pending and a later terminal would not arrive.
/// The result is **advisory** (and `Partial`/`Indeterminate`/`Unverified` are
/// explicitly not a completed payment); the verified receipt remains the signed
/// ground truth.
///
/// # Known limitation
///
/// Settled outcomes are recorded in [`LedgerStateV1::settlements`], but a
/// reload does not reconstruct them into the activity log (the payer's own hop
/// entry is not carried in the result).
pub fn apply_settlement_result(
    state: &mut LedgerStateV1,
    result: &OrderResultV3,
    self_node: &str,
    expected_parent: &NodeId,
    _now: u64,
) -> Result<SettlementApplication, String> {
    apply_settlement_result_inner(
        state,
        result.order_hash,
        &result.status,
        result.balance.as_ref(),
        result.proof.as_ref(),
        self_node,
        expected_parent,
    )
}

/// Match an inbound v2 settlement result (no proof) against the pending set and
/// apply it atomically.
///
/// Identical to [`apply_settlement_result`] except that a v2 `Applied`/
/// `Duplicate` carries no terminal proof, so it is recorded as
/// [`SettlementStateV1::Unverified`] rather than success. The remaining
/// statuses keep their existing semantics.
pub fn apply_settlement_result_v2(
    state: &mut LedgerStateV1,
    result: &OrderResultV2,
    self_node: &str,
    expected_parent: &NodeId,
    _now: u64,
) -> Result<SettlementApplication, String> {
    apply_settlement_result_inner(
        state,
        result.order_hash,
        &result.status,
        result.balance.as_ref(),
        None,
        self_node,
        expected_parent,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{
        AccountRef, Commitment, Entry, EntryBody, EntryInclusionProof, Ledger, LedgerSecretKey,
        MemLog, OperatorSecretKey, PeerKeys, PeerRole, Posting, SignedAmount, SignedCommitment,
        SignedEntry, attest_balance, build_commitment, entry_hash, entry_root,
    };
    use cawala_msg::MsgId;
    use cawala_topology::ChildKind;

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn ledger(seed: u8) -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([seed; 32])
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    /// A root ledger that opens `n` accounts (`n0..n{n-1}`), mirroring the
    /// fixture in `cawala_ledger::commit`'s tests.
    fn ledger_with(n: usize, key: &LedgerSecretKey) -> Ledger<MemLog> {
        let mut ledger = Ledger::new_root(key.public());
        let mut prev = Hash::ZERO;
        for seq in 0..n {
            let entry = Entry {
                ledger_id: key.public(),
                seq: seq as u64,
                height: seq as u64,
                prev_hash: prev,
                issued_at: seq as u64,
                body: EntryBody::OpenAccount {
                    child: NodeId::from(format!("n{seq}")),
                    kind: ChildKind::Node,
                },
                postings: vec![],
                auth: None,
            };
            let signed = SignedEntry::sign(entry, key).unwrap();
            prev = entry_hash(&signed.entry).unwrap();
            ledger.append(signed).unwrap();
        }
        ledger
    }

    /// A cryptographically valid receipt for `child` attesting its balance at
    /// the head of a fresh ledger.
    fn receipt_for(key: &LedgerSecretKey, parent: &NodeId, child: &NodeId) -> BalanceReceiptV1 {
        let ledger = ledger_with(3, key);
        let commitment =
            SignedCommitment::sign(build_commitment(&ledger, Hash::ZERO, 1).unwrap(), key)
                .unwrap();
        let attestation = attest_balance(&ledger, parent, child).unwrap();
        BalanceReceiptV1 {
            reply_to: None,
            query_id: None,
            ledger_pubkey: key.public(),
            attestation,
            commitment,
            history: vec![],
            notice: None,
        }
    }

    fn notice(seq: u64, hash_byte: u8) -> ValueNoticeV1 {
        ValueNoticeV1 {
            entry_seq: seq,
            entry_hash: Hash::from_bytes([hash_byte; 32]),
            payment_id: Hash::from_bytes([0x22; 32]),
            from: node("n1"),
            to: node("n2"),
            amount: Amount::new(5),
            role: HopRole::Direct,
            issued_at: 10,
        }
    }

    fn pending_order(nonce: u64) -> PaymentOrder {
        build_payment_order(node("n1"), node("n2"), 5, nonce, u64::MAX)
    }

    /// Push `order` into `state` with an auth that actually matches it.
    ///
    /// The ledger key parameter is kept so call sites stay symmetric with the
    /// receipt fixtures; order authorisation uses an operator key.
    fn push_pending(state: &mut LedgerStateV1, _ledger_key: &LedgerSecretKey, order: PaymentOrder) {
        let auth = order.authorize(&operator(1)).unwrap();
        state.push_pending(order, auth, 1);
    }

    fn result_for(order_hash: Hash, status: OrderStatusV1) -> OrderResultV1 {
        OrderResultV1 {
            reply_to: MsgId([0x11; 16]),
            order_hash,
            status,
            entry_seq: Some(7),
            entry_hash: Some(Hash::from_bytes([0x55; 32])),
            reason: None,
            balance: None,
        }
    }

    fn settlement_result(order_hash: Hash, status: SettlementStatusV2) -> OrderResultV2 {
        OrderResultV2 {
            reply_to: MsgId([0x11; 16]),
            order_hash,
            status,
            balance: None,
        }
    }

    fn settlement_result_v3(
        order_hash: Hash,
        status: SettlementStatusV2,
        proof: Option<EntryProofV1>,
    ) -> OrderResultV3 {
        OrderResultV3 {
            reply_to: MsgId([0x11; 16]),
            order_hash,
            status,
            balance: None,
            proof,
        }
    }

    /// Build a fully valid same-leaf `Direct` terminal proof for `order`.
    ///
    /// The single-leaf entry tree is `leaf_hash(entry_hash(entry))`; the entry
    /// is signed by `key` and credits the order's payee while debiting its
    /// payer, so it satisfies `verify_applied_entry(.., payer_leaf = true)` and
    /// `verify_entry_inclusion`. `leaf_addr` is the **terminal leaf's own
    /// asserted address** (the node's contract), not the payee user address.
    fn direct_terminal_proof(
        key: &LedgerSecretKey,
        leaf_node: &str,
        leaf_addr: &str,
        order: &PaymentOrder,
    ) -> EntryProofV1 {
        let amount = order.amount.get() as i64;
        let entry = Entry {
            ledger_id: key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::Transfer {
                payment_id: order.hash(),
                amount: order.amount,
                role: HopRole::Direct,
            },
            postings: vec![
                Posting {
                    account: AccountRef::Child(order.from.clone()),
                    delta: SignedAmount::new(-amount),
                },
                Posting {
                    account: AccountRef::Child(order.to.clone()),
                    delta: SignedAmount::new(amount),
                },
            ],
            auth: Some(order.authorize(&operator(1)).unwrap()),
        };
        let signed = SignedEntry::sign(entry, key).unwrap();
        let root = entry_root(std::slice::from_ref(&signed)).unwrap();
        let commitment = Commitment {
            ledger_id: key.public(),
            ledger_pubkey: key.public(),
            height: 1,
            entry_count: 1,
            entry_root: root,
            state_root: Hash::ZERO,
            prev_commitment_hash: Hash::ZERO,
            issued_at: 0,
        };
        EntryProofV1 {
            entry: signed,
            signer: PeerKeys {
                node_id: node(leaf_node),
                operator: operator(1).public(),
                ledger: Some(key.public()),
                role: PeerRole::Node,
            },
            leaf_addr: leaf_addr.parse().unwrap(),
            commitment: SignedCommitment::sign(commitment, key).unwrap(),
            inclusion: EntryInclusionProof {
                index: 0,
                tree_size: 1,
                proof: vec![],
            },
        }
    }

    /// Build a fully valid cross-leaf `Descend` terminal proof for `order`.
    ///
    /// This mirrors the payee leaf's actual terminal hop: the entry credits
    /// `order.to` from the parent-side `Parent` account, so it satisfies
    /// `verify_applied_entry(.., payer_leaf = false)`. `leaf_addr` is the
    /// **terminal payee leaf's own asserted address**, e.g. `0.2` for a payee
    /// user at `0.2.4`.
    fn descend_terminal_proof(
        key: &LedgerSecretKey,
        leaf_node: &str,
        leaf_addr: &str,
        order: &PaymentOrder,
    ) -> EntryProofV1 {
        let amount = order.amount.get() as i64;
        let entry = Entry {
            ledger_id: key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::Transfer {
                payment_id: order.hash(),
                amount: order.amount,
                role: HopRole::Descend,
            },
            postings: vec![
                Posting {
                    account: AccountRef::Parent,
                    delta: SignedAmount::new(amount),
                },
                Posting {
                    account: AccountRef::Child(order.to.clone()),
                    delta: SignedAmount::new(amount),
                },
            ],
            auth: Some(order.authorize(&operator(1)).unwrap()),
        };
        let signed = SignedEntry::sign(entry, key).unwrap();
        let root = entry_root(std::slice::from_ref(&signed)).unwrap();
        let commitment = Commitment {
            ledger_id: key.public(),
            ledger_pubkey: key.public(),
            height: 1,
            entry_count: 1,
            entry_root: root,
            state_root: Hash::ZERO,
            prev_commitment_hash: Hash::ZERO,
            issued_at: 0,
        };
        EntryProofV1 {
            entry: signed,
            signer: PeerKeys {
                node_id: node(leaf_node),
                operator: operator(1).public(),
                ledger: Some(key.public()),
                role: PeerRole::Node,
            },
            leaf_addr: leaf_addr.parse().unwrap(),
            commitment: SignedCommitment::sign(commitment, key).unwrap(),
            inclusion: EntryInclusionProof {
                index: 0,
                tree_size: 1,
                proof: vec![],
            },
        }
    }

    /// Push `order` with a same-leaf `Direct` binding to `payee_addr`.
    fn push_pending_direct(
        state: &mut LedgerStateV1,
        order: PaymentOrder,
        payee_addr: &str,
        pinned_leaf: Option<(NodeId, LedgerPubKey)>,
    ) {
        let auth = order.authorize(&operator(1)).unwrap();
        state.push_pending_with(
            order,
            auth,
            1,
            Some(payee_addr.parse().unwrap()),
            true,
            pinned_leaf,
        );
    }

    /// Push `order` with a cross-leaf `Descend` binding to `payee_addr`.
    fn push_pending_cross_leaf(
        state: &mut LedgerStateV1,
        order: PaymentOrder,
        payee_addr: &str,
        pinned_leaf: Option<(NodeId, LedgerPubKey)>,
    ) {
        let auth = order.authorize(&operator(1)).unwrap();
        state.push_pending_with(
            order,
            auth,
            1,
            Some(payee_addr.parse().unwrap()),
            false,
            pinned_leaf,
        );
    }

    // -- amount validation -------------------------------------------------

    #[test]
    fn amount_validation_rejects_bad_values_accepts_good() {
        assert!(validate_amount(f64::NAN).is_err());
        assert!(validate_amount(f64::INFINITY).is_err());
        assert!(validate_amount(-1.0).is_err());
        assert!(validate_amount(0.0).is_err());
        assert!(validate_amount(1.5).is_err());
        assert!(validate_amount((MAX_SAFE_AMOUNT as f64) + 1.0).is_err());
        assert_eq!(validate_amount(1.0).unwrap(), 1);
        assert_eq!(validate_amount(42.0).unwrap(), 42);
        assert_eq!(
            validate_amount(MAX_SAFE_AMOUNT as f64).unwrap(),
            MAX_SAFE_AMOUNT
        );
    }

    #[test]
    fn order_builder_maps_all_fields() {
        let order = build_payment_order(node("alice"), node("bob"), 7, 9, 100);
        assert_eq!(order.from, node("alice"));
        assert_eq!(order.to, node("bob"));
        assert_eq!(order.amount, Amount::new(7));
        assert_eq!(order.nonce, 9);
        assert_eq!(order.expiry, 100);
    }

    // -- export/import -----------------------------------------------------

    #[test]
    fn export_import_round_trip() {
        let key = ledger(1);
        let mut state = LedgerStateV1::new();
        state.pinned_ledger = Some(key.public());
        state.balance = Some(VerifiedBalanceV1 {
            amount: 12,
            height: 3,
            state_root: Hash::from_bytes([0x33; 32]),
        });
        state.record_activity(activity_from_notice(&notice(1, 0xaa)));
        state.pin_leaf_key(node("leaf-a"), key.public());
        push_pending(&mut state, &key, pending_order(1));

        let bytes = state.to_bytes();
        let back = LedgerStateV1::from_bytes(&bytes).unwrap();
        assert_eq!(back, state);
        assert_eq!(back.pinned_leaf_keys.len(), 1);
    }

    #[test]
    fn pinned_leaf_keys_evict_oldest_and_are_bounded() {
        let mut state = LedgerStateV1::new();
        for i in 0..(MAX_PINNED_LEAF_KEYS + 5) {
            let key = ledger((i % 250) as u8 + 1);
            state.pin_leaf_key(node(&format!("leaf-{i}")), key.public());
        }
        assert_eq!(state.pinned_leaf_keys.len(), MAX_PINNED_LEAF_KEYS);
        assert!(state.pinned_leaf_key(&node("leaf-0")).is_none());
        // Re-pinning an existing node replaces in place (no growth).
        let initial = state.pinned_leaf_keys.len();
        assert!(state.pinned_leaf_key(&node("leaf-5")).is_some());
        state.pin_leaf_key(node("leaf-5"), ledger(9).public());
        assert_eq!(state.pinned_leaf_keys.len(), initial);
        assert_eq!(
            state.pinned_leaf_key(&node("leaf-5")),
            Some(ledger(9).public())
        );

        // An over-long vector is rejected on import rather than truncated.
        let mut over = LedgerStateV1::new();
        for i in 0..=MAX_PINNED_LEAF_KEYS {
            over.pinned_leaf_keys
                .push((node(&format!("l{i}")), ledger(1).public()));
        }
        assert!(LedgerStateV1::from_bytes(&over.to_bytes()).is_err());
    }

    #[test]
    fn import_rejects_garbage_wrong_version_and_trailing_bytes() {
        assert!(LedgerStateV1::from_bytes(b"not postcard").is_err());
        let mut wrong = LedgerStateV1::new();
        wrong.version = LEDGER_STATE_VERSION + 1;
        let bytes = wrong.to_bytes();
        assert!(LedgerStateV1::from_bytes(&bytes).is_err());

        let mut good = LedgerStateV1::new().to_bytes();
        good.push(0x00);
        assert!(LedgerStateV1::from_bytes(&good).is_err());
    }

    #[test]
    fn import_rejects_over_long_vectors_instead_of_truncating() {
        let mut state = LedgerStateV1::new();
        for i in 0..=MAX_PENDING_ORDERS {
            state.pending.push(PendingOrderV1 {
                order: build_payment_order(node("a"), node("b"), 1, i as u64, 1),
                auth: pending_order(i as u64)
                    .authorize(&operator(1))
                    .unwrap(),
                sent_at: i as u64,
                payee_addr: None,
                payer_leaf: false,
                pinned_leaf: None,
            });
        }
        assert!(LedgerStateV1::from_bytes(&state.to_bytes()).is_err());

        let mut state = LedgerStateV1::new();
        for i in 0..=MAX_ACTIVITY_ENTRIES {
            state.activity.push(ActivityEntryV1 {
                entry_seq: i as u64,
                entry_hash: Hash::from_bytes([(i % 251) as u8; 32]),
                payment_id: Hash::ZERO,
                from: node("a"),
                to: node("b"),
                amount: 1,
                role: HopRole::Direct,
                issued_at: 0,
            });
        }
        assert!(LedgerStateV1::from_bytes(&state.to_bytes()).is_err());
    }

    #[test]
    fn pending_and_activity_evict_oldest() {
        let mut state = LedgerStateV1::new();
        for i in 0..(MAX_PENDING_ORDERS + 5) as u64 {
            let order = build_payment_order(node("a"), node("b"), 1, i, 1);
            let auth = order.authorize(&operator(1)).unwrap();
            state.push_pending(order, auth, i);
        }
        assert_eq!(state.pending.len(), MAX_PENDING_ORDERS);
        // The oldest nonce is evicted; the newest is retained.
        assert_eq!(state.pending.first().unwrap().order.nonce, 5);
        assert_eq!(
            state.pending.last().unwrap().order.nonce,
            (MAX_PENDING_ORDERS + 4) as u64
        );

        let mut state = LedgerStateV1::new();
        for i in 0..(MAX_ACTIVITY_ENTRIES + 5) as u64 {
            state.record_activity(ActivityEntryV1 {
                entry_seq: i,
                entry_hash: Hash::from_bytes([(i % 251) as u8; 32]),
                payment_id: Hash::ZERO,
                from: node("a"),
                to: node("b"),
                amount: 1,
                role: HopRole::Direct,
                issued_at: 0,
            });
        }
        assert_eq!(state.activity.len(), MAX_ACTIVITY_ENTRIES);
        assert_eq!(state.activity.first().unwrap().entry_seq, 5);
    }

    #[test]
    fn activity_dedups_by_entry_hash_and_pending_removal_works() {
        let mut state = LedgerStateV1::new();
        assert!(state.record_activity(activity_from_notice(&notice(1, 0xaa))));
        assert!(!state.record_activity(activity_from_notice(&notice(1, 0xaa))));
        assert_eq!(state.activity.len(), 1);

        let key = ledger(1);
        let order = pending_order(3);
        let hash = order.hash();
        push_pending(&mut state, &key, order);
        assert!(state.remove_pending_by_hash(&hash).is_some());
        assert!(state.remove_pending_by_hash(&hash).is_none());
        assert!(state.pending.is_empty());
    }

    // -- receipt verification / pinning ------------------------------------

    #[test]
    fn first_verified_receipt_pins_the_ledger() {
        let key = ledger(1);
        let parent = node("parent");
        let receipt = receipt_for(&key, &parent, &node("n1"));
        let mut state = LedgerStateV1::new();

        let verified = verify_receipt(&mut state, &receipt, "n1", &parent).unwrap();
        assert_eq!(state.pinned_ledger, Some(key.public()));
        assert_eq!(verified.height, 3);
        assert_eq!(verified.amount, 0);
        assert_eq!(verified.state_root, receipt.commitment.commitment.state_root);
    }

    #[test]
    fn different_ledger_key_is_rejected_without_state_change() {
        let pinned = ledger(1);
        let other = ledger(2);
        let parent = node("parent");
        let receipt = receipt_for(&other, &parent, &node("n1"));
        let mut state = LedgerStateV1::new();
        state.pinned_ledger = Some(pinned.public());
        state.balance = Some(VerifiedBalanceV1 {
            amount: 5,
            height: 1,
            state_root: Hash::ZERO,
        });

        assert!(verify_receipt(&mut state, &receipt, "n1", &parent).is_err());
        assert_eq!(state.pinned_ledger, Some(pinned.public()));
        assert_eq!(state.balance.as_ref().unwrap().amount, 5);
    }

    #[test]
    fn failing_attestation_rolls_back_pin_and_leaves_balance_untouched() {
        let key = ledger(1);
        let parent = node("parent");
        let mut receipt = receipt_for(&key, &parent, &node("n1"));
        receipt.attestation.balance = Amount::new(999); // proof no longer matches

        let mut state = LedgerStateV1::new();
        assert!(verify_receipt(&mut state, &receipt, "n1", &parent).is_err());
        assert!(state.pinned_ledger.is_none(), "pin must roll back");
        assert!(state.balance.is_none(), "balance must not change");
    }

    #[test]
    fn receipt_binding_rejects_wrong_edge_and_key_mismatch() {
        let key = ledger(1);
        let parent = node("parent");
        let receipt = receipt_for(&key, &parent, &node("n1"));
        let mut state = LedgerStateV1::new();

        // Wrong parent edge.
        assert!(verify_receipt(&mut state, &receipt, "n1", &node("other")).is_err());
        // Wrong child (our node id).
        assert!(verify_receipt(&mut state, &receipt, "n2", &parent).is_err());
        assert!(state.pinned_ledger.is_none());

        // Attestation key disagrees with the top-level key.
        let mut tampered = receipt.clone();
        tampered.attestation.ledger_pubkey = ledger(9).public();
        assert!(verify_receipt(&mut state, &tampered, "n1", &parent).is_err());

        // Absurd proof length is rejected.
        let mut long = receipt.clone();
        long.attestation.proof = vec![Hash::ZERO; MAX_ATTESTATION_PROOF + 1];
        assert_eq!(
            verify_receipt(&mut state, &long, "n1", &parent),
            Err("proof_too_long".to_string())
        );
    }

    #[test]
    fn balance_receipt_merges_history_and_replaces_balance() {
        let key = ledger(1);
        let parent = node("parent");
        let mut receipt = receipt_for(&key, &parent, &node("n1"));
        receipt.history = vec![notice(1, 0xaa), notice(2, 0xbb)];
        receipt.notice = Some(notice(3, 0xcc));

        let mut state = LedgerStateV1::new();
        let verified = apply_balance_receipt(&mut state, &receipt, "n1", &parent).unwrap();
        assert_eq!(verified.height, 3);
        assert_eq!(state.activity.len(), 3);
        assert_eq!(state.balance.as_ref().unwrap().amount, 0);

        // Duplicate history is deduplicated.
        let before = state.activity.len();
        apply_balance_receipt(&mut state, &receipt, "n1", &parent).unwrap();
        assert_eq!(state.activity.len(), before);
    }

    // -- order results -----------------------------------------------------

    #[test]
    fn applied_order_result_moves_pending_to_activity() {
        let key = ledger(1);
        let parent = node("parent");
        let order = pending_order(1);
        let hash = order.hash();
        let mut state = LedgerStateV1::new();
        push_pending(&mut state, &key, order);

        let result = result_for(hash, OrderStatusV1::Applied);
        let app = apply_order_result(&mut state, &result, "n1", &parent, 42).unwrap();
        assert_eq!(app.status, "applied");
        assert_eq!(app.entry_seq, Some(7));
        assert_eq!(app.amount, 5);
        assert_eq!(app.counterparty, node("n2"));
        assert!(state.pending.is_empty());
        assert_eq!(state.activity.len(), 1);
        assert_eq!(state.activity[0].issued_at, 42);
    }

    #[test]
    fn duplicate_and_rejected_order_results_map_stably() {
        let key = ledger(1);
        let parent = node("parent");

        // Duplicate.
        let order = pending_order(1);
        let hash = order.hash();
        let mut state = LedgerStateV1::new();
        push_pending(&mut state, &key, order);
        let app = apply_order_result(
            &mut state,
            &result_for(hash, OrderStatusV1::Duplicate),
            "n1",
            &parent,
            0,
        )
        .unwrap();
        assert_eq!(app.status, "duplicate");
        assert!(state.pending.is_empty());

        // Rejected.
        let order = pending_order(2);
        let hash = order.hash();
        let mut state = LedgerStateV1::new();
        push_pending(&mut state, &key, order);
        let mut result = result_for(hash, OrderStatusV1::Rejected);
        result.reason = Some(OrderRejectV1::InsufficientBalance);
        result.entry_seq = None;
        result.entry_hash = None;
        let app = apply_order_result(&mut state, &result, "n1", &parent, 0).unwrap();
        assert_eq!(app.status, "rejected");
        assert_eq!(app.reason, Some("insufficient_balance"));
        assert!(state.pending.is_empty());
        assert!(state.activity.is_empty());
    }

    #[test]
    fn unknown_order_result_is_rejected_without_mutation() {
        let parent = node("parent");
        let mut state = LedgerStateV1::new();
        let result = result_for(Hash::from_bytes([0x99; 32]), OrderStatusV1::Applied);
        assert_eq!(
            apply_order_result(&mut state, &result, "n1", &parent, 0),
            Err("unknown_order".to_string())
        );
        assert!(state.pending.is_empty());
        assert!(state.balance.is_none());
    }

    #[test]
    fn settlement_result_maps_non_terminal_statuses() {
        let key = ledger(1);
        let parent = node("parent");

        // partial (payer debited, downstream hop failed)
        let order = pending_order(3);
        let hash = order.hash();
        let mut state = LedgerStateV1::new();
        push_pending(&mut state, &key, order);
        let app = apply_settlement_result_v2(
            &mut state,
            &settlement_result(
                hash,
                SettlementStatusV2::Partial {
                    failed_at: node("leaf-b"),
                    reason: OrderRejectV1::InsufficientBalance,
                },
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();
        assert_eq!(app.status, "partial");
        assert_eq!(app.reason, Some("insufficient_balance".to_string()));
        assert_eq!(app.failed_at, Some(node("leaf-b")));
        assert!(state.pending.is_empty());
        assert_eq!(
            state.settlements[0].state,
            SettlementStateV1::Partial {
                failed_at: node("leaf-b")
            }
        );

        // rejected (no local hop applied)
        let order = pending_order(4);
        let hash = order.hash();
        let mut state = LedgerStateV1::new();
        push_pending(&mut state, &key, order);
        let app = apply_settlement_result_v2(
            &mut state,
            &settlement_result(
                hash,
                SettlementStatusV2::Rejected {
                    reason: OrderRejectV1::BadRequest,
                },
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();
        assert_eq!(app.status, "rejected");
        assert_eq!(app.reason, Some("bad_request".to_string()));
        assert_eq!(app.failed_at, None);
        assert_eq!(app.entry_seq, None);
        assert!(state.pending.is_empty());

        // indeterminate (debit committed, outcome unknown) is terminal
        // client-side: the pending order is removed and the outcome recorded so
        // the UI keeps the "outcome unknown" state without a stuck pending.
        let order = pending_order(5);
        let hash = order.hash();
        let mut state = LedgerStateV1::new();
        push_pending(&mut state, &key, order);
        let app = apply_settlement_result_v2(
            &mut state,
            &settlement_result(
                hash,
                SettlementStatusV2::Indeterminate {
                    reason: OrderRejectV1::Internal,
                },
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();
        assert_eq!(app.status, "indeterminate");
        assert_eq!(app.reason, Some("internal".to_string()));
        assert_eq!(app.failed_at, None);
        assert!(
            state.pending.is_empty(),
            "indeterminate must not leave a stuck pending order"
        );
        assert_eq!(
            state.settlements[0].state,
            SettlementStateV1::Indeterminate {
                reason: "internal".to_string()
            }
        );
    }

    #[test]
    fn settlement_v2_applied_and_duplicate_without_proof_are_unverified() {
        let key = ledger(1);
        let parent = node("parent");

        for (nonce, status) in [
            (
                1,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
            ),
            (
                2,
                SettlementStatusV2::Duplicate {
                    entry_seq: 3,
                    entry_hash: Hash::from_bytes([0x33; 32]),
                },
            ),
        ] {
            let order = pending_order(nonce);
            let hash = order.hash();
            let mut state = LedgerStateV1::new();
            push_pending(&mut state, &key, order);
            let app =
                apply_settlement_result_v2(&mut state, &settlement_result(hash, status), "n1", &parent, 0)
                    .unwrap();
            assert_eq!(app.status, "unverified");
            assert_eq!(app.reason, Some("missing proof".to_string()));
            assert_eq!(app.entry_seq, None, "an unproven outcome must not claim a seq");
            assert!(state.pending.is_empty());
            assert_eq!(
                state.settlements[0].state,
                SettlementStateV1::Unverified {
                    reason: "missing proof".to_string()
                }
            );
        }
    }

    #[test]
    fn settlement_v3_valid_proof_pins_leaf_and_reports_applied() {
        let key = ledger(1);
        let parent = node("parent");
        let payee = "0.2.4";
        let payee_leaf = "0.2";
        let order = pending_order(1);
        let hash = order.hash();
        let leaf_key = key.public();
        let proof = direct_terminal_proof(&key, "leaf-a", payee_leaf, &order);

        let mut state = LedgerStateV1::new();
        push_pending_direct(&mut state, order, payee, None);
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
                Some(proof),
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();

        assert_eq!(app.status, "applied");
        assert_eq!(app.entry_seq, Some(7));
        assert_eq!(app.amount, 5);
        assert_eq!(app.counterparty, node("n2"));
        assert!(app.reason.is_none());
        assert!(state.pending.is_empty());
        assert_eq!(state.settlements[0].state, SettlementStateV1::Applied);
        assert_eq!(
            state.pinned_leaf_key(&node("leaf-a")),
            Some(leaf_key),
            "a verified terminal proof must TOFU-pin the leaf key"
        );
    }

    /// Regression: the proof's `leaf_addr` is the terminal **leaf** address the
    /// node signs with (`payee_addr.parent()`), not the payee user address. A
    /// mismatch (as the old `payee_addr`-vs-`leaf_addr` contract produced) is
    /// `Unverified`; the cross-leaf Descend and same-leaf Direct paths both
    /// verify.
    #[test]
    fn settlement_v3_binds_proof_leaf_addr_to_the_payee_leaf() {
        let key = ledger(1);
        let parent = node("parent");

        // (a) Cross-leaf: the payee user is `0.2.4`, but the terminal leaf (and
        //     so the signed proof's `leaf_addr`) is `0.2`.
        let order = pending_order(11);
        let hash = order.hash();
        let proof = descend_terminal_proof(&key, "leaf-b", "0.2", &order);
        let mut state = LedgerStateV1::new();
        push_pending_cross_leaf(&mut state, order, "0.2.4", None);
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
                Some(proof),
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();
        assert_eq!(app.status, "applied", "reason {:?}", app.reason);
        assert_eq!(app.reason, None);

        // (b) A proof signed by a different leaf (`0.3`) must not bind to the
        //     `0.2.4` payee.
        let order = pending_order(12);
        let hash = order.hash();
        let proof = descend_terminal_proof(&key, "leaf-c", "0.3", &order);
        let mut state = LedgerStateV1::new();
        push_pending_cross_leaf(&mut state, order, "0.2.4", None);
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
                Some(proof),
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();
        assert_eq!(app.status, "unverified");
        assert_eq!(app.reason, Some("proof leaf address mismatch".to_string()));
        assert!(
            state.pinned_leaf_key(&node("leaf-c")).is_none(),
            "a leaf-address mismatch must not TOFU-pin"
        );

        // (c) Same-leaf: payer and payee share leaf `0.1`, so the `Direct`
        //     proof's `leaf_addr` is that shared leaf address.
        let order = pending_order(13);
        let hash = order.hash();
        let proof = direct_terminal_proof(&key, "leaf-a", "0.1", &order);
        let mut state = LedgerStateV1::new();
        push_pending_direct(&mut state, order, "0.1.5", None);
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
                Some(proof),
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();
        assert_eq!(app.status, "applied", "reason {:?}", app.reason);
    }

    #[test]
    fn settlement_v3_duplicate_proof_reports_duplicate() {
        let key = ledger(1);
        let parent = node("parent");
        let payee = "0.2.4";
        let payee_leaf = "0.2";
        let order = pending_order(2);
        let hash = order.hash();
        let proof = direct_terminal_proof(&key, "leaf-a", payee_leaf, &order);

        let mut state = LedgerStateV1::new();
        push_pending_direct(&mut state, order, payee, None);
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Duplicate {
                    entry_seq: 3,
                    entry_hash: Hash::from_bytes([0x33; 32]),
                },
                Some(proof),
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();

        assert_eq!(app.status, "duplicate");
        assert_eq!(app.entry_seq, Some(3));
        assert!(state.pending.is_empty());
        assert_eq!(state.settlements[0].state, SettlementStateV1::Duplicate);
        assert_eq!(state.pinned_leaf_key(&node("leaf-a")), Some(key.public()));
    }

    #[test]
    fn settlement_v3_wrong_pinned_key_is_unverified() {
        let key = ledger(1);
        let other = ledger(2);
        let parent = node("parent");
        let payee = "0.2.4";
        let payee_leaf = "0.2";
        let order = pending_order(1);
        let hash = order.hash();
        let proof = direct_terminal_proof(&key, "leaf-a", payee_leaf, &order);

        let mut state = LedgerStateV1::new();
        state.pin_leaf_key(node("leaf-a"), other.public());
        push_pending_direct(&mut state, order, payee, None);
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
                Some(proof),
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();

        assert_eq!(app.status, "unverified");
        assert_eq!(app.entry_seq, None);
        assert!(
            app.reason
                .as_deref()
                .unwrap()
                .contains("pinned leaf key mismatch")
        );
        assert!(state.pending.is_empty());
        assert_eq!(
            state.pinned_leaf_key(&node("leaf-a")),
            Some(other.public()),
            "a rejected proof must not replace an existing pin"
        );
        assert!(matches!(
            state.settlements[0].state,
            SettlementStateV1::Unverified { .. }
        ));
    }

    #[test]
    fn settlement_v3_uri_pin_mismatch_is_unverified() {
        let key = ledger(1);
        let wrong = ledger(2);
        let parent = node("parent");
        let payee = "0.2.4";
        let payee_leaf = "0.2";
        let order = pending_order(1);
        let hash = order.hash();
        let proof = direct_terminal_proof(&key, "leaf-a", payee_leaf, &order);

        // No registry entry, but the pending record carries an out-of-band URI
        // pin for a different key.
        let mut state = LedgerStateV1::new();
        push_pending_direct(
            &mut state,
            order,
            payee,
            Some((node("leaf-a"), wrong.public())),
        );
        assert!(state.pinned_leaf_key(&node("leaf-a")).is_none());
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
                Some(proof),
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();

        assert_eq!(app.status, "unverified");
        assert!(
            app.reason
                .as_deref()
                .unwrap()
                .contains("receive uri pin mismatch")
        );
        assert!(
            state.pinned_leaf_key(&node("leaf-a")).is_none(),
            "a failed URI-pin match must not TOFU-pin"
        );
    }

    #[test]
    fn settlement_v3_uri_pin_match_pins_and_reports_applied() {
        let key = ledger(1);
        let parent = node("parent");
        let payee = "0.2.4";
        let payee_leaf = "0.2";
        let order = pending_order(1);
        let hash = order.hash();
        let proof = direct_terminal_proof(&key, "leaf-a", payee_leaf, &order);

        let mut state = LedgerStateV1::new();
        push_pending_direct(
            &mut state,
            order,
            payee,
            Some((node("leaf-a"), key.public())),
        );
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
                Some(proof),
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();

        assert_eq!(app.status, "applied");
        assert_eq!(state.pinned_leaf_key(&node("leaf-a")), Some(key.public()));
    }

    #[test]
    fn settlement_v3_missing_or_oversized_proof_is_unverified() {
        let key = ledger(1);
        let parent = node("parent");
        let payee = "0.2.4";
        let payee_leaf = "0.2";

        // Missing proof.
        let order = pending_order(1);
        let hash = order.hash();
        let mut state = LedgerStateV1::new();
        push_pending_direct(&mut state, order, payee, None);
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
                None,
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();
        assert_eq!(app.status, "unverified");
        assert_eq!(app.reason, Some("missing proof".to_string()));
        assert!(state.pinned_leaf_key(&node("leaf-a")).is_none());

        // Oversized audit path.
        let order = pending_order(2);
        let hash = order.hash();
        let mut proof = direct_terminal_proof(&key, "leaf-a", payee_leaf, &order);
        proof.inclusion.proof = vec![Hash::ZERO; MAX_ENTRY_PROOF + 1];
        let mut state = LedgerStateV1::new();
        push_pending_direct(&mut state, order, payee, None);
        let app = apply_settlement_result(
            &mut state,
            &settlement_result_v3(
                hash,
                SettlementStatusV2::Applied {
                    entry_seq: 7,
                    entry_hash: Hash::from_bytes([0x55; 32]),
                },
                Some(proof),
            ),
            "n1",
            &parent,
            0,
        )
        .unwrap();
        assert_eq!(app.status, "unverified");
        assert!(
            app.reason
                .as_deref()
                .unwrap()
                .contains("proof invalid"),
            "reason {:?}",
            app.reason
        );
        assert!(state.pinned_leaf_key(&node("leaf-a")).is_none());
    }

    #[test]
    fn settlement_result_with_bad_balance_does_not_mutate_state() {
        let key = ledger(1);
        let parent = node("parent");
        let order = pending_order(1);
        let hash = order.hash();
        let mut state = LedgerStateV1::new();
        push_pending(&mut state, &key, order);

        let mut result = settlement_result(
            hash,
            SettlementStatusV2::Applied {
                entry_seq: 7,
                entry_hash: Hash::from_bytes([0x55; 32]),
            },
        );
        let mut receipt = receipt_for(&key, &parent, &node("n1"));
        receipt.attestation.balance = Amount::new(999);
        result.balance = Some(receipt);

        assert!(apply_settlement_result_v2(&mut state, &result, "n1", &parent, 0).is_err());
        assert_eq!(state.pending.len(), 1, "pending must be untouched");
        assert!(state.balance.is_none());
        assert!(state.settlements.is_empty());
    }

    #[test]
    fn order_v2_signing_and_serialization_shape() {
        use cawala_msg::{LedgerPayloadV2, OrderV2};

        let operator = operator(9);
        let order = build_payment_order(node("alice"), node("bob"), 7, 5, 100);
        let auth = order.authorize(&operator).unwrap();
        let payload = LedgerPayloadV2::Order(OrderV2 {
            order: order.clone(),
            auth: auth.clone(),
            payee_addr: "0.2.4".parse().unwrap(),
        });
        let bytes = payload.to_bytes().unwrap();
        assert_eq!(LedgerPayloadV2::from_bytes(&bytes).unwrap(), payload);

        match LedgerPayloadV2::from_bytes(&bytes).unwrap() {
            LedgerPayloadV2::Order(decoded) => {
                assert_eq!(decoded.order, order);
                assert_eq!(decoded.auth, auth);
                assert_eq!(decoded.payee_addr, "0.2.4".parse().unwrap());
                assert_eq!(
                    decoded
                        .auth
                        .operator
                        .verify(decoded.order.hash().as_bytes(), &decoded.auth.signature),
                    Ok(())
                );
            }
            other => panic!("expected Order, got {other:?}"),
        }
    }

    #[test]
    fn order_result_with_bad_balance_does_not_mutate_pending() {
        let key = ledger(1);
        let parent = node("parent");
        let order = pending_order(1);
        let hash = order.hash();
        let mut state = LedgerStateV1::new();
        push_pending(&mut state, &key, order);

        let mut result = result_for(hash, OrderStatusV1::Applied);
        let mut receipt = receipt_for(&key, &parent, &node("n1"));
        receipt.attestation.balance = Amount::new(999);
        result.balance = Some(receipt);

        assert!(apply_order_result(&mut state, &result, "n1", &parent, 0).is_err());
        assert_eq!(state.pending.len(), 1, "pending must be untouched");
        assert!(state.balance.is_none());
        assert!(state.activity.is_empty());
    }

    // -- stable strings and DTO-facing helpers -----------------------------

    #[test]
    fn stable_enum_strings() {
        assert_eq!(order_status_str(&OrderStatusV1::Applied), "applied");
        assert_eq!(order_status_str(&OrderStatusV1::Duplicate), "duplicate");
        assert_eq!(order_status_str(&OrderStatusV1::Rejected), "rejected");
        assert_eq!(order_reject_str(&OrderRejectV1::Unauthorized), "unauthorized");
        assert_eq!(order_reject_str(&OrderRejectV1::BadRequest), "bad_request");
        assert_eq!(order_reject_str(&OrderRejectV1::Expired), "expired");
        assert_eq!(
            order_reject_str(&OrderRejectV1::InsufficientBalance),
            "insufficient_balance"
        );
        assert_eq!(
            order_reject_str(&OrderRejectV1::AccountNotOpened),
            "account_not_opened"
        );
        assert_eq!(order_reject_str(&OrderRejectV1::NotAChild), "not_a_child");
        assert_eq!(order_reject_str(&OrderRejectV1::Internal), "internal");
        for (role, expected) in [
            (HopRole::Ascend, "ascend"),
            (HopRole::Lca, "lca"),
            (HopRole::Descend, "descend"),
            (HopRole::Direct, "direct"),
        ] {
            assert_eq!(hop_role_str(role), expected);
        }
    }

}
