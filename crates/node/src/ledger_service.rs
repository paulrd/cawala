//! Node-side ledger service: the leaf half of browser value messaging v1.
//!
//! A leaf node (a node that holds user children) uses [`LedgerService`] to:
//!
//! 1. **open** a user's account ([`LedgerService::ensure_account_open`]),
//! 2. **fund** a user (an explicit operator act,
//!    [`LedgerService::fund`]), and
//! 3. **verify and apply** a same-leaf [`cawala_ledger::PaymentOrder`]
//!    ([`LedgerService::apply_order`]), and
//! 4. attest a user's balance ([`LedgerService::balance_receipt`]).
//!
//! # State
//!
//! The service owns an in-memory [`Ledger<FileLog>`] replayed from
//! `<data-dir>/ledger/entries.log` plus the node's ledger signing key. Unlike
//! the pure ledger crate it is synchronous and native; it is **not** wasm-safe.
//!
//! # Resync
//!
//! `control approve` and `ledger fund` run as separate processes that append to
//! the same ledger file while a node is running. The in-memory ledger and the
//! replay guard are therefore **not** authoritative: every mutation
//! ([`ensure_account_open`](LedgerService::ensure_account_open),
//! [`fund`](LedgerService::fund),
//! [`apply_order`](LedgerService::apply_order)) and every read that must
//! reflect the log ([`balance_receipt`](LedgerService::balance_receipt))
//! re-reads and replays the whole log first (via the private
//! `refresh_from_disk`). Full replay is cheap at value v1.
//!
//! **Remaining v1 limitation:** resyncing serializes this service against
//! entries another process has *already flushed*, but provides no mutual
//! exclusion between two *concurrent* appenders. There is no OS file lock, so
//! two writers that both resync, both build at the same `seq`, and both append
//! can still interleave and publish a divergent `seq`/`prev_hash` (or leave a
//! torn tail, which replay discards). Closing that race needs a file lock or a
//! single-writer discipline; it is out of scope for this fix.
//!
//! # Replay protection
//!
//! [`apply_order`](LedgerService::apply_order) consumes an order exactly once:
//! the set of already-applied `payment_id`s is rebuilt by scanning the log on
//! [`open`](LedgerService::open), so no sidecar file is needed and the guard
//! survives restarts. Each accepted transfer carries
//! `payment_id == order.hash()`, so the rebuild is exact.
//!
//! # Effective peer registry
//!
//! Order verification needs a [`PeerRegistry`] that maps the payer to its
//! operator key and this node to its ledger key. [`LedgerService`] builds an
//! *effective* registry from `<data-dir>/ledger_peers.json` plus an in-memory
//! self row (this node's operator + ledger keys). The self row is **never
//! written back**: doing so would race concurrent control-plane approvals that
//! rewrite the same file (lost update). A self row that already exists on disk
//! and disagrees with this node's identity is treated as an error.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use cawala_ledger::{
    AccountRef, Amount, AuthRef, BalanceAttestation, Entry, EntryBody, Hash, HopRole, IssueRequest,
    Ledger, LedgerError, LedgerPubKey, LedgerSecretKey, NodeId, OperatorPubKey, OperatorSecretKey,
    PaymentOrder, PeerKeys, PeerRegistry, PeerRole, Posting, SignedAmount, SignedCommitment,
    SignedEntry, attest_balance, build_commitment, entry_hash, verify_issue, verify_transfer,
};
use cawala_msg::{
    BalanceReceiptV1, MAX_RECEIPT_HISTORY, MsgId, OrderRejectV1, OrderStatusV1, ValueNoticeV1,
};
use cawala_topology::ChildKind;

use crate::identity;
use crate::ledger_keys::load_or_create_ledger_key;
use crate::ledger_peers::load_peers;
use crate::ledger_store::{FileLog, init_ledger, open_ledger};
use crate::record::NodeRecord;

/// The result of applying one [`PaymentOrder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// Whether the order applied, was a duplicate, or was rejected.
    pub status: OrderStatusV1,
    /// The ledger `seq` of the applied (or already-applied) entry.
    pub entry_seq: Option<u64>,
    /// The hash of the applied (or already-applied) entry.
    pub entry_hash: Option<Hash>,
    /// The rejection reason, when `status == Rejected`.
    pub reason: Option<OrderRejectV1>,
}

impl ApplyOutcome {
    fn rejected(reason: OrderRejectV1) -> Self {
        ApplyOutcome {
            status: OrderStatusV1::Rejected,
            entry_seq: None,
            entry_hash: None,
            reason: Some(reason),
        }
    }
}

/// A leaf node's ledger: the replayed log, its signing key, and the
/// `payment_id` replay guard.
pub struct LedgerService {
    data_dir: PathBuf,
    node_id: String,
    ledger: Ledger<FileLog>,
    key: LedgerSecretKey,
    /// `payment_id -> (entry seq, entry hash)` for every applied transfer.
    consumed: ConsumedIndex,
}

/// `payment_id -> (entry seq, entry hash)` for every applied transfer.
type ConsumedIndex = BTreeMap<Hash, (u64, Hash)>;

impl LedgerService {
    /// Open the node's ledger, auto-initializing it if absent (idempotent),
    /// replaying it, and rebuilding the replay guard from the log.
    pub fn open(data_dir: &Path, node_id: &str) -> Result<Self> {
        let key = load_or_create_ledger_key(data_dir)?;
        let (ledger, consumed) = Self::load(data_dir, node_id, &key)?;
        Ok(LedgerService {
            data_dir: data_dir.to_path_buf(),
            node_id: node_id.to_string(),
            ledger,
            key,
            consumed,
        })
    }

    /// Replay `data_dir`'s ledger for `node_id`/`key` and rebuild the replay
    /// guard. Shared by [`open`](Self::open) and `refresh_from_disk` so the two
    /// load paths cannot drift.
    fn load(
        data_dir: &Path,
        node_id: &str,
        key: &LedgerSecretKey,
    ) -> Result<(Ledger<FileLog>, ConsumedIndex)> {
        // `init_ledger` is idempotent; calling it explicitly makes loading
        // self-bootstrapping rather than relying on `open_ledger`'s side effect.
        init_ledger(data_dir, node_id, &key.public())?;
        let ledger = open_ledger(data_dir, node_id, key)?;
        let consumed = rebuild_consumed(&ledger)?;
        Ok((ledger, consumed))
    }

    /// Re-read the on-disk ledger, replacing the in-memory ledger and replay
    /// guard with the authoritative replayed state.
    ///
    /// External processes append to `<data-dir>/ledger/entries.log` while a
    /// node runs, so mutations and authoritative reads call this first. The
    /// signing key is loaded once in [`open`](Self::open) and is **not**
    /// regenerated or rotated here.
    ///
    /// This does not lock the file: two *concurrent* appenders can still race
    /// between their resync and append (see the module-level "Resync" note).
    fn refresh_from_disk(&mut self) -> Result<()> {
        let (ledger, consumed) = Self::load(&self.data_dir, &self.node_id, &self.key)?;
        self.ledger = ledger;
        self.consumed = consumed;
        Ok(())
    }

    /// This node's id.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// The replayed ledger (read access for inspection/commitments).
    pub fn ledger(&self) -> &Ledger<FileLog> {
        &self.ledger
    }

    /// This node's ledger public key.
    pub fn ledger_key_public(&self) -> LedgerPubKey {
        self.key.public()
    }

    /// The current balance of `child`'s liability account (zero if absent).
    pub fn balance_of(&self, child: &NodeId) -> Amount {
        self.ledger.balances().child_balance(child)
    }

    /// Ensure `child` has a materialized account, appending an
    /// [`EntryBody::OpenAccount`] entry signed by the ledger key the first time.
    ///
    /// Idempotent: returns `Ok(true)` when an entry was appended and
    /// `Ok(false)` when the account was already open (regardless of the `kind`
    /// it was opened with).
    pub fn ensure_account_open(&mut self, child: &NodeId, kind: ChildKind) -> Result<bool> {
        self.refresh_from_disk()?;
        self.ensure_account_open_inner(child, kind)
    }

    /// [`ensure_account_open`](Self::ensure_account_open) without the resync;
    /// callers that have already refreshed (e.g. [`fund`](Self::fund)) use this
    /// to avoid a redundant second replay.
    fn ensure_account_open_inner(&mut self, child: &NodeId, kind: ChildKind) -> Result<bool> {
        if self.ledger.balances().accounts().any(|(account, _)| {
            matches!(account, AccountRef::Child(id) if id == *child)
        }) {
            return Ok(false);
        }
        let seq = self.ledger.len() as u64;
        let entry = Entry {
            ledger_id: self.key.public(),
            seq,
            height: seq,
            prev_hash: self.ledger.head_hash(),
            issued_at: unix_now(),
            body: EntryBody::OpenAccount {
                child: child.clone(),
                kind,
            },
            postings: vec![],
            auth: None,
        };
        let signed = SignedEntry::sign(entry, &self.key)?;
        self.ledger.append(signed)?;
        Ok(true)
    }

    /// Issue `amount` into `to`'s account against equity, authorized by the
    /// node operator key.
    ///
    /// This is an **explicit operator act**: every call issues value again (the
    /// ledger has no per-issue replay guard), which is why it is deliberately
    /// only reachable through the operator-only `ledger fund` CLI path and not
    /// through the browser `Order` path.
    ///
    /// `nonce` and `now` are caller-supplied so callers control the replay
    /// nonce and the order expiry window; the request is valid while
    /// `now <= expiry`.
    ///
    /// Returns the appended entry's `(seq, hash)`.
    pub fn fund(
        &mut self,
        to: &NodeId,
        amount: u64,
        operator: &OperatorSecretKey,
        nonce: u64,
        now: u64,
    ) -> Result<(u64, Hash)> {
        if amount == 0 {
            bail!("amount must be greater than zero");
        }
        self.refresh_from_disk()?;
        self.ensure_account_open_inner(to, ChildKind::User)?;

        let request = IssueRequest {
            node: NodeId::from(self.node_id.clone()),
            account: to.clone(),
            amount: Amount::new(amount),
            nonce,
            expiry: now.saturating_add(3600),
        };
        let auth = request.authorize(operator)?;
        let amount_i64 =
            i64::try_from(amount).context("amount exceeds the ledger's signed range")?;

        let seq = self.ledger.len() as u64;
        let entry = Entry {
            ledger_id: self.key.public(),
            seq,
            height: seq,
            prev_hash: self.ledger.head_hash(),
            issued_at: now,
            body: EntryBody::Issue {
                account: AccountRef::Child(to.clone()),
                amount: Amount::new(amount),
            },
            postings: vec![
                Posting {
                    account: AccountRef::Child(to.clone()),
                    delta: SignedAmount::new(amount_i64),
                },
                Posting {
                    account: AccountRef::Equity,
                    delta: SignedAmount::new(-amount_i64),
                },
            ],
            auth: Some(auth),
        };
        let signed = SignedEntry::sign(entry, &self.key)?;
        let registry = self.effective_registry()?;
        verify_issue(&signed, &request, &registry, now)?;

        let hash = entry_hash(&signed.entry)?;
        self.ledger.append(signed)?;
        Ok((seq, hash))
    }

    /// Verify and apply a same-leaf `Direct` [`PaymentOrder`] from `sender`.
    ///
    /// Sequence:
    ///
    /// 1. structural preflight ([`OrderRejectV1::BadRequest`] for a foreign
    ///    sender, a self-payment, or a zero amount);
    /// 2. both endpoints must be `User` children of this leaf
    ///    ([`OrderRejectV1::NotAChild`]);
    /// 3. replay guard on `order.hash()` ([`OrderStatusV1::Duplicate`], no
    ///    append);
    /// 4. build the canonical `Direct` entry and sign it with the ledger key;
    /// 5. [`verify_transfer`] against the effective registry (conservation,
    ///    registered signer, payer-operator binding, expiry, `payment_id`,
    ///    amount, and exactly-one-debit/credit);
    /// 6. append (mapping ledger errors to reject reasons);
    /// 7. record the consumed `payment_id` and report
    ///    [`OrderStatusV1::Applied`].
    ///
    /// On any rejection the ledger is left untouched and the `payment_id` is
    /// **not** consumed.
    pub fn apply_order(
        &mut self,
        order: &PaymentOrder,
        auth: &AuthRef,
        sender: &NodeId,
        record: &NodeRecord,
        now: u64,
    ) -> ApplyOutcome {
        if self.refresh_from_disk().is_err() {
            return ApplyOutcome::rejected(OrderRejectV1::Internal);
        }
        if order.from != *sender || order.from == order.to || order.amount == Amount::ZERO {
            return ApplyOutcome::rejected(OrderRejectV1::BadRequest);
        }
        if child_kind(record, &order.from) != Some(ChildKind::User)
            || child_kind(record, &order.to) != Some(ChildKind::User)
        {
            return ApplyOutcome::rejected(OrderRejectV1::NotAChild);
        }

        let payment_id = order.hash();
        if let Some((seq, hash)) = self.consumed.get(&payment_id) {
            return ApplyOutcome {
                status: OrderStatusV1::Duplicate,
                entry_seq: Some(*seq),
                entry_hash: Some(*hash),
                reason: None,
            };
        }

        let Ok(amount_i64) = i64::try_from(order.amount.get()) else {
            return ApplyOutcome::rejected(OrderRejectV1::BadRequest);
        };

        let seq = self.ledger.len() as u64;
        let entry = Entry {
            ledger_id: self.key.public(),
            seq,
            height: seq,
            prev_hash: self.ledger.head_hash(),
            issued_at: now,
            body: EntryBody::Transfer {
                payment_id,
                amount: order.amount,
                role: HopRole::Direct,
            },
            postings: vec![
                Posting {
                    account: AccountRef::Child(order.from.clone()),
                    delta: SignedAmount::new(-amount_i64),
                },
                Posting {
                    account: AccountRef::Child(order.to.clone()),
                    delta: SignedAmount::new(amount_i64),
                },
            ],
            auth: Some(auth.clone()),
        };

        let signed = match SignedEntry::sign(entry, &self.key) {
            Ok(signed) => signed,
            Err(_) => return ApplyOutcome::rejected(OrderRejectV1::Internal),
        };
        let registry = match self.effective_registry() {
            Ok(registry) => registry,
            Err(_) => return ApplyOutcome::rejected(OrderRejectV1::Internal),
        };
        if let Err(err) = verify_transfer(&signed, order, &registry, now) {
            return ApplyOutcome::rejected(reject_reason(&err));
        }

        let hash = match entry_hash(&signed.entry) {
            Ok(hash) => hash,
            Err(_) => return ApplyOutcome::rejected(OrderRejectV1::Internal),
        };
        if let Err(err) = self.ledger.append(signed) {
            return ApplyOutcome::rejected(reject_reason(&err));
        }

        self.consumed.insert(payment_id, (seq, hash));
        ApplyOutcome {
            status: OrderStatusV1::Applied,
            entry_seq: Some(seq),
            entry_hash: Some(hash),
            reason: None,
        }
    }

    /// Build a signed balance receipt for `user` from the current ledger head.
    ///
    /// The attestation is over the current state and the commitment's parent is
    /// always [`Hash::ZERO`]: the service keeps no commitment chain, so every
    /// receipt anchors its own commitment (the browser verifies it against the
    /// leaf's ledger key rather than a chain).
    ///
    /// `history` carries the recent `Direct` transfers touching `user`, oldest
    /// first, capped at [`MAX_RECEIPT_HISTORY`]. Issue/burn entries are not
    /// representable as a [`ValueNoticeV1`] (the wire shape has no issue/burn
    /// fields), so funding does not appear in history.
    ///
    /// `record` must list `user` as a `User` child of this leaf.
    pub fn balance_receipt(
        &mut self,
        user: &NodeId,
        record: &NodeRecord,
        reply_to: Option<MsgId>,
        query_id: Option<u64>,
        notice: Option<ValueNoticeV1>,
    ) -> Result<BalanceReceiptV1> {
        self.refresh_from_disk()?;
        if child_kind(record, user) != Some(ChildKind::User) {
            bail!("'{user}' is not a user child of this leaf");
        }
        let leaf = NodeId::from(self.node_id.clone());
        let attestation: BalanceAttestation = attest_balance(&self.ledger, &leaf, user)?;
        let commitment = build_commitment(&self.ledger, Hash::ZERO, unix_now())?;
        let commitment = SignedCommitment::sign(commitment, &self.key)?;
        let history = self.receipt_history(user)?;
        Ok(BalanceReceiptV1 {
            reply_to,
            query_id,
            ledger_pubkey: self.key.public(),
            attestation,
            commitment,
            history,
            notice,
        })
    }

    /// The effective peer registry: the persisted peers plus an in-memory self
    /// row (operator + ledger keys, role `Node`).
    ///
    /// The self row is never persisted here, so this is safe to call while a
    /// concurrent control-plane approval rewrites `ledger_peers.json`.
    pub fn effective_registry(&self) -> Result<PeerRegistry> {
        let mut registry = load_peers(&self.data_dir)?;
        let node_id = NodeId::from(self.node_id.clone());
        let operator = self.node_operator_public()?;
        let ledger = self.key.public();
        match registry.get(&node_id) {
            Some(existing) => {
                if existing.role != PeerRole::Node
                    || existing.operator != operator
                    || existing.ledger != Some(ledger)
                {
                    bail!("ledger_peers.json row for this node does not match its identity");
                }
            }
            None => {
                registry.insert(PeerKeys {
                    node_id,
                    operator,
                    ledger: Some(ledger),
                    role: PeerRole::Node,
                })?;
            }
        }
        Ok(registry)
    }

    /// Rebuild the `payment_id` replay guard from the replayed log.
    fn receipt_history(&self, user: &NodeId) -> Result<Vec<ValueNoticeV1>> {
        let mut notices = Vec::new();
        for index in 0..self.ledger.len() {
            let signed = self.ledger.get(index)?.ok_or_else(|| {
                anyhow::anyhow!("ledger entry {index} missing while building receipt history")
            })?;
            let entry = &signed.entry;
            let EntryBody::Transfer {
                payment_id,
                amount,
                role,
            } = &entry.body
            else {
                continue;
            };
            // Only `Direct` hops have unambiguous `from`/`to` endpoints; a leaf
            // holds users directly, so its transfers are `Direct`.
            if *role != HopRole::Direct {
                continue;
            }
            let Some((from, to)) = direct_endpoints(&entry.postings) else {
                continue;
            };
            if from != *user && to != *user {
                continue;
            }
            notices.push(ValueNoticeV1 {
                entry_seq: entry.seq,
                entry_hash: entry_hash(entry)?,
                payment_id: *payment_id,
                from,
                to,
                amount: *amount,
                role: *role,
                issued_at: entry.issued_at,
            });
        }
        if notices.len() > MAX_RECEIPT_HISTORY {
            let excess = notices.len() - MAX_RECEIPT_HISTORY;
            notices.drain(0..excess);
        }
        Ok(notices)
    }

    /// This node's operator public key, derived from the persisted identity the
    /// same way the control plane does.
    fn node_operator_public(&self) -> Result<OperatorPubKey> {
        let secret = identity::load_or_create_secret_key(&self.data_dir)
            .context("failed to load node identity for the self peer row")?;
        Ok(OperatorSecretKey::from_bytes(secret.to_bytes()).public())
    }
}

/// Rebuild `payment_id -> (seq, entry_hash)` from every applied transfer.
fn rebuild_consumed(ledger: &Ledger<FileLog>) -> Result<ConsumedIndex> {
    let mut consumed = BTreeMap::new();
    for index in 0..ledger.len() {
        let signed = ledger.get(index)?.ok_or_else(|| {
            anyhow::anyhow!("ledger entry {index} missing while rebuilding the replay guard")
        })?;
        if let EntryBody::Transfer { payment_id, .. } = &signed.entry.body {
            let hash = entry_hash(&signed.entry)?;
            consumed
                .entry(*payment_id)
                .or_insert((signed.entry.seq, hash));
        }
    }
    Ok(consumed)
}

/// The `User` kind of `id` in `record`, if the leaf lists it.
fn child_kind(record: &NodeRecord, id: &NodeId) -> Option<ChildKind> {
    record
        .children
        .iter()
        .find(|child| child.child_id.as_str() == id.as_str())
        .map(|child| child.kind)
}

/// Map a ledger error from transfer verification or append to a wire reject.
fn reject_reason(err: &LedgerError) -> OrderRejectV1 {
    match err {
        LedgerError::InsufficientBalance => OrderRejectV1::InsufficientBalance,
        LedgerError::AccountNotOpened { .. } => OrderRejectV1::AccountNotOpened,
        LedgerError::OrderExpired => OrderRejectV1::Expired,
        LedgerError::OrderMismatch | LedgerError::InvalidEntryShape => OrderRejectV1::BadRequest,
        LedgerError::Unauthorized
        | LedgerError::MissingAuthorization
        | LedgerError::InvalidSignature => OrderRejectV1::Unauthorized,
        _ => OrderRejectV1::Internal,
    }
}

/// The `(debited child, credited child)` of a `Direct` posting set, if exactly
/// one of each exists.
fn direct_endpoints(postings: &[Posting]) -> Option<(NodeId, NodeId)> {
    let mut debit = None;
    let mut credit = None;
    for posting in postings {
        let AccountRef::Child(id) = &posting.account else {
            continue;
        };
        let delta = posting.delta.get();
        if delta < 0 {
            if debit.is_some() {
                return None;
            }
            debit = Some(id.clone());
        } else if delta > 0 {
            if credit.is_some() {
                return None;
            }
            credit = Some(id.clone());
        }
    }
    Some((debit?, credit?))
}

/// Current unix time in seconds, used for non-verified coarse timestamps
/// (`OpenAccount`, commitments) where no caller-supplied clock exists.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::verify_balance_attestation;

    use crate::record::ChildEntry;

    const NODE: &str = "leaf-node";

    /// The node's operator key, derived from the persisted identity exactly as
    /// the control plane does.
    fn node_operator(dir: &Path) -> OperatorSecretKey {
        let secret = identity::load_or_create_secret_key(dir).unwrap();
        OperatorSecretKey::from_bytes(secret.to_bytes())
    }

    fn user(id: &str) -> NodeId {
        NodeId::from(id)
    }

    /// A record listing each id as a `User` child in successive slots.
    fn record_with(users: &[&str]) -> NodeRecord {
        let mut record = NodeRecord::new(NODE);
        for (slot, id) in users.iter().enumerate() {
            record.children.push(ChildEntry {
                child_id: (*id).to_string(),
                kind: ChildKind::User,
                slot: slot as u8,
                date_joined: 0,
            });
        }
        record
    }

    /// Persist user rows (each with its own operator key, no ledger) so the
    /// service's effective registry can resolve their operators.
    fn register_users(dir: &Path, users: &[(&str, &OperatorSecretKey)]) {
        let mut registry = PeerRegistry::new();
        for (id, operator) in users {
            registry
                .insert(PeerKeys {
                    node_id: user(id),
                    operator: operator.public(),
                    ledger: None,
                    role: PeerRole::User,
                })
                .unwrap();
        }
        crate::ledger_peers::save_peers(dir, &registry).unwrap();
    }

    fn order(from: &NodeId, to: &NodeId, amount: u64, nonce: u64, expiry: u64) -> PaymentOrder {
        PaymentOrder {
            from: from.clone(),
            to: to.clone(),
            amount: Amount::new(amount),
            nonce,
            expiry,
        }
    }

    /// A service with two open user accounts, 100 funded to A, and A/B
    /// registered as peers.
    struct Fixture {
        service: LedgerService,
        a: NodeId,
        b: NodeId,
        a_op: OperatorSecretKey,
        b_op: OperatorSecretKey,
        record: NodeRecord,
        now: u64,
    }

    fn fixture(dir: &Path) -> Fixture {
        let now = 1_000u64;
        let mut service = LedgerService::open(dir, NODE).unwrap();
        let a = user("user-a");
        let b = user("user-b");
        service.ensure_account_open(&a, ChildKind::User).unwrap();
        service.ensure_account_open(&b, ChildKind::User).unwrap();
        let operator = node_operator(dir);
        service.fund(&a, 100, &operator, 1, now).unwrap();

        let a_op = OperatorSecretKey::from_bytes([11u8; 32]);
        let b_op = OperatorSecretKey::from_bytes([12u8; 32]);
        register_users(dir, &[("user-a", &a_op), ("user-b", &b_op)]);
        let record = record_with(&["user-a", "user-b"]);
        Fixture {
            service,
            a,
            b,
            a_op,
            b_op,
            record,
            now,
        }
    }

    #[test]
    fn open_account_then_fund_then_verify_balance() {
        let dir = tempfile::tempdir().unwrap();
        let mut service = LedgerService::open(dir.path(), NODE).unwrap();
        let a = user("user-a");
        assert!(service.ensure_account_open(&a, ChildKind::User).unwrap());
        // Idempotent: a second open is a no-op.
        assert!(!service.ensure_account_open(&a, ChildKind::User).unwrap());

        let operator = node_operator(dir.path());
        let (seq, _hash) = service.fund(&a, 100, &operator, 1, 1_000).unwrap();
        assert_eq!(seq, 1, "seq 0 opens the account, seq 1 issues");
        assert_eq!(service.balance_of(&a), Amount::new(100));
        assert_eq!(service.ledger().len(), 2);
    }

    #[test]
    fn apply_valid_direct_transfer_moves_balances() {
        let dir = tempfile::tempdir().unwrap();
        let Fixture {
            mut service,
            a,
            b,
            a_op,
            record,
            now,
            ..
        } = fixture(dir.path());

        let payment = order(&a, &b, 30, 7, now + 100);
        let auth = payment.authorize(&a_op).unwrap();
        let outcome = service.apply_order(&payment, &auth, &a, &record, now);

        assert_eq!(outcome.status, OrderStatusV1::Applied);
        assert_eq!(outcome.entry_seq, Some(3));
        assert!(outcome.entry_hash.is_some());
        assert_eq!(outcome.reason, None);
        assert_eq!(service.balance_of(&a), Amount::new(70));
        assert_eq!(service.balance_of(&b), Amount::new(30));

        // The applied transfer is visible in the payer's receipt history.
        let receipt = service.balance_receipt(&a, &record, None, None, None).unwrap();
        assert_eq!(receipt.history.len(), 1);
        assert_eq!(receipt.history[0].from, a);
        assert_eq!(receipt.history[0].to, b);
        assert_eq!(receipt.history[0].amount, Amount::new(30));
    }

    #[test]
    fn duplicate_order_is_not_reapplied() {
        let dir = tempfile::tempdir().unwrap();
        let Fixture {
            mut service,
            a,
            b,
            a_op,
            record,
            now,
            ..
        } = fixture(dir.path());

        let payment = order(&a, &b, 30, 7, now + 100);
        let auth = payment.authorize(&a_op).unwrap();
        let first = service.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(first.status, OrderStatusV1::Applied);

        let len = service.ledger().len();
        let second = service.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(second.status, OrderStatusV1::Duplicate);
        assert_eq!(second.entry_seq, first.entry_seq);
        assert_eq!(second.entry_hash, first.entry_hash);
        assert_eq!(second.reason, None);
        assert_eq!(service.ledger().len(), len, "duplicate must not append");
    }

    #[test]
    fn foreign_sender_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let Fixture {
            mut service,
            a,
            b,
            b_op,
            record,
            now,
            ..
        } = fixture(dir.path());

        // B signs and sends, but the order debits A.
        let payment = order(&a, &b, 10, 1, now + 100);
        let auth = payment.authorize(&b_op).unwrap();
        let outcome = service.apply_order(&payment, &auth, &b, &record, now);
        assert_eq!(outcome.status, OrderStatusV1::Rejected);
        assert_eq!(outcome.reason, Some(OrderRejectV1::BadRequest));
    }

    #[test]
    fn non_child_payee_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let Fixture {
            mut service,
            a,
            a_op,
            record,
            now,
            ..
        } = fixture(dir.path());

        let stranger = user("stranger");
        let payment = order(&a, &stranger, 10, 1, now + 100);
        let auth = payment.authorize(&a_op).unwrap();
        let outcome = service.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(outcome.status, OrderStatusV1::Rejected);
        assert_eq!(outcome.reason, Some(OrderRejectV1::NotAChild));
    }

    #[test]
    fn insufficient_balance_is_rejected_without_appending() {
        let dir = tempfile::tempdir().unwrap();
        let Fixture {
            mut service,
            a,
            b,
            a_op,
            record,
            now,
            ..
        } = fixture(dir.path());

        let len = service.ledger().len();
        // A holds 100; ask for 150.
        let payment = order(&a, &b, 150, 1, now + 100);
        let auth = payment.authorize(&a_op).unwrap();
        let outcome = service.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(outcome.status, OrderStatusV1::Rejected);
        assert_eq!(outcome.reason, Some(OrderRejectV1::InsufficientBalance));
        assert_eq!(service.ledger().len(), len);
        assert_eq!(service.balance_of(&a), Amount::new(100));
    }

    #[test]
    fn unopened_payee_account_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000u64;
        let mut service = LedgerService::open(dir.path(), NODE).unwrap();
        let a = user("user-a");
        let b = user("user-b");
        // Only A is opened and funded; B has a record entry but no account.
        service.ensure_account_open(&a, ChildKind::User).unwrap();
        let operator = node_operator(dir.path());
        service.fund(&a, 100, &operator, 1, now).unwrap();

        let a_op = OperatorSecretKey::from_bytes([11u8; 32]);
        let b_op = OperatorSecretKey::from_bytes([12u8; 32]);
        register_users(dir.path(), &[("user-a", &a_op), ("user-b", &b_op)]);
        let record = record_with(&["user-a", "user-b"]);

        let payment = order(&a, &b, 10, 1, now + 100);
        let auth = payment.authorize(&a_op).unwrap();
        let outcome = service.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(outcome.status, OrderStatusV1::Rejected);
        assert_eq!(outcome.reason, Some(OrderRejectV1::AccountNotOpened));
    }

    #[test]
    fn expired_order_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let Fixture {
            mut service,
            a,
            b,
            a_op,
            record,
            now,
            ..
        } = fixture(dir.path());

        // Valid while `now <= expiry`; expire it one second before now.
        let payment = order(&a, &b, 10, 1, now - 1);
        let auth = payment.authorize(&a_op).unwrap();
        let outcome = service.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(outcome.status, OrderStatusV1::Rejected);
        assert_eq!(outcome.reason, Some(OrderRejectV1::Expired));
    }

    #[test]
    fn consumed_index_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, a_op, record, now, len) = {
            let Fixture {
                mut service,
                a,
                b,
                a_op,
                record,
                now,
                ..
            } = fixture(dir.path());
            let payment = order(&a, &b, 30, 7, now + 100);
            let auth = payment.authorize(&a_op).unwrap();
            let outcome = service.apply_order(&payment, &auth, &a, &record, now);
            assert_eq!(outcome.status, OrderStatusV1::Applied);
            (a, b, a_op, record, now, service.ledger().len())
        };

        let mut reopened = LedgerService::open(dir.path(), NODE).unwrap();
        let payment = order(&a, &b, 30, 7, now + 100);
        let auth = payment.authorize(&a_op).unwrap();
        let outcome = reopened.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(outcome.status, OrderStatusV1::Duplicate);
        assert_eq!(reopened.ledger().len(), len);
    }

    /// A second service on the same data dir simulates a separate process
    /// (`ledger fund` / `control approve`) appending to the shared log.
    #[test]
    fn refresh_sees_externally_appended_entries() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000u64;
        let a = user("user-a");
        let b = user("user-b");

        // Service A opens before any entries exist and caches an empty ledger.
        let mut a_service = LedgerService::open(dir.path(), NODE).unwrap();
        assert_eq!(a_service.ledger().len(), 0);

        // A separate process opens both accounts and funds A.
        let operator = node_operator(dir.path());
        {
            let mut external = LedgerService::open(dir.path(), NODE).unwrap();
            assert!(external.ensure_account_open(&a, ChildKind::User).unwrap());
            assert!(external.ensure_account_open(&b, ChildKind::User).unwrap());
            external.fund(&a, 100, &operator, 1, now).unwrap();
        }

        let a_op = OperatorSecretKey::from_bytes([11u8; 32]);
        let b_op = OperatorSecretKey::from_bytes([12u8; 32]);
        register_users(dir.path(), &[("user-a", &a_op), ("user-b", &b_op)]);
        let record = record_with(&["user-a", "user-b"]);

        // A's in-memory view predates the external appends. Applying must
        // resync rather than report `AccountNotOpened` or reuse a stale
        // seq/prev_hash.
        let payment = order(&a, &b, 30, 7, now + 100);
        let auth = payment.authorize(&a_op).unwrap();
        let outcome = a_service.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(
            outcome.status,
            OrderStatusV1::Applied,
            "unexpected reason: {:?}",
            outcome.reason
        );
        assert_eq!(outcome.entry_seq, Some(3), "external entries occupy seq 0..2");
        assert_eq!(a_service.balance_of(&a), Amount::new(70));
        assert_eq!(a_service.balance_of(&b), Amount::new(30));

        // Reopening from disk agrees, and the chain is dense with matching
        // prev_hash links.
        let head = a_service.ledger().head_hash();
        let len = a_service.ledger().len();
        let reopened = LedgerService::open(dir.path(), NODE).unwrap();
        assert_eq!(reopened.ledger().len(), len);
        assert_eq!(reopened.ledger().head_hash(), head);
        assert_eq!(reopened.balance_of(&a), Amount::new(70));
        assert_eq!(reopened.balance_of(&b), Amount::new(30));
        let mut prev = Hash::ZERO;
        for index in 0..len {
            let entry = reopened.ledger().get(index).unwrap().unwrap();
            assert_eq!(entry.entry.seq, index as u64);
            assert_eq!(entry.entry.prev_hash, prev);
            prev = entry_hash(&entry.entry).unwrap();
        }
        assert_eq!(prev, head);
    }

    #[test]
    fn refresh_after_external_issue_updates_balance_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000u64;
        let a = user("user-a");
        let record = record_with(&["user-a"]);

        let mut a_service = LedgerService::open(dir.path(), NODE).unwrap();
        assert_eq!(a_service.ledger().len(), 0);

        // External process opens A and issues 100 to it.
        let operator = node_operator(dir.path());
        {
            let mut external = LedgerService::open(dir.path(), NODE).unwrap();
            external.ensure_account_open(&a, ChildKind::User).unwrap();
            external.fund(&a, 100, &operator, 1, now).unwrap();
        }

        let receipt = a_service
            .balance_receipt(&a, &record, None, None, None)
            .unwrap();
        assert_eq!(receipt.attestation.balance, Amount::new(100));
        verify_balance_attestation(
            &receipt.attestation,
            &receipt.commitment,
            &receipt.ledger_pubkey,
        )
        .unwrap();

        // A second external issue is likewise reflected on the next receipt.
        {
            let mut external = LedgerService::open(dir.path(), NODE).unwrap();
            external.fund(&a, 50, &operator, 2, now).unwrap();
        }
        let receipt = a_service
            .balance_receipt(&a, &record, None, None, None)
            .unwrap();
        assert_eq!(receipt.attestation.balance, Amount::new(150));
        verify_balance_attestation(
            &receipt.attestation,
            &receipt.commitment,
            &receipt.ledger_pubkey,
        )
        .unwrap();
    }

    #[test]
    fn duplicate_detection_survives_external_append() {
        let dir = tempfile::tempdir().unwrap();
        let Fixture {
            mut service,
            a,
            b,
            a_op,
            record,
            now,
            ..
        } = fixture(dir.path());

        // An observer opened before the order is applied has an empty replay
        // guard; it must rebuild `consumed` from disk on the next apply.
        let mut observer = LedgerService::open(dir.path(), NODE).unwrap();

        let payment = order(&a, &b, 30, 7, now + 100);
        let auth = payment.authorize(&a_op).unwrap();
        let first = service.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(first.status, OrderStatusV1::Applied);
        let applied_len = service.ledger().len();

        let second = observer.apply_order(&payment, &auth, &a, &record, now);
        assert_eq!(second.status, OrderStatusV1::Duplicate);
        assert_eq!(second.entry_seq, first.entry_seq);
        assert_eq!(second.entry_hash, first.entry_hash);
        // The resync pulls in A's applied entry (observer started at 3), but the
        // duplicate appends nothing: the log stays at A's length.
        assert_eq!(
            observer.ledger().len(),
            applied_len,
            "duplicate must not append"
        );
    }

    #[test]
    fn balance_receipt_verifies_under_leaf_ledger_key() {
        let dir = tempfile::tempdir().unwrap();
        let Fixture {
            mut service,
            a,
            record,
            ..
        } = fixture(dir.path());

        let receipt = service.balance_receipt(&a, &record, None, None, None).unwrap();
        assert_eq!(receipt.ledger_pubkey, service.ledger_key_public());
        assert_eq!(receipt.attestation.balance, Amount::new(100));
        assert_eq!(receipt.attestation.edge.child, a);
        verify_balance_attestation(
            &receipt.attestation,
            &receipt.commitment,
            &receipt.ledger_pubkey,
        )
        .unwrap();
    }

    #[test]
    fn effective_registry_includes_self_without_persisting_it() {
        let dir = tempfile::tempdir().unwrap();
        let service = LedgerService::open(dir.path(), NODE).unwrap();
        let registry = service.effective_registry().unwrap();
        let self_id = user(NODE);
        assert_eq!(
            registry.get(&self_id).map(|peer| peer.ledger),
            Some(Some(service.ledger_key_public()))
        );
        // The self row is in-memory only: the file was never written.
        assert!(!dir.path().join(crate::ledger_peers::PEERS_FILE).exists());
    }
}
