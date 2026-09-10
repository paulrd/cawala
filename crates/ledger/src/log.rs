//! The append-only ledger log and its state machine.

use crate::account::Balances;
use crate::entry::{EntryBody, SignedEntry};
use crate::error::LedgerError;
use crate::hash::{Hash, entry_hash};
use crate::keys::{LedgerId, LedgerPubKey};

/// An append-only, hash-chained sequence of signed entries.
///
/// The trait exists so later phases can swap [`MemLog`] for a persistent
/// (redb-backed) store without touching the [`Ledger`] state machine. It is
/// free of borrows: [`Self::append`] takes the entry by value and
/// [`Self::get`] returns an owned clone, so a persistent implementation can
/// read from disk without lifetime gymnastics.
pub trait LedgerLog {
    /// Append an already-validated entry, updating the cached head hash.
    fn append(&mut self, entry: SignedEntry) -> Result<(), LedgerError>;

    /// Number of entries.
    fn len(&self) -> usize;

    /// Whether the log is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fetch a copy of the entry at `index`, or `None` if out of range.
    ///
    /// Fallible because a persistent implementation may fail on I/O.
    fn get(&self, index: usize) -> Result<Option<SignedEntry>, LedgerError>;

    /// Hash of the last entry, or [`Hash::ZERO`] for an empty log. Total:
    /// never fails.
    fn head_hash(&self) -> Hash;
}

/// An in-memory [`LedgerLog`] that caches the rolling head hash so
/// [`LedgerLog::head_hash`] is total and O(1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemLog {
    entries: Vec<SignedEntry>,
    head: Hash,
}

impl MemLog {
    /// Create an empty in-memory log.
    pub fn new() -> Self {
        MemLog {
            entries: Vec::new(),
            head: Hash::ZERO,
        }
    }
}

impl Default for MemLog {
    fn default() -> Self {
        Self::new()
    }
}

impl LedgerLog for MemLog {
    fn append(&mut self, entry: SignedEntry) -> Result<(), LedgerError> {
        let head = entry_hash(&entry.entry)?;
        self.entries.push(entry);
        self.head = head;
        Ok(())
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&self, index: usize) -> Result<Option<SignedEntry>, LedgerError> {
        Ok(self.entries.get(index).cloned())
    }

    fn head_hash(&self) -> Hash {
        self.head
    }
}

/// A single node's ledger: its identity, balances, and append-only log.
///
/// Generic over the [`LedgerLog`] backend, defaulting to [`MemLog`].
#[derive(Debug, Clone)]
pub struct Ledger<L: LedgerLog = MemLog> {
    ledger_id: LedgerId,
    ledger_pubkey: LedgerPubKey,
    balances: Balances,
    log: L,
    height: u64,
}

impl Ledger<MemLog> {
    /// Create a root ledger (no parent account) with an in-memory log.
    pub fn new_root(ledger_pubkey: LedgerPubKey) -> Self {
        Self::new_root_with_log(ledger_pubkey, MemLog::new())
    }

    /// Create a non-root ledger (zeroed parent account) with an in-memory log.
    pub fn new_non_root(ledger_pubkey: LedgerPubKey) -> Self {
        Self::new_non_root_with_log(ledger_pubkey, MemLog::new())
    }
}

impl<L: LedgerLog> Ledger<L> {
    /// Create a root ledger over a caller-supplied log backend.
    pub fn new_root_with_log(ledger_pubkey: LedgerPubKey, log: L) -> Self {
        Ledger {
            ledger_id: ledger_pubkey,
            ledger_pubkey,
            balances: Balances::new_root(),
            log,
            height: 0,
        }
    }

    /// Create a non-root ledger over a caller-supplied log backend.
    pub fn new_non_root_with_log(ledger_pubkey: LedgerPubKey, log: L) -> Self {
        Ledger {
            ledger_id: ledger_pubkey,
            ledger_pubkey,
            balances: Balances::new_non_root(),
            log,
            height: 0,
        }
    }

    /// The ledger's public identity.
    pub fn ledger_id(&self) -> &LedgerId {
        &self.ledger_id
    }

    /// The ledger's public key.
    pub fn ledger_pubkey(&self) -> &LedgerPubKey {
        &self.ledger_pubkey
    }

    /// Current balances.
    pub fn balances(&self) -> &Balances {
        &self.balances
    }

    /// The backing log.
    pub fn log(&self) -> &L {
        &self.log
    }

    /// Number of accepted entries.
    pub fn len(&self) -> usize {
        self.log.len()
    }

    /// Whether no entries have been accepted.
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// Fetch a copy of the accepted entry at `index`, if any.
    pub fn get(&self, index: usize) -> Result<Option<SignedEntry>, LedgerError> {
        self.log.get(index)
    }

    /// Current height (the height of the last accepted entry).
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Hash of the last accepted entry ([`Hash::ZERO`] when empty).
    pub fn head_hash(&self) -> Hash {
        self.log.head_hash()
    }

    /// Validate and append a signed entry.
    ///
    /// Verification order:
    ///
    /// 1. the entry's `ledger_id` matches this ledger;
    /// 2. `RotateLedgerKey` is rejected as [`LedgerError::Unsupported`] in
    ///    Phase A;
    /// 3. the signature verifies under this ledger's public key over
    ///    `entry.canonical_bytes()`;
    /// 4. `seq` is exactly the next position (dense from 0);
    /// 5. `height == seq` (Phase A rule);
    /// 6. `prev_hash` matches the current head ([`Hash::ZERO`] at genesis);
    /// 7. the postings satisfy conservation and the canonical body shape
    ///    ([`crate::entry::Entry::check_conservation`]);
    /// 8. applying the postings keeps every `Parent`/`Child` balance
    ///    non-negative.
    ///
    /// On any failure the ledger is left completely unchanged.
    pub fn append(&mut self, signed: SignedEntry) -> Result<(), LedgerError> {
        let entry = &signed.entry;

        if entry.ledger_id != self.ledger_id {
            return Err(LedgerError::LedgerMismatch);
        }
        if matches!(&entry.body, EntryBody::RotateLedgerKey { .. }) {
            return Err(LedgerError::Unsupported);
        }

        let bytes = entry.canonical_bytes()?;
        self.ledger_pubkey.verify(&bytes, &signed.signature)?;

        let expected_seq = self.log.len() as u64;
        if entry.seq != expected_seq {
            return Err(LedgerError::SeqOutOfOrder {
                expected: expected_seq,
                found: entry.seq,
            });
        }
        if entry.height != entry.seq {
            return Err(LedgerError::InvalidHeight {
                expected: entry.seq,
                found: entry.height,
            });
        }

        let expected_prev = self.log.head_hash();
        if entry.prev_hash != expected_prev {
            return Err(LedgerError::PrevHashMismatch {
                expected: expected_prev,
                found: entry.prev_hash,
            });
        }

        entry.check_conservation()?;

        // Apply to a clone first: a failed apply must not touch the ledger.
        // Opening an account materializes its zero balance, so `accounts()` and
        // therefore `state_root` are independent of posting history.
        let mut next_balances = self.balances.clone();
        if let EntryBody::OpenAccount { child, .. } = &entry.body {
            next_balances.open_account(child)?;
        }
        next_balances.apply(&entry.postings)?;

        let new_height = entry.height;
        self.log.append(signed)?;
        self.balances = next_balances;
        self.height = new_height;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountRef, NodeId, Posting};
    use crate::amount::{Amount, SignedAmount};
    use crate::entry::{AuthRef, Entry, HopRole};
    use crate::keys::{LedgerSecretKey, OperatorSecretKey};

    fn child(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn posting(account: AccountRef, delta: i64) -> Posting {
        Posting {
            account,
            delta: SignedAmount::new(delta),
        }
    }

    fn child_posting(id: &str, delta: i64) -> Posting {
        posting(AccountRef::Child(child(id)), delta)
    }

    fn auth(seq: u64) -> AuthRef {
        let operator = OperatorSecretKey::from_bytes([6u8; 32]);
        AuthRef {
            operator: operator.public(),
            nonce: seq,
            order_hash: Hash::ZERO,
            signature: operator.sign(b"order"),
        }
    }

    fn issue(account: &str, amount: u64) -> (EntryBody, Vec<Posting>) {
        (
            EntryBody::Issue {
                account: AccountRef::Child(child(account)),
                amount: Amount::new(amount),
            },
            vec![
                child_posting(account, amount as i64),
                posting(AccountRef::Equity, -(amount as i64)),
            ],
        )
    }

    fn transfer(from: &str, to: &str, amount: u64) -> (EntryBody, Vec<Posting>) {
        (
            EntryBody::Transfer {
                payment_id: Hash::ZERO,
                amount: Amount::new(amount),
                role: HopRole::Direct,
            },
            vec![
                child_posting(from, -(amount as i64)),
                child_posting(to, amount as i64),
            ],
        )
    }

    /// Fetch all entries through the log interface.
    fn entries(ledger: &Ledger) -> Vec<SignedEntry> {
        (0..ledger.len())
            .map(|index| ledger.get(index).unwrap().unwrap())
            .collect()
    }

    /// Builds correctly-chained, signed entries against one ledger.
    struct Harness {
        key: LedgerSecretKey,
        ledger: Ledger,
        seq: u64,
        prev: Hash,
    }

    impl Harness {
        fn root() -> Self {
            let key = LedgerSecretKey::from_bytes([7u8; 32]);
            Harness {
                ledger: Ledger::new_root(key.public()),
                key,
                seq: 0,
                prev: Hash::ZERO,
            }
        }

        fn non_root() -> Self {
            let key = LedgerSecretKey::from_bytes([8u8; 32]);
            Harness {
                ledger: Ledger::new_non_root(key.public()),
                key,
                seq: 0,
                prev: Hash::ZERO,
            }
        }

        fn build(&self, body: EntryBody, postings: Vec<Posting>) -> SignedEntry {
            let auth = match &body {
                EntryBody::Transfer { .. } | EntryBody::Issue { .. } | EntryBody::Burn { .. } => {
                    Some(auth(self.seq))
                }
                _ => None,
            };
            self.build_with_auth(body, postings, auth)
        }

        fn build_with_auth(
            &self,
            body: EntryBody,
            postings: Vec<Posting>,
            auth: Option<AuthRef>,
        ) -> SignedEntry {
            let entry = Entry {
                ledger_id: self.key.public(),
                seq: self.seq,
                height: self.seq,
                prev_hash: self.prev,
                issued_at: 1_000 + self.seq,
                body,
                postings,
                auth,
            };
            SignedEntry::sign(entry, &self.key).unwrap()
        }

        /// Build, append, and advance the chain pointers on success.
        fn commit(&mut self, body: EntryBody, postings: Vec<Posting>) -> Result<(), LedgerError> {
            let signed = self.build(body, postings);
            let head = entry_hash(&signed.entry).unwrap();
            self.ledger.append(signed)?;
            self.seq += 1;
            self.prev = head;
            Ok(())
        }

        fn commit_issue(&mut self, account: &str, amount: u64) -> Result<(), LedgerError> {
            let (body, postings) = issue(account, amount);
            self.commit(body, postings)
        }

        fn commit_open(&mut self, child_id: &str) -> Result<(), LedgerError> {
            self.commit(
                EntryBody::OpenAccount {
                    child: child(child_id),
                    kind: cawala_topology::ChildKind::Node,
                },
                vec![],
            )
        }

        fn commit_transfer(
            &mut self,
            from: &str,
            to: &str,
            amount: u64,
        ) -> Result<(), LedgerError> {
            let (body, postings) = transfer(from, to, amount);
            self.commit(body, postings)
        }
    }

    #[test]
    fn genesis_append_succeeds() {
        let mut h = Harness::root();
        h.commit_open("a").unwrap();
        h.commit_issue("a", 100).unwrap();

        assert_eq!(h.ledger.len(), 2);
        assert_eq!(h.ledger.height(), 1);
        assert_eq!(
            h.ledger.balances().child_balance(&child("a")),
            Amount::new(100)
        );
        assert_eq!(h.ledger.balances().equity(), -100);
        assert_eq!(h.ledger.head_hash(), h.prev);
        assert_ne!(h.ledger.head_hash(), Hash::ZERO);
    }

    #[test]
    fn empty_log_head_is_zero() {
        let h = Harness::root();
        assert_eq!(h.ledger.head_hash(), Hash::ZERO);
        assert!(h.ledger.is_empty());
        assert_eq!(h.ledger.get(0).unwrap(), None);
    }

    #[test]
    fn sequential_chain_is_accepted() {
        let mut h = Harness::root();
        h.commit_open("a").unwrap();
        h.commit_open("b").unwrap();
        h.commit_issue("a", 100).unwrap();
        h.commit_transfer("a", "b", 30).unwrap();
        h.commit_issue("b", 5).unwrap();

        assert_eq!(h.ledger.len(), 5);
        assert_eq!(h.ledger.height(), 4);
        assert_eq!(
            h.ledger.balances().child_balance(&child("a")),
            Amount::new(70)
        );
        assert_eq!(
            h.ledger.balances().child_balance(&child("b")),
            Amount::new(35)
        );
        assert_eq!(h.ledger.balances().equity(), -105);
    }

    #[test]
    fn get_round_trips_through_the_log() {
        let mut h = Harness::root();
        h.commit_open("a").unwrap();
        h.commit_open("b").unwrap();
        h.commit_issue("a", 100).unwrap();
        h.commit_transfer("a", "b", 10).unwrap();

        let all = entries(&h.ledger);
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].entry.seq, 0);
        assert_eq!(all[1].entry.seq, 1);
        assert_eq!(h.ledger.get(4).unwrap(), None);
    }

    #[test]
    fn seq_gap_is_rejected() {
        let mut h = Harness::root();
        let (body, postings) = issue("a", 100);
        let mut signed = h.build(body, postings);
        signed.entry.seq = 5;
        signed = SignedEntry::sign(signed.entry, &h.key).unwrap();
        assert_eq!(
            h.ledger.append(signed),
            Err(LedgerError::SeqOutOfOrder {
                expected: 0,
                found: 5
            })
        );
        assert!(h.ledger.is_empty());
    }

    #[test]
    fn height_not_equal_seq_is_rejected() {
        let mut h = Harness::root();
        let (body, postings) = issue("a", 100);
        let mut signed = h.build(body, postings);
        signed.entry.height = 3; // seq is still 0
        signed = SignedEntry::sign(signed.entry, &h.key).unwrap();
        assert_eq!(
            h.ledger.append(signed),
            Err(LedgerError::InvalidHeight {
                expected: 0,
                found: 3
            })
        );
        assert!(h.ledger.is_empty());
    }

    #[test]
    fn replayed_genesis_is_rejected() {
        let mut h = Harness::root();
        let first = h.build(
            EntryBody::OpenAccount {
                child: child("a"),
                kind: cawala_topology::ChildKind::Node,
            },
            vec![],
        );
        h.commit_open("a").unwrap();
        assert_eq!(
            h.ledger.append(first),
            Err(LedgerError::SeqOutOfOrder {
                expected: 1,
                found: 0
            })
        );
        assert_eq!(h.ledger.len(), 1);
    }

    #[test]
    fn prev_hash_mismatch_is_rejected() {
        let mut h = Harness::root();
        h.commit_open("a").unwrap();
        h.commit_open("b").unwrap();
        h.commit_issue("a", 100).unwrap();

        let (body, postings) = transfer("a", "b", 10);
        let mut signed = h.build(body, postings);
        signed.entry.prev_hash = Hash::ZERO;
        signed = SignedEntry::sign(signed.entry, &h.key).unwrap();

        assert_eq!(
            h.ledger.append(signed),
            Err(LedgerError::PrevHashMismatch {
                expected: h.prev,
                found: Hash::ZERO
            })
        );
        assert_eq!(h.ledger.len(), 3);
    }

    #[test]
    fn tampered_entry_is_rejected() {
        let mut h = Harness::root();
        h.commit_open("a").unwrap();
        h.commit_open("b").unwrap();
        h.commit_issue("a", 100).unwrap();

        let (body, postings) = transfer("a", "b", 10);
        let mut signed = h.build(body, postings);
        signed.entry.issued_at = 0;
        assert_eq!(h.ledger.append(signed), Err(LedgerError::InvalidSignature));
        assert_eq!(h.ledger.len(), 3);
    }

    #[test]
    fn missing_auth_is_rejected() {
        let mut h = Harness::root();
        let (body, postings) = issue("a", 100);
        let signed = h.build_with_auth(body, postings, None);
        assert_eq!(
            h.ledger.append(signed),
            Err(LedgerError::MissingAuthorization)
        );
        assert!(h.ledger.is_empty());
    }

    #[test]
    fn tampered_auth_is_rejected() {
        let mut h = Harness::root();
        h.commit_open("a").unwrap();
        h.commit_open("b").unwrap();
        h.commit_issue("a", 100).unwrap();
        let (body, postings) = transfer("a", "b", 10);
        let mut signed = h.build(body, postings);
        signed.entry.auth.as_mut().unwrap().nonce += 1;
        assert_eq!(h.ledger.append(signed), Err(LedgerError::InvalidSignature));
        assert_eq!(h.ledger.len(), 3);
    }

    #[test]
    fn rotate_ledger_key_is_unsupported() {
        let mut h = Harness::root();
        let body = EntryBody::RotateLedgerKey {
            new_key: LedgerSecretKey::from_bytes([9u8; 32]).public(),
            operator_sig: OperatorSecretKey::from_bytes([6u8; 32]).sign(b"rotate"),
        };
        let signed = h.build(body, vec![]);
        assert_eq!(h.ledger.append(signed), Err(LedgerError::Unsupported));
        assert!(h.ledger.is_empty());
    }

    #[test]
    fn wrong_ledger_id_is_rejected() {
        let mut h = Harness::root();
        let other = LedgerSecretKey::from_bytes([42u8; 32]).public();
        let (body, postings) = issue("a", 100);
        let mut signed = h.build(body, postings);
        signed.entry.ledger_id = other;
        assert_eq!(h.ledger.append(signed), Err(LedgerError::LedgerMismatch));
        assert!(h.ledger.is_empty());
    }

    #[test]
    fn overdraw_is_rejected_and_state_is_unchanged() {
        let mut h = Harness::root();
        h.commit_open("a").unwrap();
        h.commit_open("b").unwrap();
        h.commit_issue("a", 10).unwrap();
        let before_log = entries(&h.ledger);
        let before_balances = h.ledger.balances().clone();

        assert_eq!(
            h.commit_transfer("a", "b", 11),
            Err(LedgerError::InsufficientBalance)
        );
        assert_eq!(entries(&h.ledger), before_log);
        assert_eq!(h.ledger.balances(), &before_balances);
        assert_eq!(h.ledger.height(), 2);
    }

    #[test]
    fn non_conserving_entry_is_rejected() {
        let mut h = Harness::root();
        let entry = h.build(
            EntryBody::Issue {
                account: AccountRef::Child(child("a")),
                amount: Amount::new(100),
            },
            vec![child_posting("a", 100)],
        );
        assert_eq!(
            h.ledger.append(entry),
            Err(LedgerError::ConservationViolation)
        );
        assert!(h.ledger.is_empty());
    }

    #[test]
    fn posting_to_unopened_child_is_rejected() {
        let mut h = Harness::root();
        let (body, postings) = issue("a", 100);
        assert_eq!(
            h.commit(body, postings),
            Err(LedgerError::AccountNotOpened {
                account: AccountRef::Child(child("a"))
            })
        );
        assert!(h.ledger.is_empty());
    }

    #[test]
    fn non_root_shapes_append() {
        let mut h = Harness::non_root();
        h.commit_open("a").unwrap();
        h.commit_issue("a", 100).unwrap();

        // Descend: Parent+/Child+
        h.commit(
            EntryBody::Transfer {
                payment_id: Hash::ZERO,
                amount: Amount::new(20),
                role: HopRole::Descend,
            },
            vec![posting(AccountRef::Parent, 20), child_posting("a", 20)],
        )
        .unwrap();
        assert_eq!(h.ledger.balances().parent_balance(), Some(Amount::new(20)));
        assert_eq!(
            h.ledger.balances().child_balance(&child("a")),
            Amount::new(120)
        );
    }

    /// A distinct log backend proves `Ledger<L>` works through the trait.
    #[derive(Debug, Clone, Default)]
    struct CountingLog {
        inner: MemLog,
        appends: usize,
    }

    impl LedgerLog for CountingLog {
        fn append(&mut self, entry: SignedEntry) -> Result<(), LedgerError> {
            self.appends += 1;
            self.inner.append(entry)
        }

        fn len(&self) -> usize {
            self.inner.len()
        }

        fn get(&self, index: usize) -> Result<Option<SignedEntry>, LedgerError> {
            self.inner.get(index)
        }

        fn head_hash(&self) -> Hash {
            self.inner.head_hash()
        }
    }

    #[test]
    fn ledger_is_generic_over_the_log() {
        let key = LedgerSecretKey::from_bytes([13u8; 32]);
        let mut ledger: Ledger<CountingLog> =
            Ledger::new_root_with_log(key.public(), CountingLog::default());

        let entry = Entry {
            ledger_id: key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::OpenAccount {
                child: child("a"),
                kind: cawala_topology::ChildKind::Node,
            },
            postings: vec![],
            auth: None,
        };
        let signed = SignedEntry::sign(entry, &key).unwrap();
        ledger.append(signed).unwrap();

        assert_eq!(ledger.log().appends, 1);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.get(0).unwrap().unwrap().entry.seq, 0);
        assert_eq!(ledger.get(1).unwrap(), None);
        assert_ne!(ledger.head_hash(), Hash::ZERO);
    }

    #[test]
    fn open_account_materializes_and_rejects_replay() {
        let mut h = Harness::root();
        h.commit(
            EntryBody::OpenAccount {
                child: child("a"),
                kind: cawala_topology::ChildKind::Node,
            },
            vec![],
        )
        .unwrap();
        assert_eq!(h.ledger.balances().child_balance(&child("a")), Amount::ZERO);
        assert!(
            h.ledger.balances().accounts().any(|(account, balance)| {
                account == AccountRef::Child(child("a")) && balance == 0
            }),
            "zero account must be enumerable for state commitments"
        );

        // Replaying the same OpenAccount is rejected atomically.
        assert_eq!(
            h.commit(
                EntryBody::OpenAccount {
                    child: child("a"),
                    kind: cawala_topology::ChildKind::Node,
                },
                vec![],
            ),
            Err(LedgerError::AccountExists)
        );
        assert_eq!(h.ledger.len(), 1);

        // A different account can still be opened.
        h.commit(
            EntryBody::OpenAccount {
                child: child("b"),
                kind: cawala_topology::ChildKind::User,
            },
            vec![],
        )
        .unwrap();
        assert_eq!(h.ledger.len(), 2);
    }

    #[test]
    fn mem_log_caches_head_hash() {
        let key = LedgerSecretKey::from_bytes([3u8; 32]);
        let mut log = MemLog::new();
        assert!(log.is_empty());
        assert_eq!(log.head_hash(), Hash::ZERO);

        let entry = Entry {
            ledger_id: key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::OpenAccount {
                child: child("a"),
                kind: cawala_topology::ChildKind::Node,
            },
            postings: vec![],
            auth: None,
        };
        let signed = SignedEntry::sign(entry, &key).unwrap();
        let head = entry_hash(&signed.entry).unwrap();
        log.append(signed).unwrap();
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
        assert_eq!(log.head_hash(), head);
    }
}
