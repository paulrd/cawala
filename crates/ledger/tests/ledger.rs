//! End-to-end ledger integration tests, exercising only the public API.
//!
//! These complement the per-module unit tests: they prove the frozen public
//! model composes (chain building, key separation, conservation, canonical
//! posting shapes, prefunded-only settlement) from outside the crate.

use cawala_ledger::{
    AccountRef, Amount, AuthRef, Entry, EntryBody, Hash, HopRole, Ledger, LedgerError,
    LedgerPubKey, LedgerSecretKey, NodeId, OperatorSecretKey, Posting, SignedAmount, SignedEntry,
    entry_hash,
};

fn child(id: &str) -> NodeId {
    NodeId::from(id)
}

fn ledger_key() -> LedgerSecretKey {
    LedgerSecretKey::from_bytes([11u8; 32])
}

fn operator_key() -> OperatorSecretKey {
    OperatorSecretKey::from_bytes([12u8; 32])
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
    AuthRef {
        operator: operator_key().public(),
        nonce: seq,
        order_hash: Hash::ZERO,
        signature: operator_key().sign(b"order"),
    }
}

fn entries(ledger: &Ledger) -> Vec<SignedEntry> {
    (0..ledger.len())
        .map(|index| ledger.get(index).unwrap().unwrap())
        .collect()
}

/// Builds correctly-chained, signed entries against one ledger.
struct Chain {
    key: LedgerSecretKey,
    ledger: Ledger,
    seq: u64,
    prev: Hash,
}

impl Chain {
    fn root() -> Self {
        let key = ledger_key();
        let ledger = Ledger::new_root(key.public());
        Chain {
            key,
            ledger,
            seq: 0,
            prev: Hash::ZERO,
        }
    }

    fn non_root() -> Self {
        let key = ledger_key();
        let ledger = Ledger::new_non_root(key.public());
        Chain {
            key,
            ledger,
            seq: 0,
            prev: Hash::ZERO,
        }
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

    fn build(&self, body: EntryBody, postings: Vec<Posting>) -> SignedEntry {
        let auth = match &body {
            EntryBody::Transfer { .. } | EntryBody::Issue { .. } | EntryBody::Burn { .. } => {
                Some(auth(self.seq))
            }
            _ => None,
        };
        self.build_with_auth(body, postings, auth)
    }

    fn commit(&mut self, body: EntryBody, postings: Vec<Posting>) -> Result<(), LedgerError> {
        let signed = self.build(body, postings);
        let head = entry_hash(&signed.entry).unwrap();
        self.ledger.append(signed)?;
        self.seq += 1;
        self.prev = head;
        Ok(())
    }

    fn issue(&mut self, account: &str, amount: u64) -> Result<(), LedgerError> {
        self.commit(
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

    fn burn(&mut self, account: &str, amount: u64) -> Result<(), LedgerError> {
        self.commit(
            EntryBody::Burn {
                account: AccountRef::Child(child(account)),
                amount: Amount::new(amount),
            },
            vec![
                child_posting(account, -(amount as i64)),
                posting(AccountRef::Equity, amount as i64),
            ],
        )
    }

    fn transfer(
        &mut self,
        role: HopRole,
        from: AccountRef,
        to: AccountRef,
        amount: u64,
    ) -> Result<(), LedgerError> {
        let postings = vec![
            Posting {
                account: from,
                delta: SignedAmount::new(-(amount as i64)),
            },
            Posting {
                account: to,
                delta: SignedAmount::new(amount as i64),
            },
        ];
        self.commit(
            EntryBody::Transfer {
                payment_id: Hash::ZERO,
                amount: Amount::new(amount),
                role,
            },
            postings,
        )
    }

    /// Descend: the node's parent asset and a child liability both increase.
    fn descend(&mut self, name: &str, amount: u64) -> Result<(), LedgerError> {
        self.commit(
            EntryBody::Transfer {
                payment_id: Hash::ZERO,
                amount: Amount::new(amount),
                role: HopRole::Descend,
            },
            vec![
                posting(AccountRef::Parent, amount as i64),
                child_posting(name, amount as i64),
            ],
        )
    }

    /// Ascend: the node's parent asset and a child liability both decrease.
    fn ascend(&mut self, name: &str, amount: u64) -> Result<(), LedgerError> {
        self.commit(
            EntryBody::Transfer {
                payment_id: Hash::ZERO,
                amount: Amount::new(amount),
                role: HopRole::Ascend,
            },
            vec![
                posting(AccountRef::Parent, -(amount as i64)),
                child_posting(name, -(amount as i64)),
            ],
        )
    }

    /// Open a zeroed child account so postings may reference it.
    fn open(&mut self, child_id: &str) -> Result<(), LedgerError> {
        self.commit(
            EntryBody::OpenAccount {
                child: child(child_id),
                kind: cawala_topology::ChildKind::Node,
            },
            vec![],
        )
    }
}

#[test]
fn genesis_and_chain_end_to_end() {
    let mut chain = Chain::root();
    chain.open("a").unwrap();
    chain.open("b").unwrap();
    chain.issue("a", 100).unwrap();
    chain
        .transfer(
            HopRole::Direct,
            AccountRef::Child(child("a")),
            AccountRef::Child(child("b")),
            30,
        )
        .unwrap();
    chain.burn("a", 10).unwrap();

    assert_eq!(chain.ledger.len(), 5);
    assert_eq!(chain.ledger.height(), 4);
    assert_eq!(
        chain.ledger.balances().child_balance(&child("a")),
        Amount::new(60)
    );
    assert_eq!(
        chain.ledger.balances().child_balance(&child("b")),
        Amount::new(30)
    );
    assert_eq!(chain.ledger.balances().equity(), -90);
    assert_eq!(chain.ledger.head_hash(), chain.prev);

    for (index, signed) in entries(&chain.ledger).iter().enumerate() {
        let expected_prev = if index == 0 {
            Hash::ZERO
        } else {
            entry_hash(&entries(&chain.ledger)[index - 1].entry).unwrap()
        };
        assert_eq!(signed.entry.prev_hash, expected_prev);
        assert_eq!(signed.entry.seq, index as u64);
        assert_eq!(signed.entry.height, index as u64);
    }
}

#[test]
fn every_transfer_shape_is_accepted() {
    let mut chain = Chain::non_root();
    chain.open("a").unwrap();
    chain.open("b").unwrap();
    chain.issue("a", 100).unwrap();
    // Descend: Parent+/Child+
    chain.descend("a", 100).unwrap();
    // Ascend: Parent−/Child−
    chain.ascend("a", 40).unwrap();
    // LCA reallocation: Child a−/Child b+
    chain
        .transfer(
            HopRole::Lca,
            AccountRef::Child(child("a")),
            AccountRef::Child(child("b")),
            20,
        )
        .unwrap();
    // A credit leg at the LCA (credited child).
    chain
        .transfer(
            HopRole::Lca,
            AccountRef::Child(child("b")),
            AccountRef::Child(child("a")),
            5,
        )
        .unwrap();
    // Direct sibling move.
    chain
        .transfer(
            HopRole::Direct,
            AccountRef::Child(child("a")),
            AccountRef::Child(child("b")),
            5,
        )
        .unwrap();

    assert_eq!(
        chain.ledger.balances().parent_balance(),
        Some(Amount::new(60))
    );
    assert_eq!(
        chain.ledger.balances().child_balance(&child("a")),
        Amount::new(140)
    );
    assert_eq!(
        chain.ledger.balances().child_balance(&child("b")),
        Amount::new(20)
    );
    assert_eq!(chain.ledger.balances().equity(), -100);
}

#[test]
fn open_account_with_empty_postings_is_accepted() {
    let mut chain = Chain::root();
    chain
        .commit(
            EntryBody::OpenAccount {
                child: child("a"),
                kind: cawala_topology::ChildKind::Node,
            },
            vec![],
        )
        .unwrap();
    assert_eq!(chain.ledger.len(), 1);
    assert_eq!(
        chain.ledger.balances().child_balance(&child("a")),
        Amount::ZERO
    );
}

#[test]
fn overdraw_is_rejected() {
    let mut chain = Chain::root();
    chain.open("a").unwrap();
    chain.open("b").unwrap();
    chain.issue("a", 10).unwrap();
    let snapshot = chain.ledger.balances().clone();
    assert_eq!(
        chain.transfer(
            HopRole::Direct,
            AccountRef::Child(child("a")),
            AccountRef::Child(child("b")),
            11
        ),
        Err(LedgerError::InsufficientBalance)
    );
    assert_eq!(chain.ledger.len(), 3);
    assert_eq!(chain.ledger.balances(), &snapshot);
}

#[test]
fn non_conserving_entry_is_rejected() {
    let mut chain = Chain::root();
    let signed = chain.build(
        EntryBody::Issue {
            account: AccountRef::Child(child("a")),
            amount: Amount::new(100),
        },
        vec![child_posting("a", 100)],
    );
    assert_eq!(
        chain.ledger.append(signed),
        Err(LedgerError::ConservationViolation)
    );
    assert!(chain.ledger.is_empty());
}

#[test]
fn wrong_issue_amount_is_rejected() {
    let mut chain = Chain::root();
    let signed = chain.build(
        EntryBody::Issue {
            account: AccountRef::Child(child("a")),
            amount: Amount::new(100),
        },
        vec![child_posting("a", 99), posting(AccountRef::Equity, -99)],
    );
    assert_eq!(
        chain.ledger.append(signed),
        Err(LedgerError::InvalidEntryShape)
    );
}

#[test]
fn missing_auth_is_rejected() {
    let mut chain = Chain::root();
    let signed = chain.build_with_auth(
        EntryBody::Issue {
            account: AccountRef::Child(child("a")),
            amount: Amount::new(100),
        },
        vec![child_posting("a", 100), posting(AccountRef::Equity, -100)],
        None,
    );
    assert_eq!(
        chain.ledger.append(signed),
        Err(LedgerError::MissingAuthorization)
    );
}

#[test]
fn rotate_ledger_key_is_unsupported() {
    let mut chain = Chain::root();
    let signed = chain.build(
        EntryBody::RotateLedgerKey {
            new_key: LedgerSecretKey::from_bytes([99u8; 32]).public(),
            operator_sig: operator_key().sign(b"rotate"),
        },
        vec![],
    );
    assert_eq!(chain.ledger.append(signed), Err(LedgerError::Unsupported));
    assert!(chain.ledger.is_empty());
}

#[test]
fn hash_chain_violations_are_rejected() {
    let mut chain = Chain::root();
    chain.open("a").unwrap();
    chain.open("b").unwrap();
    chain.issue("a", 100).unwrap();

    // Wrong prev_hash for seq 1.
    let mut signed = chain.build(
        EntryBody::Transfer {
            payment_id: Hash::ZERO,
            amount: Amount::new(5),
            role: HopRole::Direct,
        },
        vec![child_posting("a", -5), child_posting("b", 5)],
    );
    let good_prev = signed.entry.prev_hash;
    signed.entry.prev_hash = Hash::ZERO;
    signed = SignedEntry::sign(signed.entry, &chain.key).unwrap();
    assert!(matches!(
        chain.ledger.append(signed),
        Err(LedgerError::PrevHashMismatch { expected, found })
            if expected == good_prev && found == Hash::ZERO
    ));

    // Seq gap.
    let mut signed = chain.build(
        EntryBody::OpenAccount {
            child: child("b"),
            kind: cawala_topology::ChildKind::Node,
        },
        vec![],
    );
    signed.entry.seq = 7;
    signed = SignedEntry::sign(signed.entry, &chain.key).unwrap();
    assert_eq!(
        chain.ledger.append(signed),
        Err(LedgerError::SeqOutOfOrder {
            expected: 3,
            found: 7
        })
    );

    // Height must equal seq.
    let mut signed = chain.build(
        EntryBody::OpenAccount {
            child: child("b"),
            kind: cawala_topology::ChildKind::Node,
        },
        vec![],
    );
    signed.entry.height = 5;
    signed = SignedEntry::sign(signed.entry, &chain.key).unwrap();
    assert_eq!(
        chain.ledger.append(signed),
        Err(LedgerError::InvalidHeight {
            expected: 3,
            found: 5
        })
    );

    // Tampered after signing.
    let mut signed = chain.build(
        EntryBody::OpenAccount {
            child: child("b"),
            kind: cawala_topology::ChildKind::Node,
        },
        vec![],
    );
    signed.entry.issued_at = 0xdead_beef;
    assert_eq!(
        chain.ledger.append(signed),
        Err(LedgerError::InvalidSignature)
    );

    assert_eq!(chain.ledger.len(), 3);
}

#[test]
fn wrong_ledger_id_is_rejected() {
    let mut chain = Chain::root();
    let other =
        LedgerPubKey::from_bytes(&LedgerSecretKey::from_bytes([99u8; 32]).public().to_bytes())
            .unwrap();
    let mut signed = chain.build(
        EntryBody::OpenAccount {
            child: child("a"),
            kind: cawala_topology::ChildKind::Node,
        },
        vec![],
    );
    signed.entry.ledger_id = other;
    assert_eq!(
        chain.ledger.append(signed),
        Err(LedgerError::LedgerMismatch)
    );
}

#[test]
fn signatures_are_bound_to_the_ledger_key() {
    let chain = Chain::root();
    let signed = chain.build(
        EntryBody::OpenAccount {
            child: child("a"),
            kind: cawala_topology::ChildKind::Node,
        },
        vec![],
    );

    // Correct ledger key verifies.
    assert_eq!(signed.verify(&chain.key.public()), Ok(()));

    // A different ledger key is rejected as a ledger mismatch (m2).
    let other = LedgerSecretKey::from_bytes([77u8; 32]);
    assert_eq!(
        signed.verify(&other.public()),
        Err(LedgerError::LedgerMismatch)
    );

    // The operator key cannot verify a ledger signature when checked directly
    // (same curve, different key material).
    let operator_as_ledger = LedgerPubKey::from_bytes(&operator_key().public().to_bytes()).unwrap();
    let bytes = signed.entry.canonical_bytes().unwrap();
    assert_eq!(
        operator_as_ledger.verify(&bytes, &signed.signature),
        Err(LedgerError::InvalidSignature)
    );
}

#[test]
fn issue_and_burn_move_equity_by_the_exact_amount() {
    let mut chain = Chain::root();
    chain.open("a").unwrap();
    chain.open("b").unwrap();
    chain.issue("a", 250).unwrap();
    assert_eq!(chain.ledger.balances().equity(), -250);

    chain.burn("a", 90).unwrap();
    assert_eq!(chain.ledger.balances().equity(), -160);

    chain.issue("b", 10).unwrap();
    assert_eq!(chain.ledger.balances().equity(), -170);
    assert_eq!(
        chain.ledger.balances().child_balance(&child("a")),
        Amount::new(160)
    );
    assert_eq!(
        chain.ledger.balances().child_balance(&child("b")),
        Amount::new(10)
    );
}
