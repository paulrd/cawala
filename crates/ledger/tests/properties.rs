//! Property-based tests for the ledger core.
//!
//! Style mirrors `crates/topology/tests/properties.rs`: a tiny deterministic
//! xorshift64* PRNG drives random-but-valid operation sequences, wrapped in
//! `proptest!` so failing seeds shrink.
//!
//! Covered invariants:
//!
//! - `root_accounting_identity_holds`: after every random issue/burn/transfer
//!   the root identity `0 − Σchildren − equity == 0` holds, the model balances
//!   match, overdraw is the only rejection, and the hash chain links cleanly.
//! - `non_root_accounting_identity_holds`: the same for a non-root ledger
//!   across all Ascend/Descend/LCA/Issue/Burn shapes.
//! - `equity_tracks_issue_and_burn`: equity changes by exactly the issued and
//!   burned amounts.

use std::collections::BTreeMap;

use cawala_ledger::{
    AccountRef, Amount, AuthRef, Balances, Entry, EntryBody, Hash, HopRole, Ledger, LedgerError,
    LedgerSecretKey, NodeId, OperatorSecretKey, Posting, SignedAmount, SignedEntry, entry_hash,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

/// Tiny deterministic xorshift64* PRNG so the generator needs no extra deps.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        debug_assert!(lo < hi);
        lo + (self.next() % (hi - lo) as u64) as usize
    }
}

const NAMES: [&str; 3] = ["a", "b", "c"];

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
    let operator = OperatorSecretKey::from_bytes([31u8; 32]);
    AuthRef {
        operator: operator.public(),
        nonce: seq,
        order_hash: Hash::ZERO,
        signature: operator.sign(b"order"),
    }
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
        let key = LedgerSecretKey::from_bytes([21u8; 32]);
        let ledger = Ledger::new_root(key.public());
        Chain {
            key,
            ledger,
            seq: 0,
            prev: Hash::ZERO,
        }
    }

    fn non_root() -> Self {
        let key = LedgerSecretKey::from_bytes([22u8; 32]);
        let ledger = Ledger::new_non_root(key.public());
        Chain {
            key,
            ledger,
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

    /// Descend: parent asset and child liability both increase.
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

    /// Ascend: parent asset and child liability both decrease.
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

fn model_children() -> BTreeMap<NodeId, i128> {
    NAMES.iter().map(|name| (child(name), 0i128)).collect()
}

fn check_root_identity(balances: &Balances) {
    let parent = balances.parent_balance().map_or(0, |a| a.get() as i128);
    let children: i128 = NAMES
        .iter()
        .map(|name| balances.child_balance(&child(name)).get() as i128)
        .sum();
    assert_eq!(
        parent - children - balances.equity(),
        0,
        "accounting identity must hold"
    );
}

fn check_non_root_identity(balances: &Balances) {
    let parent = balances.parent_balance().map_or(0, |a| a.get() as i128);
    let children: i128 = NAMES
        .iter()
        .map(|name| balances.child_balance(&child(name)).get() as i128)
        .sum();
    assert_eq!(
        parent - children - balances.equity(),
        0,
        "non-root accounting identity must hold"
    );
}

fn check_model(balances: &Balances, model: &BTreeMap<NodeId, i128>) {
    for name in NAMES {
        assert_eq!(
            balances.child_balance(&child(name)).get() as i128,
            model[&child(name)],
            "child {name} balance mismatch"
        );
    }
}

fn check_chain(chain: &Chain) {
    for index in 0..chain.ledger.len() {
        let signed = chain.ledger.get(index).unwrap().unwrap();
        assert_eq!(signed.entry.seq, index as u64, "seq must be dense from 0");
        assert_eq!(signed.entry.height, index as u64, "height must equal seq");
        let expected_prev = if index == 0 {
            Hash::ZERO
        } else {
            let previous = chain.ledger.get(index - 1).unwrap().unwrap();
            entry_hash(&previous.entry).unwrap()
        };
        assert_eq!(signed.entry.prev_hash, expected_prev, "prev_hash link");
    }
    assert_eq!(chain.ledger.head_hash(), chain.prev, "head hash");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]
    #[test]
    fn root_accounting_identity_holds(seed in any::<u64>(), steps in 1usize..=80) {
        let mut rng = Rng::new(seed);
        let mut chain = Chain::root();
        let mut model = model_children();

        let mut equity = 0i128;
        for name in NAMES {
            chain.open(name).unwrap();
        }
        for name in NAMES {
            chain.issue(name, 500).unwrap();
            *model.get_mut(&child(name)).unwrap() += 500;
            equity -= 500;
        }
        check_root_identity(chain.ledger.balances());
        check_model(chain.ledger.balances(), &model);

        for _ in 0..steps {
            let roll = rng.range(0, 100);
            if roll < 45 {
                // Sibling transfer.
                let x = child(NAMES[rng.range(0, NAMES.len())]);
                let mut y = child(NAMES[rng.range(0, NAMES.len())]);
                while y == x {
                    y = child(NAMES[rng.range(0, NAMES.len())]);
                }
                let amount = rng.range(1, 400) as i128;
                let result = chain.transfer(
                    HopRole::Direct,
                    AccountRef::Child(x.clone()),
                    AccountRef::Child(y.clone()),
                    amount as u64,
                );
                if model[&x] >= amount {
                    assert!(result.is_ok(), "transfer should succeed: {result:?}");
                    *model.get_mut(&x).unwrap() -= amount;
                    *model.get_mut(&y).unwrap() += amount;
                } else {
                    assert_eq!(result, Err(LedgerError::InsufficientBalance));
                }
            } else if roll < 75 {
                // Issue.
                let name = NAMES[rng.range(0, NAMES.len())];
                let amount = rng.range(1, 400) as i128;
                assert!(chain.issue(name, amount as u64).is_ok());
                *model.get_mut(&child(name)).unwrap() += amount;
                equity -= amount;
            } else {
                // Burn.
                let name = NAMES[rng.range(0, NAMES.len())];
                let amount = rng.range(1, 400) as i128;
                let result = chain.burn(name, amount as u64);
                if model[&child(name)] >= amount {
                    assert!(result.is_ok(), "burn should succeed: {result:?}");
                    *model.get_mut(&child(name)).unwrap() -= amount;
                    equity += amount;
                } else {
                    assert_eq!(result, Err(LedgerError::InsufficientBalance));
                }
            }

            check_root_identity(chain.ledger.balances());
            check_model(chain.ledger.balances(), &model);
            assert_eq!(chain.ledger.balances().equity(), equity);
            check_chain(&chain);
        }
    }

    #[test]
    fn non_root_accounting_identity_holds(seed in any::<u64>(), steps in 1usize..=80) {
        let mut rng = Rng::new(seed);
        let mut chain = Chain::non_root();
        let mut model = model_children();
        let mut equity = 0i128;

        for name in NAMES {
            chain.open(name).unwrap();
        }
        chain.issue("a", 800).unwrap();
        *model.get_mut(&child("a")).unwrap() += 800;
        equity -= 800;
        chain.descend("a", 800).unwrap();
        let mut parent = 800i128;
        *model.get_mut(&child("a")).unwrap() += 800;

        for _ in 0..steps {
            let roll = rng.range(0, 100);
            if roll < 20 {
                // Descend: always affordable.
                let name = NAMES[rng.range(0, NAMES.len())];
                let amount = rng.range(1, 300) as i128;
                assert!(chain.descend(name, amount as u64).is_ok());
                parent += amount;
                *model.get_mut(&child(name)).unwrap() += amount;
            } else if roll < 40 {
                // Ascend: needs parent and child both funded.
                let name = NAMES[rng.range(0, NAMES.len())];
                let amount = rng.range(1, 300) as i128;
                let result = chain.ascend(name, amount as u64);
                if parent >= amount && model[&child(name)] >= amount {
                    assert!(result.is_ok(), "ascend should succeed: {result:?}");
                    parent -= amount;
                    *model.get_mut(&child(name)).unwrap() -= amount;
                } else {
                    assert_eq!(result, Err(LedgerError::InsufficientBalance));
                }
            } else if roll < 60 {
                // LCA reallocation: Child−/Child+.
                let x = child(NAMES[rng.range(0, NAMES.len())]);
                let mut y = child(NAMES[rng.range(0, NAMES.len())]);
                while y == x {
                    y = child(NAMES[rng.range(0, NAMES.len())]);
                }
                let amount = rng.range(1, 300) as i128;
                let result = chain.transfer(
                    HopRole::Lca,
                    AccountRef::Child(x.clone()),
                    AccountRef::Child(y.clone()),
                    amount as u64,
                );
                if model[&x] >= amount {
                    assert!(result.is_ok(), "lca should succeed: {result:?}");
                    *model.get_mut(&x).unwrap() -= amount;
                    *model.get_mut(&y).unwrap() += amount;
                } else {
                    assert_eq!(result, Err(LedgerError::InsufficientBalance));
                }
            } else if roll < 80 {
                // Issue.
                let name = NAMES[rng.range(0, NAMES.len())];
                let amount = rng.range(1, 300) as i128;
                assert!(chain.issue(name, amount as u64).is_ok());
                *model.get_mut(&child(name)).unwrap() += amount;
                equity -= amount;
            } else {
                // Burn.
                let name = NAMES[rng.range(0, NAMES.len())];
                let amount = rng.range(1, 300) as i128;
                let result = chain.burn(name, amount as u64);
                if model[&child(name)] >= amount {
                    assert!(result.is_ok(), "burn should succeed: {result:?}");
                    *model.get_mut(&child(name)).unwrap() -= amount;
                    equity += amount;
                } else {
                    assert_eq!(result, Err(LedgerError::InsufficientBalance));
                }
            }

            check_non_root_identity(chain.ledger.balances());
            check_model(chain.ledger.balances(), &model);
            assert_eq!(
                chain.ledger.balances().parent_balance(),
                Some(Amount::new(parent as u64))
            );
            assert_eq!(chain.ledger.balances().equity(), equity);
            check_chain(&chain);
        }
    }

    #[test]
    fn equity_tracks_issue_and_burn(seed in any::<u64>(), operations in 1usize..=60) {
        let mut rng = Rng::new(seed);
        let mut chain = Chain::root();
        let mut equity = 0i128;

        for name in NAMES {
            chain.open(name).unwrap();
        }

        for _ in 0..operations {
            let name = NAMES[rng.range(0, NAMES.len())];
            let amount = rng.range(1, 500) as i128;
            if rng.range(0, 2) == 0 {
                chain.issue(name, amount as u64).unwrap();
                equity -= amount;
            } else if chain.ledger.balances().child_balance(&child(name)).get() as i128 >= amount {
                chain.burn(name, amount as u64).unwrap();
                equity += amount;
            }
            assert_eq!(chain.ledger.balances().equity(), equity);
        }
    }
}
