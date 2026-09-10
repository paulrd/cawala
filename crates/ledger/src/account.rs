//! Accounts, postings, and the per-node balance set.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::amount::{Amount, SignedAmount};
use crate::error::LedgerError;

/// A network node identifier (an opaque string at the ledger layer).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(String);

impl NodeId {
    /// Wrap an id string.
    pub fn new(id: impl Into<String>) -> Self {
        NodeId(id.into())
    }

    /// The raw id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for NodeId {
    fn from(value: String) -> Self {
        NodeId(value)
    }
}

impl From<&str> for NodeId {
    fn from(value: &str) -> Self {
        NodeId(value.to_string())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which account of the local node a posting touches.
///
/// - `Parent`: the asset account this node holds with its parent (absent at
///   the root).
/// - `Child`: the liability account this node holds for one child.
/// - `Equity`: the node's own equity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AccountRef {
    /// The account with the parent (asset).
    Parent,
    /// A liability account for the named child.
    Child(NodeId),
    /// The node's equity.
    Equity,
}

/// One signed balance movement against an [`AccountRef`].
///
/// A set of postings may mention the same account more than once; [`Balances`]
/// aggregates deltas per account before applying them (see [`Balances::apply`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posting {
    /// The account the delta applies to.
    pub account: AccountRef,
    /// The (signed) change to the account balance.
    pub delta: SignedAmount,
}

/// The balances of a single node.
///
/// `parent` is `None` for the root. `children` holds one liability balance per
/// child; a missing entry reads as zero. `equity` is signed: issuing value
/// drives it negative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balances {
    parent: Option<Amount>,
    children: BTreeMap<NodeId, Amount>,
    equity: i128,
}

impl Balances {
    /// Empty balances for the root node (no parent account).
    pub fn new_root() -> Self {
        Balances {
            parent: None,
            children: BTreeMap::new(),
            equity: 0,
        }
    }

    /// Empty balances for a non-root node (zeroed parent account).
    pub fn new_non_root() -> Self {
        Balances {
            parent: Some(Amount::ZERO),
            children: BTreeMap::new(),
            equity: 0,
        }
    }

    /// The asset balance with the parent. `None` at the root.
    pub fn parent_balance(&self) -> Option<Amount> {
        self.parent
    }

    /// The liability balance held for `child` (zero when absent).
    pub fn child_balance(&self, child: &NodeId) -> Amount {
        self.children.get(child).copied().unwrap_or(Amount::ZERO)
    }

    /// The node's equity.
    pub fn equity(&self) -> i128 {
        self.equity
    }

    /// Materialize a zeroed liability account for `child`.
    ///
    /// Returns [`LedgerError::AccountExists`] if the child account already
    /// exists, so replaying an `OpenAccount` entry is rejected at append time.
    /// This makes [`Balances::accounts`] (and therefore `state_root`)
    /// independent of posting history: an account opened with no postings is
    /// present as a zero balance.
    pub fn open_account(&mut self, child: &NodeId) -> Result<(), LedgerError> {
        match self.children.entry(child.clone()) {
            Entry::Occupied(_) => Err(LedgerError::AccountExists),
            Entry::Vacant(slot) => {
                slot.insert(Amount::ZERO);
                Ok(())
            }
        }
    }

    /// The current balance of an arbitrary account.
    pub fn balance(&self, account: &AccountRef) -> i128 {
        match account {
            AccountRef::Parent => self.parent.map(|a| a.get() as i128).unwrap_or(0),
            AccountRef::Child(id) => self.child_balance(id).get() as i128,
            AccountRef::Equity => self.equity,
        }
    }

    /// Enumerate every account and its balance, deterministically:
    ///
    /// 1. `Parent` (omitted at the root),
    /// 2. every `Child` account in `NodeId` (BTreeMap) order, including
    ///    accounts whose current balance is zero,
    /// 3. `Equity`.
    pub fn accounts(&self) -> impl Iterator<Item = (AccountRef, i128)> + '_ {
        let parent = self
            .parent
            .map(|amount| (AccountRef::Parent, amount.get() as i128));
        let children = self
            .children
            .iter()
            .map(|(id, amount)| (AccountRef::Child(id.clone()), amount.get() as i128));
        let equity = std::iter::once((AccountRef::Equity, self.equity));
        parent.into_iter().chain(children).chain(equity)
    }

    /// Apply a set of postings atomically and order-independently.
    ///
    /// Deltas are first aggregated per [`AccountRef`] in `i128` (checked), so
    /// the same account appearing several times in one entry is netted before
    /// any balance is touched. Then:
    ///
    /// 1. `Σdelta(Parent) − Σdelta(Child) − Σdelta(Equity) == 0`,
    /// 2. every `Parent`/`Child` balance is `>= 0` after applying, and
    /// 3. every `Child` posting names an account already materialized by
    ///    [`Balances::open_account`] (otherwise [`LedgerError::AccountNotOpened`]).
    ///
    /// Because only the final value is checked, a sequence such as
    /// `[Child(a):−10, Child(b):+10, Child(a):+5, Child(b):−5]` with `a == 5`
    /// succeeds (nets `a == 0`, `b == 5`) instead of transiently overdrawing
    /// `a`. On any error `self` is left unchanged.
    pub fn apply(&mut self, postings: &[Posting]) -> Result<(), LedgerError> {
        let deltas = aggregate_deltas(postings)?;
        let (delta_parent, delta_child, delta_equity) = class_sums(&deltas)?;
        postings_conserve(delta_parent, delta_child, delta_equity)?;

        let mut next = self.clone();
        for (account, delta) in &deltas {
            match account {
                AccountRef::Parent => match next.parent {
                    Some(current) => next.parent = Some(apply_delta(current, *delta)?),
                    None => {
                        if *delta != 0 {
                            return Err(LedgerError::NoParentAccount);
                        }
                    }
                },
                AccountRef::Child(id) => {
                    // Only `open_account` materializes a child; a posting to an
                    // unopened account is rejected so `state_root` is a pure
                    // function of opened-and-applied history.
                    let current =
                        *next
                            .children
                            .get(id)
                            .ok_or_else(|| LedgerError::AccountNotOpened {
                                account: AccountRef::Child(id.clone()),
                            })?;
                    let updated = apply_delta(current, *delta)?;
                    next.children.insert(id.clone(), updated);
                }
                AccountRef::Equity => {
                    next.equity = next
                        .equity
                        .checked_add(*delta)
                        .ok_or(LedgerError::Overflow)?;
                }
            }
        }

        *self = next;
        Ok(())
    }
}

/// Apply an aggregated signed delta to an unsigned balance, rejecting a
/// negative result (overdraw) and overflow.
fn apply_delta(current: Amount, delta: i128) -> Result<Amount, LedgerError> {
    let value = current.get() as i128 + delta;
    if value < 0 {
        return Err(LedgerError::InsufficientBalance);
    }
    if value > u64::MAX as i128 {
        return Err(LedgerError::Overflow);
    }
    Ok(Amount::new(value as u64))
}

/// Aggregate posting deltas per account, in `i128`, with checked arithmetic.
///
/// Deterministic: the returned map is a `BTreeMap`, ordered by [`AccountRef`]
/// (`Parent` < `Child(id)` < `Equity`).
pub(crate) fn aggregate_deltas(
    postings: &[Posting],
) -> Result<BTreeMap<AccountRef, i128>, LedgerError> {
    let mut deltas: BTreeMap<AccountRef, i128> = BTreeMap::new();
    for posting in postings {
        let slot = deltas.entry(posting.account.clone()).or_insert(0);
        *slot = slot
            .checked_add(posting.delta.get() as i128)
            .ok_or(LedgerError::Overflow)?;
    }
    Ok(deltas)
}

/// Sum aggregated deltas by account class: `(parent, child, equity)`.
pub(crate) fn class_sums(
    deltas: &BTreeMap<AccountRef, i128>,
) -> Result<(i128, i128, i128), LedgerError> {
    let mut parent: i128 = 0;
    let mut child: i128 = 0;
    let mut equity: i128 = 0;
    for (account, delta) in deltas {
        match account {
            AccountRef::Parent => {
                parent = parent.checked_add(*delta).ok_or(LedgerError::Overflow)?;
            }
            AccountRef::Child(_) => {
                child = child.checked_add(*delta).ok_or(LedgerError::Overflow)?;
            }
            AccountRef::Equity => {
                equity = equity.checked_add(*delta).ok_or(LedgerError::Overflow)?;
            }
        }
    }
    Ok((parent, child, equity))
}

/// Check `parent − child − equity == 0` in `i128`.
pub(crate) fn postings_conserve(
    parent: i128,
    child: i128,
    equity: i128,
) -> Result<(), LedgerError> {
    let diff = parent
        .checked_sub(child)
        .and_then(|value| value.checked_sub(equity))
        .ok_or(LedgerError::Overflow)?;
    if diff == 0 {
        Ok(())
    } else {
        Err(LedgerError::ConservationViolation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn constructors() {
        let root = Balances::new_root();
        assert_eq!(root.parent_balance(), None);
        assert_eq!(root.equity(), 0);
        assert_eq!(root.balance(&AccountRef::Parent), 0);

        let non_root = Balances::new_non_root();
        assert_eq!(non_root.parent_balance(), Some(Amount::ZERO));
        assert_eq!(non_root.balance(&AccountRef::Parent), 0);
    }

    #[test]
    fn open_account_materializes_zero_and_rejects_duplicates() {
        let mut b = Balances::new_root();
        assert_eq!(b.child_balance(&child("a")), Amount::ZERO);

        b.open_account(&child("a")).unwrap();
        assert_eq!(b.child_balance(&child("a")), Amount::ZERO);
        // The zero account is enumerable, so state commitments see it.
        assert!(
            b.accounts()
                .any(|(account, balance)| account == AccountRef::Child(child("a")) && balance == 0)
        );

        assert_eq!(b.open_account(&child("a")), Err(LedgerError::AccountExists));
    }

    #[test]
    fn sibling_transfer() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();
        b.apply(&[child_posting("a", 100), posting(AccountRef::Equity, -100)])
            .unwrap();
        b.apply(&[child_posting("a", -30), child_posting("b", 30)])
            .unwrap();
        assert_eq!(b.child_balance(&child("a")), Amount::new(70));
        assert_eq!(b.child_balance(&child("b")), Amount::new(30));
        assert_eq!(b.equity(), -100);
        assert_eq!(
            b.balance(&AccountRef::Child(child("a"))),
            70,
            "child balance reads through"
        );
    }

    #[test]
    fn ascend_shape() {
        let mut b = Balances::new_non_root();
        b.open_account(&child("a")).unwrap();
        b.apply(&[posting(AccountRef::Parent, 100), child_posting("a", 100)])
            .unwrap();
        // Ascend: Parent−/Child−
        b.apply(&[posting(AccountRef::Parent, -40), child_posting("a", -40)])
            .unwrap();
        assert_eq!(b.parent_balance(), Some(Amount::new(60)));
        assert_eq!(b.child_balance(&child("a")), Amount::new(60));
        assert_eq!(b.equity(), 0);
    }

    #[test]
    fn descend_shape() {
        let mut b = Balances::new_non_root();
        b.open_account(&child("a")).unwrap();
        b.apply(&[posting(AccountRef::Parent, 50), child_posting("a", 50)])
            .unwrap();
        assert_eq!(b.parent_balance(), Some(Amount::new(50)));
        assert_eq!(b.child_balance(&child("a")), Amount::new(50));
    }

    #[test]
    fn lca_reallocation_shape() {
        let mut b = Balances::new_non_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();
        // fund via a valid issue first
        b.apply(&[child_posting("a", 20), posting(AccountRef::Equity, -20)])
            .unwrap();
        // LCA reallocation: Child−/Child+
        b.apply(&[child_posting("a", -15), child_posting("b", 15)])
            .unwrap();
        assert_eq!(b.child_balance(&child("a")), Amount::new(5));
        assert_eq!(b.child_balance(&child("b")), Amount::new(15));
        assert_eq!(b.equity(), -20);
    }

    #[test]
    fn issue_shape() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.apply(&[child_posting("a", 100), posting(AccountRef::Equity, -100)])
            .unwrap();
        assert_eq!(b.child_balance(&child("a")), Amount::new(100));
        assert_eq!(b.equity(), -100);
    }

    #[test]
    fn burn_shape() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.apply(&[child_posting("a", 100), posting(AccountRef::Equity, -100)])
            .unwrap();
        b.apply(&[child_posting("a", -40), posting(AccountRef::Equity, 40)])
            .unwrap();
        assert_eq!(b.child_balance(&child("a")), Amount::new(60));
        assert_eq!(b.equity(), -60);
    }

    #[test]
    fn order_independent_apply_counterexample() {
        // The naive sequential application would transiently take `a` to −5;
        // aggregation applies the net −5 to a=5 and must accept.
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();
        b.apply(&[child_posting("a", 5), posting(AccountRef::Equity, -5)])
            .unwrap();
        b.apply(&[
            child_posting("a", -10),
            child_posting("b", 10),
            child_posting("a", 5),
            child_posting("b", -5),
        ])
        .unwrap();
        assert_eq!(b.child_balance(&child("a")), Amount::ZERO);
        assert_eq!(b.child_balance(&child("b")), Amount::new(5));
    }

    #[test]
    fn accounts_enumerates_deterministically() {
        let mut b = Balances::new_non_root();
        b.open_account(&child("b")).unwrap();
        b.apply(&[child_posting("b", 5), posting(AccountRef::Equity, -5)])
            .unwrap();
        b.open_account(&child("a")).unwrap();

        let accounts: Vec<(AccountRef, i128)> = b.accounts().collect();
        assert_eq!(
            accounts,
            vec![
                (AccountRef::Parent, 0),
                (AccountRef::Child(child("a")), 0),
                (AccountRef::Child(child("b")), 5),
                (AccountRef::Equity, -5),
            ]
        );

        // The root has no parent account, so it is omitted.
        let root = Balances::new_root();
        let accounts: Vec<(AccountRef, i128)> = root.accounts().collect();
        assert_eq!(accounts, vec![(AccountRef::Equity, 0)]);
    }

    #[test]
    fn overdraw_is_rejected_and_state_unchanged() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();
        b.apply(&[child_posting("a", 10), posting(AccountRef::Equity, -10)])
            .unwrap();
        let before = b.clone();
        assert_eq!(
            b.apply(&[child_posting("a", -11), child_posting("b", 11)]),
            Err(LedgerError::InsufficientBalance)
        );
        assert_eq!(b, before, "failed apply must not mutate balances");
    }

    #[test]
    fn parent_overdraw_is_rejected() {
        let mut b = Balances::new_non_root();
        b.open_account(&child("a")).unwrap();
        assert_eq!(
            b.apply(&[posting(AccountRef::Parent, -1), child_posting("a", -1)]),
            Err(LedgerError::InsufficientBalance)
        );
    }

    #[test]
    fn non_conserving_postings_are_rejected() {
        let mut b = Balances::new_root();
        assert_eq!(
            b.apply(&[child_posting("a", 10)]),
            Err(LedgerError::ConservationViolation)
        );
        assert_eq!(
            b.apply(&[child_posting("a", 10), posting(AccountRef::Equity, -9)]),
            Err(LedgerError::ConservationViolation)
        );
        assert_eq!(b, Balances::new_root());
    }

    #[test]
    fn unopened_child_posting_is_rejected() {
        // Zero delta to an unopened account is still a posting.
        let mut b = Balances::new_root();
        assert_eq!(
            b.apply(&[child_posting("a", 0)]),
            Err(LedgerError::AccountNotOpened {
                account: AccountRef::Child(child("a"))
            })
        );

        // A conserving set naming an unopened account also fails.
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        assert_eq!(
            b.apply(&[child_posting("a", 5), child_posting("b", -5)]),
            Err(LedgerError::AccountNotOpened {
                account: AccountRef::Child(child("b"))
            })
        );
        assert_eq!(b.child_balance(&child("a")), Amount::ZERO);
    }

    #[test]
    fn parent_posting_on_root_is_rejected() {
        let mut b = Balances::new_root();
        assert_eq!(
            b.apply(&[posting(AccountRef::Parent, 5), child_posting("a", 5)]),
            Err(LedgerError::NoParentAccount)
        );
    }

    #[test]
    fn zero_parent_posting_on_root_is_a_noop() {
        let mut b = Balances::new_root();
        b.apply(&[posting(AccountRef::Parent, 0)]).unwrap();
        assert_eq!(b.parent_balance(), None);
    }

    #[test]
    fn serde_round_trip() {
        let mut b = Balances::new_non_root();
        b.open_account(&child("a")).unwrap();
        b.apply(&[child_posting("a", 5), posting(AccountRef::Equity, -5)])
            .unwrap();
        let bytes = postcard::to_allocvec(&b).unwrap();
        let back: Balances = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(b, back);
    }
}
