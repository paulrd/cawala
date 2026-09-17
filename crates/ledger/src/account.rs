//! Accounts, postings, and the per-node balance set.
//!
//! # No-equity model
//!
//! The ledger stores only two account classes: the node's universal `Parent`
//! asset account and one `Child` liability account per child. There is **no**
//! `Equity` account and equity is **never posted**; a node's equity is derived
//! as `E = Parent − ΣChild` ([`Balances::equity`]). External real-world backing
//! (goodwill, land, materials, ...) is out of scope.
//!
//! The per-entry rule is a pure function of the entry body, so it is
//! deterministic under dynamic rootness:
//!
//! - `Transfer` / `OpenAccount`: **balanced**, `ΔParent == ΔΣChild`;
//! - `Issue` / `Burn`: **boundary** operations on a single child liability
//!   account, exempt from the balance equation. `Issue` is `{Child:+amount}` and
//!   `Burn` is `{Child:−amount}`.
//! - `EdgeClose`: a **boundary parent** operation writing off the universal
//!   `Parent` asset, exempt from the balance equation: `{Parent:−amount}`.
//!
//! Only `Parent`/`Child` non-negativity is enforced everywhere, so locally
//! issued value is spendable same-leaf but not cross-subtree unless the parent
//! edge is actually prefunded/mirrored.

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
/// - `Parent`: the asset account this node holds with its parent. Structurally
///   universal — every ledger has one; on a detached/top-level node it holds a
///   stranded claim (normally zero).
/// - `Child`: the liability account this node holds for one child.
///
/// There is no `Equity` variant: equity is derived (`Parent − ΣChild`) and is
/// never posted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AccountRef {
    /// The account with the parent (asset).
    Parent,
    /// A liability account for the named child.
    Child(NodeId),
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
/// The `Parent` account is **structurally universal**: `parent` is always
/// `Some`, starting at zero. Rootness is a control-plane fact (whether the node
/// currently has a parent link), never a ledger structural property, so a
/// top-level ledger simply carries a (normally zero) stranded `Parent` claim.
/// `children` holds one liability balance per child; a missing entry reads as
/// zero. Equity is **derived**, not stored ([`Balances::equity`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balances {
    parent: Option<Amount>,
    children: BTreeMap<NodeId, Amount>,
}

impl Balances {
    /// Empty balances for the root node (no parent link).
    ///
    /// The `Parent` account is universal and starts at zero, so this is
    /// identical to [`Self::new_non_root`]; the name is kept for call-site
    /// clarity. Rootness is not a ledger structural property.
    pub fn new_root() -> Self {
        Self::new_non_root()
    }

    /// Empty balances for a non-root node (zeroed parent account).
    pub fn new_non_root() -> Self {
        Balances {
            parent: Some(Amount::ZERO),
            children: BTreeMap::new(),
        }
    }

    /// The asset balance with the parent. Always `Some`: the `Parent` account is
    /// universal. On a top-level (detached) ledger it is a stranded claim,
    /// normally zero.
    pub fn parent_balance(&self) -> Option<Amount> {
        self.parent
    }

    /// The liability balance held for `child` (zero when absent).
    pub fn child_balance(&self, child: &NodeId) -> Amount {
        self.children.get(child).copied().unwrap_or(Amount::ZERO)
    }

    /// The node's **derived** equity, `Parent − ΣChild`.
    ///
    /// Equity is never posted: an `Issue` lowers it, a `Burn` raises it, and
    /// `Transfer`s leave it unchanged. `E < 0` is normal and is **not** an
    /// overdraw — it means the node holds a larger liability to its children
    /// than its parent asset, backed by external real-world value.
    pub fn equity(&self) -> i128 {
        let parent = self.parent.map(|amount| amount.get() as i128).unwrap_or(0);
        let child: i128 = self
            .children
            .values()
            .fold(0i128, |acc, amount| acc + amount.get() as i128);
        parent - child
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
        }
    }

    /// Enumerate every account and its balance, deterministically:
    ///
    /// 1. `Parent` (universal; always first), then
    /// 2. every `Child` account in `NodeId` (BTreeMap) order, including
    ///    accounts whose current balance is zero.
    ///
    /// Equity is derived and is not an account, so it is not enumerated.
    pub fn accounts(&self) -> impl Iterator<Item = (AccountRef, i128)> + '_ {
        let parent = self
            .parent
            .map(|amount| (AccountRef::Parent, amount.get() as i128));
        let children = self
            .children
            .iter()
            .map(|(id, amount)| (AccountRef::Child(id.clone()), amount.get() as i128));
        parent.into_iter().chain(children)
    }

    /// Apply a **balanced** posting set atomically and order-independently.
    ///
    /// Used for `Transfer`/`OpenAccount`: the set must satisfy
    /// `ΔParent == ΔΣChild` (via the shared [`check_posting_rule`]). Deltas are
    /// first aggregated per [`AccountRef`] in `i128` (checked), so the same
    /// account appearing several times in one entry is netted before any balance
    /// is touched. Then:
    ///
    /// 1. the balanced rule holds,
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
        check_posting_rule(&deltas, PostingRule::Balanced)?;
        self.apply_deltas(&deltas)
    }

    /// Apply a **boundary** posting set atomically (`Issue`/`Burn`).
    ///
    /// The set must be exactly one `Child` leg with a nonzero delta (via the
    /// shared [`check_posting_rule`]); it is exempt from the balance equation.
    /// Non-negativity is still enforced, so a `Burn` cannot overdraw a child.
    /// On any error `self` is left unchanged.
    pub fn apply_boundary(&mut self, postings: &[Posting]) -> Result<(), LedgerError> {
        let deltas = aggregate_deltas(postings)?;
        check_posting_rule(&deltas, PostingRule::Boundary)?;
        self.apply_deltas(&deltas)
    }

    /// Apply a **boundary parent** posting set atomically (`EdgeClose`).
    ///
    /// The set must be exactly one `Parent` leg with a nonzero delta (via the
    /// shared [`check_posting_rule`]); it is exempt from the balance equation,
    /// so it deliberately lowers the derived equity. Non-negativity is still
    /// enforced, so a write-off cannot overdraw the `Parent` asset. On any error
    /// `self` is left unchanged.
    pub fn apply_parent_boundary(&mut self, postings: &[Posting]) -> Result<(), LedgerError> {
        let deltas = aggregate_deltas(postings)?;
        check_posting_rule(&deltas, PostingRule::BoundaryParent)?;
        self.apply_deltas(&deltas)
    }

    /// Apply aggregated deltas to a clone, committing only on full success.
    fn apply_deltas(&mut self, deltas: &BTreeMap<AccountRef, i128>) -> Result<(), LedgerError> {
        let mut next = self.clone();
        for (account, delta) in deltas {
            match account {
                AccountRef::Parent => {
                    // The `Parent` account is universal (always `Some`), so a
                    // posting applies regardless of current attachment; on a
                    // detached ledger it accumulates a stranded claim.
                    let current = next
                        .parent
                        .expect("the Parent account is universal on every ledger");
                    next.parent = Some(apply_delta(current, *delta)?);
                }
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
            }
        }

        *self = next;
        Ok(())
    }
}

/// The per-entry posting rule, a pure function of the entry body.
///
/// `Transfer`/`OpenAccount` are **balanced** (`ΔParent == ΔΣChild`);
/// `Issue`/`Burn` are **boundary** operations on a single child account and are
/// exempt from the balance equation; `EdgeClose` is a **boundary parent**
/// operation on the single universal `Parent` account and is likewise exempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PostingRule {
    /// `ΔParent == ΔΣChild`.
    Balanced,
    /// Exactly one `Child` leg (boundary `Issue`/`Burn`).
    Boundary,
    /// Exactly one `Parent` leg (boundary `EdgeClose`).
    BoundaryParent,
}

/// Enforce the shared per-entry posting rule against aggregated `deltas`.
///
/// This is the single source of truth for the equation:
/// [`crate::entry::Entry::check_conservation`], [`Balances::apply`],
/// [`Balances::apply_boundary`], and [`Balances::apply_parent_boundary`] all
/// route through it so they cannot drift.
pub(crate) fn check_posting_rule(
    deltas: &BTreeMap<AccountRef, i128>,
    rule: PostingRule,
) -> Result<(), LedgerError> {
    match rule {
        PostingRule::Balanced => {
            let (parent, child) = class_sums(deltas)?;
            postings_conserve(parent, child)
        }
        PostingRule::Boundary => {
            if deltas.len() != 1 {
                return Err(LedgerError::InvalidEntryShape);
            }
            match deltas.iter().next() {
                Some((AccountRef::Child(_), delta)) if *delta != 0 => Ok(()),
                _ => Err(LedgerError::InvalidEntryShape),
            }
        }
        PostingRule::BoundaryParent => {
            if deltas.len() != 1 {
                return Err(LedgerError::InvalidEntryShape);
            }
            match deltas.iter().next() {
                Some((AccountRef::Parent, delta)) if *delta != 0 => Ok(()),
                _ => Err(LedgerError::InvalidEntryShape),
            }
        }
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
/// (`Parent` < `Child(id)`).
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

/// Sum aggregated deltas by account class: `(parent, child)`.
pub(crate) fn class_sums(
    deltas: &BTreeMap<AccountRef, i128>,
) -> Result<(i128, i128), LedgerError> {
    let mut parent: i128 = 0;
    let mut child: i128 = 0;
    for (account, delta) in deltas {
        match account {
            AccountRef::Parent => {
                parent = parent.checked_add(*delta).ok_or(LedgerError::Overflow)?;
            }
            AccountRef::Child(_) => {
                child = child.checked_add(*delta).ok_or(LedgerError::Overflow)?;
            }
        }
    }
    Ok((parent, child))
}

/// Check the balanced rule `parent − child == 0` in `i128`.
pub(crate) fn postings_conserve(parent: i128, child: i128) -> Result<(), LedgerError> {
    match parent.checked_sub(child) {
        Some(0) => Ok(()),
        Some(_) => Err(LedgerError::ConservationViolation),
        None => Err(LedgerError::Overflow),
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
        // The Parent account is universal: both constructors yield `Some(0)`.
        let root = Balances::new_root();
        assert_eq!(root.parent_balance(), Some(Amount::ZERO));
        assert_eq!(root.equity(), 0);
        assert_eq!(root.balance(&AccountRef::Parent), 0);

        let non_root = Balances::new_non_root();
        assert_eq!(non_root.parent_balance(), Some(Amount::ZERO));
        assert_eq!(non_root.balance(&AccountRef::Parent), 0);

        assert_eq!(root, non_root, "rootness is not a structural property");
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
        // Fund a via a boundary Issue (Child only).
        b.apply_boundary(&[child_posting("a", 100)]).unwrap();
        assert_eq!(b.equity(), -100);
        // Transfer a -> b is balanced (ΔParent == ΔΣChild == 0).
        b.apply(&[child_posting("a", -30), child_posting("b", 30)])
            .unwrap();
        assert_eq!(b.child_balance(&child("a")), Amount::new(70));
        assert_eq!(b.child_balance(&child("b")), Amount::new(30));
        assert_eq!(b.equity(), -100, "transfers leave equity unchanged");
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
        // Fund a via a boundary Issue.
        b.apply_boundary(&[child_posting("a", 20)]).unwrap();
        // LCA reallocation: Child−/Child+.
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
        b.apply_boundary(&[child_posting("a", 100)]).unwrap();
        assert_eq!(b.child_balance(&child("a")), Amount::new(100));
        assert_eq!(b.equity(), -100);
    }

    #[test]
    fn burn_shape() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.apply_boundary(&[child_posting("a", 100)]).unwrap();
        b.apply_boundary(&[child_posting("a", -40)]).unwrap();
        assert_eq!(b.child_balance(&child("a")), Amount::new(60));
        assert_eq!(b.equity(), -60);
    }

    #[test]
    fn derived_equity_tracks_issue_and_burn() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();

        assert_eq!(b.equity(), 0);
        b.apply_boundary(&[child_posting("a", 100)]).unwrap();
        assert_eq!(b.equity(), -100); // Issue lowers equity.
        b.apply_boundary(&[child_posting("b", 25)]).unwrap();
        assert_eq!(b.equity(), -125);
        // A balanced transfer must not move equity.
        b.apply(&[child_posting("a", -40), child_posting("b", 40)])
            .unwrap();
        assert_eq!(b.equity(), -125);
        // Descend/Ascend (Parent / Child together) must not move equity.
        b.apply(&[posting(AccountRef::Parent, 30), child_posting("a", 30)])
            .unwrap();
        assert_eq!(b.equity(), -125);
        b.apply(&[posting(AccountRef::Parent, -10), child_posting("a", -10)])
            .unwrap();
        assert_eq!(b.equity(), -125);
        b.apply_boundary(&[child_posting("a", -60)]).unwrap();
        assert_eq!(b.equity(), -65); // Burn raises equity.
    }

    #[test]
    fn boundary_ops_are_shape_strict() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();

        // Zero amount is rejected.
        assert_eq!(
            b.apply_boundary(&[child_posting("a", 0)]),
            Err(LedgerError::InvalidEntryShape)
        );
        // A `Parent` leg is rejected.
        assert_eq!(
            b.apply_boundary(&[child_posting("a", 5), posting(AccountRef::Parent, 5)]),
            Err(LedgerError::InvalidEntryShape)
        );
        // Extra child legs are rejected.
        assert_eq!(
            b.apply_boundary(&[child_posting("a", 5), child_posting("b", 5)]),
            Err(LedgerError::InvalidEntryShape)
        );
        assert_eq!(b, {
            let mut empty = Balances::new_root();
            empty.open_account(&child("a")).unwrap();
            empty.open_account(&child("b")).unwrap();
            empty
        });
    }

    #[test]
    fn parent_boundary_accepts_exactly_one_negative_parent_leg() {
        let mut b = Balances::new_non_root();
        b.open_account(&child("a")).unwrap();
        // Fund the Parent asset via a balanced Descend.
        b.apply(&[posting(AccountRef::Parent, 10), child_posting("a", 10)])
            .unwrap();

        // Exactly `[{Parent: −m}]` is accepted and lowers equity.
        b.apply_parent_boundary(&[posting(AccountRef::Parent, -4)])
            .unwrap();
        assert_eq!(b.parent_balance(), Some(Amount::new(6)));
        assert_eq!(b.equity(), 6 - 10);
    }

    #[test]
    fn parent_boundary_is_shape_strict() {
        let mut b = Balances::new_non_root();
        b.open_account(&child("a")).unwrap();
        b.apply(&[posting(AccountRef::Parent, 10), child_posting("a", 10)])
            .unwrap();
        let before = b.clone();

        // A child leg is not allowed on a parent boundary op.
        assert_eq!(
            b.apply_parent_boundary(&[posting(AccountRef::Parent, -5), child_posting("a", 5)]),
            Err(LedgerError::InvalidEntryShape)
        );
        // A multi-leg (here child-only) set is rejected: exactly one leg.
        assert_eq!(
            b.apply_parent_boundary(&[child_posting("a", -1), child_posting("b", -1)]),
            Err(LedgerError::InvalidEntryShape)
        );
        // A zero delta is rejected.
        assert_eq!(
            b.apply_parent_boundary(&[posting(AccountRef::Parent, 0)]),
            Err(LedgerError::InvalidEntryShape)
        );
        assert_eq!(b, before, "failed parent boundary must not mutate balances");
    }

    #[test]
    fn balanced_ops_require_delta_parent_eq_delta_child() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();
        // Child-only (an Issue) is not a balanced op.
        assert_eq!(
            b.apply(&[child_posting("a", 10)]),
            Err(LedgerError::ConservationViolation)
        );
        // Parent + children must net to zero.
        assert_eq!(
            b.apply(&[child_posting("a", 10), child_posting("b", -9)]),
            Err(LedgerError::ConservationViolation)
        );
        assert_eq!(
            b.apply(&[posting(AccountRef::Parent, 10), child_posting("a", 9)]),
            Err(LedgerError::ConservationViolation)
        );
        assert_eq!(b, {
            let mut empty = Balances::new_root();
            empty.open_account(&child("a")).unwrap();
            empty.open_account(&child("b")).unwrap();
            empty
        });
    }

    #[test]
    fn order_independent_apply_counterexample() {
        // The naive sequential application would transiently take `a` to −5;
        // aggregation applies the net −5 to a=5 and must accept.
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();
        b.apply_boundary(&[child_posting("a", 5)]).unwrap();
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
        b.apply_boundary(&[child_posting("b", 5)]).unwrap();
        b.open_account(&child("a")).unwrap();

        let accounts: Vec<(AccountRef, i128)> = b.accounts().collect();
        assert_eq!(
            accounts,
            vec![
                (AccountRef::Parent, 0),
                (AccountRef::Child(child("a")), 0),
                (AccountRef::Child(child("b")), 5),
            ]
        );

        // The Parent account is universal, so a detached ledger enumerates it
        // first as a zero claim, and there is no Equity account.
        let root = Balances::new_root();
        let accounts: Vec<(AccountRef, i128)> = root.accounts().collect();
        assert_eq!(accounts, vec![(AccountRef::Parent, 0)]);
    }

    #[test]
    fn overdraw_is_rejected_and_state_unchanged() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.open_account(&child("b")).unwrap();
        b.apply_boundary(&[child_posting("a", 10)]).unwrap();
        let before = b.clone();
        assert_eq!(
            b.apply(&[child_posting("a", -11), child_posting("b", 11)]),
            Err(LedgerError::InsufficientBalance)
        );
        assert_eq!(b, before, "failed apply must not mutate balances");
    }

    #[test]
    fn burn_overdraw_is_rejected() {
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.apply_boundary(&[child_posting("a", 5)]).unwrap();
        let before = b.clone();
        assert_eq!(
            b.apply_boundary(&[child_posting("a", -6)]),
            Err(LedgerError::InsufficientBalance)
        );
        assert_eq!(b, before, "failed boundary apply must not mutate balances");
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
    fn unopened_child_posting_is_rejected() {
        // Zero delta to an unopened account is still a posting.
        let mut b = Balances::new_root();
        assert_eq!(
            b.apply(&[child_posting("a", 0)]),
            Err(LedgerError::AccountNotOpened {
                account: AccountRef::Child(child("a"))
            })
        );

        // A balanced set naming an unopened account also fails.
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
    fn parent_posting_on_detached_ledger_applies() {
        // A detached (top-level) ledger still has the universal Parent account,
        // so a balanced parent posting accumulates a stranded claim.
        let mut b = Balances::new_root();
        b.open_account(&child("a")).unwrap();
        b.apply(&[posting(AccountRef::Parent, 5), child_posting("a", 5)])
            .unwrap();
        assert_eq!(b.parent_balance(), Some(Amount::new(5)));
        assert_eq!(b.child_balance(&child("a")), Amount::new(5));
        assert_eq!(b.equity(), 0);
    }

    #[test]
    fn zero_parent_posting_on_detached_ledger_is_a_noop() {
        let mut b = Balances::new_root();
        b.apply(&[posting(AccountRef::Parent, 0)]).unwrap();
        assert_eq!(b.parent_balance(), Some(Amount::ZERO));
        assert_eq!(b, Balances::new_root());
    }

    #[test]
    fn serde_round_trip() {
        let mut b = Balances::new_non_root();
        b.open_account(&child("a")).unwrap();
        b.apply_boundary(&[child_posting("a", 5)]).unwrap();
        let bytes = postcard::to_allocvec(&b).unwrap();
        let back: Balances = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(b, back);
    }
}
