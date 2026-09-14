//! Prefunded-only LCA settlement between subtrees.
//!
//! A cross-subtree payment settles at the least common ancestor (LCA) of the
//! payer's and payee's leaf addresses. Value is *ascended* from the payer's
//! leaf up to the LCA, reallocated at the LCA, then *descended* down to the
//! payee's leaf. Every hop is signed by the hop node's own ledger and carries
//! the payer's [`AuthRef`].
//!
//! v1 scope: endpoints must be [`ChildKind::User`] accounts held by leaf nodes.
//! [`plan_transfer`] assembles the canonical hop *shape* and fully dry-runs it,
//! but route/recipient binding of non-`Direct` hops is only proven by `netting`
//! (Phase D) via full route reconstruction; a cooperative set of nodes is
//! assumed here.

use std::collections::BTreeMap;

use cawala_topology::{ChildKind, OctAddr, Topology};

use crate::account::{AccountRef, Balances, NodeId, Posting};
use crate::amount::{Amount, SignedAmount};
use crate::auth::{PaymentOrder, verify_transfer};
use crate::entry::{AuthRef, Entry, EntryBody, HopRole, SignedEntry};
use crate::error::LedgerError;
use crate::hash::Hash;
use crate::keys::LedgerSecretKey;
use crate::log::{Ledger, MemLog};
use crate::registry::PeerRegistry;

/// A set of node ledgers keyed by topology [`NodeId`].
#[derive(Debug, Clone, Default)]
pub struct LedgerSet {
    ledgers: BTreeMap<NodeId, Ledger<MemLog>>,
}

impl LedgerSet {
    /// Create an empty ledger set.
    pub fn new() -> Self {
        LedgerSet {
            ledgers: BTreeMap::new(),
        }
    }

    /// Insert a node's ledger. Returns [`LedgerError::DuplicatePeer`] if the
    /// node already has a ledger.
    pub fn insert(&mut self, node: NodeId, ledger: Ledger<MemLog>) -> Result<(), LedgerError> {
        match self.ledgers.entry(node) {
            std::collections::btree_map::Entry::Occupied(_) => Err(LedgerError::DuplicatePeer),
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(ledger);
                Ok(())
            }
        }
    }

    /// Look up a node's ledger.
    pub fn get(&self, node: &NodeId) -> Option<&Ledger<MemLog>> {
        self.ledgers.get(node)
    }

    /// Look up a node's ledger mutably.
    pub fn get_mut(&mut self, node: &NodeId) -> Option<&mut Ledger<MemLog>> {
        self.ledgers.get_mut(node)
    }

    /// Whether the set contains a ledger for `node`.
    pub fn contains(&self, node: &NodeId) -> bool {
        self.ledgers.contains_key(node)
    }

    /// Iterate over the node ids, in `NodeId` (BTreeMap) order.
    pub fn node_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.ledgers.keys()
    }
}

/// One planned hop: the signer and the (unsigned) entry it must sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedHop {
    /// The node that signs and applies this hop.
    pub signer: NodeId,
    /// The entry to sign (with the payer's `auth` embedded).
    pub entry: Entry,
}

/// A transfer plan: the order plus its ordered hops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPlan {
    /// The authorised order.
    pub order: PaymentOrder,
    /// The ordered hops from payer to payee.
    pub hops: Vec<PlannedHop>,
}

/// One hop the canonical route requires: the signing node, its role, and the
/// two accounts its entry must touch.
///
/// `first` and `second` are the hop's two posting accounts in canonical order
/// (the same order [`plan_transfer`] emits them). For `Ascend`/`Descend` that
/// is `Parent` then the child on the path; for `Lca`/`Direct` it is the debited
/// child then the credited child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedHop {
    /// The node that signs this hop.
    pub signer: NodeId,
    /// The hop's position in the cascade.
    pub role: HopRole,
    /// The first account named by the hop's canonical posting shape.
    pub first: AccountRef,
    /// The second account named by the hop's canonical posting shape.
    pub second: AccountRef,
}

fn ledger<'a>(ledgers: &'a LedgerSet, node: &NodeId) -> Result<&'a Ledger<MemLog>, LedgerError> {
    ledgers
        .get(node)
        .ok_or_else(|| LedgerError::MissingLedger { node: node.clone() })
}

fn checked_i64(value: u64) -> Result<i64, LedgerError> {
    i64::try_from(value).map_err(|_| LedgerError::Overflow)
}

fn posting(account: AccountRef, delta: i64) -> Posting {
    Posting {
        account,
        delta: SignedAmount::new(delta),
    }
}

/// Extract the child id from a `Child` account, rejecting other accounts.
fn expect_child(account: &AccountRef) -> Result<&NodeId, LedgerError> {
    match account {
        AccountRef::Child(id) => Ok(id),
        _ => Err(LedgerError::InvalidEntryShape),
    }
}

/// The canonical posting set for a hop of `role`, given its two accounts.
///
/// `Ascend` and `Descend` move value on both legs in the same direction;
/// `Lca`/`Direct` move value out of `first` and into `second`.
///
/// This is the single source of truth for a hop's posting shape. The node
/// per-hop executor builds its entries through it so they stay identical to the
/// hops [`plan_transfer`] plans, and [`classify_hop`] selects the role for a
/// signer on a route.
pub fn hop_postings(role: HopRole, first: &AccountRef, second: &AccountRef, m: i64) -> Vec<Posting> {
    match role {
        HopRole::Ascend => vec![posting(first.clone(), -m), posting(second.clone(), -m)],
        HopRole::Descend => vec![posting(first.clone(), m), posting(second.clone(), m)],
        HopRole::Lca | HopRole::Direct => {
            vec![posting(first.clone(), -m), posting(second.clone(), m)]
        }
    }
}

/// The role `this` plays on the canonical route from `src` to `dst`.
///
/// `src` and `dst` are endpoint (user) addresses and `this` is a candidate hop
/// node address. Returns `None` when `this` is off the canonical route.
///
/// The route matches [`expected_hops`]: a single `Direct` hop at the shared leaf
/// when both endpoints have the same parent, otherwise the strictly-ascending
/// path from the payer's leaf to the least common ancestor, the LCA
/// reallocation, and the strictly-descending path to the payee's leaf.
pub fn classify_hop(src: &OctAddr, dst: &OctAddr, this: &OctAddr) -> Option<HopRole> {
    // Same leaf: the only hop is the leaf itself, moving between the two users.
    if src.parent() == dst.parent() {
        return if src.parent().as_ref() == Some(this) {
            Some(HopRole::Direct)
        } else {
            None
        };
    }

    let lca = src.lca(dst);
    if *this == lca {
        return Some(HopRole::Lca);
    }
    // Ascending: the source itself, or a strict ancestor of it that also lies
    // strictly below the LCA.
    if *this == *src || (lca.is_ancestor_of(this) && this.is_ancestor_of(src)) {
        return Some(HopRole::Ascend);
    }
    // Descending: the destination itself, or a strict ancestor of it that also
    // lies strictly below the LCA.
    if *this == *dst || (lca.is_ancestor_of(this) && this.is_ancestor_of(dst)) {
        return Some(HopRole::Descend);
    }
    None
}

/// Whether `account` has been materialized in `balances`.
fn is_opened(balances: &Balances, account: &AccountRef) -> bool {
    balances
        .accounts()
        .any(|(candidate, _)| &candidate == account)
}

/// Validate that `user` is a `User` held by a leaf node, returning its parent.
fn user_leaf(topology: &Topology, user: &NodeId) -> Result<NodeId, LedgerError> {
    let record = topology
        .node(user.as_str())
        .ok_or(LedgerError::UnsupportedEndpoint)?;
    if record.kind != ChildKind::User {
        return Err(LedgerError::UnsupportedEndpoint);
    }
    let parent = topology
        .parent_of(user.as_str())
        .map_err(|_| LedgerError::UnsupportedEndpoint)?
        .ok_or(LedgerError::UnsupportedEndpoint)?;
    // v1 scope: users are held by leaf nodes (no node-kind children).
    let children = topology
        .children_of(parent)
        .map_err(|_| LedgerError::UnsupportedEndpoint)?;
    if children.iter().any(|child| child.kind == ChildKind::Node) {
        return Err(LedgerError::UnsupportedEndpoint);
    }
    Ok(NodeId::from(parent))
}

/// Find the node whose derived address equals `address`.
fn node_at_address(topology: &Topology, address: &OctAddr) -> Result<NodeId, LedgerError> {
    for id in topology.node_ids() {
        if let Ok(addr) = topology.address_of(id)
            && addr == *address
        {
            return Ok(NodeId::from(id.as_str()));
        }
    }
    Err(LedgerError::UnsupportedEndpoint)
}

/// Nodes from `leaf` upward, excluding `lca`. Empty when `leaf == lca`.
fn path_below(
    topology: &Topology,
    leaf: &NodeId,
    lca: &NodeId,
) -> Result<Vec<NodeId>, LedgerError> {
    let mut out = Vec::new();
    let mut cur = leaf.clone();
    let mut guard = 0usize;
    loop {
        if cur == *lca {
            return Ok(out);
        }
        out.push(cur.clone());
        match topology
            .parent_of(cur.as_str())
            .map_err(|_| LedgerError::UnsupportedEndpoint)?
        {
            Some(parent) => cur = NodeId::from(parent),
            None => return Err(LedgerError::UnsupportedEndpoint),
        }
        guard += 1;
        if guard > topology.node_count() {
            return Err(LedgerError::UnsupportedEndpoint);
        }
    }
}

/// Compute the canonical hop route for `order`.
///
/// This is the topology-only path the payer's and payee's leaf addresses
/// induce: a single `Direct` hop when both users share a leaf, otherwise the
/// ascending path to the LCA, the LCA reallocation, and the descending path to
/// the payee. Each returned [`ExpectedHop`] names its signer, role, and
/// canonical first/second accounts. Route computation is purely topological and
/// needs no ledgers. Endpoint validation matches [`plan_transfer`]: either
/// endpoint that is not a user held by a leaf node, or an unresolvable path,
/// yields [`LedgerError::UnsupportedEndpoint`].
pub fn expected_hops(
    topology: &Topology,
    order: &PaymentOrder,
) -> Result<Vec<ExpectedHop>, LedgerError> {
    let from_leaf = user_leaf(topology, &order.from)?;
    let to_leaf = user_leaf(topology, &order.to)?;

    // Same leaf: a single Direct move between the two user accounts.
    if from_leaf == to_leaf {
        return Ok(vec![ExpectedHop {
            signer: from_leaf,
            role: HopRole::Direct,
            first: AccountRef::Child(order.from.clone()),
            second: AccountRef::Child(order.to.clone()),
        }]);
    }

    let from_addr = topology
        .address_of(order.from.as_str())
        .map_err(|_| LedgerError::UnsupportedEndpoint)?;
    let to_addr = topology
        .address_of(order.to.as_str())
        .map_err(|_| LedgerError::UnsupportedEndpoint)?;
    let lca_addr = from_addr.lca(&to_addr);
    let lca_node = node_at_address(topology, &lca_addr)?;

    // Ascending path: from_leaf upward, excluding the LCA.
    let up_nodes = path_below(topology, &from_leaf, &lca_node)?;
    // Descending path: child of LCA down to to_leaf.
    let mut down_nodes = path_below(topology, &to_leaf, &lca_node)?;
    down_nodes.reverse();

    let branch_from = up_nodes
        .last()
        .cloned()
        .unwrap_or_else(|| order.from.clone());
    let branch_to = down_nodes
        .first()
        .cloned()
        .unwrap_or_else(|| order.to.clone());

    let mut hops = Vec::with_capacity(up_nodes.len() + 1 + down_nodes.len());

    // Ascend: each node debits `Parent` and the child toward the payer.
    for (index, node) in up_nodes.iter().enumerate() {
        let down = if index == 0 {
            order.from.clone()
        } else {
            up_nodes[index - 1].clone()
        };
        hops.push(ExpectedHop {
            signer: node.clone(),
            role: HopRole::Ascend,
            first: AccountRef::Parent,
            second: AccountRef::Child(down),
        });
    }

    // LCA: debit the branch toward the payer, credit the branch toward the payee.
    hops.push(ExpectedHop {
        signer: lca_node,
        role: HopRole::Lca,
        first: AccountRef::Child(branch_from),
        second: AccountRef::Child(branch_to),
    });

    // Descend: each node credits `Parent` and the child toward the payee.
    for (index, node) in down_nodes.iter().enumerate() {
        let down = if index + 1 == down_nodes.len() {
            order.to.clone()
        } else {
            down_nodes[index + 1].clone()
        };
        hops.push(ExpectedHop {
            signer: node.clone(),
            role: HopRole::Descend,
            first: AccountRef::Parent,
            second: AccountRef::Child(down),
        });
    }

    Ok(hops)
}

/// Require a `Child` account to exist and hold at least `amount`.
fn require_child(
    ledger: &Ledger<MemLog>,
    child: &NodeId,
    amount: Amount,
) -> Result<(), LedgerError> {
    let account = AccountRef::Child(child.clone());
    if !is_opened(ledger.balances(), &account) {
        return Err(LedgerError::AccountNotOpened { account });
    }
    if ledger.balances().child_balance(child) < amount {
        Err(LedgerError::InsufficientBalance)
    } else {
        Ok(())
    }
}

/// Require the node's `Parent` asset account to hold at least `amount`.
fn require_parent(ledger: &Ledger<MemLog>, amount: Amount) -> Result<(), LedgerError> {
    match ledger.balances().parent_balance() {
        Some(balance) if balance >= amount => Ok(()),
        _ => Err(LedgerError::InsufficientBalance),
    }
}

/// Require an account to be materialized (for credits).
fn require_opened(ledger: &Ledger<MemLog>, account: &AccountRef) -> Result<(), LedgerError> {
    if is_opened(ledger.balances(), account) {
        Ok(())
    } else {
        Err(LedgerError::AccountNotOpened {
            account: account.clone(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn hop_entry(
    ledger: &Ledger<MemLog>,
    payment_id: Hash,
    amount: Amount,
    role: HopRole,
    postings: Vec<Posting>,
    auth: &AuthRef,
    issued_at: u64,
) -> Entry {
    Entry {
        ledger_id: *ledger.ledger_id(),
        seq: ledger.len() as u64,
        height: ledger.len() as u64,
        prev_hash: ledger.head_hash(),
        issued_at,
        body: EntryBody::Transfer {
            payment_id,
            amount,
            role,
        },
        postings,
        auth: Some(auth.clone()),
    }
}

/// Dry-run every hop against cloned balances.
///
/// Each signer appears at most once, so applying to per-signer clones is
/// equivalent to applying the cascade in order. Rejects the plan if any hop
/// would overdraw or touch an unopened account.
fn dry_run(ledgers: &LedgerSet, hops: &[PlannedHop]) -> Result<(), LedgerError> {
    let mut staged: BTreeMap<NodeId, Balances> = BTreeMap::new();
    for hop in hops {
        if !staged.contains_key(&hop.signer) {
            staged.insert(
                hop.signer.clone(),
                ledger(ledgers, &hop.signer)?.balances().clone(),
            );
        }
    }
    for hop in hops {
        let balances = staged
            .get_mut(&hop.signer)
            .ok_or_else(|| LedgerError::MissingLedger {
                node: hop.signer.clone(),
            })?;
        balances.apply(&hop.entry.postings)?;
    }
    Ok(())
}

/// Plan the hop cascade for `order`.
///
/// The route comes from [`expected_hops`]. Preflight then checks every debit
/// (payer `Child(order.from)`; every ascending node's `Parent` and its child
/// toward the payer; the LCA's debit branch; a `Direct` payer) and that every
/// credited child account is materialized (LCA credit branch; each descending
/// node's child toward the payee; the payee). The whole cascade is finally
/// dry-run against cloned balances so a plan cannot be built if any hop would
/// fail.
///
/// Returns [`LedgerError::UnsupportedEndpoint`] if either endpoint is not a
/// user held by a leaf node or the path cannot be resolved;
/// [`LedgerError::InsufficientBalance`] / [`LedgerError::AccountNotOpened`] for
/// the positions above.
pub fn plan_transfer(
    topology: &Topology,
    order: &PaymentOrder,
    auth: &AuthRef,
    ledgers: &LedgerSet,
    issued_at: u64,
) -> Result<SettlementPlan, LedgerError> {
    if order.amount == Amount::ZERO {
        return Err(LedgerError::InvalidEntryShape);
    }

    let amount = order.amount;
    let payment_id = order.hash();
    let m = checked_i64(amount.get())?;
    let expected = expected_hops(topology, order)?;

    // Debit preflight, in hop order: ascending nodes check `Parent` and the
    // child toward the payer; the LCA checks its debit branch; a `Direct` hop
    // checks the payer's account. `Descend` hops debit nothing here.
    for hop in &expected {
        match hop.role {
            HopRole::Ascend => {
                let node_ledger = ledger(ledgers, &hop.signer)?;
                require_parent(node_ledger, amount)?;
                require_child(node_ledger, expect_child(&hop.second)?, amount)?;
            }
            HopRole::Lca | HopRole::Direct => {
                let node_ledger = ledger(ledgers, &hop.signer)?;
                require_child(node_ledger, expect_child(&hop.first)?, amount)?;
            }
            HopRole::Descend => {}
        }
    }

    // Credit preflight: every credited child account must already be open.
    for hop in &expected {
        if matches!(hop.role, HopRole::Lca | HopRole::Direct | HopRole::Descend) {
            let node_ledger = ledger(ledgers, &hop.signer)?;
            require_opened(node_ledger, &hop.second)?;
        }
    }

    let mut hops: Vec<PlannedHop> = Vec::with_capacity(expected.len());
    for hop in &expected {
        let node_ledger = ledger(ledgers, &hop.signer)?;
        hops.push(PlannedHop {
            signer: hop.signer.clone(),
            entry: hop_entry(
                node_ledger,
                payment_id,
                amount,
                hop.role,
                hop_postings(hop.role, &hop.first, &hop.second, m),
                auth,
                issued_at,
            ),
        });
    }
    dry_run(ledgers, &hops)?;

    Ok(SettlementPlan {
        order: order.clone(),
        hops,
    })
}

/// Sign, verify, and apply every hop of `plan` atomically.
///
/// Phase 1 preflights every hop before anything is applied: the signer's ledger
/// must be present in `ledgers`, its signing key in `keys`, [`verify_transfer`]
/// must pass, and the hop's `seq`/`height`/`prev_hash` must still match the
/// signer ledger's current head. Phase 2 stages the whole cascade on a clone of
/// `ledgers` and only swaps it into `*ledgers` on full success.
///
/// On any failure, `Err` is returned and `*ledgers` is left unchanged. Returns
/// the signed entries in hop order.
pub fn execute_plan(
    plan: &SettlementPlan,
    ledgers: &mut LedgerSet,
    keys: &BTreeMap<NodeId, LedgerSecretKey>,
    registry: &PeerRegistry,
    now: u64,
) -> Result<Vec<SignedEntry>, LedgerError> {
    // Phase 1: preflight (no mutation).
    let mut signed_hops = Vec::with_capacity(plan.hops.len());
    for hop in &plan.hops {
        let key = keys
            .get(&hop.signer)
            .ok_or_else(|| LedgerError::MissingLedger {
                node: hop.signer.clone(),
            })?;
        let signed = SignedEntry::sign(hop.entry.clone(), key)?;
        verify_transfer(&signed, &plan.order, registry, now)?;

        let signer_ledger = ledger(ledgers, &hop.signer)?;
        let expected_seq = signer_ledger.len() as u64;
        if hop.entry.seq != expected_seq {
            return Err(LedgerError::SeqOutOfOrder {
                expected: expected_seq,
                found: hop.entry.seq,
            });
        }
        if hop.entry.height != hop.entry.seq {
            return Err(LedgerError::InvalidHeight {
                expected: hop.entry.seq,
                found: hop.entry.height,
            });
        }
        let expected_prev = signer_ledger.head_hash();
        if hop.entry.prev_hash != expected_prev {
            return Err(LedgerError::PrevHashMismatch {
                expected: expected_prev,
                found: hop.entry.prev_hash,
            });
        }

        signed_hops.push(signed);
    }

    // Phase 2: stage the cascade on a clone; commit only on full success.
    let mut staged = ledgers.clone();
    for (hop, signed) in plan.hops.iter().zip(signed_hops.iter()) {
        let signer_ledger =
            staged
                .get_mut(&hop.signer)
                .ok_or_else(|| LedgerError::MissingLedger {
                    node: hop.signer.clone(),
                })?;
        signer_ledger.append(signed.clone())?;
    }
    *ledgers = staged;
    Ok(signed_hops)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> OctAddr {
        s.parse()
            .unwrap_or_else(|err| panic!("parse of {s:?} failed: {err}"))
    }

    /// Tree: `R=0`, `A=0.0`, `B=0.1`, `L_A=0.0.0`, `L_B=0.1.0`, `uA=0.0.0.0`,
    /// `uA2=0.0.0.1`, `uB=0.1.0.0`. A payment `uA -> uB` routes
    /// `L_A Ascend, A Ascend, R Lca, B Descend, L_B Descend`.
    #[test]
    fn classify_same_leaf_is_direct_at_the_shared_leaf() {
        let src = addr("0.0.0.0"); // uA
        let dst = addr("0.0.0.1"); // uA2
        assert_eq!(
            classify_hop(&src, &dst, &addr("0.0.0")),
            Some(HopRole::Direct)
        );
        // Anything above (or outside) the shared leaf is off-route.
        assert_eq!(classify_hop(&src, &dst, &addr("0.0")), None);
        assert_eq!(classify_hop(&src, &dst, &addr("0.1.0")), None);
        assert_eq!(classify_hop(&src, &dst, &addr("0")), None);
    }

    #[test]
    fn classify_cross_leaf_cascade() {
        let src = addr("0.0.0.0"); // uA
        let dst = addr("0.1.0.0"); // uB

        // Payer leaf and every strict ancestor below the LCA ascend.
        assert_eq!(
            classify_hop(&src, &dst, &addr("0.0.0")),
            Some(HopRole::Ascend)
        ); // L_A
        assert_eq!(classify_hop(&src, &dst, &addr("0.0")), Some(HopRole::Ascend)); // A
        // The root-as-LCA reallocates.
        assert_eq!(classify_hop(&src, &dst, &addr("0")), Some(HopRole::Lca)); // R
        // Every strict ancestor below the LCA on the payee side descends.
        assert_eq!(
            classify_hop(&src, &dst, &addr("0.1")),
            Some(HopRole::Descend)
        ); // B
        assert_eq!(
            classify_hop(&src, &dst, &addr("0.1.0")),
            Some(HopRole::Descend)
        ); // L_B

        // Off-route siblings and unrelated branches.
        assert_eq!(classify_hop(&src, &dst, &addr("0.2")), None);
        assert_eq!(classify_hop(&src, &dst, &addr("0.1.1")), None);
        assert_eq!(classify_hop(&src, &dst, &addr("0.0.1")), None);
    }

    #[test]
    fn classify_uses_a_deeper_lca() {
        // Both endpoints under `A=0.0`, so the LCA is `A`, not the root.
        let src = addr("0.0.0.0"); // uA under L_A
        let dst = addr("0.0.1.0"); // a user under L_A's sibling leaf
        assert_eq!(classify_hop(&src, &dst, &addr("0.0")), Some(HopRole::Lca));
        assert_eq!(
            classify_hop(&src, &dst, &addr("0.0.0")),
            Some(HopRole::Ascend)
        );
        assert_eq!(
            classify_hop(&src, &dst, &addr("0.0.1")),
            Some(HopRole::Descend)
        );
        // The root is above the LCA and is off-route.
        assert_eq!(classify_hop(&src, &dst, &addr("0")), None);
    }

    #[test]
    fn classify_endpoint_addresses_follow_the_contract() {
        let src = addr("0.0.0.0");
        let dst = addr("0.1.0.0");
        assert_eq!(classify_hop(&src, &dst, &src), Some(HopRole::Ascend));
        assert_eq!(classify_hop(&src, &dst, &dst), Some(HopRole::Descend));
    }

    #[test]
    fn hop_postings_shapes_match_the_roles() {
        let m = 5;
        assert_eq!(
            hop_postings(HopRole::Ascend, &AccountRef::Parent, &AccountRef::Child(NodeId::from("a")), m),
            vec![posting(AccountRef::Parent, -m), posting(AccountRef::Child(NodeId::from("a")), -m)]
        );
        assert_eq!(
            hop_postings(HopRole::Descend, &AccountRef::Parent, &AccountRef::Child(NodeId::from("a")), m),
            vec![posting(AccountRef::Parent, m), posting(AccountRef::Child(NodeId::from("a")), m)]
        );
        assert_eq!(
            hop_postings(
                HopRole::Lca,
                &AccountRef::Child(NodeId::from("a")),
                &AccountRef::Child(NodeId::from("b")),
                m
            ),
            vec![
                posting(AccountRef::Child(NodeId::from("a")), -m),
                posting(AccountRef::Child(NodeId::from("b")), m),
            ]
        );
    }
}
