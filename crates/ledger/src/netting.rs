//! Periodic netting and double-spend reconciliation (Phase D).
//!
//! Payment-time double-spend prevention across subtrees is an accepted risk in
//! Cawala's model (see `PLAN.org`): a registered but dishonest routing node can
//! sign a locally-valid hop that routes a payment somewhere other than the
//! order's payee, and the same authorisation can be replayed onto more than one
//! cascade. Neither is caught by [`crate::log::Ledger::append`] or
//! [`crate::auth::verify_transfer`], which only check per-entry validity and the
//! payer's authorisation.
//!
//! This module is the detection half of that trade. [`verify_cascade`] rebuilds
//! the unique topology route for an order and requires the on-ledger hops to
//! match it exactly, and [`net`] audits commitment chains, edge mirrors, routes,
//! replays, reconstructed overdraws, and finally collapses opposing flows into
//! [`NetTransfer`]s. Detection happens at reconciliation time, not acceptance
//! time.
//!
//! # Mirror mismatches have a direction
//!
//! A disagreement between a parent's `Child(node)` liability and the child's
//! `Parent` asset is reported as [`Finding::MirrorMismatch`] with a
//! [`MirrorDirection`]:
//!
//! - [`MirrorDirection::UnbackedClaim`] (`child_view > parent_view`) is the
//!   signal for a value claim the parent never extended — a local, unmirrored
//!   issuance/descend, or a stranded claim after re-attach. The parent owes an
//!   eventual honour/settlement (the M5 "exit rights" obligation). Local
//!   issuance is externally backed and normal under the no-Equity model, so this
//!   is an edge-level signal, **not** a global-supply or `UnbackedLiability`
//!   finding.
//! - [`MirrorDirection::UnmirroredExtension`] (`parent_view > child_view`) is a
//!   **transient pending handoff**: the parent has extended credit the child has
//!   not mirrored yet (expected mid-flight between a parent `Descend`/`Issue`
//!   and the child recording it).
//!
//! Everything here is pure, synchronous, and wasm-safe: no I/O, no RNG.

use std::collections::{BTreeMap, BTreeSet};

use cawala_topology::Topology;
use serde::{Deserialize, Serialize};

use crate::account::{AccountRef, NodeId, aggregate_deltas};
use crate::amount::Amount;
use crate::auth::{PaymentOrder, verify_transfer};
use crate::commit::{Commitment, EdgeAccount, SignedCommitment, commitment_hash, verify_chain};
use crate::entry::{Entry, EntryBody, HopRole, SignedEntry};
use crate::error::LedgerError;
use crate::hash::Hash;
use crate::keys::LedgerPubKey;
use crate::registry::PeerRegistry;
use crate::settlement::{LedgerSet, PlannedHop, expected_hops};

/// The result of a netting pass: every anomaly found plus the collapsed flows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NettingReport {
    /// Detected anomalies, in deterministic audit order.
    pub findings: Vec<Finding>,
    /// Opposing flows collapsed per parent (derived-equity-preserving).
    pub nets: Vec<NetTransfer>,
}

/// A netted transfer between two child accounts of one parent.
///
/// A `NetTransfer` is a summary, not a new obligation: it collapses the gross
/// opposing flows between the same child pair. Settlement of the *net* between
/// `from` and `to` preserves every ledger's derived equity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetTransfer {
    /// The node that holds both child accounts.
    pub parent: NodeId,
    /// The child whose net flow is negative (pays).
    pub from: NodeId,
    /// The child whose net flow is positive (receives).
    pub to: NodeId,
    /// The collapsed amount, `> 0`.
    pub amount: Amount,
}

/// Which way an edge's two balance views disagree.
///
/// The two directions are economically distinct and are **not** equivalent:
///
/// - [`UnbackedClaim`](MirrorDirection::UnbackedClaim): the child's `Parent`
///   asset is larger than the parent's `Child(node)` liability. The child (or
///   its subtree) holds a claim the parent never extended — a local, unmirrored
///   issuance/descend, or a stranded claim after re-attach. This is the signal
///   that the parent must eventually honour or settle (the M5 "exit rights"
///   obligation). Local issuance is externally backed and normal under the
///   no-Equity model; that it appears here as an unbacked *edge* claim is what
///   matters, not a global-supply anomaly.
/// - [`UnmirroredExtension`](MirrorDirection::UnmirroredExtension): the parent's
///   `Child(node)` liability is larger than the child's `Parent` asset. The
///   parent has extended credit the child has not recorded yet — a **transient
///   pending handoff**, expected in flight between a parent's `Descend`/`Issue`
///   and the child mirroring it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MirrorDirection {
    /// `child_view > parent_view`: the child claims more than the parent owes.
    UnbackedClaim,
    /// `parent_view > child_view`: the parent credited more than the child has
    /// mirrored (a transient pending handoff).
    UnmirroredExtension,
}

/// A detected reconciliation anomaly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Finding {
    /// A ledger equivocated: two signed commitments at the same height with
    /// different entry/state roots.
    Fork {
        /// The equivocating ledger's identity.
        ledger_id: LedgerPubKey,
        /// The shared height of the conflicting commitments.
        height: u64,
        /// Distinct commitment hashes for the conflicting heads (sorted).
        heads: Vec<Hash>,
    },
    /// A node's commitment chain is not a valid chain (broken
    /// `prev_commitment_hash`, height rollback, inconsistent height/entry
    /// count, or a bad signature).
    ChainInvalid {
        /// The node whose chain failed verification.
        node: NodeId,
        /// Human-readable detail (the underlying [`verify_chain`] error).
        reason: String,
    },
    /// A parent's liability view of a child disagrees with the child's asset
    /// view of its parent. See [`MirrorDirection`] for the two directions.
    MirrorMismatch {
        /// The topology edge whose two views disagree.
        edge: EdgeAccount,
        /// The parent ledger's view of the child liability.
        parent_view: Amount,
        /// The child ledger's view of its parent asset.
        child_view: Amount,
        /// Which view is larger; see [`MirrorDirection`].
        direction: MirrorDirection,
    },
    /// An order's on-ledger cascade does not match the unique topology route.
    RouteInvalid {
        /// The order's `payment_id`.
        payment_id: Hash,
        /// Human-readable detail (the underlying rejection).
        reason: String,
    },
    /// The same order authorisation was consumed more than once.
    Replay {
        /// The replayed order's `payment_id`.
        payment_id: Hash,
        /// Human-readable detail.
        reason: String,
    },
    /// A reconstructed `Parent`/`Child` balance is negative.
    Overdraw {
        /// The node whose reconstructed balance went negative.
        node: NodeId,
        /// The account that went negative.
        account: AccountRef,
        /// The magnitude by which the balance is below zero.
        deficit: i128,
    },
    /// An independent (exited) subtree that is a weakly connected component of
    /// its own, rooted at `0`. Its root carries a stranded `Parent` claim the
    /// severed old parent never settled.
    ///
    /// This replaces the old single-root hard failure for islands. It is an
    /// **advisory**: the exit is a legitimate topology event, and the stranded
    /// claim is tolerated (the M5 "exit rights" decision), so it is visible but
    /// never gates reconciliation into a hard failure.
    Detached {
        /// The island's root node (address `0`).
        root: NodeId,
        /// The island's member node ids (sorted).
        nodes: Vec<NodeId>,
        /// The severed old parent, when a stale parent-side link identified it.
        stranded_parent: Option<NodeId>,
        /// The island root's `Parent` asset: its stranded claim.
        parent_balance: Amount,
    },
    /// A record's own `parent` link disagrees with a stale parent-side
    /// `children` row. The child's link wins; this names the stale row, which
    /// was ignored.
    ///
    /// Advisory for the same reason as [`Finding::Detached`]: a unilateral exit
    /// can leave the old parent listing a child that has already rebased to
    /// `0`.
    StaleChildLink {
        /// The parent named by the stale `children` row.
        parent: NodeId,
        /// The child whose own (authoritative) link won.
        child: NodeId,
    },
}

impl Finding {
    /// Whether this finding is **advisory**: visible to the operator but not a
    /// hard failure.
    ///
    /// Advisories are live-topology signals that need operator adjudication
    /// rather than a rejected reconciliation:
    ///
    /// - [`Finding::RouteInvalid`]: the topology a route was audited against is
    ///   live control-plane state (e.g. a re-slotted child);
    /// - [`Finding::Detached`]: an exited subtree is a legitimate independent
    ///   network with a tolerated stranded claim;
    /// - [`Finding::StaleChildLink`]: a stale parent-side link from before an
    ///   exit.
    ///
    /// Classification is independent of the netting gate: a caller must apply
    /// [`Finding::suppresses_netting`] to decide whether flows may collapse.
    pub fn is_advisory(&self) -> bool {
        matches!(
            self,
            Finding::RouteInvalid { .. }
                | Finding::Detached { .. }
                | Finding::StaleChildLink { .. }
        )
    }

    /// Whether this finding is a soundness objection that **suppresses the
    /// netting collapse**.
    ///
    /// Every finding suppresses except the two steady-state exit signals:
    ///
    /// - [`Finding::Detached`] — an exited subtree is a legitimate independent
    ///   network; its stranded claim is tolerated by design, so it must not
    ///   permanently disable reconciliation of the (still healthy) components;
    /// - [`Finding::StaleChildLink`] — a stale parent-side link from before an
    ///   exit, likewise a steady state.
    ///
    /// [`Finding::RouteInvalid`] **keeps suppressing** (as it always has): an
    /// unroutable order is a live-topology signal that needs adjudication
    /// before flows are collapsed. `Fork`/`ChainInvalid`/`MirrorMismatch`/
    /// `Replay`/`Overdraw` all suppress too.
    ///
    /// This is deliberately separate from [`Finding::is_advisory`]: severity
    /// (exit code) and the netting gate are orthogonal. `RouteInvalid` is
    /// advisory yet suppresses; `Detached`/`StaleChildLink` are advisory and do
    /// not.
    pub fn suppresses_netting(&self) -> bool {
        !matches!(
            self,
            Finding::Detached { .. } | Finding::StaleChildLink { .. }
        )
    }
}

/// One independent network for a partitioned audit: a normal single-root
/// topology, plus the severed old parent of its root when a stale link
/// identified one.
///
/// A network that has split through exit is a set of weakly connected
/// components, each rooted at `0`. Each component is audited exactly like an
/// ordinary single-root network by [`net_partition`]; [`Finding::Detached`]
/// reports the islands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetComponent {
    /// The component's single-root topology.
    pub topology: Topology,
    /// The severed old parent of this component's root, when a stale link
    /// identified it (`None` for the primary component).
    pub stranded_parent: Option<NodeId>,
}

/// Verify that the on-ledger cascade for `order` exactly matches the unique
/// topology route.
///
/// Selects every transfer entry whose **operator authorisation** is for
/// `order` — i.e. `auth.order_hash == order.hash()` and
/// `auth.operator == registry.operator_of(&order.from)` — regardless of the
/// entry body's mutable `payment_id` field, then requires:
///
/// - every selected hop is signed by a *registered* node ledger and passes
///   [`verify_transfer`] (the payer's authorisation, amount and payment id);
/// - there is exactly one actual hop per [`expected_hops`] entry, with no
///   extra, missing, or duplicate hop;
/// - each actual hop's signer, role, and canonical first/second accounts match
///   the expected hop; and
/// - the terminal hop credits `Child(order.to)`.
///
/// Any mismatch, extra, missing, or duplicate hop yields an error. A body
/// `payment_id` that disagrees with the authorisation is rejected by
/// [`verify_transfer`]'s conservation check (see
/// [`crate::entry::Entry::check_conservation`]). Expiry is checked against
/// `order.expiry` (netting is retrospective; an order is not rejected here
/// merely because wall-clock time has moved on).
///
/// This is the route binding that [`crate::auth::verify_transfer`] deliberately
/// leaves to Phase D: a registered rogue hop can be locally valid and still be
/// rejected here.
pub fn verify_cascade(
    topology: &Topology,
    order: &PaymentOrder,
    ledgers: &LedgerSet,
    registry: &PeerRegistry,
) -> Result<Vec<PlannedHop>, LedgerError> {
    let expected = expected_hops(topology, order)?;
    let actual = collect_authorized_transfers(ledgers, order);

    // Every actual hop must be signed by a registered node and carry a valid
    // authorisation for this order. Key by the registered signer so route
    // matching cannot be spoofed by storage location.
    let mut matched: BTreeMap<NodeId, SignedEntry> = BTreeMap::new();
    for signed in &actual {
        let signer = registry.verify_entry(signed)?.node_id.clone();
        verify_transfer(signed, order, registry, order.expiry)?;
        if matched.insert(signer, signed.clone()).is_some() {
            // The same signer produced more than one hop for this payment.
            return Err(LedgerError::DuplicatePeer);
        }
    }
    if matched.len() != expected.len() {
        return Err(LedgerError::InvalidEntryShape);
    }

    let mut out = Vec::with_capacity(expected.len());
    for hop in &expected {
        let signed = matched
            .get(&hop.signer)
            .ok_or(LedgerError::InvalidEntryShape)?;
        let EntryBody::Transfer { role, amount, .. } = &signed.entry.body else {
            return Err(LedgerError::InvalidEntryShape);
        };
        if *role != hop.role || *amount != order.amount {
            return Err(LedgerError::InvalidEntryShape);
        }
        let (first, second) = entry_hop_accounts(&signed.entry, hop.role)?;
        if first != hop.first || second != hop.second {
            return Err(LedgerError::InvalidEntryShape);
        }
        out.push(PlannedHop {
            signer: hop.signer.clone(),
            entry: signed.entry.clone(),
        });
    }

    // Terminal credit must bind the order's payee. Redundant with the route
    // match above, checked explicitly because it is the load-bearing recipient
    // binding.
    if let Some(terminal) = expected.last() {
        let signed = matched
            .get(&terminal.signer)
            .ok_or(LedgerError::InvalidEntryShape)?;
        let EntryBody::Transfer { role, .. } = &signed.entry.body else {
            return Err(LedgerError::InvalidEntryShape);
        };
        let (_, second) = entry_hop_accounts(&signed.entry, *role)?;
        if second != AccountRef::Child(order.to.clone()) {
            return Err(LedgerError::InvalidEntryShape);
        }
    }

    Ok(out)
}

/// Run a full netting reconciliation.
///
/// Audit order is deterministic:
///
/// 1. **Chain:** for each `(node, chain)`, run [`verify_chain`] against the
///    node's registered ledger key ([`Finding::ChainInvalid`] on failure), and
///    additionally flag any two commitments at the same height with different
///    entry/state roots ([`Finding::Fork`]).
/// 2. **Mirror:** for every topology edge whose parent and child both have
///    ledgers, compare the parent's child liability with the child's parent
///    asset.
/// 3. **Route/replay:** per order, flag a replayed authorisation (more
///    on-ledger hops than the route requires, or a duplicate signer), otherwise
///    map a [`verify_cascade`] rejection to [`Finding::RouteInvalid`].
/// 4. **Overdraw:** replay each ledger's raw entries and flag any reconstructed
///    `Parent`/`Child` that goes negative (defence in depth behind
///    [`crate::account::Balances::apply`], which already rejects negatives at
///    append time).
/// 5. **Netting collapse:** collapse opposing child-to-child flows per parent.
///
/// # Commitment chains
///
/// Each entry of `commitments` must be a full, genesis-anchored chain for its
/// node — exactly the shape [`verify_chain`] expects: the first element's
/// `prev_commitment_hash` is [`Hash::ZERO`], and each later element has a
/// strictly greater height and a `prev_commitment_hash` equal to the previous
/// commitment's hash. A partial or windowed chain (e.g. a suffix whose first
/// element does not anchor at genesis) is reported as
/// [`Finding::ChainInvalid`], even though every element verifies in isolation.
///
/// # Output gate
///
/// `nets` is populated only when no finding objects to collapsing flows
/// ([`Finding::suppresses_netting`]). `Fork`/`ChainInvalid`/`MirrorMismatch`/
/// `Replay`/`Overdraw`/`RouteInvalid` suppress; the steady-state exit signals
/// `Detached`/`StaleChildLink` do not, so an island never permanently disables
/// reconciliation. Callers still classify findings with
/// [`Finding::is_advisory`] for the process exit code.
pub fn net(
    topology: &Topology,
    ledgers: &LedgerSet,
    registry: &PeerRegistry,
    orders: &[PaymentOrder],
    commitments: &BTreeMap<NodeId, Vec<SignedCommitment>>,
) -> NettingReport {
    net_partition(
        &[NetComponent {
            topology: topology.clone(),
            stranded_parent: None,
        }],
        ledgers,
        registry,
        orders,
        commitments,
    )
}

/// Run a full netting reconciliation over a **partition** of the network.
///
/// Exiting a subtree rebases it onto root `0`, so the whole tree can
/// legitimately contain several weakly connected components, each rooted at
/// `0`. `components[0]` is the **primary** network and each later component is
/// an island; every component is a normal single-root tree and is audited
/// exactly as [`net`] audits one, with these differences:
///
/// 1. **Chains** and **overdraw** are global (one pass over every ledger).
/// 2. **Mirrors** are audited per component (island-internal parent/child edges
///    are compared normally). Each island additionally yields a
///    [`Finding::Detached`] carrying its root, members, severed parent (when
///    known) and stranded `Parent` balance.
/// 3. **Routes** are audited against the order's own component. An order whose
///    endpoints are in *different* components has no common root and is
///    reported once as [`Finding::RouteInvalid`].
/// 4. **Netting collapse** is global, as in [`net`], and runs unless some
///    finding suppresses netting (see [`Finding::suppresses_netting`]).
///    `Detached` and `StaleChildLink` are steady-state exit signals and do
///    **not** suppress, so an island's own healthy components still net;
///    [`Finding::RouteInvalid`] and every hard finding still do.
///
/// A severed edge (an island root whose old parent still lists it) is **not**
/// part of any component topology, so it is reported once via
/// [`Finding::Detached`] and never as a permanent [`Finding::MirrorMismatch`].
pub fn net_partition(
    components: &[NetComponent],
    ledgers: &LedgerSet,
    registry: &PeerRegistry,
    orders: &[PaymentOrder],
    commitments: &BTreeMap<NodeId, Vec<SignedCommitment>>,
) -> NettingReport {
    let mut findings = Vec::new();

    audit_chains(commitments, registry, &mut findings);

    if components.is_empty() {
        audit_overdraw(ledgers, &mut findings);
        return NettingReport {
            findings,
            nets: Vec::new(),
        };
    }

    // Node id -> component index. Components are disjoint by construction, but
    // keep the first (primary) assignment if a caller supplies overlap.
    let mut membership: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, component) in components.iter().enumerate() {
        for id in component.topology.node_ids() {
            membership.entry(id.as_str()).or_insert(index);
        }
    }

    for (index, component) in components.iter().enumerate() {
        audit_mirrors(&component.topology, ledgers, &mut findings);

        // Every non-primary component is an independent (exited) network.
        if index > 0 {
            let root = NodeId::from(component.topology.root_id());
            let mut nodes: Vec<NodeId> = component
                .topology
                .node_ids()
                .map(|id| NodeId::from(id.as_str()))
                .collect();
            nodes.sort();
            let parent_balance = ledgers
                .get(&root)
                .and_then(|ledger| ledger.balances().parent_balance())
                .unwrap_or(Amount::ZERO);
            findings.push(Finding::Detached {
                root,
                nodes,
                stranded_parent: component.stranded_parent.clone(),
                parent_balance,
            });
        }
    }

    audit_routes_partition(orders, components, &membership, ledgers, registry, &mut findings);
    audit_overdraw(ledgers, &mut findings);

    // Only a reconciliation free of netting-suppressing findings may collapse
    // flows. `Detached`/`StaleChildLink` are steady-state exit signals and are
    // deliberately exempt (see `Finding::suppresses_netting`).
    let nets = if findings.iter().any(Finding::suppresses_netting) {
        Vec::new()
    } else {
        collapse_nets(ledgers)
    };

    NettingReport { findings, nets }
}

/// A per-component view of `ledgers`: only the ledgers owned by nodes in
/// `topology`. Route/replay auditing must be scoped to the order's own
/// component so a hop that lives in another (now independent) network is not
/// counted as part of this route.
fn component_ledgers(ledgers: &LedgerSet, topology: &Topology) -> LedgerSet {
    let mut subset = LedgerSet::new();
    for id in topology.node_ids() {
        let node = NodeId::from(id.as_str());
        if let Some(ledger) = ledgers.get(&node) {
            // `insert` fails only on a duplicate, which cannot happen here.
            let _ = subset.insert(node, ledger.clone());
        }
    }
    subset
}

/// Every transfer entry backed by `order`'s authorisation hash.
///
/// Selection is on the *signed* authorization hash (`auth.order_hash`), never
/// the mutable body `payment_id`: an entry whose body was rewritten to a
/// different payment id is still audited (and then rejected by
/// [`verify_transfer`]). Selection deliberately does **not** filter on
/// `auth.operator`: an entry naming the payer's order hash under the wrong
/// operator must be rejected by [`verify_transfer`] (mapping to
/// [`Finding::RouteInvalid`]) and counted toward [`Finding::Replay`], not
/// silently ignored.
fn collect_authorized_transfers(ledgers: &LedgerSet, order: &PaymentOrder) -> Vec<SignedEntry> {
    let order_hash = order.hash();
    let mut out = Vec::new();
    for node in ledgers.node_ids() {
        let Some(ledger) = ledgers.get(node) else {
            continue;
        };
        for index in 0..ledger.len() {
            if let Ok(Some(signed)) = ledger.get(index)
                && matches!(&signed.entry.body, EntryBody::Transfer { .. })
                && let Some(auth) = &signed.entry.auth
                && auth.order_hash == order_hash
            {
                out.push(signed);
            }
        }
    }
    out
}

/// Whether two collected hops share a signing ledger.
fn has_duplicate_ledger(entries: &[SignedEntry]) -> bool {
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .any(|signed| !seen.insert(signed.entry.ledger_id))
}

/// Extract a hop entry's `(first, second)` accounts from its canonical shape.
///
/// `Ascend`/`Descend` name `Parent` plus one child; `Lca`/`Direct` name a
/// debited and a credited child. Posting order is not trusted: the accounts are
/// derived from role and sign so a reordered (but equivalent) posting set is
/// accepted. The returned order matches [`crate::settlement::ExpectedHop`]'s
/// `first`/`second`.
pub fn entry_hop_accounts(
    entry: &Entry,
    role: HopRole,
) -> Result<(AccountRef, AccountRef), LedgerError> {
    let deltas = aggregate_deltas(&entry.postings)?;
    match role {
        HopRole::Ascend | HopRole::Descend => {
            if !deltas.contains_key(&AccountRef::Parent) {
                return Err(LedgerError::InvalidEntryShape);
            }
            let mut child = None;
            for account in deltas.keys() {
                if let AccountRef::Child(id) = account {
                    if child.is_some() {
                        return Err(LedgerError::InvalidEntryShape);
                    }
                    child = Some(AccountRef::Child(id.clone()));
                }
            }
            let child = child.ok_or(LedgerError::InvalidEntryShape)?;
            Ok((AccountRef::Parent, child))
        }
        HopRole::Lca | HopRole::Direct => {
            let mut first = None;
            let mut second = None;
            for (account, delta) in &deltas {
                let AccountRef::Child(id) = account else {
                    return Err(LedgerError::InvalidEntryShape);
                };
                let child = AccountRef::Child(id.clone());
                if *delta < 0 {
                    if first.is_some() {
                        return Err(LedgerError::InvalidEntryShape);
                    }
                    first = Some(child);
                } else if *delta > 0 {
                    if second.is_some() {
                        return Err(LedgerError::InvalidEntryShape);
                    }
                    second = Some(child);
                } else {
                    return Err(LedgerError::InvalidEntryShape);
                }
            }
            Ok((
                first.ok_or(LedgerError::InvalidEntryShape)?,
                second.ok_or(LedgerError::InvalidEntryShape)?,
            ))
        }
    }
}

/// Step 1: verify each commitment chain and detect equivocation.
fn audit_chains(
    commitments: &BTreeMap<NodeId, Vec<SignedCommitment>>,
    registry: &PeerRegistry,
    findings: &mut Vec<Finding>,
) {
    for (node, chain) in commitments {
        let Some(expected) = registry.ledger_of(node) else {
            // Without a registered ledger key a chain cannot be attributed.
            continue;
        };

        // Linkage/signature/height walk. A same-height fork also fails this
        // (height rollback), so `ChainInvalid` and `Fork` may both fire.
        if let Err(err) = verify_chain(chain, expected) {
            findings.push(Finding::ChainInvalid {
                node: node.clone(),
                reason: err.to_string(),
            });
        }

        // Group commitments that verify under the node's registered key by
        // height. A fork is by construction *not* a valid chain, so
        // `verify_chain` cannot be relied on to describe it; group explicitly.
        // Unverifiable commitments are not heads.
        let mut groups: BTreeMap<u64, Vec<&Commitment>> = BTreeMap::new();
        for signed in chain {
            if registry.verify_commitment(signed).is_err() {
                continue;
            }
            if signed.commitment.ledger_id != *expected {
                continue;
            }
            groups
                .entry(signed.commitment.height)
                .or_default()
                .push(&signed.commitment);
        }

        for (height, group) in groups {
            let roots: BTreeSet<(Hash, Hash)> =
                group.iter().map(|c| (c.entry_root, c.state_root)).collect();
            if roots.len() > 1 {
                let mut heads: Vec<Hash> = group.iter().map(|c| commitment_hash(c)).collect();
                heads.sort_unstable();
                heads.dedup();
                findings.push(Finding::Fork {
                    ledger_id: *expected,
                    height,
                    heads,
                });
            }
        }
    }
}

/// Step 2: compare each parent/child edge's two balance views.
fn audit_mirrors(topology: &Topology, ledgers: &LedgerSet, findings: &mut Vec<Finding>) {
    // `Topology` stores nodes in a `HashMap`, so sort for deterministic output.
    let mut parents: Vec<&String> = topology.node_ids().collect();
    parents.sort();

    for parent in parents {
        let parent_id = NodeId::from(parent.as_str());
        let Some(parent_ledger) = ledgers.get(&parent_id) else {
            continue;
        };
        let Ok(children) = topology.children_of(parent) else {
            continue;
        };
        for child in children {
            let child_id = NodeId::from(child.child_id);
            let Some(child_ledger) = ledgers.get(&child_id) else {
                continue;
            };
            let parent_view = parent_ledger.balances().child_balance(&child_id);
            let child_view = child_ledger
                .balances()
                .parent_balance()
                .unwrap_or(Amount::ZERO);
            if parent_view != child_view {
                let direction = if child_view > parent_view {
                    MirrorDirection::UnbackedClaim
                } else {
                    MirrorDirection::UnmirroredExtension
                };
                findings.push(Finding::MirrorMismatch {
                    edge: EdgeAccount {
                        parent: parent_id.clone(),
                        child: child_id,
                    },
                    parent_view,
                    child_view,
                    direction,
                });
            }
        }
    }
}

/// Step 3: audit each order's route against its own component, separating
/// replay from misrouting.
///
/// An order whose endpoints lie in **different** components has no common root,
/// so it is reported once as [`Finding::RouteInvalid`] (advisory). Every other
/// order is audited against the single component its endpoints share, using a
/// component-scoped ledger view so a hop in another independent network is not
/// counted.
fn audit_routes_partition(
    orders: &[PaymentOrder],
    components: &[NetComponent],
    membership: &BTreeMap<&str, usize>,
    ledgers: &LedgerSet,
    registry: &PeerRegistry,
    findings: &mut Vec<Finding>,
) {
    // Lazily build (and cache) a per-component ledger view; most audits are
    // single-component and never need one.
    let mut subsets: Vec<Option<LedgerSet>> = vec![None; components.len()];

    for order in orders {
        let from_component = membership.get(order.from.as_str()).copied();
        let to_component = membership.get(order.to.as_str()).copied();

        if let (Some(from), Some(to)) = (from_component, to_component)
            && from != to
        {
            findings.push(Finding::RouteInvalid {
                payment_id: order.hash(),
                reason: format!(
                    "{} -> {} endpoints are in different topology components",
                    order.from, order.to
                ),
            });
            continue;
        }

        // Both endpoints are in one component, or an endpoint is unknown (fall
        // back to the primary component so `expected_hops` reports it).
        let index = from_component.or(to_component).unwrap_or(0);
        let Some(component) = components.get(index) else {
            continue;
        };
        if subsets[index].is_none() {
            subsets[index] = Some(component_ledgers(ledgers, &component.topology));
        }
        let scoped = subsets[index]
            .as_ref()
            .expect("component ledger view was just built");
        audit_one_order(order, &component.topology, scoped, registry, findings);
    }
}

/// Audit one order's route/replay against a single component.
///
/// Entries are selected by the signed authorisation, not the body `payment_id`,
/// so a rewritten body is audited too. A replay shows up as more authorised
/// hops than the route has, or as one signing ledger producing several hops.
fn audit_one_order(
    order: &PaymentOrder,
    topology: &Topology,
    ledgers: &LedgerSet,
    registry: &PeerRegistry,
    findings: &mut Vec<Finding>,
) {
    let payment_id = order.hash();
    let actual = collect_authorized_transfers(ledgers, order);
    let expected = expected_hops(topology, order);
    let expected_len = expected.as_ref().map(|hops| hops.len()).ok();

    // A replay shows up as more on-ledger hops than the route has, or as
    // one signer producing several hops for the same payment.
    let too_many = expected_len.is_some_and(|len| actual.len() > len);
    if too_many || has_duplicate_ledger(&actual) {
        let expected = expected_len
            .map(|len| len.to_string())
            .unwrap_or_else(|| "an unresolvable route".to_string());
        findings.push(Finding::Replay {
            payment_id,
            reason: format!(
                "payer {} replayed payment {} across {} on-ledger hops (expected {})",
                order.from,
                payment_id.to_hex(),
                actual.len(),
                expected
            ),
        });
        return;
    }

    if let Err(err) = verify_cascade(topology, order, ledgers, registry) {
        findings.push(Finding::RouteInvalid {
            payment_id,
            reason: format!("{} -> {} cascade rejected: {err}", order.from, order.to),
        });
    }
}

/// Step 4: reconstruct `Parent`/`Child` balances from raw entries and flag
/// negatives.
///
/// [`crate::account::Balances::apply`] already rejects any negative during
/// [`crate::log::Ledger::append`], so a ledger built through `append` can never
/// produce a finding here. This replay is defence in depth for a committed or
/// restored state whose cached balances were not re-validated against its
/// entries: it recomputes each account as an `i128` running sum and reports the
/// most negative point. Only `Parent`/`Child` are tracked — there is no Equity
/// account, and boundary `Issue`/`Burn` ops are exempt from the balance equation
/// but still cannot take a `Child` negative.
fn audit_overdraw(ledgers: &LedgerSet, findings: &mut Vec<Finding>) {
    for node in ledgers.node_ids() {
        let Some(ledger) = ledgers.get(node) else {
            continue;
        };
        let mut running: BTreeMap<AccountRef, i128> = BTreeMap::new();
        let mut lowest: BTreeMap<AccountRef, i128> = BTreeMap::new();

        for index in 0..ledger.len() {
            let Ok(Some(signed)) = ledger.get(index) else {
                continue;
            };
            let Ok(deltas) = aggregate_deltas(&signed.entry.postings) else {
                continue;
            };
            for (account, delta) in deltas {
                let value = running.entry(account.clone()).or_insert(0);
                *value = value.saturating_add(delta);
                let low = lowest.entry(account).or_insert(0);
                if *value < *low {
                    *low = *value;
                }
            }
        }

        for (account, low) in lowest {
            if low < 0 {
                findings.push(Finding::Overdraw {
                    node: node.clone(),
                    account,
                    deficit: low.saturating_neg(),
                });
            }
        }
    }
}

/// Step 5: collapse gross opposing flows between the same child pair.
fn collapse_nets(ledgers: &LedgerSet) -> Vec<NetTransfer> {
    let mut nets = Vec::new();

    for parent in ledgers.node_ids() {
        let Some(ledger) = ledgers.get(parent) else {
            continue;
        };

        // Gross directed flows between child accounts of this parent, keyed by
        // (paying child, receiving child).
        let mut gross: BTreeMap<(NodeId, NodeId), i128> = BTreeMap::new();
        for index in 0..ledger.len() {
            let Ok(Some(signed)) = ledger.get(index) else {
                continue;
            };
            let EntryBody::Transfer { role, .. } = &signed.entry.body else {
                continue;
            };
            if !matches!(role, HopRole::Lca | HopRole::Direct) {
                continue;
            }
            let Ok((first, second)) = entry_hop_accounts(&signed.entry, *role) else {
                continue;
            };
            let (AccountRef::Child(from), AccountRef::Child(to)) = (first, second) else {
                continue;
            };
            let Ok(deltas) = aggregate_deltas(&signed.entry.postings) else {
                continue;
            };
            let amount = deltas
                .get(&AccountRef::Child(from.clone()))
                .map(|delta| delta.saturating_abs())
                .unwrap_or(0);
            if amount == 0 {
                continue;
            }
            let flow = gross.entry((from, to)).or_insert(0);
            *flow = flow.saturating_add(amount);
        }

        // Net each unordered pair. A positive net runs `key.0 -> key.1`.
        let mut pairs: BTreeMap<(NodeId, NodeId), i128> = BTreeMap::new();
        for ((from, to), amount) in gross {
            let key = if from <= to {
                (from.clone(), to.clone())
            } else {
                (to.clone(), from.clone())
            };
            let signed_net = if from == key.0 { amount } else { -amount };
            let net = pairs.entry(key).or_insert(0);
            *net = net.saturating_add(signed_net);
        }

        for ((a, b), net) in pairs {
            if net == 0 {
                continue;
            }
            let (from, to, amount) = if net > 0 {
                (a, b, net)
            } else {
                (b, a, net.saturating_neg())
            };
            nets.push(NetTransfer {
                parent: parent.clone(),
                from,
                to,
                amount: Amount::new(u64::try_from(amount).unwrap_or(u64::MAX)),
            });
        }
    }

    nets
}
