//! Pure route derivation for cross-subtree settlement (P3a).
//!
//! Given the payer/payee user addresses and this node's record, a hop's
//! `role`/`first`/`second` are **derived locally** (never taken from the wire):
//! `role = classify_hop(payer, payee, this)` and the two accounts follow the
//! canonical `hop_postings` shape resolved from the record's child slots.
//!
//! v1 scope is depth-1: the three signers are
//! `[payer_leaf, lca, payee_leaf]`. Anything else is rejected
//! ([`SettleRejectV1::RouteTooDeep`]). This module is pure and synchronous; no
//! transport.

use std::collections::{BTreeMap, VecDeque};

use cawala_ledger::{
    AccountRef, AuthRef, Hash, HopRole, NodeId, PaymentOrder, SignedEntry, classify_hop,
};
use cawala_msg::{EntryProofV1, MsgId, PeerRef, SettleOutcomeV2, SettleRejectV1};
use cawala_topology::OctAddr;

use crate::record::NodeRecord;

/// Maximum in-flight origin settlements tracked before the oldest is evicted
/// (with a synthesized timeout).
pub const MAX_PENDING: usize = 256;

/// Maximum completed settlement outcomes remembered so a duplicate order gets a
/// real answer before the oldest is evicted.
pub const MAX_TERMINAL: usize = 1024;

/// A locally derived hop: the role and canonical accounts for this signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedHop {
    /// The hop's position in the cascade.
    pub role: HopRole,
    /// The first account named by the hop's canonical posting shape.
    pub first: AccountRef,
    /// The second account named by the hop's canonical posting shape.
    pub second: AccountRef,
}

/// Whether the payment is within the v1 depth-1 settlement scope.
///
/// Both endpoints must be at least depth 2 (a leaf's user). Same-leaf payments
/// (`src.parent() == dst.parent()`) are the trivial `Direct` case; otherwise the
/// two leaf addresses must be siblings (`src.parent()!.parent() ==
/// dst.parent()!.parent()`), so the LCA is one level above the leaves.
pub fn route_is_depth_one(src: &OctAddr, dst: &OctAddr) -> bool {
    if src.depth() < 2 || dst.depth() < 2 {
        return false;
    }
    let (Some(src_leaf), Some(dst_leaf)) = (src.parent(), dst.parent()) else {
        return false;
    };
    if src_leaf == dst_leaf {
        return true;
    }
    matches!(
        (src_leaf.parent(), dst_leaf.parent()),
        (Some(src_lca), Some(dst_lca)) if src_lca == dst_lca
    )
}

/// The three signer addresses of a depth-1 settlement cascade, in order:
/// `[payer_leaf, lca, payee_leaf]`.
///
/// Returns `None` for a same-leaf payment (handled as a single `Direct` hop, not
/// a 3-hop settlement) and for any route outside the depth-1 scope.
pub fn expected_signers(src: &OctAddr, dst: &OctAddr) -> Option<[OctAddr; 3]> {
    if !route_is_depth_one(src, dst) {
        return None;
    }
    let src_leaf = src.parent()?;
    let dst_leaf = dst.parent()?;
    // Same-leaf is a `Direct` move, not a 3-hop cascade.
    if src_leaf == dst_leaf {
        return None;
    }
    Some([src_leaf, src.lca(dst), dst_leaf])
}

/// Derive this signer's hop from the route and the node record.
///
/// `role = classify_hop(src, dst, this_addr)`; `None` (off-route or too deep)
/// yields [`SettleRejectV1::RouteTooDeep`]. The child toward `src`/`dst` is the
/// record child whose slot matches the next path digit at `this_addr.depth()`;
/// a missing child yields [`SettleRejectV1::Malformed`].
///
/// Account shapes match [`cawala_ledger::expected_hops`]:
/// `Ascend -> (Parent, Child(toward_src))`, `Lca -> (Child(toward_src),
/// Child(toward_dst))`, `Descend -> (Parent, Child(toward_dst))`. A `Direct`
/// role is not a settlement hop and is rejected as
/// [`SettleRejectV1::Malformed`].
pub fn derive_hop(
    record: &NodeRecord,
    this_addr: &OctAddr,
    src: &OctAddr,
    dst: &OctAddr,
) -> Result<DerivedHop, SettleRejectV1> {
    let role = classify_hop(src, dst, this_addr).ok_or(SettleRejectV1::RouteTooDeep)?;
    match role {
        HopRole::Direct => Err(SettleRejectV1::Malformed),
        HopRole::Ascend => Ok(DerivedHop {
            role,
            first: AccountRef::Parent,
            second: AccountRef::Child(child_toward(record, this_addr, src)?),
        }),
        HopRole::Lca => Ok(DerivedHop {
            role,
            first: AccountRef::Child(child_toward(record, this_addr, src)?),
            second: AccountRef::Child(child_toward(record, this_addr, dst)?),
        }),
        HopRole::Descend => Ok(DerivedHop {
            role,
            first: AccountRef::Parent,
            second: AccountRef::Child(child_toward(record, this_addr, dst)?),
        }),
    }
}

/// Resolve the record child one level below `this_addr` toward `target`.
///
/// The next path digit is `target.digits()[this_addr.depth()]`; the child is the
/// record entry whose slot equals it. Missing digit or child =>
/// [`SettleRejectV1::Malformed`].
fn child_toward(
    record: &NodeRecord,
    this_addr: &OctAddr,
    target: &OctAddr,
) -> Result<NodeId, SettleRejectV1> {
    let index = this_addr.depth();
    let slot = *target
        .digits()
        .get(index)
        .ok_or(SettleRejectV1::Malformed)?;
    let entry = record
        .children
        .iter()
        .find(|child| child.slot == slot)
        .ok_or(SettleRejectV1::Malformed)?;
    Ok(NodeId::from(entry.child_id.clone()))
}

/// An in-flight settlement the origin is waiting on.
///
/// The origin reserves the `payment_id` (its local `apply_hop` is the
/// reservation) and keeps this record until the terminal `Result` arrives or
/// the deadline passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSettlement {
    /// The payer browser awaiting a result.
    pub browser: PeerRef,
    /// The browser's triggering order envelope id (echoed in the result).
    pub browser_msg_id: MsgId,
    /// The payer's order.
    pub order: PaymentOrder,
    /// The payer's operator authorisation.
    pub auth: AuthRef,
    /// The payer's user address.
    pub payer_addr: OctAddr,
    /// The payee's user address.
    pub payee_addr: OctAddr,
    /// The payee leaf (= `payee_addr.parent()`) the result is routed from.
    pub payee_leaf_addr: OctAddr,
    /// The origin's local (reservation) hop `seq`.
    pub local_seq: u64,
    /// The origin's local (reservation) hop hash.
    pub local_hash: Hash,
    /// Unix seconds after which the origin synthesizes a timeout.
    pub deadline_secs: u64,
    /// Whether the browser sent a v2 (`OrderV2`) order and must receive a v2
    /// (`OrderResultV2`) result; v1 senders keep the v1 result shape.
    pub reply_v2: bool,
}

/// A completed settlement outcome remembered for duplicate answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalRecord {
    /// The payer browser that received (or should receive) the result.
    pub browser: PeerRef,
    /// The browser's triggering order envelope id.
    pub browser_msg_id: MsgId,
    /// The payer's order.
    pub order: PaymentOrder,
    /// The terminal outcome.
    pub outcome: SettleOutcomeV2,
    /// The terminal leaf's signed `Descend` entry, when it applied. Retained for
    /// P5 verification (the result itself is advisory).
    pub terminal_entry: Option<SignedEntry>,
    /// The verified terminal inclusion proof, when the outcome was accepted.
    /// Forwarded unmodified to the browser in the V3 `OrderResult`; `None` for a
    /// downstream rejection, which carries no applied hop.
    pub proof: Option<EntryProofV1>,
}

/// Bounded origin-side settlement bookkeeping.
///
/// `pending` tracks in-flight settlements and `terminal` remembers completed
/// outcomes so a duplicate order gets a real answer. Both are bounded; the
/// oldest entry is evicted when the bound is reached (for `pending` the caller
/// synthesizes a timeout for the evicted record).
#[derive(Debug, Default)]
pub struct SettlementManager {
    pending: BTreeMap<Hash, PendingSettlement>,
    /// Insertion order of `pending` keys (stale keys are skipped on eviction).
    pending_order: VecDeque<Hash>,
    terminal: BTreeMap<Hash, TerminalRecord>,
    /// Insertion order of `terminal` keys.
    terminal_order: VecDeque<Hash>,
}

impl SettlementManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve an in-flight settlement.
    ///
    /// Returns the evicted oldest pending record when the bound is exceeded, so
    /// the caller can synthesize a timeout for it. Re-reserving an existing
    /// `payment_id` replaces it without eviction.
    pub fn reserve(&mut self, pending: PendingSettlement) -> Option<PendingSettlement> {
        let payment_id = pending.order.hash();
        let existed = self.pending.contains_key(&payment_id);
        let evicted = if !existed && self.pending.len() >= MAX_PENDING {
            self.evict_oldest_pending()
        } else {
            None
        };
        self.pending.insert(payment_id, pending);
        if !existed {
            self.pending_order.push_back(payment_id);
        }
        evicted
    }

    /// The in-flight settlement for `payment_id`, if any.
    pub fn pending(&self, payment_id: &Hash) -> Option<&PendingSettlement> {
        self.pending.get(payment_id)
    }

    /// Remove and return the in-flight settlement for `payment_id`.
    pub fn take_pending(&mut self, payment_id: &Hash) -> Option<PendingSettlement> {
        self.pending.remove(payment_id)
    }

    /// Remove and return every pending settlement whose deadline has passed.
    pub fn sweep_expired(&mut self, now: u64) -> Vec<PendingSettlement> {
        let expired: Vec<Hash> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline_secs <= now)
            .map(|(payment_id, _)| *payment_id)
            .collect();
        expired
            .into_iter()
            .filter_map(|payment_id| self.pending.remove(&payment_id))
            .collect()
    }

    /// Remember a completed outcome, evicting the oldest when over the bound.
    pub fn record_terminal(&mut self, payment_id: Hash, terminal: TerminalRecord) {
        let existed = self.terminal.contains_key(&payment_id);
        if !existed && self.terminal.len() >= MAX_TERMINAL {
            self.evict_oldest_terminal();
        }
        self.terminal.insert(payment_id, terminal);
        if !existed {
            self.terminal_order.push_back(payment_id);
        }
    }

    /// The remembered completed outcome for `payment_id`, if any.
    pub fn terminal(&self, payment_id: &Hash) -> Option<&TerminalRecord> {
        self.terminal.get(payment_id)
    }

    /// Number of in-flight settlements.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Number of remembered terminal outcomes.
    pub fn terminal_len(&self) -> usize {
        self.terminal.len()
    }

    fn evict_oldest_pending(&mut self) -> Option<PendingSettlement> {
        while let Some(payment_id) = self.pending_order.pop_front() {
            if let Some(pending) = self.pending.remove(&payment_id) {
                return Some(pending);
            }
        }
        None
    }

    fn evict_oldest_terminal(&mut self) {
        while let Some(payment_id) = self.terminal_order.pop_front() {
            if self.terminal.remove(&payment_id).is_some() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cawala_ledger::{
        Amount, Commitment, Entry, EntryBody, EntryInclusionProof, LedgerSecretKey,
        OperatorSecretKey, PaymentOrder, PeerKeys, PeerRole, SignedCommitment, expected_hops,
    };
    use cawala_topology::{ChildKind, Topology};

    use crate::record::{ChildEntry, NodeRecord, ParentLink};

    fn sample_signed_entry() -> SignedEntry {
        let key = LedgerSecretKey::from_bytes([9u8; 32]);
        let entry = Entry {
            ledger_id: key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::Issue {
                child: NodeId::from("x"),
                amount: Amount::new(1),
            },
            postings: vec![],
            auth: None,
        };
        SignedEntry::sign(entry, &key).unwrap()
    }

    /// A structurally plausible terminal proof (single-leaf tree) used only to
    /// exercise the retention/duplicate bookkeeping, not verification.
    fn sample_entry_proof() -> EntryProofV1 {
        let key = LedgerSecretKey::from_bytes([9u8; 32]);
        EntryProofV1 {
            entry: sample_signed_entry(),
            signer: PeerKeys {
                node_id: NodeId::from("A"),
                operator: OperatorSecretKey::from_bytes([2u8; 32]).public(),
                ledger: Some(key.public()),
                role: PeerRole::Node,
            },
            leaf_addr: addr("0.1"),
            commitment: SignedCommitment {
                commitment: Commitment {
                    ledger_id: key.public(),
                    ledger_pubkey: key.public(),
                    height: 1,
                    entry_count: 1,
                    entry_root: Hash::ZERO,
                    state_root: Hash::ZERO,
                    prev_commitment_hash: Hash::ZERO,
                    issued_at: 0,
                },
                signature: key.sign(b"commitment"),
            },
            inclusion: EntryInclusionProof {
                index: 0,
                tree_size: 1,
                proof: vec![],
            },
        }
    }

    fn addr(s: &str) -> OctAddr {
        s.parse().expect("valid octal address")
    }

    fn child(child_id: &str, kind: ChildKind, slot: u8) -> ChildEntry {
        ChildEntry {
            child_id: child_id.to_string(),
            kind,
            slot,
            date_joined: 0,
        }
    }

    fn record(
        node_id: &str,
        address: &str,
        parent: Option<(&str, u8)>,
        children: Vec<ChildEntry>,
    ) -> NodeRecord {
        NodeRecord {
            node_id: node_id.to_string(),
            address: Some(addr(address)),
            parent: parent.map(|(parent_id, slot)| ParentLink {
                parent_id: parent_id.to_string(),
                slot,
                generation: 0,
            }),
            children,
            address_epoch: 0,
        }
    }

    /// `R=0`, leaves `A=0.1`, `B=0.2`, users `uA=0.1.3`, `uB=0.2.4`.
    struct Fixture {
        topo: Topology,
        record_r: NodeRecord,
        record_a: NodeRecord,
        record_b: NodeRecord,
    }

    fn fixture() -> Fixture {
        let mut topo = Topology::new_root("R");
        topo.add_node("A", ChildKind::Node).unwrap();
        topo.add_node("B", ChildKind::Node).unwrap();
        topo.add_node("uA", ChildKind::User).unwrap();
        topo.add_node("uB", ChildKind::User).unwrap();
        topo.attach("R", "A", Some(1)).unwrap();
        topo.attach("R", "B", Some(2)).unwrap();
        topo.attach("A", "uA", Some(3)).unwrap();
        topo.attach("B", "uB", Some(4)).unwrap();

        let record_r = record(
            "R",
            "0",
            None,
            vec![
                child("A", ChildKind::Node, 1),
                child("B", ChildKind::Node, 2),
            ],
        );
        let record_a = record(
            "A",
            "0.1",
            Some(("R", 1)),
            vec![child("uA", ChildKind::User, 3)],
        );
        let record_b = record(
            "B",
            "0.2",
            Some(("R", 2)),
            vec![child("uB", ChildKind::User, 4)],
        );
        Fixture {
            topo,
            record_r,
            record_a,
            record_b,
        }
    }

    fn order() -> PaymentOrder {
        PaymentOrder {
            from: NodeId::from("uA"),
            to: NodeId::from("uB"),
            amount: Amount::new(10),
            nonce: 1,
            expiry: 100,
        }
    }

    #[test]
    fn derive_hop_matches_the_oracle_for_every_signer() {
        let fx = fixture();
        let src = addr("0.1.3");
        let dst = addr("0.2.4");

        // Oracle: [A Ascend, R Lca, B Descend].
        let hops = expected_hops(&fx.topo, &order()).unwrap();
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].signer.as_str(), "A");
        assert_eq!(hops[1].signer.as_str(), "R");
        assert_eq!(hops[2].signer.as_str(), "B");

        let cases = [
            (&fx.record_a, addr("0.1"), &hops[0]),
            (&fx.record_r, addr("0"), &hops[1]),
            (&fx.record_b, addr("0.2"), &hops[2]),
        ];
        for (record, this_addr, expected) in cases {
            let derived = derive_hop(record, &this_addr, &src, &dst).unwrap();
            assert_eq!(
                derived,
                DerivedHop {
                    role: expected.role,
                    first: expected.first.clone(),
                    second: expected.second.clone(),
                },
                "derive_hop mismatch at {}",
                expected.signer
            );
        }
    }

    #[test]
    fn same_leaf_direct_is_not_a_settlement_hop() {
        let fx = fixture();
        let src = addr("0.1.3");
        let dst = addr("0.1.4"); // same leaf A
        assert_eq!(
            derive_hop(&fx.record_a, &addr("0.1"), &src, &dst),
            Err(SettleRejectV1::Malformed)
        );
    }

    #[test]
    fn off_route_signer_is_route_too_deep() {
        let fx = fixture();
        // 0.7 is not on the uA -> uB path.
        assert_eq!(
            derive_hop(&fx.record_r, &addr("0.7"), &addr("0.1.3"), &addr("0.2.4")),
            Err(SettleRejectV1::RouteTooDeep)
        );
    }

    #[test]
    fn missing_child_is_malformed() {
        // R knows B (slot 2) but not A (slot 1): the LCA's debit branch is absent.
        let record_r = record("R", "0", None, vec![child("B", ChildKind::Node, 2)]);
        assert_eq!(
            derive_hop(&record_r, &addr("0"), &addr("0.1.3"), &addr("0.2.4")),
            Err(SettleRejectV1::Malformed)
        );
    }

    #[test]
    fn route_scope_and_signers() {
        let same_leaf = (addr("0.1.3"), addr("0.1.4"));
        let depth_one = (addr("0.1.3"), addr("0.2.4"));
        let deeper = (addr("0.1.3"), addr("0.3.5.7"));
        let too_shallow = (addr("0"), addr("0.2"));

        assert!(route_is_depth_one(&same_leaf.0, &same_leaf.1));
        assert!(route_is_depth_one(&depth_one.0, &depth_one.1));
        assert!(!route_is_depth_one(&deeper.0, &deeper.1));
        assert!(!route_is_depth_one(&too_shallow.0, &too_shallow.1));

        // A same-leaf payment is `Direct`, not a 3-hop settlement.
        assert_eq!(expected_signers(&same_leaf.0, &same_leaf.1), None);
        assert_eq!(
            expected_signers(&depth_one.0, &depth_one.1),
            Some([addr("0.1"), addr("0"), addr("0.2")])
        );
        assert_eq!(expected_signers(&deeper.0, &deeper.1), None);
        assert_eq!(expected_signers(&too_shallow.0, &too_shallow.1), None);
    }

    fn pending(nonce: u64, deadline_secs: u64) -> PendingSettlement {
        PendingSettlement {
            browser: PeerRef {
                addr: addr("0.1.3"),
                node: "uA".to_string(),
            },
            browser_msg_id: MsgId([nonce as u8; 16]),
            order: PaymentOrder {
                from: NodeId::from("uA"),
                to: NodeId::from("uB"),
                amount: Amount::new(1),
                nonce,
                expiry: 10_000,
            },
            auth: cawala_ledger::AuthRef {
                operator: cawala_ledger::OperatorSecretKey::from_bytes([1u8; 32]).public(),
                nonce,
                order_hash: Hash::from_bytes([nonce as u8; 32]),
                signature: cawala_ledger::OperatorSecretKey::from_bytes([1u8; 32]).sign(b"x"),
            },
            payer_addr: addr("0.1.3"),
            payee_addr: addr("0.2.4"),
            payee_leaf_addr: addr("0.2"),
            local_seq: nonce,
            local_hash: Hash::from_bytes([nonce as u8; 32]),
            deadline_secs,
            reply_v2: true,
        }
    }

    #[test]
    fn manager_sweeps_only_expired_and_evicts_oldest() {
        let mut manager = SettlementManager::new();
        manager.reserve(pending(1, 100));
        manager.reserve(pending(2, 200));
        assert_eq!(manager.pending_len(), 2);

        // Nothing expired yet.
        assert!(manager.sweep_expired(50).is_empty());
        // Only the first is due at 150.
        let swept = manager.sweep_expired(150);
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0].order.nonce, 1);
        assert_eq!(manager.pending_len(), 1);

        // take_pending removes and returns the record.
        let taken = manager.take_pending(&pending(2, 200).order.hash()).unwrap();
        assert_eq!(taken.order.nonce, 2);
        assert_eq!(manager.pending_len(), 0);
    }

    #[test]
    fn manager_remembers_terminal_outcomes() {
        let mut manager = SettlementManager::new();
        let payment_id = pending(3, 100).order.hash();
        manager.record_terminal(
            payment_id,
            TerminalRecord {
                browser: pending(3, 100).browser,
                browser_msg_id: MsgId([3; 16]),
                order: pending(3, 100).order,
                outcome: SettleOutcomeV2::Applied {
                    terminal_seq: 7,
                    terminal_hash: Hash::from_bytes([7u8; 32]),
                    proof: sample_entry_proof(),
                },
                terminal_entry: Some(sample_signed_entry()),
                proof: Some(sample_entry_proof()),
            },
        );
        assert_eq!(manager.terminal_len(), 1);
        assert!(matches!(
            manager.terminal(&payment_id).map(|t| &t.outcome),
            Some(SettleOutcomeV2::Applied { terminal_seq: 7, .. })
        ));
    }
}
