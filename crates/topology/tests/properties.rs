//! Property-based tests for the topology crate.
//!
//! - `validate_holds_through_random_ops`: after every op (valid or rejected),
//!   the topology satisfies every invariant.
//! - `cross_region_moves_are_rejected`: illegal cross-region moves are rejected.
//! - `routing_reaches_the_holding_node`: descending from the root via the
//!   address digits reaches exactly the node that holds that address.
//! - `addresses_stay_consistent_after_moves`: address = parent address + slot
//!   after every valid move/attach/detach.

use std::collections::HashSet;

use cawala_topology::{ChildKind, Topology, TopologyError};
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

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            Some(&items[self.range(0, items.len())])
        }
    }
}

fn ids(t: &Topology) -> Vec<String> {
    t.node_ids().cloned().collect()
}

fn unattached_ids(t: &Topology) -> Vec<String> {
    ids(t)
        .into_iter()
        .filter(|id| id != t.root_id() && t.parent_of(id).ok().flatten().is_none())
        .collect()
}

fn attached_ids(t: &Topology) -> Vec<String> {
    ids(t)
        .into_iter()
        .filter(|id| t.parent_of(id).ok().flatten().is_some())
        .collect()
}

/// All descendants of `root_id`, exclusive, breadth-first.
fn descendants(t: &Topology, root_id: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![root_id.to_string()];
    while let Some(id) = stack.pop() {
        if let Ok(children) = t.children_of(&id) {
            for c in children {
                if seen.insert(c.child_id.clone()) {
                    out.push(c.child_id.clone());
                    stack.push(c.child_id);
                }
            }
        }
    }
    out
}

fn is_node_kind(t: &Topology, id: &str) -> bool {
    matches!(t.node(id).map(|r| r.kind), Some(ChildKind::Node))
}

fn has_free_slot(t: &Topology, id: &str) -> bool {
    t.children_of(id).map(|c| c.len() < 8).unwrap_or(false)
}

/// Legal downward-only move targets for `child_id`: its current parent or a
/// descendant of it, excluding the child's own subtree, restricted to
/// Node-kind parents with a free slot.
fn legal_move_targets(t: &Topology, child_id: &str) -> Vec<String> {
    let old_parent = t.parent_of(child_id).unwrap().unwrap().to_string();
    let mut targets = vec![old_parent.clone()];
    targets.extend(descendants(t, &old_parent));
    let child_subtree: HashSet<String> = descendants(t, child_id)
        .into_iter()
        .chain(std::iter::once(child_id.to_string()))
        .collect();
    targets.retain(|x| !child_subtree.contains(x));
    targets.retain(|x| is_node_kind(t, x));
    targets.retain(|x| has_free_slot(t, x));
    targets
}

/// Node-kind nodes outside `child_id`'s current parent's subtree: any move to
/// these violates the downward-only rule.
fn illegal_move_targets(t: &Topology, child_id: &str) -> Vec<String> {
    let old_parent = t.parent_of(child_id).unwrap().unwrap().to_string();
    let allowed: HashSet<String> = std::iter::once(old_parent.clone())
        .chain(descendants(t, &old_parent))
        .collect();
    ids(t)
        .into_iter()
        .filter(|x| !allowed.contains(x))
        .filter(|x| is_node_kind(t, x))
        .collect()
}

/// Free octal slots under `parent_id`.
fn free_slots(t: &Topology, parent_id: &str) -> Vec<u8> {
    let occupied: HashSet<u8> = t
        .children_of(parent_id)
        .map(|c| c.into_iter().map(|c| c.slot).collect())
        .unwrap_or_default();
    (0..=7).filter(|s| !occupied.contains(s)).collect()
}

/// Whether `ancestor` is an ancestor of `node` (walking parent links).
fn is_ancestor_of(t: &Topology, ancestor: &str, node: &str) -> bool {
    let mut cur = node;
    loop {
        if cur == ancestor {
            return true;
        }
        match t.parent_of(cur).ok().flatten() {
            Some(p) => cur = p,
            None => return false,
        }
    }
}

#[derive(Debug, Clone)]
enum Op {
    Add(String, ChildKind),
    Attach {
        parent: String,
        child: String,
        slot: Option<u8>,
    },
    Detach(String),
    Move {
        child: String,
        new_parent: String,
        slot: Option<u8>,
    },
    Remove(String),
}

impl Op {
    fn apply(self, t: &mut Topology) -> Result<(), TopologyError> {
        match self {
            Op::Add(id, kind) => t.add_node(id, kind),
            Op::Attach { parent, child, slot } => t.attach(&parent, &child, slot),
            Op::Detach(id) => t.detach(&id),
            Op::Move { child, new_parent, slot } => t.move_child(&child, &new_parent, slot),
            Op::Remove(id) => t.remove_node(&id),
        }
    }
}

/// What the caller expects from applying the op.
#[derive(Debug, Clone, Copy)]
enum Check {
    /// Must succeed.
    Ok,
    /// Must fail with some error (the tree stays valid).
    Err,
    /// Must fail specifically as a cross-region move.
    CrossRegion,
}

/// Generate one op against the current state. Legal ops are legal *by
/// construction* (downward-only targets, unattached children, Node-kind
/// parents, free or deliberately-conflicting slots).
fn gen_op(rng: &mut Rng, t: &Topology, counter: &mut usize) -> (Op, Check) {
    let all = ids(t);
    let attached = attached_ids(t);
    let unattached = unattached_ids(t);
    let roll = rng.range(0, 100);

    // Fresh id for add fallbacks.
    macro_rules! fresh_add {
        () => {{
            *counter += 1;
            (Op::Add(format!("n{counter}"), ChildKind::Node), Check::Ok)
        }};
    }

    match roll {
        // 0..=24: add_node, always valid with a fresh id.
        0..=24 => {
            *counter += 1;
            let kind = if rng.chance(30) {
                ChildKind::User
            } else {
                ChildKind::Node
            };
            (Op::Add(format!("n{counter}"), kind), Check::Ok)
        }
        // 25..=44: attach an unattached child under a Node-kind parent with a
        // free slot. 30% of the time request an already-taken slot (invalid).
        25..=44 => {
            let parents: Vec<String> = all
                .iter()
                .filter(|id| is_node_kind(t, id) && has_free_slot(t, id))
                .cloned()
                .collect();
            let Some(parent) = rng.pick(&parents) else {
                return fresh_add!();
            };
            // The unattached child must not be an ancestor of the parent
            // (attaching it would be a cycle).
            let compatible: Vec<String> = unattached
                .iter()
                .filter(|child| !is_ancestor_of(t, child, &parent))
                .cloned()
                .collect();
            let Some(child) = rng.pick(&compatible) else {
                return fresh_add!();
            };
            let taken: Vec<u8> = t
                .children_of(parent)
                .unwrap()
                .into_iter()
                .map(|c| c.slot)
                .collect();
            let slot = if rng.chance(70) || taken.is_empty() {
                None
            } else {
                Some(taken[rng.range(0, taken.len())]) // guaranteed conflict
            };
            let check = if slot.is_none() { Check::Ok } else { Check::Err };
            (
                Op::Attach {
                    parent: parent.clone(),
                    child: child.clone(),
                    slot,
                },
                check,
            )
        }
        // 45..=59: detach an attached non-root node (always valid).
        45..=59 => {
            let detachable: Vec<String> = attached
                .iter()
                .filter(|id| id.as_str() != t.root_id())
                .cloned()
                .collect();
            if let Some(child) = rng.pick(&detachable) {
                (Op::Detach(child.clone()), Check::Ok)
            } else {
                fresh_add!()
            }
        }
        // 60..=84: move. Legal downward-only targets, but 20% of the time
        // deliberately attempt an illegal cross-region move.
        60..=84 => {
            let movable: Vec<String> = attached
                .iter()
                .filter(|id| id.as_str() != t.root_id())
                .cloned()
                .collect();
            let Some(child) = rng.pick(&movable) else {
                return fresh_add!();
            };
            let legal = legal_move_targets(t, child);
            let illegal = illegal_move_targets(t, child);
            if rng.chance(20) && !illegal.is_empty() {
                let target = illegal[rng.range(0, illegal.len())].clone();
                let slot = if rng.chance(50) {
                    None
                } else {
                    Some(rng.range(0, 8) as u8)
                };
                (
                    Op::Move {
                        child: child.clone(),
                        new_parent: target,
                        slot,
                    },
                    Check::CrossRegion,
                )
            } else if !legal.is_empty() {
                let target = legal[rng.range(0, legal.len())].clone();
                let free = free_slots(t, &target);
                let slot = if rng.chance(70) {
                    None
                } else {
                    free.first().copied()
                };
                (
                    Op::Move {
                        child: child.clone(),
                        new_parent: target,
                        slot,
                    },
                    Check::Ok,
                )
            } else {
                fresh_add!()
            }
        }
        // 85..=99: remove a childless non-root node (always valid).
        _ => {
            let removable: Vec<String> = all
                .iter()
                .filter(|id| {
                    id.as_str() != t.root_id()
                        && t.children_of(id).map(|c| c.is_empty()).unwrap_or(false)
                })
                .cloned()
                .collect();
            if let Some(id) = rng.pick(&removable) {
                (Op::Remove(id.clone()), Check::Ok)
            } else {
                fresh_add!()
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// (a) After every op — valid or rejected — the topology satisfies every
    /// invariant. Legal ops succeed; deliberately-invalid ops fail without
    /// corrupting the tree.
    #[test]
    fn validate_holds_through_random_ops(seed in any::<u64>(), steps in 1usize..=80) {
        let mut rng = Rng::new(seed);
        let mut t = Topology::new_root("root");
        let mut counter = 0usize;
        for _ in 0..steps {
            let (op, check) = gen_op(&mut rng, &t, &mut counter);
            let res = op.clone().apply(&mut t);
            match check {
                Check::Ok => assert!(res.is_ok(), "op {op:?} should succeed, got {res:?}"),
                Check::Err => assert!(res.is_err(), "op {op:?} should fail, but succeeded"),
                Check::CrossRegion => assert!(
                    matches!(res, Err(TopologyError::CrossRegionMove { .. })),
                    "op {op:?} should be a CrossRegionMove, got {res:?}"
                ),
            }
            if let Err(e) = t.validate() {
                panic!(
                    "validate must pass after op {op:?}, even when the op failed; got: {e}"
                );
            }
        }
    }

    /// (b) Every cross-region move attempt on a built tree is rejected.
    #[test]
    fn cross_region_moves_are_rejected(seed in any::<u64>(), steps in 3usize..=60) {
        let mut rng = Rng::new(seed);
        let mut t = Topology::new_root("root");
        let mut counter = 0usize;
        for _ in 0..steps {
            let (op, _check) = gen_op(&mut rng, &t, &mut counter);
            let _ = op.apply(&mut t);
        }
        assert!(t.validate().is_ok());
        for child in attached_ids(&t) {
            for target in illegal_move_targets(&t, &child) {
                assert!(
                    matches!(
                        t.move_child(&child, &target, None),
                        Err(TopologyError::CrossRegionMove { .. })
                    ),
                    "moving {child} to {target} must be rejected as cross-region"
                );
            }
        }
    }

    /// (c) Routing: descending from the root via the child whose slot equals
    /// the next address digit always reaches exactly the node holding that
    /// address.
    #[test]
    fn routing_reaches_the_holding_node(seed in any::<u64>(), steps in 1usize..=60) {
        let mut rng = Rng::new(seed);
        let mut t = Topology::new_root("root");
        let mut counter = 0usize;
        for _ in 0..steps {
            let (op, _check) = gen_op(&mut rng, &t, &mut counter);
            let _ = op.apply(&mut t);
            assert!(t.validate().is_ok());
        }
        let connected: Vec<String> = ids(&t)
            .into_iter()
            .filter(|id| t.address_of(id).is_ok())
            .collect();
        if connected.is_empty() {
            return Ok(());
        }
        let target = connected[rng.range(0, connected.len())].clone();
        let addr = t.address_of(&target).unwrap();
        let mut cur = t.root_id().to_string();
        for &d in &addr.digits()[1..] {
            let children = t.children_of(&cur).unwrap();
            let next = children
                .iter()
                .find(|c| c.slot == d)
                .unwrap_or_else(|| panic!("no child at slot {d} under {cur} while routing to {addr}"));
            cur = next.child_id.clone();
        }
        assert_eq!(cur, target, "routing along {addr} must land on {target}");
    }

    /// (d) Address derivation stays consistent: every root-connected node's
    /// address equals its parent's address extended by its slot, and the root
    /// is always "0".
    #[test]
    fn addresses_stay_consistent_after_moves(seed in any::<u64>(), steps in 1usize..=60) {
        let mut rng = Rng::new(seed);
        let mut t = Topology::new_root("root");
        let mut counter = 0usize;
        for _ in 0..steps {
            let (op, _check) = gen_op(&mut rng, &t, &mut counter);
            let _ = op.apply(&mut t);
            assert!(t.validate().is_ok());
            assert_eq!(t.address_of(t.root_id()).unwrap().to_string(), "0");
            for id in attached_ids(&t) {
                // skip floating islands: they have no derived address
                if t.address_of(&id).is_err() {
                    continue;
                }
                let parent = t.parent_of(&id).unwrap().unwrap().to_string();
                let slot = t.node(&id).unwrap().slot.unwrap();
                let addr = t.address_of(&id).unwrap();
                assert_eq!(
                    addr,
                    t.address_of(&parent).unwrap().child(slot),
                    "address inconsistency for {id}"
                );
            }
        }
    }
}

