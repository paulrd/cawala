//! Hierarchical routing over [`OctAddr`] and hop-chain validation.
//!
//! A [`Routable`] is an immutable snapshot of one node's view: itself, its
//! optional parent, and its direct children. [`next_step`] answers "one step
//! from `from` toward `dst`", and [`route`] maps a destination to a local
//! decision. Addresses encode containment, so the path is deterministic and
//! needs no routing table.
//!
//! Trust boundary: addresses and hop chains are *not* authenticated. A relay
//! can forge a plausible chain; [`validate_hop_chain`] only rejects
//! structurally impossible paths, it does not prove provenance.

use serde::{Deserialize, Serialize};

use crate::MAX_HOPS;
use crate::envelope::{Envelope, Hop, PeerRef};
use proto::OctAddr;

/// What a direct neighbor is: another routing node, or a terminal user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NeighborKind {
    Node,
    User,
}

/// A direct neighbor of a [`Routable`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Neighbor {
    pub addr: OctAddr,
    pub node: String,
    pub kind: NeighborKind,
}

/// Immutable routing snapshot: self, optional parent, direct children (node or
/// user), sorted by addr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routable {
    pub this: PeerRef,
    pub parent: Option<Neighbor>,
    pub children: Vec<Neighbor>,
}

/// One step toward a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Up(OctAddr),
    Down(OctAddr),
}

/// One step from `from` toward `dst`.
///
/// - `from == dst` -> `None` (already there);
/// - `from` is a strict ancestor of `dst` -> descend into the child on `dst`'s
///   path;
/// - otherwise -> ascend to `from`'s parent, or `None` at the root.
pub fn next_step(from: &OctAddr, dst: &OctAddr) -> Option<Step> {
    if from == dst {
        return None;
    }
    if from.is_ancestor_of(dst) {
        let slot = dst.digits()[from.depth()];
        Some(Step::Down(from.child(slot)))
    } else {
        from.parent().map(Step::Up)
    }
}

/// The routing outcome for a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision<'a> {
    /// Destination is this node.
    Local,
    /// Hand the message to this direct neighbor.
    Forward(&'a Neighbor),
    /// No path: drop with this reason.
    Drop(RouteError),
}

/// Route `dst` from an immutable [`Routable`] snapshot.
///
/// Descends if `dst` is in this node's subtree (rejecting a user child that
/// has no descendants), otherwise ascends to the parent, or drops at a root
/// that cannot reach the destination.
pub fn route<'a>(routable: &'a Routable, dst: &OctAddr) -> RouteDecision<'a> {
    let this = &routable.this.addr;
    if dst == this {
        return RouteDecision::Local;
    }
    if this.is_ancestor_of(dst) {
        let slot = dst.digits()[this.depth()];
        let child = routable
            .children
            .iter()
            .find(|n| n.addr.slot() == Some(slot) && n.addr.parent().as_ref() == Some(this));
        match child {
            None => RouteDecision::Drop(RouteError::NoSuchChild {
                at: this.clone(),
                slot,
            }),
            Some(n) if n.kind == NeighborKind::User && dst.depth() != this.depth() + 1 => {
                RouteDecision::Drop(RouteError::UserHasNoDescendants { at: n.addr.clone() })
            }
            Some(n) => RouteDecision::Forward(n),
        }
    } else {
        match &routable.parent {
            Some(p) => RouteDecision::Forward(p),
            None => RouteDecision::Drop(RouteError::RootCannotRoute { dst: dst.clone() }),
        }
    }
}

/// Why `route` dropped a message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    #[error("no child in slot {slot} of {at}")]
    NoSuchChild { at: OctAddr, slot: u8 },
    #[error("{at} is a user address and has no descendants")]
    UserHasNoDescendants { at: OctAddr },
    #[error("root cannot route {dst}: no parent and not in subtree")]
    RootCannotRoute { dst: OctAddr },
}

/// Why a hop chain is structurally invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HopChainError {
    #[error("hop chain is empty")]
    Empty,
    #[error("hop chain has {len} hops, max {max}")]
    TooLong { len: usize, max: usize },
    #[error("hop chain starts at {found}, expected origin {expected}")]
    OriginMismatch { expected: OctAddr, found: OctAddr },
    #[error("hop chain starts at node '{found}', expected origin node '{expected}'")]
    OriginNodeMismatch { expected: String, found: String },
    #[error("hop {index}: {from} -> {to} is not the next step toward {dst}")]
    NotOnPath {
        index: usize,
        from: OctAddr,
        to: OctAddr,
        dst: OctAddr,
    },
    #[error("node '{0}' repeats in the hop chain")]
    RepeatedNode(String),
    #[error("address {0} repeats in the hop chain")]
    RepeatedAddress(OctAddr),
}

/// Validate that `hops` is a structurally plausible path from `src` toward
/// `dst`.
///
/// Rejects empty and over-long chains, a chain not starting at `src`, repeated
/// nodes or addresses, and any consecutive pair that is not the exact
/// `next_step` toward `dst`. This is a shape check only: it does not
/// authenticate the recorded nodes.
pub fn validate_hop_chain(src: &OctAddr, dst: &OctAddr, hops: &[Hop]) -> Result<(), HopChainError> {
    if hops.is_empty() {
        return Err(HopChainError::Empty);
    }
    if hops.len() > MAX_HOPS {
        return Err(HopChainError::TooLong {
            len: hops.len(),
            max: MAX_HOPS,
        });
    }
    if hops[0].addr != *src {
        return Err(HopChainError::OriginMismatch {
            expected: src.clone(),
            found: hops[0].addr.clone(),
        });
    }

    let mut nodes: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut addrs: std::collections::HashSet<&OctAddr> = std::collections::HashSet::new();
    for hop in hops {
        if !nodes.insert(hop.node.as_str()) {
            return Err(HopChainError::RepeatedNode(hop.node.clone()));
        }
        if !addrs.insert(&hop.addr) {
            return Err(HopChainError::RepeatedAddress(hop.addr.clone()));
        }
    }

    for (index, pair) in hops.windows(2).enumerate() {
        let (from, to) = (&pair[0], &pair[1]);
        let ok = match next_step(&from.addr, dst) {
            Some(Step::Up(a)) | Some(Step::Down(a)) => a == to.addr,
            None => false,
        };
        if !ok {
            return Err(HopChainError::NotOnPath {
                index,
                from: from.addr.clone(),
                to: to.addr.clone(),
                dst: dst.clone(),
            });
        }
    }
    Ok(())
}

/// Append `this` to `env.hop_chain`.
///
/// Checks room (`hop_chain.len() < MAX_HOPS`), rejects repeated nodes and
/// addresses, and requires `this` to be exactly `next_step(last, env.dst)`.
/// The envelope is left unchanged on error.
pub fn append_hop(env: &mut Envelope, this: &PeerRef) -> Result<(), HopChainError> {
    if env.hop_chain.len() >= MAX_HOPS {
        return Err(HopChainError::TooLong {
            len: env.hop_chain.len(),
            max: MAX_HOPS,
        });
    }
    if env.hop_chain.iter().any(|h| h.node == this.node) {
        return Err(HopChainError::RepeatedNode(this.node.clone()));
    }
    if env.hop_chain.iter().any(|h| h.addr == this.addr) {
        return Err(HopChainError::RepeatedAddress(this.addr.clone()));
    }
    let last = env.hop_chain.last().ok_or(HopChainError::Empty)?;
    let index = env.hop_chain.len() - 1;
    let ok = match next_step(&last.addr, &env.dst) {
        Some(Step::Up(a)) | Some(Step::Down(a)) => a == this.addr,
        None => false,
    };
    if !ok {
        return Err(HopChainError::NotOnPath {
            index,
            from: last.addr.clone(),
            to: this.addr.clone(),
            dst: env.dst.clone(),
        });
    }
    env.hop_chain.push(Hop {
        addr: this.addr.clone(),
        node: this.node.clone(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> OctAddr {
        s.parse()
            .unwrap_or_else(|e| panic!("parse of {s:?} failed: {e}"))
    }

    fn peer(a: &str, node: &str) -> PeerRef {
        PeerRef {
            addr: addr(a),
            node: node.to_string(),
        }
    }

    fn neighbor(a: &str, node: &str, kind: NeighborKind) -> Neighbor {
        Neighbor {
            addr: addr(a),
            node: node.to_string(),
            kind,
        }
    }

    fn hop(a: &str, node: &str) -> Hop {
        Hop {
            addr: addr(a),
            node: node.to_string(),
        }
    }

    fn routable(this: &str, parent: Option<Neighbor>, children: Vec<Neighbor>) -> Routable {
        Routable {
            this: peer(this, "me"),
            parent,
            children,
        }
    }

    #[test]
    fn route_local_when_dst_is_self() {
        let r = routable("0.3", None, vec![]);
        assert_eq!(route(&r, &addr("0.3")), RouteDecision::Local);
    }

    #[test]
    fn route_down_to_node_child() {
        let r = routable(
            "0.3",
            None,
            vec![neighbor("0.3.5", "kid", NeighborKind::Node)],
        );
        match route(&r, &addr("0.3.5")) {
            RouteDecision::Forward(n) => assert_eq!(n.addr, addr("0.3.5")),
            other => panic!("expected Forward, got {other:?}"),
        }
        // A deeper destination also goes via the same child.
        match route(&r, &addr("0.3.5.2")) {
            RouteDecision::Forward(n) => assert_eq!(n.addr, addr("0.3.5")),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn route_down_to_user_child() {
        let r = routable(
            "0.3",
            None,
            vec![neighbor("0.3.5", "user", NeighborKind::User)],
        );
        match route(&r, &addr("0.3.5")) {
            RouteDecision::Forward(n) => assert_eq!(n.addr, addr("0.3.5")),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn route_user_child_has_no_descendants() {
        let r = routable(
            "0.3",
            None,
            vec![neighbor("0.3.5", "user", NeighborKind::User)],
        );
        assert_eq!(
            route(&r, &addr("0.3.5.2")),
            RouteDecision::Drop(RouteError::UserHasNoDescendants { at: addr("0.3.5") })
        );
    }

    #[test]
    fn route_up_when_outside_subtree() {
        let parent = neighbor("0.3", "up", NeighborKind::Node);
        let r = routable("0.3.5", Some(parent.clone()), vec![]);
        match route(&r, &addr("0.4")) {
            RouteDecision::Forward(n) => assert_eq!(n.addr, addr("0.3")),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn route_root_drops_unknown_slot() {
        let r = routable("0", None, vec![]);
        assert_eq!(
            route(&r, &addr("0.4")),
            RouteDecision::Drop(RouteError::NoSuchChild {
                at: addr("0"),
                slot: 4
            })
        );
        // No parent, not in subtree -> root-style drop on a detached node.
        let detached = routable("0.1", None, vec![]);
        assert_eq!(
            route(&detached, &addr("0.7")),
            RouteDecision::Drop(RouteError::RootCannotRoute { dst: addr("0.7") })
        );
    }

    #[test]
    fn next_step_ascend_lca_descend() {
        let dst = addr("0.4.5");
        let mut cur = addr("0.1.2");
        let mut steps = Vec::new();
        while let Some(step) = next_step(&cur, &dst) {
            cur = match &step {
                Step::Up(a) | Step::Down(a) => a.clone(),
            };
            steps.push(step);
        }
        assert_eq!(cur, dst);
        assert_eq!(
            steps,
            vec![
                Step::Up(addr("0.1")),
                Step::Up(addr("0")),
                Step::Down(addr("0.4")),
                Step::Down(addr("0.4.5")),
            ]
        );
        assert_eq!(next_step(&dst, &dst), None);
    }

    #[test]
    fn hop_chain_valid_full_path() {
        let hops = vec![
            hop("0.1.2", "origin"),
            hop("0.1", "mid-up"),
            hop("0", "root"),
            hop("0.4", "mid-down"),
            hop("0.4.5", "leaf"),
        ];
        validate_hop_chain(&addr("0.1.2"), &addr("0.4.5"), &hops).unwrap();
    }

    #[test]
    fn hop_chain_rejects_off_path_and_repeat_and_too_long() {
        let src = addr("0.1.2");
        let dst = addr("0.4.5");

        // Off-path second hop.
        let off = vec![hop("0.1.2", "origin"), hop("0.1.3", "wrong")];
        assert!(matches!(
            validate_hop_chain(&src, &dst, &off),
            Err(HopChainError::NotOnPath { index: 0, .. })
        ));

        // Wrong origin.
        let wrong_origin = vec![hop("0.7", "bogus")];
        assert!(matches!(
            validate_hop_chain(&src, &dst, &wrong_origin),
            Err(HopChainError::OriginMismatch { .. })
        ));

        // Repeated address with distinct nodes.
        let repeat = vec![
            hop("0.1.2", "origin"),
            hop("0.1", "up"),
            hop("0.1.2", "other"),
        ];
        assert!(matches!(
            validate_hop_chain(&src, &dst, &repeat),
            Err(HopChainError::RepeatedAddress(_))
        ));

        // Repeated node.
        let repeat_node = vec![hop("0.1.2", "origin"), hop("0.1", "origin")];
        assert!(matches!(
            validate_hop_chain(&src, &dst, &repeat_node),
            Err(HopChainError::RepeatedNode(_))
        ));

        // Too long.
        let long: Vec<Hop> = (0..MAX_HOPS + 1)
            .map(|i| hop("0.1.2", &format!("n{i}")))
            .collect();
        assert!(matches!(
            validate_hop_chain(&src, &dst, &long),
            Err(HopChainError::TooLong { len, max })
                if len == MAX_HOPS + 1 && max == MAX_HOPS
        ));

        // Empty.
        assert_eq!(
            validate_hop_chain(&src, &dst, &[]),
            Err(HopChainError::Empty)
        );
    }

    #[test]
    fn append_hop_appends_self_and_rejects_revisit() {
        let mut env = Envelope::new(
            peer("0.1.2", "origin"),
            addr("0.4.5"),
            crate::envelope::MsgId([9; 16]),
            crate::envelope::MSG_LEDGER_V1,
            1,
            vec![],
        );
        assert_eq!(env.hop_chain.len(), 1);

        append_hop(&mut env, &peer("0.1", "up")).unwrap();
        assert_eq!(env.hop_chain.len(), 2);
        assert_eq!(env.hop_chain[1].addr, addr("0.1"));

        // Revisiting the same address/node must fail without mutating.
        let before = env.hop_chain.clone();
        assert!(matches!(
            append_hop(&mut env, &peer("0.1", "up")),
            Err(HopChainError::RepeatedNode(_) | HopChainError::RepeatedAddress(_))
        ));
        assert_eq!(env.hop_chain, before);

        // Off-path hop is rejected without mutating.
        assert!(matches!(
            append_hop(&mut env, &peer("0.2", "wrong")),
            Err(HopChainError::NotOnPath { .. })
        ));
        assert_eq!(env.hop_chain, before);
    }

    #[test]
    fn append_hop_rejects_empty_chain() {
        let mut env = Envelope::new(
            peer("0.1.2", "origin"),
            addr("0.4.5"),
            crate::envelope::MsgId([10; 16]),
            crate::envelope::MSG_LEDGER_V1,
            1,
            vec![],
        );
        env.hop_chain.clear();
        assert_eq!(
            append_hop(&mut env, &peer("0.1", "up")),
            Err(HopChainError::Empty)
        );
        assert!(env.hop_chain.is_empty());
    }
}
