//! Senior-child selection.
//!
//! "Senior" is a total, deterministic order over a node's children. It is used
//! by the control plane for tie-breaking/leadership-style decisions, so it
//! must be stable across nodes and runs.

use cawala_ledger::NodeId;

/// The most senior child: the one with the earliest `date_joined`.
///
/// Ties on `date_joined` are broken deterministically by ascending
/// [`NodeId`]. Returns `None` when `children` is empty. The input order does
/// not matter.
pub fn senior_child(children: &[(NodeId, u64)]) -> Option<&NodeId> {
    children
        .iter()
        .min_by(|(id_a, date_a), (id_b, date_b)| date_a.cmp(date_b).then_with(|| id_a.cmp(id_b)))
        .map(|(id, _)| id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    #[test]
    fn senior_child_picks_earliest_date_joined() {
        let children = vec![(node("c"), 30u64), (node("a"), 10u64), (node("b"), 20u64)];
        assert_eq!(senior_child(&children), Some(&node("a")));
    }

    #[test]
    fn senior_child_ties_break_by_node_id() {
        // Same date: ascending NodeId wins, regardless of input order.
        let children = vec![(node("b"), 10u64), (node("a"), 10u64), (node("c"), 10u64)];
        assert_eq!(senior_child(&children), Some(&node("a")));

        // A later date never beats an earlier one, even with a higher id.
        let children = vec![(node("a"), 10u64), (node("b"), 5u64)];
        assert_eq!(senior_child(&children), Some(&node("b")));
    }

    #[test]
    fn senior_child_empty_is_none() {
        assert_eq!(senior_child(&[]), None);
    }
}
