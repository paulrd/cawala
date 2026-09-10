//! The v1 direct-control reply and query surface.
//!
//! M4 phase 1 runs control **directly** over its own ALPN
//! ([`CONTROL_ALPN`]), one request/response per bi-directional stream:
//! `open_bi` -> write a [`SignedControl`](crate::SignedControl) frame ->
//! `finish` -> read one [`ControlReply`] frame. This is *not* tree-routed; the
//! indirect (hop-by-hop) control plane is a later phase.
//!
//! All types here are plain data and wasm-safe: `std` + `serde` only.
//! [`CONTROL_REPLY_VERSION`] versions the reply half independently of the
//! request half ([`CONTROL_FORMAT_VERSION`](crate::CONTROL_FORMAT_VERSION)).

use serde::{Deserialize, Serialize};

use cawala_ledger::NodeId;
use cawala_topology::{ChildKind, OctAddr};

/// ALPN negotiated on every direct control connection.
pub const CONTROL_ALPN: &[u8] = b"cawala/control/0";

/// Wire format version for [`ControlReply`].
pub const CONTROL_REPLY_VERSION: u8 = 1;

/// The node's answer to one direct control request.
///
/// Variant order is frozen: postcard encodes the discriminant positionally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlReply {
    /// The request was applied.
    Accepted,
    /// A join request was queued for admin approval.
    Pending,
    /// The request was refused; see [`RejectCode`].
    Rejected(RejectCode),
    /// Reply to [`ControlRequest::Query`](crate::ControlRequest::Query).
    Snapshot(NodeSnapshot),
}

/// Why a control request was refused.
///
/// This is a coarse, wire-stable categorization. It is deliberately not an
/// exhaustive error enum: local diagnostics may be richer, but the reply only
/// carries one of these codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectCode {
    /// The request's wire version is not supported.
    BadVersion,
    /// The origin is not allowed to make this request.
    Unauthorized,
    /// The referenced node/child/link does not exist.
    NotFound,
    /// The target node is full (all 8 child slots taken).
    Capacity,
    /// The requested slot is already occupied.
    SlotTaken,
    /// The requested slot is outside `0..=7`.
    SlotOutOfRange,
    /// The request is structurally invalid for its variant.
    BadRequest,
    /// The target is not attached (no parent / no address yet).
    NotAttached,
    /// A cross-region move was requested in a context that forbids it.
    CrossRegion,
    /// An internal error occurred; the request was not applied.
    Internal,
}

/// A point-in-time view of a node's control state.
///
/// Addresses are *derived* from the node's asserted address (the parent is
/// `address.parent()`, a child in slot `s` is `address.child(s)`); they are not
/// stored separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSnapshot {
    /// The reporting node.
    pub node_id: NodeId,
    /// The node's asserted address, if any.
    pub address: Option<OctAddr>,
    /// The parent link, if one is set and an address makes it derivable.
    pub parent: Option<ParentSnapshot>,
    /// The node's child links.
    pub children: Vec<ChildSnapshot>,
}

/// The parent link of a [`NodeSnapshot`], with its derived address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentSnapshot {
    /// The parent node.
    pub node_id: NodeId,
    /// The slot this node occupies under its parent.
    pub slot: u8,
    /// The parent's derived address.
    pub address: OctAddr,
}

/// One child link of a [`NodeSnapshot`], with its derived address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildSnapshot {
    /// The child node.
    pub child_id: NodeId,
    /// Whether the child is a node or a leaf user.
    pub kind: ChildKind,
    /// The slot the child occupies under this node.
    pub slot: u8,
    /// The child's derived address (`address.child(slot)`), if this node has an
    /// asserted address.
    pub address: Option<OctAddr>,
    /// Unix seconds when the child first joined this parent.
    pub date_joined: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn replies() -> Vec<ControlReply> {
        vec![
            ControlReply::Accepted,
            ControlReply::Pending,
            ControlReply::Rejected(RejectCode::BadVersion),
            ControlReply::Rejected(RejectCode::Unauthorized),
            ControlReply::Rejected(RejectCode::NotFound),
            ControlReply::Rejected(RejectCode::Capacity),
            ControlReply::Rejected(RejectCode::SlotTaken),
            ControlReply::Rejected(RejectCode::SlotOutOfRange),
            ControlReply::Rejected(RejectCode::BadRequest),
            ControlReply::Rejected(RejectCode::NotAttached),
            ControlReply::Rejected(RejectCode::CrossRegion),
            ControlReply::Rejected(RejectCode::Internal),
            ControlReply::Snapshot(snapshot()),
        ]
    }

    fn snapshot() -> NodeSnapshot {
        NodeSnapshot {
            node_id: node("parent"),
            address: Some("0.3".parse().unwrap()),
            parent: Some(ParentSnapshot {
                node_id: node("grandparent"),
                slot: 3,
                address: "0".parse().unwrap(),
            }),
            children: vec![
                ChildSnapshot {
                    child_id: node("child-a"),
                    kind: ChildKind::Node,
                    slot: 1,
                    address: Some("0.3.1".parse().unwrap()),
                    date_joined: 10,
                },
                ChildSnapshot {
                    child_id: node("user-b"),
                    kind: ChildKind::User,
                    slot: 5,
                    address: Some("0.3.5".parse().unwrap()),
                    date_joined: 20,
                },
            ],
        }
    }

    #[test]
    fn control_reply_round_trips_postcard() {
        for reply in replies() {
            let bytes = postcard::to_allocvec(&reply).unwrap();
            let back: ControlReply = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(back, reply);
        }
    }

    #[test]
    fn node_snapshot_round_trips_postcard() {
        let snap = snapshot();
        let bytes = postcard::to_allocvec(&snap).unwrap();
        let back: NodeSnapshot = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, snap);
    }

    #[test]
    fn empty_snapshot_round_trips_postcard() {
        let snap = NodeSnapshot {
            node_id: node("lonely"),
            address: None,
            parent: None,
            children: Vec::new(),
        };
        let bytes = postcard::to_allocvec(&snap).unwrap();
        let back: NodeSnapshot = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, snap);
    }
}
