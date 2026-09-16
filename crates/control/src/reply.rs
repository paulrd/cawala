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

use cawala_ledger::{NodeId, OperatorPubKey};
use cawala_topology::{ChildKind, OctAddr};

/// ALPN negotiated on every direct control connection.
pub const CONTROL_ALPN: &[u8] = b"cawala/control/0";

/// Wire format version for [`ControlReply`].
///
/// Bumped to 2 when the admin reply variants ([`ControlReply::AdminSnapshot`],
/// [`ControlReply::AdminApproved`], [`ControlReply::AdminRejected`]) were
/// appended. There is no on-wire reader pinned to this constant yet; it exists
/// so a future reader can reject a mismatched frame up front.
pub const CONTROL_REPLY_VERSION: u8 = 2;

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
    /// Reply to
    /// [`ControlRequest::AdminQuery`](crate::ControlRequest::AdminQuery): the
    /// node snapshot plus the joins awaiting admin approval.
    AdminSnapshot(AdminSnapshot),
    /// Reply to
    /// [`ControlRequest::AdminApproveJoin`](crate::ControlRequest::AdminApproveJoin):
    /// the approved child was assigned `slot`.
    AdminApproved(AdminApproved),
    /// Reply to
    /// [`ControlRequest::AdminRejectJoin`](crate::ControlRequest::AdminRejectJoin).
    AdminRejected(AdminRejected),
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
    /// The request's `expiry` has passed (`now > expiry`).
    Expired,
    /// The request's `nonce` was already seen for this origin.
    Replay,
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

/// The admin view of a node: its control state plus pending joins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSnapshot {
    /// The node's ordinary control snapshot.
    pub node: NodeSnapshot,
    /// Joins queued for admin approval.
    pub pending: Vec<AdminPendingJoin>,
}

/// One join awaiting admin approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminPendingJoin {
    /// The applicant node id.
    pub child: NodeId,
    /// Whether the applicant is a node or a leaf user.
    pub kind: ChildKind,
    /// The applicant's operator key.
    pub operator: OperatorPubKey,
    /// The slot the applicant asked for, or `None` if it left the choice to the
    /// parent.
    pub desired_slot: Option<u8>,
    /// Unix seconds after which the pending request is stale.
    pub expiry: u64,
}

/// An admin-approved join, with the assigned slot and delivery outcome.
///
/// The slot is echoed unconditionally (the node always assigns one, even when
/// the request left `desired_slot` as `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminApproved {
    /// The approved child.
    pub child: NodeId,
    /// The slot the child was assigned (`0..=7`).
    pub slot: u8,
    /// The child's derived octal address.
    pub address: OctAddr,
    /// Whether the approval reached the applicant.
    pub delivery: DeliveryStatus,
}

/// An admin-rejected join, with the delivery outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRejected {
    /// The rejected child.
    pub child: NodeId,
    /// Whether the rejection reached the applicant.
    pub delivery: DeliveryStatus,
}

/// Whether the node delivered an admin decision back to the applicant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// The applicant acknowledged the decision.
    Delivered,
    /// The applicant could not be reached.
    Unreachable,
    /// The applicant refused the decision; see [`RejectCode`].
    Rejected(RejectCode),
    /// Delivery timed out.
    TimedOut,
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
            ControlReply::Rejected(RejectCode::Expired),
            ControlReply::Rejected(RejectCode::Replay),
            ControlReply::Rejected(RejectCode::Internal),
            ControlReply::Snapshot(snapshot()),
            ControlReply::AdminSnapshot(admin_snapshot()),
            ControlReply::AdminApproved(AdminApproved {
                child: node("applicant"),
                slot: 3,
                address: "0.3".parse().unwrap(),
                delivery: DeliveryStatus::Delivered,
            }),
            ControlReply::AdminRejected(AdminRejected {
                child: node("applicant"),
                delivery: DeliveryStatus::Rejected(RejectCode::Unauthorized),
            }),
        ]
    }

    fn admin_snapshot() -> AdminSnapshot {
        AdminSnapshot {
            node: snapshot(),
            pending: vec![
                AdminPendingJoin {
                    child: node("applicant"),
                    kind: ChildKind::Node,
                    operator: cawala_ledger::OperatorSecretKey::from_bytes([9u8; 32]).public(),
                    desired_slot: Some(2),
                    expiry: 1_000,
                },
                AdminPendingJoin {
                    child: node("user-c"),
                    kind: ChildKind::User,
                    operator: cawala_ledger::OperatorSecretKey::from_bytes([8u8; 32]).public(),
                    desired_slot: None,
                    expiry: 2_000,
                },
            ],
        }
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
