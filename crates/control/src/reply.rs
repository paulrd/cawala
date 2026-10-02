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

use cawala_ledger::{LedgerPubKey, NodeId, OperatorPubKey};
use cawala_topology::{ChildKind, OctAddr};

/// Maximum number of account rows a [`ControlReply::AdminLedgerSnapshot`]
/// carries.
///
/// The topology cap is 8 child slots, but a ledger may retain detached/legacy
/// child accounts, so this is deliberately larger while keeping an encoded
/// snapshot far under [`MAX_CONTROL_FRAME`](crate::MAX_CONTROL_FRAME).
pub const MAX_ADMIN_LEDGER_ACCOUNTS: usize = 64;

/// ALPN negotiated on every direct control connection.
pub const CONTROL_ALPN: &[u8] = b"cawala/control/0";

/// Wire format version for [`ControlReply`].
///
/// Bumped to 2 when the admin reply variants ([`ControlReply::AdminSnapshot`],
/// [`ControlReply::AdminApproved`], [`ControlReply::AdminRejected`]) were
/// appended, and to 3 when [`ControlReply::AdminLedgerSnapshot`] was appended
/// (read-only ledger view). There is no on-wire reader pinned to this constant
/// yet; it exists so a future reader can reject a mismatched frame up front.
pub const CONTROL_REPLY_VERSION: u8 = 3;

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
    /// Reply to
    /// [`ControlRequest::AdminLedgerQuery`](crate::ControlRequest::AdminLedgerQuery):
    /// a read-only view of this node's ledger (variant 7, reply version 3).
    AdminLedgerSnapshot(AdminLedgerSnapshot),
}

/// A read-only view of one node's ledger, for a value-scoped admin.
///
/// Field order is frozen: postcard encodes positionally. `equity` is
/// `parent_balance - sum(child balances)` (it may be negative), and
/// `parent_balance`/`equity` are computed over **all** balances even when
/// `truncated` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLedgerSnapshot {
    /// The reporting node.
    pub node_id: NodeId,
    /// The node's ledger public key.
    pub ledger_id: LedgerPubKey,
    /// The ledger height (number of accepted entries).
    pub height: u64,
    /// The node's asset balance with its parent (0 when unset).
    pub parent_balance: u64,
    /// The node's derived equity (`parent - sum(children)`); may be negative.
    pub equity: i128,
    /// Whether the record is top-level (no parent link).
    pub root: bool,
    /// Whether `accounts` was truncated at
    /// [`MAX_ADMIN_LEDGER_ACCOUNTS`]; the totals above still cover every
    /// balance.
    pub truncated: bool,
    /// The account rows (record children first in slot order, then remaining
    /// ledger `Child` accounts in `NodeId` order).
    pub accounts: Vec<AdminLedgerAccount>,
}

/// One account row of an [`AdminLedgerSnapshot`].
///
/// `kind`/`slot`/`address` are `None` for a ledger `Child` account that is not
/// a current `node.json` child (detached/legacy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLedgerAccount {
    /// The child node id.
    pub id: NodeId,
    /// The child kind, when this is a current `node.json` child.
    pub kind: Option<ChildKind>,
    /// The child's slot, when it has one.
    pub slot: Option<u8>,
    /// The child's derived address, when derivable.
    pub address: Option<OctAddr>,
    /// The liability balance held for this child (0 when unopened).
    pub balance: u64,
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
            ControlReply::AdminLedgerSnapshot(admin_ledger_snapshot()),
        ]
    }

    fn ledger_pubkey() -> LedgerPubKey {
        cawala_ledger::LedgerSecretKey::from_bytes([7u8; 32]).public()
    }

    /// A snapshot exercising a negative equity and `None` kind/slot/address
    /// (a detached ledger account).
    fn admin_ledger_snapshot() -> AdminLedgerSnapshot {
        AdminLedgerSnapshot {
            node_id: node("parent"),
            ledger_id: ledger_pubkey(),
            height: 42,
            parent_balance: 100,
            equity: -25,
            root: false,
            truncated: false,
            accounts: vec![
                AdminLedgerAccount {
                    id: node("child-a"),
                    kind: Some(ChildKind::Node),
                    slot: Some(1),
                    address: Some("0.3.1".parse().unwrap()),
                    balance: 60,
                },
                AdminLedgerAccount {
                    id: node("user-b"),
                    kind: Some(ChildKind::User),
                    slot: None,
                    address: None,
                    balance: 65,
                },
                AdminLedgerAccount {
                    id: node("detached-c"),
                    kind: None,
                    slot: None,
                    address: None,
                    balance: 0,
                },
            ],
        }
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

    /// Pin the frozen postcard field order of a struct by asserting its
    /// encoding equals the concatenation of its fields' encodings.
    fn assert_postcard_field_order<T: Serialize>(value: &T, fields: &[Vec<u8>]) {
        let mut expected = Vec::new();
        for field in fields {
            expected.extend_from_slice(field);
        }
        assert_eq!(
            postcard::to_allocvec(value).unwrap(),
            expected,
            "field order changed"
        );
    }

    #[test]
    fn admin_ledger_snapshot_reply_discriminant_is_frozen() {
        let reply = ControlReply::AdminLedgerSnapshot(admin_ledger_snapshot());
        let bytes = postcard::to_allocvec(&reply).unwrap();
        assert_eq!(bytes[0], 7, "AdminLedgerSnapshot must stay discriminant 7");
    }

    #[test]
    fn admin_ledger_snapshot_golden_field_order() {
        let snapshot = admin_ledger_snapshot();
        assert_postcard_field_order(
            &snapshot,
            &[
                postcard::to_allocvec(&snapshot.node_id).unwrap(),
                postcard::to_allocvec(&snapshot.ledger_id).unwrap(),
                postcard::to_allocvec(&snapshot.height).unwrap(),
                postcard::to_allocvec(&snapshot.parent_balance).unwrap(),
                postcard::to_allocvec(&snapshot.equity).unwrap(),
                postcard::to_allocvec(&snapshot.root).unwrap(),
                postcard::to_allocvec(&snapshot.truncated).unwrap(),
                postcard::to_allocvec(&snapshot.accounts).unwrap(),
            ],
        );
    }

    #[test]
    fn admin_ledger_account_golden_field_order() {
        let account = AdminLedgerAccount {
            id: node("child-a"),
            kind: Some(ChildKind::Node),
            slot: Some(3),
            address: Some("0.3".parse().unwrap()),
            balance: 7,
        };
        assert_postcard_field_order(
            &account,
            &[
                postcard::to_allocvec(&account.id).unwrap(),
                postcard::to_allocvec(&account.kind).unwrap(),
                postcard::to_allocvec(&account.slot).unwrap(),
                postcard::to_allocvec(&account.address).unwrap(),
                postcard::to_allocvec(&account.balance).unwrap(),
            ],
        );
    }

    #[test]
    fn admin_ledger_snapshot_negative_equity_round_trips() {
        let snapshot = admin_ledger_snapshot();
        assert_eq!(snapshot.equity, -25);
        let bytes = postcard::to_allocvec(&snapshot).unwrap();
        let back: AdminLedgerSnapshot = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, snapshot);
        assert_eq!(back.equity, -25);
        assert_eq!(back.accounts[2].kind, None, "detached account keeps kind None");
        assert_eq!(back.accounts[2].slot, None);
        assert_eq!(back.accounts[2].address, None);
    }

    #[test]
    fn admin_ledger_snapshot_at_account_cap_fits_the_frame() {
        // 64 rows of a plausible worst case (long node ids, full address depth)
        // must stay far under `MAX_CONTROL_FRAME`.
        let accounts: Vec<AdminLedgerAccount> = (0..MAX_ADMIN_LEDGER_ACCOUNTS)
            .map(|i| AdminLedgerAccount {
                id: node(&format!("{i:0>64}")),
                kind: Some(ChildKind::Node),
                slot: Some((i % 8) as u8),
                address: Some("0.1.2.3.4.5.6.7".parse().unwrap()),
                balance: u64::MAX,
            })
            .collect();
        let snapshot = AdminLedgerSnapshot {
            node_id: node(&"f".repeat(64)),
            ledger_id: ledger_pubkey(),
            height: u64::MAX,
            parent_balance: u64::MAX,
            equity: i128::MIN,
            root: false,
            truncated: true,
            accounts,
        };
        let reply = ControlReply::AdminLedgerSnapshot(snapshot);
        let bytes = postcard::to_allocvec(&reply).unwrap();
        assert!(
            bytes.len() < crate::MAX_CONTROL_FRAME as usize,
            "encoded snapshot is {} bytes, frame cap is {}",
            bytes.len(),
            crate::MAX_CONTROL_FRAME
        );
        // Also comfortably below the 10 KiB estimate.
        assert!(bytes.len() < 10 * 1024, "encoded snapshot is {} bytes", bytes.len());
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
