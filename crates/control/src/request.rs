//! The v1 control-request payloads.
//!
//! Every variant is a plain data record. Field order is **frozen**: postcard
//! is positional, so adding, removing, or reordering a field is a protocol
//! break. All requests are carried inside a [`SignedControl`](crate::SignedControl),
//! which supplies the operator signature; the types here carry no authority on
//! their own.

use serde::{Deserialize, Serialize};

use cawala_ledger::{LedgerPubKey, NodeId, OperatorPubKey};
use cawala_topology::{ChildKind, MAX_SLOT, OctAddr};

use crate::sign::ControlError;

/// Maximum accepted length, in bytes, of a node id string (`JoinRequest::node`,
/// `JoinRejection::child`).
///
/// Node ids are opaque strings at the ledger layer, so this is a cheap sanity
/// bound rather than a structural guarantee.
pub const MAX_NODE_ID_LEN: usize = 128;

/// Maximum accepted length, in bytes, of [`JoinRequest::location_hint`].
///
/// The hint comes from an untrusted location service and is never
/// authoritative; it only needs to be long enough for a coordinate string.
pub const MAX_LOCATION_HINT_LEN: usize = 256;

/// Maximum accepted length, in bytes, of [`JoinRejection::reason`] and
/// [`AdminJoinReject::reason`].
pub const MAX_REASON_LEN: usize = 256;

/// An applicant's request to join the network under a parent node.
///
/// Self-signed by the applicant's operator key. `location_hint` is an
/// untrusted suggestion from a location service and must never be treated as
/// an authorization input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    /// Applicant node id.
    pub node: NodeId,
    /// Whether the applicant is a node or a user.
    pub kind: ChildKind,
    /// The applicant's operator key (self-signed join).
    pub operator: OperatorPubKey,
    /// The applicant's ledger key: `Some` for a node, `None` for a user.
    pub ledger: Option<LedgerPubKey>,
    /// Requested slot (`0..=7`) hint; `None` means the parent picks.
    pub desired_slot: Option<u8>,
    /// Location-service suggestion; a hint only, never authoritative.
    pub location_hint: Option<String>,
    /// Per-request replay nonce; echoed by the approval or rejection.
    pub nonce: u64,
    /// Unix-style expiry; valid while `now <= expiry`.
    pub expiry: u64,
}

impl JoinRequest {
    /// Check the kind/ledger invariant, the slot range, and the bounded
    /// free-string fields.
    ///
    /// A [`ChildKind::Node`] requires `Some(ledger)`; a [`ChildKind::User`]
    /// must carry `None`. `desired_slot`, when present, must be in `0..=7`.
    /// `node` must be at most [`MAX_NODE_ID_LEN`] bytes and `location_hint`, if
    /// present, at most [`MAX_LOCATION_HINT_LEN`] bytes so a valid request
    /// cannot smuggle an oversized payload into persisted state. Expiry and
    /// nonce freshness are the node's concern (this crate has no clock).
    pub fn validate(&self) -> Result<(), ControlError> {
        let node_len = self.node.as_str().len();
        if node_len > MAX_NODE_ID_LEN {
            return Err(ControlError::FieldTooLong {
                field: "node",
                len: node_len,
                max: MAX_NODE_ID_LEN,
            });
        }
        if let Some(hint) = &self.location_hint
            && hint.len() > MAX_LOCATION_HINT_LEN
        {
            return Err(ControlError::FieldTooLong {
                field: "location_hint",
                len: hint.len(),
                max: MAX_LOCATION_HINT_LEN,
            });
        }
        match (self.kind, self.ledger.is_some()) {
            (ChildKind::Node, false) => Err(ControlError::MissingLedgerForNode),
            (ChildKind::User, true) => Err(ControlError::UnexpectedLedgerForUser),
            _ => {
                if let Some(slot) = self.desired_slot
                    && slot > MAX_SLOT
                {
                    return Err(ControlError::SlotOutOfRange(slot));
                }
                Ok(())
            }
        }
    }
}

/// A parent's approval of a [`JoinRequest`].
///
/// `nonce` echoes the request so the applicant can match the reply; it is not
/// a replay defence on its own.
///
/// `parent_ledger` is the *parent's* ledger public key. The child persists it
/// as the parent's [`PeerKeys`](cawala_ledger::PeerKeys) row so the parent's
/// signed settlement hops become resolvable. It is covered by the operator
/// signature on the enclosing [`SignedControl`](crate::SignedControl), so an
/// applicant learns the key only from the parent itself. Added in
/// [`CONTROL_FORMAT_VERSION`](crate::CONTROL_FORMAT_VERSION) 2 (the field is
/// appended so the v1 layout remains a prefix).
///
/// # Trust on first use
///
/// For a direct (`--parent`) join the parent's operator key is
/// **trust-on-first-use**: the applicant has no prior knowledge of it, so the
/// first self-consistent approval it sees is trusted, and `parent_ledger`
/// inherits that TOFU caveat. An [`Invite`](crate::Invite) pins the parent's
/// operator key out-of-band; when the join was invite-initiated the approval
/// must be signed by exactly that key, which closes the TOFU gap (and thereby
/// authenticates `parent_ledger`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinApproval {
    /// The accepted child.
    pub child: NodeId,
    /// The child's operator key.
    pub child_operator: OperatorPubKey,
    /// The child's ledger key (nodes only).
    pub child_ledger: Option<LedgerPubKey>,
    /// Whether the child is a node or a user.
    pub kind: ChildKind,
    /// The slot the child was assigned (`0..=7`).
    pub slot: u8,
    /// The child's derived octal address.
    pub address: OctAddr,
    /// Unix-style time the child joined.
    pub date_joined: u64,
    /// Echo of the request nonce.
    pub nonce: u64,
    /// The parent's ledger public key (P5a key distribution).
    pub parent_ledger: LedgerPubKey,
}

/// A parent's refusal of a [`JoinRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRejection {
    /// The refused applicant.
    pub child: NodeId,
    /// Human-readable reason.
    pub reason: String,
    /// Echo of the request nonce.
    pub nonce: u64,
}

impl JoinRejection {
    /// Check the bounded free-string fields.
    ///
    /// `child` must be at most [`MAX_NODE_ID_LEN`] bytes and `reason` at most
    /// [`MAX_REASON_LEN`] bytes; both are otherwise unbounded on the wire.
    pub fn validate(&self) -> Result<(), ControlError> {
        let child_len = self.child.as_str().len();
        if child_len > MAX_NODE_ID_LEN {
            return Err(ControlError::FieldTooLong {
                field: "child",
                len: child_len,
                max: MAX_NODE_ID_LEN,
            });
        }
        if self.reason.len() > MAX_REASON_LEN {
            return Err(ControlError::FieldTooLong {
                field: "reason",
                len: self.reason.len(),
                max: MAX_REASON_LEN,
            });
        }
        Ok(())
    }
}

/// An operator's instruction to create a child directly (no request/approval
/// handshake), e.g. a parent provisioning a subordinate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateChild {
    /// The new child.
    pub child: NodeId,
    /// The child's operator key.
    pub operator: OperatorPubKey,
    /// The child's ledger key (nodes only).
    pub ledger: Option<LedgerPubKey>,
    /// Whether the child is a node or a user.
    pub kind: ChildKind,
    /// Assigned slot (`0..=7`), or `None` for the node to pick.
    pub slot: Option<u8>,
    /// Unix-style time the child joined.
    pub date_joined: u64,
}

/// Detach a child; its subtree becomes unattached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachChild {
    /// The child to detach.
    pub child: NodeId,
}

/// Re-parent a child **within its current parent** (v1: re-slotting only).
///
/// The request states the desired target, but v1 supports only re-slotting a
/// direct child under the parent that already holds it: the receiving node
/// rejects any `new_parent` other than itself, and its authority gate rejects a
/// sender that is not this node's operator or senior child. Moving a subtree to
/// a *different* parent (the old parent releases it, the new parent approves,
/// and the subtree's addresses are rebased) is not implemented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveChild {
    /// The child to move.
    pub child: NodeId,
    /// The new parent: v1 requires this node itself (re-slot under the same
    /// parent); a descendant or an external parent is rejected.
    pub new_parent: NodeId,
    /// New slot (`0..=7`), or `None` for the node to pick.
    pub slot: Option<u8>,
}

/// Assert or clear this node's published address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetAddress {
    /// The asserted address, or `None` to unset it.
    pub address: Option<OctAddr>,
}

/// A child's unilateral request to leave its parent and become the root of an
/// independent network.
///
/// Self-signed by the exiting node's operator key. The receiver is the parent,
/// which removes the child link; the child independently rebases itself onto
/// root `0`. `subtree_nodes` is an **audit-only** declaration: it is never a
/// gate, so a mismatch (or an outright lie) cannot block a legitimate exit.
/// Added in [`CONTROL_FORMAT_VERSION`](crate::CONTROL_FORMAT_VERSION) 4
/// (variant 13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitRequest {
    /// The exiting child (must equal the signed origin, whose registered
    /// operator must equal the signed controller).
    pub node: NodeId,
    /// A **best-effort declared count of the nodes this node directly accounts
    /// for** (itself plus its direct children), audit-only.
    ///
    /// It is unverifiable — a node cannot see below its direct children — so
    /// the producer emits `1 + direct_children` and the receiver must never
    /// gate on it.
    pub subtree_nodes: u32,
}

impl ExitRequest {
    /// Check the node-id length bound and that `subtree_nodes >= 1`.
    ///
    /// Whether `node` is actually a child of the receiver, and whether the
    /// signer is that child's operator, are the node's concern.
    pub fn validate(&self) -> Result<(), ControlError> {
        validate_node_id("node", self.node.as_str())?;
        if self.subtree_nodes < 1 {
            return Err(ControlError::FieldBelowMinimum {
                field: "subtree_nodes",
                value: u64::from(self.subtree_nodes),
                min: 1,
            });
        }
        Ok(())
    }
}

/// A parent's notice that it has detached a child, so the child must flip
/// itself to an independent root.
///
/// Parent-signed; the receiver is the named child. Added in
/// [`CONTROL_FORMAT_VERSION`](crate::CONTROL_FORMAT_VERSION) 4 (variant 14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachNotice {
    /// The detached child (must equal the receiver's own node id).
    pub node: NodeId,
}

impl DetachNotice {
    /// Check the node-id length bound.
    pub fn validate(&self) -> Result<(), ControlError> {
        validate_node_id("node", self.node.as_str())
    }
}

/// A parent-signed re-base of a child's local address.
///
/// The receiver is the child; `parent_address` is the sender's own (new)
/// address and `address` is the child's new address, which must equal
/// `parent_address.child(child.slot)` — a topology rule the receiver enforces
/// against its own current parent link, so it is deliberately not checked in
/// [`RebaseNotice::validate`] (which has no view of that link). Added in
/// [`CONTROL_FORMAT_VERSION`](crate::CONTROL_FORMAT_VERSION) 4 (variant 15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebaseNotice {
    /// The child whose address is being set (must equal the receiver's id).
    pub node: NodeId,
    /// The sender's own address, from which `address` must descend by one slot.
    pub parent_address: OctAddr,
    /// The child's new asserted address.
    pub address: OctAddr,
    /// Epoch of this re-base (`>= 1`), carried for a future re-homing protocol.
    ///
    /// v1 has a single generation and the node does **not** enforce ordering:
    /// the receiver applies a notice whenever the derived address differs and
    /// treats an equal address as an idempotent no-op. Out-of-order/epoch
    /// handling is a v2 concern.
    pub generation: u64,
}

impl RebaseNotice {
    /// Check the node-id length bound and that `generation >= 1`.
    ///
    /// The `address == parent_address.child(slot)` derivation is a topology
    /// check against the receiver's current parent link and is enforced by the
    /// node, not here.
    pub fn validate(&self) -> Result<(), ControlError> {
        validate_node_id("node", self.node.as_str())?;
        if self.generation < 1 {
            return Err(ControlError::FieldBelowMinimum {
                field: "generation",
                value: 0,
                min: 1,
            });
        }
        Ok(())
    }
}

/// A child's request that its parent answer with its current
/// [`ControlReply::Snapshot`](crate::ControlReply::Snapshot).
///
/// Used to heal after a missed `Rebase` notice: the snapshot carries the
/// parent's address and its children's addresses, from which the child derives
/// its expected address. Self-signed by the requesting node. Added in
/// [`CONTROL_FORMAT_VERSION`](crate::CONTROL_FORMAT_VERSION) 4 (variant 16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebasePull {
    /// The requesting child (must equal the signed origin).
    pub node: NodeId,
}

impl RebasePull {
    /// Check the node-id length bound.
    pub fn validate(&self) -> Result<(), ControlError> {
        validate_node_id("node", self.node.as_str())
    }
}

/// Reject a node id longer than [`MAX_NODE_ID_LEN`].
fn validate_node_id(field: &'static str, id: &str) -> Result<(), ControlError> {
    let len = id.len();
    if len > MAX_NODE_ID_LEN {
        return Err(ControlError::FieldTooLong {
            field,
            len,
            max: MAX_NODE_ID_LEN,
        });
    }
    Ok(())
}

/// An admin's approval of a join that a node queued for approval.
///
/// The enclosing [`SignedControl`](crate::SignedControl) must be signed by the
/// node's registered operator key; the node additionally requires that key to
/// hold an active [`AdminGrant`](crate::AdminGrant) before applying this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminJoinApprove {
    /// The pending child to approve.
    pub child: NodeId,
    /// Explicit slot (`0..=7`), or `None` to let the node pick.
    pub slot: Option<u8>,
}

impl AdminJoinApprove {
    /// Check the child-id length bound and, when present, the slot range.
    ///
    /// `child` must be at most [`MAX_NODE_ID_LEN`] bytes and `slot`, when
    /// present, must be in `0..=7`; whether the child is actually pending is
    /// the node's concern.
    pub fn validate(&self) -> Result<(), ControlError> {
        let child_len = self.child.as_str().len();
        if child_len > MAX_NODE_ID_LEN {
            return Err(ControlError::FieldTooLong {
                field: "child",
                len: child_len,
                max: MAX_NODE_ID_LEN,
            });
        }
        if let Some(slot) = self.slot
            && slot > MAX_SLOT
        {
            return Err(ControlError::SlotOutOfRange(slot));
        }
        Ok(())
    }
}

/// An admin's refusal of a join that a node queued for approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminJoinReject {
    /// The pending child to reject.
    pub child: NodeId,
    /// Optional human-readable reason.
    pub reason: Option<String>,
}

impl AdminJoinReject {
    /// Check the child-id and reason length bounds.
    ///
    /// `child` must be at most [`MAX_NODE_ID_LEN`] bytes and `reason`, when
    /// present, at most [`MAX_REASON_LEN`] bytes.
    pub fn validate(&self) -> Result<(), ControlError> {
        let child_len = self.child.as_str().len();
        if child_len > MAX_NODE_ID_LEN {
            return Err(ControlError::FieldTooLong {
                field: "child",
                len: child_len,
                max: MAX_NODE_ID_LEN,
            });
        }
        if let Some(reason) = &self.reason
            && reason.len() > MAX_REASON_LEN
        {
            return Err(ControlError::FieldTooLong {
                field: "reason",
                len: reason.len(),
                max: MAX_REASON_LEN,
            });
        }
        Ok(())
    }
}

/// An admin's request to re-send the stored decision for one child.
///
/// A node keeps the operator-signed `JoinApproved`/`JoinRejected` it most
/// recently issued per child; this asks it to deliver that decision again
/// (e.g. after the applicant missed it). The stored frame is re-sent as-is; the
/// applicant matches it by the echoed `JoinRequest.nonce`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRedeliverJoin {
    /// The child whose last decision should be re-sent.
    pub child: NodeId,
}

impl AdminRedeliverJoin {
    /// Check the child-id length bound.
    ///
    /// `child` must be at most [`MAX_NODE_ID_LEN`] bytes; whether a decision is
    /// actually stored is the node's concern.
    pub fn validate(&self) -> Result<(), ControlError> {
        let child_len = self.child.as_str().len();
        if child_len > MAX_NODE_ID_LEN {
            return Err(ControlError::FieldTooLong {
                field: "child",
                len: child_len,
                max: MAX_NODE_ID_LEN,
            });
        }
        Ok(())
    }
}

/// The v1 control-request payload.
///
/// Variant order is frozen: postcard encodes the discriminant positionally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlRequest {
    /// Ask to join under the recipient.
    Join(JoinRequest),
    /// Approve a join request.
    JoinApproved(JoinApproval),
    /// Reject a join request.
    JoinRejected(JoinRejection),
    /// Directly create a child.
    CreateChild(CreateChild),
    /// Detach a child.
    DetachChild(DetachChild),
    /// Re-parent a child.
    MoveChild(MoveChild),
    /// Set or clear this node's address.
    SetAddress(SetAddress),
    /// Read-only: the target replies with its state and balances.
    Query,
    /// Read-only admin view: pending joins and admin state.
    AdminQuery,
    /// Approve a pending join as the node's admin.
    AdminApproveJoin(AdminJoinApprove),
    /// Reject a pending join as the node's admin.
    AdminRejectJoin(AdminJoinReject),
    /// Re-send the stored decision for a child as the node's admin.
    AdminRedeliverJoin(AdminRedeliverJoin),
    /// A child's unilateral request to leave its parent (variant 13, format 4).
    Exit(ExitRequest),
    /// A parent's notice it detached a child (variant 14, format 4).
    DetachNotice(DetachNotice),
    /// A parent-signed child address re-base (variant 15, format 4).
    Rebase(RebaseNotice),
    /// A child's request for the parent's snapshot (variant 16, format 4).
    RebasePull(RebasePull),
}

impl ControlRequest {
    /// Stable label for logs and diagnostics.
    pub fn kind(&self) -> &'static str {
        match self {
            ControlRequest::Join(_) => "join",
            ControlRequest::JoinApproved(_) => "join-approved",
            ControlRequest::JoinRejected(_) => "join-rejected",
            ControlRequest::CreateChild(_) => "create-child",
            ControlRequest::DetachChild(_) => "detach-child",
            ControlRequest::MoveChild(_) => "move-child",
            ControlRequest::SetAddress(_) => "set-address",
            ControlRequest::Query => "query",
            ControlRequest::AdminQuery => "admin-query",
            ControlRequest::AdminApproveJoin(_) => "admin-approve-join",
            ControlRequest::AdminRejectJoin(_) => "admin-reject-join",
            ControlRequest::AdminRedeliverJoin(_) => "admin-redeliver-join",
            ControlRequest::Exit(_) => "exit",
            ControlRequest::DetachNotice(_) => "detach-notice",
            ControlRequest::Rebase(_) => "rebase",
            ControlRequest::RebasePull(_) => "rebase-pull",
        }
    }

    /// Whether this is one of the admin-only variants.
    pub fn is_admin(&self) -> bool {
        matches!(
            self,
            ControlRequest::AdminQuery
                | ControlRequest::AdminApproveJoin(_)
                | ControlRequest::AdminRejectJoin(_)
                | ControlRequest::AdminRedeliverJoin(_)
        )
    }
}

/// Whether `request` is one of the admin-only variants.
///
/// Admin requests are authenticated like any other control request, but are
/// authorised only when the signing operator holds an active
/// [`AdminGrant`](crate::AdminGrant) scoped to the `origin` node.
pub fn is_admin_request(request: &ControlRequest) -> bool {
    request.is_admin()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_ledger::{LedgerSecretKey, OperatorSecretKey};

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorPubKey {
        OperatorSecretKey::from_bytes([seed; 32]).public()
    }

    fn ledger(seed: u8) -> LedgerPubKey {
        LedgerSecretKey::from_bytes([seed; 32]).public()
    }

    fn join() -> JoinRequest {
        JoinRequest {
            node: node("applicant"),
            kind: ChildKind::Node,
            operator: operator(1),
            ledger: Some(ledger(11)),
            desired_slot: Some(3),
            location_hint: Some("0.3".to_string()),
            nonce: 1,
            expiry: 100,
        }
    }

    fn sample_requests() -> Vec<ControlRequest> {
        vec![
            ControlRequest::Join(join()),
            ControlRequest::JoinApproved(JoinApproval {
                child: node("applicant"),
                child_operator: operator(1),
                child_ledger: Some(ledger(11)),
                kind: ChildKind::Node,
                slot: 3,
                address: "0.3".parse().unwrap(),
                date_joined: 50,
                nonce: 1,
                parent_ledger: ledger(12),
            }),
            ControlRequest::JoinRejected(JoinRejection {
                child: node("applicant"),
                reason: "no free slot".to_string(),
                nonce: 1,
            }),
            ControlRequest::CreateChild(CreateChild {
                child: node("applicant"),
                operator: operator(1),
                ledger: Some(ledger(11)),
                kind: ChildKind::Node,
                slot: Some(3),
                date_joined: 50,
            }),
            ControlRequest::DetachChild(DetachChild {
                child: node("applicant"),
            }),
            ControlRequest::MoveChild(MoveChild {
                child: node("applicant"),
                new_parent: node("parent"),
                slot: Some(4),
            }),
            ControlRequest::SetAddress(SetAddress {
                address: Some("0.3".parse().unwrap()),
            }),
            ControlRequest::Query,
            ControlRequest::AdminQuery,
            ControlRequest::AdminApproveJoin(AdminJoinApprove {
                child: node("applicant"),
                slot: Some(3),
            }),
            ControlRequest::AdminRejectJoin(AdminJoinReject {
                child: node("applicant"),
                reason: Some("denied".to_string()),
            }),
            ControlRequest::AdminRedeliverJoin(AdminRedeliverJoin {
                child: node("applicant"),
            }),
            ControlRequest::Exit(ExitRequest {
                node: node("applicant"),
                subtree_nodes: 3,
            }),
            ControlRequest::DetachNotice(DetachNotice {
                node: node("applicant"),
            }),
            ControlRequest::Rebase(RebaseNotice {
                node: node("applicant"),
                parent_address: "0.1".parse().unwrap(),
                address: "0.1.3".parse().unwrap(),
                generation: 2,
            }),
            ControlRequest::RebasePull(RebasePull {
                node: node("applicant"),
            }),
        ]
    }

    #[test]
    fn kind_labels_are_stable() {
        let labels: Vec<&str> = sample_requests().iter().map(ControlRequest::kind).collect();
        assert_eq!(
            labels,
            vec![
                "join",
                "join-approved",
                "join-rejected",
                "create-child",
                "detach-child",
                "move-child",
                "set-address",
                "query",
                "admin-query",
                "admin-approve-join",
                "admin-reject-join",
                "admin-redeliver-join",
                "exit",
                "detach-notice",
                "rebase",
                "rebase-pull",
            ]
        );
    }

    #[test]
    fn exit_rights_variants_are_not_admin() {
        for request in [
            ControlRequest::Exit(ExitRequest {
                node: node("applicant"),
                subtree_nodes: 1,
            }),
            ControlRequest::DetachNotice(DetachNotice {
                node: node("applicant"),
            }),
            ControlRequest::Rebase(RebaseNotice {
                node: node("applicant"),
                parent_address: "0".parse().unwrap(),
                address: "0.3".parse().unwrap(),
                generation: 1,
            }),
            ControlRequest::RebasePull(RebasePull {
                node: node("applicant"),
            }),
        ] {
            assert!(!request.is_admin(), "{request:?}");
            assert!(!is_admin_request(&request), "{request:?}");
        }
    }

    #[test]
    fn exit_validate_rejects_zero_subtree_nodes_and_long_node() {
        let valid = ExitRequest {
            node: node("applicant"),
            subtree_nodes: 1,
        };
        assert_eq!(valid.validate(), Ok(()));

        let zero = ExitRequest {
            node: node("applicant"),
            subtree_nodes: 0,
        };
        assert_eq!(
            zero.validate(),
            Err(ControlError::FieldBelowMinimum {
                field: "subtree_nodes",
                value: 0,
                min: 1,
            })
        );

        let long = ExitRequest {
            node: node(&"n".repeat(MAX_NODE_ID_LEN + 1)),
            subtree_nodes: 1,
        };
        assert_eq!(
            long.validate(),
            Err(ControlError::FieldTooLong {
                field: "node",
                len: MAX_NODE_ID_LEN + 1,
                max: MAX_NODE_ID_LEN,
            })
        );
    }

    #[test]
    fn detach_notice_and_rebase_pull_validate_node_bound() {
        assert_eq!(DetachNotice { node: node("c") }.validate(), Ok(()));
        assert_eq!(RebasePull { node: node("c") }.validate(), Ok(()));
        for err in [
            DetachNotice {
                node: node(&"n".repeat(MAX_NODE_ID_LEN + 1)),
            }
            .validate(),
            RebasePull {
                node: node(&"n".repeat(MAX_NODE_ID_LEN + 1)),
            }
            .validate(),
        ] {
            assert_eq!(
                err,
                Err(ControlError::FieldTooLong {
                    field: "node",
                    len: MAX_NODE_ID_LEN + 1,
                    max: MAX_NODE_ID_LEN,
                })
            );
        }
    }

    #[test]
    fn rebase_validate_rejects_zero_generation() {
        let notice = RebaseNotice {
            node: node("c"),
            parent_address: "0".parse().unwrap(),
            address: "0.3".parse().unwrap(),
            generation: 1,
        };
        assert_eq!(notice.validate(), Ok(()));

        let zero = RebaseNotice {
            generation: 0,
            ..notice.clone()
        };
        assert_eq!(
            zero.validate(),
            Err(ControlError::FieldBelowMinimum {
                field: "generation",
                value: 0,
                min: 1,
            })
        );

        let long = RebaseNotice {
            node: node(&"n".repeat(MAX_NODE_ID_LEN + 1)),
            ..notice
        };
        assert_eq!(
            long.validate(),
            Err(ControlError::FieldTooLong {
                field: "node",
                len: MAX_NODE_ID_LEN + 1,
                max: MAX_NODE_ID_LEN,
            })
        );
    }

    /// Pin the frozen postcard field order of a struct by asserting its encoding
    /// equals the concatenation of its fields' encodings, in declaration order.
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
    fn exit_rights_variants_frozen_field_order() {
        let exit = ExitRequest {
            node: node("applicant"),
            subtree_nodes: 7,
        };
        assert_postcard_field_order(
            &exit,
            &[
                postcard::to_allocvec(&exit.node).unwrap(),
                postcard::to_allocvec(&exit.subtree_nodes).unwrap(),
            ],
        );

        let detach = DetachNotice {
            node: node("applicant"),
        };
        assert_postcard_field_order(&detach, &[postcard::to_allocvec(&detach.node).unwrap()]);

        let rebase = RebaseNotice {
            node: node("applicant"),
            parent_address: "0.1".parse().unwrap(),
            address: "0.1.3".parse().unwrap(),
            generation: 9,
        };
        assert_postcard_field_order(
            &rebase,
            &[
                postcard::to_allocvec(&rebase.node).unwrap(),
                postcard::to_allocvec(&rebase.parent_address).unwrap(),
                postcard::to_allocvec(&rebase.address).unwrap(),
                postcard::to_allocvec(&rebase.generation).unwrap(),
            ],
        );
        // `parent_address` and `address` are both `OctAddr`: swapping them keeps
        // the length but must change the encoding, so this catches a reorder the
        // plain round-trip would miss.
        let swapped = RebaseNotice {
            parent_address: rebase.address.clone(),
            address: rebase.parent_address.clone(),
            ..rebase.clone()
        };
        assert_ne!(
            postcard::to_allocvec(&rebase).unwrap(),
            postcard::to_allocvec(&swapped).unwrap()
        );

        let pull = RebasePull {
            node: node("applicant"),
        };
        assert_postcard_field_order(&pull, &[postcard::to_allocvec(&pull.node).unwrap()]);
    }

    #[test]
    fn is_admin_only_matches_admin_variants() {
        for request in sample_requests() {
            let expected = matches!(
                request,
                ControlRequest::AdminQuery
                    | ControlRequest::AdminApproveJoin(_)
                    | ControlRequest::AdminRejectJoin(_)
                    | ControlRequest::AdminRedeliverJoin(_)
            );
            assert_eq!(request.is_admin(), expected, "{request:?}");
            assert_eq!(is_admin_request(&request), expected, "{request:?}");
        }
    }

    #[test]
    fn admin_approve_join_validate_enforces_bounds() {
        let valid = AdminJoinApprove {
            child: node("applicant"),
            slot: Some(MAX_SLOT),
        };
        assert_eq!(valid.validate(), Ok(()));

        // `None` is always acceptable.
        let auto = AdminJoinApprove {
            child: node("applicant"),
            slot: None,
        };
        assert_eq!(auto.validate(), Ok(()));

        let bad_slot = AdminJoinApprove {
            child: node("applicant"),
            slot: Some(MAX_SLOT + 1),
        };
        assert_eq!(
            bad_slot.validate(),
            Err(ControlError::SlotOutOfRange(MAX_SLOT + 1))
        );

        let long_child = AdminJoinApprove {
            child: node(&"n".repeat(MAX_NODE_ID_LEN + 1)),
            slot: None,
        };
        assert_eq!(
            long_child.validate(),
            Err(ControlError::FieldTooLong {
                field: "child",
                len: MAX_NODE_ID_LEN + 1,
                max: MAX_NODE_ID_LEN,
            })
        );
    }

    #[test]
    fn admin_reject_join_validate_enforces_bounds() {
        let valid = AdminJoinReject {
            child: node("applicant"),
            reason: Some("x".repeat(MAX_REASON_LEN)),
        };
        assert_eq!(valid.validate(), Ok(()));

        // `None` reason is acceptable.
        let bare = AdminJoinReject {
            child: node("applicant"),
            reason: None,
        };
        assert_eq!(bare.validate(), Ok(()));

        let long_reason = AdminJoinReject {
            child: node("applicant"),
            reason: Some("x".repeat(MAX_REASON_LEN + 1)),
        };
        assert_eq!(
            long_reason.validate(),
            Err(ControlError::FieldTooLong {
                field: "reason",
                len: MAX_REASON_LEN + 1,
                max: MAX_REASON_LEN,
            })
        );

        let long_child = AdminJoinReject {
            child: node(&"n".repeat(MAX_NODE_ID_LEN + 1)),
            reason: None,
        };
        assert_eq!(
            long_child.validate(),
            Err(ControlError::FieldTooLong {
                field: "child",
                len: MAX_NODE_ID_LEN + 1,
                max: MAX_NODE_ID_LEN,
            })
        );
    }

    #[test]
    fn admin_redeliver_join_validate_enforces_bounds() {
        assert_eq!(
            AdminRedeliverJoin {
                child: node("applicant")
            }
            .validate(),
            Ok(())
        );

        let long_child = AdminRedeliverJoin {
            child: node(&"n".repeat(MAX_NODE_ID_LEN + 1)),
        };
        assert_eq!(
            long_child.validate(),
            Err(ControlError::FieldTooLong {
                field: "child",
                len: MAX_NODE_ID_LEN + 1,
                max: MAX_NODE_ID_LEN,
            })
        );
    }

    #[test]
    fn join_validate_rejects_node_without_ledger_and_user_with_ledger() {
        // Node needs a ledger.
        let mut request = join();
        request.ledger = None;
        assert_eq!(request.validate(), Err(ControlError::MissingLedgerForNode));

        // User must not carry one.
        let mut request = join();
        request.kind = ChildKind::User;
        assert_eq!(
            request.validate(),
            Err(ControlError::UnexpectedLedgerForUser)
        );

        // The valid combinations pass.
        assert_eq!(join().validate(), Ok(()));
        let mut user = join();
        user.kind = ChildKind::User;
        user.ledger = None;
        assert_eq!(user.validate(), Ok(()));
    }

    #[test]
    fn join_validate_rejects_slot_out_of_range() {
        let mut request = join();
        request.desired_slot = Some(MAX_SLOT);
        assert_eq!(request.validate(), Ok(()));

        request.desired_slot = Some(MAX_SLOT + 1);
        assert_eq!(
            request.validate(),
            Err(ControlError::SlotOutOfRange(MAX_SLOT + 1))
        );

        // `None` means the parent picks: always acceptable.
        request.desired_slot = None;
        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn join_validate_rejects_long_location_hint() {
        let mut request = join();
        request.location_hint = Some("x".repeat(MAX_LOCATION_HINT_LEN));
        assert_eq!(request.validate(), Ok(()));

        request.location_hint = Some("x".repeat(MAX_LOCATION_HINT_LEN + 1));
        assert_eq!(
            request.validate(),
            Err(ControlError::FieldTooLong {
                field: "location_hint",
                len: MAX_LOCATION_HINT_LEN + 1,
                max: MAX_LOCATION_HINT_LEN,
            })
        );

        // A node id longer than the sanity bound is rejected too.
        request.location_hint = None;
        request.node = node(&"n".repeat(MAX_NODE_ID_LEN + 1));
        assert_eq!(
            request.validate(),
            Err(ControlError::FieldTooLong {
                field: "node",
                len: MAX_NODE_ID_LEN + 1,
                max: MAX_NODE_ID_LEN,
            })
        );
    }

    #[test]
    fn join_rejection_validate_rejects_long_reason() {
        let mut rejection = JoinRejection {
            child: node("applicant"),
            reason: "x".repeat(MAX_REASON_LEN),
            nonce: 1,
        };
        assert_eq!(rejection.validate(), Ok(()));

        rejection.reason = "x".repeat(MAX_REASON_LEN + 1);
        assert_eq!(
            rejection.validate(),
            Err(ControlError::FieldTooLong {
                field: "reason",
                len: MAX_REASON_LEN + 1,
                max: MAX_REASON_LEN,
            })
        );

        // A child id longer than the sanity bound is rejected too.
        rejection.reason = "no".to_string();
        rejection.child = node(&"n".repeat(MAX_NODE_ID_LEN + 1));
        assert_eq!(
            rejection.validate(),
            Err(ControlError::FieldTooLong {
                field: "child",
                len: MAX_NODE_ID_LEN + 1,
                max: MAX_NODE_ID_LEN,
            })
        );
    }

    #[test]
    fn control_request_round_trips_postcard() {
        for request in sample_requests() {
            let bytes = postcard::to_allocvec(&request).unwrap();
            let back: ControlRequest = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(back, request);
            assert_eq!(back.kind(), request.kind());
        }
    }

    #[test]
    fn join_approval_round_trips_parent_ledger() {
        let approval = JoinApproval {
            child: node("applicant"),
            child_operator: operator(1),
            child_ledger: Some(ledger(11)),
            kind: ChildKind::Node,
            slot: 3,
            address: "0.3".parse().unwrap(),
            date_joined: 50,
            nonce: 1,
            parent_ledger: ledger(12),
        };
        let bytes = postcard::to_allocvec(&approval).unwrap();
        let back: JoinApproval = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, approval);
        assert_eq!(back.parent_ledger, ledger(12));
    }
}
