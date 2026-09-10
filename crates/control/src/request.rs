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

/// Maximum accepted length, in bytes, of [`JoinRejection::reason`].
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

/// Re-parent a child within its current region.
///
/// The request only states the desired target; the node applies the
/// downward-only and cycle rules and rejects moves the sender is not allowed
/// to request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveChild {
    /// The child to move.
    pub child: NodeId,
    /// The new parent: this node or a descendant (node enforces downward-only).
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
        }
    }
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
            ]
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
}
