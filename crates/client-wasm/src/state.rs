//! Pure, native-testable local state for the browser control client.
//!
//! This module holds the small amount of durable state a browser leaf needs to
//! participate in the direct [`cawala/control/0`](cawala_control::CONTROL_ALPN)
//! join handshake:
//!
//! - the single outbound [`JoinRequest`] awaiting a reverse-dialed
//!   `JoinApproved`/`JoinRejected` (with the parent's pinned operator key when
//!   the join came from an [`Invite`](cawala_control::Invite)),
//! - the local topology record learned from an approval (asserted address,
//!   parent link, child links), and
//! - the last rejection, for display.
//!
//! It is deliberately free of `iroh`, RNG, clocks, and I/O so the whole
//! handshake state machine can be exercised natively. The state serializes to
//! postcard as [`LocalStateV1`]; it contains **no secret bytes** (the operator
//! key lives in [`crate::control::SharedControl`], never in the exported blob).

use cawala_control::OctAddr;
use cawala_control::{
    ChildKind, ChildSnapshot, ControlReply, JoinApproval, JoinRejection, JoinRequest, NodeId,
    NodeSnapshot, OperatorPubKey, ParentSnapshot, RejectCode,
};
use serde::{Deserialize, Serialize};

/// Wire version of [`LocalStateV1`].
///
/// Bump only for a deliberate, documented change to the exported blob; it is
/// checked by [`LocalStateV1::from_bytes`].
pub const LOCAL_STATE_VERSION: u8 = 1;

/// A link to this client's parent, learned from an accepted `JoinApproved`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentLink {
    /// The parent node id.
    pub node_id: NodeId,
    /// The slot this client occupies under its parent.
    pub slot: u8,
}

/// A link to one of this client's children.
///
/// Browser leaves never take user children in the A′ increment, so this is
/// normally empty; it exists so a future node-capable client can persist the
/// same record shape the native node uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildLink {
    /// The child node id.
    pub child_id: NodeId,
    /// Whether the child is a node or a leaf user.
    pub kind: ChildKind,
    /// The slot the child occupies under this client.
    pub slot: u8,
    /// Unix seconds when the child first joined this client.
    pub date_joined: u64,
}

/// The local topology record: asserted address plus adjacent links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LocalRecord {
    /// This client's asserted address, `None` until an approval assigns one.
    pub address: Option<OctAddr>,
    /// The parent link, `None` while unattached.
    pub parent: Option<ParentLink>,
    /// Child links (normally empty for a browser leaf).
    pub children: Vec<ChildLink>,
}

/// The outbound join awaiting a reverse-dialed reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundJoin {
    /// The self-signed request that was sent.
    pub request: JoinRequest,
    /// The parent the request was sent to.
    pub parent: NodeId,
    /// The parent's operator key pinned out-of-band by an invite, if any.
    ///
    /// When `Some`, a `JoinApproved` is only accepted if its `controller`
    /// matches this key exactly.
    pub pinned_operator: Option<OperatorPubKey>,
    /// Unix seconds when the request was sent.
    pub sent_at: u64,
}

/// A remembered rejection, for display in the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejection {
    /// Stable machine-readable code (never a `Debug` rendering).
    pub code: String,
    /// Human-readable reason, if the parent supplied one.
    pub reason: Option<String>,
}

/// The versioned, postcard-serializable local state blob.
///
/// This is exactly what [`crate::ClientNode::export_state`] emits and
/// [`crate::ClientNode::import_state`] consumes. It holds no secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalStateV1 {
    /// [`LOCAL_STATE_VERSION`].
    pub version: u8,
    /// The in-flight outbound join, if any.
    pub outbound: Option<OutboundJoin>,
    /// The local topology record.
    pub record: LocalRecord,
    /// The last rejection, if any.
    pub last_rejection: Option<Rejection>,
}

impl Default for LocalStateV1 {
    fn default() -> Self {
        LocalStateV1 {
            version: LOCAL_STATE_VERSION,
            outbound: None,
            record: LocalRecord::default(),
            last_rejection: None,
        }
    }
}

/// The outcome of applying one inbound control event to [`LocalStateV1`].
///
/// The inbound `cawala/control/0` handler translates this into a
/// [`ControlReply`] and (where appropriate) a JavaScript event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// There is no in-flight outbound join to attach the reply to.
    NotAttached,
    /// The event was refused with `code`; state is unchanged.
    Denied(RejectCode),
    /// A `JoinApproved` was applied; the parent link and address are set.
    Approved,
    /// A `JoinRejected` consumed the outbound join.
    Rejected {
        /// The rejecting parent.
        parent: NodeId,
        /// The parent's reason.
        reason: String,
    },
    /// A parent-signed `Rebase` moved this client's asserted address in place.
    Rebased,
    /// The parent detached this client: parent and address were cleared.
    Detached,
    /// Nothing to do; reply `Accepted` (mirrors the native idempotent case).
    None,
}

impl Transition {
    /// The wire reply that corresponds to this transition.
    pub fn reply(&self) -> ControlReply {
        match self {
            Transition::NotAttached => ControlReply::Rejected(RejectCode::NotAttached),
            Transition::Denied(code) => ControlReply::Rejected(*code),
            Transition::Approved
            | Transition::Rejected { .. }
            | Transition::Rebased
            | Transition::Detached
            | Transition::None => ControlReply::Accepted,
        }
    }
}

impl LocalStateV1 {
    /// A fresh, empty state at [`LOCAL_STATE_VERSION`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (replacing any existing) outbound join, clearing any previous
    /// rejection.
    pub fn set_outbound(
        &mut self,
        request: JoinRequest,
        parent: NodeId,
        pinned_operator: Option<OperatorPubKey>,
        sent_at: u64,
    ) {
        self.outbound = Some(OutboundJoin {
            request,
            parent,
            pinned_operator,
            sent_at,
        });
        self.last_rejection = None;
    }

    /// Drop the outbound join, e.g. after a synchronous rejection.
    pub fn clear_outbound(&mut self) {
        self.outbound = None;
    }

    /// The unix-seconds timestamp of the in-flight outbound join, if any.
    pub fn outbound_sent_at(&self) -> Option<u64> {
        self.outbound.as_ref().map(|outbound| outbound.sent_at)
    }

    /// The stable code of the last rejection, if any.
    pub fn rejection_code(&self) -> Option<&str> {
        self.last_rejection
            .as_ref()
            .map(|rejection| rejection.code.as_str())
    }

    /// Record a synchronous rejection of the outbound join, clearing it.
    pub fn reject_outbound(&mut self, code: &str, reason: Option<String>) {
        self.outbound = None;
        self.last_rejection = Some(Rejection {
            code: code.to_string(),
            reason,
        });
    }

    /// The UI state label: `"pending"`, `"joined"`, `"rejected"`, or `"none"`.
    pub fn status_label(&self) -> &'static str {
        if self.outbound.is_some() {
            "pending"
        } else if self.record.parent.is_some() {
            "joined"
        } else if self.last_rejection.is_some() {
            "rejected"
        } else {
            "none"
        }
    }

    /// Apply an inbound `JoinApproved`.
    ///
    /// The caller has already verified the signature; this method enforces the
    /// reply-matching rules (identical to the native node):
    ///
    /// - the parent must equal the outbound parent,
    /// - the approved child must be this client,
    /// - the approval's nonce must match the outstanding request (so a stale
    ///   approval cannot be replayed onto a later re-join),
    /// - if the join pinned an operator key, the signer must match it.
    ///
    /// On success the parent link and asserted address are installed, the
    /// outbound join is cleared, and any prior rejection is forgotten.
    pub fn on_join_approved(
        &mut self,
        self_node_id: &str,
        approval: &JoinApproval,
        origin: &NodeId,
        controller: &OperatorPubKey,
    ) -> Transition {
        let Some(outbound) = self.outbound.as_ref() else {
            return Transition::NotAttached;
        };
        if &outbound.parent != origin || approval.child.as_str() != self_node_id {
            return Transition::Denied(RejectCode::Unauthorized);
        }
        if approval.nonce != outbound.request.nonce {
            return Transition::Denied(RejectCode::Unauthorized);
        }
        if let Some(expected) = &outbound.pinned_operator
            && controller != expected
        {
            return Transition::Denied(RejectCode::Unauthorized);
        }
        self.record.parent = Some(ParentLink {
            node_id: origin.clone(),
            slot: approval.slot,
        });
        self.record.address = Some(approval.address.clone());
        self.outbound = None;
        self.last_rejection = None;
        Transition::Approved
    }

    /// Apply an inbound `JoinRejected`.
    ///
    /// The caller has already verified the signature and validated the
    /// payload. A rejection for a different parent is refused (`Denied`); when
    /// the join pinned an operator key (an invite), the signer must match it,
    /// else the rejection is denied and the outbound join is **retained** (a
    /// spoofed rejection must not cancel a real join). A stale rejection whose
    /// nonce does not match the outstanding request is likewise denied and the
    /// outbound join is retained. A rejection with no matching outbound join is
    /// a no-op (`None`).
    pub fn on_join_rejected(
        &mut self,
        rejection: &JoinRejection,
        origin: &NodeId,
        controller: &OperatorPubKey,
    ) -> Transition {
        let Some(outbound) = self.outbound.as_ref() else {
            return Transition::None;
        };
        if &outbound.parent != origin {
            return Transition::Denied(RejectCode::Unauthorized);
        }
        if let Some(expected) = &outbound.pinned_operator
            && controller != expected
        {
            return Transition::Denied(RejectCode::Unauthorized);
        }
        // Staleness check, mirroring `on_join_approved`: only a rejection whose
        // nonce answers the outstanding request may consume it, so a replayed
        // rejection cannot cancel a later re-join. A `0` nonce on either side is
        // treated as a wildcard (documented residual): the parent's CLI
        // `control reject` legitimately sends `0` when it has no pending row, so
        // an unpinned TOFU join can still be cancelled by a zero-nonce
        // rejection. Closing that fully requires making the CLI require a
        // pending row; out of scope here.
        if outbound.request.nonce != 0
            && rejection.nonce != 0
            && rejection.nonce != outbound.request.nonce
        {
            return Transition::Denied(RejectCode::Unauthorized);
        }
        self.outbound = None;
        self.last_rejection = Some(Rejection {
            code: "rejected".to_string(),
            reason: Some(rejection.reason.clone()),
        });
        Transition::Rejected {
            parent: origin.clone(),
            reason: rejection.reason.clone(),
        }
    }

    /// Apply a parent-signed `Rebase`: update the asserted address in place.
    ///
    /// A browser is a leaf, so its address is always
    /// `parent_address.child(record.parent.slot)`; the caller has already
    /// checked the notice against this client's node id and its current parent
    /// link. This method re-derives the expected address from the recorded slot
    /// (defence in depth, so a mis-dispatched call cannot install an arbitrary
    /// address) and:
    ///
    /// - returns [`Transition::Denied`]`(Unauthorized)` when there is no parent
    ///   link or the target does not descend from `parent_address` by the
    ///   recorded slot;
    /// - returns [`Transition::None`] (an idempotent no-op) when the target
    ///   already equals the asserted address;
    /// - otherwise replaces `record.address` and returns
    ///   [`Transition::Rebased`].
    ///
    /// The [`ParentLink`] is deliberately left untouched: a re-base moves the
    /// prefix, not the parent, and a browser never becomes root.
    pub fn apply_rebase(&mut self, parent_address: &OctAddr, address: &OctAddr) -> Transition {
        let Some(parent) = self.record.parent.as_ref() else {
            return Transition::Denied(RejectCode::Unauthorized);
        };
        if address != &parent_address.child(parent.slot) {
            return Transition::Denied(RejectCode::Unauthorized);
        }
        if self.record.address.as_ref() == Some(address) {
            return Transition::None;
        }
        self.record.address = Some(address.clone());
        Transition::Rebased
    }

    /// Apply a `DetachNotice` (or a local [`leave`](crate::ClientNode::leave)):
    /// clear the parent link and the asserted address.
    ///
    /// A [`ChildKind::User`](cawala_control::ChildKind::User) leaf takes the
    /// clear-both branch of the address law (it has no meaningful root `0`
    /// leaf), so after this [`Self::status_label`] returns `"none"`. Any
    /// in-flight outbound join is dropped too. Idempotent: detaching an already
    /// detached record is a no-op returning [`Transition::None`]. Child links
    /// are left alone (a browser is a leaf and keeps none in practice).
    pub fn apply_detach(&mut self) -> Transition {
        if self.record.parent.is_none() && self.record.address.is_none() {
            return Transition::None;
        }
        self.record.parent = None;
        self.record.address = None;
        self.outbound = None;
        Transition::Detached
    }

    /// The control-plane view of this state, as a [`NodeSnapshot`].
    ///
    /// Used to answer a self-admin `Query`; addresses are derived from the
    /// asserted address (`address.parent()` / `address.child(slot)`).
    pub fn to_node_snapshot(&self, node_id: &str) -> NodeSnapshot {
        let address = self.record.address.clone();
        let parent = match (&self.record.parent, &address) {
            (Some(parent), Some(address)) => {
                address.parent().map(|parent_address| ParentSnapshot {
                    node_id: parent.node_id.clone(),
                    slot: parent.slot,
                    address: parent_address,
                })
            }
            _ => None,
        };
        let children = self
            .record
            .children
            .iter()
            .map(|child| ChildSnapshot {
                child_id: child.child_id.clone(),
                kind: child.kind,
                slot: child.slot,
                address: address.as_ref().map(|address| address.child(child.slot)),
                date_joined: child.date_joined,
            })
            .collect();
        NodeSnapshot {
            node_id: NodeId::from(node_id),
            address,
            parent,
            children,
        }
    }

    /// Encode as postcard bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("local state is always postcard-encodable")
    }

    /// Decode postcard bytes, rejecting an unsupported [`Self::version`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let state: LocalStateV1 =
            postcard::from_bytes(bytes).map_err(|err| format!("invalid local state: {err}"))?;
        if state.version != LOCAL_STATE_VERSION {
            return Err(format!(
                "unsupported local state version {} (expected {LOCAL_STATE_VERSION})",
                state.version
            ));
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_control::OperatorSecretKey;
    use cawala_ledger::{LedgerPubKey, LedgerSecretKey};

    fn node(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn ledger(seed: u8) -> LedgerPubKey {
        LedgerSecretKey::from_bytes([seed; 32]).public()
    }

    fn join_request(me: &str, operator: &OperatorSecretKey) -> JoinRequest {
        JoinRequest {
            node: node(me),
            kind: ChildKind::User,
            operator: operator.public(),
            ledger: None,
            desired_slot: None,
            location_hint: None,
            nonce: 7,
            expiry: u64::MAX,
        }
    }

    fn approval_for(request: &JoinRequest) -> JoinApproval {
        JoinApproval {
            child: request.node.clone(),
            child_operator: request.operator,
            child_ledger: None,
            kind: ChildKind::User,
            slot: 2,
            address: "0.2".parse().unwrap(),
            date_joined: 10,
            nonce: request.nonce,
            parent_ledger: ledger(9),
        }
    }

    fn pending(pinned: Option<OperatorPubKey>) -> (LocalStateV1, JoinRequest) {
        let operator = operator(1);
        let request = join_request("me", &operator);
        let mut state = LocalStateV1::new();
        state.set_outbound(request.clone(), node("parent"), pinned, 5);
        (state, request)
    }

    #[test]
    fn approval_matching_installs_link_and_clears_outbound() {
        let (mut state, request) = pending(None);
        let approval = approval_for(&request);
        let transition =
            state.on_join_approved("me", &approval, &node("parent"), &operator(9).public());

        assert_eq!(transition, Transition::Approved);
        assert_eq!(transition.reply(), ControlReply::Accepted);
        assert_eq!(state.record.address, Some("0.2".parse().unwrap()));
        assert_eq!(
            state.record.parent,
            Some(ParentLink {
                node_id: node("parent"),
                slot: 2,
            })
        );
        assert!(state.outbound.is_none());
        assert_eq!(state.status_label(), "joined");
    }

    #[test]
    fn approval_for_wrong_parent_or_child_is_denied() {
        let (mut state, request) = pending(None);
        let approval = approval_for(&request);

        let wrong_parent =
            state.on_join_approved("me", &approval, &node("other"), &operator(9).public());
        assert_eq!(wrong_parent, Transition::Denied(RejectCode::Unauthorized));

        let wrong_child = state.on_join_approved(
            "someone-else",
            &approval,
            &node("parent"),
            &operator(9).public(),
        );
        assert_eq!(wrong_child, Transition::Denied(RejectCode::Unauthorized));
        assert!(state.outbound.is_some(), "outbound is retained on denial");
    }

    #[test]
    fn stale_approval_nonce_is_denied() {
        let (mut state, request) = pending(None);
        // A later re-join to the same parent uses a fresh nonce.
        let mut newer = request.clone();
        newer.nonce = 99;
        state.set_outbound(newer, node("parent"), None, 6);

        // The old approval (nonce 7) no longer answers the outstanding request.
        let stale = approval_for(&request);
        let transition =
            state.on_join_approved("me", &stale, &node("parent"), &operator(9).public());
        assert_eq!(transition, Transition::Denied(RejectCode::Unauthorized));
        assert!(state.record.parent.is_none(), "no link was installed");
        assert!(state.outbound.is_some(), "the current outbound is retained");
    }

    #[test]
    fn pinned_operator_mismatch_is_denied_and_retains_outbound() {
        let pinned = operator(9).public();
        let (mut state, request) = pending(Some(pinned));
        let approval = approval_for(&request);

        let forged =
            state.on_join_approved("me", &approval, &node("parent"), &operator(10).public());
        assert_eq!(forged, Transition::Denied(RejectCode::Unauthorized));
        assert!(state.record.parent.is_none());
        assert!(state.outbound.is_some());

        let good = state.on_join_approved("me", &approval, &node("parent"), &pinned);
        assert_eq!(good.reply(), ControlReply::Accepted);
        assert!(state.outbound.is_none());
    }

    #[test]
    fn replay_after_clear_is_not_attached() {
        let (mut state, request) = pending(None);
        let approval = approval_for(&request);
        assert_eq!(
            state
                .on_join_approved("me", &approval, &node("parent"), &operator(9).public())
                .reply(),
            ControlReply::Accepted
        );
        // The outbound join is gone, so the same approval cannot be replayed.
        let replay =
            state.on_join_approved("me", &approval, &node("parent"), &operator(9).public());
        assert_eq!(replay, Transition::NotAttached);
        assert_eq!(
            replay.reply(),
            ControlReply::Rejected(RejectCode::NotAttached)
        );
    }

    #[test]
    fn reject_flow_stores_reason_and_clears_outbound() {
        let (mut state, _) = pending(None);
        let rejection = JoinRejection {
            child: node("me"),
            reason: "no free slot".to_string(),
            nonce: 7,
        };
        let transition = state.on_join_rejected(&rejection, &node("parent"), &operator(9).public());
        assert_eq!(
            transition,
            Transition::Rejected {
                parent: node("parent"),
                reason: "no free slot".to_string(),
            }
        );
        assert_eq!(transition.reply(), ControlReply::Accepted);
        assert!(state.outbound.is_none());
        assert_eq!(state.status_label(), "rejected");
        assert_eq!(
            state.last_rejection.as_ref().unwrap().reason.as_deref(),
            Some("no free slot")
        );
    }

    #[test]
    fn reject_without_outbound_is_a_noop() {
        let mut state = LocalStateV1::new();
        let rejection = JoinRejection {
            child: node("me"),
            reason: "late".to_string(),
            nonce: 1,
        };
        assert_eq!(
            state.on_join_rejected(&rejection, &node("parent"), &operator(9).public()),
            Transition::None
        );
        assert!(state.last_rejection.is_none());
    }

    #[test]
    fn reject_for_other_parent_is_denied() {
        let (mut state, _) = pending(None);
        let rejection = JoinRejection {
            child: node("me"),
            reason: "nope".to_string(),
            nonce: 7,
        };
        assert_eq!(
            state.on_join_rejected(&rejection, &node("other"), &operator(9).public()),
            Transition::Denied(RejectCode::Unauthorized)
        );
        assert!(state.outbound.is_some());
    }

    #[test]
    fn pinned_rejection_requires_the_pinned_signer() {
        let pinned = operator(9).public();
        let (mut state, _) = pending(Some(pinned));
        let rejection = JoinRejection {
            child: node("me"),
            reason: "cancelled".to_string(),
            nonce: 7,
        };

        // A self-consistent rejection signed by a different key is denied and
        // leaves the outbound join intact.
        let forged = state.on_join_rejected(&rejection, &node("parent"), &operator(10).public());
        assert_eq!(forged, Transition::Denied(RejectCode::Unauthorized));
        assert!(state.outbound.is_some(), "outbound is retained on denial");
        assert!(state.last_rejection.is_none());

        // The pinned key's rejection is accepted and clears the outbound join.
        let good = state.on_join_rejected(&rejection, &node("parent"), &pinned);
        assert_eq!(good.reply(), ControlReply::Accepted);
        assert!(state.outbound.is_none());
        assert_eq!(state.status_label(), "rejected");
        assert_eq!(
            state.last_rejection.as_ref().unwrap().reason.as_deref(),
            Some("cancelled")
        );
    }

    #[test]
    fn unpinned_rejection_accepts_any_self_consistent_signer() {
        // A direct (`--parent`) join has no pin, so a self-consistent rejection
        // signed by an arbitrary key is accepted (unchanged TOFU behavior).
        let (mut state, _) = pending(None);
        let rejection = JoinRejection {
            child: node("me"),
            reason: "direct".to_string(),
            nonce: 7,
        };
        let transition =
            state.on_join_rejected(&rejection, &node("parent"), &operator(10).public());
        assert_eq!(transition.reply(), ControlReply::Accepted);
        assert!(state.outbound.is_none());
        assert_eq!(state.status_label(), "rejected");
    }

    #[test]
    fn stale_rejection_nonce_is_denied() {
        let (mut state, request) = pending(None);
        // A later re-join to the same parent uses a fresh nonce.
        let mut newer = request.clone();
        newer.nonce = 99;
        state.set_outbound(newer, node("parent"), None, 6);

        // The old rejection (nonce 7) no longer answers the outstanding request.
        let stale = JoinRejection {
            child: node("me"),
            reason: "stale".to_string(),
            nonce: request.nonce,
        };
        let transition = state.on_join_rejected(&stale, &node("parent"), &operator(9).public());
        assert_eq!(transition, Transition::Denied(RejectCode::Unauthorized));
        assert!(state.outbound.is_some(), "the current outbound is retained");
        assert!(state.last_rejection.is_none());
    }

    #[test]
    fn zero_rejection_nonce_is_accepted_residual() {
        // Documented residual: a `0` rejection nonce is a wildcard and still
        // cancels the outbound join. This is legitimate for the parent's CLI
        // `control reject` when it has no pending row; an unpinned TOFU join can
        // therefore still be cancelled by a zero-nonce rejection.
        let (mut state, _) = pending(None);
        let rejection = JoinRejection {
            child: node("me"),
            reason: "cli cancel".to_string(),
            nonce: 0,
        };
        let transition = state.on_join_rejected(&rejection, &node("parent"), &operator(9).public());
        assert_eq!(transition.reply(), ControlReply::Accepted);
        assert!(state.outbound.is_none());
        assert_eq!(state.status_label(), "rejected");
        assert_eq!(
            state.last_rejection.as_ref().unwrap().reason.as_deref(),
            Some("cli cancel")
        );
    }

    #[test]
    fn export_import_round_trip() {
        let (mut state, request) = pending(Some(operator(9).public()));
        state.record.children.push(ChildLink {
            child_id: node("kid"),
            kind: ChildKind::User,
            slot: 4,
            date_joined: 99,
        });
        let bytes = state.to_bytes();
        let back = LocalStateV1::from_bytes(&bytes).unwrap();
        assert_eq!(back, state);
        // The blob carries the request but no secret key material.
        assert_eq!(back.outbound.as_ref().unwrap().request.node, request.node);
    }

    #[test]
    fn import_rejects_garbage_and_wrong_version() {
        assert!(LocalStateV1::from_bytes(b"not postcard").is_err());

        let mut state = LocalStateV1::new();
        state.version = LOCAL_STATE_VERSION + 1;
        let bytes = postcard::to_allocvec(&state).unwrap();
        assert!(LocalStateV1::from_bytes(&bytes).is_err());
    }

    #[test]
    fn snapshot_derives_addresses() {
        let (mut state, request) = pending(None);
        let approval = approval_for(&request);
        state.on_join_approved("me", &approval, &node("parent"), &operator(9).public());
        state.record.children.push(ChildLink {
            child_id: node("kid"),
            kind: ChildKind::User,
            slot: 5,
            date_joined: 99,
        });

        let snapshot = state.to_node_snapshot("me");
        assert_eq!(snapshot.node_id, node("me"));
        assert_eq!(snapshot.address, Some("0.2".parse().unwrap()));
        // Our address is `parent.child(2)`, so the parent's is `0`.
        let parent = snapshot.parent.unwrap();
        assert_eq!(parent.address, "0".parse().unwrap());
        assert_eq!(parent.slot, 2);
        assert_eq!(snapshot.children[0].address, Some("0.2.5".parse().unwrap()));
    }

    #[test]
    fn status_label_progression() {
        let mut state = LocalStateV1::new();
        assert_eq!(state.status_label(), "none");
        state.set_outbound(join_request("me", &operator(1)), node("parent"), None, 1);
        assert_eq!(state.status_label(), "pending");
        state.reject_outbound("slot_taken", None);
        assert_eq!(state.status_label(), "rejected");
        assert_eq!(state.rejection_code(), Some("slot_taken"));
    }

    /// A joined leaf at `address` under `parent_id` in `slot`.
    fn joined(address: &str, parent_id: &str, slot: u8) -> LocalStateV1 {
        let mut state = LocalStateV1::new();
        state.record.address = Some(address.parse().unwrap());
        state.record.parent = Some(ParentLink {
            node_id: node(parent_id),
            slot,
        });
        state
    }

    #[test]
    fn rebase_updates_address_in_place_and_keeps_parent() {
        let mut state = joined("0.2.3", "parent", 3);
        let transition = state.apply_rebase(&"0.4".parse().unwrap(), &"0.4.3".parse().unwrap());
        assert_eq!(transition, Transition::Rebased);
        assert_eq!(transition.reply(), ControlReply::Accepted);
        assert_eq!(state.record.address, Some("0.4.3".parse().unwrap()));
        // The parent link (the slot) is unchanged by a prefix move.
        assert_eq!(
            state.record.parent,
            Some(ParentLink {
                node_id: node("parent"),
                slot: 3,
            })
        );
        assert_eq!(state.status_label(), "joined");
    }

    #[test]
    fn rebase_to_current_address_is_a_noop() {
        let mut state = joined("0.2.3", "parent", 3);
        assert_eq!(
            state.apply_rebase(&"0.2".parse().unwrap(), &"0.2.3".parse().unwrap()),
            Transition::None
        );
        assert_eq!(state.record.address, Some("0.2.3".parse().unwrap()));
    }

    #[test]
    fn rebase_without_parent_or_wrong_derivation_is_denied() {
        // No parent link: a re-base from anyone is refused.
        let mut detached = LocalStateV1::new();
        assert_eq!(
            detached.apply_rebase(&"0".parse().unwrap(), &"0.3".parse().unwrap()),
            Transition::Denied(RejectCode::Unauthorized)
        );
        assert!(detached.record.address.is_none());

        // The target must equal `parent_address.child(slot)`.
        let mut state = joined("0.2.3", "parent", 3);
        assert_eq!(
            state.apply_rebase(&"0.2".parse().unwrap(), &"0.2.4".parse().unwrap()),
            Transition::Denied(RejectCode::Unauthorized)
        );
        assert_eq!(state.record.address, Some("0.2.3".parse().unwrap()));
    }

    #[test]
    fn detach_clears_parent_address_and_outbound() {
        let (mut state, _) = pending(None);
        state.record.address = Some("0.2".parse().unwrap());
        state.record.parent = Some(ParentLink {
            node_id: node("parent"),
            slot: 2,
        });
        assert!(state.outbound.is_some());

        assert_eq!(state.apply_detach(), Transition::Detached);
        assert_eq!(Transition::Detached.reply(), ControlReply::Accepted);
        assert!(state.record.parent.is_none());
        assert!(state.record.address.is_none());
        assert!(state.outbound.is_none());
        assert_eq!(state.status_label(), "none");

        // Detaching an already detached record is an idempotent no-op.
        assert_eq!(state.apply_detach(), Transition::None);
    }

    #[test]
    fn rebase_and_detach_round_trip_at_version_1() {
        // No fields were added for exit rights, so the blob version is
        // unchanged and both transitions serialize losslessly.
        assert_eq!(LOCAL_STATE_VERSION, 1);

        let mut rebased = joined("0.2.3", "parent", 3);
        assert_eq!(
            rebased.apply_rebase(&"0.5".parse().unwrap(), &"0.5.3".parse().unwrap()),
            Transition::Rebased
        );
        let back = LocalStateV1::from_bytes(&rebased.to_bytes()).unwrap();
        assert_eq!(back.version, LOCAL_STATE_VERSION);
        assert_eq!(back, rebased);

        let mut detached = back;
        assert_eq!(detached.apply_detach(), Transition::Detached);
        let back = LocalStateV1::from_bytes(&detached.to_bytes()).unwrap();
        assert_eq!(back.version, LOCAL_STATE_VERSION);
        assert_eq!(back, detached);
        assert_eq!(back.status_label(), "none");
    }
}
