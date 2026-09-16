//! Native node integration for the direct `cawala/control/0` protocol.
//!
//! M4 phase 1 runs control **directly**: a node dials a direct neighbor over
//! [`CONTROL_ALPN`](cawala_control::CONTROL_ALPN), writes one
//! [`SignedControl`] frame, finishes the send stream, and reads one
//! [`ControlReply`] frame. One request/response per bi-directional stream.
//! Tree-routed (indirect) control is a later phase.
//!
//! # Trust boundary
//!
//! [`SignedControl`] proves *which operator key* signed a request, and
//! [`verify_control`] additionally proves that key is the one the
//! [`cawala_ledger::PeerRegistry`] binds to the `origin` node id. Neither
//! proves the request is *authorized*: [`ControlNode::receive`] applies the
//! senior-child rule (and self-admin) on top. The authenticated QUIC peer id
//! is deliberately **not** consulted for authorization — signatures are the
//! authority.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::Mutex;
use tracing::{info, warn};

use cawala_control::{
    ADMIN_GRANT_VERSION, AdminApproved, AdminJoinApprove, AdminJoinReject, AdminPendingJoin,
    AdminRedeliverJoin, AdminRejected, AdminScope, AdminSnapshot, CONTROL_ALPN,
    CONTROL_FORMAT_VERSION, CONTROL_REQUEST_MAX_TTL_SECS, CONTROL_REQUEST_TTL_SECS, ChildKind,
    ChildSnapshot, ControlError, ControlReply, ControlRequest, CreateChild, DeliveryStatus,
    DetachChild, Invite, JoinApproval, JoinRejection, JoinRequest, MAX_CONTROL_FRAME, MoveChild,
    NodeId, NodeSnapshot, OperatorPubKey, OperatorSecretKey, ParentSnapshot, ROUTED_REPLY_VERSION,
    RejectCode, RoutedControlV1, RoutedForward, RoutedReplyV1, SetAddress, SignedAdminGrant,
    SignedControl, SignedRoutedReply, is_admin_request, senior_child, verify_control,
};
use cawala_ledger::{LedgerPubKey, PeerKeys, PeerRegistry, PeerRole};
use cawala_msg::{MsgId, PeerRef, Seen, SeenConfig, SeenSet};

use crate::admin_store::AdminStore;
use crate::control_store::ControlStore;
use crate::ledger_peers;
use crate::msg::{MSG_ALPN, MsgConfig, MsgHandler, NeighborSource, RoutableSnapshot};
use crate::record::{NodeRecord, RecordError, RecordStore};

/// Default sink capacity for locally delivered envelopes when control is
/// co-hosted with messaging.
const SINK_CAPACITY: usize = 256;

/// Maximum number of distinct applicants queued for admin approval.
///
/// A join request is self-signed and needs no prior relationship, so an
/// unauthenticated peer could otherwise append unbounded rows to
/// `pending_joins.json`. Once the queue is full, new applicants are refused
/// with [`RejectCode::Capacity`]; an already-queued applicant stays idempotent.
const MAX_PENDING_JOINS: usize = 64;

/// Per-attempt deadline when delivering a queued `JoinApproved`/`JoinRejected`
/// to its applicant.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Replay-guard bounds for the per-node control engine.
///
/// Control requests are terminal, so there is no `unobserve` rollback; the
/// window only needs to outlive a retry burst.
const CONTROL_SEEN_CONFIG: SeenConfig = SeenConfig {
    max_per_origin: 256,
    max_origins: 128,
};

/// Maximum number of most-recent per-child decisions retained for redelivery.
const MAX_STORED_DECISIONS: usize = 64;

/// Placeholder delivery status in a reply produced by the engine; the
/// [`ControlHandler`] patches it after dialing the applicant.
const PENDING_DELIVERY: DeliveryStatus = DeliveryStatus::Unreachable;

/// Who an authenticated control request is acting as.
///
/// Returned by [`ControlNode::authorize`] (topology surface) and
/// [`ControlNode::authorize_admin`] (admin surface) so a handler can tell which
/// rule admitted the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// This node's own operator key (self-admin).
    SelfOperator,
    /// An operator holding an active [`AdminScope`] scoped to this node.
    Delegated(AdminScope),
    /// A directly-controlled peer (senior child) verified against the registry.
    Peer,
}

/// What a queued outbound frame answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    /// An operator-signed `JoinApproved`.
    Approved,
    /// An operator-signed `JoinRejected`.
    Rejected,
}

impl OutboundKind {
    /// Stable label for logs and audit lines.
    fn label(self) -> &'static str {
        match self {
            OutboundKind::Approved => "join-approved",
            OutboundKind::Rejected => "join-rejected",
        }
    }
}

/// A frame the engine wants delivered to an applicant after the current
/// request is answered.
#[derive(Debug, Clone)]
pub struct OutboundControl {
    /// The applicant to dial.
    pub target: NodeId,
    /// The operator-signed frame to send.
    pub signed: SignedControl,
    /// What the frame is.
    pub kind: OutboundKind,
}

/// The local control engine: persisted links plus the judge of who may mutate
/// them.
///
/// One instance is shared behind a [`tokio::sync::Mutex`] by the
/// [`ControlHandler`]. `receive` takes `&mut self` because applying a request
/// mutates the record/peer/pending stores and persists them.
#[derive(Debug)]
pub struct ControlNode {
    data_dir: PathBuf,
    node_id: String,
    operator: OperatorSecretKey,
    record: RecordStore,
    peers: PeerRegistry,
    pending: ControlStore,
    admins: AdminStore,
    /// Frames to deliver after the current request is answered. Drained by the
    /// `ControlHandler` while it still holds the engine lock.
    outbound: VecDeque<OutboundControl>,
    /// Most-recent operator-signed decision per child, for redelivery.
    decisions: VecDeque<SignedControl>,
    /// Per-node replay guard keyed `origin:controller`, id = request nonce.
    seen: SeenSet,
}

impl ControlNode {
    /// Build an engine from already-open stores.
    pub fn new(
        data_dir: impl Into<PathBuf>,
        node_id: impl Into<String>,
        operator: OperatorSecretKey,
        record: RecordStore,
        peers: PeerRegistry,
        pending: ControlStore,
        admins: AdminStore,
    ) -> Self {
        ControlNode {
            data_dir: data_dir.into(),
            node_id: node_id.into(),
            operator,
            record,
            peers,
            pending,
            admins,
            outbound: VecDeque::new(),
            decisions: VecDeque::new(),
            seen: SeenSet::new(CONTROL_SEEN_CONFIG),
        }
    }

    /// Open (or create) the node's record, peers, pending-join, and admin-grant
    /// state from `data_dir`.
    ///
    /// `admins.json` is validated against this node's operator key: a corrupt
    /// or mis-scoped document fails the open (fail closed).
    pub fn open(
        data_dir: impl Into<PathBuf>,
        node_id: &str,
        operator: OperatorSecretKey,
    ) -> Result<Self, ControlError> {
        let data_dir = data_dir.into();
        let record = RecordStore::open(&data_dir, node_id)
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        let peers = ledger_peers::load_peers(&data_dir)
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        let pending =
            ControlStore::open(&data_dir).map_err(|err| ControlError::Codec(err.to_string()))?;
        let admins = AdminStore::load(&data_dir, node_id, &operator.public())
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        Ok(ControlNode {
            data_dir,
            node_id: node_id.to_string(),
            operator,
            record,
            peers,
            pending,
            admins,
            outbound: VecDeque::new(),
            decisions: VecDeque::new(),
            seen: SeenSet::new(CONTROL_SEEN_CONFIG),
        })
    }

    /// This node's id.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// This node's data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// This node's record.
    pub fn record(&self) -> &NodeRecord {
        self.record.record()
    }

    /// This node's peer registry.
    pub fn peers(&self) -> &PeerRegistry {
        &self.peers
    }

    /// This node's pending/outbound join state.
    pub fn pending(&self) -> &ControlStore {
        &self.pending
    }

    /// This node's admin-grant store.
    pub fn admins(&self) -> &AdminStore {
        &self.admins
    }

    /// This node's operator public key.
    pub fn operator_public(&self) -> OperatorPubKey {
        self.operator.public()
    }

    /// Drain the frames queued for delivery by the last `receive*` call.
    pub fn take_outbound(&mut self) -> Vec<OutboundControl> {
        self.outbound.drain(..).collect()
    }

    /// The senior child rule: `origin` may control this node iff it is this
    /// node (self-admin) or the most senior child (earliest `date_joined`,
    /// ties broken by ascending node id).
    ///
    /// This is *authorization only*; the caller still authenticates the
    /// signature (self-admin) or calls [`verify_control`] (child).
    fn authorized(&self, origin: &NodeId) -> bool {
        if origin.as_str() == self.node_id {
            return true;
        }
        senior_child(&self.seniority()).is_some_and(|id| id == origin)
    }

    /// This node's *node* children as `(node_id, date_joined)` pairs, in record
    /// order. [`senior_child`] is order-independent.
    ///
    /// `ChildKind::User` children are excluded: they are browser clients, not
    /// routing peers, and must never be eligible for senior-child control. Only
    /// `ChildKind::Node` children carry topology authority.
    fn seniority(&self) -> Vec<(NodeId, u64)> {
        self.record
            .record()
            .children
            .iter()
            .filter(|child| child.kind == ChildKind::Node)
            .map(|child| (NodeId::from(child.child_id.clone()), child.date_joined))
            .collect()
    }

    /// Authenticate and authorize a topology-changing request.
    ///
    /// This is the **strict** surface: self-origin must be signed by this
    /// node's own operator key, and any other origin must be the senior child
    /// and verify against the peer registry. A *delegated admin* (an operator
    /// with an [`AdminScope`] but not this node's operator key, and not a
    /// senior child) therefore never passes here, so it can never reach
    /// `CreateChild`/`DetachChild`/`MoveChild`/`SetAddress`/`Query`. Use
    /// [`ControlNode::authorize_admin`] for the admin surface.
    fn authorize(&self, signed: &SignedControl, _now: u64) -> Result<Authority, RejectCode> {
        if !self.authorized(&signed.origin) {
            return Err(RejectCode::Unauthorized);
        }
        if signed.origin.as_str() == self.node_id {
            // Self-admin: the controller must be this node's own operator key.
            if signed.controller != self.operator.public() || signed.verify_signature().is_err() {
                return Err(RejectCode::Unauthorized);
            }
            return Ok(Authority::SelfOperator);
        }
        verify_control(signed, &self.peers).map_err(|err| map_control_error(&err))?;
        Ok(Authority::Peer)
    }

    /// Authenticate and authorize an **admin** request.
    ///
    /// Requirements, all mandatory:
    /// - `signed.origin` is this node (`self.node_id`), so a peer or senior
    ///   child can never drive the admin surface;
    /// - the request is one of the `is_admin_request` variants;
    /// - the controller is either this node's own operator key (self-admin) or
    ///   an operator holding an active [`AdminScope`] granted by this node.
    ///
    /// The grant store is refreshed from disk before this is consulted (see
    /// [`ControlNode::receive_at`]); a grant is only active while
    /// `now <= expiry`.
    fn authorize_admin(&self, signed: &SignedControl, now: u64) -> Result<Authority, RejectCode> {
        if signed.origin.as_str() != self.node_id {
            return Err(RejectCode::Unauthorized);
        }
        if !is_admin_request(&signed.request) {
            return Err(RejectCode::Unauthorized);
        }
        if signed.controller == self.operator.public() {
            return Ok(Authority::SelfOperator);
        }
        match self.admins.active_scope(&signed.controller, now) {
            Some(scope) => Ok(Authority::Delegated(scope)),
            None => Err(RejectCode::Unauthorized),
        }
    }

    /// Handle one incoming request and produce its reply.
    ///
    /// Uses the system clock for join-expiry checks. Tests that need
    /// deterministic time call [`ControlNode::receive_at`]. The authenticated
    /// QUIC `remote` is informational only.
    pub async fn receive(
        &mut self,
        remote: iroh::EndpointId,
        signed: cawala_control::SignedControl,
    ) -> cawala_control::ControlReply {
        self.receive_at(remote, signed, now_unix_seconds()).await
    }

    /// [`ControlNode::receive`] with a caller-supplied clock (unix seconds).
    ///
    /// The checks run strictly in this order:
    /// 1. wire version is [`CONTROL_FORMAT_VERSION`];
    /// 2. the operator signature verifies under `signed.controller`;
    /// 3. `now <= expiry <= now + CONTROL_REQUEST_MAX_TTL_SECS`;
    /// 4. admin grants are reloaded from disk (fail closed to empty);
    /// 5. the `(origin, controller, nonce)` replay guard;
    /// 6. dispatch.
    pub async fn receive_at(
        &mut self,
        _remote: EndpointId,
        signed: SignedControl,
        now: u64,
    ) -> ControlReply {
        if signed.version != CONTROL_FORMAT_VERSION {
            return ControlReply::Rejected(RejectCode::BadVersion);
        }
        if signed.verify_signature().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if now > signed.expiry {
            return ControlReply::Rejected(RejectCode::Expired);
        }
        if signed.expiry > now.saturating_add(CONTROL_REQUEST_MAX_TTL_SECS) {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        // Full reload so a grant/revoke performed by a separate operator CLI
        // process is observed without a restart. On any load failure, serve no
        // delegated authority (fail closed).
        if let Err(err) = self
            .admins
            .reload(&self.data_dir, &self.node_id, &self.operator.public())
        {
            warn!(%err, "admin grant reload failed; serving no delegated authority");
            self.admins = AdminStore::empty();
        }
        // Replay guard: per (origin, controller), keyed by the request nonce.
        // Control requests are terminal, so a marked nonce is never unobserved.
        let seen_origin = format!("{}:{}", signed.origin, signed.controller);
        if self.seen.observe(&seen_origin, nonce_msg_id(signed.nonce)) == Seen::Duplicate {
            let reply = ControlReply::Rejected(RejectCode::Replay);
            self.audit_request(&signed, &reply, now);
            return reply;
        }
        let reply = match &signed.request {
            ControlRequest::Join(join) => self.handle_join(&signed, join, now),
            ControlRequest::JoinApproved(approval) => self.handle_join_approved(&signed, approval),
            ControlRequest::JoinRejected(rejection) => {
                self.handle_join_rejected(&signed, rejection)
            }
            ControlRequest::CreateChild(create) => self.handle_create_child(&signed, create, now),
            ControlRequest::DetachChild(detach) => self.handle_detach_child(&signed, detach, now),
            ControlRequest::MoveChild(move_child) => {
                self.handle_move_child(&signed, move_child, now)
            }
            ControlRequest::SetAddress(set) => self.handle_set_address(&signed, set, now),
            ControlRequest::Query => self.handle_query(&signed, now),
            ControlRequest::AdminQuery => self.handle_admin_query(&signed, now),
            ControlRequest::AdminApproveJoin(approve) => {
                self.handle_admin_approve_join(&signed, approve, now)
            }
            ControlRequest::AdminRejectJoin(reject) => {
                self.handle_admin_reject_join(&signed, reject, now)
            }
            ControlRequest::AdminRedeliverJoin(redeliver) => {
                self.handle_admin_redeliver_join(&signed, redeliver, now)
            }
        };
        self.audit_request(&signed, &reply, now);
        reply
    }

    /// Handle one routed control request, using the system clock.
    ///
    /// See [`ControlNode::receive_routed_at`]. The envelope-level coherence
    /// checks (`requester == env.src`, `forwards.len() == hop_chain.len()`,
    /// per-index hop match) are enforced by the caller
    /// (`dispatch_control_envelope`) because they need the transport envelope;
    /// everything that is a property of the routed payload plus `remote` is
    /// enforced here.
    pub async fn receive_routed(
        &mut self,
        remote: EndpointId,
        routed: RoutedControlV1,
    ) -> ControlReply {
        self.receive_routed_at(remote, routed, now_unix_seconds()).await
    }

    /// Handle one routed control request reaching this node as its destination.
    ///
    /// The transport has already checked the envelope: the hop chain is a
    /// plausible path, this node is the destination, the chain's last hop is the
    /// authenticated QUIC `remote` and a direct neighbor, and `(src, msg_id)` is
    /// not a replay. `remote` is the authenticated final hop, so it — not any
    /// unauthenticated `RoutedForward.hop` — is authority.
    ///
    /// Checks here, in order:
    /// 1. [`RoutedControlV1::validate`] (version, bounded forwards, intent
    ///    version, per-forward request/origin coherence);
    /// 2. `target.node`/`target.addr` name this node;
    /// 3. the carried intent self-verifies and its expiry is inside the TTL cap;
    /// 4. a forward exists, its `hop.node` is the authenticated `remote`, and
    ///    the destination's registry verifies it;
    /// 5. class gate:
    ///    - `Join`/`JoinApproved`/`JoinRejected` are refused on the routed path;
    ///    - admin requests dispatch the **intent** (so the existing
    ///      `authorize_admin` grant store, replay, and TTL rules apply verbatim);
    ///    - a self-operator intent dispatches the intent;
    ///    - topology requests dispatch the **last hop's** signed control, and
    ///      only when it is this node's senior node child (`Authority::Peer`).
    ///
    /// A carried [`SignedAdminGrant`] is verified for audit only: it must verify
    /// under this node's operator, be scoped to this node, and name the intent
    /// controller, but it never authorizes on its own — the
    /// [`AdminStore`](crate::admin_store::AdminStore) is the authority, so a
    /// revoke wins over a still-valid carried grant.
    pub async fn receive_routed_at(
        &mut self,
        remote: EndpointId,
        routed: RoutedControlV1,
        now: u64,
    ) -> ControlReply {
        if routed.validate().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if routed.target.node != self.node_id {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if self.record.record().address.as_ref() != Some(&routed.target.addr) {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if routed.intent.verify_signature().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if now > routed.intent.expiry {
            return ControlReply::Rejected(RejectCode::Expired);
        }
        if routed.intent.expiry > now.saturating_add(CONTROL_REQUEST_MAX_TTL_SECS) {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }

        // The predecessor is authority; `RoutedForward.hop` alone never is.
        let Some(last) = routed.forwards.last() else {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        };
        if last.hop.node != remote.to_string() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if self.verify_forward(last).is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }

        // Join traffic is direct-only: a routed `Join`/`JoinApproved`/
        // `JoinRejected` is never accepted, whatever its signatures say.
        if matches!(
            &routed.intent.request,
            ControlRequest::Join(_)
                | ControlRequest::JoinApproved(_)
                | ControlRequest::JoinRejected(_)
        ) {
            self.audit(serde_json::json!({
                "ts": now,
                "event": "routed-refused",
                "kind": routed.intent.request.kind(),
                "origin": routed.intent.origin.to_string(),
                "requester": routed.requester.node,
                "forwarder": last.hop.node,
                "hops": routed.forwards.len(),
                "routed": true,
            }));
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }

        // Routing context recorded on every dispatched routed request. `last` is
        // the authenticated predecessor (the msg layer bound it to the QUIC
        // remote); this is accountability evidence, never authority.
        let requester = routed.requester.node.clone();
        let forwarder = last.hop.node.clone();
        let hops = routed.forwards.len();
        let kind = routed.intent.request.kind();

        // Admin class: dispatch the end-to-end intent; its origin is already
        // this node, so the untouched `authorize_admin` path (store + replay +
        // TTL) decides.
        if is_admin_request(&routed.intent.request) {
            if let Some(grant) = &routed.grant {
                let well_formed = grant.grant.validate().is_ok()
                    && grant.verify(&self.operator.public()).is_ok()
                    && grant.grant.node.as_str() == self.node_id
                    && grant.grant.admin == routed.intent.controller;
                if !well_formed {
                    return ControlReply::Rejected(RejectCode::Unauthorized);
                }
                // Evidence, not authority: record when the store does not back
                // the carried grant, then let `authorize_admin` refuse it.
                if self
                    .admins
                    .active_scope(&routed.intent.controller, now)
                    .is_none()
                {
                    self.audit(serde_json::json!({
                        "ts": now,
                        "event": "grant_store_missing",
                        "admin": routed.intent.controller.to_string(),
                        "node": self.node_id,
                        "requester": routed.requester.node,
                        "forwarder": last.hop.node,
                        "hops": routed.forwards.len(),
                        "routed": true,
                    }));
                }
            }
            let reply = self.receive_at(remote, routed.intent, now).await;
            self.audit_routed(now, kind, &reply, &requester, &forwarder, hops);
            return reply;
        }

        // Self-operator class: the intent is addressed to this node and signed
        // by this node's own operator key.
        if routed.intent.origin.as_str() == self.node_id
            && routed.intent.controller == self.operator.public()
        {
            let reply = self.receive_at(remote, routed.intent, now).await;
            self.audit_routed(now, kind, &reply, &requester, &forwarder, hops);
            return reply;
        }

        // Topology class: only the immediate predecessor's own signed control
        // is dispatched, and only if it is this node's senior node child.
        match self.authorize(&last.signed, now) {
            Ok(Authority::Peer) => {}
            _ => return ControlReply::Rejected(RejectCode::Unauthorized),
        }
        let last_signed = last.signed.clone();
        let reply = self.receive_at(remote, last_signed, now).await;
        self.audit_routed(now, kind, &reply, &requester, &forwarder, hops);
        reply
    }

    /// Re-sign `request` as this node's own per-hop routed forward.
    ///
    /// The returned forward's `hop` is this node's record address and id, and
    /// its `signed` control's origin is this node, so structural coherence
    /// (`hop.node == signed.origin`) holds by construction. A node with no
    /// asserted address cannot forward routed control.
    pub fn sign_forward(&self, request: &ControlRequest) -> Result<RoutedForward, ControlError> {
        let address = self.record.record().address.clone().ok_or_else(|| {
            ControlError::Codec(
                "cannot sign a routed forward without an asserted address".to_string(),
            )
        })?;
        let signed = SignedControl::authorize(
            NodeId::from(self.node_id.clone()),
            &self.operator,
            fresh_nonce(),
            now_unix_seconds().saturating_add(CONTROL_REQUEST_TTL_SECS),
            request.clone(),
        )?;
        Ok(RoutedForward::new(
            PeerRef {
                addr: address,
                node: self.node_id.clone(),
            },
            signed,
        ))
    }

    /// Verify one per-hop forward against this node's registry.
    ///
    /// `verify_control` binds the forward's `origin` to the operator key the
    /// registry knows (the stronger form of the `hop.node == origin` string
    /// check, which is also enforced structurally). A forward whose hop and
    /// signed origin disagree is refused.
    pub fn verify_forward(&self, forward: &RoutedForward) -> Result<(), RejectCode> {
        verify_control(&forward.signed, &self.peers).map_err(|err| map_control_error(&err))?;
        if forward.hop.node != forward.signed.origin.as_str() {
            return Err(RejectCode::Unauthorized);
        }
        Ok(())
    }

    /// Build and sign a routed reply as this node.
    ///
    /// The responder is this node's id and record address; the signature is the
    /// routed-reply domain ([`ROUTED_REPLY_CONTEXT`](cawala_control::ROUTED_REPLY_CONTEXT))
    /// under this node's operator key. A node with no asserted address cannot
    /// answer routed control.
    pub fn sign_routed_reply(
        &self,
        reply_to: MsgId,
        requester: PeerRef,
        reply: ControlReply,
    ) -> Result<SignedRoutedReply, ControlError> {
        let address = self.record.record().address.clone().ok_or_else(|| {
            ControlError::Codec("cannot sign a routed reply without an asserted address".to_string())
        })?;
        let routed = RoutedReplyV1 {
            version: ROUTED_REPLY_VERSION,
            reply_to,
            requester,
            responder: PeerRef {
                addr: address,
                node: self.node_id.clone(),
            },
            reply,
        };
        SignedRoutedReply::authorize(routed, &self.operator)
            .map_err(|err| ControlError::Codec(err.to_string()))
    }

    /// Applicant side: queue the outbound join so a later `JoinApproved` /
    /// `JoinRejected` from `parent` can be matched.
    ///
    /// `pinned_operator` is the parent's operator key when the join was started
    /// from an [`Invite`](cawala_control::Invite); it is then enforced in
    /// [`ControlNode::handle_join_approved`]. Pass `None` for a direct
    /// `--parent` join.
    pub fn begin_outbound_join(
        &mut self,
        request: JoinRequest,
        parent: NodeId,
        pinned_operator: Option<OperatorPubKey>,
    ) -> Result<(), ControlError> {
        self.pending.set_outbound(request, parent, pinned_operator);
        self.pending
            .save()
            .map_err(|err| ControlError::Codec(err.to_string()))
    }

    /// Parent side: consume the pending request for `node`, assign it a slot,
    /// attach it to this node's record, register its peer keys, and return the
    /// [`JoinApproval`] to send back to the applicant.
    ///
    /// `parent_ledger` is this node's own ledger public key (from
    /// [`LedgerService::ledger_key_public`](crate::LedgerService::ledger_key_public)).
    /// It is carried in the approval so the child can persist the parent's row
    /// and later verify the parent's signed settlement hops.
    ///
    /// Requires this node to have an asserted [`NodeRecord::address`].
    pub fn approve_pending(
        &mut self,
        node: &str,
        slot: Option<u8>,
        now: u64,
        parent_ledger: LedgerPubKey,
    ) -> Result<JoinApproval, ControlError> {
        let node_id = NodeId::from(node);
        let Some(request) = self.pending.pending_for(&node_id).cloned() else {
            return Err(ControlError::Codec(format!("no pending join for '{node}'")));
        };

        let base_address =
            self.record.record().address.clone().ok_or_else(|| {
                ControlError::Codec("this node has no asserted address".to_string())
            })?;

        let slot = match slot {
            Some(s) => {
                if s > cawala_topology::MAX_SLOT {
                    return Err(ControlError::SlotOutOfRange(s));
                }
                if self.record.record().children.iter().any(|c| c.slot == s) {
                    return Err(ControlError::Codec(format!("slot {s} is already taken")));
                }
                s
            }
            None => lowest_free_slot(self.record.record())
                .ok_or_else(|| ControlError::Codec("node is full".to_string()))?,
        };
        let child_address = base_address.child(slot);

        // Only now consume the pending row.
        self.pending.remove_pending(&node_id);

        if let Err(err) =
            self.record
                .attach_child(request.node.as_str(), request.kind, Some(slot), now)
        {
            self.pending.add_pending(request);
            return Err(ControlError::Codec(err.to_string()));
        }

        let role = match request.kind {
            ChildKind::Node => PeerRole::Node,
            ChildKind::User => PeerRole::User,
        };
        let peer = PeerKeys {
            node_id: request.node.clone(),
            operator: request.operator,
            ledger: request.ledger,
            role,
        };
        if let Err(err) = self.peers.insert(peer) {
            let _ = self.record.detach_child(request.node.as_str());
            self.pending.add_pending(request);
            return Err(ControlError::Codec(err.to_string()));
        }

        self.record
            .save()
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        ledger_peers::save_peers(&self.data_dir, &self.peers)
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        self.pending
            .save()
            .map_err(|err| ControlError::Codec(err.to_string()))?;

        Ok(JoinApproval {
            child: request.node,
            child_operator: request.operator,
            child_ledger: request.ledger,
            kind: request.kind,
            slot,
            address: child_address,
            date_joined: now,
            nonce: request.nonce,
            parent_ledger,
        })
    }

    /// Parent side: drop the pending request for `node` after sending a
    /// `JoinRejected`.
    pub fn reject_pending(&mut self, node: &str) -> Result<(), ControlError> {
        self.pending.remove_pending(&NodeId::from(node));
        self.pending
            .save()
            .map_err(|err| ControlError::Codec(err.to_string()))
    }

    /// Self-admin or senior-child only: build the node's current snapshot.
    pub fn snapshot(&self) -> NodeSnapshot {
        let record = self.record.record();
        let address = record.address.clone();
        let parent = match (&record.parent, &address) {
            (Some(parent), Some(address)) => {
                address.parent().map(|parent_address| ParentSnapshot {
                    node_id: NodeId::from(parent.parent_id.clone()),
                    slot: parent.slot,
                    address: parent_address,
                })
            }
            _ => None,
        };
        let children = record
            .children
            .iter()
            .map(|child| ChildSnapshot {
                child_id: NodeId::from(child.child_id.clone()),
                kind: child.kind,
                slot: child.slot,
                address: address.as_ref().map(|address| address.child(child.slot)),
                date_joined: child.date_joined,
            })
            .collect();
        NodeSnapshot {
            node_id: NodeId::from(self.node_id.clone()),
            address,
            parent,
            children,
        }
    }

    fn handle_join(
        &mut self,
        signed: &SignedControl,
        join: &JoinRequest,
        now: u64,
    ) -> ControlReply {
        // The applicant self-signs and must be the named node/operator.
        if signed.verify_signature().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if signed.controller != join.operator || signed.origin != join.node {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if join.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        if now > join.expiry {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        // Idempotent: an already-queued request stays queued.
        if self.pending.pending_for(&join.node).is_some() {
            return ControlReply::Pending;
        }
        // Capacity check: an explicit slot must be free, otherwise the parent
        // picks the lowest free slot; a full node refuses.
        match join.desired_slot {
            Some(slot) => {
                if self.record.record().children.iter().any(|c| c.slot == slot) {
                    return ControlReply::Rejected(RejectCode::SlotTaken);
                }
            }
            None => {
                if lowest_free_slot(self.record.record()).is_none() {
                    return ControlReply::Rejected(RejectCode::Capacity);
                }
            }
        }
        // Bound the pending-join queue so an unauthenticated peer cannot bloat
        // `pending_joins.json` with unlimited distinct applicants. An applicant
        // that is already queued returned `Pending` above and is unaffected.
        if self.pending.pending().len() >= MAX_PENDING_JOINS
            && self.pending.pending_for(&join.node).is_none()
        {
            return ControlReply::Rejected(RejectCode::Capacity);
        }
        self.pending.add_pending(join.clone());
        if self.pending.save().is_err() {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        ControlReply::Pending
    }

    /// Applicant side: apply a parent's [`JoinApproval`] by setting the parent
    /// link and the assigned address, and persist the parent's row (operator
    /// and ledger keys) to `ledger_peers.json`.
    ///
    /// The approval must answer the *current* outbound request: `approval.nonce`
    /// must equal the outstanding request's nonce, so an authentic but stale
    /// approval cannot be replayed onto a later re-join.
    ///
    /// # Pinning closes the trust-on-first-use gap
    ///
    /// For a direct `--parent` join the applicant has no prior knowledge of the
    /// parent's operator key, so the first signature it sees is trusted
    /// (trust-on-first-use): the approval only has to be *self*-consistent.
    /// An invite removes that gap by carrying the parent's operator key
    /// out-of-band; when
    /// [`OutboundJoin::pinned_operator`](crate::control_store::OutboundJoin::pinned_operator)
    /// is `Some`, this method additionally requires `signed.controller` to equal the pinned
    /// key and rejects the approval as [`RejectCode::Unauthorized`] otherwise.
    /// The `None` case keeps the previous behavior unchanged.
    ///
    /// # v1 gap: assigned-address subtree is not verified
    ///
    /// v1 accepts whatever address the parent assigns without checking that it
    /// lies within the parent's subtree. At approval time the applicant has no
    /// knowledge of the parent's asserted address, so there is nothing to
    /// check against; an honest parent derives the child address as
    /// `parent_address.child(slot)`, but a malicious parent can assign an
    /// arbitrary address. This is an accepted v1 gap, recorded here so it is
    /// not mistaken for a guarantee.
    fn handle_join_approved(
        &mut self,
        signed: &SignedControl,
        approval: &JoinApproval,
    ) -> ControlReply {
        if signed.verify_signature().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        let Some(outbound) = self.pending.outbound().cloned() else {
            return ControlReply::Rejected(RejectCode::NotAttached);
        };
        if outbound.parent != signed.origin || outbound.request.node != approval.child {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        // The approval must answer the *current* outbound request. An authentic
        // but stale approval (an earlier join's nonce) must not be applied to a
        // later re-join: it would reset the parent link/address/slot and, now
        // that the approval carries the parent ledger key, replace a newer key
        // with an old one.
        if approval.nonce != outbound.request.nonce {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        // An invite pins the parent's operator key: the approval must be signed
        // by exactly that key, not merely by any self-consistent one.
        if let Some(expected) = outbound.pinned_operator
            && signed.controller != expected
        {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        // The parent's ledger key must be present and non-degenerate; a zero
        // key would install an unusable registry row.
        if approval.parent_ledger.to_bytes() == [0u8; 32] {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }

        let record_backup = self.record.clone();
        let peers_backup = self.peers.clone();
        if let Err(err) = self
            .record
            .set_parent(signed.origin.as_str(), approval.slot)
        {
            return ControlReply::Rejected(map_record_error(&err));
        }
        if let Err(err) = self.record.set_address(approval.address.clone()) {
            self.record = record_backup;
            return ControlReply::Rejected(map_record_error(&err));
        }
        // Persist the parent's row (from the signed approval) so the parent's
        // carried settlement hops become resolvable. A conflicting pre-existing
        // row is refused; an identical row is idempotent.
        if let Err(code) = self.remember_parent_peer(signed, approval) {
            self.record = record_backup;
            self.peers = peers_backup;
            return ControlReply::Rejected(code);
        }
        if self.record.save().is_err()
            || ledger_peers::save_peers(&self.data_dir, &self.peers).is_err()
        {
            self.record = record_backup;
            self.peers = peers_backup;
            return ControlReply::Rejected(RejectCode::Internal);
        }
        self.pending.clear_outbound();
        if self.pending.save().is_err() {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        ControlReply::Accepted
    }

    /// Record the approving parent in this node's peer registry.
    ///
    /// The row binds the parent's node id to the operator key that signed the
    /// approval and the ledger key the approval carries. Idempotent: an
    /// existing identical row is kept.
    ///
    /// A row with the **same operator** (and role) but a different ledger key is
    /// *updated* to the approval's `parent_ledger`: the signed approval is
    /// authoritative, and a parent that legitimately regenerated its ledger key
    /// (restored `node.json`, lost ledger key) must not be permanently locked
    /// out of re-attaching its child. A conflicting operator or role is still
    /// refused. The caller persists the registry and rolls it back on error.
    fn remember_parent_peer(
        &mut self,
        signed: &SignedControl,
        approval: &JoinApproval,
    ) -> Result<(), RejectCode> {
        let expected = PeerKeys {
            node_id: signed.origin.clone(),
            operator: signed.controller,
            ledger: Some(approval.parent_ledger),
            role: PeerRole::Node,
        };
        let existing = self.peers.get(&signed.origin).cloned();
        match existing {
            Some(existing) if existing == expected => Ok(()),
            Some(existing)
                if existing.operator == expected.operator && existing.role == expected.role =>
            {
                self.replace_parent_ledger(&signed.origin, approval.parent_ledger)
            }
            Some(_) => Err(RejectCode::Unauthorized),
            None => self
                .peers
                .insert(expected)
                .map_err(|_| RejectCode::Unauthorized),
        }
    }

    /// Replace an existing parent row's ledger key, preserving its operator.
    ///
    /// `PeerRegistry` exposes no in-place update or removal (and the ledger
    /// crate is out of scope here), so rebuild it from its canonical
    /// seq-of-rows serde form with the one key swapped. The rebuild is into a
    /// fresh registry, so a failure (e.g. a ledger-key collision) leaves
    /// `self.peers` untouched.
    fn replace_parent_ledger(
        &mut self,
        parent: &NodeId,
        ledger: LedgerPubKey,
    ) -> Result<(), RejectCode> {
        let value = serde_json::to_value(&self.peers).map_err(|_| RejectCode::Internal)?;
        let rows =
            serde_json::from_value::<Vec<PeerKeys>>(value).map_err(|_| RejectCode::Internal)?;
        let mut rebuilt = PeerRegistry::new();
        for mut row in rows {
            if &row.node_id == parent {
                row.ledger = Some(ledger);
            }
            rebuilt.insert(row).map_err(|_| RejectCode::Unauthorized)?;
        }
        self.peers = rebuilt;
        Ok(())
    }

    fn handle_join_rejected(
        &mut self,
        signed: &SignedControl,
        rejection: &JoinRejection,
    ) -> ControlReply {
        if signed.verify_signature().is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if rejection.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        match self.pending.outbound().cloned() {
            None => ControlReply::Accepted,
            Some(outbound) if outbound.parent != signed.origin => {
                ControlReply::Rejected(RejectCode::Unauthorized)
            }
            Some(outbound) => {
                // An invite pins the parent's operator key: the rejection must
                // be signed by exactly that key, not merely by any
                // self-consistent one. On mismatch the outbound join is left
                // intact (a spoofed rejection must not cancel a real join).
                // A direct `--parent` join (`pinned_operator == None`) keeps the
                // old trust-on-first-use behavior, as with approvals.
                if let Some(expected) = outbound.pinned_operator
                    && signed.controller != expected
                {
                    return ControlReply::Rejected(RejectCode::Unauthorized);
                }
                self.pending.clear_outbound();
                if self.pending.save().is_err() {
                    return ControlReply::Rejected(RejectCode::Internal);
                }
                ControlReply::Accepted
            }
        }
    }

    fn handle_create_child(
        &mut self,
        signed: &SignedControl,
        create: &CreateChild,
        now: u64,
    ) -> ControlReply {
        if let Err(code) = self.authorize(signed, now) {
            return ControlReply::Rejected(code);
        }
        let backup = self.record.clone();
        if let Err(err) = self.record.attach_child(
            create.child.as_str(),
            create.kind,
            create.slot,
            create.date_joined,
        ) {
            return ControlReply::Rejected(map_record_error(&err));
        }
        let role = match create.kind {
            ChildKind::Node => PeerRole::Node,
            ChildKind::User => PeerRole::User,
        };
        let peer = PeerKeys {
            node_id: create.child.clone(),
            operator: create.operator,
            ledger: create.ledger,
            role,
        };
        if let Err(err) = self.peers.insert(peer) {
            self.record = backup;
            return ControlReply::Rejected(map_ledger_error(&err));
        }
        if self.record.save().is_err()
            || ledger_peers::save_peers(&self.data_dir, &self.peers).is_err()
        {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        ControlReply::Accepted
    }

    fn handle_detach_child(
        &mut self,
        signed: &SignedControl,
        detach: &DetachChild,
        now: u64,
    ) -> ControlReply {
        if let Err(code) = self.authorize(signed, now) {
            return ControlReply::Rejected(code);
        }
        if let Err(err) = self.record.detach_child(detach.child.as_str()) {
            return ControlReply::Rejected(map_record_error(&err));
        }
        // The peer registry entry is intentionally left in place: a detached
        // child may be re-attached, and stale peer rows are harmless.
        if self.record.save().is_err() {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        ControlReply::Accepted
    }

    fn handle_move_child(
        &mut self,
        signed: &SignedControl,
        move_child: &MoveChild,
        now: u64,
    ) -> ControlReply {
        if let Err(code) = self.authorize(signed, now) {
            return ControlReply::Rejected(code);
        }
        // v1 supports only re-slotting a direct child under this node.
        if move_child.new_parent.as_str() != self.node_id {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        let Some((kind, date_joined)) = self
            .record
            .record()
            .children
            .iter()
            .find(|child| child.child_id == move_child.child.as_str())
            .map(|child| (child.kind, child.date_joined))
        else {
            return ControlReply::Rejected(RejectCode::NotFound);
        };
        let backup = self.record.clone();
        if let Err(err) = self.record.detach_child(move_child.child.as_str()) {
            return ControlReply::Rejected(map_record_error(&err));
        }
        if let Err(err) = self.record.attach_child(
            move_child.child.as_str(),
            kind,
            move_child.slot,
            date_joined,
        ) {
            self.record = backup;
            return ControlReply::Rejected(map_record_error(&err));
        }
        if self.record.save().is_err() {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        ControlReply::Accepted
    }

    fn handle_set_address(
        &mut self,
        signed: &SignedControl,
        set: &SetAddress,
        now: u64,
    ) -> ControlReply {
        if let Err(code) = self.authorize(signed, now) {
            return ControlReply::Rejected(code);
        }
        let result = match &set.address {
            Some(address) => self.record.set_address(address.clone()),
            None => self.record.unset_address(),
        };
        if let Err(err) = result {
            return ControlReply::Rejected(map_record_error(&err));
        }
        if self.record.save().is_err() {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        ControlReply::Accepted
    }

    fn handle_query(&mut self, signed: &SignedControl, now: u64) -> ControlReply {
        if let Err(code) = self.authorize(signed, now) {
            return ControlReply::Rejected(code);
        }
        ControlReply::Snapshot(self.snapshot())
    }

    /// Admin: return this node's control snapshot plus the joins awaiting
    /// approval.
    ///
    /// Pending rows are capped by [`MAX_PENDING_JOINS`]; the untrusted
    /// `location_hint` on a [`JoinRequest`] is deliberately omitted.
    fn handle_admin_query(&mut self, signed: &SignedControl, now: u64) -> ControlReply {
        if let Err(code) = self.authorize_admin(signed, now) {
            return ControlReply::Rejected(code);
        }
        let pending = self
            .pending
            .pending()
            .iter()
            .take(MAX_PENDING_JOINS)
            .map(|request| AdminPendingJoin {
                child: request.node.clone(),
                kind: request.kind,
                operator: request.operator,
                desired_slot: request.desired_slot,
                expiry: request.expiry,
            })
            .collect();
        ControlReply::AdminSnapshot(AdminSnapshot {
            node: self.snapshot(),
            pending,
        })
    }

    /// Admin: approve a pending join, assign its slot/address, sign a
    /// `JoinApproved` with this node's operator key, and queue it for
    /// delivery.
    ///
    /// The parent ledger public key is resolved lazily from
    /// `<data-dir>/ledger_key`; the node deliberately does not couple a
    /// [`LedgerService`](crate::LedgerService) into the control path or open
    /// the child's account here. The account is materialized later by `ledger
    /// fund`/first issue.
    fn handle_admin_approve_join(
        &mut self,
        signed: &SignedControl,
        approve: &AdminJoinApprove,
        now: u64,
    ) -> ControlReply {
        if let Err(code) = self.authorize_admin(signed, now) {
            return ControlReply::Rejected(code);
        }
        if approve.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        if let Err(code) = self.precheck_approve(&approve.child, approve.slot) {
            return ControlReply::Rejected(code);
        }
        let parent_ledger = match crate::ledger_keys::load_or_create_ledger_key(&self.data_dir) {
            Ok(key) => key.public(),
            Err(err) => {
                warn!(%err, "admin approve: cannot resolve this node's ledger key");
                return ControlReply::Rejected(RejectCode::Internal);
            }
        };
        let approval =
            match self.approve_pending(approve.child.as_str(), approve.slot, now, parent_ledger) {
                Ok(approval) => approval,
                Err(err) => {
                    warn!(%err, child = %approve.child, "admin approve failed");
                    return ControlReply::Rejected(map_approve_error(&err));
                }
            };
        let signed_approval =
            match self.sign_decision(ControlRequest::JoinApproved(approval.clone()), now) {
                Ok(signed) => signed,
                Err(code) => return ControlReply::Rejected(code),
            };
        self.store_decision(signed_approval.clone());
        self.outbound.push_back(OutboundControl {
            target: approval.child.clone(),
            signed: signed_approval,
            kind: OutboundKind::Approved,
        });
        ControlReply::AdminApproved(AdminApproved {
            child: approval.child,
            slot: approval.slot,
            address: approval.address,
            delivery: PENDING_DELIVERY,
        })
    }

    /// Admin: reject a pending join and queue the operator-signed rejection for
    /// delivery.
    fn handle_admin_reject_join(
        &mut self,
        signed: &SignedControl,
        reject: &AdminJoinReject,
        now: u64,
    ) -> ControlReply {
        if let Err(code) = self.authorize_admin(signed, now) {
            return ControlReply::Rejected(code);
        }
        if reject.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        let Some(pending) = self.pending.pending_for(&reject.child) else {
            return ControlReply::Rejected(RejectCode::NotFound);
        };
        let nonce = pending.nonce;
        if let Err(err) = self.reject_pending(reject.child.as_str()) {
            warn!(%err, child = %reject.child, "admin reject failed");
            return ControlReply::Rejected(RejectCode::Internal);
        }
        let rejection = JoinRejection {
            child: reject.child.clone(),
            reason: reject
                .reason
                .clone()
                .unwrap_or_else(|| "rejected".to_string()),
            nonce,
        };
        let signed_rejection =
            match self.sign_decision(ControlRequest::JoinRejected(rejection), now) {
                Ok(signed) => signed,
                Err(code) => return ControlReply::Rejected(code),
            };
        self.store_decision(signed_rejection.clone());
        self.outbound.push_back(OutboundControl {
            target: reject.child.clone(),
            signed: signed_rejection,
            kind: OutboundKind::Rejected,
        });
        ControlReply::AdminRejected(AdminRejected {
            child: reject.child.clone(),
            delivery: PENDING_DELIVERY,
        })
    }

    /// Admin: re-send the stored decision for `child`, if one is retained.
    ///
    /// The stored frame is reused as-is (fresh top-level nonce not needed: the
    /// applicant matches it by the echoed `JoinRequest.nonce`). If nothing is
    /// stored, reply [`RejectCode::NotFound`].
    fn handle_admin_redeliver_join(
        &mut self,
        signed: &SignedControl,
        redeliver: &AdminRedeliverJoin,
        now: u64,
    ) -> ControlReply {
        if let Err(code) = self.authorize_admin(signed, now) {
            return ControlReply::Rejected(code);
        }
        if redeliver.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        let Some(stored) = self.stored_decision(&redeliver.child).cloned() else {
            return ControlReply::Rejected(RejectCode::NotFound);
        };
        // Clone the request out so the decision's fields can be read without
        // holding a borrow of `stored` while it is moved into the outbound
        // queue.
        let request = stored.request.clone();
        match &request {
            ControlRequest::JoinApproved(approval) => {
                let child = approval.child.clone();
                self.outbound.push_back(OutboundControl {
                    target: child.clone(),
                    signed: stored,
                    kind: OutboundKind::Approved,
                });
                ControlReply::AdminApproved(AdminApproved {
                    child,
                    slot: approval.slot,
                    address: approval.address.clone(),
                    delivery: PENDING_DELIVERY,
                })
            }
            ControlRequest::JoinRejected(rejection) => {
                let child = rejection.child.clone();
                self.outbound.push_back(OutboundControl {
                    target: child.clone(),
                    signed: stored,
                    kind: OutboundKind::Rejected,
                });
                ControlReply::AdminRejected(AdminRejected {
                    child,
                    delivery: PENDING_DELIVERY,
                })
            }
            _ => {
                warn!("stored decision is not a join decision");
                ControlReply::Rejected(RejectCode::Internal)
            }
        }
    }

    /// Validate an admin approval against current state, returning the precise
    /// [`RejectCode`] without mutating anything.
    ///
    /// Doing this first avoids relying on the string form of the errors
    /// [`ControlNode::approve_pending`] returns.
    fn precheck_approve(&self, child: &NodeId, slot: Option<u8>) -> Result<(), RejectCode> {
        if self.pending.pending_for(child).is_none() {
            return Err(RejectCode::NotFound);
        }
        if self.record.record().address.is_none() {
            return Err(RejectCode::NotAttached);
        }
        match slot {
            Some(slot) if slot > cawala_topology::MAX_SLOT => Err(RejectCode::SlotOutOfRange),
            Some(slot) if self.record.record().children.iter().any(|c| c.slot == slot) => {
                Err(RejectCode::SlotTaken)
            }
            None if lowest_free_slot(self.record.record()).is_none() => Err(RejectCode::Capacity),
            _ => Ok(()),
        }
    }

    /// Sign an outbound decision with this node's own operator key, using a
    /// fresh top-level nonce and a short expiry.
    fn sign_decision(
        &self,
        request: ControlRequest,
        now: u64,
    ) -> Result<SignedControl, RejectCode> {
        SignedControl::authorize(
            NodeId::from(self.node_id.clone()),
            &self.operator,
            fresh_nonce(),
            now.saturating_add(CONTROL_REQUEST_TTL_SECS),
            request,
        )
        .map_err(|_| RejectCode::Internal)
    }

    /// Retain an operator-signed decision as the most recent one for its child.
    fn store_decision(&mut self, signed: SignedControl) {
        let Some(child) = decision_target(&signed).cloned() else {
            return;
        };
        self.decisions
            .retain(|stored| decision_target(stored) != Some(&child));
        self.decisions.push_back(signed);
        while self.decisions.len() > MAX_STORED_DECISIONS {
            self.decisions.pop_front();
        }
    }

    /// The most recent stored decision for `child`, if any.
    fn stored_decision(&self, child: &NodeId) -> Option<&SignedControl> {
        self.decisions
            .iter()
            .find(|stored| decision_target(stored) == Some(child))
    }

    /// Insert or replace an operator-signed admin grant and persist it.
    ///
    /// The grant must be scoped to this node and signed by this node's own
    /// operator key; otherwise it is refused before touching the store.
    pub fn grant_admin(&mut self, grant: SignedAdminGrant) -> Result<(), ControlError> {
        if grant.grant.version != ADMIN_GRANT_VERSION {
            return Err(ControlError::UnsupportedVersion(grant.grant.version));
        }
        if grant.grant.node.as_str() != self.node_id {
            return Err(ControlError::Codec(format!(
                "admin grant is scoped to node '{}', expected '{}'",
                grant.grant.node, self.node_id
            )));
        }
        grant
            .verify(&self.operator.public())
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        let admin = grant.grant.admin;
        let expiry = grant.grant.expiry;
        self.admins.grant(grant);
        self.admins
            .save(&self.data_dir)
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        self.audit(serde_json::json!({
            "event": "grant",
            "admin": admin.to_string(),
            "node": self.node_id,
            "expiry": expiry,
        }));
        Ok(())
    }

    /// Remove the grant for `admin` and persist, returning whether one existed.
    pub fn revoke_admin(&mut self, admin: &OperatorPubKey) -> Result<bool, ControlError> {
        let removed = self.admins.revoke(admin);
        if removed {
            self.admins
                .save(&self.data_dir)
                .map_err(|err| ControlError::Codec(err.to_string()))?;
        }
        self.audit(serde_json::json!({
            "event": "revoke",
            "admin": admin.to_string(),
            "node": self.node_id,
            "removed": removed,
        }));
        Ok(removed)
    }

    /// Append one best-effort JSONL audit record. Never fails a request.
    fn audit(&self, event: serde_json::Value) {
        crate::audit::append(&self.data_dir, event);
    }

    /// Audit an admin request outcome (non-admin requests are not audited).
    fn audit_request(&self, signed: &SignedControl, reply: &ControlReply, now: u64) {
        if !is_admin_request(&signed.request) {
            return;
        }
        self.audit(serde_json::json!({
            "ts": now,
            "event": "request",
            "actor": signed.controller.to_string(),
            "origin": signed.origin.to_string(),
            "kind": signed.request.kind(),
            "outcome": reply_outcome(reply),
        }));
    }

    /// Audit a routed dispatch with its routing context.
    ///
    /// Additive and backward compatible with existing `control_audit.jsonl`
    /// consumers: the only new keys are `routed`, `requester`, `forwarder`, and
    /// `hops`. `requester`/`forwarder` are public node ids already carried in
    /// the envelope; no secrets or payloads are logged. The admin surface keeps
    /// its own [`ControlNode::audit_request`] line alongside this one.
    fn audit_routed(
        &self,
        now: u64,
        kind: &str,
        reply: &ControlReply,
        requester: &str,
        forwarder: &str,
        hops: usize,
    ) {
        self.audit(serde_json::json!({
            "ts": now,
            "event": "routed",
            "kind": kind,
            "outcome": reply_outcome(reply),
            "routed": true,
            "requester": requester,
            "forwarder": forwarder,
            "hops": hops,
        }));
    }

    /// Build the direct dial target for an [`Invite`], applying its optional
    /// `relay`/`ip` transport hints.
    ///
    /// An invite carrying neither hint yields an id-only [`EndpointAddr`],
    /// preserving the address-lookup path. A hint that cannot be converted to
    /// an iroh transport address is a [`ControlError::Codec`].
    pub fn invite_endpoint_addr(invite: &Invite) -> Result<EndpointAddr, ControlError> {
        let parent: EndpointId = invite.parent.as_str().parse().map_err(|err| {
            ControlError::Codec(format!(
                "invalid parent endpoint id '{}': {err}",
                invite.parent
            ))
        })?;
        let mut addrs = Vec::new();
        if let Some(url) = &invite.relay {
            let relay: iroh::RelayUrl = url.as_str().parse().map_err(|err| {
                ControlError::Codec(format!("invalid relay URL in invite: {err}"))
            })?;
            addrs.push(iroh::TransportAddr::Relay(relay));
        }
        if let Some(ip) = invite.ip {
            addrs.push(iroh::TransportAddr::Ip(ip));
        }
        Ok(if addrs.is_empty() {
            EndpointAddr::from(parent)
        } else {
            EndpointAddr::from_parts(parent, addrs)
        })
    }

    /// Dial `target` and perform one direct control request/response.
    pub async fn send_direct(
        endpoint: &Endpoint,
        target: EndpointId,
        signed: &SignedControl,
        timeout: Duration,
    ) -> Result<ControlReply, ControlError> {
        ControlNode::send_direct_addr(endpoint, EndpointAddr::from(target), signed, timeout).await
    }

    /// Like [`ControlNode::send_direct`], but with an explicit
    /// [`EndpointAddr`] so hermetic tests can dial by a known loopback address.
    pub async fn send_direct_addr(
        endpoint: &Endpoint,
        target: EndpointAddr,
        signed: &SignedControl,
        timeout: Duration,
    ) -> Result<ControlReply, ControlError> {
        let exchange = async {
            let connection = endpoint
                .connect(target, CONTROL_ALPN)
                .await
                .map_err(|err| ControlError::Codec(format!("control connect failed: {err}")))?;
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|err| ControlError::Codec(format!("control open_bi failed: {err}")))?;
            proto::write_framed(&mut send, signed)
                .await
                .map_err(|err| ControlError::Codec(format!("control write failed: {err}")))?;
            send.finish()
                .map_err(|err| ControlError::Codec(format!("control finish failed: {err}")))?;
            let reply: ControlReply =
                proto::read_framed_with_limit::<ControlReply, _>(&mut recv, MAX_CONTROL_FRAME)
                    .await
                    .map_err(|err| ControlError::Codec(format!("control read failed: {err}")))?;
            connection.close(0u8.into(), b"done");
            Ok::<ControlReply, ControlError>(reply)
        };
        match tokio::time::timeout(timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(ControlError::Codec("control request timed out".to_string())),
        }
    }
}

/// Server side of the direct control protocol.
#[derive(Debug, Clone)]
pub struct ControlHandler {
    node: Arc<Mutex<ControlNode>>,
    endpoint: Endpoint,
}

impl ControlHandler {
    /// Wrap a shared engine and the node's own endpoint (used to dial the
    /// applicant when delivering a queued decision).
    pub fn new(node: Arc<Mutex<ControlNode>>, endpoint: Endpoint) -> Self {
        ControlHandler { node, endpoint }
    }

    /// A clone of the shared engine handle.
    pub fn node(&self) -> Arc<Mutex<ControlNode>> {
        Arc::clone(&self.node)
    }
}

impl ProtocolHandler for ControlHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        let (mut send, mut recv) = connection.accept_bi().await?;
        let signed: SignedControl =
            proto::read_framed_with_limit::<SignedControl, _>(&mut recv, MAX_CONTROL_FRAME).await?;

        // Process the request and drain any frames it queued, all under the
        // engine lock. The lock is dropped before any delivery (await) or file
        // I/O; audit writes here happen while the lock is held but are cheap.
        let (mut reply, outbound, data_dir) = {
            let mut engine = self.node.lock().await;
            let reply = engine.receive(remote, signed).await;
            let outbound = engine.take_outbound();
            let data_dir = engine.data_dir().to_path_buf();
            (reply, outbound, data_dir)
        };

        // Deliver decisions owned by this node and patch the reply with the
        // applicant's view. Never hold the engine mutex across `send_direct`.
        deliver_outbound_decisions(&self.endpoint, &data_dir, outbound, &mut reply).await;
        info!(%remote, kind = signed_kind(&reply), "control reply");

        proto::write_framed(&mut send, &reply).await?;
        send.finish()?;

        // Wait until the remote closes, keeping the stream alive long enough
        // for the reply to be delivered.
        connection.closed().await;
        Ok(())
    }
}

/// Register the ping + control handlers on `endpoint` (no messaging).
pub fn spawn_control_only_on(endpoint: Endpoint, node: Arc<Mutex<ControlNode>>) -> Router {
    let handler = ControlHandler::new(node, endpoint.clone());
    Router::builder(endpoint)
        .accept(proto::ALPN, crate::PingHandler)
        .accept(CONTROL_ALPN, handler)
        .spawn()
}

/// Bind a node endpoint with ping + control (no messaging) and register the
/// handlers. Used when the node has no asserted address yet but must still be
/// able to answer direct control (e.g. an applicant awaiting `JoinApproved`).
pub async fn spawn_control_only(
    secret_key: iroh::SecretKey,
    node: Arc<Mutex<ControlNode>>,
) -> anyhow::Result<Router> {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .bind()
        .await?;
    Ok(spawn_control_only_on(endpoint, node))
}

/// Bind a node endpoint with ping + msg + control and register all handlers.
///
/// Returns the router plus the channel of locally delivered msg envelopes.
pub async fn spawn_control_node(
    secret_key: iroh::SecretKey,
    snapshot: RoutableSnapshot,
    config: MsgConfig,
    node: Arc<Mutex<ControlNode>>,
) -> anyhow::Result<(Router, tokio::sync::mpsc::Receiver<cawala_msg::Envelope>)> {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .bind()
        .await?;
    Ok(spawn_control_node_on(endpoint, snapshot, config, node))
}

/// Like [`spawn_control_node`], but on an already-bound endpoint.
pub fn spawn_control_node_on(
    endpoint: Endpoint,
    snapshot: RoutableSnapshot,
    config: MsgConfig,
    node: Arc<Mutex<ControlNode>>,
) -> (Router, tokio::sync::mpsc::Receiver<cawala_msg::Envelope>) {
    spawn_control_node_live_on(endpoint, NeighborSource::Static(snapshot), config, node)
}

/// Bind a node endpoint with ping + msg + control and register all handlers,
/// using a [`NeighborSource::Live`] routing view.
///
/// Used by the long-running `run()` path so a child approved by a separate
/// `control approve` process is accepted without restarting the node.
pub async fn spawn_control_node_live(
    secret_key: iroh::SecretKey,
    source: NeighborSource,
    config: MsgConfig,
    node: Arc<Mutex<ControlNode>>,
) -> anyhow::Result<(Router, tokio::sync::mpsc::Receiver<cawala_msg::Envelope>)> {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .bind()
        .await?;
    Ok(spawn_control_node_live_on(endpoint, source, config, node))
}

/// Like [`spawn_control_node_live`], but on an already-bound endpoint.
pub fn spawn_control_node_live_on(
    endpoint: Endpoint,
    source: NeighborSource,
    config: MsgConfig,
    node: Arc<Mutex<ControlNode>>,
) -> (Router, tokio::sync::mpsc::Receiver<cawala_msg::Envelope>) {
    let (sink, receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
    let handler = MsgHandler::with_source_and_control(
        endpoint.clone(),
        source,
        config,
        sink,
        Arc::clone(&node),
    );
    let control = ControlHandler::new(node, endpoint.clone());
    let router = Router::builder(endpoint)
        .accept(proto::ALPN, crate::PingHandler)
        .accept(MSG_ALPN, handler)
        .accept(CONTROL_ALPN, control)
        .spawn();
    (router, receiver)
}

/// The lowest free child slot, or `None` when all 8 are taken.
fn lowest_free_slot(record: &NodeRecord) -> Option<u8> {
    (0..=cawala_topology::MAX_SLOT).find(|slot| !record.children.iter().any(|c| c.slot == *slot))
}

/// Current time as unix seconds.
fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A fresh request nonce from the OS randomness source.
///
/// `getrandom` failing is effectively impossible on supported platforms; the
/// clock is a monotonic fallback (a collision is caught by the replay guard,
/// never silently applied).
fn fresh_nonce() -> u64 {
    getrandom::u64().unwrap_or_else(|_| now_unix_seconds())
}

/// Pack a nonce into the 16-byte replay [`MsgId`] (first 8 bytes big-endian).
fn nonce_msg_id(nonce: u64) -> MsgId {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&nonce.to_be_bytes());
    MsgId::from_bytes(id)
}

/// The child a stored decision answers, if it is an approval/rejection.
fn decision_target(signed: &SignedControl) -> Option<&NodeId> {
    match &signed.request {
        ControlRequest::JoinApproved(approval) => Some(&approval.child),
        ControlRequest::JoinRejected(rejection) => Some(&rejection.child),
        _ => None,
    }
}

/// Map an [`ControlNode::approve_pending`] failure to the wire [`RejectCode`].
///
/// The precise cases are pre-checked in [`ControlNode::precheck_approve`]; this
/// is the fallback for persist/ledger failures.
fn map_approve_error(err: &ControlError) -> RejectCode {
    if matches!(err, ControlError::SlotOutOfRange(_)) {
        RejectCode::SlotOutOfRange
    } else {
        RejectCode::Internal
    }
}

/// Short outcome label for an audited reply.
fn reply_outcome(reply: &ControlReply) -> String {
    match reply {
        ControlReply::Accepted => "accepted".to_string(),
        ControlReply::Pending => "pending".to_string(),
        ControlReply::Rejected(code) => format!("rejected:{code:?}"),
        ControlReply::Snapshot(_) => "snapshot".to_string(),
        ControlReply::AdminSnapshot(_) => "admin-snapshot".to_string(),
        ControlReply::AdminApproved(_) => "admin-approved".to_string(),
        ControlReply::AdminRejected(_) => "admin-rejected".to_string(),
    }
}

/// Map a direct-delivery exchange to the applicant's view of it.
fn delivery_status(result: Result<ControlReply, ControlError>) -> DeliveryStatus {
    match result {
        Ok(ControlReply::Rejected(code)) => DeliveryStatus::Rejected(code),
        Ok(_) => DeliveryStatus::Delivered,
        Err(ControlError::Codec(message)) if message.contains("timed out") => {
            DeliveryStatus::TimedOut
        }
        Err(_) => DeliveryStatus::Unreachable,
    }
}

/// Reverse-dial each queued outbound decision and patch `reply` with the last
/// applicant's delivery outcome.
///
/// Shared by the direct [`ControlHandler`] and the routed destination path so
/// `AdminApproved.delivery`/`AdminRejected.delivery` stay correct whichever
/// transport carried the request. The caller must have dropped the engine lock
/// (this awaits `send_direct`).
pub(crate) async fn deliver_outbound_decisions(
    endpoint: &Endpoint,
    data_dir: &Path,
    outbound: Vec<OutboundControl>,
    reply: &mut ControlReply,
) {
    let mut last_status = None;
    for item in outbound {
        let status = match item.target.as_str().parse::<EndpointId>() {
            Ok(target) => delivery_status(
                ControlNode::send_direct(endpoint, target, &item.signed, DELIVERY_TIMEOUT).await,
            ),
            Err(err) => {
                warn!(child = %item.target, %err, "invalid applicant endpoint id");
                DeliveryStatus::Unreachable
            }
        };
        audit_delivery(data_dir, &item.target, item.kind, &status);
        last_status = Some(status);
    }
    if let Some(status) = last_status {
        patch_delivery(reply, status);
    }
}

/// Patch the `delivery` field of an admin reply with the real outcome.
fn patch_delivery(reply: &mut ControlReply, status: DeliveryStatus) {
    match reply {
        ControlReply::AdminApproved(approved) => approved.delivery = status,
        ControlReply::AdminRejected(rejected) => rejected.delivery = status,
        _ => {}
    }
}

/// Best-effort delivery audit line. Never fails a request.
fn audit_delivery(data_dir: &Path, child: &NodeId, kind: OutboundKind, status: &DeliveryStatus) {
    crate::audit::append(
        data_dir,
        serde_json::json!({
            "event": "delivery",
            "child": child.to_string(),
            "kind": kind.label(),
            "outcome": format!("{status:?}"),
        }),
    );
}

/// Stable label for a reply, for logs.
fn signed_kind(reply: &ControlReply) -> &'static str {
    match reply {
        ControlReply::Accepted => "accepted",
        ControlReply::Pending => "pending",
        ControlReply::Rejected(_) => "rejected",
        ControlReply::Snapshot(_) => "snapshot",
        ControlReply::AdminSnapshot(_) => "admin-snapshot",
        ControlReply::AdminApproved(_) => "admin-approved",
        ControlReply::AdminRejected(_) => "admin-rejected",
    }
}

/// Map a record mutation failure to the wire [`RejectCode`].
fn map_record_error(err: &RecordError) -> RejectCode {
    match err {
        RecordError::SlotTaken(_) => RejectCode::SlotTaken,
        RecordError::SlotOutOfRange(_) => RejectCode::SlotOutOfRange,
        RecordError::CapExceeded => RejectCode::Capacity,
        RecordError::ChildNotFound(_) => RejectCode::NotFound,
        RecordError::AddressWithoutParent(_) => RejectCode::NotAttached,
        RecordError::DuplicateChild(_)
        | RecordError::SelfReference(_)
        | RecordError::AddressSlotMismatch { .. }
        | RecordError::IdMismatch { .. } => RejectCode::BadRequest,
        RecordError::ReadFailed { .. }
        | RecordError::WriteFailed { .. }
        | RecordError::Corrupt { .. } => RejectCode::Internal,
    }
}

/// Map a control verification failure to the wire [`RejectCode`].
fn map_control_error(err: &ControlError) -> RejectCode {
    match err {
        ControlError::UnsupportedVersion(_) => RejectCode::BadVersion,
        ControlError::UnknownOrigin(_)
        | ControlError::OperatorMismatch
        | ControlError::InvalidSignature => RejectCode::Unauthorized,
        ControlError::MissingLedgerForNode
        | ControlError::UnexpectedLedgerForUser
        | ControlError::SlotOutOfRange(_)
        | ControlError::FieldTooLong { .. }
        | ControlError::GrantExpiryNotAfterGrant { .. }
        | ControlError::GrantTtlTooLong { .. } => RejectCode::BadRequest,
        ControlError::Codec(_) => RejectCode::Internal,
    }
}

/// Map a peer-registry insertion failure to the wire [`RejectCode`].
fn map_ledger_error(err: &cawala_ledger::LedgerError) -> RejectCode {
    match err {
        cawala_ledger::LedgerError::InvalidPeerKeys
        | cawala_ledger::LedgerError::DuplicatePeer
        | cawala_ledger::LedgerError::DuplicateKey => RejectCode::BadRequest,
        _ => RejectCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::ChildEntry;
    use cawala_control::{AdminGrant, DEFAULT_ADMIN_TTL_SECS};
    use cawala_ledger::{LedgerPubKey, LedgerSecretKey};
    use iroh::SecretKey;

    fn record(node_id: &str, address: Option<&str>) -> NodeRecord {
        NodeRecord {
            node_id: node_id.to_string(),
            address: address.map(|a| a.parse().unwrap()),
            parent: None,
            children: Vec::new(),
        }
    }

    fn child(id: &str, slot: u8, date_joined: u64) -> ChildEntry {
        ChildEntry {
            child_id: id.to_string(),
            kind: ChildKind::Node,
            slot,
            date_joined,
        }
    }

    fn ledger(seed: u8) -> LedgerPubKey {
        LedgerSecretKey::from_bytes([seed; 32]).public()
    }

    /// Sign a control request for a synthetic-clock engine (`now == 0`), with an
    /// expiry inside `CONTROL_REQUEST_MAX_TTL_SECS`.
    fn authorize_at(
        origin: &str,
        op: &OperatorSecretKey,
        nonce: u64,
        request: ControlRequest,
    ) -> SignedControl {
        SignedControl::authorize(
            NodeId::from(origin),
            op,
            nonce,
            CONTROL_REQUEST_MAX_TTL_SECS,
            request,
        )
        .unwrap()
    }

    #[test]
    fn lowest_free_slot_skips_taken() {
        let mut rec = record("n", None);
        rec.children.push(child("a", 0, 1));
        rec.children.push(child("b", 2, 2));
        assert_eq!(lowest_free_slot(&rec), Some(1));

        for slot in 0..=cawala_topology::MAX_SLOT {
            if !rec.children.iter().any(|c| c.slot == slot) {
                rec.children.push(child("x", slot, 9));
            }
        }
        assert_eq!(lowest_free_slot(&rec), None);
    }

    fn applicant_join(i: usize, operator: &OperatorSecretKey) -> JoinRequest {
        JoinRequest {
            node: NodeId::from(format!("applicant-{i}")),
            kind: ChildKind::User,
            operator: operator.public(),
            ledger: None,
            desired_slot: None,
            location_hint: None,
            nonce: i as u64,
            expiry: u64::MAX,
        }
    }

    #[tokio::test]
    async fn join_queue_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let operator = OperatorSecretKey::from_bytes([1u8; 32]);
        let applicant_op = OperatorSecretKey::from_bytes([7u8; 32]);
        let store = ControlStore::open(dir.path()).unwrap();
        let mut record = RecordStore::open(dir.path(), "parent").unwrap();
        record.set_address("0".parse().unwrap()).unwrap();
        record.save().unwrap();
        let mut engine = ControlNode::new(
            dir.path(),
            "parent",
            operator,
            record,
            PeerRegistry::new(),
            store,
            AdminStore::empty(),
        );
        // `receive_at` ignores the remote; any endpoint id will do.
        let remote = EndpointId::from(SecretKey::generate().public());

        // Exactly `MAX_PENDING_JOINS` distinct applicants are queued.
        for i in 0..MAX_PENDING_JOINS {
            let join = applicant_join(i, &applicant_op);
            let origin = join.node.clone();
            let signed = authorize_at(
                origin.as_str(),
                &applicant_op,
                i as u64,
                ControlRequest::Join(join),
            );
            assert_eq!(
                engine.receive_at(remote, signed, 0).await,
                ControlReply::Pending,
                "applicant {i}"
            );
        }
        assert_eq!(engine.pending().pending().len(), MAX_PENDING_JOINS);

        // One more distinct applicant is refused; the queue does not grow.
        let overflow = applicant_join(MAX_PENDING_JOINS, &applicant_op);
        let overflow_origin = overflow.node.clone();
        let signed = authorize_at(
            overflow_origin.as_str(),
            &applicant_op,
            MAX_PENDING_JOINS as u64,
            ControlRequest::Join(overflow),
        );
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Rejected(RejectCode::Capacity)
        );
        assert_eq!(engine.pending().pending().len(), MAX_PENDING_JOINS);

        // An already-queued applicant is still idempotent even when full. A
        // fresh nonce models a genuine retry; the replay guard would reject the
        // exact same frame.
        let requeue = applicant_join(0, &applicant_op);
        let requeue_origin = requeue.node.clone();
        let signed = authorize_at(
            requeue_origin.as_str(),
            &applicant_op,
            9_999,
            ControlRequest::Join(requeue),
        );
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Pending
        );
        assert_eq!(engine.pending().pending().len(), MAX_PENDING_JOINS);
    }

    /// A fresh applicant engine ("me") with no parent/address, plus the join
    /// request it has outbound.
    fn outbound_applicant(
        dir: &std::path::Path,
        pinned: Option<OperatorPubKey>,
    ) -> (ControlNode, JoinRequest) {
        let operator = OperatorSecretKey::from_bytes([1u8; 32]);
        let request = JoinRequest {
            node: NodeId::from("me"),
            kind: ChildKind::User,
            operator: operator.public(),
            ledger: None,
            desired_slot: None,
            location_hint: None,
            nonce: 7,
            expiry: u64::MAX,
        };
        let store = ControlStore::open(dir).unwrap();
        let record = RecordStore::open(dir, "me").unwrap();
        let mut engine = ControlNode::new(
            dir.to_path_buf(),
            "me",
            operator,
            record,
            PeerRegistry::new(),
            store,
            AdminStore::empty(),
        );
        engine
            .begin_outbound_join(request.clone(), NodeId::from("parent"), pinned)
            .unwrap();
        (engine, request)
    }

    fn approval_for(request: &JoinRequest) -> JoinApproval {
        JoinApproval {
            child: request.node.clone(),
            child_operator: request.operator,
            child_ledger: request.ledger,
            kind: request.kind,
            slot: 2,
            address: "0.2".parse().unwrap(),
            date_joined: 10,
            nonce: request.nonce,
            parent_ledger: ledger(77),
        }
    }

    #[tokio::test]
    async fn begin_outbound_join_stores_pinned_operator() {
        let dir = tempfile::tempdir().unwrap();
        let pinned = OperatorSecretKey::from_bytes([9u8; 32]).public();
        let (engine, _) = outbound_applicant(dir.path(), Some(pinned));

        let outbound = engine.pending().outbound().expect("outbound present");
        assert_eq!(outbound.parent, NodeId::from("parent"));
        assert_eq!(outbound.pinned_operator, Some(pinned));

        // The pin is persisted, not just in-memory.
        let reloaded = ControlStore::open(dir.path()).unwrap();
        assert_eq!(
            reloaded.outbound().unwrap().pinned_operator,
            Some(pinned),
            "pinned operator must survive a save/reload"
        );
    }

    #[tokio::test]
    async fn pinned_approval_requires_the_pinned_signer() {
        let dir = tempfile::tempdir().unwrap();
        let pinned = OperatorSecretKey::from_bytes([9u8; 32]);
        let attacker = OperatorSecretKey::from_bytes([10u8; 32]);
        let (mut engine, request) = outbound_applicant(dir.path(), Some(pinned.public()));
        let approval = approval_for(&request);
        let remote = EndpointId::from(SecretKey::generate().public());

        // A self-consistent approval signed by some other key is rejected.
        let forged = authorize_at(
            "parent",
            &attacker,
            1,
            ControlRequest::JoinApproved(approval.clone()),
        );
        assert_eq!(
            engine.receive_at(remote, forged, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        assert!(engine.record().parent.is_none(), "no link was installed");
        assert!(
            engine.pending().outbound().is_some(),
            "the outbound join is retained for a legitimate approval"
        );

        // The pinned key's approval is accepted.
        let good = authorize_at("parent", &pinned, 2, ControlRequest::JoinApproved(approval));
        assert_eq!(
            engine.receive_at(remote, good, 0).await,
            ControlReply::Accepted
        );
        assert_eq!(engine.record().parent.as_ref().unwrap().parent_id, "parent");
        assert!(engine.pending().outbound().is_none());
    }

    /// A pinned (invite) join refuses a rejection signed by any key other than
    /// the pinned parent operator, and leaves the outbound join intact; the
    /// pinned key's rejection is accepted and clears it.
    #[tokio::test]
    async fn pinned_rejection_requires_the_pinned_signer() {
        let dir = tempfile::tempdir().unwrap();
        let pinned = OperatorSecretKey::from_bytes([9u8; 32]);
        let attacker = OperatorSecretKey::from_bytes([10u8; 32]);
        let (mut engine, request) = outbound_applicant(dir.path(), Some(pinned.public()));
        let remote = EndpointId::from(SecretKey::generate().public());
        let rejection = JoinRejection {
            child: NodeId::from("me"),
            reason: "cancelled".to_string(),
            nonce: request.nonce,
        };

        // A self-consistent rejection signed by another key must not cancel the
        // in-flight join.
        let forged = authorize_at(
            "parent",
            &attacker,
            1,
            ControlRequest::JoinRejected(rejection.clone()),
        );
        assert_eq!(
            engine.receive_at(remote, forged, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        assert!(
            engine.pending().outbound().is_some(),
            "the outbound join survives a spoofed rejection"
        );

        // The pinned key's rejection is accepted and clears the outbound join.
        let good = authorize_at(
            "parent",
            &pinned,
            2,
            ControlRequest::JoinRejected(rejection),
        );
        assert_eq!(
            engine.receive_at(remote, good, 0).await,
            ControlReply::Accepted
        );
        assert!(engine.pending().outbound().is_none());
    }

    /// A rejection with no outstanding outbound join is a no-op `Accepted`,
    /// regardless of who signed it.
    #[tokio::test]
    async fn rejection_without_outbound_is_accepted_noop() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, request) = outbound_applicant(dir.path(), None);
        engine.pending.clear_outbound();
        engine.pending.save().unwrap();
        let remote = EndpointId::from(SecretKey::generate().public());
        let rejection = JoinRejection {
            child: NodeId::from("me"),
            reason: "late".to_string(),
            nonce: request.nonce,
        };
        let signed = authorize_at(
            "parent",
            &OperatorSecretKey::from_bytes([11u8; 32]),
            1,
            ControlRequest::JoinRejected(rejection),
        );
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Accepted
        );
        assert!(engine.pending().outbound().is_none());
    }

    /// A direct (unpinned) join still accepts a self-consistent rejection
    /// (trust-on-first-use, unchanged), clearing the outbound join.
    #[tokio::test]
    async fn unpinned_rejection_accepts_any_self_consistent_signer() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, request) = outbound_applicant(dir.path(), None);
        let remote = EndpointId::from(SecretKey::generate().public());
        let rejection = JoinRejection {
            child: NodeId::from("me"),
            reason: "direct".to_string(),
            nonce: request.nonce,
        };
        let signed = authorize_at(
            "parent",
            &OperatorSecretKey::from_bytes([12u8; 32]),
            1,
            ControlRequest::JoinRejected(rejection),
        );
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Accepted
        );
        assert!(engine.pending().outbound().is_none());
    }

    /// **P5a**: an accepted approval persists the parent's operator + ledger
    /// keys so the parent's carried settlement hops become resolvable, and a
    /// re-delivered approval is idempotent.
    #[tokio::test]
    async fn approval_persists_parent_peer_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = OperatorSecretKey::from_bytes([3u8; 32]);
        let (mut engine, request) = outbound_applicant(dir.path(), None);
        let approval = approval_for(&request);
        let remote = EndpointId::from(SecretKey::generate().public());

        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::JoinApproved(approval.clone()),
        );
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Accepted
        );

        let expected = PeerKeys {
            node_id: NodeId::from("parent"),
            operator: parent_op.public(),
            ledger: Some(ledger(77)),
            role: PeerRole::Node,
        };
        let peers = ledger_peers::load_peers(dir.path()).unwrap();
        assert_eq!(peers.get(&NodeId::from("parent")), Some(&expected));

        // Re-delivering the same approval (e.g. after a lost ack) rewrites the
        // identical row: no duplicate, no corruption. A fresh frame models the
        // retry (the exact same frame would be caught by the replay guard).
        engine
            .begin_outbound_join(request.clone(), NodeId::from("parent"), None)
            .unwrap();
        let signed = authorize_at(
            "parent",
            &parent_op,
            2,
            ControlRequest::JoinApproved(approval),
        );
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Accepted
        );
        let peers_again = ledger_peers::load_peers(dir.path()).unwrap();
        assert_eq!(peers_again, peers);
        assert_eq!(peers_again.len(), 1);
    }

    /// **F**: an authentic but *stale* approval (the nonce from an earlier
    /// outbound request) must not be applied to a later re-join. Without the
    /// nonce binding it could reset the address/slot and, now that the approval
    /// carries the parent ledger key, replace a newer key with an old one.
    #[tokio::test]
    async fn stale_approval_nonce_is_rejected_without_change() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = OperatorSecretKey::from_bytes([3u8; 32]);
        let (mut engine, request) = outbound_applicant(dir.path(), None);
        let approval = approval_for(&request);
        let remote = EndpointId::from(SecretKey::generate().public());

        // First join completes with the request's nonce and installs the row.
        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::JoinApproved(approval.clone()),
        );
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Accepted
        );
        let peers_after_first = ledger_peers::load_peers(dir.path()).unwrap();
        let record_after_first = engine.record().clone();

        // A later re-join to the same parent carries a fresh nonce.
        let mut new_request = request.clone();
        new_request.nonce += 100;
        engine
            .begin_outbound_join(new_request, NodeId::from("parent"), None)
            .unwrap();

        // Replaying the old approval is refused before any mutation. The
        // top-level frame is fresh so the replay guard does not preempt the
        // inner stale-nonce rule under test.
        let replay = authorize_at(
            "parent",
            &parent_op,
            2,
            ControlRequest::JoinApproved(approval),
        );
        assert_eq!(
            engine.receive_at(remote, replay, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        assert_eq!(
            ledger_peers::load_peers(dir.path()).unwrap(),
            peers_after_first,
            "the parent row must be untouched"
        );
        assert_eq!(
            *engine.record(),
            record_after_first,
            "the record must be untouched"
        );
        assert!(
            engine.pending().outbound().is_some(),
            "the current outbound join is retained for a matching approval"
        );
    }

    /// A pre-existing row for the parent node id with a **different operator**
    /// is refused, and the record/registry are rolled back.
    #[tokio::test]
    async fn approval_different_operator_conflict_is_refused_without_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = OperatorSecretKey::from_bytes([3u8; 32]);
        let (mut engine, request) = outbound_applicant(dir.path(), None);
        let approval = approval_for(&request);

        let conflicting = PeerKeys {
            node_id: NodeId::from("parent"),
            operator: OperatorSecretKey::from_bytes([4u8; 32]).public(),
            ledger: Some(ledger(5)),
            role: PeerRole::Node,
        };
        engine.peers.insert(conflicting.clone()).unwrap();
        ledger_peers::save_peers(dir.path(), &engine.peers).unwrap();

        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::JoinApproved(approval),
        );
        let remote = EndpointId::from(SecretKey::generate().public());
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        assert!(
            engine.record().parent.is_none(),
            "the record must be rolled back"
        );
        let peers = ledger_peers::load_peers(dir.path()).unwrap();
        assert_eq!(peers.get(&NodeId::from("parent")), Some(&conflicting));
        assert_eq!(peers.len(), 1);
    }

    /// **F2**: the parent keeps its operator key but regenerates its ledger key
    /// (restored `node.json`, lost ledger key). The signed approval is
    /// authoritative, so the existing row's ledger key is replaced rather than
    /// permanently blocking re-attach.
    #[tokio::test]
    async fn approval_same_operator_new_ledger_updates_parent_row() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = OperatorSecretKey::from_bytes([3u8; 32]);
        let (mut engine, request) = outbound_applicant(dir.path(), None);
        let approval = approval_for(&request);

        // The child already knows the parent under the same operator with an
        // older ledger key.
        engine
            .peers
            .insert(PeerKeys {
                node_id: NodeId::from("parent"),
                operator: parent_op.public(),
                ledger: Some(ledger(5)),
                role: PeerRole::Node,
            })
            .unwrap();
        ledger_peers::save_peers(dir.path(), &engine.peers).unwrap();

        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::JoinApproved(approval),
        );
        let remote = EndpointId::from(SecretKey::generate().public());
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Accepted
        );

        let peers = ledger_peers::load_peers(dir.path()).unwrap();
        let row = peers.get(&NodeId::from("parent")).expect("parent row");
        assert_eq!(row.operator, parent_op.public(), "operator is preserved");
        assert_eq!(
            row.ledger,
            Some(ledger(77)),
            "the ledger key must be replaced with the signed approval's"
        );
        assert_eq!(row.role, PeerRole::Node);
        assert_eq!(peers.len(), 1, "the replacement must not add a second row");
        assert!(
            engine.record().parent.is_some(),
            "the link is installed once the row is updated"
        );
    }

    /// An admin-capable engine ("parent") with an asserted address.
    fn admin_engine(dir: &std::path::Path) -> (ControlNode, OperatorSecretKey) {
        let operator = OperatorSecretKey::from_bytes([1u8; 32]);
        let mut record = RecordStore::open(dir, "parent").unwrap();
        record.set_address("0".parse().unwrap()).unwrap();
        record.save().unwrap();
        let store = ControlStore::open(dir).unwrap();
        let engine = ControlNode::new(
            dir.to_path_buf(),
            "parent",
            operator.clone(),
            record,
            PeerRegistry::new(),
            store,
            AdminStore::empty(),
        );
        (engine, operator)
    }

    /// Queue one applicant's join on `engine` and return the request.
    async fn queue_join(engine: &mut ControlNode, i: usize) -> JoinRequest {
        let applicant_op = OperatorSecretKey::from_bytes([7u8; 32]);
        let join = applicant_join(i, &applicant_op);
        let origin = join.node.clone();
        let signed = authorize_at(
            origin.as_str(),
            &applicant_op,
            i as u64 + 1,
            ControlRequest::Join(join.clone()),
        );
        let remote = EndpointId::from(SecretKey::generate().public());
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Pending
        );
        join
    }

    #[tokio::test]
    async fn admin_approve_queues_signed_approval() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, operator) = admin_engine(dir.path());
        let join = queue_join(&mut engine, 0).await;
        let remote = EndpointId::from(SecretKey::generate().public());

        let approve = authorize_at(
            "parent",
            &operator,
            100,
            ControlRequest::AdminApproveJoin(AdminJoinApprove {
                child: join.node.clone(),
                slot: Some(2),
            }),
        );
        let reply = engine.receive_at(remote, approve, 0).await;
        let ControlReply::AdminApproved(approved) = reply else {
            panic!("expected AdminApproved, got {reply:?}");
        };
        assert_eq!(approved.child, join.node);
        assert_eq!(approved.slot, 2);
        assert_eq!(approved.address, "0.2".parse().unwrap());
        assert_eq!(
            approved.delivery,
            DeliveryStatus::Unreachable,
            "the engine returns a placeholder; the handler patches it"
        );

        // The child is attached and the signed decision is queued.
        assert!(
            engine
                .record()
                .children
                .iter()
                .any(|c| c.child_id == join.node.as_str())
        );
        let outbound = engine.take_outbound();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].kind, OutboundKind::Approved);
        assert_eq!(outbound[0].target, join.node);
        assert_eq!(outbound[0].signed.controller, operator.public());
        assert_eq!(outbound[0].signed.verify_signature(), Ok(()));
        let ControlRequest::JoinApproved(approval) = &outbound[0].signed.request else {
            panic!("expected a JoinApproved frame");
        };
        assert_eq!(approval.child, join.node);
        assert_eq!(approval.slot, 2);
        assert!(engine.take_outbound().is_empty());
    }

    #[tokio::test]
    async fn admin_reject_queues_signed_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, operator) = admin_engine(dir.path());
        let join = queue_join(&mut engine, 0).await;
        let remote = EndpointId::from(SecretKey::generate().public());

        let reject = authorize_at(
            "parent",
            &operator,
            101,
            ControlRequest::AdminRejectJoin(AdminJoinReject {
                child: join.node.clone(),
                reason: Some("nope".to_string()),
            }),
        );
        let reply = engine.receive_at(remote, reject, 0).await;
        let ControlReply::AdminRejected(rejected) = reply else {
            panic!("expected AdminRejected, got {reply:?}");
        };
        assert_eq!(rejected.child, join.node);
        assert_eq!(rejected.delivery, DeliveryStatus::Unreachable);

        // The pending row is gone and the signed rejection is queued.
        assert!(engine.pending().pending().is_empty());
        let outbound = engine.take_outbound();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].kind, OutboundKind::Rejected);
        let ControlRequest::JoinRejected(rejection) = &outbound[0].signed.request else {
            panic!("expected a JoinRejected frame");
        };
        assert_eq!(rejection.child, join.node);
        assert_eq!(rejection.reason, "nope");
        assert_eq!(rejection.nonce, join.nonce);
        assert_eq!(outbound[0].signed.verify_signature(), Ok(()));
    }

    #[tokio::test]
    async fn admin_redeliver_requeues_and_unknown_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, operator) = admin_engine(dir.path());
        let join = queue_join(&mut engine, 0).await;
        let remote = EndpointId::from(SecretKey::generate().public());

        let approve = authorize_at(
            "parent",
            &operator,
            200,
            ControlRequest::AdminApproveJoin(AdminJoinApprove {
                child: join.node.clone(),
                slot: Some(1),
            }),
        );
        assert!(matches!(
            engine.receive_at(remote, approve, 0).await,
            ControlReply::AdminApproved(_)
        ));
        let first = engine.take_outbound();
        assert_eq!(first.len(), 1);

        // Redelivery re-queues the stored frame unchanged.
        let redeliver = authorize_at(
            "parent",
            &operator,
            201,
            ControlRequest::AdminRedeliverJoin(AdminRedeliverJoin {
                child: join.node.clone(),
            }),
        );
        assert!(matches!(
            engine.receive_at(remote, redeliver, 0).await,
            ControlReply::AdminApproved(_)
        ));
        let second = engine.take_outbound();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].signed, first[0].signed, "the frame is reused");

        // Nothing stored for an unknown child.
        let unknown = authorize_at(
            "parent",
            &operator,
            202,
            ControlRequest::AdminRedeliverJoin(AdminRedeliverJoin {
                child: NodeId::from("ghost"),
            }),
        );
        assert_eq!(
            engine.receive_at(remote, unknown, 0).await,
            ControlReply::Rejected(RejectCode::NotFound)
        );
        assert!(engine.take_outbound().is_empty());
    }

    #[tokio::test]
    async fn admin_approve_unknown_child_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, operator) = admin_engine(dir.path());
        let remote = EndpointId::from(SecretKey::generate().public());
        let approve = authorize_at(
            "parent",
            &operator,
            300,
            ControlRequest::AdminApproveJoin(AdminJoinApprove {
                child: NodeId::from("ghost"),
                slot: None,
            }),
        );
        assert_eq!(
            engine.receive_at(remote, approve, 0).await,
            ControlReply::Rejected(RejectCode::NotFound)
        );
    }

    #[tokio::test]
    async fn delegated_admin_is_scoped_and_cannot_use_topology_surface() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, operator) = admin_engine(dir.path());
        let admin_op = OperatorSecretKey::from_bytes([5u8; 32]);
        let grant = AdminGrant {
            version: ADMIN_GRANT_VERSION,
            node: NodeId::from("parent"),
            admin: admin_op.public(),
            scope: AdminScope::Admin,
            granted_at: 10,
            expiry: 10 + DEFAULT_ADMIN_TTL_SECS,
            label: None,
        };
        engine
            .grant_admin(SignedAdminGrant::authorize(grant, &operator).unwrap())
            .unwrap();

        let remote = EndpointId::from(SecretKey::generate().public());

        // A delegated admin may use the admin surface...
        let admin_query = authorize_at("parent", &admin_op, 400, ControlRequest::AdminQuery);
        assert!(matches!(
            engine.receive_at(remote, admin_query, 0).await,
            ControlReply::AdminSnapshot(_)
        ));

        // ...but never the topology surface (`Query` etc.).
        let topology_query = authorize_at("parent", &admin_op, 401, ControlRequest::Query);
        assert_eq!(
            engine.receive_at(remote, topology_query, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );

        // Revoking removes the delegated authority (and the reload is from disk).
        assert!(engine.revoke_admin(&admin_op.public()).unwrap());
        let after_revoke = authorize_at("parent", &admin_op, 402, ControlRequest::AdminQuery);
        assert_eq!(
            engine.receive_at(remote, after_revoke, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
    }

    #[tokio::test]
    async fn peer_cannot_use_admin_surface() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, _operator) = admin_engine(dir.path());
        // A directly-controlled peer (e.g. the senior child) would pass
        // `authorize`, but `authorize_admin` requires the origin to be this
        // node, so the admin surface is closed to it.
        let peer_op = OperatorSecretKey::from_bytes([6u8; 32]);
        let remote = EndpointId::from(SecretKey::generate().public());
        let query = authorize_at("peer", &peer_op, 500, ControlRequest::AdminQuery);
        assert_eq!(
            engine.receive_at(remote, query, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
    }

    #[tokio::test]
    async fn replay_guard_rejects_duplicate_admin_frame() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, operator) = admin_engine(dir.path());
        let remote = EndpointId::from(SecretKey::generate().public());
        let query = authorize_at("parent", &operator, 600, ControlRequest::AdminQuery);

        assert!(matches!(
            engine.receive_at(remote, query.clone(), 0).await,
            ControlReply::AdminSnapshot(_)
        ));
        assert_eq!(
            engine.receive_at(remote, query, 0).await,
            ControlReply::Rejected(RejectCode::Replay)
        );
    }

    #[tokio::test]
    async fn expiry_window_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, operator) = admin_engine(dir.path());
        let remote = EndpointId::from(SecretKey::generate().public());

        // Already expired: `now > expiry`.
        let expired = SignedControl::authorize(
            NodeId::from("parent"),
            &operator,
            1,
            0,
            ControlRequest::AdminQuery,
        )
        .unwrap();
        assert_eq!(
            engine.receive_at(remote, expired, 1).await,
            ControlReply::Rejected(RejectCode::Expired)
        );

        // An expiry further out than the cap.
        let too_long = SignedControl::authorize(
            NodeId::from("parent"),
            &operator,
            2,
            CONTROL_REQUEST_MAX_TTL_SECS + 1,
            ControlRequest::AdminQuery,
        )
        .unwrap();
        assert_eq!(
            engine.receive_at(remote, too_long, 0).await,
            ControlReply::Rejected(RejectCode::BadRequest)
        );
    }

    #[tokio::test]
    async fn tampered_expiry_is_rejected_as_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, operator) = admin_engine(dir.path());
        let remote = EndpointId::from(SecretKey::generate().public());
        let mut query = authorize_at("parent", &operator, 700, ControlRequest::AdminQuery);
        query.expiry += 1;
        assert_eq!(
            engine.receive_at(remote, query, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
    }
}
