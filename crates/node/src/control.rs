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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::Mutex;
use tracing::info;

use cawala_control::{
    CONTROL_ALPN, CONTROL_FORMAT_VERSION, ChildKind, ChildSnapshot, ControlError, ControlReply,
    ControlRequest, CreateChild, DetachChild, JoinApproval, JoinRejection, JoinRequest,
    MAX_CONTROL_FRAME, MoveChild, NodeId, NodeSnapshot, OperatorPubKey, OperatorSecretKey,
    ParentSnapshot, RejectCode, SetAddress, SignedControl, senior_child, verify_control,
};
use cawala_ledger::{PeerKeys, PeerRegistry, PeerRole};

use crate::control_store::ControlStore;
use crate::ledger_peers;
use crate::msg::{MSG_ALPN, MsgConfig, MsgHandler, RoutableSnapshot};
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
    ) -> Self {
        ControlNode {
            data_dir: data_dir.into(),
            node_id: node_id.into(),
            operator,
            record,
            peers,
            pending,
        }
    }

    /// Open (or create) the node's record, peers, and pending-join state from
    /// `data_dir`.
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
        Ok(ControlNode {
            data_dir,
            node_id: node_id.to_string(),
            operator,
            record,
            peers,
            pending,
        })
    }

    /// This node's id.
    pub fn node_id(&self) -> &str {
        &self.node_id
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

    /// This node's operator public key.
    pub fn operator_public(&self) -> OperatorPubKey {
        self.operator.public()
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

    /// This node's children as `(node_id, date_joined)` pairs, in record
    /// order. [`senior_child`] is order-independent.
    fn seniority(&self) -> Vec<(NodeId, u64)> {
        self.record
            .record()
            .children
            .iter()
            .map(|child| (NodeId::from(child.child_id.clone()), child.date_joined))
            .collect()
    }

    /// Authenticate and authorize a topology-changing request.
    fn authorize(&self, signed: &SignedControl) -> Result<(), RejectCode> {
        if !self.authorized(&signed.origin) {
            return Err(RejectCode::Unauthorized);
        }
        if signed.origin.as_str() == self.node_id {
            // Self-admin: the controller must be this node's own operator key.
            if signed.controller != self.operator.public() || signed.verify_signature().is_err() {
                return Err(RejectCode::Unauthorized);
            }
        } else {
            verify_control(signed, &self.peers).map_err(|err| map_control_error(&err))?;
        }
        Ok(())
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
    pub async fn receive_at(
        &mut self,
        _remote: EndpointId,
        signed: SignedControl,
        now: u64,
    ) -> ControlReply {
        if signed.version != CONTROL_FORMAT_VERSION {
            return ControlReply::Rejected(RejectCode::BadVersion);
        }
        match &signed.request {
            ControlRequest::Join(join) => self.handle_join(&signed, join, now),
            ControlRequest::JoinApproved(approval) => self.handle_join_approved(&signed, approval),
            ControlRequest::JoinRejected(rejection) => {
                self.handle_join_rejected(&signed, rejection)
            }
            ControlRequest::CreateChild(create) => self.handle_create_child(&signed, create),
            ControlRequest::DetachChild(detach) => self.handle_detach_child(&signed, detach),
            ControlRequest::MoveChild(move_child) => self.handle_move_child(&signed, move_child),
            ControlRequest::SetAddress(set) => self.handle_set_address(&signed, set),
            ControlRequest::Query => self.handle_query(&signed),
        }
    }

    /// Applicant side: queue the outbound join so a later `JoinApproved` /
    /// `JoinRejected` from `parent` can be matched.
    pub fn begin_outbound_join(
        &mut self,
        request: JoinRequest,
        parent: NodeId,
    ) -> Result<(), ControlError> {
        self.pending.set_outbound(request, parent);
        self.pending
            .save()
            .map_err(|err| ControlError::Codec(err.to_string()))
    }

    /// Parent side: consume the pending request for `node`, assign it a slot,
    /// attach it to this node's record, register its peer keys, and return the
    /// [`JoinApproval`] to send back to the applicant.
    ///
    /// Requires this node to have an asserted [`NodeRecord::address`].
    pub fn approve_pending(
        &mut self,
        node: &str,
        slot: Option<u8>,
        now: u64,
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
    /// link and the assigned address.
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

        let backup = self.record.clone();
        if let Err(err) = self
            .record
            .set_parent(signed.origin.as_str(), approval.slot)
        {
            return ControlReply::Rejected(map_record_error(&err));
        }
        if let Err(err) = self.record.set_address(approval.address.clone()) {
            self.record = backup;
            return ControlReply::Rejected(map_record_error(&err));
        }
        if self.record.save().is_err() {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        self.pending.clear_outbound();
        if self.pending.save().is_err() {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        ControlReply::Accepted
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
            Some(_) => {
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
    ) -> ControlReply {
        if let Err(code) = self.authorize(signed) {
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
    ) -> ControlReply {
        if let Err(code) = self.authorize(signed) {
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
    ) -> ControlReply {
        if let Err(code) = self.authorize(signed) {
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

    fn handle_set_address(&mut self, signed: &SignedControl, set: &SetAddress) -> ControlReply {
        if let Err(code) = self.authorize(signed) {
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

    fn handle_query(&mut self, signed: &SignedControl) -> ControlReply {
        if let Err(code) = self.authorize(signed) {
            return ControlReply::Rejected(code);
        }
        ControlReply::Snapshot(self.snapshot())
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
}

impl ControlHandler {
    /// Wrap a shared engine.
    pub fn new(node: Arc<Mutex<ControlNode>>) -> Self {
        ControlHandler { node }
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

        let reply = {
            let mut engine = self.node.lock().await;
            engine.receive(remote, signed).await
        };
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
    Router::builder(endpoint)
        .accept(proto::ALPN, crate::PingHandler)
        .accept(CONTROL_ALPN, ControlHandler::new(node))
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
    let (sink, receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
    let handler = MsgHandler::new(endpoint.clone(), snapshot, config, sink);
    let router = Router::builder(endpoint)
        .accept(proto::ALPN, crate::PingHandler)
        .accept(MSG_ALPN, handler)
        .accept(CONTROL_ALPN, ControlHandler::new(node))
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

/// Stable label for a reply, for logs.
fn signed_kind(reply: &ControlReply) -> &'static str {
    match reply {
        ControlReply::Accepted => "accepted",
        ControlReply::Pending => "pending",
        ControlReply::Rejected(_) => "rejected",
        ControlReply::Snapshot(_) => "snapshot",
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
        | ControlError::FieldTooLong { .. } => RejectCode::BadRequest,
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
        );
        // `receive_at` ignores the remote; any endpoint id will do.
        let remote = EndpointId::from(SecretKey::generate().public());

        // Exactly `MAX_PENDING_JOINS` distinct applicants are queued.
        for i in 0..MAX_PENDING_JOINS {
            let join = applicant_join(i, &applicant_op);
            let signed = SignedControl::authorize(
                join.node.clone(),
                &applicant_op,
                ControlRequest::Join(join),
            )
            .unwrap();
            assert_eq!(
                engine.receive_at(remote, signed, 0).await,
                ControlReply::Pending,
                "applicant {i}"
            );
        }
        assert_eq!(engine.pending().pending().len(), MAX_PENDING_JOINS);

        // One more distinct applicant is refused; the queue does not grow.
        let overflow = applicant_join(MAX_PENDING_JOINS, &applicant_op);
        let signed = SignedControl::authorize(
            overflow.node.clone(),
            &applicant_op,
            ControlRequest::Join(overflow),
        )
        .unwrap();
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Rejected(RejectCode::Capacity)
        );
        assert_eq!(engine.pending().pending().len(), MAX_PENDING_JOINS);

        // An already-queued applicant is still idempotent even when full.
        let requeue = applicant_join(0, &applicant_op);
        let signed = SignedControl::authorize(
            requeue.node.clone(),
            &applicant_op,
            ControlRequest::Join(requeue),
        )
        .unwrap();
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Pending
        );
        assert_eq!(engine.pending().pending().len(), MAX_PENDING_JOINS);
    }
}
