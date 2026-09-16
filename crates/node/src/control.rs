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
    DetachChild, DetachNotice, ExitRequest, Invite, JoinApproval, JoinRejection, JoinRequest,
    MAX_CONTROL_FRAME, MoveChild, NodeId, NodeSnapshot, OctAddr, OperatorPubKey, OperatorSecretKey,
    ParentSnapshot, ROUTED_REPLY_VERSION, RebaseNotice, RebasePull, RejectCode, RoutedControlV1,
    RoutedForward, RoutedReplyV1, SetAddress, SignedAdminGrant, SignedControl, SignedRoutedReply,
    is_admin_request, is_supported_control_version, senior_child, verify_control,
};
use cawala_ledger::{LedgerPubKey, PeerKeys, PeerRegistry, PeerRole};
use cawala_msg::{MsgId, PeerRef, Seen, SeenConfig};

use crate::admin_store::AdminStore;
use crate::control_store::ControlStore;
use crate::ledger_peers;
use crate::msg::{MSG_ALPN, MsgConfig, MsgHandler, NeighborSource, RoutableSnapshot};
use crate::record::{NodeRecord, RecordError, RecordStore};
use crate::seen_store::SeenStore;

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

/// Bound on the in-memory pending re-base queue.
///
/// Re-base notices are cheap to re-derive (a parent can always answer a
/// `RebasePull`), so the queue is a best-effort retry buffer, not durable state:
/// the oldest entry is dropped once the bound is reached. A restart heals via
/// the child's startup pull instead.
const MAX_PENDING_REBASE: usize = 32;

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
    /// An operator-signed `Rebase` notice pushed to a child.
    Rebase,
    /// An operator-signed `DetachNotice` pushed to a detached child.
    DetachNotice,
}

impl OutboundKind {
    /// Stable label for logs and audit lines.
    fn label(self) -> &'static str {
        match self {
            OutboundKind::Approved => "join-approved",
            OutboundKind::Rejected => "join-rejected",
            OutboundKind::Rebase => "rebase",
            OutboundKind::DetachNotice => "detach-notice",
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

/// How an existing peer row relates to a freshly approved/re-created one.
///
/// Split out from the old `Option<bool>` so a ledger-only change can be
/// reconciled (updated) rather than mistaken for a conflict: the operator key
/// is the identity/authority, the ledger key is the node's own settlement key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerState {
    /// No row exists for the node.
    Absent,
    /// The retained row is byte-identical to the expected one.
    Identical,
    /// The retained row has the same operator and role but a different ledger
    /// key; the stored row is updated to the expected key.
    LedgerChanged,
    /// The retained row conflicts on operator or role (identity/authority).
    Conflict,
}

/// The local control engine: persisted links plus the judge of who may mutate
/// them.
///
/// One instance is shared behind a [`tokio::sync::Mutex`] by the
/// [`ControlHandler`]. `receive` takes `&mut self` because applying a request
/// mutates the record/peer/pending stores and persists them.
///
/// # Per-request state freshness
///
/// The **control-plane** state — the node record (`node.json`) and the peer
/// registry (`ledger_peers.json`) — is re-read from disk at the start of every
/// [`ControlNode::receive_at`] **and** [`ControlNode::receive_routed_at`] (via
/// [`ControlNode::refresh_control_plane`]), so mutations made by a separate
/// process (CLI `control exit`, `control admin approve`, node-to-node join
/// approval) are observed without a restart on both the direct and routed
/// paths. Both reloads warn and continue on failure: they describe
/// topology/identity, not authority to refuse service on.
///
/// The pending-join store and the replay sidecar ([`SeenStore`]) are
/// deliberately **not** reloaded per request: the former is this process's own
/// queue (persisted on every mutation), and the latter is seeded once at open so
/// a per-request reload could un-observe a nonce.
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
    /// Re-base/`DetachNotice` frames whose immediate delivery failed, retried by
    /// the bounded periodic sweep ([`sweep_pending_rebase`]). In-memory only: a
    /// restart heals via the child's startup `RebasePull` instead.
    pending_rebase: VecDeque<OutboundControl>,
    /// Whether this process is a node or a browser-style user leaf.
    ///
    /// A native node is always [`ChildKind::Node`]; the wasm client handles the
    /// [`ChildKind::User`] case itself (P3a). It is stored so the detach-notice
    /// flip (root `0` for a node, clear both for a user) is one tested code
    /// path.
    self_kind: ChildKind,
    /// Most-recent operator-signed decision per child, for redelivery.
    decisions: VecDeque<SignedControl>,
    /// Per-node replay guard keyed `origin:controller`, id = request nonce.
    /// Persisted across restarts via [`SeenStore`].
    seen: SeenStore,
}

impl ControlNode {
    /// Build an engine from already-open stores.
    ///
    /// This constructor is for harnesses/tests and does **not** load persisted
    /// replay marks: it starts with an empty guard even when `data_dir` already
    /// holds a `control_seen.json`, and the first accepted request will
    /// overwrite that file with the marks seen since construction. Production
    /// nodes must use [`ControlNode::open`], which re-seeds the guard from
    /// disk.
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
            pending_rebase: VecDeque::new(),
            self_kind: ChildKind::Node,
            decisions: VecDeque::new(),
            seen: SeenStore::empty(CONTROL_SEEN_CONFIG),
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
        let seen = SeenStore::open(&data_dir, CONTROL_SEEN_CONFIG, now_unix_seconds());
        Ok(ControlNode {
            data_dir,
            node_id: node_id.to_string(),
            operator,
            record,
            peers,
            pending,
            admins,
            outbound: VecDeque::new(),
            pending_rebase: VecDeque::new(),
            self_kind: ChildKind::Node,
            decisions: VecDeque::new(),
            seen,
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

    /// Drain the re-base notices awaiting a retry sweep.
    ///
    /// The sweep ([`sweep_pending_rebase`]) removes entries whose target is no
    /// longer a child before dialing; this accessor hands the rest to it.
    pub fn take_pending_rebase(&mut self) -> Vec<OutboundControl> {
        self.pending_rebase.drain(..).collect()
    }

    /// Put failed re-base notices back for a later sweep.
    ///
    /// Drops any entry whose target is no longer a current child (an exited or
    /// re-parented child can no longer be re-based by this node), de-duplicates
    /// by `(target, kind)`, and caps the queue at [`MAX_PENDING_REBASE`] by
    /// evicting the oldest entries.
    pub fn requeue_pending_rebase(&mut self, failed: Vec<OutboundControl>) {
        let children: Vec<String> = self
            .record
            .record()
            .children
            .iter()
            .map(|child| child.child_id.clone())
            .collect();
        for item in failed {
            if !children.iter().any(|id| id == item.target.as_str()) {
                continue;
            }
            self.pending_rebase
                .retain(|pending| !(pending.target == item.target && pending.kind == item.kind));
            self.pending_rebase.push_back(item);
        }
        while self.pending_rebase.len() > MAX_PENDING_REBASE {
            self.pending_rebase.pop_front();
        }
    }

    /// The node's best-effort subtree size (itself plus its direct children).
    ///
    /// A node only knows its direct child links, so it cannot count deeper
    /// descendants. This is the audit-only `subtree_nodes` value in
    /// [`ExitRequest`]; it never gates an exit.
    fn subtree_size(&self) -> u32 {
        self.record.record().children.len() as u32 + 1
    }

    /// Sign an [`ExitRequest`] naming this node, for its current parent.
    ///
    /// Self-signed with this node's own operator key (the parent authorizes it
    /// via `verify_control`). A node with no parent still produces a well-formed
    /// request; the caller decides whether to deliver it.
    pub fn sign_exit_request(&self, now: u64) -> Result<SignedControl, ControlError> {
        self.sign_decision(
            ControlRequest::Exit(ExitRequest {
                node: NodeId::from(self.node_id.clone()),
                subtree_nodes: self.subtree_size(),
            }),
            now,
        )
        .map_err(|code| ControlError::Codec(format!("cannot sign exit request: {code:?}")))
    }

    /// Apply the **local** half of an exit: re-root this node at `0` and queue a
    /// `Rebase` for each child.
    ///
    /// This is the durable, unilateral step and never depends on the parent
    /// being reachable. Delivering the `ExitRequest` to the parent is the
    /// caller's best-effort job; the queued child notices are drained by the
    /// caller (CLI) or retried by [`sweep_pending_rebase`].
    pub fn apply_exit(&mut self, now: u64) -> Result<(), ControlError> {
        self.record
            .rebase_to_root()
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        self.record
            .save()
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        let address = self
            .record
            .record()
            .address
            .clone()
            .expect("rebase_to_root always asserts the root address");
        self.propagate_rebase(&address, 1, now);
        self.audit(serde_json::json!({
            "ts": now,
            "event": "exit-applied",
            "node": self.node_id,
            "address": address.to_string(),
            "children": self.record.record().children.len(),
        }));
        Ok(())
    }

    /// Sign a `RebasePull` for this node, or `None` when it has no parent link.
    pub fn sign_rebase_pull(&self, now: u64) -> Option<SignedControl> {
        self.record.record().parent.as_ref()?;
        self.sign_decision(
            ControlRequest::RebasePull(RebasePull {
                node: NodeId::from(self.node_id.clone()),
            }),
            now,
        )
        .ok()
    }

    /// Verify a `RebasePull` reply snapshot and, if it names a different
    /// address for this node, apply it and recurse to this node's children.
    ///
    /// The reply is an **unsigned** [`ControlReply::Snapshot`] carried over
    /// direct control (the transport does not authenticate it), so nothing is
    /// applied until the snapshot is internally consistent *with this node's own
    /// parent link*:
    /// - `snapshot.node_id == record.parent.parent_id`;
    /// - the snapshot's own address derives this node's expected address as
    ///   `snapshot.address.child(record.parent.slot)`;
    /// - the snapshot lists this node with exactly that derived address.
    ///
    /// Returns `Ok(true)` when a different (verified) address was applied,
    /// `Ok(false)` when it was already current, and `Err` when the snapshot does
    /// not verify (the caller logs and ignores it — no mutation).
    pub fn apply_pull_snapshot(
        &mut self,
        snapshot: &NodeSnapshot,
        now: u64,
    ) -> Result<bool, ControlError> {
        let Some(parent) = self.record.record().parent.clone() else {
            return Err(ControlError::Codec(
                "cannot apply a pull without a parent link".to_string(),
            ));
        };
        if snapshot.node_id.as_str() != parent.parent_id {
            return Err(ControlError::Codec(format!(
                "pull snapshot names '{}', expected parent '{}'",
                snapshot.node_id, parent.parent_id
            )));
        }
        let Some(parent_address) = snapshot.address.clone() else {
            return Err(ControlError::Codec(
                "pull snapshot carries no address".to_string(),
            ));
        };
        let expected = parent_address.child(parent.slot);
        let child = snapshot
            .children
            .iter()
            .find(|child| child.child_id.as_str() == self.node_id)
            .ok_or_else(|| {
                ControlError::Codec("pull snapshot does not list this node".to_string())
            })?;
        if child.address.as_ref() != Some(&expected) {
            return Err(ControlError::Codec(format!(
                "pull snapshot derives {} for this node, expected {expected}",
                child
                    .address
                    .as_ref()
                    .map_or_else(|| "none".to_string(), |address| address.to_string())
            )));
        }
        if self.record.record().address.as_ref() == Some(&expected) {
            return Ok(false);
        }
        self.record
            .set_address(expected.clone())
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        self.record
            .save()
            .map_err(|err| ControlError::Codec(err.to_string()))?;
        self.audit(serde_json::json!({
            "ts": now,
            "event": "rebase-pull-applied",
            "node": self.node_id,
            "parent": parent.parent_id,
            "address": expected.to_string(),
        }));
        self.propagate_rebase(&expected, 1, now);
        Ok(true)
    }

    /// Override this process's own child kind (defaults to
    /// [`ChildKind::Node`]).
    ///
    /// A native node is always a node, so this is test-only: it exists so the
    /// shared detach-notice flip can be exercised for the [`ChildKind::User`]
    /// shape (which the wasm client otherwise owns).
    #[cfg(test)]
    pub fn set_self_kind(&mut self, kind: ChildKind) {
        self.self_kind = kind;
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

    /// Reload the **control-plane** state — the persisted node record
    /// (`node.json`) and the peer registry (`ledger_peers.json`) — from disk.
    ///
    /// Called at the top of both [`ControlNode::receive_at`] and
    /// [`ControlNode::receive_routed_at`], before any check that reads the
    /// record or the registry, so a mutation made by a *separate process* (the
    /// CLI rewriting `node.json`, or `control admin approve` registering a peer
    /// row) is observed without a restart on the routed path as well as the
    /// direct one.
    ///
    /// Both reloads are existence-guarded: a harness that never persisted a
    /// record/peers has no file to reload and keeps its in-memory state. Both
    /// warn and continue on failure: they describe topology/identity, not
    /// authority to refuse service on.
    fn refresh_control_plane(&mut self) {
        // Full reload of the persisted record so a topology mutation made by a
        // *separate process* is observed without a restart. The CLI `control
        // exit` rewrites `node.json` directly (it does not go through this
        // engine), so without this a live node would keep serving its stale
        // parent/children and never run the healing path.
        if self.data_dir.join(crate::record::NODE_RECORD_FILE).exists() {
            match RecordStore::open(&self.data_dir, &self.node_id) {
                Ok(record) => self.record = record,
                Err(err) => {
                    warn!(%err, "node record reload failed; using the in-memory record");
                }
            }
        }
        // Full reload so a peer row registered by a *separate process* is
        // observed without a restart. A child operator registered by `control
        // admin approve` / node-to-node join approval lives only on disk until
        // now, and exit/healing frames from that child are verified against this
        // registry (`verify_control` in `authorize`), so without this a live
        // node would keep refusing an otherwise-valid `Exit`/`RebasePull` with
        // `Unauthorized` until restart.
        if self.data_dir.join(ledger_peers::PEERS_FILE).exists() {
            match ledger_peers::load_peers(&self.data_dir) {
                Ok(peers) => self.peers = peers,
                Err(err) => {
                    warn!(%err, "peer registry reload failed; using the in-memory registry");
                }
            }
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
    /// 4. the persisted node record is reloaded from disk (warn-and-continue;
    ///    see [`ControlNode::refresh_control_plane`]);
    /// 5. the peer registry is reloaded from disk (warn-and-continue; same
    ///    helper);
    /// 6. admin grants are reloaded from disk (fail closed to empty);
    /// 7. the `(origin, controller, nonce)` replay guard;
    /// 8. dispatch.
    pub async fn receive_at(
        &mut self,
        _remote: EndpointId,
        signed: SignedControl,
        now: u64,
    ) -> ControlReply {
        if !is_supported_control_version(signed.version) {
            return ControlReply::Rejected(RejectCode::BadVersion);
        }
        // A v3 frame may carry only the pre-existing variants: the four exit
        // variants are v4-additive, so a v3 declaration over one is malformed
        // and must not be dispatched.
        if signed.version != CONTROL_FORMAT_VERSION && carries_v4_variant(&signed.request) {
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
        self.refresh_control_plane();
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
        match self
            .seen
            .observe(&seen_origin, nonce_msg_id(signed.nonce), signed.expiry)
        {
            Seen::Duplicate => {
                let reply = ControlReply::Rejected(RejectCode::Replay);
                self.audit_request(&signed, &reply, now);
                return reply;
            }
            Seen::Fresh => {
                // Persist the mark *before* dispatch so a crash cannot reopen
                // the window for an already-applied request. Fail closed: if
                // the mark is not durable, the request is not applied. The mark
                // stays set even if dispatch later rejects, matching the
                // terminal semantics of the in-memory guard.
                if let Err(err) = self.seen.save(&self.data_dir, now) {
                    warn!(
                        %err,
                        "control replay mark could not be persisted; refusing request"
                    );
                    let reply = ControlReply::Rejected(RejectCode::Internal);
                    self.audit_request(&signed, &reply, now);
                    return reply;
                }
            }
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
            ControlRequest::Exit(exit) => self.handle_exit(&signed, exit, now),
            ControlRequest::DetachNotice(notice) => self.handle_detach_notice(&signed, notice, now),
            ControlRequest::Rebase(notice) => self.handle_rebase(&signed, notice, now),
            ControlRequest::RebasePull(pull) => self.handle_rebase_pull(&signed, pull, now),
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
    /// 2. the persisted node record and peer registry are reloaded from disk
    ///    (warn-and-continue; see [`ControlNode::refresh_control_plane`]) so an
    ///    externally rewritten `node.json` or `ledger_peers.json` is observed;
    /// 3. `target.node`/`target.addr` name this node;
    /// 4. the carried intent self-verifies and its expiry is inside the TTL cap;
    /// 5. a forward exists, its `hop.node` is the authenticated `remote`, and
    ///    the destination's registry verifies it;
    /// 6. class gate:
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
        // Observe a control-plane mutation made by a *separate process* before
        // any record/registry-dependent check below (the `target.addr` match and
        // `verify_forward`/`authorize`). Without this a routed request would be
        // refused against stale state after a CLI rewrite of `node.json` or
        // `ledger_peers.json`.
        self.refresh_control_plane();
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

        // Join traffic and exit-rights traffic are direct-only: a routed
        // `Join`/`JoinApproved`/`JoinRejected`/`Exit`/`DetachNotice`/`Rebase`/
        // `RebasePull` is never accepted, whatever its signatures say. Exit
        // authority is peer-scoped and its propagation is a direct dial.
        if matches!(
            &routed.intent.request,
            ControlRequest::Join(_)
                | ControlRequest::JoinApproved(_)
                | ControlRequest::JoinRejected(_)
                | ControlRequest::Exit(_)
                | ControlRequest::DetachNotice(_)
                | ControlRequest::Rebase(_)
                | ControlRequest::RebasePull(_)
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
    /// # Idempotent re-approval
    ///
    /// `Exit` retains the child's [`PeerKeys`] row and, when the parent never
    /// processed the `Exit`, its child link too. Approving a re-join must
    /// therefore reconcile rather than fail:
    /// - an **identical** retained row is success and is not re-inserted
    ///   (`PeerRegistry::insert` rejects duplicates);
    /// - a child the record **already lists** is already attached: its existing
    ///   slot/address are returned and it is not re-attached;
    /// - a **ledger-only** change (same operator and role) updates the stored
    ///   row's ledger key and audits `peer-ledger-updated`: the operator key is
    ///   the identity/authority, while the ledger key is the child's own
    ///   settlement key, and retaining a stale key would reject the child's
    ///   future hops. This is sound because the pending [`JoinRequest`] was
    ///   **self-signed by the child** (`signed.origin == join.node`,
    ///   `signed.controller == join.operator`), so the child's own operator
    ///   vouches for the new key — the reconciliation is unconditional here.
    ///   (Contrast [`ControlNode::handle_create_child`], which is narrowed: a
    ///   `CreateChild` is not signed by the peer whose row changes.)
    /// - a **conflicting** row (different operator/role) or a slot taken by a
    ///   *different* child is still an error.
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
        // Reconcile the retained registry row before any mutation: an identical
        // row must not be re-inserted, a changed-operator/role row is refused
        // outright, and a ledger-only change is applied later (after the child
        // link is in place) by `reconcile_peer_row`.
        let peer_state = self.existing_peer_state(&peer);
        if peer_state == PeerState::Conflict {
            return Err(ControlError::Codec(format!(
                "peer row for '{}' conflicts with the approved operator/role",
                request.node
            )));
        }
        let peer_present = peer_state == PeerState::Identical;

        // A child the record already lists is already approved; keep its
        // existing slot and never re-attach it.
        let already_listed = self
            .record
            .record()
            .children
            .iter()
            .find(|c| c.child_id == request.node.as_str())
            .map(|c| c.slot);

        let slot = match already_listed {
            Some(existing) => {
                if let Some(requested) = slot {
                    if requested > cawala_topology::MAX_SLOT {
                        return Err(ControlError::SlotOutOfRange(requested));
                    }
                    if requested != existing
                        && self.record.record().children.iter().any(|c| c.slot == requested)
                    {
                        return Err(ControlError::Codec(format!(
                            "slot {requested} is already taken"
                        )));
                    }
                }
                existing
            }
            None => match slot {
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
            },
        };
        let child_address = base_address.child(slot);

        // Only now consume the pending row.
        self.pending.remove_pending(&node_id);

        if already_listed.is_none()
            && let Err(err) =
                self.record
                    .attach_child(request.node.as_str(), request.kind, Some(slot), now)
        {
            self.pending.add_pending(request);
            return Err(ControlError::Codec(err.to_string()));
        }

        // The retained row is reconciled unconditionally here: the pending
        // `JoinRequest` was **self-signed by the child** (`signed.origin ==
        // join.node`, `signed.controller == join.operator`), so the child's own
        // operator vouches for the new ledger key. The audit attributes the
        // rotation to that child.
        if !peer_present
            && let Err(code) =
                self.reconcile_peer_row(&peer, peer_state, request.node.as_str(), now)
        {
            if already_listed.is_none() {
                let _ = self.record.detach_child(request.node.as_str());
            }
            self.pending.add_pending(request);
            return Err(ControlError::Codec(format!(
                "peer row update failed: {code:?}"
            )));
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
        // An applicant the record already lists is a re-join of a child whose
        // `Exit` the parent never processed (or a duplicate of an existing
        // child): it is already attached, so queue it rather than reject it for
        // its own slot or for capacity. `approve_pending` then returns the
        // idempotent approval with the child's existing slot.
        let already_listed = self
            .record
            .record()
            .children
            .iter()
            .any(|c| c.child_id == join.node.as_str());
        if !already_listed {
            // Capacity check: an explicit slot must be free, otherwise the
            // parent picks the lowest free slot; a full node refuses.
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
        // Attach order matters: a node re-attaching from an independent root is
        // currently at `address = 0, parent = None`, and setting the parent
        // first would leave `parent = Some` + `address = 0`, which fails
        // validation (`AddressSlotMismatch`). Clear the address, set the parent,
        // then install the assigned address; each intermediate state is legal.
        if let Err(err) = self.record.unset_address() {
            self.record = record_backup;
            return ControlReply::Rejected(map_record_error(&err));
        }
        if let Err(err) = self
            .record
            .set_parent(signed.origin.as_str(), approval.slot)
        {
            self.record = record_backup;
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
                self.replace_peer_ledger(&signed.origin, Some(approval.parent_ledger))
            }
            Some(_) => Err(RejectCode::Unauthorized),
            None => self
                .peers
                .insert(expected)
                .map_err(|_| RejectCode::Unauthorized),
        }
    }

    /// Classify the registry row for `expected`'s node.
    ///
    /// The operator key is the identity/authority; the ledger key is the node's
    /// own settlement key, which it controls. A retained row that differs only
    /// in its ledger key is therefore reconciled ([`PeerState::LedgerChanged`])
    /// rather than refused: retaining a stale key would reject the node's future
    /// settlement hops. A changed operator or role is a genuine conflict
    /// ([`PeerState::Conflict`]).
    ///
    /// `Exit` deliberately retains the node's row, so "exit then change your
    /// mind" must treat the identical retained row as already registered rather
    /// than as a `DuplicateKey` conflict.
    fn existing_peer_state(&self, expected: &PeerKeys) -> PeerState {
        match self.peers.get(&expected.node_id) {
            None => PeerState::Absent,
            Some(existing) if existing == expected => PeerState::Identical,
            Some(existing)
                if existing.operator == expected.operator && existing.role == expected.role =>
            {
                PeerState::LedgerChanged
            }
            Some(_) => PeerState::Conflict,
        }
    }

    /// Apply the registry mutation implied by a re-approval/re-create.
    ///
    /// [`PeerState::Absent`] inserts the new row; [`PeerState::LedgerChanged`]
    /// replaces the retained row's ledger key and appends the additive
    /// `peer-ledger-updated` audit line naming `actor`; [`PeerState::Identical`]
    /// is a no-op (`PeerRegistry::insert` rejects a duplicate).
    /// [`PeerState::Conflict`] is refused — callers check it first, so it is
    /// defensive here.
    ///
    /// The operator key is the identity/authority and the ledger key is the
    /// child's own settlement key (which the child controls), so a
    /// same-operator/same-role row whose ledger key changed is updated: a stale
    /// key would reject the child's future hops. Whether that is sound depends
    /// on *who* vouches for the new key, which is the caller's concern: see
    /// [`ControlNode::approve_pending`] (the child's self-signed join) and
    /// [`ControlNode::handle_create_child`] (self-operator only).
    ///
    /// # Operational consequences
    ///
    /// A rotation is not a local bookkeeping detail:
    /// - the **old** ledger key's historical commitments and carried hops no
    ///   longer resolve against the updated registry — there is one ledger row
    ///   per node, so the new key replaces the old rather than supplementing it;
    /// - the rotation is **network-wide**: peers that still hold the old row
    ///   produce conflicting registry rows in a merged netting harness until
    ///   they too observe the new key.
    fn reconcile_peer_row(
        &mut self,
        peer: &PeerKeys,
        state: PeerState,
        actor: &str,
        now: u64,
    ) -> Result<(), RejectCode> {
        match state {
            PeerState::Identical => Ok(()),
            PeerState::Conflict => Err(RejectCode::Unauthorized),
            PeerState::Absent => self
                .peers
                .insert(peer.clone())
                .map_err(|err| map_ledger_error(&err)),
            PeerState::LedgerChanged => {
                let old = self.peers.get(&peer.node_id).and_then(|row| row.ledger);
                self.replace_peer_ledger(&peer.node_id, peer.ledger)?;
                self.audit(serde_json::json!({
                    "ts": now,
                    "event": "peer-ledger-updated",
                    "node": peer.node_id.to_string(),
                    "actor": actor,
                    "old_ledger": old.map(|key| key.to_string()),
                    "new_ledger": peer.ledger.map(|key| key.to_string()),
                }));
                Ok(())
            }
        }
    }

    /// Replace an existing peer row's ledger key, preserving its operator.
    ///
    /// `PeerRegistry` exposes no in-place update or removal (and the ledger
    /// crate is out of scope here), so rebuild it from its canonical
    /// seq-of-rows serde form with the one key swapped. The rebuild is into a
    /// fresh registry, so a failure (e.g. a ledger-key collision) leaves
    /// `self.peers` untouched.
    fn replace_peer_ledger(
        &mut self,
        node: &NodeId,
        ledger: Option<LedgerPubKey>,
    ) -> Result<(), RejectCode> {
        let value = serde_json::to_value(&self.peers).map_err(|_| RejectCode::Internal)?;
        let rows =
            serde_json::from_value::<Vec<PeerKeys>>(value).map_err(|_| RejectCode::Internal)?;
        let mut rebuilt = PeerRegistry::new();
        for mut row in rows {
            if &row.node_id == node {
                row.ledger = ledger;
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
                // The rejection must answer the *current* outbound request. A
                // non-zero rejection nonce that does not echo the outstanding
                // request's nonce is stale (or aimed at a different join) and
                // must not cancel this one; the outbound join is retained,
                // mirroring the pinned-mismatch behavior above.
                //
                // Residual: a rejection carrying nonce `0` is still accepted,
                // because the CLI `control reject` legitimately sends `0` when
                // the parent has no pending row (`main.rs` `.unwrap_or(0)`).
                // An unpinned (trust-on-first-use) join can therefore still be
                // cancelled by a zero-nonce rejection; closing that fully means
                // requiring a pending row in the CLI, which is out of scope
                // here.
                if outbound.request.nonce != 0
                    && rejection.nonce != 0
                    && rejection.nonce != outbound.request.nonce
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
        let authority = match self.authorize(signed, now) {
            Ok(authority) => authority,
            Err(code) => return ControlReply::Rejected(code),
        };
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
        // A retained identical row (a child that exited, or a replayed create)
        // must not be re-inserted, a changed-operator/role row is refused, and a
        // ledger-only change is applied by `reconcile_peer_row` — but **only**
        // when this node's own operator drove the create. Unlike a re-attach
        // join, a `CreateChild` is not signed by the peer whose row changes: a
        // senior child (`Authority::Peer`) could otherwise substitute a
        // sibling's/descendant's ledger key with one it controls. A senior-child
        // create with a changed ledger therefore keeps the pre-reconciliation
        // refusal (`Unauthorized`); new/identical rows are unchanged.
        let peer_state = self.existing_peer_state(&peer);
        if (peer_state == PeerState::LedgerChanged && authority != Authority::SelfOperator)
            || peer_state == PeerState::Conflict
        {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        let peer_present = peer_state == PeerState::Identical;

        // A child the record already lists is already created: idempotent
        // `Accepted`, no re-attach.
        let already_listed = self
            .record
            .record()
            .children
            .iter()
            .any(|c| c.child_id == create.child.as_str());
        if already_listed {
            if !peer_present {
                if let Err(code) = self.reconcile_peer_row(
                    &peer,
                    peer_state,
                    signed.origin.as_str(),
                    now,
                ) {
                    return ControlReply::Rejected(code);
                }
                if ledger_peers::save_peers(&self.data_dir, &self.peers).is_err() {
                    return ControlReply::Rejected(RejectCode::Internal);
                }
            }
            return ControlReply::Accepted;
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
        if !peer_present
            && let Err(code) =
                self.reconcile_peer_row(&peer, peer_state, signed.origin.as_str(), now)
        {
            self.record = backup;
            return ControlReply::Rejected(code);
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
        // Best-effort: tell the child it has been detached so it flips to an
        // independent root. A failed dial is audited by the delivery plumbing,
        // never surfaced to the requester.
        self.queue_notice(&detach.child, OutboundKind::DetachNotice, |node| {
            ControlRequest::DetachNotice(DetachNotice { node })
        }, now);
        ControlReply::Accepted
    }

    /// Queue one parent→child notice (signed by this node) for best-effort
    /// delivery.
    ///
    /// Signing is local and effectively infallible; on the theoretical failure
    /// it is logged and skipped rather than failing an already-applied mutation.
    fn queue_notice(
        &mut self,
        child: &NodeId,
        kind: OutboundKind,
        build: impl FnOnce(NodeId) -> ControlRequest,
        now: u64,
    ) {
        match self.sign_decision(build(child.clone()), now) {
            Ok(signed) => self.outbound.push_back(OutboundControl {
                target: child.clone(),
                signed,
                kind,
            }),
            Err(code) => warn!(child = %child, ?code, "could not sign outbound notice"),
        }
    }

    /// Parent side: a child unilaterally exits, so remove it from this node's
    /// child list.
    ///
    /// Authority is the child's **own** operator: `exit.node` must equal the
    /// signed `origin`, whose registered operator key must equal the signed
    /// `controller` (`verify_control`). This is deliberately **not**
    /// seniority-gated — any child may leave. `subtree_nodes` is audit-only and
    /// never gates the request. The child's [`PeerRegistry`] row is retained so
    /// it can re-attach; an already-removed child whose row still exists is an
    /// idempotent [`ControlReply::Accepted`], while an entirely unknown node is
    /// [`RejectCode::Unauthorized`].
    fn handle_exit(&mut self, signed: &SignedControl, exit: &ExitRequest, now: u64) -> ControlReply {
        if exit.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        if exit.node != signed.origin {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        // Binds `signed.origin` to its registered operator key and proves a
        // registry row exists, so an unknown node is refused here.
        if verify_control(signed, &self.peers).is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        let listed = self
            .record
            .record()
            .children
            .iter()
            .any(|child| child.child_id == exit.node.as_str());
        if listed {
            if let Err(err) = self.record.detach_child(exit.node.as_str()) {
                return ControlReply::Rejected(map_record_error(&err));
            }
            if self.record.save().is_err() {
                return ControlReply::Rejected(RejectCode::Internal);
            }
        }
        self.audit(serde_json::json!({
            "ts": now,
            "event": "exit",
            "child": exit.node.to_string(),
            "parent": self.node_id,
            "subtree_nodes": exit.subtree_nodes,
            "removed": listed,
        }));
        ControlReply::Accepted
    }

    /// Child side: the current direct parent detached this node, so flip to an
    /// independent root.
    ///
    /// Only the **current** direct parent may issue this (a stale former
    /// parent's notice is refused), and its operator must bind to `origin`. A
    /// [`ChildKind::Node`] receiver rebases to root `0`; a [`ChildKind::User`]
    /// receiver (a browser leaf) has no meaningful root address, so it clears
    /// both its parent link and its address. An already-detached node accepts
    /// this as a no-op.
    fn handle_detach_notice(
        &mut self,
        signed: &SignedControl,
        notice: &DetachNotice,
        now: u64,
    ) -> ControlReply {
        if notice.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        if notice.node.as_str() != self.node_id {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        let Some(parent) = self.record.record().parent.clone() else {
            // Already detached: a pure idempotent no-op. There is no state to
            // apply and, with no parent link, no origin to check against — a
            // redelivered notice (or one from a stale former parent) is accepted
            // rather than refused. Nothing is mutated, so accepting is safe.
            self.audit(serde_json::json!({
                "ts": now,
                "event": "detach-notice",
                "node": self.node_id,
                "outcome": "noop",
            }));
            return ControlReply::Accepted;
        };
        if signed.origin.as_str() != parent.parent_id {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if verify_control(signed, &self.peers).is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        let result = match self.self_kind {
            ChildKind::Node => self.record.rebase_to_root(),
            ChildKind::User => self
                .record
                .unset_address()
                .and_then(|()| self.record.unset_parent()),
        };
        if let Err(err) = result {
            return ControlReply::Rejected(map_record_error(&err));
        }
        if self.record.save().is_err() {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        self.audit(serde_json::json!({
            "ts": now,
            "event": "detach-notice",
            "node": self.node_id,
            "parent": parent.parent_id,
            "kind": child_kind_label(self.self_kind),
            "outcome": "applied",
        }));
        // A node that becomes a root must re-base its own children.
        if self.self_kind == ChildKind::Node {
            let root = self.record.record().address.clone();
            if let Some(root) = root {
                self.propagate_rebase(&root, 1, now);
            }
        }
        ControlReply::Accepted
    }

    /// Child side: apply a parent-signed address re-base, then recurse down.
    ///
    /// The receiver is the child. Authority is the **current** direct parent's
    /// operator (`origin == record.parent.parent_id`, bound by
    /// `verify_control`), and the topology rule `address ==
    /// parent_address.child(record.parent.slot)` is enforced here (a pure
    /// [`RebaseNotice::validate`] has no view of the parent link). Applying the
    /// already-current address is an idempotent [`ControlReply::Accepted`] that
    /// does not re-propagate.
    fn handle_rebase(
        &mut self,
        signed: &SignedControl,
        notice: &RebaseNotice,
        now: u64,
    ) -> ControlReply {
        if notice.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        if notice.node.as_str() != self.node_id {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        let Some(parent) = self.record.record().parent.clone() else {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        };
        if signed.origin.as_str() != parent.parent_id {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if verify_control(signed, &self.peers).is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if notice.address != notice.parent_address.child(parent.slot) {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        if self.record.record().address.as_ref() == Some(&notice.address) {
            self.audit(serde_json::json!({
                "ts": now,
                "event": "rebase",
                "node": self.node_id,
                "parent": parent.parent_id,
                "address": notice.address.to_string(),
                "generation": notice.generation,
                "outcome": "noop",
            }));
            return ControlReply::Accepted;
        }
        if let Err(err) = self.record.set_address(notice.address.clone()) {
            return ControlReply::Rejected(map_record_error(&err));
        }
        if self.record.save().is_err() {
            return ControlReply::Rejected(RejectCode::Internal);
        }
        self.audit(serde_json::json!({
            "ts": now,
            "event": "rebase",
            "node": self.node_id,
            "parent": parent.parent_id,
            "address": notice.address.to_string(),
            "generation": notice.generation,
            "outcome": "applied",
        }));
        self.propagate_rebase(&notice.address, notice.generation, now);
        ControlReply::Accepted
    }

    /// Queue a `Rebase` notice for every child, deriving each child's new
    /// address as `parent_address.child(slot)`.
    ///
    /// Best-effort: a child that cannot be reached is retried by the P2 sweep
    /// seam, never surfaced to the requester.
    fn propagate_rebase(&mut self, parent_address: &OctAddr, generation: u64, now: u64) {
        let children: Vec<(NodeId, u8)> = self
            .record
            .record()
            .children
            .iter()
            .map(|child| (NodeId::from(child.child_id.clone()), child.slot))
            .collect();
        for (child, slot) in children {
            let notice = RebaseNotice {
                node: child.clone(),
                parent_address: parent_address.clone(),
                address: parent_address.child(slot),
                generation,
            };
            self.queue_notice(&child, OutboundKind::Rebase, |node| {
                ControlRequest::Rebase(RebaseNotice {
                    node,
                    ..notice.clone()
                })
            }, now);
        }
    }

    /// Parent side: answer a child's healing pull with this node's snapshot.
    ///
    /// Authority is the requester's own operator (`pull.node == origin`, bound
    /// by `verify_control`) **and** the requester must be a *current child*: the
    /// reply is a full routing snapshot, and this node's own parent (or a former
    /// child whose peer row was retained across an `Exit`) must not be able to
    /// pull it. The snapshot already carries this node's address and each
    /// child's derived address, from which the child can compute its expected
    /// `parent_address.child(slot)` — no DTO change is needed.
    fn handle_rebase_pull(
        &mut self,
        signed: &SignedControl,
        pull: &RebasePull,
        now: u64,
    ) -> ControlReply {
        if pull.validate().is_err() {
            return ControlReply::Rejected(RejectCode::BadRequest);
        }
        if pull.node != signed.origin {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        // Only a current child may pull: the registry row (checked by
        // `verify_control` below) survives an `Exit`, and the parent link is
        // never a child link.
        if !self
            .record
            .record()
            .children
            .iter()
            .any(|child| child.child_id == pull.node.as_str())
        {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        if verify_control(signed, &self.peers).is_err() {
            return ControlReply::Rejected(RejectCode::Unauthorized);
        }
        self.audit(serde_json::json!({
            "ts": now,
            "event": "rebase-pull",
            "node": self.node_id,
            "requester": pull.node.to_string(),
        }));
        ControlReply::Snapshot(self.snapshot())
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
        // A re-join of a child the record already lists is already approved: its
        // own slot is not a conflict, and its presence does not consume capacity.
        let already_listed = self
            .record
            .record()
            .children
            .iter()
            .any(|c| c.child_id == child.as_str());
        match slot {
            Some(slot) if slot > cawala_topology::MAX_SLOT => Err(RejectCode::SlotOutOfRange),
            Some(slot)
                if self
                    .record
                    .record()
                    .children
                    .iter()
                    .any(|c| c.slot == slot && c.child_id != child.as_str()) =>
            {
                Err(RejectCode::SlotTaken)
            }
            None if !already_listed && lowest_free_slot(self.record.record()).is_none() => {
                Err(RejectCode::Capacity)
            }
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
        let failed_notices =
            deliver_outbound_decisions(&self.endpoint, &data_dir, outbound, &mut reply).await;
        if !failed_notices.is_empty() {
            // Topology notices have no reply field, so a failed dial is kept in
            // memory for the periodic retry sweep instead of being lost.
            let mut engine = self.node.lock().await;
            engine.requeue_pending_rebase(failed_notices);
        }
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

/// Whether `request` is one of the four variants appended in control format 4.
///
/// A v3-declared frame must not carry one of these; the node rejects such a
/// frame as [`RejectCode::BadVersion`] rather than dispatching it.
fn carries_v4_variant(request: &ControlRequest) -> bool {
    matches!(
        request,
        ControlRequest::Exit(_)
            | ControlRequest::DetachNotice(_)
            | ControlRequest::Rebase(_)
            | ControlRequest::RebasePull(_)
    )
}

/// Stable `"node"`/`"user"` label for a [`ChildKind`], for audit lines.
fn child_kind_label(kind: ChildKind) -> &'static str {
    match kind {
        ChildKind::Node => "node",
        ChildKind::User => "user",
    }
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

/// Dial one queued outbound frame and map the exchange to a [`DeliveryStatus`].
async fn deliver_one(endpoint: &Endpoint, item: &OutboundControl) -> DeliveryStatus {
    match item.target.as_str().parse::<EndpointId>() {
        Ok(target) => {
            delivery_status(
                ControlNode::send_direct(endpoint, target, &item.signed, DELIVERY_TIMEOUT).await,
            )
        }
        Err(err) => {
            warn!(child = %item.target, %err, "invalid outbound endpoint id");
            DeliveryStatus::Unreachable
        }
    }
}

/// Reverse-dial each queued outbound decision and patch `reply` with the last
/// applicant's delivery outcome.
///
/// Shared by the direct [`ControlHandler`] and the routed destination path so
/// `AdminApproved.delivery`/`AdminRejected.delivery` stay correct whichever
/// transport carried the request. The caller must have dropped the engine lock
/// (this awaits `send_direct`).
///
/// Returns the failed [`OutboundKind::Rebase`]/[`OutboundKind::DetachNotice`]
/// frames (best-effort topology notices have no reply field to surface a
/// failure), so the caller can requeue them via
/// [`ControlNode::requeue_pending_rebase`] for the retry sweep. Join decisions
/// are *not* returned: their outcome is carried in the patched reply.
pub(crate) async fn deliver_outbound_decisions(
    endpoint: &Endpoint,
    data_dir: &Path,
    outbound: Vec<OutboundControl>,
    reply: &mut ControlReply,
) -> Vec<OutboundControl> {
    let mut last_status = None;
    let mut failed_notices = Vec::new();
    for item in outbound {
        let status = deliver_one(endpoint, &item).await;
        audit_delivery(data_dir, &item.target, item.kind, &status);
        if !matches!(status, DeliveryStatus::Delivered)
            && matches!(
                item.kind,
                OutboundKind::Rebase | OutboundKind::DetachNotice
            )
        {
            failed_notices.push(item);
        }
        last_status = Some(status);
    }
    if let Some(status) = last_status {
        patch_delivery(reply, status);
    }
    failed_notices
}

/// Retry the re-base/`DetachNotice` frames whose immediate delivery failed.
///
/// One bounded pass: entries whose target is no longer a current child are
/// dropped (a re-based-by-another-parent child is no longer ours to re-base),
/// still-unreachable entries are put back for a later sweep, and the queue is
/// capped by [`ControlNode::requeue_pending_rebase`]. In-memory only; a restart
/// heals through the child's startup `RebasePull`.
pub async fn sweep_pending_rebase(endpoint: &Endpoint, control: &Arc<Mutex<ControlNode>>) {
    let (pending, children, data_dir) = {
        let mut engine = control.lock().await;
        let children: Vec<String> = engine
            .record
            .record()
            .children
            .iter()
            .map(|child| child.child_id.clone())
            .collect();
        (
            engine.take_pending_rebase(),
            children,
            engine.data_dir().to_path_buf(),
        )
    };
    if pending.is_empty() {
        return;
    }
    let mut retry = Vec::new();
    for item in pending {
        if !children.iter().any(|id| id == item.target.as_str()) {
            crate::audit::append(
                &data_dir,
                serde_json::json!({
                    "event": "delivery",
                    "child": item.target.to_string(),
                    "kind": item.kind.label(),
                    "outcome": "stale",
                }),
            );
            continue;
        }
        let status = deliver_one(endpoint, &item).await;
        audit_delivery(&data_dir, &item.target, item.kind, &status);
        if !matches!(status, DeliveryStatus::Delivered) {
            retry.push(item);
        }
    }
    if retry.is_empty() {
        return;
    }
    let mut engine = control.lock().await;
    engine.requeue_pending_rebase(retry);
}

/// Ask this node's parent for its snapshot and apply a verified re-base.
///
/// The pull is self-signed and sent over direct control. The reply is verified
/// by [`ControlNode::apply_pull_snapshot`] against the local parent link before
/// anything is applied; an unreachable parent (or an unverifiable snapshot) is
/// ignored, not fatal.
///
/// Returns `Ok(true)` when a different address was applied and `Ok(false)`
/// otherwise (no parent, no verifiable reply, or already current). Used at
/// startup and as the periodic healing probe.
pub async fn pull_rebase_from_parent(
    endpoint: &Endpoint,
    control: &Arc<Mutex<ControlNode>>,
    timeout: Duration,
    now: u64,
) -> Result<bool, ControlError> {
    let (target, signed) = {
        let engine = control.lock().await;
        let Some(parent) = engine.record.record().parent.as_ref() else {
            return Ok(false);
        };
        let Some(signed) = engine.sign_rebase_pull(now) else {
            return Ok(false);
        };
        (parent.parent_id.clone(), signed)
    };
    let target: EndpointId = target.parse().map_err(|err| {
        ControlError::Codec(format!("parent id '{target}' is not an endpoint id: {err}"))
    })?;
    let reply = ControlNode::send_direct(endpoint, target, &signed, timeout).await?;
    let ControlReply::Snapshot(snapshot) = reply else {
        return Err(ControlError::Codec(format!(
            "unexpected rebase-pull reply: {reply:?}"
        )));
    };
    let (applied, notices, data_dir) = {
        let mut engine = control.lock().await;
        let applied = engine.apply_pull_snapshot(&snapshot, now)?;
        let notices = if applied {
            engine.take_outbound()
        } else {
            Vec::new()
        };
        (applied, notices, engine.data_dir().to_path_buf())
    };
    if !applied {
        return Ok(false);
    }
    // A verified re-base queues a `Rebase` for each child; deliver them here so
    // the healing pull converges the whole subtree, keeping failures for the
    // periodic sweep.
    let mut retry = Vec::new();
    for item in notices {
        let status = deliver_one(endpoint, &item).await;
        audit_delivery(&data_dir, &item.target, item.kind, &status);
        if !matches!(status, DeliveryStatus::Delivered) {
            retry.push(item);
        }
    }
    if !retry.is_empty() {
        let mut engine = control.lock().await;
        engine.requeue_pending_rebase(retry);
    }
    Ok(true)
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
        | ControlError::FieldBelowMinimum { .. }
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

    /// **F**: a rejection whose non-zero nonce does not echo the outstanding
    /// request must not cancel the in-flight join; a matching nonce is
    /// accepted and clears it. Mirrors `stale_approval_nonce_is_rejected_without_change`.
    #[tokio::test]
    async fn stale_rejection_nonce_is_rejected_without_change() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = OperatorSecretKey::from_bytes([3u8; 32]);
        let (mut engine, request) = outbound_applicant(dir.path(), None);
        let remote = EndpointId::from(SecretKey::generate().public());

        // A rejection for a different (non-zero) request nonce is refused
        // before any mutation; the current outbound join is retained.
        let stale = JoinRejection {
            child: NodeId::from("me"),
            reason: "stale".to_string(),
            nonce: request.nonce + 100,
        };
        let signed = authorize_at("parent", &parent_op, 1, ControlRequest::JoinRejected(stale));
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        assert!(
            engine.pending().outbound().is_some(),
            "the current outbound join is retained for a matching rejection"
        );

        // The rejection that echoes the outstanding nonce is accepted.
        let matching = JoinRejection {
            child: NodeId::from("me"),
            reason: "matched".to_string(),
            nonce: request.nonce,
        };
        let signed = authorize_at(
            "parent",
            &parent_op,
            2,
            ControlRequest::JoinRejected(matching),
        );
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Accepted
        );
        assert!(engine.pending().outbound().is_none());
    }

    /// Documented residual: a `0` rejection nonce is still accepted. The CLI
    /// `control reject` sends `0` when the parent has no pending row
    /// (`main.rs`), so treating it as stale would break that path. Closing this
    /// fully requires the CLI to require a pending row (out of scope).
    #[tokio::test]
    async fn zero_rejection_nonce_is_still_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = OperatorSecretKey::from_bytes([3u8; 32]);
        let (mut engine, _request) = outbound_applicant(dir.path(), None);
        let remote = EndpointId::from(SecretKey::generate().public());
        let rejection = JoinRejection {
            child: NodeId::from("me"),
            reason: "cli".to_string(),
            nonce: 0,
        };
        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::JoinRejected(rejection),
        );
        assert_eq!(
            engine.receive_at(remote, signed, 0).await,
            ControlReply::Accepted
        );
        assert!(engine.pending().outbound().is_none());
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

    // -----------------------------------------------------------------------
    // M5 exit rights (format 4): Exit / DetachNotice / Rebase / RebasePull
    // -----------------------------------------------------------------------

    fn secret(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn node_peer(id: &str, op: &OperatorSecretKey, ledger_seed: u8) -> PeerKeys {
        PeerKeys {
            node_id: NodeId::from(id),
            operator: op.public(),
            ledger: Some(ledger(ledger_seed)),
            role: PeerRole::Node,
        }
    }

    fn user_peer(id: &str, op: &OperatorSecretKey) -> PeerKeys {
        PeerKeys {
            node_id: NodeId::from(id),
            operator: op.public(),
            ledger: None,
            role: PeerRole::User,
        }
    }

    /// A `RecordStore` with the given links (parent set before address, so a
    /// non-root address validates).
    fn record_store(
        dir: &std::path::Path,
        node_id: &str,
        address: Option<&str>,
        parent: Option<(&str, u8)>,
        children: &[(&str, ChildKind, u8, u64)],
    ) -> RecordStore {
        let mut store = RecordStore::open(dir, node_id).unwrap();
        if let Some((parent, slot)) = parent {
            store.set_parent(parent, slot).unwrap();
        }
        if let Some(address) = address {
            store.set_address(address.parse().unwrap()).unwrap();
        }
        for (id, kind, slot, date) in children {
            store.attach_child(*id, *kind, Some(*slot), *date).unwrap();
        }
        store
    }

    fn engine_with(
        dir: &std::path::Path,
        node_id: &str,
        operator: OperatorSecretKey,
        record: RecordStore,
        peers: &[PeerKeys],
    ) -> ControlNode {
        let mut registry = PeerRegistry::new();
        for row in peers {
            registry.insert(row.clone()).unwrap();
        }
        let store = ControlStore::open(dir).unwrap();
        ControlNode::new(
            dir.to_path_buf(),
            node_id,
            operator,
            record,
            registry,
            store,
            AdminStore::empty(),
        )
    }

    /// A `SignedControl` that declares `version`, re-signing so the version byte
    /// is inside the signed preimage exactly as a real peer would have it.
    fn authorize_version(
        origin: &str,
        op: &OperatorSecretKey,
        nonce: u64,
        request: ControlRequest,
        version: u8,
    ) -> SignedControl {
        let mut signed = authorize_at(origin, op, nonce, request);
        signed.version = version;
        signed.signature = op.sign(signed.signing_hash().as_bytes());
        signed
    }

    fn any_remote() -> EndpointId {
        EndpointId::from(SecretKey::generate().public())
    }

    fn exit_request(node: &str, subtree_nodes: u32) -> ControlRequest {
        ControlRequest::Exit(ExitRequest {
            node: NodeId::from(node),
            subtree_nodes,
        })
    }

    #[tokio::test]
    async fn exit_non_senior_node_child_can_leave() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[
                ("senior", ChildKind::Node, 0, 1),
                ("child", ChildKind::Node, 3, 2),
            ],
        );
        let peers = [
            node_peer("senior", &secret(3), 3),
            node_peer("child", &child_op, 2),
        ];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);

        let signed = authorize_at("child", &child_op, 1, exit_request("child", 1));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
        let children = &engine.record().children;
        assert!(
            !children.iter().any(|c| c.child_id == "child"),
            "the exiting child is removed"
        );
        assert!(
            children.iter().any(|c| c.child_id == "senior"),
            "other children are untouched"
        );
        assert!(
            engine.peers().get(&NodeId::from("child")).is_some(),
            "the peer row is retained for a possible re-attach"
        );
    }

    #[tokio::test]
    async fn exit_user_child_can_leave() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let user_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[("browser", ChildKind::User, 5, 7)],
        );
        let peers = [user_peer("browser", &user_op)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);

        let signed = authorize_at("browser", &user_op, 1, exit_request("browser", 1));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
        assert!(
            !engine
                .record()
                .children
                .iter()
                .any(|c| c.child_id == "browser")
        );
    }

    #[tokio::test]
    async fn exit_wrong_origin_or_controller_is_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[
                ("senior", ChildKind::Node, 0, 1),
                ("child", ChildKind::Node, 3, 2),
            ],
        );
        let peers = [
            node_peer("senior", &secret(3), 3),
            node_peer("child", &child_op, 2),
        ];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);

        // The request names `child` but is signed by a different (registered)
        // origin.
        let wrong_origin = authorize_at("senior", &secret(3), 1, exit_request("child", 1));
        assert_eq!(
            engine.receive_at(any_remote(), wrong_origin, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );

        // Same origin node, but signed by a key that is not its registered
        // operator.
        let wrong_controller = authorize_at("child", &secret(9), 2, exit_request("child", 1));
        assert_eq!(
            engine.receive_at(any_remote(), wrong_controller, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        assert!(
            engine
                .record()
                .children
                .iter()
                .any(|c| c.child_id == "child"),
            "no mutation on refusal"
        );
    }

    #[tokio::test]
    async fn exit_without_registry_row_is_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let record = record_store(dir.path(), "parent", Some("0"), None, &[]);
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &[]);
        let signed = authorize_at("ghost", &secret(8), 1, exit_request("ghost", 1));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
    }

    #[tokio::test]
    async fn exit_absent_but_registered_is_idempotent_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        // The parent no longer lists the child, but the registry row remains.
        let record = record_store(dir.path(), "parent", Some("0"), None, &[]);
        let peers = [node_peer("child", &child_op, 2)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);
        let signed = authorize_at("child", &child_op, 1, exit_request("child", 1));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
    }

    #[tokio::test]
    async fn exit_replay_returns_replay() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[("child", ChildKind::Node, 3, 2)],
        );
        let peers = [node_peer("child", &child_op, 2)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);
        let signed = authorize_at("child", &child_op, 1, exit_request("child", 1));
        assert_eq!(
            engine.receive_at(any_remote(), signed.clone(), 0).await,
            ControlReply::Accepted
        );
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Rejected(RejectCode::Replay)
        );
    }

    #[tokio::test]
    async fn detach_notice_rebases_node_child_to_root() {
        let dir = tempfile::tempdir().unwrap();
        let child_op = secret(1);
        let parent_op = secret(2);
        let record = record_store(
            dir.path(),
            "child",
            Some("0.2"),
            Some(("parent", 2)),
            &[("c1", ChildKind::Node, 0, 1)],
        );
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut engine = engine_with(dir.path(), "child", child_op, record, &peers);

        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from("child"),
            }),
        );
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
        assert!(engine.record().parent.is_none());
        assert_eq!(engine.record().address, Some("0".parse().unwrap()));

        // The new root pushes a Rebase to each of its own children.
        let outbound = engine.take_outbound();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].kind, OutboundKind::Rebase);
        assert_eq!(outbound[0].target, NodeId::from("c1"));
        let ControlRequest::Rebase(notice) = &outbound[0].signed.request else {
            panic!("expected a Rebase frame");
        };
        assert_eq!(notice.node, NodeId::from("c1"));
        assert_eq!(notice.parent_address, "0".parse().unwrap());
        assert_eq!(notice.address, "0.0".parse().unwrap());
        assert_eq!(outbound[0].signed.origin, NodeId::from("child"));
    }

    #[tokio::test]
    async fn detach_notice_clears_user_parent_and_address() {
        let dir = tempfile::tempdir().unwrap();
        let user_op = secret(1);
        let parent_op = secret(2);
        let record = record_store(
            dir.path(),
            "browser",
            Some("0.2"),
            Some(("parent", 2)),
            &[],
        );
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut engine = engine_with(dir.path(), "browser", user_op, record, &peers);
        engine.set_self_kind(ChildKind::User);

        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from("browser"),
            }),
        );
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
        assert!(engine.record().parent.is_none());
        assert_eq!(engine.record().address, None, "a user has no root address");
        assert!(engine.take_outbound().is_empty());
    }

    #[tokio::test]
    async fn detach_notice_wrong_node_origin_and_stale_former_parent_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let child_op = secret(1);
        let parent_op = secret(2);
        let other_op = secret(3);
        let record = record_store(
            dir.path(),
            "child",
            Some("0.2"),
            Some(("parent", 2)),
            &[],
        );
        let peers = [
            node_peer("parent", &parent_op, 3),
            node_peer("other", &other_op, 4),
        ];
        let mut engine = engine_with(dir.path(), "child", child_op.clone(), record, &peers);

        // Names a different node.
        let wrong_node = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from("other"),
            }),
        );
        assert_eq!(
            engine.receive_at(any_remote(), wrong_node, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );

        // Signed by a registered peer that is not the current parent.
        let wrong_origin = authorize_at(
            "other",
            &other_op,
            2,
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from("child"),
            }),
        );
        assert_eq!(
            engine.receive_at(any_remote(), wrong_origin, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );

        // A former parent: the current parent is `newparent`.
        let dir2 = tempfile::tempdir().unwrap();
        let record = record_store(
            dir2.path(),
            "child",
            Some("0.3"),
            Some(("newparent", 3)),
            &[],
        );
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut stale = engine_with(dir2.path(), "child", child_op.clone(), record, &peers);
        let stale_notice = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from("child"),
            }),
        );
        assert_eq!(
            stale.receive_at(any_remote(), stale_notice, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
        assert!(stale.record().parent.is_some(), "no mutation on refusal");
    }

    #[tokio::test]
    async fn detach_notice_already_detached_is_accepted_noop() {
        let dir = tempfile::tempdir().unwrap();
        let child_op = secret(1);
        let parent_op = secret(2);
        let record = record_store(dir.path(), "child", None, None, &[]);
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut engine = engine_with(dir.path(), "child", child_op, record, &peers);
        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from("child"),
            }),
        );
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
        assert!(engine.record().parent.is_none());
    }

    fn rebase_request(
        address: &str,
        parent_address: &str,
        generation: u64,
    ) -> ControlRequest {
        ControlRequest::Rebase(RebaseNotice {
            node: NodeId::from("child"),
            parent_address: parent_address.parse().unwrap(),
            address: address.parse().unwrap(),
            generation,
        })
    }

    #[tokio::test]
    async fn rebase_applies_parent_derived_address() {
        let dir = tempfile::tempdir().unwrap();
        let child_op = secret(1);
        let parent_op = secret(2);
        let record = record_store(
            dir.path(),
            "child",
            Some("0.2"),
            Some(("parent", 2)),
            &[],
        );
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut engine = engine_with(dir.path(), "child", child_op, record, &peers);
        let signed = authorize_at("parent", &parent_op, 1, rebase_request("0.5.2", "0.5", 1));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
        assert_eq!(engine.record().address, Some("0.5.2".parse().unwrap()));
    }

    #[tokio::test]
    async fn rebase_rejects_address_slot_mismatch_and_stale_former_parent() {
        let dir = tempfile::tempdir().unwrap();
        let child_op = secret(1);
        let parent_op = secret(2);
        let record = record_store(
            dir.path(),
            "child",
            Some("0.2"),
            Some(("parent", 2)),
            &[],
        );
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut engine = engine_with(dir.path(), "child", child_op.clone(), record, &peers);

        // `parent_address.child(2)` is `0.5.2`, not `0.5.3`.
        let mismatch = authorize_at("parent", &parent_op, 1, rebase_request("0.5.3", "0.5", 1));
        assert_eq!(
            engine.receive_at(any_remote(), mismatch, 0).await,
            ControlReply::Rejected(RejectCode::BadRequest)
        );
        assert_eq!(engine.record().address, Some("0.2".parse().unwrap()));

        // Current parent is `newparent`; `parent` is stale.
        let dir2 = tempfile::tempdir().unwrap();
        let record = record_store(
            dir2.path(),
            "child",
            Some("0.3"),
            Some(("newparent", 3)),
            &[],
        );
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut stale = engine_with(dir2.path(), "child", child_op.clone(), record, &peers);
        let stale_rebase = authorize_at("parent", &parent_op, 1, rebase_request("0.5.3", "0.5", 1));
        assert_eq!(
            stale.receive_at(any_remote(), stale_rebase, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
    }

    #[tokio::test]
    async fn rebase_is_idempotent_on_reapply() {
        let dir = tempfile::tempdir().unwrap();
        let child_op = secret(1);
        let parent_op = secret(2);
        let record = record_store(
            dir.path(),
            "child",
            Some("0.5.2"),
            Some(("parent", 2)),
            &[],
        );
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut engine = engine_with(dir.path(), "child", child_op, record, &peers);
        let signed = authorize_at("parent", &parent_op, 1, rebase_request("0.5.2", "0.5", 1));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
        assert_eq!(engine.record().address, Some("0.5.2".parse().unwrap()));
        assert!(
            engine.take_outbound().is_empty(),
            "an idempotent re-apply must not re-propagate"
        );
    }

    #[tokio::test]
    async fn rebase_queues_notices_to_children() {
        let dir = tempfile::tempdir().unwrap();
        let child_op = secret(1);
        let parent_op = secret(2);
        let record = record_store(
            dir.path(),
            "child",
            Some("0.2"),
            Some(("parent", 2)),
            &[
                ("c1", ChildKind::Node, 0, 1),
                ("c2", ChildKind::Node, 4, 2),
            ],
        );
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut engine = engine_with(dir.path(), "child", child_op, record, &peers);
        let signed = authorize_at("parent", &parent_op, 1, rebase_request("0.5.2", "0.5", 1));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );

        let outbound = engine.take_outbound();
        assert_eq!(outbound.len(), 2);
        let mut addresses: Vec<(String, String)> = outbound
            .iter()
            .map(|item| {
                assert_eq!(item.kind, OutboundKind::Rebase);
                assert_eq!(item.signed.origin, NodeId::from("child"));
                let ControlRequest::Rebase(notice) = &item.signed.request else {
                    panic!("expected a Rebase frame");
                };
                (
                    item.target.to_string(),
                    notice.address.to_string(),
                )
            })
            .collect();
        addresses.sort();
        assert_eq!(
            addresses,
            vec![
                ("c1".to_string(), "0.5.2.0".to_string()),
                ("c2".to_string(), "0.5.2.4".to_string()),
            ]
        );
        // The notice's generation is carried down.
        for item in &outbound {
            let ControlRequest::Rebase(notice) = &item.signed.request else {
                unreachable!();
            };
            assert_eq!(notice.generation, 1);
            assert_eq!(notice.parent_address, "0.5.2".parse().unwrap());
        }
    }

    #[tokio::test]
    async fn rebase_pull_replies_with_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0.5"),
            Some(("grand", 5)),
            &[("child", ChildKind::Node, 2, 1)],
        );
        let peers = [node_peer("child", &child_op, 3)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);
        let signed = authorize_at(
            "child",
            &child_op,
            1,
            ControlRequest::RebasePull(RebasePull {
                node: NodeId::from("child"),
            }),
        );
        let reply = engine.receive_at(any_remote(), signed, 0).await;
        let ControlReply::Snapshot(snapshot) = reply else {
            panic!("expected Snapshot, got {reply:?}");
        };
        assert_eq!(snapshot.address, Some("0.5".parse().unwrap()));
        assert_eq!(snapshot.children.len(), 1);
        assert_eq!(snapshot.children[0].child_id, NodeId::from("child"));
        assert_eq!(
            snapshot.children[0].address,
            Some("0.5.2".parse().unwrap()),
            "the snapshot carries the child's derived address"
        );
    }

    /// **M1**: a node's own parent must not be able to pull the node's full
    /// routing snapshot. It is registered (so `verify_control` passes) but is
    /// not a child.
    #[tokio::test]
    async fn rebase_pull_from_own_parent_is_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        let child_op = secret(1);
        let parent_op = secret(2);
        let record = record_store(
            dir.path(),
            "child",
            Some("0.5.2"),
            Some(("parent", 2)),
            &[],
        );
        let peers = [node_peer("parent", &parent_op, 3)];
        let mut engine = engine_with(dir.path(), "child", child_op, record, &peers);
        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::RebasePull(RebasePull {
                node: NodeId::from("parent"),
            }),
        );
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
    }

    /// **M1**: a former child's registry row is retained across `Exit`, but an
    /// already-exited child is no longer a child and must not be able to pull.
    #[tokio::test]
    async fn rebase_pull_from_retained_former_child_is_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        // `child` is registered but not listed as a child (it has exited).
        let record = record_store(dir.path(), "parent", Some("0"), None, &[]);
        let peers = [node_peer("child", &child_op, 3)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);
        let signed = authorize_at(
            "child",
            &child_op,
            1,
            ControlRequest::RebasePull(RebasePull {
                node: NodeId::from("child"),
            }),
        );
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
    }

    #[tokio::test]
    async fn rebase_pull_wrong_node_is_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0.5"),
            Some(("grand", 5)),
            &[("child", ChildKind::Node, 2, 1)],
        );
        let peers = [node_peer("child", &child_op, 3)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);
        // Signed by `child`, but claims a different requester.
        let signed = authorize_at(
            "child",
            &child_op,
            1,
            ControlRequest::RebasePull(RebasePull {
                node: NodeId::from("other"),
            }),
        );
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized)
        );
    }

    #[tokio::test]
    async fn v3_frame_cannot_carry_exit_but_v4_query_works() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[("child", ChildKind::Node, 3, 2)],
        );
        let peers = [node_peer("child", &child_op, 2)];
        let mut engine = engine_with(dir.path(), "parent", parent_op.clone(), record, &peers);

        let v3_exit = authorize_version("child", &child_op, 1, exit_request("child", 1), 3);
        assert_eq!(
            engine.receive_at(any_remote(), v3_exit, 0).await,
            ControlReply::Rejected(RejectCode::BadVersion)
        );

        // A v4 frame over a pre-existing variant is dispatched normally.
        let query = authorize_at("parent", &parent_op, 2, ControlRequest::Query);
        assert!(matches!(
            engine.receive_at(any_remote(), query, 0).await,
            ControlReply::Snapshot(_)
        ));
    }

    /// **A6**: the v3 shape gate covers all four v4 variants, not just `Exit`.
    #[test]
    fn carries_v4_variant_covers_all_four_appended_variants() {
        let v4 = [
            exit_request("child", 1),
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from("child"),
            }),
            rebase_request("0.5.2", "0.5", 1),
            ControlRequest::RebasePull(RebasePull {
                node: NodeId::from("child"),
            }),
        ];
        for request in v4 {
            assert!(carries_v4_variant(&request), "{request:?}");
        }
        // Pre-existing variants are not covered by the gate.
        for request in [
            ControlRequest::Query,
            ControlRequest::SetAddress(SetAddress { address: None }),
            ControlRequest::DetachChild(DetachChild {
                child: NodeId::from("child"),
            }),
        ] {
            assert!(!carries_v4_variant(&request), "{request:?}");
        }
    }

    /// **A6**: a v3-declared frame carrying an *old* (pre-v4) variant still
    /// dispatches under a v4 node; only the four appended variants are gated.
    #[tokio::test]
    async fn v3_frame_carrying_old_variant_still_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let applicant_op = secret(2);
        let record = record_store(dir.path(), "parent", Some("0"), None, &[]);
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &[]);

        let join = JoinRequest {
            node: NodeId::from("applicant"),
            kind: ChildKind::User,
            operator: applicant_op.public(),
            ledger: None,
            desired_slot: None,
            location_hint: None,
            nonce: 7,
            expiry: u64::MAX,
        };
        let v3_join = authorize_version(
            "applicant",
            &applicant_op,
            1,
            ControlRequest::Join(join),
            3,
        );
        assert_eq!(
            engine.receive_at(any_remote(), v3_join, 0).await,
            ControlReply::Pending,
            "a v3 frame over a pre-existing variant must dispatch"
        );
    }

    /// **A4**: a failed notice whose target is no longer a child is dropped, and
    /// the pending queue de-duplicates by `(target, kind)`.
    #[test]
    fn requeue_pending_rebase_drops_non_children_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[("child", ChildKind::Node, 1, 1)],
        );
        let op = secret(1);
        let mut engine = engine_with(dir.path(), "parent", op.clone(), record, &[]);
        let item = |target: &str, nonce: u64| OutboundControl {
            target: NodeId::from(target),
            signed: authorize_at(
                "parent",
                &op,
                nonce,
                ControlRequest::Rebase(RebaseNotice {
                    node: NodeId::from(target),
                    parent_address: "0".parse().unwrap(),
                    address: "0.1".parse().unwrap(),
                    generation: 1,
                }),
            ),
            kind: OutboundKind::Rebase,
        };

        engine.requeue_pending_rebase(vec![item("child", 1), item("ghost", 2)]);
        assert_eq!(engine.take_pending_rebase().len(), 1, "ghost is not a child");

        engine.requeue_pending_rebase(vec![item("child", 3), item("child", 4)]);
        assert_eq!(engine.take_pending_rebase().len(), 1, "de-duplicated");
    }

    /// **A3**: a `RebasePull` reply is verified against the local parent link
    /// before anything is applied.
    #[test]
    fn apply_pull_snapshot_verifies_parent_and_derived_address() {
        let dir = tempfile::tempdir().unwrap();
        let record = record_store(
            dir.path(),
            "child",
            Some("0.5.2"),
            Some(("parent", 2)),
            &[],
        );
        let mut engine = engine_with(dir.path(), "child", secret(1), record, &[]);
        let snapshot = |node_id: &str, address: &str, child_address: Option<&str>| NodeSnapshot {
            node_id: NodeId::from(node_id),
            address: Some(address.parse().unwrap()),
            parent: None,
            children: vec![ChildSnapshot {
                child_id: NodeId::from("child"),
                kind: ChildKind::Node,
                slot: 2,
                address: child_address.map(|a| a.parse().unwrap()),
                date_joined: 1,
            }],
        };

        // Already current: verifies, no mutation, no propagation.
        assert_eq!(
            engine.apply_pull_snapshot(&snapshot("parent", "0.5", Some("0.5.2")), 0),
            Ok(false)
        );
        assert!(engine.take_outbound().is_empty());

        // A different, consistent prefix is applied and propagated.
        assert_eq!(
            engine.apply_pull_snapshot(&snapshot("parent", "0.7", Some("0.7.2")), 0),
            Ok(true)
        );
        assert_eq!(engine.record().address, Some("0.7.2".parse().unwrap()));

        // The snapshot must name the current parent...
        assert!(
            engine
                .apply_pull_snapshot(&snapshot("impostor", "0.7", Some("0.7.2")), 0)
                .is_err()
        );
        // ...and derive exactly this node's address.
        assert!(
            engine
                .apply_pull_snapshot(&snapshot("parent", "0.7", Some("0.7.3")), 0)
                .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // Integration-gate remediation: G2 (idempotent re-approval) and G3 (live
    // record reload).
    // -----------------------------------------------------------------------

    /// Build a persisted root engine so the record-reload path has a file to
    /// read (unlike the in-memory-only `engine_with` harnesses).
    fn persisted_root_engine(dir: &std::path::Path, op: OperatorSecretKey) -> ControlNode {
        let mut record = RecordStore::open(dir, "parent").unwrap();
        record.set_address("0".parse().unwrap()).unwrap();
        record.save().unwrap();
        ControlNode::new(
            dir,
            "parent",
            op,
            record,
            PeerRegistry::new(),
            ControlStore::open(dir).unwrap(),
            AdminStore::empty(),
        )
    }

    /// **G3**: a control request observes a `node.json` rewritten by a separate
    /// process (e.g. CLI `control exit`), not the stale in-memory record.
    #[tokio::test]
    async fn receive_at_observes_externally_rewritten_record() {
        let dir = tempfile::tempdir().unwrap();
        let operator = secret(1);
        let mut engine = persisted_root_engine(dir.path(), operator.clone());
        let remote = any_remote();

        let before = engine
            .receive_at(
                remote,
                authorize_at("parent", &operator, 1, ControlRequest::Query),
                0,
            )
            .await;
        let ControlReply::Snapshot(before) = before else {
            panic!("expected Snapshot, got {before:?}");
        };
        assert!(before.children.is_empty());

        // An external process rewrites `node.json`.
        let mut external = RecordStore::open(dir.path(), "parent").unwrap();
        external
            .attach_child("browser", ChildKind::User, Some(2), 5)
            .unwrap();
        external.save().unwrap();

        let after = engine
            .receive_at(
                remote,
                authorize_at("parent", &operator, 2, ControlRequest::Query),
                0,
            )
            .await;
        let ControlReply::Snapshot(after) = after else {
            panic!("expected Snapshot, got {after:?}");
        };
        assert!(
            after
                .children
                .iter()
                .any(|c| c.child_id.as_str() == "browser"),
            "the reloaded record must be visible: {after:?}"
        );
    }

    /// **G3**: a failed record reload warns and keeps serving the in-memory
    /// record (topology is not authority, so it must not fail closed).
    #[tokio::test]
    async fn receive_at_keeps_in_memory_record_when_reload_fails() {
        let dir = tempfile::tempdir().unwrap();
        let operator = secret(1);
        let mut engine = persisted_root_engine(dir.path(), operator.clone());
        std::fs::write(dir.path().join(crate::record::NODE_RECORD_FILE), b"not json").unwrap();

        let reply = engine
            .receive_at(
                any_remote(),
                authorize_at("parent", &operator, 1, ControlRequest::Query),
                0,
            )
            .await;
        let ControlReply::Snapshot(snapshot) = reply else {
            panic!("expected Snapshot, got {reply:?}");
        };
        assert_eq!(snapshot.address, Some("0".parse().unwrap()));
    }

    // -----------------------------------------------------------------------
    // Integration-gate remediation, G3 follow-up: live peer-registry reload.
    // -----------------------------------------------------------------------

    /// A persisted root engine whose `node.json` lists `child` but whose
    /// `ledger_peers.json` is absent (the child's row is not registered yet).
    fn persisted_parent_with_child(
        dir: &std::path::Path,
        parent_op: OperatorSecretKey,
        child_id: &str,
    ) -> ControlNode {
        let mut record = RecordStore::open(dir, "parent").unwrap();
        record.set_address("0".parse().unwrap()).unwrap();
        record
            .attach_child(child_id, ChildKind::Node, Some(0), 1)
            .unwrap();
        record.save().unwrap();
        ControlNode::new(
            dir,
            "parent",
            parent_op,
            record,
            PeerRegistry::new(),
            ControlStore::open(dir).unwrap(),
            AdminStore::empty(),
        )
    }

    /// **G3 follow-up**: a peer row written to `ledger_peers.json` by a separate
    /// process (CLI `control admin approve` / node-to-node join approval) is
    /// visible to the next `receive_at`, so a child's signed `Exit` verifies
    /// where it previously failed `Unauthorized`.
    #[tokio::test]
    async fn receive_at_observes_externally_written_peer_row() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let mut engine = persisted_parent_with_child(dir.path(), parent_op, "child");

        // Before the external write there is no row to verify the child against.
        let before = engine
            .receive_at(
                any_remote(),
                authorize_at("child", &child_op, 1, exit_request("child", 1)),
                0,
            )
            .await;
        assert_eq!(
            before,
            ControlReply::Rejected(RejectCode::Unauthorized),
            "an unregistered child must not pass `verify_control`"
        );

        // A separate process registers the child's keys on disk.
        let mut external = PeerRegistry::new();
        external.insert(node_peer("child", &child_op, 2)).unwrap();
        ledger_peers::save_peers(dir.path(), &external).unwrap();

        // The next request re-reads the registry and the child's exit applies.
        let after = engine
            .receive_at(
                any_remote(),
                authorize_at("child", &child_op, 2, exit_request("child", 1)),
                0,
            )
            .await;
        assert_eq!(
            after,
            ControlReply::Accepted,
            "the externally written peer row must be visible to the next request"
        );
        assert!(
            !engine
                .record()
                .children
                .iter()
                .any(|c| c.child_id == "child"),
            "the exit must have detached the child"
        );
    }

    /// **G3 follow-up**: with no `ledger_peers.json` on disk (the in-memory-only
    /// `engine_with` harness shape), a request must keep the constructed
    /// registry rather than replacing it with the loader's empty result.
    #[tokio::test]
    async fn receive_at_keeps_in_memory_peers_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        // `record_store` persists nothing, so neither `node.json` nor
        // `ledger_peers.json` exists: both reloads are correctly skipped.
        let record = record_store(dir.path(), "parent", Some("0"), None, &[]);
        let peers = [node_peer("child", &child_op, 2)];
        let mut engine = engine_with(dir.path(), "parent", parent_op.clone(), record, &peers);
        assert!(engine.peers().get(&NodeId::from("child")).is_some());

        let reply = engine
            .receive_at(
                any_remote(),
                authorize_at("parent", &parent_op, 1, ControlRequest::Query),
                0,
            )
            .await;
        assert!(matches!(reply, ControlReply::Snapshot(_)));
        assert!(
            engine.peers().get(&NodeId::from("child")).is_some(),
            "a missing peer file must not wipe the in-memory registry"
        );
    }

    /// **G3 follow-up**: a normal in-process `approve_pending` still works after
    /// a reload, and its persisted row survives the next request (not lost and
    /// not duplicated).
    #[tokio::test]
    async fn in_process_approve_survives_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let mut record = RecordStore::open(dir.path(), "parent").unwrap();
        record.set_address("0".parse().unwrap()).unwrap();
        record.save().unwrap();
        let mut engine = ControlNode::new(
            dir.path().to_path_buf(),
            "parent",
            parent_op.clone(),
            record,
            PeerRegistry::new(),
            ControlStore::open(dir.path()).unwrap(),
            AdminStore::empty(),
        );

        // A request first runs the reload phase (no peer file yet; skipped).
        let snapshot = engine
            .receive_at(
                any_remote(),
                authorize_at("parent", &parent_op, 1, ControlRequest::Query),
                0,
            )
            .await;
        assert!(matches!(snapshot, ControlReply::Snapshot(_)));

        // The normal in-process approve path (the pending store is intentionally
        // not reloaded, so the queued row survives) persists the child's row.
        engine.pending.add_pending(JoinRequest {
            node: NodeId::from("child"),
            kind: ChildKind::Node,
            operator: child_op.public(),
            ledger: Some(ledger(2)),
            desired_slot: Some(0),
            location_hint: None,
            nonce: 3,
            expiry: u64::MAX,
        });
        let approval = engine
            .approve_pending("child", Some(0), 5, ledger(1))
            .unwrap();
        assert_eq!(approval.slot, 0);
        assert!(
            ledger_peers::load_peers(dir.path())
                .unwrap()
                .get(&NodeId::from("child"))
                .is_some(),
            "the approve must have persisted the child's row"
        );

        // The child's signed exit now verifies against the reloaded registry.
        let reply = engine
            .receive_at(
                any_remote(),
                authorize_at("child", &child_op, 2, exit_request("child", 1)),
                0,
            )
            .await;
        assert_eq!(reply, ControlReply::Accepted);
        assert!(engine.peers().get(&NodeId::from("child")).is_some());
    }

    /// **G2**: re-approving a child the record already lists at its existing
    /// slot succeeds with the identical retained row (no re-attach, no
    /// duplicate-insert error). This is the stale-row case where the parent
    /// never processed the `Exit`.
    #[tokio::test]
    async fn approve_pending_reapproves_listed_child_with_retained_row() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[("child", ChildKind::Node, 3, 1)],
        );
        let peers = [node_peer("child", &child_op, 2)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);

        let join = JoinRequest {
            node: NodeId::from("child"),
            kind: ChildKind::Node,
            operator: child_op.public(),
            ledger: Some(ledger(2)),
            desired_slot: Some(3),
            location_hint: None,
            nonce: 1,
            expiry: u64::MAX,
        };
        let signed = authorize_at("child", &child_op, 1, ControlRequest::Join(join));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Pending,
            "a listed child's own slot must not be refused at join time"
        );

        let approval = engine
            .approve_pending("child", Some(3), 0, ledger(1))
            .expect("idempotent re-approval");
        assert_eq!(approval.slot, 3);
        assert_eq!(approval.address, "0.3".parse().unwrap());
        assert_eq!(engine.record().children.len(), 1, "no re-attach");
        assert_eq!(engine.peers().len(), 1, "no duplicate row");
    }

    /// **G2**: a retained row for the same node under a *different* operator is
    /// a genuine conflict and is refused.
    #[tokio::test]
    async fn approve_pending_conflicting_operator_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let applicant_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[("child", ChildKind::Node, 3, 1)],
        );
        // The retained row names a different operator (secret 9).
        let peers = [node_peer("child", &secret(9), 9)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);

        let join = JoinRequest {
            node: NodeId::from("child"),
            kind: ChildKind::Node,
            operator: applicant_op.public(),
            ledger: Some(ledger(2)),
            desired_slot: Some(3),
            location_hint: None,
            nonce: 1,
            expiry: u64::MAX,
        };
        let signed = authorize_at("child", &applicant_op, 1, ControlRequest::Join(join));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Pending
        );
        assert!(
            engine.approve_pending("child", Some(3), 0, ledger(1)).is_err(),
            "a conflicting retained operator must error"
        );
    }

    /// **Exit-rights follow-up**: a re-approval whose retained row has the same
    /// operator and role but a *different ledger key* is accepted, the stored
    /// row is updated, and an additive `peer-ledger-updated` audit line is
    /// written. The child controls its own settlement ledger key, so a stale key
    /// must not lock it out of re-attaching.
    #[tokio::test]
    async fn approve_pending_updates_changed_ledger_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[("child", ChildKind::Node, 3, 1)],
        );
        // The retained row has the same operator/role but ledger seed 2.
        let peers = [node_peer("child", &child_op, 2)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);

        engine.pending.add_pending(JoinRequest {
            node: NodeId::from("child"),
            kind: ChildKind::Node,
            operator: child_op.public(),
            // The child regenerated its settlement key (seed 5).
            ledger: Some(ledger(5)),
            desired_slot: Some(3),
            location_hint: None,
            nonce: 1,
            expiry: u64::MAX,
        });

        let approval = engine
            .approve_pending("child", Some(3), 0, ledger(1))
            .expect("a changed ledger key must be reconciled, not refused");
        assert_eq!(approval.slot, 3);
        assert_eq!(
            engine
                .peers()
                .get(&NodeId::from("child"))
                .and_then(|row| row.ledger),
            Some(ledger(5)),
            "the stored row must carry the child's new ledger key"
        );
        assert_eq!(engine.peers().len(), 1, "the retained row is not duplicated");

        // The additive audit line names the node, the actor (the child whose
        // self-signed join vouched for the new key) and both keys.
        let audit = std::fs::read_to_string(dir.path().join(crate::audit::CONTROL_AUDIT_FILE))
            .expect("audit log");
        assert!(audit.contains("\"event\":\"peer-ledger-updated\""), "{audit}");
        assert!(audit.contains("\"node\":\"child\""), "{audit}");
        assert!(audit.contains("\"actor\":\"child\""), "{audit}");
        assert!(
            audit.contains(&format!("\"old_ledger\":\"{}\"", ledger(2))),
            "{audit}"
        );
        assert!(
            audit.contains(&format!("\"new_ledger\":\"{}\"", ledger(5))),
            "{audit}"
        );
    }

    /// **Exit-rights follow-up**: a retained row for the same operator but a
    /// *different role* is still a genuine conflict.
    #[tokio::test]
    async fn approve_pending_conflicting_role_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let child_op = secret(2);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[("child", ChildKind::Node, 3, 1)],
        );
        // The retained row is a `User` for the same operator.
        let peers = [user_peer("child", &child_op)];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);

        engine.pending.add_pending(JoinRequest {
            node: NodeId::from("child"),
            kind: ChildKind::Node,
            operator: child_op.public(),
            ledger: Some(ledger(2)),
            desired_slot: Some(3),
            location_hint: None,
            nonce: 1,
            expiry: u64::MAX,
        });

        let err = engine
            .approve_pending("child", Some(3), 0, ledger(1))
            .expect_err("a changed role must be refused");
        assert!(
            err.to_string().contains("conflicts"),
            "unexpected error: {err}"
        );
        assert_eq!(
            engine
                .peers()
                .get(&NodeId::from("child"))
                .map(|row| row.role),
            Some(PeerRole::User),
            "the retained row is untouched"
        );
    }

    /// **Exit-rights follow-up (oracle review)**: a senior-child `CreateChild`
    /// that changes an existing node's ledger key is refused. The request is not
    /// signed by the peer whose row changes, so only this node's own operator
    /// may rotate a ledger on the `CreateChild` path. No `peer-ledger-updated`
    /// line is written.
    #[tokio::test]
    async fn create_child_senior_peer_cannot_rotate_a_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let senior_op = secret(3);
        let victim_op = secret(4);
        // `senior` (date_joined 1) outranks `victim` (2), so a create signed by
        // `senior` is admitted by `authorize` as `Authority::Peer`.
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[
                ("senior", ChildKind::Node, 0, 1),
                ("victim", ChildKind::Node, 1, 2),
            ],
        );
        let peers = [
            node_peer("senior", &senior_op, 3),
            node_peer("victim", &victim_op, 2),
        ];
        let mut engine = engine_with(dir.path(), "parent", parent_op, record, &peers);

        let create = CreateChild {
            child: NodeId::from("victim"),
            operator: victim_op.public(),
            ledger: Some(ledger(5)),
            kind: ChildKind::Node,
            slot: Some(1),
            date_joined: 2,
        };
        let signed = authorize_at("senior", &senior_op, 1, ControlRequest::CreateChild(create));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Rejected(RejectCode::Unauthorized),
            "a senior child must not substitute a sibling's ledger key"
        );
        assert_eq!(
            engine
                .peers()
                .get(&NodeId::from("victim"))
                .and_then(|row| row.ledger),
            Some(ledger(2)),
            "the retained row is untouched"
        );

        // `CreateChild` is not an admin request (so `audit_request` writes
        // nothing) and the reconciliation never ran: no rotation line.
        let audit = std::fs::read_to_string(dir.path().join(crate::audit::CONTROL_AUDIT_FILE))
            .unwrap_or_default();
        assert!(
            !audit.contains("peer-ledger-updated"),
            "unexpected audit: {audit}"
        );
    }

    /// **Exit-rights follow-up (oracle review)**: this node's own operator may
    /// still rotate an existing node's ledger key via `CreateChild`, and the
    /// `peer-ledger-updated` audit names the operator as the actor.
    #[tokio::test]
    async fn create_child_self_operator_rotates_ledger_and_audits_actor() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let victim_op = secret(4);
        let record = record_store(
            dir.path(),
            "parent",
            Some("0"),
            None,
            &[("victim", ChildKind::Node, 1, 2)],
        );
        let peers = [node_peer("victim", &victim_op, 2)];
        let mut engine = engine_with(dir.path(), "parent", parent_op.clone(), record, &peers);

        let create = CreateChild {
            child: NodeId::from("victim"),
            operator: victim_op.public(),
            ledger: Some(ledger(5)),
            kind: ChildKind::Node,
            slot: Some(1),
            date_joined: 2,
        };
        let signed = authorize_at("parent", &parent_op, 1, ControlRequest::CreateChild(create));
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
        assert_eq!(
            engine
                .peers()
                .get(&NodeId::from("victim"))
                .and_then(|row| row.ledger),
            Some(ledger(5)),
            "the operator-driven rotation updates the row"
        );

        let audit = std::fs::read_to_string(dir.path().join(crate::audit::CONTROL_AUDIT_FILE))
            .expect("audit log");
        assert!(audit.contains("\"event\":\"peer-ledger-updated\""), "{audit}");
        assert!(audit.contains("\"node\":\"victim\""), "{audit}");
        assert!(audit.contains("\"actor\":\"parent\""), "{audit}");
        assert!(
            audit.contains(&format!("\"old_ledger\":\"{}\"", ledger(2))),
            "{audit}"
        );
        assert!(
            audit.contains(&format!("\"new_ledger\":\"{}\"", ledger(5))),
            "{audit}"
        );
    }

    #[tokio::test]
    async fn routed_refuses_all_exit_rights_variants() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(1);
        let record = record_store(dir.path(), "parent", Some("0"), None, &[]);
        let fwd_secret = SecretKey::generate();
        let fwd_id = fwd_secret.public().to_string();
        let fwd_op = secret(9);
        let peers = [node_peer(&fwd_id, &fwd_op, 9)];
        let mut engine = engine_with(dir.path(), "parent", parent_op.clone(), record, &peers);
        let remote = EndpointId::from(fwd_secret.public());

        let requests = vec![
            exit_request("child", 1),
            ControlRequest::DetachNotice(DetachNotice {
                node: NodeId::from("child"),
            }),
            rebase_request("0.5.2", "0.5", 1),
            ControlRequest::RebasePull(RebasePull {
                node: NodeId::from("child"),
            }),
        ];
        for (index, request) in requests.into_iter().enumerate() {
            let nonce = 100 + index as u64;
            let intent = authorize_at("parent", &parent_op, nonce, request.clone());
            let forward = authorize_at(&fwd_id, &fwd_op, nonce, request);
            let routed = RoutedControlV1 {
                version: cawala_control::ROUTED_CONTROL_VERSION,
                target: PeerRef {
                    addr: "0".parse().unwrap(),
                    node: "parent".to_string(),
                },
                requester: PeerRef {
                    addr: "0.1".parse().unwrap(),
                    node: fwd_id.clone(),
                },
                intent,
                grant: None,
                forwards: vec![RoutedForward::new(
                    PeerRef {
                        addr: "0.1".parse().unwrap(),
                        node: fwd_id.clone(),
                    },
                    forward,
                )],
            };
            assert_eq!(
                engine.receive_routed_at(remote, routed, 0).await,
                ControlReply::Rejected(RejectCode::Unauthorized),
                "variant {index}"
            );
        }
    }

    /// A node at an independent root can re-attach: the approval clears the
    /// root address before linking the new parent (no `AddressSlotMismatch`).
    #[tokio::test]
    async fn join_approved_reattaches_a_root_zero_node() {
        let dir = tempfile::tempdir().unwrap();
        let parent_op = secret(3);
        let (mut engine, request) = outbound_applicant(dir.path(), None);
        // The applicant is now an independent root.
        engine.record.rebase_to_root().unwrap();
        assert_eq!(engine.record().address, Some("0".parse().unwrap()));
        engine.record.save().unwrap();

        let approval = approval_for(&request);
        let signed = authorize_at(
            "parent",
            &parent_op,
            1,
            ControlRequest::JoinApproved(approval.clone()),
        );
        assert_eq!(
            engine.receive_at(any_remote(), signed, 0).await,
            ControlReply::Accepted
        );
        assert_eq!(engine.record().parent.as_ref().unwrap().parent_id, "parent");
        assert_eq!(engine.record().address, Some(approval.address));
    }
}
