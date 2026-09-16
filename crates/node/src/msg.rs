//! Native node integration for the `cawala/msg/0` protocol.
//!
//! This module wires [`cawala_msg`] into iroh: a [`MsgHandler`] accepts one
//! framed [`Envelope`] per bi-directional stream, validates and routes it, and
//! answers with an [`Ack`]. Local destinations are pushed into an unbounded-ish
//! mpsc sink the node application drains; remote destinations are forwarded
//! hop-by-hop, synchronously, over a fresh QUIC connection to the next neighbor.
//!
//! Routing is derived from the node's persisted [`NodeRecord`](crate::record::NodeRecord):
//! the asserted octal address supplies this node's position, and the parent and
//! child links supply the neighbor set. Because a lone record only knows its
//! direct parent and children, forward dialing needs a network address for each
//! neighbor; [`RoutableSnapshot::hints`] supplies those (tests and CLI), and a
//! bare [`iroh::EndpointId`] is the fallback (address lookup).
//!
//! # Trust boundary
//!
//! Exactly as [`cawala_msg`] documents: envelope metadata is unauthenticated.
//! The only thing this handler authenticates is the *direct QUIC peer* of each
//! hop, and it verifies only that the last recorded hop matches that peer and
//! is a configured neighbor.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId};

use cawala_ledger::{
    AuthRef, Hash, HopRole, LedgerPubKey, NodeId, PaymentOrder, PeerKeys, PeerRegistry, PeerRole,
    SignedEntry, classify_hop, hop_postings,
};
use cawala_control::{ControlReply, RejectCode, RoutedControlV1, SignedRoutedReply};
use cawala_msg::{
    Ack, AckStatus, Envelope, EntryProofV1, Hop, LedgerPayloadV1, LedgerPayloadV2, LedgerPayloadV3,
    MSG_CONTROL_V1, MSG_LEDGER_V1, MSG_SETTLE_V1, MessageType, MsgError, MsgId, Neighbor,
    NeighborKind, OrderRejectV1, OrderResultV1, OrderResultV2, OrderResultV3, OrderStatusV1, PeerRef,
    RejectReason, Routable,
    RouteDecision, RouteError, Seen, SeenConfig, SeenSet, SettleForwardV1, SettleHopV1,
    SettleOutcomeV2, SettlePayloadV2, SettleRejectV1, SettleResultV2, SettlementStatusV2,
    ValueNoticeV1, VersionedLedgerPayload, decode_versioned,
};
use cawala_topology::ChildKind;

use crate::control::{ControlNode, deliver_outbound_decisions};

use crate::ledger_service::{ApplyOutcome, HopOutcome, LedgerService};
use crate::orders;
use crate::record::{NodeRecord, RecordStore};
use crate::settlement::{
    DerivedHop, PendingSettlement, SettlementManager, TerminalRecord, derive_hop, expected_signers,
    route_is_depth_one,
};

/// ALPN negotiated on every `cawala/msg/0` connection.
pub use cawala_msg::ALPN as MSG_ALPN;

/// Default sink capacity for delivered envelopes.
const SINK_CAPACITY: usize = 256;

/// Tunables for the messaging layer.
#[derive(Debug, Clone)]
pub struct MsgConfig {
    /// Remaining authorized forwards placed on freshly built envelopes.
    pub ttl: u8,
    /// Rejected payload size ceiling (also enforced by `cawala_msg`).
    pub max_payload: usize,
    /// Per-hop deadline for connecting, writing, and reading the downstream ack.
    pub hop_timeout: Duration,
    /// Bounds for the replay-detection set.
    pub seen: SeenConfig,
}

impl Default for MsgConfig {
    fn default() -> Self {
        MsgConfig {
            ttl: cawala_msg::MAX_HOPS as u8,
            max_payload: cawala_msg::MAX_PAYLOAD,
            hop_timeout: Duration::from_secs(10),
            seen: SeenConfig::default(),
        }
    }
}

/// Routing view plus optional explicit next-hop addresses (tests/CLI).
#[derive(Debug, Clone)]
pub struct RoutableSnapshot {
    /// The immutable routing view derived from a node record.
    pub routable: Routable,
    /// Explicit `node id -> network address` overrides, keyed by the neighbor's
    /// *canonical* node id string (the [`iroh::EndpointId`] `Display` form).
    /// Non-canonical record ids (e.g. base32) are normalized before lookup.
    pub hints: std::collections::HashMap<String, EndpointAddr>,
}

impl RoutableSnapshot {
    /// Derive a routing snapshot from a node record.
    ///
    /// Requires an asserted [`NodeRecord::address`](crate::record::NodeRecord::address)
    /// (admin-set; see `cawala-node topo set-address`). The parent address is
    /// `address.parent()` and each child address is `address.child(slot)`.
    /// Every neighbor id must parse as an [`iroh::EndpointId`], and is stored
    /// in its canonical `Display` form so `is_neighbor`/hint lookups are not
    /// broken by a non-canonical (e.g. base32) record encoding.
    pub fn from_record(record: &NodeRecord) -> Result<Self, RoutingSetupError> {
        let address = record.address.clone().ok_or(RoutingSetupError::NoAddress)?;

        let parent = match &record.parent {
            Some(link) => {
                let parsed = parse_endpoint_id(&link.parent_id)?;
                // A non-root address always has a parent, and record validation
                // rejects root-with-parent; an asserted root plus a parent link
                // is structurally inconsistent, so refuse rather than panic.
                let addr = address.parent().ok_or_else(|| {
                    RoutingSetupError::InvalidRecord(format!(
                        "record links parent '{}' but its address is root '{address}'",
                        link.parent_id
                    ))
                })?;
                Some(Neighbor {
                    addr,
                    node: parsed.to_string(),
                    kind: NeighborKind::Node,
                })
            }
            None => None,
        };

        let mut children = Vec::with_capacity(record.children.len());
        for child in &record.children {
            let parsed = parse_endpoint_id(&child.child_id)?;
            let kind = match child.kind {
                cawala_topology::ChildKind::Node => NeighborKind::Node,
                cawala_topology::ChildKind::User => NeighborKind::User,
            };
            children.push(Neighbor {
                addr: address.child(child.slot),
                node: parsed.to_string(),
                kind,
            });
        }
        children.sort_by(|a, b| a.addr.cmp(&b.addr));

        Ok(RoutableSnapshot {
            routable: Routable {
                this: PeerRef {
                    addr: address,
                    node: record.node_id.clone(),
                },
                parent,
                children,
            },
            hints: std::collections::HashMap::new(),
        })
    }

    /// Network address for `node`: an explicit hint first, else a bare
    /// [`EndpointAddr`] built from the node id (address lookup).
    ///
    /// `node` may be in any encoding [`iroh::EndpointId`] accepts; it is
    /// canonicalized before the hint lookup.
    pub fn endpoint_addr(&self, node: &str) -> Result<EndpointAddr, RoutingSetupError> {
        let id = parse_endpoint_id(node)?;
        let canonical = id.to_string();
        if let Some(addr) = self.hints.get(&canonical) {
            return Ok(addr.clone());
        }
        Ok(EndpointAddr::from(id))
    }

    /// Whether `node`/`addr` identifies this node's direct parent or a direct
    /// child. `node` may be non-canonical; it is canonicalized first.
    pub fn is_neighbor(&self, node: &str, addr: &cawala_msg::OctAddr) -> bool {
        let Ok(canonical) = parse_endpoint_id(node) else {
            return false;
        };
        let canonical = canonical.to_string();
        self.routable
            .parent
            .iter()
            .chain(self.routable.children.iter())
            .any(|n| n.node == canonical && n.addr == *addr)
    }
}

/// Where a [`MsgHandler`] gets its routing view.
///
/// The handler stores this instead of a bare [`RoutableSnapshot`] so a running
/// node can observe a topology change made by a *separate* process. `control
/// approve` rewrites `<data-dir>/node.json`; a [`NeighborSource::Live`] source
/// re-reads that file for every message and so accepts a just-approved child
/// without a restart.
#[derive(Debug, Clone)]
pub enum NeighborSource {
    /// A fixed routing view. Used by tests and the simple spawn paths.
    Static(RoutableSnapshot),
    /// Re-reads the persisted record on each message, falling back to the last
    /// good snapshot when the file is unreadable or invalid.
    Live {
        data_dir: PathBuf,
        node_id: String,
        /// Explicit `node id -> network address` overrides applied to every
        /// reloaded snapshot. Usually empty outside tests.
        hints: HashMap<String, EndpointAddr>,
        /// The most recent successfully derived snapshot.
        last_good: Arc<Mutex<RoutableSnapshot>>,
    },
}

impl NeighborSource {
    /// A live source rooted at `<data_dir>/node.json`.
    ///
    /// Fails only if the *initial* record cannot be loaded/derived; the live
    /// reload path itself never fails (it falls back to the last good view).
    pub fn live(
        data_dir: impl Into<PathBuf>,
        node_id: impl Into<String>,
        hints: HashMap<String, EndpointAddr>,
    ) -> anyhow::Result<Self> {
        use anyhow::Context;

        let data_dir = data_dir.into();
        let node_id = node_id.into();
        let store = RecordStore::open(&data_dir, &node_id).with_context(|| {
            format!(
                "live neighbor source: opening {}",
                data_dir.join(crate::record::NODE_RECORD_FILE).display()
            )
        })?;
        let mut initial = RoutableSnapshot::from_record(store.record())
            .context("live neighbor source: deriving routing snapshot from record")?;
        initial.hints = hints.clone();
        Ok(NeighborSource::Live {
            data_dir,
            node_id,
            hints,
            last_good: Arc::new(Mutex::new(initial)),
        })
    }

    /// The current routing view.
    ///
    /// [`NeighborSource::Static`] clones its fixed snapshot. `Live` reloads and
    /// rebuilds from disk; on a load/parse error it logs and returns the last
    /// good snapshot rather than failing the message.
    pub fn snapshot(&self) -> RoutableSnapshot {
        match self {
            NeighborSource::Static(snapshot) => snapshot.clone(),
            NeighborSource::Live {
                data_dir,
                node_id,
                hints,
                last_good,
            } => {
                let loaded = RecordStore::open(data_dir, node_id)
                    .map_err(|err| err.to_string())
                    .and_then(|store| {
                        RoutableSnapshot::from_record(store.record()).map_err(|err| err.to_string())
                    });
                match loaded {
                    Ok(mut snapshot) => {
                        snapshot.hints = hints.clone();
                        if let Ok(mut guard) = last_good.lock() {
                            *guard = snapshot.clone();
                        }
                        snapshot
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "live neighbor snapshot reload failed; using last good snapshot"
                        );
                        last_good
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                    }
                }
            }
        }
    }

    /// See [`RoutableSnapshot::is_neighbor`].
    pub fn is_neighbor(&self, node: &str, addr: &cawala_msg::OctAddr) -> bool {
        self.snapshot().is_neighbor(node, addr)
    }

    /// See [`RoutableSnapshot::endpoint_addr`].
    pub fn endpoint_addr(&self, node: &str) -> Result<EndpointAddr, RoutingSetupError> {
        self.snapshot().endpoint_addr(node)
    }
}

fn parse_endpoint_id(node_id: &str) -> Result<EndpointId, RoutingSetupError> {
    EndpointId::from_str(node_id).map_err(|err| RoutingSetupError::BadEndpointId {
        node_id: node_id.to_string(),
        detail: err.to_string(),
    })
}

/// Errors raised while deriving a routing view from a node record.
#[derive(Debug, thiserror::Error)]
pub enum RoutingSetupError {
    #[error("node record has no address; run `cawala-node topo set-address <ADDR>`")]
    NoAddress,
    #[error("neighbor id '{node_id}' is not an iroh EndpointId: {detail}")]
    BadEndpointId { node_id: String, detail: String },
    #[error("node record is structurally inconsistent: {0}")]
    InvalidRecord(String),
}

/// Errors raised by the origin-side [`send_envelope`] helper.
#[derive(Debug, thiserror::Error)]
pub enum MsgSendError {
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(cawala_msg::MsgError),
    #[error("no route: {0}")]
    NoRoute(RouteError),
    #[error("recipient is this node")]
    LocalDelivery,
    #[error("next hop {node} is unreachable: {detail}")]
    NextHopUnreachable { node: String, detail: String },
    #[error("hop {node} timed out after {timeout:?}")]
    Timeout { node: String, timeout: Duration },
    #[error("transport: {0}")]
    Transport(String),
}

/// Server-side handler for `cawala/msg/0`.
#[derive(Debug)]
pub struct MsgHandler {
    endpoint: Endpoint,
    neighbors: NeighborSource,
    config: MsgConfig,
    seen: Mutex<SeenSet>,
    sink: tokio::sync::mpsc::Sender<Envelope>,
    /// Shared control engine, set only when messaging is co-hosted with control
    /// (see [`spawn_control_node_live_on`](crate::control::spawn_control_node_live_on)).
    ///
    /// The plain [`spawn_msg_node`]/[`spawn_msg_node_on`] paths leave this
    /// `None`, so they cannot authenticate or re-sign routed control and reject
    /// `MSG_CONTROL_V1` outright.
    control: Option<Arc<tokio::sync::Mutex<ControlNode>>>,
}

impl MsgHandler {
    /// Build a handler with a fixed routing view that delivers locally destined
    /// envelopes to `sink` and forwards the rest through `endpoint`.
    pub fn new(
        endpoint: Endpoint,
        snapshot: RoutableSnapshot,
        config: MsgConfig,
        sink: tokio::sync::mpsc::Sender<Envelope>,
    ) -> Self {
        Self::with_source(endpoint, NeighborSource::Static(snapshot), config, sink)
    }

    /// Build a handler whose routing view comes from `source`. A
    /// [`NeighborSource::Live`] source re-reads `<data-dir>/node.json` per
    /// message, so a child approved by a separate `control` process is accepted
    /// without a restart.
    pub fn with_source(
        endpoint: Endpoint,
        source: NeighborSource,
        config: MsgConfig,
        sink: tokio::sync::mpsc::Sender<Envelope>,
    ) -> Self {
        Self::build(endpoint, source, config, sink, None)
    }

    /// Like [`MsgHandler::with_source`], but sharing the node's control engine so
    /// the handler can authenticate and re-sign `MSG_CONTROL_V1` forwards.
    ///
    /// Only the combined control+msg spawn uses this; the plain msg spawn paths
    /// leave the engine unset.
    pub(crate) fn with_source_and_control(
        endpoint: Endpoint,
        source: NeighborSource,
        config: MsgConfig,
        sink: tokio::sync::mpsc::Sender<Envelope>,
        control: Arc<tokio::sync::Mutex<ControlNode>>,
    ) -> Self {
        Self::build(endpoint, source, config, sink, Some(control))
    }

    fn build(
        endpoint: Endpoint,
        source: NeighborSource,
        config: MsgConfig,
        sink: tokio::sync::mpsc::Sender<Envelope>,
        control: Option<Arc<tokio::sync::Mutex<ControlNode>>>,
    ) -> Self {
        let seen = Mutex::new(SeenSet::new(config.seen));
        MsgHandler {
            endpoint,
            neighbors: source,
            config,
            seen,
            sink,
            control,
        }
    }

    /// Replace the next-hop address hint for `node`, canonicalizing the key.
    ///
    /// Intended for tests and operational address repairs: a stale or bogus
    /// hint can be corrected in place and the same envelope retried, because a
    /// transient rejection rolls the replay mark back.
    pub fn set_hint(&mut self, node: &str, addr: EndpointAddr) -> Result<(), RoutingSetupError> {
        let id = parse_endpoint_id(node)?;
        let canonical = id.to_string();
        match &mut self.neighbors {
            NeighborSource::Static(snapshot) => {
                snapshot.hints.insert(canonical, addr);
            }
            NeighborSource::Live {
                hints, last_good, ..
            } => {
                hints.insert(canonical.clone(), addr.clone());
                last_good
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .hints
                    .insert(canonical, addr);
            }
        }
        Ok(())
    }

    /// Finalize a terminal status: roll the replay mark back for transient
    /// failures so a retry is not spuriously answered `Duplicate`.
    ///
    /// The guard is taken and released here, never across an `.await`.
    fn settle(&self, origin: &str, msg_id: MsgId, status: AckStatus) -> Ack {
        if matches!(
            status,
            AckStatus::Rejected(
                RejectReason::Unreachable | RejectReason::Busy | RejectReason::Internal
            )
        ) {
            let mut guard = self
                .seen
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.unobserve(origin, msg_id);
        }
        Ack { msg_id, status }
    }

    /// Prepare a `MSG_CONTROL_V1` envelope for the next hop.
    ///
    /// Both routed payloads declare their version as the first field and share
    /// the value `1`, so direction cannot be inferred from the route; it is
    /// decided by a **full decode plus envelope coherence**:
    ///
    /// - a [`RoutedControlV1`] whose `target`/`requester` match the envelope is a
    ///   request: its forward vector must mirror the hop chain 1:1, its
    ///   predecessor must verify against this hop's registry, and this hop's own
    ///   forward is appended (freshly signed) before re-encoding;
    /// - a [`SignedRoutedReply`] whose `responder` matches `env.src` is a reply
    ///   and is passed through unchanged;
    /// - anything else is refused.
    ///
    /// The control lock is taken only for the synchronous verify/sign and
    /// released before the caller forwards; it is never held across
    /// [`forward_once`].
    async fn prepare_control_forward(&self, env: &mut Envelope) -> Result<(), RejectReason> {
        // Bound the payload before any decode work.
        if env.payload.len() > cawala_control::MAX_CONTROL_FRAME as usize {
            return Err(RejectReason::BadPayload);
        }
        let Some(control) = self.control.as_ref() else {
            // Messaging without a co-hosted control engine cannot route control.
            return Err(RejectReason::NoRoute);
        };

        if let Ok(mut routed) = RoutedControlV1::from_bytes(&env.payload)
            && routed.target.addr == env.dst
            && routed.requester.node == env.src.node
            && routed.requester.addr == env.src.addr
        {
            // Fail fast on inner coherence (version, bound, per-forward
            // request/origin equality) instead of trusting the destination to
            // catch it: a relay must not sign its own forward onto a malformed
            // payload.
            if routed.validate().is_err() {
                return Err(RejectReason::BadPayload);
            }
            // `forwards` is the signature vector parallel to the transport hop
            // chain: exactly one per hop, in path order.
            if routed.forwards.len() != env.hop_chain.len() {
                return Err(RejectReason::BadPayload);
            }
            for (index, forward) in routed.forwards.iter().enumerate() {
                if !same_hop(&forward.hop, &env.hop_chain[index]) {
                    return Err(RejectReason::BadPayload);
                }
            }
            // Relays drop an expired intent rather than carrying it further.
            if routed.intent.expiry < unix_now() {
                return Err(RejectReason::TtlExpired);
            }
            // Verify the immediate predecessor and append this hop's forward.
            // The lock is dropped at the end of this block.
            let own = {
                let engine = control.lock().await;
                let Some(last) = routed.forwards.last() else {
                    return Err(RejectReason::BadPayload);
                };
                engine
                    .verify_forward(last)
                    .map_err(|_| RejectReason::BadPayload)?;
                engine
                    .sign_forward(&routed.intent.request)
                    .map_err(|_| RejectReason::BadPayload)?
            };
            routed.forwards.push(own);
            env.payload = routed
                .to_bytes()
                .map_err(|_| RejectReason::BadPayload)?;
            return Ok(());
        }

        if let Ok(reply) = SignedRoutedReply::from_bytes(&env.payload)
            && reply.reply.responder.node == env.src.node
        {
            return Ok(());
        }

        Err(RejectReason::NoRoute)
    }

    /// Full receive decision for one envelope.
    ///
    /// `remote` is the authenticated QUIC peer id. See the module docs and the
    /// milestone spec for the exact decision order.
    pub async fn handle(&self, remote: EndpointId, mut env: Envelope) -> Ack {
        let msg_id = env.msg_id;
        let origin = env.src.node.clone();
        let reject = |reason: RejectReason| Ack {
            msg_id,
            status: AckStatus::Rejected(reason),
        };

        // 1. Structural validation.
        if let Err(err) = env.validate() {
            let reason = match err {
                MsgError::UnsupportedVersion(_) => RejectReason::BadVersion,
                MsgError::PayloadTooLarge { .. } | MsgError::NodeIdTooLong { .. } => {
                    RejectReason::BadPayload
                }
                MsgError::BadTtl { .. } => RejectReason::TtlExpired,
                MsgError::HopChain(_) => RejectReason::BadHopChain,
                MsgError::InvalidEntryProof(_) => RejectReason::BadPayload,
                MsgError::Codec(_) => RejectReason::Internal,
            };
            return reject(reason);
        }

        // 2. The hop chain must be a structurally plausible path.
        if cawala_msg::validate_hop_chain(&env.src.addr, &env.dst, &env.hop_chain).is_err() {
            return reject(RejectReason::BadHopChain);
        }

        // Resolve the routing view once per envelope. A live source reloads the
        // persisted record here, so a child approved after spawn is seen.
        let snapshot = self.neighbors.snapshot();
        let this = &snapshot.routable.this;

        // 3. Reject any chain that already visited this node (loop).
        if env
            .hop_chain
            .iter()
            .any(|h| h.node == this.node || h.addr == this.addr)
        {
            return reject(RejectReason::BadHopChain);
        }

        // 4. The last hop must be the authenticated remote and a direct neighbor.
        let Some(last) = env.hop_chain.last() else {
            return reject(RejectReason::BadHopChain);
        };
        if last.node != remote.to_string() || !snapshot.is_neighbor(&last.node, &last.addr) {
            return reject(RejectReason::NotNeighbor);
        }

        // 5. Replay defense. The guard is released before any await.
        let seen = {
            let mut guard = self
                .seen
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.observe(&origin, msg_id)
        };
        if seen == Seen::Duplicate {
            return Ack {
                msg_id,
                status: AckStatus::Duplicate,
            };
        }

        // 6. Route. Transient outcomes roll the mark back via `settle`; the
        // deterministic rejections keep it (a retry of those changes nothing).
        let status = match cawala_msg::route(&snapshot.routable, &env.dst) {
            RouteDecision::Local => match self.sink.try_send(env) {
                Ok(()) => AckStatus::Delivered,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    AckStatus::Rejected(RejectReason::Busy)
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    AckStatus::Rejected(RejectReason::Internal)
                }
            },
            RouteDecision::Forward(next) => {
                // Exhaustion is a TTL failure, not a malformed chain: check it
                // before `append_hop`, which would otherwise report `TooLong`.
                if env.ttl == 0 || env.hop_chain.len() >= cawala_msg::MAX_HOPS {
                    AckStatus::Rejected(RejectReason::TtlExpired)
                } else {
                    let next_node = next.node.clone();
                    // Routed control is re-signed per hop before the hop chain
                    // changes, so a refused payload leaves the envelope intact.
                    if env.msg_type == MSG_CONTROL_V1
                        && let Err(reason) = self.prepare_control_forward(&mut env).await
                    {
                        return self.settle(&origin, msg_id, AckStatus::Rejected(reason));
                    }
                    if cawala_msg::append_hop(&mut env, this).is_err() {
                        AckStatus::Rejected(RejectReason::BadHopChain)
                    } else {
                        env.ttl -= 1;

                        match snapshot.endpoint_addr(&next_node) {
                            Err(_) => AckStatus::Rejected(RejectReason::Unreachable),
                            Ok(addr) => match forward_once(
                                &self.endpoint,
                                &next_node,
                                addr,
                                &env,
                                self.config.hop_timeout,
                            )
                            .await
                            {
                                Ok(ack) => ack.status,
                                Err(_) => AckStatus::Rejected(RejectReason::Unreachable),
                            },
                        }
                    }
                }
            }
            RouteDecision::Drop(_) => AckStatus::Rejected(RejectReason::NoRoute),
        };

        self.settle(&origin, msg_id, status)
    }
}

impl ProtocolHandler for MsgHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;

        let env: Envelope = match proto::read_framed_with_limit::<Envelope, _>(
            &mut recv,
            cawala_msg::MAX_MSG_FRAME,
        )
        .await
        {
            Ok(env) => env,
            Err(err) => {
                return Err(AcceptError::from_err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("cawala/msg/0 decode failed: {err}"),
                )));
            }
        };

        let ack = self.handle(connection.remote_id(), env).await;
        proto::write_framed(&mut send, &ack).await?;
        send.finish()?;

        // The remote reads the ack and closes; waiting here keeps the stream
        // alive long enough for the ack to be delivered.
        connection.closed().await;
        Ok(())
    }
}

/// Dial `addr`, write one envelope frame, read one ack frame, and close.
async fn forward_once(
    endpoint: &Endpoint,
    node: &str,
    addr: EndpointAddr,
    env: &Envelope,
    timeout: Duration,
) -> Result<Ack, MsgSendError> {
    let exchange = async {
        let connection = endpoint.connect(addr, MSG_ALPN).await.map_err(|err| {
            MsgSendError::NextHopUnreachable {
                node: node.to_string(),
                detail: err.to_string(),
            }
        })?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|err| MsgSendError::Transport(err.to_string()))?;
        proto::write_framed(&mut send, env)
            .await
            .map_err(|err| MsgSendError::Transport(err.to_string()))?;
        send.finish()
            .map_err(|err| MsgSendError::Transport(err.to_string()))?;
        let ack: Ack = proto::read_framed_with_limit(&mut recv, cawala_msg::MAX_MSG_FRAME)
            .await
            .map_err(|err| MsgSendError::Transport(err.to_string()))?;
        connection.close(0u8.into(), b"done");
        Ok(ack)
    };

    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_) => Err(MsgSendError::Timeout {
            node: node.to_string(),
            timeout,
        }),
    }
}

/// Bind a node endpoint with BOTH `cawala/ping/0` and `cawala/msg/0`, register
/// [`crate::PingHandler`] and [`MsgHandler`], and return the router plus the
/// channel of locally delivered envelopes.
pub async fn spawn_msg_node(
    secret_key: iroh::SecretKey,
    snapshot: RoutableSnapshot,
    config: MsgConfig,
) -> anyhow::Result<(Router, tokio::sync::mpsc::Receiver<Envelope>)> {
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![proto::ALPN.to_vec(), MSG_ALPN.to_vec()])
        .bind()
        .await?;
    Ok(spawn_msg_node_on(endpoint, snapshot, config))
}

/// Like [`spawn_msg_node`], but on an already-bound endpoint. Used by hermetic
/// tests that bind with relay mode disabled.
pub fn spawn_msg_node_on(
    endpoint: Endpoint,
    snapshot: RoutableSnapshot,
    config: MsgConfig,
) -> (Router, tokio::sync::mpsc::Receiver<Envelope>) {
    spawn_msg_node_with_source_on(endpoint, NeighborSource::Static(snapshot), config)
}

/// Like [`spawn_msg_node_on`], but with an explicit [`NeighborSource`] so the
/// handler can use a live routing view.
pub fn spawn_msg_node_with_source_on(
    endpoint: Endpoint,
    source: NeighborSource,
    config: MsgConfig,
) -> (Router, tokio::sync::mpsc::Receiver<Envelope>) {
    let (sink, receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
    let handler = MsgHandler::with_source(endpoint.clone(), source, config, sink);
    let router = Router::builder(endpoint)
        .accept(proto::ALPN, crate::PingHandler)
        .accept(MSG_ALPN, handler)
        .spawn();
    (router, receiver)
}

/// Build a fresh envelope: random `msg_id` and `nonce`, `hop_chain = [src]`,
/// and `ttl` as configured. Rejects payloads over `MAX_PAYLOAD` and a `ttl`
/// above [`cawala_msg::MAX_HOPS`].
pub fn build_envelope(
    src: &PeerRef,
    dst: cawala_msg::OctAddr,
    msg_type: MessageType,
    payload: Vec<u8>,
    ttl: u8,
) -> Result<Envelope, MsgError> {
    if payload.len() > cawala_msg::MAX_PAYLOAD {
        return Err(MsgError::PayloadTooLarge {
            actual: payload.len(),
            max: cawala_msg::MAX_PAYLOAD,
        });
    }
    if ttl > cawala_msg::MAX_HOPS as u8 {
        return Err(MsgError::BadTtl { ttl });
    }

    let mut id = [0u8; cawala_msg::MsgId::LEN];
    getrandom::fill(&mut id).map_err(|err| MsgError::Codec(format!("getrandom: {err}")))?;
    let nonce = getrandom::u64().map_err(|err| MsgError::Codec(format!("getrandom: {err}")))?;

    let mut env = Envelope::new(
        src.clone(),
        dst,
        cawala_msg::MsgId::from_bytes(id),
        msg_type,
        nonce,
        payload,
    );
    env.ttl = ttl;
    Ok(env)
}

/// Origin side: route `env.dst` and either report local delivery or forward one
/// hop to the next neighbor.
///
/// Self is already `hop_chain[0]`; this helper does **not** append it.
pub async fn send_envelope(
    endpoint: &Endpoint,
    snapshot: &RoutableSnapshot,
    env: &Envelope,
    hop_timeout: Duration,
) -> Result<Ack, MsgSendError> {
    env.validate().map_err(MsgSendError::InvalidEnvelope)?;

    match cawala_msg::route(&snapshot.routable, &env.dst) {
        RouteDecision::Local => Ok(Ack {
            msg_id: env.msg_id,
            status: AckStatus::Delivered,
        }),
        RouteDecision::Forward(next) => {
            let addr = snapshot.endpoint_addr(&next.node).map_err(|err| {
                MsgSendError::NextHopUnreachable {
                    node: next.node.clone(),
                    detail: err.to_string(),
                }
            })?;
            forward_once(endpoint, &next.node, addr, env, hop_timeout).await
        }
        RouteDecision::Drop(err) => Err(MsgSendError::NoRoute(err)),
    }
}

/// Current unix time in seconds, the caller-supplied clock for ledger ops.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// The settlement timeout used for origin reservations, in seconds.
pub const SETTLE_TIMEOUT_SECS: u64 = 30;

/// Process one locally delivered `MSG_LEDGER_V1` envelope.
///
/// `Order` payloads are applied to the shared [`LedgerService`]; a v2 order with
/// a remote payee starts a cross-subtree settlement. `BalanceQuery` payloads
/// from a `User` child are answered with a signed receipt. No failure path
/// panics: a bad payload or an unreachable reply must not kill the drain task.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_ledger_envelope(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    manager: &Arc<tokio::sync::Mutex<SettlementManager>>,
    data_dir: &Path,
    node_id: &str,
    env: Envelope,
) {
    match decode_versioned(&env.payload) {
        Ok(VersionedLedgerPayload::V1(payload)) => {
            dispatch_ledger_payload_v1(endpoint, source, config, ledger, data_dir, node_id, env, payload)
                .await;
        }
        Ok(VersionedLedgerPayload::V2(LedgerPayloadV2::Order(order_v2))) => {
            let order = order_v2.order;
            let auth = order_v2.auth;
            let payee_addr = order_v2.payee_addr;

            let record = match RecordStore::open(data_dir, node_id) {
                Ok(store) => store.record().clone(),
                Err(err) => {
                    tracing::warn!(%err, "cannot reload node record to apply an order; skipping");
                    return;
                }
            };

            // The sender must be a local `User` child at the address it claims.
            if user_child_address(&record, &env.src.node) != Some(env.src.addr.clone()) {
                send_settlement_reply(
                    endpoint,
                    source,
                    config,
                    &env.src,
                    env.msg_id,
                    order.hash(),
                    SettlementStatusV2::Rejected {
                        reason: OrderRejectV1::NotAChild,
                    },
                    None,
                    None,
                )
                .await;
                return;
            }

            let payee_is_local = record
                .children
                .iter()
                .any(|child| child.kind == ChildKind::User && child.child_id == order.to.as_str());
            if payee_is_local {
                apply_same_leaf_order(
                    endpoint, source, config, ledger, data_dir, &env, &record, &order, &auth, true,
                )
                .await;
            } else {
                handle_settlement_order(
                    endpoint,
                    source,
                    config,
                    ledger,
                    manager,
                    data_dir,
                    &env,
                    &record,
                    &order,
                    &auth,
                    &payee_addr,
                )
                .await;
            }
        }
        Ok(VersionedLedgerPayload::V2(LedgerPayloadV2::OrderResult(_))) => {
            tracing::debug!(
                msg_id = %env.msg_id.to_hex(),
                "ignoring browser-directed v2 order result at a leaf node"
            );
        }
        Ok(VersionedLedgerPayload::V3(LedgerPayloadV3::OrderResult(_))) => {
            tracing::debug!(
                msg_id = %env.msg_id.to_hex(),
                "ignoring browser-directed v3 order result at a leaf node"
            );
        }
        Err(err) => {
            tracing::warn!(
                msg_id = %env.msg_id.to_hex(),
                %err,
                "malformed MSG_LEDGER_V1 payload; skipping"
            );
        }
    }
}

/// Apply the existing same-leaf `Direct` order path (v1 and local-payee v2).
#[allow(clippy::too_many_arguments)]
async fn apply_same_leaf_order(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    data_dir: &Path,
    env: &Envelope,
    record: &NodeRecord,
    order: &PaymentOrder,
    auth: &AuthRef,
    reply_v2: bool,
) {
    let order = order.clone();
    let order_record = order.clone();
    let auth = auth.clone();
    let record = record.clone();
    let sender = env.src.node.clone();
    let order_hash = order.hash();
    let ledger = Arc::clone(ledger);
    let now = unix_now();

    let applied = tokio::task::spawn_blocking(move || {
        let mut service = ledger.blocking_lock();
        let sender_is_user_child = record
            .children
            .iter()
            .any(|child| child.kind == ChildKind::User && child.child_id == sender);
        if !sender_is_user_child {
            return (
                ApplyOutcome {
                    status: OrderStatusV1::Rejected,
                    entry_seq: None,
                    entry_hash: None,
                    reason: Some(OrderRejectV1::NotAChild),
                },
                None,
                None,
            );
        }
        let outcome = service.apply_order(
            &order,
            &auth,
            &cawala_ledger::NodeId::from(sender),
            &record,
            now,
        );
        // A same-leaf move is terminal here; its proof is the `Direct` entry the
        // browser verifies against this leaf's pinned key. Only a v2 sender
        // consumes proofs.
        let proof = if reply_v2 {
            match &outcome.status {
                OrderStatusV1::Applied | OrderStatusV1::Duplicate => {
                    let leaf_addr = record.address.clone();
                    match (outcome.entry_seq, leaf_addr) {
                        (Some(seq), Some(leaf_addr)) => {
                            service.build_entry_proof(seq, leaf_addr).ok()
                        }
                        _ => None,
                    }
                }
                OrderStatusV1::Rejected => None,
            }
        } else {
            None
        };
        let balance = match &outcome.status {
            OrderStatusV1::Applied | OrderStatusV1::Duplicate => {
                match service.balance_receipt(&order.from, &record, None, None, None) {
                    Ok(receipt) => Some(receipt),
                    Err(err) => {
                        tracing::warn!(
                            %err,
                            "payer balance receipt omitted (ledger read lock contention)"
                        );
                        None
                    }
                }
            }
            OrderStatusV1::Rejected => None,
        };
        (outcome, balance, proof)
    })
    .await;

    let (outcome, balance, proof) = match applied {
        Ok(applied) => applied,
        Err(err) => {
            tracing::warn!(%err, "ledger apply task failed; skipping order");
            return;
        }
    };

    // Journal the order only now that its hop has actually applied (Applied, or
    // a previously-applied Duplicate). Journaling at receipt would record
    // received-but-rejected orders, whose missing cascade then shows up as a
    // false `RouteInvalid` finding in `net` and suppresses nets. Dedup by order
    // hash keeps several applied hops at one node to a single line.
    match outcome.status {
        OrderStatusV1::Applied | OrderStatusV1::Duplicate => {
            if let Err(err) = orders::append(data_dir, &order_record) {
                tracing::warn!(%err, "failed to journal an applied order");
            }
        }
        OrderStatusV1::Rejected => {}
    }

    if reply_v2 {
        // A v2 (`OrderV2`) sender gets a v3 result; a same-leaf move is already
        // terminal, so `Applied`/`Duplicate`/`Rejected` map directly.
        let status = match outcome.status {
            OrderStatusV1::Applied => SettlementStatusV2::Applied {
                entry_seq: outcome.entry_seq.unwrap_or_default(),
                entry_hash: outcome.entry_hash.unwrap_or(Hash::ZERO),
            },
            OrderStatusV1::Duplicate => SettlementStatusV2::Duplicate {
                entry_seq: outcome.entry_seq.unwrap_or_default(),
                entry_hash: outcome.entry_hash.unwrap_or(Hash::ZERO),
            },
            OrderStatusV1::Rejected => SettlementStatusV2::Rejected {
                reason: outcome.reason.unwrap_or(OrderRejectV1::BadRequest),
            },
        };
        // The browser requires a verified proof for `Applied`/`Duplicate`; if it
        // could not be built, report the committed debit as `Indeterminate`
        // rather than an unverifiable success.
        if matches!(
            status,
            SettlementStatusV2::Applied { .. } | SettlementStatusV2::Duplicate { .. }
        ) && proof.is_none()
        {
            tracing::warn!(
                order_hash = %order_hash.to_hex(),
                "same-leaf entry proof unavailable; reporting Indeterminate"
            );
            send_settlement_reply(
                endpoint,
                source,
                config,
                &env.src,
                env.msg_id,
                order_hash,
                SettlementStatusV2::Indeterminate {
                    reason: OrderRejectV1::Internal,
                },
                balance,
                None,
            )
            .await;
            return;
        }
        send_settlement_reply(
            endpoint,
            source,
            config,
            &env.src,
            env.msg_id,
            order_hash,
            status,
            balance,
            proof,
        )
        .await;
        return;
    }

    let result = OrderResultV1 {
        reply_to: env.msg_id,
        order_hash,
        status: outcome.status,
        entry_seq: outcome.entry_seq,
        entry_hash: outcome.entry_hash,
        reason: outcome.reason,
        balance,
    };
    send_ledger_reply(
        endpoint,
        source,
        config,
        env,
        LedgerPayloadV1::OrderResult(result),
    )
    .await;
}

/// Dispatch a v1 ledger payload body.
#[allow(clippy::too_many_arguments)]
async fn dispatch_ledger_payload_v1(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    data_dir: &Path,
    node_id: &str,
    env: Envelope,
    payload: LedgerPayloadV1,
) {
    match payload {
        LedgerPayloadV1::Order(order_v1) => {
            let record = match RecordStore::open(data_dir, node_id) {
                Ok(store) => store.record().clone(),
                Err(err) => {
                    tracing::warn!(%err, "cannot reload node record to apply an order; skipping");
                    return;
                }
            };
            apply_same_leaf_order(
                endpoint,
                source,
                config,
                ledger,
                data_dir,
                &env,
                &record,
                &order_v1.order,
                &order_v1.auth,
                false,
            )
            .await;
        }
        LedgerPayloadV1::BalanceQuery(query) => {
            let record = match RecordStore::open(data_dir, node_id) {
                Ok(store) => store.record().clone(),
                Err(err) => {
                    tracing::warn!(%err, "cannot reload node record to answer a balance query");
                    return;
                }
            };

            if user_child_address(&record, &env.src.node).as_ref() != Some(&env.src.addr) {
                tracing::warn!(
                    src = %env.src.node,
                    "BalanceQuery from a non-user-child or mismatched address; ignoring"
                );
                return;
            }

            let user = cawala_ledger::NodeId::from(env.src.node.clone());
            let reply_to = env.msg_id;
            let query_id = query.query_id;
            let ledger = Arc::clone(ledger);
            let receipt = tokio::task::spawn_blocking(move || {
                let mut service = ledger.blocking_lock();
                service.balance_receipt(&user, &record, Some(reply_to), Some(query_id), None)
            })
            .await;

            let receipt = match receipt {
                Ok(Ok(receipt)) => receipt,
                Ok(Err(err)) => {
                    tracing::warn!(%err, "failed to build balance receipt");
                    return;
                }
                Err(err) => {
                    tracing::warn!(%err, "balance receipt task failed");
                    return;
                }
            };
            send_ledger_reply(
                endpoint,
                source,
                config,
                &env,
                LedgerPayloadV1::BalanceReceipt(receipt),
            )
            .await;
        }
        LedgerPayloadV1::OrderResult(_) | LedgerPayloadV1::BalanceReceipt(_) => {
            tracing::debug!(
                msg_id = %env.msg_id.to_hex(),
                "ignoring leaf-directed ledger reply at a leaf node"
            );
        }
    }
}

/// Start a cross-subtree settlement at the payer's leaf (the origin).
#[allow(clippy::too_many_arguments)]
async fn handle_settlement_order(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    manager: &Arc<tokio::sync::Mutex<SettlementManager>>,
    data_dir: &Path,
    env: &Envelope,
    record: &NodeRecord,
    order: &PaymentOrder,
    auth: &AuthRef,
    payee_addr: &cawala_msg::OctAddr,
) {
    let payment_id = order.hash();
    let now = unix_now();

    let Some(payer_addr) = user_child_address(record, &env.src.node) else {
        return;
    };
    let Some(this_addr) = record.address.clone() else {
        return;
    };
    let Some(payee_leaf_addr) = payee_addr.parent() else {
        send_settlement_reject(endpoint, source, config, env, order.hash(), OrderRejectV1::BadRequest).await;
        return;
    };

    // v1 depth-1 guard: reject anything deeper without touching the ledger.
    if !route_is_depth_one(&payer_addr, payee_addr) {
        send_settlement_reject(endpoint, source, config, env, order.hash(), OrderRejectV1::BadRequest).await;
        return;
    }
    let Ok(derived) = derive_hop(record, &this_addr, &payer_addr, payee_addr) else {
        send_settlement_reject(endpoint, source, config, env, order.hash(), OrderRejectV1::BadRequest).await;
        return;
    };

    let order_c = order.clone();
    let auth_c = auth.clone();
    let ledger_arc = Arc::clone(ledger);
    let outcome = tokio::task::spawn_blocking(move || {
        let mut service = ledger_arc.blocking_lock();
        // Resolve the payer's row locally; the browser is our own user child.
        let payer_key = service
            .effective_registry()
            .ok()
            .and_then(|registry| registry.get(&order_c.from).cloned());
        let Some(payer_key) = payer_key else {
            return (HopOutcome::Rejected { reason: OrderRejectV1::Unauthorized }, None, None);
        };
        let registry = match assemble_settlement_registry(&service, &payer_key, &order_c, &auth_c) {
            Ok(registry) => registry,
            Err(reason) => return (HopOutcome::Rejected { reason }, None, None),
        };
        let outcome = service.apply_hop(
            &order_c,
            &auth_c,
            derived.role,
            derived.first,
            derived.second,
            &registry,
            now,
        );
        let entry = match &outcome {
            HopOutcome::Applied { seq, .. } | HopOutcome::Duplicate { seq, .. } => {
                service.entry_at(*seq).ok()
            }
            HopOutcome::Rejected { .. } => None,
        };
        (outcome, Some(payer_key), entry)
    })
    .await;

    let (outcome, payer_key, entry) = match outcome {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(%err, "settlement reserve task failed");
            return;
        }
    };

    match outcome {
        HopOutcome::Applied { seq, hash } => {
            let (Some(payer_key), Some(entry)) = (payer_key, entry) else {
                send_settlement_reject(endpoint, source, config, env, order.hash(), OrderRejectV1::Internal).await;
                return;
            };
            let forward = SettleForwardV1 {
                order: order.clone(),
                auth: auth.clone(),
                payer_key,
                payer_addr: payer_addr.clone(),
                payee_addr: payee_addr.clone(),
                hops: vec![SettleHopV1 {
                    signer_addr: this_addr.clone(),
                    entry,
                }],
            };
            if !forward.hops_within_bound() {
                send_settlement_reject(endpoint, source, config, env, order.hash(), OrderRejectV1::BadRequest).await;
                return;
            }
            let pending = PendingSettlement {
                browser: env.src.clone(),
                browser_msg_id: env.msg_id,
                order: order.clone(),
                auth: auth.clone(),
                payer_addr: payer_addr.clone(),
                payee_addr: payee_addr.clone(),
                payee_leaf_addr: payee_leaf_addr.clone(),
                local_seq: seq,
                local_hash: hash,
                deadline_secs: now + SETTLE_TIMEOUT_SECS,
                reply_v2: true,
            };
            // Journal at the reservation point: this branch is reached only
            // after this origin leaf's own hop applied, so recording here (not
            // at receipt) avoids false route-audit findings. Idempotent with the
            // per-hop journals; never fails the request.
            if let Err(err) = orders::append(data_dir, order) {
                tracing::warn!(%err, "failed to journal a reserved settlement order");
            }
            if let Some(evicted) = manager.lock().await.reserve(pending) {
                send_timeout_result(endpoint, source, config, ledger, Some(record), &evicted).await;
            }
            let signers = expected_signers(&payer_addr, payee_addr)
                .expect("depth-1 route has three signers");
            send_settle_payload_to(
                endpoint,
                source,
                config,
                signers[1].clone(),
                SettlePayloadV2::Forward(forward),
            )
            .await;
        }
        HopOutcome::Duplicate { seq, hash } => {
            // The local reservation already exists. Answer from the cached
            // terminal if the cascade finished; if it is still in flight, stay
            // silent so the eventual true terminal can resolve it (answering a
            // bare `Duplicate` here would let the client drop its pending order
            // and discard that terminal).
            let (terminal, in_flight) = {
                let mgr = manager.lock().await;
                (
                    mgr.terminal(&payment_id).cloned(),
                    mgr.pending(&payment_id).is_some(),
                )
            };
            if terminal.is_none() && in_flight {
                return;
            }
            let status = match &terminal {
                Some(term) => match &term.outcome {
                    SettleOutcomeV2::Applied {
                        terminal_seq,
                        terminal_hash,
                        ..
                    } => SettlementStatusV2::Duplicate {
                        entry_seq: *terminal_seq,
                        entry_hash: *terminal_hash,
                    },
                    // A cached downstream rejection is surfaced as the real
                    // partial/rejected state, not a bare duplicate.
                    SettleOutcomeV2::Rejected { reason } => settle_reject_to_status(reason),
                },
                // No cached terminal (e.g. the pending was evicted or the origin
                // restarted): the origin holds only its own reservation hop, so
                // it has no terminal proof to forward and must not synthesize
                // one.
                None => SettlementStatusV2::Duplicate {
                    entry_seq: seq,
                    entry_hash: hash,
                },
            };
            let proof = terminal.and_then(|term| term.proof);
            let balance = payer_receipt(ledger, record, &order.from).await;
            send_settlement_reply(
                endpoint,
                source,
                config,
                &env.src,
                env.msg_id,
                payment_id,
                status,
                balance,
                proof,
            )
            .await;
        }
        HopOutcome::Rejected { reason } => {
            send_settlement_reject(endpoint, source, config, env, payment_id, reason).await;
        }
    }
}

/// Reply a settlement result to a v2 browser over `MSG_LEDGER_V1`.
///
/// The result is **advisory**; the payer's own signed receipt is ground truth.
/// `proof` is the verified terminal inclusion proof for an accepted
/// `Applied`/`Duplicate` outcome and `None` otherwise. `Applied`/`Duplicate`
/// are sent as a v3 `OrderResultV3` (carrying the proof); the remaining
/// statuses keep today's v2 `OrderResultV2` shape.
#[allow(clippy::too_many_arguments)]
async fn send_settlement_reply(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    browser: &PeerRef,
    reply_to: MsgId,
    order_hash: Hash,
    status: SettlementStatusV2,
    balance: Option<cawala_msg::BalanceReceiptV1>,
    proof: Option<EntryProofV1>,
) {
    if matches!(
        status,
        SettlementStatusV2::Applied { .. } | SettlementStatusV2::Duplicate { .. }
    ) {
        let result = OrderResultV3 {
            reply_to,
            order_hash,
            status,
            balance,
            proof,
        };
        send_order_result_v3_to(endpoint, source, config, browser, result).await;
    } else {
        let result = OrderResultV2 {
            reply_to,
            order_hash,
            status,
            balance,
        };
        send_order_result_v2_to(endpoint, source, config, browser, result).await;
    }
}

/// Reply `Rejected(reason)` to a v2 settlement browser.
async fn send_settlement_reject(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    env: &Envelope,
    order_hash: Hash,
    reason: OrderRejectV1,
) {
    send_settlement_reply(
        endpoint,
        source,
        config,
        &env.src,
        env.msg_id,
        order_hash,
        SettlementStatusV2::Rejected { reason },
        None,
        None,
    )
    .await;
}

/// Build a fresh payer balance receipt, if one can be built.
async fn payer_receipt(
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    record: &NodeRecord,
    payer: &cawala_ledger::NodeId,
) -> Option<cawala_msg::BalanceReceiptV1> {
    let ledger = Arc::clone(ledger);
    let record = record.clone();
    let payer = payer.clone();
    tokio::task::spawn_blocking(move || {
        let mut service = ledger.blocking_lock();
        match service.balance_receipt(&payer, &record, None, None, None) {
            Ok(receipt) => Some(receipt),
            Err(err) => {
                tracing::warn!(
                    %err,
                    "payer balance receipt omitted (ledger read lock contention)"
                );
                None
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Emit a synthesized timeout result for an expired/evicted settlement.
///
/// The origin only reserves a pending settlement *after* its own hop applied,
/// so a timeout is never a "rejected before the debit" case: it is
/// `Indeterminate`, carrying a fresh payer receipt so the committed debit is
/// surfaced.
async fn send_timeout_result(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    record: Option<&NodeRecord>,
    pending: &PendingSettlement,
) {
    if pending.reply_v2 {
        let balance = match record {
            Some(record) => payer_receipt(ledger, record, &pending.order.from).await,
            None => None,
        };
        send_order_result_v2_to(
            endpoint,
            source,
            config,
            &pending.browser,
            OrderResultV2 {
                reply_to: pending.browser_msg_id,
                order_hash: pending.order.hash(),
                status: SettlementStatusV2::Indeterminate {
                    reason: OrderRejectV1::Internal,
                },
                balance,
            },
        )
        .await;
        return;
    }
    // v1 fallback (settlements are v2-only today).
    let result = OrderResultV1 {
        reply_to: pending.browser_msg_id,
        order_hash: pending.order.hash(),
        status: OrderStatusV1::Rejected,
        entry_seq: None,
        entry_hash: None,
        reason: Some(OrderRejectV1::Internal),
        balance: None,
    };
    send_order_result_to(endpoint, source, config, &pending.browser, result).await;
}

/// Sweep timed-out origin settlements and notify their browsers.
#[allow(clippy::too_many_arguments)]
pub async fn sweep_settlements(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    data_dir: &Path,
    node_id: &str,
    manager: &Arc<tokio::sync::Mutex<SettlementManager>>,
    now: u64,
) {
    let expired = manager.lock().await.sweep_expired(now);
    if expired.is_empty() {
        return;
    }
    let record = RecordStore::open(data_dir, node_id)
        .map(|store| store.record().clone())
        .ok();
    for pending in expired {
        send_timeout_result(endpoint, source, config, ledger, record.as_ref(), &pending).await;
    }
}

/// Process one locally delivered `MSG_SETTLE_V1` envelope.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_settle_envelope(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    manager: &Arc<tokio::sync::Mutex<SettlementManager>>,
    data_dir: &Path,
    node_id: &str,
    env: Envelope,
) {
    let payload = match SettlePayloadV2::from_bytes(&env.payload) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                msg_id = %env.msg_id.to_hex(),
                %err,
                "malformed MSG_SETTLE_V1 payload; skipping"
            );
            return;
        }
    };
    match payload {
        SettlePayloadV2::Result(result) => {
            handle_settle_result(endpoint, source, config, ledger, manager, data_dir, node_id, env, result)
                .await;
        }
        SettlePayloadV2::Forward(forward) => {
            handle_settle_forward(endpoint, source, config, ledger, data_dir, node_id, env, forward)
                .await;
        }
    }
}

/// Process one locally delivered `MSG_CONTROL_V1` envelope addressed to this
/// node as the routed target.
///
/// The transport has authenticated only the final hop, so this function
/// enforces the envelope-level coherence the routed wrapper cannot see: the
/// request names this envelope's destination and source, and its forward vector
/// mirrors the hop chain 1:1. The wrapper's authority rules then run inside
/// [`ControlNode::receive_routed_at`].
///
/// The reply is a fresh descending `MSG_CONTROL_V1` envelope signed by this
/// node's operator; an already-decoded `SignedRoutedReply` (a reply addressed to
/// this node as its own requester) is ignored. Any admin decision queued by the
/// engine is reverse-dialed, and its outcome patched into the reply's
/// `delivery` field, before the reply is signed.
pub async fn dispatch_control_envelope(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    control: &Arc<tokio::sync::Mutex<ControlNode>>,
    env: Envelope,
) {
    let routed = match RoutedControlV1::from_bytes(&env.payload) {
        Ok(routed) => routed,
        Err(err) => {
            tracing::warn!(
                msg_id = %env.msg_id.to_hex(),
                %err,
                "malformed MSG_CONTROL_V1 payload at destination; skipping"
            );
            return;
        }
    };
    // The authenticated last hop; the msg layer proved it is the QUIC remote and
    // a direct neighbor, so it is the authority this node binds to.
    let Some(hop) = env.hop_chain.last() else {
        return;
    };
    let Ok(remote) = hop.node.parse::<EndpointId>() else {
        return;
    };

    // Envelope coherence. A request that fails any of these is answered with an
    // `Unauthorized` reply rather than silently dropped, so the requester can
    // distinguish a refusal from a lost message.
    let coherent = routed.target.addr == env.dst
        && routed.requester == env.src
        && routed.forwards.len() == env.hop_chain.len()
        && routed
            .forwards
            .iter()
            .zip(env.hop_chain.iter())
            .all(|(forward, hop)| same_hop(&forward.hop, hop));
    if !coherent {
        tracing::warn!(
            msg_id = %env.msg_id.to_hex(),
            "MSG_CONTROL_V1 request failed envelope coherence; refusing"
        );
        send_control_reply(
            endpoint,
            source,
            config,
            control,
            &env,
            routed.requester,
            ControlReply::Rejected(RejectCode::Unauthorized),
        )
        .await;
        return;
    }

    let requester = routed.requester.clone();
    let (mut reply, outbound, data_dir) = {
        let mut engine = control.lock().await;
        let reply = engine.receive_routed(remote, routed).await;
        let outbound = engine.take_outbound();
        let data_dir = engine.data_dir().to_path_buf();
        (reply, outbound, data_dir)
    };
    // Reverse-dial any queued join decision, patch `delivery`, then sign the
    // reply. The engine lock is not held across the dials.
    deliver_outbound_decisions(endpoint, &data_dir, outbound, &mut reply).await;
    tracing::info!(%remote, "routed control reply");

    send_control_reply(endpoint, source, config, control, &env, requester, reply).await;
}

/// Sign `reply` as this node and send it back down to `requester` as a fresh
/// `MSG_CONTROL_V1` envelope.
///
/// `reply_to` correlates with the request envelope's `msg_id`; the msg layer has
/// no reply channel, so the requester matches it by that id.
async fn send_control_reply(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    control: &Arc<tokio::sync::Mutex<ControlNode>>,
    request: &Envelope,
    requester: PeerRef,
    reply: ControlReply,
) {
    let signed = {
        let engine = control.lock().await;
        match engine.sign_routed_reply(request.msg_id, requester.clone(), reply) {
            Ok(signed) => signed,
            Err(err) => {
                tracing::warn!(%err, "cannot sign routed control reply");
                return;
            }
        }
    };
    let bytes = match signed.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(%err, "cannot encode routed control reply");
            return;
        }
    };
    let snapshot = source.snapshot();
    let src = snapshot.routable.this.clone();
    let outgoing = match build_envelope(&src, requester.addr, MSG_CONTROL_V1, bytes, config.ttl) {
        Ok(outgoing) => outgoing,
        Err(err) => {
            tracing::warn!(%err, "cannot build routed control reply envelope");
            return;
        }
    };
    if let Err(err) = send_envelope(endpoint, &snapshot, &outgoing, config.hop_timeout).await {
        tracing::warn!(%err, "routed control reply could not be sent");
    }
}

/// Whether a routed [`PeerRef`] names the same hop as an envelope [`Hop`].
fn same_hop(peer: &PeerRef, hop: &Hop) -> bool {
    peer.addr == hop.addr && peer.node == hop.node
}

/// Handle a settlement `Result` at the origin: emit the browser's `OrderResult`.
#[allow(clippy::too_many_arguments)]
async fn handle_settle_result(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    manager: &Arc<tokio::sync::Mutex<SettlementManager>>,
    data_dir: &Path,
    node_id: &str,
    env: Envelope,
    result: SettleResultV2,
) {
    let payment_id = result.payment_id;
    let (pending, status, proof) = {
        let mut mgr = manager.lock().await;
        let Some(pending) = mgr.pending(&payment_id).cloned() else {
            return;
        };
        // Provenance: `Applied` must come from the payee leaf; a downstream
        // `Rejected` (which implies the payer's reservation applied) may come
        // from any expected signer — the LCA or the payee leaf. The immediate
        // sender is only authenticated to the neighbor, so provenance is no
        // longer the security boundary: the terminal proof below is.
        match &result.outcome {
            SettleOutcomeV2::Applied { .. } => {
                if env.src.addr != pending.payee_leaf_addr {
                    tracing::warn!(
                        src = %env.src.node,
                        "applied settlement result from a non-payee-leaf; ignoring"
                    );
                    return;
                }
            }
            SettleOutcomeV2::Rejected { .. } => {
                let expected = expected_signers(&pending.payer_addr, &pending.payee_addr)
                    .map(|signers| signers.iter().any(|addr| addr == &env.src.addr))
                    .unwrap_or(false);
                if !expected {
                    tracing::warn!(
                        src = %env.src.node,
                        "settlement rejection from a non-signer; ignoring"
                    );
                    return;
                }
            }
        }

        // Verify the terminal proof before accepting `Applied`. The origin has
        // no registry row binding a sibling leaf's node id to its ledger key,
        // so this is self-consistency only; a failure resolves as
        // `Indeterminate` (the payer's debit is already committed) and is never
        // stored as a terminal record.
        let (status, proof, resolved) = match &result.outcome {
            SettleOutcomeV2::Applied {
                terminal_seq,
                terminal_hash,
                proof,
            } => {
                if verify_terminal_proof(
                    proof,
                    &pending.order,
                    &pending.payee_leaf_addr,
                    *terminal_seq,
                    terminal_hash,
                ) {
                    (
                        SettlementStatusV2::Applied {
                            entry_seq: *terminal_seq,
                            entry_hash: *terminal_hash,
                        },
                        Some(proof.clone()),
                        true,
                    )
                } else {
                    tracing::warn!(
                        payment_id = %payment_id.to_hex(),
                        "settlement result carries an invalid terminal proof; resolving Indeterminate"
                    );
                    (
                        SettlementStatusV2::Indeterminate {
                            reason: OrderRejectV1::Internal,
                        },
                        None,
                        false,
                    )
                }
            }
            // `IntermediateRejected` means the payer's local hop (the origin
            // reservation) already applied, so it is a `Partial` cascade rather
            // than a plain rejection.
            SettleOutcomeV2::Rejected { reason } => (settle_reject_to_status(reason), None, true),
        };

        let Some(pending) = mgr.take_pending(&payment_id) else {
            return;
        };
        // A failed proof must not poison the terminal record: only a resolved
        // (accepted or downstream-rejected) outcome is remembered.
        if resolved {
            mgr.record_terminal(
                payment_id,
                TerminalRecord {
                    browser: pending.browser.clone(),
                    browser_msg_id: pending.browser_msg_id,
                    order: pending.order.clone(),
                    terminal_entry: match &result.outcome {
                        SettleOutcomeV2::Applied { proof, .. } => Some(proof.entry.clone()),
                        SettleOutcomeV2::Rejected { .. } => None,
                    },
                    proof: proof.clone(),
                    outcome: result.outcome.clone(),
                },
            );
        }
        (pending, status, proof)
    };

    // Any outcome other than a pre-reservation `Rejected` implies the payer's
    // hop applied, so surface a fresh payer receipt as signed ground truth.
    let needs_receipt = !matches!(status, SettlementStatusV2::Rejected { .. });
    let balance = if needs_receipt {
        let record = RecordStore::open(data_dir, node_id)
            .map(|store| store.record().clone())
            .ok();
        match record {
            Some(record) => payer_receipt(ledger, &record, &pending.order.from).await,
            None => None,
        }
    } else {
        None
    };

    if pending.reply_v2 {
        send_settlement_reply(
            endpoint,
            source,
            config,
            &pending.browser,
            pending.browser_msg_id,
            pending.order.hash(),
            status,
            balance,
            proof,
        )
        .await;
    } else {
        // v1 fallback (settlements are v2-only today).
        let (status_v1, reason) = settlement_status_to_v1(&status);
        let (entry_seq, entry_hash) = match &status {
            SettlementStatusV2::Applied {
                entry_seq,
                entry_hash,
            }
            | SettlementStatusV2::Duplicate {
                entry_seq,
                entry_hash,
            } => (Some(*entry_seq), Some(*entry_hash)),
            _ => (None, None),
        };
        let order_result = OrderResultV1 {
            reply_to: pending.browser_msg_id,
            order_hash: pending.order.hash(),
            status: status_v1,
            entry_seq,
            entry_hash,
            reason,
            balance,
        };
        send_order_result_to(endpoint, source, config, &pending.browser, order_result).await;
    }
}

/// Handle a settlement `Forward` at an intermediate or terminal signer.
#[allow(clippy::too_many_arguments)]
async fn handle_settle_forward(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    data_dir: &Path,
    node_id: &str,
    env: Envelope,
    forward: SettleForwardV1,
) {
    if !forward.hops_within_bound() {
        return;
    }
    let snapshot = source.snapshot();
    let this = snapshot.routable.this.clone();
    // Addresses of our direct neighbors, so a carried hop can be resolved to
    // the registry row of the node that signed it (when that row is known).
    let neighbors: Vec<(cawala_msg::OctAddr, NodeId)> = snapshot
        .routable
        .parent
        .iter()
        .chain(snapshot.routable.children.iter())
        .map(|neighbor| (neighbor.addr.clone(), NodeId::from(neighbor.node.clone())))
        .collect();

    let Some(signers) = expected_signers(&forward.payer_addr, &forward.payee_addr) else {
        return;
    };
    // The hop index is derived from how many hops are already carried; the wire
    // never chooses it. This node must be the next expected signer.
    let index = forward.hops.len();
    if index >= signers.len() || this.addr != signers[index] {
        return;
    }
    // The transport-appended chain must be exactly the expected signer prefix
    // (`signers[0]`, then each previous signer). This binds the derived hop
    // index to the authenticated path and rejects a forged cascade that a
    // non-signer (e.g. a User child) relays through a leaf: the transport keeps
    // the true origin as `hop_chain[0]`, so it cannot name `signers[0]`.
    if env.hop_chain.len() != index {
        return;
    }
    for (i, hop) in env.hop_chain.iter().enumerate() {
        if hop.addr != signers[i] {
            return;
        }
    }
    // The sender is the neighbor-verified last hop appended by the transport,
    // never the unauthenticated `env.src`.
    let Some(sender) = env.hop_chain.last().map(|hop| &hop.addr) else {
        return;
    };
    if index == 0 {
        // Only the payer leaf may start a cascade...
        if sender != &signers[0] {
            return;
        }
    } else if sender != &signers[index - 1] {
        // ...and only the previous expected signer may hand off.
        return;
    }
    let is_terminal = index + 1 == signers.len();

    let record = match RecordStore::open(data_dir, node_id) {
        Ok(store) => store.record().clone(),
        Err(err) => {
            tracing::warn!(%err, "cannot reload node record for a settlement hop");
            return;
        }
    };

    // If this node is the payer leaf (`index == 0`), the order's payer must be
    // its own user child at `payer_addr`.
    if this.addr == signers[0]
        && user_child_address(&record, forward.order.from.as_str())
            != Some(forward.payer_addr.clone())
    {
        return;
    }

    if is_terminal
        && user_child_address(&record, forward.order.to.as_str())
            != Some(forward.payee_addr.clone())
    {
        send_settle_result(
            endpoint,
            source,
            config,
            signers[0].clone(),
            forward.order.hash(),
            SettleOutcomeV2::Rejected {
                reason: SettleRejectV1::IntermediateRejected {
                    at: cawala_ledger::NodeId::from(this.node.clone()),
                    reason: OrderRejectV1::NotAChild,
                },
            },
        )
        .await;
        return;
    }

    let Ok(derived) = derive_hop(&record, &this.addr, &forward.payer_addr, &forward.payee_addr)
    else {
        send_settle_result(
            endpoint,
            source,
            config,
            signers[0].clone(),
            forward.order.hash(),
            SettleOutcomeV2::Rejected {
                reason: SettleRejectV1::Malformed,
            },
        )
        .await;
        return;
    };

    let order = forward.order.clone();
    let auth = forward.auth.clone();
    let payer_key = forward.payer_key.clone();
    let derived_c = derived.clone();
    let carried = forward.hops.clone();
    let signers_c = signers.clone();
    let payer_addr = forward.payer_addr.clone();
    let payee_addr = forward.payee_addr.clone();
    let this_addr = this.addr.clone();
    let ledger_arc = Arc::clone(ledger);
    let now = unix_now();
    let applied = tokio::task::spawn_blocking(move || {
        let mut service = ledger_arc.blocking_lock();
        let self_key = service.ledger_key_public();
        let registry = match assemble_settlement_registry(&service, &payer_key, &order, &auth) {
            Ok(registry) => registry,
            Err(reason) => {
                return Err(HopOutcome::Rejected { reason });
            }
        };
        // Defense in depth: the carried evidence must name the expected
        // signers, be a valid transfer of this order, and (where the signer's
        // ledger key is resolvable) carry a valid signature.
        if !carried_hops_match(
            &carried,
            &signers_c,
            &payer_addr,
            &payee_addr,
            &this_addr,
            &order,
            &self_key,
            &neighbors,
            &registry,
        ) {
            return Err(HopOutcome::Rejected {
                reason: OrderRejectV1::Unauthorized,
            });
        }
        Ok(service.apply_hop(
            &order,
            &auth,
            derived_c.role,
            derived_c.first,
            derived_c.second,
            &registry,
            now,
        ))
    })
    .await;

    let outcome = match applied {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(outcome)) => outcome,
        Err(err) => {
            tracing::warn!(%err, "settlement hop task failed");
            return;
        }
    };

    let (seq, hash) = match outcome {
        HopOutcome::Applied { seq, hash } => (seq, hash),
        HopOutcome::Duplicate { seq, hash } => {
            let ledger_arc = Arc::clone(ledger);
            let recovered = tokio::task::spawn_blocking(move || {
                ledger_arc.blocking_lock().entry_at(seq).ok()
            })
            .await
            .ok()
            .flatten();
            let Some(entry) = recovered else {
                return;
            };
            if !entry_matches_hop(&entry, &forward.order, &derived) {
                return;
            }
            (seq, hash)
        }
        HopOutcome::Rejected { reason } => {
            send_settle_result(
                endpoint,
                source,
                config,
                signers[0].clone(),
                forward.order.hash(),
                SettleOutcomeV2::Rejected {
                    reason: SettleRejectV1::IntermediateRejected {
                        at: cawala_ledger::NodeId::from(this.node.clone()),
                        reason,
                    },
                },
            )
            .await;
            return;
        }
    };

    // Journal this order now that this node's hop has actually applied
    // (Applied, or a previously-applied Duplicate); a rejected hop must not be
    // recorded, or `net` would report a false `RouteInvalid` for it.
    if let Err(err) = orders::append(data_dir, &forward.order) {
        tracing::warn!(%err, "failed to journal an applied settlement hop");
    }

    // Recover the appended (or already-applied) entry as evidence, and, at the
    // terminal leaf, assemble the full inclusion proof the origin verifies. A
    // terminal leaf builds it once from its own live ledger; an intermediate
    // signer skips it.
    let ledger_arc = Arc::clone(ledger);
    let leaf_addr = this.addr.clone();
    let recovered = tokio::task::spawn_blocking(move || {
        let service = ledger_arc.blocking_lock();
        let entry = service.entry_at(seq).ok();
        let proof = if is_terminal {
            service.build_entry_proof(seq, leaf_addr).ok()
        } else {
            None
        };
        (entry, proof)
    })
    .await;

    let (entry, proof) = match recovered {
        Ok(recovered) => recovered,
        Err(err) => {
            tracing::warn!(%err, "settlement evidence task failed");
            return;
        }
    };
    let mut hops = forward.hops.clone();
    if let Some(entry) = &entry
        && !hops.iter().any(|hop| hop.signer_addr == this.addr)
    {
        hops.push(SettleHopV1 {
            signer_addr: this.addr.clone(),
            entry: entry.clone(),
        });
    }

    if is_terminal {
        // A terminal `Applied` result carries the signed `Descend` entry with a
        // full inclusion proof so the origin retains verifiable ground truth;
        // without a proof we cannot vouch for the outcome, so stay silent
        // rather than emit an unverifiable success.
        let Some(proof) = proof else {
            return;
        };
        send_settle_result(
            endpoint,
            source,
            config,
            signers[0].clone(),
            forward.order.hash(),
            SettleOutcomeV2::Applied {
                terminal_seq: seq,
                terminal_hash: hash,
                proof,
            },
        )
        .await;
        push_payee_receipt(
            endpoint,
            source,
            config,
            ledger,
            &record,
            &forward,
            seq,
            hash,
            now,
        )
        .await;
    } else {
        let next = signers[index + 1].clone();
        let relayed = SettleForwardV1 { hops, ..forward };
        relay_settle_forward(endpoint, source, config, &env, next, relayed).await;
    }
}

/// Cap on the once-per-signer "unresolvable key" warning dedup.
///
/// The set is keyed by an untrusted carried address, so it must be bounded;
/// once full, new addresses are neither recorded nor warned about (repeats are
/// silent either way).
const MAX_UNRESOLVABLE_SIGNER_NOTES: usize = 4096;

/// Process-wide set of unresolvable carried-signer addresses already logged.
///
/// The terminal logs each distinct unresolvable signer address **at most once**:
/// in the depth-1 route the payer leaf's carried hop is always unresolvable at
/// the terminal, so a per-hop `warn!` on every honest cross-leaf settlement
/// would be alert noise. Bounded so a hostile flood of distinct addresses cannot
/// grow it without limit.
static UNRESOLVABLE_SIGNERS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

/// Record `addr` and return whether this call is the first sighting that fits
/// under the cap (and therefore should warn). A repeat, or an address seen while
/// the set is already full, returns `false` (silent).
fn note_unresolvable_signer(addr: &cawala_msg::OctAddr) -> bool {
    let set = UNRESOLVABLE_SIGNERS.get_or_init(|| Mutex::new(BTreeSet::new()));
    let mut set = set.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if set.len() >= MAX_UNRESOLVABLE_SIGNER_NOTES {
        return false;
    }
    set.insert(addr.to_string())
}

/// Defense-in-depth check over carried settlement evidence.
///
/// Every carried hop must name the expected signer, be a canonical transfer of
/// this order with the role the classifier derives for that signer, and pass
/// conservation. Independently of resolvability, every carried entry must also
/// be **signed by the key it names** and have the role's **canonical posting
/// shape** (see [`cawala_ledger::entry_hop_accounts`]); an unsigned, garbage, or
/// malformed-shape entry is rejected even when the signer's registered key is
/// unknown here.
///
/// Where the signer is resolvable — this node itself, or a direct neighbor whose
/// registry row (with a ledger key) is known — the entry signature is verified
/// under exactly that signer's key; a mismatch rejects.
///
/// In the depth-1 route the immediately-preceding hop (`signers[index-1]`,
/// already authenticated as the transport sender) is a direct neighbor of this
/// node, so its signature is required at the terminal leaf and at the LCA.
///
/// Residual: a carried hop naming a node that is neither us nor a known direct
/// neighbor cannot be bound to that node's registered key here; it is logged and
/// only the internal self-signature plus structural checks apply. A malicious
/// parent/LCA can still author such a chain with its own well-formed key. Full
/// route verification is deferred (Phase 2).
#[allow(clippy::too_many_arguments)]
fn carried_hops_match(
    hops: &[SettleHopV1],
    signers: &[cawala_msg::OctAddr; 3],
    payer_addr: &cawala_msg::OctAddr,
    payee_addr: &cawala_msg::OctAddr,
    this_addr: &cawala_msg::OctAddr,
    order: &PaymentOrder,
    self_key: &LedgerPubKey,
    neighbors: &[(cawala_msg::OctAddr, NodeId)],
    registry: &PeerRegistry,
) -> bool {
    for (i, hop) in hops.iter().enumerate() {
        if i >= signers.len() || hop.signer_addr != signers[i] {
            return false;
        }
        let expected_role = classify_hop(payer_addr, payee_addr, &signers[i]);
        let entry = &hop.entry.entry;
        let cawala_ledger::EntryBody::Transfer {
            payment_id,
            amount,
            role,
        } = &entry.body
        else {
            return false;
        };
        if Some(*role) != expected_role
            || *payment_id != order.hash()
            || *amount != order.amount
            || entry.check_conservation().is_err()
        {
            return false;
        }
        // Internal integrity, independent of whether the signer is resolvable:
        // the entry must be signed by the ledger key it declares, and its
        // postings must have the role-canonical shape. This rejects unsigned or
        // garbage entries that merely carry a plausible address.
        if hop.entry.verify(&entry.ledger_id).is_err() {
            return false;
        }
        if cawala_ledger::entry_hop_accounts(entry, *role).is_err() {
            return false;
        }

        // Authoritative binding: where we hold the signer's registered key, the
        // entry must verify under exactly that key (which also rejects a
        // `ledger_id` naming any other key).
        let mut key_verified = false;
        if hop.signer_addr == *this_addr {
            if entry.ledger_id != *self_key || hop.entry.verify(self_key).is_err() {
                return false;
            }
            key_verified = true;
        } else if let Some(expected_node) = neighbors
            .iter()
            .find(|(addr, _)| addr == &hop.signer_addr)
            .map(|(_, node)| node)
            && let Some(expected_key) = registry.ledger_of(expected_node)
        {
            if hop.entry.verify(expected_key).is_err() {
                return false;
            }
            key_verified = true;
        }
        if !key_verified && note_unresolvable_signer(&hop.signer_addr) {
            tracing::warn!(
                hop_index = i,
                signer_addr = %hop.signer_addr,
                "carried settlement hop signer key is not resolvable here; \
                 only the entry's self-signature and structural checks applied"
            );
        }
    }
    true
}

/// Verify a recovered duplicate hop entry matches the locally derived hop.
fn entry_matches_hop(entry: &SignedEntry, order: &PaymentOrder, derived: &DerivedHop) -> bool {
    let cawala_ledger::EntryBody::Transfer {
        payment_id,
        amount,
        role,
    } = &entry.entry.body
    else {
        return false;
    };
    let Ok(m) = i64::try_from(order.amount.get()) else {
        return false;
    };
    *payment_id == order.hash()
        && *amount == order.amount
        && *role == derived.role
        && entry.entry.postings == hop_postings(derived.role, &derived.first, &derived.second, m)
}

/// Send a settlement `Result` to the origin.
async fn send_settle_result(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    origin: cawala_msg::OctAddr,
    payment_id: Hash,
    outcome: SettleOutcomeV2,
) {
    send_settle_payload_to(
        endpoint,
        source,
        config,
        origin,
        SettlePayloadV2::Result(SettleResultV2 {
            payment_id,
            outcome,
        }),
    )
    .await;
}

/// Push a signed receipt with a `Descend` notice to the payee user.
#[allow(clippy::too_many_arguments)]
async fn push_payee_receipt(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    record: &NodeRecord,
    forward: &SettleForwardV1,
    entry_seq: u64,
    entry_hash: Hash,
    now: u64,
) {
    let notice = ValueNoticeV1 {
        entry_seq,
        entry_hash,
        payment_id: forward.order.hash(),
        from: forward.order.from.clone(),
        to: forward.order.to.clone(),
        amount: forward.order.amount,
        role: HopRole::Descend,
        issued_at: now,
    };
    let user = forward.order.to.clone();
    let record = record.clone();
    let ledger_arc = Arc::clone(ledger);
    let receipt = tokio::task::spawn_blocking(move || {
        let mut service = ledger_arc.blocking_lock();
        match service.balance_receipt(&user, &record, None, None, Some(notice)) {
            Ok(receipt) => Some(receipt),
            Err(err) => {
                tracing::warn!(
                    %err,
                    "payee balance receipt omitted (ledger read lock contention)"
                );
                None
            }
        }
    })
    .await
    .ok()
    .flatten();
    if let Some(receipt) = receipt {
        send_ledger_payload_to(
            endpoint,
            source,
            config,
            forward.payee_addr.clone(),
            LedgerPayloadV1::BalanceReceipt(receipt),
        )
        .await;
    }
}

/// Encode `payload`, build a reply envelope to `env.src`, and send it. Failures
/// are logged and dropped so the drain loop keeps running.
async fn send_ledger_reply(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    env: &Envelope,
    payload: LedgerPayloadV1,
) {
    send_ledger_payload_to(endpoint, source, config, env.src.addr.clone(), payload).await;
}

/// Encode a v1 ledger `payload` and send it to `dst` over `MSG_LEDGER_V1`.
/// Failures are logged and dropped so the drain loop keeps running.
async fn send_ledger_payload_to(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    dst: cawala_msg::OctAddr,
    payload: LedgerPayloadV1,
) {
    let bytes = match payload.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(%err, "failed to encode ledger payload");
            return;
        }
    };
    let snapshot = source.snapshot();
    let src = snapshot.routable.this.clone();
    let env = match build_envelope(&src, dst, MSG_LEDGER_V1, bytes, config.ttl) {
        Ok(env) => env,
        Err(err) => {
            tracing::warn!(%err, "failed to build ledger envelope");
            return;
        }
    };
    match send_envelope(endpoint, &snapshot, &env, config.hop_timeout).await {
        Ok(ack) => tracing::debug!(
            msg_id = %env.msg_id.to_hex(),
            status = ack.status_str(),
            "sent ledger payload"
        ),
        Err(err) => tracing::warn!(%err, "failed to send ledger payload"),
    }
}

/// Encode a v2 ledger `payload` and send it to `dst` over `MSG_LEDGER_V1`.
/// Replies for v2 senders stay on the ledger message type.
async fn send_ledger_payload_v2_to(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    dst: cawala_msg::OctAddr,
    payload: LedgerPayloadV2,
) {
    let bytes = match payload.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(%err, "failed to encode v2 ledger payload");
            return;
        }
    };
    let snapshot = source.snapshot();
    let src = snapshot.routable.this.clone();
    let env = match build_envelope(&src, dst, MSG_LEDGER_V1, bytes, config.ttl) {
        Ok(env) => env,
        Err(err) => {
            tracing::warn!(%err, "failed to build v2 ledger envelope");
            return;
        }
    };
    match send_envelope(endpoint, &snapshot, &env, config.hop_timeout).await {
        Ok(ack) => tracing::debug!(
            msg_id = %env.msg_id.to_hex(),
            status = ack.status_str(),
            "sent v2 ledger payload"
        ),
        Err(err) => tracing::warn!(%err, "failed to send v2 ledger payload"),
    }
}

/// Encode a v3 ledger `payload` and send it to `dst` over `MSG_LEDGER_V1`.
/// Replies for v2 senders stay on the ledger message type.
async fn send_ledger_payload_v3_to(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    dst: cawala_msg::OctAddr,
    payload: LedgerPayloadV3,
) {
    let bytes = match payload.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(%err, "failed to encode v3 ledger payload");
            return;
        }
    };
    let snapshot = source.snapshot();
    let src = snapshot.routable.this.clone();
    let env = match build_envelope(&src, dst, MSG_LEDGER_V1, bytes, config.ttl) {
        Ok(env) => env,
        Err(err) => {
            tracing::warn!(%err, "failed to build v3 ledger envelope");
            return;
        }
    };
    match send_envelope(endpoint, &snapshot, &env, config.hop_timeout).await {
        Ok(ack) => tracing::debug!(
            msg_id = %env.msg_id.to_hex(),
            status = ack.status_str(),
            "sent v3 ledger payload"
        ),
        Err(err) => tracing::warn!(%err, "failed to send v3 ledger payload"),
    }
}

/// Encode a settlement `payload` and send it to `dst` over `MSG_SETTLE_V1`.
async fn send_settle_payload_to(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    dst: cawala_msg::OctAddr,
    payload: SettlePayloadV2,
) {
    let bytes = match payload.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(%err, "failed to encode settle payload");
            return;
        }
    };
    let snapshot = source.snapshot();
    let src = snapshot.routable.this.clone();
    let env = match build_envelope(&src, dst, MSG_SETTLE_V1, bytes, config.ttl) {
        Ok(env) => env,
        Err(err) => {
            tracing::warn!(%err, "failed to build settle envelope");
            return;
        }
    };
    match send_envelope(endpoint, &snapshot, &env, config.hop_timeout).await {
        Ok(ack) => tracing::debug!(
            msg_id = %env.msg_id.to_hex(),
            status = ack.status_str(),
            "sent settle payload"
        ),
        Err(err) => tracing::warn!(%err, "failed to send settle payload"),
    }
}

/// Relay an in-flight settlement forward one more step, preserving the
/// envelope's hop chain (so the settlement origin stays `hop_chain[0]`).
async fn relay_settle_forward(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    env: &Envelope,
    next: cawala_msg::OctAddr,
    forward: SettleForwardV1,
) {
    let bytes = match SettlePayloadV2::Forward(forward).to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(%err, "failed to encode settle forward");
            return;
        }
    };
    let mut out = env.clone();
    out.dst = next;
    out.msg_type = MSG_SETTLE_V1;
    out.payload = bytes;
    let snapshot = source.snapshot();
    // The transport appends a hop only when *forwarding*; a locally delivered
    // envelope has not recorded this node, so add it before re-addressing and
    // consume one TTL for the extra hop.
    if cawala_msg::append_hop(&mut out, &snapshot.routable.this).is_err() {
        tracing::warn!("failed to append settlement hop to the relayed envelope");
        return;
    }
    out.ttl = out.ttl.saturating_sub(1);
    match send_envelope(endpoint, &snapshot, &out, config.hop_timeout).await {
        Ok(ack) => tracing::debug!(
            msg_id = %out.msg_id.to_hex(),
            status = ack.status_str(),
            "relayed settle forward"
        ),
        // A downstream transport failure is handled by the origin's timeout
        // sweep; the local hop is already applied and retry is idempotent.
        Err(err) => tracing::warn!(%err, "failed to relay settle forward"),
    }
}

/// Send an `OrderResultV1` to a v1 browser over `MSG_LEDGER_V1`.
async fn send_order_result_to(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    browser: &PeerRef,
    result: OrderResultV1,
) {
    send_ledger_payload_to(
        endpoint,
        source,
        config,
        browser.addr.clone(),
        LedgerPayloadV1::OrderResult(result),
    )
    .await;
}

/// Send an `OrderResultV2` to a v2 browser over `MSG_LEDGER_V1`.
async fn send_order_result_v2_to(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    browser: &PeerRef,
    result: OrderResultV2,
) {
    send_ledger_payload_v2_to(
        endpoint,
        source,
        config,
        browser.addr.clone(),
        LedgerPayloadV2::OrderResult(result),
    )
    .await;
}

/// Send an `OrderResultV3` to a v2 browser over `MSG_LEDGER_V1`.
async fn send_order_result_v3_to(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    browser: &PeerRef,
    result: OrderResultV3,
) {
    send_ledger_payload_v3_to(
        endpoint,
        source,
        config,
        browser.addr.clone(),
        LedgerPayloadV3::OrderResult(result),
    )
    .await;
}

/// The derived address of `child_id` in `record`, if it is a `User` child.
fn user_child_address(record: &NodeRecord, child_id: &str) -> Option<cawala_msg::OctAddr> {
    let address = record.address.as_ref()?;
    record
        .children
        .iter()
        .find(|child| child.kind == ChildKind::User && child.child_id == child_id)
        .map(|child| address.child(child.slot))
}

/// Fully verify a terminal leaf's inclusion proof before the origin accepts an
/// `Applied` outcome.
///
/// Self-consistency only: the origin has no registry row binding a sibling
/// leaf's node id to its ledger key, so this proves the presented terminal hop
/// is internally consistent (correct order binding, valid terminal shape,
/// signed by the key the commitment names, included in the committed Merkle
/// tree) rather than that the sibling authored it. The leaf-address binding and
/// transport provenance remain the routing guard, and the origin must never
/// synthesize a proof itself.
///
/// All of the following must hold:
///
/// 1. `proof.leaf_addr ==` the pending payee leaf address;
/// 2. `terminal_seq == proof.entry.entry.seq` and `terminal_hash` is the real
///    entry hash;
/// 3. [`cawala_ledger::verify_applied_entry`] with `payer_leaf = false` (the
///    terminal hop is a `Descend` that credits the order's payee);
/// 4. the entry verifies under `proof.signer.ledger`, the signer is a `Node`,
///    and the commitment names that same ledger key;
/// 5. the proof structurally validates and the Merkle inclusion verifies
///    against the commitment's entry root.
fn verify_terminal_proof(
    proof: &EntryProofV1,
    order: &PaymentOrder,
    payee_leaf_addr: &cawala_msg::OctAddr,
    terminal_seq: u64,
    terminal_hash: &Hash,
) -> bool {
    // 1. Address binding.
    if proof.leaf_addr != *payee_leaf_addr {
        return false;
    }
    // 2. The claimed terminal coordinates must describe this exact entry.
    let Ok(entry_hash) = cawala_ledger::entry_hash(&proof.entry.entry) else {
        return false;
    };
    if terminal_seq != proof.entry.entry.seq || *terminal_hash != entry_hash {
        return false;
    }
    // 3. A terminal `Descend` that credits the order's payee.
    if cawala_ledger::verify_applied_entry(&proof.entry, order, false).is_err() {
        return false;
    }
    // 4. A ledger-bearing node signed the entry and the commitment names that
    //    same key.
    if proof.signer.role != PeerRole::Node {
        return false;
    }
    let Some(signer_ledger) = proof.signer.ledger.as_ref() else {
        return false;
    };
    if proof.entry.verify(signer_ledger).is_err() {
        return false;
    }
    if &proof.commitment.commitment.ledger_pubkey != signer_ledger {
        return false;
    }
    // 5. Structural bounds and Merkle inclusion against the committed root.
    if proof.validate().is_err() {
        return false;
    }
    if proof.commitment.commitment.entry_count != u64::from(proof.inclusion.tree_size) {
        return false;
    }
    if proof.inclusion.index >= proof.inclusion.tree_size {
        return false;
    }
    if proof.entry.entry.seq >= u64::from(proof.inclusion.tree_size) {
        return false;
    }
    cawala_ledger::verify_entry_inclusion(
        &proof.entry,
        &proof.inclusion,
        &proof.commitment.commitment.entry_root,
    )
}

/// Map a downstream `SettleRejectV1` to a browser settlement status, preserving
/// the failing hop: an `IntermediateRejected` after the payer's reservation is a
/// `Partial` cascade; a post-reservation `Malformed` is `Indeterminate` (the
/// debit is committed but the outcome is unknown); everything else is a plain
/// `Rejected` (pre-reservation refusal).
fn settle_reject_to_status(reason: &SettleRejectV1) -> SettlementStatusV2 {
    match reason {
        SettleRejectV1::IntermediateRejected { at, reason } => SettlementStatusV2::Partial {
            failed_at: at.clone(),
            reason: reason.clone(),
        },
        SettleRejectV1::Malformed => SettlementStatusV2::Indeterminate {
            reason: OrderRejectV1::BadRequest,
        },
        SettleRejectV1::PayerRejected | SettleRejectV1::RouteTooDeep => {
            SettlementStatusV2::Rejected {
                reason: OrderRejectV1::BadRequest,
            }
        }
    }
}

/// Map a v2 settlement status onto the v1 `OrderStatusV1` + reason pair (used
/// only for the theoretical v1 settlement sender).
fn settlement_status_to_v1(status: &SettlementStatusV2) -> (OrderStatusV1, Option<OrderRejectV1>) {
    match status {
        SettlementStatusV2::Applied { .. } => (OrderStatusV1::Applied, None),
        SettlementStatusV2::Duplicate { .. } => (OrderStatusV1::Duplicate, None),
        SettlementStatusV2::Partial { reason, .. }
        | SettlementStatusV2::Rejected { reason }
        | SettlementStatusV2::Indeterminate { reason } => {
            (OrderStatusV1::Rejected, Some(reason.clone()))
        }
    }
}

/// Assemble the registry for a settlement hop: this node's effective registry
/// plus the carried payer row (validated against the order/authorisation).
fn assemble_settlement_registry(
    service: &LedgerService,
    payer_key: &PeerKeys,
    order: &PaymentOrder,
    auth: &AuthRef,
) -> Result<PeerRegistry, OrderRejectV1> {
    if payer_key.node_id != order.from
        || payer_key.role != PeerRole::User
        || payer_key.ledger.is_some()
        || payer_key.operator != auth.operator
    {
        return Err(OrderRejectV1::Unauthorized);
    }
    let mut registry = service
        .effective_registry()
        .map_err(|_| OrderRejectV1::Internal)?;
    match registry.get(&order.from) {
        Some(existing) => {
            if existing.operator != auth.operator
                || existing.role != PeerRole::User
                || existing.ledger.is_some()
            {
                return Err(OrderRejectV1::Unauthorized);
            }
        }
        None => {
            registry
                .insert(payer_key.clone())
                .map_err(|_| OrderRejectV1::Unauthorized)?;
        }
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{ChildEntry, ParentLink};
    use cawala_ledger::OperatorSecretKey;
    use cawala_msg::{MAX_PAYLOAD, MSG_LEDGER_V1, PROTOCOL_VERSION};
    use cawala_topology::ChildKind;
    use iroh::SecretKey;

    fn peer(addr: &str, node: &str) -> PeerRef {
        PeerRef {
            addr: addr.parse().expect("valid octal address"),
            node: node.to_string(),
        }
    }

    fn record(
        node_id: &str,
        address: &str,
        parent: Option<(&str, u8)>,
        children: Vec<(&str, u8, ChildKind)>,
    ) -> NodeRecord {
        NodeRecord {
            node_id: node_id.to_string(),
            address: Some(address.parse().expect("valid octal address")),
            parent: parent.map(|(id, slot)| ParentLink {
                parent_id: id.to_string(),
                slot,
                generation: 0,
            }),
            children: children
                .into_iter()
                .map(|(id, slot, kind)| ChildEntry {
                    child_id: id.to_string(),
                    kind,
                    slot,
                    date_joined: 0,
                })
                .collect(),
            address_epoch: 0,
        }
    }

    #[test]
    fn routable_from_record_derives_parent_and_child_addresses() {
        let me = SecretKey::generate();
        let parent = SecretKey::generate();
        let child = SecretKey::generate();
        let user = SecretKey::generate();

        let rec = record(
            &me.public().to_string(),
            "0.1.2",
            Some((&parent.public().to_string(), 2)),
            vec![
                (&child.public().to_string(), 3, ChildKind::Node),
                (&user.public().to_string(), 5, ChildKind::User),
            ],
        );

        let snap = RoutableSnapshot::from_record(&rec).unwrap();
        assert_eq!(snap.routable.this.addr, "0.1.2".parse().unwrap());
        assert_eq!(snap.routable.this.node, me.public().to_string());

        let p = snap.routable.parent.as_ref().expect("parent present");
        assert_eq!(p.addr, "0.1".parse().unwrap());
        assert_eq!(p.node, parent.public().to_string());
        assert_eq!(p.kind, NeighborKind::Node);

        assert_eq!(snap.routable.children.len(), 2);
        let n3 = &snap.routable.children[0];
        assert_eq!(n3.addr, "0.1.2.3".parse().unwrap());
        assert_eq!(n3.node, child.public().to_string());
        assert_eq!(n3.kind, NeighborKind::Node);
        let n5 = &snap.routable.children[1];
        assert_eq!(n5.addr, "0.1.2.5".parse().unwrap());
        assert_eq!(n5.node, user.public().to_string());
        assert_eq!(n5.kind, NeighborKind::User);

        assert!(snap.hints.is_empty());
    }

    #[test]
    fn routable_from_record_requires_address() {
        let rec = NodeRecord {
            node_id: "node-a".to_string(),
            address: None,
            parent: None,
            children: Vec::new(),
            address_epoch: 0,
        };
        assert!(matches!(
            RoutableSnapshot::from_record(&rec),
            Err(RoutingSetupError::NoAddress)
        ));
    }

    #[test]
    fn routable_from_record_rejects_bad_endpoint_id() {
        let parent = record("node-a", "0.1", Some(("not-an-endpoint-id", 1)), vec![]);
        match RoutableSnapshot::from_record(&parent) {
            Err(RoutingSetupError::BadEndpointId { node_id, .. }) => {
                assert_eq!(node_id, "not-an-endpoint-id");
            }
            other => panic!("expected BadEndpointId, got {other:?}"),
        }

        let child = record(
            "node-a",
            "0.1",
            None,
            vec![("also-not-an-endpoint-id", 0, ChildKind::Node)],
        );
        match RoutableSnapshot::from_record(&child) {
            Err(RoutingSetupError::BadEndpointId { node_id, .. }) => {
                assert_eq!(node_id, "also-not-an-endpoint-id");
            }
            other => panic!("expected BadEndpointId, got {other:?}"),
        }
    }

    #[test]
    fn build_envelope_starts_chain_at_origin_and_uses_configured_ttl() {
        let src = peer("0.1.2", "origin-node");
        let dst: cawala_msg::OctAddr = "0.4.5".parse().unwrap();
        let env = build_envelope(&src, dst.clone(), MSG_LEDGER_V1, b"hello".to_vec(), 7).unwrap();

        assert_eq!(env.version, PROTOCOL_VERSION);
        assert_eq!(env.src, src);
        assert_eq!(env.dst, dst);
        assert_eq!(env.msg_type, MSG_LEDGER_V1);
        assert_eq!(env.payload, b"hello");
        assert_eq!(env.ttl, 7);
        assert_eq!(env.hop_chain.len(), 1);
        assert_eq!(env.hop_chain[0].addr, src.addr);
        assert_eq!(env.hop_chain[0].node, src.node);
        assert_ne!(env.nonce, 0);

        let err = build_envelope(
            &src,
            "0.4.5".parse().unwrap(),
            MSG_LEDGER_V1,
            vec![0u8; MAX_PAYLOAD + 1],
            7,
        )
        .unwrap_err();
        assert!(matches!(err, MsgError::PayloadTooLarge { .. }));
    }

    #[test]
    fn build_envelope_rejects_ttl_too_large() {
        let src = peer("0.1.2", "origin-node");
        let too_large = cawala_msg::MAX_HOPS as u8 + 1;
        let err = build_envelope(
            &src,
            "0.4.5".parse().unwrap(),
            MSG_LEDGER_V1,
            Vec::new(),
            too_large,
        )
        .unwrap_err();
        assert_eq!(err, MsgError::BadTtl { ttl: too_large });
    }

    #[test]
    fn routable_from_record_rejects_root_address_with_parent() {
        let me = SecretKey::generate();
        let parent = SecretKey::generate();
        // Structurally inconsistent: a root address with a parent link. This
        // must be a typed error, never a panic.
        let rec = record(
            &me.public().to_string(),
            "0",
            Some((&parent.public().to_string(), 1)),
            vec![],
        );
        assert!(matches!(
            RoutableSnapshot::from_record(&rec),
            Err(RoutingSetupError::InvalidRecord(_))
        ));
    }

    #[test]
    fn base32_neighbor_id_still_matches() {
        let me = SecretKey::generate();
        let parent = SecretKey::generate();
        let canonical = parent.public().to_string();
        // `Display` is canonical lowercase hex, but `FromStr` also accepts
        // RFC 4648 base32. A record storing that non-canonical form must not
        // break `is_neighbor` or hint lookups.
        let non_canonical = base32_nopad(parent.public().as_bytes());
        assert_ne!(non_canonical, canonical);
        assert_eq!(
            EndpointId::from_str(&non_canonical).unwrap(),
            parent.public()
        );

        let rec = record(
            &me.public().to_string(),
            "0.1",
            Some((&non_canonical, 1)),
            vec![],
        );
        let mut snap = RoutableSnapshot::from_record(&rec).unwrap();
        let p = snap.routable.parent.as_ref().expect("parent present");
        assert_eq!(p.node, canonical);

        // `is_neighbor` accepts either encoding; the stored id is canonical.
        let up: cawala_msg::OctAddr = "0".parse().unwrap();
        assert!(snap.is_neighbor(&canonical, &up));
        assert!(snap.is_neighbor(&non_canonical, &up));
        assert!(!snap.is_neighbor(&non_canonical, &"0.2".parse().unwrap()));

        // `endpoint_addr` canonicalizes before the hint lookup.
        let hinted = SecretKey::generate().public();
        snap.hints
            .insert(canonical.clone(), EndpointAddr::from(hinted));
        assert_eq!(
            snap.endpoint_addr(&non_canonical).unwrap(),
            EndpointAddr::from(hinted)
        );
    }

    /// Minimal RFC 4648 base32 (no padding), matching the encoding
    /// `iroh::EndpointId`'s `FromStr` accepts.
    fn base32_nopad(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;
        for &byte in bytes {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
            }
            buffer &= (1u32 << bits) - 1;
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
        }
        out
    }

    // ---------------------------------------------------------------------
    // End-to-end ledger dispatch tests
    // ---------------------------------------------------------------------

    /// Bind a hermetic endpoint on IPv4 loopback with relays disabled.
    async fn hermetic_endpoint(secret: &SecretKey) -> Endpoint {
        Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(secret.clone())
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind address")
            .bind()
            .await
            .expect("bind endpoint")
    }

    fn ledger_test_config() -> MsgConfig {
        MsgConfig {
            hop_timeout: Duration::from_secs(2),
            ..MsgConfig::default()
        }
    }

    /// Attach a `User` child to a persisted leaf record (the write `control
    /// approve` performs).
    fn attach_user_child(dir: &Path, node_id: &str, child_id: &str, slot: u8) {
        let mut store = RecordStore::open(dir, node_id).unwrap();
        store
            .attach_child(child_id, ChildKind::User, Some(slot), 1)
            .unwrap();
        store.save().unwrap();
    }

    /// Register a `User` peer row, as `control approve` does.
    fn register_user_peer(dir: &Path, user_id: &str, operator: &OperatorSecretKey) {
        use crate::ledger_peers::{load_peers, save_peers};
        use cawala_ledger::{NodeId, PeerKeys, PeerRole};
        let mut registry = load_peers(dir).unwrap();
        registry
            .insert(PeerKeys {
                node_id: NodeId::from(user_id.to_string()),
                operator: operator.public(),
                ledger: None,
                role: PeerRole::User,
            })
            .unwrap();
        save_peers(dir, &registry).unwrap();
    }

    /// Build an `Order` envelope from `snap`'s node to the root leaf (`0`).
    fn order_envelope(
        snap: &RoutableSnapshot,
        order: &cawala_ledger::PaymentOrder,
        operator: &OperatorSecretKey,
        config: &MsgConfig,
        dst: cawala_msg::OctAddr,
    ) -> Envelope {
        use cawala_msg::OrderV1;
        let auth = order.authorize(operator).unwrap();
        let payload = LedgerPayloadV1::Order(OrderV1 {
            order: order.clone(),
            auth,
        })
        .to_bytes()
        .unwrap();
        build_envelope(&snap.routable.this, dst, MSG_LEDGER_V1, payload, config.ttl).unwrap()
    }

    fn balance_query_envelope(
        snap: &RoutableSnapshot,
        query_id: u64,
        config: &MsgConfig,
        dst: cawala_msg::OctAddr,
    ) -> Envelope {
        let payload = LedgerPayloadV1::BalanceQuery(cawala_msg::BalanceQueryV1 { query_id })
            .to_bytes()
            .unwrap();
        build_envelope(&snap.routable.this, dst, MSG_LEDGER_V1, payload, config.ttl).unwrap()
    }

    /// A leaf whose `node.json` initially lists no children: the live source
    /// must observe children added *after* the handler is spawned.
    #[tokio::test]
    async fn live_source_accepts_user_approved_after_spawn_and_applies_order() {
        use cawala_ledger::{
            Amount, NodeId, OperatorSecretKey, PaymentOrder, verify_balance_attestation,
        };

        let dir = tempfile::tempdir().unwrap();
        let node_secret = crate::identity::load_or_create_secret_key(dir.path()).unwrap();
        let node_id = node_secret.public().to_string();

        let payer_secret = SecretKey::generate();
        let payer_id = payer_secret.public().to_string();
        let payer_op = OperatorSecretKey::from_bytes([31u8; 32]);
        let payee_id = SecretKey::generate().public().to_string();
        let payee_op = OperatorSecretKey::from_bytes([32u8; 32]);
        let payer = NodeId::from(payer_id.clone());
        let payee = NodeId::from(payee_id.clone());

        // The leaf starts as a root with no children.
        let mut store = RecordStore::open(dir.path(), &node_id).unwrap();
        store.set_address("0".parse().unwrap()).unwrap();
        store.save().unwrap();

        // Ledger: open both user accounts and fund the payer before the order.
        let mut service = LedgerService::open(dir.path(), &node_id).unwrap();
        service.ensure_account_open(&payer, ChildKind::User).unwrap();
        service.ensure_account_open(&payee, ChildKind::User).unwrap();
        let node_operator = OperatorSecretKey::from_bytes(node_secret.to_bytes());
        service.fund(&payer, ChildKind::User, 100, &node_operator, 1, 1_000).unwrap();

        let leaf_endpoint = hermetic_endpoint(&node_secret).await;
        let payer_endpoint = hermetic_endpoint(&payer_secret).await;

        // The live source carries a hint for the payer (replies need a dial
        // target); neighbor status itself comes from node.json.
        let mut leaf_hints = HashMap::new();
        leaf_hints.insert(payer_id.clone(), payer_endpoint.addr());
        let source = NeighborSource::live(dir.path(), &node_id, leaf_hints).unwrap();

        let config = ledger_test_config();
        let (leaf_router, mut leaf_rx) =
            spawn_msg_node_with_source_on(leaf_endpoint.clone(), source.clone(), config.clone());

        // Dispatch task mirrors `run()`'s sink drain loop.
        let ledger = Arc::new(tokio::sync::Mutex::new(service));
        let manager = Arc::new(tokio::sync::Mutex::new(SettlementManager::new()));
        let dispatch_manager = Arc::clone(&manager);
        let dispatch_dir = dir.path().to_path_buf();
        let dispatch_node = node_id.clone();
        let dispatch_source = source.clone();
        let dispatch_ledger = Arc::clone(&ledger);
        let dispatch_endpoint = leaf_endpoint.clone();
        let dispatch_config = config.clone();
        tokio::spawn(async move {
            while let Some(env) = leaf_rx.recv().await {
                dispatch_ledger_envelope(
                    &dispatch_endpoint,
                    &dispatch_source,
                    &dispatch_config,
                    &dispatch_ledger,
                    &dispatch_manager,
                    &dispatch_dir,
                    &dispatch_node,
                    env,
                )
                .await;
            }
        });

        // The payer's own view: a child of the leaf at slot 3 (address 0.3).
        let payer_record = record(&payer_id, "0.3", Some((&node_id, 3)), vec![]);
        let mut payer_snap = RoutableSnapshot::from_record(&payer_record).unwrap();
        payer_snap
            .hints
            .insert(node_id.clone(), leaf_endpoint.addr());
        let (_payer_router, mut payer_rx) =
            spawn_msg_node_on(payer_endpoint.clone(), payer_snap.clone(), config.clone());

        let leaf_addr: cawala_msg::OctAddr = "0".parse().unwrap();
        let expiry = unix_now() + 3_600;
        let order = PaymentOrder {
            from: payer.clone(),
            to: payee.clone(),
            amount: Amount::new(30),
            nonce: 7,
            expiry,
        };

        // Before approval the leaf does not list the payer -> not a neighbor,
        // so the handler refuses and no result is produced.
        let pre = order_envelope(&payer_snap, &order, &payer_op, &config, leaf_addr.clone());
        let ack = send_envelope(&payer_endpoint, &payer_snap, &pre, config.hop_timeout)
            .await
            .unwrap();
        assert_eq!(ack.status, AckStatus::Rejected(RejectReason::NotNeighbor));
        assert!(payer_rx.try_recv().is_err());

        // Control-style approval: persist the child rows and peer registrations.
        attach_user_child(dir.path(), &node_id, &payer_id, 3);
        attach_user_child(dir.path(), &node_id, &payee_id, 4);
        register_user_peer(dir.path(), &payer_id, &payer_op);
        register_user_peer(dir.path(), &payee_id, &payee_op);

        // The *same* running handler now accepts the payer: the live source
        // re-read node.json, and the order is applied end to end.
        let post = order_envelope(&payer_snap, &order, &payer_op, &config, leaf_addr);
        let ack = send_envelope(&payer_endpoint, &payer_snap, &post, config.hop_timeout)
            .await
            .unwrap();
        assert_eq!(ack.status, AckStatus::Delivered);

        let reply = tokio::time::timeout(Duration::from_secs(5), payer_rx.recv())
            .await
            .expect("order result within timeout")
            .expect("order result envelope");
        let LedgerPayloadV1::OrderResult(result) =
            LedgerPayloadV1::from_bytes(&reply.payload).unwrap()
        else {
            panic!("expected an OrderResult");
        };
        assert_eq!(result.reply_to, post.msg_id);
        assert_eq!(result.order_hash, order.hash());
        assert_eq!(result.status, OrderStatusV1::Applied);
        assert_eq!(result.reason, None);

        let receipt = result.balance.expect("a payer balance receipt");
        verify_balance_attestation(
            &receipt.attestation,
            &receipt.commitment,
            &receipt.ledger_pubkey,
        )
        .unwrap();
        assert_eq!(receipt.attestation.balance, Amount::new(70));

        {
            let svc = ledger.lock().await;
            assert_eq!(svc.balance_of(&payer), Amount::new(70));
            assert_eq!(svc.balance_of(&payee), Amount::new(30));
        }

        // Restart recovery: a fresh service replays the log and sees the
        // post-transfer balances.
        let reopened = LedgerService::open(dir.path(), &node_id).unwrap();
        assert_eq!(reopened.balance_of(&payer), Amount::new(70));
        assert_eq!(reopened.balance_of(&payee), Amount::new(30));

        leaf_router.shutdown().await.unwrap();
    }

    /// A `BalanceQuery` from an approved user returns a receipt that verifies
    /// under the leaf's ledger key, echoing the query/reply correlation ids.
    #[tokio::test]
    async fn balance_query_returns_verifiable_receipt() {
        use cawala_ledger::{Amount, NodeId, OperatorSecretKey, verify_balance_attestation};

        let dir = tempfile::tempdir().unwrap();
        let node_secret = crate::identity::load_or_create_secret_key(dir.path()).unwrap();
        let node_id = node_secret.public().to_string();

        let user_secret = SecretKey::generate();
        let user_id = user_secret.public().to_string();
        let user = NodeId::from(user_id.clone());

        // Persist a leaf record that already lists the user (approval happened
        // before spawn).
        let mut store = RecordStore::open(dir.path(), &node_id).unwrap();
        store.set_address("0".parse().unwrap()).unwrap();
        store
            .attach_child(user_id.clone(), ChildKind::User, Some(5), 1)
            .unwrap();
        store.save().unwrap();
        register_user_peer(
            dir.path(),
            &user_id,
            &OperatorSecretKey::from_bytes([51u8; 32]),
        );

        let mut service = LedgerService::open(dir.path(), &node_id).unwrap();
        service.ensure_account_open(&user, ChildKind::User).unwrap();
        let node_operator = OperatorSecretKey::from_bytes(node_secret.to_bytes());
        service.fund(&user, ChildKind::User, 42, &node_operator, 1, 1_000).unwrap();

        let leaf_endpoint = hermetic_endpoint(&node_secret).await;
        let user_endpoint = hermetic_endpoint(&user_secret).await;

        let leaf_record = RecordStore::open(dir.path(), &node_id).unwrap();
        let mut leaf_snap = RoutableSnapshot::from_record(leaf_record.record()).unwrap();
        leaf_snap
            .hints
            .insert(user_id.clone(), user_endpoint.addr());
        let source = NeighborSource::Static(leaf_snap);

        let config = ledger_test_config();
        let (leaf_router, mut leaf_rx) =
            spawn_msg_node_with_source_on(leaf_endpoint.clone(), source.clone(), config.clone());

        let ledger = Arc::new(tokio::sync::Mutex::new(service));
        let manager = Arc::new(tokio::sync::Mutex::new(SettlementManager::new()));
        let dispatch_manager = Arc::clone(&manager);
        let dispatch_dir = dir.path().to_path_buf();
        let dispatch_node = node_id.clone();
        let dispatch_source = source;
        let dispatch_ledger = Arc::clone(&ledger);
        let dispatch_endpoint = leaf_endpoint.clone();
        let dispatch_config = config.clone();
        tokio::spawn(async move {
            while let Some(env) = leaf_rx.recv().await {
                dispatch_ledger_envelope(
                    &dispatch_endpoint,
                    &dispatch_source,
                    &dispatch_config,
                    &dispatch_ledger,
                    &dispatch_manager,
                    &dispatch_dir,
                    &dispatch_node,
                    env,
                )
                .await;
            }
        });

        let user_record = record(&user_id, "0.5", Some((&node_id, 5)), vec![]);
        let mut user_snap = RoutableSnapshot::from_record(&user_record).unwrap();
        user_snap
            .hints
            .insert(node_id.clone(), leaf_endpoint.addr());
        let (_user_router, mut user_rx) =
            spawn_msg_node_on(user_endpoint.clone(), user_snap.clone(), config.clone());

        let query = balance_query_envelope(
            &user_snap,
            99,
            &config,
            "0".parse().unwrap(),
        );
        let ack = send_envelope(&user_endpoint, &user_snap, &query, config.hop_timeout)
            .await
            .unwrap();
        assert_eq!(ack.status, AckStatus::Delivered);

        let reply = tokio::time::timeout(Duration::from_secs(5), user_rx.recv())
            .await
            .expect("balance receipt within timeout")
            .expect("balance receipt envelope");
        let LedgerPayloadV1::BalanceReceipt(receipt) =
            LedgerPayloadV1::from_bytes(&reply.payload).unwrap()
        else {
            panic!("expected a BalanceReceipt");
        };
        assert_eq!(receipt.reply_to, Some(query.msg_id));
        assert_eq!(receipt.query_id, Some(99));
        assert!(receipt.history_within_bound());
        verify_balance_attestation(
            &receipt.attestation,
            &receipt.commitment,
            &receipt.ledger_pubkey,
        )
        .unwrap();
        assert_eq!(receipt.attestation.balance, Amount::new(42));
        assert_eq!(receipt.attestation.edge.child, user);

        leaf_router.shutdown().await.unwrap();
    }

    /// An `Order` from a direct neighbor that is a `Node` child (not a leaf
    /// `User` child) is answered `Rejected(NotAChild)` rather than dropped.
    #[tokio::test]
    async fn order_from_non_user_child_is_rejected_with_result() {
        use cawala_ledger::{Amount, NodeId, OperatorSecretKey, PaymentOrder};

        let dir = tempfile::tempdir().unwrap();
        let node_secret = crate::identity::load_or_create_secret_key(dir.path()).unwrap();
        let node_id = node_secret.public().to_string();
        let _service = LedgerService::open(dir.path(), &node_id).unwrap();

        let child_secret = SecretKey::generate();
        let child_id = child_secret.public().to_string();
        let child = NodeId::from(child_id.clone());

        // Leaf record lists the sender as a *Node* child in slot 1.
        let mut store = RecordStore::open(dir.path(), &node_id).unwrap();
        store.set_address("0".parse().unwrap()).unwrap();
        store
            .attach_child(child_id.clone(), ChildKind::Node, Some(1), 1)
            .unwrap();
        store.save().unwrap();

        let leaf_endpoint = hermetic_endpoint(&node_secret).await;
        let child_endpoint = hermetic_endpoint(&child_secret).await;

        let leaf_record = RecordStore::open(dir.path(), &node_id).unwrap();
        let mut leaf_snap = RoutableSnapshot::from_record(leaf_record.record()).unwrap();
        leaf_snap
            .hints
            .insert(child_id.clone(), child_endpoint.addr());
        let source = NeighborSource::Static(leaf_snap);

        let config = ledger_test_config();
        let (leaf_router, mut leaf_rx) =
            spawn_msg_node_with_source_on(leaf_endpoint.clone(), source.clone(), config.clone());

        let ledger = Arc::new(tokio::sync::Mutex::new(
            LedgerService::open(dir.path(), &node_id).unwrap(),
        ));
        let manager = Arc::new(tokio::sync::Mutex::new(SettlementManager::new()));
        let dispatch_manager = Arc::clone(&manager);
        let dispatch_dir = dir.path().to_path_buf();
        let dispatch_node = node_id.clone();
        let dispatch_source = source;
        let dispatch_ledger = Arc::clone(&ledger);
        let dispatch_endpoint = leaf_endpoint.clone();
        let dispatch_config = config.clone();
        tokio::spawn(async move {
            while let Some(env) = leaf_rx.recv().await {
                dispatch_ledger_envelope(
                    &dispatch_endpoint,
                    &dispatch_source,
                    &dispatch_config,
                    &dispatch_ledger,
                    &dispatch_manager,
                    &dispatch_dir,
                    &dispatch_node,
                    env,
                )
                .await;
            }
        });

        // The node child's own view: address 0.1, parent is the leaf.
        let child_record = record(&child_id, "0.1", Some((&node_id, 1)), vec![]);
        let mut child_snap = RoutableSnapshot::from_record(&child_record).unwrap();
        child_snap
            .hints
            .insert(node_id.clone(), leaf_endpoint.addr());
        let (_child_router, mut child_rx) =
            spawn_msg_node_on(child_endpoint.clone(), child_snap.clone(), config.clone());

        let stranger = NodeId::from("stranger");
        let order = PaymentOrder {
            from: child.clone(),
            to: stranger,
            amount: Amount::new(1),
            nonce: 1,
            expiry: unix_now() + 3_600,
        };
        let op = OperatorSecretKey::from_bytes([61u8; 32]);
        let env = order_envelope(
            &child_snap,
            &order,
            &op,
            &config,
            "0".parse().unwrap(),
        );
        let ack = send_envelope(&child_endpoint, &child_snap, &env, config.hop_timeout)
            .await
            .unwrap();
        assert_eq!(ack.status, AckStatus::Delivered);

        let reply = tokio::time::timeout(Duration::from_secs(5), child_rx.recv())
            .await
            .expect("order result within timeout")
            .expect("order result envelope");
        let LedgerPayloadV1::OrderResult(result) =
            LedgerPayloadV1::from_bytes(&reply.payload).unwrap()
        else {
            panic!("expected an OrderResult");
        };
        assert_eq!(result.status, OrderStatusV1::Rejected);
        assert_eq!(result.reason, Some(OrderRejectV1::NotAChild));
        assert!(result.balance.is_none());

        leaf_router.shutdown().await.unwrap();
    }

    // ---------------------------------------------------------------------
    // P5a: carried-prefix verification where the signer's key is resolvable
    // ---------------------------------------------------------------------

    fn carried_order() -> PaymentOrder {
        PaymentOrder {
            from: NodeId::from("uA"),
            to: NodeId::from("uB"),
            amount: cawala_ledger::Amount::new(100),
            nonce: 1,
            expiry: u64::MAX,
        }
    }

    fn signer_addrs() -> [cawala_msg::OctAddr; 3] {
        expected_signers(&"0.1.3".parse().unwrap(), &"0.2.4".parse().unwrap())
            .expect("depth-1 route has three signers")
    }

    fn node_row(
        id: &str,
        operator: &OperatorSecretKey,
        key: &cawala_ledger::LedgerSecretKey,
    ) -> PeerKeys {
        PeerKeys {
            node_id: NodeId::from(id),
            operator: operator.public(),
            ledger: Some(key.public()),
            role: PeerRole::Node,
        }
    }

    fn make_hop(
        signer_addr: &str,
        order: &PaymentOrder,
        ledger_key: &cawala_ledger::LedgerSecretKey,
        role: HopRole,
        first: cawala_ledger::AccountRef,
        second: cawala_ledger::AccountRef,
    ) -> SettleHopV1 {
        let m = i64::try_from(order.amount.get()).unwrap();
        let entry = cawala_ledger::Entry {
            ledger_id: ledger_key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: cawala_ledger::EntryBody::Transfer {
                payment_id: order.hash(),
                amount: order.amount,
                role,
            },
            postings: hop_postings(role, &first, &second, m),
            auth: Some(
                order
                    .authorize(&OperatorSecretKey::from_bytes([1u8; 32]))
                    .unwrap(),
            ),
        };
        SettleHopV1 {
            signer_addr: signer_addr.parse().unwrap(),
            entry: SignedEntry::sign(entry, ledger_key).unwrap(),
        }
    }

    fn posting(account: cawala_ledger::AccountRef, delta: i64) -> cawala_ledger::Posting {
        cawala_ledger::Posting {
            account,
            delta: cawala_ledger::SignedAmount::new(delta),
        }
    }

    /// Like [`make_hop`] but with explicit postings, so a non-canonical carried
    /// entry can be built (the entry is still signed by `ledger_key`).
    fn make_hop_with_postings(
        signer_addr: &str,
        order: &PaymentOrder,
        ledger_key: &cawala_ledger::LedgerSecretKey,
        role: HopRole,
        postings: Vec<cawala_ledger::Posting>,
    ) -> SettleHopV1 {
        let entry = cawala_ledger::Entry {
            ledger_id: ledger_key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: cawala_ledger::EntryBody::Transfer {
                payment_id: order.hash(),
                amount: order.amount,
                role,
            },
            postings,
            auth: Some(
                order
                    .authorize(&OperatorSecretKey::from_bytes([1u8; 32]))
                    .unwrap(),
            ),
        };
        SettleHopV1 {
            signer_addr: signer_addr.parse().unwrap(),
            entry: SignedEntry::sign(entry, ledger_key).unwrap(),
        }
    }

    fn ascend_hop(order: &PaymentOrder, key: &cawala_ledger::LedgerSecretKey) -> SettleHopV1 {
        make_hop(
            "0.1",
            order,
            key,
            HopRole::Ascend,
            cawala_ledger::AccountRef::Parent,
            cawala_ledger::AccountRef::Child(NodeId::from("0.1.3")),
        )
    }

    fn lca_hop(order: &PaymentOrder, key: &cawala_ledger::LedgerSecretKey) -> SettleHopV1 {
        make_hop(
            "0",
            order,
            key,
            HopRole::Lca,
            cawala_ledger::AccountRef::Child(NodeId::from("0.1")),
            cawala_ledger::AccountRef::Child(NodeId::from("0.2")),
        )
    }

    /// Terminal leaf `0.2`: the LCA's carried hop (`signers[1]`) is verified
    /// under the now-known parent key; a tampered LCA entry is rejected.
    #[test]
    fn carried_prefix_verifies_lca_hop_at_terminal() {
        let order = carried_order();
        let a_key = cawala_ledger::LedgerSecretKey::from_bytes([11u8; 32]);
        let p_key = cawala_ledger::LedgerSecretKey::from_bytes([22u8; 32]);
        let b_key = cawala_ledger::LedgerSecretKey::from_bytes([33u8; 32]);
        let hops = vec![ascend_hop(&order, &a_key), lca_hop(&order, &p_key)];
        let signers = signer_addrs();
        let payer = "0.1.3".parse().unwrap();
        let payee = "0.2.4".parse().unwrap();
        let this = "0.2".parse().unwrap();
        // B knows its parent P; sibling A is not resolvable at B.
        let neighbors = vec![("0".parse().unwrap(), NodeId::from("P"))];
        let mut registry = PeerRegistry::new();
        registry
            .insert(node_row(
                "P",
                &OperatorSecretKey::from_bytes([2u8; 32]),
                &p_key,
            ))
            .unwrap();

        assert!(carried_hops_match(
            &hops,
            &signers,
            &payer,
            &payee,
            &this,
            &order,
            &b_key.public(),
            &neighbors,
            &registry,
        ));

        let mut tampered = hops.clone();
        tampered[1].entry.signature = b_key.sign(b"forged");
        assert!(
            !carried_hops_match(
                &tampered,
                &signers,
                &payer,
                &payee,
                &this,
                &order,
                &b_key.public(),
                &neighbors,
                &registry,
            ),
            "a tampered LCA signature must be rejected"
        );
    }

    /// LCA `0`: the payer leaf's carried hop (`signers[0]`) is verified under
    /// the known child key, and an entry naming that child but signed by a
    /// different registered neighbor is rejected.
    #[test]
    fn carried_prefix_verifies_payer_leaf_hop_at_lca() {
        let order = carried_order();
        let a_key = cawala_ledger::LedgerSecretKey::from_bytes([11u8; 32]);
        let p_key = cawala_ledger::LedgerSecretKey::from_bytes([22u8; 32]);
        let b_key = cawala_ledger::LedgerSecretKey::from_bytes([33u8; 32]);
        let signers = signer_addrs();
        let payer = "0.1.3".parse().unwrap();
        let payee = "0.2.4".parse().unwrap();
        let this = "0".parse().unwrap();
        let neighbors = vec![
            ("0.1".parse().unwrap(), NodeId::from("A")),
            ("0.2".parse().unwrap(), NodeId::from("B")),
        ];
        let mut registry = PeerRegistry::new();
        registry
            .insert(node_row(
                "A",
                &OperatorSecretKey::from_bytes([1u8; 32]),
                &a_key,
            ))
            .unwrap();
        registry
            .insert(node_row(
                "B",
                &OperatorSecretKey::from_bytes([3u8; 32]),
                &b_key,
            ))
            .unwrap();

        let honest = vec![ascend_hop(&order, &a_key)];
        assert!(carried_hops_match(
            &honest,
            &signers,
            &payer,
            &payee,
            &this,
            &order,
            &p_key.public(),
            &neighbors,
            &registry,
        ));

        // Names the payer leaf `A` but is signed by the registered B key: the
        // address is bound to A's row, not merely to any registered key.
        let forged = vec![make_hop(
            "0.1",
            &order,
            &b_key,
            HopRole::Ascend,
            cawala_ledger::AccountRef::Parent,
            cawala_ledger::AccountRef::Child(NodeId::from("0.1.3")),
        )];
        assert!(
            !carried_hops_match(
                &forged,
                &signers,
                &payer,
                &payee,
                &this,
                &order,
                &p_key.public(),
                &neighbors,
                &registry,
            ),
            "a non-neighbor key must not vouch for another signer's address"
        );
    }

    /// A signer whose row is genuinely absent keeps the name/role/shape checks
    /// (the documented residual until full route verification lands).
    #[test]
    fn carried_prefix_defers_unresolvable_signer() {
        let order = carried_order();
        let a_key = cawala_ledger::LedgerSecretKey::from_bytes([11u8; 32]);
        let p_key = cawala_ledger::LedgerSecretKey::from_bytes([22u8; 32]);
        let b_key = cawala_ledger::LedgerSecretKey::from_bytes([33u8; 32]);
        let hops = vec![ascend_hop(&order, &a_key), lca_hop(&order, &p_key)];
        let signers = signer_addrs();
        let payer = "0.1.3".parse().unwrap();
        let payee = "0.2.4".parse().unwrap();
        let this = "0.2".parse().unwrap();
        let neighbors = vec![("0".parse().unwrap(), NodeId::from("P"))];

        // No registry rows at all: the keys are unavailable here, so only the
        // shape/role checks apply.
        assert!(carried_hops_match(
            &hops,
            &signers,
            &payer,
            &payee,
            &this,
            &order,
            &b_key.public(),
            &neighbors,
            &PeerRegistry::new(),
        ));
    }

    /// An unresolvable signer's hop must still be signed by the key it names:
    /// a forged signature is rejected even though the signer's registered key
    /// is unknown here.
    #[test]
    fn carried_prefix_rejects_unresolvable_invalid_signature() {
        let order = carried_order();
        let a_key = cawala_ledger::LedgerSecretKey::from_bytes([11u8; 32]);
        let p_key = cawala_ledger::LedgerSecretKey::from_bytes([22u8; 32]);
        let b_key = cawala_ledger::LedgerSecretKey::from_bytes([33u8; 32]);
        let mut hops = vec![ascend_hop(&order, &a_key), lca_hop(&order, &p_key)];
        // The entry declares `a_key` but is signed by a different key.
        hops[0].entry.signature = b_key.sign(b"forged");

        let signers = signer_addrs();
        let payer = "0.1.3".parse().unwrap();
        let payee = "0.2.4".parse().unwrap();
        let this = "0.2".parse().unwrap();
        // A (`0.1`) is neither this node nor a neighbor at the terminal.
        let neighbors = vec![("0".parse().unwrap(), NodeId::from("P"))];

        assert!(
            !carried_hops_match(
                &hops,
                &signers,
                &payer,
                &payee,
                &this,
                &order,
                &b_key.public(),
                &neighbors,
                &PeerRegistry::new(),
            ),
            "an unresolvable hop whose signature does not match its declared ledger_id must be rejected"
        );
    }

    /// An unresolvable signer's hop must have the role-canonical posting shape;
    /// a malformed shape is rejected even though the signer's key is unknown.
    #[test]
    fn carried_prefix_rejects_unresolvable_non_canonical_shape() {
        let order = carried_order();
        let a_key = cawala_ledger::LedgerSecretKey::from_bytes([11u8; 32]);
        let p_key = cawala_ledger::LedgerSecretKey::from_bytes([22u8; 32]);
        let b_key = cawala_ledger::LedgerSecretKey::from_bytes([33u8; 32]);
        let m = i64::try_from(order.amount.get()).unwrap();
        // `Ascend` must be exactly `Parent + one child`; add a second child leg.
        let malformed = make_hop_with_postings(
            "0.1",
            &order,
            &a_key,
            HopRole::Ascend,
            vec![
                posting(cawala_ledger::AccountRef::Parent, -m),
                posting(cawala_ledger::AccountRef::Child(NodeId::from("x")), -m),
                posting(cawala_ledger::AccountRef::Child(NodeId::from("y")), m),
            ],
        );
        let hops = vec![malformed, lca_hop(&order, &p_key)];

        let signers = signer_addrs();
        let payer = "0.1.3".parse().unwrap();
        let payee = "0.2.4".parse().unwrap();
        let this = "0.2".parse().unwrap();
        let neighbors = vec![("0".parse().unwrap(), NodeId::from("P"))];

        assert!(
            !carried_hops_match(
                &hops,
                &signers,
                &payer,
                &payee,
                &this,
                &order,
                &b_key.public(),
                &neighbors,
                &PeerRegistry::new(),
            ),
            "an unresolvable hop with a non-canonical posting shape must be rejected"
        );
    }

    /// The unresolvable-signer warning fires once per distinct address: the
    /// first sighting returns `true`, repeats and other-address calls behave as
    /// documented. This is logging-only and never affects `carried_hops_match`.
    #[test]
    fn unresolvable_signer_note_warns_once_per_address() {
        let addr: cawala_msg::OctAddr = "0.7.7".parse().unwrap();
        assert!(
            note_unresolvable_signer(&addr),
            "the first sighting of an address should warn"
        );
        assert!(
            !note_unresolvable_signer(&addr),
            "a repeat of the same address should stay silent"
        );

        let other: cawala_msg::OctAddr = "0.7.6".parse().unwrap();
        assert!(
            note_unresolvable_signer(&other),
            "a distinct address should warn on its first sighting"
        );
        assert!(!note_unresolvable_signer(&other));
    }
}
