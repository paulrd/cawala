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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId};

use cawala_msg::{
    Ack, AckStatus, Envelope, LedgerPayloadV1, MSG_LEDGER_V1, MessageType, MsgError, MsgId,
    Neighbor, NeighborKind, OrderRejectV1, OrderResultV1, OrderStatusV1, PeerRef, RejectReason,
    Routable, RouteDecision, RouteError, Seen, SeenConfig, SeenSet,
};
use cawala_topology::ChildKind;

use crate::ledger_service::{ApplyOutcome, LedgerService};
use crate::record::{NodeRecord, RecordStore};

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
        let seen = Mutex::new(SeenSet::new(config.seen));
        MsgHandler {
            endpoint,
            neighbors: source,
            config,
            seen,
            sink,
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

/// Process one locally delivered `MSG_LEDGER_V1` envelope at a leaf node.
///
/// This is the node's **drain-loop** half of the ledger protocol: it runs after
/// [`MsgHandler`] has queued the envelope (`Delivered` means "queued", not
/// "applied"). Dispatch deliberately lives outside [`MsgHandler`] so the
/// transport never blocks on ledger IO.
///
/// `Order` payloads are applied to the shared [`LedgerService`] and answered
/// with an [`OrderResultV1`] carrying a fresh balance receipt for the payer.
/// `BalanceQuery` payloads from a `User` child are answered with a signed
/// [`BalanceReceiptV1`]. Inbound results/receipts at a leaf and malformed
/// payloads are logged and skipped. No failure path panics: a bad payload or an
/// unreachable reply must not kill the drain task.
pub async fn dispatch_ledger_envelope(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    ledger: &Arc<tokio::sync::Mutex<LedgerService>>,
    data_dir: &Path,
    node_id: &str,
    env: Envelope,
) {
    let payload = match LedgerPayloadV1::from_bytes(&env.payload) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                msg_id = %env.msg_id.to_hex(),
                %err,
                "malformed MSG_LEDGER_V1 payload; skipping"
            );
            return;
        }
    };

    match payload {
        LedgerPayloadV1::Order(order_v1) => {
            let order = order_v1.order;
            let auth = order_v1.auth;
            let order_hash = order.hash();
            let sender = env.src.node.clone();

            let record = match RecordStore::open(data_dir, node_id) {
                Ok(store) => store.record().clone(),
                Err(err) => {
                    tracing::warn!(%err, "cannot reload node record to apply an order; skipping");
                    return;
                }
            };

            // `apply_order` alone cannot distinguish "not a child" from other
            // structural failures, so reject a non-user-child sender up front
            // and always answer with a result (never drop silently).
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
                    );
                }
                let outcome = service.apply_order(
                    &order,
                    &auth,
                    &cawala_ledger::NodeId::from(sender),
                    &record,
                    now,
                );
                let balance = match &outcome.status {
                    OrderStatusV1::Applied | OrderStatusV1::Duplicate => service
                        .balance_receipt(&order.from, &record, None, None, None)
                        .ok(),
                    OrderStatusV1::Rejected => None,
                };
                (outcome, balance)
            })
            .await;

            let (outcome, balance) = match applied {
                Ok(applied) => applied,
                Err(err) => {
                    tracing::warn!(%err, "ledger apply task failed; skipping order");
                    return;
                }
            };

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
                &env,
                LedgerPayloadV1::OrderResult(result),
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

            // Only this leaf's own users get receipts, and only at the address
            // their slot derives. This mirrors the `is_neighbor` check in the
            // handler with an explicit record lookup.
            let derived = record.address.as_ref().and_then(|address| {
                record
                    .children
                    .iter()
                    .find(|child| child.child_id == env.src.node && child.kind == ChildKind::User)
                    .map(|child| address.child(child.slot))
            });
            if derived.as_ref() != Some(&env.src.addr) {
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

/// Encode `payload`, build a reply envelope to `env.src`, and send it. Failures
/// are logged and dropped so the drain loop keeps running.
async fn send_ledger_reply(
    endpoint: &Endpoint,
    source: &NeighborSource,
    config: &MsgConfig,
    env: &Envelope,
    payload: LedgerPayloadV1,
) {
    let bytes = match payload.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(%err, "failed to encode ledger reply");
            return;
        }
    };
    let snapshot = source.snapshot();
    let src = snapshot.routable.this.clone();
    let reply = match build_envelope(&src, env.src.addr.clone(), MSG_LEDGER_V1, bytes, config.ttl) {
        Ok(reply) => reply,
        Err(err) => {
            tracing::warn!(%err, "failed to build ledger reply envelope");
            return;
        }
    };
    match send_envelope(endpoint, &snapshot, &reply, config.hop_timeout).await {
        Ok(ack) => tracing::debug!(
            msg_id = %reply.msg_id.to_hex(),
            status = ack.status_str(),
            "sent ledger reply"
        ),
        Err(err) => tracing::warn!(%err, "failed to send ledger reply"),
    }
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
        service.fund(&payer, 100, &node_operator, 1, 1_000).unwrap();

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
        service.fund(&user, 42, &node_operator, 1, 1_000).unwrap();

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
}
