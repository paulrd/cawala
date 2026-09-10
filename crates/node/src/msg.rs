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

use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId};

use cawala_msg::{
    Ack, AckStatus, Envelope, MessageType, MsgError, MsgId, Neighbor, NeighborKind, PeerRef,
    RejectReason, Routable, RouteDecision, RouteError, Seen, SeenConfig, SeenSet,
};

use crate::record::NodeRecord;

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
    snapshot: RoutableSnapshot,
    config: MsgConfig,
    seen: Mutex<SeenSet>,
    sink: tokio::sync::mpsc::Sender<Envelope>,
}

impl MsgHandler {
    /// Build a handler that delivers locally destined envelopes to `sink` and
    /// forwards the rest through `endpoint`.
    pub fn new(
        endpoint: Endpoint,
        snapshot: RoutableSnapshot,
        config: MsgConfig,
        sink: tokio::sync::mpsc::Sender<Envelope>,
    ) -> Self {
        let seen = Mutex::new(SeenSet::new(config.seen));
        MsgHandler {
            endpoint,
            snapshot,
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
        self.snapshot.hints.insert(id.to_string(), addr);
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

        let this = &self.snapshot.routable.this;

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
        if last.node != remote.to_string() || !self.snapshot.is_neighbor(&last.node, &last.addr) {
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
        let status = match cawala_msg::route(&self.snapshot.routable, &env.dst) {
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

                        match self.snapshot.endpoint_addr(&next_node) {
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
    let (sink, receiver) = tokio::sync::mpsc::channel(SINK_CAPACITY);
    let handler = MsgHandler::new(endpoint.clone(), snapshot, config, sink);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{ChildEntry, ParentLink};
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
}
