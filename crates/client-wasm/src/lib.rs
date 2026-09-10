//! Cawala browser client: a wasm-bindgen wrapper around an iroh [`Endpoint`]
//! running the `cawala/ping/0` and `cawala/msg/0` accept loops, so a browser
//! tab can both answer pings and send/receive messaging envelopes as a leaf of
//! the routing tree.
//!
//! Connections go over the public N0 relay ([`iroh::endpoint::presets::N0`])
//! because browsers cannot dial UDP directly. Holding the [`Router`] in
//! [`ClientNode`] keeps the accept loop alive (dropping it would abort
//! accepts).
//!
//! Browsers are **leaves**: they accept envelopes addressed to them and never
//! forward for others. [`MsgHandler`] mirrors the native `cawala-node`
//! handler's receive-origin behavior, without any forwarding.

use std::io;
use std::sync::Mutex;

use cawala_msg::{
    Ack, AckStatus, Envelope, MsgError, MsgId, OctAddr, PeerRef, RejectReason, Seen, SeenConfig,
    SeenSet,
};
use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber_wasm::MakeConsoleWriter;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

/// WASM entry point, called once when the module is instantiated.
#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .with_writer(
            // Avoid trace events in the browser from showing their JS backtrace.
            MakeConsoleWriter::default().map_trace_level_to(tracing::Level::DEBUG),
        )
        // If we don't do this in the browser, we get a runtime error.
        .without_time()
        .with_ansi(false)
        .init();

    tracing::info!("cawala client (wasm) started");
}

/// Server side of the `cawala/ping/0` protocol: accept a connection, read one
/// framed `Ping`, reply with `Pong { seq: 1, payload }`, finish the send
/// stream, then wait for the connection to close.
///
/// Mirrors the native `cawala-node` `PingHandler` so a browser tab answers
/// pings exactly like the Rust node does.
#[derive(Debug)]
pub struct PingHandler;

impl PingHandler {
    async fn handle_connection(&self, connection: &Connection) -> Result<(), AcceptError> {
        let endpoint_id = connection.remote_id();

        // Our protocol is a simple request-response protocol, so we expect the
        // connecting peer to open a single bi-directional stream.
        let (mut send, mut recv) = connection.accept_bi().await?;

        let msg = proto::read_frame(&mut recv).await?;
        let proto::PingPong::Ping { payload } = msg else {
            return Err(AcceptError::from_err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected Ping, got {msg:?}"),
            )));
        };

        // No seq is carried in the ping, so the reply seq starts at 1.
        let seq: u64 = 0;
        let pong = proto::PingPong::Pong {
            seq: seq + 1,
            payload,
        };
        info!(%endpoint_id, seq, "replying with pong");
        proto::write_frame(&mut send, &pong).await?;

        // By calling `finish` on the send stream we signal that we will not
        // send anything further, which makes the receive stream on the other
        // end terminate.
        send.finish()?;

        // Wait until the remote closes the connection, which it does once it
        // received the response.
        connection.closed().await;
        Ok(())
    }
}

impl ProtocolHandler for PingHandler {
    /// Called for each incoming connection for our ALPN. The returned future
    /// runs on a newly spawned task, so it can run as long as the connection
    /// lasts.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let endpoint_id = connection.remote_id();
        info!(%endpoint_id, "accepted connection");
        let res = self.handle_connection(&connection).await;
        if let Err(err) = &res {
            info!(%endpoint_id, %err, "connection handler failed");
        }
        res
    }
}

/// Build a rejection [`Ack`] for `msg_id`.
fn rejected(msg_id: MsgId, reason: RejectReason) -> Ack {
    Ack {
        msg_id,
        status: AckStatus::Rejected(reason),
    }
}

/// Server side of the `cawala/msg/0` protocol for a browser leaf.
///
/// Mirrors the native `cawala-node` `MsgHandler`'s receive-origin behavior:
/// validate, de-duplicate, and deliver envelopes addressed to this leaf. It
/// never forwards for other peers, so anything not addressed here is answered
/// with [`RejectReason::NoRoute`].
#[derive(Debug)]
pub struct MsgHandler {
    self_addr: OctAddr,
    self_node: String,
    seen: Mutex<SeenSet>,
    sink: mpsc::Sender<Envelope>,
}

impl MsgHandler {
    /// Build a handler for the leaf at `self_addr`/`self_node`, delivering
    /// accepted envelopes to `sink`.
    pub fn new(self_addr: OctAddr, self_node: String, sink: mpsc::Sender<Envelope>) -> Self {
        MsgHandler {
            self_addr,
            self_node,
            seen: Mutex::new(SeenSet::new(SeenConfig::default())),
            sink,
        }
    }

    /// Validate, de-duplicate, and locally deliver one received envelope.
    ///
    /// The rules match the native handler, minus forwarding: structural
    /// validation, hop-chain shape, loop/replay defense, and a check that the
    /// last recorded hop equals the authenticated QUIC peer, then delivery to
    /// the sink if the envelope is addressed to us. A wasm leaf keeps no
    /// neighbor list, so that last-hop check is the only adjacency test.
    pub async fn handle(&self, remote: iroh::EndpointId, env: Envelope) -> Ack {
        let msg_id = env.msg_id;
        let origin = env.src.node.clone();

        // 1. Structural validation.
        if let Err(err) = env.validate() {
            let reason = match err {
                MsgError::UnsupportedVersion(_) => RejectReason::BadVersion,
                MsgError::PayloadTooLarge { .. } => RejectReason::BadPayload,
                MsgError::NodeIdTooLong { .. } => RejectReason::BadPayload,
                MsgError::BadTtl { .. } => RejectReason::TtlExpired,
                MsgError::HopChain(_) => RejectReason::BadHopChain,
                MsgError::Codec(_) => RejectReason::Internal,
            };
            return rejected(msg_id, reason);
        }

        // 2. Routing shape: the recorded path must be a plausible walk.
        if cawala_msg::validate_hop_chain(&env.src.addr, &env.dst, &env.hop_chain).is_err() {
            return rejected(msg_id, RejectReason::BadHopChain);
        }

        // 3. We must not already appear in the path we are being handed.
        if env
            .hop_chain
            .iter()
            .any(|hop| hop.addr == self.self_addr || hop.node == self.self_node)
        {
            return rejected(msg_id, RejectReason::BadHopChain);
        }

        // 4. The last hop must be the peer we are actually talking to.
        let remote_node = remote.to_string();
        match env.hop_chain.last() {
            Some(last) if last.node == remote_node => {}
            _ => return rejected(msg_id, RejectReason::NotNeighbor),
        }

        // 5. Replay: remember (origin, msg_id) and never deliver a duplicate.
        //    The guard is scoped so it is never held across an `.await`.
        let seen = {
            let mut seen = self
                .seen
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            seen.observe(&origin, env.msg_id)
        };
        if seen == Seen::Duplicate {
            return Ack {
                msg_id,
                status: AckStatus::Duplicate,
            };
        }

        // 6. Leaf delivery. Browsers never forward, so anything not addressed
        //    to us has no route from here.
        if env.dst != self.self_addr {
            return rejected(msg_id, RejectReason::NoRoute);
        }
        match self.sink.try_send(env) {
            Ok(()) => Ack {
                msg_id,
                status: AckStatus::Delivered,
            },
            Err(TrySendError::Full(_)) => {
                self.unobserve(&origin, msg_id);
                rejected(msg_id, RejectReason::Busy)
            }
            Err(TrySendError::Closed(_)) => {
                self.unobserve(&origin, msg_id);
                rejected(msg_id, RejectReason::Internal)
            }
        }
    }

    /// Roll back the replay mark for `(origin, msg_id)` after a transient
    /// delivery failure, so a retry is not spuriously reported as a duplicate.
    /// The guard is scoped to this synchronous method and never held across an
    /// `.await`.
    fn unobserve(&self, origin: &str, msg_id: MsgId) {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        seen.unobserve(origin, msg_id);
    }
}

impl ProtocolHandler for MsgHandler {
    /// Called for each incoming `cawala/msg/0` connection: read one framed
    /// [`Envelope`] from a single bi stream, handle it, and reply with the
    /// framed [`Ack`].
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        info!(%remote, "accepted msg connection");
        let (mut send, mut recv) = connection.accept_bi().await?;
        let env: Envelope =
            proto::read_framed_with_limit(&mut recv, cawala_msg::MAX_MSG_FRAME).await?;
        let ack = self.handle(remote, env).await;
        proto::write_framed(&mut send, &ack).await?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

/// A snapshot of an [`Envelope`] delivered to this browser leaf, exposed to JS.
#[wasm_bindgen]
pub struct ReceivedEnvelope {
    src_addr: String,
    src_node: String,
    dst: String,
    msg_type: u16,
    msg_id_hex: String,
    payload: Vec<u8>,
}

impl From<Envelope> for ReceivedEnvelope {
    fn from(env: Envelope) -> Self {
        ReceivedEnvelope {
            src_addr: env.src.addr.to_string(),
            src_node: env.src.node,
            dst: env.dst.to_string(),
            msg_type: env.msg_type,
            msg_id_hex: env.msg_id.to_hex(),
            payload: env.payload,
        }
    }
}

#[wasm_bindgen]
impl ReceivedEnvelope {
    /// Origin address of the envelope (`src.addr`), e.g. `"0.3.5"`.
    #[wasm_bindgen(getter)]
    pub fn src_addr(&self) -> String {
        self.src_addr.clone()
    }

    /// Origin node identity (`src.node`, an iroh endpoint id string).
    #[wasm_bindgen(getter)]
    pub fn src_node(&self) -> String {
        self.src_node.clone()
    }

    /// Destination address this envelope was addressed to.
    #[wasm_bindgen(getter)]
    pub fn dst(&self) -> String {
        self.dst.clone()
    }

    /// Application payload discriminator.
    #[wasm_bindgen(getter)]
    pub fn msg_type(&self) -> u16 {
        self.msg_type
    }

    /// Lowercase hex rendering of the message id (32 characters).
    #[wasm_bindgen(getter)]
    pub fn msg_id_hex(&self) -> String {
        self.msg_id_hex.clone()
    }

    /// Opaque payload bytes.
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
}

/// A wasm-bindgen handle to an iroh [`Endpoint`] running the `cawala/ping/0`
/// accept loop on the N0 relay preset. Holds the [`Router`]; dropping it would
/// abort the accept loop.
///
/// Clients created with [`ClientNode::spawn_with_address`] additionally accept
/// `cawala/msg/0` and expose [`ClientNode::send_envelope`] /
/// [`ClientNode::try_recv_envelope`].
#[wasm_bindgen]
pub struct ClientNode {
    router: Router,
    address: Option<String>,
    rx: Option<tokio::sync::Mutex<mpsc::Receiver<Envelope>>>,
}

#[wasm_bindgen]
impl ClientNode {
    /// Bind a new endpoint using the `cawala/ping/0` ALPN and the N0 relay
    /// preset, and start the accept loop. Returns a client that can both
    /// answer and initiate pings.
    ///
    /// This M0 client has no messaging address; use
    /// [`ClientNode::spawn_with_address`] for `cawala/msg/0`.
    pub async fn spawn() -> Result<ClientNode, JsError> {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![proto::ALPN.to_vec()])
            .bind()
            .await
            .map_err(to_js_err)?;
        let router = Router::builder(endpoint)
            .accept(proto::ALPN, PingHandler)
            .spawn();
        Ok(ClientNode {
            router,
            address: None,
            rx: None,
        })
    }

    /// Bind a new endpoint that speaks both `cawala/ping/0` and
    /// `cawala/msg/0`, registering this leaf under `self_addr`.
    ///
    /// The N0 relay preset is still required (browsers need relays). Envelopes
    /// accepted for `self_addr` are queued for [`ClientNode::try_recv_envelope`].
    pub async fn spawn_with_address(self_addr: String) -> Result<ClientNode, JsError> {
        let addr: OctAddr = self_addr.parse().map_err(to_js_err)?;
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![proto::ALPN.to_vec(), cawala_msg::ALPN.to_vec()])
            .bind()
            .await
            .map_err(to_js_err)?;
        let self_node = endpoint.id().to_string();
        // Bounded, so a slow consumer applies backpressure via `Busy` acks
        // rather than growing without limit.
        let (sink, rx) = mpsc::channel(32);
        let router = Router::builder(endpoint)
            .accept(proto::ALPN, PingHandler)
            .accept(cawala_msg::ALPN, MsgHandler::new(addr, self_node, sink))
            .spawn();
        Ok(ClientNode {
            router,
            address: Some(self_addr),
            rx: Some(tokio::sync::Mutex::new(rx)),
        })
    }

    /// This client's endpoint id (node public key), as a string. Give this to
    /// other peers so they can connect to you.
    pub fn endpoint_id(&self) -> String {
        self.router.endpoint().id().to_string()
    }

    /// This client's messaging address, or `None` for a ping-only client.
    pub fn address(&self) -> Option<String> {
        self.address.clone()
    }

    /// Send one framed [`Envelope`] to a direct neighbor (the leaf node) and
    /// return the acknowledgement status: `"delivered"`, `"duplicate"`, or
    /// `"rejected"`.
    ///
    /// The envelope's source is this client's address/node, `dst` is the final
    /// destination address, and `msg_id`/`nonce` are freshly random. The
    /// connection is dialed on `cawala_msg::ALPN`; the remote address is
    /// resolved through the endpoint's address lookup services, as with
    /// [`ClientNode::ping`].
    pub async fn send_envelope(
        &self,
        next_hop: String,
        dst: String,
        msg_type: u16,
        payload: Vec<u8>,
    ) -> Result<String, JsError> {
        let self_addr: OctAddr = self
            .address
            .as_deref()
            .ok_or_else(|| JsError::new("client has no messaging address; use spawn_with_address"))?
            .parse()
            .map_err(to_js_err)?;
        let dst: OctAddr = dst.parse().map_err(to_js_err)?;
        let next_hop: iroh::EndpointId = next_hop.parse().map_err(to_js_err)?;

        let mut id_bytes = [0u8; MsgId::LEN];
        getrandom::fill(&mut id_bytes).map_err(to_js_err)?;
        let mut nonce_bytes = [0u8; 8];
        getrandom::fill(&mut nonce_bytes).map_err(to_js_err)?;

        let src = PeerRef {
            addr: self_addr,
            node: self.router.endpoint().id().to_string(),
        };
        let env = Envelope::new(
            src,
            dst,
            MsgId::from_bytes(id_bytes),
            msg_type,
            u64::from_le_bytes(nonce_bytes),
            payload,
        );

        let ack = n0_future::time::timeout(n0_future::time::Duration::from_secs(10), async {
            let connection = self
                .router
                .endpoint()
                .connect(next_hop, cawala_msg::ALPN)
                .await
                .map_err(to_js_err)?;
            let (mut send, mut recv) = connection.open_bi().await.map_err(to_js_err)?;
            proto::write_framed(&mut send, &env)
                .await
                .map_err(to_js_err)?;
            send.finish().map_err(to_js_err)?;

            let ack: Ack = proto::read_framed_with_limit(&mut recv, cawala_msg::MAX_MSG_FRAME)
                .await
                .map_err(to_js_err)?;

            // We received the last data, so we close the connection.
            connection.close(1u8.into(), b"done");

            Ok::<Ack, JsError>(ack)
        })
        .await
        .map_err(|_| JsError::new("send_envelope timed out waiting for ack"))??;

        Ok(ack.status_str().to_string())
    }

    /// Non-blocking receive of the next envelope delivered to this leaf.
    ///
    /// Returns `Ok(None)` when the queue is empty (or this is a ping-only
    /// client), or an error if the queue is currently busy elsewhere.
    pub fn try_recv_envelope(&self) -> Result<Option<ReceivedEnvelope>, JsError> {
        let Some(rx) = &self.rx else {
            return Ok(None);
        };
        let mut rx = rx.try_lock().map_err(to_js_err)?;
        match rx.try_recv() {
            Ok(env) => Ok(Some(ReceivedEnvelope::from(env))),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => Ok(None),
        }
    }

    /// Send one framed `Ping` with the given UTF-8 payload to `endpoint_id`
    /// and return the `Pong` payload as a (lossy) UTF-8 string.
    ///
    /// The remote address is resolved through the endpoint's configured
    /// address lookup services (pkarr/DNS with the `N0` preset). If that is
    /// unavailable (blocked or flaky in some browsers/sandboxes), the connect
    /// falls back to routing through this endpoint's own home relay — browser
    /// tabs on the same network share the N0 relay, so the peer is reachable
    /// there.
    pub async fn ping(&self, endpoint_id: String, payload: String) -> Result<String, JsError> {
        let endpoint_id: iroh::EndpointId = endpoint_id.parse().map_err(to_js_err)?;
        let endpoint = self.router.endpoint();

        let connection = match endpoint.connect(endpoint_id, proto::ALPN).await {
            Ok(conn) => conn,
            Err(first_err) => match self.connect_via_local_relay(endpoint, endpoint_id).await {
                Ok(conn) => conn,
                Err(_) => return Err(to_js_err(first_err)),
            },
        };
        let (mut send, mut recv) = connection.open_bi().await.map_err(to_js_err)?;

        proto::write_frame(
            &mut send,
            &proto::PingPong::Ping {
                payload: payload.as_bytes().to_vec(),
            },
        )
        .await
        .map_err(to_js_err)?;

        let pong = proto::read_frame(&mut recv).await.map_err(to_js_err)?;

        // We received the last data, so we close the connection.
        connection.close(1u8.into(), b"done");

        match pong {
            proto::PingPong::Pong { seq, payload } => {
                tracing::info!(seq, len = payload.len(), "received pong");
                Ok(String::from_utf8_lossy(&payload).into_owned())
            }
            proto::PingPong::Ping { .. } => Err(JsError::new("expected Pong, got Ping")),
        }
    }

    /// Connect to `endpoint_id` via this endpoint's own home relay, without
    /// relying on address lookup services.
    async fn connect_via_local_relay(
        &self,
        endpoint: &iroh::Endpoint,
        endpoint_id: iroh::EndpointId,
    ) -> Result<iroh::endpoint::Connection, JsError> {
        // Ensure we are registered on a relay before reading our address.
        endpoint.online().await;
        let relays: Vec<iroh::RelayUrl> = endpoint.addr().relay_urls().cloned().collect();
        if relays.is_empty() {
            return Err(JsError::new("endpoint has no relay address"));
        }
        let addr = iroh::EndpointAddr::from_parts(
            endpoint_id,
            relays.into_iter().map(iroh::TransportAddr::Relay),
        );
        tracing::info!(%endpoint_id, ?addr, "connecting via local relay fallback");
        endpoint.connect(addr, proto::ALPN).await.map_err(to_js_err)
    }
}

fn to_js_err(err: impl std::fmt::Display) -> JsError {
    JsError::new(&err.to_string())
}
