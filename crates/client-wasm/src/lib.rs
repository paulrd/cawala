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
//!
//! [`ClientNode::spawn_control`] additionally binds a **stable** control
//! identity and speaks `cawala/control/0`: it can send a `Join` and receive the
//! reverse-dialed `JoinApproved`/`JoinRejected`, exposing the handshake state
//! as [`JoinStatus`]/[`SnapshotDto`]/[`ControlEventDto`]. See [`state`] for the
//! pure, native-testable state machine.

use std::io;
use std::sync::{Arc, Mutex};

use cawala_control::{
    CONTROL_ALPN, ChildKind, ControlReply, ControlRequest, Invite, JoinRequest, NodeId,
    OperatorSecretKey, SignedControl,
};
use cawala_msg::{
    Ack, AckStatus, Envelope, MsgError, MsgId, OctAddr, PeerRef, RejectReason, Seen, SeenConfig,
    SeenSet,
};
use iroh::{EndpointAddr, EndpointId};
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

mod control;
pub mod dto;
pub mod state;

use crate::control::{
    ControlHandler, JOIN_TTL_SECONDS, SharedControl, exchange_control, invite_endpoint_addr,
};
use crate::dto::{
    ControlEventDto, JoinOutcome, JoinStatus, SnapshotDto, parse_operator_hex, reject_code_str,
};
use crate::state::LocalStateV1;

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

/// Generate a fresh 32-byte Ed25519 secret seed for a stable control identity.
///
/// Persist these bytes in the PWA (e.g. IndexedDB) and hand them back to
/// [`ClientNode::spawn_control`] so the browser keeps the same endpoint id and
/// operator key across reloads.
#[wasm_bindgen]
pub fn generate_secret_key() -> Result<Vec<u8>, JsError> {
    let mut bytes = vec![0u8; 32];
    getrandom::fill(&mut bytes).map_err(to_js_err)?;
    Ok(bytes)
}

/// Current time as unix seconds, via [`web_time::SystemTime`] so it works on
/// `wasm32-unknown-unknown` as well as natively.
fn now_unix_seconds() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
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
    control: Arc<SharedControl>,
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
        let control = Arc::new(SharedControl::new(endpoint.id().to_string(), None));
        let router = Router::builder(endpoint)
            .accept(proto::ALPN, PingHandler)
            .spawn();
        Ok(ClientNode {
            router,
            address: None,
            rx: None,
            control,
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
        let control = Arc::new(SharedControl::new(self_node.clone(), None));
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
            control,
        })
    }

    /// Bind a new endpoint with a **stable** identity derived from a 32-byte
    /// Ed25519 `secret_key`, speaking `cawala/ping/0` and
    /// `cawala/control/0` over the N0 relay preset.
    ///
    /// The same seed always yields the same endpoint id *and* operator public
    /// key, so the PWA can keep a durable identity across reloads by persisting
    /// the bytes from [`generate_secret_key`]. The control ALPN accept loop is
    /// registered here so the parent's `JoinApproved`/`JoinRejected` can be
    /// received by reverse dial.
    pub async fn spawn_control(secret_key: &[u8]) -> Result<ClientNode, JsError> {
        let seed: [u8; 32] = secret_key
            .try_into()
            .map_err(|_| JsError::new("secret key must be exactly 32 bytes"))?;
        let secret = iroh::SecretKey::from_bytes(&seed);
        // The operator key is the same Ed25519 key as the iroh endpoint id, as
        // in the native node (`OperatorSecretKey::from_bytes(sk.to_bytes())`).
        let operator = OperatorSecretKey::from_bytes(secret.to_bytes());
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret)
            .alpns(vec![proto::ALPN.to_vec(), CONTROL_ALPN.to_vec()])
            .bind()
            .await
            .map_err(to_js_err)?;
        let control = Arc::new(SharedControl::new(
            endpoint.id().to_string(),
            Some(operator),
        ));
        let router = Router::builder(endpoint)
            .accept(proto::ALPN, PingHandler)
            .accept(CONTROL_ALPN, ControlHandler::new(Arc::clone(&control)))
            .spawn();
        Ok(ClientNode {
            router,
            address: None,
            rx: None,
            control,
        })
    }

    /// This client's endpoint id (node public key), as a string. Give this to
    /// other peers so they can connect to you.
    pub fn endpoint_id(&self) -> String {
        self.router.endpoint().id().to_string()
    }

    /// This client's operator public key as 64 lowercase hex characters.
    ///
    /// The control identity derives the operator key from the same Ed25519 seed
    /// as the endpoint, so this always equals [`ClientNode::endpoint_id`].
    pub fn operator_public_key(&self) -> String {
        self.router.endpoint().id().to_string()
    }

    /// Parse and validate an invite, then send a `Join` to its parent,
    /// pinning the invite's operator key.
    ///
    /// The request is always a `ChildKind::User` join with no ledger key. The
    /// immediate reply carries the outcome; an eventual `JoinApproved` or
    /// `JoinRejected` arrives later through the control accept loop and is
    /// surfaced by [`ClientNode::join_status`] /
    /// [`ClientNode::try_recv_control_event`].
    pub async fn join_via_invite(&self, uri: &str) -> Result<JoinOutcome, JsError> {
        let invite = Invite::parse(uri).map_err(to_js_err)?;
        invite.validate().map_err(to_js_err)?;
        let now = now_unix_seconds();
        if let Some(expiry) = invite.expiry
            && now > expiry
        {
            return Err(JsError::new("invite has expired"));
        }
        let target = invite_endpoint_addr(&invite)?;
        self.join_inner(
            invite.parent.clone(),
            invite.slot,
            invite.expiry,
            Some(invite.operator),
            target,
        )
        .await
    }

    /// Send a `Join` to `parent` (an endpoint-id string), optionally requesting
    /// `slot`, expiring at `expiry` (unix seconds; defaults to one hour), and
    /// pinning `pinned_operator_hex` (64 hex characters) when known.
    ///
    /// This is the unpinned/direct path used when no invite is available;
    /// [`ClientNode::join_via_invite`] wraps it with invite parsing and
    /// transport hints.
    pub async fn join(
        &self,
        parent: String,
        slot: Option<u8>,
        expiry: Option<f64>,
        pinned_operator_hex: Option<String>,
    ) -> Result<JoinOutcome, JsError> {
        let parent = NodeId::from(parent);
        let endpoint_id: EndpointId = parent.as_str().parse().map_err(to_js_err)?;
        let pinned_operator = match pinned_operator_hex {
            Some(hex) => Some(parse_operator_hex(&hex).map_err(to_js_err)?),
            None => None,
        };
        self.join_inner(
            parent,
            slot,
            expiry.map(|secs| secs as u64),
            pinned_operator,
            EndpointAddr::from(endpoint_id),
        )
        .await
    }

    /// Shared implementation for [`ClientNode::join`] and
    /// [`ClientNode::join_via_invite`].
    async fn join_inner(
        &self,
        parent: NodeId,
        desired_slot: Option<u8>,
        expiry: Option<u64>,
        pinned_operator: Option<cawala_control::OperatorPubKey>,
        target: EndpointAddr,
    ) -> Result<JoinOutcome, JsError> {
        let operator = self
            .control
            .operator
            .clone()
            .ok_or_else(|| JsError::new("client has no control identity; use spawn_control"))?;
        let node_id = self.control.node_id().to_string();
        let me = NodeId::from(node_id);

        let now = now_unix_seconds();
        let expiry = expiry.unwrap_or_else(|| now.saturating_add(JOIN_TTL_SECONDS));
        if now > expiry {
            return Err(JsError::new("join request has expired"));
        }

        let mut nonce_bytes = [0u8; 8];
        getrandom::fill(&mut nonce_bytes).map_err(to_js_err)?;
        let request = JoinRequest {
            node: me.clone(),
            kind: ChildKind::User,
            operator: operator.public(),
            // A browser is always a leaf user: never a node, never a ledger key.
            ledger: None,
            desired_slot,
            location_hint: None,
            nonce: u64::from_le_bytes(nonce_bytes),
            expiry,
        };
        request.validate().map_err(to_js_err)?;

        // Persist the outbound join *before* dialing so a reverse-dialed reply
        // racing the exchange can still be matched.
        self.control.lock_state().set_outbound(
            request.clone(),
            parent.clone(),
            pinned_operator,
            now,
        );

        let signed = SignedControl::authorize(me, &operator, ControlRequest::Join(request))
            .map_err(to_js_err)?;
        let reply = exchange_control(self.router.endpoint(), target, &signed).await?;

        match reply {
            ControlReply::Pending | ControlReply::Accepted => Ok(JoinOutcome::pending()),
            ControlReply::Rejected(code) => {
                let code_str = reject_code_str(code).to_string();
                self.control.lock_state().reject_outbound(&code_str, None);
                self.control
                    .push_event(ControlEventDto::rejected(&parent, None));
                Ok(JoinOutcome::rejected(Some(code_str), None))
            }
            ControlReply::Snapshot(_) => {
                Err(JsError::new("unexpected snapshot reply to a join request"))
            }
        }
    }

    /// A local summary of the join handshake state.
    pub fn join_status(&self) -> JoinStatus {
        JoinStatus::from_state(&self.control.lock_state())
    }

    /// A snapshot of this client's local topology (address, parent, children).
    pub fn local_snapshot(&self) -> SnapshotDto {
        SnapshotDto::from_state(self.control.node_id(), &self.control.lock_state())
    }

    /// Export the local state as postcard bytes.
    ///
    /// The blob contains the outbound join, topology record, and last
    /// rejection; it contains **no secret key material**, so it is safe to
    /// persist in browser storage.
    pub fn export_state(&self) -> Vec<u8> {
        self.control.lock_state().to_bytes()
    }

    /// Replace the local state from bytes previously produced by
    /// [`ClientNode::export_state`].
    pub fn import_state(&self, bytes: &[u8]) -> Result<(), JsError> {
        let state = LocalStateV1::from_bytes(bytes).map_err(to_js_err)?;
        *self.control.lock_state() = state;
        Ok(())
    }

    /// Non-blocking drain of the next queued control event.
    ///
    /// Returns `None` when the queue is empty.
    pub fn try_recv_control_event(&self) -> Option<ControlEventDto> {
        self.control.lock_events().pop_front()
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

pub(crate) fn to_js_err(err: impl std::fmt::Display) -> JsError {
    JsError::new(&err.to_string())
}
