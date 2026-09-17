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
    AdminJoinApprove, AdminJoinReject, AdminRedeliverJoin, CONTROL_ALPN, CONTROL_REQUEST_TTL_SECS,
    ChildKind, ControlReply, ControlRequest, ExitRequest, Invite, JoinRequest, NodeId,
    OperatorSecretKey, RejectCode, SignedControl,
};
use cawala_msg::{
    Ack, AckStatus, BalanceQueryV1, Envelope, LedgerPayloadV1, LedgerPayloadV2, LedgerPayloadV3,
    MSG_LEDGER_V1, MsgError, MsgId, OctAddr, OrderV2, PeerRef, RejectReason, Seen, SeenConfig,
    SeenSet, VersionedLedgerPayload, decode_versioned,
};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{EndpointAddr, EndpointId};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber_wasm::MakeConsoleWriter;
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

mod control;
pub mod dto;
pub mod ledger_state;
pub mod state;

use crate::control::{
    ControlHandler, JOIN_TTL_SECONDS, ROUTED_REPLY_TIMEOUT_SECS, SharedControl,
    build_routed_control, exchange_admin, exchange_control, invite_endpoint_addr,
    routed_request_envelope, should_try_routed, sign_admin_request, verify_routed_reply_bytes,
};
use crate::dto::{
    AdminActionDto, AdminSnapshotDto, ControlEventDto, JoinOutcome, JoinStatus, LeaveOutcome,
    LedgerEventDto, LedgerStatusDto, PaymentOutcome, SnapshotDto, parse_operator_hex,
    reject_code_str,
};
use crate::ledger_state::LedgerStateV1;
use crate::state::{LocalStateV1, ParentLink, Transition};

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
pub(crate) fn now_unix_seconds() -> u64 {
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

/// Where a browser leaf's current asserted address comes from.
///
/// [`ClientNode::spawn_with_address`] supplies a fixed address, but a control
/// client is assigned one only after `JoinApproved`. Because
/// [`RouterBuilder::spawn`](iroh::protocol::RouterBuilder::spawn) fixes the
/// advertised ALPNs at spawn time, the handler is registered up front and reads
/// the live address from [`SharedControl`] instead.
enum AddressSource {
    /// A fixed address supplied by `spawn_with_address`.
    Fixed(OctAddr),
    /// The live address in the control client's [`LocalStateV1`].
    Shared(Arc<SharedControl>),
}

impl std::fmt::Debug for AddressSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressSource::Fixed(addr) => f.debug_tuple("Fixed").field(addr).finish(),
            AddressSource::Shared(_) => f.write_str("Shared(..)"),
        }
    }
}

/// Which origins a handler accepts for delivery.
enum ParentRule {
    /// No origin restriction (the fixed-address client knows no parent).
    Unrestricted,
    /// Only envelopes whose `src.node` equals the recorded parent. `None` means
    /// an address exists but no parent does, so every sender is refused.
    Required(Option<String>),
}

/// Result of queueing one accepted envelope for delivery.
///
/// A dedicated enum keeps the oversized [`Envelope`] out of the error variant
/// (clippy's `result_large_err`); the variants map one-to-one onto
/// [`TrySendError`].
enum DeliveryOutcome {
    /// Queued successfully.
    Delivered,
    /// The target queue is full; report `Busy`.
    Full,
    /// The target queue is closed; report `Internal`.
    Closed,
}

/// Server side of the `cawala/msg/0` protocol for a browser leaf.
///
/// Mirrors the native `cawala-node` `MsgHandler`'s receive-origin behavior:
/// validate, de-duplicate, and deliver envelopes addressed to this leaf. It
/// never forwards for other peers, so anything not addressed here is answered
/// with [`RejectReason::NoRoute`].
pub struct MsgHandler {
    source: AddressSource,
    self_node: String,
    seen: Mutex<SeenSet>,
    sink: mpsc::Sender<Envelope>,
    /// Dedicated delivery queue for `MSG_CONTROL_V1` envelopes.
    ///
    /// A control client owns this queue's receiver and awaits correlated
    /// routed replies on it, so routed replies never mix into the general
    /// [`ClientNode::try_recv_envelope`] drain that JS reads. `None` for a
    /// fixed-address leaf, which cannot originate routed control and so keeps
    /// delivering every message type to `sink`.
    control: Option<mpsc::Sender<Envelope>>,
}

impl std::fmt::Debug for MsgHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsgHandler")
            .field("source", &self.source)
            .field("self_node", &self.self_node)
            .finish_non_exhaustive()
    }
}

impl MsgHandler {
    /// Build a handler for the leaf at the fixed `self_addr`/`self_node`,
    /// delivering accepted envelopes to `sink`.
    ///
    /// A fixed-address leaf has no control identity and cannot originate a
    /// routed request, so it has no control-reply queue: every delivered
    /// envelope (including any `MSG_CONTROL_V1`) goes to `sink`, preserving the
    /// pre-split behavior.
    pub fn new(self_addr: OctAddr, self_node: String, sink: mpsc::Sender<Envelope>) -> Self {
        MsgHandler {
            source: AddressSource::Fixed(self_addr),
            self_node,
            seen: Mutex::new(SeenSet::new(SeenConfig::default())),
            sink,
            control: None,
        }
    }

    /// Build a handler whose asserted address and accepted parent are read live
    /// from `shared`, for a control client that learns its address only after
    /// `JoinApproved`.
    ///
    /// `control_sink` receives `MSG_CONTROL_V1` envelopes (routed replies);
    /// everything else goes to `sink`.
    pub(crate) fn for_shared(
        shared: Arc<SharedControl>,
        self_node: String,
        sink: mpsc::Sender<Envelope>,
        control_sink: mpsc::Sender<Envelope>,
    ) -> Self {
        MsgHandler {
            source: AddressSource::Shared(shared),
            self_node,
            seen: Mutex::new(SeenSet::new(SeenConfig::default())),
            sink,
            control: Some(control_sink),
        }
    }

    /// This leaf's current asserted address, if any.
    fn current_address(&self) -> Option<OctAddr> {
        match &self.source {
            AddressSource::Fixed(addr) => Some(addr.clone()),
            AddressSource::Shared(shared) => shared.lock_state().record.address.clone(),
        }
    }

    /// The origin restriction for this handler.
    fn parent_rule(&self) -> ParentRule {
        match &self.source {
            AddressSource::Fixed(_) => ParentRule::Unrestricted,
            AddressSource::Shared(shared) => {
                let parent = shared
                    .lock_state()
                    .record
                    .parent
                    .as_ref()
                    .map(|link| link.node_id.as_str().to_string());
                ParentRule::Required(parent)
            }
        }
    }

    /// Validate, de-duplicate, and locally deliver one received envelope.
    ///
    /// The rules match the native handler, minus forwarding: structural
    /// validation, hop-chain shape, loop/replay defense, a check that the last
    /// recorded hop equals the authenticated QUIC peer, and (for a control
    /// leaf) that the origin is the parent it joined, then delivery to the sink
    /// if the envelope is addressed to us. A wasm leaf keeps no neighbor list,
    /// so that last-hop check is the only adjacency test.
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
                MsgError::InvalidEntryProof(_) => RejectReason::BadPayload,
            };
            return rejected(msg_id, reason);
        }

        // 2. We must have been assigned an address (a control client learns one
        //    only after `JoinApproved`).
        let Some(self_addr) = self.current_address() else {
            return rejected(msg_id, RejectReason::NoAddress);
        };

        // 3. Leaf delivery. Browsers never forward, so anything not addressed
        //    to us has no route from here.
        if env.dst != self_addr {
            return rejected(msg_id, RejectReason::NoRoute);
        }

        // 4. Routing shape: the recorded path must be a plausible walk.
        if cawala_msg::validate_hop_chain(&env.src.addr, &env.dst, &env.hop_chain).is_err() {
            return rejected(msg_id, RejectReason::BadHopChain);
        }

        // 5. We must not already appear in the path we are being handed.
        if env
            .hop_chain
            .iter()
            .any(|hop| hop.addr == self_addr || hop.node == self.self_node)
        {
            return rejected(msg_id, RejectReason::BadHopChain);
        }

        // 6. The last hop must be the peer we are actually talking to.
        let remote_node = remote.to_string();
        match env.hop_chain.last() {
            Some(last) if last.node == remote_node => {}
            _ => return rejected(msg_id, RejectReason::NotNeighbor),
        }

        // 7. A control leaf only accepts envelopes originated by the parent it
        //    joined; the routing leaf is the sole legitimate sender.
        //
        //    `MSG_CONTROL_V1` is the one exemption: a routed control reply
        //    travels back down the tree from the target node, so its `src` is
        //    an ancestor of this leaf, not the joined parent. Accepting it from
        //    any non-parent origin is safe because (a) the payload is an
        //    end-to-end operator-signed `SignedRoutedReply` under a signing
        //    domain that can never be replayed as a control request or an admin
        //    grant, and (b) the waiter correlates it by `reply_to` against a
        //    request this leaf just sent and verifies the responder key before
        //    surfacing it. An unsolicited control envelope therefore cannot
        //    change any state; it is simply dropped by the waiter. Every other
        //    check below (dst == self, hop-chain shape, self-not-in-chain,
        //    last-hop == authenticated remote) still applies unchanged.
        if env.msg_type != cawala_msg::MSG_CONTROL_V1 {
            match self.parent_rule() {
                ParentRule::Unrestricted => {}
                ParentRule::Required(Some(parent)) if env.src.node == parent => {}
                ParentRule::Required(_) => return rejected(msg_id, RejectReason::NotNeighbor),
            }
        }

        // 8. Replay: remember (origin, msg_id) and never deliver a duplicate.
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

        match self.deliver(env) {
            DeliveryOutcome::Delivered => Ack {
                msg_id,
                status: AckStatus::Delivered,
            },
            DeliveryOutcome::Full => {
                self.unobserve(&origin, msg_id);
                rejected(msg_id, RejectReason::Busy)
            }
            DeliveryOutcome::Closed => {
                self.unobserve(&origin, msg_id);
                rejected(msg_id, RejectReason::Internal)
            }
        }
    }

    /// Queue one accepted envelope on its delivery channel.
    ///
    /// `MSG_CONTROL_V1` goes to the dedicated control queue when one exists,
    /// so routed replies do not pollute the JS envelope/ledger drain;
    /// everything else (and every message on a fixed-address leaf) goes to the
    /// general sink.
    fn deliver(&self, env: Envelope) -> DeliveryOutcome {
        let channel = if env.msg_type == cawala_msg::MSG_CONTROL_V1 {
            self.control.as_ref().unwrap_or(&self.sink)
        } else {
            &self.sink
        };
        match channel.try_send(env) {
            Ok(()) => DeliveryOutcome::Delivered,
            Err(TrySendError::Full(_)) => DeliveryOutcome::Full,
            Err(TrySendError::Closed(_)) => DeliveryOutcome::Closed,
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
    /// Receiver for `MSG_CONTROL_V1` envelopes split out by [`MsgHandler`].
    ///
    /// Held here (not in [`SharedControl`]) so the async routed request can
    /// await a correlated reply without stealing ledger envelopes via
    /// [`ClientNode::try_recv_envelope`]. `None` for clients with no control
    /// identity.
    control_rx: Option<tokio::sync::Mutex<mpsc::Receiver<Envelope>>>,
    control: Arc<SharedControl>,
    /// The leaf ledger state.
    ///
    /// Shared with the inbound [`ControlHandler`] so a verified `JoinApproval`
    /// can re-pin the parent ledger synchronously, before any balance request
    /// races the stale pin.
    ledger: Arc<Mutex<LedgerStateV1>>,
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
            control_rx: None,
            control,
            ledger: Arc::new(Mutex::new(LedgerStateV1::new())),
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
            control_rx: None,
            control,
            ledger: Arc::new(Mutex::new(LedgerStateV1::new())),
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
            .alpns(vec![
                proto::ALPN.to_vec(),
                CONTROL_ALPN.to_vec(),
                cawala_msg::ALPN.to_vec(),
            ])
            .bind()
            .await
            .map_err(to_js_err)?;
        let self_node = endpoint.id().to_string();
        let control = Arc::new(SharedControl::new(self_node.clone(), Some(operator)));
        // Bounded, so a slow consumer applies backpressure via `Busy` acks
        // rather than growing without limit. The handler reads the assigned
        // address live from `control`, which is empty until `JoinApproved`.
        let (sink, rx) = mpsc::channel(32);
        // Routed control replies are split onto their own queue so the JS
        // envelope/ledger drain ([`ClientNode::try_recv_envelope`]) sees only
        // application traffic.
        let (control_sink, control_rx) = mpsc::channel(32);
        // Shared with the control handler so a verified `JoinApproval` can
        // re-pin the parent ledger synchronously.
        let ledger: Arc<Mutex<LedgerStateV1>> = Arc::new(Mutex::new(LedgerStateV1::new()));
        let router = Router::builder(endpoint)
            .accept(proto::ALPN, PingHandler)
            .accept(
                CONTROL_ALPN,
                ControlHandler::new(Arc::clone(&control), Arc::clone(&ledger)),
            )
            .accept(
                cawala_msg::ALPN,
                MsgHandler::for_shared(Arc::clone(&control), self_node, sink, control_sink),
            )
            .spawn();
        Ok(ClientNode {
            router,
            address: None,
            rx: Some(tokio::sync::Mutex::new(rx)),
            control_rx: Some(tokio::sync::Mutex::new(control_rx)),
            control,
            ledger,
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

        let mut signed_nonce = [0u8; 8];
        getrandom::fill(&mut signed_nonce).map_err(to_js_err)?;
        let signed = SignedControl::authorize(
            me,
            &operator,
            u64::from_le_bytes(signed_nonce),
            now.saturating_add(CONTROL_REQUEST_TTL_SECS),
            ControlRequest::Join(request),
        )
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
            _ => Err(JsError::new("unexpected reply to a join request")),
        }
    }

    /// A local summary of the join handshake state.
    pub fn join_status(&self) -> JoinStatus {
        JoinStatus::from_state(&self.control.lock_state())
    }

    /// Leave the current parent: sign an [`ExitRequest`], best-effort deliver
    /// it to the parent over `cawala/control/0`, then clear the local parent
    /// and address **regardless of the reply**.
    ///
    /// Requires a joined state (an assigned address and a parent link). A
    /// browser is a `User` leaf, so leaving clears both links (there is no
    /// meaningful root `0` leaf). The parent notice is best-effort and
    /// eventual-convergence: even when the send fails, times out, or the parent
    /// refuses, the local state is cleared and the caller gets
    /// `status == "detached"`, so an unreachable parent cannot trap the user.
    /// `subtree_nodes` is `1` — audit-only, and a browser leaf has no children.
    ///
    /// A `"detached"` [`ControlEventDto`] is queued for
    /// [`ClientNode::try_recv_control_event`] so the UI can react. The returned
    /// `delivery` reports the former parent's reply bucket and is diagnostic
    /// only.
    pub async fn leave(&self) -> Result<LeaveOutcome, JsError> {
        let operator = self
            .control
            .operator
            .clone()
            .ok_or_else(|| JsError::new("client has no control identity; use spawn_control"))?;
        // Require a joined state up front: leaving an unjoined client is a
        // caller error, not a silent no-op.
        let (_self_addr, parent) = self.joined_context()?;
        let me = NodeId::from(self.control.node_id().to_string());

        let mut nonce_bytes = [0u8; 8];
        getrandom::fill(&mut nonce_bytes).map_err(to_js_err)?;
        let signed = SignedControl::authorize(
            me.clone(),
            &operator,
            u64::from_le_bytes(nonce_bytes),
            now_unix_seconds().saturating_add(CONTROL_REQUEST_TTL_SECS),
            ControlRequest::Exit(ExitRequest {
                node: me,
                subtree_nodes: 1,
            }),
        )
        .map_err(to_js_err)?;

        // Best-effort: the parent may be gone. Dialing uses an id-only
        // `EndpointAddr`, exactly like the join path, and reuses the shared
        // `exchange_control` deadline.
        let target: EndpointId = parent.node_id.as_str().parse().map_err(to_js_err)?;
        let delivery =
            match exchange_control(self.router.endpoint(), EndpointAddr::from(target), &signed).await
            {
                Ok(reply) => leave_delivery(&reply),
                Err(_) => "unreachable".to_string(),
            };

        // Clear locally no matter what the parent said (or if it never
        // answered), so a failed parent cannot trap the user.
        let transition = self.control.lock_state().apply_detach();
        if matches!(transition, Transition::Detached) {
            // The balance claim belongs to the leaf we just left: drop the pin
            // and parent-scoped balance/pending before surfacing the event, so a
            // subsequent store sync cannot resurrect it.
            self.ledger
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear_parent_binding();
            self.control
                .push_event(ControlEventDto::detached(&parent.node_id));
        }
        Ok(LeaveOutcome::new(delivery))
    }

    /// Install a delegated admin key (K_admin) used by the `admin_*` methods.
    ///
    /// `secret_key` must be exactly 32 bytes (an Ed25519 seed). The key is held
    /// in memory only: it is **never** persisted on the Rust side and never
    /// enters [`ClientNode::export_state`]/[`ClientNode::export_ledger_state`].
    /// The PWA owns its storage.
    pub fn set_admin_key(&self, secret_key: &[u8]) -> Result<(), JsError> {
        let seed: [u8; 32] = secret_key
            .try_into()
            .map_err(|_| JsError::new("admin key must be exactly 32 bytes"))?;
        self.control
            .set_admin(Some(OperatorSecretKey::from_bytes(seed)));
        Ok(())
    }

    /// Forget the delegated admin key, if any.
    pub fn clear_admin_key(&self) {
        self.control.set_admin(None);
    }

    /// The configured admin public key as 64 lowercase hex characters, or
    /// `None` when no admin key is set.
    pub fn admin_public_key(&self) -> Option<String> {
        self.control.admin_key().map(|key| key.public().to_string())
    }

    /// Query `node`'s admin snapshot (its topology plus pending joins).
    ///
    /// `node` is the target's endpoint id. Requires a configured admin key.
    /// When `node_addr` is `None` the node is dialed directly over
    /// `cawala/control/0`; when it is `Some`, a failed direct dial (transport
    /// error only) is retried over the routed tree using `node_addr` as the
    /// target's asserted address.
    pub async fn admin_query(
        &self,
        node: String,
        node_addr: Option<String>,
    ) -> Result<AdminSnapshotDto, JsError> {
        let reply = self
            .admin_exchange(&node, ControlRequest::AdminQuery, node_addr)
            .await?;
        match reply {
            ControlReply::AdminSnapshot(snapshot) => Ok(AdminSnapshotDto::from_snapshot(&snapshot)),
            ControlReply::Rejected(code) => Err(admin_rejected(code)),
            _ => Err(unexpected_admin_reply("an admin query")),
        }
    }

    /// Approve `child`'s pending join at `node`, optionally assigning `slot`.
    ///
    /// `node_addr` optionally names `node`'s asserted address for the routed
    /// fallback; see [`ClientNode::admin_query`].
    pub async fn admin_approve_join(
        &self,
        node: String,
        child: String,
        slot: Option<u8>,
        node_addr: Option<String>,
    ) -> Result<AdminActionDto, JsError> {
        let child = parse_child(&child)?;
        let request = ControlRequest::AdminApproveJoin(AdminJoinApprove { child, slot });
        let reply = self.admin_exchange(&node, request, node_addr).await?;
        match reply {
            ControlReply::AdminApproved(approved) => Ok(AdminActionDto::from_approved(&approved)),
            ControlReply::AdminRejected(rejected) => Ok(AdminActionDto::from_rejected(&rejected)),
            ControlReply::Rejected(code) => Err(admin_rejected(code)),
            _ => Err(unexpected_admin_reply("an admin approval")),
        }
    }

    /// Reject `child`'s pending join at `node`, optionally carrying `reason`.
    ///
    /// `node_addr` optionally names `node`'s asserted address for the routed
    /// fallback; see [`ClientNode::admin_query`].
    pub async fn admin_reject_join(
        &self,
        node: String,
        child: String,
        reason: Option<String>,
        node_addr: Option<String>,
    ) -> Result<AdminActionDto, JsError> {
        let child = parse_child(&child)?;
        let request = ControlRequest::AdminRejectJoin(AdminJoinReject { child, reason });
        let reply = self.admin_exchange(&node, request, node_addr).await?;
        match reply {
            ControlReply::AdminApproved(approved) => Ok(AdminActionDto::from_approved(&approved)),
            ControlReply::AdminRejected(rejected) => Ok(AdminActionDto::from_rejected(&rejected)),
            ControlReply::Rejected(code) => Err(admin_rejected(code)),
            _ => Err(unexpected_admin_reply("an admin rejection")),
        }
    }

    /// Re-send `child`'s most recent stored decision from `node`.
    ///
    /// `node_addr` optionally names `node`'s asserted address for the routed
    /// fallback; see [`ClientNode::admin_query`].
    pub async fn admin_redeliver_join(
        &self,
        node: String,
        child: String,
        node_addr: Option<String>,
    ) -> Result<AdminActionDto, JsError> {
        let child = parse_child(&child)?;
        let request = ControlRequest::AdminRedeliverJoin(AdminRedeliverJoin { child });
        let reply = self.admin_exchange(&node, request, node_addr).await?;
        match reply {
            ControlReply::AdminApproved(approved) => Ok(AdminActionDto::from_approved(&approved)),
            ControlReply::AdminRejected(rejected) => Ok(AdminActionDto::from_rejected(&rejected)),
            ControlReply::Rejected(code) => Err(admin_rejected(code)),
            _ => Err(unexpected_admin_reply("an admin redelivery")),
        }
    }

    /// Run one admin request: direct first, routed fallback only on a
    /// **transport** failure.
    ///
    /// With `node_addr == None` this is exactly the old direct exchange,
    /// including its error. With `Some`, a failed direct dial (dial error,
    /// timeout, no route) is retried over the routed tree; a delivered
    /// `Rejected(..)` reply means the node answered and is never retried.
    async fn admin_exchange(
        &self,
        node: &str,
        request: ControlRequest,
        node_addr: Option<String>,
    ) -> Result<ControlReply, JsError> {
        let (target, admin) = self.admin_context(node)?;
        let direct = exchange_admin(self.router.endpoint(), target, &admin, request.clone()).await;

        if !should_try_routed(&direct) {
            return direct;
        }
        let Some(raw_addr) = node_addr else {
            // No target address supplied: preserve the exact direct error and
            // never fall back.
            return direct;
        };
        let target_addr: OctAddr = raw_addr.parse().map_err(to_js_err)?;
        // The routed intent is signed exactly like the direct request: origin
        // is the target (the destination engine requires `origin == self`) and
        // the controller is the delegated admin key. The per-hop forward is
        // signed separately with this browser's operator key.
        let intent = sign_admin_request(target, &admin, request)?;
        self.exchange_routed_control(target, target_addr, intent)
            .await
    }

    /// Send `intent` to `target` over the routing tree and await its verified
    /// reply.
    ///
    /// The browser must be joined (an assigned address and parent). The
    /// request is framed as a `MSG_CONTROL_V1` envelope addressed to
    /// `target.addr` and dialed to the parent; the reply arrives later through
    /// the `cawala/msg/0` accept loop on the split control queue. A reply is
    /// accepted only if it decodes as a
    /// [`SignedRoutedReply`](cawala_control::SignedRoutedReply), correlates by
    /// `reply_to`, echoes this client as `requester`, names `target` as
    /// `responder`, and verifies under the target node's operator key. A
    /// non-matching control envelope is dropped: one outstanding routed request
    /// per client is the intended usage, and an uncorrelated reply cannot be
    /// trusted. The control-receiver mutex is held for the whole wait, so
    /// concurrent routed requests on one client are serialized.
    async fn exchange_routed_control(
        &self,
        target: EndpointId,
        target_addr: OctAddr,
        intent: SignedControl,
    ) -> Result<ControlReply, JsError> {
        let operator = self
            .control
            .operator
            .clone()
            .ok_or_else(|| JsError::new("client has no control identity; use spawn_control"))?;
        let (self_addr, parent) = self.joined_context()?;
        let requester = PeerRef {
            addr: self_addr,
            node: self.control.node_id().to_string(),
        };
        let target_ref = PeerRef {
            addr: target_addr,
            node: target.to_string(),
        };

        let mut forward_nonce = [0u8; 8];
        getrandom::fill(&mut forward_nonce).map_err(to_js_err)?;
        let mut id_bytes = [0u8; MsgId::LEN];
        getrandom::fill(&mut id_bytes).map_err(to_js_err)?;
        let mut nonce_bytes = [0u8; 8];
        getrandom::fill(&mut nonce_bytes).map_err(to_js_err)?;

        let routed = build_routed_control(
            target_ref.clone(),
            requester.clone(),
            intent,
            &operator,
            u64::from_le_bytes(forward_nonce),
            now_unix_seconds().saturating_add(CONTROL_REQUEST_TTL_SECS),
        )
        .map_err(to_js_err)?;
        // `to_bytes` rejects a payload over `MAX_CONTROL_FRAME` before framing.
        let payload = routed.to_bytes().map_err(to_js_err)?;
        let env = routed_request_envelope(
            &requester,
            &target_ref,
            MsgId::from_bytes(id_bytes),
            u64::from_le_bytes(nonce_bytes),
            payload,
        );

        let next_hop: EndpointId = parent.node_id.as_str().parse().map_err(to_js_err)?;
        let ack = self.exchange_ack(next_hop, &env).await?;
        match ack.status {
            AckStatus::Delivered | AckStatus::Duplicate => {}
            AckStatus::Rejected(_) => {
                return Err(JsError::new(&format!(
                    "routed control request refused by the parent relay: {}",
                    ack.status_str()
                )));
            }
        }

        let control_rx = self.control_rx.as_ref().ok_or_else(|| {
            JsError::new("client has no routed-control channel; use spawn_control")
        })?;
        // Serialize concurrent routed waits on one client.
        let mut rx = control_rx.lock().await;
        let request_msg_id = env.msg_id;

        let wait_for_reply = async {
            loop {
                let received = rx
                    .recv()
                    .await
                    .ok_or_else(|| JsError::new("control reply channel closed"))?;
                if received.msg_type != cawala_msg::MSG_CONTROL_V1 {
                    continue;
                }
                // Cheap correlation first; drop anything that is not our reply
                // (including malformed and unrelated control traffic).
                let Ok(decoded) = cawala_control::SignedRoutedReply::from_bytes(&received.payload)
                else {
                    tracing::debug!("dropping malformed routed control envelope");
                    continue;
                };
                if decoded.reply.reply_to != request_msg_id {
                    tracing::debug!("dropping unrelated routed control envelope");
                    continue;
                }
                let verified = verify_routed_reply_bytes(
                    &received.payload,
                    request_msg_id,
                    &target_ref,
                    &requester,
                )
                .map_err(to_js_err)?;
                return Ok::<ControlReply, JsError>(verified.reply.reply);
            }
        };

        n0_future::time::timeout(
            n0_future::time::Duration::from_secs(ROUTED_REPLY_TIMEOUT_SECS),
            wait_for_reply,
        )
        .await
        .map_err(|_| JsError::new("routed control request timed out"))?
    }

    /// Require a configured admin key and parse the target node id.
    fn admin_context(&self, node: &str) -> Result<(EndpointId, OperatorSecretKey), JsError> {
        let admin = self
            .control
            .admin_key()
            .ok_or_else(|| JsError::new("no admin key configured; call set_admin_key first"))?;
        let target: EndpointId = node.parse().map_err(to_js_err)?;
        Ok((target, admin))
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
    ///
    /// For a control client the assigned address lives in the shared local
    /// state (set by `JoinApproved`), so it is read live rather than duplicated
    /// here; [`ClientNode::spawn_with_address`] clients keep the fixed address
    /// they were constructed with.
    pub fn address(&self) -> Option<String> {
        if let Some(address) = &self.address {
            return Some(address.clone());
        }
        self.control
            .lock_state()
            .record
            .address
            .as_ref()
            .map(|address| address.to_string())
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
            .address()
            .ok_or_else(|| {
                JsError::new("client has no messaging address; use spawn_with_address or join")
            })?
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

        let ack = self.exchange_ack(next_hop, &env).await?;

        Ok(ack.status_str().to_string())
    }

    /// Dial `next_hop` on `cawala/msg/0`, frame `env`, and read the [`Ack`],
    /// bounded by a 10-second timeout.
    ///
    /// Uses [`n0_future::time::timeout`] (never a `tokio` runtime) because this
    /// runs on wasm.
    async fn exchange_ack(&self, next_hop: EndpointId, env: &Envelope) -> Result<Ack, JsError> {
        n0_future::time::timeout(n0_future::time::Duration::from_secs(10), async {
            let connection = self
                .router
                .endpoint()
                .connect(next_hop, cawala_msg::ALPN)
                .await
                .map_err(to_js_err)?;
            let (mut send, mut recv) = connection.open_bi().await.map_err(to_js_err)?;
            proto::write_framed(&mut send, env)
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
        .map_err(|_| JsError::new("send timed out waiting for ack"))?
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

    /// Send a same-leaf `Direct` payment order to `to` (a node id string) and
    /// return its hash plus the routing leaf's ack.
    ///
    /// The client must be joined (an assigned address and parent). `to` is the
    /// payee's `EndpointId` and `to_address` is the payee's user `OctAddr`
    /// (normally from a receive URI); `amount` is in the single Cawala nominal
    /// unit, must be a whole number, and must fit an exact JavaScript integer
    /// (`<= 2^53-1`). The order is operator-signed and persisted as pending
    /// **before** it is dialed, so a racing `"order_result"` event can always be
    /// matched; the terminal status arrives through
    /// [`ClientNode::try_recv_ledger_event`] as an `"order_result"` event whose
    /// `status` is `applied`/`duplicate`/`partial`/`rejected` (`partial` carries
    /// the failing hop).
    pub async fn send_payment(
        &self,
        to: String,
        to_address: String,
        amount: f64,
    ) -> Result<PaymentOutcome, JsError> {
        let operator = self
            .control
            .operator
            .clone()
            .ok_or_else(|| JsError::new("client has no control identity; use spawn_control"))?;
        let (self_addr, parent) = self.joined_context()?;
        let self_node = self.control.node_id().to_string();

        let recipient: EndpointId = to.parse().map_err(to_js_err)?;
        if recipient.to_string() == self_node {
            return Err(JsError::new("cannot send a payment to yourself"));
        }
        let payee_addr: OctAddr = to_address
            .parse()
            .map_err(|_| JsError::new("invalid payee address"))?;
        let amount = ledger_state::validate_amount(amount).map_err(to_js_err)?;

        let now = now_unix_seconds();
        let mut nonce_bytes = [0u8; 8];
        getrandom::fill(&mut nonce_bytes).map_err(to_js_err)?;
        let order = ledger_state::build_payment_order(
            cawala_ledger::NodeId::from(self_node.clone()),
            cawala_ledger::NodeId::from(recipient.to_string()),
            amount,
            u64::from_le_bytes(nonce_bytes),
            now.saturating_add(ledger_state::ORDER_TTL_SECS),
        );
        let order_hash = order.hash();
        let auth = order.authorize(&operator).map_err(to_js_err)?;

        // The leaf decides same-leaf `Direct` vs a cross-leaf depth-1 `Descend`
        // settlement; record the payer role now so a later terminal proof can be
        // verified against it. The out-of-band leaf pin (when the payer pinned
        // one from the receive URI) is already in the pinned-leaf registry.
        let payer_leaf = self_addr.parent() == payee_addr.parent();

        // Persist before dialing so a result racing the ack can still match.
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push_pending_with(
                order.clone(),
                auth.clone(),
                now,
                Some(payee_addr.clone()),
                payer_leaf,
                None,
            );

        // v2: the leaf decides same-leaf `Direct` vs a depth-1 settlement from
        // the payee address.
        let payload = LedgerPayloadV2::Order(OrderV2 {
            order,
            auth,
            payee_addr,
        });
        let ack = self
            .send_ledger_payload_v2(self_addr, &parent, payload)
            .await?;
        Ok(PaymentOutcome::new(
            order_hash.to_hex(),
            ack.status_str().to_string(),
        ))
    }

    /// This client's own user `OctAddr`, when joined.
    pub fn user_address(&self) -> Option<String> {
        let state = self.control.lock_state();
        state.record.address.as_ref().map(|addr| addr.to_string())
    }

    /// This client's payment receive URI:
    /// `cawala://pay?to=<EndpointId>&addr=<OctAddr>`.
    ///
    /// Share (paste/scan) it so a payer can address a cross-subtree payment to
    /// this user.
    ///
    /// When this leaf's routing ledger key has been pinned (from a verified
    /// balance receipt), the URI also carries the out-of-band leaf pin
    /// `ln=<parent leaf node id>&lk=<pinned ledger key hex>` so a payer can
    /// require and verify the terminal inclusion proof under that key before
    /// treating the payment as applied.
    pub fn receive_uri(&self) -> Result<String, JsError> {
        let address = self
            .user_address()
            .ok_or_else(|| JsError::new("not joined: no assigned address"))?;
        let parent = self.join_status().parent();
        let pinned = self.ledger_status().pinned_ledger();
        match (parent, pinned) {
            (Some(parent), Some(pinned)) => Ok(dto::receive_uri_with_leaf(
                self.control.node_id(),
                &address,
                &parent,
                &pinned,
            )),
            _ => Ok(dto::receive_uri_for(self.control.node_id(), &address)),
        }
    }

    /// Pin the payee leaf's ledger key from a receive URI before sending a
    /// payment.
    ///
    /// `node_id` is the URI's `ln` (the payee's parent leaf node id) and
    /// `ledger_hex` is the URI's `lk` (that leaf's 64-hex ledger public key).
    /// Once pinned, a terminal proof for this leaf must verify under exactly
    /// that key; a mismatch is reported as an `"unverified"` settlement, never
    /// as success. The pin is stored in the secret-free ledger state, so it
    /// survives [`ClientNode::export_ledger_state`] round trips.
    pub fn pin_payee_leaf(&self, node_id: String, ledger_hex: String) -> Result<(), JsError> {
        let endpoint: EndpointId = node_id.parse().map_err(to_js_err)?;
        let node = cawala_ledger::NodeId::from(endpoint.to_string());
        let key = dto::parse_ledger_hex(&ledger_hex).map_err(to_js_err)?;
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pin_leaf_key(node, key);
        Ok(())
    }

    /// Request a signed balance receipt from the routing leaf and return the
    /// leaf's ack bucket.
    ///
    /// The verified receipt arrives asynchronously through
    /// [`ClientNode::try_recv_ledger_event`] as a `"balance_receipt"` event.
    pub async fn request_balance(&self) -> Result<String, JsError> {
        let (self_addr, parent) = self.joined_context()?;
        let mut query_bytes = [0u8; 8];
        getrandom::fill(&mut query_bytes).map_err(to_js_err)?;
        let payload = LedgerPayloadV1::BalanceQuery(BalanceQueryV1 {
            query_id: u64::from_le_bytes(query_bytes),
        });
        let ack = self
            .send_ledger_payload(self_addr, &parent, payload)
            .await?;
        Ok(ack.status_str().to_string())
    }

    /// Non-blocking drain of the next ledger event.
    ///
    /// Envelopes that are not `MSG_LEDGER_V1` are skipped; a malformed,
    /// unexpected, or unverifiable ledger message yields a `kind = "invalid"`
    /// event and never mutates the balance or pending set. Returns `None` when
    /// the queue is empty.
    pub fn try_recv_ledger_event(&self) -> Option<LedgerEventDto> {
        let Some(rx) = &self.rx else {
            return None;
        };
        let mut rx = rx.try_lock().ok()?;
        loop {
            let env = match rx.try_recv() {
                Ok(env) => env,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return None,
            };
            if env.msg_type != MSG_LEDGER_V1 {
                tracing::info!(msg_type = env.msg_type, "skipping non-ledger envelope");
                continue;
            }
            let payload = match decode_versioned(&env.payload) {
                Ok(payload) => payload,
                Err(err) => {
                    tracing::warn!(%err, "malformed ledger payload");
                    return Some(LedgerEventDto::invalid("malformed_payload"));
                }
            };
            return Some(match payload {
                VersionedLedgerPayload::V1(LedgerPayloadV1::OrderResult(result)) => {
                    self.apply_order_result_event(&result)
                }
                VersionedLedgerPayload::V1(LedgerPayloadV1::BalanceReceipt(receipt)) => {
                    self.apply_balance_receipt_event(&receipt)
                }
                VersionedLedgerPayload::V2(LedgerPayloadV2::OrderResult(result)) => {
                    self.apply_settlement_result_v2_event(&result)
                }
                VersionedLedgerPayload::V3(LedgerPayloadV3::OrderResult(result)) => {
                    self.apply_settlement_result_v3_event(&result)
                }
                _ => {
                    tracing::warn!("unexpected inbound ledger payload");
                    LedgerEventDto::invalid("unexpected_payload")
                }
            });
        }
    }

    /// Apply one inbound `OrderResult` to the persisted ledger state.
    fn apply_order_result_event(&self, result: &cawala_msg::OrderResultV1) -> LedgerEventDto {
        let Some((self_node, parent)) = self.ledger_binding() else {
            return LedgerEventDto::invalid("not_joined");
        };
        let now = now_unix_seconds();
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match ledger_state::apply_order_result(&mut ledger, result, &self_node, &parent, now) {
            Ok(app) => LedgerEventDto::order_result(&app),
            Err(reason) => LedgerEventDto::invalid(&reason),
        }
    }

    /// Apply one inbound v2 settlement `OrderResultV2` to the persisted ledger
    /// state.
    fn apply_settlement_result_v2_event(
        &self,
        result: &cawala_msg::OrderResultV2,
    ) -> LedgerEventDto {
        let Some((self_node, parent)) = self.ledger_binding() else {
            return LedgerEventDto::invalid("not_joined");
        };
        let now = now_unix_seconds();
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match ledger_state::apply_settlement_result_v2(&mut ledger, result, &self_node, &parent, now)
        {
            Ok(app) => LedgerEventDto::settlement(&app),
            Err(reason) => LedgerEventDto::invalid(&reason),
        }
    }

    /// Apply one inbound v3 settlement `OrderResultV3` (with a terminal
    /// inclusion proof) to the persisted ledger state.
    fn apply_settlement_result_v3_event(
        &self,
        result: &cawala_msg::OrderResultV3,
    ) -> LedgerEventDto {
        let Some((self_node, parent)) = self.ledger_binding() else {
            return LedgerEventDto::invalid("not_joined");
        };
        let now = now_unix_seconds();
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match ledger_state::apply_settlement_result(&mut ledger, result, &self_node, &parent, now) {
            Ok(app) => LedgerEventDto::settlement(&app),
            Err(reason) => LedgerEventDto::invalid(&reason),
        }
    }

    /// Apply one inbound `BalanceReceipt` to the persisted ledger state.
    fn apply_balance_receipt_event(
        &self,
        receipt: &cawala_msg::BalanceReceiptV1,
    ) -> LedgerEventDto {
        let Some((self_node, parent)) = self.ledger_binding() else {
            return LedgerEventDto::invalid("not_joined");
        };
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match ledger_state::apply_balance_receipt(&mut ledger, receipt, &self_node, &parent) {
            Ok(balance) => LedgerEventDto::balance_receipt(&balance),
            Err(reason) => LedgerEventDto::invalid(&reason),
        }
    }

    /// The `(self_node, parent)` pair used to bind an inbound receipt.
    fn ledger_binding(&self) -> Option<(String, cawala_ledger::NodeId)> {
        let self_node = self.control.node_id().to_string();
        let parent = {
            let state = self.control.lock_state();
            state
                .record
                .parent
                .as_ref()
                .map(|link| cawala_ledger::NodeId::from(link.node_id.as_str().to_string()))?
        };
        Some((self_node, parent))
    }

    /// A snapshot of the persisted balance/height, pinned ledger key, and
    /// pending/activity counts.
    pub fn ledger_status(&self) -> LedgerStatusDto {
        let (address, parent) = {
            let state = self.control.lock_state();
            (
                state.record.address.as_ref().map(|a| a.to_string()),
                state
                    .record
                    .parent
                    .as_ref()
                    .map(|p| p.node_id.as_str().to_string()),
            )
        };
        let ledger = self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        LedgerStatusDto::from_state(address, parent, &ledger)
    }

    /// The persisted activity log, oldest first, for UI reconstruction after a
    /// reload.
    ///
    /// Entries come from verified value notices (balance receipts and their
    /// history) and are bounded by
    /// [`ledger_state::MAX_ACTIVITY_ENTRIES`](crate::ledger_state::MAX_ACTIVITY_ENTRIES).
    pub fn ledger_activity(&self) -> Vec<dto::ActivityEntryDto> {
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .activity
            .iter()
            .map(dto::ActivityEntryDto::from_entry)
            .collect()
    }

    /// The persisted terminal settlement outcomes, oldest first, for UI
    /// reconstruction after a reload.
    ///
    /// Records are bounded by
    /// [`ledger_state::MAX_SETTLEMENT_RECORDS`](crate::ledger_state::MAX_SETTLEMENT_RECORDS)
    /// and carry the order's amount, payee, and verified terminal `seq` when the
    /// resolving result provided them.
    pub fn settlement_records(&self) -> Vec<dto::SettlementRecordDto> {
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .settlements
            .iter()
            .map(dto::SettlementRecordDto::from_record)
            .collect()
    }

    /// Export the ledger state as postcard bytes.
    ///
    /// The blob contains the pinned ledger key, verified balance, activity, and
    /// pending orders; it contains **no secret key material**, so it is safe to
    /// persist in browser storage.
    pub fn export_ledger_state(&self) -> Vec<u8> {
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .to_bytes()
    }

    /// Replace the ledger state from bytes previously produced by
    /// [`ClientNode::export_ledger_state`].
    pub fn import_ledger_state(&self, bytes: &[u8]) -> Result<(), JsError> {
        let state = LedgerStateV1::from_bytes(bytes).map_err(to_js_err)?;
        *self
            .ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = state;
        Ok(())
    }

    /// Require a joined client and return its assigned address and parent link.
    fn joined_context(&self) -> Result<(OctAddr, ParentLink), JsError> {
        let state = self.control.lock_state();
        let addr = state
            .record
            .address
            .clone()
            .ok_or_else(|| JsError::new("not joined: no assigned address"))?;
        let parent = state
            .record
            .parent
            .clone()
            .ok_or_else(|| JsError::new("not joined: no parent"))?;
        Ok((addr, parent))
    }

    /// Frame a v1 `payload` as a `MSG_LEDGER_V1` envelope addressed to the
    /// routing leaf (the parent) and exchange it for an [`Ack`].
    async fn send_ledger_payload(
        &self,
        self_addr: OctAddr,
        parent: &ParentLink,
        payload: LedgerPayloadV1,
    ) -> Result<Ack, JsError> {
        let bytes = payload.to_bytes().map_err(to_js_err)?;
        self.send_ledger_bytes(self_addr, parent, bytes).await
    }

    /// Frame a v2 `payload` as a `MSG_LEDGER_V1` envelope addressed to the
    /// routing leaf (the parent) and exchange it for an [`Ack`].
    async fn send_ledger_payload_v2(
        &self,
        self_addr: OctAddr,
        parent: &ParentLink,
        payload: LedgerPayloadV2,
    ) -> Result<Ack, JsError> {
        let bytes = payload.to_bytes().map_err(to_js_err)?;
        self.send_ledger_bytes(self_addr, parent, bytes).await
    }

    /// Frame encoded `bytes` as a `MSG_LEDGER_V1` envelope addressed to the
    /// routing leaf (the parent) and exchange it for an [`Ack`].
    async fn send_ledger_bytes(
        &self,
        self_addr: OctAddr,
        parent: &ParentLink,
        bytes: Vec<u8>,
    ) -> Result<Ack, JsError> {
        let dst = self_addr
            .parent()
            .ok_or_else(|| JsError::new("assigned address has no parent"))?;
        let next_hop: EndpointId = parent.node_id.as_str().parse().map_err(to_js_err)?;

        let mut id_bytes = [0u8; MsgId::LEN];
        getrandom::fill(&mut id_bytes).map_err(to_js_err)?;
        let mut nonce_bytes = [0u8; 8];
        getrandom::fill(&mut nonce_bytes).map_err(to_js_err)?;
        let src = PeerRef {
            addr: self_addr,
            node: self.control.node_id().to_string(),
        };
        let env = Envelope::new(
            src,
            dst,
            MsgId::from_bytes(id_bytes),
            MSG_LEDGER_V1,
            u64::from_le_bytes(nonce_bytes),
            bytes,
        );
        self.exchange_ack(next_hop, &env).await
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

/// Validate a child node id string and return its canonical [`NodeId`] form.
///
/// The wire accepts opaque strings, but a browser should only ever name a real
/// endpoint; parsing as an [`EndpointId`] rejects anything else and normalizes
/// hex/base32 spellings.
fn parse_child(raw: &str) -> Result<NodeId, JsError> {
    let endpoint: EndpointId = raw.parse().map_err(to_js_err)?;
    Ok(NodeId::from(endpoint.to_string()))
}

/// Map an admin reply rejection to a JS error carrying the stable code string.
fn admin_rejected(code: RejectCode) -> JsError {
    JsError::new(&format!(
        "admin request rejected: {}",
        reject_code_str(code)
    ))
}

/// Build the error for a structurally unexpected reply to an admin action.
fn unexpected_admin_reply(what: &str) -> JsError {
    JsError::new(&format!("unexpected reply to {what}"))
}

/// Stable `delivery` bucket for the parent's reply to a [`ClientNode::leave`]
/// `Exit` notice.
///
/// The native handler answers an `Exit` with `Accepted`/`Rejected`; any other
/// reply shape is structurally impossible and is reported as `"unexpected"`
/// rather than being mistaken for success.
fn leave_delivery(reply: &ControlReply) -> String {
    match reply {
        ControlReply::Accepted => "accepted".to_string(),
        ControlReply::Rejected(code) => format!("rejected:{}", reject_code_str(*code)),
        _ => "unexpected".to_string(),
    }
}

pub(crate) fn to_js_err(err: impl std::fmt::Display) -> JsError {
    JsError::new(&err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cawala_msg::Hop;

    fn peer(addr: &str, node: &str) -> PeerRef {
        PeerRef {
            addr: addr.parse().expect("sample address parses"),
            node: node.to_string(),
        }
    }

    /// A joined control leaf at `self_addr` under `parent`, with its split
    /// envelope and control-reply queues.
    fn joined_handler(
        self_addr: &str,
        parent_node: &str,
    ) -> (
        MsgHandler,
        mpsc::Receiver<Envelope>,
        mpsc::Receiver<Envelope>,
    ) {
        let self_node = "browser-leaf".to_string();
        let shared = Arc::new(SharedControl::new(
            self_node.clone(),
            Some(OperatorSecretKey::from_bytes([1u8; 32])),
        ));
        {
            let mut state = shared.lock_state();
            state.record.address = Some(self_addr.parse().expect("sample address parses"));
            state.record.parent = Some(ParentLink {
                node_id: NodeId::from(parent_node.to_string()),
                slot: 2,
            });
        }
        let (sink, rx) = mpsc::channel(4);
        let (control_sink, control_rx) = mpsc::channel(4);
        (
            MsgHandler::for_shared(shared, self_node, sink, control_sink),
            rx,
            control_rx,
        )
    }

    /// An envelope descending from a non-parent ancestor `ancestor` to the
    /// leaf, with a valid hop chain whose last hop is the authenticated parent.
    fn ancestor_envelope(
        ancestor: &PeerRef,
        self_addr: &str,
        parent: &PeerRef,
        msg_type: u16,
        msg_id: MsgId,
    ) -> Envelope {
        let mut env = Envelope::new(
            ancestor.clone(),
            self_addr.parse().expect("sample address parses"),
            msg_id,
            msg_type,
            7,
            Vec::new(),
        );
        // One recorded hop consumed one TTL (see `cawala_msg` forwarding).
        env.ttl = 1;
        env.hop_chain.push(Hop {
            addr: parent.addr.clone(),
            node: parent.node.clone(),
        });
        env
    }

    #[tokio::test]
    async fn control_envelope_from_non_parent_ancestor_reaches_control_queue() {
        // The parent must be a real endpoint id so it can authenticate as the
        // QUIC remote.
        let parent_op = OperatorSecretKey::from_bytes([2u8; 32]);
        let parent_node = parent_op.public().to_string();
        let ancestor_node = OperatorSecretKey::from_bytes([3u8; 32])
            .public()
            .to_string();
        let (handler, mut sink_rx, mut control_rx) = joined_handler("0.2.3", &parent_node);
        let parent = peer("0.2", &parent_node);
        let ancestor = peer("0", &ancestor_node);
        let remote: EndpointId = parent_node.parse().expect("endpoint id parses");

        let env = ancestor_envelope(
            &ancestor,
            "0.2.3",
            &parent,
            cawala_msg::MSG_CONTROL_V1,
            MsgId([0x5a; 16]),
        );
        let ack = handler.handle(remote, env).await;

        assert_eq!(ack.status, AckStatus::Delivered);
        let delivered = control_rx
            .try_recv()
            .expect("control envelope reaches the control queue");
        assert_eq!(delivered.msg_type, cawala_msg::MSG_CONTROL_V1);
        assert_eq!(delivered.src.node, ancestor_node);
        assert!(
            sink_rx.try_recv().is_err(),
            "control replies must not mix into the general sink"
        );
    }

    #[tokio::test]
    async fn non_control_envelope_from_non_parent_ancestor_is_rejected() {
        let parent_op = OperatorSecretKey::from_bytes([2u8; 32]);
        let parent_node = parent_op.public().to_string();
        let ancestor_node = OperatorSecretKey::from_bytes([4u8; 32])
            .public()
            .to_string();
        let (handler, mut sink_rx, mut control_rx) = joined_handler("0.2.3", &parent_node);
        let parent = peer("0.2", &parent_node);
        let ancestor = peer("0", &ancestor_node);
        let remote: EndpointId = parent_node.parse().expect("endpoint id parses");

        let env = ancestor_envelope(
            &ancestor,
            "0.2.3",
            &parent,
            MSG_LEDGER_V1,
            MsgId([0x5b; 16]),
        );
        let ack = handler.handle(remote, env).await;

        assert_eq!(
            ack.status,
            AckStatus::Rejected(RejectReason::NotNeighbor),
            "the parent rule still applies to non-control traffic"
        );
        assert!(sink_rx.try_recv().is_err());
        assert!(control_rx.try_recv().is_err());
    }
}
