//! Cawala browser client: a wasm-bindgen wrapper around an iroh [`Endpoint`]
//! running the `cawala/ping/0` accept loop, so a browser tab can both answer
//! and initiate pings.
//!
//! Connections go over the public N0 relay ([`iroh::endpoint::presets::N0`])
//! because browsers cannot dial UDP directly. Holding the [`Router`] in
//! [`ClientNode`] keeps the accept loop alive (dropping it would abort
//! accepts).

use std::io;

use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use tracing::level_filters::LevelFilter;
use tracing::info;
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

/// A wasm-bindgen handle to an iroh [`Endpoint`] running the `cawala/ping/0`
/// accept loop on the N0 relay preset. Holds the [`Router`]; dropping it would
/// abort the accept loop.
#[wasm_bindgen]
pub struct ClientNode {
    router: Router,
}

#[wasm_bindgen]
impl ClientNode {
    /// Bind a new endpoint using the `cawala/ping/0` ALPN and the N0 relay
    /// preset, and start the accept loop. Returns a client that can both
    /// answer and initiate pings.
    pub async fn spawn() -> Result<ClientNode, JsError> {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![proto::ALPN.to_vec()])
            .bind()
            .await
            .map_err(to_js_err)?;
        let router = Router::builder(endpoint)
            .accept(proto::ALPN, PingHandler)
            .spawn();
        Ok(ClientNode { router })
    }

    /// This client's endpoint id (node public key), as a string. Give this to
    /// other peers so they can connect to you.
    pub fn endpoint_id(&self) -> String {
        self.router.endpoint().id().to_string()
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
            Err(first_err) => {
                match self.connect_via_local_relay(endpoint, endpoint_id).await {
                    Ok(conn) => conn,
                    Err(_) => return Err(to_js_err(first_err)),
                }
            }
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
        let addr =
            iroh::EndpointAddr::from_parts(endpoint_id, relays.into_iter().map(iroh::TransportAddr::Relay));
        tracing::info!(%endpoint_id, ?addr, "connecting via local relay fallback");
        endpoint.connect(addr, proto::ALPN).await.map_err(to_js_err)
    }
}

fn to_js_err(err: impl std::fmt::Display) -> JsError {
    JsError::new(&err.to_string())
}
