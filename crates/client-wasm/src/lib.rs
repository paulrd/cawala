//! Cawala browser client: a minimal wasm-bindgen wrapper around an iroh
//! `Endpoint`, exposing the `cawala/ping/0` protocol to JavaScript.
//!
//! Connections go over the public N0 relay ([`iroh::endpoint::presets::N0`])
//! because browsers cannot dial UDP directly.

use iroh::Endpoint;
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

/// A wasm-bindgen handle to an iroh [`Endpoint`], bound to the N0 relay
/// preset so the browser can reach peers over the public relay.
#[wasm_bindgen]
pub struct ClientNode(Endpoint);

#[wasm_bindgen]
impl ClientNode {
    /// Bind a new endpoint using the `cawala/ping/0` ALPN and the N0 relay
    /// preset. Returns a client that can `ping` any node with a public key.
    pub async fn spawn() -> Result<ClientNode, JsError> {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![proto::ALPN.to_vec()])
            .bind()
            .await
            .map_err(to_js_err)?;
        Ok(ClientNode(endpoint))
    }

    /// This client's endpoint id (node public key), as a string. Give this to
    /// other peers so they can connect to you.
    pub fn endpoint_id(&self) -> String {
        self.0.id().to_string()
    }

    /// Send one framed `Ping` with the given UTF-8 payload to `endpoint_id`
    /// and return the `Pong` payload as a (lossy) UTF-8 string.
    pub async fn ping(&self, endpoint_id: String, payload: String) -> Result<String, JsError> {
        let endpoint_id: iroh::EndpointId = endpoint_id.parse().map_err(to_js_err)?;

        let connection = self.0.connect(endpoint_id, proto::ALPN).await.map_err(to_js_err)?;
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
}

fn to_js_err(err: impl std::fmt::Display) -> JsError {
    JsError::new(&err.to_string())
}
