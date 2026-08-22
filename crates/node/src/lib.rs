//! Cawala node: the native peer for the M0 ping/pong spike.
//!
//! Provides [`PingHandler`], a [`ProtocolHandler`] that answers a single
//! framed ping with a pong over a relayed connection, and [`ping`], the
//! matching client helper used by the integration test and (in spirit) the
//! WASM client.

use iroh::{
    Endpoint,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
};
use std::io;
use tracing::info;

pub use proto::{PingPong, ALPN};

pub mod identity;
pub mod record;

/// Bind an endpoint with the given persisted [`iroh::SecretKey`] and start the
/// `cawala/ping/0` accept loop.
///
/// A key persisted via [`identity::load_or_create_secret_key`] yields a stable
/// [`iroh::EndpointId`] across restarts.
pub async fn spawn_with_secret_key(secret_key: iroh::SecretKey) -> anyhow::Result<Router> {
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    Ok(Router::builder(endpoint).accept(ALPN, PingHandler).spawn())
}

/// Server side of the `cawala/ping/0` protocol: accept a connection, read one
/// framed `Ping`, reply with `Pong { seq: seq+1, payload }`, finish the send
/// stream, then wait for the connection to close.
#[derive(Debug)]
pub struct PingHandler;

impl PingHandler {
    async fn handle_connection(&self, connection: &Connection) -> Result<(), AcceptError> {
        let endpoint_id = connection.remote_id();

        // Our protocol is a simple request-response protocol, so we expect the
        // connecting peer to open a single bi-directional stream.
        let (mut send, mut recv) = connection.accept_bi().await?;

        let msg = proto::read_frame(&mut recv).await?;
        let PingPong::Ping { payload } = msg else {
            return Err(AcceptError::from_err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected Ping, got {msg:?}"),
            )));
        };

        // No seq is carried in the ping, so the reply seq starts at 1.
        let seq: u64 = 0;
        let pong = PingPong::Pong {
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
    /// runs on a newly spawned tokio task, so it can run as long as the
    /// connection lasts.
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

/// Client helper: connect to `endpoint_id`, send one framed `Ping`, wait for
/// the framed `Pong` reply, and close the connection.
///
/// The address of the remote is resolved through the endpoint's configured
/// address lookup services (pkarr/DNS with the `N0` preset).
pub async fn ping(
    endpoint: &Endpoint,
    endpoint_id: iroh::EndpointId,
    payload: Vec<u8>,
) -> anyhow::Result<PingPong> {
    ping_with_addr(endpoint, endpoint_id.into(), payload).await
}

/// Client helper like [`ping`], but with an explicit [`EndpointAddr`] so the
/// connection can be routed through a known relay without relying on address
/// lookup services.
pub async fn ping_with_addr(
    endpoint: &Endpoint,
    endpoint_addr: iroh::EndpointAddr,
    payload: Vec<u8>,
) -> anyhow::Result<PingPong> {
    let connection = endpoint.connect(endpoint_addr, ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    proto::write_frame(&mut send, &PingPong::Ping { payload }).await?;
    // Signal we will not send anything further on this stream.
    send.finish()?;

    let pong = proto::read_frame(&mut recv).await?;

    // We received the last data, so we close the connection.
    connection.close(1u8.into(), b"done");
    Ok(pong)
}
