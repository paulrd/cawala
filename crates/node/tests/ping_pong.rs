//! Integration test: in-process server + client endpoints over the public N0
//! relay (presets::N0). Requires network access to the N0 relay.

use cawala_node::{ping, ping_with_addr, PingHandler, PingPong, ALPN};
use iroh::endpoint::presets::N0;
use iroh::protocol::Router;

#[tokio::test]
async fn ping_pong_roundtrip_over_n0_relay() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::INFO)
        .try_init()
        .ok();

    // Server side.
    let server_endpoint = iroh::Endpoint::builder(N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .expect("bind server endpoint");
    let router = Router::builder(server_endpoint)
        .accept(ALPN, PingHandler)
        .spawn();
    let server_id = router.endpoint().id();
    println!("server endpoint id: {server_id}");

    // Client side.
    let client_endpoint = iroh::Endpoint::builder(N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .expect("bind client endpoint");
    println!("client endpoint id: {}", client_endpoint.id());

    let payload = b"hello cawala from the integration test".to_vec();

    // Primary path: resolve the server via address lookup (pkarr/DNS), exactly
    // like the browser-echo demo's CLI connect.
    let pong = match ping(&client_endpoint, server_id, payload.clone()).await {
        Ok(pong) => {
            println!("primary ping() path succeeded (address lookup worked)");
            pong
        }
        Err(err) => {
            // Some sandboxes block the pkarr-over-HTTPS and DNS TXT address
            // lookup services while still allowing the relay itself. Fall back
            // to an explicit relay hint through the same N0 relays.
            println!(
                "ping() via address lookup failed ({err}); retrying with explicit N0 relay hints"
            );
            let addr = iroh::EndpointAddr::from_parts(
                server_id,
                [
                    iroh::defaults::prod::NA_EAST_RELAY_HOSTNAME,
                    iroh::defaults::prod::NA_WEST_RELAY_HOSTNAME,
                    iroh::defaults::prod::EU_RELAY_HOSTNAME,
                    iroh::defaults::prod::AP_RELAY_HOSTNAME,
                ]
                .into_iter()
                .map(|host| {
                    iroh::TransportAddr::Relay(
                        format!("https://{host}")
                            .parse()
                            .expect("default relay url"),
                    )
                }),
            );
            ping_with_addr(&client_endpoint, addr, payload.clone())
                .await
                .expect("relay-hinted ping/pong round-trip failed (is the N0 relay reachable?)")
        }
    };

    println!("got pong: {pong:?}");
    match pong {
        PingPong::Pong {
            seq,
            payload: got_payload,
        } => {
            assert_eq!(seq, 1, "seq should be incremented from 0 to 1");
            assert_eq!(
                got_payload, payload,
                "pong payload should match the ping payload"
            );
        }
        PingPong::Ping { .. } => panic!("expected Pong, got Ping"),
    }

    // Clean shutdown.
    router.shutdown().await.expect("router shutdown");
    client_endpoint.close().await;
}
