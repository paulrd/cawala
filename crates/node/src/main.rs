use anyhow::Result;
use cawala_node::{PingHandler, ALPN};
use iroh::protocol::Router;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    info!(endpoint_id = %endpoint.id(), "node endpoint bound");

    let router = Router::builder(endpoint).accept(ALPN, PingHandler).spawn();

    let endpoint_id = router.endpoint().id();
    println!("EndpointId: {endpoint_id}");
    println!(
        "Run the web client to ping this node, or check the round-trip with: cargo test -p cawala-node"
    );

    // Await forever; dropping `router` would abort the accept loop.
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
