mod config;
mod indexer;
mod models;
mod routes;
mod store;

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::indexer::Indexer;
use crate::store::new_shared_store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Parse configuration
    let config = Config::parse();

    info!("Starting Agent Marketplace API");
    info!("Bind address: {}", config.bind_addr);
    info!("RPC HTTP: {}", config.rpc_http_url);
    info!("RPC WS: {}", config.rpc_ws_url);
    info!("Agent Registry: {}", config.agent_registry_address);
    info!("Task Contract: {}", config.task_contract_address);
    info!("Schema Registry: {}", config.schema_registry_address);
    info!("Start block: {}", config.start_block);

    // Create the shared in-memory store
    let store = new_shared_store();

    // Start the indexer in a background task
    let indexer_config = config.clone();
    let indexer_store = store.clone();
    tokio::spawn(async move {
        let indexer = Indexer::new(indexer_store, indexer_config);
        if let Err(e) = indexer.run().await {
            tracing::error!("Indexer error: {}", e);
        }
    });

    // Build the router
    let app = routes::build_router(store);

    // Start the server
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    info!("API server listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;

    Ok(())
}
