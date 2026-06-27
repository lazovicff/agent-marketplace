use clap::Parser;

/// Configuration for the Agent Marketplace API backend.
#[derive(Debug, Clone, Parser)]
#[command(name = "agent-marketplace-api")]
pub struct Config {
    /// Ethereum RPC WebSocket URL (for real-time event subscriptions).
    #[arg(long, env = "RPC_WS_URL", default_value = "ws://localhost:8545")]
    pub rpc_ws_url: String,

    /// Ethereum RPC HTTP URL (for historical event sync).
    #[arg(long, env = "RPC_HTTP_URL", default_value = "http://localhost:8545")]
    pub rpc_http_url: String,

    /// Agent Registry contract address.
    #[arg(long, env = "AGENT_REGISTRY_ADDRESS")]
    pub agent_registry_address: String,

    /// Task contract address.
    #[arg(long, env = "TASK_CONTRACT_ADDRESS")]
    pub task_contract_address: String,

    /// Schema Registry contract address.
    #[arg(long, env = "SCHEMA_REGISTRY_ADDRESS")]
    pub schema_registry_address: String,

    /// Block number to start syncing from.
    #[arg(long, env = "START_BLOCK", default_value = "0")]
    pub start_block: u64,

    /// API server bind address.
    #[arg(long, env = "BIND_ADDR", default_value = "0.0.0.0:8080")]
    pub bind_addr: String,
}
