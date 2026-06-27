use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::sol;
use alloy::transports::http::{Client, Http};
use clap::Parser;
use tracing::info;

use crate::utils;

sol! {
    /// Minimal ABI for the AgentRegistry contract.
    #[sol(rpc)]
    contract AgentRegistry {
        function isRegistered(address agent) external view returns (bool);
        function getAgent(address agent) external view returns (address agentAddress, bytes teePublicKey, bytes attestationQuote, string metadataURI, uint256 registeredAt, bool active);
    }
}

/// Check agent registration status.
#[derive(Parser)]
pub struct StatusArgs {
    /// Ethereum RPC URL.
    #[arg(long, env = "RPC_URL", default_value = "http://localhost:8545")]
    pub rpc_url: String,

    /// Agent Registry contract address.
    #[arg(long, env = "AGENT_REGISTRY_ADDRESS")]
    pub contract_address: String,

    /// Agent address to check (or use the signer's address if not provided).
    #[arg(long)]
    pub agent_address: Option<String>,

    /// Private key (used to derive the agent address if --agent-address is not given).
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: Option<String>,
}

pub async fn run(args: StatusArgs) -> anyhow::Result<()> {
    // Determine the agent address
    let agent_addr: Address = if let Some(ref addr) = args.agent_address {
        addr.parse()
            .map_err(|e| anyhow::anyhow!("Invalid agent address: {}", e))?
    } else if let Some(ref pk) = args.private_key {
        let wallet: alloy::signers::local::PrivateKeySigner = pk
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
        wallet.address()
    } else {
        anyhow::bail!("Either --agent-address or --private-key must be provided");
    };

    info!("Checking agent status...");
    info!("  Agent:  {}", agent_addr);
    info!("  Contract: {}", args.contract_address);

    // Parse the contract address
    let contract_addr: Address = args
        .contract_address
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid contract address: {}", e))?;

    // Create the provider
    let provider: RootProvider<Http<Client>> = ProviderBuilder::default().on_http(
        args.rpc_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid RPC URL: {}", e))?,
    );

    // Build the contract instance
    let contract = AgentRegistry::new(contract_addr, &provider);

    // Check if registered
    let is_registered = contract
        .isRegistered(agent_addr)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check registration: {}", e))?
        ._0;

    if !is_registered {
        println!("Agent: {}", agent_addr);
        println!("Status: Not registered");
        return Ok(());
    }

    // Fetch full agent info
    let agent = contract
        .getAgent(agent_addr)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch agent info: {}", e))?;

    let tee_pk_hex = utils::hex_string(&agent.teePublicKey);
    let registered_at = agent.registeredAt.to_string();
    let status = if agent.active {
        "Registered (active)"
    } else {
        "Registered (inactive)"
    };

    println!("Agent: {}", agent_addr);
    println!("Status: {}", status);
    println!("TEE Public Key: {}", tee_pk_hex);
    println!("Registered At: block {}", registered_at);
    if !agent.metadataURI.is_empty() {
        println!("Metadata URI: {}", agent.metadataURI);
    }

    Ok(())
}
