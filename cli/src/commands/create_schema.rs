use alloy::consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy::network::TxSigner;
use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy::transports::http::{Client, Http};
use clap::Parser;
use tracing::info;

sol! {
    /// Minimal ABI for the SchemaRegistry contract.
    #[sol(rpc)]
    contract SchemaRegistry {
        function addSchema(string calldata name, string calldata description, string calldata serverHost, string calldata requestSchema, string calldata responseSchema) external returns (uint256 schemaId);
        function getSchema(uint256 schemaId) external view returns (uint256 id, string name, string description, string serverHost, string requestSchema, string responseSchema, address creator, uint256 createdAt, bool active);
    }
}

/// Create a new zkTLS schema.
///
/// Schemas define the request/response format for a zkTLS proof.
/// No verification key is needed — the universal zkTLS circuit handles
/// all schemas with a single VK.
#[derive(Parser)]
pub struct CreateSchemaArgs {
    /// Ethereum RPC URL.
    #[arg(long, env = "RPC_URL", default_value = "http://localhost:8545")]
    pub rpc_url: String,

    /// Schema Registry contract address.
    #[arg(long, env = "SCHEMA_REGISTRY_ADDRESS")]
    pub contract_address: String,

    /// Private key for signing transactions.
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: String,

    /// Schema name (e.g. "github-stars").
    #[arg(long)]
    pub name: String,

    /// Human-readable description.
    #[arg(long)]
    pub description: String,

    /// TLS server hostname (e.g. "api.github.com").
    #[arg(long)]
    pub server_host: String,

    /// Path to the request schema JSON file.
    #[arg(long)]
    pub request_schema: String,

    /// Path to the response schema JSON file.
    #[arg(long)]
    pub response_schema: String,
}

pub async fn run(args: CreateSchemaArgs) -> anyhow::Result<()> {
    info!("Creating new zkTLS schema...");
    info!("  Name:        {}", args.name);
    info!("  Server host: {}", args.server_host);
    info!("  Contract:    {}", args.contract_address);

    let contract_addr: Address = args
        .contract_address
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid contract address: {}", e))?;

    let pk_hex = args
        .private_key
        .strip_prefix("0x")
        .unwrap_or(&args.private_key);
    let secret_key = alloy::signers::k256::SecretKey::from_slice(&hex::decode(pk_hex)?)?;
    let signer = PrivateKeySigner::from(secret_key);
    let caller = signer.address();

    let provider: RootProvider<Http<Client>> = ProviderBuilder::default().on_http(
        args.rpc_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid RPC URL: {}", e))?,
    );

    let request_schema = tokio::fs::read_to_string(&args.request_schema)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read request schema: {}", e))?;

    let response_schema = tokio::fs::read_to_string(&args.response_schema)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read response schema: {}", e))?;

    let call = SchemaRegistry::addSchemaCall {
        name: args.name.clone(),
        description: args.description.clone(),
        serverHost: args.server_host.clone(),
        requestSchema: request_schema,
        responseSchema: response_schema,
    };
    let calldata = call.abi_encode();

    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(caller).await?;
    let gas_price = provider.get_gas_price().await?;

    let mut tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: gas_price as u128,
        gas_limit: 200_000,
        to: TxKind::Call(contract_addr),
        value: U256::ZERO,
        input: calldata.into(),
        ..Default::default()
    };

    let signature = signer.sign_transaction(&mut tx).await?;
    let signed_tx = tx.into_signed(signature);
    let envelope = TxEnvelope::Legacy(signed_tx);

    let encoded = alloy::rlp::encode(&envelope);
    let tx_hash = provider.send_raw_transaction(&encoded).await?;

    info!("✅ Schema created successfully!");
    info!("  Name: {}", args.name);
    info!("  Tx:   {:?}", tx_hash);

    Ok(())
}
