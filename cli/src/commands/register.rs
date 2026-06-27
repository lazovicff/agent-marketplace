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

use crate::utils;

sol! {
    /// Minimal ABI for the AgentRegistry contract.
    #[sol(rpc)]
    contract AgentRegistry {
        function register(bytes calldata teePublicKey, bytes calldata attestationQuote, string calldata metadataURI) external;
        function isRegistered(address agent) external view returns (bool);
        function getAgent(address agent) external view returns (address agentAddress, bytes teePublicKey, bytes attestationQuote, string metadataURI, uint256 registeredAt, bool active);
    }
}

/// Register the agent in the on-chain Agent Registry.
#[derive(Parser)]
pub struct RegisterArgs {
    /// Ethereum RPC URL.
    #[arg(long, env = "RPC_URL", default_value = "http://localhost:8545")]
    pub rpc_url: String,

    /// Agent Registry contract address.
    #[arg(long, env = "AGENT_REGISTRY_ADDRESS")]
    pub contract_address: String,

    /// Private key for signing transactions.
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: String,

    /// TEE public key (hex-encoded).
    #[arg(long)]
    pub tee_public_key: String,

    /// TEE attestation quote (hex-encoded).
    #[arg(long)]
    pub attestation_quote: String,

    /// Optional metadata URI (e.g. IPFS).
    #[arg(long, default_value = "")]
    pub metadata_uri: String,
}

pub async fn run(args: RegisterArgs) -> anyhow::Result<()> {
    info!("Registering agent in Agent Registry...");
    info!("  Contract: {}", args.contract_address);

    // Parse the contract address
    let contract_addr: Address = args
        .contract_address
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid contract address: {}", e))?;

    // Create a basic HTTP provider for read-only calls
    let provider: RootProvider<Http<Client>> = ProviderBuilder::default().on_http(
        args.rpc_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid RPC URL: {}", e))?,
    );

    // Build the contract instance for read-only calls
    let contract = AgentRegistry::new(contract_addr, &provider);

    // Create the signer
    let pk_hex = args
        .private_key
        .strip_prefix("0x")
        .unwrap_or(&args.private_key);
    let secret_key = alloy::signers::k256::SecretKey::from_slice(&hex::decode(pk_hex)?)?;
    let signer = PrivateKeySigner::from(secret_key);
    let caller = signer.address();

    // Check if already registered
    let is_registered = contract
        .isRegistered(caller)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check registration: {}", e))?
        ._0;

    if is_registered {
        info!("Agent is already registered at {}", caller);
        return Ok(());
    }

    // Parse the TEE public key and attestation quote
    let tee_pk: Bytes = args
        .tee_public_key
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid TEE public key hex: {}", e))?;
    let attestation: Bytes = args
        .attestation_quote
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid attestation quote hex: {}", e))?;

    // Encode the register call data
    let call = AgentRegistry::registerCall {
        teePublicKey: tee_pk,
        attestationQuote: attestation,
        metadataURI: args.metadata_uri.clone(),
    };
    let calldata = call.abi_encode();

    // Get chain ID, nonce, and gas price
    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(caller).await?;
    let gas_price = provider.get_gas_price().await?;

    // Build a legacy transaction
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

    // Sign the transaction
    let signature = signer.sign_transaction(&mut tx).await?;
    let signed_tx = tx.into_signed(signature);
    let envelope = TxEnvelope::Legacy(signed_tx);

    // RLP-encode and send
    let encoded = alloy::rlp::encode(&envelope);
    let tx_hash = provider.send_raw_transaction(&encoded).await?;

    info!("✅ Agent registered successfully!");
    info!("  Address: {}", caller);
    info!("  Tx:      {:?}", tx_hash);

    Ok(())
}
