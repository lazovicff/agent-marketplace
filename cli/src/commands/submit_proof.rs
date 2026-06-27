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
    /// Minimal ABI for the TaskContract.
    #[sol(rpc)]
    contract TaskContract {
        function submitProof(uint256 taskId, bytes calldata proof, bytes calldata publicInputs) external;
        function getTask(uint256 taskId) external view returns (uint256 id, address poster, string description, uint256 reward, uint256 schemaId, uint256 deadline, uint256 createdAt, uint8 status, address executor, bytes proof, bool proofVerified);
    }
}

/// Submit a zkTLS proof for a task.
#[derive(Parser)]
pub struct SubmitProofArgs {
    /// Ethereum RPC URL.
    #[arg(long, env = "RPC_URL", default_value = "http://localhost:8545")]
    pub rpc_url: String,

    /// Task contract address.
    #[arg(long, env = "TASK_CONTRACT_ADDRESS")]
    pub contract_address: String,

    /// Private key for signing transactions.
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: String,

    /// Task ID to submit the proof for.
    #[arg(long)]
    pub task_id: u64,

    /// Path to the proof file (binary).
    #[arg(long)]
    pub proof_file: String,

    /// Path to the public inputs file (raw ABI-encoded bytes).
    #[arg(long)]
    pub public_inputs_file: String,
}

pub async fn run(args: SubmitProofArgs) -> anyhow::Result<()> {
    info!("Submitting zkTLS proof for task #{}...", args.task_id);
    info!("  Contract: {}", args.contract_address);
    info!("  Proof file: {}", args.proof_file);
    info!("  Inputs file: {}", args.public_inputs_file);

    // Parse the contract address
    let contract_addr: Address = args
        .contract_address
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid contract address: {}", e))?;

    // Create the signer
    let pk_hex = args
        .private_key
        .strip_prefix("0x")
        .unwrap_or(&args.private_key);
    let secret_key = alloy::signers::k256::SecretKey::from_slice(&hex::decode(pk_hex)?)?;
    let signer = PrivateKeySigner::from(secret_key);
    let caller = signer.address();

    // Create a basic HTTP provider
    let provider: RootProvider<Http<Client>> = ProviderBuilder::default().on_http(
        args.rpc_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid RPC URL: {}", e))?,
    );

    // Build the contract instance for read-only calls
    let contract = TaskContract::new(contract_addr, &provider);

    // Fetch the task to verify it exists and is in the right state
    let task = contract
        .getTask(U256::from(args.task_id))
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch task: {}", e))?;

    info!("  Task status: {}", task.status);
    info!("  Task executor: {:?}", task.executor);

    // Read the proof file
    let proof_bytes = tokio::fs::read(&args.proof_file)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read proof file: {}", e))?;

    // Read the public inputs file (raw ABI-encoded bytes)
    let inputs_bytes = tokio::fs::read(&args.public_inputs_file)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read public inputs file: {}", e))?;

    // Encode the submitProof call data
    let call = TaskContract::submitProofCall {
        taskId: U256::from(args.task_id),
        proof: Bytes::from(proof_bytes),
        publicInputs: Bytes::from(inputs_bytes),
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

    info!("✅ Proof submitted successfully!");
    info!("  Task ID: {}", args.task_id);
    info!("  Tx:      {:?}", tx_hash);

    Ok(())
}
