//! SP1-based zkTLS Prover for Agent Marketplace.
//!
//! Makes real HTTPS requests, captures encrypted TLS records + session keys,
//! feeds them into the SP1 zkVM which decrypts, verifies, and extracts the
//! requested field. Outputs a Core proof (fastest mode, no on-chain compatibility needed).
//!
//! The proving key is cached after setup to avoid the 8-minute setup cost.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use num_bigint::BigUint;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sp1_sdk::{
    include_elf, utils, CpuProver, Elf, HashableKey, ProveRequest, Prover, ProvingKey,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;
use tls_capture::capture_tls_session;

const ELF: Elf = include_elf!("zk-tls-program");

// ============================================================
//  Minimal DER Parser (for extracting cert signatures)
// ============================================================

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn read_tag(&mut self) -> Option<(u8, &'a [u8])> {
        if self.pos >= self.data.len() {
            return None;
        }
        let tag = self.data[self.pos];
        self.pos += 1;
        if self.pos >= self.data.len() {
            return None;
        }
        let len = if self.data[self.pos] & 0x80 != 0 {
            let n = (self.data[self.pos] & 0x7f) as usize;
            self.pos += 1;
            let mut l = 0usize;
            for _ in 0..n {
                if self.pos >= self.data.len() {
                    return None;
                }
                l = (l << 8) | self.data[self.pos] as usize;
                self.pos += 1;
            }
            l
        } else {
            let l = self.data[self.pos] as usize;
            self.pos += 1;
            l
        };
        if self.pos + len > self.data.len() {
            return None;
        }
        let val = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some((tag, val))
    }
}

/// P-256 curve order n (big-endian).
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Precompute modular inverses for ECDSA certs in the chain.
/// For each cert, if it uses ECDSA P-256, extracts s from the signature and
/// returns w = s⁻¹ mod n as 32-byte little-endian. For RSA certs, returns empty vec.
fn precompute_inverses(cert_chain: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let n = BigUint::from_bytes_be(&P256_N);
    cert_chain
        .iter()
        .map(|cert| {
            // Parse outer SEQUENCE
            let mut outer = match DerReader::new(cert) {
                r if r.data.is_empty() => return vec![],
                r => r,
            };
            let (_tag, _tbs) = match outer.read_tag() {
                Some(v) => v,
                None => return vec![],
            };
            // Skip signatureAlgorithm
            let _ = outer.read_tag();
            // Read signatureValue (BIT STRING)
            let sig = match outer.read_tag() {
                Some((_, v)) => v,
                None => return vec![],
            };
            // BIT STRING: first byte is unused bits, rest is content
            let sig_content = if sig.first() == Some(&0) {
                &sig[1..]
            } else {
                sig
            };
            // Parse ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }
            let mut sig_rdr = DerReader::new(sig_content);
            let (_tag, seq) = match sig_rdr.read_tag() {
                Some(v) => v,
                None => return vec![],
            };
            let mut inner = DerReader::new(seq);
            let _r = match inner.read_tag() {
                Some(v) => v.1,
                None => return vec![],
            };
            let s_bytes = match inner.read_tag() {
                Some(v) => v.1,
                None => return vec![],
            };
            if s_bytes.is_empty() {
                return vec![];
            }
            // Compute w = s⁻¹ mod n
            let s = BigUint::from_bytes_be(s_bytes);
            if s.is_zero() {
                return vec![];
            }
            let w = s.modinv(&n).unwrap_or(BigUint::zero());
            if w.is_zero() {
                return vec![];
            }
            // Return as 32-byte little-endian
            let mut w_le = w.to_bytes_le();
            w_le.resize(32, 0);
            w_le
        })
        .collect()
}

#[derive(Parser)]
#[command(name = "amp-prover", about = "zkTLS Prover using SP1 zkVM")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Setup {
        #[arg(short, long, default_value = "default")]
        context: String,
        #[arg(short, long, default_value = "build")]
        output: PathBuf,
    },
    Prove {
        #[arg(short, long, default_value = "default")]
        context: String,
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        field: String,
        #[arg(short, long, default_value = "build")]
        output: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct ProofData {
    circuit: String,
    response_url: Option<String>,
    response_body: Option<String>,
    field_value: Option<u64>,
    body_hash: String,
    vk_hash: String,
    proof_hex: String,
    proof_length: usize,
}

fn context_dir(output: &PathBuf, context: &str) -> PathBuf {
    output.join(context)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

async fn load_or_create_pk(prover: &CpuProver, ctx_dir: &PathBuf) -> Result<SP1ProvingKey> {
    let vk_path = ctx_dir.join("vk.bin");
    if vk_path.exists() {
        let vk_bytes = std::fs::read(&vk_path)?;
        let vk: SP1VerifyingKey = bincode::deserialize(&vk_bytes)?;
        println!("  ✓ Loaded cached VK");
        Ok(SP1ProvingKey::new(vk, ELF))
    } else {
        println!("  Generating proving key (this takes ~8 min)...");
        let pk = prover.setup(ELF).await?;
        let vk_bytes = bincode::serialize(pk.verifying_key())?;
        std::fs::write(&vk_path, &vk_bytes)?;
        println!("  ✓ Cached VK to {}", vk_path.display());
        Ok(pk)
    }
}

async fn cmd_setup(output: &PathBuf, context: &str) -> Result<()> {
    let ctx_dir = context_dir(output, context);
    println!("Setting up SP1 prover for context: {}", context);
    std::fs::create_dir_all(&ctx_dir)?;

    let prover = CpuProver::new().await;
    let pk = load_or_create_pk(&prover, &ctx_dir).await?;

    // Export the program VK hash (identifies which program this proof is for)
    let vk_hash = pk.verifying_key().bytes32();
    let vk_path = ctx_dir.join("verification_key.hex");
    std::fs::write(&vk_path, &vk_hash)
        .with_context(|| format!("Failed to write VK hash: {}", vk_path.display()))?;

    println!("VK hash: {}", vk_hash);
    Ok(())
}

async fn cmd_prove(output: &PathBuf, context: &str, url: &str, field: &str) -> Result<ProofData> {
    let ctx_dir = context_dir(output, context);
    println!("=== Real zkTLS Proof ===");
    println!("URL:   {}", url);
    println!("Field: {}", field);

    println!("\n[1/3] Capturing TLS session...");
    let (session_data, response_body) = capture_tls_session(url, field).await?;
    println!(
        "  ✓ Encrypted records: {} bytes",
        session_data.encrypted_records.len()
    );
    println!(
        "  ✓ Cert chain: {} certs",
        session_data.server_cert_chain.len()
    );

    let json: serde_json::Value = serde_json::from_str(&response_body)?;
    let field_value = json
        .get(field)
        .and_then(|v| v.as_u64())
        .with_context(|| format!("Field '{}' not found", field))?;
    println!("  ✓ {} = {}", field, field_value);

    println!("\n[2/3] Loading proving key...");
    let prover = CpuProver::new().await;
    let pk = load_or_create_pk(&prover, &ctx_dir).await?;

    println!("\n[3/3] Generating Compressed proof...");
    let mut stdin = SP1Stdin::new();
    stdin.write(&session_data.encrypted_records);
    stdin.write(&session_data.server_handshake_traffic_secret);
    stdin.write(&session_data.server_application_traffic_secret);
    stdin.write(&session_data.server_cert_chain);
    stdin.write(&session_data.field_path);
    stdin.write(&session_data.server_name);
    let full_response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
        response_body
    );
    stdin.write(&full_response.as_bytes().to_vec());

    // Precompute modular inverses for ECDSA certs (avoid expensive bn_modinv in zkVM)
    let precomputed_inverses = precompute_inverses(&session_data.server_cert_chain);
    stdin.write(&precomputed_inverses);

    eprintln!(
        "[TIMING] Starting prover.prove() at {:?}",
        std::time::Instant::now()
    );
    let proof_with_inputs = prover.prove(&pk, stdin).compressed().await?;
    eprintln!(
        "[TIMING] prover.prove() done at {:?}",
        std::time::Instant::now()
    );
    println!("  ✓ Proof generated");

    println!("  ✓ Verifying proof...");
    prover.verify(&proof_with_inputs, pk.verifying_key(), None)?;
    println!("  ✓ Proof verified!");

    // Serialize the full proof (Core mode: Vec<ShardProof>)
    let proof_bytes =
        bincode::serialize(&proof_with_inputs).context("Failed to serialize proof")?;
    let proof_hex = bytes_to_hex(&proof_bytes);

    let vk_hash = pk.verifying_key().bytes32();

    let proof_data = ProofData {
        circuit: "sp1-zk-tls".to_string(),
        response_url: Some(url.to_string()),
        response_body: Some({
            let truncated: String = response_body.chars().take(200).collect();
            if response_body.chars().count() > 200 {
                truncated + "..."
            } else {
                truncated
            }
        }),
        field_value: Some(field_value),
        body_hash: hex::encode(sha2::Sha256::digest(response_body.as_bytes())),
        vk_hash,
        proof_hex,
        proof_length: proof_bytes.len(),
    };

    let proof_path = ctx_dir.join("proof_data.json");
    let output_json = serde_json::to_string_pretty(&proof_data)?;
    std::fs::write(&proof_path, &output_json)?;
    println!("  ✓ Proof saved to: {}", proof_path.display());

    println!("\n=== zkTLS Proof Generated ===");
    println!("Field: {} = {}", field, field_value);
    println!("Proof: {} bytes", proof_bytes.len());

    Ok(proof_data)
}

#[tokio::main]
async fn main() -> Result<()> {
    utils::setup_logger();
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup { context, output } => cmd_setup(&output, &context).await,
        Commands::Prove {
            context,
            url,
            field,
            output,
        } => {
            cmd_prove(&output, &context, &url, &field).await?;
            Ok(())
        }
    }
}
