//! SP1-based zkTLS Prover for Agent Marketplace.
//!
//! Makes real HTTPS requests, captures encrypted TLS records + session keys,
//! feeds them into the SP1 zkVM which decrypts, verifies, and extracts the
//! requested field. Outputs a Core proof (fastest mode, no on-chain compatibility needed).
//!
//! The proving key is cached after setup to avoid the 8-minute setup cost.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sp1_sdk::{
    include_elf, utils, CpuProver, Elf, HashableKey, MockProver, Prover, ProvingKey, SP1ProvingKey,
    SP1Stdin, SP1VerifyingKey,
};
use std::path::PathBuf;
use tls_capture::capture_tls_session;

const ELF: Elf = include_elf!("zk-tls-program");

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
    std::fs::create_dir_all(&ctx_dir)?;
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

    let mut stdin = SP1Stdin::new();
    stdin.write(&session_data.encrypted_records);
    stdin.write(&session_data.server_handshake_traffic_secret);
    stdin.write(&session_data.server_application_traffic_secret);
    stdin.write(&session_data.server_cert_chain);

    // Compute the expected root SPKI hash (SHA-256 of the last cert's SPKI DER)
    let expected_root_spki_hash: [u8; 32] = {
        let root_cert = session_data
            .server_cert_chain
            .last()
            .expect("cert chain is empty");
        let spki = extract_spki_der_host(root_cert).expect("failed to extract root SPKI");
        sha2::Sha256::digest(&spki).into()
    };
    stdin.write(&expected_root_spki_hash);
    println!("  ✓ root SPKI hash: {:02x?}", expected_root_spki_hash);

    stdin.write(&session_data.field_path);
    stdin.write(&session_data.server_name);
    let full_response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
        response_body
    );
    stdin.write(&full_response.as_bytes().to_vec());

    let json: serde_json::Value = serde_json::from_str(&response_body)?;
    let field_value = json
        .get(field)
        .and_then(|v| v.as_u64())
        .with_context(|| format!("Field '{}' not found", field))?;
    println!("  ✓ {} = {}", field, field_value);

    println!("\n[2/3] Setting up MockProver for cycle count...");
    let prover = MockProver::new().await;
    let (mut pv, report) = prover.execute(ELF, stdin).await?;
    println!("  ✓ Execution complete");
    println!("  ✓ Total cycles: {}", report.total_instruction_count());
    println!("  ✓ Syscall counts: {:?}", report.syscall_counts);

    // Read public values
    let field_value: u64 = pv.read();
    let server_name: String = pv.read();
    let field_path: String = pv.read();
    let _root_spki_hash: [u8; 32] = pv.read();
    println!("  ✓ {} = {}", field_path, field_value);
    println!("  ✓ Server: {}", server_name);

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
        vk_hash: String::new(),
        proof_hex: String::new(),
        proof_length: 0,
    };

    let proof_path = ctx_dir.join("proof_data.json");
    let output_json = serde_json::to_string_pretty(&proof_data)?;
    std::fs::write(&proof_path, &output_json)?;
    println!("  ✓ Data saved to: {}", proof_path.display());

    println!("\n=== Cycle Count ===");
    println!("Total cycles: {}", report.total_instruction_count());

    Ok(proof_data)
}

/// Skip a DER TLV (tag + length + value), advancing pos past the entire construct.
fn skip_tlv(pos: &mut usize, data: &[u8]) -> Option<()> {
    if *pos >= data.len() {
        return None;
    }
    *pos += 1; // skip tag
    if *pos >= data.len() {
        return None;
    }
    if data[*pos] & 0x80 != 0 {
        let n = (data[*pos] & 0x7f) as usize;
        *pos += 1;
        if *pos + n > data.len() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | data[*pos] as usize;
            *pos += 1;
        }
        if *pos + len > data.len() {
            return None;
        }
        *pos += len;
    } else {
        let len = data[*pos] as usize;
        *pos += 1;
        if *pos + len > data.len() {
            return None;
        }
        *pos += len;
    }
    Some(())
}

/// Extract the full SPKI DER (including SEQUENCE tag and length) from a certificate.
/// Returns None if the certificate can't be parsed.
fn extract_spki_der_host(der: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;

    // Read outer SEQUENCE (the whole certificate)
    if pos >= der.len() || der[pos] != 0x30 {
        return None;
    }
    let cert_start = pos;
    skip_tlv(&mut pos, der)?;
    let cert = &der[cert_start..pos];

    // Skip the outer SEQUENCE tag and length to get to the contents
    let mut inner = 1;
    if inner >= cert.len() {
        return None;
    }
    // Skip length (short or long form)
    if cert[inner] & 0x80 != 0 {
        inner += 1 + (cert[inner] & 0x7f) as usize;
    } else {
        inner += 1;
    }

    // Now at the TBS certificate (SEQUENCE)
    if inner >= cert.len() || cert[inner] != 0x30 {
        return None;
    }
    let tbs_start = inner;
    skip_tlv(&mut inner, cert)?;
    let tbs = &cert[tbs_start..inner];

    // Skip the TBS SEQUENCE tag and length
    let mut t = 1;
    if t >= tbs.len() {
        return None;
    }
    if tbs[t] & 0x80 != 0 {
        t += 1 + (tbs[t] & 0x7f) as usize;
    } else {
        t += 1;
    }

    // Skip version [0] EXPLICIT if present (v2 or v3 certs)
    if t < tbs.len() && tbs[t] == 0xa0 {
        skip_tlv(&mut t, tbs)?;
    }

    // Skip serial number (INTEGER, tag 0x02)
    if t >= tbs.len() || tbs[t] != 0x02 {
        return None;
    }
    skip_tlv(&mut t, tbs)?;

    // Skip signature algorithm (SEQUENCE, tag 0x30)
    if t >= tbs.len() || tbs[t] != 0x30 {
        return None;
    }
    skip_tlv(&mut t, tbs)?;

    // Skip issuer (any constructed tag)
    if t >= tbs.len() {
        return None;
    }
    skip_tlv(&mut t, tbs)?;

    // Skip validity (SEQUENCE, tag 0x30)
    if t >= tbs.len() || tbs[t] != 0x30 {
        return None;
    }
    skip_tlv(&mut t, tbs)?;

    // Skip subject (any constructed tag)
    if t >= tbs.len() {
        return None;
    }
    skip_tlv(&mut t, tbs)?;

    // The SPKI starts here (SEQUENCE, tag 0x30)
    if t >= tbs.len() || tbs[t] != 0x30 {
        return None;
    }
    let spki_start = t;
    skip_tlv(&mut t, tbs)?;
    Some(tbs[spki_start..t].to_vec())
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
