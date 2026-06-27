//! Verify decryption with aes-gcm crate.
//! Run with: cargo run --example debug_aes

use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha384;
use tls_capture::capture_tls_session;

fn hkdflabel(label: &[u8], ctx: &[u8], len: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&len.to_be_bytes());
    let f = [b"tls13 ", label].concat();
    v.push(f.len() as u8);
    v.extend_from_slice(&f);
    v.push(ctx.len() as u8);
    v.extend_from_slice(ctx);
    v
}

fn parse_tls_records(data: &[u8]) -> Vec<(u8, u16, &[u8])> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset + 5 <= data.len() {
        let content_type = data[offset];
        let version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
        let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if offset + 5 + length > data.len() {
            break;
        }
        records.push((
            content_type,
            version,
            &data[offset + 5..offset + 5 + length],
        ));
        offset += 5 + length;
    }
    records
}

fn main() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let url = "https://api.github.com/repos/succinctlabs/sp1";
        let field = "stargazers_count";

        let (session, _) = capture_tls_session(url, field).await?;
        let records = parse_tls_records(&session.encrypted_records);

        let mut ccs_seen = false;
        for (i, (ct, ver, data)) in records.iter().enumerate() {
            if *ct == 20 { ccs_seen = true; continue; }
            if !ccs_seen { continue; }
            if *ct != 23 { continue; }

            println!("=== Record {}: type={} len={} ===", i, ct, data.len());

            // Derive key with from_prk
            let hkdf = Hkdf::<Sha384>::from_prk(&session.server_handshake_traffic_secret).unwrap();
            let mut key = [0u8; 32];
            let mut iv = [0u8; 12];
            hkdf.expand(&hkdflabel(b"key", b"", 32), &mut key).unwrap();
            hkdf.expand(&hkdflabel(b"iv", b"", 12), &mut iv).unwrap();

            // Build nonce for seq=0
            let seq: u64 = 0;
            let seq_bytes = seq.to_be_bytes();
            let mut nonce = iv;
            for j in 0..8 { nonce[4 + j] ^= seq_bytes[j]; }

            // Build AAD
            let data_len = data.len() as u16;
            let mut aad = Vec::new();
            aad.extend_from_slice(&seq_bytes);
            aad.push(*ct);
            aad.extend_from_slice(&ver.to_be_bytes());
            aad.extend_from_slice(&data_len.to_be_bytes());

            println!("Key: {}", hex::encode(key));
            println!("Nonce: {}", hex::encode(nonce));
            println!("AAD: {}", hex::encode(&aad));
            println!("CT ({} bytes): {}", data.len(), hex::encode(data));

            // Try decrypting with aes-gcm crate using raw API
            // Use openssl command-line as a reference
            println!("\nTo verify with openssl:");
            println!("  echo '{}' | xxd -r -p > /tmp/ct.bin", hex::encode(data));
            println!("  echo '{}' | xxd -r -p > /tmp/key.bin", hex::encode(key));
            println!("  echo '{}' | xxd -r -p > /tmp/nonce.bin", hex::encode(nonce));
            println!("  echo '{}' | xxd -r -p > /tmp/aad.bin", hex::encode(&aad));
            println!("  openssl enc -aes-256-gcm -d -in /tmp/ct.bin -K $(xxd -p /tmp/key.bin | tr -d '\\n') -iv $(xxd -p /tmp/nonce.bin | tr -d '\\n') -nopad 2>&1 || true");

            break;
        }

        Ok(())
    })
}
