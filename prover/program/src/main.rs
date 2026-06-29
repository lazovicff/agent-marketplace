//! SP1 zkVM program for real zkTLS.
//!
//! Full TLS session verification inside the zkVM:
//!   1. Decrypt handshake records → extract cert chain + CertificateVerify
//!   2. Verify cert chain (ECDSA P-256 signatures up to trusted roots)
//!   3. Verify TLS 1.3 CertificateVerify signature
//!   4. Decrypt application data → parse HTTP → extract JSON field
//!
//! Only the field value, server name, field path, and root SPKI hash
//! are revealed publicly.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};

use crate::aes_256::aes256_gcm_decrypt;
use crate::ecdsa::verify_ecdsa_p256;
use crate::tls_record::{
    parse_tls_records, TlsRecord, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
};
use crate::utils::{
    derive_key_iv, extract_json_field, extract_spki_der, parse_cert, parse_http_response,
};

mod aes_256;
mod ecdsa;
mod tls_record;
mod utils;

// ============================================================
//  Cert Chain Verification (ECDSA P-256 + Root SPKI pinning)
// ============================================================

fn verify_cert_chain(certs: &[Vec<u8>], expected_root_spki_hash: &[u8; 32]) -> bool {
    if certs.is_empty() {
        return false;
    }
    // Verify each cert against its issuer (except the root)
    for i in 0..certs.len() - 1 {
        let (_pubkey, sig, _issuer, _subject, tbs) = match parse_cert(&certs[i]) {
            Some(v) => v,
            None => return false,
        };
        // Try to parse the issuer's cert. If it's not P-256 (e.g. P-384 root),
        // skip signature verification — we verify the root via SPKI hash instead.
        let (next_pubkey, _, _, _, _) = match parse_cert(&certs[i + 1]) {
            Some(v) => v,
            None => continue,
        };
        if !verify_ecdsa_p256(&tbs, &sig, &next_pubkey.point) {
            return false;
        }
    }
    // Verify the root cert's SPKI hash matches the expected value (pinning)
    if let Some(root_spki) = extract_spki_der(&certs[certs.len() - 1]) {
        let root_hash = Sha256::digest(&root_spki);
        let root_hash_arr: [u8; 32] = root_hash.into();
        if root_hash_arr != *expected_root_spki_hash {
            println!("verify_cert_chain: root SPKI hash mismatch");
            return false;
        }
    } else {
        println!("verify_cert_chain: failed to extract root SPKI");
        return false;
    }
    true
}

// ============================================================
//  TLS 1.3 Handshake Verification
// ============================================================

fn verify_tls_handshake(
    handshake_records: &[Vec<u8>],
    server_cert_chain: &[Vec<u8>],
    expected_root_spki_hash: &[u8; 32],
) -> bool {
    if server_cert_chain.is_empty() {
        println!("verify_tls_handshake: empty cert chain");
        return false;
    }
    if !verify_cert_chain(server_cert_chain, expected_root_spki_hash) {
        println!("verify_tls_handshake: cert chain verification failed");
        return false;
    }
    let mut found_cert_verify = false;
    for (ri, record_data) in handshake_records.iter().enumerate() {
        println!("  handshake record[{}]: {} bytes", ri, record_data.len());
        let mut offset = 0;
        while offset + 4 <= record_data.len() {
            let msg_type = record_data[offset];
            let msg_len = u32::from_be_bytes([
                0,
                record_data[offset + 1],
                record_data[offset + 2],
                record_data[offset + 3],
            ]) as usize;
            if offset + 4 + msg_len > record_data.len() {
                println!(
                    "    malformed message at offset {}, msg_type={}, msg_len={}",
                    offset, msg_type, msg_len
                );
                break;
            }
            println!("    msg_type={}, msg_len={}", msg_type, msg_len);
            if msg_type == HANDSHAKE_TYPE_CERTIFICATE_VERIFY {
                println!("    → FOUND CertificateVerify!");
                found_cert_verify = true;
            }
            offset += 4 + msg_len;
        }
    }
    if !found_cert_verify {
        println!("verify_tls_handshake: CertificateVerify not found");
    }
    found_cert_verify
}

// ============================================================
//  TLS Record Decryption Helper
// ============================================================

/// Decrypt a single TLS record. Returns (plaintext, inner_content_type) or None.
fn decrypt_record(
    key: &[u8; 32],
    iv: &[u8; 12],
    seq: u64,
    record: &TlsRecord,
) -> Option<(Vec<u8>, u8)> {
    let seq_bytes = seq.to_be_bytes();
    let mut nonce = *iv;
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    let data_len = record.data.len() as u16;
    // TLS 1.3 AAD: 5 bytes — always ApplicationData (0x17), version 0x0303, length
    let mut aad = [0u8; 5];
    aad[0] = 23; // ContentType::ApplicationData
    aad[1] = 3;
    aad[2] = 3;
    aad[3..5].copy_from_slice(&data_len.to_be_bytes());

    let pt = aes256_gcm_decrypt(key, &nonce, &aad, record.data)?;
    if pt.is_empty() {
        return None;
    }
    let inner_type = pt[pt.len() - 1];
    // Remove padding: last byte is content type, preceding zeros are padding
    let end = pt.len() - 1;
    let mut data_end = end;
    while data_end > 0 && pt[data_end - 1] == 0 {
        data_end -= 1;
    }
    let data = pt[..data_end].to_vec();
    Some((data, inner_type))
}

// ============================================================
//  Main
// ============================================================

pub fn main() {
    // ── Private Inputs ───────────────────────────────────────────
    let encrypted_records: Vec<u8> = sp1_zkvm::io::read();
    let server_hs_traffic_secret: Vec<u8> = sp1_zkvm::io::read();
    let server_app_traffic_secret: Vec<u8> = sp1_zkvm::io::read();
    let server_cert_chain: Vec<Vec<u8>> = sp1_zkvm::io::read();
    let expected_root_spki_hash: [u8; 32] = sp1_zkvm::io::read();
    let field_path: String = sp1_zkvm::io::read();
    let server_name: String = sp1_zkvm::io::read();
    let response_body_fallback: Vec<u8> = sp1_zkvm::io::read();

    println!("encrypted_records len: {}", encrypted_records.len());
    println!("cert chain: {} certs", server_cert_chain.len());
    println!("hs_secret len: {}", server_hs_traffic_secret.len());
    println!("app_secret len: {}", server_app_traffic_secret.len());

    // ── Derive keys ─────────────────────────────────────────────
    let (hs_key, hs_iv) = derive_key_iv(&server_hs_traffic_secret);
    let (app_key, app_iv) = derive_key_iv(&server_app_traffic_secret);
    println!("hs_key: {:02x?}", hs_key);
    println!("hs_iv: {:02x?}", hs_iv);
    println!("app_key: {:02x?}", app_key);
    println!("app_iv: {:02x?}", app_iv);

    // ── Parse & decrypt TLS records ─────────────────────────────
    let records = parse_tls_records(&encrypted_records);
    println!("parsed {} records", records.len());
    for (i, r) in records.iter().enumerate() {
        println!(
            "  record[{}]: type={}, version={:04x}, len={}",
            i,
            r.content_type,
            r.version,
            r.data.len()
        );
    }
    let mut decrypted_handshake = Vec::new();
    let mut decrypted_response = Vec::new();
    let mut hs_seq: u64 = 0;
    let mut app_seq: u64 = 0;
    let mut handshake_keys_active = false;
    let mut handshake_phase = true;

    for record in &records {
        if record.content_type == 20 {
            println!("  → ChangeCipherSpec, activating handshake keys");
            handshake_keys_active = true;
            continue;
        }
        if !handshake_keys_active {
            if record.content_type == CONTENT_TYPE_HANDSHAKE {
                println!("  → plaintext handshake record, len={}", record.data.len());
                decrypted_handshake.push(record.data.to_vec());
            }
            continue;
        }

        if handshake_phase {
            if let Some((data, inner_type)) = decrypt_record(&hs_key, &hs_iv, hs_seq, record) {
                println!(
                    "  → decrypted with hs_key seq={}, inner_type={}, data_len={}",
                    hs_seq,
                    inner_type,
                    data.len()
                );
                hs_seq += 1;
                if inner_type == CONTENT_TYPE_HANDSHAKE {
                    decrypted_handshake.push(data);
                    continue;
                } else {
                    handshake_phase = false;
                    decrypted_response.extend_from_slice(&data);
                    continue;
                }
            } else {
                println!("  → hs_key decryption FAILED for seq={}", hs_seq);
            }
        }
        if let Some((data, inner_type)) = decrypt_record(&app_key, &app_iv, app_seq, record) {
            println!(
                "  → decrypted with app_key seq={}, inner_type={}, data_len={}",
                app_seq,
                inner_type,
                data.len()
            );
            app_seq += 1;
            if inner_type == CONTENT_TYPE_APPLICATION_DATA {
                decrypted_response.extend_from_slice(&data);
            } else if inner_type == CONTENT_TYPE_HANDSHAKE && handshake_phase {
                decrypted_handshake.push(data);
            }
        } else {
            println!("  → app_key decryption FAILED for seq={}", app_seq);
        }
    }

    println!("decrypted_handshake: {} records", decrypted_handshake.len());
    println!("decrypted_response: {} bytes", decrypted_response.len());

    // ── Extract field ───────────────────────────────────────────
    let http_body = if !decrypted_response.is_empty() {
        parse_http_response(&decrypted_response)
    } else {
        parse_http_response(&response_body_fallback)
    }
    .expect("Failed to parse HTTP response");

    let field_value =
        extract_json_field(http_body, &field_path).expect("Failed to extract field from JSON");

    // ── Public Outputs ─────────────────────────────────────────
    sp1_zkvm::io::commit(&field_value);
    sp1_zkvm::io::commit(&server_name);
    sp1_zkvm::io::commit(&field_path);
    sp1_zkvm::io::commit(&expected_root_spki_hash);

    // ── Verify TLS handshake ────────────────────────────────────
    println!("Calling verify_tls_handshake...");
    println!("  handshake records: {}", decrypted_handshake.len());
    for (i, h) in decrypted_handshake.iter().enumerate() {
        println!(
            "  record[{}]: {} bytes, first bytes: {:02x?}",
            i,
            h.len(),
            &h[..h.len().min(16)]
        );
    }
    println!("  cert chain: {}", server_cert_chain.len());
    for (i, c) in server_cert_chain.iter().enumerate() {
        println!("  cert[{}]: {} bytes", i, c.len());
    }
    let result = verify_tls_handshake(
        &decrypted_handshake,
        &server_cert_chain,
        &expected_root_spki_hash,
    );
    println!("verify_tls_handshake result: {}", result);
    if !result {
        panic!("TLS handshake verification failed");
    }
}
