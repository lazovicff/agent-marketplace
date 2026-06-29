// ============================================================
//  ECDSA P-256 (secp256r1) Signature Verification
//
//  Uses the `p256` crate (pure Rust, specifically for P-256).
// ============================================================

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Verify an ECDSA P-256 signature using SHA-256.
pub fn verify_ecdsa_p256(message: &[u8], sig_der: &[u8], pubkey_point: &[u8; 64]) -> bool {
    // Build SEC1-encoded public key: 0x04 || x (32 bytes) || y (32 bytes)
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&pubkey_point[..32]);
    sec1.extend_from_slice(&pubkey_point[32..]);

    let verifying_key = match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    let signature = match Signature::from_der(sig_der) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let hash = Sha256::digest(message);
    verifying_key.verify_prehash(&hash, &signature).is_ok()
}
