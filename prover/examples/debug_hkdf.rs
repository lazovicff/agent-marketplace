//! Verify HKDF-Expand implementation.
//! Run with: cargo run --example debug_hkdf

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha384;
use tls_capture::capture_tls_session;

type HmacSha384 = Hmac<Sha384>;

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

/// Manual HKDF-Expand implementation
fn hkdf_expand_manual(prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hash_len = 48; // SHA-384
    let n = (out_len + hash_len - 1) / hash_len;
    let mut output = Vec::new();
    let mut t = Vec::new();

    for i in 1..=n {
        let mut mac = HmacSha384::new_from_slice(prk).expect("HMAC key");
        mac.update(&t);
        mac.update(info);
        mac.update(&[i as u8]);
        t = mac.finalize().into_bytes().to_vec();
        output.extend_from_slice(&t);
    }

    output.truncate(out_len);
    output
}

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let url = "https://api.github.com/repos/succinctlabs/sp1";
        let field = "stargazers_count";

        let (session, _) = capture_tls_session(url, field).await.unwrap();
        let secret = &session.server_handshake_traffic_secret;

        println!("Secret ({} bytes): {}", secret.len(), hex::encode(secret));

        // Test with from_prk (correct label: just "key", hkdflabel adds "tls13 " prefix)
        let hkdf = Hkdf::<Sha384>::from_prk(secret).expect("from_prk failed");
        let info = hkdflabel(b"key", b"", 32);
        println!("\nInfo ({} bytes): {}", info.len(), hex::encode(&info));

        let mut key_crate = [0u8; 32];
        hkdf.expand(&info, &mut key_crate).unwrap();
        println!("Key (crate): {}", hex::encode(key_crate));

        // Manual HKDF-Expand
        let key_manual = hkdf_expand_manual(secret, &info, 32);
        println!("Key (manual): {}", hex::encode(&key_manual));
        println!("Match: {}", key_crate == key_manual[..]);

        // Also test with new(None, secret)
        let hkdf2 = Hkdf::<Sha384>::new(None, secret);
        let mut key_crate2 = [0u8; 32];
        hkdf2.expand(&info, &mut key_crate2).unwrap();
        println!("\nKey (crate, new): {}", hex::encode(key_crate2));

        // Manual HKDF-Extract + Expand
        // HKDF-Extract with empty salt: PRK = HMAC-SHA384("", secret)
        let mut mac = HmacSha384::new_from_slice(&[]).expect("HMAC key");
        mac.update(secret);
        let prk = mac.finalize().into_bytes();
        println!(
            "PRK after extract ({} bytes): {}",
            prk.len(),
            hex::encode(&prk[..])
        );

        let key_manual2 = hkdf_expand_manual(&prk, &info, 32);
        println!("Key (manual, new): {}", hex::encode(&key_manual2));
        println!("Match: {}", key_crate2 == key_manual2[..]);
    });
}
