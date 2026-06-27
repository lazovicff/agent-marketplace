//! Local debug: test TLS decryption outside zkVM.
//! Run with: cargo run --example debug_decrypt2

use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha384;
use tls_capture::capture_tls_session;

fn main() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let url = "https://api.github.com/repos/succinctlabs/sp1";
        let field = "stargazers_count";

        println!("Capturing TLS session...");
        let (session, _response_body) = capture_tls_session(url, field).await?;

        let hs_secret = &session.server_handshake_traffic_secret;
        let app_secret = &session.server_application_traffic_secret;

        println!("Handshake secret: {} bytes", hs_secret.len());
        println!("App secret: {} bytes", app_secret.len());

        // Try both HKDF approaches
        println!("\n=== Testing HKDF approaches ===");

        // Approach 1: from_prk (correct per TLS 1.3 spec)
        match Hkdf::<Sha384>::from_prk(hs_secret) {
            Ok(hkdf) => {
                let mut key = [0u8; 32];
                let mut iv = [0u8; 12];
                hkdf.expand(&hkdflabel(b"tls13 key", b"", 32), &mut key)
                    .unwrap();
                hkdf.expand(&hkdflabel(b"tls13 iv", b"", 12), &mut iv)
                    .unwrap();
                println!(
                    "from_prk OK: key={} iv={}",
                    hex::encode(key),
                    hex::encode(iv)
                );
            }
            Err(e) => {
                println!("from_prk FAILED: {:?}", e);
            }
        }

        // Approach 2: new(None, secret) — HKDF-Extract first
        let hkdf2 = Hkdf::<Sha384>::new(None, hs_secret);
        let mut key2 = [0u8; 32];
        let mut iv2 = [0u8; 12];
        hkdf2
            .expand(&hkdflabel(b"tls13 key", b"", 32), &mut key2)
            .unwrap();
        hkdf2
            .expand(&hkdflabel(b"tls13 iv", b"", 12), &mut iv2)
            .unwrap();
        println!(
            "new(None)  OK: key={} iv={}",
            hex::encode(key2),
            hex::encode(iv2)
        );

        // Also test app secret
        println!("\n=== App secret HKDF ===");
        match Hkdf::<Sha384>::from_prk(app_secret) {
            Ok(hkdf) => {
                let mut key = [0u8; 32];
                let mut iv = [0u8; 12];
                hkdf.expand(&hkdflabel(b"tls13 key", b"", 32), &mut key)
                    .unwrap();
                hkdf.expand(&hkdflabel(b"tls13 iv", b"", 12), &mut iv)
                    .unwrap();
                println!(
                    "from_prk OK: key={} iv={}",
                    hex::encode(key),
                    hex::encode(iv)
                );
            }
            Err(e) => {
                println!("from_prk FAILED: {:?}", e);
            }
        }

        Ok(())
    })
}

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
