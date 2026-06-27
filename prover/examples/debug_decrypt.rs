//! Local debug test for TLS decryption logic.

use anyhow::Result;
use tls_capture::capture_tls_session;

fn main() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let url = "https://api.github.com/repos/succinctlabs/sp1";
        let field = "stargazers_count";

        println!("Capturing TLS session...");
        let (session, response_body) = capture_tls_session(url, field).await?;

        println!("Server name: {}", session.server_name);
        println!(
            "Encrypted records: {} bytes",
            session.encrypted_records.len()
        );
        println!("Cert chain: {} certs", session.server_cert_chain.len());
        println!(
            "Handshake secret: {} bytes",
            session.server_handshake_traffic_secret.len()
        );
        println!(
            "App secret: {} bytes",
            session.server_application_traffic_secret.len()
        );
        println!("Field path: {}", session.field_path);
        println!(
            "Response body (first 200): {}",
            &response_body[..200.min(response_body.len())]
        );

        // Print first 100 bytes of encrypted records as hex
        println!("\nFirst 100 bytes of encrypted records:");
        for chunk in
            session.encrypted_records[..100.min(session.encrypted_records.len())].chunks(16)
        {
            print!("  ");
            for b in chunk {
                print!("{:02x} ", b);
            }
            println!();
        }

        // Parse TLS records
        let records = parse_tls_records(&session.encrypted_records);
        println!("\nParsed {} TLS records:", records.len());
        for (i, r) in records.iter().enumerate() {
            let type_name = match r.content_type {
                20 => "ChangeCipherSpec",
                21 => "Alert",
                22 => "Handshake",
                23 => "ApplicationData",
                _ => "Unknown",
            };
            println!(
                "  [{}] type={} ({}) version={:04x} len={}",
                i,
                r.content_type,
                type_name,
                r.version,
                r.data.len()
            );
        }

        Ok(())
    })
}

struct TlsRecord<'a> {
    content_type: u8,
    version: u16,
    data: &'a [u8],
}

fn parse_tls_records(data: &[u8]) -> Vec<TlsRecord> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset + 5 <= data.len() {
        let content_type = data[offset];
        let version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
        let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if offset + 5 + length > data.len() {
            break;
        }
        records.push(TlsRecord {
            content_type,
            version,
            data: &data[offset + 5..offset + 5 + length],
        });
        offset += 5 + length;
    }
    records
}
