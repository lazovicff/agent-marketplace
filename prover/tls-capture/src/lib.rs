//! TLS session capture for zkTLS proof generation.
//!
//! Makes an HTTPS request using raw rustls::ClientConnection with a
//! custom Read/Write wrapper that captures ALL encrypted TLS records.
//! The captured data + session keys are fed into the SP1 zkVM which
//! decrypts, verifies, and extracts the field.

use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, KeyLog};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::task::spawn_blocking;

// ============================================================
//  Data Structures
// ============================================================

/// Captured TLS session data — private input to the SP1 program.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsSessionData {
    pub server_name: String,
    pub server_cert_chain: Vec<Vec<u8>>,
    pub server_handshake_traffic_secret: Vec<u8>,
    pub server_application_traffic_secret: Vec<u8>,
    /// ALL encrypted TLS records captured from the wire
    pub encrypted_records: Vec<u8>,
    pub http_request: Vec<u8>,
    pub field_path: String,
}

// ============================================================
//  Key Log
// ============================================================

#[derive(Debug)]
struct CaptureKeyLog {
    captured: Mutex<Vec<(String, Vec<u8>, Vec<u8>)>>,
}

impl CaptureKeyLog {
    fn new() -> Self {
        Self {
            captured: Mutex::new(Vec::new()),
        }
    }
}

impl KeyLog for CaptureKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Ok(mut captured) = self.captured.lock() {
            captured.push((label.to_string(), client_random.to_vec(), secret.to_vec()));
        }
    }
}

// ============================================================
//  Capture Stream
// ============================================================

#[derive(Debug)]
struct CaptureStream {
    inner: TcpStream,
    captured: Vec<u8>,
}

impl CaptureStream {
    fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            captured: Vec::new(),
        }
    }

    fn take_captured(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.captured)
    }
}

impl Read for CaptureStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.captured.extend_from_slice(&buf[..n]);
        }
        Ok(n)
    }
}

impl Write for CaptureStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Only capture server→client data (reads), not client→server (writes).
        // Client records (ClientHello, client ChangeCipherSpec, client Finished)
        // would interfere with server handshake record processing.
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// ============================================================
//  TLS Capture
// ============================================================

pub async fn capture_tls_session(url: &str, field_path: &str) -> Result<(TlsSessionData, String)> {
    let url = url.to_string();
    let field_path = field_path.to_string();

    // Use tokio TcpStream (async) then convert to std for blocking TLS
    let parsed = url::Url::parse(&url)?;
    let host = parsed
        .host_str()
        .context("URL must have a host")?
        .to_string();
    let port = parsed.port_or_known_default().context("Unknown port")?;
    let path = parsed.path().to_string();

    println!("Connecting to {}:{}...", host, port);

    let tcp = tokio::net::TcpStream::connect((&host[..], port)).await?;
    let tcp = tcp.into_std()?;
    tcp.set_nonblocking(false)?;

    // Run blocking TLS I/O on a blocking thread
    spawn_blocking(move || {
        // Create a custom CryptoProvider with only AES-256-GCM (the SP1 program
        // only implements AES-256, not AES-128).
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites.retain(|cs| {
            cs.suite() == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
        });
        let _ = provider.install_default();

        // ── Set up TLS with key log ──────────────────────────────────
        let key_log = Arc::new(CaptureKeyLog::new());

        let root_certs =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        config.key_log = key_log.clone();
        let config = Arc::new(config);

        // ── Connect TCP with capture wrapper ─────────────────────────
        let mut capture = CaptureStream::new(tcp);

        // ── Create TLS connection ────────────────────────────────────
        let server_name = ServerName::try_from(host.as_str()).unwrap().to_owned();
        let mut client = ClientConnection::new(config, server_name).unwrap();

        // ── Complete TLS handshake ───────────────────────────────────
        client.complete_io(&mut capture).unwrap();

        // ── Extract session info ─────────────────────────────────────
        let cert_chain: Vec<Vec<u8>> = client
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.to_vec()).collect())
            .unwrap_or_default();

        // Get the traffic secrets from the key log
        let keys = key_log.captured.lock().unwrap().clone();
        let server_handshake_traffic_secret = keys
            .iter()
            .find(|(label, _, _)| label == "SERVER_HANDSHAKE_TRAFFIC_SECRET")
            .map(|(_, _, secret)| secret.clone())
            .ok_or_else(|| anyhow::anyhow!("SERVER_HANDSHAKE_TRAFFIC_SECRET not found"))?;
        let server_traffic_secret = keys
            .iter()
            .find(|(label, _, _)| label == "SERVER_TRAFFIC_SECRET_0")
            .map(|(_, _, secret)| secret.clone())
            .ok_or_else(|| anyhow::anyhow!("SERVER_TRAFFIC_SECRET_0 not found"))?;

        // ── Send HTTP request ────────────────────────────────────────
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: zkTLS-Prover/1.0\r\nAccept: application/vnd.github.v3+json\r\nConnection: close\r\n\r\n",
            path, host
        );

        client.writer().write_all(request.as_bytes()).unwrap();
        client.writer().flush().unwrap();

        while client.wants_write() {
            client.write_tls(&mut capture).unwrap();
        }

        // ── Read the encrypted response ──────────────────────────────
        let mut response_body = Vec::new();
        let mut buf = [0u8; 65536];

        loop {
            if client.read_tls(&mut capture).unwrap() == 0 {
                break;
            }
            let state = client.process_new_packets().unwrap();
            loop {
                match client.reader().read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        response_body.extend_from_slice(&buf[..n]);
                    }
                }
            }
            if state.peer_has_closed() {
                break;
            }
        }

        // ── Get the captured encrypted data ─────────────────────────
        let encrypted_records = capture.take_captured();

        let response_text = String::from_utf8_lossy(&response_body).to_string();

        // Parse HTTP response: find headers/body boundary
        let body = if let Some(pos) = response_text.find("\r\n\r\n") {
            let headers = &response_text[..pos];
            let raw_body = &response_text[pos + 4..];
            // Check for chunked transfer encoding
            if headers.to_lowercase().contains("transfer-encoding: chunked") {
                // Parse chunked body: each chunk is "<size>\r\n<data>\r\n"
                let mut result = String::new();
                let mut chunk_start = 0;
                while chunk_start < raw_body.len() {
                    // Find the chunk size line
                    if let Some(crlf) = raw_body[chunk_start..].find("\r\n") {
                        let size_str = &raw_body[chunk_start..chunk_start + crlf];
                        if let Ok(size) = usize::from_str_radix(size_str.trim(), 16) {
                            if size == 0 { break; } // Last chunk
                            let data_start = chunk_start + crlf + 2;
                            if data_start + size <= raw_body.len() {
                                result.push_str(&raw_body[data_start..data_start + size]);
                                chunk_start = data_start + size + 2; // Skip trailing CRLF
                            } else { break; }
                        } else { break; }
                    } else { break; }
                }
                result
            } else {
                raw_body.trim().to_string()
            }
        } else {
            response_text.trim().to_string()
        };

        let session_data = TlsSessionData {
            server_name: host,
            server_cert_chain: cert_chain,
            server_handshake_traffic_secret,
            server_application_traffic_secret: server_traffic_secret,
            encrypted_records,
            http_request: request.into_bytes(),
            field_path: field_path.to_string(),
        };

        Ok((session_data, body))
    })
    .await
    .context("Blocking task panicked")?
}
