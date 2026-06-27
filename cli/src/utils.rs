use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Parse a hex address string (with or without 0x prefix) into a 20-byte array.
pub fn parse_address(addr: &str) -> Result<[u8; 20]> {
    let s = addr.strip_prefix("0x").unwrap_or(addr);
    let bytes = hex::decode(s).context("Invalid hex address")?;
    if bytes.len() != 20 {
        anyhow::bail!("Address must be 20 bytes (40 hex chars)");
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Format bytes as a 0x-prefixed hex string.
pub fn hex_string(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// JSON-RPC request.
#[derive(Serialize)]
struct JsonRpcRequest<T: Serialize> {
    jsonrpc: String,
    id: u64,
    method: String,
    params: T,
}

/// JSON-RPC response.
#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    message: String,
}

/// Make a JSON-RPC call and deserialize the result.
pub async fn rpc_call<T: Serialize, R: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: T,
) -> Result<R> {
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: method.to_string(),
        params,
    };

    let response: JsonRpcResponse<R> = client
        .post(url)
        .json(&request)
        .send()
        .await
        .context("RPC call failed")?
        .json()
        .await
        .context("Failed to parse RPC response")?;

    if let Some(err) = response.error {
        anyhow::bail!("RPC error: {}", err.message);
    }

    response.result.context("RPC returned no result")
}
