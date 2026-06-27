use serde::{Deserialize, Serialize};

/// An agent registered in the AgentRegistry contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub address: String,
    pub tee_public_key: String,
    pub metadata_uri: Option<String>,
    pub registered_at: u64,
    pub active: bool,
}

/// A task posted in the TaskContract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: u64,
    pub poster: String,
    pub description: String,
    pub reward: String,
    pub schema_id: u64,
    pub schema_name: Option<String>,
    pub deadline: u64,
    pub created_at: u64,
    pub status: String,
    pub executor: Option<String>,
    pub proof_verified: bool,
}

/// A zkTLS schema from the SchemaRegistry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub server_host: String,
    pub request_schema: serde_json::Value,
    pub response_schema: serde_json::Value,
    pub creator: String,
    pub created_at: u64,
    pub active: bool,
}

/// Paginated response wrapper.
#[derive(Debug, Clone, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub page: u64,
    pub limit: u64,
    pub total: u64,
}

/// Health check response.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub last_synced_block: u64,
}
