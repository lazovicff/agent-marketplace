use axum::{extract::State, routing::get, Json, Router};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::HealthResponse;
use crate::store::Store;

pub fn routes(store: Arc<RwLock<Store>>) -> Router {
    Router::new()
        .route("/", get(health_check))
        .with_state(store)
}

async fn health_check(State(store): State<Arc<RwLock<Store>>>) -> Json<HealthResponse> {
    let store = store.read().await;
    Json(HealthResponse {
        status: "ok".to_string(),
        last_synced_block: store.last_synced_block,
    })
}
