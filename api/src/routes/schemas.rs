use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::{PaginatedResponse, Schema};
use crate::store::Store;

pub fn routes(store: Arc<RwLock<Store>>) -> Router {
    Router::new()
        .route("/", get(list_schemas))
        .route("/{id}", get(get_schema))
        .with_state(store)
}

#[derive(Deserialize)]
pub struct SchemaQuery {
    active: Option<bool>,
    page: Option<u64>,
    limit: Option<u64>,
}

async fn list_schemas(
    State(store): State<Arc<RwLock<Store>>>,
    Query(query): Query<SchemaQuery>,
) -> Json<PaginatedResponse<Schema>> {
    let store = store.read().await;
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).min(100);

    let mut schemas: Vec<&Schema> = store.schemas.values().collect();

    // Filter by active status if provided
    if let Some(active) = query.active {
        schemas.retain(|s| s.active == active);
    }

    // Sort by ID descending (newest first)
    schemas.sort_by(|a, b| b.id.cmp(&a.id));

    let total = schemas.len() as u64;
    let start = ((page - 1) * limit) as usize;
    let data: Vec<Schema> = schemas
        .into_iter()
        .skip(start)
        .take(limit as usize)
        .cloned()
        .collect();

    Json(PaginatedResponse {
        data,
        page,
        limit,
        total,
    })
}

async fn get_schema(
    State(store): State<Arc<RwLock<Store>>>,
    Path(id): Path<u64>,
) -> Json<Option<Schema>> {
    let store = store.read().await;
    Json(store.schemas.get(&id).cloned())
}
