use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::{Agent, PaginatedResponse};
use crate::store::Store;

pub fn routes(store: Arc<RwLock<Store>>) -> Router {
    Router::new()
        .route("/", get(list_agents))
        .route("/{address}", get(get_agent))
        .with_state(store)
}

#[derive(Deserialize)]
pub struct AgentQuery {
    active: Option<bool>,
    page: Option<u64>,
    limit: Option<u64>,
}

async fn list_agents(
    State(store): State<Arc<RwLock<Store>>>,
    Query(query): Query<AgentQuery>,
) -> Json<PaginatedResponse<Agent>> {
    let store = store.read().await;
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).min(100);

    let mut agents: Vec<&Agent> = store.agents.values().collect();

    // Filter by active status if provided
    if let Some(active) = query.active {
        agents.retain(|a| a.active == active);
    }

    let total = agents.len() as u64;
    let start = ((page - 1) * limit) as usize;
    let data: Vec<Agent> = agents
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

async fn get_agent(
    State(store): State<Arc<RwLock<Store>>>,
    Path(address): Path<String>,
) -> Json<Option<Agent>> {
    let store = store.read().await;
    Json(store.agents.get(&address.to_lowercase()).cloned())
}
