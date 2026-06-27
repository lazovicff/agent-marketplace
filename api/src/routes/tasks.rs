use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::{PaginatedResponse, Task};
use crate::store::Store;

pub fn routes(store: Arc<RwLock<Store>>) -> Router {
    Router::new()
        .route("/", get(list_tasks))
        .route("/{id}", get(get_task))
        .with_state(store)
}

#[derive(Deserialize)]
pub struct TaskQuery {
    status: Option<String>,
    page: Option<u64>,
    limit: Option<u64>,
}

async fn list_tasks(
    State(store): State<Arc<RwLock<Store>>>,
    Query(query): Query<TaskQuery>,
) -> Json<PaginatedResponse<Task>> {
    let store = store.read().await;
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).min(100);

    let mut tasks: Vec<&Task> = store.tasks.values().collect();

    // Filter by status if provided
    if let Some(ref status) = query.status {
        tasks.retain(|t| t.status == *status);
    }

    // Sort by ID descending (newest first)
    tasks.sort_by(|a, b| b.id.cmp(&a.id));

    let total = tasks.len() as u64;
    let start = ((page - 1) * limit) as usize;
    let data: Vec<Task> = tasks
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

async fn get_task(
    State(store): State<Arc<RwLock<Store>>>,
    Path(id): Path<u64>,
) -> Json<Option<Task>> {
    let store = store.read().await;
    Json(store.tasks.get(&id).cloned())
}
