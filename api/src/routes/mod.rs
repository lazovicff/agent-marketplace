pub mod agents;
pub mod health;
pub mod schemas;
pub mod tasks;

use crate::store::SharedStore;
use axum::Router;

/// Build the full API router with all routes.
pub fn build_router(store: SharedStore) -> Router {
    Router::new()
        .nest("/api/v1/tasks", tasks::routes(store.clone()))
        .nest("/api/v1/agents", agents::routes(store.clone()))
        .nest("/api/v1/schemas", schemas::routes(store.clone()))
        .nest("/api/v1/health", health::routes(store))
}
