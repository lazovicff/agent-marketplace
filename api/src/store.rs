use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::{Agent, Schema, Task};

/// In-memory store that holds all indexed on-chain data.
///
/// On startup, the indexer populates this store by replaying historical events.
/// New events are applied in real time via WebSocket subscriptions.
#[derive(Debug, Default)]
pub struct Store {
    /// All agents keyed by their address (lowercase hex).
    pub agents: HashMap<String, Agent>,
    /// All tasks keyed by their ID.
    pub tasks: HashMap<u64, Task>,
    /// All schemas keyed by their ID.
    pub schemas: HashMap<u64, Schema>,
    /// The last block number that was fully synced.
    pub last_synced_block: u64,
}

/// Thread-safe shared store.
pub type SharedStore = Arc<RwLock<Store>>;

/// Create a new shared store.
pub fn new_shared_store() -> SharedStore {
    Arc::new(RwLock::new(Store::default()))
}
