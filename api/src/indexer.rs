use std::sync::Arc;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy::pubsub::PubSubFrontend;
use alloy::rpc::types::eth::{Filter, Log};
use alloy::transports::http::{Client, Http};
use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::models::{Agent, Schema, Task};
use crate::store::Store;

/// The block range to query per batch during historical sync.
const SYNC_BATCH_SIZE: u64 = 10_000;

// ---------------------------------------------------------------------------
//  Indexer
// ---------------------------------------------------------------------------

pub struct Indexer {
    store: Arc<RwLock<Store>>,
    config: crate::config::Config,
}

impl Indexer {
    pub fn new(store: Arc<RwLock<Store>>, config: crate::config::Config) -> Self {
        Self { store, config }
    }

    /// Run the indexer: first sync historical events, then subscribe to new ones.
    pub async fn run(&self) -> Result<()> {
        // Connect to HTTP provider for historical sync
        let http_provider: RootProvider<Http<Client>> =
            ProviderBuilder::default().on_http(self.config.rpc_http_url.parse()?);

        // Historical sync
        self.sync_history(&http_provider).await?;

        // Connect to WebSocket provider for real-time events
        let ws = WsConnect::new(self.config.rpc_ws_url.clone());
        let ws_provider: RootProvider<PubSubFrontend> =
            ProviderBuilder::default().on_ws(ws).await?;

        // Subscribe to new blocks and process events
        self.subscribe(&ws_provider).await?;

        Ok(())
    }

    /// Sync all historical events from start_block to latest.
    async fn sync_history(&self, provider: &RootProvider<Http<Client>>) -> Result<()> {
        let latest_block = provider
            .get_block_number()
            .await
            .context("Failed to get latest block number")?;

        info!(
            "Syncing history from block {} to {}",
            self.config.start_block, latest_block
        );

        let mut from = self.config.start_block;
        while from <= latest_block {
            let to = (from + SYNC_BATCH_SIZE - 1).min(latest_block);
            self.sync_batch(provider, from, to).await?;
            from = to + 1;
        }

        // Update last synced block
        {
            let mut store = self.store.write().await;
            store.last_synced_block = latest_block;
        }

        info!("Historical sync complete. Last block: {}", latest_block);
        Ok(())
    }

    /// Sync a single batch of blocks.
    async fn sync_batch(
        &self,
        provider: &RootProvider<Http<Client>>,
        from: u64,
        to: u64,
    ) -> Result<()> {
        let filter = Filter::new()
            .from_block(BlockNumberOrTag::Number(from))
            .to_block(BlockNumberOrTag::Number(to));

        let logs = provider
            .get_logs(&filter)
            .await
            .context("Failed to get logs")?;

        for log in &logs {
            self.process_log(log).await;
        }

        info!("Synced blocks {}-{} ({} logs)", from, to, logs.len());
        Ok(())
    }

    /// Subscribe to new events via polling.
    async fn subscribe(&self, _provider: &RootProvider<PubSubFrontend>) -> Result<()> {
        info!("Starting event polling (every 2s)...");

        loop {
            sleep(Duration::from_secs(2)).await;

            let http_provider: RootProvider<Http<Client>> =
                ProviderBuilder::default().on_http(self.config.rpc_http_url.parse()?);

            let latest = match http_provider.get_block_number().await {
                Ok(n) => n,
                Err(e) => {
                    warn!("Failed to get latest block: {}", e);
                    continue;
                }
            };

            let last_synced = {
                let store = self.store.read().await;
                store.last_synced_block
            };

            if latest > last_synced {
                self.sync_batch(&http_provider, last_synced + 1, latest)
                    .await?;

                let mut store = self.store.write().await;
                store.last_synced_block = latest;
            }
        }
    }

    /// Process a single log entry and update the in-memory store.
    async fn process_log(&self, log: &Log) {
        let topic0 = log.inner.topics().first().map(|t| format!("{:?}", t));

        match topic0.as_deref() {
            Some("AgentRegistered") => {
                self.handle_agent_registered(log).await;
            }
            Some("AgentDeregistered") => {
                self.handle_agent_deregistered(log).await;
            }
            Some("TaskCreated") => {
                self.handle_task_created(log).await;
            }
            Some("TaskApplied") => {
                self.handle_task_applied(log).await;
            }
            Some("ProofSubmitted") => {
                self.handle_proof_submitted(log).await;
            }
            Some("SchemaAdded") => {
                self.handle_schema_added(log).await;
            }
            _ => {
                // Unknown event — skip
            }
        }
    }

    // -----------------------------------------------------------------------
    //  Event handlers
    // -----------------------------------------------------------------------

    async fn handle_agent_registered(&self, log: &Log) {
        let topics = log.inner.topics();
        if topics.len() < 2 {
            return;
        }

        let agent_address = format!("{:?}", topics[1]);

        let agent = Agent {
            address: agent_address.clone(),
            tee_public_key: "0x".to_string(),
            metadata_uri: None,
            registered_at: log.block_number.unwrap_or(0),
            active: true,
        };

        let mut store = self.store.write().await;
        store.agents.insert(agent_address, agent);
        info!("Indexed AgentRegistered event");
    }

    async fn handle_agent_deregistered(&self, log: &Log) {
        let topics = log.inner.topics();
        if topics.len() < 2 {
            return;
        }

        let agent_address = format!("{:?}", topics[1]);
        let mut store = self.store.write().await;

        if let Some(agent) = store.agents.get_mut(&agent_address) {
            agent.active = false;
        }

        info!("Indexed AgentDeregistered event");
    }

    async fn handle_task_created(&self, log: &Log) {
        let topics = log.inner.topics();
        if topics.len() < 3 {
            return;
        }

        let data = &log.inner.data.data;
        let task_id = U256::from_be_slice(topics[1].as_slice()).to::<u64>();
        let poster = format!("{:?}", topics[2]);

        let reward = if data.len() >= 32 {
            U256::from_be_slice(&data[..32]).to_string()
        } else {
            "0".to_string()
        };

        let schema_id = if data.len() >= 64 {
            U256::from_be_slice(&data[32..64]).to::<u64>()
        } else {
            0
        };

        let deadline = if data.len() >= 96 {
            U256::from_be_slice(&data[64..96]).to::<u64>()
        } else {
            0
        };

        let task = Task {
            id: task_id,
            poster,
            description: String::new(),
            reward,
            schema_id,
            schema_name: None,
            deadline,
            created_at: log.block_number.unwrap_or(0),
            status: "Open".to_string(),
            executor: None,
            proof_verified: false,
        };

        let mut store = self.store.write().await;
        store.tasks.insert(task_id, task);
        info!("Indexed TaskCreated event: task #{}", task_id);
    }

    async fn handle_task_applied(&self, log: &Log) {
        let topics = log.inner.topics();
        if topics.len() < 3 {
            return;
        }

        let task_id = U256::from_be_slice(topics[1].as_slice()).to::<u64>();
        let executor = format!("{:?}", topics[2]);

        let mut store = self.store.write().await;
        if let Some(task) = store.tasks.get_mut(&task_id) {
            task.executor = Some(executor);
            task.status = "InProgress".to_string();
        }

        info!("Indexed TaskApplied event: task #{}", task_id);
    }

    async fn handle_proof_submitted(&self, log: &Log) {
        let topics = log.inner.topics();
        if topics.len() < 2 {
            return;
        }

        let task_id = U256::from_be_slice(topics[1].as_slice()).to::<u64>();

        let mut store = self.store.write().await;
        if let Some(task) = store.tasks.get_mut(&task_id) {
            task.status = "Completed".to_string();
            task.proof_verified = true;
        }

        info!("Indexed ProofSubmitted event: task #{}", task_id);
    }

    async fn handle_schema_added(&self, log: &Log) {
        let topics = log.inner.topics();
        if topics.len() < 3 {
            return;
        }

        let schema_id = U256::from_be_slice(topics[1].as_slice()).to::<u64>();
        let creator = format!("{:?}", topics[2]);

        let schema = Schema {
            id: schema_id,
            name: String::new(),
            description: String::new(),
            server_host: String::new(),
            request_schema: serde_json::Value::Null,
            response_schema: serde_json::Value::Null,
            creator,
            created_at: log.block_number.unwrap_or(0),
            active: true,
        };

        let mut store = self.store.write().await;
        store.schemas.insert(schema_id, schema);
        info!("Indexed SchemaAdded event: schema #{}", schema_id);
    }
}
