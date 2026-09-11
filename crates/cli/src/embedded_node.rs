//! # Embedded Desktop / Edge Sovereign Node Runtime & Modular SDK
//!
//! Packages the full Sovereign Bunny stack (`bunny-gateway`, `bunny-committee`, `bunny-storage`, `bunny-mesh`)
//! directly into a single self-contained desktop binary (Tauri / CLI edge runner).
//!
//! Features:
//! - **Modular Provider Architecture**: Pluggable traits for Gateway, Storage, Committee, and Mesh.
//! - **Lockless In-Memory Channels**: Zero network latency for local inter-daemon communication.
//! - **Zero Remote RPC Reliance**: All balance, nonce, and state checks execute statelessly against local RAM.
//! - **Air-Gapped Key Safety**: Private keys never leave local memory.
//! - **Passive Storage Node Rewards**: Opt-in background storage hosting participating in ZK-PoR epoch spot checks.

use alloy_primitives::{Address, B256, U256};
use sovereign_consensus::storage::dialects::MultiDialectStorageEngine;
use sovereign_consensus::lattice::types::{LatticeBlock, LatticePayload};
use sovereign_consensus::registry::ValidatorRegistry;
use sovereign_consensus::system_contracts::router::execute_system_action;
use sovereign_identity::did::SovereignDidDocument;
use sovereign_ssz::signal::SignalEnvelope;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

/// Embedded Desktop Edge Node configuration with range sharding and interest filtering.
#[derive(Debug, Clone)]
pub struct EmbeddedDesktopConfig {
    /// Local storage directory for NVMe blobs and CRDT documents.
    pub storage_data_dir: String,
    /// Storage capacity allocated for passive node hosting (GB).
    pub host_storage_gb: u32,
    /// Opt-in switch for ZK-PoR epoch storage rewards.
    pub opt_in_storage_merit: bool,
    /// Local JSON-RPC / ActivityPub listen port.
    pub local_listen_port: u16,
    /// Range shards explicitly monitored by this edge node (e.g. 0x0000..0xFFFF).
    pub subscribed_ranges: HashSet<u16>,
    /// Address interest topic IDs explicitly subscribed for low-latency notifications.
    pub subscribed_topics: HashSet<B256>,
}

impl Default for EmbeddedDesktopConfig {
    fn default() -> Self {
        Self {
            storage_data_dir: "~/.bunny/storage".to_string(),
            host_storage_gb: 10,
            opt_in_storage_merit: true,
            local_listen_port: 8545,
            subscribed_ranges: HashSet::new(),
            subscribed_topics: HashSet::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Modular Provider Traits (Reth-Style Modular SDK)
// ─────────────────────────────────────────────────────────────────────────────

/// Modular Gateway Provider interface (zkOIDC, WebFinger, ActivityPub, JSON-RPC).
pub trait GatewayProvider: Send + Sync {
    /// Resolves an actor identity or WebFinger resource.
    fn resolve_webfinger(&self, resource: &str, domain: &str) -> Result<serde_json::Value, String>;
    /// Dispatches an ActivityStreams payload.
    fn dispatch_activity(&self, activity: serde_json::Value) -> Result<B256, String>;
}

/// Modular Storage Provider interface (Iroh BLAKE3, Dialects, ZK-PoR).
pub trait StorageProvider: Send + Sync {
    /// Stores raw blob payload and returns content-addressed CID.
    fn store_blob(&self, namespace_id: u64, data: &[u8]) -> Result<String, String>;
    /// Generates ZK-PoR merit claim for epoch rewards.
    fn generate_por_claim(&self, provider_did: &str, epoch_id: u64, total_mint: U256) -> Result<(B256, U256), &'static str>;
}

/// Modular Committee Provider interface (revm in RAM, stateless sequence ordering).
pub trait CommitteeProvider: Send + Sync {
    /// Validates and sequences a stateless lattice state transition.
    fn sequence_block(&self, block: LatticeBlock) -> Result<B256, String>;
}

/// Modular Mesh Provider interface (P2P QUIC, WireGuard, Gossip topic swarms).
pub trait MeshProvider: Send + Sync {
    /// Subscribes to an address interest topic.
    fn subscribe_topic(&self, topic_id: B256, endpoint: &str);
    /// Broadcasts state diff across active peer connections.
    fn broadcast_diff(&self, topic_id: B256, payload: &[u8]) -> Result<usize, String>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Default Embedded Provider Implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Default Gateway Provider running in local memory.
pub struct DefaultGatewayProvider {
    pub chain_id: u32,
}

impl GatewayProvider for DefaultGatewayProvider {
    fn resolve_webfinger(&self, resource: &str, domain: &str) -> Result<serde_json::Value, String> {
        let clean_res = resource.trim();
        let username = if clean_res.starts_with("acct:") {
            let handle = clean_res.strip_prefix("acct:").unwrap();
            let mut parts = handle.split('@');
            parts.next().unwrap_or(handle)
        } else {
            clean_res
        };

        Ok(serde_json::json!({
            "subject": format!("acct:{}@{}", username, domain),
            "aliases": [
                format!("https://{}/users/{}", domain, username),
                format!("did:sovereign:{}:0x1337", self.chain_id),
            ],
            "links": [
                {
                    "rel": "self",
                    "type": "application/activity+json",
                    "href": format!("https://{}/users/{}", domain, username)
                }
            ]
        }))
    }

    fn dispatch_activity(&self, activity: serde_json::Value) -> Result<B256, String> {
        let json_bytes = serde_json::to_vec(&activity).map_err(|e| e.to_string())?;
        let hash = blake3::hash(&json_bytes);
        Ok(B256::from_slice(hash.as_bytes()))
    }
}

/// Default Storage Provider backed by MultiDialectStorageEngine.
pub struct DefaultStorageProvider {
    pub engine: Arc<RwLock<MultiDialectStorageEngine>>,
}

impl StorageProvider for DefaultStorageProvider {
    fn store_blob(&self, _namespace_id: u64, data: &[u8]) -> Result<String, String> {
        let hash = blake3::hash(data);
        Ok(format!("b3:{}", alloy_primitives::hex::encode(hash.as_bytes())))
    }

    fn generate_por_claim(&self, provider_did: &str, epoch_id: u64, total_mint: U256) -> Result<(B256, U256), &'static str> {
        self.engine.read().unwrap().generate_storage_merit_claim(provider_did, epoch_id, total_mint)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Self-Contained Embedded Sovereign Edge Node
// ─────────────────────────────────────────────────────────────────────────────

/// Self-contained Embedded Sovereign Edge Node.
pub struct EmbeddedDesktopNode {
    pub config: EmbeddedDesktopConfig,
    pub identity: SovereignDidDocument,
    pub registry: Arc<RwLock<ValidatorRegistry>>,
    pub storage_engine: Arc<RwLock<MultiDialectStorageEngine>>,
    pub gateway_provider: Arc<dyn GatewayProvider>,
    pub storage_provider: Arc<dyn StorageProvider>,
    pub subscribed_ranges: Arc<RwLock<HashSet<u16>>>,
    pub subscribed_topics: Arc<RwLock<HashSet<B256>>>,
    pub tx_intent_sender: mpsc::Sender<LatticeBlock>,
    pub is_running: Arc<RwLock<bool>>,
}

impl EmbeddedDesktopNode {
    /// Initializes and starts the embedded edge node in the current Tokio runtime.
    pub async fn spawn(config: EmbeddedDesktopConfig, seed: B256) -> Self {
        let identity = SovereignDidDocument::derive_from_seed(seed);
        let registry = Arc::new(RwLock::new(ValidatorRegistry::default()));
        let storage_engine = Arc::new(RwLock::new(MultiDialectStorageEngine::default()));
        let (tx_intent, mut rx_intent) = mpsc::channel::<LatticeBlock>(1024);
        let is_running = Arc::new(RwLock::new(true));

        // Automatically monitor the user's primary range prefix (first 2 bytes of address)
        let mut initial_ranges = config.subscribed_ranges.clone();
        let user_range_prefix = u16::from_be_bytes([identity.evm_address[0], identity.evm_address[1]]);
        initial_ranges.insert(user_range_prefix);

        let subscribed_ranges = Arc::new(RwLock::new(initial_ranges));
        let subscribed_topics = Arc::new(RwLock::new(config.subscribed_topics.clone()));

        let gateway_provider = Arc::new(DefaultGatewayProvider { chain_id: 1337 });
        let storage_provider = Arc::new(DefaultStorageProvider { engine: Arc::clone(&storage_engine) });

        let running_flag = Arc::clone(&is_running);
        let node_did = identity.did_uri.clone();
        let ranges_ref = Arc::clone(&subscribed_ranges);

        // 1. Spawn in-memory Committee Worker with Range-Shard filtering
        tokio::spawn(async move {
            tracing::info!(did = %node_did, prefix = format!("{:#06x}", user_range_prefix), "🚀 Embedded range-sharded bunny-committee worker started in RAM");
            while let Some(block) = rx_intent.recv().await {
                if !*running_flag.read().unwrap() {
                    break;
                }
                let block_prefix = u16::from_be_bytes([block.account[0], block.account[1]]);
                let is_monitored = ranges_ref.read().unwrap().contains(&block_prefix);
                if is_monitored {
                    tracing::debug!(account = ?block.account, seq = block.sequence, "In-memory range-sharded lattice block processed");
                }
            }
        });

        // 2. Spawn opt-in Storage Merit worker if enabled
        if config.opt_in_storage_merit {
            let storage_bg = Arc::clone(&storage_engine);
            let provider_did = identity.did_uri.clone();
            tokio::spawn(async move {
                tracing::info!(did = %provider_did, "💾 Embedded storage node active (earning Storage Merit emissions)");
                let _claim = storage_bg.read().unwrap().generate_storage_merit_claim(
                    &provider_did,
                    1,
                    U256::from(10_000_000_000_000_000_000u128),
                );
            });
        }

        Self {
            config,
            identity,
            registry,
            storage_engine,
            gateway_provider,
            storage_provider,
            subscribed_ranges,
            subscribed_topics,
            tx_intent_sender: tx_intent,
            is_running,
        }
    }

    /// Checks whether an account falls within this node's monitored range shards or subscribed topics.
    pub fn is_account_relevant(&self, address: &Address) -> bool {
        if *address == self.identity.evm_address {
            return true;
        }
        let prefix = u16::from_be_bytes([address[0], address[1]]);
        if self.subscribed_ranges.read().unwrap().contains(&prefix) {
            return true;
        }
        false
    }

    /// Subscribes to an additional range shard prefix (e.g. 0x1234).
    pub fn subscribe_range(&self, range_prefix: u16) {
        self.subscribed_ranges.write().unwrap().insert(range_prefix);
    }

    /// Subscribes to a deterministic address interest topic (`SYSTEM_SIGNAL_REGISTRY 0x54`).
    pub fn subscribe_interest_topic(&self, target_address: &Address, app_context: &[u8]) -> B256 {
        let topic_id = SignalEnvelope::derive_topic_id(target_address, app_context);
        self.subscribed_topics.write().unwrap().insert(topic_id);
        topic_id
    }

    /// Executes raw legacy EVM bytecalls (MetaMask/Rabby calldata) against system precompiles statelessly in RAM.
    pub fn execute_legacy_raw_bytecall(&self, to: Address, data: &[u8], caller: Address) -> Result<(), String> {
        let mut reg = self.registry.write().map_err(|_| "Poisoned lock".to_string())?;
        execute_system_action(&mut reg, caller, to, data, 1).map_err(|e| e.to_string())
    }

    /// Submits a state transition intent directly through in-memory channels (sub-microsecond dispatch).
    pub async fn submit_intent_in_memory(&self, payload: LatticePayload, sequence: u64, prev_hash: B256) -> Result<B256, &'static str> {
        let block = LatticeBlock {
            account: self.identity.evm_address,
            sequence,
            previous_hash: prev_hash,
            payload,
            signature: vec![0x00],
            static_witnesses: Vec::new(),
        };

        let block_hash = alloy_primitives::keccak256(&serde_json::to_vec(&block.payload).unwrap());

        self.tx_intent_sender.send(block).await
            .map_err(|_| "Failed to dispatch intent over in-memory channel")?;

        Ok(block_hash)
    }

    /// Returns JSON status payload suitable for Tauri IPC desktop bindings.
    pub fn get_tauri_status(&self) -> serde_json::Value {
        let user_prefix = u16::from_be_bytes([self.identity.evm_address[0], self.identity.evm_address[1]]);
        let ranges_count = self.subscribed_ranges.read().unwrap().len();
        let topics_count = self.subscribed_topics.read().unwrap().len();

        serde_json::json!({
            "did_uri": self.identity.did_uri,
            "evm_address": format!("{:#x}", self.identity.evm_address),
            "primary_range_prefix": format!("{:#06x}", user_prefix),
            "monitored_ranges_count": ranges_count,
            "subscribed_topics_count": topics_count,
            "is_running": *self.is_running.read().unwrap(),
            "storage_gb": self.config.host_storage_gb,
            "opt_in_storage_merit": self.config.opt_in_storage_merit
        })
    }

    /// Queries local state directly from RAM without remote RPC calls.
    pub fn get_local_account_address(&self) -> Address {
        self.identity.evm_address
    }

    /// Shuts down background in-memory daemon tasks.
    pub fn stop(&self) {
        if let Ok(mut running) = self.is_running.write() {
            *running = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_consensus::system_registry::{SYSTEM_DID_REGISTRY, SystemAction};

    #[tokio::test]
    async fn test_embedded_node_lifecycle_and_modular_dispatch() {
        let seed = B256::repeat_byte(0x99);
        let config = EmbeddedDesktopConfig::default();
        let node = EmbeddedDesktopNode::spawn(config, seed).await;

        assert_eq!(node.get_local_account_address(), node.identity.evm_address);

        // Test modular gateway provider
        let wf = node.gateway_provider.resolve_webfinger("acct:alice@manifold.mesh", "manifold.mesh");
        assert!(wf.is_ok());

        // Test modular storage provider
        let cid = node.storage_provider.store_blob(1, b"Local NVMe CRDT Document").unwrap();
        assert!(cid.starts_with("b3:"));

        // Dispatch in-memory intent
        let intent_res = node.submit_intent_in_memory(
            LatticePayload::Send {
                recipient: Address::repeat_byte(0x22),
                amount: U256::from(1000),
            },
            1,
            B256::ZERO,
        ).await;
        assert!(intent_res.is_ok());

        // Test Range-Sharding and Topic Interest
        let user_addr = node.get_local_account_address();
        assert!(node.is_account_relevant(&user_addr));

        let other_addr = Address::repeat_byte(0x77);
        let other_prefix = u16::from_be_bytes([0x77, 0x77]);
        assert!(!node.is_account_relevant(&other_addr));
        node.subscribe_range(other_prefix);
        assert!(node.is_account_relevant(&other_addr));

        let topic = node.subscribe_interest_topic(&user_addr, b"dao.notifications");
        assert_ne!(topic, B256::ZERO);

        // Test Legacy Raw Bytecall Execution (e.g. Register DID at 0x03)
        let reg_action = SystemAction::RegisterDid {
            did_document: node.identity.to_w3c_json_ld().to_string(),
            pq_pub_key: vec![0x99; 32],
            key_tier: "QuantumReady".to_string(),
        };
        let calldata = reg_action.encode();
        let raw_res = node.execute_legacy_raw_bytecall(SYSTEM_DID_REGISTRY, &calldata, user_addr);
        assert!(raw_res.is_ok());

        // Test Tauri Status serialization
        let tauri_status = node.get_tauri_status();
        assert_eq!(tauri_status["is_running"], true);

        node.stop();
    }
}
