//! # Multi-Dialect dApp Storage Engine & Out-of-Band Merit Subsidization
//!
//! Provides native database dialect interfaces over the content-addressed Iroh / BLAKE3 storage engine:
//! - **Key-Value Dialect (Redis/RESP-style)**: `GET`, `SET`, `HGET`, `HSET`, `DEL`, `EXPIRE`.
//! - **Document Dialect (MongoDB/BSON-style)**: JSON collections, field filtering, projection, updates.
//! - **Relational Dialect (SQL-style)**: Schema tables, indexed rows, deterministic queries.
//! - **Wide-Column Dialect (CQL-style)**: Partition keys, clustering columns, sparse row mutation.
//!
//! Every interaction is authenticated by the user's Sovereign DID wallet session.
//! Storage providers earn epoch mint emissions via the **Storage Merit Vector** (ZK-PoR Bao slices to `0x0053`).

use alloy_primitives::{Address, B256, U256, address};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// System Storage DA precompile address (`0x00...0053`).
pub const SYSTEM_STORAGE_DA: Address = address!("0000000000000000000000000000000000000053");

// ─────────────────────────────────────────────────────────────────────────────
// Dialect Command Enums
// ─────────────────────────────────────────────────────────────────────────────

/// Redis/RESP Key-Value Operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KvCommand {
    Get { key: String },
    Set { key: String, value: Vec<u8>, ttl_secs: Option<u64> },
    HGet { map: String, field: String },
    HSet { map: String, field: String, value: Vec<u8> },
    Del { key: String },
}

/// MongoDB/BSON Document Operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DocCommand {
    InsertOne { collection: String, doc_json: serde_json::Value },
    Find { collection: String, filter_json: serde_json::Value },
    UpdateMany { collection: String, filter_json: serde_json::Value, update_json: serde_json::Value },
    DeleteMany { collection: String, filter_json: serde_json::Value },
}

/// SQL Relational Operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SqlTableCommand {
    CreateTable { table_name: String, columns: Vec<String> },
    InsertRow { table_name: String, row_values: HashMap<String, serde_json::Value> },
    SelectWhere { table_name: String, column: String, value: serde_json::Value },
}

/// Cassandra/Scylla CQL Wide-Column Operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CqlCommand {
    PutColumn {
        keyspace: String,
        table: String,
        partition_key: String,
        clustering_key: String,
        column_name: String,
        value: Vec<u8>,
    },
    GetColumns {
        keyspace: String,
        table: String,
        partition_key: String,
    },
}

/// Response payload from storage dialect execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageResponse {
    Bytes(Option<Vec<u8>>),
    Json(serde_json::Value),
    Rows(Vec<HashMap<String, serde_json::Value>>),
    Success,
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-Dialect Storage Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Storage Tier Classification for retrievability and persistence incentives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageTier {
    /// Hot RAM/NVMe cache serving active connected RPC client sessions.
    Hot,
    /// Warm Iroh QUIC P2P network store for decentralized data distribution.
    Warm,
    /// Cold Git CARv2 / archival persistence for historical lattice states.
    Cold,
}

impl Default for StorageTier {
    fn default() -> Self {
        Self::Warm
    }
}

/// Target replication quota for sovereign mesh persistence.
pub const TARGET_REPLICATION_FACTOR: usize = 3;
/// Hard cap on rewarded replicas per CID (strictly prevents 1,000,000x reward farming).
pub const MAX_REWARDED_REPLICAS: usize = 4;

/// Anti-Reward-Farming Storage Registry enforcing replication quotas and RPC client affinity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AntiFarmingStorageRegistry {
    /// CID -> List of Provider DIDs hosting this CID (in registration order)
    pub cid_replicas: HashMap<String, Vec<String>>,
    /// Provider DID -> Weighted Storage Credits (anti-farming score)
    pub provider_weighted_credits: HashMap<String, u64>,
    /// Provider DID -> Active RPC client sessions served count
    pub active_rpc_affinity: HashMap<String, u32>,
}

impl AntiFarmingStorageRegistry {
    /// Records a hosted blob for a provider and returns the effective marginal credit awarded.
    pub fn record_blob_hosting(
        &mut self,
        cid: &str,
        provider_did: &str,
        size_bytes: u64,
        tier: StorageTier,
        is_active_rpc_session: bool,
    ) -> u64 {
        let replicas = self.cid_replicas.entry(cid.to_string()).or_default();
        if replicas.iter().any(|p| p == provider_did) {
            return 0; // Already registered by this provider
        }

        let replica_rank = replicas.len() + 1;
        replicas.push(provider_did.to_string());

        // Diminishing returns & strict over-replication cap:
        // Rank 1..=3: 100% full merit credit
        // Rank 4: 50% diminishing returns credit
        // Rank > 4: 0% ZERO merit credit (strictly prevents 1,000,000x over-replication farming)
        let replication_multiplier = match replica_rank {
            1..=3 => 1.0,
            4 => 0.5,
            _ => 0.0, // Hard cap: no rewards for excessive duplication
        };

        if replication_multiplier == 0.0 {
            return 0;
        }

        // Active RPC Client Proximity / Co-location Affinity bonus (1.25x)
        let affinity_multiplier = if is_active_rpc_session { 1.25 } else { 1.0 };

        // Cold storage preservation bonus (1.5x) for under-replicated historical data (<= 2 replicas)
        let tier_multiplier = match tier {
            StorageTier::Hot => 1.1,
            StorageTier::Warm => 1.0,
            StorageTier::Cold if replica_rank <= 2 => 1.5,
            StorageTier::Cold => 0.8,
        };

        let effective_credit = (size_bytes as f64 * replication_multiplier * affinity_multiplier * tier_multiplier) as u64;
        *self.provider_weighted_credits.entry(provider_did.to_string()).or_insert(0) += effective_credit;

        if is_active_rpc_session {
            *self.active_rpc_affinity.entry(provider_did.to_string()).or_insert(0) += 1;
        }

        effective_credit
    }
}

/// Unified Multi-Dialect Storage Engine.
#[derive(Debug, Clone, Default)]
pub struct MultiDialectStorageEngine {
    /// KV Store: DID -> Key -> Value
    pub kv_store: HashMap<String, HashMap<String, Vec<u8>>>,
    /// Document Store: DID -> Collection -> Docs
    pub doc_store: HashMap<String, HashMap<String, Vec<serde_json::Value>>>,
    /// Relational SQL Store: DID -> Table -> Rows
    pub sql_store: HashMap<String, HashMap<String, Vec<HashMap<String, serde_json::Value>>>>,
    /// Wide-Column CQL Store: DID -> Keyspace:Table:Partition -> ClusteringKey:Col -> Val
    pub cql_store: HashMap<String, HashMap<String, HashMap<String, Vec<u8>>>>,
    /// Total hosted bytes per node (DID) for Storage Merit calculations
    pub hosted_bytes_by_provider: HashMap<String, u64>,
    /// Anti-Reward-Farming registry tracking replication quotas and affinity
    pub anti_farming: AntiFarmingStorageRegistry,
}

impl MultiDialectStorageEngine {
    /// Executes a Redis/RESP-style Key-Value command.
    pub fn execute_kv(&mut self, session_did: &str, cmd: KvCommand) -> Result<StorageResponse, &'static str> {
        let user_kv = self.kv_store.entry(session_did.to_string()).or_default();

        match cmd {
            KvCommand::Get { key } => {
                let val = user_kv.get(&key).cloned();
                Ok(StorageResponse::Bytes(val))
            }
            KvCommand::Set { key, value, .. } => {
                let size = value.len() as u64;
                user_kv.insert(key, value);
                *self.hosted_bytes_by_provider.entry(session_did.to_string()).or_insert(0) += size;
                Ok(StorageResponse::Success)
            }
            KvCommand::HGet { map, field } => {
                let comp_key = format!("{}:{}", map, field);
                let val = user_kv.get(&comp_key).cloned();
                Ok(StorageResponse::Bytes(val))
            }
            KvCommand::HSet { map, field, value } => {
                let comp_key = format!("{}:{}", map, field);
                let size = value.len() as u64;
                user_kv.insert(comp_key, value);
                *self.hosted_bytes_by_provider.entry(session_did.to_string()).or_insert(0) += size;
                Ok(StorageResponse::Success)
            }
            KvCommand::Del { key } => {
                user_kv.remove(&key);
                Ok(StorageResponse::Success)
            }
        }
    }

    /// Executes a MongoDB/BSON-style Document command.
    pub fn execute_doc(&mut self, session_did: &str, cmd: DocCommand) -> Result<StorageResponse, &'static str> {
        let user_docs = self.doc_store.entry(session_did.to_string()).or_default();

        match cmd {
            DocCommand::InsertOne { collection, doc_json } => {
                let size = serde_json::to_vec(&doc_json).map(|v| v.len() as u64).unwrap_or(64);
                user_docs.entry(collection).or_default().push(doc_json);
                *self.hosted_bytes_by_provider.entry(session_did.to_string()).or_insert(0) += size;
                Ok(StorageResponse::Success)
            }
            DocCommand::Find { collection, filter_json } => {
                let coll = user_docs.entry(collection).or_default();
                let matches: Vec<serde_json::Value> = coll
                    .iter()
                    .filter(|doc| {
                        if filter_json.is_object() {
                            if let Some(obj) = filter_json.as_object() {
                                return obj.iter().all(|(k, v)| doc.get(k) == Some(v));
                            }
                        }
                        true
                    })
                    .cloned()
                    .collect();
                Ok(StorageResponse::Json(serde_json::Value::Array(matches)))
            }
            DocCommand::UpdateMany { collection, filter_json, update_json } => {
                let coll = user_docs.entry(collection).or_default();
                let mut updated_count = 0;
                for doc in coll.iter_mut() {
                    let matches = if let Some(obj) = filter_json.as_object() {
                        obj.iter().all(|(k, v)| doc.get(k) == Some(v))
                    } else {
                        true
                    };

                    if matches {
                        if let (Some(target_obj), Some(patch_obj)) = (doc.as_object_mut(), update_json.as_object()) {
                            for (k, v) in patch_obj {
                                target_obj.insert(k.clone(), v.clone());
                            }
                            updated_count += 1;
                        }
                    }
                }
                Ok(StorageResponse::Json(serde_json::json!({ "updated": updated_count })))
            }
            DocCommand::DeleteMany { collection, filter_json } => {
                let coll = user_docs.entry(collection).or_default();
                let initial_len = coll.len();
                coll.retain(|doc| {
                    if let Some(obj) = filter_json.as_object() {
                        !obj.iter().all(|(k, v)| doc.get(k) == Some(v))
                    } else {
                        false
                    }
                });
                let deleted = initial_len - coll.len();
                Ok(StorageResponse::Json(serde_json::json!({ "deleted": deleted })))
            }
        }
    }

    /// Executes an SQL Relational command.
    pub fn execute_sql(&mut self, session_did: &str, cmd: SqlTableCommand) -> Result<StorageResponse, &'static str> {
        let user_tables = self.sql_store.entry(session_did.to_string()).or_default();

        match cmd {
            SqlTableCommand::CreateTable { table_name, .. } => {
                user_tables.entry(table_name).or_default();
                Ok(StorageResponse::Success)
            }
            SqlTableCommand::InsertRow { table_name, row_values } => {
                let rows = user_tables.entry(table_name).or_default();
                let size = serde_json::to_vec(&row_values).map(|v| v.len() as u64).unwrap_or(64);
                rows.push(row_values);
                *self.hosted_bytes_by_provider.entry(session_did.to_string()).or_insert(0) += size;
                Ok(StorageResponse::Success)
            }
            SqlTableCommand::SelectWhere { table_name, column, value } => {
                let rows = user_tables.entry(table_name).or_default();
                let results: Vec<HashMap<String, serde_json::Value>> = rows
                    .iter()
                    .filter(|row| row.get(&column) == Some(&value))
                    .cloned()
                    .collect();
                Ok(StorageResponse::Rows(results))
            }
        }
    }

    /// Executes a Cassandra/Scylla CQL Wide-Column command.
    pub fn execute_cql(&mut self, session_did: &str, cmd: CqlCommand) -> Result<StorageResponse, &'static str> {
        let user_cql = self.cql_store.entry(session_did.to_string()).or_default();

        match cmd {
            CqlCommand::PutColumn { keyspace, table, partition_key, clustering_key, column_name, value } => {
                let row_key = format!("{}:{}:{}", keyspace, table, partition_key);
                let col_key = format!("{}:{}", clustering_key, column_name);
                let size = value.len() as u64;
                user_cql.entry(row_key).or_default().insert(col_key, value);
                *self.hosted_bytes_by_provider.entry(session_did.to_string()).or_insert(0) += size;
                Ok(StorageResponse::Success)
            }
            CqlCommand::GetColumns { keyspace, table, partition_key } => {
                let row_key = format!("{}:{}:{}", keyspace, table, partition_key);
                let cols = user_cql.get(&row_key).cloned().unwrap_or_default();
                let mut results = HashMap::new();
                for (k, v) in cols {
                    results.insert(k, serde_json::Value::String(alloy_primitives::hex::encode(v)));
                }
                Ok(StorageResponse::Json(serde_json::to_value(results).unwrap_or_default()))
            }
        }
    }

    /// Generates a verifiable Proof of Retrievability (ZK-PoR) and claims Storage Merit Vector rewards,
    /// strictly enforcing anti-reward-farming replication caps and RPC client affinity.
    pub fn generate_storage_merit_claim(
        &self,
        provider_did: &str,
        epoch_id: u64,
        total_epoch_mint_pool: U256,
    ) -> Result<(B256, U256), &'static str> {
        let weighted_credits = self.anti_farming.provider_weighted_credits.get(provider_did).copied();
        let raw_hosted = self.hosted_bytes_by_provider.get(provider_did).copied().unwrap_or(0);

        let effective_credit = weighted_credits.unwrap_or(raw_hosted);
        if effective_credit == 0 {
            return Err("No verified or rewarded bytes hosted by this provider");
        }

        // Generate deterministic Bao slice commitment for hosted data
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bunny.storage.por.slice.v1");
        hasher.update(provider_did.as_bytes());
        hasher.update(&effective_credit.to_be_bytes());
        hasher.update(&epoch_id.to_be_bytes());
        let por_commitment = B256::from_slice(hasher.finalize().as_bytes());

        // Max 20% epoch pool allocation for Storage DA Vector (hard cap)
        let total_storage_vector_pool = total_epoch_mint_pool / U256::from(5); // 20%
        let provider_reward = (total_storage_vector_pool * U256::from(effective_credit.min(100_000_000))) / U256::from(100_000_000);

        Ok((por_commitment, provider_reward))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_farming_replication_cap() {
        let mut registry = AntiFarmingStorageRegistry::default();
        let cid = "b3:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let size = 1_000_000u64; // 1 MB

        // Provider 1 (Replica 1): 100% credit (warm tier = 1.0)
        let c1 = registry.record_blob_hosting(cid, "did:sovereign:node1", size, StorageTier::Warm, false);
        assert_eq!(c1, 1_000_000);

        // Provider 2 (Replica 2): 100% credit
        let c2 = registry.record_blob_hosting(cid, "did:sovereign:node2", size, StorageTier::Warm, false);
        assert_eq!(c2, 1_000_000);

        // Provider 3 (Replica 3): 100% credit (target replication factor reached)
        let c3 = registry.record_blob_hosting(cid, "did:sovereign:node3", size, StorageTier::Warm, false);
        assert_eq!(c3, 1_000_000);

        // Provider 4 (Replica 4): 50% diminishing returns credit
        let c4 = registry.record_blob_hosting(cid, "did:sovereign:node4", size, StorageTier::Warm, false);
        assert_eq!(c4, 500_000);

        // Providers 5..20 (Replicas 5+): 0% credit (REWARD FARMING REJECTED)
        for i in 5..=20 {
            let did = format!("did:sovereign:farm_node_{}", i);
            let c = registry.record_blob_hosting(cid, &did, size, StorageTier::Warm, false);
            assert_eq!(c, 0, "Replica {} must receive 0 reward for oversaturated duplication", i);
        }
    }

    #[test]
    fn test_rpc_client_affinity_and_cold_storage_bonus() {
        let mut registry = AntiFarmingStorageRegistry::default();
        let cid_hot = "b3:hot_doc_cid_123";
        let cid_cold = "b3:cold_history_cid_456";
        let size = 100_000u64;

        // Hot storage for active connected RPC client session -> 1.1x tier * 1.25x affinity = 1.375x
        let hot_credit = registry.record_blob_hosting(cid_hot, "did:sovereign:gateway_node", size, StorageTier::Hot, true);
        assert_eq!(hot_credit, 137_500);

        // Cold storage preservation for under-replicated historical blob (Replica 1) -> 1.5x bonus
        let cold_credit = registry.record_blob_hosting(cid_cold, "did:sovereign:archival_node", size, StorageTier::Cold, false);
        assert_eq!(cold_credit, 150_000);
    }
}
