//! # Multi-Dialect dApp Storage & Storage Merit Vector Test Suite
//!
//! Validates:
//! 1. Key-Value Dialect (Redis/RESP) operations.
//! 2. Document Dialect (MongoDB/BSON) operations with JSON selectors.
//! 3. Relational Dialect (SQL) table creation and indexed selection.
//! 4. Wide-Column Dialect (CQL) partition and clustering operations.
//! 5. DID Session Authentication and Storage Merit Vector (ZK-PoR Bao) emission claims.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use alloy_primitives::U256;
use sovereign_consensus::storage::dialects::{
    CqlCommand, DocCommand, KvCommand, MultiDialectStorageEngine, SqlTableCommand, StorageResponse,
};
use std::collections::HashMap;

#[test]
fn test_given_did_session_when_kv_and_document_operations_executed_then_mutates_state_accurately() {
    let mut storage = MultiDialectStorageEngine::default();
    let session_did = "did:sovereign:13371337:0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

    // ── GIVEN: KV (Redis-style) SET and HSET commands ──
    storage.execute_kv(session_did, KvCommand::Set {
        key: "user:profile:theme".to_string(),
        value: b"dark_mode".to_vec(),
        ttl_secs: None,
    }).unwrap();

    storage.execute_kv(session_did, KvCommand::HSet {
        map: "user:settings".to_string(),
        field: "language".to_string(),
        value: b"rust".to_vec(),
    }).unwrap();

    // ── WHEN: KV GET and HGET commands are executed ──
    let theme_res = storage.execute_kv(session_did, KvCommand::Get {
        key: "user:profile:theme".to_string(),
    }).unwrap();

    let lang_res = storage.execute_kv(session_did, KvCommand::HGet {
        map: "user:settings".to_string(),
        field: "language".to_string(),
    }).unwrap();

    // ── THEN: Exact values are returned ──
    assert_eq!(theme_res, StorageResponse::Bytes(Some(b"dark_mode".to_vec())));
    assert_eq!(lang_res, StorageResponse::Bytes(Some(b"rust".to_vec())));

    // ── AND WHEN: Document (MongoDB-style) collections are inserted and queried ──
    let doc1 = serde_json::json!({ "title": "First Blog Post", "author": "Alice", "views": 100 });
    let doc2 = serde_json::json!({ "title": "Second Blog Post", "author": "Bob", "views": 250 });

    storage.execute_doc(session_did, DocCommand::InsertOne {
        collection: "posts".to_string(),
        doc_json: doc1,
    }).unwrap();

    storage.execute_doc(session_did, DocCommand::InsertOne {
        collection: "posts".to_string(),
        doc_json: doc2,
    }).unwrap();

    let find_res = storage.execute_doc(session_did, DocCommand::Find {
        collection: "posts".to_string(),
        filter_json: serde_json::json!({ "author": "Alice" }),
    }).unwrap();

    // ── AND THEN: Query matches Alice's document exactly ──
    if let StorageResponse::Json(serde_json::Value::Array(docs)) = find_res {
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0]["title"], "First Blog Post");
    } else {
        panic!("Expected JSON array result");
    }
}

#[test]
fn test_given_relational_and_wide_column_dialects_when_executed_then_returns_structured_rows() {
    let mut storage = MultiDialectStorageEngine::default();
    let session_did = "did:sovereign:13371337:0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";

    // ── GIVEN: Relational SQL Table schema and rows ──
    storage.execute_sql(session_did, SqlTableCommand::CreateTable {
        table_name: "users".to_string(),
        columns: vec!["id".to_string(), "username".to_string(), "role".to_string()],
    }).unwrap();

    let mut row1 = HashMap::new();
    row1.insert("id".to_string(), serde_json::json!(1));
    row1.insert("username".to_string(), serde_json::json!("charlie"));
    row1.insert("role".to_string(), serde_json::json!("admin"));

    let mut row2 = HashMap::new();
    row2.insert("id".to_string(), serde_json::json!(2));
    row2.insert("username".to_string(), serde_json::json!("dan"));
    row2.insert("role".to_string(), serde_json::json!("user"));

    storage.execute_sql(session_did, SqlTableCommand::InsertRow {
        table_name: "users".to_string(),
        row_values: row1,
    }).unwrap();
    storage.execute_sql(session_did, SqlTableCommand::InsertRow {
        table_name: "users".to_string(),
        row_values: row2,
    }).unwrap();

    // ── WHEN: SQL SELECT is executed with a filter condition ──
    let select_res = storage.execute_sql(session_did, SqlTableCommand::SelectWhere {
        table_name: "users".to_string(),
        column: "role".to_string(),
        value: serde_json::json!("admin"),
    }).unwrap();

    // ── THEN: Only the admin row is returned ──
    if let StorageResponse::Rows(rows) = select_res {
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("username").unwrap(), &serde_json::json!("charlie"));
    } else {
        panic!("Expected SQL rows result");
    }

    // ── AND WHEN: Wide-Column (CQL) data is stored and retrieved ──
    storage.execute_cql(session_did, CqlCommand::PutColumn {
        keyspace: "analytics".to_string(),
        table: "events".to_string(),
        partition_key: "sensor_42".to_string(),
        clustering_key: "2026-08-30".to_string(),
        column_name: "temp".to_string(),
        value: vec![0x1a, 0x2b],
    }).unwrap();

    let cql_res = storage.execute_cql(session_did, CqlCommand::GetColumns {
        keyspace: "analytics".to_string(),
        table: "events".to_string(),
        partition_key: "sensor_42".to_string(),
    }).unwrap();

    // ── AND THEN: Column family returns matching clustered values ──
    if let StorageResponse::Json(obj) = cql_res {
        assert!(obj.get("2026-08-30:temp").is_some());
    } else {
        panic!("Expected CQL json result");
    }
}

#[test]
fn test_given_storage_provider_when_zk_por_slice_generated_then_claims_storage_merit_vector_reward() {
    let mut storage = MultiDialectStorageEngine::default();
    let provider_did = "did:sovereign:13371337:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    // ── GIVEN: Provider hosts 10 MB of data ──
    let payload = vec![0xaa; 10_000_000]; // 10MB
    storage.execute_kv(provider_did, KvCommand::Set {
        key: "large_dataset".to_string(),
        value: payload,
        ttl_secs: None,
    }).unwrap();

    let epoch_mint_pool = U256::from(100_000_000_000_000_000_000u128); // 100 ETH epoch pool

    // ── WHEN: Provider submits ZK-PoR proof to Storage Merit Vector ──
    let (por_commitment, reward) = storage.generate_storage_merit_claim(
        provider_did,
        1,
        epoch_mint_pool,
    ).expect("Generate Storage Merit Claim");

    // ── THEN: Valid commitment is emitted and reward is funded from the 20% Storage DA pool ──
    assert_ne!(por_commitment, alloy_primitives::B256::ZERO);
    assert!(reward > U256::ZERO);
    // Max 20% pool is 20 ETH; 10MB/100MB cap earns 2.0 ETH
    assert_eq!(reward, U256::from(2_000_000_000_000_000_000u128));
}

#[test]
fn test_anti_farming_replication_cap_and_rpc_affinity_in_storage_merit() {
    use sovereign_consensus::storage::dialects::StorageTier;

    let mut storage = MultiDialectStorageEngine::default();
    let epoch_mint_pool = U256::from(100_000_000_000_000_000_000u128); // 100 ETH
    let popular_cid = "b3:popular_viral_media_blob_777";
    let file_size = 10_000_000u64; // 10MB

    // ── 1. Replicas 1, 2, 3 earn full merit ──
    for i in 1..=3 {
        let did = format!("did:sovereign:legit_provider_{}", i);
        let credit = storage.anti_farming.record_blob_hosting(
            popular_cid,
            &did,
            file_size,
            StorageTier::Warm,
            false,
        );
        assert_eq!(credit, 10_000_000, "Replica {} earns 100% full storage credit", i);

        let (_, reward) = storage.generate_storage_merit_claim(&did, 1, epoch_mint_pool).unwrap();
        assert_eq!(reward, U256::from(2_000_000_000_000_000_000u128)); // 2.0 ETH
    }

    // ── 2. Replica 4 earns diminishing returns (50%) ──
    let replica_4_did = "did:sovereign:legit_provider_4";
    let credit_4 = storage.anti_farming.record_blob_hosting(
        popular_cid,
        replica_4_did,
        file_size,
        StorageTier::Warm,
        false,
    );
    assert_eq!(credit_4, 5_000_000, "Replica 4 earns 50% diminishing return credit");
    let (_, reward_4) = storage.generate_storage_merit_claim(replica_4_did, 1, epoch_mint_pool).unwrap();
    assert_eq!(reward_4, U256::from(1_000_000_000_000_000_000u128)); // 1.0 ETH

    // ── 3. Replicas 5 to 1000 earn ZERO (Reward farming strictly shut down) ──
    for i in 5..=50 {
        let farming_did = format!("did:sovereign:sybil_farm_node_{}", i);
        let credit_farm = storage.anti_farming.record_blob_hosting(
            popular_cid,
            &farming_did,
            file_size,
            StorageTier::Warm,
            false,
        );
        assert_eq!(credit_farm, 0, "Oversaturated replica {} earns 0 credits", i);
        assert!(storage.generate_storage_merit_claim(&farming_did, 1, epoch_mint_pool).is_err());
    }

    // ── 4. Active RPC client session gateway earns affinity bonus (1.25x * 1.1x hot = 1.375x) ──
    let rpc_gateway_did = "did:sovereign:active_rpc_gateway_node";
    let user_state_cid = "b3:active_user_lattice_state_999";
    let rpc_credit = storage.anti_farming.record_blob_hosting(
        user_state_cid,
        rpc_gateway_did,
        file_size,
        StorageTier::Hot,
        true, // Active connected RPC client session!
    );
    assert_eq!(rpc_credit, 13_750_000); // 1.375x bonus
    let (_, rpc_reward) = storage.generate_storage_merit_claim(rpc_gateway_did, 1, epoch_mint_pool).unwrap();
    assert_eq!(rpc_reward, U256::from(2_750_000_000_000_000_000u128)); // 2.75 ETH
}

