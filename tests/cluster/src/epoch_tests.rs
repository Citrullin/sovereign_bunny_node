//! Epoch Progression and Cross-Node Block Replication Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic cluster validation.

use crate::harness::ProcessCluster;
use alloy_primitives::B256;
use sovereign_identity::did::SovereignDidDocument;

#[tokio::test]
async fn test_given_two_node_cluster_when_system_tx_mined_on_node_a_then_state_replicates_to_node_b() {
    // ── GIVEN: 2 independent interconnected nodes running on distinct ports at genesis ──
    let cluster = ProcessCluster::spawn(2).await;
    let node_a = &cluster.nodes[0];
    let node_b = &cluster.nodes[1];

    let block_a_start = node_a.get_block_number().await;
    let block_b_start = node_b.get_block_number().await;
    assert_eq!(block_a_start, 0);
    assert_eq!(block_b_start, 0);

    assert_eq!(node_a.get_peer_count().await, 1, "Node A must have exactly 1 peer");
    assert_eq!(node_b.get_peer_count().await, 1, "Node B must have exactly 1 peer");

    // ── WHEN: Alice registers her Sovereign DID on Node A targeting SYSTEM_DID_REGISTRY ──
    let alice_priv_hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let alice_seed_bytes = alloy_primitives::hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let alice_seed = B256::from_slice(&alice_seed_bytes);
    let alice_doc = SovereignDidDocument::derive_from_seed(alice_seed);

    let reg_tx_hash = node_a.register_did_onchain(
        alice_priv_hex,
        &alice_doc.did_uri,
        &alice_doc.ml_dsa_pubkey,
        "QuantumReady",
        0,
    ).await;
    assert!(!reg_tx_hash.is_empty(), "DID registration transaction must be submitted and confirmed");

    // ── THEN: Node A commits block #1 with receipt status 0x1 ──
    let block_a_end = node_a.get_block_number().await;
    assert!(block_a_end >= 1, "Node A must advance to block #1 with the DID registration tx");

    let receipt_a = node_a.wait_for_receipt(&reg_tx_hash).await;
    assert_eq!(receipt_a["status"].as_str().unwrap(), "0x1", "On-chain system transaction must succeed on Node A");
    assert_eq!(receipt_a["to"].as_str().unwrap().to_lowercase(), format!("{:#x}", sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY).to_lowercase());

    // ── AND THEN: Node B synchronizes to block #1 and exposes the identical transaction receipt ──
    let mut block_b_end = node_b.get_block_number().await;
    let start_wait = std::time::Instant::now();
    while block_b_end < block_a_end && start_wait.elapsed() < std::time::Duration::from_secs(10) {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        block_b_end = node_b.get_block_number().await;
    }
    assert!(block_b_end >= block_a_end, "Node B must synchronize block height with Node A");

    let receipt_b = node_b.wait_for_receipt(&reg_tx_hash).await;
    assert_eq!(receipt_b["status"].as_str().unwrap(), "0x1", "Transaction receipt must be verified on Node B");
}
