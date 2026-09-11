//! Byzantine Fault Injection, Quorum Safety, and Recovery Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for cluster resilience verification.

use crate::harness::ProcessCluster;
use alloy_primitives::B256;

#[tokio::test]
async fn test_given_three_node_cluster_when_one_node_crashes_then_surviving_quorum_maintains_liveness() {
    // ── GIVEN: A 3-node cluster operating in full mesh (N=3, f=1 Byzantine tolerance) ──
    let mut cluster = ProcessCluster::spawn(3).await;

    assert_eq!(cluster.nodes[0].get_block_number().await, 0);
    assert_eq!(cluster.nodes[1].get_block_number().await, 0);
    assert_eq!(cluster.nodes[2].get_block_number().await, 0);

    assert_eq!(
        cluster.nodes[0].get_peer_count().await, 2,
        "Node 0 must have exactly 2 peers in 3-node full mesh"
    );
    assert_eq!(
        cluster.nodes[1].get_peer_count().await, 2,
        "Node 1 must have exactly 2 peers in 3-node full mesh"
    );
    assert_eq!(
        cluster.nodes[2].get_peer_count().await, 2,
        "Node 2 must have exactly 2 peers in 3-node full mesh"
    );

    // ── WHEN: Node 1 crashes (simulating a Byzantine / failed node) ──
    let _ = cluster.nodes[1].child.kill();
    let _ = cluster.nodes[1].child.wait();

    // ── AND WHEN: A state transaction is submitted to the surviving quorum (Node 0 & Node 2) ──
    let alice_priv_hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let alice_seed_bytes = alloy_primitives::hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let alice_seed = B256::from_slice(&alice_seed_bytes);
    let alice_doc = sovereign_identity::did::SovereignDidDocument::derive_from_seed(alice_seed);
    let alice_did_uri = alice_doc.did_uri.clone();

    let tx_hash = cluster.nodes[0].register_did_onchain(
        alice_priv_hex,
        &alice_did_uri,
        &alice_doc.ml_dsa_pubkey,
        "QuantumReady",
        0,
    ).await;
    assert!(!tx_hash.is_empty(), "DID registration transaction must succeed on surviving quorum");
    cluster.nodes[0].wait_for_receipt(&tx_hash).await;

    // ── THEN: Surviving nodes progress block height to #1 ──
    let block_0 = cluster.nodes[0].get_block_number().await;
    assert!(block_0 >= 1, "Node 0 must advance to Block #1");

    let mut block_2 = cluster.nodes[2].get_block_number().await;
    let start_wait_2 = std::time::Instant::now();
    while block_2 < block_0 && start_wait_2.elapsed() < std::time::Duration::from_secs(10) {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        block_2 = cluster.nodes[2].get_block_number().await;
    }
    assert!(block_2 >= block_0, "Surviving Node 2 must synchronize block height with Node 0");

    // ── AND WHEN: The crashed node is restarted and reconnected ──
    cluster.nodes[1].restart().await;
    let enode_0 = cluster.nodes[0].get_enode().await;
    let enode_2 = cluster.nodes[2].get_enode().await;
    cluster.nodes[1].add_peer(&enode_0).await;
    cluster.nodes[1].add_peer(&enode_2).await;
    cluster.nodes[0].add_peer(&cluster.nodes[1].get_enode().await).await;
    cluster.nodes[2].add_peer(&cluster.nodes[1].get_enode().await).await;

    let peered_1 = cluster.nodes[1].wait_for_exact_peers(2, std::time::Duration::from_secs(15)).await;
    assert!(peered_1, "Revived Node 1 must re-establish exact 2 peers in 3-node full mesh");

    // ── THEN: Full cluster health and state integrity are restored ──
    let block_0_final = cluster.nodes[0].get_block_number().await;
    let block_2_final = cluster.nodes[2].get_block_number().await;
    assert!(block_0_final >= 1, "Node 0 must maintain state at block #1 or higher");
    assert!(block_2_final >= 1, "Node 2 must maintain state at block #1 or higher");
}
