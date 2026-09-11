//! Merit, Balance Settlement, and Gas Accounting Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use crate::harness::{ProcessCluster, find_did_tool};
use alloy_primitives::{B256, U256};
use sovereign_identity::did::SovereignDidDocument;
use std::process::Command;

#[tokio::test]
async fn test_given_two_node_cluster_when_funds_transferred_then_settled_balance_replicates_to_peer() {
    // ── GIVEN: 2 independent interconnected nodes running on distinct ports ──
    let cluster = ProcessCluster::spawn(2).await;
    let node_a = &cluster.nodes[0];
    let node_b = &cluster.nodes[1];

    let did_tool = find_did_tool();

    assert_eq!(node_a.get_peer_count().await, 1, "Node A must have exactly 1 peer");
    assert_eq!(node_b.get_peer_count().await, 1, "Node B must have exactly 1 peer");

    // ── AND GIVEN: Alice registers her DID and Bob starts with zero balance ──
    let alice_priv_hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let alice_seed_bytes = alloy_primitives::hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let alice_seed = B256::from_slice(&alice_seed_bytes);
    let alice_doc = SovereignDidDocument::derive_from_seed(alice_seed);
    let alice_addr = alice_doc.evm_address;

    let reg_hash = node_a.register_did_onchain(
        alice_priv_hex,
        &alice_doc.did_uri,
        &alice_doc.ml_dsa_pubkey,
        "QuantumReady",
        0,
    ).await;
    assert!(!reg_hash.is_empty(), "Alice DID registration must succeed on-chain");

    let bob_seed = alloy_primitives::keccak256(b"bob_settled_balance_seed");
    let bob_doc = SovereignDidDocument::derive_from_seed(bob_seed);
    let bob_addr = bob_doc.evm_address;

    let bob_bal_initial_a = node_a.get_balance(&bob_addr).await;
    let bob_bal_initial_b = node_b.get_balance(&bob_addr).await;
    assert_eq!(bob_bal_initial_a, U256::ZERO, "Bob must start with zero balance on Node A");
    assert_eq!(bob_bal_initial_b, U256::ZERO, "Bob must start with zero balance on Node B");

    let alice_bal_before = node_a.get_balance(&alice_addr).await;

    // ── WHEN: Alice transfers 1 ETH to Bob on Node A ──
    let alice_nonce_res = node_a.post_rpc("eth_getTransactionCount", serde_json::json!([format!("{alice_addr:#x}"), "pending"])).await;
    let alice_nonce_hex = alice_nonce_res["result"].as_str().unwrap_or("0x1");
    let alice_nonce = u64::from_str_radix(alice_nonce_hex.trim_start_matches("0x"), 16).unwrap_or(1);
    let chain_id = node_a.get_chain_id().await;

    let send_amt = "1000000000000000000"; // 1 ETH in wei
    let fund_output = Command::new(did_tool)
        .args(&[
            "--rpc-url",
            &node_a.proxy_url,
            "sign-tx",
            "--private-key",
            alice_priv_hex,
            "--to",
            &format!("{bob_addr:#x}"),
            "--value",
            send_amt,
            "--nonce",
            &alice_nonce.to_string(),
            "--chain-id",
            &chain_id.to_string(),
        ])
        .output()
        .expect("Failed to execute did_tool sign-tx");

    let fund_stdout = String::from_utf8_lossy(&fund_output.stdout);
    let fund_stderr = String::from_utf8_lossy(&fund_output.stderr);
    assert!(fund_output.status.success(), "did_tool sign-tx failed. stdout: {}, stderr: {}", fund_stdout, fund_stderr);

    let raw_tx_line = fund_stdout.lines()
        .find(|l| l.contains("Broadcast Succeeded! Tx Hash:"))
        .and_then(|l| l.split(": ").nth(1))
        .expect("Failed to extract broadcast tx hash from did_tool output");
    let tx_hash = raw_tx_line.trim().trim_matches('"');
    node_a.wait_for_receipt(tx_hash).await;

    // ── THEN: Bob's settled balance on Node A becomes exactly 1 ETH and Alice's balance reflects the transfer ──
    let expected_amt = U256::from(1_000_000_000_000_000_000u128);
    let bob_bal_final_a = node_a.get_balance(&bob_addr).await;
    assert_eq!(bob_bal_final_a, expected_amt, "Bob's balance must reflect the settled transfer on Node A");

    let alice_bal_after = node_a.get_balance(&alice_addr).await;
    assert!(
        alice_bal_after <= alice_bal_before - expected_amt,
        "Alice balance must decrease by at least the transferred amount + gas fee"
    );

    // ── AND THEN: Bob's settled balance accurately replicates across P2P consensus to Node B ──
    let mut bob_bal_final_b = node_b.get_balance(&bob_addr).await;
    let start_wait = std::time::Instant::now();
    while bob_bal_final_b < expected_amt && start_wait.elapsed() < std::time::Duration::from_secs(10) {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        bob_bal_final_b = node_b.get_balance(&bob_addr).await;
    }
    assert_eq!(bob_bal_final_b, expected_amt, "Bob's settled balance must replicate to Node B over P2P consensus");
}
