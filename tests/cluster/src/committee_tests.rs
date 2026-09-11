//! Dynamic Committee Rotation, Validator Onboarding, and Leader Election Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic cluster validation.

use crate::harness::ProcessCluster;
use alloy_primitives::B256;
use sovereign_identity::did::SovereignDidDocument;

#[tokio::test]
async fn test_given_two_node_cluster_when_multiple_validators_registered_then_state_replicates_to_all_peers() {
    // ── GIVEN: 2 independent interconnected nodes running on distinct ports ──
    let cluster = ProcessCluster::spawn(2).await;
    let node_a = &cluster.nodes[0];
    let node_b = &cluster.nodes[1];

    assert_eq!(node_a.get_block_number().await, 0);
    assert_eq!(node_b.get_block_number().await, 0);
    assert_eq!(node_a.get_peer_count().await, 1, "Node A must have exactly 1 peer");
    assert_eq!(node_b.get_peer_count().await, 1, "Node B must have exactly 1 peer");

    // ── WHEN: Validator 1 registers on-chain on Node A ──
    let val1_priv_hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let val1_seed_bytes = alloy_primitives::hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let doc1 = SovereignDidDocument::derive_from_seed(B256::from_slice(&val1_seed_bytes));

    let tx_val1 = node_a.register_did_onchain(
        val1_priv_hex,
        &doc1.did_uri,
        &doc1.ml_dsa_pubkey,
        "QuantumReady",
        0,
    ).await;
    assert!(!tx_val1.is_empty(), "Validator 1 registration transaction must succeed");
    node_a.wait_for_receipt(&tx_val1).await;

    // ── AND WHEN: Validator 1 funds and registers Validator 2 ──
    let did_tool = crate::harness::find_did_tool();
    let val2_seed = alloy_primitives::keccak256(b"validator_2_committee_seed");
    let doc2 = SovereignDidDocument::derive_from_seed(val2_seed);
    let val2_priv_hex = format!("0x{}", alloy_primitives::hex::encode(val2_seed));
    let val2_addr = doc2.evm_address;

    let fund_output = std::process::Command::new(did_tool)
        .args(&[
            "sign-tx",
            "--private-key",
            val1_priv_hex,
            "--to",
            &format!("{val2_addr:#x}"),
            "--value",
            "1000000000000000000",
            "--nonce",
            "1",
            "--chain-id",
            "13371337",
            "--no-broadcast",
        ])
        .output()
        .unwrap();
    let fund_stdout = String::from_utf8(fund_output.stdout).unwrap();
    let fund_raw = fund_stdout.lines().find(|l| l.contains("Signed Transaction Hex:")).unwrap().split(": ").nth(1).unwrap();
    let fund_tx_hash = node_a.send_raw_tx(fund_raw).await;
    assert!(!fund_tx_hash.is_empty(), "Funding transaction to Validator 2 must succeed");

    let tx_val2_a = node_a.register_did_onchain(
        &val2_priv_hex,
        &doc2.did_uri,
        &doc2.ml_dsa_pubkey,
        "QuantumReady",
        0,
    ).await;
    assert!(!tx_val2_a.is_empty(), "Validator 2 registration transaction on Node A must succeed");
    node_a.wait_for_receipt(&tx_val2_a).await;

    // ── THEN: Node B synchronizes block height with Node A ──
    let block_a_final = node_a.get_block_number().await;
    let mut block_b_final = node_b.get_block_number().await;
    let start_wait = std::time::Instant::now();
    while block_b_final < block_a_final && start_wait.elapsed() < std::time::Duration::from_secs(10) {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        block_b_final = node_b.get_block_number().await;
    }
    assert!(block_b_final >= block_a_final, "Node B must sync block height with Node A");

    // ── AND THEN: Both Validator 1 and Validator 2 are confirmed registered on both Node A and Node B ──
    for (node_label, node) in [("Node A", node_a), ("Node B", node_b)] {
        for (val_label, doc) in [("Val 1", &doc1), ("Val 2", &doc2)] {
            let res = node.client.post(&node.proxy_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "eth_call",
                    "params": [
                        {
                            "to": format!("{:#x}", sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY),
                            "data": format!("0x{}", alloy_primitives::hex::encode(doc.evm_address.as_slice()))
                        },
                        "latest"
                    ],
                    "id": 1
                }))
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap();

            assert!(res["error"].is_null(), "{} {} DID query failed: {:?}", node_label, val_label, res);
            let hex_val = res["result"].as_str().unwrap_or("0x");
            assert!(hex_val.len() > 2, "{} {} must be registered on-chain. result: {:?}", node_label, val_label, res);
        }
    }
}
