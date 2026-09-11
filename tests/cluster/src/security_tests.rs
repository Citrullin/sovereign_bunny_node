//! Security Gating, Replay Prevention, and Identity Validation Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use crate::harness::ProcessCluster;
use alloy_primitives::{Address, B256, U256};
use alloy_consensus::{TxEnvelope, SignableTransaction};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSigner;
use alloy_signer_local::PrivateKeySigner;
use sovereign_identity::did::SovereignDidDocument;

#[tokio::test]
async fn test_given_mined_transaction_when_resubmitted_then_strictly_rejected_as_replay_attack() {
    // ── GIVEN: A 2-node cluster and a validly signed on-chain transaction ──
    let cluster = ProcessCluster::spawn(2).await;
    let node_a = &cluster.nodes[0];
    let node_b = &cluster.nodes[1];

    let alice_seed_bytes = alloy_primitives::hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let alice_seed = B256::from_slice(&alice_seed_bytes);
    let alice_doc = SovereignDidDocument::derive_from_seed(alice_seed);

    let chain_id = node_a.get_chain_id().await;
    let signer = PrivateKeySigner::from_slice(&alice_seed_bytes).unwrap();

    let action = sovereign_consensus::system_registry::SystemAction::RegisterDid {
        did_document: alice_doc.did_uri.clone(),
        pq_pub_key: alice_doc.ml_dsa_pubkey.clone(),
        key_tier: "QuantumReady".to_string(),
    };
    let calldata = action.encode();

    let mut tx = alloy_consensus::TxEip1559 {
        chain_id,
        nonce: 0,
        gas_limit: 100_000,
        max_fee_per_gas: 20_000_000_000, // 20 gwei
        max_priority_fee_per_gas: 1_000_000_000, // 1 gwei
        to: alloy_primitives::TxKind::Call(sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY),
        value: U256::ZERO,
        input: calldata.into(),
        access_list: Default::default(),
    };

    let signature = signer.sign_transaction(&mut tx).await.unwrap();
    let signed_tx = TxEnvelope::Eip1559(tx.into_signed(signature));
    let buf = signed_tx.encoded_2718();
    let raw_hex = format!("0x{}", alloy_primitives::hex::encode(buf));

    // ── WHEN: First submission is executed and mined on Node A ──
    let tx_hash = node_a.send_raw_tx(&raw_hex).await;
    assert!(!tx_hash.is_empty(), "First transaction submission must succeed");

    // ── THEN: Subsequent duplicate submissions on Node A and Node B are strictly rejected ──
    let replay_res_a = node_a.post_rpc("eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(
        replay_res_a["error"].is_object() || replay_res_a["result"].is_null(),
        "Replay on Node A must return an error: {:?}",
        replay_res_a
    );

    let first_b = node_b.post_rpc("eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    let replay_b = node_b.post_rpc("eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(
        first_b["error"].is_object() || replay_b["error"].is_object(),
        "Replay on Node B must return an error: first={:?}, replay={:?}",
        first_b,
        replay_b
    );
}

#[tokio::test]
async fn test_given_unregistered_identity_when_tx_submitted_then_pool_validation_gate_rejects() {
    // ── GIVEN: An attacker keypair that has never been registered in the DID registry ──
    let cluster = ProcessCluster::spawn(2).await;
    let node_a = &cluster.nodes[0];

    let attacker_priv = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c];
    let attacker_signer = PrivateKeySigner::from_slice(&attacker_priv).unwrap();
    let chain_id = node_a.get_chain_id().await;
    let victim_addr: Address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".parse().unwrap();

    let mut attack_tx = alloy_consensus::TxEip1559 {
        chain_id,
        nonce: 0,
        gas_limit: 100_000,
        max_fee_per_gas: 20_000_000_000, // 20 gwei
        max_priority_fee_per_gas: 1_000_000_000, // 1 gwei
        to: alloy_primitives::TxKind::Call(victim_addr),
        value: U256::from(1000),
        input: vec![].into(),
        access_list: Default::default(),
    };

    let sig = attacker_signer.sign_transaction(&mut attack_tx).await.unwrap();
    let signed_tx = TxEnvelope::Eip1559(attack_tx.into_signed(sig));
    let buf = signed_tx.encoded_2718();
    let raw_hex = format!("0x{}", alloy_primitives::hex::encode(buf));

    // ── WHEN: The unregistered attacker attempts to submit a raw transaction ──
    let res = node_a.post_rpc("eth_sendRawTransaction", serde_json::json!([raw_hex])).await;

    // ── THEN: The transaction is rejected by the transaction pool identity verification gate ──
    assert!(
        res["error"].is_object(),
        "Transaction from unregistered DID sender must be rejected by the pool: {:?}",
        res
    );
}
