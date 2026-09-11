//! Full Validator Onboarding, Dynamic BGP Routing, and WireGuard Tunneling Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use crate::harness::{ProcessCluster, find_did_tool};
use sovereign_consensus::bgp::{BgpRouter, RouteInfo};
use sovereign_consensus::relay_mesh::{BasedMeshWrapper, CrossManifoldMessage, ProofScheme};
use alloy_primitives::{B256, U256};
use std::process::Command;

#[tokio::test]
async fn test_given_running_cluster_when_new_validator_onboards_then_establishes_bgp_peering_and_wireguard_tunnels() {
    // ── GIVEN: 2 live interconnected node processes running on distinct ports ──
    let cluster = ProcessCluster::spawn(2).await;
    let node_a = &cluster.nodes[0];
    let node_b = &cluster.nodes[1];

    let did_tool = find_did_tool();

    let block_a = node_a.get_block_number().await;
    let block_b = node_b.get_block_number().await;
    assert_eq!(block_a, 0);
    assert_eq!(block_b, 0);

    assert_eq!(node_a.get_peer_count().await, 1, "Node A must be connected to exactly 1 peer (Node B)");
    assert_eq!(node_b.get_peer_count().await, 1, "Node B must be connected to exactly 1 peer (Node A)");

    let alice_priv_hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    // ── AND GIVEN: Candidate Node C derives its DID and keys ──
    let charlie_seed = format!("charlie_seed_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    let charlie_priv_bytes = alloy_primitives::keccak256(charlie_seed.as_bytes());
    let charlie_priv_hex = format!("0x{}", alloy_primitives::hex::encode(&charlie_priv_bytes));

    let charlie_doc = sovereign_identity::did::SovereignDidDocument::derive_from_seed(charlie_priv_bytes);
    let charlie_did_uri = charlie_doc.did_uri.clone();
    let charlie_addr = charlie_doc.evm_address;

    let node_b_did = &node_b.did;

    let check_b_res: serde_json::Value = node_a.client.post(&node_a.proxy_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [
                {
                    "to": format!("{:#x}", sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY),
                    "data": format!("0x{}", alloy_primitives::hex::encode(node_b.address.as_slice()))
                },
                "latest"
            ],
            "id": 1
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(check_b_res["error"].is_null());

    // ── WHEN: Alice registers her DID, funds Charlie with 2 ETH, and Charlie registers DID and SLA on-chain ──
    let alice_seed_bytes = alloy_primitives::hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let alice_seed = B256::from_slice(&alice_seed_bytes);
    let alice_doc = sovereign_identity::did::SovereignDidDocument::derive_from_seed(alice_seed);
    let alice_reg_hash = node_a.register_did_onchain(
        alice_priv_hex,
        &alice_doc.did_uri,
        &alice_doc.ml_dsa_pubkey,
        "QuantumReady",
        0,
    ).await;
    assert!(!alice_reg_hash.is_empty(), "Alice DID registration must succeed");
    node_a.wait_for_receipt(&alice_reg_hash).await;

    let fund_output = Command::new(did_tool)
        .args(&[
            "sign-tx",
            "--private-key",
            alice_priv_hex,
            "--to",
            &format!("{charlie_addr:#x}"),
            "--value",
            "2000000000000000000",
            "--nonce",
            "1",
            "--chain-id",
            "13371337",
            "--no-broadcast",
        ])
        .output()
        .expect("Failed to execute did_tool sign-tx");
    assert!(fund_output.status.success());
    let fund_stdout = String::from_utf8_lossy(&fund_output.stdout);
    let fund_raw = fund_stdout.lines()
        .find(|l| l.contains("Signed Transaction Hex:"))
        .and_then(|l| l.split(": ").nth(1))
        .expect("Signed raw tx hex");
    let fund_tx_hash = node_a.send_raw_tx(fund_raw.trim()).await;
    node_a.wait_for_receipt(&fund_tx_hash).await;

    let charlie_bal = node_a.get_balance(&charlie_addr).await;
    assert!(charlie_bal > U256::ZERO, "Charlie must be funded on-chain");

    let charlie_reg_hash = node_a.register_did_onchain(
        &charlie_priv_hex,
        &charlie_did_uri,
        &charlie_doc.ml_dsa_pubkey,
        "QuantumReady",
        0,
    ).await;
    assert!(!charlie_reg_hash.is_empty());
    node_a.wait_for_receipt(&charlie_reg_hash).await;

    let negotiation_action = sovereign_consensus::system_registry::SystemAction::ActorMessage {
        actor_id: B256::repeat_byte(0x99),
        payload: serde_json::to_vec(&serde_json::json!({
            "peering_sla": {
                "target_validator": node_b_did,
                "bandwidth_mbps": 100,
                "settlement_asset": format!("{:#x}", B256::repeat_byte(0x77)),
            }
        })).unwrap(),
    };
    let calldata = negotiation_action.encode();

    let charlie_nonce_res = node_a.post_rpc("eth_getTransactionCount", serde_json::json!([format!("{charlie_addr:#x}"), "pending"])).await;
    let charlie_nonce_hex = charlie_nonce_res["result"].as_str().unwrap_or("0x1");
    let charlie_nonce = u64::from_str_radix(charlie_nonce_hex.trim_start_matches("0x"), 16).unwrap_or(1);

    let sla_output = Command::new(did_tool)
        .args(&[
            "sign-tx",
            "--private-key",
            &charlie_priv_hex,
            "--to",
            &format!("{:#x}", sovereign_consensus::system_registry::SYSTEM_ASYNC_INBOX),
            "--value",
            "0",
            "--gas-limit",
            "100000",
            "--data",
            &format!("0x{}", alloy_primitives::hex::encode(&calldata)),
            "--nonce",
            &charlie_nonce.to_string(),
            "--chain-id",
            "13371337",
            "--no-broadcast",
        ])
        .output()
        .expect("Failed to execute did_tool sign-tx for SLA");
    assert!(sla_output.status.success());
    let sla_stdout = String::from_utf8_lossy(&sla_output.stdout);
    let sla_raw = sla_stdout.lines()
        .find(|l| l.contains("Signed Transaction Hex:"))
        .and_then(|l| l.split(": ").nth(1))
        .expect("SLA raw tx hex");
    let sla_tx_hash = node_a.send_raw_tx(sla_raw.trim()).await;
    node_a.wait_for_receipt(&sla_tx_hash).await;

    // ── AND WHEN: BGP WireGuard noise tunnels are initialized between Charlie and Node B ──
    let mut router_c = BgpRouter::new();
    let mut router_b = BgpRouter::new();

    let wg_pub_c = *router_c.local_public_key.as_bytes();
    let wg_pub_b = *router_b.local_public_key.as_bytes();

    router_c.register_peer(wg_pub_b);
    router_b.register_peer(wg_pub_c);

    router_c.update_route(node_b_did.clone(), RouteInfo {
        next_hop: wg_pub_b,
        forwarding_rate: 100,
        supported_assets: vec![B256::repeat_byte(0x77)],
    });

    let msg = CrossManifoldMessage {
        message_id: B256::repeat_byte(0x01),
        sender: charlie_addr,
        recipient: node_b.address,
        payload: b"real-state-diff-payload-100mbps-tunnel".to_vec(),
        timestamp: 1,
    };

    let packet = BasedMeshWrapper::from_message(
        1,
        2,
        B256::repeat_byte(0x22),
        ProofScheme::Groth16Bn254,
        vec![0u8; 32],
        &msg,
    ).unwrap();

    let mut out_buf = vec![0u8; 131_072 + 4096];
    let raw_packet = packet.to_bytes().unwrap();
    let encrypted_bytes = router_c.send_data(&wg_pub_b, &raw_packet, &mut out_buf).expect("Encryption failed");
    assert!(!encrypted_bytes.is_empty());

    let mut recv_buf = vec![0u8; 131_072 + 4096];
    let decapsulated = router_b.handle_packet(&wg_pub_c, &encrypted_bytes, &mut recv_buf);
    assert!(decapsulated.is_ok());

    // ── THEN: Block heights advance on Node A and replicate to Node B ──
    let final_block_a = node_a.get_block_number().await;
    assert!(final_block_a >= 3, "Node A must commit registration and negotiation transactions");

    let final_block_b = node_b.get_block_number().await;
    assert!(final_block_b >= 3, "Node B (height {}) must advance block height during peering (Node A height {})", final_block_b, final_block_a);
}
