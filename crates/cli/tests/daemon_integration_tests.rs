//! Comprehensive Integration Test Suite for Sovereign Bunny Microservice Daemons.
//!
//! Tests real HTTP, JSON-RPC, WireGuard, and Iroh storage endpoints on live sockets.

use std::time::Duration;
use serde_json::{json, Value};
use tokio::time::sleep;
use bunny_cli::daemons::{
    run_gateway_daemon, run_identity_daemon, run_storage_daemon,
    run_enclave_daemon, run_rpc_daemon,
};

#[tokio::test]
async fn test_real_gateway_daemon_json_rpc() {
    let port = 28545;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65001).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    // 1. eth_chainId
    let resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_chainId",
            "params": []
        }))
        .send()
        .await
        .expect("Failed to query eth_chainId")
        .json()
        .await
        .expect("Failed to parse response");

    assert_eq!(resp["result"], "0xcccd39");

    // 2. eth_sendRawTransaction
    let resp_tx: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_sendRawTransaction",
            "params": ["0x010203040506070809"]
        }))
        .send()
        .await
        .expect("Failed to send raw tx")
        .json()
        .await
        .expect("Failed to parse response");

    assert!(resp_tx["result"].as_str().unwrap().starts_with("0x"));

    // 3. Batch JSON-RPC Request (ethers.js batch calls)
    let batch_resp: Value = client.post(&rpc_url)
        .json(&json!([
            { "jsonrpc": "2.0", "id": 101, "method": "eth_chainId", "params": [] },
            { "jsonrpc": "2.0", "id": 102, "method": "eth_call", "params": [{ "to": "0x0000000000000000000000000000000000000002" }, "latest"] }
        ]))
        .send()
        .await
        .expect("Failed to send batch request")
        .json()
        .await
        .expect("Failed to parse batch response");

    assert!(batch_resp.is_array());
    let arr = batch_resp.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], 101);
    assert_eq!(arr[0]["result"], "0xcccd39");
    assert_eq!(arr[1]["id"], 102);
    assert!(arr[1]["result"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn test_real_identity_daemon_endpoints() {
    let port = 28547;
    tokio::spawn(async move {
        let _ = run_identity_daemon(port).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    // Register .bunny namespace
    let resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "bunny_registerNamespace",
            "params": ["alice", "did:peer:4:z6MkuAlice", 5.0, 100]
        }))
        .send()
        .await
        .expect("Failed to register namespace")
        .json()
        .await
        .expect("Failed to parse response");

    assert_eq!(resp["result"]["name"], "alice.bunny");
    assert_eq!(resp["result"]["registered"], true);
}

#[tokio::test]
async fn test_real_storage_daemon_por_and_blob_endpoints() {
    let port = 28548;
    let dir = tempfile::tempdir().unwrap();
    let dir_path = dir.path().to_str().unwrap().to_string();

    tokio::spawn(async move {
        let _ = run_storage_daemon(1, dir_path, port).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    // 1. Store blob
    let payload_hex = hex::encode(b"Decentralized Blog Post Article on Sovereign Mesh");
    let resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "bunny_pinBlob",
            "params": [format!("0x{}", payload_hex)]
        }))
        .send()
        .await
        .expect("Failed to pin blob")
        .json()
        .await
        .expect("Failed to parse response");

    let cid = resp["result"]["cid"].as_str().expect("CID missing");
    assert!(cid.starts_with("b3:"));

    // 2. Fetch blob
    let resp_fetch: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "bunny_getBlob",
            "params": [cid]
        }))
        .send()
        .await
        .expect("Failed to get blob")
        .json()
        .await
        .expect("Failed to parse response");

    let fetched_hex = resp_fetch["result"].as_str().expect("fetched hex missing");
    assert_eq!(fetched_hex, format!("0x{}", payload_hex));

    // 3. Generate PoR proof
    let resp_por: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "bunny_generatePoR",
            "params": [cid, 0, 32]
        }))
        .send()
        .await
        .expect("Failed to generate PoR")
        .json()
        .await
        .expect("Failed to parse response");

    assert_eq!(resp_por["result"]["slice_length"], 32);
}

#[tokio::test]
async fn test_real_enclave_daemon_attestation_verification() {
    let port = 28549;
    tokio::spawn(async move {
        let _ = run_enclave_daemon(1, port).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    let mock_quote = hex::encode(b"MOCK_SGX_QUOTE_VALID_PROVEN_BY_INTEL_DCAP");
    let resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "sovereign_verifyEnclaveQuote",
            "params": [format!("0x{}", mock_quote)]
        }))
        .send()
        .await
        .expect("Failed to verify quote")
        .json()
        .await
        .expect("Failed to parse response");

    assert_eq!(resp["result"]["valid"], true);
    assert_eq!(resp["result"]["enclave_id"], 1);
}

#[tokio::test]
async fn test_real_rpc_proxy_forwarding() {
    let gateway_port = 28555;
    let rpc_proxy_port = 28556;

    // Start upstream gateway
    tokio::spawn(async move {
        let _ = run_gateway_daemon(gateway_port, 65001).await;
    });

    // Start RPC proxy pointing to upstream gateway
    let upstream = format!("http://127.0.0.1:{gateway_port}");
    tokio::spawn(async move {
        let _ = run_rpc_daemon(rpc_proxy_port, upstream).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let proxy_url = format!("http://127.0.0.1:{rpc_proxy_port}");

    let resp: Value = client.post(&proxy_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "eth_chainId",
            "params": []
        }))
        .send()
        .await
        .expect("Failed to query eth_chainId through RPC proxy")
        .json()
        .await
        .expect("Failed to parse response");

    assert_eq!(resp["result"], "0xcccd39");
}

#[tokio::test]
async fn test_real_account_lattice_paxos_and_did_resolution() {
    let port = 28557;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65001).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    let test_addr = "0x1111111111111111111111111111111111111111";

    // 1. Register DID on precompile 0x03 with structured document
    let did_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": format!("did:sovereign:13371337:{test_addr}"),
        "verificationMethod": [{
            "id": format!("did:sovereign:13371337:{test_addr}#ml-dsa"),
            "type": "JsonWebKey2020",
            "controller": format!("did:sovereign:13371337:{test_addr}")
        }]
    });

    let reg_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "bunny_registerDid",
            "params": [{
                "address": test_addr,
                "did": format!("did:sovereign:13371337:{test_addr}"),
                "doc": did_doc
            }]
        }))
        .send()
        .await
        .expect("Failed to register DID")
        .json()
        .await
        .expect("Failed to parse response");

    assert_eq!(reg_resp["result"]["status"], "registered");
    assert_eq!(reg_resp["result"]["address"], test_addr);

    // 2. Resolve DID document by EVM address
    let resolve_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 51,
            "method": "bunny_resolveDidDocument",
            "params": [test_addr]
        }))
        .send()
        .await
        .expect("Failed to resolve DID document")
        .json()
        .await
        .expect("Failed to parse response");

    assert!(resolve_resp["result"]["id"].as_str().unwrap().contains(test_addr));

    // 3. Mount Slot 0x05 (fediverse.activitypub) on-chain
    let mount_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 52,
            "method": "bunny_mountSlot",
            "params": [5, "fediverse.activitypub", "0x123456", test_addr]
        }))
        .send()
        .await
        .expect("Failed to mount slot")
        .json()
        .await
        .expect("Failed to parse response");

    assert_eq!(mount_resp["result"]["status"], "mounted");
    assert_eq!(mount_resp["result"]["slot_id"], 5);
    assert_eq!(mount_resp["result"]["sequence"], 2);

    // 4. Resolve Slot 0x0100 for Account Height
    let slot_height_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 53,
            "method": "bunny_resolveSlot",
            "params": [test_addr, "0x0100"]
        }))
        .send()
        .await
        .expect("Failed to resolve slot 0x0100")
        .json()
        .await
        .expect("Failed to parse response");

    assert_eq!(slot_height_resp["result"]["mounted"], true);
    let root_hex = slot_height_resp["result"]["root"].as_str().unwrap();
    let seq_from_hex = u64::from_str_radix(root_hex.trim_start_matches("0x"), 16).unwrap();
    assert!(seq_from_hex >= 2, "Account height on slot 0x0100 must be >= 2");

    // 5. Query Consensus State and verify Rotating Paxos Shards
    let consensus_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 54,
            "method": "sovereign_getConsensusState",
            "params": []
        }))
        .send()
        .await
        .expect("Failed to query consensus state")
        .json()
        .await
        .expect("Failed to parse response");

    let shards = consensus_resp["result"]["paxos_shards"].as_array().expect("Shards must be array");
    assert_eq!(shards.len(), 4, "Must have 4 partition shards");
}

#[tokio::test]
async fn test_zero_prefunding_and_pq_paymaster_gate() {
    let port = 28555;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65001).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    let fresh_addr = "0x2222222222222222222222222222222222222222";

    // 1. Fresh address balance must strictly be 0x0 (no pre-funded garbage)
    let bal_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBalance",
            "params": [fresh_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(bal_resp["result"], "0x0", "Fresh address must have 0 balance, not 100 pre-funded");

    // 2. Unregistered account attempting state send without paymaster must be rejected (-32001)
    let send_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_sendTransaction",
            "params": [{
                "from": fresh_addr,
                "to": "0x3333333333333333333333333333333333333333",
                "value": "0x100",
                "nonce": "0x0"
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(send_resp["error"].is_object(), "Unregistered account must be rejected");
    assert_eq!(send_resp["error"]["code"], -32001, "Expected -32001 Post-Quantum security required");

    // 3. Receiving / claiming a block on precompile 0x02 is permitted without quantum signatures or DID
    let claim_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "eth_sendTransaction",
            "params": [{
                "from": fresh_addr,
                "to": "0x0000000000000000000000000000000000000002",
                "value": "0xde0b6b3a7640000", // 1 ETH
                "nonce": "0x0"
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(claim_resp["result"].is_string(), "Claim must succeed without quantum keys");

    // 4. Balance should now reflect the claimed funds
    let bal_after_claim: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "eth_getBalance",
            "params": [fresh_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let claimed_bal_hex = bal_after_claim["result"].as_str().unwrap();
    assert_ne!(claimed_bal_hex, "0x0", "Balance must be credited from claim");
}

#[tokio::test]
async fn test_nonce_sequencing_and_rejection() {
    let port = 28556;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65001).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    let test_sender = "0x4444444444444444444444444444444444444444";

    // 1. Initial claim with valid nonce 0
    let tx1: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendTransaction",
            "params": [{
                "from": test_sender,
                "to": "0x0000000000000000000000000000000000000002",
                "nonce": "0x0"
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(tx1["result"].is_string());

    // 2. Replay same nonce 0 (stale nonce from old chain profile) -> MUST BE REJECTED (-32003)
    let replay_tx: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_sendTransaction",
            "params": [{
                "from": test_sender,
                "to": "0x0000000000000000000000000000000000000002",
                "nonce": "0x0"
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(replay_tx["error"].is_object(), "Replayed nonce must be rejected");
    assert_eq!(replay_tx["error"]["code"], -32003, "Expected -32003 Nonce too low");

    // 3. Gap nonce 5 -> MUST BE REJECTED (-32003)
    let gap_tx: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "eth_sendTransaction",
            "params": [{
                "from": test_sender,
                "to": "0x0000000000000000000000000000000000000002",
                "nonce": "0x5"
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(gap_tx["error"].is_object(), "Nonce gap must be rejected");
    assert_eq!(gap_tx["error"]["code"], -32003, "Expected -32003 Nonce too high");

    // 4. Correct sequence nonce 1 -> MUST SUCCEED
    let seq_tx: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "eth_sendTransaction",
            "params": [{
                "from": test_sender,
                "to": "0x0000000000000000000000000000000000000002",
                "nonce": "0x1"
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(seq_tx["result"].is_string(), "Sequential nonce must succeed");
}

#[tokio::test]
async fn test_continuous_rotating_paxos_epochs() {
    let port = 28559;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65001).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    // Query initial epoch
    let initial_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sovereign_getLastEpoch",
            "params": []
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let e1 = initial_resp["result"]["epoch"].as_u64().unwrap();

    // Poll up to 8 seconds for continuous epoch progression tick without any state changes
    let start = std::time::Instant::now();
    let mut e2 = e1;
    while e2 <= e1 && start.elapsed() < Duration::from_millis(8000) {
        sleep(Duration::from_millis(200)).await;
        let next_resp: Value = client.post(&rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "sovereign_getLastEpoch",
                "params": []
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(ep) = next_resp["result"]["epoch"].as_u64() {
            e2 = ep;
        }
    }

    assert!(e2 > e1, "Epoch must advance continuously via tick-driven progression (e1={}, e2={})", e1, e2);
}

#[tokio::test]
async fn test_genesis_allocations_and_real_account_history() {
    let port = 28558;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65001).await;
    });

    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");
    for _ in 0..30 {
        if let Ok(resp) = client.post(&rpc_url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": [] }))
            .send().await {
            if resp.status().is_success() {
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    let genesis_alloc_addr = "0x81f16Dc0351D44c84234F4e4514C03cE51E6Dab3";

    // 1. eth_getBalance for genesis allocated address
    let bal_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBalance",
            "params": [genesis_alloc_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(bal_resp["result"], "0xffffffffffffffffffffffff", "Genesis allocated address must have full initial balance from genesis.json");

    // 2. eth_getTransactionCount for genesis allocated address starts at 0
    let nonce_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_getTransactionCount",
            "params": [genesis_alloc_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(nonce_resp["result"], "0x0");

    // 3. sovereign_getAccountHistory returns the canonical genesis allocation transaction
    let hist_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "sovereign_getAccountHistory",
            "params": [genesis_alloc_addr]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let txs = hist_resp["result"].as_array().expect("Expected array of transactions");
    assert!(!txs.is_empty(), "Genesis account history must contain the genesis allocation");
    let gen_tx = &txs[0];
    assert_eq!(gen_tx["type"], "receive");
    assert_eq!(gen_tx["title"], "Genesis Lattice Allocation");
    assert_eq!(gen_tx["amount"], "0xffffffffffffffffffffffff");

    // 4. bunny_resolveDidDocument resolves the stored Iroh DID document
    let did_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "bunny_resolveDidDocument",
            "params": [genesis_alloc_addr]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(did_resp["result"].is_object(), "DID Document must resolve from Iroh storage: {:?}", did_resp);
    assert!(did_resp["result"]["id"].as_str().unwrap().contains("0x81f16dc0351d44c84234f4e4514c03ce51e6dab3"));

    // Explicitly register on-chain DID (Slot 0x03)
    let _reg_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "bunny_registerDid",
            "params": [genesis_alloc_addr]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // 5. bunny_resolveSlot confirms Slot 0x03 is mounted
    let slot_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "bunny_resolveSlot",
            "params": [genesis_alloc_addr, "0x03"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(slot_resp["result"]["mounted"], true, "Slot 0x03 must be mounted for registered account");

    // 6. Sending state transaction must NOT be blocked by Post-Quantum error -32001
    let send_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "eth_sendTransaction",
            "params": [{
                "from": genesis_alloc_addr,
                "to": "0x4444444444444444444444444444444444444444",
                "value": "0x1000",
                "nonce": "0x0"
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let err_code = send_resp["error"]["code"].as_i64();
    assert_ne!(err_code, Some(-32001), "Transaction must not fail with -32001 Post-Quantum security required: {:?}", send_resp);
}

#[tokio::test]
async fn test_account_lattice_send_and_claim_lifecycle() {
    let port = 28555;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65005).await;
    });

    sleep(Duration::from_millis(350)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");
    let sender_addr = "0x9999999999999999999999999999999999999999";
    let recipient_addr = "0x7777777777777777777777777777777777777777";

    // Pre-fund sender_addr and mount Slot 0x03 DID so genesis balance is untouched
    sovereign_consensus::registry::get_registry().write().unwrap().credit_account_balance(
        sender_addr.parse::<alloy_primitives::Address>().unwrap(),
        alloy_primitives::U256::from(10_000_000),
    );
    sovereign_consensus::registry::get_registry().write().unwrap().address_to_did.insert(
        sender_addr.parse::<alloy_primitives::Address>().unwrap(),
        format!("did:sovereign:13371337:{sender_addr}"),
    );

    // Query current nonce for sender_addr
    let nonce_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "eth_getTransactionCount",
            "params": [sender_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let current_nonce = nonce_resp["result"].as_str().unwrap_or("0x0");

    // 1. Send 500,000 wei from sender_addr to recipient_addr
    let send_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendTransaction",
            "params": [{
                "from": sender_addr,
                "to": recipient_addr,
                "value": "0x7a120", // 500,000 wei
                "nonce": current_nonce
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let tx_hash = send_resp["result"].as_str().expect("Send tx should return hash");
    assert!(tx_hash.starts_with("0x"));

    // 2. In an account-lattice, recipient balance MUST NOT be credited immediately
    let bal_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_getBalance",
            "params": [recipient_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(bal_resp["result"], "0x0", "Recipient balance must remain 0 before claim block is processed");

    // 3. Sender's transaction log must show status "Pending Claim"
    let hist_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "sovereign_getAccountHistory",
            "params": [sender_addr]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let txs = hist_resp["result"].as_array().expect("Expected array of transactions");
    let send_entry = txs.iter().find(|t| t["hash"] == tx_hash).expect("Send block must exist in tx history");
    assert_eq!(send_entry["status"], "Pending Claim");

    // 4. Query SYSTEM_RECEIVE_HOOK (0x02) for recipient_addr via eth_call
    // Recipient address padded to 32 bytes calldata
    let call_calldata = format!("0x{:0>64}", recipient_addr.trim_start_matches("0x"));
    let inbox_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "eth_call",
            "params": [{
                "to": "0x0000000000000000000000000000000000000002",
                "data": call_calldata
            }, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let hex_result = inbox_resp["result"].as_str().expect("eth_call must return hex string");
    let raw_bytes = hex::decode(hex_result.trim_start_matches("0x")).expect("Valid hex string");
    let parsed_json_str = if raw_bytes.len() >= 64 {
        let offset = usize::from_be_bytes(raw_bytes[24..32].try_into().unwrap());
        let len = usize::from_be_bytes(raw_bytes[56..64].try_into().unwrap());
        if raw_bytes.len() >= offset + 32 + len {
            String::from_utf8_lossy(&raw_bytes[offset + 32..offset + 32 + len]).to_string()
        } else {
            String::from_utf8_lossy(&raw_bytes).to_string()
        }
    } else {
        String::from_utf8_lossy(&raw_bytes).to_string()
    };
    let inbox: Value = serde_json::from_str(&parsed_json_str).expect("Parsed claim inbox JSON");
    let inbox_arr = inbox.as_array().expect("Claim inbox must be an array");
    assert_eq!(inbox_arr.len(), 1, "There should be exactly 1 pending claim for recipient");
    assert!(inbox_arr[0]["amount"].as_str().unwrap().starts_with("500000"));

    // 5. Recipient submits Receive block (claiming the pending send block)
    let claim_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "eth_sendTransaction",
            "params": [{
                "from": recipient_addr,
                "to": "0x0000000000000000000000000000000000000002",
                "data": tx_hash,
                "value": "0x0"
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let claim_hash = claim_resp["result"].as_str().expect("Claim tx should succeed");
    assert!(claim_hash.starts_with("0x"));

    // 6. Verify recipient's balance is now credited with 500,000 wei
    let bal_credited: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "eth_getBalance",
            "params": [recipient_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(bal_credited["result"], "0x7a120", "Recipient must now have 500,000 wei");

    // 7. Verify claim inbox for recipient is now empty
    let inbox_resp_after: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "eth_call",
            "params": [{
                "to": "0x0000000000000000000000000000000000000002",
                "data": call_calldata
            }, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let hex_result_after = inbox_resp_after["result"].as_str().unwrap();
    let raw_bytes_after = hex::decode(hex_result_after.trim_start_matches("0x")).unwrap();
    let parsed_json_str_after = if raw_bytes_after.len() >= 64 {
        let offset = usize::from_be_bytes(raw_bytes_after[24..32].try_into().unwrap());
        let len = usize::from_be_bytes(raw_bytes_after[56..64].try_into().unwrap());
        if raw_bytes_after.len() >= offset + 32 + len {
            String::from_utf8_lossy(&raw_bytes_after[offset + 32..offset + 32 + len]).to_string()
        } else {
            String::from_utf8_lossy(&raw_bytes_after).to_string()
        }
    } else {
        String::from_utf8_lossy(&raw_bytes_after).to_string()
    };
    let inbox_after: Value = serde_json::from_str(&parsed_json_str_after).unwrap();
    assert_eq!(inbox_after.as_array().unwrap().len(), 0, "Claim inbox must now have 0 pending items");

    // 8. Verify sender's transaction log updated to "Settled / Claimed"
    let hist_resp_after: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "sovereign_getAccountHistory",
            "params": [sender_addr]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let txs_after = hist_resp_after["result"].as_array().unwrap();
    let send_entry_after = txs_after.iter().find(|t| t["hash"] == tx_hash).unwrap();
    assert_eq!(send_entry_after["status"], "Settled / Claimed");
}

#[tokio::test]
async fn test_activitypub_and_signals_rpc() {
    let port = 28556;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65006).await;
    });

    sleep(Duration::from_millis(350)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    let test_author = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let author_addr = test_author.parse::<alloy_primitives::Address>().unwrap();
    // Register DID for test_author so it passes the DID check and tests solvency
    sovereign_consensus::registry::get_registry().write().unwrap().address_to_did.insert(author_addr, format!("did:sovereign:13371337:{test_author}"));

    // 1a. Attempt to post with 0 balance (Must be rejected due to lack of solvency for storage lease)
    let reject_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "bunny_postActivityPub",
            "params": [{
                "author": test_author,
                "content": "Unfunded note attempt",
                "recipient": "@lattice_mesh@sovereign.local"
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(reject_resp["error"]["code"], -32002, "Unfunded account must be rejected with solvency error -32002");

    // 1b. Fund test_author from genesis with 10 TBL
    let author_addr = test_author.parse::<alloy_primitives::Address>().unwrap();
    sovereign_consensus::registry::get_registry().write().unwrap().credit_account_balance(
        author_addr,
        alloy_primitives::U256::from(10_000_000_000_000_000_000u128),
    );

    // 1c. Post ActivityPub note with funded author
    let post_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "bunny_postActivityPub",
            "params": [{
                "author": test_author,
                "content": "Hello Sovereign Mesh Network from Lattice micro-chains!",
                "recipient": "@lattice_mesh@sovereign.local",
                "tags": ["sovereign", "p2p", "mesh"]
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(post_resp["result"]["status"], "published");
    let note_id = post_resp["result"]["note_id"].as_str().expect("Note ID required");
    assert_eq!(post_resp["result"]["duration_years"], 1);

    // 2. Get ActivityPub Outbox for test_author
    let outbox_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "bunny_getActivityPubOutbox",
            "params": [test_author]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let notes = outbox_resp["result"].as_array().expect("Outbox array");
    let found = notes.iter().find(|n| n["id"] == note_id).expect("Posted note in outbox");
    assert_eq!(found["content"], "Hello Sovereign Mesh Network from Lattice micro-chains!");

    // 3. Get ActivityPub Feed (global/mesh)
    let feed_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "bunny_getActivityPubFeed",
            "params": [10]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let feed = feed_resp["result"].as_array().expect("Feed array");
    assert!(feed.iter().any(|n| n["id"] == note_id));

    // 4. Inscribe Signal (Slot 0x54)
    let inscribe_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "bunny_inscribeSignal",
            "params": [test_author, "signal://feed/subscribe", "Subscribing to address feed"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(inscribe_resp["result"]["status"], "inscribed");
    assert_eq!(inscribe_resp["result"]["slot"], "0x54");

    // 5. Get Signals for test_author
    let get_sig_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "bunny_getSignals",
            "params": [test_author]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let sigs = get_sig_resp["result"].as_array().expect("Signals array");
    assert!(!sigs.is_empty());
    assert_eq!(sigs[0]["topic"], "signal://feed/subscribe");
}

#[tokio::test]
async fn test_raw_scale_lattice_claim_via_eth_send_raw_transaction() {
    use scale::Encode;
    use sovereign_consensus::lattice::{LatticeBlock, LatticePayload, StaticWitnessProof};
    use alloy_primitives::{Address, B256, U256};

    let port = 28556;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65006).await;
    });

    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");
    for _ in 0..30 {
        if let Ok(resp) = client.post(&rpc_url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": [] }))
            .send().await {
            if resp.status().is_success() {
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    let sender_addr = "0x8888888888888888888888888888888888888888";
    let recipient_addr = "0x6666666666666666666666666666666666666666";
    let sender = sender_addr.parse::<Address>().unwrap();
    let recipient = recipient_addr.parse::<Address>().unwrap();

    // 1. Pre-fund sender and register DID
    sovereign_consensus::registry::get_registry().write().unwrap().credit_account_balance(
        sender,
        U256::from(500_000),
    );
    sovereign_consensus::registry::get_registry().write().unwrap().address_to_did.insert(
        sender,
        format!("did:sovereign:13371337:{sender_addr}"),
    );

    // Query current nonce for sender_addr
    let nonce_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "eth_getTransactionCount",
            "params": [sender_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let current_nonce = nonce_resp["result"].as_str().unwrap_or("0x0");

    // 2. Sender dispatches Send transaction for 50,000 wei
    let send_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendTransaction",
            "params": [{
                "from": sender_addr,
                "to": recipient_addr,
                "value": "0xc350", // 50,000 wei
                "nonce": current_nonce
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let tx_hash_str = send_resp["result"].as_str().unwrap_or_else(|| panic!("Send tx should return hash, got: {:?}", send_resp));
    let send_block_hash = tx_hash_str.parse::<B256>().expect("Valid B256 hash");

    // 3. Verify recipient has 0 balance before claim
    let bal_pre: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_getBalance",
            "params": [recipient_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bal_pre["result"], "0x0");

    // 4. Verify claim inbox shows the send block
    let call_calldata = format!("0x{:0>64}", recipient_addr.trim_start_matches("0x"));
    let inbox_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "eth_call",
            "params": [{
                "to": "0x0000000000000000000000000000000000000002",
                "data": call_calldata
            }, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hex_result = inbox_resp["result"].as_str().expect("eth_call hex");
    let raw_inbox = hex::decode(hex_result.trim_start_matches("0x")).unwrap();
    let inbox_str = if raw_inbox.len() >= 64 {
        let offset = usize::from_be_bytes(raw_inbox[24..32].try_into().unwrap());
        let len = usize::from_be_bytes(raw_inbox[56..64].try_into().unwrap());
        String::from_utf8_lossy(&raw_inbox[offset + 32..offset + 32 + len]).to_string()
    } else {
        String::from_utf8_lossy(&raw_inbox).to_string()
    };
    let inbox_json: Value = serde_json::from_str(&inbox_str).unwrap();
    assert_eq!(inbox_json.as_array().unwrap().len(), 1);

    // 5. Construct SCALE-encoded LatticeBlock with LatticePayload::Receive and StaticWitnessProof (as generated by WASM)
    let witness = StaticWitnessProof {
        target_account: recipient,
        state_root: B256::ZERO,
        proof_data: vec![0xbb; 32],
        quadrant_matrix: [0; 4],
        compliance_proof: Vec::new(),
    };
    let receive_block = LatticeBlock {
        account: recipient,
        previous_hash: B256::ZERO,
        sequence: 0,
        payload: LatticePayload::Receive {
            send_block_hash,
            amount: U256::from(50_000),
        },
        signature: vec![0x42; 65],
        static_witnesses: vec![witness],
    };

    let encoded_block = receive_block.encode();
    let hex_raw_tx = format!("0x{}", hex::encode(encoded_block));

    // 6. Broadcast via eth_sendRawTransaction
    let claim_raw_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "eth_sendRawTransaction",
            "params": [hex_raw_tx]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(claim_raw_resp.get("error").is_none(), "Claim eth_sendRawTransaction failed: {:?}", claim_raw_resp);
    let claim_tx_hash = claim_raw_resp["result"].as_str().expect("Claim tx hash");
    assert!(claim_tx_hash.starts_with("0x"));

    // 7. Verify recipient's balance is now credited with 50,000 wei (0xc350)
    let bal_post: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "eth_getBalance",
            "params": [recipient_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bal_post["result"], "0xc350", "Recipient must have 50,000 wei after scale claim");

    // 8. Verify claim inbox for recipient is now empty
    let inbox_after: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "eth_call",
            "params": [{
                "to": "0x0000000000000000000000000000000000000002",
                "data": call_calldata
            }, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hex_after = inbox_after["result"].as_str().expect("eth_call hex");
    let raw_after = hex::decode(hex_after.trim_start_matches("0x")).unwrap();
    let str_after = if raw_after.len() >= 64 {
        let offset = usize::from_be_bytes(raw_after[24..32].try_into().unwrap());
        let len = usize::from_be_bytes(raw_after[56..64].try_into().unwrap());
        String::from_utf8_lossy(&raw_after[offset + 32..offset + 32 + len]).to_string()
    } else {
        String::from_utf8_lossy(&raw_after).to_string()
    };
    let inbox_after_json: Value = serde_json::from_str(&str_after).unwrap();
    assert_eq!(inbox_after_json.as_array().unwrap().len(), 0, "Claim inbox must be empty after claim");

    // 9. Verify original send transaction in history is marked "Settled / Claimed"
    let hist_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "sovereign_getAccountHistory",
            "params": [sender_addr]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let txs = hist_resp["result"].as_array().expect("Account history");
    let send_entry = txs.iter().find(|t| t["hash"] == tx_hash_str).expect("Send block in history");
    assert_eq!(send_entry["status"], "Settled / Claimed", "Original send block must show Settled / Claimed");
}

#[tokio::test]
async fn test_reclaim_send_block_lifecycle() {
    use alloy_primitives::{Address, U256};

    let port = 28557;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65007).await;
    });

    sleep(Duration::from_millis(350)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");
    let sender_addr = "0x5555555555555555555555555555555555555555";
    let recipient_addr = "0x4444444444444444444444444444444444444444";
    let sender = sender_addr.parse::<Address>().unwrap();

    // 1. Fund sender with 100,000 wei and register DID
    sovereign_consensus::registry::get_registry().write().unwrap().credit_account_balance(
        sender,
        U256::from(100_000),
    );
    sovereign_consensus::registry::get_registry().write().unwrap().address_to_did.insert(
        sender,
        format!("did:sovereign:13371337:{sender_addr}"),
    );

    // Query current nonce for sender_addr
    let nonce_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "eth_getTransactionCount",
            "params": [sender_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let current_nonce = nonce_resp["result"].as_str().unwrap_or("0x0");

    // 2. Dispatch send of 40,000 wei
    let send_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendTransaction",
            "params": [{
                "from": sender_addr,
                "to": recipient_addr,
                "value": "0x9c40", // 40,000 wei
                "nonce": current_nonce
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let tx_hash_str = send_resp["result"].as_str().expect("Send hash");

    // Sender balance is now 60,000 wei (100,000 - 40,000)
    let bal_after_send: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_getBalance",
            "params": [sender_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bal_after_send["result"], "0xea60", "Sender balance should be 60,000 wei");

    // 3. Sender triggers Reclaim via sovereign_reclaimSend RPC
    let reclaim_rpc_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "sovereign_reclaimSend",
            "params": [sender_addr, tx_hash_str]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(reclaim_rpc_resp.get("error").is_none(), "Reclaim RPC failed: {:?}", reclaim_rpc_resp);

    // 4. Verify sender balance is fully refunded to 100,000 wei (0x186a0)
    let bal_after_reclaim: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "eth_getBalance",
            "params": [sender_addr, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bal_after_reclaim["result"], "0x186a0", "Sender balance must be refunded back to 100,000 wei");

    // 5. Verify tx history shows status "Reclaimed"
    let hist_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "sovereign_getAccountHistory",
            "params": [sender_addr]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let txs = hist_resp["result"].as_array().unwrap();
    let send_entry = txs.iter().find(|t| t["hash"] == tx_hash_str).unwrap();
    assert_eq!(send_entry["status"], "Reclaimed");

    // 6. Verify claim inbox for recipient is empty
    let call_calldata = format!("0x{:0>64}", recipient_addr.trim_start_matches("0x"));
    let inbox_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "eth_call",
            "params": [{
                "to": "0x0000000000000000000000000000000000000002",
                "data": call_calldata
            }, "latest"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hex_inbox = inbox_resp["result"].as_str().unwrap();
    let raw_inbox = hex::decode(hex_inbox.trim_start_matches("0x")).unwrap();
    let str_inbox = if raw_inbox.len() >= 64 {
        let offset = usize::from_be_bytes(raw_inbox[24..32].try_into().unwrap());
        let len = usize::from_be_bytes(raw_inbox[56..64].try_into().unwrap());
        String::from_utf8_lossy(&raw_inbox[offset + 32..offset + 32 + len]).to_string()
    } else {
        String::from_utf8_lossy(&raw_inbox).to_string()
    };
    let inbox_json: Value = serde_json::from_str(&str_inbox).unwrap();
    assert_eq!(inbox_json.as_array().unwrap().len(), 0, "Recipient inbox must be cleared after reclaim");
}

#[tokio::test]
async fn test_dao_app_anchoring_and_provenance_verification() {
    let port = 28590;
    tokio::spawn(async move {
        let _ = run_gateway_daemon(port, 65001).await;
    });

    sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    let rpc_url = format!("http://127.0.0.1:{port}");

    let unfunded_addr = "0x3333333333333333333333333333333333333333";
    let _funded_addr = "0x81f16Dc0351D44c84234F4e4514C03cE51E6Dab3"; // Has genesis balance

    // 1. Unfunded account must be rejected with -32002 (Insufficient balance)
    let unfunded_anchor: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "bunny_anchorDaoApp",
            "params": [{
                "app_id": "TreasuryGovernance",
                "app_version": "v1.0.0",
                "sql_state_root": "0x1234567890123456789012345678901234567890123456789012345678901234",
                "media_cid": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "manifest_cid": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "previous_anchor": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "sender": unfunded_addr
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(unfunded_anchor["error"]["code"], -32002, "Unfunded account must be gated by solvency check");

    // 2. Funded account without registered DID must be rejected with -32001
    // (Ensure funded_addr is not yet registered on this fresh test gateway port)
    // Note: If previously registered in shared in-memory registry, register a fresh funded address:
    let funded_alice = "0x7777777777777777777777777777777777777777";
    {
        let mut reg = sovereign_consensus::registry::get_registry().write().unwrap();
        reg.account_balances.insert(funded_alice.parse().unwrap(), alloy_primitives::U256::from(1000000000000000000u64));
    }

    let no_did_anchor: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "bunny_anchorDaoApp",
            "params": [{
                "app_id": "TreasuryGovernance",
                "app_version": "v1.0.0",
                "sql_state_root": "0x1234567890123456789012345678901234567890123456789012345678901234",
                "media_cid": "0x0",
                "manifest_cid": "0x0",
                "previous_anchor": "0x0",
                "sender": funded_alice
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(no_did_anchor["error"]["code"], -32001, "Account without on-chain DID must be gated");

    // 3. Register on-chain DID for funded_alice
    let _reg_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "bunny_registerDid",
            "params": [funded_alice]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // 4. Anchor DAO App state root
    let anchor_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "bunny_anchorDaoApp",
            "params": [{
                "app_id": "TreasuryGovernance",
                "app_version": "v1.0.0",
                "sql_state_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "media_cid": "0x2222222222222222222222222222222222222222222222222222222222222222",
                "manifest_cid": "0x3333333333333333333333333333333333333333333333333333333333333333",
                "previous_anchor": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "sender": funded_alice
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(anchor_resp["result"]["status"], "anchored");
    let state_tip = anchor_resp["result"]["state_tip"].as_str().unwrap();
    assert!(state_tip.starts_with("0x"), "Must return new account state tip");

    // 5. Query recorded anchors
    let get_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "bunny_getDaoAppAnchors",
            "params": [funded_alice, "TreasuryGovernance"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let anchors = get_resp["result"].as_array().unwrap();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0]["app_id"], "TreasuryGovernance");
    assert_eq!(anchors[0]["app_version"], "v1.0.0");

    // 6. Verify cryptographic provenance & Verkle stem proof
    let verify_resp: Value = client.post(&rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "bunny_verifyDaoAppProof",
            "params": [funded_alice, "TreasuryGovernance", "v1.0.0"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(verify_resp["result"]["verified"], true);
    assert_eq!(verify_resp["result"]["provenance_valid"], true);
    assert_eq!(verify_resp["result"]["account_state_tip"], state_tip);
    assert!(verify_resp["result"]["stateless_verkle_stem"].is_string());
}


