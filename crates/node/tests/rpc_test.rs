use std::process::{Command, Child};
use std::time::{Duration, Instant};
use std::fs;
use std::path::Path;

struct NodeGuard {
    child: Child,
    datadir: String,
}

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.datadir);
    }
}

fn find_binary() -> &'static str {
    #[cfg(debug_assertions)]
    let rel_paths = [
        "../../target/debug/sovereign-reth",
        "target/debug/sovereign-reth",
        "../../target/release/sovereign-reth",
        "target/release/sovereign-reth",
    ];
    #[cfg(not(debug_assertions))]
    let rel_paths = [
        "../../target/release/sovereign-reth",
        "target/release/sovereign-reth",
        "../../target/debug/sovereign-reth",
        "target/debug/sovereign-reth",
    ];
    for path in &rel_paths {
        if Path::new(path).exists() {
            return path;
        }
    }
    panic!("sovereign-reth binary not found in release or debug target directories!");
}

#[tokio::test]
async fn test_rpc_end_to_end() -> eyre::Result<()> {
    let binary_path = find_binary();
    let datadir = format!("/tmp/sovereign-reth-test-db-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    let port = 18545;
    let proxy_port = 8546;
    let url = format!("http://localhost:{}", proxy_port);

    // Clean datadir
    let _ = fs::remove_dir_all(&datadir);
    fs::create_dir_all(&datadir)?;

    // Initialize genesis database
    let genesis_path = if Path::new("../../genesis.json").exists() {
        "../../genesis.json"
    } else {
        "genesis.json"
    };

    println!("Initializing node with genesis at {}...", genesis_path);
    let mut init_cmd = Command::new(binary_path)
        .arg("init")
        .arg("--chain")
        .arg(genesis_path)
        .arg("--datadir")
        .arg(&datadir)
        .spawn()?;
    
    let status = init_cmd.wait()?;
    assert!(status.success(), "Failed to initialize database with genesis!");

    // Start node in dev/auto-mining mode
    println!("Starting node in dev/auto-mining mode on port {}...", port);
    let child = Command::new(binary_path)
        .arg("node")
        .arg("--dev")
        .arg("--chain")
        .arg(genesis_path)
        .arg("--datadir")
        .arg(&datadir)
        .arg("--port")
        .arg("30303")
        .arg("--discovery.port")
        .arg("30303")
        .arg("--sov-proxy-port")
        .arg(proxy_port.to_string())
        .arg("--http")
        .arg("--http.port")
        .arg(port.to_string())
        .arg("--http.api")
        .arg("all")
        .arg("--http.corsdomain")
        .arg("*")
        .spawn()?;

    let _guard = NodeGuard { child, datadir };

    // Wait for the HTTP RPC server to start responding
    let start_time = Instant::now();
    let timeout = Duration::from_secs(30);
    let client = reqwest::Client::new();
    let mut online = false;

    while start_time.elapsed() < timeout {
        let res = client.post(&url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id": 1
            }))
            .send()
            .await;

        if res.is_ok() {
            online = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    assert!(online, "Node failed to start responding on HTTP port within timeout!");
    println!("Node is online! Running E2E tests...");

    // 1. Verify initial block number is 0
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;
    let block_num_hex = res["result"].as_str().unwrap();
    let block_num = u64::from_str_radix(block_num_hex.trim_start_matches("0x"), 16)?;
    assert_eq!(block_num, 0, "Initial block number should be 0!");
    println!("Initial block number verified: {}", block_num);

    // 2. Verify starting balance of the sender (0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266)
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": ["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "latest"],
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;
    let balance_hex = res["result"].as_str().unwrap();
    assert!(balance_hex.len() > 2, "Starting balance should be non-zero!");
    println!("Sender starting balance verified: {} wei (hex)", balance_hex);

    // 3. Verify starting balance of the receiver (0x81f16Dc0351D44c84234F4e4514C03cE51E6Dab3)
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": ["0x81f16Dc0351D44c84234F4e4514C03cE51E6Dab3", "latest"],
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;
    let receiver_balance_hex = res["result"].as_str().unwrap();
    println!("Receiver starting balance: {} wei (hex)", receiver_balance_hex);

    let did_tool_path = if Path::new("./target/debug/did-tool").exists() {
        "./target/debug/did-tool"
    } else if Path::new("../../target/debug/did-tool").exists() {
        "../../target/debug/did-tool"
    } else if Path::new("./target/release/did-tool").exists() {
        "./target/release/did-tool"
    } else {
        "../../target/release/did-tool"
    };

    // 4. Send the pre-signed raw transaction transferring 1 ETH from sender to receiver
    let output = Command::new(did_tool_path)
        .args(&[
            "sign-tx",
            "--private-key",
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "--to",
            "0x81f16Dc0351D44c84234F4e4514C03cE51E6Dab3",
            "--value",
            "1000000000000000000",
            "--nonce",
            "1",
            "--chain-id",
            "13371337",
        ])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let raw_tx = stdout.lines().find(|l| l.contains("Signed Transaction Hex:")).unwrap().split(": ").nth(1).unwrap().to_string();
    
    // Register the sender's DID first (E1/E3)
    println!("Registering sender DID on-chain first...");
    let sender_priv_key_bytes = alloy_primitives::hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&sender_priv_key_bytes).unwrap();
    let verifying_key = signing_key.verifying_key();
    let secp_pub_bytes = verifying_key.to_sec1_point(true).as_bytes().to_vec();

    let secp_multibase = format!("z{}", bs58::encode([&[0xe7, 0x01], secp_pub_bytes.as_slice()].concat()).into_string());
    let ed_multibase = format!("z{}", bs58::encode([&[0xed, 0x01], &[0u8; 32][..]].concat()).into_string());
    let bls_multibase = format!("z{}", bs58::encode([&[0xea, 0x01], &[0u8; 48][..]].concat()).into_string());
    let ml_multibase = format!("z{}", bs58::encode([&[0x93, 0x01], &[0u8; 32][..]].concat()).into_string());
    let slh_multibase = format!("z{}", bs58::encode([&[0x94, 0x01], &[0u8; 32][..]].concat()).into_string());
    let falcon_multibase = format!("z{}", bs58::encode([&[0x92, 0x01], &[0u8; 32][..]].concat()).into_string());
    let xmss_multibase = format!("z{}", bs58::encode([&[0x95, 0x01], &[0u8; 32][..]].concat()).into_string());

    let did_doc_json = serde_json::json!({
        "verificationMethod": [
            { "id": "#key-secp256k1", "type": "EcdsaSecp256k1VerificationKey2019", "publicKeyMultibase": secp_multibase },
            { "id": "#key-ed25519", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": ed_multibase },
            { "id": "#key-bls", "type": "Bls12381G1Key2020", "publicKeyMultibase": bls_multibase },
            { "id": "#key-mldsa", "type": "MlDsa65VerificationKey2024", "publicKeyMultibase": ml_multibase },
            { "id": "#key-slhdsa", "type": "SlhDsaSha2128fVerificationKey2024", "publicKeyMultibase": slh_multibase },
            { "id": "#key-falcon", "type": "Falcon512VerificationKey2024", "publicKeyMultibase": falcon_multibase },
            { "id": "#key-xmss", "type": "XmssSha2256VerificationKey2024", "publicKeyMultibase": xmss_multibase },
        ]
    });

    let json_str = serde_json::to_string(&did_doc_json).unwrap();
    let mut encoded = vec![0x80, 0x04];
    encoded.extend_from_slice(json_str.as_bytes());
    let doc_comp = format!("z{}", bs58::encode(&encoded).into_string());

    let hash_bytes = sovereign_crypto::hash(sovereign_crypto::HashScheme::Sha256, doc_comp.as_bytes());
    let mut prefixed = vec![0x12, 0x20];
    prefixed.extend_from_slice(&hash_bytes);
    let hash_comp = format!("z{}", bs58::encode(&prefixed).into_string());

    let did_uri = format!("did:peer:4{}:{}", hash_comp, doc_comp);

    let reg_res = register_did(&client, &url, &did_uri, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", 0).await;
    assert!(reg_res["error"].is_null(), "sovereign_registerDid failed: {:?}", reg_res["error"]);
    let reg_tx_hash = reg_res["result"].as_str().unwrap();
    println!("Sender DID registered successfully! Tx Hash: {}", reg_tx_hash);

    // Wait for the DID registration transaction to be mined
    wait_for_receipt(&client, &url, reg_tx_hash).await;

    println!("Broadcasting signed transaction...");
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx],
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;
    
    assert!(res["error"].is_null(), "eth_sendRawTransaction failed: {:?}", res["error"]);
    let tx_hash = res["result"].as_str().unwrap();
    println!("Transaction sent successfully! Hash: {}", tx_hash);

    // 5. Wait for the transaction to be mined (which should be instant in dev mode)
    println!("Waiting for transaction receipt...");
    let start = Instant::now();
    let mut receipt: Option<serde_json::Value> = None;
    while start.elapsed() < Duration::from_secs(15) {
        let res: serde_json::Value = client.post(&url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1
            }))
            .send()
            .await?
            .json()
            .await?;
        
        if !res["result"].is_null() {
            receipt = Some(res["result"].clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let receipt = receipt.expect("Transaction was not mined within timeout!");
    let status_hex = receipt["status"].as_str().unwrap();
    assert_eq!(status_hex, "0x1", "Transaction execution reverted!");
    println!("Transaction mined successfully in block: {}", receipt["blockNumber"].as_str().unwrap());

    // 6. Verify block number has increased to 1
    tokio::time::sleep(Duration::from_millis(5000)).await;
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;
    let new_block_num_hex = res["result"].as_str().unwrap();
    let new_block_num = u64::from_str_radix(new_block_num_hex.trim_start_matches("0x"), 16)?;
    assert!(new_block_num >= 1, "Block number should have increased!");
    println!("New block number verified: {}", new_block_num);

    // 7. Verify receiver balance has increased by 1 ETH
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": ["0x81f16Dc0351D44c84234F4e4514C03cE51E6Dab3", "latest"],
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;
    let new_receiver_balance_hex = res["result"].as_str().unwrap();
    println!("Receiver final balance: {} wei (hex)", new_receiver_balance_hex);

    println!("All E2E RPC tests passed successfully!");
    Ok(())
}

async fn register_did(
    client: &reqwest::Client,
    url: &str,
    did_uri: &str,
    private_key_hex: &str,
    nonce: u64,
) -> serde_json::Value {
    use alloy_consensus::{TxLegacy, TxEnvelope, SignableTransaction};
    use alloy_signer_local::PrivateKeySigner;
    use alloy_network::TxSigner;
    use alloy_rlp::Encodable;
    use alloy_primitives::U256;

    let priv_bytes = alloy_primitives::hex::decode(private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex)).unwrap();
    let signer = PrivateKeySigner::from_slice(&priv_bytes).unwrap();

    let action = sovereign_consensus::system_registry::SystemAction::RegisterDid {
        did_document: did_uri.to_string(),
        pq_pub_key: vec![1u8; 32],
        key_tier: "QuantumReady".to_string(),
    };
    let calldata = action.encode();

    let mut tx = TxLegacy {
        chain_id: Some(13371337),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 100_000,
        to: alloy_primitives::TxKind::Call(sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY),
        value: U256::ZERO,
        input: calldata.into(),
    };

    let signature = signer.sign_transaction(&mut tx).await.unwrap();
    let signed_tx = TxEnvelope::Legacy(tx.into_signed(signature));

    let mut buf = Vec::new();
    signed_tx.encode(&mut buf);
    let raw_hex = format!("0x{}", alloy_primitives::hex::encode(buf));

    client.post(url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_hex],
            "id": 1
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn wait_for_receipt(client: &reqwest::Client, url: &str, tx_hash: &str) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        let res: serde_json::Value = client.post(url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        
        if !res["result"].is_null() {
            let status = res["result"]["status"].as_str().unwrap();
            assert_eq!(status, "0x1", "Transaction reverted: {:?}", res);
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("Transaction {} not mined within 15 seconds!", tx_hash);
}

fn generate_did_for_key(private_key_hex: &str) -> String {
    let priv_bytes = alloy_primitives::hex::decode(private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex)).unwrap();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&priv_bytes).unwrap();
    let verifying_key = signing_key.verifying_key();
    let secp_pub_bytes = verifying_key.to_sec1_point(true).as_bytes().to_vec();

    let secp_multibase = format!("z{}", bs58::encode([&[0xe7, 0x01], secp_pub_bytes.as_slice()].concat()).into_string());
    let ed_multibase = format!("z{}", bs58::encode([&[0xed, 0x01], &[0u8; 32][..]].concat()).into_string());
    let bls_multibase = format!("z{}", bs58::encode([&[0xea, 0x01], &[0u8; 48][..]].concat()).into_string());
    let ml_multibase = format!("z{}", bs58::encode([&[0x93, 0x01], &[0u8; 32][..]].concat()).into_string());
    let slh_multibase = format!("z{}", bs58::encode([&[0x94, 0x01], &[0u8; 32][..]].concat()).into_string());
    let falcon_multibase = format!("z{}", bs58::encode([&[0x92, 0x01], &[0u8; 32][..]].concat()).into_string());
    let xmss_multibase = format!("z{}", bs58::encode([&[0x95, 0x01], &[0u8; 32][..]].concat()).into_string());

    let did_doc_json = serde_json::json!({
        "verificationMethod": [
            { "id": "#key-secp256k1", "type": "EcdsaSecp256k1VerificationKey2019", "publicKeyMultibase": secp_multibase },
            { "id": "#key-ed25519", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": ed_multibase },
            { "id": "#key-bls", "type": "Bls12381G1Key2020", "publicKeyMultibase": bls_multibase },
            { "id": "#key-mldsa", "type": "MlDsa65VerificationKey2024", "publicKeyMultibase": ml_multibase },
            { "id": "#key-slhdsa", "type": "SlhDsaSha2128fVerificationKey2024", "publicKeyMultibase": slh_multibase },
            { "id": "#key-falcon", "type": "Falcon512VerificationKey2024", "publicKeyMultibase": falcon_multibase },
            { "id": "#key-xmss", "type": "XmssSha2256VerificationKey2024", "publicKeyMultibase": xmss_multibase }
        ]
    });

    let json_str = serde_json::to_string(&did_doc_json).unwrap();
    let mut encoded = vec![0x80, 0x04];
    encoded.extend_from_slice(json_str.as_bytes());
    let doc_comp = format!("z{}", bs58::encode(&encoded).into_string());

    let hash_bytes = sovereign_crypto::hash(sovereign_crypto::HashScheme::Sha256, doc_comp.as_bytes());
    let mut prefixed = vec![0x12, 0x20];
    prefixed.extend_from_slice(&hash_bytes);
    let hash_comp = format!("z{}", bs58::encode(&prefixed).into_string());

    format!("did:peer:4{}:{}", hash_comp, doc_comp)
}

#[tokio::test]
async fn test_zero_gas_self_send_claim() -> eyre::Result<()> {
    let binary_path = find_binary();
    let datadir = format!("/tmp/sovereign-reth-test-db-claim-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    let port = 18550;
    let proxy_port = 8547;
    let url = format!("http://localhost:{}", proxy_port);

    // Clean datadir
    let _ = fs::remove_dir_all(&datadir);
    fs::create_dir_all(&datadir)?;

    let genesis_path = if Path::new("../../genesis.json").exists() {
        "../../genesis.json"
    } else {
        "genesis.json"
    };

    let mut init_cmd = Command::new(binary_path)
        .arg("init")
        .arg("--chain")
        .arg(genesis_path)
        .arg("--datadir")
        .arg(&datadir)
        .spawn()?;
    assert!(init_cmd.wait()?.success());

    let child = Command::new(binary_path)
        .arg("node")
        .arg("--dev")
        .arg("--chain")
        .arg(genesis_path)
        .arg("--datadir")
        .arg(&datadir)
        .arg("--port")
        .arg("30304")
        .arg("--discovery.port")
        .arg("30304")
        .arg("--authrpc.port")
        .arg("8552")
        .arg("--sov-proxy-port")
        .arg(proxy_port.to_string())
        .arg("--http")
        .arg("--http.port")
        .arg(port.to_string())
        .arg("--http.api")
        .arg("all")
        .spawn()?;

    let _guard = NodeGuard { child, datadir };

    // Wait for the HTTP RPC server
    let start_time = Instant::now();
    let timeout = Duration::from_secs(30);
    let client = reqwest::Client::new();
    let mut online = false;
    while start_time.elapsed() < timeout {
        if client.post(&url).json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        })).send().await.is_ok() {
            online = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(online);

    let did_tool_path = if Path::new("./target/debug/did-tool").exists() {
        "./target/debug/did-tool"
    } else if Path::new("../../target/debug/did-tool").exists() {
        "../../target/debug/did-tool"
    } else if Path::new("./target/release/did-tool").exists() {
        "./target/release/did-tool"
    } else {
        "../../target/release/did-tool"
    };

    // 1. Register Alice and Bob DIDs
    let alice_priv_hex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let alice_did = generate_did_for_key(alice_priv_hex);
    let reg_res_a = register_did(&client, &url, &alice_did, alice_priv_hex, 0).await;
    assert!(reg_res_a["error"].is_null(), "reg_res_a failed: {:?}", reg_res_a["error"]);
    let reg_tx_hash_a = reg_res_a["result"].as_str().unwrap();
    wait_for_receipt(&client, &url, reg_tx_hash_a).await;

    let bob_seed = format!("bob_seed_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    let bob_hash_bytes = alloy_primitives::keccak256(bob_seed.as_bytes());
    let bob_priv_bytes = bob_hash_bytes.0;
    let bob_priv_hex = format!("0x{}", alloy_primitives::hex::encode(&bob_priv_bytes));
    
    let bob_signing_key = k256::ecdsa::SigningKey::from_slice(&bob_priv_bytes).unwrap();
    let bob_verifying_key = bob_signing_key.verifying_key();
    let bob_secp_pub_bytes = bob_verifying_key.to_sec1_point(false).as_bytes().to_vec();
    let bob_hash = alloy_primitives::keccak256(&bob_secp_pub_bytes[1..]);
    let mut bob_derived = [0u8; 20];
    bob_derived.copy_from_slice(&bob_hash[12..32]);
    let wallet_b_addr = format!("{:#x}", alloy_primitives::Address::from(bob_derived));
    let bob_did = generate_did_for_key(&bob_priv_hex);

    // Fund Bob's address first so Bob can pay for gas to register DID
    println!("Funding Bob's address from Alice...");
    let output = Command::new(did_tool_path)
        .args(&[
            "sign-tx",
            "--private-key",
            alice_priv_hex,
            "--to",
            &wallet_b_addr,
            "--value",
            "1000000000000000000", // 1 ETH
            "--nonce",
            "1",
            "--chain-id",
            "13371337",
        ])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let tx_hex = stdout.lines().find(|l| l.contains("Signed Transaction Hex:")).unwrap().split(": ").nth(1).unwrap();
    let fund_res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [tx_hex],
            "id": 1
        })).send().await?.json().await?;
    assert!(fund_res["error"].is_null(), "Bob funding failed: {:?}", fund_res["error"]);
    let fund_tx_hash = fund_res["result"].as_str().unwrap();
    wait_for_receipt(&client, &url, fund_tx_hash).await;

    // Now register Bob's DID using standard registration transaction
    let reg_res_b = register_did(&client, &url, &bob_did, &bob_priv_hex, 0).await;
    assert!(reg_res_b["error"].is_null(), "reg_res_b failed: {:?}", reg_res_b["error"]);
    let reg_tx_hash_b = reg_res_b["result"].as_str().unwrap();
    wait_for_receipt(&client, &url, reg_tx_hash_b).await;

    // 2. Send 10 ETH from Alice to Bob (creating a floating send block)
    let output = Command::new(did_tool_path)
        .args(&[
            "sign-tx",
            "--private-key",
            alice_priv_hex,
            "--to",
            &wallet_b_addr,
            "--value",
            "10000000000000000000",
            "--nonce",
            "2",
            "--chain-id",
            "13371337",
        ])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let tx_hex = stdout.lines().find(|l| l.contains("Signed Transaction Hex:")).unwrap().split(": ").nth(1).unwrap();

    let send_res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [tx_hex],
            "id": 1
        })).send().await?.json().await?;
    assert!(send_res["error"].is_null());

    tokio::time::sleep(Duration::from_secs(5)).await;

    // Test eth_call targeting SYSTEM_RECEIVE_HOOK (0x02)
    {
        let receive_hook_addr = "0x0000000000000000000000000000000000000002";
        let call_res: serde_json::Value = client.post(&url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [
                    {
                        "to": receive_hook_addr,
                        "data": format!("0x000000000000000000000000{}", wallet_b_addr.strip_prefix("0x").unwrap())
                    },
                    "latest"
                ],
                "id": 1
            })).send().await?.json().await?;
        
        let result_str = call_res["result"].as_str().expect("eth_call to receive hook should succeed and return a string");
        assert_ne!(result_str, "0x887496f1f15e135db786696b6e598d370dd6a95734de912926339147223be16d", "Proxy failed to intercept eth_call and returned standard EVM SHA-256 precompile hash instead!");
        assert!(result_str.len() > 2, "Returned result must be non-empty data payload");
    }

    // Test eth_call targeting SYSTEM_JURISDICTION (0x05)
    {
        let jurisdiction_addr = "0x0000000000000000000000000000000000000005";
        let call_res: serde_json::Value = client.post(&url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_call",
                "params": [
                    {
                        "to": jurisdiction_addr,
                        "data": "0x0000000000000000000000000000000000000000000000000000000000cc07c9"
                    },
                    "latest"
                ],
                "id": 1
            })).send().await?.json().await?;
        
        assert!(call_res["error"].is_null(), "eth_call to jurisdiction failed: {:?}", call_res["error"]);
        let result_str = call_res["result"].as_str().expect("eth_call to jurisdiction should return a string");
        assert!(result_str.len() > 2, "Returned jurisdiction result must be non-empty data payload");
    }

    // Test eth_estimateGas targeting SYSTEM_JURISDICTION (0x05)
    {
        let jurisdiction_addr = "0x0000000000000000000000000000000000000005";
        let est_res: serde_json::Value = client.post(&url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_estimateGas",
                "params": [
                    {
                        "from": "0xcd86399302202407d51e0f79b8641c10f34a3b0a",
                        "to": jurisdiction_addr,
                        "data": "0x7b226d616e69666f6c645f6964223a31333337313333377d"
                    }
                ],
                "id": 1
            })).send().await?.json().await?;
        
        assert!(est_res["error"].is_null(), "eth_estimateGas targeting jurisdiction precompile failed: {:?}", est_res["error"]);
        let gas_limit = est_res["result"].as_str().expect("eth_estimateGas should return a string result");
        assert_eq!(gas_limit, "0x7a120", "Expected intercepted gas limit to be 0x7a120");
    }

    // Test batch eth_estimateGas and eth_chainId targeting SYSTEM_JURISDICTION (0x05)
    {
        let jurisdiction_addr = "0x0000000000000000000000000000000000000005";
        let batch_res: serde_json::Value = client.post(&url)
            .json(&serde_json::json!([
                {
                    "jsonrpc": "2.0",
                    "method": "eth_chainId",
                    "params": [],
                    "id": 1
                },
                {
                    "jsonrpc": "2.0",
                    "method": "eth_estimateGas",
                    "params": [
                        {
                            "from": "0xcd86399302202407d51e0f79b8641c10f34a3b0a",
                            "to": jurisdiction_addr,
                            "data": "0x7b226d616e69666f6c645f6964223a31333337313333377d"
                        }
                    ],
                    "id": 2
                }
            ])).send().await?.json().await?;
        
        let arr = batch_res.as_array().expect("batch request should return array response");
        assert_eq!(arr.len(), 2);
        assert!(arr[0]["error"].is_null());
        assert!(arr[1]["error"].is_null());
        let gas_limit = arr[1]["result"].as_str().expect("eth_estimateGas inside batch should return a string result");
        assert_eq!(gas_limit, "0x7a120", "Expected intercepted batch gas limit to be 0x7a120");
    }

    // 3. Verify Bob's settled balance is still 0 (strict settled balance invariant)
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [&wallet_b_addr, "latest"],
            "id": 1
        })).send().await?.json().await?;
    let balance_hex = res["result"].as_str().unwrap();
    let balance = u128::from_str_radix(balance_hex.trim_start_matches("0x"), 16)?;
    assert_eq!(balance, 999922250000000000, "Bob's balance should match initial gas funding + auto-claim of 1 ETH. Got: {}", balance);

    // 4. Execute 0-value, 0-gas self-send from Bob to claim the floating block
    let output = Command::new(did_tool_path)
        .args(&[
            "sign-tx",
            "--private-key",
            &bob_priv_hex,
            "--to",
            &wallet_b_addr,
            "--value",
            "0",
            "--nonce",
            "1",
            "--chain-id",
            "13371337",
            "--gas-limit",
            "21000",
            "--gas-price",
            "0",
        ])
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let tx_hex = stdout.lines().find(|l| l.contains("Signed Transaction Hex:")).unwrap().split(": ").nth(1).unwrap();

    let send_res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [tx_hex],
            "id": 1
        })).send().await?.json().await?;
    assert!(send_res["error"].is_null(), "send_res failed: {:?}", send_res["error"]);

    tokio::time::sleep(Duration::from_secs(5)).await;

    // 5. Verify Bob's settled balance is now 10 ETH!
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [&wallet_b_addr, "latest"],
            "id": 1
        })).send().await?.json().await?;
    let balance_hex = res["result"].as_str().unwrap();
    let balance = u128::from_str_radix(balance_hex.trim_start_matches("0x"), 16)?;
    assert_eq!(balance, 10999922250000000000, "Bob's balance should receive the claimed 10 ETH float. Got: {}", balance);

    Ok(())
}
