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
    let rel_paths = [
        "../../target/release/sovereign-reth",
        "../../target/debug/sovereign-reth",
        "target/release/sovereign-reth",
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
    let url = format!("http://localhost:{}", port);

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

    // 3. Verify starting balance of the receiver (0x918c30482462c8024ba6cf34a18ba1f8bbdb755f)
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": ["0x918c30482462c8024ba6cf34a18ba1f8bbdb755f", "latest"],
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;
    let receiver_balance_hex = res["result"].as_str().unwrap();
    println!("Receiver starting balance: {} wei (hex)", receiver_balance_hex);

    // 4. Send the pre-signed raw transaction transferring 1 ETH from sender to receiver
    // Signed transaction details:
    // Sender: 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
    // Receiver: 0x918c30482462C8024ba6Cf34a18ba1f8bBdb755F
    // Value: 1 ETH (10^18 wei)
    // Gas Price: 1 gwei, Gas Limit: 21000, Nonce: 0, ChainId: 13371337
    let raw_tx = "0x01f87083cc07c980843b9aca0082520894918c30482462c8024ba6cf34a18ba1f8bbdb755f880de0b6b3a764000080c080a099c986756ba6708e5f1ec0015cfae419544219e63bacb20ce97e8af9cbf5bc9ba06803f04dc69211392001b3454b82d0b6288d4ad5c9f60afcc7f251e1dcf277f6";
    
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
    assert_eq!(new_block_num, 1, "Block number should have increased to 1!");
    println!("New block number verified: {}", new_block_num);

    // 7. Verify receiver balance has increased by 1 ETH
    let res: serde_json::Value = client.post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": ["0x918c30482462c8024ba6cf34a18ba1f8bbdb755f", "latest"],
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
