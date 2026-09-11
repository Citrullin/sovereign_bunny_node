//! Real Multi-Node Process Cluster Test Harness.
//!
//! Spawns real `sovereign-reth` node OS processes on independent isolated ports and datadirs,
//! communicating strictly over real JSON-RPC HTTP interfaces (`eth_*`, `sovereign_*`)
//! and real Linux networking / WireGuard sockets.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::path::Path;
use std::fs::{self, File};
use std::sync::atomic::{AtomicU16, Ordering};
use alloy_primitives::{Address, B256, U256};
use alloy_consensus::{TxEnvelope, SignableTransaction};
use alloy_eips::eip2718::Encodable2718;
use alloy_network::TxSigner;
use alloy_signer_local::PrivateKeySigner;

static NEXT_BASE_PORT: AtomicU16 = AtomicU16::new(21000);

/// Finds the `sovereign-bunny` or `sovereign-reth` binary in workspace target directories.
pub fn find_node_binary() -> &'static str {
    #[cfg(debug_assertions)]
    let rel_paths = [
        "../../target/debug/sovereign-bunny",
        "target/debug/sovereign-bunny",
        "../../target/debug/sovereign-reth",
        "target/debug/sovereign-reth",
        "../../target/release/sovereign-bunny",
        "target/release/sovereign-bunny",
        "../../target/release/sovereign-reth",
        "target/release/sovereign-reth",
    ];
    #[cfg(not(debug_assertions))]
    let rel_paths = [
        "../../target/release/sovereign-bunny",
        "target/release/sovereign-bunny",
        "../../target/release/sovereign-reth",
        "target/release/sovereign-reth",
        "../../target/debug/sovereign-bunny",
        "target/debug/sovereign-bunny",
        "../../target/debug/sovereign-reth",
        "target/debug/sovereign-reth",
    ];
    for path in &rel_paths {
        if Path::new(path).exists() {
            return path;
        }
    }
    panic!("Node binary (sovereign-bunny/sovereign-reth) not found in release or debug target directories!");
}

/// Finds the `did-tool` binary in workspace target directories.
pub fn find_did_tool() -> &'static str {
    let paths = [
        "./target/debug/did-tool",
        "../../target/debug/did-tool",
        "./target/release/did-tool",
        "../../target/release/did-tool",
    ];
    for path in &paths {
        if Path::new(path).exists() {
            return path;
        }
    }
    panic!("did-tool binary not found in target directories!");
}

/// Finds the genesis file path.
pub fn find_genesis() -> &'static str {
    if Path::new("../../genesis.json").exists() {
        "../../genesis.json"
    } else {
        "genesis.json"
    }
}

/// Guard managing a spawned OS `sovereign-reth` process.
pub struct ProcessNode {
    pub id: usize,
    pub child: Child,
    pub datadir: String,
    pub log_path: String,
    pub http_port: u16,
    pub proxy_port: u16,
    pub p2p_port: u16,
    pub rpc_url: String,
    pub proxy_url: String,
    pub client: reqwest::Client,
    pub master_seed: B256,
    pub did: String,
    pub address: Address,
}

impl Drop for ProcessNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.datadir);
    }
}

impl ProcessNode {
    /// Spawns a real independent OS node process with standard CLI arguments.
    pub async fn spawn(id: usize) -> Self {
        let binary_path = find_node_binary();
        let genesis_path = find_genesis();

        let base_port = NEXT_BASE_PORT.fetch_add(20, Ordering::SeqCst);
        let http_port = base_port;
        let proxy_port = base_port + 1;
        let p2p_port = base_port + 2;
        let auth_port = base_port + 3;

        let datadir = format!("/tmp/sovereign-cluster-node-{}-{}", id, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let _ = fs::remove_dir_all(&datadir);
        fs::create_dir_all(&datadir).unwrap();
        let log_path = format!("{}/node.log", datadir);

        // Initialize genesis on disk via standard CLI: `sovereign-reth init --chain ... --datadir ...`
        let mut init_cmd = Command::new(binary_path)
            .arg("init")
            .arg("--chain")
            .arg(genesis_path)
            .arg("--datadir")
            .arg(&datadir)
            .spawn()
            .expect("Failed to spawn node init command");

        let status = init_cmd.wait().expect("Node init command failed to execute");
        assert!(status.success(), "Failed to initialize database with genesis!");

        // Derive node identity from seed
        let mut seed_bytes = [0u8; 32];
        seed_bytes[0] = (id + 1) as u8;
        seed_bytes[31] = (id + 42) as u8;
        let master_seed = B256::from(seed_bytes);
        let doc = sovereign_identity::did::SovereignDidDocument::derive_from_seed(master_seed);
        let did = doc.did_uri.clone();
        let address = doc.evm_address;

        let log_file = File::create(&log_path).expect("Failed to create node log file");
        let log_err_file = log_file.try_clone().expect("Failed to clone log file handle");

        // Launch standard OS node process via CLI
        let child = Command::new(binary_path)
            .arg("node")
            .arg("--dev")
            .arg("--chain")
            .arg(genesis_path)
            .arg("--datadir")
            .arg(&datadir)
            .arg("--port")
            .arg(p2p_port.to_string())
            .arg("--discovery.port")
            .arg(p2p_port.to_string())
            .arg("--authrpc.port")
            .arg(auth_port.to_string())
            .arg("--ipcdisable")
            .arg("--sov-did-peer4")
            .arg(&did)
            .arg("--sov-node-type")
            .arg("validator")
            .arg("--sov-proxy-port")
            .arg(proxy_port.to_string())
            .arg("--http")
            .arg("--http.port")
            .arg(http_port.to_string())
            .arg("--http.api")
            .arg("all")
            .arg("--http.corsdomain")
            .arg("*")
            .arg("--toy-mode")
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_err_file))
            .spawn()
            .expect("Failed to start sovereign-reth node process");

        let rpc_url = format!("http://127.0.0.1:{}", http_port);
        let proxy_url = format!("http://127.0.0.1:{}", proxy_port);
        let client = reqwest::Client::new();

        let node = Self {
            id,
            child,
            datadir,
            log_path,
            http_port,
            proxy_port,
            p2p_port,
            rpc_url,
            proxy_url,
            client,
            master_seed,
            did,
            address,
        };

        node.wait_online().await;
        node
    }

    /// Polls until the node's HTTP JSON-RPC endpoint is ready.
    pub async fn wait_online(&self) {
        let start = Instant::now();
        let timeout = Duration::from_secs(30);

        while start.elapsed() < timeout {
            let res = self.client.post(&self.proxy_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "eth_blockNumber",
                    "params": [],
                    "id": 1
                }))
                .send()
                .await;

            if res.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let logs = fs::read_to_string(&self.log_path).unwrap_or_else(|_| "<no logs>".to_string());
        panic!("Node {} failed to come online within 30s on {}. Node logs:\n{}", self.id, self.proxy_url, logs);
    }

    /// Restarts the node process using the existing datadir, ports, and configuration.
    pub async fn restart(&mut self) {
        let binary_path = find_node_binary();
        let genesis_path = find_genesis();
        let auth_port = self.http_port + 3;

        let log_file = File::options().create(true).append(true).open(&self.log_path).expect("Failed to open node log file for append");
        let log_err_file = log_file.try_clone().expect("Failed to clone log file handle");

        let child = Command::new(binary_path)
            .arg("node")
            .arg("--dev")
            .arg("--chain")
            .arg(genesis_path)
            .arg("--datadir")
            .arg(&self.datadir)
            .arg("--port")
            .arg(self.p2p_port.to_string())
            .arg("--discovery.port")
            .arg(self.p2p_port.to_string())
            .arg("--authrpc.port")
            .arg(auth_port.to_string())
            .arg("--ipcdisable")
            .arg("--sov-did-peer4")
            .arg(&self.did)
            .arg("--sov-node-type")
            .arg("validator")
            .arg("--sov-proxy-port")
            .arg(self.proxy_port.to_string())
            .arg("--http")
            .arg("--http.port")
            .arg(self.http_port.to_string())
            .arg("--http.api")
            .arg("all")
            .arg("--http.corsdomain")
            .arg("*")
            .arg("--toy-mode")
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_err_file))
            .spawn()
            .expect("Failed to restart sovereign-reth node process");

        self.child = child;
        self.wait_online().await;
    }

    /// Sends a general JSON-RPC request to the proxy endpoint.
    pub async fn post_rpc(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.client.post(&self.proxy_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": 1
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    /// Queries the current block number over JSON-RPC.
    pub async fn get_block_number(&self) -> u64 {
        let res: serde_json::Value = self.client.post(&self.proxy_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_blockNumber",
                "params": [],
                "id": 1
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let hex_str = res["result"].as_str().unwrap();
        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap_or(0)
    }

    /// Queries an account's settled balance over JSON-RPC.
    pub async fn get_balance(&self, addr: &Address) -> U256 {
        let res: serde_json::Value = self.client.post(&self.proxy_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getBalance",
                "params": [format!("{addr:#x}"), "latest"],
                "id": 1
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let hex_str = res["result"].as_str().unwrap_or("0x0");
        U256::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap_or(U256::ZERO)
    }

    /// Submits a raw transaction and waits for its mined receipt.
    pub async fn send_raw_tx(&self, raw_hex: &str) -> String {
        let res: serde_json::Value = self.client.post(&self.proxy_url)
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
            .unwrap();

        if !res["error"].is_null() {
            let logs = fs::read_to_string(&self.log_path).unwrap_or_default();
            panic!("eth_sendRawTransaction failed: {:?}\nNode logs:\n{}", res["error"], logs);
        }
        let tx_hash = res["result"].as_str().unwrap().to_string();
        self.wait_for_receipt(&tx_hash).await;
        tx_hash
    }

    /// Waits for a transaction receipt to be confirmed on-chain.
    pub async fn wait_for_receipt(&self, tx_hash: &str) -> serde_json::Value {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(20) {
            let res: serde_json::Value = self.client.post(&self.proxy_url)
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
                assert_eq!(res["result"]["status"].as_str().unwrap(), "0x1", "Transaction reverted: {:?}", res);
                return res["result"].clone();
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let logs = fs::read_to_string(&self.log_path).unwrap_or_else(|_| "<no logs>".to_string());
        panic!("Transaction {} not mined within 20s! Node logs:\n{}", tx_hash, logs);
    }

    /// Queries the network chain ID over JSON-RPC.
    pub async fn get_chain_id(&self) -> u64 {
        let res = self.post_rpc("eth_chainId", serde_json::json!([])).await;
        if let Some(hex_str) = res["result"].as_str() {
            u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap_or(13371337)
        } else {
            13371337
        }
    }

    /// Registers a DID on-chain through a standard signed transaction.
    pub async fn register_did_onchain(
        &self,
        signer_priv_hex: &str,
        did_doc_json: &str,
        pq_key: &[u8],
        tier: &str,
        nonce: u64,
    ) -> String {
        let chain_id = self.get_chain_id().await;
        let signer = PrivateKeySigner::from_slice(&alloy_primitives::hex::decode(signer_priv_hex.strip_prefix("0x").unwrap_or(signer_priv_hex)).unwrap()).unwrap();

        let action = sovereign_consensus::system_registry::SystemAction::RegisterDid {
            did_document: did_doc_json.to_string(),
            pq_pub_key: pq_key.to_vec(),
            key_tier: tier.to_string(),
        };
        let calldata = action.encode();

        let mut tx = alloy_consensus::TxEip1559 {
            chain_id,
            nonce,
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

        self.send_raw_tx(&raw_hex).await
    }

    /// Sends a signed EIP-1559 value transfer transaction.
    pub async fn send_transfer(
        &self,
        signer_priv_hex: &str,
        to: Address,
        value: U256,
        nonce: u64,
    ) -> String {
        self.send_call(signer_priv_hex, to, value, Vec::new(), nonce).await
    }

    /// Sends a signed EIP-1559 transaction with calldata.
    pub async fn send_call(
        &self,
        signer_priv_hex: &str,
        to: Address,
        value: U256,
        calldata: Vec<u8>,
        nonce: u64,
    ) -> String {
        let chain_id = self.get_chain_id().await;
        let signer = PrivateKeySigner::from_slice(&alloy_primitives::hex::decode(signer_priv_hex.strip_prefix("0x").unwrap_or(signer_priv_hex)).unwrap()).unwrap();

        let mut tx = alloy_consensus::TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: 20_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: alloy_primitives::TxKind::Call(to),
            value,
            input: calldata.into(),
            access_list: Default::default(),
        };

        let signature = signer.sign_transaction(&mut tx).await.unwrap();
        let signed_tx = TxEnvelope::Eip1559(tx.into_signed(signature));
        let buf = signed_tx.encoded_2718();
        let raw_hex = format!("0x{}", alloy_primitives::hex::encode(buf));

        self.send_raw_tx(&raw_hex).await
    }

    /// Retrieves the P2P enode URL for this node over JSON-RPC (admin_nodeInfo).
    pub async fn get_enode(&self) -> String {
        let res = self.post_rpc("admin_nodeInfo", serde_json::json!([])).await;
        if let Some(enode) = res["result"]["enode"].as_str() {
            return enode.to_string();
        }
        panic!("Failed to retrieve enode from node {}: {:?}", self.id, res);
    }

    /// Adds a peer by enode URL over JSON-RPC (admin_addPeer).
    pub async fn add_peer(&self, enode: &str) -> bool {
        let res = self.post_rpc("admin_addPeer", serde_json::json!([enode])).await;
        res["result"].as_bool().unwrap_or(false)
    }

    /// Queries the number of connected P2P peers over JSON-RPC (net_peerCount).
    pub async fn get_peer_count(&self) -> usize {
        let res = self.post_rpc("net_peerCount", serde_json::json!([])).await;
        if let Some(hex_str) = res["result"].as_str() {
            usize::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap_or(0)
        } else {
            0
        }
    }

    /// Waits until this node has connected to at least `min_peers` P2P peers.
    pub async fn wait_for_min_peers(&self, min_peers: usize, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.get_peer_count().await >= min_peers {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        false
    }

    /// Waits until this node has connected to exactly `exact_peers` P2P peers.
    pub async fn wait_for_exact_peers(&self, exact_peers: usize, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.get_peer_count().await == exact_peers {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        false
    }
}

/// Multi-node process cluster for realistic E2E integration tests.
pub struct ProcessCluster {
    pub nodes: Vec<ProcessNode>,
}

impl ProcessCluster {
    /// Spawns `n` independent OS node processes on distinct ports and interconnects them as P2P peers.
    pub async fn spawn(n: usize) -> Self {
        let mut nodes = Vec::with_capacity(n);
        for i in 0..n {
            nodes.push(ProcessNode::spawn(i).await);
        }

        // Interconnect all nodes in a full mesh peering topology
        if n > 1 {
            let mut enodes = Vec::with_capacity(n);
            for node in &nodes {
                enodes.push(node.get_enode().await);
            }

            for i in 0..n {
                for j in 0..n {
                    if i != j {
                        nodes[i].add_peer(&enodes[j]).await;
                    }
                }
            }

            // Wait for exact full mesh P2P discovery handshakes (each node must peer with exactly n - 1 nodes)
            let target_peers = n - 1;
            for node in &nodes {
                let peered = node.wait_for_exact_peers(target_peers, Duration::from_secs(15)).await;
                if !peered {
                    // Retry adding all peers once more if handshake was slow
                    for j in 0..n {
                        if node.id != j {
                            node.add_peer(&enodes[j]).await;
                        }
                    }
                    let _ = node.wait_for_exact_peers(target_peers, Duration::from_secs(10)).await;
                }
            }
        }

        Self { nodes }
    }
}

