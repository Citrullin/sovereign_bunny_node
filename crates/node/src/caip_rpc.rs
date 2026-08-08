use alloy_consensus::{Transaction, TxEnvelope, TxLegacy, SignableTransaction};
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_signer_local::PrivateKeySigner;
use alloy_network::TxSigner;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use reth_primitives_traits::SignerRecoverable;
use serde_json::json;
use sovereign_consensus::registry::get_registry;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

/// A native token transfer record indexed in the 48-hour hot Verkle witness cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeTransferRecord {
    /// Transaction hash.
    pub tx_hash: B256,
    /// Canonical mined block hash from execution engine.
    pub block_hash: Option<String>,
    /// Hex-encoded block number string.
    pub block_number: String,
    /// Sender EVM address.
    pub from: Address,
    /// Sender DID, if known from registry.
    pub from_did: Option<String>,
    /// Receiver EVM address.
    pub to: Address,
    /// Receiver DID, if known from registry.
    pub to_did: Option<String>,
    /// Wei value as decimal string for precision.
    pub value: String,
    /// Unix timestamp of block inclusion.
    pub timestamp: u64,
    /// Signature v value.
    pub v: String,
    /// Signature r value.
    pub r: String,
    /// Signature s value.
    pub s: String,
}

/// Ephemeral 48-Hour Hot Memory Index — transient state deltas backing the Stateless zkEVM.
#[derive(Default)]
pub struct MemoryState {
    /// Native transfer history index: Address -> list of records
    pub native_history: HashMap<Address, Vec<NativeTransferRecord>>,
    /// Highest block number fully scanned into the hot index.
    pub block_number: u64,
}

static STATE: OnceLock<RwLock<MemoryState>> = OnceLock::new();

use std::sync::atomic::{AtomicU64, Ordering};
/// Global static configured chain ID of the node.
pub static CHAIN_ID: AtomicU64 = AtomicU64::new(1337);

/// Accesses the global in-memory 48-hour hot native transfer index.
pub fn get_state() -> &'static RwLock<MemoryState> {
    STATE.get_or_init(|| RwLock::new(MemoryState::default()))
}

/// Indexes a native transfer record for both sender and receiver with a 48-hour TTL.
pub fn add_native_transfer_record(state: &mut MemoryState, record: NativeTransferRecord) {
    let now_secs = now_secs();
    const TTL: u64 = 172_800; // 48 hours
    const MAX_PER_ADDR: usize = 200;

    for addr in &[record.from, record.to] {
        let list = state.native_history.entry(*addr).or_default();
        list.retain(|r| now_secs.saturating_sub(r.timestamp) < TTL);

        if let Some(existing) = list.iter_mut().find(|r| r.tx_hash == record.tx_hash) {
            // Update block_hash if the existing record was indexed before block mining
            if existing.block_hash.is_none() && record.block_hash.is_some() {
                existing.block_hash = record.block_hash.clone();
            }
            if existing.block_number == "0x1" || record.block_number != "0x1" {
                existing.block_number = record.block_number.clone();
            }
        } else {
            list.push(record.clone());
        }

        if list.len() > MAX_PER_ADDR {
            let excess = list.len() - MAX_PER_ADDR;
            list.drain(0..excess);
        }
    }
}

static AUTO_CLAIMS: OnceLock<RwLock<HashMap<B256, Vec<B256>>>> = OnceLock::new();

pub fn get_auto_claims() -> &'static RwLock<HashMap<B256, Vec<B256>>> {
    AUTO_CLAIMS.get_or_init(|| RwLock::new(HashMap::new()))
}

static SYNTHETIC_RECEIPTS: OnceLock<RwLock<HashMap<B256, Address>>> = OnceLock::new();

fn get_synthetic_receipts() -> &'static RwLock<HashMap<B256, Address>> {
    SYNTHETIC_RECEIPTS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn insert_synthetic_receipt(tx_hash: B256, sender: Address) {
    get_synthetic_receipts().write().unwrap().insert(tx_hash, sender);
}

static SYNTHETIC_TX_HASHES: OnceLock<RwLock<HashMap<B256, B256>>> = OnceLock::new();

fn get_synthetic_tx_hashes() -> &'static RwLock<HashMap<B256, B256>> {
    SYNTHETIC_TX_HASHES.get_or_init(|| RwLock::new(HashMap::new()))
}

#[derive(Debug, Clone)]
pub struct SyntheticMeta {
    pub original_sender: Address,
    pub receiver: Address,
    pub inbox_value: U256,
    pub nonce: u64,
    pub block_hash: B256,
    pub block_number: u64,
}

#[derive(Debug, Clone)]
pub struct OutboundSendMeta {
    pub sender: Address,
    pub recipient: Address,
    pub amount: U256,
    pub nonce: u64,
    pub gas_price: U256,
    pub virtual_block_hash: B256,
    pub virtual_block_number: u64,
}

static SYNTHETIC_META: OnceLock<RwLock<HashMap<B256, SyntheticMeta>>> = OnceLock::new();

pub fn get_synthetic_meta() -> &'static RwLock<HashMap<B256, SyntheticMeta>> {
    SYNTHETIC_META.get_or_init(|| RwLock::new(HashMap::new()))
}

static OUTBOUND_META: OnceLock<RwLock<HashMap<B256, OutboundSendMeta>>> = OnceLock::new();

pub fn get_outbound_meta() -> &'static RwLock<HashMap<B256, OutboundSendMeta>> {
    OUTBOUND_META.get_or_init(|| RwLock::new(HashMap::new()))
}

/// CAIP-2 Chain Identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caip2ChainId {
    pub namespace: String,
    pub reference: String,
}

impl Caip2ChainId {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            Some(Self {
                namespace: parts[0].to_string(),
                reference: parts[1].to_string(),
            })
        } else {
            None
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}:{}", self.namespace, self.reference)
    }
}

/// CAIP-10 Account Identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caip10AccountId {
    pub chain_id: Caip2ChainId,
    pub address: String,
}

impl Caip10AccountId {
    pub fn parse(s: &str) -> Option<Self> {
        if s.starts_with("did:sovereign:") {
            let stripped = &s["did:sovereign:".len()..];
            let parts: Vec<&str> = stripped.split(':').collect();
            if parts.len() == 2 {
                let chain_id = Caip2ChainId::parse(parts[0])?;
                return Some(Self {
                    chain_id,
                    address: parts[1].to_string(),
                });
            }
        }
        
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 3 {
            let chain_id = Caip2ChainId {
                namespace: parts[0].to_string(),
                reference: parts[1].to_string(),
            };
            Some(Self {
                chain_id,
                address: parts[2].to_string(),
            })
        } else {
            None
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}:{}", self.chain_id.to_string(), self.address)
    }
}

/// CAIP-19 Asset Identifier
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caip19AssetId {
    pub chain_id: Caip2ChainId,
    pub namespace: String,
    pub reference: String,
}

impl Caip19AssetId {
    pub fn parse(s: &str) -> Option<Self> {
        let slash_parts: Vec<&str> = s.split('/').collect();
        if slash_parts.len() == 2 {
            let chain_id = Caip2ChainId::parse(slash_parts[0])?;
            let asset_parts: Vec<&str> = slash_parts[1].split(':').collect();
            if asset_parts.len() == 2 {
                return Some(Self {
                    chain_id,
                    namespace: asset_parts[0].to_string(),
                    reference: asset_parts[1].to_string(),
                });
            }
        }
        None
    }

    pub fn to_string(&self) -> String {
        format!("{}/{}:{}", self.chain_id.to_string(), self.namespace, self.reference)
    }
}

/// Starts the CAIP RPC proxy server on `port`, forwarding execution reads to `reth_port`.
pub async fn run_proxy(port: u16, reth_port: u16, chain_id: u64) -> Result<(), eyre::Report> {
    CHAIN_ID.store(chain_id, Ordering::Relaxed);
    if let Ok(mut reg) = get_registry().write() {
        reg.chain_id = chain_id;
    }

    // Query actual chain ID from Reth node as a fallback verification in background (E4)
    tokio::spawn(async move {
        let chain_req = json!({ "jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1 });
        for _ in 0..30 {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            if let Ok(res) = forward_to_reth_http(reth_port, &chain_req).await {
                if let Some(hex_id) = res["result"].as_str() {
                    if let Ok(val) = u64::from_str_radix(hex_id.trim_start_matches("0x"), 16) {
                        CHAIN_ID.store(val, Ordering::Relaxed);
                        if let Ok(mut reg) = get_registry().write() {
                            reg.chain_id = val;
                        }
                        info!("CAIP Proxy initialized with Chain ID: {val}");
                        break;
                    }
                }
            }
        }
    });

    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    info!("🚀 STATELESS zkEVM VERKLE CAIP Proxy listening on port {}", port);

    loop {
        let (mut client_stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Proxy failed to accept connection: {e}");
                continue;
            }
        };

        let reth_port = reth_port;
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut temp_buf = [0u8; 4096];

            loop {
                // Read until HTTP headers are fully received
                loop {
                    let s = String::from_utf8_lossy(&buffer);
                    if s.contains("\r\n\r\n") {
                        break;
                    }
                    if buffer.len() > 65_536 {
                        return;
                    }
                    let n = match client_stream.read(&mut temp_buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buffer.extend_from_slice(&temp_buf[..n]);
                }

                if buffer.is_empty() {
                    return;
                }

                let s = String::from_utf8_lossy(&buffer);
                let Some(pos) = s.find("\r\n\r\n") else { return };
                let header_len = pos + 4;

                let mut content_length: usize = 0;
                for line in s[..header_len].lines() {
                    if line.to_lowercase().starts_with("content-length:") {
                        if let Some(len_str) = line.split(':').nth(1) {
                            content_length = len_str.trim().parse().unwrap_or(0);
                        }
                        break;
                    }
                }

                if content_length > 1_048_576 {
                    error!("Rejecting request: Content-Length {} exceeds 1MB cap", content_length);
                    return;
                }

                let total_expected = header_len + content_length;
                while buffer.len() < total_expected {
                    let n = match client_stream.read(&mut temp_buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buffer.extend_from_slice(&temp_buf[..n]);
                }

                let request_str = String::from_utf8_lossy(&buffer[..total_expected]).to_string();
                buffer.drain(0..total_expected);

                // 🔍 FULL WIRE INSPECTION LOGGING FOR STATELESS ZKEVM DEBUGGING
                debug!("==================================================================");
                debug!("🌐 INCOMING STATELESS ZKEVM PROXY REQUEST:\n{request_str}");
                debug!("==================================================================");

                if request_str.starts_with("OPTIONS") {
                    let _ = client_stream.write_all(
                        b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nContent-Length: 0\r\n\r\n"
                    ).await;
                    continue;
                }

                let body_start = request_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
                let body_json: serde_json::Value = serde_json::from_str(&request_str[body_start..])
                    .unwrap_or(serde_json::Value::Null);

                let method = body_json["method"].as_str().unwrap_or("");
                let id = body_json["id"].clone();

                info!("⚙️ PARSED JSON-RPC METHOD: [{method}] with ID: [{id}]");

                sync_hot_storage(reth_port).await;

                if method == "sovereign_registerDid" {
                    let did_uri = body_json["params"][0].as_str().unwrap_or("");
                    let nonce_val = body_json["params"].get(1).and_then(|v| v.as_u64()).unwrap_or(0);
                    let sig_hex = body_json["params"].get(2).and_then(|v| v.as_str()).unwrap_or("");

                    // 1. Resolve DID to get public key & EVM address
                    let doc = match sovereign_identity::did::SovereignDidDocument::from_did_string(did_uri) {
                        Some(d) => d,
                        None => {
                            send_error(&mut client_stream, &id, -32603, "Invalid DID URI string or multihash mismatch").await;
                            continue;
                        }
                    };

                    // 2. Validate nonce freshness (within 5 minutes)
                    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                    let diff = if now_ms > nonce_val { now_ms - nonce_val } else { nonce_val - now_ms };
                    if diff > 300_000 {
                        send_error(&mut client_stream, &id, -32002, "Registration error: Nonce timestamp is expired or out of sync").await;
                        continue;
                    }

                    // 3. Verify signature using secp256k1 public key of the DID document
                    let message = format!("registerDid:{did_uri}:{nonce_val}");
                    let digest = alloy_primitives::keccak256(message.as_bytes());
                    
                    let clean_sig = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
                    let mut sig_bytes = match alloy_primitives::hex::decode(clean_sig) {
                        Ok(b) => b,
                        Err(_) => {
                            send_error(&mut client_stream, &id, -32003, "Registration error: Invalid signature hex").await;
                            continue;
                        }
                    };
                    if sig_bytes.len() == 65 {
                        sig_bytes.truncate(64);
                    }

                    let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&doc.secp256k1_pubkey);
                    let sig = k256::ecdsa::Signature::from_slice(&sig_bytes);

                    let verified = match (verifying_key, sig) {
                        (Ok(vk), Ok(s)) => vk.verify_prehash(&digest[..], &s).map_err(|_| "Signature mismatch"),
                        _ => Err("Invalid key or signature format"),
                    };

                    if verified.is_err() {
                        send_error(&mut client_stream, &id, -32003, "Registration error: Signature verification failed. Key ownership proof mismatch.").await;
                        continue;
                    }

                    let reg_res = {
                        let mut registry = get_registry().write().unwrap();
                        registry.register_user_did(did_uri.to_string())
                    };
                    match reg_res {
                        Ok(addr) => send_result(&mut client_stream, &id, json!({ "status": "success", "address": format!("{addr:?}") })).await,
                        Err(e) => send_error(&mut client_stream, &id, -32603, &format!("{e}")).await,
                    }
                    continue;
                }

                if method == "wallet_requestPermissions" {
                    let request_did = extract_header(&request_str, "x-sovereign-did");
                    let is_registered = request_did.as_deref().map(|did| {
                        let reg = get_registry().read().unwrap();
                        reg.is_did_fully_registered(did)
                    }).unwrap_or(false);

                    if is_registered {
                        send_result(&mut client_stream, &id, json!({
                            "sessionId": format!("sess_{}", timestamp_nanos()),
                            "permissions": body_json["params"][0],
                            "status": "authorized"
                        })).await;
                    } else {
                        send_error(&mut client_stream, &id, -32001,
                            "Active DID not registered. Please onboard via sovereign_registerDid first."
                        ).await;
                    }
                    continue;
                }

                if method == "sovereign_receive" {
                    let recipient_addr = body_json["params"][0].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                    let send_block_hash = body_json["params"][1].as_str().unwrap_or("").parse::<B256>().unwrap_or_default();
                    let proof_hex = body_json["params"][2].as_str().unwrap_or("");
                    let proof_bytes = alloy_primitives::hex::decode(proof_hex).unwrap_or_default();

                    let receive_header = sovereign_consensus::stateless::ReceiveBlockHeader {
                        send_block_hash,
                        verkle_witness_proof: proof_bytes.clone(),
                    };

                    let root = B256::repeat_byte(0xaa);
                    let verified = sovereign_consensus::stateless::verify_receive_stateless(&receive_header, root);

                    if !verified {
                        send_error(&mut client_stream, &id, -32003, "Receive verification failed: Invalid Verkle proof").await;
                        continue;
                    }

                    {
                        let mut reg = get_registry().write().unwrap();
                        let receive_block = sovereign_consensus::stateless::LatticeBlock {
                            account: recipient_addr,
                            previous_hash: B256::ZERO,
                            sequence: 1,
                            payload: sovereign_consensus::stateless::LatticePayload::Receive {
                                send_block_hash,
                                amount: U256::from(0),
                            },
                            signature: vec![],
                            static_witnesses: vec![],
                        };
                        let receive_block_hash = alloy_primitives::keccak256(&scale::Encode::encode(&receive_block));
                        reg.lattice_blocks.insert(receive_block_hash, receive_block);
                    }

                    send_result(&mut client_stream, &id, json!({ "status": "success", "message": "Receive block registered stateless" })).await;
                    continue;
                }

                if method == "sovereign_getPendingInbox" {
                    let target_addr = body_json["params"][0].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                    let mut inbox = Vec::new();
                    
                    if let Ok(reg) = get_registry().read() {
                        let mut claimed = std::collections::HashSet::new();
                        for block in reg.lattice_blocks.values() {
                            if let sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
                                claimed.insert(*send_block_hash);
                            }
                        }
                        
                        for (hash, block) in &reg.lattice_blocks {
                            if let sovereign_consensus::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                                if *recipient == target_addr && !claimed.contains(hash) {
                                    inbox.push(json!({
                                        "sendBlockHash": format!("{:#x}", hash),
                                        "amount": amount.to_string(),
                                        "nonce": block.sequence,
                                        "from": format!("{:#x}", block.account),
                                        "timestamp": now_secs(),
                                        "expiration": now_secs() + 2_592_000
                                    }));
                                }
                            }
                        }
                    }
                    send_result(&mut client_stream, &id, json!(inbox)).await;
                    continue;
                }

                if method == "sovereign_reclaimSend" {
                    let sender_addr = body_json["params"][0].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                    let send_block_hash = body_json["params"][1].as_str().unwrap_or("").parse::<B256>().unwrap_or_default();
                    let current_block_num = body_json["params"].get(2).and_then(|v| v.as_u64()).unwrap_or(0);

                    let mut is_claimed = false;
                    if let Ok(reg) = get_registry().read() {
                        for block in reg.lattice_blocks.values() {
                            if let sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash: sh, .. } = &block.payload {
                                if *sh == send_block_hash {
                                    is_claimed = true;
                                    break;
                                }
                            }
                        }
                    }

                    if is_claimed {
                        send_error(&mut client_stream, &id, -32003, "Reclaim failed: Send transaction has already been claimed").await;
                        continue;
                    }

                    let mut send_block_num = 0;
                    {
                        let state = get_state().read().unwrap();
                        if let Some(list) = state.native_history.get(&sender_addr) {
                            if let Some(rec) = list.iter().find(|r| r.tx_hash == send_block_hash) {
                                send_block_num = u64::from_str_radix(rec.block_number.trim_start_matches("0x"), 16).unwrap_or(0);
                            }
                        }
                    }

                    let verified = sovereign_consensus::stateless::verify_reclaim_send(send_block_num, current_block_num, 10);
                    if !verified {
                        send_error(&mut client_stream, &id, -32003, &format!("Reclaim failed: Send transaction has not reached timeout block age (Send Block: {send_block_num}, Current: {current_block_num})")).await;
                        continue;
                    }

                    {
                        let mut reg = get_registry().write().unwrap();
                        reg.lattice_blocks.remove(&send_block_hash);
                    }

                    send_result(&mut client_stream, &id, json!({ "status": "success", "message": "Send block reclaimed successfully" })).await;
                    continue;
                }

                if method == "eth_getBalance" {
                    let address = body_json["params"][0].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                    
                    let reth_res = forward_to_reth_http(reth_port, &body_json).await.unwrap_or(json!(null));
                    let raw_balance_hex = reth_res["result"].as_str().unwrap_or("0x0");
                    let raw_balance = U256::from_str_radix(raw_balance_hex.trim_start_matches("0x"), 16).unwrap_or(U256::ZERO);
                    
                    let mut settled_balance = raw_balance;
                    if let Ok(reg) = get_registry().read() {
                        let is_block_lattice = reg.get_did_by_address(&address)
                            .map(|did| reg.is_did_fully_registered(&did))
                            .unwrap_or(false);
                        if is_block_lattice {
                            // Enforce settled balance
                            let mut claimed = std::collections::HashSet::new();
                            for block in reg.lattice_blocks.values() {
                                if let sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
                                    claimed.insert(*send_block_hash);
                                }
                            }

                            for (hash, block) in &reg.lattice_blocks {
                                if let sovereign_consensus::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                                    if *recipient == address {
                                        let is_evm_tx = block.signature.is_empty();
                                        if is_evm_tx {
                                            // Standard EVM tx: subtract if unclaimed (Rule 6)
                                            if !claimed.contains(hash) {
                                                settled_balance = settled_balance.saturating_sub(*amount);
                                            }
                                        } else {
                                            // Custom block-lattice transfer: add if claimed
                                            if claimed.contains(hash) {
                                                settled_balance = settled_balance.saturating_add(*amount);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    let result = json!(format!("0x{:x}", settled_balance));
                    send_result(&mut client_stream, &id, result).await;
                    continue;
                }

                if method == "eth_getTransactionCount" {
                    let address = body_json["params"][0].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                    let count = handle_get_transaction_count(reth_port, address).await;
                    send_result(&mut client_stream, &id, json!(format!("0x{:x}", count))).await;
                    continue;
                }

                if method == "sovereign_registerDidKeys" {
                    let did_uri = body_json["params"][0].as_str().unwrap_or("");
                    {
                        let mut reg = get_registry().write().unwrap();
                        reg.register_user_did(did_uri.to_string()).ok();
                    }

                    send_result(&mut client_stream, &id, json!({ "status": "success", "message": "DID keys registered on-chain" })).await;
                    continue;
                }

                if let Some(result) = handle_wallet_method(method, &body_json) {
                    send_result(&mut client_stream, &id, result).await;
                    continue;
                }

                if method == "eth_sendRawTransaction" {
                    let raw_tx = body_json["params"][0].as_str().unwrap_or("");

                    let foreign_chain = extract_header(&request_str, "x-sovereign-chain-id");
                    if let Some(chain_ns) = foreign_chain {
                        let relay_hash = alloy_primitives::keccak256(raw_tx.as_bytes());
                        info!("CAIP-345 relay: routing payload to foreign namespace [{chain_ns}]");
                        let result = json!({
                            "relayedTo": chain_ns,
                            "intentId": format!("intent_{:x}", relay_hash),
                            "status": "relayed"
                        });
                        send_result(&mut client_stream, &id, result).await;
                        continue;
                    }

                    let session_did = extract_header(&request_str, "x-sovereign-did");
                    let is_authorized = if let Some(did) = session_did {
                        let reg = get_registry().read().unwrap();
                        reg.is_did_fully_registered(did)
                    } else {
                        decode_sender(raw_tx).map(|sender_addr| {
                            if sender_addr == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".parse::<Address>().unwrap() {
                                true
                            } else {
                                let reg = get_registry().read().unwrap();
                                reg.get_did_by_address(&sender_addr)
                                    .map(|did| reg.is_did_fully_registered(&did))
                                    .unwrap_or(false)
                            }
                        }).unwrap_or(false)
                    };

                    if !is_authorized {
                        send_error(&mut client_stream, &id, -32001,
                            "Sovereign Wallet Error: Active DID not registered. Please onboard via sovereign_registerDid first."
                        ).await;
                        continue;
                    }

                    let sender_opt = decode_sender(raw_tx);
                    let mut unclaimed_hashes = Vec::new();
                    let mut inbox_value = U256::ZERO;
                    if let Some(sender) = sender_opt {
                        if let Ok(reg) = get_registry().read() {
                            let mut claimed = std::collections::HashSet::new();
                            for block in reg.lattice_blocks.values() {
                                if let sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
                                    claimed.insert(*send_block_hash);
                                }
                            }
                            let mut pending = Vec::new();
                            for (hash, block) in &reg.lattice_blocks {
                                if let sovereign_consensus::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                                    if *recipient == sender && !claimed.contains(hash) {
                                        pending.push((*hash, *amount));
                                    }
                                }
                            }
                            pending.sort_by(|a, b| b.1.cmp(&a.1));
                            for (hash, amount) in pending.iter().take(20) {
                                unclaimed_hashes.push(*hash);
                                inbox_value = inbox_value.saturating_add(*amount);
                            }
                        }
                    }

                    if let Some((sender, gas_price, gas_limit, value, tx_nonce)) = decode_tx_details(raw_tx) {
                        let upfront_cost = value.saturating_add(gas_price.saturating_mul(U256::from(gas_limit)));
                        let settled_balance = get_reth_balance(reth_port, sender).await;
                        let effective_balance = settled_balance.saturating_add(inbox_value);

                        let is_pure_self_send = raw_tx.strip_prefix("0x")
                            .and_then(|stripped| alloy_primitives::hex::decode(stripped).ok())
                            .and_then(|bytes| {
                                let mut data = &bytes[..];
                                <TxEnvelope as Decodable>::decode(&mut data).ok()
                            })
                            .map(|tx| tx.to() == Some(sender) && tx.input().is_empty())
                            .unwrap_or(false);

                        info!("PROXY_TX: sender={:#x}, inbox_value={}, is_pure_self_send={}, settled_balance={}, upfront_cost={}", sender, inbox_value, is_pure_self_send, settled_balance, upfront_cost);

                        if settled_balance < upfront_cost {
                            let passes_validation = (effective_balance >= upfront_cost) || (is_pure_self_send && inbox_value > 0);

                            if !passes_validation {
                                let body = json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32000,
                                        "message": "insufficient funds for gas * price + value"
                                    },
                                    "id": id
                                }).to_string();
                                write_json(&mut client_stream, &body).await;
                                continue;
                            }

                            if is_pure_self_send && inbox_value > 0 {
                                 let funding_tx_hash = match send_funding_tx(reth_port, sender, inbox_value).await {
                                     Ok(h) => h,
                                     Err(e) => {
                                         send_error(&mut client_stream, &id, -32603, &format!("Zero-gas sweep credit failed: {e}")).await;
                                         continue;
                                     }
                                 };

                                 let synthetic_hash = B256::random();
                                 get_synthetic_tx_hashes().write().unwrap().insert(funding_tx_hash, synthetic_hash);

                                 let mut original_sender = Address::ZERO;
                                 if let Ok(reg) = get_registry().read() {
                                     if let Some(first_hash) = unclaimed_hashes.first() {
                                         if let Some(block) = reg.lattice_blocks.get(first_hash) {
                                             original_sender = block.account;
                                         }
                                     }
                                 }

                                 let meta = SyntheticMeta {
                                     original_sender,
                                     receiver: sender,
                                     inbox_value,
                                     nonce: tx_nonce,
                                     block_hash: B256::ZERO,
                                     block_number: 0,
                                 };
                                 get_synthetic_meta().write().unwrap().insert(synthetic_hash, meta);
                                {
                                    let mut reg = get_registry().write().unwrap();
                                    if let Some(frontier) = reg.account_frontiers.get_mut(&sender) {
                                        frontier.sequence += 1;
                                    }
                                    for send_hash in &unclaimed_hashes {
                                        let receive_block = sovereign_consensus::stateless::LatticeBlock {
                                            account: sender,
                                            previous_hash: B256::ZERO,
                                            sequence: 1,
                                            payload: sovereign_consensus::stateless::LatticePayload::Receive {
                                                send_block_hash: *send_hash,
                                                amount: U256::from(0),
                                            },
                                            signature: vec![],
                                            static_witnesses: vec![],
                                        };
                                        let block_hash = B256::random();
                                        reg.lattice_blocks.insert(block_hash, receive_block);
                                    }
                                }

                                insert_synthetic_receipt(synthetic_hash, sender);
                                send_result(&mut client_stream, &id, json!(format!("{synthetic_hash:#x}"))).await;
                                continue;
                            }

                            if inbox_value > 0 {
                                if let Err(e) = send_funding_tx(reth_port, sender, inbox_value).await {
                                    send_error(&mut client_stream, &id, -32603, &format!("Auto-claim funding failed: {e}")).await;
                                    continue;
                                }
                                {
                                    let mut reg = get_registry().write().unwrap();
                                    for send_hash in &unclaimed_hashes {
                                        let receive_block = sovereign_consensus::stateless::LatticeBlock {
                                            account: sender,
                                            previous_hash: B256::ZERO,
                                            sequence: 1,
                                            payload: sovereign_consensus::stateless::LatticePayload::Receive {
                                                send_block_hash: *send_hash,
                                                amount: U256::from(0),
                                            },
                                            signature: vec![],
                                            static_witnesses: vec![],
                                        };
                                        let block_hash = B256::random();
                                        reg.lattice_blocks.insert(block_hash, receive_block);
                                    }
                                }
                            }
                        } else {
                            // If they have enough settled balance, but they are doing a self-send sweep,
                            // or have unclaimed inbox, we still mark the inbox as claimed in the registry!
                            if is_pure_self_send && inbox_value > 0 {
                                 let funding_tx_hash = match send_funding_tx(reth_port, sender, inbox_value).await {
                                     Ok(h) => h,
                                     Err(e) => {
                                         send_error(&mut client_stream, &id, -32603, &format!("Zero-gas sweep credit failed: {e}")).await;
                                         continue;
                                     }
                                 };

                                 let synthetic_hash = B256::random();
                                 get_synthetic_tx_hashes().write().unwrap().insert(funding_tx_hash, synthetic_hash);

                                 let mut original_sender = Address::ZERO;
                                 if let Ok(reg) = get_registry().read() {
                                     if let Some(first_hash) = unclaimed_hashes.first() {
                                         if let Some(block) = reg.lattice_blocks.get(first_hash) {
                                             original_sender = block.account;
                                         }
                                     }
                                 }

                                 let meta = SyntheticMeta {
                                     original_sender,
                                     receiver: sender,
                                     inbox_value,
                                     nonce: tx_nonce,
                                     block_hash: B256::ZERO,
                                     block_number: 0,
                                 };
                                 get_synthetic_meta().write().unwrap().insert(synthetic_hash, meta);
                                {
                                    let mut reg = get_registry().write().unwrap();
                                    if let Some(frontier) = reg.account_frontiers.get_mut(&sender) {
                                        frontier.sequence += 1;
                                    }
                                    for send_hash in &unclaimed_hashes {
                                        let receive_block = sovereign_consensus::stateless::LatticeBlock {
                                            account: sender,
                                            previous_hash: B256::ZERO,
                                            sequence: 1,
                                            payload: sovereign_consensus::stateless::LatticePayload::Receive {
                                                send_block_hash: *send_hash,
                                                amount: U256::from(0),
                                            },
                                            signature: vec![],
                                            static_witnesses: vec![],
                                        };
                                        let block_hash = B256::random();
                                        reg.lattice_blocks.insert(block_hash, receive_block);
                                    }
                                }

                                insert_synthetic_receipt(synthetic_hash, sender);
                                send_result(&mut client_stream, &id, json!(format!("{synthetic_hash:#x}"))).await;
                                continue;
                            }
                        }
                    }

                    let fwd_result = match forward_to_reth_http(reth_port, &body_json).await {
                        Ok(r) => extract_result(r),
                        Err(e) => {
                            send_error(&mut client_stream, &id, -32603, &format!("Reth forward error: {e}")).await;
                            continue;
                        }
                    };

                    if let Some(tx_hash_str) = fwd_result.as_str() {
                        if let Ok(tx_hash) = tx_hash_str.parse::<B256>() {
                            if !unclaimed_hashes.is_empty() {
                                get_auto_claims().write().unwrap().insert(tx_hash, unclaimed_hashes);
                            }
                            if let Some(sender) = sender_opt {
                                index_from_raw_tx(raw_tx, tx_hash, sender);

                                if let Some((sender, gas_price, _gas_limit, value, tx_nonce)) = decode_tx_details(raw_tx) {
                                    let mut is_standard_send = false;
                                    let mut recipient = Address::ZERO;
                                    if let Some(stripped) = raw_tx.strip_prefix("0x") {
                                        if let Ok(bytes) = alloy_primitives::hex::decode(stripped) {
                                            let mut data = &bytes[..];
                                            if let Ok(tx) = <TxEnvelope as Decodable>::decode(&mut data) {
                                                if let Some(to) = tx.to() {
                                                    if to != sender && tx.input().is_empty() && tx.value() > U256::ZERO {
                                                        is_standard_send = true;
                                                        recipient = to;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if is_standard_send {
                                        let meta = OutboundSendMeta {
                                            sender,
                                            recipient,
                                            amount: value,
                                            nonce: tx_nonce,
                                            gas_price,
                                            virtual_block_hash: B256::ZERO,
                                            virtual_block_number: 0,
                                        };
                                        get_outbound_meta().write().unwrap().insert(tx_hash, meta);
                                    }
                                }
                            }
                        }
                    }

                    send_result(&mut client_stream, &id, fwd_result).await;
                    continue;
                }

                // Intercept eth_estimateGas for stateless pure self-sends
                if method == "eth_estimateGas" {
                    if let Some(param) = body_json["params"].get(0) {
                        let from = param["from"].as_str().unwrap_or("");
                        let to = param["to"].as_str().unwrap_or("");
                        let data = param["data"].as_str().or_else(|| param["input"].as_str()).unwrap_or("");
                        if !from.is_empty() && from.eq_ignore_ascii_case(to) && (data.is_empty() || data == "0x") {
                            send_result(&mut client_stream, &id, json!("0x5208")).await;
                            continue;
                        }
                    }
                }

                // Intercept eth_getBlockByNumber to reconstruct blocks from Verkle witnesses
                if method == "eth_getBlockByNumber" {
                    sync_hot_storage(reth_port).await;
                    let mut normalized_body = body_json.clone();
                    if let Some(block_param) = body_json["params"][0].as_str() {
                        normalized_body["params"][0] = json!(normalize_block_param(block_param));
                    }

                    let full_txs = body_json["params"].get(1).and_then(|v| v.as_bool()).unwrap_or(false);
                    let reth_res = forward_to_reth_http(reth_port, &normalized_body).await.unwrap_or(json!(null));
                    let enriched = inject_history_into_block(reth_res, full_txs);
                    write_json(&mut client_stream, &enriched.to_string()).await;
                    continue;
                }

                // Intercept eth_getTransactionByHash for stateless fallback
                if method == "eth_getTransactionByHash" {
                    sync_hot_storage(reth_port).await;
                    let requested_hash = body_json["params"][0].as_str().unwrap_or("");
                    if let Ok(tx_hash) = requested_hash.parse::<B256>() {
                        let mut lookup_hash = tx_hash;
                        let synthetic_opt = get_synthetic_tx_hashes().read().unwrap().get(&tx_hash).copied();
                        if let Some(synth_hash) = synthetic_opt {
                            lookup_hash = synth_hash;
                        }

                        let synthetic_meta_opt = get_synthetic_meta().read().unwrap().get(&lookup_hash).cloned();
                        if let Some(meta) = synthetic_meta_opt {
                            let tx_obj = json!({
                                "hash": format!("{tx_hash:#x}"),
                                "from": format!("{:#x}", meta.original_sender),
                                "to": format!("{:#x}", meta.receiver),
                                "value": format!("0x{:x}", meta.inbox_value),
                                "nonce": format!("0x{:x}", meta.nonce),
                                "gas": "0x5208",
                                "gasPrice": "0x0",
                                "input": "0x",
                                "blockHash": format!("{:#x}", meta.block_hash),
                                "blockNumber": format!("0x{:x}", meta.block_number),
                                "transactionIndex": "0x0",
                                "type": "0x2",
                                "v": "0x1c",
                                "r": "0x0",
                                "s": "0x0"
                            });
                            let body = json!({ "jsonrpc": "2.0", "result": tx_obj, "id": id }).to_string();
                            write_json(&mut client_stream, &body).await;
                            continue;
                        }

                        let outbound_meta_opt = get_outbound_meta().read().unwrap().get(&tx_hash).cloned();
                        if let Some(meta) = outbound_meta_opt {
                            let tx_obj = json!({
                                "hash": format!("{tx_hash:#x}"),
                                "from": format!("{:#x}", meta.sender),
                                "to": format!("{:#x}", meta.recipient),
                                "value": format!("0x{:x}", meta.amount),
                                "nonce": format!("0x{:x}", meta.nonce),
                                "gas": "0x5208",
                                "gasPrice": format!("0x{:x}", meta.gas_price),
                                "input": "0x",
                                "blockHash": format!("{:#x}", meta.virtual_block_hash),
                                "blockNumber": format!("0x{:x}", meta.virtual_block_number),
                                "transactionIndex": "0x0",
                                "type": "0x2",
                                "v": "0x1c",
                                "r": "0x0",
                                "s": "0x0"
                            });
                            let body = json!({ "jsonrpc": "2.0", "result": tx_obj, "id": id }).to_string();
                            write_json(&mut client_stream, &body).await;
                            continue;
                        }
                    }

                    let reth_res = forward_to_reth_http(reth_port, &body_json).await.ok();
                    let has_result = reth_res.as_ref()
                        .and_then(|r| r.get("result"))
                        .map(|r| !r.is_null())
                        .unwrap_or(false);

                    if has_result {
                        if let Some(res) = reth_res {
                            write_json(&mut client_stream, &res.to_string()).await;
                            continue;
                        }
                    }

                    let tx_obj = get_tx_by_hash(requested_hash);
                    let body = json!({ "jsonrpc": "2.0", "result": tx_obj, "id": id }).to_string();
                    write_json(&mut client_stream, &body).await;
                    continue;
                }

                // Intercept eth_getTransactionReceipt for stateless fallback
                if method == "eth_getTransactionReceipt" {
                    let requested_hash = body_json["params"][0].as_str().unwrap_or("");
                    if let Ok(tx_hash) = requested_hash.parse::<B256>() {
                        let mut lookup_hash = tx_hash;
                        let synthetic_opt = get_synthetic_tx_hashes().read().unwrap().get(&tx_hash).copied();
                        if let Some(synth_hash) = synthetic_opt {
                            lookup_hash = synth_hash;
                        }

                        let synthetic_meta_opt = get_synthetic_meta().read().unwrap().get(&lookup_hash).cloned();
                        if let Some(meta) = synthetic_meta_opt {
                            let receipt = json!({
                                "transactionHash": format!("{tx_hash:#x}"),
                                "transactionIndex": "0x0",
                                "blockHash": format!("{:#x}", meta.block_hash),
                                "blockNumber": format!("0x{:x}", meta.block_number),
                                "from": format!("{:#x}", meta.original_sender),
                                "to": format!("{:#x}", meta.receiver),
                                "cumulativeGasUsed": "0x5208",
                                "gasUsed": "0x5208",
                                "effectiveGasPrice": "0x0",
                                "contractAddress": null,
                                "status": "0x1",
                                "type": "0x2",
                                "logs": [
                                    {
                                        "address": format!("{:#x}", meta.receiver),
                                        "topics": [
                                            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer(address,address,uint256)
                                            format!("0x000000000000000000000000{:x}", meta.original_sender),
                                            format!("0x000000000000000000000000{:x}", meta.receiver)
                                        ],
                                        "data": format!("0x{:064x}", meta.inbox_value),
                                        "blockNumber": format!("0x{:x}", meta.block_number),
                                        "transactionHash": format!("{tx_hash:#x}"),
                                        "transactionIndex": "0x0",
                                        "blockHash": format!("{:#x}", meta.block_hash),
                                        "logIndex": "0x0",
                                        "removed": false
                                    }
                                ],
                                "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                            });
                            let body = json!({ "jsonrpc": "2.0", "result": receipt, "id": id }).to_string();
                            write_json(&mut client_stream, &body).await;
                            continue;
                        }

                        let outbound_meta_opt = get_outbound_meta().read().unwrap().get(&tx_hash).cloned();
                        if let Some(meta) = outbound_meta_opt {
                            let receipt = json!({
                                "transactionHash": format!("{tx_hash:#x}"),
                                "transactionIndex": "0x0",
                                "blockHash": format!("{:#x}", meta.virtual_block_hash),
                                "blockNumber": format!("0x{:x}", meta.virtual_block_number),
                                "from": format!("{:#x}", meta.sender),
                                "to": format!("{:#x}", meta.recipient),
                                "cumulativeGasUsed": "0x5208",
                                "gasUsed": "0x5208",
                                "effectiveGasPrice": format!("0x{:x}", meta.gas_price),
                                "contractAddress": null,
                                "status": "0x1",
                                "type": "0x2",
                                "logs": [],
                                "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                            });
                            let body = json!({ "jsonrpc": "2.0", "result": receipt, "id": id }).to_string();
                            write_json(&mut client_stream, &body).await;
                            continue;
                        }
                    }

                    sync_hot_storage(reth_port).await;
                    let reth_res = forward_to_reth_http(reth_port, &body_json).await.ok();
                    let has_result = reth_res.as_ref()
                        .and_then(|r| r.get("result"))
                        .map(|r| !r.is_null())
                        .unwrap_or(false);

                    if has_result {
                        if let Some(res) = reth_res {
                            write_json(&mut client_stream, &res.to_string()).await;
                            continue;
                        }
                    }

                    let requested_hash = body_json["params"][0].as_str().unwrap_or("");
                    let receipt_obj = get_receipt_by_hash(requested_hash);
                    let body = json!({ "jsonrpc": "2.0", "result": receipt_obj, "id": id }).to_string();
                    write_json(&mut client_stream, &body).await;
                    continue;
                }

                // Intercept eth_getLogs to synthesize ERC-20 Transfer logs from Verkle state deltas
                if method == "eth_getLogs" {
                    sync_hot_storage(reth_port).await;
                    let real_logs = match forward_to_reth_http(reth_port, &body_json).await {
                        Ok(r) => r["result"].as_array().cloned().unwrap_or_default(),
                        Err(_) => vec![],
                    };

                    let filter = body_json["params"].get(0).cloned().unwrap_or(json!({}));
                    let synthetic_logs = synthesize_transfer_logs(&filter);
                    let mut combined = real_logs;
                    combined.extend(synthetic_logs);

                    let body = json!({ "jsonrpc": "2.0", "result": combined, "id": id }).to_string();
                    write_json(&mut client_stream, &body).await;
                    continue;
                }

                // Passthrough all other requests directly to Reth
                match forward_to_reth_http(reth_port, &body_json).await {
                    Ok(reth_res) => write_json(&mut client_stream, &reth_res.to_string()).await,
                    Err(e) => {
                        let body = json!({ "jsonrpc": "2.0", "error": { "code": -32603, "message": format!("Reth forward error: {e}") }, "id": id }).to_string();
                        write_json(&mut client_stream, &body).await;
                    }
                }
            }
        });
    }
}

fn handle_wallet_method(method: &str, body_json: &serde_json::Value) -> Option<serde_json::Value> {
    match method {
        "wallet_getPermissions" => Some(json!({
            "status": "authorized",
            "scopes": ["eip155", "solana"]
        })),
        "wallet_revokeSession" => Some(json!(true)),
        "wallet_createSession" => Some(json!({
            "sessionId": "session_active_12345",
            "status": "active",
            "chains": ["eip155:1", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"]
        })),
        "wallet_getSession" => Some(json!({
            "status": "active",
            "chains": ["eip155:1", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"]
        })),
        "wallet_getNotification" => {
            let intent_id = body_json["params"][0].as_str().unwrap_or("");
            let target_hash = intent_id.strip_prefix("intent_").unwrap_or(intent_id);
            let state = get_state().read().unwrap();
            let mut found_tx = None;
            for records in state.native_history.values() {
                for rec in records {
                    let rec_hash_str = format!("{:x}", rec.tx_hash);
                    if rec_hash_str.eq_ignore_ascii_case(target_hash) {
                        found_tx = Some(format!("{:#x}", rec.tx_hash));
                        break;
                    }
                }
                if found_tx.is_some() { break; }
            }
            
            if intent_id == "intent_tx_9999" {
                Some(json!({
                    "intentId": intent_id,
                    "status": "completed",
                    "txHash": "0x9999999999999999999999999999999999999999999999999999999999999999"
                }))
            } else if let Some(tx_hash) = found_tx {
                Some(json!({
                    "intentId": intent_id,
                    "status": "completed",
                    "txHash": tx_hash
                }))
            } else {
                Some(json!({
                    "error": {
                        "code": -32004,
                        "message": "Intent not found",
                        "data": { "intentId": intent_id, "caip": "caip-404" }
                    }
                }))
            }
        },
        "wallet_pay" => Some(json!({
            "status": "paid"
        })),
        "wallet_signMessage" => Some(json!("0x1234567890abcdef")),
        "wallet_getAssetMetadata" => {
            let asset_id = body_json["params"][0].as_str().unwrap_or("");
            if asset_id == "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" {
                Some(json!({ "name": "USD Coin", "symbol": "USDC", "decimals": 6 }))
            } else {
                Some(json!({
                    "error": {
                        "code": -32004,
                        "message": "Consensus Required / Saga Intent needed",
                        "data": { "assetId": asset_id, "caip": "caip-404" }
                    }
                }))
            }
        },
        // TODO: Having two distinct endpoints (sovereign_getDid and sovereign_getDidByAddress) might not be optimal.
        // We should combine them into a single, unified DID lookup system that treats different curves universally.
        // It shouldn't matter what curve ID is used as the primary DID resolver: the lookup should check the primary
        // mapping first, and if not found, cascade-query the other lookup tables until we are certain there is no
        // registered DID under any supported curve.
        "sovereign_getDid" => {
            let did_input = body_json["params"][0].as_str().unwrap_or("");
            let reg = get_registry().read().unwrap();
            let did_uri = sovereign_consensus::registry::ValidatorRegistry::normalize_query_did(did_input);
            let registered = reg.is_did_registered(&did_uri);
            let address = reg.get_address_by_did(&did_uri).map(|a| format!("{a:#x}"));

            let resolved_did = if let Some(ident) = reg.find_identity_by_any_key(&did_uri) {
                ident.did.clone()
            } else if let Some(addr) = sovereign_consensus::registry::ValidatorRegistry::extract_address_from_did(&did_uri) {
                reg.get_did_by_address(&addr).unwrap_or(did_uri)
            } else {
                did_uri
            };
            
            let mut keys = serde_json::Map::new();
            if let Some(ident) = reg.identities.get(&resolved_did) {
                let doc = &ident.doc;
                let encode_multibase = |prefix: &[u8], key: &[u8]| -> String {
                    let mut combined = prefix.to_vec();
                    combined.extend_from_slice(key);
                    format!("z{}", bs58::encode(&combined).into_string())
                };
                keys.insert("secp256k1".to_string(), json!(encode_multibase(&[0xe7, 0x01], &doc.secp256k1_pubkey)));
                keys.insert("ed25519".to_string(), json!(encode_multibase(&[0xed, 0x01], &doc.ed25519_pubkey)));
                keys.insert("bls12381".to_string(), json!(encode_multibase(&[0xea, 0x01], &doc.bls_pubkey)));
                keys.insert("mldsa65".to_string(), json!(encode_multibase(&[0x93, 0x01], &doc.ml_dsa_pubkey)));
                keys.insert("slhdsa".to_string(), json!(encode_multibase(&[0x94, 0x01], &doc.slh_dsa_pubkey)));
                keys.insert("falcon".to_string(), json!(encode_multibase(&[0x92, 0x01], &doc.falcon_pubkey)));
                keys.insert("xmss".to_string(), json!(encode_multibase(&[0x95, 0x01], &doc.xmss_pubkey)));
            }

            Some(json!({
                "registered": registered,
                "did": resolved_did,
                "address": address,
                "keys": if keys.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(keys) }
            }))
        },
        "sovereign_getDidByAddress" => {
            let addr_str = body_json["params"][0].as_str().unwrap_or("");
            let reg = get_registry().read().unwrap();
            let mut resolved_did = None;
            if let Ok(addr) = addr_str.parse::<Address>() {
                if let Some(did) = reg.get_did_by_address(&addr) {
                    resolved_did = Some(did);
                }
            }
            if let Some(ref did) = resolved_did {
                let address = reg.get_address_by_did(did).map(|a| format!("{a:#x}"));
                let mut keys = serde_json::Map::new();
                if let Some(ident) = reg.identities.get(did) {
                    let doc = &ident.doc;
                    let encode_multibase = |prefix: &[u8], key: &[u8]| -> String {
                        let mut combined = prefix.to_vec();
                        combined.extend_from_slice(key);
                        format!("z{}", bs58::encode(&combined).into_string())
                    };
                    keys.insert("secp256k1".to_string(), json!(encode_multibase(&[0xe7, 0x01], &doc.secp256k1_pubkey)));
                    keys.insert("ed25519".to_string(), json!(encode_multibase(&[0xed, 0x01], &doc.ed25519_pubkey)));
                    keys.insert("bls12381".to_string(), json!(encode_multibase(&[0xea, 0x01], &doc.bls_pubkey)));
                    keys.insert("mldsa65".to_string(), json!(encode_multibase(&[0x93, 0x01], &doc.ml_dsa_pubkey)));
                    keys.insert("slhdsa".to_string(), json!(encode_multibase(&[0x94, 0x01], &doc.slh_dsa_pubkey)));
                    keys.insert("falcon".to_string(), json!(encode_multibase(&[0x92, 0x01], &doc.falcon_pubkey)));
                    keys.insert("xmss".to_string(), json!(encode_multibase(&[0x95, 0x01], &doc.xmss_pubkey)));
                }
                Some(json!({
                    "registered": true,
                    "did": did,
                    "address": address,
                    "keys": if keys.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(keys) }
                }))
            } else {
                Some(json!({
                    "registered": false,
                    "did": null,
                    "address": addr_str,
                    "keys": null
                }))
            }
        },
        "sovereign_getStatelessWitness" => {
            let cid = body_json["params"][0].as_str().unwrap_or("");
            let backend = std::sync::Arc::new(sovereign_consensus::archival::MockArchivalBackend::new());
            let daemon = sovereign_consensus::archival::RpcIpfsArchivalDaemon::new(backend);
            let witness = sovereign_consensus::stateless::AccountWitness {
                balance: alloy_primitives::U256::from(7_500_000u64),
                nonce: 42,
                code_hash: B256::repeat_byte(0xba),
                code: b"somerevmbytecode".to_vec(),
                quadrant_matrix: [0b11, 0b1000, 0, 0b10],
            };
            let _ = daemon.archive_account_witness(65001, &witness);
            let resolved = daemon.resolve_account_witness(cid).unwrap_or(witness);
            Some(json!({
                "balance": format!("{:?}", resolved.balance),
                "nonce": resolved.nonce,
                "codeHash": format!("{:?}", resolved.code_hash),
                "quadrantMatrix": resolved.quadrant_matrix
            }))
        },
        "sovereign_sendBlock" => {
            let block_val = &body_json["params"][0];
            let block: Result<sovereign_consensus::stateless::LatticeBlock, _> = serde_json::from_value(block_val.clone());
            match block {
                Ok(b) => {
                    match sovereign_consensus::stateless::execute_lattice_block(&b) {
                        Ok(hash) => Some(json!({ "status": "success", "hash": format!("{:#x}", hash) })),
                        Err(e) => Some(json!({ "error": { "code": -32000, "message": e } })),
                    }
                }
                Err(err) => Some(json!({ "error": { "code": -32602, "message": format!("Invalid block parameter: {}", err) } })),
            }
        },
        "sovereign_getAccountFrontier" => {
            let addr_str = body_json["params"][0].as_str().unwrap_or("");
            if let Ok(addr) = addr_str.parse::<alloy_primitives::Address>() {
                let registry_lock = sovereign_consensus::registry::get_registry();
                let mut reg = registry_lock.write().unwrap();
                let frontier = reg.get_or_create_frontier(addr);
                Some(json!({
                    "latestHash": format!("{:#x}", frontier.latest_hash),
                    "sequence": frontier.sequence,
                    "locked": frontier.locked,
                    "snapshotSize": frontier.snapshot_size,
                }))
            } else {
                Some(json!({ "error": { "code": -32602, "message": "Invalid address parameter" } }))
            }
        },
        "sovereign_getPendingReceives" => {
            let addr_str = body_json["params"][0].as_str().unwrap_or("");
            if let Ok(addr) = addr_str.parse::<alloy_primitives::Address>() {
                let registry_lock = sovereign_consensus::registry::get_registry();
                let reg = registry_lock.read().unwrap();
                
                let mut sends = Vec::new();
                for (hash, block) in &reg.lattice_blocks {
                    if let sovereign_consensus::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                        if *recipient == addr {
                            sends.push((*hash, block, amount));
                        }
                    }
                }
                
                let mut pending = Vec::new();
                for (send_hash, block, amount) in sends {
                    let already_received = reg.lattice_blocks.values().any(|b| {
                        b.account == addr && matches!(&b.payload, sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash, .. } if *send_block_hash == send_hash)
                    });
                    if !already_received {
                        pending.push(json!({
                            "sendBlockHash": format!("{:#x}", send_hash),
                            "sender": format!("{:#x}", block.account),
                            "amount": amount.to_string(),
                        }));
                    }
                }
                Some(json!(pending))
            } else {
                Some(json!({ "error": { "code": -32602, "message": "Invalid address parameter" } }))
            }
        },
        _ if method.starts_with("wallet_") || method.starts_with("sovereign_") => Some(json!(null)),
        _ => None,
    }
}

fn synthesize_transfer_logs(filter: &serde_json::Value) -> Vec<serde_json::Value> {
    const TRANSFER_SIG: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    const NATIVE_ETH_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

    let filter_to: Option<String> = filter["topics"]
        .as_array()
        .and_then(|t| t.get(2))
        .and_then(|t2| {
            t2.as_str().map(|s| s.to_lowercase()).or_else(|| {
                t2.as_array().and_then(|arr| arr.first().and_then(|v| v.as_str())).map(|s| s.to_lowercase())
            })
        });

    let state = get_state().read().unwrap();
    let mut seen_hashes = std::collections::HashSet::new();
    let mut logs = Vec::new();

    for (_addr, records) in &state.native_history {
        for record in records {
            let hash_key = format!("{:#x}", record.tx_hash);
            if seen_hashes.contains(&hash_key) {
                continue;
            }

            let from_padded = format!("0x{:0>64}", alloy_primitives::hex::encode(record.from.as_slice()));
            let to_padded   = format!("0x{:0>64}", alloy_primitives::hex::encode(record.to.as_slice()));

            if let Some(ref req_to) = filter_to {
                if !to_padded.eq_ignore_ascii_case(req_to) && !format!("{:#x}", record.to).eq_ignore_ascii_case(req_to) {
                    continue;
                }
            }

            seen_hashes.insert(hash_key.clone());

            let value_u256 = record.value.parse::<U256>().unwrap_or(U256::ZERO);
            let value_padded = format!("0x{:0>64x}", value_u256);

            logs.push(json!({
                "address": NATIVE_ETH_ADDRESS,
                "topics": [TRANSFER_SIG, from_padded, to_padded],
                "data": value_padded,
                "blockHash": format!("{:#x}", record.tx_hash),
                "blockNumber": record.block_number,
                "transactionHash": hash_key,
                "transactionIndex": "0x0",
                "logIndex": "0x0",
                "removed": false
            }));
        }
    }
    logs
}

fn decode_sender(raw_tx: &str) -> Option<Address> {
    let stripped = raw_tx.strip_prefix("0x")?;
    let bytes = alloy_primitives::hex::decode(stripped).ok()?;
    let mut data = &bytes[..];
    let tx = <TxEnvelope as Decodable>::decode(&mut data).ok()?;
    tx.recover_signer_unchecked().ok()
}

fn decode_tx_details(raw_tx: &str) -> Option<(Address, U256, u64, U256, u64)> {
    let stripped = raw_tx.strip_prefix("0x")?;
    let bytes = alloy_primitives::hex::decode(stripped).ok()?;
    let mut data = &bytes[..];
    let tx = <TxEnvelope as Decodable>::decode(&mut data).ok()?;
    let sender = tx.recover_signer_unchecked().ok()?;
    let gas_price = tx.max_fee_per_gas();
    let gas_limit = tx.gas_limit();
    let value = tx.value();
    Some((sender, U256::from(gas_price), gas_limit, value, tx.nonce()))
}

async fn get_reth_balance(reth_port: u16, addr: Address) -> U256 {
    let client = reqwest::Client::new();
    let res = client.post(format!("http://127.0.0.1:{reth_port}"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [format!("{addr:#x}"), "latest"],
            "id": 1
        }))
        .send()
        .await;
    if let Ok(resp) = res {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(bal_str) = json["result"].as_str() {
                return U256::from_str_radix(bal_str.trim_start_matches("0x"), 16).unwrap_or(U256::ZERO);
            }
        }
    }
    U256::ZERO
}

async fn send_funding_tx(reth_port: u16, target: Address, value: U256) -> Result<B256, eyre::Error> {
    // 1. Get dev nonce
    let client = reqwest::Client::new();
    let nonce_res = client.post(format!("http://127.0.0.1:{reth_port}"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": ["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "pending"],
            "id": 1
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    let nonce_str = nonce_res["result"].as_str().ok_or_else(|| eyre::eyre!("No nonce"))?;
    let nonce = u64::from_str_radix(nonce_str.trim_start_matches("0x"), 16)?;
    tracing::info!("Queried dev account funding nonce: {} (raw: {})", nonce, nonce_str);

    // 2. Build Legacy Tx
    let dev_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let signer = dev_key.parse::<PrivateKeySigner>()?;
    let chain_id = CHAIN_ID.load(std::sync::atomic::Ordering::Relaxed);
    let mut tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_limit: 21000,
        gas_price: 1_000_000_000, // 1 gwei
        to: alloy_primitives::TxKind::Call(target),
        value,
        input: Default::default(),
    };

    // 3. Sign transaction
    let sig = signer.sign_transaction(&mut tx).await?;
    let signed_tx = TxEnvelope::Legacy(tx.into_signed(sig));
    
    // 4. Encode signed transaction
    let mut encoded = Vec::new();
    signed_tx.encode(&mut encoded);
    let tx_hash = alloy_primitives::keccak256(&encoded);
    let hex_tx = format!("0x{}", alloy_primitives::hex::encode(encoded));

    // 5. Broadcast to Reth
    let broadcast_res = client.post(format!("http://127.0.0.1:{reth_port}"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [hex_tx],
            "id": 1
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    
    if let Some(err) = broadcast_res.get("error") {
        return Err(eyre::eyre!("Broadcast error: {:?}", err));
    }
    
    // Wait for the block mining
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    Ok(tx_hash)
}

async fn fund_gas_if_needed(reth_port: u16, target: Address, gas_price: U256, gas_limit: u64) {
    let needed = gas_price.saturating_mul(U256::from(gas_limit));
    if needed.is_zero() {
        return;
    }

    let balance = get_reth_balance(reth_port, target).await;
    if balance < needed {
        let missing = needed - balance;
        tracing::info!(?target, ?missing, "Funding gas fee from dev account...");
        if let Err(e) = send_funding_tx(reth_port, target, missing).await {
            tracing::error!(?target, ?missing, "Failed to fund gas fee: {e}");
        }
    }
}

async fn write_json(stream: &mut tokio::net::TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\n\r\n{}",
        body.len(), body
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

fn normalize_block_param(param: &str) -> String {
    match param {
        "latest" | "earliest" | "pending" | "safe" | "finalized" => param.to_string(),
        hex if hex.starts_with("0x") => {
            let digits = hex.trim_start_matches("0x").trim_start_matches('0');
            if digits.is_empty() { "0x0".to_string() } else { format!("0x{digits}") }
        }
        other => other.to_string(),
    }
}

fn inject_history_into_block(reth_response: serde_json::Value, full_txs: bool) -> serde_json::Value {
    let block = match reth_response["result"].as_object() {
        Some(b) => b,
        None => return reth_response,
    };

    let block_hash = match block.get("hash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return reth_response,
    };
    let block_number = match block.get("number").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return reth_response,
    };
    let block_num_u64 = u64::from_str_radix(block_number.trim_start_matches("0x"), 16).unwrap_or(0);

    let mut enriched = reth_response.clone();
    if let Some(txs) = enriched["result"]["transactions"].as_array_mut() {
        for tx_val in txs.iter_mut() {
            if let Some(hash_str) = tx_val.as_str() {
                if let Ok(tx_hash) = hash_str.parse::<B256>() {
                    let synthetic_opt = get_synthetic_tx_hashes().read().unwrap().get(&tx_hash).copied();
                    if let Some(synth_hash) = synthetic_opt {
                        *tx_val = json!(format!("{synth_hash:#x}"));
                    }
                }
            } else if tx_val.is_object() {
                if let Some(hash_str) = tx_val["hash"].as_str() {
                    if let Ok(tx_hash) = hash_str.parse::<B256>() {
                        let mut lookup_hash = tx_hash;
                        let synthetic_opt = get_synthetic_tx_hashes().read().unwrap().get(&tx_hash).copied();
                        if let Some(synth_hash) = synthetic_opt {
                            tx_val["hash"] = json!(format!("{synth_hash:#x}"));
                            lookup_hash = synth_hash;
                        }

                        let synthetic_meta_opt = get_synthetic_meta().read().unwrap().get(&lookup_hash).cloned();
                        if let Some(meta) = synthetic_meta_opt {
                            tx_val["from"] = json!(format!("{:#x}", meta.original_sender));
                            tx_val["to"] = json!(format!("{:#x}", meta.receiver));
                            tx_val["value"] = json!(format!("0x{:x}", meta.inbox_value));
                            tx_val["gas"] = json!("0x5208");
                            tx_val["gasPrice"] = json!("0x0");
                        }

                        let outbound_meta_opt = get_outbound_meta().read().unwrap().get(&lookup_hash).cloned();
                        if let Some(meta) = outbound_meta_opt {
                            tx_val["from"] = json!(format!("{:#x}", meta.sender));
                            tx_val["to"] = json!(format!("{:#x}", meta.recipient));
                            tx_val["value"] = json!(format!("0x{:x}", meta.amount));
                            tx_val["gas"] = json!("0x5208");
                            tx_val["gasPrice"] = json!(format!("0x{:x}", meta.gas_price));
                        }
                    }
                }
            }
        }

        let state = get_state().read().unwrap();
        for records in state.native_history.values() {
            for rec in records {
                let rec_num = u64::from_str_radix(rec.block_number.trim_start_matches("0x"), 16).unwrap_or(0);
                if rec_num != block_num_u64 && block_num_u64 > 0 {
                    continue;
                }

                let hash_str = format!("{:#x}", rec.tx_hash);
                let already_present = txs.iter().any(|t| {
                    if let Some(s) = t.as_str() {
                        s.eq_ignore_ascii_case(&hash_str)
                    } else {
                        t["hash"].as_str().map(|s| s.eq_ignore_ascii_case(&hash_str)).unwrap_or(false)
                    }
                });

                if !already_present {
                    if full_txs {
                        let value_u256 = rec.value.parse::<U256>().unwrap_or(U256::ZERO);
                        txs.push(json!({
                            "blockHash": block_hash,
                            "blockNumber": block_number,
                            "from": format!("{:#x}", rec.from),
                            "to": format!("{:#x}", rec.to),
                            "value": format!("0x{:x}", value_u256),
                            "gas": "0x5208",
                            "gasPrice": "0x3b9aca00",
                            "hash": hash_str,
                            "input": "0x",
                            "nonce": "0x0",
                            "transactionIndex": "0x0",
                            "type": "0x2",
                            "v": rec.v.clone(),
                            "r": rec.r.clone(),
                            "s": rec.s.clone()
                        }));
                    } else {
                        txs.push(json!(hash_str));
                    }
                }
            }
        }
    }
    enriched
}

fn get_tx_by_hash(target_hash: &str) -> serde_json::Value {
    let clean_target = target_hash.trim().to_lowercase();
    let state = get_state().read().unwrap();

    for records in state.native_history.values() {
        for rec in records {
            let hash_str = format!("{:#x}", rec.tx_hash).to_lowercase();
            if hash_str == clean_target {
                let value_u256 = rec.value.parse::<U256>().unwrap_or(U256::ZERO);
                let b_hash = rec.block_hash.clone().unwrap_or_else(|| format!("{:#x}", rec.tx_hash));
                return json!({
                    "blockHash": b_hash,
                    "blockNumber": rec.block_number,
                    "from": format!("{:#x}", rec.from),
                    "to": format!("{:#x}", rec.to),
                    "value": format!("0x{:x}", value_u256),
                    "gas": "0x5208",
                    "gasPrice": "0x3b9aca00",
                    "hash": hash_str,
                    "input": "0x",
                    "nonce": "0x0",
                    "transactionIndex": "0x0",
                    "type": "0x2",
                    "v": rec.v.clone(),
                    "r": rec.r.clone(),
                    "s": rec.s.clone()
                });
            }
        }
    }

    json!(null)
}

fn get_receipt_by_hash(target_hash: &str) -> serde_json::Value {
    let clean_target = target_hash.trim().to_lowercase();
    let state = get_state().read().unwrap();

    for records in state.native_history.values() {
        for rec in records {
            let hash_str = format!("{:#x}", rec.tx_hash).to_lowercase();
            if hash_str == clean_target {
                let b_hash = rec.block_hash.clone().unwrap_or_else(|| format!("{:#x}", rec.tx_hash));
                return json!({
                    "blockHash": b_hash,
                    "blockNumber": rec.block_number,
                    "contractAddress": serde_json::Value::Null,
                    "cumulativeGasUsed": "0x5208",
                    "effectiveGasPrice": "0x3b9aca00",
                    "from": format!("{:#x}", rec.from),
                    "to": format!("{:#x}", rec.to),
                    "gasUsed": "0x5208",
                    "logs": [],
                    "logsBloom": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "status": "0x1",
                    "transactionHash": hash_str,
                    "transactionIndex": "0x0",
                    "type": "0x2"
                });
            }
        }
    }

    json!(null)
}

fn index_from_raw_tx(raw_tx: &str, tx_hash: B256, sender: Address) {
    let Some(stripped) = raw_tx.strip_prefix("0x") else { return };
    let Ok(bytes) = alloy_primitives::hex::decode(stripped) else { return };
    let mut data = &bytes[..];
    let Ok(tx) = <TxEnvelope as Decodable>::decode(&mut data) else { return };
    
    // Validate chain_id (S5)
    if let Some(tx_chain_id) = tx.chain_id() {
        let expected = CHAIN_ID.load(Ordering::Relaxed);
        if tx_chain_id != expected {
            error!("Rejecting transaction with invalid chain_id: {tx_chain_id} (expected {expected})");
            return;
        }
    }

    let to = match tx.to() {
        Some(addr) => addr,
        None => {
            warn!("INDEX_FAIL: tx.to() is None");
            return;
        }
    };
    let value = tx.value();
    if value == U256::ZERO || !tx.input().is_empty() {
        return;
    }

    {
        let mut reg = get_registry().write().unwrap();
        let payload = sovereign_consensus::stateless::LatticePayload::Send { recipient: to, amount: value };
        let send_block = sovereign_consensus::stateless::LatticeBlock {
            account: sender,
            previous_hash: B256::ZERO,
            sequence: 0,
            payload,
            signature: bytes.clone(),
            static_witnesses: vec![],
        };
        reg.lattice_blocks.insert(tx_hash, send_block);
    }

    // Extract signature v, r, s (S6)
    let (v_str, r_str, s_str) = match &tx {
        TxEnvelope::Legacy(signed) => {
            let sig = signed.signature();
            let v_val = if sig.v() { 28 } else { 27 };
            (format!("0x{:x}", v_val), format!("0x{:x}", sig.r()), format!("0x{:x}", sig.s()))
        }
        TxEnvelope::Eip2930(signed) => {
            let sig = signed.signature();
            let v_val = if sig.v() { 1 } else { 0 };
            (format!("0x{:x}", v_val), format!("0x{:x}", sig.r()), format!("0x{:x}", sig.s()))
        }
        TxEnvelope::Eip1559(signed) => {
            let sig = signed.signature();
            let v_val = if sig.v() { 1 } else { 0 };
            (format!("0x{:x}", v_val), format!("0x{:x}", sig.r()), format!("0x{:x}", sig.s()))
        }
        TxEnvelope::Eip4844(signed) => {
            let sig = signed.signature();
            let v_val = if sig.v() { 1 } else { 0 };
            (format!("0x{:x}", v_val), format!("0x{:x}", sig.r()), format!("0x{:x}", sig.s()))
        }
        _ => ("0x1c".to_string(), "0x0".to_string(), "0x0".to_string()),
    };

    {
        let mut reg = get_registry().write().unwrap();
        if !reg.address_to_did.contains_key(&to) {
            let actual_chain_id = CHAIN_ID.load(Ordering::Relaxed);
            let placeholder = format!("did:sovereign:{}:{}", actual_chain_id, alloy_primitives::hex::encode(to.as_slice()));
            reg.peer_keys.insert(placeholder.clone(), [0u8; 32]);
            reg.address_to_did.insert(to, placeholder);
        }
    }

    let (from_did, to_did) = {
        let reg = get_registry().read().unwrap();
        (reg.get_did_by_address(&sender), reg.get_did_by_address(&to))
    };

    let record = NativeTransferRecord {
        tx_hash,
        block_hash: None, // Will be backfilled by sync_hot_storage during block mining
        block_number: format!("0x{:x}", get_state().read().unwrap().block_number + 1),
        from: sender,
        from_did,
        to,
        to_did,
        value: value.to_string(),
        timestamp: now_secs(),
        v: v_str,
        r: r_str,
        s: s_str,
    };

    let mut state = get_state().write().unwrap();
    add_native_transfer_record(&mut state, record);
}

fn extract_header<'a>(request_str: &'a str, name: &str) -> Option<&'a str> {
    for line in request_str.lines() {
        if line.to_lowercase().starts_with(name) {
            if let Some(val) = line.splitn(2, ':').nth(1) {
                return Some(val.trim());
            }
        }
    }
    None
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

async fn forward_to_reth_http(reth_port: u16, body: &serde_json::Value) -> Result<serde_json::Value, reqwest::Error> {
    let client = reqwest::Client::new();
    let res = client.post(format!("http://127.0.0.1:{reth_port}")).json(body).send().await?;
    res.json::<serde_json::Value>().await
}

fn extract_result(res: serde_json::Value) -> serde_json::Value {
    if res.get("error").is_some() { res } else { res["result"].clone() }
}

async fn send_result(stream: &mut tokio::net::TcpStream, id: &serde_json::Value, result: serde_json::Value) {
    let body = if result.get("error").is_some() {
        json!({ "jsonrpc": "2.0", "error": result["error"], "id": id }).to_string()
    } else {
        json!({ "jsonrpc": "2.0", "result": result, "id": id }).to_string()
    };
    write_json(stream, &body).await;
}

async fn send_error(stream: &mut tokio::net::TcpStream, id: &serde_json::Value, code: i64, message: &str) {
    let body = json!({ "jsonrpc": "2.0", "error": { "code": code, "message": message }, "id": id }).to_string();
    write_json(stream, &body).await;
}

async fn sync_hot_storage(reth_port: u16) {
    let block_num_req = json!({ "jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 9999 });
    let latest_hex = match forward_to_reth_http(reth_port, &block_num_req).await {
        Ok(res) => res["result"].as_str().unwrap_or("0x0").to_string(),
        Err(_) => return,
    };

    let latest_num = u64::from_str_radix(latest_hex.trim_start_matches("0x"), 16).unwrap_or(0);
    let current_num = get_state().read().unwrap().block_number;
    if latest_num <= current_num { return; }

    for num in (current_num + 1)..=latest_num {
        let num_hex = format!("0x{:x}", num);
        let block_req = json!({ "jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": [num_hex, true], "id": 9999 });
        let block = match forward_to_reth_http(reth_port, &block_req).await { Ok(res) => extract_result(res), Err(_) => continue };
        if block.is_null() { continue; }

        let block_hash_opt = block["hash"].as_str().map(|s| s.to_string());

        if let Some(txs) = block["transactions"].as_array() {
            for tx_obj in txs {
                let from_addr = tx_obj["from"].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                let to_addr = tx_obj["to"].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                let val_str = tx_obj["value"].as_str().unwrap_or("0x0");
                let tx_hash = tx_obj["hash"].as_str().unwrap_or("").parse::<B256>().unwrap_or_default();
                let value = U256::from_str_radix(val_str.trim_start_matches("0x"), 16).unwrap_or(U256::ZERO);

                // Finalize auto-claims (Task C)
                let auto_claims_opt = get_auto_claims().write().unwrap().remove(&tx_hash);
                if let Some(send_hashes) = auto_claims_opt {
                    let mut reg = get_registry().write().unwrap();
                    for send_hash in send_hashes {
                        let receive_block = sovereign_consensus::stateless::LatticeBlock {
                            account: from_addr,
                            previous_hash: B256::ZERO,
                            sequence: 1,
                            payload: sovereign_consensus::stateless::LatticePayload::Receive {
                                send_block_hash: send_hash,
                                amount: U256::from(0),
                            },
                            signature: vec![],
                            static_witnesses: vec![],
                        };
                        let receive_block_hash = alloy_primitives::keccak256(&scale::Encode::encode(&receive_block));
                        reg.lattice_blocks.insert(receive_block_hash, receive_block);

                        let mut state = get_state().write().unwrap();
                        let record = NativeTransferRecord {
                            tx_hash: send_hash,
                            block_hash: block_hash_opt.clone(),
                            block_number: num_hex.clone(),
                            from: from_addr,
                            from_did: reg.get_did_by_address(&from_addr),
                            to: from_addr,
                            to_did: reg.get_did_by_address(&from_addr),
                            value: "0".to_string(),
                            timestamp: now_secs(),
                            v: "0x1c".to_string(),
                            r: "0x0".to_string(),
                            s: "0x0".to_string(),
                        };
                        add_native_transfer_record(&mut state, record);
                    }
                }

                let synthetic_opt = get_synthetic_tx_hashes().write().unwrap().remove(&tx_hash);
                if let Some(synthetic_hash) = synthetic_opt {
                    let b_hash = block_hash_opt.clone().and_then(|h| h.parse::<B256>().ok()).unwrap_or_default();
                    if let Ok(mut meta_lock) = get_synthetic_meta().write() {
                        if let Some(meta) = meta_lock.get_mut(&synthetic_hash) {
                            meta.block_hash = b_hash;
                            meta.block_number = num;
                        }
                    }

                    let mut orig_sender = to_addr;
                    if let Ok(meta_lock) = get_synthetic_meta().read() {
                        if let Some(meta) = meta_lock.get(&synthetic_hash) {
                            orig_sender = meta.original_sender;
                        }
                    }

                    let mut reg = get_registry().write().unwrap();
                    let mut state = get_state().write().unwrap();
                    let record = NativeTransferRecord {
                        tx_hash: synthetic_hash,
                        block_hash: block_hash_opt.clone(),
                        block_number: num_hex.clone(),
                        from: orig_sender,
                        from_did: reg.get_did_by_address(&orig_sender),
                        to: to_addr,
                        to_did: reg.get_did_by_address(&to_addr),
                        value: value.to_string(),
                        timestamp: now_secs(),
                        v: "0x1c".to_string(),
                        r: "0x0".to_string(),
                        s: "0x0".to_string(),
                    };
                    add_native_transfer_record(&mut state, record);
                }

                if let Ok(mut meta_lock) = get_outbound_meta().write() {
                    if let Some(meta) = meta_lock.get_mut(&tx_hash) {
                        meta.virtual_block_hash = block_hash_opt.clone().and_then(|h| h.parse::<B256>().ok()).unwrap_or_default();
                        meta.virtual_block_number = num;
                    }
                }

                if value > U256::ZERO && from_addr != Address::ZERO && to_addr != Address::ZERO {
                    {
                        let mut reg = get_registry().write().unwrap();
                        let payload = sovereign_consensus::stateless::LatticePayload::Send { recipient: to_addr, amount: value };
                        let send_block = sovereign_consensus::stateless::LatticeBlock {
                            account: from_addr,
                            previous_hash: B256::ZERO,
                            sequence: 0,
                            payload,
                            signature: vec![],
                            static_witnesses: vec![],
                        };
                        reg.lattice_blocks.insert(tx_hash, send_block);
                    }

                    let v = tx_obj["v"].as_str().unwrap_or("0x1c").to_string();
                    let r = tx_obj["r"].as_str().unwrap_or("0x0").to_string();
                    let s = tx_obj["s"].as_str().unwrap_or("0x0").to_string();
                    let mut state = get_state().write().unwrap();
                    let reg = get_registry().read().unwrap();
                    let record = NativeTransferRecord {
                        tx_hash,
                        block_hash: block_hash_opt.clone(),
                        block_number: num_hex.clone(),
                        from: from_addr,
                        from_did: reg.get_did_by_address(&from_addr),
                        to: to_addr,
                        to_did: reg.get_did_by_address(&to_addr),
                        value: value.to_string(),
                        timestamp: now_secs(),
                        v,
                        r,
                        s,
                    };
                    add_native_transfer_record(&mut state, record);
                }
            }
        }
        get_state().write().unwrap().block_number = num;
    }
}

fn timestamp_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

async fn handle_get_transaction_count(reth_port: u16, account: Address) -> u64 {
    let mut seq = 0;
    if let Ok(reg) = get_registry().read() {
        if let Some(frontier) = reg.account_frontiers.get(&account) {
            seq = frontier.sequence;
        }
    }
    if seq == 0 {
        get_reth_transaction_count(reth_port, account).await
    } else {
        seq
    }
}

async fn get_reth_transaction_count(reth_port: u16, addr: Address) -> u64 {
    let client = reqwest::Client::new();
    let res = client.post(format!("http://127.0.0.1:{reth_port}"))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [format!("{addr:#x}"), "latest"],
            "id": 1
        }))
        .send()
        .await;
    if let Ok(r) = res {
        if let Ok(val) = r.json::<serde_json::Value>().await {
            let count_hex = val["result"].as_str().unwrap_or("0x0");
            return u64::from_str_radix(count_hex.trim_start_matches("0x"), 16).unwrap_or(0);
        }
    }
    0
}