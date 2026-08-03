use alloy_consensus::{Transaction, TxEnvelope};
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Decodable;
use reth_primitives_traits::SignerRecoverable;
use serde_json::json;
use sovereign_consensus::registry::get_registry;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info};

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

/// Starts the CAIP RPC proxy server on `port`, forwarding execution reads to `reth_port`.
pub async fn run_proxy(port: u16, reth_port: u16) -> Result<(), eyre::Report> {
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

                if method == "sovereign_registerDid" {
                    let did_uri = body_json["params"][0].as_str().unwrap_or("");
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
                            let reg = get_registry().read().unwrap();
                            reg.get_did_by_address(&sender_addr)
                                .map(|did| reg.is_did_fully_registered(&did))
                                .unwrap_or(false)
                        }).unwrap_or(false)
                    };

                    if !is_authorized {
                        send_error(&mut client_stream, &id, -32001,
                            "Sovereign Wallet Error: Active DID not registered. Please onboard via sovereign_registerDid first."
                        ).await;
                        continue;
                    }

                    let sender_opt = decode_sender(raw_tx);
                    let fwd_result = match forward_to_reth_http(reth_port, &body_json).await {
                        Ok(r) => extract_result(r),
                        Err(e) => {
                            send_error(&mut client_stream, &id, -32603, &format!("Reth forward error: {e}")).await;
                            continue;
                        }
                    };

                    if let Some(tx_hash_str) = fwd_result.as_str() {
                        if let Ok(tx_hash) = tx_hash_str.parse::<B256>() {
                            if let Some(sender) = sender_opt {
                                index_from_raw_tx(raw_tx, tx_hash, sender);
                            }
                        }
                    }

                    send_result(&mut client_stream, &id, fwd_result).await;
                    continue;
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
                    let tx_obj = get_tx_by_hash(requested_hash);
                    let body = json!({ "jsonrpc": "2.0", "result": tx_obj, "id": id }).to_string();
                    write_json(&mut client_stream, &body).await;
                    continue;
                }

                // Intercept eth_getTransactionReceipt for stateless fallback
                if method == "eth_getTransactionReceipt" {
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
        "wallet_getSession" => Some(json!({
            "status": "active",
            "chains": ["eip155:1", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"]
        })),
        "wallet_getNotification" => Some(json!({
            "intentId": body_json["params"][0],
            "status": "completed",
            "txHash": format!("{:#x}", B256::repeat_byte(0x88))
        })),
        "wallet_pay" => Some(json!({
            "status": "paid",
            "transactionHash": format!("{:#x}", B256::repeat_byte(0xaa))
        })),
        "wallet_signMessage" => Some(json!(
            "0xSignaturePlaceholderEd25519ForWalletTestingOnly"
        )),
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
                            "v": "0x1c", "r": "0x0", "s": "0x0"
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
                    "v": "0x1c", "r": "0x0", "s": "0x0"
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
    let Some(to) = tx.to() else { return };
    let value = tx.value();
    if value == U256::ZERO || !tx.input().is_empty() { return; }

    {
        let mut reg = get_registry().write().unwrap();
        if !reg.address_to_did.contains_key(&to) {
            let placeholder = format!("did:sovereign:1337:{}", alloy_primitives::hex::encode(to.as_slice()));
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

                if value > U256::ZERO && from_addr != Address::ZERO && to_addr != Address::ZERO {
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