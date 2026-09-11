//! Upstream Reth forwarding, block synchronization, and gas funding routines.

use alloy_consensus::{SignableTransaction, TxEnvelope};
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Encodable;
use alloy_signer_local::PrivateKeySigner;
use alloy_network::TxSigner;
use serde_json::{json, Value};
use sovereign_consensus::registry::get_registry;
use std::sync::atomic::Ordering;
use tokio::io::AsyncWriteExt;

use super::evm_compat::normalize_block_param;
use super::memory_state::{
    add_native_transfer_record, get_auto_claims, get_outbound_meta, get_state, get_synthetic_meta,
    get_synthetic_tx_hashes, now_secs, NativeTransferRecord, CHAIN_ID,
};
use super::wallet::decode_sender;

pub async fn write_json(stream: &mut tokio::net::TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

pub async fn forward_to_reth_http(reth_port: u16, body: &Value) -> Result<Value, reqwest::Error> {
    let client = reqwest::Client::new();
    let res = client.post(format!("http://127.0.0.1:{reth_port}")).json(body).send().await?;
    let val = res.json::<Value>().await?;
    tracing::info!(%reth_port, response = ?val, "forward_to_reth_http raw response");
    Ok(val)
}

pub fn extract_result(res: Value) -> Value {
    if res.get("error").is_some() && !res["error"].is_null() {
        res
    } else {
        res["result"].clone()
    }
}

pub async fn send_result(stream: &mut tokio::net::TcpStream, id: &Value, result: Value) {
    let body = if result.is_object() && result.get("error").is_some() && !result["error"].is_null() {
        json!({ "jsonrpc": "2.0", "error": result["error"], "id": id }).to_string()
    } else {
        json!({ "jsonrpc": "2.0", "result": result, "id": id }).to_string()
    };
    write_json(stream, &body).await;
}

pub async fn send_error(stream: &mut tokio::net::TcpStream, id: &Value, code: i64, message: &str) {
    let body = json!({ "jsonrpc": "2.0", "error": { "code": code, "message": message }, "id": id }).to_string();
    write_json(stream, &body).await;
}

pub fn extract_header<'a>(request_str: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{}: ", name.to_lowercase());
    for line in request_str.lines() {
        if line.to_lowercase().starts_with(&prefix) {
            return Some(line[prefix.len()..].trim());
        }
    }
    None
}

pub async fn get_reth_balance(reth_port: u16, addr: Address) -> U256 {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://127.0.0.1:{reth_port}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [format!("{addr:#x}"), "latest"],
            "id": 1
        }))
        .send()
        .await;
    if let Ok(resp) = res {
        if let Ok(val) = resp.json::<Value>().await {
            if let Some(bal_str) = val["result"].as_str() {
                return U256::from_str_radix(bal_str.trim_start_matches("0x"), 16).unwrap_or(U256::ZERO);
            }
        }
    }
    U256::ZERO
}

pub async fn send_funding_tx(reth_port: u16, target: Address, value: U256) -> Result<B256, eyre::Error> {
    let funder_key = if let Ok(k) = std::env::var("SOVEREIGN_FUNDER_KEY") {
        k
    } else if cfg!(debug_assertions)
        || std::env::var("SOVEREIGN_MOCK_SGX").is_ok()
        || std::env::args().any(|arg| arg == "--dev" || arg == "--toy-mode")
    {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string()
    } else {
        return Err(eyre::eyre!("SOVEREIGN_FUNDER_KEY env var is required in production mode"));
    };
    let signer = funder_key.parse::<PrivateKeySigner>()?;
    let funder_addr = signer.address();

    if target == funder_addr {
        return Ok(B256::ZERO);
    }

    let client = reqwest::Client::new();
    let nonce_res = client
        .post(format!("http://127.0.0.1:{reth_port}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [format!("{funder_addr:#x}"), "pending"],
            "id": 1
        }))
        .send()
        .await?
        .json::<Value>()
        .await?;
    let nonce_str = nonce_res["result"].as_str().ok_or_else(|| eyre::eyre!("No nonce"))?;
    let nonce = u64::from_str_radix(nonce_str.trim_start_matches("0x"), 16)?;

    let chain_id = CHAIN_ID.load(Ordering::Relaxed);
    let mut tx = alloy_consensus::TxEip1559 {
        chain_id,
        nonce,
        gas_limit: 21000,
        max_fee_per_gas: 20_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: alloy_primitives::TxKind::Call(target),
        value,
        input: Default::default(),
        access_list: Default::default(),
    };

    let sig = signer.sign_transaction(&mut tx).await?;
    let signed_tx = TxEnvelope::Eip1559(tx.into_signed(sig));

    let mut encoded = Vec::new();
    signed_tx.encode(&mut encoded);
    let tx_hash = alloy_primitives::keccak256(&encoded);
    let hex_tx = format!("0x{}", alloy_primitives::hex::encode(encoded));

    let broadcast_res = client
        .post(format!("http://127.0.0.1:{reth_port}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [hex_tx],
            "id": 1
        }))
        .send()
        .await?
        .json::<Value>()
        .await?;

    if let Some(err) = broadcast_res.get("error") {
        return Err(eyre::eyre!("Broadcast error: {:?}", err));
    }
    let poll_start = std::time::Instant::now();
    let mut mined = false;
    while poll_start.elapsed() < std::time::Duration::from_secs(5) {
        let receipt_res = client
            .post(format!("http://127.0.0.1:{reth_port}"))
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")],
                "id": 1
            }))
            .send()
            .await;
        if let Ok(resp) = receipt_res {
            if let Ok(val) = resp.json::<Value>().await {
                if !val["result"].is_null() {
                    mined = true;
                    break;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    if !mined {
        tracing::warn!(%tx_hash, "Funding transaction was not mined within 5s");
    }

    Ok(tx_hash)
}

pub async fn fund_gas_if_needed(_reth_port: u16, _target: Address, _gas_price: U256, _gas_limit: u64) {
    // Strict invariant: Zero artificial token creation. Balances strictly come from genesis allocation, gas rewards, or epoch merit.
}

pub async fn get_reth_transaction_count(reth_port: u16, addr: Address) -> u64 {
    let client = reqwest::Client::new();
    let mut max_count = 0;
    for block_tag in &["pending", "latest"] {
        let res = client
            .post(format!("http://127.0.0.1:{reth_port}"))
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionCount",
                "params": [format!("{addr:#x}"), block_tag],
                "id": 1
            }))
            .send()
            .await;
        if let Ok(r) = res {
            if let Ok(val) = r.json::<Value>().await {
                let count_hex = val["result"].as_str().unwrap_or("0x0");
                let c = u64::from_str_radix(count_hex.trim_start_matches("0x"), 16).unwrap_or(0);
                max_count = max_count.max(c);
            }
        }
    }
    let state = get_state().read().unwrap();
    if let Some(records) = state.native_history.get(&addr) {
        let sent_count = records.iter().filter(|r| r.from == addr).count() as u64;
        max_count = max_count.max(sent_count);
    }
    max_count
}

pub async fn handle_get_transaction_count(reth_port: u16, account: Address) -> u64 {
    let reth_count = get_reth_transaction_count(reth_port, account).await;
    let mut seq = 0;
    if let Ok(reg) = get_registry().read() {
        if let Some(frontier) = reg.account_frontiers.get(&account) {
            seq = frontier.sequence;
        }
    }
    reth_count.max(seq)
}

static LAST_SYNCED_BLOCK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SYNC_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn sync_hot_storage(reth_port: u16) {
    let _guard = match SYNC_MUTEX.try_lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    let block_num_req = json!({ "jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 9999 });
    let latest_hex = match forward_to_reth_http(reth_port, &block_num_req).await {
        Ok(res) => {
            let val = extract_result(res);
            val.as_str().unwrap_or("0x0").to_string()
        }
        Err(e) => {
            tracing::error!("sync_hot_storage: eth_blockNumber error: {:?}", e);
            return;
        }
    };

    let latest_num = u64::from_str_radix(latest_hex.trim_start_matches("0x"), 16).unwrap_or(0);
    let last_synced = LAST_SYNCED_BLOCK.load(std::sync::atomic::Ordering::Relaxed);
    let start_num = if last_synced > 0 { last_synced + 1 } else { 0 };
    if start_num > latest_num && last_synced > 0 {
        return;
    }

    for num in start_num..=latest_num {
        let num_hex = normalize_block_param(&format!("0x{num:x}"));
        let block_req = json!({ "jsonrpc": "2.0", "method": "eth_getBlockByNumber", "params": [num_hex, true], "id": 9999 });
        let block_res = forward_to_reth_http(reth_port, &block_req).await;
        let block = match block_res {
            Ok(res) => {
                let r = extract_result(res);
                if r.is_object() {
                    r
                } else {
                    continue;
                }
            }
            Err(_) => continue,
        };

        let block_hash_opt = block["hash"].as_str().map(std::string::ToString::to_string);

        if let Some(txs) = block["transactions"].as_array() {
            for tx_obj in txs {
                let mut from_addr = tx_obj["from"].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                let to_addr = tx_obj["to"].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                let val_str = tx_obj["value"].as_str().unwrap_or("0x0");
                let tx_hash = tx_obj["hash"].as_str().unwrap_or("").parse::<B256>().unwrap_or_default();
                let value = U256::from_str_radix(val_str.trim_start_matches("0x"), 16).unwrap_or(U256::ZERO);

                if from_addr == Address::ZERO {
                    if let Some(raw_input) = tx_obj.get("input").or_else(|| tx_obj.get("data")).and_then(|v| v.as_str()) {
                        if let Some(s) = decode_sender(raw_input) {
                            from_addr = s;
                        }
                    }
                }

                // Finalize auto-claims
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

                    let reg = get_registry().read().unwrap();
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

                if value > U256::ZERO && to_addr != Address::ZERO {
                    let reg = get_registry().read().unwrap();
                    let mut state = get_state().write().unwrap();
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
                        v: "0x1c".to_string(),
                        r: "0x0".to_string(),
                        s: "0x0".to_string(),
                    };
                    add_native_transfer_record(&mut state, record);
                }

                if let Ok(mut meta_lock) = get_outbound_meta().write() {
                    meta_lock.remove(&tx_hash);
                }

                if sovereign_consensus::system_registry::is_system_address(&to_addr) {
                    let input_str_opt = tx_obj.get("input").or_else(|| tx_obj.get("data")).and_then(|v| v.as_str());
                    if let Some(input_hex) = input_str_opt {
                        let clean_input = input_hex.trim_start_matches("0x");
                        if let Ok(calldata) = alloy_primitives::hex::decode(clean_input) {
                            let mut reg = get_registry().write().unwrap();
                            let _ = sovereign_consensus::precompile_router::execute_system_action(
                                &mut reg,
                                from_addr,
                                to_addr,
                                &calldata,
                                num,
                            );
                        }
                    }
                }
            }
        }
    }
    LAST_SYNCED_BLOCK.store(latest_num, std::sync::atomic::Ordering::Relaxed);
}
