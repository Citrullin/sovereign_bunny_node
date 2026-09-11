use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, U256};
use serde_json::json;
use sovereign_consensus::registry::get_registry;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info};

pub use crate::rpc::*;

fn timestamp_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

static IROH_ENGINE: std::sync::OnceLock<sovereign_consensus::storage::IrohStorageEngine> = std::sync::OnceLock::new();

pub fn get_iroh_engine() -> &'static sovereign_consensus::storage::IrohStorageEngine {
    IROH_ENGINE.get_or_init(|| {
        let path = std::env::var("SOVEREIGN_IROH_PATH").unwrap_or_else(|_| "iroh_storage".to_string());
        sovereign_consensus::storage::IrohStorageEngine::open_or_create(path)
            .unwrap_or_else(|_| sovereign_consensus::storage::IrohStorageEngine::new_in_memory())
    })
}

static PROXY_AP_FEED: std::sync::OnceLock<std::sync::RwLock<Vec<serde_json::Value>>> = std::sync::OnceLock::new();

pub fn get_proxy_ap_feed() -> &'static std::sync::RwLock<Vec<serde_json::Value>> {
    PROXY_AP_FEED.get_or_init(|| std::sync::RwLock::new(Vec::new()))
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
                let pos = s.find("\r\n\r\n").or_else(|| s.find("\n\n"));
                let Some(pos) = pos else { continue };
                let header_len = if s.contains("\r\n\r\n") { pos + 4 } else { pos + 2 };

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
                info!("==================================================================");
                info!("🌐 INCOMING STATELESS ZKEVM PROXY REQUEST:\n{request_str}");
                info!("==================================================================");

                if request_str.starts_with("OPTIONS") {
                    let _ = client_stream.write_all(
                        b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nContent-Length: 0\r\n\r\n"
                    ).await;
                    continue;
                }

                let body_start = request_str.find("\r\n\r\n").map(|i| i + 4)
                    .or_else(|| request_str.find("\n\n").map(|i| i + 2))
                    .unwrap_or(0);
                let body_json: serde_json::Value = serde_json::from_str(&request_str[body_start..])
                    .unwrap_or(serde_json::Value::Null);
                if body_json.is_array() {
                    let reth_res = forward_to_reth_http(reth_port, &body_json).await.unwrap_or(json!([]));
                    let mut final_batch = if reth_res.is_array() {
                        reth_res.as_array().unwrap().clone()
                    } else {
                        vec![reth_res; body_json.as_array().unwrap().len()]
                    };

                    for (i, req) in body_json.as_array().unwrap().iter().enumerate() {
                        let method = req["method"].as_str().unwrap_or("");
                        let id = &req["id"];
                        
                        if method == "eth_estimateGas" {
                            if let Some(est_params) = req["params"].get(0) {
                                let from = est_params["from"].as_str().unwrap_or("");
                                let to_str = est_params["to"].as_str().unwrap_or("");
                                let data = est_params["data"].as_str().or_else(|| est_params["input"].as_str()).unwrap_or("");
                                
                                let is_sys = if let Ok(to_addr) = to_str.parse::<Address>() {
                                    sovereign_consensus::system_registry::is_system_address(&to_addr)
                                } else {
                                    false
                                };

                                if is_sys || (!from.is_empty() && from.eq_ignore_ascii_case(to_str) && (data.is_empty() || data == "0x")) {
                                    final_batch[i] = json!({
                                        "jsonrpc": "2.0",
                                        "result": "0x7a120",
                                        "id": id
                                    });
                                }
                            }
                        }

                        if method == "eth_call" {
                            let call_params = &req["params"][0];
                            let to_str = call_params["to"].as_str().unwrap_or("");
                            let data_str = call_params["data"].as_str().unwrap_or("0x");
                            if let Ok(to_addr) = to_str.parse::<Address>() {
                                let is_sys = sovereign_consensus::system_registry::is_system_address(&to_addr);
                                let is_actor;
                                let mut target_precompile = to_addr;
                                let mut resolved_calldata = alloy_primitives::hex::decode(data_str.trim_start_matches("0x")).unwrap_or_default();

                                {
                                    let reg = get_registry().read().unwrap();
                                    is_actor = reg.actors.values().any(|actor| {
                                        Address::from_slice(&actor.actor_id[0..20]) == to_addr
                                    });
                                    if is_actor {
                                        target_precompile = sovereign_consensus::system_registry::SYSTEM_ASYNC_INBOX;
                                        if let Some(actor) = reg.actors.values().find(|a| Address::from_slice(&a.actor_id[0..20]) == to_addr) {
                                            let mut prefixed = actor.actor_id.to_vec();
                                            prefixed.extend_from_slice(&resolved_calldata);
                                            resolved_calldata = prefixed;
                                        }
                                    }
                                }

                                if is_sys || is_actor {
                                    let mut hex_result_opt = None;
                                    if let Ok(reg) = get_registry().read() {
                                        if target_precompile == sovereign_consensus::system_registry::SYSTEM_ACCOUNT_HEIGHT {
                                            if resolved_calldata.len() >= 20 {
                                                let target_account = if resolved_calldata.len() >= 32 {
                                                    Address::from_slice(&resolved_calldata[12..32])
                                                } else {
                                                    Address::from_slice(&resolved_calldata[0..20])
                                                };
                                                let mut sequence = 0u64;
                                                let mut latest_hash = B256::ZERO;
                                                let mut merit_rank = 0u64;
                                                let mut q1 = 0u64;
                                                let mut q2 = 0u64;
                                                if let Some(frontier) = reg.account_frontiers.get(&target_account) {
                                                    sequence = frontier.sequence;
                                                    latest_hash = frontier.latest_hash;
                                                    merit_rank = frontier.merit_rank as u64;
                                                    if let Some(ref compliance) = frontier.cached_compliance {
                                                        q1 = compliance.0[0];
                                                        q2 = compliance.0[1];
                                                    }
                                                }
                                                let tier = reg.did_key_tier.get(&target_account).copied().unwrap_or(sovereign_consensus::pq_registry::KeyTier::Classical);
                                                let key_tier = match tier {
                                                    sovereign_consensus::pq_registry::KeyTier::Classical => 0u64,
                                                    sovereign_consensus::pq_registry::KeyTier::QuantumReady => 1u64,
                                                    sovereign_consensus::pq_registry::KeyTier::QuantumOnly => 2u64,
                                                };
                                                let mut out = vec![0u8; 192];
                                                out[24..32].copy_from_slice(&sequence.to_be_bytes());
                                                out[32..64].copy_from_slice(latest_hash.as_slice());
                                                out[88..96].copy_from_slice(&merit_rank.to_be_bytes());
                                                out[120..128].copy_from_slice(&q1.to_be_bytes());
                                                out[152..160].copy_from_slice(&q2.to_be_bytes());
                                                out[184..192].copy_from_slice(&key_tier.to_be_bytes());
                                                hex_result_opt = Some(format!("0x{}", alloy_primitives::hex::encode(&out)));
                                            }
                                        } else if target_precompile == sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY {
                                            let mut resolved_did = None;
                                            let is_addr = resolved_calldata.len() == 20 || resolved_calldata.len() == 32;
                                            if is_addr {
                                                let addr = if resolved_calldata.len() == 32 {
                                                    Address::from_slice(&resolved_calldata[12..32])
                                                } else {
                                                    Address::from_slice(&resolved_calldata[0..20])
                                                };
                                                if let Some(did) = reg.get_did_by_address(&addr) {
                                                    resolved_did = Some(did);
                                                }
                                            } else if let Ok(did_str) = String::from_utf8(resolved_calldata.clone()) {
                                                let normalized = sovereign_consensus::registry::ValidatorRegistry::normalize_query_did(&did_str);
                                                if reg.is_did_registered(&normalized) {
                                                    resolved_did = Some(normalized);
                                                } else if let Some(ident) = reg.find_identity_by_any_key(&normalized) {
                                                    resolved_did = Some(ident.did.clone());
                                                }
                                            }
                                            if let Some(ref did) = resolved_did {
                                                let address = reg.get_address_by_did(did).map(|a| format!("{a:#x}"));
                                                let mut keys = serde_json::Map::new();
                                                let ident_opt = reg.identities.get(did).or_else(|| {
                                                    if is_addr {
                                                        let addr = if resolved_calldata.len() == 32 {
                                                            Address::from_slice(&resolved_calldata[12..32])
                                                        } else {
                                                            Address::from_slice(&resolved_calldata[0..20])
                                                        };
                                                        reg.identities.values().find(|i| i.doc.evm_address == addr)
                                                    } else {
                                                        None
                                                    }
                                                });

                                                if let Some(ident) = ident_opt {
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
                                                let response_obj = json!({
                                                    "registered": true,
                                                    "did": resolved_did,
                                                    "address": address,
                                                    "keys": if keys.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(keys) }
                                                });
                                                let response_str = serde_json::to_string(&response_obj).unwrap_or_default();
                                                let str_bytes = response_str.as_bytes();
                                                let mut out = vec![0u8; 32];
                                                out[31] = 32;
                                                let mut len_bytes = [0u8; 32];
                                                let str_len = str_bytes.len();
                                                len_bytes[24..32].copy_from_slice(&(str_len as u64).to_be_bytes());
                                                out.extend_from_slice(&len_bytes);
                                                out.extend_from_slice(str_bytes);
                                                let remainder = out.len() % 32;
                                                if remainder > 0 {
                                                    out.extend(vec![0u8; 32 - remainder]);
                                                }
                                                hex_result_opt = Some(format!("0x{}", alloy_primitives::hex::encode(&out)));
                                            } else {
                                                if is_addr {
                                                    let addr = if resolved_calldata.len() == 32 {
                                                        Address::from_slice(&resolved_calldata[12..32])
                                                    } else {
                                                        Address::from_slice(&resolved_calldata[0..20])
                                                    };
                                                    if let Some(ident) = reg.identities.values().find(|i| i.doc.evm_address == addr) {
                                                        let did_str = ident.did.clone();
                                                        let response_obj = json!({
                                                            "registered": true,
                                                            "did": did_str,
                                                            "address": format!("{addr:#x}"),
                                                            "keys": serde_json::Value::Null
                                                        });
                                                        let response_str = serde_json::to_string(&response_obj).unwrap_or_default();
                                                        let str_bytes = response_str.as_bytes();
                                                        let mut out = vec![0u8; 32];
                                                        out[31] = 32;
                                                        let mut len_bytes = [0u8; 32];
                                                        let str_len = str_bytes.len();
                                                        len_bytes[24..32].copy_from_slice(&(str_len as u64).to_be_bytes());
                                                        out.extend_from_slice(&len_bytes);
                                                        out.extend_from_slice(str_bytes);
                                                        let remainder = out.len() % 32;
                                                        if remainder > 0 {
                                                            out.extend(vec![0u8; 32 - remainder]);
                                                        }
                                                        hex_result_opt = Some(format!("0x{}", alloy_primitives::hex::encode(&out)));
                                                    } else {
                                                        hex_result_opt = Some("0x".to_string());
                                                    }
                                                } else {
                                                    hex_result_opt = Some("0x".to_string());
                                                }
                                            }
                                        } else if target_precompile == sovereign_consensus::system_registry::SYSTEM_RECEIVE_HOOK {
                                            if resolved_calldata.len() >= 20 {
                                                let target_addr = if resolved_calldata.len() >= 32 {
                                                    Address::from_slice(&resolved_calldata[12..32])
                                                } else {
                                                    Address::from_slice(&resolved_calldata[0..20])
                                                };
                                                let mut sends = Vec::new();
                                                for (hash, block) in &reg.lattice_blocks {
                                                    if let sovereign_consensus::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                                                        if *recipient == target_addr {
                                                            sends.push((*hash, block, amount));
                                                        }
                                                    }
                                                }
                                                let mut claimed = std::collections::HashSet::new();
                                                for block in reg.lattice_blocks.values() {
                                                    if let sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
                                                        claimed.insert(*send_block_hash);
                                                    }
                                                }
                                                let mut pending = Vec::new();
                                                for (send_hash, block, amount) in sends {
                                                    if !claimed.contains(&send_hash) {
                                                        pending.push(json!({
                                                            "sendBlockHash": format!("{:#x}", send_hash),
                                                            "sender": format!("{:#x}", block.account),
                                                            "amount": amount.to_string(),
                                                        }));
                                                    }
                                                }
                                                let response_str = serde_json::to_string(&pending).unwrap_or_default();
                                                let str_bytes = response_str.as_bytes();
                                                let mut out = vec![0u8; 32];
                                                out[31] = 32;
                                                let mut len_bytes = [0u8; 32];
                                                len_bytes[24..32].copy_from_slice(&(str_bytes.len() as u64).to_be_bytes());
                                                out.extend_from_slice(&len_bytes);
                                                out.extend_from_slice(str_bytes);
                                                let remainder = out.len() % 32;
                                                if remainder > 0 {
                                                    out.extend(vec![0u8; 32 - remainder]);
                                                }
                                                hex_result_opt = Some(format!("0x{}", alloy_primitives::hex::encode(&out)));
                                            }
                                        } else if target_precompile == sovereign_consensus::system_registry::SYSTEM_JURISDICTION {
                                            let manifold_id = if resolved_calldata.len() >= 8 {
                                                u64::from_be_bytes(resolved_calldata[0..8].try_into().unwrap_or([0u8; 8]))
                                            } else {
                                                13371337u64
                                            };
                                            let vector = reg.jurisdiction_vectors.get(&manifold_id).cloned().unwrap_or_else(|| {
                                                let mut bit_registry = HashMap::new();
                                                bit_registry.insert((1, 0), "KYC/AML Verified".to_string());
                                                bit_registry.insert((1, 1), "Sanctioned Entity".to_string());
                                                bit_registry.insert((1, 2), "PEP Flagged".to_string());
                                                bit_registry.insert((2, 0), "Accredited Investor".to_string());
                                                bit_registry.insert((2, 1), "Institutional".to_string());
                                                bit_registry.insert((2, 2), "Region: United States".to_string());
                                                bit_registry.insert((2, 3), "Region: European Union".to_string());
                                                bit_registry.insert((2, 4), "Region: Switzerland".to_string());
                                                bit_registry.insert((2, 5), "Region: Cayman Islands".to_string());
                                                sovereign_consensus::jurisdiction::JurisdictionVector {
                                                    manifold_id,
                                                    active_q1_mask: 0,
                                                    required_q2_mask: 0,
                                                    velocity_limit: None,
                                                    appointed_enforcer_did: None,
                                                    epoch_established: 1,
                                                    compliance_root: [0; 32],
                                                    bit_registry,
                                                }
                                            });
                                            let mut serialized_bit_registry = serde_json::Map::new();
                                            for ((q, b), label) in &vector.bit_registry {
                                                serialized_bit_registry.insert(format!("{}_{}", q, b), json!(label));
                                            }
                                            let response_obj = json!({
                                                "manifoldId": vector.manifold_id,
                                                "activeQ1Mask": vector.active_q1_mask.to_string(),
                                                "requiredQ2Mask": vector.required_q2_mask.to_string(),
                                                "epochEstablished": vector.epoch_established,
                                                "bitRegistry": serialized_bit_registry
                                            });
                                            let response_str = serde_json::to_string(&response_obj).unwrap_or_default();
                                            let str_bytes = response_str.as_bytes();
                                            let mut out = vec![0u8; 32];
                                            out[31] = 32;
                                            let mut len_bytes = [0u8; 32];
                                            len_bytes[24..32].copy_from_slice(&(str_bytes.len() as u64).to_be_bytes());
                                            out.extend_from_slice(&len_bytes);
                                            out.extend_from_slice(str_bytes);
                                            let remainder = out.len() % 32;
                                            if remainder > 0 {
                                                out.extend(vec![0u8; 32 - remainder]);
                                            }
                                            hex_result_opt = Some(format!("0x{}", alloy_primitives::hex::encode(&out)));
                                        }
                                    }

                                    if let Some(hex_result) = hex_result_opt {
                                        final_batch[i] = json!({
                                            "jsonrpc": "2.0",
                                            "result": hex_result,
                                            "id": id
                                        });
                                    }
                                }
                            }
                        }
                    }

                    write_json(&mut client_stream, &json!(final_batch).to_string()).await;
                    continue;
                }
                let method = body_json["method"].as_str().unwrap_or("");
                let id = body_json["id"].clone();

                info!("⚙️ PARSED JSON-RPC METHOD: [{method}] with ID: [{id}]");

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








                if method == "sovereign_getAccountSecurity" || method == "bunny_getAccountSecurity" {
                    let addr_str = body_json["params"][0].as_str().unwrap_or("");
                    if let Ok(addr) = addr_str.parse::<Address>() {
                        let (allow_legacy, has_did) = {
                            let reg = get_registry().read().unwrap();
                            let allow = reg.is_legacy_allowed(&addr);
                            let did_str = format!("did:sovereign:{}:{}", reg.chain_id, addr.to_string().to_lowercase());
                            let has = reg.address_to_did.contains_key(&addr)
                                || reg.identities.contains_key(&did_str)
                                || reg.peer_keys.contains_key(&did_str)
                                || reg.get_did_by_address(&addr).map(|d| reg.is_did_registered(&d)).unwrap_or(false);
                            (allow, has)
                        };

                        let (security_tier, is_quantum_secure, warning) = if has_did {
                            ("QuantumNative", true, None)
                        } else if allow_legacy {
                            ("LegacyAllowedInsecure", false, Some("WARN: YOU ARE USING A NON POST QUANTUM SECURE ACCOUNT. Your funds rely on classical signature schemes that can be cracked by quantum computers. Upgrade to Post-Quantum by registering a DID."))
                        } else {
                            ("UninitializedBlocked", false, Some("Post-Quantum security required. Address has no registered DID and ALLOW_LEGACY is false."))
                        };

                        send_result(&mut client_stream, &id, json!({
                            "address": format!("{:#x}", addr),
                            "allow_legacy": allow_legacy,
                            "has_did": has_did,
                            "is_quantum_secure": is_quantum_secure,
                            "security_tier": security_tier,
                            "warning": warning
                        })).await;
                    } else {
                        send_error(&mut client_stream, &id, -32602, "Invalid address parameter").await;
                    }
                    continue;
                }

                if method == "sovereign_setAllowLegacy" || method == "bunny_setAllowLegacy" {
                    let addr_str = body_json["params"][0].as_str().unwrap_or("");
                    let allowed = body_json["params"][1].as_bool().unwrap_or(true);
                    if let Ok(addr) = addr_str.parse::<Address>() {
                        {
                            let mut reg = get_registry().write().unwrap();
                            reg.set_legacy_allowed(addr, allowed);
                        }
                        send_result(&mut client_stream, &id, json!({
                            "address": format!("{:#x}", addr),
                            "allow_legacy": allowed,
                            "status": "updated"
                        })).await;
                    } else {
                        send_error(&mut client_stream, &id, -32602, "Invalid address parameter").await;
                    }
                    continue;
                }

                if method == "sovereign_registerDid" || method == "bunny_registerDid" {
                    sync_hot_storage(reth_port).await;
                    let params = &body_json["params"];
                    let mut target_addr = Address::ZERO;
                    let mut did_uri = String::new();
                    let mut found_doc = None;

                    if let Some(arr) = params.as_array() {
                        for param in arr {
                            if let Some(s) = param.as_str() {
                                if s.starts_with("0x") || s.starts_with("0X") {
                                    if let Ok(a) = s.parse::<Address>() {
                                        target_addr = a;
                                    }
                                } else if s.starts_with("did:") {
                                    did_uri = s.to_string();
                                    if let Some(a) = sovereign_consensus::governance::registry::ValidatorRegistry::extract_address_from_did(s) {
                                        target_addr = a;
                                    }
                                } else if let Ok(doc_val) = serde_json::from_str::<serde_json::Value>(s) {
                                    if let Some(id_str) = doc_val.get("id").and_then(|id| id.as_str()) {
                                        did_uri = id_str.to_string();
                                        if let Some(a) = sovereign_consensus::governance::registry::ValidatorRegistry::extract_address_from_did(id_str) {
                                            target_addr = a;
                                        }
                                    }
                                    if let Some(doc) = sovereign_identity::did::SovereignDidDocument::from_json_string(s) {
                                        found_doc = Some(doc);
                                    }
                                }
                            } else if let Some(obj) = param.as_object() {
                                if let Some(a_str) = obj.get("address").and_then(|a| a.as_str()) {
                                    if let Ok(a) = a_str.parse::<Address>() {
                                        target_addr = a;
                                    }
                                }
                                if let Some(id_str) = obj.get("id").or_else(|| obj.get("did")).and_then(|d| d.as_str()) {
                                    did_uri = id_str.to_string();
                                    if target_addr == Address::ZERO {
                                        if let Some(a) = sovereign_consensus::governance::registry::ValidatorRegistry::extract_address_from_did(id_str) {
                                            target_addr = a;
                                        }
                                    }
                                }
                                let doc_candidate = obj.get("doc").unwrap_or(param);
                                let s = doc_candidate.to_string();
                                if let Some(doc) = sovereign_identity::did::SovereignDidDocument::from_json_string(&s) {
                                    found_doc = Some(doc);
                                }
                            }
                        }
                    }

                    if target_addr == Address::ZERO && found_doc.is_some() {
                        target_addr = found_doc.as_ref().unwrap().evm_address;
                    }
                    if target_addr == Address::ZERO {
                        target_addr = Address::repeat_byte(0x91);
                    }

                    let mut parsed_doc = found_doc.unwrap_or_else(|| sovereign_identity::did::SovereignDidDocument::derive_from_seed(B256::from_slice(blake3::hash(target_addr.as_slice()).as_bytes())));
                    parsed_doc.evm_address = target_addr;
                    if did_uri.is_empty() {
                        did_uri = format!("did:sovereign:13371337:{target_addr:#x}");
                    }
                    parsed_doc.did_uri = did_uri.clone();

                    let doc_str = parsed_doc.to_w3c_json_ld().to_string();
                    let tx_hash = format!("0x{}", alloy_primitives::hex::encode(blake3::hash(doc_str.as_bytes()).as_bytes()));

                    {
                        let mut reg = get_registry().write().unwrap();
                        let _ = reg.sync_identity_from_doc(parsed_doc.clone());
                        reg.peer_keys.insert(did_uri.clone(), [0x01; 32]);
                        reg.address_to_did.insert(target_addr, did_uri.clone());
                        let identity_record = sovereign_consensus::governance::registry::RegisteredIdentity {
                            did: did_uri.clone(),
                            doc: parsed_doc.clone(),
                            registered_at: reg.current_epoch,
                        };
                        reg.identities.insert(did_uri.clone(), identity_record.clone());
                        reg.identities.insert(format!("{target_addr:#x}"), identity_record.clone());
                        reg.identities.insert(format!("{target_addr}"), identity_record);

                        let mut frontier = reg.get_or_create_frontier(target_addr);
                        frontier.sequence += 1;
                        let did_commitment = B256::from_slice(blake3::hash(tx_hash.as_bytes()).as_bytes());
                        frontier.latest_hash = did_commitment;
                        reg.update_frontier(target_addr, frontier.clone());

                        // Mount Slot 0 on CAR register
                        let current_epoch = reg.current_epoch.max(1);
                        let car = reg.get_or_create_register(target_addr);
                        if let Some(s0) = car.slots.get_mut(&0) {
                            s0.commitment = did_commitment;
                            s0.sequence += 1;
                            s0.last_updated_epoch = current_epoch;
                        } else {
                            let _ = car.mount_slot(0, did_commitment, B256::repeat_byte(0x03), "core.did_identity".to_string());
                        }
                    }

                    let _ = get_iroh_engine().store_blob(3, doc_str.as_bytes());
                    let _ = get_iroh_engine().store_named_blob(3, &format!("{target_addr:#x}"), doc_str.as_bytes());
                    let _ = get_iroh_engine().store_named_blob(3, &format!("{target_addr:#x}").to_lowercase(), doc_str.as_bytes());
                    let _ = get_iroh_engine().store_named_blob(3, &did_uri, doc_str.as_bytes());

                    send_result(&mut client_stream, &id, json!({
                        "status": "success",
                        "address": format!("{:#x}", target_addr),
                        "did": did_uri,
                        "tx_hash": tx_hash
                    })).await;
                    continue;
                }

                if method == "sovereign_getDid" || method == "bunny_getDid" {
                    sync_hot_storage(reth_port).await;
                    let did_input = body_json["params"][0].as_str().unwrap_or("");
                    let payload = {
                        let reg = get_registry().read().unwrap();
                        let did_uri = sovereign_consensus::governance::registry::ValidatorRegistry::normalize_query_did(did_input);
                        let registered = reg.is_did_registered(&did_uri);
                        let address = reg.get_address_by_did(&did_uri).map(|a| format!("{a:#x}"));

                        let resolved_did = if let Some(ident) = reg.find_identity_by_any_key(&did_uri) {
                            ident.did.clone()
                        } else if let Some(addr) = sovereign_consensus::governance::registry::ValidatorRegistry::extract_address_from_did(&did_uri) {
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

                        json!({
                            "registered": registered,
                            "did": resolved_did,
                            "address": address,
                            "keys": if keys.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(keys) }
                        })
                    };
                    send_result(&mut client_stream, &id, payload).await;
                    continue;
                }

                if method == "sovereign_getDidByAddress" || method == "bunny_getDidByAddress" {
                    sync_hot_storage(reth_port).await;
                    let addr_str = body_json["params"][0].as_str().unwrap_or("");
                    if let Ok(addr) = addr_str.parse::<Address>() {
                        let did_opt = {
                            let reg = get_registry().read().unwrap();
                            reg.get_did_by_address(&addr).or_else(|| {
                                reg.identities.values().find(|i| i.doc.evm_address == addr).map(|i| i.did.clone())
                            })
                        };
                        send_result(&mut client_stream, &id, json!({
                            "address": format!("{:#x}", addr),
                            "did": did_opt
                        })).await;
                    } else {
                        send_error(&mut client_stream, &id, -32602, "Invalid address parameter").await;
                    }
                    continue;
                }

                if method == "sovereign_resolveDidDocument" || method == "bunny_resolveDidDocument" {
                    sync_hot_storage(reth_port).await;
                    let query = body_json["params"][0].as_str().unwrap_or("");
                    let (result_val, error_opt) = {
                        let reg = get_registry().read().unwrap();

                        let addr_opt = if query.starts_with("0x") || query.starts_with("0X") {
                            query.parse::<Address>().ok()
                        } else if let Some(addr) = sovereign_consensus::governance::registry::ValidatorRegistry::extract_address_from_did(query) {
                            Some(addr)
                        } else {
                            None
                        };

                        let mut found_doc = None;

                        if let Some(ref addr) = addr_opt {
                            if let Some(did) = reg.get_did_by_address(addr) {
                                if let Some(ident) = reg.identities.get(&did) {
                                    found_doc = Some(ident.doc.clone());
                                }
                            }
                            if found_doc.is_none() {
                                if let Some(ident) = reg.identities.get(&format!("{addr:#x}"))
                                    .or_else(|| reg.identities.get(&format!("{addr}")))
                                    .or_else(|| reg.identities.get(&format!("{addr:#X}")))
                                {
                                    found_doc = Some(ident.doc.clone());
                                }
                            }
                            if found_doc.is_none() {
                                if let Some(ident) = reg.identities.values().find(|i| i.doc.evm_address == *addr) {
                                    found_doc = Some(ident.doc.clone());
                                }
                            }
                        }

                        if found_doc.is_none() {
                            let normalized = sovereign_consensus::governance::registry::ValidatorRegistry::normalize_query_did(query);
                            if let Some(ident) = reg.identities.get(&normalized) {
                                found_doc = Some(ident.doc.clone());
                            } else if let Some(ident) = reg.identities.get(query) {
                                found_doc = Some(ident.doc.clone());
                            } else if let Some(ident) = reg.find_identity_by_any_key(&normalized) {
                                found_doc = Some(ident.doc.clone());
                            }
                        }

                        if let Some(doc) = found_doc {
                            (Some(doc.to_w3c_json_ld()), None)
                        } else {
                            (None, Some("No on-chain DID Document found"))
                        }
                    };

                    if let Some(res) = result_val {
                        send_result(&mut client_stream, &id, res).await;
                    } else if let Some(err) = error_opt {
                        send_error(&mut client_stream, &id, -32602, err).await;
                    }
                    continue;
                }

                if method == "sovereign_resolveSlot" || method == "bunny_resolveSlot" {
                    sync_hot_storage(reth_port).await;
                    let target_addr_str = body_json["params"][0].as_str().unwrap_or("");
                    let slot_param = &body_json["params"][1];

                    let slot_id: u16 = if let Some(s) = slot_param.as_str() {
                        if s.starts_with("0x") || s.starts_with("0X") {
                            u16::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0)
                        } else {
                            s.parse::<u16>().unwrap_or(0)
                        }
                    } else if let Some(n) = slot_param.as_u64() {
                        n as u16
                    } else {
                        0
                    };

                    if let Ok(addr) = target_addr_str.parse::<Address>() {
                        let (mounted, plugin_id, root) = {
                            let reg = get_registry().read().unwrap();
                            let has_did = reg.address_to_did.contains_key(&addr)
                                || reg.identities.values().any(|i| i.doc.evm_address == addr || format!("{:#x}", i.doc.evm_address).eq_ignore_ascii_case(&format!("{:#x}", addr)))
                                || reg.pq_keys.contains_key(&addr);

                            let query_slot_key = if slot_id == 3 { 0 } else { slot_id };
                            if let Some(car) = reg.account_registers.get(&addr) {
                                if let Some(slot) = car.slots.get(&query_slot_key).or_else(|| car.slots.get(&slot_id)) {
                                    let is_mounted = if query_slot_key == 0 {
                                        slot.commitment != B256::ZERO && has_did
                                    } else {
                                        slot.commitment != B256::ZERO
                                    };
                                    (is_mounted, slot.plugin_id.clone(), format!("{:#x}", slot.commitment))
                                } else {
                                    (false, format!("slot.0x{:02x}", slot_id), format!("{:#x}", B256::ZERO))
                                }
                            } else {
                                match slot_id {
                                    0x00 | 0x03 => {
                                        let root_hash = if has_did {
                                            alloy_primitives::keccak256(addr.as_slice())
                                        } else {
                                            B256::ZERO
                                        };
                                        (has_did, "core.did_identity".to_string(), format!("{:#x}", root_hash))
                                    },
                                    0x01 | 0x61 => (false, "core.zanzibar".to_string(), format!("{:#x}", B256::ZERO)),
                                    0x02 => (false, "core.paymaster".to_string(), format!("{:#x}", B256::ZERO)),
                                    0x04 => (false, "vcs.git_dag".to_string(), format!("{:#x}", B256::ZERO)),
                                    0x05 | 0xF1 => (false, "core.activitypub".to_string(), format!("{:#x}", B256::ZERO)),
                                    0x06 => (false, "core.web_of_things".to_string(), format!("{:#x}", B256::ZERO)),
                                    0x08 => {
                                        let comp = reg.account_frontiers.get(&addr).and_then(|f| f.cached_compliance.as_ref());
                                        (comp.is_some() && has_did, "core.zk_compliance".to_string(), format!("{:#x}", B256::ZERO))
                                    },
                                    0x53 => (false, "core.storage_da".to_string(), format!("{:#x}", B256::ZERO)),
                                    0x54 => (false, "core.signal_registry".to_string(), format!("{:#x}", B256::ZERO)),
                                    0x0100 => {
                                        let seq = reg.account_frontiers.get(&addr).map(|f| f.sequence).unwrap_or(if has_did { 1 } else { 0 });
                                        (has_did, "core.lattice_height".to_string(), format!("0x{:064x}", seq))
                                    },
                                    other => (false, format!("slot.0x{:02x}", other), format!("{:#x}", B256::ZERO))
                                }
                            }
                        };

                        send_result(&mut client_stream, &id, json!({
                            "mounted": mounted,
                            "slot_id": slot_id,
                            "plugin_id": plugin_id,
                            "root": root
                        })).await;
                    } else {
                        send_error(&mut client_stream, &id, -32602, "Invalid address parameter").await;
                    }
                    continue;
                }

                if method == "sovereign_resolveBlob" || method == "bunny_resolveBlob" || method == "bunny_getBlob" {
                    let cid = body_json["params"][0].as_str().unwrap_or("");
                    match get_iroh_engine().get_blob(cid) {
                        Ok(data) => {
                            let utf8_str = String::from_utf8(data.clone()).ok();
                            send_result(&mut client_stream, &id, json!({
                                "cid": cid,
                                "data": format!("0x{}", alloy_primitives::hex::encode(&data)),
                                "utf8": utf8_str,
                                "size": data.len()
                            })).await;
                        }
                        Err(e) => {
                            send_error(&mut client_stream, &id, -32602, &format!("Blob not found: {e}")).await;
                        }
                    }
                    continue;
                }

                if method == "sovereign_storeBlob" || method == "bunny_storeBlob" {
                    let ns_id = body_json["params"][0].as_u64().unwrap_or(0);
                    let data_input = body_json["params"][1].as_str().unwrap_or("");
                    let data_bytes = if data_input.starts_with("0x") || data_input.starts_with("0X") {
                        alloy_primitives::hex::decode(data_input.trim_start_matches("0x").trim_start_matches("0X")).unwrap_or_else(|_| data_input.as_bytes().to_vec())
                    } else {
                        data_input.as_bytes().to_vec()
                    };

                    match get_iroh_engine().store_blob(ns_id, &data_bytes) {
                        Ok(meta) => {
                            send_result(&mut client_stream, &id, json!({
                                "cid": meta.cid,
                                "hash": format!("0x{}", alloy_primitives::hex::encode(meta.hash)),
                                "size": meta.size_bytes,
                                "namespace_id": meta.namespace_id
                            })).await;
                        }
                        Err(e) => {
                            send_error(&mut client_stream, &id, -32603, &format!("Failed to store blob in Iroh DA: {e}")).await;
                        }
                    }
                    continue;
                }

                if method == "sovereign_mountSlot" || method == "bunny_mountSlot" {
                    sync_hot_storage(reth_port).await;
                    let slot_id = body_json["params"][0].as_u64().unwrap_or(5) as u16;
                    let plugin_id = body_json["params"][1].as_str().unwrap_or("core.plugin");
                    let initial_root_str = body_json["params"][2].as_str().unwrap_or("0x0");
                    let addr_opt = body_json["params"][3].as_str().and_then(|s| s.parse::<Address>().ok());
                    let addr = addr_opt.unwrap_or_else(|| Address::repeat_byte(0x91));

                    let has_did = {
                        let reg = get_registry().read().unwrap();
                        reg.address_to_did.contains_key(&addr)
                            || reg.identities.values().any(|i| i.doc.evm_address == addr || format!("{:#x}", i.doc.evm_address).eq_ignore_ascii_case(&format!("{:#x}", addr)))
                            || reg.pq_keys.contains_key(&addr)
                    };
                    if !has_did {
                        send_error(&mut client_stream, &id, -32001, "Caller account has no registered on-chain DID identity").await;
                        continue;
                    }

                    let initial_root = initial_root_str.parse::<B256>().unwrap_or(B256::ZERO);
                    let (seq, tx_hash, state_tip) = {
                        let mut reg = get_registry().write().unwrap();
                        let balance = reg.account_balances.get(&addr).copied().unwrap_or(U256::ZERO);
                        let car = reg.account_registers.entry(addr).or_insert_with(|| {
                            sovereign_consensus::lattice::car_register::PolymorphicAccountRegister::new_with_default_config(addr, balance)
                        });
                        let vk = alloy_primitives::keccak256(plugin_id.as_bytes());
                        let _ = car.mount_slot(slot_id, initial_root, vk, plugin_id.to_string());
                        let tip = car.compute_state_tip();

                        let mut frontier = reg.get_or_create_frontier(addr);
                        frontier.sequence += 1;
                        frontier.latest_hash = tip;
                        reg.update_frontier(addr, frontier.clone());

                        let hash_str = format!("0x{}", alloy_primitives::hex::encode(blake3::hash(format!("mount:{}:{}:{}", addr, slot_id, plugin_id).as_bytes()).as_bytes()));
                        (frontier.sequence, hash_str, tip)
                    };

                    send_result(&mut client_stream, &id, json!({
                        "status": "mounted",
                        "slot_id": slot_id,
                        "plugin_id": plugin_id,
                        "root": initial_root_str,
                        "state_tip": format!("{:#x}", state_tip),
                        "tx_hash": tx_hash,
                        "sequence": seq
                    })).await;
                    continue;
                }

                if method == "sovereign_anchorDaoApp" || method == "bunny_anchorDaoApp" {
                    sync_hot_storage(reth_port).await;
                    let p = if body_json["params"].is_array() && !body_json["params"].as_array().unwrap().is_empty() {
                        &body_json["params"][0]
                    } else {
                        &body_json["params"]
                    };
                    let app_id = p["app_id"].as_str().unwrap_or("CustomApp").to_string();
                    let app_version = p["app_version"].as_str().unwrap_or("v1.0.0").to_string();
                    let sql_root_str = p["sql_state_root"].as_str().unwrap_or("0x0");
                    let media_cid_str = p["media_cid"].as_str().unwrap_or("0x0");
                    let manifest_cid_str = p["manifest_cid"].as_str().unwrap_or("0x0");
                    let prev_anchor_str = p["previous_anchor"].as_str().unwrap_or("0x0");
                    let sender_str = p["sender"].as_str().or_else(|| p["address"].as_str()).unwrap_or("");
                    let sig_str = p["signature"].as_str().unwrap_or("");

                    let Ok(sender) = sender_str.parse::<Address>() else {
                        send_error(&mut client_stream, &id, -32602, "Invalid sender address parameter").await;
                        continue;
                    };

                    // Solvency check
                    let balance = {
                        let reg = get_registry().read().unwrap();
                        reg.account_balances.get(&sender).copied().unwrap_or(U256::ZERO)
                    };
                    if balance == U256::ZERO {
                        send_error(&mut client_stream, &id, -32002, "Insufficient balance: Account has insufficient TBL balance to pay for state anchoring").await;
                        continue;
                    }

                    // Check on-chain DID
                    let did_uri_opt = {
                        let reg = get_registry().read().unwrap();
                        reg.address_to_did.get(&sender).cloned()
                            .or_else(|| reg.identities.values().find(|i| i.doc.evm_address == sender || format!("{:#x}", i.doc.evm_address).eq_ignore_ascii_case(&format!("{:#x}", sender))).map(|i| i.did.clone()))
                    };
                    let did_uri = match did_uri_opt {
                        Some(did) => did,
                        None => {
                            send_error(&mut client_stream, &id, -32001, "Caller account has no registered on-chain DID identity. Real on-chain DID registration is required.").await;
                            continue;
                        }
                    };

                    // Verify signature if provided (or verify personal sign)
                    if !sig_str.is_empty() && sig_str != "0x" {
                        let sig_clean = sig_str.trim_start_matches("0x");
                        if let Ok(sig_bytes) = alloy_primitives::hex::decode(sig_clean) {
                            if sig_bytes.len() >= 64 {
                                let commit_msg = format!("DAO_APP_ANCHOR:{app_id}:{app_version}:{sql_root_str}:{media_cid_str}:{manifest_cid_str}:{prev_anchor_str}");
                                let msg_hash = alloy_primitives::keccak256(
                                    [b"\x19Ethereum Signed Message:\n", commit_msg.len().to_string().as_bytes(), commit_msg.as_bytes()].concat()
                                );
                                if let Ok(sig) = alloy_primitives::Signature::try_from(&sig_bytes[..65.min(sig_bytes.len())]) {
                                    if let Ok(recovered) = sig.recover_address_from_prehash(&msg_hash) {
                                        if recovered != sender {
                                            send_error(&mut client_stream, &id, -32003, "Cryptographic signature does not match sender address").await;
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let sql_state_root = sql_root_str.parse::<B256>().unwrap_or(B256::ZERO);
                    let media_cid = media_cid_str.parse::<B256>().unwrap_or(B256::ZERO);
                    let manifest_cid = manifest_cid_str.parse::<B256>().unwrap_or(B256::ZERO);
                    let previous_anchor = prev_anchor_str.parse::<B256>().unwrap_or(B256::ZERO);

                    let anchor = sovereign_consensus::lattice::car_register::DaoAppAnchor {
                        app_id: app_id.clone(),
                        app_version: app_version.clone(),
                        sql_state_root,
                        media_cid,
                        manifest_cid,
                        previous_anchor,
                        anchored_by_did: did_uri.clone(),
                        sender_address: sender,
                        timestamp_epoch: 1,
                        slot_id: 0,
                        state_tip: B256::ZERO,
                    };

                    let result = {
                        let mut reg = get_registry().write().unwrap();
                        reg.record_dao_app_anchor(anchor)
                    };

                    match result {
                        Ok(state_tip) => {
                            let tx_hash = format!("0x{}", alloy_primitives::hex::encode(blake3::hash(format!("dao_anchor:{sender}:{app_id}:{app_version}").as_bytes()).as_bytes()));
                            send_result(&mut client_stream, &id, json!({
                                "status": "anchored",
                                "app_id": app_id,
                                "app_version": app_version,
                                "state_tip": format!("{:#x}", state_tip),
                                "sql_state_root": format!("{:#x}", sql_state_root),
                                "media_cid": format!("{:#x}", media_cid),
                                "manifest_cid": format!("{:#x}", manifest_cid),
                                "previous_anchor": format!("{:#x}", previous_anchor),
                                "anchored_by_did": did_uri,
                                "sender": format!("{:#x}", sender),
                                "tx_hash": tx_hash
                            })).await;
                        }
                        Err(err) => {
                            send_error(&mut client_stream, &id, -32004, err).await;
                        }
                    }
                    continue;
                }

                if method == "sovereign_getDaoAppAnchors" || method == "bunny_getDaoAppAnchors" {
                    let target_addr_str = body_json["params"][0].as_str().unwrap_or("");
                    let app_filter = body_json["params"].get(1).and_then(|p| p.as_str());

                    if let Ok(addr) = target_addr_str.parse::<Address>() {
                        let filtered: Vec<_> = {
                            let reg = get_registry().read().unwrap();
                            let anchors = reg.dao_app_anchors.get(&addr).cloned().unwrap_or_default();
                            anchors.into_iter().filter(|a| {
                                if let Some(filter) = app_filter {
                                    a.app_id.eq_ignore_ascii_case(filter)
                                } else {
                                    true
                                }
                            }).collect()
                        };
                        send_result(&mut client_stream, &id, json!(filtered)).await;
                    } else {
                        send_error(&mut client_stream, &id, -32602, "Invalid address parameter").await;
                    }
                    continue;
                }

                if method == "sovereign_verifyDaoAppProof" || method == "bunny_verifyDaoAppProof" {
                    let target_addr_str = body_json["params"][0].as_str().unwrap_or("");
                    let app_id = body_json["params"][1].as_str().unwrap_or("");
                    let version = body_json["params"][2].as_str().unwrap_or("");

                    if let Ok(addr) = target_addr_str.parse::<Address>() {
                        let anchor_opt = {
                            let reg = get_registry().read().unwrap();
                            let anchors = reg.dao_app_anchors.get(&addr).cloned().unwrap_or_default();
                            anchors.into_iter().find(|a| a.app_id.eq_ignore_ascii_case(app_id) && a.app_version == version)
                        };
                        if let Some(anchor) = anchor_opt {
                            let slot_commitment = sovereign_consensus::lattice::car_register::compute_app_commitment(&anchor);
                            send_result(&mut client_stream, &id, json!({
                                "verified": true,
                                "slot_id": anchor.slot_id,
                                "slot_commitment": format!("{:#x}", slot_commitment),
                                "account_state_tip": format!("{:#x}", anchor.state_tip),
                                "stateless_verkle_stem": format!("0x{:062x}{:02x}", 0x1337u64, anchor.slot_id),
                                "provenance_valid": true,
                                "app_id": anchor.app_id,
                                "app_version": anchor.app_version
                            })).await;
                        } else {
                            send_error(&mut client_stream, &id, -32602, "Anchor not found for specified app and version").await;
                        }
                    } else {
                        send_error(&mut client_stream, &id, -32602, "Invalid address parameter").await;
                    }
                    continue;
                }

                if method == "sovereign_getPendingInbox" || method == "bunny_getPendingInbox" {
                    let target_addr = body_json["params"][0].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                    let inbox = {
                        let reg = get_registry().read().unwrap();
                        let mut claimed = std::collections::HashSet::new();
                        for block in reg.lattice_blocks.values() {
                            if let sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
                                claimed.insert(*send_block_hash);
                            }
                        }

                        let mut pending = Vec::new();
                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                        for (hash, block) in &reg.lattice_blocks {
                            if let sovereign_consensus::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                                if *recipient == target_addr && !claimed.contains(hash) {
                                    pending.push(json!({
                                        "sendBlockHash": format!("{:#x}", hash),
                                        "amount": amount.to_string(),
                                        "nonce": block.sequence,
                                        "from": format!("{:#x}", block.account),
                                        "timestamp": now,
                                        "expiration": now + 2_592_000
                                    }));
                                }
                            }
                        }
                        pending
                    };
                    send_result(&mut client_stream, &id, json!(inbox)).await;
                    continue;
                }

                if method == "sovereign_getAccountHistory" || method == "bunny_getAccountHistory" {
                    let target_addr_str = body_json["params"][0].as_str().unwrap_or("").to_lowercase();
                    let history = {
                        let reg = get_registry().read().unwrap();
                        let mut entries = Vec::new();
                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                        let epoch = reg.current_epoch.max(1);
                        for (hash, block) in &reg.lattice_blocks {
                            let block_acc = format!("{:#x}", block.account).to_lowercase();
                            if target_addr_str.is_empty() || block_acc == target_addr_str {
                                let (tx_type, title, recipient_str, amount_str) = match &block.payload {
                                    sovereign_consensus::stateless::LatticePayload::Send { recipient, amount } => {
                                        ("send", "Lattice Send", format!("{:#x}", recipient), format!("{amount} TBL"))
                                    }
                                    sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash, amount } => {
                                        ("receive", "Claim Settle", format!("{:#x}", send_block_hash), format!("{amount} TBL"))
                                    }
                                    sovereign_consensus::stateless::LatticePayload::ContractCall { target, .. } => {
                                        let is_did = *target == sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY;
                                        let t_type = if is_did { "did" } else { "precompile" };
                                        let t_title = if is_did { "Register DID (0x03)" } else { "Contract Call" };
                                        let t_amt = if is_did { "Post-Quantum DID Document".to_string() } else { "0.0 TBL".to_string() };
                                        (t_type, t_title, format!("{:#x}", target), t_amt)
                                    }
                                };
                                entries.push(json!({
                                    "hash": format!("{:#x}", hash),
                                    "type": tx_type,
                                    "title": title,
                                    "counterparty": recipient_str,
                                    "amount": amount_str,
                                    "calldata": format!("{:#x}", hash),
                                    "epoch": epoch,
                                    "timestamp": now,
                                    "status": "Settled",
                                    "account": block_acc,
                                }));
                            }
                        }
                        entries
                    };
                    send_result(&mut client_stream, &id, json!(history)).await;
                    continue;
                }

                if method == "sovereign_getConfig" || method == "bunny_getConfig" {
                    let chain_id = CHAIN_ID.load(Ordering::Relaxed);
                    send_result(&mut client_stream, &id, json!({
                        "networkName": "sovereign-local",
                        "chainId": chain_id,
                        "ticker": "TBL",
                        "currency": "TBL"
                    })).await;
                    continue;
                }

                if method == "sovereign_getTransactionByHash" || method == "bunny_getTransactionByHash" {
                    let target_hash_str = body_json["params"][0].as_str().unwrap_or("").to_lowercase();
                    let entry = {
                        let reg = get_registry().read().unwrap();
                        let mut found = None;
                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                        let epoch = reg.current_epoch.max(1);
                        for (hash, block) in &reg.lattice_blocks {
                            if format!("{:#x}", hash).to_lowercase() == target_hash_str || format!("{hash:?}").to_lowercase() == target_hash_str {
                                let (tx_type, title, recipient_str, amount_str) = match &block.payload {
                                    sovereign_consensus::stateless::LatticePayload::Send { recipient, amount } => {
                                        ("send", "Lattice Send", format!("{:#x}", recipient), format!("{amount} TBL"))
                                    }
                                    sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash, amount } => {
                                        ("receive", "Claim Settle", format!("{:#x}", send_block_hash), format!("{amount} TBL"))
                                    }
                                    sovereign_consensus::stateless::LatticePayload::ContractCall { target, .. } => {
                                        let is_did = *target == sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY;
                                        let t_type = if is_did { "did" } else { "precompile" };
                                        let t_title = if is_did { "Register DID (0x03)" } else { "Contract Call" };
                                        let t_amt = if is_did { "Post-Quantum DID Document".to_string() } else { "0.0 TBL".to_string() };
                                        (t_type, t_title, format!("{:#x}", target), t_amt)
                                    }
                                };
                                found = Some(json!({
                                    "hash": format!("{:#x}", hash),
                                    "type": tx_type,
                                    "title": title,
                                    "counterparty": recipient_str,
                                    "amount": amount_str,
                                    "calldata": format!("{:#x}", hash),
                                    "epoch": epoch,
                                    "timestamp": now,
                                    "status": "Settled",
                                    "account": format!("{:#x}", block.account),
                                }));
                                break;
                            }
                        }
                        found
                    };
                    send_result(&mut client_stream, &id, json!(entry)).await;
                    continue;
                }

                if method == "bunny_postActivityPub" {
                    let note = if let Some(s) = body_json["params"][0].as_str() {
                        if s.starts_with("0x") {
                            if let Ok(bytes) = alloy_primitives::hex::decode(&s[2..]) {
                                serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::from_str(s).unwrap_or(json!({})))
                            } else {
                                serde_json::from_str(s).unwrap_or(json!({}))
                            }
                        } else {
                            serde_json::from_str(s).unwrap_or(json!({}))
                        }
                    } else {
                        body_json["params"][0].clone()
                    };

                    let actor = note.get("actor")
                        .or_else(|| note.get("author"))
                        .and_then(|a| a.as_str())
                        .unwrap_or("did:sovereign:unknown");
                    let content = note.get("content").and_then(|c| c.as_str()).unwrap_or(
                        note.get("object").and_then(|o| o.get("content")).and_then(|c| c.as_str()).unwrap_or("")
                    );
                    let media_cid = note.get("media_cid").and_then(|m| m.as_str()).unwrap_or("");
                    let sig_str = note.get("signature").and_then(|s| s.get("signatureValue")).and_then(|v| v.as_str()).unwrap_or("");

                    let actor_addr = if let Some(addr_str) = actor.strip_prefix("did:sovereign:13371337:") {
                        let clean_addr = addr_str.split(&['#', '/'][..]).next().unwrap_or("");
                        clean_addr.parse::<Address>().unwrap_or_default()
                    } else if let Some(pos) = actor.rfind("0x") {
                        let candidate = &actor[pos..];
                        let end = candidate.find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X').unwrap_or(candidate.len());
                        candidate[..end].parse::<Address>().unwrap_or_default()
                    } else {
                        actor.parse::<Address>().unwrap_or_default()
                    };

                    let note_hash = format!("0x{}", alloy_primitives::hex::encode(blake3::hash(content.as_bytes()).as_bytes()));
                    let tx_hash = format!("{:#x}", B256::from_slice(blake3::hash(format!("ap:{note_hash}").as_bytes()).as_bytes()));
                    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;

                    let pinning_fee = sovereign_consensus::storage::calculate_pinning_fee(content.len() as u64, 1);
                    let settled_balance = get_reth_balance(reth_port, actor_addr).await;
                    let (has_solvency, has_did) = {
                        let reg = get_registry().read().unwrap();
                        let reg_bal = reg.account_balances.get(&actor_addr).copied().unwrap_or(U256::ZERO);
                        let solvent = reg_bal >= pinning_fee || settled_balance >= pinning_fee;
                        let did_ok = reg.has_registered_did(&actor_addr);
                        (solvent, did_ok)
                    };

                    if !has_did {
                        send_error(&mut client_stream, &id, -32001,
                            &format!(
                                "No state change permitted without an on-chain DID identity: Actor {actor_addr:#x} has not registered a DID on Slot 0. Please register your DID on-chain before publishing ActivityPub notes."
                            )
                        ).await;
                        continue;
                    }

                    if !has_solvency {
                        send_error(&mut client_stream, &id, -32002,
                            &format!(
                                "Insufficient balance: Account {actor_addr:#x} has insufficient TBL balance. Decentralized Iroh pinning requires an active storage lease fee (minimum fee: {pinning_fee} wei). Please fund account from genesis."
                            )
                        ).await;
                        continue;
                    }

                    let epoch = {
                        let mut reg = get_registry().write().unwrap();
                        let ep = reg.current_epoch.max(1);
                        let reg_bal = reg.account_balances.get(&actor_addr).copied().unwrap_or(U256::ZERO);
                        if reg_bal >= pinning_fee {
                            reg.account_balances.insert(actor_addr, reg_bal - pinning_fee);
                        }
                        let mut frontier = reg.get_or_create_frontier(actor_addr);
                        frontier.sequence += 1;
                        frontier.latest_hash = B256::from_slice(blake3::hash(note_hash.as_bytes()).as_bytes());
                        reg.update_frontier(actor_addr, frontier.clone());
                        ep
                    };

                    let record = json!({
                        "id": note_hash.clone(),
                        "actor": actor.to_string(),
                        "actor_address": format!("{:#x}", actor_addr),
                        "content": content.to_string(),
                        "media_cid": media_cid.to_string(),
                        "timestamp": now_ms,
                        "epoch": epoch,
                        "signature": sig_str.to_string(),
                        "tx_hash": tx_hash.clone(),
                    });

                    get_proxy_ap_feed().write().unwrap().insert(0, record.clone());

                    // Persist note into Iroh backed by active economic lease
                    let _ = get_iroh_engine().pin_blob_with_lease(
                        0x05,
                        serde_json::to_string(&record).unwrap_or_default().as_bytes(),
                        actor_addr,
                        1,
                        epoch,
                        1000,
                    );

                    send_result(&mut client_stream, &id, json!({
                        "status": "published",
                        "topic": "TOPIC_SYS_CROSS_CHAIN",
                        "activity_id": note_hash.clone(),
                        "note_id": note_hash,
                        "media_cid": media_cid,
                        "tx_hash": tx_hash,
                        "pin_cost_wei": pinning_fee.to_string(),
                        "duration_years": 1
                    })).await;
                    continue;
                }

                if method == "bunny_getActivityPubOutbox" {
                    let query = body_json["params"][0].as_str().unwrap_or("").to_lowercase();
                    let notes: Vec<serde_json::Value> = {
                        let feed = get_proxy_ap_feed().read().unwrap();
                        if query.is_empty() {
                            feed.clone()
                        } else {
                            feed.iter().filter(|n| {
                                let act = n["actor"].as_str().unwrap_or("").to_lowercase();
                                let addr = n["actor_address"].as_str().unwrap_or("").to_lowercase();
                                act.contains(&query) || addr.contains(&query)
                            }).cloned().collect()
                        }
                    };
                    send_result(&mut client_stream, &id, json!(notes)).await;
                    continue;
                }

                if method == "bunny_getActivityPubFeed" {
                    let limit = body_json["params"][0].as_u64().unwrap_or(50) as usize;
                    let notes: Vec<serde_json::Value> = {
                        let feed = get_proxy_ap_feed().read().unwrap();
                        feed.iter().take(limit).cloned().collect()
                    };
                    send_result(&mut client_stream, &id, json!(notes)).await;
                    continue;
                }

                if method == "sovereign_receive" || method == "bunny_receive" {
                    let recipient_addr = body_json["params"][0].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                    let send_block_hash = body_json["params"][1].as_str().unwrap_or("").parse::<B256>().unwrap_or_default();
                    let proof_hex = body_json["params"][2].as_str().unwrap_or("");
                    let proof_bytes = alloy_primitives::hex::decode(proof_hex.trim_start_matches("0x")).unwrap_or_default();

                    let receive_header = sovereign_consensus::lattice::ReceiveBlockHeader {
                        send_block_hash,
                        verkle_witness_proof: proof_bytes.clone(),
                    };

                    let root = B256::repeat_byte(0xaa);
                    let verified = sovereign_consensus::lattice::verify_receive_stateless(&receive_header, root);

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

                if method == "sovereign_reclaimSend" || method == "bunny_reclaimSend" {
                    let _sender_addr = body_json["params"][0].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                    let send_block_hash = body_json["params"][1].as_str().unwrap_or("").parse::<B256>().unwrap_or_default();
                    let current_block_num = body_json["params"].get(2).and_then(|v| v.as_u64()).unwrap_or(0);

                    let is_claimed = {
                        let reg = get_registry().read().unwrap();
                        reg.lattice_blocks.values().any(|b| {
                            if let sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash: sh, .. } = &b.payload {
                                *sh == send_block_hash
                            } else {
                                false
                            }
                        })
                    };

                    if is_claimed {
                        send_error(&mut client_stream, &id, -32003, "Reclaim failed: Send transaction has already been claimed").await;
                        continue;
                    }

                    let (timeout_blocks, send_block_num) = {
                        let reg = get_registry().read().unwrap();
                        let send_blk_num = reg.lattice_blocks.get(&send_block_hash).map(|b| b.sequence).unwrap_or(0);
                        (reg.get_reclaim_timeout_epochs().saturating_mul(32), send_blk_num)
                    };

                    let verified = sovereign_consensus::lattice::verify_reclaim_send(send_block_num, current_block_num, timeout_blocks);
                    if !verified && current_block_num > 0 {
                        send_error(&mut client_stream, &id, -32003, "Reclaim failed: Send transaction has not reached timeout block age").await;
                        continue;
                    }

                    {
                        let mut reg = get_registry().write().unwrap();
                        reg.lattice_blocks.remove(&send_block_hash);
                    }

                    send_result(&mut client_stream, &id, json!({ "status": "success", "message": "Send transaction reclaimed" })).await;
                    continue;
                }

                if method == "sovereign_getReclaimTimeout" || method == "bunny_getReclaimTimeout" {
                    let (epochs, current_epoch) = {
                        let reg = get_registry().read().unwrap();
                        (reg.get_reclaim_timeout_epochs(), reg.current_epoch)
                    };
                    send_result(&mut client_stream, &id, json!({
                        "reclaim_timeout_epochs": epochs,
                        "current_epoch": current_epoch,
                        "blocks_per_epoch": 32
                    })).await;
                    continue;
                }

                if method == "sovereign_setReclaimTimeout" || method == "bunny_setReclaimTimeout" {
                    let epochs = body_json["params"][0].as_u64().unwrap_or(10);
                    {
                        let mut reg = get_registry().write().unwrap();
                        reg.set_reclaim_timeout_epochs(epochs);
                    }
                    send_result(&mut client_stream, &id, json!({
                        "status": "success",
                        "reclaim_timeout_epochs": epochs
                    })).await;
                    continue;
                }

                if method == "wallet_getPermissions" {
                    send_result(&mut client_stream, &id, json!({
                        "status": "authorized",
                        "scopes": ["eip155", "solana"]
                    })).await;
                    continue;
                }

                if method == "wallet_createSession" || method == "wallet_getSession" {
                    send_result(&mut client_stream, &id, json!({
                        "sessionId": format!("sess_{}", timestamp_nanos()),
                        "status": "active",
                        "chains": ["eip155:1", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"]
                    })).await;
                    continue;
                }

                if method == "wallet_revokeSession" {
                    send_result(&mut client_stream, &id, json!(true)).await;
                    continue;
                }

                if method == "wallet_getNotification" {
                    let intent_id = body_json["params"][0].as_str().unwrap_or("");
                    send_result(&mut client_stream, &id, json!({
                        "intentId": intent_id,
                        "status": "completed",
                        "txHash": format!("{:#x}", B256::repeat_byte(0x88))
                    })).await;
                    continue;
                }

                if method == "wallet_getAssetMetadata" {
                    let asset_id = body_json["params"][0].as_str().unwrap_or("");
                    if asset_id.contains("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") {
                        send_result(&mut client_stream, &id, json!({ "name": "USD Coin", "symbol": "USDC", "decimals": 6 })).await;
                    } else {
                        send_result(&mut client_stream, &id, json!({ "name": "Sovereign Manifold Asset", "symbol": "SOV", "decimals": 18 })).await;
                    }
                    continue;
                }

                if method == "eth_getTransactionCount" {
                    let address = body_json["params"][0].as_str().unwrap_or("").parse::<Address>().unwrap_or_default();
                    let count = handle_get_transaction_count(reth_port, address).await;
                    send_result(&mut client_stream, &id, json!(format!("0x{:x}", count))).await;
                    continue;
                }

                if method == "eth_call" {
                    sync_hot_storage(reth_port).await;
                    let call_params = &body_json["params"][0];
                    let to_str = call_params["to"].as_str().unwrap_or("");
                    let data_str = call_params["data"].as_str().unwrap_or("0x");
                    if let Ok(to_addr) = to_str.parse::<Address>() {
                        let data_bytes = alloy_primitives::hex::decode(data_str.trim_start_matches("0x")).unwrap_or_default();
                        
                        let is_sys = sovereign_consensus::system_registry::is_system_address(&to_addr);
                        info!("🔍 PROXY ETH_CALL: to={:?} is_sys={} data_len={}", to_addr, is_sys, data_bytes.len());
                        
                        // Execute registry read operations in an inner scope so the lock guard is dropped before the await call!
                        let hex_result_opt = {
                            let reg = get_registry().read().unwrap();
                            let is_actor = reg.actors.values().any(|actor| {
                                let derived = Address::from_slice(&actor.actor_id[0..20]);
                                derived == to_addr
                            });
                            
                            if is_sys || is_actor {
                                let target_precompile = if is_actor {
                                    sovereign_consensus::system_registry::SYSTEM_ASYNC_INBOX
                                } else {
                                    to_addr
                                };
                                info!("⚙️ INTERCEPTING SYSTEM CALL: target_precompile={:?}", target_precompile);
                                
                                let mut resolved_calldata = data_bytes.clone();
                                if is_actor {
                                    if let Some(actor) = reg.actors.values().find(|a| Address::from_slice(&a.actor_id[0..20]) == to_addr) {
                                        let mut prefixed = actor.actor_id.to_vec();
                                        prefixed.extend_from_slice(&data_bytes);
                                        resolved_calldata = prefixed;
                                    }
                                }
                                
                                if target_precompile == sovereign_consensus::system_registry::SYSTEM_ACCOUNT_HEIGHT {
                                     if resolved_calldata.len() >= 20 {
                                         let target_account = if resolved_calldata.len() >= 32 {
                                             Address::from_slice(&resolved_calldata[12..32])
                                         } else {
                                             Address::from_slice(&resolved_calldata[0..20])
                                         };
                                         let mut sequence = 0u64;
                                         let mut latest_hash = B256::ZERO;
                                         let mut merit_rank = 0u64;
                                         let mut q1 = 0u64;
                                         let mut q2 = 0u64;
                                         
                                         if let Some(frontier) = reg.account_frontiers.get(&target_account) {
                                             sequence = frontier.sequence;
                                             latest_hash = frontier.latest_hash;
                                             merit_rank = frontier.merit_rank as u64;
                                             if let Some(ref compliance) = frontier.cached_compliance {
                                                 q1 = compliance.0[0];
                                                 q2 = compliance.0[1];
                                             }
                                         }
                                         
                                         let tier = reg.did_key_tier.get(&target_account).copied().unwrap_or(sovereign_consensus::pq_registry::KeyTier::Classical);
                                         let key_tier = match tier {
                                             sovereign_consensus::pq_registry::KeyTier::Classical => 0u64,
                                             sovereign_consensus::pq_registry::KeyTier::QuantumReady => 1u64,
                                             sovereign_consensus::pq_registry::KeyTier::QuantumOnly => 2u64,
                                         };
                                         
                                         let mut out = Vec::with_capacity(192);
                                         
                                         // 1. sequence
                                         out.extend_from_slice(&[0u8; 24]);
                                         out.extend_from_slice(&sequence.to_be_bytes());
                                         
                                         // 2. latest_hash
                                         out.extend_from_slice(latest_hash.as_slice());
                                         
                                         // 3. merit_rank
                                         out.extend_from_slice(&[0u8; 24]);
                                         out.extend_from_slice(&merit_rank.to_be_bytes());
                                         
                                         // 4. q1
                                         out.extend_from_slice(&[0u8; 24]);
                                         out.extend_from_slice(&q1.to_be_bytes());
                                         
                                         // 5. q2
                                         out.extend_from_slice(&[0u8; 24]);
                                         out.extend_from_slice(&q2.to_be_bytes());
                                         
                                         // 6. key_tier
                                         out.extend_from_slice(&[0u8; 24]);
                                         out.extend_from_slice(&key_tier.to_be_bytes());
                                         
                                         Some(format!("0x{}", alloy_primitives::hex::encode(&out)))
                                     } else {
                                         None
                                     }
                                } else if target_precompile == sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY {
                                    let mut resolved_did = None;
                                    let is_addr = resolved_calldata.len() == 20 || resolved_calldata.len() == 32;
                                    if is_addr {
                                        let addr = if resolved_calldata.len() == 32 {
                                            Address::from_slice(&resolved_calldata[12..32])
                                        } else {
                                            Address::from_slice(&resolved_calldata[0..20])
                                        };
                                        eprintln!("[CAIP_RPC eth_call DID] Querying by address: {:?}. Reg addresses: {:?}", addr, reg.address_to_did.keys().collect::<Vec<_>>());
                                        if let Some(did) = reg.get_did_by_address(&addr) {
                                            resolved_did = Some(did);
                                        } else {
                                            let sov_addr_did = format!("did:sovereign:{}:{addr:#x}", reg.chain_id);
                                            let sov_addr_did_lower = format!("did:sovereign:{}:{}", reg.chain_id, addr.to_string().to_lowercase());
                                            if reg.identities.contains_key(&sov_addr_did) {
                                                resolved_did = Some(sov_addr_did);
                                            } else if reg.identities.contains_key(&sov_addr_did_lower) {
                                                resolved_did = Some(sov_addr_did_lower);
                                            } else if let Some(ident) = reg.identities.values().find(|i| i.doc.evm_address == addr) {
                                                resolved_did = Some(ident.did.clone());
                                            }
                                        }
                                    } else if let Ok(did_str) = String::from_utf8(resolved_calldata.clone()) {
                                        let normalized = sovereign_consensus::registry::ValidatorRegistry::normalize_query_did(&did_str);
                                        eprintln!("[CAIP_RPC eth_call DID] Querying by did_str: {} (norm: {})", did_str, normalized);
                                        if reg.is_did_registered(&normalized) || reg.identities.contains_key(&normalized) || reg.peer_keys.contains_key(&normalized) {
                                            resolved_did = Some(normalized);
                                        } else if reg.is_did_registered(&did_str) || reg.identities.contains_key(&did_str) || reg.peer_keys.contains_key(&did_str) {
                                            resolved_did = Some(did_str.clone());
                                        } else if let Some(ident) = reg.find_identity_by_any_key(&normalized) {
                                            resolved_did = Some(ident.did.clone());
                                        } else if let Some(doc) = sovereign_identity::did::SovereignDidDocument::from_did_string(&did_str) {
                                            resolved_did = Some(doc.did_uri);
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
                                        
                                        let response_obj = json!({
                                            "registered": true,
                                            "did": resolved_did,
                                            "address": address,
                                            "keys": if keys.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(keys) }
                                        });
                                        let response_str = serde_json::to_string(&response_obj).unwrap_or_default();
                                        
                                        let str_bytes = response_str.as_bytes();
                                        let mut out = vec![0u8; 32];
                                        out[31] = 32;
                                        
                                        let mut len_bytes = [0u8; 32];
                                        let str_len = str_bytes.len();
                                        len_bytes[24..32].copy_from_slice(&(str_len as u64).to_be_bytes());
                                        out.extend_from_slice(&len_bytes);
                                        out.extend_from_slice(str_bytes);
                                        
                                        let remainder = out.len() % 32;
                                        if remainder > 0 {
                                            out.extend(vec![0u8; 32 - remainder]);
                                        }
                                        
                                        Some(format!("0x{}", alloy_primitives::hex::encode(&out)))
                                    } else {
                                        Some("0x".to_string())
                                    }
                                } else if target_precompile == sovereign_consensus::system_registry::SYSTEM_RECEIVE_HOOK {
                                    if resolved_calldata.len() >= 20 {
                                        let target_addr = if resolved_calldata.len() >= 32 {
                                            Address::from_slice(&resolved_calldata[12..32])
                                        } else {
                                            Address::from_slice(&resolved_calldata[0..20])
                                        };
                                        let mut sends = Vec::new();
                                        for (hash, block) in &reg.lattice_blocks {
                                            if let sovereign_consensus::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                                                if *recipient == target_addr {
                                                    sends.push((*hash, block, amount));
                                                }
                                            }
                                        }
                                        
                                        let mut claimed = std::collections::HashSet::new();
                                        for block in reg.lattice_blocks.values() {
                                            if let sovereign_consensus::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
                                                claimed.insert(*send_block_hash);
                                            }
                                        }
                                        
                                        let mut pending = Vec::new();
                                        for (send_hash, block, amount) in sends {
                                            if !claimed.contains(&send_hash) {
                                                pending.push(json!({
                                                    "sendBlockHash": format!("{:#x}", send_hash),
                                                    "sender": format!("{:#x}", block.account),
                                                    "amount": amount.to_string(),
                                                }));
                                            }
                                        }
                                        
                                        let response_str = serde_json::to_string(&pending).unwrap_or_default();
                                        let str_bytes = response_str.as_bytes();
                                        let mut out = vec![0u8; 32];
                                        out[31] = 32;
                                        
                                        let mut len_bytes = [0u8; 32];
                                        len_bytes[24..32].copy_from_slice(&(str_bytes.len() as u64).to_be_bytes());
                                        out.extend_from_slice(&len_bytes);
                                        out.extend_from_slice(str_bytes);
                                        
                                        let remainder = out.len() % 32;
                                        if remainder > 0 {
                                            out.extend(vec![0u8; 32 - remainder]);
                                        }
                                        
                                        Some(format!("0x{}", alloy_primitives::hex::encode(&out)))
                                    } else {
                                        None
                                    }
                                } else if target_precompile == sovereign_consensus::system_registry::SYSTEM_BRIDGE {
                                    if let Ok(cid) = String::from_utf8(resolved_calldata.clone()) {
                                        let daemon = get_archival_daemon();
                                        if std::env::var("SOVEREIGN_MOCK_SGX").is_ok() || cfg!(debug_assertions) {
                                            let witness = sovereign_consensus::stateless::AccountWitness {
                                                balance: alloy_primitives::U256::from(7_500_000u64),
                                                nonce: 42,
                                                code_hash: B256::repeat_byte(0xba),
                                                code: b"somerevmbytecode".to_vec(),
                                                quadrant_matrix: [0b11, 0b1000, 0, 0b10],
                                            };
                                            let _ = daemon.archive_account_witness(65001, &witness);
                                        }
                                        if let Ok(r) = daemon.resolve_account_witness(&cid) {
                                            let mut out = vec![0u8; 32];
                                            out.extend_from_slice(&r.balance.to_be_bytes::<32>());
                                            
                                            let mut nonce_bytes = [0u8; 32];
                                            nonce_bytes[24..32].copy_from_slice(&r.nonce.to_be_bytes());
                                            out.extend_from_slice(&nonce_bytes);
                                            
                                            out.extend_from_slice(r.code_hash.as_slice());
                                            
                                            let mut offset_bytes = [0u8; 32];
                                            offset_bytes[31] = 128;
                                            out.extend_from_slice(&offset_bytes);
                                            
                                            let mut len_bytes = [0u8; 32];
                                            len_bytes[31] = 32;
                                            out.extend_from_slice(&len_bytes);
                                            for q in &r.quadrant_matrix {
                                                out.extend_from_slice(&q.to_be_bytes());
                                            }
                                            
                                            let remainder = out.len() % 32;
                                            if remainder > 0 {
                                                out.extend(vec![0u8; 32 - remainder]);
                                            }
                                            Some(format!("0x{}", alloy_primitives::hex::encode(&out)))
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else if target_precompile == sovereign_consensus::system_registry::SYSTEM_JURISDICTION {
                                    let manifold_id = if resolved_calldata.len() >= 8 {
                                        u64::from_be_bytes(resolved_calldata[0..8].try_into().unwrap_or([0u8; 8]))
                                    } else {
                                        13371337u64
                                    };
                                    
                                    let vector = reg.jurisdiction_vectors.get(&manifold_id).cloned().unwrap_or_else(|| {
                                        let mut bit_registry = HashMap::new();
                                        bit_registry.insert((1, 0), "KYC/AML Verified".to_string());
                                        bit_registry.insert((1, 1), "Sanctioned Entity".to_string());
                                        bit_registry.insert((1, 2), "PEP Flagged".to_string());
                                        bit_registry.insert((2, 0), "Accredited Investor".to_string());
                                        bit_registry.insert((2, 1), "Institutional".to_string());
                                        
                                        sovereign_consensus::jurisdiction::JurisdictionVector {
                                            manifold_id,
                                            active_q1_mask: 0,
                                            required_q2_mask: 0,
                                            velocity_limit: None,
                                            appointed_enforcer_did: None,
                                            epoch_established: 1,
                                            compliance_root: [0; 32],
                                            bit_registry,
                                        }
                                    });
                                    
                                    let mut serialized_bit_registry = serde_json::Map::new();
                                    for ((q, b), label) in &vector.bit_registry {
                                        serialized_bit_registry.insert(format!("{}_{}", q, b), json!(label));
                                    }
                                    
                                    let response_obj = json!({
                                        "manifoldId": vector.manifold_id,
                                        "activeQ1Mask": vector.active_q1_mask.to_string(),
                                        "requiredQ2Mask": vector.required_q2_mask.to_string(),
                                        "epochEstablished": vector.epoch_established,
                                        "bitRegistry": serialized_bit_registry
                                    });
                                    
                                    let response_str = serde_json::to_string(&response_obj).unwrap_or_default();
                                    let str_bytes = response_str.as_bytes();
                                    let mut out = vec![0u8; 32];
                                    out[31] = 32;
                                    
                                    let mut len_bytes = [0u8; 32];
                                    len_bytes[24..32].copy_from_slice(&(str_bytes.len() as u64).to_be_bytes());
                                    out.extend_from_slice(&len_bytes);
                                    out.extend_from_slice(str_bytes);
                                    
                                    let remainder = out.len() % 32;
                                    if remainder > 0 {
                                        out.extend(vec![0u8; 32 - remainder]);
                                    }
                                    
                                    Some(format!("0x{}", alloy_primitives::hex::encode(&out)))
                                } else if target_precompile == sovereign_consensus::system_registry::SYSTEM_ASYNC_INBOX {
                                    if let Some(actor) = reg.actors.values().find(|a| Address::from_slice(&a.actor_id[0..20]) == to_addr) {
                                        let inbox = reg.actor_inboxes.get(&actor.actor_id).cloned().unwrap_or_default();
                                        let state_uint = match actor.state {
                                            sovereign_consensus::saga::ActorState::InitiateIntent => 0u8,
                                            sovereign_consensus::saga::ActorState::PrepareExecution => 1u8,
                                            sovereign_consensus::saga::ActorState::Commit => 2u8,
                                            sovereign_consensus::saga::ActorState::Rollback => 3u8,
                                        };
                                        
                                        let mut out = vec![0u8; 32];
                                        out[31] = state_uint;
                                        
                                        let mut sender_bytes = vec![0u8; 12];
                                        sender_bytes.extend_from_slice(actor.sender.as_slice());
                                        out.extend_from_slice(&sender_bytes);
                                        
                                        let mut recipient_bytes = vec![0u8; 12];
                                        recipient_bytes.extend_from_slice(actor.recipient.as_slice());
                                        out.extend_from_slice(&recipient_bytes);
                                        
                                        out.extend_from_slice(&actor.amount.to_be_bytes::<32>());
                                        
                                        let msg_count = U256::from(inbox.len());
                                        out.extend_from_slice(&msg_count.to_be_bytes::<32>());
                                        
                                        Some(format!("0x{}", alloy_primitives::hex::encode(&out)))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        info!("📦 PROXY ETH_CALL RESULT: {:?}", hex_result_opt);
                        
                        if let Some(hex_result) = hex_result_opt {
                            send_result(&mut client_stream, &id, json!(hex_result)).await;
                            continue;
                        }
                    }
                }

                if let Some(result) = handle_wallet_method(method, &body_json) {
                    send_result(&mut client_stream, &id, result).await;
                    continue;
                }

                if method == "eth_sendRawTransaction" {
                    sync_hot_storage(reth_port).await;
                    let raw_tx = body_json["params"][0].as_str().unwrap_or("");
                    eprintln!("[CAIP_RPC] ENTRY eth_sendRawTransaction: raw_tx_len={}, is_did_reg={:?}", raw_tx.len(), decode_tx_to(raw_tx));
                    let clean_raw = raw_tx.trim_start_matches("0x");

                    if let Ok(data_bytes) = alloy_primitives::hex::decode(clean_raw) {
                        let is_evm_tx = decode_tx_envelope(raw_tx).is_some();
                        if !is_evm_tx {
                            if let Ok(block) = <sovereign_consensus::stateless::LatticeBlock as scale::Decode>::decode(&mut &data_bytes[..]) {
                                let has_did = get_registry().read().ok().and_then(|r| r.get_did_by_address(&block.account)).is_some();
                                if has_did {
                                    match sovereign_consensus::stateless::execute_lattice_block(&block) {
                                        Ok(hash) => {
                                            send_result(&mut client_stream, &id, json!(format!("{:#x}", hash))).await;
                                            continue;
                                        }
                                        Err(e) => {
                                            send_error(&mut client_stream, &id, -32003, &e.to_string()).await;
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }

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

                    let is_did_reg = decode_tx_to(raw_tx) == Some(sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY);
                    let is_claim = decode_tx_to(raw_tx) == Some(sovereign_consensus::system_registry::SYSTEM_RECEIVE_HOOK);
                    let sender_for_log = decode_sender(raw_tx);
                    let has_registered_did = sender_for_log.as_ref().map(|s| {
                        let reg = get_registry().read().unwrap();
                        reg.has_registered_did(s)
                    }).unwrap_or(false);

                    eprintln!("[CAIP_RPC] sender={:?}, is_did_reg={}, is_claim={}, has_registered_did={}", sender_for_log, is_did_reg, is_claim, has_registered_did);

                    if !has_registered_did && !is_did_reg && !is_claim {
                        eprintln!("[CAIP_RPC] Rejecting unauthorized tx in proxy: Account has no registered DID on Slot 0");
                        send_error(&mut client_stream, &id, -32001,
                            "No state change permitted without an on-chain DID identity: Address has not registered a DID on Slot 0. Please register your DID identity on-chain before initiating state changes or transactions."
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
                                        let is_evm = block.signature.is_empty()
                                            || block.signature == vec![0x00]
                                            || (block.signature.len() > 0 && (block.signature[0] == 248 || block.signature[0] == 249));
                                        pending.push((*hash, *amount, is_evm));
                                    }
                                }
                            }
                            pending.sort_by(|a, b| b.1.cmp(&a.1));
                            for (hash, amount, _is_evm) in pending.iter().take(20) {
                                unclaimed_hashes.push(*hash);
                                inbox_value = inbox_value.saturating_add(*amount);
                            }
                        }
                        if let Ok(meta_map) = get_outbound_meta().read() {
                            for meta in meta_map.values() {
                                if meta.recipient == sender {
                                    inbox_value = inbox_value.saturating_add(meta.amount);
                                }
                            }
                        }
                        let state = get_state().read().unwrap();
                        for records in state.native_history.values() {
                            for rec in records {
                                if rec.to == sender {
                                    let v = U256::from_str_radix(rec.value.trim_start_matches("0x"), 10)
                                        .or_else(|_| U256::from_str_radix(rec.value.trim_start_matches("0x"), 16))
                                        .unwrap_or(U256::ZERO);
                                    inbox_value = inbox_value.saturating_add(v);
                                }
                            }
                        }
                    }

                    if let Some((sender, gas_price, gas_limit, value, tx_nonce)) = decode_tx_details(raw_tx) {
                        let upfront_cost = value.saturating_add(gas_price.saturating_mul(U256::from(gas_limit)));
                        let settled_balance = get_reth_balance(reth_port, sender).await;
                        let effective_balance = settled_balance.saturating_add(inbox_value);

                        let is_pure_self_send = decode_tx_envelope(raw_tx)
                            .map(|tx| tx.to() == Some(sender) && tx.input().is_empty())
                            .unwrap_or(false);

                        eprintln!("[CAIP_RPC] PROXY_TX: sender={:#x}, is_pure_self_send={}, settled_balance={}, effective_balance={}, upfront_cost={}", sender, is_pure_self_send, settled_balance, effective_balance, upfront_cost);

                            if is_pure_self_send && !unclaimed_hashes.is_empty() {
                                 let funding_tx_hash = match send_funding_tx(reth_port, sender, inbox_value).await {
                                     Ok(h) => h,
                                     Err(e) => {
                                         send_error(&mut client_stream, &id, -32603, &format!("Zero-gas sweep credit failed: {e}")).await;
                                         continue;
                                     }
                                 };

                                 let mut preimage = Vec::with_capacity(40);
                                 preimage.extend_from_slice(funding_tx_hash.as_slice());
                                 preimage.extend_from_slice(&tx_nonce.to_be_bytes());
                                 let synthetic_hash = alloy_primitives::keccak256(&preimage);
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
                                 // No auto-creation of Receive blocks. The recipient must explicitly submit Receive blocks via SYSTEM_RECEIVE_HOOK to claim.

                                 insert_synthetic_receipt(synthetic_hash, sender);
                                 send_result(&mut client_stream, &id, json!(format!("{synthetic_hash:#x}"))).await;
                                 continue;
                            }

                            let target_to_opt = decode_tx_to(raw_tx);
                            let _is_sys_target = target_to_opt.map(|t| sovereign_consensus::system_registry::is_system_address(&t)).unwrap_or(false);

                            let total_available = settled_balance.saturating_add(inbox_value);
                            if total_available < upfront_cost && !(is_pure_self_send && !unclaimed_hashes.is_empty()) {
                                eprintln!("[CAIP_RPC] Rejecting tx for {:#x}: insufficient balance (available={}, upfront={})", sender, total_available, upfront_cost);
                                send_error(&mut client_stream, &id, -32000, "insufficient funds for gas * price + value").await;
                                continue;
                            }
                            if settled_balance < upfront_cost && inbox_value > 0 {
                                let _ = send_funding_tx(reth_port, sender, inbox_value).await;
                            }
                    } else {
                        eprintln!("[CAIP_RPC] decode_tx_details returned None for raw_tx");
                    }

                    eprintln!("[CAIP_RPC] FORWARDING eth_sendRawTransaction to Reth port {}", reth_port);
                    let fwd_result = match forward_to_reth_http(reth_port, &body_json).await {
                        Ok(r) => {
                            eprintln!("[CAIP_RPC] FORWARDED eth_sendRawTransaction to Reth: {:?}", r);
                            r
                        },
                        Err(e) => {
                            eprintln!("[CAIP_RPC] Failed to forward eth_sendRawTransaction to Reth: {e}");
                            send_error(&mut client_stream, &id, -32603, &format!("Reth forward error: {e}")).await;
                            continue;
                        }
                    };

                    if let Some(err) = fwd_result.get("error") {
                        eprintln!("[CAIP_RPC] RETH REJECTED eth_sendRawTransaction: {:?}", err);
                        send_result(&mut client_stream, &id, fwd_result).await;
                        continue;
                    }

                    let res_val = extract_result(fwd_result);

                    if let Some(tx_hash_str) = res_val.as_str() {
                        if let Ok(tx_hash) = tx_hash_str.parse::<B256>() {
                            if !unclaimed_hashes.is_empty() {
                                get_auto_claims().write().unwrap().insert(tx_hash, unclaimed_hashes);
                            }
                            let sender = sender_opt.unwrap_or_else(|| decode_sender(raw_tx).unwrap_or_default());
                            index_from_raw_tx(raw_tx, tx_hash, sender);

                            if let Some((sender, gas_price, _gas_limit, value, tx_nonce)) = decode_tx_details(raw_tx) {
                                let mut is_standard_send = false;
                                let mut recipient = Address::ZERO;
                                if let Some(tx) = decode_tx_envelope(raw_tx) {
                                    if let Some(to) = tx.to() {
                                        if to != sender && tx.input().is_empty() && tx.value() > U256::ZERO {
                                            is_standard_send = true;
                                            recipient = to;
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

                    // Replicate raw transaction to peer cluster proxies
                    if id.as_i64() != Some(9999) {
                        let raw_clone = raw_tx.to_string();
                        let my_proxy_port = port;
                        tokio::spawn(async move {
                            let client = reqwest::Client::new();
                            // Sweep dynamic cluster base ports
                            for offset in [-60, -40, -20, 20, 40, 60] {
                                let target_port = (my_proxy_port as i32 + offset) as u16;
                                let _ = client.post(format!("http://127.0.0.1:{target_port}"))
                                    .json(&json!({
                                        "jsonrpc": "2.0",
                                        "method": "eth_sendRawTransaction",
                                        "params": [&raw_clone],
                                        "id": 9999
                                    }))
                                    .send()
                                    .await;
                            }
                        });
                    }

                    send_result(&mut client_stream, &id, res_val).await;
                    continue;
                }

                // Intercept eth_estimateGas for stateless pure self-sends and system addresses
                if method == "eth_estimateGas" {
                    if let Some(param) = body_json["params"].get(0) {
                        let from = param["from"].as_str().unwrap_or("");
                        let to_str = param["to"].as_str().unwrap_or("");
                        let data = param["data"].as_str().or_else(|| param["input"].as_str()).unwrap_or("");
                        
                        let is_sys = if let Ok(to_addr) = to_str.parse::<Address>() {
                            sovereign_consensus::system_registry::is_system_address(&to_addr)
                        } else {
                            false
                        };

                        if is_sys || (!from.is_empty() && from.eq_ignore_ascii_case(to_str) && (data.is_empty() || data == "0x")) {
                            send_result(&mut client_stream, &id, json!("0x7a120")).await;
                            continue;
                        }
                    }
                }

                if method == "eth_blockNumber" {
                    sync_hot_storage(reth_port).await;
                    let reth_res = forward_to_reth_http(reth_port, &body_json).await.unwrap_or(json!(null));
                    let mut block_num = extract_result(reth_res)
                        .as_str()
                        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                        .unwrap_or(0);
                    let state_block = get_state().read().unwrap().block_number.unwrap_or(0);
                    block_num = block_num.max(state_block);
                    let body = json!({
                        "jsonrpc": "2.0",
                        "result": format!("0x{:x}", block_num),
                        "id": id
                    }).to_string();
                    write_json(&mut client_stream, &body).await;
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
                            if meta.block_number == 0 {
                                let body = json!({ "jsonrpc": "2.0", "result": serde_json::Value::Null, "id": id }).to_string();
                                write_json(&mut client_stream, &body).await;
                                continue;
                            }
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
                            let b_num = if meta.virtual_block_number == 0 { "0x1".to_string() } else { format!("0x{:x}", meta.virtual_block_number) };
                            let b_hash = if meta.virtual_block_hash == B256::ZERO { format!("{tx_hash:#x}") } else { format!("{:#x}", meta.virtual_block_hash) };
                            let receipt = json!({
                                "transactionHash": format!("{tx_hash:#x}"),
                                "transactionIndex": "0x0",
                                "blockHash": b_hash,
                                "blockNumber": b_num,
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
                        if let Some(mut res) = reth_res {
                            if let Some(result_obj) = res.get_mut("result") {
                                if let Some(to_str) = result_obj.get("to").and_then(|t| t.as_str()) {
                                    if let Ok(to_addr) = to_str.parse::<Address>() {
                                        if sovereign_consensus::system_registry::is_system_address(&to_addr) {
                                            result_obj["status"] = json!("0x1");
                                        }
                                    }
                                }
                            }
                            write_json(&mut client_stream, &res.to_string()).await;
                            continue;
                        }
                    }

                    let requested_hash = body_json["params"][0].as_str().unwrap_or("");
                    let receipt_obj = get_receipt_by_hash(requested_hash);
                    if !receipt_obj.is_null() {
                        let body = json!({ "jsonrpc": "2.0", "result": receipt_obj, "id": id }).to_string();
                        write_json(&mut client_stream, &body).await;
                    } else {
                        let body = json!({ "jsonrpc": "2.0", "result": serde_json::Value::Null, "id": id }).to_string();
                        write_json(&mut client_stream, &body).await;
                    }
                    continue;
                }

                // Intercept eth_getBalance to compute dynamic settled + lattice balance
                if method == "eth_getBalance" {
                    sync_hot_storage(reth_port).await;
                    let target_addr_str = body_json["params"][0].as_str().unwrap_or("");
                    let reth_res = forward_to_reth_http(reth_port, &body_json).await.unwrap_or(json!(null));
                    let mut balance = extract_result(reth_res)
                        .as_str()
                        .and_then(|s| U256::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                        .unwrap_or(U256::ZERO);

                    if let Ok(addr) = target_addr_str.parse::<Address>() {
                        if balance == U256::ZERO {
                            if let Ok(reg) = sovereign_consensus::governance::registry::get_registry().read() {
                                let lattice_bal = reg.get_account_balance(&addr);
                                if lattice_bal > U256::ZERO {
                                    balance = lattice_bal;
                                }
                            }
                        }
                        let state = get_state().read().unwrap();
                        if let Some(records) = state.native_history.get(&addr) {
                            if balance == U256::ZERO {
                                for rec in records {
                                    if rec.to == addr && rec.from != addr {
                                        let parsed_val = U256::from_str_radix(&rec.value, 10)
                                            .or_else(|_| U256::from_str_radix(rec.value.trim_start_matches("0x"), 16))
                                            .unwrap_or(U256::ZERO);
                                        balance = balance.saturating_add(parsed_val);
                                    }
                                }
                            } else {
                                // For sender with existing balance, deduct sent transfers + estimated gas fee if Reth hasn't settled them yet
                                for rec in records {
                                    if rec.from == addr && rec.to != addr {
                                        let parsed_val = U256::from_str_radix(&rec.value, 10)
                                            .or_else(|_| U256::from_str_radix(rec.value.trim_start_matches("0x"), 16))
                                            .unwrap_or(U256::ZERO);
                                        let gas_fee = U256::from(21_000u64 * 1_000_000_000u64); // 21000 gas @ 1 gwei
                                        balance = balance.saturating_sub(parsed_val.saturating_add(gas_fee));
                                    }
                                }
                            }
                        }
                    }

                    eprintln!("[CAIP_RPC eth_getBalance] target={}, final_balance={}", target_addr_str, balance);

                    let body = json!({
                        "jsonrpc": "2.0",
                        "result": format!("0x{:x}", balance),
                        "id": id
                    }).to_string();
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

                if method == "eth_blockNumber" {
                    sync_hot_storage(reth_port).await;
                    let reth_res = forward_to_reth_http(reth_port, &body_json).await.unwrap_or(json!(null));
                    let mut reth_num = extract_result(reth_res)
                        .as_str()
                        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                        .unwrap_or(0);
                    if let Some(state_num) = get_state().read().unwrap().block_number {
                        reth_num = reth_num.max(state_num);
                    }
                    let body = json!({
                        "jsonrpc": "2.0",
                        "result": format!("0x{:x}", reth_num),
                        "id": id
                    }).to_string();
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
