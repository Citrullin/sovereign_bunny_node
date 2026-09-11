//! CAIP-2 / CAIP-10 and DID resolution handlers for JSON-RPC.

use alloy_primitives::Address;
use serde_json::{json, Value};
use sovereign_identity::did::SovereignDidDocument;

use super::caip_types::{Caip10AccountId, Caip2ChainId};

/// Resolves a W3C DID into a complete DID document with verification methods.
pub fn handle_caip_resolve_did(params: &Value) -> Value {
    let did_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return json!({
                "jsonrpc": "2.0",
                "error": { "code": -32602, "message": "Missing required 'did' parameter" },
                "id": null
            })
        }
    };

    match SovereignDidDocument::from_did_string(did_str) {
        Some(doc) => json!({
            "jsonrpc": "2.0",
            "result": {
                "did": doc.did_uri,
                "shortForm": doc.short_form,
                "evmAddress": format!("{:#x}", doc.evm_address),
                "authorityPath": doc.authority_path,
            },
            "id": 1
        }),
        None => json!({
            "jsonrpc": "2.0",
            "error": { "code": -32000, "message": format!("DID resolution failed for {did_str}") },
            "id": 1
        }),
    }
}

/// Converts an Ethereum address to a canonical CAIP-10 Account ID.
pub fn handle_caip_to_account_id(params: &Value, chain_id: u64) -> Value {
    let addr_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return json!({
                "jsonrpc": "2.0",
                "error": { "code": -32602, "message": "Missing address parameter" },
                "id": null
            })
        }
    };

    let clean = addr_str.strip_prefix("0x").unwrap_or(addr_str);
    match clean.parse::<Address>() {
        Ok(addr) => {
            let caip10 = Caip10AccountId {
                chain_id: Caip2ChainId {
                    namespace: "eip155".to_string(),
                    reference: chain_id.to_string(),
                },
                address: format!("{addr:#x}"),
            };
            json!({
                "jsonrpc": "2.0",
                "result": caip10.to_string(),
                "id": 1
            })
        }
        Err(_) => json!({
            "jsonrpc": "2.0",
            "error": { "code": -32602, "message": "Invalid Ethereum address format" },
            "id": 1
        }),
    }
}
