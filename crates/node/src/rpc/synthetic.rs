//! Synthetic receipts, outbound metadata, and log enrichment for stateless execution.

use alloy_primitives::{Address, B256};
use serde_json::{json, Value};

use super::memory_state::get_synthetic_tx_hashes;

/// Enriches and injects synthetic transactions into an upstream Reth JSON-RPC block response.
pub fn inject_history_into_block(reth_response: Value, _full_txs: bool) -> Value {
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
            }
        }
    }

    enriched
}

/// Synthesizes an EVM transaction receipt for instant client feedback.
pub fn synthesize_receipt(
    tx_hash: B256,
    from: Address,
    to: Address,
    block_hash: B256,
    block_number: u64,
) -> Value {
    json!({
        "transactionHash": format!("{tx_hash:#x}"),
        "transactionIndex": "0x0",
        "blockHash": format!("{block_hash:#x}"),
        "blockNumber": format!("{block_number:#x}"),
        "from": format!("{from:#x}"),
        "to": format!("{to:#x}"),
        "cumulativeGasUsed": "0x5208",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x0",
        "status": "0x1",
        "logs": [],
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "type": "0x0"
    })
}
