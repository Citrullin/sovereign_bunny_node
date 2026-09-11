//! Receipt Simulator for Precompile Bytecode Transactions.
//!
//! Synthesizes standard EVM transaction receipts for calls executed directly
//! by the node's low-entropy precompiles in RAM without requiring full Reth L1 mining.

use alloy_primitives::{Address, B256};
use serde_json::json;

/// Constructs a synthetic standard EVM transaction receipt for a precompile call.
pub fn build_synthetic_precompile_receipt(
    tx_hash: B256,
    from: Address,
    to: Address,
    block_number: u64,
) -> serde_json::Value {
    json!({
        "transactionHash": format!("0x{}", alloy_primitives::hex::encode(tx_hash)),
        "transactionIndex": "0x1",
        "blockHash": format!("0x{}", alloy_primitives::hex::encode(B256::repeat_byte(0xaa))),
        "blockNumber": format!("0x{:x}", block_number),
        "from": format!("0x{}", alloy_primitives::hex::encode(from)),
        "to": format!("0x{}", alloy_primitives::hex::encode(to)),
        "cumulativeGasUsed": "0x5208",
        "gasUsed": "0x5208",
        "contractAddress": serde_json::Value::Null,
        "logs": [],
        "logsBloom": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "status": "0x1",
        "effectiveGasPrice": "0x3b9aca00",
        "type": "0x2"
    })
}
