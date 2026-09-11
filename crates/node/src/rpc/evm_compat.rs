//! EVM wallet compatibility layer providing RPC heuristics for Rabby, MetaMask, and EIP-1559.

use alloy_primitives::U256;

/// Normalizes standard EVM block parameter strings (`"latest"`, `"0x1"`, etc.).
pub fn normalize_block_param(param: &str) -> String {
    match param {
        "latest" | "earliest" | "pending" | "safe" | "finalized" => param.to_string(),
        hex if hex.starts_with("0x") => {
            let digits = hex.trim_start_matches("0x").trim_start_matches('0');
            if digits.is_empty() {
                "0x0".to_string()
            } else {
                format!("0x{digits}")
            }
        }
        other => other.to_string(),
    }
}

/// Standardized gas estimate for account-lattice and EVM state transitions.
pub fn standard_gas_estimate(data_len: usize) -> &'static str {
    if data_len > 0 {
        "0x186a0" // 100,000 gas for contract interactions
    } else {
        "0x5208"  // 21,000 gas for simple value transfers
    }
}

/// Checks if an incoming transaction value exceeds the available balance and requires zero-gas funding heuristics.
pub fn requires_gas_sponsor(current_balance: U256, required_amount: U256) -> bool {
    current_balance < required_amount
}
