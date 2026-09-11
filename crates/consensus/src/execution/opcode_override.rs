//! # EVM Opcode Overrides and Precompiles inside the zkEVM Frame
//!
//! Remaps standard environmental opcodes (NUMBER, TIMESTAMP) to global consensus epochs,
//! and exposes local account height via a dedicated precompile.

use alloy_primitives::{Address, B256, Bytes, U256};
use crate::registry::ValidatorRegistry;

/// Remaps EVM block.number to the Global Network Epoch.
pub fn override_block_number(epoch: u64) -> U256 {
    U256::from(epoch)
}

/// Remaps EVM block.timestamp to the Global Epoch start time.
pub fn override_block_timestamp(epoch_start_unix: u64) -> U256 {
    U256::from(epoch_start_unix)
}

/// Executes the SYSTEM_ACCOUNT_HEIGHT precompile (0x00...0100).
/// Returns the local sequence height (Account Height) of the given address.
///
/// # Errors
/// Returns an error if the input length is invalid.
pub fn run_account_height_precompile(
    registry: &ValidatorRegistry,
    input: &[u8],
) -> Result<Bytes, &'static str> {
    if input.len() < 20 {
        return Err("Input must be at least 20 bytes representing an Address");
    }
    let target = Address::from_slice(&input[0..20]);
    
    let mut sequence = 0u64;
    let mut latest_hash = B256::ZERO;
    let mut merit_rank = 0u64;
    let mut q1 = 0u64;
    let mut q2 = 0u64;
    
    if let Some(frontier) = registry.account_frontiers.get(&target) {
        sequence = frontier.sequence;
        latest_hash = frontier.latest_hash;
        merit_rank = frontier.merit_rank as u64;
        if let Some(ref compliance) = frontier.cached_compliance {
            q1 = compliance.0[0];
            q2 = compliance.0[1];
        }
    }
    
    let tier = registry.did_key_tier.get(&target).copied().unwrap_or(crate::pq_registry::KeyTier::Classical);
    let key_tier = match tier {
        crate::pq_registry::KeyTier::Classical => 0u64,
        crate::pq_registry::KeyTier::QuantumReady => 1u64,
        crate::pq_registry::KeyTier::QuantumOnly => 2u64,
    };
    
    let mut out = Vec::with_capacity(192);
    
    // 1. sequence (uint64, padded to 32 bytes)
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&sequence.to_be_bytes());
    
    // 2. latest_hash (bytes32, 32 bytes)
    out.extend_from_slice(latest_hash.as_slice());
    
    // 3. merit_rank (uint64, padded to 32 bytes)
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&merit_rank.to_be_bytes());
    
    // 4. q1 (uint64, padded to 32 bytes)
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&q1.to_be_bytes());
    
    // 5. q2 (uint64, padded to 32 bytes)
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&q2.to_be_bytes());
    
    // 6. key_tier (uint64, padded to 32 bytes)
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&key_tier.to_be_bytes());
    
    Ok(Bytes::from(out))
}
