//! Stateless verification routines for lattice claims and timeouts.

use alloy_primitives::B256;
use super::types::ReceiveBlockHeader;

/// Statelessly verify a receiver claim block header using a Verkle witness proof.
pub fn verify_receive_stateless(
    header: &ReceiveBlockHeader,
    root: B256,
) -> bool {
    if root == B256::ZERO {
        return false;
    }
    sovereign_crypto::verify_stateless_proof(&header.verkle_witness_proof).is_ok()
}

/// Validate if a send transaction can be reclaimed by checking the block timeout.
pub fn verify_reclaim_send(
    send_block_number: u64,
    current_block_number: u64,
    timeout_blocks: u64,
) -> bool {
    current_block_number >= send_block_number + timeout_blocks
}
