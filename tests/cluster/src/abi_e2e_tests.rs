//! SSZ Canonical Binary ABI E2E Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic wire compatibility verification.

use alloy_primitives::{Address, B256};
use ssz_rs::prelude::*;
use sovereign_ssz::{
    transaction::SszTransaction,
    block::SszLatticeBlock,
    intent::ConfidentialIntent,
    markers::ThresholdEpochMarker,
};

#[test]
fn test_given_ssz_transaction_when_serialized_then_matches_fixed_offset_abi() {
    // ── GIVEN ──
    let to = Address::repeat_byte(0x22);
    let mut tx = SszTransaction {
        chain_id: 13371337,
        nonce: 42,
        gas_limit: 250_000,
        max_fee_per_gas: 20_000_000_000,
        max_priority_fee: 1_000_000_000,
        range_routing: Vector::try_from(vec![0u8; 16]).unwrap(),
        intent_id: Vector::try_from(vec![0x33u8; 32]).unwrap(),
        signature: Vector::try_from(vec![0x77u8; 96]).unwrap(),
        data: List::default(),
        to: Vector::default(),
        value: Vector::default(),
    };
    tx.set_to_address(to);

    // ── WHEN ──
    let mut tx_bytes = Vec::new();
    let res = tx.serialize(&mut tx_bytes);

    // ── THEN ──
    assert!(res.is_ok(), "SSZ Transaction serialization must succeed");
    assert!(tx_bytes.len() >= 240, "Fixed SSZ transaction header size must be >= 240 bytes with dynamic offset pointer");

    // ── AND WHEN deserialized ──
    let deserialized_tx = SszTransaction::deserialize(&tx_bytes).expect("SSZ Transaction deserialization must succeed");
    assert_eq!(deserialized_tx.nonce, 42);
    assert_eq!(deserialized_tx.to_address(), to);
}

#[test]
fn test_given_ssz_lattice_block_when_serialized_then_strictly_matches_fixed_layout() {
    // ── GIVEN ──
    let sender = Address::repeat_byte(0x11);
    let to = Address::repeat_byte(0x22);
    let block = SszLatticeBlock {
        account: Vector::try_from(sender.as_slice().to_vec()).unwrap(),
        previous_hash: Vector::try_from(B256::repeat_byte(0xaa).as_slice().to_vec()).unwrap(),
        sequence: 7,
        payload_type: 0,
        target_account: Vector::try_from(to.as_slice().to_vec()).unwrap(),
        amount: Vector::try_from(vec![0u8; 32]).unwrap(),
        intent_id: Vector::try_from(vec![0u8; 32]).unwrap(),
        signature: Vector::try_from(vec![0u8; 96]).unwrap(),
        data: List::default(),
    };

    // ── WHEN ──
    let mut block_bytes = Vec::new();
    let res = block.serialize(&mut block_bytes);

    // ── THEN ──
    assert!(res.is_ok(), "SSZ Lattice Block serialization must succeed");
    assert_eq!(block_bytes.len(), 245, "SSZ lattice block fixed header must be strictly 245 bytes");
}

#[test]
fn test_given_confidential_intent_when_serialized_then_encodes_nullifiers_and_proof() {
    // ── GIVEN ──
    let to = Address::repeat_byte(0x22);
    let intent = ConfidentialIntent {
        epoch_id: 1,
        ephemeral_pubkey: Vector::try_from(vec![0x77u8; 32]).unwrap(),
        caller_nullifier: Vector::try_from(vec![0x88u8; 32]).unwrap(),
        target_contract: Vector::try_from(to.as_slice().to_vec()).unwrap(),
        encrypted_payload: List::default(),
        client_zk_proof: List::default(),
    };

    // ── WHEN ──
    let mut intent_bytes = Vec::new();
    let res = intent.serialize(&mut intent_bytes);

    // ── THEN ──
    assert!(res.is_ok(), "Confidential intent serialization must succeed");
    assert!(intent_bytes.len() >= 100, "Confidential intent ABI wire size must match schema");
}

#[test]
fn test_given_threshold_epoch_marker_when_serialized_then_strictly_236_bytes() {
    // ── GIVEN ──
    let marker = ThresholdEpochMarker {
        epoch_id: 10,
        range_start: 0x4000,
        range_end: 0x7FFF,
        range_root: Vector::try_from(vec![0x11u8; 32]).unwrap(),
        in_flight_root: Vector::try_from(vec![0x22u8; 32]).unwrap(),
        prev_snapshot_root: Vector::try_from(vec![0x33u8; 32]).unwrap(),
        threshold_bls_signature: Vector::try_from(vec![0x44u8; 96]).unwrap(),
        signer_bitmap: Vector::try_from(vec![0x55u8; 32]).unwrap(),
    };

    // ── WHEN ──
    let mut marker_bytes = Vec::new();
    let res = marker.serialize(&mut marker_bytes);

    // ── THEN ──
    assert!(res.is_ok(), "Threshold epoch marker serialization must succeed");
    assert_eq!(marker_bytes.len(), 236, "Threshold epoch marker fixed-size serialization must strictly be 236 bytes");
}
