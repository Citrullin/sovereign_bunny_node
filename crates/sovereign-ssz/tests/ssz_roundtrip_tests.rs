use ssz_rs::prelude::*;
use sovereign_ssz::{
    SszTransaction, ConfidentialIntent, ThresholdEpochMarker,
};
use alloy_primitives::{Address, B256};

#[test]
fn test_ssz_transaction_roundtrip() {
    let mut tx = SszTransaction::default();
    tx.chain_id = 1337;
    tx.nonce = 42;
    tx.gas_limit = 21000;
    let target = Address::from([0x77; 20]);
    tx.set_to_address(target);

    // Serialize
    let mut encoded = Vec::new();
    tx.serialize(&mut encoded).expect("serialize tx");
    assert!(!encoded.is_empty());

    // Deserialize
    let decoded = SszTransaction::deserialize(&encoded).expect("deserialize tx");
    assert_eq!(decoded.chain_id, 1337);
    assert_eq!(decoded.nonce, 42);
    assert_eq!(decoded.to_address(), target);
}

#[test]
fn test_threshold_epoch_marker_roundtrip() {
    let mut marker = ThresholdEpochMarker::default();
    marker.epoch_id = 100;
    marker.range_start = 0x0000;
    marker.range_end = 0x3FFF;
    marker.range_root = Vector::try_from(vec![0xAA; 32]).unwrap();
    marker.threshold_bls_signature = Vector::try_from(vec![0xBB; 96]).unwrap();

    let mut encoded = Vec::new();
    marker.serialize(&mut encoded).expect("serialize marker");

    let decoded = ThresholdEpochMarker::deserialize(&encoded).expect("deserialize marker");
    assert_eq!(decoded.epoch_id, 100);
    assert_eq!(decoded.range_start, 0x0000);
    assert_eq!(decoded.range_end, 0x3FFF);
}

#[test]
fn test_confidential_intent_roundtrip() {
    let mut intent = ConfidentialIntent::default();
    intent.epoch_id = 5;
    intent.caller_nullifier = Vector::try_from(vec![0x01; 32]).unwrap();
    intent.target_contract = Vector::try_from(vec![0x02; 20]).unwrap();

    let mut encoded = Vec::new();
    intent.serialize(&mut encoded).expect("serialize intent");

    let decoded = ConfidentialIntent::deserialize(&encoded).expect("deserialize intent");
    assert_eq!(decoded.epoch_id, 5);
    assert_eq!(decoded.nullifier(), B256::from([0x01; 32]));
}
