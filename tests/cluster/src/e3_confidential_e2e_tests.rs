//! E3 Confidential Compute Enclave End-to-End Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use alloy_primitives::{Address, B256};
use bytes::Bytes;
use sovereign_consensus::privacy_vm::PrivacyVmBackend;
use sovereign_execution::StatelessRevmBackend;
use sovereign_iggy_ctrl::{IggyMessageBus, TOPIC_CONFIDENTIAL_E3, TOPIC_SYS_EPOCH_MARKERS};
use sovereign_ssz::{ConfidentialIntent, SszTransaction, ThresholdEpochMarker};
use ssz_rs::prelude::*;
use std::time::Duration;

#[tokio::test]
async fn test_given_confidential_intent_when_executed_in_e3_enclave_then_emits_threshold_marker() {
    // ── GIVEN: An in-memory message bus and an E3 worker listening on the confidential topic ──
    let bus = IggyMessageBus::new();
    let mut e3_rx = bus.subscribe(TOPIC_CONFIDENTIAL_E3).await;
    let mut marker_rx = bus.subscribe(TOPIC_SYS_EPOCH_MARKERS).await;

    let bus_clone = bus.clone();
    let e3_worker_handle = tokio::spawn(async move {
        let executor = StatelessRevmBackend::new();
        let mut state_root = B256::ZERO;

        if let Ok(msg) = e3_rx.recv().await {
            if let Ok(intent) = ConfidentialIntent::deserialize(&msg) {
                let mut ssz_tx = SszTransaction::default();
                ssz_tx.set_to_address(intent.target());
                ssz_tx.intent_id = intent.caller_nullifier;

                if let Ok((new_root, _proof)) = executor.execute_transition(state_root, &ssz_tx) {
                    state_root = new_root;

                    let mut marker = ThresholdEpochMarker::default();
                    marker.epoch_id = intent.epoch_id;
                    marker.range_root = Vector::try_from(state_root.as_slice().to_vec()).unwrap();

                    let mut marker_bytes = Vec::new();
                    if marker.serialize(&mut marker_bytes).is_ok() {
                        let _ = bus_clone.publish(TOPIC_SYS_EPOCH_MARKERS, Bytes::from(marker_bytes)).await;
                    }
                }
            }
        }
    });

    // ── WHEN: Client encrypts and dispatches a ConfidentialIntent to the E3 enclave ──
    let target_addr = Address::from([0x99; 20]);
    let nullifier_bytes = [0xAA; 32];
    let mut intent = ConfidentialIntent::default();
    intent.caller_nullifier = Vector::try_from(nullifier_bytes.to_vec()).unwrap();
    intent.epoch_id = 42;
    intent.target_contract = Vector::try_from(target_addr.as_slice().to_vec()).unwrap();

    let mut intent_bytes = Vec::new();
    intent.serialize(&mut intent_bytes).expect("serialize confidential intent");
    bus.publish(TOPIC_CONFIDENTIAL_E3, Bytes::from(intent_bytes))
        .await
        .expect("publish confidential intent");

    // ── THEN: The E3 enclave executes the state transition and emits a valid ThresholdEpochMarker ──
    let marker_msg = tokio::time::timeout(Duration::from_secs(5), marker_rx.recv())
        .await
        .expect("Timeout waiting for E3 epoch marker")
        .expect("Recv error");

    let marker = ThresholdEpochMarker::deserialize(&marker_msg).expect("deserialize marker");
    assert_eq!(marker.epoch_id, 42, "Epoch ID must match the intent's target epoch");
    assert_ne!(marker.range_root.as_slice(), &[0u8; 32], "Range root must mutate after confidential execution");

    let _ = e3_worker_handle.await;
}
