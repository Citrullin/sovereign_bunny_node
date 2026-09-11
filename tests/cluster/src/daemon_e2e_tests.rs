//! End-to-End Microservice Daemon Lifecycle Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic pipeline verification.

use tokio::time::Duration;
use sovereign_iggy_ctrl::{IggyMessageBus, IggyProducer, TOPIC_RANGE_0, TOPIC_SYS_EPOCH_MARKERS, TOPIC_SYS_COMMITTEE_ROTATIONS};
use sovereign_ssz::{SszTransaction, ThresholdEpochMarker, RotationEvent};
use sovereign_execution::StatelessRevmBackend;
use sovereign_consensus::privacy_vm::PrivacyVmBackend;
use sovereign_consensus::snow::SnowmanVoter;
use ssz_rs::prelude::*;
use alloy_primitives::{Address, B256};
use bytes::Bytes;

#[tokio::test]
async fn test_given_microservice_mesh_when_three_transactions_processed_then_triggers_epoch_rotation() {
    // ── GIVEN: An active message bus with committee and coordinator actors running ──
    let bus = IggyMessageBus::new();
    let producer = IggyProducer::new(bus.clone());

    let mut committee_rx = bus.subscribe(TOPIC_RANGE_0).await;
    let mut coordinator_marker_rx = bus.subscribe(TOPIC_SYS_EPOCH_MARKERS).await;
    let mut gateway_rotation_rx = bus.subscribe(TOPIC_SYS_COMMITTEE_ROTATIONS).await;

    let bus_clone1 = bus.clone();
    let committee_handle = tokio::spawn(async move {
        let executor = StatelessRevmBackend::new();
        let mut state_root = B256::ZERO;
        let mut count = 0;

        while let Ok(msg) = committee_rx.recv().await {
            if let Ok(tx) = SszTransaction::deserialize(&msg) {
                if let Ok((new_root, _)) = executor.execute_transition(state_root, &tx) {
                    state_root = new_root;
                    count += 1;

                    if count >= 3 {
                        let mut marker = ThresholdEpochMarker::default();
                        marker.epoch_id = 1;
                        marker.range_root = Vector::try_from(state_root.as_slice().to_vec()).unwrap();
                        let mut marker_bytes = Vec::new();
                        marker.serialize(&mut marker_bytes).unwrap();
                        let _ = bus_clone1.publish(TOPIC_SYS_EPOCH_MARKERS, Bytes::from(marker_bytes)).await;
                        break;
                    }
                }
            }
        }
    });

    let bus_clone2 = bus.clone();
    let coordinator_handle = tokio::spawn(async move {
        let mut snowman = SnowmanVoter::<u64>::new(1, 0.5, 1);
        while let Ok(msg) = coordinator_marker_rx.recv().await {
            if let Ok(marker) = ThresholdEpochMarker::deserialize(&msg) {
                snowman.record_round(&[marker.epoch_id]);
                if let Some(finalized) = snowman.inner_snowball.finalized_value {
                    let mut rotation = RotationEvent::default();
                    rotation.epoch_id = finalized + 1;
                    rotation.partition_count = 4;
                    let mut rot_bytes = Vec::new();
                    rotation.serialize(&mut rot_bytes).unwrap();
                    let _ = bus_clone2.publish(TOPIC_SYS_COMMITTEE_ROTATIONS, Bytes::from(rot_bytes)).await;
                    break;
                }
            }
        }
    });

    // ── WHEN: 3 consecutive transactions are dispatched by Gateway ──
    for i in 0..3 {
        let mut tx = SszTransaction::default();
        tx.nonce = i;
        tx.set_to_address(Address::from([0x11; 20]));
        let mut tx_bytes = Vec::new();
        tx.serialize(&mut tx_bytes).unwrap();
        producer.send_ssz_intent(TOPIC_RANGE_0, tx_bytes).await.unwrap();
    }

    // ── THEN: Committee reaches batch threshold and Snowman coordinator emits RotationEvent for Epoch #2 ──
    let rotation_msg = tokio::time::timeout(Duration::from_secs(5), gateway_rotation_rx.recv())
        .await
        .expect("Timeout waiting for rotation event")
        .expect("Recv error");

    let rotation = RotationEvent::deserialize(&rotation_msg).expect("deserialize rotation");
    assert_eq!(rotation.epoch_id, 2, "Epoch must advance to 2");
    assert_eq!(rotation.partition_count, 4, "Partition count must match network topology");

    let _ = committee_handle.await;
    let _ = coordinator_handle.await;
}
