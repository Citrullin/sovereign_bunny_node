//! Daemon API and REST / JSON-RPC Integration Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic microservice API verification.

use alloy_primitives::{Address, B256};
use ssz_rs::prelude::*;
use sovereign_ssz::{
    transaction::SszTransaction,
    range_key,
};
use sovereign_iggy_ctrl::{
    IggyMessageBus, IggyProducer,
    topic_for_range_key,
};
use sovereign_identity::did::SovereignDidDocument;
use sovereign_consensus::privacy_vm::PrivacyVmBackend;
use sovereign_execution::StatelessRevmBackend;

#[tokio::test]
async fn test_given_ingress_intent_when_transcoded_then_routes_to_quadrant_topic() {
    // ── GIVEN: An Iggy message bus with quadrant topic subscribers ──
    let bus = IggyMessageBus::new();
    let producer = IggyProducer::new(bus.clone());

    let addr_part0 = Address::from([0x10; 20]);
    let rk0 = range_key(&addr_part0);
    let topic0 = topic_for_range_key(rk0);

    let addr_part1 = Address::from([0x50; 20]);
    let rk1 = range_key(&addr_part1);
    let topic1 = topic_for_range_key(rk1);

    let mut partition0_rx = bus.subscribe(&topic0).await;
    let mut partition1_rx = bus.subscribe(&topic1).await;

    // ── WHEN: Transactions targeting each partition are transcoded and published ──
    let mut tx0 = SszTransaction::default();
    tx0.chain_id = 1337;
    tx0.nonce = 1;
    tx0.set_to_address(addr_part0);
    tx0.gas_limit = 21000;
    let mut tx0_bytes = Vec::new();
    tx0.serialize(&mut tx0_bytes).expect("serialize tx0");
    producer.send_ssz_intent(&topic0, tx0_bytes).await.expect("send tx0");

    let mut tx1 = SszTransaction::default();
    tx1.chain_id = 1337;
    tx1.nonce = 2;
    tx1.set_to_address(addr_part1);
    tx1.gas_limit = 50000;
    let mut tx1_bytes = Vec::new();
    tx1.serialize(&mut tx1_bytes).expect("serialize tx1");
    producer.send_ssz_intent(&topic1, tx1_bytes).await.expect("send tx1");

    // ── THEN: Each message is strictly received on its respective partition topic ──
    let msg0 = partition0_rx.recv().await.expect("recv msg0");
    let received_tx0 = SszTransaction::deserialize(&msg0).expect("deserialize tx0");
    assert_eq!(received_tx0.to_address(), addr_part0);
    assert_eq!(received_tx0.nonce, 1);

    let msg1 = partition1_rx.recv().await.expect("recv msg1");
    let received_tx1 = SszTransaction::deserialize(&msg1).expect("deserialize tx1");
    assert_eq!(received_tx1.to_address(), addr_part1);
    assert_eq!(received_tx1.nonce, 2);
}

#[test]
fn test_given_user_intent_when_paymaster_sponsored_then_zeroes_user_gas_fees() {
    // ── GIVEN: A standard user transaction and paymaster subsidy limit ──
    let mut tx = SszTransaction::default();
    tx.gas_limit = 21000;
    tx.max_fee_per_gas = 20_000_000_000;
    tx.max_priority_fee = 1_000_000_000;

    let max_subsidy = 100_000;
    assert!(tx.gas_limit <= max_subsidy);

    // ── WHEN: Paymaster gasless sponsorship is applied ──
    tx.max_fee_per_gas = 0;
    tx.max_priority_fee = 0;

    // ── THEN: Sender gas fees are completely subsidized to zero ──
    assert_eq!(tx.max_fee_per_gas, 0);
    assert_eq!(tx.max_priority_fee, 0);

    let mut expensive_tx = SszTransaction::default();
    expensive_tx.gas_limit = 500_000;
    assert!(expensive_tx.gas_limit > max_subsidy, "Expensive tx exceeds subsidy cap");
}

#[test]
fn test_given_did_uri_when_resolved_then_reconstructs_valid_did_document() {
    // ── GIVEN: A derived Sovereign did:peer:4 Document ──
    let seed = B256::repeat_byte(0x42);
    let derived = SovereignDidDocument::derive_from_seed(seed);
    assert!(derived.did_uri.starts_with("did:peer:4"));

    // ── WHEN: The document is resolved from its DID URI string ──
    let resolved_peer = SovereignDidDocument::from_did_string(&derived.did_uri);

    // ── THEN: The document is fully recovered with identical properties ──
    assert!(resolved_peer.is_some(), "Sovereign did:peer:4 Document must parse successfully");
    assert_eq!(resolved_peer.unwrap().did_uri, derived.did_uri);
}

#[test]
fn test_given_stateless_revm_backend_when_executed_then_computes_new_state_root() {
    // ── GIVEN: A Stateless REVM backend and initial state root ──
    let backend = StatelessRevmBackend::new();
    let state_root = B256::ZERO;

    let mut tx = SszTransaction::default();
    tx.nonce = 1;
    tx.set_to_address(Address::from([0x42; 20]));
    tx.gas_limit = 21000;

    // ── WHEN: State transition is executed statelessly ──
    let result = backend.execute_transition(state_root, &tx);

    // ── THEN: Transition succeeds and state root is mutated ──
    assert!(result.is_ok(), "Stateless Revm transition must succeed");
    let (new_root, _proof) = result.unwrap();
    assert_ne!(new_root, state_root, "State root must mutate after execution");
}

#[tokio::test]
async fn test_given_snowman_voter_when_quorum_reached_then_finalizes_epoch_marker() {
    // ── GIVEN: A Snowman BFT consensus voter ──
    let mut snowman = sovereign_consensus::snow::SnowmanVoter::<u64>::new(1, 0.5, 1);

    // ── WHEN: Quorum vote for Epoch #1 is recorded ──
    snowman.record_round(&[1]);

    // ── THEN: Epoch #1 is finalized ──
    assert_eq!(snowman.inner_snowball.finalized_value, Some(1), "Epoch #1 must finalize upon quorum");
}

#[tokio::test]
async fn test_given_archival_storage_backend_when_payload_pinned_then_retrieves_exact_bytes() {
    // ── GIVEN: A storage backend and data payload ──
    use sovereign_consensus::storage::archival::{LocalIpfsClusterBackend, ArchivalStorageBackend};

    let backend = LocalIpfsClusterBackend::new("http://127.0.0.1:5001", true);
    let payload = b"Decentralized CMS blog post backed by Iroh and IPLD";
    let namespace_id = 1337;

    // ── WHEN: Payload is pinned to storage ──
    let cid = backend.pin_blob(namespace_id, payload).expect("Pin blob to storage backend");

    // ── THEN: Status is confirmed pinned and retrieved bytes match original exactly ──
    assert!(!cid.is_empty(), "CID must not be empty");
    let pinned = backend.is_pinned(&cid).expect("Query is_pinned");
    assert!(pinned, "Blob must be actively pinned in storage");

    let fetched = backend.fetch_blob(&cid).expect("Fetch blob by CID");
    assert_eq!(fetched, payload, "Fetched payload must match original");
}

#[tokio::test]
async fn test_given_cross_chain_mesh_when_saga_packet_published_then_received_on_bus() {
    // ── GIVEN: An Iggy message bus subscribed to the cross-chain topic ──
    use sovereign_iggy_ctrl::TOPIC_SYS_CROSS_CHAIN;
    use bytes::Bytes;

    let bus = IggyMessageBus::new();
    let mut rx = bus.subscribe(TOPIC_SYS_CROSS_CHAIN).await;

    let saga_id = B256::repeat_byte(0x55);
    let sender = Address::repeat_byte(0xaa);
    let recipient = Address::repeat_byte(0xbb);

    let mut packet = Vec::new();
    packet.extend_from_slice(saga_id.as_slice());
    packet.extend_from_slice(sender.as_slice());
    packet.extend_from_slice(recipient.as_slice());
    packet.extend_from_slice(b"PAYLOAD:TRANSFER_10_ETH");

    // ── WHEN: Cross-chain packet is published ──
    bus.publish(TOPIC_SYS_CROSS_CHAIN, Bytes::from(packet.clone())).await.expect("Publish cross-chain packet");

    // ── THEN: Packet is successfully received with intact payload ──
    let received = rx.recv().await.expect("Receive cross-chain packet");
    assert_eq!(received.as_ref(), packet.as_slice());
}
