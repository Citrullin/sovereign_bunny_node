//! # Address Interest Signaling & Guarded Swarm End-to-End Tests
//!
//! Verifies deterministic topic derivation, Cuckoo filter matching in $O(1)$,
//! blinded subscription intents at `SYSTEM_SIGNAL_REGISTRY (0x00...0054)`, and
//! noise-isolated guarded bus communication.

use alloy_primitives::{Address, B256};
use sovereign_consensus::registry::ValidatorRegistry;
use sovereign_consensus::system_contracts::router::execute_system_action;
use sovereign_consensus::system_registry::{SYSTEM_SIGNAL_REGISTRY, SystemAction};
use sovereign_identity::zk_merit::{GovernanceTier, ZkMeritProof};
use sovereign_network::signal_swarm::{GuardedBus, SignalTopicSwarm};
use sovereign_ssz::signal::SignalEnvelope;

#[test]
fn test_address_signaling_and_guarded_swarm_pipeline() {
    let mut registry = ValidatorRegistry::default();
    let monitored_account = Address::repeat_byte(0x55);
    let app_context = b"dao.governance.treasury.notifications";

    // 1. Inscribe Blinded Signal Intent to SYSTEM_SIGNAL_REGISTRY (0x54)
    let topic_id = SignalEnvelope::derive_topic_id(&monitored_account, app_context);
    let cuckoo_root = B256::repeat_byte(0x88);

    let signal_action = SystemAction::SignalInterest {
        topic_id,
        target_address: monitored_account,
        cuckoo_digest: cuckoo_root,
        expiry_epoch: 500,
    };
    let calldata = signal_action.encode();
    execute_system_action(&mut registry, monitored_account, SYSTEM_SIGNAL_REGISTRY, &calldata, 1)
        .expect("Signal interest registration at 0x54");

    // 2. Initialize P2P Signal Topic Swarm
    let swarm = SignalTopicSwarm::default();
    let envelope = SignalEnvelope::new(
        monitored_account,
        app_context,
        cuckoo_root,
        500,
        &[0x77u8; 96],
    );

    let registered_topic = swarm.register_signal(&envelope, "quic://10.0.0.1:4242");
    assert_eq!(registered_topic, topic_id);

    // Verify O(1) matching
    assert!(swarm.should_forward(&monitored_account));
    let random_account = Address::repeat_byte(0x99);
    assert!(!swarm.should_forward(&random_account));

    // 3. Noise-Filtered Guarded Bus Verification
    let dao_merkle_root = B256::repeat_byte(0x44);
    let guarded_bus = GuardedBus::new(GovernanceTier::Contributor, dao_merkle_root);

    // Contributor with valid ZK-Merit proof passes
    let valid_contributor_proof = ZkMeritProof {
        dao_merkle_root,
        blinded_nullifier: ZkMeritProof::compute_nullifier(b"user_salt", &dao_merkle_root, b"devops"),
        claimed_min_score: 750,
        target_tier: GovernanceTier::Contributor,
        proof_bytes: vec![0x01, 0x02, 0x03],
    };

    let msg_hash = guarded_bus.submit_guarded_message(
        &valid_contributor_proof,
        b"Emergency patch proposal for shard 4".to_vec(),
    ).expect("Guarded message submission");
    assert_ne!(msg_hash, B256::ZERO);

    // Public user / spammer without contributor credentials is dropped at the filter plane
    let unauthenticated_proof = ZkMeritProof {
        dao_merkle_root,
        blinded_nullifier: ZkMeritProof::compute_nullifier(b"spam_salt", &dao_merkle_root, b"devops"),
        claimed_min_score: 50,
        target_tier: GovernanceTier::PublicUser,
        proof_bytes: vec![0x01],
    };

    let fail_res = guarded_bus.submit_guarded_message(
        &unauthenticated_proof,
        b"Unsolicited spam payload".to_vec(),
    );
    assert!(fail_res.is_err(), "Unauthenticated noise rejected at filter layer");
}
