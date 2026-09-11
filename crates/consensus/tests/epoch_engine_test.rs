use alloy_primitives::{Address, B256, U256};
use sovereign_consensus::epoch_engine::{
    execute_chandy_lamport_snapshot, finalize_epoch, process_merit_distribution,
};
use sovereign_consensus::jurisdiction::MeritRank;
use sovereign_consensus::registry::ValidatorRegistry;
use sovereign_consensus::stateless::{LatticeBlock, LatticePayload};

#[test]
fn test_merit_distribution_and_promotion() {
    // GIVEN: A registered account with Rank0 merit and reputation score > 0.95
    let mut registry = ValidatorRegistry::default();
    let addr = Address::repeat_byte(0x42);
    let did = "did:sovereign:1337:0x42".to_string();

    let mut frontier = registry.get_or_create_frontier(addr);
    frontier.merit_rank = MeritRank::Rank0;
    frontier.epochs_at_current_rank = 3; // Satisfy MERIT_RANK_COOLDOWN_EPOCHS
    registry.update_frontier(addr, frontier);

    registry.address_to_did.insert(addr, did.clone());
    registry.reputation.insert(did, 0.95);

    // WHEN: The merit distribution cycle executes for epoch 90
    let epoch_id = 90; // Rank0 interval is 90
    let payouts = process_merit_distribution(&mut registry, epoch_id);

    // THEN: Payout is credited and the account frontier is auto-promoted to Rank4
    assert!(payouts.iter().any(|(a, amt)| *a == addr && *amt > U256::ZERO));

    let updated_frontier = registry.account_frontiers.get(&addr).unwrap();
    assert_eq!(updated_frontier.merit_rank, MeritRank::Rank4);
}

#[test]
fn test_chandy_lamport_snapshot_and_in_flight() {
    // GIVEN: A sender account with an un-claimed lattice send block in flight
    let mut registry = ValidatorRegistry::default();
    let sender = Address::repeat_byte(0x01);
    let recipient = Address::repeat_byte(0x02);

    let mut frontier_sender = registry.get_or_create_frontier(sender);
    frontier_sender.sequence = 5;
    registry.update_frontier(sender, frontier_sender);

    let send_hash = B256::repeat_byte(0xaa);
    let send_block = LatticeBlock {
        account: sender,
        previous_hash: B256::ZERO,
        sequence: 1,
        payload: LatticePayload::Send {
            recipient,
            amount: U256::from(500),
        },
        signature: Vec::new(),
        static_witnesses: Vec::new(),
    };
    registry.lattice_blocks.insert(send_hash, send_block);

    // WHEN: A Chandy-Lamport distributed snapshot executes
    let (states, in_flight) = execute_chandy_lamport_snapshot(&registry);
    assert_eq!(states.get(&sender).copied(), Some(5));
    assert_eq!(in_flight.len(), 1);
    assert_eq!(in_flight[0].sender, sender);
    assert_eq!(in_flight[0].recipient, recipient);
    assert_eq!(in_flight[0].amount, U256::from(500));
    assert_eq!(in_flight[0].send_block_hash, send_hash);

    // Now insert matching receive block
    let recv_hash = B256::repeat_byte(0xbb);
    let recv_block = LatticeBlock {
        account: recipient,
        previous_hash: B256::ZERO,
        sequence: 1,
        payload: LatticePayload::Receive {
            send_block_hash: send_hash,
            amount: U256::from(500),
        },
        signature: Vec::new(),
        static_witnesses: Vec::new(),
    };
    registry.lattice_blocks.insert(recv_hash, recv_block);

    // Snapshot after receive: in-flight is empty
    let (_, in_flight_after) = execute_chandy_lamport_snapshot(&registry);
    assert!(in_flight_after.is_empty());
}

#[test]
fn test_finalize_epoch_creates_checkpoint() {
    // GIVEN: A validator registry with consensus and state roots
    let mut registry = ValidatorRegistry::default();
    let epoch_id = 1;
    let consensus_root = B256::repeat_byte(0x11);
    let state_root = B256::repeat_byte(0x22);

    // WHEN: The epoch is finalized
    let checkpoint = finalize_epoch(&mut registry, epoch_id, consensus_root, state_root);

    // THEN: An immutable EpochCheckpoint is produced and committed to the registry
    assert_eq!(checkpoint.epoch_id, epoch_id);
    assert_eq!(checkpoint.consensus_root, consensus_root);
    assert_eq!(checkpoint.state_root, state_root);
    assert_ne!(checkpoint.snapshot_hash, B256::ZERO);

    let latest = registry.latest_checkpoint.as_ref().unwrap();
    assert_eq!(latest.epoch_id, checkpoint.epoch_id);
    assert_eq!(latest.consensus_root, checkpoint.consensus_root);
    assert_eq!(latest.state_root, checkpoint.state_root);
    assert_eq!(latest.snapshot_hash, checkpoint.snapshot_hash);
}

#[test]
fn test_derive_next_epoch_seed_and_marker() {
    use sovereign_consensus::epoch_engine::{derive_next_epoch_seed, ThresholdEpochMarker};

    // GIVEN: Prior epoch seed and global frontier root
    let seed_0 = B256::repeat_byte(0xaa);
    let root_0 = B256::repeat_byte(0xbb);

    // WHEN: Next epoch entropy seed is derived
    let seed_1 = derive_next_epoch_seed(seed_0, root_0);

    // THEN: Seed is non-zero, mutated, and strictly deterministic
    assert_ne!(seed_1, B256::ZERO);
    assert_ne!(seed_1, seed_0);
    assert_eq!(seed_1, derive_next_epoch_seed(seed_0, root_0));

    let marker = ThresholdEpochMarker {
        epoch_id: 1,
        previous_global_root: root_0,
        target_validator: Address::repeat_byte(0x11),
        issuer_leader: Address::repeat_byte(0x22),
        threshold_signature: vec![0x99; 48],
    };
    assert_eq!(marker.epoch_id, 1);
    assert_eq!(marker.target_validator, Address::repeat_byte(0x11));
}
