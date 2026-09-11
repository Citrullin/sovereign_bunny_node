//! # 3-Tier Fractal Account-Lattice & Autonomous Range Sharding Test Suite
//!
//! Validates:
//! 1. Address space segmentation and prefix collision immunity.
//! 2. Autonomous Range SplitBlock on sustained high load (> 85% for 3 epochs).
//! 3. Autonomous Range MergeBlock on quiet period (< 10% for 10 epochs).
//! 4. Localized PID Toxic Velocity Surge Pricing against spam and MEV arbitrage.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use alloy_primitives::{B256, U256, address};
use sovereign_consensus::lattice::range::{
    classify_address, derive_range_meta_address, AddressClassification,
    RangeShardingCoordinator, ToxicVelocityEngine, GLOBAL_EPOCH_CHAIN_ADDRESS,
};

#[test]
fn test_given_address_space_when_classified_then_strictly_prevents_shard_collisions() {
    // ── GIVEN: Addresses from different tiers of the fractal hierarchy ──
    let system_epoch = GLOBAL_EPOCH_CHAIN_ADDRESS; // 0x00...00E0
    let mirrored_eth = sovereign_consensus::governance::system_registry::virtual_chain_address(1); // Ethereum Mainnet
    let range_meta = derive_range_meta_address(0x4000, 1); // 0x00014000...
    let user_wallet = address!("4200000000000000000000000000000000000042"); // Entropy >= 0x01

    // ── WHEN: Address classification is evaluated ──
    let class_epoch = classify_address(&system_epoch);
    let class_mirrored = classify_address(&mirrored_eth);
    let class_range = classify_address(&range_meta);
    let class_user = classify_address(&user_wallet);

    // ── THEN: All addresses map cleanly without collision ──
    assert_eq!(class_epoch, AddressClassification::SystemPrecompile);
    assert_eq!(class_mirrored, AddressClassification::MirroredForeignChain);
    assert_eq!(class_range, AddressClassification::RangeMetaChain);
    assert_eq!(class_user, AddressClassification::UserAccount);
}

#[test]
fn test_given_sustained_high_load_when_three_epochs_pass_then_executes_autonomous_split_block() {
    // ── GIVEN: Genesis range coordinator with root range [0x0000..0xFFFF] at depth 0 ──
    let mut coordinator = RangeShardingCoordinator::new_genesis();
    assert_eq!(coordinator.active_shards.len(), 1);

    // ── WHEN: Sustained traffic exceeds 85% capacity over 3 consecutive epochs ──
    let root_shard = coordinator.active_shards.get_mut(&0x0000).unwrap();
    root_shard.load_factor = 0.92;
    root_shard.active_accounts_count = 100_000;

    let left_root = B256::repeat_byte(0x11);
    let right_root = B256::repeat_byte(0x22);

    // Epoch 1: High load recorded
    let split_ep1 = coordinator.evaluate_split(0x0000, left_root, right_root, 1).unwrap();
    assert!(split_ep1.is_none());

    // Epoch 2: High load recorded
    let split_ep2 = coordinator.evaluate_split(0x0000, left_root, right_root, 2).unwrap();
    assert!(split_ep2.is_none());

    // Epoch 3: High load sustained -> Autonomous SplitBlock triggers
    let split_ep3 = coordinator.evaluate_split(0x0000, left_root, right_root, 3).unwrap();
    assert!(split_ep3.is_some());

    let split_block = split_ep3.unwrap();
    assert_eq!(split_block.parent_range_start, 0x0000);
    assert_eq!(split_block.parent_range_end, 0xFFFF);
    assert_eq!(split_block.left_child_smt_root, left_root);
    assert_eq!(split_block.right_child_smt_root, right_root);

    // ── THEN: Two child shards exist at depth 1 with halved address partitions ──
    assert_eq!(coordinator.active_shards.len(), 2);
    let left = coordinator.active_shards.get(&0x0000).unwrap();
    let right = coordinator.active_shards.get(&0x8000).unwrap();

    assert_eq!(left.range_start, 0x0000);
    assert_eq!(left.range_end, 0x7FFF);
    assert_eq!(left.depth, 1);
    assert_eq!(left.smt_root, left_root);

    assert_eq!(right.range_start, 0x8000);
    assert_eq!(right.range_end, 0xFFFF);
    assert_eq!(right.depth, 1);
    assert_eq!(right.smt_root, right_root);
}

#[test]
fn test_given_quiet_period_when_ten_epochs_pass_then_executes_autonomous_merge_block() {
    // ── GIVEN: Two child shards at depth 1 ──
    let mut coordinator = RangeShardingCoordinator::new_genesis();
    let root_shard = coordinator.active_shards.get_mut(&0x0000).unwrap();
    root_shard.load_factor = 0.95;
    coordinator.evaluate_split(0x0000, B256::repeat_byte(0x11), B256::repeat_byte(0x22), 1).unwrap();
    coordinator.evaluate_split(0x0000, B256::repeat_byte(0x11), B256::repeat_byte(0x22), 2).unwrap();
    coordinator.evaluate_split(0x0000, B256::repeat_byte(0x11), B256::repeat_byte(0x22), 3).unwrap();
    assert_eq!(coordinator.active_shards.len(), 2);

    // ── WHEN: Utilization drops below 10% on both sibling shards for 10 consecutive epochs ──
    for shard in coordinator.active_shards.values_mut() {
        shard.load_factor = 0.04;
    }

    let combined_root = B256::repeat_byte(0x33);
    for ep in 4..13 {
        let merge_res = coordinator.evaluate_merge(0x0000, 0x8000, combined_root, ep).unwrap();
        assert!(merge_res.is_none());
    }

    // Epoch 13 (10th consecutive low-load epoch) -> Autonomous MergeBlock triggers
    let merge_ep13 = coordinator.evaluate_merge(0x0000, 0x8000, combined_root, 13).unwrap();
    assert!(merge_ep13.is_some());

    let merge_block = merge_ep13.unwrap();
    assert_eq!(merge_block.left_range_start, 0x0000);
    assert_eq!(merge_block.right_range_start, 0x8000);
    assert_eq!(merge_block.parent_smt_root, combined_root);

    // ── THEN: Shards consolidate back into the single parent partition at depth 0 ──
    assert_eq!(coordinator.active_shards.len(), 1);
    let parent = coordinator.active_shards.get(&0x0000).unwrap();
    assert_eq!(parent.range_start, 0x0000);
    assert_eq!(parent.range_end, 0xFFFF);
    assert_eq!(parent.depth, 0);
    assert_eq!(parent.smt_root, combined_root);
}

#[test]
fn test_given_speculative_spam_attack_when_turnover_spikes_then_toxic_velocity_engine_applies_quadratic_surcharge() {
    let mut engine = ToxicVelocityEngine::default();
    let base_gas = engine.base_fee;

    // ── GIVEN: Normal traffic at target utilization (85%) ──
    let normal_gas = engine.calculate_surge_gas_price(0.85, U256::ZERO, 100);
    assert_eq!(normal_gas, base_gas);

    // ── WHEN: High-frequency speculative MEV / spam attack floods the range (rapid state churn) ──
    let attack_turnover = U256::from(100_000_000_000_000_000_000u128); // 100 ETH rapid turnover
    let surge_gas = engine.calculate_surge_gas_price(0.99, attack_turnover, 101);

    // ── THEN: Quadratic surge surcharge increases gas price exponentially ──
    assert!(surge_gas > normal_gas * U256::from(2));
}
