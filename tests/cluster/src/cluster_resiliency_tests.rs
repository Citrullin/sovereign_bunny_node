//! Cluster Resiliency, Partition Failover, Distributed Snapshotting, and Saga E2E Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use alloy_primitives::{Address, B256, U256};
use sovereign_consensus::epoch_engine::execute_chandy_lamport_snapshot;
use sovereign_consensus::subset_election::EpochSubsetElection;
use sovereign_consensus::saga::{ActorState, SagaActor};
use sovereign_consensus::registry::get_registry;
use std::collections::HashSet;

#[tokio::test]
async fn test_given_active_partitions_when_chandy_lamport_snapshot_executed_then_captures_frontier_and_in_flight() {
    // ── GIVEN: An active ledger with account frontiers and an in-flight send block ──
    let reg_lock = get_registry();
    let p0_sender = Address::from([0x11; 20]);
    let p1_recipient = Address::from([0x22; 20]);

    if let Ok(mut reg) = reg_lock.write() {
        reg.account_frontiers.insert(p0_sender, sovereign_consensus::registry::AccountFrontier {
            sequence: 10,
            latest_hash: B256::repeat_byte(0x01),
            ..Default::default()
        });

        let send_block = sovereign_consensus::stateless::LatticeBlock {
            account: p0_sender,
            previous_hash: B256::ZERO,
            sequence: 1,
            payload: sovereign_consensus::stateless::LatticePayload::Send {
                recipient: p1_recipient,
                amount: U256::from(500),
            },
            signature: vec![],
            static_witnesses: vec![],
        };
        reg.lattice_blocks.insert(B256::repeat_byte(0x99), send_block);
    }

    // ── WHEN: Chandy-Lamport snapshot algorithm is executed ──
    let reg = reg_lock.read().unwrap();
    let (states, in_flight) = execute_chandy_lamport_snapshot(&reg);

    // ── THEN: Account frontier and in-flight channel messages are completely captured ──
    assert!(states.contains_key(&p0_sender));
    assert_eq!(states.get(&p0_sender), Some(&10));
    assert_eq!(in_flight.len(), 1);
    assert_eq!(in_flight[0].sender, p0_sender);
    assert_eq!(in_flight[0].recipient, p1_recipient);
    assert_eq!(in_flight[0].amount, U256::from(500));
}

#[test]
fn test_given_validator_pool_when_node_fails_then_vrf_reelects_healthy_subset() {
    // ── GIVEN: A validator pool of 4 nodes ──
    let mut election = EpochSubsetElection::new(1);
    let mut pool = HashSet::new();
    pool.insert(Address::from([0x01; 20]));
    pool.insert(Address::from([0x02; 20]));
    pool.insert(Address::from([0x03; 20]));
    pool.insert(Address::from([0x04; 20]));

    let res = election.trigger_election(&pool, 1, 2);
    assert!(res.is_ok());
    assert_eq!(election.current_subset.len(), 2);

    // ── WHEN: Node 04 fails and is removed from the active candidate pool ──
    pool.remove(&Address::from([0x04; 20]));
    let res2 = election.trigger_election(&pool, 2, 2);

    // ── THEN: New committee subset is successfully elected without the failed node ──
    assert!(res2.is_ok());
    assert_eq!(election.current_subset.len(), 2);
    assert!(!election.current_subset.contains(&Address::from([0x04; 20])));
}

#[test]
fn test_given_cross_chain_saga_when_phases_progress_then_commits_or_rolls_back() {
    // ── GIVEN: An initiated cross-chain saga actor ──
    let sender = Address::from([0xaa; 20]);
    let recipient = Address::from([0xbb; 20]);
    let amount = U256::from(1_000_000_000);
    let actor_id = B256::repeat_byte(0x01);

    let mut saga = SagaActor::new(actor_id, sender, recipient, amount, 100);
    assert_eq!(saga.state, ActorState::InitiateIntent);

    // ── WHEN: Phase 1 (Prepare / Escrow Lock) executes ──
    let prep_res = saga.prepare();

    // ── THEN: State transitions to PrepareExecution ──
    assert!(prep_res.is_ok());
    assert_eq!(saga.state, ActorState::PrepareExecution);

    // ── AND WHEN: Phase 2 (Commit) executes ──
    let commit_res = saga.commit();

    // ── THEN: State transitions to Commit ──
    assert!(commit_res.is_ok());
    assert_eq!(saga.state, ActorState::Commit);

    // ── AND WHEN: A failing saga encounters a timeout ──
    let mut failing_saga = SagaActor::new(B256::repeat_byte(0x02), sender, recipient, amount, 10);
    let _ = failing_saga.prepare();
    failing_saga.rollback();

    // ── THEN: State cleanly reverts to Rollback ──
    assert_eq!(failing_saga.state, ActorState::Rollback);
}
