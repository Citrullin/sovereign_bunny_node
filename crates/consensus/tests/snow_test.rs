use alloy_primitives::Address;
use sovereign_consensus::snow::{sample_peers_weighted, SnowballVoter, SnowflakeVoter, SnowmanVoter};

#[test]
fn test_snowflake_voter_convergence() {
    // GIVEN: A Snowflake voter initialized with sample size 10, threshold 0.8, and beta 3
    let mut voter = SnowflakeVoter::<bool>::new(10, 0.8, 3);
    assert_eq!(voter.finalized_value, None);

    // WHEN: Recording consecutive successful voting rounds
    // Round 1: 9 true, 1 false => success 1
    voter.record_round(&[true, true, true, true, true, true, true, true, true, false]);
    assert_eq!(voter.current_preference, Some(true));
    assert_eq!(voter.consecutive_successes, 1);
    assert_eq!(voter.finalized_value, None);

    // Round 2: 8 true, 2 false => success 2
    voter.record_round(&[true, true, true, true, true, true, true, true, false, false]);
    assert_eq!(voter.consecutive_successes, 2);

    // Round 3: 10 true => success 3 >= beta(3) => finalized
    voter.record_round(&[true; 10]);

    // THEN: Voter reaches consensus finality on true
    assert_eq!(voter.consecutive_successes, 3);
    assert_eq!(voter.finalized_value, Some(true));
}

#[test]
fn test_snowball_voter_multi_choice_confidence() {
    // GIVEN: A Snowball voter with multi-choice confidence tracking
    let mut voter = SnowballVoter::<u32>::new(10, 0.7, 2);

    // WHEN: Round 1 votes 8/10 for option 1
    voter.record_round(&[1, 1, 1, 1, 1, 1, 1, 1, 2, 3]);
    assert_eq!(voter.current_preference, Some(1));
    assert_eq!(voter.confidence_counters.get(&1).copied(), Some(1));
    assert_eq!(voter.finalized_value, None);

    // WHEN: Round 2 votes unanimously for option 1
    voter.record_round(&[1; 10]);

    // THEN: Option 1 achieves irreversible finality
    assert_eq!(voter.finalized_value, Some(1));
}

#[test]
fn test_snowman_voter_tree_tracking() {
    // GIVEN: A Snowman DAG/tree voter
    let mut snowman = SnowmanVoter::<[u8; 32]>::new(10, 0.8, 2);
    let genesis = [0u8; 32];
    let block1 = [1u8; 32];

    snowman.add_node(block1, genesis);
    assert_eq!(snowman.parent_map.get(&block1), Some(&genesis));

    // WHEN: Multiple rounds vote for block1
    snowman.record_round(&[block1; 10]);
    snowman.record_round(&[block1; 10]);

    // THEN: block1 is finalized as linear canonical head
    assert_eq!(snowman.inner_snowball.finalized_value, Some(block1));
}

#[test]
fn test_sample_peers_weighted() {
    // GIVEN: A weighted list of validator reputation scores
    let addr1 = Address::repeat_byte(0x01);
    let addr2 = Address::repeat_byte(0x02);
    let addr3 = Address::repeat_byte(0x03);
    let validators = vec![(addr1, 1.0), (addr2, 0.5), (addr3, 0.1)];

    // WHEN: Sampling peers weighted by reputation
    let sampled = sample_peers_weighted(&validators, 2, 12345);

    // THEN: Sample size matches requested count and contains valid validators
    assert_eq!(sampled.len(), 2);
    assert!(sampled.contains(&addr1) || sampled.contains(&addr2) || sampled.contains(&addr3));
}
