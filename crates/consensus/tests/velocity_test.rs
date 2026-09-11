use sovereign_consensus::velocity::VelocityEngine;

#[test]
fn test_velocity_engine_output_and_optimal() {
    // GIVEN: Default velocity engine state
    let engine = VelocityEngine::default();

    // WHEN: Calculating total and optimal velocity
    let total_v = engine.total_velocity();
    let optimal_v = engine.optimal_velocity();
    let k = 100.0;
    let output = engine.compute_output(k);
    let eff = engine.efficiency_ratio(k);

    // THEN: Velocity metrics and efficiency ratio are positive and circuit breaker is inactive
    assert_eq!(total_v, 1.1); // 1.0 productive + 0.1 speculative
    assert!((optimal_v - (0.7 / 0.15)).abs() < 1e-5);
    assert!(output > 0.0);
    assert!(eff > 0.0);
    assert!(!engine.is_circuit_breaker_triggered(k));
}

#[test]
fn test_velocity_circuit_breaker_trigger() {
    // GIVEN: Velocity engine with speculative churn exceeding 5x productive velocity
    let mut engine = VelocityEngine::default();
    engine.v_productive = 1.0;
    engine.v_speculative = 6.0;

    // WHEN: Checking circuit breaker status
    // THEN: Circuit breaker is triggered to protect against toxic flow
    assert!(engine.is_circuit_breaker_triggered(100.0));
}

#[test]
fn test_gas_escalation_scalar() {
    // GIVEN: Velocity engine with zero speculative flow
    let mut engine = VelocityEngine::default();
    engine.v_productive = 1.0;
    engine.v_speculative = 0.0;

    // THEN: Base gas escalation scalar is 1.0
    assert!((engine.gas_escalation_scalar() - 1.0).abs() < 1e-4);

    // WHEN: Speculative flow escalates
    engine.v_speculative = 2.0;

    // THEN: Escalation scalar scales super-linearly
    assert!(engine.gas_escalation_scalar() > 4.0);
}

#[test]
fn test_dynamic_shard_count() {
    // GIVEN: Default low velocity state
    let mut engine = VelocityEngine::default();

    // WHEN: Shard count is computed under low velocity
    let shards_low_v = engine.dynamic_shard_count(16, 16, 4096);

    // THEN: Scale expands shard capacity above base
    assert!(shards_low_v >= 16);

    // WHEN: System experiences high productive velocity
    engine.v_productive = 9.0;
    engine.v_speculative = 1.0;
    let shards_high_v = engine.dynamic_shard_count(16, 16, 4096);

    // THEN: Shard count stabilizes at base count (16)
    assert_eq!(shards_high_v, 16);
}
