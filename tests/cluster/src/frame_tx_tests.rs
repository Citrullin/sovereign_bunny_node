//! # EIP-8141 Frame Transactions Test Suite
//!
//! Validates:
//! 1. EIP-8141 VERIFY frame: sandboxed authorization and APPROVE execution against in-memory account tip.
//! 2. EIP-8141 EXECUTE frame: state transition payload execution without EntryPoint bundler tax.
//! 3. Rejection of unapproved or invalid state witness frame transactions.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use alloy_primitives::{B256, Bytes, U256, address};
use sovereign_consensus::execution::frame_tx::{
    FrameExecutor, FrameTransaction, EIP8141_TX_TYPE,
};

#[test]
fn test_given_valid_frame_tx_when_verify_and_execute_frames_run_then_advances_account_tip_statelessly() {
    let sender = address!("1111111111111111111111111111111111111111");
    let target = address!("2222222222222222222222222222222222222222");
    let state_tip = B256::repeat_byte(0xaa);

    // ── GIVEN: EIP-8141 Frame Transaction carrying state witness and APPROVE bytecode ──
    let tx = FrameTransaction {
        sender,
        target,
        nonce: 1,
        target_slot: 0,
        max_fee_per_gas: U256::from(20_000_000_000u64), // 20 Gwei
        max_priority_fee_per_gas: U256::from(1_000_000_000u64),
        gas_limits: sovereign_consensus::execution::frame_tx::MultiDimGasLimit::default(),
        verify_calldata: Bytes::from(vec![0x01, 0xaa, 0xbb]), // Contains APPROVE authorization
        signature_scheme: 0,
        public_key: vec![],
        authorization_signature: vec![],
        delegation: None,
        paymaster_frame: None,
        execute_calldata: Bytes::from(b"transfer(recipient,100)".to_vec()),
        state_witness: state_tip,
    };

    assert_eq!(EIP8141_TX_TYPE, 0x06);

    // ── WHEN: VERIFY frame executes in sandboxed RAM ──
    let verify_res = FrameExecutor::execute_verify_frame(&tx, state_tip);

    // ── THEN: Verification passes without off-chain bundler overhead ──
    assert!(verify_res.is_ok());
    let v_result = verify_res.unwrap();
    assert!(v_result.approved);
    assert_eq!(v_result.payer, sender);

    // ── AND WHEN: EXECUTE frame executes against the Account-Lattice ──
    let exec_res = FrameExecutor::execute_payload_frame(&tx, state_tip);

    // ── AND THEN: Execution succeeds and produces a new state tip H_{t+1} ──
    assert!(exec_res.is_ok());
    let e_result = exec_res.unwrap();
    assert!(e_result.success);
    assert_ne!(e_result.new_state_tip, state_tip);
}

#[test]
fn test_given_stale_state_witness_when_verify_frame_runs_then_strictly_rejects() {
    let sender = address!("1111111111111111111111111111111111111111");
    let target = address!("2222222222222222222222222222222222222222");
    let current_tip = B256::repeat_byte(0xbb);
    let stale_tip = B256::repeat_byte(0xaa);

    // ── GIVEN: Transaction carrying a stale state witness ──
    let tx = FrameTransaction {
        sender,
        target,
        nonce: 1,
        target_slot: 0,
        max_fee_per_gas: U256::from(20_000_000_000u64),
        max_priority_fee_per_gas: U256::from(1_000_000_000u64),
        gas_limits: sovereign_consensus::execution::frame_tx::MultiDimGasLimit::default(),
        verify_calldata: Bytes::from(vec![0x01]),
        signature_scheme: 0,
        public_key: vec![],
        authorization_signature: vec![],
        delegation: None,
        paymaster_frame: None,
        execute_calldata: Bytes::from(vec![0x02]),
        state_witness: stale_tip,
    };

    // ── WHEN: VERIFY frame evaluates against current account state tip ──
    let verify_res = FrameExecutor::execute_verify_frame(&tx, current_tip);

    // ── THEN: Rejects immediately in RAM with zero state pollution ──
    assert!(verify_res.is_err());
    assert_eq!(
        verify_res.unwrap_err(),
        "VERIFY Frame failed: State witness mismatch with account frontier tip"
    );
}
