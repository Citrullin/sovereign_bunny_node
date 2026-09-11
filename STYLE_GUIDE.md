# Sovereign Reth & Sovereign Bunny Engineering Style Guide

## 1. Stateless Ledger Invariants

1. **Deterministic Account Partitioning**:
   - Accounts are identified by fixed SSZ byte slices (`16..36` in `SszTransaction`).
   - Range keys are 16-bit high-order slices (`92..94`) routing into deterministic committee actor partitions.
2. **Zero Implicit State**:
   - WASM actor containers and SGX privacy enclaves hold zero long-term implicit host state.
   - All state transitions receive explicit `(AccountFrontier, SszTransaction, WitnessProof)` tuples.
3. **No Unstructured Pure Self-Sends**:
   - Sweeps and claims targeting floating balance inboxes must explicitly invoke low-entropy system precompile addresses:
     - `SYSTEM_RECEIVE_HOOK = 0x0000000000000000000000000000000000000002`
     - `SYSTEM_BRIDGE = 0x0000000000000000000000000000000000000006`

---

## 2. Native Cross-Chain Composability & Reserve Shadow Contracts

1. **1:1 Native Token Wrapping**:
   - Native tokens wrap into ERC-20 / NFT Reserve Shadow Contracts held in system escrow (`SYSTEM_BRIDGE`).
   - Introducing fractional reserves or external custodial multi-sigs is strictly prohibited.
2. **Deterministic Ownership Invariant**:
   - The token `owner` on the originating ledger is locked to the Shadow Contract Virtual Address (`0x00...00_01_<ChainID>`).
3. **Burn $\to$ Destruct Settlement**:
   - When a shadow token is burned on an external chain, the escrow unwinds and directly credits the native ledger via `SYSTEM_RECEIVE_HOOK`.

---

## 3. Testing Conventions: Given-When-Then (BDD)

Every unit test, integration test, and cluster test must follow the **Given-When-Then** format:

```rust
#[test]
fn test_feature_scenario() {
    // GIVEN: Initial preconditions, funded accounts, or registered DIDs
    let initial_balance = U256::from(10);
    
    // WHEN: The action or state transition is triggered
    let outcome = execute_transition(initial_balance);
    
    // THEN: Explicit assertions verifying state invariants and cryptographic validity
    assert_eq!(outcome, expected_outcome);
}
```

---

## 4. Code Cleanliness & Zero Legacy Stubs

- Avoid circular aliases or empty forwarding files (`actor.rs`, `sync_committee.rs`). Use primary domain crate modules directly.
- Avoid hardcoded ports or static IP addresses in production paths; use dynamic discovery or structured configuration.
