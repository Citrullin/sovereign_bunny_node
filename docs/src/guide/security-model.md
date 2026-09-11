# Security Model

## Threat Model Summary

Sovereign Bunny operates in an adversarial environment where any participant
may be malicious. The security model is layered:

### Identity — who can act

Every account must register a W3C DID document before submitting any
state-changing transaction. The DID document binds an EVM address to one or
more public keys (classical secp256k1/ed25519 and/or post-quantum ML-DSA-65,
Falcon-512). Every lattice block signature is verified against the account's
registered public key.

**Quantum threat mode** — when `zero_latency_quantum_trigger` is set in
`DynamicConfig`, classical signature schemes are rejected globally. All new
blocks must be signed with a registered post-quantum key. This can be
activated at any time via governance without a hard fork.

### Replay Protection — the same action cannot execute twice

| Attack surface | Defense |
|---|---|
| Lattice block replay (same account) | Monotone sequence number + previous hash chain |
| Cross-account double-receive | `claimed_sends` nullifier set in registry |
| Cross-cluster message replay | `processed_manifold_messages` nullifier set (per-registry) |
| Shadow burn double-release | `nullifier` field in `ShadowBurnReceipt` |
| Duplicate ContractCall saga | `used_intent_ids` set in registry |
| EIP-712 cross-deployment replay | Domain separator binds `chain_id` + `verifyingContract` |
| Paymaster reuse across epochs | `valid_until_epoch` expiry check |

### Solvency — balances cannot go negative

A `Send` block is rejected unless the sender's settled balance is ≥ the
requested amount at the time of block execution. Debit happens atomically
at block processing time, not at settlement time. This prevents the
sender from generating concurrent over-drawn Sends to multiple recipients.

### BFT Finality — no single node controls epoch boundaries

Epoch checkpoints require at least one (wip: t-of-n) BLS signature from
registered validators before being accepted. A node cannot finalize
arbitrary epochs with arbitrary state roots.

### Locking — cross-account calls do not deadlock indefinitely

When an account enters a synchronous ContractCall (`mutating:` prefix),
it is locked at the current global block height. The lock is released
automatically when `reg.current_block > frontier.locked_at`, using the
global block height rather than the account's own sequence number. This
means the timeout is in absolute time (blocks) rather than relative to
account activity — a slow callee cannot keep a caller's account locked
indefinitely by simply not producing blocks.

## Known Limitations (Work in Progress)

See [Implementation Status](implementation-status.md) for the full list.
Key gaps affecting security:

- **ZK / SGX proof verification is a stub** — frames are accepted on byte
  length only. No cryptographic enclave attestation or SNARK verification.
- **Anti-sybil PPID/ASN fields are self-reported** — validator registration
  does not yet verify hardware or network diversity claims.
- **BFT threshold is 1-of-n** — full threshold BLS aggregation is pending.

These gaps are acknowledged, tracked, and each has documented production
requirements. The node is honest about them rather than hiding them behind
stub implementations that appear to work.
