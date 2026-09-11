# Implementation Status

> This page is derived from [`docs/components.toml`](../../components.toml),
> the machine-readable manifest that tracks the status of every component.
> **Legend:** ✅ Production &nbsp;|&nbsp; 🔧 Work in Progress &nbsp;|&nbsp; ⚠️ Stub &nbsp;|&nbsp; 📋 Planned

The goal of this project is production-quality code. This page documents
honestly where each component stands today and exactly what is required to
reach production for every stub or WIP item.

---

## Execution Layer

| Component | Status | Module |
|---|---|---|
| [Block-Lattice Transaction Execution](#block-lattice-transaction-execution) | 🔧 WIP | `execution::stateless` |
| [StatelessTransitionFrame Verifier](#statelesstransitionframe-verifier) | ⚠️ Stub | `execution::stateless` |
| [EIP-712 Lattice Block Signing](#eip-712-lattice-block-signing) | ✅ Production | `execution::stateless` |
| [secp256k1 Lattice Signature Verification](#secp256k1-lattice-signature-verification) | ✅ Production | `execution::stateless` |
| [Implicit State Block Validation](#implicit-state-block-validation) | ✅ Production | `execution::stateless` |
| [Paymaster Risk Frame Verification](#paymaster-risk-frame-verification) | ✅ Production | `execution::frame_tx` |

## Consensus & Epoch Layer

| Component | Status | Module |
|---|---|---|
| [Epoch BFT Finalization](#epoch-bft-finalization) | 🔧 WIP | `engine::epoch` |
| [Progressive Merit Rank Distribution](#progressive-merit-rank-distribution) | ✅ Production | `engine::epoch` |
| [GnosisPaymentWatcher](#gnosispaymentwatcher) | ⚠️ Stub | `engine::epoch` |

## Governance & Registry

| Component | Status | Module |
|---|---|---|
| [ValidatorRegistry](#validatorregistry) | 🔧 WIP | `governance::registry` |
| [DID Identity Registry](#did-identity-registry) | ✅ Production | `governance::registry` |
| [Floating Send Reclaim](#floating-send-reclaim) | ✅ Production | `governance::registry` |
| [Genesis Allocation Loader](#genesis-allocation-loader) | ✅ Production | `governance::registry` |
| [Anti-Sybil Topology Validation](#anti-sybil-topology-validation) | 🔧 WIP | `governance::anti_sybil` |

## Shadow Contracts

| Component | Status | Module |
|---|---|---|
| [Universal Reverse Shadow Contracts](#universal-reverse-shadow-contracts) | 🔧 WIP | `system_contracts::shadow_contract` |

## Network & Relay

| Component | Status | Module |
|---|---|---|
| [Cross-Manifold Message Relay](#cross-manifold-message-relay) | 🔧 WIP | `mesh::relay_mesh` |
| [ZK Proof Scheme Verifier](#zk-proof-scheme-verifier-relay-mesh) | ⚠️ Stub | `mesh::relay_mesh` |

## SGX / Enclave

| Component | Status | Module |
|---|---|---|
| [SGX Gramine Confidential Execution](#sgx-gramine-confidential-execution) | 📋 Planned | — |

---

## Component Details

### Block-Lattice Transaction Execution

**Status:** 🔧 Work in Progress  
**Crate:** `sovereign-consensus` · **Module:** `execution::stateless`  
**Architecture:** [Account-Lattice & Epochs](architecture/epoch-lattice.md)  
**Spec:** [JSON-RPC API](specifications/json-rpc.md)

Stateless execution of account-lattice Send, Receive, and ContractCall blocks
against a witness-cached EVM. Each account maintains an independent chain
(frontier) of blocks identified by hash; sequence numbers prevent gaps and
reordering. Balance debits on Send and credits on Receive are live.
Classical secp256k1 and post-quantum ML-DSA-65 signature paths are both
complete. Epoch-gated merit rank promotion with cooldown is operational.

**What is still WIP:**
- The zkEVM context snapshot stored in `paused_context` during a synchronous
  ContractCall uses a 4-byte placeholder. Full Gramine/SGX enclave
  snapshotting is the production path — see
  [SGX Gramine Confidential Execution](#sgx-gramine-confidential-execution).
- Frame-level ZK proof verification is a stub — see
  [StatelessTransitionFrame Verifier](#statelesstransitionframe-verifier).

---

### StatelessTransitionFrame Verifier

**Status:** ⚠️ Stub  
**Crate:** `sovereign-consensus` · **Module:** `execution::stateless`  
**Architecture:** [Dual Architecture: Classical & Quantum](architecture/dual-arch.md)

Verifies the cryptographic proof attached to a stateless transition frame
before the frame's state delta is applied to the global state root. Two
backends are defined:

- **SGX DCAP** — Parses the DCAP attestation quote and validates the
  MRENCLAVE measurement against the node's signed allowlist, proving that
  execution occurred inside an authentic hardware enclave.
- **Noir UltraHonk** — Submits the proof bytes and public inputs to the
  Barretenberg verifier with the circuit's registered verification key.

**Current stub behaviour:** Both backends accept any payload ≥ 64 bytes.
No cryptographic verification is performed.

**Production requires:**
1. `dcap-qvl` (or `intel-tee-qvl-rust`) for DCAP quote parsing and MRENCLAVE allowlist verification
2. Barretenberg UltraHonk verifier via C FFI for Noir proof validation
3. Registered VK store mapping `circuit_id → verification_key` in `ValidatorRegistry`
4. Strict scheme-to-curve pinning in the relay mesh ZK verifier

---

### EIP-712 Lattice Block Signing

**Status:** ✅ Production  
**Crate:** `sovereign-consensus` · **Module:** `execution::stateless`

Computes the EIP-712 structured-data digest for lattice blocks. The domain
separator binds the signature to this specific chain via the runtime
`chain_id` and the canonical system DID registry address as
`verifyingContract`. This prevents cross-deployment signature replay.

---

### secp256k1 Lattice Signature Verification

**Status:** ✅ Production  
**Crate:** `sovereign-consensus` · **Module:** `execution::stateless`

Verifies a 65-byte (r, s, v) secp256k1 signature using full recovery via
`k256::ecdsa::VerifyingKey::recover_from_prehash`. Address recovery is
attempted against EIP-712, raw payload hash, and EIP-191 digests to
tolerate different signing conventions across wallet implementations.

---

### Implicit State Block Validation

**Status:** ✅ Production  
**Crate:** `sovereign-consensus` · **Module:** `execution::stateless`  
**Architecture:** [Hybrid Consensus](architecture/hybrid-consensus.md)

Validates committee-signed implicit state blocks. Enforces BFT quorum of
⌊2n/3⌋+1 valid validator signatures before accepting a new state root.

---

### Paymaster Risk Frame Verification

**Status:** ✅ Production  
**Crate:** `sovereign-consensus` · **Module:** `execution::frame_tx`

Verifies a `PaymasterRiskFrame` before accepting a gasless transaction.
The paymaster's secp256k1 signature must recover to their registered EVM
address, and the frame must not be expired (`valid_until_epoch ≥ current_epoch`).

---

### Epoch BFT Finalization

**Status:** 🔧 Work in Progress  
**Crate:** `sovereign-consensus` · **Module:** `engine::epoch`  
**Architecture:** [Hybrid Consensus](architecture/hybrid-consensus.md)

Finalizes epoch boundaries by collecting threshold BLS signatures from
`ThresholdEpochMarker` events, crediting merit payouts to account balances,
and writing immutable `EpochCheckpoint` records. Checkpoints with empty
signature sets are rejected.

**What is still WIP:** Full t-of-n BLS threshold aggregation.

**Production requires:**
1. `blst` or `bls12-381` crate for BLS signature aggregation and verification
2. VRF-based validator set rotation seeding

---

### Progressive Merit Rank Distribution

**Status:** ✅ Production  
**Crate:** `sovereign-consensus` · **Module:** `engine::epoch`  
**Architecture:** [Penta-Vector Economics](architecture/economics.md)

Distributes TBL merit rewards at each epoch boundary. Rank promotion requires
holding the current rank for `MERIT_RANK_COOLDOWN_EPOCHS` consecutive epochs,
preventing reputation-spike rank-sniping attacks. Balance credits are applied
directly to `account_balances` in the registry.

---

### GnosisPaymentWatcher

**Status:** ⚠️ Stub  
**Crate:** `sovereign-consensus` · **Module:** `engine::epoch`

Monitors the Gnosis Chain EURe contract for Transfer events confirming
pending NFT purchase intents. The structural logic (rejecting unverifiable
intents, tracking pending set) is correct; no real RPC calls are made.

**Production requires:**
1. `alloy-provider` for `eth_getLogs` calls against Gnosis Chain
2. Configurable finality depth k in `StaticConfig`
3. EURe contract address and Transfer event ABI in config

---

### ValidatorRegistry

**Status:** 🔧 Work in Progress  
**Crate:** `sovereign-consensus` · **Module:** `governance::registry`  
**Architecture:** [C4 Container Model](architecture/c4.md)

Central in-memory state store. Intentionally monolithic at this stage —
each committee partition holds its own registry snapshot reconciled at
epoch boundaries, avoiding distributed state synchronization during
stateless execution.

**What is still WIP:** Planned split into focused sub-modules
(`identity`, `frontier`, `epoch_state`, `genesis`, `manifold`).

---

### DID Identity Registry

**Status:** ✅ Production  
**Architecture:** [ZK-OIDC Authentication](architecture/zk-oidc.md)

Resolves and stores W3C DID documents for registered identities. Supports
`did:sovereign:[chain_id]:[evm_address]` and `did:peer:4...` long-form DIDs.
Classical and post-quantum public keys stored per-account with key-tier tracking.

---

### Floating Send Reclaim

**Status:** ✅ Production

Processes timed-out unclaimed Send blocks and refunds the sender after
`reclaim_timeout_epochs` epochs. Prevents indefinite balance lock when
recipients are non-responsive.

---

### Genesis Allocation Loader

**Status:** ✅ Production

Loads initial account balances from a genesis.json at an explicit,
config-supplied path only. No parent-directory walking to prevent
working-directory injection attacks.

---

### Anti-Sybil Topology Validation

**Status:** 🔧 Work in Progress  
**Architecture:** [Hybrid Consensus](architecture/hybrid-consensus.md)

Enforces hardware and network diversity across the registered validator set.
The structural diversity checks are in place; field values are currently
self-reported without external attestation.

**Production requires:**
1. PPID extracted from a verified DCAP attestation quote
2. BGP ASN cross-referenced with IP-to-ASN database at registration time
3. Vivaldi coordinates validated against measured RTTs to known peers

---

### Universal Reverse Shadow Contracts

**Status:** 🔧 Work in Progress  
**Architecture:** [Reverse Shadow Contracts](architecture/shadow-contracts.md)

Cross-chain asset lifecycle: lock native → mint shadow → transfer → burn shadow
→ release native. The 1:1 reserve invariant is enforced by debiting the
depositor at wrap time. Nullifier-based double-release prevention is live.

**What is still WIP:** Cross-chain Merkle inclusion proof for burn receipts.

**Production requires:**
1. Cross-chain Merkle proof verifier for `ShadowBurnReceipt` inclusion
2. Light-client state root feed for destination chains

---

### Cross-Manifold Message Relay

**Status:** 🔧 Work in Progress  
**Architecture:** [Based Witness Mesh](architecture/witness-mesh.md)

Routes inter-cluster messages over KZG-committed blob envelopes with
nullifier replay protection. Nullifier expiry cleanup loop is not yet
wired to the epoch finalizer.

---

### ZK Proof Scheme Verifier (relay mesh)

**Status:** ⚠️ Stub  
**Architecture:** [Based Witness Mesh](architecture/witness-mesh.md)

Verifies BiniusBinaryStark and Plonky3Blake3 proofs in cross-manifold
messages. Currently performs byte-length check only.

**Production requires:**
1. Binius binary field STARK verifier
2. Plonky3 verifier with Blake3 Merkle trees
3. Strict scheme-to-curve pinning table

---

### SGX Gramine Confidential Execution

**Status:** 📋 Planned  
**Architecture:** [Dual Architecture](architecture/dual-arch.md)  
**Source:** [`gramine/`](../../gramine/)

Hardware-isolated confidential EVM execution producing DCAP attestation
quotes as proof of authentic execution.

**Production requires:**
1. Gramine manifest and enclave build (see `gramine/` directory)
2. `dcap-qvl` integration in `StatelessTransitionFrame::verify`
3. MRENCLAVE allowlist management in `ValidatorRegistry`
4. Full zkEVM context snapshot/restore for `paused_context`
