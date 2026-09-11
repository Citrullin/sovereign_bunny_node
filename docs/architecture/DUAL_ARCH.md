# Dual-Architecture Specification

## 1. Executive Summary

Sovereign Reth implements a **Dual-Architecture** execution model designed to bridge today's high-performance hardware-isolated EVM execution with tomorrow's fully client-side verifiable zero-knowledge (ZK) and Fully Homomorphic Encryption (FHE) execution engines.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENT INTERFACE                              │
│         (CAIP-2 / CAIP-10 Multi-Chain RPC / WebAssembly Wallet)         │
└───────────────────┬─────────────────────────────────┬───────────────────┘
                    │                                 │
           [Path A: SGXv2 TEE]               [Path B: ZK-Circuit]
                    │                                 │
                    ▼                                 ▼
┌──────────────────────────────────────┐  ┌───────────────────────────────┐
│   Hardware Enclave Execution (revm)   │  │   Client-Side Circuit Prover  │
│   • Stateless Witness Execution      │  │   • Noir / UltraHonk / Groth16│
│   • SGXv2 / TDX DCAP Attestation     │  │   • Stateless SMT Non-Exclusion│
│   • Low-latency / Full EVM Opcode    │  │   • FHE / E3 ACVM Trajectory  │
└───────────────────┬──────────────────┘  └───────────────┬───────────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     STATELESS VALIDATOR NETWORK                         │
│   • Tracks only Account-Lattice Frontier HEAD Commits                   │
│   • Verifies Proof / Attestation against Poseidon-SMT Roots             │
│   • Zero Persistent World State Bloat                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The Current Path: Stateless revm in SGXv2

Today, the validator network executes EVM state transitions inside hardware-isolated secure enclaves (Intel SGXv2 / AMD SEV-SNP / Intel TDX):

1. **Stateless Witness Pre-flight:**
   Transactions are submitted alongside an execution witness (`WitnessDatabase`). The enclave loads only the accounts and storage slots touched by the causal footprint of the transaction.
2. **Revm Execution:**
   The standard `revm` interpreter processes opcodes against the ephemeral witness cache.
3. **Hardware Attestation:**
   The validator produces an ECDSA/DCAP hardware attestation quote proving that the state root delta was computed accurately inside an authentic enclave running the canonical bytecode.

---

## 3. The Future Trajectory: E3 & Circuit Execution

Executing arbitrary monolithic EVM contracts inside ZK circuits is computationally expensive and requires specialized proving clusters. However, Sovereign Reth establishes the modular foundations to transition execution entirely to circuit-level proving:

1. **Interfold E3 Engine Abstraction:**
   An `ExecutionEngine` trait decouples state transition semantics from `revm`. The E3 ACVM engine from Interfold is integrated via a fork-first crate strategy.
2. **Compact Groth16 / UltraHonk Proofs:**
   Client devices (including mobile browsers and NFC tokens) generate succinct validity and compliance proofs (~200–300 bytes) rather than transmitting full execution traces.
3. **Zero Translation Cost:**
   By transitioning the state tree from Verkle trees over Bandersnatch to Poseidon-hashed Sparse Merkle Trees (SMTs) over BN254, state inclusion and exclusion proofs are directly verifiable inside Noir circuits with zero field translation overhead.

---

## 4. Architectural Invariants

- **Statelessness:** Neither revm nor E3 nodes custody historical world states. Only the latest commit hashes (Account Frontiers) and Chandy-Lamport epoch snapshots are tracked.
- **Client Sovereignty:** Clients can freely choose Path A (relying on validator TEE attestations for high throughput) or Path B (submitting self-generated ZK proofs for zero-trust client verification).
