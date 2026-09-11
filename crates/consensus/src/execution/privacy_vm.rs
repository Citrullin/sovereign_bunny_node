//! Universal Modular Privacy & Multi-VM Stateless Execution Engine Trait.
//!
//! # Two Execution Paradigms:
//!
//! ### 1. Primary Native Model: Client-Side Zero-Knowledge (Noir Circuits)
//! In the pure Sovereign Bunny architecture, **consensus nodes do not execute smart contract bytecode at all**.
//! The client (browser WASM wallet / edge device) executes the state transition locally inside a private
//! Noir circuit, generating an $\mathcal{O}(1)$ UltraHonk or Groth16 ZK proof ($\pi$).
//! - Validators only verify the mathematical proof ($\pi$) against the nullifier tree and update the account frontier.
//! - Yields $0$ validator execution overhead, infinite parallel horizontal scalability, and $100\%$ user privacy.
//!
//! ### 2. Transitional Legacy Model: Server-Side Execution (Stateless REVM / Secure Enclaves)
//! For backward-compatibility with legacy EVM smart contracts (Solidity, ERC-20, Uniswap, Aave)
//! and unshielded transactions where clients do not have client-side Noir provers:
//! - Partition committee nodes or hardware secure enclaves (SGXv2 / TDX / Gramine) execute the bytecode statelessly
//!   via `StatelessRevmBackend`, computing state diffs $\Delta$ and Merkle witness proofs.
//!
//! Satisfies the unified state transition: $f(S_t, \text{tx}) \to (S_{t+1}, \Delta, \pi)$.

use alloy_primitives::B256;
use sovereign_ssz::SszTransaction;

/// Targeted execution virtual machine engine architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VmEngineType {
    /// Native Client-Side Noir ZK Circuit Prover (Zero Node Execution)
    NoirClientZk,
    /// Legacy Ethereum Virtual Machine (revm / alloy-evm compatibility layer)
    Evm,
    /// Solana Virtual Machine (Sealevel / eBPF)
    Svm,
    /// Move Virtual Machine (Move bytecode resource types)
    Move,
    /// Native WASM / LLVM JIT Stateless Bytecode
    WasmJit,
}

/// Cryptographic proof or remote hardware attestation output by a privacy VM backend.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TransitionProof {
    /// Pure mathematical ZK proof (Aztec Noir UltraHonk / Groth16 / SP1)
    ZkSnark {
        proof_bytes: Vec<u8>,
        verifying_key_id: B256,
        public_inputs: Vec<B256>,
    },
    /// Hardware remote attestation quote (Intel SGXv2 DCAP / Gramine Enclave / AMD SEV-SNP)
    TeeAttestation {
        quote: Vec<u8>,
        ephemeral_pubkey: [u8; 32],
        enclave_measurement: [u8; 32],
    },
    /// Stateless Verkle / SMT execution witness proof
    StatelessWitness {
        state_root: B256,
        witness_hash: B256,
    },
    /// Plain unshielded execution receipt (for transparent / developer transactions)
    Unshielded {
        state_diff_hash: B256,
    },
}

/// Universal trait satisfied by all confidential & stateless VM execution backends.
pub trait PrivacyVmBackend: Send + Sync + std::fmt::Debug {
    /// Unique identifier of this VM backend (e.g., "sgx-revm-v1", "noir-ultrahonk", "stateless-revm")
    fn backend_id(&self) -> &'static str;

    /// Returns the VM engine architecture type (EVM, SVM, Move, WASM).
    fn engine_type(&self) -> VmEngineType {
        VmEngineType::Evm
    }

    /// Execute a state transition statelessly given an input account root and SSZ transaction.
    /// Produces the post-transition root and corresponding proof/attestation \pi.
    fn execute_transition(
        &self,
        pre_state_root: B256,
        tx: &SszTransaction,
    ) -> Result<(B256, TransitionProof), String>;

    /// Verify a state transition proof \pi independently without executing the bytecode.
    fn verify_proof(
        &self,
        pre_state_root: B256,
        post_state_root: B256,
        tx: &SszTransaction,
        proof: &TransitionProof,
    ) -> Result<bool, String>;
}
