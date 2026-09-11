//! # Sovereign Execution Engine
//!
//! Exposes execution adapters for the Stateless Account-Lattice ledger:
//!
//! 1. **Client-Side ZK (Noir Circuits)**: The primary native model where clients generate UltraHonk proofs
//!    client-side, making server-side VM execution completely unnecessary.
//! 2. **Legacy Server-Side Execution (Stateless REVM / Secure Enclaves)**: The compatibility layer providing
//!    stateless execution for standard Solidity smart contracts and unshielded EVM transactions.

pub mod backend;

pub use backend::StatelessRevmBackend;

