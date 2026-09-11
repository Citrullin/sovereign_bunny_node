//! # Sovereign Consensus & Execution Architecture
//!
//! ## Core Architecture: Decentralized Divide-and-Conquer Paxos & Snowman Consensus
//! 
//! 1. **Stateless Account-Lattice Ledger**:
//!    - The primary ledger is an asynchronously concurrent **Account-Lattice** where each account maintains
//!      its own independent sequence of Send/Receive/State blocks with $\mathcal{O}(1)$ ZK verification.
//!    - **Legacy Monolithic Smart Contract Compatibility**: When executing EVM bytecode involving synchronous
//!      inter-contract calls (`CALL`, `DELEGATECALL`, `STATICCALL`), participating smart contract accounts in the
//!      call graph are dynamically locked in the lattice for the duration of the execution frame, guaranteeing
//!      linearizability without blocking unrelated accounts in the lattice.
//!
//! 2. **Dual Consensus Hierarchy**:
//!    - **Snowman Engine (`engine::snow`, `engine::subset`)**: Sybil-resistant, metastably-secure global consensus
//!      for **committee selection**, epoch boundary finalization, validator jurisdiction rules, and security anchoring.
//!    - **Decentralized Divide-and-Conquer Paxos (`config::EpochConfig`, `engine::epoch`)**: Sharded sub-committees
//!      operate rotating Multi-Paxos instances per account/partition for ultra-low-latency, high-throughput
//!      **double-spend and reorg conflict resolution**.
//!    - **Epoch Markers Ratifying Account-Lattice Tips**: Each epoch cut commits to the Merkle/Verkle root of the
//!      verified **tips of the Account-Lattice**, ratifying state progression, distributing merit rewards,
//!      and rotating the active Paxos and Snowman committees.
//!
//! Contains domain-partitioned consensus engines, execution bridges, governance, mesh networking, and transaction pool.

#![allow(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::module_name_repetitions)]

// Core domain modules
pub mod config;
pub mod engine;
pub mod execution;
pub mod governance;
pub mod lattice;
pub mod mesh;
pub mod pool;
pub mod storage;
pub mod system_contracts;

// Backward-compatibility aliases for existing crate consumers & tests
pub use engine::epoch as epoch_engine;
pub use engine::reanchor;
pub use engine::slashing;
pub use engine::snow;
pub use engine::subset as subset_election;

pub use execution::opcode_override;
pub use execution::parallel;
pub use execution::privacy_vm;
pub use execution::stateless;
pub use execution::velocity;
pub use execution::frame_tx;

pub use governance::compliance as compliance_vector;
pub use governance::jurisdiction;
pub use governance::pq_registry;
pub use governance::registry;
pub use governance::system_registry;
pub use governance::anti_sybil;

pub use lattice::range as lattice_range;

pub use system_contracts::actuator;
pub use system_contracts::ai_merit;
pub use system_contracts::cross_chain as cross_chain_committee;
pub use system_contracts::router as precompile_router;
pub use system_contracts::saga;
pub use system_contracts::shadow_contract;

pub use mesh::bgp;
pub use mesh::dataplane;
pub use mesh::relay_mesh;

pub use storage::archival;
pub use storage::flat_state;
pub use storage::kzg;
pub use storage::nmt;
pub use storage::dialects as storage_dialects;

pub use pool::{FCFSOrdering, SovereignPoolBuilder};

