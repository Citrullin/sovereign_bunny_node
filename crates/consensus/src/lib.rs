//! Sovereign Consensus Crate
//! Contains custom transaction ordering and pool builders.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::module_name_repetitions)]

/// Custom FCFS transaction ordering and pool builders.
pub mod pool;
/// Sovereign configurations.
pub mod config;
/// Stateless EVM execution/validation.
pub mod stateless;
/// Native cryptographic verification.
pub mod crypto;
/// Namespaced Merkle Trees for state-diff partitioning.
pub mod nmt;
/// Validator registry and reputation.
pub mod registry;
/// BGP router sync and WireGuard peering.
pub mod bgp;
/// Cross-manifold precompiles module.
pub mod precompile;
/// Reputation slashing and decay rules.
pub mod slashing;
/// Parallel execution stubs.
pub mod parallel;
/// Snow-based subset election.
pub mod subset_election;

/// `PageRank` KZG commitments.
pub mod kzg;
/// MetaLex organization management.
pub mod metalex;
/// Sync committee and BLS signature aggregation.
pub mod sync_committee;
/// Velocity telemetry and circuit breaker engine.
pub mod velocity;
/// SIL-3 Actuator Oracles & Heartbeat precompile 0xfe.
pub mod actuator;
/// Cross-manifold Actor system and Saga rollback engine.
pub mod actor;
/// Based meshing and succinct zkEVM proof broadcasting.
pub mod based_mesh;
/// RPC-to-IPFS archival pinning engine and daemon.
pub mod archival;

pub use pool::{FCFSOrdering, SovereignPoolBuilder};
