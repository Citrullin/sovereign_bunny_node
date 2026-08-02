//! Hardware routing offload abstraction module.
//!
//! Enables the BGP control plane to push negotiated routes, rate limits, and
//! cryptographic tunnels directly into hardware/kernel structures (eBPF/XDP, FPGAs, Netlink).

use alloy_primitives::B256;
use std::collections::HashMap;
use std::sync::RwLock;

/// Trait defining the contract for high-speed data plane hardware routing offload.
pub trait DataPlaneDriver: Send + Sync + std::fmt::Debug {
    /// Pushes a dynamic route and bandwidth allocation rate limit into hardware tables.
    fn push_route(&self, dest_hash: B256, next_hop_pubkey: [u8; 32], rate_limit_bps: u64) -> Result<(), String>;

    /// Removes a route from hardware tables.
    fn remove_route(&self, dest_hash: B256) -> Result<(), String>;

    /// Updates the bandwidth allocation rate limit for an existing route.
    fn update_rate_limit(&self, dest_hash: B256, rate_limit_bps: u64) -> Result<(), String>;
}

/// A thread-safe mock implementation of `DataPlaneDriver` for local testing and simulations.
#[derive(Debug)]
pub struct MockHardwareDriver {
    /// In-memory representation of hardware routing table mapping:
    /// `dest_hash` -> (next_hop_pubkey, rate_limit_bps)
    pub hardware_table: RwLock<HashMap<B256, ([u8; 32], u64)>>,
}

impl Default for MockHardwareDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl MockHardwareDriver {
    /// Creates a new `MockHardwareDriver`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hardware_table: RwLock::new(HashMap::new()),
        }
    }

    /// Verifies if a specific route exists in the mock hardware table.
    pub fn has_route(&self, dest_hash: &B256) -> bool {
        self.hardware_table.read().unwrap().contains_key(dest_hash)
    }

    /// Retrieves the mock hardware route details.
    pub fn get_route(&self, dest_hash: &B256) -> Option<([u8; 32], u64)> {
        self.hardware_table.read().unwrap().get(dest_hash).copied()
    }
}

impl DataPlaneDriver for MockHardwareDriver {
    fn push_route(&self, dest_hash: B256, next_hop_pubkey: [u8; 32], rate_limit_bps: u64) -> Result<(), String> {
        self.hardware_table.write().unwrap().insert(dest_hash, (next_hop_pubkey, rate_limit_bps));
        Ok(())
    }

    fn remove_route(&self, dest_hash: B256) -> Result<(), String> {
        self.hardware_table.write().unwrap().remove(&dest_hash);
        Ok(())
    }

    fn update_rate_limit(&self, dest_hash: B256, rate_limit_bps: u64) -> Result<(), String> {
        let mut table = self.hardware_table.write().unwrap();
        if let Some(entry) = table.get_mut(&dest_hash) {
            entry.1 = rate_limit_bps;
            Ok(())
        } else {
            Err("Route not found in hardware table".to_string())
        }
    }
}
