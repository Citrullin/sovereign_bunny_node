//! Snow-based subset election module for cross-manifold relaying.
//!
//! Randomly samples validators from the routing pool every 15 minutes.

use alloy_primitives::Address;
use std::collections::HashSet;
use alloy_primitives::keccak256;

/// Represents a Snow subset election state.
pub struct SnowSubsetElection {
    /// The currently elected subset of validators.
    pub current_subset: HashSet<Address>,
    /// The manifold ID targeted by this election.
    pub manifold_id: u64,
}

impl SnowSubsetElection {
    /// Creates a new `SnowSubsetElection` helper.
    #[must_use]
    pub fn new(manifold_id: u64) -> Self {
        Self {
            current_subset: HashSet::new(),
            manifold_id,
        }
    }

    /// Triggers an election based on the given pool of routable validators.
    /// Uses a VRF-style deterministic sort based on epoch to sample the subset.
    ///
    /// # Errors
    /// Returns an error if the pool of routable validators is empty.
    pub fn trigger_election(&mut self, routable_validators: &HashSet<Address>, epoch: u64, subset_size: usize) -> Result<(), &'static str> {
        if routable_validators.is_empty() {
            self.current_subset.clear();
            return Err("No routable validators available for election.");
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&self.manifold_id.to_be_bytes());
        payload.extend_from_slice(&epoch.to_be_bytes());
        let seed = keccak256(&payload);

        let mut validators_vec: Vec<Address> = routable_validators.iter().copied().collect();
        
        // Sort deterministically based on distance to the seed hash
        validators_vec.sort_by_key(|addr| {
            let mut addr_payload = Vec::new();
            addr_payload.extend_from_slice(addr.as_slice());
            addr_payload.extend_from_slice(seed.as_slice());
            keccak256(&addr_payload)
        });
        
        let sample_size = std::cmp::min(validators_vec.len(), subset_size);
        self.current_subset = validators_vec.into_iter().take(sample_size).collect();
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snow_subset_election_success() {
        let mut election = SnowSubsetElection::new(42);
        let mut pool = HashSet::new();
        let addr1 = Address::repeat_byte(0x01);
        let addr2 = Address::repeat_byte(0x02);
        let addr3 = Address::repeat_byte(0x03);
        pool.insert(addr1);
        pool.insert(addr2);
        pool.insert(addr3);

        // Elect 2 out of 3 validators
        let res = election.trigger_election(&pool, 100, 2);
        assert!(res.is_ok());
        assert_eq!(election.current_subset.len(), 2);
        for addr in &election.current_subset {
            assert!(pool.contains(addr));
        }

        // Test deterministic behavior: same epoch & pool must yield the exact same subset
        let mut election2 = SnowSubsetElection::new(42);
        let res2 = election2.trigger_election(&pool, 100, 2);
        assert!(res2.is_ok());
        assert_eq!(election.current_subset, election2.current_subset);

        // Test epoch rotation: different epoch should yield a potentially different sort/subset (or same if sample size matches pool)
        let mut election3 = SnowSubsetElection::new(42);
        let _ = election3.trigger_election(&pool, 200, 2);
        assert_eq!(election3.current_subset.len(), 2);
    }

    #[test]
    fn test_snow_subset_election_empty_pool() {
        let mut election = SnowSubsetElection::new(42);
        let pool = HashSet::new();
        let res = election.trigger_election(&pool, 100, 2);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "No routable validators available for election.");
        assert!(election.current_subset.is_empty());
    }

    #[test]
    fn test_snow_subset_election_clamped_sample_size() {
        let mut election = SnowSubsetElection::new(42);
        let mut pool = HashSet::new();
        let addr1 = Address::repeat_byte(0x01);
        pool.insert(addr1);

        // Requesting 5 items from a pool of 1 should clamp to 1 item
        let res = election.trigger_election(&pool, 100, 5);
        assert!(res.is_ok());
        assert_eq!(election.current_subset.len(), 1);
        assert!(election.current_subset.contains(&addr1));
    }
}
