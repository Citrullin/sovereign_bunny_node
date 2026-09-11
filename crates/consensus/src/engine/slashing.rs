//! Reputation slashing and decay rules module.

use alloy_primitives::{Address, U256};
use std::collections::HashMap;

/// Non-transferable ERC-20 / Soulbound Token (SOV merit).
#[derive(Debug, Clone, Default)]
pub struct SoulboundToken {
    /// Token balances mapping EVM Address to balance amount.
    pub balances: HashMap<Address, U256>,
}

impl SoulboundToken {
    /// Mint tokens to an address based on their reputation score.
    pub fn mint(&mut self, to: Address, amount: U256) {
        let bal = self.balances.entry(to).or_default();
        *bal += amount;
    }

    /// Try to transfer tokens. This will always fail/revert because the token is soulbound.
    ///
    /// # Errors
    /// Always returns an error indicating that soulbound tokens are non-transferable.
    pub fn transfer(&mut self, _from: Address, _to: Address, _amount: U256) -> Result<(), &'static str> {
        Err("SOV_merit token is non-transferable (Soulbound)")
    }
}

/// Byzantine Slashing Violation Category.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SlashReason {
    /// Cartel formation: >20% mutual endorsement loop.
    CartelFormation,
    /// Missing KZG PageRank commitment during the epoch window.
    MissingCommitment,
    /// Equivocation: Signing two conflicting blocks or epoch markers at identical sequence/height.
    Equivocation {
        /// Sequence / epoch height where equivocation was detected
        height: u64,
        /// First signed block hash
        first_hash: alloy_primitives::B256,
        /// Conflicting second signed block hash
        second_hash: alloy_primitives::B256,
    },
    /// Invalid state root or corrupted ZK validity proof proposal.
    InvalidStateProof {
        /// Proposed invalid state root
        state_root: alloy_primitives::B256,
        /// Detailed reason for proof failure
        reason: String,
    },
    /// SIL-3 Actuator safety interlock violation or continuity heartbeat timeout (>200ms).
    ActuatorSafetyFault {
        /// Device DID or hardware address
        device_id: Address,
        /// Unsafe physical work units or fault description
        fault: String,
    },
    /// Fraudulent or revoked TEE enclave attestation quote.
    FraudulentAttestation {
        /// Target enclave DID
        enclave_did: String,
        /// Verification error
        error: String,
    },
}

impl SlashReason {
    /// Returns the standard penalty percentage to deduct from the node's reputation score.
    pub fn penalty_rate(&self) -> f64 {
        match self {
            Self::CartelFormation => 0.25,
            Self::MissingCommitment => 0.10,
            Self::Equivocation { .. } => 0.50,
            Self::InvalidStateProof { .. } => 1.00, // 100% full eviction
            Self::ActuatorSafetyFault { .. } => 0.40,
            Self::FraudulentAttestation { .. } => 1.00, // 100% full eviction
        }
    }
}

/// `ReputationSlash` handler and `TinyMeritRank` rules.
#[derive(Debug, Default)]
pub struct SlashingManager {
    /// Current merit rank of validators.
    merit_rank: HashMap<Address, u64>,
}

impl SlashingManager {
    /// Creates a new `SlashingManager`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            merit_rank: HashMap::new(),
        }
    }

    /// Handles a reputation slash.
    pub fn slash(&mut self, address: Address, amount: u64) {
        if let Some(rank) = self.merit_rank.get_mut(&address) {
            *rank = rank.saturating_sub(amount);
        }
    }

    /// Applies a structured Byzantine `SlashReason` against a validator node.
    pub fn slash_validator(
        registry: &mut crate::registry::ValidatorRegistry,
        did: &str,
        reason: &SlashReason,
    ) -> f64 {
        let penalty_rate = reason.penalty_rate();
        let current_rep = registry.reputation.get(did).copied().unwrap_or(0.0);
        let penalty = current_rep * penalty_rate;
        let new_rep = (current_rep - penalty).max(0.0);
        registry.reputation.insert(did.to_string(), new_rep);

        // If penalty is full eviction (1.0), demote MeritRank to Rank0
        if penalty_rate >= 0.99 {
            if let Some((addr, _)) = registry.address_to_did.iter().find(|(_, d)| *d == did) {
                if let Some(frontier) = registry.account_frontiers.get_mut(addr) {
                    frontier.merit_rank = crate::jurisdiction::MeritRank::Rank0;
                }
            }
        }
        new_rep
    }

    /// Applies `TinyMeritRank` decay rules over an epoch.
    pub fn decay(&mut self, decay_factor: u64) {
        for rank in self.merit_rank.values_mut() {
            *rank = rank.saturating_sub(decay_factor);
        }
    }

    /// Checks if a validator is still in the allowed sequencers set based on threshold.
    #[must_use]
    pub fn is_allowed_sequencer(&self, address: &Address, threshold: u64) -> bool {
        self.merit_rank.get(address).copied().unwrap_or(0) >= threshold
    }

    /// Checks for cartel formation (nodes giving >20% of their endorsement weight to mutual endorsers)
    pub fn slash_cartels(registry: &mut crate::registry::ValidatorRegistry, slash_amount: f64) {
        let mut to_slash = Vec::new();
        for (u, targets) in &registry.endorsements {
            let total_out: f64 = targets.values().sum();
            if total_out == 0.0 { continue; }
            
            let mut mutual_weight = 0.0;
            for (v, &weight) in targets {
                if let Some(v_targets) = registry.endorsements.get(v) {
                    if v_targets.contains_key(u) {
                        mutual_weight += weight;
                    }
                }
            }
            
            if mutual_weight / total_out > 0.20 {
                to_slash.push(u.clone());
            }
        }
        
        for did in to_slash {
            if let Some(rep) = registry.reputation.get_mut(&did) {
                *rep = (*rep - slash_amount).max(0.0);
            }
        }
    }

    /// Slashes nodes that failed to submit their KZG commitment within the epoch publishing window.
    pub fn slash_missing_commitments(registry: &mut crate::registry::ValidatorRegistry, slash_amount: f64) {
        let mut to_slash = Vec::new();
        for did in registry.reputation.keys() {
            if !registry.commitments.contains_key(did) {
                to_slash.push(did.clone());
            }
        }
        
        for did in to_slash {
            if let Some(rep) = registry.reputation.get_mut(&did) {
                *rep = (*rep - slash_amount).max(0.0);
            }
        }
        
        // Reset commitments for the next epoch
        registry.commitments.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soulbound_token() {
        // GIVEN: A Soulbound SOV merit token instance
        let mut token = SoulboundToken::default();
        let user = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);

        // WHEN: Minting merit tokens to a user
        token.mint(user, U256::from(500));

        // THEN: Balance is credited and transfers are rejected
        assert_eq!(token.balances.get(&user), Some(&U256::from(500)));

        let res = token.transfer(user, recipient, U256::from(100));
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "SOV_merit token is non-transferable (Soulbound)");
    }

    #[test]
    fn test_byzantine_slashing_matrix() {
        // GIVEN: A validator registry with an active validator
        let mut registry = crate::registry::ValidatorRegistry::default();
        let did = "did:sovereign:node-1".to_string();
        let addr = Address::repeat_byte(0x55);
        registry.reputation.insert(did.clone(), 1.0);
        registry.address_to_did.insert(addr, did.clone());
        let frontier = registry.account_frontiers.entry(addr).or_default();
        frontier.merit_rank = crate::jurisdiction::MeritRank::Rank4;

        // WHEN: Slashing for Equivocation (50% penalty)
        let rep = SlashingManager::slash_validator(
            &mut registry,
            &did,
            &SlashReason::Equivocation {
                height: 100,
                first_hash: alloy_primitives::B256::repeat_byte(0x01),
                second_hash: alloy_primitives::B256::repeat_byte(0x02),
            },
        );

        // THEN: Reputation is reduced by 50%
        assert!((rep - 0.5).abs() < 1e-5);

        // WHEN: Slashing for InvalidStateProof (100% penalty)
        let rep_final = SlashingManager::slash_validator(
            &mut registry,
            &did,
            &SlashReason::InvalidStateProof {
                state_root: alloy_primitives::B256::repeat_byte(0xee),
                reason: "Corrupted Verkle Transition".to_string(),
            },
        );

        // THEN: Reputation collapses to 0.0 and merit rank is reset to Rank0
        assert_eq!(rep_final, 0.0);
        assert_eq!(registry.account_frontiers.get(&addr).unwrap().merit_rank, crate::jurisdiction::MeritRank::Rank0);
    }
}

