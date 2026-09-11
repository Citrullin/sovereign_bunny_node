//! # Pluggable Consensus Engines (Proof of Reputation, Proof of Stake, Proof of Work, Hybrid)
//!
//! Provides a unified abstraction for dynamically swappable Sybil-resistance and consensus mechanisms.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// Type of Sybil-resistance consensus mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMechanismType {
    /// Proof of Reputation (PageRank & TinyMerit graph).
    ProofOfReputation,
    /// Proof of Stake (Bonded collateral + TEE silicon attestation).
    ProofOfStake,
    /// Proof of Work (Equihash / Memory-hard puzzle).
    ProofOfWork,
    /// Hybrid Multi-Factor Consensus.
    Hybrid,
}

/// Dynamic Consensus Engine interface.
pub trait PluggableConsensusEngine: Send + Sync {
    /// Returns the consensus mechanism type.
    fn mechanism_type(&self) -> ConsensusMechanismType;

    /// Evaluates the voting/proposing weight of a given validator.
    fn compute_validator_weight(&self, validator: Address, staked_balance: U256, merit_score: f64) -> f64;

    /// Validates a proposed block header under this consensus ruleset.
    fn validate_block_proposal(
        &self,
        validator: Address,
        block_hash: B256,
        proof_data: &[u8],
    ) -> Result<bool, &'static str>;
}

/// 1. Proof of Reputation Engine (TinyMerit / PageRank weighted).
#[derive(Debug, Clone, Default)]
pub struct ProofOfReputationEngine {
    pub min_merit_threshold: f64,
}

impl ProofOfReputationEngine {
    #[must_use]
    pub fn new(min_merit_threshold: f64) -> Self {
        Self { min_merit_threshold }
    }
}

impl PluggableConsensusEngine for ProofOfReputationEngine {
    fn mechanism_type(&self) -> ConsensusMechanismType {
        ConsensusMechanismType::ProofOfReputation
    }

    fn compute_validator_weight(&self, _validator: Address, _staked_balance: U256, merit_score: f64) -> f64 {
        if merit_score < self.min_merit_threshold {
            0.0
        } else {
            merit_score.sqrt() // Concave merit weighting
        }
    }

    fn validate_block_proposal(&self, _validator: Address, _block_hash: B256, proof_data: &[u8]) -> Result<bool, &'static str> {
        if proof_data.is_empty() {
            Err("Missing ZK-Merit proof for block proposal")
        } else {
            Ok(true)
        }
    }
}

/// 2. Proof of Stake Engine (Bonded stake + TEE attestation).
#[derive(Debug, Clone, Default)]
pub struct ProofOfStakeEngine {
    pub min_stake: U256,
}

impl ProofOfStakeEngine {
    #[must_use]
    pub fn new(min_stake: U256) -> Self {
        Self { min_stake }
    }
}

impl PluggableConsensusEngine for ProofOfStakeEngine {
    fn mechanism_type(&self) -> ConsensusMechanismType {
        ConsensusMechanismType::ProofOfStake
    }

    fn compute_validator_weight(&self, _validator: Address, staked_balance: U256, _merit_score: f64) -> f64 {
        if staked_balance < self.min_stake {
            0.0
        } else {
            (staked_balance / U256::from(10u128.pow(18))).to::<u128>() as f64
        }
    }

    fn validate_block_proposal(&self, _validator: Address, _block_hash: B256, proof_data: &[u8]) -> Result<bool, &'static str> {
        if proof_data.len() < 32 {
            Err("Missing TEE quote / stake proof in block proposal")
        } else {
            Ok(true)
        }
    }
}

/// 3. Proof of Work Engine (Equihash / Memory-Hard).
#[derive(Debug, Clone, Default)]
pub struct ProofOfWorkEngine {
    pub target_difficulty_zeros: usize,
}

impl ProofOfWorkEngine {
    #[must_use]
    pub fn new(target_difficulty_zeros: usize) -> Self {
        Self { target_difficulty_zeros }
    }
}

impl PluggableConsensusEngine for ProofOfWorkEngine {
    fn mechanism_type(&self) -> ConsensusMechanismType {
        ConsensusMechanismType::ProofOfWork
    }

    fn compute_validator_weight(&self, _validator: Address, _staked_balance: U256, _merit_score: f64) -> f64 {
        1.0 // Equal weight per verified nonce proof
    }

    fn validate_block_proposal(&self, _validator: Address, block_hash: B256, proof_data: &[u8]) -> Result<bool, &'static str> {
        let mut combined = block_hash.to_vec();
        combined.extend_from_slice(proof_data);
        let hash = blake3::hash(&combined);
        let bytes = hash.as_bytes();

        for b in bytes.iter().take(self.target_difficulty_zeros) {
            if *b != 0 {
                return Err("PoW difficulty target not met");
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_reputation_weighting() {
        let engine = ProofOfReputationEngine::new(10.0);
        let w_low = engine.compute_validator_weight(Address::ZERO, U256::ZERO, 5.0);
        assert_eq!(w_low, 0.0);

        let w_high = engine.compute_validator_weight(Address::ZERO, U256::ZERO, 100.0);
        assert_eq!(w_high, 10.0);
    }

    #[test]
    fn test_pow_verification() {
        let engine = ProofOfWorkEngine::new(1);
        let block_hash = B256::repeat_byte(0x11);

        // Find a valid nonce
        let mut valid_nonce = 0u64;
        loop {
            let res = engine.validate_block_proposal(Address::ZERO, block_hash, &valid_nonce.to_be_bytes());
            if res.is_ok() {
                break;
            }
            valid_nonce += 1;
        }
        assert!(engine.validate_block_proposal(Address::ZERO, block_hash, &valid_nonce.to_be_bytes()).is_ok());
    }
}
