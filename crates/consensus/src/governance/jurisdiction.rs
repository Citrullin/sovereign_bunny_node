//! # Jurisdiction Vector and Governance Actions
//!
//! Defines the rules, constraints, on-chain bit registry, and voting structures
//! finalized by the sub-committee via Snowman consensus.

use alloy_primitives::{Address, B256, U256};
use std::collections::HashMap;

/// Repetition/meritrank progression ranks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum MeritRank {
    /// Initial rank, 3-month distribution frequency.
    #[default]
    Rank0 = 0,
    /// Rank 1, 1-month distribution frequency.
    Rank1 = 1,
    /// Rank 2, 2-week distribution frequency.
    Rank2 = 2,
    /// Rank 3, 1-week distribution frequency.
    Rank3 = 3,
    /// Rank 4, daily distribution frequency.
    Rank4 = 4,
}

impl MeritRank {
    /// Returns the distribution interval in epochs.
    /// Default assumes: 1 epoch = 1 day (1296 blocks at 6s/block).
    pub fn distribution_interval_epochs(&self) -> u64 {
        match self {
            MeritRank::Rank0 => 90,   // ~3 months
            MeritRank::Rank1 => 30,   // ~1 month
            MeritRank::Rank2 => 14,   // ~2 weeks
            MeritRank::Rank3 => 7,    // ~1 week
            MeritRank::Rank4 => 1,    // daily
        }
    }

    /// Checks if a distribution should be performed for the given epoch height.
    pub fn should_distribute(&self, epoch_id: u64) -> bool {
        if self.distribution_interval_epochs() == 0 {
            return false;
        }
        epoch_id % self.distribution_interval_epochs() == 0
    }
}

/// Active policy rules, filters, and boundaries attached to a manifold.
/// Mutated only via Snowman-finalized `JurisdictionDecision` actions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JurisdictionVector {
    /// Identifier of the target manifold
    pub manifold_id: u64,
    /// Active Q1 sanction/allow mask. Checked: (user.Q1 & active_q1_mask) == active_q1_mask
    pub active_q1_mask: u64,
    /// Required Q2 entity/asset type. Checked: (user.Q2 & required_q2_mask) != 0
    pub required_q2_mask: u64,
    /// Max transfer amount per transaction or epoch
    pub velocity_limit: Option<U256>,
    /// Appointed enforcer DID string
    pub appointed_enforcer_did: Option<String>,
    /// Epoch this policy vector was established or updated
    pub epoch_established: u64,
    /// Hash of the state Verkle root of the compliance data
    pub compliance_root: [u8; 32],
    /// Human-readable bit dictionary: (quadrant, bit_index) -> label string
    pub bit_registry: HashMap<(u8, u8), String>,
}

/// Patch structure containing subset fields of dynamic config to update.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DynamicConfigPatch {
    pub sgx_reputation_threshold: Option<f64>,
    pub manifold_quorum_threshold: Option<usize>,
    pub social_promotion_threshold: Option<f64>,
    pub zero_latency_quantum_trigger: Option<bool>,
    pub default_pq_scheme: Option<String>,
    pub default_crypto_profile: Option<String>,
    pub profile_switch_block_height: Option<u64>,
    pub next_crypto_profile: Option<String>,
    pub saga_intent_timeout_seconds: Option<u64>,
    pub committee_threshold: Option<f64>,
    pub connectivity_decay_penalty: Option<f64>,
}

/// Discrete governance actions affecting registry state, policy, and rewards.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum JurisdictionAction {
    /// Sets specific bits in a target account's compliance quadrant (sanction/restrict).
    SetQuadrantBits { target: Address, quadrant: u8, bits: u64 },
    /// Clears specific bits in a target account's compliance quadrant (lift sanction).
    ClearQuadrantBits { target: Address, quadrant: u8, bits: u64 },
    /// Registers a human-readable description for a compliance bit.
    RegisterBitDefinition { quadrant: u8, bit: u8, label: String },
    /// Grants a membership bit in Q3.
    GrantMembership { target: Address, membership_bit: u64 },
    /// Revokes a membership bit in Q3.
    RevokeMembership { target: Address, membership_bit: u64 },
    /// Sets global velocity transfer cap.
    SetVelocityLimit { velocity: U256 },
    /// Appoints enforcer DID string.
    AppointEnforcer { enforcer_did: String },
    /// Patches dynamic configurations on the network registry.
    UpdateDynamicConfig(DynamicConfigPatch),
    /// Mandates post-quantum verification override.
    ActivateZlqt(bool),
    /// Activates or deactivates emergency circuit breaker.
    TriggerCircuitBreaker(bool),
    /// Slashes validator state reputation.
    SlashValidator { target: Address, amount: u64 },
    /// Mints merit/reputation reward.
    MintMeritReward { recipient: Address, amount: U256 },
    /// Advances account's MeritRank progression level.
    AdvanceMeritRank {
        target: Address,
        new_rank: MeritRank,
        evidence_epoch: u64,
        evidence_hash: B256,
    },
    /// Demotes account's MeritRank progression level.
    DemoteMeritRank {
        target: Address,
        new_rank: MeritRank,
    },
}

/// A decision proposal that undergoes Snowball voting by the committee.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JurisdictionDecision {
    /// Manifold scope of this decision
    pub manifold_id: u64,
    /// Targeted governance action
    pub action: JurisdictionAction,
    /// Validator address who proposed this decision
    pub proposed_by: Address,
    /// Epoch during which proposal was submitted
    pub epoch: u64,
}

/// A governance manager that resolves jurisdiction decisions using Snowball consensus.
#[derive(Debug, Clone)]
pub struct JurisdictionConsensusEngine {
    pub voter: crate::snow::SnowballVoter<B256>, // votes on the decision hash
    pub decision: JurisdictionDecision,
}

impl JurisdictionConsensusEngine {
    pub fn new(decision: JurisdictionDecision, k: usize, alpha: f64, beta: u32) -> Self {
        Self {
            voter: crate::snow::SnowballVoter::new(k, alpha, beta),
            decision,
        }
    }

    /// Records validator votes for the decision proposal.
    pub fn record_vote_round(&mut self, responses: &[B256]) {
        self.voter.record_round(responses);
    }

    /// If finalized, applies the governance action to the registry state.
    pub fn apply_if_finalized(
        &self,
        registry: &mut crate::registry::ValidatorRegistry,
    ) -> Result<bool, &'static str> {
        if let Some(ref final_hash) = self.voter.finalized_value {
            let decision_hash = alloy_primitives::keccak256(serde_json::to_vec(&self.decision).unwrap());
            if *final_hash == decision_hash {
                // Apply the action on-chain to the registry
                match &self.decision.action {
                    JurisdictionAction::SetQuadrantBits { target, quadrant, bits } => {
                        let mut frontier = registry.get_or_create_frontier(*target);
                        let mut compliance = frontier.cached_compliance.clone()
                            .unwrap_or(crate::compliance_vector::ComplianceVector([0; 4]));
                        let q_idx = (*quadrant as usize).saturating_sub(1);
                        if q_idx < 4 {
                            compliance.0[q_idx] |= *bits;
                        }
                        frontier.cached_compliance = Some(compliance);
                        registry.update_frontier(*target, frontier);
                    }
                    JurisdictionAction::ClearQuadrantBits { target, quadrant, bits } => {
                        let mut frontier = registry.get_or_create_frontier(*target);
                        let mut compliance = frontier.cached_compliance.clone()
                            .unwrap_or(crate::compliance_vector::ComplianceVector([0; 4]));
                        let q_idx = (*quadrant as usize).saturating_sub(1);
                        if q_idx < 4 {
                            compliance.0[q_idx] &= !*bits;
                        }
                        frontier.cached_compliance = Some(compliance);
                        registry.update_frontier(*target, frontier);
                    }
                    JurisdictionAction::SlashValidator { target, amount } => {
                        if let Some(did) = registry.get_did_by_address(target) {
                            registry.penalize_validator_reputation(&did, *amount as f64 / 100.0);
                        }
                    }
                    JurisdictionAction::AdvanceMeritRank { target, new_rank, .. } => {
                        let mut frontier = registry.get_or_create_frontier(*target);
                        frontier.merit_rank = *new_rank;
                        registry.update_frontier(*target, frontier);
                    }
                    _ => {}
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ValidatorRegistry;

    #[test]
    fn test_jurisdiction_decision_snowball_finality() {
        let mut registry = ValidatorRegistry::default();
        let target = Address::repeat_byte(0x99);

        let action = JurisdictionAction::SetQuadrantBits {
            target,
            quadrant: 1,
            bits: 0b101,
        };
        let decision = JurisdictionDecision {
            manifold_id: 1,
            action,
            proposed_by: Address::repeat_byte(0x01),
            epoch: 1,
        };

        let mut engine = JurisdictionConsensusEngine::new(decision.clone(), 1, 0.8, 2);
        let decision_hash = alloy_primitives::keccak256(serde_json::to_vec(&decision).unwrap());

        // Query round 1
        engine.record_vote_round(&[decision_hash]);
        assert_eq!(engine.apply_if_finalized(&mut registry).unwrap(), false);

        // Query round 2 (reaches beta=2 successes)
        engine.record_vote_round(&[decision_hash]);
        assert_eq!(engine.apply_if_finalized(&mut registry).unwrap(), true);

        // Verify state is mutated in registry
        let frontier = registry.get_or_create_frontier(target);
        let compliance = frontier.cached_compliance.unwrap();
        assert_eq!(compliance.0[0], 0b101);
    }
}
