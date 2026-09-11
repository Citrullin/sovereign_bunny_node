//! AI Agent Multi-Dimensional Merit Evaluation & Soulbound Reward Engine.
//!
//! Autonomous AI Evaluator Agents running inside TEE enclaves evaluate developer
//! code commits, governance forum debates, and social media/community outreach,
//! signing deterministic `EvaluatedContribution` attestations that mint non-transferable
//! `SOV_merit` and dynamically advance the contributor's `MeritRank` (Rank0 -> Rank4).

use alloy_primitives::{Address, B256, U256};
use sovereign_crypto::SignatureScheme;
use crate::jurisdiction::MeritRank;
use crate::registry::ValidatorRegistry;
use crate::slashing::SoulboundToken;

/// Category and metadata of the evaluated real-world contribution.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ContributionKind {
    /// Developer code contribution: Git commit / PR diff hash, repository identifier, complexity score.
    CodeCommit {
        /// Keccak256 hash of the git commit or PR diff
        diff_hash: B256,
        /// PR number or issue tracking identifier
        pr_id: u64,
        /// Evaluated code quality / complexity score in [0.0, 1.0]
        complexity_score: f64,
    },
    /// Governance and forum participation: Proposal hash, consensus debate weight.
    ForumGovernance {
        /// Keccak256 hash of the forum thread or RFC proposal
        proposal_hash: B256,
        /// AI evaluation of debate depth and consensus contribution in [0.0, 1.0]
        consensus_weight: f64,
    },
    /// Social media, education, and community outreach.
    SocialOutreach {
        /// Platform identifier (e.g., "x", "farcaster", "discord", "blog")
        platform: String,
        /// Verified engagement and educational value score in [0.0, 1.0]
        engagement_score: f64,
    },
}

impl ContributionKind {
    /// Computes the base merit score multiplier from the contribution.
    pub fn score_multiplier(&self) -> f64 {
        match self {
            Self::CodeCommit { complexity_score, .. } => 1.5 * complexity_score.clamp(0.0, 1.0),
            Self::ForumGovernance { consensus_weight, .. } => 1.0 * consensus_weight.clamp(0.0, 1.0),
            Self::SocialOutreach { engagement_score, .. } => 0.5 * engagement_score.clamp(0.0, 1.0),
        }
    }
}

/// An evaluated contribution payload signed by an authorized AI Evaluator Agent.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EvaluatedContribution {
    /// Address of the contributor receiving merit
    pub contributor: Address,
    /// DID or Address of the AI Evaluator Agent
    pub evaluator: Address,
    /// Kind and specific metadata of the contribution
    pub contribution: ContributionKind,
    /// Base raw units evaluated by the AI model (e.g. lines of code, tokens, impressions)
    pub raw_units: u64,
    /// Unix timestamp when the evaluation was executed
    pub timestamp: u64,
    /// Signature of the AI Evaluator Agent over the evaluation digest
    pub evaluator_signature: Vec<u8>,
}

impl EvaluatedContribution {
    /// Computes the 32-byte digest of this evaluated contribution for signing.
    pub fn digest(&self) -> B256 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.contributor.as_slice());
        bytes.extend_from_slice(self.evaluator.as_slice());
        let kind_bytes = serde_json::to_vec(&self.contribution).unwrap_or_default();
        bytes.extend_from_slice(&kind_bytes);
        bytes.extend_from_slice(&self.raw_units.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        alloy_primitives::keccak256(&bytes)
    }

    /// Verifies the signature of the AI Evaluator Agent.
    pub fn verify_evaluator_signature(&self) -> Result<(), &'static str> {
        if self.evaluator_signature.is_empty() {
            return Err("Missing evaluator signature");
        }
        let digest = self.digest();
        // Classical 65-byte Secp256k1 or ML-DSA signature verification
        if self.evaluator_signature.len() == 65 {
            let sig = &self.evaluator_signature;
            let recid = sig[64] % 4;
            let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
                digest.as_slice(),
                &k256::ecdsa::Signature::from_slice(&sig[0..64]).map_err(|_| "Invalid ECDSA signature format")?,
                k256::ecdsa::RecoveryId::try_from(recid).map_err(|_| "Invalid recovery id")?,
            ).map_err(|_| "Failed to recover signer")?;
            let uncompressed = recovered.to_sec1_point(false);
            let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&hash[12..32]);
            if Address::from(addr) != self.evaluator {
                return Err("Evaluator signature mismatch");
            }
        } else {
            // Post-Quantum ML-DSA check
            sovereign_crypto::verify_signature(
                SignatureScheme::MlDsa,
                self.evaluator.as_slice(),
                digest.as_slice(),
                &self.evaluator_signature,
                false,
            ).map_err(|_| "Invalid PQ signature")?;
        }
        Ok(())
    }
}

/// Applies an evaluated contribution to the registry and mints Soulbound SOV merit tokens.
pub fn apply_contribution_evaluation(
    registry: &mut ValidatorRegistry,
    soulbound: &mut SoulboundToken,
    eval: &EvaluatedContribution,
) -> Result<(U256, MeritRank), &'static str> {
    // 1. Verify evaluator signature
    eval.verify_evaluator_signature()?;

    // 2. Compute merit token amount
    let multiplier = eval.contribution.score_multiplier();
    let merit_amount_u64 = (eval.raw_units as f64 * multiplier * 1_000.0) as u64;
    let merit_token_payout = U256::from(merit_amount_u64) * U256::from(1_000_000_000_000_000u64); // 10^15 base

    // 3. Mint non-transferable Soulbound tokens
    soulbound.mint(eval.contributor, merit_token_payout);

    // 4. Update contributor reputation score in ValidatorRegistry
    let did = registry.address_to_did.get(&eval.contributor)
        .cloned()
        .unwrap_or_else(|| format!("did:sovereign:{}", eval.contributor));
    
    let current_rep = registry.reputation.get(&did).copied().unwrap_or(0.0);
    let delta = (multiplier * 0.05).min(0.2);
    let new_rep = (current_rep + delta).min(1.0);
    registry.reputation.insert(did.clone(), new_rep);
    registry.address_to_did.insert(eval.contributor, did);

    // 5. Promote MeritRank
    let frontier = registry.account_frontiers.entry(eval.contributor).or_default();
    let current_rank = frontier.merit_rank;
    let target_rank = if new_rep >= 0.85 {
        MeritRank::Rank4
    } else if new_rep >= 0.60 {
        MeritRank::Rank3
    } else if new_rep >= 0.35 {
        MeritRank::Rank2
    } else if new_rep >= 0.10 {
        MeritRank::Rank1
    } else {
        MeritRank::Rank0
    };

    if target_rank > current_rank {
        frontier.merit_rank = target_rank;
    }

    Ok((merit_token_payout, frontier.merit_rank))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    #[test]
    fn test_ai_merit_evaluation_and_rank_progression() {
        // GIVEN: An AI Evaluator Agent with Secp256k1 keypair and an empty registry
        let mut registry = ValidatorRegistry::default();
        let mut soulbound = SoulboundToken::default();

        let signing_key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let uncompressed = verifying_key.to_sec1_point(false);
        let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
        let mut evaluator_addr = [0u8; 20];
        evaluator_addr.copy_from_slice(&hash[12..32]);
        let evaluator = Address::from(evaluator_addr);

        let contributor = Address::repeat_byte(0x77);

        // WHEN: Evaluating a high-complexity code contribution (PR commit)
        let mut eval = EvaluatedContribution {
            contributor,
            evaluator,
            contribution: ContributionKind::CodeCommit {
                diff_hash: B256::repeat_byte(0xaa),
                pr_id: 101,
                complexity_score: 0.95,
            },
            raw_units: 500, // 500 lines of rigorous rust code
            timestamp: 1_700_000_000,
            evaluator_signature: Vec::new(),
        };

        let digest = eval.digest();
        let (sig, recid) = signing_key.sign_prehash_recoverable(digest.as_slice());
        let mut sig_bytes = [0u8; 65];
        sig_bytes[0..64].copy_from_slice(&sig.to_bytes());
        sig_bytes[64] = recid.to_byte();
        eval.evaluator_signature = sig_bytes.to_vec();

        // THEN: Applying the contribution mints soulbound tokens and updates merit rank
        let res = apply_contribution_evaluation(&mut registry, &mut soulbound, &eval);
        assert!(res.is_ok());
        let (payout, rank) = res.unwrap();
        assert!(payout > U256::ZERO);
        assert!(rank >= MeritRank::Rank0);
        assert_eq!(soulbound.balances.get(&contributor), Some(&payout));
    }
}
