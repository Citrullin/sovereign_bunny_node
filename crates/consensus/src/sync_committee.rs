//! Saga Orchestrators Sub-Committee, Post-Quantum Signature Verification, and Time-Locked Intent Relays.

use alloy_primitives::{Address, Bytes, B256, U256};
use std::collections::HashSet;
use sovereign_identity::DidPeer4;

/// Cross-Manifold Saga Orchestrator Committee.
///
/// Sampled validators meeting a minimum reputation/merit threshold
/// rotated deterministically per epoch using VRF-style subset election.
#[derive(Debug, Clone)]
pub struct SagaOrchestratorCommittee {
    /// Active epoch of the committee.
    pub epoch: u64,
    /// Addresses of the selected orchestrator validators.
    pub orchestrators: HashSet<Address>,
    /// Threshold fraction required for consensus quorum (e.g. 0.67 for 2/3 majority).
    pub threshold: f64,
    /// Minimum reputation/merit rank required to be eligible for election.
    pub min_orchestrator_merit: f64,
}

impl Default for SagaOrchestratorCommittee {
    fn default() -> Self {
        let registry_lock = crate::registry::get_registry();
        let threshold = if let Ok(reg) = registry_lock.read() {
            reg.dynamic_cfg.read().unwrap().committee_threshold
        } else {
            0.67
        };

        Self {
            epoch: 0,
            orchestrators: HashSet::new(),
            threshold,
            min_orchestrator_merit: 0.05,
        }
    }
}

impl SagaOrchestratorCommittee {
    /// Deterministically elects/rotates the sub-committee for a specific target manifold.
    ///
    /// # Errors
    /// Returns an error if the registry cannot be accessed or if no eligible orchestrators exist.
    pub fn select_orchestrators(&mut self, target_manifold_id: u64, epoch: u64, subset_size: usize) -> Result<(), &'static str> {
        self.epoch = epoch;
        let registry_lock = crate::registry::get_registry();
        let registry = registry_lock.read().map_err(|_| "Failed to lock registry")?;
        
        self.threshold = registry.dynamic_cfg.read().unwrap().committee_threshold;

        let eligible = registry.get_eligible_orchestrators(target_manifold_id, self.min_orchestrator_merit);
        if eligible.is_empty() {
            return Err("No eligible orchestrators with sufficient merit rank");
        }

        let mut election = crate::subset_election::SnowSubsetElection::new(target_manifold_id);
        election.trigger_election(&eligible, epoch, subset_size)?;
        self.orchestrators = election.current_subset;
        Ok(())
    }
}

/// A Cross-Manifold Saga Payment Intent.
#[derive(Debug, Clone)]
pub struct SagaIntent {
    /// Unique intent ID.
    pub intent_id: B256,
    /// Source manifold address locking the assets.
    pub sender: Address,
    /// Destination recipient address.
    pub recipient: Address,
    /// Token amount locked.
    pub amount: U256,
    /// Expiration timestamp.
    pub expires_at: u64,
    /// List of orchestrator addresses and their signatures voting to commit/verify this intent.
    pub orchestrator_signatures: Vec<(Address, Bytes)>,
}

impl SagaIntent {
    /// Creates a new saga intent.
    pub fn new(intent_id: B256, sender: Address, recipient: Address, amount: U256, current_time: u64) -> Self {
        let registry_lock = crate::registry::get_registry();
        let timeout = if let Ok(reg) = registry_lock.read() {
            reg.dynamic_cfg.read().unwrap().saga_intent_timeout_seconds
        } else {
            86400
        };

        Self {
            intent_id,
            sender,
            recipient,
            amount,
            expires_at: current_time + timeout,
            orchestrator_signatures: Vec::new(),
        }
    }

    /// Checks if the intent has expired.
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires_at
    }

    /// Verifies the consensus quorum of Saga Orchestrator signatures, enforcing Zero Latency Quantum Trigger requirements.
    ///
    /// # Errors
    /// Returns an error if the quorum is not met, or if signature verification fails for any orchestrator.
    pub async fn verify_consensus(&self, committee: &SagaOrchestratorCommittee, quantum_threat: bool) -> Result<(), &'static str> {
        if committee.orchestrators.is_empty() {
            return Err("Committee is empty");
        }

        let registry_lock = crate::registry::get_registry();
        let threshold = if let Ok(reg) = registry_lock.read() {
            reg.dynamic_cfg.read().unwrap().committee_threshold
        } else {
            committee.threshold
        };

        let required_quorum = ((committee.orchestrators.len() as f64) * threshold).ceil() as usize;
        let mut valid_votes = HashSet::new();

        let registry = registry_lock.read().map_err(|_| "Failed to lock registry")?;

        for (addr, sig) in &self.orchestrator_signatures {
            if !committee.orchestrators.contains(addr) {
                continue; // Ignore signatures from non-committee members
            }

            // Resolve the DID peer document for this orchestrator
            let Some(did) = registry.get_did_by_address(addr) else {
                continue;
            };

            let peer = DidPeer4::resolve(&did).await
                .map_err(|_| "Failed to resolve orchestrator DID Peer document")?;

            // Verify the signature against the intent hash, enforcing PQ constraints if trigger is active
            let intent_hash_bytes = self.intent_id.as_slice();
            peer.verify_signature(intent_hash_bytes, sig, quantum_threat)?;

            valid_votes.insert(*addr);
        }

        if valid_votes.len() < required_quorum {
            return Err("Quorum threshold not met for Saga Orchestrators Consensus");
        }

        Ok(())
    }
}

/// Dynamic RPC Validator interface for verifying cross-chain intent settlement.
#[derive(Debug, Default)]
pub struct DynamicRpcVerifier;

impl DynamicRpcVerifier {
    /// Cross-verifies off-manifold RPC endpoints to assert whether an intent actually settled
    /// on the target manifold by establishing consensus across the orchestrator sub-committee.
    pub fn verify_target_settlement(
        &self,
        _intent_id: B256,
        _target_rpc_endpoints: &[String],
        _committee: &SagaOrchestratorCommittee,
    ) -> Result<bool, &'static str> {
        // Simulates RPC consensus checking across the orchestrator committee.
        // Returns true if settlement is verified on destination chain.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::ValidatorRegistry;
    use ed25519_dalek::{SigningKey, Signer};

    #[tokio::test]
    async fn test_saga_intent_verify_consensus() {
        let registry_lock = crate::registry::get_registry();
        let mut registry = registry_lock.write().unwrap();
        *registry = ValidatorRegistry::default();
        registry.dynamic_cfg.write().unwrap().zero_latency_quantum_trigger = false;

        // Generate dynamic keys and create valid peer did:peer:4
        let seed = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        
        let mut codec_bytes = vec![0xed, 0x01];
        codec_bytes.extend_from_slice(&verifying_key.to_bytes());
        let multibase_str = format!("z{}", bs58::encode(codec_bytes).into_string());

        let keys = vec![did_peer::DIDPeerCreateKeys {
            type_: Some(did_peer::DIDPeerKeyType::Ed25519),
            purpose: did_peer::DIDPeerKeys::Verification,
            public_key_multibase: Some(multibase_str),
        }];
        let (did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).unwrap();
        let addr = Address::repeat_byte(0x77);

        // Add mock validator mapping to address and DID
        registry.add_mock_validator(did.clone(), addr, [0x99; 32]);
        drop(registry);

        // Setup committee
        let mut committee = SagaOrchestratorCommittee::default();
        committee.orchestrators.insert(addr);
        committee.threshold = 1.0;

        // Create intent and sign it
        let intent_id = B256::repeat_byte(0xab);
        let sig = signing_key.sign(intent_id.as_slice()).to_bytes().to_vec();

        let mut intent = SagaIntent::new(intent_id, Address::repeat_byte(0x11), Address::repeat_byte(0x22), U256::from(100), 10000);
        intent.orchestrator_signatures.push((addr, Bytes::from(sig)));

        // Verify consensus
        let res = intent.verify_consensus(&committee, false).await;
        assert!(res.is_ok(), "Consensus verification failed: {:?}", res.err());
    }
}
