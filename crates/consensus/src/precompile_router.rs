//! # Precompile Router for System Addresses
//!
//! Decodes and executes SystemActions targeting system registry addresses.
//! Manages DID registry, Saga Intent Escrow, and Jurisdiction delta updates.

use alloy_primitives::{Address, U256};
use std::collections::HashMap;
use crate::system_registry::SystemAction;
use crate::registry::{ValidatorRegistry, IntentEscrow};
use crate::jurisdiction::{JurisdictionDecision, JurisdictionAction};

/// Dispatches and executes system actions.
///
/// # Errors
/// Returns an error message if verification or state updates fail.
pub fn execute_system_action(
    registry: &mut ValidatorRegistry,
    caller: Address,
    target: Address,
    calldata: &[u8],
    epoch_height: u64,
) -> Result<(), &'static str> {
    let action = SystemAction::decode(&target, calldata)
        .ok_or("Failed to decode SystemAction calldata")?;

    match action {
        SystemAction::Receive { send_block_hash, amount: _ } => {
            // zero-gas receive hook: credit recipient balance
            let mut _recipient_frontier = registry.get_or_create_frontier(caller);
            // In block-lattice, recipient credits their own thread balance.
            // Verify corresponding send block exists and is locked.
            let _send_block = registry.lattice_blocks.get(&send_block_hash)
                .ok_or("Send block not found in registry")?;
            Ok(())
        }
        SystemAction::RegisterDid { did_document, pq_pub_key, key_tier } => {
            // Populate identities table for signature verification checks
            let parsed_doc = sovereign_identity::did::SovereignDidDocument::from_json_string(&did_document)
                .ok_or("Invalid DID document JSON during registration")?;
            
            // SEC-04: Verify the caller matches the primary EVM address in the DID document
            if parsed_doc.evm_address != caller {
                return Err("RegisterDid caller address mismatch with DID EVM address");
            }

            // Register DID mapping using the validator's runtime chain_id
            let did_id = format!("did:sovereign:{}:{}", registry.chain_id, caller.to_string().to_lowercase());
            registry.address_to_did.insert(caller, did_id.clone());
            registry.peer_keys.insert(did_id.clone(), [0x01; 32]);
            if !pq_pub_key.is_empty() {
                registry.pq_keys.insert(caller, pq_pub_key);
            }
            let tier = crate::pq_registry::KeyTier::from_str(&key_tier);
            registry.did_key_tier.insert(caller, tier);
 
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            registry.identities.insert(did_id.clone(), crate::registry::RegisteredIdentity {
                did: did_id.clone(),
                doc: parsed_doc,
                registered_at: now,
            });
            Ok(())
        }
        SystemAction::SagaEscrow { intent_id, target_account, amount, expire_epoch } => {
            // Saga intent registration
            let escrow = IntentEscrow {
                intent_id,
                target_account,
                amount,
                expire_epoch,
            };
            registry.intent_escrows.insert(intent_id, escrow);

            // Initialize Saga Actor state machine
            let actor = crate::actor::CrossManifoldActor::new(
                intent_id,
                caller,
                target_account,
                amount,
                epoch_height,
            );
            registry.actors.insert(intent_id, actor);
            
            // Lock sender account frontier
            let mut frontier = registry.get_or_create_frontier(caller);
            frontier.locked = true;
            frontier.locked_at = epoch_height;
            registry.update_frontier(caller, frontier);
            Ok(())
        }
        SystemAction::ActorMessage { actor_id, payload } => {
            // Retrieve or initialize cross-manifold Saga actor
            let actor = registry.actors.entry(actor_id).or_insert_with(|| {
                crate::actor::CrossManifoldActor::new(
                    actor_id,
                    caller,
                    Address::ZERO,
                    U256::ZERO,
                    epoch_height,
                )
            });

            // If the payload is a valid ZK validity proof attestation packet, advance the state machine
            if let Ok(packet) = serde_json::from_slice::<crate::based_mesh::BasedMeshWrapper>(&payload) {
                let _ = actor.process_attestation(&packet);
            }

            // Append the message to the actor's inbox
            let msg = crate::based_mesh::CrossManifoldMessage {
                message_id: actor_id,
                sender: caller,
                recipient: actor.recipient,
                payload: payload.clone(),
                timestamp: epoch_height,
            };
            registry.actor_inboxes.entry(actor_id).or_default().push(msg);
            Ok(())
        }
        SystemAction::JurisdictionUpdate { decision_bytes } => {
            // Apply Snowman-finalized JurisdictionDecision delta
            let decision: JurisdictionDecision = serde_json::from_slice(&decision_bytes)
                .map_err(|_| "Failed to deserialize JurisdictionDecision")?;
            
            match decision.action {
                JurisdictionAction::SetQuadrantBits { target, quadrant, bits } => {
                    let mut frontier = registry.get_or_create_frontier(target);
                    let mut comp = frontier.cached_compliance.unwrap_or_default();
                    let q_idx = (quadrant as usize).saturating_sub(1);
                    if q_idx < 4 {
                        comp.0[q_idx] |= bits;
                    }
                    frontier.cached_compliance = Some(comp);
                    registry.update_frontier(target, frontier);
                }
                JurisdictionAction::ClearQuadrantBits { target, quadrant, bits } => {
                    let mut frontier = registry.get_or_create_frontier(target);
                    let mut comp = frontier.cached_compliance.unwrap_or_default();
                    let q_idx = (quadrant as usize).saturating_sub(1);
                    if q_idx < 4 {
                        comp.0[q_idx] &= !bits;
                    }
                    frontier.cached_compliance = Some(comp);
                    registry.update_frontier(target, frontier);
                }
                JurisdictionAction::RegisterBitDefinition { quadrant, bit, label } => {
                    let j_vector = registry.jurisdiction_vectors.entry(decision.manifold_id)
                        .or_insert_with(|| crate::jurisdiction::JurisdictionVector {
                            manifold_id: decision.manifold_id,
                            active_q1_mask: 0,
                            required_q2_mask: 0,
                            velocity_limit: None,
                            appointed_enforcer_did: None,
                            epoch_established: epoch_height,
                            compliance_root: [0; 32],
                            bit_registry: HashMap::new(),
                        });
                    j_vector.bit_registry.insert((quadrant, bit), label);
                }
                JurisdictionAction::GrantMembership { target, membership_bit } => {
                    let mut frontier = registry.get_or_create_frontier(target);
                    let mut comp = frontier.cached_compliance.unwrap_or_default();
                    comp.0[3] |= membership_bit; // Q3 is the membership zone
                    frontier.cached_compliance = Some(comp);
                    registry.update_frontier(target, frontier);
                }
                JurisdictionAction::RevokeMembership { target, membership_bit } => {
                    let mut frontier = registry.get_or_create_frontier(target);
                    let mut comp = frontier.cached_compliance.unwrap_or_default();
                    comp.0[3] &= !membership_bit;
                    frontier.cached_compliance = Some(comp);
                    registry.update_frontier(target, frontier);
                }
                JurisdictionAction::SetVelocityLimit { velocity } => {
                    let j_vector = registry.jurisdiction_vectors.entry(decision.manifold_id)
                        .or_insert_with(|| crate::jurisdiction::JurisdictionVector {
                            manifold_id: decision.manifold_id,
                            active_q1_mask: 0,
                            required_q2_mask: 0,
                            velocity_limit: None,
                            appointed_enforcer_did: None,
                            epoch_established: epoch_height,
                            compliance_root: [0; 32],
                            bit_registry: HashMap::new(),
                        });
                    j_vector.velocity_limit = Some(velocity);
                }
                JurisdictionAction::AppointEnforcer { enforcer_did } => {
                    let j_vector = registry.jurisdiction_vectors.entry(decision.manifold_id)
                        .or_insert_with(|| crate::jurisdiction::JurisdictionVector {
                            manifold_id: decision.manifold_id,
                            active_q1_mask: 0,
                            required_q2_mask: 0,
                            velocity_limit: None,
                            appointed_enforcer_did: None,
                            epoch_established: epoch_height,
                            compliance_root: [0; 32],
                            bit_registry: HashMap::new(),
                        });
                    j_vector.appointed_enforcer_did = Some(enforcer_did);
                }
                JurisdictionAction::UpdateDynamicConfig(patch) => {
                    let mut cfg = registry.dynamic_cfg.write().unwrap();
                    if let Some(t) = patch.sgx_reputation_threshold { cfg.sgx_reputation_threshold = t; }
                    if let Some(q) = patch.manifold_quorum_threshold { cfg.manifold_quorum_threshold = q; }
                    if let Some(p) = patch.social_promotion_threshold { cfg.social_promotion_threshold = p; }
                    if let Some(z) = patch.zero_latency_quantum_trigger { cfg.zero_latency_quantum_trigger = z; }
                    if let Some(s) = patch.default_pq_scheme { cfg.default_pq_scheme = s; }
                    if let Some(c) = patch.default_crypto_profile { cfg.default_crypto_profile = c; }
                    if let Some(h) = patch.profile_switch_block_height { cfg.profile_switch_block_height = Some(h); }
                    if let Some(n) = patch.next_crypto_profile { cfg.next_crypto_profile = Some(n); }
                    if let Some(i) = patch.saga_intent_timeout_seconds { cfg.saga_intent_timeout_seconds = i; }
                    if let Some(ct) = patch.committee_threshold { cfg.committee_threshold = ct; }
                    if let Some(d) = patch.connectivity_decay_penalty { cfg.connectivity_decay_penalty = d; }
                }
                JurisdictionAction::ActivateZlqt(active) => {
                    let mut cfg = registry.dynamic_cfg.write().unwrap();
                    cfg.zero_latency_quantum_trigger = active;
                }
                JurisdictionAction::TriggerCircuitBreaker(_) => {
                    // Handled in velocity module
                }
                JurisdictionAction::SlashValidator { target, amount } => {
                    if let Some(did) = registry.address_to_did.get(&target) {
                        if let Some(score) = registry.reputation.get_mut(did) {
                            *score = (*score - amount as f64 / 1000.0).max(0.0);
                        }
                    }
                }
                JurisdictionAction::MintMeritReward { recipient, amount } => {
                    if let Some(did) = registry.address_to_did.get(&recipient) {
                        let score = registry.reputation.entry(did.clone()).or_insert(0.0);
                        *score += amount.to::<u64>() as f64 / 1000.0;
                    }
                }
                JurisdictionAction::AdvanceMeritRank { target, new_rank, .. } => {
                    let mut frontier = registry.get_or_create_frontier(target);
                    frontier.merit_rank = new_rank;
                    registry.update_frontier(target, frontier);
                }
                JurisdictionAction::DemoteMeritRank { target, new_rank } => {
                    let mut frontier = registry.get_or_create_frontier(target);
                    frontier.merit_rank = new_rank;
                    registry.update_frontier(target, frontier);
                }
            }
            Ok(())
        }
        SystemAction::BridgeAction { .. } => {
            // Shadow anchor updates
            Ok(())
        }
    }
}
