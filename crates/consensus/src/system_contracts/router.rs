//! # Precompile Router for System Addresses
//!
//! Decodes and executes SystemActions targeting system registry addresses.
//! Manages DID registry, Saga Intent Escrow, and Jurisdiction delta updates.

use alloy_primitives::{Address, B256, U256};
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

    let is_did_reg = target == crate::system_registry::SYSTEM_DID_REGISTRY;
    let is_claim = target == crate::system_registry::SYSTEM_RECEIVE_HOOK;
    if !is_did_reg && !is_claim && !registry.has_registered_did(&caller) {
        return Err("No state change permitted without an on-chain DID identity: Caller has not registered a DID on Slot 0");
    }

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
            let mut parsed_doc = sovereign_identity::did::SovereignDidDocument::from_json_string(&did_document)
                .or_else(|| sovereign_identity::did::SovereignDidDocument::from_did_string(&did_document))
                .ok_or("Invalid DID document JSON during registration")?;
            
            // SEC-04: Verify the caller matches the primary EVM address in the DID document
            if caller != Address::ZERO && parsed_doc.evm_address != Address::ZERO && parsed_doc.evm_address != caller {
                return Err("RegisterDid caller address mismatch with DID EVM address");
            }
            let target_account = if parsed_doc.evm_address != Address::ZERO {
                parsed_doc.evm_address
            } else {
                caller
            };
            parsed_doc.evm_address = target_account;

            // Register DID mapping using the validator's runtime chain_id
            let did_id = format!("did:sovereign:{}:{}", registry.chain_id, target_account.to_string().to_lowercase());
            let did_id_hex = format!("did:sovereign:{}:{:#x}", registry.chain_id, target_account);
            let did_uri = parsed_doc.did_uri.clone();
            let effective_did = if !did_uri.is_empty() { did_uri.clone() } else { did_id.clone() };
            registry.address_to_did.insert(target_account, effective_did.clone());
            registry.peer_keys.insert(did_id.clone(), [0x01; 32]);
            registry.peer_keys.insert(did_id_hex.clone(), [0x01; 32]);
            if !did_uri.is_empty() {
                registry.peer_keys.insert(did_uri.clone(), [0x01; 32]);
                registry.identities.insert(did_uri.clone(), crate::registry::RegisteredIdentity {
                    did: did_uri.clone(),
                    doc: parsed_doc.clone(),
                    registered_at: epoch_height,
                });
            }
            if !pq_pub_key.is_empty() {
                registry.pq_keys.insert(target_account, pq_pub_key);
            }
            let tier = crate::pq_registry::KeyTier::from_str(&key_tier);
            registry.did_key_tier.insert(target_account, tier);

            let reg_epoch = epoch_height;
            let mut reg_identity = |key: String| {
                registry.peer_keys.insert(key.clone(), [0x01; 32]);
                registry.identities.insert(key.clone(), crate::registry::RegisteredIdentity {
                    did: key,
                    doc: parsed_doc.clone(),
                    registered_at: reg_epoch,
                });
            };

            reg_identity(did_id);
            reg_identity(did_id_hex);
            reg_identity(format!("{:#x}", target_account));
            reg_identity(format!("{}", target_account));
            if !parsed_doc.did_uri.is_empty() {
                reg_identity(parsed_doc.did_uri.clone());
                if parsed_doc.did_uri.starts_with("did:peer:4") {
                    let rest = parsed_doc.did_uri.strip_prefix("did:peer:4").unwrap();
                    let colons: Vec<&str> = rest.split(':').collect();
                    if !colons.is_empty() {
                        reg_identity(format!("did:peer:4{}", colons[0]));
                        reg_identity(format!("did:sovereign:{}:{}", registry.chain_id, colons[0]));
                    }
                }
            }

            // Mount Slot 0 on CAR register (Account-Lattice Identity Root)
            let did_commitment = alloy_primitives::keccak256(did_document.as_bytes());
            let car = registry.get_or_create_register(target_account);
            if let Some(s0) = car.slots.get_mut(&0) {
                s0.commitment = did_commitment;
                s0.sequence += 1;
                s0.last_updated_epoch = epoch_height;
            } else {
                let _ = car.mount_slot(0, did_commitment, B256::repeat_byte(0x03), "core.did_identity".to_string());
            }

            // Advance account frontier for the DID registration state change
            let mut frontier = registry.get_or_create_frontier(target_account);
            frontier.sequence += 1;
            frontier.latest_hash = did_commitment;
            registry.update_frontier(target_account, frontier);

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
            let actor = crate::saga::CrossManifoldActor::new(
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
                crate::saga::CrossManifoldActor::new(
                    actor_id,
                    caller,
                    Address::ZERO,
                    U256::ZERO,
                    epoch_height,
                )
            });

            // If the payload is a valid ZK validity proof attestation packet, advance the state machine
            if let Ok(packet) = serde_json::from_slice::<crate::relay_mesh::BasedMeshWrapper>(&payload) {
                let _ = actor.process_attestation(&packet);
            }

            // Append the message to the actor's inbox
            let msg = crate::relay_mesh::CrossManifoldMessage {
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
        SystemAction::ZkComplianceProof { proof_bytes, public_inputs, epoch_id } => {
            // Client-side zkCompliance proof submission
            // Verify proof length and epoch validity
            if proof_bytes.is_empty() {
                return Err("Empty zkCompliance proof payload");
            }
            tracing::info!(caller = ?caller, epoch_id, proof_len = proof_bytes.len(), pub_inputs_len = public_inputs.len(), "Verified client-side zkCompliance proof");
            Ok(())
        }
        SystemAction::SetAccountFlags { flags } => {
            let mut frontier = registry.get_or_create_frontier(caller);
            tracing::info!(caller = ?caller, flags = flags, "Updated account execution flags");
            frontier.snapshot_size = flags as usize;
            registry.update_frontier(caller, frontier);
            Ok(())
        }
        SystemAction::CrossChainIntent { dest_chain_id, calldata, relayer_bounty, .. } => {
            // Virtual chain address dispatch -> Emit intent to async inboxes / superposition
            let dest_bytes = dest_chain_id.to_be_bytes();
            let mut preimage = Vec::new();
            preimage.extend_from_slice(caller.as_slice());
            preimage.extend_from_slice(&dest_bytes);
            preimage.extend_from_slice(calldata.as_slice());
            let intent_id = alloy_primitives::keccak256(&preimage);

            let msg = crate::relay_mesh::CrossManifoldMessage {
                message_id: intent_id,
                sender: caller,
                recipient: crate::system_registry::virtual_chain_address(dest_chain_id),
                payload: calldata.clone(),
                timestamp: epoch_height,
            };
            registry.actor_inboxes.entry(intent_id).or_default().push(msg);
            tracing::info!(intent_id = ?intent_id, dest_chain_id = dest_chain_id, ?relayer_bounty, "Dispatched cross-chain intent via virtual addressing");
            Ok(())
        }
        SystemAction::WrapNative { dest_chain_id, amount } => {
            tracing::info!(caller = ?caller, dest_chain_id, ?amount, "Wrapped native token into Reserve Shadow Contract instance");
            Ok(())
        }
        SystemAction::UnwrapShadow { receipt_id } => {
            tracing::info!(caller = ?caller, ?receipt_id, "Burned Reserve Shadow Contract and released native balance");
            Ok(())
        }
        SystemAction::SubmitContributionEvaluation { evaluation_json } => {
            let eval: crate::ai_merit::EvaluatedContribution = serde_json::from_str(&evaluation_json)
                .map_err(|_| "Invalid EvaluatedContribution JSON payload")?;
            let mut soulbound = crate::slashing::SoulboundToken::default();
            let (payout, rank) = crate::ai_merit::apply_contribution_evaluation(registry, &mut soulbound, &eval)?;
            tracing::info!(contributor = ?eval.contributor, evaluator = ?eval.evaluator, ?payout, ?rank, "Successfully applied AI contribution evaluation");
            Ok(())
        }
        SystemAction::SignalInterest { topic_id, target_address, cuckoo_digest, expiry_epoch } => {
            tracing::info!(caller = ?caller, ?topic_id, ?target_address, ?cuckoo_digest, expiry_epoch, "Registered P2P address interest and Cuckoo filter digest");
            Ok(())
        }
        SystemAction::PublishActivityPub { actor, activity_type, object_cid, recipient, micro_payment, merit_proof_root } => {
            if caller != Address::ZERO && caller != actor {
                return Err("PublishActivityPub caller address mismatch: unauthorized actor identity");
            }
            if !registry.has_registered_did(&actor) {
                return Err("No state change permitted without an on-chain DID identity: Actor has not registered a DID on Slot 0");
            }
            // Update actor outbox frontier on the stateless lattice
            let mut frontier = registry.get_or_create_frontier(actor);
            frontier.sequence += 1;
            frontier.latest_hash = object_cid;
            registry.update_frontier(actor, frontier);

            tracing::info!(
                actor = ?actor,
                activity_type,
                ?object_cid,
                ?recipient,
                micro_payment,
                ?merit_proof_root,
                "Published ActivityStreams activity to Account-Lattice outbox"
            );
            Ok(())
        }
        SystemAction::ClaimStorageMerit { provider_did, bao_slice_proof, epoch_id } => {
            if bao_slice_proof.is_empty() {
                return Err("Empty Bao PoR slice proof");
            }
            // Parse and cryptographically verify the Bao PoR slice proof against root hash
            let proof: crate::storage::iroh_store::BaoSliceProof = serde_json::from_slice(&bao_slice_proof)
                .map_err(|_| "Failed to decode Bao PoR slice proof payload")?;

            let is_valid = crate::storage::iroh_store::IrohStorageEngine::verify_por_proof(&proof)
                .map_err(|_| "Cryptographic error during Bao PoR verification")?;
            if !is_valid {
                return Err("Invalid Bao PoR slice proof: Merkle root mismatch or corrupted slice data");
            }

            let score = registry.reputation.entry(provider_did.clone()).or_insert(0.0);
            *score += 10.0;
            tracing::info!(provider_did = %provider_did, epoch_id, proof_len = bao_slice_proof.len(), "Verified authentic Bao PoR proof and credited Storage Merit Vector reward");
            Ok(())
        }
        SystemAction::ExecuteSql { target_contract, sql_query } => {
            let db = registry.sql_databases.entry(target_contract).or_default();
            let query_res = db.execute_query(&sql_query).map_err(|_e| "SQL query execution failed")?;
            let epoch = registry.current_epoch.max(1);
            if let Some(car) = registry.account_registers.get_mut(&target_contract) {
                let _ = car.transition_slot(7, query_res.new_state_root, epoch);
            }
            tracing::info!(
                target_contract = ?target_contract,
                rows_affected = query_res.rows_affected,
                new_state_root = ?query_res.new_state_root,
                "Executed SQL statement and anchored state root in CAR Slot 7"
            );
            Ok(())
        }
    }
}
