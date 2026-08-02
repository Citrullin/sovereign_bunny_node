//! Cross-Manifold Actor System (Distributed Saga Intent Pattern).
//! Handles multi-manifold transaction state machines: INITIATE_INTENT -> PREPARE_EXECUTION -> COMMIT / ROLLBACK.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// Discrete execution states for a Cross-Manifold Transaction Actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorState {
    /// Cross-chain intent initiated.
    InitiateIntent,
    /// Target manifold preparing execution and checking attestation.
    PrepareExecution,
    /// Transaction committed successfully.
    Commit,
    /// Execution failed or timed out; intent rolled back.
    Rollback,
}

/// A Cross-Manifold Distributed Actor instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossManifoldActor {
    /// Unique Actor / Intent ID.
    pub actor_id: B256,
    /// Current state of the Saga state machine.
    pub state: ActorState,
    /// Source manifold address.
    pub sender: Address,
    /// Target manifold address.
    pub recipient: Address,
    /// Intended token amount.
    pub amount: U256,
    /// Intent creation timestamp.
    pub created_at: u64,
    /// Expiration window in seconds.
    pub timeout_seconds: u64,
}

impl CrossManifoldActor {
    /// Initializes a new Cross-Manifold Actor in `InitiateIntent` state.
    pub fn new(actor_id: B256, sender: Address, recipient: Address, amount: U256, current_time: u64) -> Self {
        let registry_lock = crate::registry::get_registry();
        let timeout = if let Ok(reg) = registry_lock.read() {
            reg.dynamic_cfg.read().unwrap().saga_intent_timeout_seconds
        } else {
            86400
        };

        Self {
            actor_id,
            state: ActorState::InitiateIntent,
            sender,
            recipient,
            amount,
            created_at: current_time,
            timeout_seconds: timeout,
        }
    }

    /// Advances the state machine to `PREPARE_EXECUTION`.
    ///
    /// # Errors
    /// Returns an error if transition is invalid.
    pub fn prepare(&mut self) -> Result<(), &'static str> {
        if self.state != ActorState::InitiateIntent {
            return Err("Invalid state transition to PrepareExecution");
        }
        self.state = ActorState::PrepareExecution;
        Ok(())
    }

    /// Commits the transaction trajectory upon verified target execution.
    ///
    /// # Errors
    /// Returns an error if transition is invalid.
    pub fn commit(&mut self) -> Result<(), &'static str> {
        if self.state != ActorState::PrepareExecution {
            return Err("Invalid state transition to Commit");
        }
        self.state = ActorState::Commit;
        Ok(())
    }

    /// Triggers an automated Rollback, reverting the intent.
    pub fn rollback(&mut self) {
        self.state = ActorState::Rollback;
    }

    /// Evaluates timeout conditions and auto-triggers Rollback if expired.
    pub fn evaluate_timeout(&mut self, current_time: u64) -> bool {
        let registry_lock = crate::registry::get_registry();
        let timeout = if let Ok(reg) = registry_lock.read() {
            reg.dynamic_cfg.read().unwrap().saga_intent_timeout_seconds
        } else {
            self.timeout_seconds
        };

        if self.state != ActorState::Commit && current_time > (self.created_at + timeout) {
            self.rollback();
            true
        } else {
            false
        }
    }

    /// Generates a cross-manifold attestation packet to trigger execution preparation on the target manifold.
    ///
    /// # Errors
    /// Returns an error if the actor state is not `InitiateIntent` or serialization fails.
    pub fn emit_prepare_attestation(
        &self,
        source_manifold_id: u64,
        target_manifold_id: u64,
        state_diff_blob_hash: B256,
        proof_scheme: crate::based_mesh::ProofScheme,
        attestation_proof: Vec<u8>,
    ) -> Result<crate::based_mesh::BasedMeshWrapper, &'static str> {
        if self.state != ActorState::InitiateIntent {
            return Err("Cannot emit prepare attestation: actor is not in InitiateIntent state");
        }

        // Encode actor state transition detail as the payload
        let payload = serde_json::to_vec(self)
            .map_err(|_| "Failed to serialize actor state for cross-manifold message")?;

        let message = crate::based_mesh::CrossManifoldMessage {
            message_id: self.actor_id,
            sender: self.sender,
            recipient: self.recipient,
            payload,
            timestamp: self.created_at,
        };

        crate::based_mesh::BasedMeshWrapper::from_message(
            source_manifold_id,
            target_manifold_id,
            state_diff_blob_hash,
            proof_scheme,
            attestation_proof,
            &message,
        )
    }

    /// Processes an incoming attestation packet, verifying the ZK validity proof and advancing the actor state machine.
    ///
    /// # Errors
    /// Returns an error if the attestation proof fails to verify or the message payload is invalid.
    pub fn process_attestation(
        &mut self,
        packet: &crate::based_mesh::BasedMeshWrapper,
    ) -> Result<(), &'static str> {
        // Extract the embedded message (this verifies the ZK validity proof)
        let message = packet.extract_message()?;

        if message.message_id != self.actor_id {
            return Err("Attestation message ID does not match actor ID");
        }

        // Deserialize the payload to check/validate the actor state transition
        let remote_actor: Self = serde_json::from_slice(&message.payload)
            .map_err(|_| "Failed to deserialize actor state payload")?;

        if remote_actor.sender != self.sender || remote_actor.recipient != self.recipient || remote_actor.amount != self.amount {
            return Err("Attestation actor state parameters do not match local actor state");
        }

        // Advance state machine based on packet information
        match self.state {
            ActorState::InitiateIntent => {
                self.prepare()?;
            }
            ActorState::PrepareExecution => {
                self.commit()?;
            }
            ActorState::Commit | ActorState::Rollback => {
                return Err("Actor is already in a terminal state");
            }
        }

        Ok(())
    }

    /// Processes an incoming attestation packet, requiring consensus sign-off from the Saga Orchestrators sub-committee.
    ///
    /// # Errors
    /// Returns an error if the consensus threshold is not met, or if signature verification fails.
    pub async fn process_attestation_with_committee(
        &mut self,
        packet: &crate::based_mesh::BasedMeshWrapper,
        committee: &crate::sync_committee::SagaOrchestratorCommittee,
        intent: &crate::sync_committee::SagaIntent,
        quantum_threat: bool,
    ) -> Result<(), &'static str> {
        // Verify consensus from the orchestrator committee
        intent.verify_consensus(committee, quantum_threat).await?;

        // Fallback to standard attestation payload processing
        self.process_attestation(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::based_mesh::ProofScheme;

    #[tokio::test]
    async fn test_cross_manifold_actor_attestation_flow() {
        let actor_id = B256::repeat_byte(0x99);
        let sender = Address::repeat_byte(0x12);
        let recipient = Address::repeat_byte(0x34);
        let amount = U256::from(1000);
        let current_time = 10000;

        // Initialize source actor
        let source_actor = CrossManifoldActor::new(actor_id, sender, recipient, amount, current_time);
        assert_eq!(source_actor.state, ActorState::InitiateIntent);

        let packet = source_actor.emit_prepare_attestation(
            65001,
            65002,
            B256::ZERO,
            ProofScheme::Groth16Bn254,
            vec![0u8; 32], // Valid mock proof length >= 32
        ).unwrap();

        // Initialize target actor (starts in InitiateIntent locally)
        let mut target_actor = CrossManifoldActor::new(actor_id, sender, recipient, amount, current_time);

        // Target actor processes the packet, advancing its state
        target_actor.process_attestation(&packet).unwrap();
        assert_eq!(target_actor.state, ActorState::PrepareExecution);

        // Target actor processes the packet again (simulating confirmation loop)
        // From PrepareExecution, target actor goes to Commit
        target_actor.process_attestation(&packet).unwrap();
        assert_eq!(target_actor.state, ActorState::Commit);
    }
}
