//! Saga Actor State Machine & Cross-Manifold Intent Coordination.
//! Handles multi-manifold transaction state machines: INITIATE_INTENT -> PREPARE_EXECUTION -> COMMIT / ROLLBACK.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// Discrete execution states for a Saga Transaction Actor.
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

/// A Saga Actor instance coordinating distributed intents with rollback capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SagaActor {
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

/// Backward compatibility alias
pub type CrossManifoldActor = SagaActor;

impl SagaActor {
    /// Initializes a new Saga Actor in `InitiateIntent` state.
    pub fn new(actor_id: B256, sender: Address, recipient: Address, amount: U256, current_time: u64) -> Self {
        let registry_lock = crate::registry::get_registry();
        let timeout = if let Ok(reg) = registry_lock.try_read() {
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
    pub fn prepare(&mut self) -> Result<(), &'static str> {
        if self.state != ActorState::InitiateIntent {
            return Err("Invalid state transition to PrepareExecution");
        }
        self.state = ActorState::PrepareExecution;
        Ok(())
    }

    /// Commits the transaction trajectory upon verified target execution.
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
        let timeout = if let Ok(reg) = registry_lock.try_read() {
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
    pub fn emit_prepare_attestation(
        &self,
        source_manifold_id: u64,
        target_manifold_id: u64,
        state_diff_blob_hash: B256,
        proof_scheme: crate::relay_mesh::ProofScheme,
        attestation_proof: Vec<u8>,
    ) -> Result<crate::relay_mesh::BasedMeshWrapper, &'static str> {
        if self.state != ActorState::InitiateIntent {
            return Err("Cannot emit prepare attestation: actor is not in InitiateIntent state");
        }

        let payload = serde_json::to_vec(self)
            .map_err(|_| "Failed to serialize actor state for cross-manifold message")?;

        let message = crate::relay_mesh::CrossManifoldMessage {
            message_id: self.actor_id,
            sender: self.sender,
            recipient: self.recipient,
            payload,
            timestamp: self.created_at,
        };

        crate::relay_mesh::BasedMeshWrapper::from_message(
            source_manifold_id,
            target_manifold_id,
            state_diff_blob_hash,
            proof_scheme,
            attestation_proof,
            &message,
        )
    }

    /// Processes an incoming attestation packet, verifying the ZK validity proof and advancing the actor state machine.
    pub fn process_attestation(
        &mut self,
        packet: &crate::relay_mesh::BasedMeshWrapper,
    ) -> Result<(), &'static str> {
        let message = packet.extract_message()?;

        if message.message_id != self.actor_id {
            return Err("Attestation message ID does not match actor ID");
        }

        let remote_actor: Self = serde_json::from_slice(&message.payload)
            .map_err(|_| "Failed to deserialize actor state payload")?;

        if remote_actor.sender != self.sender || remote_actor.recipient != self.recipient || remote_actor.amount != self.amount {
            return Err("Attestation actor state parameters do not match local actor state");
        }

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

    /// Processes an incoming attestation packet, requiring consensus sign-off from the Relay committee.
    pub async fn process_attestation_with_committee(
        &mut self,
        packet: &crate::relay_mesh::BasedMeshWrapper,
        committee: &crate::cross_chain_committee::CrossChainRelayCommittee,
        intent: &crate::cross_chain_committee::AsyncIntent,
        quantum_threat: bool,
    ) -> Result<(), &'static str> {
        intent.verify_consensus(committee, quantum_threat).await?;
        self.process_attestation(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_mesh::ProofScheme;

    #[tokio::test]
    async fn test_saga_actor_attestation_flow() {
        let actor_id = B256::repeat_byte(0x99);
        let sender = Address::repeat_byte(0x12);
        let recipient = Address::repeat_byte(0x34);
        let amount = U256::from(1000);
        let current_time = 10000;

        let source_actor = SagaActor::new(actor_id, sender, recipient, amount, current_time);
        assert_eq!(source_actor.state, ActorState::InitiateIntent);

        let packet = source_actor.emit_prepare_attestation(
            65001,
            65002,
            B256::ZERO,
            ProofScheme::Groth16Bn254,
            vec![0u8; 32],
        ).unwrap();

        let mut target_actor = SagaActor::new(actor_id, sender, recipient, amount, current_time);
        target_actor.process_attestation(&packet).unwrap();
        assert_eq!(target_actor.state, ActorState::PrepareExecution);

        // Reset nullifier tracking to allow the commit attestation step in unit test
        {
            let registry_lock = crate::registry::get_registry();
            registry_lock.write().unwrap().processed_manifold_messages.clear();
        }

        target_actor.process_attestation(&packet).unwrap();
        assert_eq!(target_actor.state, ActorState::Commit);
    }
}
