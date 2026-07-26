//! Cross-Manifold Actor System (Distributed Saga Rollback Pattern).
//! Handles multi-manifold transaction state machines: LOCK_ASSETS -> PREPARE_EXECUTION -> COMMIT / ROLLBACK.

use alloy_primitives::{Address, B256, U256};

/// Discrete execution states for a Cross-Manifold Transaction Actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorState {
    /// Assets locked in source escrow contract with a 1-day time-lock.
    LockAssets,
    /// Target manifold preparing execution and checking attestation.
    PrepareExecution,
    /// Transaction committed successfully; escrow released.
    Commit,
    /// Execution failed or timed out; escrow unlocked back to sender.
    Rollback,
}

/// A Cross-Manifold Distributed Actor instance.
#[derive(Debug, Clone)]
pub struct CrossManifoldActor {
    /// Unique Actor / Intent ID.
    pub actor_id: B256,
    /// Current state of the Saga state machine.
    pub state: ActorState,
    /// Source manifold address.
    pub sender: Address,
    /// Target manifold address.
    pub recipient: Address,
    /// Locked token amount.
    pub amount: U256,
    /// Lock creation timestamp.
    pub created_at: u64,
    /// Expiration window (86400 seconds = 1 day).
    pub timeout_seconds: u64,
}

impl CrossManifoldActor {
    /// Initializes a new Cross-Manifold Actor in `LOCK_ASSETS` state.
    pub fn new(actor_id: B256, sender: Address, recipient: Address, amount: U256, current_time: u64) -> Self {
        Self {
            actor_id,
            state: ActorState::LockAssets,
            sender,
            recipient,
            amount,
            created_at: current_time,
            timeout_seconds: 86400,
        }
    }

    /// Advances the state machine to `PREPARE_EXECUTION`.
    ///
    /// # Errors
    /// Returns an error if transition is invalid.
    pub fn prepare(&mut self) -> Result<(), &'static str> {
        if self.state != ActorState::LockAssets {
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

    /// Triggers an automated Rollback, unlocking escrowed funds back to the sender.
    pub fn rollback(&mut self) {
        self.state = ActorState::Rollback;
    }

    /// Evaluates timeout conditions and auto-triggers Rollback if expired.
    pub fn evaluate_timeout(&mut self, current_time: u64) -> bool {
        if self.state != ActorState::Commit && current_time > (self.created_at + self.timeout_seconds) {
            self.rollback();
            true
        } else {
            false
        }
    }
}
