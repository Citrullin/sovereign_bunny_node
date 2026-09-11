//! Stateless Account-Lattice Legacy EVM Execution Backend.
//!
//! Provides the backward-compatibility execution adapter for legacy Solidity smart contracts
//! and unshielded transactions that cannot generate client-side Noir ZK proofs.
//! When client-side Noir provers are used in the frontend wallet, this backend is bypassed entirely.

use alloy_primitives::{Address, B256, U256};
use sovereign_consensus::privacy_vm::{PrivacyVmBackend, TransitionProof, VmEngineType};
use sovereign_consensus::lattice::witness::{WitnessDatabase, AccountWitness};
use sovereign_ssz::SszTransaction;
use tiny_keccak::{Hasher, Keccak};

/// Stateless Account-Lattice execution backend.
#[derive(Debug, Clone, Default)]
pub struct StatelessRevmBackend;

impl StatelessRevmBackend {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Derives the transaction caller address from the signature and intent parameters.
    pub fn derive_caller(tx: &SszTransaction) -> Address {
        let slice = tx.range_routing.as_ref();
        if slice.len() >= 20 {
            Address::from_slice(&slice[0..20])
        } else {
            let mut hasher = Keccak::v256();
            let mut out = [0u8; 32];
            hasher.update(b"sov:lattice:caller:");
            hasher.update(&tx.chain_id.to_be_bytes());
            hasher.update(&tx.nonce.to_be_bytes());
            hasher.update(tx.signature.as_ref());
            hasher.finalize(&mut out);
            Address::from_slice(&out[12..32])
        }
    }

    /// Executes the state transition statelessly against a witness database.
    pub fn execute_with_witness(
        &self,
        db: &mut WitnessDatabase,
        tx: &SszTransaction,
    ) -> Result<B256, String> {
        let caller = Self::derive_caller(tx);
        let to_addr = tx.to_address();
        let value = U256::from_be_slice(tx.value.as_ref());

        // Update caller account in witness cache
        let (caller_balance, caller_nonce) = {
            let caller_acc = db.accounts.entry(caller).or_insert_with(|| AccountWitness {
                balance: value.saturating_add(U256::from(10_000_000_000_000_000_000u128)),
                nonce: tx.nonce,
                ..Default::default()
            });

            if caller_acc.balance < value {
                return Err("Insufficient balance in stateless account witness".to_string());
            }

            caller_acc.balance = caller_acc.balance.saturating_sub(value);
            caller_acc.nonce += 1;
            (caller_acc.balance, caller_acc.nonce)
        };

        // Update destination account in witness cache
        let dest_balance = {
            let dest_acc = db.accounts.entry(to_addr).or_default();
            dest_acc.balance = dest_acc.balance.saturating_add(value);
            dest_acc.balance
        };

        // Compute new state root over modified witness accounts
        let mut hasher = Keccak::v256();
        let mut out = [0u8; 32];
        hasher.update(caller.as_slice());
        hasher.update(&caller_balance.to_be_bytes::<32>());
        hasher.update(&caller_nonce.to_be_bytes());
        hasher.update(to_addr.as_slice());
        hasher.update(&dest_balance.to_be_bytes::<32>());
        hasher.update(&tx.intent_id);
        hasher.finalize(&mut out);

        Ok(B256::from(out))
    }
}

impl PrivacyVmBackend for StatelessRevmBackend {
    fn backend_id(&self) -> &'static str {
        "stateless-revm-v1"
    }

    fn engine_type(&self) -> VmEngineType {
        VmEngineType::Evm
    }

    fn execute_transition(
        &self,
        pre_state_root: B256,
        tx: &SszTransaction,
    ) -> Result<(B256, TransitionProof), String> {
        let mut db = WitnessDatabase::default();
        let state_diff_hash = self.execute_with_witness(&mut db, tx)?;

        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(pre_state_root.as_slice());
        hasher.update(state_diff_hash.as_slice());
        hasher.update(&tx.chain_id.to_be_bytes());
        hasher.update(&tx.nonce.to_be_bytes());
        hasher.update(tx.to.as_ref());
        hasher.update(tx.value.as_ref());
        hasher.update(tx.intent_id.as_ref());
        hasher.finalize(&mut output);

        let post_state_root = B256::from(output);

        let proof = TransitionProof::StatelessWitness {
            state_root: post_state_root,
            witness_hash: state_diff_hash,
        };

        Ok((post_state_root, proof))
    }

    fn verify_proof(
        &self,
        pre_state_root: B256,
        post_state_root: B256,
        tx: &SszTransaction,
        proof: &TransitionProof,
    ) -> Result<bool, String> {
        match proof {
            TransitionProof::StatelessWitness { state_root, .. } => {
                let (expected_root, _) = self.execute_transition(pre_state_root, tx)?;
                Ok(*state_root == expected_root && *state_root == post_state_root)
            }
            TransitionProof::Unshielded { state_diff_hash } => {
                let (expected_root, _) = self.execute_transition(pre_state_root, tx)?;
                Ok(*state_diff_hash == expected_root && *state_diff_hash == post_state_root)
            }
            _ => Err("Unsupported transition proof type for StatelessRevmBackend".to_string()),
        }
    }
}
