use ssz_rs::prelude::*;
use alloy_primitives::{Address, B256};

/// Confidential Intent targeted at system address 0xE3
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct ConfidentialIntent {
    pub epoch_id: u64,
    pub ephemeral_pubkey: Vector<u8, 32>,
    pub caller_nullifier: Vector<u8, 32>,
    pub target_contract: Vector<u8, 20>,
    pub encrypted_payload: List<u8, 2097152>, // Max 2MB encrypted ciphertext
    pub client_zk_proof: List<u8, 65536>,    // Optional client Noir/Groth16 ZK proof
}

impl ConfidentialIntent {
    pub fn target(&self) -> Address {
        Address::from_slice(self.target_contract.as_ref())
    }

    pub fn nullifier(&self) -> B256 {
        B256::from_slice(self.caller_nullifier.as_ref())
    }
}
