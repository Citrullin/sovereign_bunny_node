//! Stateless witness structures and ephemeral execution caches.

use std::collections::HashMap;
use alloy_primitives::{Address, B256, U256};

/// Static Witness Proof for STATICCALL validation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StaticWitnessProof {
    pub target_account: Address,
    pub state_root: B256,
    pub proof_data: Vec<u8>,
    /// Caller's compliance vector snapshot
    pub quadrant_matrix: [u64; 4],
    /// Verkle opening of Compliance Filter Stem leaf
    pub compliance_proof: Vec<u8>,
}

/// Verkle tree vector commitment proof (EIP-6800).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VerkleNodeProof {
    /// Stem (31 bytes: Address + Storage Key Prefix)
    pub stem: [u8; 31],
    /// Commit point (Bandersnatch curve point)
    pub commit_point: [u8; 32],
    /// Suffix Index (0 - 255)
    pub suffix_index: u8,
    /// Value (32 bytes)
    pub value: [u8; 32],
}

/// Witness details for a single account.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountWitness {
    /// Account balance
    pub balance: U256,
    /// Account nonce
    pub nonce: u64,
    /// Account code hash
    pub code_hash: B256,
    /// Account code byte commitment
    pub code: Vec<u8>,
    /// Quadrant matrix for compliance [Q0, Q1, Q2, Q3]
    pub quadrant_matrix: [u64; 4],
}

/// A stateless database that satisfies storage reads entirely using a pre-populated witness cache.
#[derive(Debug, Clone, Default)]
pub struct WitnessDatabase {
    /// Account states pre-populated from the witness.
    pub accounts: HashMap<Address, AccountWitness>,
    /// Storage slots pre-populated from the witness.
    pub storage: HashMap<Address, HashMap<U256, U256>>,
    /// Verkle proofs associated with the witness.
    pub verkle_proofs: Vec<VerkleNodeProof>,
}

impl scale::Encode for StaticWitnessProof {
    fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
        self.target_account.0.encode_to(dest);
        self.state_root.0.encode_to(dest);
        self.proof_data.encode_to(dest);
        self.quadrant_matrix.encode_to(dest);
        self.compliance_proof.encode_to(dest);
    }
}

impl scale::Decode for StaticWitnessProof {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let target_account = Address::from(<[u8; 20]>::decode(input)?);
        let state_root = B256::from(<[u8; 32]>::decode(input)?);
        let proof_data = Vec::<u8>::decode(input)?;
        let quadrant_matrix = <[u64; 4]>::decode(input)?;
        let compliance_proof = Vec::<u8>::decode(input)?;
        Ok(StaticWitnessProof {
            target_account,
            state_root,
            proof_data,
            quadrant_matrix,
            compliance_proof,
        })
    }
}

impl scale::Encode for VerkleNodeProof {
    fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
        self.stem.encode_to(dest);
        self.commit_point.encode_to(dest);
        self.suffix_index.encode_to(dest);
        self.value.encode_to(dest);
    }
}

impl scale::Decode for VerkleNodeProof {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let stem = <[u8; 31]>::decode(input)?;
        let commit_point = <[u8; 32]>::decode(input)?;
        let suffix_index = u8::decode(input)?;
        let value = <[u8; 32]>::decode(input)?;
        Ok(VerkleNodeProof {
            stem,
            commit_point,
            suffix_index,
            value,
        })
    }
}

impl scale::Encode for AccountWitness {
    fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
        self.balance.to_be_bytes::<32>().encode_to(dest);
        self.nonce.encode_to(dest);
        self.code_hash.0.encode_to(dest);
        self.code.encode_to(dest);
        self.quadrant_matrix.encode_to(dest);
    }
}

impl scale::Decode for AccountWitness {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let balance_bytes = <[u8; 32]>::decode(input)?;
        let balance = U256::from_be_bytes(balance_bytes);
        let nonce = u64::decode(input)?;
        let code_hash = B256::from(<[u8; 32]>::decode(input)?);
        let code = Vec::<u8>::decode(input)?;
        let quadrant_matrix = <[u64; 4]>::decode(input)?;
        Ok(AccountWitness {
            balance,
            nonce,
            code_hash,
            code,
            quadrant_matrix,
        })
    }
}
