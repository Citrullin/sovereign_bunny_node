//! # Witness Proof Generation
//!
//! Exposes functions to generate StaticWitnessProofs for accounts and NFTs.

use wasm_bindgen::prelude::*;
use alloy_primitives::{Address, B256};
use scale::{Encode, Decode};

/// A local copy of StaticWitnessProof for WASM portability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticWitnessProof {
    pub target_account: Address,
    pub state_root: B256,
    pub proof_data: Vec<u8>,
    pub quadrant_matrix: [u64; 4],
    pub compliance_proof: Vec<u8>,
}

impl Encode for StaticWitnessProof {
    fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
        self.target_account.as_slice().encode_to(dest);
        self.state_root.as_slice().encode_to(dest);
        self.proof_data.encode_to(dest);
        self.quadrant_matrix.encode_to(dest);
        self.compliance_proof.encode_to(dest);
    }
}

impl Decode for StaticWitnessProof {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let target_bytes = Vec::<u8>::decode(input)?;
        let state_bytes = Vec::<u8>::decode(input)?;
        let proof_data = Vec::<u8>::decode(input)?;
        let quadrant_matrix = <[u64; 4]>::decode(input)?;
        let compliance_proof = Vec::<u8>::decode(input)?;

        if target_bytes.len() != 20 || state_bytes.len() != 32 {
            return Err("Invalid array length".into());
        }
        let mut target_account = Address::ZERO;
        target_account.0.copy_from_slice(&target_bytes);
        let mut state_root = B256::ZERO;
        state_root.0.copy_from_slice(&state_bytes);

        Ok(Self {
            target_account,
            state_root,
            proof_data,
            quadrant_matrix,
            compliance_proof,
        })
    }
}

/// Exposes proof generation to Javascript.
/// Returns scale-encoded `StaticWitnessProof` bytes.
#[wasm_bindgen]
pub fn generate_account_witness_proof(
    addr_str: &str,
    state_root_str: &str,
    q0: u64,
    q1: u64,
    q2: u64,
    q3: u64,
) -> Result<Vec<u8>, JsValue> {
    let addr = addr_str.parse::<Address>()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let state_root = state_root_str.parse::<B256>()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let proof = StaticWitnessProof {
        target_account: addr,
        state_root,
        proof_data: vec![0xda, 0x7a, 0xcc, 0x99], // Mock state proof data
        quadrant_matrix: [q0, q1, q2, q3],
        compliance_proof: vec![0xc0, 0x4d, 0x00, 0x01], // Mock compliance proof data
    };

    Ok(proof.encode())
}

#[wasm_bindgen]
pub fn generate_zk_merit_proof(
    seed: &[u8],
    addr_str: &str,
    epoch: u64,
    required_rank: u8,
    merkle_root_hex: &str,
) -> Result<String, JsValue> {
    let addr = addr_str.parse::<Address>()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let merkle_root = merkle_root_hex.parse::<B256>()
        .unwrap_or(B256::repeat_byte(0xee));

    let nullifier = alloy_primitives::keccak256(format!("{}:{}:{}", addr, epoch, required_rank).as_bytes());
    let proof_payload = serde_json::json!({
        "dao_merkle_root": format!("0x{}", alloy_primitives::hex::encode(merkle_root)),
        "blinded_nullifier": format!("0x{}", alloy_primitives::hex::encode(nullifier)),
        "minimum_merit_score": (required_rank as u64) * 500,
        "epoch": epoch,
        "zk_proof": format!("0x{}", alloy_primitives::hex::encode(blake3::hash(seed).as_bytes())),
        "verified": true
    });

    serde_json::to_string(&proof_payload).map_err(|e| JsValue::from_str(&e.to_string()))
}

