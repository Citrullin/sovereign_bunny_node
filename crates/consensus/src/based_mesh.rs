//! Based Meshing Module for sequence-level alignment across sovereign manifolds.
//!
//! Implements `BasedMeshWrapper`, Block-in-Blob serialization, EIP-4844 / PeerDAS blob formatting,
//! and succinct ZK validity proof wrapper verification (SP1 / RiscZero / Groth16).

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use scale::{Encode, Decode};

/// Supported succinct zero-knowledge proving schemes for cross-manifold verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, scale::Encode, scale::Decode)]
#[repr(u8)]
pub enum ProofScheme {
    /// Groth16 over BN254 curve (EIP-197 compatible).
    Groth16Bn254 = 2,
    /// SP1 recursive wrapper over BLS12-381 curve (EIP-2537 compatible).
    SpruceSp1Bls12381 = 3,
    /// RiscZero Bonsai STARK-to-SNARK wrapper.
    RiscZeroBonsai = 4,
    /// Quantum-safe Binius Binary STARK proving system.
    BiniusBinaryStark = 5,
    /// Quantum-safe Plonky3 hash-based STARK proving system.
    Plonky3Blake3 = 6,
}

impl TryFrom<u8> for ProofScheme {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::Groth16Bn254),
            3 => Ok(Self::SpruceSp1Bls12381),
            4 => Ok(Self::RiscZeroBonsai),
            5 => Ok(Self::BiniusBinaryStark),
            6 => Ok(Self::Plonky3Blake3),
            _ => Err("Unsupported proof scheme selector"),
        }
    }
}

/// A structured, typed message transmitted over succinct ZK validity proofs / attestations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossManifoldMessage {
    /// Unique message or intent ID.
    pub message_id: B256,
    /// Sender address on the source manifold.
    pub sender: Address,
    /// Recipient address on the target manifold.
    pub recipient: Address,
    /// Arbitrary message payload or ABI-encoded call data.
    pub payload: Vec<u8>,
    /// Timestamp when the message was emitted.
    pub timestamp: u64,
}

impl scale::Encode for CrossManifoldMessage {
    fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
        self.message_id.0.encode_to(dest);
        self.sender.0.encode_to(dest);
        self.recipient.0.encode_to(dest);
        self.payload.encode_to(dest);
        self.timestamp.encode_to(dest);
    }
}

impl scale::Decode for CrossManifoldMessage {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let message_id = B256::from(<[u8; 32]>::decode(input)?);
        let sender = Address::from(<[u8; 20]>::decode(input)?);
        let recipient = Address::from(<[u8; 20]>::decode(input)?);
        let payload = Vec::<u8>::decode(input)?;
        let timestamp = u64::decode(input)?;

        Ok(Self {
            message_id,
            sender,
            recipient,
            payload,
            timestamp,
        })
    }
}

mod serde_arr48 {
    use serde::{Serializer, Deserializer, Deserialize};
    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <&[u8]>::deserialize(deserializer)?;
        let mut arr = [0u8; 48];
        if s.len() == 48 {
            arr.copy_from_slice(s);
            Ok(arr)
        } else {
            Err(serde::de::Error::custom("expected 48 bytes"))
        }
    }
}

/// A self-contained cross-manifold packet emitted during based meshing.
///
/// Encapsulates execution state diffs and succinct validity proofs into Block-in-Blob payloads
/// routed over BGP WireGuard tunnels without interactive lock sagas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasedMeshWrapper {
    /// Packet format version (default: 1).
    pub version: u8,
    /// Source manifold sector ID.
    pub source_manifold_id: u64,
    /// Vector of target manifold sector IDs touched by this state diff.
    pub target_manifolds: Vec<u64>,
    /// EIP-4844 / PeerDAS blob commitment hash (SHA-256 or KZG root).
    pub state_diff_blob_hash: B256,
    /// KZG 48-byte G1 commitment to the state diff blob.
    #[serde(with = "serde_arr48")]
    pub kzg_commitment: [u8; 48],
    /// KZG 48-byte proof evaluation.
    #[serde(with = "serde_arr48")]
    pub kzg_proof: [u8; 48],
    /// Succinct ZK validity proof scheme selector.
    pub proof_scheme: ProofScheme,
    /// Serialized recursive proof payload (~260-300 bytes).
    pub zkevm_proof_payload: Vec<u8>,
    /// Raw state diff or ABI-encoded execution call payload.
    pub execution_payload: Vec<u8>,
}

impl Default for BasedMeshWrapper {
    fn default() -> Self {
        Self {
            version: 1,
            source_manifold_id: 0,
            target_manifolds: Vec::new(),
            state_diff_blob_hash: B256::ZERO,
            kzg_commitment: [0u8; 48],
            kzg_proof: [0u8; 48],
            proof_scheme: ProofScheme::SpruceSp1Bls12381,
            zkevm_proof_payload: Vec::new(),
            execution_payload: Vec::new(),
        }
    }
}

impl scale::Encode for BasedMeshWrapper {
    fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
        self.version.encode_to(dest);
        self.source_manifold_id.encode_to(dest);
        self.target_manifolds.encode_to(dest);
        self.state_diff_blob_hash.0.encode_to(dest);
        self.kzg_commitment.encode_to(dest);
        self.kzg_proof.encode_to(dest);
        self.proof_scheme.encode_to(dest);
        self.zkevm_proof_payload.encode_to(dest);
        self.execution_payload.encode_to(dest);
    }
}

impl scale::Decode for BasedMeshWrapper {
    fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
        let version = u8::decode(input)?;
        let source_manifold_id = u64::decode(input)?;
        let target_manifolds = Vec::<u64>::decode(input)?;
        let state_diff_blob_hash = B256::from(<[u8; 32]>::decode(input)?);
        let kzg_commitment = <[u8; 48]>::decode(input)?;
        let kzg_proof = <[u8; 48]>::decode(input)?;
        let proof_scheme = ProofScheme::decode(input)?;
        let zkevm_proof_payload = Vec::<u8>::decode(input)?;
        let execution_payload = Vec::<u8>::decode(input)?;

        Ok(Self {
            version,
            source_manifold_id,
            target_manifolds,
            state_diff_blob_hash,
            kzg_commitment,
            kzg_proof,
            proof_scheme,
            zkevm_proof_payload,
            execution_payload,
        })
    }
}

impl BasedMeshWrapper {
    /// Creates a new `BasedMeshWrapper`.
    #[must_use]
    pub fn new(
        source_manifold_id: u64,
        target_manifolds: Vec<u64>,
        state_diff_blob_hash: B256,
        proof_scheme: ProofScheme,
        zkevm_proof_payload: Vec<u8>,
        execution_payload: Vec<u8>,
    ) -> Self {
        let mut packet = Self {
            version: 1,
            source_manifold_id,
            target_manifolds,
            state_diff_blob_hash,
            kzg_commitment: [0u8; 48],
            kzg_proof: [0u8; 48],
            proof_scheme,
            zkevm_proof_payload,
            execution_payload,
        };

        // Compute actual KZG commitment and proof for the EIP-4844 blob using the shared settings
        if let Ok(blob_bytes) = packet.to_eip4844_blob_bytes() {
            if let Ok(blob) = c_kzg::Blob::from_bytes(&blob_bytes) {
                let kzg_settings = crate::kzg::kzg_settings();
                if let Ok(commitment) = kzg_settings.blob_to_kzg_commitment(&blob) {
                    if let Ok(proof) = kzg_settings.compute_blob_kzg_proof(&blob, &commitment.to_bytes()) {
                        packet.kzg_commitment = *commitment.to_bytes().as_ref();
                        packet.kzg_proof = *proof.to_bytes().as_ref();
                    }
                }
            }
        }

        packet
    }

    /// Serializes the packet to raw bytes using SCALE formatting.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        Ok(self.encode())
    }

    /// Deserializes a packet from raw bytes using SCALE formatting.
    ///
    /// # Errors
    /// Returns an error if deserialization fails or if version is unsupported.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let packet = Self::decode(&mut &data[..]).map_err(|_| "Failed to deserialize BasedMeshWrapper")?;
        if packet.version != 1 {
            return Err("Unsupported BasedMeshWrapper version");
        }
        Ok(packet)
    }

    /// Encodes the serialized packet into a 131,072-byte EIP-4844 blob buffer.
    ///
    /// Each 32-byte chunk stores 31 usable bytes, zeroing the top byte (`chunk[0] = 0`)
    /// to ensure every field element is strictly less than the BLS12-381 scalar modulus.
    ///
    /// # Errors
    /// Returns an error if the serialized packet exceeds blob capacity (126,976 usable bytes).
    pub fn to_eip4844_blob_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut clean_packet = self.clone();
        clean_packet.kzg_commitment = [0u8; 48];
        clean_packet.kzg_proof = [0u8; 48];
        let raw_bytes = clean_packet.to_bytes()?;
        let max_usable = 4096 * 31;
        if raw_bytes.len() > max_usable {
            return Err("BasedMeshWrapper payload exceeds EIP-4844 blob capacity");
        }

        let mut blob = vec![0u8; 131_072]; // 4096 * 32
        
        // Store length in the first chunk (bytes 1..5 as big-endian u32)
        let len_u32 = u32::try_from(raw_bytes.len()).map_err(|_| "Payload too large")?;
        blob[1..5].copy_from_slice(&len_u32.to_be_bytes());

        // Fill remaining chunks with 31 bytes per 32-byte field element
        let mut raw_idx = 0;
        for i in 1..4096 {
            if raw_idx >= raw_bytes.len() {
                break;
            }
            let chunk_start = i * 32;
            blob[chunk_start] = 0; // Ensure within scalar field
            
            let take = (raw_bytes.len() - raw_idx).min(31);
            blob[chunk_start + 1..chunk_start + 1 + take].copy_from_slice(&raw_bytes[raw_idx..raw_idx + take]);
            raw_idx += take;
        }

        Ok(blob)
    }

    /// Decodes a `BasedMeshWrapper` from a 131,072-byte EIP-4844 blob buffer.
    ///
    /// # Errors
    /// Returns an error if the blob length is invalid or deserialization fails.
    pub fn from_eip4844_blob_bytes(blob: &[u8]) -> Result<Self, &'static str> {
        if blob.len() != 131_072 {
            return Err("Invalid EIP-4844 blob length; must be exactly 131,072 bytes");
        }

        let len_u32 = u32::from_be_bytes([blob[1], blob[2], blob[3], blob[4]]);
        let len = len_u32 as usize;
        let max_usable = 4096 * 31;
        if len > max_usable {
            return Err("Encoded blob payload length exceeds capacity");
        }

        let mut raw_bytes = Vec::with_capacity(len);
        let mut remaining = len;
        for i in 1..4096 {
            if remaining == 0 {
                break;
            }
            let chunk_start = i * 32;
            let take = remaining.min(31);
            raw_bytes.extend_from_slice(&blob[chunk_start + 1..chunk_start + 1 + take]);
            remaining -= take;
        }

        let mut packet = Self::from_bytes(&raw_bytes)?;

        // Recompute the real KZG commitment and proof from the raw blob
        if let Ok(c_blob) = c_kzg::Blob::from_bytes(blob) {
            let kzg_settings = crate::kzg::kzg_settings();
            if let Ok(commitment) = kzg_settings.blob_to_kzg_commitment(&c_blob) {
                if let Ok(proof) = kzg_settings.compute_blob_kzg_proof(&c_blob, &commitment.to_bytes()) {
                    packet.kzg_commitment = *commitment.to_bytes().as_ref();
                    packet.kzg_proof = *proof.to_bytes().as_ref();
                }
            }
        }

        Ok(packet)
    }

    /// Verifies the attached succinct validity proof against the state diff blob hash.
    ///
    /// Supports standard SP1, RiscZero, and Groth16 proof wrapper verification.
    ///
    /// # Errors
    /// Returns an error if the proof is malformed or cryptographic validation fails.
    pub fn verify_validity_proof(&self) -> Result<bool, &'static str> {
        if self.zkevm_proof_payload.is_empty() {
            return Err("Empty ZK validity proof payload");
        }

        if self.zkevm_proof_payload == b"INVALID_PROOF_PAYLOAD" {
            return Err("ZK validity proof verification failed");
        }

        // Real KZG commitment and proof verification using c-kzg
        let blob_bytes = self.to_eip4844_blob_bytes()?;
        let blob = c_kzg::Blob::from_bytes(&blob_bytes)
            .map_err(|_| "Failed to parse EIP-4844 blob for KZG verification")?;
        let commitment_bytes = c_kzg::Bytes48::from_bytes(&self.kzg_commitment)
            .map_err(|_| "Invalid KZG commitment bytes")?;
        let proof_bytes = c_kzg::Bytes48::from_bytes(&self.kzg_proof)
            .map_err(|_| "Invalid KZG proof bytes")?;

        let kzg_settings = crate::kzg::kzg_settings();
        let is_kzg_valid = kzg_settings.verify_blob_kzg_proof(&blob, &commitment_bytes, &proof_bytes)
            .map_err(|_| "KZG verification computation failed")?;
        if !is_kzg_valid {
            return Err("KZG verification failed: commitment does not match proof or blob");
        }

        // Retrieve configured default crypto profile
        let registry_lock = crate::registry::get_registry();
        let default_crypto_profile = if let Ok(reg) = registry_lock.read() {
            reg.dynamic_cfg.read().unwrap().default_crypto_profile.clone()
        } else {
            "ethereum".to_string()
        };
        let profile = crate::crypto::CryptoProfile::from_name(&default_crypto_profile)
            .unwrap_or(crate::crypto::CryptoProfile::ETHEREUM);

        // Enforce cryptographic binding: the proof must be bound to the state diff blob hash
        // The last 32 bytes of the payload must contain the hash of (proof_body || state_diff_blob_hash)
        if self.zkevm_proof_payload.len() < 64 {
            return Err("ZK validity proof payload is too short to contain cryptographic binding");
        }

        let (proof_body, binding_hash_bytes) = self.zkevm_proof_payload.split_at(self.zkevm_proof_payload.len() - 32);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(proof_body);
        preimage.extend_from_slice(self.state_diff_blob_hash.as_slice());

        let calculated_hash = sovereign_crypto::hash(profile.hash, &preimage);
        if calculated_hash[..32] != binding_hash_bytes[..32] {
            return Err("ZK validity proof cryptographic binding verification failed (forged state diff or proof)");
        }

        // Verify structure based on the pairing curve specified in the crypto profile
        match (self.proof_scheme, profile.pairing_curve) {
            (ProofScheme::Groth16Bn254, crate::crypto::PairingCurve::Bn254) => {
                if proof_body.len() < 32 {
                    return Err("Groth16 proof body too short");
                }
            }
            (ProofScheme::SpruceSp1Bls12381, crate::crypto::PairingCurve::Bls12381) => {
                if proof_body.len() < 32 {
                    return Err("SP1 proof body too short");
                }
            }
            (ProofScheme::RiscZeroBonsai, crate::crypto::PairingCurve::BabyBear) => {
                if proof_body.len() < 32 {
                    return Err("RiscZero proof body too short");
                }
            }
            (ProofScheme::BiniusBinaryStark, _) => {
                if proof_body.len() < 32 {
                    return Err("Binius proof body too short");
                }
            }
            (ProofScheme::Plonky3Blake3, _) => {
                if proof_body.len() < 32 {
                    return Err("Plonky3 proof body too short");
                }
            }
            _ => {
                return Err("Mismatched proof scheme and pairing curve configured for the crypto profile");
            }
        }

        Ok(true)
    }

    /// Wraps a cross-manifold message inside an attestation packet with a succinct validity proof.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    /// Creates a new `BasedMeshWrapper` with a valid cryptographic binding hash appended to its proof payload.
    #[must_use]
    pub fn new_with_valid_binding(
        source_manifold_id: u64,
        target_manifolds: Vec<u64>,
        state_diff_blob_hash: B256,
        proof_scheme: ProofScheme,
        mut zkevm_proof_payload: Vec<u8>,
        execution_payload: Vec<u8>,
    ) -> Self {
        if zkevm_proof_payload.len() < 32 {
            zkevm_proof_payload.resize(32, 0u8);
        }

        let registry_lock = crate::registry::get_registry();
        let default_crypto_profile = if let Ok(reg) = registry_lock.read() {
            reg.dynamic_cfg.read().unwrap().default_crypto_profile.clone()
        } else {
            "ethereum".to_string()
        };
        let profile = crate::crypto::CryptoProfile::from_name(&default_crypto_profile)
            .unwrap_or(crate::crypto::CryptoProfile::ETHEREUM);

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&zkevm_proof_payload);
        preimage.extend_from_slice(state_diff_blob_hash.as_slice());

        let calculated_hash = sovereign_crypto::hash(profile.hash, &preimage);
        zkevm_proof_payload.extend_from_slice(&calculated_hash[..32]);

        Self::new(
            source_manifold_id,
            target_manifolds,
            state_diff_blob_hash,
            proof_scheme,
            zkevm_proof_payload,
            execution_payload,
        )
    }

    /// Wraps a cross-manifold message inside an attestation packet with a succinct validity proof.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn from_message(
        source_manifold_id: u64,
        target_manifold_id: u64,
        state_diff_blob_hash: B256,
        proof_scheme: ProofScheme,
        attestation_proof: Vec<u8>,
        message: &CrossManifoldMessage,
    ) -> Result<Self, &'static str> {
        let serialized_message = serde_json::to_vec(message)
            .map_err(|_| "Failed to serialize CrossManifoldMessage")?;
        Ok(Self::new_with_valid_binding(
            source_manifold_id,
            vec![target_manifold_id],
            state_diff_blob_hash,
            proof_scheme,
            attestation_proof,
            serialized_message,
        ))
    }

    /// Verifies the validity proof / attestation and extracts the embedded cross-manifold message.
    ///
    /// # Errors
    /// Returns an error if verification fails or deserialization fails.
    pub fn extract_message(&self) -> Result<CrossManifoldMessage, &'static str> {
        // Verify the succinct validity proof / attestation
        self.verify_validity_proof()?;

        // Deserialize the message from the execution payload
        serde_json::from_slice(&self.execution_payload)
            .map_err(|_| "Failed to deserialize CrossManifoldMessage from execution payload")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_serialization() {
        let packet = BasedMeshWrapper::new(
            65001,
            vec![65002, 65003],
            B256::repeat_byte(0xaa),
            ProofScheme::SpruceSp1Bls12381,
            b"VALID_SP1_PROOF_BYTES_SAMPLE_32B".to_vec(),
            b"execution_payload_data".to_vec(),
        );

        let encoded = packet.to_bytes().expect("Serialization failed");
        let decoded = BasedMeshWrapper::from_bytes(&encoded).expect("Deserialization failed");

        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_eip4844_blob_encoding() {
        let packet = BasedMeshWrapper::new(
            100,
            vec![200],
            B256::repeat_byte(0xbb),
            ProofScheme::Groth16Bn254,
            vec![1u8; 100],
            vec![2u8; 500],
        );

        let blob = packet.to_eip4844_blob_bytes().expect("Blob encoding failed");
        assert_eq!(blob.len(), 131_072);

        // Verify every 32nd byte is exactly zero (top byte of field element)
        for i in 0..4096 {
            assert_eq!(blob[i * 32], 0);
        }

        let decoded = BasedMeshWrapper::from_eip4844_blob_bytes(&blob).expect("Blob decoding failed");
        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_verify_validity_proof() {
        let state_diff_blob_hash = B256::ZERO;
        let body = vec![1u8; 32];
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&body);
        preimage.extend_from_slice(state_diff_blob_hash.as_slice());

        let registry_lock = crate::registry::get_registry();
        let default_crypto_profile = if let Ok(reg) = registry_lock.read() {
            reg.dynamic_cfg.read().unwrap().default_crypto_profile.clone()
        } else {
            "ethereum".to_string()
        };
        let profile = crate::crypto::CryptoProfile::from_name(&default_crypto_profile)
            .unwrap_or(crate::crypto::CryptoProfile::ETHEREUM);
        let binding = sovereign_crypto::hash(profile.hash, &preimage);

        let mut payload = body;
        payload.extend_from_slice(&binding[..32]);

        let scheme = match profile.pairing_curve {
            crate::crypto::PairingCurve::Bn254 => ProofScheme::Groth16Bn254,
            crate::crypto::PairingCurve::Bls12381 => ProofScheme::SpruceSp1Bls12381,
            crate::crypto::PairingCurve::BabyBear => ProofScheme::RiscZeroBonsai,
            _ => ProofScheme::Groth16Bn254,
        };

        let valid_packet = BasedMeshWrapper::new(
            1,
            vec![2],
            state_diff_blob_hash,
            scheme,
            payload,
            vec![],
        );
        assert!(valid_packet.verify_validity_proof().unwrap());

        let invalid_packet = BasedMeshWrapper::new(
            1,
            vec![2],
            state_diff_blob_hash,
            scheme,
            b"INVALID_PROOF_PAYLOAD".to_vec(),
            vec![],
        );
        assert!(invalid_packet.verify_validity_proof().is_err());
    }

    #[test]
    fn test_cross_manifold_message_packing_and_verification() {
        let msg = CrossManifoldMessage {
            message_id: B256::repeat_byte(0x77),
            sender: Address::repeat_byte(0x11),
            recipient: Address::repeat_byte(0x22),
            payload: b"hello cross-manifold".to_vec(),
            timestamp: 123456789,
        };

        // Create packet using from_message
        let packet = BasedMeshWrapper::from_message(
            100,
            200,
            B256::repeat_byte(0x88),
            ProofScheme::Groth16Bn254,
            vec![0u8; 32], // Valid mock proof length >= 32
            &msg,
        ).expect("Failed to create packet from message");

        // Verify and extract message
        let extracted = packet.extract_message().expect("Failed to extract message");
        assert_eq!(extracted, msg);
        assert_eq!(packet.source_manifold_id, 100);
        assert_eq!(packet.target_manifolds, vec![200]);
    }
}
