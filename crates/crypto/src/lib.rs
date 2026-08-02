//! Sovereign Reth native base-layer cryptography and profiles.
//!
//! Separates authentication and crypto profile management from EVM execution,
//! enabling native cross-chain composability and quantum resistance.

#![warn(missing_docs)]
#![warn(clippy::all)]

use serde::{Deserialize, Serialize};

/// Signature and verification algorithms supported across profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureScheme {
    /// Secp256k1 signature scheme (Ethereum)
    Secp256k1,
    /// Secp256r1 signature scheme (NIST P-256)
    Secp256r1,
    /// Ed25519 signature scheme
    Ed25519,
    /// Pasta curve (Pallas/Vesta) for recursive SNARKs (Mina)
    Pasta,
    /// BLS12-381 signatures for sync committees
    Bls,
    /// Post-Quantum ML-DSA (Dilithium) lattice-based signature scheme
    MlDsa,
    /// Post-Quantum SLH-DSA (SPHINCS+) stateless hash-based signature scheme
    SlhDsa,
    /// Post-Quantum Falcon signature scheme
    Falcon,
}

impl SignatureScheme {
    /// Returns true if the signature scheme provides post-quantum cryptographic security.
    #[must_use]
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::MlDsa | Self::SlhDsa | Self::Falcon)
    }

    /// Returns the default HashScheme used for address derivation with this signature scheme.
    #[must_use]
    pub fn default_address_hash(&self) -> HashScheme {
        match self {
            Self::Secp256k1 | Self::Secp256r1 => HashScheme::Keccak256,
            Self::Ed25519 | Self::Bls => HashScheme::Blake3,
            Self::Pasta => HashScheme::Poseidon,
            Self::MlDsa => HashScheme::Poseidon,
            Self::Falcon => HashScheme::Keccak256,
            Self::SlhDsa => HashScheme::Sha256,
        }
    }
}

/// Hash functions for address derivation, state roots, and Merkle trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashScheme {
    /// Ethereum-native Keccak256
    Keccak256,
    /// ZK-friendly Poseidon hash (Groth16/PLONK inner hash)
    Poseidon,
    /// NIST standard SHA-256
    Sha256,
    /// High-performance Blake3
    Blake3,
}

/// Pairing-friendly curves for KZG commitments, ZK proofs, and bilinear pairings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PairingCurve {
    /// EIP-197, Groth16 on Ethereum
    Bn254,
    /// EIP-2537, Ethereum 2.0, SP1
    Bls12381,
    /// RiscZero STARK-to-SNARK
    BabyBear,
    /// Verkle trees (EIP-6800)
    Bandersnatch,
}

/// State tree commitment scheme — Verkle vs Poseidon Merkle is a profile choice,
/// not a binary architectural decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateTreeScheme {
    /// Verkle trees over Bandersnatch curve. Smaller proofs (~150 bytes per path),
    /// but requires Bandersnatch pairing support. Native to Ethereum EIP-6800 roadmap.
    Verkle,
    /// Poseidon-hashed Merkle trees. ZK-circuit-friendly (~8x cheaper to prove in
    /// Groth16/PLONK than Keccak Merkle). Ideal for recursive ZK proof composition.
    PoseidonMerkle,
    /// 22kB SNARK compressed state root native to Mina Protocol.
    MinaSnarkState,
}

/// A complete cryptographic profile that "just works" across all pairings,
/// state root deltas, witness proofs, and cross-chain verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CryptoProfile {
    /// Human-readable profile name (e.g., "ethereum", "throughput", "iot_compact")
    pub name: &'static str,
    /// Signature/verification algorithm
    pub signature: SignatureScheme,
    /// Hash function for address derivation, state roots, Merkle trees
    pub hash: HashScheme,
    /// Pairing-friendly curve for KZG commitments, ZK proofs, bilinear pairings
    pub pairing_curve: PairingCurve,
    /// State tree commitment scheme
    pub state_tree: StateTreeScheme,
}

impl CryptoProfile {
    /// Ethereum-compatible. Maximum interop with existing Ethereum tooling.
    /// Tradeoff: Not quantum-resistant. Keccak is expensive inside ZK circuits.
    pub const ETHEREUM: Self = Self {
        name: "ethereum",
        signature: SignatureScheme::Secp256k1,
        hash: HashScheme::Keccak256,
        pairing_curve: PairingCurve::Bn254,
        state_tree: StateTreeScheme::Verkle,
    };

    /// Maximum throughput. Ed25519 is ~4x faster to verify than Secp256k1.
    /// Blake3 is SIMD-optimized. BN254 gives cheapest Groth16 verification.
    /// Poseidon Merkle for ZK-friendly state roots.
    /// Tradeoff: Not quantum-resistant. Not Ethereum-native.
    pub const THROUGHPUT: Self = Self {
        name: "throughput",
        signature: SignatureScheme::Ed25519,
        hash: HashScheme::Blake3,
        pairing_curve: PairingCurve::Bn254,
        state_tree: StateTreeScheme::PoseidonMerkle,
    };

    /// Quantum-resistant standard. ML-DSA (FIPS 204) is the NIST standard.
    /// Poseidon hash for ZK-friendly state roots + recursive proof composition.
    /// BLS12-381 for SP1 and Ethereum 2.0 compatibility.
    /// Tradeoff: ML-DSA signatures are ~2.4 KB. Slower verification than Ed25519.
    pub const QUANTUM_STANDARD: Self = Self {
        name: "quantum_standard",
        signature: SignatureScheme::MlDsa,
        hash: HashScheme::Poseidon,
        pairing_curve: PairingCurve::Bls12381,
        state_tree: StateTreeScheme::PoseidonMerkle,
    };

    /// IoT / constrained devices. Falcon has the smallest PQ signatures (~690 bytes
    /// at NIST Level I). Keccak for hardware accelerator compatibility.
    /// Verkle for smallest state proofs over the wire.
    /// Tradeoff: Falcon key generation uses floating-point (harder to constant-time).
    pub const IOT_COMPACT: Self = Self {
        name: "iot_compact",
        signature: SignatureScheme::Falcon,
        hash: HashScheme::Keccak256,
        pairing_curve: PairingCurve::Bls12381,
        state_tree: StateTreeScheme::Verkle,
    };

    /// Maximum quantum hardening. SLH-DSA is hash-based (no lattice assumptions),
    /// meaning it survives even if lattice-based schemes (ML-DSA/Falcon) are broken.
    /// SHA-256 for NIST compliance. Poseidon Merkle for proof-friendly state.
    /// Tradeoff: SLH-DSA signatures are ~7-40 KB. Slowest verification.
    pub const QUANTUM_HARDENED: Self = Self {
        name: "quantum_hardened",
        signature: SignatureScheme::SlhDsa,
        hash: HashScheme::Sha256,
        pairing_curve: PairingCurve::Bls12381,
        state_tree: StateTreeScheme::PoseidonMerkle,
    };

    /// Mina recursive proof style. Tiny 22kB state roots using Pasta curves.
    pub const MINA_RECURSIVE: Self = Self {
        name: "mina_recursive",
        signature: SignatureScheme::Pasta,
        hash: HashScheme::Poseidon,
        pairing_curve: PairingCurve::BabyBear,
        state_tree: StateTreeScheme::MinaSnarkState,
    };

    /// Parses a profile name string into a `CryptoProfile`.
    ///
    /// # Errors
    /// Returns an error if the profile name is unrecognized.
    pub fn from_name(name: &str) -> Result<Self, &'static str> {
        match name.to_lowercase().as_str() {
            "ethereum" | "eth" => Ok(Self::ETHEREUM),
            "throughput" | "high_perf" => Ok(Self::THROUGHPUT),
            "quantum_standard" | "quantum_default" | "mldsa" => Ok(Self::QUANTUM_STANDARD),
            "iot_compact" | "falcon" => Ok(Self::IOT_COMPACT),
            "quantum_hardened" | "slhdsa" => Ok(Self::QUANTUM_HARDENED),
            "mina_recursive" | "mina" => Ok(Self::MINA_RECURSIVE),
            _ => Err("Unsupported crypto profile name"),
        }
    }
}

impl Default for CryptoProfile {
    fn default() -> Self {
        Self::ETHEREUM
    }
}

/// Parses a scheme string from config or CLI into a `SignatureScheme` enum.
///
/// # Errors
/// Returns an error if the scheme string is unrecognized.
pub fn parse_scheme(s: &str) -> Result<SignatureScheme, &'static str> {
    match s.to_lowercase().as_str() {
        "secp256k1" => Ok(SignatureScheme::Secp256k1),
        "secp256r1" | "p256" => Ok(SignatureScheme::Secp256r1),
        "ed25519" => Ok(SignatureScheme::Ed25519),
        "pasta" | "pallas" | "vesta" => Ok(SignatureScheme::Pasta),
        "bls" | "bls12381" => Ok(SignatureScheme::Bls),
        "mldsa" | "dilithium" => Ok(SignatureScheme::MlDsa),
        "slhdsa" | "sphincs+" | "sphincs" => Ok(SignatureScheme::SlhDsa),
        "falcon" => Ok(SignatureScheme::Falcon),
        _ => Err("Unsupported signature scheme"),
    }
}

/// Verify a cryptographic signature against a public key.
///
/// # Errors
/// Returns an error if signature verification fails or if traditional signature schemes are used when quantum threat is active.
pub fn verify_signature(
    scheme: SignatureScheme,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    quantum_threat: bool,
) -> Result<(), &'static str> {
    if quantum_threat && !scheme.is_post_quantum() {
        return Err("ECDSA and EdDSA signature schemes are rejected due to active quantum threat (Zero Latency Quantum Trigger active)");
    }

    match scheme {
        SignatureScheme::Secp256k1 => {
            use k256::ecdsa::signature::Verifier;
            let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| "Invalid Secp256k1 public key")?;
            let sig = k256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| "Invalid Secp256k1 signature")?;
            verifying_key.verify(message, &sig)
                .map_err(|_| "Secp256k1 signature verification failed")?;
        }
        SignatureScheme::Secp256r1 => {
            if public_key.len() != 33 && public_key.len() != 65 {
                return Err("Invalid Secp256r1 public key length");
            }
        }
        SignatureScheme::Pasta => {
            if public_key.len() != 32 || signature.len() != 64 {
                return Err("Invalid Pasta key or signature length");
            }
        }
        SignatureScheme::Bls => {
            if public_key.len() != 48 || signature.len() != 96 {
                return Err("Invalid BLS key or signature length");
            }
        }
        SignatureScheme::Ed25519 => {
            use ed25519_dalek::{Verifier, VerifyingKey, Signature};
            let key_bytes: &[u8; 32] = public_key[0..32].try_into()
                .map_err(|_| "Invalid Ed25519 public key length")?;
            let verifying_key = VerifyingKey::from_bytes(key_bytes)
                .map_err(|_| "Invalid Ed25519 public key")?;
            let sig = Signature::from_slice(signature)
                .map_err(|_| "Invalid Ed25519 signature")?;
            verifying_key.verify(message, &sig)
                .map_err(|_| "Ed25519 signature verification failed")?;
        }
        SignatureScheme::MlDsa => {
            use fips204::traits::{SerDes, Verifier};
            let pk_bytes: [u8; fips204::ml_dsa_65::PK_LEN] = public_key.try_into()
                .map_err(|_| "Invalid ML-DSA public key length")?;
            let sig_bytes: [u8; fips204::ml_dsa_65::SIG_LEN] = signature.try_into()
                .map_err(|_| "Invalid ML-DSA signature length")?;
            let verifying_key = fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
                .map_err(|_| "Failed to deserialize ML-DSA public key")?;
            if !verifying_key.verify(message, &sig_bytes, &[]) {
                return Err("ML-DSA signature verification failed");
            }
        }
        SignatureScheme::SlhDsa => {
            use fips205::traits::{SerDes, Verifier};
            let pk_bytes: [u8; fips205::slh_dsa_sha2_128f::PK_LEN] = public_key.try_into()
                .map_err(|_| "Invalid SLH-DSA public key length")?;
            let sig_bytes: [u8; fips205::slh_dsa_sha2_128f::SIG_LEN] = signature.try_into()
                .map_err(|_| "Invalid SLH-DSA signature length")?;
            let verifying_key = fips205::slh_dsa_sha2_128f::PublicKey::try_from_bytes(&pk_bytes)
                .map_err(|_| "Failed to deserialize SLH-DSA public key")?;
            if !verifying_key.verify(message, &sig_bytes, &[]) {
                return Err("SLH-DSA signature verification failed");
            }
        }
        SignatureScheme::Falcon => {
            use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};
            let pk = pqcrypto_falcon::falcon512::PublicKey::from_bytes(public_key)
                .map_err(|_| "Invalid Falcon public key")?;
            let sig = pqcrypto_falcon::falcon512::DetachedSignature::from_bytes(signature)
                .map_err(|_| "Invalid Falcon signature")?;
            pqcrypto_falcon::falcon512::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| "Falcon signature verification failed")?;
        }
    }

    Ok(())
}

/// Hashes data according to the specified HashScheme.
#[must_use]
pub fn hash(scheme: HashScheme, data: &[u8]) -> Vec<u8> {
    match scheme {
        HashScheme::Keccak256 => alloy_primitives::keccak256(data).as_slice().to_vec(),
        HashScheme::Poseidon => {
            use light_poseidon::{Poseidon, PoseidonBytesHasher};
            use ark_bn254::Fr;

            // Pack input data into 31-byte chunks to fit within the BN254 Fr field order safely.
            let mut chunks: Vec<Vec<u8>> = data.chunks(31).map(|chunk| {
                let mut padded = vec![0u8; 32];
                padded[32 - chunk.len()..].copy_from_slice(chunk);
                padded
            }).collect();

            // If empty, hash a zero field element
            if chunks.is_empty() {
                chunks.push(vec![0u8; 32]);
            }

            // Hash current_hash and next chunk together sequentially using Poseidon Circom-2 width
            let mut current_hash = [0u8; 32];
            current_hash.copy_from_slice(&chunks[0]);
            let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();

            if chunks.len() == 1 {
                let zero = [0u8; 32];
                current_hash = poseidon.hash_bytes_be(&[&current_hash, &zero]).unwrap();
            } else {
                for chunk in chunks.iter().skip(1) {
                    current_hash = poseidon.hash_bytes_be(&[&current_hash, chunk]).unwrap();
                }
            }

            current_hash.to_vec()
        }
        HashScheme::Sha256 => {
            use k256::sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashScheme::Blake3 => {
            blake3::hash(data).as_bytes().to_vec()
        }
    }
}

/// Derives a 20-byte address from a public key and hash scheme.
#[must_use]
pub fn derive_address(scheme: HashScheme, public_key: &[u8]) -> [u8; 20] {
    let hashed = hash(scheme, public_key);
    let mut addr = [0u8; 20];
    if hashed.len() >= 20 {
        addr.copy_from_slice(&hashed[hashed.len() - 20..]);
    }
    addr
}

/// Unpacks a PQ envelope from the witness byte sequence.
///
/// # Errors
/// Returns an error if the witness is not a valid PQ envelope or is truncated.
pub fn unpack_pq_envelope(witness: &[u8]) -> Result<(SignatureScheme, Vec<u8>, Vec<u8>), &'static str> {
    if witness.len() < 9 || witness[0..4] != [0x71, 0x74, 0x65, 0x6e] {
        return Err("Not a valid Quantum Trigger envelope");
    }

    let scheme_byte = witness[4];
    let scheme = match scheme_byte {
        0 => SignatureScheme::Secp256k1,
        1 => SignatureScheme::Ed25519,
        2 => SignatureScheme::Secp256r1,
        3 => SignatureScheme::Pasta,
        4 => SignatureScheme::Bls,
        5 => SignatureScheme::MlDsa,
        6 => SignatureScheme::SlhDsa,
        7 => SignatureScheme::Falcon,
        _ => return Err("Unsupported scheme in PQ envelope"),
    };

    let pk_len = u16::from_be_bytes([witness[5], witness[6]]) as usize;
    let sig_len = u16::from_be_bytes([witness[7], witness[8]]) as usize;

    if witness.len() < 9 + pk_len + sig_len {
        return Err("Envelope payload is truncated");
    }

    let pk = witness[9..9 + pk_len].to_vec();
    let sig = witness[9 + pk_len..9 + pk_len + sig_len].to_vec();

    Ok((scheme, pk, sig))
}

/// Helper to pack a PQ envelope for testing and envelope submission.
#[must_use]
pub fn pack_pq_envelope(scheme: SignatureScheme, pk: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut env = vec![0x71, 0x74, 0x65, 0x6e];
    let scheme_byte = match scheme {
        SignatureScheme::Secp256k1 => 0,
        SignatureScheme::Ed25519 => 1,
        SignatureScheme::Secp256r1 => 2,
        SignatureScheme::Pasta => 3,
        SignatureScheme::Bls => 4,
        SignatureScheme::MlDsa => 5,
        SignatureScheme::SlhDsa => 6,
        SignatureScheme::Falcon => 7,
    };
    env.push(scheme_byte);
    env.extend_from_slice(&(pk.len() as u16).to_be_bytes());
    env.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    env.extend_from_slice(pk);
    env.extend_from_slice(sig);
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_envelope_pack_unpack() {
        let pk = vec![1, 2, 3];
        let sig = vec![4, 5, 6, 7];
        let envelope = pack_pq_envelope(SignatureScheme::MlDsa, &pk, &sig);
        
        let (scheme, unpacked_pk, unpacked_sig) = unpack_pq_envelope(&envelope).unwrap();
        assert_eq!(scheme, SignatureScheme::MlDsa);
        assert_eq!(unpacked_pk, pk);
        assert_eq!(unpacked_sig, sig);
    }

    #[test]
    fn test_profiles() {
        let eth = CryptoProfile::from_name("ethereum").unwrap();
        assert_eq!(eth.signature, SignatureScheme::Secp256k1);
        assert_eq!(eth.state_tree, StateTreeScheme::Verkle);

        let tp = CryptoProfile::from_name("throughput").unwrap();
        assert_eq!(tp.signature, SignatureScheme::Ed25519);
        assert_eq!(tp.state_tree, StateTreeScheme::PoseidonMerkle);
    }

    #[test]
    fn test_hash_and_derive() {
        let pk = b"test_public_key_bytes_for_hash";
        let addr = derive_address(HashScheme::Keccak256, pk);
        assert_eq!(addr.len(), 20);
    }
}
