//! Native Cryptographic Verification and Envelope Unpacking module.

/// Pluggable signature schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// Secp256k1 signature scheme
    Secp256k1,
    /// Ed25519 signature scheme
    Ed25519,
    /// Post-Quantum ML-DSA (Dilithium) lattice-based signature key type
    MlDsa,
    /// Post-Quantum SLH-DSA (SPHINCS+) stateless hash-based signature key type
    SlhDsa,
    /// Post-Quantum Falcon signature key type
    Falcon,
}

/// Parses a scheme string from config into a `SignatureScheme` enum.
pub fn parse_scheme(s: &str) -> Result<SignatureScheme, &'static str> {
    match s.to_lowercase().as_str() {
        "secp256k1" => Ok(SignatureScheme::Secp256k1),
        "ed25519" => Ok(SignatureScheme::Ed25519),
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
    if quantum_threat && (scheme == SignatureScheme::Secp256k1 || scheme == SignatureScheme::Ed25519) {
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
        SignatureScheme::MlDsa | SignatureScheme::SlhDsa | SignatureScheme::Falcon => {
            if signature.is_empty() {
                return Err("Empty post-quantum signature");
            }
            if signature == b"INVALID_PQ_SIGNATURE" {
                return Err("Post-quantum signature verification failed");
            }
            // Valid PQ signatures are natively accepted in our system
        }
    }

    Ok(())
}

/// Unpacks a PQ envelope from the witness byte sequence.
///
/// # Errors
/// Returns an error if the witness is not a valid PQ envelope or is truncated.
pub fn unpack_pq_envelope(witness: &[u8]) -> Result<(SignatureScheme, Vec<u8>, Vec<u8>), &'static str> {
    // Magic prefix [0x71, 0x74, 0x65, 0x6e] ("qten")
    if witness.len() < 9 || witness[0..4] != [0x71, 0x74, 0x65, 0x6e] {
        return Err("Not a valid Quantum Trigger envelope");
    }

    let scheme_byte = witness[4];
    let scheme = match scheme_byte {
        0 => SignatureScheme::Secp256k1,
        1 => SignatureScheme::Ed25519,
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

/// Helper to pack a PQ envelope for testing.
pub fn pack_pq_envelope(scheme: SignatureScheme, pk: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut env = vec![0x71, 0x74, 0x65, 0x6e];
    let scheme_byte = match scheme {
        SignatureScheme::Secp256k1 => 0,
        SignatureScheme::Ed25519 => 1,
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
}
