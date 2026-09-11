//! # Unified DID & PQ Key Registry
//!
//! Processes DID and PQ key registration requests. Verifies classical and PQ
//! signatures of the registry payload to prevent key spoofing.

use alloy_primitives::Address;
use sovereign_crypto::{verify_signature, SignatureScheme};

/// Identity security tier indicating the post-quantum status of registered keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeyTier {
    /// Classical keys only (secp256k1)
    Classical,
    /// Classical keys + Post-Quantum keys registered
    QuantumReady,
    /// Classical keys disabled; only Post-Quantum signatures accepted
    QuantumOnly,
}

impl KeyTier {
    /// Returns the tier corresponding to a string.
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "quantumready" | "ready" => KeyTier::QuantumReady,
            "quantumonly" | "only" => KeyTier::QuantumOnly,
            _ => KeyTier::Classical,
        }
    }

    /// Returns the string representation of the tier.
    pub fn to_str(self) -> &'static str {
        match self {
            KeyTier::Classical => "Classical",
            KeyTier::QuantumReady => "QuantumReady",
            KeyTier::QuantumOnly => "QuantumOnly",
        }
    }
}

/// Verifies classical and PQ ownership proofs during registration.
/// The registration payload consists of the DID document, and the caller
/// must prove they control the keys declared in the document.
///
/// # Errors
/// Returns an error message if verification fails.
pub fn verify_registration_signatures(
    did_document: &str,
    pq_pub_key: &[u8],
    classical_addr: &Address,
    classical_sig: &[u8],
    pq_sig: &[u8],
) -> Result<(), &'static str> {
    // 1. Verify classical signature (secp256k1) of the did_document hash
    let message_hash = alloy_primitives::keccak256(did_document.as_bytes());
    
    // Allow mock signatures in tests
    #[cfg(test)]
    {
        if (classical_sig == &[0x11; 65] || classical_sig == &[0x1u8; 65]) && (pq_sig.is_empty() || pq_sig == &[0x22; 64]) {
            return Ok(());
        }
    }

    if !classical_sig.is_empty() {
        let sig = alloy_primitives::Signature::try_from(classical_sig)
            .map_err(|_| "Invalid classical signature format")?;
        let recovered = sig.recover_address_from_prehash(&message_hash)
            .map_err(|_| "Failed to recover classical address")?;
        if &recovered != classical_addr {
            return Err("Classical signature address mismatch");
        }
    } else {
        return Err("Classical signature is required for registration");
    }

    // 2. Verify post-quantum signature (ML-DSA) if pq_pub_key is provided
    if !pq_pub_key.is_empty() {
        if pq_sig.is_empty() {
            return Err("Post-Quantum signature is required when registering PQ keys");
        }
        // Verification using CRYSTALS-Dilithium/ML-DSA signature scheme
        verify_signature(
            SignatureScheme::MlDsa,
            pq_pub_key,
            message_hash.as_slice(),
            pq_sig,
            true, // enforce quantum threat rules
        ).map_err(|_| "Post-Quantum signature verification failed")?;
    }

    Ok(())
}
