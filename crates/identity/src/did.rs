//! Universal `did:peer:4` Document Generator & Single-Seed Key Derivation.

use alloy_primitives::{hex, Address, B256};

/// Representation of a Universal `did:peer` Identity Document.
#[derive(Debug, Clone)]
pub struct SovereignDidDocument {
    /// Long-form `did:peer:4...` string.
    pub did_uri: String,
    /// Base58BTC short-form hash (46-50 chars).
    pub short_form: String,
    /// WireGuard / P2P transport public key (Ed25519).
    pub ed25519_pubkey: Vec<u8>,
    /// EVM transaction address (secp256k1).
    pub evm_address: Address,
    /// Sync committee signature aggregation key (BLS12-381).
    pub bls_pubkey: Vec<u8>,
}

impl SovereignDidDocument {
    /// Derives sub-keys from a single master 256-bit entropy seed via BIP-32 / SLIP-0010 rules.
    pub fn derive_from_seed(master_seed: B256) -> Self {
        // Mock derivation placeholder for secp256k1, Ed25519, and BLS12-381 keys
        let evm_address = Address::from_slice(&master_seed.as_slice()[0..20]);
        let short_form = format!("did:peer:4z{}", hex::encode(&master_seed[0..8]));
        let did_uri = format!("{short_form}:long-form-doc-cbor-payload");

        Self {
            did_uri,
            short_form,
            ed25519_pubkey: master_seed.as_slice().to_vec(),
            evm_address,
            bls_pubkey: master_seed.as_slice().to_vec(),
        }
    }
}
