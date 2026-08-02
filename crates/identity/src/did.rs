use alloy_primitives::{hex, Address, B256};
use std::collections::HashSet;

/// Representation of a Universal `did:peer` Identity Document or a cross-chain `did:sovereign` document.
#[derive(Debug, Clone)]
pub struct SovereignDidDocument {
    /// Long-form `did:peer:4...` or `did:sovereign:[chain_id]:...` string.
    pub did_uri: String,
    /// Base58BTC short-form hash (46-50 chars) or raw foreign address.
    pub short_form: String,
    /// WireGuard / P2P transport public key (Ed25519) if applicable.
    pub ed25519_pubkey: Vec<u8>,
    /// EVM transaction address (secp256k1).
    pub evm_address: Address,
    /// Sync committee signature aggregation key (BLS12-381) if applicable.
    pub bls_pubkey: Vec<u8>,
    /// Recursive parent authority path (from local municipality upwards)
    pub authority_path: Vec<String>,
    /// Explicit directed trust edges to other DIDs (accepts rules from)
    pub trusted_authorities: HashSet<String>,
}

impl SovereignDidDocument {
    /// Synthesizes a valid Sovereign DID document from a foreign chain key/address on-the-fly.
    /// This makes external multichain networks appear as native DID endpoints.
    pub fn wrap_foreign_key(chain_id: u64, raw_address_or_key: &[u8]) -> Self {
        let evm_address = if raw_address_or_key.len() >= 20 {
            Address::from_slice(&raw_address_or_key[0..20])
        } else {
            Address::ZERO
        };
        let hex_key = hex::encode(raw_address_or_key);
        let did_uri = format!("did:sovereign:{}:{}", chain_id, hex_key);

        Self {
            did_uri,
            short_form: hex_key,
            ed25519_pubkey: vec![],
            evm_address,
            bls_pubkey: vec![],
            authority_path: vec![],
            trusted_authorities: HashSet::new(),
        }
    }
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
            authority_path: vec![
                "did:peer:munich".to_string(),
                "did:peer:bavaria".to_string(),
                "did:peer:germany".to_string(),
                "did:peer:eu".to_string(),
            ],
            trusted_authorities: HashSet::from([
                "did:peer:bavaria".to_string(),
                "did:peer:germany".to_string(),
            ]),
        }
    }
}
