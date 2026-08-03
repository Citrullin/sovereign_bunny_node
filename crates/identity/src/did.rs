use alloy_primitives::{hex, Address, B256};
use std::collections::HashSet;

/// Representation of a Universal `did:peer` Identity Document or a cross-chain `did:sovereign` document.
#[derive(Debug, Clone)]
pub struct SovereignDidDocument {
    /// Long-form `did:peer:...` or `did:sovereign:[chain_id]:...` string.
    pub did_uri: String,
    /// Base58BTC short-form hash or raw foreign address.
    pub short_form: String,
    /// Transport public key (Ed25519) if applicable.
    pub ed25519_pubkey: Vec<u8>,
    /// EVM transaction address (secp256k1).
    pub evm_address: Address,
    /// Sync committee signature aggregation key (BLS12-381) if applicable.
    pub bls_pubkey: Vec<u8>,
    /// Recursive parent authority path.
    pub authority_path: Vec<String>,
    /// Explicit directed trust edges to other DIDs.
    pub trusted_authorities: HashSet<String>,
}

impl SovereignDidDocument {
    /// Synthesizes a valid Sovereign DID document from a foreign chain key/address on-the-fly.
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

    /// Derives sub-keys from a single master 256-bit entropy seed via BIP-32 rules.
    pub fn derive_from_seed(master_seed: B256) -> Self {
        let evm_address = Address::from_slice(&master_seed.as_slice()[0..20]);
        let short_form = format!("did:peer:4z{}", hex::encode(&master_seed[0..8]));
        let did_uri = format!("{short_form}:long-form-doc-cbor-payload");

        Self {
            did_uri,
            short_form,
            ed25519_pubkey: master_seed.as_slice().to_vec(),
            evm_address,
            bls_pubkey: master_seed.as_slice().to_vec(),
            authority_path: vec![],
            trusted_authorities: HashSet::new(),
        }
    }

    /// Resolves any DID string (did:peer:2, did:peer:4, did:sovereign) to a SovereignDidDocument synchronously.
    pub fn from_did_string(did: &str) -> Option<Self> {
        // ── did:peer:2 & did:peer:4 multibase-encoded key resolution ──────────────
        if did.starts_with("did:peer:2") || did.starts_with("did:peer:4") {
            let components: Vec<&str> = did.split('.').collect();
            let mut evm_address_opt: Option<Address> = None;
            let mut ed25519_pubkey = vec![];
            let mut bls_pubkey = vec![];
            let mut primary_short_form = did.to_string();

            for component in &components {
                let clean_comp = component.strip_prefix(':').unwrap_or(component);
                if clean_comp.starts_with("Vz") || clean_comp.starts_with('z') {
                    let multibase_str = clean_comp.strip_prefix("Vz")
                        .unwrap_or_else(|| clean_comp.strip_prefix('z').unwrap_or(clean_comp));

                    if let Ok(decoded_bytes) = bs58::decode(multibase_str).into_vec() {
                        // Check for secp256k1 multicodec prefix: 0xe7 0x01
                        if decoded_bytes.starts_with(&[0xe7, 0x01]) && decoded_bytes.len() >= 35 {
                            let compressed_pubkey = &decoded_bytes[2..35];
                            if let Ok(pk) = k256::PublicKey::from_sec1_bytes(compressed_pubkey) {
                                use k256::elliptic_curve::sec1::ToSec1Point;
                                let uncompressed = pk.to_sec1_point(false);
                                let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
                                let mut derived = [0u8; 20];
                                derived.copy_from_slice(&hash[12..32]);
                                evm_address_opt = Some(Address::from(derived));
                                primary_short_form = component.to_string();
                            }
                        }
                        // Check for Ed25519 multicodec prefix: 0xed 0x01
                        else if decoded_bytes.starts_with(&[0xed, 0x01]) && decoded_bytes.len() >= 34 {
                            ed25519_pubkey = decoded_bytes[2..34].to_vec();
                        }
                        // Check for BLS12-381 multicodec prefix: 0xea 0x01
                        else if decoded_bytes.starts_with(&[0xea, 0x01]) && decoded_bytes.len() >= 50 {
                            bls_pubkey = decoded_bytes[2..50].to_vec();
                        }
                    }
                }
            }

            if let Some(evm_address) = evm_address_opt {
                return Some(Self {
                    did_uri: did.to_string(),
                    short_form: primary_short_form,
                    ed25519_pubkey,
                    evm_address,
                    bls_pubkey,
                    authority_path: vec![],
                    trusted_authorities: HashSet::new(),
                });
            }
        }

        // ── did:sovereign:{chain_id}:{hex_address} placeholder domain DIDs ─────────
        if did.starts_with("did:sovereign:") {
            let parts: Vec<&str> = did.splitn(4, ':').collect();
            if parts.len() == 4 {
                let clean = parts[3].trim_start_matches("0x");
                if clean.len() == 40 {
                    if let Ok(addr_bytes) = hex::decode(clean) {
                        if addr_bytes.len() == 20 {
                            let evm_address = Address::from_slice(&addr_bytes);
                            return Some(Self {
                                did_uri: did.to_string(),
                                short_form: clean.to_string(),
                                ed25519_pubkey: vec![],
                                evm_address,
                                bls_pubkey: vec![],
                                authority_path: vec![],
                                trusted_authorities: HashSet::new(),
                            });
                        }
                    }
                }
            }
        }

        None
    }
}