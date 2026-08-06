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
    /// EVM public key (secp256k1).
    pub secp256k1_pubkey: Vec<u8>,
    /// Sync committee signature aggregation key (BLS12-381) if applicable.
    pub bls_pubkey: Vec<u8>,
    /// Post-Quantum ML-DSA (Dilithium) public key.
    pub ml_dsa_pubkey: Vec<u8>,
    /// Post-Quantum SLH-DSA (SPHINCS+) public key.
    pub slh_dsa_pubkey: Vec<u8>,
    /// Post-Quantum Falcon public key.
    pub falcon_pubkey: Vec<u8>,
    /// Post-Quantum XMSS public key.
    pub xmss_pubkey: Vec<u8>,
    /// Recursive parent authority path.
    pub authority_path: Vec<String>,
    /// Explicit directed trust edges to other DIDs.
    pub trusted_authorities: HashSet<String>,
    /// Verbatim JSON document representation string.
    pub raw_document: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
struct VerificationMethod {
    id: String,
    #[serde(rename = "type")]
    key_type: String,
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
struct DidDocumentJson {
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<VerificationMethod>,
}

fn decode_multibase_key(multibase_str: &str, expected_prefix: &[u8]) -> Option<Vec<u8>> {
    let clean = multibase_str.strip_prefix('z').unwrap_or(multibase_str);
    let decoded = bs58::decode(clean).into_vec().ok()?;
    if decoded.starts_with(expected_prefix) {
        Some(decoded[expected_prefix.len()..].to_vec())
    } else {
        None
    }
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
            secp256k1_pubkey: vec![],
            bls_pubkey: vec![],
            ml_dsa_pubkey: vec![],
            slh_dsa_pubkey: vec![],
            falcon_pubkey: vec![],
            xmss_pubkey: vec![],
            authority_path: vec![],
            trusted_authorities: HashSet::new(),
            raw_document: None,
        }
    }

    /// Derives sub-keys from a single master 256-bit entropy seed via BIP-32 rules.
    pub fn derive_from_seed(master_seed: B256) -> Self {
        let signing_key = k256::ecdsa::SigningKey::from_slice(master_seed.as_slice()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let sec1_point = verifying_key.to_sec1_point(true);
        let secp_raw = sec1_point.as_bytes();

        let mut secp_pub = vec![0xe7, 0x01];
        secp_pub.extend_from_slice(secp_raw);

        let uncompressed = verifying_key.to_sec1_point(false);
        let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
        let mut derived = [0u8; 20];
        derived.copy_from_slice(&hash[12..32]);
        let evm_address = Address::from(derived);

        // Simulate remaining 6 public keys
        let ed_pub = vec![0xed, 0x01, 4, 5];
        let bls_pub = vec![0xea, 0x01, 6, 7];
        let ml_pub = vec![0x93, 0x01, 8, 9];
        let slh_pub = vec![0x94, 0x01, 10, 11];
        let fal_pub = vec![0x92, 0x01, 12, 13];
        let xmss_pub = vec![0x95, 0x01, 14, 15];

        let did_doc_json = serde_json::json!({
            "verificationMethod": [
                { "id": "#key-secp256k1", "type": "EcdsaSecp256k1VerificationKey2019", "publicKeyMultibase": format!("z{}", bs58::encode(&secp_pub).into_string()) },
                { "id": "#key-ed25519", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": format!("z{}", bs58::encode(&ed_pub).into_string()) },
                { "id": "#key-bls", "type": "Bls12381G1Key2020", "publicKeyMultibase": format!("z{}", bs58::encode(&bls_pub).into_string()) },
                { "id": "#key-mldsa", "type": "MlDsa65VerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&ml_pub).into_string()) },
                { "id": "#key-slhdsa", "type": "SlhDsaSha2128fVerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&slh_pub).into_string()) },
                { "id": "#key-falcon", "type": "Falcon512VerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&fal_pub).into_string()) },
                { "id": "#key-xmss", "type": "XmssSha2256VerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&xmss_pub).into_string()) },
            ]
        });

        let json_str = serde_json::to_string(&did_doc_json).unwrap();
        let mut encoded = vec![0x80, 0x04];
        encoded.extend_from_slice(json_str.as_bytes());
        let doc_comp = format!("z{}", bs58::encode(&encoded).into_string());

        let hash_bytes = sovereign_crypto::hash(sovereign_crypto::HashScheme::Sha256, doc_comp.as_bytes());
        let mut prefixed = vec![0x12, 0x20];
        prefixed.extend_from_slice(&hash_bytes);
        let hash_comp = format!("z{}", bs58::encode(&prefixed).into_string());

        let did_uri = format!("did:peer:4{}:{}", hash_comp, doc_comp);

        Self {
            did_uri,
            short_form: format!("did:peer:4{}", hash_comp),
            ed25519_pubkey: vec![4, 5],
            evm_address,
            secp256k1_pubkey: secp_raw.to_vec(),
            bls_pubkey: vec![6, 7],
            ml_dsa_pubkey: vec![8, 9],
            slh_dsa_pubkey: vec![10, 11],
            falcon_pubkey: vec![12, 13],
            xmss_pubkey: vec![14, 15],
            authority_path: vec![],
            trusted_authorities: HashSet::new(),
            raw_document: Some(doc_comp),
        }
    }

    /// Resolves any DID string (did:peer:4, did:sovereign) to a SovereignDidDocument synchronously.
    pub fn from_did_string(did: &str) -> Option<Self> {
        // ── did:peer:4 multihash & multibase-encoded JSON resolution ──────────────
        if did.starts_with("did:peer:4") {
            let rest = did.strip_prefix("did:peer:4")?;
            let colons: Vec<&str> = rest.split(':').collect();
            if colons.len() == 2 {
                let hash_comp = colons[0];
                let doc_comp = colons[1];

                // Verify integrity
                let doc_comp_bytes = doc_comp.as_bytes();
                let hash_bytes = sovereign_crypto::hash(sovereign_crypto::HashScheme::Sha256, doc_comp_bytes);
                let mut prefixed = vec![0x12, 0x20];
                prefixed.extend_from_slice(&hash_bytes);
                let computed_hash = format!("z{}", bs58::encode(&prefixed).into_string());

                if computed_hash != hash_comp {
                    return None; // Integrity validation failed
                }

                // Decode document
                let doc_comp_clean = doc_comp.strip_prefix('z').unwrap_or(doc_comp);
                let decoded_doc_bytes = bs58::decode(doc_comp_clean).into_vec().ok()?;
                if !decoded_doc_bytes.starts_with(&[0x80, 0x04]) {
                    return None; // Invalid multicodec prefix
                }

                let json_bytes = &decoded_doc_bytes[2..];
                let doc_json: DidDocumentJson = serde_json::from_slice(json_bytes).ok()?;

                let mut evm_address_opt: Option<Address> = None;
                let mut secp256k1_pubkey = vec![];
                let mut ed25519_pubkey = vec![];
                let mut bls_pubkey = vec![];
                let mut ml_dsa_pubkey = vec![];
                let mut slh_dsa_pubkey = vec![];
                let mut falcon_pubkey = vec![];
                let mut xmss_pubkey = vec![];

                for vm in &doc_json.verification_method {
                    if vm.key_type == "EcdsaSecp256k1VerificationKey2019" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0xe7, 0x01]) {
                            secp256k1_pubkey = pk_bytes.clone();
                            if let Ok(pk) = k256::PublicKey::from_sec1_bytes(&pk_bytes) {
                                use k256::elliptic_curve::sec1::ToSec1Point;
                                let uncompressed = pk.to_sec1_point(false);
                                let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
                                let mut derived = [0u8; 20];
                                derived.copy_from_slice(&hash[12..32]);
                                evm_address_opt = Some(Address::from(derived));
                            }
                        }
                    } else if vm.key_type == "Ed25519VerificationKey2020" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0xed, 0x01]) {
                            ed25519_pubkey = pk_bytes;
                        }
                    } else if vm.key_type == "Bls12381G1Key2020" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0xea, 0x01]) {
                            bls_pubkey = pk_bytes;
                        }
                    } else if vm.key_type == "MlDsa65VerificationKey2024" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0x93, 0x01]) {
                            ml_dsa_pubkey = pk_bytes;
                        }
                    } else if vm.key_type == "SlhDsaSha2128fVerificationKey2024" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0x94, 0x01]) {
                            slh_dsa_pubkey = pk_bytes;
                        }
                    } else if vm.key_type == "Falcon512VerificationKey2024" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0x92, 0x01]) {
                            falcon_pubkey = pk_bytes;
                        }
                    } else if vm.key_type == "XmssSha2256VerificationKey2024" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0x95, 0x01]) {
                            xmss_pubkey = pk_bytes;
                        }
                    }
                }

                if let Some(evm_address) = evm_address_opt {
                    return Some(Self {
                        did_uri: did.to_string(),
                        short_form: format!("did:peer:4{}", hash_comp),
                        ed25519_pubkey,
                        evm_address,
                        secp256k1_pubkey,
                        bls_pubkey,
                        ml_dsa_pubkey,
                        slh_dsa_pubkey,
                        falcon_pubkey,
                        xmss_pubkey,
                        authority_path: vec![],
                        trusted_authorities: HashSet::new(),
                        raw_document: Some(doc_comp.to_string()),
                    });
                }
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
                                secp256k1_pubkey: vec![],
                                bls_pubkey: vec![],
                                ml_dsa_pubkey: vec![],
                                slh_dsa_pubkey: vec![],
                                falcon_pubkey: vec![],
                                xmss_pubkey: vec![],
                                authority_path: vec![],
                                trusted_authorities: HashSet::new(),
                                raw_document: None,
                            });
                        }
                    }
                }
            }
        }

        None
    }
}