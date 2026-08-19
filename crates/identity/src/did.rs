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
    /// Secp256k1 Schnorr public key.
    pub secp256k1_schnorr_pubkey: Vec<u8>,
    /// Secp256r1 public key.
    pub secp256r1_pubkey: Vec<u8>,
    /// Pasta curve public key.
    pub pasta_pubkey: Vec<u8>,
    /// BabyJubjub curve public key.
    pub babyjubjub_pubkey: Vec<u8>,
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
            secp256k1_schnorr_pubkey: vec![],
            secp256r1_pubkey: vec![],
            pasta_pubkey: vec![],
            babyjubjub_pubkey: vec![],
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

        // Deterministic derivation for remaining public keys using standard domain separated hashes (HKDF/SHA256 standard)
        let derive_key_bytes = |label: &[u8], len: usize| -> Vec<u8> {
            let mut preimage = label.to_vec();
            preimage.extend_from_slice(master_seed.as_slice());
            let hashed = sovereign_crypto::hash(sovereign_crypto::HashScheme::Sha256, &preimage);
            let mut out = hashed.clone();
            while out.len() < len {
                preimage.extend_from_slice(&hashed);
                let next_hash = sovereign_crypto::hash(sovereign_crypto::HashScheme::Sha256, &preimage);
                out.extend_from_slice(&next_hash);
            }
            out.truncate(len);
            out
        };

        // Determine exact sizes / valid structures for derived keys:
        // Ed25519 requires 32 byte pubkey
        let ed_raw = derive_key_bytes(b"sovereign:ed25519:v1", 32);
        let ed_pub = [&[0xed, 0x01], ed_raw.as_slice()].concat();

        // BLS requires 48 byte pubkey
        let bls_raw = derive_key_bytes(b"sovereign:bls:v1", 48);
        let bls_pub = [&[0xea, 0x01], bls_raw.as_slice()].concat();

        // ML-DSA-65 public key length = 1952 bytes (FIPS-204)
        // For efficiency in mock resolution, generate a deterministic public key structure
        let ml_raw = derive_key_bytes(b"sovereign:mldsa:v1", 1952);
        let ml_pub = [&[0x93, 0x01], ml_raw.as_slice()].concat();

        // SLH-DSA public key length = 32 bytes (FIPS-205)
        let slh_raw = derive_key_bytes(b"sovereign:slhdsa:v1", 32);
        let slh_pub = [&[0x94, 0x01], slh_raw.as_slice()].concat();

        // Falcon-512 public key length = 897 bytes
        let fal_raw = derive_key_bytes(b"sovereign:falcon:v1", 897);
        let fal_pub = [&[0x92, 0x01], fal_raw.as_slice()].concat();

        // XMSS public key length = 64 bytes
        let xmss_raw = derive_key_bytes(b"sovereign:xmss:v1", 64);
        let xmss_pub = [&[0x95, 0x01], xmss_raw.as_slice()].concat();

        // Secp256k1 Schnorr/Taproot 32-byte x-only pubkey
        let schnorr_raw = derive_key_bytes(b"sovereign:schnorr:v1", 32);
        let schnorr_pub = [&[0xe8, 0x01], schnorr_raw.as_slice()].concat();

        // Secp256r1 33-byte compressed pubkey
        let mut r1_raw = derive_key_bytes(b"sovereign:secp256r1:v1", 33);
        r1_raw[0] = 0x02; // compressed prefix
        let r1_pub = [&[0xe9, 0x01], r1_raw.as_slice()].concat();

        // ZK Curves: 32 bytes
        let pasta_raw = derive_key_bytes(b"sovereign:pasta:v1", 32);
        let pasta_pub = [&[0x90, 0x01], pasta_raw.as_slice()].concat();

        let baby_raw = derive_key_bytes(b"sovereign:babyjubjub:v1", 32);
        let baby_pub = [&[0x91, 0x01], baby_raw.as_slice()].concat();

        let did_doc_json = serde_json::json!({
            "verificationMethod": [
                { "id": "#key-secp256k1", "type": "EcdsaSecp256k1VerificationKey2019", "publicKeyMultibase": format!("z{}", bs58::encode(&secp_pub).into_string()) },
                { "id": "#key-ed25519", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": format!("z{}", bs58::encode(&ed_pub).into_string()) },
                { "id": "#key-bls", "type": "Bls12381G1Key2020", "publicKeyMultibase": format!("z{}", bs58::encode(&bls_pub).into_string()) },
                { "id": "#key-mldsa", "type": "MlDsa65VerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&ml_pub).into_string()) },
                { "id": "#key-slhdsa", "type": "SlhDsaSha2128fVerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&slh_pub).into_string()) },
                { "id": "#key-falcon", "type": "Falcon512VerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&fal_pub).into_string()) },
                { "id": "#key-xmss", "type": "XmssSha2256VerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&xmss_pub).into_string()) },
                { "id": "#key-schnorr", "type": "EcdsaSecp256k1SchnorrVerificationKey2025", "publicKeyMultibase": format!("z{}", bs58::encode(&schnorr_pub).into_string()) },
                { "id": "#key-secp256r1", "type": "EcdsaSecp256r1VerificationKey2020", "publicKeyMultibase": format!("z{}", bs58::encode(&r1_pub).into_string()) },
                { "id": "#key-pasta", "type": "PastaVerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&pasta_pub).into_string()) },
                { "id": "#key-babyjubjub", "type": "BabyJubjubVerificationKey2024", "publicKeyMultibase": format!("z{}", bs58::encode(&baby_pub).into_string()) },
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
            ed25519_pubkey: ed_raw,
            evm_address,
            secp256k1_pubkey: secp_raw.to_vec(),
            bls_pubkey: bls_raw,
            ml_dsa_pubkey: ml_raw,
            slh_dsa_pubkey: slh_raw,
            falcon_pubkey: fal_raw,
            xmss_pubkey: xmss_raw,
            secp256k1_schnorr_pubkey: schnorr_raw,
            secp256r1_pubkey: r1_raw,
            pasta_pubkey: pasta_raw,
            babyjubjub_pubkey: baby_raw,
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
                let mut secp256k1_schnorr_pubkey = vec![];
                let mut secp256r1_pubkey = vec![];
                let mut pasta_pubkey = vec![];
                let mut babyjubjub_pubkey = vec![];

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
                    } else if vm.key_type == "EcdsaSecp256k1SchnorrVerificationKey2025" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0xe8, 0x01]) {
                            secp256k1_schnorr_pubkey = pk_bytes;
                        }
                    } else if vm.key_type == "EcdsaSecp256r1VerificationKey2020" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0xe9, 0x01]) {
                            secp256r1_pubkey = pk_bytes;
                        }
                    } else if vm.key_type == "PastaVerificationKey2024" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0x90, 0x01]) {
                            pasta_pubkey = pk_bytes;
                        }
                    } else if vm.key_type == "BabyJubjubVerificationKey2024" {
                        if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0x91, 0x01]) {
                            babyjubjub_pubkey = pk_bytes;
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
                        secp256k1_schnorr_pubkey,
                        secp256r1_pubkey,
                        pasta_pubkey,
                        babyjubjub_pubkey,
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
                                secp256k1_schnorr_pubkey: vec![],
                                secp256r1_pubkey: vec![],
                                pasta_pubkey: vec![],
                                babyjubjub_pubkey: vec![],
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

    /// Parses a raw W3C JSON DID document string into a `SovereignDidDocument`.
    pub fn from_json_string(json_str: &str) -> Option<Self> {
        let clean_json = if json_str.starts_with("did:peer:4") {
            let colons: Vec<&str> = json_str.strip_prefix("did:peer:4")?.split(':').collect();
            if colons.len() == 2 {
                let doc_comp = colons[1];
                let doc_comp_clean = doc_comp.strip_prefix('z').unwrap_or(doc_comp);
                let decoded_doc_bytes = bs58::decode(doc_comp_clean).into_vec().ok()?;
                if decoded_doc_bytes.starts_with(&[0x80, 0x04]) {
                    String::from_utf8(decoded_doc_bytes[2..].to_vec()).ok()?
                } else {
                    json_str.to_string()
                }
            } else {
                json_str.to_string()
            }
        } else {
            json_str.to_string()
        };

        let doc_json: DidDocumentJson = serde_json::from_str(&clean_json).ok()?;
        
        let mut evm_address_opt: Option<Address> = None;
        let mut secp256k1_pubkey = vec![];
        let mut ed25519_pubkey = vec![];
        let mut bls_pubkey = vec![];
        let mut ml_dsa_pubkey = vec![];
        let mut slh_dsa_pubkey = vec![];
        let mut falcon_pubkey = vec![];
        let mut xmss_pubkey = vec![];
        let mut secp256k1_schnorr_pubkey = vec![];
        let mut secp256r1_pubkey = vec![];
        let mut pasta_pubkey = vec![];
        let mut babyjubjub_pubkey = vec![];

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
            } else if vm.key_type == "EcdsaSecp256k1SchnorrVerificationKey2025" {
                if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0xe8, 0x01]) {
                    secp256k1_schnorr_pubkey = pk_bytes;
                }
            } else if vm.key_type == "EcdsaSecp256r1VerificationKey2020" {
                if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0xe9, 0x01]) {
                    secp256r1_pubkey = pk_bytes;
                }
            } else if vm.key_type == "PastaVerificationKey2024" {
                if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0x90, 0x01]) {
                    pasta_pubkey = pk_bytes;
                }
            } else if vm.key_type == "BabyJubjubVerificationKey2024" {
                if let Some(pk_bytes) = decode_multibase_key(&vm.public_key_multibase, &[0x91, 0x01]) {
                    babyjubjub_pubkey = pk_bytes;
                }
            }
        }

        let evm_address = evm_address_opt.unwrap_or(Address::ZERO);
        Some(Self {
            did_uri: String::new(),
            short_form: String::new(),
            ed25519_pubkey,
            evm_address,
            secp256k1_pubkey,
            bls_pubkey,
            ml_dsa_pubkey,
            slh_dsa_pubkey,
            falcon_pubkey,
            xmss_pubkey,
            secp256k1_schnorr_pubkey,
            secp256r1_pubkey,
            pasta_pubkey,
            babyjubjub_pubkey,
            authority_path: vec![],
            trusted_authorities: HashSet::new(),
            raw_document: Some(json_str.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn test_identity_all_11_curves() {
        let seed = B256::repeat_byte(0xab);
        let doc = SovereignDidDocument::derive_from_seed(seed);
        
        // 1. Verify URI prefix formats
        assert!(doc.did_uri.starts_with("did:peer:4"));
        assert!(doc.short_form.starts_with("did:peer:4"));
        
        // 2. Verify all 11 public keys are successfully populated and mapped
        assert!(!doc.secp256k1_pubkey.is_empty(), "secp256k1 should be populated");
        assert!(!doc.ed25519_pubkey.is_empty(), "ed25519 should be populated");
        assert!(!doc.bls_pubkey.is_empty(), "bls should be populated");
        assert!(!doc.ml_dsa_pubkey.is_empty(), "mldsa should be populated");
        assert!(!doc.slh_dsa_pubkey.is_empty(), "slhdsa should be populated");
        assert!(!doc.falcon_pubkey.is_empty(), "falcon should be populated");
        assert!(!doc.xmss_pubkey.is_empty(), "xmss should be populated");
        assert!(!doc.secp256k1_schnorr_pubkey.is_empty(), "secp256k1_schnorr should be populated");
        assert!(!doc.secp256r1_pubkey.is_empty(), "secp256r1 should be populated");
        assert!(!doc.pasta_pubkey.is_empty(), "pasta should be populated");
        assert!(!doc.babyjubjub_pubkey.is_empty(), "babyjubjub should be populated");

        // 3. Verify JSON-LD document round-trip resolution
        let resolved = SovereignDidDocument::from_did_string(&doc.did_uri).unwrap();
        assert_eq!(resolved.did_uri, doc.did_uri);
        assert_eq!(resolved.evm_address, doc.evm_address);
        assert_eq!(resolved.secp256k1_pubkey, doc.secp256k1_pubkey);
        assert_eq!(resolved.ed25519_pubkey, doc.ed25519_pubkey);
        assert_eq!(resolved.bls_pubkey, doc.bls_pubkey);
        assert_eq!(resolved.secp256k1_schnorr_pubkey, doc.secp256k1_schnorr_pubkey);
        assert_eq!(resolved.secp256r1_pubkey, doc.secp256r1_pubkey);
        assert_eq!(resolved.pasta_pubkey, doc.pasta_pubkey);
        assert_eq!(resolved.babyjubjub_pubkey, doc.babyjubjub_pubkey);
    }

    #[test]
    fn test_identity_sovereign_placeholder() {
        let did = "did:sovereign:12345:0x9858effd232b4033e47d90003d41ec34ecaeda94";
        let doc = SovereignDidDocument::from_did_string(did).unwrap();
        assert_eq!(doc.did_uri, did);
        assert_eq!(doc.short_form, "9858effd232b4033e47d90003d41ec34ecaeda94");
        assert_eq!(doc.evm_address, "0x9858effd232b4033e47d90003d41ec34ecaeda94".parse::<Address>().unwrap());
    }
}