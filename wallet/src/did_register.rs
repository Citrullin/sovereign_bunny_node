//! # DID Document Builder
//!
//! Constructs a standard W3C JSON-LD DID Document from derived public keys.

use wasm_bindgen::prelude::*;
use serde_json::json;

/// Builds W3C JSON-LD DID Document from keys.
#[wasm_bindgen]
pub fn build_did_document(
    eth_address: &str,
    secp256k1_pub: &str,
    ed25519_pub: &str,
    bls_pub: &str,
    ml_dsa_pub: &str,
    slh_dsa_pub: &str,
    falcon_pub: &str,
) -> Result<String, JsValue> {
    let did_uri = format!("did:pkh:eip155:1:{}", eth_address);
    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": did_uri,
        "verificationMethod": [
            {
                "id": format!("{}#eth-key", did_uri),
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": did_uri,
                "publicKeyMultibase": secp256k1_pub,
                "note": "Primary EVM wallet key (Rabby). Used for all ETH transactions."
            },
            {
                "id": format!("{}#ed25519", did_uri),
                "type": "Ed25519VerificationKey2020",
                "controller": did_uri,
                "publicKeyMultibase": ed25519_pub,
                "note": "Classical EdDSA key. Used for DID-to-DID signing in non-EVM contexts."
            },
            {
                "id": format!("{}#bls12-381", did_uri),
                "type": "Bls12381G2VerificationKey2020",
                "controller": did_uri,
                "publicKeyMultibase": bls_pub,
                "note": "BLS aggregation key. Used for Snowman committee signature aggregation."
            },
            {
                "id": format!("{}#ml-dsa-87", did_uri),
                "type": "MlDsa87VerificationKey2024",
                "controller": did_uri,
                "publicKeyMultibase": ml_dsa_pub,
                "note": "Post-quantum signing key (ML-DSA-87 / CRYSTALS-Dilithium5). Enabled under active ZLQT."
            },
            {
                "id": format!("{}#slh-dsa", did_uri),
                "type": "SlhDsaVerificationKey2024",
                "controller": did_uri,
                "publicKeyMultibase": slh_dsa_pub,
                "note": "Post-quantum SPHINCS+ signing key."
            },
            {
                "id": format!("{}#falcon", did_uri),
                "type": "FalconVerificationKey2024",
                "controller": did_uri,
                "publicKeyMultibase": falcon_pub,
                "note": "Post-quantum Falcon signing key."
            }
        ],
        "authentication": [
            format!("{}#eth-key", did_uri),
            format!("{}#ml-dsa-87", did_uri)
        ],
        "keyAgreement": [
            format!("{}#bls12-381", did_uri)
        ],
        "capabilityInvocation": [
            format!("{}#eth-key", did_uri)
        ]
    });

    serde_json::to_string_pretty(&doc)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
