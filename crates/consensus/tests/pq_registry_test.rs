use alloy_primitives::Address;
use sovereign_consensus::pq_registry::{verify_registration_signatures, KeyTier};

#[test]
fn test_key_tier_parsing_and_str() {
    // GIVEN: String inputs representing different key tiers
    // WHEN: Parsing into KeyTier enum
    // THEN: Values parse correctly into Classical, QuantumReady, and QuantumOnly tiers
    assert_eq!(KeyTier::from_str("classical"), KeyTier::Classical);
    assert_eq!(KeyTier::from_str("quantumready"), KeyTier::QuantumReady);
    assert_eq!(KeyTier::from_str("ready"), KeyTier::QuantumReady);
    assert_eq!(KeyTier::from_str("quantumonly"), KeyTier::QuantumOnly);
    assert_eq!(KeyTier::from_str("only"), KeyTier::QuantumOnly);
    assert_eq!(KeyTier::from_str("unknown"), KeyTier::Classical);

    assert_eq!(KeyTier::Classical.to_str(), "Classical");
    assert_eq!(KeyTier::QuantumReady.to_str(), "QuantumReady");
    assert_eq!(KeyTier::QuantumOnly.to_str(), "QuantumOnly");
}

#[test]
fn test_verify_registration_signatures_classical() {
    // GIVEN: A DID document, message hash, and Secp256k1 signing key
    let doc = r#"{"id":"did:sovereign:1:0x1"}"#;
    let message_hash = alloy_primitives::keccak256(doc.as_bytes());

    let signing_key = k256::ecdsa::SigningKey::from_slice(&[0x55; 32]).unwrap();
    let verifying_key = signing_key.verifying_key();
    let uncompressed = verifying_key.to_sec1_point(false);
    let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&hash[12..32]);
    let classical_addr = Address::from(addr_bytes);

    // WHEN: Signing the document hash and recovering the address
    let (signature, recid) = signing_key.sign_prehash_recoverable(message_hash.as_slice());
    let mut sig_bytes = [0u8; 65];
    sig_bytes[0..64].copy_from_slice(&signature.to_bytes());
    sig_bytes[64] = recid.to_byte();

    let res = verify_registration_signatures(doc, &[], &classical_addr, &sig_bytes, &[]);

    // THEN: Registration signature is valid and authentic
    assert!(res.is_ok(), "Signature verification failed: {:?}", res.err());
}
