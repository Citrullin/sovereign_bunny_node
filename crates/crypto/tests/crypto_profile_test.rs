use sovereign_crypto::{
    hash, parse_scheme, verify_signature, CryptoProfile, HashScheme, PairingCurve, SignatureScheme,
    StateTreeScheme,
};

#[test]
fn test_crypto_profiles() {
    let eth = CryptoProfile::from_name("ethereum").unwrap();
    assert_eq!(eth.signature, SignatureScheme::Secp256k1);
    assert_eq!(eth.hash, HashScheme::Keccak256);
    assert_eq!(eth.pairing_curve, PairingCurve::Bn254);
    assert_eq!(eth.state_tree, StateTreeScheme::Verkle);

    let pq = CryptoProfile::from_name("quantum_standard").unwrap();
    assert_eq!(pq.signature, SignatureScheme::MlDsa);
    assert!(pq.signature.is_post_quantum());

    let throughput = CryptoProfile::from_name("throughput").unwrap();
    assert_eq!(throughput.signature, SignatureScheme::Ed25519);
    assert_eq!(throughput.hash, HashScheme::Blake3);

    assert!(CryptoProfile::from_name("invalid_profile").is_err());
}

#[test]
fn test_parse_schemes() {
    assert_eq!(parse_scheme("secp256k1").unwrap(), SignatureScheme::Secp256k1);
    assert_eq!(parse_scheme("ed25519").unwrap(), SignatureScheme::Ed25519);
    assert_eq!(parse_scheme("mldsa").unwrap(), SignatureScheme::MlDsa);
    assert_eq!(parse_scheme("falcon").unwrap(), SignatureScheme::Falcon);
    assert_eq!(parse_scheme("slhdsa").unwrap(), SignatureScheme::SlhDsa);
}

#[test]
fn test_hash_functions() {
    let data = b"hello sovereign";
    let h_keccak = hash(HashScheme::Keccak256, data);
    let h_blake3 = hash(HashScheme::Blake3, data);
    let h_sha256 = hash(HashScheme::Sha256, data);
    let h_poseidon = hash(HashScheme::Poseidon, data);

    assert_eq!(h_keccak.len(), 32);
    assert_eq!(h_blake3.len(), 32);
    assert_eq!(h_sha256.len(), 32);
    assert_eq!(h_poseidon.len(), 32);

    assert_ne!(h_keccak, h_blake3);
    assert_ne!(h_blake3, h_sha256);
}

#[test]
fn test_quantum_threat_trigger_rejection() {
    let msg = b"test message";
    let dummy_pk = [0u8; 33];
    let dummy_sig = [0u8; 64];

    // Classical signature scheme should be rejected if quantum_threat is true
    let res = verify_signature(SignatureScheme::Secp256k1, &dummy_pk, msg, &dummy_sig, true);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("quantum threat"));
}
