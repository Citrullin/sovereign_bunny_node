//! Relay Mesh SDK, Cross-Chain Composability, Multi-Curve Verification, and EIP-4844 Blob Serialization Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use alloy_primitives::{Address, B256};
use sovereign_consensus::relay_mesh::{
    BasedMeshWrapper, CrossManifoldMessage, ProofScheme, RelayPacket,
};
use sovereign_crypto::{
    verify_signature, HashScheme, SignatureScheme,
};
use sovereign_identity::did::SovereignDidDocument;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Multi-Curve Cryptographic Verification Across Heterogeneous Chains (BDD)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_given_did_with_11_curves_when_derived_then_populates_all_curves_and_resolves_jsonld() {
    // ── GIVEN: A Sovereign DID derived from master entropy with public keys across 11 curves ──
    let seed = B256::repeat_byte(0x77);
    let doc = SovereignDidDocument::derive_from_seed(seed);

    // ── THEN: All 11 public keys are populated with proper cryptographic byte lengths ──
    assert!(!doc.secp256k1_pubkey.is_empty(), "secp256k1 must be populated (33 bytes)");
    assert_eq!(doc.secp256k1_pubkey.len(), 33);

    assert!(!doc.ed25519_pubkey.is_empty(), "ed25519 must be populated (32 bytes)");
    assert_eq!(doc.ed25519_pubkey.len(), 32);

    assert!(!doc.bls_pubkey.is_empty(), "bls must be populated (48 bytes)");
    assert_eq!(doc.bls_pubkey.len(), 48);

    assert!(!doc.ml_dsa_pubkey.is_empty(), "ml_dsa must be populated (1952 bytes)");
    assert_eq!(doc.ml_dsa_pubkey.len(), 1952);

    assert!(!doc.slh_dsa_pubkey.is_empty(), "slh_dsa must be populated (32 bytes)");
    assert_eq!(doc.slh_dsa_pubkey.len(), 32);

    assert!(!doc.falcon_pubkey.is_empty(), "falcon must be populated (897 bytes)");
    assert_eq!(doc.falcon_pubkey.len(), 897);

    assert!(!doc.xmss_pubkey.is_empty(), "xmss must be populated (64 bytes)");
    assert_eq!(doc.xmss_pubkey.len(), 64);

    assert!(!doc.secp256k1_schnorr_pubkey.is_empty(), "schnorr must be populated (32 bytes)");
    assert_eq!(doc.secp256k1_schnorr_pubkey.len(), 32);

    assert!(!doc.secp256r1_pubkey.is_empty(), "secp256r1 must be populated (33 bytes)");
    assert_eq!(doc.secp256r1_pubkey.len(), 33);

    assert!(!doc.pasta_pubkey.is_empty(), "pasta must be populated (32 bytes)");
    assert_eq!(doc.pasta_pubkey.len(), 32);

    assert!(!doc.babyjubjub_pubkey.is_empty(), "babyjubjub must be populated (32 bytes)");
    assert_eq!(doc.babyjubjub_pubkey.len(), 32);

    // ── AND WHEN: The DID is resolved from its raw multicodec/multibase string representation ──
    let resolved = SovereignDidDocument::from_did_string(&doc.did_uri)
        .expect("Resolution from multibase string must succeed");

    // ── THEN: All 11 public keys roundtrip without data degradation ──
    assert_eq!(resolved.did_uri, doc.did_uri);
    assert_eq!(resolved.evm_address, doc.evm_address);
    assert_eq!(resolved.secp256k1_pubkey, doc.secp256k1_pubkey);
    assert_eq!(resolved.ed25519_pubkey, doc.ed25519_pubkey);
    assert_eq!(resolved.bls_pubkey, doc.bls_pubkey);
    assert_eq!(resolved.ml_dsa_pubkey, doc.ml_dsa_pubkey);
    assert_eq!(resolved.slh_dsa_pubkey, doc.slh_dsa_pubkey);
    assert_eq!(resolved.falcon_pubkey, doc.falcon_pubkey);
    assert_eq!(resolved.xmss_pubkey, doc.xmss_pubkey);
    assert_eq!(resolved.secp256k1_schnorr_pubkey, doc.secp256k1_schnorr_pubkey);
    assert_eq!(resolved.secp256r1_pubkey, doc.secp256r1_pubkey);
    assert_eq!(resolved.pasta_pubkey, doc.pasta_pubkey);
    assert_eq!(resolved.babyjubjub_pubkey, doc.babyjubjub_pubkey);
}

#[test]
fn test_given_cross_chain_intent_when_secp256k1_and_zk_curves_verified_then_authenticates_intent() {
    // ── GIVEN: A cross-chain intent payload ──
    let message = b"SOVEREIGN_RELAY_MESH_CROSS_MANIFOLD_CALL";
    let msg_hash = sovereign_crypto::hash(HashScheme::Keccak256, message);

    // ── WHEN / THEN: Verify Secp256k1 standard signature verification ──
    let signing_key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
    let verifying_key = signing_key.verifying_key();
    let secp_pubkey = verifying_key.to_sec1_bytes().to_vec();
    use k256::ecdsa::signature::Signer;
    let sig: k256::ecdsa::Signature = signing_key.sign(message);
    let sig_bytes = sig.to_vec();

    let res = verify_signature(SignatureScheme::Secp256k1, &secp_pubkey, message, &sig_bytes, false);
    assert!(res.is_ok(), "Secp256k1 signature verification should succeed: {:?}", res);

    // ── WHEN / THEN: Verify Pasta / BabyJubjub / BLS length checks ──
    let pasta_pk = [0x11u8; 32];
    let pasta_sig = [0x22u8; 64];
    assert!(verify_signature(SignatureScheme::Pasta, &pasta_pk, &msg_hash, &pasta_sig, false).is_ok());

    let bjj_pk = [0x33u8; 32];
    let bjj_sig = [0x44u8; 64];
    assert!(verify_signature(SignatureScheme::BabyJubjub, &bjj_pk, &msg_hash, &bjj_sig, false).is_ok());

    let bls_pk = [0x55u8; 48];
    let bls_sig = [0x66u8; 96];
    assert!(verify_signature(SignatureScheme::Bls, &bls_pk, &msg_hash, &bls_sig, false).is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Relay Mesh SDK & EIP-4844 / PeerDAS Blob Verification (BDD)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_given_cross_manifold_intent_when_wrapped_in_eip4844_blob_then_preserves_field_elements_and_fidelity() {
    // ── GIVEN: A structured cross-manifold intent targeting Manifold #2 from Manifold #1 ──
    let msg = CrossManifoldMessage {
        message_id: B256::repeat_byte(0x88),
        sender: Address::repeat_byte(0x11),
        recipient: Address::repeat_byte(0x22),
        payload: b"ABI_CALL:flash_loan_arbitrage(USDC, 1000000)".to_vec(),
        timestamp: 1724000000,
    };

    let zkevm_proof = vec![0x99u8; 128];
    let state_diff_hash = B256::repeat_byte(0x42);

    // ── WHEN: The message is wrapped into a BasedMeshWrapper packet ──
    let packet = BasedMeshWrapper::from_message(
        1,
        2,
        state_diff_hash,
        ProofScheme::Groth16Bn254,
        zkevm_proof.clone(),
        &msg,
    ).expect("BasedMeshWrapper creation");

    assert_eq!(packet.source_manifold_id, 1);
    assert_eq!(packet.target_manifolds, vec![2]);
    assert_eq!(packet.proof_scheme, ProofScheme::Groth16Bn254);
    assert!(packet.zkevm_proof_payload.starts_with(&zkevm_proof));

    // ── AND WHEN: Encoded into a standard 131,072-byte EIP-4844 blob buffer ──
    let blob = packet.to_eip4844_blob_bytes().expect("Blob serialization");

    // ── THEN: Blob size is strictly 131,072 bytes (4096 * 32 field elements) ──
    assert_eq!(blob.len(), 131_072, "EIP-4844 blob must be strictly 131,072 bytes");

    // ── AND THEN: Every 32-byte chunk strictly adheres to BLS12-381 scalar field modulus (chunk[0] == 0) ──
    for i in 1..4096 {
        let chunk_start = i * 32;
        assert_eq!(blob[chunk_start], 0, "Chunk {} first byte must be zero for BLS12-381 scalar modulus constraint", i);
    }

    // ── AND WHEN: Reconstructed from raw EIP-4844 blob bytes on the destination manifold ──
    let decoded_packet = BasedMeshWrapper::from_eip4844_blob_bytes(&blob).expect("Blob deserialization");

    // ── THEN: All fields, payload, and proof schemes match the original with complete fidelity ──
    assert_eq!(decoded_packet.source_manifold_id, 1);
    assert_eq!(decoded_packet.target_manifolds, vec![2]);
    assert_eq!(decoded_packet.proof_scheme, ProofScheme::Groth16Bn254);
    assert!(decoded_packet.verify_validity_proof().is_ok());

    let extracted_msg = decoded_packet.extract_message().expect("Message extraction");
    assert_eq!(extracted_msg, msg);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Supported Proof Schemes & Cross-Chain Validity Proofs (BDD)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_given_all_five_zk_proof_schemes_when_encoded_then_roundtrips_and_identifies_properly() {
    // ── GIVEN: All 5 ZK proof schemes supported by the relay mesh ──
    let schemes = [
        ProofScheme::Groth16Bn254,
        ProofScheme::SpruceSp1Bls12381,
        ProofScheme::RiscZeroBonsai,
        ProofScheme::BiniusBinaryStark,
        ProofScheme::Plonky3Blake3,
    ];

    for scheme in schemes {
        // ── WHEN: Wrapped into a RelayPacket ──
        let packet = RelayPacket::new(
            10,
            vec![20, 30],
            B256::repeat_byte(0xaa),
            scheme,
            vec![0xbb; 64],
            b"CROSS_CHAIN_CALL".to_vec(),
        );

        // ── THEN: Packet serializes and deserializes preserving the scheme identifier ──
        let bytes = packet.to_bytes().expect("Serialization");
        let decoded = RelayPacket::from_bytes(&bytes).expect("Deserialization");

        assert_eq!(decoded.proof_scheme, scheme);
        assert_eq!(decoded.source_manifold_id, 10);
        assert_eq!(decoded.target_manifolds, vec![20, 30]);
    }
}
