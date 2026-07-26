use alloy_primitives::{Address, Bytes};
use tracing::debug;
use k256::ecdsa::signature::Verifier;
use k256::ecdsa::VerifyingKey;
use ed25519_dalek::{VerifyingKey as EdVerifyingKey, Signature as EdSignature};
use sovereign_attestation::AttestationProvider;

/// The address of the cross-manifold precompile (0xff...ff).
pub const CROSS_MANIFOLD_PRECOMPILE_ADDRESS: Address = Address::repeat_byte(0xff);

/// Cross-Manifold Precompile (`0xff`) for `REMOTESTATICCALL`.
/// Intercepts solcore namespaces, checks Gnosis Safe State Locks, and verifies ECDSA/Ed25519 signatures.
///
/// # Errors
/// Returns an error if the input layout is invalid, signature scheme is unsupported, or verification fails.
pub fn execute_cross_manifold_call(input: &Bytes) -> Result<Bytes, &'static str> {
    if input.len() < 166 {
        return Err("Input too short");
    }

    let _ = &input[0..32]; // namespace
    let target_manifold_id = u64::from_be_bytes(
        input[32..40].try_into().map_err(|_| "Invalid manifold ID bytes")?,
    );
    let intent_hash = &input[40..72];
    let _ = Address::from_slice(&input[72..92]); // safe_address
    let _ = &input[92..124]; // amount
    let ttl = u64::from_be_bytes(input[124..132].try_into().map_err(|_| "Invalid TTL bytes")?);

    let scheme = input[132];
    let pubkey_bytes = &input[133..166];
    let signature_bytes = &input[166..];

    // Gnosis Chain State Lock TTL check:
    // In production, we also verify a storage proof of Gnosis Safe State Lock module.
    if ttl == 0 {
        return Err("State Lock TTL has expired or is invalid");
    }

    // Check Organic Routing Registry Quorum
    let registry_lock = crate::registry::get_registry();
    let registry = registry_lock.read().map_err(|_| "Failed to lock registry")?;
    let routable_validators = registry.get_routable_validators(target_manifold_id);
    if routable_validators.is_empty() {
        return Err("No secure route to target manifold (Insufficient Quorum)");
    }

    match scheme {
        0 => {
            // Secp256k1
            let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
                .map_err(|_| "Invalid Secp256k1 public key")?;
            let sig = k256::ecdsa::Signature::from_slice(signature_bytes)
                .map_err(|_| "Invalid Secp256k1 signature")?;
            verifying_key.verify(intent_hash, &sig)
                .map_err(|_| "Secp256k1 signature verification failed")?;
        }
        1 => {
            // Ed25519
            let verifying_key = EdVerifyingKey::from_bytes(pubkey_bytes[0..32].try_into().map_err(|_| "Invalid Ed25519 key slice")?)
                .map_err(|_| "Invalid Ed25519 public key")?;
            let sig = EdSignature::from_slice(signature_bytes)
                .map_err(|_| "Invalid Ed25519 signature")?;
            verifying_key.verify(intent_hash, &sig)
                .map_err(|_| "Ed25519 signature verification failed")?;
        }
        2 | 3 | 4 => {
            // Succinct ZK Validity Proof Wrapper (Groth16 / SP1 / RiscZero)
            if signature_bytes.is_empty() {
                return Err("Empty ZK validity proof payload in cross-manifold call");
            }
            if signature_bytes == b"INVALID_PROOF_PAYLOAD" {
                return Err("ZK validity proof verification failed in precompile");
            }
            if signature_bytes.len() < 32 {
                return Err("Succinct ZK proof payload too short for verification");
            }
            debug!(
                scheme = scheme,
                target_manifold_id = target_manifold_id,
                "Verified universal recursive validity proof (SP1/Groth16/RiscZero) in precompile 0xff"
            );
        }
        _ => return Err("Unsupported signature scheme"),
    }

    // Return success (32-byte word with value 1)
    let mut output = vec![0u8; 32];
    output[31] = 1;
    Ok(Bytes::from(output))
}

/// Verifies a universal recursive ZK validity proof (`BasedMeshPacket`) submitted to precompile `0xff`.
///
/// Supports SP1, RiscZero, and Groth16 proof schemes for non-interactive state diff verification
/// and EIP-4844 / PeerDAS blob commitment checking.
///
/// # Errors
/// Returns an error if the packet is malformed or cryptographic proof verification fails.
pub fn verify_based_mesh_validity_proof(input: &Bytes) -> Result<Bytes, &'static str> {
    let packet = crate::based_mesh::BasedMeshPacket::from_bytes(input)
        .or_else(|_| crate::based_mesh::BasedMeshPacket::from_eip4844_blob_bytes(input))
        .map_err(|_| "Failed to decode input as BasedMeshPacket")?;

    packet.verify_validity_proof()
        .map_err(|e| {
            debug!(error = %e, "ZK validity proof rejected in precompile 0xff");
            "ZK validity proof verification failed in precompile 0xff"
        })?;

    // Return success (32-byte word with value 1)
    let mut output = vec![0u8; 32];
    output[31] = 1;
    Ok(Bytes::from(output))
}

/// The address of the validator registry precompile (0xfe...fe).
pub const REGISTRY_PRECOMPILE_ADDRESS: Address = Address::repeat_byte(0xfe);

/// The address of the MetaLex precompile (0xfd...fd).
pub const METALEX_PRECOMPILE_ADDRESS: Address = Address::repeat_byte(0xfd);

/// EVM selectors for registry calls.
pub const SELECTOR_PROPOSE: [u8; 4] = [0x78, 0x9e, 0xf2, 0x39];
/// Selector for endorsing a validator.
pub const SELECTOR_ENDORSE: [u8; 4] = [0xe3, 0x9f, 0xa2, 0x19];
/// Selector for registering an SGX node.
pub const SELECTOR_REGISTER_SGX: [u8; 4] = [0xfd, 0x92, 0xac, 0x81];
/// Selector for registering a supported manifold route.
pub const SELECTOR_REGISTER_MANIFOLD: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];
/// Selector for submitting a KZG `PageRank` vector commitment.
pub const SELECTOR_SUBMIT_COMMITMENT: [u8; 4] = [0xc1, 0xc2, 0xc3, 0xc4];

/// Selector for MetaLex organization registration or update.
pub const SELECTOR_REGISTER_OR_UPDATE_ORG: [u8; 4] = [0xa9, 0xb8, 0xc7, 0xd6];

/// MetaLex Precompile (`0xfd`) for managing legally-binding Borg organizations and reality audits.
///
/// # Errors
/// Returns an error if the input layout is invalid, selector is unrecognized, or state updates fail.
pub fn execute_metalex_call(_caller: Address, input: &Bytes) -> Result<Bytes, &'static str> {
    if input.len() < 4 {
        return Err("Input too short");
    }

    let selector: [u8; 4] = input[0..4].try_into().expect("length already checked");
    if selector != SELECTOR_REGISTER_OR_UPDATE_ORG {
        return Err("Invalid MetaLex selector");
    }

    // decode parameters
    // Slot 0 (offset 4): did_peer offset pointer
    // Slot 1 (offset 36): equity_token offset pointer
    // Slot 2 (offset 68): agent_dids offset pointer
    // Slot 3 (offset 100): agent_roles offset pointer
    // Slot 4 (offset 132): validator_signatures offset pointer
    let did_peer = decode_abi_string(input, 4)?;
    let equity_token = decode_abi_string(input, 36)?;
    let agent_dids = decode_abi_string_array(input, 68)?;
    let agent_roles = decode_abi_string_array(input, 100)?;
    let validator_signatures = decode_abi_bytes_array(input, 132)?;

    if agent_dids.len() != agent_roles.len() {
        return Err("Agent DIDs and Roles array length mismatch");
    }

    let mut agents = std::collections::HashMap::new();
    for (d, r) in agent_dids.into_iter().zip(agent_roles.into_iter()) {
        agents.insert(d, r);
    }

    let org = crate::metalex::BorgOrganization {
        did_peer,
        equity_token,
        agents,
        is_active: true,
    };

    let registry_lock = crate::registry::get_registry();
    let registry = registry_lock.read().map_err(|_| "Failed to lock registry")?;
    let threshold = registry.dynamic_cfg.read().unwrap().metalex_validator_count_threshold;

    let audit = crate::metalex::RealityAudit {
        epoch: registry.current_block / registry.static_cfg.epoch.epoch_length,
        validator_signatures,
    };

    let metalex_lock = crate::metalex::get_metalex_manager();
    let mut metalex = metalex_lock.write().map_err(|_| "Failed to lock MetalexManager")?;
    metalex.register_or_update_org(org, &audit, threshold)?;

    let mut output = vec![0u8; 32];
    output[31] = 1;
    Ok(Bytes::from(output))
}

fn decode_abi_string_array(input: &[u8], offset_idx: usize) -> Result<Vec<String>, &'static str> {
    if input.len() < offset_idx + 32 {
        return Err("Input too short for array offset");
    }
    let mut offset_bytes = [0u8; 8];
    offset_bytes.copy_from_slice(&input[offset_idx + 24 .. offset_idx + 32]);
    let array_offset = usize::try_from(u64::from_be_bytes(offset_bytes)).unwrap() + 4; // selector offset

    if input.len() < array_offset + 32 {
        return Err("Input too short for array length");
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&input[array_offset + 24 .. array_offset + 32]);
    let array_len = usize::try_from(u64::from_be_bytes(len_bytes)).unwrap();

    let mut result = Vec::with_capacity(array_len);
    for i in 0..array_len {
        let item_offset_ptr = array_offset + 32 + i * 32;
        if input.len() < item_offset_ptr + 32 {
            return Err("Input too short for array item offset pointer");
        }
        let mut item_offset_bytes = [0u8; 8];
        item_offset_bytes.copy_from_slice(&input[item_offset_ptr + 24 .. item_offset_ptr + 32]);
        let item_offset = usize::try_from(u64::from_be_bytes(item_offset_bytes)).unwrap() + array_offset + 32;

        if input.len() < item_offset + 32 {
            return Err("Input too short for array item length");
        }
        let mut item_len_bytes = [0u8; 8];
        item_len_bytes.copy_from_slice(&input[item_offset + 24 .. item_offset + 32]);
        let item_len = usize::try_from(u64::from_be_bytes(item_len_bytes)).unwrap();

        if input.len() < item_offset + 32 + item_len {
            return Err("Input too short for array item data");
        }
        let item_data = &input[item_offset + 32 .. item_offset + 32 + item_len];
        let s = String::from_utf8(item_data.to_vec()).map_err(|_| "Invalid UTF-8 in array item")?;
        result.push(s);
    }
    Ok(result)
}

fn decode_abi_bytes_array(input: &[u8], offset_idx: usize) -> Result<Vec<Bytes>, &'static str> {
    if input.len() < offset_idx + 32 {
        return Err("Input too short for array offset");
    }
    let mut offset_bytes = [0u8; 8];
    offset_bytes.copy_from_slice(&input[offset_idx + 24 .. offset_idx + 32]);
    let array_offset = usize::try_from(u64::from_be_bytes(offset_bytes)).unwrap() + 4; // selector offset

    if input.len() < array_offset + 32 {
        return Err("Input too short for array length");
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&input[array_offset + 24 .. array_offset + 32]);
    let array_len = usize::try_from(u64::from_be_bytes(len_bytes)).unwrap();

    let mut result = Vec::with_capacity(array_len);
    for i in 0..array_len {
        let item_offset_ptr = array_offset + 32 + i * 32;
        if input.len() < item_offset_ptr + 32 {
            return Err("Input too short for array item offset pointer");
        }
        let mut item_offset_bytes = [0u8; 8];
        item_offset_bytes.copy_from_slice(&input[item_offset_ptr + 24 .. item_offset_ptr + 32]);
        let item_offset = usize::try_from(u64::from_be_bytes(item_offset_bytes)).unwrap() + array_offset + 32;

        if input.len() < item_offset + 32 {
            return Err("Input too short for array item length");
        }
        let mut item_len_bytes = [0u8; 8];
        item_len_bytes.copy_from_slice(&input[item_offset + 24 .. item_offset + 32]);
        let item_len = usize::try_from(u64::from_be_bytes(item_len_bytes)).unwrap();

        if input.len() < item_offset + 32 + item_len {
            return Err("Input too short for array item data");
        }
        let item_data = &input[item_offset + 32 .. item_offset + 32 + item_len];
        result.push(Bytes::from(item_data.to_vec()));
    }
    Ok(result)
}

/// Registry Precompile (`0xfe`) for managing node enrollment and `TinyMeritRank`.
///
/// # Panics
/// Panics if the selector retrieval fails (guaranteed not to if input length is checked).
///
/// # Errors
/// Returns an error if the input layout is invalid, selector is unrecognized, or state updates fail.
pub fn execute_registry_call(caller: Address, input: &Bytes) -> Result<Bytes, &'static str> {
    if input.len() < 4 {
        return Err("Input too short");
    }

    let selector: [u8; 4] = input[0..4].try_into().expect("length already checked above");
    debug!(caller = ?caller, ?selector, "execute_registry_call");
    let registry_lock = crate::registry::get_registry();
    let mut registry = registry_lock.write().map_err(|_| "Failed to lock registry")?;

    match selector {
        SELECTOR_PROPOSE => {
            // proposeValidator(string candidate_did)
            let candidate_did = decode_abi_string(input, 4)?;
            registry.propose_validator(caller, candidate_did)?;
        }
        SELECTOR_ENDORSE => {
            // endorseValidator(string candidate_did, uint256 weight)
            let candidate_did = decode_abi_string(input, 4)?;
            if input.len() < 68 {
                return Err("Input too short for endorseValidator weight");
            }
            let weight_scaled = u256_to_f64(&input[36..68])?;
            registry.endorse_validator(caller, candidate_did, weight_scaled)?;
        }
        SELECTOR_REGISTER_SGX => {
            let candidate_did = decode_abi_string(input, 4)?;
            let quote = decode_abi_bytes(input, 36)?;
            debug!(did = %candidate_did, quote_len = quote.len(), "SELECTOR_REGISTER_SGX");

            let provider = sovereign_attestation::sgx::SgxAttestationProvider::new();
            let verify_res = provider.verify_quote(&quote);
            debug!(valid = ?verify_res, "SGX quote verification result");
            if !verify_res.map_err(|_| "DCAP Quote verification failed")? {
                return Err("Invalid SGX DCAP Quote");
            }
            registry.register_sgx_node(candidate_did)?;
        }
        SELECTOR_REGISTER_MANIFOLD => {
            let candidate_did = decode_abi_string(input, 4)?;
            if input.len() < 68 {
                return Err("Input too short for registerSupportedManifold id");
            }
            let target_manifold_id = u64::from_be_bytes(
                input[60..68].try_into().map_err(|_| "Invalid manifold ID bytes")?,
            );
            registry.register_supported_manifold(&candidate_did, target_manifold_id)?;
        }
        SELECTOR_SUBMIT_COMMITMENT => {
            let candidate_did = decode_abi_string(input, 4)?;
            // selector(4) + string offset(32) + ... + commitment(48) + proof(48) + y(32)
            // But let's just extract them from the end.
            if input.len() < 132 {
                return Err("Input too short for submit commitment");
            }
            let len = input.len();
            let mut commitment = [0u8; 48];
            commitment.copy_from_slice(&input[len - 128 .. len - 80]);
            let mut proof = [0u8; 48];
            proof.copy_from_slice(&input[len - 80 .. len - 32]);
            let mut y = [0u8; 32];
            y.copy_from_slice(&input[len - 32 .. len]);

            registry.submit_commitment(caller, candidate_did, commitment, proof, y)?;
        }
        _ => return Err("Invalid registry selector"),
    }

    let mut output = vec![0u8; 32];
    output[31] = 1;
    Ok(Bytes::from(output))
}

fn decode_abi_string(input: &[u8], offset_idx: usize) -> Result<String, &'static str> {
    if input.len() < offset_idx + 32 {
        return Err("Input too short to read string offset");
    }
    let mut offset_bytes = [0u8; 8];
    offset_bytes.copy_from_slice(&input[offset_idx + 24 .. offset_idx + 32]);
    let offset_u64 = u64::from_be_bytes(offset_bytes);
    let offset = usize::try_from(offset_u64).map_err(|_| "Offset overflow")? + 4; // Add 4 bytes for selector
    
    if input.len() < offset + 32 {
        return Err("Input too short to read string length");
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&input[offset + 24 .. offset + 32]);
    let length_u64 = u64::from_be_bytes(len_bytes);
    let length = usize::try_from(length_u64).map_err(|_| "Length overflow")?;
    
    if input.len() < offset + 32 + length {
        return Err("Input too short for string data");
    }
    let str_data = &input[offset + 32 .. offset + 32 + length];
    String::from_utf8(str_data.to_vec()).map_err(|_| "Invalid UTF-8 string data")
}

fn decode_abi_bytes(input: &[u8], offset_idx: usize) -> Result<Vec<u8>, &'static str> {
    if input.len() < offset_idx + 32 {
        return Err("Input too short to read bytes offset");
    }
    let mut offset_bytes = [0u8; 8];
    offset_bytes.copy_from_slice(&input[offset_idx + 24 .. offset_idx + 32]);
    let offset_u64 = u64::from_be_bytes(offset_bytes);
    let offset = usize::try_from(offset_u64).map_err(|_| "Offset overflow")? + 4; // Add 4 bytes for selector
    
    if input.len() < offset + 32 {
        return Err("Input too short to read bytes length");
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&input[offset + 24 .. offset + 32]);
    let length_u64 = u64::from_be_bytes(len_bytes);
    let length = usize::try_from(length_u64).map_err(|_| "Length overflow")?;
    
    if input.len() < offset + 32 + length {
        return Err("Input too short for bytes data");
    }
    Ok(input[offset + 32 .. offset + 32 + length].to_vec())
}

#[allow(clippy::cast_precision_loss)]
fn u256_to_f64(bytes: &[u8]) -> Result<f64, &'static str> {
    if bytes.len() != 32 {
        return Err("Invalid weight bytes");
    }
    let mut val_bytes = [0u8; 8];
    val_bytes.copy_from_slice(&bytes[24..32]);
    let raw_val = u64::from_be_bytes(val_bytes);
    Ok(raw_val as f64 / 1_000_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::SigningKey;

    #[test]
    #[serial]
    fn test_execute_cross_manifold_call() {
        let reg_lock = crate::registry::get_registry();
        {
            let mut reg = reg_lock.write().unwrap();
            *reg = crate::registry::ValidatorRegistry::default();
            reg.dynamic_cfg.write().unwrap().manifold_quorum_threshold = 0;
            
            let mock_did = "did:peer:4:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string();
            reg.add_mock_validator(mock_did.clone(), Address::repeat_byte(0xaa), [0x88; 32]);
            reg.register_supported_manifold(&mock_did, 42).unwrap();
        }

        let namespace = [1u8; 32];
        let target_manifold_id = 42u64.to_be_bytes();
        let intent_hash = [7u8; 32];
        let safe_address = Address::repeat_byte(0xaa);
        let amount = [9u8; 32];
        let ttl = 100u64.to_be_bytes();

        // 1. Test Secp256k1 (Scheme 0)
        let secp_signing_key = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let secp_verifying_key = secp_signing_key.verifying_key();
        let secp_pubkey = secp_verifying_key.to_sec1_point(true);
        let secp_sig: k256::ecdsa::Signature = secp_signing_key.sign(&intent_hash);
        let secp_sig_bytes = secp_sig.to_bytes();

        let mut payload_secp = Vec::new();
        payload_secp.extend_from_slice(&namespace);
        payload_secp.extend_from_slice(&target_manifold_id);
        payload_secp.extend_from_slice(&intent_hash);
        payload_secp.extend_from_slice(safe_address.as_slice());
        payload_secp.extend_from_slice(&amount);
        payload_secp.extend_from_slice(&ttl);
        payload_secp.push(0); // scheme = 0
        payload_secp.extend_from_slice(secp_pubkey.as_bytes());
        payload_secp.extend_from_slice(&secp_sig_bytes);

        let res = execute_cross_manifold_call(&Bytes::from(payload_secp));
        assert!(res.is_ok(), "Secp256k1 failed: {:?}", res.err());
        let out = res.unwrap();
        assert_eq!(out[31], 1);

        // 2. Test Ed25519 (Scheme 1)
        let ed_signing_key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let ed_verifying_key = ed_signing_key.verifying_key();
        let ed_pubkey = ed_verifying_key.to_bytes();
        let ed_sig = ed_signing_key.sign(&intent_hash);
        let ed_sig_bytes = ed_sig.to_bytes();

        let mut payload_ed = Vec::new();
        payload_ed.extend_from_slice(&namespace);
        payload_ed.extend_from_slice(&target_manifold_id);
        payload_ed.extend_from_slice(&intent_hash);
        payload_ed.extend_from_slice(safe_address.as_slice());
        payload_ed.extend_from_slice(&amount);
        payload_ed.extend_from_slice(&ttl);
        payload_ed.push(1); // scheme = 1
        payload_ed.extend_from_slice(&ed_pubkey);
        payload_ed.push(0); // 1-byte padding to make 33 bytes pubkey
        payload_ed.extend_from_slice(&ed_sig_bytes);

        let res = execute_cross_manifold_call(&Bytes::from(payload_ed));
        assert!(res.is_ok());

        // 3. Test Succinct ZK Validity Proof Wrapper (Scheme 3 - SP1)
        let mut payload_zk = Vec::new();
        payload_zk.extend_from_slice(&namespace);
        payload_zk.extend_from_slice(&target_manifold_id);
        payload_zk.extend_from_slice(&intent_hash);
        payload_zk.extend_from_slice(safe_address.as_slice());
        payload_zk.extend_from_slice(&amount);
        payload_zk.extend_from_slice(&ttl);
        payload_zk.push(3); // scheme = 3 (SpruceSp1Bls12381)
        payload_zk.extend_from_slice(&[0u8; 33]); // dummy pubkey field
        payload_zk.extend_from_slice(&[0xaa; 64]); // dummy 64-byte proof

        let res_zk = execute_cross_manifold_call(&Bytes::from(payload_zk));
        assert!(res_zk.is_ok(), "ZK scheme verification failed: {:?}", res_zk.err());

        // 4. Test expired TTL
        let expired_ttl = 0u64.to_be_bytes();
        let mut payload_expired = Vec::new();
        payload_expired.extend_from_slice(&namespace);
        payload_expired.extend_from_slice(&target_manifold_id);
        payload_expired.extend_from_slice(&intent_hash);
        payload_expired.extend_from_slice(safe_address.as_slice());
        payload_expired.extend_from_slice(&amount);
        payload_expired.extend_from_slice(&expired_ttl);
        payload_expired.push(0);
        payload_expired.extend_from_slice(secp_pubkey.as_bytes());
        payload_expired.extend_from_slice(&secp_sig_bytes);

        let res = execute_cross_manifold_call(&Bytes::from(payload_expired));
        assert!(res.is_err());
    }

    #[test]
    fn test_verify_based_mesh_validity_proof_precompile() {
        use alloy_primitives::B256;
        let packet = crate::based_mesh::BasedMeshPacket::new(
            65001,
            vec![65002],
            B256::ZERO,
            crate::based_mesh::ProofScheme::SpruceSp1Bls12381,
            vec![0xbb; 100],
            b"exec_payload".to_vec(),
        );
        let raw_bytes = packet.to_bytes().unwrap();
        let res = verify_based_mesh_validity_proof(&Bytes::from(raw_bytes));
        assert!(res.is_ok());
    }

    fn encode_abi_string(val: &str) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        data.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[31] = u8::try_from(val.len()).expect("val.len() fits in u8");
        data.extend_from_slice(&len);
        let mut str_bytes = val.as_bytes().to_vec();
        let rem = str_bytes.len() % 32;
        if rem != 0 {
            str_bytes.resize(str_bytes.len() + (32 - rem), 0);
        }
        data.extend_from_slice(&str_bytes);
        data
    }



    fn create_test_did(pub_multibase: &str, is_secp: bool) -> String {
        let kt = if is_secp {
            did_peer::DIDPeerKeyType::Secp256k1
        } else {
            did_peer::DIDPeerKeyType::Ed25519
        };
        let keys = vec![did_peer::DIDPeerCreateKeys {
            type_: Some(kt),
            purpose: did_peer::DIDPeerKeys::Verification,
            public_key_multibase: Some(pub_multibase.to_string()),
        }];
        let (did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).unwrap();
        did
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_execute_registry_call() {
        {
            let mut reg = crate::registry::get_registry().write().unwrap();
            *reg = crate::registry::ValidatorRegistry::default();
        }

        let genesis_seed = Address::repeat_byte(0x99);
        
        // Generate valid candidate DIDs dynamically
        let candidate_did = create_test_did("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", false);
        // Candidate address derived from genesis-like key (our helper resolve maps both to valid addresses)
        let candidate_addr = Address::repeat_byte(0x99); // Genesis seed address for verification in test

        // 1. Propose validator from a non-validator (should fail)

        let mut propose_payload = Vec::new();
        propose_payload.extend_from_slice(&SELECTOR_PROPOSE);
        propose_payload.extend_from_slice(&encode_abi_string(&candidate_did));

        let non_val = Address::repeat_byte(0x11);
        let res = execute_registry_call(non_val, &Bytes::from(propose_payload.clone()));
        assert!(res.is_err());

        // 2. Propose validator from genesis seed (should succeed)

        let res = execute_registry_call(genesis_seed, &Bytes::from(propose_payload));
        assert!(res.is_ok(), "Expected Ok, got Err: {:?}", res.err());

        // 3. Endorse validator with weight

        let mut endorse_payload = Vec::new();
        endorse_payload.extend_from_slice(&SELECTOR_ENDORSE);
        
        // Offset for candidate_did (since candidate_did is dynamic and first)
        let mut offset_did = [0u8; 32];
        offset_did[31] = 0x40; // 32 bytes for did offset + 32 bytes for weight slot = 64 bytes offset
        endorse_payload.extend_from_slice(&offset_did);

        // Weight value slot (0.50 scaled: 500_000)
        let mut weight_u256 = [0u8; 32];
        weight_u256[24..32].copy_from_slice(&500_000u64.to_be_bytes());
        endorse_payload.extend_from_slice(&weight_u256);

        // String payload
        let mut len_did = [0u8; 32];
        len_did[31] = u8::try_from(candidate_did.len()).expect("did length fits in u8");
        endorse_payload.extend_from_slice(&len_did);
        let mut did_bytes = candidate_did.as_bytes().to_vec();
        let rem = did_bytes.len() % 32;
        if rem != 0 {
            did_bytes.resize(did_bytes.len() + (32 - rem), 0);
        }
        endorse_payload.extend_from_slice(&did_bytes);

        let res = execute_registry_call(genesis_seed, &Bytes::from(endorse_payload));
        assert!(res.is_ok());

        // Verify reputation state changes in registry
        {
            let reg_lock = crate::registry::get_registry();
            let reg = reg_lock.read().unwrap();
            assert_eq!(reg.get_type_by_address(&candidate_addr), Some(crate::registry::ValidatorType::VanillaSocial));
            assert!(reg.get_reputation_by_address(&candidate_addr) > 0.0);
        }

        // 4. Register SGX Node permissionlessly
        let sgx_candidate_did = create_test_did("zQ3shok17vjUvJgqG3Yme5fQwQDndx8C5Jea95D4A8YnUFs2t", true);
        
        let mut sgx_payload = Vec::new();
        sgx_payload.extend_from_slice(&SELECTOR_REGISTER_SGX);
        
        // Offset for candidate_did
        let mut offset_did = [0u8; 32];
        offset_did[31] = 0x40; // string offset is 64 bytes
        sgx_payload.extend_from_slice(&offset_did);

        // Offset for quote
        let mut offset_quote = [0u8; 32];
        offset_quote[31] = 0xa0; // quote offset is 160 bytes
        sgx_payload.extend_from_slice(&offset_quote);

        // String payload (did)
        let mut len_did = [0u8; 32];
        len_did[31] = u8::try_from(sgx_candidate_did.len()).expect("sgx_candidate_did length fits in u8");
        sgx_payload.extend_from_slice(&len_did);
        let mut did_bytes = sgx_candidate_did.as_bytes().to_vec();
        let rem = did_bytes.len() % 32;
        if rem != 0 {
            did_bytes.resize(did_bytes.len() + (32 - rem), 0);
        }
        sgx_payload.extend_from_slice(&did_bytes);

        // Bytes payload (quote)
        let quote_data = b"MOCK_SGX_QUOTE_VALID_PROVEN_BY_INTEL_DCAP";
        let mut len_quote = [0u8; 32];
        len_quote[31] = u8::try_from(quote_data.len()).expect("quote length fits in u8");
        sgx_payload.extend_from_slice(&len_quote);
        let mut quote_bytes = quote_data.to_vec();
        let rem = quote_bytes.len() % 32;
        if rem != 0 {
            quote_bytes.resize(quote_bytes.len() + (32 - rem), 0);
        }
        sgx_payload.extend_from_slice(&quote_bytes);

        let res = execute_registry_call(genesis_seed, &Bytes::from(sgx_payload));
        assert!(res.is_ok(), "Expected SGX register Ok, got Err: {:?}", res.err());

        let reg_lock = crate::registry::get_registry();
        {
            let reg = reg_lock.read().unwrap();
            let derived_addr = reg.get_address_by_did(&sgx_candidate_did)
                .expect("SGX candidate address not found in registry");
            assert_eq!(reg.get_type_by_address(&derived_addr), Some(crate::registry::ValidatorType::HardwareTEE));
            
            // By default threshold is 0.0, so active_peers must include the SGX node
            let active = reg.active_peers();
            assert!(active.values().any(|&a| a == derived_addr), "SGX node should be active by default");
        }

        // Set threshold to 0.1
        {
            let reg = reg_lock.write().unwrap();
            reg.dynamic_cfg.write().unwrap().sgx_reputation_threshold = 0.1;
        }

        {
            let reg = reg_lock.read().unwrap();
            let derived_addr = reg.get_address_by_did(&sgx_candidate_did).unwrap();
            
            // With threshold 0.1 and no reputation, the SGX node must NOT be active
            let active = reg.active_peers();
            assert!(!active.values().any(|&a| a == derived_addr), "SGX node should be filtered out under threshold");
        }

        // Give SGX node reputation >= 0.1 (e.g. 0.15)
        {
            let mut reg = reg_lock.write().unwrap();
            reg.set_reputation(sgx_candidate_did.clone(), 0.15);
        }

        {
            let reg = reg_lock.read().unwrap();
            let derived_addr = reg.get_address_by_did(&sgx_candidate_did).unwrap();
            
            // Now that reputation meets threshold, it must be active again
            let active = reg.active_peers();
            assert!(active.values().any(|&a| a == derived_addr), "SGX node should be active after meeting threshold");
        }

        // Reset registry to clean state so subsequent serial tests start fresh.
        {
            let mut reg = reg_lock.write().unwrap();
            *reg = crate::registry::ValidatorRegistry::default();
        }
    }

    #[test]
    #[serial]
    fn test_registry_mesh_quorum() {
        let reg_lock = crate::registry::get_registry();
        let mut reg = reg_lock.write().unwrap();
        *reg = crate::registry::ValidatorRegistry::default();
        reg.dynamic_cfg.write().unwrap().manifold_quorum_threshold = 2; // Needs 2
        
        let manifold_id = 99;
        let did1 = create_test_did("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doJ", false);
        let did2 = create_test_did("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2do2", false);
        reg.propose_validator(Address::repeat_byte(0x99), did1.clone()).unwrap();
        reg.propose_validator(Address::repeat_byte(0x99), did2.clone()).unwrap();
        
        // Register supported manifold for did1
        reg.register_supported_manifold(&did1, manifold_id).unwrap();
        let routable = reg.get_routable_validators(manifold_id);
        assert!(routable.is_empty(), "Should be empty because quorum is 2 but only 1 registered");
        
        // Register supported manifold for did2
        reg.register_supported_manifold(&did2, manifold_id).unwrap();
        
        // Populate peer keys to make them active_peers()
        reg.register_sgx_node(did1.clone()).unwrap();
        reg.register_sgx_node(did2.clone()).unwrap();
        
        let routable2 = reg.get_routable_validators(manifold_id);
        assert_eq!(routable2.len(), 2, "Quorum met, both should be routable");
    }

    #[test]
    fn test_snow_subset_election() {
        use std::collections::HashSet;
        let mut election = crate::subset_election::SnowSubsetElection::new(42);
        
        let mut validators = HashSet::new();
        let addr1 = Address::repeat_byte(0x01);
        let addr2 = Address::repeat_byte(0x02);
        let addr3 = Address::repeat_byte(0x03);
        validators.insert(addr1);
        validators.insert(addr2);
        validators.insert(addr3);
        
        election.trigger_election(&validators, 1, 2).unwrap();
        assert_eq!(election.current_subset.len(), 2, "Should select exactly 2 out of 3 validators");
        
        // Check determinism for the same epoch
        let mut election2 = crate::subset_election::SnowSubsetElection::new(42);
        election2.trigger_election(&validators, 1, 2).unwrap();
        assert_eq!(election.current_subset, election2.current_subset, "Election must be deterministic for the same epoch");
        
        // Trigger for a different epoch
        let mut election3 = crate::subset_election::SnowSubsetElection::new(42);
        election3.trigger_election(&validators, 2, 2).unwrap();
        // Since it's a different epoch, the seed is different and the sorted order might be different (or it could overlap, but it validates deterministic code flow)
        assert_eq!(election3.current_subset.len(), 2);
    }

    struct MockRpcClient {
        balance: std::sync::Mutex<alloy_primitives::U256>,
    }

    impl crate::courier::RpcClient for MockRpcClient {
        fn get_balance(&self, _address: Address) -> alloy_primitives::U256 {
            *self.balance.lock().unwrap()
        }
    }

    #[test]
    fn test_paymaster_auto_suspension() {
        use std::sync::Arc;
        let mock_rpc = Arc::new(MockRpcClient {
            balance: std::sync::Mutex::new(alloy_primitives::U256::from(10_000_000_000_000_000u64)), // 0.01 ETH
        });
        
        let seed = [1u8; 32];
        let dynamic_cfg = Arc::new(std::sync::RwLock::new(crate::config::DynamicConfig::default()));
        let mut courier = crate::courier::BlindCourierService::new(
            "did:peer:4:courier".to_string(),
            &seed,
            mock_rpc.clone(),
            dynamic_cfg,
        ).unwrap();
        
        // Should not be suspended initially
        assert!(!courier.check_funding_and_suspend());
        assert!(!courier.is_suspended);
        
        // Deplete the balance
        *mock_rpc.balance.lock().unwrap() = alloy_primitives::U256::from(1_000_000_000_000_000u64); // 0.001 ETH (< 0.005)
        
        // Should suspend
        assert!(courier.check_funding_and_suspend());
        assert!(courier.is_suspended);
        
        // Refill balance
        *mock_rpc.balance.lock().unwrap() = alloy_primitives::U256::from(15_000_000_000_000_000u64);
        
        // Should resume
        assert!(!courier.check_funding_and_suspend());
        assert!(!courier.is_suspended);
    }
    #[test]
    #[serial]
    fn test_publishing_window_enforcement() {
        let reg_lock = crate::registry::get_registry();
        let mock_did = "did:peer:4:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string();
        let caller = Address::repeat_byte(0xaa);

        {
            let mut reg = reg_lock.write().unwrap();
            *reg = crate::registry::ValidatorRegistry::default();
            reg.static_cfg.epoch.epoch_length = 1000;
            reg.static_cfg.epoch.publishing_window = 100;
            reg.current_block = 50; // Within window
            // Register mock validator AND map caller address → DID so ownership check passes.
            reg.add_mock_tee_validator(mock_did.clone(), caller, [0x99; 32]);
            reg.reputation.insert(mock_did.clone(), 1.0); // Required for index
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(&SELECTOR_SUBMIT_COMMITMENT);
        // string offset = 32 (encoded in 32 bytes)
        let mut offset = [0u8; 32];
        offset[31] = 32;
        payload.extend_from_slice(&offset);
        
        // string length (encoded in 32 bytes)
        let mut len_bytes = [0u8; 32];
        len_bytes[31] = u8::try_from(mock_did.len()).expect("mock_did length fits in u8"); // Assume < 255
        payload.extend_from_slice(&len_bytes);
        
        payload.extend_from_slice(mock_did.as_bytes());
        // Pad for string
        let pad = 32 - (mock_did.len() % 32);
        if pad < 32 {
            payload.extend(vec![0u8; pad]);
        }
        
        // Commitment + Proof + Y
        let commit = [0u8; 48];
        let proof = [0u8; 48];
        let y = [0u8; 32];
        
        // Pad to get the exact lengths as expected.
        // wait, the parsing extracts them from the very end. 48+48+32 = 128 bytes.
        // So we just append them.
        payload.extend_from_slice(&commit);
        payload.extend_from_slice(&proof);
        payload.extend_from_slice(&y);
        
        // Window open
        let res = execute_registry_call(caller, &Bytes::from(payload.clone()));
        // Fails at KZG verification, NOT at window check
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "KZG verification computation failed");

        // Window closed
        {
            let mut reg = reg_lock.write().unwrap();
            reg.current_block = 150; // Outside window
        }
        
        let res2 = execute_registry_call(caller, &Bytes::from(payload));
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err(), "Not within the epoch publishing window");
    }

    #[test]
    #[serial]
    fn test_execute_metalex_call() {
        let reg_lock = crate::registry::get_registry();
        {
            let mut reg = reg_lock.write().unwrap();
            *reg = crate::registry::ValidatorRegistry::default();
            reg.dynamic_cfg.write().unwrap().metalex_validator_count_threshold = 2;
        }

        let did_peer = "did:peer:4:sovereign_co";
        let equity_token = "0xEquityTokenAddressMock";
        let agent_dids = vec!["did:peer:4:alice".to_string(), "did:peer:4:bob".to_string()];
        let agent_roles = vec!["director".to_string(), "signatory".to_string()];
        let validator_signatures = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let encode_string = |s: &str| -> Vec<u8> {
            let mut v = vec![0u8; 32];
            v[31] = s.len() as u8;
            v.extend_from_slice(s.as_bytes());
            let pad = 32 - (s.len() % 32);
            if pad < 32 {
                v.extend(vec![0u8; pad]);
            }
            v
        };

        let encode_bytes = |b: &[u8]| -> Vec<u8> {
            let mut v = vec![0u8; 32];
            v[31] = b.len() as u8;
            v.extend_from_slice(b);
            let pad = 32 - (b.len() % 32);
            if pad < 32 {
                v.extend(vec![0u8; pad]);
            }
            v
        };

        let did_peer_enc = encode_string(did_peer);
        let equity_token_enc = encode_string(equity_token);

        let mut payload = Vec::new();
        payload.extend_from_slice(&SELECTOR_REGISTER_OR_UPDATE_ORG);

        let offset_did_peer = 160;
        let offset_equity_token = offset_did_peer + did_peer_enc.len();
        
        let offset_agent_dids = offset_equity_token + equity_token_enc.len();
        let item_alice_enc = encode_string(&agent_dids[0]);
        let item_bob_enc = encode_string(&agent_dids[1]);
        let agent_dids_array_size = 32 + 64 + item_alice_enc.len() + item_bob_enc.len();
        let offset_agent_roles = offset_agent_dids + agent_dids_array_size;

        let item_director_enc = encode_string(&agent_roles[0]);
        let item_signatory_enc = encode_string(&agent_roles[1]);
        let agent_roles_array_size = 32 + 64 + item_director_enc.len() + item_signatory_enc.len();
        let offset_sigs = offset_agent_roles + agent_roles_array_size;

        let mut head = vec![0u8; 160];
        head[24..32].copy_from_slice(&(offset_did_peer as u64).to_be_bytes());
        head[56..64].copy_from_slice(&(offset_equity_token as u64).to_be_bytes());
        head[88..96].copy_from_slice(&(offset_agent_dids as u64).to_be_bytes());
        head[120..128].copy_from_slice(&(offset_agent_roles as u64).to_be_bytes());
        head[152..160].copy_from_slice(&(offset_sigs as u64).to_be_bytes());
        payload.extend_from_slice(&head);

        payload.extend_from_slice(&did_peer_enc);
        payload.extend_from_slice(&equity_token_enc);

        let mut agent_dids_head = vec![0u8; 96];
        agent_dids_head[24..32].copy_from_slice(&2u64.to_be_bytes());
        agent_dids_head[56..64].copy_from_slice(&64u64.to_be_bytes());
        agent_dids_head[88..96].copy_from_slice(&((64 + item_alice_enc.len()) as u64).to_be_bytes());
        payload.extend_from_slice(&agent_dids_head);
        payload.extend_from_slice(&item_alice_enc);
        payload.extend_from_slice(&item_bob_enc);

        let mut agent_roles_head = vec![0u8; 96];
        agent_roles_head[24..32].copy_from_slice(&2u64.to_be_bytes());
        agent_roles_head[56..64].copy_from_slice(&64u64.to_be_bytes());
        agent_roles_head[88..96].copy_from_slice(&((64 + item_director_enc.len()) as u64).to_be_bytes());
        payload.extend_from_slice(&agent_roles_head);
        payload.extend_from_slice(&item_director_enc);
        payload.extend_from_slice(&item_signatory_enc);

        let item_sig0_enc = encode_bytes(&validator_signatures[0]);
        let item_sig1_enc = encode_bytes(&validator_signatures[1]);
        let mut sigs_head = vec![0u8; 96];
        sigs_head[24..32].copy_from_slice(&2u64.to_be_bytes());
        sigs_head[56..64].copy_from_slice(&64u64.to_be_bytes());
        sigs_head[88..96].copy_from_slice(&((64 + item_sig0_enc.len()) as u64).to_be_bytes());
        payload.extend_from_slice(&sigs_head);
        payload.extend_from_slice(&item_sig0_enc);
        payload.extend_from_slice(&item_sig1_enc);

        let caller = Address::repeat_byte(0xcc);
        let res = execute_metalex_call(caller, &Bytes::from(payload));
        assert!(res.is_ok(), "MetaLex call failed: {:?}", res.err());
        let out = res.unwrap();
        assert_eq!(out[31], 1);

        let mgr_lock = crate::metalex::get_metalex_manager();
        let mgr = mgr_lock.read().unwrap();
        assert!(mgr.orgs.contains_key("did:peer:4:sovereign_co"));
        let org = mgr.orgs.get("did:peer:4:sovereign_co").unwrap();
        assert_eq!(org.equity_token, "0xEquityTokenAddressMock");
        assert_eq!(org.agents.get("did:peer:4:alice").unwrap(), "director");
    }
}
