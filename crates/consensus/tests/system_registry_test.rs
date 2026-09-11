use alloy_primitives::{Address, B256, U256};
use sovereign_consensus::system_registry::{
    is_system_address, SystemAction, SYSTEM_ACCOUNT_HEIGHT, SYSTEM_AI_ORACLE, SYSTEM_ASYNC_INBOX,
    SYSTEM_BRIDGE, SYSTEM_CMS, SYSTEM_DID_REGISTRY, SYSTEM_JURISDICTION, SYSTEM_RECEIVE_HOOK,
    SYSTEM_SAGA_ESCROW, SYSTEM_SIGNAL_REGISTRY, SYSTEM_STORAGE_DA,
};

#[test]
fn test_is_system_address() {
    // GIVEN: System precompile addresses in the EIP-1352 namespace
    // WHEN: Checking system address membership
    // THEN: System addresses return true, standard user addresses return false
    assert!(is_system_address(&SYSTEM_RECEIVE_HOOK));
    assert!(is_system_address(&SYSTEM_DID_REGISTRY));
    assert!(is_system_address(&SYSTEM_SAGA_ESCROW));
    assert!(is_system_address(&SYSTEM_JURISDICTION));
    assert!(is_system_address(&SYSTEM_BRIDGE));
    assert!(is_system_address(&SYSTEM_ASYNC_INBOX));
    assert!(is_system_address(&SYSTEM_AI_ORACLE));
    assert!(is_system_address(&SYSTEM_ACCOUNT_HEIGHT));
    assert!(is_system_address(&SYSTEM_STORAGE_DA));
    assert!(is_system_address(&SYSTEM_SIGNAL_REGISTRY));
    assert!(is_system_address(&SYSTEM_CMS));

    let user_addr = Address::repeat_byte(0x77);
    assert!(!is_system_address(&user_addr));
}

#[test]
fn test_system_action_receive_roundtrip() {
    // GIVEN: A Receive system action targeting SYSTEM_RECEIVE_HOOK
    let action = SystemAction::Receive {
        send_block_hash: B256::repeat_byte(0x12),
        amount: U256::from(100_000),
    };

    // WHEN: Calldata is encoded and decoded
    let calldata = action.encode();
    let decoded = SystemAction::decode(&SYSTEM_RECEIVE_HOOK, &calldata).unwrap();

    // THEN: Decoded action matches all fields exactly
    match decoded {
        SystemAction::Receive { send_block_hash, amount } => {
            assert_eq!(send_block_hash, B256::repeat_byte(0x12));
            assert_eq!(amount, U256::from(100_000));
        }
        _ => panic!("Expected SystemAction::Receive"),
    }
}

#[test]
fn test_system_action_register_did_roundtrip() {
    // GIVEN: A RegisterDid action with DID document, PQ public key, and key tier
    let action = SystemAction::RegisterDid {
        did_document: r#"{"id":"did:sovereign:1:0x11"}"#.to_string(),
        pq_pub_key: vec![0xaa, 0xbb, 0xcc],
        key_tier: "QuantumReady".to_string(),
    };

    // WHEN: Calldata is encoded and decoded against SYSTEM_DID_REGISTRY
    let calldata = action.encode();
    let decoded = SystemAction::decode(&SYSTEM_DID_REGISTRY, &calldata).unwrap();

    // THEN: Decoded fields match the original specification
    match decoded {
        SystemAction::RegisterDid { did_document, pq_pub_key, key_tier } => {
            assert_eq!(did_document, r#"{"id":"did:sovereign:1:0x11"}"#);
            assert_eq!(pq_pub_key, vec![0xaa, 0xbb, 0xcc]);
            assert_eq!(key_tier, "QuantumReady");
        }
        _ => panic!("Expected SystemAction::RegisterDid"),
    }
}

#[test]
fn test_system_action_saga_escrow_roundtrip() {
    // GIVEN: A SagaEscrow action with intent ID, target account, amount, and expiry
    let action = SystemAction::SagaEscrow {
        intent_id: B256::repeat_byte(0x55),
        target_account: Address::repeat_byte(0x33),
        amount: U256::from(999),
        expire_epoch: 42,
    };

    // WHEN: Calldata is encoded and decoded against SYSTEM_SAGA_ESCROW
    let calldata = action.encode();
    let decoded = SystemAction::decode(&SYSTEM_SAGA_ESCROW, &calldata).unwrap();

    // THEN: Decoded struct matches the original values
    match decoded {
        SystemAction::SagaEscrow { intent_id, target_account, amount, expire_epoch } => {
            assert_eq!(intent_id, B256::repeat_byte(0x55));
            assert_eq!(target_account, Address::repeat_byte(0x33));
            assert_eq!(amount, U256::from(999));
            assert_eq!(expire_epoch, 42);
        }
        _ => panic!("Expected SystemAction::SagaEscrow"),
    }
}

#[test]
fn test_system_action_actor_message_roundtrip() {
    // GIVEN: An ActorMessage action with actor ID and byte payload
    let action = SystemAction::ActorMessage {
        actor_id: B256::repeat_byte(0x88),
        payload: vec![1, 2, 3, 4, 5],
    };

    // WHEN: Calldata is encoded and decoded against SYSTEM_ASYNC_INBOX
    let calldata = action.encode();
    let decoded = SystemAction::decode(&SYSTEM_ASYNC_INBOX, &calldata).unwrap();

    // THEN: Decoded payload matches the original
    match decoded {
        SystemAction::ActorMessage { actor_id, payload } => {
            assert_eq!(actor_id, B256::repeat_byte(0x88));
            assert_eq!(payload, vec![1, 2, 3, 4, 5]);
        }
        _ => panic!("Expected SystemAction::ActorMessage"),
    }
}

#[test]
fn test_system_action_ai_oracle_roundtrip() {
    // GIVEN: A SubmitContributionEvaluation action with serialized JSON
    let sample_json = r#"{"contributor":"0x1111111111111111111111111111111111111111","raw_units":100}"#;
    let action = SystemAction::SubmitContributionEvaluation {
        evaluation_json: sample_json.to_string(),
    };

    // WHEN: Calldata is encoded and decoded against SYSTEM_AI_ORACLE
    let calldata = action.encode();
    let decoded = SystemAction::decode(&SYSTEM_AI_ORACLE, &calldata).unwrap();

    // THEN: Decoded JSON matches the original payload
    match decoded {
        SystemAction::SubmitContributionEvaluation { evaluation_json } => {
            assert_eq!(evaluation_json, sample_json);
        }
        _ => panic!("Expected SystemAction::SubmitContributionEvaluation"),
    }
}

#[test]
fn test_system_action_signal_interest_roundtrip() {
    let action = SystemAction::SignalInterest {
        topic_id: B256::repeat_byte(0x42),
        target_address: Address::repeat_byte(0x55),
        cuckoo_digest: B256::repeat_byte(0x66),
        expiry_epoch: 12345,
    };

    let calldata = action.encode();
    let decoded = SystemAction::decode(&SYSTEM_SIGNAL_REGISTRY, &calldata).unwrap();

    match decoded {
        SystemAction::SignalInterest { topic_id, target_address, cuckoo_digest, expiry_epoch } => {
            assert_eq!(topic_id, B256::repeat_byte(0x42));
            assert_eq!(target_address, Address::repeat_byte(0x55));
            assert_eq!(cuckoo_digest, B256::repeat_byte(0x66));
            assert_eq!(expiry_epoch, 12345);
        }
        _ => panic!("Expected SystemAction::SignalInterest"),
    }
}

#[test]
fn test_system_action_publish_activitypub_roundtrip() {
    let action = SystemAction::PublishActivityPub {
        actor: Address::repeat_byte(0x11),
        activity_type: 1, // Create
        object_cid: B256::repeat_byte(0x22),
        recipient: Address::repeat_byte(0x33),
        micro_payment: 50_000,
        merit_proof_root: B256::repeat_byte(0x44),
    };

    let calldata = action.encode();
    let decoded = SystemAction::decode(&SYSTEM_CMS, &calldata).unwrap();

    match decoded {
        SystemAction::PublishActivityPub { actor, activity_type, object_cid, recipient, micro_payment, merit_proof_root } => {
            assert_eq!(actor, Address::repeat_byte(0x11));
            assert_eq!(activity_type, 1);
            assert_eq!(object_cid, B256::repeat_byte(0x22));
            assert_eq!(recipient, Address::repeat_byte(0x33));
            assert_eq!(micro_payment, 50_000);
            assert_eq!(merit_proof_root, B256::repeat_byte(0x44));
        }
        _ => panic!("Expected SystemAction::PublishActivityPub"),
    }
}

#[test]
fn test_system_action_claim_storage_merit_roundtrip() {
    let action = SystemAction::ClaimStorageMerit {
        provider_did: "did:sovereign:1337:0xprovider".to_string(),
        bao_slice_proof: vec![0xde, 0xad, 0xbe, 0xef],
        epoch_id: 420,
    };

    let calldata = action.encode();
    let decoded = SystemAction::decode(&SYSTEM_STORAGE_DA, &calldata).unwrap();

    match decoded {
        SystemAction::ClaimStorageMerit { provider_did, bao_slice_proof, epoch_id } => {
            assert_eq!(provider_did, "did:sovereign:1337:0xprovider");
            assert_eq!(bao_slice_proof, vec![0xde, 0xad, 0xbe, 0xef]);
            assert_eq!(epoch_id, 420);
        }
        _ => panic!("Expected SystemAction::ClaimStorageMerit"),
    }
}

