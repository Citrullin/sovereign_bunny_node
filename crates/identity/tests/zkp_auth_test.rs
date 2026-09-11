use sovereign_identity::zkp_auth::{
    IdentityProvider, NextCloudAuth, NextCloudCredentials, NextErpAuth, NextErpCredentials,
    NfcCredentials, NfcTokenAuth, ZeroKnowledgeProof,
};

#[test]
fn test_next_erp_auth_success() {
    let auth = NextErpAuth {
        tenant_id: "tenant_1".to_string(),
        relay_server: "https://auth.relay.local".to_string(),
    };

    let creds = NextErpCredentials {
        user_did: "did:sovereign:1:0x123".to_string(),
        authentik_relay_signature: vec![0x11; 64],
        internal_user_email: "alice@company.com".to_string(),
        group_proof: Some(ZeroKnowledgeProof {
            proof: vec![0xaa; 32],
            public_inputs: vec![0xbb; 32],
        }),
    };

    let res = auth.verify_identity(&creds).unwrap();
    assert_eq!(res.internal_user_id, "alice@company.com");
    assert_eq!(res.identity_server, "https://auth.relay.local");
}

#[test]
fn test_next_erp_auth_invalid_proof() {
    let auth = NextErpAuth {
        tenant_id: "tenant_1".to_string(),
        relay_server: "https://auth.relay.local".to_string(),
    };

    let creds = NextErpCredentials {
        user_did: "did:sovereign:1:0x123".to_string(),
        authentik_relay_signature: vec![0x11; 64],
        internal_user_email: "alice@company.com".to_string(),
        group_proof: Some(ZeroKnowledgeProof {
            proof: b"INVALID_GROUP_PROOF".to_vec(),
            public_inputs: vec![],
        }),
    };

    let res = auth.verify_identity(&creds);
    assert!(res.is_err());
}

#[test]
fn test_next_cloud_auth() {
    let auth = NextCloudAuth {
        instance_url: "https://cloud.local".to_string(),
        relay_server: "https://auth.local".to_string(),
    };

    let creds = NextCloudCredentials {
        user_did: "did:sovereign:1:0x456".to_string(),
        relay_token: "token_123".to_string(),
        internal_username: "bob_cloud".to_string(),
        session_proof: ZeroKnowledgeProof {
            proof: vec![0x12; 32],
            public_inputs: vec![],
        },
    };

    let res = auth.verify_identity(&creds).unwrap();
    assert_eq!(res.internal_user_id, "bob_cloud");
}

#[test]
fn test_nfc_token_auth() {
    let auth = NfcTokenAuth {
        chip_type: "NTAG424".to_string(),
    };

    let creds = NfcCredentials {
        card_uid: vec![0x04, 0xa1, 0xb2, 0xc3],
        dynamic_signature: vec![0x99; 64],
        challenge: vec![0x01; 32],
    };

    let res = auth.verify_identity(&creds).unwrap();
    assert_eq!(res.internal_user_id, "nfc_card_04a1b2c3");
    assert_eq!(res.identity_server, "NFC_Reader");
}
