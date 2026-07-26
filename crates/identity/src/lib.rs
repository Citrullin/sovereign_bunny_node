//! Identity & Reputation Module
//! Handles DID Peer 4 resolution and identity management.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

pub mod delegation;
pub mod merit;
pub mod zkp_auth;
pub mod namespace;
pub mod did;

/// The supported key types in DID Peer 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 signature key type
    Ed25519,
    /// Secp256k1 signature key type
    Secp256k1,
}

/// A struct representing a resolved DID Peer 4 identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidPeer4 {
    /// The original DID string.
    pub did: String,
    /// The decoded public key type.
    pub key_type: KeyType,
    /// The raw public key bytes.
    pub public_key: Vec<u8>,
}

impl DidPeer4 {
    /// Resolves a DID Peer 4 string statically and decodes the multibase public key.
    ///
    /// # Errors
    /// Returns an error if the DID format is invalid or key decoding fails.
    pub async fn resolve(did: &str) -> Result<Self, &'static str> {
        if !did.starts_with("did:peer:") {
            return Err("Invalid DID format. Must start with 'did:peer:'");
        }


        let resolver = did_peer::DIDPeer;
        let doc = resolver.resolve(did).await.map_err(|_| "Failed to resolve did:peer")?;

        if doc.verification_method.is_empty() {
            return Err("Resolved DID document has no verification methods");
        }

        let vm = &doc.verification_method[0];
        let public_key = vm.get_public_key_bytes().map_err(|_| "Failed to extract public key bytes")?;

        // Detect key type based on VM type or key length
        let key_type = match vm.type_.as_str() {
            "JsonWebKey2020" => KeyType::Secp256k1, // typically used for secp256k1/EcdsaSecp256k1VerificationKey2019
            _ => {
                if public_key.len() == 32 {
                    KeyType::Ed25519
                } else {
                    KeyType::Secp256k1
                }
            }
        };

        Ok(Self {
            did: did.to_string(),
            key_type,
            public_key,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp_auth::{
        IdentityProvider, AuthentikZkpAuth, ZeroKnowledgeProof,
        NextErpAuth, NextErpCredentials, NextCloudAuth, NextCloudCredentials,
        NfcTokenAuth, NfcCredentials,
    };

    #[tokio::test]
    async fn test_did_peer4_resolve_ed25519() {
        let keys = vec![did_peer::DIDPeerCreateKeys {
            type_: Some(did_peer::DIDPeerKeyType::Ed25519),
            purpose: did_peer::DIDPeerKeys::Verification,
            public_key_multibase: Some("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into()),
        }];
        let (did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).unwrap();
        // The created DID starts with did:peer:4:
        let resolved = DidPeer4::resolve(&did).await.unwrap();
        assert_eq!(resolved.key_type, KeyType::Ed25519);
        assert!(!resolved.public_key.is_empty());
    }

    #[tokio::test]
    async fn test_did_peer4_resolve_secp256k1() {
        let keys = vec![did_peer::DIDPeerCreateKeys {
            type_: Some(did_peer::DIDPeerKeyType::Secp256k1),
            purpose: did_peer::DIDPeerKeys::Verification,
            public_key_multibase: Some("zQ3shok17vjUvJgqG3Yme5fQwQDndx8C5Jea95D4A8YnUFs2t".into()),
        }];
        let (did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).unwrap();
        let resolved = DidPeer4::resolve(&did).await.unwrap();
        assert_eq!(resolved.key_type, KeyType::Secp256k1);
        assert!(!resolved.public_key.is_empty());
    }

    #[tokio::test]
    async fn test_did_peer4_invalid_format() {
        assert!(DidPeer4::resolve("did:peer:3:z6M").await.is_err());
        assert!(DidPeer4::resolve("did:peer:4:").await.is_err());
    }


    #[test]
    fn test_authentik_zkp_auth_flow() {
        use std::str::FromStr;
        let auth = AuthentikZkpAuth {
            identity_server: "https://authentik.local".to_string(),
        };
        let address = [0u8; 20];
        let domain = "authentik.local".parse().unwrap();
        let uri = "https://authentik.local/login".parse().unwrap();
        let msg = siwe::Message {
            domain,
            address,
            statement: Some("Accept the Terms of Service.".to_string()),
            uri,
            version: siwe::Version::V1,
            chain_id: 1,
            nonce: "32891752".to_string(),
            issued_at: siwe::TimeStamp::from_str("2021-09-30T16:25:24Z").unwrap(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: vec![],
        };
        let siwe_msg = msg.to_string();

        let mapping = auth.verify_identity(&siwe_msg).unwrap();
        assert_eq!(mapping.internal_user_id, format!("{:?}", alloy_primitives::Address::from(address)));
        assert_eq!(mapping.identity_server, "https://authentik.local");

        let invalid_siwe = "invalid message";
        assert!(auth.verify_identity(&invalid_siwe.to_string()).is_err());
    }



    #[test]
    fn test_nexterp_zkp_auth_flow() {
        let auth = NextErpAuth {
            tenant_id: "erp_tenant_1".to_string(),
            relay_server: "https://authentik.relay".to_string(),
        };
        let creds = NextErpCredentials {
            user_did: "did:peer:4:z6M".to_string(),
            authentik_relay_signature: b"valid_sig".to_vec(),
            internal_user_email: "employee@company.com".to_string(),
            group_proof: Some(ZeroKnowledgeProof {
                proof: b"valid_group_proof".to_vec(),
                public_inputs: b"group_id_1".to_vec(),
            }),
        };
        let mapping = auth.verify_identity(&creds).unwrap();
        assert_eq!(mapping.internal_user_id, "employee@company.com");
        assert_eq!(mapping.identity_server, "https://authentik.relay");

        let invalid_creds = NextErpCredentials {
            user_did: "did:peer:4:z6M".to_string(),
            authentik_relay_signature: b"INVALID".to_vec(),
            internal_user_email: "employee@company.com".to_string(),
            group_proof: None,
        };
        assert!(auth.verify_identity(&invalid_creds).is_err());
    }

    #[test]
    fn test_nextcloud_zkp_auth_flow() {
        let auth = NextCloudAuth {
            instance_url: "https://nextcloud.local".to_string(),
            relay_server: "https://authentik.relay".to_string(),
        };
        let creds = NextCloudCredentials {
            user_did: "did:peer:4:z6M".to_string(),
            relay_token: "nc_session_token_xyz".to_string(),
            internal_username: "nextcloud_user_99".to_string(),
            session_proof: ZeroKnowledgeProof {
                proof: b"valid_session_proof".to_vec(),
                public_inputs: b"session_id_456".to_vec(),
            },
        };
        let mapping = auth.verify_identity(&creds).unwrap();
        assert_eq!(mapping.internal_user_id, "nextcloud_user_99");
        assert_eq!(mapping.identity_server, "https://authentik.relay");

        let bad_session_creds = NextCloudCredentials {
            user_did: "did:peer:4:z6M".to_string(),
            relay_token: "nc_session_token_xyz".to_string(),
            internal_username: "nextcloud_user_99".to_string(),
            session_proof: ZeroKnowledgeProof {
                proof: b"INVALID_SESSION_PROOF".to_vec(),
                public_inputs: b"session_id_456".to_vec(),
            },
        };
        assert!(auth.verify_identity(&bad_session_creds).is_err());
    }

    #[test]
    fn test_nfc_token_auth_flow() {
        let auth = NfcTokenAuth {
            chip_type: "NTAG424_DNA".to_string(),
        };
        let creds = NfcCredentials {
            card_uid: vec![0x04, 0x23, 0x45],
            dynamic_signature: b"valid_cmac_or_ecdsa_sig".to_vec(),
            challenge: vec![0x01, 0x02, 0x03, 0x04],
        };
        let mapping = auth.verify_identity(&creds).unwrap();
        assert_eq!(mapping.internal_user_id, "nfc_card_042345");
        assert_eq!(mapping.identity_server, "NFC_Reader");

        let bad_creds = NfcCredentials {
            card_uid: vec![0x04, 0x23, 0x45],
            dynamic_signature: b"BAD_SIGNATURE".to_vec(),
            challenge: vec![0x01, 0x02, 0x03, 0x04],
        };
        assert!(auth.verify_identity(&bad_creds).is_err());
    }
}
