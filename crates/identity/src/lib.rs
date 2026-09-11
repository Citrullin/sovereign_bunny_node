//! Identity & Reputation Module
//! Handles DID Peer 4 resolution and identity management.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

pub mod delegation;
pub mod zkp_auth;
pub mod namespace;
/// Decentralized Identifier (DID) management module.
pub mod did;
/// Universal IPLD, Multicodec, CIDv1, and W3C JSON-LD / WoT module.
pub mod ipld;
/// W3C ActivityStreams 2.0 JSON-LD & ActivityPub transcoder.
pub mod activitypub_ld;
/// Multi-Tiered ZK-Merit & Delegated Ephemeral Sessions.
pub mod zk_merit;
/// Extensible Protocol Plugin Registry & Decentralized Git.
pub mod protocol_plugin;

pub use ipld::{CidV1, HashCodec, IpldBlock, IpldCodec, Multihash, WotThingDescription};
pub use activitypub_ld::{ActivityPubActor, ActivityStreamsActivity};
pub use zk_merit::{DelegatedEphemeralSession, GovernanceTier, ZkMeritProof};
pub use protocol_plugin::{GitIpldCommit, ProtocolHandler, ProtocolPluginRegistry};

/// The supported key types in DID Peer 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 signature key type
    Ed25519,
    /// Secp256k1 signature key type (Ethereum)
    Secp256k1,
    /// Secp256r1 signature key type (NIST P-256)
    Secp256r1,
    /// Pasta signature key type (Mina)
    Pasta,
    /// Bls12-381 signature key type
    Bls,
    /// Post-Quantum ML-DSA (Dilithium) lattice-based signature key type
    MlDsa,
    /// Post-Quantum SLH-DSA (SPHINCS+) stateless hash-based signature key type
    SlhDsa,
    /// Post-Quantum Falcon signature key type
    Falcon,
}

impl KeyType {
    /// Returns true if the key type provides post-quantum cryptographic security.
    #[must_use]
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, KeyType::MlDsa | KeyType::SlhDsa | KeyType::Falcon)
    }
}

impl From<KeyType> for sovereign_crypto::SignatureScheme {
    fn from(kt: KeyType) -> Self {
        match kt {
            KeyType::Ed25519 => sovereign_crypto::SignatureScheme::Ed25519,
            KeyType::Secp256k1 => sovereign_crypto::SignatureScheme::Secp256k1,
            KeyType::Secp256r1 => sovereign_crypto::SignatureScheme::Secp256r1,
            KeyType::Pasta => sovereign_crypto::SignatureScheme::Pasta,
            KeyType::Bls => sovereign_crypto::SignatureScheme::Bls,
            KeyType::MlDsa => sovereign_crypto::SignatureScheme::MlDsa,
            KeyType::SlhDsa => sovereign_crypto::SignatureScheme::SlhDsa,
            KeyType::Falcon => sovereign_crypto::SignatureScheme::Falcon,
        }
    }
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
            "JsonWebKey2020" => KeyType::Secp256k1,
            "DilithiumVerificationKey2023" | "MlDsaVerificationKey2024" => KeyType::MlDsa,
            "SphincsPlusVerificationKey2023" | "SlhDsaVerificationKey2024" => KeyType::SlhDsa,
            "FalconVerificationKey2023" => KeyType::Falcon,
            _ => {
                if public_key.len() == 32 {
                    KeyType::Ed25519
                } else if public_key.len() == 1312 || public_key.len() == 1952 || public_key.len() == 2592 {
                    KeyType::MlDsa
                } else if public_key.starts_with(&[0x01, 0xd0]) {
                    KeyType::SlhDsa
                } else if public_key.starts_with(&[0x01, 0xd1]) {
                    KeyType::Falcon
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

    /// Verifies a signature against the public key, checking Zero Latency Quantum Trigger requirements.
    ///
    /// # Errors
    /// Returns an error if signature verification fails or if traditional keys are used when `quantum_threat` is true.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8], quantum_threat: bool) -> Result<(), &'static str> {
        sovereign_crypto::verify_signature(
            self.key_type.into(),
            &self.public_key,
            message,
            signature,
            quantum_threat,
        )
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
    async fn test_did_peer4_resolve_multikey() {
        let keys = vec![
            did_peer::DIDPeerCreateKeys {
                type_: Some(did_peer::DIDPeerKeyType::Secp256k1),
                purpose: did_peer::DIDPeerKeys::Verification,
                public_key_multibase: Some("zQ3shok17vjUvJgqG3Yme5fQwQDndx8C5Jea95D4A8YnUFs2t".into()),
            },
            did_peer::DIDPeerCreateKeys {
                type_: Some(did_peer::DIDPeerKeyType::Ed25519),
                purpose: did_peer::DIDPeerKeys::Verification,
                public_key_multibase: Some("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into()),
            },
        ];
        let (did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).unwrap();
        // Check that the generated multi-key DID works
        let doc = did_peer::DIDPeer.resolve(&did).await.unwrap();
        assert_eq!(doc.verification_method.len(), 2);
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
    fn test_live_identity_connection_failure() {
        let res = zkp_auth::check_live_server_active("https://nonexistent-authentik-server.xyz");
        assert!(res.is_err());
        let err_msg = res.unwrap_err();
        assert!(err_msg.contains("Connection") || err_msg.contains("resolve") || err_msg.contains("refused"));
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

    #[test]
    fn test_zero_latency_quantum_trigger_enforcement() {
        use k256::ecdsa::signature::Signer;
        use k256::ecdsa::SigningKey;

        // 1. Generate valid Secp256k1 signature
        let secp_signing_key = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let secp_verifying_key = secp_signing_key.verifying_key();
        let secp_pubkey = secp_verifying_key.to_sec1_point(true);
        
        let msg = b"test message for quantum trigger enforcement check";
        let sig: k256::ecdsa::Signature = secp_signing_key.sign(msg);
        let sig_bytes = sig.to_bytes();

        use fips204::traits::{KeyGen, SerDes, Signer as FipsSigner};
        let (pk_struct, sk_struct) = fips204::ml_dsa_65::KG::try_keygen().unwrap();
        let pk_bytes = pk_struct.into_bytes();
        let mldsa_sig = FipsSigner::try_sign(&sk_struct, msg, &[]).unwrap();

        let secp_peer = DidPeer4 {
            did: "did:peer:4:zQ3s".to_string(),
            key_type: KeyType::Secp256k1,
            public_key: secp_pubkey.as_bytes().to_vec(),
        };

        let mldsa_peer = DidPeer4 {
            did: "did:peer:4:zDilithium".to_string(),
            key_type: KeyType::MlDsa,
            public_key: pk_bytes.to_vec(),
        };

        // Enforced == false: secp should succeed, ML-DSA should succeed
        assert!(secp_peer.verify_signature(msg, &sig_bytes, false).is_ok());
        assert!(mldsa_peer.verify_signature(msg, &mldsa_sig, false).is_ok());

        // Enforced == true: secp (traditional) must fail, ML-DSA (PQ) must succeed
        let res_secp = secp_peer.verify_signature(msg, &sig_bytes, true);
        assert!(res_secp.is_err());
        assert_eq!(res_secp.unwrap_err(), "ECDSA and EdDSA signature schemes are rejected due to active quantum threat (Zero Latency Quantum Trigger active)");
        
        assert!(mldsa_peer.verify_signature(msg, &mldsa_sig, true).is_ok());
    }
}
