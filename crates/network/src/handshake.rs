use alloy_primitives::keccak256;
use boringtun::x25519::{StaticSecret, PublicKey};

/// Derives multiple key types from a single master seed.
pub struct KeyDeriver {
    /// The master seed.
    pub master_seed: [u8; 32],
}

impl Drop for KeyDeriver {
    fn drop(&mut self) {
        self.master_seed.fill(0);
    }
}

impl KeyDeriver {
    /// Creates a new key deriver from a 32-byte seed.
    #[must_use]
    pub fn new(master_seed: [u8; 32]) -> Self {
        Self { master_seed }
    }

    /// Derives a Curve25519 keypair for `WireGuard`.
    #[must_use]
    pub fn derive_curve25519(&self) -> ([u8; 32], [u8; 32]) {
        let mut seed = [0u8; 42];
        seed[..10].copy_from_slice(b"curve25519");
        seed[10..].copy_from_slice(&self.master_seed);
        let priv_bytes = keccak256(seed).0;
        let local_priv = StaticSecret::from(priv_bytes);
        let local_pub = PublicKey::from(&local_priv);
        let pub_bytes = *local_pub.as_bytes();
        (priv_bytes, pub_bytes)
    }

    /// Derives an Ed25519 keypair for standard signing.
    #[must_use]
    pub fn derive_ed25519(&self) -> ([u8; 32], [u8; 32]) {
        let mut seed = [0u8; 39];
        seed[..7].copy_from_slice(b"ed25519");
        seed[7..].copy_from_slice(&self.master_seed);
        let priv_bytes = keccak256(seed).0;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_bytes);
        let verifying_key = signing_key.verifying_key();
        (priv_bytes, verifying_key.to_bytes())
    }

    /// Derives a secp256k1 keypair for EVM compat.
    #[must_use]
    pub fn derive_secp256k1(&self) -> ([u8; 32], [u8; 33]) {
        let mut seed = [0u8; 41];
        seed[..9].copy_from_slice(b"secp256k1");
        seed[9..].copy_from_slice(&self.master_seed);
        let mut priv_bytes = keccak256(seed).0;
        
        let signing_key = loop {
            if let Ok(key) = k256::ecdsa::SigningKey::from_bytes(&priv_bytes.into()) {
                break key;
            }
            priv_bytes = keccak256(priv_bytes).0;
        };

        let verifying_key = signing_key.verifying_key();
        let pub_point = verifying_key.to_sec1_point(true); // compressed
        let mut out_pub = [0u8; 33];
        out_pub.copy_from_slice(pub_point.as_bytes());
        (priv_bytes, out_pub)
    }

    /// Derives a post-quantum keypair based on the scheme.
    #[must_use]
    pub fn derive_pq_keypair(&self, scheme: sovereign_identity::KeyType) -> (Vec<u8>, Vec<u8>) {
        let prefix: &[u8] = match scheme {
            sovereign_identity::KeyType::MlDsa => b"mldsa",
            sovereign_identity::KeyType::SlhDsa => b"slhdsa",
            sovereign_identity::KeyType::Falcon => b"falcon",
            _ => b"mldsa",
        };
        let mut seed = Vec::new();
        seed.extend_from_slice(prefix);
        seed.extend_from_slice(&self.master_seed);
        let priv_bytes = keccak256(&seed).0.to_vec();
        // Return derived mock PQ key pair bytes based on master seed
        let mut pub_bytes = priv_bytes.clone();
        pub_bytes.reverse(); // simple deterministic mock public key
        (priv_bytes, pub_bytes)
    }
}

/// Zero-configuration mesh handshaker that processes NFC taps to establish peering.
pub struct ZeroConfigMesh {
    /// `WireGuard` manager to control the interfaces.
    pub wg_manager: WireguardManager,
    /// List of actively peered DIDs.
    pub peered_dids: Vec<String>,
}

impl ZeroConfigMesh {
    /// Creates a new `ZeroConfigMesh` instance.
    #[must_use]
    pub fn new(interface_name: &str) -> Self {
        Self {
            wg_manager: WireguardManager::new(interface_name),
            peered_dids: Vec::new(),
        }
    }

    /// Automatically registers a peer and establishes a `WireGuard` interface configuration
    /// upon receiving an NFC credentials handshake exchange.
    ///
    /// # Errors
    /// Returns an error if the signature credentials verification fails or if peering setup fails.
    pub fn handle_nfc_handshake(
        &mut self,
        did: &str,
        creds: &sovereign_identity::zkp_auth::NfcCredentials,
        endpoint: &str,
    ) -> Result<(), &'static str> {
        // 1. Verify credentials using peer's public key resolved from DID
        let resolved = futures::executor::block_on(sovereign_identity::DidPeer4::resolve(did))
            .map_err(|_| "Failed to resolve DID for signature verification")?;

        resolved.verify_signature(&creds.challenge, &creds.dynamic_signature, false)?;

        // 2. Configure Wireguard interface
        self.wg_manager
            .add_peer_from_did(did, endpoint)
            .map_err(|_| "Wireguard peering failed")?;

        // 3. Track peered DID
        self.peered_dids.push(did.to_string());

        Ok(())
    }
}

use crate::wireguard::WireguardManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let master_seed = [42u8; 32];
        let deriver = KeyDeriver::new(master_seed);
        
        let (wg_priv, wg_pub) = deriver.derive_curve25519();
        assert_ne!(wg_priv, [0u8; 32]);
        assert_ne!(wg_pub, [0u8; 32]);
        
        let (ed_priv, ed_pub) = deriver.derive_ed25519();
        assert_ne!(ed_priv, [0u8; 32]);
        assert_ne!(ed_pub, [0u8; 32]);
        
        let (secp_priv, secp_pub) = deriver.derive_secp256k1();
        assert_ne!(secp_priv, [0u8; 32]);
        assert_ne!(secp_pub, [0u8; 33]);

        // Verify determinism
        let deriver2 = KeyDeriver::new(master_seed);
        assert_eq!(deriver2.derive_curve25519(), (wg_priv, wg_pub));
        assert_eq!(deriver2.derive_ed25519(), (ed_priv, ed_pub));
        assert_eq!(deriver2.derive_secp256k1(), (secp_priv, secp_pub));
    }

    #[test]
    fn test_zero_config_nfc_handshake() {
        use ed25519_dalek::{SigningKey, Signer};

        let mut mesh = ZeroConfigMesh::new("wg0");
        let seed = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        
        let mut codec_bytes = vec![0xed, 0x01];
        codec_bytes.extend_from_slice(&verifying_key.to_bytes());
        let multibase_str = format!("z{}", bs58::encode(codec_bytes).into_string());

        let keys = vec![did_peer::DIDPeerCreateKeys {
            type_: Some(did_peer::DIDPeerKeyType::Ed25519),
            purpose: did_peer::DIDPeerKeys::Verification,
            public_key_multibase: Some(multibase_str),
        }];
        let (did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).unwrap();

        let challenge = vec![1, 2, 3];
        let sig = signing_key.sign(&challenge).to_bytes().to_vec();

        let creds = sovereign_identity::zkp_auth::NfcCredentials {
            card_uid: vec![0x11, 0x22],
            dynamic_signature: sig.clone(),
            challenge: challenge.clone(),
        };
        
        let res = mesh.handle_nfc_handshake(&did, &creds, "10.0.0.2:51820");
        res.unwrap();
        assert_eq!(mesh.peered_dids[0], did);

        // Invalid signature test
        let bad_creds = sovereign_identity::zkp_auth::NfcCredentials {
            card_uid: vec![0x11, 0x22],
            dynamic_signature: b"BAD_SIGNATURE_BYTES_REPEATED_BYTE_000000000000000000000000000000".to_vec(),
            challenge,
        };
        let res_err = mesh.handle_nfc_handshake(&did, &bad_creds, "10.0.0.2:51820");
        assert!(res_err.is_err());
    }
}
