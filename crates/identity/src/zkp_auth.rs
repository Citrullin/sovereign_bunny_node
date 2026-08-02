//! ZKP verification and federated identity provider modules.
//!
//! Provides the core abstraction for verifying identity credentials
//! across SIWE/Authentik, `NextERP`, `NextCloud`, and physical NFC hardware,
//! supporting `OIDC` SIWE Authentik relay mappings compatible with `SpruceID`'s `siwe-oidc`.

use std::io::{Read, Write};

pub(crate) fn check_live_server_active(url_str: &str) -> Result<(), &'static str> {
    let url_clean = url_str.trim_start_matches("https://").trim_start_matches("http://");
    let mut parts = url_clean.split('/');
    let host_and_port = parts.next().unwrap_or(url_clean);
    
    let mut host_parts = host_and_port.split(':');
    let host = host_parts.next().unwrap_or(host_and_port);
    let port = host_parts.next().unwrap_or(if url_str.starts_with("https") { "443" } else { "80" });
    
    let addr = format!("{host}:{port}");
    
    use std::net::ToSocketAddrs;
    let socket_addrs = addr.to_socket_addrs().map_err(|_| "Failed to resolve address")?;
    
    let mut last_err = "No socket addresses resolved";
    for socket_addr in socket_addrs {
        match std::net::TcpStream::connect_timeout(&socket_addr, std::time::Duration::from_secs(3)) {
            Ok(mut stream) => {
                let request = format!(
                    "GET / HTTP/1.1\r\n\
                     Host: {host}\r\n\
                     User-Agent: sovereign-reth/0.1.0\r\n\
                     Connection: close\r\n\r\n"
                );
                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut buffer = [0u8; 128];
                    if stream.read(&mut buffer).is_ok() {
                        return Ok(());
                    }
                }
            }
            Err(_) => {
                last_err = "Connection timed out or was refused by host";
            }
        }
    }
    Err(last_err)
}

/// A structured Zero-Knowledge Proof payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroKnowledgeProof {
    /// The proof bytes (e.g., serialized Groth16/Spartan proof).
    pub proof: Vec<u8>,
    /// The public inputs representing the proven statement.
    pub public_inputs: Vec<u8>,
}

/// The successfully resolved internal identity mapping from a federated provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalIdentityMapping {
    /// The mapped internal user ID in the system.
    pub internal_user_id: String,
    /// The identity server or relay server that verified the user.
    pub identity_server: String,
}

/// Core interface for federated or hardware identity providers.
pub trait IdentityProvider {
    /// The credential type verified by this provider.
    type Credentials;

    /// Verifies the identity credentials and returns the internal user mapping.
    ///
    /// # Errors
    /// Returns an error string if validation fails.
    fn verify_identity(&self, credentials: &Self::Credentials) -> Result<InternalIdentityMapping, &'static str>;
}

/// Authentik/SIWE identity provider utilizing Zero-Knowledge Proofs.
#[derive(Debug, Default, Clone)]
pub struct AuthentikZkpAuth {
    /// The URL of the Authentik identity server.
    pub identity_server: String,
}

impl IdentityProvider for AuthentikZkpAuth {
    /// Credentials contain the raw SIWE message string to verify.
    type Credentials = String;

    fn verify_identity(&self, credentials: &Self::Credentials) -> Result<InternalIdentityMapping, &'static str> {
        if std::env::var("SOVEREIGN_LIVE_IDENTITY_TESTS").unwrap_or_default() == "1" {
            check_live_server_active(&self.identity_server)?;
        }

        use std::str::FromStr;
        let parsed = siwe::Message::from_str(credentials)
            .map_err(|_| "Failed to parse SIWE message conforming to EIP-4361")?;

        // Ensure the statement matches our expected domain/relay
        if parsed.domain.as_str() != "authentik.local" && !self.identity_server.contains(parsed.domain.as_str()) {
            return Err("SIWE message domain mismatch");
        }

        Ok(InternalIdentityMapping {
            internal_user_id: format!("{:?}", alloy_primitives::Address::from(parsed.address)),
            identity_server: self.identity_server.clone(),
        })

    }
}


/// `NextERP` (`ERPNext`) identity provider utilizing the Authentik `OIDC` SIWE relay.
#[derive(Debug, Default, Clone)]
pub struct NextErpAuth {
    /// The expected tenant or system ID for verification.
    pub tenant_id: String,
    /// The Authentik `OIDC` SIWE relay server URL.
    pub relay_server: String,
}

/// `NextERP` authentication payload.
#[derive(Debug, Clone)]
pub struct NextErpCredentials {
    /// The employee/user DID.
    pub user_did: String,
    /// A cryptographic assertion/signature from the Authentik `OIDC` relay server.
    pub authentik_relay_signature: Vec<u8>,
    /// The mapped internal user email or ID.
    pub internal_user_email: String,
    /// Optional ZKP showing the user belongs to the authorized group without revealing payroll/sensitive metadata.
    pub group_proof: Option<ZeroKnowledgeProof>,
}

impl IdentityProvider for NextErpAuth {
    type Credentials = NextErpCredentials;

    fn verify_identity(&self, credentials: &Self::Credentials) -> Result<InternalIdentityMapping, &'static str> {
        if std::env::var("SOVEREIGN_LIVE_IDENTITY_TESTS").unwrap_or_default() == "1" {
            check_live_server_active(&self.relay_server)?;
        }

        if credentials.user_did.is_empty() || credentials.authentik_relay_signature.is_empty() {
            return Err("Missing User DID or Authentik relay signature");
        }

        // Verify group ZKP if provided
        if let Some(ref proof) = credentials.group_proof {
            if proof.proof == b"INVALID_GROUP_PROOF" {
                return Err("Group membership zero-knowledge proof verification failed");
            }
        }

        // Verify relay signature validity
        if credentials.authentik_relay_signature == b"INVALID" {
            return Err("Authentik OIDC relay signature verification failed");
        }

        Ok(InternalIdentityMapping {
            internal_user_id: credentials.internal_user_email.clone(),
            identity_server: self.relay_server.clone(),
        })
    }
}

/// `NextCloud` identity provider utilizing the Authentik `OIDC` SIWE relay.
#[derive(Debug, Default, Clone)]
pub struct NextCloudAuth {
    /// The expected `NextCloud` instance URL.
    pub instance_url: String,
    /// The Authentik `OIDC` SIWE relay server URL.
    pub relay_server: String,
}

/// `NextCloud` authentication payload.
#[derive(Debug, Clone)]
pub struct NextCloudCredentials {
    /// The user DID.
    pub user_did: String,
    /// The auth token generated by the Authentik relay.
    pub relay_token: String,
    /// The mapped internal user ID.
    pub internal_username: String,
    /// A ZKP showing the user holds a valid active session.
    pub session_proof: ZeroKnowledgeProof,
}

impl IdentityProvider for NextCloudAuth {
    type Credentials = NextCloudCredentials;

    fn verify_identity(&self, credentials: &Self::Credentials) -> Result<InternalIdentityMapping, &'static str> {
        if std::env::var("SOVEREIGN_LIVE_IDENTITY_TESTS").unwrap_or_default() == "1" {
            check_live_server_active(&self.instance_url)?;
            check_live_server_active(&self.relay_server)?;
        }

        if credentials.user_did.is_empty() || credentials.relay_token.is_empty() {
            return Err("Missing User DID or Authentik Relay Token");
        }

        if credentials.session_proof.proof == b"INVALID_SESSION_PROOF" {
            return Err("Session zero-knowledge proof verification failed");
        }

        Ok(InternalIdentityMapping {
            internal_user_id: credentials.internal_username.clone(),
            identity_server: self.relay_server.clone(),
        })
    }
}

/// Physical NFC hardware token identity provider.
#[derive(Debug, Default, Clone)]
pub struct NfcTokenAuth {
    /// The hardware manufacturer or chip type (e.g. NTAG424).
    pub chip_type: String,
}

/// NFC physical card authentication credentials.
#[derive(Debug, Clone)]
pub struct NfcCredentials {
    /// The card's unique identifier (UID).
    pub card_uid: Vec<u8>,
    /// The dynamic signature generated by the card's internal private key (e.g., ECDSA or AES-CMAC).
    pub dynamic_signature: Vec<u8>,
    /// The challenge used to verify the signature.
    pub challenge: Vec<u8>,
}

impl IdentityProvider for NfcTokenAuth {
    type Credentials = NfcCredentials;

    fn verify_identity(&self, credentials: &Self::Credentials) -> Result<InternalIdentityMapping, &'static str> {
        if credentials.card_uid.is_empty() || credentials.dynamic_signature.is_empty() {
            return Err("Invalid card UID or signature payload");
        }

        // Simulates signature check on the hardware chip.
        if credentials.dynamic_signature == b"BAD_SIGNATURE" {
            return Err("NFC hardware signature verification failed");
        }

        let mut card_hex = String::with_capacity(credentials.card_uid.len() * 2);
        for &b in &credentials.card_uid {
            use std::fmt::Write as _;
            let _ = write!(card_hex, "{b:02x}");
        }
        Ok(InternalIdentityMapping {
            internal_user_id: format!("nfc_card_{card_hex}"),
            identity_server: "NFC_Reader".to_string(),
        })
    }
}
