//! # W3C ActivityStreams 2.0 JSON-LD & ActivityPub Transcoder
//!
//! Bridges W3C ActivityStreams 2.0 / ActivityPub data models with content-addressed
//! IPLD blocks (`dag-json`) and fixed-offset SSZ `ActivityPubEnvelope`s on the Account-Lattice.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use sovereign_ssz::activitypub::{ActivityPubEnvelope, ActivityType};
use crate::ipld::IpldBlock;

/// Canonical ActivityStreams 2.0 @context URI.
pub const ACTIVITYSTREAMS_CONTEXT: &str = "https://www.w3.org/ns/activitystreams";
/// Canonical W3C Security @context URI.
pub const SECURITY_CONTEXT: &str = "https://w3id.org/security/v1";

/// W3C ActivityStreams 2.0 PublicKey block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityPubPublicKey {
    /// URI identifier for the public key.
    pub id: String,
    /// Owner actor URI.
    pub owner: String,
    /// PEM-encoded public key.
    #[serde(rename = "publicKeyPem")]
    pub public_key_pem: String,
}

/// W3C ActivityStreams 2.0 Actor document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityPubActor {
    /// JSON-LD Context URIs.
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Global Actor URI ID.
    pub id: String,
    /// Type of Actor ("Person", "Service", "Organization").
    #[serde(rename = "type")]
    pub actor_type: String,
    /// Preferred short handle / username.
    #[serde(rename = "preferredUsername")]
    pub preferred_username: String,
    /// Display name.
    pub name: Option<String>,
    /// Biography / summary description.
    pub summary: Option<String>,
    /// ActivityPub Inbox endpoint URI.
    pub inbox: String,
    /// ActivityPub Outbox endpoint URI.
    pub outbox: String,
    /// Cryptographic public key container.
    #[serde(rename = "publicKey")]
    pub public_key: ActivityPubPublicKey,
    /// Bound Sovereign DID URI.
    #[serde(default, rename = "sovereignDid")]
    pub sovereign_did: Option<String>,
    /// Bound Account-Lattice address.
    #[serde(default, rename = "latticeAddress")]
    pub lattice_address: Option<String>,
}

impl ActivityPubActor {
    /// Creates a new `ActivityPubActor` linked to a Sovereign DID and Lattice account.
    pub fn new(
        username: &str,
        domain: &str,
        evm_address: Address,
        did_uri: &str,
        pubkey_pem: &str,
    ) -> Self {
        let actor_id = format!("https://{}/users/{}", domain, username);
        let key_id = format!("{}#main-key", actor_id);

        Self {
            context: vec![
                ACTIVITYSTREAMS_CONTEXT.to_string(),
                SECURITY_CONTEXT.to_string(),
            ],
            id: actor_id.clone(),
            actor_type: "Person".to_string(),
            preferred_username: username.to_string(),
            name: Some(username.to_string()),
            summary: Some("Sovereign Account-Lattice Federated Actor".to_string()),
            inbox: format!("{}/inbox", actor_id),
            outbox: format!("{}/outbox", actor_id),
            public_key: ActivityPubPublicKey {
                id: key_id,
                owner: actor_id,
                public_key_pem: pubkey_pem.to_string(),
            },
            sovereign_did: Some(did_uri.to_string()),
            lattice_address: Some(format!("{:#x}", evm_address)),
        }
    }

    /// Converts to W3C JSON-LD Value.
    pub fn to_json_ld(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Serializes to an IPLD `dag-json` Block.
    pub fn to_ipld_block(&self) -> Result<IpldBlock, String> {
        IpldBlock::from_dag_json(self)
    }

    /// Parses from an IPLD `dag-json` Block.
    pub fn from_ipld_block(block: &IpldBlock) -> Result<Self, String> {
        if !block.verify_integrity() {
            return Err("IPLD block cryptographic integrity check failed".to_string());
        }
        serde_json::from_slice(&block.raw_data)
            .map_err(|e| format!("Failed to parse ActivityPubActor: {e}"))
    }
}

/// W3C ActivityStreams 2.0 Activity document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityStreamsActivity {
    /// JSON-LD Context definition.
    #[serde(rename = "@context")]
    pub context: serde_json::Value,
    /// Global Activity URI ID.
    pub id: String,
    /// Type of Activity ("Create", "Follow", "Announce", "Like", "Undo", "PaywallGrant").
    #[serde(rename = "type")]
    pub activity_type: String,
    /// Actor URI initiating the activity.
    pub actor: String,
    /// Target Object payload.
    pub object: serde_json::Value,
    /// Target recipients.
    #[serde(default)]
    pub to: Vec<String>,
    /// CC recipients.
    #[serde(default)]
    pub cc: Vec<String>,
    /// Optional attached micro-payment in atomic units.
    #[serde(default, rename = "attachedMicroPayment")]
    pub attached_micro_payment: Option<u64>,
    /// Optional ZK-Merit proof root hex.
    #[serde(default, rename = "meritProofRoot")]
    pub merit_proof_root: Option<String>,
}

impl ActivityStreamsActivity {
    /// Transcodes a high-level ActivityStreams JSON-LD activity into a canonical SSZ `ActivityPubEnvelope`.
    pub fn to_ssz_envelope(
        &self,
        actor_address: Address,
        target_recipient: Address,
        object_cid: B256,
        signature: &[u8],
    ) -> Result<ActivityPubEnvelope, String> {
        let act_type = match self.activity_type.as_str() {
            "Create" => ActivityType::Create,
            "Follow" => ActivityType::Follow,
            "Announce" => ActivityType::Announce,
            "Like" => ActivityType::Like,
            "Undo" => ActivityType::Undo,
            "PaywallGrant" => ActivityType::PaywallGrant,
            other => return Err(format!("Unsupported ActivityStreams type: {other}")),
        };

        let merit_root = if let Some(ref root_hex) = self.merit_proof_root {
            let clean = root_hex.strip_prefix("0x").unwrap_or(root_hex);
            let bytes = alloy_primitives::hex::decode(clean)
                .map_err(|e| format!("Invalid meritProofRoot hex: {e}"))?;
            if bytes.len() == 32 {
                B256::from_slice(&bytes)
            } else {
                B256::ZERO
            }
        } else {
            B256::ZERO
        };

        let payment = self.attached_micro_payment.unwrap_or(0);

        Ok(ActivityPubEnvelope::new(
            actor_address,
            act_type,
            object_cid,
            target_recipient,
            payment,
            merit_root,
            signature,
        ))
    }

    /// Reconstructs a JSON-LD Activity from an SSZ `ActivityPubEnvelope` and object payload.
    pub fn from_ssz_envelope(
        envelope: &ActivityPubEnvelope,
        domain: &str,
        object_payload: serde_json::Value,
    ) -> Self {
        let act_type_str = envelope.parsed_activity_type()
            .map(|t| t.as_str())
            .unwrap_or("Create");

        let actor_uri = format!("https://{}/users/{:#x}", domain, envelope.actor());
        let activity_id = format!("{}/activities/{:#x}", actor_uri, envelope.cid_b256());

        Self {
            context: serde_json::json!(ACTIVITYSTREAMS_CONTEXT),
            id: activity_id,
            activity_type: act_type_str.to_string(),
            actor: actor_uri,
            object: object_payload,
            to: vec![format!("https://{}/users/{:#x}", domain, envelope.recipient())],
            cc: vec!["https://www.w3.org/ns/activitystreams#Public".to_string()],
            attached_micro_payment: Some(envelope.attached_micro_payment),
            merit_proof_root: Some(format!("{:#x}", envelope.merit_root_b256())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actor_json_ld_and_ipld_roundtrip() {
        let actor = ActivityPubActor::new(
            "alice",
            "manifold.mesh",
            Address::repeat_byte(0x11),
            "did:sovereign:1337:0x1111111111111111111111111111111111111111",
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----",
        );

        let json_val = actor.to_json_ld();
        assert_eq!(json_val["preferredUsername"], "alice");
        assert_eq!(json_val["inbox"], "https://manifold.mesh/users/alice/inbox");

        let block = actor.to_ipld_block().expect("IPLD block creation");
        assert!(block.verify_integrity());

        let decoded = ActivityPubActor::from_ipld_block(&block).expect("IPLD decode");
        assert_eq!(decoded.id, actor.id);
        assert_eq!(decoded.preferred_username, "alice");
        assert_eq!(decoded.sovereign_did, actor.sovereign_did);
    }

    #[test]
    fn test_activitystreams_transcoding_to_ssz() {
        let activity = ActivityStreamsActivity {
            context: serde_json::json!(ACTIVITYSTREAMS_CONTEXT),
            id: "https://manifold.mesh/users/alice/activities/1".to_string(),
            activity_type: "Create".to_string(),
            actor: "https://manifold.mesh/users/alice".to_string(),
            object: serde_json::json!({
                "type": "Note",
                "content": "Hello Sovereign Fediverse with Iroh ZK-PoR storage!",
            }),
            to: vec!["https://manifold.mesh/users/bob".to_string()],
            cc: vec![],
            attached_micro_payment: Some(100_000),
            merit_proof_root: Some("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()),
        };

        let actor_addr = Address::repeat_byte(0x11);
        let bob_addr = Address::repeat_byte(0x22);
        let cid = B256::repeat_byte(0x33);
        let sig = [0x77u8; 96];

        let ssz_envelope = activity.to_ssz_envelope(actor_addr, bob_addr, cid, &sig).unwrap();
        assert_eq!(ssz_envelope.actor(), actor_addr);
        assert_eq!(ssz_envelope.recipient(), bob_addr);
        assert_eq!(ssz_envelope.attached_micro_payment, 100_000);
        assert_eq!(ssz_envelope.parsed_activity_type(), Some(ActivityType::Create));

        let reconstructed = ActivityStreamsActivity::from_ssz_envelope(
            &ssz_envelope,
            "manifold.mesh",
            serde_json::json!({ "type": "Note", "content": "Restored Note" }),
        );
        assert_eq!(reconstructed.activity_type, "Create");
        assert_eq!(reconstructed.attached_micro_payment, Some(100_000));
    }
}
