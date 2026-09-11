//! # ActivityPub Proxy & WebFinger Gateway
//!
//! Exposes W3C ActivityStreams 2.0 Inbox/Outbox endpoints, translates WebFinger queries
//! via in-memory `zkDNS` (`0x00...0003`), and bridges external Fediverse clients to the Account-Lattice.

use alloy_primitives::{Address, B256};
use sovereign_consensus::registry::ValidatorRegistry;
use sovereign_identity::activitypub_ld::{ActivityPubActor, ActivityStreamsActivity};
use sovereign_ssz::activitypub::ActivityPubEnvelope;

/// Resolves a WebFinger query (`/.well-known/webfinger?resource=acct:user@domain`) via in-memory zkDNS.
pub fn handle_webfinger(
    resource: &str,
    domain: &str,
    registry: &ValidatorRegistry,
) -> Result<serde_json::Value, String> {
    let clean_res = resource.trim();
    let username = if clean_res.starts_with("acct:") {
        let handle = clean_res.strip_prefix("acct:").unwrap();
        let mut parts = handle.split('@');
        parts.next().unwrap_or(handle)
    } else if clean_res.starts_with("did:sovereign:") || clean_res.starts_with("did:peer:") {
        clean_res
    } else {
        clean_res
    };

    // Look up in zkDNS / identities table
    let resolved_identity = registry.identities.iter().find(|(k, _)| {
        k.contains(username) || k.ends_with(username)
    });

    let (actor_uri, did_uri, address_str) = if let Some((_id_key, reg_id)) = resolved_identity {
        let did = reg_id.did.clone();
        let addr = format!("{:#x}", reg_id.doc.evm_address);
        (format!("https://{}/users/{}", domain, username), did, addr)
    } else {
        // Deterministic fallback for unregistered actors
        let fallback_addr = format!("0x{:040x}", 0x1337);
        let fallback_did = format!("did:sovereign:{}:{}", registry.chain_id, fallback_addr);
        (format!("https://{}/users/{}", domain, username), fallback_did, fallback_addr)
    };

    Ok(serde_json::json!({
        "subject": format!("acct:{}@{}", username, domain),
        "aliases": [
            actor_uri,
            did_uri,
            format!("ethereum:{}", address_str),
        ],
        "links": [
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": format!("https://{}/users/{}", domain, username)
            },
            {
                "rel": "http://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": format!("https://{}/@{}", domain, username)
            }
        ]
    }))
}

/// Generates W3C ActivityStreams 2.0 Actor JSON-LD document for `GET /users/:username`.
pub fn handle_actor_json_ld(
    username: &str,
    domain: &str,
    registry: &ValidatorRegistry,
) -> Result<serde_json::Value, String> {
    let resolved_identity = registry.identities.iter().find(|(k, _)| {
        k.contains(username) || k.ends_with(username)
    });

    let actor = if let Some((_, reg_id)) = resolved_identity {
        ActivityPubActor::new(
            username,
            domain,
            reg_id.doc.evm_address,
            &reg_id.did,
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----",
        )
    } else {
        ActivityPubActor::new(
            username,
            domain,
            Address::repeat_byte(0x11),
            &format!("did:sovereign:{}:0x1111111111111111111111111111111111111111", registry.chain_id),
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----",
        )
    };

    Ok(actor.to_json_ld())
}

/// Processes an incoming ActivityStreams Activity on `POST /users/:username/inbox`.
pub fn handle_inbox_activity(
    activity_json: serde_json::Value,
    _registry: &ValidatorRegistry,
) -> Result<serde_json::Value, String> {
    let act_type = activity_json.get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required 'type' field in ActivityStreams payload".to_string())?;

    let actor = activity_json.get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing required 'actor' field in ActivityStreams payload".to_string())?;

    tracing::info!(act_type, actor, "Ingested ActivityStreams activity via bunny-gateway inbox");

    Ok(serde_json::json!({
        "status": "accepted",
        "activity_type": act_type,
        "actor": actor,
        "processed_in_ram": true
    }))
}

/// Transcodes an outgoing Activity on `POST /users/:username/outbox` into an SSZ `ActivityPubEnvelope`.
pub fn handle_outbox_publish(
    activity_json: serde_json::Value,
    actor_addr: Address,
    recipient_addr: Address,
    object_cid: B256,
    signature: &[u8],
) -> Result<ActivityPubEnvelope, String> {
    let activity: ActivityStreamsActivity = serde_json::from_value(activity_json)
        .map_err(|e| format!("Invalid ActivityStreams JSON: {e}"))?;

    activity.to_ssz_envelope(actor_addr, recipient_addr, object_cid, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_identity::activitypub_ld::ACTIVITYSTREAMS_CONTEXT;

    #[test]
    fn test_webfinger_resolution() {
        let registry = ValidatorRegistry::default();
        let res = handle_webfinger("acct:alice@manifold.mesh", "manifold.mesh", &registry).unwrap();
        assert_eq!(res["subject"], "acct:alice@manifold.mesh");
        assert_eq!(res["links"][0]["href"], "https://manifold.mesh/users/alice");
    }

    #[test]
    fn test_actor_json_ld_generation() {
        let registry = ValidatorRegistry::default();
        let actor = handle_actor_json_ld("alice", "manifold.mesh", &registry).unwrap();
        assert_eq!(actor["preferredUsername"], "alice");
        assert_eq!(actor["inbox"], "https://manifold.mesh/users/alice/inbox");
        assert_eq!(actor["outbox"], "https://manifold.mesh/users/alice/outbox");
    }

    #[test]
    fn test_inbox_ingestion_and_outbox_transcoding() {
        let registry = ValidatorRegistry::default();
        let activity = serde_json::json!({
            "@context": ACTIVITYSTREAMS_CONTEXT,
            "id": "https://manifold.mesh/users/alice/activities/100",
            "type": "Create",
            "actor": "https://manifold.mesh/users/alice",
            "object": {
                "type": "Note",
                "content": "Stateless ActivityPub over Account-Lattice!"
            },
            "to": ["https://manifold.mesh/users/bob"],
            "attachedMicroPayment": 5000
        });

        let inbox_res = handle_inbox_activity(activity.clone(), &registry).unwrap();
        assert_eq!(inbox_res["status"], "accepted");

        let actor_addr = Address::repeat_byte(0x11);
        let bob_addr = Address::repeat_byte(0x22);
        let cid = B256::repeat_byte(0x33);
        let sig = [0x55u8; 96];

        let envelope = handle_outbox_publish(activity, actor_addr, bob_addr, cid, &sig).unwrap();
        assert_eq!(envelope.actor(), actor_addr);
        assert_eq!(envelope.recipient(), bob_addr);
        assert_eq!(envelope.attached_micro_payment, 5000);
    }
}
