//! # ActivityPub & Fediverse Bridge End-to-End Cluster Tests
//!
//! Verifies full federation between external ActivityStreams 2.0 / WebFinger clients,
//! in-memory zkDNS resolution, SSZ ActivityPubEnvelope transcoding, Account-Lattice
//! outbox tip progression ($H_t \to H_{t+1}$), and Iroh ZK-PoR storage merit emissions.

use alloy_primitives::{Address, B256, U256};
use sovereign_consensus::registry::ValidatorRegistry;
use sovereign_consensus::system_contracts::router::execute_system_action;
use sovereign_consensus::system_registry::{SYSTEM_CMS, SYSTEM_STORAGE_DA, SystemAction};
use sovereign_identity::activitypub_ld::{ActivityPubActor, ActivityStreamsActivity, ACTIVITYSTREAMS_CONTEXT};
use sovereign_identity::did::SovereignDidDocument;
use sovereign_ssz::activitypub::ActivityType;
use sovereign_consensus::storage::dialects::MultiDialectStorageEngine;

#[test]
fn test_activitypub_end_to_end_manifold_federation() {
    // ─────────────────────────────────────────────────────────────────────────
    // 1. WebFinger & zkDNS Discovery Layer
    // ─────────────────────────────────────────────────────────────────────────
    let mut registry = ValidatorRegistry::default();
    let alice_seed = B256::repeat_byte(0x11);
    let alice_did_doc = SovereignDidDocument::derive_from_seed(alice_seed);
    let alice_addr = alice_did_doc.evm_address;

    // Register Alice in zkDNS (SYSTEM_DID_REGISTRY 0x00...03)
    let reg_did_action = SystemAction::RegisterDid {
        did_document: alice_did_doc.to_w3c_json_ld().to_string(),
        pq_pub_key: vec![0x11; 32],
        key_tier: "QuantumReady".to_string(),
    };
    let reg_calldata = reg_did_action.encode();
    execute_system_action(&mut registry, alice_addr, sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY, &reg_calldata, 1)
        .expect("Alice zkDNS registration");

    // 2. Generate W3C Actor JSON-LD document
    let actor_doc = ActivityPubActor::new(
        "alice",
        "manifold.mesh",
        alice_addr,
        &alice_did_doc.did_uri,
        "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----",
    );
    let actor_json = actor_doc.to_json_ld();
    assert_eq!(actor_json["preferredUsername"], "alice");
    assert_eq!(actor_json["inbox"], "https://manifold.mesh/users/alice/inbox");

    // Verify IPLD dag-json roundtrip
    let ipld_block = actor_doc.to_ipld_block().expect("IPLD block encoding");
    assert!(ipld_block.verify_integrity());

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Media Blob Pinned via Iroh BLAKE3 & ZK-PoR Storage Engine
    // ─────────────────────────────────────────────────────────────────────────
    let mut storage_engine = MultiDialectStorageEngine::default();
    let media_payload = b"Federated HD Video & Post Image Attachment over Iroh P2P";
    let media_cid = B256::from_slice(blake3::hash(media_payload).as_bytes());

    // Store media bytes under Alice's provider session
    storage_engine.execute_kv(
        &alice_did_doc.did_uri,
        sovereign_consensus::storage::dialects::KvCommand::Set {
            key: format!("media:{}", alloy_primitives::hex::encode(media_cid.as_slice())),
            value: media_payload.to_vec(),
            ttl_secs: None,
        },
    ).expect("Store media payload in dialect store");

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Create ActivityPub Note Activity & Transcode to SSZ ActivityPubEnvelope
    // ─────────────────────────────────────────────────────────────────────────
    let bob_addr = Address::repeat_byte(0x22);
    let note_activity = ActivityStreamsActivity {
        context: serde_json::json!(ACTIVITYSTREAMS_CONTEXT),
        id: "https://manifold.mesh/users/alice/activities/1".to_string(),
        activity_type: "Create".to_string(),
        actor: "https://manifold.mesh/users/alice".to_string(),
        object: serde_json::json!({
            "type": "Note",
            "content": "Excited to federate from the stateless Sovereign Account-Lattice!",
            "attachment": [{
                "type": "Document",
                "mediaType": "video/mp4",
                "url": format!("iroh://b3:{}", alloy_primitives::hex::encode(media_cid.as_slice()))
            }]
        }),
        to: vec![format!("https://manifold.mesh/users/{:#x}", bob_addr)],
        cc: vec!["https://www.w3.org/ns/activitystreams#Public".to_string()],
        attached_micro_payment: Some(25_000), // 25,000 atomic units tip
        merit_proof_root: Some(format!("{:#x}", B256::repeat_byte(0x77))),
    };

    let sig = [0x55u8; 96];
    let ssz_envelope = note_activity.to_ssz_envelope(alice_addr, bob_addr, media_cid, &sig)
        .expect("Transcode to SSZ envelope");

    assert_eq!(ssz_envelope.actor(), alice_addr);
    assert_eq!(ssz_envelope.recipient(), bob_addr);
    assert_eq!(ssz_envelope.cid_b256(), media_cid);
    assert_eq!(ssz_envelope.attached_micro_payment, 25_000);
    assert_eq!(ssz_envelope.parsed_activity_type(), Some(ActivityType::Create));

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Commit Outbox State Transition ($H_t \to H_{t+1}$) to SYSTEM_CMS (0xF1)
    // ─────────────────────────────────────────────────────────────────────────
    let initial_frontier = registry.get_or_create_frontier(alice_addr);
    let initial_seq = initial_frontier.sequence;

    let cms_action = SystemAction::PublishActivityPub {
        actor: ssz_envelope.actor(),
        activity_type: ssz_envelope.activity_type,
        object_cid: ssz_envelope.cid_b256(),
        recipient: ssz_envelope.recipient(),
        micro_payment: ssz_envelope.attached_micro_payment,
        merit_proof_root: ssz_envelope.merit_root_b256(),
    };
    let cms_calldata = cms_action.encode();
    execute_system_action(&mut registry, alice_addr, SYSTEM_CMS, &cms_calldata, 1)
        .expect("Publish ActivityPub to SYSTEM_CMS");

    let updated_frontier = registry.get_or_create_frontier(alice_addr);
    assert_eq!(updated_frontier.sequence, initial_seq + 1, "Outbox tip sequence advanced");
    assert_eq!(updated_frontier.latest_hash, media_cid, "Outbox tip hash points to media CID");

    // ─────────────────────────────────────────────────────────────────────────
    // 6. Claim Storage Merit Yield at SYSTEM_STORAGE_DA (0x00...0053) via Bao PoR
    // ─────────────────────────────────────────────────────────────────────────
    let epoch_mint_pool = U256::from(100_000_000_000_000_000_000u128); // 100 tokens
    let (por_commitment, reward) = storage_engine.generate_storage_merit_claim(
        &alice_did_doc.did_uri,
        1,
        epoch_mint_pool,
    ).expect("Generate Bao PoR merit claim");

    assert_ne!(por_commitment, B256::ZERO);
    assert!(reward > U256::ZERO);
    assert!(reward <= epoch_mint_pool / U256::from(5), "Capped within 20% epoch pool limit");

    let claim_action = SystemAction::ClaimStorageMerit {
        provider_did: alice_did_doc.did_uri.clone(),
        bao_slice_proof: por_commitment.as_slice().to_vec(),
        epoch_id: 1,
    };
    let claim_calldata = claim_action.encode();
    execute_system_action(&mut registry, alice_addr, SYSTEM_STORAGE_DA, &claim_calldata, 1)
        .expect("Settle Storage Merit emission at SYSTEM_STORAGE_DA");

    let final_reputation = registry.reputation.get(&alice_did_doc.did_uri).copied().unwrap_or(0.0);
    assert!(final_reputation > 0.0, "Provider reputation and emission credited");
}
