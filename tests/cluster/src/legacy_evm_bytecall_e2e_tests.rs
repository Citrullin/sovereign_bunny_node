//! # Legacy EVM Wallet Raw Bytecalls & Range-Sharded Embedded Daemons End-to-End Tests
//!
//! Verifies that standard legacy EVM wallets (MetaMask / Rabby / ethers.js) sending raw
//! calldata bytecalls to Sovereign system precompiles (`0x03`, `0x05`, `0x53`, `0x54`, `0xF1`)
//! execute statelessly through the precompile router and replicate across range-sharded embedded daemons.

use alloy_primitives::{Address, B256};
use bunny_cli::embedded_node::{EmbeddedDesktopConfig, EmbeddedDesktopNode};
use sovereign_consensus::registry::ValidatorRegistry;
use sovereign_consensus::system_contracts::router::execute_system_action;
use sovereign_consensus::system_registry::{
    SYSTEM_CMS, SYSTEM_DID_REGISTRY, SYSTEM_JURISDICTION, SYSTEM_SIGNAL_REGISTRY,
    SYSTEM_STORAGE_DA, SystemAction,
};
use sovereign_identity::did::SovereignDidDocument;
use sovereign_ssz::activitypub::ActivityType;

#[tokio::test]
async fn test_given_legacy_evm_wallet_when_raw_bytecalls_executed_then_system_state_updates_and_filters_by_range() {
    // ─────────────────────────────────────────────────────────────────────────
    // 1. Initialize Registry & Range-Sharded Embedded Desktop Node
    // ─────────────────────────────────────────────────────────────────────────
    let mut registry = ValidatorRegistry::default();
    let seed = B256::repeat_byte(0x42);
    let user_did_doc = SovereignDidDocument::derive_from_seed(seed);
    let user_address = user_did_doc.evm_address;

    let config = EmbeddedDesktopConfig::default();
    let embedded_node = EmbeddedDesktopNode::spawn(config, seed).await;

    // Verify embedded node's primary range prefix
    let user_prefix = u16::from_be_bytes([user_address[0], user_address[1]]);
    assert!(embedded_node.is_account_relevant(&user_address));

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Legacy EVM Bytecall: Register DID on Chain (SYSTEM_DID_REGISTRY 0x03)
    // ─────────────────────────────────────────────────────────────────────────
    let reg_action = SystemAction::RegisterDid {
        did_document: user_did_doc.to_w3c_json_ld().to_string(),
        pq_pub_key: vec![0x42; 32],
        key_tier: "QuantumReady".to_string(),
    };
    let did_calldata = reg_action.encode();

    // Execute via standard EVM raw bytecall (to: 0x00...03, data: did_calldata)
    let did_res = execute_system_action(&mut registry, user_address, SYSTEM_DID_REGISTRY, &did_calldata, 1);
    assert!(did_res.is_ok(), "Raw bytecall to SYSTEM_DID_REGISTRY (0x03) succeeded");

    // Also verify execution directly inside the embedded node
    let embedded_did_res = embedded_node.execute_legacy_raw_bytecall(SYSTEM_DID_REGISTRY, &did_calldata, user_address);
    assert!(embedded_did_res.is_ok(), "Embedded node executed raw DID bytecall in local RAM");

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Legacy EVM Bytecall: Set Jurisdiction Compliance (SYSTEM_JURISDICTION 0x05)
    // ─────────────────────────────────────────────────────────────────────────
    let decision = sovereign_consensus::jurisdiction::JurisdictionDecision {
        manifold_id: 13371337,
        action: sovereign_consensus::jurisdiction::JurisdictionAction::SetQuadrantBits {
            target: user_address,
            quadrant: 2,
            bits: 0b00000001,
        },
        proposed_by: user_address,
        epoch: 1,
    };
    let decision_bytes = serde_json::to_vec(&decision).unwrap();
    let juris_action = SystemAction::JurisdictionUpdate {
        decision_bytes,
    };
    let juris_calldata = juris_action.encode();
    let juris_res = execute_system_action(&mut registry, user_address, SYSTEM_JURISDICTION, &juris_calldata, 1);
    assert!(juris_res.is_ok(), "Raw bytecall to SYSTEM_JURISDICTION (0x05) succeeded");

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Legacy EVM Bytecall: Address Interest Signaling (SYSTEM_SIGNAL_REGISTRY 0x54)
    // ─────────────────────────────────────────────────────────────────────────
    let target_monitored = Address::repeat_byte(0x88);
    let app_ctx = b"dao.governance.proposals";
    let topic_id = embedded_node.subscribe_interest_topic(&target_monitored, app_ctx);
    let cuckoo_root = B256::repeat_byte(0x55);

    let signal_action = SystemAction::SignalInterest {
        topic_id,
        target_address: target_monitored,
        cuckoo_digest: cuckoo_root,
        expiry_epoch: 1000,
    };
    let signal_calldata = signal_action.encode();
    let signal_res = execute_system_action(&mut registry, user_address, SYSTEM_SIGNAL_REGISTRY, &signal_calldata, 1);
    assert!(signal_res.is_ok(), "Raw bytecall to SYSTEM_SIGNAL_REGISTRY (0x54) succeeded");

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Legacy EVM Bytecall: Publish ActivityPub Note (SYSTEM_CMS 0xF1)
    // ─────────────────────────────────────────────────────────────────────────
    let media_cid = B256::repeat_byte(0x66);
    let initial_frontier = registry.get_or_create_frontier(user_address);
    let initial_seq = initial_frontier.sequence;

    let cms_action = SystemAction::PublishActivityPub {
        actor: user_address,
        activity_type: ActivityType::Create as u8,
        object_cid: media_cid,
        recipient: Address::repeat_byte(0x99),
        micro_payment: 10_000,
        merit_proof_root: B256::repeat_byte(0x77),
    };
    let cms_calldata = cms_action.encode();
    let cms_res = execute_system_action(&mut registry, user_address, SYSTEM_CMS, &cms_calldata, 1);
    assert!(cms_res.is_ok(), "Raw bytecall to SYSTEM_CMS (0xF1) succeeded");

    let updated_frontier = registry.get_or_create_frontier(user_address);
    assert_eq!(updated_frontier.sequence, initial_seq + 1, "Account-Lattice sequence advanced via raw bytecall");
    assert_eq!(updated_frontier.latest_hash, media_cid, "Frontier points to object CID");

    // ─────────────────────────────────────────────────────────────────────────
    // 6. Legacy EVM Bytecall: Claim Storage Merit Yield (SYSTEM_STORAGE_DA 0x53)
    // ─────────────────────────────────────────────────────────────────────────
    let claim_action = SystemAction::ClaimStorageMerit {
        provider_did: user_did_doc.did_uri.clone(),
        bao_slice_proof: vec![0x11, 0x22, 0x33, 0x44],
        epoch_id: 1,
    };
    let claim_calldata = claim_action.encode();
    let claim_res = execute_system_action(&mut registry, user_address, SYSTEM_STORAGE_DA, &claim_calldata, 1);
    assert!(claim_res.is_ok(), "Raw bytecall to SYSTEM_STORAGE_DA (0x53) succeeded");

    // ─────────────────────────────────────────────────────────────────────────
    // 7. Range-Sharded Embedded Daemon Verification
    // ─────────────────────────────────────────────────────────────────────────
    // An account matching the user's primary range prefix is processed
    let matching_account = Address::from_slice(&[
        (user_prefix >> 8) as u8,
        (user_prefix & 0xFF) as u8,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
    ]);
    assert!(embedded_node.is_account_relevant(&matching_account), "Matching range shard accepted");

    // An unmonitored range prefix is filtered out to save RAM and bandwidth
    let non_matching_account = Address::repeat_byte(0xEE);
    assert!(!embedded_node.is_account_relevant(&non_matching_account), "Foreign range shard filtered out");

    // Tauri status check
    let tauri_status = embedded_node.get_tauri_status();
    assert_eq!(tauri_status["is_running"], true);
    assert_eq!(tauri_status["monitored_ranges_count"], 1);
    assert_eq!(tauri_status["subscribed_topics_count"], 1);

    embedded_node.stop();
}
