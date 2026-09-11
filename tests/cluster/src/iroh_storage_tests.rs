//! Cross-Cluster P2P Iroh Storage, BLAKE3 Bao Verified Streaming, and Proof of Retrievability Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use sovereign_consensus::storage::iroh_store::IrohStorageEngine;
use tempfile::tempdir;

pub struct ClusterIrohNode {
    pub _cluster_name: String,
    pub _chain_id: u32,
    pub storage: IrohStorageEngine,
}

impl ClusterIrohNode {
    pub fn new_in_memory(name: &str, chain_id: u32) -> Self {
        Self {
            _cluster_name: name.to_string(),
            _chain_id: chain_id,
            storage: IrohStorageEngine::new_in_memory(),
        }
    }

    pub fn new_disk(name: &str, chain_id: u32, path: &std::path::Path) -> Self {
        Self {
            _cluster_name: name.to_string(),
            _chain_id: chain_id,
            storage: IrohStorageEngine::open_or_create(path).expect("Failed to open Iroh disk store"),
        }
    }
}

#[test]
fn test_given_cluster_alpha_when_blob_pinned_then_generates_canonical_cid_and_retrieves() {
    // ── GIVEN: Cluster Alpha with an initialized in-memory Iroh storage engine ──
    let alpha = ClusterIrohNode::new_in_memory("Cluster-Alpha", 1337);
    let state_snapshot = b"Canonical State Snapshot: Epoch #100, Root: 0x48a3f910e42d...";

    // ── WHEN: State snapshot blob is stored and pinned ──
    let meta = alpha
        .storage
        .store_blob(1, state_snapshot)
        .expect("Cluster Alpha store failed");

    // ── THEN: Canonical BLAKE3 CID is assigned and data is accurately retrieved ──
    assert!(meta.cid.starts_with("b3:"));
    assert_eq!(meta.size_bytes, state_snapshot.len() as u64);
    assert_eq!(meta.namespace_id, 1);
    assert!(alpha.storage.is_pinned(&meta.cid));

    let retrieved = alpha.storage.get_blob(&meta.cid).expect("Fetch failed");
    assert_eq!(retrieved, state_snapshot);
}

#[test]
fn test_given_two_independent_clusters_when_sync_bundle_transferred_then_replicates_all_cids() {
    // ── GIVEN: Two independent clusters (Alpha and Beta) ──
    let alpha = ClusterIrohNode::new_in_memory("Cluster-Alpha", 1337);
    let beta = ClusterIrohNode::new_in_memory("Cluster-Beta", 4200);

    let doc1 = b"ActivityPub Note: Sovereign Mesh Announcement #1";
    let doc2 = b"CMS Article: Decentralized Storage over BLAKE3 Bao Streams";
    let doc3 = b"Account-Lattice Frontier Cut Epoch #420";

    let meta1 = alpha.storage.store_blob(1, doc1).unwrap();
    let meta2 = alpha.storage.store_blob(2, doc2).unwrap();
    let meta3 = alpha.storage.store_blob(3, doc3).unwrap();

    // ── WHEN: Sync bundle is exported from Alpha and imported into Beta ──
    let sync_bundle = alpha.storage.export_sync_bundle();
    assert_eq!(sync_bundle.len(), 3);

    let imported_count = beta.storage.import_sync_bundle(&sync_bundle).unwrap();

    // ── THEN: Beta has pinned all three documents with exact matching contents ──
    assert_eq!(imported_count, 3);
    assert!(beta.storage.is_pinned(&meta1.cid));
    assert!(beta.storage.is_pinned(&meta2.cid));
    assert!(beta.storage.is_pinned(&meta3.cid));

    assert_eq!(beta.storage.get_blob(&meta1.cid).unwrap(), doc1);
    assert_eq!(beta.storage.get_blob(&meta2.cid).unwrap(), doc2);
    assert_eq!(beta.storage.get_blob(&meta3.cid).unwrap(), doc3);
}

#[test]
fn test_given_stored_multi_chunk_sector_when_challenged_then_produces_verifiable_por_slice() {
    // ── GIVEN: An 8 KiB multi-chunk sector blob pinned on Cluster Alpha ──
    let alpha = ClusterIrohNode::new_in_memory("Cluster-Alpha", 1337);
    let mut sector_payload = Vec::with_capacity(8192);
    for i in 0..8192 {
        sector_payload.push((i % 251) as u8);
    }
    let meta = alpha.storage.store_blob(10, &sector_payload).unwrap();

    // ── WHEN: Cluster Beta challenges Cluster Alpha for byte range [2048..4096] ──
    let proof = alpha
        .storage
        .generate_por_proof(&meta.cid, 2048, 2048)
        .expect("PoR slice generation failed");

    // ── THEN: Proof of Retrievability contains exact slice and verifies against root BLAKE3 hash ──
    assert_eq!(proof.slice_offset, 2048);
    assert_eq!(proof.slice_length, 2048);
    assert_eq!(proof.total_blob_size, 8192);
    assert_eq!(proof.extract_requested_slice(), &sector_payload[2048..4096]);

    let is_valid = IrohStorageEngine::verify_por_proof(&proof).expect("PoR verification failed");
    assert!(is_valid, "Valid PoR slice proof must verify against root BLAKE3 hash");
}

#[test]
fn test_given_tampered_sync_bundle_when_imported_then_byzantine_detection_rejects() {
    // ── GIVEN: Stored data on Cluster Alpha and an exported sync bundle ──
    let alpha = ClusterIrohNode::new_in_memory("Cluster-Alpha", 1337);
    let beta = ClusterIrohNode::new_in_memory("Cluster-Beta", 4200);

    let clean_data = b"Sovereign Trustless Data Payload";
    alpha.storage.store_blob(1, clean_data).unwrap();
    let mut bundle = alpha.storage.export_sync_bundle();
    assert_eq!(bundle.len(), 1);

    // ── WHEN: A Byzantine peer mutates payload bytes in transit ──
    bundle[0].payload[0] ^= 0x01;

    // ── THEN: Cluster Beta detects BLAKE3 checksum mismatch and strictly rejects import ──
    let import_result = beta.storage.import_sync_bundle(&bundle);
    assert!(import_result.is_err(), "Corrupted payload in sync bundle must be rejected");
}

#[test]
fn test_given_persistent_disk_directory_when_rebooted_then_retains_all_pinned_blobs() {
    // ── GIVEN: An isolated disk directory on Cluster Alpha ──
    let dir_alpha = tempdir().expect("Failed to create tempdir");
    let alpha_path = dir_alpha.path();
    let meta_cid;
    let payload = b"Persistent Cluster Alpha State Snapshot across restarts";

    // ── WHEN: Node writes blob to persistent storage and restarts ──
    {
        let alpha = ClusterIrohNode::new_disk("Cluster-Alpha", 1337, alpha_path);
        let meta = alpha.storage.store_blob(100, payload).unwrap();
        meta_cid = meta.cid;
        assert!(alpha.storage.is_pinned(&meta_cid));
    }

    // ── THEN: Upon reboot, all pinned CIDs and exact payload contents remain intact ──
    {
        let alpha_rebooted = ClusterIrohNode::new_disk("Cluster-Alpha", 1337, alpha_path);
        assert!(alpha_rebooted.storage.is_pinned(&meta_cid), "CID must remain pinned after cluster restart");
        let restored_blob = alpha_rebooted.storage.get_blob(&meta_cid).unwrap();
        assert_eq!(restored_blob, payload);
    }
}

#[test]
fn test_given_cross_cluster_did_and_wot_when_ipld_encoded_then_replicated_and_resolved_across_clusters() {
    use sovereign_identity::did::SovereignDidDocument;
    use sovereign_identity::ipld::{IpldCodec, WotThingDescription};

    // ── GIVEN: Two independent clusters (Alpha and Beta) ──
    let alpha = ClusterIrohNode::new_in_memory("Cluster-Alpha", 1337);
    let beta = ClusterIrohNode::new_in_memory("Cluster-Beta", 4200);

    // 1. Cluster Alpha derives a Sovereign DID document and converts to IPLD dag-json block
    let seed = alloy_primitives::B256::repeat_byte(0x42);
    let doc = SovereignDidDocument::derive_from_seed(seed);
    let did_block = doc.to_ipld_block(IpldCodec::DagJson).expect("DID IPLD block conversion failed");
    let did_cid = did_block.cid.clone();

    // 2. Cluster Alpha creates a W3C WoT Thing Description for an autonomous SIL-3 actuator
    let mut td = WotThingDescription::new(&format!("{}#actuator-valve", doc.did_uri), "SIL-3 Cryogenic Relief Valve");
    td.properties.insert(
        "pressure_kpa".to_string(),
        serde_json::json!({ "type": "number", "minimum": 0.0, "maximum": 10000.0, "readOnly": true }),
    );
    td.actions.insert(
        "emergency_isolation".to_string(),
        serde_json::json!({ "description": "Trigger instant isolation", "safe": false }),
    );
    let td_block = td.to_ipld_block().expect("WoT IPLD block conversion failed");
    let td_cid = td_block.cid.clone();

    // ── WHEN: Cluster Alpha stores both IPLD blocks and syncs with Cluster Beta ──
    alpha.storage.store_ipld_block(1, &did_block).unwrap();
    alpha.storage.store_ipld_block(1, &td_block).unwrap();

    let sync_bundle = alpha.storage.export_sync_bundle();
    assert!(sync_bundle.len() >= 2);

    let imported_count = beta.storage.import_sync_bundle(&sync_bundle).unwrap();
    assert!(imported_count >= 2);

    // ── THEN: Cluster Beta resolves and verifies both DID and WoT documents from IPLD blocks ──
    let beta_did_block = beta.storage.get_ipld_block(&did_cid).expect("Beta failed to fetch DID IPLD block");
    assert!(beta_did_block.verify_integrity());

    let resolved_did = SovereignDidDocument::from_ipld_block(&beta_did_block).expect("Beta failed to resolve DID document");
    assert_eq!(resolved_did.evm_address, doc.evm_address);
    assert_eq!(resolved_did.secp256k1_pubkey, doc.secp256k1_pubkey);
    assert_eq!(resolved_did.ed25519_pubkey, doc.ed25519_pubkey);

    let beta_td_block = beta.storage.get_ipld_block(&td_cid).expect("Beta failed to fetch WoT IPLD block");
    assert!(beta_td_block.verify_integrity());

    let resolved_td = WotThingDescription::from_ipld_block(&beta_td_block).expect("Beta failed to resolve WoT Thing Description");
    assert_eq!(resolved_td.id, td.id);
    assert_eq!(resolved_td.title, td.title);
    assert_eq!(resolved_td.properties, td.properties);
    assert_eq!(resolved_td.actions, td.actions);
}
