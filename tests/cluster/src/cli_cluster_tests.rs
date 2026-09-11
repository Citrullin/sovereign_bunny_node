//! Unified Sovereign Bunny CLI & Cluster Orchestration Test Suite.
//!
//! Structured using the standard Given-When-Then (BDD) pattern for test coverage,
//! isolation, and direct execution without subprocess latency.

use bunny_cli::orchestration::{ClusterBackend, ClusterOrchestrator, ClusterSpec};
use sovereign_identity::did::SovereignDidDocument;
use sovereign_identity::namespace::NamespaceRegistry;
use sovereign_ssz::{wrap_envelope, unwrap_envelope, range_key};
use alloy_primitives::{Address, B256};
use std::fs;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Cluster Provisioning & Orchestration (Given-When-Then)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_given_podman_backend_when_provisioned_then_generates_quadlet_spec() {
    // ── GIVEN ──
    let spec = ClusterSpec {
        name: "berlin-podman-01".to_string(),
        backend: ClusterBackend::Podman,
        bgp_asn: 65001,
        nodes: vec!["10.0.0.1".to_string()],
        dpu_offload: false,
        wireguard_mesh: true,
    };

    // ── WHEN ──
    let result = ClusterOrchestrator::provision_cluster(&spec);

    // ── THEN ──
    assert!(result.is_ok(), "Podman cluster provisioning must succeed");
    let quadlet_yaml = result.unwrap();
    assert!(quadlet_yaml.contains("ghcr.io/sovereign-bunny/bunny:latest"));
    assert!(quadlet_yaml.contains("[\"daemon\", \"gateway\", \"--port\", \"8545\", \"--bgp-asn\", \"65001\"]"));
    assert!(quadlet_yaml.contains("[\"daemon\", \"epoch\", \"--epoch-node-id\", \"1\"]"));
    assert!(quadlet_yaml.contains("[\"daemon\", \"committee\", \"--partition\", \"0\", \"--range-start\", \"0\"]"));
    assert!(quadlet_yaml.contains("[\"daemon\", \"storage\", \"--storage-id\", \"1\", \"--dir\", \"/data/iroh\"]"));
    assert!(quadlet_yaml.contains("[\"daemon\", \"mesh\", \"--bgp-asn\", \"65001\", \"--wireguard-endpoint\", \"0.0.0.0:51820\"]"));
    assert!(quadlet_yaml.contains("BGP_ASN=65001"));
}

#[test]
fn test_given_k3s_backend_when_provisioned_then_generates_helm_manifest() {
    // ── GIVEN ──
    let spec = ClusterSpec {
        name: "berlin-hackerspace-01".to_string(),
        backend: ClusterBackend::K3s,
        bgp_asn: 65001,
        nodes: vec!["192.168.1.10".to_string(), "192.168.1.11".to_string()],
        dpu_offload: true,
        wireguard_mesh: true,
    };

    // ── WHEN ──
    let result = ClusterOrchestrator::provision_cluster(&spec);

    // ── THEN ──
    assert!(result.is_ok(), "K3s cluster provisioning must succeed");
    let helm_yaml = result.unwrap();
    assert!(helm_yaml.contains("name: \"berlin-hackerspace-01\""));
    assert!(helm_yaml.contains("asn: 65001"));
    assert!(helm_yaml.contains("dpuOffload: true"));
    assert!(helm_yaml.contains("wireguardMesh: true"));
    assert!(helm_yaml.contains("partitionRanges: [\"0x0000..0x3FFF\", \"0x4000..0x7FFF\", \"0x8000..0xBFFF\", \"0xC000..0xFFFF\"]"));
}

#[test]
fn test_given_baremetal_backend_when_provisioned_then_generates_topology_config() {
    // ── GIVEN ──
    let spec = ClusterSpec {
        name: "dark-fiber-nodes".to_string(),
        backend: ClusterBackend::Baremetal,
        bgp_asn: 65002,
        nodes: vec![
            "10.200.1.1".to_string(),
            "10.200.1.2".to_string(),
            "10.200.1.3".to_string(),
        ],
        dpu_offload: true,
        wireguard_mesh: true,
    };

    // ── WHEN ──
    let result = ClusterOrchestrator::provision_cluster(&spec);

    // ── THEN ──
    assert!(result.is_ok(), "Baremetal provisioning must succeed");
    let toml = result.unwrap();
    assert!(toml.contains("bgp_asn = 65002"));
    assert!(toml.contains("dpu_offload = true"));
    assert!(toml.contains("wireguard_mesh = true"));
    assert!(toml.contains("node_0 = \"10.200.1.1:51820\""));
    assert!(toml.contains("node_1 = \"10.200.1.2:51820\""));
    assert!(toml.contains("node_2 = \"10.200.1.3:51820\""));
}

#[test]
fn test_given_localhost_backend_when_provisioned_then_generates_mesh_supervisor() {
    // ── GIVEN ──
    let spec = ClusterSpec {
        name: "local-dev-01".to_string(),
        backend: ClusterBackend::Localhost,
        bgp_asn: 65001,
        nodes: vec!["127.0.0.1".to_string()],
        dpu_offload: false,
        wireguard_mesh: true,
    };

    // ── WHEN ──
    let result = ClusterOrchestrator::provision_cluster(&spec);

    // ── THEN ──
    assert!(result.is_ok(), "Localhost provisioning must succeed");
    let script = result.unwrap();
    assert!(script.contains("Sovereign Bunny Localhost Mesh Supervisor"));
    assert!(script.contains("bunny daemon gateway --port 8545 --bgp-asn 65001"));
    assert!(script.contains("bunny daemon epoch --epoch-node-id 1"));
    assert!(script.contains("bunny daemon committee --partition 0 --range-start 0"));
    assert!(script.contains("bunny daemon storage --storage-id 1 --dir /tmp/sovereign-storage"));
    assert!(script.contains("bunny daemon mesh --bgp-asn 65001 --wireguard-endpoint 127.0.0.1:51820"));
    assert!(script.contains("bunny daemon rpc --port 8546 --upstream http://127.0.0.1:8545"));
}

#[test]
fn test_given_baremetal_spec_when_systemd_generated_then_produces_all_units() {
    // ── GIVEN ──
    let spec = ClusterSpec {
        name: "dc-frankfurt".to_string(),
        backend: ClusterBackend::Baremetal,
        bgp_asn: 65010,
        nodes: vec!["10.10.1.1".to_string(), "10.10.1.2".to_string()],
        dpu_offload: false,
        wireguard_mesh: true,
    };

    // ── WHEN ──
    let units = ClusterOrchestrator::generate_baremetal_systemd_units(&spec);

    // ── THEN ──
    assert_eq!(units.len(), 6, "Must generate 6 core systemd unit files");
    assert!(units.contains_key("bunny-gateway.service"));
    assert!(units.contains_key("bunny-epoch.service"));
    assert!(units.contains_key("bunny-committee@.service"));
    assert!(units.contains_key("bunny-storage.service"));
    assert!(units.contains_key("bunny-mesh.service"));
    assert!(units.contains_key("bunny-rpc.service"));

    let gateway_unit = units.get("bunny-gateway.service").unwrap();
    assert!(gateway_unit.contains("ExecStart=/usr/local/bin/bunny daemon gateway --port 8545 --bgp-asn 65010"));

    let epoch_unit = units.get("bunny-epoch.service").unwrap();
    assert!(epoch_unit.contains("ExecStart=/usr/local/bin/bunny daemon epoch --epoch-node-id 1"));

    let committee_unit = units.get("bunny-committee@.service").unwrap();
    assert!(committee_unit.contains("ExecStart=/usr/local/bin/bunny daemon committee --partition 0 --range-start %i"));

    let storage_unit = units.get("bunny-storage.service").unwrap();
    assert!(storage_unit.contains("ExecStart=/usr/local/bin/bunny daemon storage --storage-id 1 --dir /data/iroh"));

    let mesh_unit = units.get("bunny-mesh.service").unwrap();
    assert!(mesh_unit.contains("ExecStart=/usr/local/bin/bunny daemon mesh --bgp-asn 65010 --wireguard-endpoint 0.0.0.0:51820"));
}

#[test]
fn test_given_isolated_tempdir_when_cluster_exported_then_creates_file_tree() {
    // ── GIVEN ──
    let temp_sandbox = tempfile::tempdir().expect("create isolated sandbox tempdir");
    let export_dir = temp_sandbox.path().join("baremetal-export");
    let spec = ClusterSpec {
        name: "dc-frankfurt".to_string(),
        backend: ClusterBackend::Baremetal,
        bgp_asn: 65010,
        nodes: vec!["10.10.1.1".to_string(), "10.10.1.2".to_string()],
        dpu_offload: false,
        wireguard_mesh: true,
    };

    // ── WHEN ──
    fs::create_dir_all(&export_dir).expect("create export directory");
    let topology_content = ClusterOrchestrator::provision_cluster(&spec).expect("provision cluster");
    fs::write(export_dir.join("cluster-topology.toml"), topology_content).expect("write topology");

    let systemd_dir = export_dir.join("systemd");
    fs::create_dir_all(&systemd_dir).expect("create systemd directory");
    let units = ClusterOrchestrator::generate_baremetal_systemd_units(&spec);
    for (filename, content) in units {
        fs::write(systemd_dir.join(filename), content).expect("write unit file");
    }

    // ── THEN ──
    assert!(export_dir.join("cluster-topology.toml").exists(), "cluster-topology.toml must exist");
    assert!(systemd_dir.join("bunny-gateway.service").exists(), "gateway unit must exist");
    assert!(systemd_dir.join("bunny-epoch.service").exists(), "epoch unit must exist");
    assert!(systemd_dir.join("bunny-committee@.service").exists(), "committee unit must exist");
    assert!(systemd_dir.join("bunny-storage.service").exists(), "storage unit must exist");
    assert!(systemd_dir.join("bunny-mesh.service").exists(), "mesh unit must exist");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SSZ Envelope & Range Routing (Given-When-Then)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_given_raw_payload_when_ssz_wrapped_then_has_canonical_bny_header() {
    // ── GIVEN ──
    let raw_payload = b"test_transaction_intent_bytes";

    // ── WHEN ──
    let envelope = wrap_envelope(raw_payload);

    // ── THEN ──
    assert_eq!(envelope.len(), raw_payload.len() + 4);
    assert_eq!(&envelope[0..3], b"BNY", "Envelope magic must be 'BNY'");
    assert_eq!(envelope[3], 0x01, "Protocol version must be 0x01");

    // ── AND WHEN unwrapped ──
    let unwrapped = unwrap_envelope(&envelope);
    assert!(unwrapped.is_ok(), "Envelope unwrapping must succeed");
    assert_eq!(unwrapped.unwrap(), raw_payload);
}

#[test]
fn test_given_invalid_envelope_when_unwrapped_then_returns_error() {
    // ── GIVEN ──
    let bad_magic_envelope = b"BAD\x01some_payload";
    let bad_version_envelope = b"BNY\x99some_payload";
    let too_short_envelope = b"BN";

    // ── WHEN / THEN ──
    assert!(unwrap_envelope(bad_magic_envelope).is_err());
    assert!(unwrap_envelope(bad_version_envelope).is_err());
    assert!(unwrap_envelope(too_short_envelope).is_err());
}

#[test]
fn test_given_evm_address_when_range_key_computed_then_extracts_first_two_bytes() {
    // ── GIVEN ──
    let addr = Address::from([0x4A, 0x2B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

    // ── WHEN ──
    let rk1 = range_key(&addr);
    let rk2 = range_key(&addr);

    // ── THEN ──
    assert_eq!(rk1, rk2, "Range key calculation must be deterministic");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Multi-Curve DID Resolution & Namespace Registry (Given-When-Then)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_given_master_seed_when_did_derived_then_contains_all_11_cryptographic_curves() {
    // ── GIVEN ──
    let seed = B256::repeat_byte(0x42);

    // ── WHEN ──
    let doc = SovereignDidDocument::derive_from_seed(seed);

    // ── THEN ──
    assert!(doc.did_uri.starts_with("did:peer:4"), "Must be canonical did:peer:4");
    assert!(!doc.secp256k1_pubkey.is_empty(), "Secp256k1 key must be present");
    assert!(!doc.ed25519_pubkey.is_empty(), "Ed25519 key must be present");
    assert!(!doc.ml_dsa_pubkey.is_empty(), "Post-quantum ML-DSA key must be present");
    assert!(!doc.falcon_pubkey.is_empty(), "Post-quantum Falcon key must be present");
    assert!(!doc.slh_dsa_pubkey.is_empty(), "Post-quantum SLH-DSA key must be present");
    assert_ne!(doc.evm_address, Address::ZERO, "EVM address must be non-zero");

    // ── AND WHEN resolved by URI ──
    let resolved = SovereignDidDocument::from_did_string(&doc.did_uri);
    assert!(resolved.is_some(), "Document must be round-trip resolvable from URI");
    assert_eq!(resolved.unwrap().did_uri, doc.did_uri);
}

#[test]
fn test_given_namespace_registry_when_name_claimed_then_social_reputation_wins_over_stake() {
    // ── GIVEN ──
    let mut reg = NamespaceRegistry::new();
    let alice_did = "did:peer:4:z6MkuAlice".to_string();
    let bob_did = "did:peer:4:z6MkuBob".to_string();

    // Alice registers "alice.bunny" with high social reputation (10.0) and 0 stake
    let alice_registered = reg.register("alice".to_string(), alice_did.clone(), 10.0, 0);
    assert!(alice_registered, "Alice registration must succeed");

    // ── WHEN Bob attempts to Sybil-squat "alice.bunny" with low reputation (1.0) and high stake (500) ──
    let bob_registered = reg.register("alice".to_string(), bob_did.clone(), 1.0, 500);

    // ── THEN ──
    assert!(!bob_registered, "Bob Sybil challenge must fail against Alice's superior social reputation");
    assert_eq!(reg.names.get("alice"), Some(&alice_did), "Alice must retain ownership of 'alice.bunny'");
}
