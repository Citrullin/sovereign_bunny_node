//! # Anti-Sybil Defense Test Suite
//!
//! Validates the 4 cryptographic and physical anti-sybil defenses:
//! 1. Speed-of-Light RTT Multilateration & Vivaldi Network Coordinates.
//! 2. BGP Autonomous System (ASN) Topology Diversity Quotas.
//! 3. Silicon Enclave Unique Hardware Attestations (DCAP / TEE Binding).
//! 4. Quadratic Anti-Correlation Slashing Penalties.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic validation.

use alloy_primitives::{Address, B256, U256};
use sovereign_consensus::governance::anti_sybil::{
    AntiSybilEngine, NodeTopologyDescriptor, VivaldiCoordinate,
};

#[test]
fn test_given_candidate_committee_when_single_asn_dominates_then_bgp_quota_strictly_rejects() {
    // ── GIVEN: Anti-Sybil Engine configured with 20% max ASN quota ──
    let mut engine = AntiSybilEngine::new();

    let node1 = Address::repeat_byte(0x01);
    let node2 = Address::repeat_byte(0x02);
    let node3 = Address::repeat_byte(0x03);
    let node4 = Address::repeat_byte(0x04);
    let node5 = Address::repeat_byte(0x05);

    // Node 1, 2, 3 all belong to AWS ASN 16509 (60% concentration)
    engine.register_validator(NodeTopologyDescriptor {
        validator: node1,
        bgp_asn: 16509,
        ip_prefix: "3.220.0.0/16".to_string(),
        coordinate: VivaldiCoordinate { x: 10.0, y: 20.0, z: 0.0, height: 5.0, error: 0.1 },
        hardware_ppid: B256::repeat_byte(0x11),
    }).unwrap();

    engine.register_validator(NodeTopologyDescriptor {
        validator: node2,
        bgp_asn: 16509,
        ip_prefix: "3.221.0.0/16".to_string(),
        coordinate: VivaldiCoordinate { x: 12.0, y: 22.0, z: 0.0, height: 5.0, error: 0.1 },
        hardware_ppid: B256::repeat_byte(0x22),
    }).unwrap();

    engine.register_validator(NodeTopologyDescriptor {
        validator: node3,
        bgp_asn: 16509,
        ip_prefix: "3.222.0.0/16".to_string(),
        coordinate: VivaldiCoordinate { x: 15.0, y: 25.0, z: 0.0, height: 5.0, error: 0.1 },
        hardware_ppid: B256::repeat_byte(0x33),
    }).unwrap();

    // Node 4 is Hetzner ASN 24940, Node 5 is Residential ISP ASN 7922
    engine.register_validator(NodeTopologyDescriptor {
        validator: node4,
        bgp_asn: 24940,
        ip_prefix: "168.119.0.0/16".to_string(),
        coordinate: VivaldiCoordinate { x: 80.0, y: 90.0, z: 0.0, height: 15.0, error: 0.1 },
        hardware_ppid: B256::repeat_byte(0x44),
    }).unwrap();

    engine.register_validator(NodeTopologyDescriptor {
        validator: node5,
        bgp_asn: 7922,
        ip_prefix: "73.189.0.0/16".to_string(),
        coordinate: VivaldiCoordinate { x: -50.0, y: -60.0, z: 0.0, height: 25.0, error: 0.1 },
        hardware_ppid: B256::repeat_byte(0x55),
    }).unwrap();

    // ── WHEN: A 5-node sub-committee is formed with 3 AWS nodes (60% > 20% cap) ──
    let invalid_committee = vec![node1, node2, node3, node4, node5];
    let quota_res = engine.verify_committee_asn_diversity(&invalid_committee);

    // ── THEN: BGP ASN quota rejects the committee as centralized ──
    assert!(quota_res.is_err());
    assert_eq!(
        quota_res.unwrap_err(),
        "BGP ASN concentration quota exceeded: Single cloud provider dominates > 20% of sub-committee"
    );

    // ── AND WHEN: A diverse 5-node committee is formed with unique ASNs ──
    let node6 = Address::repeat_byte(0x06);
    let node7 = Address::repeat_byte(0x07);
    engine.register_validator(NodeTopologyDescriptor {
        validator: node6,
        bgp_asn: 13335, // Cloudflare
        ip_prefix: "104.16.0.0/12".to_string(),
        coordinate: VivaldiCoordinate { x: 30.0, y: -40.0, z: 0.0, height: 10.0, error: 0.1 },
        hardware_ppid: B256::repeat_byte(0x66),
    }).unwrap();
    engine.register_validator(NodeTopologyDescriptor {
        validator: node7,
        bgp_asn: 15169, // Google Fiber
        ip_prefix: "8.8.8.0/24".to_string(),
        coordinate: VivaldiCoordinate { x: -80.0, y: 30.0, z: 0.0, height: 12.0, error: 0.1 },
        hardware_ppid: B256::repeat_byte(0x77),
    }).unwrap();

    let valid_committee = vec![node1, node4, node5, node6, node7];
    assert!(engine.verify_committee_asn_diversity(&valid_committee).is_ok());
}

#[test]
fn test_given_colocated_vpc_nodes_when_rtt_dispersion_checked_then_detects_artificial_latency() {
    // ── GIVEN: Anti-Sybil Engine ──
    let mut engine = AntiSybilEngine::new();

    let node_berlin = Address::repeat_byte(0x10);
    let node_fake_tokyo = Address::repeat_byte(0x20);

    // Both nodes claim to be far apart, but their coordinates are nearly identical (intra-rack 0.1ms)
    engine.register_validator(NodeTopologyDescriptor {
        validator: node_berlin,
        bgp_asn: 24940,
        ip_prefix: "10.0.0.1/32".to_string(),
        coordinate: VivaldiCoordinate { x: 0.0, y: 0.0, z: 0.0, height: 0.1, error: 0.01 },
        hardware_ppid: B256::repeat_byte(0xa1),
    }).unwrap();

    engine.register_validator(NodeTopologyDescriptor {
        validator: node_fake_tokyo,
        bgp_asn: 24940,
        ip_prefix: "10.0.0.2/32".to_string(),
        coordinate: VivaldiCoordinate { x: 0.05, y: 0.05, z: 0.0, height: 0.1, error: 0.01 },
        hardware_ppid: B256::repeat_byte(0xa2),
    }).unwrap();

    // ── WHEN: RTT dispersion is verified across the co-located pair ──
    let rtt_res = engine.verify_committee_rtt_dispersion(&[node_berlin, node_fake_tokyo]);

    // ── THEN: Artificial sub-millisecond dispersion is detected and rejected ──
    assert!(rtt_res.is_err());
    assert_eq!(
        rtt_res.unwrap_err(),
        "Co-location detected: Sub-committee members exhibit artificial sub-millisecond dispersion (co-located VPC/rack)"
    );
}

#[test]
fn test_given_duplicate_physical_cpu_when_registered_then_unique_silicon_attestation_rejects() {
    // ── GIVEN: Anti-Sybil Engine with an existing validator on physical silicon PPID 0xCAFE ──
    let mut engine = AntiSybilEngine::new();
    let ppid_chip = B256::repeat_byte(0xfe);

    let validator_a = Address::repeat_byte(0xaa);
    let validator_b = Address::repeat_byte(0xbb);

    let reg_a = engine.register_validator(NodeTopologyDescriptor {
        validator: validator_a,
        bgp_asn: 16509,
        ip_prefix: "1.1.1.1/32".to_string(),
        coordinate: VivaldiCoordinate::default(),
        hardware_ppid: ppid_chip,
    });
    assert!(reg_a.is_ok());

    // ── WHEN: An operator tries to register a second validator on the same physical CPU ──
    let reg_b = engine.register_validator(NodeTopologyDescriptor {
        validator: validator_b,
        bgp_asn: 16509,
        ip_prefix: "1.1.1.2/32".to_string(),
        coordinate: VivaldiCoordinate::default(),
        hardware_ppid: ppid_chip,
    });

    // ── THEN: Registration is strictly rejected preventing CPU virtualization Sybil attacks ──
    assert!(reg_b.is_err());
    assert_eq!(
        reg_b.unwrap_err(),
        "Sybil detected: Physical silicon chip (PPID) already registered to another validator"
    );
}

#[test]
fn test_given_varying_outage_scales_when_anti_correlation_slashing_evaluated_then_applies_quadratic_penalty() {
    let staked_stake = U256::from(100_000_000_000_000_000_000u128); // 100 ETH stake
    let total_validators = 100;

    // ── GIVEN: 1 isolated node fails (home-lab power outage, 1/100) ──
    let slash_single = AntiSybilEngine::calculate_anti_correlation_slashing_penalty(1, total_validators, staked_stake);
    // (1/100)^2 = 0.0001 = 0.01%
    assert_eq!(slash_single, U256::from(10_000_000_000_000_000u128)); // 0.01 ETH

    // ── WHEN: 40 nodes fail simultaneously (AWS us-east-1 datacenter outage, 40/100) ──
    let slash_cloud = AntiSybilEngine::calculate_anti_correlation_slashing_penalty(40, total_validators, staked_stake);
    // (40/100)^2 = 0.16 = 16.0%
    assert_eq!(slash_cloud, U256::from(16_000_000_000_000_000_000u128)); // 16.0 ETH

    // ── THEN: 100 nodes fail simultaneously (100% mass outage) ──
    let slash_mass = AntiSybilEngine::calculate_anti_correlation_slashing_penalty(100, total_validators, staked_stake);
    // (100/100)^2 = 1.0 = 100%
    assert_eq!(slash_mass, staked_stake); // 100.0 ETH (full wipeout)
}
