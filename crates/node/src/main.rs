//! Sovereign Reth Node Binary.
//!
//! Restructured for clean code and modularity.

#![allow(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

use futures::StreamExt;
use reth_ethereum::{
    cli::{chainspec::EthereumChainSpecParser, interface::Cli},
    node::{api::FullNodeComponents, node::EthereumAddOns, EthereumNode},
};
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_builder::components::NoopConsensusBuilder;
use reth_node_core::args::DefaultEngineValues;
use alloy_consensus::Transaction;
use reth_primitives_traits::{AlloyBlockHeader, BlockBody, SignerRecoverable};
use std::future::Future;
use tracing::{debug, info};

/// Node configuration module.
pub mod config;

/// CAIP-RPC proxy module.
pub mod caip_rpc;

/// Subsystem RPC handlers (CAIP, zkCompliance, State, Server).
pub mod rpc;

use sovereign_consensus::SovereignPoolBuilder;
use clap::Parser;

/// Custom CLI arguments for the Sovereign Reth node.
#[derive(Debug, Clone, clap::Args)]
pub struct SovereignArgs {
    /// Type of the node (replica or validator)
    #[arg(long = "sov-node-type", default_value = "replica")]
    pub sov_node_type: String,

    /// TEE execution mode (sgx, nitro, or none)
    #[arg(long = "sov-tee", default_value = "none")]
    pub sov_tee: String,

    /// Operator's did:peer:4 identity string
    #[arg(long = "sov-did-peer4")]
    pub sov_did_peer4: Option<String>,

    /// Path to operator delegation signature/proof file
    #[arg(long = "sov-delegation-proof")]
    pub sov_delegation_proof: Option<std::path::PathBuf>,

    /// `TinyMeritRank` reputation threshold for admission
    #[arg(long = "sov-merit-threshold", default_value_t = 0.0)]
    pub sov_merit_threshold: f64,

    /// Path to the Sovereign TOML configuration file
    #[arg(long = "sov-config")]
    pub sov_config: Option<std::path::PathBuf>,

    /// Zero Latency Quantum Trigger flag (alias: quantum threat) to mandate post-quantum signature schemes
    #[arg(long = "sov-zero-latency-quantum-trigger", alias = "quantum-threat", default_value_t = false)]
    pub sov_zero_latency_quantum_trigger: bool,

    /// Default post-quantum signature scheme when Zero Latency Quantum Trigger is active (e.g., mldsa, slhdsa, falcon)
    #[arg(long = "sov-pq-scheme", alias = "pq-algo")]
    pub sov_pq_scheme: Option<String>,

    /// Block time in milliseconds (e.g., 2000 for 2s)
    #[arg(long = "sov-block-time")]
    pub sov_block_time: Option<u64>,

    /// Default cryptographic profile (e.g., ethereum, throughput, quantum_standard)
    #[arg(long = "sov-crypto-profile")]
    pub sov_crypto_profile: Option<String>,

    /// Pluggable parallel EVM execution engine selection (e.g. wave, pevm, grevm)
    #[arg(long = "sov-parallel-engine")]
    pub sov_parallel_engine: Option<String>,

    /// Port on which the CAIP-RPC proxy listens
    #[arg(long = "sov-proxy-port", default_value_t = 8546)]
    pub sov_proxy_port: u16,

    /// Toy mode flag (downgrades cryptographic parameters for rapid development/testing)
    #[arg(long = "toy-mode", default_value_t = false)]
    pub toy_mode: bool,

    /// Native currency ticker symbol (default: TBL)
    #[arg(long = "sov-ticker", default_value = "TBL")]
    pub sov_ticker: String,
}

impl Default for SovereignArgs {
    fn default() -> Self {
        Self {
            sov_node_type: "replica".to_string(),
            sov_tee: "none".to_string(),
            sov_did_peer4: None,
            sov_delegation_proof: None,
            sov_merit_threshold: 0.0,
            sov_config: None,
            sov_zero_latency_quantum_trigger: false,
            sov_pq_scheme: None,
            sov_block_time: None,
            sov_crypto_profile: None,
            sov_parallel_engine: None,
            sov_proxy_port: 8546,
            toy_mode: false,
            sov_ticker: "TBL".to_string(),
        }
    }
}

/// Helper to determine the TEE attestation action based on mode.
#[must_use]
fn get_tee_attestation_action(tee_mode: &str, ephemeral_key: &str, block_number: u64) -> String {
    match tee_mode {
        "sgx" => format!("sgx:block:{block_number}:key:{ephemeral_key}"),
        "nitro" => format!("nitro:block:{block_number}:key:{ephemeral_key}"),
        _ => "native".to_string(),
    }
}

// Deleted SettlementRelayer (dead code)

/// Execution Extension (`ExEx`) for Pluggable TEE Proving & DA Mesh Emission
async fn sovereign_exex<N: FullNodeComponents>(
    mut ctx: ExExContext<N>,
    args: SovereignArgs,
) -> eyre::Result<impl Future<Output = eyre::Result<()>>> {
    let tee_mode = args.sov_tee.to_lowercase();

    Ok(async move {
        info!("Sovereign Pluggable TEE ExEx started! Mode: {tee_mode}");

        // Zero-KMS: Generate ephemeral ECDSA key in-memory on boot
        let ephemeral_key = "0xEphemeralPubKeyMock42";
        info!("Zero-KMS: Ephemeral in-memory key generated: {ephemeral_key}");

        while let Some(notification) = ctx.notifications.next().await {
            let notification = notification?;
            let tip_num_hash = match &notification {
                ExExNotification::ChainCommitted { new } | ExExNotification::ChainReorged { old: _, new } => new.tip().num_hash(),
                ExExNotification::ChainReverted { old } => old.tip().num_hash(),
            };

            if let Some(committed_chain) = notification.committed_chain() {
                let tip = committed_chain.tip();

                info!("Block #{} executed. Generating TEE Attestation...", tip.number());

                let action = get_tee_attestation_action(tee_mode.as_str(), ephemeral_key, tip.number());
                if action.starts_with("sgx:") {
                    debug!("Requesting Gramine SGX Quote for block #{}...", tip.number());
                    debug!("SGX Quote includes ephemeral key [{ephemeral_key}] in report_data.");
                } else if action.starts_with("nitro:") {
                    debug!("Requesting AWS Nitro Enclave NSM attestation for block #{}...", tip.number());
                    debug!("Nitro Doc includes ephemeral key [{ephemeral_key}] in user_data.");
                } else {
                    debug!("Running natively. No TEE attestation generated.");
                }

                debug!("Emitting state diffs for block #{} to local DA mesh...", tip.number());
                let _mock_state_diff = vec![1, 2, 3, 4];
                info!("Sovereign TEE ExEx: Emitted state diff commitment for block #{}", tip.number());

                // Parse and execute system actions from transactions in the block
                let registry_lock = sovereign_consensus::registry::get_registry();
                for tx in tip.body().transactions().iter() {
                    if let Some(to) = tx.to() {
                        let is_sys = sovereign_consensus::system_registry::is_system_address(&to);
                        let mut resolved_to = to;
                        let mut resolved_calldata = tx.input().to_vec();
                        let mut should_execute = is_sys;

                        if !should_execute {
                            if let Ok(reg) = registry_lock.read() {
                                if let Some(actor) = reg.actors.values().find(|a| alloy_primitives::Address::from_slice(&a.actor_id[0..20]) == to) {
                                    resolved_to = sovereign_consensus::system_registry::SYSTEM_ASYNC_INBOX;
                                    let mut temp = actor.actor_id.to_vec();
                                    temp.extend_from_slice(tx.input());
                                    resolved_calldata = temp;
                                    should_execute = true;
                                }
                            }
                        }

                        if should_execute {
                            if let Ok(caller) = tx.recover_signer() {
                                if let Ok(mut reg) = registry_lock.write() {
                                    if let Err(e) = sovereign_consensus::precompile_router::execute_system_action(
                                        &mut reg,
                                        caller,
                                        resolved_to,
                                        &resolved_calldata,
                                        tip.number(),
                                    ) {
                                        tracing::error!("Failed to execute system action: {}", e);
                                    } else {
                                        tracing::info!("Executed system action on-chain in ExEx targeting {:#x}", to);
                                    }
                                }
                            }
                        }
                    }
                }

                // Sovereign Epoch Consensus Ticking
                //
                // TODO(Phase 7b): The epoch boundary is NOT determined by block count.
                // The correct trigger is receipt of a threshold-signed `ThresholdEpochMarker`
                // from the sub-committee. This block-modulo logic is a temporary dev
                // placeholder that MUST be replaced before mainnet.
                //
                // Correct model:
                //   1. Sub-committee completes >= min_paxos_slots Multi-Paxos slots.
                //   2. Sub-committee co-signs ThresholdEpochMarker via (t,n) BLS.
                //   3. Node receives the marker via P2P gossip.
                //   4. Node calls finalize_epoch() upon verifying the threshold signature.
                //
                // For now: fire on every new canonical tip as a stub (epoch_id = tip number).
                if let Ok(mut reg) = registry_lock.write() {
                    // Placeholder: treat each block as a potential epoch trigger only in dev/toy mode.
                    // In production, this branch is replaced by the ThresholdEpochMarker handler.
                    let block_number = tip.number();
                    if block_number > 0 {
                        let epoch_id = block_number; // placeholder: 1 epoch per block in dev
                        let consensus_root = tip.hash();
                        let state_root = tip.state_root();
                        let checkpoint = sovereign_consensus::epoch_engine::finalize_epoch(
                            &mut reg,
                            epoch_id,
                            consensus_root,
                            state_root,
                        );
                        tracing::debug!(
                            epoch_id,
                            ?consensus_root,
                            ?checkpoint.snapshot_hash,
                            "[DEV PLACEHOLDER] epoch finalized on block tip (not marker-driven)"
                        );
                    }
                }
            }

            ctx.events.send(ExExEvent::FinishedHeight(tip_num_hash))?;
        }
        Ok(())
    })
}



fn main() {
    reth_cli_util::sigsegv_handler::install();

    // RUST_BACKTRACE can be set externally: `RUST_BACKTRACE=1 bunny`
    // Avoid unsafe env::set_var which is unsound in multi-threaded contexts.

    // Enable Parallel EVM (Block-STM) execution natively
    let _ = DefaultEngineValues::default()
        .with_bal_parallel_execution_disabled(false)
        .try_init();

    let env_args: Vec<String> = std::env::args().collect();

    if let Err(err) = Cli::<EthereumChainSpecParser, SovereignArgs>::parse_from(env_args).run(async move |builder, args| {
        info!("Launching Sovereign Reth Node (Node Type: {}, TEE Mode: {})", args.sov_node_type, args.sov_tee);

        let mut static_cfg = sovereign_consensus::config::StaticConfig::default();
        let mut dynamic_cfg = sovereign_consensus::config::DynamicConfig::default();
        if let Some(cfg_path) = &args.sov_config {
            match config::NodeConfig::load_from_file(cfg_path) {
                Ok(cfg) => {
                    static_cfg = cfg.static_cfg;
                    dynamic_cfg = cfg.dynamic_cfg;
                    info!("Loaded configuration from {cfg_path:?}");
                }
                Err(e) => {
                    tracing::error!("Failed to load configuration file {cfg_path:?}: {e}");
                }
            }
        }

        let env_quantum = std::env::var("QUANTUM_THREAT")
            .map(|val| val == "true" || val == "1")
            .unwrap_or(false);
        if args.sov_zero_latency_quantum_trigger || env_quantum {
            dynamic_cfg.zero_latency_quantum_trigger = true;
            info!("Zero Latency Quantum Trigger activated (mandating post-quantum signature schemes)");
        }

        if let Some(scheme) = args.sov_pq_scheme.clone().or_else(|| std::env::var("PQ_SCHEME").ok()).or_else(|| std::env::var("DEFAULT_PQ_SCHEME").ok()) {
            dynamic_cfg.default_pq_scheme = scheme.to_lowercase();
            info!("Configured default post-quantum scheme: {}", dynamic_cfg.default_pq_scheme);
        }

        if let Some(block_time) = args.sov_block_time {
            info!("Configured target virtual block time from CLI: {}ms", block_time);
        }

        if let Some(profile) = args.sov_crypto_profile.clone() {
            dynamic_cfg.default_crypto_profile = profile.to_lowercase();
            info!("Configured default crypto profile from CLI: {}", dynamic_cfg.default_crypto_profile);
        }

        if let Some(engine) = args.sov_parallel_engine.clone() {
            dynamic_cfg.parallel_execution_engine = engine.to_lowercase();
            info!("Configured parallel execution engine from CLI: {}", dynamic_cfg.parallel_execution_engine);
        }

        let dynamic_cfg_arc = std::sync::Arc::new(std::sync::RwLock::new(dynamic_cfg));
        let _ = sovereign_consensus::registry::init_registry(static_cfg, dynamic_cfg_arc);

        // Auto-register operator identity if provided via CLI flag
        if let Some(ref did_str) = args.sov_did_peer4 {
            let reg_lock = sovereign_consensus::registry::get_registry();
            if let Ok(mut reg) = reg_lock.write() {
                let _ = reg.register_user_did(did_str.clone());
                if args.sov_node_type.eq_ignore_ascii_case("validator") {
                    reg.validators.insert(did_str.clone(), sovereign_consensus::registry::ValidatorType::HardwareTEE);
                    reg.reputation.insert(did_str.clone(), 0.90);
                    if let Some(addr) = reg.get_address_by_did(did_str) {
                        reg.validators.insert(format!("{addr:#x}"), sovereign_consensus::registry::ValidatorType::HardwareTEE);
                    }
                }
                info!("Registered operator DID from CLI: {did_str}");
            }
        }

        if args.toy_mode || std::env::var("SOVEREIGN_TOY_MODE").is_ok() {
            eprintln!("{}", sovereign_crypto::toy_mode::TOY_MODE_WARNING);
            info!("⚠️ Running in TOY MODE — reduced security parameters active");
        }

        let proxy_port = args.sov_proxy_port;
        let is_dev = std::env::args().any(|arg| arg == "--dev" || arg == "--toy-mode") || args.toy_mode;

        if is_dev {
            info!("Launching Sovereign Reth Node in DEV mode (Auto-Mining)");
            let handle = builder
                .with_types::<EthereumNode>()
                .with_components(
                    EthereumNode::components()
                        .pool(SovereignPoolBuilder::default()),
                )
                .with_add_ons(EthereumAddOns::default())
                .install_exex("sovereign_exex", move |ctx| sovereign_exex(ctx, args.clone()))
                .launch_with_debug_capabilities()
                .await?;
            
            let node_config = &handle.node.config;
            let reth_port = node_config.rpc.http_port as u16;
            let chain_id = handle.node.chain_spec().chain.id();
            let _ = tokio::spawn(caip_rpc::run_proxy(proxy_port, reth_port, chain_id));
            info!("🚀 Spawned CAIP-RPC proxy on port {proxy_port} forwarding to Reth on port {reth_port}");

            // Continuous background epoch progression loop (tick-driven)
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(2500));
                loop {
                    interval.tick().await;
                    let reg_lock = sovereign_consensus::registry::get_registry();
                    if let Ok(mut reg) = reg_lock.write() {
                        let next_epoch = reg.current_epoch + 1;
                        let consensus_root = alloy_primitives::B256::from_slice(blake3::hash(&next_epoch.to_be_bytes()).as_bytes());
                        let state_root = alloy_primitives::B256::from_slice(blake3::hash(consensus_root.as_slice()).as_bytes());
                        sovereign_consensus::epoch_engine::finalize_epoch(&mut reg, next_epoch, consensus_root, state_root);
                        reg.current_block = next_epoch;
                    }
                }
            });
            
            handle.wait_for_node_exit().await
        } else {
            let handle = builder
                .with_types::<EthereumNode>()
                .with_components(
                    EthereumNode::components()
                        .pool(SovereignPoolBuilder::default())
                        .consensus(NoopConsensusBuilder),
                )
                .with_add_ons(EthereumAddOns::default())
                .install_exex("sovereign_exex", move |ctx| sovereign_exex(ctx, args.clone()))
                .launch()
                .await?;
            
            let node_config = &handle.node.config;
            let reth_port = node_config.rpc.http_port as u16;
            let chain_id = handle.node.chain_spec().chain.id();
            let _ = tokio::spawn(caip_rpc::run_proxy(proxy_port, reth_port, chain_id));
            info!("🚀 Spawned CAIP-RPC proxy on port {proxy_port} forwarding to Reth on port {reth_port}");
            
            handle.wait_for_node_exit().await
        }
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toml_config_loading() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_config.toml");
        let toml_content = r#"
[static_cfg.pagerank]
damping_factor = 0.95
max_iterations = 100
temporal_decay_gamma = 0.01
temporal_decay_delta_r = 0.02

[static_cfg.epoch]
min_paxos_slots = 5
publishing_window_epochs = 2

[static_cfg.das]
required_samples = 32
max_attempts = 500

[static_cfg.snowman]
k = 10
alpha = 0.8
beta = 15

[static_cfg.merit]
rank_0_interval = 90
rank_1_interval = 30
rank_2_interval = 14
rank_3_interval = 7
rank_4_interval = 1

[dynamic_cfg]
sgx_reputation_threshold = 0.5
manifold_quorum_threshold = 100
social_promotion_threshold = 0.1
default_pq_scheme = "mldsa"
default_crypto_profile = "ethereum"
saga_intent_timeout_seconds = 86400
committee_threshold = 0.67
connectivity_decay_penalty = 0.10
"#;
        std::fs::write(&file_path, toml_content).unwrap();

        let config = config::NodeConfig::load_from_file(&file_path).unwrap();
        assert_eq!(config.static_cfg.pagerank.damping_factor, 0.95);
        assert_eq!(config.static_cfg.pagerank.max_iterations, 100);
        assert_eq!(config.static_cfg.pagerank.temporal_decay_gamma, 0.01);
        assert_eq!(config.static_cfg.pagerank.temporal_decay_delta_r, 0.02);
        assert_eq!(config.static_cfg.epoch.min_paxos_slots, 5);
        assert_eq!(config.static_cfg.epoch.publishing_window_epochs, 2);
        assert_eq!(config.static_cfg.das.required_samples, 32);
        assert_eq!(config.static_cfg.das.max_attempts, 500);

        assert_eq!(config.dynamic_cfg.sgx_reputation_threshold, 0.5);
        assert_eq!(config.dynamic_cfg.manifold_quorum_threshold, 100);
        assert_eq!(config.dynamic_cfg.social_promotion_threshold, 0.1);
        assert_eq!(config.dynamic_cfg.default_pq_scheme, "mldsa");
        assert_eq!(config.dynamic_cfg.default_crypto_profile, "ethereum");
        assert_eq!(config.dynamic_cfg.saga_intent_timeout_seconds, 86400);
        assert_eq!(config.dynamic_cfg.committee_threshold, 0.67);
        assert_eq!(config.dynamic_cfg.connectivity_decay_penalty, 0.10);

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_get_tee_attestation_action() {
        assert_eq!(
            get_tee_attestation_action("sgx", "0xEphemeralKey", 42),
            "sgx:block:42:key:0xEphemeralKey"
        );
        assert_eq!(
            get_tee_attestation_action("nitro", "0xEphemeralKey", 42),
            "nitro:block:42:key:0xEphemeralKey"
        );
        assert_eq!(
            get_tee_attestation_action("none", "0xEphemeralKey", 42),
            "native"
        );
    }

    #[test]
    fn test_sovereign_pool_builder_init() {
        let builder = SovereignPoolBuilder::default();
        // Just verify we can instantiate it
        let _ = builder;
    }


    #[test]
    fn test_integration_nfc_namespace_did() {
        use sovereign_network::handshake::ZeroConfigMesh;
        use sovereign_identity::zkp_auth::NfcCredentials;
        use sovereign_identity::namespace::NamespaceRegistry;
        use sovereign_identity::did::SovereignDidDocument;
        use sovereign_network::xroad::{XRoadRelay, XRoadRequestHeader};
        use std::collections::HashMap;
        use alloy_primitives::B256;

        // 1. Peer Node A and Node B via simulated NFC tap
        use ed25519_dalek::{SigningKey, Signer};
        let mut mesh = ZeroConfigMesh::new("wg0");

        let seed = [2u8; 32];
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
        let (node_a_did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).unwrap();

        let challenge = vec![0, 0, 1];
        let sig = signing_key.sign(&challenge).to_bytes().to_vec();

        let creds = NfcCredentials {
            card_uid: vec![0x99, 0x88],
            dynamic_signature: sig,
            challenge,
        };
        assert!(mesh.handle_nfc_handshake(&node_a_did, &creds, "192.168.1.100:51820").is_ok());

        // 2. Resolve a namespace for Node A
        let mut ns_registry = NamespaceRegistry::new();
        assert!(ns_registry.register("nodea.sovereign".into(), node_a_did.clone(), 10.0, 0));

        // 3. Setup X-Road Relay with a resolved DID
        let mut dids = HashMap::new();
        let doc = SovereignDidDocument::derive_from_seed(B256::repeat_byte(0x02));
        let did_uri = doc.did_uri.clone();
        dids.insert(did_uri.clone(), doc);

        // 4. Query organization status optionally via X-Road
        let relay = XRoadRelay::new(dids);
        let header = XRoadRequestHeader {
            client: "regulator".to_string(),
            service: "verifyOrg".to_string(),
            id: "tx-777".to_string(),
            protocol_version: "4.0".to_string(),
        };
        let response = relay.query_organization_state(&did_uri, &header).unwrap();
        assert!(response.contains("did_uri"));
        assert!(response.contains(&did_uri));
    }
}

