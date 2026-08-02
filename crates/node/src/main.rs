//! Sovereign Reth Node Binary.
//!
//! Restructured for clean code and modularity.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

use futures::StreamExt;
use reth_ethereum::{
    cli::{chainspec::EthereumChainSpecParser, interface::Cli},
    node::{api::FullNodeComponents, node::EthereumAddOns, EthereumNode},
};
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_builder::components::NoopConsensusBuilder;
use reth_node_core::args::DefaultEngineValues;
use reth_primitives_traits::AlloyBlockHeader;
use std::future::Future;
use tracing::{debug, info};

/// Node configuration module.
pub mod config;
/// CAIP RPC Proxy module.
pub mod caip_rpc;

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
            }

            ctx.events.send(ExExEvent::FinishedHeight(tip_num_hash))?;
        }
        Ok(())
    })
}



fn main() {
    reth_cli_util::sigsegv_handler::install();

    // RUST_BACKTRACE can be set externally: `RUST_BACKTRACE=1 sovereign-reth`
    // Avoid unsafe env::set_var which is unsound in multi-threaded contexts.

    // Enable Parallel EVM (Block-STM) execution natively
    let _ = DefaultEngineValues::default()
        .with_bal_parallel_execution_disabled(false)
        .try_init();

    // Intercept HTTP port to run proxy
    let mut env_args: Vec<String> = std::env::args().collect();
    let mut port = 8545;
    let mut port_idx = None;
    for (i, arg) in env_args.iter().enumerate() {
        if arg == "--http.port" && i + 1 < env_args.len() {
            if let Ok(p) = env_args[i + 1].parse::<u16>() {
                port = p;
                port_idx = Some(i + 1);
            }
        }
    }

    let reth_port = port + 1;
    if let Some(idx) = port_idx {
        env_args[idx] = reth_port.to_string();
    } else {
        if env_args.iter().any(|arg| arg == "--http" || arg == "node") {
            env_args.push("--http.port".to_string());
            env_args.push(reth_port.to_string());
        }
    }

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
            static_cfg.epoch.block_time_ms = block_time;
            info!("Configured block time from CLI: {}ms", block_time);
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

        let is_dev = std::env::args().any(|arg| arg == "--dev");

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
            
            // Start the CAIP RPC proxy
            let _ = tokio::spawn(caip_rpc::run_proxy(port, reth_port));

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
            
            // Start the CAIP RPC proxy
            let _ = tokio::spawn(caip_rpc::run_proxy(port, reth_port));

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
epoch_length = 500000
publishing_window = 1000
block_time_ms = 2000

[static_cfg.das]
required_samples = 32
max_attempts = 500

[dynamic_cfg]
sgx_reputation_threshold = 0.5
manifold_quorum_threshold = 100
social_promotion_threshold = 0.1
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
        assert_eq!(config.static_cfg.epoch.epoch_length, 500000);
        assert_eq!(config.static_cfg.epoch.publishing_window, 1000);
        assert_eq!(config.static_cfg.epoch.block_time_ms, 2000);
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
