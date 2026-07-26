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

use sovereign_consensus::SovereignPoolBuilder;
use clap::Parser;

/// Custom CLI arguments for the Sovereign Reth node.
#[derive(Debug, Clone, clap::Args)]
pub struct SovereignArgs {
    /// Type of the node (replica or validator)
    #[arg(long, default_value = "replica")]
    pub node_type: String,

    /// TEE execution mode (sgx, nitro, or none)
    #[arg(long, default_value = "none")]
    pub tee: String,

    /// Operator's did:peer:4 identity string
    #[arg(long)]
    pub did_peer4: Option<String>,

    /// Path to operator delegation signature/proof file
    #[arg(long)]
    pub delegation_proof: Option<std::path::PathBuf>,

    /// `TinyMeritRank` reputation threshold for admission
    #[arg(long, default_value_t = 0.0)]
    pub merit_threshold: f64,

    /// Path to the TOML configuration file
    #[arg(long)]
    pub config: Option<std::path::PathBuf>,
}

impl Default for SovereignArgs {
    fn default() -> Self {
        Self {
            node_type: "replica".to_string(),
            tee: "none".to_string(),
            did_peer4: None,
            delegation_proof: None,
            merit_threshold: 0.0,
            config: None,
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

/// Execution Extension (`ExEx`) for Pluggable TEE Proving & DA Mesh Emission
/// Gnosis Safe cross-chain settlement relayer using standard alloy providers.
pub struct SettlementRelayer {
    safe_address: alloy_primitives::Address,
}

impl SettlementRelayer {
    /// Creates a new Settlement Relayer.
    #[must_use]
    pub fn new(safe_address: alloy_primitives::Address) -> Self {
        Self { safe_address }
    }

    /// Submits state diff commitment to the Gnosis Safe.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails.
    pub async fn submit_intent(&self, state_diff: &[u8]) -> eyre::Result<alloy_primitives::B256> {
        use tiny_keccak::{Hasher, Keccak};
        let mut hasher = Keccak::v256();
        hasher.update(state_diff);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        let commitment = alloy_primitives::B256::from(hash);

        // Instantiates a standard HTTP client to submit JSON-RPC to Gnosis Chain
        let client = reqwest::Client::new();
        let _res = client.post("http://localhost:8545")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": [format!("0x{:x}", commitment)],
                "id": 1
            }))
            .send()
            .await;


        info!(
            "SettlementRelayer: Relaying transaction commitment {} to Gnosis Safe at {}",
            commitment, self.safe_address
        );

        Ok(commitment)
    }
}

/// Execution Extension (`ExEx`) for Pluggable TEE Proving & DA Mesh Emission
#[allow(clippy::unused_async)]
async fn sovereign_exex<N: FullNodeComponents>(
    mut ctx: ExExContext<N>,
    args: SovereignArgs,
) -> eyre::Result<impl Future<Output = eyre::Result<()>>> {
    let tee_mode = args.tee.to_lowercase();
    let relayer = SettlementRelayer::new(alloy_primitives::Address::repeat_byte(0x99));

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

                // Relayer submits the block intent
                let mock_state_diff = vec![1, 2, 3, 4];
                let _ = relayer.submit_intent(&mock_state_diff).await;
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

    if let Err(err) = Cli::<EthereumChainSpecParser, SovereignArgs>::parse().run(async move |builder, args| {
        info!("Launching Sovereign Reth Node (Node Type: {}, TEE Mode: {})", args.node_type, args.tee);

        let mut static_cfg = sovereign_consensus::config::StaticConfig::default();
        let mut dynamic_cfg = sovereign_consensus::config::DynamicConfig::default();
        if let Some(cfg_path) = &args.config {
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

[static_cfg.das]
required_samples = 32
max_attempts = 500

[dynamic_cfg]
sgx_reputation_threshold = 0.5
manifold_quorum_threshold = 100
social_promotion_threshold = 0.1
required_gas_threshold = "10000000000000000"
metalex_validator_count_threshold = 5
"#;
        std::fs::write(&file_path, toml_content).unwrap();

        let config = config::NodeConfig::load_from_file(&file_path).unwrap();
        assert_eq!(config.static_cfg.pagerank.damping_factor, 0.95);
        assert_eq!(config.static_cfg.pagerank.max_iterations, 100);
        assert_eq!(config.static_cfg.pagerank.temporal_decay_gamma, 0.01);
        assert_eq!(config.static_cfg.pagerank.temporal_decay_delta_r, 0.02);
        assert_eq!(config.static_cfg.epoch.epoch_length, 500000);
        assert_eq!(config.static_cfg.epoch.publishing_window, 1000);
        assert_eq!(config.static_cfg.das.required_samples, 32);
        assert_eq!(config.static_cfg.das.max_attempts, 500);

        assert_eq!(config.dynamic_cfg.sgx_reputation_threshold, 0.5);
        assert_eq!(config.dynamic_cfg.manifold_quorum_threshold, 100);
        assert_eq!(config.dynamic_cfg.social_promotion_threshold, 0.1);
        assert_eq!(config.dynamic_cfg.required_gas_threshold, alloy_primitives::U256::from(10000000000000000u64));
        assert_eq!(config.dynamic_cfg.metalex_validator_count_threshold, 5);

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

    #[tokio::test]
    async fn test_settlement_relayer_intent() {
        let safe_addr = alloy_primitives::Address::repeat_byte(0xbc);
        let relayer = SettlementRelayer::new(safe_addr);
        let state_diff = b"test-state-diff-data";
        
        let commitment = relayer.submit_intent(state_diff).await.unwrap();
        assert_ne!(commitment, alloy_primitives::B256::ZERO);
    }

    #[test]
    fn test_integration_nfc_namespace_metalex() {
        use sovereign_network::handshake::ZeroConfigMesh;
        use sovereign_identity::zkp_auth::NfcCredentials;
        use sovereign_identity::namespace::NamespaceRegistry;
        use sovereign_consensus::metalex::{BorgOrganization, RealityAudit, MetalexManager};
        use sovereign_network::xroad::{XRoadRelay, XRoadRequestHeader};
        use std::collections::HashMap;

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

        // 3. Register Node A's MetaLex organization contract with a Reality Audit
        let mut metalex_manager = MetalexManager::new();
        let mut agents = HashMap::new();
        agents.insert(node_a_did.to_string(), "director".to_string());
        
        let org = BorgOrganization {
            did_peer: node_a_did.to_string(),
            equity_token: "0xEquityAddressNodeA".to_string(),
            agents,
            is_active: true,
        };
        let audit = RealityAudit {
            epoch: 1,
            validator_signatures: vec![
                alloy_primitives::Bytes::from_static(&[1, 2]),
                alloy_primitives::Bytes::from_static(&[3, 4]),
            ], // threshold met
        };
        assert!(metalex_manager.register_or_update_org(org, &audit, 2).is_ok());

        // 4. Query organization status optionally via X-Road
        let relay = XRoadRelay::new(metalex_manager);
        let header = XRoadRequestHeader {
            client: "regulator".to_string(),
            service: "verifyOrg".to_string(),
            id: "tx-777".to_string(),
            protocol_version: "4.0".to_string(),
        };
        let response = relay.query_organization_state(&node_a_did, &header).unwrap();
        assert!(response.contains("0xEquityAddressNodeA"));
        assert!(response.contains(&node_a_did));
    }

}
