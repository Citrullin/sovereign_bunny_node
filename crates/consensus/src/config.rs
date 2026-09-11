use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

fn default_ticker() -> String {
    "TBL".to_string()
}

/// Dynamic network configuration defining genesis accounts, schemas, and elastic sharding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGenesisConfig {
    pub network_name: String,
    pub chain_id: u64,
    /// Native currency ticker symbol (default: "TBL")
    #[serde(default = "default_ticker")]
    pub ticker: String,
    /// Registered system function accounts (e.g., precompiles)
    pub system_accounts: Vec<SystemAccountConfig>,
    /// Global slot schema definitions
    pub slot_schemas: Vec<SlotSchemaConfig>,
    /// Genesis sharding parameters
    #[serde(default)]
    pub shard_genesis: ShardGenesisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardGenesisConfig {
    pub initial_shards: u32,
    pub min_shards: u32,
    pub max_shards: u32,
    pub elasticity_scale_up_tps: u64,
    pub elasticity_scale_down_idle_epochs: u64,
}

impl Default for ShardGenesisConfig {
    fn default() -> Self {
        Self {
            initial_shards: 16,
            min_shards: 16,
            max_shards: 4096,
            elasticity_scale_up_tps: 5000,
            elasticity_scale_down_idle_epochs: 5,
        }
    }
}

impl Default for NetworkGenesisConfig {
    fn default() -> Self {
        Self {
            network_name: "sovereign-local".to_string(),
            chain_id: 65001,
            ticker: "TBL".to_string(),
            system_accounts: vec![
                SystemAccountConfig {
                    address: Address::repeat_byte(0x01),
                    name: "core.precompile.router".to_string(),
                    kind: "Precompile".to_string(),
                },
                SystemAccountConfig {
                    address: Address::repeat_byte(0x02),
                    name: "zkdns.canonical.registry".to_string(),
                    kind: "NamespaceRegistry".to_string(),
                },
            ],
            slot_schemas: vec![
                SlotSchemaConfig {
                    slot_id: 0,
                    name: "DID Document Root".to_string(),
                    plugin_name: "core.did_identity".to_string(),
                    version: 1,
                    activation_epoch: 0,
                },
                SlotSchemaConfig {
                    slot_id: 1,
                    name: "Zanzibar ReBAC SMT".to_string(),
                    plugin_name: "core.zanzibar".to_string(),
                    version: 1,
                    activation_epoch: 0,
                },
                SlotSchemaConfig {
                    slot_id: 2,
                    name: "Native Payment Core".to_string(),
                    plugin_name: "core.native_payment".to_string(),
                    version: 1,
                    activation_epoch: 0,
                },
                SlotSchemaConfig {
                    slot_id: 3,
                    name: "Git VCS Object DAG".to_string(),
                    plugin_name: "vcs.git_dag".to_string(),
                    version: 1,
                    activation_epoch: 0,
                },
                SlotSchemaConfig {
                    slot_id: 4,
                    name: "Relational SQL Digest".to_string(),
                    plugin_name: "ext.sqldigest".to_string(),
                    version: 1,
                    activation_epoch: 0,
                },
                SlotSchemaConfig {
                    slot_id: 7,
                    name: "Reputation & Merit Score".to_string(),
                    plugin_name: "reputation.merit".to_string(),
                    version: 1,
                    activation_epoch: 0,
                },
            ],
            shard_genesis: ShardGenesisConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemAccountConfig {
    pub address: Address,
    pub name: String,
    pub kind: String, // "Precompile", "NamespaceRegistry", etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotSchemaConfig {
    pub slot_id: u16,
    pub name: String,
    pub plugin_name: String,
    pub version: u32,
    pub activation_epoch: u64,
}

/// Static configurations loaded at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticConfig {
    /// PageRank parameters.
    pub pagerank: PageRankConfig,
    /// Epoch management parameters.
    pub epoch: EpochConfig,
    /// Data Availability Sampling parameters.
    pub das: DasConfig,
    /// Snowman consensus parameters.
    pub snowman: GlobalConsensusConfig,
    /// Merit progressive distribution parameters.
    pub merit: MeritTierConfig,
    /// Shard consensus parameters.
    #[serde(default)]
    pub shard: ShardConfig,
}

impl Default for StaticConfig {
    fn default() -> Self {
        Self {
            pagerank: PageRankConfig::default(),
            epoch: EpochConfig::default(),
            das: DasConfig::default(),
            snowman: GlobalConsensusConfig::default(),
            merit: MeritTierConfig::default(),
            shard: ShardConfig::default(),
        }
    }
}

/// PageRank static mathematical constants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRankConfig {
    /// Damping factor `d` for PageRank computations (e.g. 0.85).
    pub damping_factor: f64,
    /// Maximum convergence iterations for PageRank (e.g. 50).
    pub max_iterations: usize,
    /// Temporal decay factor `gamma` (e.g. 0.05).
    pub temporal_decay_gamma: f64,
    /// Temporal decay factor `delta_r` (e.g. 0.05).
    pub temporal_decay_delta_r: f64,
}

impl Default for PageRankConfig {
    fn default() -> Self {
        Self {
            damping_factor: 0.85,
            max_iterations: 50,
            temporal_decay_gamma: 0.05,
            temporal_decay_delta_r: 0.05,
        }
    }
}

/// Epoch configuration.
///
/// # The epoch IS the clock
///
/// Epoch boundaries are defined by a `ThresholdEpochMarker` completing its BFT frontier cut
/// across the sub-committee — not by block count, not by wall-clock time.
/// The duration of an epoch is emergent: it depends on network latency, quorum collection
/// time, and marker propagation. You cannot know ahead of time how long an epoch takes.
///
/// All time-sensitive protocol parameters (publishing windows, distribution intervals,
/// committee rotation) are expressed exclusively in **epoch heights**.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Minimum number of Multi-Paxos log slots a sub-committee must complete before any
    /// member may propose co-signing the next `ThresholdEpochMarker`.
    /// This is the liveness lower bound: an epoch cannot close with zero progress.
    /// Default: 1 (at least one Paxos slot must commit before marker is eligible).
    pub min_paxos_slots: u64,
    /// Number of epoch heights that form the publishing window after an epoch closes.
    /// Validators must submit KZG DA commitments and PageRank Merkle roots within this window.
    /// Default: 1 (next epoch height is the deadline; missing = slash).
    pub publishing_window_epochs: u64,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            min_paxos_slots: 1,
            publishing_window_epochs: 1,
        }
    }
}

/// DAS static constants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DasConfig {
    /// Required successful samples.
    pub required_samples: usize,
    /// Maximum random sampling attempts.
    pub max_attempts: usize,
}

impl Default for DasConfig {
    fn default() -> Self {
        Self {
            required_samples: 16,
            max_attempts: 1000,
        }
    }
}

/// Dynamic, hot-reloadable configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicConfig {
    /// Reputation threshold below which Hardware TEE validators are untrusted/ignored (e.g. 0.0).
    pub sgx_reputation_threshold: f64,
    /// Threshold to enforce minimum required validators for organic manifold routing (e.g. 500).
    pub manifold_quorum_threshold: usize,
    /// Minimum reputation required to promote social validators (e.g. 0.05).
    pub social_promotion_threshold: f64,
    /// Toggle to instantly mandate post-quantum signature verification schemes across the network.
    #[serde(alias = "quantum_threat", default)]
    pub zero_latency_quantum_trigger: bool,
    /// Default post-quantum signature scheme mandated when Zero Latency Quantum Trigger is active (e.g. "mldsa", "slhdsa", "falcon").
    #[serde(alias = "pq_scheme", default = "default_pq_scheme")]
    pub default_pq_scheme: String,
    /// Default cryptographic profile (e.g. "ethereum", "throughput", "quantum_standard").
    pub default_crypto_profile: String,
    /// Block height at which a genesis softfork occurs to switch crypto profiles automatically.
    #[serde(default)]
    pub profile_switch_block_height: Option<u64>,
    /// The next cryptographic profile to activate at the switch block height.
    #[serde(default)]
    pub next_crypto_profile: Option<String>,
    /// Saga intent validity window / timeout in seconds (e.g., 86400).
    pub saga_intent_timeout_seconds: u64,
    /// Threshold to reach orchestrator quorum for a Saga Intent (e.g. 0.67).
    pub committee_threshold: f64,
    /// Decay penalty applied to offline orchestrators (e.g. 0.10).
    pub connectivity_decay_penalty: f64,
    /// Pluggable parallel EVM execution engine selection (e.g. "wave", "pevm", "grevm").
    #[serde(default = "default_parallel_engine")]
    pub parallel_execution_engine: String,
    /// Dynamic, consensus-driven registry of CAIP-2 namespaces mapped to Signature and Hash schemes.
    #[serde(default = "default_caip_registry")]
    pub caip_registry: std::collections::HashMap<String, (sovereign_crypto::SignatureScheme, sovereign_crypto::HashScheme)>,
}

fn default_parallel_engine() -> String {
    "wave".to_string()
}

fn default_pq_scheme() -> String {
    "mldsa".to_string()
}

fn default_caip_registry() -> std::collections::HashMap<String, (sovereign_crypto::SignatureScheme, sovereign_crypto::HashScheme)> {
    let mut map = std::collections::HashMap::new();
    map.insert("eip155".to_string(), (sovereign_crypto::SignatureScheme::Secp256k1, sovereign_crypto::HashScheme::Keccak256));
    map.insert("solana".to_string(), (sovereign_crypto::SignatureScheme::Ed25519, sovereign_crypto::HashScheme::Blake3));
    map.insert("cosmos".to_string(), (sovereign_crypto::SignatureScheme::Secp256k1, sovereign_crypto::HashScheme::Sha256));
    map.insert("bip122".to_string(), (sovereign_crypto::SignatureScheme::Secp256k1, sovereign_crypto::HashScheme::Sha256));
    map.insert("polkadot".to_string(), (sovereign_crypto::SignatureScheme::Ed25519, sovereign_crypto::HashScheme::Blake3));
    map.insert("tezos".to_string(), (sovereign_crypto::SignatureScheme::Secp256r1, sovereign_crypto::HashScheme::Keccak256));
    map
}

impl Default for DynamicConfig {
    fn default() -> Self {
        Self {
            sgx_reputation_threshold: 0.0,
            manifold_quorum_threshold: 500,
            social_promotion_threshold: 0.05,
            zero_latency_quantum_trigger: false,
            default_pq_scheme: default_pq_scheme(),
            default_crypto_profile: "ethereum".to_string(),
            profile_switch_block_height: None,
            next_crypto_profile: None,
            saga_intent_timeout_seconds: 86400,
            committee_threshold: 0.67,
            connectivity_decay_penalty: 0.10,
            parallel_execution_engine: "wave".to_string(),
            caip_registry: default_caip_registry(),
        }
    }
}

/// Global Snowman BFT consensus parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConsensusConfig {
    /// Sample size k
    pub k: usize,
    /// Quorum fraction alpha
    pub alpha: f64,
    /// Finalization successes beta
    pub beta: u32,
}

/// Backward compatibility alias
pub type SnowmanConfig = GlobalConsensusConfig;

impl Default for GlobalConsensusConfig {
    fn default() -> Self {
        Self {
            k: 10,
            alpha: 0.8,
            beta: 15,
        }
    }
}

/// Dynamic Shard consensus and superposition parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConfig {
    /// Base shard count at optimal velocity.
    pub base_shards: u32,
    /// Minimum shard count (floor).
    pub min_shards: u32,
    /// Maximum shard count (ceiling).
    pub max_shards: u32,
    /// Timeout in epochs for floating blocks before auto-reclaim.
    pub superposition_timeout_epochs: u64,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            base_shards: 16,
            min_shards: 16,
            max_shards: 4096,
            superposition_timeout_epochs: 10,
        }
    }
}

/// Merit progressive distribution parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeritTierConfig {
    /// Interval in epochs for Rank0 (e.g. 90)
    pub rank_0_interval: u64,
    /// Interval in epochs for Rank1 (e.g. 30)
    pub rank_1_interval: u64,
    /// Interval in epochs for Rank2 (e.g. 14)
    pub rank_2_interval: u64,
    /// Interval in epochs for Rank3 (e.g. 7)
    pub rank_3_interval: u64,
    /// Interval in epochs for Rank4 (e.g. 1)
    pub rank_4_interval: u64,
}

impl Default for MeritTierConfig {
    fn default() -> Self {
        Self {
            rank_0_interval: 90,
            rank_1_interval: 30,
            rank_2_interval: 14,
            rank_3_interval: 7,
            rank_4_interval: 1,
        }
    }
}

