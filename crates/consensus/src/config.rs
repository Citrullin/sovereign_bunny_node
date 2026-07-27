use serde::{Deserialize, Serialize};

/// Static configurations loaded at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticConfig {
    /// PageRank parameters.
    pub pagerank: PageRankConfig,
    /// Epoch management parameters.
    pub epoch: EpochConfig,
    /// Data Availability Sampling parameters.
    pub das: DasConfig,
}

impl Default for StaticConfig {
    fn default() -> Self {
        Self {
            pagerank: PageRankConfig::default(),
            epoch: EpochConfig::default(),
            das: DasConfig::default(),
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

/// Epoch static timings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Length of an epoch in blocks (e.g., 1_296_000).
    pub epoch_length: u64,
    /// Publishing window length in blocks (e.g., 300).
    pub publishing_window: u64,
    /// Target block time in milliseconds (e.g. 2000 for 2s).
    pub block_time_ms: u64,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            epoch_length: 1_296_000,
            publishing_window: 300,
            block_time_ms: 2000,
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
    /// Validator count threshold for MetaLex reality audit verification (e.g. 2).
    pub metalex_validator_count_threshold: usize,
    /// Toggle to instantly mandate post-quantum signature verification schemes across the network.
    #[serde(alias = "quantum_threat", default)]
    pub zero_latency_quantum_trigger: bool,
    /// Default post-quantum signature scheme mandated when Zero Latency Quantum Trigger is active (e.g. "mldsa", "slhdsa", "falcon").
    #[serde(alias = "pq_scheme", default = "default_pq_scheme")]
    pub default_pq_scheme: String,
    /// Default cryptographic profile (e.g. "ethereum", "throughput", "quantum_standard").
    pub default_crypto_profile: String,
    /// Saga intent validity window / timeout in seconds (e.g., 86400).
    pub saga_intent_timeout_seconds: u64,
    /// Threshold to reach orchestrator quorum for a Saga Intent (e.g. 0.67).
    pub committee_threshold: f64,
    /// Decay penalty applied to offline orchestrators (e.g. 0.10).
    pub connectivity_decay_penalty: f64,
    /// Pluggable parallel EVM execution engine selection (e.g. "wave", "pevm", "grevm").
    #[serde(default = "default_parallel_engine")]
    pub parallel_execution_engine: String,
}

fn default_parallel_engine() -> String {
    "wave".to_string()
}

fn default_pq_scheme() -> String {
    "mldsa".to_string()
}

impl Default for DynamicConfig {
    fn default() -> Self {
        Self {
            sgx_reputation_threshold: 0.0,
            manifold_quorum_threshold: 500,
            social_promotion_threshold: 0.05,
            metalex_validator_count_threshold: 2,
            zero_latency_quantum_trigger: false,
            default_pq_scheme: default_pq_scheme(),
            default_crypto_profile: "ethereum".to_string(),
            saga_intent_timeout_seconds: 86400,
            committee_threshold: 0.67,
            connectivity_decay_penalty: 0.10,
            parallel_execution_engine: "wave".to_string(),
        }
    }
}

