//! Toy Mode security downgrade configuration and warning banners.

/// Warning banner displayed prominently in logs and terminals when toy mode is activated.
pub const TOY_MODE_WARNING: &str = concat!(
    "\n⚠️  ═══════════════════════════════════════════════════════════════════ ⚠️\n",
    "⚠️   TOY MODE ACTIVE — cryptographic parameters are deliberately reduced ⚠️\n",
    "⚠️   Proofs & attestations have NO security. NOT FOR PRODUCTION ASSETS. ⚠️\n",
    "⚠️  ═══════════════════════════════════════════════════════════════════ ⚠️\n"
);

/// Toy mode parameter overrides for rapid local development.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct ToyModeConfig {
    /// Curve choice for toy-mode proving (e.g. "bn254_tiny")
    pub groth16_curve: &'static str,
    /// Fast FHE parameter set
    pub fhe_params: &'static str,
    /// Circuit recursion depth in toy mode
    pub noir_recursion_depth: u8,
    /// Snowflake/Snowball/Snowman consecutive successes beta (toy: 2 vs prod: 15)
    pub snow_beta: u32,
    /// Shard Raft election timeout in ms (toy: 100 vs prod: 1000)
    pub raft_election_timeout_ms: u64,
    /// Superposition floating block auto-reclaim timeout in epochs (toy: 1 vs prod: 10)
    pub superposition_timeout_epochs: u64,
}

impl Default for ToyModeConfig {
    fn default() -> Self {
        Self {
            groth16_curve: "bn254_tiny",
            fhe_params: "tfhe_toy",
            noir_recursion_depth: 1,
            snow_beta: 2,
            raft_election_timeout_ms: 100,
            superposition_timeout_epochs: 1,
        }
    }
}
