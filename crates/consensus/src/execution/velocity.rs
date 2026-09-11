//! Velocity Economics Telemetry & Circuit Breaker Engine.
//! Implements Solow-Minsky output functions Q(V) = k * V^\alpha * e^{-\delta * V}
//! and monetary inflation nexus controls.

/// Real-time economic velocity telemetry.
#[derive(Debug, Clone)]
pub struct VelocityEngine {
    /// Productive transaction velocity (wages, procurement, physical output).
    pub v_productive: f64,
    /// Speculative transaction velocity (recursive arbitrage, high-frequency loops).
    pub v_speculative: f64,
    /// Productive elasticity coefficient \alpha (0 < \alpha < 1).
    pub alpha: f64,
    /// Entropic decay / speculative churn sensitivity \delta.
    pub delta: f64,
    /// Minimum efficiency ratio \eta_min = Q / V.
    pub min_efficiency: f64,
}

impl Default for VelocityEngine {
    fn default() -> Self {
        Self {
            v_productive: 1.0,
            v_speculative: 0.1,
            alpha: 0.7,
            delta: 0.15,
            min_efficiency: 0.20,
        }
    }
}

impl VelocityEngine {
    /// Calculates total velocity V = V_p + V_s.
    #[must_use]
    pub fn total_velocity(&self) -> f64 {
        self.v_productive + self.v_speculative
    }

    /// Computes the Sovereign Output Function: Q(V) = k * V^\alpha * e^{-\delta * V}
    #[must_use]
    pub fn compute_output(&self, k: f64) -> f64 {
        let v = self.total_velocity();
        k * v.powf(self.alpha) * (-self.delta * v).exp()
    }

    /// Calculates the optimal velocity peak ("Switzerland Sweet Spot"): V_opt = \alpha / \delta.
    #[must_use]
    pub fn optimal_velocity(&self) -> f64 {
        self.alpha / self.delta
    }

    /// Computes systemic efficiency ratio \eta = Q / V.
    #[must_use]
    pub fn efficiency_ratio(&self, k: f64) -> f64 {
        let v = self.total_velocity();
        if v == 0.0 {
            return 0.0;
        }
        self.compute_output(k) / v
    }

    /// Checks if monetary issuance should enter a Halt State (Circuit Breaker)
    /// due to excessive speculative churn or drop in productive elasticity.
    #[must_use]
    pub fn is_circuit_breaker_triggered(&self, k: f64) -> bool {
        self.efficiency_ratio(k) < self.min_efficiency || self.v_speculative > (5.0 * self.v_productive)
    }

    /// Computes the non-linear gas escalation scalar f(V) = 1.0 + (v_speculative / (v_productive + 0.001))^2
    #[must_use]
    pub fn gas_escalation_scalar(&self) -> f64 {
        let ratio = self.v_speculative / (self.v_productive + 0.001);
        1.0 + ratio * ratio
    }

    /// Dynamic shard count: shrinks shard address range as network grows organically with productive velocity.
    #[must_use]
    pub fn dynamic_shard_count(&self, base_shards: u32, min_shards: u32, max_shards: u32) -> u32 {
        let v_opt = self.optimal_velocity();
        let v = self.total_velocity().max(0.001);
        let scale = (v_opt / v).max(1.0);
        let calculated = (base_shards as f64 * scale).floor() as u32;
        calculated.clamp(min_shards, max_shards)
    }
}
