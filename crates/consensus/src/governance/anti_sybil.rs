//! # Four Cryptographic & Physical Anti-Sybil Defense Mechanisms
//!
//! Provides topological, cryptographic, and economic defenses against centralized proxy farms,
//! co-located VPC validators, virtualized Sybil clusters, and correlated cloud outages.
//!
//! ## Defenses Implemented:
//! 1. **Speed-of-Light RTT Multi-Lateration (Vivaldi Network Coordinates)**:
//!    - Nodes cannot fake the speed of light. Triangulates physical distances across the mesh.
//!    - Requires minimum verified RTT dispersion index $\sigma_{\text{RTT}} > \tau$ across sub-committees.
//! 2. **BGP Autonomous System (ASN) Diversity Quotas**:
//!    - Caps concentration of any single ASN (e.g., AWS 16509, Hetzner 24940) at $\le 20\%$ per Paxos sub-committee.
//! 3. **Silicon Enclave Unique Attestations (DCAP / TEE Hardware Fingerprints)**:
//!    - Enforces 1:1 mapping between active validator slots and physical silicon packages via PPID / TCB roots.
//! 4. **Anti-Correlation Slashing (Correlated Failure Penalties)**:
//!    - Non-linear quadratic slashing: $\text{Penalty} \propto (\text{Number of simultaneously failing nodes})^2$.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 3D Vivaldi synthetic network coordinate + local error estimation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct VivaldiCoordinate {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub height: f64,
    pub error: f64,
}

impl Default for VivaldiCoordinate {
    fn default() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            height: 10.0, // base 10ms network interface delay
            error: 1.0,
        }
    }
}

impl VivaldiCoordinate {
    /// Computes estimated synthetic distance (in milliseconds) to another coordinate.
    #[must_use]
    pub fn distance_to(&self, other: &Self) -> f64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        let dz = self.z - other.z;
        let euclidean = (dx * dx + dy * dy + dz * dz).sqrt();
        euclidean + self.height + other.height
    }

    /// Updates this node's coordinate based on observed RTT to a peer (Vivaldi timestep).
    pub fn update(&mut self, peer: &Self, rtt_ms: f64) {
        let c_c = 0.25; // Tuning parameter
        let c_e = 0.25;
        let dist = self.distance_to(peer);
        if dist.abs() < 1e-6 {
            return;
        }

        // Relative error of this measurement
        let err = (dist - rtt_ms).abs() / rtt_ms.max(1.0);
        let weight = self.error / (self.error + peer.error).max(1e-6);

        // Update local error estimate
        self.error = self.error * (1.0 - c_e * weight) + err * (c_e * weight);

        // Compute coordinate delta
        let delta = c_c * weight * (rtt_ms - dist);
        let unit_x = (self.x - peer.x) / dist;
        let unit_y = (self.y - peer.y) / dist;
        let unit_z = (self.z - peer.z) / dist;

        self.x += delta * unit_x;
        self.y += delta * unit_y;
        self.z += delta * unit_z;
    }
}

/// BGP Autonomous System descriptor and network topology identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeTopologyDescriptor {
    pub validator: Address,
    pub bgp_asn: u32,
    pub ip_prefix: String,
    pub coordinate: VivaldiCoordinate,
    pub hardware_ppid: B256,
}

/// Anti-Sybil Defense Engine coordinating topological and physical verification.
#[derive(Debug, Clone, Default)]
pub struct AntiSybilEngine {
    /// Registered node topologies indexed by validator address
    pub topologies: HashMap<Address, NodeTopologyDescriptor>,
    /// Unique hardware silicon fingerprints mapped to registered validator address
    pub silicon_registry: HashMap<B256, Address>,
    /// Max allowed fraction of a single ASN in any committee (default: 0.20 = 20%)
    pub max_asn_concentration: f64,
    /// Minimum required RTT dispersion index in milliseconds across committee (default: 15.0 ms)
    pub min_rtt_dispersion_ms: f64,
}

impl AntiSybilEngine {
    /// Creates a new `AntiSybilEngine` with default production bounds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            topologies: HashMap::new(),
            silicon_registry: HashMap::new(),
            max_asn_concentration: 0.20, // 20% cap per ASN
            min_rtt_dispersion_ms: 15.0,  // 15ms minimum standard deviation
        }
    }

    /// Registers a validator's hardware TEE attestation and network topology.
    ///
    /// # Errors
    /// Returns an error if the physical silicon package (PPID) is already registered to another validator.
    pub fn register_validator(
        &mut self,
        descriptor: NodeTopologyDescriptor,
    ) -> Result<(), &'static str> {
        if let Some(existing) = self.silicon_registry.get(&descriptor.hardware_ppid) {
            if *existing != descriptor.validator {
                return Err("Sybil detected: Physical silicon chip (PPID) already registered to another validator");
            }
        }

        self.silicon_registry.insert(descriptor.hardware_ppid, descriptor.validator);
        self.topologies.insert(descriptor.validator, descriptor);
        Ok(())
    }

    /// Verifies that a candidate Paxos sub-committee satisfies BGP ASN diversity quotas.
    ///
    /// # Errors
    /// Returns an error if any single Autonomous System (e.g. AWS or Hetzner) exceeds `max_asn_concentration`.
    pub fn verify_committee_asn_diversity(&self, committee: &[Address]) -> Result<(), &'static str> {
        if committee.is_empty() {
            return Err("Committee is empty");
        }

        let mut asn_counts: HashMap<u32, usize> = HashMap::new();
        let total = committee.len();

        for member in committee {
            let desc = self.topologies.get(member).ok_or("Validator missing registered topology")?;
            *asn_counts.entry(desc.bgp_asn).or_insert(0) += 1;
        }

        let max_allowed = ((total as f64) * self.max_asn_concentration).ceil() as usize;
        for (asn, count) in asn_counts {
            if count > max_allowed {
                tracing::warn!(asn = asn, count = count, max_allowed = max_allowed, "BGP ASN concentration quota exceeded in committee");
                return Err("BGP ASN concentration quota exceeded: Single cloud provider dominates > 20% of sub-committee");
            }
        }

        Ok(())
    }

    /// Verifies physical Speed-of-Light RTT dispersion across sub-committee members.
    ///
    /// # Errors
    /// Returns an error if RTT dispersion is below threshold (indicating co-located VPC/rack nodes).
    pub fn verify_committee_rtt_dispersion(&self, committee: &[Address]) -> Result<f64, &'static str> {
        if committee.len() < 2 {
            return Err("Committee must have at least 2 members for RTT dispersion calculation");
        }

        let mut pairwise_distances = Vec::new();
        for i in 0..committee.len() {
            for j in (i + 1)..committee.len() {
                let desc_a = self.topologies.get(&committee[i]).ok_or("Validator missing topology")?;
                let desc_b = self.topologies.get(&committee[j]).ok_or("Validator missing topology")?;
                let dist = desc_a.coordinate.distance_to(&desc_b.coordinate);
                pairwise_distances.push(dist);
            }
        }

        if pairwise_distances.is_empty() {
            return Err("No pairwise distances calculated");
        }

        let mean = pairwise_distances.iter().sum::<f64>() / pairwise_distances.len() as f64;
        let variance = pairwise_distances.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / pairwise_distances.len() as f64;
        let std_dev = variance.sqrt();

        if std_dev < self.min_rtt_dispersion_ms {
            tracing::warn!(std_dev = std_dev, min_required = self.min_rtt_dispersion_ms, "Speed-of-light RTT dispersion check failed");
            return Err("Co-location detected: Sub-committee members exhibit artificial sub-millisecond dispersion (co-located VPC/rack)");
        }

        Ok(std_dev)
    }

    /// Calculates non-linear Quadratic Anti-Correlation Slashing penalty for simultaneously failing nodes.
    ///
    /// Formula:
    /// $$\text{SlashingRate}(k, N) = \min\left(1.0, \; \text{BaseRate} \times \left(\frac{k}{N}\right)^2 \times 100\right)$$
    ///
    /// Example:
    /// - $k = 1, N = 100 \implies (1/100)^2 \times 100 = 0.01\%$ penalty (isolated home-lab outage).
    /// - $k = 40, N = 100 \implies (40/100)^2 \times 100 = 16.0\%$ penalty (major cloud outage).
    /// - $k = 80, N = 100 \implies (80/100)^2 \times 100 = 64.0\%$ penalty (mass outage).
    #[must_use]
    pub fn calculate_anti_correlation_slashing_penalty(
        failing_nodes_count: usize,
        total_validator_count: usize,
        staked_balance: U256,
    ) -> U256 {
        if total_validator_count == 0 || failing_nodes_count == 0 {
            return U256::ZERO;
        }

        let k = U256::from(failing_nodes_count);
        let n = U256::from(total_validator_count);

        let numerator = staked_balance * (k * k);
        let denominator = n * n;

        (numerator / denominator).min(staked_balance)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Personalized PageRank Trust Engine & Directed Graph Math
// ─────────────────────────────────────────────────────────────────────────────

/// Directed trust edge between soulbound agent wallets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustEdge {
    pub from: Address,
    pub to: Address,
    pub weight: f64,
    pub co_committee_agreement_count: u32,
}

/// Personalized PageRank trust graph engine with hard-coded decay mechanisms.
#[derive(Debug, Clone)]
pub struct PersonalizedPageRankEngine {
    /// Damping factor (default: 0.85)
    pub damping_factor: f64,
    /// Monthly temporal decay rate (default: 0.05 = 5%)
    pub temporal_decay_rate: f64,
    /// Directed adjacency list: from_node -> [(to_node, weight)]
    pub trust_graph: HashMap<Address, Vec<(Address, f64)>>,
    /// Registered soulbound agents
    pub agents: Vec<Address>,
}

impl Default for PersonalizedPageRankEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PersonalizedPageRankEngine {
    /// Creates a new PageRank trust engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            damping_factor: 0.85,
            temporal_decay_rate: 0.05,
            trust_graph: HashMap::new(),
            agents: Vec::new(),
        }
    }

    /// Registers a soulbound agent if not already present.
    pub fn register_agent(&mut self, agent: Address) {
        if !self.agents.contains(&agent) {
            self.agents.push(agent);
        }
    }

    /// Adds an explicit on-chain directed trust relationship (created via signed ERC-4337 user-op).
    pub fn add_trust_edge(&mut self, from: Address, to: Address, co_committee_agreements: u32) {
        self.register_agent(from);
        self.register_agent(to);

        // Weight = f(co-committee agreement history) * existence_of_follow_edge
        let weight = (1.0 + (co_committee_agreements as f64) * 0.1).max(0.1);
        let entry = self.trust_graph.entry(from).or_default();
        if let Some(existing) = entry.iter_mut().find(|(target, _)| *target == to) {
            existing.1 = weight;
        } else {
            entry.push((to, weight));
        }
    }

    /// Computes Personalized PageRank vector R_i(.) for agent i.
    ///
    /// Equation:
    /// $$R_i(j) = (1 - d) \cdot s_i(j) + d \cdot \sum_{k \to j} \left(\frac{w_{kj}}{\text{out}_k}\right) \cdot R_i(k)$$
    pub fn compute_personalized_pagerank(&self, source: Address, max_iterations: usize) -> HashMap<Address, f64> {
        let n = self.agents.len();
        if n == 0 {
            return HashMap::new();
        }

        let mut r: HashMap<Address, f64> = HashMap::new();
        for &agent in &self.agents {
            r.insert(agent, if agent == source { 1.0 } else { 0.0 });
        }

        let d = self.damping_factor;
        let teleport = 1.0 - d;

        // Compute total outgoing weights out_k
        let mut out_weights: HashMap<Address, f64> = HashMap::new();
        for (&from, targets) in &self.trust_graph {
            let sum: f64 = targets.iter().map(|(_, w)| *w).sum();
            out_weights.insert(from, sum);
        }

        for _ in 0..max_iterations {
            let mut next_r: HashMap<Address, f64> = HashMap::new();
            for &j in &self.agents {
                // (1 - d) * s_i(j)
                let s_ij = if j == source { 1.0 } else { 0.0 };
                let mut sum_incoming = 0.0;

                // Find all k -> j
                for &k in &self.agents {
                    if let Some(targets) = self.trust_graph.get(&k) {
                        if let Some((_, w_kj)) = targets.iter().find(|(target, _)| *target == j) {
                            let out_k = out_weights.get(&k).copied().unwrap_or(1.0);
                            if out_k > 1e-9 {
                                let r_k = r.get(&k).copied().unwrap_or(0.0);
                                sum_incoming += (w_kj / out_k) * r_k;
                            }
                        }
                    }
                }

                let new_score = teleport * s_ij + d * sum_incoming;
                next_r.insert(j, new_score);
            }
            r = next_r;
        }

        // Apply Connectivity Decay: if max node-disjoint paths <= 2 => R_i(j) *= 0.90
        for (&j, score) in r.iter_mut() {
            if j != source {
                let disjoint_paths = self.estimate_node_disjoint_paths(source, j);
                if disjoint_paths <= 2 {
                    *score *= 0.90;
                }
            }
        }

        r
    }

    /// Estimates node-disjoint paths between source and target for connectivity decay.
    pub fn estimate_node_disjoint_paths(&self, source: Address, target: Address) -> usize {
        if source == target {
            return usize::MAX;
        }
        // Direct edge counts as 1 path
        let mut paths = 0;
        if let Some(targets) = self.trust_graph.get(&source) {
            if targets.iter().any(|(t, _)| *t == target) {
                paths += 1;
            }
        }
        // Check 2-hop disjoint intermediaries
        if let Some(source_targets) = self.trust_graph.get(&source) {
            for (inter, _) in source_targets {
                if *inter != target && *inter != source {
                    if let Some(inter_targets) = self.trust_graph.get(inter) {
                        if inter_targets.iter().any(|(t, _)| *t == target) {
                            paths += 1;
                        }
                    }
                }
            }
        }
        paths
    }

    /// Applies monthly temporal decay: R_i(j) <- (1 - gamma) * R_i(j) + delta_R_new
    pub fn apply_temporal_decay(score: f64, delta_r_new: f64, gamma: f64) -> f64 {
        (1.0 - gamma) * score + delta_r_new
    }

    /// Deterministic placeholder identity for unclaimed off-chain content.
    #[must_use]
    pub fn deterministic_placeholder_identity(user_id: &str) -> B256 {
        alloy_primitives::keccak256(user_id.as_bytes())
    }
}
