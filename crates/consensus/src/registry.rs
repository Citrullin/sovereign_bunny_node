//! `DPoT` Validator Directory module.

use alloy_primitives::Address;
use c_kzg::{Bytes32, Bytes48};
use k256::elliptic_curve::sec1::ToSec1Point as _;
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};

/// Represents the type of a validator in the `DPoT` system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// Hardware TEE validator (high security).
    HardwareTEE,
    /// Vanilla Social validator (reputation based).
    VanillaSocial,
}

/// `DPoT` Validator Directory with `TinyMeritRank` reputation using did:peer:4.
#[derive(Debug, Clone)]
pub struct ValidatorRegistry {
    /// Active validators mapped to their type.
    validators: HashMap<String, ValidatorType>,
    /// Resolved `WireGuard` keys mapped by DID.
    peer_keys: HashMap<String, [u8; 32]>,
    /// Mapping from resolved EVM Address to DID.
    address_to_did: HashMap<Address, String>,
    /// The seeds (bootstrap roots) of trust.
    seeds: HashSet<String>,
    /// Directed edges: `u_did` -> (`v_did`, weight) representing endorsements.
    pub endorsements: HashMap<String, HashMap<String, f64>>,
    /// Global reputation mapping: DID -> Score
    pub reputation: HashMap<String, f64>,
    /// Mapping of validator DID -> Set of Manifold IDs they are willing to route to.
    supported_manifolds: HashMap<String, HashSet<u64>>,
    /// Current block number tracked by the consensus engine
    pub current_block: u64,
    /// Store KZG commitments submitted by validators: DID -> 48-byte commitment
    pub commitments: HashMap<String, [u8; 48]>,
    /// Static configurations loaded at startup.
    pub static_cfg: crate::config::StaticConfig,
    /// Dynamic, hot-reloadable configurations.
    pub dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new(
            crate::config::StaticConfig::default(),
            std::sync::Arc::new(std::sync::RwLock::new(crate::config::DynamicConfig::default())),
        )
    }
}

impl ValidatorRegistry {
    /// Creates a new validator registry and bootstraps with default genesis seeds.
    ///
    /// # Panics
    /// Panics if bootstrap genesis peer DID creation fails.
    pub fn new(
        static_cfg: crate::config::StaticConfig,
        dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
    ) -> Self {
        let mut registry = Self {
            validators: HashMap::new(),
            peer_keys: HashMap::new(),
            address_to_did: HashMap::new(),
            endorsements: HashMap::new(),
            supported_manifolds: HashMap::new(),
            seeds: HashSet::new(),
            reputation: HashMap::new(),
            current_block: 0,
            commitments: HashMap::new(),
            static_cfg,
            dynamic_cfg,
        };

        // Bootstrap with genesis seeds
        let keys = vec![did_peer::DIDPeerCreateKeys {
            type_: Some(did_peer::DIDPeerKeyType::Ed25519),
            purpose: did_peer::DIDPeerKeys::Verification,
            public_key_multibase: Some("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()),
        }];
        let (genesis_did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).expect("Genesis peer DID generation is deterministic and must succeed");
        let genesis_addr = Address::repeat_byte(0x99);

        registry.seeds.insert(genesis_did.clone());
        registry.validators.insert(genesis_did.clone(), ValidatorType::VanillaSocial);
        registry.peer_keys.insert(genesis_did.clone(), [0x99; 32]);
        registry.address_to_did.insert(genesis_addr, genesis_did.clone());

        // Self-endorsement for genesis seed to keep them in the PageRank loop
        let mut self_end = HashMap::new();
        self_end.insert(genesis_did.clone(), 1.0);
        registry.endorsements.insert(genesis_did, self_end);

        registry.compute_pagerank();
        registry
    }

    /// Submits an epoch commitment and proofs.
    ///
    /// # Errors
    /// Returns an error if the caller does not own the DID or if submission is not within the publishing window.
    pub fn submit_commitment(
        &mut self,
        caller: Address,
        did: String,
        commitment: [u8; 48],
        proof: [u8; 48],
        y: [u8; 32],
    ) -> Result<(), &'static str> {
        let caller_did = self.get_did_by_address(&caller).ok_or("Caller is not a registered validator")?;
        let caller_type = self.validators.get(&caller_did).ok_or("Caller type not found")?;

        if self.get_did_by_address(&caller).as_deref() != Some(did.as_str()) {
            // Posting on behalf of another node. Caller must be a TEE.
            if *caller_type != ValidatorType::HardwareTEE {
                return Err("Only TEE validators can submit commitments on behalf of other nodes");
            }
        } else {
            // Posting for themselves. Must be a TEE.
            if *caller_type != ValidatorType::HardwareTEE {
                return Err("Only TEE validators can calculate and submit their own commitments");
            }
        }

        if self.current_block % self.static_cfg.epoch.epoch_length > self.static_cfg.epoch.publishing_window {
            return Err("Not within the epoch publishing window");
        }

        let mut sorted_dids: Vec<_> = self.reputation.keys().collect();
        sorted_dids.sort();
        let index = sorted_dids.iter().position(|&d| d == &did).ok_or("DID not found in reputation map")?;

        let c_bytes = Bytes48::from_bytes(&commitment).map_err(|_| "Invalid commitment bytes")?;
        let p_bytes = Bytes48::from_bytes(&proof).map_err(|_| "Invalid proof bytes")?;
        let y_bytes = Bytes32::from_bytes(&y).map_err(|_| "Invalid y bytes")?;

        let is_valid = crate::kzg::PageRankKzg::verify_proof(&c_bytes, index, &y_bytes, &p_bytes)
            .map_err(|_| "KZG verification computation failed")?;

        if !is_valid {
            return Err("Invalid KZG polynomial evaluation proof");
        }

        self.commitments.insert(did, commitment);
        Ok(())
    }

    /// Resolves EVM Address and `WireGuard` key from DID and registers as TEE validator.
    ///
    /// # Errors
    /// Returns an error if the DID fails to resolve.
    pub fn register_sgx_node(&mut self, candidate_did: String) -> Result<(), &'static str> {
        let (addr, wg_key) = self.resolve_did_keys(&candidate_did)?;
        self.validators.insert(candidate_did.clone(), ValidatorType::HardwareTEE);
        self.peer_keys.insert(candidate_did.clone(), wg_key);
        self.address_to_did.insert(addr, candidate_did);
        Ok(())
    }

    /// Proposes a new social validator (creates initial endorsement).
    ///
    /// # Errors
    /// Returns an error if the proposer is not registered or candidate resolution fails.
    pub fn propose_validator(&mut self, proposer_addr: Address, candidate_did: String) -> Result<(), &'static str> {
        let _proposer_did = self.address_to_did.get(&proposer_addr)
            .ok_or("Proposer must be an active registered validator")?
            .clone();

        let (candidate_addr, wg_key) = self.resolve_did_keys(&candidate_did)?;
        self.peer_keys.insert(candidate_did.clone(), wg_key);
        self.address_to_did.insert(candidate_addr, candidate_did.clone());

        self.endorse_validator(proposer_addr, candidate_did, 1.0)
    }

    /// Endorses a candidate with a specific weight.
    ///
    /// # Errors
    /// Returns an error if the endorser is not registered.
    pub fn endorse_validator(&mut self, endorser_addr: Address, candidate_did: String, weight: f64) -> Result<(), &'static str> {
        let endorser_did = self.address_to_did.get(&endorser_addr)
            .ok_or("Endorser must be an active registered validator")?
            .clone();

        self.endorsements.entry(endorser_did).or_default().insert(candidate_did, weight);
        self.compute_pagerank();
        self.update_active_validators();
        Ok(())
    }

    #[allow(clippy::unused_self)]
    fn resolve_did_keys(&self, did: &str) -> Result<(Address, [u8; 32]), &'static str> {
        debug!(did, "Resolving DID keys");
        // Resolve using the identity crate on an isolated thread with its own tokio runtime to prevent deadlocks
        let did_str = did.to_string();
        let resolved = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "Failed to build local tokio runtime")?;
            rt.block_on(sovereign_identity::DidPeer4::resolve(&did_str))
        }).join().map_err(|_| "Thread panic during DID resolution")??;
        debug!(did, key_type = ?resolved.key_type, "DID resolved successfully");
        
        let mut wg_key = [0u8; 32];
        let bytes = &resolved.public_key;
        let len = bytes.len().min(32);
        wg_key[..len].copy_from_slice(&bytes[..len]);

        // Derive EVM Address
        let addr = match resolved.key_type {
            sovereign_identity::KeyType::Secp256k1 => {
                let pk = k256::PublicKey::from_sec1_bytes(&resolved.public_key)
                    .map_err(|_| "Failed to parse public key bytes")?;
                let uncompressed = pk.to_sec1_point(false);
                let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
                Address::from_slice(&hash[12..32])
            }
            sovereign_identity::KeyType::Ed25519 |
            sovereign_identity::KeyType::MlDsa |
            sovereign_identity::KeyType::SlhDsa |
            sovereign_identity::KeyType::Falcon => {
                // For other algorithms, hash public key bytes directly to produce EVM Address
                let hash = alloy_primitives::keccak256(&resolved.public_key);
                Address::from_slice(&hash[12..32])
            }
        };

        Ok((addr, wg_key))
    }

    /// Returns the active `WireGuard` peer keys.
    pub fn active_peers(&self) -> HashMap<[u8; 32], Address> {
        let mut active = HashMap::new();
        for (did, &peer_key) in &self.peer_keys {
            if let Some(val_type) = self.validators.get(did) {
                // If the enclave is suspected to be compromised and reputation threshold is set,
                // verify that the SGX node also possesses sufficient social reputation.
                let sgx_threshold = self.dynamic_cfg.read().unwrap().sgx_reputation_threshold;
                if *val_type == ValidatorType::HardwareTEE && sgx_threshold > 0.0 {
                    let rep = self.reputation.get(did).copied().unwrap_or(0.0);
                    if rep < sgx_threshold {
                        continue;
                    }
                }
                // Find EVM address for this DID
                if let Some((&addr, _)) = self.address_to_did.iter().find(|(_, d)| *d == did) {
                    active.insert(peer_key, addr);
                }
            }
        }
        active
    }

    /// Registers a manifold that the validator is willing to route to.
    ///
    /// # Errors
    /// Returns an error if the DID is not registered as a validator.
    pub fn register_supported_manifold(&mut self, did: &str, target_manifold_id: u64) -> Result<(), &'static str> {
        if !self.validators.contains_key(did) {
            return Err("Only registered validators can declare routing support");
        }
        
        let entry = self.supported_manifolds.entry(did.to_string()).or_default();
        entry.insert(target_manifold_id);
        
        // Operator Warning if quorum is not met
        let mut total_supporters = 0;
        for manifolds in self.supported_manifolds.values() {
            if manifolds.contains(&target_manifold_id) {
                total_supporters += 1;
            }
        }
        
        let quorum_threshold = self.dynamic_cfg.read().unwrap().manifold_quorum_threshold;
        if total_supporters < quorum_threshold {
            warn!(
                did,
                target_manifold_id,
                total_supporters,
                threshold = quorum_threshold,
                "Insufficient quorum — manifold route is not yet secure/active",
            );
        }
        
        Ok(())
    }

    /// Returns the active EVM addresses of validators that route to a specific manifold.
    /// Only returns a route if the total quorum threshold is met.
    pub fn get_routable_validators(&self, target_manifold_id: u64) -> HashSet<Address> {
        let mut routable = HashSet::new();
        let active = self.active_peers();
        
        // Active returns peer_key -> Address. We need to iterate over Address -> DID -> supported
        for addr in active.values() {
            if let Some(did) = self.get_did_by_address(addr) {
                if let Some(manifolds) = self.supported_manifolds.get(&did) {
                    if manifolds.contains(&target_manifold_id) {
                        routable.insert(*addr);
                    }
                }
            }
        }
        
        // Enforce Quorum Threshold
        let quorum_threshold = self.dynamic_cfg.read().unwrap().manifold_quorum_threshold;
        if routable.len() < quorum_threshold {
            return HashSet::new(); // Route is disabled
        }
        
        routable
    }

    /// Filters routable validators for target_manifold_id that meet the minimum orchestrator reputation/merit threshold.
    pub fn get_eligible_orchestrators(&self, target_manifold_id: u64, min_orchestrator_merit: f64) -> HashSet<Address> {
        let mut eligible = HashSet::new();
        for addr in self.get_routable_validators(target_manifold_id) {
            if self.get_reputation_by_address(&addr) >= min_orchestrator_merit {
                eligible.insert(addr);
            }
        }
        eligible
    }

    /// Computes `TinyMeritRank` reputation using Personalized `PageRank`.
    #[allow(clippy::cast_precision_loss)]
    pub fn compute_pagerank(&mut self) {
        if self.seeds.is_empty() {
            return;
        }

        let d = self.static_cfg.pagerank.damping_factor;
        let teleport_prob = 1.0 - d;
        let iterations = self.static_cfg.pagerank.max_iterations;

        // Collect all unique nodes in the graph
        let mut nodes = HashSet::new();
        for seed in &self.seeds {
            nodes.insert(seed.clone());
        }
        for (u, targets) in &self.endorsements {
            nodes.insert(u.clone());
            for v in targets.keys() {
                nodes.insert(v.clone());
            }
        }

        // Initialize PageRank scores
        let mut pr: HashMap<String, f64> = nodes.iter().map(|addr| (addr.clone(), 1.0 / nodes.len() as f64)).collect();

        // Compute out-going weights
        let mut out_weights: HashMap<String, f64> = HashMap::new();
        for (u, targets) in &self.endorsements {
            let total: f64 = targets.values().sum();
            out_weights.insert(u.clone(), total);
        }

        // Power Iteration
        for _ in 0..iterations {
            let mut next_pr: HashMap<String, f64> = nodes.iter().map(|addr| (addr.clone(), 0.0)).collect();

            for u in &nodes {
                let u_pr = *pr.get(u).unwrap_or(&0.0);
                if let Some(targets) = self.endorsements.get(u) {
                    let total_weight = *out_weights.get(u).unwrap_or(&0.0);
                    if total_weight > 0.0 {
                        for (v, &weight) in targets {
                            let share = (weight / total_weight) * u_pr * d;
                            *next_pr.entry(v.clone()).or_default() += share;
                        }
                    } else {
                        // Distribute to seeds
                        for seed in &self.seeds {
                            *next_pr.entry(seed.clone()).or_default() += (u_pr * d) / self.seeds.len() as f64;
                        }
                    }
                } else {
                    // Distribute to seeds
                    for seed in &self.seeds {
                        *next_pr.entry(seed.clone()).or_default() += (u_pr * d) / self.seeds.len() as f64;
                    }
                }

                // Add teleport probability
                if self.seeds.contains(u) {
                    *next_pr.entry(u.clone()).or_default() += teleport_prob / self.seeds.len() as f64;
                }
            }
            pr = next_pr;
        }

        // Apply Connectivity Decay (Phase 6)
        // For each node j, calculate max node-disjoint paths from any seed to j.
        // If paths <= 2, apply a 10% penalty.
        let graph: HashMap<String, Vec<String>> = self.endorsements.iter()
            .map(|(u, targets)| (u.clone(), targets.keys().cloned().collect()))
            .collect();

        for node in &nodes {
            if self.seeds.contains(node) {
                continue; // Seeds are not penalized
            }
            let paths = Self::max_node_disjoint_paths(&self.seeds, node, &graph);
            if paths <= 2 {
                if let Some(score) = pr.get_mut(node) {
                    *score *= 0.90; // 10% penalty
                }
            }
        }

        self.reputation = pr;
    }

    /// Computes max node-disjoint paths from a set of sources to a target using Edmonds-Karp on a node-split graph.
    fn max_node_disjoint_paths(sources: &HashSet<String>, target: &String, graph: &HashMap<String, Vec<String>>) -> usize {
        let mut capacity: HashMap<(String, String), i32> = HashMap::new();
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        
        let mut add_edge = |u: String, v: String, cap: i32| {
            adj.entry(u.clone()).or_default().push(v.clone());
            adj.entry(v.clone()).or_default().push(u.clone()); // reverse edge for residual graph
            capacity.insert((u.clone(), v.clone()), cap);
            capacity.insert((v, u), 0);
        };

        for (u, neighbors) in graph {
            add_edge(format!("{u}_in"), format!("{u}_out"), 1);
            for v in neighbors {
                add_edge(format!("{u}_out"), format!("{v}_in"), 10000);
            }
        }
        
        let super_source = "SUPER_SOURCE".to_string();
        for s in sources {
            add_edge(super_source.clone(), format!("{s}_in"), 10000);
        }
        let target_in = format!("{target}_in");
        
        let mut max_flow = 0;
        let mut flow: HashMap<(String, String), i32> = HashMap::new();

        loop {
            let mut parent: HashMap<String, String> = HashMap::new();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(super_source.clone());
            parent.insert(super_source.clone(), super_source.clone());
            
            let mut found = false;
            while let Some(u) = queue.pop_front() {
                if u == target_in {
                    found = true;
                    break;
                }
                if let Some(neighbors) = adj.get(&u) {
                    for v in neighbors {
                        let cap = *capacity.get(&(u.clone(), v.clone())).unwrap_or(&0);
                        let f = *flow.get(&(u.clone(), v.clone())).unwrap_or(&0);
                        if !parent.contains_key(v) && cap - f > 0 {
                            parent.insert(v.clone(), u.clone());
                            queue.push_back(v.clone());
                        }
                    }
                }
            }
            
            if !found {
                break;
            }
            
            let mut path_flow = i32::MAX;
            let mut curr = target_in.clone();
            while curr != super_source {
                let p = parent.get(&curr).expect("BFS path guarantees predecessor exists");
                let cap = *capacity.get(&(p.clone(), curr.clone())).expect("Graph build guarantees capacity edge exists");
                let f = *flow.get(&(p.clone(), curr.clone())).unwrap_or(&0);
                path_flow = path_flow.min(cap - f);
                curr = p.clone();
            }
            
            let mut curr = target_in.clone();
            while curr != super_source {
                let p = parent.get(&curr).expect("BFS path guarantees predecessor exists");
                *flow.entry((p.clone(), curr.clone())).or_insert(0) += path_flow;
                *flow.entry((curr.clone(), p.clone())).or_insert(0) -= path_flow;
                curr = p.clone();
            }
            max_flow += path_flow;
        }
        
        #[allow(clippy::cast_sign_loss)]
        {
            max_flow as usize
        }
    }

    fn update_active_validators(&mut self) {
        let promo_threshold = self.dynamic_cfg.read().unwrap().social_promotion_threshold;
        for (did, &rep) in &self.reputation {
            if rep >= promo_threshold && !self.validators.contains_key(did) {
                self.validators.insert(did.clone(), ValidatorType::VanillaSocial);
            }
        }
    }

    /// Applies monthly temporal decay: `R_i(j)` = (1 - gamma) * `R_i(j)` + `delta_R` * gamma
    pub fn apply_temporal_decay(&mut self) {
        let gamma = self.static_cfg.pagerank.temporal_decay_gamma;
        let delta_r = self.static_cfg.pagerank.temporal_decay_delta_r;
        for rep in self.reputation.values_mut() {
            *rep = (1.0 - gamma) * (*rep) + delta_r * gamma;
        }
        self.update_active_validators();
    }

    /// Checks if address is registered and returns its type.
    pub fn get_type_by_address(&self, address: &Address) -> Option<ValidatorType> {
        let did = self.address_to_did.get(address)?;
        self.validators.get(did).copied()
    }

    /// Returns the registered DID of an address.
    pub fn get_did_by_address(&self, address: &Address) -> Option<String> {
        self.address_to_did.get(address).cloned()
    }

    /// Returns the EVM Address associated with a DID.
    pub fn get_address_by_did(&self, did: &str) -> Option<Address> {
        self.address_to_did.iter()
            .find(|(_, d)| *d == did)
            .map(|(&addr, _)| addr)
    }

    /// Returns the reputation of a validator by address.
    pub fn get_reputation_by_address(&self, address: &Address) -> f64 {
        let Some(did) = self.address_to_did.get(address) else { return 0.0; };
        self.reputation.get(did).copied().unwrap_or(0.0)
    }

    /// Sets the reputation score for a DID (used in testing).
    #[cfg(test)]
    pub fn set_reputation(&mut self, did: String, value: f64) {
        self.reputation.insert(did, value);
    }

    /// Adds a mock validator directly (used in testing).
    #[cfg(test)]
    pub fn add_mock_validator(&mut self, did: String, addr: Address, peer_key: [u8; 32]) {
        self.validators.insert(did.clone(), ValidatorType::VanillaSocial);
        self.peer_keys.insert(did.clone(), peer_key);
        self.address_to_did.insert(addr, did);
    }

    /// Adds a mock TEE validator directly (used in testing).
    #[cfg(test)]
    pub fn add_mock_tee_validator(&mut self, did: String, addr: Address, peer_key: [u8; 32]) {
        self.validators.insert(did.clone(), ValidatorType::HardwareTEE);
        self.peer_keys.insert(did.clone(), peer_key);
        self.address_to_did.insert(addr, did);
    }
}

use std::sync::{OnceLock, RwLock};

/// Global static validator registry.
pub static VALIDATOR_REGISTRY: OnceLock<RwLock<ValidatorRegistry>> = OnceLock::new();

/// Returns a static reference to the shared thread-safe validator registry.
pub fn get_registry() -> &'static RwLock<ValidatorRegistry> {
    VALIDATOR_REGISTRY.get_or_init(|| {
        RwLock::new(ValidatorRegistry::new(
            crate::config::StaticConfig::default(),
            std::sync::Arc::new(std::sync::RwLock::new(crate::config::DynamicConfig::default())),
        ))
    })
}

/// Initializes the global validator registry with custom configurations.
///
/// # Errors
/// Returns an error if the registry has already been initialized.
pub fn init_registry(
    static_cfg: crate::config::StaticConfig,
    dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
) -> Result<(), &'static str> {
    VALIDATOR_REGISTRY
        .set(RwLock::new(ValidatorRegistry::new(static_cfg, dynamic_cfg)))
        .map_err(|_| "Global registry has already been initialized")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connectivity_decay() {
        let mut registry = ValidatorRegistry::default();
        registry.seeds.clear();
        registry.validators.clear();
        registry.endorsements.clear();
        
        let seed = "did:peer:SEED".to_string();
        registry.seeds.insert(seed.clone());
        
        let node_a = "did:peer:A".to_string(); 
        let node_b = "did:peer:B".to_string(); 
        
        let mut seed_end = HashMap::new();
        seed_end.insert("did:peer:P1".to_string(), 1.0);
        seed_end.insert("did:peer:P2".to_string(), 1.0);
        seed_end.insert("did:peer:P3".to_string(), 1.0);
        seed_end.insert("did:peer:P4".to_string(), 1.0);
        registry.endorsements.insert(seed.clone(), seed_end);

        registry.endorsements.insert("did:peer:P1".to_string(), { let mut m = HashMap::new(); m.insert(node_a.clone(), 1.0); m });
        registry.endorsements.insert("did:peer:P2".to_string(), { let mut m = HashMap::new(); m.insert(node_a.clone(), 1.0); m });
        registry.endorsements.insert("did:peer:P3".to_string(), { let mut m = HashMap::new(); m.insert(node_a.clone(), 1.0); m });
        
        registry.endorsements.insert("did:peer:P4".to_string(), { let mut m = HashMap::new(); m.insert(node_b.clone(), 1.0); m });

        registry.endorsements.insert(node_a.clone(), { let mut m = HashMap::new(); m.insert(node_a.clone(), 1.0); m });
        registry.endorsements.insert(node_b.clone(), { let mut m = HashMap::new(); m.insert(node_b.clone(), 1.0); m });

        registry.compute_pagerank();
        
        let rep_a = *registry.reputation.get(&node_a).unwrap_or(&0.0);
        let rep_b = *registry.reputation.get(&node_b).unwrap_or(&0.0);
        
        assert!(rep_a > rep_b);
    }

    #[test]
    fn test_cartel_slashing_scenario() {
        let mut registry = ValidatorRegistry::default();
        registry.reputation.insert("did:peer:A".to_string(), 1.0);
        registry.reputation.insert("did:peer:B".to_string(), 1.0);
        registry.reputation.insert("did:peer:C".to_string(), 1.0);

        // A and B endorse each other mutually (cartel)
        let mut end_a = HashMap::new();
        end_a.insert("did:peer:B".to_string(), 1.0);
        registry.endorsements.insert("did:peer:A".to_string(), end_a);

        let mut end_b = HashMap::new();
        end_b.insert("did:peer:A".to_string(), 1.0);
        registry.endorsements.insert("did:peer:B".to_string(), end_b);

        // C endorses D (no loop)
        let mut end_c = HashMap::new();
        end_c.insert("did:peer:D".to_string(), 1.0);
        registry.endorsements.insert("did:peer:C".to_string(), end_c);

        // Trigger cartel slashing
        crate::slashing::SlashingManager::slash_cartels(&mut registry, 0.5);

        // A and B should be slashed by 0.5
        assert!((*registry.reputation.get("did:peer:A").unwrap() - 0.5).abs() < f64::EPSILON);
        assert!((*registry.reputation.get("did:peer:B").unwrap() - 0.5).abs() < f64::EPSILON);
        // C should not be slashed
        assert!((*registry.reputation.get("did:peer:C").unwrap() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_epoch_rollover_slashing_scenario() {
        let mut registry = ValidatorRegistry::default();
        registry.reputation.insert("did:peer:A".to_string(), 1.0);
        registry.reputation.insert("did:peer:B".to_string(), 1.0);

        // Node A submits commitment
        registry.commitments.insert("did:peer:A".to_string(), [0u8; 48]);

        // Trigger missing commitment slashing
        crate::slashing::SlashingManager::slash_missing_commitments(&mut registry, 0.4);

        // Node A did submit, so reputation stays 1.0
        assert!((*registry.reputation.get("did:peer:A").unwrap() - 1.0).abs() < f64::EPSILON);
        // Node B missed, so reputation slashed by 0.4 -> 0.6
        assert!((*registry.reputation.get("did:peer:B").unwrap() - 0.6).abs() < f64::EPSILON);
        // Commitments list should be reset/cleared for the next epoch
        assert!(registry.commitments.is_empty());
    }
}

