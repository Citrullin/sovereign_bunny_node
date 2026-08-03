//! `DPoT` Validator Directory module.

use alloy_primitives::Address;
use std::collections::{HashMap, HashSet};

/// Represents the type of a validator in the `DPoT` system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// Hardware TEE validator (high security).
    HardwareTEE,
    /// Vanilla Social validator (reputation based).
    VanillaSocial,
}

/// `DPoT` Validator Directory with `TinyMeritRank` reputation.
#[derive(Debug, Clone)]
pub struct ValidatorRegistry {
    validators: HashMap<String, ValidatorType>,
    /// Resolved `WireGuard` keys mapped by DID.
    pub peer_keys: HashMap<String, [u8; 32]>,
    /// Mapping from resolved EVM Address to DID.
    pub address_to_did: HashMap<Address, String>,
    _seeds: HashSet<String>,
    /// Directed edges representing endorsements.
    pub endorsements: HashMap<String, HashMap<String, f64>>,
    /// Global reputation mapping: DID -> Score
    pub reputation: HashMap<String, f64>,
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
    /// Creates a new validator registry instance.
    pub fn new(
        static_cfg: crate::config::StaticConfig,
        dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
    ) -> Self {
        Self {
            validators: HashMap::new(),
            peer_keys: HashMap::new(),
            address_to_did: HashMap::new(),
            endorsements: HashMap::new(),
            supported_manifolds: HashMap::new(),
            _seeds: HashSet::new(),
            reputation: HashMap::new(),
            current_block: 0,
            commitments: HashMap::new(),
            static_cfg,
            dynamic_cfg,
        }
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

    /// Checks if address is registered and returns its type.
    pub fn get_type_by_address(&self, address: &Address) -> Option<ValidatorType> {
        let did = self.address_to_did.get(address)?;
        self.validators.get(did).copied()
    }

    /// Checks if a DID is registered in the validator or user directory.
    pub fn is_did_registered(&self, did: &str) -> bool {
        self.peer_keys.contains_key(did)
    }

    /// Checks if a DID is fully registered (not a placeholder).
    pub fn is_did_fully_registered(&self, did: &str) -> bool {
        if let Some(key) = self.peer_keys.get(did) {
            *key != [0u8; 32]
        } else {
            false
        }
    }

    /// Returns the active `WireGuard` peer keys and their mapped addresses.
    pub fn active_peers(&self) -> HashMap<[u8; 32], Address> {
        let mut active = HashMap::new();
        for (did, &peer_key) in &self.peer_keys {
            if let Some(val_type) = self.validators.get(did) {
                let sgx_threshold = self.dynamic_cfg.read().unwrap().sgx_reputation_threshold;
                if *val_type == ValidatorType::HardwareTEE && sgx_threshold > 0.0 {
                    let rep = self.reputation.get(did).copied().unwrap_or(0.0);
                    if rep < sgx_threshold {
                        continue;
                    }
                }
                if let Some((&addr, _)) = self.address_to_did.iter().find(|(_, d)| *d == did) {
                    active.insert(peer_key, addr);
                }
            }
        }
        active
    }

    /// Returns routable validators for a target manifold ID.
    pub fn get_routable_validators(&self, target_manifold_id: u64) -> HashSet<Address> {
        let mut routable = HashSet::new();
        let active = self.active_peers();
        for addr in active.values() {
            if let Some(did) = self.get_did_by_address(addr) {
                if let Some(manifolds) = self.supported_manifolds.get(&did) {
                    if manifolds.contains(&target_manifold_id) {
                        routable.insert(*addr);
                    }
                }
            }
        }
        let quorum_threshold = self.dynamic_cfg.read().unwrap().manifold_quorum_threshold;
        if routable.len() < quorum_threshold {
            return HashSet::new();
        }
        routable
    }

    /// Filters routable validators meeting the minimum orchestrator merit threshold.
    pub fn get_eligible_orchestrators(&self, target_manifold_id: u64, min_orchestrator_merit: f64) -> HashSet<Address> {
        let mut eligible = HashSet::new();
        for addr in self.get_routable_validators(target_manifold_id) {
            if self.get_reputation_by_address(&addr) >= min_orchestrator_merit {
                eligible.insert(addr);
            }
        }
        eligible
    }

    /// Returns the reputation score of a validator by address.
    pub fn get_reputation_by_address(&self, address: &Address) -> f64 {
        let Some(did) = self.address_to_did.get(address) else { return 0.0; };
        self.reputation.get(did).copied().unwrap_or(0.0)
    }

    /// Resolves and registers a user DID, mapping their EVM Address.
    pub fn register_user_did(&mut self, candidate_did: String) -> Result<Address, &'static str> {
        // Validate key completeness for did:peer:2 DIDs before registering.
        // A sovereign node requires BOTH secp256k1 (for EVM signing) and Ed25519 (for P2P/WireGuard).
        if candidate_did.starts_with("did:peer:2") {
            let components: Vec<&str> = candidate_did.split('.').collect();
            // components[0] = "did:peer:2", components[1..] = key fragments
            let key_parts: Vec<&str> = components.iter().skip(1).copied().collect();

            let has_secp256k1 = key_parts.iter().any(|part| {
                if let Some(rest) = part.strip_prefix("Vz") {
                    bs58::decode(rest).into_vec()
                        .map(|b| b.starts_with(&[0xe7, 0x01]))
                        .unwrap_or(false)
                } else {
                    false
                }
            });

            let has_ed25519 = key_parts.iter().any(|part| {
                if let Some(rest) = part.strip_prefix("Vz") {
                    bs58::decode(rest).into_vec()
                        .map(|b| b.starts_with(&[0xed, 0x01]))
                        .unwrap_or(false)
                } else {
                    false
                }
            });

            if !has_secp256k1 || !has_ed25519 {
                return Err("Sovereign DID Error: DID is missing required verification keys. Please provision Secp256k1 and Ed25519 keys.");
            }
        }

        let doc = sovereign_identity::did::SovereignDidDocument::from_did_string(&candidate_did)
            .ok_or("Failed to resolve Sovereign DID document synchronously")?;

        let addr = doc.evm_address;
        // Non-zero key marks this as fully registered (can send transactions)
        self.peer_keys.insert(candidate_did.clone(), [0x01; 32]);
        self.address_to_did.insert(addr, candidate_did);
        Ok(addr)
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
pub fn init_registry(
    static_cfg: crate::config::StaticConfig,
    dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
) -> Result<(), &'static str> {
    VALIDATOR_REGISTRY
        .set(RwLock::new(ValidatorRegistry::new(static_cfg, dynamic_cfg)))
        .map_err(|_| "Global registry has already been initialized")
}