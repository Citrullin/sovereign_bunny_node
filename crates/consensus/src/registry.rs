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

/// Full resolved identity documents stored in the directory.
#[derive(Debug, Clone)]
pub struct RegisteredIdentity {
    /// Long-form `did:peer:...` or `did:sovereign:[chain_id]:...` string.
    pub did: String,
    /// Resolved DID document details.
    pub doc: sovereign_identity::did::SovereignDidDocument,
    /// Unix timestamp when the identity was registered.
    pub registered_at: u64,
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
    /// Full identity documents.
    pub identities: HashMap<String, RegisteredIdentity>,
    /// Chain ID of the node.
    pub chain_id: u64,
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
            identities: HashMap::new(),
            chain_id: 1337,
        }
    }

    /// Returns the registered DID of an address.
    pub fn get_did_by_address(&self, address: &Address) -> Option<String> {
        self.address_to_did.get(address).cloned()
    }

    /// Helper to normalize a query DID string (prepending did:peer: if it starts with 4zQm or z).
    pub fn normalize_query_did(did: &str) -> String {
        let trimmed = did.trim();
        if trimmed.starts_with("did:sovereign:") {
            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() == 4 {
                let id = parts[3];
                if !id.starts_with("0x") {
                    return format!("did:peer:{}", id);
                }
            }
        }
        if trimmed.starts_with("did:") {
            trimmed.to_string()
        } else if !trimmed.starts_with("0x") {
            format!("did:peer:{}", trimmed)
        } else {
            trimmed.to_string()
        }
    }

    /// Helper to extract an EVM address from a query DID if possible.
    pub fn extract_address_from_did(did: &str) -> Option<Address> {
        let norm_did = Self::normalize_query_did(did);
        if norm_did.starts_with("did:sovereign:") {
            let parts: Vec<&str> = norm_did.split(':').collect();
            if parts.len() == 4 {
                let clean = parts[3].trim_start_matches("0x");
                if clean.len() == 40 {
                    if let Ok(addr_bytes) = alloy_primitives::hex::decode(clean) {
                        return Some(Address::from_slice(&addr_bytes));
                    }
                }
            }
        }
        if let Some(pos) = norm_did.find("0x") {
            if norm_did.len() >= pos + 42 {
                let addr_str = &norm_did[pos..pos+42];
                if let Ok(addr) = addr_str.parse::<Address>() {
                    return Some(addr);
                }
            }
        }
        None
    }

    /// Search registered identities for any public key matching the query (multibase prefix-agnostic).
    pub fn find_identity_by_any_key(&self, query: &str) -> Option<&RegisteredIdentity> {
        let norm_query = Self::normalize_query_did(query);
        let clean_query = norm_query.strip_prefix("did:peer:").unwrap_or(&norm_query);
        if clean_query.starts_with('z') {
            if let Ok(decoded) = bs58::decode(&clean_query[1..]).into_vec() {
                for ident in self.identities.values() {
                    let doc = &ident.doc;
                    let primary_ident = if let Some(primary_did) = self.address_to_did.get(&doc.evm_address) {
                        self.identities.get(primary_did).unwrap_or(ident)
                    } else {
                        ident
                    };
                    if doc.secp256k1_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.secp256k1_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.ed25519_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.ed25519_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.bls_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.bls_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.ml_dsa_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.ml_dsa_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.slh_dsa_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.slh_dsa_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.falcon_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.falcon_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.xmss_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.xmss_pubkey) {
                        return Some(primary_ident);
                    }
                }
            }
        }
        None
    }

    /// Returns the EVM Address associated with a DID.
    pub fn get_address_by_did(&self, did: &str) -> Option<Address> {
        let norm_did = Self::normalize_query_did(did);
        if let Some(ident) = self.identities.get(&norm_did) {
            return Some(ident.doc.evm_address);
        }
        if let Some(ident) = self.find_identity_by_any_key(&norm_did) {
            return Some(ident.doc.evm_address);
        }
        if let Some(addr) = Self::extract_address_from_did(&norm_did) {
            if self.address_to_did.contains_key(&addr) {
                return Some(addr);
            }
        }
        self.address_to_did.iter()
            .find(|(_, d)| d.as_str() == norm_did.as_str())
            .map(|(&addr, _)| addr)
    }

    /// Checks if address is registered and returns its type.
    pub fn get_type_by_address(&self, address: &Address) -> Option<ValidatorType> {
        let did = self.address_to_did.get(address)?;
        self.validators.get(did).copied()
    }

    /// Checks if a DID is registered in the validator or user directory.
    pub fn is_did_registered(&self, did: &str) -> bool {
        let norm_did = Self::normalize_query_did(did);
        if self.peer_keys.contains_key(&norm_did) {
            return true;
        }
        if self.find_identity_by_any_key(&norm_did).is_some() {
            return true;
        }
        if let Some(addr) = Self::extract_address_from_did(&norm_did) {
            if let Some(mapped_did) = self.address_to_did.get(&addr) {
                return self.peer_keys.contains_key(mapped_did);
            }
        }
        false
    }

    /// Checks if a DID is fully registered (not a placeholder).
    pub fn is_did_fully_registered(&self, did: &str) -> bool {
        let norm_did = Self::normalize_query_did(did);
        if let Some(key) = self.peer_keys.get(&norm_did) {
            return *key != [0u8; 32];
        }
        if self.find_identity_by_any_key(&norm_did).is_some() {
            return true;
        }
        if let Some(addr) = Self::extract_address_from_did(&norm_did) {
            if let Some(mapped_did) = self.address_to_did.get(&addr) {
                if let Some(key) = self.peer_keys.get(mapped_did) {
                    return *key != [0u8; 32];
                }
            }
        }
        false
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
        if candidate_did.starts_with("did:peer:2") {
            return Err("Sovereign DID Error: did:peer:2 is deprecated and no longer supported. Please use did:peer:4.");
        }

        let doc = sovereign_identity::did::SovereignDidDocument::from_did_string(&candidate_did)
            .ok_or("Failed to resolve Sovereign DID document synchronously. Ensure it is a valid did:peer:4 or did:sovereign format.")?;

        if candidate_did.starts_with("did:peer:4") {
            // Check that all 7 required key types are present and complete
            if doc.evm_address == alloy_primitives::Address::ZERO
                || doc.ed25519_pubkey.is_empty()
                || doc.bls_pubkey.is_empty()
                || doc.ml_dsa_pubkey.is_empty()
                || doc.slh_dsa_pubkey.is_empty()
                || doc.falcon_pubkey.is_empty()
                || doc.xmss_pubkey.is_empty()
            {
                return Err("Sovereign DID Error: DID is missing required verification keys. A fully registered identity requires all 7 keys (Secp256k1, Ed25519, BLS, ML-DSA, SLH-DSA, Falcon, XMSS).");
            }
        }

        let addr = doc.evm_address;

        // Duplicate registration check
        if let Some(existing_did) = self.address_to_did.get(&addr) {
            if self.is_did_fully_registered(existing_did) {
                return Err("Sovereign DID Error: EVM Address is already registered to a complete identity.");
            }
        }

        // Non-zero key marks this as fully registered (can send transactions)
        self.peer_keys.insert(candidate_did.clone(), [0x01; 32]);
        self.address_to_did.insert(addr, candidate_did.clone());

        // Converted/Domain formats:
        // 1. Short did:peer:4 format: did:peer:4{hash_comp}
        let short_peer_did = if candidate_did.starts_with("did:peer:4") {
            let rest = candidate_did.strip_prefix("did:peer:4").unwrap();
            let colons: Vec<&str> = rest.split(':').collect();
            if !colons.is_empty() {
                Some(format!("did:peer:4{}", colons[0]))
            } else {
                None
            }
        } else {
            None
        };

        if let Some(ref sp_did) = short_peer_did {
            self.peer_keys.insert(sp_did.clone(), [0x01; 32]);
        }

        // 2. did:sovereign:{chain_id}:{id}
        let sovereign_hash_did = if candidate_did.starts_with("did:peer:4") {
            let rest = candidate_did.strip_prefix("did:peer:4").unwrap();
            let colons: Vec<&str> = rest.split(':').collect();
            if !colons.is_empty() {
                Some(format!("did:sovereign:{}:{}", self.chain_id, colons[0]))
            } else {
                None
            }
        } else {
            None
        };

        let sovereign_addr_did = format!("did:sovereign:{}:{addr:#x}", self.chain_id);

        if let Some(ref sh_did) = sovereign_hash_did {
            self.peer_keys.insert(sh_did.clone(), [0x01; 32]);
        }
        self.peer_keys.insert(sovereign_addr_did.clone(), [0x01; 32]);

        // Map EVM address to the sovereign address DID
        // Keep candidate_did as the primary mapping in address_to_did to return full DID document on reverse lookups.

        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        self.identities.insert(candidate_did.clone(), RegisteredIdentity {
            did: candidate_did.clone(),
            doc: doc.clone(),
            registered_at: now,
        });

        if let Some(ref sp_did) = short_peer_did {
            self.identities.insert(sp_did.clone(), RegisteredIdentity {
                did: sp_did.clone(),
                doc: doc.clone(),
                registered_at: now,
            });
        }
        if let Some(ref sh_did) = sovereign_hash_did {
            self.identities.insert(sh_did.clone(), RegisteredIdentity {
                did: sh_did.clone(),
                doc: doc.clone(),
                registered_at: now,
            });
        }
        self.identities.insert(sovereign_addr_did.clone(), RegisteredIdentity {
            did: sovereign_addr_did.clone(),
            doc: doc.clone(),
            registered_at: now,
        });

        Ok(addr)
    }

    /// Mock validator insertion helper for testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn add_mock_validator(&mut self, did: String, address: Address, peer_key: [u8; 32]) {
        self.peer_keys.insert(did.clone(), peer_key);
        self.address_to_did.insert(address, did.clone());
        self.validators.insert(did.clone(), ValidatorType::HardwareTEE);
        self.reputation.insert(did, 1.0);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_domain_conversion_and_lookup() {
        let mut registry = ValidatorRegistry::new(
            crate::config::StaticConfig::default(),
            std::sync::Arc::new(std::sync::RwLock::new(crate::config::DynamicConfig::default())),
        );
        registry.chain_id = 420;

        // Generate a valid did:peer:4 from a seed
        let seed = alloy_primitives::B256::repeat_byte(0xbc);
        let doc = sovereign_identity::did::SovereignDidDocument::derive_from_seed(seed);
        let original_did = doc.did_uri.clone();

        // Register the DID
        let addr_res = registry.register_user_did(original_did.clone());
        assert!(addr_res.is_ok());
        let addr = addr_res.unwrap();

        // Check lookup with original DID
        assert!(registry.is_did_registered(&original_did));
        assert!(registry.is_did_fully_registered(&original_did));
        assert_eq!(registry.get_address_by_did(&original_did), Some(addr));

        // Check lookup with short did:peer:4 DID (domain conversion)
        let short_peer_did = format!("did:peer:4{}", doc.short_form.strip_prefix("did:peer:4").unwrap_or(&doc.short_form));
        assert!(registry.is_did_registered(&short_peer_did));
        assert_eq!(registry.get_address_by_did(&short_peer_did), Some(addr));

        // Check lookup with did:sovereign:{chain_id}:{hash}
        let hash_part = original_did.strip_prefix("did:peer:4").unwrap().split(':').next().unwrap();
        let sovereign_hash_did = format!("did:sovereign:420:{hash_part}");
        assert!(registry.is_did_registered(&sovereign_hash_did));
        assert_eq!(registry.get_address_by_did(&sovereign_hash_did), Some(addr));

        // Check lookup with did:sovereign:{chain_id}:{address_hex}
        let sovereign_addr_did = format!("did:sovereign:420:{addr:#x}");
        assert!(registry.is_did_registered(&sovereign_addr_did));
        assert_eq!(registry.get_address_by_did(&sovereign_addr_did), Some(addr));

        // Check lookup with did:peer:0x... format (embedded EVM address)
        let did_peer_with_addr = format!("did:peer:{addr:#x}");
        assert!(registry.is_did_registered(&did_peer_with_addr));
        assert_eq!(registry.get_address_by_did(&did_peer_with_addr), Some(addr));

        // Verify reverse lookup of EVM Address returns the primary full did:peer:4 DID (with all curves)
        let resolved_primary_did = registry.get_did_by_address(&addr);
        assert_eq!(resolved_primary_did, Some(original_did.clone()));

        // Helper to encode multibase key
        let encode_mb = |prefix: &[u8], key: &[u8]| -> String {
            let mut combined = prefix.to_vec();
            combined.extend_from_slice(key);
            format!("did:peer:z{}", bs58::encode(&combined).into_string())
        };

        // Assert sub-key queries for all curves resolve to the correct identity
        let secp_query = encode_mb(&[0xe7, 0x01], &doc.secp256k1_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&secp_query).map(|i| &i.did), Some(&original_did));

        let ed_query = encode_mb(&[0xed, 0x01], &doc.ed25519_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&ed_query).map(|i| &i.did), Some(&original_did));

        let bls_query = encode_mb(&[0xea, 0x01], &doc.bls_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&bls_query).map(|i| &i.did), Some(&original_did));

        let ml_query = encode_mb(&[0x93, 0x01], &doc.ml_dsa_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&ml_query).map(|i| &i.did), Some(&original_did));

        let slh_query = encode_mb(&[0x94, 0x01], &doc.slh_dsa_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&slh_query).map(|i| &i.did), Some(&original_did));

        let falcon_query = encode_mb(&[0x92, 0x01], &doc.falcon_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&falcon_query).map(|i| &i.did), Some(&original_did));

        let xmss_query = encode_mb(&[0x95, 0x01], &doc.xmss_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&xmss_query).map(|i| &i.did), Some(&original_did));
    }
}