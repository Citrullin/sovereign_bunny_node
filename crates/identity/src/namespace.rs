//! Namespace Registry & Resolution Module
//! Implements social-first name resolution with slot-based reputation scaling and staking backup.

use std::collections::HashMap;

/// Namespace resolution registry.
#[derive(Debug, Clone, Default)]
pub struct NamespaceRegistry {
    /// Maps a namespace to its current owner DID.
    pub names: HashMap<String, String>,
    /// Maps a DID to the list of names it has registered.
    pub did_names: HashMap<String, Vec<String>>,
    /// Maps a DID to its active stake amount for namespace protection.
    pub stakes: HashMap<String, u64>,
    /// Maps a DID to its recorded reputation score.
    pub reputations: HashMap<String, f64>,
}

impl NamespaceRegistry {
    /// Creates a new Namespace Registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculates the effective claim score of a DID for a potential name registration.
    ///
    /// The social layer is prioritized:
    /// - First 3 names (1 main, 2 secondary) incur no penalty.
    /// - Additional names face an exponential penalty on their reputation score.
    /// - Staking can augment the claim score, but the required stake scales up exponentially to protect against the social layer.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_precision_loss)]
    pub fn calculate_score(&self, did: &str, reputation: f64, proposed_stake: u64) -> f64 {
        let existing_names = self.did_names.get(did).map_or(0, Vec::len);
        
        // Slot system: up to 3 slots has no penalty.
        let extra_slots = if existing_names >= 3 {
            existing_names - 2 // 3rd slot is index 2, so 4th name means extra_slots = 1
        } else {
            0
        };

        // Exponential penalty on reputation: reputation / 10^extra_slots
        let penalty_divisor = 10.0_f64.powi(extra_slots as i32);
        let social_score = reputation / penalty_divisor;

        // Staking bonus. Converting stake to reputation weight.
        // Staking bonus is: proposed_stake / (100.0 * 2^extra_slots)
        // This makes staking for extra slots exponentially less efficient, representing the "losing fight" against the social layer.
        let staking_efficiency = 2.0_f64.powi(extra_slots as i32);
        let staking_bonus = (proposed_stake as f64) / (100.0 * staking_efficiency);

        social_score + staking_bonus
    }

    /// Attempts to register a name to a DID.
    ///
    /// If the name is already claimed, conflict resolution applies:
    /// - Compare the `calculate_score` of the current owner vs the challenger.
    /// - If the challenger wins, the name is transferred, and the previous owner's stake is returned (mocked).
    ///
    /// Returns `true` if registration succeeded (either fresh or via winning conflict resolution).
    pub fn register(&mut self, name: String, challenger_did: String, challenger_reputation: f64, stake: u64) -> bool {
        self.reputations.insert(challenger_did.clone(), challenger_reputation);

        if let Some(current_owner) = self.names.get(&name).cloned() {
            if current_owner == challenger_did {
                // Already owned by the challenger.
                return true;
            }

            // Conflict resolution using recorded owner reputation.
            let owner_reputation = self.reputations.get(&current_owner).copied().unwrap_or(1.0);
            let owner_stake = self.stakes.get(&current_owner).copied().unwrap_or(0);
            
            let owner_score = self.calculate_score(&current_owner, owner_reputation, owner_stake);
            let challenger_score = self.calculate_score(&challenger_did, challenger_reputation, stake);

            if challenger_score > owner_score {
                // Challenger wins. Evict old owner.
                if let Some(names) = self.did_names.get_mut(&current_owner) {
                    names.retain(|x| x != &name);
                }
                
                self.names.insert(name.clone(), challenger_did.clone());
                self.did_names.entry(challenger_did.clone()).or_default().push(name);
                self.stakes.insert(challenger_did, stake);
                true
            } else {
                false
            }
        } else {
            // Fresh registration
            self.names.insert(name.clone(), challenger_did.clone());
            self.did_names.entry(challenger_did.clone()).or_default().push(name);
            self.stakes.insert(challenger_did, stake);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_slots_and_penalties() {
        let mut registry = NamespaceRegistry::new();
        let alice = "did:peer:4:alice";

        // Alice claims 3 names. First 3 should have no penalty.
        assert!(registry.register("alice.sovereign".into(), alice.into(), 10.0, 0));
        assert!(registry.register("ali.sovereign".into(), alice.into(), 10.0, 0));
        assert!(registry.register("al.sovereign".into(), alice.into(), 10.0, 0));

        // Score for 4th name (extra_slots = 1)
        let score_4th = registry.calculate_score(alice, 10.0, 0);
        // reputation / 10^1 = 1.0
        assert!((score_4th - 1.0).abs() < f64::EPSILON);

        // Score for 5th name (extra_slots = 2)
        // We register a 4th name first
        assert!(registry.register("alice4.sovereign".into(), alice.into(), 10.0, 0));
        let score_5th = registry.calculate_score(alice, 10.0, 0);
        // reputation / 10^2 = 0.1
        assert!((score_5th - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_conflict_resolution_primary_vs_secondary() {
        let mut registry = NamespaceRegistry::new();
        let alice = "did:peer:4:alice";
        let bob = "did:peer:4:bob";

        // Alice has 4 names already, making this new name her 5th (extra_slots = 2)
        for i in 1..=4 {
            registry.register(format!("alice{i}.sovereign"), alice.into(), 10.0, 0);
        }

        // Alice claims "shared.sovereign" (her 5th name)
        registry.register("shared.sovereign".into(), alice.into(), 10.0, 0);

        // Bob has 0 names, so "shared.sovereign" is his primary (no penalty).
        // Bob has lower raw reputation (2.0) than Alice (10.0), but no penalty.
        // Alice's score: 10.0 / 10^2 = 0.1.
        // Bob's score: 2.0.
        // Bob should evict Alice.
        let success = registry.register("shared.sovereign".into(), bob.into(), 2.0, 0);
        assert!(success);
        assert_eq!(registry.names.get("shared.sovereign").unwrap(), bob);
    }

    #[test]
    fn test_staking_to_offset_penalty() {
        let mut registry = NamespaceRegistry::new();
        let alice = "did:peer:4:alice";
        let bob = "did:peer:4:bob";

        // Alice has 4 names.
        for i in 1..=4 {
            registry.register(format!("alice{i}.sovereign"), alice.into(), 10.0, 0);
        }
        
        // Alice claims "shared.sovereign" (her 5th) and stakes 400 tokens.
        // Alice's score: 1.0 / 10^3 + 400 / (100 * 2^3) = 0.001 + 0.5 = 0.501
        registry.register("shared.sovereign".into(), alice.into(), 10.0, 400);

        // Bob tries to claim with raw reputation 0.5 and no stake.
        // Bob's score: 0.5
        // Alice wins and retains ownership because of her stake.
        let bob_success = registry.register("shared.sovereign".into(), bob.into(), 0.5, 0);
        assert!(!bob_success);
        assert_eq!(registry.names.get("shared.sovereign").unwrap(), alice);
    }
}
