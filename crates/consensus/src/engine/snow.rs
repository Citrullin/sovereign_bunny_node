//! # Snow Family Consensus Library (Snowflake, Snowball, Snowman)
//!
//! Implements the Snow-family consensus voters (Snowflake, Snowball, Snowman)
//! to establish decentralized probabilistic agreement across the manifold network.

use std::collections::HashMap;
use alloy_primitives::Address;

/// 1. Snowflake Voter: Binary/Single-event voter without confidence counters.
/// Ideal for observer sub-committees verifying external event states.
#[derive(Debug, Clone)]
pub struct SnowflakeVoter<T: Clone + Eq + std::hash::Hash> {
    pub current_preference: Option<T>,
    pub consecutive_successes: u32,
    pub finalized_value: Option<T>,
    pub k: usize,
    pub alpha: f64,
    pub beta: u32,
}

impl<T: Clone + Eq + std::hash::Hash> SnowflakeVoter<T> {
    pub fn new(k: usize, alpha: f64, beta: u32) -> Self {
        Self {
            current_preference: None,
            consecutive_successes: 0,
            finalized_value: None,
            k,
            alpha,
            beta,
        }
    }

    pub fn record_round(&mut self, responses: &[T]) {
        if self.finalized_value.is_some() || responses.is_empty() {
            return;
        }

        let mut counts = HashMap::new();
        for r in responses {
            *counts.entry(r.clone()).or_insert(0) += 1;
        }

        let mut majority_candidate = None;
        let mut max_count = 0;
        for (cand, count) in counts {
            if count > max_count {
                max_count = count;
                majority_candidate = Some(cand);
            }
        }

        if let Some(candidate) = majority_candidate {
            let threshold = (self.k as f64 * self.alpha).ceil() as usize;
            if max_count >= threshold {
                if Some(&candidate) == self.current_preference.as_ref() {
                    self.consecutive_successes += 1;
                } else {
                    self.current_preference = Some(candidate);
                    self.consecutive_successes = 1;
                }

                if self.consecutive_successes >= self.beta {
                    self.finalized_value = self.current_preference.clone();
                }
            } else {
                self.consecutive_successes = 0;
            }
        }
    }
}

/// 2. Snowball Voter: Confidence-based multi-choice voter.
/// Ideal for account-lattice double-spend path resolution.
#[derive(Debug, Clone)]
pub struct SnowballVoter<T: Clone + Eq + std::hash::Hash> {
    pub current_preference: Option<T>,
    pub confidence_counters: HashMap<T, u32>,
    pub consecutive_successes: u32,
    pub finalized_value: Option<T>,
    pub k: usize,
    pub alpha: f64,
    pub beta: u32,
}

impl<T: Clone + Eq + std::hash::Hash> SnowballVoter<T> {
    pub fn new(k: usize, alpha: f64, beta: u32) -> Self {
        Self {
            current_preference: None,
            confidence_counters: HashMap::new(),
            consecutive_successes: 0,
            finalized_value: None,
            k,
            alpha,
            beta,
        }
    }

    pub fn record_round(&mut self, responses: &[T]) {
        if self.finalized_value.is_some() || responses.is_empty() {
            return;
        }

        let mut counts = HashMap::new();
        for r in responses {
            *counts.entry(r.clone()).or_insert(0) += 1;
        }

        let mut majority_candidate = None;
        let mut max_count = 0;
        for (cand, count) in counts {
            if count > max_count {
                max_count = count;
                majority_candidate = Some(cand);
            }
        }

        if let Some(candidate) = majority_candidate {
            let threshold = (self.k as f64 * self.alpha).ceil() as usize;
            if max_count >= threshold {
                // Increment counter and release borrow
                {
                    let conf = self.confidence_counters.entry(candidate.clone()).or_insert(0);
                    *conf += 1;
                }

                if self.current_preference.is_none() {
                    self.current_preference = Some(candidate.clone());
                    self.consecutive_successes = 1;
                } else if Some(&candidate) == self.current_preference.as_ref() {
                    self.consecutive_successes += 1;
                } else {
                    let prev_cand = self.current_preference.as_ref().unwrap();
                    let prev_conf = self.confidence_counters.get(prev_cand).copied().unwrap_or(0);
                    let new_conf = self.confidence_counters.get(&candidate).copied().unwrap_or(0);
                    if new_conf > prev_conf {
                        self.current_preference = Some(candidate);
                    }
                    self.consecutive_successes = 1;
                }

                if self.consecutive_successes >= self.beta {
                    self.finalized_value = self.current_preference.clone();
                }
            } else {
                self.consecutive_successes = 0;
            }
        }
    }
}

/// 3. Snowman Voter: Linear chain consensus engine built on top of Snowball.
/// Ideal for Epoch boundary and global jurisdiction state checkpointing.
#[derive(Debug, Clone)]
pub struct SnowmanVoter<T: Clone + Eq + std::hash::Hash> {
    pub inner_snowball: SnowballVoter<T>,
    pub parent_map: HashMap<T, T>,
}

impl<T: Clone + Eq + std::hash::Hash> SnowmanVoter<T> {
    pub fn new(k: usize, alpha: f64, beta: u32) -> Self {
        Self {
            inner_snowball: SnowballVoter::new(k, alpha, beta),
            parent_map: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: T, parent: T) {
        self.parent_map.insert(node, parent);
    }

    pub fn record_round(&mut self, responses: &[T]) {
        self.inner_snowball.record_round(responses);
    }
}

/// Helper to perform Efraimidis-Spirakis weighted sampling over active validators.
pub fn sample_peers_weighted(
    validators: &[(Address, f64)],
    k: usize,
    seed: u64,
) -> Vec<Address> {
    if validators.is_empty() || k == 0 {
        return Vec::new();
    }

    use rand::prelude::*;
    use rand_chacha::ChaCha8Rng;

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut candidates: Vec<(Address, f64)> = validators
        .iter()
        .map(|(addr, score)| {
            let weight = (score.max(0.01)).powi(2);
            let u: f64 = rng.gen_range(0.0..=1.0);
            let u_val = u.max(1e-9);
            let key = u_val.ln() / weight;
            (*addr, key)
        })
        .collect();

    candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    candidates.into_iter().take(k).map(|(addr, _)| addr).collect()
}
