//! # Address Interest Signaling Swarm & Guarded Communication Bus
//!
//! Provides deterministic Iroh-Gossip topic swarming, Cuckoo filter matching for
//! $O(1)$ stream filtering, and noise-isolated multi-tiered communication planes.

use alloy_primitives::{Address, B256};
use sovereign_identity::zk_merit::{GovernanceTier, ZkMeritProof};
use sovereign_ssz::signal::SignalEnvelope;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// In-memory Compressed Cuckoo Filter for O(1) monitored address lookup.
#[derive(Debug, Clone)]
pub struct CompressedCuckooFilter {
    /// 256-bit bitfield representation for high-speed bitwise checking.
    pub filter_bitmap: [u64; 4],
    /// Fast set of indexed account addresses.
    entries: HashSet<Address>,
}

impl CompressedCuckooFilter {
    /// Creates a new empty Cuckoo filter.
    pub fn new() -> Self {
        Self {
            filter_bitmap: [0; 4],
            entries: HashSet::new(),
        }
    }

    /// Inserts an account address into the filter.
    pub fn insert(&mut self, addr: &Address) {
        self.entries.insert(*addr);
        let hash = blake3::hash(addr.as_slice());
        let hash_bytes = hash.as_bytes();
        let idx0 = (u64::from_be_bytes(hash_bytes[0..8].try_into().unwrap()) % 256) as usize;
        let idx1 = (u64::from_be_bytes(hash_bytes[8..16].try_into().unwrap()) % 256) as usize;

        self.filter_bitmap[idx0 / 64] |= 1 << (idx0 % 64);
        self.filter_bitmap[idx1 / 64] |= 1 << (idx1 % 64);
    }

    /// Checks in O(1) if an address might be monitored.
    pub fn contains(&self, addr: &Address) -> bool {
        let hash = blake3::hash(addr.as_slice());
        let hash_bytes = hash.as_bytes();
        let idx0 = (u64::from_be_bytes(hash_bytes[0..8].try_into().unwrap()) % 256) as usize;
        let idx1 = (u64::from_be_bytes(hash_bytes[8..16].try_into().unwrap()) % 256) as usize;

        let bit0 = (self.filter_bitmap[idx0 / 64] & (1 << (idx0 % 64))) != 0;
        let bit1 = (self.filter_bitmap[idx1 / 64] & (1 << (idx1 % 64))) != 0;

        bit0 && bit1 && self.entries.contains(addr)
    }

    /// Computes the 32-byte cryptographic root of the Cuckoo filter.
    pub fn digest(&self) -> B256 {
        let mut hasher = blake3::Hasher::new();
        for word in &self.filter_bitmap {
            hasher.update(&word.to_be_bytes());
        }
        B256::from_slice(hasher.finalize().as_bytes())
    }
}

impl Default for CompressedCuckooFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Address Interest Signaling Swarm managing P2P push notifications and CRDT diff streams.
#[derive(Debug, Default)]
pub struct SignalTopicSwarm {
    /// Active subscriptions mapped by TopicID -> Set of subscriber node endpoints.
    pub active_subscriptions: Arc<RwLock<HashMap<B256, Vec<String>>>>,
    /// Gateway Cuckoo filter for monitored accounts.
    pub cuckoo_filter: Arc<RwLock<CompressedCuckooFilter>>,
}

impl SignalTopicSwarm {
    /// Registers a subscription intent from a SignalEnvelope.
    pub fn register_signal(&self, envelope: &SignalEnvelope, subscriber_endpoint: &str) -> B256 {
        let topic_id = envelope.topic_b256();
        let target = envelope.target();

        if let Ok(mut cuckoo) = self.cuckoo_filter.write() {
            cuckoo.insert(&target);
        }

        if let Ok(mut subs) = self.active_subscriptions.write() {
            let list = subs.entry(topic_id).or_default();
            if !list.iter().any(|ep| ep == subscriber_endpoint) {
                list.push(subscriber_endpoint.to_string());
            }
        }

        topic_id
    }

    /// Evaluates in O(1) whether incoming traffic targets any monitored address.
    pub fn should_forward(&self, target_address: &Address) -> bool {
        if let Ok(cuckoo) = self.cuckoo_filter.read() {
            cuckoo.contains(target_address)
        } else {
            false
        }
    }
}

/// Guarded Communication Bus for noise-free engineering and governance channels.
#[derive(Debug, Default)]
pub struct GuardedBus {
    /// Minimum governance tier required to write to this bus.
    pub required_tier: GovernanceTier,
    /// Expected DAO merit root committed on the lattice tip.
    pub dao_merkle_root: B256,
    /// Ingested messages on the guarded plane.
    pub write_buffer: Arc<RwLock<Vec<Vec<u8>>>>,
    /// Public read mirror CIDs.
    pub public_mirror_cids: Arc<RwLock<Vec<B256>>>,
}

impl GuardedBus {
    /// Creates a new GuardedBus with required governance tier.
    pub fn new(required_tier: GovernanceTier, dao_merkle_root: B256) -> Self {
        Self {
            required_tier,
            dao_merkle_root,
            write_buffer: Arc::new(RwLock::new(Vec::new())),
            public_mirror_cids: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Ingests a message into the write plane after verifying Noir ZK-Merit credentials.
    ///
    /// # Errors
    /// Returns an error if the ZK-Merit proof fails or is below the required governance tier.
    pub fn submit_guarded_message(
        &self,
        proof: &ZkMeritProof,
        payload: Vec<u8>,
    ) -> Result<B256, &'static str> {
        if proof.target_tier < self.required_tier {
            return Err("Sender governance tier is insufficient for this guarded channel");
        }

        // Verify ZK-Merit in RAM in <1ms
        proof.verify_in_ram(&self.dao_merkle_root)?;

        let payload_hash = B256::from_slice(blake3::hash(&payload).as_bytes());

        if let Ok(mut buf) = self.write_buffer.write() {
            buf.push(payload);
        }

        if let Ok(mut mirror) = self.public_mirror_cids.write() {
            mirror.push(payload_hash);
        }

        Ok(payload_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_swarm_cuckoo_matching() {
        let swarm = SignalTopicSwarm::default();
        let target = Address::repeat_byte(0x42);
        let envelope = SignalEnvelope::new(
            target,
            b"dao.governance.votes",
            B256::repeat_byte(0x11),
            100,
            &[0x99; 96],
        );

        let topic = swarm.register_signal(&envelope, "quic://127.0.0.1:4242");
        assert_eq!(topic, envelope.topic_b256());

        assert!(swarm.should_forward(&target));

        let unmonitored = Address::repeat_byte(0x99);
        assert!(!swarm.should_forward(&unmonitored));
    }

    #[test]
    fn test_guarded_bus_noise_elimination() {
        let dao_root = B256::repeat_byte(0x77);
        let bus = GuardedBus::new(GovernanceTier::Contributor, dao_root);

        // Valid contributor proof
        let valid_proof = ZkMeritProof {
            dao_merkle_root: dao_root,
            blinded_nullifier: B256::repeat_byte(0xaa),
            claimed_min_score: 600,
            target_tier: GovernanceTier::Contributor,
            proof_bytes: vec![0x1, 0x2, 0x3],
        };

        let res = bus.submit_guarded_message(&valid_proof, b"Engineering PR #42 approved".to_vec());
        assert!(res.is_ok());

        // Low tier proof (PublicUser < Contributor) is rejected at filter layer
        let spam_proof = ZkMeritProof {
            dao_merkle_root: dao_root,
            blinded_nullifier: B256::repeat_byte(0xbb),
            claimed_min_score: 10,
            target_tier: GovernanceTier::PublicUser,
            proof_bytes: vec![0x1],
        };

        let spam_res = bus.submit_guarded_message(&spam_proof, b"Spam message".to_vec());
        assert!(spam_res.is_err());
    }
}
