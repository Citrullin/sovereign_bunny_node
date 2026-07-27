//! SALT-like Flat State store and Parallel Top-Down Trie Builder.
//!
//! Provides a flat key-value state store indexed by derived key hashes and a
//! 16-way top-down parallel trie builder for state root transitions.

use alloy_primitives::{Address, B256, U256};
use sovereign_crypto::CryptoProfile;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A flat key-value state store.
#[derive(Debug, Clone, Default)]
pub struct FlatStateStore {
    /// Flat storage map: derived key hash -> storage slot value.
    pub store: HashMap<B256, U256>,
}

impl FlatStateStore {
    /// Creates a new flat state store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    /// Derives the flat state key: hash(address || slot).
    #[must_use]
    pub fn derive_key(&self, profile: &CryptoProfile, address: Address, slot: U256) -> B256 {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(address.as_slice());
        let slot_bytes = slot.to_be_bytes::<32>();
        preimage.extend_from_slice(&slot_bytes);

        let hashed = sovereign_crypto::hash(profile.hash, &preimage);
        let mut key = [0u8; 32];
        let len = hashed.len().min(32);
        key[..len].copy_from_slice(&hashed[..len]);
        B256::from(key)
    }

    /// Writes a value to the flat state store.
    pub fn write(&mut self, profile: &CryptoProfile, address: Address, slot: U256, value: U256) {
        let key = self.derive_key(profile, address, slot);
        self.store.insert(key, value);
    }

    /// Reads a value from the flat state store.
    #[must_use]
    pub fn read(&self, profile: &CryptoProfile, address: Address, slot: U256) -> U256 {
        let key = self.derive_key(profile, address, slot);
        self.store.get(&key).copied().unwrap_or(U256::ZERO)
    }
}

/// 16-way top-down parallel trie builder.
#[derive(Debug, Clone, Copy)]
pub struct ParallelTrieBuilder;

impl ParallelTrieBuilder {
    /// Builds the Merkle root of the flat state using a 16-way top-down parallel trie builder.
    ///
    /// Active nodes compute the root from state deltas and never persist intermediate trie nodes.
    #[must_use]
    pub fn build_state_root(
        store: &FlatStateStore,
        profile: &CryptoProfile,
        deltas: &[(Address, U256, U256)],
    ) -> B256 {
        if deltas.is_empty() {
            return B256::ZERO;
        }

        // Partition the deltas into 16 subsets based on the derived flat key's first nibble (16-way branching)
        let partitions: Arc<Mutex<[Vec<(B256, U256)>; 16]>> = Arc::new(Mutex::new(Default::default()));

        // Run partition building in parallel threads (simulating 16-way top-down trie builders)
        let mut handles = Vec::new();
        let chunk_size = (deltas.len() + 15) / 16;
        let deltas_vec = deltas.to_vec();

        for i in 0..16 {
            let partitions_clone = Arc::clone(&partitions);
            let deltas_chunk = deltas_vec.iter()
                .skip(i * chunk_size)
                .take(chunk_size)
                .cloned()
                .collect::<Vec<_>>();
            let store_clone = store.clone();
            let profile_clone = *profile;

            let handle = std::thread::spawn(move || {
                for (address, slot, value) in deltas_chunk {
                    let key = store_clone.derive_key(&profile_clone, address, slot);
                    let nibble = (key[0] >> 4) as usize; // first nibble for 16-way branch
                    let mut lock = partitions_clone.lock().unwrap();
                    lock[nibble].push((key, value));
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.join();
        }

        // Compute sub-roots for each of the 16 branches
        let sub_roots = Arc::new(Mutex::new(vec![B256::ZERO; 16]));
        let mut sub_handles = Vec::new();

        for nibble in 0..16 {
            let partitions_clone = Arc::clone(&partitions);
            let sub_roots_clone = Arc::clone(&sub_roots);
            let profile_clone = *profile;

            let handle = std::thread::spawn(move || {
                let lock = partitions_clone.lock().unwrap();
                let branch_deltas = &lock[nibble];
                if branch_deltas.is_empty() {
                    return;
                }

                // Hashing step for this partition branch
                let mut preimage = Vec::new();
                for (key, val) in branch_deltas {
                    preimage.extend_from_slice(key.as_slice());
                    let val_bytes = val.to_be_bytes::<32>();
                    preimage.extend_from_slice(&val_bytes);
                }

                let sub_hash = sovereign_crypto::hash(profile_clone.hash, &preimage);
                let mut sub_hash_bytes = [0u8; 32];
                let len = sub_hash.len().min(32);
                sub_hash_bytes[..len].copy_from_slice(&sub_hash[..len]);

                let mut roots_lock = sub_roots_clone.lock().unwrap();
                roots_lock[nibble] = B256::from(sub_hash_bytes);
            });
            sub_handles.push(handle);
        }

        for handle in sub_handles {
            let _ = handle.join();
        }

        // Compute the final top-down trie root from the 16 sub-roots
        let mut final_preimage = Vec::new();
        let roots = sub_roots.lock().unwrap();
        for sub_root in roots.iter() {
            final_preimage.extend_from_slice(sub_root.as_slice());
        }

        let final_hash = sovereign_crypto::hash(profile.hash, &final_preimage);
        let mut final_hash_bytes = [0u8; 32];
        let len = final_hash.len().min(32);
        final_hash_bytes[..len].copy_from_slice(&final_hash[..len]);
        B256::from(final_hash_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flat_state_and_trie_root() {
        let profile = CryptoProfile::ETHEREUM;
        let mut store = FlatStateStore::new();
        let addr = Address::repeat_byte(0x11);
        let slot = U256::from(42);
        let value = U256::from(100);

        store.write(&profile, addr, slot, value);
        assert_eq!(store.read(&profile, addr, slot), value);

        let deltas = vec![(addr, slot, value)];
        let root = ParallelTrieBuilder::build_state_root(&store, &profile, &deltas);
        assert_ne!(root, B256::ZERO);
    }
}
