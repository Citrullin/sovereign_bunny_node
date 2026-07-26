use std::collections::{HashSet, HashMap};
use std::sync::{Arc, Mutex};
use alloy_primitives::{Address, U256};

/// Transaction storage access description representing EIP-2930 access lists.
#[derive(Debug, Clone, Default)]
pub struct TxAccessList {
    /// The transaction index in the block.
    pub tx_index: usize,
    /// Addresses read by this transaction.
    pub read_addresses: HashSet<Address>,
    /// Addresses written to by this transaction.
    pub write_addresses: HashSet<Address>,
    /// Storage slots read by this transaction per address.
    pub read_slots: HashMap<Address, HashSet<U256>>,
    /// Storage slots written to by this transaction per address.
    pub write_slots: HashMap<Address, HashSet<U256>>,
}

/// Block-STM parallel executor that partition transactions based on conflicts.
pub struct BlockStmExecutor;

impl Default for BlockStmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStmExecutor {
    /// Creates a new `BlockStmExecutor`.
    pub fn new() -> Self {
        Self
    }

    /// Segregates transactions into independent execution waves that can be run in parallel.
    pub fn partition_waves(&self, access_lists: &[TxAccessList]) -> Vec<Vec<TxAccessList>> {
        let mut waves: Vec<Vec<TxAccessList>> = Vec::new();
        let mut processed = HashSet::new();

        while processed.len() < access_lists.len() {
            let mut current_wave = Vec::new();
            let mut wave_write_addresses: HashSet<Address> = HashSet::new();
            let mut wave_read_addresses: HashSet<Address> = HashSet::new();
            let mut wave_write_slots: HashMap<Address, HashSet<U256>> = HashMap::new();
            let mut wave_read_slots: HashMap<Address, HashSet<U256>> = HashMap::new();

            for tx in access_lists {
                if processed.contains(&tx.tx_index) {
                    continue;
                }

                // Check address conflict
                let address_conflict = tx.write_addresses.iter().any(|addr| wave_read_addresses.contains(addr) || wave_write_addresses.contains(addr))
                    || tx.read_addresses.iter().any(|addr| wave_write_addresses.contains(addr));

                // Check slot conflict
                let mut slot_conflict = false;
                for (addr, slots) in &tx.write_slots {
                    if let Some(wave_slots) = wave_read_slots.get(addr) {
                        if slots.iter().any(|s| wave_slots.contains(s)) {
                            slot_conflict = true;
                            break;
                        }
                    }
                    if let Some(wave_slots) = wave_write_slots.get(addr) {
                        if slots.iter().any(|s| wave_slots.contains(s)) {
                            slot_conflict = true;
                            break;
                        }
                    }
                }
                for (addr, slots) in &tx.read_slots {
                    if let Some(wave_slots) = wave_write_slots.get(addr) {
                        if slots.iter().any(|s| wave_slots.contains(s)) {
                            slot_conflict = true;
                            break;
                        }
                    }
                }

                if !address_conflict && !slot_conflict {
                    current_wave.push(tx.clone());
                    processed.insert(tx.tx_index);
                    
                    // Merge into wave's write/read sets
                    wave_write_addresses.extend(&tx.write_addresses);
                    wave_read_addresses.extend(&tx.read_addresses);
                    for (addr, slots) in &tx.write_slots {
                        wave_write_slots.entry(*addr).or_default().extend(slots);
                    }
                    for (addr, slots) in &tx.read_slots {
                        wave_read_slots.entry(*addr).or_default().extend(slots);
                    }
                }
            }
            waves.push(current_wave);
        }

        waves
    }

    /// Simulates execution in parallel using the partition waves.
    ///
    /// # Errors
    /// Returns an error if parallel execution fails.
    pub fn execute_parallel_access_lists(&self, access_lists: &[TxAccessList]) -> Result<(), String> {
        let waves = self.partition_waves(access_lists);
        let completed = Arc::new(Mutex::new(Vec::new()));

        for wave in waves {
            let mut handles = Vec::new();
            for tx in wave {
                let completed_clone = Arc::clone(&completed);
                let handle = std::thread::spawn(move || {
                    // Simulate EVM execution on WitnessDatabase
                    // In real execution, this would run revm with WitnessDatabase
                    let mut lock = completed_clone.lock().unwrap();
                    lock.push(tx.tx_index);
                });
                handles.push(handle);
            }
            for handle in handles {
                handle.join().map_err(|_| "Thread execution panicked".to_string())?;
            }
        }

        Ok(())
    }
}

/// Enforces that a transaction declares state access (EIP-2930).
///
/// # Errors
/// Returns an error if `has_access_list` is `false`.
pub fn enforce_access_list_stub(has_access_list: bool) -> Result<(), &'static str> {
    if has_access_list {
        Ok(())
    } else {
        Err("Transaction must declare an EIP-2930 access list for parallel execution")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_execution_partitioning() {
        let executor = BlockStmExecutor::new();
        let addr1 = Address::repeat_byte(0x11);
        let addr2 = Address::repeat_byte(0x22);
        
        let tx1 = TxAccessList {
            tx_index: 0,
            write_addresses: vec![addr1].into_iter().collect(),
            ..Default::default()
        };
        let tx2 = TxAccessList {
            tx_index: 1,
            read_addresses: vec![addr1].into_iter().collect(), // conflict with tx1
            ..Default::default()
        };
        let tx3 = TxAccessList {
            tx_index: 2,
            write_addresses: vec![addr2].into_iter().collect(), // independent
            ..Default::default()
        };

        let waves = executor.partition_waves(&[tx1, tx2, tx3]);
        // Wave 0 should have tx1 and tx3
        // Wave 1 should have tx2
        assert_eq!(waves.len(), 2);
        assert!(waves[0].iter().any(|tx| tx.tx_index == 0));
        assert!(waves[0].iter().any(|tx| tx.tx_index == 2));
        assert!(waves[1].iter().any(|tx| tx.tx_index == 1));
    }
}
