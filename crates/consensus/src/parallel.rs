use std::collections::{HashSet, HashMap};
use std::sync::{Arc, Mutex};
use alloy_primitives::{Address, U256};
use crate::stateless::{WitnessDatabase, AccountWitness};

/// Transaction storage access description representing EIP-2930 access lists and execution metadata.
#[derive(Debug, Clone, Default)]
pub struct TxAccessList {
    /// The transaction index in the block.
    pub tx_index: usize,
    /// The sender of the transaction.
    pub sender: Address,
    /// The recipient of the transaction.
    pub recipient: Address,
    /// The transfer value.
    pub value: U256,
    /// The expected nonce of the sender.
    pub nonce: u64,
    /// Addresses read by this transaction.
    pub read_addresses: HashSet<Address>,
    /// Addresses written to by this transaction.
    pub write_addresses: HashSet<Address>,
    /// Storage slots read by this transaction per address.
    pub read_slots: HashMap<Address, HashSet<U256>>,
    /// Storage slots written to by this transaction per address.
    pub write_slots: HashMap<Address, HashSet<U256>>,
}

/// Pluggable interface for local EVM parallel execution engines.
pub trait ParallelExecutor: Send + Sync {
    /// Execute a batch of transactions in parallel against the state database using real EVM-like state transition logic.
    fn execute_parallel_access_lists(
        &self,
        access_lists: &[TxAccessList],
        db: &mut WitnessDatabase,
    ) -> Result<(), String>;
    
    /// Returns the engine name.
    fn name(&self) -> &'static str;
}

/// Dynamic factory to retrieve the configured parallel executor.
pub fn get_executor(engine_name: &str) -> Box<dyn ParallelExecutor> {
    match engine_name.to_lowercase().as_str() {
        "pevm" | "block_stm" => Box::new(PevmExecutor::new()),
        "grevm" | "zk_parallel" => Box::new(GrevmExecutor::new()),
        _ => Box::new(WaveExecutor::new()),
    }
}

/// EIP-2930 conflict wave partitioner with real parallel state updates.
pub struct WaveExecutor;

impl Default for WaveExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl WaveExecutor {
    /// Creates a new `WaveExecutor`.
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
}

struct WaveTxResult {
    sender_addr: Address,
    sender_acc: AccountWitness,
    recipient_addr: Address,
    recipient_acc: AccountWitness,
    write_slots: HashMap<Address, HashMap<U256, U256>>,
}

impl ParallelExecutor for WaveExecutor {
    fn name(&self) -> &'static str {
        "wave-static"
    }

    fn execute_parallel_access_lists(
        &self,
        access_lists: &[TxAccessList],
        db: &mut WitnessDatabase,
    ) -> Result<(), String> {
        let waves = self.partition_waves(access_lists);
        
        for wave in waves {
            // Compute updates concurrently without holding any global lock.
            // Since the wave partitioner guarantees disjoint address read/write sets,
            // we can safely read initial states from the database copy and compute updates.
            let db_snapshot = Arc::new(db.clone());
            let mut handles = Vec::new();

            for tx in wave {
                let db_clone = Arc::clone(&db_snapshot);
                let handle = std::thread::spawn(move || -> Result<WaveTxResult, String> {
                    // 1. Authenticate sender and check nonce from local snapshot
                    let mut sender_acc = db_clone.accounts.get(&tx.sender).cloned().unwrap_or_default();
                    if sender_acc.nonce != tx.nonce {
                        return Err(format!("Nonce mismatch for {:?}: expected {}, found {}", tx.sender, tx.nonce, sender_acc.nonce));
                    }
                    // Pre-Execution Auto-Claim Pipeline (Task B):
                    let auto_claim_amount = if let Ok(reg) = crate::registry::get_registry().read() {
                        let mut claimed = std::collections::HashSet::new();
                        for block in reg.lattice_blocks.values() {
                            if let crate::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
                                claimed.insert(*send_block_hash);
                            }
                        }
                        let mut pending = Vec::new();
                        for (hash, block) in &reg.lattice_blocks {
                            if let crate::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                                if *recipient == tx.sender && !claimed.contains(hash) {
                                    pending.push(*amount);
                                }
                            }
                        }
                        pending.sort_by(|a, b| b.cmp(a));
                        pending.iter().take(20).sum::<alloy_primitives::U256>()
                    } else {
                        alloy_primitives::U256::ZERO
                    };
                    sender_acc.balance += auto_claim_amount;

                    if sender_acc.balance < tx.value {
                        return Err(format!("Insufficient balance for {:?}", tx.sender));
                    }

                    // 2. Perform value transfer (Sender only for Block-Lattice Send)
                    sender_acc.balance -= tx.value;
                    sender_acc.nonce += 1;

                    let mut recipient_acc = db_clone.accounts.get(&tx.recipient).cloned().unwrap_or_default();
                    // Do NOT increase recipient balance if this is a block-lattice transfer (recipient has registered DID).
                    let is_block_lattice = if let Ok(reg) = crate::registry::get_registry().read() {
                        reg.address_to_did.contains_key(&tx.recipient)
                    } else {
                        false
                    };
                    if !is_block_lattice {
                        recipient_acc.balance += tx.value;
                    }

                    // 3. Write storage slots using a deterministic simulated value based on tx_index and slot key
                    let mut write_slots: HashMap<Address, HashMap<U256, U256>> = HashMap::new();
                    for (addr, slots) in &tx.write_slots {
                        let inner_map = write_slots.entry(*addr).or_default();
                        for slot in slots {
                            // Produce a unique deterministic value based on slot + tx_index + 1
                            let val = *slot + U256::from(tx.tx_index as u64 + 1);
                            inner_map.insert(*slot, val);
                        }
                    }

                    Ok(WaveTxResult {
                        sender_addr: tx.sender,
                        sender_acc,
                        recipient_addr: tx.recipient,
                        recipient_acc,
                        write_slots,
                    })
                });
                handles.push(handle);
            }

            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.join().map_err(|_| "Execution thread panicked")??);
            }

            // Apply all results to db sequentially (guaranteed collision-free inside a wave)
            for res in results {
                db.accounts.insert(res.sender_addr, res.sender_acc);
                db.accounts.insert(res.recipient_addr, res.recipient_acc);
                for (addr, slots) in res.write_slots {
                    let db_slots = db.storage.entry(addr).or_default();
                    for (slot, val) in slots {
                        db_slots.insert(slot, val);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Optimistic MVCC Block-STM Parallel Executor.
pub struct PevmExecutor;

impl Default for PevmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl PevmExecutor {
    /// Creates a new `PevmExecutor`.
    pub fn new() -> Self {
        Self
    }
}

/// MVCC versioned state storage for Block-STM execution.
#[derive(Clone, Default)]
struct MvccState {
    // Map: address -> list of (tx_index, account_state)
    accounts: HashMap<Address, Vec<(usize, AccountWitness)>>,
    // Map: (address, slot) -> list of (tx_index, value)
    storage: HashMap<(Address, U256), Vec<(usize, U256)>>,
}

impl MvccState {
    fn read_account(&self, tx_index: usize, addr: Address, backing: &WitnessDatabase) -> (usize, AccountWitness) {
        if let Some(versions) = self.accounts.get(&addr) {
            for (writer_idx, acc) in versions.iter().rev() {
                if *writer_idx < tx_index {
                    return (*writer_idx, acc.clone());
                }
            }
        }
        (usize::MAX, backing.accounts.get(&addr).cloned().unwrap_or_default())
    }

    fn read_storage(&self, tx_index: usize, addr: Address, slot: U256, backing: &WitnessDatabase) -> (usize, U256) {
        if let Some(versions) = self.storage.get(&(addr, slot)) {
            for (writer_idx, val) in versions.iter().rev() {
                if *writer_idx < tx_index {
                    return (*writer_idx, *val);
                }
            }
        }
        let backing_val = backing.storage.get(&addr)
            .and_then(|slots| slots.get(&slot))
            .copied()
            .unwrap_or(U256::ZERO);
        (usize::MAX, backing_val)
    }

    fn write_account(&mut self, tx_index: usize, addr: Address, acc: AccountWitness) {
        let versions = self.accounts.entry(addr).or_default();
        if let Some(pos) = versions.iter().position(|(idx, _)| *idx == tx_index) {
            versions[pos] = (tx_index, acc);
        } else {
            versions.push((tx_index, acc));
            versions.sort_by_key(|(idx, _)| *idx);
        }
    }

    fn write_storage(&mut self, tx_index: usize, addr: Address, slot: U256, val: U256) {
        let versions = self.storage.entry((addr, slot)).or_default();
        if let Some(pos) = versions.iter().position(|(idx, _)| *idx == tx_index) {
            versions[pos] = (tx_index, val);
        } else {
            versions.push((tx_index, val));
            versions.sort_by_key(|(idx, _)| *idx);
        }
    }

    fn clear_writes(&mut self, tx_index: usize) {
        for versions in self.accounts.values_mut() {
            versions.retain(|(idx, _)| *idx != tx_index);
        }
        for versions in self.storage.values_mut() {
            versions.retain(|(idx, _)| *idx != tx_index);
        }
    }
}

struct TxExecutionResult {
    tx_index: usize,
    read_accounts: HashMap<Address, (usize, AccountWitness)>,
    read_storage: HashMap<(Address, U256), (usize, U256)>,
    sender_acc: AccountWitness,
    recipient_acc: AccountWitness,
    written_storage: HashMap<(Address, U256), U256>,
}

impl ParallelExecutor for PevmExecutor {
    fn name(&self) -> &'static str {
        "pevm-mvcc"
    }

    fn execute_parallel_access_lists(
        &self,
        access_lists: &[TxAccessList],
        db: &mut WitnessDatabase,
    ) -> Result<(), String> {
        let mvcc = Arc::new(Mutex::new(MvccState::default()));
        let backing_db = Arc::new(db.clone());
        let mut executed = vec![false; access_lists.len()];
        let max_retries = 20;

        for retry in 0..max_retries {
            let mut handles = Vec::new();
            let mvcc_shared = Arc::clone(&mvcc);
            let backing_shared = Arc::clone(&backing_db);

            for (idx, tx) in access_lists.iter().enumerate() {
                if executed[idx] {
                    continue;
                }

                let mvcc_clone = Arc::clone(&mvcc_shared);
                let backing_clone = Arc::clone(&backing_shared);
                let tx_clone = tx.clone();

                let handle = std::thread::spawn(move || -> Result<TxExecutionResult, String> {
                    let mvcc_lock = mvcc_clone.lock().unwrap();
                    let tx_idx = tx_clone.tx_index;

                    // 1. Read parameters and record read versions
                    let mut read_accounts = HashMap::new();
                    let mut read_storage = HashMap::new();

                    let (sender_v, mut sender_acc) = mvcc_lock.read_account(tx_idx, tx_clone.sender, &backing_clone);
                    read_accounts.insert(tx_clone.sender, (sender_v, sender_acc.clone()));

                    let (recipient_v, mut recipient_acc) = mvcc_lock.read_account(tx_idx, tx_clone.recipient, &backing_clone);
                    read_accounts.insert(tx_clone.recipient, (recipient_v, recipient_acc.clone()));

                    for addr in &tx_clone.read_addresses {
                        if !read_accounts.contains_key(addr) {
                            let (v, acc) = mvcc_lock.read_account(tx_idx, *addr, &backing_clone);
                            read_accounts.insert(*addr, (v, acc));
                        }
                    }

                    for (addr, slots) in &tx_clone.read_slots {
                        for slot in slots {
                            let (v, val) = mvcc_lock.read_storage(tx_idx, *addr, *slot, &backing_clone);
                            read_storage.insert((*addr, *slot), (v, val));
                        }
                    }

                    // Drop lock before execution calculation
                    drop(mvcc_lock);

                    // 2. Perform state execution transition
                    if sender_acc.nonce != tx_clone.nonce {
                        return Err(format!("Nonce mismatch for {:?}: expected {}, found {}", tx_clone.sender, tx_clone.nonce, sender_acc.nonce));
                    }
                    // Pre-Execution Auto-Claim Pipeline (Task B):
                    let auto_claim_amount = if let Ok(reg) = crate::registry::get_registry().read() {
                        let mut claimed = std::collections::HashSet::new();
                        for block in reg.lattice_blocks.values() {
                            if let crate::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
                                claimed.insert(*send_block_hash);
                            }
                        }
                        let mut pending = Vec::new();
                        for (hash, block) in &reg.lattice_blocks {
                            if let crate::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                                if *recipient == tx_clone.sender && !claimed.contains(hash) {
                                    pending.push(*amount);
                                }
                            }
                        }
                        pending.sort_by(|a, b| b.cmp(a));
                        pending.iter().take(20).sum::<alloy_primitives::U256>()
                    } else {
                        alloy_primitives::U256::ZERO
                    };
                    sender_acc.balance += auto_claim_amount;

                    if sender_acc.balance < tx_clone.value {
                        return Err(format!("Insufficient balance for {:?}", tx_clone.sender));
                    }

                    sender_acc.balance -= tx_clone.value;
                    sender_acc.nonce += 1;
                    // Do NOT increase recipient_acc.balance if this is a block-lattice transfer (recipient has registered DID).
                    let is_block_lattice = if let Ok(reg) = crate::registry::get_registry().read() {
                        reg.address_to_did.contains_key(&tx_clone.recipient)
                    } else {
                        false
                    };
                    if !is_block_lattice {
                        recipient_acc.balance += tx_clone.value;
                    }

                    let mut written_storage = HashMap::new();
                    for (addr, slots) in &tx_clone.write_slots {
                        for slot in slots {
                            // Produce a unique deterministic value based on slot + tx_idx + 1
                            let val = *slot + U256::from(tx_idx as u64 + 1);
                            written_storage.insert((*addr, *slot), val);
                        }
                    }

                    Ok(TxExecutionResult {
                        tx_index: tx_idx,
                        read_accounts,
                        read_storage,
                        sender_acc,
                        recipient_acc,
                        written_storage,
                    })
                });
                handles.push((idx, handle));
            }

            let mut re_execute = HashSet::new();

            for (idx, handle) in handles {
                match handle.join().map_err(|_| "Thread panicked".to_string())? {
                    Ok(exec_res) => {
                        let mut mvcc_lock = mvcc.lock().unwrap();
                        let tx_idx = exec_res.tx_index;

                        // Validate read set versions: if any read item was overwritten by a transaction with index < tx_idx since we read it, validation fails
                        let mut conflict = false;
                        for (addr, (v_read, _)) in &exec_res.read_accounts {
                            let (v_now, _) = mvcc_lock.read_account(tx_idx, *addr, &backing_db);
                            if v_now != *v_read {
                                conflict = true;
                                break;
                            }
                        }
                        if !conflict {
                            for ((addr, slot), (v_read, _)) in &exec_res.read_storage {
                                let (v_now, _) = mvcc_lock.read_storage(tx_idx, *addr, *slot, &backing_db);
                                if v_now != *v_read {
                                    conflict = true;
                                    break;
                                }
                            }
                        }

                        if conflict {
                            mvcc_lock.clear_writes(tx_idx);
                            re_execute.insert(idx);
                        } else {
                            // Commit writes to MVCC state
                            mvcc_lock.write_account(tx_idx, access_lists[idx].sender, exec_res.sender_acc);
                            mvcc_lock.write_account(tx_idx, access_lists[idx].recipient, exec_res.recipient_acc);
                            for ((addr, slot), val) in exec_res.written_storage {
                                mvcc_lock.write_storage(tx_idx, addr, slot, val);
                            }
                            executed[idx] = true;
                        }
                    }
                    Err(e) => {
                        // Hard execution error (nonce mismatch, insufficient balance) -> fail immediately
                        return Err(e);
                    }
                }
            }

            if re_execute.is_empty() && executed.iter().all(|x| *x) {
                break;
            }

            if retry == max_retries - 1 {
                return Err("Block-STM failed to converge due to high transaction conflict density".to_string());
            }
        }

        // Apply finalized MVCC writes to backing WitnessDatabase
        let finalized_mvcc = mvcc.lock().unwrap();
        for (addr, versions) in &finalized_mvcc.accounts {
            if let Some((_, acc)) = versions.last() {
                db.accounts.insert(*addr, acc.clone());
            }
        }
        for ((addr, slot), versions) in &finalized_mvcc.storage {
            if let Some((_, val)) = versions.last() {
                db.storage.entry(*addr).or_default().insert(*slot, *val);
            }
        }

        Ok(())
    }
}

/// ZK-friendly Parallel Executor recording execution witness traces.
pub struct GrevmExecutor;

impl Default for GrevmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl GrevmExecutor {
    /// Creates a new `GrevmExecutor`.
    pub fn new() -> Self {
        Self
    }
}

struct GrevmTxResult {
    trace: Vec<String>,
    sender_addr: Address,
    sender_acc: AccountWitness,
    recipient_addr: Address,
    recipient_acc: AccountWitness,
    write_slots: HashMap<Address, HashMap<U256, U256>>,
}

impl ParallelExecutor for GrevmExecutor {
    fn name(&self) -> &'static str {
        "grevm-zk"
    }

    fn execute_parallel_access_lists(
        &self,
        access_lists: &[TxAccessList],
        db: &mut WitnessDatabase,
    ) -> Result<(), String> {
        let partitioner = WaveExecutor::new();
        let waves = partitioner.partition_waves(access_lists);
        let mut witness_trace = Vec::new();

        for wave in waves {
            let db_snapshot = Arc::new(db.clone());
            let mut handles = Vec::new();

            for tx in wave {
                let db_clone = Arc::clone(&db_snapshot);
                let handle = std::thread::spawn(move || -> Result<GrevmTxResult, String> {
                    let mut trace = Vec::new();

                    let mut sender_acc = db_clone.accounts.get(&tx.sender).cloned().unwrap_or_default();
                    trace.push(format!("READ Account {:?} Balance={:?} Nonce={}", tx.sender, sender_acc.balance, sender_acc.nonce));

                    if sender_acc.nonce != tx.nonce {
                        return Err(format!("Nonce mismatch for {:?}: expected {}, found {}", tx.sender, tx.nonce, sender_acc.nonce));
                    }
                    // Pre-Execution Auto-Claim Pipeline (Task B):
                    let auto_claim_amount = if let Ok(reg) = crate::registry::get_registry().read() {
                        let mut claimed = std::collections::HashSet::new();
                        for block in reg.lattice_blocks.values() {
                            if let crate::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
                                claimed.insert(*send_block_hash);
                            }
                        }
                        let mut pending = Vec::new();
                        for (hash, block) in &reg.lattice_blocks {
                            if let crate::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
                                if *recipient == tx.sender && !claimed.contains(hash) {
                                    pending.push(*amount);
                                }
                            }
                        }
                        pending.sort_by(|a, b| b.cmp(a));
                        pending.iter().take(20).sum::<alloy_primitives::U256>()
                    } else {
                        alloy_primitives::U256::ZERO
                    };
                    sender_acc.balance += auto_claim_amount;

                    if sender_acc.balance < tx.value {
                        return Err(format!("Insufficient balance for {:?}", tx.sender));
                    }

                    sender_acc.balance -= tx.value;
                    sender_acc.nonce += 1;
                    trace.push(format!("WRITE Account {:?} Balance={:?} Nonce={}", tx.sender, sender_acc.balance, sender_acc.nonce));

                    let mut recipient_acc = db_clone.accounts.get(&tx.recipient).cloned().unwrap_or_default();
                    // Do NOT increase recipient_acc.balance if this is a block-lattice transfer (recipient has registered DID).
                    let is_block_lattice = if let Ok(reg) = crate::registry::get_registry().read() {
                        reg.address_to_did.contains_key(&tx.recipient)
                    } else {
                        false
                    };
                    if !is_block_lattice {
                        recipient_acc.balance += tx.value;
                    }
                    trace.push(format!("WRITE Account {:?} Balance={:?}", tx.recipient, recipient_acc.balance));

                    let mut write_slots: HashMap<Address, HashMap<U256, U256>> = HashMap::new();
                    for (addr, slots) in &tx.write_slots {
                        let inner_map = write_slots.entry(*addr).or_default();
                        for slot in slots {
                            // Produce a unique deterministic value based on slot + tx_index + 1
                            let val = *slot + U256::from(tx.tx_index as u64 + 1);
                            inner_map.insert(*slot, val);
                            trace.push(format!("WRITE Storage {:?} Slot={:?} Val={:?}", addr, slot, val));
                        }
                    }

                    Ok(GrevmTxResult {
                        trace,
                        sender_addr: tx.sender,
                        sender_acc,
                        recipient_addr: tx.recipient,
                        recipient_acc,
                        write_slots,
                    })
                });
                handles.push(handle);
            }

            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.join().map_err(|_| "Grevm thread panicked")??);
            }

            // Apply all results to db sequentially (guaranteed collision-free inside a wave)
            for res in results {
                witness_trace.extend(res.trace);
                db.accounts.insert(res.sender_addr, res.sender_acc);
                db.accounts.insert(res.recipient_addr, res.recipient_acc);
                for (addr, slots) in res.write_slots {
                    let db_slots = db.storage.entry(addr).or_default();
                    for (slot, val) in slots {
                        db_slots.insert(slot, val);
                    }
                }
            }
        }

        tracing::info!(trace_length = witness_trace.len(), "Grevm ZK parallel execution witness trace generated");
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
        let executor = WaveExecutor::new();
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
        assert_eq!(waves.len(), 2);
        assert!(waves[0].iter().any(|tx| tx.tx_index == 0));
        assert!(waves[0].iter().any(|tx| tx.tx_index == 2));
        assert!(waves[1].iter().any(|tx| tx.tx_index == 1));
    }

    #[test]
    fn test_wave_executor_real_execution() {
        let executor = WaveExecutor::new();
        let mut db = WitnessDatabase::default();
        let sender = Address::repeat_byte(0xaa);
        let recipient = Address::repeat_byte(0xbb);
        
        db.accounts.insert(sender, AccountWitness {
            balance: U256::from(1000),
            nonce: 0,
            ..Default::default()
        });

        let tx = TxAccessList {
            tx_index: 0,
            sender,
            recipient,
            value: U256::from(200),
            nonce: 0,
            ..Default::default()
        };

        let res = executor.execute_parallel_access_lists(&[tx], &mut db);
        assert!(res.is_ok());
        assert_eq!(db.accounts.get(&sender).unwrap().balance, U256::from(800));
        assert_eq!(db.accounts.get(&sender).unwrap().nonce, 1);
        assert_eq!(db.accounts.get(&recipient).unwrap().balance, U256::from(200));
    }

    #[test]
    fn test_pevm_executor_real_execution() {
        let executor = PevmExecutor::new();
        let mut db = WitnessDatabase::default();
        let sender = Address::repeat_byte(0xaa);
        let recipient = Address::repeat_byte(0xbb);
        
        db.accounts.insert(sender, AccountWitness {
            balance: U256::from(1000),
            nonce: 0,
            ..Default::default()
        });

        let tx = TxAccessList {
            tx_index: 0,
            sender,
            recipient,
            value: U256::from(200),
            nonce: 0,
            ..Default::default()
        };

        let res = executor.execute_parallel_access_lists(&[tx], &mut db);
        assert!(res.is_ok());
        assert_eq!(db.accounts.get(&sender).unwrap().balance, U256::from(800));
        assert_eq!(db.accounts.get(&recipient).unwrap().balance, U256::from(200));
    }

    #[test]
    fn test_grevm_executor_real_execution() {
        let executor = GrevmExecutor::new();
        let mut db = WitnessDatabase::default();
        let sender = Address::repeat_byte(0xaa);
        let recipient = Address::repeat_byte(0xbb);
        
        db.accounts.insert(sender, AccountWitness {
            balance: U256::from(1000),
            nonce: 0,
            ..Default::default()
        });

        let tx = TxAccessList {
            tx_index: 0,
            sender,
            recipient,
            value: U256::from(200),
            nonce: 0,
            ..Default::default()
        };

        let res = executor.execute_parallel_access_lists(&[tx], &mut db);
        assert!(res.is_ok());
        assert_eq!(db.accounts.get(&sender).unwrap().balance, U256::from(800));
        assert_eq!(db.accounts.get(&recipient).unwrap().balance, U256::from(200));
    }
}
