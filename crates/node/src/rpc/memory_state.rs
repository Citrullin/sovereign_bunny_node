use alloy_primitives::{Address, B256, U256};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::sync::atomic::AtomicU64;

/// A native token transfer record indexed in the 48-hour hot Verkle witness cache.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeTransferRecord {
    /// Transaction hash.
    pub tx_hash: B256,
    /// Canonical mined block hash from execution engine.
    pub block_hash: Option<String>,
    /// Hex-encoded block number string.
    pub block_number: String,
    /// Sender EVM address.
    pub from: Address,
    /// Sender DID, if known from registry.
    pub from_did: Option<String>,
    /// Receiver EVM address.
    pub to: Address,
    /// Receiver DID, if known from registry.
    pub to_did: Option<String>,
    /// Wei value as decimal string for precision.
    pub value: String,
    /// Unix timestamp of block inclusion.
    pub timestamp: u64,
    /// Signature v value.
    pub v: String,
    /// Signature r value.
    pub r: String,
    /// Signature s value.
    pub s: String,
}

/// Ephemeral 48-Hour Hot Memory Index — transient state deltas backing the Stateless zkEVM.
#[derive(Default)]
pub struct MemoryState {
    /// Native transfer history index: Address -> list of records
    pub native_history: HashMap<Address, Vec<NativeTransferRecord>>,
    /// Highest block number fully scanned into the hot index.
    pub block_number: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SyntheticMeta {
    pub original_sender: Address,
    pub receiver: Address,
    pub inbox_value: U256,
    pub nonce: u64,
    pub block_hash: B256,
    pub block_number: u64,
}

#[derive(Debug, Clone)]
pub struct OutboundSendMeta {
    pub sender: Address,
    pub recipient: Address,
    pub amount: U256,
    pub nonce: u64,
    pub gas_price: U256,
    pub virtual_block_hash: B256,
    pub virtual_block_number: u64,
}

static STATE: OnceLock<RwLock<MemoryState>> = OnceLock::new();
static AUTO_CLAIMS: OnceLock<RwLock<HashMap<B256, Vec<B256>>>> = OnceLock::new();
static SYNTHETIC_RECEIPTS: OnceLock<RwLock<HashMap<B256, Address>>> = OnceLock::new();
static SYNTHETIC_TX_HASHES: OnceLock<RwLock<HashMap<B256, B256>>> = OnceLock::new();
static SYNTHETIC_META: OnceLock<RwLock<HashMap<B256, SyntheticMeta>>> = OnceLock::new();
static OUTBOUND_META: OnceLock<RwLock<HashMap<B256, OutboundSendMeta>>> = OnceLock::new();
static DAEMON: OnceLock<sovereign_consensus::archival::RpcIpfsArchivalDaemon> = OnceLock::new();

/// Global static configured chain ID of the node.
pub static CHAIN_ID: AtomicU64 = AtomicU64::new(1337);

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn get_state() -> &'static RwLock<MemoryState> {
    STATE.get_or_init(|| RwLock::new(MemoryState::default()))
}

pub fn get_auto_claims() -> &'static RwLock<HashMap<B256, Vec<B256>>> {
    AUTO_CLAIMS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn get_synthetic_receipts() -> &'static RwLock<HashMap<B256, Address>> {
    SYNTHETIC_RECEIPTS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn insert_synthetic_receipt(tx_hash: B256, sender: Address) {
    get_synthetic_receipts().write().unwrap().insert(tx_hash, sender);
}

pub fn get_synthetic_tx_hashes() -> &'static RwLock<HashMap<B256, B256>> {
    SYNTHETIC_TX_HASHES.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn get_synthetic_meta() -> &'static RwLock<HashMap<B256, SyntheticMeta>> {
    SYNTHETIC_META.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn get_outbound_meta() -> &'static RwLock<HashMap<B256, OutboundSendMeta>> {
    OUTBOUND_META.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn get_archival_daemon() -> &'static sovereign_consensus::archival::RpcIpfsArchivalDaemon {
    DAEMON.get_or_init(|| {
        let is_mock = std::env::var("SOVEREIGN_MOCK_SGX").is_ok() || cfg!(debug_assertions);
        let backend: std::sync::Arc<dyn sovereign_consensus::archival::ArchivalStorageBackend> = if is_mock {
            std::sync::Arc::new(sovereign_consensus::archival::MockArchivalBackend::new())
        } else {
            std::sync::Arc::new(sovereign_consensus::archival::LocalIpfsClusterBackend::new("http://127.0.0.1:5001", false))
        };
        sovereign_consensus::archival::RpcIpfsArchivalDaemon::new(backend)
    })
}

/// Indexes a native transfer record for both sender and receiver with a 48-hour TTL.
pub fn add_native_transfer_record(state: &mut MemoryState, record: NativeTransferRecord) {
    let now = now_secs();
    const TTL: u64 = 172_800; // 48 hours
    const MAX_PER_ADDR: usize = 200;

    for addr in &[record.from, record.to] {
        let list = state.native_history.entry(*addr).or_default();
        list.retain(|r| now.saturating_sub(r.timestamp) < TTL);

        if let Some(existing) = list.iter_mut().find(|r| r.tx_hash == record.tx_hash) {
            if existing.block_hash.is_none() && record.block_hash.is_some() {
                existing.block_hash = record.block_hash.clone();
            }
            if existing.block_number == "0x1" || record.block_number != "0x1" {
                existing.block_number = record.block_number.clone();
            }
        } else {
            list.push(record.clone());
        }

        if list.len() > MAX_PER_ADDR {
            let excess = list.len() - MAX_PER_ADDR;
            list.drain(0..excess);
        }
    }
}
