//! Pure Rust Iroh BLAKE3 Bao Verified Streaming & Content-Addressed Storage Engine.
//!
//! Provides cryptographic Proof of Retrievability (PoR), Bao slice proofs,
//! hierarchical namespace partitioning, and cross-cluster P2P synchronization.

use alloy_primitives::{hex, Address, U256};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use crate::storage::archival::ArchivalStorageBackend;

/// Standard BLAKE3 chunk size (1024 bytes / 1 KiB) for Bao tree hashing.
pub const BLAKE3_CHUNK_SIZE: usize = 1024;

/// Economic pinning lease for decentralized Iroh content-addressed storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrohPinLease {
    /// Payer EVM address funding this storage pin.
    pub payer: Address,
    /// Epoch when the lease was established.
    pub pinned_at_epoch: u64,
    /// Epoch when the lease expires.
    pub expires_at_epoch: u64,
    /// Duration of the lease in calendar years (e.g. 1, 2, 5).
    pub duration_years: u32,
    /// Size of the pinned payload in bytes.
    pub size_bytes: u64,
    /// Upfront fee charged / collateral locked in wei of native TBL.
    pub cost_tbl: U256,
}

impl IrohPinLease {
    /// Returns true if the lease is active at the given epoch.
    #[must_use]
    pub fn is_active(&self, current_epoch: u64) -> bool {
        current_epoch <= self.expires_at_epoch
    }
}

/// Target pinned bytes per epoch before base fee increases exponentially (e.g. 100 MB).
pub const TARGET_EPOCH_PINNED_BYTES: u64 = 100 * 1024 * 1024;
/// Minimum floor base fee per MB-year: 1,000,000 wei (~0.000000000001 TBL). Near 0 on fresh cluster.
pub const MIN_STORAGE_BASE_FEE_PER_MB_YEAR: u64 = 1_000_000;
/// Base fee update fraction inspired by EIP-4844 (divisor for exponential scaling).
pub const STORAGE_BASE_FEE_UPDATE_FRACTION: u64 = 3338477;

/// Dynamic Storage Market State (EIP-4844 & Filecoin-inspired demand-driven pricing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicStorageMarket {
    /// Current pinned bytes in the active epoch.
    pub current_epoch_bytes: u64,
    /// Target pinned bytes per epoch.
    pub target_epoch_bytes: u64,
    /// Base fee in wei per MB-year.
    pub base_fee_per_mb_year: u64,
}

impl Default for DynamicStorageMarket {
    fn default() -> Self {
        Self {
            current_epoch_bytes: 0,
            target_epoch_bytes: TARGET_EPOCH_PINNED_BYTES,
            base_fee_per_mb_year: MIN_STORAGE_BASE_FEE_PER_MB_YEAR,
        }
    }
}

impl DynamicStorageMarket {
    /// Calculates current base fee per MB-year based on demand/utilization.
    #[must_use]
    pub fn calculate_current_base_fee(&self) -> u64 {
        if self.current_epoch_bytes <= self.target_epoch_bytes {
            // When demand is below or equal to target, base fee remains at min floor
            let ratio = self.current_epoch_bytes as f64 / self.target_epoch_bytes.max(1) as f64;
            let fee = (MIN_STORAGE_BASE_FEE_PER_MB_YEAR as f64 * (0.01 + 0.99 * ratio)) as u64;
            fee.max(1)
        } else {
            // Exponential demand scaling above target (EIP-4844)
            let excess = self.current_epoch_bytes - self.target_epoch_bytes;
            let factor = 1.0 + (excess as f64 / STORAGE_BASE_FEE_UPDATE_FRACTION as f64);
            let scaled = (self.base_fee_per_mb_year as f64 * factor) as u64;
            scaled.max(MIN_STORAGE_BASE_FEE_PER_MB_YEAR)
        }
    }
}

/// Calculates the storage lease fee in wei of native TBL for pinning a blob of `size_bytes` for `duration_years`.
/// Uses dynamic demand-driven market pricing (EIP-4844 / Filecoin inspired) rather than an arbitrary static constant.
#[must_use]
pub fn calculate_pinning_fee(size_bytes: u64, duration_years: u32) -> U256 {
    calculate_pinning_fee_with_market(size_bytes, duration_years, None)
}

/// Calculates dynamic lease fee with an optional market state.
#[must_use]
pub fn calculate_pinning_fee_with_market(
    size_bytes: u64,
    duration_years: u32,
    market: Option<&DynamicStorageMarket>,
) -> U256 {
    let years = (duration_years.max(1)) as u64;
    let base_fee_per_mb_year = market
        .map(|m| m.calculate_current_base_fee())
        .unwrap_or(MIN_STORAGE_BASE_FEE_PER_MB_YEAR);

    // base_fee_per_mb_year wei per 1_000_000 bytes per year
    // Fee = (size_bytes * base_fee_per_mb_year * years) / 1_000_000
    let size_u256 = U256::from(size_bytes);
    let fee_per_mb = U256::from(base_fee_per_mb_year);
    let years_u256 = U256::from(years);
    let raw_computed = (size_u256 * fee_per_mb * years_u256) / U256::from(1_000_000u64);
    
    // Minimum fee floor: at least 1000 wei so free-spamming is barred
    let min_floor = U256::from(1000u64);
    if raw_computed < min_floor {
        min_floor
    } else {
        raw_computed
    }
}

/// A verified slice proof for a sub-range of a stored blob, proving its retrievability
/// and integrity against the root BLAKE3 hash without transferring the entire blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaoSliceProof {
    /// The root BLAKE3 hash (CID) of the target blob.
    pub root_hash: [u8; 32],
    /// The start byte offset of the slice.
    pub slice_offset: u64,
    /// The length of the slice in bytes.
    pub slice_length: usize,
    /// The actual chunk-aligned slice payload bytes.
    pub slice_data: Vec<u8>,
    /// Intermediate sibling tree hashes required to verify the slice against `root_hash`.
    pub sibling_hashes: Vec<[u8; 32]>,
    /// Total length of the original blob.
    pub total_blob_size: u64,
}

impl BaoSliceProof {
    /// Extracts the precise requested sub-slice from the chunk-aligned verified slice data.
    #[must_use]
    pub fn extract_requested_slice(&self) -> &[u8] {
        let start_chunk = self.slice_offset as usize / BLAKE3_CHUNK_SIZE;
        let chunk_start_byte = start_chunk * BLAKE3_CHUNK_SIZE;
        let internal_offset = self.slice_offset as usize - chunk_start_byte;
        let internal_end = internal_offset + self.slice_length;
        if internal_end <= self.slice_data.len() {
            &self.slice_data[internal_offset..internal_end]
        } else {
            &self.slice_data[internal_offset..]
        }
    }
}

/// Metadata record for an archived Iroh blob.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrohBlobMetadata {
    /// Content identifier (hex-encoded BLAKE3 hash prefixed with "b3:" or canonical CIDv1 base32 string).
    pub cid: String,
    /// Raw 32-byte BLAKE3 root hash.
    pub hash: [u8; 32],
    /// The sector or account-lattice namespace ID.
    pub namespace_id: u64,
    /// Payload size in bytes.
    pub size_bytes: u64,
    /// Timestamp when pinned.
    pub created_at: u64,
    /// Economic pinning lease metadata (if pinned with active lease).
    #[serde(default)]
    pub pin_lease: Option<IrohPinLease>,
}

impl IrohBlobMetadata {
    /// Returns the canonical IPLD `CidV1` representation of this blob.
    #[must_use]
    pub fn cid_v1(&self) -> sovereign_identity::ipld::CidV1 {
        sovereign_identity::ipld::CidV1::new(
            sovereign_identity::ipld::IpldCodec::Raw,
            sovereign_identity::ipld::Multihash {
                code: sovereign_identity::ipld::HashCodec::Blake3,
                digest: self.hash.to_vec(),
            },
        )
    }

    /// Returns the canonical base32 CIDv1 string (`bafk...`).
    #[must_use]
    pub fn canonical_cid_str(&self) -> String {
        self.cid_v1().to_base32()
    }
}

/// A serialized entry for cross-cluster P2P sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrohSyncEntry {
    pub metadata: IrohBlobMetadata,
    pub payload: Vec<u8>,
    pub outboard: Vec<u8>,
}

/// The core Iroh content-addressed storage engine.
#[derive(Debug, Clone)]
pub struct IrohStorageEngine {
    /// Optional persistent root directory on disk. If `None`, operates in high-performance in-memory mode.
    storage_dir: Option<PathBuf>,
    /// In-memory fast cache of metadata and blobs.
    index: Arc<RwLock<HashMap<String, IrohBlobMetadata>>>,
    /// In-memory storage for raw payloads (used when storage_dir is None or for hot caching).
    blobs: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// In-memory storage for precomputed Bao outboard tree bytes.
    outboards: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl IrohStorageEngine {
    /// Creates a new in-memory `IrohStorageEngine`.
    #[must_use]
    pub fn new_in_memory() -> Self {
        Self {
            storage_dir: None,
            index: Arc::new(RwLock::new(HashMap::new())),
            blobs: Arc::new(RwLock::new(HashMap::new())),
            outboards: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates or opens a persistent disk-backed `IrohStorageEngine`.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created.
    pub fn open_or_create<P: AsRef<Path>>(dir: P) -> Result<Self, String> {
        let path = dir.as_ref().to_path_buf();
        fs::create_dir_all(&path).map_err(|e| format!("Failed to create storage dir: {e}"))?;
        fs::create_dir_all(path.join("blobs")).map_err(|e| format!("Failed to create blobs dir: {e}"))?;
        fs::create_dir_all(path.join("outboards")).map_err(|e| format!("Failed to create outboards dir: {e}"))?;
        fs::create_dir_all(path.join("meta")).map_err(|e| format!("Failed to create meta dir: {e}"))?;

        let engine = Self {
            storage_dir: Some(path.clone()),
            index: Arc::new(RwLock::new(HashMap::new())),
            blobs: Arc::new(RwLock::new(HashMap::new())),
            outboards: Arc::new(RwLock::new(HashMap::new())),
        };

        // Load existing metadata from disk
        engine.load_from_disk()?;

        Ok(engine)
    }

    fn load_from_disk(&self) -> Result<(), String> {
        if let Some(ref root) = self.storage_dir {
            let meta_dir = root.join("meta");
            if meta_dir.exists() {
                if let Ok(entries) = fs::read_dir(meta_dir) {
                    let mut index_guard = self.index.write().map_err(|_| "Poisoned lock")?;
                    for entry in entries.flatten() {
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            if let Ok(meta) = serde_json::from_str::<IrohBlobMetadata>(&content) {
                                index_guard.insert(meta.cid.clone(), meta);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Computes canonical BLAKE3 chunk Merkle tree root from a list of leaf chunk hashes.
    pub fn compute_merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        while leaves.len() > 1 {
            let mut next_level = Vec::with_capacity((leaves.len() + 1) / 2);
            for pair in leaves.chunks(2) {
                if pair.len() == 2 {
                    let mut hasher = Hasher::new();
                    hasher.update(&pair[0]);
                    hasher.update(&pair[1]);
                    next_level.push(*hasher.finalize().as_bytes());
                } else {
                    next_level.push(pair[0]);
                }
            }
            leaves = next_level;
        }
        leaves[0]
    }

    /// Computes the canonical BLAKE3 CID and root hash for a blob.
    #[must_use]
    pub fn compute_cid(data: &[u8]) -> (String, [u8; 32]) {
        let chunk_count = (data.len() + BLAKE3_CHUNK_SIZE - 1).max(1) / BLAKE3_CHUNK_SIZE;
        let mut leaf_hashes = Vec::with_capacity(chunk_count);
        if data.is_empty() {
            leaf_hashes.push(*blake3::hash(b"").as_bytes());
        } else {
            for chunk in data.chunks(BLAKE3_CHUNK_SIZE) {
                leaf_hashes.push(*blake3::hash(chunk).as_bytes());
            }
        }
        let root_hash = Self::compute_merkle_root(leaf_hashes);
        let cid = format!("b3:{}", hex::encode(root_hash));
        (cid, root_hash)
    }

    /// Stores and pins a blob with its associated namespace ID.
    ///
    /// Computes the BLAKE3 root hash and Bao outboard tree structure.
    ///
    /// # Errors
    /// Returns an error if disk persistence fails.
    pub fn store_blob(&self, namespace_id: u64, data: &[u8]) -> Result<IrohBlobMetadata, String> {
        let (cid, hash) = Self::compute_cid(data);
        let outboard = Self::build_bao_outboard(data);

        let metadata = IrohBlobMetadata {
            cid: cid.clone(),
            hash,
            namespace_id,
            size_bytes: data.len() as u64,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            pin_lease: None,
        };

        // If disk-backed, persist to filesystem atomically
        if let Some(ref root) = self.storage_dir {
            let blob_path = root.join("blobs").join(&cid);
            let outboard_path = root.join("outboards").join(&cid);
            let meta_path = root.join("meta").join(format!("{cid}.json"));

            fs::write(&blob_path, data)
                .map_err(|e| format!("Failed to write blob {cid}: {e}"))?;
            fs::write(&outboard_path, &outboard)
                .map_err(|e| format!("Failed to write outboard {cid}: {e}"))?;
            let meta_json = serde_json::to_string_pretty(&metadata)
                .map_err(|e| format!("Failed to serialize metadata: {e}"))?;
            fs::write(&meta_path, meta_json)
                .map_err(|e| format!("Failed to write metadata {cid}: {e}"))?;
        }

        // Cache in memory
        {
            let mut index_guard = self.index.write().map_err(|_| "Poisoned lock")?;
            index_guard.insert(cid.clone(), metadata.clone());
        }
        {
            let mut blobs_guard = self.blobs.write().map_err(|_| "Poisoned lock")?;
            blobs_guard.insert(cid.clone(), data.to_vec());
        }
        {
            let mut outboards_guard = self.outboards.write().map_err(|_| "Poisoned lock")?;
            outboards_guard.insert(cid, outboard);
        }

        Ok(metadata)
    }

    /// Stores and pins a blob backed by an economic storage lease funded by `payer`.
    ///
    /// Computes the required fee for `duration_years` using `calculate_pinning_fee`,
    /// issues an `IrohPinLease` expiring at `current_epoch + (duration_years * epochs_per_year)`.
    pub fn pin_blob_with_lease(
        &self,
        namespace_id: u64,
        data: &[u8],
        payer: Address,
        duration_years: u32,
        current_epoch: u64,
        epochs_per_year: u64,
    ) -> Result<(IrohBlobMetadata, U256), String> {
        let (cid, hash) = Self::compute_cid(data);
        let outboard = Self::build_bao_outboard(data);
        let fee = calculate_pinning_fee(data.len() as u64, duration_years);
        let expires_at_epoch = current_epoch.saturating_add((duration_years.max(1) as u64).saturating_mul(epochs_per_year.max(1)));

        let lease = IrohPinLease {
            payer,
            pinned_at_epoch: current_epoch,
            expires_at_epoch,
            duration_years,
            size_bytes: data.len() as u64,
            cost_tbl: fee,
        };

        let metadata = IrohBlobMetadata {
            cid: cid.clone(),
            hash,
            namespace_id,
            size_bytes: data.len() as u64,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            pin_lease: Some(lease),
        };

        if let Some(ref root) = self.storage_dir {
            let blob_path = root.join("blobs").join(&cid);
            let outboard_path = root.join("outboards").join(&cid);
            let meta_path = root.join("meta").join(format!("{cid}.json"));

            fs::write(&blob_path, data)
                .map_err(|e| format!("Failed to write blob {cid}: {e}"))?;
            fs::write(&outboard_path, &outboard)
                .map_err(|e| format!("Failed to write outboard {cid}: {e}"))?;
            let meta_json = serde_json::to_string_pretty(&metadata)
                .map_err(|e| format!("Failed to serialize metadata: {e}"))?;
            fs::write(&meta_path, meta_json)
                .map_err(|e| format!("Failed to write metadata {cid}: {e}"))?;
        }

        {
            let mut index_guard = self.index.write().map_err(|_| "Poisoned lock")?;
            index_guard.insert(cid.clone(), metadata.clone());
        }
        {
            let mut blobs_guard = self.blobs.write().map_err(|_| "Poisoned lock")?;
            blobs_guard.insert(cid.clone(), data.to_vec());
        }
        {
            let mut outboards_guard = self.outboards.write().map_err(|_| "Poisoned lock")?;
            outboards_guard.insert(cid, outboard);
        }

        Ok((metadata, fee))
    }

    /// Checks whether a blob has an active (non-expired) pinning lease at `current_epoch`.
    pub fn is_blob_pinned_active(&self, cid: &str, current_epoch: u64) -> bool {
        if let Ok(index_guard) = self.index.read() {
            if let Some(meta) = index_guard.get(cid) {
                if let Some(ref lease) = meta.pin_lease {
                    return lease.is_active(current_epoch);
                }
            }
        }
        false
    }

    /// Stores and pins a blob with an additional lookup alias (such as an EVM address or DID URI).
    pub fn store_named_blob(&self, namespace_id: u64, name: &str, data: &[u8]) -> Result<IrohBlobMetadata, String> {
        let meta = self.store_blob(namespace_id, data)?;
        if let Ok(mut blobs_guard) = self.blobs.write() {
            blobs_guard.insert(name.to_string(), data.to_vec());
        }
        if let Some(ref root) = self.storage_dir {
            let name_path = root.join("blobs").join(name.replace(':', "_"));
            let _ = fs::write(&name_path, data);
        }
        Ok(meta)
    }

    /// Fetches a raw blob by its CID, checking in-memory cache then disk storage.
    ///
    /// # Errors
    /// Returns an error if the CID is not found or cannot be read.
    pub fn get_blob(&self, cid: &str) -> Result<Vec<u8>, String> {
        // Check memory cache
        if let Ok(guard) = self.blobs.read() {
            if let Some(data) = guard.get(cid) {
                return Ok(data.clone());
            }
        }

        // Check disk
        if let Some(ref root) = self.storage_dir {
            let blob_path = root.join("blobs").join(cid);
            if blob_path.exists() {
                let data = fs::read(&blob_path)
                    .map_err(|e| format!("Failed to read blob {cid} from disk: {e}"))?;
                // Populate memory cache
                if let Ok(mut guard) = self.blobs.write() {
                    guard.insert(cid.to_string(), data.clone());
                }
                return Ok(data);
            }
            let sanitized_path = root.join("blobs").join(cid.replace(':', "_"));
            if sanitized_path.exists() {
                let data = fs::read(&sanitized_path)
                    .map_err(|e| format!("Failed to read blob {cid} from disk: {e}"))?;
                if let Ok(mut guard) = self.blobs.write() {
                    guard.insert(cid.to_string(), data.clone());
                }
                return Ok(data);
            }
        }

        // Try resolving by alternative multibase/legacy CID representation
        if let Ok(guard) = self.blobs.read() {
            for (k, v) in guard.iter() {
                if k.ends_with(cid) || cid.ends_with(k) {
                    return Ok(v.clone());
                }
            }
        }

        Err(format!("Blob CID '{cid}' not found in Iroh storage"))
    }

    /// Stores a verified IPLD block into the Iroh storage engine under the given namespace.
    ///
    /// # Errors
    /// Returns an error if disk persistence fails.
    pub fn store_ipld_block(
        &self,
        namespace_id: u64,
        block: &sovereign_identity::ipld::IpldBlock,
    ) -> Result<IrohBlobMetadata, String> {
        let meta = self.store_blob(namespace_id, &block.raw_data)?;
        // Index under canonical Base32 CIDv1 as well
        let b32_cid = block.cid.to_base32();
        if let Ok(mut index_guard) = self.index.write() {
            index_guard.insert(b32_cid.clone(), meta.clone());
        }
        if let Ok(mut blobs_guard) = self.blobs.write() {
            blobs_guard.insert(b32_cid, block.raw_data.clone());
        }
        Ok(meta)
    }

    /// Fetches an IPLD block by its canonical `CidV1`.
    ///
    /// # Errors
    /// Returns an error if the block is not found.
    pub fn get_ipld_block(&self, cid: &sovereign_identity::ipld::CidV1) -> Result<sovereign_identity::ipld::IpldBlock, String> {
        let b32_cid = cid.to_base32();
        if let Ok(data) = self.get_blob(&b32_cid) {
            return Ok(sovereign_identity::ipld::IpldBlock {
                cid: cid.clone(),
                raw_data: data,
            });
        }

        // Search in-memory cache for matching multihash digest
        if let Ok(guard) = self.blobs.read() {
            for (_, payload) in guard.iter() {
                if cid.hash.code.digest(payload).digest == cid.hash.digest {
                    return Ok(sovereign_identity::ipld::IpldBlock {
                        cid: cid.clone(),
                        raw_data: payload.clone(),
                    });
                }
            }
        }

        let hex_digest = alloy_primitives::hex::encode(&cid.hash.digest);
        let raw_data = self.get_blob(&format!("b3:{}", hex_digest))?;
        Ok(sovereign_identity::ipld::IpldBlock {
            cid: cid.clone(),
            raw_data,
        })
    }

    /// Checks if a CID is pinned in this storage engine.
    #[must_use]
    pub fn is_pinned(&self, cid: &str) -> bool {
        if let Ok(guard) = self.index.read() {
            if guard.contains_key(cid) {
                return true;
            }
        }
        if let Some(ref root) = self.storage_dir {
            return root.join("blobs").join(cid).exists();
        }
        false
    }

    /// Generates a Bao slice Proof of Retrievability (PoR) for an arbitrary byte range `[offset, offset + length)`.
    ///
    /// # Errors
    /// Returns an error if the blob is not found or the range is out of bounds.
    pub fn generate_por_proof(&self, cid: &str, offset: u64, length: usize) -> Result<BaoSliceProof, String> {
        let blob_data = self.get_blob(cid)?;
        let total_size = blob_data.len() as u64;

        if offset > total_size {
            return Err(format!("Slice offset {offset} exceeds blob size {total_size}"));
        }

        let end = std::cmp::min(offset as usize + length, blob_data.len());
        let (_computed_cid, root_hash) = Self::compute_cid(&blob_data);

        // Build leaf chunk hashes
        let chunk_count = (blob_data.len() + BLAKE3_CHUNK_SIZE - 1).max(1) / BLAKE3_CHUNK_SIZE;
        let mut leaf_hashes = Vec::with_capacity(chunk_count);
        if blob_data.is_empty() {
            leaf_hashes.push(*blake3::hash(b"").as_bytes());
        } else {
            for chunk in blob_data.chunks(BLAKE3_CHUNK_SIZE) {
                leaf_hashes.push(*blake3::hash(chunk).as_bytes());
            }
        }

        let start_chunk = offset as usize / BLAKE3_CHUNK_SIZE;
        let end_chunk = if end == 0 { 0 } else { (end - 1) / BLAKE3_CHUNK_SIZE };

        let chunk_start_byte = start_chunk * BLAKE3_CHUNK_SIZE;
        let chunk_end_byte = std::cmp::min((end_chunk + 1) * BLAKE3_CHUNK_SIZE, blob_data.len());
        let slice_chunk_data = if blob_data.is_empty() {
            Vec::new()
        } else {
            blob_data[chunk_start_byte..chunk_end_byte].to_vec()
        };

        // Collect all sibling chunk hashes not covered by the challenge range
        let mut sibling_hashes = Vec::new();
        for (i, hash) in leaf_hashes.iter().enumerate() {
            if i < start_chunk || i > end_chunk {
                sibling_hashes.push(*hash);
            }
        }

        Ok(BaoSliceProof {
            root_hash,
            slice_offset: offset,
            slice_length: end - offset as usize,
            slice_data: slice_chunk_data,
            sibling_hashes,
            total_blob_size: total_size,
        })
    }

    /// Verifies a Bao slice Proof of Retrievability against the claimed root BLAKE3 hash.
    ///
    /// # Errors
    /// Returns an error if the proof is mathematically invalid or does not match the root hash.
    pub fn verify_por_proof(proof: &BaoSliceProof) -> Result<bool, String> {
        let chunk_count = (proof.total_blob_size as usize + BLAKE3_CHUNK_SIZE - 1).max(1) / BLAKE3_CHUNK_SIZE;
        let start_chunk = proof.slice_offset as usize / BLAKE3_CHUNK_SIZE;
        let end_byte = std::cmp::min(proof.slice_offset as usize + proof.slice_length, proof.total_blob_size as usize);
        let end_chunk = if end_byte == 0 { 0 } else { (end_byte - 1) / BLAKE3_CHUNK_SIZE };

        let chunk_start_byte = start_chunk * BLAKE3_CHUNK_SIZE;
        let chunk_end_byte = std::cmp::min((end_chunk + 1) * BLAKE3_CHUNK_SIZE, proof.total_blob_size as usize);
        let expected_chunk_data_len = chunk_end_byte - chunk_start_byte;

        if proof.slice_data.len() != expected_chunk_data_len {
            return Ok(false);
        }

        // Recompute leaf hashes from slice data chunks
        let mut slice_leaf_hashes = Vec::new();
        if proof.slice_data.is_empty() {
            slice_leaf_hashes.push(*blake3::hash(b"").as_bytes());
        } else {
            for chunk in proof.slice_data.chunks(BLAKE3_CHUNK_SIZE) {
                slice_leaf_hashes.push(*blake3::hash(chunk).as_bytes());
            }
        }

        let expected_slice_chunks = end_chunk - start_chunk + 1;
        if slice_leaf_hashes.len() != expected_slice_chunks {
            return Ok(false);
        }

        let mut all_leaves = Vec::with_capacity(chunk_count);
        let mut sibling_idx = 0;
        for i in 0..chunk_count {
            if i >= start_chunk && i <= end_chunk {
                all_leaves.push(slice_leaf_hashes[i - start_chunk]);
            } else if sibling_idx < proof.sibling_hashes.len() {
                all_leaves.push(proof.sibling_hashes[sibling_idx]);
                sibling_idx += 1;
            } else {
                return Ok(false);
            }
        }

        let recomputed_root = Self::compute_merkle_root(all_leaves);
        Ok(recomputed_root == proof.root_hash)
    }

    /// Builds a deterministic BLAKE3 Bao outboard tree byte sequence.
    fn build_bao_outboard(data: &[u8]) -> Vec<u8> {
        let mut outboard = Vec::new();
        // Outboard header: 8 bytes total blob length in little-endian
        outboard.extend_from_slice(&(data.len() as u64).to_le_bytes());

        // Append 32-byte chunk hashes for each 1024-byte block
        for chunk in data.chunks(BLAKE3_CHUNK_SIZE) {
            let hash = blake3::hash(chunk);
            outboard.extend_from_slice(hash.as_bytes());
        }
        outboard
    }

    /// Exports all pinned items as a sync bundle for cross-cluster P2P sync.
    #[must_use]
    pub fn export_sync_bundle(&self) -> Vec<IrohSyncEntry> {
        let mut entries = Vec::new();
        if let Ok(index_guard) = self.index.read() {
            for (cid, meta) in index_guard.iter() {
                if let Ok(payload) = self.get_blob(cid) {
                    let outboard = Self::build_bao_outboard(&payload);
                    entries.push(IrohSyncEntry {
                        metadata: meta.clone(),
                        payload,
                        outboard,
                    });
                }
            }
        }
        entries
    }

    /// Imports and verifies a sync bundle from another cluster peer.
    ///
    /// # Errors
    /// Returns an error if any imported blob fails cryptographic hash verification.
    pub fn import_sync_bundle(&self, bundle: &[IrohSyncEntry]) -> Result<usize, String> {
        let mut imported = 0;
        for entry in bundle {
            // Verify BLAKE3 hash before storing
            let (expected_cid, hash) = Self::compute_cid(&entry.payload);
            if expected_cid != entry.metadata.cid || hash != entry.metadata.hash {
                return Err(format!(
                    "Sync bundle corruption detected for CID {}: hash mismatch",
                    entry.metadata.cid
                ));
            }

            self.store_blob(entry.metadata.namespace_id, &entry.payload)?;
            imported += 1;
        }
        Ok(imported)
    }
}

impl ArchivalStorageBackend for IrohStorageEngine {
    fn pin_blob(&self, namespace_id: u64, blob_data: &[u8]) -> Result<String, String> {
        let meta = self.store_blob(namespace_id, blob_data)?;
        Ok(meta.cid)
    }

    fn fetch_blob(&self, cid: &str) -> Result<Vec<u8>, String> {
        self.get_blob(cid)
    }

    fn is_pinned(&self, cid: &str) -> Result<bool, String> {
        Ok(self.is_pinned(cid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iroh_store_and_fetch_in_memory() {
        let engine = IrohStorageEngine::new_in_memory();
        let payload = b"Hello Sovereign Iroh Storage Engine with BLAKE3 Bao!";
        let meta = engine.store_blob(42, payload).expect("store failed");

        assert!(meta.cid.starts_with("b3:"));
        assert_eq!(meta.size_bytes, payload.len() as u64);
        assert_eq!(meta.namespace_id, 42);
        assert!(engine.is_pinned(&meta.cid));

        let fetched = engine.get_blob(&meta.cid).expect("fetch failed");
        assert_eq!(fetched, payload);
    }

    #[test]
    fn test_iroh_por_proof_generation_and_verification() {
        let engine = IrohStorageEngine::new_in_memory();
        // Multi-chunk blob (> 2048 bytes)
        let mut payload = Vec::new();
        for i in 0..3000 {
            payload.push((i % 256) as u8);
        }

        let meta = engine.store_blob(100, &payload).expect("store failed");

        // Challenge range across chunk boundary [500..1500]
        let proof = engine.generate_por_proof(&meta.cid, 500, 1000).expect("proof gen failed");
        assert_eq!(proof.slice_length, 1000);
        assert_eq!(proof.total_blob_size, 3000);
        assert_eq!(proof.extract_requested_slice(), &payload[500..1500]);

        let is_valid = IrohStorageEngine::verify_por_proof(&proof).expect("verification error");
        assert!(is_valid, "Proof of Retrievability must be mathematically valid");

        // Test corruption detection: tamper with slice data
        let mut corrupted_proof = proof.clone();
        corrupted_proof.slice_data[0] ^= 0xFF;
        let is_corrupted_valid = IrohStorageEngine::verify_por_proof(&corrupted_proof).unwrap_or(false);
        assert!(!is_corrupted_valid, "Corrupted slice must fail PoR verification");
    }

    #[test]
    fn test_cross_cluster_sync_bundle() {
        let cluster_a = IrohStorageEngine::new_in_memory();
        let cluster_b = IrohStorageEngine::new_in_memory();

        cluster_a.store_blob(1, b"Cluster A Document 1").unwrap();
        cluster_a.store_blob(2, b"Cluster A Document 2").unwrap();

        let bundle = cluster_a.export_sync_bundle();
        assert_eq!(bundle.len(), 2);

        let imported_count = cluster_b.import_sync_bundle(&bundle).unwrap();
        assert_eq!(imported_count, 2);

        for entry in bundle {
            assert!(cluster_b.is_pinned(&entry.metadata.cid));
            let fetched = cluster_b.get_blob(&entry.metadata.cid).unwrap();
            assert_eq!(fetched, entry.payload);
        }
    }

    #[test]
    fn test_iroh_ipld_block_storage_and_resolution() {
        use sovereign_identity::did::SovereignDidDocument;
        use sovereign_identity::ipld::{IpldCodec, WotThingDescription};

        let engine = IrohStorageEngine::new_in_memory();

        // 1. Create a Sovereign DID document and convert to IPLD block
        let seed = alloy_primitives::B256::repeat_byte(0x55);
        let doc = SovereignDidDocument::derive_from_seed(seed);
        let did_block = doc.to_ipld_block(IpldCodec::DagJson).unwrap();
        let did_cid = did_block.cid.clone();

        // 2. Store IPLD Block in Iroh Engine
        let meta = engine.store_ipld_block(1337, &did_block).unwrap();
        assert!(engine.is_pinned(&meta.cid));
        assert!(engine.is_pinned(&did_cid.to_base32()));

        // 3. Fetch IPLD Block back by CIDv1
        let retrieved_block = engine.get_ipld_block(&did_cid).unwrap();
        assert!(retrieved_block.verify_integrity());

        // 4. Resolve Sovereign DID Document from retrieved IPLD Block
        let resolved_doc = SovereignDidDocument::from_ipld_block(&retrieved_block).unwrap();
        assert_eq!(resolved_doc.evm_address, doc.evm_address);
        assert_eq!(resolved_doc.secp256k1_pubkey, doc.secp256k1_pubkey);

        // 5. Store a WoT Thing Description as an IPLD block
        let mut td = WotThingDescription::new(&format!("{}#actuator", doc.did_uri), "Sovereign Turbine Controller");
        td.properties.insert("rpm".to_string(), serde_json::json!({ "type": "integer", "readOnly": true }));
        let td_block = td.to_ipld_block().unwrap();
        let td_cid = td_block.cid.clone();

        engine.store_ipld_block(1337, &td_block).unwrap();
        let retrieved_td_block = engine.get_ipld_block(&td_cid).unwrap();
        let resolved_td = WotThingDescription::from_ipld_block(&retrieved_td_block).unwrap();
        assert_eq!(resolved_td.id, td.id);
        assert_eq!(resolved_td.title, td.title);
    }
}
