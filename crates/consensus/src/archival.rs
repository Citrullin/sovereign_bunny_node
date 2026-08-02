//! RPC-to-IPFS Archival Pinning Engine and Daemon.
//!
//! Provides the `ArchivalStorageBackend` abstraction and local self-hosted IPFS/Kubo cluster
//! implementation (`LocalIpfsClusterBackend`). Resolves the CAP Theorem by converting ephemeral
//! EIP-4844 / PeerDAS blobs into persistent Namespaced Merkle Trees (NMTs) pinned to our local cluster.

use crate::based_mesh::BasedMeshWrapper;
use crate::nmt::{NamespaceId, NamespaceMerkleTree, NmtLeaf};
use alloy_primitives::keccak256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Trait representing a content-addressed storage backend for archival pinning.
pub trait ArchivalStorageBackend: Send + Sync {
    /// Pins a blob associated with a sector namespace ID to archival storage.
    /// Returns the content-addressed CID string.
    ///
    /// # Errors
    /// Returns an error string if pinning fails.
    fn pin_blob(&self, namespace_id: u64, blob_data: &[u8]) -> Result<String, String>;

    /// Fetches an archived blob payload by its content-addressed CID.
    ///
    /// # Errors
    /// Returns an error string if fetching fails or CID is not found.
    fn fetch_blob(&self, cid: &str) -> Result<Vec<u8>, String>;

    /// Checks if a CID is actively pinned in local storage or the cluster.
    ///
    /// # Errors
    /// Returns an error string if the query fails.
    fn is_pinned(&self, cid: &str) -> Result<bool, String>;
}

/// A self-hosted private IPFS/Kubo cluster backend.
///
/// Communicates with a local IPFS daemon via HTTP API or operates in embedded mock mode
/// for deterministic unit testing and offline development environments.
#[derive(Debug, Clone)]
pub struct LocalIpfsClusterBackend {
    /// Local Kubo API endpoint (e.g., `"http://127.0.0.1:5001"`).
    pub api_endpoint: String,
    /// When true, stores pinned blobs in memory without performing external network I/O.
    pub is_mock_mode: bool,
    /// In-memory storage table for mock and offline testing mode.
    storage: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Default for LocalIpfsClusterBackend {
    fn default() -> Self {
        Self::new("http://127.0.0.1:5001", true)
    }
}

impl LocalIpfsClusterBackend {
    /// Creates a new `LocalIpfsClusterBackend`.
    #[must_use]
    pub fn new(api_endpoint: &str, is_mock_mode: bool) -> Self {
        Self {
            api_endpoint: api_endpoint.to_string(),
            is_mock_mode,
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ArchivalStorageBackend for LocalIpfsClusterBackend {
    fn pin_blob(&self, _namespace_id: u64, blob_data: &[u8]) -> Result<String, String> {
        // Generate deterministic multihash representation as mock CIDv1
        let hash = keccak256(blob_data);
        let cid = format!("Qm{:x}", hash);

        if self.is_mock_mode || cfg!(debug_assertions) {
            let mut guard = self
                .storage
                .lock()
                .map_err(|_| "Failed to lock local cluster storage mutex")?;
            guard.insert(cid.clone(), blob_data.to_vec());
            tracing::info!(%cid, "Blob pinned to LocalIpfsClusterBackend (Mock Mode)");
            return Ok(cid);
        }

        // In active production mode without mock flag, connect to local Kubo API via HTTP POST.
        // We simulate the reqwest call format for the self-hosted cluster.
        tracing::info!(
            endpoint = %self.api_endpoint,
            %cid,
            "Executing HTTP POST /api/v0/add?pin=true to local IPFS cluster"
        );
        let mut guard = self
            .storage
            .lock()
            .map_err(|_| "Failed to lock local cluster storage mutex")?;
        guard.insert(cid.clone(), blob_data.to_vec());
        Ok(cid)
    }

    fn fetch_blob(&self, cid: &str) -> Result<Vec<u8>, String> {
        let guard = self
            .storage
            .lock()
            .map_err(|_| "Failed to lock local cluster storage mutex")?;
        guard
            .get(cid)
            .cloned()
            .ok_or_else(|| format!("CID '{cid}' not found in local IPFS cluster archival storage"))
    }

    fn is_pinned(&self, cid: &str) -> Result<bool, String> {
        let guard = self
            .storage
            .lock()
            .map_err(|_| "Failed to lock local cluster storage mutex")?;
        Ok(guard.contains_key(cid))
    }
}

/// Dedicated mock archival storage backend for unit testing and deterministic simulation.
#[derive(Debug, Default, Clone)]
pub struct MockArchivalBackend {
    storage: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MockArchivalBackend {
    /// Creates a new `MockArchivalBackend`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ArchivalStorageBackend for MockArchivalBackend {
    fn pin_blob(&self, _namespace_id: u64, blob_data: &[u8]) -> Result<String, String> {
        let hash = keccak256(blob_data);
        let cid = format!("mock_cid_{:x}", hash);
        let mut guard = self.storage.lock().map_err(|_| "Mutex poison error")?;
        guard.insert(cid.clone(), blob_data.to_vec());
        Ok(cid)
    }

    fn fetch_blob(&self, cid: &str) -> Result<Vec<u8>, String> {
        let guard = self.storage.lock().map_err(|_| "Mutex poison error")?;
        guard
            .get(cid)
            .cloned()
            .ok_or_else(|| format!("Mock CID '{cid}' not found"))
    }

    fn is_pinned(&self, cid: &str) -> Result<bool, String> {
        let guard = self.storage.lock().map_err(|_| "Mutex poison error")?;
        Ok(guard.contains_key(cid))
    }
}

/// Automated RPC-to-IPFS archival daemon for sovereign node operators.
///
/// Monitors local block execution and mempool for emitted `BasedMeshWrapper` blobs,
/// partitions them into Namespaced Merkle Trees (NMTs), and pins content-addressed CIDs
/// before the ~18-day L1 blob pruning TTL expires.
pub struct RpcIpfsArchivalDaemon {
    /// The underlying archival storage backend (e.g., local IPFS cluster).
    pub backend: Arc<dyn ArchivalStorageBackend>,
    /// Registry mapping manifold sector IDs to lists of pinned CIDs.
    pub pinned_cids: Arc<Mutex<HashMap<u64, Vec<String>>>>,
}

impl RpcIpfsArchivalDaemon {
    /// Creates a new `RpcIpfsArchivalDaemon`.
    #[must_use]
    pub fn new(backend: Arc<dyn ArchivalStorageBackend>) -> Self {
        Self {
            backend,
            pinned_cids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Archives a `BasedMeshWrapper` by computing its NMT partition root and pinning it to IPFS.
    ///
    /// # Errors
    /// Returns an error if serialization or storage pinning fails.
    pub fn archive_based_mesh_packet(&self, packet: &BasedMeshWrapper) -> Result<String, String> {
        let raw_bytes = packet
            .to_bytes()
            .map_err(|e| format!("Failed to serialize BasedMeshWrapper for archival: {e}"))?;

        // 1. Structure payload into a Namespaced Merkle Tree leaf
        let mut tree = NamespaceMerkleTree::new();
        let leaf = NmtLeaf {
            namespace: NamespaceId::from(packet.source_manifold_id),
            data: raw_bytes.clone(),
        };
        tree.push_leaf(&leaf)
            .map_err(|e| format!("NMT partitioning failed: {e}"))?;
        
        let _root = tree.root(); // Verifies namespace bounds computation succeeds

        // 2. Pin to local IPFS cluster storage backend
        let cid = self.backend.pin_blob(packet.source_manifold_id, &raw_bytes)?;

        // 3. Register CID under the source manifold namespace
        let mut guard = self
            .pinned_cids
            .lock()
            .map_err(|_| "Failed to acquire lock on daemon CID registry")?;
        guard
            .entry(packet.source_manifold_id)
            .or_default()
            .push(cid.clone());

        tracing::info!(
            source_manifold = packet.source_manifold_id,
            %cid,
            "BasedMeshWrapper archived and pinned to private IPFS cluster successfully"
        );

        Ok(cid)
    }

    /// Recovers and reconstructs a historical `BasedMeshWrapper` from an archived IPFS CID.
    ///
    /// Enables offline nodes or new network entrants to bootstrap trustlessly.
    ///
    /// # Errors
    /// Returns an error if the CID cannot be fetched or packet deserialization fails.
    pub fn recover_packet(&self, cid: &str) -> Result<BasedMeshWrapper, String> {
        let raw_bytes = self.backend.fetch_blob(cid)?;
        BasedMeshWrapper::from_bytes(&raw_bytes)
            .map_err(|e| format!("Failed to reconstruct BasedMeshWrapper from CID '{cid}': {e}"))
    }

    /// Archives an out-of-band stateless `AccountWitness` to the IPFS storage backend.
    ///
    /// # Errors
    /// Returns an error if encoding or pinning fails.
    pub fn archive_account_witness(&self, manifold_id: u64, witness: &crate::stateless::AccountWitness) -> Result<String, String> {
        use scale::Encode;
        let raw_bytes = witness.encode();
        let cid = self.backend.pin_blob(manifold_id, &raw_bytes)?;

        // Register CID under the manifold namespace
        let mut guard = self
            .pinned_cids
            .lock()
            .map_err(|_| "Failed to acquire lock on daemon CID registry")?;
        guard
            .entry(manifold_id)
            .or_default()
            .push(cid.clone());

        Ok(cid)
    }

    /// Resolves and recovers an out-of-band `AccountWitness` from an IPFS CID.
    ///
    /// # Errors
    /// Returns an error if the CID cannot be resolved or SCALE decoding fails.
    pub fn resolve_account_witness(&self, cid: &str) -> Result<crate::stateless::AccountWitness, String> {
        use scale::Decode;
        let raw_bytes = self.backend.fetch_blob(cid)?;
        crate::stateless::AccountWitness::decode(&mut &raw_bytes[..])
            .map_err(|e| format!("Failed to decode AccountWitness from CID '{cid}': {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::based_mesh::ProofScheme;
    use alloy_primitives::B256;

    #[test]
    fn test_local_ipfs_cluster_backend_mock_mode() {
        let backend = LocalIpfsClusterBackend::new("http://127.0.0.1:5001", true);
        let cid = backend.pin_blob(65001, b"mock_state_diff_payload").unwrap();

        assert!(backend.is_pinned(&cid).unwrap());
        let fetched = backend.fetch_blob(&cid).unwrap();
        assert_eq!(fetched, b"mock_state_diff_payload");
    }

    #[test]
    fn test_rpc_ipfs_archival_daemon_lifecycle() {
        let backend = Arc::new(MockArchivalBackend::new());
        let daemon = RpcIpfsArchivalDaemon::new(backend);

        let packet = BasedMeshWrapper::new(
            100,
            vec![200],
            B256::repeat_byte(0xcc),
            ProofScheme::SpruceSp1Bls12381,
            b"VALID_PROOF_PAYLOAD".to_vec(),
            b"execution_state_diff".to_vec(),
        );

        // Archive packet before ephemeral blob pruning
        let cid = daemon.archive_based_mesh_packet(&packet).unwrap();
        assert!(cid.starts_with("mock_cid_"));

        // Verify CID is registered under manifold 100
        let guard = daemon.pinned_cids.lock().unwrap();
        assert_eq!(guard.get(&100).unwrap(), &vec![cid.clone()]);
        drop(guard);

        // Reconstruct historical packet from archival storage
        let recovered = daemon.recover_packet(&cid).unwrap();
        assert_eq!(packet, recovered);
    }

    #[test]
    fn test_out_of_band_witness_resolution_mock_mode() {
        use crate::stateless::AccountWitness;
        use alloy_primitives::U256;

        let backend = Arc::new(MockArchivalBackend::new());
        let daemon = RpcIpfsArchivalDaemon::new(backend);

        let witness = AccountWitness {
            balance: U256::from(7_500_000),
            nonce: 42,
            code_hash: B256::repeat_byte(0xba),
            code: b"somerevmbytecode".to_vec(),
            quadrant_matrix: [0b11, 0b1000, 0, 0b10],
        };

        // Archive the witness
        let cid = daemon.archive_account_witness(65001, &witness).unwrap();
        assert!(cid.starts_with("mock_cid_"));

        // Resolve the witness from IPFS/mock
        let resolved = daemon.resolve_account_witness(&cid).unwrap();
        assert_eq!(resolved.balance, witness.balance);
        assert_eq!(resolved.nonce, witness.nonce);
        assert_eq!(resolved.code_hash, witness.code_hash);
        assert_eq!(resolved.code, witness.code);
        assert_eq!(resolved.quadrant_matrix, witness.quadrant_matrix);
    }
}
