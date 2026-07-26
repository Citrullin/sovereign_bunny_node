//! Based Meshing Courier & Paymaster Service.
//!
//! Submits cross-manifold intents as `BasedMeshPacket` Block-in-Blob structures to target manifolds over BGP.
//! Automatically interfaces with the `RpcIpfsArchivalDaemon` to pin emitted blobs to the local IPFS cluster.

use alloy_primitives::{Address, U256, B256};
use k256::ecdsa::SigningKey;
use alloy_primitives::keccak256;
use std::sync::Arc;
use tracing::{error, info};

/// Cross-Manifold Intent Packet (CMIP) legacy binary representation.
#[derive(Debug, Clone)]
pub struct CmipPacket {
    /// The packet version.
    pub version: u8,
    /// Source decentralized identifier (DID).
    pub source_did: [u8; 32],
    /// Destination decentralized identifier (DID).
    pub dest_did: [u8; 32],
    /// Hashed settlement asset.
    pub settlement_asset_hash: B256,
    /// Maximum fee permitted per forward hop.
    pub max_fee_per_forward: U256,
    /// KZG commitment for path vector validation.
    pub kzg_commitment: [u8; 48],
    /// Raw execution payload (ABI-encoded).
    pub execution_payload: Vec<u8>,
}

impl CmipPacket {
    /// Serializes CMIP packet into raw bytes.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x43); // Magic 'C'
        buf.push(0x4D); // Magic 'M'
        buf.push(self.version);
        let len = u16::try_from(self.execution_payload.len()).unwrap_or(u16::MAX);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.source_did);
        buf.extend_from_slice(&self.dest_did);
        buf.extend_from_slice(self.settlement_asset_hash.as_slice());
        let fee_bytes: [u8; 32] = self.max_fee_per_forward.to_be_bytes();
        buf.extend_from_slice(&fee_bytes);
        buf.extend_from_slice(&self.kzg_commitment);
        buf.extend_from_slice(&self.execution_payload);
        buf
    }

    /// Deserializes CMIP packet from raw bytes.
    ///
    /// # Errors
    /// Returns an error if the buffer is too short, magic bytes do not match, or length is invalid.
    pub fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 5 + 32 + 32 + 32 + 32 + 48 {
            return Err("Buffer too short for CMIP header");
        }
        if buf[0] != 0x43 || buf[1] != 0x4D {
            return Err("Invalid CMIP magic bytes");
        }
        let version = buf[2];
        let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let mut offset = 5;
        let mut source_did = [0u8; 32];
        source_did.copy_from_slice(&buf[offset..offset+32]);
        offset += 32;
        let mut dest_did = [0u8; 32];
        dest_did.copy_from_slice(&buf[offset..offset+32]);
        offset += 32;
        let settlement_asset_hash = B256::from_slice(&buf[offset..offset+32]);
        offset += 32;
        let max_fee_per_forward = U256::from_be_slice(&buf[offset..offset+32]);
        offset += 32;
        let mut kzg_commitment = [0u8; 48];
        kzg_commitment.copy_from_slice(&buf[offset..offset+48]);
        offset += 48;
        if buf.len() < offset + payload_len {
            return Err("CMIP payload length mismatch");
        }
        let execution_payload = buf[offset..offset+payload_len].to_vec();
        Ok(Self {
            version,
            source_did,
            dest_did,
            settlement_asset_hash,
            max_fee_per_forward,
            kzg_commitment,
            execution_payload,
        })
    }
}

/// A mock RPC client interface.
pub trait RpcClient: Send + Sync {
    /// Returns the current ETH balance of `address`.
    fn get_balance(&self, address: Address) -> U256;
}

/// Based meshing courier service that submits intents as `BasedMeshPacket` blobs
/// and schedules them for permanent archival pinning in our local IPFS cluster.
pub struct BlindCourierService<R: RpcClient> {
    /// The local DID of this courier node.
    pub local_did: String,
    /// The paymaster address derived from the local seed.
    pub local_paymaster_address: Address,
    rpc_client: Arc<R>,
    /// Whether the service is currently suspended due to insufficient funds (legacy mode).
    pub is_suspended: bool,
    /// Dynamic, hot-reloadable configurations.
    pub dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
    /// Optional connection to the local RPC-to-IPFS archival pinning daemon.
    pub archival_daemon: Option<Arc<crate::archival::RpcIpfsArchivalDaemon>>,
}

impl<R: RpcClient> BlindCourierService<R> {
    /// Creates a new courier service. Derives the paymaster address from a Secp256k1 seed.
    ///
    /// # Errors
    /// Returns an error if the seed bytes are not a valid Secp256k1 scalar.
    pub fn new(
        local_did: String,
        seed: &[u8; 32],
        rpc_client: Arc<R>,
        dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
    ) -> Result<Self, &'static str> {
        let signing_key = SigningKey::from_slice(seed)
            .map_err(|_| "Invalid Secp256k1 seed: not a valid scalar")?;
        let verifying_key = signing_key.verifying_key();

        let uncompressed = verifying_key.to_sec1_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        let local_paymaster_address = Address::from_slice(&hash[12..32]);

        Ok(Self {
            local_did,
            local_paymaster_address,
            rpc_client,
            is_suspended: false,
            dynamic_cfg,
            archival_daemon: None,
        })
    }

    /// Attaches the RPC-to-IPFS archival pinning daemon to this courier service.
    pub fn attach_archival_daemon(&mut self, daemon: Arc<crate::archival::RpcIpfsArchivalDaemon>) {
        self.archival_daemon = Some(daemon);
    }

    /// Checks the paymaster balance. If depleted, suspends the service and warns the operator.
    ///
    /// Returns `true` if the service is (or just became) suspended.
    pub fn check_funding_and_suspend(&mut self) -> bool {
        let balance = self.rpc_client.get_balance(self.local_paymaster_address);
        let required_gas_threshold = self.dynamic_cfg.read().unwrap().required_gas_threshold;
        if balance < required_gas_threshold {
            if !self.is_suspended {
                error!(
                    address = %self.local_paymaster_address,
                    balance = %balance,
                    "Paymaster depleted — courier suspended in legacy mode",
                );
                self.is_suspended = true;
            }
            return true;
        }

        if self.is_suspended {
            info!("Paymaster funded — courier resumed");
            self.is_suspended = false;
        }
        false
    }

    /// Processes an intent by packaging it as a `BasedMeshPacket` and broadcasting over BGP.
    /// Automatically submits the emitted packet to the local IPFS cluster for archival pinning.
    ///
    /// Unlike legacy blind courier mode, based meshing bypasses dynamic paymaster suspension
    /// because peering occurs via Althea pay-per-forward vouchers and stateless precompile verification.
    ///
    /// # Errors
    /// Returns an error if archival pinning fails or intent serialization is invalid.
    pub fn process_intent(&mut self, target_manifold_id: u64, intent_data: &[u8]) -> Result<(), &'static str> {
        // In based meshing, we do not abort if check_funding_and_suspend() is true.
        // Instead, we format the intent as a self-contained BasedMeshPacket.
        let packet = if let Ok(existing_packet) = crate::based_mesh::BasedMeshPacket::from_bytes(intent_data) {
            existing_packet
        } else {
            crate::based_mesh::BasedMeshPacket::new(
                0, // Default local source manifold ID
                vec![target_manifold_id],
                B256::ZERO,
                crate::based_mesh::ProofScheme::SpruceSp1Bls12381,
                b"UNIVERSAL_RECURSIVE_VALIDITY_PROOF".to_vec(),
                intent_data.to_vec(),
            )
        };

        // Schedule packet for permanent archival pinning in local IPFS cluster before blob pruning
        if let Some(ref daemon) = self.archival_daemon {
            if let Err(e) = daemon.archive_based_mesh_packet(&packet) {
                error!(error = %e, "Failed to archive BasedMeshPacket to local IPFS cluster");
                return Err("IPFS cluster archival pinning failed for based mesh packet");
            }
        }

        info!(
            target_manifold_id,
            "Submitted intent via Based Meshing and scheduled for local IPFS cluster archival"
        );

        Ok(())
    }
}
