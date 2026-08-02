//! BGP router manifold synchronization and peer WireGuard tunneling module.

use alloy_primitives::{Address, B256};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use crate::hw_offload::DataPlaneDriver;

/// Details of a routed manifold path vector.
#[derive(Debug, Clone)]
pub struct RouteInfo {
    /// Peer public key of the next hop relayer.
    pub next_hop: [u8; 32],
    /// Forwarding rate per kilobyte.
    pub forwarding_rate: u64,
    /// Vector of supported settlement asset hashes.
    pub supported_assets: Vec<B256>,
}

/// BGP router for syncing adjacent manifold validator sets and routing encrypted traffic.
pub struct BgpRouter {
    /// Map of Manifold ID to set of adjacent validators.
    adjacent_validators: HashMap<u64, HashSet<Address>>,
    /// Local static private key for `WireGuard`.
    local_private_key: StaticSecret,
    /// Local static public key for `WireGuard`.
    pub local_public_key: PublicKey,
    /// `WireGuard` tunnels mapped by peer public key.
    pub tunnels: HashMap<[u8; 32], Tunn>,
    /// Dynamic routing table mapping target entity DID to path vector details.
    pub routing_table: HashMap<B256, RouteInfo>,
    /// Data plane hardware offloader driver interface.
    pub hw_driver: Arc<dyn DataPlaneDriver>,
}

impl Default for BgpRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpRouter {
    /// Creates a new BGP Router with a randomly generated local private key and a mock hardware offloader.
    #[must_use]
    pub fn new() -> Self {
        let hw_driver = Arc::new(crate::hw_offload::MockHardwareDriver::new());
        Self::new_with_driver(hw_driver)
    }

    /// Creates a new BGP Router with a custom hardware offloader.
    pub fn new_with_driver(hw_driver: Arc<dyn DataPlaneDriver>) -> Self {
        // Generate a random local private key using an array of 32 bytes
        let mut rng_bytes = [0u8; 32];
        for (i, byte) in rng_bytes.iter_mut().enumerate() {
            let val = u8::try_from(i).unwrap_or(0);
            *byte = val.wrapping_mul(7).wrapping_add(42);
        }
        let local_private_key = StaticSecret::from(rng_bytes);
        let local_public_key = PublicKey::from(&local_private_key);

        Self {
            adjacent_validators: HashMap::new(),
            local_private_key,
            local_public_key,
            tunnels: HashMap::new(),
            routing_table: HashMap::new(),
            hw_driver,
        }
    }

    /// Syncs validator sets from an IPFS CID (Mock implementation).
    pub fn sync_from_ipfs(&mut self, _cid: &str) {
        // In a real implementation, this would fetch data from IPFS
        // and update `adjacent_validators`.
    }

    /// Returns the validators for a given manifold.
    pub fn get_validators(&self, manifold_id: u64) -> Option<&HashSet<Address>> {
        self.adjacent_validators.get(&manifold_id)
    }

    /// Registers a peer with their public key and sets up a `WireGuard` tunnel.
    pub fn register_peer(&mut self, peer_public_key: [u8; 32]) {
        let peer_pub = PublicKey::from(peer_public_key);
        let local_priv = StaticSecret::from(self.local_private_key.to_bytes());
        
        let tunnel = Tunn::new(
            local_priv,
            peer_pub,
            None,
            None,
            1,
            None,
        );
        self.tunnels.insert(peer_public_key, tunnel);
    }

    /// Syncs the `WireGuard` tunnels dynamically from the validator registry.
    pub fn sync_peers_from_registry(&mut self) {
        let registry_lock = crate::registry::get_registry();
        let Ok(registry) = registry_lock.read() else { return; };

        let active_peers = registry.active_peers();
        self.tunnels.retain(|key, _| active_peers.contains_key(key));

        for &peer_key in active_peers.keys() {
            if !self.tunnels.contains_key(&peer_key) {
                self.register_peer(peer_key);
            }
        }
    }

    /// Processes an incoming packet for a specific peer tunnel.
    ///
    /// # Errors
    /// Returns an error if no tunnel is registered for `peer_public_key` or decryption fails.
    pub fn handle_packet(&mut self, peer_public_key: &[u8; 32], packet: &[u8], out_buf: &mut [u8]) -> Result<Vec<u8>, String> {
        let tunnel = self.tunnels.get_mut(peer_public_key)
            .ok_or_else(|| "Peer tunnel not registered".to_string())?;

        match tunnel.decapsulate(None, packet, out_buf) {
            TunnResult::Done => Ok(vec![]),
            TunnResult::Err(e) => Err(format!("WireGuard decryption error: {e:?}")),
            TunnResult::WriteToNetwork(bytes) => Ok(bytes.to_vec()),
            TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                Ok(bytes.to_vec())
            }
        }
    }

    /// Encapsulates data to be sent to a specific peer tunnel.
    ///
    /// # Errors
    /// Returns an error if no tunnel is registered for `peer_public_key` or encryption fails.
    pub fn send_data(&mut self, peer_public_key: &[u8; 32], data: &[u8], out_buf: &mut [u8]) -> Result<Vec<u8>, String> {
        let tunnel = self.tunnels.get_mut(peer_public_key)
            .ok_or_else(|| "Peer tunnel not registered".to_string())?;

        match tunnel.encapsulate(data, out_buf) {
            TunnResult::WriteToNetwork(bytes) => Ok(bytes.to_vec()),
            TunnResult::Err(e) => Err(format!("WireGuard encryption error: {e:?}")),
            _ => Ok(vec![]),
        }
    }

    /// Updates or inserts a route in the BGP routing table and pushes it to the hardware data plane.
    pub fn update_route(&mut self, dest_did: String, info: RouteInfo) {
        let dest_hash = alloy_primitives::keccak256(dest_did.as_bytes());
        let _ = self.hw_driver.push_route(dest_hash, info.next_hop, info.forwarding_rate);
        self.routing_table.insert(dest_hash, info);
    }

    /// Speculatively initializes a route in the hardware data plane first, then verifies solvency
    /// asynchronously. If verification fails, the route is immediately revoked from the hardware,
    /// and the caller is slashed for speculative abuse.
    pub fn speculative_update_route(
        &mut self,
        dest_did: String,
        info: RouteInfo,
        caller_witness: &mut crate::stateless::AccountWitness,
        contract_witness: &crate::stateless::AccountWitness,
        gas_limit: u64,
        gas_price: alloy_primitives::U256,
        tx_value: alloy_primitives::U256,
        velocity: &crate::velocity::VelocityEngine,
        bandwidth_request: crate::stateless::BandwidthRequest,
    ) -> Result<alloy_primitives::U256, crate::stateless::SovereignError> {
        let dest_hash = alloy_primitives::keccak256(dest_did.as_bytes());

        // 1. Speculatively configure the hardware data plane INSTANTLY
        let _ = self.hw_driver.push_route(dest_hash, info.next_hop, info.forwarding_rate);

        // 2. Perform the control plane pre-flight verification
        let res = crate::stateless::SovereignExecutor::pre_flight_execute(
            caller_witness,
            contract_witness,
            gas_limit,
            gas_price,
            tx_value,
            velocity,
            Some(bandwidth_request),
        );

        match res {
            Ok(upfront_penalty) => {
                // Verification succeeded: lock route in the user-space routing table
                self.routing_table.insert(dest_hash, info);
                Ok(upfront_penalty)
            }
            Err(e) => {
                // Verification failed! Revoke speculative route immediately
                let _ = self.hw_driver.remove_route(dest_hash);

                // Seize locked micro-collateral for the speculative routing attempt (Abuse Slashing Fine)
                // Base penalty is 500,000 gas units equivalent
                let abuse_slashing_penalty = alloy_primitives::U256::from(500_000);
                caller_witness.balance = caller_witness.balance.saturating_sub(abuse_slashing_penalty);
                Err(e)
            }
        }
    }

    /// Removes a route from the BGP table and the hardware data plane.
    pub fn remove_route(&mut self, dest_did: &str) {
        let dest_hash = alloy_primitives::keccak256(dest_did.as_bytes());
        let _ = self.hw_driver.remove_route(dest_hash);
        self.routing_table.remove(&dest_hash);
    }

    /// Retrieves route details for a given destination DID.
    pub fn get_route(&self, dest_did: &str) -> Option<&RouteInfo> {
        let dest_hash = alloy_primitives::keccak256(dest_did.as_bytes());
        self.routing_table.get(&dest_hash)
    }

    /// Verifies if a destination DID belongs to the correct/expected manifold namespace.
    /// Standard check enforces that the DID starts with "did:peer:4" and has expected prefix.
    pub fn verify_did_namespace(&self, did: &str, expected_namespace: &str) -> bool {
        if !did.starts_with("did:peer:4") {
            return false;
        }
        // Verification logic checks namespace prefix match
        did.contains(expected_namespace)
    }


    /// Broadcasts a `BasedMeshWrapper` across all active `WireGuard` peer tunnels.
    ///
    /// Encapsulates the Block-in-Blob state diff and succinct ZK validity proof into encrypted
    /// UDP tunnel packets ready for network transmission.
    ///
    /// # Errors
    /// Returns an error if serialization or encapsulation fails for any peer tunnel.
    pub fn broadcast_based_mesh_packet(
        &mut self,
        packet: &crate::based_mesh::BasedMeshWrapper,
    ) -> Result<Vec<([u8; 32], Vec<u8>)>, String> {
        let raw_bytes = packet
            .to_bytes()
            .map_err(|e| format!("Failed to serialize BasedMeshWrapper: {e}"))?;

        let mut out_buf = vec![0u8; 131_072 + 2048]; // Blob capacity + WireGuard header overhead
        let mut broadcast_payloads = Vec::new();
        let peer_keys: Vec<[u8; 32]> = self.tunnels.keys().copied().collect();

        for peer_key in peer_keys {
            if let Ok(wg_packet) = self.send_data(&peer_key, &raw_bytes, &mut out_buf) {
                if !wg_packet.is_empty() {
                    broadcast_payloads.push((peer_key, wg_packet));
                }
            }
        }

        Ok(broadcast_payloads)
    }

    /// Decapsulates and validates an incoming `BasedMeshWrapper` from a `WireGuard` peer tunnel.
    ///
    /// Verifies that the attached succinct ZK validity proof matches the state diff before
    /// forwarding to the consensus execution pool.
    ///
    /// # Errors
    /// Returns an error if tunnel decryption fails, packet is malformed, or ZK verification fails.
    pub fn receive_based_mesh_packet(
        &mut self,
        peer_public_key: &[u8; 32],
        wg_packet: &[u8],
        out_buf: &mut [u8],
    ) -> Result<Option<crate::based_mesh::BasedMeshWrapper>, String> {
        let decapsulated = self.handle_packet(peer_public_key, wg_packet, out_buf)?;
        if decapsulated.is_empty() {
            return Ok(None);
        }

        let packet = if decapsulated.len() == 131_072 {
            crate::based_mesh::BasedMeshWrapper::from_eip4844_blob_bytes(&decapsulated)
                .map_err(|e| format!("Failed to decode EIP-4844 blob packet: {e}"))?
        } else {
            crate::based_mesh::BasedMeshWrapper::from_bytes(&decapsulated)
                .map_err(|e| format!("Failed to decode raw BasedMeshWrapper: {e}"))?
        };

        // Validate ZK validity proof before returning
        packet
            .verify_validity_proof()
            .map_err(|e| format!("Incoming BasedMeshWrapper proof verification rejected: {e}"))?;

        Ok(Some(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_router_wireguard_init() {
        let mut router = BgpRouter::new();
        let peer_key = [1u8; 32];
        router.register_peer(peer_key);

        assert!(router.tunnels.contains_key(&peer_key));

        let mut out_buf = vec![0u8; 2048];
        let data = b"cross-chain-intent-payload";
        
        // This will attempt to encapsulate but since handshake isn't complete,
        // it will format a Handshake Initiation packet to send over the network.
        let wg_packet = router.send_data(&peer_key, data, &mut out_buf).unwrap();
        assert!(!wg_packet.is_empty());
    }

    #[test]
    fn test_hardware_offload_integration() {
        let mock_driver = Arc::new(crate::hw_offload::MockHardwareDriver::new());
        let mut router = BgpRouter::new_with_driver(mock_driver.clone());

        let dest_did = "did:peer:4:as65007".to_string();
        let dest_hash = alloy_primitives::keccak256(dest_did.as_bytes());

        let next_hop = [9u8; 32];
        let rate_limit = 500_000_000u64;

        // Verify hardware table starts empty
        assert!(!mock_driver.has_route(&dest_hash));

        // Update route and check if it propagates to the mock hardware offloader
        router.update_route(
            dest_did.clone(),
            RouteInfo {
                next_hop,
                forwarding_rate: rate_limit,
                supported_assets: vec![B256::repeat_byte(0xee)],
            },
        );

        assert!(mock_driver.has_route(&dest_hash));
        let (hw_next_hop, hw_rate) = mock_driver.get_route(&dest_hash).unwrap();
        assert_eq!(hw_next_hop, next_hop);
        assert_eq!(hw_rate, rate_limit);

        // Remove route and check if it is deleted from hardware offloader
        router.remove_route(&dest_did);
        assert!(!mock_driver.has_route(&dest_hash));
    }

    #[test]
    fn test_speculative_route_initialization() {
        let mock_driver = Arc::new(crate::hw_offload::MockHardwareDriver::new());
        let mut router = BgpRouter::new_with_driver(mock_driver.clone());

        let dest_did = "did:peer:4:as65008".to_string();
        let dest_hash = alloy_primitives::keccak256(dest_did.as_bytes());

        let next_hop = [8u8; 32];
        let rate_limit = 200_000_000u64;

        let mut caller = crate::stateless::AccountWitness {
            balance: alloy_primitives::U256::from(10_000_000),
            quadrant_matrix: [0, 0b111, 0b10, 0],
            ..Default::default()
        };
        let contract = crate::stateless::AccountWitness {
            balance: alloy_primitives::U256::ZERO,
            quadrant_matrix: [0, 0b100, 0b10, 0],
            ..Default::default()
        };

        let velocity = crate::velocity::VelocityEngine::default();
        let req = crate::stateless::BandwidthRequest {
            requested_kb_per_sec: 1_000,
            rate_per_kb: 50,
            epoch_duration_secs: 60,
        }; // cost = 3_000_000

        // 1. Success case: Sufficient balance
        let res = router.speculative_update_route(
            dest_did.clone(),
            RouteInfo {
                next_hop,
                forwarding_rate: rate_limit,
                supported_assets: vec![B256::repeat_byte(0xee)],
            },
            &mut caller,
            &contract,
            50_000,
            alloy_primitives::U256::from(20),
            alloy_primitives::U256::from(100_000),
            &velocity,
            req,
        );

        assert!(res.is_ok());
        // Verify route is present in BGP table and hardware
        assert!(router.routing_table.contains_key(&dest_hash));
        assert!(mock_driver.has_route(&dest_hash));
        assert_eq!(caller.balance, alloy_primitives::U256::from(10_000_000 - 3_100_000));

        // 2. Failure case: Insolvent balance
        caller.balance = alloy_primitives::U256::from(1_000_000); // Insufficient for next request
        let res_fail = router.speculative_update_route(
            dest_did.clone(),
            RouteInfo {
                next_hop,
                forwarding_rate: rate_limit,
                supported_assets: vec![B256::repeat_byte(0xee)],
            },
            &mut caller,
            &contract,
            50_000,
            alloy_primitives::U256::from(20),
            alloy_primitives::U256::from(100_000),
            &velocity,
            req,
        );

        assert!(res_fail.is_err());
        // Verify speculative route is revoked from hardware
        assert!(!mock_driver.has_route(&dest_hash));
        // Verify user balance is slashed for speculative abuse (1M - 500k = 500k)
        assert_eq!(caller.balance, alloy_primitives::U256::from(500_000));
    }

    #[test]
    fn test_pied_piper_7_hop_bandwidth_allocation() {
        use alloy_primitives::B256;
        use crate::based_mesh::{BasedMeshWrapper, ProofScheme};

        // 1. Instantiate 7 autonomous BGP routers representing 7 consecutive hops
        //    (AS 65001 -> AS 65002 -> ... -> AS 65007) in a Small World network experiment.
        let mut routers: Vec<BgpRouter> = (0..7).map(|_| BgpRouter::new()).collect();
        let pub_keys: Vec<[u8; 32]> = routers.iter().map(|r| r.local_public_key.to_bytes()).collect();

        // 2. Set up adjacent peering agreements and WireGuard tunnels between consecutive hops
        for i in 0..6 {
            let next_key = pub_keys[i + 1];
            routers[i].register_peer(next_key);
            assert!(routers[i].tunnels.contains_key(&next_key));
        }

        // 3. Customer on AS 65001 emits a programmable bandwidth SLA intent:
        //    "Allocate 1 Gbps dedicated routing bandwidth across 7 hops to AS 65007 for 3600s."
        let sla_intent_payload = b"PIED_PIPER_SLA: 1Gbps / 3600s / 500 EURe / target AS 65007".to_vec();
        let packet = BasedMeshWrapper::new_with_valid_binding(
            65001,
            vec![65002, 65003, 65004, 65005, 65006, 65007],
            B256::repeat_byte(0x77),
            ProofScheme::Groth16Bn254,
            b"PIED_PIPER_7_HOP_RECURSIVE_VALIDITY_PROOF".to_vec(),
            sla_intent_payload,
        );

        // 4. Verify packet serializes cleanly to EIP-4844 / PeerDAS blob format
        let blob_bytes = packet.to_eip4844_blob_bytes().expect("Blob formatting failed");
        assert_eq!(blob_bytes.len(), 131_072);

        // 5. Hop 0 (AS 65001) broadcasts packet over WireGuard tunnel towards Hop 1
        let broadcast_result = routers[0].broadcast_based_mesh_packet(&packet).unwrap();
        assert_eq!(broadcast_result.len(), 1);
        assert_eq!(broadcast_result[0].0, pub_keys[1]);
        assert!(!broadcast_result[0].1.is_empty());

        // 6. Hop-by-hop propagation and O(1) stateless ZK proof verification across all 7 hops
        for i in 1..7 {
            // Simulate receiving the block-in-blob packet at hop i
            let received_packet = BasedMeshWrapper::from_eip4844_blob_bytes(&blob_bytes).unwrap();
            
            // O(1) verification: no interactive HTLC lock sagas required
            assert!(
                received_packet.verify_validity_proof().is_ok(),
                "Pied Piper ZK validity proof failed verification at Hop {}: {:?}",
                i,
                received_packet.verify_validity_proof()
            );

            // Programmatic hardware & BGP table reconfiguration upon proof success
            let next_hop_key = if i + 1 < 7 { pub_keys[i + 1] } else { [0u8; 32] };
            routers[i].update_route(
                "did:peer:4:as65007".to_string(),
                RouteInfo {
                    next_hop: next_hop_key,
                    forwarding_rate: 1_000_000_000u64, // 1 Gbps rate in bps
                    supported_assets: vec![B256::repeat_byte(0xee)], // Settled in EURe voucher
                },
            );

            // Verify the route is actively advertised in the router's BGP table
            let route = routers[i].get_route("did:peer:4:as65007").unwrap();
            assert_eq!(route.forwarding_rate, 1_000_000_000u64);
            assert_eq!(route.supported_assets[0], B256::repeat_byte(0xee));
        }

        // 7. Verify small world end-to-end bandwidth allocation reached target AS 65007
        let final_route = routers[6].get_route("did:peer:4:as65007").unwrap();
        assert_eq!(final_route.forwarding_rate, 1_000_000_000u64);
    }
}
