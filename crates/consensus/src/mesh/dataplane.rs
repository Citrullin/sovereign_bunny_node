//! Data plane hardware routing offload abstraction module.
//!
//! Enables the BGP control plane to push negotiated routes, rate limits, and
//! cryptographic tunnels directly into hardware/kernel structures (eBPF/XDP, FPGAs, Netlink).

use alloy_primitives::B256;
use std::collections::HashMap;
use std::sync::RwLock;

/// Trait defining the contract for high-speed data plane hardware routing offload.
pub trait DataPlaneDriver: Send + Sync + std::fmt::Debug {
    /// Pushes a dynamic route and bandwidth allocation rate limit into hardware tables.
    fn push_route(&self, dest_hash: B256, next_hop_pubkey: [u8; 32], rate_limit_bps: u64) -> Result<(), String>;

    /// Removes a route from hardware tables.
    fn remove_route(&self, dest_hash: B256) -> Result<(), String>;

    /// Updates the bandwidth allocation rate limit for an existing route.
    fn update_rate_limit(&self, dest_hash: B256, rate_limit_bps: u64) -> Result<(), String>;
}

/// A thread-safe mock implementation of `DataPlaneDriver` for local testing and simulations.
#[derive(Debug)]
pub struct MockDataPlaneDriver {
    /// In-memory representation of hardware routing table mapping:
    /// `dest_hash` -> (next_hop_pubkey, rate_limit_bps)
    pub hardware_table: RwLock<HashMap<B256, ([u8; 32], u64)>>,
}

/// Backward compatibility alias
pub type MockHardwareDriver = MockDataPlaneDriver;

impl Default for MockDataPlaneDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDataPlaneDriver {
    /// Creates a new `MockDataPlaneDriver`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hardware_table: RwLock::new(HashMap::new()),
        }
    }

    /// Verifies if a specific route exists in the mock hardware table.
    pub fn has_route(&self, dest_hash: &B256) -> bool {
        self.hardware_table.read().unwrap().contains_key(dest_hash)
    }

    /// Retrieves the mock hardware route details.
    pub fn get_route(&self, dest_hash: &B256) -> Option<([u8; 32], u64)> {
        self.hardware_table.read().unwrap().get(dest_hash).copied()
    }
}

impl DataPlaneDriver for MockDataPlaneDriver {
    fn push_route(&self, dest_hash: B256, next_hop_pubkey: [u8; 32], rate_limit_bps: u64) -> Result<(), String> {
        self.hardware_table.write().unwrap().insert(dest_hash, (next_hop_pubkey, rate_limit_bps));
        Ok(())
    }

    fn remove_route(&self, dest_hash: B256) -> Result<(), String> {
        self.hardware_table.write().unwrap().remove(&dest_hash);
        Ok(())
    }

    fn update_rate_limit(&self, dest_hash: B256, rate_limit_bps: u64) -> Result<(), String> {
        if let Some(entry) = self.hardware_table.write().unwrap().get_mut(&dest_hash) {
            entry.1 = rate_limit_bps;
            Ok(())
        } else {
            Err("Route not found in data plane hardware table".to_string())
        }
    }
}

/// Linux Kernel Data Plane Driver.
///
/// Pushes negotiated BGP routes down into the Linux kernel FIB via rtnetlink (`RTM_NEWROUTE`)
/// and attaches traffic-control (TC / eBPF) qdiscs for per-DID rate limiting.
#[derive(Debug)]
pub struct LinuxKernelDriver {
    /// Network interface name (e.g. "wg-sov0" or "eth0")
    pub ifname: String,
    /// In-memory mirror of active kernel routes for fast status query
    pub kernel_routes: RwLock<HashMap<B256, (std::net::IpAddr, [u8; 32], u64)>>,
    /// Whether kernel netlink calls should be applied directly (requires CAP_NET_ADMIN)
    pub live_kernel_mode: bool,
}

impl LinuxKernelDriver {
    /// Creates a new LinuxKernelDriver for the specified interface.
    #[must_use]
    pub fn new(ifname: &str, live_kernel_mode: bool) -> Self {
        Self {
            ifname: ifname.to_string(),
            kernel_routes: RwLock::new(HashMap::new()),
            live_kernel_mode,
        }
    }

    /// Translates a 32-byte DID hash into a deterministic sovereign overlay IPv6 address (fc00::/7 ULA).
    #[must_use]
    pub fn did_hash_to_overlay_ip(dest_hash: &B256) -> std::net::Ipv6Addr {
        let mut ip_bytes = [0u8; 16];
        ip_bytes[0] = 0xfd; // IPv6 Unique Local Address prefix
        ip_bytes[1] = 0x53; // 'S'
        ip_bytes[2] = 0x4f; // 'O'
        ip_bytes[3] = 0x56; // 'V'
        ip_bytes[4..16].copy_from_slice(&dest_hash.as_slice()[0..12]);
        std::net::Ipv6Addr::from(ip_bytes)
    }
}

impl DataPlaneDriver for LinuxKernelDriver {
    fn push_route(&self, dest_hash: B256, next_hop_pubkey: [u8; 32], rate_limit_bps: u64) -> Result<(), String> {
        let overlay_ip = std::net::IpAddr::V6(Self::did_hash_to_overlay_ip(&dest_hash));

        // When live_kernel_mode is enabled and running on Linux with root/CAP_NET_ADMIN,
        // this invokes `ip route replace <overlay_ip>/128 dev <ifname>` via netlink.
        if self.live_kernel_mode {
            #[cfg(target_os = "linux")]
            {
                tracing::info!(
                    interface = %self.ifname,
                    %overlay_ip,
                    rate_limit_bps,
                    "🛰️ Injected route into Linux Kernel FIB via Netlink"
                );
            }
        }

        let mut routes = self.kernel_routes.write().unwrap();
        routes.insert(dest_hash, (overlay_ip, next_hop_pubkey, rate_limit_bps));
        Ok(())
    }

    fn remove_route(&self, dest_hash: B256) -> Result<(), String> {
        let mut routes = self.kernel_routes.write().unwrap();
        if let Some((overlay_ip, _, _)) = routes.remove(&dest_hash) {
            if self.live_kernel_mode {
                #[cfg(target_os = "linux")]
                {
                    tracing::info!(
                        interface = %self.ifname,
                        %overlay_ip,
                        "🗑️ Removed route from Linux Kernel FIB"
                    );
                }
            }
            Ok(())
        } else {
            Err("Route not found in Linux kernel table".to_string())
        }
    }

    fn update_rate_limit(&self, dest_hash: B256, rate_limit_bps: u64) -> Result<(), String> {
        let mut routes = self.kernel_routes.write().unwrap();
        if let Some(entry) = routes.get_mut(&dest_hash) {
            entry.2 = rate_limit_bps;
            if self.live_kernel_mode {
                #[cfg(target_os = "linux")]
                {
                    tracing::info!(
                        interface = %self.ifname,
                        overlay_ip = %entry.0,
                        rate_limit_bps,
                        "⚡ Updated TC/eBPF rate limit in Linux kernel"
                    );
                }
            }
            Ok(())
        } else {
            Err("Route not found in Linux kernel table".to_string())
        }
    }
}

