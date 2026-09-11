use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClusterBackend {
    K8s,
    K3s,
    Podman,
    Baremetal,
    Lxc,
    Localhost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSpec {
    pub name: String,
    pub backend: ClusterBackend,
    pub bgp_asn: u32,
    pub nodes: Vec<String>,
    pub dpu_offload: bool,
    pub wireguard_mesh: bool,
}

pub struct ClusterOrchestrator;

impl ClusterOrchestrator {
    /// Generates orchestration deployment descriptors based on the chosen backend.
    pub fn provision_cluster(spec: &ClusterSpec) -> Result<String, String> {
        match spec.backend {
            ClusterBackend::Localhost => {
                let localhost_runner = format!(
                    r#"#!/usr/bin/env bash
# Sovereign Bunny Localhost Mesh Supervisor
# Cluster: {name} (BGP ASN: {asn})

set -euo pipefail
echo "🐇 Starting Sovereign Bunny Localhost Microservice Cluster: {name}"

# Export runtime environment
export RUST_LOG=info
export BGP_ASN={asn}
export SIDECAR_BGP="127.0.0.1"

# 1. Start Gateway
bunny daemon gateway --port 8545 --bgp-asn {asn} &
PID_GATEWAY=$!

# 2. Start Epoch Coordinator
bunny daemon epoch --epoch-node-id 1 &
PID_EPOCH=$!

# 3. Start Partition Committees
bunny daemon committee --partition 0 --range-start 0 &
PID_COMMITTEE=$!

# 4. Start P2P Storage Daemon
bunny daemon storage --storage-id 1 --dir /tmp/sovereign-storage &
PID_STORAGE=$!

# 5. Start Inter-Cluster Mesh
bunny daemon mesh --bgp-asn {asn} --wireguard-endpoint 127.0.0.1:51820 &
PID_MESH=$!

# 6. Start RPC Proxy
bunny daemon rpc --port 8546 --upstream http://127.0.0.1:8545 &
PID_RPC=$!

echo "✅ All 6 Sovereign Bunny daemons launched on localhost."
trap "kill $PID_GATEWAY $PID_EPOCH $PID_COMMITTEE $PID_STORAGE $PID_MESH $PID_RPC" EXIT
wait
"#,
                    name = spec.name,
                    asn = spec.bgp_asn
                );
                Ok(localhost_runner)
            }
            ClusterBackend::Lxc => {
                let lxc_profile = format!(
                    r#"# LXC / LXD Container Profile for Sovereign Bunny: {name}
name: {name}
config:
  security.privileged: "true"
  raw.lxc: |
    lxc.cgroup2.devices.allow = c 10:242 rwm
    lxc.mount.entry = /dev/sgx_enclave dev/sgx_enclave none bind,optional,create=file 0 0
    lxc.mount.entry = /dev/sgx_provision dev/sgx_provision none bind,optional,create=file 0 0
devices:
  eth0:
    name: eth0
    nictype: physical
    parent: eth0
    type: nic
  qsfp0:
    name: qsfp0
    nictype: physical
    parent: qsfp0
    type: nic
"#,
                    name = spec.name
                );
                Ok(lxc_profile)
            }
            ClusterBackend::Podman => {
                let podman_compose = format!(
                    r#"# Sovereign Bunny Podman Quadlet / Container Spec: {}
version: "3.8"
services:
  bunny-gateway:
    image: ghcr.io/sovereign-bunny/bunny:latest
    command: ["daemon", "gateway", "--port", "8545", "--bgp-asn", "{}"]
    ports:
      - "8545:8545"
    environment:
      - BGP_ASN={}
      - SIDECAR_BGP=127.0.0.1
    network_mode: host

  bunny-epoch:
    image: ghcr.io/sovereign-bunny/bunny:latest
    command: ["daemon", "epoch", "--epoch-node-id", "1"]
    network_mode: host

  bunny-committee-0:
    image: ghcr.io/sovereign-bunny/bunny:latest
    command: ["daemon", "committee", "--partition", "0", "--range-start", "0"]
    network_mode: host

  bunny-storage:
    image: ghcr.io/sovereign-bunny/bunny:latest
    command: ["daemon", "storage", "--storage-id", "1", "--dir", "/data/iroh"]
    network_mode: host

  bunny-mesh:
    image: ghcr.io/sovereign-bunny/bunny:latest
    command: ["daemon", "mesh", "--bgp-asn", "{}", "--wireguard-endpoint", "0.0.0.0:51820"]
    network_mode: host
"#,
                    spec.name, spec.bgp_asn, spec.bgp_asn, spec.bgp_asn
                );
                Ok(podman_compose)
            }
            ClusterBackend::K8s | ClusterBackend::K3s => {
                let helm_manifest = format!(
                    r#"# Generated Sovereign Bunny Helm Values for {}
cluster:
  name: "{}"
  backend: "{:?}"
  bgp:
    asn: {}
    sidecarMode: "127.0.0.1"
  runtime:
    dpuOffload: {}
    wireguardMesh: {}
  daemons:
    gateway:
      replicas: 2
      port: 8545
    committee:
      replicas: 4
      partitionRanges: ["0x0000..0x3FFF", "0x4000..0x7FFF", "0x8000..0xBFFF", "0xC000..0xFFFF"]
    epoch:
      replicas: 1
      consensus: "snowman"
    storage:
      replicas: 3
      storageClass: "local-nvme"
    mesh:
      replicas: 2
      bgpAsn: {}
    e3:
      dcapAttestation: true
"#,
                    spec.name, spec.name, spec.backend, spec.bgp_asn, spec.dpu_offload, spec.wireguard_mesh, spec.bgp_asn
                );
                Ok(helm_manifest)
            }
            ClusterBackend::Baremetal => {
                let mut config = format!(
                    r#"# Sovereign Bunny Baremetal Topology: {}
[mesh]
bgp_asn = {}
dpu_offload = {}
wireguard_mesh = {}

[nodes]
"#,
                    spec.name, spec.bgp_asn, spec.dpu_offload, spec.wireguard_mesh
                );
                for (idx, ip) in spec.nodes.iter().enumerate() {
                    config.push_str(&format!("node_{idx} = \"{ip}:51820\"\n"));
                }
                Ok(config)
            }
        }
    }

    /// Generates systemd service unit files for bare metal deployments.
    pub fn generate_baremetal_systemd_units(spec: &ClusterSpec) -> HashMap<String, String> {
        let mut units = HashMap::new();

        // 1. bunny-gateway.service
        units.insert(
            "bunny-gateway.service".to_string(),
            format!(
                r#"[Unit]
Description=Sovereign Bunny L7 Ingress Gateway ({name})
After=network.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bunny daemon gateway --port 8545 --bgp-asn {asn}
Restart=always
RestartSec=3
LimitNOFILE=65536
Environment="BGP_ASN={asn}"
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
"#,
                name = spec.name,
                asn = spec.bgp_asn
            ),
        );

        // 2. bunny-epoch.service
        units.insert(
            "bunny-epoch.service".to_string(),
            format!(
                r#"[Unit]
Description=Sovereign Bunny Snowman Epoch Consensus Daemon ({name})
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bunny daemon epoch --epoch-node-id 1
Restart=always
RestartSec=3
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
"#,
                name = spec.name
            ),
        );

        // 3. bunny-committee@.service (template unit)
        units.insert(
            "bunny-committee@.service".to_string(),
            format!(
                r#"[Unit]
Description=Sovereign Bunny Partition Committee Worker %i ({name})
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bunny daemon committee --partition 0 --range-start %i
Restart=always
RestartSec=3
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
"#,
                name = spec.name
            ),
        );

        // 4. bunny-storage.service
        units.insert(
            "bunny-storage.service".to_string(),
            format!(
                r#"[Unit]
Description=Sovereign Bunny Iroh P2P Storage Daemon ({name})
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bunny daemon storage --storage-id 1 --dir /data/iroh
Restart=always
RestartSec=3
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
"#,
                name = spec.name
            ),
        );

        // 5. bunny-mesh.service
        units.insert(
            "bunny-mesh.service".to_string(),
            format!(
                r#"[Unit]
Description=Sovereign Bunny BGP & WireGuard Transport Daemon ({name})
After=network.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bunny daemon mesh --bgp-asn {asn} --wireguard-endpoint 0.0.0.0:51820
Restart=always
RestartSec=3
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
"#,
                name = spec.name,
                asn = spec.bgp_asn
            ),
        );

        // 6. bunny-rpc.service
        units.insert(
            "bunny-rpc.service".to_string(),
            format!(
                r#"[Unit]
Description=Sovereign Bunny EVM Read-Path RPC Proxy ({name})
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/bunny-rpc --port 8546 --reth-url http://127.0.0.1:8545
Restart=always
RestartSec=3
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
"#,
                name = spec.name
            ),
        );

        units
    }

    /// Generates WireGuard interface configuration (wg0.conf) for point-to-point and mesh routing.
    pub fn generate_wireguard_conf(spec: &ClusterSpec) -> String {
        let mut conf = format!(
            r#"# WireGuard Mesh Configuration for Sovereign Bunny Cluster: {}
[Interface]
Address = 10.254.0.1/24
ListenPort = 51820
PrivateKey = <NODE_PRIVATE_KEY>
SaveConfig = false

"#,
            spec.name
        );

        for (idx, ip) in spec.nodes.iter().enumerate() {
            conf.push_str(&format!(
                r#"# Peer: node_{idx}
[Peer]
PublicKey = <NODE_{idx}_PUBLIC_KEY>
AllowedIPs = 10.254.0.{peer_ip}/32
Endpoint = {ip}:51820
PersistentKeepalive = 25

"#,
                idx = idx,
                peer_ip = idx + 2,
                ip = ip
            ));
        }

        conf
    }

    /// Validates a cluster specification for correctness.
    pub fn validate_cluster_spec(spec: &ClusterSpec) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if spec.name.trim().is_empty() {
            errors.push("Cluster name cannot be empty".to_string());
        }

        if spec.bgp_asn == 0 {
            errors.push(format!("Invalid BGP ASN: {}", spec.bgp_asn));
        }

        if spec.nodes.is_empty() {
            errors.push("At least one node IP must be specified".to_string());
        }

        for (i, node) in spec.nodes.iter().enumerate() {
            if node.trim().is_empty() {
                errors.push(format!("Node index {i} has empty IP address"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Exports all configuration files, manifests, and systemd units to disk.
    pub fn export_cluster_files(spec: &ClusterSpec, out_dir: &Path) -> Result<Vec<PathBuf>, String> {
        fs::create_dir_all(out_dir).map_err(|e| format!("Failed to create output dir: {e}"))?;
        let mut generated_files = Vec::new();

        // 1. Primary config file
        let primary_content = Self::provision_cluster(spec)?;
        let primary_filename = match spec.backend {
            ClusterBackend::Localhost => "run-localhost.sh",
            ClusterBackend::Lxc => "lxc-profile.yaml",
            ClusterBackend::Podman => "podman-compose.yaml",
            ClusterBackend::K8s | ClusterBackend::K3s => "values.yaml",
            ClusterBackend::Baremetal => "cluster-topology.toml",
        };
        let primary_path = out_dir.join(primary_filename);
        fs::write(&primary_path, primary_content).map_err(|e| format!("Failed to write {primary_filename}: {e}"))?;
        generated_files.push(primary_path);

        // 2. Baremetal extras: systemd units and wg0.conf
        if spec.backend == ClusterBackend::Baremetal {
            let systemd_dir = out_dir.join("systemd");
            fs::create_dir_all(&systemd_dir).map_err(|e| format!("Failed to create systemd dir: {e}"))?;

            let units = Self::generate_baremetal_systemd_units(spec);
            for (filename, unit_content) in units {
                let unit_path = systemd_dir.join(&filename);
                fs::write(&unit_path, unit_content).map_err(|e| format!("Failed to write unit {filename}: {e}"))?;
                generated_files.push(unit_path);
            }

            if spec.wireguard_mesh {
                let wg_path = out_dir.join("wg0.conf");
                let wg_content = Self::generate_wireguard_conf(spec);
                fs::write(&wg_path, wg_content).map_err(|e| format!("Failed to write wg0.conf: {e}"))?;
                generated_files.push(wg_path);
            }
        }

        Ok(generated_files)
    }
}
