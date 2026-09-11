use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
pub enum TransportKind {
    Nfc,
    Ble,
    Dif,
    Bgp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDiscoveryRecord {
    pub did: String,
    pub transport: TransportKind,
    pub endpoint: String,
    pub public_key_multibase: String,
    pub signal_rssi_or_link_speed: String,
}

pub struct PeerDiscoveryManager;

impl PeerDiscoveryManager {
    /// Simulates/discovers proximity and dark-fiber peers via NFC, BLE, DIF, or BGP.
    pub fn discover_peer(transport: TransportKind) -> PeerDiscoveryRecord {
        match transport {
            TransportKind::Nfc => PeerDiscoveryRecord {
                did: "did:bunny:c-base-berlin:nfc-touch-01".to_string(),
                transport,
                endpoint: "nfc://tap-01".to_string(),
                public_key_multibase: "z6MkuTi8sT7Xk9q6jL7Q23K4v".to_string(),
                signal_rssi_or_link_speed: "Contact (Proximity 0cm)".to_string(),
            },
            TransportKind::Ble => PeerDiscoveryRecord {
                did: "did:bunny:c-base-berlin:ble-adv-02".to_string(),
                transport,
                endpoint: "ble://AA:BB:CC:DD:EE:FF".to_string(),
                public_key_multibase: "z6Mks7J92nL84Pk3Y91X42z".to_string(),
                signal_rssi_or_link_speed: "-42 dBm (Immediate)".to_string(),
            },
            TransportKind::Dif => PeerDiscoveryRecord {
                did: "did:peer:4z6MkuTi8sT7Xk9q6jL7Q23K4v".to_string(),
                transport,
                endpoint: "https://bunny.mesh/dif-document.json".to_string(),
                public_key_multibase: "z6MkuTi8sT7Xk9q6jL7Q23K4v".to_string(),
                signal_rssi_or_link_speed: "DIF Verified".to_string(),
            },
            TransportKind::Bgp => PeerDiscoveryRecord {
                did: "did:bunny:c-base-berlin:qsfp-dd-400g".to_string(),
                transport,
                endpoint: "10.254.0.1:179".to_string(),
                public_key_multibase: "z6MkgT78Xv94jK21M98Q71P".to_string(),
                signal_rssi_or_link_speed: "400 Gbps (120ns P4 Bypass)".to_string(),
            },
        }
    }
}
