use ssz_rs::prelude::*;

/// Threshold-signed Epoch Marker emitted by sub-committees upon completing Multi-Paxos slots.
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct ThresholdEpochMarker {
    pub epoch_id: u64,
    pub range_start: u16,
    pub range_end: u16,
    pub range_root: Vector<u8, 32>,
    pub in_flight_root: Vector<u8, 32>,
    pub prev_snapshot_root: Vector<u8, 32>,
    pub threshold_bls_signature: Vector<u8, 96>,
    pub signer_bitmap: Vector<u8, 32>,
}

/// Committee Rotation Event emitted by bunny-epoch to update the gateway and P4 routers.
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct RotationEvent {
    pub epoch_id: u64,
    pub effective_from_timestamp: u64,
    pub seed: Vector<u8, 32>,
    pub partition_count: u32,
    pub committee_pubkeys: List<Vector<u8, 32>, 1024>,
}

/// Finalized Global Epoch Checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct EpochCheckpoint {
    pub epoch_id: u64,
    pub consensus_root: Vector<u8, 32>,
    pub state_root: Vector<u8, 32>,
    pub snapshot_hash: Vector<u8, 32>,
    pub timestamp: u64,
}
