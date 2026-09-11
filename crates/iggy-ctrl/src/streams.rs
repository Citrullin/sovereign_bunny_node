//! Canonical stream and topic identifiers across the Sovereign Iggy bus.

pub const INTENT_STREAM: &str = "intent-ingress";
pub const SYS_STREAM: &str = "sys-control";

// Partition topics under INTENT_STREAM
pub const TOPIC_RANGE_0: &str = "range-0x0000-0x3FFF";
pub const TOPIC_RANGE_1: &str = "range-0x4000-0x7FFF";
pub const TOPIC_RANGE_2: &str = "range-0x8000-0xBFFF";
pub const TOPIC_RANGE_3: &str = "range-0xC000-0xFFFF";
pub const TOPIC_CONFIDENTIAL_E3: &str = "confidential-0xE3";

// System topics under SYS_STREAM
pub const TOPIC_SYS_EPOCH_MARKERS: &str = "sys.epoch-markers";
pub const TOPIC_SYS_COMMITTEE_ROTATIONS: &str = "sys.committee-rotations";
pub const TOPIC_SYS_CHANDY_CUTS: &str = "sys.chandy-cuts";
pub const TOPIC_SYS_STATE_ROOTS: &str = "sys.state-roots";
pub const TOPIC_SYS_CROSS_CHAIN: &str = "sys.cross-chain";
pub const TOPIC_SYS_TX_RECEIPTS: &str = "sys.tx-receipts";
pub const TOPIC_SYS_ZK_DNS: &str = "sys.zkdns-updates";
pub const TOPIC_STORAGE_PARTITION: &str = "range.storage";

/// Resolves the canonical topic name for a 16-bit range key
pub fn topic_for_range_key(key: u16) -> &'static str {
    match key {
        0x0000..=0x3FFF => TOPIC_RANGE_0,
        0x4000..=0x7FFF => TOPIC_RANGE_1,
        0x8000..=0xBFFF => TOPIC_RANGE_2,
        _ => TOPIC_RANGE_3,
    }
}
