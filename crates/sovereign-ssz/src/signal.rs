//! # Address Interest Signaling Protocol SSZ Envelope
//!
//! Canonical fixed-offset SSZ envelope for registering interest subscriptions,
//! Cuckoo filter inscriptions, and deterministic Iroh-Gossip topic swarms.

use alloy_primitives::{Address, B256};
use ssz_rs::prelude::*;

/// Domain separator prefix for deterministic topic derivation.
pub const SIGNAL_TOPIC_DOMAIN: &[u8] = b"bunny.mesh.interest.v1";

/// Canonical 220-byte Fixed-Offset Signal Envelope.
///
/// Layout:
/// - Bytes   0..20  : target_address (Vector<u8, 20>) -> Account/DAO monitored
/// - Bytes  20..52  : topic_id (Vector<u8, 32>) -> Deterministic Iroh-Gossip Topic Hash
/// - Bytes  52..84  : app_context_hash (Vector<u8, 32>) -> DApp / Channel Context
/// - Bytes  84..116 : cuckoo_filter_digest (Vector<u8, 32>) -> Compressed Cuckoo / Bloom root
/// - Bytes 116..124 : expiry_epoch (u64) -> Expiration epoch for signal subscription
/// - Bytes 124..220 : signature (Vector<u8, 96>) -> Authorizing signature
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SignalEnvelope {
    pub target_address: Vector<u8, 20>,
    pub topic_id: Vector<u8, 32>,
    pub app_context_hash: Vector<u8, 32>,
    pub cuckoo_filter_digest: Vector<u8, 32>,
    pub expiry_epoch: u64,
    pub signature: Vector<u8, 96>,
}

impl SignalEnvelope {
    /// Derives deterministic TopicID: `Keccak256("bunny.mesh.interest.v1" || TargetAddress || AppContext)`.
    pub fn derive_topic_id(target_address: &Address, app_context: &[u8]) -> B256 {
        use tiny_keccak::{Hasher, Keccak};
        let mut hasher = Keccak::v256();
        hasher.update(SIGNAL_TOPIC_DOMAIN);
        hasher.update(target_address.as_slice());
        hasher.update(app_context);
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        B256::from(out)
    }

    /// Creates a new `SignalEnvelope` with auto-derived topic ID.
    pub fn new(
        target_address: Address,
        app_context: &[u8],
        cuckoo_filter_digest: B256,
        expiry_epoch: u64,
        signature_bytes: &[u8],
    ) -> Self {
        use tiny_keccak::{Hasher, Keccak};
        let mut app_hasher = Keccak::v256();
        app_hasher.update(app_context);
        let mut app_ctx_hash = [0u8; 32];
        app_hasher.finalize(&mut app_ctx_hash);

        let topic_id = Self::derive_topic_id(&target_address, app_context);

        let mut sig_vec = vec![0u8; 96];
        let copy_len = signature_bytes.len().min(96);
        sig_vec[..copy_len].copy_from_slice(&signature_bytes[..copy_len]);

        Self {
            target_address: Vector::try_from(target_address.as_slice().to_vec()).expect("20 bytes"),
            topic_id: Vector::try_from(topic_id.as_slice().to_vec()).expect("32 bytes"),
            app_context_hash: Vector::try_from(app_ctx_hash.to_vec()).expect("32 bytes"),
            cuckoo_filter_digest: Vector::try_from(cuckoo_filter_digest.as_slice().to_vec()).expect("32 bytes"),
            expiry_epoch,
            signature: Vector::try_from(sig_vec).expect("96 bytes"),
        }
    }

    /// Helper to get target address as alloy `Address`.
    pub fn target(&self) -> Address {
        Address::from_slice(self.target_address.as_ref())
    }

    /// Helper to get topic ID as `B256`.
    pub fn topic_b256(&self) -> B256 {
        B256::from_slice(self.topic_id.as_ref())
    }

    /// Helper to get cuckoo filter digest as `B256`.
    pub fn cuckoo_b256(&self) -> B256 {
        B256::from_slice(self.cuckoo_filter_digest.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_envelope_derivation_and_roundtrip() {
        let target = Address::repeat_byte(0x7a);
        let context = b"social.feed.notifications";
        let cuckoo_root = B256::repeat_byte(0x99);
        let sig = [0xabu8; 96];

        let expected_topic = SignalEnvelope::derive_topic_id(&target, context);

        let envelope = SignalEnvelope::new(
            target,
            context,
            cuckoo_root,
            1000,
            &sig,
        );

        assert_eq!(envelope.target(), target);
        assert_eq!(envelope.topic_b256(), expected_topic);
        assert_eq!(envelope.cuckoo_b256(), cuckoo_root);
        assert_eq!(envelope.expiry_epoch, 1000);

        let mut encoded = Vec::new();
        envelope.serialize(&mut encoded).expect("SSZ serialize");
        assert_eq!(encoded.len(), 220, "Fixed 220-byte canonical size");

        let decoded = SignalEnvelope::deserialize(&encoded).expect("SSZ deserialize");
        assert_eq!(envelope, decoded);
    }
}
