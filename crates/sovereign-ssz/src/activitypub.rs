//! # ActivityPub SSZ Wire Envelope
//!
//! Canonical fixed-offset 209-byte SSZ wire envelope binding W3C ActivityStreams 2.0
//! activities to stateless Account-Lattice state transitions and Iroh ZK-PoR media storage.

use alloy_primitives::{Address, B256};
use ssz_rs::prelude::*;

/// ActivityStreams 2.0 Activity Types mapped to fixed u8 discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ActivityType {
    Create = 1,
    Follow = 2,
    Announce = 3,
    Like = 4,
    Undo = 5,
    PaywallGrant = 6,
}

impl ActivityType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Create),
            2 => Some(Self::Follow),
            3 => Some(Self::Announce),
            4 => Some(Self::Like),
            5 => Some(Self::Undo),
            6 => Some(Self::PaywallGrant),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "Create",
            Self::Follow => "Follow",
            Self::Announce => "Announce",
            Self::Like => "Like",
            Self::Undo => "Undo",
            Self::PaywallGrant => "PaywallGrant",
        }
    }
}

impl Default for ActivityType {
    fn default() -> Self {
        Self::Create
    }
}

/// Canonical 209-byte Fixed-Offset ActivityPub SSZ Envelope.
///
/// Layout:
/// - Bytes   0..20  : actor_address (Vector<u8, 20>)
/// - Bytes  20..21  : activity_type (u8)
/// - Bytes  21..53  : object_cid (Vector<u8, 32>) -> Iroh / BLAKE3 / IPLD CID digest
/// - Bytes  53..73  : target_recipient (Vector<u8, 20>) -> Inbox recipient / channel address
/// - Bytes  73..81  : attached_micro_payment (u64) -> Micro-escrow or tip in atomic units
/// - Bytes  81..113 : merit_proof_root (Vector<u8, 32>) -> Noir ZK-Merit Merkle root
/// - Bytes 113..209 : signature (Vector<u8, 96>) -> Multi-curve or ML-DSA signature
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct ActivityPubEnvelope {
    pub actor_address: Vector<u8, 20>,
    pub activity_type: u8,
    pub object_cid: Vector<u8, 32>,
    pub target_recipient: Vector<u8, 20>,
    pub attached_micro_payment: u64,
    pub merit_proof_root: Vector<u8, 32>,
    pub signature: Vector<u8, 96>,
}

impl ActivityPubEnvelope {
    /// Creates a new `ActivityPubEnvelope`.
    pub fn new(
        actor: Address,
        activity_type: ActivityType,
        object_cid: B256,
        target_recipient: Address,
        attached_micro_payment: u64,
        merit_proof_root: B256,
        signature_bytes: &[u8],
    ) -> Self {
        let mut sig_vec = vec![0u8; 96];
        let copy_len = signature_bytes.len().min(96);
        sig_vec[..copy_len].copy_from_slice(&signature_bytes[..copy_len]);

        Self {
            actor_address: Vector::try_from(actor.as_slice().to_vec()).expect("20 bytes"),
            activity_type: activity_type as u8,
            object_cid: Vector::try_from(object_cid.as_slice().to_vec()).expect("32 bytes"),
            target_recipient: Vector::try_from(target_recipient.as_slice().to_vec()).expect("20 bytes"),
            attached_micro_payment,
            merit_proof_root: Vector::try_from(merit_proof_root.as_slice().to_vec()).expect("32 bytes"),
            signature: Vector::try_from(sig_vec).expect("96 bytes"),
        }
    }

    /// Helper to get actor address as alloy `Address`.
    pub fn actor(&self) -> Address {
        Address::from_slice(self.actor_address.as_ref())
    }

    /// Helper to get target recipient as alloy `Address`.
    pub fn recipient(&self) -> Address {
        Address::from_slice(self.target_recipient.as_ref())
    }

    /// Helper to get object CID as `B256`.
    pub fn cid_b256(&self) -> B256 {
        B256::from_slice(self.object_cid.as_ref())
    }

    /// Helper to get merit proof root as `B256`.
    pub fn merit_root_b256(&self) -> B256 {
        B256::from_slice(self.merit_proof_root.as_ref())
    }

    /// Helper to get typed `ActivityType`.
    pub fn parsed_activity_type(&self) -> Option<ActivityType> {
        ActivityType::from_u8(self.activity_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activitypub_envelope_ssz_roundtrip() {
        let actor = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let cid = B256::repeat_byte(0x33);
        let merit_root = B256::repeat_byte(0x44);
        let sig = [0x55u8; 96];

        let envelope = ActivityPubEnvelope::new(
            actor,
            ActivityType::Create,
            cid,
            recipient,
            500_000,
            merit_root,
            &sig,
        );

        assert_eq!(envelope.actor(), actor);
        assert_eq!(envelope.recipient(), recipient);
        assert_eq!(envelope.cid_b256(), cid);
        assert_eq!(envelope.merit_root_b256(), merit_root);
        assert_eq!(envelope.parsed_activity_type(), Some(ActivityType::Create));
        assert_eq!(envelope.attached_micro_payment, 500_000);

        let mut encoded = Vec::new();
        envelope.serialize(&mut encoded).expect("SSZ serialize");
        assert_eq!(encoded.len(), 209, "Fixed 209-byte canonical size");

        let decoded = ActivityPubEnvelope::deserialize(&encoded).expect("SSZ deserialize");
        assert_eq!(envelope, decoded);
    }
}
