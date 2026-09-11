//! # Compliance Vector wrapper for quadrant_matrix
//!
//! Provides helper functions and bitwise constants for compliance verification
//! on top of the existing `quadrant_matrix: [u64; 4]` representation.

use alloy_primitives::B256;

/// Named quadrant bit positions — matches the on-chain bit registry for manifold_id=1.
pub mod bits {
    // Q0 — Global Safety
    /// Bit indicating the account is slashed/frozen
    pub const Q0_FROZEN:           u64 = 1 << 0;
    /// Bit indicating velocity circuit breaker is active for this account
    pub const Q0_VELOCITY_CAP:     u64 = 1 << 1;

    // Q1 — Jurisdiction Subsumption Zone
    /// European Union / EEA compliance bit
    pub const Q1_EU_EEA:           u64 = 1 << 0;
    /// United States SEC/CFTC compliance bit
    pub const Q1_US_SEC_CFTC:      u64 = 1 << 1;
    /// Asia-Pacific compliance bit
    pub const Q1_APAC:             u64 = 1 << 2;
    /// FATF High-Risk / Blacklist compliance bit
    pub const Q1_FATF_HIGH_RISK:   u64 = 1 << 3;
    /// Sanctioned / OFAC compliance bit
    pub const Q1_OFAC_SANCTIONED:  u64 = 1 << 4;

    // Q2 — Category / Asset Overlap Zone
    /// Retail Externally Owned Account (EOA)
    pub const Q2_RETAIL_EOA:       u64 = 1 << 0;
    /// Institutional / Bank entity type
    pub const Q2_INSTITUTIONAL:    u64 = 1 << 1;
    /// Smart Contract / Automated Agent
    pub const Q2_SMART_CONTRACT:   u64 = 1 << 2;
    /// Regulated Financial Institution (RFI)
    pub const Q2_RFI:              u64 = 1 << 3;
    /// Saga Orchestrator node thread
    pub const Q2_SAGA_NODE:        u64 = 1 << 4;
    /// Physical Actuator Device
    pub const Q2_ACTUATOR:         u64 = 1 << 5;
    /// Cross-chain bridge/relay
    pub const Q2_CROSS_CHAIN:      u64 = 1 << 6;

    // Q3 — Membership Proof Zone (DAO / Employer / Consortium)
    /// Appointed DAO member bit
    pub const Q3_DAO_MEMBER:       u64 = 1 << 0;
    /// Committee validator bit
    pub const Q3_VALIDATOR:        u64 = 1 << 1;
    /// Employer or consortium slot 1
    pub const Q3_EMPLOYER_1:       u64 = 1 << 2;
}

/// Newtype for the 256-bit quadrant compliance matrix.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComplianceVector(pub [u64; 4]);

impl ComplianceVector {
    /// Creates a new ComplianceVector from a quadrant matrix.
    pub fn from_quadrant_matrix(m: [u64; 4]) -> Self {
        Self(m)
    }

    /// Converts to standard quadrant matrix.
    pub fn to_quadrant_matrix(self) -> [u64; 4] {
        self.0
    }

    /// Encodes into 32-byte wire format (big endian bytes).
    pub fn to_bytes(self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, q) in self.0.iter().enumerate() {
            b[i * 8..(i + 1) * 8].copy_from_slice(&q.to_be_bytes());
        }
        b
    }

    /// Decodes from 32-byte wire format (big endian bytes).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        let mut m = [0u64; 4];
        for i in 0..4 {
            m[i] = u64::from_be_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        Self(m)
    }

    /// Q0 Global safety bits
    pub fn q0(&self) -> u64 { self.0[0] }
    /// Q1 Jurisdiction bits
    pub fn q1(&self) -> u64 { self.0[1] }
    /// Q2 Entity category bits
    pub fn q2(&self) -> u64 { self.0[2] }
    /// Q3 Membership bits
    pub fn q3(&self) -> u64 { self.0[3] }

    /// Q1 jurisdiction subsumption check: (user.q1 & contract.q1) == contract.q1
    pub fn subsumes_jurisdiction(&self, contract: &Self) -> bool {
        (self.q1() & contract.q1()) == contract.q1()
    }

    /// Q2 category overlap check: (user.q2 & contract.q2) != 0
    pub fn has_category_overlap(&self, contract: &Self) -> bool {
        (self.q2() & contract.q2()) != 0
    }

    /// Q3 DAO membership check: (user.q3 & required_bit) != 0
    pub fn is_dao_member(&self, required_bit: u64) -> bool {
        (self.q3() & required_bit) != 0
    }
}

/// Derives the Verkle leaf key under the Compliance Filter Stem (0xC04D0001) namespace.
pub fn compliance_leaf_key(addr: &alloy_primitives::Address) -> B256 {
    let mut preimage = Vec::with_capacity(24);
    // COMPLIANCE_PREFIX = [0xC0, 0x4D, 0x00, 0x01]
    preimage.extend_from_slice(&[0xC0, 0x4D, 0x00, 0x01]);
    preimage.extend_from_slice(addr.as_slice());
    let hashed = sovereign_crypto::hash(sovereign_crypto::HashScheme::Sha256, &preimage);
    B256::from_slice(&hashed[..32])
}
