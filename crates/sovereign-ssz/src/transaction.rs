use ssz_rs::prelude::*;
use alloy_primitives::{Address, B256};

/// Canonical SSZ Transaction container.
///
/// Note: Fixed-offset byte layout invariant:
/// - Bytes   0..8   : chain_id (u64)
/// - Bytes   8..16  : nonce (u64)
/// - Bytes  16..36  : to (Vector<u8, 20>) -> AccountID inspected by P4/FPGA
/// - Bytes  36..68  : value (Vector<u8, 32>)
/// - Bytes  68..76  : gas_limit (u64)
/// - Bytes  76..84  : max_fee_per_gas (u64)
/// - Bytes  84..92  : max_priority_fee (u64)
/// - Bytes  92..108 : range_routing (Vector<u8, 16>)
/// - Bytes 108..140 : intent_id (Vector<u8, 32>)
/// - Bytes 140..236 : signature (Vector<u8, 96>)
/// - Bytes 236..    : data offset vector & dynamic payload
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SszTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub to: Vector<u8, 20>,
    pub value: Vector<u8, 32>,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee: u64,
    pub range_routing: Vector<u8, 16>,
    pub intent_id: Vector<u8, 32>,
    pub signature: Vector<u8, 96>,
    pub data: List<u8, 1048576>, // Max 1MB calldata list
}

impl SszTransaction {
    /// Helper to convert `to` address to alloy Address
    pub fn to_address(&self) -> Address {
        Address::from_slice(self.to.as_ref())
    }

    /// Helper to set `to` address
    pub fn set_to_address(&mut self, addr: Address) {
        self.to = Vector::try_from(addr.as_slice().to_vec()).expect("20 bytes");
    }

    /// Helper to get intent_id as B256
    pub fn intent_b256(&self) -> B256 {
        B256::from_slice(self.intent_id.as_ref())
    }
}
