use ssz_rs::prelude::*;
use alloy_primitives::{Address, B256};

/// Discrete block-lattice payloads represented in SSZ format
#[derive(Debug, Clone, PartialEq, Eq, Default, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SszLatticeBlock {
    pub account: Vector<u8, 20>,
    pub previous_hash: Vector<u8, 32>,
    pub sequence: u64,
    pub payload_type: u8, // 0 = Send, 1 = Receive, 2 = ContractCall, 3 = Confidential
    pub target_account: Vector<u8, 20>,
    pub amount: Vector<u8, 32>,
    pub intent_id: Vector<u8, 32>,
    pub signature: Vector<u8, 96>,
    pub data: List<u8, 1048576>,
}

impl SszLatticeBlock {
    pub fn account_address(&self) -> Address {
        Address::from_slice(self.account.as_ref())
    }

    pub fn prev_hash(&self) -> B256 {
        B256::from_slice(self.previous_hash.as_ref())
    }
}
