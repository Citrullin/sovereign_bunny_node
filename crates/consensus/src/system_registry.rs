//! # System Registry Address Constants and System Action Decoder
//!
//! Exposes reserved system addresses in EIP-1352 namespace and parses
//! incoming transaction payloads targeting these addresses.

use alloy_primitives::{Address, B256, U256, address};

/// Hook for receiving stateless block payments and sweeps (0x00...02)
pub const SYSTEM_RECEIVE_HOOK: Address = address!("0000000000000000000000000000000000000002");

/// Hook for registering DIDs and PQ keys (0x00...03)
pub const SYSTEM_DID_REGISTRY: Address = address!("0000000000000000000000000000000000000003");

/// Hook for Saga Intent escrow locks (0x00...04)
pub const SYSTEM_SAGA_ESCROW: Address = address!("0000000000000000000000000000000000000004");

/// Hook for Snowman-finalized jurisdiction rules (0x00...05)
pub const SYSTEM_JURISDICTION: Address = address!("0000000000000000000000000000000000000005");

/// Hook for L1/L2 shadow anchor receipts (0x00...06)
pub const SYSTEM_BRIDGE: Address = address!("0000000000000000000000000000000000000006");

/// Hook for Actuator heartbeat / emergency stops (0x00...07)
pub const SYSTEM_ACTUATOR: Address = address!("0000000000000000000000000000000000000007");

/// Precompile returning local account block height (0x00...0100)
pub const SYSTEM_ACCOUNT_HEIGHT: Address = address!("0000000000000000000000000000000000000100");

/// Checks if an address is a reserved system address in EIP-1352 namespace.
pub fn is_system_address(addr: &Address) -> bool {
    addr == &SYSTEM_RECEIVE_HOOK
        || addr == &SYSTEM_DID_REGISTRY
        || addr == &SYSTEM_SAGA_ESCROW
        || addr == &SYSTEM_JURISDICTION
        || addr == &SYSTEM_BRIDGE
        || addr == &SYSTEM_ACTUATOR
        || addr == &SYSTEM_ACCOUNT_HEIGHT
}

/// The cryptographic verification scheme used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProofKind {
    /// Traditional ECDSA/EdDSA signature
    Classical,
    /// Post-Quantum signature (ML-DSA)
    PostQuantum,
    /// Zero-Knowledge validity proof
    ZkProof,
}

/// Decoded system action payloads targeting system addresses.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SystemAction {
    /// Sweep or transfer targeting SYSTEM_RECEIVE_HOOK
    Receive {
        /// Hash of the original send block
        send_block_hash: B256,
        /// Amount to be credited
        amount: U256,
    },
    /// Register DID document and associated keys targeting SYSTEM_DID_REGISTRY
    RegisterDid {
        /// Full DID document JSON
        did_document: String,
        /// Post-quantum public key bytes
        pq_pub_key: Vec<u8>,
        /// Identity tier (e.g. "Classical", "QuantumReady", "QuantumOnly")
        key_tier: String,
    },
    /// Saga intent registration targeting SYSTEM_SAGA_ESCROW
    SagaEscrow {
        /// Intent identifier
        intent_id: B256,
        /// Recipient or target account
        target_account: Address,
        /// Escrow amount
        amount: U256,
        /// Expiry epoch height
        expire_epoch: u64,
    },
    /// Jurisdiction delta update or bit registry change targeting SYSTEM_JURISDICTION
    JurisdictionUpdate {
        /// Serialized `JurisdictionDecision` bytes
        decision_bytes: Vec<u8>,
    },
    /// Bridge action or receipt verification targeting SYSTEM_BRIDGE
    BridgeAction {
        /// Bridge payload
        payload: Vec<u8>,
    },
    /// Send cross-chain / cross-account actor message targeting SYSTEM_ACTUATOR
    ActorMessage {
        /// Target actor id
        actor_id: B256,
        /// Message payload / validity proof
        payload: Vec<u8>,
    },
}

impl SystemAction {
    /// Decodes transaction calldata targeting a system address.
    /// Payload structure uses standard prefix-based or SCALE-like encoding.
    pub fn decode(target: &Address, data: &[u8]) -> Option<Self> {
        if target == &SYSTEM_RECEIVE_HOOK {
            if data.len() < 64 {
                return None;
            }
            let send_block_hash = B256::from_slice(&data[0..32]);
            let amount = U256::from_be_slice(&data[32..64]);
            Some(SystemAction::Receive { send_block_hash, amount })
        } else if target == &SYSTEM_DID_REGISTRY {
            // Simple serialization: format: key_tier_len (1 byte) || key_tier || pq_pub_key_len (4 bytes) || pq_pub_key || did_document
            if data.len() < 6 {
                return None;
            }
            let tier_len = data[0] as usize;
            if data.len() < 1 + tier_len + 4 {
                return None;
            }
            let key_tier = String::from_utf8(data[1..1 + tier_len].to_vec()).ok()?;
            let pq_len = u32::from_be_bytes(data[1 + tier_len..1 + tier_len + 4].try_into().ok()?) as usize;
            if data.len() < 1 + tier_len + 4 + pq_len {
                return None;
            }
            let pq_pub_key = data[1 + tier_len + 4..1 + tier_len + 4 + pq_len].to_vec();
            let did_document = String::from_utf8(data[1 + tier_len + 4 + pq_len..].to_vec()).ok()?;
            Some(SystemAction::RegisterDid { did_document, pq_pub_key, key_tier })
        } else if target == &SYSTEM_SAGA_ESCROW {
            if data.len() < 32 + 20 + 32 + 8 {
                return None;
            }
            let intent_id = B256::from_slice(&data[0..32]);
            let target_account = Address::from_slice(&data[32..52]);
            let amount = U256::from_be_slice(&data[52..84]);
            let expire_epoch = u64::from_be_bytes(data[84..92].try_into().ok()?);
            Some(SystemAction::SagaEscrow { intent_id, target_account, amount, expire_epoch })
        } else if target == &SYSTEM_JURISDICTION {
            Some(SystemAction::JurisdictionUpdate { decision_bytes: data.to_vec() })
        } else if target == &SYSTEM_BRIDGE {
            Some(SystemAction::BridgeAction { payload: data.to_vec() })
        } else if target == &SYSTEM_ACTUATOR {
            if data.len() < 32 {
                return None;
            }
            let actor_id = B256::from_slice(&data[0..32]);
            let payload = data[32..].to_vec();
            Some(SystemAction::ActorMessage { actor_id, payload })
        } else {
            None
        }
    }

    /// Helper to encode SystemAction payloads to calldata bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            SystemAction::Receive { send_block_hash, amount } => {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(send_block_hash.as_slice());
                data.extend_from_slice(&amount.to_be_bytes::<32>());
                data
            }
            SystemAction::RegisterDid { did_document, pq_pub_key, key_tier } => {
                let mut data = Vec::new();
                let tier_bytes = key_tier.as_bytes();
                data.push(tier_bytes.len() as u8);
                data.extend_from_slice(tier_bytes);
                data.extend_from_slice(&(pq_pub_key.len() as u32).to_be_bytes());
                data.extend_from_slice(pq_pub_key);
                data.extend_from_slice(did_document.as_bytes());
                data
            }
            SystemAction::SagaEscrow { intent_id, target_account, amount, expire_epoch } => {
                let mut data = Vec::with_capacity(32 + 20 + 32 + 8);
                data.extend_from_slice(intent_id.as_slice());
                data.extend_from_slice(target_account.as_slice());
                data.extend_from_slice(&amount.to_be_bytes::<32>());
                data.extend_from_slice(&expire_epoch.to_be_bytes());
                data
            }
            SystemAction::JurisdictionUpdate { decision_bytes } => decision_bytes.clone(),
            SystemAction::BridgeAction { payload } => payload.clone(),
            SystemAction::ActorMessage { actor_id, payload } => {
                let mut data = Vec::with_capacity(32 + payload.len());
                data.extend_from_slice(actor_id.as_slice());
                data.extend_from_slice(payload);
                data
            }
        }
    }
}
