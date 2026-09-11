//! # System Registry Address Constants and System Action Decoder
//!
//! Exposes reserved system addresses in EIP-1352 namespace and parses
//! incoming transaction payloads targeting these addresses.

use alloy_primitives::{Address, B256, U256, address};

/// Hook for the Global System Blockchain (Epoch Checkpoints, Block References & Pointers) (0x00...01)
pub const SYSTEM_EPOCH_REGISTRY: Address = address!("0000000000000000000000000000000000000001");

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

/// Hook for Async Message / Actuator inbox (0x00...07)
pub const SYSTEM_ASYNC_INBOX: Address = address!("0000000000000000000000000000000000000007");

/// Hook for client-side zkCompliance proof submission (0x00...08)
pub const SYSTEM_ZK_COMPLIANCE: Address = address!("0000000000000000000000000000000000000008");

/// Hook for setting account execution flags (ONLY_ASYNC etc.) (0x00...09)
pub const SYSTEM_ACCOUNT_FLAGS: Address = address!("0000000000000000000000000000000000000009");

/// Hook for AI Evaluator Agent Contribution Attestation (0x00...0a)
pub const SYSTEM_AI_ORACLE: Address = address!("000000000000000000000000000000000000000a");

/// Precompile returning local account block height (0x00...0100)
pub const SYSTEM_ACCOUNT_HEIGHT: Address = address!("0000000000000000000000000000000000000100");

/// Hook for P2P Storage DA & ZK-PoR proof verification (0x00...0053)
pub const SYSTEM_STORAGE_DA: Address = address!("0000000000000000000000000000000000000053");

/// Hook for P2P Address Interest Signaling & Cuckoo Filter Inscription (0x00...0054)
pub const SYSTEM_SIGNAL_REGISTRY: Address = address!("0000000000000000000000000000000000000054");

/// Hook for Content Management System & ActivityPub Anchors (0x00...00F1)
pub const SYSTEM_CMS: Address = address!("00000000000000000000000000000000000000f1");

/// Hook for Relational SQL Query & Table Execution against DAO & Contract Accounts (0x00...0055)
pub const SYSTEM_SQL_ENGINE: Address = address!("0000000000000000000000000000000000000055");

/// Hook for Global Epoch Coordinator & Meta-Consensus Cuts (0x00...00e0)
pub const SYSTEM_EPOCH_COORDINATOR: Address = address!("00000000000000000000000000000000000000e0");

/// Prefix byte identifying a virtual external-chain address.
/// Address layout: [0x00 x 15 bytes] || [0x01 namespace byte] || [ChainID u32 big-endian]
pub const VIRTUAL_CHAIN_PREFIX_BYTE: u8 = 0x01;
/// Byte offset of the namespace byte in a 20-byte address.
pub const VIRTUAL_CHAIN_NS_OFFSET: usize = 15;

/// Returns the target ChainID if `addr` is a virtual cross-chain address,
/// or `None` if it is a normal or reserved system address.
pub fn virtual_chain_id(addr: &Address) -> Option<u32> {
    let b = addr.as_slice();
    if b[0..15].iter().all(|&x| x == 0) && b[15] == VIRTUAL_CHAIN_PREFIX_BYTE {
        let chain_id = u32::from_be_bytes([b[16], b[17], b[18], b[19]]);
        Some(chain_id)
    } else {
        None
    }
}

/// Constructs the virtual address for a given external ChainID.
pub fn virtual_chain_address(chain_id: u32) -> Address {
    let mut bytes = [0u8; 20];
    bytes[15] = VIRTUAL_CHAIN_PREFIX_BYTE;
    bytes[16..20].copy_from_slice(&chain_id.to_be_bytes());
    Address::from(bytes)
}

/// Checks if an address is a reserved system address in EIP-1352 namespace or a virtual chain address.
pub fn is_system_address(addr: &Address) -> bool {
    addr == &SYSTEM_EPOCH_REGISTRY
        || addr == &SYSTEM_RECEIVE_HOOK
        || addr == &SYSTEM_DID_REGISTRY
        || addr == &SYSTEM_SAGA_ESCROW
        || addr == &SYSTEM_JURISDICTION
        || addr == &SYSTEM_BRIDGE
        || addr == &SYSTEM_ASYNC_INBOX
        || addr == &SYSTEM_ZK_COMPLIANCE
        || addr == &SYSTEM_ACCOUNT_FLAGS
        || addr == &SYSTEM_AI_ORACLE
        || addr == &SYSTEM_ACCOUNT_HEIGHT
        || addr == &SYSTEM_STORAGE_DA
        || addr == &SYSTEM_SIGNAL_REGISTRY
        || addr == &SYSTEM_CMS
        || addr == &SYSTEM_SQL_ENGINE
        || addr == &SYSTEM_EPOCH_COORDINATOR
        || virtual_chain_id(addr).is_some()
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
    /// Send cross-chain / cross-account actor message targeting SYSTEM_ASYNC_INBOX
    ActorMessage {
        /// Target actor id
        actor_id: B256,
        /// Message payload / validity proof
        payload: Vec<u8>,
    },
    /// Client-side zkCompliance proof submission targeting SYSTEM_ZK_COMPLIANCE
    ZkComplianceProof {
        /// Serialized Groth16/UltraHonk proof bytes
        proof_bytes: Vec<u8>,
        /// Public inputs representing non-membership in compliance set
        public_inputs: Vec<u8>,
        /// Epoch ID of the referenced compliance root
        epoch_id: u64,
    },
    /// Update account execution flags targeting SYSTEM_ACCOUNT_FLAGS
    SetAccountFlags {
        /// AccountFlags bitfield (ONLY_ASYNC, FROZEN, ZK_REQUIRE)
        flags: u8,
    },
    /// Cross-chain intent dispatched to a virtual chain address
    CrossChainIntent {
        /// Destination chain ID
        dest_chain_id: u32,
        /// ABI calldata
        calldata: Vec<u8>,
        /// Relayer execution bounty
        relayer_bounty: U256,
        /// Optional callback selector
        callback_selector: Option<[u8; 4]>,
    },
    /// Wrap native tokens into an ERC-20 Reserve Shadow Contract targeting SYSTEM_BRIDGE (0x06)
    WrapNative {
        /// Destination chain ID
        dest_chain_id: u32,
        /// Amount of native tokens to wrap
        amount: U256,
    },
    /// Destruct burned shadow contract and release native balance targeting SYSTEM_RECEIVE_HOOK (0x02)
    /// Destruct burned shadow contract and release native balance targeting SYSTEM_RECEIVE_HOOK (0x02)
    UnwrapShadow {
        /// Receipt ID of the shadow contract
        receipt_id: B256,
    },
    /// AI Evaluator Agent contribution attestation targeting SYSTEM_AI_ORACLE (0x0a)
    SubmitContributionEvaluation {
        /// Serialized JSON of EvaluatedContribution
        evaluation_json: String,
    },
    /// Signal address interest / Cuckoo filter inscription targeting SYSTEM_SIGNAL_REGISTRY (0x54)
    SignalInterest {
        /// Deterministic topic identifier
        topic_id: B256,
        /// Monitored account address
        target_address: Address,
        /// Compressed Cuckoo filter digest
        cuckoo_digest: B256,
        /// Subscription expiration epoch
        expiry_epoch: u64,
    },
    /// Publish ActivityStreams activity / anchor targeting SYSTEM_CMS (0xF1)
    PublishActivityPub {
        /// Actor address
        actor: Address,
        /// Activity type (Create=1, Follow=2, etc.)
        activity_type: u8,
        /// Content-addressed object CID
        object_cid: B256,
        /// Recipient or channel address
        recipient: Address,
        /// Micro-payment in atomic units
        micro_payment: u64,
        /// ZK-Merit root
        merit_proof_root: B256,
    },
    /// Claim Storage Merit Vector emission yield targeting SYSTEM_STORAGE_DA (0x53)
    ClaimStorageMerit {
        /// Storage provider DID URI
        provider_did: String,
        /// Verifiable Bao slice proof bytes
        bao_slice_proof: Vec<u8>,
        /// Target epoch ID
        epoch_id: u64,
    },
    /// Execute or anchor SQL table state against DAO / Sub-DAO contract accounts targeting SYSTEM_SQL_ENGINE (0x55)
    ExecuteSql {
        /// Target contract or DAO account address
        target_contract: Address,
        /// SQL statement (SELECT, INSERT, CREATE TABLE, etc.)
        sql_query: String,
    },
}

impl SystemAction {
    /// Decodes transaction calldata targeting a system address.
    pub fn decode(target: &Address, data: &[u8]) -> Option<Self> {
        if let Some(dest_chain_id) = virtual_chain_id(target) {
            let relayer_bounty = if data.len() >= 32 {
                U256::from_be_slice(&data[0..32])
            } else {
                U256::ZERO
            };
            let calldata = if data.len() > 32 {
                data[32..].to_vec()
            } else {
                data.to_vec()
            };
            return Some(SystemAction::CrossChainIntent {
                dest_chain_id,
                calldata,
                relayer_bounty,
                callback_selector: None,
            });
        }

        if target == &SYSTEM_RECEIVE_HOOK {
            if data.len() == 32 {
                let receipt_id = B256::from_slice(&data[0..32]);
                return Some(SystemAction::UnwrapShadow { receipt_id });
            }
            if data.len() < 64 {
                return None;
            }
            let send_block_hash = B256::from_slice(&data[0..32]);
            let amount = U256::from_be_slice(&data[32..64]);
            Some(SystemAction::Receive { send_block_hash, amount })
        } else if target == &SYSTEM_DID_REGISTRY {
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
            if data.len() >= 36 {
                let dest_chain_id = u32::from_be_bytes(data[0..4].try_into().unwrap_or([0u8; 4]));
                let amount = U256::from_be_slice(&data[4..36]);
                return Some(SystemAction::WrapNative { dest_chain_id, amount });
            }
            Some(SystemAction::BridgeAction { payload: data.to_vec() })
        } else if target == &SYSTEM_ASYNC_INBOX {
            if data.len() < 32 {
                return None;
            }
            let actor_id = B256::from_slice(&data[0..32]);
            let payload = data[32..].to_vec();
            Some(SystemAction::ActorMessage { actor_id, payload })
        } else if target == &SYSTEM_ZK_COMPLIANCE {
            if data.len() < 8 + 4 {
                return None;
            }
            let epoch_id = u64::from_be_bytes(data[0..8].try_into().ok()?);
            let proof_len = u32::from_be_bytes(data[8..12].try_into().ok()?) as usize;
            if data.len() < 12 + proof_len {
                return None;
            }
            let proof_bytes = data[12..12 + proof_len].to_vec();
            let public_inputs = data[12 + proof_len..].to_vec();
            Some(SystemAction::ZkComplianceProof { proof_bytes, public_inputs, epoch_id })
        } else if target == &SYSTEM_ACCOUNT_FLAGS {
            if data.is_empty() {
                return None;
            }
            Some(SystemAction::SetAccountFlags { flags: data[0] })
        } else if target == &SYSTEM_AI_ORACLE {
            let evaluation_json = String::from_utf8(data.to_vec()).ok()?;
            Some(SystemAction::SubmitContributionEvaluation { evaluation_json })
        } else if target == &SYSTEM_SIGNAL_REGISTRY {
            if data.len() < 32 + 20 + 32 + 8 {
                return None;
            }
            let topic_id = B256::from_slice(&data[0..32]);
            let target_address = Address::from_slice(&data[32..52]);
            let cuckoo_digest = B256::from_slice(&data[52..84]);
            let expiry_epoch = u64::from_be_bytes(data[84..92].try_into().ok()?);
            Some(SystemAction::SignalInterest {
                topic_id,
                target_address,
                cuckoo_digest,
                expiry_epoch,
            })
        } else if target == &SYSTEM_CMS {
            if data.len() < 20 + 1 + 32 + 20 + 8 + 32 {
                return None;
            }
            let actor = Address::from_slice(&data[0..20]);
            let activity_type = data[20];
            let object_cid = B256::from_slice(&data[21..53]);
            let recipient = Address::from_slice(&data[53..73]);
            let micro_payment = u64::from_be_bytes(data[73..81].try_into().ok()?);
            let merit_proof_root = B256::from_slice(&data[81..113]);
            Some(SystemAction::PublishActivityPub {
                actor,
                activity_type,
                object_cid,
                recipient,
                micro_payment,
                merit_proof_root,
            })
        } else if target == &SYSTEM_STORAGE_DA {
            if data.len() < 8 + 4 {
                return None;
            }
            let epoch_id = u64::from_be_bytes(data[0..8].try_into().ok()?);
            let did_len = u32::from_be_bytes(data[8..12].try_into().ok()?) as usize;
            if data.len() < 12 + did_len {
                return None;
            }
            let provider_did = String::from_utf8(data[12..12 + did_len].to_vec()).ok()?;
            let bao_slice_proof = data[12 + did_len..].to_vec();
            Some(SystemAction::ClaimStorageMerit {
                provider_did,
                bao_slice_proof,
                epoch_id,
            })
        } else if target == &SYSTEM_SQL_ENGINE {
            if data.len() < 20 {
                return None;
            }
            let target_contract = Address::from_slice(&data[0..20]);
            let sql_query = String::from_utf8_lossy(&data[20..]).to_string();
            Some(SystemAction::ExecuteSql {
                target_contract,
                sql_query,
            })
        } else {
            None
        }
    }

    /// Helper to encode SystemAction payloads to calldata bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            SystemAction::ExecuteSql { target_contract, sql_query } => {
                let mut data = Vec::with_capacity(20 + sql_query.len());
                data.extend_from_slice(target_contract.as_slice());
                data.extend_from_slice(sql_query.as_bytes());
                data
            }
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
            SystemAction::ZkComplianceProof { proof_bytes, public_inputs, epoch_id } => {
                let mut data = Vec::with_capacity(12 + proof_bytes.len() + public_inputs.len());
                data.extend_from_slice(&epoch_id.to_be_bytes());
                data.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
                data.extend_from_slice(proof_bytes);
                data.extend_from_slice(public_inputs);
                data
            }
            SystemAction::SetAccountFlags { flags } => vec![*flags],
            SystemAction::CrossChainIntent { calldata, relayer_bounty, .. } => {
                let mut data = Vec::with_capacity(32 + calldata.len());
                data.extend_from_slice(&relayer_bounty.to_be_bytes::<32>());
                data.extend_from_slice(calldata);
                data
            }
            SystemAction::WrapNative { dest_chain_id, amount } => {
                let mut data = Vec::with_capacity(4 + 32);
                data.extend_from_slice(&dest_chain_id.to_be_bytes());
                data.extend_from_slice(&amount.to_be_bytes::<32>());
                data
            }
            SystemAction::UnwrapShadow { receipt_id } => receipt_id.as_slice().to_vec(),
            SystemAction::SubmitContributionEvaluation { evaluation_json } => evaluation_json.as_bytes().to_vec(),
            SystemAction::SignalInterest { topic_id, target_address, cuckoo_digest, expiry_epoch } => {
                let mut data = Vec::with_capacity(32 + 20 + 32 + 8);
                data.extend_from_slice(topic_id.as_slice());
                data.extend_from_slice(target_address.as_slice());
                data.extend_from_slice(cuckoo_digest.as_slice());
                data.extend_from_slice(&expiry_epoch.to_be_bytes());
                data
            }
            SystemAction::PublishActivityPub { actor, activity_type, object_cid, recipient, micro_payment, merit_proof_root } => {
                let mut data = Vec::with_capacity(20 + 1 + 32 + 20 + 8 + 32);
                data.extend_from_slice(actor.as_slice());
                data.push(*activity_type);
                data.extend_from_slice(object_cid.as_slice());
                data.extend_from_slice(recipient.as_slice());
                data.extend_from_slice(&micro_payment.to_be_bytes());
                data.extend_from_slice(merit_proof_root.as_slice());
                data
            }
            SystemAction::ClaimStorageMerit { provider_did, bao_slice_proof, epoch_id } => {
                let mut data = Vec::with_capacity(8 + 4 + provider_did.len() + bao_slice_proof.len());
                data.extend_from_slice(&epoch_id.to_be_bytes());
                data.extend_from_slice(&(provider_did.len() as u32).to_be_bytes());
                data.extend_from_slice(provider_did.as_bytes());
                data.extend_from_slice(bao_slice_proof);
                data
            }
        }
    }
}
