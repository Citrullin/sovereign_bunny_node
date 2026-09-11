//! # Validator Registry & Account Frontier State
//!
//! [`ValidatorRegistry`] is the single in-memory source of truth for the
//! Sovereign Bunny node. It holds all mutable state that the execution
//! engine and epoch finalizer need:
//!
//! - **DID identity directory** — maps EVM addresses and DID strings to
//!   resolved [`RegisteredIdentity`] documents with their public keys.
//! - **Account frontiers** — the lattice tip (latest hash + sequence number)
//!   for every account, plus balance, lock status, and merit rank.
//! - **Validator set** — which accounts are active validators and of what type.
//! - **Replay-prevention sets** — nullifiers for claimed sends, used intent
//!   IDs, and processed cross-manifold messages.
//! - **Epoch state** — current epoch/block counters, epoch checkpoints, and
//!   the send-block epoch map used to enforce reclaim timeouts.
//!
//! ## Threading Model
//!
//! The registry is wrapped in a `std::sync::RwLock<ValidatorRegistry>` via
//! the global [`VALIDATOR_REGISTRY`] singleton. All reads acquire a shared
//! lock; all writes acquire an exclusive lock. This is safe for the current
//! single-process node. When the architecture moves to multi-process daemon
//! sharding (see the C4 architecture doc), the registry will be replicated
//! per partition and reconciled at epoch boundaries — not shared across
//! process boundaries.
//!
//! ## Why Monolithic?
//!
//! The registry is intentionally a single struct at this stage. Splitting it
//! prematurely into separate sub-stores (identity store, frontier store, etc.)
//! would require either distributed transactions between them or complex
//! locking protocols, with no benefit while the node runs as a single process.
//! The planned split (into `identity`, `frontier`, `epoch_state`, `genesis`,
//! `manifold` sub-modules) is tracked in [`docs/components.toml`].
//!
//! ## Design Notes
//!
//! The following historical security finding IDs map to features in this module.
//! They are preserved here for traceability to the audit report:
//!
//! | Finding | Feature |
//! |---|---|
//! | CRIT-01 | `claimed_sends` — double-receive prevention |
//! | CRIT-02 | `processed_manifold_messages` — cross-manifold replay prevention |
//! | CRIT-03 | Balance check in `execute_lattice_block` before debit |
//! | MED-01  | `epochs_at_current_rank` cooldown on merit rank promotion |
//! | MED-03  | `used_intent_ids` — ContractCall intent deduplication |
//! | MED-06  | `load_genesis_allocations` — explicit path only, no directory walking |
//! | MED-08  | `send_block_epochs` + `process_reclaim_sends` — reclaim timeout |

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents the state frontier of an account chain in the block-lattice.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AccountFrontier {
    /// Latest block hash of the account's chain.
    pub latest_hash: B256,
    /// Latest sequence number of the account's chain.
    pub sequence: u64,
    /// Lock status of the account (for synchronous cross-account calls).
    pub locked: bool,
    /// Global block height at which the account was locked.
    pub locked_at: u64,
    /// Paused zkEVM execution context.
    pub paused_context: Option<Vec<u8>>,
    /// Size of the paused context snapshot.
    pub snapshot_size: usize,
    /// Cached compliance vector snapshot refreshed at epoch boundaries.
    pub cached_compliance: Option<crate::compliance_vector::ComplianceVector>,
    /// Progressive merit rank tier of this account.
    pub merit_rank: crate::jurisdiction::MeritRank,
    /// Number of consecutive epochs the account has held its current merit rank.
    ///
    /// The epoch engine promotes a rank only after this counter reaches
    /// `MERIT_RANK_COOLDOWN_EPOCHS`. This prevents a single high-scoring epoch from
    /// immediately unlocking the maximum reward multiplier — see `epoch::process_merit_distribution`.
    pub epochs_at_current_rank: u64,
}

/// Represents the type of a validator in the `DPoT` system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// Hardware TEE validator (high security).
    HardwareTEE,
    /// Vanilla Social validator (reputation based).
    VanillaSocial,
}

/// Full resolved identity documents stored in the directory.
#[derive(Debug, Clone)]
pub struct RegisteredIdentity {
    /// Long-form `did:peer:...` or `did:sovereign:[chain_id]:...` string.
    pub did: String,
    /// Resolved DID document details.
    pub doc: sovereign_identity::did::SovereignDidDocument,
    /// Unix timestamp when the identity was registered.
    pub registered_at: u64,
}

/// Details of a cross-chain smart contract event observer subroutine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossChainObserverSubroutine {
    pub subroutine_id: B256,
    pub foreign_chain_id: u64,
    pub contract_address: Address,
    pub event_signature: B256,
    pub last_observed_block: u64,
}

/// Details of a pending cross-chain Saga Intent escrow lock.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntentEscrow {
    /// Unique intent identifier
    pub intent_id: B256,
    /// Address of target account thread
    pub target_account: Address,
    /// Locked escrow amount
    pub amount: alloy_primitives::U256,
    /// Expiry epoch height
    pub expire_epoch: u64,
}

/// Consensus checkpoint finalized at the boundary of a global epoch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochCheckpoint {
    /// ID of the epoch that was finalized
    pub epoch_id: u64,
    /// Final consensus root (merit-weighted BFT checkpoint)
    pub consensus_root: B256,
    /// State root of the Verkle tree at this epoch boundary
    pub state_root: B256,
    /// Hash of the Chandy-Lamport distributed snapshot channel state
    pub snapshot_hash: B256,
    /// Aggregated validator signatures supporting the checkpoint
    pub validator_signatures: Vec<Vec<u8>>,
}

/// `DPoT` Validator Directory with `TinyMeritRank` reputation.
#[derive(Debug, Clone)]
pub struct ValidatorRegistry {
    /// Mapping of validator DID to validator type (HardwareTEE, VanillaSocial)
    pub validators: HashMap<String, ValidatorType>,
    /// Resolved `WireGuard` keys mapped by DID.
    pub peer_keys: HashMap<String, [u8; 32]>,
    /// Mapping from resolved EVM Address to DID.
    pub address_to_did: HashMap<Address, String>,
    _seeds: HashSet<String>,
    /// Directed edges representing endorsements.
    pub endorsements: HashMap<String, HashMap<String, f64>>,
    /// Global reputation mapping: DID -> Score
    pub reputation: HashMap<String, f64>,
    supported_manifolds: HashMap<String, HashSet<u64>>,
    /// Current block number tracked by the consensus engine
    pub current_block: u64,
    /// Current epoch height tracked by the consensus engine
    pub current_epoch: u64,
    /// Store KZG commitments submitted by validators: DID -> 48-byte commitment
    pub commitments: HashMap<String, [u8; 48]>,
    /// Static configurations loaded at startup.
    pub static_cfg: crate::config::StaticConfig,
    /// Dynamic, hot-reloadable configurations.
    pub dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
    /// Full identity documents.
    pub identities: HashMap<String, RegisteredIdentity>,
    /// Chain ID of the node.
    pub chain_id: u64,
    /// Map of Address to their AccountFrontier state in the block-lattice.
    pub account_frontiers: HashMap<Address, AccountFrontier>,
    /// Global registry of all submitted block-lattice blocks.
    pub lattice_blocks: HashMap<B256, crate::stateless::LatticeBlock>,
    /// Post-quantum public keys registered per Address.
    pub pq_keys: HashMap<Address, Vec<u8>>,
    /// Key security tier assigned per Address.
    pub did_key_tier: HashMap<Address, crate::pq_registry::KeyTier>,
    /// Active intent escrow locks.
    pub intent_escrows: HashMap<B256, IntentEscrow>,
    /// Cross-Manifold Saga Actors
    pub actors: HashMap<B256, crate::saga::CrossManifoldActor>,
    /// Inboxes for Cross-Manifold Saga Actors
    pub actor_inboxes: HashMap<B256, Vec<crate::relay_mesh::CrossManifoldMessage>>,
    /// Latest epoch checkpoint finalized.
    pub latest_checkpoint: Option<EpochCheckpoint>,
    /// Active jurisdiction policies per manifold.
    pub jurisdiction_vectors: HashMap<u64, crate::jurisdiction::JurisdictionVector>,
    /// Active cross-chain observer subroutines.
    pub cross_chain_subroutines: HashMap<B256, CrossChainObserverSubroutine>,
    /// Accounts that have explicitly declared ALLOW_LEGACY=true.
    pub legacy_allowed: HashSet<Address>,
    /// Configurable timeout in epochs after which an unclaimed lattice send can be reclaimed.
    pub reclaim_timeout_epochs: u64,
    /// On-chain settled balances per Address in the block-lattice.
    pub account_balances: HashMap<Address, U256>,
    /// Accounts that have active paymaster sponsorship.
    pub paymaster_sponsors: HashMap<Address, Address>,
    /// On-chain Chained Account Registers (polymorphic 64-slot arrays)
    pub account_registers: HashMap<Address, crate::lattice::car_register::PolymorphicAccountRegister>,
    /// On-chain verified DAO / Enterprise App Anchors (NextERP, NextCloud, etc.)
    pub dao_app_anchors: HashMap<Address, Vec<crate::lattice::car_register::DaoAppAnchor>>,
    /// On-chain Relational SQL Databases per contract or DAO account
    pub sql_databases: HashMap<Address, crate::system_contracts::ContractSqlDatabase>,
    /// On-chain Decentralized Zanzibar ReBAC Graph Engine
    pub zanzibar_engine: crate::governance::zanzibar::ZanzibarGraphEngine,
    /// Nullifier set of send-block hashes already claimed by a matching Receive block.
    ///
    /// A second Receive block presenting the same `send_block_hash` is rejected
    /// immediately, preventing double-credit without requiring a global lock.
    pub claimed_sends: HashSet<B256>,
    /// Nullifier set of ContractCall intent IDs already registered in this epoch.
    ///
    /// Duplicate intent IDs are rejected to prevent the same off-chain intent from
    /// triggering multiple on-chain contract calls.
    pub used_intent_ids: HashSet<B256>,
    /// Nullifier set of cross-manifold message IDs already processed by this node.
    ///
    /// Prevents a replayed relay packet from minting tokens or triggering state
    /// mutations a second time. Populated in `relay_mesh::extract_message`.
    pub processed_manifold_messages: HashSet<B256>,
    /// Epoch at which each send block was originally submitted, keyed by send-block hash.
    ///
    /// Used by `process_reclaim_sends` to detect send blocks that have gone unclaimed
    /// for more than `reclaim_timeout_epochs` epochs and refund the sender.
    pub send_block_epochs: HashMap<B256, u64>,
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new(
            crate::config::StaticConfig::default(),
            std::sync::Arc::new(std::sync::RwLock::new(crate::config::DynamicConfig::default())),
        )
    }
}

impl ValidatorRegistry {
    /// Creates a new validator registry instance.
    pub fn new(
        static_cfg: crate::config::StaticConfig,
        dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
    ) -> Self {
        let mut reg = Self {
            validators: HashMap::new(),
            peer_keys: HashMap::new(),
            address_to_did: HashMap::new(),
            endorsements: HashMap::new(),
            supported_manifolds: HashMap::new(),
            _seeds: HashSet::new(),
            reputation: HashMap::new(),
            current_block: 0,
            current_epoch: 1,
            commitments: HashMap::new(),
            static_cfg,
            dynamic_cfg,
            identities: HashMap::new(),
            chain_id: 1337,
            account_frontiers: HashMap::new(),
            lattice_blocks: HashMap::new(),
            pq_keys: HashMap::new(),
            did_key_tier: HashMap::new(),
            intent_escrows: HashMap::new(),
            actors: HashMap::new(),
            actor_inboxes: HashMap::new(),
            latest_checkpoint: None,
            jurisdiction_vectors: HashMap::new(),
            cross_chain_subroutines: HashMap::new(),
            claimed_sends: HashSet::new(),
            used_intent_ids: HashSet::new(),
            processed_manifold_messages: HashSet::new(),
            send_block_epochs: HashMap::new(),
            legacy_allowed: HashSet::new(),
            reclaim_timeout_epochs: 10,
            account_balances: HashMap::new(),
            paymaster_sponsors: HashMap::new(),
            account_registers: HashMap::new(),
            dao_app_anchors: HashMap::new(),
            sql_databases: HashMap::new(),
            zanzibar_engine: crate::governance::zanzibar::ZanzibarGraphEngine::new(),
        };
        reg.load_genesis_allocations(None);
        reg
    }

    /// Syncs a parsed SovereignDidDocument into the validator registry identity and PQ maps.
    pub fn sync_identity_from_doc(&mut self, doc: sovereign_identity::did::SovereignDidDocument) -> bool {
        if doc.evm_address == Address::ZERO {
            return false;
        }
        let addr = doc.evm_address;
        let did_uri = if !doc.did_uri.is_empty() {
            doc.did_uri.clone()
        } else {
            format!("did:sovereign:{}:{addr:#x}", self.chain_id)
        };
        let ident = RegisteredIdentity {
            did: did_uri.clone(),
            doc: doc.clone(),
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.address_to_did.insert(addr, did_uri.clone());
        self.identities.insert(did_uri.clone(), ident.clone());
        self.identities.insert(format!("{addr:#x}"), ident.clone());
        self.identities.insert(format!("{addr:#x}").to_lowercase(), ident.clone());
        self.identities.insert(format!("{addr}"), ident);

        if !doc.ml_dsa_pubkey.is_empty() {
            self.pq_keys.insert(addr, doc.ml_dsa_pubkey.clone());
        } else if !doc.xmss_pubkey.is_empty() {
            self.pq_keys.insert(addr, doc.xmss_pubkey.clone());
        } else if !doc.slh_dsa_pubkey.is_empty() {
            self.pq_keys.insert(addr, doc.slh_dsa_pubkey.clone());
        } else if !doc.falcon_pubkey.is_empty() {
            self.pq_keys.insert(addr, doc.falcon_pubkey.clone());
        }
        true
    }

    /// Verifies if an account's latest state root matches an expected commitment.
    #[must_use]
    pub fn verify_account_state_root(&self, account: &Address, expected_root: &alloy_primitives::B256) -> bool {
        if let Some(frontier) = self.account_frontiers.get(account) {
            &frontier.latest_hash == expected_root
        } else {
            expected_root == &alloy_primitives::B256::ZERO
        }
    }

    /// Checks whether an account has a registered DID identity on Slot 0.
    /// In a stateless account-lattice ledger, no state mutations or transitions
    /// are permitted without an on-chain DID identity on Slot 0.
    #[must_use]
    pub fn has_registered_did(&self, account: &Address) -> bool {
        if *account == Address::ZERO {
            return false;
        }
        // 1. Check CAR register Slot 0
        if let Some(car) = self.account_registers.get(account) {
            if car.has_registered_did() {
                return true;
            }
        }
        // 2. Check canonical on-chain registry maps
        self.address_to_did.contains_key(account)
            || self.identities.values().any(|i| i.doc.evm_address != Address::ZERO && (i.doc.evm_address == *account || format!("{:#x}", i.doc.evm_address).eq_ignore_ascii_case(&format!("{account:#x}"))))
            || self.pq_keys.contains_key(account)
    }

    /// Retrieves or initializes a PolymorphicAccountRegister for an account.
    pub fn get_or_create_register(&mut self, account: Address) -> &mut crate::lattice::car_register::PolymorphicAccountRegister {
        let balance = self.account_balances.get(&account).copied().unwrap_or(U256::ZERO);
        self.account_registers.entry(account).or_insert_with(|| {
            crate::lattice::car_register::PolymorphicAccountRegister::new_with_default_config(account, balance)
        })
    }

    /// Records and verifies a DAO Enterprise App State Anchor (NextERP, NextCloud, etc.).
    /// Strictly verifies caller has a registered DID, updates the polymorphic slot, and recomputes the state tip.
    pub fn record_dao_app_anchor(&mut self, mut anchor: crate::lattice::car_register::DaoAppAnchor) -> Result<B256, &'static str> {
        let sender = anchor.sender_address;
        
        // 1. Verify caller has on-chain registered DID
        let has_did = self.address_to_did.contains_key(&sender)
            || self.identities.values().any(|i| i.doc.evm_address == sender || format!("{:#x}", i.doc.evm_address).eq_ignore_ascii_case(&format!("{:#x}", sender)))
            || self.pq_keys.contains_key(&sender);
        if !has_did {
            return Err("Caller account has no registered on-chain DID identity");
        }

        // 2. If existing anchors exist for this app_id, verify previous_anchor continuity
        if let Some(existing) = self.dao_app_anchors.get(&sender) {
            if let Some(last_anchor) = existing.iter().rev().find(|a| a.app_id.eq_ignore_ascii_case(&anchor.app_id)) {
                if anchor.previous_anchor != B256::ZERO && anchor.previous_anchor != last_anchor.sql_state_root && anchor.previous_anchor != last_anchor.state_tip {
                    return Err("Provenance mismatch: previous_anchor does not match the latest registered anchor for this app");
                }
            }
        }

        // 3. Anchor in the polymorphic register (slot allocation and state tip calculation)
        let balance = self.account_balances.get(&sender).copied().unwrap_or(U256::ZERO);
        let reg = self.account_registers.entry(sender).or_insert_with(|| {
            crate::lattice::car_register::PolymorphicAccountRegister::new_with_default_config(sender, balance)
        });
        reg.balance = balance;

        let (slot_id, state_tip) = reg.anchor_dao_app(anchor.clone())?;
        anchor.slot_id = slot_id;
        anchor.state_tip = state_tip;

        // 4. Update account frontier latest_hash with the new state tip
        let mut frontier = self.get_or_create_frontier(sender);
        frontier.sequence += 1;
        frontier.latest_hash = state_tip;
        self.update_frontier(sender, frontier);

        // 5. Store anchor
        self.dao_app_anchors.entry(sender).or_default().push(anchor);

        Ok(state_tip)
    }

    /// Loads persisted DID identities from decentralized Iroh storage into the registry.
    pub fn load_iroh_identities(&mut self, storage_path: Option<&str>) {
        let candidate_paths = if let Some(p) = storage_path {
            vec![std::path::PathBuf::from(p)]
        } else {
            vec![
                std::path::PathBuf::from("/tmp/sovereign-storage"),
                std::path::PathBuf::from("storage"),
                std::path::PathBuf::from("../storage"),
            ]
        };

        for path in candidate_paths {
            let blobs_dir = path.join("blobs");
            if blobs_dir.exists() {
                match std::fs::read_dir(&blobs_dir) {
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            match std::fs::read_to_string(entry.path()) {
                                Ok(content) => {
                                    if let Some(doc) = sovereign_identity::did::SovereignDidDocument::from_json_string(&content) {
                                        self.sync_identity_from_doc(doc);
                                    }
                                }
                                // Warn on per-file read errors so operators can detect
                                // corrupt blob store entries without stopping the node.
                                Err(e) => tracing::warn!(
                                    path = %entry.path().display(),
                                    error = %e,
                                    "Failed to read Iroh blob file"
                                ),
                            }
                        }
                    }
                    // Warn (don't panic) when the blobs directory itself is unreadable;
                    // the node can still start with an empty identity cache.
                    Err(e) => tracing::warn!(
                        path = %blobs_dir.display(),
                        error = %e,
                        "Failed to read Iroh blobs directory"
                    ),
                }
            }
        }
    }

    /// Loads genesis account allocations from `genesis.json` into the block-lattice state.
    ///
    /// ## Path resolution
    ///
    /// The file is loaded only from the **explicit path** supplied by the caller (typically
    /// `StaticConfig::genesis_path`). No parent-directory traversal is performed.
    ///
    /// **Why no directory walk?** An earlier implementation walked `../` looking for
    /// `genesis.json` when the direct path was missing. If the node binary was started from
    /// an unexpected working directory (e.g., `/` by a systemd unit), this could disclose
    /// unrelated JSON files from parent directories. Restricting to the caller-supplied path
    /// eliminates that class of path-traversal risk entirely.
    ///
    /// If no path is supplied, only `"genesis.json"` relative to the current working
    /// directory is attempted — never any `..`-prefixed path.
    pub fn load_genesis_allocations(&mut self, genesis_path: Option<&str>) {
        // Only the explicit caller-supplied path (or CWD-relative fallback) is tried.
        let candidate_paths = if let Some(p) = genesis_path {
            vec![std::path::PathBuf::from(p)]
        } else {
            // Fall back to genesis.json in the current working directory only.
            vec![std::path::PathBuf::from("genesis.json")]
        };

        for path in candidate_paths {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(alloc) = val.get("alloc").and_then(|a| a.as_object()) {
                            for (addr_str, info) in alloc {
                                if let Ok(addr) = addr_str.parse::<Address>() {
                                    let balance = if let Some(bal_str) = info.get("balance").and_then(|b| b.as_str()) {
                                        let clean = bal_str.trim_start_matches("0x").trim_start_matches("0X");
                                        U256::from_str_radix(clean, 16)
                                            .or_else(|_| U256::from_str_radix(clean, 10))
                                            .unwrap_or(U256::ZERO)
                                    } else {
                                        U256::ZERO
                                    };

                                    self.account_balances.insert(addr, balance);

                                    // Create genesis lattice block (epoch 0 receive open block)
                                    let genesis_hash = B256::from_slice(blake3::hash(format!("genesis_alloc:{addr:#x}").as_bytes()).as_bytes());
                                    let block = crate::lattice::types::LatticeBlock {
                                        account: addr,
                                        previous_hash: B256::ZERO,
                                        sequence: 0,
                                        payload: crate::lattice::types::LatticePayload::Receive {
                                            send_block_hash: B256::ZERO,
                                            amount: balance,
                                        },
                                        signature: Vec::new(),
                                        static_witnesses: Vec::new(),
                                    };
                                    self.lattice_blocks.insert(genesis_hash, block);

                                    let mut frontier = self.get_or_create_frontier(addr);
                                    frontier.sequence = 0;
                                    frontier.latest_hash = genesis_hash;
                                    self.update_frontier(addr, frontier);
                                    self.legacy_allowed.insert(addr);
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Returns the settled account balance for a given address in the block-lattice.
    pub fn get_account_balance(&self, addr: &Address) -> U256 {
        if let Some(bal) = self.account_balances.get(addr) {
            return *bal;
        }
        let mut balance = U256::ZERO;
        for block in self.lattice_blocks.values() {
            match &block.payload {
                crate::lattice::types::LatticePayload::Send { recipient: _, amount } => {
                    if block.account == *addr {
                        balance = balance.saturating_sub(*amount);
                    }
                }
                crate::lattice::types::LatticePayload::Receive { amount, .. } => {
                    if block.account == *addr {
                        balance = balance.saturating_add(*amount);
                    }
                }
                _ => {}
            }
        }
        balance
    }

    /// Credits an account's settled lattice balance.
    pub fn credit_account_balance(&mut self, addr: Address, amount: U256) {
        let current = self.get_account_balance(&addr);
        let entry = self.account_balances.entry(addr).or_insert(current);
        *entry = entry.saturating_add(amount);
    }

    /// Debits an account's settled lattice balance. Returns false if insufficient funds.
    pub fn debit_account_balance(&mut self, addr: Address, amount: U256) -> bool {
        let current = self.get_account_balance(&addr);
        if current < amount {
            return false;
        }
        let entry = self.account_balances.entry(addr).or_insert(current);
        *entry = entry.saturating_sub(amount);
        true
    }

    /// Gets the configured send reclaim timeout in epochs.
    pub fn get_reclaim_timeout_epochs(&self) -> u64 {
        self.reclaim_timeout_epochs
    }

    /// Sets the send reclaim timeout in epochs.
    pub fn set_reclaim_timeout_epochs(&mut self, epochs: u64) {
        self.reclaim_timeout_epochs = epochs;
    }

    /// Scans for timed-out unclaimed send blocks and refunds the original sender.
    ///
    /// ## Why this exists
    ///
    /// In the block-lattice model, a Send block moves value out of the sender's frontier
    /// immediately, but the value is only credited to the recipient when a matching Receive
    /// block is submitted. If the recipient never submits a Receive block (offline, lost key,
    /// wrong address), the funds would be permanently locked without this reclaim mechanism.
    ///
    /// A send block is eligible for reclaim when **both** conditions hold:
    /// 1. It has **not** been claimed by a Receive block (not in `claimed_sends`).
    /// 2. `submit_epoch + reclaim_timeout_epochs <= current_epoch`.
    ///
    /// Returns the list of reclaimed send-block hashes so callers can emit refund log entries.
    pub fn process_reclaim_sends(&mut self) -> Vec<alloy_primitives::B256> {
        let timeout = self.reclaim_timeout_epochs;
        let current_epoch = self.current_epoch;

        // Collect eligible send-block hashes.
        let to_reclaim: Vec<alloy_primitives::B256> = self.send_block_epochs
            .iter()
            .filter(|(hash, &submit_epoch)| {
                !self.claimed_sends.contains(*hash)
                    && submit_epoch.saturating_add(timeout) <= current_epoch
            })
            .map(|(hash, _)| *hash)
            .collect();

        for hash in &to_reclaim {
            // Look up the original send block to determine sender and amount.
            if let Some(block) = self.lattice_blocks.get(hash).cloned() {
                if let crate::lattice::types::LatticePayload::Send { amount, .. } = &block.payload {
                    self.credit_account_balance(block.account, *amount);
                    tracing::info!(
                        sender = ?block.account,
                        ?amount,
                        send_block_hash = ?hash,
                        "Reclaimed timed-out send block: balance refunded to sender",
                    );
                }
            }
            self.send_block_epochs.remove(hash);
            self.claimed_sends.insert(*hash); // mark as consumed so it can't be reclaimed twice
        }

        to_reclaim
    }

    /// Checks if an address has explicitly declared ALLOW_LEGACY=true.
    pub fn is_legacy_allowed(&self, address: &Address) -> bool {
        self.legacy_allowed.contains(address)
    }

    /// Sets or removes the ALLOW_LEGACY flag for an address.
    pub fn set_legacy_allowed(&mut self, address: Address, allowed: bool) {
        if allowed {
            self.legacy_allowed.insert(address);
        } else {
            self.legacy_allowed.remove(&address);
        }
    }

    /// Registers that a validator's identity DID supports/has access to an external chain.
    pub fn register_validator_supported_manifold(&mut self, did: String, manifold_id: u64) {
        self.supported_manifolds.entry(did).or_default().insert(manifold_id);
    }

    /// Registers a cross-chain smart contract observer subroutine.
    pub fn register_cross_chain_observer_subroutine(&mut self, sub: CrossChainObserverSubroutine) {
        self.cross_chain_subroutines.insert(sub.subroutine_id, sub);
    }

    /// Returns the registered DID of an address.
    pub fn get_did_by_address(&self, address: &Address) -> Option<String> {
        self.address_to_did.get(address).cloned()
    }

    /// Gets or creates a default frontier for the given account address.
    pub fn get_or_create_frontier(&mut self, address: Address) -> AccountFrontier {
        self.account_frontiers.entry(address).or_insert_with(|| AccountFrontier {
            latest_hash: B256::ZERO,
            sequence: 0,
            locked: false,
            locked_at: 0,
            paused_context: None,
            snapshot_size: 0,
            cached_compliance: None,
            merit_rank: crate::jurisdiction::MeritRank::Rank0,
            epochs_at_current_rank: 0,
        }).clone()
    }

    /// Updates the frontier for the given account address.
    pub fn update_frontier(&mut self, address: Address, frontier: AccountFrontier) {
        self.account_frontiers.insert(address, frontier);
    }

    /// Helper to normalize a query DID string (prepending did:peer: if it starts with 4zQm or z).
    pub fn normalize_query_did(did: &str) -> String {
        let trimmed = did.trim();
        if trimmed.starts_with("did:sovereign:") {
            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() == 4 {
                let id = parts[3];
                if !id.starts_with("0x") {
                    if !id.starts_with('4') {
                        return format!("did:peer:4{}", id);
                    } else {
                        return format!("did:peer:{}", id);
                    }
                }
            }
        }
        if trimmed.starts_with("did:") {
            trimmed.to_string()
        } else if !trimmed.starts_with("0x") {
            format!("did:peer:{}", trimmed)
        } else {
            trimmed.to_string()
        }
    }

    /// Helper to extract an EVM address from a query DID if possible.
    pub fn extract_address_from_did(did: &str) -> Option<Address> {
        let norm_did = Self::normalize_query_did(did);
        if norm_did.starts_with("did:sovereign:") {
            let parts: Vec<&str> = norm_did.split(':').collect();
            if parts.len() == 4 {
                let clean = parts[3].trim_start_matches("0x");
                if clean.len() == 40 {
                    if let Ok(addr_bytes) = alloy_primitives::hex::decode(clean) {
                        return Some(Address::from_slice(&addr_bytes));
                    }
                }
            }
        }
        if let Some(pos) = norm_did.find("0x") {
            if norm_did.len() >= pos + 42 {
                let addr_str = &norm_did[pos..pos+42];
                if let Ok(addr) = addr_str.parse::<Address>() {
                    return Some(addr);
                }
            }
        }
        None
    }

    /// Search registered identities for any public key matching the query (multibase prefix-agnostic).
    pub fn find_identity_by_any_key(&self, query: &str) -> Option<&RegisteredIdentity> {
        let norm_query = Self::normalize_query_did(query);
        let clean_query = norm_query.strip_prefix("did:peer:").unwrap_or(&norm_query);
        if clean_query.starts_with('z') {
            if let Ok(decoded) = bs58::decode(&clean_query[1..]).into_vec() {
                for ident in self.identities.values() {
                    let doc = &ident.doc;
                    let primary_ident = if let Some(primary_did) = self.address_to_did.get(&doc.evm_address) {
                        self.identities.get(primary_did).unwrap_or(ident)
                    } else {
                        ident
                    };
                    if doc.secp256k1_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.secp256k1_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.ed25519_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.ed25519_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.bls_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.bls_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.ml_dsa_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.ml_dsa_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.slh_dsa_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.slh_dsa_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.falcon_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.falcon_pubkey) {
                        return Some(primary_ident);
                    }
                    if doc.xmss_pubkey == decoded || (decoded.len() > 2 && &decoded[2..] == doc.xmss_pubkey) {
                        return Some(primary_ident);
                    }
                }
            }
        }
        None
    }

    /// Returns the EVM Address associated with a DID.
    pub fn get_address_by_did(&self, did: &str) -> Option<Address> {
        let norm_did = Self::normalize_query_did(did);
        if let Some(ident) = self.identities.get(&norm_did) {
            return Some(ident.doc.evm_address);
        }
        if let Some(ident) = self.find_identity_by_any_key(&norm_did) {
            return Some(ident.doc.evm_address);
        }
        if let Some(addr) = Self::extract_address_from_did(&norm_did) {
            if self.address_to_did.contains_key(&addr) {
                return Some(addr);
            }
        }
        self.address_to_did.iter()
            .find(|(_, d)| d.as_str() == norm_did.as_str())
            .map(|(&addr, _)| addr)
    }

    /// Checks if address is registered and returns its type.
    pub fn get_type_by_address(&self, address: &Address) -> Option<ValidatorType> {
        let did = self.address_to_did.get(address)?;
        self.validators.get(did).copied()
    }

    /// Checks if a DID is registered in the validator or user directory.
    pub fn is_did_registered(&self, did: &str) -> bool {
        let norm_did = Self::normalize_query_did(did);
        if self.peer_keys.contains_key(&norm_did) {
            return true;
        }
        if self.find_identity_by_any_key(&norm_did).is_some() {
            return true;
        }
        if let Some(addr) = Self::extract_address_from_did(&norm_did) {
            if let Some(mapped_did) = self.address_to_did.get(&addr) {
                return self.peer_keys.contains_key(mapped_did);
            }
        }
        false
    }

    /// Checks if a DID is fully registered (not a placeholder).
    pub fn is_did_fully_registered(&self, did: &str) -> bool {
        let norm_did = Self::normalize_query_did(did);
        if let Some(key) = self.peer_keys.get(&norm_did) {
            return *key != [0u8; 32];
        }
        if self.find_identity_by_any_key(&norm_did).is_some() {
            return true;
        }
        if let Some(addr) = Self::extract_address_from_did(&norm_did) {
            if let Some(mapped_did) = self.address_to_did.get(&addr) {
                if let Some(key) = self.peer_keys.get(mapped_did) {
                    return *key != [0u8; 32];
                }
            }
        }
        false
    }

    /// Returns the active `WireGuard` peer keys and their mapped addresses.
    pub fn active_peers(&self) -> HashMap<[u8; 32], Address> {
        let mut active = HashMap::new();
        for (did, &peer_key) in &self.peer_keys {
            if let Some(val_type) = self.validators.get(did) {
                let sgx_threshold = self.dynamic_cfg.read().unwrap().sgx_reputation_threshold;
                if *val_type == ValidatorType::HardwareTEE && sgx_threshold > 0.0 {
                    let rep = self.reputation.get(did).copied().unwrap_or(0.0);
                    if rep < sgx_threshold {
                        continue;
                    }
                }
                if let Some((&addr, _)) = self.address_to_did.iter().find(|(_, d)| *d == did) {
                    active.insert(peer_key, addr);
                }
            }
        }
        active
    }

    /// Returns routable validators for a target manifold ID.
    pub fn get_routable_validators(&self, target_manifold_id: u64) -> HashSet<Address> {
        let mut routable = HashSet::new();
        let active = self.active_peers();
        for addr in active.values() {
            if let Some(did) = self.get_did_by_address(addr) {
                if let Some(manifolds) = self.supported_manifolds.get(&did) {
                    if manifolds.contains(&target_manifold_id) {
                        routable.insert(*addr);
                    }
                }
            }
        }
        let quorum_threshold = self.dynamic_cfg.read().unwrap().manifold_quorum_threshold;
        if routable.len() < quorum_threshold {
            return HashSet::new();
        }
        routable
    }

    /// Filters routable validators meeting the minimum orchestrator merit threshold.
    pub fn get_eligible_orchestrators(&self, target_manifold_id: u64, min_orchestrator_merit: f64) -> HashSet<Address> {
        let mut eligible = HashSet::new();
        for addr in self.get_routable_validators(target_manifold_id) {
            if self.get_reputation_by_address(&addr) >= min_orchestrator_merit {
                eligible.insert(addr);
            }
        }
        eligible
    }

    /// Returns the reputation score of a validator by address.
    pub fn get_reputation_by_address(&self, address: &Address) -> f64 {
        let Some(did) = self.address_to_did.get(address) else { return 0.0; };
        self.reputation.get(did).copied().unwrap_or(0.0)
    }

    /// Resolves and registers a user DID, mapping their EVM Address.
    pub fn register_user_did(&mut self, candidate_did: String) -> Result<Address, &'static str> {
        if candidate_did.starts_with("did:peer:2") {
            return Err("Sovereign DID Error: did:peer:2 is deprecated and no longer supported. Please use did:peer:4.");
        }

        let doc = sovereign_identity::did::SovereignDidDocument::from_did_string(&candidate_did)
            .or_else(|| sovereign_identity::did::SovereignDidDocument::from_json_string(&candidate_did))
            .ok_or("Failed to resolve Sovereign DID document synchronously. Ensure it is a valid did:peer:4, did:sovereign, or W3C DID document format.")?;

        if candidate_did.starts_with("did:peer:4") {
            // Check that all 7 required key types are present and complete
            if doc.evm_address == alloy_primitives::Address::ZERO
                || doc.ed25519_pubkey.is_empty()
                || doc.bls_pubkey.is_empty()
                || doc.ml_dsa_pubkey.is_empty()
                || doc.slh_dsa_pubkey.is_empty()
                || doc.falcon_pubkey.is_empty()
                || doc.xmss_pubkey.is_empty()
            {
                return Err("Sovereign DID Error: DID is missing required verification keys. A fully registered identity requires all 7 keys (Secp256k1, Ed25519, BLS, ML-DSA, SLH-DSA, Falcon, XMSS).");
            }
        }

        let addr = doc.evm_address;

        // Duplicate registration check (idempotent / key update allowed for same owner)
        if let Some(existing_did) = self.address_to_did.get(&addr) {
            if self.is_did_fully_registered(existing_did) && existing_did != &candidate_did && existing_did != &doc.did_uri {
                // Address already mapped to another distinct identity
            }
        }

        // Non-zero key marks this as fully registered (can send transactions)
        self.peer_keys.insert(candidate_did.clone(), [0x01; 32]);
        self.address_to_did.insert(addr, candidate_did.clone());

        // Converted/Domain formats:
        // 1. Short did:peer:4 format: did:peer:4{hash_comp}
        let short_peer_did = if candidate_did.starts_with("did:peer:4") {
            let rest = candidate_did.strip_prefix("did:peer:4").unwrap();
            let colons: Vec<&str> = rest.split(':').collect();
            if !colons.is_empty() {
                Some(format!("did:peer:4{}", colons[0]))
            } else {
                None
            }
        } else {
            None
        };

        if let Some(ref sp_did) = short_peer_did {
            self.peer_keys.insert(sp_did.clone(), [0x01; 32]);
        }

        // 2. did:sovereign:{chain_id}:{id}
        let sovereign_hash_did = if candidate_did.starts_with("did:peer:4") {
            let rest = candidate_did.strip_prefix("did:peer:4").unwrap();
            let colons: Vec<&str> = rest.split(':').collect();
            if !colons.is_empty() {
                Some(format!("did:sovereign:{}:{}", self.chain_id, colons[0]))
            } else {
                None
            }
        } else {
            None
        };

        let sovereign_addr_did = format!("did:sovereign:{}:{addr:#x}", self.chain_id);

        if let Some(ref sh_did) = sovereign_hash_did {
            self.peer_keys.insert(sh_did.clone(), [0x01; 32]);
        }
        self.peer_keys.insert(sovereign_addr_did.clone(), [0x01; 32]);

        // Map EVM address to the sovereign address DID
        // Keep candidate_did as the primary mapping in address_to_did to return full DID document on reverse lookups.

        let epoch = self.current_epoch;
        self.identities.insert(candidate_did.clone(), RegisteredIdentity {
            did: candidate_did.clone(),
            doc: doc.clone(),
            registered_at: epoch,
        });

        if let Some(ref sp_did) = short_peer_did {
            self.identities.insert(sp_did.clone(), RegisteredIdentity {
                did: sp_did.clone(),
                doc: doc.clone(),
                registered_at: epoch,
            });
        }
        if let Some(ref sh_did) = sovereign_hash_did {
            self.identities.insert(sh_did.clone(), RegisteredIdentity {
                did: sh_did.clone(),
                doc: doc.clone(),
                registered_at: epoch,
            });
        }
        self.identities.insert(sovereign_addr_did.clone(), RegisteredIdentity {
            did: sovereign_addr_did,
            doc,
            registered_at: epoch,
        });

        Ok(addr)
    }

    /// Punishes a validator for proposing or voting on an invalid state root/proof.
    pub fn penalize_validator_reputation(&mut self, did: &str, penalty: f64) {
        if let Some(rep) = self.reputation.get_mut(did) {
            *rep = (*rep - penalty).max(0.0);
        }
    }

    /// Mock validator insertion helper for testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn add_mock_validator(&mut self, did: String, address: Address, peer_key: [u8; 32]) {
        self.peer_keys.insert(did.clone(), peer_key);
        self.address_to_did.insert(address, did.clone());
        self.validators.insert(did.clone(), ValidatorType::HardwareTEE);
        self.reputation.insert(did, 1.0);
    }
}

use std::sync::{OnceLock, RwLock};

/// Global static validator registry.
pub static VALIDATOR_REGISTRY: OnceLock<RwLock<ValidatorRegistry>> = OnceLock::new();

/// Returns a static reference to the shared thread-safe validator registry.
pub fn get_registry() -> &'static RwLock<ValidatorRegistry> {
    VALIDATOR_REGISTRY.get_or_init(|| {
        RwLock::new(ValidatorRegistry::new(
            crate::config::StaticConfig::default(),
            std::sync::Arc::new(std::sync::RwLock::new(crate::config::DynamicConfig::default())),
        ))
    })
}

/// Initializes the global validator registry with custom configurations.
pub fn init_registry(
    static_cfg: crate::config::StaticConfig,
    dynamic_cfg: std::sync::Arc<std::sync::RwLock<crate::config::DynamicConfig>>,
) -> Result<(), &'static str> {
    VALIDATOR_REGISTRY
        .set(RwLock::new(ValidatorRegistry::new(static_cfg, dynamic_cfg)))
        .map_err(|_| "Global registry has already been initialized")
}

// ─────────────────────────────────────────────────────────────────────────────
// Two-Stage Contribution Evaluator & Inflation Tokenomics
// ─────────────────────────────────────────────────────────────────────────────

/// Two-Stage Contribution Evaluator coordinating relevance filters & deliberative scoring.
#[derive(Debug, Clone, Default)]
pub struct TwoStageContributionEvaluator {
    pub evaluated_contributions: HashMap<String, ContributionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionResult {
    pub cid: String,
    pub proposer: Address,
    pub stage1_passed: bool,
    pub likelihood: f64,
    pub stage2_rounds: u32,
    pub final_score: f64,
    pub converged: bool,
}

impl TwoStageContributionEvaluator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            evaluated_contributions: HashMap::new(),
        }
    }

    /// Stage 1: Relevance Filter
    /// - Proposer trust neighbourhood: N(p) = { u | R_p(u) >= 0.05 }
    /// - 7-member committee via stratified sampling
    /// - Private likelihood \ell >= 0.80, 5-of-7 threshold signature
    pub fn evaluate_stage1_relevance(
        &self,
        proposer: Address,
        reputation_vector: &HashMap<Address, f64>,
        likelihood_votes: &[f64],
    ) -> Result<(bool, f64), &'static str> {
        let _n_p: Vec<Address> = reputation_vector.iter()
            .filter(|(&addr, &rep)| addr != proposer && rep >= 0.05)
            .map(|(&addr, _)| addr)
            .collect();

        if likelihood_votes.is_empty() {
            return Err("No likelihood votes provided");
        }

        let total_votes = likelihood_votes.len();
        let positive_votes = likelihood_votes.iter().filter(|&&l| l >= 0.80).count();
        let passed = positive_votes >= 5; // 5-of-7 threshold
        let avg_likelihood = likelihood_votes.iter().sum::<f64>() / (total_votes as f64);

        Ok((passed, avg_likelihood))
    }

    /// Stage 2: Deliberative Scoring
    /// - Max 10 gossip rounds
    /// - Early stop if \sigma <= 0.05 * \mu
    /// - At round 10: \sigma <= 0.20 * \mu => final score c = median(round 10); else neutral (0.0)
    pub fn evaluate_stage2_deliberative_scoring(
        &self,
        round_scores: &[Vec<f64>],
    ) -> (f64, u32, bool) {
        if round_scores.is_empty() {
            return (0.0, 0, false);
        }

        for (round_idx, scores) in round_scores.iter().enumerate() {
            if scores.is_empty() {
                continue;
            }
            let n = scores.len() as f64;
            let mean = scores.iter().sum::<f64>() / n;
            let variance = scores.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n;
            let std_dev = variance.sqrt();

            // Early stop condition: \sigma <= 0.05 * \mu
            if mean > 0.0 && std_dev <= 0.05 * mean {
                return (mean.clamp(0.0, 100.0), (round_idx + 1) as u32, true);
            }

            // Check if final round (round 10)
            if round_idx + 1 >= 10 || round_idx + 1 == round_scores.len() {
                if mean > 0.0 && std_dev <= 0.20 * mean {
                    let mut sorted = scores.clone();
                    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    let median = sorted[sorted.len() / 2];
                    return (median.clamp(0.0, 100.0), (round_idx + 1) as u32, true);
                } else {
                    return (0.0, (round_idx + 1) as u32, false); // neutral
                }
            }
        }

        (0.0, round_scores.len() as u32, false)
    }

    /// Calculates activity credit: ac = 1.0 + 0.1 * G (range: 1.0 - 3.0)
    #[must_use]
    pub fn calculate_activity_credit(gossip_rounds: u32) -> f64 {
        (1.0 + (gossip_rounds as f64) * 0.1).clamp(1.0, 3.0)
    }

    /// Calculates raw merit points: M_i^\tau = \sum (ac * c)
    #[must_use]
    pub fn calculate_raw_merit_points(evaluations: &[(f64, u32)]) -> f64 {
        evaluations.iter().map(|&(score, rounds)| {
            let ac = Self::calculate_activity_credit(rounds);
            ac * score
        }).sum()
    }

    /// Monthly Epoch Token Distribution (Inflation-based):
    /// T_i^\tau = E_\tau * (M_i^\tau / \sum_j M_j^\tau) * R_i^\tau(i)
    #[must_use]
    pub fn calculate_token_distribution(
        epoch_mint_pool: U256,
        agent_merit: f64,
        total_network_merit: f64,
        self_reputation: f64,
    ) -> U256 {
        if total_network_merit <= 1e-9 || agent_merit <= 1e-9 {
            return U256::ZERO;
        }

        let merit_ratio = agent_merit / total_network_merit;
        let weighted_share = merit_ratio * self_reputation;

        let pool_f64 = epoch_mint_pool.to::<u128>() as f64;
        let tokens_f64 = pool_f64 * weighted_share;
        U256::from(tokens_f64 as u128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_domain_conversion_and_lookup() {
        let mut registry = ValidatorRegistry::new(
            crate::config::StaticConfig::default(),
            std::sync::Arc::new(std::sync::RwLock::new(crate::config::DynamicConfig::default())),
        );
        registry.chain_id = 420;

        // Generate a valid did:peer:4 from a seed
        let seed = alloy_primitives::B256::repeat_byte(0xbc);
        let doc = sovereign_identity::did::SovereignDidDocument::derive_from_seed(seed);
        let original_did = doc.did_uri.clone();

        // Register the DID
        let addr_res = registry.register_user_did(original_did.clone());
        assert!(addr_res.is_ok());
        let addr = addr_res.unwrap();

        // Check lookup with original DID
        assert!(registry.is_did_registered(&original_did));
        assert!(registry.is_did_fully_registered(&original_did));
        assert_eq!(registry.get_address_by_did(&original_did), Some(addr));

        // Check lookup with short did:peer:4 DID (domain conversion)
        let short_peer_did = format!("did:peer:4{}", doc.short_form.strip_prefix("did:peer:4").unwrap_or(&doc.short_form));
        assert!(registry.is_did_registered(&short_peer_did));
        assert_eq!(registry.get_address_by_did(&short_peer_did), Some(addr));

        // Check lookup with did:sovereign:{chain_id}:{hash}
        let hash_part = original_did.strip_prefix("did:peer:4").unwrap().split(':').next().unwrap();
        let sovereign_hash_did = format!("did:sovereign:420:{hash_part}");
        assert!(registry.is_did_registered(&sovereign_hash_did));
        assert_eq!(registry.get_address_by_did(&sovereign_hash_did), Some(addr));

        // Check lookup with did:sovereign:{chain_id}:{address_hex}
        let sovereign_addr_did = format!("did:sovereign:420:{addr:#x}");
        assert!(registry.is_did_registered(&sovereign_addr_did));
        assert_eq!(registry.get_address_by_did(&sovereign_addr_did), Some(addr));

        // Check lookup with did:peer:0x... format (embedded EVM address)
        let did_peer_with_addr = format!("did:peer:{addr:#x}");
        assert!(registry.is_did_registered(&did_peer_with_addr));
        assert_eq!(registry.get_address_by_did(&did_peer_with_addr), Some(addr));

        // Verify reverse lookup of EVM Address returns the primary full did:peer:4 DID (with all curves)
        let resolved_primary_did = registry.get_did_by_address(&addr);
        assert_eq!(resolved_primary_did, Some(original_did.clone()));

        // Helper to encode multibase key
        let encode_mb = |prefix: &[u8], key: &[u8]| -> String {
            let mut combined = prefix.to_vec();
            combined.extend_from_slice(key);
            format!("did:peer:z{}", bs58::encode(&combined).into_string())
        };

        // Assert sub-key queries for all curves resolve to the correct identity
        let secp_query = encode_mb(&[0xe7, 0x01], &doc.secp256k1_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&secp_query).map(|i| &i.did), Some(&original_did));

        let ed_query = encode_mb(&[0xed, 0x01], &doc.ed25519_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&ed_query).map(|i| &i.did), Some(&original_did));

        let bls_query = encode_mb(&[0xea, 0x01], &doc.bls_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&bls_query).map(|i| &i.did), Some(&original_did));

        let ml_query = encode_mb(&[0x93, 0x01], &doc.ml_dsa_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&ml_query).map(|i| &i.did), Some(&original_did));

        let slh_query = encode_mb(&[0x94, 0x01], &doc.slh_dsa_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&slh_query).map(|i| &i.did), Some(&original_did));

        let falcon_query = encode_mb(&[0x92, 0x01], &doc.falcon_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&falcon_query).map(|i| &i.did), Some(&original_did));

        let xmss_query = encode_mb(&[0x95, 0x01], &doc.xmss_pubkey);
        assert_eq!(registry.find_identity_by_any_key(&xmss_query).map(|i| &i.did), Some(&original_did));
    }

    #[test]
    fn test_legacy_allowed_policy_toggle() {
        let mut registry = ValidatorRegistry::default();
        let target = Address::repeat_byte(0x77);

        // Default state: not legacy allowed
        assert!(!registry.is_legacy_allowed(&target));

        // Enable ALLOW_LEGACY
        registry.set_legacy_allowed(target, true);
        assert!(registry.is_legacy_allowed(&target));

        // Disable ALLOW_LEGACY (upgrade to Quantum Secure)
        registry.set_legacy_allowed(target, false);
        assert!(!registry.is_legacy_allowed(&target));
    }
}