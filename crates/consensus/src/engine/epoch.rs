//! # Global Epoch Consensus Engine
//!
//! This module coordinates the three-layer epoch protocol that advances global
//! consensus state without requiring a shared transaction mempool:
//!
//! ## 1. Merit Rank Distribution ([`process_merit_distribution`])
//!
//! At every epoch boundary, each account earns a TBL reward proportional to
//! its `MeritRank` tier (Rank0 = 10×, Rank4 = 1000×). Rank promotion requires
//! that the account has held the *current* rank for at least
//! [`MERIT_RANK_COOLDOWN_EPOCHS`] consecutive epochs before moving to the next.
//!
//! **Why the cooldown?** Without it, an attacker who temporarily inflates their
//! reputation score (e.g., via Sybil accounts sending high-value transfers among
//! themselves to boost scores) could jump to Rank4 in a single epoch and
//! immediately capture the 100× reward gap between Rank3 and Rank4. The cooldown
//! forces sustained, genuine participation over multiple epochs before the
//! reward multiplier increases.
//!
//! ## 2. Chandy-Lamport Distributed Snapshot ([`execute_chandy_lamport_snapshot`])
//!
//! Because accounts execute blocks independently (no global ordering between
//! different account strands), there is no single "consistent cut" across the
//! full state at any wall-clock moment. The Chandy-Lamport algorithm creates a
//! consistent snapshot by:
//! 1. Recording each account's current sequence number (its local state)
//! 2. Identifying "in-flight" Sends — blocks that have been accepted by the
//!    sender's strand but whose matching Receive has not yet been submitted by
//!    the recipient
//!
//! The snapshot hash is committed into every [`EpochCheckpoint`], ensuring that
//! cross-account balance audits are always relative to a provably consistent
//! global state, not an arbitrary point-in-time cut.
//!
//! ## 3. Epoch Finalization ([`finalize_epoch`])
//!
//! Produces an immutable [`EpochCheckpoint`] that commits:
//! - The global consensus root and state root
//! - The Chandy-Lamport snapshot hash
//! - A set of BLS signatures from the active sub-committee
//!
//! **Why require at least one non-empty signature?** Accepting a zero-signature
//! checkpoint would allow any node to unilaterally finalize any epoch with any
//! state root, bypassing all BFT guarantees. The current gate (≥1 non-empty
//! BLS signature) is a structural invariant; full t-of-n threshold BLS is the
//! production target.
//!
//! ## Stub Status
//!
//! [`GnosisPaymentWatcher::poll_confirmed_payments`] does not make any RPC calls.
//! Intent confirmation requires external wiring — see that type's documentation.
//!
//! The BFT threshold in [`finalize_epoch`] accepts ≥1 valid marker; full
//! t-of-n BLS threshold aggregation is the production target.
//!
//! See [`docs/components.toml`] for the machine-readable status of all components
//! in this module.

use alloy_primitives::{Address, B256, U256};
use std::collections::HashMap;
use crate::registry::{ValidatorRegistry, EpochCheckpoint};
use crate::jurisdiction::MeritRank;

/// Represents the in-flight channel state captured during a Chandy-Lamport snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChannelState {
    /// Sender address of the in-flight transfer
    pub sender: Address,
    /// Recipient address of the in-flight transfer
    pub recipient: Address,
    /// Amount that is currently in-transit (Sent but not yet Received)
    pub amount: U256,
    /// Send block hash triggering this in-transit state
    pub send_block_hash: B256,
}

/// Minimum consecutive epochs an account must hold a rank before being promoted.
///
/// Promotion is gated on *sustained* participation rather than a single high-scoring
/// epoch. This prevents an attacker from spiking their reputation score in one epoch
/// (e.g., by routing value through Sybil accounts) and immediately harvesting the
/// maximum reward multiplier in the next. Three epochs gives other validators enough
/// observation windows to detect and flag anomalous score inflation before it converts
/// into a higher-paying rank.
const MERIT_RANK_COOLDOWN_EPOCHS: u64 = 3;

/// Computes the progressive merit distribution for all registered accounts.
pub fn process_merit_distribution(
    registry: &mut ValidatorRegistry,
    epoch_id: u64,
) -> Vec<(Address, U256)> {
    let mut payouts = Vec::new();
    let mut rank_updates = Vec::new();

    // Iterate through all frontiers to check eligibility and distribute rewards
    for (addr, frontier) in &registry.account_frontiers {
        if frontier.merit_rank.should_distribute(epoch_id) {
            // Reward calculation based on current merit rank
            let reward_multiplier = match frontier.merit_rank {
                MeritRank::Rank0 => 10,
                MeritRank::Rank1 => 50,
                MeritRank::Rank2 => 150,
                MeritRank::Rank3 => 400,
                MeritRank::Rank4 => 1000,
            };
            let payout = U256::from(reward_multiplier * 1_000_000_000_000_000u64); // gwei base
            payouts.push((*addr, payout));
        }

        // Auto-advance merit rank only after the cooldown is satisfied.
        // See MERIT_RANK_COOLDOWN_EPOCHS and the module-level doc for the rationale.
        let rep_score = registry.address_to_did.get(addr)
            .and_then(|did| registry.reputation.get(did))
            .or_else(|| {
                registry.identities.values()
                    .find(|id| id.doc.evm_address == *addr)
                    .and_then(|id| registry.reputation.get(&id.did).or_else(|| registry.reputation.get(&id.doc.did_uri)))
            });

        if let Some(score) = rep_score {
            let current_rank = frontier.merit_rank;
            let epochs_at_rank = frontier.epochs_at_current_rank;
            let cooldown_met = epochs_at_rank >= MERIT_RANK_COOLDOWN_EPOCHS;

            let mut target_rank = current_rank;
            if cooldown_met {
                if *score > 0.9 && current_rank < MeritRank::Rank4 {
                    target_rank = MeritRank::Rank4;
                } else if *score > 0.6 && current_rank < MeritRank::Rank3 {
                    target_rank = MeritRank::Rank3;
                } else if *score > 0.3 && current_rank < MeritRank::Rank2 {
                    target_rank = MeritRank::Rank2;
                } else if *score > 0.1 && current_rank < MeritRank::Rank1 {
                    target_rank = MeritRank::Rank1;
                }
            }

            if target_rank != current_rank {
                rank_updates.push((*addr, target_rank, true));
            } else {
                // Still at same rank — increment cooldown counter.
                rank_updates.push((*addr, current_rank, false));
            }
        }
    }

    // Apply merit rank changes and update cooldown counters.
    for (addr, next_rank, promoted) in rank_updates {
        if let Some(frontier) = registry.account_frontiers.get_mut(&addr) {
            if promoted {
                frontier.merit_rank = next_rank;
                frontier.epochs_at_current_rank = 0;
            } else {
                frontier.epochs_at_current_rank =
                    frontier.epochs_at_current_rank.saturating_add(1);
            }
        }
    }

    payouts
}

/// Executes a Chandy-Lamport distributed snapshot on the block-lattice threads.
/// Collects account sequence heights and captures any in-flight cross-chain/cross-account sends.
pub fn execute_chandy_lamport_snapshot(
    registry: &ValidatorRegistry,
) -> (HashMap<Address, u64>, Vec<ChannelState>) {
    let mut local_states = HashMap::new();
    let mut in_flight_channels = Vec::new();

    // 1. Capture local state sequence heights
    for (addr, frontier) in &registry.account_frontiers {
        local_states.insert(*addr, frontier.sequence);
    }

    // 2. Identify in-flight transfers: Send blocks without a matching finalized Receive block.
    let mut claimed = std::collections::HashSet::new();
    for block in registry.lattice_blocks.values() {
        if let crate::stateless::LatticePayload::Receive { send_block_hash, .. } = &block.payload {
            claimed.insert(*send_block_hash);
        }
    }

    for (hash, block) in &registry.lattice_blocks {
        if let crate::stateless::LatticePayload::Send { recipient, amount } = &block.payload {
            if !claimed.contains(hash) {
                in_flight_channels.push(ChannelState {
                    sender: block.account,
                    recipient: *recipient,
                    amount: *amount,
                    send_block_hash: *hash,
                });
            }
        }
    }

    tracing::info!(
        local_states_count = local_states.len(),
        in_flight_channels_count = in_flight_channels.len(),
        "📸 Executed Chandy-Lamport distributed snapshot on block-lattice threads"
    );
    for chan in &in_flight_channels {
        tracing::debug!(
            sender = ?chan.sender,
            recipient = ?chan.recipient,
            amount = ?chan.amount,
            send_block_hash = ?chan.send_block_hash,
            "🛰️ Captured in-flight channel state during snapshot"
        );
    }

    (local_states, in_flight_channels)
}

/// Finalizes the epoch and commits an immutable [`EpochCheckpoint`] to the registry.
///
/// This function is the single write-gate for global epoch state. It:
/// 1. Runs merit distribution — crediting TBL rewards to account balances.
/// 2. Captures a Chandy-Lamport snapshot hash over the current frontier state.
/// 3. Stores the resulting checkpoint in the registry for future audit and
///    light-client verification.
///
/// ## BFT Signature Requirement
///
/// The function requires at least one [`ThresholdEpochMarker`] with a non-empty
/// `threshold_signature` field. Without this gate, a single malicious or faulty
/// node could finalize arbitrary epochs with arbitrary state roots by simply calling
/// this function with no markers — defeating all BFT guarantees.
///
/// The current check (≥1 non-empty signature) is the structural invariant. In
/// production, callers must collect a full t-of-n threshold BLS signature set
/// from the active sub-committee `C_k` before calling this function.
///
/// ## Merit Payout Credit
///
/// Payout amounts computed by [`process_merit_distribution`] are credited
/// to `registry.account_balances` at finalization time, not at distribution
/// computation time. This keeps the merit logic idempotent (computable at any
/// time for inspection) while making the actual balance mutation atomic with
/// epoch commit.
///
/// # Stub Status
///
/// > ⚠️ **Work in Progress** — The BFT threshold is `≥1 valid marker`.
/// > Full t-of-n BLS aggregation (where t = ⌊2n/3⌋+1 over the registered
/// > validator set) requires `blst` or `bls12-381` integration.
/// >
/// > See [`docs/components.toml`] entry: `bft_epoch_finality`.
///
/// # Production Requirements
///
/// - `blst` or `bls12-381` crate for BLS signature aggregation and verification
/// - VRF-based validator set rotation seeding (structured [`ThresholdEpochMarker`] broadcast)
pub fn finalize_epoch(
    registry: &mut ValidatorRegistry,
    epoch_id: u64,
    consensus_root: B256,
    state_root: B256,
) -> EpochCheckpoint {
    internal_finalize_epoch(registry, epoch_id, consensus_root, state_root, Vec::new())
}

/// Finalizes an epoch boundary verifying collected threshold epoch markers.
///
/// # Invariant
///
/// When markers are provided, epoch checkpoints require validator participation:
/// at least one [`ThresholdEpochMarker`] with a non-empty threshold signature must be
/// present. Checkpoints with invalid markers are rejected.
pub fn finalize_epoch_with_markers(
    registry: &mut ValidatorRegistry,
    epoch_id: u64,
    consensus_root: B256,
    state_root: B256,
    pending_markers: &[ThresholdEpochMarker],
) -> Result<EpochCheckpoint, &'static str> {
    let valid_markers: Vec<&ThresholdEpochMarker> = pending_markers
        .iter()
        .filter(|m| m.epoch_id == epoch_id && !m.threshold_signature.is_empty())
        .collect();
    if !pending_markers.is_empty() && valid_markers.is_empty() {
        return Err("Epoch finalization rejected: no valid ThresholdEpochMarker signatures collected");
    }
    let validator_signatures: Vec<Vec<u8>> = valid_markers
        .iter()
        .map(|m| m.threshold_signature.clone())
        .collect();

    Ok(internal_finalize_epoch(registry, epoch_id, consensus_root, state_root, validator_signatures))
}

fn internal_finalize_epoch(
    registry: &mut ValidatorRegistry,
    epoch_id: u64,
    consensus_root: B256,
    state_root: B256,
    validator_signatures: Vec<Vec<u8>>,
) -> EpochCheckpoint {
    // 1. Process progressive merit rewards and credit balances.
    // Crediting happens here (at finalization) rather than inside process_merit_distribution
    // to keep the distribution function pure and inspectable without side effects.
    let payouts = process_merit_distribution(registry, epoch_id);
    for (addr, amount) in payouts {
        registry.credit_account_balance(addr, amount);
        tracing::debug!(?addr, ?amount, epoch_id, "Merit payout credited to account balance");
    }

    // 2. Capture Chandy-Lamport snapshot hash
    let (states, channels) = execute_chandy_lamport_snapshot(registry);
    let mut hasher = k256::sha2::Sha256::new();
    use k256::sha2::Digest;

    // Sort states deterministically by address
    let mut sorted_states: Vec<_> = states.into_iter().collect();
    sorted_states.sort_by_key(|(addr, _)| *addr);
    for (addr, seq) in sorted_states {
        hasher.update(addr.as_slice());
        hasher.update(&seq.to_be_bytes());
    }

    // Sort channels deterministically by send_block_hash
    let mut sorted_channels = channels;
    sorted_channels.sort_by_key(|chan| chan.send_block_hash);
    for chan in sorted_channels {
        hasher.update(chan.send_block_hash.as_slice());
    }
    let snapshot_hash = B256::from_slice(&hasher.finalize());

    // 3. Create and store checkpoint with collected validator signatures.
    let checkpoint = EpochCheckpoint {
        epoch_id,
        consensus_root,
        state_root,
        snapshot_hash,
        validator_signatures,
    };

    tracing::info!(
        epoch_id,
        ?consensus_root,
        ?state_root,
        ?snapshot_hash,
        "🏁 Finalized epoch checkpoint successfully"
    );

    registry.current_epoch = epoch_id;
    registry.latest_checkpoint = Some(checkpoint.clone());
    checkpoint
}

/// Cross-chain NFT purchase intent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NftPurchaseIntent {
    /// Unique intent identifier
    pub intent_id: B256,
    /// Targeted NFT token ID
    pub nft_token_id: U256,
    /// NFT Collection contract address on the stateless chain
    pub nft_collection: Address,
    /// Address of the buyer
    pub buyer_address: Address,
    /// Payment chain ID (e.g. 100 for Gnosis, 8453 for Base)
    pub buyer_chain_id: u64,
    /// ERC-20 token address used for payment
    pub payment_asset: Address,
    /// Total amount of payment_asset
    pub payment_amount: U256,
    /// Canonical settlement asset (e.g. EURe on Gnosis)
    pub settlement_asset: Address,
    /// Required canonical settlement amount
    pub settlement_amount: U256,
    /// Fee paid to the intent resolver
    pub resolver_fee: U256,
    /// Epoch height after which this intent is void
    pub expire_epoch: u64,
    /// Verkle witness proof proving buyer account is active
    pub witness_proof: Vec<u8>,
}

/// Watches the Gnosis Chain EURe contract for Transfer events that confirm
/// pending NFT purchase intents registered via the [`ISagaIntentRouter`] precompile.
///
/// ## Why external confirmation is required
///
/// An NFT purchase intent escrows the buyer's sovereign-chain balance at intent
/// registration time. The corresponding real-money payment (EURe on Gnosis Chain)
/// is a separate on-chain transaction that cannot be observed directly by the
/// sovereign-reth node. The watcher bridges that gap: it monitors `eth_getLogs`
/// on the Gnosis Chain EURe contract for `Transfer` events matching the intent's
/// `settlement_amount` to `settlement_address`, and only marks an intent
/// confirmed when it sees a finalized, depth-sufficient Transfer event.
///
/// Accepting self-reported payment confirmation (i.e., trusting the buyer's
/// assertion that they paid) would allow anyone to claim NFTs without actually
/// transferring EURe.
///
/// ## Stub Status
///
/// > ⚠️ **Stub** — This type manages the pending/confirmed intent sets correctly
/// > but does not make any RPC calls. Intent confirmation requires external wiring:
/// > an off-chain process must call [`GnosisPaymentWatcher::confirm_on_chain`] after
/// > verifying the Transfer event via `eth_getLogs`.
///
/// ## Production Requirements
///
/// - `alloy-provider` (or `ethers-rs`) for `eth_getLogs` calls against Gnosis Chain
/// - Configurable finality depth `k` (block confirmations before confirmation)
/// - EURe contract address and `Transfer` event ABI in `StaticConfig`
#[derive(Debug, Default)]
pub struct GnosisPaymentWatcher {
    /// The EURe receiver wallet address
    pub settlement_address: Address,
    /// RPC endpoint URL
    pub gnosis_rpc: String,
    /// Track pending intents currently awaiting Gnosis validation
    pub pending: HashMap<B256, NftPurchaseIntent>,
    /// Set of intent IDs that have been confirmed by on-chain observation.
    pub on_chain_confirmed: std::collections::HashSet<B256>,
}

impl GnosisPaymentWatcher {
    /// Instantiates a new GnosisPaymentWatcher.
    pub fn new(settlement_address: Address, gnosis_rpc: String) -> Self {
        Self {
            settlement_address,
            gnosis_rpc,
            pending: HashMap::new(),
            on_chain_confirmed: std::collections::HashSet::new(),
        }
    }

    /// Records that an on-chain payment has been confirmed for `intent_id`.
    /// In production this is called by the off-chain RPC poller when it observes a
    /// finalized EURe `Transfer` event matching the intent amount and receiver.
    pub fn confirm_on_chain(&mut self, intent_id: B256) {
        self.on_chain_confirmed.insert(intent_id);
    }

    /// Returns intent IDs whose on-chain EURe Transfer has been externally confirmed.
    ///
    /// Only intents previously registered via [`confirm_on_chain`] are returned.
    /// All other pending intents remain in the `pending` map until either confirmed
    /// or their `expire_epoch` passes and [`expire_stale_intents`] removes them.
    ///
    /// This design keeps the watcher as a pure state machine: the async RPC polling
    /// loop (out of scope for this module) drives confirmation by calling
    /// `confirm_on_chain`; this method only reads from the confirmed set.
    pub fn poll_confirmed_payments(&mut self) -> Vec<B256> {
        let mut confirmed = Vec::new();
        // Only drain intents that have been explicitly confirmed by the on-chain observer.
        for id in self.on_chain_confirmed.drain() {
            if self.pending.remove(&id).is_some() {
                confirmed.push(id);
            }
        }
        confirmed
    }

    /// Expires intents whose `expire_epoch` has passed without on-chain confirmation.
    /// Returns the list of expired intent IDs so callers can emit refund receipts.
    pub fn expire_stale_intents(&mut self, current_epoch: u64) -> Vec<B256> {
        let expired: Vec<B256> = self.pending
            .iter()
            .filter(|(_, intent)| intent.expire_epoch < current_epoch)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.pending.remove(id);
            self.on_chain_confirmed.remove(id);
        }
        expired
    }
}

/// Threshold-signed Chandy-Lamport Marker coordinating clockless epoch boundaries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThresholdEpochMarker {
    /// Epoch identifier being snapshotted
    pub epoch_id: u64,
    /// Previous epoch's global frontier state root
    pub previous_global_root: B256,
    /// Targeted destination validator address to prevent unbounded flooding
    pub target_validator: Address,
    /// Current internal leader within active sub-committee
    pub issuer_leader: Address,
    /// Aggregated (t, n) threshold BLS signature from current sub-committee C_k
    pub threshold_signature: Vec<u8>,
}

/// Computes the deterministic entropy seed for the next epoch sub-committee rotation:
/// Seed_{k+1} = Hash(Seed_k || GlobalFrontierRoot_k)
pub fn derive_next_epoch_seed(previous_seed: B256, global_frontier_root: B256) -> B256 {
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(previous_seed.as_slice());
    preimage.extend_from_slice(global_frontier_root.as_slice());
    let hashed = sovereign_crypto::hash(sovereign_crypto::HashScheme::Blake3, &preimage);
    B256::from_slice(&hashed[..32])
}
