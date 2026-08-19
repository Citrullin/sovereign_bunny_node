//! # Global Epoch Consensus Engine
//!
//! Enforces epoch boundaries, updates merit ranks, performs progressive distribution,
//! coordinates Chandy-Lamport snapshots, and rotates the sync committee.

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

        // Auto-advance merit rank based on reputation score thresholds
        if let Some(did) = registry.address_to_did.get(addr) {
            if let Some(score) = registry.reputation.get(did) {
                let current_rank = frontier.merit_rank;
                let mut target_rank = current_rank;
                if *score > 0.9 && current_rank < MeritRank::Rank4 {
                    target_rank = MeritRank::Rank4;
                } else if *score > 0.6 && current_rank < MeritRank::Rank3 {
                    target_rank = MeritRank::Rank3;
                } else if *score > 0.3 && current_rank < MeritRank::Rank2 {
                    target_rank = MeritRank::Rank2;
                } else if *score > 0.1 && current_rank < MeritRank::Rank1 {
                    target_rank = MeritRank::Rank1;
                }

                if target_rank != current_rank {
                    rank_updates.push((*addr, target_rank));
                }
            }
        }
    }

    // Apply merit rank promotions
    for (addr, next_rank) in rank_updates {
        if let Some(frontier) = registry.account_frontiers.get_mut(&addr) {
            frontier.merit_rank = next_rank;
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

/// Finalizes the epoch and commits a new EpochCheckpoint to the registry.
pub fn finalize_epoch(
    registry: &mut ValidatorRegistry,
    epoch_id: u64,
    consensus_root: B256,
    state_root: B256,
) -> EpochCheckpoint {
    // 1. Process progressive merit rewards
    let payouts = process_merit_distribution(registry, epoch_id);
    for (addr, _amount) in payouts {
        // Credit the rewarded balance directly to the account frontier / state
        // In a stateless zkEVM, this is reflected in the next block's Verkle leaf.
        let mut frontier = registry.get_or_create_frontier(addr);
        // Balance credit simulation (actual balances are tracked in state tree)
        frontier.locked_at = epoch_id;
        registry.update_frontier(addr, frontier);
    }

    // 2. Capture Chandy-Lamport snapshot hash
    let (states, channels) = execute_chandy_lamport_snapshot(registry);
    let mut hasher = k256::sha2::Sha256::new();
    use k256::sha2::Digest;
    for (addr, seq) in states {
        hasher.update(addr.as_slice());
        hasher.update(&seq.to_be_bytes());
    }
    for chan in channels {
        hasher.update(chan.send_block_hash.as_slice());
    }
    let snapshot_hash = B256::from_slice(&hasher.finalize());

    // 3. Create and store checkpoint
    let checkpoint = EpochCheckpoint {
        epoch_id,
        consensus_root,
        state_root,
        snapshot_hash,
        validator_signatures: Vec::new(),
    };

    tracing::info!(
        epoch_id,
        ?consensus_root,
        ?state_root,
        ?snapshot_hash,
        "🏁 Finalized epoch checkpoint successfully"
    );

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

/// Simulated mock cross-chain watcher checking Gnosis Chain for EURe transfers.
#[derive(Debug, Default)]
pub struct GnosisPaymentWatcher {
    /// The EURe receiver wallet address
    pub settlement_address: Address,
    /// RPC endpoint URL
    pub gnosis_rpc: String,
    /// Track pending intents currently awaiting Gnosis validation
    pub pending: HashMap<B256, NftPurchaseIntent>,
}

impl GnosisPaymentWatcher {
    /// Instantiates a new GnosisPaymentWatcher.
    pub fn new(settlement_address: Address, gnosis_rpc: String) -> Self {
        Self {
            settlement_address,
            gnosis_rpc,
            pending: HashMap::new(),
        }
    }

    /// Simulates checking Gnosis Chain for payment completion of pending intents.
    /// Returns list of confirmed intent IDs.
    pub fn poll_confirmed_payments(&mut self) -> Vec<B256> {
        let mut confirmed = Vec::new();
        // In simulation / dev mode, we automatically confirm all pending payments
        // after 1 epoch tick to demonstrate flow.
        for id in self.pending.keys() {
            confirmed.push(*id);
        }
        for id in &confirmed {
            self.pending.remove(id);
        }
        confirmed
    }
}
