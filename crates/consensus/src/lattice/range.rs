//! # 3-Tier Fractal Account-Lattice & Autonomous Range Sharding
//!
//! Provides the uniform Account-Lattice sharding model:
//! - **Tier 0 (User Account Chains)**: Standard user accounts (`0x0100...` to `0xFFFF...`).
//! - **Tier 1 (Range Meta-Chains)**: Shard boundaries (`0x0001...` to `0x00FF...`) storing SMT roots of child account tips.
//! - **Tier 2 (Global Epoch Chain)**: Root address `0x00...00E0` tracking the meta-consensus cut over Tier 1 heads.
//!
//! Autonomous `SplitBlock` (scale out on $>85\%$ load) and `MergeBlock` (scale in on $<10\%$ load) transitions,
//! strict address space bitmask segmentation, and localized PID Toxic Velocity Surge Pricing.

use alloy_primitives::{Address, B256, U256, address};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Global Epoch Meta-Chain Root Address (Tier 2).
pub const GLOBAL_EPOCH_CHAIN_ADDRESS: Address = address!("00000000000000000000000000000000000000e0");

/// Address Space Classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClassification {
    /// `0x00...0000 .. 0x00...00FF`: Core System Precompiles (Epoch 0x00E0, Paymaster 0x0002, DA 0x0053)
    SystemPrecompile,
    /// `0x00...0100 .. 0x00...FFFF`: Mirrored Foreign Chains (`0x00..01<ChainID>`)
    MirroredForeignChain,
    /// `0x00010000... .. 0x00FFFFFF...`: Shard Range Meta-Chains (Tagged by Depth)
    RangeMetaChain,
    /// `0x01000000... .. 0xFFFFFFFF...`: User Accounts & Smart Contracts (Entropy >= 0x01)
    UserAccount,
}

use crate::governance::system_registry::{is_system_address, virtual_chain_id};

/// Classifies an address according to the strict prefix bitmask.
#[must_use]
pub fn classify_address(addr: &Address) -> AddressClassification {
    let bytes = addr.as_slice();

    // 1. User Accounts: bytes[0] >= 0x01 (Entropy >= 0x01)
    if bytes[0] >= 0x01 {
        return AddressClassification::UserAccount;
    }

    // 2. Mirrored Foreign Chains: virtual_chain_id matches [0x00 x 15] || [0x01] || [ChainID u32]
    if virtual_chain_id(addr).is_some() {
        return AddressClassification::MirroredForeignChain;
    }

    // 3. System Precompiles: in EIP-1352 namespace or explicitly reserved
    if is_system_address(addr) {
        return AddressClassification::SystemPrecompile;
    }

    // 4. Shard Range Meta-Chains (Depth >= 1 or custom range partition heads)
    AddressClassification::RangeMetaChain
}

/// Derives the Tier 1 Range Meta-Chain address for a given partition key and depth.
#[must_use]
pub fn derive_range_meta_address(range_prefix: u16, depth: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0x00;
    bytes[1] = depth;
    bytes[2..4].copy_from_slice(&range_prefix.to_be_bytes());
    Address::from(bytes)
}

/// Tier 1 Range Shard Meta-Chain State.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RangeShardState {
    /// Partition range start (e.g. 0x0000)
    pub range_start: u16,
    /// Partition range end (e.g. 0x7FFF)
    pub range_end: u16,
    /// Sub-tree depth (0 = root /16, 1 = /17, up to max depth 16)
    pub depth: u8,
    /// SMT root of all child account tips in this range
    pub smt_root: B256,
    /// Number of active user accounts in this shard
    pub active_accounts_count: u64,
    /// Sustained gas load factor over recent epochs (0.0 to 1.0)
    pub load_factor: f64,
    /// Epoch height of latest SMT root update
    pub updated_at_epoch: u64,
}

/// Localized PID Toxic Velocity Surge Pricing Engine.
#[derive(Debug, Clone)]
pub struct ToxicVelocityEngine {
    pub base_fee: U256,
    pub target_utilization: f64,
    pub alpha_pid: f64,
    pub beta_velocity: f64,
    pub previous_turnover: U256,
    pub previous_timestamp: u64,
}

impl Default for ToxicVelocityEngine {
    fn default() -> Self {
        Self {
            base_fee: U256::from(1_000_000_000u64), // 1 Gwei base
            target_utilization: 0.85,
            alpha_pid: 0.125,
            beta_velocity: 0.25,
            previous_turnover: U256::ZERO,
            previous_timestamp: 0,
        }
    }
}

impl ToxicVelocityEngine {
    /// Computes dynamic surge gas price for this range based on current utilization and turnover velocity.
    ///
    /// Formula:
    /// $$\text{GasFee}_{\text{range}}(t) = \text{BaseFee} \times \left(1 + \alpha \frac{U(t)-U_{\text{target}}}{U_{\text{target}}}\right) + \beta \left(\frac{d\text{Turnover}}{dt}\right)^2$$
    #[must_use]
    pub fn calculate_surge_gas_price(
        &mut self,
        current_utilization: f64,
        current_turnover: U256,
        current_timestamp: u64,
    ) -> U256 {
        let base_f64 = self.base_fee.to::<u128>() as f64;

        // 1. Linear PID Utilization component
        let util_diff = (current_utilization - self.target_utilization) / self.target_utilization;
        let pid_factor = (1.0 + self.alpha_pid * util_diff).max(0.5);

        // 2. Quadratic Turnover Velocity component
        let dt = (current_timestamp.saturating_sub(self.previous_timestamp)).max(1) as f64;
        let d_turnover = if current_turnover >= self.previous_turnover {
            (current_turnover - self.previous_turnover).to::<u128>() as f64
        } else {
            0.0
        };

        let turnover_rate = (d_turnover / (dt * 1e18)).max(0.0);
        let velocity_penalty = self.beta_velocity * turnover_rate * turnover_rate * base_f64;

        self.previous_turnover = current_turnover;
        self.previous_timestamp = current_timestamp;

        let total_price = (base_f64 * pid_factor + velocity_penalty) as u128;
        U256::from(total_price)
    }
}

/// Split Block Transition: Emitted when a range exceeds 85% utilization, splitting into left and right child SMTs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitBlock {
    pub parent_range_start: u16,
    pub parent_range_end: u16,
    pub parent_depth: u8,
    pub left_child_smt_root: B256,
    pub right_child_smt_root: B256,
    pub epoch_id: u64,
}

/// Merge Block Transition: Emitted when sibling ranges drop below 10% utilization, folding back into the parent SMT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeBlock {
    pub left_range_start: u16,
    pub left_range_end: u16,
    pub right_range_start: u16,
    pub right_range_end: u16,
    pub parent_smt_root: B256,
    pub epoch_id: u64,
}

/// Range Sharding Coordinator managing Tier 1 meta-chains and split/merge lifecycle.
#[derive(Debug, Clone, Default)]
pub struct RangeShardingCoordinator {
    /// Active range shards indexed by range start prefix
    pub active_shards: HashMap<u16, RangeShardState>,
    /// Toxic velocity engines per range
    pub velocity_engines: HashMap<u16, ToxicVelocityEngine>,
    /// Consecutively observed high-load epochs for splitting
    pub high_load_epochs: HashMap<u16, u32>,
    /// Consecutively observed low-load epochs for merging
    pub low_load_epochs: HashMap<u16, u32>,
}

impl RangeShardingCoordinator {
    /// Initializes genesis range shard (`[0x0000..0xFFFF]` at depth 0).
    #[must_use]
    pub fn new_genesis() -> Self {
        let mut coordinator = Self::default();
        let genesis_shard = RangeShardState {
            range_start: 0x0000,
            range_end: 0xFFFF,
            depth: 0,
            smt_root: B256::ZERO,
            active_accounts_count: 0,
            load_factor: 0.10,
            updated_at_epoch: 0,
        };
        coordinator.active_shards.insert(0x0000, genesis_shard);
        coordinator.velocity_engines.insert(0x0000, ToxicVelocityEngine::default());
        coordinator
    }

    /// Evaluates telemetry and executes an autonomous SplitBlock if a range experiences > 85% load for 3 epochs.
    pub fn evaluate_split(
        &mut self,
        range_start: u16,
        left_root: B256,
        right_root: B256,
        epoch_id: u64,
    ) -> Result<Option<SplitBlock>, &'static str> {
        let shard = self.active_shards.get_mut(&range_start).ok_or("Shard not found")?;
        if shard.depth >= 16 {
            return Ok(None); // Shard depth limit reached (/16 max partitions)
        }

        if shard.load_factor > 0.85 {
            let count = self.high_load_epochs.entry(range_start).or_insert(0);
            *count += 1;
            if *count >= 3 {
                // Trigger Split
                let mid = shard.range_start + (shard.range_end - shard.range_start) / 2;
                let split_block = SplitBlock {
                    parent_range_start: shard.range_start,
                    parent_range_end: shard.range_end,
                    parent_depth: shard.depth,
                    left_child_smt_root: left_root,
                    right_child_smt_root: right_root,
                    epoch_id,
                };

                let new_depth = shard.depth + 1;
                let left_shard = RangeShardState {
                    range_start: shard.range_start,
                    range_end: mid,
                    depth: new_depth,
                    smt_root: left_root,
                    active_accounts_count: shard.active_accounts_count / 2,
                    load_factor: 0.40,
                    updated_at_epoch: epoch_id,
                };
                let right_shard = RangeShardState {
                    range_start: mid + 1,
                    range_end: shard.range_end,
                    depth: new_depth,
                    smt_root: right_root,
                    active_accounts_count: shard.active_accounts_count / 2,
                    load_factor: 0.40,
                    updated_at_epoch: epoch_id,
                };

                self.active_shards.remove(&range_start);
                self.high_load_epochs.remove(&range_start);

                self.active_shards.insert(left_shard.range_start, left_shard);
                self.active_shards.insert(right_shard.range_start, right_shard);
                self.velocity_engines.insert(mid + 1, ToxicVelocityEngine::default());

                return Ok(Some(split_block));
            }
        } else {
            self.high_load_epochs.insert(range_start, 0);
        }

        Ok(None)
    }

    /// Evaluates telemetry and executes an autonomous MergeBlock if sibling ranges experience < 10% load for 10 epochs.
    pub fn evaluate_merge(
        &mut self,
        left_start: u16,
        right_start: u16,
        combined_root: B256,
        epoch_id: u64,
    ) -> Result<Option<MergeBlock>, &'static str> {
        let left_shard = self.active_shards.get(&left_start).ok_or("Left shard not found")?.clone();
        let right_shard = self.active_shards.get(&right_start).ok_or("Right shard not found")?.clone();

        if left_shard.depth != right_shard.depth || left_shard.depth == 0 {
            return Ok(None);
        }

        if left_shard.load_factor < 0.10 && right_shard.load_factor < 0.10 {
            let count = self.low_load_epochs.entry(left_start).or_insert(0);
            *count += 1;
            if *count >= 10 {
                let merge_block = MergeBlock {
                    left_range_start: left_shard.range_start,
                    left_range_end: left_shard.range_end,
                    right_range_start: right_shard.range_start,
                    right_range_end: right_shard.range_end,
                    parent_smt_root: combined_root,
                    epoch_id,
                };

                let parent_shard = RangeShardState {
                    range_start: left_shard.range_start,
                    range_end: right_shard.range_end,
                    depth: left_shard.depth - 1,
                    smt_root: combined_root,
                    active_accounts_count: left_shard.active_accounts_count + right_shard.active_accounts_count,
                    load_factor: 0.15,
                    updated_at_epoch: epoch_id,
                };

                self.active_shards.remove(&left_start);
                self.active_shards.remove(&right_start);
                self.low_load_epochs.remove(&left_start);

                self.active_shards.insert(parent_shard.range_start, parent_shard);
                return Ok(Some(merge_block));
            }
        } else {
            self.low_load_epochs.insert(left_start, 0);
        }

        Ok(None)
    }
}
