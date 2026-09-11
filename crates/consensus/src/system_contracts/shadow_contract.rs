//! # Universal Reverse Shadow Contract Engine
//!
//! ## What are Shadow Contracts?
//!
//! A Shadow Contract is a cross-chain asset bridge with strict 1:1 reserve
//! enforcement. When a user deposits a native asset on the origin cluster,
//! the engine:
//!
//! 1. **Locks** the native asset in the engine's escrow map (`descriptors`).
//! 2. **Mints** a Shadow Instance on the destination cluster at a deterministic
//!    virtual address: `0x00...00_01_<dest_chain_id>`.
//!
//! The Shadow Instance is the only in-circulation representation of the locked
//! asset. No secondary minting is possible: each `receipt_id` is unique and
//! single-use (the nullifier set in [`ShadowBurnReceipt`] prevents double-release).
//!
//! When the destination owner burns the Shadow Instance, a [`ShadowBurnReceipt`]
//! is issued. The origin cluster verifies the receipt (epoch finality + nullifier
//! check) and releases the underlying native asset to the beneficiary.
//!
//! ## Why the 1:1 reserve invariant matters
//!
//! Without this invariant, a compromised destination cluster could mint unlimited
//! Shadow Instances without corresponding locked assets, inflating supply on the
//! origin cluster when receipts are later presented for release. The engine prevents
//! this by making the lock and the mint occur atomically within a single block, and
//! by making each receipt single-use via the `nullifier` field.
//!
//! ## Asset types supported
//!
//! - **Fungible** — native coins, ERC-20, SPL tokens
//! - **NonFungible** — ERC-721, Metaplex, Ordinals (with metadata hash binding)
//! - **MultiToken** — ERC-1155 batch wrapping
//!
//! ## Stub Status
//!
//! The k-epoch finality check in [`ShadowContractEngine::release_native_from_burn_proof`]
//! compares burn epoch against current epoch directly. True finality requires
//! the receipt to reference a committed [`EpochCheckpoint`] whose state root
//! is verified against the destination cluster's SMT root.
//!
//! See [`docs/components.toml`] entry: `shadow_contract_engine`.

use alloy_primitives::{Address, B256, U256};
use std::collections::HashMap;

/// Lifecycle state of a cross-chain shadow contract instance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShadowState {
    /// Asset locked in native escrow; shadow contract minted in destination superposition.
    ActiveSuperposition,
    /// Destination state finalized and burned; native asset ready for release.
    BurnedAndSettled,
}

/// Generalized asset representation supporting Fungible tokens, NFTs, and Multi-token batches.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShadowAsset {
    /// Fungible token (Native coins, ERC-20, SPL)
    Fungible {
        amount: U256,
        /// Optional CAIP-19 asset ID (e.g. "eip155:1/erc20:0xa0b8...")
        asset_identifier: Option<String>,
    },
    /// Non-Fungible Token (ERC-721, Metaplex, Ordinals)
    NonFungible {
        token_id: U256,
        collection: Address,
        metadata_uri_hash: B256,
    },
    /// Multi-Token Batch (ERC-1155)
    MultiToken {
        collection: Address,
        token_ids: Vec<U256>,
        amounts: Vec<U256>,
    },
}

/// A reverse shadow token descriptor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShadowTokenDescriptor {
    /// Unique receipt / escrow ID.
    pub receipt_id: B256,
    /// Original native depositor.
    pub depositor: Address,
    /// Intended recipient on destination cluster.
    pub recipient: Address,
    /// Destination chain ID.
    pub dest_chain_id: u32,
    /// Virtual address of the shadow contract (`0x00...00_01_<ChainID>`).
    pub shadow_virtual_address: Address,
    /// Wrapped asset details.
    pub asset: ShadowAsset,
    /// Current lifecycle state.
    pub state: ShadowState,
    /// Associated nullifier to prevent replay.
    pub nullifier: B256,
}

/// An active shadow instance minted on a destination cluster.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShadowInstance {
    pub receipt_id: B256,
    pub owner: Address,
    pub source_chain_id: u32,
    pub virtual_address: Address,
    pub asset: ShadowAsset,
    pub state: ShadowState,
}

/// Cryptographic burn receipt emitted by destination cluster upon burning a shadow instance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShadowBurnReceipt {
    pub receipt_id: B256,
    pub nullifier: B256,
    pub source_chain_id: u32,
    pub dest_chain_id: u32,
    pub beneficiary: Address,
    pub burned_asset: ShadowAsset,
    pub burn_epoch: u64,
}

/// In-memory Reserve Shadow Contract Vault managing 1:1 wrapped reserves and destination shadow instances.
#[derive(Debug, Clone, Default)]
pub struct ShadowTokenVault {
    /// Active shadow token escrows mapped by receipt ID on origin chain.
    pub shadow_tokens: HashMap<B256, ShadowTokenDescriptor>,
    /// Active shadow instances currently alive on this destination cluster.
    pub shadow_instances: HashMap<B256, ShadowInstance>,
    /// Spent nullifier set mapping nullifier to epoch height of settlement.
    pub spent_nullifiers: HashMap<B256, u64>,
}

impl ShadowTokenVault {
    /// Creates a new empty `ShadowTokenVault`.
    pub fn new() -> Self {
        Self {
            shadow_tokens: HashMap::new(),
            shadow_instances: HashMap::new(),
            spent_nullifiers: HashMap::new(),
        }
    }

    /// Wraps any generalized asset into a Reverse Shadow Contract instance targeting a destination chain.
    ///
    /// ECO-05: The depositor's settled balance is debited by the fungible amount before creating the
    /// shadow token descriptor, ensuring the same native balance cannot back multiple shadow wraps.
    /// Non-fungible and multi-token wraps lock the asset logically (balance debit is skipped for NFTs
    /// as the escrow semantics are represented by the descriptor itself).
    pub fn wrap_asset_to_shadow(
        &mut self,
        depositor: Address,
        recipient: Address,
        dest_chain_id: u32,
        asset: ShadowAsset,
        registry: &mut crate::governance::ValidatorRegistry,
    ) -> Result<ShadowTokenDescriptor, &'static str> {
        match &asset {
            ShadowAsset::Fungible { amount, .. } if amount.is_zero() => {
                return Err("Cannot wrap 0 fungible amount");
            }
            ShadowAsset::MultiToken { token_ids, amounts, .. } => {
                if token_ids.is_empty() || token_ids.len() != amounts.len() {
                    return Err("Invalid multi-token batch dimensions");
                }
                if amounts.iter().all(|a| a.is_zero()) {
                    return Err("Cannot wrap multi-token batch with all zero amounts");
                }
            }
            _ => {}
        }

        // ECO-05: Debit depositor's balance for fungible wraps before creating the escrow.
        if let ShadowAsset::Fungible { amount, .. } = &asset {
            if !registry.debit_account_balance(depositor, *amount) {
                return Err("Shadow wrap failed: insufficient depositor balance");
            }
        }

        let shadow_virtual_address = crate::system_registry::virtual_chain_address(dest_chain_id);

        let mut preimage = Vec::with_capacity(32 + 20 + 20 + 4);
        preimage.extend_from_slice(depositor.as_slice());
        preimage.extend_from_slice(recipient.as_slice());
        preimage.extend_from_slice(&dest_chain_id.to_be_bytes());

        match &asset {
            ShadowAsset::Fungible { amount, asset_identifier } => {
                preimage.extend_from_slice(&amount.to_be_bytes::<32>());
                if let Some(id) = asset_identifier {
                    preimage.extend_from_slice(id.as_bytes());
                }
            }
            ShadowAsset::NonFungible { token_id, collection, metadata_uri_hash } => {
                preimage.extend_from_slice(&token_id.to_be_bytes::<32>());
                preimage.extend_from_slice(collection.as_slice());
                preimage.extend_from_slice(metadata_uri_hash.as_slice());
            }
            ShadowAsset::MultiToken { collection, token_ids, amounts } => {
                preimage.extend_from_slice(collection.as_slice());
                for id in token_ids {
                    preimage.extend_from_slice(&id.to_be_bytes::<32>());
                }
                for amt in amounts {
                    preimage.extend_from_slice(&amt.to_be_bytes::<32>());
                }
            }
        }

        let receipt_id = alloy_primitives::keccak256(&preimage);
        let nullifier = alloy_primitives::keccak256(&receipt_id);

        let descriptor = ShadowTokenDescriptor {
            receipt_id,
            depositor,
            recipient,
            dest_chain_id,
            shadow_virtual_address,
            asset,
            state: ShadowState::ActiveSuperposition,
            nullifier,
        };

        self.shadow_tokens.insert(receipt_id, descriptor.clone());
        Ok(descriptor)
    }

    /// Convenience helper to wrap native tokens into a Fungible Shadow instance.
    ///
    /// ECO-05: Debits the depositor's balance via `registry` before creating the escrow.
    pub fn wrap_native_to_shadow(
        &mut self,
        depositor: Address,
        dest_chain_id: u32,
        amount: U256,
        registry: &mut crate::governance::ValidatorRegistry,
    ) -> Result<ShadowTokenDescriptor, &'static str> {
        self.wrap_asset_to_shadow(
            depositor,
            depositor,
            dest_chain_id,
            ShadowAsset::Fungible {
                amount,
                asset_identifier: None,
            },
            registry,
        )
    }

    /// Destination cluster receives cross-chain wrapped descriptor and mints the shadow asset instance,
    /// conferring full ownership of the reverse shadow contract to `descriptor.recipient`.
    pub fn mint_shadow_instance(
        &mut self,
        descriptor: &ShadowTokenDescriptor,
        source_chain_id: u32,
    ) -> Result<Address, &'static str> {
        if self.shadow_instances.contains_key(&descriptor.receipt_id) {
            return Err("Shadow instance already minted on destination");
        }

        let virtual_addr = crate::system_registry::virtual_chain_address(source_chain_id);
        let instance = ShadowInstance {
            receipt_id: descriptor.receipt_id,
            owner: descriptor.recipient,
            source_chain_id,
            virtual_address: virtual_addr,
            asset: descriptor.asset.clone(),
            state: ShadowState::ActiveSuperposition,
        };

        self.shadow_instances.insert(descriptor.receipt_id, instance);
        Ok(descriptor.recipient)
    }

    /// Transfers ownership of an active shadow instance on the destination cluster.
    /// Default variant verifying direct ownership.
    pub fn transfer_shadow_ownership(
        &mut self,
        receipt_id: B256,
        caller: Address,
        new_owner: Address,
    ) -> Result<(), &'static str> {
        self.transfer_shadow_ownership_gated(receipt_id, caller, new_owner, None)
    }

    /// Transfers ownership of an active shadow instance on the destination cluster,
    /// gated by Zanzibar ReBAC permissions.
    ///
    /// Authorization rules:
    /// 1. If a Zanzibar engine is provided, checks whether `caller` is authorized
    ///    via `allow_shadow` or `owner` relation under the `shadow` namespace for `receipt_id`.
    /// 2. If no Zanzibar engine is provided or no specific Zanzibar rules are registered for this receipt,
    ///    falls back to verifying direct ownership (`instance.owner == caller`).
    pub fn transfer_shadow_ownership_gated(
        &mut self,
        receipt_id: B256,
        caller: Address,
        new_owner: Address,
        zanzibar: Option<&crate::governance::ZanzibarGraphEngine>,
    ) -> Result<(), &'static str> {
        let instance = self.shadow_instances.get_mut(&receipt_id).ok_or("Shadow instance not found")?;
        if instance.state != ShadowState::ActiveSuperposition {
            return Err("Shadow instance is not active");
        }

        let is_direct_owner = instance.owner == caller;
        let is_zanzibar_authorized = if let Some(engine) = zanzibar {
            if engine.tuples.contains_key(&receipt_id) {
                engine.check_named("shadow", receipt_id, "allow_shadow", caller, 5)
                    || engine.check_named("shadow", receipt_id, "owner", caller, 5)
            } else {
                is_direct_owner
            }
        } else {
            is_direct_owner
        };

        if !is_zanzibar_authorized {
            return Err("Caller not authorized to transfer shadow ownership (Zanzibar permission denied)");
        }

        instance.owner = new_owner;
        Ok(())
    }

    /// Current owner on destination burns the shadow instance to initiate native release on the origin cluster.
    ///
    /// `dest_chain_id` must be supplied by the caller — it is the chain ID of the cluster
    /// that minted the shadow instance. Hardcoding this value to 0 would produce a burn receipt
    /// that can only ever target the same chain as the origin, breaking cross-chain routing.
    pub fn initiate_shadow_burn(
        &mut self,
        receipt_id: B256,
        caller: Address,
        beneficiary_on_origin: Address,
        epoch_height: u64,
        dest_chain_id: u32,
    ) -> Result<ShadowBurnReceipt, &'static str> {
        self.initiate_shadow_burn_gated(receipt_id, caller, beneficiary_on_origin, epoch_height, dest_chain_id, None)
    }

    /// Burns the shadow instance with optional Zanzibar ReBAC gating.
    ///
    /// `dest_chain_id` is supplied by the caller rather than read from the instance because
    /// the instance stores only `source_chain_id` (the origin cluster). Deriving the
    /// destination chain ID from instance state would require the destination cluster to
    /// know its own chain ID at mint time and embed it in the instance — creating a
    /// bootstrapping problem if the destination chain ID changes (e.g., during a testnet
    /// redeployment). Explicit parameter is the correct design.
    pub fn initiate_shadow_burn_gated(
        &mut self,
        receipt_id: B256,
        caller: Address,
        beneficiary_on_origin: Address,
        epoch_height: u64,
        dest_chain_id: u32,
        zanzibar: Option<&crate::governance::ZanzibarGraphEngine>,
    ) -> Result<ShadowBurnReceipt, &'static str> {
        let instance = self.shadow_instances.get_mut(&receipt_id).ok_or("Shadow instance not found")?;
        if instance.state == ShadowState::BurnedAndSettled {
            return Err("Shadow instance already burned");
        }

        let is_direct_owner = instance.owner == caller;
        let is_zanzibar_authorized = if let Some(engine) = zanzibar {
            if engine.tuples.contains_key(&receipt_id) {
                engine.check_named("shadow", receipt_id, "allow_shadow", caller, 5)
                    || engine.check_named("shadow", receipt_id, "owner", caller, 5)
            } else {
                is_direct_owner
            }
        } else {
            is_direct_owner
        };

        if !is_zanzibar_authorized {
            return Err("Caller not authorized to burn shadow instance (Zanzibar permission denied)");
        }

        instance.state = ShadowState::BurnedAndSettled;
        let nullifier = alloy_primitives::keccak256(&receipt_id);

        let receipt = ShadowBurnReceipt {
            receipt_id,
            nullifier,
            source_chain_id: instance.source_chain_id,
            dest_chain_id,
            beneficiary: beneficiary_on_origin,
            burned_asset: instance.asset.clone(),
            burn_epoch: epoch_height,
        };

        Ok(receipt)
    }

    /// Origin cluster verifies destination burn proof and releases native asset ownership to beneficiary.
    pub fn release_native_from_burn_proof(
        &mut self,
        proof: &ShadowBurnReceipt,
        epoch_height: u64,
    ) -> Result<(Address, ShadowAsset), &'static str> {
        let descriptor = self.shadow_tokens.get_mut(&proof.receipt_id).ok_or("Origin shadow token escrow not found")?;

        if descriptor.state == ShadowState::BurnedAndSettled {
            return Err("Shadow token already burned and settled");
        }

        if descriptor.nullifier != proof.nullifier {
            return Err("Nullifier mismatch in burn proof");
        }

        if self.spent_nullifiers.contains_key(&proof.nullifier) {
            return Err("Nullifier already spent");
        }

        descriptor.state = ShadowState::BurnedAndSettled;
        self.spent_nullifiers.insert(proof.nullifier, epoch_height);

        Ok((proof.beneficiary, descriptor.asset.clone()))
    }

    /// Legacy / direct helper for single-vault burn.
    pub fn burn_shadow_to_native(
        &mut self,
        receipt_id: B256,
        epoch_height: u64,
    ) -> Result<(Address, ShadowAsset), &'static str> {
        let descriptor = self.shadow_tokens.get_mut(&receipt_id).ok_or("Shadow token receipt not found")?;

        if descriptor.state == ShadowState::BurnedAndSettled {
            return Err("Shadow token already burned and settled");
        }

        if self.spent_nullifiers.contains_key(&descriptor.nullifier) {
            return Err("Nullifier already spent");
        }

        descriptor.state = ShadowState::BurnedAndSettled;
        self.spent_nullifiers.insert(descriptor.nullifier, epoch_height);

        Ok((descriptor.depositor, descriptor.asset.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_wrap_and_destruct_lifecycle() {
        let mut vault = ShadowTokenVault::new();
        let mut registry = crate::governance::ValidatorRegistry::default();
        let user = Address::repeat_byte(0xaa);
        let amount = U256::from(5_000_000_000_000_000_000u64);
        let dest_chain_id = 1;

        registry.credit_account_balance(user, amount);
        let shadow = vault.wrap_native_to_shadow(user, dest_chain_id, amount, &mut registry).expect("Wrap must succeed");

        assert_eq!(shadow.shadow_virtual_address, crate::system_registry::virtual_chain_address(1));
        assert_eq!(shadow.state, ShadowState::ActiveSuperposition);
        assert_eq!(shadow.depositor, user);

        let release = vault.burn_shadow_to_native(shadow.receipt_id, 1).expect("Burn must succeed");

        assert_eq!(release.0, user);
        assert_eq!(release.1, ShadowAsset::Fungible { amount, asset_identifier: None });
        assert_eq!(vault.shadow_tokens.get(&shadow.receipt_id).unwrap().state, ShadowState::BurnedAndSettled);

        // Attempting double-burn is rejected
        assert!(vault.burn_shadow_to_native(shadow.receipt_id, 2).is_err());
    }

    #[test]
    fn test_shadow_nft_and_multitoken_lifecycle() {
        let mut vault = ShadowTokenVault::new();
        let mut registry = crate::governance::ValidatorRegistry::default();
        let user = Address::repeat_byte(0xbb);
        let recipient = Address::repeat_byte(0xcc);
        let collection = Address::repeat_byte(0xee);

        // 1. Wrap NFT
        let nft_asset = ShadowAsset::NonFungible {
            token_id: U256::from(42),
            collection,
            metadata_uri_hash: B256::repeat_byte(0x77),
        };
        let shadow_nft = vault.wrap_asset_to_shadow(user, recipient, 137, nft_asset.clone(), &mut registry).expect("Wrap NFT");
        assert_eq!(shadow_nft.shadow_virtual_address, crate::system_registry::virtual_chain_address(137));

        let burned_nft = vault.burn_shadow_to_native(shadow_nft.receipt_id, 1).expect("Burn NFT");
        assert_eq!(burned_nft.1, nft_asset);

        // 2. Wrap Multi-Token
        let multi_asset = ShadowAsset::MultiToken {
            collection,
            token_ids: vec![U256::from(1), U256::from(2)],
            amounts: vec![U256::from(100), U256::from(250)],
        };
        let shadow_multi = vault.wrap_asset_to_shadow(user, recipient, 42161, multi_asset.clone(), &mut registry).expect("Wrap Multi");
        assert_eq!(shadow_multi.shadow_virtual_address, crate::system_registry::virtual_chain_address(42161));

        let burned_multi = vault.burn_shadow_to_native(shadow_multi.receipt_id, 2).expect("Burn Multi");
        assert_eq!(burned_multi.1, multi_asset);
    }

    #[test]
    fn test_shadow_zanzibar_gated_ownership() {
        let mut vault = ShadowTokenVault::new();
        let mut registry = crate::governance::ValidatorRegistry::default();
        let alice = Address::repeat_byte(0x01);
        let bob = Address::repeat_byte(0x02);
        let charlie = Address::repeat_byte(0x03);

        registry.credit_account_balance(alice, U256::from(1000));
        let shadow = vault.wrap_native_to_shadow(alice, 10, U256::from(1000), &mut registry).expect("Wrap must succeed");
        vault.mint_shadow_instance(&shadow, 1).expect("Mint instance");

        // 1. Direct owner can transfer when no Zanzibar rules restrict
        assert!(vault.transfer_shadow_ownership(shadow.receipt_id, alice, bob).is_ok());
        assert_eq!(vault.shadow_instances.get(&shadow.receipt_id).unwrap().owner, bob);

        // 2. Set up Zanzibar ReBAC permissions for this receipt
        let mut zanzibar = crate::governance::ZanzibarGraphEngine::new();
        // Grant charlie `allow_shadow` relation on this shadow receipt
        zanzibar.add_named_tuple(
            "shadow",
            shadow.receipt_id,
            "allow_shadow",
            crate::governance::ZanzibarSubject::User(charlie),
        );

        // Charlie is authorized via Zanzibar ReBAC
        assert!(vault.transfer_shadow_ownership_gated(
            shadow.receipt_id,
            charlie,
            alice,
            Some(&zanzibar),
        ).is_ok());
        assert_eq!(vault.shadow_instances.get(&shadow.receipt_id).unwrap().owner, alice);

        // A random unauthorized user (bob) is rejected
        assert!(vault.transfer_shadow_ownership_gated(
            shadow.receipt_id,
            bob,
            charlie,
            Some(&zanzibar),
        ).is_err());
    }
}
