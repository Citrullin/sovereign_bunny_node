//! Cross-Cluster Multi-Manifold Reverse Shadow Contract Integration Test Suite.
//!
//! Structured using the Given-When-Then (BDD) pattern for cross-chain settlement verification.

use alloy_primitives::{Address, B256, U256};
use sovereign_consensus::shadow_contract::{
    ShadowAsset, ShadowState, ShadowTokenVault, ShadowTokenDescriptor, ShadowBurnReceipt,
};
use sovereign_consensus::system_registry::virtual_chain_address;
use std::collections::VecDeque;

#[allow(dead_code)]
pub struct CrossClusterMeshRelay {
    pub alpha_chain_id: u32,
    pub beta_chain_id: u32,
    pub alpha_to_beta_inbox: VecDeque<ShadowTokenDescriptor>,
    pub beta_to_alpha_inbox: VecDeque<(ShadowBurnReceipt, u64)>,
}

impl CrossClusterMeshRelay {
    pub fn new(alpha_chain_id: u32, beta_chain_id: u32) -> Self {
        Self {
            alpha_chain_id,
            beta_chain_id,
            alpha_to_beta_inbox: VecDeque::new(),
            beta_to_alpha_inbox: VecDeque::new(),
        }
    }

    pub fn relay_wrap_to_beta(&mut self, descriptor: ShadowTokenDescriptor) {
        self.alpha_to_beta_inbox.push_back(descriptor);
    }

    pub fn relay_burn_to_alpha(&mut self, receipt: ShadowBurnReceipt, burn_epoch: u64) {
        self.beta_to_alpha_inbox.push_back((receipt, burn_epoch));
    }
}

pub struct SovereignClusterState {
    pub chain_id: u32,
    pub current_epoch: u64,
    pub vault: ShadowTokenVault,
    pub registry: sovereign_consensus::governance::ValidatorRegistry,
    pub reorg_confirmation_depth: u64,
}

impl SovereignClusterState {
    pub fn new(chain_id: u32, reorg_depth: u64) -> Self {
        Self {
            chain_id,
            current_epoch: 1,
            vault: ShadowTokenVault::new(),
            registry: sovereign_consensus::governance::ValidatorRegistry::default(),
            reorg_confirmation_depth: reorg_depth,
        }
    }

    pub fn advance_epochs(&mut self, epochs: u64) {
        self.current_epoch += epochs;
    }
}

pub struct TwoClusterMeshHarness {
    pub cluster_alpha: SovereignClusterState,
    pub cluster_beta: SovereignClusterState,
    pub relay: CrossClusterMeshRelay,
}

impl TwoClusterMeshHarness {
    pub fn new() -> Self {
        let alpha_chain = 1337;
        let beta_chain = 4200;
        let reorg_depth = 3;
        Self {
            cluster_alpha: SovereignClusterState::new(alpha_chain, reorg_depth),
            cluster_beta: SovereignClusterState::new(beta_chain, reorg_depth),
            relay: CrossClusterMeshRelay::new(alpha_chain, beta_chain),
        }
    }

    pub fn pump_alpha_to_beta(&mut self) -> usize {
        let mut count = 0;
        while let Some(desc) = self.relay.alpha_to_beta_inbox.pop_front() {
            self.cluster_beta
                .vault
                .mint_shadow_instance(&desc, self.cluster_alpha.chain_id)
                .expect("Failed to mint shadow on Beta");
            count += 1;
        }
        count
    }

    pub fn pump_beta_to_alpha_with_reorg_check(&mut self) -> Result<Vec<(Address, ShadowAsset)>, String> {
        let mut released = Vec::new();
        let mut unready = VecDeque::new();

        while let Some((receipt, burn_epoch)) = self.relay.beta_to_alpha_inbox.pop_front() {
            let required_confirmation_epoch = burn_epoch + self.cluster_beta.reorg_confirmation_depth;
            if self.cluster_beta.current_epoch < required_confirmation_epoch {
                unready.push_back((receipt, burn_epoch));
                continue;
            }

            let release_result = self.cluster_alpha
                .vault
                .release_native_from_burn_proof(&receipt, self.cluster_alpha.current_epoch)?;

            released.push(release_result);
        }

        self.relay.beta_to_alpha_inbox = unready;
        Ok(released)
    }
}

#[test]
fn test_given_erc20_wrapped_on_alpha_when_transferred_and_burned_on_beta_then_releases_to_dan_on_alpha() {
    // ── GIVEN: Two meshed clusters (Alpha & Beta) and 50 native USDC tokens locked by Alice on Alpha ──
    let mut mesh = TwoClusterMeshHarness::new();
    let alice = Address::from([0xaa; 20]);
    let bob = Address::from([0xbb; 20]);
    let charlie = Address::from([0xcc; 20]);
    let dan = Address::from([0xdd; 20]);
    let amount = U256::from(50_000_000_000_000_000_000u128);

    let usdc_asset = ShadowAsset::Fungible {
        amount,
        asset_identifier: Some("eip155:1337/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string()),
    };

    // ── WHEN: Alice wraps the tokens targeting Bob on Beta, and Bob transfers shadow ownership to Charlie ──
    mesh.cluster_alpha.registry.credit_account_balance(alice, amount);
    let shadow_desc = mesh.cluster_alpha.vault.wrap_asset_to_shadow(
        alice,
        bob,
        mesh.cluster_beta.chain_id,
        usdc_asset.clone(),
        &mut mesh.cluster_alpha.registry,
    ).expect("Alice wrap on Cluster Alpha");

    assert_eq!(shadow_desc.shadow_virtual_address, virtual_chain_address(4200));
    assert_eq!(shadow_desc.state, ShadowState::ActiveSuperposition);

    mesh.relay.relay_wrap_to_beta(shadow_desc.clone());
    assert_eq!(mesh.pump_alpha_to_beta(), 1);

    let shadow_inst = mesh.cluster_beta.vault.shadow_instances.get(&shadow_desc.receipt_id).unwrap();
    assert_eq!(shadow_inst.owner, bob);
    assert_eq!(shadow_inst.virtual_address, virtual_chain_address(1337));

    mesh.cluster_beta.vault.transfer_shadow_ownership(shadow_desc.receipt_id, bob, charlie)
        .expect("Transfer on Beta to Charlie");
    assert_eq!(mesh.cluster_beta.vault.shadow_instances.get(&shadow_desc.receipt_id).unwrap().owner, charlie);

    // ── AND WHEN: Charlie initiates a reverse burn on Beta targeting Dan on Alpha ──
    let burn_receipt = mesh.cluster_beta.vault.initiate_shadow_burn(
        shadow_desc.receipt_id,
        charlie,
        dan,
        mesh.cluster_beta.current_epoch,
        mesh.cluster_alpha.chain_id,
    ).expect("Burn shadow on Beta");

    mesh.relay.relay_burn_to_alpha(burn_receipt.clone(), mesh.cluster_beta.current_epoch);

    // ── THEN: Premature release attempt before k=3 epochs is blocked by reorg protection ──
    let early_releases = mesh.pump_beta_to_alpha_with_reorg_check().expect("Reorg check");
    assert!(early_releases.is_empty(), "Release must not occur before $k$ epochs confirmation");

    // ── AND THEN: After advancing Beta by k=3 epochs, Alpha unlocks native assets to Dan ──
    mesh.cluster_beta.advance_epochs(3);
    let confirmed_releases = mesh.pump_beta_to_alpha_with_reorg_check().expect("Release after $k$ epochs");
    assert_eq!(confirmed_releases.len(), 1);
    assert_eq!(confirmed_releases[0].0, dan, "Native tokens must be released to Dan on Cluster Alpha");
    assert_eq!(confirmed_releases[0].1, usdc_asset);
}

#[test]
fn test_given_erc721_nft_wrapped_on_alpha_when_burned_on_beta_then_releases_to_patron_on_alpha() {
    // ── GIVEN: Creator locks NFT on Cluster Alpha targeting Collector on Beta ──
    let mut mesh = TwoClusterMeshHarness::new();
    let creator = Address::from([0x11; 20]);
    let collector = Address::from([0x22; 20]);
    let gallery = Address::from([0x33; 20]);
    let patron = Address::from([0x44; 20]);
    let nft_contract = Address::from([0x99; 20]);
    let token_id = U256::from(777);
    let metadata_hash = B256::repeat_byte(0xab);

    let nft_asset = ShadowAsset::NonFungible {
        token_id,
        collection: nft_contract,
        metadata_uri_hash: metadata_hash,
    };

    let shadow_nft = mesh.cluster_alpha.vault.wrap_asset_to_shadow(
        creator,
        collector,
        mesh.cluster_beta.chain_id,
        nft_asset.clone(),
        &mut mesh.cluster_alpha.registry,
    ).expect("Creator wrap NFT");

    mesh.relay.relay_wrap_to_beta(shadow_nft.clone());
    mesh.pump_alpha_to_beta();

    // ── WHEN: Collector transfers shadow NFT to Gallery, and Gallery burns targeting Patron ──
    mesh.cluster_beta.vault.transfer_shadow_ownership(shadow_nft.receipt_id, collector, gallery)
        .expect("Transfer NFT to Gallery on Beta");

    let burn_receipt = mesh.cluster_beta.vault.initiate_shadow_burn(
        shadow_nft.receipt_id,
        gallery,
        patron,
        mesh.cluster_beta.current_epoch,
        mesh.cluster_alpha.chain_id,
    ).expect("Gallery burn NFT on Beta");

    mesh.relay.relay_burn_to_alpha(burn_receipt, mesh.cluster_beta.current_epoch);
    mesh.cluster_beta.advance_epochs(3);

    // ── THEN: Alpha confirms burn proof and delivers physical NFT to Patron ──
    let releases = mesh.pump_beta_to_alpha_with_reorg_check().expect("Release NFT");
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].0, patron, "Native NFT must be owned by Patron on Alpha");
    assert_eq!(releases[0].1, nft_asset);
}

#[test]
fn test_given_erc1155_multitoken_batch_when_burned_on_beta_then_releases_batch_to_player() {
    // ── GIVEN: Game issuer wraps a multi-token inventory batch on Alpha ──
    let mut mesh = TwoClusterMeshHarness::new();
    let issuer = Address::from([0x55; 20]);
    let game_server = Address::from([0x66; 20]);
    let player = Address::from([0x77; 20]);
    let multi_contract = Address::from([0x88; 20]);

    let token_ids = vec![U256::from(1), U256::from(2), U256::from(3)];
    let amounts = vec![U256::from(100), U256::from(50), U256::from(1)];

    let batch_asset = ShadowAsset::MultiToken {
        collection: multi_contract,
        token_ids: token_ids.clone(),
        amounts: amounts.clone(),
    };

    let shadow_batch = mesh.cluster_alpha.vault.wrap_asset_to_shadow(
        issuer,
        game_server,
        mesh.cluster_beta.chain_id,
        batch_asset.clone(),
        &mut mesh.cluster_alpha.registry,
    ).expect("Wrap MultiToken batch");

    mesh.relay.relay_wrap_to_beta(shadow_batch.clone());
    mesh.pump_alpha_to_beta();

    // ── WHEN: Game server burns batch on Beta delivering items to Player on Alpha ──
    let burn_receipt = mesh.cluster_beta.vault.initiate_shadow_burn(
        shadow_batch.receipt_id,
        game_server,
        player,
        mesh.cluster_beta.current_epoch,
        mesh.cluster_alpha.chain_id,
    ).expect("Burn batch on Beta");

    mesh.relay.relay_burn_to_alpha(burn_receipt, mesh.cluster_beta.current_epoch);
    mesh.cluster_beta.advance_epochs(3);

    // ── THEN: Alpha releases the entire native multi-token batch to Player ──
    let releases = mesh.pump_beta_to_alpha_with_reorg_check().expect("Release batch");
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].0, player);
    assert_eq!(releases[0].1, batch_asset);
}

#[test]
fn test_given_settled_burn_receipt_when_replayed_then_replay_protection_strictly_rejects() {
    // ── GIVEN: A completed reverse shadow burn settlement ──
    let mut mesh = TwoClusterMeshHarness::new();
    let alice = Address::from([0xaa; 20]);
    let bob = Address::from([0xbb; 20]);

    let asset = ShadowAsset::Fungible {
        amount: U256::from(1000),
        asset_identifier: None,
    };

    mesh.cluster_alpha.registry.credit_account_balance(alice, U256::from(1000));
    let shadow = mesh.cluster_alpha.vault.wrap_asset_to_shadow(
        alice,
        bob,
        mesh.cluster_beta.chain_id,
        asset,
        &mut mesh.cluster_alpha.registry,
    ).expect("Wrap");

    mesh.relay.relay_wrap_to_beta(shadow.clone());
    mesh.pump_alpha_to_beta();

    let burn_receipt = mesh.cluster_beta.vault.initiate_shadow_burn(
        shadow.receipt_id,
        bob,
        alice,
        mesh.cluster_beta.current_epoch,
        mesh.cluster_alpha.chain_id,
    ).expect("Burn on Beta");

    // ── WHEN: Adversary attempts duplicate burn on Beta ──
    assert!(mesh.cluster_beta.vault.initiate_shadow_burn(shadow.receipt_id, bob, alice, 2, mesh.cluster_alpha.chain_id).is_err());

    mesh.cluster_beta.advance_epochs(3);
    let (released_to, _) = mesh.cluster_alpha.vault.release_native_from_burn_proof(
        &burn_receipt,
        mesh.cluster_alpha.current_epoch,
    ).expect("First release");
    assert_eq!(released_to, alice);

    // ── THEN: Subsequent duplicate release submission on Alpha is strictly rejected ──
    let replay_err = mesh.cluster_alpha.vault.release_native_from_burn_proof(
        &burn_receipt,
        mesh.cluster_alpha.current_epoch + 1,
    );
    assert!(replay_err.is_err());
    assert_eq!(replay_err.unwrap_err(), "Shadow token already burned and settled");
}
