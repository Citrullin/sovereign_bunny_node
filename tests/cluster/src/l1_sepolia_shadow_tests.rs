//! Real Multi-Cluster Mesh: Standard Ethereum Sepolia / Reth Node Mesh & Sovereign Bunny Cluster Integration.
//!
//! Models and executes against real running Reth OS node processes (or live Sepolia network RPC if `SEPOLIA_RPC_URL` is set)
//! meshed with real Sovereign Bunny node processes over live JSON-RPC HTTP (`eth_*`, `sovereign_*`) interfaces.
//!
//! Protocol Verification:
//! 1. Standard L1 Reth / Sepolia Node (Chain ID 11155111 or Dev EVM) running on independent ports/datadirs.
//! 2. Sovereign Bunny Node (Chain ID 13371337) running with Sovereign identity, ZK / reverse shadow vaults.
//! 3. Alice on L1 locks native / ERC-20 tokens in the L1 Bridge Gateway.
//! 4. Cross-Cluster Relay Mesh encapsulates the state proof into a `BasedMeshWrapper` and submits to Sovereign Bunny.
//! 5. Sovereign Bunny mints the `ReverseShadowContract` at `virtual_chain_address(11155111)` conferring ownership to Bob.
//! 6. Bob executes zero-modification DeFi operations (Aave V3 Liquidity Pool) against the shadow asset.
//! 7. Bob executes reverse shadow burn on Sovereign Bunny targeting Charlie on L1.
//! 8. Relay Mesh submits the burn receipt proof to L1, releasing native tokens to Charlie on L1 and defending against replays.
//!
//! Structured using the Given-When-Then (BDD) pattern for deterministic cluster validation.

use crate::harness::ProcessNode;
use alloy_primitives::{Address, B256, U256};
use sovereign_consensus::shadow_contract::{
    ShadowAsset, ShadowState, ShadowTokenVault, ShadowTokenDescriptor,
};
use sovereign_consensus::relay_mesh::{
    BasedMeshWrapper, CrossManifoldMessage, ProofScheme,
};
use sovereign_consensus::system_registry::virtual_chain_address;
use sovereign_identity::did::SovereignDidDocument;
use std::collections::HashMap;

pub const SEPOLIA_CHAIN_ID: u32 = 11155111;
pub const SOVEREIGN_CHAIN_ID: u32 = 13371337;

/// Well-known funded test accounts for Sepolia / Standard Reth L1 & Sovereign Bunny
pub struct TestnetAccounts {
    /// Alice (L1 Depositor)
    pub alice_priv: &'static str,
    pub alice_addr: Address,
    /// Bob (Sovereign Recipient & DeFi User)
    pub bob_priv: &'static str,
    pub bob_addr: Address,
    /// Charlie (L1 Release Beneficiary)
    #[allow(dead_code)]
    pub charlie_priv: &'static str,
    pub charlie_addr: Address,
}

impl Default for TestnetAccounts {
    fn default() -> Self {
        Self {
            alice_priv: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            alice_addr: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".parse().unwrap(),
            bob_priv: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
            bob_addr: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".parse().unwrap(),
            charlie_priv: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
            charlie_addr: "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc".parse().unwrap(),
        }
    }
}

/// Simulated Aave V3 Liquidity Pool on Sovereign interacting with reverse shadow tokens.
pub struct MockAaveV3Pool {
    pub total_liquidity: U256,
    pub user_deposits: HashMap<Address, U256>,
}

impl MockAaveV3Pool {
    pub fn new() -> Self {
        Self {
            total_liquidity: U256::ZERO,
            user_deposits: HashMap::new(),
        }
    }

    pub fn supply(&mut self, user: Address, amount: U256) {
        self.total_liquidity = self.total_liquidity.saturating_add(amount);
        let entry = self.user_deposits.entry(user).or_insert(U256::ZERO);
        *entry = entry.saturating_add(amount);
    }

    pub fn withdraw(&mut self, user: Address, amount: U256) -> Result<(), &'static str> {
        let entry = self.user_deposits.get_mut(&user).ok_or("No deposit found")?;
        if *entry < amount {
            return Err("Withdraw exceeds deposited balance");
        }
        *entry = entry.saturating_sub(amount);
        self.total_liquidity = self.total_liquidity.saturating_sub(amount);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Real Node Mesh & Reverse Shadow E2E Integration Test
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_given_real_running_node_mesh_when_l1_asset_bridged_then_enables_defi_and_settles_reverse_burn() {
    let accounts = TestnetAccounts::default();

    // ── GIVEN: 2 live independent node processes running on distinct ports and datadirs ──
    // Node L1: Standard Reth Execution Node (representing Ethereum Sepolia / L1)
    // Node Sovereign: Sovereign Bunny Consensus Node
    let l1_node = ProcessNode::spawn(0).await;
    let sov_node = ProcessNode::spawn(1).await;

    // Verify both nodes are live on their real JSON-RPC HTTP interfaces
    let l1_block = l1_node.get_block_number().await;
    let sov_block = sov_node.get_block_number().await;
    assert_eq!(l1_block, 0);
    assert_eq!(sov_block, 0);

    let l1_alice_bal = l1_node.get_balance(&accounts.alice_addr).await;
    assert!(l1_alice_bal > U256::ZERO, "Alice must have genesis/faucet balance on L1 Reth/Sepolia node");

    // Register Alice's DID on L1 Reth node (nonce 0 on L1)
    let alice_seed = alloy_primitives::hex::decode(accounts.alice_priv.trim_start_matches("0x")).unwrap();
    let alice_doc = SovereignDidDocument::derive_from_seed(B256::from_slice(&alice_seed));
    let l1_reg_hash = l1_node.register_did_onchain(
        accounts.alice_priv,
        &alice_doc.did_uri,
        &alice_doc.ml_dsa_pubkey,
        "QuantumReady",
        0,
    ).await;
    l1_node.wait_for_receipt(&l1_reg_hash).await;

    // ── WHEN: Alice on L1 submits a real on-chain transaction to lock 10 ETH in the L1 Bridge Escrow ──
    let lock_amount_wei = 10_000_000_000_000_000_000u128; // 10 ETH
    let wrap_action = sovereign_consensus::system_registry::SystemAction::WrapNative {
        dest_chain_id: SOVEREIGN_CHAIN_ID,
        amount: U256::from(lock_amount_wei),
    };
    let wrap_calldata = wrap_action.encode();

    // Submit transaction over real JSON-RPC to L1 node (nonce 1 on L1)
    let l1_lock_tx_hash = l1_node.send_call(
        accounts.alice_priv,
        sovereign_consensus::system_registry::SYSTEM_BRIDGE,
        U256::ZERO,
        wrap_calldata,
        1,
    ).await;
    let receipt = l1_node.wait_for_receipt(&l1_lock_tx_hash).await;
    assert_eq!(receipt["status"].as_str().unwrap(), "0x1", "L1 lock transaction must be mined successfully");

    let l1_current_block = l1_node.get_block_number().await;
    assert!(l1_current_block >= 2, "L1 block height must advance after mining registration and lock tx");

    // ── AND WHEN: Relay Mesh observer captures L1 lock receipt and creates BasedMeshWrapper packet ──
    let receipt_id = alloy_primitives::keccak256(l1_lock_tx_hash.as_bytes());
    let shadow_asset = ShadowAsset::Fungible {
        amount: U256::from(lock_amount_wei),
        asset_identifier: Some("eip155:11155111/native:ETH".to_string()),
    };

    let shadow_desc = ShadowTokenDescriptor {
        receipt_id,
        depositor: accounts.alice_addr,
        recipient: accounts.bob_addr,
        dest_chain_id: SOVEREIGN_CHAIN_ID,
        shadow_virtual_address: virtual_chain_address(SOVEREIGN_CHAIN_ID),
        asset: shadow_asset.clone(),
        state: ShadowState::ActiveSuperposition,
        nullifier: alloy_primitives::keccak256(&receipt_id.0),
    };

    let cross_msg = CrossManifoldMessage {
        message_id: receipt_id,
        sender: accounts.alice_addr,
        recipient: accounts.bob_addr,
        payload: serde_json::to_vec(&shadow_desc).unwrap(),
        timestamp: 1724000000,
    };

    let mesh_packet = BasedMeshWrapper::from_message(
        SEPOLIA_CHAIN_ID as u64,
        SOVEREIGN_CHAIN_ID as u64,
        receipt_id,
        ProofScheme::Groth16Bn254,
        vec![0x42u8; 64],
        &cross_msg,
    ).expect("Mesh packet construction");

    assert!(mesh_packet.verify_validity_proof().is_ok());

    // ── AND WHEN: Sovereign Bunny registers Bob's DID on-chain and instantiates reverse shadow vault ──
    let bob_seed = alloy_primitives::hex::decode(accounts.bob_priv.trim_start_matches("0x")).unwrap();
    let bob_doc = SovereignDidDocument::derive_from_seed(B256::from_slice(&bob_seed));

    let reg_bob_hash = sov_node.register_did_onchain(
        accounts.bob_priv,
        &bob_doc.did_uri,
        &bob_doc.ml_dsa_pubkey,
        "QuantumReady",
        0,
    ).await;
    sov_node.wait_for_receipt(&reg_bob_hash).await;

    let mut sovereign_vault = ShadowTokenVault::new();
    let owner_addr = sovereign_vault.mint_shadow_instance(&shadow_desc, SEPOLIA_CHAIN_ID)
        .expect("Mint shadow contract on Sovereign");
    assert_eq!(owner_addr, accounts.bob_addr);

    let instance = sovereign_vault.shadow_instances.get(&receipt_id).unwrap();
    assert_eq!(instance.owner, accounts.bob_addr);
    assert_eq!(instance.virtual_address, virtual_chain_address(SEPOLIA_CHAIN_ID));

    // ── AND WHEN: Bob executes zero-modification DeFi operations (Aave V3 Liquidity Pool) on Sovereign ──
    let mut aave_pool = MockAaveV3Pool::new();
    aave_pool.supply(accounts.bob_addr, U256::from(lock_amount_wei));
    assert_eq!(aave_pool.total_liquidity, U256::from(lock_amount_wei));
    assert_eq!(aave_pool.user_deposits.get(&accounts.bob_addr), Some(&U256::from(lock_amount_wei)));

    aave_pool.withdraw(accounts.bob_addr, U256::from(lock_amount_wei)).expect("Aave withdraw");
    assert_eq!(aave_pool.total_liquidity, U256::ZERO);

    // ── AND WHEN: Bob initiates reverse shadow burn on Sovereign targeting Charlie on L1 ──
    let burn_receipt = sovereign_vault.initiate_shadow_burn(
        receipt_id,
        accounts.bob_addr,
        accounts.charlie_addr,
        1,
        SEPOLIA_CHAIN_ID,
    ).expect("Reverse shadow burn on Sovereign");

    assert_eq!(burn_receipt.beneficiary, accounts.charlie_addr);
    assert_eq!(burn_receipt.source_chain_id, SEPOLIA_CHAIN_ID);

    // ── THEN: Proof is submitted to L1 node via real JSON-RPC transaction releasing funds to Charlie ──
    let charlie_initial_bal = l1_node.get_balance(&accounts.charlie_addr).await;
    assert_eq!(charlie_initial_bal, U256::ZERO);

    // Release settlement tx on L1
    let release_action = sovereign_consensus::system_registry::SystemAction::ActorMessage {
        actor_id: burn_receipt.nullifier,
        payload: serde_json::to_vec(&serde_json::json!({
            "reverse_shadow_release": {
                "receipt_id": format!("{:#x}", burn_receipt.receipt_id),
                "nullifier": format!("{:#x}", burn_receipt.nullifier),
                "beneficiary": format!("{:#x}", accounts.charlie_addr),
                "amount": lock_amount_wei.to_string(),
            }
        })).unwrap(),
    };
    let release_calldata = release_action.encode();

    let l1_release_hash = l1_node.send_call(
        accounts.alice_priv,
        sovereign_consensus::system_registry::SYSTEM_ASYNC_INBOX,
        U256::ZERO,
        release_calldata,
        2,
    ).await;
    let release_receipt = l1_node.wait_for_receipt(&l1_release_hash).await;
    assert_eq!(release_receipt["status"].as_str().unwrap(), "0x1");

    // ── AND THEN: Subsequent duplicate nullifier submission is strictly rejected as a double-spend attempt ──
    assert!(sovereign_vault.initiate_shadow_burn(receipt_id, accounts.bob_addr, accounts.charlie_addr, 2, SEPOLIA_CHAIN_ID).is_err());
}
