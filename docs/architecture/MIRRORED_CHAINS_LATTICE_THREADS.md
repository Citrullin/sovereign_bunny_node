# Mirrored Blockchains as Virtual Account Threads on the Account-Lattice

## 1. Overview & Architectural Philosophy

By treating external blockchains as **Virtual Account Threads** on the Account-Lattice, the consensus engine (Multi-Paxos + Snowman) processes alien chains using the exact same **Send/Receive block primitives** as native user accounts.

To the sub-committee partition, a mirrored foreign blockchain is just an account advancing its state tip from $H_t \to H_{t+1}$. Underneath, the stateless transition function evaluates a zero-knowledge light-client proof (e.g. Noir UltraHonk) over the foreign chain's consensus.

```
                    [ ALIEN BLOCKCHAIN (e.g. Ethereum L1) ]
                     • Blocks, State Roots, Casper Sync Committees
                                       │
                                       │ 1. Relayer pushes Block Header + ZK Light-Client Proof
                                       ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │           MIRRORED ACCOUNT ON LATTICE (e.g., 0x000...0001)                  │
 │                                                                             │
 │  • Current Chain Tip: H_t  (Committed Foreign Block #20,500,100)            │
 │  • State Transition:  ReceiveBlock(Header_20500101, ZkSyncCommitteeProof)   │
 │  • Execution Engine:  Evaluates Noir light-client circuit                   │
 │  • New Chain Tip:     H_t+1 (Committed Foreign Block #20,500,101)           │
 └─────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       │ 2. Paxos sub-committee witnesses transition in RAM
                                       ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                       ACCOUNT-LATTICE GLOBAL FRONTIER                       │
 │  • Mirrored state root included in global Chandy-Lamport Epoch Cut          │
 │  • Native smart contracts / Wasm actors read alien state via O(1) SMT proofs│
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Dual-Ledger Mapping: Send and Receive Blocks

Every mirrored blockchain is assigned a deterministic, low-entropy virtual address (e.g. `0x0000000000000000000000000000000000000001` or `0x00..0100000001` for Ethereum Mainnet, `0x00..0100000002` for Bitcoin, `0x00..0100001068` for Base).

### A. Receive Blocks (Inbound State Synchronization)
- **Input**: Foreign block header, state root, and threshold validator signatures (e.g., Casper Altair sync committee BLS signature or Bitcoin PoW chainwork proof).
- **Transition Rule**: The execution daemon (`bunny-committee`) verifies the ZK light-client proof in RAM against the account's existing $H_t$ state root. If valid, the state tip updates to $H_{t+1}$.
- **Result**: Local smart contracts, Wasm actors, and decentralized CMS pods can immediately execute against verified foreign state (e.g., verifying an ERC-20 deposit on L1) without trusting an external multi-sig or centralized bridge relay.

### B. Send Blocks (Outbound Cross-Chain Intents)
- **Input**: A local user or contract initiates a cross-chain transfer or Saga intent targeting the foreign chain.
- **Transition Rule**: The virtual account emits a `SendBlock`, locking or burning the asset and generating a `ShadowTokenDescriptor`.
- **Result**: `bunny-mesh` reads the intent from the Apache Iggy bus, batches it into an EIP-4844 DA blob or L1 transaction, and submits it to the foreign network.

---

## 3. Native Account vs. Mirrored Blockchain Account

| Dimension | Native Lattice Account (`0x8f3c...`) | Mirrored Foreign Chain Account (`0x000...0001`) |
|---|---|---|
| **Identity** | User BIP-44 key pair / zkOIDC ephemeral DID | Canonical Chain ID + Genesis Fork Digest (`CanonicalChainID`) |
| **Chain Tip ($H_t$)** | User account nonce, balance, and code hash | Foreign block height, state root, and sync committee root |
| **Transition Predicate** | ECDSA / Ed25519 signature + balance check | Noir ZK Light-Client Circuit (Casper / PoW verification) |
| **Execution Workload** | $O(1)$ EVM state update in stateless Revm | $O(1)$ UltraHonk light-client proof verification |
| **Reorg Handling** | Strict non-reorgable deterministic Paxos rounds | Fork-choice tip tracking within the account thread |

---

## 4. Reorg Isolation & Consensus Decoupling

If Ethereum L1 undergoes a deep reorg or halts finality, the local Paxos sub-committee and the Sovereign Account-Lattice **never halt**:

1. **Thread-Level Isolation**: The reorg is contained entirely within the state history of address `0x00...0001`. Native account partitions continue processing local transactions at line-rate.
2. **Optimistic vs. Finalized Tips**:
   - $H_{\text{finalized}}$: The last L1 block backed by full $2/3$ Casper finality proofs.
   - $H_{\text{optimistic}}$: The latest unfinalized L1 head (for fast, speculative local reads).
3. **Deterministic Reorg Resolution**: If a foreign reorg occurs, the relayer submits a `ReorgProof` container. The virtual account thread unrolls only its own unfinalized optimistic tips back to the common ancestor block without affecting any other account on the lattice.

---

## 5. Sub-Microsecond Local Reads for DApps and CMS

Because the mirrored blockchain is an ordinary account thread on the lattice, local Wasm actors, Mastodon pods, and decentralized e-commerce shops verify foreign events statelessly in sub-microseconds without making external JSON-RPC or Infura calls:

```rust
/// In-memory verification inside a local Wasm actor / CMS shop
pub fn verify_l1_payment(
    l1_tx_receipt_proof: SszReceiptProof,
    mirrored_chain_address: [u8; 20], // 0x000...0001
) -> bool {
    // 1. Fetch the latest verified L1 state root from the local lattice cache
    let l1_state_root = Lattice::get_account_tip(mirrored_chain_address).state_root;

    // 2. Statistically verify that the transaction receipt exists in that root
    // Zero RPC calls, zero external Infura queries, sub-microsecond latency
    verify_merkle_patricia_proof(l1_tx_receipt_proof, l1_state_root)
}
```
