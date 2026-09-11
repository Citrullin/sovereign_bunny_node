# Based Witness Mesh & Virtual Chain Addressing

## 1. Overview

The **Based Witness Mesh** enables universal cross-chain composability across distinct blockchain ecosystems (Ethereum, Base, Gnosis, Arbitrum, Mina, Solana) without centralized lock-and-mint bridge honeypots or stateful multi-chain indexers.

---

## 2. Virtual Chain Address Space

The address space is **symmetric and bidirectional**. Each chain (both external monolithic chains and other sovereign-reth instances) gets two well-known low-entropy addresses:

$$\text{Outbound: } [0\text{x}00 \dots 00] \parallel [0\text{x}01] \parallel [\text{ChainID}_{\text{u32}}]$$
$$\text{Inbound:  } [0\text{x}00 \dots 00] \parallel [0\text{x}02] \parallel [\text{ChainID}_{\text{u32}}]$$

| Prefix | Direction | Purpose |
|---|---|---|
| `0x01` | **Outbound** | You call this address to send to that chain. Acts as the virtual account chain / shadow oracle for the target's head. |
| `0x02` | **Inbound** | Other chains post cross-chain blobs **to** this address to reach you. This is the receiving channel. |

### Registered Chains (Outbound `0x01` Space)

| Target Network | ChainID | Outbound Call Address |
|---|---|---|
| Ethereum Mainnet | 1 (`0x00000001`) | `0x00000000000000000000000100000001` |
| Base | 8453 (`0x00002105`) | `0x00000000000000000000000100002105` |
| Gnosis | 100 (`0x00000064`) | `0x00000000000000000000000100000064` |
| Local Anvil / Toy | 31337 (`0x00007a69`) | `0x00000000000000000000000100007a69` |

### This Chain's Inbound Channel (`0x02` Space)

Every sovereign-reth instance has its own chain ID and thus its own well-known inbound channel address. Other chains (sovereign or monolithic) post cross-chain blobs to this address:

```
0x00000000000000000000000200{OUR_CHAIN_ID}   ← inbound channel for this instance
```

The account chain at this address acts as the **virtual block history** of this sovereign chain from the outside world's perspective. Each epoch snapshot is posted here as a `VirtualBlock` — making the sovereign system look like a sequential block-producing chain to any monolithic consumer. Underneath, the data is ephemeral:

| Phase | Data Available | Duration |
|---|---|---|
| **Active (hot)** | Full blob: account states, hot data, witness roots | Configurable (default: ~2 days) |
| **Pruned** | Blob removed from consensus nodes; IPFS pin attempted by `ArchivalDaemon` | After hot window expires |
| **Archived** | Raw data available only from IPFS pinners (voluntary) | Indefinite, no guarantee |
| **Hash-only** | Only `EpochSnapshotRoot` hash chain remains on-chain | Permanent |

> [!NOTE]
> The blob retention window is **not** the 18-day L1 Ethereum blob expiry — that constraint belongs to Ethereum's protocol. The sovereign system's blob retention is independently configurable (`das.blob_retention_epochs`). Default target is ~2 days of network epoch ticks, reflecting the expected window for any receiver to catch up and process inbound messages.

**If the blob is pruned before a receiver processes it:** The receiver can request it from IPFS (if pinned) or from any archival node that chose to retain it. If nobody pinned it, only the `EpochSnapshotRoot` hash is available — sufficient to prove historical validity via SNARK over the KZG commitment, but the raw account data is gone. This is by design: nodes are not required to be full historical archives.


### Developer Experience

Smart contracts invoke cross-chain interactions as standard EVM `CALL` opcodes targeting the virtual chain address:
```solidity
// Calling Ethereum Mainnet contract directly from Sovereign Reth
address constant ETH_MAINNET = 0x00000000000000000000000100000001;
(bool success, bytes memory returnData) = ETH_MAINNET.call(payload);
```
- The invocation never blocks the calling contract.
- It returns an asynchronous **`OutboxIntentReceipt`** promise handle.
- The intent enters the `SuperpositionIndex`.

### Sovereign-to-Sovereign Channel

When the mesh partner is another sovereign-reth instance, we post **epoch snapshots as blocks** to the outbound `0x01` virtual address account chain. From the perspective of any external system — monolithic or sovereign — this looks like a normal block-producing chain: each epoch snapshot = one block on the virtual account chain. This is intentional: it makes the sovereign system composable with any EVM contract or relay that expects a chain to produce sequential blocks.

**What we actually post as a "block":**
```
VirtualBlock {
    block_number:  epoch_height,           // epoch height IS the block number
    state_root:    EpochSnapshotRoot_e,    // Chandy-Lamport frontier cut root
    prev_root:     EpochSnapshotRoot_{e-1},
    bls_signature: ThresholdEpochMarker_e, // (2f+1) committee co-signature
}
```

This means any other sovereign-reth instance (or external chain) can verify our "blocks" by checking the BLS threshold signature on the epoch snapshot — no PoW, no PoS stake lookup, just the committee signature.

#### Inbound Validity: Account Witness, Not Global State Root

This is the critical difference from monolithic chains:

> The epoch snapshot reference in an incoming cross-chain message can be arbitrarily stale.  
> **What matters is the account-level witness proof against the account's current frontier head.**

- The epoch can be 10 snapshots behind. That's fine.
- If the **specific account** being touched has not advanced its frontier since the witness was constructed, the witness is still valid.
- If the account frontier HAS advanced (someone sent a new block on that account chain), the witness is stale — reject.

This check happens at **pre-flight validation**, before the intent even enters the account's local mempool:

```
Incoming cross-chain intent (source: sovereign-reth instance B):
  1. Deserialize intent: { account_address, witness_proof, payload, epoch_ref }
  2. PRE-FLIGHT (before mempool):
       current_head = account_chain[account_address].frontier_head
       if witness_proof.verify(current_head) == Valid:
           → accept into local mempool
       else:
           → reject with InboundIntentRejected::StaleAccountWitness
             (caller must rebuild witness against current frontier)
  3. Epoch reference check is NOT performed. Irrelevant.
```

| Property | Monolithic (Ethereum) | Sovereign-to-Sovereign |
|---|---|---|
| Validity unit | Global state root per block | Per-account frontier head |
| Epoch/block reference stale? | Fatal — immediate invalidation | Irrelevant — ignored |
| Witness still valid if epoch stale? | No | Yes, if account head unchanged |
| Flush triggers | A (capacity), B (consensus), **C (block advance)** | A (capacity), B (consensus) only |
| "Block" we expose externally | N/A — we receive theirs | Epoch snapshot posted as `VirtualBlock` |
| Pre-flight rejection | Block hash mismatch | Account witness invalid against frontier |

---

## 3. Data Availability (DA) Aggregation & Ephemeral Buffers

```
[ Local Account Outbox Intents ]
   ├── Intent 1 (Dest: Chain A) ──┐
   ├── Intent 2 (Dest: Chain B) ──┼──► [ Cross-Chain Committee Aggregator ]
   └── Intent 3 (Dest: Chain A) ──┘                   │
                                                      ▼
                                       [ Compress into Single EIP-4844 Blob ]
                                       • Namespaced Merkle Tree (NMT) Slices
                                       • 48-byte KZG Commitment Posted to L1
                                                      │
                                  ┌───────────────────┴───────────────────┐
                                  ▼                                       ▼
                        [ Chain A Ingestion ]                   [ Chain B Ingestion ]
                        • Reads NMT Slice                       • Reads NMT Slice
                        • Verifies KZG Proof                    • Verifies KZG Proof
                        • Checks Nullifier SMT                  • Checks Nullifier SMT
```

### Epoch Snapshot Data Lifecycle

Epoch snapshots are reflected in the virtual address space (`0x01` / `0x02`) as sequential blocks, making the sovereign system appear monolithic to external observers. The underlying data follows a three-phase lifecycle:

```
Epoch e closes (ThresholdEpochMarker)
  │
  ▼
[ PHASE 1: ACTIVE HOT (~2 days) ]
  Blob stored on consensus nodes.
  Full data queryable: account frontiers, hot state, witness roots.
  Virtual block posted at 0x02{OUR_CHAIN_ID}: epoch_height=e, state_root=EpochSnapshotRoot_e
  Any client or cross-chain receiver can fetch and verify.
  │
  ▼
[ PHASE 2: PRUNED ]
  Blob removed from consensus nodes (after das.blob_retention_epochs).
  ArchivalDaemon attempts IPFS pin before pruning.
  Only the KZG commitment (48 bytes) is retained locally.
  If a receiver missed it → request from IPFS or archival nodes.
  │
  ▼  (if IPFS pin exists)          (if no IPFS pin)
  ▼                                 ▼
[ ARCHIVED ]                  [ HASH-ONLY ]
Raw data available             Only EpochSnapshotRoot hash remains.
from IPFS pinners.             Historical validity provable via
No node obligation             SNARK over KZG commitment.
to serve it.                   Raw account data: gone. Too bad.
```

- **Who pins to IPFS?** Voluntary — validators, archival services, or users who care about historical access. There is no protocol obligation.
- **What remains permanently?** The `EpochSnapshotRoot` hash chain (one hash per epoch). This is sufficient to prove that a given account state was valid at epoch `e` via a ZK proof over the KZG commitment.
- **Hot data retention is short by design.** Nodes are not full historical archives. The stateless model means only frontier state is needed for liveness — history is an opt-in archival concern.


---

## 4. Double-Spend Prevention: Nullifier SMT

To prevent an adversary from replaying valid cross-chain witness proofs, each destination network maintains a `NullifierSmt`:
1. When submitting an intent for ingestion, the relayer supplies an **SMT non-membership proof** showing:
   $$\text{Poseidon}(\text{IntentID}) \notin \text{NullifierSmt}$$
2. Upon verified execution, the intent ID is inserted into the `NullifierSmt`.
3. Subsequent replay attempts are rejected in $O(1)$ without stateful contract lookups.

---

## 5. Flush Window Actor: Batch Closing & Throughput Amplification

### The Problem

Calling into the Based Mesh emits an `OutboxIntentReceipt` that enters `SuperpositionIndex`. But a blob slot has to be **claimed** at some point — there is a cost to committing, and committing one intent per blob is maximally wasteful. You need a mechanism that:

1. **Accumulates** cross-chain intents (or intra-chain state changes) into a staging buffer
2. **Closes** the buffer at the right moment and commits them atomically as a batch
3. **Generalizes** across the whole system — not just cross-chain, but any actor that benefits from deferred batch execution

### The Pattern: Flush Window Actor

This is a well-established pattern in actor systems:

| System | Pattern Name |
|---|---|
| Erlang/OTP | `gen_server` with `handle_cast` accumulation + `handle_info({timeout})` flush |
| Akka | `Stash + TimerScheduler`, or `Flow.groupedWithin(n, duration)` |
| Kafka Producer | `linger.ms` + `batch.size` — flush on capacity or time |
| Database WAL | **Group Commit** — accumulate writes, fsync once |

In our system, the **`SagaActor` state machine is extended** with a new actor type: the **`FlushWindowActor`**.

### Closing Conditions (Three Triggers)

```
FlushWindowActor buffer accumulates OutboxIntentReceipts.
                │
                ├── Trigger A: Capacity
                │     Buffer would overflow EIP-4844 blob capacity (> 126,976 usable bytes).
                │     → Close immediately, commit current batch, open new window for overflow.
                │
                ├── Trigger B: Explicit Consensus Close
                │     CrossChainRelayCommittee reaches quorum agreement to close this window
                │     (e.g. intentional forced flush, governance action, or liveness recovery).
                │     → Close and commit immediately upon threshold BLS signature.
                │
                └── Trigger C: Target Chain Head Advancement  ← THE HARD DEADLINE
                      The target chain (e.g. Ethereum) produced a new block.
                      ALL witness proofs anchored to the previous state root are now INVALID.
                      → Force-close immediately: commit or abandon. No epoch grace period.
```

> [!CAUTION]
> Trigger C is not optional for monolithic global-state chains. Ethereum, Base, Gnosis etc.
> have a single global state root per block. A witness proof is only valid against one
> specific state root. Once the target chain advances, you cannot commit — the proof is stale.
> The closing window MUST fire before the target chain's next block, not at some internal
> epoch boundary.

Trigger C fires by observing **shadow blocks** on the target chain's virtual account chain (see §5.1 below).

### 5.1 Virtual Chain Shadow Blocks (The Trigger C Mechanism)

Each virtual chain address (e.g. `0x00...0100000001` for Ethereum Mainnet) is **not just a routing label** — it is a real account chain in the lattice. The `CrossChainRelayCommittee` maintains it by producing new blocks on that account chain every time they reach consensus on the target chain advancing:

```
CrossChainRelayCommittee monitors Ethereum via the based mesh relay.

  Ethereum block N finalized:
    Committee runs BFT agreement: "Ethereum head is now block N, state root S_N"
    On (2f+1) threshold BLS signature:
      → Produce new BLOCK on virtual account 0x00...0100000001
        Block payload: { block_number: N, state_root: S_N, timestamp: T_N }
      → All FlushWindowActors targeting Ethereum observe this new block:
          if actor.staged[*].witness_anchored_at < N:
            → Trigger C: force-close, commit (if witness still valid) or abort
```

This means the virtual chain account IS the canonical oracle for the target chain's head within the sovereign system. Any contract or actor can read the latest block on `0x00...01CHAINID` to know the current valid state root for witness construction.

**Consequence for witness construction:**
Before staging an intent into a `FlushWindowActor`, the sender must:
1. Read the current shadow block head on the virtual chain account
2. Construct the witness proof anchored to that state root
3. Stage the intent, recording `witness_anchored_at = shadow_block.block_number`

If a new shadow block arrives before the flush commits, the committee checks: is the proof still valid against the new state root? If the transition was non-conflicting (account state unchanged), the proof can be forwarded. Otherwise the intent is aborted and the sender must rebuild.

### Generalization: Not Just Cross-Chain

The same `FlushWindowActor` pattern applies identically to:

| Use Case | What Accumulates | What Commits |
|---|---|---|
| Cross-chain outbox | `OutboxIntentReceipt` → target chain | EIP-4844 blob + `BatchAttestation` |
| Intra-chain contract state | State mutation intents from multiple callers | Single atomic revm execution pass |
| TinyMeritRank epoch submission | Per-agent PageRank vector deltas | Epoch Merkle root commitment |
| Contribution evaluation | Stage 2 deliberation round scores | `CommitContributionScore` SystemAction |
| Jurisdiction compliance delta | Account add/remove from enforcement set | `EpochHoldGuard` delta commit |

Contracts that are not fully async can still benefit: instead of executing each call immediately, they register a **deferred state mutation** into the window actor's inbox. When the window closes, all mutations execute together in one atomic pass — significantly higher throughput at the cost of one epoch of latency.

### Struct Design

```rust
/// A window-based batch aggregator actor.
/// Accumulates payloads and flushes atomically on capacity or epoch close.
pub struct FlushWindowActor {
    /// Unique actor / window ID.
    pub actor_id: B256,
    /// Target destination (chain virtual address, contract address, or system precompile).
    pub destination: Address,
    /// Staged payloads awaiting flush.
    pub staged: Vec<StagedIntent>,
    /// Epoch height at which this window closes (set when first intent arrives).
    pub close_at_epoch: u64,
    /// Current byte occupancy of staged payloads (against EIP-4844 blob capacity).
    pub staged_bytes: usize,
    /// Whether the window has been closed and committed.
    pub state: FlushWindowState,
}

pub enum FlushWindowState {
    /// Accepting new intents.
    Open,
    /// Window closed; batch committed to blob/DA. Awaiting execution confirmation.
    Committed { batch_id: B256 },
    /// Execution confirmed on destination; receipts deliverable.
    Settled,
    /// Timeout or commit failure; intents returned via SuperpositionReclaimer.
    Aborted,
}

pub struct StagedIntent {
    pub intent_id: B256,
    pub sender: Address,
    pub payload: Vec<u8>,
    pub arrived_at_epoch: u64,
    /// Shadow block number on the target chain's virtual account at time of staging.
    /// If the virtual chain account advances past this, this intent's witness is stale.
    pub witness_anchored_at: u64,
}
```

### Flush Algorithm

```
On new intent arriving at FlushWindowActor(window_id, destination):
  1. If state != Open  → reject (return OutboxIntentReceipt::Rejected)
  2. If staged_bytes + intent.payload.len() > BLOB_CAPACITY:
     → flush immediately (Trigger A)
     → create new window for this intent
  3. Append to staged[], update staged_bytes
  4. If staged.len() == 1: set close_at_epoch = current_epoch + window_epochs

On ThresholdEpochMarker received at epoch E:
  For each Open FlushWindowActor where close_at_epoch <= E:
    → flush (Trigger B): pack NMT blob, compute KZG, post BatchAttestation
    → transition to Committed { batch_id }

On BatchAttestation confirmed by CrossChainRelayCommittee:
  → transition to Settled
  → deliver OutboxIntentReceipt::Settled to each sender's account frontier

On timeout (close_at_epoch + timeout_window_epochs exceeded, still not Settled):
  → transition to Aborted
  → SuperpositionReclaimer returns all staged intents to senders
```

### System Address

```rust
/// Hook for registering a FlushWindowActor or submitting an intent to an open window.
/// Address: 0x00...0B
pub const SYSTEM_FLUSH_WINDOW: Address =
    address!("000000000000000000000000000000000000000b");
```

### Config

Add to `StaticConfig`:

```rust
pub struct BatchConfig {
    /// Default window size in network epoch heights before auto-flush.
    /// Default: 1 (flush at next epoch marker after first intent arrives).
    pub window_epochs: u64,
    /// Maximum payload bytes before capacity-triggered flush (< 126,976).
    /// Default: 110_000 (leaving headroom for NMT namespace headers).
    pub max_batch_bytes: usize,
    /// Epochs after close_at_epoch before window is aborted and intents reclaimed.
    pub abort_timeout_epochs: u64,
}
```

