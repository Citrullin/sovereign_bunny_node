# Account-Lattice & Byzantine Chandy-Lamport Epoch Finality

## 1. Git-Repository Federation Mental Model

In Sovereign Reth, the global ledger is not a single serialized sequence of global blocks. Instead, every individual account operates as an independent, asynchronous **Git-like commit thread**:

```
Alice's Account Thread:  [Commit 1] ──► [Commit 2] ──► [Tip / HEAD: H_A]
Bob's Account Thread:    [Commit 1] ──► [Commit 2] ──► [Tip / HEAD: H_B]
Charlie's Account:       [Commit 1] ──► [Commit 2] ──► [Tip / HEAD: H_C]
                                              │
                                              ▼
                         Stateless Validator Network:
                         Tracks ONLY the HEAD Commit Hashes
                         Anchored by Byzantine Chandy-Lamport Epoch Cuts
```

---

## 2. Stateless Account Frontiers

Each validator maintains a lightweight table of `AccountFrontier` structs:

```rust
pub struct AccountFrontier {
    /// Latest block/commit hash of this account's thread
    pub latest_hash: B256,
    /// Sequence height (nonce)
    pub sequence: u64,
    /// Lock status (e.g. while participating in a Saga escrow)
    pub locked: bool,
    pub locked_at: u64,
    pub paused_context: Option<Vec<u8>>,
    pub snapshot_size: usize,
    pub cached_compliance: Option<ComplianceVector>,
    pub merit_rank: MeritRank,
}
```

Validators do not store historical transaction bodies or contract storage tries. When an account submits block $N+1$, it includes a cryptographic witness proving its state transition against its previous commit $H_A$ and the current epoch state root.

---

## 3. Byzantine Chandy-Lamport: Pure Sovereign Clockless Finality

Sovereign Reth does **not** rely on external L1 clocks, beacon slots, or synchronized node wall clocks. In a pure asynchronous Account-Lattice, **the round-trip traversal of threshold-signed marker messages is the clock**.

```
[ GENESIS / BOOTSTRAP ]
• Configurable Seed Sub-Committee (C_0)
• Epoch Parameter Configuration (K rounds per committee)
                    │
                    ▼
[ STEP 1: INTRA-COMMITTEE LEADER & THRESHOLD MARKER ]
• Active Committee C_k elects an internal Leader (round-robin)
• Committee threshold-signs the Marker: Marker(e) = ThresholdSign_{C_k}(e || GlobalRoot_{e-1})
• Leader emits the targeted Marker to designated validator routes
                    │
                    ▼
[ STEP 2: LATTICE TRAVERSAL & CHANNEL RECORDING ]
• Marker propagates across account/channel frontiers
• Accounts freeze tip state (H_t) upon first seeing Marker
• In-flight messages recorded until Marker sweeps all incoming edges
                    │
                    ▼
[ STEP 3: SNAPSHOT CONVERGENCE & ACCUMULATION ]
• Marker loop completes across designated routing ring
• Local commitments aggregated into GlobalFrontierRoot_e via Poseidon-SMT
• Shared with peers who independently confirm the snapshot cut
                    │
                    ▼
[ STEP 4: INTRA-COMMITTEE ROTATION ]
• Next internal leader takes over within current committee C_k
• Repeats steps 1–3 until committee epoch budget (K rounds) expires
                    │
                    ▼
[ STEP 5: INTER-COMMITTEE DETERMINISTIC HANDOFF ]
• Next Seed derived: Seed_{k+1} = Hash(Seed_k || GlobalFrontierRoot_k)
• Next Committee sampled: C_{k+1} = Sample(ValidatorSet, Seed_{k+1}, Range_i)
• Authority transfers seamlessly across the validator ring (Go to Step 1)
```

---

## 4. Key Cryptographic Invariants

### 1. Targeted Addressing & Threshold Verification (Anti-DoS)
A rogue node cannot fabricate fake markers or cause split-brain freezes:
- An epoch marker is only valid if it carries a $(t, n)$ threshold BLS signature from the currently assigned sub-committee $C_k$:
  $$\text{Marker}(e) = \text{ThresholdSign}_{C_k}(e \parallel \text{GlobalFrontierRoot}_{e-1})$$
- The marker is addressed to specific validator routes along the account topology, preventing unbounded network flooding.

### 2. Self-Seeding Hash Chains (Zero External Oracles)
The entropy seed for subsequent committee rotations is generated deterministically from the completed snapshot root:
$$\text{Seed}_{k+1} = \text{Hash}(\text{Seed}_k \parallel \text{GlobalFrontierRoot}_k)$$
Every validator in the network computes the exact same committee assignment $C_{k+1}$ locally without passing a single vote or querying an external oracle.

### 3. Non-Fatal Stalls in the Account-Lattice
If an assigned sub-committee stalls or goes offline during an epoch cut:
- **Accounts Never Stop:** Account owners continue signing local blocks asynchronously $(S_t \to S_{t+1})$.
- **Deterministic Handover:** When the logical round distance threshold is exceeded, authority passes to $C_{k+1}$, which queries the p2p gossip pool for uncommitted tips and folds both periods into a single aggregate cut for Epoch $e+1$.
- **No Fork or Reorg:** Because every account block is uniquely signed by its owner and cryptographically chained, history cannot be rewritten or forked.

---

## 5. Summary: Classical vs. Sovereign Byzantine Chandy-Lamport

| Dimension | Classical Chandy-Lamport (1985) | Sovereign Byzantine Chandy-Lamport |
|---|---|---|
| **Clock Source** | Shared FIFO process queues | **Self-clocking Marker Traversal Loop** |
| **Marker Authority** | Single trusted process | **$(t, n)$ Threshold BLS Signature** |
| **Propagation** | Unauthenticated channel broadcast | **Targeted Route Traversal with Verification** |
| **Completion Check** | Issuer tallies incoming markers | **Self-proving Poseidon-SMT / ZK Accumulator** |
| **Committee Rotation** | Static process IDs | **Self-seeding Hash Chain ($\text{Seed}_{k+1} = \text{Hash}(\text{Seed}_k \parallel \text{Root}_k)$)** |
| **Failure Mode** | Deadlock on process crash | **Autonomous Handover to $C_{k+1}$ across Account Tips** |
