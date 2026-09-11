# Two-Tier Consensus: Self-Seeding Shard Consensus + Global Epoch Settlement

## 1. Overview

Sovereign Reth decouples consensus into a resilient **Two-Tier Architecture**: 
1. **Tier 2 (Localized Range Execution & Marker Sweep):** Localized Multi-Paxos / Raft for ultra-high transaction throughput per account range, executing Chandy-Lamport frontier cuts and co-signing epoch snapshot roots via $(t, n)$ Threshold BLS.
2. **Tier 1 (Global Epoch Settlement & Virtual Block Cadence):** Self-authenticating epoch commitments anchored into the global Epoch DAG, exposing regular low-latency **Virtual Heartbeat Blocks** to maintain seamless EVM/RPC compatibility.

```
[ TIER 1: GLOBAL EPOCH SETTLEMENT & VIRTUAL BLOCK CADENCE ]
• Continuous Virtual Heartbeat Blocks emitted at target block cadence (e.g. 1-2s)
• Commits self-authenticating (2f + 1) Threshold BLS Epoch Snapshot Roots into global DAG
• Snowman BFT metastable sampling reserved for validator set churn & dispute resolution
                           │
       ┌───────────────────┴───────────────────┐
       ▼                                       ▼
[ TIER 2: RANGE SUB-COMMITTEE A ]       [ TIER 2: RANGE SUB-COMMITTEE B ]
Range: [0x0000..0x7FFF]                 Range: [0x8000..0xFFFF]
  ├── Multi-Paxos / openraft Execution    ├── Multi-Paxos / openraft Execution
  ├── Runs Chandy-Lamport Marker Loop     ├── Runs Chandy-Lamport Marker Loop
  └── Collective (t, n) BLS Co-Sign       └── Collective (t, n) BLS Co-Sign
```

---

## 2. Tier 2: Localized Range Execution (Multi-Paxos / openraft)

Individual account transactions do not require network-wide global BFT consensus:
- **Range Partitioning:** The address space is deterministically divided into ranges (e.g. $[0\text{x}0000..0\text{x}7\text{FFF}]$, $[0\text{x}8000..0\text{xFFFF}]$, scaled dynamically via velocity telemetry).
- **High-Throughput Sequencing:** Within each partition, the assigned sub-committee runs Multi-Paxos / `openraft` to sequence account state transitions with sub-millisecond local latency.
- **Merit Barrier:** Only validators meeting minimum reputation/merit thresholds ($\tau_{\text{merit}}$) are eligible for election as partition leaders.

---

## 3. Byzantine Chandy-Lamport Cuts & Collective BLS Co-Signing

1. **Deterministic State Convergence:**
   Because all members of a range sub-committee execute identical Multi-Paxos logs over their partition, they deterministically arrive at the exact same:
   - **Frontier Cut Vector:** $\{ (A_1, H_{t_1}), (A_2, H_{t_2}), \dots \}$
   - **In-Flight Message Set:** All cross-account send receipts emitted before the sender's marker arrival but unreceived by the target.

2. **Verifiable Marker Initiation & Reliable Echo Broadcast:**
   - Markers are proposed round-robin among committee members and threshold-signed ($2f + 1$ BLS quorum):
     $$\text{Marker}(e) = \text{ThresholdSign}_{C_k}(e \parallel \text{GlobalFrontierRoot}_{e-1})$$
   - Consistent broadcast (Bracha-style echo) ensures no Byzantine leader can selectively isolate or partition account channels.

3. **Collective $(t, n)$ BLS Co-Signing:**
   Sub-committee nodes independently compute the snapshot hash:
   $$\text{EpochSnapshotRoot}_e = \text{Hash}\Big(e \;\big\Vert{}\; \text{RangeRoot}_e \;\big\Vert{}\; \text{InFlightRoot}_e \;\big\Vert{}\; \text{PrevSnapshotRoot}_{e-1}\Big)$$
   Each node signs this root with its BLS key share. Upon reaching a supermajority ($2f + 1$), individual shares aggregate into a single compact $O(1)$ BLS signature.

4. **Empirical Rolling Median Duration ($\Delta \tau_{\text{epoch}}$):**
   The committee measures the empirical time taken for the marker sweep and quorum aggregation, committing the rolling median into the epoch header. This gives the network an on-chain, clockless time-reference metric.

---

## 4. Tier 1: Virtual Block Cadence & Direct DAG Settlement

1. **Continuous Virtual Heartbeat Blocks:**
   To provide standard EVM tooling, RPC clients, and indexers with a predictable block cadence (e.g. $T_{\text{target}} = 1\text{s}$), the node emits virtual blocks at regular intervals:
   - While epoch $e$ is processing, intermediate virtual blocks reference the **latest finalized `EpochSnapshotRoot_{e-1}`** (acting as heartbeats / micro-progress ticks).
   - Once `EpochSnapshotRoot_e` is finalized via its $2f+1$ BLS signature, the next virtual block anchors the new state root and advances the epoch pointer.

2. **Direct Self-Authenticating DAG Ingestion:**
   Because the $(t, n)$ Aggregated BLS Signature on `EpochSnapshotRoot_e` is an $O(1)$ cryptographic proof of committee supermajority, nodes across other shards ingest and verify it immediately without requiring redundant Snowman voting rounds.

3. **Role of Snowman Metastable Sampling:**
   Snowman is reserved for meta-level membership disputes, global validator registration/slashing challenges, and cross-manifold protocol forks.

4. **Self-Seeding Committee Rotation:**
   The network derives the next committee assignment deterministically from the finalized snapshot root without external oracles or synchronous coordination:
   $$\text{Seed}_{e+1} = \text{Hash}\Big(\text{Seed}_e \;\big\Vert{}\; \text{EpochSnapshotRoot}_e \;\big\Vert{}\; \text{MeritRoot}_e\Big)$$
   $$\text{Committee}(\text{Range}_i, e+1) = \text{Sample}(\text{Eligible}, \text{Seed}_{e+1}, \text{Range}_i)$$


**TinyMeritRank** is a PageRank-inspired graph reputation engine that provides the merit substrate underpinning both the Two-Tier Consensus and the reward distribution system. It gates who can be sampled into sub-committees and how frequently they receive progressive SOV micro-rewards.

### Score Computation (per Epoch Tick)

Reputation scores are updated over a directed weighted endorsement graph. Each epoch runs 6 deterministic steps:

```
1. PageRank Iteration:    R_v(t+1) = (1-d) + d * Σ_{u→v} R_u(t) * w(u,v) / Σ_w(u,·)
2. Connectivity Decay:    R_v -= γ * (1 - connectivity_score_v)
3. Cartel Detection:      slash_cartels()  — fires if >20% mutual endorsement weight
4. KZG Commitment Slash:  slash_missing_commitments() — penalizes absent DA publications
5. MeritRank Tier:        auto-promote/demote { Rank0, Rank1, Rank2, Rank3, Rank4 }
6. Reward Distribution:   distribute SOV at tier-specific epoch intervals
```

### MeritRank Tiers & Progressive Rewards

| Tier | R_v Threshold | Reward Interval | Base Multiplier |
|---|---|---|---|
| Rank 0 | default / new node | Every 90 epochs (~3 months) | 10 |
| Rank 1 | R_v > 0.10 | Every 30 epochs (~1 month) | 50 |
| Rank 2 | R_v > 0.30 | Every 14 epochs (~2 weeks) | 150 |
| Rank 3 | R_v > 0.60 | Every 7 epochs (~1 week) | 400 |
| Rank 4 | R_v > 0.90 | Every 1 epoch | 1000 |

### Genesis Seed & Bootstrap Configuration

Since the network is fully sovereign (no external clock or beacon), genesis requires two explicit seeds:

| Seed | Purpose | Field |
|---|---|---|
| **Genesis Validator Set** | The initial committee $C_0$ that emits the first `ThresholdEpochMarker` | `genesis.validator_seeds` |
| **Genesis Epoch Snapshot Seed** | Starting `Seed_0` for the self-seeding hash chain rotation | `genesis.epoch_snapshot_seed` |

During the configurable `genesis_bootstrap_epochs` window, all genesis seed validators are eligible for committee sampling **regardless of merit score**, allowing the network to bootstrap before organic reputation accumulates.

After bootstrap completes:
$$\text{Eligible}(\text{epoch}\ e) = \{ v \in \text{ValidatorSet} : R_v \ge \tau_\text{merit} \}$$
$$\text{Seed}_{k+1} = \text{Hash}(\text{Seed}_k \parallel \text{EpochSnapshotRoot}_k \parallel \text{MeritRoot}_k)$$
$$\text{Committee}(\text{Range}_i, k+1) = \text{Sample}(\text{Eligible}, \text{Seed}_{k+1}, \text{Range}_i)$$

Incorporating the **MeritRoot** (SMT root of all current reputation scores) into the seed derivation makes committee assignment unpredictable to any actor trying to game the scoring to land in a specific committee.

### Stratified Committee Sampling (Anti-Plutocracy)

To prevent the concentration of consensus power into a wealthy/high-reputation oligopoly (the classic Proof-of-Stake plutocracy trap), sub-committee and relay committee sampling is strictly **stratified across TinyMeritRank tiers/deciles**:

1. **Decile / Tier Partitioning**: The eligible validator set $\text{Eligible}(e)$ is partitioned into $D$ strata (e.g. 7 deciles or MeritRank tiers Rank 0 through Rank 4).
2. **Stratum Allocation**: Each committee of target size $K$ allocates guaranteed quota slots $k_s$ across the strata ($K = \sum_s k_s$).
3. **Deterministic Intra-Stratum VRF Selection**: Within each stratum, members are selected using distance to the entropy seed $\text{Seed}_e$:
   $$\text{Sample}_s = \text{VRFSort}(\text{Strata}_s, \text{Seed}_e)[..k_s]$$
4. **Anti-Capture Invariant**: No single merit rank or decile can hold $> \frac{1}{3}$ of voting power in any sub-committee, guaranteeing that Byzantine quorums ($2f + 1$) require cross-tier consensus across emerging and established participants alike.

### Anti-Cartel Invariant

Mutual endorsement rings (where A backs B, B backs A, with >20% of their total endorsement weight) are detected and slashed automatically each epoch by `SlashingManager::slash_cartels()`. This prevents validators from forming closed reputation inflation cartels.


