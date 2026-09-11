# Superposition State Semantics & Auto-Reclaim

## 1. Overview

In Sovereign Reth's Account-Lattice architecture, state transitions obey strict **Superposition State Semantics**:

> **Core Invariant:** State changes **ONLY** finalize when a **Receive** block is committed to the recipient's account frontier. While a transaction exists only as a Send block, the value and intent remain in a floating **Superposition State** that can be safely reclaimed upon timeout.

```
ACCOUNT ALICE:                                ACCOUNT BOB:
  Frontier: [B_0 ──► B_1 ──► SEND(to: Bob)]     Frontier: [B_0 ──► B_1 ──► RECV(from: Alice)]
                                   │                                         ▲
                                   │                                         │
                                   ▼                                         │
                        [ Superposition Index ]                              │
                        • Floating / In-transit                              │
                        • Timeout: T_epochs                                  │
                        • Auto-Reclaimable ──────────────────────────────────┘ (Finalized only here)
```

---

## 2. Superposition Mechanics

1. **Send Block Creation:**
   When Alice transfers tokens or initiates a cross-manifold Saga intent, Alice's account frontier appends a `Send` block.
   - The funds are deducted from Alice's active balance.
   - The transaction enters the global `SuperpositionIndex`.
   - **No recipient state is mutated yet.**

2. **Receive Block Commitment:**
   When Bob submits a matching `Receive` block referencing Alice's `send_block_hash`:
   - Bob's account frontier commits the balance credit.
   - The entry is removed from the `SuperpositionIndex`.
   - The state transition is irreversibly finalized.

---

## 3. Auto-Reclaim at Epoch Boundaries

If a floating Send block or Saga intent is not claimed by the recipient within its designated timeout window ($T_{\text{epochs}}$), the network automatically executes an **Auto-Reclaim**:

1. **Deterministic Trigger:**
   Epochs function as the network's high-frequency reference tick (e.g., 30–60 seconds). During each epoch finalization (`finalize_epoch`), the `SuperpositionReclaimer` scans the `SuperpositionIndex` for entries where:
   $$\text{created\_at\_epoch} + \text{timeout\_epochs} \le \text{current\_epoch}$$
   *(With $T_{\text{epochs}} = 5\text{ ticks}$, timeouts resolve within ~2.5–5 minutes, ensuring sender funds are never locked for extended periods).*

2. **Non-Blocking Reclaim Block Creation:**
   Instead of locking Alice's account, the network generates a **new Reclaim block** on Alice's account chain:
   - Alice's account remains asynchronous and free to produce subsequent blocks.
   - The expired balance is credited back to Alice.
   - For Saga intents, `SagaActor::rollback()` is triggered, safely reverting cross-chain intent escrows.

3. **Inclusion in Epoch Snapshot:**
   The reclaimed state is finalized in the epoch's Chandy-Lamport snapshot, guaranteeing cryptographic consistency without manual user intervention.
