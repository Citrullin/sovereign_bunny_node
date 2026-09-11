# ONLY_ASYNC Account Execution Model

## 1. Motivation

Monolithic EVM architectures assume synchronous, re-entrant call execution: Contract A invokes Contract B via `CALL`, blocks execution, and waits for a synchronous return value. This synchronous lock-step model creates systemic vulnerabilities (re-entrancy, cross-contract deadlock, flash-loan exploits) and prevents horizontal scalability across decentralized shards.

Sovereign Reth introduces the **`ONLY_ASYNC`** account flag to enforce asynchronous actor messaging across smart contracts and accounts.

---

## 2. AccountFlags Bitfield

Account behavior is governed by an extensible bitfield embedded in each account's witness:

```rust
bitflags::bitflags! {
    pub struct AccountFlags: u8 {
        /// Account only accepts asynchronous messages (inbox delivery).
        /// Rejects synchronous CALL, STATICCALL, and blocking saga locks.
        const ONLY_ASYNC = 0b0000_0001;

        /// Account is frozen by jurisdiction policy or security circuit breaker.
        const FROZEN     = 0b0000_0010;

        /// Account mandates client-side zkCompliance proof on every incoming interaction.
        const ZK_REQUIRE = 0b0000_0100;
    }
}
```

---

## 3. Witness-Level Enforcement (Pre-EVM Rejection)

To maximize throughput and eliminate wasted computational resources, `ONLY_ASYNC` constraints are enforced **before the EVM (revm or E3) is invoked**:

```
[Incoming Transaction / Contract Call]
                 │
                 ▼
     [Witness Database Pre-Flight]
                 │
                 ├─► Target has ONLY_ASYNC set?
                 │         │
                 │         ├─► Invocation is synchronous CALL / DELEGATECALL?
                 │         │         │
                 │         │         └─► REJECT IMMEDIATELY (0 Gas Consumed)
                 │         │             Returns ExecutionError::AsyncOnlyAccount
                 │         │
                 │         └─► Invocation is Async Message to Inbox?
                 │                   │
                 │                   └─► ACCEPT & Queue into Async Inbox
                 │
                 ▼
     [Standard revm / E3 Execution]
```

### Key Properties:
1. **Zero Wasted Gas:** Invalid synchronous calls fail during witness validation, consuming zero EVM execution cycles.
2. **Explicit Error Receipts:** The caller receives an explicit error receipt indicating the target is an `ONLY_ASYNC` account, enabling dApp frontends and contracts to route interactions via asynchronous messaging.
3. **Decentralized Actor Pattern:** Forces developers to build resilient, distributed dApps based on asynchronous event loops and messaging inboxes rather than vulnerable synchronous re-entrancy chains.
