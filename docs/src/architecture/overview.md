# Architecture Overview

This section documents the design of every major subsystem. Each chapter
covers the *why* — the invariants, threat model, and design decisions —
alongside the formal diagrams and state machines.

## Chapters

| Chapter | What it covers |
|---|---|
| [C4 Container Model](c4.md) | System context, container decomposition, daemon responsibilities, message flow sequences |
| [Account-Lattice & Epochs](epoch-lattice.md) | Per-account block chains, epoch boundaries, merit distribution, lattice threading |
| [Hybrid Consensus](hybrid-consensus.md) | Snowman BFT sampling, epoch cut markers, validator rotation via VRF |
| [Dual Architecture](dual-arch.md) | Classical EVM path vs. confidential SGX path vs. Noir ZK path |
| [Reverse Shadow Contracts](shadow-contracts.md) | Cross-chain 2PC lifecycle, nullifier design, k-epoch reorg protection |
| [Based Witness Mesh](witness-mesh.md) | KZG blob transport, cross-manifold relay, ZK proof verification |
| [Penta-Vector Economics](economics.md) | TBL token emission model, merit rank multipliers, cartel detection |
| [ZK-OIDC Authentication](zk-oidc.md) | W3C DID identity, multi-curve keys, quantum trigger, ZK auth proofs |
| [Jurisdiction & Compliance](jurisdiction.md) | SMT quadrant bitmask, compliance vectors, jurisdictional reveal |
| [SMT State Model](smt-state.md) | Sparse Merkle Tree structure for account state commitments |
| [Superposition State](superposition.md) | Parallel speculative execution and state superposition |
| [Daemon API & ABI](daemon-abi.md) | SSZ envelope format, precompile bytecode routing matrix |

## Cross-References

Architecture chapters link directly to:
- The relevant [Specifications](../specifications/transport-matrix.md)
  (OpenRPC methods, AsyncAPI channels, Protobuf messages)
- The [Implementation Status](../implementation-status.md) entry for each component
- The Rust types in the [API Reference](../api-reference.md)
