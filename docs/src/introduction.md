# Sovereign Bunny Ledger

**Sovereign Bunny** is a stateless account-lattice node built on top of
[reth](https://github.com/paradigmxyz/reth). It combines a Nano-style
block-lattice per-account transaction model with a Snow family BFT consensus
layer, post-quantum identity (ML-DSA-65, Falcon-512), an SGX confidential
execution backend, and a universal cross-chain shadow asset system.

This book is the authoritative reference for the architecture, wire-format
specifications, Rust API, and implementation status of every component.

---

## Navigation

| Section | What you'll find |
|---|---|
| [Implementation Status](implementation-status.md) | Which components are production-ready, work-in-progress, or stubs — and exactly what each stub needs to become real |
| [Architecture](architecture/overview.md) | Design documents, C4 diagrams, FSMs, and rationale for every major subsystem |
| [Specifications](specifications/transport-matrix.md) | OpenRPC, AsyncAPI, Protobuf, SSZ, and WIT formal interface specifications |
| [API Reference](api-reference.md) | Links into the generated `cargo doc` rustdoc for all public Rust types and functions |
| [Developer Guide](guide/running-a-node.md) | How to run a node, integrate a wallet, and write a lattice client |

---

## Design Philosophy

**Stateless execution over shared witness caches.** No committee actor reads
or writes to a shared database during block execution. All state needed for
a transaction is delivered as a cryptographic witness alongside the
transaction. This makes execution horizontally scalable and enclave-friendly.

**Account-lattice over a global chain.** Each account has its own independent
chain of blocks, identified by hash, ordered by sequence number. This
eliminates account-level contention and allows parallel execution across
non-overlapping account sets.

**Honest about what is real.** Every stub and work-in-progress component is
marked as such in the [Implementation Status](implementation-status.md) page,
in the `docs/components.toml` manifest, and in the inline rustdoc for the
relevant Rust types and functions. The goal is production — the path to it is
documented explicitly.

---

## Source Repository

```
crates/consensus/   — core execution, consensus, governance, mesh
crates/node/        — binary entry point and JSON-RPC server
crates/identity/    — DID resolution, ZKP auth, delegation
crates/attestation/ — SGX DCAP attestation pipeline
crates/network/     — P2P networking, DAS, WireGuard
crates/crypto/      — cryptographic profiles and signature schemes
wallet/             — WASM wallet (wasm-bindgen, Noir/Groth16 frontend)
docs/               — this book, specifications, component manifest
specs/              — OpenAPI, Protobuf
```
