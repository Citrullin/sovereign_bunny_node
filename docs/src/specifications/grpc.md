# Protobuf / gRPC

The full `.proto` definition lives at
[`specs/proto/sovereign.proto`](../../../specs/proto/sovereign.proto).

The gRPC service (`LatticeNodeService`) runs over HTTP/3 (QUIC) and accepts
native `StatelessTransitionFrame` messages with post-quantum signatures
and UltraHonk SNARK witnesses — no EIP-8141 outer envelope needed.

## Why gRPC for the native path?

JSON-RPC carries roughly 70% overhead compared to Protobuf binary encoding
for the same transaction content. For high-throughput validators and
performance-sensitive applications, the gRPC path is the correct choice.
The JSON-RPC gateway exists for compatibility with existing EVM tooling
(MetaMask, Hardhat, Foundry) — it is not the performance path.

## WIT Component Interfaces

WebAssembly Interface Types (WIT) definitions for WASM component model
integration are at [`docs/specifications/wit/`](../../specifications/wit/):

| File | Interface |
|---|---|
| `gateway.wit` | L7 ingress transcoding component |
| `lattice-actor.wit` | Committee partition execution actor |
| `mesh-router.wit` | Cross-manifold relay component |
| `storage-daemon.wit` | Archival storage daemon |
| `storage-engine.wit` | Underlying KV storage engine |

## Related

- [C4 Container Diagram](../architecture/c4.md) — service topology
- [API Transport Matrix](transport-matrix.md) — which transport to use for what
