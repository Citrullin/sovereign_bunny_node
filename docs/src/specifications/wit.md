# WIT Component Interfaces

[WebAssembly Interface Types (WIT)](https://component-model.bytecodealliance.org/design/wit.html)
definitions for the WASM Component Model are in
[`docs/specifications/wit/`](../../specifications/wit/).

These interfaces define the component boundaries for each daemon — enabling
independent compilation, testing, and hot-reload of individual services
without recompiling the entire node binary.

| Interface file | Component |
|---|---|
| [`gateway.wit`](../../specifications/wit/gateway.wit) | L7 JSON-RPC ingress: RLP → SSZ transcoding, paymaster intent routing |
| [`lattice-actor.wit`](../../specifications/wit/lattice-actor.wit) | Committee partition: stateless block execution against witness caches |
| [`mesh-router.wit`](../../specifications/wit/mesh-router.wit) | Cross-manifold relay: KZG blob packaging and inter-cluster routing |
| [`storage-daemon.wit`](../../specifications/wit/storage-daemon.wit) | Archival storage: NMT sector partitioning and Iroh/IPFS pinning |
| [`storage-engine.wit`](../../specifications/wit/storage-engine.wit) | KV engine abstraction: MDBX / RocksDB backend interface |

## Related

- [Protobuf / gRPC](grpc.md) — binary wire encoding for inter-service messages
- [C4 Container Diagram](../architecture/c4.md) — component topology
