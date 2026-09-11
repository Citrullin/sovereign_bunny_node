# JSON-RPC 2.0 API (OpenRPC)

The full machine-readable specification lives at
[`docs/specifications/openrpc.json`](../../specifications/openrpc.json).
It follows the [OpenRPC 1.3.2](https://open-rpc.org/) standard and can be
loaded into the [OpenRPC Playground](https://playground.open-rpc.org/) or
any compatible tooling for interactive exploration and client generation.

## Endpoints

| URL | Purpose |
|---|---|
| `http://127.0.0.1:8545` | L7 JSON-RPC gateway — transcodes RLP/JSON into 4-byte framed SSZ envelopes |
| `http://127.0.0.1:8546` | High-performance read proxy — synthetic receipts and 48-hour hot state cache |

## Method Groups

- **Standard EVM** — `eth_sendRawTransaction`, `eth_call`, `eth_getTransactionReceipt`, etc.
- **Sovereign Extensions** — `bunny_*` fast-path methods for lattice-native operations
- **System Precompile Shortcuts** — targeting low-entropy addresses `0x00..01`–`0x00..0100`

## Related

- [API Transport Matrix](transport-matrix.md) — full precompile routing table
- [AsyncAPI Event Streams](async-api.md) — internal daemon message bus
- [Protobuf / gRPC](grpc.md) — high-performance native client path
