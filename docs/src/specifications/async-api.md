# Event Streams (AsyncAPI)

The full machine-readable specification lives at
[`docs/specifications/asyncapi.yaml`](../../specifications/asyncapi.yaml).
It follows [AsyncAPI 3.0.0](https://www.asyncapi.com/) and describes all
internal daemon message channels on the Apache Iggy stream broker.

## Stream Channels

| Channel | Address | Publisher | Consumers |
|---|---|---|---|
| Partition Queues | `range.{partitionId}` | gateway, demux | committee actors |
| Epoch Markers | `sys.epoch-markers` | committee actors | epoch coordinator |
| Committee Rotations | `sys.committee-rotations` | epoch coordinator | all daemons |
| State Roots | `sys.state-roots` | committee actors | storage, epoch |
| Cross-Chain | `sys.cross-chain` | committee actors | mesh relay |

The `partitionId` is the upper 16 bits of `keccak256(to_address)`, giving
65,536 independent partition queues. This sharding allows horizontal
scaling of committee actors without coordination: each actor owns a disjoint
range of account addresses.

## Message Format

All messages are 4-byte framed SSZ envelopes with the magic header `b"BNY\x01"`.
The gateway transcodes incoming JSON-RPC / RLP transactions into this format
before publishing to the appropriate partition queue.

## Related

- [C4 Container Diagram](../architecture/c4.md) — daemon topology and message flow
- [Daemon API & ABI](../architecture/daemon-abi.md) — SSZ envelope wire format
