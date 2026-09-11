# SSZ Wire Format

The full SSZ schema lives at
[`docs/specifications/ssz/schemas.yaml`](../../specifications/ssz/schemas.yaml).

All internal messages between daemons use
[Simple Serialize (SSZ)](https://ethereum.org/en/developers/docs/data-structures-and-encoding/ssz/)
wrapped in a 4-byte magic envelope:

```
b"BNY\x01" | ssz_encoded_message
```

SSZ was chosen over RLP and JSON because:
- **Fixed-size fields are zero-copy** — no length-prefixed parsing for
  fixed-width types like `B256`, `Address`, `u64`
- **Merkle-tree native** — SSZ's chunked structure maps directly onto the
  Sparse Merkle Tree state model; generating inclusion proofs requires no
  re-encoding
- **Deterministic** — identical inputs always produce identical bytes,
  which is required for cryptographic commitments

## Key Types

| Type | SSZ encoding |
|---|---|
| `LatticeBlock` | `Container(account: Address, payload: Union, signature: List[u8, 65], ...)` |
| `StatelessTransitionFrame` | `Container(backend: u8, proof_data: List[u8, 4096], ...)` |
| `EpochCheckpoint` | `Container(epoch_id: u64, state_root: B256, validator_signatures: List[BLSSig, 512])` |
| `ShadowBurnReceipt` | `Container(receipt_id: B256, dest_chain_id: u64, nullifier: B256, ...)` |

## Related

- [Daemon API & ABI](../architecture/daemon-abi.md) — envelope framing and routing
- [Rust crate `sovereign-ssz`](../api-reference.md) — Rust implementation
