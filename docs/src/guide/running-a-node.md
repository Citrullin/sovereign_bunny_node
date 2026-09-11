# Running a Node

## Prerequisites

- Rust toolchain (stable, via `rustup`)
- `cargo` build tool
- Intel SGX-capable hardware (optional — required only for the SGX execution backend)

## Build

```sh
cargo build --release -p sovereign-node
```

The binary is at `target/release/sovereign-node`.

## Configuration

The node is configured via two config structs loaded at startup:

**`StaticConfig`** — values that cannot change without a restart:
- `genesis_path` — absolute path to `genesis.json` (no parent-directory walking)
- `chain_id` — the network's chain ID (written into EIP-712 domain separators)
- `reclaim_timeout_epochs` — how many epochs before a floating Send can be reclaimed
- `system_registry_address` — the canonical DID registry address

**`DynamicConfig`** — values that can be updated at runtime via governance:
- `zero_latency_quantum_trigger` — when `true`, classical (secp256k1) signatures are rejected globally
- `merit_rank_cooldown_epochs` — minimum epochs before rank promotion

## Running

```sh
# Start with default config
./target/release/sovereign-node

# With explicit genesis path
./target/release/sovereign-node --genesis /path/to/genesis.json

# Enable SGX enclave backend
./target/release/sovereign-node --backend sgx
```

## Daemon subcommands

Each daemon can be run independently in microservice mode:

```sh
./target/release/sovereign-node daemon gateway    # L7 JSON-RPC ingress
./target/release/sovereign-node daemon committee  # Stateless execution
./target/release/sovereign-node daemon epoch      # BFT epoch finalization
./target/release/sovereign-node daemon storage    # Archival / IPFS pinning
./target/release/sovereign-node daemon mesh       # Cross-cluster relay
```

See the [C4 Container Diagram](../architecture/c4.md) for the full daemon topology.

## Related

- [Wallet Integration](wallet-integration.md)
- [Security Model](security-model.md)
