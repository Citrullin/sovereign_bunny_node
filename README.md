# Sovereign Bunny: Autonomous Bare-Silicon Cloud & Microservice Mesh

The **Stateless Consensus Database & Microservice Mesh** of the Sovereignty‑Stack Manifold.  
Sovereign Bunny compiles into a single high-performance binary (`bunny`) capable of orchestrating multi-node clusters or executing as decoupled microservice daemons communicating via Apache Iggy streams and kernel-bypass AF_XDP queues.

---

## ⚠️ Toy Mode Notice

> [!WARNING]
> When running with `--toy-mode`, cryptographic parameters (Groth16 curve dimensions, Snow beta finalization rounds, Raft election timeouts) are deliberately downgraded for rapid local development and testing. **Proofs and attestations generated in Toy Mode provide NO cryptographic security and must NOT be used in production or for real assets.**

---

## Core Architectural Pillars

### 1. Single Binary, Multi-Role Actor Mesh (`bunny`)
- **One Binary Everywhere:** A single binary (`bunny`) serves as the cluster orchestrator, microservice daemon worker, and interactive terminal debugging tool.
- **Single Container Image:** Deploy `ghcr.io/sovereign-bunny/bunny:latest` to any K8s/K3s pod, LXC container, or Bare Metal host, simply choosing the runtime mode via subcommands (`bunny daemon gateway`, `bunny daemon committee`, `bunny daemon epoch`, etc.).
- **Actor-Lattice Homomorphism:** The off-chain daemon topology directly mirrors the on-chain stateless account-lattice: asynchronous inboxes (`range.<partition>`), non-blocking Saga streams, zero shared memory, and cryptographic witness state transitions.

### 2. High-Performance Versioned SSZ ABI
- **4-Byte Versioned Envelope Header:** All inter-daemon messages begin with `[ 'B' (0x42), 'N' (0x4E), 'Y' (0x59), Version (0x01) ]`, providing 1-CPU-cycle version validation.
- **Zero-Copy & Zero-Alloc:** SSZ frames map directly from memory-mapped ring buffers with 0 heap allocations, sustaining line-rate 400GbE QSFP-DD / AF_XDP throughput.

### 3. Sharded Multi-Curve & Post-Quantum Identity
- **W3C DIDs across 11 Curves:** Resolves `did:peer:4` and `did:sovereign:<chain_id>:<address>` across Secp256k1, Ed25519, BLS12-381, ML-DSA-65 (FIPS-204), Falcon-512, SLH-DSA (FIPS-205), Secp256r1, Pasta, and BabyJubjub.
- **Social-First `.bunny` Namespaces:** Slot-based reputation name registry with exponential staking defense against domain squatting.

### 4. P2P Storage & Proof of Retrievability (Iroh / IPLD / BLAKE3)
- **Iroh Documents & Sync:** Pure-Rust BLAKE3 Bao verified streaming and QUIC transport for edge CMS documents and decentralized blobs.
- **Noir ZK-PoR:** Zero-knowledge Proof of Retrievability spot-checks verifying data availability without downloading entire files.

### 5. Universal Reverse Shadow Contracts (ERC-20, ERC-721, ERC-1155)
- **Zero-Honeypot Composability:** External chains are mapped to low-entropy virtual addresses (e.g. `0x00...00_01_00000001` for Ethereum Mainnet).
- **Superposition & Nullifier Lifecycle:** Assets locked on source clusters enter `ActiveSuperposition`; destination terminal burns consume nullifiers and release native assets directly into account-lattice accounts.

---

## Formal Specifications & Architecture Documentation

Sovereign Bunny uses industry-standard formal interface contracts across all layers:

| Layer / Concern | Standard | Specification Path | Purpose |
|---|---|---|---|
| **Stream & Queue Contracts** | **AsyncAPI 3.0** | [`docs/specifications/asyncapi.yaml`](docs/specifications/asyncapi.yaml) | Channel addresses, message schemas, and consumer groups over Apache Iggy streams. |
| **RPC Gateway Ingress** | **OpenRPC 1.3** | [`docs/specifications/openrpc.json`](docs/specifications/openrpc.json) | Complete JSON-RPC 2.0 interface for Web3 wallets (`eth_*`) and sovereign extensions (`bunny_*`). |
| **Actor Binary Boundaries** | **WASI WIT** | [`docs/specifications/wit/`](docs/specifications/wit/) | WebAssembly Interface Types for isolated guest-host actor boundaries (`lattice-actor.wit`, etc.). |
| **Binary Wire Layouts** | **Canonical SSZ** | [`docs/specifications/ssz/schemas.yaml`](docs/specifications/ssz/schemas.yaml) | 32-byte fixed-offset binary container layouts and 4-byte `BNY\x01` envelope framing. |
| **System Architecture & Statecharts** | **C4 Model & FSMs** | [`docs/architecture/C4_ARCHITECTURE.md`](docs/architecture/C4_ARCHITECTURE.md) | Multi-tiered C4 architecture diagrams, sequence message flows, and Snowman BFT statecharts. |
| **Zero-Knowledge OIDC** | **Architecture Guide** | [`docs/architecture/ZKOIDC_AUTHENTICATION.md`](docs/architecture/ZKOIDC_AUTHENTICATION.md) | Client-side Noir circuit, ephemeral session keys, and zero-PII authentication. |
| **Chain Disambiguation & CROA** | **Security Specification** | [`docs/architecture/CHAIN_DISAMBIGUATION_CROA.md`](docs/architecture/CHAIN_DISAMBIGUATION_CROA.md) | CAIP-2/fork-digest anchors, BGP CROAs, Snowman VRF tie-breaking, and ZK light-clients. |
| **Mirrored Foreign Chains** | **Consensus Architecture** | [`docs/architecture/MIRRORED_CHAINS_LATTICE_THREADS.md`](docs/architecture/MIRRORED_CHAINS_LATTICE_THREADS.md) | Foreign blockchains as virtual account threads on the Account-Lattice with reorg isolation. |
| **Decentralized CMS & P2P Data** | **Storage Architecture** | [`docs/architecture/DECENTRALIZED_CMS_P2P_DATA.md`](docs/architecture/DECENTRALIZED_CMS_P2P_DATA.md) | Post-Ceramic local-first P2P data layers (Iroh, Tableland, OrbitDB, Polybase). |
| **Penta-Vector Economics & VFS** | **Economic Specification** | [`docs/architecture/PENTA_VECTOR_ECONOMICS.md`](docs/architecture/PENTA_VECTOR_ECONOMICS.md) | 20% capped orthogonal emission vectors, smart slashing matrix, Kryder decay, and WASI VFS driver. |
| **Daemon ABI & Routing** | **Architecture Guide** | [`docs/architecture/DAEMON_ABI.md`](docs/architecture/DAEMON_ABI.md) | Service decomposition and streaming matrix. |

---

## Repository Crate Layout

```
crates/
├── cli/              # Unified `bunny` binary (Orchestrator + all daemon subcommands + debug tools)
├── consensus/        # Core consensus & domain logic:
│   ├── engine/           # Snowman BFT meta-consensus, Chandy-Lamport cuts, partition engine
│   ├── execution/        # Stateless Revm, Multi-VM adapter, transition proofs
│   ├── governance/       # 256-bit Quadrant compliance matrix & PQ validator registry
│   ├── lattice/          # Account-Lattice, 2PC escrow, SAGAs, state transitions
│   ├── mesh/             # BGP Anycast routing, WireGuard mesh, cross-chain transport
│   ├── pool/             # Transaction pool, mempool, paymaster sponsorship
│   ├── storage/          # Flat state, BLAKE3 Iroh storage integration, ZK-PoR
│   └── system_contracts/ # Universal Reverse Shadow Contracts (ERC-20, ERC-721, ERC-1155)
├── identity/         # Multi-curve/PQ DIDs, .bunny namespace registry, zkOIDC, delegation trees
├── execution/        # Stateless Revm backend (`StatelessRevmBackend`, `SovereignExecutor`)
├── sovereign-ssz/    # Canonical fixed-offset SSZ wire schemas & 4-byte 'BNY\x01' envelope
├── iggy-ctrl/        # Apache Iggy stream routing & client
├── crypto/           # ML-DSA-65, Falcon-512, Poseidon SMT, Secp256k1, Ed25519
├── attestation/      # Intel SGX/TDX DCAP quote verification
├── koral-verify/     # Sigstore supply chain verification & SBOM validation
├── network/          # P2P networking & Data Availability Sampling
└── node/             # Monolithic Reth compatibility node (`bunny-node` / legacy)
wallet/               # WebAssembly browser wallet (Noir / Groth16 client-side prover)
tests/cluster/        # Multi-daemon integration & cluster E2E test suites
```

---

## Building and Running

### Prerequisites
- Rust 1.80+ (`stable`)
- `wasm-pack` (for wallet compilation)
- Node.js 20+ (for E2E integration test runner)

### Running the Unified `bunny` Binary

By default, `cargo run` launches the `bunny` CLI:

```bash
# Build the unified binary
cargo build --release

# Run the full microservice mesh locally on a single machine
cargo run -- cluster run --backend localhost
```

### Cluster Management

```bash
# Initialize a cluster specification (localhost, lxc, k8s, k3s, podman, baremetal)
cargo run -- cluster create sovereign-alpha --backend localhost --bgp-asn 65001

# Export deployment manifests (Helm values, systemd units, LXC profiles, WireGuard config)
cargo run -- cluster export sovereign-alpha --backend baremetal --out-dir ./deploy/baremetal
cargo run -- cluster export sovereign-alpha --backend lxc --out-dir ./deploy/lxc
cargo run -- cluster export sovereign-alpha --backend k8s --out-dir ./deploy/k8s

# Validate cluster topology and check status
cargo run -- cluster validate sovereign-alpha --backend localhost
cargo run -- cluster status sovereign-alpha
```

### Running Microservice Daemons

Run any daemon role individually with the same binary:

```bash
# L7 Gateway Ingress & Paymaster Sponsor
cargo run -- daemon gateway --port 8545

# Multi-Curve & Post-Quantum DID / Namespace Resolver
cargo run -- daemon identity --port 8547

# Partition Committee Worker
cargo run -- daemon committee --partition 0 --range-start 0

# Global Epoch Snowman BFT Coordinator
cargo run -- daemon epoch --epoch-node-id 1

# Iroh P2P Storage Daemon
cargo run -- daemon storage --storage-id 1 --dir /tmp/sovereign-storage

# BGP & WireGuard Mesh Router
cargo run -- daemon mesh --bgp-asn 65001

# Secure Hardware Enclave Worker (SGXv2 / TDX)
cargo run -- daemon enclave --enclave-id 1

# EVM Read-Path RPC Proxy
cargo run -- daemon rpc --port 8546 --upstream http://127.0.0.1:8545
```

### Interactive Terminal Debugging Tools

```bash
# Resolve W3C Multi-Curve & Post-Quantum DID Document
cargo run -- debug did resolve did:sovereign:1337:0x1111111111111111111111111111111111111111

# Register a .bunny social namespace
cargo run -- debug did register-name --did did:peer:4z6M... --name alice --reputation 1.0

# Wrap raw SSZ payload with canonical 4-byte 'BNY\x01' envelope header
cargo run -- debug ssz wrap deadbeef

# Unwrap and validate 4-byte envelope header
cargo run -- debug ssz unwrap 424e5901deadbeef

# Inspect 16-bit partition range key for an EVM address
cargo run -- debug ssz range-key 0x1111111111111111111111111111111111111111

# Inspect BLAKE3 Bao CID for Iroh storage chunk
cargo run -- debug storage inspect "Hello Sovereign Mesh"
```

---

## Running Tests

```bash
# Run all workspace unit and integration tests (35+ test suites)
cargo test --workspace -- --test-threads=1

# Run the cluster and CLI test suite
cargo test -p sovereign-cluster-tests -p bunny-cli -- --test-threads=1
```
