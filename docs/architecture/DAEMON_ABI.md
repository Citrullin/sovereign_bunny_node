# Sovereign Bunny Daemon Architecture & ABI / API Specification

## 1. Overview & Service Decomposition

Sovereign Bunny runs as a high-performance, stateless, and hardware-accelerated distributed execution environment. Instead of a single monolithic blockchain process, responsibilities are partitioned into **single-purpose daemons** communicating via high-throughput in-memory/TCP event bus topics (`sovereign-iggy-ctrl`) and canonical SSZ encoding (`sovereign-ssz`).

```
                     [ Wire: 400GbE QSFP-DD ]
                                │
                                ▼
                       ┌─────────────────┐
                       │   bunny-demux   │ (Kernel Bypass DMA)
                       └────────┬────────┘
                                │
                                │ Writes binary SSZ chunks
                                ▼
┌──────────────────┐    ┌───────────────┐    ┌──────────────────┐
│  bunny-gateway   ├───►│  IGGY STREAMS ├───►│ bunny-committee  │
│(Legacy RPC/zkOIDC│    │               │    │(Paxos / revm SGX)│
└──────────────────┘    └───────┬───────┘    └────────┬─────────┘
                                ▲                     │
                                │ Emits epoch markers │ Emits state diffs
                                │ & rotations         ▼
┌──────────────────┐    ┌───────┴───────┐    ┌──────────────────┐
│    bunny-mesh    │◄───┤  bunny-epoch  │◄───┤  bunny-storage   │
│(Cross-Chain/BGP) │    │(Snowman / VRF)│    │(Iroh / ZK-PoR)   │
└──────────────────┘    └───────────────┘    └──────────────────┘
```

---

## 2. Specification & Documentation Standards

All daemons adhere to formal interface contracts defined under [`docs/specifications/`](../specifications/):

| Layer / Concern | Specification Standard | Specification Document | Description |
|---|---|---|---|
| **Stream & Queue Contracts** | **AsyncAPI 3.0** | [`docs/specifications/asyncapi.yaml`](../specifications/asyncapi.yaml) | Channel addresses, message payloads, and consumer group contracts for Apache Iggy stream queues. |
| **RPC Gateway Ingress** | **OpenRPC 1.3** | [`docs/specifications/openrpc.json`](../specifications/openrpc.json) | Complete JSON-RPC 2.0 interface for `bunny-gateway` and `bunny-rpc` (`eth_*`, `bunny_*`). |
| **Actor Interfaces (WASI)** | **WASI WIT** | [`docs/specifications/wit/`](../specifications/wit/) | WebAssembly Interface Types for guest-host actor boundaries (`lattice-actor.wit`, `gateway.wit`, `storage-daemon.wit`, `mesh-router.wit`). |
| **Binary Wire Layouts** | **Canonical SSZ** | [`docs/specifications/ssz/schemas.yaml`](../specifications/ssz/schemas.yaml) | 32-byte fixed-offset binary container layouts and 4-byte `BNY\x01` envelope framing. |
| **System Architecture & Statecharts** | **C4 Model & FSMs** | [`docs/architecture/C4_ARCHITECTURE.md`](C4_ARCHITECTURE.md) | Multi-tiered C4 architecture diagrams, sequence message flows, and Snowman BFT / Reverse Shadow FSM statecharts. |

---

## 3. Daemon Directory & Stream Routing Matrix

All microservices run from the unified multi-role binary `bunny daemon <subcommand>` ([`crates/cli/src/daemons.rs`](../../crates/cli/src/daemons.rs)):

| Daemon Command | Primary Protocol / Ingress | Message Bus Subscription | Message Bus Emission | Primary Architectural Role |
|---|---|---|---|---|
| **`bunny daemon demux`** | AF_XDP / L2 Ethernet (`eth0`, `qsfp0`) | Physical Wire / Kernel Bypass | `range.<partition>` | High-speed DMA demultiplexer extracting fixed-offset SSZ account ranges in hardware and pushing directly to Iggy queues. |
| **`bunny daemon gateway`** | `TCP 8545` (HTTP/JSON-RPC) | `sys.committee-rotations` | `range.<partition>` | Transcodes legacy RLP/EVM payloads to typed SSZ, executes Paymaster gasless sponsorship, verifies DIDs, and routes to partition streams. |
| **`bunny daemon rpc`** | `TCP 8546` (HTTP JSON-RPC) | Reads local cache + upstream | None | Read-path RPC proxy with 48h hot memory index, zero-gas spoofing, and synthetic receipts. |
| **`bunny daemon committee`** | Apache Iggy In-Memory Streams | `range.<partition>` | `sys.state-roots`, `sys.epoch-markers` | Partition actor. Executes stateless Revm transitions against ephemeral witness caches and publishes post-state roots. |
| **`bunny daemon epoch`** | Apache Iggy In-Memory Streams | `sys.epoch-markers` | `sys.committee-rotations` | Decentralized coordinator. Collects BFT snapshot markers, drives Snowman meta-consensus sampling, and derives deterministic VRF seeds for shard rotation. |
| **`bunny daemon storage`** | Iroh / IPFS / Bitswap | `sys.state-roots` | `sys.storage-partition` | P2P storage daemon. Partitions sector blobs into Namespaced Merkle Trees (NMTs), pins to IPFS/Iroh, and produces BLAKE3 Bao ZK-PoR proofs. |
| **`bunny daemon mesh`** | BGP Anycast / WireGuard (`51820`) | `sys.cross-chain` | Remote BGP Peers | Inter-cluster transport daemon routing 2PC Sagas and executing Universal Reverse Shadow Contract state proofs. |
| **`bunny daemon identity`** | Local RPC / P2P | Local Resolver | Local Cache | Multi-curve W3C DID document & `.bunny` social namespace registry with reputation and staking protection. |
| **`bunny daemon enclave`** | Hardware Mailbox / SGXv2 | Internal Mailbox | `sys.state-roots` | Hardware-isolated SGXv2/TDX Gramine confidential worker for zero-knowledge private state transitions. |

---

## 4. Dual-Path Architecture: Low-Entropy Precompile Addresses vs. Daemon Fast-Paths

Sovereign Bunny guarantees 100% interoperability with standard EVM smart contracts via **Low-Entropy System Addresses (EIP-1352 namespace)** while providing **Zero-Overhead Daemon Fast-Path RPCs (`bunny_*`)** for off-chain simulations and P2P DHT queries:

```
                                    [ USER / DAPP REQUEST ]
                                               │
                        ┌──────────────────────┴──────────────────────┐
                        │                                             │
               [ Standard Smart Contract ]                   [ Daemon Fast-Path ]
               `eth_sendRawTransaction` / `eth_call`        `bunny_*` JSON-RPC / WASI WIT
                        │                                             │
                        ▼                                             ▼
          ┌───────────────────────────┐                 ┌───────────────────────────┐
          │ Low-Entropy System Address│                 │ In-Memory Microservice    │
          │ (0x00...0001 - 0x00...0100│                 │ Actor Simulation (RAM)    │
          └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                        │ On-Chain Settlement                         │ Immediate Result
                        ▼                                             ▼
          ┌───────────────────────────┐                 ┌───────────────────────────┐
          │ Stateless Account-Lattice │                 │ Direct Zero-Gas Response  │
          │ Witness State Transition  │                 │ (Simulation / P2P DID)    │
          └───────────────────────────┘                 └───────────────────────────┘
```

### Low-Entropy System Address Mapping Table

| System Address | Symbol | On-Chain Interface (`eth_call` / `eth_sendRawTransaction`) | Off-Chain / Fast-Path Equivalent (`bunny_*`) | Architectural Concern |
|---|---|---|---|---|
| `0x0000000000000000000000000000000000000001` | `SYSTEM_EPOCH_REGISTRY` | Checkpoint verification, epoch pointers | `eth_blockNumber`, `bunny_queryStorageCid` | Epoch cut indexing & checkpoint tracking. |
| `0x0000000000000000000000000000000000000002` | `SYSTEM_RECEIVE_HOOK` | Stateless claim sweep against send block hash | Daemon 2PC auto-sweep | In-flight balance settlement. |
| `0x0000000000000000000000000000000000000003` | `SYSTEM_DID_REGISTRY` | `registerDid(didDoc, pqKey, tier)` | `bunny_resolveDid(didUri)` | Multi-curve & PQ DID registration/resolution. |
| `0x0000000000000000000000000000000000000004` | `SYSTEM_SAGA_ESCROW` | `lockSagaEscrow(intentId, target, amount)` | `bunny_simulateSagaIntent(payload)` | 2PC cross-account/cross-chain escrow locks. |
| `0x0000000000000000000000000000000000000005` | `SYSTEM_JURISDICTION` | Jurisdiction rule updates & voting | Local compliance vector check | Compliance filter stems & sanction filtering. |
| `0x0000000000000000000000000000000000000006` | `SYSTEM_BRIDGE` | `wrapNative(destChainId, amount)` | `bunny_simulateSagaIntent(payload)` | Universal Reverse Shadow Contract superposition. |
| `0x0000000000000000000000000000000000000007` | `SYSTEM_ASYNC_INBOX` | `postActorMessage(actorId, payload)` | Iggy Stream Direct Publish | Cross-actor asynchronous mailbox. |
| `0x0000000000000000000000000000000000000008` | `SYSTEM_ZK_COMPLIANCE`| `submitZkCompliance(proof, inputs)` | WASI WIT `verify-proof` | Client-side zero-knowledge compliance verification. |
| `0x0000000000000000000000000000000000000009` | `SYSTEM_ACCOUNT_FLAGS` | `setFlags(flags)` (ONLY_ASYNC, FROZEN)| Fast state cache lookup | Account execution mode configuration. |
| `0x000000000000000000000000000000000000000a` | `SYSTEM_AI_ORACLE` | `submitAiAttestation(evaluationJson)` | P2P agent gossip | AI Evaluator Agent contribution attestations. |
| `0x0000000000000000000000000000000000000100` | `SYSTEM_ACCOUNT_HEIGHT`| `getHeight(account)` precompile | `eth_getTransactionCount` | Local lattice sequence height. |
| `0x00...00_01_<ChainID>` | `VIRTUAL_CHAIN_ADDRESS` | `transferToRemote(recipient, calldata)` | Mesh daemon WireGuard relay | Low-entropy destination virtual addresses. |

---

## 5. Web3 Decentralized Database & CMS Architecture

Sovereign Bunny storage nodes and edge CMS applications leverage modular decentralized database protocols:

### A. Relational & Document Web3 Databases
- **Tableland (SQL on EVM + Decentralized Validators)**: Implements standard SQLite schemas where table ownership and write access are gated by ERC-721 tokens or smart contract rules. Queries are written in standard SQL, while mutations route through the EVM and materialize deterministically across a validator network. Ideal for relational catalogs, eCommerce, and multi-author editorial blogs.
- **Polybase (ZK-Indexed Decentralized Document Store)**: A Rust-based, decentralized alternative to Firebase/MongoDB. Collections and schemas are defined with built-in cryptographic access control. State transitions and query indexes are validated via zero-knowledge proofs.

### B. Pure Local-First & P2P CRDT Stores (No Blockchain Dependency)
- **OrbitDB v2 (CRDTs over IPFS / Helia / libp2p)**: A serverless, peer-to-peer database engine built on top of IPFS Merkle-DAGs and CRDTs (Conflict-free Replicated Data Types). Provides document stores, key-value stores, and append-only event logs with zero gas fees.
- **Iroh Documents & Sync (Pure-Rust P2P Data Layer)**: Built in pure Rust. Uses BLAKE3-verified streaming (Bao) and QUIC transport to sync structured key-value documents across peers with sub-millisecond local reads. Embeds directly into Sovereign Wasm pods and Yocto ARM images without IPFS daemon bloat.

### C. Git-Backed & Static Content-Addressed Workflows
- **Decap CMS / TinaCMS + Radicle / IPFS**: The CMS frontend manages Markdown and JSON frontmatter files directly against a Git repository (hosted locally, on Radicle, or pinned to IPFS/Arweave). When content is published, static assets build and commit the new root CID to the lattice.

### Architectural Comparison Matrix

| Protocol / Engine | Data Model | Access Control | Storage / Transport | Ideal Sovereignty Fit |
|---|---|---|---|---|
| **Tableland** | Relational (SQLite / SQL) | Smart Contract / ERC-721 | EVM event log + SQLite | Multi-author blogs, relational catalogs, eCommerce |
| **Polybase** | Document / Collections (NoSQL) | Public Key / ZK Rules | Native ZK-indexed nodes | Dynamic apps, user profiles, social feeds |
| **OrbitDB v2** | Key-Value / Doc / Log | Identity Providers (DID) | IPFS (Helia) / libp2p | P2P forums, decentralized wikis, offline-first notes |
| **Iroh Docs** | Hierarchical Key-Value | Capabilities / Ed25519 | QUIC + BLAKE3 Bao | Embedded Rust nodes, sovereign edge CMS, media sync |
| **Git + Radicle / IPFS** | Markdown / JSON / Flat Files | GPG / SSH Signatures | Git DAG + Content Addressing | Editorial publications, documentation, static shops |

---

## 4. ABI Specifications (SSZ Schemas)

All inter-daemon messages use deterministic SSZ encoding.

### A. `SszTransaction` (Wire Format)
Total fixed size: 104 bytes.

```
Offset   Field Name       Type             Description
0..8     `nonce`          `uint64`         Sender account sequence number
8..16    `intent_id`      `uint64`         Unique intent / nullifier tracking key
16..36   `from`           `Vector[uint8,20]` Sender EVM address
36..56   `to`             `Vector[uint8,20]` Target recipient / precompile address
56..88   `value`          `Vector[uint8,32]` Big-endian 256-bit token value (wei)
88..92   `gas_limit`      `uint32`         Execution gas budget
92..94   `range_key`      `Vector[uint8,2]` High-order 16 bits of target for partition routing
94..104  `_padding`       `Vector[uint8,10]` Reserved alignment bytes
```

### B. `ThresholdEpochMarker`
Emitted by `bunny-committee` and `bunny-e3` to `sys.epoch-markers`.

```
Field Name      Type             Description
`epoch_id`      `uint64`         Monotonically increasing epoch sequence index
`range_start`   `uint16`         Lower bound of partition range (e.g. 0x0000)
`range_end`     `uint16`         Upper bound of partition range (e.g. 0x3FFF)
`range_root`    `Vector[uint8,32]` Poseidon-SMT post-execution state root
`bls_signature` `Vector[uint8,32]` Aggregated BLS committee threshold signature
`prev_marker`   `Vector[uint8,32]` Hash of previous finalized epoch marker
```

### C. `RotationEvent`
Emitted by `bunny-epoch` to `sys.committee-rotations`.

```
Field Name        Type     Description
`epoch_id`        `uint64` Epoch ID when rotation takes effect
`partition_count` `uint32` Active partition committee count
```
