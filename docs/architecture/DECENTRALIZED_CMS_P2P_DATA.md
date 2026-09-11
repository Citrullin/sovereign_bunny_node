# Decentralized CMS, Structured Web3 Data & P2P Storage Architecture

## 1. The Post-Ceramic Architecture Shift

Ceramic's decline stemmed from fundamental architectural friction: running ComposeDB required heavy anchor services (CAS), complex indexing daemons, and constant consensus sync on Ethereum L1s that introduced latency, gas overhead, and centralized operational dependencies incompatible with responsive, local-first CMS workloads.

In the Sovereign Bunny stack, decentralized content management and structured data are decomposed into **local-first P2P data layers**, **relational Web3 databases**, and **lattice-anchored state cuts**.

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         DECENTRALIZED DATA & CMS TIERS                      │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │ Tier 1: Local-First P2P CRDTs (Iroh Documents & Sync / OrbitDB v2)          │
 │ Tier 2: Relational & Document Web3 DBs (Tableland SQLite / Polybase ZK)     │
 │ Tier 3: Git-Backed & Static Content-Addressed (Radicle / IPFS / Decap CMS)  │
 │ Tier 4: Account-Lattice Anchor (0x00...00F1 tip cuts via O(1) SSZ proofs)   │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Structured Data Protocols & Fit Analysis

### A. Relational & Document Web3 Databases

#### 1. Tableland (SQL on EVM + Decentralized Validators)
- **Mechanism**: Implements standard SQLite schemas where table ownership and write access are gated by ERC-721 tokens or smart contract rules. Queries are written in standard SQL (`SELECT * FROM posts_1_42 WHERE tag = 'rust'`), while mutations route through the EVM and materialize deterministically across a validator network.
- **Why it fits CMS**: Ideal for structured catalogs, eCommerce inventory, multi-author editorial permissions, and relational tags with zero custom indexing overhead.
- **Ecosystem Status**: Production-grade, active developer adoption across EVM rollups.

#### 2. Polybase (ZK-Indexed Decentralized Document Store)
- **Mechanism**: A Rust-based, decentralized alternative to Firebase/MongoDB. Collections and schemas are defined with built-in cryptographic access control. State transitions and query indexes are validated via zero-knowledge proofs.
- **Why it fits CMS**: Resolves ComposeDB's latency and indexing bottlenecks with fast client-side reads, native cryptographic permissions, and JSON-like collection schemas.

---

### B. Pure Local-First & P2P CRDT Stores (Zero Gas / Zero Blockchain Dependency)

#### 1. OrbitDB v2 (CRDTs over IPFS / Helia / libp2p)
- **Mechanism**: A serverless, peer-to-peer database engine built on top of IPFS Merkle-DAGs and CRDTs (Conflict-free Replicated Data Types). Provides Document Stores, Key-Value stores, and append-only Event Logs.
- **Why it fits CMS**: Fully decentralized with no token economics or gas fees. Posts and edits replicate peer-to-peer between nodes that open the same database address.
- **Ecosystem Status**: Completely rewritten for modern IPFS (Helia) and libp2p.

#### 2. Iroh Documents & Sync (Rust-Native P2P Data Layer)
- **Mechanism**: Built in pure Rust. Uses BLAKE3-verified streaming (Bao) and QUIC transport to sync structured key-value documents across peers with sub-millisecond local reads.
- **Why it fits CMS**: Embeds directly as a Rust crate into Sovereign Wasm pods, microservice daemons (`bunny-storage`), or Yocto ARM images without IPFS daemon bloat.
- **Ecosystem Status**: Rapidly becoming the standard P2P data layer in the Rust ecosystem.

---

### C. Git-Backed & Static Content-Addressed Workflows

#### Decap CMS / TinaCMS + Radicle / IPFS
- **Mechanism**: The CMS frontend manages Markdown and JSON frontmatter files directly against a Git repository (hosted locally, on Radicle, or pinned to IPFS/Arweave). When content is published, a headless static site generator builds static assets and commits the new root CID to the lattice.
- **Why it fits CMS**: Completely decoupled from database runtime failures. If the network goes offline, content remains accessible as plain text files.

---

## 3. Protocol Comparison Matrix

| Protocol / Engine | Data Model | Access Control | Storage / Transport | Ideal Sovereignty Fit |
|---|---|---|---|---|
| **Tableland** | Relational (SQLite / SQL) | Smart Contract / ERC-721 | EVM event log + SQLite | Multi-author blogs, relational catalogs, eCommerce |
| **Polybase** | Document / Collections (NoSQL) | Public Key / ZK Rules | Native ZK-indexed nodes | Dynamic apps, user profiles, social feeds |
| **OrbitDB v2** | Key-Value / Doc / Log | Identity Providers (DID) | IPFS (Helia) / libp2p | P2P forums, decentralized wikis, offline-first notes |
| **Iroh Docs** | Hierarchical Key-Value | Capabilities / Ed25519 | QUIC + BLAKE3 Bao | Embedded Rust nodes, sovereign edge CMS, media sync |
| **Git + Radicle / IPFS** | Markdown / JSON / Flat Files | GPG / SSH Signatures | Git DAG + Content Addressing | Editorial publications, documentation, static shops |

---

## 4. Integration with the Sovereign Bunny Mesh

For a sovereign bare-metal node architecture:

1. **Structured P2P CMS Execution**:
   - Run Iroh or OrbitDB embedded inside the node's K3s Wasm / Rust sidecar.
   - Content edits replicate over direct 400GbE / BGP peering connections at wire speed with **zero transaction fees**.
2. **Public Dynamic Publishing & Lattice Anchoring**:
   - The root state hash of local CMS collections is anchored into the Account-Lattice frontier cut under low-entropy address `0x00000000000000000000000000000000000000F1`.
   - Every article, revision, edit, and asset is globally verifiable via $O(1)$ SSZ generalized multiproofs without downloading whole datasets.
