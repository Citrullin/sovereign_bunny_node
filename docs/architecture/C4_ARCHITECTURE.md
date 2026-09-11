# Sovereign Bunny Cluster Architecture & State Dynamics

This document specifies the multi-tiered **C4 Model Architecture**, **Message Flow Sequences**, and **Statecharts (FSMs)** governing the stateless microservice daemons of the Sovereign Bunny Ledger.

---

## 1. C4 Model Architecture

### Level 1: System Context Diagram
Shows how external users, Web3 dApps, and peer clusters interact with the Sovereign Bunny node fabric.

```mermaid
C4Context
    title System Context Diagram for Sovereign Bunny Ledger Fabric

    Person(user, "Web3 User / Client", "Initiates transactions, executes DID social registrations, and transfers cross-cluster assets.")
    System(gateway, "bunny-gateway & RPC", "L7 JSON-RPC 2.0 Ingress, Paymaster Gasless Sponsor, and DID Resolution Endpoint.")
    System_Ext(peerCluster, "External Sovereign / Base Cluster", "Meshed cluster communicating via BGP Anycast & Universal Reverse Shadow Contracts.")
    System_Ext(ipfs, "IPFS / Iroh Cluster", "Decentralized storage layer for BLAKE3 Bao verified streaming and ZK-PoR archiving.")

    System(bunnyCluster, "Sovereign Bunny Stateless Node", "Microservice cluster executing transactions statelessly across Account-Lattice partitions over Apache Iggy streams.")

    Rel(user, gateway, "JSON-RPC / WebSockets", "HTTP:8545 / 8546")
    Rel(gateway, bunnyCluster, "4-Byte Framed SSZ Envelopes", "Iggy: range.{partitionId}")
    Rel(bunnyCluster, peerCluster, "Cross-Chain Saga Intent / WireGuard Tunnels", "BGP / IPv6 ULA")
    Rel(bunnyCluster, ipfs, "Pin Sector Blobs & Query ZK-PoR", "BLAKE3 / Multihash")
```

---

### Level 2: Container Diagram (Microservice Daemons & Streams)
Illustrates the decomposition of `bunny` into isolated microservice daemons connected strictly via **Apache Iggy message topics**.

```mermaid
C4Container
    title Container Diagram - Sovereign Bunny Daemons & Iggy Streams

    Container(demux, "bunny-demux", "C / Rust (AF_XDP)", "Kernel-bypass DMA frame demultiplexer reading raw Ethernet frames.")
    Container(gw, "bunny-gateway", "Rust (Axum/Tokio)", "L7 HTTP JSON-RPC ingress; transcodes RLP into fixed-offset SSZ envelopes.")
    Container(iggy, "Apache Iggy Bus", "Rust / MMAP", "In-memory zero-copy streaming engine organizing partition queues and system topics.")
    Container(committee, "bunny-committee", "Rust (Stateless Revm)", "Stateless Account-Lattice actor executing transactions against witness caches.")
    Container(epoch, "bunny-epoch", "Rust (Snowman BFT)", "Global consensus coordinator sampling epoch cut markers and rotating committee VRF seeds.")
    Container(storage, "bunny-storage", "Rust (Iroh/Bao)", "Archival daemon pinning NMT sector blobs with ZK Proofs of Retrievability.")
    Container(mesh, "bunny-mesh", "Rust (BoringTun/BGP)", "Inter-cluster mesh transport routing 2PC Sagas and Reverse Shadow receipts.")

    Rel(demux, iggy, "DMA zero-copy write", "range.0xXXXX")
    Rel(gw, iggy, "Transcoded SSZ (b'BNY\\x01')", "range.0xXXXX")
    Rel(iggy, committee, "Consume Batch", "range.0xXXXX")
    Rel(committee, iggy, "Emit State Diff", "sys.state-roots")
    Rel(committee, iggy, "Publish Cut Marker", "sys.epoch-markers")
    Rel(iggy, epoch, "Sample Markers", "sys.epoch-markers")
    Rel(epoch, iggy, "Broadcast Rotation", "sys.committee-rotations")
    Rel(iggy, storage, "Pin State Snapshot", "sys.state-roots")
    Rel(committee, iggy, "Cross-Cluster Transfer", "sys.cross-chain")
    Rel(iggy, mesh, "Relay Across Mesh", "sys.cross-chain")
```

---

## 2. Event-Driven Message Flow Sequences

### End-to-End Stateless Transaction Lifecycle
Demonstrates the zero-shared-memory execution flow from ingress to storage archival.

```mermaid
sequenceDiagram
    autonumber
    actor User as Web3 DApp / User
    participant GW as bunny-gateway
    participant IG as Iggy Stream (range.0x4000)
    participant CM as bunny-committee (Partition Actor)
    participant EP as bunny-epoch (Snowman Coordinator)
    participant ST as bunny-storage (Archival Daemon)

    User->>GW: eth_sendRawTransaction(rlp_bytes)
    Note over GW: 1. Calculate range key = keccak256(to)[0..2]<br/>2. Transcode RLP to SSZ<br/>3. Wrap with b"BNY\x01" Envelope
    GW->>IG: Publish message to range.0x4000
    IG->>CM: Pull batch (Consumer Group: committee-0x4000)
    Note over CM: 4. Stateless Revm execution against AccountWitness<br/>5. Generate TransitionProof::StatelessWitness (π)<br/>6. Update local partition state root
    CM->>IG: Publish state root (sys.state-roots)
    CM->>IG: Publish epoch cut marker (sys.epoch-markers)
    IG->>ST: Consume state root for archiving
    Note over ST: 7. Build Namespaced Merkle Tree (NMT)<br/>8. Pin BLAKE3 Bao document to Iroh/IPFS
    IG->>EP: Consume epoch cut marker
    Note over EP: 9. Snowman BFT confidence sampling<br/>10. Finalize epoch boundary
    EP->>IG: Broadcast new VRF seed (sys.committee-rotations)
```

---

## 3. Statecharts & Deterministic FSMs

### A. Snowman BFT Meta-Consensus FSM ([`crates/consensus/src/engine/snow.rs`](../../crates/consensus/src/engine/snow.rs))
Governs probabilistic confidence accumulation across committee partition markers.

```mermaid
stateDiagram-v2
    [*] --> Sampling : Round Started
    
    state Sampling {
        [*] --> QueryPeers
        QueryPeers --> CountVotes : Receive k sample responses
        CountVotes --> CheckThreshold
    }

    CheckThreshold --> ResetConsecutive : Majority < alpha * k
    ResetConsecutive --> Sampling : Reset counter (consecutive = 0)

    CheckThreshold --> IncrementConfidence : Majority >= alpha * k
    IncrementConfidence --> CheckFinality : consecutive += 1

    CheckFinality --> Finalized : consecutive >= beta
    CheckFinality --> Sampling : consecutive < beta

    Finalized --> BroadcastRotation : Emit RotationEvent to sys.committee-rotations
    BroadcastRotation --> [*]
```

---

### B. Universal Reverse Shadow Contract Cross-Cluster 2PC Lifecycle ([`crates/consensus/src/system_contracts/shadow_contract.rs`](../../crates/consensus/src/system_contracts/shadow_contract.rs))
Governs two-way asset superposition, ownership transfers on destination chains, reverse burns, and $k$-epoch reorg protection.

```mermaid
stateDiagram-v2
    [*] --> OriginLocked : Alice locks native asset on Cluster Alpha
    
    OriginLocked --> ActiveSuperposition : Generate receipt_id & nullifier hash
    ActiveSuperposition --> MeshRelayed : Cross-Mesh relayer transmits state proof to Cluster Beta
    
    state "Cluster Beta (Destination Chain)" as BetaState {
        MeshRelayed --> ShadowMinted : Beta mints shadow instance at virtual_chain_address(1337)
        ShadowMinted --> OwnedByBob : Bob holds full shadow asset ownership
        OwnedByBob --> TransferredToCharlie : Bob sells/transfers shadow token to Charlie
        TransferredToCharlie --> ReverseBurnInitiated : Charlie initiates shadow burn targeting Dan on Alpha
        ReverseBurnInitiated --> ShadowBurnedOnBeta : Destroy shadow instance & emit ShadowBurnReceipt
    }

    ShadowBurnedOnBeta --> AwaitingKDepth : Queue proof in Cross-Mesh Relay
    AwaitingKDepth --> AwaitingKDepth : Current Beta Epoch < BurnedEpoch + k
    AwaitingKDepth --> VerifiedFinality : Current Beta Epoch >= BurnedEpoch + k (k=3)

    VerifiedFinality --> OriginSettlement : Submit ShadowBurnReceipt to Cluster Alpha Vault
    OriginSettlement --> CheckNullifier : Verify nullifier is unspent in Alpha registry
    
    CheckNullifier --> ReplayRejected : Nullifier already spent (Revert / Reject)
    CheckNullifier --> NativeReleased : Nullifier valid & unspent
    
    NativeReleased --> SettledTerminal : Mark nullifier spent & transfer native asset to Dan
    SettledTerminal --> [*]
```

---

## 4. Single Responsibility Summary Matrix

| Daemon | Binary Subcommand | Primary Inbox (Iggy) | Outbox Topics | Primary Concern |
|---|---|---|---|---|
| **Gateway** | `bunny daemon gateway` | Network JSON-RPC (HTTP) | `range.{partitionId}` | L7 ingress, RLP $\to$ SSZ transcoding, Paymaster gasless intent sponsorship. |
| **Committee** | `bunny daemon committee` | `range.{partitionId}` | `sys.state-roots`, `sys.epoch-markers` | Stateless Revm execution over ephemeral witness caches. |
| **Epoch** | `bunny daemon epoch` | `sys.epoch-markers` | `sys.committee-rotations` | Snowman BFT consensus, global epoch cuts, and VRF validator rotation. |
| **Storage** | `bunny daemon storage` | `sys.state-roots` | `sys.storage-partition` | NMT sector partitioning, IPFS/Iroh pinning, BLAKE3 Bao ZK-PoR proofs. |
| **Mesh** | `bunny daemon mesh` | `sys.cross-chain` | Remote BGP peers | Inter-cluster BGP Anycast routing, WireGuard encryption, Reverse Shadow relay. |
| **Identity** | `bunny daemon identity` | Local RPC / P2P | Local Resolver Cache | Multi-curve W3C DID document & `.bunny` social namespace resolution. |
| **Enclave** | `bunny daemon enclave` | Hardware Mailbox | `sys.state-roots` | SGXv2/TDX Gramine hardware-isolated confidential VM execution. |
| **RPC Proxy** | `bunny daemon rpc` | HTTP :8546 | Upstream Node | 48-hour hot state cache and synthetic receipt generation. |
