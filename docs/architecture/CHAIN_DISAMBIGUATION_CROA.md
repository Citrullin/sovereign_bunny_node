# Cryptographic Chain Disambiguation, BGP CROAs & SMT Conflict Resolution

## 1. Overview & Threat Model

In decentralized multi-chain and sovereign manifold topologies, self-reported integer `chain_id`s (e.g., `chain_id = 1`) and human-readable network names (e.g., `alpha.mesh`) create severe vulnerabilities:
- **Malicious Chain Collisions**: An attacker spinning up an Ethereum Classic or testnet node claiming `chain_id = 1` to impersonate Ethereum Mainnet.
- **BGP Route Hijacking**: A rogue node announcing routes for virtual address prefix `0x00..0100` (`chain_id = 1`) over BGP Anycast to intercept bridge traffic.
- **Namespace Squatting / Frontrunning**: Two sovereign clusters simultaneously broadcasting registrations for the same human-readable `.mesh` namespace.

The Sovereign Bunny mesh enforces conflict resolution through a **four-tier defense**:

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         FOUR-TIER DISAMBIGUATION DEFENSE                    │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │ Tier 1: Canonical Genesis & Fork-Digest Hash (eBPF NIC Drop)               │
 │ Tier 2: BGP Chain Route Origin Authorization (CROA / RPKI Validation)       │
 │ Tier 3: Snowman-Ordered SMT Inscriptions with VRF Deterministic Tie-Breaking│
 │ Tier 4: ZK Light-Client Verification (Noir Sync Committee / PoW Circuits)   │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Tier 1: The CAIP-2 / Fork-Digest Anchor

In `bunny-demux` and `bunny-mesh`, an integer `chain_id` is strictly a local routing alias bound to an immutable **Canonical Chain Descriptor**:

$$\text{CanonicalChainID} = \text{Poseidon}(\text{chain\_id}, \text{genesis\_header\_hash}, \text{genesis\_state\_root}, \text{fork\_digest})$$

```
[ Inbound Wire Frame ]
  • Claims: chain_id = 0x0001
              │
              ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                     BUNNY-DEMUX / GATEWAY                   │
 │                                                             │
 │  1. Looks up SMT Root for chain_id = 0x0001                 │
 │  2. Evaluates Canonical Hash:                               │
 │     • Ethereum Mainnet: Poseidon(1, 0xd4e567..., 0x1f2a...)  │
 │     • Attacker (ETC):   Poseidon(1, 0xd4e567..., 0x9b3c...)  │
 │  3. MISMATCH DETECTED ──► Drop Packet at eBPF Layer (0-cost)│
 └─────────────────────────────────────────────────────────────┘
```

- **Ethereum vs. Ethereum Classic**: While both share genesis block 0, their fork histories diverge at block 1,920,000 (The DAO hard fork). Their EIP-2124 `fork_digest` values are cryptographically distinct.
- **Hardware Enforcement**: `bunny-demux` filters inbound packets via an eBPF map populated by `bunny-epoch`. If the claimed `fork_digest` does not match the canonical hash committed to the lattice state root, the packet is dropped at the NIC level before consuming CPU cycles.

---

## 3. Tier 2: Chain Route Origin Authorization (CROA / BGP Mesh)

Inspired by BGP RPKI (Resource Public Key Infrastructure), the P2P mesh uses **Chain Route Origin Authorizations (CROAs)** to prevent unauthorized peers from announcing routes for sovereign manifolds or foreign chains:

```rust
struct CROA {
    canonical_chain_id: [u8; 32],      // Unique Poseidon hash
    authorized_asn: u32,               // BGP Autonomous System Number
    validator_quorum_pubkey: [u8; 96], // BLS threshold key of sub-committee
    valid_until_epoch: u64,            // Expiration epoch marker
}
```

### Route Announcement Verification Flow
1. When a cluster node joins the BGP mesh and advertises a route for virtual address prefix `0x00..0100` (`chain_id = 1`), it must present a valid CROA signature signed by the threshold key of the sub-committee responsible for that bridge.
2. If a rogue node advertises an invalid route, neighboring FRR/BGP routers flag the announcement as **RPKI Invalid** and suppress route propagation across the 400GbE dark fiber fabric.

---

## 4. Tier 3: Namespace Conflict Resolution (*.mesh)

When two independent sovereign clusters simultaneously claim a human-readable namespace (e.g., both claim `alpha.mesh` with different public keys):

```
Cluster A claims "alpha.mesh" (Tx_A) ──┐
                                     ├──► [ Snowman Meta-Consensus ] ──► Finalized Epoch Cut
Cluster B claims "alpha.mesh" (Tx_B) ──┘                                 (Only Tx_A included)
                                                                                  │
                                                                                  ▼
                                                                     Cluster B gets SMT Nullifier
                                                                     (Must pick "alpha-2.mesh")
```

1. **Epoch Cut Ordering**: Namespace registrations are submitted as intents to the global registry address (`0x0000000000000000000000000000000000000003`).
2. **Deterministic Tie-Breaking**: If two clusters broadcast registrations within the same $k$-round Paxos window, the global Snowman consensus breaks the tie using the deterministic VRF beacon seed of the epoch:

$$\text{Winner} = \min\Big(\text{Poseidon}(\text{Seed}_E, \text{Tx}_A), \text{Poseidon}(\text{Seed}_E, \text{Tx}_B)\Big)$$

3. **Sparse Merkle Tree (SMT) Mutation**: The winning claim occupies the SMT leaf `Poseidon("alpha.mesh")`. The losing claim is rejected, its bonded registration deposit is refunded (or burned if flagged as malicious), and the winning route propagates to all nodes via `sys.zkdns-updates`.

---

## 5. Tier 4: ZK Light-Client Verification for Foreign Chains

For cross-chain message passing and Saga escrows, `bunny-mesh` executes Noir ZK Light-Client circuits rather than trusting raw validator assertions:

| Foreign Chain Claim | Verification Mechanism | Defense Against Spoofing Attack |
|---|---|---|
| **Ethereum Mainnet (`0x01`)** | Noir circuit validates Sync Committee BLS threshold signatures (Altair/Casper) against the latest finalized Beacon State Root. | An attacker running Ethereum Classic cannot produce Casper Sync Committee signatures $\to$ Proof generation fails $\to$ Transaction rejected. |
| **Bitcoin / UTXO (`0x02`)** | Noir circuit verifies SHA-256 Proof-of-Work difficulty target and cumulative chainwork over 6 blocks. | A forged chain without proof-of-work is rejected in ZK. |
| **Sovereign Bunny Mesh (`0x...`)** | Verifies $2f+1$ Snowman Epoch Marker signatures against the active validator stake table in the Lattice root. | Malicious nodes lacking stake cannot produce valid threshold markers. |

---

## 6. Canonical SSZ Data Structure: `ChainRegistrationDescriptor`

```yaml
  ChainRegistrationDescriptor:
    description: "Cryptographic binding for registered namespaces and chain IDs"
    fields:
      - name: chain_id
        type: uint64
        offset: 0..8
      - name: name_hash
        type: Vector[uint8, 32]
        offset: 8..40
      - name: genesis_header_hash
        type: Vector[uint8, 32]
        offset: 40..72
      - name: fork_digest
        type: Vector[uint8, 4]
        offset: 72..76
      - name: consensus_type
        type: uint8
        offset: 76..77
        enum: [1: EthereumAltair, 2: BitcoinPoW, 3: BunnySnowman, 4: TendermintBFT]
      - name: light_client_root
        type: Vector[uint8, 32]
        offset: 77..109
      - name: registration_epoch
        type: uint64
        offset: 109..117
      - name: authority_signature
        type: Vector[uint8, 96]
        offset: 117..213
```
