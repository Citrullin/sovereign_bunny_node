# Sparse Merkle Tree (Poseidon-SMT) State Architecture

## 1. Overview

Sovereign Reth migrates its primary state tree from Verkle trees over Bandersnatch to **Poseidon-hashed Sparse Merkle Trees (SMTs)** over the BN254 field.

```
                      [ EpochSMTSnapshot Root ]
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
[ Account & Storage SMT ]                       [ Nullifier & Compliance SMT ]
• Poseidon(Addr || Slot) ──► Value              • Poseidon(IntentID / Account)
• O(log N) Inclusion Proof                      • O(log N) Non-Inclusion Proof
• Zero-overhead Noir Circuit Verification       • Double-Spend & Sanctions Exclusion
```

---

## 2. Why Poseidon-SMT Over Verkle

While Verkle trees (EIP-6800) produce compact vector commitment proofs (~150 bytes), verifying Bandersnatch group operations inside arithmetic SNARK circuits incurs massive constraint counts.

| Metric | Bandersnatch Verkle Tree | Poseidon-SMT (BN254) |
|---|---|---|
| Native Proving Circuit | Expensive (Curve Emulation) | Direct Arithmetic Field ($O(1)$) |
| Proof Generation in Browser | Heavy (>500 MB RAM) | Lightweight (<50 MB RAM) |
| Non-Inclusion Proofs | Complex Multi-point Openings | Direct SMT Sibling Default Zero |
| Noir / Groth16 Prover | ~150,000 Constraints | ~4,200 Constraints per Path |

---

## 3. Leaf & Key Formatting

1. **State & Storage Leaves:**
   $$\text{LeafKey} = \text{Poseidon}(\text{Address} \parallel \text{StorageSlot})$$
   $$\text{LeafValue} = \text{Poseidon}(\text{Nonce} \parallel \text{Balance} \parallel \text{CodeHash} \parallel \text{StorageValue})$$

2. **Compliance & Nullifier Leaves:**
   - **Compliance:** $\text{Key} = \text{Poseidon}(\text{0xC04D0001} \parallel \text{Address})$
   - **Nullifier:** $\text{Key} = \text{Poseidon}(\text{0x0000DEAD} \parallel \text{IntentID})$

3. **Stateless Non-Membership Verification:**
   To prove an intent is unspent or an account is not in an exclusion list, the prover provides an SMT path ending at an empty default zero node, verifiable in a standard Noir circuit.
