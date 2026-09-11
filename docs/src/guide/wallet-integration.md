# Wallet Integration

The Sovereign Bunny wallet is a WASM module (built with `wasm-bindgen`) that
runs in the browser and handles all signing, DID registration, and lattice
block construction client-side. No private key material ever leaves the browser.

## Build the wallet

```sh
cd wallet/
python build.py   # runs wasm-pack, TypeScript tsc, bundles assets
```

Output is in `wallet/app/` — a self-contained static site with no external CDN dependencies.

## Two integration modes

### Mode 1: Legacy (MetaMask / Rabby compatible)

Transactions are submitted as standard `eth_sendRawTransaction` JSON-RPC calls.
When quantum wrapping is enabled, the inner PQ-signed payload is encapsulated
in an EIP-8141 multi-frame envelope signed by the user's classical secp256k1
key — existing hardware wallets (Ledger, Trezor) sign the outer envelope
without protocol changes.

### Mode 2: Native (CAIP-25 / gRPC)

`StatelessTransitionFrame` messages with native PQ signatures and UltraHonk
SNARK witnesses are transmitted directly via gRPC over HTTP/3. ~70% lower
packet overhead than JSON-RPC.

## DID Registration flow

1. Wallet generates a secp256k1 keypair (and optionally a ML-DSA-65 keypair)
2. Constructs a W3C DID document with `did:sovereign:[chain_id]:[address]`
3. Encodes the registration as a `ContractCall` lattice block targeting the
   DID registry precompile (`0x00...0003`)
4. Signs with the classical key (or PQ key if quantum mode active)
5. Submits via `eth_sendRawTransaction` or gRPC

Once the DID block is included, the account can submit any other lattice block
types (Send, Receive, ContractCall for other targets).

## Related

- [API Transport Matrix](../specifications/transport-matrix.md)
- [ZK-OIDC Authentication](../architecture/zk-oidc.md)
- [JSON-RPC Spec](../specifications/json-rpc.md)
