# Writing a Lattice Client

A lattice client constructs and submits `LatticeBlock` transactions to the node.
This guide walks through the complete lifecycle using the JSON-RPC transport.

## 1. Register a DID

Before submitting any other transaction type, the account must register a
W3C DID document. This is a `ContractCall` block targeting the DID registry
precompile at `0x00...0003`.

```json
{
  "account": "0xYOUR_ADDRESS",
  "payload": {
    "ContractCall": {
      "target": "0x0000000000000000000000000000000000000003",
      "intent_id": "0x<32-byte-unique-id>",
      "data": "0x<abi-encoded registerDid(string,bytes,string)>"
    }
  },
  "previous_hash": "0x0000...0000",
  "sequence": 1,
  "signature": "0x<65-byte-secp256k1-sig>"
}
```

## 2. Send TBL to another account

A `Send` block debits the sender's balance and creates a pending receive
that the recipient must claim with a matching `Receive` block.

```json
{
  "payload": {
    "Send": {
      "recipient": "0xRECIPIENT",
      "amount": "0x<U256 hex>"
    }
  },
  "sequence": 2,
  ...
}
```

The node verifies:
- Sender has sufficient settled balance
- Sequence is exactly `frontier.sequence + 1`
- `previous_hash` matches the account's current frontier tip
- Signature recovers to the sender's registered DID EVM address

## 3. Receive a Send

The recipient submits a `Receive` block referencing the sender's `Send` block hash:

```json
{
  "payload": {
    "Receive": {
      "send_block_hash": "0x<hash of the Send block>",
      "amount": "0x<same amount as Send>"
    }
  },
  ...
}
```

The node verifies:
- The referenced Send block exists and targets this recipient
- The amount matches exactly
- The Send has not been claimed before (double-receive prevention)

## Signature format

All lattice blocks use a 65-byte secp256k1 signature `[r (32) | s (32) | v (1)]`.
The node attempts recovery against three digest formats and accepts whichever
matches the account's registered EVM address:

1. **EIP-712** — structured-data digest with domain separator
2. **Raw keccak256** of the SCALE-encoded payload
3. **EIP-191** personal-sign envelope

This flexibility lets you use any standard Ethereum signing library.

## Related

- [JSON-RPC Spec](../specifications/json-rpc.md)
- [Account-Lattice Architecture](../architecture/epoch-lattice.md)
- [Implementation Status — Lattice Execution](../implementation-status.md#block-lattice-transaction-execution)
