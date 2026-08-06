#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "🧹 Cleaning up port 8545..."
fuser -k 8545/tcp || true
sleep 1

echo "🚀 Launching Sovereign-Reth node for CLI test..."
TEST_DB="/tmp/sovereign-reth-cli-db-$(date +%s)"
rm -rf "$TEST_DB"
mkdir -p "$TEST_DB"

./target/debug/sovereign-reth node --dev --datadir "$TEST_DB" --http --http.port 8545 > node_cli_test.log 2>&1 &
NODE_PID=$!

cleanup() {
    echo "🛑 Stopping node..."
    kill "$NODE_PID" || true
    wait "$NODE_PID" 2>/dev/null || true
    rm -rf "$TEST_DB" || true
}
trap cleanup EXIT

echo "⏳ Waiting for RPC HTTP server to start..."
while ! curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
    http://127.0.0.1:8545 >/dev/null; do
    sleep 1
done

echo "✅ Node is active! Running did-cli with --seed..."
./target/debug/did-cli --seed "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" --rpc-url "http://localhost:8545"

echo "✅ Running did-cli with --seedphrase..."
OUTPUT=$(./target/debug/did-cli --seedphrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --rpc-url "http://localhost:8545")
echo "$OUTPUT"

# Extract generated DID
FULL_DID=$(echo "$OUTPUT" | grep -o 'did:peer:4[^ ]*')
SHORT_DID=$(echo "$FULL_DID" | cut -d':' -f1-3)

echo "✅ Querying registered short DID using did-cli get..."
./target/debug/did-cli get --did "$SHORT_DID" --rpc-url "http://localhost:8545"

echo "✅ Querying registered EVM Address DID using did-cli get..."
./target/debug/did-cli get --did "did:peer:0x9858effd232b4033e47d90003d41ec34ecaeda94" --rpc-url "http://localhost:8545"

echo "✅ Querying registered did:sovereign using did-cli get..."
GET_OUTPUT=$(./target/debug/did-cli get --did "did:sovereign:1337:0x9858effd232b4033e47d90003d41ec34ecaeda94" --rpc-url "http://localhost:8545")
echo "$GET_OUTPUT"

# Extract ed25519 verification key from get output to test reverse lookup on sub-keys
ED25519_KEY=$(echo "$GET_OUTPUT" | grep -oE 'ed25519: z[1-9A-HJ-NP-Za-km-z]+' | cut -d' ' -f2)
echo "Extracted Ed25519 Key: $ED25519_KEY"

echo "✅ Querying registered Ed25519 public key DID using did-cli get..."
./target/debug/did-cli get --did "did:peer:$ED25519_KEY" --rpc-url "http://localhost:8545"

echo "✅ Querying registered Ed25519 public key DID WITHOUT did:peer prefix..."
./target/debug/did-cli get --did "$ED25519_KEY" --rpc-url "http://localhost:8545"

echo "✅ Querying registered Ed25519 public key DID via did:sovereign prefix..."
./target/debug/did-cli get --did "did:sovereign:1337:$ED25519_KEY" --rpc-url "http://localhost:8545"

# Strip did:peer: prefix from full DID
STRIPPED_FULL_DID="${FULL_DID#did:peer:}"
echo "✅ Querying registered full DID WITHOUT did:peer prefix..."
./target/debug/did-cli get --did "$STRIPPED_FULL_DID" --rpc-url "http://localhost:8545"

echo "🎉 test_did_cli completed successfully!"
