#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "🚀 Launching Sovereign-Reth node for CLI test..."
./target/debug/sovereign-reth node --dev --http --http.port 8545 > node_cli_test.log 2>&1 &
NODE_PID=$!

cleanup() {
    echo "🛑 Stopping node..."
    kill "$NODE_PID" || true
    wait "$NODE_PID" 2>/dev/null || true
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
./target/debug/did-cli --seedphrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --rpc-url "http://localhost:8545"

echo "🎉 test_did_cli completed successfully!"
