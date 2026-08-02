#!/usr/bin/env bash

# Sovereign-Reth E2E Test Runner script
# Spins up the local node, runs integration tests, and teardown automatically.

set -euo pipefail

# Ensure we are in the repository root directory
cd "$(dirname "$0")/../.."

echo "🛠️  Building Sovereign-Reth..."
cargo build --bin sovereign-reth --bin did-cli --config 'build.rustc-workspace-wrapper=""' -j 1

# Cleanup function to kill background node
cleanup() {
    if [ -n "${NODE_PID:-}" ]; then
        echo "🛑 Stopping Sovereign-Reth node (PID: $NODE_PID)..."
        kill "$NODE_PID" || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "🚀 Launching Sovereign-Reth node in dev mode..."
./target/debug/sovereign-reth node --dev --http --http.port 8545 > node_e2e.log 2>&1 &
NODE_PID=$!

echo "⏳ Waiting for RPC HTTP server to start on port 8545..."
MAX_ATTEMPTS=30
ATTEMPT=0
while ! curl -s -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
    http://127.0.0.1:8545 >/dev/null; do
    
    ATTEMPT=$((ATTEMPT + 1))
    if [ "$ATTEMPT" -ge "$MAX_ATTEMPTS" ]; then
        echo "❌ Error: Node failed to start after $MAX_ATTEMPTS seconds. Logs:"
        cat node_e2e.log
        exit 1
    fi
    sleep 1
done

echo "✅ Node is active! Running E2E Wallet Integration Tests..."
SOVEREIGN_RPC_URL="http://127.0.0.1:8545" node tests/e2e/wallet_setup_snap.js
SOVEREIGN_RPC_URL="http://127.0.0.1:8545" node tests/e2e/wallet_tests.js

echo "🎉 E2E Tests completed successfully!"
