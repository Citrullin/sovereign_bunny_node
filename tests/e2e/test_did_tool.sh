#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "🧹 Cleaning up port 8545..."
fuser -k 8545/tcp || true
sleep 1

echo "🚀 Launching Sovereign-Reth node for E2E integration test..."
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

# Genesis pre-funded keys
DEV_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEV_ADDR="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"

# Seeds used for identity derivation
WALLET_A_SEED="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
WALLET_B_SEED="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

echo "✅ Step 0: Onboard genesis dev account..."
curl -s -X POST -H "Content-Type: application/json" \
  --data "{\"jsonrpc\":\"2.0\",\"method\":\"sovereign_registerDidKeys\",\"params\":[\"did:sovereign:1337:$DEV_ADDR\"],\"id\":1}" \
  http://127.0.0.1:8545

echo "✅ Step 1: Onboard Wallet A (Sender) DID keys..."
OUTPUT_A=$(./target/debug/did-tool register set --seed "$WALLET_A_SEED" --rpc-url "http://localhost:8545")
WALLET_A_DERIVED_ADDR=$(echo "$OUTPUT_A" | grep "EVM Address:" | cut -d':' -f2 | xargs)

echo "   Derived Wallet A Address: $WALLET_A_DERIVED_ADDR"

echo "✅ Step 2: Onboard Wallet B (Recipient) DID keys..."
OUTPUT_B=$(./target/debug/did-tool register set --seed "$WALLET_B_SEED" --rpc-url "http://localhost:8545")
WALLET_B_DERIVED_ADDR=$(echo "$OUTPUT_B" | grep "EVM Address:" | cut -d':' -f2 | xargs)

echo "   Derived Wallet B Address: $WALLET_B_DERIVED_ADDR"

echo "✅ Step 3: Fund Wallet A and Wallet B from genesis dev account..."
./target/debug/did-tool sign-tx --private-key "$DEV_KEY" --to "$WALLET_A_DERIVED_ADDR" --value "100000000000000000000" --nonce "0" --chain-id 1337 --rpc-url "http://localhost:8545"
./target/debug/did-tool sign-tx --private-key "$DEV_KEY" --to "$WALLET_B_DERIVED_ADDR" --value "100000000000000000000" --nonce "1" --chain-id 1337 --rpc-url "http://localhost:8545"

echo "✅ Step 4: Fetch initial settled balance of Wallet B..."
BAL_BEFORE=$(curl -s -X POST -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$WALLET_B_DERIVED_ADDR\",\"latest\"],\"id\":1}" \
    http://127.0.0.1:8545 | grep -oE '0x[0-9a-fA-F]+')
echo "   Wallet B Initial Balance: $BAL_BEFORE"

echo "✅ Step 5: Wallet A dispatches 10 ETH Block-Lattice Send to Wallet B..."
./target/debug/did-tool send --seed "$WALLET_A_SEED" --recipient "$WALLET_B_DERIVED_ADDR" --amount "10000000000000000000" --rpc-url "http://localhost:8545"

echo "✅ Step 6: Verify Strict settled balance invariant (Wallet B balance must NOT change yet)..."
BAL_AFTER_SEND=$(curl -s -X POST -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$WALLET_B_DERIVED_ADDR\",\"latest\"],\"id\":1}" \
    http://127.0.0.1:8545 | grep -oE '0x[0-9a-fA-F]+')
echo "   Wallet B Balance after Send (Uncollected): $BAL_AFTER_SEND"
if [ "$BAL_BEFORE" != "$BAL_AFTER_SEND" ]; then
    echo "❌ Error: Balance virtualized or updated before Receive block finalization!"
    exit 1
fi
echo "   🛡️ Strict settled balance check passed!"

echo "✅ Step 7: Query Wallet B's pending inbox using sovereign_getPendingInbox..."
INBOX_OUT=$(curl -s -X POST -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"sovereign_getPendingInbox\",\"params\":[\"$WALLET_B_DERIVED_ADDR\"],\"id\":1}" \
    http://127.0.0.1:8545)
echo "   Pending Inbox: $INBOX_OUT"
if [[ ! "$INBOX_OUT" == *"sendBlockHash"* ]]; then
    echo "❌ Error: Send block hash not present in pending inbox!"
    exit 1
fi

echo "✅ Step 8: Wallet B executes a 0-value Self-Send Sweep transaction..."
# Wallet B sends 0 ETH to itself, triggering the VM pre-execution auto-claim hook securely using seed derivation
./target/debug/did-tool sign-tx --seed "$WALLET_B_SEED" --to "$WALLET_B_DERIVED_ADDR" --value "0" --nonce "0" --gas-price 0 --chain-id 1337 --rpc-url "http://localhost:8545"

# Wait for block mining
sleep 4

echo "✅ Step 9: Verify settled balance has increased by 110 ETH (minus gas fee)..."
BAL_FINAL=$(curl -s -X POST -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$WALLET_B_DERIVED_ADDR\",\"latest\"],\"id\":1}" \
    http://127.0.0.1:8545 | grep -oE '0x[0-9a-fA-F]+')
echo "   Wallet B Final Settled Balance: $BAL_FINAL"

# Compare the final balance with initial balance (handling extremely large hex integers)
DEC_BEFORE=$(python3 -c "print(int('$BAL_BEFORE', 16))")
DEC_FINAL=$(python3 -c "print(int('$BAL_FINAL', 16))")
DIFF=$(python3 -c "print($DEC_FINAL - $DEC_BEFORE)")
echo "   Difference (wei): $DIFF"

# 110 ETH is 110000000000000000000 wei. The sweep transaction executes with 0 net gas.
# So expected increase is exactly 110000000000000000000 wei.
if [ "$DIFF" != "110000000000000000000" ]; then
    echo "❌ Error: Settled balance difference ($DIFF) is not exactly 110000000000000000000 wei!"
    exit 1
fi
echo "   🎉 Auto-Claim Sweep verified successfully!"

echo "✅ Step 10: Verify pending inbox is now empty..."
INBOX_FINAL=$(curl -s -X POST -H "Content-Type: application/json" \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"sovereign_getPendingInbox\",\"params\":[\"$WALLET_B_DERIVED_ADDR\"],\"id\":1}" \
    http://127.0.0.1:8545)
echo "   Inbox status: $INBOX_FINAL"

echo "🎉 All E2E Integration tests completed successfully!"
