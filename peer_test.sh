#!/bin/bash
# Sovereign Reth Local Peer-to-Peer Simulation Network
# Starts a local multi-node network with Node 1 (Validator/Auto-Miner) and Node 2 (Replica) peering via P2P.

set -e

# Configuration
NODE1_HTTP_PORT=8545
NODE1_P2P_PORT=30303
NODE1_AUTH_PORT=8551

NODE2_HTTP_PORT=8546
NODE2_P2P_PORT=30304
NODE2_AUTH_PORT=8552

# Clean up function
cleanup() {
  echo ""
  echo "=== Stopping Local Nodes ==="
  if [ -n "$NODE1_PID" ]; then
    echo "Killing Node 1 (PID $NODE1_PID)..."
    kill "$NODE1_PID" 2>/dev/null || true
  fi
  if [ -n "$NODE2_PID" ]; then
    echo "Killing Node 2 (PID $NODE2_PID)..."
    kill "$NODE2_PID" 2>/dev/null || true
  fi
  exit 0
}

trap cleanup INT TERM EXIT

# Check if binary is built
if [ ! -f "./target/release/sovereign-reth" ]; then
  echo "ERROR: sovereign-reth binary not found at ./target/release/sovereign-reth"
  echo "Please run: ./build.sh --target host"
  exit 1
fi

# Generate JWT secret for AuthRPC interface
if [ ! -f "jwt.hex" ]; then
  echo "Generating JWT secret..."
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > jwt.hex
  else
    echo "0xec2f1f0a2d594b2da96fb24caef02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a" > jwt.hex
  fi
fi

# Clean old data directories
echo "=== Resetting Databases ==="
rm -rf db1 db2 node1.log node2.log

# Initialize genesis storage
echo "=== Initializing Node 1 ==="
./target/release/sovereign-reth init --chain genesis.json --datadir db1

echo "=== Initializing Node 2 ==="
./target/release/sovereign-reth init --chain genesis.json --datadir db2

# Start Node 1 (Validator / Auto-Mining Mode)
echo "=== Starting Node 1 (Validator/Auto-Miner) ==="
./target/release/sovereign-reth node \
  --dev \
  --chain genesis.json \
  --datadir db1 \
  --http --http.port $NODE1_HTTP_PORT --http.api all --http.corsdomain "*" \
  --port $NODE1_P2P_PORT \
  --discovery.port $NODE1_P2P_PORT \
  --discovery.addr 127.0.0.1 \
  --addr 127.0.0.1 \
  --authrpc.port $NODE1_AUTH_PORT \
  --authrpc.jwtsecret jwt.hex \
  > node1.log 2>&1 &
NODE1_PID=$!

echo "Node 1 started with PID $NODE1_PID. Waiting for startup..."
sleep 3

# Retrieve enode address from Node 1
echo "=== Retrieving Node 1 Enode URL ==="
ENODE=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}' http://localhost:$NODE1_HTTP_PORT | grep -o 'enode://[^"]*' || true)

if [ -z "$ENODE" ]; then
  # Fallback: scan node1.log for enode
  ENODE=$(grep -o 'enode://[^ ]*' node1.log | head -n 1 || true)
fi

if [ -z "$ENODE" ]; then
  echo "WARNING: Failed to retrieve enode URL. Peering may not occur automatically."
  echo "Node 1 Log output:"
  tail -n 20 node1.log
else
  echo "Node 1 Enode URL: $ENODE"
fi

# Start Node 2 (Replica / Peering Mode)
echo "=== Starting Node 2 (Replica) ==="
./target/release/sovereign-reth node \
  --node-type replica \
  --chain genesis.json \
  --datadir db2 \
  --http --http.port $NODE2_HTTP_PORT --http.api all --http.corsdomain "*" \
  --port $NODE2_P2P_PORT \
  --discovery.port $NODE2_P2P_PORT \
  --discovery.addr 127.0.0.1 \
  --addr 127.0.0.1 \
  --authrpc.port $NODE2_AUTH_PORT \
  --authrpc.jwtsecret jwt.hex \
  ${ENODE:+--bootnodes "$ENODE"} \
  > node2.log 2>&1 &
NODE2_PID=$!

echo "Node 2 started with PID $NODE2_PID. Waiting for peering..."
sleep 3

echo ""
echo "=== Simulation Network is Active ==="
echo "Node 1 (Validator/Auto-Miner) RPC: http://localhost:$NODE1_HTTP_PORT"
echo "Node 2 (Replica) RPC: http://localhost:$NODE2_HTTP_PORT"
echo ""
echo "Monitoring blocks:"
echo "Node 1 block number: \$(curl -s -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}' http://localhost:$NODE1_HTTP_PORT | grep -o '\"result\":\"[^\"]*\"')"
echo "Node 2 block number: \$(curl -s -X POST -H 'Content-Type: application/json' --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}' http://localhost:$NODE2_HTTP_PORT | grep -o '\"result\":\"[^\"]*\"')"
echo ""
echo "You can view logs with: tail -f node1.log or tail -f node2.log"
echo "Press [Ctrl+C] to stop the nodes and exit the simulation."
echo ""

# Keep script running
while true; do
  sleep 1
done
