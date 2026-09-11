#!/bin/bash
# Sovereign Reth Build and Deployment Script
# Enforces resource constraints to prevent WSL OOM system freezes and limits disk storage footprint.

set -e

TARGET="host"
CLEAN_ONLY=false

# Help message
show_help() {
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  --target <target>   Build target: host (default), x86, ARM, RISC-V, or ALL"
  echo "  --clean             Stop compiler daemons, clear sccache, clean cargo workspace, and exit"
  echo "  --help              Show this help message"
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --clean)
      CLEAN_ONLY=true
      shift
      ;;
    --help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

# Resource Boundary setup for compiler wrapper and cache
export SCCACHE_CACHE_SIZE="5G"
export SCCACHE_IDLE_TIMEOUT="1800"

# Stop sccache server and clean if clean requested
if [ "$CLEAN_ONLY" = true ]; then
  echo "=== Cleaning Sovereign Reth Workspace ==="
  if command -v sccache >/dev/null 2>&1; then
    echo "Stopping sccache compiler daemon..."
    sccache --stop-server 2>/dev/null || true
  fi
  echo "Removing sccache disk storage..."
  rm -rf ~/.cache/sccache/
  echo "Cleaning Cargo build artifacts..."
  cargo clean
  echo "Cleaning database data directories..."
  rm -rf db/
  echo "Workspace cleaned successfully!"
  exit 0
fi

# Start sccache server without artificial virtual memory limits (single-thread jobs=1 prevents host OOM)
if command -v sccache >/dev/null 2>&1; then
  echo "=== Starting sccache ==="
  sccache --stop-server 2>/dev/null || true
  sccache --start-server 2>/dev/null || true
fi

echo "=== Step 1: Compiling Smart Contracts ==="
cd contracts
mkdir -p out
if [ ! -d "node_modules/solc" ]; then
  if [ -f "src/SimplePaymaster.runtime.bin" ]; then
    echo "Using vendored SimplePaymaster runtime bytecode..."
    cp src/SimplePaymaster.runtime.bin out/SimplePaymaster.runtime.bin
  else
    echo "Installing contracts dependencies (solc)..."
    npm install --prefer-offline --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund || true
  fi
fi

if [ -d "node_modules/solc" ]; then
  node compile.js
elif [ -f "src/SimplePaymaster.runtime.bin" ] && [ ! -f "out/SimplePaymaster.runtime.bin" ]; then
  cp src/SimplePaymaster.runtime.bin out/SimplePaymaster.runtime.bin
fi
cd ..

echo "=== Step 2: Generating Genesis Configuration ==="
node build_genesis.js

echo "=== Step 3: Compiling Node ==="
# Export compilation flags that enforce single-job execution and high-split LLVM compilation units
export RUSTC_BOOTSTRAP=1
# Use codegen-units=16 to dramatically reduce peak compiler memory compared to codegen-units=1
export RUSTFLAGS="-Z mir-opt-level=0 -C codegen-units=16 -C opt-level=0 -C debuginfo=0 -C llvm-args=-threads=1 -C link-arg=-fuse-ld=mold -C link-arg=-Wl,--no-keep-memory -C link-arg=-Wl,--strip-all"
export CXX=g++
export CC=gcc
export NUM_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=1
export RUST_MIN_STACK=33554432

# Helper to verify cross-compilation toolchains are present before attempting builds
check_compiler() {
  local cmd=$1
  local pkg=$2
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Cross-compiler '$cmd' is not installed."
    echo "Please install it using: sudo apt-get update && sudo apt-get install -y gcc-$pkg"
    exit 1
  fi
}

build_target() {
  local t=$1
  echo "--- Building Target: $t ---"
  if [ "$t" = "host" ]; then
    cargo build --release -j 1
  else
    rustup target add "$t"
    if [ "$t" = "aarch64-unknown-linux-gnu" ]; then
      check_compiler "aarch64-linux-gnu-gcc" "aarch64-linux-gnu"
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    elif [ "$t" = "riscv64gc-unknown-linux-gnu" ]; then
      check_compiler "riscv64-linux-gnu-gcc" "riscv64-linux-gnu"
      export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc
    fi
    cargo build --release --target "$t" -j 1
  fi
}

case $TARGET in
  host)
    build_target "host"
    ;;
  x86)
    build_target "x86_64-unknown-linux-gnu"
    ;;
  ARM)
    build_target "aarch64-unknown-linux-gnu"
    ;;
  RISC-V)
    build_target "riscv64gc-unknown-linux-gnu"
    ;;
  ALL)
    build_target "x86_64-unknown-linux-gnu"
    build_target "aarch64-unknown-linux-gnu"
    build_target "riscv64gc-unknown-linux-gnu"
    ;;
  *)
    echo "Invalid target: $TARGET"
    echo "Supported targets: host, x86, ARM, RISC-V, ALL"
    exit 1
    ;;
esac

echo "=== Step 3b: Compiling WebAssembly Wallet ==="
if command -v wasm-pack >/dev/null 2>&1; then
  cd wallet
  # Clear RUSTFLAGS temporarily to avoid target-incompatible linker flags from host build
  RUSTFLAGS="" wasm-pack build --target no-modules --out-dir www/pkg
  echo "Inlining HTML/CSS/JS frontend assets into wallet/app..."
  python3 build.py
  cd ..
else
  echo "⚠️ wasm-pack not found. Skipping Rust WASM wallet compilation."
  echo "If you want to compile the wallet, please install wasm-pack (curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh)."
  # Still try to run build.py to inline existing pkg assets
  if [ -f "wallet/build.py" ]; then
    cd wallet
    python3 build.py || true
    cd ..
  fi
fi

echo "=== Step 4: Re-initializing Database ==="
rm -rf db
if [ "$TARGET" = "host" ] || [ "$TARGET" = "x86" ] || [ "$TARGET" = "ALL" ]; then
  # Determine local compiled binary path
  BIN_PATH="./target/release/sovereign-reth"
  if [ "$TARGET" = "x86" ]; then
    BIN_PATH="./target/x86_64-unknown-linux-gnu/release/sovereign-reth"
  fi
  
  if [ -f "$BIN_PATH" ]; then
    echo "Running storage database initialization..."
    "$BIN_PATH" init --chain genesis.json --datadir db
  else
    echo "Compiled binary not found at $BIN_PATH; skipping storage init."
  fi
else
  echo "Cross-compiled build completed. Database init skipped (requires host runner)."
fi

echo "=== Build Complete! ==="
