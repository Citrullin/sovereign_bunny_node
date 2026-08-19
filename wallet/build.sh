#!/bin/bash
# Wallet build script
set -e

# Change directory to script folder
cd "$(dirname "$0")"

echo "Building Rust WASM Wallet using wasm-pack..."
wasm-pack build --target no-modules --out-dir www/pkg

echo "Executing resource inliner..."
python3 build.py

echo "Done!"
