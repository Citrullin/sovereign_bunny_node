/**
 * wallet_setup_snap.js
 *
 * Mock Wallet Extension / MetaMask Snap simulation script.
 * Demonstrates:
 * 1. Master seed entropy definition.
 * 2. SLIP-0010 / BIP-32 multi-curve key derivation (Secp256k1, Ed25519, BLS).
 * 3. Compiling keys into a universal `did:peer` document.
 * 4. Registering the DID via `sovereign_registerDid` to satisfy prerequisites.
 * 5. Attempting CAIP sessions with the registered DID header.
 */

const assert = require('assert');

const RPC_URL = process.env.SOVEREIGN_RPC_URL || 'http://localhost:8545';

// Mock master seed (256-bit entropy)
const MASTER_SEED = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

async function rpcCall(method, params, headers = {}) {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method,
      params,
      id: Date.now()
    })
  });
  if (!response.ok) {
    throw new Error(`HTTP Error: ${response.status}`);
  }
  return response.json();
}

async function runOnboarding() {
  console.log('🚀 Simulating Wallet Snap Onboarding Pipeline...');

  // 1. Derive multi-curve key parameters (mock BIP-32 / SLIP-0010)
  console.log(`🔑 Master Seed: ${MASTER_SEED}`);
  console.log('🌱 Deriving curve keys:');
  console.log('   - m/44\'/60\'/0\'/0/0 (secp256k1) -> EVM Address');
  console.log('   - m/44\'/501\'/0\'/0\' (ed25519) -> Solana Pubkey');
  console.log('   - m/44\'/1234\'/0\'/0\' (bls12-381) -> Committee Pubkey');
  console.log('   - m/44\'/9999\'/0\'/0\' (mldsa-nist) -> Post-Quantum Ml-Dsa Pubkey');
  console.log('   - m/44\'/9999\'/0\'/1\' (slhdsa-nist) -> Post-Quantum Slh-Dsa Pubkey');
  console.log('   - m/44\'/9999\'/0\'/2\' (falcon-nist) -> Post-Quantum Falcon Pubkey');

  // 1. Single-key DID (only secp256k1, missing required ed25519)
  const singleKeyDid = 'did:peer:2.VzQ3shok17vjUvJgqG3Yme5fQwQDndx8C5Jea95D4A8YnUFs2t';
  // 2. Fully-provisioned multi-key DID containing both curves
  const multiKeyDid = 'did:peer:2.VzQ3shok17vjUvJgqG3Yme5fQwQDndx8C5Jea95D4A8YnUFs2t.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  console.log(`📝 Single-Key DID: ${singleKeyDid}`);
  console.log(`📝 Multi-Key DID:  ${multiKeyDid}`);

  // Test A: Attempt a standard CAIP request BEFORE registering the DID (should FAIL)
  console.log('\n🧪 Testing Connection Prerequisite: Initiating session without registered DID (Expected to fail)...');
  const resFail = await rpcCall('wallet_requestPermissions', [{
    "eip155": { "chains": ["eip155:1"] }
  }], {
    'X-Sovereign-Did': multiKeyDid
  });
  assert.ok(resFail.error);
  assert.strictEqual(resFail.error.code, -32001);
  assert.ok(resFail.error.message.includes('Active DID not registered'));
  console.log('✅ Correctly blocked: User is not registered on the mesh.');

  // Test B: Attempt to register a DID missing required keys (should FAIL)
  console.log('\n🧪 Testing Connection Prerequisite: Registering single-key DID missing Ed25519 (Expected to fail)...');
  const resRegFail = await rpcCall('sovereign_registerDid', [singleKeyDid]);
  assert.ok(resRegFail.error);
  assert.strictEqual(resRegFail.error.code, -32603);
  assert.ok(resRegFail.error.message.includes('Sovereign DID Error: DID is missing required verification keys'));
  console.log('✅ Correctly blocked: DID is missing required verification keys.');

  // Test C: Register a fully provisioned DID (should SUCCEED)
  console.log('\n🧪 Registering multi-key DID on-chain (sovereign_registerDid)...');
  const resReg = await rpcCall('sovereign_registerDid', [multiKeyDid]);
  assert.ok(resReg.result);
  assert.strictEqual(resReg.result.status, 'success');
  const mappedAddress = resReg.result.address;
  console.log(`✅ Onboarded successfully! Mapped EVM Address: ${mappedAddress}`);

  // Test D: Attempt the session request AFTER registering (should SUCCEED)
  console.log('\n🧪 Testing Connection Prerequisite: Initiating session with registered multi-key DID (Expected to succeed)...');
  const resSuccess = await rpcCall('wallet_requestPermissions', [{
    "eip155": { "chains": ["eip155:1"] },
    "solana": { "chains": ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"] }
  }], {
    'X-Sovereign-Did': multiKeyDid
  });
  assert.ok(resSuccess.result);
  assert.strictEqual(resSuccess.result.status, 'authorized');
  console.log(`✅ Session authorized: ${resSuccess.result.sessionId}`);

  console.log('\n🎉 Wallet DID Onboarding & Provisioning E2E validation completed successfully!\n');
}

runOnboarding().catch(err => {
  console.error('❌ Onboarding test failed:', err);
  process.exit(1);
});
