/**
 * wallet_setup_snap.js
 *
 * Mock Wallet Extension / MetaMask Snap simulation script.
 */

const assert = require('assert');
const crypto = require('crypto');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { keccak256 } = require('viem');

const RPC_URL = process.env.SOVEREIGN_RPC_URL || 'http://localhost:8545';

// Mock master seed (256-bit entropy)
const MASTER_SEED = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';

// Base58 encoder
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function encodeBase58(buffer) {
  const digits = [0];
  for (let i = 0; i < buffer.length; i++) {
    let carry = buffer[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) {
    digits.push(0);
  }
  return digits.reverse().map(digit => ALPHABET[digit]).join('');
}

function generatePeer4Did(privateKeyHex, includeAll = true) {
  const privateKeyBytes = Buffer.from(privateKeyHex.replace('0x', ''), 'hex');
  const secpPubBytes = Buffer.from(secp256k1.ProjectivePoint.BASE.multiply(BigInt('0x' + privateKeyHex.replace('0x', ''))).toRawBytes(true));
  
  const secpMulticodec = Buffer.concat([Buffer.from([0xe7, 0x01]), secpPubBytes]);
  const secpMultibase = 'z' + encodeBase58(secpMulticodec);

  const verificationMethod = [
    { "id": "#key-secp256k1", "type": "EcdsaSecp256k1VerificationKey2019", "publicKeyMultibase": secpMultibase }
  ];

  if (includeAll) {
    const dummyEd = 'z' + encodeBase58(Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.alloc(32)]));
    const dummyBls = 'z' + encodeBase58(Buffer.concat([Buffer.from([0xea, 0x01]), Buffer.alloc(48)]));
    const dummyMl = 'z' + encodeBase58(Buffer.concat([Buffer.from([0x93, 0x01]), Buffer.alloc(32)]));
    const dummySlh = 'z' + encodeBase58(Buffer.concat([Buffer.from([0x94, 0x01]), Buffer.alloc(32)]));
    const dummyFalcon = 'z' + encodeBase58(Buffer.concat([Buffer.from([0x92, 0x01]), Buffer.alloc(32)]));
    const dummyXmss = 'z' + encodeBase58(Buffer.concat([Buffer.from([0x95, 0x01]), Buffer.alloc(32)]));

    verificationMethod.push(
      { "id": "#key-ed25519", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": dummyEd },
      { "id": "#key-bls", "type": "Bls12381G1Key2020", "publicKeyMultibase": dummyBls },
      { "id": "#key-mldsa", "type": "MlDsa65VerificationKey2024", "publicKeyMultibase": dummyMl },
      { "id": "#key-slhdsa", "type": "SlhDsaSha2128fVerificationKey2024", "publicKeyMultibase": dummySlh },
      { "id": "#key-falcon", "type": "Falcon512VerificationKey2024", "publicKeyMultibase": dummyFalcon },
      { "id": "#key-xmss", "type": "XmssSha2256VerificationKey2024", "publicKeyMultibase": dummyXmss }
    );
  }

  const didDocJson = {
    "verificationMethod": verificationMethod
  };

  const jsonStr = JSON.stringify(didDocJson);
  const encoded = Buffer.concat([Buffer.from([0x80, 0x04]), Buffer.from(jsonStr)]);
  const docComp = 'z' + encodeBase58(encoded);

  const hashBytes = crypto.createHash('sha256').update(docComp).digest();
  const prefixed = Buffer.concat([Buffer.from([0x12, 0x20]), hashBytes]);
  const hashComp = 'z' + encodeBase58(prefixed);

  return `did:peer:4${hashComp}:${docComp}`;
}

function signRegistration(didUri, nonce, privateKeyHex) {
  const message = `registerDid:${didUri}:${nonce}`;
  const hash = keccak256(Buffer.from(message));
  const privateKeyBytes = Buffer.from(privateKeyHex.replace('0x', ''), 'hex');
  const sig = secp256k1.sign(Buffer.from(hash.replace('0x', ''), 'hex'), privateKeyBytes);
  
  const rBytes = Buffer.from(sig.r.toString(16).padStart(64, '0'), 'hex');
  const sBytes = Buffer.from(sig.s.toString(16).padStart(64, '0'), 'hex');
  const vByte = Buffer.from([sig.recovery]);
  const sigBytes = Buffer.concat([rBytes, sBytes, vByte]);
  return '0x' + sigBytes.toString('hex');
}

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

  const singleKeyDid = generatePeer4Did(MASTER_SEED, false);
  const multiKeyDid = generatePeer4Did(MASTER_SEED, true);
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
  const nonceFail = Date.now();
  const sigFail = signRegistration(singleKeyDid, nonceFail, MASTER_SEED);
  const resRegFail = await rpcCall('sovereign_registerDid', [singleKeyDid, nonceFail, sigFail]);
  assert.ok(resRegFail.error);
  assert.strictEqual(resRegFail.error.code, -32603);
  assert.ok(resRegFail.error.message.includes('Sovereign DID Error: DID is missing required verification keys'));
  console.log('✅ Correctly blocked: DID is missing required verification keys.');

  // Test C: Register a fully provisioned DID (should SUCCEED)
  console.log('\n🧪 Registering multi-key DID on-chain (sovereign_registerDid)...');
  const nonceSuccess = Date.now();
  const sigSuccess = signRegistration(multiKeyDid, nonceSuccess, MASTER_SEED);
  const resReg = await rpcCall('sovereign_registerDid', [multiKeyDid, nonceSuccess, sigSuccess]);
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
