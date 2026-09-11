/**
 * E2E Wallet Integration Tests for Sovereign Bunny.
 *
 * Verifies:
 * 1. CAIP-25, 211, 285, 311, 312 Session Lifecycle.
 * 2. CAIP-10 / CAIP-2 Chain-Agnostic identifiers.
 * 3. CAIP-319 Notifications (asynchronous callbacks).
 * 4. CAIP-358 Payments.
 * 5. CAIP-375 & EIP-712 Message Signing.
 * 6. CAIP-390 Caching vs Consensus Economics (CAIP-404).
 * 7. CAIP-345 Intelligent Mesh Relaying.
 */

const assert = require('assert');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const crypto = require('crypto');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { keccak256 } = require('viem');

const RPC_URL = process.env.SOVEREIGN_RPC_URL || 'http://localhost:8545';

const MASTER_SEED = '0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba';

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

let USER_DID;

async function rpcCall(method, params, headers = {}) {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Sovereign-Did': USER_DID,
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

function getDidToolPath() {
  const paths = [
    path.resolve(__dirname, '../../target/debug/did-tool'),
    path.resolve(__dirname, '../../target/release/did-tool'),
    path.resolve(__dirname, '../target/debug/did-tool'),
    path.resolve(__dirname, '../target/release/did-tool'),
    path.resolve('target/debug/did-tool'),
    path.resolve('target/release/did-tool'),
  ];
  for (const p of paths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  throw new Error("did-tool binary not found!");
}

async function runTests() {
  console.log('🚀 Starting Sovereign Bunny CAIP E2E Integration Tests...\n');

  USER_DID = generatePeer4Did(MASTER_SEED, true);

  // Pre-onboard: Register the user DID via standard transaction targeting SYSTEM_DID_REGISTRY using did-tool
  console.log('📝 Registering user DID on-chain via did-tool...');
  const didToolPath = getDidToolPath();
  const registerCmd = `"${didToolPath}" register set --seed ${MASTER_SEED} --rpc-url ${RPC_URL}`;
  const regOutput = execSync(registerCmd).toString().trim();
  console.log(`  did-tool register output: ${regOutput}`);
  assert.ok(regOutput.includes('Broadcast Succeeded!'), "DID registration must succeed");
  console.log(`✅ Onboarded user DID: ${USER_DID}`);

  // Test 1: CAIP-25 Session Initiation
  console.log('\n🧪 Test 1: Initiating CAIP-25 Session (wallet_requestPermissions)...');
  const resSession = await rpcCall('wallet_requestPermissions', [{
    "eip155": { "chains": ["eip155:1"] },
    "solana": { "chains": ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"] }
  }]);
  assert.ok(resSession.result);
  assert.strictEqual(resSession.result.status, 'authorized');
  const sessionId = resSession.result.sessionId;
  console.log(`✅ Session initiated: ${sessionId}`);

  // Test 2: CAIP-312 Session State Retrieval
  console.log('\n🧪 Test 2: Retrieving Session state (wallet_getSession)...');
  const resGetSess = await rpcCall('wallet_getSession', []);
  assert.strictEqual(resGetSess.result.status, 'active');
  assert.ok(resGetSess.result.chains.includes('solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'));
  console.log('✅ Active session retrieved successfully.');

  // Test 3: CAIP-319 Asynchronous Notifications
  console.log('\n🧪 Test 3: Querying Saga Intent status (wallet_getNotification)...');
  const resNotify = await rpcCall('wallet_getNotification', ['intent_tx_9999']);
  assert.strictEqual(resNotify.result.status, 'completed');
  console.log('✅ Saga Intent notifications resolved.');

  // Test 4: CAIP-358 Universal Payments
  console.log('\n🧪 Test 4: Creating universal payment (wallet_pay)...');
  const resPay = await rpcCall('wallet_pay', [{
    "amount": "1000000",
    "asset": "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
  }]);
  assert.strictEqual(resPay.result.status, 'paid');
  console.log('✅ Payment completed successfully.');

  // Test 5: CAIP-375 Message Signing
  console.log('\n🧪 Test 5: Requesting chain-agnostic signature (wallet_signMessage)...');
  const resSign = await rpcCall('wallet_signMessage', ['Hello Sovereign Mesh']);
  assert.ok(resSign.result.startsWith('0x'));
  console.log('✅ Message signed successfully.');

  // Test 6: CAIP-390 Metadata Caching & Consensus (CAIP-404)
  console.log('\n🧪 Test 6: Retrieving cached CAIP-390 metadata...');
  const resMetaCached = await rpcCall('wallet_getAssetMetadata', [
    'eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'
  ]);
  assert.strictEqual(resMetaCached.result.symbol, 'USDC');
  console.log('✅ Served cached metadata directly (Free Path).');

  console.log('🧪 Test 6.1: Querying uncached metadata (triggering consensus/CAIP-404)...');
  const resMetaUncached = await rpcCall('wallet_getAssetMetadata', [
    'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:unknown'
  ]);
  assert.ok(resMetaUncached.error);
  assert.strictEqual(resMetaUncached.error.code, -32004);
  assert.strictEqual(resMetaUncached.error.message, 'Consensus Required / Saga Intent needed');
  console.log('✅ Successfully triggered CAIP-404 Consensus Required error.');

  // Test 7: CAIP-345 Relaying using headers
  console.log('\n🧪 Test 7: Executing CAIP-345 transaction relaying to foreign namespace...');
  const resRelay = await rpcCall('eth_sendRawTransaction', ['0xMockRawPayload'], {
    'X-Sovereign-Chain-Id': 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
  });
  assert.ok(resRelay.result);
  console.log('✅ Transaction dynamically routed and relayed to best-reputed peer.');

  // Test 8: CAIP-285 Session Revocation
  console.log('\n🧪 Test 8: Revoking session (wallet_revokeSession)...');
  const resRevoke = await rpcCall('wallet_revokeSession', [sessionId]);
  assert.strictEqual(resRevoke.result, true);
  console.log('✅ Session revoked.');

  // Test 9: Out-of-Band Stateless Witness Resolution
  console.log('\n🧪 Test 9: Resolving stateless witness via IPFS (sovereign_getStatelessWitness)...');
  const resWitness = await rpcCall('sovereign_getStatelessWitness', ['mock_cid_abcdef1234567890']);
  assert.ok(resWitness.result);
  assert.ok(resWitness.result.balance);
  assert.ok(resWitness.result.quadrantMatrix);
  console.log('✅ Stateless witness resolved from IPFS mock backend successfully.');

  // Test 10: Legacy Rabby Proxy translation
  console.log('\n🧪 Test 10: Verifying legacy wallet translation proxy (eth_getBalance & eth_getTransactionCount)...');
  const SENDER_A = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
  const RECEIVER_B = '0xa11b4bafdad6661fc5ab1a3fd47bb4653c22ce83';
  const SENDER_A_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

  const resLegacyBal = await rpcCall('eth_getBalance', [SENDER_A, 'latest']);
  assert.ok(resLegacyBal.result.startsWith('0x'));
  const initialSenderBalance = BigInt(resLegacyBal.result);
  console.log(`  Initial sender balance: ${resLegacyBal.result} wei`);

  const resReceiverBal = await rpcCall('eth_getBalance', [RECEIVER_B, 'latest']);
  assert.ok(resReceiverBal.result.startsWith('0x'));
  const initialReceiverBalance = BigInt(resReceiverBal.result);
  console.log(`  Initial receiver balance: ${resReceiverBal.result} wei`);

  const resLegacyNonce = await rpcCall('eth_getTransactionCount', [SENDER_A, 'latest']);
  assert.ok(resLegacyNonce.result.startsWith('0x'));
  const initialSenderNonce = parseInt(resLegacyNonce.result, 16);
  console.log(`  Initial sender nonce: ${initialSenderNonce}`);
  console.log('✅ Legacy RPC queries translated and served successfully.');

  // Test 11: Transaction History Verification with Time Delay (Simulating Reality)
  console.log('\n🧪 Test 11: Verifying legacy transaction history proxy with time delay and receiver scanning...');

  // Sign a real transaction dynamically via did-tool
  console.log('  ✍️ Signing legacy transaction using did-tool...');
  didToolPath = getDidToolPath();
  const valueToSend = 1000000000000000000n; // 1 ETH in wei
  const gasLimit = 21000;
  const gasPrice = 1000000000; // 1 gwei
  
  const resChainId = await rpcCall('eth_chainId', []);
  const chainId = parseInt(resChainId.result, 16);
  console.log(`  Detected Chain ID: ${chainId}`);

  const cmd = `"${didToolPath}" sign-tx --private-key ${SENDER_A_PK} --to ${RECEIVER_B} --value ${valueToSend} --nonce ${initialSenderNonce} --gas-limit ${gasLimit} --gas-price ${gasPrice} --chain-id ${chainId}`;
  const output = execSync(cmd).toString().trim();
  console.log(`  did-tool output: ${output}`);

  let txHash;
  if (output.includes('Broadcast Succeeded!')) {
      const match = output.match(/Tx Hash: "([^"]+)"/) || output.match(/Tx Hash: ([0-9a-fA-Fx]+)/);
      if (match) {
          txHash = match[1];
      }
  }
  if (!txHash) {
      const match = output.match(/Signed Transaction Hex: (0x[0-9a-fA-F]+)/);
      const signedRawTx = match ? match[1] : output;
      const resSendTx = await rpcCall('eth_sendRawTransaction', [signedRawTx]);
      txHash = resSendTx.result;
  }
  assert.ok(txHash && txHash.startsWith('0x'), "Must return valid transaction hash");
  console.log(`  Sent transaction hash: ${txHash}`);

  console.log('  ⏳ Simulating real-world time passing (waiting 5 seconds)...');
  await new Promise(resolve => setTimeout(resolve, 5000));

  // Query updated balance for sender (should be less than initialSenderBalance)
  const resNewBal = await rpcCall('eth_getBalance', [SENDER_A, 'latest']);
  const newSenderBalance = BigInt(resNewBal.result);
  assert.ok(newSenderBalance < initialSenderBalance, "Sender balance must have decreased");
  console.log(`  Updated sender balance checked successfully: ${resNewBal.result} wei`);

  // The receiver wallet comes online and checks the latest block using multiple query formats (like padded hex)
  console.log('  🔍 Receiver wallet comes online and scans the latest block (eth_getBlockByNumber)...');
  
  // Format A: "latest"
  const resBlockLatest = await rpcCall('eth_getBlockByNumber', ['latest', false]);
  assert.ok(resBlockLatest.result, "Block 'latest' should not be null");
  assert.ok(resBlockLatest.result.transactions.includes(txHash), "Transaction hash must be present in the block 'latest'");
  console.log('  ✅ Receiver successfully saw the transaction in the latest block using "latest".');

  // Format B: Unpadded hex block number
  const blockNumHex = resBlockLatest.result.number; // e.g. "0x1"
  const resBlockUnpadded = await rpcCall('eth_getBlockByNumber', [blockNumHex, false]);
  assert.ok(resBlockUnpadded.result, `Block ${blockNumHex} should not be null`);
  assert.ok(resBlockUnpadded.result.transactions.includes(txHash), `Transaction hash must be present in block ${blockNumHex}`);
  console.log(`  ✅ Receiver successfully saw the transaction using unpadded block number: ${blockNumHex}`);

  // Format C: Padded hex block number
  const cleanHex = blockNumHex.replace('0x', '');
  const paddedHex = '0x' + cleanHex.padStart(8, '0'); // e.g. "0x00000001"
  const resBlockPadded = await rpcCall('eth_getBlockByNumber', [paddedHex, false]);
  assert.ok(resBlockPadded.result, `Block ${paddedHex} should not be null`);
  assert.ok(resBlockPadded.result.transactions.includes(txHash), `Transaction hash must be present in block ${paddedHex}`);
  console.log(`  ✅ Receiver successfully saw the transaction using padded block number: ${paddedHex}`);

  // Receiver fetches transaction details
  console.log('  🔍 Receiver wallet fetches transaction details (eth_getTransactionByHash)...');
  const resTx = await rpcCall('eth_getTransactionByHash', [txHash]);
  assert.ok(resTx.result, "Transaction should not be null");
  assert.strictEqual(resTx.result.hash, txHash);
  console.log('  ✅ Receiver successfully retrieved transaction object from CAIP cache.');

  // Receiver fetches transaction receipt
  console.log('  🔍 Receiver wallet fetches transaction receipt (eth_getTransactionReceipt)...');
  const resReceipt = await rpcCall('eth_getTransactionReceipt', [txHash]);
  assert.ok(resReceipt.result, "Receipt should not be null");
  assert.strictEqual(resReceipt.result.transactionHash, txHash);
  assert.strictEqual(resReceipt.result.status, '0x1');
  console.log('  ✅ Receiver successfully retrieved transaction receipt.');

  // Receiver checks updated balance (should have increased by exactly 1 ETH)
  console.log('  🔍 Receiver checks their updated balance...');
  const resNewReceiverBal = await rpcCall('eth_getBalance', [RECEIVER_B, 'latest']);
  const newReceiverBalance = BigInt(resNewReceiverBal.result);
  assert.strictEqual(newReceiverBalance - initialReceiverBalance, valueToSend, "Receiver balance must have increased by exactly 1 ETH");
  console.log('✅ Receiver successfully retrieved full transaction history and receipts from CAIP stateless cache.');

  // Test 12: Verify DID enforcement on transaction sending
  console.log('\n🧪 Test 12: Verifying DID registration enforcement on sending raw transaction (Expected to fail)...');
  const resBadSend = await rpcCall('eth_sendRawTransaction', ['0xMockRawPayload'], {
    'X-Sovereign-Did': 'did:peer:4zQmcwtTkvd3pusB1PK2eyGv14tqZkyVYiyyN5JFrJcQ2KdL:z9Z6XTsA687tYW9Ad5G7jjpkG6z7BduqXqckseKMySWGo7vwehZJ2xy6nEKU9ZXLZ4wfwoaVGRjHZNGxNiu5JbkUnregistered'
  });
  assert.ok(resBadSend.error);
  assert.strictEqual(resBadSend.error.code, -32001);
  console.log('✅ Correctly rejected transaction: unregistered DID');

  console.log('\n🎉 All CAIP E2E integration tests completed successfully!');
}

runTests().catch(err => {
  console.error('❌ E2E Tests Failed:', err);
  process.exit(1);
});
