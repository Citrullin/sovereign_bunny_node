/**
 * E2E Wallet Integration Tests for Sovereign-Reth.
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

const RPC_URL = process.env.SOVEREIGN_RPC_URL || 'http://localhost:8545';

const USER_DID = 'did:peer:2.VzQ3shok17vjUvJgqG3Yme5fQwQDndx8C5Jea95D4A8YnUFs2t.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

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

function getDidCliPath() {
  const paths = [
    path.resolve(__dirname, '../../target/debug/did-cli'),
    path.resolve(__dirname, '../../target/release/did-cli'),
    path.resolve(__dirname, '../target/debug/did-cli'),
    path.resolve(__dirname, '../target/release/did-cli'),
    path.resolve('target/debug/did-cli'),
    path.resolve('target/release/did-cli'),
  ];
  for (const p of paths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  throw new Error("did-cli binary not found!");
}

async function runTests() {
  console.log('🚀 Starting Sovereign-Reth CAIP E2E Integration Tests...\n');

  // Pre-onboard: Register the user DID
  console.log('📝 Registering user DID on-chain (sovereign_registerDid)...');
  const resReg = await rpcCall('sovereign_registerDid', [USER_DID]);
  assert.ok(resReg.result);
  assert.strictEqual(resReg.result.status, 'success');
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
  const RECEIVER_B = '0x918c30482462c8024ba6cf34a18ba1f8bbdb755f';
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

  // Sign a real transaction dynamically via did-cli
  console.log('  ✍️ Signing legacy transaction using did-cli tool...');
  const didCliPath = getDidCliPath();
  const valueToSend = 1000000000000000000n; // 1 ETH in wei
  const gasLimit = 21000;
  const gasPrice = 1000000000; // 1 gwei
  
  const resChainId = await rpcCall('eth_chainId', []);
  const chainId = parseInt(resChainId.result, 16);
  console.log(`  Detected Chain ID: ${chainId}`);

  const cmd = `"${didCliPath}" sign-tx --private-key ${SENDER_A_PK} --to ${RECEIVER_B} --value ${valueToSend} --nonce ${initialSenderNonce} --gas-limit ${gasLimit} --gas-price ${gasPrice} --chain-id ${chainId}`;
  const signedRawTx = execSync(cmd).toString().trim();
  console.log(`  Signed raw transaction generated successfully.`);

  // Submit the dynamic transaction (Sender)
  const resSendTx = await rpcCall('eth_sendRawTransaction', [signedRawTx]);
  const txHash = resSendTx.result;
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
    'X-Sovereign-Did': 'did:peer:2.UnregisteredDIDHere1234567890abcdef'
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
