/**
 * Isolated E2E Integration Test to expose Receiver (Wallet B) failure to retrieve
 * historical native token transfers from the stateless block-in-blob cache.
 */

const assert = require('assert');
const { execSync } = require('child_process');

const RPC_URL = process.env.SOVEREIGN_RPC_URL || 'http://localhost:8545';

// Alice (Sender) configuration
const ALICE_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const ALICE_DID = 'did:peer:2.VzQ3shok17vjUvJgqG3Yme5fQwQDndx8C5Jea95D4A8YnUFs2t.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const ALICE_ADDR = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';

// Bob (Receiver) configuration
const BOB_DID = 'did:peer:2.VzQ3shjBj7WwKgYTt2wz9LaBFCoUCJ3rdjk7NLVxFjmT2HKxiW.Vz6Mkgw6zXCvr5woFMe53hn9HTxaPJXZVM6f3pR84wrU2un41';
const BOB_ADDR = '0xa11b4bafdad6661fc5ab1a3fd47bb4653c22ce82';

async function rpcCall(method, params, headers = {}) {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Sovereign-Did': ALICE_DID,
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

async function run() {
  console.log('--- STARTING NATIVE TOKEN TRANSFERS HISTORY FAILURE TEST ---');

  // 1. SETUP: Register Alice's DID so she is authorized to submit state changes
  console.log('1. Onboarding Alice (Sender) DID on-chain...');
  const regRes = await rpcCall('sovereign_registerDid', [ALICE_DID]);
  assert.ok(regRes.result, 'Alice registration must succeed');
  console.log('   Alice DID registered successfully.');

  // Initialize session
  console.log('   Initializing CAIP-25 session...');
  await rpcCall('wallet_requestPermissions', [
    {
      chains: ['eip155:1337'],
      permissions: [{ type: 'wallet_action', name: 'personal_sign' }]
    }
  ]);

  // Fetch current nonce and chain ID for signing
  const chainIdRes = await rpcCall('eth_chainId', []);
  const chainId = parseInt(chainIdRes.result, 16);
  const nonceRes = await rpcCall('eth_getTransactionCount', [ALICE_ADDR, 'latest']);
  const nonce = parseInt(nonceRes.result, 16);
  console.log(`   Fetched Chain ID: ${chainId}, Nonce: ${nonce}`);

  // 2. NATIVE TRANSFER: Alice signs a raw NATIVE transfer payload using did-cli
  console.log('2. Signing and submitting raw native transfer payload (no contracts)...');
  const value = 1000000000000000000n; // 1 ETH in Wei
  const signCmd = `./target/debug/did-tool sign-tx --private-key "${ALICE_PK}" --to "${BOB_ADDR}" --value ${value} --nonce ${nonce} --chain-id ${chainId}`;
  const signedRawTx = execSync(signCmd).toString().trim();
  
  const resSendTx = await rpcCall('eth_sendRawTransaction', [signedRawTx]);
  console.log('   DEBUG resSendTx:', JSON.stringify(resSendTx));
  const txHash = resSendTx.result;
  assert.ok(txHash && txHash.startsWith('0x'), 'Must return valid tx hash');
  console.log(`   Transaction submitted. Hash: ${txHash}`);

  // Wait 3 seconds for block inclusion
  console.log('   Waiting for block execution/inclusion...');
  await new Promise(resolve => setTimeout(resolve, 3000));

  // 3. HISTORY QUERY: Bob queries history endpoint by Bob's DID (which auto-registers Bob's placeholder DID)
  const historyUrlBob = `${RPC_URL}/cache/history?account=${BOB_DID}`;
  console.log(`3. Querying cache history endpoint for Bob's DID: ${historyUrlBob}`);
  
  let historyResBob;
  try {
    const response = await fetch(historyUrlBob);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    historyResBob = await response.json();
  } catch (err) {
    console.error(`   History query encountered error: ${err.message}`);
    historyResBob = null;
  }

  // 4. ASSERTIONS (Bob): Verify that native history payload is populated and reflects the delta
  console.log('4. Running assertions to verify stateless native transaction history for Bob (Receiver)...');
  
  assert.ok(historyResBob, 'History response must not be null/error');
  assert.ok(Array.isArray(historyResBob.history), 'History response must contain history array');
  assert.ok(historyResBob.history.length > 0, "Bob's native history must not be empty");
  
  const transferBob = historyResBob.history.find(t => t.txHash === txHash);
  assert.ok(transferBob, 'Historical record of native transfer must exist in history index');
  assert.strictEqual(transferBob.to.toLowerCase(), BOB_ADDR.toLowerCase());
  assert.strictEqual(transferBob.from.toLowerCase(), ALICE_ADDR.toLowerCase());
  assert.strictEqual(transferBob.value.toString(), value.toString(), 'Transfer value must match native state change');

  // 5. HISTORY QUERY: Alice queries history endpoint by Alice's EVM address
  const historyUrlAlice = `${RPC_URL}/cache/history?account=${ALICE_ADDR}`;
  console.log(`5. Querying cache history endpoint for Alice's address: ${historyUrlAlice}`);
  
  let historyResAlice;
  try {
    const response = await fetch(historyUrlAlice);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    historyResAlice = await response.json();
  } catch (err) {
    console.error(`   History query encountered error: ${err.message}`);
    historyResAlice = null;
  }

  // 6. ASSERTIONS (Alice): Verify that native history payload is populated and reflects the delta
  console.log('6. Running assertions to verify stateless native transaction history for Alice (Sender)...');
  
  assert.ok(historyResAlice, 'History response must not be null/error');
  assert.ok(Array.isArray(historyResAlice.history), 'History response must contain history array');
  assert.ok(historyResAlice.history.length > 0, "Alice's native history must not be empty");
  
  const transferAlice = historyResAlice.history.find(t => t.txHash === txHash);
  assert.ok(transferAlice, 'Historical record of native transfer must exist in history index');
  assert.strictEqual(transferAlice.to.toLowerCase(), BOB_ADDR.toLowerCase());
  assert.strictEqual(transferAlice.from.toLowerCase(), ALICE_ADDR.toLowerCase());
  assert.strictEqual(transferAlice.value.toString(), value.toString(), 'Transfer value must match native state change');

  // 7. TRANSACTION SUBMISSION VERIFICATION:
  // Now verify that Bob trying to initiate a transaction using his auto-registered placeholder DID FAILS
  // because the placeholder DID has no curves (not fully registered)
  console.log('7. Verifying that transaction creation from Bob placeholder DID fails...');
  
  const nextNonceRes = await rpcCall('eth_getTransactionCount', [ALICE_ADDR, 'latest']);
  const nextNonce = parseInt(nextNonceRes.result, 16);
  
  const signCmd2 = `./target/debug/did-tool sign-tx --private-key "${ALICE_PK}" --to "${BOB_ADDR}" --value ${value} --nonce ${nextNonce} --chain-id ${chainId}`;
  const signedRawTx2 = execSync(signCmd2).toString().trim();
  
  // Submit with Bob's DID (which is a placeholder) as X-Sovereign-Did
  const resBobSendTx = await rpcCall('eth_sendRawTransaction', [signedRawTx2], {
    'X-Sovereign-Did': BOB_DID
  });
  
  console.log('   DEBUG resBobSendTx:', JSON.stringify(resBobSendTx));
  assert.ok(resBobSendTx.error, 'Transaction from Bob placeholder DID must fail');
  assert.strictEqual(resBobSendTx.error.code, -32001, 'Should fail with active DID not registered (placeholder)');
  assert.ok(resBobSendTx.error.message.includes('not registered') || resBobSendTx.error.message.includes('Please onboard'), 'Error message should complain about registration');
  
  console.log('🎉 SUCCESS: Stateless native transfer history is fully indexed, verified, and placeholder checks pass!');
}

run().catch(err => {
  console.error('\n❌ Test failed:\n', err);
  process.exit(1);
});
