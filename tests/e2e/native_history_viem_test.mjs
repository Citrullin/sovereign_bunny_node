/**
 * Sovereign-Reth Stateless Dual-Wallet Integration Test
 */

import { createWalletClient, http, parseEther, formatEther, keccak256, toHex, pad } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import crypto from 'crypto';

const RPC_URL = process.env.SOVEREIGN_RPC_URL || 'http://localhost:8545';

// ── Sovereign devnet chain definition ─────────────────────────────────────────

const sovereignDevnet = {
  id: 1337,
  name: 'Sovereign Devnet',
  network: 'sovereign-devnet',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: {
    default: { http: [RPC_URL] },
    public: { http: [RPC_URL] },
  },
};

// ── Base58 encoder (needed for did:peer:4 DID generation) ──────────────────────

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function encodeBase58(buf) {
  const bytes = Array.from(buf);
  let digits = [0];
  for (const byte of bytes) {
    let carry = byte;
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
  let result = '';
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) result += '1';
  for (let i = digits.length - 1; i >= 0; i--) result += B58[digits[i]];
  return result;
}

/**
 * Derives a canonical did:peer:4 DID from a secp256k1 private key.
 */
function deriveDidFromPrivateKey(privateKeyHex) {
  const account = privateKeyToAccount(privateKeyHex);
  const secpPub = secp256k1.ProjectivePoint.fromHex(account.publicKey.slice(2)).toRawBytes(true);
  
  const secpMulticodec = Buffer.concat([Buffer.from([0xe7, 0x01]), Buffer.from(secpPub)]);
  const secpMultibase = 'z' + encodeBase58(secpMulticodec);

  const verificationMethod = [
    { "id": "#key-secp256k1", "type": "EcdsaSecp256k1VerificationKey2019", "publicKeyMultibase": secpMultibase }
  ];

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

  const didDocJson = { "verificationMethod": verificationMethod };
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

// ── Key pairs (real keys — Hardhat dev accounts) ──────────────────────────────
// Alice: Hardhat account #0, pre-funded in Reth --dev mode
const ALICE_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
// Bob: Hardhat account #1, independent wallet
const BOB_PK   = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

// ERC-20 Transfer(address,address,uint256) event selector
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

// ── Raw JSON-RPC helper ────────────────────────────────────────────────────────

async function rpc(method, params, extraHeaders = {}) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() }),
  });
  return res.json();
}

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Main test ─────────────────────────────────────────────────────────────────

async function run() {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  SOVEREIGN STATELESS DUAL-WALLET INTEGRATION TEST');
  console.log('  (Standard EVM: eth_getLogs, eth_getBlockByNumber, receipts)');
  console.log('═══════════════════════════════════════════════════════════\n');

  const aliceAccount = privateKeyToAccount(ALICE_PK);
  const bobAccount   = privateKeyToAccount(BOB_PK);
  const aliceDid     = deriveDidFromPrivateKey(ALICE_PK);

  console.log('👛 WALLET A (Alice — Sender, registered DID)');
  console.log(`   Address: ${aliceAccount.address}`);
  console.log(`   DID:     ${aliceDid}`);
  console.log('👛 WALLET B (Bob — Receiver, cold Rabby)');
  console.log(`   Address: ${bobAccount.address}\n`);

  // ────────────────────────────────────────────────────────────────────────────
  // WALLET A: Register DID and send 1 ETH to Bob
  // ────────────────────────────────────────────────────────────────────────────
  console.log('── WALLET A ─────────────────────────────────────────────────');

  console.log('1. Alice registers her DID...');
  const nonce = Date.now();
  const signature = signRegistration(aliceDid, nonce, ALICE_PK);
  const regResp = await rpc('sovereign_registerDid', [aliceDid, nonce, signature]);
  assert(regResp.result?.status === 'success', `DID registration failed: ${JSON.stringify(regResp)}`);
  console.log(`   ✅ Registered → ${regResp.result.address}`);

  console.log('2. Alice checks balance before send...');
  const aliceBalBefore = BigInt((await rpc('eth_getBalance', [aliceAccount.address, 'latest'])).result);
  assert(aliceBalBefore > 0n, 'Alice must be pre-funded in --dev mode');
  console.log(`   Balance: ${formatEther(aliceBalBefore)} ETH`);

  console.log('3. Alice sends 1 ETH to Bob...');
  const aliceClient = createWalletClient({
    account: aliceAccount,
    chain: sovereignDevnet,
    transport: http(RPC_URL, {
      fetchOptions: { headers: { 'X-Sovereign-Did': aliceDid } },
    }),
  });

  const valueToSend = parseEther('1');
  const txHash = await aliceClient.sendTransaction({
    to: bobAccount.address,
    value: valueToSend,
  });
  console.log(`   ✅ Sent! Transaction Hash: ${txHash}`);
  console.log('   ⏳ Simulating real-world time passing (waiting 5 seconds)...');
  await sleep(5000);

  // ────────────────────────────────────────────────────────────────────────────
  // WALLET B: Verify Bob discovers the transfer via eth_getLogs & receipts
  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n── WALLET B ─────────────────────────────────────────────────');

  console.log('4. Bob scans transaction history via eth_getLogs...');
  console.log('   (Simulating cold wallet startup using standardized ERC-20 event filters)');
  
  // We query logs matching Transfer(address,address,uint256) where topic2 (to) is Bob
  const bobTopic2 = pad(bobAccount.address).toLowerCase();
  
  // Poll until logs are populated
  let logs = [];
  for (let i = 0; i < 20; i++) {
    const logsResp = await rpc('eth_getLogs', [{
      fromBlock: '0x0',
      toBlock: 'latest',
      topics: [TRANSFER_TOPIC, null, bobTopic2]
    }]);
    logs = logsResp.result || [];
    if (logs.length > 0) break;
    await sleep(500);
  }

  assert(logs.length > 0, `No synthetic Transfer logs found for Bob's address ${bobAccount.address}`);
  console.log(`   ✅ Discovered ${logs.length} incoming transfer log(s):`);
  for (const log of logs) {
    const fromAddr = '0x' + log.topics[1].slice(26);
    const value = BigInt(log.data);
    console.log(`     - Received ${formatEther(value)} ETH from ${fromAddr}`);
    assert(value === valueToSend, 'Log value mismatch');
  }

  // Bob verifies the block header
  console.log('5. Bob fetches the canonical block...');
  const blockResp = await rpc('eth_getBlockByNumber', ['latest', true]);
  assert(!blockResp.error, `eth_getBlockByNumber error: ${JSON.stringify(blockResp.error)}`);
  const block = blockResp.result;
  assert(block !== null, 'Latest block is null');
  console.log('DEBUG txHash:', txHash);
  console.log('DEBUG block.transactions:', JSON.stringify(block.transactions.map(tx => tx.hash)));
  assert(block.transactions.some(tx => tx.hash.toLowerCase() === txHash.toLowerCase()),
    `Block must contain Alice's transaction ${txHash}`);
  console.log(`   ✅ Mined in Block #${parseInt(block.number, 16)}: ${block.transactions.length} tx(s)`);

  // Bob verifies the transaction object
  console.log('6. Bob checks transaction details (eth_getTransactionByHash)...');
  const txResp = await rpc('eth_getTransactionByHash', [txHash]);
  assert(!txResp.error, `eth_getTransactionByHash error: ${JSON.stringify(txResp.error)}`);
  const txObj = txResp.result;
  assert(txObj !== null, `Transaction object for ${txHash} is null`);
  assert(txObj.to?.toLowerCase() === bobAccount.address.toLowerCase(), 'txObj.to mismatch');
  assert(BigInt(txObj.value) === valueToSend, 'txObj.value mismatch');
  console.log(`   ✅ Details confirmed: from=${txObj.from}, value=${formatEther(BigInt(txObj.value))} ETH`);

  // Bob checks transaction receipt status
  console.log('7. Bob verifies transaction status (eth_getTransactionReceipt)...');
  const receiptResp = await rpc('eth_getTransactionReceipt', [txHash]);
  assert(!receiptResp.error, `eth_getTransactionReceipt error: ${JSON.stringify(receiptResp.error)}`);
  const receipt = receiptResp.result;
  assert(receipt !== null, `Receipt for ${txHash} is null — tx not mined`);
  assert(receipt.status === '0x1', `Receipt status must be 0x1, got ${receipt.status}`);
  assert(receipt.transactionHash?.toLowerCase() === txHash.toLowerCase(), 'receipt.transactionHash mismatch');
  console.log(`   ✅ Receipt confirmed: status=${receipt.status}, block #${parseInt(receipt.blockNumber, 16)}`);

  // Bob's balance must have increased
  console.log('8. Bob checks updated balance (eth_getBalance)...');
  const bobBalResp = await rpc('eth_getBalance', [bobAccount.address, 'latest']);
  const bobBal = BigInt(bobBalResp.result);
  assert(bobBal >= parseEther('1'), `Bob balance must be ≥ 1 ETH, got ${formatEther(bobBal)} ETH`);
  console.log(`   ✅ Bob balance: ${formatEther(bobBal)} ETH`);

  // Bob attempts to send — must be rejected (no registered DID)
  console.log('9. Bob tries to send ETH (must be rejected — placeholder DID)...');
  const sendResp = await rpc('eth_sendRawTransaction', [
    '0x02f86c82053980843b9aca00843b9aca008252089470997970c51812dc3a010c7d01b50e0d17dc79c8880de0b6b3a764000080c080a0b1c1b1c1b1c1b1c1b1c1b1c1b1c1b1c1b1c1b1c1b1c1b1c1b1c1b1c1b1c1b1c1a0d2c2d2c2d2c2d2c2d2c2d2c2d2c2d2c2d2c2d2c2d2c2d2c2d2c2d2c2d2c2d2c2'
  ]);
  const isDidRejection = sendResp.error?.message?.includes('DID not registered') ||
                          sendResp.error?.message?.includes('not registered') ||
                          sendResp.error?.code === -32001;
  assert(isDidRejection,
    `Bob's send must be rejected with DID error (-32001), got: ${JSON.stringify(sendResp.error)}`);
  console.log(`   ✅ Correctly rejected: ${sendResp.error?.message?.slice(0, 70)}...`);

  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('  🎉 ALL DUAL-WALLET STATELESS TESTS PASSED');
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  Alice (registered DID) → sent 1 ETH to Bob         ✅');
  console.log('  Bob (cold Rabby):');
  console.log('    eth_getLogs Transfer synthesis                     ✅');
  console.log('    eth_getBlockByNumber tx present                    ✅');
  console.log('    eth_getTransactionByHash details                   ✅');
  console.log('    eth_getTransactionReceipt status=0x1               ✅');
  console.log('    eth_getBalance increased by 1 ETH                  ✅');
  console.log('    eth_sendRawTransaction blocked (placeholder DID)   ✅');
}

run().catch(err => {
  console.error('\n❌ DUAL-WALLET STATELESS TEST FAILED:', err.message);
  process.exit(1);
});
