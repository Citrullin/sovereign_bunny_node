import { createPublicClient, createWalletClient, http, parseEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';

const RPC_URL = process.env.SOVEREIGN_RPC_URL || 'http://localhost:8545';

// Define the custom chain spec for our devnet
const sovereignDevnet = {
  ...mainnet,
  id: 1337,
  name: 'Sovereign Devnet',
  network: 'sovereign-devnet',
  rpcUrls: {
    default: { http: [RPC_URL] },
    public: { http: [RPC_URL] },
  },
};

// Base58 Encoder for DID multibase formatting
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function encodeBase58(buffer: Uint8Array): string {
  let result = '';
  let bytes = Array.from(buffer);
  let carry;
  let digits = [0];
  for (let i = 0; i < bytes.length; i++) {
    carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    result += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

// Derive a did:peer:2 representation dynamically from keys
function deriveDidFromKeys(privateKeyHex: string, publicKeyHex: string): string {
  // 1. Secp256k1 compressed public key (prefix: 0xe7 0x01)
  const secpPub = secp256k1.ProjectivePoint.fromHex(publicKeyHex.slice(2)).toRawBytes(true);
  const muticodecSecp = new Uint8Array([0xe7, 0x01, ...secpPub]);
  const secpMultibase = 'Vz' + encodeBase58(muticodecSecp);

  // 2. Deterministic Ed25519 public key (using the secp private key as seed, prefix: 0xed 0x01)
  const pkBytes = new Uint8Array(
    privateKeyHex.slice(2).match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
  );
  const edPub = ed25519.getPublicKey(pkBytes);
  const multicodecEd = new Uint8Array([0xed, 0x01, ...edPub]);
  const edMultibase = 'Vz' + encodeBase58(multicodecEd);

  return `did:peer:2.${secpMultibase}.${edMultibase}`;
}

// Alice (Sender)
const ALICE_PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

// Bob (Receiver, dynamic)
const BOB_PK = '0x303471f545717334e4a48ef022aac62081d3708a66bb1b0c0bd7edd632294871';

async function run() {
  console.log('--- STARTING BARE-METAL VIEM NATIVE HISTORY INTEGRATION TEST ---');

  const aliceAccount = privateKeyToAccount(ALICE_PK);
  const bobAccount = privateKeyToAccount(BOB_PK);

  // Derive addresses and DIDs dynamically
  const aliceAddress = aliceAccount.address;
  const bobAddress = bobAccount.address;
  
  const aliceDid = deriveDidFromKeys(ALICE_PK, aliceAccount.publicKey);
  const bobDid = deriveDidFromKeys(BOB_PK, bobAccount.publicKey);

  console.log(`   Alice Address: ${aliceAddress}`);
  console.log(`   Alice DID:     ${aliceDid}`);
  console.log(`   Bob Address:   ${bobAddress}`);
  console.log(`   Bob DID:       ${bobDid}`);

  const publicClient = createPublicClient({
    chain: sovereignDevnet,
    transport: http(),
  });

  const aliceWalletClient = createWalletClient({
    account: aliceAccount,
    chain: sovereignDevnet,
    transport: http(),
  });

  const bobWalletClient = createWalletClient({
    account: bobAccount,
    chain: sovereignDevnet,
    transport: http(),
  });

  // 1. SETUP: Onboard Alice on-chain via sovereign_registerDid
  console.log('1. Onboarding Alice (Sender) DID on-chain...');
  await aliceWalletClient.request({
    method: 'sovereign_registerDid' as any,
    params: [aliceDid] as any,
  });
  console.log('   Alice DID registered successfully.');

  // Initialize session
  console.log('   Initializing CAIP-25 session...');
  await aliceWalletClient.request({
    method: 'wallet_requestPermissions' as any,
    params: [
      {
        chains: ['eip155:1337'],
        permissions: [{ type: 'wallet_action', name: 'personal_sign' }],
      },
    ] as any,
  });

  // 2. SEND TRANSACTION: Send 1 ETH natively using standard Viem Client
  console.log(`2. Sending 1 ETH natively from Alice to Bob (${bobAddress})...`);
  const txHash = await aliceWalletClient.sendTransaction({
    to: bobAddress,
    value: parseEther('1'),
    headers: {
      'X-Sovereign-Did': aliceDid,
    }
  } as any);
  console.log(`   Transaction submitted! Hash: ${txHash}`);

  // Wait 3 seconds for block execution and canonical inclusion
  console.log('   Waiting 3 seconds for block execution...');
  await new Promise(resolve => setTimeout(resolve, 3000));

  // 3. HISTORY QUERY BY ADDRESS: Bob queries history endpoint by address
  const historyUrlAddr = `${RPC_URL}/cache/history?account=${bobAddress}`;
  console.log(`3. Querying cache history for Bob by Address: ${historyUrlAddr}`);
  const historyResAddr = await fetch(historyUrlAddr).then(res => res.json()) as any;

  console.log('4. Running assertions for address query...');
  if (!historyResAddr.history || historyResAddr.history.length === 0) {
    throw new Error(`Bob's history is empty when querying by address: ${JSON.stringify(historyResAddr)}`);
  }

  const recordAddr = historyResAddr.history.find((t: any) => t.txHash.toLowerCase() === txHash.toLowerCase());
  if (!recordAddr) {
    throw new Error(`Transaction ${txHash} not found in Bob's history by address`);
  }
  if (recordAddr.value !== '1000000000000000000') {
    throw new Error(`Value mismatch: expected 1000000000000000000, got ${recordAddr.value}`);
  }
  console.log('   ✅ Query by Address passed successfully.');

  // 4. HISTORY QUERY BY DID: Bob queries history endpoint by DID (which auto-registers Bob's placeholder DID)
  const historyUrlDid = `${RPC_URL}/cache/history?account=${bobDid}`;
  console.log(`5. Querying cache history for Bob by DID: ${historyUrlDid}`);
  
  // Pass X-Sovereign-Did header representing Bob to auto-register Bob's DID placeholder on connection
  const historyResDid = await fetch(historyUrlDid, {
    headers: {
      'X-Sovereign-Did': bobDid,
    }
  }).then(res => res.json()) as any;

  console.log('6. Running assertions for DID query...');
  if (!historyResDid.history || historyResDid.history.length === 0) {
    throw new Error(`Bob's history is empty when querying by DID: ${JSON.stringify(historyResDid)}`);
  }

  const recordDid = historyResDid.history.find((t: any) => t.txHash.toLowerCase() === txHash.toLowerCase());
  if (!recordDid) {
    throw new Error(`Transaction ${txHash} not found in Bob's history by DID`);
  }
  if (recordDid.value !== '1000000000000000000') {
    throw new Error(`Value mismatch: expected 1000000000000000000, got ${recordDid.value}`);
  }
  console.log('   ✅ Query by DID passed successfully.');

  // 5. TRANSACTION BLOCK CHECK: Verify Bob (who only has auto-registered placeholder DID) cannot execute transaction
  console.log('7. Verifying that Bob (placeholder DID) cannot submit a transaction...');
  let errorOccurred = false;
  try {
    await bobWalletClient.sendTransaction({
      to: aliceAddress,
      value: parseEther('0.1'),
      headers: {
        'X-Sovereign-Did': bobDid,
      }
    } as any);
  } catch (err: any) {
    errorOccurred = true;
    console.log(`   Transaction correctly rejected with error: ${err.message}`);
  }

  if (!errorOccurred) {
    throw new Error('Expected transaction from Bob (placeholder DID) to fail, but it succeeded!');
  }
  console.log('   ✅ Placeholder DID check passed successfully.');

  console.log('🎉 ALL BARE-METAL VIEM NATIVE HISTORY INTEGRATION TESTS PASSED!');
}

run().catch(err => {
  console.error('❌ Integration Test Failed:', err);
  process.exit(1);
});
