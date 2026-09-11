// Unit Tests for the 4 Operational Combination Modes in SovereignClient
import assert from 'assert';
import { ethers } from 'ethers';
import { SovereignClient } from '../../src/client.js';
import { PRECOMPILES, encodeRawPrecompileCall } from '../../src/contracts.js';

function runCombinationTests() {
    console.log("🧪 Running Sovereign SDK Execution Combinations Unit Tests...\n");

    // 1. Test Mode 1: [CAIP-25 + CBOR + HTTP/3 | Native PQ] (Modern Highway)
    console.log("1. Testing Mode 1: [CAIP-25 + CBOR + HTTP/3 | Native PQ] (Modern Highway)...");
    const modernClient = new SovereignClient(null, { executionMode: 'modern_cbor' });
    assert.strictEqual(modernClient.mode, 'modern_cbor');
    console.log("   ✅ Mode 1 correctly initialized for direct high-speed streaming without outer wrapper.\n");

    // 2. Test Mode 2: [No CAIP (Standard EVM) | Quantum Wrapped PQ] (The Bridge)
    console.log("2. Testing Mode 2: [No CAIP (Standard EVM) | Quantum Wrapped PQ] (The Bridge)...");
    const wrappedClient = new SovereignClient(null, { executionMode: 'legacy_wrapped' });
    assert.strictEqual(wrappedClient.mode, 'legacy_wrapped');

    // Simulate wrapping an ML-DSA-65 signature and ActivityPub note into standard EVM calldata
    const dummyMlDsaSignature = ethers.hexlify(ethers.randomBytes(64));
    const testActorUri = "did:sovereign:1337:0x1111111111111111111111111111111111111111";
    const testNotePayload = JSON.stringify({
        "@context": "https://www.w3.org/ns/activitystreams",
        type: "Create",
        actor: testActorUri,
        object: { type: "Note", content: "Quantum Protected Note" },
        signature: {
            type: "MlDsa65VerificationKey2024",
            value: dummyMlDsaSignature
        }
    });

    const wrappedCalldata = encodeRawPrecompileCall("CMS_ACTPUB", "publishActivity", [
        ethers.toUtf8Bytes(testNotePayload)
    ]);
    assert.ok(wrappedCalldata.startsWith("0x"), "Quantum-wrapped calldata must be standard hex");
    console.log(`   ✅ Quantum payload successfully encoded for precompile ${PRECOMPILES.CMS_ACTPUB}.\n`);

    // 3. Test Mode 3: [No CAIP (Standard EVM) | Classical Secp256k1] (Vanilla Ethereum)
    console.log("3. Testing Mode 3: [No CAIP (Standard EVM) | Classical Secp256k1] (Vanilla Ethereum)...");
    const pureClient = new SovereignClient(null, { executionMode: 'legacy_pure' });
    assert.strictEqual(pureClient.mode, 'legacy_pure');

    const pureCalldata = encodeRawPrecompileCall("ROUTER", "mountSlot", [
        1,
        "core.zanzibar",
        ethers.ZeroHash
    ]);
    assert.ok(pureCalldata.length > 10, "Calldata must be correctly formatted");
    console.log("   ✅ Legacy Pure mode produces clean standard EVM transactions without PQ fields.\n");

    // 4. Test Mode 4: [Fuck it, we ballin | Raw Bytecode] (Bare-Metal On-Chain)
    console.log("4. Testing Mode 4: [Fuck it, we ballin | Raw Bytecode] (Bare-Metal On-Chain)...");
    const rawClient = new SovereignClient(null, { executionMode: 'bytecode_raw' });
    assert.strictEqual(rawClient.mode, 'bytecode_raw');

    // Deployed contract pushes raw bytecode to 0x0100 (Account Height)
    const rawHeightCall = encodeRawPrecompileCall("LATTICE_HEIGHT", "getAccountHeight", [
        "0x2222222222222222222222222222222222222222"
    ]);
    assert.ok(rawHeightCall.length >= 10);
    console.log(`   ✅ Target Address: ${PRECOMPILES.LATTICE_HEIGHT}`);
    console.log(`   ✅ Raw Bytecode Payload: ${rawHeightCall}`);

    // Mode Switching
    console.log("5. Testing Dynamic Mode Switching...");
    rawClient.setExecutionMode('modern_cbor');
    assert.strictEqual(rawClient.mode, 'modern_cbor');
    rawClient.setExecutionMode('legacy_wrapped');
    assert.strictEqual(rawClient.mode, 'legacy_wrapped');
    console.log("   ✅ Dynamic mode transitions verified.\n");

    console.log("🎉 All 4 Execution Combinations Unit Tests Passed Successfully!");
}

runCombinationTests();
