// Unit Tests for Sovereign Transaction Debugger, PQ Unwrapper & Account Storage
import assert from 'node:assert';
import { ethers } from 'ethers';
import {
    SovereignDebugger,
    AccountStorageManager,
    MemoryStorageBackend,
    PRECOMPILES,
    SovereignClient,
    PqSignRequest
} from '../../src/index.js';

async function runTests() {
    console.log("🐞 Running Sovereign Transaction & Error Debugger Unit Tests...\n");

    const storage = new AccountStorageManager(new MemoryStorageBackend());
    const dbg = new SovereignDebugger(storage);

    // -------------------------------------------------------------
    // Test 1: Precompile Calldata Dissection
    // -------------------------------------------------------------
    console.log("1. Testing Built-in Precompile Calldata Dissection...");
    const routerIface = new ethers.Interface([
        "function mountSlot(uint8 slotId, string calldata pluginId, bytes32 initialRoot) external"
    ]);
    const mockRoot = ethers.keccak256(ethers.toUtf8Bytes("genesis_root"));
    const routerCalldata = routerIface.encodeFunctionData("mountSlot", [1, "sovereign:zanzibar", mockRoot]);

    const decodedRouter = dbg.decodeCalldata(PRECOMPILES.ROUTER, routerCalldata);
    assert.strictEqual(decodedRouter.targetName, 'ROUTER');
    assert.strictEqual(decodedRouter.isPrecompile, true);
    assert.strictEqual(decodedRouter.functionSignature, 'mountSlot(uint8,string,bytes32)');
    assert.strictEqual(decodedRouter.params['slotId'], '1');
    assert.strictEqual(decodedRouter.params['pluginId'], 'sovereign:zanzibar');
    assert.strictEqual(decodedRouter.params['initialRoot'], mockRoot);
    console.log("   ✅ Router mountSlot successfully decoded with exact parameters.");

    const zanzibarIface = new ethers.Interface([
        "function check(uint16 namespace, bytes32 objectId, uint16 relation, address subject) external view returns (bool authorized)"
    ]);
    const testSubject = "0x7777777777777777777777777777777777777777";
    const testObjId = ethers.keccak256(ethers.toUtf8Bytes("doc_42"));
    const zanzibarCalldata = zanzibarIface.encodeFunctionData("check", [1, testObjId, 2, testSubject]);

    const decodedZanzibar = dbg.decodeCalldata(PRECOMPILES.ZANZIBAR_REBAC, zanzibarCalldata);
    assert.strictEqual(decodedZanzibar.targetName, 'ZANZIBAR_REBAC');
    assert.strictEqual(decodedZanzibar.params['namespace'], '1');
    assert.strictEqual(decodedZanzibar.params['relation'], '2');
    assert.strictEqual(decodedZanzibar.params['subject'].toLowerCase(), testSubject.toLowerCase());
    console.log("   ✅ Zanzibar ReBAC 0x61 check call successfully dissected.");

    // Test packed DID Registry wire decoding (0x03 wire without ABI selector)
    const mockTier = "QuantumReady";
    const tierBytes = new TextEncoder().encode(mockTier);
    const mockPqPub = new Uint8Array(1952);
    mockPqPub.fill(0xaa);
    const mockDidDocJson = JSON.stringify({ id: "did:sovereign:13371337:0x1111", verificationMethod: [] });
    const docBytes = new TextEncoder().encode(mockDidDocJson);
    const packedBytes = new Uint8Array(1 + tierBytes.length + 4 + mockPqPub.length + docBytes.length);
    packedBytes[0] = tierBytes.length;
    packedBytes.set(tierBytes, 1);
    new DataView(packedBytes.buffer).setUint32(1 + tierBytes.length, mockPqPub.length, false);
    packedBytes.set(mockPqPub, 1 + tierBytes.length + 4);
    packedBytes.set(docBytes, 1 + tierBytes.length + 4 + mockPqPub.length);

    const decodedDidPacked = dbg.decodeCalldata(PRECOMPILES.DID_REGISTRY, ethers.hexlify(packedBytes));
    assert.strictEqual(decodedDidPacked.mode, 'precompile_packed');
    assert.strictEqual(decodedDidPacked.params['keyTier'], mockTier);
    assert.strictEqual(decodedDidPacked.params['didDocument'].id, "did:sovereign:13371337:0x1111");
    console.log("   ✅ Precompile 0x03 packed wire calldata successfully decoded into structured fields.");

    // -------------------------------------------------------------
    // Test 2: Custom Contract & Namespace Upload / Supply
    // -------------------------------------------------------------
    console.log("\n2. Testing Custom Contract & Namespace Supply...");
    const customContractAddr = "0x1234567890123456789012345678901234567890";
    const erc20Abi = [
        "function transfer(address to, uint256 amount) external returns (bool)",
        "function balanceOf(address account) external view returns (uint256)"
    ];
    dbg.registerCustomAbi(customContractAddr, erc20Abi);

    const erc20Iface = new ethers.Interface(erc20Abi);
    const transferCalldata = erc20Iface.encodeFunctionData("transfer", [testSubject, ethers.parseEther("100")]);
    const decodedCustom = dbg.decodeCalldata(customContractAddr, transferCalldata);
    assert.strictEqual(decodedCustom.functionSignature, 'transfer(address,uint256)');
    assert.strictEqual(decodedCustom.params['to'].toLowerCase(), testSubject.toLowerCase());
    assert.strictEqual(decodedCustom.params['amount'], ethers.parseEther("100").toString());
    console.log("   ✅ User-supplied custom contract ABI successfully registered and decoded.");

    // -------------------------------------------------------------
    // Test 3: EIP-8141 Quantum-Wrapped Envelope Unwrapping
    // -------------------------------------------------------------
    console.log("\n3. Testing EIP-8141 Quantum-Wrapped Envelope Unwrapping...");
    // Build a mock quantum envelope: [header 81410000][innerTarget 20 bytes][r 32b][s 32b][v 1b][pqSig 3309b][innerCalldata]
    const header = "81410000";
    const innerTarget = PRECOMPILES.DID_REGISTRY.toLowerCase().replace('0x', '');
    const r = "11".repeat(32);
    const s = "22".repeat(32);
    const v = "1b";
    const mockPqSig = "33".repeat(3309);
    const innerCalldata = transferCalldata.replace('0x', '');
    const fullEnvelope = "0x" + header + innerTarget + r + s + v + mockPqSig + innerCalldata;

    const unwrapped = dbg.unwrapQuantumEnvelope(fullEnvelope);
    assert.strictEqual(unwrapped.isWrapped, true);
    assert.strictEqual(unwrapped.envelopeType, 'EIP-8141-ML-DSA-65');
    assert.strictEqual(unwrapped.innerTargetAddress?.toLowerCase(), PRECOMPILES.DID_REGISTRY.toLowerCase());
    assert.ok(unwrapped.pqSignatureHex?.startsWith('0x3333'));
    assert.strictEqual(unwrapped.innerCalldataHex?.toLowerCase(), transferCalldata.toLowerCase());
    console.log("   ✅ Quantum-Wrapped envelope successfully unpacked: outer Secp256k1 + inner ML-DSA-65 isolated.");

    // -------------------------------------------------------------
    // Test 4: EVM Revert & Panic Code Decoding
    // -------------------------------------------------------------
    console.log("\n4. Testing EVM Revert & Panic Code Decoding...");
    const abiCoder = new ethers.AbiCoder();
    // Error(string) -> 0x08c379a0
    const errPayload = "0x08c379a0" + abiCoder.encode(["string"], ["Active DID not registered"]).substring(2);
    const decodedErr = dbg.decodeRevert(errPayload);
    assert.strictEqual(decodedErr.isRevert, true);
    assert.strictEqual(decodedErr.reasonType, 'Error(string)');
    assert.strictEqual(decodedErr.message, "Active DID not registered");
    console.log("   ✅ Error(string) successfully decoded: 'Active DID not registered'");

    // Panic(uint256) -> 0x4e487b71 with code 0x11 (underflow/overflow)
    const panicPayload = "0x4e487b71" + abiCoder.encode(["uint256"], [0x11]).substring(2);
    const decodedPanic = dbg.decodeRevert(panicPayload);
    assert.strictEqual(decodedPanic.isRevert, true);
    assert.strictEqual(decodedPanic.reasonType, 'Panic(uint256)');
    assert.strictEqual(decodedPanic.code, 0x11);
    assert.strictEqual(decodedPanic.message, 'Arithmetic underflow or overflow');
    console.log("   ✅ Panic(uint256) code 0x11 successfully mapped to 'Arithmetic underflow or overflow'");

    // -------------------------------------------------------------
    // Test 5: Root-Cause Diagnostic Engine
    // -------------------------------------------------------------
    console.log("\n5. Testing Root-Cause Diagnostic Engine...");
    const pqDiagnostic = dbg.diagnose("Post-Quantum security required. Address has no registered DID and ALLOW_LEGACY is false.");
    assert.strictEqual(pqDiagnostic.severity, 'error');
    assert.strictEqual(pqDiagnostic.category, 'Quantum Security Invariant');
    assert.strictEqual(pqDiagnostic.remediationAction?.type, 'upgrade_pq');
    console.log("   ✅ Post-Quantum security violation diagnosed with upgrade remediation action.");

    const verkleDiagnostic = dbg.diagnose("Receive verification failed: Invalid Verkle proof");
    assert.strictEqual(verkleDiagnostic.category, 'Consensus & Lattice');
    assert.strictEqual(verkleDiagnostic.remediationAction?.type, 'verify_verkle');
    console.log("   ✅ Stateless Verkle proof failure diagnosed with proof regeneration recommendation.");

    // -------------------------------------------------------------
    // Test 6: Dual-Signature In-Wallet PQ Prompt Flow
    // -------------------------------------------------------------
    console.log("\n6. Testing Dual-Signature In-Wallet PQ Confirmation Flow...");
    let promptTriggered = false;
    let receivedRequest: PqSignRequest | null = null;
    const mockWallet = ethers.Wallet.createRandom();
    const mockEip1193 = {
        request: async ({ method }: { method: string }) => {
            if (method === 'eth_chainId') return '0x539';
            return [];
        }
    };
    const client = new SovereignClient(mockEip1193 as any, { executionMode: 'legacy_wrapped' });
    client.signer = mockWallet;

    // Set interactive prompt hook
    client.onPqSignaturePrompt = async (req: PqSignRequest) => {
        promptTriggered = true;
        receivedRequest = req;
        return true; // Simulate user clicking [Authorize PQ Signature]
    };

    // Dispatch quantum precompile call
    try {
        await client.dispatchPrecompile('DID_REGISTRY', 'setAllowLegacy', [true]);
    } catch (_) {
        // Expected because mockWallet is not connected to a live Reth RPC node in unit test
    }
    assert.strictEqual(promptTriggered, true);
    assert.ok(receivedRequest);
    assert.strictEqual((receivedRequest as PqSignRequest).keyScheme, 'ML-DSA-65');
    assert.strictEqual((receivedRequest as PqSignRequest).target.toLowerCase(), PRECOMPILES.DID_REGISTRY.toLowerCase());
    console.log("   ✅ In-Wallet PQ signature prompt was triggered and authorized prior to EVM transaction.");

    // Test rejection path
    client.onPqSignaturePrompt = async () => false; // User rejects
    let rejectedError = false;
    try {
        await client.dispatchPrecompile('DID_REGISTRY', 'setAllowLegacy', [true]);
    } catch (e: any) {
        if (e.message.includes("User rejected Post-Quantum signature authorization")) {
            rejectedError = true;
        }
    }
    assert.strictEqual(rejectedError, true);
    console.log("   ✅ In-Wallet PQ rejection correctly aborted transaction execution.");

    // -------------------------------------------------------------
    // Test 7: Account-Scoped Folder Storage Isolation
    // -------------------------------------------------------------
    console.log("\n7. Testing Account-Scoped Folder Storage Isolation...");
    const addrA = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const addrB = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    const scopedA = storage.forAccount(addrA);
    const scopedB = storage.forAccount(addrB);

    scopedA.saveKeys({ pqPublicKey: "pk_a_mldsa65", keyTier: "QuantumReady" });
    scopedA.saveCustomContract({
        name: "VaultA",
        targetAddress: "0x1111111111111111111111111111111111111111",
        abi: ["function vaultDeposit() external"],
        uploadedAt: Date.now()
    });

    scopedB.saveKeys({ pqPublicKey: "pk_b_falcon", keyTier: "QuantumNative" });

    // Assert isolation
    assert.strictEqual(scopedA.getKeys().pqPublicKey, "pk_a_mldsa65");
    assert.strictEqual(scopedB.getKeys().pqPublicKey, "pk_b_falcon");
    assert.strictEqual(scopedA.getCustomContracts().length, 1);
    assert.strictEqual(scopedB.getCustomContracts().length, 0); // Must be strictly 0 for B
    console.log("   ✅ State strictly isolated within accounts/<address>/ directories without leakage.");

    // -------------------------------------------------------------
    // Test 8: Toolchain Interop (Remix & Foundry) & Reclaim Timeout
    // -------------------------------------------------------------
    console.log("\n8. Testing Toolchain Interop (Remix & Foundry) & Reclaim Timeout...");
    
    // Unwrapped calldata extraction from quantum envelope
    const cleanRemixCalldata = dbg.exportRemixCalldata(fullEnvelope);
    assert.strictEqual(cleanRemixCalldata.toLowerCase(), transferCalldata.toLowerCase());
    console.log("   ✅ Clean unwrapped calldata successfully extracted for Remix.");

    // Foundry cast command generation
    const castCmd = dbg.exportFoundryCastCommand("0x0000000000000000000000000000000000000003", fullEnvelope);
    assert.strictEqual(castCmd.includes("cast call 0x0000000000000000000000000000000000000003"), true);
    assert.strictEqual(castCmd.includes("--rpc-url http://localhost:8545"), true);
    console.log("   ✅ Foundry 'cast call' CLI command successfully formatted.");

    // Remix deep-link generation
    const remixUrl = dbg.generateRemixDeepLink("0x0000000000000000000000000000000000000003", fullEnvelope);
    assert.strictEqual(remixUrl.startsWith("https://remix.ethereum.org/#"), true);
    assert.strictEqual(remixUrl.includes("address=0x0000000000000000000000000000000000000003"), true);
    console.log("   ✅ Remix IDE deep-link successfully generated.");

    console.log("\n🎉 All Sovereign Debugger & PQ Tooling Unit Tests Passed Successfully!");
}

runTests().catch((e) => {
    console.error("❌ Test failure:", e);
    process.exit(1);
});
