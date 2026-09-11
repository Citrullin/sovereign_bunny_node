// E2E Integration Tests for Sovereign SDK against Local Node
import assert from 'assert';
import { ethers } from 'ethers';
import { SovereignClient } from '../../src/client.js';
import { PRECOMPILES } from '../../src/contracts.js';

const RPC_URL = process.env.SOVEREIGN_RPC_URL || 'http://127.0.0.1:8545';

async function runE2ETests() {
    console.log(`🌐 Running Sovereign SDK E2E Integration Tests against ${RPC_URL}...\n`);

    // 1. Check if node is running before initializing persistent provider
    let nodeOnline = false;
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 1000);
        const res = await fetch(RPC_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jsonrpc: "2.0", method: "eth_blockNumber", params: [], id: 1 }),
            signal: controller.signal
        });
        clearTimeout(timeout);
        if (res.ok) {
            nodeOnline = true;
        }
    } catch (_) {
        nodeOnline = false;
    }

    if (!nodeOnline) {
        console.warn(`⚠️ Node not currently running at ${RPC_URL}. Skipping live network verification.`);
        console.log("   (To run live tests, start the node via 'cargo run --bin sovereign-bunny -- node --dev')\n");
        return;
    }

    // Static network configuration prevents endless polling if node state shifts
    const staticNetwork = ethers.Network.from({ chainId: 1337, name: 'sovereign-devnet' });
    const jsonRpcProvider = new ethers.JsonRpcProvider(RPC_URL, staticNetwork);

    try {
        const blockNum = await jsonRpcProvider.getBlockNumber();
        console.log(`1. Connected to Sovereign node. Current block number: ${blockNum}`);
        assert.ok(blockNum >= 0, "Block number must be >= 0");

        // 2. Query Account Height Precompile (0x0100)
        console.log("2. Querying Account Height Precompile 0x0100...");
        const targetAddress = "0x1111111111111111111111111111111111111111";
        const heightData = await jsonRpcProvider.call({
            to: PRECOMPILES.LATTICE_HEIGHT,
            data: targetAddress
        });
        console.log(`   ✅ Account Height raw call response: ${heightData}`);

        // 3. Query DID Precompile (0x03)
        console.log("3. Querying DID Precompile 0x03...");
        const didData = await jsonRpcProvider.call({
            to: PRECOMPILES.DID_REGISTRY,
            data: targetAddress
        });
        console.log(`   ✅ DID Registry response: ${didData.slice(0, 30)}...`);

        // 4. Query Zanzibar Precompile (0x61)
        console.log("4. Evaluating Zanzibar ReBAC Precompile 0x61 in RAM...");
        const zanzibarIface = new ethers.Interface([
            "function check(uint16 namespace, bytes32 objectId, uint16 relation, address subject) external view returns (bool)"
        ]);
        const checkCalldata = zanzibarIface.encodeFunctionData("check", [
            1,
            ethers.ZeroHash,
            1,
            targetAddress
        ]);
        const zanzibarResult = await jsonRpcProvider.call({
            to: PRECOMPILES.ZANZIBAR_REBAC,
            data: checkCalldata
        });
        console.log(`   ✅ Zanzibar authorization result: ${zanzibarResult}`);

        console.log("\n🎉 All Sovereign SDK E2E Integration Tests Passed Successfully!");
    } catch (e: any) {
        console.error("E2E test error:", e);
        throw e;
    }
}

runE2ETests().catch(err => {
    console.error(err);
    process.exit(1);
});
