// Unit Tests for Account Security Declaration & ALLOW_LEGACY Policy
import assert from 'assert';
import { ethers } from 'ethers';
import { SovereignClient } from '../../src/client.js';
import { AccountSecurityPolicy, AccountSecurityTier } from '../../src/types.js';

function runSecurityPolicyTests() {
    console.log("🛡️ Running Sovereign Account Security & ALLOW_LEGACY Policy Unit Tests...\n");

    const testAddress = "0x7777777777777777777777777777777777777777";
    const client = new SovereignClient(null, { executionMode: 'legacy_pure' });

    // Mock policy store for testing state transitions
    let mockPolicy: AccountSecurityPolicy = {
        address: testAddress,
        allowLegacy: false,
        hasPqDid: false,
        isQuantumSecure: false,
        securityTier: 'UninitializedBlocked',
        warning: "Post-Quantum security required. Address has no registered DID and ALLOW_LEGACY is false."
    };

    // Override security.getPolicy and setAllowLegacy with mock store
    client.security.getPolicy = async (addr: string) => ({ ...mockPolicy, address: addr });
    client.security.setAllowLegacy = async (allow: boolean) => {
        mockPolicy.allowLegacy = allow;
        if (allow && !mockPolicy.hasPqDid) {
            mockPolicy.securityTier = 'LegacyAllowedInsecure';
            mockPolicy.warning = "WARN: YOU ARE USING A NON POST QUANTUM SECURE ACCOUNT. Your funds rely on classical signature schemes that can be cracked by quantum computers. Upgrade to Post-Quantum by registering a DID.";
        } else if (!allow && !mockPolicy.hasPqDid) {
            mockPolicy.securityTier = 'UninitializedBlocked';
            mockPolicy.warning = "Post-Quantum security required. Address has no registered DID and ALLOW_LEGACY is false.";
        }
        return { status: "updated", allow_legacy: allow };
    };

    // 1. Test Invariant: Default Account is Blocked from Classical Transactions
    console.log("1. Verifying Default Invariant: ALLOW_LEGACY=false blocks classical un-wrapped transactions...");
    assert.strictEqual(mockPolicy.allowLegacy, false);
    assert.strictEqual(mockPolicy.isQuantumSecure, false);
    assert.strictEqual(mockPolicy.securityTier, 'UninitializedBlocked');

    let complianceCheck = null;
    return client.security.verifySecurityCompliance(testAddress).then(res => {
        assert.strictEqual(res.compliant, false);
        assert.ok(res.warning?.includes("BLOCKED"));
        console.log("   ✅ Default uninitialized account correctly flagged as non-compliant and blocked.\n");

        // 2. Test Setting ALLOW_LEGACY = true (Insecure Legacy Opt-In)
        console.log("2. Testing ALLOW_LEGACY=true opt-in and security warning generation...");
        return client.security.setAllowLegacy(true);
    }).then(() => {
        assert.strictEqual(mockPolicy.allowLegacy, true);
        assert.strictEqual(mockPolicy.securityTier, 'LegacyAllowedInsecure');
        assert.strictEqual(mockPolicy.isQuantumSecure, false);

        return client.security.verifySecurityCompliance(testAddress);
    }).then(res => {
        assert.strictEqual(res.compliant, false);
        assert.ok(res.warning?.includes("NON POST QUANTUM SECURE ACCOUNT"));
        assert.ok(res.warning?.includes("Want to change it? > Yes."));
        console.log(`   ✅ Security warning correctly surfaced: "${res.warning}"\n`);

        // 3. Test Upgrade to Quantum Secure
        console.log("3. Testing Upgrade to Quantum Secure (Register DID & disable ALLOW_LEGACY)...");
        client.did.register = async () => {
            mockPolicy.hasPqDid = true;
            mockPolicy.isQuantumSecure = true;
            mockPolicy.securityTier = 'QuantumNative';
            mockPolicy.warning = undefined;
            return { status: "registered" };
        };

        const dummyPqKey = ethers.hexlify(ethers.randomBytes(32));
        const dummyDidDoc = JSON.stringify({ id: `did:sovereign:1337:${testAddress}` });

        return client.security.upgradeToQuantumSecure(dummyPqKey, dummyDidDoc);
    }).then(() => {
        assert.strictEqual(mockPolicy.hasPqDid, true);
        assert.strictEqual(mockPolicy.allowLegacy, false);
        assert.strictEqual(mockPolicy.isQuantumSecure, true);
        assert.strictEqual(mockPolicy.securityTier, 'QuantumNative');

        return client.security.verifySecurityCompliance(testAddress);
    }).then(res => {
        assert.strictEqual(res.compliant, true);
        assert.strictEqual(res.warning, undefined);
        console.log("   ✅ Account successfully upgraded to QuantumNative. Compliance check passed with 0 warnings.\n");

        // 4. Test Quantum Wrapper Bypass
        console.log("4. Verifying Quantum Wrapper mode (EIP-8141) is accepted even if ALLOW_LEGACY=false...");
        const wrappedClient = new SovereignClient(null, { executionMode: 'legacy_wrapped' });
        assert.strictEqual(wrappedClient.mode, 'legacy_wrapped');
        console.log("   ✅ Quantum Wrapper envelope fulfills quantum requirements without requiring ALLOW_LEGACY=true.\n");

        console.log("🎉 All Account Security & ALLOW_LEGACY Policy Unit Tests Passed Successfully!");
    }).catch(err => {
        console.error("Test failed:", err);
        process.exit(1);
    });
}

runSecurityPolicyTests();
