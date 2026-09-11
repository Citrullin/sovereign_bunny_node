// Sovereign SDK: SovereignProvider & SovereignClient extending ethers.js
// Provides transparent dual-mode execution (Legacy Bytecode + Quantum Wrapper vs Modern CAIP/gRPC)

class SovereignProvider extends ethers.BrowserProvider {
    constructor(ethereumProvider, network) {
        super(ethereumProvider, network);
    }

    /// Queries target account lattice height via Precompile 0x0100
    async getAccountHeight(targetAddress) {
        try {
            const contract = getPrecompileContract('LATTICE_HEIGHT', this);
            const height = await contract.getAccountHeight(targetAddress);
            return BigInt(height);
        } catch (e) {
            console.warn("Failed to getAccountHeight via precompile, falling back to 0:", e);
            return 0n;
        }
    }

    /// Resolves mounted polymorphic slot via Precompile 0x01
    async resolveSlot(account, slotId) {
        try {
            const contract = getPrecompileContract('ROUTER', this);
            return await contract.resolveSlot(account, slotId);
        } catch (e) {
            console.warn(`Failed to resolve slot ${slotId} via precompile:`, e);
            return { mounted: false, pluginId: "", root: ethers.ZeroHash };
        }
    }

    /// Resolves W3C DID document via Precompile 0x03
    async resolveDid(account) {
        try {
            const contract = getPrecompileContract('DID_REGISTRY', this);
            return await contract.resolveDid(account);
        } catch (e) {
            console.warn("Failed to resolveDid via precompile:", e);
            return null;
        }
    }

    /// Evaluates Zanzibar ReBAC authorization in RAM via Precompile 0x61
    async checkRebac(namespace, objectId, relation, subject) {
        try {
            const contract = getPrecompileContract('ZANZIBAR_REBAC', this);
            const objIdBytes32 = ethers.getBytes(objectId.padEnd(66, '0').slice(0, 66));
            return await contract.check(namespace, objIdBytes32, relation, subject);
        } catch (e) {
            console.warn("ReBAC precompile check failed:", e);
            return false;
        }
    }

    /// Checks compliance against jurisdiction quadrant via Precompile 0x05
    async checkCompliance(account, quadrant) {
        try {
            const contract = getPrecompileContract('JURISDICTION', this);
            return await contract.checkCompliance(account, quadrant);
        } catch (e) {
            console.warn("Jurisdiction precompile check failed:", e);
            return { compliant: false, activeBits: 0n };
        }
    }
}

class SovereignClient {
    constructor(ethereumProvider, options = {}) {
        this.rawProvider = ethereumProvider || null;
        this.provider = (ethereumProvider && typeof ethereumProvider.request === 'function')
            ? new SovereignProvider(ethereumProvider)
            : null;
        this.signer = null;
        this.apiMode = options.apiMode || localStorage.getItem("sovereign_api_mode") || "legacy";
        this.cryptoWrap = options.cryptoWrap || localStorage.getItem("sovereign_crypto_wrap") || "wrapped";
        this.rpcUrl = options.rpcUrl || localStorage.getItem("sovereign_rpc_url") || "http://localhost:8545";
        this.storageUrl = options.storageUrl || localStorage.getItem("sovereign_storage_url") || "http://localhost:8548";

        this.storageManager = new AccountStorageManager();
        this.debugger = new SovereignDebugger(this.storageManager);
        this.onPqSignaturePrompt = null;

        this._initDomainControllers();
    }

    async initSigner() {
        if (this.provider) {
            try {
                this.signer = await this.provider.getSigner();
                return this.signer;
            } catch (e) {
                console.warn("No active EVM signer available:", e);
                this.signer = null;
            }
        }
        return null;
    }

    setMode(apiMode, cryptoWrap) {
        this.apiMode = apiMode;
        this.cryptoWrap = cryptoWrap;
        localStorage.setItem("sovereign_api_mode", apiMode);
        localStorage.setItem("sovereign_crypto_wrap", cryptoWrap);
    }

    async _promptAuth(type, target, summary, calldata, caller) {
        const promptFn = this.onPqSignaturePrompt || (typeof window !== "undefined" ? window.promptPqSignature : null);
        if (promptFn) {
            let callerAddr = caller;
            if (!callerAddr) {
                try {
                    callerAddr = this.signer ? await this.signer.getAddress() : null;
                } catch (_) {}
            }
            if (!callerAddr && typeof connectedAddress !== "undefined") {
                callerAddr = connectedAddress;
            }
            const approved = await promptFn({
                type: type || 'CAIP State Change',
                target: target || '0x0000000000000000000000000000000000000000',
                caller: callerAddr || '0x0000000000000000000000000000000000000000',
                keyScheme: 'ML-DSA-65 (NIST FIPS 204)',
                summary: summary || 'Authorize State Change',
                calldata: calldata || '0x'
            });
            if (!approved) {
                throw new Error("Transaction authorization rejected by user in Sovereign Wallet");
            }
        }
    }

    _initDomainControllers() {
        const self = this;

        // 1. Polymorphic Slots (Precompile 0x01)
        this.slots = {
            async mount(slotId, pluginId, initialRoot) {
                if (self.apiMode === "legacy") {
                    await self.initSigner();
                    if (!self.signer) throw new Error("Wallet not connected for legacy transaction");
                    const contract = getPrecompileContract('ROUTER', self.signer);
                    const rootBytes32 = typeof initialRoot === "string" ? ethers.getBytes(initialRoot) : initialRoot;
                    const tx = await contract.mountSlot(slotId, pluginId, rootBytes32);
                    console.log(`[dApp Mode] Sent mountSlot tx: ${tx.hash}`);
                    return await tx.wait();
                } else {
                    // Modern CAIP / RPC dispatch
                    await self._promptAuth(
                        'CAIP Slot Mount',
                        '0x0000000000000000000000000000000000000001',
                        `Mount Polymorphic Slot ${slotId} (${pluginId})`,
                        `slotId=${slotId}&plugin=${pluginId}&root=${initialRoot}`
                    );
                    const res = await self._postRpc("bunny_mountSlot", [slotId, pluginId, initialRoot]);
                    return { status: 1, result: res };
                }
            },
            async resolve(account, slotId) {
                if (self.provider) {
                    return await self.provider.resolveSlot(account, slotId);
                }
                const res = await self._postRpc("bunny_resolveSlot", [account, slotId]);
                return res;
            }
        };

        // 2. DID Registry (Precompile 0x03)
        this.did = {
            async register(keyTier, pqPublicKey, didDocument) {
                if (self.apiMode === "legacy") {
                    await self.initSigner();
                    if (!self.signer) throw new Error("Wallet not connected: DID registration requires on-chain caller signature");
                    const contract = getPrecompileContract('DID_REGISTRY', self.signer);
                    const pqBytes = typeof pqPublicKey === "string" ? ethers.getBytes(pqPublicKey) : pqPublicKey;
                    const tx = await contract.registerDid(keyTier, pqBytes, didDocument);
                    console.log(`[dApp Mode] Sent registerDid tx: ${tx.hash}`);
                    return await tx.wait();
                } else {
                    // Modern CAIP in-wallet authorization & RPC dispatch
                    const docStr = typeof didDocument === "string" ? didDocument : JSON.stringify(didDocument);
                    await self._promptAuth(
                        'CAIP DID Registration',
                        '0x0000000000000000000000000000000000000003',
                        'Register Post-Quantum DID Document on Chain (Slot 0x03)',
                        docStr
                    );
                    const parsedDoc = typeof didDocument === "string" ? JSON.parse(didDocument) : didDocument;
                    const res = await self._postRpc("bunny_registerDid", [parsedDoc]);
                    return { status: 1, result: res, hash: res?.tx_hash, transactionHash: res?.tx_hash };
                }
            },
            async resolve(account) {
                if (self.provider) {
                    const doc = await self.provider.resolveDid(account);
                    if (doc) return JSON.parse(doc);
                }
                const res = await self._postRpc("bunny_resolveDidDocument", [account]);
                return res;
            }
        };

        // 3. ActivityPub CMS (Precompile 0xF1)
        this.activitypub = {
            async publish(signedActivityPayload, pinningFeeWei = 0n) {
                const payloadBytes = typeof signedActivityPayload === "string" 
                    ? ethers.toUtf8Bytes(signedActivityPayload) 
                    : signedActivityPayload;

                if (self.apiMode === "legacy") {
                    await self.initSigner();
                    if (!self.signer) throw new Error("Wallet not connected for legacy transaction");
                    const contract = getPrecompileContract('CMS_ACTPUB', self.signer);
                    const tx = await contract.publishActivity(payloadBytes, { value: pinningFeeWei });
                    console.log(`[dApp Mode] Sent publishActivity tx: ${tx.hash} with fee ${pinningFeeWei}`);
                    return await tx.wait();
                } else {
                    // Modern CAIP confirmation prompt before broadcasting note
                    const rawStr = typeof signedActivityPayload === "string" ? signedActivityPayload : ethers.toUtf8String(payloadBytes);
                    await self._promptAuth(
                        'CAIP ActivityPub Broadcast',
                        '0x00000000000000000000000000000000000000F1',
                        'Publish Fediverse ActivityPub Note to CMS Outbox',
                        rawStr
                    );
                    const hexPayload = ethers.hexlify(payloadBytes);
                    const res = await self._postRpc("bunny_postActivityPub", [hexPayload]);
                    return { status: 1, result: res };
                }
            }
        };

        // 4. Zanzibar ReBAC (Precompile 0x61)
        this.zanzibar = {
            async check(namespace, objectId, relation, subject) {
                if (self.provider) {
                    return await self.provider.checkRebac(namespace, objectId, relation, subject);
                }
                return await self._postRpc("bunny_zanzibarCheck", [namespace, objectId, relation, subject]);
            },
            async inscribe(namespace, objectId, relation, subject) {
                if (self.apiMode === "legacy") {
                    await self.initSigner();
                    if (!self.signer) throw new Error("Wallet not connected");
                    const contract = getPrecompileContract('ZANZIBAR_REBAC', self.signer);
                    const objIdBytes32 = ethers.getBytes(objectId.padEnd(66, '0').slice(0, 66));
                    const tx = await contract.inscribeTuple(namespace, objIdBytes32, relation, subject);
                    console.log(`[dApp Mode] Inscribed Zanzibar tuple tx: ${tx.hash}`);
                    return await tx.wait();
                } else {
                    await self._promptAuth(
                        'CAIP Zanzibar Inscription',
                        '0x0000000000000000000000000000000000000061',
                        `Inscribe ReBAC Relation (ns: ${namespace}, rel: ${relation})`,
                        `ns=${namespace}&obj=${objectId}&rel=${relation}&sub=${subject}`
                    );
                    return await self._postRpc("bunny_inscribeTuple", [namespace, objectId, relation, subject]);
                }
            }
        };

        // 5. Jurisdiction (Precompile 0x05)
        this.jurisdiction = {
            async setQuadrantBits(quadrant, bits) {
                if (self.apiMode === "legacy") {
                    await self.initSigner();
                    if (!self.signer) throw new Error("Wallet not connected");
                    const contract = getPrecompileContract('JURISDICTION', self.signer);
                    const tx = await contract.setQuadrantBits(quadrant, BigInt(bits));
                    return await tx.wait();
                } else {
                    await self._promptAuth(
                        'CAIP Jurisdiction Update',
                        '0x0000000000000000000000000000000000000005',
                        `Set Ingress Compliance Bits (Quadrant ${quadrant})`,
                        `quadrant=${quadrant}&bits=${bits}`
                    );
                    return await self._postRpc("bunny_setJurisdiction", [quadrant, bits]);
                }
            },
            async check(account, quadrant) {
                if (self.provider) {
                    return await self.provider.checkCompliance(account, quadrant);
                }
                return await self._postRpc("bunny_checkCompliance", [account, quadrant]);
            }
        };

        // 6. Decentralized Storage DA (Iroh / Precompile 0x53)
        this.storage = {
            async uploadBlob(dataBytes) {
                const hexData = ethers.hexlify(dataBytes);
                if (self.apiMode === "modern") {
                    await self._promptAuth(
                        'CAIP Storage DA Upload',
                        '0x0000000000000000000000000000000000000053',
                        `Store Blob in Decentralized Iroh DA (${dataBytes.length} bytes)`,
                        hexData.slice(0, 66) + '...'
                    );
                }
                const res = await fetch(`${self.storageUrl}/storage_storeBlob`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ data: hexData })
                });
                if (!res.ok) {
                    // Fallback to local node JSON-RPC
                    return await self._postRpc("storage_storeBlob", [{ data: hexData }]);
                }
                return await res.json();
            },
            async fetchBlob(cid) {
                const res = await fetch(`${self.storageUrl}/blob/${cid}`);
                if (!res.ok) throw new Error(`Failed to fetch blob CID: ${cid}`);
                return await res.blob();
            }
        };

        // 7. Security Policy & ALLOW_LEGACY Controller
        this.security = {
            async getPolicy(account) {
                if (self.provider) {
                    try {
                        const contract = getPrecompileContract('DID_REGISTRY', self.provider);
                        const res = await contract.getSecurityPolicy(account);
                        const allowLegacy = Boolean(res[0]);
                        const hasPqDid = Boolean(res[1]);
                        const isQuantumSecure = Boolean(res[2]);
                        const tier = hasPqDid ? 'QuantumNative' : (allowLegacy ? 'LegacyAllowedInsecure' : 'UninitializedBlocked');
                        return {
                            address: account,
                            allowLegacy,
                            hasPqDid,
                            isQuantumSecure,
                            securityTier: tier,
                            warning: (!isQuantumSecure && allowLegacy)
                                ? "WARN: YOU ARE USING A NON POST QUANTUM SECURE ACCOUNT. Your funds rely on classical signature schemes that can be cracked by quantum computers. Upgrade to Post-Quantum by registering a DID."
                                : undefined
                        };
                    } catch (_) {}
                }
                return await self._postRpc("sovereign_getAccountSecurity", [account]);
            },
            async setAllowLegacy(allow) {
                if (self.apiMode === "legacy") {
                    await self.initSigner();
                    if (!self.signer) throw new Error("Wallet not connected");
                    const contract = getPrecompileContract('DID_REGISTRY', self.signer);
                    const tx = await contract.setAllowLegacy(allow);
                    return await tx.wait();
                } else {
                    await self.initSigner();
                    const addr = self.signer ? await self.signer.getAddress() : (typeof connectedAddress !== "undefined" ? connectedAddress : ethers.ZeroAddress);
                    await self._promptAuth(
                        'CAIP Security Policy Update',
                        '0x0000000000000000000000000000000000000003',
                        `Set ALLOW_LEGACY policy to ${allow}`,
                        `account=${addr}&allowLegacy=${allow}`,
                        addr
                    );
                    return await self._postRpc("sovereign_setAllowLegacy", [addr, allow]);
                }
            },
            async verifySecurityCompliance(account) {
                const policy = await this.getPolicy(account);
                if (policy.isQuantumSecure) {
                    return { compliant: true };
                }
                if (policy.allowLegacy) {
                    return {
                        compliant: false,
                        warning: "WARN: YOU ARE USING A NON POST QUANTUM SECURE ACCOUNT. Want to change it? > Yes."
                    };
                }
                return {
                    compliant: false,
                    warning: "🛑 BLOCKED: Address has no registered Post-Quantum DID and ALLOW_LEGACY is false. Classical transactions rejected."
                };
            },
            async upgradeToQuantumSecure(pqPublicKey, didDocument) {
                await self.did.register("QuantumReady", pqPublicKey, didDocument);
                await this.setAllowLegacy(false);
                return { status: "upgraded_to_quantum_secure" };
            }
        };

        // 8. Account-Lattice & Send/Receive/Reclaim Controller
        this.lattice = {
            async getHeight(address) {
                if (self.provider) {
                    return await self.provider.getAccountHeight(address);
                }
                const res = await self._postRpc("bunny_getAccountHeight", [address]);
                return BigInt(res || 0);
            },
            async getPendingInbox(address) {
                return await self._postRpc("sovereign_getPendingInbox", [address]);
            },
            async receive(recipient, sendBlockHash, proofHex = "0x") {
                if (self.apiMode === "modern") {
                    await self._promptAuth(
                        'CAIP Lattice Receive',
                        '0x0000000000000000000000000000000000000002',
                        `Settle Lattice Receive Block for ${sendBlockHash.slice(0, 10)}...`,
                        `recipient=${recipient}&sendBlock=${sendBlockHash}`,
                        recipient
                    );
                }
                return await self._postRpc("sovereign_receive", [recipient, sendBlockHash, proofHex]);
            },
            async reclaimSend(sender, sendBlockHash, currentBlockNum = 0) {
                if (self.apiMode === "modern") {
                    await self._promptAuth(
                        'CAIP Lattice Reclaim',
                        '0x0000000000000000000000000000000000000002',
                        `Reclaim Unclaimed Transfer ${sendBlockHash.slice(0, 10)}...`,
                        `sender=${sender}&sendBlock=${sendBlockHash}`,
                        sender
                    );
                }
                return await self._postRpc("sovereign_reclaimSend", [sender, sendBlockHash, currentBlockNum]);
            },
            async getReclaimTimeout() {
                return await self._postRpc("sovereign_getReclaimTimeout");
            },
            async setReclaimTimeout(epochs) {
                if (self.apiMode === "modern") {
                    await self._promptAuth(
                        'CAIP Reclaim Timeout',
                        '0x0000000000000000000000000000000000000002',
                        `Set Reclaim Timeout to ${epochs} epochs`,
                        `epochs=${epochs}`
                    );
                }
                return await self._postRpc("sovereign_setReclaimTimeout", [epochs]);
            }
        };
    }

    async _postRpc(method, params = []) {
        const payload = {
            jsonrpc: "2.0",
            method: method,
            params: params,
            id: Date.now()
        };
        const res = await fetch(this.rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const json = await res.json();
        if (json.error) {
            throw new Error(json.error.message || `RPC Error: ${json.error.code}`);
        }
        return json.result;
    }
}

// Account-Scoped Storage Manager (Browser Runtime)
class AccountStorageManager {
    _key(address, category, subkey) {
        const norm = (address || 'global').toLowerCase();
        return subkey ? `accounts/${norm}/${category}/${subkey}` : `accounts/${norm}/${category}`;
    }
    getAccountKeys(address) {
        try { return JSON.parse(localStorage.getItem(this._key(address, 'keys'))) || {}; } catch (_) { return {}; }
    }
    saveAccountKeys(address, updates) {
        const current = this.getAccountKeys(address);
        localStorage.setItem(this._key(address, 'keys'), JSON.stringify({ ...current, ...updates }));
    }
    getCustomContracts(address) {
        try { return JSON.parse(localStorage.getItem(this._key(address, 'contracts'))) || []; } catch (_) { return []; }
    }
    saveCustomContract(address, contract) {
        const contracts = this.getCustomContracts(address);
        const idx = contracts.findIndex(c => c.targetAddress?.toLowerCase() === contract.targetAddress?.toLowerCase() || c.name?.toLowerCase() === contract.name?.toLowerCase());
        if (idx >= 0) contracts[idx] = contract; else contracts.push(contract);
        localStorage.setItem(this._key(address, 'contracts'), JSON.stringify(contracts));
    }
    getZanzibarTuples(address) {
        try { return JSON.parse(localStorage.getItem(this._key(address, 'zanzibar', 'tuples'))) || []; } catch (_) { return []; }
    }
    saveZanzibarTuple(address, tuple) {
        const tuples = this.getZanzibarTuples(address);
        tuples.push(tuple);
        localStorage.setItem(this._key(address, 'zanzibar', 'tuples'), JSON.stringify(tuples));
    }
    getDebugTraces(address) {
        try { return JSON.parse(localStorage.getItem(this._key(address, 'traces'))) || []; } catch (_) { return []; }
    }
    saveDebugTrace(address, trace) {
        const traces = this.getDebugTraces(address);
        traces.unshift(trace);
        if (traces.length > 50) traces.length = 50;
        localStorage.setItem(this._key(address, 'traces'), JSON.stringify(traces));
    }
}

const EVM_OPCODES_JS = {
    0x00: 'STOP', 0x01: 'ADD', 0x02: 'MUL', 0x03: 'SUB', 0x04: 'DIV', 0x05: 'SDIV', 0x06: 'MOD', 0x07: 'SMOD',
    0x08: 'ADDMOD', 0x09: 'MULMOD', 0x0a: 'EXP', 0x0b: 'SIGNEXTEND', 0x10: 'LT', 0x11: 'GT', 0x12: 'SLT',
    0x13: 'SGT', 0x14: 'EQ', 0x15: 'ISZERO', 0x16: 'AND', 0x17: 'OR', 0x18: 'XOR', 0x19: 'NOT', 0x1a: 'BYTE',
    0x1b: 'SHL', 0x1c: 'SHR', 0x1d: 'SAR', 0x20: 'KECCAK256', 0x30: 'ADDRESS', 0x31: 'BALANCE', 0x32: 'ORIGIN',
    0x33: 'CALLER', 0x34: 'CALLVALUE', 0x35: 'CALLDATALOAD', 0x36: 'CALLDATASIZE', 0x37: 'CALLDATACOPY',
    0x38: 'CODESIZE', 0x39: 'CODECOPY', 0x3a: 'GASPRICE', 0x3b: 'EXTCODESIZE', 0x3c: 'EXTCODECOPY',
    0x3d: 'RETURNDATASIZE', 0x3e: 'RETURNDATACOPY', 0x3f: 'EXTCODEHASH', 0x40: 'BLOCKHASH', 0x41: 'COINBASE',
    0x42: 'TIMESTAMP', 0x43: 'NUMBER', 0x44: 'PREVRANDAO', 0x45: 'GASLIMIT', 0x46: 'CHAINID', 0x47: 'SELFBALANCE',
    0x48: 'BASEFEE', 0x49: 'BLOBHASH', 0x4a: 'BLOBBASEFEE', 0x50: 'POP', 0x51: 'MLOAD', 0x52: 'MSTORE',
    0x53: 'MSTORE8', 0x54: 'SLOAD', 0x55: 'SSTORE', 0x56: 'JUMP', 0x57: 'JUMPI', 0x58: 'PC', 0x59: 'MSIZE',
    0x5a: 'GAS', 0x5b: 'JUMPDEST', 0x5c: 'TLOAD', 0x5d: 'TSTORE', 0x5e: 'MCOPY', 0x5f: 'PUSH0',
    0x80: 'DUP1', 0x81: 'DUP2', 0x82: 'DUP3', 0x83: 'DUP4', 0x84: 'DUP5', 0x85: 'DUP6', 0x86: 'DUP7', 0x87: 'DUP8',
    0x88: 'DUP9', 0x89: 'DUP10', 0x8a: 'DUP11', 0x8b: 'DUP12', 0x8c: 'DUP13', 0x8d: 'DUP14', 0x8e: 'DUP15', 0x8f: 'DUP16',
    0x90: 'SWAP1', 0x91: 'SWAP2', 0x92: 'SWAP3', 0x93: 'SWAP4', 0x94: 'SWAP5', 0x95: 'SWAP6', 0x96: 'SWAP7', 0x97: 'SWAP8',
    0x98: 'SWAP9', 0x99: 'SWAP10', 0x9a: 'SWAP11', 0x9b: 'SWAP12', 0x9c: 'SWAP13', 0x9d: 'SWAP14', 0x9e: 'SWAP15', 0x9f: 'SWAP16',
    0xa0: 'LOG0', 0xa1: 'LOG1', 0xa2: 'LOG2', 0xa3: 'LOG3', 0xa4: 'LOG4',
    0xf0: 'CREATE', 0xf1: 'CALL', 0xf2: 'CALLCODE', 0xf3: 'RETURN', 0xf4: 'DELEGATECALL', 0xf5: 'CREATE2',
    0xfa: 'STATICCALL', 0xfd: 'REVERT', 0xfe: 'INVALID', 0xff: 'SELFDESTRUCT'
};
for (let i = 1; i <= 32; i++) {
    EVM_OPCODES_JS[0x5f + i] = `PUSH${i}`;
}

// Sovereign Debugger Engine (Browser Runtime)
class SovereignDebugger {
    constructor(storageManager) {
        this.storageManager = storageManager;
        this.customAbis = new Map();
    }
    registerCustomAbi(addressOrName, abi) {
        try {
            const iface = new ethers.Interface(abi);
            this.customAbis.set(addressOrName.toLowerCase(), iface);
        } catch (e) {
            console.warn("Failed to register custom ABI in browser:", e);
        }
    }
    loadAccountCustomContracts(accountAddress) {
        if (!this.storageManager || !accountAddress) return;
        const contracts = this.storageManager.getCustomContracts(accountAddress);
        for (const c of contracts) {
            this.registerCustomAbi(c.targetAddress, c.abi);
            this.registerCustomAbi(c.name, c.abi);
        }
    }
    unwrapQuantumEnvelope(calldataHex) {
        const cleanHex = (calldataHex || "").trim().toLowerCase().startsWith("0x")
            ? calldataHex.trim().substring(2)
            : (calldataHex || "").trim();
        if (cleanHex.startsWith("8141") || cleanHex.startsWith("f18141") || cleanHex.length > 500) {
            try {
                if (cleanHex.length >= 136) {
                    const innerTarget = "0x" + cleanHex.slice(8, 48);
                    const r = "0x" + cleanHex.slice(48, 112);
                    const s = "0x" + cleanHex.slice(112, 176);
                    const v = parseInt(cleanHex.slice(176, 178) || "1b", 16);
                    const pqSig = "0x" + cleanHex.slice(178, Math.min(cleanHex.length, 178 + 3309 * 2));
                    const innerCalldata = cleanHex.length > (178 + 3309 * 2)
                        ? "0x" + cleanHex.slice(178 + 3309 * 2)
                        : "0x";
                    return {
                        isWrapped: true,
                        envelopeType: "EIP-8141-ML-DSA-65",
                        outerSignature: { v, r, s },
                        pqSignatureHex: pqSig,
                        innerTargetAddress: innerTarget,
                        innerCalldataHex: innerCalldata
                    };
                }
            } catch (_) {}
        }
        return { isWrapped: false, envelopeType: "None" };
    }
    decodeCalldata(targetAddress, calldataHex) {
        const normTarget = (targetAddress || "").toLowerCase();
        let targetName = normTarget;
        let functions = [];
        for (const [key, addr] of Object.entries(PRECOMPILES)) {
            if (addr.toLowerCase() === normTarget) {
                targetName = key;
                functions = SOVEREIGN_ABIS[key] || [];
                break;
            }
        }
        const isPrecompile = functions.length > 0;
        let raw = (calldataHex || "").trim();
        if (!raw.startsWith("0x")) raw = "0x" + raw;

        const unwrapped = this.unwrapQuantumEnvelope(raw);
        const effectiveTarget = (unwrapped.isWrapped && unwrapped.innerTargetAddress) ? unwrapped.innerTargetAddress : targetAddress;
        const effectiveCalldata = (unwrapped.isWrapped && unwrapped.innerCalldataHex && unwrapped.innerCalldataHex !== "0x") ? unwrapped.innerCalldataHex : raw;

        const selector = effectiveCalldata.slice(0, 10).toLowerCase();
        let functionSignature = null;
        let params = {};
        let mode = unwrapped.isWrapped ? "legacy_wrapped" : "legacy_pure";

        if (functions.length > 0) {
            try {
                const iface = new ethers.Interface(functions);
                const parsed = iface.parseTransaction({ data: effectiveCalldata });
                if (parsed) {
                    functionSignature = parsed.signature;
                    parsed.fragment.inputs.forEach((input, i) => {
                        const val = parsed.args[i];
                        params[input.name || `param_${i}`] = typeof val === 'bigint' ? val.toString() : val;
                    });
                }
            } catch (_) {}
        }
        if (!functionSignature && this.customAbis.has(normTarget)) {
            try {
                const iface = this.customAbis.get(normTarget);
                const parsed = iface.parseTransaction({ data: effectiveCalldata });
                if (parsed) {
                    functionSignature = parsed.signature;
                    parsed.fragment.inputs.forEach((input, i) => {
                        const val = parsed.args[i];
                        params[input.name || `param_${i}`] = typeof val === 'bigint' ? val.toString() : val;
                    });
                }
            } catch (_) {}
        }
        // 3. Specialized Precompile Bytecode Wire Decoders (Direct Packed Wire Format & CBOR)
        if (!functionSignature && (isPrecompile || effectiveTarget.startsWith("0x00000000000000000000000000000000000000") || effectiveTarget.startsWith("0x00000000000000000000000000000000000001"))) {
            const rawBytes = ethers.getBytes(effectiveCalldata.startsWith("0x") ? effectiveCalldata : "0x" + effectiveCalldata);
            const targetLower = effectiveTarget.toLowerCase();

            // 0x03 Universal DID Registry (Packed Wire: 1B tier_len || tier || 4B pq_len || pq_pub || did_doc)
            if (targetLower.endsWith("0003") || targetName === "DID_REGISTRY") {
                try {
                    let parsedSuccess = false;
                    if (rawBytes.length > 5) {
                        const tierLen = rawBytes[0];
                        if (rawBytes.length >= 1 + tierLen + 4) {
                            const keyTier = new TextDecoder().decode(rawBytes.slice(1, 1 + tierLen));
                            const pqLen = new DataView(rawBytes.buffer, rawBytes.byteOffset + 1 + tierLen, 4).getUint32(0, false);
                            const jsonOffset = 1 + tierLen + 4 + pqLen;
                            if (rawBytes.length >= jsonOffset) {
                                const pqPubKeyHex = ethers.hexlify(rawBytes.slice(1 + tierLen + 4, jsonOffset));
                                const docStr = new TextDecoder().decode(rawBytes.slice(jsonOffset));
                                let parsedDoc = docStr;
                                try { parsedDoc = JSON.parse(docStr); } catch (_) {}
                                functionSignature = "registerDid(string,bytes,string)";
                                mode = "precompile_packed";
                                params = {
                                    keyTier,
                                    pqPublicKey: pqPubKeyHex.length > 66 ? `${pqPubKeyHex.slice(0, 18)}... (${(pqPubKeyHex.length - 2) / 2} bytes)` : pqPubKeyHex,
                                    pqPublicKeyLength: `${(pqPubKeyHex.length - 2) / 2} bytes`,
                                    didDocument: parsedDoc
                                };
                                parsedSuccess = true;
                            }
                        }
                    }
                    if (!parsedSuccess) {
                        const docStr = new TextDecoder().decode(rawBytes);
                        if (docStr.includes("{") && docStr.includes("}")) {
                            const start = docStr.indexOf("{");
                            const end = docStr.lastIndexOf("}");
                            const parsedDoc = JSON.parse(docStr.slice(start, end + 1));
                            functionSignature = "registerDid(string)";
                            mode = "precompile_packed";
                            params = { didDocument: parsedDoc };
                            parsedSuccess = true;
                        }
                    }
                } catch (_) {}
            }

            // 0x02 Block-Lattice Receive / Reclaim Hook
            if (!functionSignature && (targetLower.endsWith("0002") || targetName === "RECEIVE")) {
                try {
                    const text = new TextDecoder().decode(rawBytes);
                    if (text.startsWith("reclaim:")) {
                        functionSignature = "reclaim(bytes32)";
                        mode = "precompile_packed";
                        params = { targetSendBlockHash: text.slice(8).trim() };
                    } else if (rawBytes.length === 32) {
                        functionSignature = "sweepReceive(bytes32)";
                        mode = "precompile_packed";
                        params = { sendBlockHash: ethers.hexlify(rawBytes) };
                    } else if (rawBytes.length >= 64) {
                        functionSignature = "sweepReceive(bytes32,uint256)";
                        mode = "precompile_packed";
                        params = {
                            sendBlockHash: ethers.hexlify(rawBytes.slice(0, 32)),
                            amount: ethers.toBigInt(rawBytes.slice(32, 64)).toString()
                        };
                    }
                } catch (_) {}
            }

            // 0x61 Zanzibar ReBAC Precompile
            if (!functionSignature && (targetLower.endsWith("0061") || targetName === "ZANZIBAR_REBAC")) {
                try {
                    if (rawBytes.length >= 54) {
                        const view = new DataView(rawBytes.buffer, rawBytes.byteOffset, rawBytes.length);
                        const namespace = view.getUint16(0, false);
                        const objectId = ethers.hexlify(rawBytes.slice(2, 34));
                        const relation = view.getUint16(34, false);
                        const subject = ethers.getAddress(ethers.hexlify(rawBytes.slice(36, 56)));
                        functionSignature = "check(uint16,bytes32,uint16,address)";
                        mode = "precompile_packed";
                        params = { namespace, objectId, relation, subject };
                    }
                } catch (_) {}
            }

            // 0xF1 W3C ActivityPub / CMS Precompile
            if (!functionSignature && (targetLower.endsWith("00f1") || targetName === "CMS_ACTPUB")) {
                try {
                    const docStr = new TextDecoder().decode(rawBytes);
                    if (docStr.includes("{") && docStr.includes("}")) {
                        const start = docStr.indexOf("{");
                        const end = docStr.lastIndexOf("}");
                        const parsed = JSON.parse(docStr.slice(start, end + 1));
                        functionSignature = "publishActivity(ActivityStreamsJson)";
                        mode = "precompile_packed";
                        params = parsed;
                    }
                } catch (_) {}
            }

            // 0x53 Storage DA & Bao Precompile
            if (!functionSignature && (targetLower.endsWith("0053") || targetName === "STORAGE_DA")) {
                try {
                    if (rawBytes.length >= 36) {
                        const chunkIdx = new DataView(rawBytes.buffer, rawBytes.byteOffset, 4).getUint32(0, false);
                        const cid = ethers.hexlify(rawBytes.slice(4, 36));
                        functionSignature = "verifyStoragePor(uint32,bytes32,bytes)";
                        mode = "precompile_packed";
                        params = { chunkIdx, cid, proofLength: `${rawBytes.length - 36} bytes` };
                    }
                } catch (_) {}
            }

            // 0x54 Signal Registry Precompile
            if (!functionSignature && (targetLower.endsWith("0054") || targetName === "SIGNAL_REGISTRY")) {
                try {
                    if (rawBytes.length >= 60) {
                        const topicId = ethers.hexlify(rawBytes.slice(0, 32));
                        const targetAddr = ethers.getAddress(ethers.hexlify(rawBytes.slice(32, 52)));
                        functionSignature = "inscribeSignal(bytes32,address,bytes)";
                        mode = "precompile_packed";
                        params = { topicId, target: targetAddr, signatureLength: `${rawBytes.length - 52} bytes` };
                    }
                } catch (_) {}
            }

            // 0x0100 Lattice Height
            if (!functionSignature && (targetLower.endsWith("0100") || targetName === "LATTICE_HEIGHT")) {
                try {
                    if (rawBytes.length >= 20) {
                        const account = ethers.getAddress(ethers.hexlify(rawBytes.slice(0, 20)));
                        functionSignature = "getAccountHeight(address)";
                        mode = "precompile_packed";
                        params = { account };
                    }
                } catch (_) {}
            }
        }

        // 4. Fallback to structured bytecode representation
        if (!functionSignature && effectiveCalldata.length > 10) {
            mode = "bytecode_raw";
            const byteLen = (effectiveCalldata.length - 2) / 2;
            const sliceEnd = Math.min(effectiveCalldata.length, 66);
            params = {
                byteLength: `${byteLen} bytes`,
                entryOpcode: effectiveCalldata.slice(2, 4).toUpperCase(),
                payloadPrefix: effectiveCalldata.slice(2, sliceEnd)
            };
        }
        return {
            targetAddress: effectiveTarget,
            targetName,
            isPrecompile,
            selector,
            functionSignature,
            params,
            rawCalldata: raw,
            mode,
            quantumEnvelope: unwrapped.isWrapped ? unwrapped : null
        };
    }
    decodeRevert(revertHex) {
        const clean = (revertHex || "").trim().toLowerCase().startsWith("0x")
            ? revertHex.trim().substring(2)
            : (revertHex || "").trim();
        if (clean.length < 8) return { isRevert: false, reasonType: "None", message: "No revert data" };
        const selector = clean.slice(0, 8);
        if (selector === "08c379a0") {
            try {
                const decoded = ethers.AbiCoder.defaultAbiCoder().decode(["string"], "0x" + clean.slice(8));
                return { isRevert: true, reasonType: "Error(string)", message: decoded[0] };
            } catch (_) {}
        }
        if (selector === "4e487b71") {
            try {
                const decoded = ethers.AbiCoder.defaultAbiCoder().decode(["uint256"], "0x" + clean.slice(8));
                const code = Number(decoded[0]);
                const PANIC_MAP = {
                    0x01: "Assertion failed (assert false)",
                    0x11: "Arithmetic underflow or overflow",
                    0x12: "Division or modulo by zero",
                    0x21: "Enum conversion out of bounds",
                    0x32: "Array index out of bounds",
                    0x41: "Out of memory allocation"
                };
                return { isRevert: true, reasonType: "Panic(uint256)", message: PANIC_MAP[code] || `Solidity Panic Code ${code}`, code };
            } catch (_) {}
        }
        return { isRevert: true, reasonType: "Custom", message: `Custom Revert Selector: 0x${selector}` };
    }
    diagnose(errorInput, context = {}) {
        const errStr = typeof errorInput === 'string' ? errorInput : JSON.stringify(errorInput);
        if (errStr.includes("Post-Quantum security required") || errStr.includes("-32001") || errStr.includes("ALLOW_LEGACY is false")) {
            return {
                severity: "error",
                category: "Quantum Security Invariant",
                title: "Classical Transaction Blocked by Post-Quantum Invariant",
                rootCause: "The sending address does not have a registered Post-Quantum DID on Precompile 0x03, and ALLOW_LEGACY is false. Sovereign networks require quantum-resistant signature schemes by default.",
                technicalDetails: `Target: ${context.to || 'Unknown'} | Invariant: ALLOW_LEGACY=false without DID registration`,
                suggestedRemediation: "Register a Post-Quantum DID (ML-DSA-65) for this account or enable ALLOW_LEGACY=true in Settings.",
                remediationAction: { type: "upgrade_pq", label: "🛡️ Upgrade to Quantum Secure" }
            };
        }
        if (errStr.includes("Active DID not registered") || errStr.includes("sovereign_registerDid first")) {
            return {
                severity: "error",
                category: "Identity & Authorization",
                title: "DID Identity Document Missing",
                rootCause: "The requested system action requires an active Sovereign DID registered in the consensus registry, but none was found for this caller.",
                technicalDetails: `Caller: ${context.from || 'Unknown'} | Precompile 0x03 Lookup Failed`,
                suggestedRemediation: "Call sovereign_registerDid on Precompile 0x03 with your public key and DID document.",
                remediationAction: { type: "upgrade_pq", label: "🌐 Register DID on Chain" }
            };
        }
        if (errStr.includes("Invalid Verkle proof") || errStr.includes("Receive verification failed")) {
            return {
                severity: "error",
                category: "Consensus & Lattice",
                title: "Stateless Verkle Witness Verification Failed",
                rootCause: "Precompile 0x02 (Receive) rejected the claim transaction because the provided Verkle witness proof did not match the latest finalized state root.",
                technicalDetails: "sovereign_consensus::lattice::verify_receive_stateless returned false",
                suggestedRemediation: "Generate a fresh Verkle witness proof against the current block header before dispatching the receive claim."
            };
        }
        if (errStr.includes("has not reached timeout block age") || errStr.includes("Reclaim failed")) {
            return {
                severity: "warning",
                category: "Lattice Timelock",
                title: "Send Transaction Timeout Block Height Not Reached",
                rootCause: "An unspent send transaction can only be reclaimed by the sender after the configured block timeout period has elapsed.",
                technicalDetails: "current_block_number < send_block_number + timeout_blocks",
                suggestedRemediation: "Wait until the target block height is mined before submitting sovereign_reclaimSend."
            };
        }
        if (errStr.includes("Zanzibar") || errStr.includes("unauthorized") || errStr.includes("0x61")) {
            return {
                severity: "error",
                category: "ReBAC Permissions",
                title: "Zanzibar Relation-Based Access Control Denied",
                rootCause: "Precompile 0x61 evaluated the requested (namespace, objectId, relation, subject) tuple and returned false. The subject lacks the required relation.",
                technicalDetails: "Precompile 0x61: check(namespace, objectId, relation, subject) => false",
                suggestedRemediation: "Inscribe the missing relation tuple into Slot 1 (0x61 inscribeTuple) using an authorized administrative key."
            };
        }
        if (errStr.includes("insufficient funds")) {
            return {
                severity: "error",
                category: "Account Balance",
                title: "Insufficient Funds for Gas or Transfer",
                rootCause: "The account balance is too low to cover the transaction value plus maximum gas cost.",
                technicalDetails: errStr,
                suggestedRemediation: "Top up the account or claim pending incoming zero-gas transfers from your inbox."
            };
        }
        return {
            severity: "info",
            category: "Execution Diagnostic",
            title: "Diagnostic Inspection Complete",
            rootCause: "Transaction or state-change evaluated. No known invariant violations detected.",
            technicalDetails: errStr,
            suggestedRemediation: "Inspect the decoded calldata and target precompile parameters below."
        };
    }
    disassembleBytecode(bytecodeHex) {
        const clean = (bytecodeHex || "").trim().replace(/^0x/i, '');
        if (!clean || clean.length % 2 !== 0) return [];
        const bytes = [];
        for (let i = 0; i < clean.length; i += 2) {
            bytes.push(parseInt(clean.slice(i, i + 2), 16));
        }

        const instructions = [];
        let pc = 0;
        while (pc < bytes.length) {
            const currentPc = pc;
            const op = bytes[pc];
            pc++;

            let mnemonic = EVM_OPCODES_JS[op] || `UNKNOWN_0x${op.toString(16).padStart(2, '0').toUpperCase()}`;
            let pushData = null;
            let annotation = null;

            if (op >= 0x60 && op <= 0x7f) {
                const pushBytesCount = op - 0x5f;
                const slice = bytes.slice(pc, pc + pushBytesCount);
                pushData = '0x' + slice.map(b => b.toString(16).padStart(2, '0')).join('');
                pc += pushBytesCount;

                if (pushBytesCount === 4) {
                    const sel = pushData.toLowerCase();
                    if (sel === '0x745ced80') annotation = 'mountSlot(uint8,string,bytes32)';
                    else if (sel === '0x9586e679') annotation = 'check(uint8,bytes32,uint8,address)';
                    else if (sel === '0xbfe671c0') annotation = 'registerDid(string,bytes,string)';
                    else if (sel === '0x23877017') annotation = 'getAccountHeight(address)';
                    else if (sel === '0x095ea7b3') annotation = 'approve(address,uint256)';
                    else if (sel === '0xa9059cbb') annotation = 'transfer(address,uint256)';
                }
            }

            instructions.push({
                pc: currentPc,
                opcode: op,
                mnemonic,
                pushData,
                annotation
            });
        }
        return instructions;
    }

    formatDisassembly(instructions) {
        if (!instructions || !instructions.length) return '';
        return instructions.map(inst => {
            const pcStr = `[${inst.pc.toString(16).padStart(4, '0')}]`;
            const opStr = inst.mnemonic.padEnd(12, ' ');
            const pushStr = inst.pushData ? inst.pushData : '';
            const annStr = inst.annotation ? ` // ${inst.annotation}` : '';
            return `${pcStr} ${opStr} ${pushStr}${annStr}`.trimEnd();
        }).join('\n');
    }

    async analyze(rawDump) {
        const trimmed = (rawDump || "").trim();
        let inputType = "calldata";
        let targetAddress = "0x0000000000000000000000000000000000000001";
        let senderAddress = null;
        let calldata = "0x";
        let txHash = null;
        let errorToDiagnose = trimmed;

        const isTxHash = /^0x[0-9a-fA-F]{64}$/.test(trimmed) || /^[0-9a-fA-F]{64}$/.test(trimmed);
        if (isTxHash) {
            inputType = 'tx_hash';
            txHash = trimmed.startsWith('0x') ? trimmed : ('0x' + trimmed);
            return {
                rawInput: rawDump,
                inputType: 'tx_hash',
                txHash,
                targetAddress,
                diagnostic: {
                    severity: 'info',
                    category: 'Transaction Hash',
                    title: 'State-Change / Transaction Hash Identified',
                    rootCause: `Supplied hash ${txHash} points to a block-lattice transaction.`,
                    technicalDetails: `Querying canonical history and RPC proxies for hash ${txHash}`,
                    suggestedRemediation: 'Loading full payload and parameters from node RPC...'
                }
            };
        }

        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            inputType = "json_rpc";
            try {
                const parsed = JSON.parse(trimmed);
                if (parsed.method === "eth_sendRawTransaction") {
                    calldata = parsed.params?.[0] || "0x";
                } else if (parsed.method === "eth_call") {
                    const txObj = parsed.params?.[0] || {};
                    targetAddress = txObj.to || targetAddress;
                    senderAddress = txObj.from;
                    calldata = txObj.data || "0x";
                } else if (parsed.error) {
                    errorToDiagnose = parsed.error.message || JSON.stringify(parsed.error);
                } else if (parsed.params && parsed.params[0]) {
                    calldata = typeof parsed.params[0] === 'string' ? parsed.params[0] : JSON.stringify(parsed.params[0]);
                }
            } catch (_) {}
        } else if (trimmed.startsWith("0x08c379a0") || trimmed.startsWith("0x4e487b71")) {
            inputType = "revert_hex";
        } else if (trimmed.startsWith("0x") && trimmed.length > 2) {
            inputType = "calldata";
            calldata = trimmed;
        } else if (/^[0-9a-fA-F]{4,}$/.test(trimmed)) {
            inputType = "bytecode";
            calldata = "0x" + trimmed;
        } else {
            inputType = "error_text";
        }

        const decodedRevert = (inputType === "revert_hex" || trimmed.includes("08c379a0") || trimmed.includes("4e487b71"))
            ? this.decodeRevert(trimmed)
            : null;

        const decodedCalldata = calldata !== "0x"
            ? this.decodeCalldata(targetAddress, calldata)
            : null;

        let disassembledOpcodes = null;
        let formattedOpcodes = null;
        if (calldata !== '0x' && calldata.length >= 4) {
            const unwrapped = this.unwrapQuantumEnvelope(calldata);
            const targetHex = (unwrapped.isWrapped && unwrapped.innerCalldataHex) ? unwrapped.innerCalldataHex : calldata;
            disassembledOpcodes = this.disassembleBytecode(targetHex);
            if (disassembledOpcodes.length > 0) {
                formattedOpcodes = this.formatDisassembly(disassembledOpcodes);
            }
        }

        const diagnostic = this.diagnose(errorToDiagnose, {
            to: targetAddress,
            from: senderAddress,
            data: calldata
        });

        if (senderAddress) {
            this.loadAccountCustomContracts(senderAddress);
        }

        return {
            rawInput: rawDump,
            inputType,
            txHash,
            senderAddress,
            targetAddress: decodedCalldata ? decodedCalldata.targetAddress : targetAddress,
            decodedCalldata,
            decodedRevert,
            diagnostic,
            disassembledOpcodes,
            formattedOpcodes
        };
    }

    exportRemixCalldata(rawCalldataHex) {
        const unwrapped = this.unwrapQuantumEnvelope(rawCalldataHex);
        if (unwrapped.isWrapped && unwrapped.innerCalldataHex && unwrapped.innerCalldataHex !== "0x") {
            return unwrapped.innerCalldataHex;
        }
        let clean = (rawCalldataHex || "").trim();
        if (!clean.startsWith("0x")) clean = "0x" + clean;
        return clean;
    }

    exportFoundryCastCommand(targetAddress, rawCalldataHex, rpcUrl = "http://localhost:8545") {
        const cleanCalldata = this.exportRemixCalldata(rawCalldataHex);
        return `cast call ${targetAddress} ${cleanCalldata} --rpc-url ${rpcUrl}`;
    }

    generateRemixDeepLink(targetAddress, rawCalldataHex) {
        const cleanCalldata = rawCalldataHex ? this.exportRemixCalldata(rawCalldataHex) : "";
        const params = new URLSearchParams({
            address: targetAddress,
            calldata: cleanCalldata,
        });
        return `https://remix.ethereum.org/#${params.toString()}`;
    }
}
