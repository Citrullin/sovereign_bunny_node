// Sovereign SDK Client & Provider extending ethers.js
// Handles all 4 execution combinations:
// 1. Modern Web dApp (Ethers Classes + CBOR/QUIC)
// 2. Legacy dApp (Bytecode-Only to Precompile Addresses)
// 3. Legacy Pure EVM (Classical Secp256k1)
// 4. Quantum-Wrapped Envelope (EIP-8141 / Secp256k1 outer frame)

import { ethers } from 'ethers';
import {
    PrecompileName,
    SovereignClientOptions,
    SovereignExecutionMode,
    AccountSlotInfo,
    W3cDidDocument,
    JurisdictionComplianceResult,
    AccountSecurityPolicy,
    AccountSecurityTier
} from './types.js';
import { PRECOMPILES, getPrecompileContract, encodeRawPrecompileCall } from './contracts.js';
import { AccountStorageManager } from './storage_manager.js';
import { SovereignDebugger } from './debugger.js';

export interface PqSignRequest {
    type: 'quantum_envelope' | 'did_registration' | 'lattice_claim' | 'debugger_re_sign' | 'caip_state_change';
    target: string;
    caller: string;
    keyScheme: string;
    summary: string;
    calldata: string;
}

export class SovereignProvider extends ethers.BrowserProvider {
    constructor(ethereumProvider: ethers.Eip1193Provider, network?: ethers.Networkish) {
        super(ethereumProvider, network);
    }

    /// Queries target account lattice height via Precompile 0x0100
    async getAccountHeight(targetAddress: string): Promise<bigint> {
        try {
            const contract = getPrecompileContract('LATTICE_HEIGHT', this);
            const height = await contract.getAccountHeight(targetAddress);
            return BigInt(height);
        } catch (e) {
            console.warn("Failed to getAccountHeight via precompile:", e);
            return 0n;
        }
    }

    /// Resolves mounted polymorphic slot via Precompile 0x01
    async resolveSlot(account: string, slotId: number): Promise<AccountSlotInfo> {
        try {
            const contract = getPrecompileContract('ROUTER', this);
            const res = await contract.resolveSlot(account, slotId);
            return {
                mounted: Boolean(res[0]),
                pluginId: String(res[1]),
                root: String(res[2])
            };
        } catch (e) {
            return { mounted: false, pluginId: "", root: ethers.ZeroHash };
        }
    }

    /// Resolves W3C DID document via Precompile 0x03
    async resolveDid(account: string): Promise<W3cDidDocument | null> {
        try {
            const contract = getPrecompileContract('DID_REGISTRY', this);
            const docStr: string = await contract.resolveDid(account);
            if (!docStr) return null;
            return JSON.parse(docStr);
        } catch (e) {
            return null;
        }
    }

    /// Evaluates Zanzibar ReBAC authorization in RAM (<12µs) via Precompile 0x61
    async checkRebac(namespace: number, objectId: string, relation: number, subject: string): Promise<boolean> {
        try {
            const contract = getPrecompileContract('ZANZIBAR_REBAC', this);
            const objIdBytes32 = ethers.getBytes(objectId.padEnd(66, '0').slice(0, 66));
            return await contract.check(namespace, objIdBytes32, relation, subject);
        } catch (e) {
            return false;
        }
    }

    /// Checks compliance against jurisdiction quadrant via Precompile 0x05
    async checkCompliance(account: string, quadrant: number): Promise<JurisdictionComplianceResult> {
        try {
            const contract = getPrecompileContract('JURISDICTION', this);
            const res = await contract.checkCompliance(account, quadrant);
            return { compliant: Boolean(res[0]), activeBits: BigInt(res[1]) };
        } catch (e) {
            return { compliant: false, activeBits: 0n };
        }
    }

    /// Queries the account security policy via Precompile 0x03 or RPC
    async getSecurityPolicy(account: string): Promise<AccountSecurityPolicy> {
        try {
            const contract = getPrecompileContract('DID_REGISTRY', this);
            const res = await contract.getSecurityPolicy(account);
            const allowLegacy = Boolean(res[0]);
            const hasPqDid = Boolean(res[1]);
            const isQuantumSecure = Boolean(res[2]);
            const tier: AccountSecurityTier = hasPqDid 
                ? 'QuantumNative' 
                : (allowLegacy ? 'LegacyAllowedInsecure' : 'UninitializedBlocked');
            const warning = (!isQuantumSecure && allowLegacy)
                ? "WARN: YOU ARE USING A NON POST QUANTUM SECURE ACCOUNT. Your funds rely on classical signature schemes that can be cracked by quantum computers. Upgrade to Post-Quantum by registering a DID."
                : undefined;
            return {
                address: account,
                allowLegacy,
                hasPqDid,
                isQuantumSecure,
                securityTier: tier,
                warning
            };
        } catch (_) {
            return {
                address: account,
                allowLegacy: false,
                hasPqDid: false,
                isQuantumSecure: false,
                securityTier: 'UninitializedBlocked',
                warning: "Post-Quantum security required. Address has no registered DID and ALLOW_LEGACY is false."
            };
        }
    }
}

export class SovereignClient {
    public rawProvider: ethers.Eip1193Provider | null;
    public provider: SovereignProvider | null;
    public signer: ethers.Signer | null = null;
    public mode: SovereignExecutionMode;
    public rpcUrl: string;
    public storageUrl: string;

    // Domain Controllers
    public slots: {
        mount: (slotId: number, pluginId: string, initialRoot: string | Uint8Array) => Promise<any>;
        resolve: (account: string, slotId: number) => Promise<AccountSlotInfo>;
    };
    public did: {
        register: (keyTier: string, pqPublicKey: string | Uint8Array, didDocument: string) => Promise<any>;
        resolve: (account: string) => Promise<W3cDidDocument | null>;
        get: (didOrAddress: string) => Promise<any>;
        getByAddress: (address: string) => Promise<any>;
    };
    public activitypub: {
        publish: (signedActivityPayload: string | Uint8Array) => Promise<any>;
    };
    public zanzibar: {
        check: (namespace: number, objectId: string, relation: number, subject: string) => Promise<boolean>;
        inscribe: (namespace: number, objectId: string, relation: number, subject: string) => Promise<any>;
    };
    public jurisdiction: {
        setQuadrantBits: (quadrant: number, bits: bigint | number) => Promise<any>;
        check: (account: string, quadrant: number) => Promise<JurisdictionComplianceResult>;
    };
    public storage: {
        uploadBlob: (dataBytes: Uint8Array) => Promise<{ cid: string; size?: number }>;
        fetchBlob: (cid: string) => Promise<any>;
    };
    public lattice: {
        getHeight: (address: string) => Promise<bigint>;
        sweepReceive: (recipient: string, amountWei: bigint) => Promise<any>;
        getPendingInbox: (address: string) => Promise<any[]>;
        receive: (recipient: string, sendBlockHash: string, proofHex?: string) => Promise<any>;
        reclaimSend: (sender: string, sendBlockHash: string, currentBlockNum?: number) => Promise<any>;
        getReclaimTimeout: () => Promise<{ reclaim_timeout_epochs: number; current_epoch: number; blocks_per_epoch: number }>;
        setReclaimTimeout: (epochs: number) => Promise<any>;
    };
    public sessions: {
        getPermissions: () => Promise<any>;
        createSession: () => Promise<any>;
        getSession: () => Promise<any>;
        revokeSession: () => Promise<any>;
    };
    public security: {
        getPolicy: (account: string) => Promise<AccountSecurityPolicy>;
        setAllowLegacy: (allow: boolean) => Promise<any>;
        verifySecurityCompliance: (account: string) => Promise<{ compliant: boolean; warning?: string }>;
        upgradeToQuantumSecure: (pqPublicKey: string | Uint8Array, didDocument: string) => Promise<any>;
    };

    public storageManager: AccountStorageManager;
    public debugger: SovereignDebugger;
    public onPqSignaturePrompt?: (request: PqSignRequest) => Promise<boolean>;

    constructor(ethereumProvider?: ethers.Eip1193Provider | null, options: SovereignClientOptions = {}) {
        this.rawProvider = ethereumProvider || null;
        this.provider = (ethereumProvider && typeof (ethereumProvider as any).request === 'function')
            ? new SovereignProvider(ethereumProvider)
            : null;
        
        // Derive execution mode from options
        if (options.executionMode) {
            this.mode = options.executionMode;
        } else if (options.apiMode === 'modern') {
            this.mode = 'modern_cbor';
        } else if (options.cryptoWrap === 'pure') {
            this.mode = 'legacy_pure';
        } else {
            this.mode = 'legacy_wrapped';
        }

        this.rpcUrl = options.rpcUrl || 'http://localhost:8545';
        this.storageUrl = options.storageUrl || 'http://localhost:8548';

        this.storageManager = new AccountStorageManager();
        this.debugger = new SovereignDebugger(this.storageManager);

        this.slots = this._initSlots();
        this.did = this._initDid();
        this.activitypub = this._initActivityPub();
        this.zanzibar = this._initZanzibar();
        this.jurisdiction = this._initJurisdiction();
        this.storage = this._initStorage();
        this.lattice = this._initLattice();
        this.sessions = this._initSessions();
        this.security = this._initSecurity();
    }

    public async initSigner(): Promise<ethers.Signer | null> {
        if (!this.signer && this.rawProvider) {
            const browserProvider = new ethers.BrowserProvider(this.rawProvider);
            this.signer = await browserProvider.getSigner();
        }
        return this.signer;
    }

    setExecutionMode(mode: SovereignExecutionMode) {
        this.mode = mode;
    }

    /// Dispatches a precompile call according to the active execution combination
    async dispatchPrecompile(
        precompile: PrecompileName,
        functionName: string,
        params: any[] = [],
        valueWei: bigint = 0n
    ): Promise<any> {
        // Enforce account security invariants when in classical (non-quantum) execution modes
        if (this.mode === 'legacy_pure' || this.mode === 'bytecode_raw') {
            await this.initSigner();
            if (this.signer && this.provider) {
                try {
                    const senderAddr = await this.signer.getAddress();
                    const policy = await this.provider.getSecurityPolicy(senderAddr);
                    if (!policy.allowLegacy && !policy.hasPqDid) {
                        const compliance = await this.security.verifySecurityCompliance(senderAddr);
                        if (!compliance.compliant) {
                            throw new Error(`Sovereign Security Error: ${compliance.warning}`);
                        }
                    }
                } catch (e: any) {
                    if (e.message?.includes("Sovereign Security Error")) throw e;
                }
            }
        }

        // Enforce signer requirement for state-modifying actions in legacy_pure / bytecode_raw mode
        if ((this.mode === 'legacy_pure' || this.mode === 'bytecode_raw') && precompile === 'DID_REGISTRY' && (functionName === 'registerDid' || functionName === 'setAllowLegacy')) {
            await this.initSigner();
            if (!this.signer) throw new Error("Wallet not connected: DID registration and security policies require on-chain caller signature");
            const contract = getPrecompileContract(precompile, this.signer);
            const tx = await (contract as any)[functionName](...params, { value: valueWei });
            return await tx.wait();
        }

        switch (this.mode) {
            case 'modern_cbor': {
                // In modern CAIP mode, prompt user before executing state-changing action
                if (this.onPqSignaturePrompt) {
                    let callerAddr = '0x0000000000000000000000000000000000000000';
                    try {
                        if (this.signer) callerAddr = await this.signer.getAddress();
                    } catch (_) {}
                    const approved = await this.onPqSignaturePrompt({
                        type: 'caip_state_change',
                        target: PRECOMPILES[precompile],
                        caller: callerAddr,
                        keyScheme: 'ML-DSA-65',
                        summary: `Authorize CAIP state change for ${precompile}.${functionName}`,
                        calldata: encodeRawPrecompileCall(precompile, functionName, params)
                    });
                    if (!approved) {
                        throw new Error("User rejected Post-Quantum signature authorization in Sovereign Wallet");
                    }
                }
                // High-speed native dispatch over CBOR/HTTP-3 / JSON-RPC
                return await this._postRpc(`bunny_${functionName}`, params);
            }
            case 'legacy_wrapped': {
                // EIP-8141 Quantum-Wrapped Envelope / standard EVM transaction with PQ calldata
                await this.initSigner();
                if (!this.signer) throw new Error("Wallet not connected for legacy transaction");
                const caller = await this.signer.getAddress();

                // Dual-signature prompt: Ask user explicitly to sign PQ request inside Sovereign Wallet
                if (this.onPqSignaturePrompt) {
                    const approved = await this.onPqSignaturePrompt({
                        type: 'quantum_envelope',
                        target: PRECOMPILES[precompile],
                        caller,
                        keyScheme: 'ML-DSA-65',
                        summary: `Authorize Post-Quantum signature for ${precompile}.${functionName}`,
                        calldata: encodeRawPrecompileCall(precompile, functionName, params)
                    });
                    if (!approved) {
                        throw new Error("User rejected Post-Quantum signature authorization in Sovereign Wallet");
                    }
                }

                const contract = getPrecompileContract(precompile, this.signer);
                const tx = await (contract as any)[functionName](...params, { value: valueWei });
                return await tx.wait();
            }
            case 'legacy_pure': {
                // Classical Secp256k1 transaction
                await this.initSigner();
                if (!this.signer) throw new Error("Wallet not connected");
                const contract = getPrecompileContract(precompile, this.signer);
                const tx = await (contract as any)[functionName](...params, { value: valueWei });
                return await tx.wait();
            }
            case 'bytecode_raw': {
                // Raw bytecode push to precompile address
                await this.initSigner();
                if (!this.signer) throw new Error("Wallet not connected");
                const calldata = encodeRawPrecompileCall(precompile, functionName, params);
                const tx = await this.signer.sendTransaction({
                    to: PRECOMPILES[precompile],
                    data: calldata,
                    value: valueWei
                });
                return await tx.wait();
            }
        }
    }

    private _initSlots() {
        const self = this;
        return {
            async mount(slotId: number, pluginId: string, initialRoot: string | Uint8Array) {
                const rootBytes32 = typeof initialRoot === 'string' ? ethers.getBytes(initialRoot) : initialRoot;
                return await self.dispatchPrecompile('ROUTER', 'mountSlot', [slotId, pluginId, rootBytes32]);
            },
            async resolve(account: string, slotId: number): Promise<AccountSlotInfo> {
                if (self.provider) {
                    return await self.provider.resolveSlot(account, slotId);
                }
                const res = await self._postRpc("bunny_resolveSlot", [account, slotId]);
                return res as AccountSlotInfo;
            }
        };
    }

    private _initDid() {
        const self = this;
        return {
            async register(keyTier: string, pqPublicKey: string | Uint8Array, didDocument: string) {
                const pqBytes = typeof pqPublicKey === 'string' ? ethers.getBytes(pqPublicKey) : pqPublicKey;
                return await self.dispatchPrecompile('DID_REGISTRY', 'registerDid', [keyTier, pqBytes, didDocument]);
            },
            async resolve(account: string): Promise<W3cDidDocument | null> {
                if (self.provider) {
                    return await self.provider.resolveDid(account);
                }
                const res = await self._postRpc("bunny_resolveDidDocument", [account]);
                return res as W3cDidDocument | null;
            },
            async get(didOrAddress: string): Promise<any> {
                return await self._postRpc("sovereign_getDid", [didOrAddress]);
            },
            async getByAddress(address: string): Promise<any> {
                return await self._postRpc("sovereign_getDidByAddress", [address]);
            }
        };
    }

    private _initActivityPub() {
        const self = this;
        return {
            async publish(signedActivityPayload: string | Uint8Array, pinningFeeWei: bigint = 0n) {
                const payloadBytes = typeof signedActivityPayload === 'string'
                    ? ethers.toUtf8Bytes(signedActivityPayload)
                    : signedActivityPayload;
                // Broadcast via bunny_postActivityPub for network feed and outbox indexing
                try {
                    const parsed = typeof signedActivityPayload === "string"
                        ? JSON.parse(signedActivityPayload)
                        : JSON.parse(ethers.toUtf8String(payloadBytes));
                    await self._postRpc("bunny_postActivityPub", [parsed]);
                } catch (_) {}
                return await self.dispatchPrecompile('CMS_ACTPUB', 'publishActivity', [payloadBytes], pinningFeeWei);
            }
        };
    }

    private _initZanzibar() {
        const self = this;
        return {
            async check(namespace: number, objectId: string, relation: number, subject: string): Promise<boolean> {
                if (self.provider) {
                    return await self.provider.checkRebac(namespace, objectId, relation, subject);
                }
                const res = await self._postRpc("bunny_zanzibarCheck", [namespace, objectId, relation, subject]);
                return Boolean(res);
            },
            async inscribe(namespace: number, objectId: string, relation: number, subject: string) {
                const objIdBytes32 = ethers.getBytes(objectId.padEnd(66, '0').slice(0, 66));
                return await self.dispatchPrecompile('ZANZIBAR_REBAC', 'inscribeTuple', [namespace, objIdBytes32, relation, subject]);
            }
        };
    }

    private _initJurisdiction() {
        const self = this;
        return {
            async setQuadrantBits(quadrant: number, bits: bigint | number) {
                return await self.dispatchPrecompile('JURISDICTION', 'setQuadrantBits', [quadrant, BigInt(bits)]);
            },
            async check(account: string, quadrant: number): Promise<JurisdictionComplianceResult> {
                if (self.provider) {
                    return await self.provider.checkCompliance(account, quadrant);
                }
                const res = await self._postRpc("bunny_checkCompliance", [account, quadrant]);
                return res as JurisdictionComplianceResult;
            }
        };
    }

    private _initStorage() {
        const self = this;
        return {
            async uploadBlob(dataBytes: Uint8Array, namespaceId: number = 0): Promise<{ cid: string; size?: number; hash?: string }> {
                const hexData = ethers.hexlify(dataBytes);
                try {
                    return await self._postRpc("bunny_storeBlob", [namespaceId, hexData]);
                } catch (_) {}
                try {
                    const res = await fetch(`${self.storageUrl}/storage_storeBlob`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ data: hexData })
                    });
                    if (res.ok) return await res.json();
                } catch (_) {}
                return await self._postRpc("storage_storeBlob", [{ data: hexData }]);
            },
            async fetchBlob(cid: string): Promise<any> {
                try {
                    return await self._postRpc("bunny_resolveBlob", [cid]);
                } catch (_) {}
                const res = await fetch(`${self.storageUrl}/blob/${cid}`);
                if (!res.ok) throw new Error(`Failed to fetch blob: ${cid}`);
                return await res.blob();
            }
        };
    }

    private _initLattice() {
        const self = this;
        return {
            async getHeight(address: string): Promise<bigint> {
                if (self.provider) {
                    return await self.provider.getAccountHeight(address);
                }
                const res = await self._postRpc("bunny_getAccountHeight", [address]);
                return BigInt(res || 0);
            },
            async sweepReceive(recipient: string, amountWei: bigint) {
                return await self.dispatchPrecompile('RECEIVE', 'sweepTransfer', [recipient], amountWei);
            },
            async getPendingInbox(address: string): Promise<any[]> {
                return await self._postRpc("sovereign_getPendingInbox", [address]);
            },
            async receive(recipient: string, sendBlockHash: string, proofHex: string = "0x") {
                return await self._postRpc("sovereign_receive", [recipient, sendBlockHash, proofHex]);
            },
            async reclaimSend(sender: string, sendBlockHash: string, currentBlockNum: number = 0) {
                return await self._postRpc("sovereign_reclaimSend", [sender, sendBlockHash, currentBlockNum]);
            },
            async getReclaimTimeout(): Promise<{ reclaim_timeout_epochs: number; current_epoch: number; blocks_per_epoch: number }> {
                return await self._postRpc("sovereign_getReclaimTimeout");
            },
            async setReclaimTimeout(epochs: number) {
                return await self._postRpc("sovereign_setReclaimTimeout", [epochs]);
            }
        };
    }

    private _initSessions() {
        const self = this;
        return {
            async getPermissions(): Promise<any> {
                return await self._postRpc("wallet_getPermissions");
            },
            async createSession(): Promise<any> {
                return await self._postRpc("wallet_createSession");
            },
            async getSession(): Promise<any> {
                return await self._postRpc("wallet_getSession");
            },
            async revokeSession(): Promise<any> {
                return await self._postRpc("wallet_revokeSession");
            }
        };
    }

    private _initSecurity() {
        const self = this;
        return {
            async getPolicy(account: string): Promise<AccountSecurityPolicy> {
                if (self.provider) {
                    return await self.provider.getSecurityPolicy(account);
                }
                const res = await self._postRpc("sovereign_getAccountSecurity", [account]);
                return res as AccountSecurityPolicy;
            },
            async setAllowLegacy(allow: boolean) {
                if (self.mode === 'modern_cbor') {
                    await self.initSigner();
                    const addr = self.signer ? await self.signer.getAddress() : ethers.ZeroAddress;
                    return await self._postRpc("sovereign_setAllowLegacy", [addr, allow]);
                }
                return await self.dispatchPrecompile('DID_REGISTRY', 'setAllowLegacy', [allow]);
            },
            async verifySecurityCompliance(account: string): Promise<{ compliant: boolean; warning?: string }> {
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
            async upgradeToQuantumSecure(pqPublicKey: string | Uint8Array, didDocument: string) {
                // Register quantum DID and flip ALLOW_LEGACY to false
                await self.did.register("QuantumReady", pqPublicKey, didDocument);
                await this.setAllowLegacy(false);
                return { status: "upgraded_to_quantum_secure" };
            }
        };
    }

    private async _postRpc(method: string, params: any[] = []): Promise<any> {
        const payload = {
            jsonrpc: "2.0",
            method: method,
            params: params,
            id: Date.now()
        };
        const endpoints = [];
        if (method.startsWith("bunny_") || method.startsWith("sovereign_")) {
            if (this.rpcUrl.includes(":8545")) {
                endpoints.push(this.rpcUrl.replace(":8545", ":8546"));
            } else if (!this.rpcUrl.includes(":8546")) {
                endpoints.push("http://localhost:8546");
            }
            endpoints.push(this.rpcUrl);
        } else {
            endpoints.push(this.rpcUrl);
            if (this.rpcUrl.includes(":8545")) {
                endpoints.push(this.rpcUrl.replace(":8545", ":8546"));
            }
        }

        let lastError = null;
        for (const ep of endpoints) {
            try {
                const res = await fetch(ep, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const json = await res.json();
                if (json.error) {
                    if (json.error.code === -32601) continue;
                    throw new Error(json.error.message || `RPC Error: ${json.error.code}`);
                }
                return json.result;
            } catch (err) {
                lastError = err;
            }
        }
        throw lastError || new Error(`RPC failed for method ${method}`);
    }
}
