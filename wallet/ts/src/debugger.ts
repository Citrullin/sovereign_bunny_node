// Sovereign Transaction & State-Change Debugger Engine
// Dissects calldata across 4 execution modes, unwraps PQ envelopes, decodes EVM reverts, and diagnoses errors.

import { ethers } from 'ethers';
import { PRECOMPILES, SOVEREIGN_ABIS } from './contracts.js';
import { PrecompileName, SovereignExecutionMode } from './types.js';
import { AccountStorageManager, CustomContractEntry } from './storage_manager.js';

export interface PrecompileMetadata {
    name: PrecompileName;
    address: string;
    description: string;
    functions: string[];
}

export const PRECOMPILE_CATALOG: Record<string, PrecompileMetadata> = {
    [PRECOMPILES.ROUTER.toLowerCase()]: {
        name: 'ROUTER',
        address: PRECOMPILES.ROUTER,
        description: 'Polymorphic Account Slot Router (EIP-1352 Low-Entropy)',
        functions: SOVEREIGN_ABIS.ROUTER
    },
    [PRECOMPILES.RECEIVE.toLowerCase()]: {
        name: 'RECEIVE',
        address: PRECOMPILES.RECEIVE,
        description: 'Block-Lattice Zero-Gas Value Receive & Claim Precompile',
        functions: SOVEREIGN_ABIS.RECEIVE
    },
    [PRECOMPILES.DID_REGISTRY.toLowerCase()]: {
        name: 'DID_REGISTRY',
        address: PRECOMPILES.DID_REGISTRY,
        description: 'Universal Multi-Curve Decentralized Identifier & Key Registry',
        functions: SOVEREIGN_ABIS.DID_REGISTRY
    },
    [PRECOMPILES.SAGA_INTENT.toLowerCase()]: {
        name: 'SAGA_INTENT',
        address: PRECOMPILES.SAGA_INTENT,
        description: 'Cross-Manifold Distributed Saga Escrow & Intent Coordinator',
        functions: SOVEREIGN_ABIS.SAGA_INTENT
    },
    [PRECOMPILES.JURISDICTION.toLowerCase()]: {
        name: 'JURISDICTION',
        address: PRECOMPILES.JURISDICTION,
        description: 'Snowman-Finalized 4-Quadrant Compliance Bitmask Precompile',
        functions: SOVEREIGN_ABIS.JURISDICTION
    },
    [PRECOMPILES.BRIDGE_SHADOW.toLowerCase()]: {
        name: 'BRIDGE_SHADOW',
        address: PRECOMPILES.BRIDGE_SHADOW,
        description: 'L1 Shadow Receipt & Zero-Knowledge Minting Bridge Anchor',
        functions: SOVEREIGN_ABIS.BRIDGE_SHADOW
    },
    [PRECOMPILES.ASYNC_INBOX.toLowerCase()]: {
        name: 'ASYNC_INBOX',
        address: PRECOMPILES.ASYNC_INBOX,
        description: 'Asynchronous Cross-Thread Actor Message Inbox',
        functions: SOVEREIGN_ABIS.ASYNC_INBOX
    },
    [PRECOMPILES.ZK_COMPLIANCE.toLowerCase()]: {
        name: 'ZK_COMPLIANCE',
        address: PRECOMPILES.ZK_COMPLIANCE,
        description: 'Barretenberg UltraHonk Zero-Knowledge Compliance Ticket Verifier',
        functions: SOVEREIGN_ABIS.ZK_COMPLIANCE
    },
    [PRECOMPILES.STORAGE_DA.toLowerCase()]: {
        name: 'STORAGE_DA',
        address: PRECOMPILES.STORAGE_DA,
        description: 'Iroh Decentralized Storage & Bao Outboard Por Verifier',
        functions: SOVEREIGN_ABIS.STORAGE_DA
    },
    [PRECOMPILES.SIGNAL_REGISTRY.toLowerCase()]: {
        name: 'SIGNAL_REGISTRY',
        address: PRECOMPILES.SIGNAL_REGISTRY,
        description: 'Post-Quantum On-Chain Signaling & Attestation Topic Store',
        functions: SOVEREIGN_ABIS.SIGNAL_REGISTRY
    },
    [PRECOMPILES.ZANZIBAR_REBAC.toLowerCase()]: {
        name: 'ZANZIBAR_REBAC',
        address: PRECOMPILES.ZANZIBAR_REBAC,
        description: 'Decentralized Google Zanzibar Relation-Based Access Control (ReBAC)',
        functions: SOVEREIGN_ABIS.ZANZIBAR_REBAC
    },
    [PRECOMPILES.CMS_ACTPUB.toLowerCase()]: {
        name: 'CMS_ACTPUB',
        address: PRECOMPILES.CMS_ACTPUB,
        description: 'W3C ActivityStreams 2.0 / ActivityPub Outbox & Federation Hub',
        functions: SOVEREIGN_ABIS.CMS_ACTPUB
    },
    [PRECOMPILES.LATTICE_HEIGHT.toLowerCase()]: {
        name: 'LATTICE_HEIGHT',
        address: PRECOMPILES.LATTICE_HEIGHT,
        description: 'Deterministic Account-Lattice Monotonic Height Querier',
        functions: SOVEREIGN_ABIS.LATTICE_HEIGHT
    }
};

export interface UnwrappedQuantumEnvelope {
    isWrapped: boolean;
    envelopeType: 'EIP-8141-ML-DSA-65' | 'Custom-PQ' | 'None';
    outerSignature?: {
        v: number;
        r: string;
        s: string;
    };
    pqSignatureHex?: string;
    innerTargetAddress?: string;
    innerCalldataHex?: string;
}

export interface DecodedCalldata {
    targetAddress: string;
    targetName: string;
    isPrecompile: boolean;
    selector: string;
    functionSignature?: string;
    params: Record<string, any>;
    rawCalldata: string;
    mode: SovereignExecutionMode;
    quantumEnvelope?: UnwrappedQuantumEnvelope;
}

export interface DisassembledInstruction {
    pc: number;
    opcode: number;
    mnemonic: string;
    pushData?: string;
    annotation?: string;
}

export const EVM_OPCODES: Record<number, string> = {
    0x00: 'STOP',
    0x01: 'ADD',
    0x02: 'MUL',
    0x03: 'SUB',
    0x04: 'DIV',
    0x05: 'SDIV',
    0x06: 'MOD',
    0x07: 'SMOD',
    0x08: 'ADDMOD',
    0x09: 'MULMOD',
    0x0a: 'EXP',
    0x0b: 'SIGNEXTEND',
    0x10: 'LT',
    0x11: 'GT',
    0x12: 'SLT',
    0x13: 'SGT',
    0x14: 'EQ',
    0x15: 'ISZERO',
    0x16: 'AND',
    0x17: 'OR',
    0x18: 'XOR',
    0x19: 'NOT',
    0x1a: 'BYTE',
    0x1b: 'SHL',
    0x1c: 'SHR',
    0x1d: 'SAR',
    0x20: 'KECCAK256',
    0x30: 'ADDRESS',
    0x31: 'BALANCE',
    0x32: 'ORIGIN',
    0x33: 'CALLER',
    0x34: 'CALLVALUE',
    0x35: 'CALLDATALOAD',
    0x36: 'CALLDATASIZE',
    0x37: 'CALLDATACOPY',
    0x38: 'CODESIZE',
    0x39: 'CODECOPY',
    0x3a: 'GASPRICE',
    0x3b: 'EXTCODESIZE',
    0x3c: 'EXTCODECOPY',
    0x3d: 'RETURNDATASIZE',
    0x3e: 'RETURNDATACOPY',
    0x3f: 'EXTCODEHASH',
    0x40: 'BLOCKHASH',
    0x41: 'COINBASE',
    0x42: 'TIMESTAMP',
    0x43: 'NUMBER',
    0x44: 'PREVRANDAO',
    0x45: 'GASLIMIT',
    0x46: 'CHAINID',
    0x47: 'SELFBALANCE',
    0x48: 'BASEFEE',
    0x49: 'BLOBHASH',
    0x4a: 'BLOBBASEFEE',
    0x50: 'POP',
    0x51: 'MLOAD',
    0x52: 'MSTORE',
    0x53: 'MSTORE8',
    0x54: 'SLOAD',
    0x55: 'SSTORE',
    0x56: 'JUMP',
    0x57: 'JUMPI',
    0x58: 'PC',
    0x59: 'MSIZE',
    0x5a: 'GAS',
    0x5b: 'JUMPDEST',
    0x5c: 'TLOAD',
    0x5d: 'TSTORE',
    0x5e: 'MCOPY',
    0x5f: 'PUSH0',
    0x80: 'DUP1', 0x81: 'DUP2', 0x82: 'DUP3', 0x83: 'DUP4', 0x84: 'DUP5', 0x85: 'DUP6', 0x86: 'DUP7', 0x87: 'DUP8',
    0x88: 'DUP9', 0x89: 'DUP10', 0x8a: 'DUP11', 0x8b: 'DUP12', 0x8c: 'DUP13', 0x8d: 'DUP14', 0x8e: 'DUP15', 0x8f: 'DUP16',
    0x90: 'SWAP1', 0x91: 'SWAP2', 0x92: 'SWAP3', 0x93: 'SWAP4', 0x94: 'SWAP5', 0x95: 'SWAP6', 0x96: 'SWAP7', 0x97: 'SWAP8',
    0x98: 'SWAP9', 0x99: 'SWAP10', 0x9a: 'SWAP11', 0x9b: 'SWAP12', 0x9c: 'SWAP13', 0x9d: 'SWAP14', 0x9e: 'SWAP15', 0x9f: 'SWAP16',
    0xa0: 'LOG0', 0xa1: 'LOG1', 0xa2: 'LOG2', 0xa3: 'LOG3', 0xa4: 'LOG4',
    0xf0: 'CREATE',
    0xf1: 'CALL',
    0xf2: 'CALLCODE',
    0xf3: 'RETURN',
    0xf4: 'DELEGATECALL',
    0xf5: 'CREATE2',
    0xfa: 'STATICCALL',
    0xfd: 'REVERT',
    0xfe: 'INVALID',
    0xff: 'SELFDESTRUCT'
};
// Populate PUSH1..PUSH32
for (let i = 1; i <= 32; i++) {
    EVM_OPCODES[0x5f + i] = `PUSH${i}`;
}

export interface DecodedRevert {
    isRevert: boolean;
    reasonType: 'Error(string)' | 'Panic(uint256)' | 'Custom' | 'None';
    message: string;
    code?: number;
}

export interface DiagnosticReport {
    severity: 'error' | 'warning' | 'info' | 'success';
    category: string;
    title: string;
    rootCause: string;
    technicalDetails: string;
    suggestedRemediation: string;
    remediationAction?: {
        type: 'upgrade_pq' | 'set_allow_legacy' | 'supply_abi' | 'verify_verkle';
        label: string;
        payload?: any;
    };
}

export interface DebugAnalysisResult {
    rawInput: string;
    inputType: 'json_rpc' | 'revert_hex' | 'calldata' | 'tx_hex' | 'tx_hash' | 'bytecode' | 'error_text';
    txHash?: string;
    senderAddress?: string;
    targetAddress?: string;
    value?: string;
    decodedCalldata?: DecodedCalldata;
    decodedRevert?: DecodedRevert;
    diagnostic: DiagnosticReport;
    disassembledOpcodes?: DisassembledInstruction[];
    formattedOpcodes?: string;
}

export class SovereignDebugger {
    private customAbis: Map<string, ethers.Interface> = new Map();
    private storageManager?: AccountStorageManager;

    constructor(storageManager?: AccountStorageManager) {
        this.storageManager = storageManager;
    }

    public registerCustomAbi(addressOrName: string, abi: any[]): void {
        try {
            const iface = new ethers.Interface(abi);
            this.customAbis.set(addressOrName.toLowerCase(), iface);
        } catch (e: any) {
            throw new Error(`Failed to parse custom ABI: ${e.message}`);
        }
    }

    public loadAccountCustomContracts(accountAddress: string): void {
        if (!this.storageManager) return;
        const contracts = this.storageManager.getCustomContracts(accountAddress);
        for (const c of contracts) {
            this.registerCustomAbi(c.targetAddress, c.abi);
            this.registerCustomAbi(c.name, c.abi);
        }
    }

    // Unwrap EIP-8141 Quantum-Wrapped Envelopes
    public unwrapQuantumEnvelope(calldataHex: string): UnwrappedQuantumEnvelope {
        const cleanHex = calldataHex.trim().toLowerCase().startsWith('0x')
            ? calldataHex.trim().substring(2)
            : calldataHex.trim();

        // Check for EIP-8141 envelope header: 0x8141 or wrapper prefix
        if (cleanHex.startsWith('8141') || cleanHex.startsWith('f18141') || cleanHex.length > 500) {
            // EIP-8141 layout: [4 bytes header][20 bytes innerTarget][32 bytes r][32 bytes s][1 byte v][3309 bytes ML-DSA-65 sig][innerCalldata]
            try {
                if (cleanHex.length >= 136) { // Minimum outer envelope size
                    const innerTarget = '0x' + cleanHex.slice(8, 48);
                    const r = '0x' + cleanHex.slice(48, 112);
                    const s = '0x' + cleanHex.slice(112, 176);
                    const v = parseInt(cleanHex.slice(176, 178) || '1b', 16);
                    const pqSig = '0x' + cleanHex.slice(178, Math.min(cleanHex.length, 178 + 3309 * 2));
                    const innerCalldata = cleanHex.length > (178 + 3309 * 2)
                        ? '0x' + cleanHex.slice(178 + 3309 * 2)
                        : '0x';

                    return {
                        isWrapped: true,
                        envelopeType: 'EIP-8141-ML-DSA-65',
                        outerSignature: { v, r, s },
                        pqSignatureHex: pqSig,
                        innerTargetAddress: innerTarget,
                        innerCalldataHex: innerCalldata
                    };
                }
            } catch (_) {}
        }

        return {
            isWrapped: false,
            envelopeType: 'None'
        };
    }

    // Calldata Dissector
    public decodeCalldata(targetAddress: string, calldataHex: string): DecodedCalldata {
        const normTarget = targetAddress.toLowerCase();
        const precompileMeta = PRECOMPILE_CATALOG[normTarget];
        const isPrecompile = !!precompileMeta;
        const targetName = precompileMeta ? precompileMeta.name : (normTarget.slice(0, 10) + '...');
        
        let raw = calldataHex.trim();
        if (!raw.startsWith('0x')) raw = '0x' + raw;

        // Check if quantum wrapped first
        const unwrapped = this.unwrapQuantumEnvelope(raw);
        const effectiveTarget = (unwrapped.isWrapped && unwrapped.innerTargetAddress)
            ? unwrapped.innerTargetAddress
            : targetAddress;
        const effectiveCalldata = (unwrapped.isWrapped && unwrapped.innerCalldataHex && unwrapped.innerCalldataHex !== '0x')
            ? unwrapped.innerCalldataHex
            : raw;

        const selector = effectiveCalldata.slice(0, 10).toLowerCase();
        let functionSignature: string | undefined;
        let params: Record<string, any> = {};
        let mode: SovereignExecutionMode = unwrapped.isWrapped ? 'legacy_wrapped' : 'legacy_pure';

        // 1. Try Precompile ABIs
        if (precompileMeta) {
            const iface = new ethers.Interface(precompileMeta.functions);
            try {
                const parsed = iface.parseTransaction({ data: effectiveCalldata });
                if (parsed) {
                    functionSignature = parsed.signature;
                    for (let i = 0; i < parsed.fragment.inputs.length; i++) {
                        const input = parsed.fragment.inputs[i];
                        const val = parsed.args[i];
                        params[input.name || `param_${i}`] = typeof val === 'bigint' ? val.toString() : val;
                    }
                }
            } catch (_) {}
        }

        // 2. Try User-Uploaded Custom ABIs
        if (!functionSignature && this.customAbis.has(normTarget)) {
            const iface = this.customAbis.get(normTarget)!;
            try {
                const parsed = iface.parseTransaction({ data: effectiveCalldata });
                if (parsed) {
                    functionSignature = parsed.signature;
                    for (let i = 0; i < parsed.fragment.inputs.length; i++) {
                        const input = parsed.fragment.inputs[i];
                        const val = parsed.args[i];
                        params[input.name || `param_${i}`] = typeof val === 'bigint' ? val.toString() : val;
                    }
                }
            } catch (_) {}
        }

        // 3. Specialized Precompile Bytecode Wire Decoders (Direct Packed Wire Format & CBOR/JSON)
        if (!functionSignature && (isPrecompile || effectiveTarget.startsWith('0x00000000000000000000000000000000000000') || effectiveTarget.startsWith('0x00000000000000000000000000000000000001'))) {
            const rawBytes = ethers.getBytes(effectiveCalldata.startsWith('0x') ? effectiveCalldata : '0x' + effectiveCalldata);
            const targetLower = effectiveTarget.toLowerCase();

            // 0x03 Universal DID Registry (Packed Wire: 1B tier_len || tier || 4B pq_len || pq_pub || did_doc)
            if (targetLower.endsWith('0003') || targetName === 'DID_REGISTRY') {
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
                                let parsedDoc: any = docStr;
                                try { parsedDoc = JSON.parse(docStr); } catch (_) {}
                                functionSignature = 'registerDid(string,bytes,string)';
                                mode = 'precompile_packed';
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
                        if (docStr.includes('{') && docStr.includes('}')) {
                            const start = docStr.indexOf('{');
                            const end = docStr.lastIndexOf('}');
                            const parsedDoc = JSON.parse(docStr.slice(start, end + 1));
                            functionSignature = 'registerDid(string)';
                            mode = 'precompile_packed';
                            params = { didDocument: parsedDoc };
                            parsedSuccess = true;
                        }
                    }
                } catch (_) {}
            }

            // 0x02 Block-Lattice Receive / Reclaim Hook
            if (!functionSignature && (targetLower.endsWith('0002') || targetName === 'RECEIVE')) {
                try {
                    const text = new TextDecoder().decode(rawBytes);
                    if (text.startsWith('reclaim:')) {
                        functionSignature = 'reclaim(bytes32)';
                        mode = 'precompile_packed';
                        params = { targetSendBlockHash: text.slice(8).trim() };
                    } else if (rawBytes.length === 32) {
                        functionSignature = 'sweepReceive(bytes32)';
                        mode = 'precompile_packed';
                        params = { sendBlockHash: ethers.hexlify(rawBytes) };
                    } else if (rawBytes.length >= 64) {
                        functionSignature = 'sweepReceive(bytes32,uint256)';
                        mode = 'precompile_packed';
                        params = {
                            sendBlockHash: ethers.hexlify(rawBytes.slice(0, 32)),
                            amount: ethers.toBigInt(rawBytes.slice(32, 64)).toString()
                        };
                    }
                } catch (_) {}
            }

            // 0x61 Zanzibar ReBAC Precompile
            if (!functionSignature && (targetLower.endsWith('0061') || targetName === 'ZANZIBAR_REBAC')) {
                try {
                    if (rawBytes.length >= 54) {
                        const view = new DataView(rawBytes.buffer, rawBytes.byteOffset, rawBytes.length);
                        const namespace = view.getUint16(0, false);
                        const objectId = ethers.hexlify(rawBytes.slice(2, 34));
                        const relation = view.getUint16(34, false);
                        const subject = ethers.getAddress(ethers.hexlify(rawBytes.slice(36, 56)));
                        functionSignature = 'check(uint16,bytes32,uint16,address)';
                        mode = 'precompile_packed';
                        params = { namespace, objectId, relation, subject };
                    }
                } catch (_) {}
            }

            // 0xF1 W3C ActivityPub / CMS Precompile
            if (!functionSignature && (targetLower.endsWith('00f1') || targetName === 'CMS_ACTPUB')) {
                try {
                    const docStr = new TextDecoder().decode(rawBytes);
                    if (docStr.includes('{') && docStr.includes('}')) {
                        const start = docStr.indexOf('{');
                        const end = docStr.lastIndexOf('}');
                        const parsed = JSON.parse(docStr.slice(start, end + 1));
                        functionSignature = 'publishActivity(ActivityStreamsJson)';
                        mode = 'precompile_packed';
                        params = parsed;
                    }
                } catch (_) {}
            }

            // 0x53 Storage DA & Bao Precompile
            if (!functionSignature && (targetLower.endsWith('0053') || targetName === 'STORAGE_DA')) {
                try {
                    if (rawBytes.length >= 36) {
                        const chunkIdx = new DataView(rawBytes.buffer, rawBytes.byteOffset, 4).getUint32(0, false);
                        const cid = ethers.hexlify(rawBytes.slice(4, 36));
                        functionSignature = 'verifyStoragePor(uint32,bytes32,bytes)';
                        mode = 'precompile_packed';
                        params = { chunkIdx, cid, proofLength: `${rawBytes.length - 36} bytes` };
                    }
                } catch (_) {}
            }

            // 0x54 Signal Registry Precompile
            if (!functionSignature && (targetLower.endsWith('0054') || targetName === 'SIGNAL_REGISTRY')) {
                try {
                    if (rawBytes.length >= 60) {
                        const topicId = ethers.hexlify(rawBytes.slice(0, 32));
                        const targetAddr = ethers.getAddress(ethers.hexlify(rawBytes.slice(32, 52)));
                        functionSignature = 'inscribeSignal(bytes32,address,bytes)';
                        mode = 'precompile_packed';
                        params = { topicId, target: targetAddr, signatureLength: `${rawBytes.length - 52} bytes` };
                    }
                } catch (_) {}
            }

            // 0x0100 Lattice Height
            if (!functionSignature && (targetLower.endsWith('0100') || targetName === 'LATTICE_HEIGHT')) {
                try {
                    if (rawBytes.length >= 20) {
                        const account = ethers.getAddress(ethers.hexlify(rawBytes.slice(0, 20)));
                        functionSignature = 'getAccountHeight(address)';
                        mode = 'precompile_packed';
                        params = { account };
                    }
                } catch (_) {}
            }
        }

        // 4. Fallback to Bytecode Raw inspection if no selector or precompile wire format matched
        if (!functionSignature && effectiveCalldata.length > 10) {
            mode = 'bytecode_raw';
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
            quantumEnvelope: unwrapped.isWrapped ? unwrapped : undefined
        };
    }

    // EVM Revert Decoder
    public decodeRevert(revertHex: string): DecodedRevert {
        const clean = revertHex.trim().toLowerCase().startsWith('0x')
            ? revertHex.trim().substring(2)
            : revertHex.trim();

        if (clean.length < 8) {
            return { isRevert: false, reasonType: 'None', message: 'No revert bytes provided' };
        }

        const selector = clean.slice(0, 8);

        // Error(string) -> 0x08c379a0
        if (selector === '08c379a0') {
            try {
                const defaultAbi = new ethers.AbiCoder();
                const decoded = defaultAbi.decode(['string'], '0x' + clean.slice(8));
                return {
                    isRevert: true,
                    reasonType: 'Error(string)',
                    message: decoded[0]
                };
            } catch (_) {}
        }

        // Panic(uint256) -> 0x4e487b71
        if (selector === '4e487b71') {
            try {
                const defaultAbi = new ethers.AbiCoder();
                const decoded = defaultAbi.decode(['uint256'], '0x' + clean.slice(8));
                const code = Number(decoded[0]);
                const PANIC_MAP: Record<number, string> = {
                    0x01: 'Assertion failed (assert false)',
                    0x11: 'Arithmetic underflow or overflow',
                    0x12: 'Division or modulo by zero',
                    0x21: 'Enum conversion out of bounds',
                    0x22: 'Incorrect storage byte array encoding',
                    0x31: 'Empty array pop()',
                    0x32: 'Array index out of bounds',
                    0x41: 'Out of memory allocation',
                    0x51: 'Internal function call to uninitialized pointer'
                };
                return {
                    isRevert: true,
                    reasonType: 'Panic(uint256)',
                    message: PANIC_MAP[code] || `Solidity Panic Code ${code}`,
                    code
                };
            } catch (_) {}
        }

        return {
            isRevert: true,
            reasonType: 'Custom',
            message: `Custom Revert Selector: 0x${selector}`
        };
    }

    // Diagnostic Reasoner
    public diagnose(errorInput: any, context?: { to?: string; from?: string; data?: string }): DiagnosticReport {
        const errStr = typeof errorInput === 'string' 
            ? errorInput 
            : JSON.stringify(errorInput);

        // Pattern 1: Post-Quantum Security Invariant Violated
        if (errStr.includes("Post-Quantum security required") || errStr.includes("-32001") || errStr.includes("ALLOW_LEGACY is false")) {
            return {
                severity: 'error',
                category: 'Quantum Security Invariant',
                title: 'Classical Transaction Blocked by Post-Quantum Invariant',
                rootCause: 'The sending address does not have a registered Post-Quantum DID on Precompile 0x03, and ALLOW_LEGACY is false. Sovereign networks require quantum-resistant signature schemes by default to protect funds against quantum cryptanalysis.',
                technicalDetails: `Target: ${context?.to || 'Unknown'} | Sender: ${context?.from || 'Unknown'} | Invariant: ALLOW_LEGACY=false without DID registration`,
                suggestedRemediation: 'Register a Post-Quantum DID (ML-DSA-65) for this account or enable ALLOW_LEGACY=true in your account settings.',
                remediationAction: {
                    type: 'upgrade_pq',
                    label: '🛡️ Upgrade to Quantum Secure'
                }
            };
        }

        // Pattern 2: Active DID Not Registered
        if (errStr.includes("Active DID not registered") || errStr.includes("sovereign_registerDid first")) {
            return {
                severity: 'error',
                category: 'Identity & Authorization',
                title: 'DID Identity Document Missing',
                rootCause: 'The requested system action requires an active Sovereign DID registered in the consensus registry, but none was found for this caller.',
                technicalDetails: `Caller: ${context?.from || 'Unknown'} | Precompile 0x03 Lookup Failed`,
                suggestedRemediation: 'Call sovereign_registerDid or registerDid on precompile 0x03 with your public key and DID document.',
                remediationAction: {
                    type: 'upgrade_pq',
                    label: '🌐 Register DID on Chain'
                }
            };
        }

        // Pattern 3: Stateless Verkle Witness Verification Failure
        if (errStr.includes("Invalid Verkle proof") || errStr.includes("Receive verification failed")) {
            return {
                severity: 'error',
                category: 'Consensus & Lattice',
                title: 'Stateless Verkle Witness Verification Failed',
                rootCause: 'Precompile 0x02 (Receive) rejected the claim transaction because the provided Verkle witness proof did not match the latest finalized state root.',
                technicalDetails: 'sovereign_consensus::lattice::verify_receive_stateless returned false',
                suggestedRemediation: 'Generate a fresh Verkle witness proof against the current block header before dispatching the receive claim.',
                remediationAction: {
                    type: 'verify_verkle',
                    label: '🔄 Regenerate Verkle Witness'
                }
            };
        }

        // Pattern 4: Reclaim Timeout Not Met
        if (errStr.includes("has not reached timeout block age") || errStr.includes("Reclaim failed")) {
            return {
                severity: 'warning',
                category: 'Lattice Timelock',
                title: 'Send Transaction Timeout Block Height Not Reached',
                rootCause: 'An unspent send transaction can only be reclaimed by the sender after the configured block timeout period has elapsed.',
                technicalDetails: 'current_block_number < send_block_number + timeout_blocks',
                suggestedRemediation: 'Wait until the target block height is mined before submitting sovereign_reclaimSend.'
            };
        }

        // Pattern 5: Zanzibar ReBAC Unauthorized
        if (errStr.includes("Zanzibar") || errStr.includes("unauthorized") || errStr.includes("0x61")) {
            return {
                severity: 'error',
                category: 'ReBAC Permissions',
                title: 'Zanzibar Relation-Based Access Control Denied',
                rootCause: 'Precompile 0x61 evaluated the requested (namespace, objectId, relation, subject) tuple and returned false. The subject lacks the required relation.',
                technicalDetails: 'Precompile 0x61: check(namespace, objectId, relation, subject) => false',
                suggestedRemediation: 'Inscribe the missing relation tuple into Slot 1 (0x61 inscribeTuple) using an authorized administrative key.'
            };
        }

        // Pattern 6: Insufficient Funds
        if (errStr.includes("insufficient funds")) {
            return {
                severity: 'error',
                category: 'Account Balance',
                title: 'Insufficient Funds for Gas or Transfer',
                rootCause: 'The account balance is too low to cover the transaction value plus maximum gas cost (gas * gas_price).',
                technicalDetails: errStr,
                suggestedRemediation: 'Top up the account or claim pending incoming zero-gas transfers from your inbox.'
            };
        }

        // Default Generic Fallback
        return {
            severity: 'info',
            category: 'Execution Diagnostic',
            title: 'Diagnostic Inspection Complete',
            rootCause: 'Transaction or state-change evaluated. No known invariant violations detected.',
            technicalDetails: errStr,
            suggestedRemediation: 'Inspect the decoded calldata and target precompile parameters below for syntax or parameter errors.'
        };
    }

    public disassembleBytecode(bytecodeHex: string): DisassembledInstruction[] {
        const clean = bytecodeHex.trim().replace(/^0x/i, '');
        if (!clean || clean.length % 2 !== 0) return [];
        const bytes: number[] = [];
        for (let i = 0; i < clean.length; i += 2) {
            bytes.push(parseInt(clean.slice(i, i + 2), 16));
        }

        const instructions: DisassembledInstruction[] = [];
        let pc = 0;
        while (pc < bytes.length) {
            const currentPc = pc;
            const op = bytes[pc];
            pc++;

            const mnemonic = EVM_OPCODES[op] || `UNKNOWN_0x${op.toString(16).padStart(2, '0').toUpperCase()}`;
            let pushData: string | undefined;
            let annotation: string | undefined;

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

    public formatDisassembly(instructions: DisassembledInstruction[]): string {
        return instructions.map(inst => {
            const pcStr = `[${inst.pc.toString(16).padStart(4, '0')}]`;
            const opStr = inst.mnemonic.padEnd(12, ' ');
            const pushStr = inst.pushData ? inst.pushData : '';
            const annStr = inst.annotation ? ` // ${inst.annotation}` : '';
            return `${pcStr} ${opStr} ${pushStr}${annStr}`.trimEnd();
        }).join('\n');
    }

    // Main Unified Analysis Entry Point
    public async analyze(rawDump: string): Promise<DebugAnalysisResult> {
        const trimmed = rawDump.trim();
        let inputType: DebugAnalysisResult['inputType'] = 'calldata';
        let targetAddress = '0x0000000000000000000000000000000000000001';
        let senderAddress: string | undefined;
        let calldata = '0x';
        let txHash: string | undefined;
        let errorToDiagnose = trimmed;

        // Check if input is a 32-byte state change / transaction hash (64 hex characters)
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

        // 1. Try parsing JSON-RPC dump
        if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
            inputType = 'json_rpc';
            try {
                const parsed = JSON.parse(trimmed);
                if (parsed.method === 'eth_sendRawTransaction') {
                    calldata = parsed.params?.[0] || '0x';
                } else if (parsed.method === 'eth_call') {
                    const txObj = parsed.params?.[0] || {};
                    targetAddress = txObj.to || targetAddress;
                    senderAddress = txObj.from;
                    calldata = txObj.data || '0x';
                } else if (parsed.error) {
                    errorToDiagnose = parsed.error.message || JSON.stringify(parsed.error);
                } else if (parsed.params && parsed.params[0]) {
                    calldata = typeof parsed.params[0] === 'string' ? parsed.params[0] : JSON.stringify(parsed.params[0]);
                }
            } catch (_) {}
        } else if (trimmed.startsWith('0x08c379a0') || trimmed.startsWith('0x4e487b71')) {
            inputType = 'revert_hex';
        } else if (trimmed.startsWith('0x') && trimmed.length > 2) {
            inputType = 'calldata';
            calldata = trimmed;
        } else if (/^[0-9a-fA-F]{4,}$/.test(trimmed)) {
            inputType = 'bytecode';
            calldata = '0x' + trimmed;
        } else {
            inputType = 'error_text';
        }

        // Decode Revert if applicable
        const decodedRevert = (inputType === 'revert_hex' || trimmed.includes('08c379a0') || trimmed.includes('4e487b71'))
            ? this.decodeRevert(trimmed)
            : undefined;

        // Decode Calldata if present
        const decodedCalldata = calldata !== '0x'
            ? this.decodeCalldata(targetAddress, calldata)
            : undefined;

        // Disassemble EVM Bytecode if hex is present
        let disassembledOpcodes: DisassembledInstruction[] | undefined;
        let formattedOpcodes: string | undefined;
        if (calldata !== '0x' && calldata.length >= 4) {
            // If it's a quantum envelope, disassemble the inner calldata, otherwise disassemble raw calldata
            const unwrapped = this.unwrapQuantumEnvelope(calldata);
            const targetHex = (unwrapped.isWrapped && unwrapped.innerCalldataHex) ? unwrapped.innerCalldataHex : calldata;
            disassembledOpcodes = this.disassembleBytecode(targetHex);
            if (disassembledOpcodes.length > 0) {
                formattedOpcodes = this.formatDisassembly(disassembledOpcodes);
            }
        }

        // Run Diagnostic
        const diagnostic = this.diagnose(errorToDiagnose, {
            to: targetAddress,
            from: senderAddress,
            data: calldata
        });

        // If we found an account address and storage manager, load its custom contracts
        if (senderAddress) {
            this.loadAccountCustomContracts(senderAddress);
        }

        return {
            rawInput: rawDump,
            inputType,
            txHash,
            senderAddress,
            targetAddress: decodedCalldata?.targetAddress || targetAddress,
            decodedCalldata,
            decodedRevert,
            diagnostic,
            disassembledOpcodes,
            formattedOpcodes
        };
    }

    /**
     * Extracts pure, unwrapped EVM calldata suitable for standard EVM debuggers,
     * Remix "Low level interaction" / "At Address", or Foundry.
     */
    public exportRemixCalldata(rawCalldataHex: string): string {
        const unwrapped = this.unwrapQuantumEnvelope(rawCalldataHex);
        if (unwrapped.isWrapped && unwrapped.innerCalldataHex && unwrapped.innerCalldataHex !== '0x') {
            return unwrapped.innerCalldataHex;
        }
        let clean = (rawCalldataHex || '').trim();
        if (!clean.startsWith('0x')) clean = '0x' + clean;
        return clean;
    }

    /**
     * Formats a Foundry cast command (e.g. cast call / cast send) for CLI debugging and replaying.
     */
    public exportFoundryCastCommand(targetAddress: string, rawCalldataHex: string, rpcUrl: string = 'http://localhost:8545'): string {
        const cleanCalldata = this.exportRemixCalldata(rawCalldataHex);
        return `cast call ${targetAddress} ${cleanCalldata} --rpc-url ${rpcUrl}`;
    }

    /**
     * Generates a Remix IDE deep-link URL preloaded with the target address and clean calldata.
     */
    public generateRemixDeepLink(targetAddress: string, rawCalldataHex?: string): string {
        const cleanCalldata = rawCalldataHex ? this.exportRemixCalldata(rawCalldataHex) : '';
        const params = new URLSearchParams({
            address: targetAddress,
            calldata: cleanCalldata,
        });
        return `https://remix.ethereum.org/#${params.toString()}`;
    }
}

