// TypeScript Type Definitions for Sovereign Account-Lattice SDK

export type SovereignExecutionMode = 
  | 'modern_cbor'      // [CAIP-25 + CBOR + HTTP/3 | Native PQ]: The Modern Highway. CAIP session negotiates custom methods and native Post-Quantum keys over binary QUIC. No EVM gas ceremony.
  | 'legacy_wrapped'   // [No CAIP (Standard EVM) | Quantum Wrapped PQ]: The Bridge. MetaMask has no CAIP custom curve support, so we wrap the ML-DSA-65 payload inside an EIP-8141 Secp256k1 envelope to let legacy wallets broadcast it.
  | 'legacy_pure'      // [No CAIP (Standard EVM) | Classical Secp256k1]: Vanilla Ethereum mode. Standard Web3 tooling, Foundry/Hardhat, and accounts without quantum keys.
  | 'precompile_packed'// Native precompile wire encoding: Directly structured binary layouts (DID registry, sweep, ReBAC, CMS).
  | 'bytecode_raw';    // [Fuck it, we ballin | Raw Bytecode]: Bare-metal on-chain execution. No ABIs, no Ethers classes. Smart contracts pushing raw bytes directly to precompiles (0x01..0x0100) via low-level CALL opcodes.

export interface PrecompileAddresses {
    ROUTER: string;
    RECEIVE: string;
    DID_REGISTRY: string;
    SAGA_INTENT: string;
    JURISDICTION: string;
    BRIDGE_SHADOW: string;
    ASYNC_INBOX: string;
    ZK_COMPLIANCE: string;
    STORAGE_DA: string;
    SIGNAL_REGISTRY: string;
    ZANZIBAR_REBAC: string;
    CMS_ACTPUB: string;
    LATTICE_HEIGHT: string;
}

export type PrecompileName = keyof PrecompileAddresses;

export interface Eip8141QuantumEnvelope {
    scheme: 'ml_dsa_65' | 'falcon_512' | 'noir_ultrahonk';
    publicKey: Uint8Array | string;
    signatureOrProof: Uint8Array | string;
    innerPayload: Uint8Array | string;
    secpSignerAddress: string;
}

export interface AccountSlotInfo {
    mounted: boolean;
    pluginId: string;
    root: string;
}

export interface W3cVerificationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase?: string;
    publicKeyJwk?: Record<string, unknown>;
}

export interface W3cDidDocument {
    '@context': string[];
    id: string;
    verificationMethod: W3cVerificationMethod[];
    authentication?: string[];
    assertionMethod?: string[];
}

export interface ZanzibarRelationTuple {
    namespace: number;
    objectId: string;
    relation: number;
    subject: string;
}

export interface JurisdictionComplianceResult {
    compliant: boolean;
    activeBits: bigint;
}

export interface StorageBlobCommitment {
    cid: string;
    sizeBytes: bigint;
    baoOutboardHash: string;
}

export type AccountSecurityTier = 
  | 'QuantumNative'         // Registered DID with native Post-Quantum keys
  | 'QuantumWrappedOnly'    // Uses Post-Quantum proofs wrapped in EIP-8141 envelope
  | 'LegacyAllowedInsecure' // ALLOW_LEGACY=true, classical Secp256k1 only (vulnerable to quantum attack)
  | 'UninitializedBlocked'; // ALLOW_LEGACY=false, no DID (blocked from sending transactions)

export interface AccountSecurityPolicy {
    address: string;
    allowLegacy: boolean;
    hasPqDid: boolean;
    isQuantumSecure: boolean;
    securityTier: AccountSecurityTier;
    warning?: string;
}

export interface SovereignClientOptions {
    apiMode?: 'legacy' | 'modern';
    cryptoWrap?: 'wrapped' | 'pure';
    executionMode?: SovereignExecutionMode;
    rpcUrl?: string;
    storageUrl?: string;
}
