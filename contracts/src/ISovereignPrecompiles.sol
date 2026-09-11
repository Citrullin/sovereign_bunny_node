// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ISovereignPrecompiles
/// @notice Comprehensive EVM ABI bytecode interfaces for all Sovereign Account-Lattice low-entropy precompiles (EIP-1352 namespace).
/// @dev In dApp Mode, client wallets (MetaMask, Rabby) interact with these standard function selectors.

/// @notice Hook for Register Precompile Router and Dynamic Polymorphic Slots (0x00...0001)
interface IRegisterRouter {
    event SlotMounted(uint8 indexed slotId, string pluginId, bytes32 initialRoot);
    event SlotUpdated(uint8 indexed slotId, bytes32 newRoot);

    /// @notice Mounts or bootstraps a polymorphic slot on the caller's account lattice
    /// @param slotId Target slot index (0..63)
    /// @param pluginId Unique plugin identifier (e.g. "fediverse.activitypub", "vcs.git_dag")
    /// @param initialRoot 32-byte initial commitment or Poseidon sponge root
    function mountSlot(uint8 slotId, string calldata pluginId, bytes32 initialRoot) external;

    /// @notice Resolves the active root commitment for a specific slot on an account
    /// @param account The target account address
    /// @param slotId The slot index to query
    function resolveSlot(address account, uint8 slotId) external view returns (bool mounted, string memory pluginId, bytes32 root);
}

/// @notice Hook for receiving stateless block payments and balance sweeps (0x00...0002)
interface IReceiveHook {
    event ValueReceived(address indexed sender, address indexed recipient, uint256 amount, uint64 newHeight);

    /// @notice Sweeps or records value transfer to advance recipient block lattice tip
    function sweepTransfer(address recipient) external payable returns (uint64 newHeight);
}

/// @notice Hook for registering W3C DIDs and Multibase Post-Quantum public keys (0x00...0003)
interface IDidRegistry {
    event DidRegistered(address indexed account, string didUri, string keyTier);
    event SecurityPolicyUpdated(address indexed account, bool allowLegacy);

    /// @notice Registers an on-chain DID document and post-quantum verification methods
    /// @param keyTier Security tier identifier (e.g. "QuantumReady", "Classical")
    /// @param pqPublicKey Raw binary multibase-decoded post-quantum public key (ML-DSA-65 / Falcon)
    /// @param didDocument Complete JSON-LD formatted W3C DID document string
    function registerDid(string calldata keyTier, bytes calldata pqPublicKey, string calldata didDocument) external;

    /// @notice Resolves the registered DID document for an account
    /// @param account The account address to inspect
    function resolveDid(address account) external view returns (string memory didDocument);

    /// @notice Explicitly sets whether this account permits legacy non-quantum transactions (ALLOW_LEGACY)
    /// @param allow True to permit insecure classical Secp256k1 transactions; false to require post-quantum security
    function setAllowLegacy(bool allow) external;

    /// @notice Returns the security policy and tier for an account
    /// @param account The address to inspect
    /// @return allowLegacy Whether insecure legacy transactions are permitted
    /// @return hasPqDid Whether a post-quantum DID document has been registered
    /// @return isQuantumSecure Whether the account is protected against quantum attacks
    function getSecurityPolicy(address account) external view returns (bool allowLegacy, bool hasPqDid, bool isQuantumSecure);
}

/// @notice Hook for Saga Intent escrow locks and asynchronous settlements (0x00...0004)
interface ISagaIntentRouter {
    event IntentRegistered(bytes32 indexed intentId, address indexed targetAccount, uint256 amount, uint64 expireEpoch);
    event IntentSettled(bytes32 indexed intentId, address indexed resolver);

    /// @notice Submits an intent escrow commitment for cross-shard or cross-chain payment
    /// @param intentId Unique 32-byte identifier for the intent
    /// @param targetAccount Recipient account address
    /// @param amount Escrowed payment value in atomic units
    /// @param expireEpoch Epoch height after which unfulfilled escrow expires
    function registerIntent(bytes32 intentId, address targetAccount, uint256 amount, uint64 expireEpoch) external payable;
}

/// @notice Hook for Snowman-finalized jurisdiction rules and SMT compliance tickets (0x00...0005)
interface IJurisdiction {
    event JurisdictionUpdated(address indexed target, uint8 indexed quadrant, uint64 bits);

    /// @notice Sets geographic or regulatory quadrant bitmask for an account
    /// @param quadrant Quadrant index (0: Global, 1: EU, 2: US, 3: Asia-Pacific)
    /// @param bits Bitmask representing declared compliance flags
    function setQuadrantBits(uint8 quadrant, uint64 bits) external;

    /// @notice Evaluates if an account satisfies the active jurisdiction filter
    function checkCompliance(address account, uint8 quadrant) external view returns (bool compliant, uint64 activeBits);
}

/// @notice Hook for L1/L2 shadow anchor receipts and cross-chain bridging (0x00...0006)
interface IBridgeShadow {
    event ShadowReceiptAnchored(bytes32 indexed l1TxHash, address tokenContract, address indexed recipient, uint256 amount);

    /// @notice Submits an L1/L2 proof receipt to anchor assets into Sovereign account lattice
    function anchorShadowReceipt(bytes32 l1TxHash, address tokenContract, address recipient, uint256 amount, bytes calldata proof) external;
}

/// @notice Hook for Async Message and Actuator mailbox (0x00...0007)
interface IAsyncInbox {
    event AsyncDispatched(address indexed sender, address indexed target, bytes32 messageHash);

    /// @notice Enqueues an asynchronous inter-account intent into the target mailbox
    function dispatchAsync(address target, bytes calldata messagePayload) external returns (bytes32 messageHash);
}

/// @notice Hook for client-side zkCompliance proof submission (0x00...0008)
interface IZkCompliance {
    event ComplianceProofVerified(address indexed account, bytes32 nullifier);

    /// @notice Verifies a stateless Noir UltraHonk zero-knowledge compliance ticket in RAM
    function submitComplianceTicket(bytes calldata ultraHonkProof, bytes32 publicInputsHash) external returns (bool verified);
}

/// @notice Hook for P2P Storage DA & Bao Verified Streaming (0x00...0053)
interface IStorageDA {
    event BlobCommitted(bytes cidBytes, address indexed publisher, uint64 sizeBytes);

    /// @notice Verifies a Bao outboard tree chunk or ZK Proof-of-Retrievability (ZK-PoR)
    function verifyStoragePor(bytes calldata cidBytes, uint32 chunkIdx, bytes calldata baoProof) external view returns (bool valid);
}

/// @notice Hook for P2P Address Interest Signaling & Cuckoo Filter Inscriptions (0x00...0054)
interface ISignalRegistry {
    event SignalInscribed(address indexed target, bytes32 indexed topicId, uint64 timestamp);

    /// @notice Inscribes a blinded interest signal onto the network's RAM Cuckoo Filter
    function inscribeSignal(address target, bytes32 topicId, bytes calldata mlDsaSignature) external;
}

/// @notice Hook for Zanzibar Relation-Based Access Control (ReBAC) Precompile (0x00...0061)
interface IZanzibarReBAC {
    event TupleInscribed(uint16 indexed namespace, bytes32 indexed objectId, uint16 relation, address indexed subject);

    /// @notice Verifies authorization in RAM (<12µs) against the Zanzibar relation tuple table
    /// @param namespace ReBAC namespace identifier (e.g. 0x0001: Documents, 0x0002: Shards)
    /// @param objectId Unique 32-byte object identifier
    /// @param relation Relation index (e.g. 1: Owner, 2: Editor, 3: Viewer)
    /// @param subject Target subject account address
    function check(uint16 namespace, bytes32 objectId, uint16 relation, address subject) external view returns (bool authorized);

    /// @notice Inscribes a new authorization tuple to Slot 1 (R_1)
    function inscribeTuple(uint16 namespace, bytes32 objectId, uint16 relation, address subject) external;
}

/// @notice Hook for Content Management System & ActivityPub Anchors (0x00...00F1)
interface IActivityPubCMS {
    event ActivityPublished(bytes32 indexed activityHash, address indexed actor, bytes mediaCid);

    /// @notice Validates and anchors a W3C ActivityStreams 2.0 note with ML-DSA signature
    function publishActivity(bytes calldata signedActivityPayload) external payable returns (bytes32 activityHash);
}

/// @notice Precompile returning the target account block sequence height (0x00...0100)
interface ILatticeHeight {
    /// @notice Returns the local block sequence number (Account Height) of the target address
    function getAccountHeight(address target) external view returns (uint256);
}
