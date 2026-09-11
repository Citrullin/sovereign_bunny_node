// Sovereign Precompile Addresses and Standard EVM ABI Definitions
// Generated to align with contracts/src/ISovereignPrecompiles.sol (EIP-1352 namespace)

const PRECOMPILES = {
    ROUTER: "0x0000000000000000000000000000000000000001",
    RECEIVE: "0x0000000000000000000000000000000000000002",
    DID_REGISTRY: "0x0000000000000000000000000000000000000003",
    SAGA_INTENT: "0x0000000000000000000000000000000000000004",
    JURISDICTION: "0x0000000000000000000000000000000000000005",
    BRIDGE_SHADOW: "0x0000000000000000000000000000000000000006",
    ASYNC_INBOX: "0x0000000000000000000000000000000000000007",
    ZK_COMPLIANCE: "0x0000000000000000000000000000000000000008",
    STORAGE_DA: "0x0000000000000000000000000000000000000053",
    SIGNAL_REGISTRY: "0x0000000000000000000000000000000000000054",
    ZANZIBAR_REBAC: "0x0000000000000000000000000000000000000061",
    CMS_ACTPUB: "0x00000000000000000000000000000000000000F1",
    LATTICE_HEIGHT: "0x0000000000000000000000000000000000000100"
};

const SOVEREIGN_ABIS = {
    ROUTER: [
        "function mountSlot(uint8 slotId, string calldata pluginId, bytes32 initialRoot) external",
        "function resolveSlot(address account, uint8 slotId) external view returns (bool mounted, string memory pluginId, bytes32 root)",
        "event SlotMounted(uint8 indexed slotId, string pluginId, bytes32 initialRoot)"
    ],
    RECEIVE: [
        "function sweepTransfer(address recipient) external payable returns (uint64 newHeight)",
        "event ValueReceived(address indexed sender, address indexed recipient, uint256 amount, uint64 newHeight)"
    ],
    DID_REGISTRY: [
        "function registerDid(string calldata keyTier, bytes calldata pqPublicKey, string calldata didDocument) external",
        "function resolveDid(address account) external view returns (string memory didDocument)",
        "function setAllowLegacy(bool allow) external",
        "function getSecurityPolicy(address account) external view returns (bool allowLegacy, bool hasPqDid, bool isQuantumSecure)",
        "event DidRegistered(address indexed account, string didUri, string keyTier)",
        "event SecurityPolicyUpdated(address indexed account, bool allowLegacy)"
    ],
    SAGA_INTENT: [
        "function registerIntent(bytes32 intentId, address targetAccount, uint256 amount, uint64 expireEpoch) external payable",
        "event IntentRegistered(bytes32 indexed intentId, address indexed targetAccount, uint256 amount, uint64 expireEpoch)"
    ],
    JURISDICTION: [
        "function setQuadrantBits(uint8 quadrant, uint64 bits) external",
        "function checkCompliance(address account, uint8 quadrant) external view returns (bool compliant, uint64 activeBits)",
        "event JurisdictionUpdated(address indexed target, uint8 indexed quadrant, uint64 bits)"
    ],
    BRIDGE_SHADOW: [
        "function anchorShadowReceipt(bytes32 l1TxHash, address tokenContract, address recipient, uint256 amount, bytes calldata proof) external",
        "event ShadowReceiptAnchored(bytes32 indexed l1TxHash, address tokenContract, address indexed recipient, uint256 amount)"
    ],
    ASYNC_INBOX: [
        "function dispatchAsync(address target, bytes calldata messagePayload) external returns (bytes32 messageHash)",
        "event AsyncDispatched(address indexed sender, address indexed target, bytes32 messageHash)"
    ],
    ZK_COMPLIANCE: [
        "function submitComplianceTicket(bytes calldata ultraHonkProof, bytes32 publicInputsHash) external returns (bool verified)",
        "event ComplianceProofVerified(address indexed account, bytes32 nullifier)"
    ],
    STORAGE_DA: [
        "function verifyStoragePor(bytes calldata cidBytes, uint32 chunkIdx, bytes calldata baoProof) external view returns (bool valid)",
        "event BlobCommitted(bytes cidBytes, address indexed publisher, uint64 sizeBytes)"
    ],
    SIGNAL_REGISTRY: [
        "function inscribeSignal(address target, bytes32 topicId, bytes calldata mlDsaSignature) external",
        "event SignalInscribed(address indexed target, bytes32 indexed topicId, uint64 timestamp)"
    ],
    ZANZIBAR_REBAC: [
        "function check(uint16 namespace, bytes32 objectId, uint16 relation, address subject) external view returns (bool authorized)",
        "function check(string object, string relation, string subject) external view returns (bool authorized)",
        "function inscribeTuple(uint16 namespace, bytes32 objectId, uint16 relation, address subject) external",
        "event TupleInscribed(uint16 indexed namespace, bytes32 indexed objectId, uint16 relation, address indexed subject)"
    ],
    CMS_ACTPUB: [
        "function publishActivity(bytes calldata signedActivityPayload) external payable returns (bytes32 activityHash)",
        "event ActivityPublished(bytes32 indexed activityHash, address indexed actor, bytes mediaCid)"
    ],
    LATTICE_HEIGHT: [
        "function getAccountHeight(address target) external view returns (uint256)"
    ]
};

function getPrecompileContract(name, signerOrProvider) {
    const address = PRECOMPILES[name];
    const abi = SOVEREIGN_ABIS[name];
    if (!address || !abi) {
        throw new Error(`Unknown precompile: ${name}`);
    }
    return new ethers.Contract(address, abi, signerOrProvider);
}
