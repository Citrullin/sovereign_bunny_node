// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ISovereignPrecompiles.sol";

/// @title SovereignSDK
/// @notice Comprehensive developer library wrapping native Sovereign Account-Lattice precompiles (EIP-1352 namespace).
/// @dev Exposes typed fixed slots (0x01..0x100) and precompiles for DIDs, Zanzibar ReBAC, Git VCS CIDs, Storage DA, and Lattice Height.
library SovereignSDK {
    // ── Low-Entropy Precompile Addresses ──────────────────────────────
    address internal constant ROUTER          = 0x0000000000000000000000000000000000000001;
    address internal constant RECEIVE         = 0x0000000000000000000000000000000000000002;
    address internal constant DID_REGISTRY    = 0x0000000000000000000000000000000000000003;
    address internal constant SAGA_INTENT     = 0x0000000000000000000000000000000000000004;
    address internal constant JURISDICTION    = 0x0000000000000000000000000000000000000005;
    address internal constant BRIDGE_SHADOW   = 0x0000000000000000000000000000000000000006;
    address internal constant ASYNC_INBOX     = 0x0000000000000000000000000000000000000007;
    address internal constant ZK_COMPLIANCE   = 0x0000000000000000000000000000000000000008;
    address internal constant STORAGE_DA      = 0x0000000000000000000000000000000000000053;
    address internal constant SIGNAL_REGISTRY = 0x0000000000000000000000000000000000000054;
    address internal constant ZANZIBAR_REBAC  = 0x0000000000000000000000000000000000000061;
    address internal constant CMS_ACTPUB      = 0x00000000000000000000000000000000000000f1;
    address internal constant LATTICE_HEIGHT  = 0x0000000000000000000000000000000000000100;

    // ── Canonical Fixed Slot Indexes ─────────────────────────────────
    uint8 internal constant SLOT_ZANZIBAR      = 0x01;
    uint8 internal constant SLOT_PAYMASTER     = 0x02;
    uint8 internal constant SLOT_DID           = 0x03;
    uint8 internal constant SLOT_GIT_DAG       = 0x04;
    uint8 internal constant SLOT_ACTIVITYPUB   = 0x05;
    uint8 internal constant SLOT_WEB_OF_THINGS = 0x06;
    uint8 internal constant SLOT_ZK_COMPLIANCE = 0x08;
    uint8 internal constant SLOT_STORAGE_DA    = 0x53;
    uint8 internal constant SLOT_SIGNAL        = 0x54;

    // ── Precompile Accessors ──────────────────────────────────────────

    /// @notice Resolves on-chain DID Document JSON-LD for an account from Precompile 0x03
    function resolveDid(address account) internal view returns (string memory) {
        return IDidRegistry(DID_REGISTRY).resolveDid(account);
    }

    /// @notice Registers an on-chain DID Document with Post-Quantum public key
    function registerDid(
        string memory keyTier,
        bytes memory pqPublicKey,
        string memory didDocument
    ) internal {
        IDidRegistry(DID_REGISTRY).registerDid(keyTier, pqPublicKey, didDocument);
    }

    /// @notice Checks Zanzibar ReBAC authorization tuple in RAM (<12µs)
    function checkPermission(
        uint16 namespace,
        bytes32 objectId,
        uint16 relation,
        address subject
    ) internal view returns (bool) {
        return IZanzibarReBAC(ZANZIBAR_REBAC).check(namespace, objectId, relation, subject);
    }

    /// @notice Inscribes a new authorization tuple to Slot 0x01 (R_1)
    function inscribePermission(
        uint16 namespace,
        bytes32 objectId,
        uint16 relation,
        address subject
    ) internal {
        IZanzibarReBAC(ZANZIBAR_REBAC).inscribeTuple(namespace, objectId, relation, subject);
    }

    /// @notice Mounts or bootstraps a polymorphic slot on the caller's account lattice
    function mountSlot(uint8 slotId, string memory pluginId, bytes32 initialRoot) internal {
        IRegisterRouter(ROUTER).mountSlot(slotId, pluginId, initialRoot);
    }

    /// @notice Resolves the root commitment of a slot on an account
    function resolveSlot(address account, uint8 slotId) internal view returns (bool mounted, string memory pluginId, bytes32 root) {
        return IRegisterRouter(ROUTER).resolveSlot(account, slotId);
    }

    /// @notice Returns the account's block lattice height from Precompile 0x0100
    function getLatticeHeight(address account) internal view returns (uint256) {
        return ILatticeHeight(LATTICE_HEIGHT).getAccountHeight(account);
    }

    /// @notice Checks jurisdiction compliance for an account against a quadrant
    function checkCompliance(address account, uint8 quadrant) internal view returns (bool compliant, uint64 activeBits) {
        return IJurisdiction(JURISDICTION).checkCompliance(account, quadrant);
    }

    /// @notice Submits a client-side zkCompliance proof ticket in RAM
    function submitComplianceTicket(bytes memory ultraHonkProof, bytes32 publicInputsHash) internal returns (bool) {
        return IZkCompliance(ZK_COMPLIANCE).submitComplianceTicket(ultraHonkProof, publicInputsHash);
    }

    /// @notice Verifies a Bao outboard tree chunk or ZK Proof-of-Retrievability
    function verifyStoragePor(bytes memory cidBytes, uint32 chunkIdx, bytes memory baoProof) internal view returns (bool) {
        return IStorageDA(STORAGE_DA).verifyStoragePor(cidBytes, chunkIdx, baoProof);
    }

    /// @notice Inscribes a blinded interest signal onto the network's RAM Cuckoo Filter
    function inscribeSignal(address target, bytes32 topicId, bytes memory mlDsaSignature) internal {
        ISignalRegistry(SIGNAL_REGISTRY).inscribeSignal(target, topicId, mlDsaSignature);
    }
}
