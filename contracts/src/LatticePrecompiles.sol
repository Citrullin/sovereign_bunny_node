// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ISovereignPrecompiles.sol";

/// @title LatticePrecompiles
/// @notice Central registry and static address constants for Sovereign Account-Lattice Precompiles (EIP-1352)
contract LatticePrecompiles {
    address public constant PRECOMPILE_ROUTER          = address(0x0000000000000000000000000000000000000001);
    address public constant PRECOMPILE_RECEIVE         = address(0x0000000000000000000000000000000000000002);
    address public constant PRECOMPILE_DID_REGISTRY    = address(0x0000000000000000000000000000000000000003);
    address public constant PRECOMPILE_SAGA_ESCROW     = address(0x0000000000000000000000000000000000000004);
    address public constant PRECOMPILE_JURISDICTION    = address(0x0000000000000000000000000000000000000005);
    address public constant PRECOMPILE_BRIDGE          = address(0x0000000000000000000000000000000000000006);
    address public constant PRECOMPILE_ASYNC_INBOX     = address(0x0000000000000000000000000000000000000007);
    address public constant PRECOMPILE_ZK_COMPLIANCE   = address(0x0000000000000000000000000000000000000008);
    address public constant PRECOMPILE_STORAGE_DA      = address(0x0000000000000000000000000000000000000053);
    address public constant PRECOMPILE_SIGNAL_REGISTRY = address(0x0000000000000000000000000000000000000054);
    address public constant PRECOMPILE_ZANZIBAR_REBAC  = address(0x0000000000000000000000000000000000000061);
    address public constant PRECOMPILE_CMS_ACTPUB      = address(0x00000000000000000000000000000000000000F1);
    address public constant PRECOMPILE_LATTICE_HEIGHT  = address(0x0000000000000000000000000000000000000100);

    /// @notice Queries the local block sequence number (Account Height) of the target address
    function getAccountHeight(address target) external view returns (uint256) {
        return ILatticeHeight(PRECOMPILE_LATTICE_HEIGHT).getAccountHeight(target);
    }

    /// @notice Performs a sub-microsecond in-memory Zanzibar ReBAC authorization check
    function checkPermission(uint16 namespace, bytes32 objectId, uint16 relation, address subject) external view returns (bool) {
        return IZanzibarReBAC(PRECOMPILE_ZANZIBAR_REBAC).check(namespace, objectId, relation, subject);
    }
}
