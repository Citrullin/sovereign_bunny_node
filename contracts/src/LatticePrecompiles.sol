// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LatticePrecompiles
/// @notice Solidity wrapper interface for accessing the account-lattice height precompile
contract LatticePrecompiles {
    address constant LATTICE_HEIGHT_PRECOMPILE = address(0x0100);

    /// @notice Queries the local block sequence number (Account Height) of the target address
    /// @param target The account address to query
    /// @return The sequence height of the target account
    function getAccountHeight(address target) public view returns (uint256) {
        bytes memory payload = abi.encodePacked(target);
        (bool success, bytes memory result) = LATTICE_HEIGHT_PRECOMPILE.staticcall(payload);
        if (!success || result.length < 32) {
            return 0;
        }
        return abi.decode(result, (uint256));
    }
}
