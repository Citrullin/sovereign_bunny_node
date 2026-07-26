// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

contract SimplePaymaster {
    address public immutable entryPoint;

    enum PostOpMode {
        opSucceeded,
        opReverted,
        postOpReverted
    }

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function validatePaymasterUserOp(
        UserOperation calldata /*userOp*/,
        bytes32 /*userOpHash*/,
        uint256 /*maxCost*/
    ) external view returns (bytes memory context, uint256 validationData) {
        // Return 0 to indicate signature / validation is valid
        return ("", 0);
    }

    function postOp(
        PostOpMode /*mode*/,
        bytes calldata /*context*/,
        uint256 /*actualGasCost*/
    ) external view {
    }
}
