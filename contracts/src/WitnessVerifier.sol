// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WitnessVerifier
/// @notice Implements O(1) Pairing check on BN254 curve (alt_bn128) in Solidity
contract WitnessVerifier {
    // BN254 field prime p
    uint256 constant P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @notice Verifies Verkle state leaf witness pairing: e(pi, g2) == e(leaf, r_stateless)
    /// @return true if verification succeeds
    function verifyPairing(
        uint256[2] memory pi_g1,       // x, y coordinate of proof pi
        uint256[2] memory leaf_g1,     // x, y coordinate of Leaf(H, owner)
        uint256[4] memory g2_point,    // G2 generator point
        uint256[4] memory r_stateless  // G2 stateless root reference point
    ) public view returns (bool) {
        // Pairing input structure for 0x08 precompile:
        // [P1.x, P1.y, Q1.x_a, Q1.x_b, Q1.y_a, Q1.y_b, P2.x, P2.y, Q2.x_a, Q2.x_b, Q2.y_a, Q2.y_b]
        uint256[12] memory input;

        // 1. First pair: e(pi, g2_point)
        input[0] = pi_g1[0];
        input[1] = pi_g1[1];
        input[2] = g2_point[0];
        input[3] = g2_point[1];
        input[4] = g2_point[2];
        input[5] = g2_point[3];

        // 2. Second pair: e(-leaf_g1, r_stateless) -> negating y mod P
        input[6] = leaf_g1[0];
        input[7] = P - (leaf_g1[1] % P);
        input[8] = r_stateless[0];
        input[9] = r_stateless[1];
        input[10] = r_stateless[2];
        input[11] = r_stateless[3];

        uint256[1] memory out;
        bool success;
        assembly {
            // Call alt_bn128 pairing precompile at address 0x08
            success := staticcall(gas(), 8, input, 384, out, 32)
        }
        return success && out[0] == 1;
    }
}
