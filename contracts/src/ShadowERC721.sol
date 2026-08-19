// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./WitnessVerifier.sol";
import "./LatticePrecompiles.sol";

/**
 * @dev OpenZeppelin ERC721 mock interfaces to make contract standalone and easy to compile.
 */
interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

contract ShadowERC721 is WitnessVerifier, LatticePrecompiles {
    string public name = "Shadow Sovereign NFT";
    string public symbol = "SHADOW";

    // Mappings
    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    // Bridge mapping to track active bridges and timeouts
    struct BridgeState {
        address originalOwner;
        uint256 bridgeEpoch;
        bool active;
    }
    mapping(uint256 => BridgeState) public bridgeStates;

    // Events
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    
    event BridgedIn(uint256 indexed tokenId, address indexed recipient, uint256 epoch);
    event BridgedBack(uint256 indexed tokenId, address indexed originalOwner);

    constructor() {}

    function balanceOf(address owner) public view returns (uint256) {
        require(owner != address(0), "Zero address query");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "Invalid tokenId");
        return owner;
    }

    // Standard ERC721 approvals and transfer logic
    function approve(address to, uint256 tokenId) public {
        address owner = ownerOf(tokenId);
        require(to != owner, "Approval to current owner");
        require(msg.sender == owner || isApprovedForAll(owner, msg.sender), "Not approved");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function getApproved(uint256 tokenId) public view returns (address) {
        require(_owners[tokenId] != address(0), "Invalid tokenId");
        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) public {
        require(operator != msg.sender, "Approve to caller");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function _transfer(address from, address to, uint256 tokenId) internal {
        require(ownerOf(tokenId) == from, "Transfer from incorrect owner");
        require(to != address(0), "Transfer to zero address");

        _tokenApprovals[tokenId] = address(0);
        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Not approved or owner");
        _transfer(from, to, tokenId);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {
        address owner = ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }

    /**
     * @notice O(1) Bridge In: Mint NFT on Base/Arbitrum using Verkle state leaf witness
     */
    function bridgeIn(
        uint256 tokenId,
        address recipient,
        uint256[2] memory pi_g1,
        uint256[2] memory leaf_g1,
        uint256[4] memory g2_point,
        uint256[4] memory r_stateless,
        uint256 epoch
    ) public {
        require(_owners[tokenId] == address(0), "Token already bridged in");

        // Verify pairing e(pi, g2) == e(leaf, r_stateless)
        bool verified = verifyPairing(pi_g1, leaf_g1, g2_point, r_stateless);
        require(verified, "Verkle state witness verification failed");

        // Mint token
        _owners[tokenId] = recipient;
        _balances[recipient] += 1;
        
        bridgeStates[tokenId] = BridgeState({
            originalOwner: recipient,
            bridgeEpoch: epoch,
            active: true
        });

        emit Transfer(address(0), recipient, tokenId);
        emit BridgedIn(tokenId, recipient, epoch);
    }

    /**
     * @notice Burn on L1/L2 and bridge back to stateless chain
     */
    function burnAndBridge(uint256 tokenId) public {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner || _isApprovedOrOwner(msg.sender, tokenId), "Not authorized");

        // Clean approvals
        _tokenApprovals[tokenId] = address(0);
        _balances[owner] -= 1;
        _owners[tokenId] = address(0);

        bridgeStates[tokenId].active = false;

        emit Transfer(owner, address(0), tokenId);
        emit BridgedBack(tokenId, bridgeStates[tokenId].originalOwner);
    }

    /**
     * @notice Returns fully self-contained base64 data JSON URI (compatible with OpenSea/Rabby)
     */
    function tokenURI(uint256 tokenId) public view returns (string memory) {
        require(_owners[tokenId] != address(0), "Token does not exist");
        
        // Base64 encode JSON containing SVG image (from Component 15 extended design)
        string memory svg = '<svg xmlns="http://www.w3.org/2000/svg" width="150" height="150"><rect width="150" height="150" fill="#0b0c10"/><circle cx="75" cy="75" r="50" fill="none" stroke="#66fcf1" stroke-width="5"/></svg>';
        string memory json = string(abi.encodePacked(
            '{"name": "Shadow Sovereign #', _uint2str(tokenId), 
            '", "description": "Local-first post-quantum shadow NFT", "image": "data:image/svg+xml;utf8,', svg, '"}'
        ));
        
        return string(abi.encodePacked("data:application/json;utf8,", json));
    }

    function _uint2str(uint256 _i) internal pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (uint8)(48 + _i % 10);
            bstr[k] = bytes1(temp);
            _i /= 10;
        }
        return string(bstr);
    }
}
