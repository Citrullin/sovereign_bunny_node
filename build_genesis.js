const fs = require('fs');
const path = require('path');

const entrypointBytecode = fs.readFileSync(
    path.resolve(__dirname, 'entrypoint_bytecode.txt'),
    'utf8'
).trim();

// Ensure it starts with 0x
const entrypointHex = entrypointBytecode.startsWith('0x') 
    ? entrypointBytecode 
    : '0x' + entrypointBytecode;

const paymasterBytecode = fs.readFileSync(
    path.resolve(__dirname, 'contracts', 'out', 'SimplePaymaster.runtime.bin'),
    'utf8'
).trim();

const paymasterHex = paymasterBytecode.startsWith('0x')
    ? paymasterBytecode
    : '0x' + paymasterBytecode;

const genesis = {
  "config": {
    "chainId": 13371337,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "muirGlacierBlock": 0,
    "berlinBlock": 0,
    "londonBlock": 0,
    "arrowGlacierBlock": 0,
    "grayGlacierBlock": 0,
    "shanghaiTime": 0,
    "cancunTime": 0,
    "pragueTime": 0,
    "parisBlock": 0,
    "mergeNetsplitBlock": 0,
    "terminalTotalDifficulty": 0
  },
  "nonce": "0x0",
  "timestamp": "0x0",
  "extraData": "0x",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x0",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000",
  "alloc": {
    "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789": {
      "balance": "0xffffffffffffffffffffffff",
      "code": entrypointHex
    },
    "0x0000000000000000000000000000000013371337": {
      "balance": "0xffffffffffffffffffffffff",
      "code": paymasterHex
    },
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266": {
      "balance": "0xffffffffffffffffffffffff"
    },
    "0x918c30482462c8024ba6cf34a18ba1f8bbdb755f": {
      "balance": "0xffffffffffffffffffffffff"
    }
  }
};

fs.writeFileSync(
    path.resolve(__dirname, 'genesis.json'),
    JSON.stringify(genesis, null, 2)
);

console.log('Genesis file created successfully!');
