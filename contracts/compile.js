const fs = require('fs');
const path = require('path');
const solc = require('solc');

const sourcePath = path.resolve(__dirname, 'src', 'SimplePaymaster.sol');
const source = fs.readFileSync(sourcePath, 'utf8');

const input = {
    language: 'Solidity',
    sources: {
        'SimplePaymaster.sol': {
            content: source
        }
    },
    settings: {
        outputSelection: {
            '*': {
                '*': ['abi', 'evm.deployedBytecode']
            }
        }
    }
};

const output = JSON.parse(solc.compile(JSON.stringify(input)));

if (output.errors) {
    output.errors.forEach(err => {
        console.error(err.formattedMessage);
    });
}

const contract = output.contracts['SimplePaymaster.sol']['SimplePaymaster'];
const runtimeBytecode = contract.evm.deployedBytecode.object;
const abi = contract.abi;

const outDir = path.resolve(__dirname, 'out');
if (!fs.existsSync(outDir)) {
    fs.mkdirSync(outDir, { recursive: true });
}

fs.writeFileSync(path.resolve(outDir, 'SimplePaymaster.runtime.bin'), runtimeBytecode);
console.log('Runtime bytecode length:', runtimeBytecode.length);
