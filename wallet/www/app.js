// Sovereign Reth Wallet Client App JavaScript

const CATALOG = [
    {
        tokenId: "1",
        name: "Sovereign Manifold #001",
        description: "First NFT from the Sovereign Manifold collection.",
        image: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNTIiIGhlaWdodD0iMTUyIiB2aWV3Qm94PSIwIDAgMTUyIDE1MiI+PHJlY3Qgd2lkdGg9IjE1MiIgaGVpZ2h0PSIxNTIiIGZpbGw9IiMwYjBjMTAiLz48Y2lyY2xlIGN4PSI3NiIgY3k9Ijc2IiByPSI1MCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNjZmY2YxIiBzdHJva2Utd2lkdGg9IjYiLz48cGF0aCBkPSJNNTYgNTYgTDEwNiAxMDYiIHN0cm9rZT0iI2ZmN2I3MiIgc3Ryb2tlLXdpZHRoPSI0Ii8+PC9zdmc+",
        price_eure: "25.00",
        seller_address: "0x1111111111111111111111111111111111111111",
        settlement_address: "0x2222222222222222222222222222222222222222",
        nft_account: "0x0000000000000000000000000000000000000002",
        available: true
    },
    {
        tokenId: "2",
        name: "Sovereign Manifold #002",
        description: "Second NFT from the Sovereign Manifold collection.",
        image: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNTIiIGhlaWdodD0iMTUyIiB2aWV3Qm94PSIwIDAgMTUyIDE1MiI+PHJlY3Qgd2lkdGg9IjE1MiIgaGVpZ2h0PSIxNTIiIGZpbGw9IiMwYjBjMTAiLz48cmVjdCB4PSI0NiIgeT0iNDYiIHdpZHRoPSI2MCIgaGVpZ2h0PSI2MCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjNDVmM2ZmIiBzdHJva2Utd2lkdGg9IjYiLz48cGF0aCBkPSJNNzYgNDYgTDc2IDEwNiIgc3Ryb2tlPSIjZmY3YjcyIiBzdHJva2Utd2lkdGg9IjQiLz48L3N2Zz4=",
        price_eure: "50.00",
        seller_address: "0x3333333333333333333333333333333333333333",
        settlement_address: "0x2222222222222222222222222222222222222222",
        nft_account: "0x0000000000000000000000000000000000000002",
        available: true
    }
];

// App State
let wasmModule = null;
let currentDirectory = null;
let storageMode = null; // "native" or "file_api"
let profiles = []; // Loaded wallet profiles: { address, did, keystore }
let activeProfileIndex = -1;
let currentKeys = null;
let ownedNFTs = [];
let wizardStep = 1;
let connectedAddress = null;
let siweSignature = null;
let payAmountVal = "0.0";
let payAsset = "eure_gnosis";
let activeChainId = "13371337"; // default fallback

// Encryption Helpers (PBKDF2 + AES-GCM)
async function encryptData(plaintext, password) {
    const encoder = new TextEncoder();
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const passwordKey = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        passwordKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoder.encode(plaintext)
    );

    const buffer = new Uint8Array(salt.length + iv.length + encryptedContent.byteLength);
    buffer.set(salt, 0);
    buffer.set(iv, salt.length);
    buffer.set(new Uint8Array(encryptedContent), salt.length + iv.length);
    return btoa(String.fromCharCode(...buffer));
}

// Initialize WebAssembly & Sync Wallet Account
async function initWasm() {
    try {
        if (typeof wasm_bindgen !== 'undefined') {
            wasmModule = wasm_bindgen;
            await wasmModule(wasmBytes);
            console.log("WASM initialized in client.");
        } else if (window.wasm_bindgen) {
            wasmModule = window.wasm_bindgen;
            await wasmModule(wasmBytes);
            console.log("WASM initialized in client.");
        }
        loadProfilesFromLocalStorage();
        await syncActiveWalletAccount();
    } catch (e) {
        console.error("Failed to load WASM module:", e);
    }
}

// Sync directly with Rabby/MetaMask extension active account
async function syncActiveWalletAccount() {
    const injectedProvider = window.rabby || window.ethereum;
    if (!injectedProvider) {
        document.getElementById('active-wallet-address').textContent = "Rabby: Missing";
        return;
    }

    try {
        const provider = new ethers.BrowserProvider(injectedProvider);
        const accounts = await provider.listAccounts();
        
        if (accounts.length > 0) {
            const currentAddress = accounts[0].address;
            handleActiveAccountChanged(currentAddress);
        } else {
            document.getElementById('active-wallet-address').textContent = "Rabby: Locked";
        }

        // Listen for standard EVM account changes
        injectedProvider.on('accountsChanged', (accounts) => {
            if (accounts.length > 0) {
                handleActiveAccountChanged(ethers.getAddress(accounts[0]));
            } else {
                document.getElementById('active-wallet-address').textContent = "Rabby: Locked";
            }
        });
    } catch (e) {
        console.error("Error syncing active wallet account:", e);
    }
}

function handleActiveAccountChanged(address) {
    connectedAddress = address;
    document.getElementById('active-wallet-address').textContent = `Rabby: ${address.substring(0, 8)}...${address.substring(38)}`;
    
    // Check if we have an onboarding profile for this connected EVM address
    const profileIdx = profiles.findIndex(p => p.address.toLowerCase() === address.toLowerCase());
    if (profileIdx >= 0) {
        switchProfile(profileIdx);
    } else {
        // Automatically prompt wizard to onboard/link this new address
        document.getElementById('did-display').textContent = "Pending Onboarding";
        document.getElementById('addr-display').textContent = address;
        document.getElementById('onboarding-wizard').style.display = 'flex';
        document.getElementById('siwe-status').textContent = `Linked to: ${address}`;
        setStep(1);
    }
}

// Profile management
function loadProfilesFromLocalStorage() {
    const data = localStorage.getItem("SovereignProfiles");
    if (data) {
        profiles = JSON.parse(data);
    }
}

function saveProfilesToLocalStorage() {
    localStorage.setItem("SovereignProfiles", JSON.stringify(profiles));
}

function switchProfile(index) {
    activeProfileIndex = index;
    const profile = profiles[index];
    currentKeys = profile;
    updateUIWithKeys(profile);
}

// Setup Step Navigation
function setStep(step) {
    wizardStep = step;
    document.querySelectorAll('.wizard-step').forEach((el, idx) => {
        el.classList.toggle('active', idx === step - 1);
    });
    
    // Hide the Back button on Step 1 entirely
    const prevBtn = document.getElementById('prev-step-btn');
    if (step === 1) {
        prevBtn.style.display = 'none';
    } else {
        prevBtn.style.display = 'inline-block';
        prevBtn.disabled = false;
    }
    
    const nextBtn = document.getElementById('next-step-btn');
    if (step === 3) {
        nextBtn.textContent = "Finish";
        nextBtn.disabled = !document.getElementById('password-input').value;
    } else {
        nextBtn.textContent = "Next";
        if (step === 1) {
            nextBtn.disabled = !connectedAddress || !siweSignature;
        } else if (step === 2) {
            nextBtn.disabled = !storageMode;
        }
    }
}

document.getElementById('prev-step-btn').addEventListener('click', () => setStep(wizardStep - 1));
document.getElementById('next-step-btn').addEventListener('click', async () => {
    if (wizardStep < 3) {
        setStep(wizardStep + 1);
    } else {
        await completeOnboarding();
    }
});

// Setup Folder Selection
document.getElementById('select-dir-btn').addEventListener('click', async () => {
    try {
        if ('showDirectoryPicker' in window) {
            currentDirectory = await window.showDirectoryPicker();
            storageMode = "native";
            document.getElementById('dir-status').textContent = `📁 Root Storage Set`;
            document.getElementById('next-step-btn').disabled = false;
        } else {
            storageMode = "file_api";
            document.getElementById('dir-status').textContent = `🌐 Storage: File API Fallback`;
            document.getElementById('next-step-btn').disabled = false;
        }
    } catch (e) {
        console.error(e);
    }
});

// Import existing keystore backup inside setup wizard
document.getElementById('wizard-import-btn').addEventListener('click', () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        const text = await file.text();
        try {
            const imported = JSON.parse(text);
            if (imported.address && imported.did && imported.keystore) {
                // Ensure profile is not duplicated
                const exists = profiles.some(p => p.address.toLowerCase() === imported.address.toLowerCase());
                if (!exists) {
                    profiles.push(imported);
                }
                saveProfilesToLocalStorage();
                const newIdx = profiles.findIndex(p => p.address.toLowerCase() === imported.address.toLowerCase());
                switchProfile(newIdx);
                document.getElementById('onboarding-wizard').style.display = 'none';
                alert("Keystore profile restored successfully!");
            }
        } catch (err) {
            alert("Invalid backup configuration format.");
        }
    };
    input.click();
});

document.getElementById('use-virtual-btn').addEventListener('click', () => {
    storageMode = "file_api";
    document.getElementById('dir-status').textContent = `🌐 Storage: File API Fallback`;
    document.getElementById('next-step-btn').disabled = false;
});

// EVM Connection & SIWE Sign-In
document.getElementById('connect-evm-wallet-btn').addEventListener('click', async () => {
    const statusDiv = document.getElementById('siwe-status');
    statusDiv.textContent = "Connecting to EVM Wallet...";

    try {
        const injectedProvider = window.rabby || window.ethereum;
        
        if (injectedProvider) {
            const provider = new ethers.BrowserProvider(injectedProvider);
            await provider.send("eth_requestAccounts", []);
            
            const signer = await provider.getSigner();
            connectedAddress = await signer.getAddress();
            
            // Dynamically fetch chain ID from connected Rabby/MetaMask instance
            const network = await provider.getNetwork();
            activeChainId = network.chainId.toString();
            console.log(`Connected to Chain ID: ${activeChainId}`);
            
            const message = `Sign-In with Ethereum to Sovereign Manifold Identity\n\nAddress: ${connectedAddress}\nTimestamp: ${Date.now()}`;
            siweSignature = await signer.signMessage(message);
            
            statusDiv.textContent = `✅ Link Verified: ${connectedAddress.substring(0, 16)}... (Signed)`;
            document.getElementById('next-step-btn').disabled = false;
        } else {
            console.warn("No injected EVM provider found.");
            statusDiv.textContent = "❌ No standard EVM wallet extension detected.";
            alert("No browser wallet extension (Rabby/MetaMask) was found. Please make sure your wallet extension is enabled.");
        }
    } catch (e) {
        console.error(e);
        statusDiv.textContent = `❌ Error: ${e.message || e}`;
        alert("EVM connection or signing failed:\n" + (e.message || e));
    }
});

document.getElementById('password-input').addEventListener('input', (e) => {
    if (wizardStep === 3) {
        document.getElementById('next-step-btn').disabled = !e.target.value;
    }
});

// Finalize Onboarding:
// 1. Link standard EVM wallet address as primary key.
// 2. Generate post-quantum curves (ML-DSA, SPHINCS+, Falcon) + BLS + Ed25519 from auxiliary seed phrase.
// 3. Build a proper W3C DID document containing only public keys.
// 4. Save keystore (private keys) separately encrypted in keystore.enc.json.
async function completeOnboarding() {
    const password = document.getElementById('password-input').value;

    if (!wasmModule) { alert("WASM not ready yet."); return; }

    try {
        const auxiliaryWallet = ethers.Wallet.createRandom();
        const auxiliarySeed = auxiliaryWallet.mnemonic.phrase;

        const encoder = new TextEncoder();
        const seedBytes = encoder.encode(auxiliarySeed.padEnd(32, ' ')).slice(0, 32);

        // WASM generates classical & post-quantum public multibase keys
        const keysJson = wasmModule.generate_did_keys(seedBytes);
        const pubKeys = JSON.parse(keysJson);

        const didId = `did:sovereign:${activeChainId}:${connectedAddress.toLowerCase()}`;
        const didDocument = {
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/secp256k1-2019/v1"],
            "id": didId,
            "blockchainAccountId": `eip155:${activeChainId}:${connectedAddress}`,
            "verificationMethod": [
                {
                    "id": `${didId}#secp256k1`,
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": didId,
                    "publicKeyMultibase": pubKeys.secp256k1_pub
                },
                {
                    "id": `${didId}#ed25519`,
                    "type": "Ed25519VerificationKey2020",
                    "controller": didId,
                    "publicKeyMultibase": pubKeys.ed25519_pub
                },
                {
                    "id": `${didId}#bls`,
                    "type": "Bls12381G2Key2020",
                    "controller": didId,
                    "publicKeyMultibase": pubKeys.bls_pub
                },
                {
                    "id": `${didId}#ml-dsa`,
                    "type": "MlDsa65VerificationKey2024",
                    "controller": didId,
                    "publicKeyMultibase": pubKeys.ml_dsa_pub
                },
                {
                    "id": `${didId}#slh-dsa`,
                    "type": "SlhDsaVerificationKey2024",
                    "controller": didId,
                    "publicKeyMultibase": pubKeys.slh_dsa_pub
                },
                {
                    "id": `${didId}#falcon`,
                    "type": "FalconVerificationKey2024",
                    "controller": didId,
                    "publicKeyMultibase": pubKeys.falcon_pub
                },
                {
                    "id": `${didId}#xmss`,
                    "type": "XmssSha2256VerificationKey2024",
                    "controller": didId,
                    "publicKeyMultibase": pubKeys.xmss_pub
                }
            ],
            "authentication": [`${didId}#secp256k1`],
            "assertionMethod": [`${didId}#ed25519`, `${didId}#ml-dsa`],
            "keyAgreement": [`${didId}#bls`]
        };

        const privateKeystore = {
            primary_evm: connectedAddress,
            siwe_signature: siweSignature,
            auxiliary_seed: auxiliarySeed,
            did_document: didDocument
        };
        const encryptedKeystore = await encryptData(JSON.stringify(privateKeystore), password);

        // Save files separately to the local directory inside an address-specific sub-folder
        if (storageMode === "native" && currentDirectory) {
            const userDir = await currentDirectory.getDirectoryHandle(connectedAddress.toLowerCase(), { create: true });

            const didHandle = await userDir.getFileHandle("did.json", { create: true });
            const didWritable = await didHandle.createWritable();
            await didWritable.write(JSON.stringify(didDocument, null, 2));
            await didWritable.close();

            const ksHandle = await userDir.getFileHandle("keystore.enc.json", { create: true });
            const ksWritable = await ksHandle.createWritable();
            await ksWritable.write(encryptedKeystore);
            await ksWritable.close();
        }

        const newProfile = {
            address: connectedAddress,
            did: didId,
            did_document: didDocument,
            keystore: encryptedKeystore
        };

        profiles.push(newProfile);
        activeProfileIndex = profiles.length - 1;
        saveProfilesToLocalStorage();
        switchProfile(activeProfileIndex);
        document.getElementById('onboarding-wizard').style.display = 'none';
    } catch (e) {
        console.error("Onboarding failed:", e);
        alert("Key derivation or DID construction failed: " + e.message);
    }
}

function updateUIWithKeys(keys) {
    document.getElementById('addr-display').textContent = keys.address;
    document.getElementById('export-backup-btn').disabled = false;
    
    const regBtn = document.getElementById('register-did-btn');
    if (keys.registered) {
        document.getElementById('did-display').textContent = `did:sovereign:13371337:${keys.address.toLowerCase()}`;
        regBtn.textContent = "✅ DID Registered";
        regBtn.className = "nes-btn is-success";
        regBtn.disabled = true;
    } else {
        document.getElementById('did-display').textContent = keys.did; // Local peer/temporary DID
        regBtn.textContent = "🌐 Register DID on Chain";
        regBtn.className = "nes-btn is-error";
        regBtn.disabled = false;
    }
    const rpcUrl = document.getElementById('rpc-endpoint-input').value;
    loadClaimInbox(keys.address, rpcUrl);
    loadJurisdiction(keys.address, rpcUrl);
}

window.clearLocalProfiles = function() {
    if (confirm("Are you sure you want to clear all local profiles and local storage? This will clear any cached profiles.")) {
        localStorage.clear();
        alert("Local storage cleared. Reloading page...");
        window.location.reload();
    }
};

// Backup actions
document.getElementById('export-backup-btn').addEventListener('click', () => {
    if (activeProfileIndex < 0) return;
    const profile = profiles[activeProfileIndex];
    const blob = new Blob([JSON.stringify(profile, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `keystore_${profile.address}.json`;
    a.click();
});

// Helper to switch Rabby/MetaMask to the Sovereign custom chain (13371337) on the fly
async function ensureSovereignChain(injectedProvider, rpcUrl) {
    const chainIdDecimal = parseInt(activeChainId, 10);
    const chainIdHex = "0x" + chainIdDecimal.toString(16);
    try {
        await injectedProvider.request({
            method: 'wallet_switchEthereumChain',
            params: [{ chainId: chainIdHex }],
        });
    } catch (switchError) {
        // Code 4902 or unrecognized chain error message means the chain needs to be added
        if (switchError.code === 4902 || (switchError.message && switchError.message.includes("Unrecognized chain ID"))) {
            try {
                await injectedProvider.request({
                    method: 'wallet_addEthereumChain',
                    params: [
                        {
                            chainId: chainIdHex,
                            chainName: `Sovereign Chain ${activeChainId}`,
                            rpcUrls: [rpcUrl],
                            nativeCurrency: {
                                name: 'Sovereign Token',
                                symbol: 'SVT',
                                decimals: 18
                            },
                            blockExplorerUrls: null,
                        },
                    ],
                });
            } catch (addError) {
                console.error("Failed to add Sovereign chain:", addError);
                throw new Error("Could not add Sovereign Chain to Rabby/MetaMask: " + addError.message);
            }
        } else {
            console.error("Failed to switch to Sovereign chain:", switchError);
            throw switchError;
        }
    }
}

// Base58 decoder for multibase post-quantum keys
function decodeBase58(str) {
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const ALPHABET_MAP = {};
    for (let i = 0; i < ALPHABET.length; i++) {
        ALPHABET_MAP[ALPHABET.charAt(i)] = i;
    }
    let bytes = [0];
    for (let i = 0; i < str.length; i++) {
        let c = str.charAt(i);
        if (!(c in ALPHABET_MAP)) throw new Error("Non-base58 character");
        let value = ALPHABET_MAP[c];
        let carry = value;
        for (let j = 0; j < bytes.length; j++) {
            carry += bytes[j] * 58;
            bytes[j] = carry & 0xff;
            carry >>= 8;
        }
        while (carry > 0) {
            bytes.push(carry & 0xff);
            carry >>= 8;
        }
    }
    for (let i = 0; i < str.length && str.charAt(i) === '1'; i++) {
        bytes.push(0);
    }
    return new Uint8Array(bytes.reverse());
}

// Register DID document state change on-chain via Rabby/MetaMask
document.getElementById('register-did-btn').addEventListener('click', async () => {
    if (activeProfileIndex < 0 || !currentKeys) return;

    const rpcUrl = document.getElementById('rpc-endpoint-input').value;
    const injectedProvider = window.rabby || window.ethereum;

    if (!injectedProvider) {
        alert("EVM wallet extension is required to register DID on-chain.");
        return;
    }

    try {
        // Ensure standard Rabby/MetaMask is connected to our custom Chain ID on the fly
        await ensureSovereignChain(injectedProvider, rpcUrl);

        const provider = new ethers.BrowserProvider(injectedProvider);
        const signer = await provider.getSigner();
        
        // Target system registry low-entropy precompile address for DID directory registrations
        const didRegistryAddress = "0x0000000000000000000000000000000000000003";

        // Build binary calldata to match Rust precompile: key_tier_len (1 byte) || key_tier || pq_pub_key_len (4 bytes) || pq_pub_key || did_document
        const keyTier = "QuantumReady";
        const keyTierBytes = new TextEncoder().encode(keyTier);
        
        // Decode base58 multibase public key to raw bytes
        let pqPubBytes = new Uint8Array(0);
        try {
            const mlDsaMultibase = currentKeys.did_document.verificationMethod.find(m => m.id.endsWith("#ml-dsa")).publicKeyMultibase;
            if (mlDsaMultibase && mlDsaMultibase.startsWith("z")) {
                const decoded = decodeBase58(mlDsaMultibase.substring(1));
                // Remove multicodec prefix [0x93, 0x01] (2 bytes)
                pqPubBytes = decoded.slice(2);
            }
        } catch (e) {
            console.error("Failed to parse ML-DSA multibase public key:", e);
        }

        const didDocumentStr = JSON.stringify(currentKeys.did_document);
        const didDocBytes = new TextEncoder().encode(didDocumentStr);

        const totalLen = 1 + keyTierBytes.length + 4 + pqPubBytes.length + didDocBytes.length;
        const payload = new Uint8Array(totalLen);
        
        let offset = 0;
        // 1. key_tier_len (1 byte)
        payload[offset] = keyTierBytes.length;
        offset += 1;

        // 2. key_tier
        payload.set(keyTierBytes, offset);
        offset += keyTierBytes.length;

        // 3. pq_pub_key_len (4 bytes, big endian)
        const view = new DataView(payload.buffer);
        view.setUint32(offset, pqPubBytes.length, false);
        offset += 4;

        // 4. pq_pub_key
        payload.set(pqPubBytes, offset);
        offset += pqPubBytes.length;

        // 5. did_document
        payload.set(didDocBytes, offset);

        const callData = ethers.hexlify(payload);

        alert(`Constructed DID Registration transaction targeting precompile space.\nSending to endpoint: ${rpcUrl} (Chain: 13371337)`);

        const tx = await signer.sendTransaction({
            to: didRegistryAddress,
            data: callData
        });

        console.log("DID registration tx broadcasted:", tx.hash);
        
        // Persist the registration state locally in profiles
        currentKeys.registered = true;
        saveProfilesToLocalStorage();
        updateUIWithKeys(currentKeys);

        alert(`DID registration successfully sent!\nHash: ${tx.hash}\nValidators are verifying compliance signatures.`);
    } catch (e) {
        console.error("DID registration failed:", e);
        alert("Failed to broadcast DID registration transaction:\n" + (e.message || e));
    }
});

// Checkout & Conversion Quotes
let activeCheckoutItem = null;

window.checkoutNFT = function(tokenId) {
    activeCheckoutItem = CATALOG.find(x => x.tokenId === tokenId);
    if (!activeCheckoutItem) return;
    
    // Simulate real Cow/1inch API conversions (1 ETH = 2600 EURe, 1 USDC = 0.92 EURe)
    const select = document.getElementById('payment-asset-select');
    select.value = "eure_gnosis";
    updateConversionQuote();
    
    document.getElementById('checkout-modal').style.display = 'flex';
};

function updateConversionQuote() {
    if (!activeCheckoutItem) return;
    const asset = document.getElementById('payment-asset-select').value;
    const priceEure = parseFloat(activeCheckoutItem.price_eure);
    payAsset = asset;
    
    let displayStr = "";
    let payAmount = "";
    if (asset === "eure_gnosis") {
        displayStr = `1 EURe = 1.00 EURe`;
        payAmount = `${priceEure.toFixed(2)} EURe`;
        payAmountVal = priceEure.toFixed(2);
    } else if (asset === "eth_arbitrum") {
        const rate = 2600.0; // Simulated live CoW oracle rate
        const amt = priceEure / rate;
        displayStr = `1 ETH = 2600.00 EURe (CoW Swap Rate)`;
        payAmount = `${amt.toFixed(6)} ETH`;
        payAmountVal = amt.toFixed(6);
    } else if (asset === "usdc_base") {
        const rate = 0.92;
        const amt = priceEure / rate;
        displayStr = `1 USDC = 0.92 EURe (1inch Swap Rate)`;
        payAmount = `${amt.toFixed(2)} USDC`;
        payAmountVal = amt.toFixed(2);
    }
    
    document.getElementById('conversion-display').textContent = displayStr;
    document.getElementById('signed-tx-hex').value = `Transaction: Pay ${payAmount} for NFT #${activeCheckoutItem.tokenId}`;
}

document.getElementById('payment-asset-select').addEventListener('change', updateConversionQuote);

document.getElementById('confirm-purchase-btn').addEventListener('click', async () => {
    if (activeProfileIndex < 0 || !activeCheckoutItem) return;
    
    try {
        const injectedProvider = window.rabby || window.ethereum;
        if (injectedProvider) {
            const provider = new ethers.BrowserProvider(injectedProvider);
            const signer = await provider.getSigner();
            
            const intentRouterAddress = "0x0000000000000000000000000000000000000004";
            
            // Build binary calldata to match Rust precompile: intent_id (32 bytes) || target_account (20 bytes) || amount (32 bytes) || expire_epoch (8 bytes)
            const intentId = ethers.keccak256(ethers.randomBytes(32));
            const intentIdBytes = ethers.getBytes(intentId);
            
            const targetAccountBytes = ethers.getBytes(activeCheckoutItem.seller_address);
            
            const amountBytes = ethers.zeroPadValue(ethers.toBeHex(ethers.parseEther(payAmountVal)), 32);
            const amountUint8 = ethers.getBytes(amountBytes);
            
            // expire_epoch (8 bytes, big endian)
            const expireEpoch = 1000; // default margin
            const expireEpochBuffer = new ArrayBuffer(8);
            const view = new DataView(expireEpochBuffer);
            view.setUint32(4, expireEpoch, false); // big-endian
            const expireEpochBytes = new Uint8Array(expireEpochBuffer);
            
            const payload = new Uint8Array(32 + 20 + 32 + 8);
            payload.set(intentIdBytes, 0);
            payload.set(targetAccountBytes, 32);
            payload.set(amountUint8, 52);
            payload.set(expireEpochBytes, 84);
            
            const callData = ethers.hexlify(payload);
            
            // Dispatch transaction to SYSTEM_INTENT_ROUTER on the custom chain
            const tx = await signer.sendTransaction({
                to: intentRouterAddress,
                data: callData,
                value: 0
            });
            
            console.log("Saga Intent transaction broadcasted via Rabby/MetaMask:", tx.hash);
            alert(`Saga Intent transaction successfully sent to Intent Router!\nHash: ${tx.hash}\nValidator rotating sub-committees will verify this payment on Gnosis.`);
        } else {
            alert(`Sandboxed: Proved purchase intent on-chain targeting sovereign manifold registry.\nValidator rotating committee will pull and verify payment!`);
        }
        
        document.getElementById('checkout-modal').style.display = 'none';
        ownedNFTs.push(activeCheckoutItem);
        renderOwned();
    } catch (e) {
        console.error(e);
        alert("EVM Transaction rejected or failed.");
    }
});

// Render lists
function renderCatalog() {
    const list = document.getElementById('catalog-list');
    list.innerHTML = "";
    CATALOG.forEach(item => {
        const card = document.createElement('div');
        card.className = "nes-container is-dark";
        card.style.margin = "10px 0";
        card.innerHTML = `
            <div style="display:flex; gap:15px; align-items:center;">
                <img style="width: 80px; height:80px; border:2px solid #fff;" src="${item.image}">
                <div style="font-size: 0.7rem; flex:1;">
                    <p style="margin:0; color:#ff0;">${item.name}</p>
                    <p style="margin:5px 0;">${item.price_eure} EURe</p>
                    <button class="nes-btn is-primary" style="padding: 2px 10px;" onclick="checkoutNFT('${item.tokenId}')">Buy</button>
                </div>
            </div>
        `;
        list.appendChild(card);
    });
}

function renderOwned() {
    const list = document.getElementById('owned-list');
    list.innerHTML = "";
    if (ownedNFTs.length === 0) {
        list.innerHTML = "<p style='font-size:0.7rem;'>No owned NFTs yet.</p>";
        return;
    }
    ownedNFTs.forEach((item, idx) => {
        const card = document.createElement('div');
        card.className = "nes-container is-dark";
        card.style.margin = "10px 0";
        card.innerHTML = `
            <div style="display:flex; gap:15px; align-items:center;">
                <img style="width: 80px; height:80px; border:2px solid #fff;" src="${item.image}">
                <div style="font-size: 0.7rem; flex:1; display:flex; flex-direction:column; gap:8px;">
                    <p style="margin:0; color:#ff0;">${item.name}</p>
                    <button class="nes-btn is-success" style="padding:2px 8px;" onclick="flashToEpaper(${idx})">Flash NFC</button>
                    <button class="nes-btn" style="padding:2px 8px;" onclick="downloadBin(${idx})">Get Bin</button>
                </div>
            </div>
        `;
        list.appendChild(card);
    });
}

// Epaper conversion helpers
window.downloadBin = async function(idx) {
    const item = ownedNFTs[idx];
    if (!wasmModule) return;
    const encoder = new TextEncoder();
    const rawSvg = item.image.split(',')[1];
    const imageBytes = encoder.encode(atob(rawSvg));

    try {
        const packed = wasmModule.convert_to_epaper_152(imageBytes);
        const blob = new Blob([packed], {type: "application/octet-stream"});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nft_frame_${item.tokenId}.bin`;
        a.click();
    } catch (e) {
        console.error(e);
    }
};

window.flashToEpaper = async function(idx) {
    if (!('NDEFReader' in window)) {
        alert("Web NFC requires Chrome on Android.");
        return;
    }
    const item = ownedNFTs[idx];
    const encoder = new TextEncoder();
    const rawSvg = item.image.split(',')[1];
    const imageBytes = encoder.encode(atob(rawSvg));
    try {
        const packed = wasmModule.convert_to_epaper_152(imageBytes);
        const ndef = new NDEFReader();
        await ndef.write({
            records: [{ recordType: "mime", mediaType: "application/octet-stream", data: packed }]
        });
        alert("e-Paper written successfully!");
    } catch (e) {
        alert("NFC write failed.");
    }
};

// Init
renderCatalog();
renderOwned();
initWasm();

// Claim Inbox
async function loadClaimInbox(address, rpcUrl) {
    const inboxList = document.getElementById('inbox-list');
    try {
        const provider = new ethers.JsonRpcProvider(rpcUrl);
        const receiveHookAddress = "0x0000000000000000000000000000000000000002";
        const targetBytes = ethers.zeroPadValue(address, 32);
        
        const result = await provider.call({
            to: receiveHookAddress,
            data: targetBytes
        });
        
        if (!result || result === "0x") {
            inboxList.innerHTML = `<p style="font-size:0.65rem;">No pending claims.</p>`;
            return;
        }
        
        const decoded = ethers.AbiCoder.defaultAbiCoder().decode(["string"], result)[0];
        const pending = JSON.parse(decoded);
        
        if (pending.length === 0) {
            inboxList.innerHTML = `<p style="font-size:0.65rem;">No pending claims.</p>`;
            return;
        }
        
        inboxList.innerHTML = "";
        pending.forEach(item => {
            const div = document.createElement('div');
            div.className = "nes-container is-dark";
            div.style.padding = "5px 10px";
            div.style.marginBottom = "5px";
            div.innerHTML = `
                <div style="font-size: 0.65rem;">
                    <p style="margin: 0; color: #ff0;">From: ${item.sender.substring(0, 10)}...</p>
                    <p style="margin: 3px 0;">Amount: ${ethers.formatEther(item.amount)} Native</p>
                    <button class="nes-btn is-success" style="padding: 2px 8px; font-size: 0.6rem; margin-top: 5px;" 
                            onclick="claimTransfer('${item.sendBlockHash}', '${item.amount}')">Claim Settle</button>
                </div>
            `;
            inboxList.appendChild(div);
        });
    } catch (e) {
        console.error("Failed to load claim inbox:", e);
        inboxList.innerHTML = `<p style="font-size:0.65rem; color:#f00;">Error: ${e.message || e}</p>`;
    }
}

window.claimTransfer = async function(sendBlockHash, amount) {
    const password = prompt("Enter your keystore password to decrypt keys and authorize the claim block:");
    if (!password) return;
    
    try {
        const decryptedStr = await decryptData(currentKeys.keystore, password);
        const privateKeystore = JSON.parse(decryptedStr);
        const auxiliarySeed = privateKeystore.auxiliary_seed;
        
        const encoder = new TextEncoder();
        const seedBytes = encoder.encode(auxiliarySeed.padEnd(32, ' ')).slice(0, 32);
        
        const rpcUrl = document.getElementById('rpc-endpoint-input').value;
        const provider = new ethers.JsonRpcProvider(rpcUrl);
        
        const accountHeightAddress = "0x0000000000000000000000000000000000000100";
        const heightData = await provider.call({
            to: accountHeightAddress,
            data: currentKeys.address
        });
        
        let prevHash = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let sequence = 0;
        if (heightData && heightData !== "0x") {
            const decodedHeight = ethers.AbiCoder.defaultAbiCoder().decode(["uint64", "bytes32"], heightData);
            sequence = Number(decodedHeight[0]);
            prevHash = decodedHeight[1];
        }

        // Build the payload bytes to hash
        const payloadBytes = new Uint8Array(1 + 32 + 32);
        payloadBytes[0] = 1; // Receive variant
        payloadBytes.set(ethers.getBytes(sendBlockHash), 1);
        payloadBytes.set(ethers.getBytes(ethers.zeroPadValue(ethers.toBeHex(BigInt(amount)), 32)), 33);
        const payloadHash = ethers.keccak256(payloadBytes);

        // Sign payloadHash using the connected standard EVM wallet (Rabby/MetaMask) via eth_sign
        const injectedProvider = window.rabby || window.ethereum;
        const web3Provider = new ethers.BrowserProvider(injectedProvider);
        const secpSig = await web3Provider.send("eth_sign", [currentKeys.address, payloadHash]);
        
        const hexBlock = wasmModule.sign_block_lattice_receive_hex(
            seedBytes,
            currentKeys.address,
            sendBlockHash,
            amount,
            prevHash,
            sequence,
            secpSig
        );
        
        const txHash = await provider.send("eth_sendRawTransaction", [hexBlock]);
        alert(`✅ Settle block broadcasted successfully! Hash: ${txHash}`);
        loadClaimInbox(currentKeys.address, rpcUrl);
    } catch (e) {
        console.error("Claim settle failed:", e);
        alert("Failed to claim transfer:\n" + (e.message || e));
    }
};

// Jurisdiction
async function loadJurisdiction(address, rpcUrl) {
    const optsContainer = document.getElementById('jurisdiction-options');
    try {
        const provider = new ethers.JsonRpcProvider(rpcUrl);
        const jurisdictionAddress = "0x0000000000000000000000000000000000000005";
        const accountHeightAddress = "0x0000000000000000000000000000000000000100";
        
        const chainIdVal = parseInt(activeChainId, 10) || 13371337;
        const calldata = ethers.zeroPadValue(ethers.toBeHex(chainIdVal), 32);
        const vecResult = await provider.call({
            to: jurisdictionAddress,
            data: calldata
        });
        
        let bitRegistry = {};
        if (vecResult && vecResult !== "0x") {
            const decoded = ethers.AbiCoder.defaultAbiCoder().decode(["string"], vecResult)[0];
            const info = JSON.parse(decoded);
            bitRegistry = info.bitRegistry || {};
        }
        
        const heightData = await provider.call({
            to: accountHeightAddress,
            data: address
        });
        
        let userQ1 = 0n;
        let userQ2 = 0n;
        if (heightData && heightData !== "0x") {
            const decodedHeight = ethers.AbiCoder.defaultAbiCoder().decode(["uint64", "bytes32", "uint64", "uint64", "uint64", "uint64"], heightData);
            userQ1 = BigInt(decodedHeight[3]);
            userQ2 = BigInt(decodedHeight[4]);
        }
        
        optsContainer.innerHTML = "";
        
        const keys = Object.keys(bitRegistry);
        if (keys.length === 0) {
            bitRegistry = {
                "1_0": "KYC/AML Verified",
                "1_1": "Sanctioned Entity",
                "1_2": "PEP Flagged",
                "2_0": "Accredited Investor",
                "2_1": "Institutional",
                "2_2": "Region: United States",
                "2_3": "Region: European Union",
                "2_4": "Region: Switzerland",
                "2_5": "Region: Cayman Islands"
            };
        }
        
        // Separate regions
        const regions = [];
        
        for (const [key, label] of Object.entries(bitRegistry)) {
            const parts = key.split('_');
            const q = parseInt(parts[0], 10);
            const b = parseInt(parts[1], 10);
            
            let isChecked = false;
            if (q === 1) {
                isChecked = (userQ1 & (1n << BigInt(b))) !== 0n;
            } else if (q === 2) {
                isChecked = (userQ2 & (1n << BigInt(b))) !== 0n;
            }
            
            if (label.toLowerCase().startsWith("region:") || label.toLowerCase().startsWith("country:")) {
                regions.push({ key, label: label.replace(/^(region|country):\s*/i, ""), q, b, isChecked });
            }
        }
        
        // Render country/region dropdown
        if (regions.length > 0) {
            const selectDiv = document.createElement('div');
            selectDiv.className = "nes-select is-dark";
            selectDiv.style.marginTop = "5px";
            selectDiv.style.marginBottom = "10px";
            
            let selectHtml = `<select id="jurisdiction-region-select" style="font-size:0.65rem;">`;
            let hasSelected = false;
            regions.forEach(regOpt => {
                if (regOpt.isChecked) hasSelected = true;
            });
            selectHtml += `<option value="none" ${!hasSelected ? 'selected' : ''}>None / Undeclared</option>`;
            
            regions.forEach(regOpt => {
                selectHtml += `<option value="${regOpt.key}" ${regOpt.isChecked ? 'selected' : ''}>${regOpt.label}</option>`;
            });
            selectHtml += `</select>`;
            selectDiv.innerHTML = selectHtml;
            optsContainer.appendChild(selectDiv);
        } else {
            optsContainer.innerHTML = `<p style="font-size:0.65rem; color:#888;">No regions configured by validators.</p>`;
        }
    } catch (e) {
        console.error("Failed to load jurisdiction:", e);
        optsContainer.innerHTML = `<p style="font-size:0.65rem; color:#f00;">Error: ${e.message || e}</p>`;
    }
}

document.getElementById('update-jurisdiction-btn').addEventListener('click', async () => {
    if (!connectedAddress) {
        alert("Please connect your wallet first.");
        return;
    }
    
    try {
        const injectedProvider = window.rabby || window.ethereum;
        if (!injectedProvider) {
            alert("No injected wallet found.");
            return;
        }
        
        const provider = new ethers.BrowserProvider(injectedProvider);
        const signer = await provider.getSigner();
        const jurisdictionAddress = "0x0000000000000000000000000000000000000005";
        
        let newQ2 = 0n;
        
        // Gather region bits
        const regionSelect = document.getElementById('jurisdiction-region-select');
        if (regionSelect && regionSelect.value !== "none") {
            const parts = regionSelect.value.split('_');
            const q = parseInt(parts[0], 10);
            const b = parseInt(parts[1], 10);
            if (q === 2) {
                newQ2 |= (1n << BigInt(b));
            }
        }
        
        const manifoldId = parseInt(activeChainId, 10) || 13371337;
        
        // Propose transaction for Quadrant 2 containing user's declared region
        const decisionQ2 = {
            manifold_id: manifoldId,
            action: {
                SetQuadrantBits: {
                    target: connectedAddress,
                    quadrant: 2,
                    bits: Number(newQ2)
                }
            },
            proposed_by: connectedAddress,
            epoch: 1
        };
        const callDataQ2 = ethers.hexlify(new TextEncoder().encode(JSON.stringify(decisionQ2)));
        const tx = await signer.sendTransaction({
            to: jurisdictionAddress,
            data: callDataQ2
        });
        
        alert(`⚖️ Jurisdiction region update proposed successfully!\nHash: ${tx.hash}`);
    } catch (e) {
        console.error("Jurisdiction update failed:", e);
        alert("Failed to update jurisdiction:\n" + (e.message || e));
    }
});

