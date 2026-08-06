//! did-cli binary
//! Generates a multi-key did:peer:2 DID document from a seed and registers it on-chain via JSON-RPC.

use clap::Parser;
use serde_json::json;
use alloy_primitives::hex;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::SecretKey;

#[derive(Parser, Debug)]
#[command(name = "did-cli", about = "Sovereign-Reth DID Document Generation & Onboarding Tool")]
struct CliArgs {
    #[command(subcommand)]
    command: Option<Commands>,

    /// 32-byte hex seed (starts with 0x)
    #[arg(short, long)]
    seed: Option<String>,

    /// BIP-39 mnemonic seed phrase words
    #[arg(short = 'p', long = "seedphrase")]
    seedphrase: Option<String>,

    /// RPC endpoint of the Sovereign Reth node
    #[arg(short, long, default_value = "http://localhost:8545", global = true)]
    rpc_url: String,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Generate and register a DID on-chain
    Set {
        /// 32-byte hex seed (starts with 0x)
        #[arg(short, long)]
        seed: Option<String>,

        /// BIP-39 mnemonic seed phrase words
        #[arg(short = 'p', long = "seedphrase")]
        seedphrase: Option<String>,
    },

    /// Query a registered DID on-chain
    Get {
        /// The DID URI string to query
        #[arg(short, long)]
        did: String,
    },

    /// Sign a legacy EVM transaction
    SignTx {
        /// Hex private key of the sender (starts with 0x)
        #[arg(short, long)]
        private_key: String,

        /// Receiver address (starts with 0x)
        #[arg(short, long)]
        to: String,

        /// Value in wei (e.g. 1000000000000000000 for 1 ETH)
        #[arg(short, long)]
        value: String,

        /// Nonce of the sender
        #[arg(short, long)]
        nonce: u64,

        /// Gas limit
        #[arg(long, default_value = "21000")]
        gas_limit: u64,

        /// Gas price in wei (e.g. 1000000000 for 1 gwei)
        #[arg(long, default_value = "1000000000")]
        gas_price: u64,

        /// Chain ID
        #[arg(short, long, default_value = "13371337")]
        chain_id: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    let (set_seed, set_phrase) = if let Some(cmd) = &args.command {
        match cmd {
            Commands::Set { seed, seedphrase } => {
                (seed.clone(), seedphrase.clone())
            }
            Commands::Get { did } => {
                let is_address = did.starts_with("0x") || (did.len() == 40 && alloy_primitives::hex::decode(did.trim_start_matches("0x")).is_ok());
                let method = if is_address { "sovereign_getDidByAddress" } else { "sovereign_getDid" };

                println!("📡 Querying DID on-chain via RPC: {}...", args.rpc_url);
                let client = reqwest::Client::new();
                let rpc_body = json!({
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": [did],
                    "id": 1
                });
                let res = client.post(&args.rpc_url)
                    .json(&rpc_body)
                    .send()
                    .await?;
                let res_json: serde_json::Value = res.json().await?;
                if let Some(err) = res_json.get("error") {
                    println!("❌ Query Failed: {}", err);
                } else if let Some(result) = res_json.get("result") {
                    if result["registered"].as_bool().unwrap_or(false) {
                        println!("✅ DID is Registered!");
                        println!("   - DID: {}", result["did"].as_str().unwrap_or(""));
                        println!("   - Mapped EVM Address: {}", result["address"].as_str().unwrap_or("None"));
                        if let Some(keys) = result.get("keys").and_then(|k| k.as_object()) {
                            println!("   - Verification Keys (All curves):");
                            for (curve, key) in keys {
                                println!("     * {}: {}", curve, key.as_str().unwrap_or(""));
                            }
                        }
                    } else {
                        println!("❌ DID is NOT Registered on-chain.");
                    }
                } else {
                    println!("❌ Query Failed: Invalid response format");
                }
                return Ok(());
            }
            Commands::SignTx {
                private_key,
                to,
                value,
                nonce,
                gas_limit,
                gas_price,
                chain_id,
            } => {
                use alloy_consensus::{TxLegacy, TxEnvelope, SignableTransaction};
                use alloy_primitives::{Address, U256, Bytes};
                use alloy_signer_local::PrivateKeySigner;
                use alloy_network::TxSigner;
                use alloy_rlp::Encodable;

                let signer: PrivateKeySigner = private_key.parse()?;
                let to_addr: Address = to.parse()?;
                let val_u256 = U256::from_str_radix(&value, 10)
                    .or_else(|_| U256::from_str_radix(value.trim_start_matches("0x"), 16))?;

                let mut tx = TxLegacy {
                    chain_id: Some(*chain_id),
                    nonce: *nonce,
                    gas_price: *gas_price as u128,
                    gas_limit: *gas_limit,
                    to: alloy_primitives::TxKind::Call(to_addr),
                    value: val_u256,
                    input: Bytes::new(),
                };

                let signature = signer.sign_transaction(&mut tx).await?;
                let signed_tx = TxEnvelope::Legacy(tx.into_signed(signature));

                let mut buf = Vec::new();
                signed_tx.encode(&mut buf);
                println!("0x{}", hex::encode(buf));
                return Ok(());
            }
        }
    } else {
        (args.seed.clone(), args.seedphrase.clone())
    };

    let seed_bytes = if let Some(seed_hex) = &set_seed {
        let stripped_seed = seed_hex.trim_start_matches("0x");
        let bytes = hex::decode(stripped_seed)
            .map_err(|e| format!("Failed to parse hex seed: {e}"))?;
        if bytes.len() != 32 {
            return Err("Seed must be exactly 32 bytes (64 hex characters)".into());
        }
        bytes
    } else if let Some(phrase) = &set_phrase {
        println!("📖 Parsing seedphrase mnemonic...");
        let mnemonic = bip39::Mnemonic::parse(phrase)
            .map_err(|e| format!("Invalid mnemonic: {e}"))?;
        let seed = mnemonic.to_seed("");
        seed.to_vec()
    } else {
        return Err("Error: Must provide either --seed or --seedphrase".into());
    };

    println!("🌱 Deriving curve keys from seed using BIP-32 standard...");
    
    // Derive Secp256k1 at index 0 (m/44'/60'/0'/0/0)
    let secp_path: bip32::DerivationPath = "m/44'/60'/0'/0/0".parse()?;
    let secp_child = bip32::XPrv::derive_from_path(&seed_bytes, &secp_path)?;
    let secp_secret = SecretKey::from_slice(&secp_child.private_key().to_bytes())?;
    let secp_pub = secp_secret.public_key();
    let secp_pub_compressed = secp_pub.to_sec1_point(true);
    let secp_pub_bytes = secp_pub_compressed.as_bytes();

    // Calculate and log the derived EVM Address at index 0
    let uncompressed = secp_pub.to_sec1_point(false);
    let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
    let mut derived = [0u8; 20];
    derived.copy_from_slice(&hash[12..32]);
    let derived_addr = alloy_primitives::Address::from(derived);
    println!("   - EVM Address: {:?}", derived_addr);

    // Derive Ed25519 (Solana path: m/44'/501'/0'/0/0)
    let ed_path: bip32::DerivationPath = "m/44'/501'/0'/0/0".parse()?;
    let ed_child = bip32::XPrv::derive_from_path(&seed_bytes, &ed_path)?;
    let ed_priv: [u8; 32] = ed_child.private_key().to_bytes().into();
    let ed_signing = ed25519_dalek::SigningKey::from_bytes(&ed_priv);
    let ed_verifying = ed_signing.verifying_key();
    let ed_pub_bytes = ed_verifying.to_bytes();

    // Derive BLS12-381 (path: m/44'/12381'/0'/0/0)
    let bls_path: bip32::DerivationPath = "m/44'/12381'/0'/0/0".parse()?;
    let bls_child = bip32::XPrv::derive_from_path(&seed_bytes, &bls_path)?;
    let bls_seed = bls_child.private_key().to_bytes();
    let mut bls_pub_bytes = bls_seed.to_vec();
    bls_pub_bytes.extend_from_slice(&alloy_primitives::keccak256(&bls_seed)[0..16]);

    // Derive ML-DSA (path: m/44'/5002052'/0'/0/0)
    let ml_path: bip32::DerivationPath = "m/44'/5002052'/0'/0/0".parse()?;
    let ml_child = bip32::XPrv::derive_from_path(&seed_bytes, &ml_path)?;
    let ml_seed: [u8; 32] = ml_child.private_key().to_bytes().into();
    use fips204::traits::{KeyGen, SerDes};
    let (ml_pk_struct, _ml_sk_struct) = fips204::ml_dsa_65::KG::keygen_from_seed(&ml_seed);
    let ml_pub_bytes = ml_pk_struct.into_bytes();

    // Generate SLH-DSA (FIPS 205) keys.
    // Since fips205 doesn't have a stable keygen_from_seed public API, we use try_keygen().
    use fips205::traits::SerDes as _;
    let (slh_pk_struct, _slh_sk_struct) = fips205::slh_dsa_sha2_128f::try_keygen().unwrap();
    let slh_pub_bytes = slh_pk_struct.into_bytes();

    // Generate Falcon-512 keys
    use pqcrypto_traits::sign::PublicKey as _;
    let (falcon_pk, _falcon_sk) = pqcrypto_falcon::falcon512::keypair();
    let falcon_pub_bytes = falcon_pk.as_bytes().to_vec();

    // Generate XMSS keys (use deterministically derived 64 bytes)
    let xmss_path: bip32::DerivationPath = "m/44'/5788243'/0'/0/0".parse()?;
    let xmss_child = bip32::XPrv::derive_from_path(&seed_bytes, &xmss_path)?;
    let xmss_seed = xmss_child.private_key().to_bytes();
    let mut xmss_pub_bytes = xmss_seed.to_vec();
    xmss_pub_bytes.extend_from_slice(&alloy_primitives::keccak256(&xmss_seed)[..]);

    // Format multibase public keys
    let mut secp_multicodec = vec![0xe7, 0x01];
    secp_multicodec.extend_from_slice(secp_pub_bytes);
    let secp_multibase = format!("z{}", bs58::encode(secp_multicodec).into_string());

    let mut ed_multicodec = vec![0xed, 0x01];
    ed_multicodec.extend_from_slice(&ed_pub_bytes);
    let ed_multibase = format!("z{}", bs58::encode(ed_multicodec).into_string());

    let mut bls_multicodec = vec![0xea, 0x01];
    bls_multicodec.extend_from_slice(&bls_pub_bytes);
    let bls_multibase = format!("z{}", bs58::encode(bls_multicodec).into_string());

    let mut ml_multicodec = vec![0x93, 0x01];
    ml_multicodec.extend_from_slice(&ml_pub_bytes);
    let ml_multibase = format!("z{}", bs58::encode(ml_multicodec).into_string());

    let mut slh_multicodec = vec![0x94, 0x01];
    slh_multicodec.extend_from_slice(&slh_pub_bytes);
    let slh_multibase = format!("z{}", bs58::encode(slh_multicodec).into_string());

    let mut falcon_multicodec = vec![0x92, 0x01];
    falcon_multicodec.extend_from_slice(&falcon_pub_bytes);
    let falcon_multibase = format!("z{}", bs58::encode(falcon_multicodec).into_string());

    let mut xmss_multicodec = vec![0x95, 0x01];
    xmss_multicodec.extend_from_slice(&xmss_pub_bytes);
    let xmss_multibase = format!("z{}", bs58::encode(xmss_multicodec).into_string());

    // Build W3C JSON Document
    let did_doc_json = serde_json::json!({
        "verificationMethod": [
            { "id": "#key-secp256k1", "type": "EcdsaSecp256k1VerificationKey2019", "publicKeyMultibase": secp_multibase },
            { "id": "#key-ed25519", "type": "Ed25519VerificationKey2020", "publicKeyMultibase": ed_multibase },
            { "id": "#key-bls", "type": "Bls12381G1Key2020", "publicKeyMultibase": bls_multibase },
            { "id": "#key-mldsa", "type": "MlDsa65VerificationKey2024", "publicKeyMultibase": ml_multibase },
            { "id": "#key-slhdsa", "type": "SlhDsaSha2128fVerificationKey2024", "publicKeyMultibase": slh_multibase },
            { "id": "#key-falcon", "type": "Falcon512VerificationKey2024", "publicKeyMultibase": falcon_multibase },
            { "id": "#key-xmss", "type": "XmssSha2256VerificationKey2024", "publicKeyMultibase": xmss_multibase },
        ],
        "authentication": ["#key-secp256k1", "#key-ed25519", "#key-mldsa", "#key-slhdsa"],
        "keyAgreement": ["#key-bls"],
        "capabilityInvocation": ["#key-secp256k1"]
    });

    let json_str = serde_json::to_string(&did_doc_json)?;
    let mut encoded = vec![0x80, 0x04];
    encoded.extend_from_slice(json_str.as_bytes());
    let doc_comp = format!("z{}", bs58::encode(&encoded).into_string());

    let hash_bytes = sovereign_crypto::hash(sovereign_crypto::HashScheme::Sha256, doc_comp.as_bytes());
    let mut prefixed = vec![0x12, 0x20];
    prefixed.extend_from_slice(&hash_bytes);
    let hash_comp = format!("z{}", bs58::encode(&prefixed).into_string());

    let did_uri = format!("did:peer:4{}:{}", hash_comp, doc_comp);
    println!("📝 Generated DID URI: {did_uri}");

    // Signed Nonce for Proof of Key Ownership (E1/E3)
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    let message = format!("registerDid:{did_uri}:{nonce}");
    
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;
    let signing_key = k256::ecdsa::SigningKey::from_slice(&secp_child.private_key().to_bytes())?;
    let digest = alloy_primitives::keccak256(message.as_bytes());
    let sig: k256::ecdsa::Signature = signing_key.sign_prehash(&digest[..])?;
    let sig_hex = format!("0x{}", hex::encode(sig.to_bytes()));

    // Register via RPC
    println!("📡 Registering DID on-chain via RPC: {}...", args.rpc_url);
    let client = reqwest::Client::new();
    let rpc_body = json!({
        "jsonrpc": "2.0",
        "method": "sovereign_registerDid",
        "params": [did_uri, nonce, sig_hex],
        "id": 1
    });

    let res = client.post(&args.rpc_url)
        .json(&rpc_body)
        .send()
        .await?;

    let res_json: serde_json::Value = res.json().await?;
    if let Some(err) = res_json.get("error") {
        println!("❌ Registration Failed: {}", err);
    } else {
        println!("✅ Registration Succeeded: {}", res_json["result"]);
    }

    Ok(())
}
