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
    #[arg(short, long, default_value = "http://localhost:8545")]
    rpc_url: String,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
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

fn to_peer_did_key_format(multibase: &str) -> String {
    if let Some(stripped) = multibase.strip_prefix('z') {
        format!("Vz{}", stripped)
    } else {
        multibase.to_string()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    if let Some(cmd) = args.command {
        match cmd {
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
                    chain_id: Some(chain_id),
                    nonce,
                    gas_price: gas_price as u128,
                    gas_limit,
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
    }

    let seed_bytes = if let Some(seed_hex) = &args.seed {
        let stripped_seed = seed_hex.trim_start_matches("0x");
        let bytes = hex::decode(stripped_seed)
            .map_err(|e| format!("Failed to parse hex seed: {e}"))?;
        if bytes.len() != 32 {
            return Err("Seed must be exactly 32 bytes (64 hex characters)".into());
        }
        bytes
    } else if let Some(phrase) = &args.seedphrase {
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
    println!("   - Secp256k1 Private Key: 0x{}", hex::encode(secp_child.private_key().to_bytes()));

    // Derive Ed25519 (Solana path: m/44'/501'/0'/0/0)
    let ed_path: bip32::DerivationPath = "m/44'/501'/0'/0/0".parse()?;
    let ed_child = bip32::XPrv::derive_from_path(&seed_bytes, &ed_path)?;
    let ed_priv: [u8; 32] = ed_child.private_key().to_bytes().into();
    let ed_signing = ed25519_dalek::SigningKey::from_bytes(&ed_priv);
    let ed_verifying = ed_signing.verifying_key();
    let ed_pub_bytes = ed_verifying.to_bytes();

    // Format multibase public keys
    // Secp256k1 multicodec prefix: 0xe7 0x01
    let mut secp_multicodec = vec![0xe7, 0x01];
    secp_multicodec.extend_from_slice(secp_pub_bytes);
    let secp_multibase = format!("z{}", bs58::encode(secp_multicodec).into_string());

    // Ed25519 multicodec prefix: 0xed 0x01
    let mut ed_multicodec = vec![0xed, 0x01];
    ed_multicodec.extend_from_slice(&ed_pub_bytes);
    let ed_multibase = format!("z{}", bs58::encode(ed_multicodec).into_string());

    let secp_did_key = to_peer_did_key_format(&secp_multibase);
    let ed_did_key = to_peer_did_key_format(&ed_multibase);

    // Build the did:peer:2 DID string containing both keys
    let did_uri = format!("did:peer:2.{}.{}", secp_did_key, ed_did_key);
    println!("📝 Generated DID URI: {did_uri}");

    // Register via RPC
    println!("📡 Registering DID on-chain via RPC: {}...", args.rpc_url);
    let client = reqwest::Client::new();
    let rpc_body = json!({
        "jsonrpc": "2.0",
        "method": "sovereign_registerDid",
        "params": [did_uri],
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
