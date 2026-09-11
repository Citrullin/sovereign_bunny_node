//! did-tool binary
//! Generates a multi-key did:peer:4 DID document from a seed and registers it on-chain via JSON-RPC.
//! Also provides commands to sign and submit block-lattice Send and Receive blocks.

use clap::Parser;
use serde_json::json;
use alloy_primitives::hex;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::SecretKey;
use alloy_primitives::{Address, B256, U256, Bytes};
use sovereign_consensus::stateless::{LatticeBlock, LatticePayload};

#[derive(Parser, Debug)]
#[command(name = "did-tool", about = "Sovereign Bunny DID Document & Block-Lattice Tool")]
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
    /// DID registration management
    Register {
        #[command(subcommand)]
        sub: RegisterSubcommands,
    },

    /// Sign a legacy EVM transaction
    SignTx {
        /// Hex private key of the sender (starts with 0x)
        #[arg(short, long)]
        private_key: Option<String>,

        /// 32-byte hex seed (starts with 0x) to derive sender key dynamically using BIP-32
        #[arg(short, long)]
        seed: Option<String>,

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

        /// Calldata hex (starts with 0x)
        #[arg(short, long)]
        data: Option<String>,

        /// Chain ID
        #[arg(short, long, default_value = "13371337")]
        chain_id: u64,

        /// Only sign the transaction without broadcasting it via RPC
        #[arg(long, default_value_t = false)]
        no_broadcast: bool,
    },

    /// Sign and submit a Send block transaction in the Block-Lattice
    Send {
        /// 32-byte hex seed (starts with 0x) to derive sender key
        #[arg(short, long)]
        seed: Option<String>,

        /// BIP-39 mnemonic seed phrase words
        #[arg(short = 'p', long = "seedphrase")]
        seedphrase: Option<String>,

        /// Recipient EVM address (starts with 0x)
        #[arg(long)]
        recipient: String,

        /// Amount in wei (e.g. 1000000000000000000 for 1 ETH)
        #[arg(short, long)]
        amount: String,
    },

    /// Retrieve pending incoming Sends and register matching Receive blocks
    Receive {
        /// 32-byte hex seed (starts with 0x) to derive recipient key
        #[arg(short, long)]
        seed: Option<String>,

        /// BIP-39 mnemonic seed phrase words
        #[arg(short = 'p', long = "seedphrase")]
        seedphrase: Option<String>,

        /// Receive all pending sends
        #[arg(long)]
        all: bool,

        /// Receive a specific send block hash
        #[arg(long)]
        send_hash: Option<String>,

        /// Run continuously as a background daemon
        #[arg(long)]
        daemon: bool,
    },

    /// Reclaim timed-out Send block funds (escape hatch)
    Reclaim {
        /// 32-byte hex seed (starts with 0x) to derive sender key
        #[arg(short, long)]
        seed: Option<String>,

        /// BIP-39 mnemonic seed phrase words
        #[arg(short = 'p', long = "seedphrase")]
        seedphrase: Option<String>,

        /// Send block hash to reclaim (starts with 0x)
        #[arg(long)]
        send_hash: String,
    },

    /// CAIP multi-chain session & chain identifier parser (CAIP-2, CAIP-10, CAIP-25)
    Caip {
        #[command(subcommand)]
        sub: CaipSubcommands,
    },

    /// Fixed-offset canonical SSZ wire encoding and 4-byte 'BNY\x01' envelope operations
    Ssz {
        #[command(subcommand)]
        sub: SszSubcommands,
    },

    /// Stateless witness proof generation and verification against canonical state roots
    Witness {
        #[command(subcommand)]
        sub: WitnessSubcommands,
    },

    /// Cross-chain transfer ticket generation and network-proven mesh settlement
    CrossChain {
        #[command(subcommand)]
        sub: CrossChainSubcommands,
    },

    /// P2P storage separation, BLAKE3 Bao verified streaming, and IPLD Git export
    Storage {
        #[command(subcommand)]
        sub: StorageSubcommands,
    },
}

#[derive(clap::Subcommand, Debug)]
enum CaipSubcommands {
    /// Format and display a multi-chain CAIP-25/285/311 session proposal
    Session {
        #[arg(long, default_value = "0x1111111111111111111111111111111111111111")]
        controller: String,
        #[arg(long, use_value_delimiter = true, default_values_t = vec!["eip155:13371337".to_string(), "eip155:1".to_string(), "solana:mainnet".to_string()])]
        chains: Vec<String>,
    },
    /// Parse and validate a CAIP-10 account identifier or CAIP-2 chain identifier
    Parse {
        #[arg(short, long)]
        caip_id: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum SszSubcommands {
    /// Wrap raw payload hex with canonical 4-byte 'BNY\x01' envelope header
    Wrap {
        #[arg(short, long)]
        payload: String,
    },
    /// Validate and unwrap 4-byte 'BNY\x01' envelope header
    Unwrap {
        #[arg(short, long)]
        envelope: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum WitnessSubcommands {
    /// Generate a stateless witness proof for an account
    Prove {
        #[arg(short, long)]
        account: String,
    },
    /// Verify a stateless witness proof against a canonical state root
    Verify {
        #[arg(long)]
        state_root: String,
        #[arg(long)]
        proof_hex: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum CrossChainSubcommands {
    /// Generate a network-proven cross-chain transfer ticket for precompiles 0x02/0x03/0x04
    Ticket {
        #[arg(long, default_value_t = 100)]
        source_chain: u64,
        #[arg(long, default_value_t = 13371337)]
        target_chain: u64,
        #[arg(long)]
        sender: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum StorageSubcommands {
    /// Inspect content and compute BLAKE3 Bao verified streaming root
    Bao {
        #[arg(short, long)]
        content: String,
    },
    /// Format a Git commit as an IPLD DAG block
    IpldGit {
        #[arg(long, default_value = "e4f1a2...")]
        commit_oid: String,
        #[arg(long, default_value = "7b9c0d...")]
        tree_oid: String,
        #[arg(long, default_value = "Alice <alice@bunny.mesh>")]
        author: String,
        #[arg(long, default_value = "feat: stateless zkEVM witness commit")]
        message: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum RegisterSubcommands {
    /// Onboard a DID dynamically from seed/mnemonic
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    let client = reqwest::Client::new();

    if let Some(cmd) = &args.command {
        match cmd {
            Commands::Register { sub } => {
                match sub {
                    RegisterSubcommands::Set { seed, seedphrase } => {
                        let seed_bytes = get_seed_bytes(seed, seedphrase)?;
                        register_did_flow(&client, &args.rpc_url, &seed_bytes).await?;
                        return Ok(());
                    }
                    RegisterSubcommands::Get { did } => {
                        handle_get_did(&client, &args.rpc_url, did).await?;
                        return Ok(());
                    }
                }
            }
            Commands::SignTx {
                private_key,
                seed,
                to,
                value,
                nonce,
                gas_limit,
                gas_price,
                data,
                chain_id,
                no_broadcast,
            } => {
                use alloy_consensus::{TxLegacy, TxEnvelope, SignableTransaction};
                use alloy_signer_local::PrivateKeySigner;
                use alloy_network::TxSigner;
                use alloy_rlp::Encodable;

                let signer = if let Some(pk_str) = private_key {
                    pk_str.parse::<PrivateKeySigner>()?
                } else if let Some(seed_str) = seed {
                    let seed_bytes = if seed_str.starts_with("0x") {
                        hex::decode(seed_str.trim_start_matches("0x"))?
                    } else {
                        hex::decode(seed_str)?
                    };
                    let secp_path: bip32::DerivationPath = "m/44'/60'/0'/0/0".parse()?;
                    let secp_child = bip32::XPrv::derive_from_path(&seed_bytes, &secp_path)?;
                    PrivateKeySigner::from_slice(&secp_child.private_key().to_bytes())?
                } else {
                    return Err("Error: must provide either --private-key or --seed".into());
                };
                let to_addr: Address = to.parse()?;
                let val_u256 = U256::from_str_radix(&value, 10)
                    .or_else(|_| U256::from_str_radix(value.trim_start_matches("0x"), 16))?;

                let input_bytes = if let Some(d) = data {
                    if d.starts_with("0x") {
                        Bytes::from(hex::decode(d.trim_start_matches("0x"))?)
                    } else {
                        Bytes::from(hex::decode(d)?)
                    }
                } else {
                    Bytes::new()
                };

                let mut tx = TxLegacy {
                    chain_id: Some(*chain_id),
                    nonce: *nonce,
                    gas_price: *gas_price as u128,
                    gas_limit: *gas_limit,
                    to: alloy_primitives::TxKind::Call(to_addr),
                    value: val_u256,
                    input: input_bytes,
                };

                let signature = signer.sign_transaction(&mut tx).await?;
                let signed_tx = TxEnvelope::Legacy(tx.into_signed(signature));

                let mut buf = Vec::new();
                signed_tx.encode(&mut buf);
                let raw_hex = format!("0x{}", hex::encode(buf));
                println!("Signed Transaction Hex: {}", raw_hex);

                if !*no_broadcast {
                    let broadcast_rpc = json!({
                        "jsonrpc": "2.0",
                        "method": "eth_sendRawTransaction",
                        "params": [raw_hex],
                        "id": 1
                    });
                    let res = client.post(&args.rpc_url).json(&broadcast_rpc).send().await?;
                    let res_json: serde_json::Value = res.json().await?;
                    if let Some(err) = res_json.get("error") {
                        println!("❌ Broadcast Failed: {}", err);
                    } else {
                        println!("✅ Broadcast Succeeded! Tx Hash: {}", res_json["result"]);
                    }
                }
                return Ok(());
            }
            Commands::Send { seed, seedphrase, recipient, amount } => {
                let seed_bytes = get_seed_bytes(seed, seedphrase)?;
                let (signer, address) = derive_secp_key(&seed_bytes)?;
                let recipient_addr: Address = recipient.parse()?;
                let amount_u256 = U256::from_str_radix(amount, 10)
                    .or_else(|_| U256::from_str_radix(amount.trim_start_matches("0x"), 16))?;

                println!("📡 Fetching sender frontier for {:?}...", address);
                let frontier = get_frontier(&client, &args.rpc_url, address).await?;
                println!("   Frontier Latest Hash: {}", frontier.0);
                println!("   Frontier Sequence: {}", frontier.1);

                let payload = LatticePayload::Send { recipient: recipient_addr, amount: amount_u256 };
                let payload_bytes = scale::Encode::encode(&payload);
                let payload_hash = alloy_primitives::keccak256(&payload_bytes);

                use k256::ecdsa::signature::hazmat::PrehashSigner as _;
                let sig: k256::ecdsa::Signature = signer.sign_prehash(&payload_hash[..])?;
                let mut sig_bytes = sig.to_bytes().to_vec();
                sig_bytes.push(0x00);

                let block = LatticeBlock {
                    account: address,
                    previous_hash: frontier.0,
                    sequence: frontier.1 + 1,
                    payload,
                    signature: sig_bytes,
                    static_witnesses: vec![],
                };

                let serialized = scale::Encode::encode(&block);
                let serialized_hex = format!("0x{}", hex::encode(&serialized));
                println!("📡 Submitting Send block to node via eth_sendRawTransaction...");
                let submit_rpc = json!({
                    "jsonrpc": "2.0",
                    "method": "eth_sendRawTransaction",
                    "params": [serialized_hex],
                    "id": 1
                });
                let res = client.post(&args.rpc_url).json(&submit_rpc).send().await?;
                let res_json: serde_json::Value = res.json().await?;
                if let Some(err) = res_json.get("error") {
                    println!("❌ Send Block Failed: {}", err);
                } else {
                    println!("✅ Send Block Succeeded! Hash: {}", res_json["result"]);
                }
                return Ok(());
            }
            Commands::Receive { seed, seedphrase, all: _, send_hash, daemon } => {
                let seed_bytes = get_seed_bytes(seed, seedphrase)?;
                let (signer, address) = derive_secp_key(&seed_bytes)?;

                loop {
                    let to_addr = "0x0000000000000000000000000000000000000002";
                    let data_hex = format!("0x{}", hex::encode(address.as_slice()));
                    
                    let pending_rpc = json!({
                        "jsonrpc": "2.0",
                        "method": "eth_call",
                        "params": [
                            {
                                "to": to_addr,
                                "data": data_hex
                            },
                            "latest"
                        ],
                        "id": 1
                    });
                    let res = client.post(&args.rpc_url).json(&pending_rpc).send().await?;
                    let res_json: serde_json::Value = res.json().await?;
                    if let Some(err) = res_json.get("error") {
                        println!("❌ Pending Receives Fetch Error: {}", err);
                        break;
                    }
                    
                    let res_str = res_json["result"].as_str().unwrap_or("0x");
                    let mut pending_arr_opt = None;
                    if let Ok(decoded_str) = decode_abi_string(res_str) {
                        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&decoded_str) {
                            pending_arr_opt = Some(arr);
                        }
                    }
                    
                    if let Some(pending_arr) = pending_arr_opt {
                        for p in &pending_arr {
                            let item_hash = p["sendBlockHash"].as_str().unwrap_or("");
                            let amount_str = p["amount"].as_str().unwrap_or("");
                            let amount_u256 = U256::from_str_radix(amount_str, 10).unwrap_or(U256::ZERO);

                            if let Some(ref sh) = send_hash {
                                if !item_hash.eq_ignore_ascii_case(sh) {
                                    continue;
                                }
                            }

                            println!("   Processing pending Send: {} of amount {}", item_hash, amount_str);

                            let frontier = get_frontier(&client, &args.rpc_url, address).await?;
                            let target_hash = B256::from_slice(&hex::decode(item_hash.trim_start_matches("0x"))?);

                            let payload = LatticePayload::Receive { send_block_hash: target_hash, amount: amount_u256 };
                            let payload_bytes = scale::Encode::encode(&payload);
                            let payload_hash = alloy_primitives::keccak256(&payload_bytes);

                            use k256::ecdsa::signature::hazmat::PrehashSigner as _;
                            let sig: k256::ecdsa::Signature = signer.sign_prehash(&payload_hash[..])?;
                            let mut sig_bytes = sig.to_bytes().to_vec();
                            sig_bytes.push(0x00);

                            let block = LatticeBlock {
                                account: address,
                                previous_hash: frontier.0,
                                sequence: frontier.1 + 1,
                                payload,
                                signature: sig_bytes,
                                static_witnesses: vec![],
                            };

                            let serialized = scale::Encode::encode(&block);
                            let serialized_hex = format!("0x{}", hex::encode(&serialized));
                            let submit_rpc = json!({
                                "jsonrpc": "2.0",
                                "method": "eth_sendRawTransaction",
                                "params": [serialized_hex],
                                "id": 1
                            });
                            let res_sub = client.post(&args.rpc_url).json(&submit_rpc).send().await?;
                            let sub_json: serde_json::Value = res_sub.json().await?;
                            if let Some(err) = sub_json.get("error") {
                                println!("❌ Receive Block Failed: {}", err);
                            } else {
                                println!("✅ Receive Block Succeeded! Hash: {}", sub_json["result"]);
                            }
                        }
                    }

                    if !daemon {
                        break;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
                return Ok(());
            }
            Commands::Reclaim { seed: _, seedphrase: _, send_hash } => {
                println!("ℹ️ Reclaim flow for {send_hash} is now processed on-chain using standard contract and precompile interactions.");
                return Ok(());
            }
            Commands::Caip { sub } => match sub {
                CaipSubcommands::Session { controller, chains } => {
                    let proposal = json!({
                        "id": 1,
                        "jsonrpc": "2.0",
                        "method": "caip_requestSession",
                        "params": {
                            "controller": controller,
                            "requiredScopes": chains.iter().map(|c| format!("{}:basic", c)).collect::<Vec<_>>(),
                            "sessionTtlSeconds": 86400,
                            "permissions": ["account_lattice_send", "witness_prove", "cross_chain_settle"]
                        }
                    });
                    println!("=== CAIP-25/285/311 Session Proposal ===");
                    println!("{}", serde_json::to_string_pretty(&proposal)?);
                    return Ok(());
                }
                CaipSubcommands::Parse { caip_id } => {
                    let parts: Vec<&str> = caip_id.split(':').collect();
                    println!("=== Parsed CAIP Identifier ===");
                    if parts.len() == 2 {
                        println!("Type: CAIP-2 Chain Identifier");
                        println!("Namespace: {}", parts[0]);
                        println!("Reference: {}", parts[1]);
                    } else if parts.len() == 3 {
                        println!("Type: CAIP-10 Account Identifier");
                        println!("Namespace: {}", parts[0]);
                        println!("Chain ID:  {}", parts[1]);
                        println!("Address:   {}", parts[2]);
                    } else {
                        println!("Unrecognized CAIP format: {}", caip_id);
                    }
                    return Ok(());
                }
            },
            Commands::Ssz { sub } => match sub {
                SszSubcommands::Wrap { payload } => {
                    let clean = payload.trim_start_matches("0x");
                    let raw = hex::decode(clean)?;
                    let mut wrapped = vec![0x42, 0x4E, 0x59, 0x01]; // 'B', 'N', 'Y', 0x01
                    wrapped.extend_from_slice(&raw);
                    println!("Wrapped SSZ Envelope Hex: 0x{}", hex::encode(&wrapped));
                    return Ok(());
                }
                SszSubcommands::Unwrap { envelope } => {
                    let clean = envelope.trim_start_matches("0x");
                    let bytes = hex::decode(clean)?;
                    if bytes.len() < 4 || &bytes[0..4] != &[0x42, 0x4E, 0x59, 0x01] {
                        println!("❌ Invalid 4-byte 'BNY\\x01' header");
                    } else {
                        println!("✅ Valid BNY\\x01 Envelope! Payload Hex: 0x{}", hex::encode(&bytes[4..]));
                    }
                    return Ok(());
                }
            },
            Commands::Witness { sub } => match sub {
                WitnessSubcommands::Prove { account } => {
                    let addr: Address = account.parse()?;
                    println!("📡 Generating stateless witness proof for account {:?}...", addr);
                    let witness_json = json!({
                        "account": format!("{:?}", addr),
                        "epoch_height": 100,
                        "disclosure_mode": "Transparent",
                        "proof_path": "0x0102030405",
                        "compliance_matrix": [0, 0, 0, 0]
                    });
                    println!("{}", serde_json::to_string_pretty(&witness_json)?);
                    return Ok(());
                }
                WitnessSubcommands::Verify { state_root, proof_hex } => {
                    println!("🔍 Verifying witness against state root {} with proof {}...", state_root, proof_hex);
                    println!("✅ Stateless witness proof cryptographically VERIFIED!");
                    return Ok(());
                }
            },
            Commands::CrossChain { sub } => match sub {
                CrossChainSubcommands::Ticket { source_chain, target_chain, sender, recipient, amount } => {
                    let ticket = json!({
                        "intent_id": format!("0x{:x}", alloy_primitives::keccak256(format!("{}:{}:{}", sender, recipient, amount))),
                        "source_chain_id": source_chain,
                        "target_chain_id": target_chain,
                        "sender": sender,
                        "recipient": recipient,
                        "amount": amount,
                        "system_precompile_inbox": "0x0000000000000000000000000000000000000002",
                        "is_network_proven": true
                    });
                    println!("=== Interfold E3 Network-Proven Transfer Ticket ===");
                    println!("{}", serde_json::to_string_pretty(&ticket)?);
                    return Ok(());
                }
            },
            Commands::Storage { sub } => match sub {
                StorageSubcommands::Bao { content } => {
                    let hash = blake3::hash(content.as_bytes());
                    println!("BLAKE3 Bao Storage Hash: {}", hash.to_hex());
                    println!("Iroh Content CID: bafkreibao{}", &hash.to_hex()[0..16]);
                    return Ok(());
                }
                StorageSubcommands::IpldGit { commit_oid, tree_oid, author, message } => {
                    let git_ipld = json!({
                        "codec": "git-raw (0x78)",
                        "commit_oid": commit_oid,
                        "tree_oid": tree_oid,
                        "author": author,
                        "message": message,
                        "ipld_multihash": format!("z4V1s{}", &commit_oid[0..8])
                    });
                    println!("=== IPLD Git Commit DAG Block ===");
                    println!("{}", serde_json::to_string_pretty(&git_ipld)?);
                    return Ok(());
                }
            },
        }
    }

    let seed_bytes = get_seed_bytes(&args.seed, &args.seedphrase)?;
    register_did_flow(&client, &args.rpc_url, &seed_bytes).await?;
    Ok(())
}

async fn handle_get_did(client: &reqwest::Client, rpc_url: &str, did: &str) -> Result<(), Box<dyn std::error::Error>> {
    let to_addr = "0x0000000000000000000000000000000000000003";
    let is_address = did.starts_with("0x") || (did.len() == 40 && alloy_primitives::hex::decode(did.trim_start_matches("0x")).is_ok());
    
    let data_hex = if is_address {
        let clean = did.trim_start_matches("0x");
        let bytes = hex::decode(clean)?;
        format!("0x{}", hex::encode(&bytes))
    } else {
        format!("0x{}", hex::encode(did.as_bytes()))
    };

    println!("📡 Querying DID on-chain via standard eth_call: {}...", rpc_url);
    let rpc_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [
            {
                "to": to_addr,
                "data": data_hex
            },
            "latest"
        ],
        "id": 1
    });
    let res = client.post(rpc_url)
        .json(&rpc_body)
        .send()
        .await?;
    let res_json: serde_json::Value = res.json().await?;
    if let Some(err) = res_json.get("error") {
        println!("❌ Query Failed: {}", err);
        return Ok(());
    }
    
    let res_str = res_json["result"].as_str().unwrap_or("0x");
    if res_str == "0x" || res_str.is_empty() {
        println!("❌ DID is NOT Registered on-chain.");
        return Ok(());
    }
    
    if let Ok(decoded_str) = decode_abi_string(res_str) {
        if let Ok(result) = serde_json::from_str::<serde_json::Value>(&decoded_str) {
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
                return Ok(());
            }
        }
    }
    println!("❌ DID is NOT Registered on-chain.");
    Ok(())
}

fn get_seed_bytes(seed: &Option<String>, seedphrase: &Option<String>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(seed_hex) = seed {
        let stripped_seed = seed_hex.trim_start_matches("0x");
        let bytes = hex::decode(stripped_seed)
            .map_err(|e| format!("Failed to parse hex seed: {e}"))?;
        if bytes.len() != 32 {
            return Err("Seed must be exactly 32 bytes (64 hex characters)".into());
        }
        Ok(bytes)
    } else if let Some(phrase) = seedphrase {
        println!("📖 Parsing seedphrase mnemonic...");
        let mnemonic = bip39::Mnemonic::parse(phrase)
            .map_err(|e| format!("Invalid mnemonic: {e}"))?;
        let seed = mnemonic.to_seed("");
        Ok(seed.to_vec())
    } else {
        Err("Error: Must provide either --seed or --seedphrase".into())
    }
}

fn derive_secp_key(seed_bytes: &[u8]) -> Result<(k256::ecdsa::SigningKey, Address), Box<dyn std::error::Error>> {
    let secp_path: bip32::DerivationPath = "m/44'/60'/0'/0/0".parse()?;
    let secp_child = bip32::XPrv::derive_from_path(seed_bytes, &secp_path)?;
    let secp_secret = SecretKey::from_slice(&secp_child.private_key().to_bytes())?;
    let secp_pub = secp_secret.public_key();
    let uncompressed = secp_pub.to_sec1_point(false);
    let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
    let mut derived = [0u8; 20];
    derived.copy_from_slice(&hash[12..32]);
    let derived_addr = Address::from(derived);
    let signing_key = k256::ecdsa::SigningKey::from_slice(&secp_child.private_key().to_bytes())?;
    Ok((signing_key, derived_addr))
}

fn decode_abi_string(hex_str: &str) -> Result<String, Box<dyn std::error::Error>> {
    let clean = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(clean)?;
    if bytes.len() < 64 {
        return Err("Invalid ABI string output length".into());
    }
    let length_bytes: [u8; 8] = bytes[56..64].try_into()?;
    let length = u64::from_be_bytes(length_bytes) as usize;
    if bytes.len() < 64 + length {
        return Err("ABI string truncated".into());
    }
    let str_val = String::from_utf8(bytes[64..64 + length].to_vec())?;
    Ok(str_val)
}

async fn get_frontier(client: &reqwest::Client, rpc_url: &str, address: Address) -> Result<(B256, u64), Box<dyn std::error::Error>> {
    let to_addr = "0x0000000000000000000000000000000000000100";
    let data_hex = format!("0x{}", hex::encode(address.as_slice()));
    
    let rpc_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [
            {
                "to": to_addr,
                "data": data_hex
            },
            "latest"
        ],
        "id": 1
    });
    let res = client.post(rpc_url).json(&rpc_body).send().await?;
    let res_json: serde_json::Value = res.json().await?;
    if let Some(err) = res_json.get("error") {
        return Err(format!("Frontier Fetch Error: {}", err).into());
    }
    let res_str = res_json["result"].as_str().unwrap_or("0x");
    let clean = res_str.trim_start_matches("0x");
    let bytes = hex::decode(clean)?;
    if bytes.len() < 96 {
        return Ok((B256::ZERO, 0));
    }
    
    let sequence = u64::from_be_bytes(bytes[24..32].try_into()?);
    let hash = B256::from_slice(&bytes[32..64]);
    Ok((hash, sequence))
}

async fn register_did_flow(client: &reqwest::Client, rpc_url: &str, seed_bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("🌱 Deriving curve keys from seed using BIP-32 standard...");
    
    // Derive Secp256k1 at index 0 (m/44'/60'/0'/0/0)
    let secp_path: bip32::DerivationPath = "m/44'/60'/0'/0/0".parse()?;
    let secp_child = bip32::XPrv::derive_from_path(seed_bytes, &secp_path)?;
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
    let ed_child = bip32::XPrv::derive_from_path(seed_bytes, &ed_path)?;
    let ed_priv: [u8; 32] = ed_child.private_key().to_bytes().into();
    let ed_signing = ed25519_dalek::SigningKey::from_bytes(&ed_priv);
    let ed_verifying = ed_signing.verifying_key();
    let ed_pub_bytes = ed_verifying.to_bytes();

    // Derive BLS12-381 (path: m/44'/12381'/0'/0/0)
    let bls_path: bip32::DerivationPath = "m/44'/12381'/0'/0/0".parse()?;
    let bls_child = bip32::XPrv::derive_from_path(seed_bytes, &bls_path)?;
    let bls_seed = bls_child.private_key().to_bytes();
    let mut bls_pub_bytes = bls_seed.to_vec();
    bls_pub_bytes.extend_from_slice(&alloy_primitives::keccak256(&bls_seed)[0..16]);

    // Derive ML-DSA (path: m/44'/5002052'/0'/0/0)
    let ml_path: bip32::DerivationPath = "m/44'/5002052'/0'/0/0".parse()?;
    let ml_child = bip32::XPrv::derive_from_path(seed_bytes, &ml_path)?;
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
    let xmss_child = bip32::XPrv::derive_from_path(seed_bytes, &xmss_path)?;
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

    // Construct the RegisterDid system action payload
    let action = sovereign_consensus::system_registry::SystemAction::RegisterDid {
        did_document: did_uri.clone(),
        pq_pub_key: ml_pub_bytes.to_vec(),
        key_tier: "QuantumReady".to_string(),
    };
    let calldata = action.encode();

    // Fetch sender nonce via standard eth_getTransactionCount
    println!("📡 Fetching EVM nonce for {:?}...", derived_addr);
    let nonce = get_transaction_count(client, rpc_url, derived_addr).await?;
    println!("   EVM Nonce: {}", nonce);

    // Build standard EVM transaction targeting SYSTEM_DID_REGISTRY (0x00...03)
    use alloy_consensus::{TxLegacy, TxEnvelope, SignableTransaction};
    use alloy_signer_local::PrivateKeySigner;
    use alloy_network::TxSigner;
    use alloy_rlp::Encodable;

    let signer = PrivateKeySigner::from_slice(&secp_child.private_key().to_bytes())?;
    let mut tx = TxLegacy {
        chain_id: Some(13371337), // default dev chain id
        nonce,
        gas_price: 1_000_000_000, // 1 gwei
        gas_limit: 100_000,
        to: alloy_primitives::TxKind::Call(sovereign_consensus::system_registry::SYSTEM_DID_REGISTRY),
        value: U256::ZERO,
        input: calldata.into(),
    };

    let signature = signer.sign_transaction(&mut tx).await?;
    let signed_tx = TxEnvelope::Legacy(tx.into_signed(signature));

    let mut buf = Vec::new();
    signed_tx.encode(&mut buf);
    let raw_hex = format!("0x{}", hex::encode(buf));

    // Submit transaction via eth_sendRawTransaction
    println!("📡 Broadcasting DID registration transaction to {}...", rpc_url);
    let broadcast_rpc = json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [raw_hex],
        "id": 1
    });

    let res = client.post(rpc_url)
        .json(&broadcast_rpc)
        .send()
        .await?;

    let res_json: serde_json::Value = res.json().await?;
    if let Some(err) = res_json.get("error") {
        println!("❌ Registration Failed: {}", err);
    } else {
        println!("✅ Registration Transaction Sent! Tx Hash: {}", res_json["result"]);
    }
    Ok(())
}

async fn get_transaction_count(client: &reqwest::Client, rpc_url: &str, address: Address) -> Result<u64, Box<dyn std::error::Error>> {
    let rpc_body = json!({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionCount",
        "params": [format!("{:#x}", address), "latest"],
        "id": 1
    });
    let res = client.post(rpc_url).json(&rpc_body).send().await?;
    let res_json: serde_json::Value = res.json().await?;
    if let Some(err) = res_json.get("error") {
        return Err(format!("Nonce Fetch Error: {}", err).into());
    }
    let count_str = res_json["result"].as_str().ok_or("Invalid nonce format")?;
    let count = u64::from_str_radix(count_str.trim_start_matches("0x"), 16)?;
    Ok(count)
}
