use clap::Subcommand;
use alloy_primitives::{Address, B256};
use sovereign_identity::did::SovereignDidDocument;
use sovereign_identity::namespace::NamespaceRegistry;
use sovereign_ssz::{wrap_envelope, unwrap_envelope, range_key};

#[derive(Subcommand, Debug)]
pub enum DebugCommands {
    /// DID and namespace tools
    Did {
        #[command(subcommand)]
        sub: DidCommands,
    },
    /// Inspect or encode SSZ wire frames
    Ssz {
        #[command(subcommand)]
        sub: SszCommands,
    },
    /// Inspect storage chunks
    Storage {
        #[command(subcommand)]
        sub: StorageCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum DidCommands {
    /// Resolve a W3C DID string across 11 cryptographic and post-quantum curves
    Resolve {
        did: String,
    },
    /// Register a .bunny namespace with slot-based reputation
    RegisterName {
        did: String,
        name: String,
        #[arg(long, default_value_t = 1.0)]
        reputation: f64,
        #[arg(long, default_value_t = 0)]
        stake: u64,
    },
    /// Derive a master DID document from a seed
    Derive {
        seed_hex: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum SszCommands {
    /// Wrap a raw payload with the canonical 4-byte 'BNY\x01' envelope header
    Wrap {
        payload_hex: String,
    },
    /// Unwrap and validate the 4-byte envelope header
    Unwrap {
        envelope_hex: String,
    },
    /// Calculate the 16-bit partition range key for an EVM address
    RangeKey {
        address: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum StorageCommands {
    /// Calculate BLAKE3 Bao CID for a file or payload
    Inspect {
        payload: String,
    },
}

pub async fn run_debug(cmd: DebugCommands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        DebugCommands::Did { sub } => match sub {
            DidCommands::Resolve { did } => {
                println!("Resolving DID: {}", did);
                if let Some(doc) = SovereignDidDocument::from_did_string(&did) {
                    println!("✅ Resolved Sovereign DID Document:");
                    println!("  - DID URI:      {}", doc.did_uri);
                    println!("  - Short Form:   {}", doc.short_form);
                    println!("  - EVM Address:  {:?}", doc.evm_address);
                    println!("  - Secp256k1:    0x{}", hex::encode(&doc.secp256k1_pubkey));
                    println!("  - Ed25519:      0x{}", hex::encode(&doc.ed25519_pubkey));
                    println!("  - ML-DSA-65:    {} bytes (PQ FIPS-204)", doc.ml_dsa_pubkey.len());
                    println!("  - Falcon-512:   {} bytes (PQ)", doc.falcon_pubkey.len());
                    println!("  - SLH-DSA:      {} bytes (PQ FIPS-205)", doc.slh_dsa_pubkey.len());
                } else {
                    eprintln!("❌ Failed to parse DID URI: {}", did);
                }
                Ok(())
            }
            DidCommands::RegisterName { did, name, reputation, stake } => {
                let mut reg = NamespaceRegistry::new();
                let score = reg.calculate_score(&did, reputation, stake);
                let registered = reg.register(name.clone(), did.clone(), reputation, stake);
                println!("Namespace Registration for '{}.bunny':", name);
                println!("  - Owner DID:    {}", did);
                println!("  - Social Score: {:.2}", score);
                println!("  - Success:      {}", registered);
                Ok(())
            }
            DidCommands::Derive { seed_hex } => {
                let bytes = hex::decode(seed_hex.trim_start_matches("0x"))?;
                if bytes.len() < 32 {
                    return Err(format!("Seed hex must be at least 32 bytes (got {} bytes)", bytes.len()).into());
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes[..32]);
                let doc = SovereignDidDocument::derive_from_seed(B256::from_slice(&seed));
                println!("Derived Sovereign Master DID Document:");
                println!("  - DID URI:      {}", doc.did_uri);
                println!("  - EVM Address:  {:?}", doc.evm_address);
                Ok(())
            }
        },
        DebugCommands::Ssz { sub } => match sub {
            SszCommands::Wrap { payload_hex } => {
                let bytes = hex::decode(payload_hex.trim_start_matches("0x"))?;
                let wrapped = wrap_envelope(&bytes);
                println!("Wrapped SSZ Frame ({} bytes):", wrapped.len());
                println!("0x{}", hex::encode(&wrapped));
                Ok(())
            }
            SszCommands::Unwrap { envelope_hex } => {
                let bytes = hex::decode(envelope_hex.trim_start_matches("0x"))?;
                match unwrap_envelope(&bytes) {
                    Ok(payload) => {
                        println!("✅ Valid 'BNY' Envelope (Payload: {} bytes):", payload.len());
                        println!("0x{}", hex::encode(payload));
                    }
                    Err(e) => eprintln!("❌ Invalid envelope header: {}", e),
                }
                Ok(())
            }
            SszCommands::RangeKey { address } => {
                let bytes = hex::decode(address.trim_start_matches("0x"))?;
                if bytes.len() < 20 {
                    return Err(format!("Address hex must be at least 20 bytes (got {} bytes)", bytes.len()).into());
                }
                let addr = Address::from_slice(&bytes[..20]);
                let rk = range_key(&addr);
                println!("Address:   {:?}", addr);
                println!("Range Key: 0x{:04X} ({})", rk, rk);
                println!("Topic:     range-0x{:04X}", rk);
                Ok(())
            }
        },
        DebugCommands::Storage { sub } => match sub {
            StorageCommands::Inspect { payload } => {
                let hash = blake3::hash(payload.as_bytes());
                println!("BLAKE3 Bao Hash: 0x{}", hash.to_hex());
                println!("Iroh CID:        0x{}", hex::encode(hash.as_bytes()));
                Ok(())
            }
        },
    }
}
