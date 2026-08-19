use wasm_bindgen::prelude::*;
use alloy_consensus::{TxLegacy, TxEnvelope, SignableTransaction};
use alloy_primitives::{Address, B256, U256, Bytes};
use alloy_signer_local::PrivateKeySigner;
use alloy_network::TxSigner;
use alloy_rlp::Encodable;
use fips204::traits::KeyGen;
use bip32::{XPrv, DerivationPath};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum LatticePayload {
    Send {
        recipient: Address,
        amount: U256,
    },
    Receive {
        send_block_hash: B256,
        amount: U256,
    },
}

impl scale::Encode for LatticePayload {
    fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
        match self {
            LatticePayload::Send { recipient, amount } => {
                0u8.encode_to(dest);
                recipient.0.encode_to(dest);
                amount.to_be_bytes::<32>().encode_to(dest);
            }
            LatticePayload::Receive { send_block_hash, amount } => {
                1u8.encode_to(dest);
                send_block_hash.0.encode_to(dest);
                amount.to_be_bytes::<32>().encode_to(dest);
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct LatticeBlock {
    pub account: Address,
    pub previous_hash: B256,
    pub sequence: u64,
    pub payload: LatticePayload,
    pub signature: Vec<u8>,
    pub static_witnesses: Vec<Vec<u8>>,
}

impl scale::Encode for LatticeBlock {
    fn encode_to<T: scale::Output + ?Sized>(&self, dest: &mut T) {
        self.account.0.encode_to(dest);
        self.previous_hash.0.encode_to(dest);
        self.sequence.encode_to(dest);
        self.payload.encode_to(dest);
        self.signature.encode_to(dest);
        self.static_witnesses.encode_to(dest);
    }
}

fn derive_secp_key(seed: &[u8]) -> Result<PrivateKeySigner, String> {
    let secp_path: DerivationPath = "m/44'/60'/0'/0/0".parse().map_err(|e: bip32::Error| e.to_string())?;
    let secp_child = XPrv::derive_from_path(seed, &secp_path).map_err(|e: bip32::Error| e.to_string())?;
    let signer = PrivateKeySigner::from_slice(&secp_child.private_key().to_bytes()).map_err(|e| e.to_string())?;
    Ok(signer)
}

#[wasm_bindgen]
pub async fn sign_evm_transaction(
    seed: &[u8],
    to_hex: &str,
    value_str: &str,
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
    chain_id: u64,
) -> Result<String, JsValue> {
    let signer = derive_secp_key(seed).map_err(|e| JsValue::from_str(&e))?;
    let to_addr: Address = to_hex.parse().map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let val_u256 = U256::from_str_radix(value_str, 10)
        .or_else(|_| U256::from_str_radix(value_str.trim_start_matches("0x"), 16))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: gas_price as u128,
        gas_limit,
        to: alloy_primitives::TxKind::Call(to_addr),
        value: val_u256,
        input: Bytes::new(),
    };

    let signature = signer.sign_transaction(&mut tx).await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let signed_tx = TxEnvelope::Legacy(tx.into_signed(signature));

    let mut buf = Vec::new();
    signed_tx.encode(&mut buf);
    Ok(format!("0x{}", alloy_primitives::hex::encode(buf)))
}

fn sign_with_mldsa(seed: &[u8], payload_hash: &[u8]) -> Result<Vec<u8>, JsValue> {
    use fips204::traits::Signer;
    let mut ml_seed = [0u8; 32];
    if seed.len() >= 32 {
        ml_seed.copy_from_slice(&seed[0..32]);
    } else {
        ml_seed[..seed.len()].copy_from_slice(seed);
    }
    let (_, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&ml_seed);
    let sig = sk.try_sign(payload_hash, &[])
        .map_err(|_| JsValue::from_str("ML-DSA signature generation failed"))?;
    Ok(sig.to_vec())
}

#[wasm_bindgen]
pub fn sign_block_lattice_send(
    seed: &[u8],
    account_hex: &str,
    recipient_hex: &str,
    amount_str: &str,
    prev_hash_hex: &str,
    sequence: u64,
    secp_sig_hex: &str,
) -> Result<String, JsValue> {
    let address: Address = account_hex.parse().map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let recipient_addr: Address = recipient_hex.parse().map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let amount_u256 = U256::from_str_radix(amount_str, 10)
        .or_else(|_| U256::from_str_radix(amount_str.trim_start_matches("0x"), 16))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let prev_hash = B256::from_slice(&alloy_primitives::hex::decode(prev_hash_hex.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?);

    let payload = LatticePayload::Send {
        recipient: recipient_addr,
        amount: amount_u256,
    };
    let payload_bytes = scale::Encode::encode(&payload);
    let payload_hash = alloy_primitives::keccak256(&payload_bytes);

    let pq_sig = sign_with_mldsa(seed, payload_hash.as_slice())?;
    let sig_bytes = alloy_primitives::hex::decode(secp_sig_hex.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let block = LatticeBlock {
        account: address,
        previous_hash: prev_hash,
        sequence,
        payload,
        signature: sig_bytes,
        static_witnesses: vec![pq_sig],
    };

    let serialized = serde_json::to_string(&block)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serialized)
}

#[wasm_bindgen]
pub fn sign_block_lattice_receive(
    seed: &[u8],
    account_hex: &str,
    send_block_hash_hex: &str,
    amount_str: &str,
    prev_hash_hex: &str,
    sequence: u64,
    secp_sig_hex: &str,
) -> Result<String, JsValue> {
    let address: Address = account_hex.parse().map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let send_block_hash = B256::from_slice(&alloy_primitives::hex::decode(send_block_hash_hex.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?);
    let amount_u256 = U256::from_str_radix(amount_str, 10)
        .or_else(|_| U256::from_str_radix(amount_str.trim_start_matches("0x"), 16))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let prev_hash = B256::from_slice(&alloy_primitives::hex::decode(prev_hash_hex.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?);

    let payload = LatticePayload::Receive {
        send_block_hash,
        amount: amount_u256,
    };
    let payload_bytes = scale::Encode::encode(&payload);
    let payload_hash = alloy_primitives::keccak256(&payload_bytes);

    let pq_sig = sign_with_mldsa(seed, payload_hash.as_slice())?;
    let sig_bytes = alloy_primitives::hex::decode(secp_sig_hex.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let block = LatticeBlock {
        account: address,
        previous_hash: prev_hash,
        sequence,
        payload,
        signature: sig_bytes,
        static_witnesses: vec![pq_sig],
    };

    let serialized = serde_json::to_string(&block)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serialized)
}

#[wasm_bindgen]
pub fn sign_block_lattice_receive_hex(
    seed: &[u8],
    account_hex: &str,
    send_block_hash_hex: &str,
    amount_str: &str,
    prev_hash_hex: &str,
    sequence: u64,
    secp_sig_hex: &str,
) -> Result<String, JsValue> {
    let address: Address = account_hex.parse().map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let send_block_hash = B256::from_slice(&alloy_primitives::hex::decode(send_block_hash_hex.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?);
    let amount_u256 = U256::from_str_radix(amount_str, 10)
        .or_else(|_| U256::from_str_radix(amount_str.trim_start_matches("0x"), 16))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let prev_hash = B256::from_slice(&alloy_primitives::hex::decode(prev_hash_hex.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?);

    let payload = LatticePayload::Receive {
        send_block_hash,
        amount: amount_u256,
    };
    let payload_bytes = scale::Encode::encode(&payload);
    let payload_hash = alloy_primitives::keccak256(&payload_bytes);

    let pq_sig = sign_with_mldsa(seed, payload_hash.as_slice())?;
    let sig_bytes = alloy_primitives::hex::decode(secp_sig_hex.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let block = LatticeBlock {
        account: address,
        previous_hash: prev_hash,
        sequence,
        payload,
        signature: sig_bytes,
        static_witnesses: vec![pq_sig],
    };

    let serialized = scale::Encode::encode(&block);
    Ok(format!("0x{}", alloy_primitives::hex::encode(serialized)))
}

