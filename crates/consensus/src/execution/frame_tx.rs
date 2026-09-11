//! # EIP-8141 Frame Transactions & Universal Account-Lattice Bridge
//!
//! Implements multi-frame execution over the stateless Account-Lattice:
//! - **VERIFY Frame**: Read-only sandboxed pre-execution validating authorizations across
//!   any supported cryptographic curve (secp256k1, secp256r1/P-256 Passkeys, Ed25519, ML-DSA/Falcon).
//! - **PAYMASTER Frame**: Risk-sponsorship frame allowing third-party paymasters/exchanges to cover
//!   gas liability for legacy or non-quantum-registered users within their jurisdiction.
//! - **EIP-7702 DELEGATION Frame**: Temporary code delegation designations without address alteration.
//! - **EIP-7706 Multi-Dimensional Gas**: Orthogonal tracking of execution, witness/calldata, and blob gas.
//! - **EIP-7685 Execution Requests**: Structured asynchronous consensus requests emitted upon execution.
//! - **EXECUTE Frame**: Mutates the account's polymorphic register slot.

use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use sovereign_crypto::{verify_signature, SignatureScheme};

/// EIP-8141 Frame Transaction Type Indicator.
pub const EIP8141_TX_TYPE: u8 = 0x06;

/// EIP-7702 Code Delegation Authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip7702Delegation {
    pub chain_id: u64,
    pub delegate_code_address: Address,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

/// EIP-7706 Multi-Dimensional Gas Limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiDimGasLimit {
    /// Execution compute gas
    pub execution_gas: u64,
    /// Calldata and stateless witness bandwidth gas
    pub witness_calldata_gas: u64,
    /// Data availability and blob storage gas
    pub storage_gas: u64,
}

impl Default for MultiDimGasLimit {
    fn default() -> Self {
        Self {
            execution_gas: 100_000,
            witness_calldata_gas: 25_000,
            storage_gas: 0,
        }
    }
}

/// Paymaster Risk-Sponsorship Frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterRiskFrame {
    /// Sponsoring paymaster address
    pub paymaster: Address,
    /// Maximum fee budget sponsored
    pub max_cost: U256,
    /// Valid until epoch height
    pub valid_until_epoch: u64,
    /// Jurisdictional review / compliance tag (e.g. EU BaFin, US OFAC)
    pub jurisdiction_tag: String,
    /// Paymaster signature
    pub signature: Vec<u8>,
}

/// EIP-7685 Asynchronous Execution Request emitted to consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip7685Request {
    /// Request type indicator (e.g. 0x00: Deposit, 0x01: Withdrawal, 0x02: Slashing, 0x03: ShardSplit)
    pub request_type: u8,
    /// Encoded request payload
    pub request_data: Bytes,
}

/// EIP-8141 Universal Frame Transaction Envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameTransaction {
    /// Target sender smart account
    pub sender: Address,
    /// Destination contract recipient
    pub target: Address,
    /// Account nonce / sequence number
    pub nonce: u64,
    /// Target polymorphic register slot (default 0 for EVM)
    pub target_slot: u16,
    /// Max fee per gas
    pub max_fee_per_gas: U256,
    /// Max priority fee per gas
    pub max_priority_fee_per_gas: U256,
    /// Multi-dimensional gas allocation
    pub gas_limits: MultiDimGasLimit,
    /// Sandboxed VERIFY frame calldata
    pub verify_calldata: Bytes,
    /// Cryptographic signature scheme used in VERIFY frame (Secp256k1, Secp256r1, Ed25519, MlDsa, etc.)
    pub signature_scheme: u8,
    /// Public key bytes for verification
    pub public_key: Vec<u8>,
    /// Authorization signature bytes
    pub authorization_signature: Vec<u8>,
    /// Optional EIP-7702 code delegation frame
    pub delegation: Option<Eip7702Delegation>,
    /// Optional Paymaster sponsorship frame
    pub paymaster_frame: Option<PaymasterRiskFrame>,
    /// EXECUTE frame calldata
    pub execute_calldata: Bytes,
    /// Account state witness carrying the current account state tip
    pub state_witness: B256,
}

/// Result of executing an EIP-8141 VERIFY frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFrameResult {
    pub approved: bool,
    pub max_fee: U256,
    pub gas_used: u64,
    pub payer: Address,
    pub delegation_applied: Option<Address>,
}

/// Result of executing an EIP-8141 EXECUTE frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteFrameResult {
    pub success: bool,
    pub return_data: Bytes,
    pub gas_used: u64,
    pub new_state_tip: B256,
    pub execution_requests: Vec<Eip7685Request>,
}

/// Stateless EIP-8141 Multi-Frame Executor.
pub struct FrameExecutor;

impl FrameExecutor {
    /// Executes the sandboxed `VERIFY` frame in RAM.
    pub fn execute_verify_frame(
        tx: &FrameTransaction,
        expected_state_tip: B256,
    ) -> Result<VerifyFrameResult, &'static str> {
        if tx.state_witness != expected_state_tip {
            return Err("VERIFY Frame failed: State witness mismatch with account frontier tip");
        }

        // Determine fee payer (sender or sponsoring paymaster)
        let payer = if let Some(ref paymaster) = tx.paymaster_frame {
            // HIGH-03: Verify that the paymaster signature actually recovers to paymaster.paymaster
            // over a canonical commitment. An empty or trivial byte is no longer accepted.
            if paymaster.signature.len() != 65 {
                return Err("VERIFY Frame failed: Paymaster signature must be exactly 65 bytes");
            }

            // ECO-04: Reject expired paymaster frames.
            {
                let registry_lock = crate::registry::get_registry();
                if let Ok(reg) = registry_lock.read() {
                    if paymaster.valid_until_epoch < reg.current_epoch {
                        return Err("VERIFY Frame failed: Paymaster epoch authorization has expired");
                    }
                }
            }

            // Canonical commitment: keccak256(paymaster_addr || sender || max_cost_be32 || valid_until_epoch_be8)
            let mut commitment_buf = Vec::with_capacity(20 + 20 + 32 + 8);
            commitment_buf.extend_from_slice(paymaster.paymaster.as_slice());
            commitment_buf.extend_from_slice(tx.sender.as_slice());
            commitment_buf.extend_from_slice(&paymaster.max_cost.to_be_bytes::<32>());
            commitment_buf.extend_from_slice(&paymaster.valid_until_epoch.to_be_bytes());
            let commitment_hash = alloy_primitives::keccak256(&commitment_buf);

            // Recover the signer from the 65-byte ECDSA signature.
            let sig_bytes = &paymaster.signature;
            let recid = sig_bytes[64] % 4;
            let rec_id = k256::ecdsa::RecoveryId::try_from(recid)
                .map_err(|_| "VERIFY Frame failed: Invalid paymaster signature recovery id")?;
            let sig_raw = k256::ecdsa::Signature::from_slice(&sig_bytes[..64])
                .map_err(|_| "VERIFY Frame failed: Malformed paymaster signature bytes")?;
            let recovered_vk = k256::ecdsa::VerifyingKey::recover_from_prehash(
                commitment_hash.as_slice(),
                &sig_raw,
                rec_id,
            ).map_err(|_| "VERIFY Frame failed: Paymaster signature recovery failed")?;
            let sec1 = recovered_vk.to_sec1_point(false);
            let rec_hash = alloy_primitives::keccak256(&sec1.as_bytes()[1..]);
            let recovered_addr = Address::from_slice(&rec_hash[12..]);

            if recovered_addr != paymaster.paymaster {
                return Err("VERIFY Frame failed: Paymaster signature does not recover to paymaster address");
            }

            paymaster.paymaster
        } else {
            tx.sender
        };

        // If authorization signature is present, verify against sovereign-crypto curve
        if !tx.authorization_signature.is_empty() && !tx.public_key.is_empty() {
            let scheme = match tx.signature_scheme {
                0 => SignatureScheme::Secp256k1,
                1 => SignatureScheme::Secp256r1,
                2 => SignatureScheme::Ed25519,
                3 => SignatureScheme::MlDsa,
                4 => SignatureScheme::Falcon,
                _ => SignatureScheme::Secp256k1,
            };

            let msg = tx.state_witness;
            if verify_signature(scheme, &tx.public_key, msg.as_slice(), &tx.authorization_signature, false).is_err() {
                return Err("VERIFY Frame failed: Multi-curve signature verification rejected");
            }
        }

        let delegation_applied = tx.delegation.as_ref().map(|d| d.delegate_code_address);
        let total_gas = tx.gas_limits.execution_gas + tx.gas_limits.witness_calldata_gas;
        let max_fee = tx.max_fee_per_gas * U256::from(total_gas);

        Ok(VerifyFrameResult {
            approved: true,
            max_fee,
            gas_used: 21_000,
            payer,
            delegation_applied,
        })
    }

    /// Executes the `EXECUTE` frame after successful verification.
    pub fn execute_payload_frame(
        tx: &FrameTransaction,
        current_state_tip: B256,
    ) -> Result<ExecuteFrameResult, &'static str> {
        let mut hasher = k256::sha2::Sha256::new();
        use k256::sha2::Digest;
        hasher.update(current_state_tip.as_slice());
        hasher.update(tx.sender.as_slice());
        hasher.update(tx.target.as_slice());
        hasher.update(&tx.nonce.to_be_bytes());
        hasher.update(&tx.target_slot.to_le_bytes());
        hasher.update(&tx.execute_calldata);
        let new_state_tip = B256::from_slice(&hasher.finalize());

        // Emit EIP-7685 execution request if executing a staking or cross-chain action
        let mut requests = Vec::new();
        if !tx.execute_calldata.is_empty() && tx.execute_calldata[0] == 0xff {
            requests.push(Eip7685Request {
                request_type: 0x01, // Withdrawal / Settle
                request_data: tx.execute_calldata.clone(),
            });
        }

        Ok(ExecuteFrameResult {
            success: true,
            return_data: Bytes::from(b"EIP8141_EXEC_SUCCESS".to_vec()),
            gas_used: 45_000,
            new_state_tip,
            execution_requests: requests,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_tx_verify_and_execute_lifecycle() {
        let state_tip = B256::repeat_byte(0x11);
        let tx = FrameTransaction {
            sender: Address::repeat_byte(0x01),
            target: Address::repeat_byte(0x02),
            nonce: 0,
            target_slot: 0,
            max_fee_per_gas: U256::from(100),
            max_priority_fee_per_gas: U256::from(10),
            gas_limits: MultiDimGasLimit::default(),
            verify_calldata: Bytes::from(vec![0x01]),
            signature_scheme: 0,
            public_key: Vec::new(),
            authorization_signature: Vec::new(),
            delegation: None,
            paymaster_frame: None,
            execute_calldata: Bytes::from(vec![0x12, 0x34]),
            state_witness: state_tip,
        };

        let verify_res = FrameExecutor::execute_verify_frame(&tx, state_tip).unwrap();
        assert!(verify_res.approved);
        assert_eq!(verify_res.payer, tx.sender);

        let exec_res = FrameExecutor::execute_payload_frame(&tx, state_tip).unwrap();
        assert!(exec_res.success);
        assert_ne!(exec_res.new_state_tip, state_tip);
    }

    #[test]
    fn test_frame_tx_paymaster_sponsorship() {
        use k256::ecdsa::SigningKey;

        let state_tip = B256::repeat_byte(0x22);
        let signing_key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let uncompressed = verifying_key.to_sec1_point(false);
        let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
        let mut paymaster_addr_bytes = [0u8; 20];
        paymaster_addr_bytes.copy_from_slice(&hash[12..32]);
        let paymaster_addr = Address::from(paymaster_addr_bytes);

        let sender = Address::repeat_byte(0x01);
        let max_cost = U256::from(50000);
        let valid_until_epoch: u64 = 1000;

        let mut commitment_buf = Vec::with_capacity(20 + 20 + 32 + 8);
        commitment_buf.extend_from_slice(paymaster_addr.as_slice());
        commitment_buf.extend_from_slice(sender.as_slice());
        commitment_buf.extend_from_slice(&max_cost.to_be_bytes::<32>());
        commitment_buf.extend_from_slice(&valid_until_epoch.to_be_bytes());
        let commitment_hash = alloy_primitives::keccak256(&commitment_buf);

        let (sig, recid) = signing_key.sign_prehash_recoverable(commitment_hash.as_slice());
        let mut sig_bytes = [0u8; 65];
        sig_bytes[0..64].copy_from_slice(&sig.to_bytes());
        sig_bytes[64] = recid.to_byte();

        let tx = FrameTransaction {
            sender,
            target: Address::repeat_byte(0x02),
            nonce: 1,
            target_slot: 0,
            max_fee_per_gas: U256::from(100),
            max_priority_fee_per_gas: U256::from(10),
            gas_limits: MultiDimGasLimit::default(),
            verify_calldata: Bytes::from(vec![0x01]),
            signature_scheme: 0,
            public_key: Vec::new(),
            authorization_signature: Vec::new(),
            delegation: None,
            paymaster_frame: Some(PaymasterRiskFrame {
                paymaster: paymaster_addr,
                max_cost,
                valid_until_epoch,
                jurisdiction_tag: "EU_BaFin_Compliant".to_string(),
                signature: sig_bytes.to_vec(),
            }),
            execute_calldata: Bytes::from(vec![0x56]),
            state_witness: state_tip,
        };

        let verify_res = FrameExecutor::execute_verify_frame(&tx, state_tip).unwrap();
        assert!(verify_res.approved);
        assert_eq!(verify_res.payer, paymaster_addr);
    }
}
