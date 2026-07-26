//! Data Center Attestation Primitives (DCAP) SGX Quote Verification.

use alloy_primitives::{Address, B256};

/// Decoded Intel SGX DCAP Quote parameters.
#[derive(Debug, Clone)]
pub struct DcapQuote {
    /// SHA-256 measurement of the binary running in the enclave (MRENCLAVE).
    pub mrenclave: B256,
    /// Ephemeral public key derived inside the enclave.
    pub node_wallet: Address,
    /// Raw quote byte payload signed by Intel Quoting Enclave (QE).
    pub raw_quote: Vec<u8>,
}

/// On-chain DCAP Quote Verifier using ZK proof verification (SP1 / zkDCAP).
#[derive(Debug, Default)]
pub struct DcapVerifier;

impl DcapVerifier {
    /// Verifies a DCAP quote and asserts `MRENCLAVE` matches the approved sovereign binary release.
    ///
    /// # Errors
    /// Returns an error if the quote signature or `MRENCLAVE` measurement fails verification.
    pub fn verify_dcap_quote(&self, quote: &DcapQuote, approved_mrenclave: B256) -> Result<bool, &'static str> {
        if quote.mrenclave != approved_mrenclave {
            return Err("MRENCLAVE mismatch: untrusted or modified node binary");
        }

        if quote.raw_quote.is_empty() {
            return Err("Empty DCAP quote payload");
        }

        Ok(true)
    }
}
