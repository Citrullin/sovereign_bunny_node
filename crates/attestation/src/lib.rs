//! TEE Attestation Module
//! Provides abstraction for Hardware TEE, DCAP, and Mock attestations.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

pub mod sgx;
pub mod mock;
pub mod dcap;

/// A generic trait for providing TEE attestations.
pub trait AttestationProvider {
    /// Generates an attestation quote.
    ///
    /// # Errors
    /// Returns an error if the quote generation fails.
    fn generate_quote(&self, report_data: &[u8]) -> Result<Vec<u8>, String>;
    
    /// Verifies an attestation quote.
    ///
    /// # Errors
    /// Returns an error if the verification fails.
    fn verify_quote(&self, quote: &[u8]) -> Result<bool, String>;
}
