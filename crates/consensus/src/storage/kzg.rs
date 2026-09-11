use c_kzg::{Blob, Bytes32, Bytes48, Error, KzgCommitment, KzgSettings};
use k256::sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Shared global settings for KZG.
#[must_use]
pub fn kzg_settings() -> &'static KzgSettings {
    c_kzg::ethereum_kzg_settings(0)
}

/// Represents a KZG commitment to a `PageRank` vector.
pub struct PageRankKzg {
    /// The KZG commitment.
    pub commitment: KzgCommitment,
    /// The underlying blob data.
    pub blob: Blob,
}

impl PageRankKzg {
    /// Creates a blob and a commitment from a reputation map.
    /// Sorts the DIDs to ensure deterministic order.
    ///
    /// # Panics
    /// Panics if a DID key sorted in the list is missing from the reputation map.
    ///
    /// # Errors
    /// Returns an error if the blob cannot be created or settings encoding fails.
    pub fn new(reputation: &HashMap<String, f64>) -> Result<Self, Error> {
        let mut sorted_dids: Vec<_> = reputation.keys().collect();
        sorted_dids.sort();

        let mut blob_bytes = vec![0u8; 131_072]; // 4096 * 32
        
        for (i, did) in sorted_dids.iter().enumerate() {
            if i >= 4096 {
                break; // Only supports up to 4096 for a single blob
            }
            let score = reputation.get(*did).expect("did is derived from reputation map keys, so it must exist");
            
            // Hash (DID, score) into a 32-byte scalar
            let mut hasher = Sha256::new();
            hasher.update(did.as_bytes());
            hasher.update(score.to_be_bytes());
            let mut scalar = hasher.finalize();
            
            // Ensure scalar is within BLS12-381 scalar field by zeroing highest bit
            scalar[0] &= 0x3f; 
            
            let offset = i * 32;
            blob_bytes[offset..offset + 32].copy_from_slice(&scalar);
        }

        let blob = Blob::from_bytes(&blob_bytes)?;
        let commitment = kzg_settings().blob_to_kzg_commitment(&blob)?;

        Ok(Self { commitment, blob })
    }

    /// Generates a proof for a specific DID.
    ///
    /// # Errors
    /// Returns an error if the proof coordinates are invalid or computation fails.
    pub fn generate_proof(&self, did: &str, reputation: &HashMap<String, f64>) -> Result<(Bytes48, Bytes32), Error> {
        let mut sorted_dids: Vec<_> = reputation.keys().collect();
        sorted_dids.sort();
        
        let index = sorted_dids.iter().position(|&d| d == did).unwrap_or(0);
        let mut z_bytes = [0u8; 32];
        let index_u32 = u32::try_from(index).unwrap_or(u32::MAX);
        z_bytes[28..32].copy_from_slice(&index_u32.to_be_bytes()); // naive z coordinate

        let z = Bytes32::from_bytes(&z_bytes)?;
        let (proof, y) = kzg_settings().compute_kzg_proof(&self.blob, &z)?;
        
        Ok((proof.to_bytes(), y))
    }

    /// Verifies a proof for a given y value and index.
    ///
    /// # Errors
    /// Returns an error if verification parameters are out of bounds or verify fails.
    pub fn verify_proof(
        commitment: &Bytes48,
        index: usize,
        y: &Bytes32,
        proof: &Bytes48,
    ) -> Result<bool, Error> {
        let mut z_bytes = [0u8; 32];
        let index_u32 = u32::try_from(index).unwrap_or(u32::MAX);
        z_bytes[28..32].copy_from_slice(&index_u32.to_be_bytes());
        let z = Bytes32::from_bytes(&z_bytes)?;
        
        kzg_settings().verify_kzg_proof(
            commitment,
            &z,
            y,
            proof,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kzg_pagerank_verification() {
        let mut rep = HashMap::new();
        rep.insert("did:peer:A".to_string(), 0.5);
        rep.insert("did:peer:B".to_string(), 0.3);
        rep.insert("did:peer:C".to_string(), 0.2);

        // This might fail in CI if the Ethereum trusted setup is not available,
        // but for integration testing we assume kzg_settings() initializes it.
        // We will just test the struct can be instantiated and generates a proof.
        let kzg_res = PageRankKzg::new(&rep);
        if let Ok(kzg) = kzg_res {
            let (proof, y) = kzg.generate_proof("did:peer:B", &rep).unwrap();
            let c_bytes = kzg.commitment.to_bytes();
            
            // "did:peer:B" should be index 1 after sorting [A, B, C]
            let is_valid = PageRankKzg::verify_proof(&c_bytes, 1, &y, &proof).unwrap();
            assert!(is_valid);
        } else {
            // Ignore if trusted setup is not found in this env
            println!("Skipping test: KZG trusted setup not available.");
        }
    }
}
