//! Celestia-compatible Namespaced Merkle Trees for state-diff partitioning.
//!
//! Uses the standard `nmt-rs` crate by Sovereign-Labs to verify range proofs
//! and inclusion proofs.

use nmt_rs::{CelestiaNmt, NamespaceId as NmtNamespaceId, NamespaceProof, NamespacedHash, NamespacedSha2Hasher, NamespaceMerkleHasher};
use std::ops::Range;

/// Size of Celestia namespace ID in bytes.
pub const NS_ID_SIZE: usize = 29;

/// A namespace ID representing a partition of the manifold state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NamespaceId(pub [u8; NS_ID_SIZE]);

impl From<u64> for NamespaceId {
    fn from(val: u64) -> Self {
        let mut bytes = [0u8; NS_ID_SIZE];
        bytes[NS_ID_SIZE - 8..].copy_from_slice(&val.to_be_bytes());
        Self(bytes)
    }
}

/// A Namespaced Merkle Tree Leaf.
#[derive(Debug, Clone)]
pub struct NmtLeaf {
    /// The namespace ID associated with this leaf.
    pub namespace: NamespaceId,
    /// The leaf payload data.
    pub data: Vec<u8>,
}

/// The result of a namespace range proof query: leaf data and the associated proof.
pub struct NamespaceRangeResult {
    /// The raw leaf data items returned for the requested range.
    pub leaves: Vec<Vec<u8>>,
    /// The namespace inclusion proof.
    pub proof: NamespaceProof<NamespacedSha2Hasher<NS_ID_SIZE>, NS_ID_SIZE>,
}

/// Namespace Merkle Tree wrapper.
pub struct NamespaceMerkleTree {
    inner: CelestiaNmt,
}

impl Default for NamespaceMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceMerkleTree {
    /// Creates a new Namespaced Merkle Tree.
    #[must_use]
    pub fn new() -> Self {
        let hasher = NamespacedSha2Hasher::with_ignore_max_ns(true);
        Self {
            inner: CelestiaNmt::with_hasher(hasher),
        }
    }

    /// Pushes a leaf to the tree. Leaves must be pushed in ascending namespace order.
    ///
    /// # Errors
    /// Returns an error if the leaves are not pushed in sorted order.
    pub fn push_leaf(&mut self, leaf: &NmtLeaf) -> Result<(), &'static str> {
        let ns = NmtNamespaceId(leaf.namespace.0);
        self.inner.push_leaf(&leaf.data, ns)
    }

    /// Computes and returns the tree root commitment.
    pub fn root(&mut self) -> NamespacedHash<NS_ID_SIZE> {
        self.inner.root()
    }

    /// Generates a namespace inclusion proof for a range of leaves.
    ///
    /// Returns a [`NamespaceRangeResult`] wrapping the leaf data and proof,
    /// rather than exposing the raw `Vec<Vec<u8>>` from the underlying library.
    pub fn get_range_with_proof(&mut self, range: Range<usize>) -> NamespaceRangeResult {
        let (leaves, proof) = self.inner.get_range_with_proof(range);
        NamespaceRangeResult { leaves, proof }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmt_rs_integration() {
        let mut tree = NamespaceMerkleTree::new();
        let leaf1 = NmtLeaf {
            namespace: NamespaceId::from(1),
            data: b"state_diff_part1".to_vec(),
        };
        let leaf2 = NmtLeaf {
            namespace: NamespaceId::from(2),
            data: b"state_diff_part2".to_vec(),
        };

        tree.push_leaf(&leaf1).unwrap();
        tree.push_leaf(&leaf2).unwrap();

        let root = tree.root();
        // The tree root should cover the namespace range of its descendants
        assert_eq!(root.min_namespace().0, NamespaceId::from(1).0);
        assert_eq!(root.max_namespace().0, NamespaceId::from(2).0);

        // Fetch range with proof via clean wrapper type
        let result = tree.get_range_with_proof(0..1);
        assert_eq!(result.leaves[0], b"state_diff_part1");

        // Verify proof
        let res = result.proof.verify_complete_namespace(
            &root,
            &result.leaves,
            NmtNamespaceId(NamespaceId::from(1).0),
        );
        assert!(res.is_ok());
    }
}
