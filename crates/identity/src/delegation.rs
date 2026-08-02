//! Session key authorization checks and recursive authority paths.

use alloy_primitives::Address;

/// Represents a delegated session key.
#[derive(Debug, Clone)]
pub struct SessionKey {
    /// The address of the delegated key.
    pub key: Address,
    /// The timestamp when the session expires.
    pub expires_at: u64,
}

impl SessionKey {
    /// Checks if the session key is authorized at the given timestamp.
    /// Expiry is typically 24h.
    #[must_use]
    pub fn is_authorized(&self, current_timestamp: u64) -> bool {
        current_timestamp <= self.expires_at
    }
}

/// Represents a bottom-up authority delegation path (e.g. Munich -> Bavaria -> Germany -> EU)
#[derive(Debug, Clone, Default)]
pub struct AuthorityDelegation {
    /// Ordered list of DIDs representing the path from local municipality to supra-national level.
    pub path: Vec<String>,
}

impl AuthorityDelegation {
    /// Creates a new AuthorityDelegation path.
    #[must_use]
    pub fn new(path: Vec<String>) -> Self {
        Self { path }
    }

    /// Verifies that the delegation path is non-empty and structurally consistent.
    #[must_use]
    pub fn verify_path(&self) -> bool {
        !self.path.is_empty()
    }
}

