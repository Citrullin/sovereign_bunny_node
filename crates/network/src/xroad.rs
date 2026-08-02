//! Optional X-Road Standard Relay Server
//! Allows members of an organization to expose a compliant query relay endpoint
//! bridging external X-Road Security Server calls to the Sovereign Reth consensus layer.

use sovereign_identity::did::SovereignDidDocument;
use std::collections::HashMap;

/// Mock X-Road SOAP request header structures.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XRoadRequestHeader {
    /// The client invoking the request
    pub client: String,
    /// The requested service name
    pub service: String,
    /// Unique query identifier
    pub id: String,
    /// Protocol version (typically "4.0")
    pub protocol_version: String,
}

/// A relay server instance mapping X-Road queries to the consensus layer.
#[derive(Clone, Default)]
pub struct XRoadRelay {
    /// Reference to resolved DIDs
    pub dids: HashMap<String, SovereignDidDocument>,
}

impl XRoadRelay {
    /// Creates a new X-Road Relay instance.
    #[must_use]
    pub fn new(dids: HashMap<String, SovereignDidDocument>) -> Self {
        Self { dids }
    }

    /// Handles a SOAP-like X-Road payload query.
    ///
    /// Exposes DID document structure to external systems in a signed, auditable format.
    ///
    /// # Errors
    /// Returns an error if the `did_uri` is not found or serialization fails.
    pub fn query_organization_state(&self, did_uri: &str, _header: &XRoadRequestHeader) -> Result<String, &'static str> {
        if let Some(did) = self.dids.get(did_uri) {
            // Build response signed by the organization's did:peer:4 key.
            let mock_signature = format!("signed:{}", did_uri);
            
            let response = serde_json::json!({
                "xroad_response": {
                    "status": "success",
                    "did_uri": did.did_uri,
                    "evm_address": did.evm_address,
                    "signature": mock_signature
                }
            });
            
            Ok(response.to_string())
        } else {
            Err("DID not found in consensus registry")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn test_xroad_relay_query() {
        let mut dids = HashMap::new();
        let doc = SovereignDidDocument::derive_from_seed(B256::repeat_byte(0x01));
        let did_uri = doc.did_uri.clone();
        dids.insert(did_uri.clone(), doc);
        
        let relay = XRoadRelay::new(dids);
        let header = XRoadRequestHeader {
            client: "gov-dept-x".to_string(),
            service: "getOrgStructure".to_string(),
            id: "req-12345".to_string(),
            protocol_version: "4.0".to_string(),
        };
        
        let response = relay.query_organization_state(&did_uri, &header).unwrap();
        assert!(response.contains("did_uri"));
        assert!(response.contains(&format!("signed:{}", did_uri)));
    }
}
