use serde::{Deserialize, Serialize};

/// CAIP-2 Blockchain Identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caip2ChainId {
    pub namespace: String,
    pub reference: String,
}

impl Caip2ChainId {
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            Some(Self {
                namespace: parts[0].to_string(),
                reference: parts[1].to_string(),
            })
        } else {
            None
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}:{}", self.namespace, self.reference)
    }
}

/// CAIP-10 Account Identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caip10AccountId {
    pub chain_id: Caip2ChainId,
    pub address: String,
}

impl Caip10AccountId {
    pub fn parse(s: &str) -> Option<Self> {
        if s.starts_with("did:sovereign:") {
            let stripped = &s["did:sovereign:".len()..];
            let parts: Vec<&str> = stripped.split(':').collect();
            if parts.len() == 2 {
                let chain_id = Caip2ChainId::parse(parts[0])?;
                return Some(Self {
                    chain_id,
                    address: parts[1].to_string(),
                });
            }
        }
        
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 3 {
            let chain_id = Caip2ChainId {
                namespace: parts[0].to_string(),
                reference: parts[1].to_string(),
            };
            Some(Self {
                chain_id,
                address: parts[2].to_string(),
            })
        } else {
            None
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}:{}", self.chain_id.to_string(), self.address)
    }
}

/// CAIP-19 Asset Identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caip19AssetId {
    pub chain_id: Caip2ChainId,
    pub namespace: String,
    pub reference: String,
}

impl Caip19AssetId {
    pub fn parse(s: &str) -> Option<Self> {
        let slash_parts: Vec<&str> = s.split('/').collect();
        if slash_parts.len() == 2 {
            let chain_id = Caip2ChainId::parse(slash_parts[0])?;
            let asset_parts: Vec<&str> = slash_parts[1].split(':').collect();
            if asset_parts.len() == 2 {
                return Some(Self {
                    chain_id,
                    namespace: asset_parts[0].to_string(),
                    reference: asset_parts[1].to_string(),
                });
            }
        }
        None
    }

    pub fn to_string(&self) -> String {
        format!("{}/{}:{}", self.chain_id.to_string(), self.namespace, self.reference)
    }
}
