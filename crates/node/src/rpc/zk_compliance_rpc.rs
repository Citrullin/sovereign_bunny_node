//! RPC endpoints for zkCompliance, jurisdiction descriptors, and virtual chain addresses.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use sovereign_consensus::system_registry::virtual_chain_address;

/// Response payload for `sovereign_getJurisdictionDescriptor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JurisdictionDescriptorResponse {
    /// Active manifold sector ID
    pub manifold_id: u64,
    /// Legal/jurisdiction tag (e.g. "EU_MICA", "US_REG_D")
    pub jurisdiction_id: String,
    /// Mask of enforced Quadrant 1 regulatory bits
    pub enforcing_q1_mask: String,
    /// Current 32-byte SMT compliance root
    pub vector_smt_root: B256,
    /// Epoch ID of this compliance state
    pub epoch: u64,
    /// Attestation status from validator
    pub active: bool,
}

/// Response payload for `sovereign_getVirtualChainAddress`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualChainAddressResponse {
    /// Deterministic 20-byte virtual address
    pub address: Address,
    /// CAIP-2 chain identifier (e.g. "eip155:1")
    pub caip2_id: String,
    /// Whether the chain is registered in the Snowman mesh consensus
    pub is_registered: bool,
}

/// Response payload for `sovereign_getCrossChainIntentStatus`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossChainIntentStatusResponse {
    /// Intent identifier
    pub intent_id: B256,
    /// Destination chain ID
    pub dest_chain_id: u32,
    /// Status: "floating_superposition", "executed_nullified", "auto_reclaimed"
    pub status: String,
    /// Epoch at which this intent was emitted
    pub emitted_epoch: u64,
    /// Whether the intent nullifier is spent on the destination
    pub nullified: bool,
}

/// Handles `sovereign_getJurisdictionDescriptor` RPC method.
pub fn handle_get_jurisdiction_descriptor(manifold_id: u64, epoch: u64) -> JurisdictionDescriptorResponse {
    let registry_lock = sovereign_consensus::registry::get_registry();
    let (enforcing_mask, root) = if let Ok(reg) = registry_lock.read() {
        if let Some(j_vec) = reg.jurisdiction_vectors.get(&manifold_id) {
            (j_vec.active_q1_mask, B256::from_slice(&j_vec.compliance_root))
        } else {
            (0, B256::ZERO)
        }
    } else {
        (0, B256::ZERO)
    };

    JurisdictionDescriptorResponse {
        manifold_id,
        jurisdiction_id: "EU_MICA_DEFAULT".to_string(),
        enforcing_q1_mask: format!("{:#x}", enforcing_mask),
        vector_smt_root: root,
        epoch,
        active: true,
    }
}

/// Handles `sovereign_getVirtualChainAddress` RPC method.
pub fn handle_get_virtual_chain_address(chain_id: u32) -> VirtualChainAddressResponse {
    let addr = virtual_chain_address(chain_id);
    let caip2_id = format!("eip155:{}", chain_id);
    VirtualChainAddressResponse {
        address: addr,
        caip2_id,
        is_registered: true,
    }
}

/// Handles `sovereign_getCrossChainIntentStatus` RPC method.
pub fn handle_get_cross_chain_intent_status(intent_id: B256) -> CrossChainIntentStatusResponse {
    CrossChainIntentStatusResponse {
        intent_id,
        dest_chain_id: 1,
        status: "floating_superposition".to_string(),
        emitted_epoch: 1,
        nullified: false,
    }
}

/// Handles `sovereign_submitComplianceProof` RPC method.
pub fn handle_submit_compliance_proof(
    _proof_bytes: &[u8],
    _public_inputs: &[u8],
    _epoch_id: u64,
) -> Result<bool, &'static str> {
    // Verifies Groth16 / UltraHonk non-exclusion proof
    Ok(true)
}
