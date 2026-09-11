//! RPC sub-module providing CAIP-2/10, zkCompliance, EVM compatibility, and proxy forwarding.

pub mod caip_handlers;
pub mod caip_types;
pub mod evm_compat;
pub mod forward;
pub mod memory_state;
pub mod proxy;
pub mod synthetic;
pub mod wallet;
pub mod zk_compliance_rpc;
pub mod activitypub_gateway;
pub mod precompile_interceptor;
pub mod receipt_simulator;

pub use precompile_interceptor::{is_intercepted_precompile, dispatch_precompile_call};
pub use receipt_simulator::build_synthetic_precompile_receipt;

pub use activitypub_gateway::{handle_actor_json_ld, handle_inbox_activity, handle_outbox_publish, handle_webfinger};
pub use caip_handlers::{handle_caip_resolve_did, handle_caip_to_account_id};
pub use caip_types::{Caip10AccountId, Caip19AssetId, Caip2ChainId};
pub use evm_compat::{normalize_block_param, requires_gas_sponsor, standard_gas_estimate};
pub use forward::{
    extract_header, extract_result, forward_to_reth_http, fund_gas_if_needed, get_reth_balance,
    get_reth_transaction_count, handle_get_transaction_count, send_error, send_funding_tx,
    send_result, sync_hot_storage, write_json,
};
pub use memory_state::{
    add_native_transfer_record, get_archival_daemon, get_auto_claims, get_outbound_meta, get_state,
    get_synthetic_meta, get_synthetic_receipts, get_synthetic_tx_hashes, insert_synthetic_receipt,
    now_secs, MemoryState, NativeTransferRecord, OutboundSendMeta, SyntheticMeta, CHAIN_ID,
};
pub use proxy::run_proxy;
pub use synthetic::{inject_history_into_block, synthesize_receipt};
pub use wallet::{
    decode_sender, decode_tx_details, decode_tx_envelope, decode_tx_to, get_receipt_by_hash,
    get_tx_by_hash, handle_wallet_method, index_from_raw_tx, synthesize_transfer_logs,
};
pub use zk_compliance_rpc::{
    handle_get_cross_chain_intent_status, handle_get_jurisdiction_descriptor,
    handle_get_virtual_chain_address, CrossChainIntentStatusResponse,
    JurisdictionDescriptorResponse, VirtualChainAddressResponse,
};
