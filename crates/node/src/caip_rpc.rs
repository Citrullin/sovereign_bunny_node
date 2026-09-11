//! CAIP-RPC proxy facade re-exporting modular sub-modules.

pub use crate::rpc::caip_handlers::*;
pub use crate::rpc::caip_types::*;
pub use crate::rpc::evm_compat::*;
pub use crate::rpc::forward::*;
pub use crate::rpc::memory_state::*;
pub use crate::rpc::proxy::run_proxy;
pub use crate::rpc::synthetic::*;
pub use crate::rpc::wallet::*;
pub use crate::rpc::zk_compliance_rpc::*;
