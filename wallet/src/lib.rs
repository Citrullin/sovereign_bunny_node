//! # Sovereign Reth WASM Wallet Library
//!
//! Exposes key generation, witness proof construction, and e-Paper image conversion
//! to the local frontend.

pub mod pq_keygen;
pub mod proof_gen;
pub mod epaper;
pub mod did_register;
pub mod wasm_signing;

use wasm_bindgen::prelude::*;

/// Initializer invoked automatically upon WASM load.
#[wasm_bindgen(start)]
pub fn start_init() {
    // Setup simple console logger
    web_sys::console::log_1(&JsValue::from_str("Sovereign WASM Wallet module loaded successfully."));
}
