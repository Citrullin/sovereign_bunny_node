//! # Sovereign Apache Iggy Control & Ring-Buffer Interface
//!
//! Exposes partition stream constants, zero-copy buffer abstractions,
//! and producer/consumer wrappers for the stateless account-lattice pipeline.

pub mod streams;
pub mod client;

pub use streams::*;
pub use client::{IggyMessageBus, IggyProducer, IggyConsumer};
