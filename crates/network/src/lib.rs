//! Physical Layer & Peering Module
//! Handles `WireGuard` interfaces, single-key derivation, and cross-manifold gossip.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

/// Key derivation and Zero-KMS handshake module.
pub mod handshake;
pub mod wireguard;
pub mod das;
pub mod xroad;
