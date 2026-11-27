//! Vernam (VRNM) v0.5 — Ultra-fast, 100% information-theoretically secure OTP coin core.
//!
//! Zero external crates. Zero computational cryptography (no SHA-256, RSA, ECDSA, AES,
//! or zk-SNARKs). Security rests solely on Shannon information theory and quantum mechanics.

pub mod bft;
pub mod explorer_ui;
pub mod fast_engine;
pub mod field;
pub mod otp;
pub mod p2p_node;
pub mod pop_mining;
pub mod privacy_mpc;
pub mod qkd;
pub mod testnet_server;
pub mod tokenomics;
pub mod turbo_crypto;
pub mod turbo_express;
pub mod turbo_shielded;
pub mod wallet;
