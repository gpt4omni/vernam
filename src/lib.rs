//! Vernam (VRNM) v0.3 — High-speed, information-theoretically secure OTP coin core.
//!
//! Zero external crates. Zero computational cryptography (no SHA-256, RSA, ECDSA, AES,
//! or zk-SNARKs). Security rests solely on Shannon information theory and quantum mechanics.

pub mod bft;
pub mod fast_engine;
pub mod field;
pub mod otp;
pub mod privacy_mpc;
pub mod qkd;
pub mod testnet_server;
pub mod tokenomics;
pub mod wallet;
