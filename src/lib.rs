//! Vernam (VRNM) v0.2 — High-speed, information-theoretically secure OTP coin core.
//!
//! Zero external crates. Zero computational cryptography (no SHA-256, RSA, ECDSA, AES,
//! or zk-SNARKs). Security rests solely on Shannon information theory and quantum mechanics.

pub mod bft;
pub mod field;
pub mod otp;
pub mod privacy_mpc;
pub mod qkd;
pub mod tokenomics;
