//! Minimal formally-verifiable `#![no_std]` `#![forbid(unsafe_code)]` cryptographic and consensus
//! kernel for Vernam (`VRNM`).
//!
//! Design properties:
//! - Zero external crate dependencies.
//! - Zero computational cryptography (no SHA-256, RSA, ECDSA, AES, or zk-SNARKs).
//! - Zero heap allocations (`no_std`, no `alloc`).
//! - Zero `unsafe` code (`#![forbid(unsafe_code)]`).
//! - Panic-free production APIs using checked integer arithmetic and `Result`/`Option`.

#![no_std]
#![forbid(unsafe_code)]

pub mod bft_sm;
pub mod cw_mac;
pub mod field;
pub mod mpc_checks;
pub mod shamir;
pub mod supply;
