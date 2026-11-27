//! Vernam (VRNM) v2.1 — Zero-admin, 100% decentralized, information-theoretically secure OTP coin & confidential IT-MPC circuit VM.
//!
//! Zero external crates. Zero computational cryptography (no SHA-256, RSA, ECDSA, AES,
//! or zk-SNARKs). Security rests solely on Shannon information theory and quantum mechanics.

pub mod adaptive_tuner;
pub mod bft;
pub mod distributed_mpc;
pub mod dynamic_quorum;
pub mod entropy_beacon;
pub mod entropy_harvester;
pub mod explorer_ui;
pub mod fast_engine;
pub mod field;
pub mod geo_triangulation;
pub mod hw_entropy;
pub mod key_transport;
pub mod mpc_bytecode;
pub mod mpc_defi;
pub mod mpc_vm;
pub mod oblivious_shuffle;
pub mod otp;
pub mod p2p_node;
pub mod pop_mining;
pub mod privacy_mpc;
pub mod qkd;
pub mod storage;
pub mod testnet_server;
pub mod tokenomics;
pub mod turbo_crypto;
pub mod turbo_express;
pub mod turbo_shielded;
pub mod validator_daemon;
pub mod vault_recovery;
pub mod wallet;
