//! Vernam (VRNM) Live Testnet HTTP/1.1 Node & Interactive Web Explorer.
//!
//! Zero external crates (`std::net`, `std::sync`, `std::thread`, `std::io`).
//! Zero computational cryptography (no SHA-256, RSA, ECDSA, AES, or zk-SNARKs).
//! Orchestrates the real Vernam engines:
//! - 4-validator 2-phase BFT Express Lane (`crate::bft::BftCluster`)
//! - Sharded IT-MPC Shielded Lane (`crate::privacy_mpc::{ShardedPrivateLedger, BeaverPool}`)
//! - Live BB84 + Decoy-State QKD Channel (`crate::qkd::Bb84Channel`)
//! - 21M-Cap Proof-of-Pad Tokenomics & 80/20 Pad-Burn Engine (`crate::tokenomics::TokenomicsEngine`)
//! - Proof-of-Personhood Web-of-Trust Registry (`crate::bft::WebOfTrustRegistry`)

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::bft::{BftCluster, BftConfig, BinaryTx, WebOfTrustRegistry};
use crate::explorer_ui::VERNAM_EXPLORER_HTML;
use crate::field::{random_field_elem, random_nonzero_field_elem, zeroize_slice};
use crate::pop_mining::{PopAuditor, PopEpochCoordinator, PopMiner};
use crate::privacy_mpc::{
    BeaverPool, ConfidentialTransferRequest, DEFAULT_BUCKET_SIZE, DEFAULT_NUM_VALIDATORS,
    DEFAULT_THRESHOLD, ShardedPrivateLedger,
};
use crate::qkd::{Bb84Channel, OsEntropySource, QkdKeyProvider};
use crate::tokenomics::{
    EpochContribution, FeeLane, TokenomicsEngine, VERN_PER_VRNM, ValidatorStatus,
};

/// Dedicated treasury account ID in the Express BFT ledger used to fund faucet payouts
/// through real 2-phase BFT consensus without colliding with user account IDs `0..max_accounts`.
pub const TREASURY_ACCOUNT_ID: u32 = u32::MAX;

/// Initial Express-lane balance pre-funded into [`TREASURY_ACCOUNT_ID`] at genesis.
pub const TREASURY_INITIAL_BALANCE: u64 = 10_000_000;

/// Maximum number of recent explorer events retained in [`TestnetState::recent_events`].
pub const MAX_RECENT_EVENTS: usize = 20;

/// Maximum Express payout per `/faucet` request.
pub const MAX_FAUCET_EXPRESS: u64 = 100_000;

/// Maximum Shielded payout per `/faucet` request.
pub const MAX_FAUCET_SHIELDED: u64 = 10_000;

/// Maximum concurrent inbound HTTP connections before returning HTTP 503.
const MAX_CONCURRENT_CONNS: usize = 64;

/// Maximum external P2P peer entries retained from `POST /p2p/announce`.
const MAX_EXTERNAL_PEERS: usize = 64;

/// Maximum peer address string length accepted by `POST /p2p/announce`.
const MAX_PEER_ADDR_LEN: usize = 128;

/// Overall wall-clock deadline for reading a single HTTP request (Slowloris defense).
const HTTP_READ_DEADLINE: Duration = Duration::from_secs(5);

/// Socket write timeout for HTTP responses.
const HTTP_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default initial Beaver triple pool size for the Shielded IT-MPC lane.
const INITIAL_BEAVER_POOL_SIZE: usize = 512;

/// Pre-provisioned pairwise OTP link slots per directed validator link in the Express BFT cluster.
const DEFAULT_BFT_SLOTS_PER_LINK: usize = 1_536;

/// Pre-provisioned single-use Carter-Wegman block sealing heights in the Express BFT cluster.
const DEFAULT_BFT_MAX_HEIGHTS: u64 = 512;

/// Pre-provisioned view-change slots per height in the Express BFT cluster.
const DEFAULT_BFT_MAX_VIEWS: u64 = 4;

/// Maximum accepted HTTP request header size (16 KiB).
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;

/// Maximum accepted HTTP request body size (64 KiB).
const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;

// ============================================================================
// 1. Configuration & Action Receipts
// ============================================================================

/// Configuration for the live Vernam (`VRNM`) testnet HTTP node.
#[derive(Debug, Clone)]
pub struct TestnetConfig {
    /// TCP bind address (defaults to `VRNM_BIND` env var or `"0.0.0.0:8080"`).
    pub bind_addr: String,
    /// Number of Shielded-lane anonymity buckets (default `4`, giving 64 accounts of size 16).
    pub num_buckets: usize,
    /// Maximum user account count exposed by the node (`0..max_accounts`, default `64`).
    pub max_accounts: usize,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        let bind_addr =
            std::env::var("VRNM_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        Self {
            bind_addr,
            num_buckets: 4,
            max_accounts: 64,
        }
    }
}

/// Receipt returned by [`TestnetState::faucet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaucetReceipt {
    pub account_id: u32,
    pub express_credited: u64,
    pub shielded_credited: u64,
    pub express_balance: u64,
    pub shielded_balance: u128,
    pub block_height: Option<u64>,
    pub pss_epoch: u64,
}

/// Receipt returned by [`TestnetState::express_transfer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressTxReceipt {
    pub sender: u32,
    pub recipient: u32,
    pub amount: u64,
    pub block_height: u64,
    pub leader_id: u32,
    pub block_tag_hex: String,
    pub fee_vern: u64,
    pub burned_vern: u64,
    pub sender_balance: u64,
    pub recipient_balance: u64,
}

/// Receipt returned by [`TestnetState::shielded_transfer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedTxReceipt {
    pub sender: usize,
    pub recipient_bucket: usize,
    pub fee_vern: u64,
    pub burned_vern: u64,
    pub triples_consumed: usize,
    pub beaver_pool_remaining: usize,
    pub pss_epoch: u64,
}

/// Balance & validator Shamir share snapshot returned by [`TestnetState::account_balance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountBalanceSnapshot {
    pub account_id: u32,
    pub express_balance: u64,
    pub shielded_balance: u128,
    pub v0_shamir_share: String,
    pub v1_shamir_share: String,
    pub v2_shamir_share: String,
    pub v3_shamir_share: String,
    pub bucket_id: usize,
    pub slot_in_bucket: usize,
    pub epoch: u64,
}

/// Receipt returned by [`TestnetState::refresh_epoch`].
#[derive(Debug, Clone, PartialEq)]
pub struct EpochRefreshReceipt {
    pub pss_epoch: u64,
    pub settled_tokenomics_epoch: u64,
    pub subsidy_minted_vern: u64,
    pub fee_rewards_distributed_vern: u64,
    pub fees_burned_in_epoch_vern: u64,
    pub total_burned_vern: u64,
    pub qber: f64,
    pub qkd_sifted_bits: usize,
    pub decoy_yield_ratio: f64,
}

// ============================================================================
// 2. Thread-Safe Testnet State Orchestrating All Vernam Engines
// ============================================================================

/// Live state for a Vernam (`VRNM`) testnet node holding all information-theoretically secure
/// engines inside an `Arc<Mutex<TestnetState>>`.
pub struct TestnetState {
    pub config: TestnetConfig,
    /// Live 4-validator 2-phase BFT Express Lane cluster (`V0..V3`).
    pub bft: BftCluster,
    /// Live Sharded IT-MPC Shielded Lane ledger.
    pub shielded_ledger: ShardedPrivateLedger,
    /// Auto-refilling offline Beaver multiplication triple pool.
    pub beaver_pool: BeaverPool,
    /// Live BB84 + Decoy-State QKD telemetry channel.
    pub qkd_channel: Bb84Channel<OsEntropySource>,
    /// Live 21M-cap Proof-of-Pad tokenomics & 80/20 pad-burn fee engine.
    pub tokenomics: TokenomicsEngine,
    /// Live Proof-of-Personhood Web-of-Trust registry (1-human = 1-vote).
    pub wot_registry: WebOfTrustRegistry,
    /// Monotonic counter of settled Express transactions.
    pub express_txs: u64,
    /// Monotonic counter of settled Shielded IT-MPC transactions.
    pub shielded_txs: u64,
    /// Monotonic counter of finalized 2-phase BFT blocks.
    pub blocks_finalized: u64,
    /// Most recently observed BB84 Quantum Bit Error Rate.
    pub last_qber: f64,
    /// Monotonic unique OTP page ID counter for Express transactions.
    pub next_page_id: u64,
    /// Capped ring buffer of the most recent [`MAX_RECENT_EVENTS`] explorer events.
    pub recent_events: Vec<String>,
    /// Per-sender monotonic nonce table for Express transactions.
    sender_nonces: BTreeMap<u32, u64>,
    /// External P2P nodes discovered via `POST /p2p/announce`: `addr -> (node_id, height, pop_score, qber)`.
    external_peers: BTreeMap<String, (u64, u64, u64, f64)>,
}

impl TestnetState {
    /// Initialize a fresh live Vernam testnet node state from `config`.
    pub fn new(config: TestnetConfig) -> Result<Self, String> {
        if config.num_buckets == 0 {
            return Err("num_buckets must be >= 1".to_string());
        }
        let shielded_capacity = config.num_buckets * DEFAULT_BUCKET_SIZE;
        if config.max_accounts == 0 || config.max_accounts > shielded_capacity {
            return Err(format!(
                "max_accounts ({}) must be in 1..={} (num_buckets * {})",
                config.max_accounts, shielded_capacity, DEFAULT_BUCKET_SIZE
            ));
        }

        // 1. Initialize 4-validator Express BFT cluster with accounts 0..max_accounts + Treasury.
        let bft_config = BftConfig::default();
        let mut initial_balances = BTreeMap::new();
        for acct in 0..config.max_accounts as u32 {
            initial_balances.insert(acct, 0u64);
        }
        initial_balances.insert(TREASURY_ACCOUNT_ID, TREASURY_INITIAL_BALANCE);

        let bft = BftCluster::new(
            bft_config,
            initial_balances,
            DEFAULT_BFT_SLOTS_PER_LINK,
            DEFAULT_BFT_MAX_HEIGHTS,
            DEFAULT_BFT_MAX_VIEWS,
        );

        // 2. Initialize Sharded IT-MPC Shielded Ledger + auto-refilling BeaverPool.
        let shielded_ledger = ShardedPrivateLedger::new_default(config.num_buckets)
            .map_err(|e| format!("failed to init ShardedPrivateLedger: {e}"))?;
        let beaver_pool = BeaverPool::new_3_of_4(INITIAL_BEAVER_POOL_SIZE);

        // 3. Initialize live BB84 + Decoy-State QKD channel and perform genesis link calibration.
        let mut qkd_channel = Bb84Channel::default_channel();
        let mut init_qkd = qkd_channel
            .exchange_key(32)
            .map_err(|e| format!("genesis BB84 QKD check failed: {e}"))?;
        let last_qber = init_qkd.qber;
        zeroize_slice(&mut init_qkd.alice_key);
        zeroize_slice(&mut init_qkd.bob_key);

        // 4. Initialize 21M-cap Proof-of-Pad TokenomicsEngine with 4 equal-bonded validators V0..V3.
        let mut tokenomics = TokenomicsEngine::with_defaults();
        tokenomics
            .mint_genesis_supply(1_000_000 * VERN_PER_VRNM)
            .map_err(|e| format!("failed to mint genesis liquid supply: {e}"))?;
        for vid in 0..DEFAULT_NUM_VALIDATORS as u64 {
            tokenomics
                .register_genesis_validator(vid)
                .map_err(|e| format!("failed to register genesis validator V{vid}: {e}"))?;
        }

        // 5. Initialize Proof-of-Personhood Web-of-Trust registry (V0..V3, 1-human = 1-vote).
        let wot_registry = WebOfTrustRegistry::for_bft_config(&bft_config);

        let mut state = Self {
            config,
            bft,
            shielded_ledger,
            beaver_pool,
            qkd_channel,
            tokenomics,
            wot_registry,
            express_txs: 0,
            shielded_txs: 0,
            blocks_finalized: 0,
            last_qber,
            next_page_id: 1,
            recent_events: Vec::with_capacity(MAX_RECENT_EVENTS),
            sender_nonces: BTreeMap::new(),
            external_peers: BTreeMap::new(),
        };

        state.push_event(format!(
            "GENESIS: 4-validator BFT (V0..V3), {} shielded buckets ({} accounts), BB84 QBER={:.4}%",
            state.config.num_buckets,
            state.shielded_ledger.total_accounts(),
            state.last_qber * 100.0
        ));

        Ok(state)
    }

    /// Push a human-readable event into the capped ring buffer (`recent_events`, max 20 entries).
    pub fn push_event(&mut self, msg: String) {
        if self.recent_events.len() >= MAX_RECENT_EVENTS {
            self.recent_events.remove(0);
        }
        self.recent_events.push(msg);
    }

    fn alloc_page_and_nonce(&mut self, sender: u32) -> (u64, u64) {
        let page_id = self.next_page_id;
        self.next_page_id += 1;
        let entry = self.sender_nonces.entry(sender).or_insert(0);
        *entry += 1;
        (page_id, *entry)
    }

    fn validate_account_id(&self, account_id: u32) -> Result<(), String> {
        if (account_id as usize) >= self.config.max_accounts {
            return Err(format!(
                "account_id {} out of range (valid: 0..{})",
                account_id, self.config.max_accounts
            ));
        }
        Ok(())
    }

    fn max_shielded_value(&self) -> u128 {
        let bw = self.shielded_ledger.bit_width();
        if bw == 64 {
            u64::MAX as u128
        } else {
            (1u128 << bw) - 1
        }
    }

    fn record_online_validators_contribution(&mut self, contrib: EpochContribution) {
        let online = self.bft.online_ids();
        for vid in online {
            let _ = self.tokenomics.record_contribution(vid as u64, contrib);
        }
    }

    /// Credit an account via the testnet faucet:
    /// - Express credits settle a real 2-phase BFT transfer from [`TREASURY_ACCOUNT_ID`] -> `account_id`.
    /// - Shielded credits mint fresh Shamir shares into `account_id` via `ShardedPrivateLedger::mint_initial_balance`.
    pub fn faucet(
        &mut self,
        account_id: u32,
        express: u64,
        shielded: u64,
    ) -> Result<FaucetReceipt, String> {
        self.validate_account_id(account_id)?;
        if express == 0 && shielded == 0 {
            return Err("faucet requires express > 0 or shielded > 0".to_string());
        }
        if express > MAX_FAUCET_EXPRESS {
            return Err(format!(
                "express faucet amount {express} exceeds per-request cap {MAX_FAUCET_EXPRESS}"
            ));
        }
        if shielded > MAX_FAUCET_SHIELDED {
            return Err(format!(
                "shielded faucet amount {shielded} exceeds per-request cap {MAX_FAUCET_SHIELDED}"
            ));
        }

        // Pre-validate shielded range ceiling before committing any BFT block so faucet is atomic.
        if shielded > 0 {
            let current = self
                .shielded_ledger
                .reconstruct_balance(account_id as usize)
                .map_err(|e| format!("failed to read shielded balance: {e}"))?;
            let max_val = self.max_shielded_value();
            if current.saturating_add(shielded as u128) > max_val {
                return Err(format!(
                    "shielded balance overflow: current {current} + {shielded} exceeds max {max_val}"
                ));
            }
        }

        let mut block_height = None;
        if express > 0 {
            let (page_id, nonce) = self.alloc_page_and_nonce(TREASURY_ACCOUNT_ID);
            let tx = BinaryTx::new(TREASURY_ACCOUNT_ID, account_id, express, page_id, nonce);
            let cert = self
                .bft
                .propose_and_finalize_batch(vec![tx])
                .map_err(|e| format!("BFT faucet settlement failed: {e}"))?;
            self.blocks_finalized = cert.height;
            block_height = Some(cert.height);
            self.record_online_validators_contribution(EpochContribution {
                pad_pages_supplied: 1,
                beaver_triples_contributed: 0,
                blocks_finalized: 1,
                pss_refreshes_completed: 0,
            });
        }

        if shielded > 0 {
            self.shielded_ledger
                .mint_initial_balance(account_id as usize, shielded as u128)
                .map_err(|e| format!("shielded faucet mint failed: {e}"))?;
        }

        let express_balance = self.bft.validators[0].ledger.balance_of(account_id);
        let shielded_balance = self
            .shielded_ledger
            .reconstruct_balance(account_id as usize)
            .map_err(|e| format!("failed to reconstruct shielded balance: {e}"))?;
        let pss_epoch = self.shielded_ledger.epoch();

        self.push_event(format!(
            "FAUCET -> Acct #{account_id}: +{express} express, +{shielded} shielded{}",
            block_height
                .map(|h| format!(" (BFT block #{h})"))
                .unwrap_or_default()
        ));

        Ok(FaucetReceipt {
            account_id,
            express_credited: express,
            shielded_credited: shielded,
            express_balance,
            shielded_balance,
            block_height,
            pss_epoch,
        })
    }

    /// Execute and finalize a real 2-phase BFT Express Lane transfer across `V0..V3`,
    /// collecting the 80/20 `FeeLane::Express` pad-burn fee in [`TokenomicsEngine`].
    pub fn express_transfer(
        &mut self,
        sender: u32,
        recipient: u32,
        amount: u64,
    ) -> Result<ExpressTxReceipt, String> {
        self.validate_account_id(sender)?;
        self.validate_account_id(recipient)?;
        if amount == 0 {
            return Err("amount must be > 0".to_string());
        }
        if sender == recipient {
            return Err("self-transfer forbidden".to_string());
        }

        let sender_bal = self.bft.validators[0].ledger.balance_of(sender);
        if sender_bal < amount {
            return Err(format!(
                "insufficient express balance: account #{sender} has {sender_bal}, needs {amount}"
            ));
        }

        let (page_id, nonce) = self.alloc_page_and_nonce(sender);
        let tx = BinaryTx::new(sender, recipient, amount, page_id, nonce);

        let cert = self
            .bft
            .propose_and_finalize_batch(vec![tx])
            .map_err(|e| format!("BFT consensus failed: {e}"))?;

        let fee = self
            .tokenomics
            .collect_fee(FeeLane::Express)
            .map_err(|e| format!("tokenomics Express fee collection failed: {e}"))?;

        self.record_online_validators_contribution(EpochContribution {
            pad_pages_supplied: 1,
            beaver_triples_contributed: 0,
            blocks_finalized: 1,
            pss_refreshes_completed: 0,
        });

        self.express_txs += 1;
        self.blocks_finalized = cert.height;

        let new_sender_bal = self.bft.validators[0].ledger.balance_of(sender);
        let new_recip_bal = self.bft.validators[0].ledger.balance_of(recipient);
        let block_tag_hex = hex_encode(&cert.block_tag);

        self.push_event(format!(
            "EXPRESS BFT Block #{}: #{sender} -> #{recipient} ({amount} VRNM) | burned {} vern",
            cert.height, fee.burn_share
        ));

        Ok(ExpressTxReceipt {
            sender,
            recipient,
            amount,
            block_height: cert.height,
            leader_id: cert.leader_id,
            block_tag_hex,
            fee_vern: fee.total_fee,
            burned_vern: fee.burn_share,
            sender_balance: new_sender_bal,
            recipient_balance: new_recip_bal,
        })
    }

    /// Execute a real confidential IT-MPC Shielded Lane transfer inside `ShardedPrivateLedger`,
    /// auto-refilling `BeaverPool` when low and collecting the 80/20 `FeeLane::Shielded` pad-burn fee.
    pub fn shielded_transfer(
        &mut self,
        sender: usize,
        recipient_bucket: usize,
        recipient_slot: usize,
        amount: u64,
    ) -> Result<ShieldedTxReceipt, String> {
        if sender >= self.config.max_accounts {
            return Err(format!(
                "sender {} out of range (valid: 0..{})",
                sender, self.config.max_accounts
            ));
        }
        if recipient_bucket >= self.shielded_ledger.num_buckets() {
            return Err(format!(
                "recipient_bucket {} out of range (valid: 0..{})",
                recipient_bucket,
                self.shielded_ledger.num_buckets()
            ));
        }
        if recipient_slot >= self.shielded_ledger.bucket_size() {
            return Err(format!(
                "recipient_slot {} out of range (valid: 0..{})",
                recipient_slot,
                self.shielded_ledger.bucket_size()
            ));
        }
        if amount == 0 {
            return Err("amount must be > 0".to_string());
        }

        let sender_balance = self
            .shielded_ledger
            .reconstruct_balance(sender)
            .map_err(|e| format!("failed to read sender shielded balance: {e}"))?;
        if sender_balance < amount as u128 {
            return Err(format!(
                "insufficient shielded balance: account #{sender} has {sender_balance}, needs {amount}"
            ));
        }

        // Prevent recipient overflow past 2^bit_width - 1.
        let recip_id = self
            .shielded_ledger
            .account_id(recipient_bucket, recipient_slot)
            .map_err(|e| format!("invalid recipient location: {e}"))?;
        let recip_balance = self
            .shielded_ledger
            .reconstruct_balance(recip_id)
            .map_err(|e| format!("failed to read recipient shielded balance: {e}"))?;
        let max_val = self.max_shielded_value();
        if recip_balance.saturating_add(amount as u128) > max_val {
            return Err(format!(
                "recipient shielded balance would exceed range bound {max_val}"
            ));
        }

        // Auto-refill Beaver triple pool if low.
        let needed = self.shielded_ledger.triples_per_transfer();
        if self.beaver_pool.len() < needed {
            let refill_batch = (needed * 8).max(INITIAL_BEAVER_POOL_SIZE);
            self.beaver_pool.refill(refill_batch);
        }

        let req = ConfidentialTransferRequest::new(
            sender,
            sender_balance,
            recipient_bucket,
            recipient_slot,
            amount as u128,
            self.shielded_ledger.bucket_size(),
            self.shielded_ledger.bit_width(),
            DEFAULT_THRESHOLD,
            DEFAULT_NUM_VALIDATORS,
        )
        .map_err(|e| format!("failed to construct confidential transfer proof: {e}"))?;

        self.shielded_ledger
            .execute_sharded_transfer(&req, &mut self.beaver_pool)
            .map_err(|e| format!("IT-MPC shielded transfer failed: {e}"))?;

        let fee = self
            .tokenomics
            .collect_fee(FeeLane::Shielded)
            .map_err(|e| format!("tokenomics Shielded fee collection failed: {e}"))?;

        self.record_online_validators_contribution(EpochContribution {
            pad_pages_supplied: 2,
            beaver_triples_contributed: (needed / DEFAULT_NUM_VALIDATORS) as u64,
            blocks_finalized: 0,
            pss_refreshes_completed: 0,
        });

        self.shielded_txs += 1;
        let pss_epoch = self.shielded_ledger.epoch();

        self.push_event(format!(
            "SHIELDED MPC: Acct #{sender} -> Bucket #{recipient_bucket} (recipient & amount blinded, {needed} triples) | burned {} vern",
            fee.burn_share
        ));

        Ok(ShieldedTxReceipt {
            sender,
            recipient_bucket,
            fee_vern: fee.total_fee,
            burned_vern: fee.burn_share,
            triples_consumed: needed,
            beaver_pool_remaining: self.beaver_pool.len(),
            pss_epoch,
        })
    }

    /// Inspect an account's Express balance, reconstructed Shielded balance, and raw 127-bit
    /// random Shamir shares held by each validator (`V0..V3`).
    pub fn account_balance(&self, account_id: u32) -> Result<AccountBalanceSnapshot, String> {
        self.validate_account_id(account_id)?;
        let express_balance = self.bft.validators[0].ledger.balance_of(account_id);
        let (bucket_id, slot_in_bucket) = self
            .shielded_ledger
            .account_location(account_id as usize)
            .map_err(|e| format!("account location error: {e}"))?;
        let shares = self
            .shielded_ledger
            .balance_shares(account_id as usize)
            .map_err(|e| format!("balance shares error: {e}"))?;
        let shielded_balance = self
            .shielded_ledger
            .reconstruct_balance(account_id as usize)
            .map_err(|e| format!("reconstruct balance error: {e}"))?;

        Ok(AccountBalanceSnapshot {
            account_id,
            express_balance,
            shielded_balance,
            v0_shamir_share: format!("0x{:032x}", shares[0]),
            v1_shamir_share: format!("0x{:032x}", shares[1]),
            v2_shamir_share: format!("0x{:032x}", shares[2]),
            v3_shamir_share: format!("0x{:032x}", shares[3]),
            bucket_id,
            slot_in_bucket,
            epoch: self.shielded_ledger.epoch(),
        })
    }

    /// Execute a full epoch rotation:
    /// 1. Live BB84 + Decoy-State QKD link verification (`exchange_key`).
    /// 2. Proactive Secret Sharing refresh across every shielded balance (`proactive_refresh_epoch`).
    /// 3. Proof-of-Pad epoch settlement & reward distribution in [`TokenomicsEngine`].
    pub fn refresh_epoch(&mut self) -> Result<EpochRefreshReceipt, String> {
        let mut qkd_res = self
            .qkd_channel
            .exchange_key(32)
            .map_err(|e| format!("live BB84 QKD check failed: {e}"))?;
        let qber = qkd_res.qber;
        let qkd_sifted_bits = qkd_res.sifted_bits;
        let decoy_yield_ratio = qkd_res.decoy_yield_ratio;
        zeroize_slice(&mut qkd_res.alice_key);
        zeroize_slice(&mut qkd_res.bob_key);

        self.apply_epoch_refresh_with_qkd(qber, qkd_sifted_bits, decoy_yield_ratio)
    }

    /// Apply PSS refresh and tokenomics settlement using QKD telemetry computed outside the mutex.
    pub fn apply_epoch_refresh_with_qkd(
        &mut self,
        qber: f64,
        qkd_sifted_bits: usize,
        decoy_yield_ratio: f64,
    ) -> Result<EpochRefreshReceipt, String> {
        let new_pss_epoch = self
            .shielded_ledger
            .proactive_refresh_epoch()
            .map_err(|e| format!("PSS epoch refresh failed: {e}"))?;

        self.last_qber = qber;

        // Record PSS refresh & QKD pad availability for online validators and settle PoP epoch.
        self.record_online_validators_contribution(EpochContribution {
            pad_pages_supplied: 4,
            beaver_triples_contributed: 16,
            blocks_finalized: 1,
            pss_refreshes_completed: 1,
        });
        let settlement = self.tokenomics.settle_epoch();

        self.push_event(format!(
            "EPOCH REFRESH: PSS -> Epoch #{new_pss_epoch} | PoP Epoch #{} settled (subsidy {} vern) | BB84 QBER={:.4}%",
            settlement.epoch,
            settlement.subsidy_minted,
            qber * 100.0
        ));

        Ok(EpochRefreshReceipt {
            pss_epoch: new_pss_epoch,
            settled_tokenomics_epoch: settlement.epoch,
            subsidy_minted_vern: settlement.subsidy_minted,
            fee_rewards_distributed_vern: settlement.fee_rewards_distributed,
            fees_burned_in_epoch_vern: settlement.fees_burned_in_epoch,
            total_burned_vern: settlement.total_burned,
            qber,
            qkd_sifted_bits,
            decoy_yield_ratio,
        })
    }

    /// Serialize complete live node telemetry as JSON for `GET /status`.
    pub fn status_json(&self) -> String {
        let active_validators = self.bft.online_ids().len();
        let qkd_status = self.qkd_channel.status("testnet-mesh");

        let mut validators_json = String::from("[");
        for (i, v) in self.bft.validators.iter().enumerate() {
            if i > 0 {
                validators_json.push(',');
            }
            let vault = self.tokenomics.vault(v.id as u64);
            let (status_str, bond, rewards, voting_power) = match vault {
                Some(vlt) => (
                    validator_status_str(vlt.status),
                    vlt.bond,
                    vlt.reward_balance,
                    vlt.voting_power(),
                ),
                None => ("Unknown", 0, 0, 0),
            };
            let wot_verified = self.wot_registry.is_verified(v.id);
            validators_json.push_str(&format!(
                "{{\"id\":{},\"label\":\"V{}\",\"online\":{},\"height\":{},\"status\":\"{}\",\"voting_power\":{},\"bond_vern\":{},\"reward_balance_vern\":{},\"wot_verified\":{}}}",
                v.id, v.id, v.online, v.ledger.height, status_str, voting_power, bond, rewards, wot_verified
            ));
        }
        validators_json.push(']');

        let mut events_json = String::from("[");
        for (i, ev) in self.recent_events.iter().enumerate() {
            if i > 0 {
                events_json.push(',');
            }
            events_json.push('"');
            events_json.push_str(&json_escape(ev));
            events_json.push('"');
        }
        events_json.push(']');

        format!(
            concat!(
                "{{",
                "\"blocks_finalized\":{},",
                "\"express_txs\":{},",
                "\"shielded_txs\":{},",
                "\"pss_epoch\":{},",
                "\"tokenomics_epoch\":{},",
                "\"total_burned_vern\":{},",
                "\"circulating_supply_vern\":{},",
                "\"total_minted_vern\":{},",
                "\"last_qber\":{:.6},",
                "\"qkd_delivered_bytes\":{},",
                "\"active_validators\":{},",
                "\"verified_humans\":{},",
                "\"beaver_pool_remaining\":{},",
                "\"num_buckets\":{},",
                "\"bucket_size\":{},",
                "\"max_accounts\":{},",
                "\"validators\":{},",
                "\"recent_events\":{}",
                "}}"
            ),
            self.blocks_finalized,
            self.express_txs,
            self.shielded_txs,
            self.shielded_ledger.epoch(),
            self.tokenomics.current_epoch(),
            self.tokenomics.total_burned(),
            self.tokenomics.circulating_supply(),
            self.tokenomics.total_minted(),
            self.last_qber,
            qkd_status.total_delivered_bytes,
            active_validators,
            self.wot_registry.verified_count(),
            self.beaver_pool.len(),
            self.shielded_ledger.num_buckets(),
            self.shielded_ledger.bucket_size(),
            self.config.max_accounts,
            validators_json,
            events_json,
        )
    }
}

fn validator_status_str(status: ValidatorStatus) -> &'static str {
    match status {
        ValidatorStatus::Active => "Active",
        ValidatorStatus::Offline => "Offline",
        ValidatorStatus::Jailed => "Jailed",
        ValidatorStatus::Ejected => "Ejected",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ============================================================================
// 3. Zero-Dependency Flat JSON Parser & Escaper
// ============================================================================

/// Escape a string for safe inclusion inside a JSON string literal.
pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Find the byte offset immediately after `"key" :` inside a flat JSON object string.
fn find_json_value_start<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let bytes = json.as_bytes();
    let mut i = 0;
    let len = bytes.len();

    while i < len {
        // Locate opening quote of a JSON string token.
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let str_start = i + 1;
        i += 1;
        let mut escaped = false;
        while i < len {
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if bytes[i] == b'\\' {
                escaped = true;
                i += 1;
                continue;
            }
            if bytes[i] == b'"' {
                break;
            }
            i += 1;
        }
        if i >= len {
            return None;
        }
        let candidate_key = &json[str_start..i];
        i += 1; // Advance past closing quote.

        // Skip ASCII whitespace after the string token.
        let mut j = i;
        while j < len && bytes[j].is_ascii_whitespace() {
            j += 1;
        }

        // Only treat this quoted string as an object key if followed by `:`.
        if j < len && bytes[j] == b':' {
            j += 1;
            while j < len && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if candidate_key == key {
                return Some(&json[j..]);
            }
            i = j;
        }
    }
    None
}

/// Parse an unsigned 64-bit integer value for `key` from a flat JSON object.
pub fn parse_json_u64(json: &str, key: &str) -> Option<u64> {
    let rest = find_json_value_start(json, key)?;
    let bytes = rest.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }
    let mut end = 0;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    // Reject trailing non-delimiter characters like `123abc` or `12.5`.
    if end < bytes.len() {
        let next = bytes[end];
        if !matches!(next, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
            return None;
        }
    }
    rest[..end].parse::<u64>().ok()
}

/// Parse a string value for `key` from a flat JSON object.
pub fn parse_json_str(json: &str, key: &str) -> Option<String> {
    let rest = find_json_value_start(json, key)?;
    let mut chars = rest.chars();
    if chars.next()? != '"' {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for ch in chars {
        if escaped {
            match ch {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => out.push(other),
            }
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some(out),
            c => out.push(c),
        }
    }
    None
}

// ============================================================================
// 4. Minimal HTTP/1.1 Parser, Router & Server (`TestnetServer`)
// ============================================================================

/// Parsed HTTP/1.1 request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub body: String,
    pub auth_header: Option<String>,
}

/// Serialized HTTP/1.1 response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: &'static str,
    pub content_type: &'static str,
    pub body: String,
}

impl HttpResponse {
    fn json(status_code: u16, status_text: &'static str, body: String) -> Self {
        Self {
            status_code,
            status_text,
            content_type: "application/json; charset=utf-8",
            body,
        }
    }

    fn ok_json(body: String) -> Self {
        Self::json(200, "OK", body)
    }

    fn err_json(status_code: u16, status_text: &'static str, msg: &str) -> Self {
        Self::json(
            status_code,
            status_text,
            format!("{{\"error\":\"{}\"}}", json_escape(msg)),
        )
    }

    fn html(body: String) -> Self {
        Self {
            status_code: 200,
            status_text: "OK",
            content_type: "text/html; charset=utf-8",
            body,
        }
    }

    fn no_content() -> Self {
        Self {
            status_code: 204,
            status_text: "No Content",
            content_type: "text/plain; charset=utf-8",
            body: String::new(),
        }
    }

    /// Encode this response into an HTTP/1.1 byte buffer with CORS headers.
    pub fn to_http_bytes(&self) -> Vec<u8> {
        let cors_origin = std::env::var("VRNM_CORS_ORIGIN")
            .ok()
            .filter(|s| !s.is_empty() && !s.contains('\r') && !s.contains('\n'))
            .unwrap_or_else(|| "*".to_string());
        let header = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: {}\r\n\
             Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
             Connection: close\r\n\r\n",
            self.status_code,
            self.status_text,
            self.content_type,
            self.body.len(),
            cors_origin,
        );
        let mut buf = Vec::with_capacity(header.len() + self.body.len());
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(self.body.as_bytes());
        buf
    }
}

fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Enforce optional `VRNM_API_TOKEN` bearer authentication on mutating/admin endpoints.
/// When `VRNM_API_TOKEN` is unset or empty, requests remain open for local devnets/tests.
fn check_api_auth(req: &HttpRequest) -> Result<(), HttpResponse> {
    let Ok(expected) = std::env::var("VRNM_API_TOKEN") else {
        return Ok(());
    };
    if expected.is_empty() {
        return Ok(());
    }
    let Some(header) = req.auth_header.as_deref() else {
        return Err(HttpResponse::err_json(
            401,
            "Unauthorized",
            "missing Authorization: Bearer token",
        ));
    };
    let Some(provided) = header.strip_prefix("Bearer ") else {
        return Err(HttpResponse::err_json(
            401,
            "Unauthorized",
            "expected Authorization: Bearer <token>",
        ));
    };
    if !ct_eq_bytes(provided.as_bytes(), expected.as_bytes()) {
        return Err(HttpResponse::err_json(
            401,
            "Unauthorized",
            "invalid bearer token",
        ));
    }
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Read and parse a single HTTP/1.1 request from `stream` with an overall wall-clock deadline.
fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let deadline = Instant::now() + HTTP_READ_DEADLINE;
    let mut raw = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];

    let header_end = loop {
        if let Some(pos) = find_header_end(&raw) {
            break pos;
        }
        if raw.len() > MAX_HTTP_HEADER_BYTES {
            return Err("HTTP headers exceed maximum allowed size".to_string());
        }
        let Some(remaining_time) = deadline.checked_duration_since(Instant::now()) else {
            return Err("HTTP request read deadline exceeded".to_string());
        };
        if remaining_time.is_zero() {
            return Err("HTTP request read deadline exceeded".to_string());
        }
        let _ = stream.set_read_timeout(Some(remaining_time));
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("failed to read HTTP request: {e}"))?;
        if n == 0 {
            return Err("connection closed before HTTP header terminator".to_string());
        }
        raw.extend_from_slice(&chunk[..n]);
    };

    let header_bytes = &raw[..header_end];
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| "HTTP headers contain invalid UTF-8".to_string())?;

    let mut lines = header_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_string())?
        .to_string();
    let raw_target = parts
        .next()
        .ok_or_else(|| "missing HTTP request target".to_string())?;
    let path = raw_target
        .split('?')
        .next()
        .unwrap_or(raw_target)
        .to_string();

    let mut content_length: usize = 0;
    let mut auth_header: Option<String> = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let trimmed_name = name.trim();
            if trimmed_name.eq_ignore_ascii_case("content-length") {
                content_length = val
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid Content-Length header".to_string())?;
            } else if trimmed_name.eq_ignore_ascii_case("authorization") {
                auth_header = Some(val.trim().to_string());
            }
        }
    }
    if content_length > MAX_HTTP_BODY_BYTES {
        return Err("HTTP body exceeds maximum allowed size".to_string());
    }

    let body_start = header_end + 4;
    // Cap upfront allocation to avoid OOM from spoofed Content-Length headers.
    let mut body_bytes = Vec::with_capacity(content_length.min(8192));
    if raw.len() > body_start {
        let already = (raw.len() - body_start).min(content_length);
        body_bytes.extend_from_slice(&raw[body_start..body_start + already]);
    }
    while body_bytes.len() < content_length {
        let Some(remaining_time) = deadline.checked_duration_since(Instant::now()) else {
            return Err("HTTP request body read deadline exceeded".to_string());
        };
        if remaining_time.is_zero() {
            return Err("HTTP request body read deadline exceeded".to_string());
        }
        let _ = stream.set_read_timeout(Some(remaining_time));
        let remaining = content_length - body_bytes.len();
        let to_read = remaining.min(chunk.len());
        let n = stream
            .read(&mut chunk[..to_read])
            .map_err(|e| format!("failed to read HTTP body: {e}"))?;
        if n == 0 {
            break;
        }
        body_bytes.extend_from_slice(&chunk[..n]);
    }

    let body = String::from_utf8(body_bytes)
        .map_err(|_| "HTTP request body is not valid UTF-8".to_string())?;

    Ok(HttpRequest {
        method,
        path,
        body,
        auth_header,
    })
}

struct ConnSlotGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for ConnSlotGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_conn_slot(active: &Arc<AtomicUsize>) -> Option<ConnSlotGuard> {
    let mut current = active.load(Ordering::Acquire);
    loop {
        if current >= MAX_CONCURRENT_CONNS {
            return None;
        }
        match active.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(ConnSlotGuard {
                    active: Arc::clone(active),
                });
            }
            Err(observed) => current = observed,
        }
    }
}

/// Zero-external-crate, VPS-ready live Vernam (`VRNM`) Testnet HTTP/1.1 Server + Web Explorer.
pub struct TestnetServer {
    listener: TcpListener,
    state: Arc<Mutex<TestnetState>>,
}

impl TestnetServer {
    /// Bind a new [`TestnetServer`] on `config.bind_addr` and initialize all live Vernam engines.
    pub fn bind(config: TestnetConfig) -> io::Result<Self> {
        let bind_addr = config.bind_addr.clone();
        let state = TestnetState::new(config)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let listener = TcpListener::bind(&bind_addr)?;
        Ok(Self {
            listener,
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Return the actual bound local socket address (useful when binding `127.0.0.1:0` in tests).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Clone a handle to the shared thread-safe [`TestnetState`].
    pub fn state(&self) -> Arc<Mutex<TestnetState>> {
        Arc::clone(&self.state)
    }

    /// Accept and serve HTTP/1.1 connections indefinitely with bounded concurrency
    /// (`MAX_CONCURRENT_CONNS`), returning HTTP 503 when saturated.
    pub fn serve_forever(&self) {
        let active_conns = Arc::new(AtomicUsize::new(0));
        for stream in self.listener.incoming() {
            match stream {
                Ok(mut tcp) => {
                    let Some(slot_guard) = try_acquire_conn_slot(&active_conns) else {
                        let _ = tcp.set_write_timeout(Some(Duration::from_millis(500)));
                        let resp = HttpResponse::err_json(
                            503,
                            "Service Unavailable",
                            "server saturated: too many concurrent connections",
                        )
                        .to_http_bytes();
                        let _ = tcp.write_all(&resp);
                        let _ = tcp.flush();
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    thread::spawn(move || {
                        let _guard = slot_guard;
                        Self::handle_connection(&state, &mut tcp);
                    });
                }
                Err(_) => continue,
            }
        }
    }

    /// Accept and serve exactly `count` HTTP/1.1 requests synchronously, then exit cleanly.
    /// Ideal for deterministic integration and unit tests.
    pub fn serve_n_requests(&self, count: usize) {
        let mut served = 0;
        for stream in self.listener.incoming() {
            if served >= count {
                break;
            }
            if let Ok(mut tcp) = stream {
                Self::handle_connection(&self.state, &mut tcp);
                served += 1;
                if served >= count {
                    break;
                }
            }
        }
    }

    fn handle_connection(state: &Arc<Mutex<TestnetState>>, stream: &mut TcpStream) {
        let _ = stream.set_write_timeout(Some(HTTP_WRITE_TIMEOUT));
        let response = match read_http_request(stream) {
            Ok(req) => Self::route_request(state, &req),
            Err(err) => HttpResponse::err_json(400, "Bad Request", &err),
        };
        let bytes = response.to_http_bytes();
        let _ = stream.write_all(&bytes);
        let _ = stream.flush();
    }

    fn peers_json(guard: &TestnetState) -> String {
        let height = guard.blocks_finalized;
        let qber = guard.last_qber;
        let adv = std::env::var("VRNM_ADVERTISE")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| guard.config.bind_addr.clone());
        let adv_esc = json_escape(&adv);
        let mut arr = String::from("[");
        arr.push_str(&format!(
            "{{\"node_id\":0,\"addr\":\"{adv_esc}\",\"height\":{height},\"pop_score\":100,\"qber\":{qber:.6},\"healthy\":true}}"
        ));
        for (addr, &(nid, ph, ps, pq)) in &guard.external_peers {
            let esc = json_escape(addr);
            arr.push_str(&format!(
                ",{{\"node_id\":{nid},\"addr\":\"{esc}\",\"height\":{ph},\"pop_score\":{ps},\"qber\":{pq:.6},\"healthy\":true}}"
            ));
        }
        arr.push(']');
        arr
    }

    /// Route a parsed [`HttpRequest`] against `state` and produce an [`HttpResponse`].
    pub fn route_request(state: &Arc<Mutex<TestnetState>>, req: &HttpRequest) -> HttpResponse {
        if req.method == "OPTIONS" {
            return HttpResponse::no_content();
        }

        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") => HttpResponse::html(VERNAM_EXPLORER_HTML.to_string()),

            ("GET", "/health") => HttpResponse::ok_json(
                "{\"status\":\"ok\",\"network\":\"vernam-vrnm-testnet\",\"version\":\"0.4.0\"}"
                    .to_string(),
            ),

            ("GET", "/p2p/peers") => {
                let guard = state.lock().expect("testnet state mutex poisoned");
                HttpResponse::ok_json(Self::peers_json(&guard))
            }

            ("POST", "/p2p/announce") => {
                if let Err(resp) = check_api_auth(req) {
                    return resp;
                }
                let Some(raw_addr) = parse_json_str(&req.body, "addr") else {
                    return HttpResponse::err_json(400, "Bad Request", "missing string field 'addr'");
                };
                let trimmed = raw_addr.trim();
                if trimmed.is_empty()
                    || trimmed.len() > MAX_PEER_ADDR_LEN
                    || !trimmed.contains(':')
                    || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
                {
                    return HttpResponse::err_json(400, "Bad Request", "malformed peer 'addr'");
                }
                let node_id = parse_json_u64(&req.body, "node_id").unwrap_or(100);
                let height = parse_json_u64(&req.body, "height").unwrap_or(0);
                let pop_score = parse_json_u64(&req.body, "pop_score").unwrap_or(100);
                let mut guard = state.lock().expect("testnet state mutex poisoned");
                let self_adv = std::env::var("VRNM_ADVERTISE")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| guard.config.bind_addr.clone());
                if trimmed != self_adv && trimmed != guard.config.bind_addr {
                    let is_new = !guard.external_peers.contains_key(trimmed);
                    if is_new && guard.external_peers.len() >= MAX_EXTERNAL_PEERS {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "external peer table full",
                        );
                    }
                    guard
                        .external_peers
                        .insert(trimmed.to_string(), (node_id, height, pop_score, 0.0));
                    if is_new {
                        guard.push_event(format!("P2P PEER JOINED: node #{node_id} ({trimmed})"));
                    }
                }
                HttpResponse::ok_json(Self::peers_json(&guard))
            }

            ("POST", "/pop/mine") => {
                if let Err(resp) = check_api_auth(req) {
                    return resp;
                }
                // Read current epoch briefly, then drop mutex so /health and /status never stall
                // while PoP QKD/entropy mining & commit-then-challenge verification execute.
                let (epoch, mut last_qber) = {
                    let guard = state.lock().expect("testnet state mutex poisoned");
                    (guard.tokenomics.current_epoch(), guard.last_qber)
                };

                let mut proofs = Vec::with_capacity(4);
                let mut last_monobit_z = 0.0f64;
                let mut last_runs_z = 0.0f64;
                let mut all_valid = true;

                for vid in 0..4u64 {
                    match PopMiner::mine_pad_batch(vid, 8, 8) {
                        Ok(mut batch) => {
                            let commit = PopMiner::commit_batch(
                                &batch,
                                random_nonzero_field_elem(),
                                random_field_elem(),
                            );
                            let challenge = PopAuditor::issue_challenge(vid, epoch);
                            let proof = PopMiner::answer_challenge(&mut batch, &challenge)
                                .with_liveness(1, 1);
                            if let Ok(rcpt) = PopAuditor::verify_proof(&commit, &challenge, &proof) {
                                last_monobit_z = rcpt.entropy_stats.monobit_z_score;
                                last_runs_z = rcpt.entropy_stats.runs_z_score;
                                last_qber = rcpt.qkd_telemetry.qber;
                            } else {
                                all_valid = false;
                            }
                            proofs.push((commit, challenge, proof));
                        }
                        Err(_) => {
                            all_valid = false;
                        }
                    }
                }

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                let report = PopEpochCoordinator::run_audited_epoch(&mut guard.tokenomics, &proofs);
                let _ = guard.shielded_ledger.proactive_refresh_epoch();
                guard.last_qber = last_qber;
                guard.push_event(format!(
                    "POP MINE: epoch #{} audited {}/{} validators, subsidy={} vern, QBER={:.4}%",
                    report.settlement.epoch,
                    report.accepted.len(),
                    proofs.len(),
                    report.settlement.subsidy_minted,
                    last_qber * 100.0
                ));
                HttpResponse::ok_json(format!(
                    "{{\"status\":\"mined\",\"epoch\":{},\"pss_epoch\":{},\"audited_validators\":{},\"passed_validators\":{},\"beaver_verified\":{},\"monobit_z\":{:.4},\"runs_z\":{:.4},\"qber\":{:.6},\"subsidy_minted_vern\":{},\"total_burned_vern\":{},\"circulating_supply_vern\":{}}}",
                    report.settlement.epoch,
                    guard.shielded_ledger.epoch(),
                    proofs.len(),
                    report.accepted.len(),
                    all_valid && report.accepted.len() == proofs.len() && !proofs.is_empty(),
                    last_monobit_z,
                    last_runs_z,
                    last_qber,
                    report.settlement.subsidy_minted,
                    report.settlement.total_burned,
                    report.settlement.circulating_supply,
                ))
            }

            ("GET", "/status") => {
                let guard = state.lock().expect("testnet state mutex poisoned");
                HttpResponse::ok_json(guard.status_json())
            }

            ("POST", "/faucet") => {
                if let Err(resp) = check_api_auth(req) {
                    return resp;
                }
                let Some(account_id_u64) = parse_json_u64(&req.body, "account_id") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'account_id'",
                    );
                };
                let Ok(account_id) = u32::try_from(account_id_u64) else {
                    return HttpResponse::err_json(400, "Bad Request", "account_id exceeds u32");
                };
                let express = parse_json_u64(&req.body, "express")
                    .or_else(|| parse_json_u64(&req.body, "express_amount"))
                    .unwrap_or(0);
                let shielded = parse_json_u64(&req.body, "shielded")
                    .or_else(|| parse_json_u64(&req.body, "shielded_amount"))
                    .unwrap_or(0);

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                match guard.faucet(account_id, express, shielded) {
                    Ok(rcpt) => {
                        let bh = match rcpt.block_height {
                            Some(h) => h.to_string(),
                            None => "null".to_string(),
                        };
                        HttpResponse::ok_json(format!(
                            "{{\"status\":\"credited\",\"account_id\":{},\"express_credited\":{},\"shielded_credited\":{},\"express_balance\":{},\"shielded_balance\":{},\"block_height\":{},\"pss_epoch\":{}}}",
                            rcpt.account_id,
                            rcpt.express_credited,
                            rcpt.shielded_credited,
                            rcpt.express_balance,
                            rcpt.shielded_balance,
                            bh,
                            rcpt.pss_epoch,
                        ))
                    }
                    Err(e) => HttpResponse::err_json(400, "Bad Request", &e),
                }
            }

            ("POST", "/tx/express") => {
                if let Err(resp) = check_api_auth(req) {
                    return resp;
                }
                let Some(sender_u64) = parse_json_u64(&req.body, "sender") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'sender'",
                    );
                };
                let Some(recipient_u64) = parse_json_u64(&req.body, "recipient") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'recipient'",
                    );
                };
                let Some(amount) = parse_json_u64(&req.body, "amount") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'amount'",
                    );
                };
                let (Ok(sender), Ok(recipient)) =
                    (u32::try_from(sender_u64), u32::try_from(recipient_u64))
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "sender or recipient exceeds u32",
                    );
                };

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                match guard.express_transfer(sender, recipient, amount) {
                    Ok(rcpt) => HttpResponse::ok_json(format!(
                        "{{\"status\":\"finalized\",\"sender\":{},\"recipient\":{},\"amount\":{},\"block_height\":{},\"leader_id\":{},\"block_tag\":\"{}\",\"fee_vern\":{},\"burned_vern\":{},\"sender_balance\":{},\"recipient_balance\":{}}}",
                        rcpt.sender,
                        rcpt.recipient,
                        rcpt.amount,
                        rcpt.block_height,
                        rcpt.leader_id,
                        rcpt.block_tag_hex,
                        rcpt.fee_vern,
                        rcpt.burned_vern,
                        rcpt.sender_balance,
                        rcpt.recipient_balance,
                    )),
                    Err(e) => HttpResponse::err_json(400, "Bad Request", &e),
                }
            }

            ("POST", "/tx/shielded") => {
                if let Err(resp) = check_api_auth(req) {
                    return resp;
                }
                let Some(sender) = parse_json_u64(&req.body, "sender") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'sender'",
                    );
                };
                let Some(recipient_bucket) = parse_json_u64(&req.body, "recipient_bucket") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'recipient_bucket'",
                    );
                };
                let Some(recipient_slot) = parse_json_u64(&req.body, "recipient_slot") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'recipient_slot'",
                    );
                };
                let Some(amount) = parse_json_u64(&req.body, "amount") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'amount'",
                    );
                };

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                match guard.shielded_transfer(
                    sender as usize,
                    recipient_bucket as usize,
                    recipient_slot as usize,
                    amount,
                ) {
                    Ok(rcpt) => HttpResponse::ok_json(format!(
                        "{{\"status\":\"settled\",\"sender\":{},\"recipient_bucket\":{},\"amount_hidden\":true,\"fee_vern\":{},\"burned_vern\":{},\"triples_consumed\":{},\"beaver_pool_remaining\":{},\"pss_epoch\":{}}}",
                        rcpt.sender,
                        rcpt.recipient_bucket,
                        rcpt.fee_vern,
                        rcpt.burned_vern,
                        rcpt.triples_consumed,
                        rcpt.beaver_pool_remaining,
                        rcpt.pss_epoch,
                    )),
                    Err(e) => HttpResponse::err_json(400, "Bad Request", &e),
                }
            }

            ("POST", "/epoch/refresh") => {
                if let Err(resp) = check_api_auth(req) {
                    return resp;
                }
                // Run the live BB84 + Decoy-State QKD link check OUTSIDE the state mutex so
                // concurrent /health and /status probes never stall.
                let mut ephemeral_qkd = Bb84Channel::default_channel();
                let mut qkd_res = match ephemeral_qkd.exchange_key(32) {
                    Ok(res) => res,
                    Err(e) => {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            &format!("live BB84 QKD check failed: {e}"),
                        );
                    }
                };
                let qber = qkd_res.qber;
                let qkd_sifted_bits = qkd_res.sifted_bits;
                let decoy_yield_ratio = qkd_res.decoy_yield_ratio;
                zeroize_slice(&mut qkd_res.alice_key);
                zeroize_slice(&mut qkd_res.bob_key);

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                match guard.apply_epoch_refresh_with_qkd(qber, qkd_sifted_bits, decoy_yield_ratio)
                {
                    Ok(rcpt) => HttpResponse::ok_json(format!(
                        "{{\"status\":\"refreshed\",\"pss_epoch\":{},\"settled_tokenomics_epoch\":{},\"subsidy_minted_vern\":{},\"fee_rewards_distributed_vern\":{},\"fees_burned_in_epoch_vern\":{},\"total_burned_vern\":{},\"qber\":{:.6},\"qkd_sifted_bits\":{},\"decoy_yield_ratio\":{:.6}}}",
                        rcpt.pss_epoch,
                        rcpt.settled_tokenomics_epoch,
                        rcpt.subsidy_minted_vern,
                        rcpt.fee_rewards_distributed_vern,
                        rcpt.fees_burned_in_epoch_vern,
                        rcpt.total_burned_vern,
                        rcpt.qber,
                        rcpt.qkd_sifted_bits,
                        rcpt.decoy_yield_ratio,
                    )),
                    Err(e) => HttpResponse::err_json(400, "Bad Request", &e),
                }
            }

            ("GET", path) if path.starts_with("/balance/") => {
                let id_str = &path["/balance/".len()..];
                let Ok(account_id) = id_str.parse::<u32>() else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "invalid account_id in /balance/<id>",
                    );
                };
                let guard = state.lock().expect("testnet state mutex poisoned");
                match guard.account_balance(account_id) {
                    Ok(snap) => HttpResponse::ok_json(format!(
                        "{{\"account_id\":{},\"express_balance\":{},\"shielded_balance\":{},\"v0_shamir_share\":\"{}\",\"v1_shamir_share\":\"{}\",\"v2_shamir_share\":\"{}\",\"v3_shamir_share\":\"{}\",\"bucket_id\":{},\"slot_in_bucket\":{},\"epoch\":{}}}",
                        snap.account_id,
                        snap.express_balance,
                        snap.shielded_balance,
                        snap.v0_shamir_share,
                        snap.v1_shamir_share,
                        snap.v2_shamir_share,
                        snap.v3_shamir_share,
                        snap.bucket_id,
                        snap.slot_in_bucket,
                        snap.epoch,
                    )),
                    Err(e) => HttpResponse::err_json(400, "Bad Request", &e),
                }
            }

            _ => HttpResponse::err_json(
                404,
                "Not Found",
                &format!("unknown endpoint: {} {}", req.method, req.path),
            ),
        }
    }
}

// ============================================================================
// 6. Comprehensive End-to-End TCP/HTTP Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Send a raw HTTP/1.1 request over TCP and return `(status_code, raw_headers, body)`.
    fn send_raw_http(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, String, String) {
        let mut stream = TcpStream::connect(addr).expect("failed to connect to TestnetServer");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");

        let req = if body.is_empty() {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
        } else {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        stream.write_all(req.as_bytes()).expect("write HTTP request");
        stream.flush().expect("flush HTTP request");

        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read HTTP response");
        let resp_str = String::from_utf8(resp).expect("UTF-8 HTTP response");

        let (headers, resp_body) = resp_str
            .split_once("\r\n\r\n")
            .expect("HTTP response missing CRLFCRLF delimiter");
        let status_line = headers.lines().next().expect("missing status line");
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .expect("missing status code")
            .parse::<u16>()
            .expect("invalid status code");

        (status_code, headers.to_string(), resp_body.to_string())
    }

    #[test]
    fn test_flat_json_helpers() {
        let j = r#"{"account_id": 2, "id": 99, "label": "vernam\"node", "express": 1000}"#;
        assert_eq!(parse_json_u64(j, "account_id"), Some(2));
        assert_eq!(parse_json_u64(j, "id"), Some(99));
        assert_eq!(parse_json_u64(j, "express"), Some(1000));
        assert_eq!(parse_json_u64(j, "missing"), None);
        assert_eq!(parse_json_str(j, "label").as_deref(), Some("vernam\"node"));
        assert_eq!(parse_json_str(j, "account_id"), None);
    }

    #[test]
    fn test_live_testnet_server_full_http_lifecycle() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
        };
        let server = TestnetServer::bind(config).expect("bind TestnetServer on ephemeral port");
        let addr = server.local_addr().expect("local_addr");

        // Total HTTP requests we will send in this end-to-end test: 11.
        let handle = thread::spawn(move || {
            server.serve_n_requests(11);
        });

        // 1. GET /health
        let (code, headers, body) = send_raw_http(addr, "GET", "/health", "");
        assert_eq!(code, 200);
        assert!(headers.contains("Access-Control-Allow-Origin: *"));
        assert_eq!(
            body,
            r#"{"status":"ok","network":"vernam-vrnm-testnet","version":"0.4.0"}"#
        );

        // 2. GET / (Dark-mode interactive explorer HTML)
        let (code, headers, body) = send_raw_http(addr, "GET", "/", "");
        assert_eq!(code, 200);
        assert!(headers.contains("text/html"));
        assert!(body.contains("Vernam (VRNM) Live Testnet Explorer"));
        assert!(body.contains("/tx/shielded"));

        // 3. POST /faucet for account 1 (1000 express + 500 shielded)
        let (code, _, body) = send_raw_http(
            addr,
            "POST",
            "/faucet",
            r#"{"account_id":1,"express":1000,"shielded":500}"#,
        );
        assert_eq!(code, 200, "faucet failed: {body}");
        assert_eq!(parse_json_u64(&body, "account_id"), Some(1));
        assert_eq!(parse_json_u64(&body, "express_balance"), Some(1000));
        assert_eq!(parse_json_u64(&body, "shielded_balance"), Some(500));
        assert_eq!(parse_json_u64(&body, "block_height"), Some(1));

        // 4. POST /tx/express (1 -> 2, amount 50)
        let (code, _, body) = send_raw_http(
            addr,
            "POST",
            "/tx/express",
            r#"{"sender":1,"recipient":2,"amount":50}"#,
        );
        assert_eq!(code, 200, "express tx failed: {body}");
        assert_eq!(parse_json_str(&body, "status").as_deref(), Some("finalized"));
        assert_eq!(parse_json_u64(&body, "block_height"), Some(2));
        assert_eq!(parse_json_u64(&body, "sender_balance"), Some(950));
        assert_eq!(parse_json_u64(&body, "recipient_balance"), Some(50));
        assert_eq!(parse_json_u64(&body, "burned_vern"), Some(2_000));

        // 5. POST /tx/shielded (sender 1 -> bucket 0, slot 2 [= account 2], amount 25)
        let (code, _, body) = send_raw_http(
            addr,
            "POST",
            "/tx/shielded",
            r#"{"sender":1,"recipient_bucket":0,"recipient_slot":2,"amount":25}"#,
        );
        assert_eq!(code, 200, "shielded tx failed: {body}");
        assert_eq!(parse_json_str(&body, "status").as_deref(), Some("settled"));
        assert_eq!(parse_json_u64(&body, "triples_consumed"), Some(65));
        assert_eq!(parse_json_u64(&body, "burned_vern"), Some(50_000));

        // 6. GET /balance/2 before PSS epoch refresh
        let (code, _, body) = send_raw_http(addr, "GET", "/balance/2", "");
        assert_eq!(code, 200, "balance/2 failed: {body}");
        assert_eq!(parse_json_u64(&body, "account_id"), Some(2));
        assert_eq!(parse_json_u64(&body, "express_balance"), Some(50));
        assert_eq!(parse_json_u64(&body, "shielded_balance"), Some(25));
        assert_eq!(parse_json_u64(&body, "epoch"), Some(1));
        let v0_before = parse_json_str(&body, "v0_shamir_share").expect("v0 share");
        let v1_before = parse_json_str(&body, "v1_shamir_share").expect("v1 share");
        assert!(v0_before.starts_with("0x") && v0_before.len() == 34);
        assert!(v1_before.starts_with("0x") && v1_before.len() == 34);

        // 7. POST /epoch/refresh (PSS refresh + PoP epoch settlement + live BB84 check)
        let (code, _, body) = send_raw_http(addr, "POST", "/epoch/refresh", "{}");
        assert_eq!(code, 200, "epoch refresh failed: {body}");
        assert_eq!(parse_json_str(&body, "status").as_deref(), Some("refreshed"));
        assert_eq!(parse_json_u64(&body, "pss_epoch"), Some(2));
        assert_eq!(parse_json_u64(&body, "settled_tokenomics_epoch"), Some(0));
        assert!(parse_json_u64(&body, "subsidy_minted_vern").unwrap() > 0);
        assert_eq!(parse_json_u64(&body, "total_burned_vern"), Some(52_000));

        // 8. GET /balance/2 after PSS refresh — balances invariant, Shamir shares rotated!
        let (code, _, body) = send_raw_http(addr, "GET", "/balance/2", "");
        assert_eq!(code, 200);
        assert_eq!(parse_json_u64(&body, "express_balance"), Some(50));
        assert_eq!(parse_json_u64(&body, "shielded_balance"), Some(25));
        assert_eq!(parse_json_u64(&body, "epoch"), Some(2));
        let v0_after = parse_json_str(&body, "v0_shamir_share").expect("v0 share after");
        let v1_after = parse_json_str(&body, "v1_shamir_share").expect("v1 share after");
        assert_ne!(v0_before, v0_after, "PSS must rotate V0's Shamir share");
        assert_ne!(v1_before, v1_after, "PSS must rotate V1's Shamir share");

        // 9. GET /status — verify aggregated telemetry across all engines
        let (code, _, body) = send_raw_http(addr, "GET", "/status", "");
        assert_eq!(code, 200, "status failed: {body}");
        assert_eq!(parse_json_u64(&body, "blocks_finalized"), Some(2));
        assert_eq!(parse_json_u64(&body, "express_txs"), Some(1));
        assert_eq!(parse_json_u64(&body, "shielded_txs"), Some(1));
        assert_eq!(parse_json_u64(&body, "pss_epoch"), Some(2));
        assert_eq!(parse_json_u64(&body, "total_burned_vern"), Some(52_000));
        assert_eq!(parse_json_u64(&body, "active_validators"), Some(4));
        assert_eq!(parse_json_u64(&body, "verified_humans"), Some(4));
        assert!(body.contains("recent_events"));

        // 10. Clean 400 error on invalid JSON / overdraft
        let (code, _, body) = send_raw_http(
            addr,
            "POST",
            "/tx/express",
            r#"{"sender":2,"recipient":1,"amount":999999}"#,
        );
        assert_eq!(code, 400);
        assert!(body.contains("insufficient express balance"));

        // 11. Clean 404 error on unknown route
        let (code, _, body) = send_raw_http(addr, "GET", "/does-not-exist", "");
        assert_eq!(code, 404);
        assert!(body.contains("unknown endpoint"));

        handle.join().expect("server thread exited cleanly");
    }

    #[test]
    fn test_faucet_account_zero_beaver_auto_refill_and_event_ring_cap() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
        };
        let mut state = TestnetState::new(config).expect("init TestnetState");

        // Account 0 must work via Treasury u32::MAX -> 0 BFT transfer without self-transfer error.
        let f0 = state.faucet(0, 500, 1000).expect("faucet account 0");
        assert_eq!(f0.express_balance, 500);
        assert_eq!(f0.shielded_balance, 1000);
        assert_eq!(f0.block_height, Some(1));

        // Run 10 shielded transfers (10 * 65 = 650 triples > INITIAL_BEAVER_POOL_SIZE 512)
        // to prove automatic BeaverPool replenishment and exact balance conservation.
        for _ in 0..10 {
            let rcpt = state
                .shielded_transfer(0, 1, 3, 10)
                .expect("shielded transfer with auto-refill");
            assert_eq!(rcpt.triples_consumed, 65);
        }
        assert_eq!(state.shielded_txs, 10);
        assert_eq!(state.account_balance(0).unwrap().shielded_balance, 900);
        // Bucket 1, slot 3 == account 1 * 16 + 3 = 19.
        assert_eq!(state.account_balance(19).unwrap().shielded_balance, 100);

        // Push extra events to ensure recent_events ring buffer stays strictly capped at 20.
        for i in 0..25 {
            state.push_event(format!("EVENT #{i}"));
        }
        assert_eq!(state.recent_events.len(), MAX_RECENT_EVENTS);
        assert_eq!(state.recent_events.last().unwrap(), "EVENT #24");

        // Tokenomics accounting invariants must hold to the exact vern.
        state
            .tokenomics
            .check_invariants()
            .expect("tokenomics invariants hold");
    }

    #[test]
    fn test_cors_options_preflight() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
        };
        let server = TestnetServer::bind(config).expect("bind server");
        let addr = server.local_addr().expect("local_addr");
        let handle = thread::spawn(move || server.serve_n_requests(1));

        let (code, headers, body) = send_raw_http(addr, "OPTIONS", "/tx/express", "");
        assert_eq!(code, 204);
        assert!(headers.contains("Access-Control-Allow-Origin: *"));
        assert!(headers.contains("Access-Control-Allow-Methods: GET, POST, OPTIONS"));
        assert!(body.is_empty());

        handle.join().expect("server thread exited cleanly");
    }

    #[test]
    fn test_testnet_server_faucet_caps_peer_caps_and_pop_mine() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
        };
        let state = Arc::new(Mutex::new(TestnetState::new(config).expect("init state")));

        // Faucet caps enforce MAX_FAUCET_EXPRESS and MAX_FAUCET_SHIELDED.
        {
            let mut g = state.lock().unwrap();
            assert!(g.faucet(1, MAX_FAUCET_EXPRESS + 1, 0).is_err());
            assert!(g.faucet(1, 0, MAX_FAUCET_SHIELDED + 1).is_err());
            assert!(g.faucet(1, MAX_FAUCET_EXPRESS, MAX_FAUCET_SHIELDED).is_ok());
        }

        // /p2p/announce rejects oversized peer addr (> 128 chars) and caps external_peers at 64.
        let long_addr = format!("{}:8080", "a".repeat(130));
        let resp_long = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/p2p/announce".to_string(),
                body: format!("{{\"addr\":\"{long_addr}\",\"node_id\":1}}"),
                auth_header: None,
            },
        );
        assert_eq!(resp_long.status_code, 400);

        for i in 0..MAX_EXTERNAL_PEERS {
            let resp = TestnetServer::route_request(
                &state,
                &HttpRequest {
                    method: "POST".to_string(),
                    path: "/p2p/announce".to_string(),
                    body: format!("{{\"addr\":\"10.0.0.1:{}\",\"node_id\":{}}}", 9000 + i, i),
                    auth_header: None,
                },
            );
            assert_eq!(resp.status_code, 200);
        }
        let resp_overflow = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/p2p/announce".to_string(),
                body: "{\"addr\":\"10.0.0.1:9999\",\"node_id\":999}".to_string(),
                auth_header: None,
            },
        );
        assert_eq!(resp_overflow.status_code, 400);

        // /pop/mine runs PoP commit-then-challenge outside the lock and settles cleanly.
        let resp_pop = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/pop/mine".to_string(),
                body: "{}".to_string(),
                auth_header: None,
            },
        );
        assert_eq!(resp_pop.status_code, 200, "pop mine failed: {}", resp_pop.body);
        assert!(resp_pop.body.contains("\"beaver_verified\":true"));
        assert_eq!(parse_json_u64(&resp_pop.body, "passed_validators"), Some(4));
        assert_eq!(parse_json_u64(&resp_pop.body, "audited_validators"), Some(4));
    }
}
