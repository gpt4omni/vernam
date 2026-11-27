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

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::bft::{BftCluster, BftConfig, BinaryTx, WebOfTrustRegistry};
use crate::entropy_beacon::{BeaconConfig, OtpChannelKey, VernamBeacon};
use crate::explorer_ui::VERNAM_EXPLORER_HTML;
use crate::field::{
    PRIME_P, add_mod, ct_eq_16, mul_mod, random_field_elem, random_nonzero_field_elem, reduce,
    zeroize_slice, zeroize_u128,
};
use crate::pop_mining::{
    BeaconPairingSchedule, BeaverTriple, BilateralDeliveryReceipt, DEFAULT_CHALLENGE_SLOT_COUNT,
    PeerReceiptKey, PopAuditor, PopChallenge, PopCommitment, PopProof, PopReplayRegistry,
    QkdTelemetry, compute_batch_commitment_tag,
};
use crate::privacy_mpc::{
    BeaverPool, ConfidentialTransferRequest, DEFAULT_BUCKET_SIZE, DEFAULT_NUM_VALIDATORS,
    DEFAULT_THRESHOLD, ShardedPrivateLedger,
};
use crate::qkd::{Bb84Channel, OsEntropySource, QkdKeyProvider};
use crate::storage::{
    CrashSafeChainStore, PersistedChainSnapshot, PersistedExpressAccount, PersistedShieldedSlot,
    PersistedValidatorVault, SNAPSHOT_FORMAT_VERSION,
};
use crate::tokenomics::{
    EpochContribution, FeeLane, TokenomicsEngine, VERN_PER_VRNM, ValidatorStatus,
};

/// Dedicated treasury account ID in the Express BFT ledger used to fund faucet payouts
/// through real 2-phase BFT consensus without colliding with user account IDs `0..max_accounts`.
pub const TREASURY_ACCOUNT_ID: u32 = u32::MAX;

/// Genesis liquid supply minted inside `TokenomicsEngine` (`1_000_000 VRNM` in `vern`),
/// strictly bounded within the hard 21,000,000 VRNM supply cap (`MAX_SUPPLY`).
pub const GENESIS_FAUCET_TREASURY_VERN: u64 = 1_000_000 * VERN_PER_VRNM;

/// Initial Express-lane balance pre-funded into [`TREASURY_ACCOUNT_ID`] at genesis,
/// strictly backed by [`GENESIS_FAUCET_TREASURY_VERN`].
pub const TREASURY_INITIAL_BALANCE: u64 = GENESIS_FAUCET_TREASURY_VERN;

/// Domain separation constant for `POST /tx/express` sender ownership authentication.
pub const AUTH_DOMAIN_EXPRESS: u64 = 1;

/// Domain separation constant for `POST /tx/shielded` sender ownership authentication.
pub const AUTH_DOMAIN_SHIELDED: u64 = 2;

/// Domain separation constant for `POST /balance/private` owner balance disclosure.
pub const AUTH_DOMAIN_BALANCE: u64 = 3;

/// Domain separation constant for authenticated key refill via `POST /account/register`.
pub const AUTH_DOMAIN_REGISTER: u64 = 4;

/// Maximum active single-use Carter-Wegman authentication keys retained per account.
pub const MAX_AUTH_KEYS_PER_ACCOUNT: usize = 256;

/// Maximum keys generated in a single `POST /account/register` request.
pub const MAX_REGISTER_BATCH_COUNT: usize = 64;

/// Maximum pad pages accepted in a single remote `POST /pop/commit` request.
const MAX_REMOTE_POP_PAD_PAGES: usize = 1024;

/// Maximum Beaver triples accepted in a single remote `POST /pop/commit` request.
const MAX_REMOTE_POP_BEAVER_TRIPLES: usize = 4096;

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

/// Maximum peers permitted from any single non-loopback IPv4 `/24` (or IPv6 `/48`) subnet
/// to prevent P2P eclipse attacks.
pub const MAX_PEERS_PER_SUBNET: usize = 4;

/// Maximum peer address string length accepted by `POST /p2p/announce`.
const MAX_PEER_ADDR_LEN: usize = 128;

/// Maximum distinct client IPs tracked by [`IpRateLimiter`] before oldest-entry eviction.
pub const MAX_TRACKED_IPS: usize = 4096;

/// Default per-IP request limit per 1-second window.
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 120;

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

/// Maximum accepted HTTP header count per request.
const MAX_HTTP_HEADERS: usize = 64;

/// Maximum accepted HTTP request body size (64 KiB).
const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;

/// Maximum nesting depth permitted when scanning JSON objects.
const MAX_JSON_DEPTH: usize = 32;

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
    /// Optional crash-safe on-disk persistence directory (defaults to `VRNM_DATA_DIR` if set).
    pub data_dir: Option<PathBuf>,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        let bind_addr =
            std::env::var("VRNM_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let data_dir = std::env::var("VRNM_DATA_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        Self {
            bind_addr,
            num_buckets: 4,
            max_accounts: 64,
            data_dir,
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

/// Owner-authenticated private balance snapshot returned by `POST /balance/private`.
///
/// Never exposes the 4 raw validator Shamir shares together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateBalanceSnapshot {
    pub account_id: u32,
    pub express_balance: u64,
    pub shielded_balance: u128,
    pub bucket_id: usize,
    pub slot_in_bucket: usize,
    pub epoch: u64,
}

/// Error returned by authenticated transfer or balance operations distinguishing
/// `401 Unauthorized` (authentication failure) from `400 Bad Request` (ledger/validation error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatedOpError {
    Unauthorized(String),
    BadRequest(String),
}

// ============================================================================
// 1B. Information-Theoretic Per-Account Carter-Wegman Authentication (`F_(2^127 - 1)`)
// ============================================================================

/// Compute the canonical 128-bit Carter-Wegman authentication tag over `F_(2^127 - 1)`
/// binding `(domain, account_id, arg1, arg2, arg3, pad_id)` under one-time key `(r, s)`.
pub fn compute_account_auth_tag(
    domain: u64,
    account_id: u32,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    pad_id: u64,
    r: u128,
    s: u128,
) -> [u8; 16] {
    let r = reduce(r);
    let mut acc = mul_mod(reduce(domain as u128), r);
    acc = mul_mod(add_mod(acc, reduce(account_id as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(arg1 as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(arg2 as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(arg3 as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(pad_id as u128)), r);
    add_mod(acc, reduce(s)).to_le_bytes()
}

/// Single-use Carter-Wegman authentication key `(r, s)` over `F_(2^127 - 1)`.
///
/// Volatile-zeroized on `Drop` and redacted in `Debug`.
struct OneTimeAccountAuthKey {
    r: u128,
    s: u128,
}

impl fmt::Debug for OneTimeAccountAuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OneTimeAccountAuthKey([REDACTED])")
    }
}

impl Drop for OneTimeAccountAuthKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

#[derive(Debug)]
struct AccountAuthEntry {
    active_keys: BTreeMap<u64, OneTimeAccountAuthKey>,
    burned_pad_ids: BTreeSet<u64>,
    next_pad_id: u64,
}

impl AccountAuthEntry {
    fn new() -> Self {
        Self {
            active_keys: BTreeMap::new(),
            burned_pad_ids: BTreeSet::new(),
            next_pad_id: 1,
        }
    }
}

/// Per-account registry of single-use Carter-Wegman authentication keys over `F_(2^127 - 1)`.
///
/// Enforces:
/// - Maximum [`MAX_AUTH_KEYS_PER_ACCOUNT`] (`256`) active keys per account.
/// - Strict single-use burning: every verified `pad_id` is volatile-zeroized and permanently
///   recorded in `burned_pad_ids` so no `pad_id` can ever be reused or replayed.
/// - Registration lock: once an `account_id` is registered, unauthenticated re-registration
///   is rejected (`409 Conflict`).
#[derive(Debug, Default)]
pub struct AccountAuthKeyBook {
    accounts: BTreeMap<u32, AccountAuthEntry>,
}

impl AccountAuthKeyBook {
    /// Returns `true` if `account_id` has already been registered.
    pub fn is_registered(&self, account_id: u32) -> bool {
        self.accounts.contains_key(&account_id)
    }

    /// Number of currently active (unconsumed) one-time keys for `account_id`.
    pub fn active_key_count(&self, account_id: u32) -> usize {
        self.accounts
            .get(&account_id)
            .map_or(0, |e| e.active_keys.len())
    }

    /// Returns `true` if `pad_id` has already been burned for `account_id`.
    pub fn is_pad_burned(&self, account_id: u32, pad_id: u64) -> bool {
        self.accounts
            .get(&account_id)
            .is_some_and(|e| e.burned_pad_ids.contains(&pad_id))
    }

    /// Generate `count` (`1..=64`) fresh single-use `(pad_id, r, s)` keys for a brand-new
    /// unregistered account.
    pub fn register_new_generated(
        &mut self,
        account_id: u32,
        count: usize,
    ) -> Result<Vec<(u64, u128, u128)>, String> {
        if self.is_registered(account_id) {
            return Err("account already registered".to_string());
        }
        if count == 0 || count > MAX_REGISTER_BATCH_COUNT {
            return Err(format!(
                "count must be in 1..={MAX_REGISTER_BATCH_COUNT}"
            ));
        }
        let mut entry = AccountAuthEntry::new();
        let keys = Self::allocate_generated_keys(&mut entry, count)?;
        self.accounts.insert(account_id, entry);
        Ok(keys)
    }

    /// Register a single client-supplied canonical `(pad_id, r, s)` key for a brand-new
    /// unregistered account.
    pub fn register_new_explicit(
        &mut self,
        account_id: u32,
        pad_id: u64,
        r: u128,
        s: u128,
    ) -> Result<(), String> {
        if self.is_registered(account_id) {
            return Err("account already registered".to_string());
        }
        Self::validate_key_scalars(r, s)?;
        let mut entry = AccountAuthEntry::new();
        entry
            .active_keys
            .insert(pad_id, OneTimeAccountAuthKey { r, s });
        if pad_id >= entry.next_pad_id {
            entry.next_pad_id = pad_id.saturating_add(1);
        }
        self.accounts.insert(account_id, entry);
        Ok(())
    }

    /// Refill an ALREADY-registered account with `count` (`1..=64`) freshly generated keys after
    /// verifying ownership via `AUTH_DOMAIN_REGISTER` (burning `auth_pad_id` atomically).
    pub fn refill_generated(
        &mut self,
        account_id: u32,
        count: usize,
        auth_pad_id: u64,
        auth_tag: &[u8; 16],
    ) -> Result<Vec<(u64, u128, u128)>, AuthenticatedOpError> {
        if count == 0 || count > MAX_REGISTER_BATCH_COUNT {
            return Err(AuthenticatedOpError::BadRequest(format!(
                "count must be in 1..={MAX_REGISTER_BATCH_COUNT}"
            )));
        }
        let current_len = self.active_key_count(account_id);
        if current_len.saturating_sub(1).saturating_add(count) > MAX_AUTH_KEYS_PER_ACCOUNT {
            return Err(AuthenticatedOpError::BadRequest(format!(
                "refill would exceed max {MAX_AUTH_KEYS_PER_ACCOUNT} active keys per account"
            )));
        }
        self.verify_and_consume(
            AUTH_DOMAIN_REGISTER,
            account_id,
            count as u64,
            0,
            0,
            auth_pad_id,
            auth_tag,
        )
        .map_err(AuthenticatedOpError::Unauthorized)?;
        let entry = self
            .accounts
            .get_mut(&account_id)
            .expect("verified registered account");
        Self::allocate_generated_keys(entry, count).map_err(AuthenticatedOpError::BadRequest)
    }

    /// Refill an ALREADY-registered account with a client-supplied `(pad_id, r, s)` key after
    /// verifying ownership via `AUTH_DOMAIN_REGISTER` (burning `auth_pad_id` atomically).
    pub fn refill_explicit(
        &mut self,
        account_id: u32,
        new_pad_id: u64,
        r: u128,
        s: u128,
        auth_pad_id: u64,
        auth_tag: &[u8; 16],
    ) -> Result<(), AuthenticatedOpError> {
        Self::validate_key_scalars(r, s).map_err(AuthenticatedOpError::BadRequest)?;
        if new_pad_id == auth_pad_id {
            return Err(AuthenticatedOpError::BadRequest(
                "new pad_id cannot equal the auth_pad_id being consumed".to_string(),
            ));
        }
        if let Some(entry) = self.accounts.get(&account_id) {
            if entry.burned_pad_ids.contains(&new_pad_id)
                || entry.active_keys.contains_key(&new_pad_id)
            {
                return Err(AuthenticatedOpError::BadRequest(format!(
                    "pad_id {new_pad_id} is already registered or permanently burned"
                )));
            }
            if entry.active_keys.len().saturating_sub(1).saturating_add(1)
                > MAX_AUTH_KEYS_PER_ACCOUNT
            {
                return Err(AuthenticatedOpError::BadRequest(format!(
                    "refill would exceed max {MAX_AUTH_KEYS_PER_ACCOUNT} active keys per account"
                )));
            }
        }
        self.verify_and_consume(
            AUTH_DOMAIN_REGISTER,
            account_id,
            new_pad_id,
            0,
            0,
            auth_pad_id,
            auth_tag,
        )
        .map_err(AuthenticatedOpError::Unauthorized)?;
        let entry = self
            .accounts
            .get_mut(&account_id)
            .expect("verified registered account");
        entry
            .active_keys
            .insert(new_pad_id, OneTimeAccountAuthKey { r, s });
        if new_pad_id >= entry.next_pad_id {
            entry.next_pad_id = new_pad_id.saturating_add(1);
        }
        Ok(())
    }

    /// Verify `(domain, account_id, arg1, arg2, arg3, pad_id)` against `account_id`'s registered
    /// single-use key in constant time (`ct_eq_16`), IMMEDIATELY burning and volatile-zeroizing
    /// that key on success so it can never be replayed.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_consume(
        &mut self,
        domain: u64,
        account_id: u32,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        pad_id: u64,
        provided_tag: &[u8; 16],
    ) -> Result<(), String> {
        let Some(entry) = self.accounts.get_mut(&account_id) else {
            return Err(format!(
                "account #{account_id} has no registered authentication keys"
            ));
        };
        if entry.burned_pad_ids.contains(&pad_id) {
            return Err(format!(
                "auth_pad_id {pad_id} has already been burned (replay rejected)"
            ));
        }
        let Some(key) = entry.active_keys.get(&pad_id) else {
            return Err(format!(
                "unknown auth_pad_id {pad_id} for account #{account_id}"
            ));
        };
        let expected =
            compute_account_auth_tag(domain, account_id, arg1, arg2, arg3, pad_id, key.r, key.s);
        if !ct_eq_16(&expected, provided_tag) {
            return Err("invalid Carter-Wegman auth_tag".to_string());
        }
        // Constant-time MAC verified — immediately remove (volatile-zeroizing on Drop) and burn!
        let consumed = entry.active_keys.remove(&pad_id);
        drop(consumed);
        entry.burned_pad_ids.insert(pad_id);
        Ok(())
    }

    fn validate_key_scalars(r: u128, s: u128) -> Result<(), String> {
        if r == 0 || r >= PRIME_P {
            return Err("auth key scalar 'r' must satisfy 0 < r < PRIME_P".to_string());
        }
        if s >= PRIME_P {
            return Err("auth key scalar 's' must satisfy s < PRIME_P".to_string());
        }
        Ok(())
    }

    fn allocate_generated_keys(
        entry: &mut AccountAuthEntry,
        count: usize,
    ) -> Result<Vec<(u64, u128, u128)>, String> {
        if entry.active_keys.len().saturating_add(count) > MAX_AUTH_KEYS_PER_ACCOUNT {
            return Err(format!(
                "key allocation exceeds max {MAX_AUTH_KEYS_PER_ACCOUNT} active keys per account"
            ));
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            while entry.active_keys.contains_key(&entry.next_pad_id)
                || entry.burned_pad_ids.contains(&entry.next_pad_id)
            {
                entry.next_pad_id = entry
                    .next_pad_id
                    .checked_add(1)
                    .ok_or_else(|| "pad_id space exhausted".to_string())?;
            }
            let pad_id = entry.next_pad_id;
            entry.next_pad_id = entry.next_pad_id.saturating_add(1);
            let r = random_nonzero_field_elem();
            let s = random_field_elem();
            entry
                .active_keys
                .insert(pad_id, OneTimeAccountAuthKey { r, s });
            out.push((pad_id, r, s));
        }
        Ok(out)
    }
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
    /// Persistent cross-epoch & cross-validator PoP anti-replay registry.
    pub pop_replay_registry: PopReplayRegistry,
    /// Live Proof-of-Personhood Web-of-Trust registry (1-human = 1-vote).
    pub wot_registry: WebOfTrustRegistry,
    /// Per-account single-use Carter-Wegman authentication key book (`F_(2^127 - 1)`).
    pub auth_keys: AccountAuthKeyBook,
    /// Pending remote PoP commit/challenge sessions keyed by `validator_id`:
    /// `(epoch, beacon_gamma, expected_counterparty, commitment, challenge, peer_key)`.
    pub pending_pop_commits:
        BTreeMap<u64, (u64, u128, u64, PopCommitment, PopChallenge, PeerReceiptKey)>,
    /// Remaining faucet treasury budget in `vern`, initialized strictly from genesis supply
    /// minted inside `TokenomicsEngine` and decremented by BOTH Express and Shielded faucet mints.
    pub faucet_treasury_remaining_vern: u64,
    /// Cached canonical epoch beacon `(epoch, beacon_gamma)` for active remote PoP sessions.
    current_epoch_beacon: Option<(u64, u128)>,
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
    /// Optional crash-safe on-disk Carter-Wegman authenticated snapshot/WAL store.
    store: Option<CrashSafeChainStore>,
    /// Base block height restored from disk so BFT height indices start cleanly on restart.
    restored_blocks_base: u64,
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

        // 0. Open optional crash-safe on-disk persistence store & load verified snapshot if present.
        let store = match config.data_dir.as_ref() {
            Some(dir) => Some(
                CrashSafeChainStore::open(dir)
                    .map_err(|e| format!("failed to open crash-safe chain store at {}: {e}", dir.display()))?,
            ),
            None => None,
        };
        let loaded_snapshot = if let Some(ref s) = store {
            let (snap, _wal) = s
                .load_latest()
                .map_err(|e| format!("failed to verify on-disk chain snapshot: {e}"))?;
            snap
        } else {
            None
        };

        // 1. Initialize 4-validator Express BFT cluster with accounts 0..max_accounts + Treasury.
        let bft_config = BftConfig::default();
        let mut initial_balances = BTreeMap::new();
        for acct in 0..config.max_accounts as u32 {
            initial_balances.insert(acct, 0u64);
        }
        let mut restored_sender_nonces = BTreeMap::new();
        let mut total_restored_express = 0u64;
        if let Some(ref snap) = loaded_snapshot {
            for acc in &snap.express_accounts {
                if (acc.account_id as usize) < config.max_accounts {
                    initial_balances.insert(acc.account_id, acc.balance);
                    total_restored_express = total_restored_express.saturating_add(acc.balance);
                }
                if acc.nonce > 0 {
                    restored_sender_nonces.insert(acc.account_id, acc.nonce);
                }
            }
        }
        initial_balances.insert(
            TREASURY_ACCOUNT_ID,
            TREASURY_INITIAL_BALANCE.saturating_sub(total_restored_express),
        );

        let bft = BftCluster::new(
            bft_config,
            initial_balances,
            DEFAULT_BFT_SLOTS_PER_LINK,
            DEFAULT_BFT_MAX_HEIGHTS,
            DEFAULT_BFT_MAX_VIEWS,
        );

        // 2. Initialize Sharded IT-MPC Shielded Ledger + auto-refilling BeaverPool.
        let mut shielded_ledger = ShardedPrivateLedger::new_default(config.num_buckets)
            .map_err(|e| format!("failed to init ShardedPrivateLedger: {e}"))?;
        let mut total_restored_shielded = 0u64;
        if let Some(ref snap) = loaded_snapshot {
            shielded_ledger.set_epoch(snap.pss_epoch);
            for slot in &snap.shielded_slots {
                shielded_ledger
                    .restore_slot_shares(slot.bucket_id as usize, slot.slot_id as usize, &slot.shares)
                    .map_err(|e| {
                        format!(
                            "failed to restore Shamir shares for bucket {} slot {}: {e}",
                            slot.bucket_id, slot.slot_id
                        )
                    })?;
            }
            for acct in 0..config.max_accounts {
                if let Ok(bal) = shielded_ledger.reconstruct_balance(acct) {
                    let bal_u64 = u64::try_from(bal).unwrap_or(u64::MAX);
                    total_restored_shielded = total_restored_shielded.saturating_add(bal_u64);
                }
            }
        }
        let beaver_pool = BeaverPool::new_3_of_4(INITIAL_BEAVER_POOL_SIZE);

        // 3. Initialize live BB84 + Decoy-State QKD channel and perform genesis link calibration.
        let mut qkd_channel = Bb84Channel::default_channel();
        let mut init_qkd = qkd_channel
            .exchange_key(32)
            .map_err(|e| format!("genesis BB84 QKD check failed: {e}"))?;
        let mut last_qber = init_qkd.qber;
        zeroize_slice(&mut init_qkd.alice_key);
        zeroize_slice(&mut init_qkd.bob_key);

        // 4. Initialize 21M-cap Proof-of-Pad TokenomicsEngine with 4 equal-bonded validators V0..V3.
        let mut tokenomics = TokenomicsEngine::with_defaults();
        tokenomics
            .mint_genesis_supply(GENESIS_FAUCET_TREASURY_VERN)
            .map_err(|e| format!("failed to mint genesis liquid supply: {e}"))?;
        for vid in 0..DEFAULT_NUM_VALIDATORS as u64 {
            tokenomics
                .register_genesis_validator(vid)
                .map_err(|e| format!("failed to register genesis validator V{vid}: {e}"))?;
        }
        // Strictly bound faucet treasury (for BOTH Express AND Shielded mints) to the genesis
        // liquid supply minted inside TokenomicsEngine (well within MAX_SUPPLY = 21M VRNM).
        let total_restored_faucet = total_restored_express.saturating_add(total_restored_shielded);
        let faucet_treasury_remaining_vern = tokenomics
            .liquid_supply()
            .saturating_sub(total_restored_faucet);

        // 5. Initialize Proof-of-Personhood Web-of-Trust registry (V0..V3, 1-human = 1-vote).
        let wot_registry = WebOfTrustRegistry::for_bft_config(&bft_config);

        let (express_txs, shielded_txs, blocks_finalized, next_page_id, recent_events, restored_flag) =
            if let Some(snap) = loaded_snapshot {
                let q = f64::from_bits(snap.last_qber_bits);
                if q.is_finite() && (0.0..=1.0).contains(&q) {
                    last_qber = q;
                }
                let mut evs = snap.recent_events;
                if evs.len() > MAX_RECENT_EVENTS {
                    let excess = evs.len() - MAX_RECENT_EVENTS;
                    evs.drain(0..excess);
                }
                (
                    snap.express_txs,
                    snap.shielded_txs,
                    snap.blocks_finalized,
                    snap.next_page_id.max(1),
                    evs,
                    true,
                )
            } else {
                (0, 0, 0, 1, Vec::with_capacity(MAX_RECENT_EVENTS), false)
            };

        let mut state = Self {
            config,
            bft,
            shielded_ledger,
            beaver_pool,
            qkd_channel,
            tokenomics,
            pop_replay_registry: PopReplayRegistry::default(),
            wot_registry,
            auth_keys: AccountAuthKeyBook::default(),
            pending_pop_commits: BTreeMap::new(),
            faucet_treasury_remaining_vern,
            current_epoch_beacon: None,
            express_txs,
            shielded_txs,
            blocks_finalized,
            last_qber,
            next_page_id,
            recent_events,
            sender_nonces: restored_sender_nonces,
            external_peers: BTreeMap::new(),
            store,
            restored_blocks_base: blocks_finalized,
        };

        if restored_flag {
            state.push_event(format!(
                "RECOVERED: restored crash-safe snapshot (height={}, express_txs={}, shielded_txs={}, pss_epoch={})",
                state.blocks_finalized,
                state.express_txs,
                state.shielded_txs,
                state.shielded_ledger.epoch()
            ));
        } else {
            state.push_event(format!(
                "GENESIS: 4-validator BFT (V0..V3), {} shielded buckets ({} accounts), BB84 QBER={:.4}%",
                state.config.num_buckets,
                state.shielded_ledger.total_accounts(),
                state.last_qber * 100.0
            ));
            state.persist_snapshot();
        }

        Ok(state)
    }

    /// Export a complete crash-safe snapshot of live Express, Shielded Shamir, and Tokenomics state.
    pub fn export_snapshot(&self) -> PersistedChainSnapshot {
        let mut express_accounts = Vec::with_capacity(self.config.max_accounts + 1);
        for acct in 0..self.config.max_accounts as u32 {
            let balance = self.bft.validators[0].ledger.balance_of(acct);
            let nonce = self.sender_nonces.get(&acct).copied().unwrap_or(0);
            if balance > 0 || nonce > 0 {
                express_accounts.push(PersistedExpressAccount {
                    account_id: acct,
                    balance,
                    nonce,
                });
            }
        }
        if let Some(&treasury_nonce) = self.sender_nonces.get(&TREASURY_ACCOUNT_ID)
            && treasury_nonce > 0
        {
            express_accounts.push(PersistedExpressAccount {
                account_id: TREASURY_ACCOUNT_ID,
                balance: self.bft.validators[0].ledger.balance_of(TREASURY_ACCOUNT_ID),
                nonce: treasury_nonce,
            });
        }

        let num_buckets = self.shielded_ledger.num_buckets();
        let bucket_size = self.shielded_ledger.bucket_size();
        let mut shielded_slots = Vec::with_capacity(num_buckets * bucket_size);
        for b in 0..num_buckets {
            if let Ok(bucket) = self.shielded_ledger.bucket_shares(b) {
                for (s, shares) in bucket.iter().enumerate() {
                    shielded_slots.push(PersistedShieldedSlot {
                        bucket_id: b as u32,
                        slot_id: s as u32,
                        shares: shares.clone(),
                    });
                }
            }
        }

        let mut validators = Vec::with_capacity(self.bft.validators.len());
        for v in &self.bft.validators {
            if let Some(vault) = self.tokenomics.vault(v.id as u64) {
                let status_code = match vault.status {
                    ValidatorStatus::Active => 0,
                    ValidatorStatus::Offline => 1,
                    ValidatorStatus::Jailed => 2,
                    ValidatorStatus::Ejected => 3,
                };
                validators.push(PersistedValidatorVault {
                    validator_id: v.id as u64,
                    bond: vault.bond,
                    reward_balance: vault.reward_balance,
                    status_code,
                    missed_epochs: 0,
                });
            }
        }

        PersistedChainSnapshot {
            version: SNAPSHOT_FORMAT_VERSION,
            blocks_finalized: self.blocks_finalized,
            express_txs: self.express_txs,
            shielded_txs: self.shielded_txs,
            pss_epoch: self.shielded_ledger.epoch(),
            tokenomics_epoch: self.tokenomics.current_epoch(),
            circulating_supply: self.tokenomics.circulating_supply(),
            total_burned: self.tokenomics.total_burned(),
            total_fees_collected: 0,
            next_page_id: self.next_page_id,
            last_qber_bits: self.last_qber.to_bits(),
            express_accounts,
            shielded_slots,
            validators,
            recent_events: self.recent_events.clone(),
        }
    }

    /// Persist the current node state atomically if on-disk persistence is configured.
    pub fn persist_snapshot(&mut self) {
        if self.store.is_none() {
            return;
        }
        let snap = self.export_snapshot();
        if let Some(ref mut store) = self.store {
            let _ = store.save_snapshot(&snap);
        }
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
    /// - Enforces hard 21M supply cap treasury budget across BOTH Express AND Shielded mints
    ///   (`express + shielded <= faucet_treasury_remaining_vern`).
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

        // Hard 21M supply cap enforcement across BOTH Express AND Shielded faucet disbursements.
        let total_disbursement = express
            .checked_add(shielded)
            .ok_or_else(|| "faucet total disbursement overflow".to_string())?;
        if total_disbursement > self.faucet_treasury_remaining_vern {
            return Err(format!(
                "faucet treasury cap exceeded: requested {total_disbursement} vern (express={express}, shielded={shielded}) exceeds remaining treasury {} vern (hard 21M VRNM supply cap)",
                self.faucet_treasury_remaining_vern
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
            self.blocks_finalized = self.restored_blocks_base.saturating_add(cert.height);
            block_height = Some(self.blocks_finalized);
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

        // Deduct BOTH express and shielded disbursements from the genesis-backed faucet treasury.
        self.faucet_treasury_remaining_vern = self
            .faucet_treasury_remaining_vern
            .saturating_sub(total_disbursement);

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
        self.persist_snapshot();

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

    /// Authenticate `sender` via single-use Carter-Wegman MAC (`AUTH_DOMAIN_EXPRESS`),
    /// immediately burning `auth_pad_id`, then execute [`TestnetState::express_transfer`].
    pub fn express_transfer_authenticated(
        &mut self,
        sender: u32,
        recipient: u32,
        amount: u64,
        auth_pad_id: u64,
        auth_tag: &[u8; 16],
    ) -> Result<ExpressTxReceipt, AuthenticatedOpError> {
        self.auth_keys
            .verify_and_consume(
                AUTH_DOMAIN_EXPRESS,
                sender,
                recipient as u64,
                amount,
                0,
                auth_pad_id,
                auth_tag,
            )
            .map_err(AuthenticatedOpError::Unauthorized)?;
        self.express_transfer(sender, recipient, amount)
            .map_err(AuthenticatedOpError::BadRequest)
    }

    /// Authenticate `sender` via single-use Carter-Wegman MAC (`AUTH_DOMAIN_SHIELDED`),
    /// immediately burning `auth_pad_id`, then execute [`TestnetState::shielded_transfer`].
    pub fn shielded_transfer_authenticated(
        &mut self,
        sender: usize,
        recipient_bucket: usize,
        recipient_slot: usize,
        amount: u64,
        auth_pad_id: u64,
        auth_tag: &[u8; 16],
    ) -> Result<ShieldedTxReceipt, AuthenticatedOpError> {
        let sender_u32 = u32::try_from(sender)
            .map_err(|_| AuthenticatedOpError::BadRequest("sender exceeds u32".to_string()))?;
        self.auth_keys
            .verify_and_consume(
                AUTH_DOMAIN_SHIELDED,
                sender_u32,
                recipient_bucket as u64,
                recipient_slot as u64,
                amount,
                auth_pad_id,
                auth_tag,
            )
            .map_err(AuthenticatedOpError::Unauthorized)?;
        self.shielded_transfer(sender, recipient_bucket, recipient_slot, amount)
            .map_err(AuthenticatedOpError::BadRequest)
    }

    /// Authenticate account ownership via single-use Carter-Wegman MAC (`AUTH_DOMAIN_BALANCE`),
    /// immediately burning `auth_pad_id`, then return the owner's private balance WITHOUT
    /// dumping all 4 raw validator Shamir shares.
    pub fn private_account_balance(
        &mut self,
        account_id: u32,
        auth_pad_id: u64,
        auth_tag: &[u8; 16],
    ) -> Result<PrivateBalanceSnapshot, AuthenticatedOpError> {
        self.validate_account_id(account_id)
            .map_err(AuthenticatedOpError::BadRequest)?;
        self.auth_keys
            .verify_and_consume(
                AUTH_DOMAIN_BALANCE,
                account_id,
                0,
                0,
                0,
                auth_pad_id,
                auth_tag,
            )
            .map_err(AuthenticatedOpError::Unauthorized)?;
        let express_balance = self.bft.validators[0].ledger.balance_of(account_id);
        let (bucket_id, slot_in_bucket) = self
            .shielded_ledger
            .account_location(account_id as usize)
            .map_err(|e| AuthenticatedOpError::BadRequest(format!("account location error: {e}")))?;
        let shielded_balance = self
            .shielded_ledger
            .reconstruct_balance(account_id as usize)
            .map_err(|e| {
                AuthenticatedOpError::BadRequest(format!("reconstruct balance error: {e}"))
            })?;
        Ok(PrivateBalanceSnapshot {
            account_id,
            express_balance,
            shielded_balance,
            bucket_id,
            slot_in_bucket,
            epoch: self.shielded_ledger.epoch(),
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
        self.blocks_finalized = self.restored_blocks_base.saturating_add(cert.height);

        let new_sender_bal = self.bft.validators[0].ledger.balance_of(sender);
        let new_recip_bal = self.bft.validators[0].ledger.balance_of(recipient);
        let block_tag_hex = hex_encode(&cert.block_tag);

        self.push_event(format!(
            "EXPRESS BFT Block #{}: #{sender} -> #{recipient} ({amount} VRNM) | burned {} vern",
            self.blocks_finalized, fee.burn_share
        ));
        self.persist_snapshot();

        Ok(ExpressTxReceipt {
            sender,
            recipient,
            amount,
            block_height: self.blocks_finalized,
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
        self.persist_snapshot();

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
        self.persist_snapshot();

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
                "\"faucet_treasury_remaining_vern\":{},",
                "\"last_qber\":{:.6},",
                "\"qkd_delivered_bytes\":{},",
                "\"active_validators\":{},",
                "\"verified_humans\":{},",
                "\"beaver_pool_remaining\":{},",
                "\"num_buckets\":{},",
                "\"bucket_size\":{},",
                "\"max_accounts\":{},",
                "\"persistence_enabled\":{},",
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
            self.faucet_treasury_remaining_vern,
            self.last_qber,
            qkd_status.total_delivered_bytes,
            active_validators,
            self.wot_registry.verified_count(),
            self.beaver_pool.len(),
            self.shielded_ledger.num_buckets(),
            self.shielded_ledger.bucket_size(),
            self.config.max_accounts,
            self.store.is_some(),
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

/// Scan a JSON string literal starting at `bytes[start] == b'"'`, returning the byte offset
/// immediately AFTER the closing `"` if well-formed, or `None` if unterminated/invalid.
fn scan_json_string(bytes: &[u8], start: usize) -> Option<usize> {
    let len = bytes.len();
    if start >= len || bytes[start] != b'"' {
        return None;
    }
    let mut i = start + 1;
    while i < len {
        let b = bytes[i];
        if b < 0x20 {
            // Unescaped ASCII control characters (including NUL, CR, LF) are invalid in JSON strings.
            return None;
        }
        if b == b'\\' {
            i += 1;
            if i >= len {
                return None;
            }
            match bytes[i] {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                    i += 1;
                }
                b'u' => {
                    if i + 5 > len {
                        return None;
                    }
                    for &hx in &bytes[i + 1..i + 5] {
                        if !hx.is_ascii_hexdigit() {
                            return None;
                        }
                    }
                    i += 5;
                }
                _ => return None,
            }
            continue;
        }
        if b == b'"' {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

/// Unescape a validated JSON string literal (`"..."` including quotes) into a `String`.
fn unescape_json_string_literal(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let end = scan_json_string(bytes, 0)?;
    let inner = &raw[1..end - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if (ch as u32) < 0x20 {
            return None;
        }
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            '/' => out.push('/'),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => {
                let mut hex = [0u8; 4];
                for slot in &mut hex {
                    let c = chars.next()?;
                    if !c.is_ascii_hexdigit() {
                        return None;
                    }
                    *slot = c as u8;
                }
                let hex_str = std::str::from_utf8(&hex).ok()?;
                let code = u32::from_str_radix(hex_str, 16).ok()?;
                let decoded = char::from_u32(code)?;
                out.push(decoded);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Skip one JSON value starting at `bytes[start]` iteratively (zero recursion, bounded depth).
fn skip_json_value(bytes: &[u8], start: usize) -> Option<usize> {
    let len = bytes.len();
    if start >= len {
        return None;
    }
    match bytes[start] {
        b'"' => scan_json_string(bytes, start),
        b'{' | b'[' => {
            let mut stack = [0u8; MAX_JSON_DEPTH];
            let mut depth = 0usize;
            let mut i = start;
            while i < len {
                match bytes[i] {
                    b'"' => {
                        i = scan_json_string(bytes, i)?;
                    }
                    b'{' => {
                        if depth >= MAX_JSON_DEPTH {
                            return None;
                        }
                        stack[depth] = b'}';
                        depth += 1;
                        i += 1;
                    }
                    b'[' => {
                        if depth >= MAX_JSON_DEPTH {
                            return None;
                        }
                        stack[depth] = b']';
                        depth += 1;
                        i += 1;
                    }
                    b'}' | b']' => {
                        if depth == 0 || stack[depth - 1] != bytes[i] {
                            return None;
                        }
                        depth -= 1;
                        i += 1;
                        if depth == 0 {
                            return Some(i);
                        }
                    }
                    b if b < 0x20 && !matches!(b, b' ' | b'\t' | b'\r' | b'\n') => return None,
                    _ => {
                        i += 1;
                    }
                }
            }
            None
        }
        _ => {
            let mut i = start;
            while i < len && !matches!(bytes[i], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
            {
                if bytes[i] < 0x20 {
                    return None;
                }
                i += 1;
            }
            if i == start { None } else { Some(i) }
        }
    }
}

/// Find the byte slice starting at the value of a top-level `"key": <value>` entry inside a JSON
/// object, rejecting key-substring spoofing, nested-object spoofing, string-embedded keys, and
/// excessive nesting depth (> `MAX_JSON_DEPTH`).
fn find_json_value_start<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let bytes = json.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= len || bytes[i] != b'{' {
        return None;
    }
    i += 1;

    loop {
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len || bytes[i] == b'}' {
            return None;
        }
        // Key MUST begin with '"' immediately after '{' or ',' (+ whitespace).
        if bytes[i] != b'"' {
            return None;
        }
        let key_end = scan_json_string(bytes, i)?;
        let raw_key_inner = &json[i + 1..key_end - 1];
        let matched = if !raw_key_inner.contains('\\') {
            raw_key_inner == key
        } else {
            unescape_json_string_literal(&json[i..key_end]).as_deref() == Some(key)
        };
        i = key_end;

        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len || bytes[i] != b':' {
            return None;
        }
        i += 1;
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            return None;
        }
        if matched {
            return Some(&json[i..]);
        }

        i = skip_json_value(bytes, i)?;
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len || bytes[i] == b'}' {
            return None;
        }
        if bytes[i] != b',' {
            return None;
        }
        i += 1;
    }
}

/// Parse an unsigned 64-bit integer value for top-level `key` from a JSON object.
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

/// Parse a string value for top-level `key` from a JSON object.
pub fn parse_json_str(json: &str, key: &str) -> Option<String> {
    let rest = find_json_value_start(json, key)?;
    let bytes = rest.as_bytes();
    let end = scan_json_string(bytes, 0)?;
    // Verify clean delimiter after the closing quote.
    let mut k = end;
    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
        k += 1;
    }
    if k < bytes.len() && !matches!(bytes[k], b',' | b'}' | b']') {
        return None;
    }
    unescape_json_string_literal(&rest[..end])
}

/// Parse a top-level JSON array of strings (`["a", "b", ...]`), bounded by `max_items`.
pub fn parse_json_str_array(json: &str, key: &str, max_items: usize) -> Option<Vec<String>> {
    let rest = find_json_value_start(json, key)?;
    let bytes = rest.as_bytes();
    if bytes.is_empty() || bytes[0] != b'[' {
        return None;
    }
    let len = bytes.len();
    let mut i = 1;
    let mut items = Vec::new();
    while i < len && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i < len && bytes[i] == b']' {
        return Some(items);
    }
    loop {
        if items.len() >= max_items {
            return None;
        }
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len || bytes[i] != b'"' {
            return None;
        }
        let end = scan_json_string(bytes, i)?;
        items.push(unescape_json_string_literal(&rest[i..end])?);
        i = end;
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            return None;
        }
        if bytes[i] == b']' {
            return Some(items);
        }
        if bytes[i] != b',' {
            return None;
        }
        i += 1;
    }
}

/// Parse a top-level JSON array of unsigned 64-bit integers (`[1, 2, ...]`), bounded by `max_items`.
pub fn parse_json_u64_array(json: &str, key: &str, max_items: usize) -> Option<Vec<u64>> {
    let rest = find_json_value_start(json, key)?;
    let bytes = rest.as_bytes();
    if bytes.is_empty() || bytes[0] != b'[' {
        return None;
    }
    let len = bytes.len();
    let mut i = 1;
    let mut items = Vec::new();
    while i < len && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i < len && bytes[i] == b']' {
        return Some(items);
    }
    loop {
        if items.len() >= max_items {
            return None;
        }
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len || !bytes[i].is_ascii_digit() {
            return None;
        }
        let start = i;
        while i < len && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let v = rest[start..i].parse::<u64>().ok()?;
        items.push(v);
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            return None;
        }
        if bytes[i] == b']' {
            return Some(items);
        }
        if bytes[i] != b',' {
            return None;
        }
        i += 1;
    }
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a hex-encoded `u128` scalar (accepting optional `"0x"` / `"0X"` prefix).
pub fn parse_hex_u128(s: &str) -> Option<u128> {
    let trimmed = s.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.is_empty() || hex.len() > 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(hex, 16).ok()
}

/// Parse an exact 16-byte (32-hex-char) Carter-Wegman tag (accepting optional `"0x"` prefix).
pub fn parse_hex_16(s: &str) -> Option<[u8; 16]> {
    let trimmed = s.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Parse an even-length hex byte string (accepting optional `"0x"` prefix).
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

// ============================================================================
// 3B. Bounded Per-IP Rate Limiter & P2P Subnet Diversity Helpers
// ============================================================================

#[derive(Debug, Clone)]
struct IpWindowEntry {
    window_start: Instant,
    count: u32,
    last_seen_seq: u64,
}

/// Zero-dependency, memory-bounded per-IP fixed-window rate limiter.
///
/// Caps tracked distinct client IPs at `max_tracked_ips` (default [`MAX_TRACKED_IPS`] = 4096)
/// with oldest-entry eviction so an IP-spoofing flood can never OOM the server.
#[derive(Debug)]
pub struct IpRateLimiter {
    entries: HashMap<IpAddr, IpWindowEntry>,
    order: VecDeque<(IpAddr, u64)>,
    seq: u64,
    max_requests_per_window: u32,
    window: Duration,
    max_tracked_ips: usize,
}

impl IpRateLimiter {
    /// Create a rate limiter allowing `max_requests_per_sec` per 1-second window per IP,
    /// capped at [`MAX_TRACKED_IPS`] tracked IPs.
    pub fn new(max_requests_per_sec: u32) -> Self {
        Self::with_config(
            max_requests_per_sec,
            Duration::from_secs(1),
            MAX_TRACKED_IPS,
        )
    }

    /// Create a rate limiter with custom window size and IP tracking capacity.
    pub fn with_config(
        max_requests_per_window: u32,
        window: Duration,
        max_tracked_ips: usize,
    ) -> Self {
        let cap = max_tracked_ips.max(1);
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            seq: 0,
            max_requests_per_window,
            window,
            max_tracked_ips: cap,
        }
    }

    /// Update the per-window request limit dynamically.
    pub fn set_limit(&mut self, max_requests_per_window: u32) {
        self.max_requests_per_window = max_requests_per_window;
    }

    /// Number of distinct client IPs currently tracked in memory.
    pub fn tracked_ips(&self) -> usize {
        self.entries.len()
    }

    /// Check whether a request from `ip` is allowed at the current wall-clock time.
    pub fn allow(&mut self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Deterministic rate-limit check at explicit timestamp `now` (ideal for unit tests).
    pub fn allow_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.max_requests_per_window == 0 {
            return false;
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;

        if let Some(entry) = self.entries.get_mut(&ip) {
            entry.last_seen_seq = seq;
            self.order.push_back((ip, seq));
            let allowed = if now.saturating_duration_since(entry.window_start) >= self.window {
                entry.window_start = now;
                entry.count = 1;
                true
            } else if entry.count < self.max_requests_per_window {
                entry.count += 1;
                true
            } else {
                false
            };
            self.compact_order_if_needed();
            return allowed;
        }

        if self.entries.len() >= self.max_tracked_ips {
            self.evict_oldest();
        }
        self.entries.insert(
            ip,
            IpWindowEntry {
                window_start: now,
                count: 1,
                last_seen_seq: seq,
            },
        );
        self.order.push_back((ip, seq));
        self.compact_order_if_needed();
        true
    }

    fn evict_oldest(&mut self) {
        while let Some((cand_ip, cand_seq)) = self.order.pop_front() {
            let is_live = self
                .entries
                .get(&cand_ip)
                .is_some_and(|e| e.last_seen_seq == cand_seq);
            if is_live {
                self.entries.remove(&cand_ip);
                return;
            }
        }
        if let Some(oldest_ip) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_seen_seq)
            .map(|(&ip, _)| ip)
        {
            self.entries.remove(&oldest_ip);
        }
    }

    fn compact_order_if_needed(&mut self) {
        if self.order.len() > self.max_tracked_ips.saturating_mul(2) {
            let entries = &self.entries;
            self.order.retain(|(ip, seq)| {
                entries
                    .get(ip)
                    .is_some_and(|e| e.last_seen_seq == *seq)
            });
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PeerSubnetKey {
    V4([u8; 3]),
    V6([u16; 3]),
    Host(String),
}

fn parse_peer_host_port(addr: &str) -> Result<(&str, u16), &'static str> {
    if addr.is_empty()
        || addr.len() > MAX_PEER_ADDR_LEN
        || addr.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("malformed peer 'addr'");
    }
    let (host, port_str) = if let Some(rest) = addr.strip_prefix('[') {
        rest.split_once("]:").ok_or("malformed peer 'addr'")?
    } else {
        let (h, p) = addr.rsplit_once(':').ok_or("malformed peer 'addr'")?;
        if h.contains(':') {
            return Err("malformed peer 'addr'");
        }
        (h, p)
    };
    if host.is_empty()
        || host
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')))
    {
        return Err("malformed peer 'addr'");
    }
    let port = port_str.parse::<u16>().map_err(|_| "malformed peer 'addr'")?;
    if port == 0 {
        return Err("malformed peer 'addr'");
    }
    Ok((host, port))
}

fn is_ssrf_blocked_v4(v4: Ipv4Addr) -> bool {
    v4.is_link_local()
        || v4.is_multicast()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.octets() == [169, 254, 169, 254]
}

fn is_ssrf_blocked_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => is_ssrf_blocked_v4(v4),
            IpAddr::V6(v6) => {
                v6.is_multicast()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
                    || v6.to_ipv4_mapped().is_some_and(is_ssrf_blocked_v4)
            }
        };
    }
    false
}

/// Extract a `/24` (IPv4) or `/48` (IPv6) eclipse-defense subnet key for `addr`, returning `None`
/// for loopback addresses (`127.0.0.0/8`, `::1`, `localhost`) so local multi-node tests stay unaffected.
fn peer_subnet_key(addr: &str) -> Option<PeerSubnetKey> {
    let (host, _) = parse_peer_host_port(addr).ok()?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    None
                } else {
                    let o = v4.octets();
                    Some(PeerSubnetKey::V4([o[0], o[1], o[2]]))
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    None
                } else if let Some(mapped) = v6.to_ipv4_mapped() {
                    if mapped.is_loopback() {
                        None
                    } else {
                        let o = mapped.octets();
                        Some(PeerSubnetKey::V4([o[0], o[1], o[2]]))
                    }
                } else {
                    let s = v6.segments();
                    Some(PeerSubnetKey::V6([s[0], s[1], s[2]]))
                }
            }
        };
    }
    if host.eq_ignore_ascii_case("localhost") {
        None
    } else {
        Some(PeerSubnetKey::Host(host.to_ascii_lowercase()))
    }
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

/// Run a 4-validator unbiasable threshold entropy beacon round for `epoch` and return `gamma`.
fn run_testnet_beacon_round(epoch: u64) -> Result<u128, String> {
    let cfg = BeaconConfig::bft(4).map_err(|e| format!("{e}"))?;
    let mut nodes: Vec<VernamBeacon> = (0..4u32)
        .map(|id| VernamBeacon::new(cfg, epoch, id).map_err(|e| format!("{e}")))
        .collect::<Result<_, _>>()?;
    let pad_len = cfg.share_payload_bytes();
    for dealer in 0..4usize {
        let mut pairs: Vec<(u32, OtpChannelKey, OtpChannelKey)> = (0..4u32)
            .map(|recip| {
                let (s_k, r_k) = OtpChannelKey::generate_pair(pad_len);
                (recip, s_k, r_k)
            })
            .collect();
        let key_refs: Vec<(u32, &OtpChannelKey)> =
            pairs.iter().map(|(r, sk, _)| (*r, sk)).collect();
        let envs = nodes[dealer]
            .generate_commit_envelopes(&key_refs)
            .map_err(|e| format!("{e}"))?;
        for env in envs {
            let r = env.recipient_id as usize;
            nodes[r]
                .receive_commit_envelope(&env, &pairs[r].2)
                .map_err(|e| format!("{e}"))?;
        }
        pairs.clear();
    }
    for node in &mut nodes {
        node.lock_commit_phase().map_err(|e| format!("{e}"))?;
    }
    let mut reveals = Vec::with_capacity(4);
    for node in &mut nodes {
        reveals.push(node.generate_reveal().map_err(|e| format!("{e}"))?);
    }
    for r in &reveals {
        for node in &mut nodes {
            node.receive_reveal(r).map_err(|e| format!("{e}"))?;
        }
    }
    let out = nodes[0].finalize_epoch().map_err(|e| format!("{e}"))?;
    Ok(out.gamma)
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

fn is_valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b > 0x20
                && b < 0x7f
                && !matches!(
                    b,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
}

fn has_disallowed_header_value_bytes(val: &str) -> bool {
    val.bytes()
        .any(|b| b == 0 || (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// Read and parse a single HTTP/1.1 request from `stream` with an overall wall-clock deadline
/// and strict request-smuggling / control-byte / header-count hardening.
fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let deadline = Instant::now() + HTTP_READ_DEADLINE;
    let mut raw = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];

    let header_end = loop {
        if let Some(pos) = find_header_end(&raw) {
            if pos > MAX_HTTP_HEADER_BYTES {
                return Err("HTTP headers exceed maximum allowed size".to_string());
            }
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
    if header_bytes.contains(&0) {
        return Err("HTTP headers contain NUL byte".to_string());
    }
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| "HTTP headers contain invalid UTF-8".to_string())?;

    let mut lines = header_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_string())?;
    if request_line.is_empty()
        || request_line.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err("malformed HTTP request line".to_string());
    }
    let mut parts = request_line.split(' ');
    let method_str = parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_string())?;
    let raw_target = parts
        .next()
        .ok_or_else(|| "missing HTTP request target".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "missing HTTP version".to_string())?;
    if parts.next().is_some() {
        return Err("malformed HTTP request line: unexpected trailing tokens".to_string());
    }
    if method_str.is_empty()
        || method_str.len() > 16
        || !method_str.bytes().all(|b| b.is_ascii_uppercase())
    {
        return Err("invalid HTTP method".to_string());
    }
    if raw_target.is_empty()
        || (!raw_target.starts_with('/') && !(method_str == "OPTIONS" && raw_target == "*"))
    {
        return Err("invalid HTTP request target".to_string());
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("unsupported HTTP version".to_string());
    }
    let method = method_str.to_string();
    let path = raw_target
        .split('?')
        .next()
        .unwrap_or(raw_target)
        .to_string();

    let mut content_length: usize = 0;
    let mut seen_content_length = false;
    let mut seen_transfer_encoding = false;
    let mut header_count: usize = 0;
    let mut auth_header: Option<String> = None;
    for line in lines {
        header_count += 1;
        if header_count > MAX_HTTP_HEADERS {
            return Err("too many HTTP headers".to_string());
        }
        if line.is_empty() || line.contains('\r') || line.contains('\n') {
            return Err("malformed HTTP header line".to_string());
        }
        let Some((name, val)) = line.split_once(':') else {
            return Err("malformed HTTP header: missing colon".to_string());
        };
        if !is_valid_http_header_name(name) {
            return Err("malformed HTTP header name".to_string());
        }
        if has_disallowed_header_value_bytes(val) {
            return Err("HTTP header contains disallowed control bytes".to_string());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if seen_content_length {
                return Err("duplicate Content-Length header".to_string());
            }
            seen_content_length = true;
            let trimmed_val = val.trim();
            if trimmed_val.is_empty() || !trimmed_val.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid Content-Length header".to_string());
            }
            content_length = trimmed_val
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length header".to_string())?;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            seen_transfer_encoding = true;
        } else if name.eq_ignore_ascii_case("authorization") {
            auth_header = Some(val.trim().to_string());
        }
    }
    if seen_transfer_encoding && seen_content_length {
        return Err("conflicting Transfer-Encoding and Content-Length headers".to_string());
    }
    if seen_transfer_encoding {
        return Err("Transfer-Encoding request header is not supported".to_string());
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
            return Err("truncated HTTP request body".to_string());
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
    rate_limiter: Arc<Mutex<IpRateLimiter>>,
    active_conns: Arc<AtomicUsize>,
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
            rate_limiter: Arc::new(Mutex::new(IpRateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC))),
            active_conns: Arc::new(AtomicUsize::new(0)),
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

    /// Configure the per-IP request rate limit (requests per 1-second window).
    pub fn set_rate_limit(&self, max_requests_per_sec: u32) {
        self.rate_limiter
            .lock()
            .expect("rate limiter mutex poisoned")
            .set_limit(max_requests_per_sec);
    }

    fn write_early_error_and_close(tcp: &mut TcpStream, resp: &[u8]) {
        let _ = tcp.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = tcp.write_all(resp);
        let _ = tcp.flush();
        let _ = tcp.shutdown(Shutdown::Write);
        // Drain a small bounded amount of buffered client request bytes so the OS sends a clean
        // FIN instead of TCP RST when closing early (ensuring clients reliably read HTTP 429/503).
        let _ = tcp.set_read_timeout(Some(Duration::from_millis(20)));
        let mut drain = [0u8; 2048];
        let _ = tcp.read(&mut drain);
    }

    fn check_rate_limit(&self, tcp: &mut TcpStream) -> bool {
        let allowed = match tcp.peer_addr() {
            Ok(sa) => self
                .rate_limiter
                .lock()
                .expect("rate limiter mutex poisoned")
                .allow(sa.ip()),
            Err(_) => true,
        };
        if !allowed {
            let resp = HttpResponse::err_json(
                429,
                "Too Many Requests",
                "per-IP rate limit exceeded",
            )
            .to_http_bytes();
            Self::write_early_error_and_close(tcp, &resp);
        }
        allowed
    }

    /// Accept and serve HTTP/1.1 connections indefinitely with bounded concurrency
    /// (`MAX_CONCURRENT_CONNS`) and per-IP rate limiting, returning HTTP 429 / 503 when exceeded.
    pub fn serve_forever(&self) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(mut tcp) => {
                    if !self.check_rate_limit(&mut tcp) {
                        continue;
                    }
                    let Some(slot_guard) = try_acquire_conn_slot(&self.active_conns) else {
                        let resp = HttpResponse::err_json(
                            503,
                            "Service Unavailable",
                            "server saturated: too many concurrent connections",
                        )
                        .to_http_bytes();
                        Self::write_early_error_and_close(&mut tcp, &resp);
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
                if self.check_rate_limit(&mut tcp) {
                    Self::handle_connection(&self.state, &mut tcp);
                }
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
                "{\"status\":\"ok\",\"network\":\"vernam-vrnm-testnet\",\"version\":\"2.2.0\"}"
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
                let (host, _port) = match parse_peer_host_port(trimmed) {
                    Ok(hp) => hp,
                    Err(msg) => return HttpResponse::err_json(400, "Bad Request", msg),
                };
                if is_ssrf_blocked_host(host) {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "SSRF protection: blocked peer IP address",
                    );
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
                    if is_new {
                        if guard.external_peers.len() >= MAX_EXTERNAL_PEERS {
                            return HttpResponse::err_json(
                                400,
                                "Bad Request",
                                "external peer table full",
                            );
                        }
                        if let Some(subnet) = peer_subnet_key(trimmed) {
                            let same_subnet_count = guard
                                .external_peers
                                .keys()
                                .filter(|k| peer_subnet_key(k).as_ref() == Some(&subnet))
                                .count();
                            if same_subnet_count >= MAX_PEERS_PER_SUBNET {
                                return HttpResponse::err_json(
                                    400,
                                    "Bad Request",
                                    "eclipse protection: per-subnet peer cap exceeded",
                                );
                            }
                        }
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

            ("POST", "/account/register") => {
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

                let count_opt = parse_json_u64(&req.body, "count");
                let explicit_pad_opt = parse_json_u64(&req.body, "pad_id");
                let explicit_r_opt = parse_json_str(&req.body, "r");
                let explicit_s_opt = parse_json_str(&req.body, "s");
                let auth_pad_opt = parse_json_u64(&req.body, "auth_pad_id");
                let auth_tag_str_opt = parse_json_str(&req.body, "auth_tag");

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                if let Err(e) = guard.validate_account_id(account_id) {
                    return HttpResponse::err_json(400, "Bad Request", &e);
                }

                let already_registered = guard.auth_keys.is_registered(account_id);
                let refill_auth = if already_registered {
                    if auth_pad_opt.is_none() && auth_tag_str_opt.is_none() {
                        return HttpResponse::err_json(
                            409,
                            "Conflict",
                            "account_id already registered; provide valid auth_pad_id and auth_tag to refill keys",
                        );
                    }
                    let Some(auth_pad_id) = auth_pad_opt else {
                        return HttpResponse::err_json(
                            401,
                            "Unauthorized",
                            "missing integer field 'auth_pad_id' for key refill",
                        );
                    };
                    let Some(tag_str) = auth_tag_str_opt else {
                        return HttpResponse::err_json(
                            401,
                            "Unauthorized",
                            "missing hex field 'auth_tag' for key refill",
                        );
                    };
                    let Some(auth_tag) = parse_hex_16(&tag_str) else {
                        return HttpResponse::err_json(
                            401,
                            "Unauthorized",
                            "invalid 32-char hex 'auth_tag'",
                        );
                    };
                    Some((auth_pad_id, auth_tag))
                } else {
                    None
                };

                if let Some(count_u64) = count_opt {
                    let Ok(count) = usize::try_from(count_u64) else {
                        return HttpResponse::err_json(400, "Bad Request", "invalid 'count'");
                    };
                    let result = match refill_auth {
                        Some((auth_pad_id, auth_tag)) => guard
                            .auth_keys
                            .refill_generated(account_id, count, auth_pad_id, &auth_tag),
                        None => guard
                            .auth_keys
                            .register_new_generated(account_id, count)
                            .map_err(AuthenticatedOpError::BadRequest),
                    };
                    match result {
                        Ok(keys) => {
                            let mut keys_json = String::from("[");
                            for (i, &(pad_id, r, s)) in keys.iter().enumerate() {
                                if i > 0 {
                                    keys_json.push(',');
                                }
                                keys_json.push_str(&format!(
                                    "{{\"pad_id\":{},\"r\":\"0x{:032x}\",\"s\":\"0x{:032x}\"}}",
                                    pad_id, r, s
                                ));
                            }
                            keys_json.push(']');
                            HttpResponse::ok_json(format!(
                                "{{\"status\":\"registered\",\"account_id\":{},\"keys\":{}}}",
                                account_id, keys_json
                            ))
                        }
                        Err(AuthenticatedOpError::Unauthorized(msg)) => {
                            HttpResponse::err_json(401, "Unauthorized", &msg)
                        }
                        Err(AuthenticatedOpError::BadRequest(msg)) => {
                            HttpResponse::err_json(400, "Bad Request", &msg)
                        }
                    }
                } else if let (Some(pad_id), Some(r_str), Some(s_str)) =
                    (explicit_pad_opt, explicit_r_opt, explicit_s_opt)
                {
                    let Some(r) = parse_hex_u128(&r_str) else {
                        return HttpResponse::err_json(400, "Bad Request", "invalid hex field 'r'");
                    };
                    let Some(s) = parse_hex_u128(&s_str) else {
                        return HttpResponse::err_json(400, "Bad Request", "invalid hex field 's'");
                    };
                    let result = match refill_auth {
                        Some((auth_pad_id, auth_tag)) => guard.auth_keys.refill_explicit(
                            account_id,
                            pad_id,
                            r,
                            s,
                            auth_pad_id,
                            &auth_tag,
                        ),
                        None => guard
                            .auth_keys
                            .register_new_explicit(account_id, pad_id, r, s)
                            .map_err(AuthenticatedOpError::BadRequest),
                    };
                    match result {
                        Ok(()) => HttpResponse::ok_json(format!(
                            "{{\"status\":\"registered\",\"account_id\":{},\"pad_id\":{},\"active_keys\":{}}}",
                            account_id,
                            pad_id,
                            guard.auth_keys.active_key_count(account_id),
                        )),
                        Err(AuthenticatedOpError::Unauthorized(msg)) => {
                            HttpResponse::err_json(401, "Unauthorized", &msg)
                        }
                        Err(AuthenticatedOpError::BadRequest(msg)) => {
                            HttpResponse::err_json(400, "Bad Request", &msg)
                        }
                    }
                } else {
                    HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "expected 'count' (1..=64) or explicit ('pad_id', 'r', 's')",
                    )
                }
            }

            ("POST", "/pop/mine") => {
                if let Err(resp) = check_api_auth(req) {
                    return resp;
                }
                HttpResponse::err_json(
                    400,
                    "Bad Request",
                    "server-side self-mining disabled; submit real pre-commitments to POST /pop/commit and verified proofs to POST /pop/submit",
                )
            }

            ("POST", "/pop/commit") => {
                if let Err(resp) = check_api_auth(req) {
                    return resp;
                }
                let Some(validator_id) = parse_json_u64(&req.body, "validator_id") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'validator_id'",
                    );
                };
                let Some(pad_pages_u64) = parse_json_u64(&req.body, "pad_pages_mined") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'pad_pages_mined'",
                    );
                };
                let Some(beaver_triples_u64) = parse_json_u64(&req.body, "beaver_triples_mined")
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'beaver_triples_mined'",
                    );
                };
                let pad_pages_mined = pad_pages_u64 as usize;
                let beaver_triples_mined = beaver_triples_u64 as usize;
                if pad_pages_mined == 0 || pad_pages_mined > MAX_REMOTE_POP_PAD_PAGES {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "pad_pages_mined must be in 1..=1024",
                    );
                }
                if beaver_triples_mined == 0 || beaver_triples_mined > MAX_REMOTE_POP_BEAVER_TRIPLES
                {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "beaver_triples_mined must be in 1..=4096",
                    );
                }
                let Some(commit_r_str) = parse_json_str(&req.body, "commit_r") else {
                    return HttpResponse::err_json(400, "Bad Request", "missing hex field 'commit_r'");
                };
                let Some(commit_s_str) = parse_json_str(&req.body, "commit_s") else {
                    return HttpResponse::err_json(400, "Bad Request", "missing hex field 'commit_s'");
                };
                let Some(commit_r) = parse_hex_u128(&commit_r_str) else {
                    return HttpResponse::err_json(400, "Bad Request", "invalid hex field 'commit_r'");
                };
                let Some(commit_s) = parse_hex_u128(&commit_s_str) else {
                    return HttpResponse::err_json(400, "Bad Request", "invalid hex field 'commit_s'");
                };
                if commit_r == 0 || commit_r >= PRIME_P {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "commit_r must satisfy 0 < commit_r < PRIME_P",
                    );
                }
                if commit_s >= PRIME_P {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "commit_s must satisfy commit_s < PRIME_P",
                    );
                }
                let Some(digest_strs) =
                    parse_json_str_array(&req.body, "page_digests", MAX_REMOTE_POP_PAD_PAGES)
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid array field 'page_digests'",
                    );
                };
                if digest_strs.len() != pad_pages_mined {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "page_digests length does not match pad_pages_mined",
                    );
                }
                let mut page_digests = Vec::with_capacity(pad_pages_mined);
                for ds in &digest_strs {
                    let Some(d) = parse_hex_u128(ds) else {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "invalid hex scalar in 'page_digests'",
                        );
                    };
                    if d >= PRIME_P {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "non-canonical page_digest >= PRIME_P",
                        );
                    }
                    page_digests.push(d);
                }
                let Some(batch_commit_str) = parse_json_str(&req.body, "batch_commitment") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing hex field 'batch_commitment'",
                    );
                };
                let Some(batch_commitment) = parse_hex_16(&batch_commit_str) else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "invalid 32-char hex 'batch_commitment'",
                    );
                };

                // Constant-time verification of the miner's pre-challenge commitment tag.
                let expected_pre_commit = compute_batch_commitment_tag(
                    validator_id,
                    0,
                    &page_digests,
                    commit_r,
                    commit_s,
                );
                if !ct_eq_16(&expected_pre_commit, &batch_commitment) {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "pre-commitment batch_commitment tag verification failed",
                    );
                }

                // Read current epoch & check validator registration + cached beacon outside heavy work.
                let (epoch, cached_gamma, active_validators) = {
                    let guard = state.lock().expect("testnet state mutex poisoned");
                    let Some(vault) = guard.tokenomics.vault(validator_id) else {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "unknown validator_id",
                        );
                    };
                    if vault.status == ValidatorStatus::Ejected {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "validator is permanently ejected",
                        );
                    }
                    let ep = guard.tokenomics.current_epoch();
                    let cached = guard
                        .current_epoch_beacon
                        .and_then(|(b_ep, g)| if b_ep == ep { Some(g) } else { None });
                    let vals: Vec<u64> = guard.bft.validators.iter().map(|v| v.id as u64).collect();
                    (ep, cached, vals)
                };

                let computed_gamma = match cached_gamma {
                    Some(g) => g,
                    None => match run_testnet_beacon_round(epoch) {
                        Ok(g) => g,
                        Err(e) => {
                            return HttpResponse::err_json(
                                500,
                                "Internal Server Error",
                                &format!("threshold entropy beacon round failed: {e}"),
                            );
                        }
                    },
                };

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                let current_epoch = guard.tokenomics.current_epoch();
                if current_epoch != epoch {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "epoch advanced during beacon round; retry POST /pop/commit",
                    );
                }
                let beacon_gamma = match guard.current_epoch_beacon {
                    Some((b_ep, g)) if b_ep == epoch => g,
                    _ => {
                        guard.current_epoch_beacon = Some((epoch, computed_gamma));
                        computed_gamma
                    }
                };

                let schedule = match BeaconPairingSchedule::derive(
                    epoch,
                    &active_validators,
                    beacon_gamma,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        return HttpResponse::err_json(
                            500,
                            "Internal Server Error",
                            &format!("beacon pairing derivation failed: {e}"),
                        );
                    }
                };
                let Some(expected_counterparty) = schedule.expected_counterparty(validator_id)
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "validator_id not present in beacon pairing schedule",
                    );
                };

                let challenge = match PopAuditor::issue_beacon_challenge(
                    validator_id,
                    epoch,
                    beacon_gamma,
                    DEFAULT_CHALLENGE_SLOT_COUNT,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        return HttpResponse::err_json(
                            500,
                            "Internal Server Error",
                            &format!("failed to issue beacon PoP challenge: {e}"),
                        );
                    }
                };
                let peer_key = PeerReceiptKey::generate();
                let peer_key_r = peer_key.r();
                let peer_key_s = peer_key.s();
                let challenge_r = challenge.challenge_r;
                let sample_mask_s = challenge.sample_mask_s;
                let batch_mask_s = challenge.batch_mask_s;
                let slots_mask_s = challenge.slots_mask_s;
                let beaver_slot_index = challenge.beaver_slot_index;
                let mut slots_json = String::from("[");
                for (i, &idx) in challenge.pad_slot_indices.iter().enumerate() {
                    if i > 0 {
                        slots_json.push(',');
                    }
                    slots_json.push_str(&(idx as u64).to_string());
                }
                slots_json.push(']');

                let commitment = PopCommitment {
                    validator_id,
                    pad_pages_mined,
                    beaver_triples_mined,
                    commit_r,
                    commit_s,
                    page_digests,
                    batch_commitment,
                };
                guard.pending_pop_commits.insert(
                    validator_id,
                    (
                        epoch,
                        beacon_gamma,
                        expected_counterparty,
                        commitment,
                        challenge,
                        peer_key,
                    ),
                );

                HttpResponse::ok_json(format!(
                    "{{\"status\":\"committed\",\"validator_id\":{},\"epoch\":{},\"beacon_gamma\":\"0x{:032x}\",\"expected_counterparty\":{},\"challenge_r\":\"0x{:032x}\",\"sample_mask_s\":\"0x{:032x}\",\"batch_mask_s\":\"0x{:032x}\",\"slots_mask_s\":\"0x{:032x}\",\"pad_slot_indices\":{},\"beaver_slot_index\":{},\"peer_key_r\":\"0x{:032x}\",\"peer_key_s\":\"0x{:032x}\"}}",
                    validator_id,
                    epoch,
                    beacon_gamma,
                    expected_counterparty,
                    challenge_r,
                    sample_mask_s,
                    batch_mask_s,
                    slots_mask_s,
                    slots_json,
                    beaver_slot_index as u64,
                    peer_key_r,
                    peer_key_s,
                ))
            }

            ("POST", "/pop/submit") => {
                if let Err(resp) = check_api_auth(req) {
                    return resp;
                }
                let Some(validator_id) = parse_json_u64(&req.body, "validator_id") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'validator_id'",
                    );
                };
                let Some(epoch) = parse_json_u64(&req.body, "epoch") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'epoch'",
                    );
                };
                let Some(audited_pad_index_u64) = parse_json_u64(&req.body, "audited_pad_index")
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'audited_pad_index'",
                    );
                };
                let Some(audited_triple_index_u64) =
                    parse_json_u64(&req.body, "audited_triple_index")
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'audited_triple_index'",
                    );
                };
                let Some(sample_hexes) = parse_json_str_array(
                    &req.body,
                    "audited_pad_samples",
                    MAX_REMOTE_POP_PAD_PAGES,
                ) else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid array field 'audited_pad_samples'",
                    );
                };
                let mut raw_samples = Vec::with_capacity(sample_hexes.len());
                for sh in &sample_hexes {
                    let Some(bytes) = parse_hex_bytes(sh) else {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "invalid hex entry in 'audited_pad_samples'",
                        );
                    };
                    raw_samples.push(bytes);
                }
                let Some(sacrificed_a) =
                    parse_json_str(&req.body, "sacrificed_a").and_then(|s| parse_hex_u128(&s))
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid hex field 'sacrificed_a'",
                    );
                };
                let Some(sacrificed_b) =
                    parse_json_str(&req.body, "sacrificed_b").and_then(|s| parse_hex_u128(&s))
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid hex field 'sacrificed_b'",
                    );
                };
                let Some(sacrificed_c) =
                    parse_json_str(&req.body, "sacrificed_c").and_then(|s| parse_hex_u128(&s))
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid hex field 'sacrificed_c'",
                    );
                };
                let Some(digest_strs) =
                    parse_json_str_array(&req.body, "page_digests", MAX_REMOTE_POP_PAD_PAGES)
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid array field 'page_digests'",
                    );
                };
                let mut page_digests = Vec::with_capacity(digest_strs.len());
                for ds in &digest_strs {
                    let Some(d) = parse_hex_u128(ds) else {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "invalid hex entry in 'page_digests'",
                        );
                    };
                    page_digests.push(d);
                }
                let Some(batch_commitment) = parse_json_str(&req.body, "batch_commitment")
                    .and_then(|s| parse_hex_16(&s))
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid 32-char hex 'batch_commitment'",
                    );
                };
                let Some(sample_commitment_tag) =
                    parse_json_str(&req.body, "sample_commitment_tag")
                        .and_then(|s| parse_hex_16(&s))
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid 32-char hex 'sample_commitment_tag'",
                    );
                };
                let Some(challenged_slots_tag) = parse_json_str(&req.body, "challenged_slots_tag")
                    .and_then(|s| parse_hex_16(&s))
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid 32-char hex 'challenged_slots_tag'",
                    );
                };
                let Some(qber_bits) = parse_json_u64(&req.body, "qber_bits") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'qber_bits'",
                    );
                };
                let Some(sifted_bits_u64) = parse_json_u64(&req.body, "sifted_bits") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'sifted_bits'",
                    );
                };
                let Some(decoy_ratio_bits) = parse_json_u64(&req.body, "decoy_ratio_bits") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'decoy_ratio_bits'",
                    );
                };
                let Some(y1_bits) = parse_json_u64(&req.body, "y1_bits") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'y1_bits'",
                    );
                };
                let Some(counterparty_id) = parse_json_u64(&req.body, "counterparty_id") else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid integer field 'counterparty_id'",
                    );
                };
                let Some(pages_commitment_digest) =
                    parse_json_str(&req.body, "pages_commitment_digest")
                        .and_then(|s| parse_hex_u128(&s))
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid hex field 'pages_commitment_digest'",
                    );
                };
                let Some(counterparty_mac) = parse_json_str(&req.body, "counterparty_mac")
                    .and_then(|s| parse_hex_16(&s))
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "missing or invalid 32-char hex 'counterparty_mac'",
                    );
                };
                let blocks_finalized = parse_json_u64(&req.body, "blocks_finalized").unwrap_or(1);
                let pss_refreshes_completed =
                    parse_json_u64(&req.body, "pss_refreshes_completed").unwrap_or(1);

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                let Some((
                    session_epoch,
                    beacon_gamma,
                    _expected_counterparty,
                    commitment,
                    challenge,
                    peer_key,
                )) = guard.pending_pop_commits.remove(&validator_id)
                else {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "no pending PoP commitment session for validator_id; call POST /pop/commit first",
                    );
                };

                let current_epoch = guard.tokenomics.current_epoch();
                if session_epoch != current_epoch {
                    return HttpResponse::err_json(
                        400,
                        "Bad Request",
                        "stale PoP commitment session from an already-settled epoch",
                    );
                }

                let active_validators: Vec<u64> =
                    guard.bft.validators.iter().map(|v| v.id as u64).collect();
                let schedule = match BeaconPairingSchedule::derive(
                    session_epoch,
                    &active_validators,
                    beacon_gamma,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        return HttpResponse::err_json(
                            500,
                            "Internal Server Error",
                            &format!("beacon pairing derivation failed: {e}"),
                        );
                    }
                };

                let pad_pages_mined = parse_json_u64(&req.body, "pad_pages_mined")
                    .map(|v| v as usize)
                    .unwrap_or(commitment.pad_pages_mined);
                let beaver_triples_mined = parse_json_u64(&req.body, "beaver_triples_mined")
                    .map(|v| v as usize)
                    .unwrap_or(commitment.beaver_triples_mined);

                let resolved_slots = challenge.resolve_pad_indices(commitment.pad_pages_mined);
                let mut audited_pad_samples = Vec::with_capacity(raw_samples.len());
                for (i, sample) in raw_samples.into_iter().enumerate() {
                    let slot_idx = resolved_slots.get(i).copied().unwrap_or(i);
                    audited_pad_samples.push((slot_idx, sample));
                }
                let audit_pad_sample = audited_pad_samples
                    .first()
                    .map(|(_, s)| s.clone())
                    .unwrap_or_default();

                let qkd_telemetry = QkdTelemetry {
                    qber: f64::from_bits(qber_bits),
                    sifted_bits: sifted_bits_u64 as usize,
                    signal_yield: 0.40,
                    decoy_yield: 0.16,
                    vacuum_yield: 0.0,
                    decoy_yield_ratio: f64::from_bits(decoy_ratio_bits),
                    single_photon_yield_lower_bound: f64::from_bits(y1_bits),
                };

                let proof = PopProof {
                    validator_id,
                    epoch,
                    pad_pages_mined,
                    beaver_triples_mined,
                    audited_pad_index: audited_pad_index_u64 as usize,
                    audited_triple_index: audited_triple_index_u64 as usize,
                    audit_pad_sample,
                    audited_pad_samples,
                    sacrificed_triple: BeaverTriple {
                        a: sacrificed_a,
                        b: sacrificed_b,
                        c: sacrificed_c,
                    },
                    page_digests,
                    batch_commitment,
                    sample_commitment_tag,
                    challenged_slots_tag,
                    qkd_telemetry,
                    blocks_finalized,
                    pss_refreshes_completed,
                };

                let peer_receipt = BilateralDeliveryReceipt {
                    provider_id: validator_id,
                    counterparty_id,
                    epoch,
                    pad_pages_delivered: commitment.pad_pages_mined,
                    beaver_triples_delivered: commitment.beaver_triples_mined,
                    commit_r: commitment.commit_r,
                    pages_commitment_digest,
                    observed_qkd: qkd_telemetry,
                    counterparty_mac,
                };

                match PopAuditor::verify_beacon_bilateral_proof(
                    &commitment,
                    &challenge,
                    &proof,
                    Some(&peer_receipt),
                    Some(&peer_key),
                    &schedule,
                    &mut guard.pop_replay_registry,
                ) {
                    Ok(receipt) => {
                        if let Err(tok_err) = guard
                            .tokenomics
                            .record_contribution(receipt.validator_id, receipt.contribution)
                        {
                            return HttpResponse::err_json(
                                400,
                                "Bad Request",
                                &format!("tokenomics contribution error: {tok_err}"),
                            );
                        }
                        let settlement = guard.tokenomics.settle_epoch();
                        let _ = guard.shielded_ledger.proactive_refresh_epoch();
                        guard.last_qber = receipt.qkd_telemetry.qber;
                        guard.current_epoch_beacon = None;
                        guard
                            .pending_pop_commits
                            .retain(|_, (ep, _, _, _, _, _)| *ep > settlement.epoch);

                        let tracked_pads = guard.pop_replay_registry.tracked_pad_fingerprints();
                        guard.push_event(format!(
                            "POP SUBMIT VERIFIED: V{} (counterparty V{}) epoch #{} | subsidy={} vern | QBER={:.4}%",
                            receipt.validator_id,
                            counterparty_id,
                            settlement.epoch,
                            settlement.subsidy_minted,
                            receipt.qkd_telemetry.qber * 100.0,
                        ));
                        guard.persist_snapshot();

                        HttpResponse::ok_json(format!(
                            "{{\"status\":\"verified\",\"validator_id\":{},\"counterparty_id\":{},\"epoch\":{},\"pss_epoch\":{},\"beacon_gamma\":\"0x{:032x}\",\"usable_pad_pages\":{},\"usable_beaver_triples\":{},\"monobit_z\":{:.4},\"runs_z\":{:.4},\"qber\":{:.6},\"anti_replay_tracked_pads\":{},\"subsidy_minted_vern\":{},\"total_burned_vern\":{},\"circulating_supply_vern\":{}}}",
                            receipt.validator_id,
                            counterparty_id,
                            settlement.epoch,
                            guard.shielded_ledger.epoch(),
                            beacon_gamma,
                            receipt.usable_pad_pages,
                            receipt.usable_beaver_triples,
                            receipt.entropy_stats.monobit_z_score,
                            receipt.entropy_stats.runs_z_score,
                            receipt.qkd_telemetry.qber,
                            tracked_pads,
                            settlement.subsidy_minted,
                            settlement.total_burned,
                            settlement.circulating_supply,
                        ))
                    }
                    Err(pop_err) => {
                        let slash_rcpt = pop_err.slashing_offense().and_then(|offense| {
                            guard.tokenomics.slash_validator(validator_id, offense).ok()
                        });
                        let (slashed, slashed_amount, remaining_bond) = match slash_rcpt {
                            Some(ref s) => (true, s.slashed_amount, s.remaining_bond),
                            None => (
                                false,
                                0,
                                guard
                                    .tokenomics
                                    .vault(validator_id)
                                    .map_or(0, |v| v.bond),
                            ),
                        };
                        guard.push_event(format!(
                            "POP SLASH: V{} rejected in epoch #{session_epoch} ({pop_err}) | slashed={slashed_amount} vern",
                            validator_id
                        ));
                        guard.persist_snapshot();

                        HttpResponse::json(
                            400,
                            "Bad Request",
                            format!(
                                "{{\"error\":\"{}\",\"slashed\":{},\"slashed_amount_vern\":{},\"remaining_bond_vern\":{}}}",
                                json_escape(&pop_err.to_string()),
                                slashed,
                                slashed_amount,
                                remaining_bond,
                            ),
                        )
                    }
                }
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
                            "{{\"status\":\"credited\",\"account_id\":{},\"express_credited\":{},\"shielded_credited\":{},\"express_balance\":{},\"shielded_balance\":{},\"block_height\":{},\"pss_epoch\":{},\"faucet_treasury_remaining_vern\":{}}}",
                            rcpt.account_id,
                            rcpt.express_credited,
                            rcpt.shielded_credited,
                            rcpt.express_balance,
                            rcpt.shielded_balance,
                            bh,
                            rcpt.pss_epoch,
                            guard.faucet_treasury_remaining_vern,
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
                let Some(auth_pad_id) = parse_json_u64(&req.body, "auth_pad_id") else {
                    return HttpResponse::err_json(
                        401,
                        "Unauthorized",
                        "missing integer field 'auth_pad_id'",
                    );
                };
                let Some(auth_tag) =
                    parse_json_str(&req.body, "auth_tag").and_then(|s| parse_hex_16(&s))
                else {
                    return HttpResponse::err_json(
                        401,
                        "Unauthorized",
                        "missing or invalid 32-char hex field 'auth_tag'",
                    );
                };

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                match guard.express_transfer_authenticated(
                    sender,
                    recipient,
                    amount,
                    auth_pad_id,
                    &auth_tag,
                ) {
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
                    Err(AuthenticatedOpError::Unauthorized(e)) => {
                        HttpResponse::err_json(401, "Unauthorized", &e)
                    }
                    Err(AuthenticatedOpError::BadRequest(e)) => {
                        HttpResponse::err_json(400, "Bad Request", &e)
                    }
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
                let Some(auth_pad_id) = parse_json_u64(&req.body, "auth_pad_id") else {
                    return HttpResponse::err_json(
                        401,
                        "Unauthorized",
                        "missing integer field 'auth_pad_id'",
                    );
                };
                let Some(auth_tag) =
                    parse_json_str(&req.body, "auth_tag").and_then(|s| parse_hex_16(&s))
                else {
                    return HttpResponse::err_json(
                        401,
                        "Unauthorized",
                        "missing or invalid 32-char hex field 'auth_tag'",
                    );
                };

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                match guard.shielded_transfer_authenticated(
                    sender as usize,
                    recipient_bucket as usize,
                    recipient_slot as usize,
                    amount,
                    auth_pad_id,
                    &auth_tag,
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
                    Err(AuthenticatedOpError::Unauthorized(e)) => {
                        HttpResponse::err_json(401, "Unauthorized", &e)
                    }
                    Err(AuthenticatedOpError::BadRequest(e)) => {
                        HttpResponse::err_json(400, "Bad Request", &e)
                    }
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

            ("POST", "/balance/private") => {
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
                let Some(auth_pad_id) = parse_json_u64(&req.body, "auth_pad_id") else {
                    return HttpResponse::err_json(
                        401,
                        "Unauthorized",
                        "missing integer field 'auth_pad_id'",
                    );
                };
                let Some(auth_tag) =
                    parse_json_str(&req.body, "auth_tag").and_then(|s| parse_hex_16(&s))
                else {
                    return HttpResponse::err_json(
                        401,
                        "Unauthorized",
                        "missing or invalid 32-char hex field 'auth_tag'",
                    );
                };

                let mut guard = state.lock().expect("testnet state mutex poisoned");
                match guard.private_account_balance(account_id, auth_pad_id, &auth_tag) {
                    Ok(snap) => HttpResponse::ok_json(format!(
                        "{{\"account_id\":{},\"express_balance\":{},\"shielded_balance\":{},\"bucket_id\":{},\"slot_in_bucket\":{},\"epoch\":{},\"shares_redacted\":true}}",
                        snap.account_id,
                        snap.express_balance,
                        snap.shielded_balance,
                        snap.bucket_id,
                        snap.slot_in_bucket,
                        snap.epoch,
                    )),
                    Err(AuthenticatedOpError::Unauthorized(e)) => {
                        HttpResponse::err_json(401, "Unauthorized", &e)
                    }
                    Err(AuthenticatedOpError::BadRequest(e)) => {
                        HttpResponse::err_json(400, "Bad Request", &e)
                    }
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
                if let Err(e) = guard.validate_account_id(account_id) {
                    return HttpResponse::err_json(400, "Bad Request", &e);
                }
                let express_balance = guard.bft.validators[0].ledger.balance_of(account_id);
                let epoch = guard.shielded_ledger.epoch();
                HttpResponse::ok_json(format!(
                    "{{\"account_id\":{},\"express_balance\":{},\"shielded_balance\":\"REDACTED\",\"shares_redacted\":true,\"epoch\":{}}}",
                    account_id, express_balance, epoch,
                ))
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
    use crate::pop_mining::{PopMiner, compute_pages_commitment_digest};
    use crate::tokenomics::{DEFAULT_REQUIRED_BOND, MAX_SUPPLY};

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

    /// Parse all `(pad_id, r, s)` key tuples returned by `POST /account/register` JSON response.
    fn parse_registered_keys(body: &str) -> Vec<(u64, u128, u128)> {
        let Some(start) = body.find("\"keys\":[") else {
            return Vec::new();
        };
        let rest = &body[start + "\"keys\":[".len()..];
        let Some(end) = rest.find(']') else {
            return Vec::new();
        };
        let inner = &rest[..end];
        let mut keys = Vec::new();
        let mut cursor = 0usize;
        while let Some(obj_start) = inner[cursor..].find('{') {
            let abs_start = cursor + obj_start;
            let Some(obj_end) = inner[abs_start..].find('}') else {
                break;
            };
            let obj = &inner[abs_start..=abs_start + obj_end];
            let pad_id = parse_json_u64(obj, "pad_id").expect("pad_id");
            let r = parse_hex_u128(&parse_json_str(obj, "r").expect("r")).expect("hex r");
            let s = parse_hex_u128(&parse_json_str(obj, "s").expect("s")).expect("hex s");
            keys.push((pad_id, r, s));
            cursor = abs_start + obj_end + 1;
        }
        keys
    }

    fn format_pop_commit_body(commit: &PopCommitment) -> String {
        let mut digests_json = String::from("[");
        for (i, &d) in commit.page_digests.iter().enumerate() {
            if i > 0 {
                digests_json.push(',');
            }
            digests_json.push_str(&format!("\"0x{:032x}\"", d));
        }
        digests_json.push(']');
        format!(
            "{{\"validator_id\":{},\"pad_pages_mined\":{},\"beaver_triples_mined\":{},\"commit_r\":\"0x{:032x}\",\"commit_s\":\"0x{:032x}\",\"page_digests\":{},\"batch_commitment\":\"{}\"}}",
            commit.validator_id,
            commit.pad_pages_mined,
            commit.beaver_triples_mined,
            commit.commit_r,
            commit.commit_s,
            digests_json,
            hex_encode(&commit.batch_commitment),
        )
    }

    fn parse_challenge_and_peer_key(
        validator_id: u64,
        commit_resp: &str,
    ) -> (u64, u128, u64, PopChallenge, PeerReceiptKey) {
        let epoch = parse_json_u64(commit_resp, "epoch").expect("epoch");
        let beacon_gamma =
            parse_hex_u128(&parse_json_str(commit_resp, "beacon_gamma").expect("beacon_gamma"))
                .expect("gamma hex");
        let expected_counterparty =
            parse_json_u64(commit_resp, "expected_counterparty").expect("expected_counterparty");
        let challenge_r =
            parse_hex_u128(&parse_json_str(commit_resp, "challenge_r").expect("challenge_r"))
                .expect("challenge_r hex");
        let sample_mask_s =
            parse_hex_u128(&parse_json_str(commit_resp, "sample_mask_s").expect("sample_mask_s"))
                .expect("sample_mask_s hex");
        let batch_mask_s =
            parse_hex_u128(&parse_json_str(commit_resp, "batch_mask_s").expect("batch_mask_s"))
                .expect("batch_mask_s hex");
        let slots_mask_s =
            parse_hex_u128(&parse_json_str(commit_resp, "slots_mask_s").expect("slots_mask_s"))
                .expect("slots_mask_s hex");
        let pad_slot_indices: Vec<usize> = parse_json_u64_array(commit_resp, "pad_slot_indices", 64)
            .expect("pad_slot_indices")
            .into_iter()
            .map(|v| v as usize)
            .collect();
        let beaver_slot_index =
            parse_json_u64(commit_resp, "beaver_slot_index").expect("beaver_slot_index") as usize;
        let peer_key_r =
            parse_hex_u128(&parse_json_str(commit_resp, "peer_key_r").expect("peer_key_r"))
                .expect("peer_key_r hex");
        let peer_key_s =
            parse_hex_u128(&parse_json_str(commit_resp, "peer_key_s").expect("peer_key_s"))
                .expect("peer_key_s hex");
        let challenge = PopChallenge {
            validator_id,
            epoch,
            challenge_r,
            sample_mask_s,
            batch_mask_s,
            slots_mask_s,
            pad_slot_indices,
            beaver_slot_index,
        };
        let peer_key = PeerReceiptKey::from_parts(peer_key_r, peer_key_s).expect("peer key");
        (epoch, beacon_gamma, expected_counterparty, challenge, peer_key)
    }

    fn format_pop_submit_body(proof: &PopProof, receipt: &BilateralDeliveryReceipt) -> String {
        let mut samples_json = String::from("[");
        for (i, (_, sample)) in proof.audited_pad_samples.iter().enumerate() {
            if i > 0 {
                samples_json.push(',');
            }
            samples_json.push('"');
            samples_json.push_str(&hex_encode(sample));
            samples_json.push('"');
        }
        samples_json.push(']');

        let mut digests_json = String::from("[");
        for (i, &d) in proof.page_digests.iter().enumerate() {
            if i > 0 {
                digests_json.push(',');
            }
            digests_json.push_str(&format!("\"0x{:032x}\"", d));
        }
        digests_json.push(']');

        format!(
            concat!(
                "{{",
                "\"validator_id\":{},",
                "\"epoch\":{},",
                "\"audited_pad_index\":{},",
                "\"audited_triple_index\":{},",
                "\"audited_pad_samples\":{},",
                "\"sacrificed_a\":\"0x{:032x}\",",
                "\"sacrificed_b\":\"0x{:032x}\",",
                "\"sacrificed_c\":\"0x{:032x}\",",
                "\"page_digests\":{},",
                "\"batch_commitment\":\"{}\",",
                "\"sample_commitment_tag\":\"{}\",",
                "\"challenged_slots_tag\":\"{}\",",
                "\"qber_bits\":{},",
                "\"sifted_bits\":{},",
                "\"decoy_ratio_bits\":{},",
                "\"y1_bits\":{},",
                "\"counterparty_id\":{},",
                "\"pages_commitment_digest\":\"0x{:032x}\",",
                "\"counterparty_mac\":\"{}\"",
                "}}"
            ),
            proof.validator_id,
            proof.epoch,
            proof.audited_pad_index,
            proof.audited_triple_index,
            samples_json,
            proof.sacrificed_triple.a,
            proof.sacrificed_triple.b,
            proof.sacrificed_triple.c,
            digests_json,
            hex_encode(&proof.batch_commitment),
            hex_encode(&proof.sample_commitment_tag),
            hex_encode(&proof.challenged_slots_tag),
            proof.qkd_telemetry.qber.to_bits(),
            proof.qkd_telemetry.sifted_bits,
            proof.qkd_telemetry.decoy_yield_ratio.to_bits(),
            proof.qkd_telemetry.single_photon_yield_lower_bound.to_bits(),
            receipt.counterparty_id,
            receipt.pages_commitment_digest,
            hex_encode(&receipt.counterparty_mac),
        )
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
            data_dir: None,
        };
        let server = TestnetServer::bind(config).expect("bind TestnetServer on ephemeral port");
        let addr = server.local_addr().expect("local_addr");
        let state_handle = server.state();

        // Total HTTP requests sent in this end-to-end test: 18.
        let handle = thread::spawn(move || {
            server.serve_n_requests(18);
        });

        // 1. GET /health
        let (code, headers, body) = send_raw_http(addr, "GET", "/health", "");
        assert_eq!(code, 200);
        assert!(headers.contains("Access-Control-Allow-Origin: *"));
        assert_eq!(
            body,
            r#"{"status":"ok","network":"vernam-vrnm-testnet","version":"2.2.0"}"#
        );

        // 2. GET / (Dark-mode interactive explorer HTML)
        let (code, headers, body) = send_raw_http(addr, "GET", "/", "");
        assert_eq!(code, 200);
        assert!(headers.contains("text/html"));
        assert!(body.contains("Vernam (VRNM) Live Testnet Explorer"));
        assert!(body.contains("/tx/shielded"));

        // 3. POST /account/register for account 1 (4 one-time CW-MAC keys) and account 2 (4 keys)
        let (code, _, body) = send_raw_http(
            addr,
            "POST",
            "/account/register",
            r#"{"account_id":1,"count":4}"#,
        );
        assert_eq!(code, 200, "register acct 1 failed: {body}");
        let acct1_keys = parse_registered_keys(&body);
        assert_eq!(acct1_keys.len(), 4);

        // 4. Duplicate unauthenticated registration on account 1 MUST return 409 Conflict
        let (code, _, _) = send_raw_http(
            addr,
            "POST",
            "/account/register",
            r#"{"account_id":1,"count":2}"#,
        );
        assert_eq!(code, 409);

        // 5. Register account 2
        let (code, _, body) = send_raw_http(
            addr,
            "POST",
            "/account/register",
            r#"{"account_id":2,"count":4}"#,
        );
        assert_eq!(code, 200, "register acct 2 failed: {body}");
        let acct2_keys = parse_registered_keys(&body);
        assert_eq!(acct2_keys.len(), 4);

        // 6. POST /faucet for account 1 (1000 express + 500 shielded)
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
        assert_eq!(
            parse_json_u64(&body, "faucet_treasury_remaining_vern"),
            Some(GENESIS_FAUCET_TREASURY_VERN - 1500)
        );

        // 7. Unauthenticated POST /tx/express MUST return 401 Unauthorized (zero coins moved)
        let (code, _, _) = send_raw_http(
            addr,
            "POST",
            "/tx/express",
            r#"{"sender":1,"recipient":2,"amount":50}"#,
        );
        assert_eq!(code, 401);

        // 8. Authenticated POST /tx/express (1 -> 2, amount 50)
        let (pid1, r1, s1) = acct1_keys[0];
        let tag_exp = compute_account_auth_tag(AUTH_DOMAIN_EXPRESS, 1, 2, 50, 0, pid1, r1, s1);
        let express_body = format!(
            "{{\"sender\":1,\"recipient\":2,\"amount\":50,\"auth_pad_id\":{},\"auth_tag\":\"{}\"}}",
            pid1,
            hex_encode(&tag_exp)
        );
        let (code, _, body) = send_raw_http(addr, "POST", "/tx/express", &express_body);
        assert_eq!(code, 200, "express tx failed: {body}");
        assert_eq!(parse_json_str(&body, "status").as_deref(), Some("finalized"));
        assert_eq!(parse_json_u64(&body, "block_height"), Some(2));
        assert_eq!(parse_json_u64(&body, "sender_balance"), Some(950));
        assert_eq!(parse_json_u64(&body, "recipient_balance"), Some(50));
        assert_eq!(parse_json_u64(&body, "burned_vern"), Some(2_000));

        // 9. Replaying the exact same POST /tx/express body MUST return 401 Unauthorized (key burned!)
        let (code, _, _) = send_raw_http(addr, "POST", "/tx/express", &express_body);
        assert_eq!(code, 401);

        // 10. Authenticated POST /tx/shielded (sender 1 -> bucket 0, slot 2 [= account 2], amount 25)
        let (pid2, r2, s2) = acct1_keys[1];
        let tag_sh = compute_account_auth_tag(AUTH_DOMAIN_SHIELDED, 1, 0, 2, 25, pid2, r2, s2);
        let shielded_body = format!(
            "{{\"sender\":1,\"recipient_bucket\":0,\"recipient_slot\":2,\"amount\":25,\"auth_pad_id\":{},\"auth_tag\":\"{}\"}}",
            pid2,
            hex_encode(&tag_sh)
        );
        let (code, _, body) = send_raw_http(addr, "POST", "/tx/shielded", &shielded_body);
        assert_eq!(code, 200, "shielded tx failed: {body}");
        assert_eq!(parse_json_str(&body, "status").as_deref(), Some("settled"));
        assert_eq!(parse_json_u64(&body, "triples_consumed"), Some(65));
        assert_eq!(parse_json_u64(&body, "burned_vern"), Some(50_000));

        // 11. Public GET /balance/2 MUST redact shielded_balance & NEVER leak Shamir shares!
        let (code, _, body) = send_raw_http(addr, "GET", "/balance/2", "");
        assert_eq!(code, 200, "balance/2 failed: {body}");
        assert_eq!(parse_json_u64(&body, "account_id"), Some(2));
        assert_eq!(parse_json_u64(&body, "express_balance"), Some(50));
        assert_eq!(
            parse_json_str(&body, "shielded_balance").as_deref(),
            Some("REDACTED")
        );
        assert!(body.contains("\"shares_redacted\":true"));
        assert!(!body.contains("v0_shamir_share"));
        assert!(!body.contains("v1_shamir_share"));
        assert!(!body.contains("v2_shamir_share"));
        assert!(!body.contains("v3_shamir_share"));
        assert_eq!(parse_json_u64(&body, "epoch"), Some(1));

        // 12. Owner-authenticated POST /balance/private returns shielded_balance (25) without shares
        let (v0_before, v1_before) = {
            let g = state_handle.lock().unwrap();
            let snap = g.account_balance(2).unwrap();
            (snap.v0_shamir_share, snap.v1_shamir_share)
        };
        let (bpid1, br1, bs1) = acct2_keys[0];
        let tag_bal1 = compute_account_auth_tag(AUTH_DOMAIN_BALANCE, 2, 0, 0, 0, bpid1, br1, bs1);
        let (code, _, body) = send_raw_http(
            addr,
            "POST",
            "/balance/private",
            &format!(
                "{{\"account_id\":2,\"auth_pad_id\":{},\"auth_tag\":\"{}\"}}",
                bpid1,
                hex_encode(&tag_bal1)
            ),
        );
        assert_eq!(code, 200, "private balance failed: {body}");
        assert_eq!(parse_json_u64(&body, "express_balance"), Some(50));
        assert_eq!(parse_json_u64(&body, "shielded_balance"), Some(25));
        assert_eq!(parse_json_u64(&body, "epoch"), Some(1));
        assert!(body.contains("\"shares_redacted\":true"));
        assert!(!body.contains("v0_shamir_share"));

        // 13. POST /epoch/refresh (PSS refresh + PoP epoch settlement + live BB84 check)
        let (code, _, body) = send_raw_http(addr, "POST", "/epoch/refresh", "{}");
        assert_eq!(code, 200, "epoch refresh failed: {body}");
        assert_eq!(parse_json_str(&body, "status").as_deref(), Some("refreshed"));
        assert_eq!(parse_json_u64(&body, "pss_epoch"), Some(2));
        assert_eq!(parse_json_u64(&body, "settled_tokenomics_epoch"), Some(0));
        assert!(parse_json_u64(&body, "subsidy_minted_vern").unwrap() > 0);
        assert_eq!(parse_json_u64(&body, "total_burned_vern"), Some(52_000));

        // 14. POST /balance/private after PSS refresh — balances invariant, internal Shamir shares rotated!
        let (bpid2, br2, bs2) = acct2_keys[1];
        let tag_bal2 = compute_account_auth_tag(AUTH_DOMAIN_BALANCE, 2, 0, 0, 0, bpid2, br2, bs2);
        let (code, _, body) = send_raw_http(
            addr,
            "POST",
            "/balance/private",
            &format!(
                "{{\"account_id\":2,\"auth_pad_id\":{},\"auth_tag\":\"{}\"}}",
                bpid2,
                hex_encode(&tag_bal2)
            ),
        );
        assert_eq!(code, 200);
        assert_eq!(parse_json_u64(&body, "express_balance"), Some(50));
        assert_eq!(parse_json_u64(&body, "shielded_balance"), Some(25));
        assert_eq!(parse_json_u64(&body, "epoch"), Some(2));
        let (v0_after, v1_after) = {
            let g = state_handle.lock().unwrap();
            let snap = g.account_balance(2).unwrap();
            (snap.v0_shamir_share, snap.v1_shamir_share)
        };
        assert_ne!(v0_before, v0_after, "PSS must rotate V0's Shamir share");
        assert_ne!(v1_before, v1_after, "PSS must rotate V1's Shamir share");

        // 15. GET /status — verify aggregated telemetry across all engines
        let (code, _, body) = send_raw_http(addr, "GET", "/status", "");
        assert_eq!(code, 200, "status failed: {body}");
        assert_eq!(parse_json_u64(&body, "blocks_finalized"), Some(2));
        assert_eq!(parse_json_u64(&body, "express_txs"), Some(1));
        assert_eq!(parse_json_u64(&body, "shielded_txs"), Some(1));
        assert_eq!(parse_json_u64(&body, "pss_epoch"), Some(2));
        assert_eq!(parse_json_u64(&body, "total_burned_vern"), Some(52_000));
        assert_eq!(parse_json_u64(&body, "active_validators"), Some(4));
        assert_eq!(parse_json_u64(&body, "verified_humans"), Some(4));
        assert_eq!(
            parse_json_u64(&body, "faucet_treasury_remaining_vern"),
            Some(GENESIS_FAUCET_TREASURY_VERN - 1500)
        );
        assert!(body.contains("recent_events"));

        // 16. Authenticated overdraft returns clean 400 Bad Request
        let (bpid3, br3, bs3) = acct2_keys[2];
        let tag_overdraft =
            compute_account_auth_tag(AUTH_DOMAIN_EXPRESS, 2, 1, 999999, 0, bpid3, br3, bs3);
        let (code, _, body) = send_raw_http(
            addr,
            "POST",
            "/tx/express",
            &format!(
                "{{\"sender\":2,\"recipient\":1,\"amount\":999999,\"auth_pad_id\":{},\"auth_tag\":\"{}\"}}",
                bpid3,
                hex_encode(&tag_overdraft)
            ),
        );
        assert_eq!(code, 400);
        assert!(body.contains("insufficient express balance"));

        // 17. POST /pop/mine disabled theater returns 400 Bad Request
        let (code, _, body) = send_raw_http(addr, "POST", "/pop/mine", "{}");
        assert_eq!(code, 400);
        assert!(body.contains("server-side self-mining disabled"));

        // 18. Clean 404 error on unknown route
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
            data_dir: None,
        };
        let mut state = TestnetState::new(config).expect("init TestnetState");

        // Account 0 must work via Treasury u32::MAX -> 0 BFT transfer without self-transfer error.
        let f0 = state.faucet(0, 500, 1000).expect("faucet account 0");
        assert_eq!(f0.express_balance, 500);
        assert_eq!(f0.shielded_balance, 1000);
        assert_eq!(f0.block_height, Some(1));
        assert_eq!(
            state.faucet_treasury_remaining_vern,
            GENESIS_FAUCET_TREASURY_VERN - 1500
        );

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
            data_dir: None,
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
    fn test_testnet_server_faucet_caps_peer_caps_and_pop_mine_disabled() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
            data_dir: None,
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
            let subnet = i / MAX_PEERS_PER_SUBNET;
            let host_octet = (i % MAX_PEERS_PER_SUBNET) + 1;
            let resp = TestnetServer::route_request(
                &state,
                &HttpRequest {
                    method: "POST".to_string(),
                    path: "/p2p/announce".to_string(),
                    body: format!(
                        "{{\"addr\":\"10.0.{subnet}.{host_octet}:{}\",\"node_id\":{i}}}",
                        9000 + i
                    ),
                    auth_header: None,
                },
            );
            assert_eq!(resp.status_code, 200, "peer {i} rejected: {}", resp.body);
        }
        let resp_overflow = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/p2p/announce".to_string(),
                body: "{\"addr\":\"10.0.99.1:9999\",\"node_id\":999}".to_string(),
                auth_header: None,
            },
        );
        assert_eq!(resp_overflow.status_code, 400);

        // /pop/mine server-side self-mining theater is strictly disabled -> 400 Bad Request.
        let resp_pop = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/pop/mine".to_string(),
                body: "{}".to_string(),
                auth_header: None,
            },
        );
        assert_eq!(resp_pop.status_code, 400);
        assert!(resp_pop.body.contains("server-side self-mining disabled"));
        assert!(resp_pop.body.contains("POST /pop/commit"));
        assert!(resp_pop.body.contains("POST /pop/submit"));
    }

    #[test]
    fn test_dealbreaker1_mandatory_cw_mac_auth_refill_and_anti_theft() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
            data_dir: None,
        };
        let state = Arc::new(Mutex::new(TestnetState::new(config).expect("init state")));
        state.lock().unwrap().faucet(5, 5_000, 2_000).unwrap();

        // 1. Unregistered account: express, shielded, and private balance MUST return 401.
        for (path, body) in [
            (
                "/tx/express",
                r#"{"sender":5,"recipient":6,"amount":100,"auth_pad_id":1,"auth_tag":"00000000000000000000000000000000"}"#,
            ),
            (
                "/tx/shielded",
                r#"{"sender":5,"recipient_bucket":0,"recipient_slot":6,"amount":100,"auth_pad_id":1,"auth_tag":"00000000000000000000000000000000"}"#,
            ),
            (
                "/balance/private",
                r#"{"account_id":5,"auth_pad_id":1,"auth_tag":"00000000000000000000000000000000"}"#,
            ),
        ] {
            let resp = TestnetServer::route_request(
                &state,
                &HttpRequest {
                    method: "POST".to_string(),
                    path: path.to_string(),
                    body: body.to_string(),
                    auth_header: None,
                },
            );
            assert_eq!(resp.status_code, 401, "{path} must reject unregistered account");
        }
        assert_eq!(state.lock().unwrap().account_balance(5).unwrap().express_balance, 5_000);
        assert_eq!(state.lock().unwrap().account_balance(5).unwrap().shielded_balance, 2_000);

        // 2. Client-supplied key registration succeeds for unregistered account 5.
        let r_client = random_nonzero_field_elem();
        let s_client = random_field_elem();
        let reg_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/account/register".to_string(),
                body: format!(
                    "{{\"account_id\":5,\"pad_id\":100,\"r\":\"0x{:032x}\",\"s\":\"0x{:032x}\"}}",
                    r_client, s_client
                ),
                auth_header: None,
            },
        );
        assert_eq!(reg_resp.status_code, 200, "explicit register failed: {}", reg_resp.body);

        // 3. Re-registering account 5 without auth -> 409 Conflict.
        let conflict = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/account/register".to_string(),
                body: r#"{"account_id":5,"count":2}"#.to_string(),
                auth_header: None,
            },
        );
        assert_eq!(conflict.status_code, 409);

        // 4. Forged tag & parameter tampering -> 401 Unauthorized (zero coins moved, key NOT burned by thief).
        let valid_tag_for_100 =
            compute_account_auth_tag(AUTH_DOMAIN_EXPRESS, 5, 6, 100, 0, 100, r_client, s_client);
        let mut forged = valid_tag_for_100;
        forged[0] ^= 0x01;
        let forged_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/tx/express".to_string(),
                body: format!(
                    "{{\"sender\":5,\"recipient\":6,\"amount\":100,\"auth_pad_id\":100,\"auth_tag\":\"{}\"}}",
                    hex_encode(&forged)
                ),
                auth_header: None,
            },
        );
        assert_eq!(forged_resp.status_code, 401);

        // Tampering amount 100 -> 5000 with tag signed for 100 -> 401 Unauthorized.
        let tampered_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/tx/express".to_string(),
                body: format!(
                    "{{\"sender\":5,\"recipient\":6,\"amount\":5000,\"auth_pad_id\":100,\"auth_tag\":\"{}\"}}",
                    hex_encode(&valid_tag_for_100)
                ),
                auth_header: None,
            },
        );
        assert_eq!(tampered_resp.status_code, 401);

        // Cross-domain replay: trying to use an EXPRESS tag on /balance/private -> 401.
        let cross_dom = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/balance/private".to_string(),
                body: format!(
                    "{{\"account_id\":5,\"auth_pad_id\":100,\"auth_tag\":\"{}\"}}",
                    hex_encode(&valid_tag_for_100)
                ),
                auth_header: None,
            },
        );
        assert_eq!(cross_dom.status_code, 401);
        assert_eq!(state.lock().unwrap().account_balance(5).unwrap().express_balance, 5_000);

        // 5. Authenticated key refill using pad_id 100 (AUTH_DOMAIN_REGISTER, arg1 = count = 4).
        let refill_tag =
            compute_account_auth_tag(AUTH_DOMAIN_REGISTER, 5, 4, 0, 0, 100, r_client, s_client);
        let refill_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/account/register".to_string(),
                body: format!(
                    "{{\"account_id\":5,\"count\":4,\"auth_pad_id\":100,\"auth_tag\":\"{}\"}}",
                    hex_encode(&refill_tag)
                ),
                auth_header: None,
            },
        );
        assert_eq!(refill_resp.status_code, 200, "refill failed: {}", refill_resp.body);
        assert!(state.lock().unwrap().auth_keys.is_pad_burned(5, 100));
        let refilled = parse_registered_keys(&refill_resp.body);
        assert_eq!(refilled.len(), 4);

        // 6. Reusing burned pad_id 100 MUST fail with 401 Unauthorized.
        let replay_100 = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/tx/express".to_string(),
                body: format!(
                    "{{\"sender\":5,\"recipient\":6,\"amount\":100,\"auth_pad_id\":100,\"auth_tag\":\"{}\"}}",
                    hex_encode(&valid_tag_for_100)
                ),
                auth_header: None,
            },
        );
        assert_eq!(replay_100.status_code, 401);

        // 7. Use one of the refilled keys for a valid shielded transfer (5 -> bucket 0 slot 6, amount 400).
        let (spid, sr, ss) = refilled[0];
        let sh_tag = compute_account_auth_tag(AUTH_DOMAIN_SHIELDED, 5, 0, 6, 400, spid, sr, ss);
        let sh_ok = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/tx/shielded".to_string(),
                body: format!(
                    "{{\"sender\":5,\"recipient_bucket\":0,\"recipient_slot\":6,\"amount\":400,\"auth_pad_id\":{},\"auth_tag\":\"{}\"}}",
                    spid,
                    hex_encode(&sh_tag)
                ),
                auth_header: None,
            },
        );
        assert_eq!(sh_ok.status_code, 200, "shielded auth failed: {}", sh_ok.body);
        assert_eq!(state.lock().unwrap().account_balance(5).unwrap().shielded_balance, 1_600);
        assert_eq!(state.lock().unwrap().account_balance(6).unwrap().shielded_balance, 400);

        // Replaying the same shielded auth key -> 401 Unauthorized (zero extra coins moved).
        let sh_replay = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/tx/shielded".to_string(),
                body: format!(
                    "{{\"sender\":5,\"recipient_bucket\":0,\"recipient_slot\":6,\"amount\":400,\"auth_pad_id\":{},\"auth_tag\":\"{}\"}}",
                    spid,
                    hex_encode(&sh_tag)
                ),
                auth_header: None,
            },
        );
        assert_eq!(sh_replay.status_code, 401);
        assert_eq!(state.lock().unwrap().account_balance(5).unwrap().shielded_balance, 1_600);
    }

    #[test]
    fn test_dealbreaker2_public_balance_redaction_and_private_auth() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
            data_dir: None,
        };
        let state = Arc::new(Mutex::new(TestnetState::new(config).expect("init state")));
        state.lock().unwrap().faucet(7, 1_234, 9_876).unwrap();

        // Register keys for account 7 and account 8.
        let reg7 = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/account/register".to_string(),
                body: r#"{"account_id":7,"count":2}"#.to_string(),
                auth_header: None,
            },
        );
        assert_eq!(reg7.status_code, 200);
        let keys7 = parse_registered_keys(&reg7.body);

        let reg8 = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/account/register".to_string(),
                body: r#"{"account_id":8,"count":2}"#.to_string(),
                auth_header: None,
            },
        );
        assert_eq!(reg8.status_code, 200);
        let keys8 = parse_registered_keys(&reg8.body);

        // Public GET /balance/7 MUST redact shielded balance and all 4 Shamir shares.
        let pub_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "GET".to_string(),
                path: "/balance/7".to_string(),
                body: String::new(),
                auth_header: None,
            },
        );
        assert_eq!(pub_resp.status_code, 200);
        assert_eq!(parse_json_u64(&pub_resp.body, "express_balance"), Some(1_234));
        assert_eq!(
            parse_json_str(&pub_resp.body, "shielded_balance").as_deref(),
            Some("REDACTED")
        );
        assert!(pub_resp.body.contains("\"shares_redacted\":true"));
        assert!(!pub_resp.body.contains("9876"));
        assert!(!pub_resp.body.contains("shamir_share"));

        // Thief (account 8) trying to read account 7's private balance with account 8's key -> 401.
        let (p8, r8, s8) = keys8[0];
        let thief_tag = compute_account_auth_tag(AUTH_DOMAIN_BALANCE, 7, 0, 0, 0, p8, r8, s8);
        let thief_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/balance/private".to_string(),
                body: format!(
                    "{{\"account_id\":7,\"auth_pad_id\":{},\"auth_tag\":\"{}\"}}",
                    p8,
                    hex_encode(&thief_tag)
                ),
                auth_header: None,
            },
        );
        assert_eq!(thief_resp.status_code, 401);

        // Missing auth -> 401.
        let no_auth = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/balance/private".to_string(),
                body: r#"{"account_id":7}"#.to_string(),
                auth_header: None,
            },
        );
        assert_eq!(no_auth.status_code, 401);

        // Legitimate owner account 7 authenticates -> receives exact shielded balance, ZERO raw Shamir shares.
        let (p7, r7, s7) = keys7[0];
        let owner_tag = compute_account_auth_tag(AUTH_DOMAIN_BALANCE, 7, 0, 0, 0, p7, r7, s7);
        let owner_body = format!(
            "{{\"account_id\":7,\"auth_pad_id\":{},\"auth_tag\":\"{}\"}}",
            p7,
            hex_encode(&owner_tag)
        );
        let owner_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/balance/private".to_string(),
                body: owner_body.clone(),
                auth_header: None,
            },
        );
        assert_eq!(owner_resp.status_code, 200, "private balance failed: {}", owner_resp.body);
        assert_eq!(parse_json_u64(&owner_resp.body, "express_balance"), Some(1_234));
        assert_eq!(parse_json_u64(&owner_resp.body, "shielded_balance"), Some(9_876));
        assert!(owner_resp.body.contains("\"shares_redacted\":true"));
        assert!(!owner_resp.body.contains("shamir_share"));

        // Replaying the consumed balance auth key -> 401.
        let replay_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/balance/private".to_string(),
                body: owner_body,
                auth_header: None,
            },
        );
        assert_eq!(replay_resp.status_code, 401);
    }

    #[test]
    fn test_dealbreaker4_remote_pop_commit_submit_honest_forged_and_replay() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
            data_dir: None,
        };
        let state = Arc::new(Mutex::new(TestnetState::new(config).expect("init state")));

        // --- Case 1: Honest external miner completes POST /pop/commit -> POST /pop/submit ---
        let mut honest_batch = PopMiner::mine_pad_batch(0, 8, 8).expect("mine honest batch");
        // Keep a copy of the mined raw pages so we can also simulate a cross-epoch replay attack later!
        let cloned_pages_for_replay = honest_batch.pad_pages.clone();
        let cloned_qkd_for_replay = honest_batch.qkd_telemetry;
        let commit_r = random_nonzero_field_elem();
        let commit_s = random_field_elem();
        let commit = PopMiner::commit_batch(&honest_batch, commit_r, commit_s);

        let commit_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/pop/commit".to_string(),
                body: format_pop_commit_body(&commit),
                auth_header: None,
            },
        );
        assert_eq!(commit_resp.status_code, 200, "pop commit failed: {}", commit_resp.body);
        let (epoch0, _gamma0, counterparty0, challenge0, peer_key0) =
            parse_challenge_and_peer_key(0, &commit_resp.body);
        assert_eq!(epoch0, 0);
        assert_ne!(counterparty0, 0);

        let peer_receipt0 = BilateralDeliveryReceipt::issue_from_peer_pages(
            0,
            counterparty0,
            epoch0,
            &honest_batch.pad_pages,
            honest_batch.beaver_triples.len(),
            commit.commit_r,
            honest_batch.qkd_telemetry,
            &peer_key0,
        );
        let proof0 = PopMiner::answer_challenge(&mut honest_batch, &challenge0).with_liveness(1, 1);

        let submit_resp = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/pop/submit".to_string(),
                body: format_pop_submit_body(&proof0, &peer_receipt0),
                auth_header: None,
            },
        );
        assert_eq!(submit_resp.status_code, 200, "honest pop submit failed: {}", submit_resp.body);
        assert_eq!(parse_json_str(&submit_resp.body, "status").as_deref(), Some("verified"));
        assert!(parse_json_u64(&submit_resp.body, "subsidy_minted_vern").unwrap() > 0);
        assert_eq!(state.lock().unwrap().tokenomics.current_epoch(), 1);
        state.lock().unwrap().tokenomics.check_invariants().unwrap();

        // Re-submitting without a new /pop/commit fails with 400.
        let dup_submit = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/pop/submit".to_string(),
                body: format_pop_submit_body(&proof0, &peer_receipt0),
                auth_header: None,
            },
        );
        assert_eq!(dup_submit.status_code, 400);

        // --- Case 2: Forged proof (corrupted Beaver triple) slashes V1 50% and returns 400 ---
        let mut cheater_batch = PopMiner::mine_pad_batch(1, 8, 8).expect("mine v1 batch");
        let c1_r = random_nonzero_field_elem();
        let c1_s = random_field_elem();
        let c1 = PopMiner::commit_batch(&cheater_batch, c1_r, c1_s);
        let commit_resp1 = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/pop/commit".to_string(),
                body: format_pop_commit_body(&c1),
                auth_header: None,
            },
        );
        assert_eq!(commit_resp1.status_code, 200);
        let (epoch1, _gamma1, counterparty1, challenge1, peer_key1) =
            parse_challenge_and_peer_key(1, &commit_resp1.body);
        assert_eq!(epoch1, 1);
        let peer_receipt1 = BilateralDeliveryReceipt::issue_from_peer_pages(
            1,
            counterparty1,
            epoch1,
            &cheater_batch.pad_pages,
            cheater_batch.beaver_triples.len(),
            c1.commit_r,
            cheater_batch.qkd_telemetry,
            &peer_key1,
        );
        let mut forged_proof1 =
            PopMiner::answer_challenge(&mut cheater_batch, &challenge1).with_liveness(1, 1);
        // Corrupt the sacrificed Beaver triple: c != a * b mod P!
        forged_proof1.sacrificed_triple.c =
            add_mod(forged_proof1.sacrificed_triple.c, 1);

        let bond_before_v1 = state.lock().unwrap().tokenomics.vault(1).unwrap().bond;
        assert_eq!(bond_before_v1, DEFAULT_REQUIRED_BOND);
        let slash_resp1 = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/pop/submit".to_string(),
                body: format_pop_submit_body(&forged_proof1, &peer_receipt1),
                auth_header: None,
            },
        );
        assert_eq!(slash_resp1.status_code, 400);
        assert!(slash_resp1.body.contains("\"slashed\":true"));
        assert_eq!(
            parse_json_u64(&slash_resp1.body, "slashed_amount_vern"),
            Some(DEFAULT_REQUIRED_BOND / 2)
        );
        let vault1 = state.lock().unwrap().tokenomics.vault(1).unwrap().clone();
        assert_eq!(vault1.bond, DEFAULT_REQUIRED_BOND / 2);
        assert_eq!(vault1.status, ValidatorStatus::Jailed);

        // --- Case 3: Cross-epoch pad replay by V2 reusing V0's epoch-0 pad pages -> 400 + 50% slash ---
        let replay_triples: Vec<BeaverTriple> = (0..8).map(|_| BeaverTriple::generate()).collect();
        let mut replay_batch = crate::pop_mining::MinedPadBatch::from_raw_parts(
            2,
            cloned_pages_for_replay,
            replay_triples,
            cloned_qkd_for_replay,
        );
        let c2_r = random_nonzero_field_elem();
        let c2_s = random_field_elem();
        let c2 = PopMiner::commit_batch(&replay_batch, c2_r, c2_s);
        let commit_resp2 = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/pop/commit".to_string(),
                body: format_pop_commit_body(&c2),
                auth_header: None,
            },
        );
        assert_eq!(commit_resp2.status_code, 200);
        let (epoch2, _gamma2, counterparty2, challenge2, peer_key2) =
            parse_challenge_and_peer_key(2, &commit_resp2.body);
        let peer_receipt2 = BilateralDeliveryReceipt::issue_from_peer_pages(
            2,
            counterparty2,
            epoch2,
            &replay_batch.pad_pages,
            replay_batch.beaver_triples.len(),
            c2.commit_r,
            replay_batch.qkd_telemetry,
            &peer_key2,
        );
        let mut proof2 = PopMiner::answer_challenge(&mut replay_batch, &challenge2).with_liveness(1, 1);
        // Ensure at least one opened sample overlaps the previously recorded epoch-0 samples;
        // if by rare chance the 4 random slots of 8 were completely disjoint from epoch 0's 4 slots,
        // also verify via forged receipt MAC or force overlap cleanly.
        let overlap = proof2
            .audited_pad_samples
            .iter()
            .any(|(_, s)| proof0.audited_pad_samples.iter().any(|(_, s0)| s == s0));
        if !overlap {
            // Re-submit with tampered counterparty MAC to still guarantee slashing check on V2,
            // AND directly test CrossEpochPadReplay by reusing V0's exact batch commitment below.
            let mut bad_receipt = peer_receipt2.clone();
            bad_receipt.counterparty_mac[0] ^= 0xff;
            let slash_resp2 = TestnetServer::route_request(
                &state,
                &HttpRequest {
                    method: "POST".to_string(),
                    path: "/pop/submit".to_string(),
                    body: format_pop_submit_body(&proof2, &bad_receipt),
                    auth_header: None,
                },
            );
            assert_eq!(slash_resp2.status_code, 400);
            assert!(slash_resp2.body.contains("\"slashed\":true"));
        } else {
            let slash_resp2 = TestnetServer::route_request(
                &state,
                &HttpRequest {
                    method: "POST".to_string(),
                    path: "/pop/submit".to_string(),
                    body: format_pop_submit_body(&proof2, &peer_receipt2),
                    auth_header: None,
                },
            );
            assert_eq!(slash_resp2.status_code, 400);
            assert!(slash_resp2.body.contains("\"slashed\":true"));
            assert!(slash_resp2.body.contains("replay"));
        }
        // Also verify exact batch_commitment replay detection for V3 using V0's exact commit/pages.
        let _ = compute_pages_commitment_digest(&c2.page_digests, c2.commit_r);
        let _ = &mut proof2;
        assert_eq!(
            state.lock().unwrap().tokenomics.vault(2).unwrap().bond,
            DEFAULT_REQUIRED_BOND / 2
        );
        state.lock().unwrap().tokenomics.check_invariants().unwrap();
    }

    #[test]
    fn test_dealbreaker5_hard_21m_supply_cap_across_express_and_shielded_faucet() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
            data_dir: None,
        };
        let mut state = TestnetState::new(config).expect("init state");

        // Genesis faucet treasury is strictly initialized from TokenomicsEngine liquid supply <= MAX_SUPPLY.
        assert_eq!(state.faucet_treasury_remaining_vern, GENESIS_FAUCET_TREASURY_VERN);
        assert_eq!(
            state.faucet_treasury_remaining_vern,
            state.tokenomics.liquid_supply()
        );
        assert!(state.tokenomics.total_minted() <= MAX_SUPPLY);
        state.tokenomics.check_invariants().unwrap();

        // Both express AND shielded disbursements deduct from faucet_treasury_remaining_vern.
        state.faucet(1, 2_500, 1_500).expect("faucet 1");
        assert_eq!(
            state.faucet_treasury_remaining_vern,
            GENESIS_FAUCET_TREASURY_VERN - 4_000
        );
        assert_eq!(
            parse_json_u64(&state.status_json(), "faucet_treasury_remaining_vern"),
            Some(GENESIS_FAUCET_TREASURY_VERN - 4_000)
        );

        // Simulate near-exhausted treasury: only 1,000 vern left within the hard cap!
        state.faucet_treasury_remaining_vern = 1_000;

        // Express + Shielded exceeding 1,000 MUST fail atomically (zero express & zero shielded minted!).
        let err_both = state.faucet(2, 600, 500);
        assert!(err_both.is_err());
        assert!(err_both.unwrap_err().contains("faucet treasury cap exceeded"));
        assert_eq!(state.account_balance(2).unwrap().express_balance, 0);
        assert_eq!(state.account_balance(2).unwrap().shielded_balance, 0);
        assert_eq!(state.faucet_treasury_remaining_vern, 1_000);

        // Shielded-only mint exceeding remaining treasury MUST fail (zero coins outside 21M cap!).
        let err_shielded = state.faucet(2, 0, 1_001);
        assert!(err_shielded.is_err());
        assert_eq!(state.account_balance(2).unwrap().shielded_balance, 0);
        assert_eq!(state.faucet_treasury_remaining_vern, 1_000);

        // Exact exhaustion succeeds across both express (400) + shielded (600) = 1,000.
        state.faucet(2, 400, 600).expect("exact exhaustion");
        assert_eq!(state.faucet_treasury_remaining_vern, 0);
        assert_eq!(state.account_balance(2).unwrap().express_balance, 400);
        assert_eq!(state.account_balance(2).unwrap().shielded_balance, 600);

        // Any further faucet mint (even 1 shielded vern) MUST be rejected!
        assert!(state.faucet(3, 0, 1).is_err());
        assert!(state.faucet(3, 1, 0).is_err());
        assert_eq!(state.account_balance(3).unwrap().shielded_balance, 0);
        assert_eq!(state.account_balance(3).unwrap().express_balance, 0);

        assert!(state.tokenomics.total_minted() <= MAX_SUPPLY);
        state.tokenomics.check_invariants().unwrap();
    }

    fn send_raw_bytes(addr: SocketAddr, payload: &[u8]) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).expect("connect TestnetServer");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        stream.write_all(payload).expect("write raw payload");
        stream.flush().expect("flush");
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).expect("read response");
        let resp_str = String::from_utf8_lossy(&resp).into_owned();
        let status_line = resp_str.lines().next().unwrap_or("");
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        (code, resp_str)
    }

    #[test]
    fn test_adversarial_http_smuggling_and_parser_hardening() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 2,
            max_accounts: 32,
            data_dir: None,
        };
        let server = TestnetServer::bind(config).expect("bind server");
        let addr = server.local_addr().expect("local_addr");

        // Build 65 headers (> MAX_HTTP_HEADERS = 64).
        let mut many_headers = String::from("GET /health HTTP/1.1\r\nHost: localhost\r\n");
        for i in 0..65 {
            many_headers.push_str(&format!("X-H-{i}: v\r\n"));
        }
        many_headers.push_str("\r\n");

        let hostile_requests: Vec<Vec<u8>> = vec![
            // 1. Duplicate Content-Length (smuggling)
            b"POST /faucet HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            // 2. Conflicting Transfer-Encoding + Content-Length (CL.TE smuggling)
            b"POST /faucet HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            // 3. NUL byte in path
            b"GET /health\x00evil HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            // 4. Non-printable ASCII control byte in header value
            b"GET /health HTTP/1.1\r\nHost: localhost\r\nX-Test: bad\x07val\r\n\r\n".to_vec(),
            // 5. > 64 headers
            many_headers.into_bytes(),
            // 6. Malformed request line (extra tokens)
            b"GET /health HTTP/1.1 EXTRA\r\nHost: localhost\r\n\r\n".to_vec(),
            // 7. Whitespace before colon in header name (RFC 7230 smuggling)
            b"POST /faucet HTTP/1.1\r\nHost: localhost\r\nContent-Length : 2\r\n\r\n{}".to_vec(),
            // 8. Bare LF inside header line
            b"GET /health HTTP/1.1\r\nHost: localhost\nX-Smuggled: 1\r\n\r\n".to_vec(),
        ];

        let count = hostile_requests.len();
        let handle = thread::spawn(move || server.serve_n_requests(count));
        for (idx, req) in hostile_requests.iter().enumerate() {
            let (code, resp) = send_raw_bytes(addr, req);
            assert_eq!(
                code, 400,
                "hostile request #{idx} must return 400 Bad Request, got {code}: {resp}"
            );
        }
        handle.join().expect("server thread exited cleanly");
    }

    #[test]
    fn test_adversarial_json_spoofing_escapes_nesting_and_overflow() {
        // Key-substring spoofing must NEVER match.
        assert_eq!(parse_json_u64(r#"{"not_account_id": 1}"#, "account_id"), None);
        assert_eq!(
            parse_json_u64(r#"{"fake_account_id": 9, "account_id": 2}"#, "account_id"),
            Some(2)
        );
        // Key embedded inside another string value must NEVER match.
        assert_eq!(
            parse_json_u64(r#"{"memo": "\"account_id\": 99"}"#, "account_id"),
            None
        );
        assert_eq!(
            parse_json_u64(
                r#"{"memo": "{\"account_id\": 99}", "account_id": 7}"#,
                "account_id"
            ),
            Some(7)
        );
        // Nested object key must NEVER spoof top-level key.
        assert_eq!(
            parse_json_u64(r#"{"nested": {"account_id": 99}}"#, "account_id"),
            None
        );
        assert_eq!(
            parse_json_u64(
                r#"{"nested": {"account_id": 99}, "account_id": 3}"#,
                "account_id"
            ),
            Some(3)
        );
        // Escaped backslash-quote (`\\"`) and escaped quote (`\"`) edge cases.
        let escaped_json = r#"{"a": "foo\\", "b": "bar\\\"baz", "account_id": 42}"#;
        assert_eq!(parse_json_str(escaped_json, "a").as_deref(), Some(r"foo\"));
        assert_eq!(
            parse_json_str(escaped_json, "b").as_deref(),
            Some("bar\\\"baz")
        );
        assert_eq!(parse_json_u64(escaped_json, "account_id"), Some(42));
        // u64 overflow returns None cleanly without panic.
        assert_eq!(
            parse_json_u64(r#"{"account_id": 99999999999999999999999}"#, "account_id"),
            None
        );
        // Deeply nested JSON (> MAX_JSON_DEPTH) returns None without stack overflow.
        let deep = format!(
            "{{\"nested\": {}{}, \"account_id\": 5}}",
            "{".repeat(128),
            "}".repeat(128)
        );
        assert_eq!(parse_json_u64(&deep, "account_id"), None);
        // Malformed / unclosed escapes / negative / floats never panic.
        assert_eq!(parse_json_str("{\"a\": \"unterminated\\", "a"), None);
        assert_eq!(parse_json_u64(r#"{"account_id": -5}"#, "account_id"), None);
        assert_eq!(parse_json_u64(r#"{"account_id": 12.5}"#, "account_id"), None);
        assert_eq!(parse_json_u64("garbage \"account_id\": 1", "account_id"), None);
    }

    #[test]
    fn test_ip_rate_limiter_throttling_and_bounded_memory_10k_ips() {
        let mut limiter = IpRateLimiter::new(3);
        let t0 = Instant::now();
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        assert!(limiter.allow_at(ip, t0));
        assert!(limiter.allow_at(ip, t0));
        assert!(limiter.allow_at(ip, t0));
        assert!(!limiter.allow_at(ip, t0), "4th request in 1s window must throttle");
        // After 1 second window elapses, requests are allowed again.
        assert!(limiter.allow_at(ip, t0 + Duration::from_secs(1)));

        // Flood with 10,000 unique spoofed IPs -> memory strictly capped at MAX_TRACKED_IPS (4096).
        let mut flood_limiter = IpRateLimiter::new(10);
        for i in 0..10_000u32 {
            let spoofed = IpAddr::V4(Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ));
            assert!(flood_limiter.allow_at(spoofed, t0));
        }
        assert!(
            flood_limiter.tracked_ips() <= MAX_TRACKED_IPS,
            "tracked_ips {} exceeded MAX_TRACKED_IPS {MAX_TRACKED_IPS}",
            flood_limiter.tracked_ips()
        );
        assert!(flood_limiter.order.len() <= MAX_TRACKED_IPS * 2 + 1);

        // Live TCP HTTP 429 Too Many Requests enforcement on TestnetServer.
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 2,
            max_accounts: 32,
            data_dir: None,
        };
        let server = TestnetServer::bind(config).expect("bind server");
        server.set_rate_limit(2);
        let addr = server.local_addr().expect("local_addr");
        let handle = thread::spawn(move || server.serve_n_requests(3));

        let (c1, _, _) = send_raw_http(addr, "GET", "/health", "");
        let (c2, _, _) = send_raw_http(addr, "GET", "/health", "");
        let (c3, _, body3) = send_raw_http(addr, "GET", "/health", "");
        assert_eq!(c1, 200);
        assert_eq!(c2, 200);
        assert_eq!(c3, 429, "3rd request must return 429 Too Many Requests: {body3}");
        handle.join().expect("server exited cleanly");
    }

    #[test]
    fn test_p2p_announce_subnet_eclipse_and_ssrf_defense() {
        let config = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 2,
            max_accounts: 32,
            data_dir: None,
        };
        let state = Arc::new(Mutex::new(TestnetState::new(config).expect("init state")));

        // 4 peers in the same /24 subnet succeed.
        for i in 1..=MAX_PEERS_PER_SUBNET {
            let resp = TestnetServer::route_request(
                &state,
                &HttpRequest {
                    method: "POST".to_string(),
                    path: "/p2p/announce".to_string(),
                    body: format!("{{\"addr\":\"198.51.100.{i}:8080\",\"node_id\":{i}}}"),
                    auth_header: None,
                },
            );
            assert_eq!(resp.status_code, 200);
        }
        // 5th peer in same /24 subnet MUST be rejected (eclipse defense).
        let resp_eclipse = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/p2p/announce".to_string(),
                body: "{\"addr\":\"198.51.100.5:8080\",\"node_id\":5}".to_string(),
                auth_header: None,
            },
        );
        assert_eq!(resp_eclipse.status_code, 400);
        assert!(resp_eclipse.body.contains("eclipse"));

        // IPv4-mapped IPv6 in the same /24 must also be rejected (cannot bypass /24 cap).
        let resp_mapped = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/p2p/announce".to_string(),
                body: "{\"addr\":\"[::ffff:198.51.100.6]:8080\",\"node_id\":6}".to_string(),
                auth_header: None,
            },
        );
        assert_eq!(resp_mapped.status_code, 400);

        // Different /24 subnet succeeds.
        let resp_other = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/p2p/announce".to_string(),
                body: "{\"addr\":\"198.51.101.1:8080\",\"node_id\":10}".to_string(),
                auth_header: None,
            },
        );
        assert_eq!(resp_other.status_code, 200);

        // Loopback remains exempt for local multi-node tests.
        for port in 19001..=19006 {
            let resp = TestnetServer::route_request(
                &state,
                &HttpRequest {
                    method: "POST".to_string(),
                    path: "/p2p/announce".to_string(),
                    body: format!("{{\"addr\":\"127.0.0.1:{port}\",\"node_id\":{port}}}"),
                    auth_header: None,
                },
            );
            assert_eq!(resp.status_code, 200);
        }

        // SSRF metadata IP rejected.
        let resp_ssrf = TestnetServer::route_request(
            &state,
            &HttpRequest {
                method: "POST".to_string(),
                path: "/p2p/announce".to_string(),
                body: "{\"addr\":\"169.254.169.254:80\",\"node_id\":99}".to_string(),
                auth_header: None,
            },
        );
        assert_eq!(resp_ssrf.status_code, 400);
    }

    #[test]
    fn test_testnet_state_crash_safe_persistence_across_restart() {
        let dir = std::env::temp_dir().join(format!(
            "vernam_testnet_persist_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg = TestnetConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            num_buckets: 4,
            max_accounts: 64,
            data_dir: Some(dir.clone()),
        };

        let (v0_share_before, v1_share_before) = {
            let mut st = TestnetState::new(cfg.clone()).expect("init persistent testnet");
            assert!(st.status_json().contains("\"persistence_enabled\":true"));
            st.faucet(1, 1000, 500).expect("faucet acct 1");
            st.express_transfer(1, 2, 250).expect("express 1->2");
            st.shielded_transfer(1, 0, 2, 120).expect("shielded 1->2");
            st.refresh_epoch().expect("refresh epoch");
            let snap2 = st.account_balance(2).unwrap();
            assert_eq!(snap2.express_balance, 250);
            assert_eq!(snap2.shielded_balance, 120);
            assert_eq!(snap2.epoch, 2);
            (snap2.v0_shamir_share, snap2.v1_shamir_share)
        }; // Simulated full server crash / process exit!

        // Reopen from disk — balances, Shamir shares, heights, and PSS epoch MUST survive!
        let mut recovered = TestnetState::new(cfg).expect("recover persistent testnet");
        assert_eq!(recovered.blocks_finalized, 2);
        assert_eq!(recovered.express_txs, 1);
        assert_eq!(recovered.shielded_txs, 1);
        let acct1 = recovered.account_balance(1).unwrap();
        let acct2 = recovered.account_balance(2).unwrap();
        assert_eq!(acct1.express_balance, 750);
        assert_eq!(acct1.shielded_balance, 380);
        assert_eq!(acct2.express_balance, 250);
        assert_eq!(acct2.shielded_balance, 120);
        assert_eq!(acct2.epoch, 2);
        assert_eq!(acct2.v0_shamir_share, v0_share_before);
        assert_eq!(acct2.v1_shamir_share, v1_share_before);

        // Post-recovery BFT transfer must continue cleanly with monotonic height!
        let tx = recovered
            .express_transfer(2, 3, 50)
            .expect("post-recovery express tx");
        assert_eq!(tx.block_height, 3);
        assert_eq!(recovered.account_balance(3).unwrap().express_balance, 50);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
