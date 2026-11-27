//! Decentralized Multi-VPS P2P Validator Node for Vernam (VRNM).
//!
//! Zero external crates (`std::net`, `std::sync`, `std::thread`, `std::io`, `std::time`).
//! Zero computational cryptography (no SHA-256, RSA, ECDSA, AES, or zk-SNARKs):
//! - Block chain tags use deterministic Carter-Wegman polynomial authentication over
//!   the Mersenne prime field `F_(2^127 - 1)` (`crate::field`).
//! - Live BB84 + Weak/Vacuum Decoy-State QKD link telemetry (`crate::qkd::Bb84Channel`)
//!   with volatile secret zeroization (`crate::field::zeroize_slice`).
//! - Bitcoin Core-style DNS (`std::net::ToSocketAddrs`) + `ip:port` seed bootstrap
//!   and automatic transitive peer gossip (`A <-> B <-> C` self-organizes into a full mesh).
//! - Automatic block gossip with tag deduplication (zero gossip storms) and catch-up sync
//!   for late-joining nodes.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, ct_eq_u128, mul_mod, random_field_elem, reduce, zeroize_slice,
    zeroize_u128,
};
use crate::qkd::{Bb84Channel, Bb84Config, OsEntropySource};
pub use crate::testnet_server::{DEFAULT_RATE_LIMIT_PER_SEC, IpRateLimiter, MAX_TRACKED_IPS};
use crate::tokenomics::MAX_SUPPLY;

/// Dedicated treasury account ID used by `/faucet` so faucet credits flow through
/// real P2P block propagation and consensus validation.
pub const TREASURY_ACCOUNT_ID: u32 = u32::MAX;

/// Initial treasury balance at genesis (10,000,000 VRNM test units), strictly capped within `MAX_SUPPLY`.
pub const TREASURY_INITIAL_BALANCE: u64 = 10_000_000;

/// Strict per-request faucet cap for P2P nodes.
pub const MAX_P2P_FAUCET_PER_REQUEST: u64 = 100_000;

const _: () = assert!(TREASURY_INITIAL_BALANCE <= MAX_SUPPLY);

/// Domain separator for P2P transaction sender Carter-Wegman authentication tags (`F_(2^127 - 1)`).
pub const AUTH_DOMAIN_P2P_TX: u64 = 4;

/// Maximum one-time sender auth keys accepted in a single `POST /p2p/register` call.
const MAX_REGISTER_KEYS_PER_CALL: usize = 256;

/// Maximum total one-time sender auth keys tracked simultaneously by a single P2P node.
const MAX_TOTAL_SENDER_AUTH_KEYS: usize = 65_536;

/// Environment variable for loading a private P2P block-sealing key (`<r_hex>:<s_hex>`).
pub const P2P_SEAL_KEY_ENV: &str = "VRNM_P2P_SEAL_KEY";

/// Maximum number of recent node events retained in `GET /status`.
pub const MAX_RECENT_EVENTS: usize = 32;

/// Default outbound peer HTTP timeout (2 seconds).
pub const DEFAULT_PEER_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum concurrent inbound HTTP/P2P connections permitted before returning HTTP 503.
const MAX_CONCURRENT_CONNS: usize = 64;

/// Maximum number of remote peers retained in the P2P peer table.
const MAX_PEERS: usize = 64;

/// Maximum peers permitted from any single non-loopback IPv4 `/24` (or IPv6 `/48`) subnet
/// to defeat P2P eclipse attacks.
pub const MAX_PEERS_PER_SUBNET: usize = 4;

/// Maximum pending jobs buffered in the asynchronous gossip queue.
const MAX_GOSSIP_QUEUE: usize = 256;

/// Maximum finalized blocks returned per `GET /p2p/blocks` page.
const MAX_BLOCKS_PER_PAGE: usize = 100;

/// Overall wall-clock deadline for reading a single inbound HTTP request (Slowloris defense).
const HTTP_READ_DEADLINE: Duration = Duration::from_secs(5);

/// Socket write timeout for HTTP responses.
const HTTP_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum accepted HTTP request/response header size (16 KiB).
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;

/// Maximum accepted HTTP header count per request.
const MAX_HTTP_HEADERS: usize = 64;

/// Maximum accepted HTTP request/response body size (4 MiB).
const MAX_HTTP_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Maximum JSON nesting depth permitted by the built-in parser.
const MAX_JSON_DEPTH: usize = 32;

/// Maximum total JSON elements/values permitted in a single parsed document (CPU/OOM defense).
const MAX_JSON_ELEMENTS: usize = 16_384;

/// Genesis block tag (16 zero bytes, 32 hex zeros).
pub const GENESIS_TAG_HEX: &str = "00000000000000000000000000000000";

/// Private Carter-Wegman block-sealing key `(r, s)` in `F_(2^127 - 1)` (`0 < r < PRIME_P`,
/// `s < PRIME_P`), with redacted `Debug`, constant-time equality, and volatile zeroization on `Drop`.
///
/// There is intentionally NO hardcoded default key in source code: keys must be generated
/// OS-randomly, loaded from `VRNM_P2P_SEAL_KEY` / a `0600` keyfile, or provisioned pairwise per peer.
#[derive(Clone)]
pub struct BlockSealKey {
    r: u128,
    s: u128,
}

impl BlockSealKey {
    /// Generate a fresh OS-random Carter-Wegman block-sealing key via `random_field_elem`
    /// with `0 < r < PRIME_P` and `0 <= s < PRIME_P`.
    pub fn generate() -> Self {
        let r = loop {
            let candidate = random_field_elem();
            if candidate != 0 {
                break candidate;
            }
        };
        let s = random_field_elem();
        Self { r, s }
    }

    /// Construct a [`BlockSealKey`] from raw field elements, validating `0 < r < PRIME_P` and `s < PRIME_P`.
    pub fn from_raw(r: u128, s: u128) -> Result<Self, String> {
        if r == 0 || r >= PRIME_P {
            return Err("invalid BlockSealKey: r must satisfy 0 < r < PRIME_P".to_string());
        }
        if s >= PRIME_P {
            return Err("invalid BlockSealKey: s must satisfy s < PRIME_P".to_string());
        }
        Ok(Self { r, s })
    }

    /// Parse a [`BlockSealKey`] from two hexadecimal strings representing `r` and `s` in `F_(2^127 - 1)`.
    pub fn from_hex_pair(r_hex: &str, s_hex: &str) -> Result<Self, String> {
        let r = parse_field_hex(r_hex, "r")?;
        let s = parse_field_hex(s_hex, "s")?;
        Self::from_raw(r, s)
    }

    /// Encode this key as a `(r_hex, s_hex)` pair of 32-character lowercase hexadecimal strings.
    pub fn to_hex_pair(&self) -> (String, String) {
        (format!("{:032x}", self.r), format!("{:032x}", self.s))
    }

    /// Parse a serialized key string (`"<r_hex>:<s_hex>"`, `"<r_hex>,<s_hex>"`, or 64-char hex).
    pub fn from_env_str(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("empty P2P block-sealing key string".to_string());
        }
        if let Some((r_hex, s_hex)) = trimmed
            .split_once(':')
            .or_else(|| trimmed.split_once(','))
        {
            return Self::from_hex_pair(r_hex, s_hex);
        }
        if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Self::from_hex_pair(&trimmed[..32], &trimmed[32..]);
        }
        Err("malformed P2P block-sealing key: expected '<r_hex>:<s_hex>'".to_string())
    }

    /// Serialize this key into `"<r_hex>:<s_hex>"` format suitable for `VRNM_P2P_SEAL_KEY` or a `0600` keyfile.
    pub fn to_env_string(&self) -> String {
        format!("{:032x}:{:032x}", self.r, self.s)
    }

    /// Load a [`BlockSealKey`] from `VRNM_P2P_SEAL_KEY` if set, otherwise load from `path`,
    /// or generate and atomically persist a fresh OS-random keyfile with `0600` permissions at `path`.
    ///
    /// Fails closed if `VRNM_P2P_SEAL_KEY` or the existing keyfile is malformed — NEVER falls back
    /// to any hardcoded constant.
    pub fn from_env_or_file(path: &Path) -> Result<Self, String> {
        if let Ok(mut env_val) = std::env::var(P2P_SEAL_KEY_ENV) {
            if !env_val.trim().is_empty() {
                let res = Self::from_env_str(&env_val);
                // SAFETY: zeroizing raw UTF-8 bytes before dropping the env string.
                zeroize_slice(unsafe { env_val.as_bytes_mut() });
                return res;
            }
        }

        if path.exists() {
            let mut raw = fs::read(path)
                .map_err(|e| format!("failed to read P2P seal keyfile {}: {e}", path.display()))?;
            let res = std::str::from_utf8(&raw)
                .map_err(|_| format!("P2P seal keyfile {} is not valid UTF-8", path.display()))
                .and_then(Self::from_env_str);
            zeroize_slice(&mut raw);
            return res;
        }

        let key = Self::generate();
        write_seal_keyfile_atomic(path, &key)?;
        Ok(key)
    }

    /// Return the Carter-Wegman evaluation point `r` in `(0, PRIME_P)`.
    #[inline]
    pub fn r(&self) -> u128 {
        self.r
    }

    /// Return the Carter-Wegman shift `s` in `[0, PRIME_P)`.
    #[inline]
    pub fn s(&self) -> u128 {
        self.s
    }
}

impl fmt::Debug for BlockSealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockSealKey")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for BlockSealKey {
    fn eq(&self, other: &Self) -> bool {
        ct_eq_u128(self.r, other.r) && ct_eq_u128(self.s, other.s)
    }
}

impl Eq for BlockSealKey {}

impl Drop for BlockSealKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

fn parse_field_hex(raw: &str, label: &str) -> Result<u128, String> {
    let trimmed = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    if trimmed.is_empty()
        || trimmed.len() > 32
        || !trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(format!(
            "invalid hex field element '{label}': expected 1..=32 hex digits"
        ));
    }
    u128::from_str_radix(trimmed, 16)
        .map_err(|_| format!("invalid hex field element '{label}'"))
}

fn write_seal_keyfile_atomic(path: &Path, key: &BlockSealKey) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                )
            })?;
        }
    }

    let pid = std::process::id();
    let rnd = random_field_elem() as u64;
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(format!(".{pid}.{rnd:016x}.tmp"));
    let tmp_path = PathBuf::from(tmp_os);

    let mut payload = format!("{}\n", key.to_env_string()).into_bytes();
    let write_res: io::Result<()> = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp_path)?;
        #[cfg(unix)]
        {
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&payload)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp_path, path)?;
        #[cfg(unix)]
        {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            if let Some(parent) = path.parent() {
                let dir = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                if let Ok(d) = File::open(dir) {
                    let _ = d.sync_all();
                }
            }
        }
        Ok(())
    })();
    zeroize_slice(&mut payload);

    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "failed to persist P2P seal keyfile {}: {e}",
            path.display()
        ));
    }
    Ok(())
}

/// Compute the canonical 127-bit Carter-Wegman sender authentication tag for a [`P2pTx`]
/// over `F_(2^127 - 1)` using domain separator `AUTH_DOMAIN_P2P_TX = 4`.
pub fn compute_p2p_tx_auth_tag(
    sender: u32,
    recipient: u32,
    amount: u64,
    nonce: u64,
    page_id: u64,
    r: u128,
    s: u128,
) -> [u8; 16] {
    let r = reduce(r);
    let mut acc = mul_mod(reduce(AUTH_DOMAIN_P2P_TX as u128), r); // AUTH_DOMAIN_P2P_TX = 4
    acc = mul_mod(add_mod(acc, reduce(sender as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(recipient as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(amount as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(nonce as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(page_id as u128)), r);
    add_mod(acc, reduce(s)).to_le_bytes()
}

// ============================================================================
// 1. Core Data Structures: Peers, Config, Transactions & Blocks
// ============================================================================

/// Metadata tracked for each peer validator in the Vernam P2P mesh.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerInfo {
    pub node_id: u64,
    pub addr: String,
    pub height: u64,
    pub pop_score: u64,
    pub qber: f64,
    pub last_seen_secs: u64,
    pub healthy: bool,
}

/// Configuration for a decentralized Vernam P2P validator node.
#[derive(Debug, Clone)]
pub struct P2pNodeConfig {
    pub node_id: u64,
    pub bind_addr: String,
    pub advertise_addr: String,
    pub seeds: Vec<String>,
    pub gossip_interval_ms: u64,
    /// Optional explicit cluster Carter-Wegman block-sealing key.
    /// When `None`, the node loads `VRNM_P2P_SEAL_KEY` if set (failing closed if malformed)
    /// or generates a fresh node-local OS-random [`BlockSealKey`] (so cross-node blocks
    /// require either a shared cluster key or pairwise per-peer keys in `pairwise_peer_keys`).
    pub cluster_seal_key: Option<BlockSealKey>,
}

impl Default for P2pNodeConfig {
    fn default() -> Self {
        Self {
            node_id: 0,
            bind_addr: "0.0.0.0:8080".to_string(),
            advertise_addr: "127.0.0.1:8080".to_string(),
            seeds: Vec::new(),
            gossip_interval_ms: 2_000,
            cluster_seal_key: None,
        }
    }
}

/// Compact 48-byte binary / JSON authenticated transfer settled on the Vernam P2P ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pTx {
    pub sender: u32,
    pub recipient: u32,
    pub amount: u64,
    pub page_id: u64,
    pub nonce: u64,
    /// Mandatory 128-bit one-time Carter-Wegman sender authentication tag (`F_(2^127 - 1)`).
    pub auth_tag: [u8; 16],
}

/// Structured transaction parsing/validation error distinguishing `401 Unauthorized` auth failures
/// from `400 Bad Request` malformed or ledger errors.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TxReject {
    Unauthorized(String),
    BadRequest(String),
}

impl TxReject {
    fn into_string(self) -> String {
        match self {
            TxReject::Unauthorized(s) | TxReject::BadRequest(s) => s,
        }
    }

    fn to_http_response(&self) -> HttpResponse {
        match self {
            TxReject::Unauthorized(msg) => HttpResponse::err_json(401, "Unauthorized", msg),
            TxReject::BadRequest(msg) => HttpResponse::err_json(400, "Bad Request", msg),
        }
    }
}

impl P2pTx {
    /// Fixed binary wire length in bytes (`4 + 4 + 8 + 8 + 8 + 16 = 48`).
    pub const WIRE_LEN: usize = 48;

    /// Construct a new [`P2pTx`] with an explicit 16-byte Carter-Wegman `auth_tag`.
    pub const fn new(
        sender: u32,
        recipient: u32,
        amount: u64,
        page_id: u64,
        nonce: u64,
        auth_tag: [u8; 16],
    ) -> Self {
        Self {
            sender,
            recipient,
            amount,
            page_id,
            nonce,
            auth_tag,
        }
    }

    /// Construct a new [`P2pTx`] authenticated with one-time Carter-Wegman key `(r, s)`.
    pub fn new_authenticated(
        sender: u32,
        recipient: u32,
        amount: u64,
        page_id: u64,
        nonce: u64,
        r: u128,
        s: u128,
    ) -> Self {
        let auth_tag = compute_p2p_tx_auth_tag(sender, recipient, amount, nonce, page_id, r, s);
        Self {
            sender,
            recipient,
            amount,
            page_id,
            nonce,
            auth_tag,
        }
    }

    /// Encode this transaction into its 48-byte little-endian binary wire format.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..4].copy_from_slice(&self.sender.to_le_bytes());
        out[4..8].copy_from_slice(&self.recipient.to_le_bytes());
        out[8..16].copy_from_slice(&self.amount.to_le_bytes());
        out[16..24].copy_from_slice(&self.page_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.nonce.to_le_bytes());
        out[32..48].copy_from_slice(&self.auth_tag);
        out
    }

    /// Decode a 48-byte little-endian binary transaction (including mandatory 16-byte `auth_tag`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::WIRE_LEN {
            return Err(format!(
                "invalid binary tx length: expected {} bytes (including 16-byte auth_tag), got {}",
                Self::WIRE_LEN,
                bytes.len()
            ));
        }
        let sender = u32::from_le_bytes(bytes[0..4].try_into().expect("4-byte slice"));
        let recipient = u32::from_le_bytes(bytes[4..8].try_into().expect("4-byte slice"));
        let amount = u64::from_le_bytes(bytes[8..16].try_into().expect("8-byte slice"));
        let page_id = u64::from_le_bytes(bytes[16..24].try_into().expect("8-byte slice"));
        let nonce = u64::from_le_bytes(bytes[24..32].try_into().expect("8-byte slice"));
        let auth_tag: [u8; 16] = bytes[32..48].try_into().expect("16-byte slice");
        Ok(Self {
            sender,
            recipient,
            amount,
            page_id,
            nonce,
            auth_tag,
        })
    }

    /// Serialize this transaction to JSON (including 32-char lowercase hex `"auth_tag"`).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"sender\":{},\"recipient\":{},\"amount\":{},\"page_id\":{},\"nonce\":{},\"auth_tag\":\"{}\"}}",
            self.sender,
            self.recipient,
            self.amount,
            self.page_id,
            self.nonce,
            hex_encode(&self.auth_tag)
        )
    }

    fn from_json_value_typed(v: &JsonValue) -> Result<Self, TxReject> {
        let sender = v
            .get_u32("sender")
            .ok_or_else(|| TxReject::BadRequest("missing or invalid u32 field 'sender'".to_string()))?;
        let recipient = v
            .get_u32("recipient")
            .ok_or_else(|| TxReject::BadRequest("missing or invalid u32 field 'recipient'".to_string()))?;
        let amount = v
            .get_u64("amount")
            .ok_or_else(|| TxReject::BadRequest("missing or invalid u64 field 'amount'".to_string()))?;
        let page_id = v
            .get_u64("page_id")
            .ok_or_else(|| TxReject::BadRequest("missing or invalid u64 field 'page_id'".to_string()))?;
        let nonce = v.get_u64("nonce").unwrap_or(0);
        let auth_tag_hex = v.get_str("auth_tag").ok_or_else(|| {
            TxReject::Unauthorized(
                "missing mandatory 32-hex Carter-Wegman 'auth_tag'".to_string(),
            )
        })?;
        let auth_tag = hex_decode_16(auth_tag_hex).ok_or_else(|| {
            TxReject::Unauthorized(
                "invalid 'auth_tag': expected 32 lowercase hex characters".to_string(),
            )
        })?;
        Ok(Self {
            sender,
            recipient,
            amount,
            page_id,
            nonce,
            auth_tag,
        })
    }

    fn from_json_value(v: &JsonValue) -> Result<Self, String> {
        Self::from_json_value_typed(v).map_err(TxReject::into_string)
    }
}

/// Finalized P2P block chained via Carter-Wegman universal authentication over `F_(2^127 - 1)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pBlock {
    pub height: u64,
    pub proposer_id: u64,
    pub prev_tag_hex: String,
    pub block_tag_hex: String,
    pub timestamp_secs: u64,
    pub txs: Vec<P2pTx>,
}

impl P2pBlock {
    /// Construct and seal a new [`P2pBlock`] using an explicit private [`BlockSealKey`]
    /// over `F_(2^127 - 1)`.
    pub fn seal(
        height: u64,
        proposer_id: u64,
        prev_tag: &[u8; 16],
        timestamp_secs: u64,
        txs: Vec<P2pTx>,
        key: &BlockSealKey,
    ) -> Self {
        let tag = compute_block_tag(height, proposer_id, prev_tag, timestamp_secs, &txs, key);
        Self {
            height,
            proposer_id,
            prev_tag_hex: hex_encode(prev_tag),
            block_tag_hex: hex_encode(&tag),
            timestamp_secs,
            txs,
        }
    }

    /// Recompute and verify this block's Carter-Wegman `F_(2^127 - 1)` tag in constant time
    /// against an explicit private [`BlockSealKey`].
    pub fn verify_tag(&self, key: &BlockSealKey) -> Result<[u8; 16], String> {
        let prev_tag = hex_decode_16(&self.prev_tag_hex)
            .ok_or_else(|| "invalid 16-byte hex 'prev_tag'".to_string())?;
        let claimed_tag = hex_decode_16(&self.block_tag_hex)
            .ok_or_else(|| "invalid 16-byte hex 'block_tag'".to_string())?;
        let expected = compute_block_tag(
            self.height,
            self.proposer_id,
            &prev_tag,
            self.timestamp_secs,
            &self.txs,
            key,
        );
        if !ct_eq_16(&claimed_tag, &expected) {
            return Err(format!(
                "invalid Carter-Wegman block tag at height {}: tag verification failed",
                self.height,
            ));
        }
        Ok(expected)
    }

    /// Serialize this block to JSON.
    pub fn to_json(&self) -> String {
        let mut txs_json = String::from("[");
        for (i, tx) in self.txs.iter().enumerate() {
            if i > 0 {
                txs_json.push(',');
            }
            txs_json.push_str(&tx.to_json());
        }
        txs_json.push(']');

        format!(
            "{{\"height\":{},\"proposer_id\":{},\"prev_tag\":\"{}\",\"block_tag\":\"{}\",\"timestamp_secs\":{},\"txs\":{}}}",
            self.height,
            self.proposer_id,
            json_escape(&self.prev_tag_hex),
            json_escape(&self.block_tag_hex),
            self.timestamp_secs,
            txs_json
        )
    }

    fn from_json_value(v: &JsonValue) -> Result<Self, String> {
        let height = v
            .get_u64("height")
            .ok_or_else(|| "missing or invalid u64 field 'height'".to_string())?;
        let proposer_id = v
            .get_u64("proposer_id")
            .ok_or_else(|| "missing or invalid u64 field 'proposer_id'".to_string())?;
        let prev_tag_hex = v
            .get_str("prev_tag")
            .ok_or_else(|| "missing string field 'prev_tag'".to_string())?
            .to_string();
        let block_tag_hex = v
            .get_str("block_tag")
            .ok_or_else(|| "missing string field 'block_tag'".to_string())?
            .to_string();
        let timestamp_secs = v.get_u64("timestamp_secs").unwrap_or(0);
        let txs_arr = v
            .get_array("txs")
            .ok_or_else(|| "missing array field 'txs'".to_string())?;
        let mut txs = Vec::with_capacity(txs_arr.len());
        for item in txs_arr {
            txs.push(P2pTx::from_json_value(item)?);
        }
        Ok(Self {
            height,
            proposer_id,
            prev_tag_hex,
            block_tag_hex,
            timestamp_secs,
            txs,
        })
    }
}

/// Summary returned by [`P2pNode::announce_to_seeds_and_peers`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub seeds_contacted: usize,
    pub peers_contacted: usize,
    pub peers_discovered: usize,
    pub blocks_synced: usize,
}

/// Compute a deterministic 127-bit Carter-Wegman universal polynomial chain tag over
/// `F_(2^127 - 1)` binding `prev_tag`, `height`, `proposer_id`, `timestamp_secs`, and all `txs`
/// (including each tx's `auth_tag`) using an explicit private [`BlockSealKey`].
pub fn compute_block_tag(
    height: u64,
    proposer_id: u64,
    prev_tag: &[u8; 16],
    timestamp_secs: u64,
    txs: &[P2pTx],
    key: &BlockSealKey,
) -> [u8; 16] {
    let cw_r = key.r();
    let cw_s = key.s();
    let mut acc = cw_s;
    let prev_elem = reduce(u128::from_le_bytes(*prev_tag));

    let header_words = [
        prev_elem,
        height as u128,
        proposer_id as u128,
        timestamp_secs as u128,
        txs.len() as u128,
    ];
    for w in header_words {
        acc = add_mod(mul_mod(acc, cw_r), reduce(w));
    }

    for tx in txs {
        let pair = ((tx.sender as u128) << 32) | (tx.recipient as u128);
        let auth_elem = reduce(u128::from_le_bytes(tx.auth_tag));
        let tx_words = [
            pair,
            tx.amount as u128,
            tx.page_id as u128,
            tx.nonce as u128,
            auth_elem,
        ];
        for w in tx_words {
            acc = add_mod(mul_mod(acc, cw_r), reduce(w));
        }
    }

    acc.to_le_bytes()
}

// ============================================================================
// 2. Address Normalization & Bitcoin Core-Style DNS Seed Resolution
// ============================================================================

/// Strip optional `http://` / `https://` scheme and trailing path, validating `host:port`.
pub fn normalize_addr(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty address".to_string());
    }
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim();
    let (host, port) = parse_host_port(authority)?;
    if host.contains(':') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

/// Split and validate a `host:port` or `[ipv6]:port` string.
pub fn parse_host_port(authority: &str) -> Result<(String, u16), String> {
    if authority.is_empty() || authority.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("malformed address '{authority}'"));
    }

    let (host, port_str) = if let Some(rest) = authority.strip_prefix('[') {
        let (ipv6, after) = rest
            .split_once("]:")
            .ok_or_else(|| format!("malformed bracketed IPv6 address '{authority}'"))?;
        (ipv6, after)
    } else {
        let (h, p) = authority
            .rsplit_once(':')
            .ok_or_else(|| format!("missing port in address '{authority}'"))?;
        if h.contains(':') {
            return Err(format!(
                "unbracketed IPv6 or extra colon in address '{authority}'"
            ));
        }
        (h, p)
    };

    if host.is_empty() {
        return Err(format!("empty host in address '{authority}'"));
    }
    if host
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')))
    {
        return Err(format!("invalid character in host '{host}'"));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port '{port_str}' in address '{authority}'"))?;
    if port == 0 {
        return Err(format!("port 0 is invalid for peer address '{authority}'"));
    }
    Ok((host.to_string(), port))
}

/// Returns `true` if `ip` is a forbidden SSRF target (cloud metadata / link-local `169.254.0.0/16`,
/// IPv6 link-local `fe80::/10`, multicast, broadcast, or unspecified `0.0.0.0`/`::`).
/// Loopback (`127.0.0.1` / `::1`) remains permitted for local multi-node deployments and tests.
pub fn is_ssrf_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_ssrf_blocked_v4(v4),
        IpAddr::V6(v6) => {
            if v6.is_multicast() || v6.is_unspecified() {
                return true;
            }
            // Reject IPv6 link-local (fe80::/10)
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Reject IPv4-mapped IPv6 addresses targeting blocked IPv4 ranges
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_ssrf_blocked_v4(mapped);
            }
            false
        }
    }
}

fn is_ssrf_blocked_v4(v4: Ipv4Addr) -> bool {
    v4.is_link_local()
        || v4.is_multicast()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.octets() == [169, 254, 169, 254]
}

fn reject_ssrf_literal_host(host: &str) -> Result<(), String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_ssrf_blocked_ip(ip) {
            return Err(format!(
                "SSRF protection: address '{host}' targets blocked metadata/link-local/multicast IP"
            ));
        }
    }
    Ok(())
}

/// Resolve a Bitcoin Core-style DNS seed (e.g., `seed.vernam.network:8080`, `localhost:8080`)
/// or plain `ip:port` seed into one or more deduplicated [`SocketAddr`] targets using
/// `std::net::ToSocketAddrs`, filtering out SSRF-blocked metadata/link-local/multicast IPs.
pub fn resolve_seed_addrs(seed: &str) -> Result<Vec<SocketAddr>, String> {
    let normalized = normalize_addr(seed)?;
    let (host, port) = parse_host_port(&normalized)?;
    reject_ssrf_literal_host(&host)?;
    let iter = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS/socket resolution failed for '{normalized}': {e}"))?;

    let mut addrs = Vec::new();
    let mut saw_blocked = false;
    for sa in iter {
        if is_ssrf_blocked_ip(sa.ip()) {
            saw_blocked = true;
            continue;
        }
        if !addrs.contains(&sa) {
            addrs.push(sa);
        }
    }
    if addrs.is_empty() {
        if saw_blocked {
            return Err(format!(
                "SSRF protection: seed '{normalized}' resolved only to blocked metadata/link-local/multicast IPs"
            ));
        }
        return Err(format!("seed '{normalized}' resolved to zero addresses"));
    }
    Ok(addrs)
}

// ============================================================================
// 3. Thread-Safe P2P Node Ledger & Peer Table State
// ============================================================================

/// Result of attempting to apply an incoming gossiped or synced block.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ApplyBlockOutcome {
    /// Block was validated and appended at `height`; caller should forward once if gossiped.
    Accepted,
    /// Block tag was already seen or already applied at this height; do NOT re-forward.
    Duplicate,
    /// Block height is ahead of `local_height + 1`; node should trigger catch-up sync.
    NeedSync { local_height: u64, incoming_height: u64 },
}

/// Complete thread-safe state of a decentralized Vernam P2P validator node.
pub struct P2pNodeState {
    pub config: P2pNodeConfig,
    /// Actual bound socket address.
    pub local_addr: SocketAddr,
    /// Private Carter-Wegman block-sealing key (never hardcoded; from config, env, or OS-random).
    seal_key: BlockSealKey,
    /// Pairwise per-peer Carter-Wegman block authentication keys keyed by normalized `host:port`.
    pub pairwise_peer_keys: BTreeMap<String, BlockSealKey>,
    /// One-time Carter-Wegman sender authentication keys: `(account_id, page_id) -> (r, s)`.
    /// Every key is verified in constant time (`ct_eq_16`) and burned immediately upon use.
    pub sender_auth_keys: BTreeMap<(u32, u64), (u128, u128)>,
    /// Known peers keyed by normalized `host:port` address.
    pub peers: BTreeMap<String, PeerInfo>,
    /// Finalized P2P blocks (`blocks[h - 1]` has `height == h`).
    pub blocks: Vec<P2pBlock>,
    /// Current committed chain height (`0` at genesis).
    pub height: u64,
    /// Current tip Carter-Wegman 16-byte tag (`[0u8; 16]` at genesis).
    pub tip_tag: [u8; 16],
    /// Account balances (treasury `u32::MAX` starts with `TREASURY_INITIAL_BALANCE`).
    pub balances: BTreeMap<u32, u64>,
    /// Total faucet units distributed from treasury (strictly capped by `TREASURY_INITIAL_BALANCE <= MAX_SUPPLY`).
    pub total_faucet_minted: u64,
    /// Replay protection table: every consumed `(sender, page_id)` OTP page.
    pub used_pages: BTreeSet<(u32, u64)>,
    /// Block tag deduplication set preventing gossip storms.
    pub seen_block_tags: HashSet<String>,
    /// Proof-of-Pad validator participation score (incremented on finalized/synced blocks & QKD).
    pub pop_score: u64,
    /// Total settled transactions across all finalized blocks.
    pub tx_count: u64,
    /// Most recently observed BB84 + Decoy-State QKD QBER.
    pub last_qber: f64,
    /// Live BB84 + Decoy-State QKD telemetry channel.
    pub qkd_channel: Bb84Channel<OsEntropySource>,
    /// Monotonic local sequence for treasury faucet page IDs.
    faucet_seq: u64,
    /// Recent human-readable P2P & consensus events.
    pub recent_events: Vec<String>,
}

impl Drop for P2pNodeState {
    fn drop(&mut self) {
        for (r, s) in self.sender_auth_keys.values_mut() {
            zeroize_u128(r);
            zeroize_u128(s);
        }
        self.sender_auth_keys.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PeerSubnetKey {
    V4([u8; 3]),
    V6([u16; 3]),
    Host(String),
}

/// Extract a `/24` IPv4 (or `/48` IPv6 / lowercase hostname) eclipse-defense subnet key for
/// `norm_addr`, returning `None` for loopback (`127.0.0.0/8`, `::1`, `localhost`) so local
/// multi-node deployments and tests remain unaffected.
fn peer_subnet_key(norm_addr: &str) -> Option<PeerSubnetKey> {
    let (host, _) = parse_host_port(norm_addr).ok()?;
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

impl P2pNodeState {
    /// Initialize a fresh P2P node state at genesis with real BB84 QKD calibration.
    pub fn new(config: P2pNodeConfig, local_addr: SocketAddr) -> Result<Self, String> {
        let seal_key = if let Some(ref key) = config.cluster_seal_key {
            key.clone()
        } else if let Ok(mut env_val) = std::env::var(P2P_SEAL_KEY_ENV) {
            if !env_val.trim().is_empty() {
                let parsed = BlockSealKey::from_env_str(&env_val);
                // SAFETY: zeroizing raw UTF-8 bytes before dropping.
                zeroize_slice(unsafe { env_val.as_bytes_mut() });
                parsed?
            } else {
                BlockSealKey::generate()
            }
        } else {
            // Fresh node-local OS-random key: cross-node block acceptance requires either an
            // explicit shared `cluster_seal_key` / `VRNM_P2P_SEAL_KEY` or pairwise per-peer keys.
            BlockSealKey::generate()
        };

        let qkd_cfg = Bb84Config {
            min_decoy_pulses: 2_000,
            min_vacuum_pulses: 500,
            ..Bb84Config::default()
        };
        let mut qkd_channel = Bb84Channel::new(qkd_cfg, OsEntropySource::new())
            .map_err(|e| format!("failed to init BB84 QKD channel: {e}"))?;
        let mut init_qkd = qkd_channel
            .exchange_key(32)
            .map_err(|e| format!("genesis BB84 QKD calibration failed: {e}"))?;
        let last_qber = init_qkd.qber;
        zeroize_slice(&mut init_qkd.alice_key);
        zeroize_slice(&mut init_qkd.bob_key);

        let mut balances = BTreeMap::new();
        balances.insert(TREASURY_ACCOUNT_ID, TREASURY_INITIAL_BALANCE);

        let mut seen_block_tags = HashSet::new();
        seen_block_tags.insert(GENESIS_TAG_HEX.to_string());

        let mut state = Self {
            config,
            local_addr,
            seal_key,
            pairwise_peer_keys: BTreeMap::new(),
            sender_auth_keys: BTreeMap::new(),
            peers: BTreeMap::new(),
            blocks: Vec::new(),
            height: 0,
            tip_tag: [0u8; 16],
            balances,
            total_faucet_minted: 0,
            used_pages: BTreeSet::new(),
            seen_block_tags,
            pop_score: 100,
            tx_count: 0,
            last_qber,
            qkd_channel,
            faucet_seq: 1,
            recent_events: Vec::with_capacity(MAX_RECENT_EVENTS),
        };

        state.push_event(format!(
            "BOOT: node_id={} addr={} seeds={} BB84 QBER={:.4}%",
            state.config.node_id,
            state.config.advertise_addr,
            state.config.seeds.len(),
            state.last_qber * 100.0
        ));

        Ok(state)
    }

    /// Borrow this node's active private [`BlockSealKey`].
    pub fn seal_key(&self) -> &BlockSealKey {
        &self.seal_key
    }

    /// Register a pairwise Carter-Wegman block authentication key for a specific remote peer address.
    pub fn register_pairwise_peer_key(
        &mut self,
        peer_addr: &str,
        key: BlockSealKey,
    ) -> Result<(), String> {
        let norm = normalize_addr(peer_addr)?;
        let (host, _) = parse_host_port(&norm)?;
        reject_ssrf_literal_host(&host)?;
        self.pairwise_peer_keys.insert(norm, key);
        Ok(())
    }

    /// Register one-time Carter-Wegman sender authentication keys `(page_id, r, s)` for `account_id`.
    ///
    /// Rejects `TREASURY_ACCOUNT_ID`, out-of-field `(r, s)` values, duplicate/overwriting keys,
    /// and already-consumed `page_id`s.
    pub fn register_sender_auth_keys(
        &mut self,
        account_id: u32,
        keys: &[(u64, u128, u128)],
    ) -> Result<usize, String> {
        if account_id == TREASURY_ACCOUNT_ID {
            return Err("cannot register external sender auth keys for treasury account".to_string());
        }
        if keys.is_empty() {
            return Err("register_sender_auth_keys requires at least one key".to_string());
        }
        if keys.len() > MAX_REGISTER_KEYS_PER_CALL {
            return Err(format!(
                "too many keys in single registration (max {MAX_REGISTER_KEYS_PER_CALL})"
            ));
        }
        if self.sender_auth_keys.len().saturating_add(keys.len()) > MAX_TOTAL_SENDER_AUTH_KEYS {
            return Err(format!(
                "sender auth key registry full (max {MAX_TOTAL_SENDER_AUTH_KEYS})"
            ));
        }

        // Pre-validate all entries atomically before inserting any.
        let mut batch_pages = BTreeSet::new();
        for &(page_id, r, s) in keys {
            if r == 0 || r >= PRIME_P {
                return Err(format!(
                    "invalid sender auth key for page_id={page_id}: r must be in (0, PRIME_P)"
                ));
            }
            if s >= PRIME_P {
                return Err(format!(
                    "invalid sender auth key for page_id={page_id}: s must be in [0, PRIME_P)"
                ));
            }
            if !batch_pages.insert(page_id) {
                return Err(format!(
                    "duplicate page_id={page_id} in registration batch"
                ));
            }
            if self.used_pages.contains(&(account_id, page_id)) {
                return Err(format!(
                    "cannot re-register already-consumed (account_id={account_id}, page_id={page_id})"
                ));
            }
            if self.sender_auth_keys.contains_key(&(account_id, page_id)) {
                return Err(format!(
                    "auth key already registered for (account_id={account_id}, page_id={page_id})"
                ));
            }
        }

        for &(page_id, r, s) in keys {
            self.sender_auth_keys.insert((account_id, page_id), (r, s));
        }
        Ok(keys.len())
    }

    /// Generate and register `count` fresh OS-random one-time sender auth keys `(page_id, r, s)`
    /// for `account_id`, starting at `start_page_id`.
    pub fn generate_and_register_sender_auth_keys(
        &mut self,
        account_id: u32,
        start_page_id: u64,
        count: usize,
    ) -> Result<Vec<(u64, u128, u128)>, String> {
        if count == 0 || count > MAX_REGISTER_KEYS_PER_CALL {
            return Err(format!(
                "key count must be in 1..={MAX_REGISTER_KEYS_PER_CALL}"
            ));
        }
        let mut generated = Vec::with_capacity(count);
        for i in 0..count {
            let page_id = start_page_id
                .checked_add(i as u64)
                .ok_or_else(|| "page_id overflow during auth key generation".to_string())?;
            let r = loop {
                let candidate = random_field_elem();
                if candidate != 0 {
                    break candidate;
                }
            };
            let s = random_field_elem();
            generated.push((page_id, r, s));
        }
        self.register_sender_auth_keys(account_id, &generated)?;
        Ok(generated)
    }

    /// Append a message into the capped `recent_events` ring buffer.
    pub fn push_event(&mut self, msg: String) {
        if self.recent_events.len() >= MAX_RECENT_EVENTS {
            self.recent_events.remove(0);
        }
        self.recent_events.push(msg);
    }

    /// Return this node's own [`PeerInfo`] descriptor.
    pub fn self_peer_info(&self) -> PeerInfo {
        PeerInfo {
            node_id: self.config.node_id,
            addr: self.config.advertise_addr.clone(),
            height: self.height,
            pop_score: self.pop_score,
            qber: self.last_qber,
            last_seen_secs: now_secs(),
            healthy: true,
        }
    }

    /// Check if `node_id` or `addr` refers to this node itself.
    pub fn is_self(&self, node_id: Option<u64>, addr: &str) -> bool {
        if let Some(id) = node_id {
            if id == self.config.node_id {
                return true;
            }
        }
        if let Ok(norm) = normalize_addr(addr) {
            if let Ok(self_norm) = normalize_addr(&self.config.advertise_addr) {
                if norm == self_norm {
                    return true;
                }
            }
            if norm == self.local_addr.to_string() {
                return true;
            }
        }
        false
    }

    /// Register or update a peer in the local peer table (ignoring self, SSRF targets, and malformed addresses).
    /// Caps the peer table at `MAX_PEERS` (64) and enforces per-`/24` IPv4 (and `/48` IPv6) subnet
    /// diversity (`MAX_PEERS_PER_SUBNET = 4`, exempting loopback) to prevent eclipse attacks.
    /// Returns `Ok(true)` if a brand-new peer was added, `Ok(false)` if updated or self-ignored.
    pub fn upsert_peer(&mut self, mut info: PeerInfo) -> Result<bool, String> {
        let norm_addr = normalize_addr(&info.addr)?;
        let (host, _) = parse_host_port(&norm_addr)?;
        reject_ssrf_literal_host(&host)?;
        if self.is_self(Some(info.node_id), &norm_addr) {
            return Ok(false);
        }
        info.addr = norm_addr.clone();
        if info.last_seen_secs == 0 {
            info.last_seen_secs = now_secs();
        }
        if !info.qber.is_finite() || info.qber < 0.0 {
            info.qber = 0.0;
        }
        let is_new = !self.peers.contains_key(&norm_addr);
        if is_new {
            // Eclipse-attack defense: cap peers per non-loopback /24 IPv4 (or /48 IPv6) subnet.
            if let Some(subnet) = peer_subnet_key(&norm_addr) {
                let same_subnet_count = self
                    .peers
                    .keys()
                    .filter(|k| peer_subnet_key(k).as_ref() == Some(&subnet))
                    .count();
                if same_subnet_count >= MAX_PEERS_PER_SUBNET {
                    let stale_in_subnet = self
                        .peers
                        .iter()
                        .filter(|(k, p)| !p.healthy && peer_subnet_key(k).as_ref() == Some(&subnet))
                        .min_by_key(|(_, p)| p.last_seen_secs)
                        .map(|(k, _)| k.clone());
                    if let Some(evict_key) = stale_in_subnet {
                        self.peers.remove(&evict_key);
                    } else {
                        return Err(format!(
                            "eclipse protection: per-subnet peer cap ({MAX_PEERS_PER_SUBNET}) reached"
                        ));
                    }
                }
            }
            if self.peers.len() >= MAX_PEERS {
                // Try evicting the stalest unhealthy peer before rejecting new peers.
                let stale_unhealthy = self
                    .peers
                    .iter()
                    .filter(|(_, p)| !p.healthy)
                    .min_by_key(|(_, p)| p.last_seen_secs)
                    .map(|(k, _)| k.clone());
                if let Some(evict_key) = stale_unhealthy {
                    self.peers.remove(&evict_key);
                } else {
                    return Err(format!("peer table full (max {MAX_PEERS} peers)"));
                }
            }
        }
        self.peers.insert(norm_addr.clone(), info);
        if is_new {
            self.push_event(format!("PEER DISCOVERED: {norm_addr}"));
        }
        Ok(is_new)
    }

    /// Mark an existing peer healthy or unhealthy after an outbound network attempt.
    pub fn set_peer_health(&mut self, addr: &str, healthy: bool) {
        if let Ok(norm) = normalize_addr(addr) {
            if let Some(p) = self.peers.get_mut(&norm) {
                p.healthy = healthy;
                if healthy {
                    p.last_seen_secs = now_secs();
                }
            }
        }
    }

    /// Return this node + all known healthy peers (for `GET /p2p/peers` and `POST /p2p/announce`).
    pub fn advertised_peers(&self) -> Vec<PeerInfo> {
        let mut list = Vec::with_capacity(1 + self.peers.len());
        list.push(self.self_peer_info());
        for p in self.peers.values() {
            if p.healthy {
                list.push(p.clone());
            }
        }
        list
    }

    /// Count of known healthy remote peers (excluding self).
    pub fn healthy_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.healthy).count()
    }

    /// Return addresses of all known healthy remote peers.
    pub fn healthy_peer_addrs(&self) -> Vec<String> {
        self.peers
            .values()
            .filter(|p| p.healthy)
            .map(|p| p.addr.clone())
            .collect()
    }

    /// Query the current balance of `account_id` (`0` if never credited).
    pub fn balance_of(&self, account_id: u32) -> u64 {
        self.balances.get(&account_id).copied().unwrap_or(0)
    }

    /// Return finalized blocks starting at height `from_height` (inclusive), paginated up to `limit`
    /// (clamped to `1..=MAX_BLOCKS_PER_PAGE`).
    pub fn blocks_from_paginated(&self, from_height: u64, limit: usize) -> Vec<P2pBlock> {
        let start = from_height.max(1);
        let cap = limit.clamp(1, MAX_BLOCKS_PER_PAGE);
        self.blocks
            .iter()
            .filter(|b| b.height >= start)
            .take(cap)
            .cloned()
            .collect()
    }

    /// Return finalized blocks starting at height `from_height` (inclusive), capped at `MAX_BLOCKS_PER_PAGE`.
    pub fn blocks_from(&self, from_height: u64) -> Vec<P2pBlock> {
        self.blocks_from_paginated(from_height, MAX_BLOCKS_PER_PAGE)
    }

    /// Validate ledger invariants (amount > 0, no self-transfer, no replay, no overdraft,
    /// faucet cap within `MAX_SUPPLY`) for a batch of transactions atomically, returning
    /// `(next_balances, next_pages, next_faucet_minted)`.
    fn validate_ledger_txs(
        &self,
        txs: &[P2pTx],
    ) -> Result<(BTreeMap<u32, u64>, BTreeSet<(u32, u64)>, u64), TxReject> {
        if txs.is_empty() {
            return Err(TxReject::BadRequest(
                "block must contain at least one transaction".to_string(),
            ));
        }

        let mut next_balances = self.balances.clone();
        let mut next_pages = self.used_pages.clone();
        let mut next_faucet_minted = self.total_faucet_minted;
        let faucet_hard_cap = TREASURY_INITIAL_BALANCE.min(MAX_SUPPLY);

        for tx in txs {
            if tx.amount == 0 {
                return Err(TxReject::BadRequest(
                    "transaction amount must be > 0".to_string(),
                ));
            }
            if tx.sender == tx.recipient {
                return Err(TxReject::BadRequest("self-transfer forbidden".to_string()));
            }
            if next_pages.contains(&(tx.sender, tx.page_id)) {
                return Err(TxReject::Unauthorized(format!(
                    "replay detected: (sender={}, page_id={}) already consumed",
                    tx.sender, tx.page_id
                )));
            }
            if tx.sender == TREASURY_ACCOUNT_ID {
                if tx.amount > MAX_P2P_FAUCET_PER_REQUEST {
                    return Err(TxReject::BadRequest(format!(
                        "faucet amount {} exceeds per-request cap {}",
                        tx.amount, MAX_P2P_FAUCET_PER_REQUEST
                    )));
                }
                next_faucet_minted = next_faucet_minted
                    .checked_add(tx.amount)
                    .filter(|&tot| tot <= faucet_hard_cap)
                    .ok_or_else(|| {
                        TxReject::BadRequest(format!(
                            "faucet hard supply cap ({faucet_hard_cap} <= MAX_SUPPLY) exceeded"
                        ))
                    })?;
            }
            let sender_bal = next_balances.get(&tx.sender).copied().unwrap_or(0);
            if sender_bal < tx.amount {
                return Err(TxReject::BadRequest(format!(
                    "insufficient balance (overdraft): account {} has {}, needs {}",
                    tx.sender, sender_bal, tx.amount
                )));
            }
            let recip_bal = next_balances.get(&tx.recipient).copied().unwrap_or(0);
            let new_recip = recip_bal
                .checked_add(tx.amount)
                .ok_or_else(|| TxReject::BadRequest("recipient balance overflow".to_string()))?;

            next_balances.insert(tx.sender, sender_bal - tx.amount);
            next_balances.insert(tx.recipient, new_recip);
            next_pages.insert((tx.sender, tx.page_id));
        }

        Ok((next_balances, next_pages, next_faucet_minted))
    }

    /// Burn and volatile-zeroize a one-time sender auth key from `self.sender_auth_keys`.
    fn burn_sender_auth_key(&mut self, sender: u32, page_id: u64) {
        if let Some((mut r, mut s)) = self.sender_auth_keys.remove(&(sender, page_id)) {
            zeroize_u128(&mut r);
            zeroize_u128(&mut s);
        }
    }

    /// Verify a non-treasury transaction's mandatory Carter-Wegman `auth_tag` in constant time
    /// against `self.sender_auth_keys[(tx.sender, tx.page_id)]` without burning yet.
    fn verify_user_tx_auth(&self, tx: &P2pTx) -> Result<(), TxReject> {
        if self.used_pages.contains(&(tx.sender, tx.page_id)) {
            return Err(TxReject::Unauthorized(format!(
                "replay detected: one-time auth key for (sender={}, page_id={}) already burned",
                tx.sender, tx.page_id
            )));
        }
        let Some(&(r, s)) = self.sender_auth_keys.get(&(tx.sender, tx.page_id)) else {
            return Err(TxReject::Unauthorized(format!(
                "unregistered or burned sender auth key for (sender={}, page_id={})",
                tx.sender, tx.page_id
            )));
        };
        let expected = compute_p2p_tx_auth_tag(
            tx.sender,
            tx.recipient,
            tx.amount,
            tx.nonce,
            tx.page_id,
            r,
            s,
        );
        if !ct_eq_16(&tx.auth_tag, &expected) {
            return Err(TxReject::Unauthorized(format!(
                "invalid Carter-Wegman sender auth_tag for (sender={}, page_id={})",
                tx.sender, tx.page_id
            )));
        }
        Ok(())
    }

    /// Verify sender auth, burn the one-time key immediately, validate ledger invariants, and
    /// commit a locally submitted transaction into a new finalized block sealed with `self.seal_key`.
    fn commit_local_tx_typed(&mut self, tx: P2pTx) -> Result<P2pBlock, TxReject> {
        if tx.sender == TREASURY_ACCOUNT_ID {
            return Err(TxReject::Unauthorized(
                "external /p2p/tx cannot spend treasury account".to_string(),
            ));
        }

        // 1. Constant-time CW-MAC verification of mandatory sender auth_tag.
        self.verify_user_tx_auth(&tx)?;

        // 2. Burn the one-time key immediately once a valid CW-MAC tag has been revealed
        //    so two-time pad reuse is strictly impossible even if ledger validation fails.
        self.burn_sender_auth_key(tx.sender, tx.page_id);

        // 3. Validate ledger balances and replay protection.
        let (next_balances, next_pages, next_faucet_minted) =
            self.validate_ledger_txs(std::slice::from_ref(&tx))?;
        let new_height = self.height + 1;
        let block = P2pBlock::seal(
            new_height,
            self.config.node_id,
            &self.tip_tag,
            now_secs(),
            vec![tx.clone()],
            &self.seal_key,
        );
        let new_tip = hex_decode_16(&block.block_tag_hex).expect("valid freshly sealed tag");

        self.balances = next_balances;
        self.total_faucet_minted = next_faucet_minted;
        self.used_pages = next_pages;
        self.height = new_height;
        self.tip_tag = new_tip;
        self.tx_count += block.txs.len() as u64;
        self.pop_score += 10;
        self.seen_block_tags.insert(block.block_tag_hex.clone());
        self.blocks.push(block.clone());

        self.push_event(format!(
            "COMMIT Block #{}: {} -> {} ({} VRNM, page={})",
            block.height, tx.sender, tx.recipient, tx.amount, tx.page_id
        ));
        Ok(block)
    }

    /// Commit a locally submitted authenticated transaction into a new finalized block sealed with
    /// this node's private Carter-Wegman [`BlockSealKey`] over `F_(2^127 - 1)`.
    pub fn commit_local_tx(&mut self, tx: P2pTx) -> Result<P2pBlock, String> {
        self.commit_local_tx_typed(tx).map_err(TxReject::into_string)
    }

    /// Credit `account_id` from [`TREASURY_ACCOUNT_ID`] (`u32::MAX`) by committing a real
    /// P2P block ready to be gossiped across the entire mesh.
    ///
    /// Strictly enforces both `MAX_P2P_FAUCET_PER_REQUEST` and the cumulative hard cap
    /// (`TREASURY_INITIAL_BALANCE <= MAX_SUPPLY`) so unlimited minting is impossible.
    pub fn commit_faucet(&mut self, account_id: u32, amount: u64) -> Result<P2pBlock, String> {
        if account_id == TREASURY_ACCOUNT_ID {
            return Err("cannot faucet into treasury account".to_string());
        }
        if amount == 0 {
            return Err("faucet amount must be > 0".to_string());
        }
        if amount > MAX_P2P_FAUCET_PER_REQUEST {
            return Err(format!(
                "faucet amount {amount} exceeds per-request cap {MAX_P2P_FAUCET_PER_REQUEST}"
            ));
        }
        let faucet_hard_cap = TREASURY_INITIAL_BALANCE.min(MAX_SUPPLY);
        if self
            .total_faucet_minted
            .checked_add(amount)
            .is_none_or(|tot| tot > faucet_hard_cap)
        {
            return Err(format!(
                "faucet hard supply cap ({faucet_hard_cap} <= MAX_SUPPLY) exceeded"
            ));
        }

        // Encode node_id in upper 32 bits of treasury page_id so concurrent faucets on
        // distinct nodes never collide on (TREASURY_ACCOUNT_ID, page_id).
        let seq = self.faucet_seq;
        let page_id = ((self.config.node_id & 0xFFFF_FFFF) << 32) | (seq & 0xFFFF_FFFF);
        let tx = P2pTx::new_authenticated(
            TREASURY_ACCOUNT_ID,
            account_id,
            amount,
            page_id,
            seq,
            self.seal_key.r(),
            self.seal_key.s(),
        );
        let (next_balances, next_pages, next_faucet_minted) = self
            .validate_ledger_txs(std::slice::from_ref(&tx))
            .map_err(TxReject::into_string)?;

        self.faucet_seq += 1;
        let new_height = self.height + 1;
        let block = P2pBlock::seal(
            new_height,
            self.config.node_id,
            &self.tip_tag,
            now_secs(),
            vec![tx.clone()],
            &self.seal_key,
        );
        let new_tip = hex_decode_16(&block.block_tag_hex).expect("valid freshly sealed tag");

        self.balances = next_balances;
        self.total_faucet_minted = next_faucet_minted;
        self.used_pages = next_pages;
        self.height = new_height;
        self.tip_tag = new_tip;
        self.tx_count += block.txs.len() as u64;
        self.pop_score += 10;
        self.seen_block_tags.insert(block.block_tag_hex.clone());
        self.blocks.push(block.clone());

        self.push_event(format!(
            "COMMIT Block #{}: FAUCET -> {} ({} VRNM, page={})",
            block.height, tx.recipient, tx.amount, tx.page_id
        ));
        Ok(block)
    }

    /// Validate and atomically apply an incoming gossiped or catch-up-synced block,
    /// authenticating the block via `self.seal_key` or pairwise peer CW-MAC key AND verifying
    /// every transaction's mandatory Carter-Wegman `auth_tag` in constant time (`ct_eq_16`).
    fn apply_remote_block_with_peer_auth(
        &mut self,
        block: P2pBlock,
        peer_addr_hdr: Option<&str>,
        peer_mac_hdr: Option<&str>,
    ) -> Result<ApplyBlockOutcome, TxReject> {
        if self.seen_block_tags.contains(&block.block_tag_hex) {
            return Ok(ApplyBlockOutcome::Duplicate);
        }

        if block.height == 0 {
            return Err(TxReject::BadRequest("invalid block height 0".to_string()));
        }

        if block.height <= self.height {
            let existing = &self.blocks[(block.height - 1) as usize];
            if existing.block_tag_hex == block.block_tag_hex {
                self.seen_block_tags.insert(block.block_tag_hex);
                return Ok(ApplyBlockOutcome::Duplicate);
            }
            return Err(TxReject::BadRequest(format!(
                "conflicting block at height {} (local tag {}, incoming tag {})",
                block.height, existing.block_tag_hex, block.block_tag_hex
            )));
        }

        // Always verify the block's Carter-Wegman authentication BEFORE queueing CatchUpSync or
        // touching state so unauthenticated/forged future blocks cannot trigger sync amplification.
        let prev_tag = hex_decode_16(&block.prev_tag_hex)
            .ok_or_else(|| TxReject::BadRequest("invalid 16-byte hex 'prev_tag'".to_string()))?;
        let claimed_block_tag = hex_decode_16(&block.block_tag_hex)
            .ok_or_else(|| TxReject::Unauthorized("invalid 16-byte hex 'block_tag'".to_string()))?;

        let authenticated_via_pairwise = if let Some(mac_hex) = peer_mac_hdr {
            let raw_peer_addr = peer_addr_hdr.ok_or_else(|| {
                TxReject::Unauthorized(
                    "missing X-VRNM-Peer-Addr header for pairwise block MAC".to_string(),
                )
            })?;
            let norm_peer = normalize_addr(raw_peer_addr)
                .map_err(|e| TxReject::Unauthorized(format!("invalid X-VRNM-Peer-Addr: {e}")))?;
            let pairwise_key = self.pairwise_peer_keys.get(&norm_peer).ok_or_else(|| {
                TxReject::Unauthorized(format!(
                    "no pairwise Carter-Wegman key registered for peer {norm_peer}"
                ))
            })?;
            let claimed_mac = hex_decode_16(mac_hex).ok_or_else(|| {
                TxReject::Unauthorized("invalid 32-hex X-VRNM-Peer-Mac header".to_string())
            })?;
            let expected_mac = compute_block_tag(
                block.height,
                block.proposer_id,
                &prev_tag,
                block.timestamp_secs,
                &block.txs,
                pairwise_key,
            );
            if !ct_eq_16(&claimed_mac, &expected_mac) {
                return Err(TxReject::Unauthorized(format!(
                    "invalid pairwise Carter-Wegman block MAC at height {} from {}",
                    block.height, norm_peer
                )));
            }
            true
        } else if block.verify_tag(&self.seal_key).is_ok() {
            false
        } else {
            // Check if the proposer's known peer address has a registered pairwise key.
            let proposer_key = self
                .peers
                .iter()
                .find(|(_, p)| p.node_id == block.proposer_id)
                .and_then(|(addr, _)| self.pairwise_peer_keys.get(addr));
            match proposer_key {
                Some(pk) if block.verify_tag(pk).is_ok() => true,
                _ => {
                    return Err(TxReject::Unauthorized(format!(
                        "invalid Carter-Wegman block tag at height {}: untrusted or mismatched BlockSealKey",
                        block.height
                    )));
                }
            }
        };

        if block.height > self.height + 1 {
            return Ok(ApplyBlockOutcome::NeedSync {
                local_height: self.height,
                incoming_height: block.height,
            });
        }

        // Verify chain linkage (`prev_tag == local tip_tag`).
        let expected_prev = hex_encode(&self.tip_tag);
        if block.prev_tag_hex != expected_prev {
            return Err(TxReject::BadRequest(format!(
                "prev_tag mismatch at height {}: expected {}, got {}",
                block.height, expected_prev, block.prev_tag_hex
            )));
        }

        // Verify mandatory sender Carter-Wegman auth_tag for EVERY tx in the block before mutating state.
        let mut batch_user_keys: BTreeSet<(u32, u64)> = BTreeSet::new();
        for tx in &block.txs {
            if tx.sender == TREASURY_ACCOUNT_ID {
                if !authenticated_via_pairwise {
                    let expected = compute_p2p_tx_auth_tag(
                        tx.sender,
                        tx.recipient,
                        tx.amount,
                        tx.nonce,
                        tx.page_id,
                        self.seal_key.r(),
                        self.seal_key.s(),
                    );
                    if !ct_eq_16(&tx.auth_tag, &expected) {
                        return Err(TxReject::Unauthorized(
                            "invalid Carter-Wegman treasury auth_tag in block".to_string(),
                        ));
                    }
                }
            } else {
                if !batch_user_keys.insert((tx.sender, tx.page_id)) {
                    return Err(TxReject::Unauthorized(format!(
                        "replay detected within block: duplicate (sender={}, page_id={})",
                        tx.sender, tx.page_id
                    )));
                }
                self.verify_user_tx_auth(tx)?;
            }
        }

        // Validate all transactions atomically before mutating state.
        let (next_balances, next_pages, next_faucet_minted) =
            self.validate_ledger_txs(&block.txs)?;

        // Burn and volatile-zeroize all consumed one-time sender auth keys immediately.
        for (sender, page_id) in batch_user_keys {
            self.burn_sender_auth_key(sender, page_id);
        }

        self.balances = next_balances;
        self.total_faucet_minted = next_faucet_minted;
        self.used_pages = next_pages;
        self.height = block.height;
        self.tip_tag = claimed_block_tag;
        self.tx_count += block.txs.len() as u64;
        self.pop_score += 5;
        self.seen_block_tags.insert(block.block_tag_hex.clone());
        self.blocks.push(block.clone());

        self.push_event(format!(
            "APPLY Block #{} from node {} ({} tx(s), tag={}..)",
            block.height,
            block.proposer_id,
            block.txs.len(),
            &block.block_tag_hex[..12]
        ));

        Ok(ApplyBlockOutcome::Accepted)
    }

    /// Validate and atomically apply an incoming gossiped or catch-up-synced block.
    fn apply_remote_block(&mut self, block: P2pBlock) -> Result<ApplyBlockOutcome, String> {
        self.apply_remote_block_with_peer_auth(block, None, None)
            .map_err(TxReject::into_string)
    }

    /// Serialize `GET /health` payload.
    pub fn health_json(&self) -> String {
        format!(
            "{{\"status\":\"ok\",\"node_id\":{},\"network\":\"vernam-vrnm-p2p\",\"height\":{},\"peers\":{}}}",
            self.config.node_id,
            self.height,
            self.healthy_peer_count()
        )
    }

    /// Serialize `GET /status` payload.
    pub fn status_json(&self) -> String {
        let peers_json = peers_to_json(&self.peers.values().cloned().collect::<Vec<_>>());
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
                "\"node_id\":{},",
                "\"advertise_addr\":\"{}\",",
                "\"height\":{},",
                "\"tip_tag\":\"{}\",",
                "\"peer_count\":{},",
                "\"peers\":{},",
                "\"pop_score\":{},",
                "\"last_qber\":{:.6},",
                "\"tx_count\":{},",
                "\"recent_events\":{}",
                "}}"
            ),
            self.config.node_id,
            json_escape(&self.config.advertise_addr),
            self.height,
            hex_encode(&self.tip_tag),
            self.healthy_peer_count(),
            peers_json,
            self.pop_score,
            self.last_qber,
            self.tx_count,
            events_json
        )
    }
}

// ============================================================================
// 4. Decentralized P2P Node Server, Async Gossip Worker & Background Sync
// ============================================================================

/// Background work items processed by the dedicated non-blocking gossip worker.
enum GossipJob {
    /// Broadcast a newly committed or newly accepted block to all known healthy peers.
    BroadcastBlock {
        block: P2pBlock,
        exclude_proposer_id: Option<u64>,
    },
    /// Trigger an immediate catch-up sync pass because a higher block height was observed.
    CatchUpSync,
}

/// Shared non-blocking gossip queue drained by a single joinable worker thread (zero thread leaks).
struct GossipQueue {
    jobs: Mutex<VecDeque<GossipJob>>,
    cv: Condvar,
}

impl GossipQueue {
    fn new() -> Self {
        Self {
            jobs: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        }
    }

    fn push(&self, job: GossipJob) {
        let mut q = self.jobs.lock().expect("gossip queue mutex poisoned");
        if matches!(job, GossipJob::CatchUpSync)
            && q.iter().any(|existing| matches!(existing, GossipJob::CatchUpSync))
        {
            return;
        }
        if q.len() >= MAX_GOSSIP_QUEUE {
            return;
        }
        q.push_back(job);
        self.cv.notify_one();
    }

    fn wake_all(&self) {
        self.cv.notify_all();
    }
}

/// Decentralized Multi-VPS Vernam (`VRNM`) P2P Validator Node.
///
/// Serves HTTP/1.1 P2P + wallet endpoints over `std::net::TcpListener`, automatically
/// discovers peers transitively via seed/peer announcements, gossips blocks without
/// storms, and cleanly joins every background thread on [`P2pNode::stop`] or `Drop`.
pub struct P2pNode {
    state: Arc<Mutex<P2pNodeState>>,
    listener: Mutex<Option<TcpListener>>,
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    gossip_queue: Arc<GossipQueue>,
    rate_limiter: Arc<Mutex<IpRateLimiter>>,
    gossip_worker_started: AtomicBool,
    sync_loop_started: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl P2pNode {
    /// Bind a new [`P2pNode`] on `config.bind_addr` and initialize genesis state + BB84 QKD.
    ///
    /// If `config.advertise_addr` is empty or uses port `:0`, it is automatically populated
    /// with the actual bound `local_addr` (ideal for `127.0.0.1:0` multi-node tests).
    pub fn bind(mut config: P2pNodeConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(&config.bind_addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;

        if config.advertise_addr.trim().is_empty() || config.advertise_addr.trim().ends_with(":0") {
            config.advertise_addr = local_addr.to_string();
        } else if let Ok(norm) = normalize_addr(&config.advertise_addr) {
            config.advertise_addr = norm;
        }

        let state = P2pNodeState::new(config, local_addr)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            listener: Mutex::new(Some(listener)),
            local_addr,
            shutdown: Arc::new(AtomicBool::new(false)),
            gossip_queue: Arc::new(GossipQueue::new()),
            rate_limiter: Arc::new(Mutex::new(IpRateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC))),
            gossip_worker_started: AtomicBool::new(false),
            sync_loop_started: AtomicBool::new(false),
            threads: Mutex::new(Vec::new()),
        })
    }

    /// Configure the per-IP inbound HTTP/P2P request rate limit (requests per 1-second window).
    pub fn set_rate_limit(&self, max_requests_per_sec: u32) {
        self.rate_limiter
            .lock()
            .expect("rate limiter mutex poisoned")
            .set_limit(max_requests_per_sec);
    }

    /// Return the actual bound local TCP socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Return this node's advertised `host:port` address.
    pub fn advertise_addr(&self) -> String {
        self.state
            .lock()
            .expect("node state mutex poisoned")
            .config
            .advertise_addr
            .clone()
    }

    /// Return this node's numeric validator ID.
    pub fn node_id(&self) -> u64 {
        self.state
            .lock()
            .expect("node state mutex poisoned")
            .config
            .node_id
    }

    /// Clone a handle to the shared thread-safe [`P2pNodeState`].
    pub fn state(&self) -> Arc<Mutex<P2pNodeState>> {
        Arc::clone(&self.state)
    }

    /// Clone the clean shutdown handle (`Arc<AtomicBool>`).
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Start the dedicated asynchronous gossip worker (idempotent).
    fn ensure_gossip_worker(&self) {
        if self
            .gossip_worker_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let state = Arc::clone(&self.state);
        let queue = Arc::clone(&self.gossip_queue);
        let shutdown = Arc::clone(&self.shutdown);

        let handle = thread::spawn(move || {
            loop {
                let job = {
                    let mut guard = queue.jobs.lock().expect("gossip queue mutex poisoned");
                    while guard.is_empty() && !shutdown.load(Ordering::Acquire) {
                        let (g, _) = queue
                            .cv
                            .wait_timeout(guard, Duration::from_millis(25))
                            .expect("gossip condvar poisoned");
                        guard = g;
                    }
                    if shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    guard.pop_front()
                };

                let Some(job) = job else {
                    continue;
                };

                match job {
                    GossipJob::BroadcastBlock {
                        block,
                        exclude_proposer_id,
                    } => {
                        gossip_block_to_peers(&state, &shutdown, &block, exclude_proposer_id);
                    }
                    GossipJob::CatchUpSync => {
                        let _ = run_announce_and_sync(&state, &shutdown);
                    }
                }
            }
        });

        self.threads
            .lock()
            .expect("threads mutex poisoned")
            .push(handle);
    }

    /// Start the HTTP/1.1 TCP accept loop on a background thread (and ensure the gossip worker
    /// is running).
    pub fn start_server(&self) -> io::Result<()> {
        self.ensure_gossip_worker();
        let listener = self
            .listener
            .lock()
            .expect("listener mutex poisoned")
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "server already started"))?;

        let state = Arc::clone(&self.state);
        let queue = Arc::clone(&self.gossip_queue);
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let shutdown = Arc::clone(&self.shutdown);

        let handle = thread::spawn(move || {
            serve_accept_loop(listener, state, queue, rate_limiter, shutdown);
        });

        self.threads
            .lock()
            .expect("threads mutex poisoned")
            .push(handle);
        Ok(())
    }

    /// Start the background peer gossip & block catch-up sync loop (idempotent).
    ///
    /// Periodically calls [`run_announce_and_sync`] every `config.gossip_interval_ms`
    /// while waking promptly on [`P2pNode::stop`].
    pub fn start_background_sync(&self) {
        self.ensure_gossip_worker();
        if self
            .sync_loop_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let interval_ms = self
            .state
            .lock()
            .expect("node state mutex poisoned")
            .config
            .gossip_interval_ms
            .max(20);
        let state = Arc::clone(&self.state);
        let shutdown = Arc::clone(&self.shutdown);

        let handle = thread::spawn(move || {
            while !shutdown.load(Ordering::Acquire) {
                let _ = run_announce_and_sync(&state, &shutdown);

                // Sleep in short slices so `stop()` terminates immediately.
                let mut remaining = interval_ms;
                while remaining > 0 && !shutdown.load(Ordering::Acquire) {
                    let step = remaining.min(15);
                    thread::sleep(Duration::from_millis(step));
                    remaining -= step;
                }
            }
        });

        self.threads
            .lock()
            .expect("threads mutex poisoned")
            .push(handle);
    }

    /// Convenience helper starting both the HTTP/1.1 TCP server and background peer gossip/sync.
    pub fn start(&self) -> io::Result<()> {
        self.start_server()?;
        self.start_background_sync();
        Ok(())
    }

    /// Run background sync + gossip worker and serve HTTP/1.1 requests synchronously on the
    /// current thread until [`P2pNode::stop`] or `shutdown_handle()` is signaled.
    pub fn serve_forever(&self) -> io::Result<()> {
        self.start_background_sync();
        let listener = self
            .listener
            .lock()
            .expect("listener mutex poisoned")
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "server already started"))?;
        serve_accept_loop(
            listener,
            Arc::clone(&self.state),
            Arc::clone(&self.gossip_queue),
            Arc::clone(&self.rate_limiter),
            Arc::clone(&self.shutdown),
        );
        self.stop();
        Ok(())
    }

    /// Perform one synchronous round of seed/peer announcement, transitive peer table merging,
    /// and catch-up block synchronization from any peer reporting a higher chain height.
    pub fn announce_to_seeds_and_peers(&self) -> SyncReport {
        run_announce_and_sync(&self.state, &self.shutdown)
    }

    /// Signal clean shutdown and join all background server, sync, and gossip threads
    /// so zero threads leak.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.gossip_queue.wake_all();
        let handles: Vec<JoinHandle<()>> = {
            let mut guard = self.threads.lock().expect("threads mutex poisoned");
            guard.drain(..).collect()
        };
        for h in handles {
            let _ = h.join();
        }
    }
}

impl Drop for P2pNode {
    fn drop(&mut self) {
        self.stop();
    }
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

fn write_early_error_and_close(stream: &mut TcpStream, resp: &[u8]) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let _ = stream.write_all(resp);
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(20)));
    let mut drain = [0u8; 2048];
    let _ = stream.read(&mut drain);
}

/// Non-blocking accept loop with per-IP rate limiting and bounded concurrency (`MAX_CONCURRENT_CONNS`),
/// returning HTTP 429 or HTTP 503 immediately instead of spawning unbounded threads.
fn serve_accept_loop(
    listener: TcpListener,
    state: Arc<Mutex<P2pNodeState>>,
    queue: Arc<GossipQueue>,
    rate_limiter: Arc<Mutex<IpRateLimiter>>,
    shutdown: Arc<AtomicBool>,
) {
    let active_conns = Arc::new(AtomicUsize::new(0));
    let mut conn_handles: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, peer_addr)) => {
                let _ = stream.set_nonblocking(false);
                let allowed = rate_limiter
                    .lock()
                    .expect("rate limiter mutex poisoned")
                    .allow(peer_addr.ip());
                if !allowed {
                    let resp = HttpResponse::err_json(
                        429,
                        "Too Many Requests",
                        "per-IP rate limit exceeded",
                    )
                    .to_http_bytes();
                    write_early_error_and_close(&mut stream, &resp);
                    continue;
                }
                let Some(slot_guard) = try_acquire_conn_slot(&active_conns) else {
                    let resp = HttpResponse::err_json(
                        503,
                        "Service Unavailable",
                        "server saturated: too many concurrent connections",
                    )
                    .to_http_bytes();
                    write_early_error_and_close(&mut stream, &resp);
                    continue;
                };
                let st = Arc::clone(&state);
                let q = Arc::clone(&queue);
                let h = thread::spawn(move || {
                    let _guard = slot_guard;
                    handle_http_connection(&st, &q, &mut stream);
                });
                conn_handles.push(h);
                // Opportunistically reap finished connection threads to keep the vec tiny.
                if conn_handles.len() >= 16 {
                    conn_handles.retain(|h| !h.is_finished());
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(8));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    for h in conn_handles {
        let _ = h.join();
    }
}

fn handle_http_connection(
    state: &Arc<Mutex<P2pNodeState>>,
    queue: &Arc<GossipQueue>,
    stream: &mut TcpStream,
) {
    let _ = stream.set_write_timeout(Some(HTTP_WRITE_TIMEOUT));
    let response = match read_http_request(stream) {
        Ok(req) => route_p2p_request(state, queue, &req),
        Err(err) => HttpResponse::err_json(400, "Bad Request", &err),
    };
    let bytes = response.to_http_bytes();
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
}

/// Route a parsed [`HttpRequest`] against `state` and enqueue async gossip jobs as needed.
fn route_p2p_request(
    state: &Arc<Mutex<P2pNodeState>>,
    queue: &Arc<GossipQueue>,
    req: &HttpRequest,
) -> HttpResponse {
    if req.method == "OPTIONS" {
        return HttpResponse::no_content();
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => HttpResponse {
            status_code: 200,
            status_text: "OK",
            content_type: "text/html; charset=utf-8",
            body: crate::explorer_ui::VERNAM_EXPLORER_HTML.to_string(),
        },

        ("GET", "/health") => {
            let guard = state.lock().expect("node state mutex poisoned");
            HttpResponse::ok_json(guard.health_json())
        }

        ("GET", "/status") => {
            let guard = state.lock().expect("node state mutex poisoned");
            HttpResponse::ok_json(guard.status_json())
        }

        ("GET", "/p2p/peers") => {
            let guard = state.lock().expect("node state mutex poisoned");
            let peers = guard.advertised_peers();
            HttpResponse::ok_json(peers_to_json(&peers))
        }

        ("POST", "/p2p/announce") => {
            let Ok(body_str) = std::str::from_utf8(&req.body) else {
                return HttpResponse::err_json(400, "Bad Request", "body is not valid UTF-8");
            };
            let json = match parse_json(body_str) {
                Ok(v) => v,
                Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
            };
            let peer = match peer_info_from_json(&json) {
                Ok(p) => p,
                Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
            };
            if let Err(e) = normalize_addr(&peer.addr) {
                return HttpResponse::err_json(400, "Bad Request", &e);
            }

            let mut guard = state.lock().expect("node state mutex poisoned");
            if let Err(e) = guard.upsert_peer(peer) {
                return HttpResponse::err_json(400, "Bad Request", &e);
            }
            let peers = guard.advertised_peers();
            HttpResponse::ok_json(peers_to_json(&peers))
        }

        ("GET", "/p2p/blocks") => {
            let from_height = req
                .query_param("from")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1);
            let limit = req
                .query_param("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(MAX_BLOCKS_PER_PAGE)
                .clamp(1, MAX_BLOCKS_PER_PAGE);
            let guard = state.lock().expect("node state mutex poisoned");
            let blocks = guard.blocks_from_paginated(from_height, limit);
            HttpResponse::ok_json(blocks_to_json(&blocks))
        }

        ("POST", "/p2p/register") => {
            let Ok(body_str) = std::str::from_utf8(&req.body) else {
                return HttpResponse::err_json(400, "Bad Request", "body is not valid UTF-8");
            };
            let json = match parse_json(body_str) {
                Ok(v) => v,
                Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
            };
            let Some(account_id) = json.get_u32("account_id") else {
                return HttpResponse::err_json(
                    400,
                    "Bad Request",
                    "missing or invalid u32 field 'account_id'",
                );
            };

            if let Some(keys_arr) = json.get_array("keys") {
                let mut parsed_keys = Vec::with_capacity(keys_arr.len());
                for item in keys_arr {
                    let Some(page_id) = item.get_u64("page_id") else {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "each key entry requires u64 'page_id'",
                        );
                    };
                    let Some(r_hex) = item.get_str("r") else {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "each key entry requires hex string 'r'",
                        );
                    };
                    let Some(s_hex) = item.get_str("s") else {
                        return HttpResponse::err_json(
                            400,
                            "Bad Request",
                            "each key entry requires hex string 's'",
                        );
                    };
                    let r = match parse_field_hex(r_hex, "r") {
                        Ok(v) => v,
                        Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
                    };
                    let s = match parse_field_hex(s_hex, "s") {
                        Ok(v) => v,
                        Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
                    };
                    parsed_keys.push((page_id, r, s));
                }

                let mut guard = state.lock().expect("node state mutex poisoned");
                let registered = match guard.register_sender_auth_keys(account_id, &parsed_keys) {
                    Ok(n) => n,
                    Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
                };
                HttpResponse::ok_json(format!(
                    "{{\"status\":\"registered\",\"account_id\":{account_id},\"registered\":{registered}}}"
                ))
            } else {
                let count = json.get_u64("count").unwrap_or(16) as usize;
                let mut guard = state.lock().expect("node state mutex poisoned");
                let start_page_id = json.get_u64("start_page_id").unwrap_or_else(|| {
                    let max_used = guard
                        .used_pages
                        .iter()
                        .filter(|&&(a, _)| a == account_id)
                        .map(|&(_, p)| p)
                        .max()
                        .unwrap_or(0);
                    let max_reg = guard
                        .sender_auth_keys
                        .keys()
                        .filter(|&&(a, _)| a == account_id)
                        .map(|&(_, p)| p)
                        .max()
                        .unwrap_or(0);
                    max_used.max(max_reg).saturating_add(1)
                });
                let generated = match guard.generate_and_register_sender_auth_keys(
                    account_id,
                    start_page_id,
                    count,
                ) {
                    Ok(k) => k,
                    Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
                };
                let mut keys_json = String::from("[");
                for (i, &(page_id, r, s)) in generated.iter().enumerate() {
                    if i > 0 {
                        keys_json.push(',');
                    }
                    keys_json.push_str(&format!(
                        "{{\"page_id\":{page_id},\"r\":\"{r:032x}\",\"s\":\"{s:032x}\"}}"
                    ));
                }
                keys_json.push(']');
                HttpResponse::ok_json(format!(
                    "{{\"status\":\"registered\",\"account_id\":{account_id},\"registered\":{},\"keys\":{keys_json}}}",
                    generated.len()
                ))
            }
        }

        ("POST", "/p2p/tx") => {
            let tx = match parse_tx_from_request(req) {
                Ok(t) => t,
                Err(reject) => return reject.to_http_response(),
            };

            let (block, sender_bal, recip_bal, peer_count) = {
                let mut guard = state.lock().expect("node state mutex poisoned");
                match guard.commit_local_tx_typed(tx.clone()) {
                    Ok(blk) => {
                        let s_bal = guard.balance_of(tx.sender);
                        let r_bal = guard.balance_of(tx.recipient);
                        let p_cnt = guard.healthy_peer_count();
                        (blk, s_bal, r_bal, p_cnt)
                    }
                    Err(reject) => return reject.to_http_response(),
                }
            };

            queue.push(GossipJob::BroadcastBlock {
                block: block.clone(),
                exclude_proposer_id: None,
            });

            HttpResponse::ok_json(format!(
                "{{\"status\":\"committed\",\"block_height\":{},\"block_tag\":\"{}\",\"sender\":{},\"recipient\":{},\"amount\":{},\"page_id\":{},\"nonce\":{},\"auth_tag\":\"{}\",\"sender_balance\":{},\"recipient_balance\":{},\"peers_notified\":{}}}",
                block.height,
                block.block_tag_hex,
                tx.sender,
                tx.recipient,
                tx.amount,
                tx.page_id,
                tx.nonce,
                hex_encode(&tx.auth_tag),
                sender_bal,
                recip_bal,
                peer_count
            ))
        }

        ("POST", "/p2p/block") => {
            let Ok(body_str) = std::str::from_utf8(&req.body) else {
                return HttpResponse::err_json(400, "Bad Request", "body is not valid UTF-8");
            };
            let json = match parse_json(body_str) {
                Ok(v) => v,
                Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
            };
            let block = match P2pBlock::from_json_value(&json) {
                Ok(b) => b,
                Err(e) => {
                    if e.contains("auth_tag") {
                        return HttpResponse::err_json(401, "Unauthorized", &e);
                    }
                    return HttpResponse::err_json(400, "Bad Request", &e);
                }
            };

            let outcome = {
                let mut guard = state.lock().expect("node state mutex poisoned");
                match guard.apply_remote_block_with_peer_auth(
                    block.clone(),
                    req.peer_addr_header.as_deref(),
                    req.peer_mac_header.as_deref(),
                ) {
                    Ok(o) => o,
                    Err(reject) => return reject.to_http_response(),
                }
            };

            match outcome {
                ApplyBlockOutcome::Accepted => {
                    queue.push(GossipJob::BroadcastBlock {
                        block: block.clone(),
                        exclude_proposer_id: Some(block.proposer_id),
                    });
                    HttpResponse::ok_json(format!(
                        "{{\"status\":\"accepted\",\"height\":{},\"block_tag\":\"{}\"}}",
                        block.height, block.block_tag_hex
                    ))
                }
                ApplyBlockOutcome::Duplicate => HttpResponse::ok_json(format!(
                    "{{\"status\":\"duplicate\",\"height\":{},\"block_tag\":\"{}\"}}",
                    block.height, block.block_tag_hex
                )),
                ApplyBlockOutcome::NeedSync {
                    local_height,
                    incoming_height,
                } => {
                    queue.push(GossipJob::CatchUpSync);
                    HttpResponse::json(
                        202,
                        "Accepted",
                        format!(
                            "{{\"status\":\"sync_required\",\"local_height\":{},\"incoming_height\":{}}}",
                            local_height, incoming_height
                        ),
                    )
                }
            }
        }

        ("POST", "/faucet") => {
            let Ok(body_str) = std::str::from_utf8(&req.body) else {
                return HttpResponse::err_json(400, "Bad Request", "body is not valid UTF-8");
            };
            let json = match parse_json(body_str) {
                Ok(v) => v,
                Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
            };
            let Some(account_id) = json
                .get_u32("account_id")
                .or_else(|| json.get_u32("recipient"))
            else {
                return HttpResponse::err_json(
                    400,
                    "Bad Request",
                    "missing or invalid u32 field 'account_id'",
                );
            };
            let Some(amount) = json
                .get_u64("amount")
                .or_else(|| json.get_u64("express"))
                .or_else(|| json.get_u64("express_amount"))
            else {
                return HttpResponse::err_json(
                    400,
                    "Bad Request",
                    "missing or invalid u64 field 'amount'",
                );
            };

            let (block, new_balance, peer_count) = {
                let mut guard = state.lock().expect("node state mutex poisoned");
                match guard.commit_faucet(account_id, amount) {
                    Ok(blk) => {
                        let bal = guard.balance_of(account_id);
                        let p_cnt = guard.healthy_peer_count();
                        (blk, bal, p_cnt)
                    }
                    Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
                }
            };

            queue.push(GossipJob::BroadcastBlock {
                block: block.clone(),
                exclude_proposer_id: None,
            });

            HttpResponse::ok_json(format!(
                "{{\"status\":\"credited\",\"account_id\":{},\"amount\":{},\"balance\":{},\"block_height\":{},\"block_tag\":\"{}\",\"peers_notified\":{}}}",
                account_id, amount, new_balance, block.height, block.block_tag_hex, peer_count
            ))
        }

        ("GET", p) if p.starts_with("/balance/") => {
            let id_str = &p["/balance/".len()..];
            let Ok(account_id) = id_str.parse::<u32>() else {
                return HttpResponse::err_json(400, "Bad Request", "invalid account_id in path");
            };
            let guard = state.lock().expect("node state mutex poisoned");
            let balance = guard.balance_of(account_id);
            HttpResponse::ok_json(format!(
                "{{\"account_id\":{},\"balance\":{},\"height\":{},\"node_id\":{}}}",
                account_id, balance, guard.height, guard.config.node_id
            ))
        }

        _ => HttpResponse::err_json(404, "Not Found", "unknown P2P endpoint"),
    }
}

fn parse_tx_from_request(req: &HttpRequest) -> Result<P2pTx, TxReject> {
    let is_binary = req
        .content_type
        .as_deref()
        .map(|ct| ct.to_ascii_lowercase().contains("octet-stream"))
        .unwrap_or(false)
        || (req.body.len() == P2pTx::WIRE_LEN && !req.body.starts_with(b"{"));

    if is_binary {
        if req.body.len() == 32 {
            return Err(TxReject::Unauthorized(
                "binary tx missing mandatory 16-byte Carter-Wegman auth_tag (expected 48 bytes)"
                    .to_string(),
            ));
        }
        return P2pTx::from_bytes(&req.body).map_err(TxReject::BadRequest);
    }

    let body_str = std::str::from_utf8(&req.body)
        .map_err(|_| TxReject::BadRequest("tx body is not valid UTF-8".to_string()))?;
    let json = parse_json(body_str).map_err(TxReject::BadRequest)?;
    P2pTx::from_json_value_typed(&json)
}

// ============================================================================
// 5. Outbound Peer Announcement, Transitive Discovery & Block Catch-Up Sync
// ============================================================================

/// Contact configured seeds + known peers, announce self, merge returned peer lists
/// (achieving transitive peer discovery), and pull any missed blocks from peers with
/// a higher chain height.
fn run_announce_and_sync(
    state: &Arc<Mutex<P2pNodeState>>,
    shutdown: &Arc<AtomicBool>,
) -> SyncReport {
    let mut report = SyncReport::default();

    // Snapshot seeds, known peer addresses, and our announce payload without holding the lock across I/O.
    let (seeds, known_addrs, announce_body) = {
        let guard = state.lock().expect("node state mutex poisoned");
        let self_info = guard.self_peer_info();
        let body = peer_info_to_json(&self_info);
        let seeds = guard.config.seeds.clone();
        let peers: Vec<String> = guard.peers.keys().cloned().collect();
        (seeds, peers, body)
    };

    // Expand DNS / IP seeds via ToSocketAddrs and combine with known peers.
    let mut targets: Vec<(String, bool)> = Vec::new();
    let mut seen_targets: HashSet<String> = HashSet::new();

    for seed in &seeds {
        if let Ok(resolved) = resolve_seed_addrs(seed) {
            for sa in resolved {
                let s = sa.to_string();
                if seen_targets.insert(s.clone()) {
                    targets.push((s, true));
                }
            }
        } else if let Ok(norm) = normalize_addr(seed) {
            if seen_targets.insert(norm.clone()) {
                targets.push((norm, true));
            }
        }
    }

    for addr in known_addrs {
        if seen_targets.insert(addr.clone()) {
            targets.push((addr, false));
        }
    }

    let mut newly_discovered: Vec<String> = Vec::new();

    // Pass 1: announce to all seeds and currently known peers.
    for (target, is_seed) in targets {
        if shutdown.load(Ordering::Acquire) {
            return report;
        }
        let is_self = {
            let guard = state.lock().expect("node state mutex poisoned");
            guard.is_self(None, &target)
        };
        if is_self {
            continue;
        }

        match announce_single_peer(&target, &announce_body, DEFAULT_PEER_TIMEOUT) {
            Ok(returned_peers) => {
                if is_seed {
                    report.seeds_contacted += 1;
                } else {
                    report.peers_contacted += 1;
                }
                let mut guard = state.lock().expect("node state mutex poisoned");
                guard.set_peer_health(&target, true);
                for peer in returned_peers {
                    let addr_clone = peer.addr.clone();
                    if let Ok(true) = guard.upsert_peer(peer) {
                        report.peers_discovered += 1;
                        if let Ok(norm) = normalize_addr(&addr_clone) {
                            if seen_targets.insert(norm.clone()) {
                                newly_discovered.push(norm);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                let mut guard = state.lock().expect("node state mutex poisoned");
                guard.set_peer_health(&target, false);
            }
        }
    }

    // Pass 2 (1-hop transitive follow-up): immediately announce ourselves to any newly
    // discovered peers so full-mesh convergence completes rapidly.
    if !newly_discovered.is_empty() && !shutdown.load(Ordering::Acquire) {
        let fresh_announce = {
            let guard = state.lock().expect("node state mutex poisoned");
            peer_info_to_json(&guard.self_peer_info())
        };
        for target in newly_discovered {
            if shutdown.load(Ordering::Acquire) {
                return report;
            }
            if let Ok(returned_peers) =
                announce_single_peer(&target, &fresh_announce, DEFAULT_PEER_TIMEOUT)
            {
                report.peers_contacted += 1;
                let mut guard = state.lock().expect("node state mutex poisoned");
                guard.set_peer_health(&target, true);
                for peer in returned_peers {
                    if let Ok(true) = guard.upsert_peer(peer) {
                        report.peers_discovered += 1;
                    }
                }
            }
        }
    }

    // Pass 3: catch-up block sync from any healthy peer reporting `peer.height > local_height`.
    let sync_candidates: Vec<(String, u64)> = {
        let guard = state.lock().expect("node state mutex poisoned");
        let local_h = guard.height;
        let mut cands: Vec<(String, u64)> = guard
            .peers
            .values()
            .filter(|p| p.healthy && p.height > local_h)
            .map(|p| (p.addr.clone(), p.height))
            .collect();
        // Prefer highest-height peers first.
        cands.sort_by(|a, b| b.1.cmp(&a.1));
        cands
    };

    for (peer_addr, peer_height) in sync_candidates {
        // Paginated catch-up sync (up to MAX_BLOCKS_PER_PAGE per page, bounded iterations per pass).
        for _page in 0..64 {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let local_h = state.lock().expect("node state mutex poisoned").height;
            if peer_height <= local_h {
                break;
            }
            let target_path = format!(
                "/p2p/blocks?from={}&limit={MAX_BLOCKS_PER_PAGE}",
                local_h + 1
            );
            let Ok((status, body)) = http_request(
                &peer_addr,
                "GET",
                &target_path,
                None,
                None,
                DEFAULT_PEER_TIMEOUT,
            ) else {
                break;
            };
            if status != 200 {
                break;
            }
            let Ok(mut blocks) = parse_blocks_json(&body) else {
                break;
            };
            if blocks.is_empty() {
                break;
            }
            let page_len = blocks.len();
            blocks.sort_by_key(|b| b.height);

            let mut applied_in_page = 0usize;
            {
                let mut guard = state.lock().expect("node state mutex poisoned");
                for blk in blocks {
                    match guard.apply_remote_block(blk) {
                        Ok(ApplyBlockOutcome::Accepted) => {
                            report.blocks_synced += 1;
                            applied_in_page += 1;
                        }
                        Ok(ApplyBlockOutcome::Duplicate) => {}
                        Ok(ApplyBlockOutcome::NeedSync { .. }) | Err(_) => break,
                    }
                }
            }
            if applied_in_page == 0 || page_len < MAX_BLOCKS_PER_PAGE {
                break;
            }
        }
    }

    report
}

fn announce_single_peer(
    addr: &str,
    announce_body: &str,
    timeout: Duration,
) -> Result<Vec<PeerInfo>, String> {
    let (status, resp_body) = http_request(
        addr,
        "POST",
        "/p2p/announce",
        Some(announce_body.as_bytes()),
        Some("application/json"),
        timeout,
    )?;
    if status != 200 {
        return Err(format!("peer {addr} rejected announce with HTTP {status}"));
    }
    parse_peers_json(&resp_body)
}

/// Asynchronously gossip a finalized block to all known healthy peers (skipping the proposer
/// when forwarding to save bandwidth; receiver-side tag deduplication prevents storms).
/// When a pairwise key exists in `pairwise_peer_keys` for a target peer, attaches per-link
/// `X-VRNM-Peer-Addr` and `X-VRNM-Peer-Mac` Carter-Wegman authentication headers.
fn gossip_block_to_peers(
    state: &Arc<Mutex<P2pNodeState>>,
    shutdown: &Arc<AtomicBool>,
    block: &P2pBlock,
    exclude_proposer_id: Option<u64>,
) {
    let prev_tag = hex_decode_16(&block.prev_tag_hex).unwrap_or([0u8; 16]);
    let (self_addr, targets): (String, Vec<(String, Option<String>)>) = {
        let guard = state.lock().expect("node state mutex poisoned");
        let adv = guard.config.advertise_addr.clone();
        let list = guard
            .peers
            .values()
            .filter(|p| p.healthy && Some(p.node_id) != exclude_proposer_id)
            .map(|p| {
                let mac_hdr = guard.pairwise_peer_keys.get(&p.addr).map(|pk| {
                    let mac = compute_block_tag(
                        block.height,
                        block.proposer_id,
                        &prev_tag,
                        block.timestamp_secs,
                        &block.txs,
                        pk,
                    );
                    hex_encode(&mac)
                });
                (p.addr.clone(), mac_hdr)
            })
            .collect();
        (adv, list)
    };

    if targets.is_empty() {
        return;
    }

    let body = block.to_json();
    for (addr, mac_hdr) in targets {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let extra_headers: Vec<(&str, &str)> = match mac_hdr.as_deref() {
            Some(mac) => vec![
                ("X-VRNM-Peer-Addr", self_addr.as_str()),
                ("X-VRNM-Peer-Mac", mac),
            ],
            None => Vec::new(),
        };
        let _ = http_request_with_headers(
            &addr,
            "POST",
            "/p2p/block",
            Some(body.as_bytes()),
            Some("application/json"),
            &extra_headers,
            DEFAULT_PEER_TIMEOUT,
        );
    }
}

// ============================================================================
// 6. Auto-Discovering Client Helper (`discover_network_peers`) & HTTP Client
// ============================================================================

/// Given ANY single seed node URL or `host:port` (including DNS seeds), query
/// `GET /p2p/peers` and return all active nodes on the Vernam P2P network so wallets
/// and explorers never need a hardcoded list of node IPs.
pub fn discover_network_peers(seed_url: &str) -> Result<Vec<PeerInfo>, String> {
    let (status, body) = http_request(
        seed_url,
        "GET",
        "/p2p/peers",
        None,
        None,
        DEFAULT_PEER_TIMEOUT,
    )?;
    if status != 200 {
        return Err(format!(
            "seed '{seed_url}' returned HTTP {status} for /p2p/peers"
        ));
    }
    parse_peers_json(&body)
}

/// Perform a synchronous HTTP/1.1 GET request to a Vernam P2P node.
pub fn http_get(addr: &str, target: &str) -> Result<(u16, String), String> {
    http_request(addr, "GET", target, None, None, DEFAULT_PEER_TIMEOUT)
}

/// Perform a synchronous HTTP/1.1 POST request with a JSON body to a Vernam P2P node.
pub fn http_post_json(addr: &str, target: &str, json_body: &str) -> Result<(u16, String), String> {
    http_request(
        addr,
        "POST",
        target,
        Some(json_body.as_bytes()),
        Some("application/json"),
        DEFAULT_PEER_TIMEOUT,
    )
}

/// Perform a synchronous HTTP/1.1 POST request with raw binary bytes to a Vernam P2P node.
pub fn http_post_binary(addr: &str, target: &str, body: &[u8]) -> Result<(u16, String), String> {
    http_request(
        addr,
        "POST",
        target,
        Some(body),
        Some("application/octet-stream"),
        DEFAULT_PEER_TIMEOUT,
    )
}

/// Low-level zero-dependency HTTP/1.1 client with DNS resolution (`ToSocketAddrs`) and timeout.
pub fn http_request(
    addr: &str,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    content_type: Option<&str>,
    timeout: Duration,
) -> Result<(u16, String), String> {
    http_request_with_headers(addr, method, target, body, content_type, &[], timeout)
}

fn http_request_with_headers(
    addr: &str,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    content_type: Option<&str>,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<(u16, String), String> {
    let host_header = normalize_addr(addr)?;
    let resolved = resolve_seed_addrs(&host_header)?;

    let mut last_err = String::from("no resolved socket addresses");
    let mut stream_opt = None;
    for sa in resolved {
        match TcpStream::connect_timeout(&sa, timeout) {
            Ok(s) => {
                stream_opt = Some(s);
                break;
            }
            Err(e) => {
                last_err = format!("connect to {sa} failed: {e}");
            }
        }
    }
    let mut stream = stream_opt.ok_or(last_err)?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let payload = body.unwrap_or(&[]);
    let mut req_buf = String::with_capacity(256);
    req_buf.push_str(&format!(
        "{method} {target} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n"
    ));
    if let Some(ct) = content_type {
        req_buf.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    for &(name, val) in extra_headers {
        req_buf.push_str(&format!("{name}: {val}\r\n"));
    }
    if !payload.is_empty() || method == "POST" {
        req_buf.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    req_buf.push_str("\r\n");

    stream
        .write_all(req_buf.as_bytes())
        .map_err(|e| format!("HTTP write headers failed: {e}"))?;
    if !payload.is_empty() {
        stream
            .write_all(payload)
            .map_err(|e| format!("HTTP write body failed: {e}"))?;
    }
    let _ = stream.flush();

    let deadline = Instant::now() + timeout;
    let mut raw = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let max_total = MAX_HTTP_HEADER_BYTES + MAX_HTTP_BODY_BYTES;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            if raw.is_empty() {
                return Err(format!("HTTP read timeout from {host_header}"));
            }
            break;
        };
        if remaining.is_zero() {
            if raw.is_empty() {
                return Err(format!("HTTP read timeout from {host_header}"));
            }
            break;
        }
        let _ = stream.set_read_timeout(Some(remaining));
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if raw.len() + n > max_total {
                    return Err("HTTP response exceeded maximum size".to_string());
                }
                raw.extend_from_slice(&chunk[..n]);
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if raw.is_empty() {
                    return Err(format!("HTTP read timeout from {host_header}"));
                }
                break;
            }
            Err(e) => return Err(format!("HTTP read failed: {e}")),
        }
    }

    let header_end = find_header_end(&raw)
        .ok_or_else(|| "malformed HTTP response: missing header terminator".to_string())?;
    if header_end > MAX_HTTP_HEADER_BYTES {
        return Err("HTTP response headers exceed maximum allowed size".to_string());
    }
    if raw[..header_end].contains(&0) {
        return Err("HTTP response headers contain NUL byte".to_string());
    }
    let header_str = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "HTTP response headers are not valid UTF-8".to_string())?;
    let status_line = header_str
        .lines()
        .next()
        .ok_or_else(|| "missing HTTP status line".to_string())?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("invalid HTTP status line: '{status_line}'"))?;

    let body_bytes = &raw[header_end + 4..];
    let resp_body = String::from_utf8(body_bytes.to_vec())
        .map_err(|_| "HTTP response body is not valid UTF-8".to_string())?;

    Ok((status_code, resp_body))
}

// ============================================================================
// 7. Minimal HTTP/1.1 Server Parser & Response Builder
// ============================================================================

#[derive(Debug, Clone)]
struct HttpRequest {
    method: String,
    path: String,
    query: Option<String>,
    content_type: Option<String>,
    peer_addr_header: Option<String>,
    peer_mac_header: Option<String>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn query_param<'a>(&'a self, key: &str) -> Option<&'a str> {
        let q = self.query.as_deref()?;
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == key {
                    return Some(v);
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
struct HttpResponse {
    status_code: u16,
    status_text: &'static str,
    content_type: &'static str,
    body: String,
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

    fn no_content() -> Self {
        Self {
            status_code: 204,
            status_text: "No Content",
            content_type: "text/plain; charset=utf-8",
            body: String::new(),
        }
    }

    fn to_http_bytes(&self) -> Vec<u8> {
        let header = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: Content-Type, X-VRNM-Peer-Addr, X-VRNM-Peer-Mac\r\n\
             Connection: close\r\n\r\n",
            self.status_code,
            self.status_text,
            self.content_type,
            self.body.len()
        );
        let mut buf = Vec::with_capacity(header.len() + self.body.len());
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(self.body.as_bytes());
        buf
    }
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

    if raw[..header_end].contains(&0) {
        return Err("HTTP headers contain NUL byte".to_string());
    }
    let header_str = std::str::from_utf8(&raw[..header_end])
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
    let (path, query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (raw_target.to_string(), None),
    };

    let mut content_length: usize = 0;
    let mut seen_content_length = false;
    let mut seen_transfer_encoding = false;
    let mut header_count: usize = 0;
    let mut content_type: Option<String> = None;
    let mut peer_addr_header: Option<String> = None;
    let mut peer_mac_header: Option<String> = None;
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
        } else if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(val.trim().to_string());
        } else if name.eq_ignore_ascii_case("x-vrnm-peer-addr") {
            peer_addr_header = Some(val.trim().to_string());
        } else if name.eq_ignore_ascii_case("x-vrnm-peer-mac") {
            peer_mac_header = Some(val.trim().to_string());
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
    // Cap initial allocation so a spoofed large Content-Length cannot cause upfront OOM.
    let mut body = Vec::with_capacity(content_length.min(8192));
    if raw.len() > body_start {
        let already = (raw.len() - body_start).min(content_length);
        body.extend_from_slice(&raw[body_start..body_start + already]);
    }
    while body.len() < content_length {
        let Some(remaining_time) = deadline.checked_duration_since(Instant::now()) else {
            return Err("HTTP request body read deadline exceeded".to_string());
        };
        if remaining_time.is_zero() {
            return Err("HTTP request body read deadline exceeded".to_string());
        }
        let _ = stream.set_read_timeout(Some(remaining_time));
        let remaining = content_length - body.len();
        let to_read = remaining.min(chunk.len());
        let n = stream
            .read(&mut chunk[..to_read])
            .map_err(|e| format!("failed to read HTTP body: {e}"))?;
        if n == 0 {
            return Err("truncated HTTP request body".to_string());
        }
        body.extend_from_slice(&chunk[..n]);
    }

    Ok(HttpRequest {
        method,
        path,
        query,
        content_type,
        peer_addr_header,
        peer_mac_header,
        body,
    })
}

// ============================================================================
// 8. Zero-Dependency JSON Serialization & Recursive-Descent Parser
// ============================================================================

fn peer_info_to_json(p: &PeerInfo) -> String {
    format!(
        "{{\"node_id\":{},\"addr\":\"{}\",\"height\":{},\"pop_score\":{},\"qber\":{:.6},\"last_seen_secs\":{},\"healthy\":{}}}",
        p.node_id,
        json_escape(&p.addr),
        p.height,
        p.pop_score,
        p.qber,
        p.last_seen_secs,
        p.healthy
    )
}

fn peers_to_json(peers: &[PeerInfo]) -> String {
    let mut out = String::from("[");
    for (i, p) in peers.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&peer_info_to_json(p));
    }
    out.push(']');
    out
}

fn blocks_to_json(blocks: &[P2pBlock]) -> String {
    let mut out = String::from("[");
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&b.to_json());
    }
    out.push(']');
    out
}

fn peer_info_from_json(v: &JsonValue) -> Result<PeerInfo, String> {
    let node_id = v
        .get_u64("node_id")
        .ok_or_else(|| "missing or invalid u64 field 'node_id'".to_string())?;
    let addr = v
        .get_str("addr")
        .ok_or_else(|| "missing string field 'addr'".to_string())?
        .to_string();
    let height = v.get_u64("height").unwrap_or(0);
    let pop_score = v.get_u64("pop_score").unwrap_or(0);
    let qber = v.get_f64("qber").unwrap_or(0.0);
    let last_seen_secs = v.get_u64("last_seen_secs").unwrap_or_else(now_secs);
    let healthy = v.get_bool("healthy").unwrap_or(true);
    Ok(PeerInfo {
        node_id,
        addr,
        height,
        pop_score,
        qber,
        last_seen_secs,
        healthy,
    })
}

fn parse_peers_json(json_str: &str) -> Result<Vec<PeerInfo>, String> {
    let val = parse_json(json_str)?;
    let JsonValue::Array(items) = val else {
        return Err("expected JSON array of peers".to_string());
    };
    let mut peers = Vec::with_capacity(items.len());
    for item in &items {
        if let Ok(p) = peer_info_from_json(item) {
            peers.push(p);
        }
    }
    Ok(peers)
}

fn parse_blocks_json(json_str: &str) -> Result<Vec<P2pBlock>, String> {
    let val = parse_json(json_str)?;
    let JsonValue::Array(items) = val else {
        return Err("expected JSON array of blocks".to_string());
    };
    let mut blocks = Vec::with_capacity(items.len());
    for item in &items {
        blocks.push(P2pBlock::from_json_value(item)?);
    }
    Ok(blocks)
}

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

#[derive(Debug, Clone)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(map) => map.get(key),
            _ => None,
        }
    }

    fn get_u64(&self, key: &str) -> Option<u64> {
        match self.get(key)? {
            JsonValue::Number(s) => s.parse::<u64>().ok(),
            _ => None,
        }
    }

    fn get_u32(&self, key: &str) -> Option<u32> {
        match self.get(key)? {
            JsonValue::Number(s) => s.parse::<u32>().ok(),
            _ => None,
        }
    }

    fn get_f64(&self, key: &str) -> Option<f64> {
        match self.get(key)? {
            JsonValue::Number(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key)? {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    fn get_str(&self, key: &str) -> Option<&str> {
        match self.get(key)? {
            JsonValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn get_array(&self, key: &str) -> Option<&[JsonValue]> {
        match self.get(key)? {
            JsonValue::Array(arr) => Some(arr.as_slice()),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    src: &'a [u8],
    pos: usize,
    elements: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            src: input.as_bytes(),
            pos: 0,
            elements: 0,
        }
    }

    fn count_element(&mut self) -> Result<(), String> {
        self.elements += 1;
        if self.elements > MAX_JSON_ELEMENTS {
            return Err(format!(
                "JSON element limit exceeded (max {MAX_JSON_ELEMENTS})"
            ));
        }
        Ok(())
    }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nesting depth exceeded".to_string());
        }
        self.count_element()?;
        self.skip_ws();
        let b = self
            .peek()
            .ok_or_else(|| "unexpected end of JSON input".to_string())?;
        match b {
            b'{' => self.parse_object(depth + 1),
            b'[' => self.parse_array(depth + 1),
            b'"' => self.parse_string().map(JsonValue::Str),
            b't' => self.expect_literal(b"true", JsonValue::Bool(true)),
            b'f' => self.expect_literal(b"false", JsonValue::Bool(false)),
            b'n' => self.expect_literal(b"null", JsonValue::Null),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(format!("unexpected JSON token '{}'", other as char)),
        }
    }

    fn expect_literal(&mut self, lit: &[u8], val: JsonValue) -> Result<JsonValue, String> {
        if self.src[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(val)
        } else {
            Err("invalid JSON literal".to_string())
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err("expected '\"'".to_string());
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.src.len() {
            let b = self.src[self.pos];
            self.pos += 1;
            if b < 0x20 {
                return Err("unescaped control byte inside JSON string".to_string());
            }
            if b == b'"' {
                return Ok(out);
            }
            if b == b'\\' {
                if self.pos >= self.src.len() {
                    return Err("unterminated JSON escape".to_string());
                }
                let esc = self.src[self.pos];
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        if self.pos + 4 > self.src.len() {
                            return Err("truncated \\uXXXX escape".to_string());
                        }
                        let hex = std::str::from_utf8(&self.src[self.pos..self.pos + 4])
                            .map_err(|_| "invalid UTF-8 in \\u escape".to_string())?;
                        let code = u32::from_str_radix(hex, 16)
                            .map_err(|_| "invalid hex in \\u escape".to_string())?;
                        self.pos += 4;
                        let ch = char::from_u32(code)
                            .ok_or_else(|| "invalid Unicode scalar in \\u escape".to_string())?;
                        out.push(ch);
                    }
                    _ => return Err("invalid JSON escape sequence".to_string()),
                }
            } else {
                // Collect contiguous plain UTF-8 bytes up to next quote/backslash/control byte.
                let start = self.pos - 1;
                while self.pos < self.src.len()
                    && self.src[self.pos] != b'"'
                    && self.src[self.pos] != b'\\'
                    && self.src[self.pos] >= 0x20
                {
                    self.pos += 1;
                }
                let slice = std::str::from_utf8(&self.src[start..self.pos])
                    .map_err(|_| "invalid UTF-8 inside JSON string".to_string())?;
                out.push_str(slice);
            }
        }
        Err("unterminated JSON string".to_string())
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digit_start = self.pos;
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if self.pos == digit_start {
            return Err("invalid JSON number".to_string());
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let frac_start = self.pos;
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err("invalid JSON fractional number".to_string());
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err("invalid JSON exponent".to_string());
            }
        }
        let s = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| "invalid UTF-8 in JSON number".to_string())?;
        Ok(JsonValue::Number(s.to_string()))
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err("expected ',' or ']' in JSON array".to_string()),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1; // '{'
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(map));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err("expected ':' after JSON object key".to_string());
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            map.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(map));
                }
                _ => return Err("expected ',' or '}' in JSON object".to_string()),
            }
        }
    }
}

fn parse_json(input: &str) -> Result<JsonValue, String> {
    let mut parser = JsonParser::new(input);
    let val = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos != parser.src.len() {
        return Err("trailing characters after JSON value".to_string());
    }
    Ok(val)
}

// ============================================================================
// 9. Small Utilities (Hex Encoding, Timestamps)
// ============================================================================

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

fn hex_decode_16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ============================================================================
// 10. Comprehensive Multi-Node Live TCP Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn_node_with_key(
        node_id: u64,
        seeds: Vec<String>,
        cluster_seal_key: Option<BlockSealKey>,
    ) -> P2pNode {
        let node = P2pNode::bind(P2pNodeConfig {
            node_id,
            bind_addr: "127.0.0.1:0".to_string(),
            advertise_addr: "127.0.0.1:0".to_string(),
            seeds,
            gossip_interval_ms: 40,
            cluster_seal_key,
        })
        .expect("bind P2pNode on 127.0.0.1:0");
        node.start().expect("start P2pNode");
        node
    }

    fn spawn_node(node_id: u64, seeds: Vec<String>) -> P2pNode {
        spawn_node_with_key(node_id, seeds, None)
    }

    fn fresh_auth_key(page_id: u64) -> (u64, u128, u128) {
        let r = loop {
            let v = random_field_elem();
            if v != 0 {
                break v;
            }
        };
        let s = random_field_elem();
        (page_id, r, s)
    }

    fn register_key_on_nodes(nodes: &[&P2pNode], account_id: u32, key: (u64, u128, u128)) {
        for n in nodes {
            n.state()
                .lock()
                .unwrap()
                .register_sender_auth_keys(account_id, &[key])
                .expect("register sender auth key");
        }
    }

    fn wait_until<F>(timeout_ms: u64, mut cond: F) -> bool
    where
        F: FnMut() -> bool,
    {
        let start = std::time::Instant::now();
        let limit = Duration::from_millis(timeout_ms);
        while start.elapsed() < limit {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(15));
        }
        cond()
    }

    #[test]
    fn test_transitive_peer_discovery_three_nodes() {
        let cluster_key = BlockSealKey::generate();
        // Node 0: seed node with no seeds of its own.
        let node0 = spawn_node_with_key(0, vec![], Some(cluster_key.clone()));
        let addr0 = node0.advertise_addr();

        // Node 1: knows ONLY Node 0.
        let node1 = spawn_node_with_key(1, vec![addr0.clone()], Some(cluster_key.clone()));
        let addr1 = node1.advertise_addr();

        // Node 2: knows ONLY Node 1 (does NOT know Node 0!).
        let node2 = spawn_node_with_key(2, vec![addr1.clone()], Some(cluster_key));
        let addr2 = node2.advertise_addr();

        // Wait for automatic transitive gossip rounds to build a full 3-node mesh.
        let converged = wait_until(3_000, || {
            let n0_has_2 = node0.state().lock().unwrap().peers.contains_key(&addr2);
            let n2_has_0 = node2.state().lock().unwrap().peers.contains_key(&addr0);
            let n1_has_both = {
                let s1 = node1.state();
                let g = s1.lock().unwrap();
                g.peers.contains_key(&addr0) && g.peers.contains_key(&addr2)
            };
            n0_has_2 && n2_has_0 && n1_has_both
        });
        assert!(
            converged,
            "3-node transitive gossip failed to form full mesh A <-> B <-> C"
        );

        // Auto-discovering wallet helper querying ONLY Node 2 must discover all 3 nodes.
        let discovered = discover_network_peers(&addr2).expect("discover_network_peers(node2)");
        let discovered_addrs: BTreeSet<String> = discovered.iter().map(|p| p.addr.clone()).collect();
        assert_eq!(discovered_addrs.len(), 3);
        assert!(discovered_addrs.contains(&addr0));
        assert!(discovered_addrs.contains(&addr1));
        assert!(discovered_addrs.contains(&addr2));

        // Verify /health and /status endpoints on Node 2.
        let (st_health, body_health) = http_get(&addr2, "/health").expect("GET /health");
        assert_eq!(st_health, 200);
        let hj = parse_json(&body_health).expect("parse /health json");
        assert_eq!(hj.get_str("status"), Some("ok"));
        assert_eq!(hj.get_str("network"), Some("vernam-vrnm-p2p"));
        assert_eq!(hj.get_u64("node_id"), Some(2));
        assert_eq!(hj.get_u64("peers"), Some(2));

        let (st_status, body_status) = http_get(&addr2, "/status").expect("GET /status");
        assert_eq!(st_status, 200);
        let sj = parse_json(&body_status).expect("parse /status json");
        assert_eq!(sj.get_u64("node_id"), Some(2));
        assert_eq!(sj.get_str("advertise_addr"), Some(addr2.as_str()));
        assert!(sj.get_array("recent_events").is_some());

        node2.stop();
        node1.stop();
        node0.stop();
    }

    #[test]
    fn test_live_cross_node_tx_gossip_and_consensus_propagation() {
        let cluster_key = BlockSealKey::generate();
        let node0 = spawn_node_with_key(0, vec![], Some(cluster_key.clone()));
        let addr0 = node0.advertise_addr();
        let node1 = spawn_node_with_key(1, vec![addr0.clone()], Some(cluster_key.clone()));
        let addr1 = node1.advertise_addr();
        let node2 = spawn_node_with_key(2, vec![addr1.clone()], Some(cluster_key));
        let addr2 = node2.advertise_addr();

        assert!(
            wait_until(3_000, || {
                node0.state().lock().unwrap().healthy_peer_count() == 2
                    && node1.state().lock().unwrap().healthy_peer_count() == 2
                    && node2.state().lock().unwrap().healthy_peer_count() == 2
            }),
            "mesh should converge to 2 healthy peers each"
        );

        // 1. Send /faucet to Node 0 crediting Account #1 with 1000 VRNM.
        let (st, body) = http_post_json(&addr0, "/faucet", r#"{"account_id":1,"amount":1000}"#)
            .expect("POST /faucet");
        assert_eq!(st, 200, "faucet failed: {body}");

        assert!(
            wait_until(2_500, || {
                node1.state().lock().unwrap().height == 1
                    && node2.state().lock().unwrap().height == 1
            }),
            "faucet block #1 should gossip to Nodes 1 and 2"
        );

        // Register one-time CW-MAC sender auth keys on all 3 validators (via HTTP /p2p/register on node0 and directly on peers).
        let k_acct1 = fresh_auth_key(7);
        let reg_body = format!(
            "{{\"account_id\":1,\"keys\":[{{\"page_id\":7,\"r\":\"{:032x}\",\"s\":\"{:032x}\"}}]}}",
            k_acct1.1, k_acct1.2
        );
        let (st_reg, body_reg) = http_post_json(&addr0, "/p2p/register", &reg_body)
            .expect("POST /p2p/register");
        assert_eq!(st_reg, 200, "register failed: {body_reg}");
        register_key_on_nodes(&[&node1, &node2], 1, k_acct1);

        let k_acct2 = fresh_auth_key(1);
        register_key_on_nodes(&[&node0, &node1, &node2], 2, k_acct2);

        // 2. Send authenticated JSON /p2p/tx to Node 0: Account #1 -> Account #2 (250 VRNM, page_id=7).
        let json_tx = P2pTx::new_authenticated(1, 2, 250, 7, 1, k_acct1.1, k_acct1.2);
        let (st, body) = http_post_json(&addr0, "/p2p/tx", &json_tx.to_json())
            .expect("POST /p2p/tx json");
        assert_eq!(st, 200, "json tx failed: {body}");

        // Wait for block #2 to propagate across the mesh before submitting binary tx on Node 1.
        assert!(
            wait_until(2_500, || {
                node1.state().lock().unwrap().height == 2
                    && node2.state().lock().unwrap().height == 2
            }),
            "tx block #2 should propagate to Nodes 1 and 2"
        );

        // Verify one-time key (1, 7) was burned on ALL 3 nodes!
        for n in [&node0, &node1, &node2] {
            assert!(!n.state().lock().unwrap().sender_auth_keys.contains_key(&(1, 7)));
        }

        // 3. Send raw 48-byte authenticated binary /p2p/tx to Node 1: Account #2 -> Account #3 (50 VRNM, page_id=1).
        let bin_tx = P2pTx::new_authenticated(2, 3, 50, 1, 1, k_acct2.1, k_acct2.2);
        let (st, body) =
            http_post_binary(&addr1, "/p2p/tx", &bin_tx.to_bytes()).expect("POST /p2p/tx binary");
        assert_eq!(st, 200, "binary tx failed: {body}");

        assert!(
            wait_until(2_500, || {
                node0.state().lock().unwrap().height == 3
                    && node1.state().lock().unwrap().height == 3
                    && node2.state().lock().unwrap().height == 3
            }),
            "binary tx block #3 should propagate across all 3 nodes"
        );

        // Verify identical tip tags and exact balances via GET /balance/<id> on all 3 nodes!
        let tip0 = node0.state().lock().unwrap().tip_tag;
        let tip1 = node1.state().lock().unwrap().tip_tag;
        let tip2 = node2.state().lock().unwrap().tip_tag;
        assert_eq!(tip0, tip1);
        assert_eq!(tip1, tip2);

        for addr in [&addr0, &addr1, &addr2] {
            for (acct, expected) in [(1u32, 750u64), (2, 200), (3, 50)] {
                let (st, b) = http_get(addr, &format!("/balance/{acct}")).expect("GET /balance");
                assert_eq!(st, 200);
                let j = parse_json(&b).expect("balance json");
                assert_eq!(j.get_u64("balance"), Some(expected));
                assert_eq!(j.get_u64("height"), Some(3));
            }
        }

        node2.stop();
        node1.stop();
        node0.stop();
    }

    #[test]
    fn test_late_joining_node_auto_catch_up_sync() {
        let cluster_key = BlockSealKey::generate();
        let node0 = spawn_node_with_key(0, vec![], Some(cluster_key.clone()));
        let addr0 = node0.advertise_addr();
        let node1 = spawn_node_with_key(1, vec![addr0.clone()], Some(cluster_key.clone()));
        let addr1 = node1.advertise_addr();
        let node2 = spawn_node_with_key(2, vec![addr1.clone()], Some(cluster_key.clone()));
        let addr2 = node2.advertise_addr();

        assert!(wait_until(3_000, || {
            node0.state().lock().unwrap().healthy_peer_count() == 2
                && node2.state().lock().unwrap().healthy_peer_count() == 2
        }));

        // Produce blocks 1 and 2 BEFORE Node 3 even exists!
        let (st, _) = http_post_json(&addr0, "/faucet", r#"{"account_id":10,"amount":500}"#)
            .expect("faucet");
        assert_eq!(st, 200);
        assert!(wait_until(2_000, || node2.state().lock().unwrap().height == 1));

        let k_acct10 = fresh_auth_key(42);
        register_key_on_nodes(&[&node0, &node1, &node2], 10, k_acct10);

        let tx = P2pTx::new_authenticated(10, 20, 125, 42, 1, k_acct10.1, k_acct10.2);
        let (st, body) = http_post_json(&addr0, "/p2p/tx", &tx.to_json()).expect("tx");
        assert_eq!(st, 200, "tx failed: {body}");
        assert!(wait_until(2_000, || node2.state().lock().unwrap().height == 2));

        // Now start late-joining Node 3 pointing ONLY at Node 2, provisioned with cluster key + sender auth key.
        let node3 = P2pNode::bind(P2pNodeConfig {
            node_id: 3,
            bind_addr: "127.0.0.1:0".to_string(),
            advertise_addr: "127.0.0.1:0".to_string(),
            seeds: vec![addr2.clone()],
            gossip_interval_ms: 40,
            cluster_seal_key: Some(cluster_key),
        })
        .expect("bind node3");
        node3
            .state()
            .lock()
            .unwrap()
            .register_sender_auth_keys(10, &[k_acct10])
            .expect("register sender auth key on node3");
        node3.start().expect("start node3");
        let addr3 = node3.advertise_addr();

        // Node 3 should automatically discover the network AND sync blocks 1..=2!
        let synced = wait_until(3_000, || {
            let s3 = node3.state();
            let g = s3.lock().unwrap();
            g.height == 2 && g.balance_of(10) == 375 && g.balance_of(20) == 125
        });
        assert!(synced, "late-joining Node 3 failed to auto-sync blocks 1..=2");

        // Exact tip tag match and full peer discovery including Node 0.
        assert_eq!(
            node3.state().lock().unwrap().tip_tag,
            node0.state().lock().unwrap().tip_tag
        );
        let (st, bal_body) = http_get(&addr3, "/balance/20").expect("GET /balance/20 on Node 3");
        assert_eq!(st, 200);
        let bj = parse_json(&bal_body).expect("parse balance json");
        assert_eq!(bj.get_u64("balance"), Some(125));
        assert_eq!(bj.get_u64("height"), Some(2));

        node3.stop();
        node2.stop();
        node1.stop();
        node0.stop();
    }

    #[test]
    fn test_replay_and_overdraft_rejection_across_p2p() {
        let cluster_key = BlockSealKey::generate();
        let node0 = spawn_node_with_key(0, vec![], Some(cluster_key.clone()));
        let addr0 = node0.advertise_addr();
        let node1 = spawn_node_with_key(1, vec![addr0.clone()], Some(cluster_key.clone()));
        let addr1 = node1.advertise_addr();

        assert!(wait_until(2_500, || {
            node0.state().lock().unwrap().healthy_peer_count() == 1
                && node1.state().lock().unwrap().healthy_peer_count() == 1
        }));

        // Fund account 1 with 100 VRNM (Block #1).
        let (st, _) = http_post_json(&addr0, "/faucet", r#"{"account_id":1,"amount":100}"#)
            .expect("faucet");
        assert_eq!(st, 200);
        assert!(wait_until(2_000, || node1.state().lock().unwrap().height == 1));

        let k99 = fresh_auth_key(99);
        let k100 = fresh_auth_key(100);
        let k101 = fresh_auth_key(101);
        register_key_on_nodes(&[&node0, &node1], 1, k99);
        register_key_on_nodes(&[&node0, &node1], 1, k100);
        register_key_on_nodes(&[&node0, &node1], 1, k101);

        // Valid transfer of 40 VRNM using (sender=1, page_id=99) (Block #2).
        let valid_tx = P2pTx::new_authenticated(1, 2, 40, 99, 1, k99.1, k99.2);
        let (st, body) = http_post_json(&addr0, "/p2p/tx", &valid_tx.to_json()).expect("valid tx");
        assert_eq!(st, 200, "valid tx failed: {body}");
        assert!(wait_until(2_000, || node1.state().lock().unwrap().height == 2));

        // Replay attack on Node 1 reusing (sender=1, page_id=99) must be rejected with 401 Unauthorized.
        let replay_tx = P2pTx::new_authenticated(1, 2, 10, 99, 2, k99.1, k99.2);
        let (st_replay, body_replay) =
            http_post_json(&addr1, "/p2p/tx", &replay_tx.to_json()).expect("replay tx");
        assert_eq!(st_replay, 401, "expected 401 on replay, got: {body_replay}");
        assert!(
            body_replay.contains("replay"),
            "expected replay error, got: {body_replay}"
        );

        // Authenticated overdraft attack (account 1 only has 60 left, tries to spend 61) must be rejected with 400.
        let overdraft_tx = P2pTx::new_authenticated(1, 2, 61, 100, 3, k100.1, k100.2);
        let (st_overdraft, body_overdraft) =
            http_post_json(&addr1, "/p2p/tx", &overdraft_tx.to_json()).expect("overdraft tx");
        assert_eq!(st_overdraft, 400, "expected 400 on overdraft, got: {body_overdraft}");
        assert!(
            body_overdraft.contains("overdraft") || body_overdraft.contains("insufficient"),
            "expected overdraft error, got: {body_overdraft}"
        );

        // Forged Carter-Wegman block submitted directly to /p2p/block must be rejected with 401.
        let tip = node1.state().lock().unwrap().tip_tag;
        let mut forged = P2pBlock::seal(
            3,
            999,
            &tip,
            now_secs(),
            vec![P2pTx::new_authenticated(1, 2, 10, 101, 4, k101.1, k101.2)],
            &cluster_key,
        );
        forged.block_tag_hex = "deadbeefdeadbeefdeadbeefdeadbeef".to_string();
        let (st_forged, body_forged) =
            http_post_json(&addr1, "/p2p/block", &forged.to_json()).expect("forged block");
        assert_eq!(st_forged, 401);
        assert!(
            body_forged.contains("Carter-Wegman"),
            "expected Carter-Wegman tag error, got: {body_forged}"
        );

        // Replayed tx inside a validly-tagged P2pBlock must also be rejected atomically with 401.
        let replayed_blk = P2pBlock::seal(
            3,
            999,
            &tip,
            now_secs(),
            vec![P2pTx::new_authenticated(1, 2, 10, 99, 5, k99.1, k99.2)],
            &cluster_key,
        );
        let (st_rblk, body_rblk) =
            http_post_json(&addr1, "/p2p/block", &replayed_blk.to_json()).expect("replayed block");
        assert_eq!(st_rblk, 401);
        assert!(body_rblk.contains("replay"), "got: {body_rblk}");

        // State on both nodes must remain cleanly at height 2 with exact balances.
        assert_eq!(node0.state().lock().unwrap().height, 2);
        assert_eq!(node1.state().lock().unwrap().height, 2);
        assert_eq!(node0.state().lock().unwrap().balance_of(1), 60);
        assert_eq!(node1.state().lock().unwrap().balance_of(1), 60);
        assert_eq!(node0.state().lock().unwrap().balance_of(2), 40);
        assert_eq!(node1.state().lock().unwrap().balance_of(2), 40);

        node1.stop();
        node0.stop();
    }

    #[test]
    fn test_dns_seed_resolution_and_announce_validation() {
        // Start seed node on loopback and connect to it via DNS hostname `localhost:<port>`.
        let seed_node = spawn_node(0, vec![]);
        let port = seed_node.local_addr().port();
        let dns_seed = format!("localhost:{port}");

        let resolved = resolve_seed_addrs(&dns_seed).expect("resolve localhost via ToSocketAddrs");
        assert!(!resolved.is_empty());

        let child = spawn_node(1, vec![dns_seed]);
        let child_addr = child.advertise_addr();

        assert!(
            wait_until(2_500, || {
                seed_node.state().lock().unwrap().peers.contains_key(&child_addr)
                    && child.state().lock().unwrap().healthy_peer_count() == 1
            }),
            "DNS seed 'localhost:<port>' failed to bootstrap peer"
        );

        // Malformed address in /p2p/announce must be rejected with 400.
        let (st_bad, _) = http_post_json(
            &seed_node.advertise_addr(),
            "/p2p/announce",
            r#"{"node_id":77,"addr":"not a valid host","height":0,"pop_score":0,"qber":0.0}"#,
        )
        .expect("bad announce");
        assert_eq!(st_bad, 400);

        // Self-announcement must be silently ignored (never inserts self into remote peer map).
        let (st_self, _) = http_post_json(
            &seed_node.advertise_addr(),
            "/p2p/announce",
            &format!(
                "{{\"node_id\":0,\"addr\":\"{}\",\"height\":0,\"pop_score\":100,\"qber\":0.0}}",
                seed_node.advertise_addr()
            ),
        )
        .expect("self announce");
        assert_eq!(st_self, 200);
        let seed_addr = seed_node.advertise_addr();
        assert!(
            !seed_node
                .state()
                .lock()
                .unwrap()
                .peers
                .contains_key(&seed_addr)
        );

        child.stop();
        seed_node.stop();
    }

    #[test]
    fn test_p2p_security_hardening_peer_cap_ssrf_pagination_json_limit_and_forged_sync() {
        // 1. SSRF protection blocks cloud metadata (169.254.169.254) and multicast (224.0.0.1).
        assert!(resolve_seed_addrs("169.254.169.254:80").is_err());
        assert!(resolve_seed_addrs("224.0.0.1:8080").is_err());
        assert!(resolve_seed_addrs("0.0.0.0:8080").is_err());
        assert!(resolve_seed_addrs("[fe80::1]:8080").is_err());
        assert!(resolve_seed_addrs("127.0.0.1:8080").is_ok());

        // 2. JSON element cap rejects oversized arrays.
        let mut huge_json = String::from("[");
        for i in 0..(MAX_JSON_ELEMENTS + 10) {
            if i > 0 {
                huge_json.push(',');
            }
            huge_json.push('0');
        }
        huge_json.push(']');
        assert!(
            parse_json(&huge_json).is_err(),
            "JSON parser must reject > MAX_JSON_ELEMENTS"
        );

        // 3. Peer table cap (MAX_PEERS = 64), SSRF rejection in upsert_peer,
        //    forged future block rejected BEFORE NeedSync, and /p2p/blocks pagination <= 100.
        let test_key = BlockSealKey::generate();
        let mut st = P2pNodeState::new(
            P2pNodeConfig {
                node_id: 0,
                bind_addr: "127.0.0.1:0".to_string(),
                advertise_addr: "127.0.0.1:18080".to_string(),
                seeds: vec![],
                gossip_interval_ms: 1000,
                cluster_seal_key: Some(test_key.clone()),
            },
            "127.0.0.1:18080".parse().unwrap(),
        )
        .expect("init state");

        assert!(
            st.upsert_peer(PeerInfo {
                node_id: 999,
                addr: "169.254.169.254:80".to_string(),
                height: 0,
                pop_score: 0,
                qber: 0.0,
                last_seen_secs: 1,
                healthy: true,
            })
            .is_err(),
            "metadata IP must be rejected by upsert_peer"
        );

        for i in 1..=(MAX_PEERS as u64) {
            st.upsert_peer(PeerInfo {
                node_id: i,
                addr: format!("127.0.0.1:{}", 20000 + i),
                height: 0,
                pop_score: 10,
                qber: 0.01,
                last_seen_secs: i,
                healthy: true,
            })
            .expect("insert within peer cap");
        }
        assert_eq!(st.peers.len(), MAX_PEERS);
        assert!(
            st.upsert_peer(PeerInfo {
                node_id: 9999,
                addr: "127.0.0.1:30000".to_string(),
                height: 0,
                pop_score: 10,
                qber: 0.01,
                last_seen_secs: 9999,
                healthy: true,
            })
            .is_err(),
            "65th healthy peer must be rejected when table is at MAX_PEERS"
        );

        // Forged block at future height 50 must fail tag verification instead of returning NeedSync.
        let mut forged_future = P2pBlock::seal(
            50,
            7,
            &[0u8; 16],
            now_secs(),
            vec![P2pTx::new(1, 2, 10, 1, 1, [0u8; 16])],
            &test_key,
        );
        forged_future.block_tag_hex = "0000000000000000000000000000dead".to_string();
        assert!(
            st.apply_remote_block(forged_future).is_err(),
            "forged future block must be rejected before NeedSync"
        );

        // Pagination caps returned blocks at MAX_BLOCKS_PER_PAGE (100).
        for i in 1..=110u32 {
            st.commit_faucet(i, 10).expect("commit faucet block");
        }
        assert_eq!(st.blocks_from(1).len(), MAX_BLOCKS_PER_PAGE);
        assert_eq!(st.blocks_from_paginated(1, 500).len(), MAX_BLOCKS_PER_PAGE);
        assert_eq!(st.blocks_from_paginated(101, 50).len(), 10);

        // GossipQueue caps at MAX_GOSSIP_QUEUE and deduplicates CatchUpSync.
        let q = GossipQueue::new();
        q.push(GossipJob::CatchUpSync);
        q.push(GossipJob::CatchUpSync);
        assert_eq!(q.jobs.lock().unwrap().len(), 1);
    }

    fn send_raw_p2p_bytes(addr: SocketAddr, payload: &[u8]) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).expect("connect P2pNode");
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
    fn test_adversarial_p2p_http_smuggling_rate_limit_json_and_subnet_eclipse() {
        // 1. Live TCP HTTP smuggling & malformed header attacks -> 400 Bad Request.
        let node = spawn_node(10, vec![]);
        let addr = node.local_addr();

        let mut many_headers = String::from("GET /health HTTP/1.1\r\nHost: localhost\r\n");
        for i in 0..65 {
            many_headers.push_str(&format!("X-H-{i}: v\r\n"));
        }
        many_headers.push_str("\r\n");

        let hostile: Vec<Vec<u8>> = vec![
            b"POST /faucet HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            b"POST /faucet HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            b"GET /health\x00evil HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            b"GET /health HTTP/1.1\r\nHost: localhost\r\nX-Bad: \x07\r\n\r\n".to_vec(),
            many_headers.into_bytes(),
            b"GET /health HTTP/1.1 EXTRA\r\nHost: localhost\r\n\r\n".to_vec(),
        ];
        for (i, payload) in hostile.iter().enumerate() {
            let (code, resp) = send_raw_p2p_bytes(addr, payload);
            assert_eq!(code, 400, "hostile P2P request #{i} expected 400, got {code}: {resp}");
        }

        // 2. Per-IP rate limiter returns HTTP 429 when burst exceeded.
        let rl_node = spawn_node(11, vec![]);
        rl_node.set_rate_limit(2);
        let rl_addr = rl_node.advertise_addr();
        assert_eq!(http_get(&rl_addr, "/health").unwrap().0, 200);
        assert_eq!(http_get(&rl_addr, "/health").unwrap().0, 200);
        assert_eq!(http_get(&rl_addr, "/health").unwrap().0, 429);
        rl_node.stop();
        node.stop();

        // 3. JSON parser adversarial checks: key-substring spoofing, escaped quotes, nesting, u64 overflow.
        let v1 = parse_json(r#"{"not_account_id": 1}"#).unwrap();
        assert_eq!(v1.get_u64("account_id"), None);
        let v2 = parse_json(r#"{"not_account_id": 1, "account_id": 2, "a": "foo\\", "b": "x\\\"y"}"#).unwrap();
        assert_eq!(v2.get_u64("account_id"), Some(2));
        assert_eq!(v2.get_str("a"), Some(r"foo\"));
        assert_eq!(v2.get_str("b"), Some("x\\\"y"));
        let v_ov = parse_json(r#"{"account_id": 99999999999999999999999}"#).unwrap();
        assert_eq!(v_ov.get_u64("account_id"), None);
        let deep = format!("{}{}", "[".repeat(MAX_JSON_DEPTH + 5), "]".repeat(MAX_JSON_DEPTH + 5));
        assert!(parse_json(&deep).is_err());
        assert!(parse_json("{\"a\": \"bad\x00str\"}").is_err());

        // 4. P2P /24 subnet eclipse-attack defense on P2pNodeState::upsert_peer.
        let mut st = P2pNodeState::new(
            P2pNodeConfig {
                node_id: 0,
                bind_addr: "127.0.0.1:0".to_string(),
                advertise_addr: "127.0.0.1:18081".to_string(),
                seeds: vec![],
                gossip_interval_ms: 1000,
                cluster_seal_key: None,
            },
            "127.0.0.1:18081".parse().unwrap(),
        )
        .expect("init state");

        for i in 1..=(MAX_PEERS_PER_SUBNET as u64) {
            st.upsert_peer(PeerInfo {
                node_id: i,
                addr: format!("203.0.113.{i}:8080"),
                height: 0,
                pop_score: 10,
                qber: 0.01,
                last_seen_secs: i,
                healthy: true,
            })
            .expect("peer within /24 subnet cap");
        }
        // 5th peer in same /24 MUST be rejected.
        let eclipse_err = st
            .upsert_peer(PeerInfo {
                node_id: 5,
                addr: "203.0.113.5:8080".to_string(),
                height: 0,
                pop_score: 10,
                qber: 0.01,
                last_seen_secs: 5,
                healthy: true,
            })
            .expect_err("5th peer in same /24 must be rejected");
        assert!(eclipse_err.contains("eclipse"), "unexpected error: {eclipse_err}");

        // IPv4-mapped IPv6 in same /24 cannot bypass subnet cap.
        assert!(
            st.upsert_peer(PeerInfo {
                node_id: 6,
                addr: "[::ffff:203.0.113.6]:8080".to_string(),
                height: 0,
                pop_score: 10,
                qber: 0.01,
                last_seen_secs: 6,
                healthy: true,
            })
            .is_err()
        );

        // Peer in a different /24 subnet succeeds.
        assert!(
            st.upsert_peer(PeerInfo {
                node_id: 7,
                addr: "203.0.114.1:8080".to_string(),
                height: 0,
                pop_score: 10,
                qber: 0.01,
                last_seen_secs: 7,
                healthy: true,
            })
            .is_ok()
        );

        // Marking one peer in 203.0.113.0/24 unhealthy allows eviction and replacement.
        st.set_peer_health("203.0.113.1:8080", false);
        assert!(
            st.upsert_peer(PeerInfo {
                node_id: 8,
                addr: "203.0.113.8:8080".to_string(),
                height: 0,
                pop_score: 10,
                qber: 0.01,
                last_seen_secs: 8,
                healthy: true,
            })
            .is_ok()
        );
    }

    #[test]
    fn test_p2p_rejects_unauthenticated_and_forged_tx_theft() {
        let cluster_key = BlockSealKey::generate();
        let node = spawn_node_with_key(0, vec![], Some(cluster_key.clone()));
        let addr = node.advertise_addr();

        // Fund victim Account #1 with 1,000 VRNM.
        let (st, body) = http_post_json(&addr, "/faucet", r#"{"account_id":1,"amount":1000}"#)
            .expect("faucet");
        assert_eq!(st, 200, "faucet failed: {body}");

        // Victim registers one-time auth key for page_id=7 via POST /p2p/register.
        let victim_key = fresh_auth_key(7);
        let reg_payload = format!(
            "{{\"account_id\":1,\"keys\":[{{\"page_id\":7,\"r\":\"{:032x}\",\"s\":\"{:032x}\"}}]}}",
            victim_key.1, victim_key.2
        );
        let (st_reg, _) = http_post_json(&addr, "/p2p/register", &reg_payload).expect("register");
        assert_eq!(st_reg, 200);

        // 1. Missing auth_tag in JSON -> 401 Unauthorized.
        let (st_missing, _) = http_post_json(
            &addr,
            "/p2p/tx",
            r#"{"sender":1,"recipient":99,"amount":500,"page_id":7,"nonce":1}"#,
        )
        .expect("missing auth_tag");
        assert_eq!(st_missing, 401, "missing auth_tag must return 401");

        // 2. Truncated 32-byte binary tx without 16-byte auth_tag -> 401 Unauthorized.
        let legacy_32b = [0u8; 32];
        let (st_bin_short, _) =
            http_post_binary(&addr, "/p2p/tx", &legacy_32b).expect("short binary tx");
        assert_eq!(st_bin_short, 401, "32-byte unauthenticated binary tx must return 401");

        // 3. Unregistered page_id -> 401 Unauthorized.
        let unreg_tx = P2pTx::new(1, 99, 500, 999, 1, [0xaa; 16]);
        let (st_unreg, _) =
            http_post_json(&addr, "/p2p/tx", &unreg_tx.to_json()).expect("unregistered key");
        assert_eq!(st_unreg, 401, "unregistered page_id must return 401");

        // 4. Forged/guessed auth_tag on victim's registered page_id=7 -> 401 Unauthorized,
        //    and MUST NOT burn victim's valid key (no DoS-burning by guessing!).
        let forged_tx = P2pTx::new(1, 99, 500, 7, 1, [0xde; 16]);
        let (st_forged, _) =
            http_post_json(&addr, "/p2p/tx", &forged_tx.to_json()).expect("forged tag");
        assert_eq!(st_forged, 401, "forged auth_tag must return 401");

        // 5. Attacker tampers with recipient (changes recipient 2 -> 99) on a real victim tag -> 401!
        let mut tampered_tx =
            P2pTx::new_authenticated(1, 2, 100, 7, 1, victim_key.1, victim_key.2);
        tampered_tx.recipient = 99;
        let (st_tamper, _) =
            http_post_json(&addr, "/p2p/tx", &tampered_tx.to_json()).expect("tampered tx");
        assert_eq!(st_tamper, 401, "tampered recipient must return 401");

        // 6. Forged unauthenticated tx injected directly inside a sealed P2pBlock -> 401!
        let tip = node.state().lock().unwrap().tip_tag;
        let evil_blk = P2pBlock::seal(2, 0, &tip, now_secs(), vec![forged_tx], &cluster_key);
        let (st_blk, _) =
            http_post_json(&addr, "/p2p/block", &evil_blk.to_json()).expect("evil block");
        assert_eq!(st_blk, 401, "block with forged tx auth_tag must return 401");

        // 7. Victim's balance is STILL 1,000 VRNM (attacker stole 0!), and victim's legitimate tx succeeds!
        assert_eq!(node.state().lock().unwrap().balance_of(1), 1000);
        assert_eq!(node.state().lock().unwrap().balance_of(99), 0);

        let legit_tx = P2pTx::new_authenticated(1, 2, 250, 7, 1, victim_key.1, victim_key.2);
        let (st_ok, body_ok) =
            http_post_json(&addr, "/p2p/tx", &legit_tx.to_json()).expect("legit tx");
        assert_eq!(st_ok, 200, "legit victim tx must succeed: {body_ok}");
        assert_eq!(node.state().lock().unwrap().balance_of(1), 750);
        assert_eq!(node.state().lock().unwrap().balance_of(2), 250);

        // 8. Replay of victim's exact legitimate tx -> 401 Unauthorized!
        let (st_rep, _) =
            http_post_json(&addr, "/p2p/tx", &legit_tx.to_json()).expect("replay legit tx");
        assert_eq!(st_rep, 401, "replayed auth_tag must return 401");
        assert_eq!(node.state().lock().unwrap().balance_of(1), 750);

        node.stop();
    }

    #[test]
    fn test_p2p_rejects_block_sealed_with_wrong_or_guessed_key() {
        // 1. BlockSealKey redacts secrets in Debug and roundtrips via 0600 keyfile.
        let key_a = BlockSealKey::generate();
        let dbg_str = format!("{key_a:?}");
        assert!(dbg_str.contains("REDACTED"), "BlockSealKey Debug must redact secrets: {dbg_str}");
        assert!(!dbg_str.contains(&format!("{:x}", key_a.r())));

        let keyfile = std::env::temp_dir().join(format!(
            "vernam_p2p_seal_key_test_{}_{}.key",
            std::process::id(),
            random_field_elem() as u64
        ));
        let _ = fs::remove_file(&keyfile);
        let loaded1 = BlockSealKey::from_env_or_file(&keyfile).expect("generate + persist keyfile");
        #[cfg(unix)]
        {
            let mode = fs::metadata(&keyfile).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "persisted P2P seal keyfile must be 0600");
        }
        let loaded2 = BlockSealKey::from_env_or_file(&keyfile).expect("reload persisted keyfile");
        assert_eq!(loaded1, loaded2, "reloaded keyfile must match generated key");
        let _ = fs::remove_file(&keyfile);

        // 2. Two nodes booted WITHOUT a shared cluster key get independent OS-random keys:
        //    blocks sealed by node_a MUST be rejected by node_b (no hardcoded fallback key!).
        let node_a = spawn_node(0, vec![]);
        let node_b = spawn_node(1, vec![]);
        let addr_b = node_b.advertise_addr();

        assert_ne!(
            node_a.state().lock().unwrap().seal_key().clone(),
            node_b.state().lock().unwrap().seal_key().clone(),
            "independent nodes without shared cluster_seal_key must not share any hardcoded key"
        );

        let block_a = node_a
            .state()
            .lock()
            .unwrap()
            .commit_faucet(5, 100)
            .expect("commit faucet on node_a");

        // Submit node_a's block to node_b without pairwise key -> MUST fail closed with 401!
        let (st_wrong, body_wrong) =
            http_post_json(&addr_b, "/p2p/block", &block_a.to_json()).expect("post wrong-key block");
        assert_eq!(st_wrong, 401, "wrong-key block must fail closed with 401: {body_wrong}");
        assert_eq!(node_b.state().lock().unwrap().height, 0);

        // Also test guessed/old hardcoded constant key -> MUST fail closed with 401!
        let guessed_key = BlockSealKey::from_raw(
            0x5645_524e_414d_5032_505f_424c_4b5f_5201 & PRIME_P,
            0x3141_5926_5358_9793_2384_6264_3383_2795 & PRIME_P,
        )
        .expect("valid field elements");
        let guessed_tx = P2pTx::new_authenticated(
            TREASURY_ACCOUNT_ID,
            5,
            100,
            1,
            1,
            guessed_key.r(),
            guessed_key.s(),
        );
        let guessed_blk = P2pBlock::seal(1, 0, &[0u8; 16], now_secs(), vec![guessed_tx], &guessed_key);
        let (st_guess, _) =
            http_post_json(&addr_b, "/p2p/block", &guessed_blk.to_json()).expect("post guessed block");
        assert_eq!(st_guess, 401, "old hardcoded key guess must be rejected with 401");
        assert_eq!(node_b.state().lock().unwrap().height, 0);

        // 3. Pairwise per-peer CW-MAC key allows authenticated inter-peer block delivery
        //    WITHOUT sharing one global cluster secret!
        let pairwise_ab = BlockSealKey::generate();
        let addr_a = node_a.advertise_addr();
        node_b
            .state()
            .lock()
            .unwrap()
            .register_pairwise_peer_key(&addr_a, pairwise_ab.clone())
            .expect("register pairwise key on node_b");

        // Wrong pairwise MAC header -> 401 Unauthorized.
        let (st_bad_pw, _) = http_request_with_headers(
            &addr_b,
            "POST",
            "/p2p/block",
            Some(block_a.to_json().as_bytes()),
            Some("application/json"),
            &[
                ("X-VRNM-Peer-Addr", addr_a.as_str()),
                ("X-VRNM-Peer-Mac", "00000000000000000000000000000000"),
            ],
            DEFAULT_PEER_TIMEOUT,
        )
        .expect("bad pairwise mac");
        assert_eq!(st_bad_pw, 401, "forged pairwise MAC must return 401");

        // Valid pairwise CW-MAC header -> 200 OK!
        let valid_pw_mac = hex_encode(&compute_block_tag(
            block_a.height,
            block_a.proposer_id,
            &[0u8; 16],
            block_a.timestamp_secs,
            &block_a.txs,
            &pairwise_ab,
        ));
        let (st_ok_pw, body_ok_pw) = http_request_with_headers(
            &addr_b,
            "POST",
            "/p2p/block",
            Some(block_a.to_json().as_bytes()),
            Some("application/json"),
            &[
                ("X-VRNM-Peer-Addr", addr_a.as_str()),
                ("X-VRNM-Peer-Mac", valid_pw_mac.as_str()),
            ],
            DEFAULT_PEER_TIMEOUT,
        )
        .expect("valid pairwise mac");
        assert_eq!(st_ok_pw, 200, "valid pairwise MAC must succeed: {body_ok_pw}");
        assert_eq!(node_b.state().lock().unwrap().height, 1);
        assert_eq!(node_b.state().lock().unwrap().balance_of(5), 100);

        // 4. Faucet strictly enforces per-request and cumulative MAX_SUPPLY hard caps.
        let (st_cap, body_cap) = http_post_json(
            &addr_b,
            "/faucet",
            &format!("{{\"account_id\":7,\"amount\":{}}}", MAX_P2P_FAUCET_PER_REQUEST + 1),
        )
        .expect("over-cap faucet");
        assert_eq!(st_cap, 400, "faucet exceeding per-request cap must fail: {body_cap}");
        assert!(node_b.state().lock().unwrap().total_faucet_minted <= MAX_SUPPLY);

        node_b.stop();
        node_a.stop();
    }
}
