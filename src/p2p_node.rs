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
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::field::{PRIME_P, add_mod, mul_mod, reduce, zeroize_slice};
use crate::qkd::{Bb84Channel, Bb84Config, OsEntropySource};
pub use crate::testnet_server::{DEFAULT_RATE_LIMIT_PER_SEC, IpRateLimiter, MAX_TRACKED_IPS};

/// Dedicated treasury account ID used by `/faucet` so faucet credits flow through
/// real P2P block propagation and consensus validation.
pub const TREASURY_ACCOUNT_ID: u32 = u32::MAX;

/// Initial treasury balance at genesis (10,000,000 VRNM test units).
pub const TREASURY_INITIAL_BALANCE: u64 = 10_000_000;

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

/// Default domain-separated Carter-Wegman evaluation point `r` in `F_(2^127 - 1)` for P2P block tags.
const CW_BLOCK_R: u128 = 0x5645_524e_414d_5032_505f_424c_4b5f_5201 & PRIME_P;

/// Default domain-separated Carter-Wegman shift `s` in `F_(2^127 - 1)` for P2P block tags.
const CW_BLOCK_S: u128 = 0x3141_5926_5358_9793_2384_6264_3383_2795 & PRIME_P;

/// Resolve the active Carter-Wegman `(r, s)` key pair in `F_(2^127 - 1)` for P2P block tags.
///
/// When `VRNM_P2P_SECRET` is set and non-empty, derives a per-network key pair purely via
/// Carter-Wegman polynomial folding over `F_(2^127 - 1)` (zero computational crypto), preventing
/// default-key forgery across private or staging networks. Falls back to the default public
/// testnet key when unset so zero-config tests and devnets work out of the box.
fn p2p_block_key() -> (u128, u128) {
    match std::env::var("VRNM_P2P_SECRET") {
        Ok(secret) if !secret.is_empty() => derive_p2p_cw_key(secret.as_bytes()),
        _ => (CW_BLOCK_R, CW_BLOCK_S),
    }
}

fn derive_p2p_cw_key(secret: &[u8]) -> (u128, u128) {
    let mut r_acc = CW_BLOCK_R;
    let mut s_acc = CW_BLOCK_S;
    let len_elem = reduce(secret.len() as u128);
    r_acc = add_mod(mul_mod(r_acc, CW_BLOCK_S), len_elem);
    s_acc = add_mod(mul_mod(s_acc, CW_BLOCK_R), len_elem);
    for (idx, &b) in secret.iter().enumerate() {
        let term = ((idx as u128 + 1) << 8) | (b as u128);
        r_acc = add_mod(mul_mod(r_acc, CW_BLOCK_R), reduce(term));
        s_acc = add_mod(mul_mod(s_acc, CW_BLOCK_S), reduce(term ^ 0xA5));
    }
    if r_acc == 0 {
        r_acc = 1;
    }
    (r_acc, s_acc)
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
}

impl Default for P2pNodeConfig {
    fn default() -> Self {
        Self {
            node_id: 0,
            bind_addr: "0.0.0.0:8080".to_string(),
            advertise_addr: "127.0.0.1:8080".to_string(),
            seeds: Vec::new(),
            gossip_interval_ms: 2_000,
        }
    }
}

/// Compact 32-byte binary / JSON transfer settled on the Vernam P2P ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pTx {
    pub sender: u32,
    pub recipient: u32,
    pub amount: u64,
    pub page_id: u64,
    pub nonce: u64,
}

impl P2pTx {
    /// Fixed binary wire length in bytes (`4 + 4 + 8 + 8 + 8 = 32`).
    pub const WIRE_LEN: usize = 32;

    /// Construct a new [`P2pTx`].
    pub const fn new(
        sender: u32,
        recipient: u32,
        amount: u64,
        page_id: u64,
        nonce: u64,
    ) -> Self {
        Self {
            sender,
            recipient,
            amount,
            page_id,
            nonce,
        }
    }

    /// Encode this transaction into its 32-byte little-endian binary wire format.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[0..4].copy_from_slice(&self.sender.to_le_bytes());
        out[4..8].copy_from_slice(&self.recipient.to_le_bytes());
        out[8..16].copy_from_slice(&self.amount.to_le_bytes());
        out[16..24].copy_from_slice(&self.page_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Decode a 32-byte little-endian binary transaction.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::WIRE_LEN {
            return Err(format!(
                "invalid binary tx length: expected {} bytes, got {}",
                Self::WIRE_LEN,
                bytes.len()
            ));
        }
        let sender = u32::from_le_bytes(bytes[0..4].try_into().expect("4-byte slice"));
        let recipient = u32::from_le_bytes(bytes[4..8].try_into().expect("4-byte slice"));
        let amount = u64::from_le_bytes(bytes[8..16].try_into().expect("8-byte slice"));
        let page_id = u64::from_le_bytes(bytes[16..24].try_into().expect("8-byte slice"));
        let nonce = u64::from_le_bytes(bytes[24..32].try_into().expect("8-byte slice"));
        Ok(Self {
            sender,
            recipient,
            amount,
            page_id,
            nonce,
        })
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"sender\":{},\"recipient\":{},\"amount\":{},\"page_id\":{},\"nonce\":{}}}",
            self.sender, self.recipient, self.amount, self.page_id, self.nonce
        )
    }

    fn from_json_value(v: &JsonValue) -> Result<Self, String> {
        let sender = v
            .get_u32("sender")
            .ok_or_else(|| "missing or invalid u32 field 'sender'".to_string())?;
        let recipient = v
            .get_u32("recipient")
            .ok_or_else(|| "missing or invalid u32 field 'recipient'".to_string())?;
        let amount = v
            .get_u64("amount")
            .ok_or_else(|| "missing or invalid u64 field 'amount'".to_string())?;
        let page_id = v
            .get_u64("page_id")
            .ok_or_else(|| "missing or invalid u64 field 'page_id'".to_string())?;
        let nonce = v.get_u64("nonce").unwrap_or(0);
        Ok(Self {
            sender,
            recipient,
            amount,
            page_id,
            nonce,
        })
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
    /// Construct and seal a new [`P2pBlock`] using Carter-Wegman universal polynomial
    /// authentication over `F_(2^127 - 1)`.
    pub fn seal(
        height: u64,
        proposer_id: u64,
        prev_tag: &[u8; 16],
        timestamp_secs: u64,
        txs: Vec<P2pTx>,
    ) -> Self {
        let tag = compute_block_tag(height, proposer_id, prev_tag, timestamp_secs, &txs);
        Self {
            height,
            proposer_id,
            prev_tag_hex: hex_encode(prev_tag),
            block_tag_hex: hex_encode(&tag),
            timestamp_secs,
            txs,
        }
    }

    /// Recompute and verify this block's Carter-Wegman `F_(2^127 - 1)` tag.
    pub fn verify_tag(&self) -> Result<[u8; 16], String> {
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
        );
        if !crate::field::ct_eq_16(&claimed_tag, &expected) {
            return Err(format!(
                "invalid Carter-Wegman block tag at height {}: claimed {}, expected {}",
                self.height,
                self.block_tag_hex,
                hex_encode(&expected)
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
/// `F_(2^127 - 1)` binding `prev_tag`, `height`, `proposer_id`, `timestamp_secs`, and all `txs`.
pub fn compute_block_tag(
    height: u64,
    proposer_id: u64,
    prev_tag: &[u8; 16],
    timestamp_secs: u64,
    txs: &[P2pTx],
) -> [u8; 16] {
    let (cw_r, cw_s) = p2p_block_key();
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
        let tx_words = [pair, tx.amount as u128, tx.page_id as u128, tx.nonce as u128];
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
            peers: BTreeMap::new(),
            blocks: Vec::new(),
            height: 0,
            tip_tag: [0u8; 16],
            balances,
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

    /// Validate a batch of transactions atomically against current balances & replay protection,
    /// returning the updated `(balances, used_pages)` snapshots on success.
    fn validate_txs_atomic(
        &self,
        txs: &[P2pTx],
    ) -> Result<(BTreeMap<u32, u64>, BTreeSet<(u32, u64)>), String> {
        if txs.is_empty() {
            return Err("block must contain at least one transaction".to_string());
        }

        let mut next_balances = self.balances.clone();
        let mut next_pages = self.used_pages.clone();

        for tx in txs {
            if tx.amount == 0 {
                return Err("transaction amount must be > 0".to_string());
            }
            if tx.sender == tx.recipient {
                return Err("self-transfer forbidden".to_string());
            }
            if next_pages.contains(&(tx.sender, tx.page_id)) {
                return Err(format!(
                    "replay detected: (sender={}, page_id={}) already consumed",
                    tx.sender, tx.page_id
                ));
            }
            let sender_bal = next_balances.get(&tx.sender).copied().unwrap_or(0);
            if sender_bal < tx.amount {
                return Err(format!(
                    "insufficient balance (overdraft): account {} has {}, needs {}",
                    tx.sender, sender_bal, tx.amount
                ));
            }
            let recip_bal = next_balances.get(&tx.recipient).copied().unwrap_or(0);
            let new_recip = recip_bal
                .checked_add(tx.amount)
                .ok_or_else(|| "recipient balance overflow".to_string())?;

            next_balances.insert(tx.sender, sender_bal - tx.amount);
            next_balances.insert(tx.recipient, new_recip);
            next_pages.insert((tx.sender, tx.page_id));
        }

        Ok((next_balances, next_pages))
    }

    /// Commit a locally submitted transaction into a new finalized block sealed with a
    /// Carter-Wegman `F_(2^127 - 1)` chain tag.
    pub fn commit_local_tx(&mut self, tx: P2pTx) -> Result<P2pBlock, String> {
        let (next_balances, next_pages) = self.validate_txs_atomic(std::slice::from_ref(&tx))?;
        let new_height = self.height + 1;
        let block = P2pBlock::seal(
            new_height,
            self.config.node_id,
            &self.tip_tag,
            now_secs(),
            vec![tx.clone()],
        );
        let new_tip = hex_decode_16(&block.block_tag_hex).expect("valid freshly sealed tag");

        self.balances = next_balances;
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

    /// Credit `account_id` from [`TREASURY_ACCOUNT_ID`] (`u32::MAX`) by committing a real
    /// P2P block ready to be gossiped across the entire mesh.
    pub fn commit_faucet(&mut self, account_id: u32, amount: u64) -> Result<P2pBlock, String> {
        if account_id == TREASURY_ACCOUNT_ID {
            return Err("cannot faucet into treasury account".to_string());
        }
        if amount == 0 {
            return Err("faucet amount must be > 0".to_string());
        }
        // Encode node_id in upper 32 bits of treasury page_id so concurrent faucets on
        // distinct nodes never collide on (TREASURY_ACCOUNT_ID, page_id).
        let seq = self.faucet_seq;
        self.faucet_seq += 1;
        let page_id = ((self.config.node_id & 0xFFFF_FFFF) << 32) | (seq & 0xFFFF_FFFF);
        let tx = P2pTx::new(TREASURY_ACCOUNT_ID, account_id, amount, page_id, seq);
        self.commit_local_tx(tx)
    }

    /// Validate and atomically apply an incoming gossiped or catch-up-synced block.
    fn apply_remote_block(&mut self, block: P2pBlock) -> Result<ApplyBlockOutcome, String> {
        if self.seen_block_tags.contains(&block.block_tag_hex) {
            return Ok(ApplyBlockOutcome::Duplicate);
        }

        if block.height == 0 {
            return Err("invalid block height 0".to_string());
        }

        if block.height <= self.height {
            let existing = &self.blocks[(block.height - 1) as usize];
            if existing.block_tag_hex == block.block_tag_hex {
                self.seen_block_tags.insert(block.block_tag_hex);
                return Ok(ApplyBlockOutcome::Duplicate);
            }
            return Err(format!(
                "conflicting block at height {} (local tag {}, incoming tag {})",
                block.height, existing.block_tag_hex, block.block_tag_hex
            ));
        }

        // Always verify the block's Carter-Wegman tag BEFORE queueing CatchUpSync or touching state
        // so unauthenticated/forged future blocks cannot trigger sync amplification.
        let verified_tag = block.verify_tag()?;

        if block.height > self.height + 1 {
            return Ok(ApplyBlockOutcome::NeedSync {
                local_height: self.height,
                incoming_height: block.height,
            });
        }

        // Verify chain linkage (`prev_tag == local tip_tag`).
        let expected_prev = hex_encode(&self.tip_tag);
        if block.prev_tag_hex != expected_prev {
            return Err(format!(
                "prev_tag mismatch at height {}: expected {}, got {}",
                block.height, expected_prev, block.prev_tag_hex
            ));
        }

        // Validate all transactions atomically before mutating state.
        let (next_balances, next_pages) = self.validate_txs_atomic(&block.txs)?;

        self.balances = next_balances;
        self.used_pages = next_pages;
        self.height = block.height;
        self.tip_tag = verified_tag;
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

        ("POST", "/p2p/tx") => {
            let tx = match parse_tx_from_request(req) {
                Ok(t) => t,
                Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
            };

            let (block, sender_bal, recip_bal, peer_count) = {
                let mut guard = state.lock().expect("node state mutex poisoned");
                match guard.commit_local_tx(tx.clone()) {
                    Ok(blk) => {
                        let s_bal = guard.balance_of(tx.sender);
                        let r_bal = guard.balance_of(tx.recipient);
                        let p_cnt = guard.healthy_peer_count();
                        (blk, s_bal, r_bal, p_cnt)
                    }
                    Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
                }
            };

            queue.push(GossipJob::BroadcastBlock {
                block: block.clone(),
                exclude_proposer_id: None,
            });

            HttpResponse::ok_json(format!(
                "{{\"status\":\"committed\",\"block_height\":{},\"block_tag\":\"{}\",\"sender\":{},\"recipient\":{},\"amount\":{},\"page_id\":{},\"nonce\":{},\"sender_balance\":{},\"recipient_balance\":{},\"peers_notified\":{}}}",
                block.height,
                block.block_tag_hex,
                tx.sender,
                tx.recipient,
                tx.amount,
                tx.page_id,
                tx.nonce,
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
                Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
            };

            let outcome = {
                let mut guard = state.lock().expect("node state mutex poisoned");
                match guard.apply_remote_block(block.clone()) {
                    Ok(o) => o,
                    Err(e) => return HttpResponse::err_json(400, "Bad Request", &e),
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

fn parse_tx_from_request(req: &HttpRequest) -> Result<P2pTx, String> {
    let is_binary = req
        .content_type
        .as_deref()
        .map(|ct| ct.to_ascii_lowercase().contains("octet-stream"))
        .unwrap_or(false)
        || (req.body.len() == P2pTx::WIRE_LEN && !req.body.starts_with(b"{"));

    if is_binary {
        return P2pTx::from_bytes(&req.body);
    }

    let body_str =
        std::str::from_utf8(&req.body).map_err(|_| "tx body is not valid UTF-8".to_string())?;
    let json = parse_json(body_str)?;
    P2pTx::from_json_value(&json)
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
fn gossip_block_to_peers(
    state: &Arc<Mutex<P2pNodeState>>,
    shutdown: &Arc<AtomicBool>,
    block: &P2pBlock,
    exclude_proposer_id: Option<u64>,
) {
    let targets: Vec<String> = {
        let guard = state.lock().expect("node state mutex poisoned");
        guard
            .peers
            .values()
            .filter(|p| p.healthy && Some(p.node_id) != exclude_proposer_id)
            .map(|p| p.addr.clone())
            .collect()
    };

    if targets.is_empty() {
        return;
    }

    let body = block.to_json();
    for addr in targets {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        let _ = http_request(
            &addr,
            "POST",
            "/p2p/block",
            Some(body.as_bytes()),
            Some("application/json"),
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
             Access-Control-Allow-Headers: Content-Type\r\n\
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

    fn spawn_node(node_id: u64, seeds: Vec<String>) -> P2pNode {
        let node = P2pNode::bind(P2pNodeConfig {
            node_id,
            bind_addr: "127.0.0.1:0".to_string(),
            advertise_addr: "127.0.0.1:0".to_string(),
            seeds,
            gossip_interval_ms: 40,
        })
        .expect("bind P2pNode on 127.0.0.1:0");
        node.start().expect("start P2pNode");
        node
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
        // Node 0: seed node with no seeds of its own.
        let node0 = spawn_node(0, vec![]);
        let addr0 = node0.advertise_addr();

        // Node 1: knows ONLY Node 0.
        let node1 = spawn_node(1, vec![addr0.clone()]);
        let addr1 = node1.advertise_addr();

        // Node 2: knows ONLY Node 1 (does NOT know Node 0!).
        let node2 = spawn_node(2, vec![addr1.clone()]);
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
        let node0 = spawn_node(0, vec![]);
        let addr0 = node0.advertise_addr();
        let node1 = spawn_node(1, vec![addr0.clone()]);
        let addr1 = node1.advertise_addr();
        let node2 = spawn_node(2, vec![addr1.clone()]);
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

        // 2. Send JSON /p2p/tx to Node 0: Account #1 -> Account #2 (250 VRNM, page_id=7).
        let (st, body) = http_post_json(
            &addr0,
            "/p2p/tx",
            r#"{"sender":1,"recipient":2,"amount":250,"page_id":7,"nonce":1}"#,
        )
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

        // 3. Send raw 32-byte binary /p2p/tx to Node 1: Account #2 -> Account #3 (50 VRNM, page_id=1).
        let bin_tx = P2pTx::new(2, 3, 50, 1, 1);
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
        let node0 = spawn_node(0, vec![]);
        let addr0 = node0.advertise_addr();
        let node1 = spawn_node(1, vec![addr0.clone()]);
        let addr1 = node1.advertise_addr();
        let node2 = spawn_node(2, vec![addr1.clone()]);
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

        let (st, _) = http_post_json(
            &addr0,
            "/p2p/tx",
            r#"{"sender":10,"recipient":20,"amount":125,"page_id":42,"nonce":1}"#,
        )
        .expect("tx");
        assert_eq!(st, 200);
        assert!(wait_until(2_000, || node2.state().lock().unwrap().height == 2));

        // Now start late-joining Node 3 pointing ONLY at Node 2.
        let node3 = spawn_node(3, vec![addr2.clone()]);
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
        let node0 = spawn_node(0, vec![]);
        let addr0 = node0.advertise_addr();
        let node1 = spawn_node(1, vec![addr0.clone()]);
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

        // Valid transfer of 40 VRNM using (sender=1, page_id=99) (Block #2).
        let (st, _) = http_post_json(
            &addr0,
            "/p2p/tx",
            r#"{"sender":1,"recipient":2,"amount":40,"page_id":99,"nonce":1}"#,
        )
        .expect("valid tx");
        assert_eq!(st, 200);
        assert!(wait_until(2_000, || node1.state().lock().unwrap().height == 2));

        // Replay attack on Node 1 reusing (sender=1, page_id=99) must be rejected with 400.
        let (st_replay, body_replay) = http_post_json(
            &addr1,
            "/p2p/tx",
            r#"{"sender":1,"recipient":2,"amount":10,"page_id":99,"nonce":2}"#,
        )
        .expect("replay tx");
        assert_eq!(st_replay, 400);
        assert!(
            body_replay.contains("replay"),
            "expected replay error, got: {body_replay}"
        );

        // Overdraft attack (account 1 only has 60 left, tries to spend 61) must be rejected.
        let (st_overdraft, body_overdraft) = http_post_json(
            &addr1,
            "/p2p/tx",
            r#"{"sender":1,"recipient":2,"amount":61,"page_id":100,"nonce":3}"#,
        )
        .expect("overdraft tx");
        assert_eq!(st_overdraft, 400);
        assert!(
            body_overdraft.contains("overdraft") || body_overdraft.contains("insufficient"),
            "expected overdraft error, got: {body_overdraft}"
        );

        // Forged Carter-Wegman block submitted directly to /p2p/block must be rejected.
        let tip = node1.state().lock().unwrap().tip_tag;
        let mut forged = P2pBlock::seal(
            3,
            999,
            &tip,
            now_secs(),
            vec![P2pTx::new(1, 2, 10, 101, 4)],
        );
        forged.block_tag_hex = "deadbeefdeadbeefdeadbeefdeadbeef".to_string();
        let (st_forged, body_forged) =
            http_post_json(&addr1, "/p2p/block", &forged.to_json()).expect("forged block");
        assert_eq!(st_forged, 400);
        assert!(
            body_forged.contains("Carter-Wegman"),
            "expected Carter-Wegman tag error, got: {body_forged}"
        );

        // Replayed tx inside a validly-tagged P2pBlock must also be rejected atomically.
        let replayed_blk = P2pBlock::seal(
            3,
            999,
            &tip,
            now_secs(),
            vec![P2pTx::new(1, 2, 10, 99, 5)],
        );
        let (st_rblk, body_rblk) =
            http_post_json(&addr1, "/p2p/block", &replayed_blk.to_json()).expect("replayed block");
        assert_eq!(st_rblk, 400);
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
        let mut st = P2pNodeState::new(
            P2pNodeConfig {
                node_id: 0,
                bind_addr: "127.0.0.1:0".to_string(),
                advertise_addr: "127.0.0.1:18080".to_string(),
                seeds: vec![],
                gossip_interval_ms: 1000,
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
            vec![P2pTx::new(1, 2, 10, 1, 1)],
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
}
