//! Crash-safe Vernam (VRNM) Basic CLI Wallet and Zero-Dependency HTTP/1.1 RPC Client.
//!
//! Zero external crates, zero computational cryptography (no SHA, RSA, ECDSA, or AES).
//! All security rests purely on information-theoretic primitives:
//! - Crash-safe WAL-backed One-Time Pad books (`WalPadBook`, `fsync` + disk zero-overwrite BEFORE emit)
//! - Fixed 256-byte OTP + Carter-Wegman universal MAC frames over `F_(2^127 - 1)`
//! - 16-bit Shamir-shared confidential range proofs + blinded one-hot selectors (`ConfidentialTransferRequest`)
//! - BB84 + Weak/Vacuum Decoy-State QKD pad replenishment (`Bb84Channel`)

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::field::{PRIME_P, zeroize_slice};
use crate::otp::{
    FRAME_BYTES, MAC_TAG_BYTES, OtpError, PadPage, WalPadBook, open_frame, seal_frame,
};
use crate::privacy_mpc::{
    ConfidentialTransferRequest, DEFAULT_BUCKET_SIZE, DEFAULT_RANGE_BITS, DEFAULT_THRESHOLD,
    MpcError,
};
use crate::qkd::{Bb84Channel, QkdError};

/// Default Vernam node RPC endpoint.
pub const DEFAULT_NODE_URL: &str = "http://127.0.0.1:8080";

/// Default TCP connect/read/write timeout for `WalletRpcClient`.
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Compact binary express transfer payload length in bytes:
/// `sender_id (4) + recipient_id (4) + amount (8) + page_id (8) + nonce (8) = 32`.
pub const EXPRESS_PAYLOAD_BYTES: usize = 32;

const METADATA_FILENAME: &str = "wallet.meta";

// ============================================================================
// Errors
// ============================================================================

/// Errors returned by wallet persistence, OTP signing, shielded MPC, QKD, and RPC operations.
#[derive(Debug)]
pub enum WalletError {
    /// Filesystem or socket I/O error.
    Io(io::Error),
    /// Underlying OTP, MAC, or crash-safe WAL pad book error.
    Otp(OtpError),
    /// Underlying IT-MPC confidential transfer error.
    Mpc(MpcError),
    /// Underlying BB84 QKD channel error.
    Qkd(QkdError),
    /// Invalid wallet configuration, argument, or URL.
    InvalidConfig(String),
    /// Wallet metadata file is missing required fields or malformed.
    CorruptMetadata(String),
    /// Local balance is insufficient for the requested transfer.
    InsufficientBalance {
        lane: &'static str,
        required: u64,
        available: u64,
    },
    /// At least one validator's one-time pad book has no unused pages left.
    PadExhausted { validator_id: usize },
    /// Malformed hexadecimal input.
    InvalidHex(String),
    /// Malformed binary express payload.
    InvalidPayload(String),
    /// HTTP/1.1 transport or protocol error.
    RpcError(String),
    /// Remote node returned a non-2xx HTTP status code.
    HttpStatus { status: u16, body: String },
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::Io(err) => write!(f, "wallet I/O error: {err}"),
            WalletError::Otp(err) => write!(f, "wallet OTP error: {err}"),
            WalletError::Mpc(err) => write!(f, "wallet shielded MPC error: {err}"),
            WalletError::Qkd(err) => write!(f, "wallet QKD error: {err}"),
            WalletError::InvalidConfig(msg) => write!(f, "invalid wallet configuration: {msg}"),
            WalletError::CorruptMetadata(msg) => write!(f, "corrupt wallet metadata: {msg}"),
            WalletError::InsufficientBalance {
                lane,
                required,
                available,
            } => write!(
                f,
                "insufficient {lane} balance: need {required}, available {available}"
            ),
            WalletError::PadExhausted { validator_id } => write!(
                f,
                "validator {validator_id} pad book exhausted; replenish pads via QKD"
            ),
            WalletError::InvalidHex(msg) => write!(f, "invalid hex string: {msg}"),
            WalletError::InvalidPayload(msg) => write!(f, "invalid express payload: {msg}"),
            WalletError::RpcError(msg) => write!(f, "wallet RPC error: {msg}"),
            WalletError::HttpStatus { status, body } => {
                write!(f, "node returned HTTP {status}: {body}")
            }
        }
    }
}

impl std::error::Error for WalletError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WalletError::Io(err) => Some(err),
            WalletError::Otp(err) => Some(err),
            WalletError::Mpc(err) => Some(err),
            WalletError::Qkd(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for WalletError {
    fn from(err: io::Error) -> Self {
        WalletError::Io(err)
    }
}

impl From<OtpError> for WalletError {
    fn from(err: OtpError) -> Self {
        WalletError::Otp(err)
    }
}

impl From<MpcError> for WalletError {
    fn from(err: MpcError) -> Self {
        WalletError::Mpc(err)
    }
}

impl From<QkdError> for WalletError {
    fn from(err: QkdError) -> Self {
        WalletError::Qkd(err)
    }
}

// ============================================================================
// Hex & Payload Encoding Helpers
// ============================================================================

/// Encode raw bytes as lowercase hexadecimal.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Decode a hexadecimal string (uppercase or lowercase) into raw bytes.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, WalletError> {
    let raw = hex.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(WalletError::InvalidHex(format!(
            "odd hex length: {}",
            raw.len()
        )));
    }

    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let hi = decode_nibble(pair[0])?;
        let lo = decode_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[inline]
fn decode_nibble(byte: u8) -> Result<u8, WalletError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(WalletError::InvalidHex(format!(
            "unexpected byte 0x{other:02x}"
        ))),
    }
}

/// Compact 32-byte express transfer payload sealed inside every validator OTP frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpressPayload {
    pub sender_id: u32,
    pub recipient_id: u32,
    pub amount: u64,
    pub page_id: u64,
    pub nonce: u64,
}

impl ExpressPayload {
    /// Encode into the canonical 32-byte big-endian binary payload.
    pub fn to_bytes(&self) -> [u8; EXPRESS_PAYLOAD_BYTES] {
        encode_express_payload(
            self.sender_id,
            self.recipient_id,
            self.amount,
            self.page_id,
            self.nonce,
        )
    }

    /// Decode from the canonical 32-byte big-endian binary payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        decode_express_payload(bytes)
    }
}

/// Encode `(sender_id, recipient_id, amount, page_id, nonce)` into 32 big-endian bytes.
pub fn encode_express_payload(
    sender_id: u32,
    recipient_id: u32,
    amount: u64,
    page_id: u64,
    nonce: u64,
) -> [u8; EXPRESS_PAYLOAD_BYTES] {
    let mut out = [0u8; EXPRESS_PAYLOAD_BYTES];
    out[0..4].copy_from_slice(&sender_id.to_be_bytes());
    out[4..8].copy_from_slice(&recipient_id.to_be_bytes());
    out[8..16].copy_from_slice(&amount.to_be_bytes());
    out[16..24].copy_from_slice(&page_id.to_be_bytes());
    out[24..32].copy_from_slice(&nonce.to_be_bytes());
    out
}

/// Decode a canonical 32-byte big-endian express transfer payload.
pub fn decode_express_payload(bytes: &[u8]) -> Result<ExpressPayload, WalletError> {
    if bytes.len() != EXPRESS_PAYLOAD_BYTES {
        return Err(WalletError::InvalidPayload(format!(
            "expected {EXPRESS_PAYLOAD_BYTES} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(ExpressPayload {
        sender_id: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
        recipient_id: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
        amount: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        page_id: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        nonce: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
    })
}

/// One validator's fixed 256-byte OTP ciphertext frame and 128-bit Carter-Wegman MAC tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSealedFrame {
    pub validator_id: usize,
    pub page_id: u64,
    pub frame: [u8; FRAME_BYTES],
    pub tag: [u8; MAC_TAG_BYTES],
}

impl ValidatorSealedFrame {
    /// Hex-encoded 256-byte OTP ciphertext frame.
    pub fn frame_hex(&self) -> String {
        bytes_to_hex(&self.frame)
    }

    /// Hex-encoded 16-byte Carter-Wegman MAC tag.
    pub fn tag_hex(&self) -> String {
        bytes_to_hex(&self.tag)
    }

    /// Verify the Carter-Wegman MAC and decrypt the 32-byte express payload using the paired page.
    pub fn open_with_page(&self, page: &PadPage) -> Result<ExpressPayload, WalletError> {
        let mut plaintext = open_frame(page, &self.frame, &self.tag)?;
        let res = decode_express_payload(&plaintext);
        zeroize_slice(&mut plaintext);
        res
    }
}

/// Complete express transfer bundle containing one WAL-burned OTP+MAC frame per validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedExpressBundle {
    pub sender_id: u32,
    pub recipient_id: u32,
    pub amount: u64,
    pub page_id: u64,
    pub nonce: u64,
    pub validator_frames: Vec<ValidatorSealedFrame>,
}

impl SignedExpressBundle {
    /// Return validator 0's sealed frame (primary frame for single-node RPC submission).
    pub fn primary_frame(&self) -> Option<&ValidatorSealedFrame> {
        self.validator_frames.first()
    }

    /// Hex-encoded primary 256-byte OTP frame.
    pub fn primary_frame_hex(&self) -> Option<String> {
        self.primary_frame().map(ValidatorSealedFrame::frame_hex)
    }

    /// Hex-encoded primary 16-byte Carter-Wegman MAC tag.
    pub fn primary_tag_hex(&self) -> Option<String> {
        self.primary_frame().map(ValidatorSealedFrame::tag_hex)
    }
}

// ============================================================================
// WalletConfig & WalletMetadata
// ============================================================================

/// Protocol and client defaults for `VernamWallet`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletConfig {
    /// Default node RPC base URL (`http://127.0.0.1:8080`).
    pub default_node_url: String,
    /// Sharded anonymity bucket size `K` for shielded transfers (default: 16).
    pub bucket_size: usize,
    /// Bit width `W` for confidential range proofs (default: 16).
    pub range_bits: usize,
    /// Shamir reconstruction threshold `t` (default: 3).
    pub shamir_threshold: usize,
    /// Network timeout for `WalletRpcClient` (default: 5 seconds).
    pub rpc_timeout: Duration,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            default_node_url: DEFAULT_NODE_URL.to_string(),
            bucket_size: DEFAULT_BUCKET_SIZE,
            range_bits: DEFAULT_RANGE_BITS,
            shamir_threshold: DEFAULT_THRESHOLD,
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
        }
    }
}

/// Persistent wallet state stored in `<wallet_dir>/wallet.meta` (`key=value`, `0600` on Unix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMetadata {
    pub name: String,
    pub account_id: u32,
    pub bucket_id: usize,
    pub slot_in_bucket: usize,
    pub num_validators: usize,
    pub next_nonce: u64,
    pub local_express_balance: u64,
    pub local_shielded_balance: u64,
    pub burned_pages: u64,
    pub node_url: String,
}

impl WalletMetadata {
    /// Serialize metadata to a deterministic `key=value` text representation.
    pub fn to_kv_string(&self) -> String {
        format!(
            "name={}\naccount_id={}\nbucket_id={}\nslot_in_bucket={}\nnum_validators={}\nnext_nonce={}\nlocal_express_balance={}\nlocal_shielded_balance={}\nburned_pages={}\nnode_url={}\n",
            self.name,
            self.account_id,
            self.bucket_id,
            self.slot_in_bucket,
            self.num_validators,
            self.next_nonce,
            self.local_express_balance,
            self.local_shielded_balance,
            self.burned_pages,
            self.node_url,
        )
    }

    /// Parse metadata from the `key=value` text representation.
    pub fn from_kv_str(text: &str) -> Result<Self, WalletError> {
        let mut name: Option<String> = None;
        let mut account_id: Option<u32> = None;
        let mut bucket_id: Option<usize> = None;
        let mut slot_in_bucket: Option<usize> = None;
        let mut num_validators: Option<usize> = None;
        let mut next_nonce: Option<u64> = None;
        let mut local_express_balance: Option<u64> = None;
        let mut local_shielded_balance: Option<u64> = None;
        let mut burned_pages: Option<u64> = None;
        let mut node_url: Option<String> = None;

        for (line_no, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, val)) = line.split_once('=') else {
                return Err(WalletError::CorruptMetadata(format!(
                    "malformed line {}: expected key=value",
                    line_no + 1
                )));
            };
            let key = key.trim();
            let val = val.trim();

            match key {
                "name" => name = Some(val.to_string()),
                "account_id" => account_id = Some(parse_field(key, val)?),
                "bucket_id" => bucket_id = Some(parse_field(key, val)?),
                "slot_in_bucket" => slot_in_bucket = Some(parse_field(key, val)?),
                "num_validators" => num_validators = Some(parse_field(key, val)?),
                "next_nonce" => next_nonce = Some(parse_field(key, val)?),
                "local_express_balance" => local_express_balance = Some(parse_field(key, val)?),
                "local_shielded_balance" => local_shielded_balance = Some(parse_field(key, val)?),
                "burned_pages" => burned_pages = Some(parse_field(key, val)?),
                "node_url" => node_url = Some(val.to_string()),
                _ => {
                    // Ignore unknown future keys for forward compatibility.
                }
            }
        }

        let name = name.ok_or_else(|| WalletError::CorruptMetadata("missing key: name".into()))?;
        if name.is_empty() {
            return Err(WalletError::CorruptMetadata("empty wallet name".into()));
        }
        let num_validators = num_validators
            .ok_or_else(|| WalletError::CorruptMetadata("missing key: num_validators".into()))?;
        if num_validators == 0 {
            return Err(WalletError::CorruptMetadata(
                "num_validators must be >= 1".into(),
            ));
        }

        let node_url = node_url
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| DEFAULT_NODE_URL.to_string());

        Ok(Self {
            name,
            account_id: account_id
                .ok_or_else(|| WalletError::CorruptMetadata("missing key: account_id".into()))?,
            bucket_id: bucket_id
                .ok_or_else(|| WalletError::CorruptMetadata("missing key: bucket_id".into()))?,
            slot_in_bucket: slot_in_bucket.ok_or_else(|| {
                WalletError::CorruptMetadata("missing key: slot_in_bucket".into())
            })?,
            num_validators,
            next_nonce: next_nonce
                .ok_or_else(|| WalletError::CorruptMetadata("missing key: next_nonce".into()))?,
            local_express_balance: local_express_balance.ok_or_else(|| {
                WalletError::CorruptMetadata("missing key: local_express_balance".into())
            })?,
            local_shielded_balance: local_shielded_balance.ok_or_else(|| {
                WalletError::CorruptMetadata("missing key: local_shielded_balance".into())
            })?,
            burned_pages: burned_pages
                .ok_or_else(|| WalletError::CorruptMetadata("missing key: burned_pages".into()))?,
            node_url,
        })
    }

    /// Atomically write metadata with `0600` permissions (Unix) via temp file + `fsync` + `rename`.
    pub fn save_atomic(&self, path: &Path) -> Result<(), WalletError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let tmp_path = temp_metadata_path(path);
        let serialized = self.to_kv_string();

        let mut file = open_owner_only_write(&tmp_path)?;
        file.write_all(serialized.as_bytes())?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp_path, path)?;

        #[cfg(unix)]
        {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Load and parse metadata from `<wallet_dir>/wallet.meta`.
    pub fn load(path: &Path) -> Result<Self, WalletError> {
        let content = fs::read_to_string(path)?;
        Self::from_kv_str(&content)
    }
}

fn parse_field<T: std::str::FromStr>(key: &str, val: &str) -> Result<T, WalletError> {
    val.parse::<T>()
        .map_err(|_| WalletError::CorruptMetadata(format!("invalid value for {key}: '{val}'")))
}

fn temp_metadata_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".tmp");
    PathBuf::from(os)
}

fn open_owner_only_write(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn validate_single_line(field_name: &str, value: &str) -> Result<(), WalletError> {
    if value.contains('\n') || value.contains('\r') {
        return Err(WalletError::InvalidConfig(format!(
            "{field_name} must not contain newline characters"
        )));
    }
    Ok(())
}

// ============================================================================
// VernamWallet
// ============================================================================

/// Crash-safe Vernam (VRNM) wallet holding metadata and one `WalPadBook` per validator.
#[derive(Debug)]
pub struct VernamWallet {
    dir: PathBuf,
    config: WalletConfig,
    metadata: WalletMetadata,
    pad_books: Vec<WalPadBook>,
}

impl VernamWallet {
    /// Create a new crash-safe `VernamWallet` in `dir`, initializing `wallet.meta` (`0600`)
    /// and one `WalPadBook` (`pad_v0.bin`, `pad_v1.bin`, ...) per validator with `initial_pages`
    /// fresh 256-byte OTP + Carter-Wegman MAC pages.
    pub fn create(
        dir: &Path,
        name: &str,
        account_id: u32,
        num_validators: usize,
        initial_pages: usize,
        node_url: &str,
    ) -> Result<Self, WalletError> {
        Self::create_with_config(
            dir,
            name,
            account_id,
            num_validators,
            initial_pages,
            node_url,
            WalletConfig::default(),
        )
    }

    /// Create a new crash-safe `VernamWallet` with custom [`WalletConfig`] parameters.
    pub fn create_with_config(
        dir: &Path,
        name: &str,
        account_id: u32,
        num_validators: usize,
        initial_pages: usize,
        node_url: &str,
        config: WalletConfig,
    ) -> Result<Self, WalletError> {
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() {
            return Err(WalletError::InvalidConfig(
                "wallet name must not be empty".into(),
            ));
        }
        validate_single_line("name", trimmed_name)?;

        if num_validators == 0 {
            return Err(WalletError::InvalidConfig(
                "num_validators must be >= 1".into(),
            ));
        }
        if config.bucket_size == 0 || config.range_bits == 0 || config.range_bits > 64 {
            return Err(WalletError::InvalidConfig(
                "bucket_size must be >= 1 and range_bits in 1..=64".into(),
            ));
        }

        let resolved_url = if node_url.trim().is_empty() {
            config.default_node_url.clone()
        } else {
            node_url.trim().to_string()
        };
        validate_single_line("node_url", &resolved_url)?;

        fs::create_dir_all(dir)?;

        let mut pad_books = Vec::with_capacity(num_validators);
        for v in 0..num_validators {
            let pages: Vec<PadPage> = (0..initial_pages)
                .map(|idx| PadPage::generate(idx as u64, FRAME_BYTES))
                .collect();
            let path = Self::pad_book_path(dir, v);
            let book = WalPadBook::create(path, FRAME_BYTES, pages)?;
            pad_books.push(book);
        }

        let account_usize = account_id as usize;
        let metadata = WalletMetadata {
            name: trimmed_name.to_string(),
            account_id,
            bucket_id: account_usize / config.bucket_size,
            slot_in_bucket: account_usize % config.bucket_size,
            num_validators,
            next_nonce: 0,
            local_express_balance: 0,
            local_shielded_balance: 0,
            burned_pages: 0,
            node_url: resolved_url,
        };

        metadata.save_atomic(&Self::metadata_path(dir))?;

        Ok(Self {
            dir: dir.to_path_buf(),
            config,
            metadata,
            pad_books,
        })
    }

    /// Reopen an existing `VernamWallet` from disk, replaying every validator's WAL so all
    /// previously burned pages remain permanently burned and wiped.
    pub fn open(dir: &Path) -> Result<Self, WalletError> {
        Self::open_with_config(dir, WalletConfig::default())
    }

    /// Reopen an existing `VernamWallet` from disk with custom [`WalletConfig`] parameters.
    pub fn open_with_config(dir: &Path, config: WalletConfig) -> Result<Self, WalletError> {
        let metadata = WalletMetadata::load(&Self::metadata_path(dir))?;
        let mut pad_books = Vec::with_capacity(metadata.num_validators);

        for v in 0..metadata.num_validators {
            let path = Self::pad_book_path(dir, v);
            let book = WalPadBook::open(&path)?;
            if book.enc_key_bytes() != FRAME_BYTES {
                return Err(WalletError::CorruptMetadata(format!(
                    "validator {v} pad book enc_key_bytes={} != expected {FRAME_BYTES}",
                    book.enc_key_bytes()
                )));
            }
            pad_books.push(book);
        }

        Ok(Self {
            dir: dir.to_path_buf(),
            config,
            metadata,
            pad_books,
        })
    }

    /// Path to the wallet metadata file (`<wallet_dir>/wallet.meta`).
    pub fn metadata_path(dir: &Path) -> PathBuf {
        dir.join(METADATA_FILENAME)
    }

    /// Path to validator `validator_id`'s crash-safe pad book (`<wallet_dir>/pad_v<id>.bin`).
    pub fn pad_book_path(dir: &Path, validator_id: usize) -> PathBuf {
        dir.join(format!("pad_v{validator_id}.bin"))
    }

    /// Wallet directory path on disk.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Borrow the wallet configuration.
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    /// Borrow the persisted wallet metadata.
    pub fn metadata(&self) -> &WalletMetadata {
        &self.metadata
    }

    /// Borrow validator `validator_id`'s `WalPadBook`, if in range.
    pub fn pad_book(&self, validator_id: usize) -> Option<&WalPadBook> {
        self.pad_books.get(validator_id)
    }

    /// Returns `true` if `page_id` is permanently burned in validator `validator_id`'s WAL book.
    pub fn is_page_burned(&self, validator_id: usize, page_id: u64) -> bool {
        self.pad_books
            .get(validator_id)
            .is_some_and(|book| book.is_burned(page_id))
    }

    /// Minimum number of unused one-time pad pages remaining across all validator pad books.
    pub fn remaining_pages(&self) -> usize {
        self.pad_books
            .iter()
            .map(WalPadBook::remaining)
            .min()
            .unwrap_or(0)
    }

    /// Construct a [`WalletRpcClient`] configured for this wallet's `node_url` and timeout.
    pub fn rpc_client(&self) -> Result<WalletRpcClient, WalletError> {
        WalletRpcClient::with_timeout(&self.metadata.node_url, self.config.rpc_timeout)
    }

    /// Prepare a crash-safe express lane transfer bundle:
    /// 1. Pre-verifies every validator's pad book has at least one unused page.
    /// 2. Pops one WAL-burned `PadPage` per validator (`fsync` WAL + `fsync` zeroed disk slot BEFORE emit).
    /// 3. Encodes the 32-byte payload `(sender_id, recipient_id, amount, page_id, nonce)` and seals
    ///    a fixed 256-byte OTP + Carter-Wegman MAC frame per validator, wiping key material on drop.
    /// 4. Increments `next_nonce` and `burned_pages` and persists `wallet.meta` atomically.
    pub fn prepare_express_transfer(
        &mut self,
        recipient_id: u32,
        amount: u64,
    ) -> Result<SignedExpressBundle, WalletError> {
        for (v, book) in self.pad_books.iter().enumerate() {
            if book.remaining() == 0 {
                return Err(WalletError::PadExhausted { validator_id: v });
            }
        }

        let sender_id = self.metadata.account_id;
        let nonce = self.metadata.next_nonce;
        let mut validator_frames = Vec::with_capacity(self.pad_books.len());
        let mut primary_page_id: Option<u64> = None;

        for (v, book) in self.pad_books.iter_mut().enumerate() {
            // Durability FIRST: WalPadBook::pop_next fsyncs the WAL burn record and overwrites
            // the disk slot with zeros + fsync BEFORE returning the PadPage.
            let page = book.pop_next()?;
            let page_id = page.page_id;
            if primary_page_id.is_none() {
                primary_page_id = Some(page_id);
            }

            let mut payload =
                encode_express_payload(sender_id, recipient_id, amount, page_id, nonce);
            let sealed = seal_frame(&page, &payload);
            zeroize_slice(&mut payload);
            // Explicitly drop PadPage now so volatile RAM zeroization runs immediately.
            drop(page);

            let (frame, tag) = sealed?;
            validator_frames.push(ValidatorSealedFrame {
                validator_id: v,
                page_id,
                frame,
                tag,
            });
        }

        self.metadata.next_nonce = self.metadata.next_nonce.saturating_add(1);
        self.metadata.burned_pages = self.metadata.burned_pages.saturating_add(1);
        self.metadata.local_express_balance =
            self.metadata.local_express_balance.saturating_sub(amount);
        self.persist_metadata()?;

        Ok(SignedExpressBundle {
            sender_id,
            recipient_id,
            amount,
            page_id: primary_page_id.unwrap_or(0),
            nonce,
            validator_frames,
        })
    }

    /// Build a 16-bit Shamir-shared range proof and blinded one-hot recipient selector for a
    /// shielded lane transfer using `local_shielded_balance` (fails cleanly on overdraft).
    pub fn prepare_shielded_transfer(
        &mut self,
        recipient_bucket: usize,
        recipient_slot: usize,
        amount: u64,
    ) -> Result<ConfidentialTransferRequest, WalletError> {
        let available = self.metadata.local_shielded_balance;
        if amount > available {
            return Err(WalletError::InsufficientBalance {
                lane: "shielded",
                required: amount,
                available,
            });
        }

        let threshold = self
            .config
            .shamir_threshold
            .min(self.metadata.num_validators)
            .max(1);

        let req = ConfidentialTransferRequest::new(
            self.metadata.account_id as usize,
            available as u128,
            recipient_bucket,
            recipient_slot,
            amount as u128,
            self.config.bucket_size,
            self.config.range_bits,
            threshold,
            self.metadata.num_validators,
        )?;

        self.metadata.local_shielded_balance = available - amount;
        self.persist_metadata()?;

        Ok(req)
    }

    /// Replenish every validator's `WalPadBook` with `num_pages` fresh OTP + Carter-Wegman MAC
    /// pages distilled via `Bb84Channel::default_channel().exchange_key(...)`.
    ///
    /// Returns the number of pages appended per validator.
    pub fn replenish_pads_via_qkd(&mut self, num_pages: usize) -> Result<usize, WalletError> {
        if num_pages == 0 {
            return Ok(0);
        }

        const MAC_BYTES_PER_PAGE: usize = 32; // 16 bytes for mac_r + 16 bytes for mac_s
        let bytes_per_page = FRAME_BYTES + MAC_BYTES_PER_PAGE;
        let total_bytes = num_pages
            .checked_mul(bytes_per_page)
            .ok_or_else(|| WalletError::InvalidConfig("QKD page count overflow".into()))?;

        let mut channel = Bb84Channel::default_channel();

        for book in &mut self.pad_books {
            let mut ex = channel.exchange_key(total_bytes)?;
            let start_id = book.next_page_id();
            let mut new_pages = Vec::with_capacity(num_pages);

            let build_res: Result<(), WalletError> = (|| {
                for i in 0..num_pages {
                    let base = i * bytes_per_page;
                    let enc_end = base + FRAME_BYTES;
                    let r_end = enc_end + 16;
                    let s_end = r_end + 16;

                    let enc_key = ex.alice_key[base..enc_end].to_vec();
                    let mac_r = qkd_field_elem_from_slice(&ex.alice_key[enc_end..r_end], &mut channel)?;
                    let mac_s = qkd_field_elem_from_slice(&ex.alice_key[r_end..s_end], &mut channel)?;

                    let page_id = start_id
                        .checked_add(i as u64)
                        .ok_or_else(|| WalletError::InvalidConfig("page_id overflow".into()))?;
                    new_pages.push(PadPage::from_raw(page_id, enc_key, mac_r, mac_s));
                }
                Ok(())
            })();

            // Zeroize transient QKD key buffers immediately regardless of outcome.
            zeroize_slice(&mut ex.alice_key);
            zeroize_slice(&mut ex.bob_key);
            build_res?;

            book.append_pages(new_pages)?;
        }

        Ok(num_pages)
    }

    /// Update cached express and shielded balances and persist `wallet.meta` atomically.
    pub fn sync_balances(&mut self, express: u64, shielded: u64) -> Result<(), WalletError> {
        self.metadata.local_express_balance = express;
        self.metadata.local_shielded_balance = shielded;
        self.persist_metadata()
    }

    /// Update the configured node RPC URL and persist `wallet.meta` atomically.
    pub fn set_node_url(&mut self, node_url: &str) -> Result<(), WalletError> {
        let trimmed = node_url.trim();
        if trimmed.is_empty() {
            return Err(WalletError::InvalidConfig(
                "node_url must not be empty".into(),
            ));
        }
        validate_single_line("node_url", trimmed)?;
        self.metadata.node_url = trimmed.to_string();
        self.persist_metadata()
    }

    /// Render a crisp, human-readable CLI status summary for this wallet.
    pub fn status_report(&self) -> String {
        let m = &self.metadata;
        let remaining = self.remaining_pages();
        let per_val: Vec<String> = self
            .pad_books
            .iter()
            .enumerate()
            .map(|(v, b)| format!("V{v}:{}", b.remaining()))
            .collect();

        format!(
            "Vernam (VRNM) Wallet Status\n\
             ----------------------------------------\n\
             Name             : {}\n\
             Account ID       : {} (bucket {}, slot {})\n\
             Wallet Dir       : {}\n\
             Node URL         : {}\n\
             Express Balance  : {} VRNM (cached)\n\
             Shielded Balance : {} VRNM (cached)\n\
             Validators       : {}\n\
             Remaining Pads   : {} min [{}]\n\
             Burned Pages     : {}\n\
             Next Nonce       : {}\n",
            m.name,
            m.account_id,
            m.bucket_id,
            m.slot_in_bucket,
            self.dir.display(),
            m.node_url,
            m.local_express_balance,
            m.local_shielded_balance,
            m.num_validators,
            remaining,
            per_val.join(", "),
            m.burned_pages,
            m.next_nonce,
        )
    }

    fn persist_metadata(&self) -> Result<(), WalletError> {
        self.metadata.save_atomic(&Self::metadata_path(&self.dir))
    }
}

/// Convert a 16-byte QKD slice into a uniform element in `[0, PRIME_P)` with zero modulo bias.
fn qkd_field_elem_from_slice(
    bytes: &[u8],
    channel: &mut Bb84Channel,
) -> Result<u128, WalletError> {
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    let candidate = u128::from_le_bytes(arr) & PRIME_P;
    zeroize_slice(&mut arr);
    if candidate < PRIME_P {
        return Ok(candidate);
    }

    // 1-in-2^127 rejection fallback: draw fresh 16 bytes from BB84.
    loop {
        let mut ex = channel.exchange_key(16)?;
        let mut retry = [0u8; 16];
        retry.copy_from_slice(&ex.alice_key[..16]);
        zeroize_slice(&mut ex.alice_key);
        zeroize_slice(&mut ex.bob_key);
        let v = u128::from_le_bytes(retry) & PRIME_P;
        zeroize_slice(&mut retry);
        if v < PRIME_P {
            return Ok(v);
        }
    }
}

// ============================================================================
// Zero-Dependency HTTP/1.1 RPC Client (`WalletRpcClient`)
// ============================================================================

/// Zero-dependency HTTP/1.1 JSON RPC client over `std::net::TcpStream`.
#[derive(Debug, Clone)]
pub struct WalletRpcClient {
    host: String,
    port: u16,
    base_path: String,
    timeout: Duration,
}

impl WalletRpcClient {
    /// Parse `http://host:port` (or `host:port`) with the default 5-second timeout.
    pub fn new(node_url: &str) -> Result<Self, WalletError> {
        Self::with_timeout(node_url, DEFAULT_RPC_TIMEOUT)
    }

    /// Parse `http://host:port` (or `host:port`) with a custom connect/read/write timeout.
    pub fn with_timeout(node_url: &str, timeout: Duration) -> Result<Self, WalletError> {
        let (host, port, base_path) = parse_http_endpoint(node_url)?;
        Ok(Self {
            host,
            port,
            base_path,
            timeout,
        })
    }

    /// Target host string (without port).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Target TCP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Configured I/O timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// `GET /health`
    pub fn health(&self) -> Result<String, WalletError> {
        self.request("GET", "/health", None)
    }

    /// `GET /status`
    pub fn status(&self) -> Result<String, WalletError> {
        self.request("GET", "/status", None)
    }

    /// `POST /faucet`
    pub fn faucet(
        &self,
        account_id: u32,
        express_amount: u64,
        shielded_amount: u64,
    ) -> Result<String, WalletError> {
        let body = format!(
            "{{\"account_id\":{account_id},\"express_amount\":{express_amount},\"shielded_amount\":{shielded_amount}}}"
        );
        self.request("POST", "/faucet", Some(&body))
    }

    /// `GET /balance/<id>`
    pub fn get_balance(&self, account_id: u32) -> Result<String, WalletError> {
        self.request("GET", &format!("/balance/{account_id}"), None)
    }

    /// `POST /tx/express`
    #[allow(clippy::too_many_arguments)]
    pub fn send_express(
        &self,
        sender: u32,
        recipient: u32,
        amount: u64,
        page_id: u64,
        nonce: u64,
        frame_hex: &str,
        tag_hex: &str,
    ) -> Result<String, WalletError> {
        let escaped_frame = escape_json_str(frame_hex);
        let escaped_tag = escape_json_str(tag_hex);
        let body = format!(
            "{{\"sender\":{sender},\"recipient\":{recipient},\"amount\":{amount},\"page_id\":{page_id},\"nonce\":{nonce},\"frame_hex\":\"{escaped_frame}\",\"tag_hex\":\"{escaped_tag}\"}}"
        );
        self.request("POST", "/tx/express", Some(&body))
    }

    /// `POST /tx/shielded`
    pub fn send_shielded(
        &self,
        sender: u32,
        recipient_bucket: usize,
        recipient_slot: usize,
        amount: u64,
    ) -> Result<String, WalletError> {
        let body = format!(
            "{{\"sender\":{sender},\"recipient_bucket\":{recipient_bucket},\"recipient_slot\":{recipient_slot},\"amount\":{amount}}}"
        );
        self.request("POST", "/tx/shielded", Some(&body))
    }

    /// `POST /epoch/refresh`
    pub fn trigger_pss_refresh(&self) -> Result<String, WalletError> {
        self.request("POST", "/epoch/refresh", Some("{}"))
    }

    /// Perform a raw HTTP/1.1 request over `TcpStream` with `Connection: close`.
    fn request(
        &self,
        method: &str,
        path: &str,
        json_body: Option<&str>,
    ) -> Result<String, WalletError> {
        let addr_host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };

        let mut addrs = addr_host.to_socket_addrs().map_err(|e| {
            WalletError::RpcError(format!("failed to resolve '{addr_host}': {e}"))
        })?;
        let sock_addr = addrs
            .next()
            .ok_or_else(|| WalletError::RpcError(format!("no addresses resolved for '{addr_host}'")))?;

        let mut stream = TcpStream::connect_timeout(&sock_addr, self.timeout).map_err(|e| {
            WalletError::RpcError(format!("failed to connect to {sock_addr}: {e}"))
        })?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let full_path = if self.base_path.is_empty() {
            path.to_string()
        } else {
            format!("{}{}", self.base_path, path)
        };

        let host_header = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };

        let req = match json_body {
            Some(body) => format!(
                "{method} {full_path} HTTP/1.1\r\n\
                 Host: {host_header}\r\n\
                 User-Agent: vernam-wallet/0.2\r\n\
                 Accept: application/json\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {body}",
                body.len()
            ),
            None => format!(
                "{method} {full_path} HTTP/1.1\r\n\
                 Host: {host_header}\r\n\
                 User-Agent: vernam-wallet/0.2\r\n\
                 Accept: application/json\r\n\
                 Connection: close\r\n\
                 \r\n"
            ),
        };

        stream.write_all(req.as_bytes())?;
        stream.flush()?;

        let mut raw_resp = Vec::new();
        stream.read_to_end(&mut raw_resp)?;

        parse_http_response(&raw_resp)
    }
}

fn parse_http_endpoint(raw_url: &str) -> Result<(String, u16, String), WalletError> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(WalletError::InvalidConfig("empty node URL".into()));
    }

    let without_scheme = if let Some(rest) = trimmed.strip_prefix("http://") {
        rest
    } else if trimmed.contains("://") {
        return Err(WalletError::InvalidConfig(format!(
            "unsupported URL scheme in '{trimmed}' (only http:// is supported)"
        )));
    } else {
        trimmed
    };

    let (authority, base_path) = match without_scheme.find('/') {
        Some(idx) => {
            let p = without_scheme[idx..].trim_end_matches('/');
            (&without_scheme[..idx], p.to_string())
        }
        None => (without_scheme, String::new()),
    };

    if authority.is_empty() {
        return Err(WalletError::InvalidConfig(format!(
            "missing host in node URL '{trimmed}'"
        )));
    }

    // Handle IPv6 bracketed form `[::1]:8080` or `[::1]`
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some(end_bracket) = rest.find(']') else {
            return Err(WalletError::InvalidConfig(format!(
                "unclosed IPv6 bracket in '{trimmed}'"
            )));
        };
        let host = &rest[..end_bracket];
        let after = &rest[end_bracket + 1..];
        let port = if after.is_empty() {
            80u16
        } else if let Some(port_str) = after.strip_prefix(':') {
            port_str.parse::<u16>().map_err(|_| {
                WalletError::InvalidConfig(format!("invalid port '{port_str}' in '{trimmed}'"))
            })?
        } else {
            return Err(WalletError::InvalidConfig(format!(
                "invalid authority '{authority}'"
            )));
        };
        (host.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if h.is_empty() {
            return Err(WalletError::InvalidConfig(format!(
                "missing host before port in '{trimmed}'"
            )));
        }
        let port = p.parse::<u16>().map_err(|_| {
            WalletError::InvalidConfig(format!("invalid port '{p}' in '{trimmed}'"))
        })?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), 80u16)
    };

    if host.is_empty() {
        return Err(WalletError::InvalidConfig(format!(
            "empty host in '{trimmed}'"
        )));
    }

    Ok((host, port, base_path))
}

fn parse_http_response(raw: &[u8]) -> Result<String, WalletError> {
    let (header_bytes, body_bytes) = if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = find_subslice(raw, b"\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        return Err(WalletError::RpcError(
            "malformed HTTP response: missing header/body delimiter".into(),
        ));
    };

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| WalletError::RpcError("HTTP response headers are not valid UTF-8".into()))?;

    let mut lines = header_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| WalletError::RpcError("empty HTTP status line".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| WalletError::RpcError(format!("malformed status line: '{status_line}'")))?
        .parse()
        .map_err(|_| WalletError::RpcError(format!("invalid HTTP status in '{status_line}'")))?;

    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("transfer-encoding")
            && v.to_ascii_lowercase().contains("chunked")
        {
            is_chunked = true;
        }
    }

    let decoded_body = if is_chunked {
        decode_chunked_body(body_bytes)?
    } else {
        body_bytes.to_vec()
    };

    let body_text = String::from_utf8_lossy(&decoded_body).into_owned();
    if (200..300).contains(&status) {
        Ok(body_text)
    } else {
        Err(WalletError::HttpStatus {
            status,
            body: body_text,
        })
    }
}

fn decode_chunked_body(mut data: &[u8]) -> Result<Vec<u8>, WalletError> {
    let mut out = Vec::new();
    loop {
        let Some(crlf) = find_subslice(data, b"\r\n") else {
            return Err(WalletError::RpcError(
                "truncated chunked HTTP response".into(),
            ));
        };
        let size_line = std::str::from_utf8(&data[..crlf])
            .map_err(|_| WalletError::RpcError("invalid chunk size line".into()))?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16).map_err(|_| {
            WalletError::RpcError(format!("invalid chunk size hex '{size_hex}'"))
        })?;
        data = &data[crlf + 2..];
        if chunk_len == 0 {
            break;
        }
        if data.len() < chunk_len + 2 {
            return Err(WalletError::RpcError(
                "chunked HTTP body shorter than declared chunk length".into(),
            ));
        }
        out.extend_from_slice(&data[..chunk_len]);
        data = &data[chunk_len + 2..];
    }
    Ok(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempWalletDir(PathBuf);

    impl TempWalletDir {
        fn new(label: &str) -> Self {
            let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "vernam_wallet_test_{}_{}_{}",
                label,
                std::process::id(),
                seq
            ));
            let _ = fs::remove_dir_all(&dir);
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempWalletDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_create_express_transfer_reopen_and_burn_persistence() {
        let tmp = TempWalletDir::new("express_persist");
        let num_validators = 4;
        let initial_pages = 5;

        let bundle0 = {
            let mut wallet = VernamWallet::create(
                tmp.path(),
                "alice",
                17,
                num_validators,
                initial_pages,
                DEFAULT_NODE_URL,
            )
            .expect("create wallet");

            // Verify bucket/slot derivation (17 = bucket 1, slot 1 for K=16)
            assert_eq!(wallet.metadata().bucket_id, 1);
            assert_eq!(wallet.metadata().slot_in_bucket, 1);
            assert_eq!(wallet.remaining_pages(), initial_pages);
            assert_eq!(wallet.metadata().next_nonce, 0);
            assert_eq!(wallet.metadata().burned_pages, 0);

            // Verify 0600 permissions on Unix
            #[cfg(unix)]
            {
                let meta_mode = fs::metadata(VernamWallet::metadata_path(tmp.path()))
                    .expect("stat wallet.meta")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(meta_mode, 0o600, "wallet.meta must be owner-only 0600");
            }

            wallet.sync_balances(10_000, 5_000).expect("sync balances");
            let bundle = wallet
                .prepare_express_transfer(42, 1_250)
                .expect("prepare express transfer");

            assert_eq!(bundle.sender_id, 17);
            assert_eq!(bundle.recipient_id, 42);
            assert_eq!(bundle.amount, 1_250);
            assert_eq!(bundle.page_id, 0);
            assert_eq!(bundle.nonce, 0);
            assert_eq!(bundle.validator_frames.len(), num_validators);
            assert_eq!(wallet.remaining_pages(), initial_pages - 1);
            assert_eq!(wallet.metadata().next_nonce, 1);
            assert_eq!(wallet.metadata().burned_pages, 1);
            assert_eq!(wallet.metadata().local_express_balance, 8_750);
            bundle
        };

        // Close and reopen from disk: page 0 MUST remain permanently burned across all validators!
        let mut reopened = VernamWallet::open(tmp.path()).expect("reopen wallet");
        assert_eq!(reopened.metadata().name, "alice");
        assert_eq!(reopened.metadata().account_id, 17);
        assert_eq!(reopened.metadata().bucket_id, 1);
        assert_eq!(reopened.metadata().slot_in_bucket, 1);
        assert_eq!(reopened.metadata().next_nonce, 1);
        assert_eq!(reopened.metadata().burned_pages, 1);
        assert_eq!(reopened.metadata().local_express_balance, 8_750);
        assert_eq!(reopened.metadata().local_shielded_balance, 5_000);
        assert_eq!(reopened.remaining_pages(), initial_pages - 1);

        for v in 0..num_validators {
            assert!(
                reopened.is_page_burned(v, 0),
                "page 0 must remain burned on validator {v} after reopen"
            );
            assert!(
                reopened.pad_book(v).unwrap().peek_unused(0).is_none(),
                "page 0 must not be unused on validator {v}"
            );
        }

        // Next transfer must automatically consume page 1 with nonce 1.
        let bundle1 = reopened
            .prepare_express_transfer(99, 500)
            .expect("second express transfer");
        assert_eq!(bundle1.page_id, 1);
        assert_eq!(bundle1.nonce, 1);
        assert_ne!(
            bundle0.primary_frame_hex().unwrap(),
            bundle1.primary_frame_hex().unwrap()
        );
        assert_eq!(reopened.remaining_pages(), initial_pages - 2);
    }

    #[test]
    fn test_express_frame_seal_and_open_roundtrip() {
        let tmp = TempWalletDir::new("seal_open");
        let mut wallet = VernamWallet::create(tmp.path(), "bob", 5, 2, 2, DEFAULT_NODE_URL)
            .expect("create wallet");

        // Duplicate validator 0's page 0 before sealing (simulating validator's paired pad copy).
        let validator0_page = wallet
            .pad_book(0)
            .unwrap()
            .peek_unused(0)
            .expect("page 0 present")
            .duplicate_for_peer();

        let bundle = wallet
            .prepare_express_transfer(12, 7_777)
            .expect("prepare express");
        let v0_frame = &bundle.validator_frames[0];
        assert_eq!(v0_frame.frame.len(), FRAME_BYTES);
        assert_eq!(v0_frame.tag.len(), MAC_TAG_BYTES);

        let decoded = v0_frame
            .open_with_page(&validator0_page)
            .expect("open validator 0 frame");
        assert_eq!(
            decoded,
            ExpressPayload {
                sender_id: 5,
                recipient_id: 12,
                amount: 7_777,
                page_id: 0,
                nonce: 0,
            }
        );

        // Flip a single ciphertext bit and confirm Carter-Wegman MAC rejects forgery.
        let mut tampered = v0_frame.clone();
        tampered.frame[13] ^= 0x01;
        assert!(matches!(
            tampered.open_with_page(&validator0_page),
            Err(WalletError::Otp(OtpError::AuthenticationFailed))
        ));
    }

    #[test]
    fn test_express_pad_exhaustion_leaves_metadata_clean() {
        let tmp = TempWalletDir::new("exhausted");
        let mut wallet =
            VernamWallet::create(tmp.path(), "exhaust", 1, 3, 1, DEFAULT_NODE_URL)
                .expect("create wallet");

        wallet
            .prepare_express_transfer(2, 10)
            .expect("consume last page");
        assert_eq!(wallet.remaining_pages(), 0);
        assert_eq!(wallet.metadata().next_nonce, 1);

        let err = wallet
            .prepare_express_transfer(2, 10)
            .expect_err("must fail when pad exhausted");
        assert!(matches!(err, WalletError::PadExhausted { validator_id: 0 }));
        assert_eq!(wallet.metadata().next_nonce, 1);
        assert_eq!(wallet.metadata().burned_pages, 1);
    }

    #[test]
    fn test_shielded_transfer_and_overdraft_rejection() {
        let tmp = TempWalletDir::new("shielded");
        let mut wallet =
            VernamWallet::create(tmp.path(), "shield", 3, 4, 2, DEFAULT_NODE_URL)
                .expect("create wallet");

        // Fresh wallet has 0 shielded balance -> overdraft rejected cleanly.
        let overdraft0 = wallet.prepare_shielded_transfer(0, 2, 1);
        assert!(matches!(
            overdraft0,
            Err(WalletError::InsufficientBalance {
                lane: "shielded",
                required: 1,
                available: 0
            })
        ));

        // Fund local shielded balance and construct a valid 16-bit confidential transfer.
        wallet.sync_balances(0, 10_000).expect("sync shielded");
        let req = wallet
            .prepare_shielded_transfer(1, 5, 2_750)
            .expect("build confidential transfer");
        assert_eq!(req.sender, 3);
        assert_eq!(req.recipient_bucket, 1);
        assert_eq!(req.v_bits.len(), DEFAULT_RANGE_BITS);
        assert_eq!(req.r_bits.len(), DEFAULT_RANGE_BITS);
        assert_eq!(req.selector_shares.len(), DEFAULT_BUCKET_SIZE);
        assert_eq!(req.v_bits[0].len(), 4);
        assert_eq!(wallet.metadata().local_shielded_balance, 7_250);

        // Overdraft above remaining 7_250 must fail cleanly without mutating balance.
        let overdraft1 = wallet.prepare_shielded_transfer(1, 5, 7_251);
        assert!(matches!(
            overdraft1,
            Err(WalletError::InsufficientBalance {
                lane: "shielded",
                required: 7_251,
                available: 7_250
            })
        ));
        assert_eq!(wallet.metadata().local_shielded_balance, 7_250);

        // Reopen from disk and confirm updated shielded balance persisted.
        let reopened = VernamWallet::open(tmp.path()).expect("reopen shielded wallet");
        assert_eq!(reopened.metadata().local_shielded_balance, 7_250);
    }

    #[test]
    fn test_qkd_pad_replenishment_increases_remaining_pages() {
        let tmp = TempWalletDir::new("qkd_replenish");
        let mut wallet =
            VernamWallet::create(tmp.path(), "quantum", 4, 4, 2, DEFAULT_NODE_URL)
                .expect("create wallet");

        wallet
            .prepare_express_transfer(8, 100)
            .expect("burn page 0");
        assert_eq!(wallet.remaining_pages(), 1);

        let added = wallet
            .replenish_pads_via_qkd(3)
            .expect("replenish 3 pages via BB84 QKD");
        assert_eq!(added, 3);
        assert_eq!(wallet.remaining_pages(), 4);

        // Reopen from disk to confirm replenished QKD pages were fsynced durably.
        let mut reopened = VernamWallet::open(tmp.path()).expect("reopen after QKD");
        assert_eq!(reopened.remaining_pages(), 4);
        for v in 0..4 {
            assert!(reopened.is_page_burned(v, 0));
        }

        // Consume all 4 remaining pages (IDs 1, 2, 3, 4).
        for expected_pid in 1..=4u64 {
            let bundle = reopened
                .prepare_express_transfer(8, 50)
                .expect("consume QKD-replenished page");
            assert_eq!(bundle.page_id, expected_pid);
        }
        assert_eq!(reopened.remaining_pages(), 0);
    }

    #[test]
    fn test_rpc_client_mock_server_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock RPC listener");
        let addr = listener.local_addr().expect("local addr");

        // Serve 7 sequential requests (health, status, faucet, balance, express, shielded, refresh).
        let server = thread::spawn(move || {
            for _ in 0..7 {
                let (mut stream, _) = listener.accept().expect("accept client");
                let mut req_buf = Vec::new();
                let mut tmp = [0u8; 2048];
                loop {
                    let n = stream.read(&mut tmp).expect("read request");
                    if n == 0 {
                        break;
                    }
                    req_buf.extend_from_slice(&tmp[..n]);
                    if let Some(hdr_end) = find_subslice(&req_buf, b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&req_buf[..hdr_end]).unwrap();
                        let content_len: usize = headers
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    v.trim().parse().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if req_buf.len() >= hdr_end + 4 + content_len {
                            break;
                        }
                    }
                }

                let req_str = String::from_utf8_lossy(&req_buf);
                let first_line = req_str.lines().next().unwrap_or("");
                let body_part = req_str.split("\r\n\r\n").nth(1).unwrap_or("");

                let (status_line, resp_body) = match first_line {
                    l if l.starts_with("GET /health ") => {
                        ("HTTP/1.1 200 OK", "{\"ok\":true,\"status\":\"healthy\"}".to_string())
                    }
                    l if l.starts_with("GET /status ") => {
                        ("HTTP/1.1 200 OK", "{\"height\":12,\"validators\":4}".to_string())
                    }
                    l if l.starts_with("POST /faucet ") => {
                        assert!(body_part.contains("\"account_id\":7"));
                        assert!(body_part.contains("\"express_amount\":5000"));
                        assert!(body_part.contains("\"shielded_amount\":2000"));
                        ("HTTP/1.1 200 OK", "{\"funded\":true}".to_string())
                    }
                    l if l.starts_with("GET /balance/7 ") => (
                        "HTTP/1.1 200 OK",
                        "{\"account_id\":7,\"express\":5000,\"shielded\":2000}".to_string(),
                    ),
                    l if l.starts_with("POST /tx/express ") => {
                        assert!(body_part.contains("\"sender\":7"));
                        assert!(body_part.contains("\"recipient\":9"));
                        assert!(body_part.contains("\"amount\":250"));
                        assert!(body_part.contains("\"page_id\":0"));
                        assert!(body_part.contains("\"nonce\":0"));
                        assert!(body_part.contains("\"frame_hex\":\"deadbeef\""));
                        assert!(body_part.contains("\"tag_hex\":\"cafebabe\""));
                        ("HTTP/1.1 200 OK", "{\"finalized\":true,\"block\":13}".to_string())
                    }
                    l if l.starts_with("POST /tx/shielded ") => {
                        assert!(body_part.contains("\"sender\":7"));
                        assert!(body_part.contains("\"recipient_bucket\":1"));
                        assert!(body_part.contains("\"recipient_slot\":4"));
                        assert!(body_part.contains("\"amount\":300"));
                        ("HTTP/1.1 200 OK", "{\"shielded_ok\":true}".to_string())
                    }
                    l if l.starts_with("POST /epoch/refresh ") => {
                        ("HTTP/1.1 200 OK", "{\"epoch\":2}".to_string())
                    }
                    other => (
                        "HTTP/1.1 404 Not Found",
                        format!("{{\"error\":\"unexpected request: {other}\"}}"),
                    ),
                };

                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                stream.write_all(response.as_bytes()).expect("write response");
                stream.flush().expect("flush response");
            }
        });

        let client = WalletRpcClient::new(&format!("http://{addr}")).expect("create RPC client");

        let h = client.health().expect("health");
        assert!(h.contains("\"healthy\""));

        let s = client.status().expect("status");
        assert!(s.contains("\"height\":12"));

        let f = client.faucet(7, 5000, 2000).expect("faucet");
        assert!(f.contains("\"funded\":true"));

        let b = client.get_balance(7).expect("get_balance");
        assert!(b.contains("\"express\":5000"));

        let ex = client
            .send_express(7, 9, 250, 0, 0, "deadbeef", "cafebabe")
            .expect("send_express");
        assert!(ex.contains("\"finalized\":true"));

        let sh = client
            .send_shielded(7, 1, 4, 300)
            .expect("send_shielded");
        assert!(sh.contains("\"shielded_ok\":true"));

        let ep = client.trigger_pss_refresh().expect("trigger_pss_refresh");
        assert!(ep.contains("\"epoch\":2"));

        server.join().expect("mock server thread finished");
    }

    #[test]
    fn test_hex_helpers_and_status_report() {
        let sample = [0x00u8, 0x0f, 0x10, 0xab, 0xff];
        let hex = bytes_to_hex(&sample);
        assert_eq!(hex, "000f10abff");
        assert_eq!(hex_to_bytes(&hex).unwrap(), sample);
        assert_eq!(hex_to_bytes("000F10ABFF").unwrap(), sample);
        assert!(matches!(hex_to_bytes("abc"), Err(WalletError::InvalidHex(_))));
        assert!(matches!(hex_to_bytes("zz"), Err(WalletError::InvalidHex(_))));

        let tmp = TempWalletDir::new("status_report");
        let mut wallet = VernamWallet::create(
            tmp.path(),
            "status_demo",
            20,
            4,
            3,
            "http://127.0.0.1:9090",
        )
        .expect("create wallet");
        wallet.sync_balances(4_200, 1_800).expect("sync");
        let report = wallet.status_report();
        assert!(report.contains("status_demo"));
        assert!(report.contains("20 (bucket 1, slot 4)"));
        assert!(report.contains("4200 VRNM"));
        assert!(report.contains("1800 VRNM"));
        assert!(report.contains("3 min"));
        assert!(report.contains("http://127.0.0.1:9090"));
    }
}
