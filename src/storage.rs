//! Crash-safe, tamper-evident on-disk persistence engine for Vernam (`VRNM`).
//!
//! Zero external crates, zero computational cryptography (no SHA-256, RSA, ECDSA, or AES).
//! Every snapshot, WAL header, WAL delta record, and integrity keyfile is authenticated
//! with a prefix-collision-free 128-bit Carter-Wegman MAC over the Mersenne prime field
//! `F_(2^127 - 1)` using `crate::field`, verified in constant time via `ct_eq_16`.
//!
//! # Rotating One-Time Carter-Wegman MAC Security
//! - Every snapshot save, WAL header write, and WAL record append consumes a **fresh,
//!   never-reused 128-bit additive pad `s_seq`** (`< PRIME_P`), indexed by
//!   `(domain, snapshot_epoch, seq)` in a crash-safe `0600` pad tape (`mac_pads.tape`)
//!   that is `fsync`ed BEFORE writing the authenticated record.
//! - Every snapshot compaction rotates the polynomial evaluation scalar `r` to a fresh
//!   non-zero scalar in `F_(2^127 - 1)`.
//! - Because NO two MAC tags ever reuse `(r, s)`, on-disk forgery resistance remains
//!   unconditionally bounded by `<= d / (2^127 - 1)` regardless of how many snapshots
//!   or WAL records an adversary observes.
//!
//! # Crash-Safety Guarantees
//! - All directory and file permissions are restricted to owner-only (`0700` dir, `0600` files) on Unix.
//! - Snapshots, keyfiles, and fresh WAL headers are written atomically via temp file ->
//!   `sync_all()` -> `rename()` -> parent-dir `fsync`.
//! - Each snapshot carries a strictly monotonic `snapshot_epoch`; companion WAL files are cryptographically
//!   bound to the active `snapshot_epoch` so a crash between snapshot rename and WAL reset safely discards
//!   the already-snapshotted stale WAL on recovery.
//! - WAL delta records are strictly sequenced (`0, 1, 2, ...`), protected by a framing guard and 128-bit
//!   Carter-Wegman MAC bound to `(wal_epoch, seq, payload_len, payload)`, and `sync_all()`ed before return.
//! - On recovery (`CrashSafeChainStore::open`), incomplete torn trailing WAL or pad-tape writes are zeroed
//!   on disk and truncated cleanly, whereas any mid-WAL corruption, bit-flip, or sequence reordering is rejected.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, mul_mod, random_field_elem, random_nonzero_field_elem, reduce,
    zeroize_slice, zeroize_u128,
};

/// Snapshot binary file magic header.
pub const SNAPSHOT_MAGIC: &[u8; 8] = b"VRNMDB01";

/// Current binary format version for `PersistedChainSnapshot` and snapshot envelopes.
pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;

/// Write-Ahead Log binary file magic header.
pub const WAL_MAGIC: &[u8; 8] = b"VRNMWL01";

/// Integrity keyfile binary magic header.
pub const KEYFILE_MAGIC: &[u8; 8] = b"VRNMKEY1";

/// Rotating CW-MAC one-time additive pad tape binary magic header.
pub const MAC_PADS_MAGIC: &[u8; 8] = b"VRNMMP01";

/// Carter-Wegman MAC tag length in bytes (128-bit big-endian canonical `F_(2^127 - 1)` element).
pub const MAC_TAG_BYTES: usize = 16;

/// Maximum number of rotating CW-MAC pad records permitted in a single pad tape.
pub const MAX_MAC_PAD_RECORDS: usize = 4_000_000;

/// Maximum number of recent events allowed in a snapshot.
pub const MAX_RECENT_EVENTS: usize = 64;

/// Maximum UTF-8 byte length of a single recent event string.
pub const MAX_EVENT_BYTES: usize = 512;

/// Maximum number of Express accounts in a single snapshot.
pub const MAX_EXPRESS_ACCOUNTS: usize = 1_000_000;

/// Maximum number of shielded slots in a snapshot or WAL delta.
pub const MAX_SHIELDED_SLOTS: usize = 1_000_000;

/// Maximum number of Shamir shares per shielded slot.
pub const MAX_SHARES_PER_SLOT: usize = 1_024;

/// Maximum number of validator vaults in a single snapshot.
pub const MAX_VALIDATORS: usize = 65_536;

/// Maximum snapshot body size in bytes (64 MiB).
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum WAL record payload size in bytes (4 MiB).
pub const MAX_WAL_RECORD_BYTES: usize = 4 * 1024 * 1024;

/// Maximum WAL records allowed before compaction is required.
pub const MAX_WAL_RECORDS: usize = 1_000_000;

// Domain separation tags for Carter-Wegman MAC evaluation.
const DOMAIN_KEYFILE: u32 = 0x5652_4B31; // "VRK1"
const DOMAIN_SNAPSHOT: u32 = 0x5652_5331; // "VRS1"
const DOMAIN_WAL_HEADER: u32 = 0x5652_5748; // "VRWH"
const DOMAIN_WAL_RECORD: u32 = 0x5652_5752; // "VRWR"

// Fixed binary layout sizes.
const KEYFILE_VERSION: u32 = 1;
const KEYFILE_LEN: usize = 8 + 4 + 16 + 16 + MAC_TAG_BYTES; // 60 bytes

const SNAPSHOT_ENVELOPE_HEADER_LEN: usize = 8 + 4 + 8 + 4; // 24 bytes
const SNAPSHOT_MIN_FILE_LEN: usize = SNAPSHOT_ENVELOPE_HEADER_LEN + MAC_TAG_BYTES; // 40 bytes

const WAL_VERSION: u32 = 1;
const WAL_HEADER_LEN: usize = 8 + 4 + 8 + MAC_TAG_BYTES; // 36 bytes
const WAL_RECORD_PREFIX_LEN: usize = 8 + 4 + 4; // seq(8) + payload_len(4) + header_guard(4) = 16 bytes
const WAL_RECORD_OVERHEAD: usize = WAL_RECORD_PREFIX_LEN + MAC_TAG_BYTES; // 32 bytes

// WAL event discriminant tags.
const WAL_TAG_EXPRESS_TRANSFER: u8 = 0x01;
const WAL_TAG_FAUCET_CREDIT: u8 = 0x02;
const WAL_TAG_SHIELDED_BUCKET_UPDATE: u8 = 0x03;
const WAL_TAG_EPOCH_SETTLED: u8 = 0x04;

// Filenames inside `data_dir`.
const KEY_FILENAME: &str = "integrity.key";
const MAC_PADS_FILENAME: &str = "mac_pads.tape";
const SNAPSHOT_FILENAME: &str = "chain.snap";
const WAL_FILENAME: &str = "chain.wal";

// Rotating CW-MAC pad tape layout constants.
const MAC_PADS_VERSION: u32 = 1;
const MAC_PADS_HEADER_GUARD: u32 = 0x5652_4D50; // "VRMP"
const MAC_PADS_HEADER_LEN: usize = 8 + 4 + 4; // magic(8) + version(4) + guard(4) = 16 bytes
const MAC_PADS_RECORD_LEN: usize = 8 + 4 + 8 + 8 + 16 + 16 + 8; // pad_id + domain + epoch + seq + r + s + guard = 68 bytes

static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Errors returned by crash-safe persistence operations.
#[derive(Debug)]
pub enum StorageError {
    /// Underlying filesystem I/O error.
    Io(io::Error),
    /// On-disk file magic header did not match the expected Vernam format identifier.
    CorruptMagic,
    /// Constant-time 128-bit Carter-Wegman MAC verification failed (tampering, bit-flip, or reorder).
    CorruptIntegrityMac,
    /// Structural or semantic binary format error.
    CorruptFormat(String),
    /// A Shamir share or field scalar was non-canonical (`>= PRIME_P = 2^127 - 1`).
    NonCanonicalFieldElement,
    /// File or record ended unexpectedly before its declared length.
    TruncatedRecord,
    /// Record, collection, or file exceeded configured safety limits.
    SizeLimitExceeded { actual: usize, max: usize },
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Io(err) => write!(f, "storage I/O error: {err}"),
            StorageError::CorruptMagic => write!(f, "corrupt storage magic header"),
            StorageError::CorruptIntegrityMac => {
                write!(f, "Carter-Wegman integrity MAC verification failed")
            }
            StorageError::CorruptFormat(msg) => write!(f, "corrupt storage format: {msg}"),
            StorageError::NonCanonicalFieldElement => {
                write!(f, "non-canonical F_(2^127 - 1) field element (>= PRIME_P)")
            }
            StorageError::TruncatedRecord => write!(f, "truncated storage record"),
            StorageError::SizeLimitExceeded { actual, max } => {
                write!(f, "storage size limit exceeded: {actual} > {max}")
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(err: io::Error) -> Self {
        StorageError::Io(err)
    }
}

/// Persistent Carter-Wegman MAC integrity key `(r, s)` in `F_(2^127 - 1)`.
///
/// Enforces `0 < r < PRIME_P` and `s < PRIME_P`, redacts secret scalars in `Debug`,
/// and volatile-zeroizes both scalars on `Drop`.
pub struct StorageIntegrityKey {
    r: u128,
    s: u128,
}

impl StorageIntegrityKey {
    /// Generate a fresh integrity key using OS randomness (`/dev/urandom`) via rejection sampling.
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

    /// Construct a `StorageIntegrityKey` from explicit canonical field scalars.
    ///
    /// Rejects `r >= PRIME_P` or `s >= PRIME_P` with `NonCanonicalFieldElement`,
    /// and rejects `r == 0` with `CorruptFormat`.
    pub fn from_parts(r: u128, s: u128) -> Result<Self, StorageError> {
        if r >= PRIME_P || s >= PRIME_P {
            return Err(StorageError::NonCanonicalFieldElement);
        }
        if r == 0 {
            return Err(StorageError::CorruptFormat(
                "integrity key evaluation scalar r must be non-zero".into(),
            ));
        }
        Ok(Self { r, s })
    }

    /// Load an existing `0600` integrity keyfile or atomically create a new one if absent.
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if path.exists() {
            Self::load(path)
        } else {
            let key = Self::generate();
            key.save_atomic(path)?;
            Ok(key)
        }
    }

    /// Load and verify an existing integrity keyfile from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let mut raw = ZeroizeVec(fs::read(path.as_ref())?);
        if raw.0.len() >= 8 && &raw.0[0..8] != KEYFILE_MAGIC {
            return Err(StorageError::CorruptMagic);
        }
        if raw.0.len() < KEYFILE_LEN {
            return Err(StorageError::TruncatedRecord);
        }
        if raw.0.len() > KEYFILE_LEN {
            return Err(StorageError::CorruptFormat(format!(
                "unexpected keyfile length {} (expected {KEYFILE_LEN})",
                raw.0.len()
            )));
        }

        let version = u32::from_be_bytes([raw.0[8], raw.0[9], raw.0[10], raw.0[11]]);
        if version != KEYFILE_VERSION {
            return Err(StorageError::CorruptFormat(format!(
                "unsupported keyfile version {version}"
            )));
        }

        let r = u128::from_be_bytes(raw.0[12..28].try_into().unwrap());
        let s = u128::from_be_bytes(raw.0[28..44].try_into().unwrap());
        let stored_tag: [u8; MAC_TAG_BYTES] = raw.0[44..60].try_into().unwrap();

        let key = Self::from_parts(r, s)?;
        if !key.verify_mac(DOMAIN_KEYFILE, version as u64, &raw.0[0..12], &stored_tag) {
            return Err(StorageError::CorruptIntegrityMac);
        }
        zeroize_slice(&mut raw.0);
        Ok(key)
    }

    /// Atomically persist this keyfile with `0600` permissions via temp + `fsync` + `rename` + parent-dir `fsync`.
    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<(), StorageError> {
        let path = path.as_ref();
        let mut buf = ZeroizeVec(Vec::with_capacity(KEYFILE_LEN));
        buf.0.extend_from_slice(KEYFILE_MAGIC);
        buf.0.extend_from_slice(&KEYFILE_VERSION.to_be_bytes());
        buf.0.extend_from_slice(&self.r.to_be_bytes());
        buf.0.extend_from_slice(&self.s.to_be_bytes());
        let mut tag = self.compute_mac(DOMAIN_KEYFILE, KEYFILE_VERSION as u64, &buf.0[0..12]);
        buf.0.extend_from_slice(&tag);
        zeroize_slice(&mut tag);

        write_file_atomic_0600(path, &buf.0)?;
        Ok(())
    }

    /// Compute a prefix-collision-free 128-bit Carter-Wegman MAC over `F_(2^127 - 1)`.
    ///
    /// # Construction
    /// - Encodes a non-zero domain + context header block `(1 << 120) | (domain << 64) | context`
    ///   (Wait: since `domain` is `u32` and `context` is `u64`, `(1 << 120)` cannot collide with bits `0..96`).
    /// - Splits `data` into 15-byte chunks (120 bits each); each chunk `c` of length `L in 1..=15`
    ///   is encoded little-endian with a `0x01` sentinel byte at offset `L`, yielding `block < 2^121 < PRIME_P`.
    /// - Appends a final length block `(1 << 120) | (data.len() as u128)` so messages of differing
    ///   lengths or prefixes map to strictly distinct polynomials over `F_(2^127 - 1)`.
    /// - Evaluates `acc = ((acc + block) * r) mod PRIME_P` at every step (ensuring multiplicative
    ///   dependence on `r` even for empty data), then masks with `(acc + s) mod PRIME_P`.
    #[inline]
    pub fn compute_mac(&self, domain: u32, context: u64, data: &[u8]) -> [u8; MAC_TAG_BYTES] {
        compute_cw_mac_raw(self.r, self.s, domain, context, data)
    }

    /// Verify a 128-bit Carter-Wegman MAC in constant time using `ct_eq_16`.
    #[inline]
    pub fn verify_mac(
        &self,
        domain: u32,
        context: u64,
        data: &[u8],
        tag: &[u8; MAC_TAG_BYTES],
    ) -> bool {
        verify_cw_mac_raw(self.r, self.s, domain, context, data, tag)
    }

    /// Immediately wipe both secret scalars in RAM using volatile writes.
    #[inline]
    pub fn zeroize(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

impl Drop for StorageIntegrityKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for StorageIntegrityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageIntegrityKey")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

/// Pure prefix-collision-free 128-bit Carter-Wegman MAC over `F_(2^127 - 1)` for a specific `(r, s)`.
#[inline]
fn compute_cw_mac_raw(
    r: u128,
    s: u128,
    domain: u32,
    context: u64,
    data: &[u8],
) -> [u8; MAC_TAG_BYTES] {
    let r = reduce(r);
    let s = reduce(s);

    let mut acc: u128 = 0;

    // Header block binding domain tag and 64-bit context (snapshot epoch or WAL epoch).
    let hdr_block: u128 = (1u128 << 120) | ((domain as u128) << 64) | (context as u128);
    acc = mul_mod(add_mod(acc, hdr_block), r);

    // Injective 15-byte chunking with trailing 0x01 sentinel per chunk.
    let mut buf = [0u8; 16];
    for chunk in data.chunks(15) {
        buf = [0u8; 16];
        buf[..chunk.len()].copy_from_slice(chunk);
        buf[chunk.len()] = 0x01;
        let block = u128::from_le_bytes(buf);
        acc = mul_mod(add_mod(acc, block), r);
    }
    zeroize_slice(&mut buf);

    // Explicit length trailer prevents prefix/extension collisions across all byte lengths.
    let len_block: u128 = (1u128 << 120) | (data.len() as u64 as u128);
    acc = mul_mod(add_mod(acc, len_block), r);

    let tag_val = add_mod(acc, s);
    zeroize_u128(&mut acc);
    debug_assert!(tag_val < PRIME_P);
    tag_val.to_be_bytes()
}

/// Constant-time Carter-Wegman MAC verification for a specific `(r, s)` using `ct_eq_16`.
#[inline]
fn verify_cw_mac_raw(
    r: u128,
    s: u128,
    domain: u32,
    context: u64,
    data: &[u8],
    tag: &[u8; MAC_TAG_BYTES],
) -> bool {
    let mut expected = compute_cw_mac_raw(r, s, domain, context, data);
    let ok = ct_eq_16(&expected, tag);
    zeroize_slice(&mut expected);
    ok
}

/// Deterministic 64-bit framing guard for `mac_pads.tape` records (torn-write / corruption detection).
#[inline]
fn compute_pad_record_guard(
    pad_id: u64,
    domain: u32,
    epoch: u64,
    seq: u64,
    r: u128,
    s: u128,
) -> u64 {
    let mut h: u64 = 0x5652_4E4D_5041_4431;
    for word in [
        pad_id,
        ((domain as u64) << 32) ^ (domain as u64).rotate_left(13),
        epoch,
        seq,
        r as u64,
        (r >> 64) as u64,
        s as u64,
        (s >> 64) as u64,
    ] {
        h = h.rotate_left(17) ^ word.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    h ^ 0xA55A_C33C_5A5A_3C3C
}

/// Rotating one-time-pad Carter-Wegman MAC key manager backed by a crash-safe `0600` pad tape
/// (`mac_pads.tape`).
///
/// Guarantees:
/// - Every snapshot save, WAL header write, and WAL record append allocates a fresh, never-reused
///   128-bit additive pad `s_seq < PRIME_P` indexed by `(domain, snapshot_epoch, seq)`.
/// - Every allocated pad is appended and `fsync`ed to `mac_pads.tape` BEFORE the authenticated
///   snapshot or WAL record is written.
/// - Every snapshot compaction rotates the polynomial evaluation scalar `r` to a fresh non-zero
///   element of `F_(2^127 - 1)`.
/// - All secret scalars are volatile-zeroized on `Drop` and redacted in `Debug`.
pub struct RotatingCwStorageKey {
    tape_path: PathBuf,
    tape_file: File,
    current_epoch: u64,
    current_r: u128,
    next_pad_id: u64,
    epoch_r: HashMap<u64, u128>,
    active_pads: HashMap<(u32, u64, u64), (u128, u128)>,
    used_s: HashSet<u128>,
}

impl RotatingCwStorageKey {
    /// Open an existing `0600` `mac_pads.tape` in `data_dir` or atomically initialize a fresh one.
    pub fn open_or_create(data_dir: impl AsRef<Path>, initial_r: u128) -> Result<Self, StorageError> {
        if initial_r >= PRIME_P {
            return Err(StorageError::NonCanonicalFieldElement);
        }
        if initial_r == 0 {
            return Err(StorageError::CorruptFormat(
                "rotating CW-MAC initial evaluation scalar r must be non-zero".into(),
            ));
        }

        let tape_path = data_dir.as_ref().join(MAC_PADS_FILENAME);
        let mut epoch_r: HashMap<u64, u128> = HashMap::new();
        let mut active_pads: HashMap<(u32, u64, u64), (u128, u128)> = HashMap::new();
        let mut used_s: HashSet<u128> = HashSet::new();

        if !tape_path.exists() {
            let mut hdr = [0u8; MAC_PADS_HEADER_LEN];
            hdr[0..8].copy_from_slice(MAC_PADS_MAGIC);
            hdr[8..12].copy_from_slice(&MAC_PADS_VERSION.to_be_bytes());
            hdr[12..16].copy_from_slice(&MAC_PADS_HEADER_GUARD.to_be_bytes());
            write_file_atomic_0600(&tape_path, &hdr)?;

            let mut tape_file = open_secret_file(&tape_path, false)?;
            tape_file.seek(SeekFrom::End(0))?;
            epoch_r.insert(0, initial_r);
            return Ok(Self {
                tape_path,
                tape_file,
                current_epoch: 0,
                current_r: initial_r,
                next_pad_id: 0,
                epoch_r,
                active_pads,
                used_s,
            });
        }

        let mut tape_file = open_secret_file(&tape_path, false)?;
        let file_len = tape_file.metadata()?.len();
        if file_len < MAC_PADS_HEADER_LEN as u64 {
            let mut partial = vec![0u8; file_len as usize];
            tape_file.seek(SeekFrom::Start(0))?;
            tape_file.read_exact(&mut partial)?;
            if partial.len() >= 8 && &partial[0..8] != MAC_PADS_MAGIC {
                return Err(StorageError::CorruptMagic);
            }
            return Err(StorageError::TruncatedRecord);
        }

        let mut hdr = [0u8; MAC_PADS_HEADER_LEN];
        tape_file.seek(SeekFrom::Start(0))?;
        tape_file.read_exact(&mut hdr)?;
        if &hdr[0..8] != MAC_PADS_MAGIC {
            return Err(StorageError::CorruptMagic);
        }
        let version = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        if version != MAC_PADS_VERSION {
            return Err(StorageError::CorruptFormat(format!(
                "unsupported mac_pads.tape version {version}"
            )));
        }
        let hdr_guard = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
        if hdr_guard != MAC_PADS_HEADER_GUARD {
            return Err(StorageError::CorruptFormat(
                "corrupt mac_pads.tape header guard".into(),
            ));
        }

        let mut offset = MAC_PADS_HEADER_LEN as u64;
        let mut expected_pad_id: u64 = 0;
        let mut current_epoch: u64 = 0;
        let mut current_r: u128 = initial_r;
        let mut torn_tail_offset: Option<u64> = None;
        let mut rec = [0u8; MAC_PADS_RECORD_LEN];

        while offset < file_len {
            let rem = file_len - offset;
            if rem < MAC_PADS_RECORD_LEN as u64 {
                // Incomplete trailing pad record from a crash prior to fsync.
                torn_tail_offset = Some(offset);
                break;
            }
            tape_file.seek(SeekFrom::Start(offset))?;
            tape_file.read_exact(&mut rec)?;

            if rec.iter().all(|&b| b == 0) && is_all_zero_tail(&mut tape_file, offset, file_len)? {
                torn_tail_offset = Some(offset);
                break;
            }

            let pad_id = u64::from_be_bytes(rec[0..8].try_into().unwrap());
            let domain = u32::from_be_bytes(rec[8..12].try_into().unwrap());
            let epoch = u64::from_be_bytes(rec[12..20].try_into().unwrap());
            let seq = u64::from_be_bytes(rec[20..28].try_into().unwrap());
            let r = u128::from_be_bytes(rec[28..44].try_into().unwrap());
            let s = u128::from_be_bytes(rec[44..60].try_into().unwrap());
            let stored_guard = u64::from_be_bytes(rec[60..68].try_into().unwrap());
            zeroize_slice(&mut rec);

            if pad_id != expected_pad_id {
                return Err(StorageError::CorruptFormat(format!(
                    "mac_pads.tape pad_id mismatch: got {pad_id}, expected {expected_pad_id}"
                )));
            }
            if stored_guard != compute_pad_record_guard(pad_id, domain, epoch, seq, r, s) {
                return Err(StorageError::CorruptFormat(format!(
                    "mac_pads.tape record {pad_id} failed integrity guard"
                )));
            }
            if r >= PRIME_P || s >= PRIME_P {
                return Err(StorageError::NonCanonicalFieldElement);
            }
            if r == 0 {
                return Err(StorageError::CorruptFormat(format!(
                    "mac_pads.tape record {pad_id} has zero evaluation scalar r"
                )));
            }

            epoch_r.insert(epoch, r);
            active_pads.insert((domain, epoch, seq), (r, s));
            used_s.insert(s);
            if epoch >= current_epoch {
                current_epoch = epoch;
                current_r = r;
            }

            offset += MAC_PADS_RECORD_LEN as u64;
            expected_pad_id = expected_pad_id
                .checked_add(1)
                .ok_or_else(|| StorageError::CorruptFormat("pad_id overflow".into()))?;
            if (expected_pad_id as usize) > MAX_MAC_PAD_RECORDS {
                return Err(StorageError::SizeLimitExceeded {
                    actual: expected_pad_id as usize,
                    max: MAX_MAC_PAD_RECORDS,
                });
            }
        }
        zeroize_slice(&mut rec);

        if let Some(valid_end) = torn_tail_offset {
            zero_and_truncate_tail(&mut tape_file, valid_end, file_len)?;
        }

        if epoch_r.is_empty() {
            epoch_r.insert(0, initial_r);
        }

        tape_file.seek(SeekFrom::End(0))?;
        Ok(Self {
            tape_path,
            tape_file,
            current_epoch,
            current_r,
            next_pad_id: expected_pad_id,
            epoch_r,
            active_pads,
            used_s,
        })
    }

    /// Path to the `0600` pad tape file (`mac_pads.tape`).
    #[inline]
    pub fn tape_path(&self) -> &Path {
        &self.tape_path
    }

    /// Total number of one-time additive pads allocated and persisted so far.
    #[inline]
    pub fn allocated_pad_count(&self) -> u64 {
        self.next_pad_id
    }

    /// Current highest snapshot epoch tracked by this key manager.
    #[inline]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Rotate the polynomial evaluation key `r` to a fresh non-zero element of `F_(2^127 - 1)`
    /// for `new_epoch` (called on every snapshot save / compaction).
    pub fn rotate_epoch_r(&mut self, new_epoch: u64) {
        let fresh_r = loop {
            let candidate = random_nonzero_field_elem();
            if candidate != self.current_r && !self.epoch_r.values().any(|&old| old == candidate) {
                break candidate;
            }
        };
        self.epoch_r.insert(new_epoch, fresh_r);
        self.current_epoch = new_epoch;
        self.current_r = fresh_r;
    }

    /// Allocate a fresh, never-reused 128-bit additive pad `s_seq < PRIME_P` for
    /// `(domain, epoch, seq)`, persist and `fsync` it to `mac_pads.tape` BEFORE returning,
    /// and compute the 128-bit Carter-Wegman MAC over `(domain, context, data)`.
    pub fn allocate_and_compute_mac(
        &mut self,
        domain: u32,
        epoch: u64,
        seq: u64,
        context: u64,
        data: &[u8],
    ) -> Result<[u8; MAC_TAG_BYTES], StorageError> {
        if (self.next_pad_id as usize) >= MAX_MAC_PAD_RECORDS {
            return Err(StorageError::SizeLimitExceeded {
                actual: (self.next_pad_id as usize).saturating_add(1),
                max: MAX_MAC_PAD_RECORDS,
            });
        }

        let r = *self.epoch_r.get(&epoch).unwrap_or(&self.current_r);
        debug_assert!(r > 0 && r < PRIME_P);

        // Rejection-sample a strictly fresh canonical 128-bit additive pad `s < PRIME_P`.
        let s = loop {
            let candidate = random_field_elem();
            if !self.used_s.contains(&candidate) {
                break candidate;
            }
        };

        let pad_id = self.next_pad_id;
        let guard = compute_pad_record_guard(pad_id, domain, epoch, seq, r, s);

        let mut rec = [0u8; MAC_PADS_RECORD_LEN];
        rec[0..8].copy_from_slice(&pad_id.to_be_bytes());
        rec[8..12].copy_from_slice(&domain.to_be_bytes());
        rec[12..20].copy_from_slice(&epoch.to_be_bytes());
        rec[20..28].copy_from_slice(&seq.to_be_bytes());
        rec[28..44].copy_from_slice(&r.to_be_bytes());
        rec[44..60].copy_from_slice(&s.to_be_bytes());
        rec[60..68].copy_from_slice(&guard.to_be_bytes());

        let prior_len = self.tape_file.seek(SeekFrom::End(0))?;
        let write_res = (|| -> io::Result<()> {
            self.tape_file.write_all(&rec)?;
            self.tape_file.sync_all()?;
            Ok(())
        })();
        zeroize_slice(&mut rec);

        if let Err(err) = write_res {
            let _ = self.tape_file.set_len(prior_len);
            let _ = self.tape_file.sync_all();
            return Err(err.into());
        }

        self.epoch_r.insert(epoch, r);
        self.active_pads.insert((domain, epoch, seq), (r, s));
        self.used_s.insert(s);
        self.next_pad_id += 1;

        Ok(compute_cw_mac_raw(r, s, domain, context, data))
    }

    /// Verify a 128-bit Carter-Wegman MAC in constant time (`ct_eq_16`) using the dedicated
    /// one-time additive pad indexed by `(domain, epoch, seq)`.
    #[inline]
    pub fn verify_mac(
        &self,
        domain: u32,
        epoch: u64,
        seq: u64,
        context: u64,
        data: &[u8],
        tag: &[u8; MAC_TAG_BYTES],
    ) -> bool {
        let Some(&(r, s)) = self.active_pads.get(&(domain, epoch, seq)) else {
            return false;
        };
        verify_cw_mac_raw(r, s, domain, context, data, tag)
    }

    /// Immediately volatile-zeroize all secret scalars held in RAM.
    pub fn zeroize(&mut self) {
        zeroize_u128(&mut self.current_r);
        for r in self.epoch_r.values_mut() {
            zeroize_u128(r);
        }
        self.epoch_r.clear();
        for (r, s) in self.active_pads.values_mut() {
            zeroize_u128(r);
            zeroize_u128(s);
        }
        self.active_pads.clear();
        self.used_s.clear();
    }

    #[cfg(test)]
    fn active_pad(&self, domain: u32, epoch: u64, seq: u64) -> Option<(u128, u128)> {
        self.active_pads.get(&(domain, epoch, seq)).copied()
    }

    #[cfg(test)]
    fn read_all_tape_records(
        tape_path: &Path,
    ) -> Result<Vec<(u64, u32, u64, u64, u128, u128)>, StorageError> {
        let raw = fs::read(tape_path)?;
        if raw.len() < MAC_PADS_HEADER_LEN {
            return Err(StorageError::TruncatedRecord);
        }
        let mut out = Vec::new();
        let mut pos = MAC_PADS_HEADER_LEN;
        while pos + MAC_PADS_RECORD_LEN <= raw.len() {
            let rec = &raw[pos..pos + MAC_PADS_RECORD_LEN];
            let pad_id = u64::from_be_bytes(rec[0..8].try_into().unwrap());
            let domain = u32::from_be_bytes(rec[8..12].try_into().unwrap());
            let epoch = u64::from_be_bytes(rec[12..20].try_into().unwrap());
            let seq = u64::from_be_bytes(rec[20..28].try_into().unwrap());
            let r = u128::from_be_bytes(rec[28..44].try_into().unwrap());
            let s = u128::from_be_bytes(rec[44..60].try_into().unwrap());
            out.push((pad_id, domain, epoch, seq, r, s));
            pos += MAC_PADS_RECORD_LEN;
        }
        Ok(out)
    }
}

impl Drop for RotatingCwStorageKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for RotatingCwStorageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatingCwStorageKey")
            .field("tape_path", &self.tape_path)
            .field("current_epoch", &self.current_epoch)
            .field("allocated_pads", &self.next_pad_id)
            .field("current_r", &"[REDACTED]")
            .field("active_pads", &"[REDACTED]")
            .finish()
    }
}

/// Persisted Express-lane account balance and replay-protection nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedExpressAccount {
    pub account_id: u32,
    pub balance: u64,
    pub nonce: u64,
}

/// Persisted Shamir-shared shielded slot in `F_(2^127 - 1)`.
///
/// Every element in `shares` MUST satisfy `share < PRIME_P`; non-canonical elements are
/// rejected on both encode and decode with `StorageError::NonCanonicalFieldElement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedShieldedSlot {
    pub bucket_id: u32,
    pub slot_id: u32,
    pub shares: Vec<u128>,
}

/// Persisted validator vault state for PoP / BFT quorum tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedValidatorVault {
    pub validator_id: u64,
    pub bond: u64,
    pub reward_balance: u64,
    pub status_code: u8,
    pub missed_epochs: u64,
}

/// Full point-in-time chain state snapshot persisted atomically in `chain.snap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedChainSnapshot {
    pub version: u32,
    pub blocks_finalized: u64,
    pub express_txs: u64,
    pub shielded_txs: u64,
    pub pss_epoch: u64,
    pub tokenomics_epoch: u64,
    pub circulating_supply: u64,
    pub total_burned: u64,
    pub total_fees_collected: u64,
    pub next_page_id: u64,
    pub last_qber_bits: u64,
    pub express_accounts: Vec<PersistedExpressAccount>,
    pub shielded_slots: Vec<PersistedShieldedSlot>,
    pub validators: Vec<PersistedValidatorVault>,
    pub recent_events: Vec<String>,
}

impl Default for PersistedChainSnapshot {
    fn default() -> Self {
        Self {
            version: SNAPSHOT_FORMAT_VERSION,
            blocks_finalized: 0,
            express_txs: 0,
            shielded_txs: 0,
            pss_epoch: 0,
            tokenomics_epoch: 0,
            circulating_supply: 0,
            total_burned: 0,
            total_fees_collected: 0,
            next_page_id: 0,
            last_qber_bits: 0,
            express_accounts: Vec::new(),
            shielded_slots: Vec::new(),
            validators: Vec::new(),
            recent_events: Vec::new(),
        }
    }
}

/// Incremental append-only WAL delta event logged between full snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalDeltaEvent {
    ExpressTransfer {
        sender: u32,
        recipient: u32,
        amount: u64,
        sender_nonce: u64,
        block_height: u64,
        next_page_id: u64,
        fee_burned: u64,
    },
    FaucetCredit {
        account_id: u32,
        express_amount: u64,
        shielded_amount: u64,
        block_height: Option<u64>,
        next_page_id: u64,
    },
    ShieldedBucketUpdate {
        bucket_id: u32,
        pss_epoch: u64,
        slots: Vec<PersistedShieldedSlot>,
        fee_burned: u64,
    },
    EpochSettled {
        tokenomics_epoch: u64,
        pss_epoch: u64,
        subsidy_minted: u64,
        total_burned: u64,
        circulating_supply: u64,
        last_qber_bits: u64,
    },
}

/// Crash-safe, rotating-CW-MAC-authenticated chain storage engine backed by an atomic
/// snapshot file (`chain.snap`), a sequenced append-only WAL (`chain.wal`), and a crash-safe
/// one-time additive pad tape (`mac_pads.tape`).
pub struct CrashSafeChainStore {
    data_dir: PathBuf,
    key_path: PathBuf,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
    key: StorageIntegrityKey,
    rotating_key: RotatingCwStorageKey,
    wal_file: File,
    snapshot_epoch: u64,
    next_wal_seq: u64,
}

impl CrashSafeChainStore {
    /// Open or initialize a crash-safe chain store in `data_dir`.
    ///
    /// - Creates `data_dir` with `0700` permissions on Unix.
    /// - Loads or atomically creates the `0600` `StorageIntegrityKey` and `0600` `mac_pads.tape`.
    /// - Verifies any existing snapshot (`chain.snap`) and companion WAL (`chain.wal`) against
    ///   their dedicated one-time CW-MAC additive pads.
    /// - Safely zeroes and truncates an incomplete torn trailing WAL record while rejecting
    ///   any mid-WAL corruption, bit-flip, or sequence reordering.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, StorageError> {
        let data_dir = data_dir.as_ref().to_path_buf();
        ensure_secret_dir(&data_dir)?;

        let key_path = data_dir.join(KEY_FILENAME);
        let snapshot_path = data_dir.join(SNAPSHOT_FILENAME);
        let wal_path = data_dir.join(WAL_FILENAME);

        let key = StorageIntegrityKey::load_or_create(&key_path)?;
        let mut rotating_key = RotatingCwStorageKey::open_or_create(&data_dir, key.r)?;

        // Verify latest snapshot if present to establish the authoritative snapshot_epoch.
        let snapshot_epoch = if snapshot_path.exists() {
            let (epoch, _snap) = read_and_verify_snapshot(&snapshot_path, &rotating_key)?;
            epoch
        } else {
            0
        };

        // Recover or initialize companion WAL.
        let (wal_file, next_wal_seq) = if wal_path.exists() {
            recover_wal(&wal_path, &mut rotating_key, snapshot_epoch)?
        } else {
            let f = create_fresh_wal_atomic(&wal_path, &mut rotating_key, snapshot_epoch)?;
            (f, 0)
        };

        Ok(Self {
            data_dir,
            key_path,
            snapshot_path,
            wal_path,
            key,
            rotating_key,
            wal_file,
            snapshot_epoch,
            next_wal_seq,
        })
    }

    /// Directory containing the store's key, pad tape, snapshot, and WAL files.
    #[inline]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Path to the `0600` integrity keyfile.
    #[inline]
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Path to the `0600` rotating CW-MAC additive pad tape (`mac_pads.tape`).
    #[inline]
    pub fn pad_tape_path(&self) -> &Path {
        self.rotating_key.tape_path()
    }

    /// Path to the atomic snapshot file (`chain.snap`).
    #[inline]
    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    /// Path to the append-only WAL file (`chain.wal`).
    #[inline]
    pub fn wal_path(&self) -> &Path {
        &self.wal_path
    }

    /// Current monotonic snapshot epoch (`0` before the first snapshot is saved).
    #[inline]
    pub fn snapshot_epoch(&self) -> u64 {
        self.snapshot_epoch
    }

    /// Number of WAL delta records currently committed since the latest snapshot.
    #[inline]
    pub fn wal_record_count(&self) -> u64 {
        self.next_wal_seq
    }

    /// Total number of distinct one-time CW-MAC additive pads allocated across this store's lifetime.
    #[inline]
    pub fn mac_pad_count(&self) -> u64 {
        self.rotating_key.allocated_pad_count()
    }

    /// Atomically persist a full chain snapshot and reset the companion WAL.
    ///
    /// Order of durability operations:
    /// 1. Validate & serialize `snapshot`, rotate evaluation key `r` for `new_epoch = snapshot_epoch + 1`,
    ///    and persist + `fsync` a fresh one-time additive pad `s` in `mac_pads.tape`.
    /// 2. Compute 128-bit CW-MAC and write temp snapshot (`0600`) -> `sync_all()` -> atomic `rename()`
    ///    -> parent-dir `fsync`.
    /// 3. Persist + `fsync` a fresh one-time additive pad `s` for the new WAL header in `mac_pads.tape`,
    ///    then write fresh temp WAL bound to `new_epoch` (`0600`) -> `sync_all()` -> atomic `rename()`
    ///    -> parent-dir `fsync`.
    ///
    /// If power is lost between step 2 and step 3, recovery detects `wal_epoch < snapshot_epoch`
    /// and cleanly discards the stale pre-snapshot WAL.
    pub fn save_snapshot(&mut self, snapshot: &PersistedChainSnapshot) -> Result<(), StorageError> {
        let body = encode_snapshot_body(snapshot)?;
        if body.len() > MAX_SNAPSHOT_BYTES {
            return Err(StorageError::SizeLimitExceeded {
                actual: body.len(),
                max: MAX_SNAPSHOT_BYTES,
            });
        }

        let new_epoch = self
            .snapshot_epoch
            .checked_add(1)
            .ok_or_else(|| StorageError::CorruptFormat("snapshot_epoch overflow".into()))?;

        let total_len = SNAPSHOT_ENVELOPE_HEADER_LEN + body.len() + MAC_TAG_BYTES;
        let mut frame = Vec::with_capacity(total_len);
        frame.extend_from_slice(SNAPSHOT_MAGIC);
        frame.extend_from_slice(&SNAPSHOT_FORMAT_VERSION.to_be_bytes());
        frame.extend_from_slice(&new_epoch.to_be_bytes());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);

        // Rotate `r` on every snapshot/compaction and consume a fresh one-time additive pad `s`.
        self.rotating_key.rotate_epoch_r(new_epoch);
        let tag = self.rotating_key.allocate_and_compute_mac(
            DOMAIN_SNAPSHOT,
            new_epoch,
            0,
            new_epoch,
            &frame,
        )?;
        frame.extend_from_slice(&tag);

        write_file_atomic_0600(&self.snapshot_path, &frame)?;
        self.snapshot_epoch = new_epoch;

        let new_wal_file =
            create_fresh_wal_atomic(&self.wal_path, &mut self.rotating_key, new_epoch)?;
        self.wal_file = new_wal_file;
        self.next_wal_seq = 0;

        Ok(())
    }

    /// Append a sequenced, rotating-CW-MAC-authenticated delta event to `chain.wal`
    /// (`fsync`ing the fresh one-time additive pad in `mac_pads.tape` BEFORE writing the WAL record)
    /// and `sync_all()` before returning.
    pub fn append_wal(&mut self, event: &WalDeltaEvent) -> Result<(), StorageError> {
        if self.next_wal_seq >= MAX_WAL_RECORDS as u64 {
            return Err(StorageError::SizeLimitExceeded {
                actual: (self.next_wal_seq as usize).saturating_add(1),
                max: MAX_WAL_RECORDS,
            });
        }

        let payload = encode_wal_event(event)?;
        if payload.is_empty() {
            return Err(StorageError::CorruptFormat(
                "WAL event encoded to empty payload".into(),
            ));
        }
        if payload.len() > MAX_WAL_RECORD_BYTES {
            return Err(StorageError::SizeLimitExceeded {
                actual: payload.len(),
                max: MAX_WAL_RECORD_BYTES,
            });
        }

        let seq = self.next_wal_seq;
        let payload_len = payload.len() as u32;
        let guard = compute_wal_header_guard(seq, payload_len);

        let mut rec = Vec::with_capacity(WAL_RECORD_OVERHEAD + payload.len());
        rec.extend_from_slice(&seq.to_be_bytes());
        rec.extend_from_slice(&payload_len.to_be_bytes());
        rec.extend_from_slice(&guard.to_be_bytes());
        rec.extend_from_slice(&payload);

        let tag = allocate_wal_record_mac(
            &mut self.rotating_key,
            self.snapshot_epoch,
            seq,
            payload_len,
            &payload,
        )?;
        rec.extend_from_slice(&tag);

        let prior_len = self.wal_file.seek(SeekFrom::End(0))?;
        let write_res = (|| -> io::Result<()> {
            self.wal_file.write_all(&rec)?;
            self.wal_file.sync_all()?;
            Ok(())
        })();

        if let Err(err) = write_res {
            let _ = self.wal_file.set_len(prior_len);
            let _ = self.wal_file.sync_all();
            return Err(err.into());
        }

        self.next_wal_seq += 1;
        Ok(())
    }

    /// Load and strictly verify the latest snapshot and all subsequent WAL delta events from disk.
    ///
    /// Verifies the 128-bit rotating Carter-Wegman MAC in constant time (`ct_eq_16`) on the snapshot,
    /// WAL header, and every WAL record, rejecting any tampered bytes, sequence gaps, or
    /// reordered records.
    pub fn load_latest(
        &self,
    ) -> Result<(Option<PersistedChainSnapshot>, Vec<WalDeltaEvent>), StorageError> {
        let (snapshot, expected_epoch) = if self.snapshot_path.exists() {
            let (epoch, snap) = read_and_verify_snapshot(&self.snapshot_path, &self.rotating_key)?;
            (Some(snap), epoch)
        } else {
            (None, 0)
        };

        let events = if self.wal_path.exists() {
            read_and_verify_wal_strict(&self.wal_path, &self.rotating_key, expected_epoch)?
        } else {
            Vec::new()
        };

        Ok((snapshot, events))
    }

    /// Compact the WAL into a fresh atomic snapshot if the pending WAL record count has reached
    /// `max_wal_records` (and at least one WAL record is pending).
    ///
    /// Returns `Ok(true)` if compaction was performed, or `Ok(false)` otherwise.
    pub fn compact_if_needed(
        &mut self,
        snapshot: &PersistedChainSnapshot,
        max_wal_records: usize,
    ) -> Result<bool, StorageError> {
        if self.next_wal_seq > 0 && (self.next_wal_seq as usize) >= max_wal_records {
            self.save_snapshot(snapshot)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl fmt::Debug for CrashSafeChainStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrashSafeChainStore")
            .field("data_dir", &self.data_dir)
            .field("snapshot_epoch", &self.snapshot_epoch)
            .field("next_wal_seq", &self.next_wal_seq)
            .field("key", &self.key)
            .field("rotating_key", &self.rotating_key)
            .finish()
    }
}

// =============================================================================
// Internal Serialization & Verification Helpers
// =============================================================================

struct ZeroizeVec(Vec<u8>);

impl Drop for ZeroizeVec {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    #[inline]
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    #[inline]
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], StorageError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(StorageError::TruncatedRecord)?;
        if end > self.buf.len() {
            return Err(StorageError::TruncatedRecord);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8, StorageError> {
        Ok(self.read_bytes(1)?[0])
    }

    #[inline]
    fn read_u32(&mut self) -> Result<u32, StorageError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    fn read_u64(&mut self) -> Result<u64, StorageError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    #[inline]
    fn read_u128(&mut self) -> Result<u128, StorageError> {
        let b = self.read_bytes(16)?;
        Ok(u128::from_be_bytes(b.try_into().unwrap()))
    }

    #[inline]
    fn finish(self) -> Result<(), StorageError> {
        if self.remaining() != 0 {
            return Err(StorageError::CorruptFormat(format!(
                "{} unexpected trailing bytes",
                self.remaining()
            )));
        }
        Ok(())
    }
}

/// Deterministic 32-bit framing guard distinguishing bit-flipped WAL record headers
/// from legitimately truncated torn writes at EOF. Cryptographic authenticity is still
/// provided solely by the 128-bit Carter-Wegman MAC.
#[inline]
fn compute_wal_header_guard(seq: u64, payload_len: u32) -> u32 {
    (!payload_len) ^ (seq as u32) ^ ((seq >> 32) as u32) ^ 0xA55A_C33C
}

/// Allocate a fresh one-time additive pad in `mac_pads.tape` (`fsync`ed) and compute the
/// 128-bit rotating Carter-Wegman MAC for a WAL record bound to `(wal_epoch, seq, payload_len, payload)`.
fn allocate_wal_record_mac(
    key: &mut RotatingCwStorageKey,
    wal_epoch: u64,
    seq: u64,
    payload_len: u32,
    payload: &[u8],
) -> Result<[u8; MAC_TAG_BYTES], StorageError> {
    let mut mac_input = Vec::with_capacity(8 + 4 + payload.len());
    mac_input.extend_from_slice(&seq.to_be_bytes());
    mac_input.extend_from_slice(&payload_len.to_be_bytes());
    mac_input.extend_from_slice(payload);
    key.allocate_and_compute_mac(DOMAIN_WAL_RECORD, wal_epoch, seq, wal_epoch, &mac_input)
}

fn verify_wal_record_mac(
    key: &RotatingCwStorageKey,
    wal_epoch: u64,
    expected_seq: u64,
    payload_len: u32,
    payload: &[u8],
    stored_tag: &[u8; MAC_TAG_BYTES],
) -> bool {
    let mut mac_input = Vec::with_capacity(8 + 4 + payload.len());
    mac_input.extend_from_slice(&expected_seq.to_be_bytes());
    mac_input.extend_from_slice(&payload_len.to_be_bytes());
    mac_input.extend_from_slice(payload);
    key.verify_mac(
        DOMAIN_WAL_RECORD,
        wal_epoch,
        expected_seq,
        wal_epoch,
        &mac_input,
        stored_tag,
    )
}

fn encode_shielded_slot(out: &mut Vec<u8>, slot: &PersistedShieldedSlot) -> Result<(), StorageError> {
    if slot.shares.len() > MAX_SHARES_PER_SLOT {
        return Err(StorageError::SizeLimitExceeded {
            actual: slot.shares.len(),
            max: MAX_SHARES_PER_SLOT,
        });
    }
    for &share in &slot.shares {
        if share >= PRIME_P {
            return Err(StorageError::NonCanonicalFieldElement);
        }
    }
    out.extend_from_slice(&slot.bucket_id.to_be_bytes());
    out.extend_from_slice(&slot.slot_id.to_be_bytes());
    out.extend_from_slice(&(slot.shares.len() as u32).to_be_bytes());
    for &share in &slot.shares {
        out.extend_from_slice(&share.to_be_bytes());
    }
    Ok(())
}

fn decode_shielded_slot(r: &mut ByteReader<'_>) -> Result<PersistedShieldedSlot, StorageError> {
    let bucket_id = r.read_u32()?;
    let slot_id = r.read_u32()?;
    let shares_len = r.read_u32()? as usize;
    if shares_len > MAX_SHARES_PER_SLOT {
        return Err(StorageError::SizeLimitExceeded {
            actual: shares_len,
            max: MAX_SHARES_PER_SLOT,
        });
    }
    let min_bytes = shares_len
        .checked_mul(16)
        .ok_or(StorageError::TruncatedRecord)?;
    if r.remaining() < min_bytes {
        return Err(StorageError::TruncatedRecord);
    }
    let mut shares = Vec::with_capacity(shares_len);
    for _ in 0..shares_len {
        let val = r.read_u128()?;
        if val >= PRIME_P {
            return Err(StorageError::NonCanonicalFieldElement);
        }
        shares.push(val);
    }
    Ok(PersistedShieldedSlot {
        bucket_id,
        slot_id,
        shares,
    })
}

fn encode_snapshot_body(snap: &PersistedChainSnapshot) -> Result<Vec<u8>, StorageError> {
    if snap.express_accounts.len() > MAX_EXPRESS_ACCOUNTS {
        return Err(StorageError::SizeLimitExceeded {
            actual: snap.express_accounts.len(),
            max: MAX_EXPRESS_ACCOUNTS,
        });
    }
    if snap.shielded_slots.len() > MAX_SHIELDED_SLOTS {
        return Err(StorageError::SizeLimitExceeded {
            actual: snap.shielded_slots.len(),
            max: MAX_SHIELDED_SLOTS,
        });
    }
    if snap.validators.len() > MAX_VALIDATORS {
        return Err(StorageError::SizeLimitExceeded {
            actual: snap.validators.len(),
            max: MAX_VALIDATORS,
        });
    }
    if snap.recent_events.len() > MAX_RECENT_EVENTS {
        return Err(StorageError::SizeLimitExceeded {
            actual: snap.recent_events.len(),
            max: MAX_RECENT_EVENTS,
        });
    }
    for ev in &snap.recent_events {
        if ev.len() > MAX_EVENT_BYTES {
            return Err(StorageError::SizeLimitExceeded {
                actual: ev.len(),
                max: MAX_EVENT_BYTES,
            });
        }
    }

    let mut out = Vec::with_capacity(128 + snap.express_accounts.len() * 20);
    out.extend_from_slice(&snap.version.to_be_bytes());
    out.extend_from_slice(&snap.blocks_finalized.to_be_bytes());
    out.extend_from_slice(&snap.express_txs.to_be_bytes());
    out.extend_from_slice(&snap.shielded_txs.to_be_bytes());
    out.extend_from_slice(&snap.pss_epoch.to_be_bytes());
    out.extend_from_slice(&snap.tokenomics_epoch.to_be_bytes());
    out.extend_from_slice(&snap.circulating_supply.to_be_bytes());
    out.extend_from_slice(&snap.total_burned.to_be_bytes());
    out.extend_from_slice(&snap.total_fees_collected.to_be_bytes());
    out.extend_from_slice(&snap.next_page_id.to_be_bytes());
    out.extend_from_slice(&snap.last_qber_bits.to_be_bytes());

    out.extend_from_slice(&(snap.express_accounts.len() as u32).to_be_bytes());
    for acc in &snap.express_accounts {
        out.extend_from_slice(&acc.account_id.to_be_bytes());
        out.extend_from_slice(&acc.balance.to_be_bytes());
        out.extend_from_slice(&acc.nonce.to_be_bytes());
    }

    out.extend_from_slice(&(snap.shielded_slots.len() as u32).to_be_bytes());
    for slot in &snap.shielded_slots {
        encode_shielded_slot(&mut out, slot)?;
    }

    out.extend_from_slice(&(snap.validators.len() as u32).to_be_bytes());
    for v in &snap.validators {
        out.extend_from_slice(&v.validator_id.to_be_bytes());
        out.extend_from_slice(&v.bond.to_be_bytes());
        out.extend_from_slice(&v.reward_balance.to_be_bytes());
        out.push(v.status_code);
        out.extend_from_slice(&v.missed_epochs.to_be_bytes());
    }

    out.extend_from_slice(&(snap.recent_events.len() as u32).to_be_bytes());
    for ev in &snap.recent_events {
        let bytes = ev.as_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    Ok(out)
}

fn decode_snapshot_body(bytes: &[u8]) -> Result<PersistedChainSnapshot, StorageError> {
    let mut r = ByteReader::new(bytes);

    let version = r.read_u32()?;
    let blocks_finalized = r.read_u64()?;
    let express_txs = r.read_u64()?;
    let shielded_txs = r.read_u64()?;
    let pss_epoch = r.read_u64()?;
    let tokenomics_epoch = r.read_u64()?;
    let circulating_supply = r.read_u64()?;
    let total_burned = r.read_u64()?;
    let total_fees_collected = r.read_u64()?;
    let next_page_id = r.read_u64()?;
    let last_qber_bits = r.read_u64()?;

    let acc_count = r.read_u32()? as usize;
    if acc_count > MAX_EXPRESS_ACCOUNTS {
        return Err(StorageError::SizeLimitExceeded {
            actual: acc_count,
            max: MAX_EXPRESS_ACCOUNTS,
        });
    }
    let min_acc_bytes = acc_count
        .checked_mul(20)
        .ok_or(StorageError::TruncatedRecord)?;
    if r.remaining() < min_acc_bytes {
        return Err(StorageError::TruncatedRecord);
    }
    let mut express_accounts = Vec::with_capacity(acc_count);
    for _ in 0..acc_count {
        let account_id = r.read_u32()?;
        let balance = r.read_u64()?;
        let nonce = r.read_u64()?;
        express_accounts.push(PersistedExpressAccount {
            account_id,
            balance,
            nonce,
        });
    }

    let slot_count = r.read_u32()? as usize;
    if slot_count > MAX_SHIELDED_SLOTS {
        return Err(StorageError::SizeLimitExceeded {
            actual: slot_count,
            max: MAX_SHIELDED_SLOTS,
        });
    }
    let min_slot_bytes = slot_count
        .checked_mul(12)
        .ok_or(StorageError::TruncatedRecord)?;
    if r.remaining() < min_slot_bytes {
        return Err(StorageError::TruncatedRecord);
    }
    let mut shielded_slots = Vec::with_capacity(slot_count);
    for _ in 0..slot_count {
        shielded_slots.push(decode_shielded_slot(&mut r)?);
    }

    let val_count = r.read_u32()? as usize;
    if val_count > MAX_VALIDATORS {
        return Err(StorageError::SizeLimitExceeded {
            actual: val_count,
            max: MAX_VALIDATORS,
        });
    }
    let min_val_bytes = val_count
        .checked_mul(33)
        .ok_or(StorageError::TruncatedRecord)?;
    if r.remaining() < min_val_bytes {
        return Err(StorageError::TruncatedRecord);
    }
    let mut validators = Vec::with_capacity(val_count);
    for _ in 0..val_count {
        let validator_id = r.read_u64()?;
        let bond = r.read_u64()?;
        let reward_balance = r.read_u64()?;
        let status_code = r.read_u8()?;
        let missed_epochs = r.read_u64()?;
        validators.push(PersistedValidatorVault {
            validator_id,
            bond,
            reward_balance,
            status_code,
            missed_epochs,
        });
    }

    let ev_count = r.read_u32()? as usize;
    if ev_count > MAX_RECENT_EVENTS {
        return Err(StorageError::SizeLimitExceeded {
            actual: ev_count,
            max: MAX_RECENT_EVENTS,
        });
    }
    let mut recent_events = Vec::with_capacity(ev_count);
    for _ in 0..ev_count {
        let len = r.read_u32()? as usize;
        if len > MAX_EVENT_BYTES {
            return Err(StorageError::SizeLimitExceeded {
                actual: len,
                max: MAX_EVENT_BYTES,
            });
        }
        let raw = r.read_bytes(len)?;
        let s = String::from_utf8(raw.to_vec())
            .map_err(|_| StorageError::CorruptFormat("invalid UTF-8 in recent_events".into()))?;
        recent_events.push(s);
    }

    r.finish()?;

    Ok(PersistedChainSnapshot {
        version,
        blocks_finalized,
        express_txs,
        shielded_txs,
        pss_epoch,
        tokenomics_epoch,
        circulating_supply,
        total_burned,
        total_fees_collected,
        next_page_id,
        last_qber_bits,
        express_accounts,
        shielded_slots,
        validators,
        recent_events,
    })
}

fn encode_wal_event(event: &WalDeltaEvent) -> Result<Vec<u8>, StorageError> {
    let mut out = Vec::with_capacity(64);
    match event {
        WalDeltaEvent::ExpressTransfer {
            sender,
            recipient,
            amount,
            sender_nonce,
            block_height,
            next_page_id,
            fee_burned,
        } => {
            out.push(WAL_TAG_EXPRESS_TRANSFER);
            out.extend_from_slice(&sender.to_be_bytes());
            out.extend_from_slice(&recipient.to_be_bytes());
            out.extend_from_slice(&amount.to_be_bytes());
            out.extend_from_slice(&sender_nonce.to_be_bytes());
            out.extend_from_slice(&block_height.to_be_bytes());
            out.extend_from_slice(&next_page_id.to_be_bytes());
            out.extend_from_slice(&fee_burned.to_be_bytes());
        }
        WalDeltaEvent::FaucetCredit {
            account_id,
            express_amount,
            shielded_amount,
            block_height,
            next_page_id,
        } => {
            out.push(WAL_TAG_FAUCET_CREDIT);
            out.extend_from_slice(&account_id.to_be_bytes());
            out.extend_from_slice(&express_amount.to_be_bytes());
            out.extend_from_slice(&shielded_amount.to_be_bytes());
            match block_height {
                None => out.push(0u8),
                Some(h) => {
                    out.push(1u8);
                    out.extend_from_slice(&h.to_be_bytes());
                }
            }
            out.extend_from_slice(&next_page_id.to_be_bytes());
        }
        WalDeltaEvent::ShieldedBucketUpdate {
            bucket_id,
            pss_epoch,
            slots,
            fee_burned,
        } => {
            if slots.len() > MAX_SHIELDED_SLOTS {
                return Err(StorageError::SizeLimitExceeded {
                    actual: slots.len(),
                    max: MAX_SHIELDED_SLOTS,
                });
            }
            out.push(WAL_TAG_SHIELDED_BUCKET_UPDATE);
            out.extend_from_slice(&bucket_id.to_be_bytes());
            out.extend_from_slice(&pss_epoch.to_be_bytes());
            out.extend_from_slice(&(slots.len() as u32).to_be_bytes());
            for slot in slots {
                encode_shielded_slot(&mut out, slot)?;
            }
            out.extend_from_slice(&fee_burned.to_be_bytes());
        }
        WalDeltaEvent::EpochSettled {
            tokenomics_epoch,
            pss_epoch,
            subsidy_minted,
            total_burned,
            circulating_supply,
            last_qber_bits,
        } => {
            out.push(WAL_TAG_EPOCH_SETTLED);
            out.extend_from_slice(&tokenomics_epoch.to_be_bytes());
            out.extend_from_slice(&pss_epoch.to_be_bytes());
            out.extend_from_slice(&subsidy_minted.to_be_bytes());
            out.extend_from_slice(&total_burned.to_be_bytes());
            out.extend_from_slice(&circulating_supply.to_be_bytes());
            out.extend_from_slice(&last_qber_bits.to_be_bytes());
        }
    }
    Ok(out)
}

fn decode_wal_event(bytes: &[u8]) -> Result<WalDeltaEvent, StorageError> {
    let mut r = ByteReader::new(bytes);
    let tag = r.read_u8()?;
    let ev = match tag {
        WAL_TAG_EXPRESS_TRANSFER => {
            let sender = r.read_u32()?;
            let recipient = r.read_u32()?;
            let amount = r.read_u64()?;
            let sender_nonce = r.read_u64()?;
            let block_height = r.read_u64()?;
            let next_page_id = r.read_u64()?;
            let fee_burned = r.read_u64()?;
            WalDeltaEvent::ExpressTransfer {
                sender,
                recipient,
                amount,
                sender_nonce,
                block_height,
                next_page_id,
                fee_burned,
            }
        }
        WAL_TAG_FAUCET_CREDIT => {
            let account_id = r.read_u32()?;
            let express_amount = r.read_u64()?;
            let shielded_amount = r.read_u64()?;
            let block_height = match r.read_u8()? {
                0 => None,
                1 => Some(r.read_u64()?),
                other => {
                    return Err(StorageError::CorruptFormat(format!(
                        "invalid Option tag 0x{other:02x} in FaucetCredit"
                    )));
                }
            };
            let next_page_id = r.read_u64()?;
            WalDeltaEvent::FaucetCredit {
                account_id,
                express_amount,
                shielded_amount,
                block_height,
                next_page_id,
            }
        }
        WAL_TAG_SHIELDED_BUCKET_UPDATE => {
            let bucket_id = r.read_u32()?;
            let pss_epoch = r.read_u64()?;
            let slots_len = r.read_u32()? as usize;
            if slots_len > MAX_SHIELDED_SLOTS {
                return Err(StorageError::SizeLimitExceeded {
                    actual: slots_len,
                    max: MAX_SHIELDED_SLOTS,
                });
            }
            let min_bytes = slots_len
                .checked_mul(12)
                .ok_or(StorageError::TruncatedRecord)?;
            if r.remaining() < min_bytes {
                return Err(StorageError::TruncatedRecord);
            }
            let mut slots = Vec::with_capacity(slots_len);
            for _ in 0..slots_len {
                slots.push(decode_shielded_slot(&mut r)?);
            }
            let fee_burned = r.read_u64()?;
            WalDeltaEvent::ShieldedBucketUpdate {
                bucket_id,
                pss_epoch,
                slots,
                fee_burned,
            }
        }
        WAL_TAG_EPOCH_SETTLED => {
            let tokenomics_epoch = r.read_u64()?;
            let pss_epoch = r.read_u64()?;
            let subsidy_minted = r.read_u64()?;
            let total_burned = r.read_u64()?;
            let circulating_supply = r.read_u64()?;
            let last_qber_bits = r.read_u64()?;
            WalDeltaEvent::EpochSettled {
                tokenomics_epoch,
                pss_epoch,
                subsidy_minted,
                total_burned,
                circulating_supply,
                last_qber_bits,
            }
        }
        other => {
            return Err(StorageError::CorruptFormat(format!(
                "unknown WAL event tag 0x{other:02x}"
            )));
        }
    };
    r.finish()?;
    Ok(ev)
}

fn read_and_verify_snapshot(
    path: &Path,
    key: &RotatingCwStorageKey,
) -> Result<(u64, PersistedChainSnapshot), StorageError> {
    let meta = fs::metadata(path)?;
    let max_file_len = (MAX_SNAPSHOT_BYTES + SNAPSHOT_MIN_FILE_LEN) as u64;
    if meta.len() > max_file_len {
        return Err(StorageError::SizeLimitExceeded {
            actual: meta.len().min(usize::MAX as u64) as usize,
            max: max_file_len as usize,
        });
    }

    let bytes = fs::read(path)?;
    if bytes.len() >= 8 && &bytes[0..8] != SNAPSHOT_MAGIC {
        return Err(StorageError::CorruptMagic);
    }
    if bytes.len() < SNAPSHOT_MIN_FILE_LEN {
        return Err(StorageError::TruncatedRecord);
    }

    let signed_len = bytes.len() - MAC_TAG_BYTES;
    let snapshot_epoch = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
    let stored_tag: [u8; MAC_TAG_BYTES] = bytes[signed_len..].try_into().unwrap();

    // Verify 128-bit rotating Carter-Wegman MAC in constant time BEFORE trusting version/lengths/body.
    if !key.verify_mac(
        DOMAIN_SNAPSHOT,
        snapshot_epoch,
        0,
        snapshot_epoch,
        &bytes[..signed_len],
        &stored_tag,
    ) {
        return Err(StorageError::CorruptIntegrityMac);
    }

    let format_version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if format_version != SNAPSHOT_FORMAT_VERSION {
        return Err(StorageError::CorruptFormat(format!(
            "unsupported snapshot format version {format_version}"
        )));
    }

    let body_len = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) as usize;
    if body_len > MAX_SNAPSHOT_BYTES {
        return Err(StorageError::SizeLimitExceeded {
            actual: body_len,
            max: MAX_SNAPSHOT_BYTES,
        });
    }
    if SNAPSHOT_ENVELOPE_HEADER_LEN + body_len != signed_len {
        return Err(StorageError::CorruptFormat(format!(
            "snapshot body_len {body_len} does not match file size {}",
            bytes.len()
        )));
    }

    let snapshot = decode_snapshot_body(&bytes[SNAPSHOT_ENVELOPE_HEADER_LEN..signed_len])?;
    Ok((snapshot_epoch, snapshot))
}

fn encode_wal_header(
    key: &mut RotatingCwStorageKey,
    wal_epoch: u64,
) -> Result<[u8; WAL_HEADER_LEN], StorageError> {
    let mut hdr = [0u8; WAL_HEADER_LEN];
    hdr[0..8].copy_from_slice(WAL_MAGIC);
    hdr[8..12].copy_from_slice(&WAL_VERSION.to_be_bytes());
    hdr[12..20].copy_from_slice(&wal_epoch.to_be_bytes());
    let tag = key.allocate_and_compute_mac(
        DOMAIN_WAL_HEADER,
        wal_epoch,
        0,
        wal_epoch,
        &hdr[0..20],
    )?;
    hdr[20..36].copy_from_slice(&tag);
    Ok(hdr)
}

fn verify_wal_header(bytes: &[u8], key: &RotatingCwStorageKey) -> Result<u64, StorageError> {
    if bytes.len() >= 8 && &bytes[0..8] != WAL_MAGIC {
        return Err(StorageError::CorruptMagic);
    }
    if bytes.len() < WAL_HEADER_LEN {
        return Err(StorageError::TruncatedRecord);
    }
    let wal_epoch = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
    let stored_tag: [u8; MAC_TAG_BYTES] = bytes[20..36].try_into().unwrap();
    if !key.verify_mac(
        DOMAIN_WAL_HEADER,
        wal_epoch,
        0,
        wal_epoch,
        &bytes[0..20],
        &stored_tag,
    ) {
        return Err(StorageError::CorruptIntegrityMac);
    }
    let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if version != WAL_VERSION {
        return Err(StorageError::CorruptFormat(format!(
            "unsupported WAL format version {version}"
        )));
    }
    Ok(wal_epoch)
}

fn create_fresh_wal_atomic(
    wal_path: &Path,
    key: &mut RotatingCwStorageKey,
    wal_epoch: u64,
) -> Result<File, StorageError> {
    let hdr = encode_wal_header(key, wal_epoch)?;
    write_file_atomic_0600(wal_path, &hdr)?;
    let mut f = open_secret_file(wal_path, false)?;
    f.seek(SeekFrom::End(0))?;
    Ok(f)
}

/// Recover `chain.wal` on `CrashSafeChainStore::open`:
/// - If `wal_epoch < snapshot_epoch`, atomically resets the stale pre-snapshot WAL.
/// - Replays and verifies every WAL record.
/// - Zeroes and truncates an incomplete torn trailing record at EOF.
/// - Rejects any mid-WAL corruption, bit-flip, or sequence reordering.
fn recover_wal(
    wal_path: &Path,
    key: &mut RotatingCwStorageKey,
    snapshot_epoch: u64,
) -> Result<(File, u64), StorageError> {
    let mut file = open_secret_file(wal_path, false)?;
    let file_len = file.metadata()?.len();

    if file_len == 0 {
        return Err(StorageError::TruncatedRecord);
    }

    let mut hdr_buf = [0u8; WAL_HEADER_LEN];
    if file_len < WAL_HEADER_LEN as u64 {
        let mut partial = vec![0u8; file_len as usize];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut partial)?;
        if partial.len() >= 8 && &partial[0..8] != WAL_MAGIC {
            return Err(StorageError::CorruptMagic);
        }
        return Err(StorageError::TruncatedRecord);
    }

    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut hdr_buf)?;
    let wal_epoch = verify_wal_header(&hdr_buf, key)?;

    if wal_epoch < snapshot_epoch {
        // Crash occurred after atomic snapshot rename and before WAL reset; safely replace stale WAL.
        drop(file);
        let fresh = create_fresh_wal_atomic(wal_path, key, snapshot_epoch)?;
        return Ok((fresh, 0));
    }
    if wal_epoch > snapshot_epoch {
        return Err(StorageError::CorruptFormat(format!(
            "WAL epoch {wal_epoch} exceeds snapshot epoch {snapshot_epoch}"
        )));
    }

    let mut offset = WAL_HEADER_LEN as u64;
    let mut expected_seq: u64 = 0;
    let mut torn_tail_offset: Option<u64> = None;

    while offset < file_len {
        let rem = file_len - offset;
        if rem < WAL_RECORD_PREFIX_LEN as u64 {
            // Fewer than 16 bytes remain at EOF: incomplete torn write of record prefix.
            torn_tail_offset = Some(offset);
            break;
        }

        let mut prefix = [0u8; WAL_RECORD_PREFIX_LEN];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut prefix)?;

        let stored_seq = u64::from_be_bytes(prefix[0..8].try_into().unwrap());
        let payload_len = u32::from_be_bytes(prefix[8..12].try_into().unwrap());
        let stored_guard = u32::from_be_bytes(prefix[12..16].try_into().unwrap());

        // Check for all-zero preallocated crash tail.
        if prefix.iter().all(|&b| b == 0) && is_all_zero_tail(&mut file, offset, file_len)? {
            torn_tail_offset = Some(offset);
            break;
        }

        let expected_guard = compute_wal_header_guard(stored_seq, payload_len);
        if stored_guard != expected_guard {
            // Framing guard mismatch indicates bit-level tampering in seq/payload_len/guard.
            return Err(StorageError::CorruptIntegrityMac);
        }

        if payload_len == 0 || (payload_len as usize) > MAX_WAL_RECORD_BYTES {
            return Err(StorageError::SizeLimitExceeded {
                actual: payload_len as usize,
                max: MAX_WAL_RECORD_BYTES,
            });
        }

        let rec_len = (WAL_RECORD_OVERHEAD as u64)
            .checked_add(payload_len as u64)
            .ok_or(StorageError::TruncatedRecord)?;

        if rem < rec_len {
            if stored_seq == expected_seq {
                // Header is well-formed for the next expected sequence number, but payload/MAC
                // was cut short at EOF: incomplete torn trailing WAL record.
                torn_tail_offset = Some(offset);
                break;
            } else {
                // Sequence mismatch on truncated record indicates corruption/tampering.
                return Err(StorageError::CorruptIntegrityMac);
            }
        }

        let mut payload = vec![0u8; payload_len as usize];
        file.read_exact(&mut payload)?;
        let mut stored_tag = [0u8; MAC_TAG_BYTES];
        file.read_exact(&mut stored_tag)?;

        // Verify MAC bound to `expected_seq` (catches any bit-flip, sequence gap, or reorder).
        if stored_seq != expected_seq
            || !verify_wal_record_mac(key, wal_epoch, expected_seq, payload_len, &payload, &stored_tag)
        {
            return Err(StorageError::CorruptIntegrityMac);
        }

        // Decode event to validate structure and canonical Shamir shares (< PRIME_P).
        let _event = decode_wal_event(&payload)?;

        offset += rec_len;
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or_else(|| StorageError::CorruptFormat("WAL sequence overflow".into()))?;
        if expected_seq as usize > MAX_WAL_RECORDS {
            return Err(StorageError::SizeLimitExceeded {
                actual: expected_seq as usize,
                max: MAX_WAL_RECORDS,
            });
        }
    }

    if let Some(valid_end) = torn_tail_offset {
        // Safely zero torn trailing bytes on disk before truncating and fsyncing.
        zero_and_truncate_tail(&mut file, valid_end, file_len)?;
    }

    file.seek(SeekFrom::End(0))?;
    Ok((file, expected_seq))
}

/// Strictly read and verify `chain.wal` without mutating the file.
fn read_and_verify_wal_strict(
    wal_path: &Path,
    key: &RotatingCwStorageKey,
    expected_epoch: u64,
) -> Result<Vec<WalDeltaEvent>, StorageError> {
    let mut file = File::open(wal_path)?;
    let file_len = file.metadata()?.len();
    if file_len < WAL_HEADER_LEN as u64 {
        let mut partial = vec![0u8; file_len as usize];
        file.read_exact(&mut partial)?;
        if partial.len() >= 8 && &partial[0..8] != WAL_MAGIC {
            return Err(StorageError::CorruptMagic);
        }
        return Err(StorageError::TruncatedRecord);
    }

    let mut hdr_buf = [0u8; WAL_HEADER_LEN];
    file.read_exact(&mut hdr_buf)?;
    let wal_epoch = verify_wal_header(&hdr_buf, key)?;

    if wal_epoch != expected_epoch {
        return Err(StorageError::CorruptFormat(format!(
            "WAL epoch {wal_epoch} does not match snapshot epoch {expected_epoch}"
        )));
    }

    let mut events = Vec::new();
    let mut offset = WAL_HEADER_LEN as u64;
    let mut expected_seq: u64 = 0;

    while offset < file_len {
        let rem = file_len - offset;
        if rem < WAL_RECORD_PREFIX_LEN as u64 {
            return Err(StorageError::TruncatedRecord);
        }

        let mut prefix = [0u8; WAL_RECORD_PREFIX_LEN];
        file.read_exact(&mut prefix)?;
        let stored_seq = u64::from_be_bytes(prefix[0..8].try_into().unwrap());
        let payload_len = u32::from_be_bytes(prefix[8..12].try_into().unwrap());
        let stored_guard = u32::from_be_bytes(prefix[12..16].try_into().unwrap());

        if stored_guard != compute_wal_header_guard(stored_seq, payload_len) {
            return Err(StorageError::CorruptIntegrityMac);
        }
        if payload_len == 0 || (payload_len as usize) > MAX_WAL_RECORD_BYTES {
            return Err(StorageError::SizeLimitExceeded {
                actual: payload_len as usize,
                max: MAX_WAL_RECORD_BYTES,
            });
        }

        let rec_len = (WAL_RECORD_OVERHEAD as u64)
            .checked_add(payload_len as u64)
            .ok_or(StorageError::TruncatedRecord)?;
        if rem < rec_len {
            return Err(StorageError::TruncatedRecord);
        }

        let mut payload = vec![0u8; payload_len as usize];
        file.read_exact(&mut payload)?;
        let mut stored_tag = [0u8; MAC_TAG_BYTES];
        file.read_exact(&mut stored_tag)?;

        if stored_seq != expected_seq
            || !verify_wal_record_mac(key, wal_epoch, expected_seq, payload_len, &payload, &stored_tag)
        {
            return Err(StorageError::CorruptIntegrityMac);
        }

        let event = decode_wal_event(&payload)?;
        events.push(event);

        offset += rec_len;
        expected_seq += 1;
        if events.len() > MAX_WAL_RECORDS {
            return Err(StorageError::SizeLimitExceeded {
                actual: events.len(),
                max: MAX_WAL_RECORDS,
            });
        }
    }

    Ok(events)
}

fn is_all_zero_tail(file: &mut File, start: u64, end: u64) -> io::Result<bool> {
    file.seek(SeekFrom::Start(start))?;
    let mut remaining = end - start;
    let mut chunk = [0u8; 4096];
    while remaining > 0 {
        let to_read = (remaining as usize).min(chunk.len());
        file.read_exact(&mut chunk[..to_read])?;
        if chunk[..to_read].iter().any(|&b| b != 0) {
            return Ok(false);
        }
        remaining -= to_read as u64;
    }
    Ok(true)
}

fn zero_and_truncate_tail(file: &mut File, valid_end: u64, file_len: u64) -> io::Result<()> {
    if valid_end >= file_len {
        return Ok(());
    }
    file.seek(SeekFrom::Start(valid_end))?;
    let zeros = [0u8; 8192];
    let mut remaining = file_len - valid_end;
    while remaining > 0 {
        let to_write = (remaining as usize).min(zeros.len());
        file.write_all(&zeros[..to_write])?;
        remaining -= to_write as u64;
    }
    file.sync_all()?;
    file.set_len(valid_end)?;
    file.sync_all()?;
    Ok(())
}

// =============================================================================
// Filesystem Durability & Permission Helpers (0700 dir, 0600 files, atomic rename)
// =============================================================================

fn ensure_secret_dir(dir: &Path) -> io::Result<()> {
    let existed = dir.exists();
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    if !existed {
        sync_parent_dir(dir)?;
    }
    sync_dir(dir)?;
    Ok(())
}

fn open_secret_file(path: &Path, create_truncate: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    if create_truncate {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    opts.mode(0o600);
    let file = opts.open(path)?;
    #[cfg(unix)]
    if create_truncate {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn write_file_atomic_0600(target: &Path, data: &[u8]) -> io::Result<()> {
    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let filename = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vernam_file");
    let pid = std::process::id();
    let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(".{filename}.tmp.{pid}.{seq}"));

    let write_res = (|| -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts.open(&tmp_path)?;
        #[cfg(unix)]
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    sync_parent_dir(target)?;
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    let f = File::open(dir)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    sync_dir(dir)
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let pid = std::process::id();
            let seq = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "vernam_storage_test_{label}_{pid}_{nanos}_{seq}"
            ));
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_snapshot() -> PersistedChainSnapshot {
        PersistedChainSnapshot {
            version: SNAPSHOT_FORMAT_VERSION,
            blocks_finalized: 42_007,
            express_txs: 1_234_567,
            shielded_txs: 98_765,
            pss_epoch: 19,
            tokenomics_epoch: 11,
            circulating_supply: 15_750_000_000_000,
            total_burned: 44_321_999,
            total_fees_collected: 88_643_998,
            next_page_id: 9_001,
            last_qber_bits: 0.0137f64.to_bits(),
            express_accounts: vec![
                PersistedExpressAccount {
                    account_id: 1,
                    balance: 500_000_000,
                    nonce: 17,
                },
                PersistedExpressAccount {
                    account_id: 2,
                    balance: 0,
                    nonce: 0,
                },
                PersistedExpressAccount {
                    account_id: u32::MAX,
                    balance: u64::MAX,
                    nonce: 999_999,
                },
            ],
            shielded_slots: vec![
                PersistedShieldedSlot {
                    bucket_id: 0,
                    slot_id: 0,
                    shares: vec![0, 1, 42, PRIME_P - 1],
                },
                PersistedShieldedSlot {
                    bucket_id: 7,
                    slot_id: 12,
                    shares: vec![
                        0x1234_5678_9ABC_DEF0_FEDC_BA98_7654_3210 & PRIME_P,
                        (1u128 << 126) + 777,
                        PRIME_P - 2,
                    ],
                },
            ],
            validators: vec![
                PersistedValidatorVault {
                    validator_id: 101,
                    bond: 1_000_000_000,
                    reward_balance: 55_000,
                    status_code: 1,
                    missed_epochs: 0,
                },
                PersistedValidatorVault {
                    validator_id: 202,
                    bond: 2_500_000_000,
                    reward_balance: 120_345,
                    status_code: 2,
                    missed_epochs: 3,
                },
            ],
            recent_events: vec![
                "genesis initialized".to_string(),
                "express tx #1234567 finalized in 0.4ms".to_string(),
                "pss epoch 19 reshare complete (QBER 1.37%)".to_string(),
            ],
        }
    }

    #[test]
    fn test_snapshot_save_and_reopen_roundtrip() {
        let dir = TempDirGuard::new("snapshot_roundtrip");
        let snap = sample_snapshot();

        {
            let mut store = CrashSafeChainStore::open(dir.path()).unwrap();
            let (initial_snap, initial_wal) = store.load_latest().unwrap();
            assert!(initial_snap.is_none());
            assert!(initial_wal.is_empty());

            store.save_snapshot(&snap).unwrap();
            assert_eq!(store.snapshot_epoch(), 1);
            assert_eq!(store.wal_record_count(), 0);
        }

        // Reopen from scratch and verify exact bit-for-bit equality across all fields.
        let reopened = CrashSafeChainStore::open(dir.path()).unwrap();
        assert_eq!(reopened.snapshot_epoch(), 1);
        assert_eq!(reopened.wal_record_count(), 0);

        let (loaded_snap, loaded_wal) = reopened.load_latest().unwrap();
        assert_eq!(loaded_snap, Some(snap));
        assert!(loaded_wal.is_empty());
    }

    #[test]
    fn test_snapshot_wal_append_crash_reopen_and_compaction() {
        let dir = TempDirGuard::new("wal_compaction");
        let base_snap = sample_snapshot();

        let events = vec![
            WalDeltaEvent::ExpressTransfer {
                sender: 1,
                recipient: 2,
                amount: 12_500,
                sender_nonce: 18,
                block_height: 42_008,
                next_page_id: 9_002,
                fee_burned: 25,
            },
            WalDeltaEvent::FaucetCredit {
                account_id: 99,
                express_amount: 1_000_000,
                shielded_amount: 500_000,
                block_height: Some(42_009),
                next_page_id: 9_003,
            },
            WalDeltaEvent::FaucetCredit {
                account_id: 100,
                express_amount: 250_000,
                shielded_amount: 0,
                block_height: None,
                next_page_id: 9_004,
            },
            WalDeltaEvent::ShieldedBucketUpdate {
                bucket_id: 3,
                pss_epoch: 20,
                slots: vec![PersistedShieldedSlot {
                    bucket_id: 3,
                    slot_id: 1,
                    shares: vec![11, 22, PRIME_P - 1],
                }],
                fee_burned: 50,
            },
            WalDeltaEvent::EpochSettled {
                tokenomics_epoch: 12,
                pss_epoch: 20,
                subsidy_minted: 1_500_000,
                total_burned: 44_322_074,
                circulating_supply: 15_751_500_000_000,
                last_qber_bits: 0.0112f64.to_bits(),
            },
        ];

        {
            let mut store = CrashSafeChainStore::open(dir.path()).unwrap();
            store.save_snapshot(&base_snap).unwrap();
            for ev in &events {
                store.append_wal(ev).unwrap();
            }
            assert_eq!(store.wal_record_count(), events.len() as u64);
            // Drop without explicit close to simulate sudden process exit.
        }

        // Reopen after crash: snapshot + all 5 WAL deltas must be recovered verbatim.
        let mut reopened = CrashSafeChainStore::open(dir.path()).unwrap();
        assert_eq!(reopened.snapshot_epoch(), 1);
        assert_eq!(reopened.wal_record_count(), events.len() as u64);

        let (loaded_snap, loaded_events) = reopened.load_latest().unwrap();
        assert_eq!(loaded_snap, Some(base_snap.clone()));
        assert_eq!(loaded_events, events);

        // Compaction below threshold should be a no-op.
        let mut updated_snap = base_snap;
        updated_snap.blocks_finalized = 42_009;
        updated_snap.pss_epoch = 20;
        updated_snap.tokenomics_epoch = 12;

        assert!(!reopened.compact_if_needed(&updated_snap, 6).unwrap());
        assert_eq!(reopened.snapshot_epoch(), 1);
        assert_eq!(reopened.wal_record_count(), 5);

        // Compaction at threshold should atomically promote snapshot and reset WAL.
        assert!(reopened.compact_if_needed(&updated_snap, 5).unwrap());
        assert_eq!(reopened.snapshot_epoch(), 2);
        assert_eq!(reopened.wal_record_count(), 0);

        // Reopen again after compaction: new snapshot present, WAL empty.
        let after_compact = CrashSafeChainStore::open(dir.path()).unwrap();
        assert_eq!(after_compact.snapshot_epoch(), 2);
        assert_eq!(after_compact.wal_record_count(), 0);
        let (final_snap, final_wal) = after_compact.load_latest().unwrap();
        assert_eq!(final_snap, Some(updated_snap));
        assert!(final_wal.is_empty());
    }

    #[test]
    fn test_single_bit_tamper_on_snapshot_rejected() {
        let dir = TempDirGuard::new("snapshot_tamper");
        let snap = sample_snapshot();

        {
            let mut store = CrashSafeChainStore::open(dir.path()).unwrap();
            store.save_snapshot(&snap).unwrap();
        }

        let snap_path = dir.path().join(SNAPSHOT_FILENAME);
        let original = fs::read(&snap_path).unwrap();

        // Flip a bit in magic -> CorruptMagic.
        {
            let mut tampered = original.clone();
            tampered[0] ^= 0x01;
            fs::write(&snap_path, &tampered).unwrap();
            let err = CrashSafeChainStore::open(dir.path()).unwrap_err();
            assert!(matches!(err, StorageError::CorruptMagic), "got: {err:?}");
        }

        // Flip a single bit in version, epoch, body_len, body, and MAC -> CorruptIntegrityMac.
        let probe_offsets = [
            8,                    // format_version
            15,                   // snapshot_epoch
            22,                   // body_len
            24,                   // start of body
            original.len() / 2,   // middle of body
            original.len() - 17,  // last byte of body
            original.len() - 16,  // first byte of MAC
            original.len() - 1,   // last byte of MAC
        ];

        for &off in &probe_offsets {
            let mut tampered = original.clone();
            tampered[off] ^= 0x01;
            fs::write(&snap_path, &tampered).unwrap();
            let err = CrashSafeChainStore::open(dir.path()).unwrap_err();
            assert!(
                matches!(err, StorageError::CorruptIntegrityMac),
                "offset {off}: expected CorruptIntegrityMac, got {err:?}"
            );
        }

        // Restore original and verify store opens cleanly again.
        fs::write(&snap_path, &original).unwrap();
        let store = CrashSafeChainStore::open(dir.path()).unwrap();
        assert_eq!(store.load_latest().unwrap().0, Some(snap));
    }

    #[test]
    fn test_single_bit_tamper_on_wal_and_sequence_reorder_rejected() {
        let dir = TempDirGuard::new("wal_tamper_reorder");
        let ev0 = WalDeltaEvent::ExpressTransfer {
            sender: 1,
            recipient: 2,
            amount: 100,
            sender_nonce: 1,
            block_height: 10,
            next_page_id: 1,
            fee_burned: 1,
        };
        let ev1 = WalDeltaEvent::ExpressTransfer {
            sender: 2,
            recipient: 3,
            amount: 200,
            sender_nonce: 1,
            block_height: 11,
            next_page_id: 2,
            fee_burned: 2,
        };

        {
            let mut store = CrashSafeChainStore::open(dir.path()).unwrap();
            store.append_wal(&ev0).unwrap();
            store.append_wal(&ev1).unwrap();
        }

        let wal_path = dir.path().join(WAL_FILENAME);
        let original = fs::read(&wal_path).unwrap();

        // Record 0 and record 1 have identical size (49-byte payload + 32-byte overhead = 81 bytes).
        let rec_size = (original.len() - WAL_HEADER_LEN) / 2;
        assert_eq!(original.len(), WAL_HEADER_LEN + 2 * rec_size);

        // 1) Flip a single bit at every critical field of BOTH record 0 (mid-WAL) and record 1 (tail).
        for rec_idx in 0..2 {
            let base = WAL_HEADER_LEN + rec_idx * rec_size;
            let field_offsets = [
                base,                // seq
                base + 8,            // payload_len
                base + 12,           // header_guard
                base + 16,           // payload tag
                base + 30,           // payload middle
                base + rec_size - 1, // MAC tag last byte
            ];
            for &off in &field_offsets {
                let mut tampered = original.clone();
                tampered[off] ^= 0x01;
                fs::write(&wal_path, &tampered).unwrap();
                let err = CrashSafeChainStore::open(dir.path()).unwrap_err();
                assert!(
                    matches!(err, StorageError::CorruptIntegrityMac),
                    "rec {rec_idx} offset {off}: expected CorruptIntegrityMac, got {err:?}"
                );
            }
        }

        // 2) Sequence reorder: swap valid record 0 and valid record 1 -> CorruptIntegrityMac.
        {
            let mut swapped = Vec::with_capacity(original.len());
            swapped.extend_from_slice(&original[..WAL_HEADER_LEN]);
            swapped.extend_from_slice(&original[WAL_HEADER_LEN + rec_size..]);
            swapped.extend_from_slice(&original[WAL_HEADER_LEN..WAL_HEADER_LEN + rec_size]);
            fs::write(&wal_path, &swapped).unwrap();
            let err = CrashSafeChainStore::open(dir.path()).unwrap_err();
            assert!(
                matches!(err, StorageError::CorruptIntegrityMac),
                "reordered WAL should fail with CorruptIntegrityMac, got {err:?}"
            );
        }

        // 3) Sequence gap: delete record 0, leaving only record 1 (seq=1) -> CorruptIntegrityMac.
        {
            let mut gapped = Vec::with_capacity(WAL_HEADER_LEN + rec_size);
            gapped.extend_from_slice(&original[..WAL_HEADER_LEN]);
            gapped.extend_from_slice(&original[WAL_HEADER_LEN + rec_size..]);
            fs::write(&wal_path, &gapped).unwrap();
            let err = CrashSafeChainStore::open(dir.path()).unwrap_err();
            assert!(
                matches!(err, StorageError::CorruptIntegrityMac),
                "gapped WAL should fail with CorruptIntegrityMac, got {err:?}"
            );
        }
    }

    #[test]
    fn test_torn_trailing_wal_recovery_vs_mid_wal_corruption() {
        let dir = TempDirGuard::new("torn_tail_vs_mid_corrupt");
        let ev0 = WalDeltaEvent::ExpressTransfer {
            sender: 10,
            recipient: 20,
            amount: 500,
            sender_nonce: 1,
            block_height: 1,
            next_page_id: 100,
            fee_burned: 5,
        };
        let ev1 = WalDeltaEvent::EpochSettled {
            tokenomics_epoch: 2,
            pss_epoch: 3,
            subsidy_minted: 10_000,
            total_burned: 5,
            circulating_supply: 1_010_000,
            last_qber_bits: 0.01f64.to_bits(),
        };
        let ev2 = WalDeltaEvent::FaucetCredit {
            account_id: 7,
            express_amount: 999,
            shielded_amount: 888,
            block_height: Some(2),
            next_page_id: 101,
        };

        {
            let mut store = CrashSafeChainStore::open(dir.path()).unwrap();
            store.append_wal(&ev0).unwrap();
            store.append_wal(&ev1).unwrap();
            store.append_wal(&ev2).unwrap();
        }

        let wal_path = dir.path().join(WAL_FILENAME);
        let full_wal = fs::read(&wal_path).unwrap();

        // Compute exact byte offset where ev2 starts.
        let rec0_len = WAL_RECORD_OVERHEAD + encode_wal_event(&ev0).unwrap().len();
        let rec1_len = WAL_RECORD_OVERHEAD + encode_wal_event(&ev1).unwrap().len();
        let rec2_start = WAL_HEADER_LEN + rec0_len + rec1_len;

        // Case A: Mid-WAL corruption in record 1 (while record 2 still follows) -> MUST reject.
        {
            let mut corrupted = full_wal.clone();
            corrupted[WAL_HEADER_LEN + rec0_len + 20] ^= 0x80;
            fs::write(&wal_path, &corrupted).unwrap();
            let err = CrashSafeChainStore::open(dir.path()).unwrap_err();
            assert!(
                matches!(err, StorageError::CorruptIntegrityMac),
                "mid-WAL corruption must be rejected, got {err:?}"
            );
        }

        // Case B: Torn trailing record cut mid-payload (leaving header + partial payload of ev2).
        {
            let torn = &full_wal[..rec2_start + WAL_RECORD_PREFIX_LEN + 7];
            fs::write(&wal_path, torn).unwrap();

            let mut store = CrashSafeChainStore::open(dir.path()).unwrap();
            assert_eq!(store.wal_record_count(), 2);
            assert_eq!(fs::metadata(&wal_path).unwrap().len(), rec2_start as u64);

            let (_snap, recovered) = store.load_latest().unwrap();
            assert_eq!(recovered, vec![ev0.clone(), ev1.clone()]);

            // Verify we can continue appending cleanly after torn-tail recovery.
            store.append_wal(&ev2).unwrap();
            let (_snap, after_append) = store.load_latest().unwrap();
            assert_eq!(after_append, vec![ev0.clone(), ev1.clone(), ev2.clone()]);
        }

        // Case C: Torn trailing record cut mid-prefix (only 5 bytes of ev2 written).
        {
            let torn = &full_wal[..rec2_start + 5];
            fs::write(&wal_path, torn).unwrap();

            let store = CrashSafeChainStore::open(dir.path()).unwrap();
            assert_eq!(store.wal_record_count(), 2);
            assert_eq!(fs::metadata(&wal_path).unwrap().len(), rec2_start as u64);
            let (_snap, recovered) = store.load_latest().unwrap();
            assert_eq!(recovered, vec![ev0.clone(), ev1.clone()]);
        }

        // Case D: Zero-filled preallocated crash tail at EOF.
        {
            let mut with_zeros = full_wal[..rec2_start].to_vec();
            with_zeros.extend_from_slice(&[0u8; 64]);
            fs::write(&wal_path, &with_zeros).unwrap();

            let store = CrashSafeChainStore::open(dir.path()).unwrap();
            assert_eq!(store.wal_record_count(), 2);
            assert_eq!(fs::metadata(&wal_path).unwrap().len(), rec2_start as u64);
        }
    }

    #[test]
    fn test_non_canonical_shamir_share_rejected_on_encode_and_decode() {
        let dir = TempDirGuard::new("non_canonical_share");
        let mut store = CrashSafeChainStore::open(dir.path()).unwrap();

        // 1) Encode rejection in snapshot for both PRIME_P and u128::MAX.
        for &bad_share in &[PRIME_P, PRIME_P + 1, u128::MAX] {
            let mut bad_snap = sample_snapshot();
            bad_snap.shielded_slots[0].shares.push(bad_share);
            let err = store.save_snapshot(&bad_snap).unwrap_err();
            assert!(
                matches!(err, StorageError::NonCanonicalFieldElement),
                "snapshot encode should reject share {bad_share:#x}, got {err:?}"
            );

            // Encode rejection in WAL ShieldedBucketUpdate.
            let bad_wal = WalDeltaEvent::ShieldedBucketUpdate {
                bucket_id: 1,
                pss_epoch: 1,
                slots: vec![PersistedShieldedSlot {
                    bucket_id: 1,
                    slot_id: 0,
                    shares: vec![bad_share],
                }],
                fee_burned: 1,
            };
            let err = store.append_wal(&bad_wal).unwrap_err();
            assert!(
                matches!(err, StorageError::NonCanonicalFieldElement),
                "WAL encode should reject share {bad_share:#x}, got {err:?}"
            );
        }

        // 2) Decode rejection even when wrapped in a valid Carter-Wegman MAC!
        let valid_snap = sample_snapshot();
        store.save_snapshot(&valid_snap).unwrap();

        let snap_path = dir.path().join(SNAPSHOT_FILENAME);
        let key = StorageIntegrityKey::load(store.key_path()).unwrap();
        let rot_key = RotatingCwStorageKey::open_or_create(dir.path(), key.r).unwrap();

        // Craft a snapshot body containing share == PRIME_P, sign with the active rotating CW-MAC pad, and write it.
        let mut raw_body = encode_snapshot_body(&valid_snap).unwrap();
        // Locate the first PRIME_P - 1 share (big-endian) in `raw_body` and increment it to PRIME_P.
        let target = (PRIME_P - 1).to_be_bytes();
        let pos = raw_body
            .windows(16)
            .position(|w| w == target)
            .expect("PRIME_P - 1 share must exist in serialized body");
        raw_body[pos..pos + 16].copy_from_slice(&PRIME_P.to_be_bytes());

        let epoch: u64 = 1;
        let mut frame = Vec::new();
        frame.extend_from_slice(SNAPSHOT_MAGIC);
        frame.extend_from_slice(&SNAPSHOT_FORMAT_VERSION.to_be_bytes());
        frame.extend_from_slice(&epoch.to_be_bytes());
        frame.extend_from_slice(&(raw_body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&raw_body);
        let (r, s) = rot_key
            .active_pad(DOMAIN_SNAPSHOT, epoch, 0)
            .expect("active rotating pad must exist for snapshot epoch 1");
        let tag = compute_cw_mac_raw(r, s, DOMAIN_SNAPSHOT, epoch, &frame);
        frame.extend_from_slice(&tag);

        fs::write(&snap_path, &frame).unwrap();

        let err = CrashSafeChainStore::open(dir.path()).unwrap_err();
        assert!(
            matches!(err, StorageError::NonCanonicalFieldElement),
            "MAC-valid snapshot with share == PRIME_P must be rejected on decode, got {err:?}"
        );
    }

    #[test]
    fn test_stale_wal_discarded_after_snapshot_rename_crash() {
        let dir = TempDirGuard::new("stale_wal_recovery");
        let snap1 = sample_snapshot();
        let mut snap2 = snap1.clone();
        snap2.blocks_finalized += 100;

        let ev = WalDeltaEvent::ExpressTransfer {
            sender: 1,
            recipient: 2,
            amount: 55,
            sender_nonce: 18,
            block_height: 42_008,
            next_page_id: 9_002,
            fee_burned: 1,
        };

        let stale_wal_bytes = {
            let mut store = CrashSafeChainStore::open(dir.path()).unwrap();
            store.save_snapshot(&snap1).unwrap();
            store.append_wal(&ev).unwrap();
            let wal_bytes = fs::read(store.wal_path()).unwrap();
            // Advance to snapshot epoch 2.
            store.save_snapshot(&snap2).unwrap();
            wal_bytes
        };

        // Simulate crash right after renaming chain.snap (epoch 2) before resetting chain.wal (epoch 1).
        fs::write(dir.path().join(WAL_FILENAME), &stale_wal_bytes).unwrap();

        let reopened = CrashSafeChainStore::open(dir.path()).unwrap();
        assert_eq!(reopened.snapshot_epoch(), 2);
        assert_eq!(reopened.wal_record_count(), 0);
        let (loaded_snap, loaded_wal) = reopened.load_latest().unwrap();
        assert_eq!(loaded_snap, Some(snap2));
        assert!(loaded_wal.is_empty());
    }

    #[test]
    fn test_event_bounds_and_key_redaction_and_prefix_free_mac() {
        let dir = TempDirGuard::new("bounds_and_mac");
        let mut store = CrashSafeChainStore::open(dir.path()).unwrap();

        // Recent events > 64 rejected.
        let mut too_many = PersistedChainSnapshot::default();
        too_many.recent_events = vec!["ev".to_string(); MAX_RECENT_EVENTS + 1];
        assert!(matches!(
            store.save_snapshot(&too_many),
            Err(StorageError::SizeLimitExceeded { .. })
        ));

        // Single event > 512 bytes rejected.
        let mut too_long = PersistedChainSnapshot::default();
        too_long.recent_events = vec!["x".repeat(MAX_EVENT_BYTES + 1)];
        assert!(matches!(
            store.save_snapshot(&too_long),
            Err(StorageError::SizeLimitExceeded { .. })
        ));

        // Debug redaction on StorageIntegrityKey.
        let key = StorageIntegrityKey::generate();
        let dbg = format!("{key:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&key.r.to_string()));
        assert!(!dbg.contains(&key.s.to_string()));

        // Prefix-collision-free MAC distinguishes empty, zero-padded, and cross-domain inputs.
        let t_empty = key.compute_mac(DOMAIN_SNAPSHOT, 1, b"");
        let t_zero1 = key.compute_mac(DOMAIN_SNAPSHOT, 1, b"\x00");
        let t_zero2 = key.compute_mac(DOMAIN_SNAPSHOT, 1, b"\x00\x00");
        let t_domain = key.compute_mac(DOMAIN_WAL_RECORD, 1, b"");
        let t_ctx = key.compute_mac(DOMAIN_SNAPSHOT, 2, b"");
        assert_ne!(t_empty, t_zero1);
        assert_ne!(t_zero1, t_zero2);
        assert_ne!(t_empty, t_domain);
        assert_ne!(t_empty, t_ctx);
        assert!(key.verify_mac(DOMAIN_SNAPSHOT, 1, b"\x00", &t_zero1));
        assert!(!key.verify_mac(DOMAIN_SNAPSHOT, 1, b"\x00\x00", &t_zero1));
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_file_and_dir_permissions() {
        let dir = TempDirGuard::new("unix_perms");
        let mut store = CrashSafeChainStore::open(dir.path()).unwrap();
        store.save_snapshot(&sample_snapshot()).unwrap();

        let dir_mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        let key_mode = fs::metadata(store.key_path()).unwrap().permissions().mode() & 0o777;
        let tape_mode = fs::metadata(store.pad_tape_path()).unwrap().permissions().mode() & 0o777;
        let snap_mode = fs::metadata(store.snapshot_path()).unwrap().permissions().mode() & 0o777;
        let wal_mode = fs::metadata(store.wal_path()).unwrap().permissions().mode() & 0o777;

        assert_eq!(dir_mode, 0o700, "data_dir must be 0700, got {dir_mode:o}");
        assert_eq!(key_mode, 0o600, "integrity.key must be 0600, got {key_mode:o}");
        assert_eq!(tape_mode, 0o600, "mac_pads.tape must be 0600, got {tape_mode:o}");
        assert_eq!(snap_mode, 0o600, "chain.snap must be 0600, got {snap_mode:o}");
        assert_eq!(wal_mode, 0o600, "chain.wal must be 0600, got {wal_mode:o}");
    }

    #[test]
    fn test_rotating_cw_mac_never_reuses_additive_pad_across_writes() {
        let dir = TempDirGuard::new("rotating_cw_mac_unique_pads");
        let snap1 = sample_snapshot();
        let mut snap2 = snap1.clone();
        snap2.blocks_finalized += 10;

        let ev = WalDeltaEvent::ExpressTransfer {
            sender: 1,
            recipient: 2,
            amount: 500,
            sender_nonce: 1,
            block_height: 100,
            next_page_id: 1,
            fee_burned: 5,
        };

        // Perform multiple WAL appends across 3 epochs (0 -> 1 -> 2), including identical events
        // and a crash/reopen boundary, to exercise every pad allocation path.
        {
            let mut store = CrashSafeChainStore::open(dir.path()).unwrap(); // pad 0: WAL hdr epoch 0
            store.append_wal(&ev).unwrap(); // pad 1: WAL rec (0, 0)
            store.append_wal(&ev).unwrap(); // pad 2: WAL rec (0, 1)
            store.save_snapshot(&snap1).unwrap(); // pad 3: snap (1, 0), pad 4: WAL hdr (1, 0) [rotates r]
            store.append_wal(&ev).unwrap(); // pad 5: WAL rec (1, 0)
            store.append_wal(&ev).unwrap(); // pad 6: WAL rec (1, 1)
            assert!(store.compact_if_needed(&snap2, 2).unwrap()); // pad 7: snap (2, 0), pad 8: WAL hdr (2, 0) [rotates r]
            store.append_wal(&ev).unwrap(); // pad 9: WAL rec (2, 0)
            assert_eq!(store.mac_pad_count(), 10);
        }

        // Reopen and append another WAL record -> pad 10: WAL rec (2, 1).
        let mut reopened = CrashSafeChainStore::open(dir.path()).unwrap();
        assert_eq!(reopened.mac_pad_count(), 10);
        reopened.append_wal(&ev).unwrap();
        assert_eq!(reopened.mac_pad_count(), 11);

        // Inspect every single pad persisted in `mac_pads.tape`.
        let records = RotatingCwStorageKey::read_all_tape_records(reopened.pad_tape_path()).unwrap();
        assert_eq!(records.len(), 11);

        let mut distinct_s: HashSet<u128> = HashSet::new();
        let mut epoch_rs: HashMap<u64, u128> = HashMap::new();

        for (idx, &(pad_id, _domain, epoch, _seq, r, s)) in records.iter().enumerate() {
            assert_eq!(pad_id, idx as u64, "pad_id must be strictly sequential");
            assert!(r > 0 && r < PRIME_P, "evaluation scalar r must be canonical non-zero");
            assert!(s < PRIME_P, "additive pad s must be canonical < PRIME_P");
            assert!(
                distinct_s.insert(s),
                "additive pad s was REUSED at pad_id {pad_id}!"
            );
            if let Some(&prev_r) = epoch_rs.get(&epoch) {
                assert_eq!(prev_r, r, "epoch {epoch} must use a consistent evaluation scalar r");
            } else {
                epoch_rs.insert(epoch, r);
            }
        }
        assert_eq!(distinct_s.len(), 11);

        // Verify evaluation scalar `r` strictly rotated across snapshot compactions (epochs 0, 1, 2).
        let r0 = epoch_rs[&0];
        let r1 = epoch_rs[&1];
        let r2 = epoch_rs[&2];
        assert_ne!(r0, r1, "r must rotate from epoch 0 to epoch 1");
        assert_ne!(r1, r2, "r must rotate from epoch 1 to epoch 2");
        assert_ne!(r0, r2, "r must rotate from epoch 0 to epoch 2");

        // Verify Debug redaction on RotatingCwStorageKey.
        let dbg = format!("{:?}", reopened.rotating_key);
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&r2.to_string()));

        // Tamper snapshot -> constant-time ct_eq_16 rejects with CorruptIntegrityMac.
        let snap_orig = fs::read(reopened.snapshot_path()).unwrap();
        {
            let mut tampered = snap_orig.clone();
            tampered[SNAPSHOT_ENVELOPE_HEADER_LEN + 3] ^= 0x04;
            fs::write(reopened.snapshot_path(), &tampered).unwrap();
            let err = reopened.load_latest().unwrap_err();
            assert!(matches!(err, StorageError::CorruptIntegrityMac));
        }
        fs::write(reopened.snapshot_path(), &snap_orig).unwrap();

        // Tamper WAL header -> constant-time ct_eq_16 rejects with CorruptIntegrityMac.
        let wal_orig = fs::read(reopened.wal_path()).unwrap();
        {
            let mut tampered = wal_orig.clone();
            tampered[WAL_HEADER_LEN - 1] ^= 0x80;
            fs::write(reopened.wal_path(), &tampered).unwrap();
            let err = reopened.load_latest().unwrap_err();
            assert!(matches!(err, StorageError::CorruptIntegrityMac));
        }

        // Tamper WAL record payload -> constant-time ct_eq_16 rejects with CorruptIntegrityMac.
        {
            let mut tampered = wal_orig.clone();
            tampered[WAL_HEADER_LEN + WAL_RECORD_PREFIX_LEN + 2] ^= 0x01;
            fs::write(reopened.wal_path(), &tampered).unwrap();
            let err = reopened.load_latest().unwrap_err();
            assert!(matches!(err, StorageError::CorruptIntegrityMac));
        }

        // Restore original WAL and verify clean load.
        fs::write(reopened.wal_path(), &wal_orig).unwrap();
        let (loaded_snap, loaded_events) = reopened.load_latest().unwrap();
        assert_eq!(loaded_snap, Some(snap2));
        assert_eq!(loaded_events, vec![ev.clone(), ev]);
    }
}
