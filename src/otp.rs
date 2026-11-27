//! Information-theoretically secure One-Time Pad (OTP), Carter-Wegman MAC over F_(2^127 - 1),
//! fixed-size framing, memory-zeroizing pad pages, and crash-safe WAL-backed pad books.
//!
//! Zero external crates, zero computational cryptography (no SHA/AES/RSA/ECDSA).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, fill_os_random, mul_mod, random_field_elem, reduce, zeroize_slice,
    zeroize_u128,
};

/// Fixed frame size in bytes (hides plaintext length up to `MAX_PAYLOAD_BYTES`).
pub const FRAME_BYTES: usize = 256;

/// Maximum payload length that fits inside a `FRAME_BYTES` frame (2-byte BE length prefix).
pub const MAX_PAYLOAD_BYTES: usize = FRAME_BYTES - 2;

/// Carter-Wegman MAC tag length in bytes (128-bit big-endian encoding of an F_(2^127 - 1) element).
pub const MAC_TAG_BYTES: usize = 16;

// Binary storage constants for `WalPadBook`.
const PAD_MAGIC: &[u8; 8] = b"VRNMPAD1";
const PAD_VERSION: u32 = 1;
const PAD_HEADER_LEN: u64 = 24; // 8 magic + 4 version + 4 enc_key_bytes + 8 reserved
const PAGE_STATE_BURNED: u8 = 0x00;
const PAGE_STATE_ACTIVE: u8 = 0x01;
const PAGE_META_BYTES: usize = 8 + 1 + 16 + 16; // page_id + state + mac_r + mac_s
const MAX_SANE_ENC_KEY_BYTES: usize = 64 * 1024 * 1024;

const WAL_MAGIC: &[u8; 8] = b"VRNMWAL1";
const WAL_HEADER_LEN: u64 = 8;
const WAL_OP_BURN: u8 = 0xB1;
const WAL_RECORD_LEN: usize = 1 + 8 + 8; // op + page_id + !page_id

#[cfg(test)]
static TEST_DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Errors returned by OTP, framing, MAC, and PadBook operations.
#[derive(Debug)]
pub enum OtpError {
    /// Provided OTP key material is shorter than the message slice.
    KeyTooShort { required: usize, available: usize },
    /// Page encryption key length does not match the book's configured key size.
    KeyLengthMismatch { expected: usize, actual: usize },
    /// Payload exceeds `MAX_PAYLOAD_BYTES`.
    PayloadTooLarge { len: usize, max: usize },
    /// Frame slice length does not equal `FRAME_BYTES`.
    InvalidFrameSize { actual: usize, expected: usize },
    /// Frame's 2-byte length prefix exceeds `MAX_PAYLOAD_BYTES`.
    InvalidFrameLength { declared: usize, max: usize },
    /// Frame padding bytes after the declared payload are non-zero.
    InvalidFramePadding,
    /// Carter-Wegman MAC verification failed (forgery or corruption).
    AuthenticationFailed,
    /// PadBook has no remaining unused pages.
    PadExhausted,
    /// Page ID has already been burned and can never be reused.
    PageAlreadyBurned(u64),
    /// Requested page ID does not exist in the PadBook.
    PageNotFound(u64),
    /// Attempted to insert a duplicate or already-burned page ID.
    DuplicatePageId(u64),
    /// On-disk pad book or WAL file is corrupted or malformed.
    CorruptStorage(String),
    /// Underlying filesystem I/O error.
    Io(io::Error),
}

impl fmt::Display for OtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtpError::KeyTooShort {
                required,
                available,
            } => write!(
                f,
                "OTP key too short: need {required} bytes, only {available} available"
            ),
            OtpError::KeyLengthMismatch { expected, actual } => write!(
                f,
                "page key length mismatch: expected {expected} bytes, got {actual}"
            ),
            OtpError::PayloadTooLarge { len, max } => {
                write!(f, "payload length {len} exceeds frame maximum {max}")
            }
            OtpError::InvalidFrameSize { actual, expected } => {
                write!(f, "invalid frame size: expected {expected} bytes, got {actual}")
            }
            OtpError::InvalidFrameLength { declared, max } => {
                write!(f, "invalid frame length prefix {declared} (max {max})")
            }
            OtpError::InvalidFramePadding => write!(f, "non-zero padding bytes in frame"),
            OtpError::AuthenticationFailed => write!(f, "Carter-Wegman MAC verification failed"),
            OtpError::PadExhausted => write!(f, "pad book exhausted: no unused pages remaining"),
            OtpError::PageAlreadyBurned(id) => {
                write!(f, "pad page {id} has already been burned (two-time pad forbidden)")
            }
            OtpError::PageNotFound(id) => write!(f, "pad page {id} not found"),
            OtpError::DuplicatePageId(id) => {
                write!(f, "pad page {id} already exists or was previously burned")
            }
            OtpError::CorruptStorage(msg) => write!(f, "corrupt pad storage: {msg}"),
            OtpError::Io(err) => write!(f, "pad storage I/O error: {err}"),
        }
    }
}

impl std::error::Error for OtpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OtpError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for OtpError {
    fn from(err: io::Error) -> Self {
        OtpError::Io(err)
    }
}

/// A single one-time pad page containing one-time encryption key bytes and one-time
/// Carter-Wegman MAC key elements `(mac_r, mac_s)` in `F_(2^127 - 1)`.
///
/// Implements `Drop` with volatile zeroization so key material is immediately wiped from RAM
/// whenever a page is burned or goes out of scope.
pub struct PadPage {
    pub page_id: u64,
    enc_key: Vec<u8>,
    mac_r: u128,
    mac_s: u128,
}

impl PadPage {
    /// Generate a fresh `PadPage` using OS cryptographic randomness (`/dev/urandom`).
    pub fn generate(page_id: u64, enc_key_bytes: usize) -> Self {
        let mut enc_key = vec![0u8; enc_key_bytes];
        if enc_key_bytes > 0 {
            fill_os_random(&mut enc_key);
        }
        let mac_r = random_field_elem();
        let mac_s = random_field_elem();
        Self {
            page_id,
            enc_key,
            mac_r,
            mac_s,
        }
    }

    /// Construct a `PadPage` from raw key material, reducing MAC scalars into `[0, PRIME_P)`.
    pub fn from_raw(page_id: u64, enc_key: Vec<u8>, mac_r: u128, mac_s: u128) -> Self {
        Self {
            page_id,
            enc_key,
            mac_r: reduce(mac_r),
            mac_s: reduce(mac_s),
        }
    }

    /// Access the one-time encryption key bytes.
    #[inline]
    pub fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    /// Access the length of the one-time encryption key in bytes.
    #[inline]
    pub fn enc_key_len(&self) -> usize {
        self.enc_key.len()
    }

    /// Access the Carter-Wegman evaluation key `r` in `F_(2^127 - 1)`.
    #[inline]
    pub fn mac_r(&self) -> u128 {
        self.mac_r
    }

    /// Access the Carter-Wegman one-time mask `s` in `F_(2^127 - 1)`.
    #[inline]
    pub fn mac_s(&self) -> u128 {
        self.mac_s
    }

    /// Explicitly duplicate this page for provisioning a counterparty's paired book.
    ///
    /// `PadPage` intentionally does not implement `Clone` so callers cannot accidentally
    /// duplicate one-time key material during normal message processing.
    pub fn duplicate_for_peer(&self) -> Self {
        Self {
            page_id: self.page_id,
            enc_key: self.enc_key.clone(),
            mac_r: self.mac_r,
            mac_s: self.mac_s,
        }
    }

    /// Immediately wipe all secret material inside this page using volatile writes.
    #[inline]
    pub fn zeroize(&mut self) {
        zeroize_slice(&mut self.enc_key);
        zeroize_u128(&mut self.mac_r);
        zeroize_u128(&mut self.mac_s);
    }
}

impl Drop for PadPage {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        TEST_DROP_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

impl fmt::Debug for PadPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PadPage")
            .field("page_id", &self.page_id)
            .field("enc_key_len", &self.enc_key.len())
            .field("enc_key", &"[REDACTED]")
            .field("mac_r", &"[REDACTED]")
            .field("mac_s", &"[REDACTED]")
            .finish()
    }
}

/// Fast word-level in-place OTP XOR (`data[i] ^= key[i]`).
///
/// Processes 8-byte `u64` chunks first so LLVM can emit wide registers and auto-vectorize
/// (SSE2/AVX2/NEON), then handles the remaining `< 8` tail bytes.
#[inline]
pub fn otp_xor_in_place(data: &mut [u8], key: &[u8]) -> Result<(), OtpError> {
    if key.len() < data.len() {
        return Err(OtpError::KeyTooShort {
            required: data.len(),
            available: key.len(),
        });
    }

    let key = &key[..data.len()];
    let mut data_chunks = data.chunks_exact_mut(8);
    let mut key_chunks = key.chunks_exact(8);

    for (d, k) in data_chunks.by_ref().zip(key_chunks.by_ref()) {
        let dv = u64::from_ne_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
        let kv = u64::from_ne_bytes([k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]]);
        d.copy_from_slice(&(dv ^ kv).to_ne_bytes());
    }

    for (d, &k) in data_chunks
        .into_remainder()
        .iter_mut()
        .zip(key_chunks.remainder().iter())
    {
        *d ^= k;
    }

    Ok(())
}

/// Fast word-level OTP XOR returning a newly allocated output buffer.
#[inline]
pub fn otp_xor(data: &[u8], key: &[u8]) -> Result<Vec<u8>, OtpError> {
    if key.len() < data.len() {
        return Err(OtpError::KeyTooShort {
            required: data.len(),
            available: key.len(),
        });
    }
    let mut out = data.to_vec();
    otp_xor_in_place(&mut out, key)?;
    Ok(out)
}

/// Compute a 128-bit information-theoretically secure Carter-Wegman One-Time MAC over
/// the Mersenne prime field `F_(2^127 - 1)`.
///
/// Construction:
/// - Splits `data` into 15-byte chunks (120 bits each).
/// - Encodes each chunk `c` of length `L in 1..=15` in little-endian with a trailing `0x01`
///   sentinel byte at index `L`, yielding `m_i < 2^121 < PRIME_P`. This mapping is strictly
///   injective across all byte strings (including distinct trailing-zero strings and empty input).
/// - Evaluates `H_r(data) = sum_{i=0}^{k-1} m_i * r^(k - i) mod PRIME_P` via Horner's rule
///   using division-free Mersenne arithmetic (`add_mod`, `mul_mod`). Note the trailing factor `r`
///   ensures even single-chunk messages depend multiplicatively on `r` (preventing 1-block forgery).
/// - Masks with one-time pad scalar `s`: `tag = (H_r(data) + s) mod PRIME_P`, returned as 16-byte
///   big-endian bytes.
///
/// Forgery probability for a fresh `(r, s)` is at most `ceil(data.len() / 15) / (2^127 - 1)`.
#[inline]
pub fn carter_wegman_mac(data: &[u8], r: u128, s: u128) -> [u8; MAC_TAG_BYTES] {
    let r = reduce(r);
    let s = reduce(s);

    let mut acc: u128 = 0;
    for chunk in data.chunks(15) {
        let mut buf = [0u8; 16];
        buf[..chunk.len()].copy_from_slice(chunk);
        buf[chunk.len()] = 0x01;
        let block = u128::from_le_bytes(buf);
        // `block < 2^121 < PRIME_P` and `acc < PRIME_P`, satisfying `add_mod` preconditions.
        acc = mul_mod(add_mod(acc, block), r);
    }

    let tag_val = add_mod(acc, s);
    debug_assert!(tag_val < PRIME_P);
    tag_val.to_be_bytes()
}

/// Constant-time verification of a Carter-Wegman MAC tag using `ct_eq_16`.
#[inline]
pub fn verify_mac(data: &[u8], r: u128, s: u128, tag: &[u8; MAC_TAG_BYTES]) -> bool {
    let expected = carter_wegman_mac(data, r, s);
    ct_eq_16(&expected, tag)
}

/// Pack a variable-length payload (`<= MAX_PAYLOAD_BYTES`) into a fixed `FRAME_BYTES` buffer:
/// `[len_hi, len_lo, payload..., 0x00...]`.
///
/// Fixed-size framing prevents traffic-analysis leaks of plaintext length.
pub fn pack_frame(payload: &[u8]) -> Result<[u8; FRAME_BYTES], OtpError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(OtpError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_BYTES,
        });
    }

    let mut frame = [0u8; FRAME_BYTES];
    let len_be = (payload.len() as u16).to_be_bytes();
    frame[0] = len_be[0];
    frame[1] = len_be[1];
    frame[2..2 + payload.len()].copy_from_slice(payload);
    Ok(frame)
}

/// Unpack a fixed `FRAME_BYTES` buffer created by `pack_frame`, validating length and zero padding.
pub fn unpack_frame(frame: &[u8]) -> Result<Vec<u8>, OtpError> {
    if frame.len() != FRAME_BYTES {
        return Err(OtpError::InvalidFrameSize {
            actual: frame.len(),
            expected: FRAME_BYTES,
        });
    }

    let declared = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    if declared > MAX_PAYLOAD_BYTES {
        return Err(OtpError::InvalidFrameLength {
            declared,
            max: MAX_PAYLOAD_BYTES,
        });
    }

    if frame[2 + declared..].iter().any(|&b| b != 0) {
        return Err(OtpError::InvalidFramePadding);
    }

    Ok(frame[2..2 + declared].to_vec())
}

/// Encrypt-then-MAC helper for a single `FRAME_BYTES` frame using a `PadPage`.
///
/// The MAC authenticates `page.page_id.to_be_bytes() || ciphertext` so neither the ciphertext
/// nor the associated page ID can be altered without detection.
pub fn seal_frame(
    page: &PadPage,
    payload: &[u8],
) -> Result<([u8; FRAME_BYTES], [u8; MAC_TAG_BYTES]), OtpError> {
    let mut frame = pack_frame(payload)?;
    otp_xor_in_place(&mut frame, page.enc_key())?;

    let mut mac_input = [0u8; 8 + FRAME_BYTES];
    mac_input[..8].copy_from_slice(&page.page_id.to_be_bytes());
    mac_input[8..].copy_from_slice(&frame);
    let tag = carter_wegman_mac(&mac_input, page.mac_r(), page.mac_s());
    Ok((frame, tag))
}

/// Verify-then-decrypt helper matching `seal_frame`.
///
/// Verifies the Carter-Wegman MAC in constant time BEFORE decrypting and zeroizes temporary
/// plaintext frame bytes before returning.
pub fn open_frame(
    page: &PadPage,
    ciphertext: &[u8],
    tag: &[u8; MAC_TAG_BYTES],
) -> Result<Vec<u8>, OtpError> {
    if ciphertext.len() != FRAME_BYTES {
        return Err(OtpError::InvalidFrameSize {
            actual: ciphertext.len(),
            expected: FRAME_BYTES,
        });
    }

    let mut mac_input = [0u8; 8 + FRAME_BYTES];
    mac_input[..8].copy_from_slice(&page.page_id.to_be_bytes());
    mac_input[8..].copy_from_slice(ciphertext);
    if !verify_mac(&mac_input, page.mac_r(), page.mac_s(), tag) {
        return Err(OtpError::AuthenticationFailed);
    }

    let mut plaintext_frame = [0u8; FRAME_BYTES];
    plaintext_frame.copy_from_slice(ciphertext);
    let res = otp_xor_in_place(&mut plaintext_frame, page.enc_key())
        .and_then(|()| unpack_frame(&plaintext_frame));
    zeroize_slice(&mut plaintext_frame);
    res
}

/// Common interface implemented by both `MemPadBook` and `WalPadBook`.
pub trait PadBook {
    fn enc_key_bytes(&self) -> usize;
    fn remaining(&self) -> usize;
    fn next_page_id(&self) -> u64;
    fn is_burned(&self, page_id: u64) -> bool;
    fn peek_unused(&self, page_id: u64) -> Option<&PadPage>;
    fn peek_next(&self) -> Option<&PadPage>;
    fn pop_next(&mut self) -> Result<PadPage, OtpError>;
    fn pop_page(&mut self, page_id: u64) -> Result<PadPage, OtpError>;
    fn burn(&mut self, page_id: u64) -> Result<(), OtpError>;
    fn append_pages(&mut self, pages: Vec<PadPage>) -> Result<(), OtpError>;
}

/// Fast in-memory strict one-time pad book.
///
/// Guarantees that once a page is popped or burned, its `page_id` is permanently recorded in
/// `burned` and can never be popped, peeked, or re-appended.
pub struct MemPadBook {
    enc_key_bytes: usize,
    pages: BTreeMap<u64, PadPage>,
    burned: BTreeSet<u64>,
    next_id: u64,
}

impl MemPadBook {
    /// Create an empty in-memory pad book for pages with `enc_key_bytes` key length.
    pub fn new(enc_key_bytes: usize) -> Self {
        Self {
            enc_key_bytes,
            pages: BTreeMap::new(),
            burned: BTreeSet::new(),
            next_id: 0,
        }
    }

    /// Generate a synchronized pair of `MemPadBook`s with `num_pages` pages numbered `0..num_pages`.
    pub fn generate_pair(num_pages: usize, enc_key_bytes: usize) -> (Self, Self) {
        Self::generate_pair_from(0, num_pages, enc_key_bytes)
    }

    /// Generate a synchronized pair of `MemPadBook`s starting at `start_page_id`.
    pub fn generate_pair_from(
        start_page_id: u64,
        num_pages: usize,
        enc_key_bytes: usize,
    ) -> (Self, Self) {
        let mut book_a = Self::new(enc_key_bytes);
        let mut book_b = Self::new(enc_key_bytes);
        book_a.next_id = start_page_id;
        book_b.next_id = start_page_id;

        for i in 0..num_pages {
            let page_id = start_page_id
                .checked_add(i as u64)
                .expect("page_id overflow");
            let page_a = PadPage::generate(page_id, enc_key_bytes);
            let page_b = page_a.duplicate_for_peer();
            book_a.pages.insert(page_id, page_a);
            book_b.pages.insert(page_id, page_b);
            book_a.next_id = page_id.saturating_add(1);
            book_b.next_id = page_id.saturating_add(1);
        }

        (book_a, book_b)
    }

    /// Configured encryption key size in bytes for pages in this book.
    #[inline]
    pub fn enc_key_bytes(&self) -> usize {
        self.enc_key_bytes
    }

    /// Number of unused pages currently available.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.pages.len()
    }

    /// Next monotonic `page_id` to allocate when replenishing this book.
    #[inline]
    pub fn next_page_id(&self) -> u64 {
        self.next_id
    }

    /// Returns `true` if `page_id` has been permanently burned.
    #[inline]
    pub fn is_burned(&self, page_id: u64) -> bool {
        self.burned.contains(&page_id)
    }

    /// Borrow an unused page by `page_id` without burning it (e.g., to verify a MAC before burning).
    #[inline]
    pub fn peek_unused(&self, page_id: u64) -> Option<&PadPage> {
        self.pages.get(&page_id)
    }

    /// Borrow the lowest-ID unused page without burning it.
    #[inline]
    pub fn peek_next(&self) -> Option<&PadPage> {
        self.pages.values().next()
    }

    /// Pop and mark as burned the lowest-ID unused page.
    pub fn pop_next(&mut self) -> Result<PadPage, OtpError> {
        let Some((page_id, page)) = self.pages.pop_first() else {
            return Err(OtpError::PadExhausted);
        };
        self.burned.insert(page_id);
        Ok(page)
    }

    /// Pop and mark as burned a specific unused page by `page_id`.
    pub fn pop_page(&mut self, page_id: u64) -> Result<PadPage, OtpError> {
        if self.burned.contains(&page_id) {
            return Err(OtpError::PageAlreadyBurned(page_id));
        }
        let Some(page) = self.pages.remove(&page_id) else {
            return Err(OtpError::PageNotFound(page_id));
        };
        self.burned.insert(page_id);
        Ok(page)
    }

    /// Permanently burn and zeroize a specific unused page by `page_id`.
    pub fn burn(&mut self, page_id: u64) -> Result<(), OtpError> {
        let page = self.pop_page(page_id)?;
        drop(page); // Explicitly invokes PadPage::drop -> volatile zeroize.
        Ok(())
    }

    /// Atomically append new pages to this book, rejecting any duplicate or previously burned IDs.
    pub fn append_pages(&mut self, pages: Vec<PadPage>) -> Result<(), OtpError> {
        if pages.is_empty() {
            return Ok(());
        }

        // Validate entire batch before mutating state.
        let mut seen = BTreeSet::new();
        for page in &pages {
            if page.enc_key_len() != self.enc_key_bytes {
                return Err(OtpError::KeyLengthMismatch {
                    expected: self.enc_key_bytes,
                    actual: page.enc_key_len(),
                });
            }
            if self.burned.contains(&page.page_id)
                || self.pages.contains_key(&page.page_id)
                || !seen.insert(page.page_id)
            {
                return Err(OtpError::DuplicatePageId(page.page_id));
            }
        }

        for page in pages {
            let next = page.page_id.saturating_add(1);
            if next > self.next_id {
                self.next_id = next;
            }
            self.pages.insert(page.page_id, page);
        }

        Ok(())
    }
}

impl fmt::Debug for MemPadBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemPadBook")
            .field("enc_key_bytes", &self.enc_key_bytes)
            .field("remaining", &self.pages.len())
            .field("burned_count", &self.burned.len())
            .field("next_page_id", &self.next_id)
            .finish()
    }
}

impl PadBook for MemPadBook {
    fn enc_key_bytes(&self) -> usize {
        self.enc_key_bytes()
    }
    fn remaining(&self) -> usize {
        self.remaining()
    }
    fn next_page_id(&self) -> u64 {
        self.next_page_id()
    }
    fn is_burned(&self, page_id: u64) -> bool {
        self.is_burned(page_id)
    }
    fn peek_unused(&self, page_id: u64) -> Option<&PadPage> {
        self.peek_unused(page_id)
    }
    fn peek_next(&self) -> Option<&PadPage> {
        self.peek_next()
    }
    fn pop_next(&mut self) -> Result<PadPage, OtpError> {
        self.pop_next()
    }
    fn pop_page(&mut self, page_id: u64) -> Result<PadPage, OtpError> {
        self.pop_page(page_id)
    }
    fn burn(&mut self, page_id: u64) -> Result<(), OtpError> {
        self.burn(page_id)
    }
    fn append_pages(&mut self, pages: Vec<PadPage>) -> Result<(), OtpError> {
        self.append_pages(pages)
    }
}

/// Crash-safe, disk-backed one-time pad book with an append-only Write-Ahead Log (`*.wal`).
///
/// # Durability & Zero Two-Time-Pad Guarantee
/// Before ANY popped page is returned to the caller (or any burn completes):
/// 1. A `BURN(page_id)` record is appended to `<path>.wal` and `File::sync_all()` (`fsync`) is called.
/// 2. The page's `state`, `mac_r`, `mac_s`, and `enc_key` bytes in `<path>` are overwritten in place
///    with zeros and `File::sync_all()` (`fsync`) is called.
/// 3. Only then is the page removed from RAM and returned/dropped.
///
/// On recovery (`WalPadBook::open`), the WAL is replayed first; any page marked burned in the WAL
/// whose disk slot was not yet wiped (due to a crash between step 1 and step 2) is immediately
/// zeroed on disk and `fsync`ed before the book becomes usable.
pub struct WalPadBook {
    data_path: PathBuf,
    wal_path: PathBuf,
    data_file: File,
    wal_file: File,
    enc_key_bytes: usize,
    pages: BTreeMap<u64, PadPage>,
    slot_map: BTreeMap<u64, u64>, // page_id -> record slot index in data_file
    burned: BTreeSet<u64>,
    total_slots: u64,
    next_id: u64,
}

impl WalPadBook {
    /// Compute the companion WAL path (`<path>.wal`) for a given pad data file path.
    pub fn wal_path_for(path: &Path) -> PathBuf {
        let mut os = path.as_os_str().to_os_string();
        os.push(".wal");
        PathBuf::from(os)
    }

    /// Path to the binary pad data file.
    #[inline]
    pub fn data_path(&self) -> &Path {
        &self.data_path
    }

    /// Path to the companion append-only WAL file.
    #[inline]
    pub fn wal_path(&self) -> &Path {
        &self.wal_path
    }

    /// Create (or re-initialize) a crash-safe `WalPadBook` on disk with `initial_pages`.
    pub fn create(
        path: impl AsRef<Path>,
        enc_key_bytes: usize,
        initial_pages: Vec<PadPage>,
    ) -> Result<Self, OtpError> {
        if enc_key_bytes > MAX_SANE_ENC_KEY_BYTES {
            return Err(OtpError::CorruptStorage(format!(
                "enc_key_bytes {enc_key_bytes} exceeds limit {MAX_SANE_ENC_KEY_BYTES}"
            )));
        }

        let data_path = path.as_ref().to_path_buf();
        let wal_path = Self::wal_path_for(&data_path);

        if let Some(parent) = data_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let mut data_file = open_secret_file(&data_path, true)?;
        let mut wal_file = open_secret_file(&wal_path, true)?;

        // Write fixed 24-byte data header.
        let mut header = [0u8; PAD_HEADER_LEN as usize];
        header[0..8].copy_from_slice(PAD_MAGIC);
        header[8..12].copy_from_slice(&PAD_VERSION.to_be_bytes());
        header[12..16].copy_from_slice(&(enc_key_bytes as u32).to_be_bytes());
        data_file.write_all(&header)?;
        data_file.sync_all()?;

        // Write 8-byte WAL header.
        wal_file.write_all(WAL_MAGIC)?;
        wal_file.sync_all()?;

        let mut book = Self {
            data_path,
            wal_path,
            data_file,
            wal_file,
            enc_key_bytes,
            pages: BTreeMap::new(),
            slot_map: BTreeMap::new(),
            burned: BTreeSet::new(),
            total_slots: 0,
            next_id: 0,
        };

        book.append_pages(initial_pages)?;
        Ok(book)
    }

    /// Generate a synchronized pair of crash-safe `WalPadBook`s persisted at `path_a` and `path_b`.
    pub fn generate_pair(
        path_a: impl AsRef<Path>,
        path_b: impl AsRef<Path>,
        num_pages: usize,
        enc_key_bytes: usize,
    ) -> Result<(Self, Self), OtpError> {
        let mut pages_a = Vec::with_capacity(num_pages);
        let mut pages_b = Vec::with_capacity(num_pages);
        for i in 0..num_pages {
            let p_a = PadPage::generate(i as u64, enc_key_bytes);
            let p_b = p_a.duplicate_for_peer();
            pages_a.push(p_a);
            pages_b.push(p_b);
        }
        let book_a = Self::create(path_a, enc_key_bytes, pages_a)?;
        let book_b = Self::create(path_b, enc_key_bytes, pages_b)?;
        Ok((book_a, book_b))
    }

    /// Open and crash-recover an existing `WalPadBook` from disk.
    ///
    /// Replays `<path>.wal`, burns and overwrites with zeros any page whose WAL burn record
    /// was committed prior to an unclean shutdown, and truncates incomplete trailing records.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OtpError> {
        let data_path = path.as_ref().to_path_buf();
        let wal_path = Self::wal_path_for(&data_path);

        let mut data_file = open_secret_file(&data_path, false)?;
        let data_len = data_file.metadata()?.len();
        if data_len < PAD_HEADER_LEN {
            return Err(OtpError::CorruptStorage(
                "pad file shorter than header".into(),
            ));
        }

        // Read & validate header.
        let mut header = [0u8; PAD_HEADER_LEN as usize];
        data_file.seek(SeekFrom::Start(0))?;
        data_file.read_exact(&mut header)?;
        if &header[0..8] != PAD_MAGIC {
            return Err(OtpError::CorruptStorage("invalid pad file magic".into()));
        }
        let version = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        if version != PAD_VERSION {
            return Err(OtpError::CorruptStorage(format!(
                "unsupported pad file version {version}"
            )));
        }
        let enc_key_bytes =
            u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
        if enc_key_bytes > MAX_SANE_ENC_KEY_BYTES {
            return Err(OtpError::CorruptStorage(format!(
                "invalid enc_key_bytes {enc_key_bytes}"
            )));
        }

        let record_size = Self::record_size_for(enc_key_bytes);
        let body_len = data_len - PAD_HEADER_LEN;
        let total_slots = body_len / record_size as u64;
        let valid_len = PAD_HEADER_LEN + total_slots * record_size as u64;

        let mut needs_data_sync = false;
        if valid_len != data_len {
            // Truncate incomplete trailing record from an interrupted append.
            data_file.set_len(valid_len)?;
            needs_data_sync = true;
        }

        // Read all page slots from the data file.
        let mut pages = BTreeMap::new();
        let mut slot_map = BTreeMap::new();
        let mut burned = BTreeSet::new();
        let mut next_id: u64 = 0;

        let mut rec_buf = vec![0u8; record_size];
        let mut slots_needing_wipe: Vec<u64> = Vec::new();

        data_file.seek(SeekFrom::Start(PAD_HEADER_LEN))?;
        for slot_idx in 0..total_slots {
            data_file.read_exact(&mut rec_buf)?;
            let page_id = u64::from_be_bytes(rec_buf[0..8].try_into().unwrap());
            let state = rec_buf[8];
            let next = page_id.saturating_add(1);
            if next > next_id {
                next_id = next;
            }

            match state {
                PAGE_STATE_BURNED => {
                    burned.insert(page_id);
                    // Defense-in-depth: if any key byte in a burned slot is non-zero, wipe it.
                    if rec_buf[9..].iter().any(|&b| b != 0) {
                        slots_needing_wipe.push(slot_idx);
                    }
                }
                PAGE_STATE_ACTIVE => {
                    if burned.contains(&page_id) || pages.contains_key(&page_id) {
                        zeroize_slice(&mut rec_buf);
                        return Err(OtpError::CorruptStorage(format!(
                            "duplicate page_id {page_id} in pad file"
                        )));
                    }
                    let mac_r = u128::from_be_bytes(rec_buf[9..25].try_into().unwrap());
                    let mac_s = u128::from_be_bytes(rec_buf[25..41].try_into().unwrap());
                    let enc_key = rec_buf[41..41 + enc_key_bytes].to_vec();
                    let page = PadPage::from_raw(page_id, enc_key, mac_r, mac_s);
                    pages.insert(page_id, page);
                    slot_map.insert(page_id, slot_idx);
                }
                other => {
                    zeroize_slice(&mut rec_buf);
                    return Err(OtpError::CorruptStorage(format!(
                        "invalid page state byte 0x{other:02x} at slot {slot_idx}"
                    )));
                }
            }
        }
        zeroize_slice(&mut rec_buf);

        // Open (or create if absent) and replay the WAL.
        let mut wal_file = if wal_path.exists() {
            open_secret_file(&wal_path, false)?
        } else {
            let mut f = open_secret_file(&wal_path, true)?;
            f.write_all(WAL_MAGIC)?;
            f.sync_all()?;
            f
        };

        let wal_len = wal_file.metadata()?.len();
        let mut wal_burned = BTreeSet::new();

        if wal_len == 0 {
            wal_file.write_all(WAL_MAGIC)?;
            wal_file.sync_all()?;
        } else {
            if wal_len < WAL_HEADER_LEN {
                return Err(OtpError::CorruptStorage(
                    "WAL file shorter than magic header".into(),
                ));
            }
            let mut wal_hdr = [0u8; WAL_HEADER_LEN as usize];
            wal_file.seek(SeekFrom::Start(0))?;
            wal_file.read_exact(&mut wal_hdr)?;
            if &wal_hdr != WAL_MAGIC {
                return Err(OtpError::CorruptStorage("invalid WAL magic header".into()));
            }

            let wal_body = wal_len - WAL_HEADER_LEN;
            let num_wal_recs = wal_body / WAL_RECORD_LEN as u64;
            let mut valid_wal_end = WAL_HEADER_LEN;
            let mut wal_rec = [0u8; WAL_RECORD_LEN];

            for i in 0..num_wal_recs {
                wal_file.read_exact(&mut wal_rec)?;
                let op = wal_rec[0];
                let pid = u64::from_be_bytes(wal_rec[1..9].try_into().unwrap());
                let pid_inv = u64::from_be_bytes(wal_rec[9..17].try_into().unwrap());
                if op == WAL_OP_BURN && pid_inv == !pid {
                    wal_burned.insert(pid);
                    valid_wal_end = WAL_HEADER_LEN + (i + 1) * WAL_RECORD_LEN as u64;
                } else {
                    // Torn WAL record at tail: stop replay and truncate tail.
                    break;
                }
            }

            if valid_wal_end != wal_len {
                wal_file.set_len(valid_wal_end)?;
                wal_file.sync_all()?;
            }
        }

        // Reconcile WAL burns against active slots (completes any burn interrupted before wipe).
        for pid in wal_burned {
            burned.insert(pid);
            let next = pid.saturating_add(1);
            if next > next_id {
                next_id = next;
            }
            if let Some(page) = pages.remove(&pid) {
                drop(page); // Volatile zeroize in RAM.
            }
            if let Some(slot_idx) = slot_map.remove(&pid) {
                slots_needing_wipe.push(slot_idx);
            }
        }

        if !slots_needing_wipe.is_empty() {
            let zeros = vec![0u8; 1 + 16 + 16 + enc_key_bytes];
            for slot_idx in slots_needing_wipe {
                let offset = Self::slot_wipe_offset(slot_idx, record_size)?;
                data_file.seek(SeekFrom::Start(offset))?;
                data_file.write_all(&zeros)?;
            }
            needs_data_sync = true;
        }

        if needs_data_sync {
            data_file.sync_all()?;
        }

        Ok(Self {
            data_path,
            wal_path,
            data_file,
            wal_file,
            enc_key_bytes,
            pages,
            slot_map,
            burned,
            total_slots,
            next_id,
        })
    }

    #[inline]
    fn record_size_for(enc_key_bytes: usize) -> usize {
        PAGE_META_BYTES + enc_key_bytes
    }

    #[inline]
    fn slot_wipe_offset(slot_idx: u64, record_size: usize) -> Result<u64, OtpError> {
        let rec_off = slot_idx
            .checked_mul(record_size as u64)
            .and_then(|v| PAD_HEADER_LEN.checked_add(v))
            .and_then(|v| v.checked_add(8)) // skip 8-byte page_id; overwrite state + mac_r + mac_s + enc_key
            .ok_or_else(|| OtpError::CorruptStorage("slot offset overflow".into()))?;
        Ok(rec_off)
    }

    /// Persist WAL burn record (`fsync`), then overwrite on-disk page key bytes with zeros (`fsync`).
    fn persist_burn_and_wipe(&mut self, page_id: u64, slot_idx: u64) -> Result<(), OtpError> {
        // Step 1: Append BURN record to WAL and fsync BEFORE touching data file or returning page.
        let mut wal_rec = [0u8; WAL_RECORD_LEN];
        wal_rec[0] = WAL_OP_BURN;
        wal_rec[1..9].copy_from_slice(&page_id.to_be_bytes());
        wal_rec[9..17].copy_from_slice(&(!page_id).to_be_bytes());
        self.wal_file.seek(SeekFrom::End(0))?;
        self.wal_file.write_all(&wal_rec)?;
        self.wal_file.sync_all()?;

        // Step 2: Overwrite state, mac_r, mac_s, and enc_key bytes on disk with zeros + fsync.
        let record_size = Self::record_size_for(self.enc_key_bytes);
        let wipe_offset = Self::slot_wipe_offset(slot_idx, record_size)?;
        let zeros = vec![0u8; 1 + 16 + 16 + self.enc_key_bytes];
        self.data_file.seek(SeekFrom::Start(wipe_offset))?;
        self.data_file.write_all(&zeros)?;
        self.data_file.sync_all()?;

        Ok(())
    }

    /// Configured encryption key size in bytes for pages in this book.
    #[inline]
    pub fn enc_key_bytes(&self) -> usize {
        self.enc_key_bytes
    }

    /// Number of unused pages currently available.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.pages.len()
    }

    /// Next monotonic `page_id` to allocate when replenishing this book.
    #[inline]
    pub fn next_page_id(&self) -> u64 {
        self.next_id
    }

    /// Returns `true` if `page_id` has been permanently burned.
    #[inline]
    pub fn is_burned(&self, page_id: u64) -> bool {
        self.burned.contains(&page_id)
    }

    /// Borrow an unused page by `page_id` without burning it.
    #[inline]
    pub fn peek_unused(&self, page_id: u64) -> Option<&PadPage> {
        self.pages.get(&page_id)
    }

    /// Borrow the lowest-ID unused page without burning it.
    #[inline]
    pub fn peek_next(&self) -> Option<&PadPage> {
        self.pages.values().next()
    }

    /// Crash-safely burn (WAL + disk zero-overwrite + fsync) and return the lowest-ID unused page.
    pub fn pop_next(&mut self) -> Result<PadPage, OtpError> {
        let Some(&page_id) = self.pages.keys().next() else {
            return Err(OtpError::PadExhausted);
        };
        self.pop_page(page_id)
    }

    /// Crash-safely burn (WAL + disk zero-overwrite + fsync) and return a specific unused page.
    pub fn pop_page(&mut self, page_id: u64) -> Result<PadPage, OtpError> {
        if self.burned.contains(&page_id) {
            return Err(OtpError::PageAlreadyBurned(page_id));
        }
        let Some(&slot_idx) = self.slot_map.get(&page_id) else {
            return Err(OtpError::PageNotFound(page_id));
        };

        // Durability FIRST: fsync WAL burn + fsync zeroed disk slot BEFORE returning page!
        self.persist_burn_and_wipe(page_id, slot_idx)?;

        // Only now update in-memory state and hand the page to the caller.
        self.slot_map.remove(&page_id);
        self.burned.insert(page_id);
        let page = self
            .pages
            .remove(&page_id)
            .expect("slot_map and pages must stay in sync");
        Ok(page)
    }

    /// Crash-safely burn and zeroize a specific unused page both on disk and in RAM.
    pub fn burn(&mut self, page_id: u64) -> Result<(), OtpError> {
        let page = self.pop_page(page_id)?;
        drop(page);
        Ok(())
    }

    /// Atomically persist and append new pages to disk (`fsync`) and memory.
    pub fn append_pages(&mut self, pages: Vec<PadPage>) -> Result<(), OtpError> {
        if pages.is_empty() {
            return Ok(());
        }

        // Validate batch before touching disk or state.
        let mut seen = BTreeSet::new();
        for page in &pages {
            if page.enc_key_len() != self.enc_key_bytes {
                return Err(OtpError::KeyLengthMismatch {
                    expected: self.enc_key_bytes,
                    actual: page.enc_key_len(),
                });
            }
            if self.burned.contains(&page.page_id)
                || self.pages.contains_key(&page.page_id)
                || !seen.insert(page.page_id)
            {
                return Err(OtpError::DuplicatePageId(page.page_id));
            }
        }

        let record_size = Self::record_size_for(self.enc_key_bytes);
        let mut buf = vec![0u8; record_size * pages.len()];
        for (i, page) in pages.iter().enumerate() {
            let base = i * record_size;
            buf[base..base + 8].copy_from_slice(&page.page_id.to_be_bytes());
            buf[base + 8] = PAGE_STATE_ACTIVE;
            buf[base + 9..base + 25].copy_from_slice(&page.mac_r().to_be_bytes());
            buf[base + 25..base + 41].copy_from_slice(&page.mac_s().to_be_bytes());
            buf[base + 41..base + 41 + self.enc_key_bytes].copy_from_slice(page.enc_key());
        }

        let write_res = (|| -> io::Result<()> {
            self.data_file.seek(SeekFrom::End(0))?;
            self.data_file.write_all(&buf)?;
            self.data_file.sync_all()?;
            Ok(())
        })();
        zeroize_slice(&mut buf);
        write_res?;

        for page in pages {
            let slot_idx = self.total_slots;
            self.total_slots += 1;
            let next = page.page_id.saturating_add(1);
            if next > self.next_id {
                self.next_id = next;
            }
            self.slot_map.insert(page.page_id, slot_idx);
            self.pages.insert(page.page_id, page);
        }

        Ok(())
    }
}

impl fmt::Debug for WalPadBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalPadBook")
            .field("data_path", &self.data_path)
            .field("wal_path", &self.wal_path)
            .field("enc_key_bytes", &self.enc_key_bytes)
            .field("remaining", &self.pages.len())
            .field("burned_count", &self.burned.len())
            .field("next_page_id", &self.next_id)
            .finish()
    }
}

impl PadBook for WalPadBook {
    fn enc_key_bytes(&self) -> usize {
        self.enc_key_bytes()
    }
    fn remaining(&self) -> usize {
        self.remaining()
    }
    fn next_page_id(&self) -> u64 {
        self.next_page_id()
    }
    fn is_burned(&self, page_id: u64) -> bool {
        self.is_burned(page_id)
    }
    fn peek_unused(&self, page_id: u64) -> Option<&PadPage> {
        self.peek_unused(page_id)
    }
    fn peek_next(&self) -> Option<&PadPage> {
        self.peek_next()
    }
    fn pop_next(&mut self) -> Result<PadPage, OtpError> {
        self.pop_next()
    }
    fn pop_page(&mut self, page_id: u64) -> Result<PadPage, OtpError> {
        self.pop_page(page_id)
    }
    fn burn(&mut self, page_id: u64) -> Result<(), OtpError> {
        self.burn(page_id)
    }
    fn append_pages(&mut self, pages: Vec<PadPage>) -> Result<(), OtpError> {
        self.append_pages(pages)
    }
}

/// Open a pad or WAL file with owner-only permissions (`0600`) on Unix.
fn open_secret_file(path: &Path, create_truncate: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    if create_truncate {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    opts.mode(0o600);
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    fn unique_temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        std::env::temp_dir().join(format!("vernam_otp_test_{label}_{pid}_{nanos}.pad"))
    }

    fn cleanup_wal_files(data_path: &Path) {
        let _ = fs::remove_file(data_path);
        let _ = fs::remove_file(WalPadBook::wal_path_for(data_path));
    }

    #[test]
    fn test_otp_xor_word_level_and_malleability_caught_by_mac() {
        // Test across unaligned, exact 8-byte, and multi-block lengths.
        for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 31, 63, 64, 255, FRAME_BYTES, 513] {
            let mut plaintext = vec![0u8; len];
            let mut key = vec![0u8; len];
            fill_os_random(&mut plaintext);
            fill_os_random(&mut key);

            let ct = otp_xor(&plaintext, &key).unwrap();
            let expected: Vec<u8> = plaintext.iter().zip(&key).map(|(a, b)| a ^ b).collect();
            assert_eq!(ct, expected, "word-level XOR diverged at len={len}");

            let mut recovered = ct.clone();
            otp_xor_in_place(&mut recovered, &key).unwrap();
            assert_eq!(recovered, plaintext, "in-place XOR roundtrip failed at len={len}");
        }

        // Key shorter than data must fail.
        assert!(matches!(
            otp_xor(&[1, 2, 3, 4], &[1, 2, 3]),
            Err(OtpError::KeyTooShort {
                required: 4,
                available: 3
            })
        ));

        // OTP malleability caught by Carter-Wegman MAC.
        let page = PadPage::generate(42, FRAME_BYTES);
        let msg = b"PAY ALICE 100 VRNM";
        let (mut ct_frame, tag) = seal_frame(&page, msg).unwrap();

        // Legitimate decryption succeeds.
        assert_eq!(open_frame(&page, &ct_frame, &tag).unwrap(), msg);

        // Attacker flips a single bit in ciphertext (classic OTP malleability attack).
        ct_frame[10] ^= 0x01;
        assert!(matches!(
            open_frame(&page, &ct_frame, &tag),
            Err(OtpError::AuthenticationFailed)
        ));

        // Standalone carter_wegman_mac / verify_mac catches single-bit flip in data or tag.
        let raw_tag = carter_wegman_mac(&ct_frame, page.mac_r(), page.mac_s());
        assert!(verify_mac(&ct_frame, page.mac_r(), page.mac_s(), &raw_tag));

        let mut bad_tag = raw_tag;
        bad_tag[15] ^= 0x80;
        assert!(!verify_mac(&ct_frame, page.mac_r(), page.mac_s(), &bad_tag));

        let mut bad_data = ct_frame;
        bad_data[0] ^= 0x01;
        assert!(!verify_mac(&bad_data, page.mac_r(), page.mac_s(), &raw_tag));
    }

    #[test]
    fn test_carter_wegman_injectivity_and_single_block_unforgeability() {
        let r = random_field_elem();
        let s = random_field_elem();

        // Distinct byte strings with trailing zeros and empty input must produce distinct tags.
        let inputs: &[&[u8]] = &[
            b"",
            b"\x00",
            b"\x00\x00",
            b"\x01",
            b"\x00\x01",
            b"\x01\x00",
            &[0x00; 15],
            &[0x00; 16],
            &[0xFF; 15],
            &[0xFF; 16],
        ];
        let mut tags = BTreeSet::new();
        for inp in inputs {
            let t = carter_wegman_mac(inp, r, s);
            assert!(verify_mac(inp, r, s, &t));
            assert!(tags.insert(t), "MAC collision detected for input {inp:?}");
        }

        // Verify 1-chunk messages depend multiplicatively on `r` (not merely `m_0 + s`).
        let r_fixed = 123456789u128;
        let s_fixed = 987654321u128;
        let t_a = u128::from_be_bytes(carter_wegman_mac(b"A", r_fixed, s_fixed));
        let t_b = u128::from_be_bytes(carter_wegman_mac(b"B", r_fixed, s_fixed));
        // m("B") - m("A") == 1, so t_b - t_a == 1 * r_fixed (mod PRIME_P), NOT 1!
        let diff = if t_b >= t_a {
            t_b - t_a
        } else {
            PRIME_P - (t_a - t_b)
        };
        assert_eq!(diff, r_fixed);
    }

    #[test]
    fn test_framing_roundtrip_and_validation() {
        for payload in [
            &b""[..],
            &b"hi"[..],
            &[0xAB; 127][..],
            &[0x55; MAX_PAYLOAD_BYTES][..],
        ] {
            let frame = pack_frame(payload).unwrap();
            assert_eq!(frame.len(), FRAME_BYTES);
            let unpacked = unpack_frame(&frame).unwrap();
            assert_eq!(unpacked.as_slice(), payload);
        }

        // Oversized payload rejected.
        assert!(matches!(
            pack_frame(&[0u8; MAX_PAYLOAD_BYTES + 1]),
            Err(OtpError::PayloadTooLarge { .. })
        ));

        // Corrupt padding detected.
        let mut frame = pack_frame(b"ok").unwrap();
        frame[FRAME_BYTES - 1] = 0x01;
        assert!(matches!(
            unpack_frame(&frame),
            Err(OtpError::InvalidFramePadding)
        ));

        // Out-of-range length prefix detected.
        let mut bad_len = [0u8; FRAME_BYTES];
        bad_len[0..2].copy_from_slice(&((MAX_PAYLOAD_BYTES + 1) as u16).to_be_bytes());
        assert!(matches!(
            unpack_frame(&bad_len),
            Err(OtpError::InvalidFrameLength { .. })
        ));
    }

    #[test]
    fn test_drop_and_zeroize_behavior() {
        // Direct zeroize_slice / zeroize_u128 verification.
        let mut secret_buf = [0xAAu8; 64];
        zeroize_slice(&mut secret_buf);
        assert!(secret_buf.iter().all(|&b| b == 0));

        let mut secret_num = 0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0u128;
        zeroize_u128(&mut secret_num);
        assert_eq!(secret_num, 0);

        // Verify PadPage::zeroize (the exact logic executed by Drop::drop) wipes all secrets.
        let mut page = PadPage::from_raw(9, vec![0xCCu8; 64], 42, 99);
        assert!(page.enc_key().iter().all(|&b| b == 0xCC));
        assert_eq!(page.mac_r(), 42);
        assert_eq!(page.mac_s(), 99);

        page.zeroize();
        assert!(page.enc_key().iter().all(|&b| b == 0));
        assert_eq!(page.mac_r(), 0);
        assert_eq!(page.mac_s(), 0);

        // Verify Drop::drop actually runs when PadPage goes out of scope and when MemPadBook burns it.
        let before = TEST_DROP_COUNT.load(Ordering::SeqCst);
        drop(page);
        assert!(TEST_DROP_COUNT.load(Ordering::SeqCst) >= before + 1);

        let (mut a, mut b) = MemPadBook::generate_pair(3, FRAME_BYTES);
        assert_eq!(a.remaining(), 3);
        assert_eq!(a.next_page_id(), 3);
        let before_burn = TEST_DROP_COUNT.load(Ordering::SeqCst);
        a.burn(0).unwrap();
        assert!(TEST_DROP_COUNT.load(Ordering::SeqCst) >= before_burn + 1);
        assert!(a.is_burned(0));
        assert!(a.peek_unused(0).is_none());
        assert!(matches!(a.burn(0), Err(OtpError::PageAlreadyBurned(0))));
        assert!(matches!(
            a.append_pages(vec![PadPage::generate(0, FRAME_BYTES)]),
            Err(OtpError::DuplicatePageId(0))
        ));

        // Peer book still has matching page 1.
        let p_a1 = a.pop_next().unwrap();
        let p_b1 = b.pop_page(1).unwrap();
        assert_eq!(p_a1.page_id, 1);
        assert_eq!(p_a1.enc_key(), p_b1.enc_key());
        assert_eq!(p_a1.mac_r(), p_b1.mac_r());
        assert_eq!(p_a1.mac_s(), p_b1.mac_s());

        // Redacted Debug never leaks key material.
        let dbg_str = format!("{p_a1:?}");
        assert!(dbg_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_wal_pad_book_crash_reload_and_disk_zeroize() {
        let path = unique_temp_path("reload");
        cleanup_wal_files(&path);

        let initial_pages = vec![
            PadPage::from_raw(0, vec![0xA5; FRAME_BYTES], 0x1111_2222, 0x3333_4444),
            PadPage::from_raw(1, vec![0x5A; FRAME_BYTES], 0x5555_6666, 0x7777_8888),
            PadPage::from_raw(2, vec![0x3C; FRAME_BYTES], 0x9999_AAAA, 0xBBBB_CCCC),
        ];

        {
            let mut book = WalPadBook::create(&path, FRAME_BYTES, initial_pages).unwrap();
            assert_eq!(book.remaining(), 3);
            assert_eq!(book.next_page_id(), 3);

            // Pop page 0 -> WAL fsync + disk zero-overwrite + fsync.
            let p0 = book.pop_next().unwrap();
            assert_eq!(p0.page_id, 0);
            assert!(p0.enc_key().iter().all(|&b| b == 0xA5));
            assert_eq!(book.remaining(), 2);
        }

        // Inspect raw bytes on disk: slot 0 must have state=0x00 and all key/MAC bytes zeroed!
        let disk_bytes = fs::read(&path).unwrap();
        let rec_size = PAGE_META_BYTES + FRAME_BYTES;
        let slot0 = &disk_bytes[PAD_HEADER_LEN as usize..PAD_HEADER_LEN as usize + rec_size];
        assert_eq!(u64::from_be_bytes(slot0[0..8].try_into().unwrap()), 0);
        assert_eq!(slot0[8], PAGE_STATE_BURNED);
        assert!(
            slot0[9..].iter().all(|&b| b == 0),
            "burned page 0 key/MAC bytes on disk were NOT zeroed!"
        );

        // Slot 1 must still be intact and active.
        let slot1 = &disk_bytes
            [PAD_HEADER_LEN as usize + rec_size..PAD_HEADER_LEN as usize + 2 * rec_size];
        assert_eq!(u64::from_be_bytes(slot1[0..8].try_into().unwrap()), 1);
        assert_eq!(slot1[8], PAGE_STATE_ACTIVE);
        assert!(slot1[41..].iter().all(|&b| b == 0x5A));

        // Simulate a sudden crash AFTER WAL fsync for page 1, BEFORE disk slot 1 was wiped!
        {
            let wal_path = WalPadBook::wal_path_for(&path);
            let mut wal = OpenOptions::new().append(true).open(&wal_path).unwrap();
            let mut wal_rec = [0u8; WAL_RECORD_LEN];
            wal_rec[0] = WAL_OP_BURN;
            wal_rec[1..9].copy_from_slice(&1u64.to_be_bytes());
            wal_rec[9..17].copy_from_slice(&(!1u64).to_be_bytes());
            wal.write_all(&wal_rec).unwrap();
            wal.sync_all().unwrap();
        }

        // Reload from disk: page 0 AND page 1 must both be burned/rejected, and slot 1 wiped!
        {
            let mut reloaded = WalPadBook::open(&path).unwrap();
            assert_eq!(reloaded.remaining(), 1);
            assert_eq!(reloaded.next_page_id(), 3);
            assert!(reloaded.is_burned(0));
            assert!(reloaded.is_burned(1));
            assert!(reloaded.peek_unused(0).is_none());
            assert!(reloaded.peek_unused(1).is_none());
            assert!(matches!(
                reloaded.pop_page(0),
                Err(OtpError::PageAlreadyBurned(0))
            ));
            assert!(matches!(
                reloaded.pop_page(1),
                Err(OtpError::PageAlreadyBurned(1))
            ));

            // Next pop MUST skip burned pages 0 and 1 and yield page 2.
            let p2 = reloaded.pop_next().unwrap();
            assert_eq!(p2.page_id, 2);
            assert!(p2.enc_key().iter().all(|&b| b == 0x3C));
            assert!(matches!(reloaded.pop_next(), Err(OtpError::PadExhausted)));

            // Refill starting at next_page_id() works and persists cleanly.
            let refill_id = reloaded.next_page_id();
            reloaded
                .append_pages(vec![PadPage::generate(refill_id, FRAME_BYTES)])
                .unwrap();
            assert_eq!(reloaded.remaining(), 1);
            assert_eq!(reloaded.next_page_id(), 4);
        }

        // Verify recovery actually overwrote slot 1 on disk with zeros too!
        let disk_after = fs::read(&path).unwrap();
        let slot1_after = &disk_after
            [PAD_HEADER_LEN as usize + rec_size..PAD_HEADER_LEN as usize + 2 * rec_size];
        assert_eq!(slot1_after[8], PAGE_STATE_BURNED);
        assert!(
            slot1_after[9..].iter().all(|&b| b == 0),
            "WAL-recovered page 1 key/MAC bytes on disk were NOT zeroed!"
        );

        cleanup_wal_files(&path);
    }

    #[test]
    fn test_throughput_10k_otp_and_mac() {
        let page = PadPage::generate(0, FRAME_BYTES);
        let payload = b"VRNM-TX|from=alice|to=bob|amount=42000|nonce=99887766";
        let start = Instant::now();

        for i in 0u32..10_000 {
            let mut frame = pack_frame(payload).unwrap();
            frame[2] ^= (i & 0xFF) as u8;
            otp_xor_in_place(&mut frame, page.enc_key()).unwrap();
            let tag = carter_wegman_mac(&frame, page.mac_r(), page.mac_s());
            assert!(verify_mac(&frame, page.mac_r(), page.mac_s(), &tag));
            otp_xor_in_place(&mut frame, page.enc_key()).unwrap();
            frame[2] ^= (i & 0xFF) as u8;
            let unpacked = unpack_frame(&frame).unwrap();
            assert_eq!(unpacked.as_slice(), payload);
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 5,
            "10,000 OTP+MAC ops unexpectedly slow: {elapsed:?}"
        );
    }
}
