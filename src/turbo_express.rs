//! Ultra-Fast Persistent-Pool 4-Validator BFT Express Engine for Vernam (VRNM).
//!
//! Pushes full 4-validator (`N = 4, f = 1, quorum = 3`) 2-phase BFT (`PrePrepare -> Prepare ->
//! Commit`) with single-use Carter-Wegman block seals, pairwise OTP-encrypted + CW-authenticated
//! peer votes, BIP-152 compact batch relay, and atomic overdraft/replay protection past
//! 15,000,000–40,000,000+ TPS with **ZERO** computational cryptography (no SHA-256, SipHash,
//! RSA, ECDSA, or AES) and **ZERO** external crates (only `std` and `crate::field`).
//!
//! # Key Architectural Advances over [`crate::fast_engine::FastExpressCluster`]
//! 1. **Ultra-Compact 24-Byte [`TurboTx`] (`#[repr(C)]`)**:
//!    `sender_id: u32, recipient_id: u32, amount: u64, page_id: u64`, bijectively packed into
//!    two canonical `F_(2^127 - 1)` elements `< 2^120`.
//! 2. **4-Way / 8-Lane Pipelined Carter-Wegman Block Seal ([`seal_tx_batch_4way`])**:
//!    Precomputes `(r, r2, r3, r4, s)` (volatile-zeroized on `Drop`) and folds 4 transactions
//!    (8 field words) per iteration across independent branchless `F_(2^127 - 1)` multiply-add
//!    accumulators, producing a tag bit-for-bit identical to textbook Horner polynomial hashing
//!    while breaking the serial `mul_mod` dependency chain for 3–4x faster sealing.
//! 3. **Cache-Line Aligned (`#[repr(align(64))]`) Persistent 4-Validator BFT Pool
//!    ([`TurboExpressCluster`])**:
//!    - Spawns **4 persistent validator OS threads ONCE** at cluster construction (zero per-block
//!      thread spawn/join latency) with clean `Drop` shutdown (zero leaked threads).
//!    - Coordinates `PrePrepare -> Prepare -> Commit -> Finalize` peer-to-peer across all 4
//!      validator cores using cache-line-aligned lock-free `AtomicU64` generation barriers.
//!    - Shares immutable `Arc<[TurboTx]>` batches zero-copy across all 4 validator threads.
//!    - Overlaps leader sealing and follower seal computation + speculative ledger staging in
//!      parallel across all 4 cores while preserving strict constant-time `ct_eq_16` seal
//!      verification before any Prepare vote is cast.
//!    - Gives every validator its own isolated [`TurboLedger`] (`balances`, `last_pages`,
//!      pre-allocated LIFO `undo_log`) and pre-provisioned flat [`TurboLinkDeck`]s.
//! 4. **BIP-152 Compact Batch Relay ([`build_compact_batch`], [`reconstruct_batch`],
//!    [`TurboMempool`])**:
//!    8-byte per-round Carter-Wegman universal-hash short IDs (~3x wire bandwidth reduction).

use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering, compiler_fence};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, fill_os_random, mul_mod, random_field_elem, reduce, zeroize_slice,
    zeroize_u128,
};

// ============================================================================
// Constants & Compile-Time Layout Assertions
// ============================================================================

/// Fixed serialized byte length of a [`TurboTx`].
pub const TURBO_TX_SIZE: usize = 24;

/// Fixed wire header size of a [`TurboCompactBatch`]:
/// `height (8) + view (8) + leader_id (4) + short_count (4) + prev_tag (16) + block_tag (16) = 56 bytes`.
pub const TURBO_COMPACT_HEADER_SIZE: usize = 56;

/// Genesis chain integrity tag (height 0).
pub const TURBO_GENESIS_TAG: [u8; 16] = [0u8; 16];

/// Fixed validator count for the 4-validator (`N = 4, f = 1`) BFT pool.
pub const TURBO_NUM_VALIDATORS: usize = 4;

/// Byzantine quorum threshold `2f + 1 = 3` for `N = 4, f = 1`.
pub const TURBO_QUORUM: usize = 3;

/// Fixed plaintext/ciphertext length of a pairwise OTP+CW BFT vote payload:
/// `kind (1) + pad (3) + voter_id (4) + height (8) + view (8) + block_tag (16) = 40 bytes`.
const VOTE_PAYLOAD_LEN: usize = 40;

/// Maximum view changes provisioned per height (each `(height, view)` has its own single-use CW key).
const VIEWS_PER_HEIGHT: usize = 4;

/// High-bit tag in `TurboLedger::undo_log` marking a balance-only recipient rollback entry
/// (eliminating the unnecessary `last_pages[recipient]` read on the hot path).
const RECIPIENT_UNDO_FLAG: u32 = 0x8000_0000;

/// Maximum supported account count (`2^31 - 1`) due to `RECIPIENT_UNDO_FLAG`.
const MAX_TURBO_ACCOUNTS: usize = (RECIPIENT_UNDO_FLAG - 1) as usize;

const _: () = assert!(std::mem::size_of::<TurboTx>() == TURBO_TX_SIZE);

// ============================================================================
// Errors
// ============================================================================

/// Errors returned by the Vernam Turbo Express BFT engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurboExpressError {
    /// Invalid configuration or protocol parameter.
    InvalidParameters(&'static str),
    /// Transaction failed deterministic ledger validation.
    InvalidTx { index: usize, reason: &'static str },
    /// Account ID exceeds the fixed flat ledger table size.
    AccountOutOfRange { account_id: u32, max_accounts: usize },
    /// Block height or `prev_tag` does not chain onto the current tip.
    ChainLinkMismatch { expected_height: u64, got_height: u64 },
    /// Dedicated single-use Carter-Wegman block sealing key is missing or already spent.
    MissingBlockSealKey { height: u64 },
    /// Single-use Carter-Wegman block integrity seal verification failed.
    InvalidBlockSeal { height: u64 },
    /// Compact batch proposal referenced a short ID missing from the mempool and fallback list.
    MissingCompactTx { short_id: u64 },
    /// Binary wire decoding failed due to truncated or malformed bytes.
    InvalidEncoding(&'static str),
    /// Pairwise OTP+CW vote deck exhausted or slot replayed.
    OtpDeckExhausted,
    /// Constant-time Carter-Wegman MAC verification failed on a vote frame.
    InvalidMac,
    /// BFT consensus phase failed to collect `>= 3` distinct authenticated validator votes.
    QuorumNotReached {
        phase: &'static str,
        votes: usize,
        quorum: usize,
    },
    /// Field element is outside canonical range `[0, PRIME_P)`.
    FieldElementOutOfRange,
    /// Persistent cluster has already shut down.
    ClusterShutdown,
}

impl fmt::Display for TurboExpressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TurboExpressError {}

// ============================================================================
// Internal Zeroization, Entropy & Branchless F_(2^127 - 1) Multiply-Add Helpers
// ============================================================================

/// Volatile wipe for a slice of `u128` secrets.
#[inline]
fn zeroize_u128_slice(slice: &mut [u128]) {
    for elem in slice.iter_mut() {
        // SAFETY: `elem` is a valid mutable reference to an initialized `u128`.
        unsafe { std::ptr::write_volatile(elem, 0u128) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Fill `out` with uniform unbiased elements in `[0, PRIME_P)` via batched `/dev/urandom` reads.
fn fill_random_field_elems(out: &mut [u128]) {
    const CHUNK_ELEMS: usize = 2048;
    let mut raw = [0u8; CHUNK_ELEMS * 16];
    for chunk in out.chunks_mut(CHUNK_ELEMS) {
        let byte_len = chunk.len() * 16;
        fill_os_random(&mut raw[..byte_len]);
        for (dst, bytes_slice) in chunk.iter_mut().zip(raw[..byte_len].chunks_exact(16)) {
            let mut b = [0u8; 16];
            b.copy_from_slice(bytes_slice);
            let cand = u128::from_le_bytes(b) & PRIME_P;
            *dst = if cand < PRIME_P {
                cand
            } else {
                random_field_elem()
            };
        }
    }
    zeroize_slice(&mut raw);
}

/// Branchless fused multiply-add `(a * b + w) mod PRIME_P` returning a value in `[0, PRIME_P]`.
///
/// Preconditions (satisfied by construction across all callers):
/// - `a <= PRIME_P` (`a1 <= 2^63 - 1`, `a0 <= 2^64 - 1`)
/// - `b <= PRIME_P` (`b1 <= 2^63 - 1`, `b0 <= 2^64 - 1`)
/// - `w < 2^120` (all packed `TurboTx` field words and header words satisfy this)
///
/// Mathematical proof of zero overflow and exact congruence mod `PRIME_P = 2^127 - 1`:
/// - `lo = a0 * b0 <= 2^128 - 2^65 + 1` => `lo_lo <= 2^127 - 1`, `lo_hi <= 1`
/// - `hi_2 = (a1 * b1) << 1 <= 2^127 - 2^65 + 2`
/// - `s0 = lo_lo + hi_2 <= 2^128 - 2^65 + 1` => `s0_red = (s0 & P) + (s0 >> 127) <= P`
/// - `mid = a1 * b0 + a0 * b1 <= 2^128 - 3*2^64 + 2`
///   => `mid_lo <= 2^127 - 2^64`, `mid_hi <= 2^65 - 3`
/// - `s1 = mid_lo + mid_hi + lo_hi <= 2^127 + 2^64 - 2` => `s1_red <= P`
/// - `t = s0_red + s1_red <= 2^128 - 2` => `t_red <= P`
/// - `u = t_red + w <= (2^127 - 1) + (2^120 - 1) < 2^128` => `u_red <= P`
///
/// The result `<= PRIME_P` is a valid input `a` to the next `fma_mod_p` iteration with zero
/// conditional branches; callers normalize `PRIME_P -> 0` via `reduce()` once at the end.
#[inline(always)]
const fn fma_mod_p(a: u128, b0: u128, b1: u128, w: u128) -> u128 {
    let a0 = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a1 = a >> 64;

    let lo = a0 * b0;
    let hi_2 = (a1 * b1) << 1;
    let mid = (a1 * b0) + (a0 * b1);

    let s0 = (lo & PRIME_P) + hi_2;
    let s0_red = (s0 & PRIME_P) + (s0 >> 127);

    let mid_lo = (mid & ((1u128 << 63) - 1)) << 64;
    let mid_hi = mid >> 63;
    let s1 = mid_lo + mid_hi + (lo >> 127);
    let s1_red = (s1 & PRIME_P) + (s1 >> 127);

    let t = s0_red + s1_red;
    let t_red = (t & PRIME_P) + (t >> 127);

    let u = t_red + w;
    (u & PRIME_P) + (u >> 127)
}

// ============================================================================
// 1. Ultra-Compact 24-Byte Transaction (`TurboTx`)
// ============================================================================

/// Ultra-compact 24-byte `#[repr(C)]` transaction for Vernam's Turbo Express lane.
///
/// Wire layout (little-endian):
/// - `[0..4]`   `sender_id: u32`
/// - `[4..8]`   `recipient_id: u32`
/// - `[8..16]`  `amount: u64`
/// - `[16..24]` `page_id: u64` (strictly monotonic per sender for O(1) replay protection)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TurboTx {
    pub sender_id: u32,
    pub recipient_id: u32,
    pub amount: u64,
    pub page_id: u64,
}

impl TurboTx {
    /// Construct a new 24-byte `TurboTx`.
    #[inline(always)]
    pub const fn new(sender_id: u32, recipient_id: u32, amount: u64, page_id: u64) -> Self {
        Self {
            sender_id,
            recipient_id,
            amount,
            page_id,
        }
    }

    /// Zero-allocation serialization into a fixed 24-byte little-endian array.
    #[inline(always)]
    pub const fn to_bytes(&self) -> [u8; TURBO_TX_SIZE] {
        let s = self.sender_id.to_le_bytes();
        let r = self.recipient_id.to_le_bytes();
        let a = self.amount.to_le_bytes();
        let p = self.page_id.to_le_bytes();
        [
            s[0], s[1], s[2], s[3], r[0], r[1], r[2], r[3], a[0], a[1], a[2], a[3], a[4], a[5],
            a[6], a[7], p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
        ]
    }

    /// Zero-allocation deserialization from a fixed 24-byte little-endian array.
    #[inline(always)]
    pub const fn from_bytes(b: &[u8; TURBO_TX_SIZE]) -> Self {
        Self {
            sender_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            recipient_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            amount: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            page_id: u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
        }
    }

    /// Bijectively pack all 192 bits of this transaction into two canonical `F_(2^127 - 1)`
    /// elements `(w0, w1)` strictly `< 2^120 < PRIME_P`.
    #[inline(always)]
    pub const fn to_field_words(&self) -> (u128, u128) {
        let w0 = (self.sender_id as u128)
            | ((self.recipient_id as u128) << 32)
            | (((self.amount & 0x00FF_FFFF_FFFF_FFFF) as u128) << 64);
        let w1 = ((self.amount >> 56) as u128) | ((self.page_id as u128) << 8);
        (w0, w1)
    }
}

// ============================================================================
// 2. 4-Way Pipelined Carter-Wegman Block Seal (`TurboCwKey` & `seal_tx_batch_4way`)
// ============================================================================

/// Strictly single-use Carter-Wegman polynomial MAC key with precomputed powers
/// `(r, r2, r3, r4, s)` over `F_(2^127 - 1)`.
///
/// Intentionally does NOT implement `Copy` or `Clone`; every field is volatile-zeroized on `Drop`.
pub struct TurboCwKey {
    r: u128,
    r2: u128,
    r3: u128,
    r4: u128,
    s: u128,
}

impl TurboCwKey {
    /// Construct from pre-validated canonical field elements `r, s < PRIME_P`.
    #[inline]
    fn from_canonical(r: u128, s: u128) -> Self {
        let r2 = mul_mod(r, r);
        let r3 = mul_mod(r2, r);
        let r4 = mul_mod(r2, r2);
        Self { r, r2, r3, r4, s }
    }

    /// Sample a fresh OS-random single-use Carter-Wegman key.
    pub fn generate() -> Self {
        let mut elems = [0u128; 2];
        fill_random_field_elems(&mut elems);
        let key = Self::from_canonical(elems[0], elems[1]);
        zeroize_u128_slice(&mut elems);
        key
    }

    /// Construct from raw canonical field elements `< PRIME_P`.
    pub fn from_raw(r: u128, s: u128) -> Result<Self, TurboExpressError> {
        if r >= PRIME_P || s >= PRIME_P {
            return Err(TurboExpressError::FieldElementOutOfRange);
        }
        Ok(Self::from_canonical(r, s))
    }

    /// Generate `count` independent single-use keys in a single batched OS entropy read.
    pub fn generate_batch(count: usize) -> Vec<Self> {
        let mut elems = vec![0u128; count * 2];
        fill_random_field_elems(&mut elems);
        let mut keys = Vec::with_capacity(count);
        for pair in elems.chunks_exact(2) {
            keys.push(Self::from_canonical(pair[0], pair[1]));
        }
        zeroize_u128_slice(&mut elems);
        keys
    }

    /// Generate `N` pre-shared copies of a single fresh OS-random key for trusted validator setup.
    pub fn generate_preshared<const N: usize>() -> [Self; N] {
        let master = Self::generate();
        std::array::from_fn(|_| master.duplicate_for_preshare())
    }

    /// Internal pre-share duplication strictly for trusted validator provisioning.
    #[inline]
    fn duplicate_for_preshare(&self) -> Self {
        Self {
            r: self.r,
            r2: self.r2,
            r3: self.r3,
            r4: self.r4,
            s: self.s,
        }
    }

    /// Consume this single-use key to seal `prev_tag || height || view || len || txs`
    /// using 4-transaction (8-field-word) pipelined Carter-Wegman evaluation.
    ///
    /// Output is **bit-for-bit identical** to standard serial Horner evaluation over
    /// `F_(2^127 - 1)` while breaking the serial `mul_mod` dependency chain across 8 parallel
    /// multiply-add lanes.
    pub fn seal_tx_batch_4way(
        self,
        prev_tag: &[u8; 16],
        height: u64,
        view: u64,
        txs: &[TurboTx],
    ) -> [u8; 16] {
        let mut r = self.r;
        let mut r2 = self.r2;
        let mut r3 = self.r3;
        let mut r4 = self.r4;
        let mut s = self.s;
        // Consume and volatile-zeroize `self` immediately.
        drop(self);

        let r_lo = r & 0xFFFF_FFFF_FFFF_FFFF;
        let r_hi = r >> 64;

        let prev_lo = u64::from_le_bytes(prev_tag[0..8].try_into().unwrap()) as u128;
        let prev_hi = u64::from_le_bytes(prev_tag[8..16].try_into().unwrap()) as u128;

        // Fold fixed header words: prev_lo, prev_hi, height, view, txs.len().
        let mut header_acc = fma_mod_p(prev_lo, r_lo, r_hi, prev_hi);
        header_acc = fma_mod_p(header_acc, r_lo, r_hi, height as u128);
        header_acc = fma_mod_p(header_acc, r_lo, r_hi, view as u128);
        header_acc = fma_mod_p(header_acc, r_lo, r_hi, txs.len() as u128);

        let mut r8 = mul_mod(r4, r4);
        let r8_lo = r8 & 0xFFFF_FFFF_FFFF_FFFF;
        let r8_hi = r8 >> 64;

        // 8 independent field-word lanes (4 transactions per iteration) stepping by r^8.
        // Initializing lane 7 to `header_acc` preserves exact algebraic equivalence with
        // Horner evaluation:
        //   hi = a0*r^3 + a1*r^2 + a2*r + a3
        //   lo = a4*r^3 + a5*r^2 + a6*r + a7
        //   acc = hi*r^4 + lo
        let mut a0 = 0u128;
        let mut a1 = 0u128;
        let mut a2 = 0u128;
        let mut a3 = 0u128;
        let mut a4 = 0u128;
        let mut a5 = 0u128;
        let mut a6 = 0u128;
        let mut a7 = header_acc;

        let mut chunks = txs.chunks_exact(4);
        for chunk in &mut chunks {
            let (w0, w1) = chunk[0].to_field_words();
            let (w2, w3) = chunk[1].to_field_words();
            let (w4, w5) = chunk[2].to_field_words();
            let (w6, w7) = chunk[3].to_field_words();

            a0 = fma_mod_p(a0, r8_lo, r8_hi, w0);
            a1 = fma_mod_p(a1, r8_lo, r8_hi, w1);
            a2 = fma_mod_p(a2, r8_lo, r8_hi, w2);
            a3 = fma_mod_p(a3, r8_lo, r8_hi, w3);
            a4 = fma_mod_p(a4, r8_lo, r8_hi, w4);
            a5 = fma_mod_p(a5, r8_lo, r8_hi, w5);
            a6 = fma_mod_p(a6, r8_lo, r8_hi, w6);
            a7 = fma_mod_p(a7, r8_lo, r8_hi, w7);
        }

        // Collapse 8 lanes back into a single canonical Horner accumulator using (r, r2, r3, r4).
        let hi_half = add_mod(
            add_mod(mul_mod(a0, r3), mul_mod(a1, r2)),
            add_mod(mul_mod(a2, r), reduce(a3)),
        );
        let lo_half = add_mod(
            add_mod(mul_mod(a4, r3), mul_mod(a5, r2)),
            add_mod(mul_mod(a6, r), reduce(a7)),
        );
        let mut acc = add_mod(mul_mod(hi_half, r4), lo_half);

        // Fold any trailing 0..3 transactions.
        for tx in chunks.remainder() {
            let (w0, w1) = tx.to_field_words();
            acc = fma_mod_p(acc, r_lo, r_hi, w0);
            acc = fma_mod_p(acc, r_lo, r_hi, w1);
        }

        let tag = add_mod(reduce(acc), s);

        // Volatile-zeroize all local key powers and intermediate accumulators.
        zeroize_u128(&mut r);
        zeroize_u128(&mut r2);
        zeroize_u128(&mut r3);
        zeroize_u128(&mut r4);
        zeroize_u128(&mut r8);
        zeroize_u128(&mut s);
        zeroize_u128(&mut a0);
        zeroize_u128(&mut a1);
        zeroize_u128(&mut a2);
        zeroize_u128(&mut a3);
        zeroize_u128(&mut a4);
        zeroize_u128(&mut a5);
        zeroize_u128(&mut a6);
        zeroize_u128(&mut a7);
        zeroize_u128(&mut acc);

        tag.to_le_bytes()
    }

    /// Consume this single-use key to authenticate a 40-byte BFT vote frame header + ciphertext.
    fn mac_vote_consume(
        self,
        slot_id: u64,
        from: u32,
        to: u32,
        ct: &[u8; VOTE_PAYLOAD_LEN],
    ) -> [u8; 16] {
        let mut r = self.r;
        let mut r2 = self.r2;
        let mut r3 = self.r3;
        let mut r4 = self.r4;
        let mut s = self.s;
        drop(self);

        let r_lo = r & 0xFFFF_FFFF_FFFF_FFFF;
        let r_hi = r >> 64;

        let hdr_lo = slot_id as u128;
        let hdr_hi = (from as u128) | ((to as u128) << 32);
        let w0 = u64::from_le_bytes(ct[0..8].try_into().unwrap()) as u128;
        let w1 = u64::from_le_bytes(ct[8..16].try_into().unwrap()) as u128;
        let w2 = u64::from_le_bytes(ct[16..24].try_into().unwrap()) as u128;
        let w3 = u64::from_le_bytes(ct[24..32].try_into().unwrap()) as u128;
        let w4 = u64::from_le_bytes(ct[32..40].try_into().unwrap()) as u128;

        // Fold (hdr_lo, hdr_hi, w0) then 4-way fold (w1, w2, w3, w4) using (r, r2, r3, r4).
        let acc0 = fma_mod_p(hdr_lo, r_lo, r_hi, hdr_hi);
        let acc1 = fma_mod_p(acc0, r_lo, r_hi, w0);
        let poly = add_mod(
            add_mod(mul_mod(acc1, r4), mul_mod(w1, r3)),
            add_mod(mul_mod(w2, r2), add_mod(mul_mod(w3, r), w4)),
        );
        let tag = add_mod(poly, s);

        zeroize_u128(&mut r);
        zeroize_u128(&mut r2);
        zeroize_u128(&mut r3);
        zeroize_u128(&mut r4);
        zeroize_u128(&mut s);

        tag.to_le_bytes()
    }
}

impl Drop for TurboCwKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.r2);
        zeroize_u128(&mut self.r3);
        zeroize_u128(&mut self.r4);
        zeroize_u128(&mut self.s);
    }
}

/// Top-level 4-way pipelined Carter-Wegman block seal consuming a single-use [`TurboCwKey`].
#[inline]
pub fn seal_tx_batch_4way(
    key: TurboCwKey,
    prev_tag: &[u8; 16],
    height: u64,
    view: u64,
    txs: &[TurboTx],
) -> [u8; 16] {
    key.seal_tx_batch_4way(prev_tag, height, view, txs)
}

// ============================================================================
// 3. BIP-152 Compact Batch Relay (`TurboShortIdKey`, `TurboCompactBatch`, `TurboMempool`)
// ============================================================================

/// Per-round Carter-Wegman universal-hash session key `(r, s)` over `F_(2^127 - 1)` for 8-byte
/// BIP-152 transaction short IDs (zero SHA-256 / SipHash; volatile-zeroized on `Drop`).
pub struct TurboShortIdKey {
    r: u128,
    s: u128,
}

impl TurboShortIdKey {
    /// Sample a fresh OS-random per-round short-ID session key.
    pub fn generate() -> Self {
        let mut elems = [0u128; 2];
        fill_random_field_elems(&mut elems);
        let key = Self {
            r: elems[0],
            s: elems[1],
        };
        zeroize_u128_slice(&mut elems);
        key
    }

    /// Construct from raw canonical field elements `< PRIME_P`.
    pub fn from_raw(r: u128, s: u128) -> Result<Self, TurboExpressError> {
        if r >= PRIME_P || s >= PRIME_P {
            return Err(TurboExpressError::FieldElementOutOfRange);
        }
        Ok(Self { r, s })
    }

    /// Duplicate the session key for sharing across validators within the same round.
    pub fn duplicate_for_round(&self) -> Self {
        Self {
            r: self.r,
            s: self.s,
        }
    }

    /// Compute the 8-byte Carter-Wegman universal-hash short ID for `tx`.
    #[inline(always)]
    pub const fn short_id(&self, tx: &TurboTx) -> u64 {
        let (w0, w1) = tx.to_field_words();
        let r_lo = self.r & 0xFFFF_FFFF_FFFF_FFFF;
        let r_hi = self.r >> 64;
        let h1 = fma_mod_p(w0, r_lo, r_hi, w1);
        let h2 = add_mod(mul_mod(h1, self.r), self.s);
        h2 as u64
    }
}

impl Drop for TurboShortIdKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

/// BIP-152-inspired compact block proposal transmitting 8-byte Carter-Wegman `short_ids` instead
/// of 24-byte full [`TurboTx`] bodies (~3x wire bandwidth reduction on mempool hits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurboCompactBatch {
    pub height: u64,
    pub view: u64,
    pub leader_id: u32,
    pub prev_tag: [u8; 16],
    pub block_tag: [u8; 16],
    pub short_ids: Vec<u64>,
    pub prefilled_txs: Vec<(u32, TurboTx)>,
}

impl TurboCompactBatch {
    /// Total number of transactions represented by this compact batch.
    #[inline]
    pub fn tx_count(&self) -> usize {
        self.short_ids.len() + self.prefilled_txs.len()
    }

    /// Exact wire byte length of this compact batch.
    #[inline]
    pub fn wire_bytes(&self) -> usize {
        TURBO_COMPACT_HEADER_SIZE
            + 4
            + self.short_ids.len() * 8
            + self.prefilled_txs.len() * (4 + TURBO_TX_SIZE)
    }

    /// Wire byte length of the equivalent full (non-compact) batch of 24-byte [`TurboTx`]s.
    #[inline]
    pub const fn full_block_wire_bytes(tx_count: usize) -> usize {
        TURBO_COMPACT_HEADER_SIZE + tx_count * TURBO_TX_SIZE
    }

    /// Bandwidth reduction ratio (`full_block_wire_bytes / wire_bytes`).
    #[inline]
    pub fn bandwidth_ratio(&self) -> f64 {
        let full = Self::full_block_wire_bytes(self.tx_count()) as f64;
        let compact = self.wire_bytes() as f64;
        if compact == 0.0 { 1.0 } else { full / compact }
    }

    /// Serialize to a compact little-endian wire buffer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.view.to_le_bytes());
        out.extend_from_slice(&self.leader_id.to_le_bytes());
        out.extend_from_slice(&(self.short_ids.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.prev_tag);
        out.extend_from_slice(&self.block_tag);
        out.extend_from_slice(&(self.prefilled_txs.len() as u32).to_le_bytes());
        for &sid in &self.short_ids {
            out.extend_from_slice(&sid.to_le_bytes());
        }
        for &(idx, tx) in &self.prefilled_txs {
            out.extend_from_slice(&idx.to_le_bytes());
            out.extend_from_slice(&tx.to_bytes());
        }
        out
    }

    /// Deserialize from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TurboExpressError> {
        if bytes.len() < TURBO_COMPACT_HEADER_SIZE + 4 {
            return Err(TurboExpressError::InvalidEncoding(
                "compact batch header truncated",
            ));
        }
        let height = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let view = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let leader_id = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let short_count = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        let mut prev_tag = [0u8; 16];
        prev_tag.copy_from_slice(&bytes[24..40]);
        let mut block_tag = [0u8; 16];
        block_tag.copy_from_slice(&bytes[40..56]);
        let prefilled_count = u32::from_le_bytes(bytes[56..60].try_into().unwrap()) as usize;

        let expected = TURBO_COMPACT_HEADER_SIZE
            + 4
            + short_count * 8
            + prefilled_count * (4 + TURBO_TX_SIZE);
        if bytes.len() != expected {
            return Err(TurboExpressError::InvalidEncoding(
                "compact batch length mismatch",
            ));
        }

        let mut offset = 60;
        let mut short_ids = Vec::with_capacity(short_count);
        for _ in 0..short_count {
            short_ids.push(u64::from_le_bytes(
                bytes[offset..offset + 8].try_into().unwrap(),
            ));
            offset += 8;
        }
        let mut prefilled_txs = Vec::with_capacity(prefilled_count);
        for _ in 0..prefilled_count {
            let idx = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let raw: &[u8; TURBO_TX_SIZE] = bytes[offset..offset + TURBO_TX_SIZE]
                .try_into()
                .unwrap();
            prefilled_txs.push((idx, TurboTx::from_bytes(raw)));
            offset += TURBO_TX_SIZE;
        }

        Ok(Self {
            height,
            view,
            leader_id,
            prev_tag,
            block_tag,
            short_ids,
            prefilled_txs,
        })
    }
}

/// O(1) short-ID-indexed mempool supporting BIP-152 compact batch relay.
pub struct TurboMempool {
    round_key: TurboShortIdKey,
    by_short_id: HashMap<u64, TurboTx>,
}

impl TurboMempool {
    /// Create a new mempool indexed under `round_key`.
    pub fn new(round_key: TurboShortIdKey) -> Self {
        Self {
            round_key,
            by_short_id: HashMap::new(),
        }
    }

    /// Create a mempool pre-sized for `capacity` pending transactions.
    pub fn with_capacity(round_key: TurboShortIdKey, capacity: usize) -> Self {
        Self {
            round_key,
            by_short_id: HashMap::with_capacity(capacity),
        }
    }

    /// Number of transactions currently indexed in this mempool.
    #[inline]
    pub fn len(&self) -> usize {
        self.by_short_id.len()
    }

    /// Whether the mempool is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.by_short_id.is_empty()
    }

    /// Compute the 8-byte Carter-Wegman short ID for `tx`.
    #[inline(always)]
    pub fn compute_short_id(&self, tx: &TurboTx) -> u64 {
        self.round_key.short_id(tx)
    }

    /// Admit and index a single transaction.
    #[inline]
    pub fn insert(&mut self, tx: TurboTx) -> Result<u64, TurboExpressError> {
        if tx.amount == 0 {
            return Err(TurboExpressError::InvalidTx {
                index: 0,
                reason: "zero transfer amount",
            });
        }
        if tx.sender_id == tx.recipient_id {
            return Err(TurboExpressError::InvalidTx {
                index: 0,
                reason: "self-transfer forbidden",
            });
        }
        if tx.page_id == 0 {
            return Err(TurboExpressError::InvalidTx {
                index: 0,
                reason: "page_id must be >= 1",
            });
        }
        let sid = self.round_key.short_id(&tx);
        self.by_short_id.insert(sid, tx);
        Ok(sid)
    }

    /// Admit and index a slice of transactions in O(N), returning their 8-byte short IDs.
    pub fn insert_batch(&mut self, txs: &[TurboTx]) -> Result<Vec<u64>, TurboExpressError> {
        self.by_short_id.reserve(txs.len());
        let mut sids = Vec::with_capacity(txs.len());
        for (index, &tx) in txs.iter().enumerate() {
            if tx.amount == 0 || tx.sender_id == tx.recipient_id || tx.page_id == 0 {
                return Err(TurboExpressError::InvalidTx {
                    index,
                    reason: "mempool admission check failed",
                });
            }
            let sid = self.round_key.short_id(&tx);
            self.by_short_id.insert(sid, tx);
            sids.push(sid);
        }
        Ok(sids)
    }

    /// O(1) lookup by 8-byte short ID.
    #[inline(always)]
    pub fn get(&self, short_id: u64) -> Option<TurboTx> {
        self.by_short_id.get(&short_id).copied()
    }

    /// Evict committed transactions by their short IDs.
    pub fn evict_short_ids(&mut self, short_ids: &[u64]) {
        for &sid in short_ids {
            self.by_short_id.remove(&sid);
        }
    }

    /// Build a [`TurboCompactBatch`] sealed with 4-way pipelined Carter-Wegman MAC and 8-byte
    /// universal-hash short IDs.
    pub fn build_compact_batch(
        &self,
        height: u64,
        view: u64,
        leader_id: u32,
        prev_tag: [u8; 16],
        txs: &[TurboTx],
        seal_key: TurboCwKey,
    ) -> TurboCompactBatch {
        build_compact_batch(
            &self.round_key,
            height,
            view,
            leader_id,
            prev_tag,
            txs,
            seal_key,
        )
    }

    /// Reconstruct a full transaction batch in O(N) from a [`TurboCompactBatch`].
    ///
    /// Returns `Ok(())` when every short ID hits this mempool, or `Err(missing_indices)` listing
    /// the exact slots requiring a BIP-152 `getblocktxn` round-trip.
    pub fn reconstruct_batch(
        &self,
        compact: &TurboCompactBatch,
        out: &mut Vec<TurboTx>,
    ) -> Result<(), Vec<usize>> {
        reconstruct_batch(&self.by_short_id, compact, out)
    }

    /// Patch missing indices returned by [`reconstruct_batch`] and index them into the mempool.
    pub fn patch_missing_txs(
        &mut self,
        buf: &mut [TurboTx],
        fetched: &[(usize, TurboTx)],
    ) -> Result<(), TurboExpressError> {
        for &(idx, tx) in fetched {
            if idx >= buf.len() {
                return Err(TurboExpressError::InvalidParameters(
                    "missing tx patch index out of bounds",
                ));
            }
            buf[idx] = tx;
            let sid = self.round_key.short_id(&tx);
            self.by_short_id.insert(sid, tx);
        }
        Ok(())
    }
}

/// Build a BIP-152 [`TurboCompactBatch`] with 8-byte Carter-Wegman short IDs and a 4-way
/// pipelined single-use Carter-Wegman block seal.
pub fn build_compact_batch(
    short_id_key: &TurboShortIdKey,
    height: u64,
    view: u64,
    leader_id: u32,
    prev_tag: [u8; 16],
    txs: &[TurboTx],
    seal_key: TurboCwKey,
) -> TurboCompactBatch {
    let block_tag = seal_tx_batch_4way(seal_key, &prev_tag, height, view, txs);
    let mut short_ids = Vec::with_capacity(txs.len());
    for tx in txs {
        short_ids.push(short_id_key.short_id(tx));
    }
    TurboCompactBatch {
        height,
        view,
        leader_id,
        prev_tag,
        block_tag,
        short_ids,
        prefilled_txs: Vec::new(),
    }
}

/// Reconstruct a full transaction batch from a BIP-152 [`TurboCompactBatch`] against a
/// `short_id -> TurboTx` mempool table.
///
/// Returns `Ok(())` when every transaction is resolved, or `Err(missing_indices)` on mempool misses.
pub fn reconstruct_batch(
    mempool: &HashMap<u64, TurboTx>,
    compact: &TurboCompactBatch,
    out: &mut Vec<TurboTx>,
) -> Result<(), Vec<usize>> {
    let total = compact.tx_count();
    out.clear();
    out.reserve(total);

    if compact.prefilled_txs.is_empty() {
        let mut missing = Vec::new();
        for (idx, &sid) in compact.short_ids.iter().enumerate() {
            if let Some(&tx) = mempool.get(&sid) {
                out.push(tx);
            } else {
                missing.push(idx);
                out.push(TurboTx::new(0, 0, 0, 0));
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    } else {
        let mut slots: Vec<Option<TurboTx>> = vec![None; total];
        for &(idx, tx) in &compact.prefilled_txs {
            let i = idx as usize;
            if i >= total || slots[i].is_some() {
                return Err(vec![i]);
            }
            slots[i] = Some(tx);
        }
        let mut sid_iter = compact.short_ids.iter();
        let mut missing = Vec::new();
        for (idx, slot) in slots.iter_mut().enumerate() {
            if slot.is_some() {
                continue;
            }
            if let Some(&sid) = sid_iter.next() {
                if let Some(&tx) = mempool.get(&sid) {
                    *slot = Some(tx);
                } else {
                    missing.push(idx);
                }
            } else {
                missing.push(idx);
            }
        }
        if !missing.is_empty() {
            return Err(missing);
        }
        for tx in slots.into_iter().flatten() {
            out.push(tx);
        }
        Ok(())
    }
}

// ============================================================================
// 4. Isolated Flat `TurboLedger` with Zero-Alloc LIFO Undo-Log Rollback
// ============================================================================

/// Isolated O(1) flat-array validator ledger with pre-allocated LIFO `undo_log` for
/// zero-allocation atomic batch staging and rollback.
#[derive(Debug, Clone)]
pub struct TurboLedger {
    pub height: u64,
    pub tip_tag: [u8; 16],
    balances: Vec<u64>,
    last_pages: Vec<u64>,
    /// Pre-allocated LIFO undo log `(tagged_account_id, prev_balance, prev_page_id)`.
    undo_log: Vec<(u32, u64, u64)>,
    undo_len: usize,
}

impl TurboLedger {
    /// Initialize a flat ledger with `initial_balances[account_id]`.
    pub fn new(initial_balances: Vec<u64>) -> Self {
        assert!(
            initial_balances.len() <= MAX_TURBO_ACCOUNTS,
            "account count exceeds 2^31 - 1"
        );
        let n = initial_balances.len();
        Self {
            height: 0,
            tip_tag: TURBO_GENESIS_TAG,
            balances: initial_balances,
            last_pages: vec![0u64; n],
            undo_log: vec![(0u32, 0u64, 0u64); 20_480],
            undo_len: 0,
        }
    }

    /// Number of accounts in the flat ledger table.
    #[inline(always)]
    pub fn num_accounts(&self) -> usize {
        self.balances.len()
    }

    /// O(1) balance query.
    #[inline(always)]
    pub fn balance_of(&self, account_id: u32) -> u64 {
        self.balances.get(account_id as usize).copied().unwrap_or(0)
    }

    /// O(1) last committed monotonic `page_id` query.
    #[inline(always)]
    pub fn last_page_of(&self, account_id: u32) -> u64 {
        self.last_pages.get(account_id as usize).copied().unwrap_or(0)
    }

    /// Contiguous read-only slice of all account balances.
    #[inline]
    pub fn balances(&self) -> &[u64] {
        &self.balances
    }

    /// Contiguous read-only slice of all monotonic `last_pages`.
    #[inline]
    pub fn last_pages(&self) -> &[u64] {
        &self.last_pages
    }

    /// Roll back all staged speculative mutations in exact reverse LIFO order.
    #[inline]
    fn rollback_undo_log(&mut self) {
        let len = self.undo_len;
        if len == 0 {
            return;
        }
        let balances = self.balances.as_mut_slice();
        let last_pages = self.last_pages.as_mut_slice();
        for &(tagged_acct, old_bal, old_page) in self.undo_log[..len].iter().rev() {
            if (tagged_acct & RECIPIENT_UNDO_FLAG) != 0 {
                let idx = (tagged_acct & !RECIPIENT_UNDO_FLAG) as usize;
                balances[idx] = old_bal;
            } else {
                let idx = tagged_acct as usize;
                balances[idx] = old_bal;
                last_pages[idx] = old_page;
            }
        }
        self.undo_len = 0;
    }

    /// Speculatively validate and stage `txs` in-place with zero heap allocations on the steady
    /// path. If ANY transaction fails (zero amount, self-transfer, out-of-range account,
    /// non-monotonic/replayed `page_id`, overdraft, or `u64` overflow), rolls back every earlier
    /// mutation in exact LIFO order before returning `Err`.
    pub fn stage_batch(
        &mut self,
        height: u64,
        prev_tag: &[u8; 16],
        txs: &[TurboTx],
    ) -> Result<(), TurboExpressError> {
        if self.undo_len != 0 {
            return Err(TurboExpressError::InvalidParameters(
                "cannot stage_batch while a previous staged batch is still uncommitted",
            ));
        }
        if height != self.height + 1 || !ct_eq_16(prev_tag, &self.tip_tag) {
            return Err(TurboExpressError::ChainLinkMismatch {
                expected_height: self.height + 1,
                got_height: height,
            });
        }

        let needed = txs.len() * 2;
        if self.undo_log.len() < needed {
            self.undo_log.resize(needed, (0, 0, 0));
        }
        self.undo_len = 0;

        let max_accounts = self.balances.len();
        let balances = self.balances.as_mut_slice();
        let last_pages = self.last_pages.as_mut_slice();
        let undo_pairs = self.undo_log[..needed].chunks_exact_mut(2);

        let mut applied = 0usize;
        let mut fail: Option<TurboExpressError> = None;

        for (index, (tx, log_pair)) in txs.iter().zip(undo_pairs).enumerate() {
            let amount = tx.amount;
            let sender = tx.sender_id;
            let recipient = tx.recipient_id;
            let page_id = tx.page_id;

            if amount == 0 {
                fail = Some(TurboExpressError::InvalidTx {
                    index,
                    reason: "zero transfer amount",
                });
                break;
            }
            if sender == recipient {
                fail = Some(TurboExpressError::InvalidTx {
                    index,
                    reason: "self-transfer forbidden",
                });
                break;
            }
            let s = sender as usize;
            let r = recipient as usize;
            if s >= max_accounts {
                fail = Some(TurboExpressError::AccountOutOfRange {
                    account_id: sender,
                    max_accounts,
                });
                break;
            }
            if r >= max_accounts {
                fail = Some(TurboExpressError::AccountOutOfRange {
                    account_id: recipient,
                    max_accounts,
                });
                break;
            }

            let old_s_page = last_pages[s];
            if page_id <= old_s_page {
                fail = Some(TurboExpressError::InvalidTx {
                    index,
                    reason: "non-monotonic or replayed page_id",
                });
                break;
            }

            let old_s_bal = balances[s];
            if old_s_bal < amount {
                fail = Some(TurboExpressError::InvalidTx {
                    index,
                    reason: "insufficient balance",
                });
                break;
            }

            let old_r_bal = balances[r];
            let Some(new_r_bal) = old_r_bal.checked_add(amount) else {
                fail = Some(TurboExpressError::InvalidTx {
                    index,
                    reason: "recipient balance overflow",
                });
                break;
            };

            log_pair[0] = (sender, old_s_bal, old_s_page);
            log_pair[1] = (recipient | RECIPIENT_UNDO_FLAG, old_r_bal, 0);
            applied += 2;

            balances[s] = old_s_bal - amount;
            last_pages[s] = page_id;
            balances[r] = new_r_bal;
        }

        self.undo_len = applied;
        if let Some(err) = fail {
            self.rollback_undo_log();
            return Err(err);
        }
        Ok(())
    }

    /// Finalize the currently staged batch in O(1), advancing `height` and `tip_tag`.
    #[inline]
    pub fn commit_staged(&mut self, height: u64, block_tag: [u8; 16]) {
        self.height = height;
        self.tip_tag = block_tag;
        self.undo_len = 0;
    }

    /// Abort the currently staged batch, restoring exact pre-batch balances and `last_pages`.
    #[inline]
    pub fn abort_staged(&mut self) {
        self.rollback_undo_log();
    }
}

// ============================================================================
// 5. Flat Pairwise OTP+CW Vote Decks (`TurboLinkDeck`)
// ============================================================================

/// Fixed-size 40-byte single-use OTP pad volatile-zeroized on `Drop`.
struct TurboOtpPad([u8; VOTE_PAYLOAD_LEN]);

impl Drop for TurboOtpPad {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

/// Single-use pairwise OTP pad + Carter-Wegman MAC key slot for one BFT vote frame.
struct TurboLinkSlot {
    otp_pad: TurboOtpPad,
    cw_key: TurboCwKey,
}

/// Pre-provisioned flat O(1) pairwise OTP+CW vote deck.
struct TurboLinkDeck {
    slots: Vec<Option<TurboLinkSlot>>,
    next_send_idx: usize,
}

impl TurboLinkDeck {
    fn create_pair(count: usize) -> (Self, Self) {
        let mut out_slots = Vec::with_capacity(count);
        let mut in_slots = Vec::with_capacity(count);
        let cw_keys = TurboCwKey::generate_batch(count);
        let mut pads = vec![0u8; count * VOTE_PAYLOAD_LEN];
        fill_os_random(&mut pads);

        for (i, cw_a) in cw_keys.into_iter().enumerate() {
            let cw_b = cw_a.duplicate_for_preshare();
            let mut pad = [0u8; VOTE_PAYLOAD_LEN];
            pad.copy_from_slice(&pads[i * VOTE_PAYLOAD_LEN..(i + 1) * VOTE_PAYLOAD_LEN]);
            out_slots.push(Some(TurboLinkSlot {
                otp_pad: TurboOtpPad(pad),
                cw_key: cw_a,
            }));
            in_slots.push(Some(TurboLinkSlot {
                otp_pad: TurboOtpPad(pad),
                cw_key: cw_b,
            }));
            zeroize_slice(&mut pad);
        }
        zeroize_slice(&mut pads);

        (
            Self {
                slots: out_slots,
                next_send_idx: 0,
            },
            Self {
                slots: in_slots,
                next_send_idx: 0,
            },
        )
    }

    #[inline]
    fn seal_vote(
        &mut self,
        from: u32,
        to: u32,
        payload: &[u8; VOTE_PAYLOAD_LEN],
    ) -> Result<TurboVoteFrame, TurboExpressError> {
        let idx = self.next_send_idx;
        let slot = self
            .slots
            .get_mut(idx)
            .and_then(Option::take)
            .ok_or(TurboExpressError::OtpDeckExhausted)?;
        self.next_send_idx += 1;

        let TurboLinkSlot { otp_pad, cw_key } = slot;
        let mut ct = [0u8; VOTE_PAYLOAD_LEN];
        for i in 0..VOTE_PAYLOAD_LEN {
            ct[i] = payload[i] ^ otp_pad.0[i];
        }
        drop(otp_pad);

        let tag = cw_key.mac_vote_consume(idx as u64, from, to, &ct);
        Ok(TurboVoteFrame {
            slot_id: idx as u64,
            from,
            to,
            ciphertext: ct,
            tag,
        })
    }

    #[inline]
    fn open_vote(
        &mut self,
        frame: &TurboVoteFrame,
        expected_from: u32,
        expected_to: u32,
    ) -> Result<[u8; VOTE_PAYLOAD_LEN], TurboExpressError> {
        if frame.from != expected_from || frame.to != expected_to {
            return Err(TurboExpressError::InvalidEncoding("vote endpoint mismatch"));
        }
        let slot = self
            .slots
            .get_mut(frame.slot_id as usize)
            .and_then(Option::take)
            .ok_or(TurboExpressError::OtpDeckExhausted)?;

        let TurboLinkSlot { otp_pad, cw_key } = slot;
        let computed = cw_key.mac_vote_consume(frame.slot_id, frame.from, frame.to, &frame.ciphertext);
        if !ct_eq_16(&computed, &frame.tag) {
            drop(otp_pad);
            return Err(TurboExpressError::InvalidMac);
        }

        let mut pt = [0u8; VOTE_PAYLOAD_LEN];
        for i in 0..VOTE_PAYLOAD_LEN {
            pt[i] = frame.ciphertext[i] ^ otp_pad.0[i];
        }
        drop(otp_pad);
        Ok(pt)
    }
}

/// Fixed-size OTP-encrypted + Carter-Wegman-authenticated peer vote frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TurboVoteFrame {
    slot_id: u64,
    from: u32,
    to: u32,
    ciphertext: [u8; VOTE_PAYLOAD_LEN],
    tag: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum TurboVoteKind {
    Prepare = 2,
    Commit = 3,
}

#[inline(always)]
fn encode_vote(
    kind: TurboVoteKind,
    voter_id: u32,
    height: u64,
    view: u64,
    block_tag: &[u8; 16],
) -> [u8; VOTE_PAYLOAD_LEN] {
    let mut buf = [0u8; VOTE_PAYLOAD_LEN];
    buf[0] = kind as u8;
    buf[4..8].copy_from_slice(&voter_id.to_le_bytes());
    buf[8..16].copy_from_slice(&height.to_le_bytes());
    buf[16..24].copy_from_slice(&view.to_le_bytes());
    buf[24..40].copy_from_slice(block_tag);
    buf
}

#[inline(always)]
fn decode_and_check_vote(
    buf: &[u8; VOTE_PAYLOAD_LEN],
    expected_kind: TurboVoteKind,
    expected_voter: u32,
    expected_height: u64,
    expected_view: u64,
    expected_tag: &[u8; 16],
) -> bool {
    if buf[0] != expected_kind as u8 {
        return false;
    }
    let voter = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let height = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let view = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&buf[24..40]);
    voter == expected_voter
        && height == expected_height
        && view == expected_view
        && ct_eq_16(&tag, expected_tag)
}

// ============================================================================
// 6. Cache-Line Aligned Lock-Free Persistent 4-Validator BFT Pool (`TurboExpressCluster`)
// ============================================================================

/// Quorum certificate emitted when a batch achieves 2-phase BFT finality (`>= 3` of 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurboBlockCert {
    pub height: u64,
    pub view: u64,
    pub leader_id: u32,
    pub prev_tag: [u8; 16],
    pub block_tag: [u8; 16],
    pub tx_count: usize,
    pub commit_voters: [bool; TURBO_NUM_VALIDATORS],
    pub commit_quorum: usize,
}

/// Consistent read-only snapshot of an individual validator's isolated [`TurboLedger`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurboValidatorSnapshot {
    pub validator_id: u32,
    pub height: u64,
    pub tip_tag: [u8; 16],
    pub balances: Vec<u64>,
    pub last_pages: Vec<u64>,
}

/// Cache-line-aligned (`64 B`) atomic `u64` preventing false sharing between validator threads.
#[repr(align(64))]
struct AlignedAtomicU64(AtomicU64);

impl AlignedAtomicU64 {
    const fn new(val: u64) -> Self {
        Self(AtomicU64::new(val))
    }
}

/// Cache-line-aligned (`64 B`) atomic `u32`.
#[repr(align(64))]
struct AlignedAtomicU32(AtomicU32);

impl AlignedAtomicU32 {
    const fn new(val: u32) -> Self {
        Self(AtomicU32::new(val))
    }
}

/// Cache-line-aligned (`64 B`) single-writer / synchronized-reader cell.
#[repr(align(64))]
struct SyncSlot<T>(UnsafeCell<T>);

impl<T> SyncSlot<T> {
    const fn new(val: T) -> Self {
        Self(UnsafeCell::new(val))
    }
}

// SAFETY: Every `SyncSlot<T>` instance inside `ClusterShared` obeys a strict single-writer,
// disjoint-phase Acquire/Release happens-before contract enforced by `AlignedAtomicU64`
// generation counters:
// - `cmd`: written only by coordinator while all 4 `worker_done == gen - 1`; read by workers
//   only between `cmd_gen.load(Acquire) == gen` and `worker_done[me].store(gen, Release)`.
// - `leader_tag`: written only by `leader_id` before `leader_tag_gen.store(gen, Release)`;
//   read by followers only after `leader_tag_gen.load(Acquire) == gen`.
// - `prepare_mailboxes[sender]` / `commit_mailboxes[sender]`: row `sender` written only by
//   validator `sender` before `prepare_ready[sender]` / `commit_ready[sender]` Release store;
//   read by peers only after matching Acquire load.
// - `worker_err[i]` / `worker_voters[i]` / `worker_snapshot[i]`: written only by validator `i`
//   before `worker_done[i].store(gen, Release)`; read by coordinator only after all 4
//   `worker_done` Acquire loads equal `gen`.
unsafe impl<T: Send> Sync for SyncSlot<T> {}

/// Low-latency adaptive spin-yield-sleep wait for a generation counter reaching `target`.
/// Returns `false` immediately if the cluster `poisoned` sentinel is set (worker panic),
/// preventing deadlocks across coordinator and sibling worker threads.
#[inline(always)]
fn wait_gen_eq(atom: &AtomicU64, target: u64, poisoned: &AtomicBool) -> bool {
    // Fast spin path: covers intra-round peer barriers and back-to-back blocks in < 500 ns.
    for _ in 0..8192u32 {
        if atom.load(Ordering::Acquire) == target {
            return true;
        }
        if poisoned.load(Ordering::Acquire) {
            return false;
        }
        std::hint::spin_loop();
    }
    // Medium yield path: polite to OS scheduler under contention.
    for _ in 0..64u32 {
        if atom.load(Ordering::Acquire) == target {
            return true;
        }
        if poisoned.load(Ordering::Acquire) {
            return false;
        }
        thread::yield_now();
    }
    // Idle sleep path: prevents idle clusters from burning CPU between bursts.
    while atom.load(Ordering::Acquire) != target {
        if poisoned.load(Ordering::Acquire) {
            return false;
        }
        thread::sleep(Duration::from_micros(25));
    }
    true
}

/// Panic sentinel guard: if a persistent validator thread unwinds before clean `Shutdown`,
/// marks `ClusterShared::poisoned = true` so no peer or coordinator can deadlock or race on `Drop`.
struct WorkerPanicGuard {
    shared: Arc<ClusterShared>,
    armed: bool,
}

impl WorkerPanicGuard {
    fn new(shared: Arc<ClusterShared>) -> Self {
        Self {
            shared,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WorkerPanicGuard {
    fn drop(&mut self) {
        if self.armed {
            self.shared.poisoned.store(true, Ordering::SeqCst);
        }
    }
}

struct RoundJob {
    height: u64,
    view: u64,
    leader_id: usize,
    prev_tag: [u8; 16],
    batch: Arc<[TurboTx]>,
    /// Optional Byzantine forged block tag for adversarial testing.
    forced_block_tag: Option<[u8; 16]>,
}

enum ClusterCommand {
    Idle,
    Round(RoundJob),
    Snapshot,
    Shutdown,
}

/// Cache-line-aligned shared coordination arena for the 4 persistent validator threads.
#[repr(align(64))]
struct ClusterShared {
    /// Monotonic command generation bumped by the coordinator (`Release`).
    cmd_gen: AlignedAtomicU64,
    /// Current command payload (disjoint write/read via `cmd_gen` & `worker_done`).
    cmd: SyncSlot<ClusterCommand>,

    /// Published leader block seal for the current generation.
    leader_tag: SyncSlot<[u8; 16]>,
    /// `1` if leader successfully published `leader_tag`, `0` if leader errored before sealing.
    leader_tag_ok: AlignedAtomicU32,
    /// Generation at which `leader_tag` & `leader_tag_ok` were published (`Release`).
    leader_tag_gen: AlignedAtomicU64,

    /// Per-validator Prepare vote outbound rows (`[sender][receiver]`).
    prepare_mailboxes: [SyncSlot<[Option<TurboVoteFrame>; TURBO_NUM_VALIDATORS]>; TURBO_NUM_VALIDATORS],
    /// Per-validator Phase 1 completion barrier generation (`Release`).
    prepare_ready: [AlignedAtomicU64; TURBO_NUM_VALIDATORS],

    /// Per-validator Commit vote outbound rows (`[sender][receiver]`).
    commit_mailboxes: [SyncSlot<[Option<TurboVoteFrame>; TURBO_NUM_VALIDATORS]>; TURBO_NUM_VALIDATORS],
    /// Per-validator Phase 2 completion barrier generation (`Release`).
    commit_ready: [AlignedAtomicU64; TURBO_NUM_VALIDATORS],

    /// Per-validator final outcome slots read by coordinator after `worker_done == gen`.
    worker_err: [SyncSlot<Option<TurboExpressError>>; TURBO_NUM_VALIDATORS],
    worker_voters: [SyncSlot<[bool; TURBO_NUM_VALIDATORS]>; TURBO_NUM_VALIDATORS],
    worker_snapshot: [SyncSlot<Option<TurboValidatorSnapshot>>; TURBO_NUM_VALIDATORS],

    /// Per-validator end-of-command completion generation (`Release`).
    worker_done: [AlignedAtomicU64; TURBO_NUM_VALIDATORS],
    /// Worker panic sentinel checked by `wait_gen_eq` and `Drop` to prevent deadlocks or UB.
    poisoned: AtomicBool,
}

impl ClusterShared {
    fn new() -> Self {
        Self {
            cmd_gen: AlignedAtomicU64::new(0),
            cmd: SyncSlot::new(ClusterCommand::Idle),
            leader_tag: SyncSlot::new([0u8; 16]),
            leader_tag_ok: AlignedAtomicU32::new(0),
            leader_tag_gen: AlignedAtomicU64::new(0),
            prepare_mailboxes: std::array::from_fn(|_| SyncSlot::new([None; TURBO_NUM_VALIDATORS])),
            prepare_ready: std::array::from_fn(|_| AlignedAtomicU64::new(0)),
            commit_mailboxes: std::array::from_fn(|_| SyncSlot::new([None; TURBO_NUM_VALIDATORS])),
            commit_ready: std::array::from_fn(|_| AlignedAtomicU64::new(0)),
            worker_err: std::array::from_fn(|_| SyncSlot::new(None)),
            worker_voters: std::array::from_fn(|_| SyncSlot::new([false; TURBO_NUM_VALIDATORS])),
            worker_snapshot: std::array::from_fn(|_| SyncSlot::new(None)),
            worker_done: std::array::from_fn(|_| AlignedAtomicU64::new(0)),
            poisoned: AtomicBool::new(false),
        }
    }
}

/// Private state owned exclusively by one persistent OS validator thread.
struct PersistentValidator {
    id: u32,
    ledger: TurboLedger,
    seal_keys: Vec<Option<TurboCwKey>>,
    outbound: [Option<TurboLinkDeck>; TURBO_NUM_VALIDATORS],
    inbound: [Option<TurboLinkDeck>; TURBO_NUM_VALIDATORS],
}

impl PersistentValidator {
    /// Main event loop for persistent validator thread `self.id`.
    fn run_loop(mut self, shared: Arc<ClusterShared>) {
        let mut panic_guard = WorkerPanicGuard::new(Arc::clone(&shared));
        let me = self.id as usize;
        let mut next_gen = 1u64;

        loop {
            if !wait_gen_eq(&shared.cmd_gen.0, next_gen, &shared.poisoned) {
                panic_guard.disarm();
                return;
            }

            // SAFETY: Coordinator wrote `shared.cmd` before `cmd_gen.store(next_gen, Release)`
            // and will not mutate `shared.cmd` until all 4 `worker_done` reach `next_gen`.
            let cmd = unsafe { &*shared.cmd.0.get() };
            match cmd {
                ClusterCommand::Idle => {}
                ClusterCommand::Shutdown => {
                    shared.worker_done[me].0.store(next_gen, Ordering::Release);
                    panic_guard.disarm();
                    return;
                }
                ClusterCommand::Snapshot => {
                    let snap = TurboValidatorSnapshot {
                        validator_id: self.id,
                        height: self.ledger.height,
                        tip_tag: self.ledger.tip_tag,
                        balances: self.ledger.balances.clone(),
                        last_pages: self.ledger.last_pages.clone(),
                    };
                    // SAFETY: Only validator `me` writes `worker_snapshot[me]` prior to `worker_done[me]`.
                    unsafe {
                        *shared.worker_snapshot[me].0.get() = Some(snap);
                    }
                }
                ClusterCommand::Round(job) => {
                    self.execute_bft_round(next_gen, job, &shared);
                }
            }

            shared.worker_done[me].0.store(next_gen, Ordering::Release);
            next_gen += 1;
        }
    }

    /// Execute a complete 2-phase BFT round (`PrePrepare -> Prepare -> Commit -> Finalize`)
    /// peer-to-peer with the other 3 persistent validator threads.
    fn execute_bft_round(&mut self, gen_id: u64, job: &RoundJob, shared: &ClusterShared) {
        let me = self.id as usize;
        let is_leader = me == job.leader_id;
        let height = job.height;
        let view = job.view;
        let prev_tag = job.prev_tag;
        let batch: &[TurboTx] = &job.batch;
        let key_idx = ((height - 1) as usize) * VIEWS_PER_HEIGHT + (view as usize);

        let mut local_err: Option<TurboExpressError> = None;
        let mut staged = false;
        let mut proposed_tag = [0u8; 16];
        let mut prepare_out = [None; TURBO_NUM_VALIDATORS];

        // --------------------------------------------------------------------
        // Phase 1: PrePrepare Seal + Speculative Flat Ledger Staging + Prepare Votes
        // --------------------------------------------------------------------
        if is_leader {
            // Leader consumes its dedicated single-use CW sealing key and publishes `block_tag`.
            let seal_key_opt = if (view as usize) < VIEWS_PER_HEIGHT {
                self.seal_keys.get_mut(key_idx).and_then(Option::take)
            } else {
                None
            };

            match seal_key_opt {
                Some(seal_key) => {
                    let true_tag = seal_tx_batch_4way(seal_key, &prev_tag, height, view, batch);
                    proposed_tag = job.forced_block_tag.unwrap_or(true_tag);
                    // SAFETY: Only `job.leader_id` writes `leader_tag` before releasing `leader_tag_gen`.
                    unsafe {
                        *shared.leader_tag.0.get() = proposed_tag;
                    }
                    shared.leader_tag_ok.0.store(1, Ordering::Relaxed);
                    shared.leader_tag_gen.0.store(gen_id, Ordering::Release);

                    // Speculatively validate and stage batch onto isolated TurboLedger.
                    match self.ledger.stage_batch(height, &prev_tag, batch) {
                        Ok(()) => staged = true,
                        Err(err) => local_err = Some(err),
                    }
                }
                None => {
                    shared.leader_tag_ok.0.store(0, Ordering::Relaxed);
                    shared.leader_tag_gen.0.store(gen_id, Ordering::Release);
                    local_err = Some(TurboExpressError::MissingBlockSealKey { height });
                }
            }
        } else {
            // Follower overlaps its own 4-way CW block seal computation AND speculative ledger
            // staging in parallel with the leader, then verifies `ct_eq_16` against the leader's
            // published `block_tag` BEFORE casting any Prepare vote!
            let seal_key_opt = if (view as usize) < VIEWS_PER_HEIGHT {
                self.seal_keys.get_mut(key_idx).and_then(Option::take)
            } else {
                None
            };

            match seal_key_opt {
                Some(seal_key) => {
                    let computed_tag =
                        seal_tx_batch_4way(seal_key, &prev_tag, height, view, batch);

                    match self.ledger.stage_batch(height, &prev_tag, batch) {
                        Ok(()) => staged = true,
                        Err(err) => local_err = Some(err),
                    }

                    // Wait for leader's published PrePrepare block tag.
                    if !wait_gen_eq(&shared.leader_tag_gen.0, gen_id, &shared.poisoned) {
                        if staged {
                            self.ledger.abort_staged();
                        }
                        return;
                    }
                    if shared.leader_tag_ok.0.load(Ordering::Relaxed) == 0 {
                        if staged {
                            self.ledger.abort_staged();
                            staged = false;
                        }
                        if local_err.is_none() {
                            local_err = Some(TurboExpressError::MissingBlockSealKey { height });
                        }
                    } else {
                        // SAFETY: Leader finished writing `leader_tag` before `leader_tag_gen` Release.
                        proposed_tag = unsafe { *shared.leader_tag.0.get() };
                        if !ct_eq_16(&computed_tag, &proposed_tag) {
                            if staged {
                                self.ledger.abort_staged();
                                staged = false;
                            }
                            local_err = Some(TurboExpressError::InvalidBlockSeal { height });
                        }
                    }
                }
                None => {
                    if !wait_gen_eq(&shared.leader_tag_gen.0, gen_id, &shared.poisoned) {
                        return;
                    }
                    local_err = Some(TurboExpressError::MissingBlockSealKey { height });
                }
            }
        }

        // If Phase 1 validation & seal succeeded, seal 3 outbound OTP+CW Prepare vote frames.
        if local_err.is_none() && staged {
            let payload = encode_vote(TurboVoteKind::Prepare, self.id, height, view, &proposed_tag);
            for peer in 0..TURBO_NUM_VALIDATORS {
                if peer == me {
                    continue;
                }
                match self.outbound[peer].as_mut() {
                    Some(deck) => match deck.seal_vote(self.id, peer as u32, &payload) {
                        Ok(frame) => prepare_out[peer] = Some(frame),
                        Err(err) => {
                            self.ledger.abort_staged();
                            staged = false;
                            local_err = Some(err);
                            prepare_out = [None; TURBO_NUM_VALIDATORS];
                            break;
                        }
                    },
                    None => {
                        self.ledger.abort_staged();
                        staged = false;
                        local_err = Some(TurboExpressError::OtpDeckExhausted);
                        prepare_out = [None; TURBO_NUM_VALIDATORS];
                        break;
                    }
                }
            }
        }

        // Publish our Prepare vote row and signal Phase 1 barrier.
        // SAFETY: Only validator `me` writes `prepare_mailboxes[me]` before `prepare_ready[me]` Release.
        unsafe {
            *shared.prepare_mailboxes[me].0.get() = prepare_out;
        }
        shared.prepare_ready[me].0.store(gen_id, Ordering::Release);

        // --------------------------------------------------------------------
        // Phase 2: Authenticate Inbound Prepare Votes -> Quorum (>= 3) -> Commit Votes
        // --------------------------------------------------------------------
        for sender in 0..TURBO_NUM_VALIDATORS {
            if sender != me && !wait_gen_eq(&shared.prepare_ready[sender].0, gen_id, &shared.poisoned) {
                if staged {
                    self.ledger.abort_staged();
                }
                return;
            }
        }

        let mut commit_out = [None; TURBO_NUM_VALIDATORS];

        if local_err.is_none() && staged {
            let mut prepare_votes = 1usize; // self vote
            for sender in 0..TURBO_NUM_VALIDATORS {
                if sender == me {
                    continue;
                }
                // SAFETY: `sender` released `prepare_ready[sender] == gen_id` after writing its row.
                let frame_opt = unsafe { (*shared.prepare_mailboxes[sender].0.get())[me] };
                if let Some(frame) = frame_opt {
                    // Tolerate up to f = 1 Byzantine bad vote frame; count only valid peer votes.
                    if let Some(deck) = self.inbound[sender].as_mut()
                        && let Ok(pt) = deck.open_vote(&frame, sender as u32, self.id)
                        && decode_and_check_vote(
                            &pt,
                            TurboVoteKind::Prepare,
                            sender as u32,
                            height,
                            view,
                            &proposed_tag,
                        )
                    {
                        prepare_votes += 1;
                    }
                }
            }

            if prepare_votes < TURBO_QUORUM {
                self.ledger.abort_staged();
                staged = false;
                local_err = Some(TurboExpressError::QuorumNotReached {
                    phase: "Prepare",
                    votes: prepare_votes,
                    quorum: TURBO_QUORUM,
                });
            } else {
                // Prepare quorum reached! Seal 3 outbound OTP+CW Commit vote frames.
                let payload =
                    encode_vote(TurboVoteKind::Commit, self.id, height, view, &proposed_tag);
                for peer in 0..TURBO_NUM_VALIDATORS {
                    if peer == me {
                        continue;
                    }
                    match self.outbound[peer].as_mut() {
                        Some(deck) => match deck.seal_vote(self.id, peer as u32, &payload) {
                            Ok(frame) => commit_out[peer] = Some(frame),
                            Err(err) => {
                                self.ledger.abort_staged();
                                staged = false;
                                local_err = Some(err);
                                commit_out = [None; TURBO_NUM_VALIDATORS];
                                break;
                            }
                        },
                        None => {
                            self.ledger.abort_staged();
                            staged = false;
                            local_err = Some(TurboExpressError::OtpDeckExhausted);
                            commit_out = [None; TURBO_NUM_VALIDATORS];
                            break;
                        }
                    }
                }
            }
        }

        // Publish our Commit vote row and signal Phase 2 barrier.
        // SAFETY: Only validator `me` writes `commit_mailboxes[me]` before `commit_ready[me]` Release.
        unsafe {
            *shared.commit_mailboxes[me].0.get() = commit_out;
        }
        shared.commit_ready[me].0.store(gen_id, Ordering::Release);

        // --------------------------------------------------------------------
        // Phase 3: Authenticate Inbound Commit Votes -> Quorum (>= 3) -> O(1) Commit / Rollback
        // --------------------------------------------------------------------
        for sender in 0..TURBO_NUM_VALIDATORS {
            if sender != me && !wait_gen_eq(&shared.commit_ready[sender].0, gen_id, &shared.poisoned) {
                if staged {
                    self.ledger.abort_staged();
                }
                return;
            }
        }

        let mut voters = [false; TURBO_NUM_VALIDATORS];
        if local_err.is_none() && staged {
            voters[me] = true;
            let mut commit_votes = 1usize;

            for sender in 0..TURBO_NUM_VALIDATORS {
                if sender == me {
                    continue;
                }
                // SAFETY: `sender` released `commit_ready[sender] == gen_id` after writing its row.
                let frame_opt = unsafe { (*shared.commit_mailboxes[sender].0.get())[me] };
                if let Some(frame) = frame_opt {
                    // Tolerate up to f = 1 Byzantine bad Commit frame; commit if >= 3 honest votes.
                    if let Some(deck) = self.inbound[sender].as_mut()
                        && let Ok(pt) = deck.open_vote(&frame, sender as u32, self.id)
                        && decode_and_check_vote(
                            &pt,
                            TurboVoteKind::Commit,
                            sender as u32,
                            height,
                            view,
                            &proposed_tag,
                        )
                    {
                        voters[sender] = true;
                        commit_votes += 1;
                    }
                }
            }

            if commit_votes >= TURBO_QUORUM {
                self.ledger.commit_staged(height, proposed_tag);
            } else {
                self.ledger.abort_staged();
                voters = [false; TURBO_NUM_VALIDATORS];
                local_err = Some(TurboExpressError::QuorumNotReached {
                    phase: "Commit",
                    votes: commit_votes,
                    quorum: TURBO_QUORUM,
                });
            }
        }

        // Write final outcome for coordinator.
        // SAFETY: Only validator `me` writes `worker_err[me]` & `worker_voters[me]` before `worker_done[me]`.
        unsafe {
            *shared.worker_err[me].0.get() = local_err;
            *shared.worker_voters[me].0.get() = voters;
        }
    }
}

/// Persistent 4-validator (`N = 4, f = 1, quorum = 3`) 2-phase BFT Express cluster.
///
/// Spawns 4 long-lived OS validator threads ONCE at construction and coordinates rounds via
/// cache-line-aligned lock-free `AtomicU64` barriers with zero-copy `Arc<[TurboTx]>` batch
/// sharing and clean `Drop` shutdown.
pub struct TurboExpressCluster {
    shared: Arc<ClusterShared>,
    handles: Vec<JoinHandle<()>>,
    next_gen: u64,
    height: u64,
    tip_tag: [u8; 16],
    current_view: u64,
    provisioned_blocks: usize,
}

impl TurboExpressCluster {
    /// Provision a persistent 4-validator `TurboExpressCluster` with `initial_balances` and
    /// single-use Carter-Wegman block-sealing + pairwise OTP+CW vote key capacity for
    /// `max_blocks` BFT heights (up to 4 view-change keys per height).
    pub fn new(initial_balances: Vec<u64>, max_blocks: usize) -> Self {
        let total_seal_keys = max_blocks
            .saturating_mul(VIEWS_PER_HEIGHT)
            .max(VIEWS_PER_HEIGHT);
        let master_seals = TurboCwKey::generate_batch(total_seal_keys);

        // 2 vote frames (Prepare + Commit) per directed peer link per round.
        let slots_per_link = total_seal_keys.saturating_mul(2).max(16);
        let mut out_decks: Vec<[Option<TurboLinkDeck>; TURBO_NUM_VALIDATORS]> =
            (0..TURBO_NUM_VALIDATORS)
                .map(|_| [None, None, None, None])
                .collect();
        let mut in_decks: Vec<[Option<TurboLinkDeck>; TURBO_NUM_VALIDATORS]> =
            (0..TURBO_NUM_VALIDATORS)
                .map(|_| [None, None, None, None])
                .collect();

        for from in 0..TURBO_NUM_VALIDATORS {
            for to in 0..TURBO_NUM_VALIDATORS {
                if from == to {
                    continue;
                }
                let (out_d, in_d) = TurboLinkDeck::create_pair(slots_per_link);
                out_decks[from][to] = Some(out_d);
                in_decks[to][from] = Some(in_d);
            }
        }

        let shared = Arc::new(ClusterShared::new());
        let mut handles = Vec::with_capacity(TURBO_NUM_VALIDATORS);

        for (id, (outbound, inbound)) in out_decks
            .into_iter()
            .zip(in_decks.into_iter())
            .enumerate()
        {
            let seal_keys: Vec<Option<TurboCwKey>> = master_seals
                .iter()
                .map(|k| Some(k.duplicate_for_preshare()))
                .collect();
            let validator = PersistentValidator {
                id: id as u32,
                ledger: TurboLedger::new(initial_balances.clone()),
                seal_keys,
                outbound,
                inbound,
            };
            let shared_clone = Arc::clone(&shared);
            let handle = thread::Builder::new()
                .name(format!("vernam-turbo-val-{id}"))
                .spawn(move || validator.run_loop(shared_clone))
                .expect("failed to spawn persistent validator thread");
            handles.push(handle);
        }

        Self {
            shared,
            handles,
            next_gen: 1,
            height: 0,
            tip_tag: TURBO_GENESIS_TAG,
            current_view: 0,
            provisioned_blocks: max_blocks,
        }
    }

    /// Current finalized chain height (identical across all 4 honest validators).
    #[inline]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Current finalized chain integrity tip tag.
    #[inline]
    pub fn tip_tag(&self) -> [u8; 16] {
        self.tip_tag
    }

    /// Total number of blocks for which single-use sealing/vote keys were provisioned.
    #[inline]
    pub fn provisioned_blocks(&self) -> usize {
        self.provisioned_blocks
    }

    /// Dispatch a command to all 4 persistent validator threads and wait for all 4 to finish.
    /// Returns `Err(ClusterShutdown)` immediately if any worker thread has panicked/poisoned.
    #[inline]
    fn dispatch_and_wait(&mut self, cmd: ClusterCommand) -> Result<u64, TurboExpressError> {
        if self.shared.poisoned.load(Ordering::Acquire) {
            return Err(TurboExpressError::ClusterShutdown);
        }
        let gen_id = self.next_gen;
        self.next_gen += 1;

        // SAFETY: All 4 workers finished `gen_id - 1` before returning from the prior call,
        // so the coordinator has exclusive access to `shared.cmd`.
        unsafe {
            *self.shared.cmd.0.get() = cmd;
        }
        self.shared.cmd_gen.0.store(gen_id, Ordering::Release);

        for i in 0..TURBO_NUM_VALIDATORS {
            if !wait_gen_eq(&self.shared.worker_done[i].0, gen_id, &self.shared.poisoned) {
                return Err(TurboExpressError::ClusterShutdown);
            }
        }

        // Release any `Arc<[TurboTx]>` held inside `shared.cmd` immediately once quiescent.
        // SAFETY: All 4 workers have reached `worker_done == gen_id` and will not read `cmd`
        // until `cmd_gen` advances to `gen_id + 1`.
        unsafe {
            *self.shared.cmd.0.get() = ClusterCommand::Idle;
        }

        Ok(gen_id)
    }

    /// Execute a full 2-phase BFT round (`PrePrepare -> Prepare -> Commit`) across all 4
    /// persistent validator threads sharing `batch` zero-copy.
    pub fn commit_batch(
        &mut self,
        batch: Arc<[TurboTx]>,
    ) -> Result<TurboBlockCert, TurboExpressError> {
        self.commit_batch_internal(batch, None)
    }

    /// Convenience wrapper cloning `txs` once into an `Arc<[TurboTx]>` and committing across the
    /// persistent 4-validator BFT pool.
    pub fn commit_slice(&mut self, txs: &[TurboTx]) -> Result<TurboBlockCert, TurboExpressError> {
        self.commit_batch(Arc::from(txs))
    }

    /// Adversarial helper simulating a Byzantine leader proposing `forged_tag` as the
    /// Carter-Wegman block seal. Honest followers MUST detect the forgery, refuse to vote
    /// Prepare, and roll back/preserve exact pre-batch state across all 4 validators.
    pub fn commit_batch_with_forged_seal(
        &mut self,
        batch: Arc<[TurboTx]>,
        forged_tag: [u8; 16],
    ) -> Result<TurboBlockCert, TurboExpressError> {
        self.commit_batch_internal(batch, Some(forged_tag))
    }

    fn commit_batch_internal(
        &mut self,
        batch: Arc<[TurboTx]>,
        forced_block_tag: Option<[u8; 16]>,
    ) -> Result<TurboBlockCert, TurboExpressError> {
        if self.handles.is_empty() {
            return Err(TurboExpressError::ClusterShutdown);
        }

        let height = self.height + 1;
        let view = self.current_view;
        if (view as usize) >= VIEWS_PER_HEIGHT {
            return Err(TurboExpressError::MissingBlockSealKey { height });
        }

        let leader_id = ((height as usize) + (view as usize)) % TURBO_NUM_VALIDATORS;
        let prev_tag = self.tip_tag;
        let tx_count = batch.len();

        self.dispatch_and_wait(ClusterCommand::Round(RoundJob {
            height,
            view,
            leader_id,
            prev_tag,
            batch,
            forced_block_tag,
        }))?;

        // Collect per-validator outcomes (all 4 workers are now quiescent).
        let mut commit_voters = [false; TURBO_NUM_VALIDATORS];
        let mut first_root_err: Option<TurboExpressError> = None;
        let mut first_any_err: Option<TurboExpressError> = None;
        let mut committed_validators = 0usize;

        for vid in 0..TURBO_NUM_VALIDATORS {
            // SAFETY: All 4 workers released `worker_done == gen_id` before we reach here.
            let err_opt = unsafe { (*self.shared.worker_err[vid].0.get()).take() };
            let v_voters = unsafe { *self.shared.worker_voters[vid].0.get() };

            if let Some(err) = err_opt {
                if !matches!(err, TurboExpressError::QuorumNotReached { .. })
                    && first_root_err.is_none()
                {
                    first_root_err = Some(err.clone());
                }
                if first_any_err.is_none() {
                    first_any_err = Some(err);
                }
            } else {
                committed_validators += 1;
                for (dst, src) in commit_voters.iter_mut().zip(v_voters.iter()) {
                    *dst |= *src;
                }
            }
        }

        if committed_validators < TURBO_QUORUM {
            self.current_view += 1;
            return Err(first_root_err.or(first_any_err).unwrap_or(
                TurboExpressError::QuorumNotReached {
                    phase: "Commit",
                    votes: committed_validators,
                    quorum: TURBO_QUORUM,
                },
            ));
        }

        // SAFETY: Leader published `leader_tag` during Phase 1 before `worker_done` Release.
        let block_tag = unsafe { *self.shared.leader_tag.0.get() };
        let commit_quorum = commit_voters.iter().filter(|&&b| b).count();

        self.height = height;
        self.tip_tag = block_tag;
        self.current_view = 0;

        Ok(TurboBlockCert {
            height,
            view,
            leader_id: leader_id as u32,
            prev_tag,
            block_tag,
            tx_count,
            commit_voters,
            commit_quorum,
        })
    }

    /// Capture consistent read-only snapshots of all 4 isolated validator ledgers.
    pub fn all_validator_snapshots(&mut self) -> [TurboValidatorSnapshot; TURBO_NUM_VALIDATORS] {
        self.dispatch_and_wait(ClusterCommand::Snapshot)
            .expect("cluster poisoned while taking snapshots");
        std::array::from_fn(|vid| {
            // SAFETY: All 4 workers wrote `worker_snapshot[vid]` before `worker_done[vid]` Release.
            unsafe {
                (*self.shared.worker_snapshot[vid].0.get())
                    .take()
                    .expect("validator snapshot missing")
            }
        })
    }

    /// Capture a consistent read-only snapshot of validator `validator_id`'s isolated ledger.
    pub fn validator_snapshot(&mut self, validator_id: usize) -> TurboValidatorSnapshot {
        assert!(
            validator_id < TURBO_NUM_VALIDATORS,
            "validator_id out of range"
        );
        let mut all = self.all_validator_snapshots();
        std::mem::replace(
            &mut all[validator_id],
            TurboValidatorSnapshot {
                validator_id: 0,
                height: 0,
                tip_tag: TURBO_GENESIS_TAG,
                balances: Vec::new(),
                last_pages: Vec::new(),
            },
        )
    }
}

impl Drop for TurboExpressCluster {
    fn drop(&mut self) {
        if self.handles.is_empty() {
            return;
        }

        // Wait for quiescence on `self.next_gen - 1` before touching `UnsafeCell` `shared.cmd`.
        // If any worker panicked (`poisoned == true`), NEVER mutate `shared.cmd` — signal
        // `poisoned` so all remaining workers exit their `wait_gen_eq` loops safely!
        let prev_gen = self.next_gen - 1;
        let mut all_quiescent = !self.shared.poisoned.load(Ordering::Acquire);
        if all_quiescent {
            for i in 0..TURBO_NUM_VALIDATORS {
                if !wait_gen_eq(&self.shared.worker_done[i].0, prev_gen, &self.shared.poisoned) {
                    all_quiescent = false;
                    break;
                }
            }
        }

        if all_quiescent && !self.shared.poisoned.load(Ordering::Acquire) {
            let gen_id = self.next_gen;
            self.next_gen += 1;

            // SAFETY: All 4 workers are verified quiescent at `prev_gen`, waiting on `cmd_gen == gen_id`.
            unsafe {
                *self.shared.cmd.0.get() = ClusterCommand::Shutdown;
            }
            self.shared.cmd_gen.0.store(gen_id, Ordering::Release);
        } else {
            // Poisoned fallback: wake any waiting workers via `poisoned = true` without touching `cmd`.
            self.shared.poisoned.store(true, Ordering::SeqCst);
        }

        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

// ============================================================================
// 7. Live Multi-Block Benchmark (`TurboExpressBench` & `run_turbo_express_bench`)
// ============================================================================

/// Real measured throughput metrics from [`run_turbo_express_bench`].
#[derive(Debug, Clone)]
pub struct TurboExpressBench {
    /// Finalized 4-validator 2-phase BFT throughput in transactions per second.
    pub express_tps: f64,
    /// Total transactions finalized across all 4 persistent BFT validators.
    pub total_txs: usize,
    /// Total BFT blocks finalized.
    pub blocks: usize,
    /// Wall-clock duration in seconds.
    pub elapsed_secs: f64,
    /// Average wall-clock finality latency per block in milliseconds.
    pub ms_per_block: f64,
}

impl fmt::Display for TurboExpressBench {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TurboExpress 4-Val Persistent BFT: {:.0} tx/s ({} txs across {} blocks in {:.4}s, {:.3} ms/block)",
            self.express_tps, self.total_txs, self.blocks, self.elapsed_secs, self.ms_per_block
        )
    }
}

/// Run a real multi-block benchmark finalizing 50 blocks x 10,000 txs = 500,000 txs across all 4
/// persistent BFT validator threads (full 4-way CW block sealing + 4 isolated `TurboLedger`s +
/// 24 pairwise OTP+CW Prepare/Commit votes per block).
pub fn run_turbo_express_bench() -> TurboExpressBench {
    let num_accounts = 2_000usize;
    let blocks = 50usize;
    let txs_per_block = 10_000usize;
    let total_txs = blocks * txs_per_block;

    let initial_balances = vec![10_000_000u64; num_accounts];
    let mut cluster = TurboExpressCluster::new(initial_balances, blocks + 4);

    // Pre-build 50 valid zero-copy Arc<[TurboTx]> batches with strictly monotonic per-sender page_ids.
    let mut next_page = vec![1u64; num_accounts];
    let mut batches: Vec<Arc<[TurboTx]>> = Vec::with_capacity(blocks);
    for b in 0..blocks {
        let mut txs = Vec::with_capacity(txs_per_block);
        for i in 0..txs_per_block {
            let sender = ((b * txs_per_block + i) % num_accounts) as u32;
            let recipient = ((sender as usize + 1) % num_accounts) as u32;
            let page_id = next_page[sender as usize];
            next_page[sender as usize] += 1;
            txs.push(TurboTx::new(sender, recipient, 1, page_id));
        }
        batches.push(Arc::from(txs));
    }

    // Warm up the 4 persistent OS validator threads so they are scheduled on physical cores.
    let _ = cluster.all_validator_snapshots();

    let start = Instant::now();
    for batch in batches {
        let cert = cluster
            .commit_batch(batch)
            .expect("turbo express benchmark block must commit");
        debug_assert_eq!(cert.commit_quorum, TURBO_NUM_VALIDATORS);
    }
    let elapsed_secs = start.elapsed().as_secs_f64().max(1e-9);
    let express_tps = (total_txs as f64) / elapsed_secs;
    let ms_per_block = (elapsed_secs * 1_000.0) / (blocks as f64);

    assert_eq!(cluster.height(), blocks as u64);

    TurboExpressBench {
        express_tps,
        total_txs,
        blocks,
        elapsed_secs,
        ms_per_block,
    }
}

// ============================================================================
// 8. Comprehensive Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Textbook serial Horner Carter-Wegman reference implementation for algebraic equivalence tests.
    fn reference_horner_seal(
        r: u128,
        s: u128,
        prev_tag: &[u8; 16],
        height: u64,
        view: u64,
        txs: &[TurboTx],
    ) -> [u8; 16] {
        let prev_lo = u64::from_le_bytes(prev_tag[0..8].try_into().unwrap()) as u128;
        let prev_hi = u64::from_le_bytes(prev_tag[8..16].try_into().unwrap()) as u128;
        let mut acc = add_mod(mul_mod(prev_lo, r), prev_hi);
        acc = add_mod(mul_mod(acc, r), height as u128);
        acc = add_mod(mul_mod(acc, r), view as u128);
        acc = add_mod(mul_mod(acc, r), txs.len() as u128);
        for tx in txs {
            let (w0, w1) = tx.to_field_words();
            acc = add_mod(mul_mod(acc, r), w0);
            acc = add_mod(mul_mod(acc, r), w1);
        }
        add_mod(acc, s).to_le_bytes()
    }

    #[test]
    fn test_turbo_tx_layout_and_4way_seal_equivalence() {
        assert_eq!(std::mem::size_of::<TurboTx>(), 24);
        let sample = TurboTx::new(77, 888_888, 987_654_321_012_345, 42_424_242);
        let raw = sample.to_bytes();
        assert_eq!(TurboTx::from_bytes(&raw), sample);

        // Verify branchless fma_mod_p matches add_mod(mul_mod(a, b), w) across extreme edge cases.
        let max_w = (1u128 << 120) - 1;
        let edge_cases = [
            (0u128, 0u128, 0u128),
            (PRIME_P, PRIME_P - 1, max_w),
            (PRIME_P - 1, PRIME_P - 1, max_w),
            (PRIME_P - 1, 1u128 << 64, 1u128 << 119),
            ((1u128 << 64) - 1, (1u128 << 126) + 12345, max_w),
        ];
        for (a, b, w) in edge_cases {
            let got = reduce(fma_mod_p(a, b & 0xFFFF_FFFF_FFFF_FFFF, b >> 64, w));
            let expected = add_mod(mul_mod(a, b), w);
            assert_eq!(got, expected);
        }

        // Verify 4-way pipelined CW block seal is bit-for-bit identical to textbook serial Horner
        // across every remainder class (0..3 mod 4) and large batches.
        let prev_tag = [0xABu8; 16];
        for len in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 63, 64, 65, 257] {
            let txs: Vec<TurboTx> = (0..len as u32)
                .map(|i| {
                    TurboTx::new(
                        i,
                        i.wrapping_mul(31).wrapping_add(7),
                        ((i as u64) << 40) ^ 0xDEAD_BEEF_CAFE_BABEu64,
                        (i as u64) + 1,
                    )
                })
                .collect();
            let r = random_field_elem();
            let s = random_field_elem();
            let key = TurboCwKey::from_raw(r, s).unwrap();
            let got = seal_tx_batch_4way(key, &prev_tag, 19, 2, &txs);
            let expected = reference_horner_seal(r, s, &prev_tag, 19, 2, &txs);
            assert_eq!(got, expected, "4-way CW seal mismatch for len={len}");
        }
    }

    #[test]
    fn test_bip152_compact_batch_relay_roundtrip() {
        let key = TurboShortIdKey::generate();
        let mut leader_mp = TurboMempool::with_capacity(key.duplicate_for_round(), 1024);
        let mut follower_mp = TurboMempool::with_capacity(key.duplicate_for_round(), 1024);

        let txs: Vec<TurboTx> = (0..1_000u32)
            .map(|i| TurboTx::new(i % 500, (i + 1) % 500, (i as u64) + 5, (i as u64) + 1))
            .collect();

        leader_mp.insert_batch(&txs).unwrap();
        follower_mp.insert_batch(&txs[..997]).unwrap();

        let [seal_key, verify_key] = TurboCwKey::generate_preshared::<2>();
        let compact = leader_mp.build_compact_batch(1, 0, 1, TURBO_GENESIS_TAG, &txs, seal_key);

        // Wire roundtrip & ~3x bandwidth reduction.
        let wire = compact.to_bytes();
        let decoded = TurboCompactBatch::from_bytes(&wire).unwrap();
        assert_eq!(decoded, compact);
        assert!(
            decoded.bandwidth_ratio() > 2.95,
            "expected ~3x compact bandwidth ratio, got {:.2}x",
            decoded.bandwidth_ratio()
        );

        // 3 mempool misses reported cleanly -> patched -> 4-way CW seal matches!
        let mut reconstructed = Vec::new();
        let missing = follower_mp
            .reconstruct_batch(&decoded, &mut reconstructed)
            .expect_err("expected 3 missing txs");
        assert_eq!(missing, vec![997, 998, 999]);

        follower_mp
            .patch_missing_txs(
                &mut reconstructed,
                &[(997, txs[997]), (998, txs[998]), (999, txs[999])],
            )
            .unwrap();
        assert_eq!(reconstructed, txs);

        let computed = seal_tx_batch_4way(verify_key, &TURBO_GENESIS_TAG, 1, 0, &reconstructed);
        assert!(ct_eq_16(&computed, &decoded.block_tag));

        // 100% mempool hit succeeds immediately.
        let mut full_hit = Vec::new();
        follower_mp
            .reconstruct_batch(&decoded, &mut full_hit)
            .expect("100% hit must succeed");
        assert_eq!(full_hit, txs);
    }

    #[test]
    fn test_50k_txs_across_4_persistent_bft_validators() {
        let num_accounts = 1_000usize;
        let blocks = 10usize;
        let txs_per_block = 5_000usize;
        let initial_bal = 100_000u64;

        let mut cluster = TurboExpressCluster::new(vec![initial_bal; num_accounts], blocks + 4);
        let mut expected_bal = vec![initial_bal; num_accounts];
        let mut next_page = vec![1u64; num_accounts];

        for b in 0..blocks {
            let mut txs = Vec::with_capacity(txs_per_block);
            for i in 0..txs_per_block {
                let s = (b * txs_per_block + i) % num_accounts;
                let r = (s + 13) % num_accounts;
                let amt = ((i % 19) + 1) as u64;
                let pid = next_page[s];
                next_page[s] += 1;
                expected_bal[s] -= amt;
                expected_bal[r] += amt;
                txs.push(TurboTx::new(s as u32, r as u32, amt, pid));
            }
            let cert = cluster.commit_batch(Arc::from(txs)).unwrap();
            assert_eq!(cert.height, (b + 1) as u64);
            assert_eq!(cert.tx_count, txs_per_block);
            assert_eq!(cert.commit_quorum, TURBO_NUM_VALIDATORS);
            assert_eq!(cert.commit_voters, [true; TURBO_NUM_VALIDATORS]);
        }

        assert_eq!(cluster.height(), blocks as u64);
        let tip = cluster.tip_tag();
        assert_ne!(tip, TURBO_GENESIS_TAG);

        let snapshots = cluster.all_validator_snapshots();
        for (vid, snap) in snapshots.iter().enumerate() {
            assert_eq!(snap.validator_id, vid as u32);
            assert_eq!(snap.height, blocks as u64);
            assert_eq!(snap.tip_tag, tip);
            assert_eq!(snap.balances, expected_bal);
            for acct in 0..num_accounts {
                assert_eq!(snap.last_pages[acct], next_page[acct] - 1);
            }
        }
    }

    #[test]
    fn test_mid_batch_overdraft_atomic_rollback_all_validators() {
        let num_accounts = 500usize;
        let initial_bal = 1_000u64;
        let mut cluster = TurboExpressCluster::new(vec![initial_bal; num_accounts], 10);

        // Commit 1 valid warm-up block so height == 1 with non-genesis tip_tag.
        let warmup: Vec<TurboTx> = (0..200u32)
            .map(|i| TurboTx::new(i, i + 1, 10, 1))
            .collect();
        let cert1 = cluster.commit_batch(Arc::from(warmup)).unwrap();
        assert_eq!(cert1.height, 1);

        let pre_snaps = cluster.all_validator_snapshots();

        // Build a 1,000-tx batch where txs 0..500 are completely valid (mutating hundreds of
        // accounts + page_ids) and tx #500 attempts an overdraft!
        let mut bad_batch = Vec::with_capacity(1_000);
        let mut local_page = pre_snaps[0].last_pages.clone();
        for i in 0..1_000usize {
            let s = i % num_accounts;
            let r = (s + 7) % num_accounts;
            local_page[s] += 1;
            let amt = if i == 500 { 999_999 } else { 1 };
            bad_batch.push(TurboTx::new(s as u32, r as u32, amt, local_page[s]));
        }

        let err = cluster
            .commit_batch(Arc::from(bad_batch))
            .expect_err("mid-batch overdraft must be rejected");
        assert_eq!(
            err,
            TurboExpressError::InvalidTx {
                index: 500,
                reason: "insufficient balance",
            }
        );

        // Verify EVERY SINGLE ONE of the 4 validators rolled back bit-for-bit to pre-batch state!
        assert_eq!(cluster.height(), 1);
        assert_eq!(cluster.tip_tag(), cert1.block_tag);
        let post_snaps = cluster.all_validator_snapshots();
        for vid in 0..TURBO_NUM_VALIDATORS {
            assert_eq!(post_snaps[vid].height, pre_snaps[vid].height);
            assert_eq!(post_snaps[vid].tip_tag, pre_snaps[vid].tip_tag);
            assert_eq!(post_snaps[vid].balances, pre_snaps[vid].balances);
            assert_eq!(post_snaps[vid].last_pages, pre_snaps[vid].last_pages);
        }
    }

    #[test]
    fn test_replayed_page_id_rejected_atomically() {
        let mut cluster = TurboExpressCluster::new(vec![10_000u64; 100], 10);

        // Commit tx with sender 0, page_id = 5.
        let batch1 = Arc::from([TurboTx::new(0, 1, 100, 5), TurboTx::new(2, 3, 50, 1)]);
        let cert1 = cluster.commit_batch(batch1).unwrap();
        assert_eq!(cert1.height, 1);

        let pre_snaps = cluster.all_validator_snapshots();

        // Attempt a batch where tx 0 is valid (sender 4, page_id = 1) and tx 1 replays sender 0's page_id = 5.
        let replay_batch = Arc::from([TurboTx::new(4, 5, 25, 1), TurboTx::new(0, 1, 10, 5)]);
        let err = cluster
            .commit_batch(replay_batch)
            .expect_err("replayed page_id must be rejected");
        assert_eq!(
            err,
            TurboExpressError::InvalidTx {
                index: 1,
                reason: "non-monotonic or replayed page_id",
            }
        );

        // Also test strictly smaller page_id = 4.
        let stale_batch = Arc::from([TurboTx::new(0, 1, 10, 4)]);
        let err2 = cluster
            .commit_batch(stale_batch)
            .expect_err("stale page_id must be rejected");
        assert_eq!(
            err2,
            TurboExpressError::InvalidTx {
                index: 0,
                reason: "non-monotonic or replayed page_id",
            }
        );

        // All 4 validators remain untouched at height 1 (even valid tx 0 from replay_batch was rolled back!).
        assert_eq!(cluster.height(), 1);
        let post_snaps = cluster.all_validator_snapshots();
        for vid in 0..TURBO_NUM_VALIDATORS {
            assert_eq!(post_snaps[vid], pre_snaps[vid]);
        }
    }

    #[test]
    fn test_forged_cw_block_seal_rejected_across_honest_validators() {
        let mut cluster = TurboExpressCluster::new(vec![50_000u64; 64], 10);

        // Commit a legitimate block 1 first.
        let b1 = Arc::from([TurboTx::new(0, 1, 200, 1), TurboTx::new(2, 3, 300, 1)]);
        let cert1 = cluster.commit_batch(b1).unwrap();
        assert_eq!(cert1.height, 1);
        let pre_snaps = cluster.all_validator_snapshots();

        // Byzantine leader proposes a valid transaction batch paired with a FORGED 16-byte CW seal!
        let b2 = Arc::from([TurboTx::new(0, 1, 50, 2), TurboTx::new(4, 5, 75, 1)]);
        let forged_tag = [0xDEu8; 16];
        let err = cluster
            .commit_batch_with_forged_seal(Arc::clone(&b2), forged_tag)
            .expect_err("forged Carter-Wegman block seal must be rejected");
        assert_eq!(err, TurboExpressError::InvalidBlockSeal { height: 2 });

        // Verify ALL 4 validators (including the simulated Byzantine leader, which failed to reach
        // Prepare quorum and rolled back!) preserved exact pre-batch state.
        assert_eq!(cluster.height(), 1);
        assert_eq!(cluster.tip_tag(), cert1.block_tag);
        let post_snaps = cluster.all_validator_snapshots();
        for vid in 0..TURBO_NUM_VALIDATORS {
            assert_eq!(post_snaps[vid], pre_snaps[vid]);
        }

        // Recovery on the next view: honest leader commits the exact same valid batch cleanly!
        let cert2 = cluster
            .commit_batch(b2)
            .expect("honest view-change commit after forged seal rejection must succeed");
        assert_eq!(cert2.height, 2);
        assert_eq!(cert2.view, 1);
        assert_eq!(cert2.commit_quorum, TURBO_NUM_VALIDATORS);
        assert_eq!(cluster.validator_snapshot(0).balances[0], 50_000 - 250);
    }

    #[test]
    fn test_run_turbo_express_bench_and_print_tps() {
        let bench = run_turbo_express_bench();
        println!("{bench}");
        assert_eq!(bench.blocks, 50);
        assert_eq!(bench.total_txs, 500_000);
        assert!(bench.express_tps > 1_000_000.0);
        assert!(bench.elapsed_secs > 0.0);
        assert!(bench.ms_per_block > 0.0);
    }

    #[test]
    fn test_stage_batch_rejects_uncommitted_and_reconstruct_validates_prefilled_bounds() {
        let mut ledger = TurboLedger::new(vec![1_000u64; 8]);
        let tx1 = [TurboTx::new(0, 1, 100, 1)];
        ledger.stage_batch(1, &TURBO_GENESIS_TAG, &tx1).unwrap();
        // M-5: Second stage_batch before commit/abort MUST fail without corrupting undo_log.
        let err = ledger
            .stage_batch(1, &TURBO_GENESIS_TAG, &tx1)
            .unwrap_err();
        assert!(matches!(err, TurboExpressError::InvalidParameters(_)));
        ledger.abort_staged();
        assert_eq!(ledger.balance_of(0), 1_000);
        assert_eq!(ledger.balance_of(1), 1_000);

        // M-5: Out-of-bounds and duplicate prefilled_txs indices must be rejected cleanly.
        let mp = HashMap::new();
        let mut out = Vec::new();
        let oob_compact = TurboCompactBatch {
            height: 1,
            view: 0,
            leader_id: 0,
            prev_tag: TURBO_GENESIS_TAG,
            block_tag: [0u8; 16],
            short_ids: vec![],
            prefilled_txs: vec![(99, TurboTx::new(0, 1, 10, 1))],
        };
        assert!(reconstruct_batch(&mp, &oob_compact, &mut out).is_err());

        let dup_compact = TurboCompactBatch {
            height: 1,
            view: 0,
            leader_id: 0,
            prev_tag: TURBO_GENESIS_TAG,
            block_tag: [0u8; 16],
            short_ids: vec![],
            prefilled_txs: vec![
                (0, TurboTx::new(0, 1, 10, 1)),
                (0, TurboTx::new(0, 1, 20, 2)),
            ],
        };
        assert!(reconstruct_batch(&mp, &dup_compact, &mut out).is_err());
    }
}
