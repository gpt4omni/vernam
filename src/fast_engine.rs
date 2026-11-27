//! High-Throughput Information-Theoretic Execution Engine for Vernam (VRNM).
//!
//! Adapts battle-tested systems optimizations from **Bitcoin Core** (BIP-152 Compact Block Relay,
//! `CCoinsViewCache` in-memory transactional state overlay, `CCheckQueue` parallel worker queues,
//! mempool indexing, and pipelined validation) and **Solana Sealevel** (flat contiguous account
//! arrays and parallel disjoint-lane execution) while preserving **100% pure information-theoretic
//! security** over the Mersenne prime field `F_(2^127 - 1)` — **ZERO** SHA-256, SipHash, RSA,
//! ECDSA, Schnorr, AES, or external crates.
//!
//! # Architecture Overview
//! - [`CompactTx`]: 24-byte `#[repr(C)]` ultra-compact binary transaction with zero-alloc encode/decode.
//! - [`FastMempool`] & [`CompactBatchProposal`]: BIP-152-inspired compact batch relay indexing
//!   pending transactions by 64-bit Carter-Wegman universal-hash short IDs under a fresh per-round
//!   session key (~3x bandwidth reduction vs 24-byte full batches, ~4x vs 32-byte `BinaryTx`).
//! - [`IndexedLedger`]: O(1) flat contiguous `Vec<u64>` balances + monotonic `last_page_id` arrays
//!   with a pre-allocated undo-log rollback buffer (zero per-batch heap allocations).
//! - [`FastExpressCluster`]: 4-validator (`N = 4, f = 1, quorum = 3`) 2-phase batched BFT cluster
//!   combining compact relay, parallel `std::thread::scope` validation/sealing, O(1) pairwise
//!   OTP+CW vote decks, and flat indexed ledger state.
//! - [`Lagrange3Of4`], [`FastBeaverPool`], & [`FastShieldedCluster`]: Zero-heap-allocation stack
//!   `[u128; 4]` `(3, 4)` Shamir IT-MPC engine with compile-time `const` Lagrange coefficients
//!   (zero online `inv_mod`, zero `mul_mod` interpolation/parity checks), full 16-bit range proofs
//!   (`v_j*(v_j-1)==0`, `r_j*(r_j-1)==0`, `B - v - r == 0`), blinded one-hot recipient updates
//!   (`s_k*(s_k-1)==0`, `sum(s_k)==1`, `+[s_k * v]`), degree-2 tamper detection, and lock-free
//!   multi-core parallel execution across disjoint anonymity buckets via `std::thread::scope`.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{Ordering, compiler_fence};
use std::time::Instant;

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, fill_os_random, mul_mod, random_field_elem, sub_mod,
    zeroize_slice, zeroize_u128,
};

// ============================================================================
// Constants & Type Aliases
// ============================================================================

/// Fixed serialized byte length of a [`CompactTx`].
pub const COMPACT_TX_SIZE: usize = 24;

/// Fixed wire size of a [`CompactBatchProposal`] header:
/// `height (8) + view (8) + leader_id (4) + tx_count (4) + prev_tag (16) + block_tag (16) = 56 bytes`.
pub const COMPACT_HEADER_SIZE: usize = 56;

/// Genesis chain integrity tag (height 0).
pub const FAST_GENESIS_TAG: [u8; 16] = [0u8; 16];

/// Fixed validator count for the `(3, 4)` BFT and Shamir IT-MPC engine.
pub const FAST_NUM_VALIDATORS: usize = 4;

/// Byzantine quorum threshold `2f + 1 = 3` for `N = 4, f = 1`.
pub const FAST_QUORUM: usize = 3;

/// Fixed 16-bit confidential range proof width (`0 <= v < 2^16`).
pub const FAST_RANGE_BITS: usize = 16;

/// Fixed anonymity bucket size (`O(1)` blinded updates per shielded transfer).
pub const FAST_BUCKET_SIZE: usize = 16;

/// Exact number of single-use Beaver triples consumed per 16-bit shielded transfer
/// (`16` amount bits + `16` remainder bits + `16` selector bits + `16` blinded credits = `64`).
pub const TRIPLES_PER_SHIELDED_TX: usize = 2 * FAST_RANGE_BITS + 2 * FAST_BUCKET_SIZE;

/// Fixed-size stack-allocated `(3, 4)` Shamir share tuple `[P(1), P(2), P(3), P(4)]`.
pub type Share4 = [u128; FAST_NUM_VALIDATORS];

/// Fixed wire payload length for a fast BFT vote (`kind(1) + pad(3) + voter(4) + height(8) + view(8) + tag(16)`).
const FAST_VOTE_PAYLOAD_LEN: usize = 40;

// Compile-time layout guarantee for CompactTx.
const _: () = assert!(std::mem::size_of::<CompactTx>() == COMPACT_TX_SIZE);

// ============================================================================
// Errors
// ============================================================================

/// Errors returned by the Vernam high-throughput Express and Shielded engines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastEngineError {
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
    /// BFT consensus phase failed to collect `>= 3` distinct validator votes.
    QuorumNotReached {
        phase: &'static str,
        votes: usize,
        quorum: usize,
    },
    /// Field element is outside canonical range `[0, PRIME_P)`.
    FieldElementOutOfRange,
    /// `(3, 4)` Shamir shares failed degree-2 Lagrange parity check (tampered or corrupted).
    InconsistentShares,
    /// Offline Beaver triple pool lacks enough single-use triples for the batch.
    BeaverPoolExhausted { needed: usize, available: usize },
    /// Anonymity bucket ID out of range.
    InvalidBucket { bucket_id: usize },
    /// Slot index inside an anonymity bucket is out of range.
    InvalidSlot { slot: usize },
    /// Confidential range proof bit check (`b * (b - 1) == 0`) failed.
    RangeProofFailed,
    /// Confidential balance equation (`B_sender - v - r == 0`) failed (e.g., overdraft).
    BalanceCheckFailed,
    /// Blinded one-hot recipient selector check (`s_k * (s_k - 1) == 0` or `sum(s_k) == 1`) failed.
    SelectorCheckFailed,
}

impl fmt::Display for FastEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for FastEngineError {}

// ============================================================================
// Internal Zeroization & Batched Entropy Helpers
// ============================================================================

/// Volatile wipe for a stack-allocated [`Share4`] with a single trailing compiler fence.
#[inline(always)]
fn zeroize_share4(shares: &mut Share4) {
    for elem in shares.iter_mut() {
        // SAFETY: `elem` is a valid mutable reference to an initialized `u128`.
        unsafe { std::ptr::write_volatile(elem, 0u128) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Volatile wipe for a slice of [`Share4`] tuples.
#[inline]
fn zeroize_share4_slice(slice: &mut [Share4]) {
    for shares in slice.iter_mut() {
        for elem in shares.iter_mut() {
            // SAFETY: `elem` is a valid mutable reference to an initialized `u128`.
            unsafe { std::ptr::write_volatile(elem, 0u128) };
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Volatile wipe for a slice of `u128` secrets.
#[inline]
fn zeroize_u128_slice(slice: &mut [u128]) {
    for elem in slice.iter_mut() {
        // SAFETY: `elem` is a valid mutable reference to an initialized `u128`.
        unsafe { std::ptr::write_volatile(elem, 0u128) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Fill `out` with uniform unbiased elements in `[0, PRIME_P)` using batched OS entropy reads.
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

// ============================================================================
// 1. Ultra-Compact 24-Byte Binary Transaction (`CompactTx`)
// ============================================================================

/// Ultra-compact 24-byte `#[repr(C)]` binary transaction for Vernam's Express lane.
///
/// By replacing both the separate `nonce` and unbounded `used_pages` set with a strictly
/// monotonic per-account `page_id`, wire size drops from 32 bytes (`BinaryTx`) to 24 bytes
/// while enabling O(1) flat-array replay protection.
///
/// Wire layout (little-endian):
/// - `[0..4]`   `sender_id: u32`
/// - `[4..8]`   `recipient_id: u32`
/// - `[8..16]`  `amount: u64`
/// - `[16..24]` `page_id: u64`
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactTx {
    pub sender_id: u32,
    pub recipient_id: u32,
    pub amount: u64,
    pub page_id: u64,
}

impl CompactTx {
    /// Construct a new 24-byte compact transaction.
    #[inline(always)]
    pub const fn new(sender_id: u32, recipient_id: u32, amount: u64, page_id: u64) -> Self {
        Self {
            sender_id,
            recipient_id,
            amount,
            page_id,
        }
    }

    /// Zero-allocation serialization into a fixed 24-byte array.
    #[inline(always)]
    pub const fn to_bytes(&self) -> [u8; COMPACT_TX_SIZE] {
        let s = self.sender_id.to_le_bytes();
        let r = self.recipient_id.to_le_bytes();
        let a = self.amount.to_le_bytes();
        let p = self.page_id.to_le_bytes();
        [
            s[0], s[1], s[2], s[3],
            r[0], r[1], r[2], r[3],
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
        ]
    }

    /// Zero-allocation deserialization from a fixed 24-byte array.
    #[inline(always)]
    pub const fn from_bytes(b: &[u8; COMPACT_TX_SIZE]) -> Self {
        Self {
            sender_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            recipient_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            amount: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            page_id: u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
        }
    }

    /// Bijectively pack all 192 bits of this transaction into two canonical field elements
    /// `(w0, w1)` strictly `< 2^120 < PRIME_P` for zero-copy Carter-Wegman polynomial hashing.
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
// Information-Theoretic Carter-Wegman Keys (Short IDs & Block Seals)
// ============================================================================

/// Per-round session key `(r, s)` over `F_(2^127 - 1)` for computing 64-bit BIP-152-style
/// universal-hash transaction short IDs with **zero** SHA-256 or SipHash.
///
/// For any two distinct transactions, the probability that they collide under a fresh random
/// `RoundShortIdKey` is at most `2 * 2^63 / (2^127 - 1) ~= 2^-63` (information-theoretic).
pub struct RoundShortIdKey {
    r: u128,
    s: u128,
}

impl RoundShortIdKey {
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
    pub fn from_raw(r: u128, s: u128) -> Result<Self, FastEngineError> {
        if r >= PRIME_P || s >= PRIME_P {
            return Err(FastEngineError::FieldElementOutOfRange);
        }
        Ok(Self { r, s })
    }

    /// Duplicate the session key for sharing across validators within the same consensus round.
    pub fn duplicate_for_round(&self) -> Self {
        Self {
            r: self.r,
            s: self.s,
        }
    }

    /// Compute the 64-bit Carter-Wegman universal-hash short ID for `tx` in 2 `mul_mod` calls.
    #[inline(always)]
    pub const fn short_id(&self, tx: &CompactTx) -> u64 {
        let (w0, w1) = tx.to_field_words();
        let h1 = add_mod(mul_mod(w0, self.r), w1);
        let h2 = add_mod(mul_mod(h1, self.r), self.s);
        h2 as u64
    }
}

impl Drop for RoundShortIdKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

/// Strictly single-use Carter-Wegman polynomial MAC key `(r, s)` over `F_(2^127 - 1)`.
///
/// Intentionally does NOT implement `Copy` or `Clone`; zeroizes itself via volatile writes on drop.
pub struct FastCwKey {
    r: u128,
    s: u128,
}

impl FastCwKey {
    /// Sample a fresh OS-random single-use Carter-Wegman key.
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

    /// Generate `count` independent single-use keys in a single batched OS entropy read.
    pub fn generate_batch(count: usize) -> Vec<Self> {
        let total_elems = count
            .checked_mul(2)
            .expect("FastCwKey batch size overflow");
        let mut elems = vec![0u128; total_elems];
        fill_random_field_elems(&mut elems);
        let mut keys = Vec::with_capacity(count);
        for pair in elems.chunks_exact(2) {
            keys.push(Self {
                r: pair[0],
                s: pair[1],
            });
        }
        zeroize_u128_slice(&mut elems);
        keys
    }

    /// Pre-share duplication strictly for trusted validator setup.
    fn duplicate_for_preshare(&self) -> Self {
        Self {
            r: self.r,
            s: self.s,
        }
    }

    /// Consume this single-use key to seal `prev_tag || height || view || len || txs`
    /// with zero heap allocation and 2 `mul_mod` operations per transaction.
    pub fn seal_batch_consume(
        self,
        prev_tag: &[u8; 16],
        height: u64,
        view: u64,
        txs: &[CompactTx],
    ) -> [u8; 16] {
        let r = self.r;
        let mut s = self.s;
        // Drop consumes and zeroizes `self.r` and `self.s`.
        drop(self);

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

        let tag = add_mod(acc, s);
        zeroize_u128(&mut acc);
        zeroize_u128(&mut s);
        tag.to_le_bytes()
    }

    /// Consume this single-use key to authenticate a fixed 40-byte vote frame header + ciphertext.
    fn mac_vote_consume(self, slot_id: u64, from: u32, to: u32, ct: &[u8; FAST_VOTE_PAYLOAD_LEN]) -> [u8; 16] {
        let r = self.r;
        let mut s = self.s;
        drop(self);

        let hdr_lo = slot_id as u128;
        let hdr_hi = (from as u128) | ((to as u128) << 32);

        let mut acc = add_mod(mul_mod(hdr_lo, r), hdr_hi);
        // 40 bytes = 5 x 8-byte words (< 2^64 < PRIME_P).
        for chunk in ct.chunks_exact(8) {
            let w = u64::from_le_bytes(chunk.try_into().unwrap()) as u128;
            acc = add_mod(mul_mod(acc, r), w);
        }
        let tag = add_mod(acc, s);
        zeroize_u128(&mut acc);
        zeroize_u128(&mut s);
        tag.to_le_bytes()
    }
}

impl Drop for FastCwKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

// ============================================================================
// 2. Bitcoin Core BIP-152-Inspired Compact Batch Relay (`FastMempool` & `CompactBatchProposal`)
// ============================================================================

/// Bitcoin Core BIP-152-inspired compact block proposal transmitting 8-byte universal-hash
/// `short_ids` instead of 24-byte full [`CompactTx`] bodies (~3x wire bandwidth reduction on
/// mempool hits, ~4x vs 32-byte `BinaryTx`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactBatchProposal {
    pub height: u64,
    pub view: u64,
    pub leader_id: u32,
    pub prev_tag: [u8; 16],
    pub block_tag: [u8; 16],
    /// 8-byte per-round Carter-Wegman short IDs in canonical batch order.
    pub short_ids: Vec<u64>,
    /// Optional pre-filled transactions `(batch_index, tx)` for txs unlikely to be in peer mempools.
    pub prefilled_txs: Vec<(u32, CompactTx)>,
}

impl CompactBatchProposal {
    /// Total number of transactions represented by this compact proposal.
    #[inline]
    pub fn tx_count(&self) -> usize {
        self.short_ids.len().saturating_add(self.prefilled_txs.len())
    }

    /// Exact wire byte length of this compact batch proposal.
    #[inline]
    pub fn wire_bytes(&self) -> usize {
        COMPACT_HEADER_SIZE
            .saturating_add(4)
            .saturating_add(self.short_ids.len().saturating_mul(8))
            .saturating_add(
                self.prefilled_txs
                    .len()
                    .saturating_mul(4 + COMPACT_TX_SIZE),
            )
    }

    /// Wire byte length of the equivalent full (non-compact) batch of [`CompactTx`] entries.
    #[inline]
    pub const fn full_block_wire_bytes(tx_count: usize) -> usize {
        COMPACT_HEADER_SIZE + tx_count * COMPACT_TX_SIZE
    }

    /// Bandwidth reduction factor (`full_wire_bytes / compact_wire_bytes`).
    #[inline]
    pub fn bandwidth_ratio(&self) -> f64 {
        let full = Self::full_block_wire_bytes(self.tx_count()) as f64;
        let compact = self.wire_bytes() as f64;
        if compact == 0.0 { 1.0 } else { full / compact }
    }

    /// Serialize the compact proposal to a tight binary wire buffer.
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

    /// Deserialize a compact proposal from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FastEngineError> {
        if bytes.len() < COMPACT_HEADER_SIZE + 4 {
            return Err(FastEngineError::InvalidEncoding("compact proposal header truncated"));
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

        let short_bytes = short_count
            .checked_mul(8)
            .ok_or(FastEngineError::InvalidEncoding(
                "compact proposal short_ids length overflow",
            ))?;
        let prefilled_bytes = prefilled_count
            .checked_mul(4 + COMPACT_TX_SIZE)
            .ok_or(FastEngineError::InvalidEncoding(
                "compact proposal prefilled length overflow",
            ))?;
        let expected_len = (COMPACT_HEADER_SIZE + 4)
            .checked_add(short_bytes)
            .and_then(|v| v.checked_add(prefilled_bytes))
            .ok_or(FastEngineError::InvalidEncoding(
                "compact proposal total length overflow",
            ))?;
        if bytes.len() != expected_len {
            return Err(FastEngineError::InvalidEncoding("compact proposal length mismatch"));
        }

        let mut offset = 60;
        let mut short_ids = Vec::with_capacity(short_count);
        for _ in 0..short_count {
            short_ids.push(u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()));
            offset += 8;
        }

        let mut prefilled_txs = Vec::with_capacity(prefilled_count);
        for _ in 0..prefilled_count {
            let idx = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let raw: &[u8; COMPACT_TX_SIZE] = bytes[offset..offset + COMPACT_TX_SIZE]
                .try_into()
                .unwrap();
            prefilled_txs.push((idx, CompactTx::from_bytes(raw)));
            offset += COMPACT_TX_SIZE;
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

/// High-speed O(1)-indexed transaction mempool supporting BIP-152-style compact batch relay
/// using per-round Carter-Wegman universal-hash 64-bit short IDs.
pub struct FastMempool {
    round_key: RoundShortIdKey,
    by_short_id: HashMap<u64, CompactTx>,
}

impl FastMempool {
    /// Create a new mempool indexed under `round_key`.
    pub fn new(round_key: RoundShortIdKey) -> Self {
        Self {
            round_key,
            by_short_id: HashMap::new(),
        }
    }

    /// Create a new mempool pre-sized for `capacity` pending transactions.
    pub fn with_capacity(round_key: RoundShortIdKey, capacity: usize) -> Self {
        Self {
            round_key,
            by_short_id: HashMap::with_capacity(capacity),
        }
    }

    /// Number of pending transactions currently indexed in the mempool.
    #[inline]
    pub fn len(&self) -> usize {
        self.by_short_id.len()
    }

    /// Whether the mempool is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.by_short_id.is_empty()
    }

    /// Compute the current round's 64-bit universal-hash short ID for `tx`.
    #[inline(always)]
    pub fn compute_short_id(&self, tx: &CompactTx) -> u64 {
        self.round_key.short_id(tx)
    }

    /// Admit and index a single transaction in O(1), returning its 64-bit short ID.
    /// Performs cheap context-free mempool admission checks (mirroring Bitcoin Core `AcceptToMemoryPool`).
    #[inline]
    pub fn insert(&mut self, tx: CompactTx) -> Result<u64, FastEngineError> {
        if tx.amount == 0 {
            return Err(FastEngineError::InvalidTx {
                index: 0,
                reason: "zero transfer amount",
            });
        }
        if tx.sender_id == tx.recipient_id {
            return Err(FastEngineError::InvalidTx {
                index: 0,
                reason: "self-transfer forbidden",
            });
        }
        if tx.page_id == 0 {
            return Err(FastEngineError::InvalidTx {
                index: 0,
                reason: "page_id must be >= 1",
            });
        }
        let sid = self.round_key.short_id(&tx);
        self.by_short_id.insert(sid, tx);
        Ok(sid)
    }

    /// Admit and index a slice of transactions in O(N), returning their 64-bit short IDs.
    pub fn insert_batch(&mut self, txs: &[CompactTx]) -> Result<Vec<u64>, FastEngineError> {
        self.by_short_id.reserve(txs.len());
        let mut sids = Vec::with_capacity(txs.len());
        for (i, &tx) in txs.iter().enumerate() {
            if tx.amount == 0 || tx.sender_id == tx.recipient_id || tx.page_id == 0 {
                return Err(FastEngineError::InvalidTx {
                    index: i,
                    reason: "mempool admission check failed",
                });
            }
            let sid = self.round_key.short_id(&tx);
            self.by_short_id.insert(sid, tx);
            sids.push(sid);
        }
        Ok(sids)
    }

    /// O(1) lookup by 64-bit short ID.
    #[inline(always)]
    pub fn get(&self, short_id: u64) -> Option<CompactTx> {
        self.by_short_id.get(&short_id).copied()
    }

    /// Rotate to a fresh per-round Carter-Wegman session key, re-indexing all remaining
    /// mempool transactions in O(M).
    pub fn rotate_round_key(&mut self, new_key: RoundShortIdKey) {
        let mut next_map = HashMap::with_capacity(self.by_short_id.len());
        for (_, tx) in self.by_short_id.drain() {
            let sid = new_key.short_id(&tx);
            next_map.insert(sid, tx);
        }
        self.round_key = new_key;
        self.by_short_id = next_map;
    }

    /// Evict committed transactions by their short IDs after block finalization.
    pub fn evict_short_ids(&mut self, short_ids: &[u64]) {
        for &sid in short_ids {
            self.by_short_id.remove(&sid);
        }
    }

    /// Build a [`CompactBatchProposal`] from an ordered transaction slice and a single-use
    /// Carter-Wegman sealing key.
    pub fn build_compact_proposal(
        &self,
        height: u64,
        view: u64,
        leader_id: u32,
        prev_tag: [u8; 16],
        txs: &[CompactTx],
        seal_key: FastCwKey,
    ) -> CompactBatchProposal {
        let block_tag = seal_key.seal_batch_consume(&prev_tag, height, view, txs);
        let mut short_ids = Vec::with_capacity(txs.len());
        for tx in txs {
            short_ids.push(self.round_key.short_id(tx));
        }
        CompactBatchProposal {
            height,
            view,
            leader_id,
            prev_tag,
            block_tag,
            short_ids,
            prefilled_txs: Vec::new(),
        }
    }

    /// Reconstruct a full transaction batch in O(N) from a [`CompactBatchProposal`].
    ///
    /// Returns `Ok(txs)` when every short ID hits the local mempool, or `Err(missing_indices)`
    /// listing the exact batch slots requiring a BIP-152 `getblocktxn` round-trip.
    pub fn reconstruct_batch(
        &self,
        proposal: &CompactBatchProposal,
        out: &mut Vec<CompactTx>,
    ) -> Result<(), Vec<usize>> {
        let Some(total) = proposal
            .short_ids
            .len()
            .checked_add(proposal.prefilled_txs.len())
        else {
            return Err(vec![usize::MAX]);
        };
        out.clear();
        out.reserve(total);

        if proposal.prefilled_txs.is_empty() {
            let mut missing = Vec::new();
            for (idx, &sid) in proposal.short_ids.iter().enumerate() {
                if let Some(&tx) = self.by_short_id.get(&sid) {
                    out.push(tx);
                } else {
                    missing.push(idx);
                    out.push(CompactTx::new(0, 0, 0, 0));
                }
            }
            if missing.is_empty() {
                Ok(())
            } else {
                Err(missing)
            }
        } else {
            // Merge prefilled transactions at their exact target indices with short_ids.
            let mut slots: Vec<Option<CompactTx>> = vec![None; total];
            for &(idx, tx) in &proposal.prefilled_txs {
                let i = idx as usize;
                if i >= total || slots[i].is_some() {
                    return Err(vec![i]);
                }
                slots[i] = Some(tx);
            }
            let mut sid_iter = proposal.short_ids.iter();
            let mut missing = Vec::new();
            for (idx, slot) in slots.iter_mut().enumerate() {
                if slot.is_some() {
                    continue;
                }
                if let Some(&sid) = sid_iter.next() {
                    if let Some(&tx) = self.by_short_id.get(&sid) {
                        *slot = Some(tx);
                    } else {
                        missing.push(idx);
                    }
                } else {
                    missing.push(idx);
                }
            }
            for slot in slots {
                out.push(slot.unwrap_or(CompactTx::new(0, 0, 0, 0)));
            }
            if !missing.is_empty() {
                return Err(missing);
            }
            Ok(())
        }
    }

    /// Complete batch reconstruction by patching missing indices fetched via `blocktxn` fallback.
    pub fn patch_missing_txs(
        &mut self,
        buf: &mut [CompactTx],
        fetched: &[(usize, CompactTx)],
    ) -> Result<(), FastEngineError> {
        for &(idx, tx) in fetched {
            if idx >= buf.len() {
                return Err(FastEngineError::InvalidParameters(
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

// ============================================================================
// 3. O(1) Flat `IndexedLedger` (Bitcoin Core CCoinsViewCache + Solana Flat Arrays)
// ============================================================================

/// O(1) flat indexed ledger state eliminating `BTreeMap` O(log N) pointer chasing and unbounded
/// `HashSet` replay sets.
///
/// Uses contiguous `Vec<u64>` tables indexed directly by `account_id as usize` plus a
/// pre-allocated undo-log rollback buffer (analogous to Bitcoin Core's `CCoinsViewCache`
/// dirty overlay) so atomic batch validation + commit runs in a single L1-cache-hot pass
/// with **zero heap allocations**.
#[derive(Debug, Clone)]
pub struct IndexedLedger {
    pub height: u64,
    pub tip_tag: [u8; 16],
    balances: Vec<u64>,
    last_page_id: Vec<u64>,
    /// Reusable LIFO undo log `(account_id, prev_balance, prev_page_id)` for atomic rollback.
    undo_log: Vec<(u32, u64, u64)>,
}

impl IndexedLedger {
    /// Initialize a flat indexed ledger with `initial_balances[account_id]`.
    pub fn new(initial_balances: Vec<u64>) -> Self {
        let n = initial_balances.len();
        Self {
            height: 0,
            tip_tag: FAST_GENESIS_TAG,
            balances: initial_balances,
            last_page_id: vec![0u64; n],
            undo_log: Vec::with_capacity(4096),
        }
    }

    /// Total number of accounts allocated in the flat table.
    #[inline(always)]
    pub fn num_accounts(&self) -> usize {
        self.balances.len()
    }

    /// O(1) balance lookup for `account_id`.
    #[inline(always)]
    pub fn balance_of(&self, account_id: u32) -> u64 {
        self.balances.get(account_id as usize).copied().unwrap_or(0)
    }

    /// O(1) last committed monotonic OTP `page_id` for `account_id`.
    #[inline(always)]
    pub fn last_page_of(&self, account_id: u32) -> u64 {
        self.last_page_id
            .get(account_id as usize)
            .copied()
            .unwrap_or(0)
    }

    /// Contiguous read-only slice of all balances (useful for state root / equality checks).
    #[inline]
    pub fn balances(&self) -> &[u64] {
        &self.balances
    }

    /// Roll back every speculative mutation recorded in `self.undo_log` in exact reverse LIFO order.
    #[inline]
    fn rollback_undo_log(&mut self) {
        for &(acct, old_bal, old_page) in self.undo_log.iter().rev() {
            let idx = acct as usize;
            self.balances[idx] = old_bal;
            self.last_page_id[idx] = old_page;
        }
        self.undo_log.clear();
    }

    /// Speculatively execute a batch in-place, rolling back automatically via the undo log if ANY
    /// transaction fails validation. Leaves mutations staged in `self.undo_log` on success so the
    /// caller can either [`commit_staged`] or [`abort_staged`] in O(1) / O(batch_len).
    pub fn stage_batch(
        &mut self,
        height: u64,
        prev_tag: &[u8; 16],
        txs: &[CompactTx],
    ) -> Result<(), FastEngineError> {
        if !self.undo_log.is_empty() {
            return Err(FastEngineError::InvalidParameters(
                "cannot stage_batch while a previous staged batch is still uncommitted",
            ));
        }
        let expected_height = self
            .height
            .checked_add(1)
            .ok_or(FastEngineError::ChainLinkMismatch {
                expected_height: u64::MAX,
                got_height: height,
            })?;
        if height != expected_height || !ct_eq_16(prev_tag, &self.tip_tag) {
            return Err(FastEngineError::ChainLinkMismatch {
                expected_height,
                got_height: height,
            });
        }

        let max_accounts = self.balances.len();
        self.undo_log.clear();
        let needed_cap = txs.len().checked_mul(2).ok_or(
            FastEngineError::InvalidParameters("batch too large for undo log"),
        )?;
        if self.undo_log.capacity() < needed_cap {
            self.undo_log.reserve(needed_cap - self.undo_log.len());
        }

        for (index, tx) in txs.iter().enumerate() {
            if tx.amount == 0 {
                self.rollback_undo_log();
                return Err(FastEngineError::InvalidTx {
                    index,
                    reason: "zero transfer amount",
                });
            }
            if tx.sender_id == tx.recipient_id {
                self.rollback_undo_log();
                return Err(FastEngineError::InvalidTx {
                    index,
                    reason: "self-transfer forbidden",
                });
            }
            let s = tx.sender_id as usize;
            let r = tx.recipient_id as usize;
            if s >= max_accounts {
                self.rollback_undo_log();
                return Err(FastEngineError::AccountOutOfRange {
                    account_id: tx.sender_id,
                    max_accounts,
                });
            }
            if r >= max_accounts {
                self.rollback_undo_log();
                return Err(FastEngineError::AccountOutOfRange {
                    account_id: tx.recipient_id,
                    max_accounts,
                });
            }

            let old_s_page = self.last_page_id[s];
            if tx.page_id <= old_s_page {
                self.rollback_undo_log();
                return Err(FastEngineError::InvalidTx {
                    index,
                    reason: "non-monotonic or replayed page_id",
                });
            }

            let old_s_bal = self.balances[s];
            if old_s_bal < tx.amount {
                self.rollback_undo_log();
                return Err(FastEngineError::InvalidTx {
                    index,
                    reason: "insufficient balance",
                });
            }

            let old_r_bal = self.balances[r];
            let Some(new_r_bal) = old_r_bal.checked_add(tx.amount) else {
                self.rollback_undo_log();
                return Err(FastEngineError::InvalidTx {
                    index,
                    reason: "recipient balance overflow",
                });
            };
            let old_r_page = self.last_page_id[r];

            self.undo_log.push((tx.sender_id, old_s_bal, old_s_page));
            self.undo_log.push((tx.recipient_id, old_r_bal, old_r_page));

            self.balances[s] = old_s_bal - tx.amount;
            self.last_page_id[s] = tx.page_id;
            self.balances[r] = new_r_bal;
        }

        Ok(())
    }

    /// Finalize the currently staged batch in O(1), advancing `height` and `tip_tag`.
    #[inline]
    pub fn commit_staged(&mut self, height: u64, block_tag: [u8; 16]) {
        self.height = height;
        self.tip_tag = block_tag;
        self.undo_log.clear();
    }

    /// Abort the currently staged batch, restoring exact pre-batch state.
    #[inline]
    pub fn abort_staged(&mut self) {
        self.rollback_undo_log();
    }

    /// Atomically validate and commit a batch in a single zero-allocation pass.
    pub fn apply_batch_atomic(
        &mut self,
        height: u64,
        prev_tag: &[u8; 16],
        block_tag: [u8; 16],
        txs: &[CompactTx],
    ) -> Result<(), FastEngineError> {
        self.stage_batch(height, prev_tag, txs)?;
        self.commit_staged(height, block_tag);
        Ok(())
    }
}

// ============================================================================
// 4. Parallel 4-Validator 2-Phase Batched BFT (`FastExpressCluster`)
// ============================================================================

/// Fixed-size vote OTP pad automatically zeroized with volatile writes on drop.
struct FastOtpPad([u8; FAST_VOTE_PAYLOAD_LEN]);

impl Drop for FastOtpPad {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

/// O(1) pairwise single-use OTP + Carter-Wegman slot for fast BFT vote frames.
/// Both `otp_pad` and `cw_key` zeroize themselves automatically on drop.
struct FastLinkSlot {
    otp_pad: FastOtpPad,
    cw_key: FastCwKey,
}

/// Flat contiguous O(1) single-use pairwise OTP+CW deck (eliminates `BTreeMap` overhead).
struct FastLinkDeck {
    slots: Vec<Option<FastLinkSlot>>,
    next_send_idx: usize,
}

impl FastLinkDeck {
    fn create_pair(count: usize) -> (Self, Self) {
        let mut out_slots = Vec::with_capacity(count);
        let mut in_slots = Vec::with_capacity(count);
        let cw_keys = FastCwKey::generate_batch(count);
        let pad_bytes = count
            .checked_mul(FAST_VOTE_PAYLOAD_LEN)
            .expect("FastLinkDeck pad buffer overflow");
        let mut pads = vec![0u8; pad_bytes];
        fill_os_random(&mut pads);

        for (i, cw_a) in cw_keys.into_iter().enumerate() {
            let cw_b = cw_a.duplicate_for_preshare();
            let mut pad = [0u8; FAST_VOTE_PAYLOAD_LEN];
            pad.copy_from_slice(
                &pads[i * FAST_VOTE_PAYLOAD_LEN..(i + 1) * FAST_VOTE_PAYLOAD_LEN],
            );
            out_slots.push(Some(FastLinkSlot {
                otp_pad: FastOtpPad(pad),
                cw_key: cw_a,
            }));
            in_slots.push(Some(FastLinkSlot {
                otp_pad: FastOtpPad(pad),
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

    fn seal_vote(
        &mut self,
        from: u32,
        to: u32,
        payload: &[u8; FAST_VOTE_PAYLOAD_LEN],
    ) -> Result<FastVoteFrame, FastEngineError> {
        let idx = self.next_send_idx;
        let next_idx = idx
            .checked_add(1)
            .ok_or(FastEngineError::OtpDeckExhausted)?;
        let slot = self
            .slots
            .get_mut(idx)
            .and_then(Option::take)
            .ok_or(FastEngineError::OtpDeckExhausted)?;
        self.next_send_idx = next_idx;

        let FastLinkSlot { otp_pad, cw_key } = slot;
        let mut ct = [0u8; FAST_VOTE_PAYLOAD_LEN];
        for i in 0..FAST_VOTE_PAYLOAD_LEN {
            ct[i] = payload[i] ^ otp_pad.0[i];
        }
        drop(otp_pad);

        let tag = cw_key.mac_vote_consume(idx as u64, from, to, &ct);
        Ok(FastVoteFrame {
            slot_id: idx as u64,
            from,
            to,
            ciphertext: ct,
            tag,
        })
    }

    fn open_vote(
        &mut self,
        frame: &FastVoteFrame,
        expected_from: u32,
        expected_to: u32,
    ) -> Result<[u8; FAST_VOTE_PAYLOAD_LEN], FastEngineError> {
        if frame.from != expected_from || frame.to != expected_to {
            return Err(FastEngineError::InvalidEncoding("vote endpoint mismatch"));
        }
        let slot_idx =
            usize::try_from(frame.slot_id).map_err(|_| FastEngineError::OtpDeckExhausted)?;
        let slot = self
            .slots
            .get_mut(slot_idx)
            .and_then(Option::take)
            .ok_or(FastEngineError::OtpDeckExhausted)?;

        let FastLinkSlot { otp_pad, cw_key } = slot;
        let computed = cw_key.mac_vote_consume(frame.slot_id, frame.from, frame.to, &frame.ciphertext);
        if !ct_eq_16(&computed, &frame.tag) {
            drop(otp_pad);
            return Err(FastEngineError::InvalidMac);
        }

        let mut pt = [0u8; FAST_VOTE_PAYLOAD_LEN];
        for i in 0..FAST_VOTE_PAYLOAD_LEN {
            pt[i] = frame.ciphertext[i] ^ otp_pad.0[i];
        }
        drop(otp_pad);
        Ok(pt)
    }
}

/// Fixed-size OTP-encrypted + Carter-Wegman-authenticated BFT vote frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FastVoteFrame {
    slot_id: u64,
    from: u32,
    to: u32,
    ciphertext: [u8; FAST_VOTE_PAYLOAD_LEN],
    tag: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum FastVoteKind {
    Prepare = 2,
    Commit = 3,
}

#[inline]
fn encode_vote(
    kind: FastVoteKind,
    voter_id: u32,
    height: u64,
    view: u64,
    block_tag: &[u8; 16],
) -> [u8; FAST_VOTE_PAYLOAD_LEN] {
    let mut buf = [0u8; FAST_VOTE_PAYLOAD_LEN];
    buf[0] = kind as u8;
    buf[4..8].copy_from_slice(&voter_id.to_le_bytes());
    buf[8..16].copy_from_slice(&height.to_le_bytes());
    buf[16..24].copy_from_slice(&view.to_le_bytes());
    buf[24..40].copy_from_slice(block_tag);
    buf
}

#[inline]
fn decode_and_check_vote(
    buf: &[u8; FAST_VOTE_PAYLOAD_LEN],
    expected_kind: FastVoteKind,
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

/// Quorum certificate returned when a batch is finalized across `FastExpressCluster`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastBlockCert {
    pub height: u64,
    pub view: u64,
    pub leader_id: u32,
    pub prev_tag: [u8; 16],
    pub block_tag: [u8; 16],
    pub tx_count: usize,
    pub commit_voters: [bool; FAST_NUM_VALIDATORS],
    pub commit_quorum: usize,
}

/// Maximum supported view changes per block height (each `(height, view)` has its own single-use seal key).
const VIEWS_PER_HEIGHT: usize = 4;

/// Independent validator state inside [`FastExpressCluster`].
struct FastValidator {
    id: u32,
    ledger: IndexedLedger,
    mempool: FastMempool,
    /// Pre-allocated scratch buffer for compact batch reconstruction (zero per-round allocs).
    tx_scratch: Vec<CompactTx>,
    /// Dedicated single-use Carter-Wegman block sealing keys indexed by `(height - 1) * VIEWS_PER_HEIGHT + view`.
    seal_keys: Vec<Option<FastCwKey>>,
    /// Directed pairwise outbound OTP+CW vote decks (index = peer validator id).
    outbound: [Option<FastLinkDeck>; FAST_NUM_VALIDATORS],
    /// Directed pairwise inbound OTP+CW vote decks (index = peer validator id).
    inbound: [Option<FastLinkDeck>; FAST_NUM_VALIDATORS],
}

/// High-throughput 4-validator (`N = 4, f = 1, quorum = 3`) 2-phase batched BFT cluster.
///
/// Combines:
/// - **BIP-152 Compact Batch Relay** (`FastMempool` + 8-byte universal-hash short IDs),
/// - **O(1) Flat `IndexedLedger`** with zero-alloc undo-log staging/rollback,
/// - **Parallel Multi-Core Validation & Sealing** across all 4 validators via `std::thread::scope`,
/// - **O(1) Pairwise OTP+CW Vote Decks** for full Prepare + Commit 2-phase BFT finality.
pub struct FastExpressCluster {
    validators: [FastValidator; FAST_NUM_VALIDATORS],
    provisioned_blocks: usize,
    current_view: u64,
}

impl FastExpressCluster {
    /// Provision a 4-validator `FastExpressCluster` with `initial_balances` and single-use key
    /// capacity for `max_blocks` BFT heights (with up to 4 view-change keys per height).
    pub fn new(initial_balances: Vec<u64>, max_blocks: usize) -> Self {
        let round_key = RoundShortIdKey::generate();
        let total_seal_keys = max_blocks.saturating_mul(VIEWS_PER_HEIGHT).max(VIEWS_PER_HEIGHT);
        let master_seals = FastCwKey::generate_batch(total_seal_keys);

        // Pre-share pairwise OTP+CW vote decks (2 vote frames per peer per round: Prepare + Commit).
        let slots_per_link = total_seal_keys.saturating_mul(2).max(16);
        let mut out_decks: Vec<[Option<FastLinkDeck>; FAST_NUM_VALIDATORS]> =
            (0..FAST_NUM_VALIDATORS).map(|_| [None, None, None, None]).collect();
        let mut in_decks: Vec<[Option<FastLinkDeck>; FAST_NUM_VALIDATORS]> =
            (0..FAST_NUM_VALIDATORS).map(|_| [None, None, None, None]).collect();

        for from in 0..FAST_NUM_VALIDATORS {
            for to in 0..FAST_NUM_VALIDATORS {
                if from == to {
                    continue;
                }
                let (out_d, in_d) = FastLinkDeck::create_pair(slots_per_link);
                out_decks[from][to] = Some(out_d);
                in_decks[to][from] = Some(in_d);
            }
        }

        let mut validators_vec = Vec::with_capacity(FAST_NUM_VALIDATORS);
        for (id, (outbound, inbound)) in out_decks
            .into_iter()
            .zip(in_decks.into_iter())
            .enumerate()
        {
            let seal_keys: Vec<Option<FastCwKey>> = master_seals
                .iter()
                .map(|k| Some(k.duplicate_for_preshare()))
                .collect();
            validators_vec.push(FastValidator {
                id: id as u32,
                ledger: IndexedLedger::new(initial_balances.clone()),
                mempool: FastMempool::new(round_key.duplicate_for_round()),
                tx_scratch: Vec::with_capacity(4096),
                seal_keys,
                outbound,
                inbound,
            });
        }

        let validators: [FastValidator; FAST_NUM_VALIDATORS] = validators_vec
            .try_into()
            .unwrap_or_else(|_| panic!("expected exactly 4 validators"));

        Self {
            validators,
            provisioned_blocks: max_blocks,
            current_view: 0,
        }
    }

    /// Current committed block height (identical across all 4 honest validators).
    #[inline]
    pub fn height(&self) -> u64 {
        self.validators[0].ledger.height
    }

    /// Current chain integrity tip tag.
    #[inline]
    pub fn tip_tag(&self) -> [u8; 16] {
        self.validators[0].ledger.tip_tag
    }

    /// Read-only view of validator `id`'s flat [`IndexedLedger`].
    #[inline]
    pub fn validator_ledger(&self, validator_id: usize) -> &IndexedLedger {
        &self.validators[validator_id].ledger
    }

    /// Read-only view of validator `id`'s [`FastMempool`].
    #[inline]
    pub fn validator_mempool(&self, validator_id: usize) -> &FastMempool {
        &self.validators[validator_id].mempool
    }

    /// Total number of blocks for which single-use sealing/vote keys were provisioned.
    #[inline]
    pub fn provisioned_blocks(&self) -> usize {
        self.provisioned_blocks
    }

    /// Gossip a batch of transactions into all 4 validators' [`FastMempool`]s, returning their
    /// 64-bit universal-hash short IDs.
    pub fn gossip_to_mempools(&mut self, txs: &[CompactTx]) -> Result<Vec<u64>, FastEngineError> {
        let mut first_sids = Vec::new();
        for (i, v) in self.validators.iter_mut().enumerate() {
            let sids = v.mempool.insert_batch(txs)?;
            if i == 0 {
                first_sids = sids;
            }
        }
        Ok(first_sids)
    }

    /// Execute a full 2-phase BFT round (PrePrepare -> Prepare -> Commit) for `txs` across all
    /// 4 validators in parallel via `std::thread::scope`.
    ///
    /// - Single-use Carter-Wegman block sealing & verification across all 4 validators.
    /// - Atomic flat `IndexedLedger` staging with automatic rollback across all 4 validators on any
    ///   invalid transaction (overdraft, replayed/non-monotonic `page_id`, zero amount, etc.).
    /// - Full pairwise OTP-encrypted, Carter-Wegman-authenticated Prepare and Commit vote frames.
    pub fn commit_batch(&mut self, txs: &[CompactTx]) -> Result<FastBlockCert, FastEngineError> {
        let height = self.validators[0]
            .ledger
            .height
            .checked_add(1)
            .ok_or(FastEngineError::ChainLinkMismatch {
                expected_height: u64::MAX,
                got_height: u64::MAX,
            })?;
        let view = self.current_view;
        let leader_id = (((height as u128) + (view as u128)) % (FAST_NUM_VALIDATORS as u128)) as usize;
        let prev_tag = self.validators[0].ledger.tip_tag;
        if (view as usize) >= VIEWS_PER_HEIGHT {
            return Err(FastEngineError::MissingBlockSealKey { height });
        }
        let key_idx = usize::try_from(height - 1)
            .ok()
            .and_then(|h| h.checked_mul(VIEWS_PER_HEIGHT))
            .and_then(|v| v.checked_add(view as usize))
            .ok_or(FastEngineError::MissingBlockSealKey { height })?;

        // Stage 1: Leader consumes its dedicated single-use sealing key and seals the batch.
        let leader_seal_key = self.validators[leader_id]
            .seal_keys
            .get_mut(key_idx)
            .and_then(Option::take)
            .ok_or(FastEngineError::MissingBlockSealKey { height })?;
        let block_tag = leader_seal_key.seal_batch_consume(&prev_tag, height, view, txs);

        let res = self.run_parallel_bft_phases(
            height,
            view,
            leader_id,
            prev_tag,
            block_tag,
            None,
            Some(txs),
        );
        match res {
            Ok(cert) => {
                self.current_view = 0;
                Ok(cert)
            }
            Err(e) => {
                self.current_view = self.current_view.saturating_add(1);
                Err(e)
            }
        }
    }

    /// Execute a full 2-phase BFT round using **BIP-152 Compact Batch Relay**:
    /// the leader broadcasts only a [`CompactBatchProposal`] (8-byte universal-hash short IDs),
    /// and all followers reconstruct the full `CompactTx` batch from their local [`FastMempool`]
    /// in O(N) in parallel across CPU cores before verifying the CW seal and voting.
    pub fn commit_compact_batch(
        &mut self,
        txs: &[CompactTx],
    ) -> Result<(FastBlockCert, CompactBatchProposal), FastEngineError> {
        let height = self.validators[0]
            .ledger
            .height
            .checked_add(1)
            .ok_or(FastEngineError::ChainLinkMismatch {
                expected_height: u64::MAX,
                got_height: u64::MAX,
            })?;
        let view = self.current_view;
        let leader_id = (((height as u128) + (view as u128)) % (FAST_NUM_VALIDATORS as u128)) as usize;
        let prev_tag = self.validators[0].ledger.tip_tag;
        if (view as usize) >= VIEWS_PER_HEIGHT {
            return Err(FastEngineError::MissingBlockSealKey { height });
        }
        let key_idx = usize::try_from(height - 1)
            .ok()
            .and_then(|h| h.checked_mul(VIEWS_PER_HEIGHT))
            .and_then(|v| v.checked_add(view as usize))
            .ok_or(FastEngineError::MissingBlockSealKey { height })?;

        let leader_seal_key = self.validators[leader_id]
            .seal_keys
            .get_mut(key_idx)
            .and_then(Option::take)
            .ok_or(FastEngineError::MissingBlockSealKey { height })?;
        let proposal = self.validators[leader_id].mempool.build_compact_proposal(
            height,
            view,
            leader_id as u32,
            prev_tag,
            txs,
            leader_seal_key,
        );

        let cert = match self.run_parallel_bft_phases(
            height,
            view,
            leader_id,
            prev_tag,
            proposal.block_tag,
            Some(&proposal),
            Some(txs),
        ) {
            Ok(c) => {
                self.current_view = 0;
                c
            }
            Err(e) => {
                self.current_view = self.current_view.saturating_add(1);
                return Err(e);
            }
        };

        // Evict committed short IDs from all mempools in parallel.
        let short_ids = &proposal.short_ids;
        std::thread::scope(|scope| {
            for v in self.validators.iter_mut() {
                scope.spawn(move || {
                    v.mempool.evict_short_ids(short_ids);
                });
            }
        });

        Ok((cert, proposal))
    }

    /// Core pipelined parallel 2-phase BFT execution across all 4 validators via `std::thread::scope`.
    #[allow(clippy::too_many_arguments)]
    fn run_parallel_bft_phases(
        &mut self,
        height: u64,
        view: u64,
        leader_id: usize,
        prev_tag: [u8; 16],
        block_tag: [u8; 16],
        compact_proposal: Option<&CompactBatchProposal>,
        fallback_txs: Option<&[CompactTx]>,
    ) -> Result<FastBlockCert, FastEngineError> {
        let key_idx = height
            .checked_sub(1)
            .and_then(|h| usize::try_from(h).ok())
            .and_then(|h| h.checked_mul(VIEWS_PER_HEIGHT))
            .and_then(|v| v.checked_add(view as usize))
            .ok_or(FastEngineError::MissingBlockSealKey { height })?;

        // Phase 1 (Parallel across 4 validators):
        // - Followers reconstruct compact batch (if compact mode) & verify dedicated CW block seal.
        // - Every validator speculatively validates & stages batch into its flat IndexedLedger.
        // - Every validator seals 3 outbound Prepare OTP+CW vote frames.
        let prepare_results: [Result<[Option<FastVoteFrame>; FAST_NUM_VALIDATORS], FastEngineError>;
            FAST_NUM_VALIDATORS] = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(FAST_NUM_VALIDATORS);
            for v in self.validators.iter_mut() {
                handles.push(scope.spawn(move || {
                    let is_leader = v.id as usize == leader_id;

                    // Determine transaction slice (reconstructing from mempool if compact proposal).
                    if let Some(prop) = compact_proposal {
                        if !is_leader {
                            if let Err(missing) = v.mempool.reconstruct_batch(prop, &mut v.tx_scratch)
                            {
                                // BIP-152 `getblocktxn` / `blocktxn` fallback for any mempool miss.
                                if let Some(src) = fallback_txs {
                                    for idx in missing {
                                        if idx < v.tx_scratch.len() && idx < src.len() {
                                            v.tx_scratch[idx] = src[idx];
                                        } else {
                                            return Err(FastEngineError::MissingCompactTx {
                                                short_id: prop
                                                    .short_ids
                                                    .get(idx)
                                                    .copied()
                                                    .unwrap_or(0),
                                            });
                                        }
                                    }
                                } else {
                                    return Err(FastEngineError::MissingCompactTx {
                                        short_id: missing
                                            .first()
                                            .and_then(|&idx| prop.short_ids.get(idx).copied())
                                            .unwrap_or(0),
                                    });
                                }
                            }
                        } else if let Some(src) = fallback_txs {
                            v.tx_scratch.clear();
                            v.tx_scratch.extend_from_slice(src);
                        }
                    } else if let Some(src) = fallback_txs {
                        v.tx_scratch.clear();
                        v.tx_scratch.extend_from_slice(src);
                    }

                    // Followers consume their dedicated single-use CW sealing key and verify seal.
                    if !is_leader {
                        let seal_key = v
                            .seal_keys
                            .get_mut(key_idx)
                            .and_then(Option::take)
                            .ok_or(FastEngineError::MissingBlockSealKey { height })?;
                        let computed = seal_key.seal_batch_consume(
                            &prev_tag,
                            height,
                            view,
                            &v.tx_scratch,
                        );
                        if !ct_eq_16(&computed, &block_tag) {
                            return Err(FastEngineError::InvalidBlockSeal { height });
                        }
                    }

                    // Zero-alloc speculative batch validation + staging onto flat IndexedLedger.
                    v.ledger.stage_batch(height, &prev_tag, &v.tx_scratch)?;

                    // Seal pairwise OTP+CW authenticated Prepare vote frames to all 3 peers.
                    let payload =
                        encode_vote(FastVoteKind::Prepare, v.id, height, view, &block_tag);
                    let mut frames: [Option<FastVoteFrame>; FAST_NUM_VALIDATORS] = [None; 4];
                    for peer in 0..FAST_NUM_VALIDATORS {
                        if peer == v.id as usize {
                            continue;
                        }
                        let deck = v.outbound[peer]
                            .as_mut()
                            .ok_or(FastEngineError::OtpDeckExhausted)?;
                        frames[peer] = Some(deck.seal_vote(v.id, peer as u32, &payload)?);
                    }
                    Ok(frames)
                }));
            }

            let mut out = [const { Ok([None; 4]) }; FAST_NUM_VALIDATORS];
            for (i, h) in handles.into_iter().enumerate() {
                out[i] = h.join().expect("validator worker thread panicked");
            }
            out
        });

        // If any validator failed validation or sealing, abort all staged ledgers cleanly.
        let mut prepare_matrix: [[Option<FastVoteFrame>; FAST_NUM_VALIDATORS]; FAST_NUM_VALIDATORS] =
            [[None; 4]; 4];
        for (i, res) in prepare_results.into_iter().enumerate() {
            match res {
                Ok(frames) => prepare_matrix[i] = frames,
                Err(err) => {
                    for v in self.validators.iter_mut() {
                        v.ledger.abort_staged();
                    }
                    return Err(err);
                }
            }
        }

        // Phase 2 (Parallel across 4 validators):
        // - Each validator opens and authenticates all inbound Prepare frames, verifies >= 3 quorum,
        //   and emits 3 outbound OTP+CW authenticated Commit frames.
        let commit_results: [Result<[Option<FastVoteFrame>; FAST_NUM_VALIDATORS], FastEngineError>;
            FAST_NUM_VALIDATORS] = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(FAST_NUM_VALIDATORS);
            let prep_ref = &prepare_matrix;
            for v in self.validators.iter_mut() {
                handles.push(scope.spawn(move || {
                    let me = v.id as usize;
                    let mut prepare_votes = 1usize; // self vote
                    for sender in 0..FAST_NUM_VALIDATORS {
                        if sender == me {
                            continue;
                        }
                        if let Some(frame) = prep_ref[sender][me] {
                            // Tolerate up to f = 1 Byzantine bad Prepare vote frame.
                            if let Some(deck) = v.inbound[sender].as_mut()
                                && let Ok(pt) = deck.open_vote(&frame, sender as u32, v.id)
                                && decode_and_check_vote(
                                    &pt,
                                    FastVoteKind::Prepare,
                                    sender as u32,
                                    height,
                                    view,
                                    &block_tag,
                                )
                            {
                                prepare_votes += 1;
                            }
                        }
                    }
                    if prepare_votes < FAST_QUORUM {
                        return Err(FastEngineError::QuorumNotReached {
                            phase: "Prepare",
                            votes: prepare_votes,
                            quorum: FAST_QUORUM,
                        });
                    }

                    let payload =
                        encode_vote(FastVoteKind::Commit, v.id, height, view, &block_tag);
                    let mut frames: [Option<FastVoteFrame>; FAST_NUM_VALIDATORS] = [None; 4];
                    for peer in 0..FAST_NUM_VALIDATORS {
                        if peer == me {
                            continue;
                        }
                        let deck = v.outbound[peer]
                            .as_mut()
                            .ok_or(FastEngineError::OtpDeckExhausted)?;
                        frames[peer] = Some(deck.seal_vote(v.id, peer as u32, &payload)?);
                    }
                    Ok(frames)
                }));
            }

            let mut out = [const { Ok([None; 4]) }; FAST_NUM_VALIDATORS];
            for (i, h) in handles.into_iter().enumerate() {
                out[i] = h.join().expect("validator worker thread panicked");
            }
            out
        });

        let mut commit_matrix: [[Option<FastVoteFrame>; FAST_NUM_VALIDATORS]; FAST_NUM_VALIDATORS] =
            [[None; 4]; 4];
        for (i, res) in commit_results.into_iter().enumerate() {
            match res {
                Ok(frames) => commit_matrix[i] = frames,
                Err(err) => {
                    for v in self.validators.iter_mut() {
                        v.ledger.abort_staged();
                    }
                    return Err(err);
                }
            }
        }

        // Phase 3 (Parallel across 4 validators):
        // - Verify >= 3 distinct Commit frames and finalize staged flat ledger state in O(1).
        let finalize_results: [Result<[bool; FAST_NUM_VALIDATORS], FastEngineError>;
            FAST_NUM_VALIDATORS] = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(FAST_NUM_VALIDATORS);
            let commit_ref = &commit_matrix;
            for v in self.validators.iter_mut() {
                handles.push(scope.spawn(move || {
                    let me = v.id as usize;
                    let mut voters = [false; FAST_NUM_VALIDATORS];
                    voters[me] = true;
                    let mut count = 1usize;

                    for sender in 0..FAST_NUM_VALIDATORS {
                        if sender == me {
                            continue;
                        }
                        if let Some(frame) = commit_ref[sender][me] {
                            // Tolerate up to f = 1 Byzantine bad Commit vote frame.
                            if let Some(deck) = v.inbound[sender].as_mut()
                                && let Ok(pt) = deck.open_vote(&frame, sender as u32, v.id)
                                && decode_and_check_vote(
                                    &pt,
                                    FastVoteKind::Commit,
                                    sender as u32,
                                    height,
                                    view,
                                    &block_tag,
                                )
                            {
                                voters[sender] = true;
                                count += 1;
                            }
                        }
                    }

                    if count < FAST_QUORUM {
                        v.ledger.abort_staged();
                        return Err(FastEngineError::QuorumNotReached {
                            phase: "Commit",
                            votes: count,
                            quorum: FAST_QUORUM,
                        });
                    }

                    v.ledger.commit_staged(height, block_tag);
                    Ok(voters)
                }));
            }

            let mut out = [const { Ok([false; 4]) }; FAST_NUM_VALIDATORS];
            for (i, h) in handles.into_iter().enumerate() {
                out[i] = h.join().expect("validator worker thread panicked");
            }
            out
        });

        let mut commit_voters = [false; FAST_NUM_VALIDATORS];
        for res in finalize_results {
            let v_votes = res?;
            for (dst, src) in commit_voters.iter_mut().zip(v_votes.iter()) {
                *dst |= *src;
            }
        }
        let commit_quorum = commit_voters.iter().filter(|&&b| b).count();
        let tx_count = self.validators[0].tx_scratch.len();

        Ok(FastBlockCert {
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
}

// ============================================================================
// 5. Compile-Time `Lagrange3Of4` & Stack-Only `(3, 4)` Shamir IT-MPC Primitives
// ============================================================================

/// Multiply a field element by 3 modulo `PRIME_P` using only 2 modular additions (zero `mul_mod`).
#[inline(always)]
const fn mul3_mod(x: u128) -> u128 {
    add_mod(add_mod(x, x), x)
}

/// Compile-time precomputed `(3, 4)` Shamir Lagrange interpolator and degree-2 verifier over
/// `F_(2^127 - 1)` for validator evaluation points `x = 1, 2, 3, 4`.
///
/// Eliminates all online `inv_mod` calls, all heap allocations, and even all `mul_mod` calls
/// during interpolation, parity checking, and polynomial evaluation via exact finite-difference
/// identities:
/// - `P(0) = 3*y1 - 3*y2 + y3 (mod P)`
/// - `P(4) = y1 - 3*y2 + 3*y3 (mod P)` (degree-2 parity check: `y1 - 3*y2 + 3*y3 - y4 == 0`)
pub struct Lagrange3Of4;

impl Lagrange3Of4 {
    /// Compile-time Lagrange basis coefficients `lambda_j(0)` for `x = 1, 2, 3`: `[3, -3, 1] mod P`.
    pub const ORIGIN_COEFFS: [u128; 3] = [3, PRIME_P - 3, 1];

    /// Compile-time Lagrange basis coefficients `ell_j(4)` for `x = 1, 2, 3`: `[1, -3, 3] mod P`.
    pub const VERIFY_X4_COEFFS: [u128; 3] = [1, PRIME_P - 3, 3];

    /// Compile-time parity-check vector `h` such that `dot(h, [y1, y2, y3, y4]) == 0` iff
    /// the 4 shares lie on a unique polynomial of degree `<= 2`.
    pub const PARITY_COEFFS: [u128; 4] = [1, PRIME_P - 3, 3, PRIME_P - 1];

    /// Evaluate degree-2 polynomial `c0 + c1*x + c2*x^2` at `x = 1, 2, 3, 4` using pure
    /// finite-difference additions (zero `mul_mod`, zero heap allocation).
    #[inline(always)]
    pub const fn eval_poly(c0: u128, c1: u128, c2: u128) -> Share4 {
        let d1 = add_mod(c1, c2);
        let d2 = add_mod(c2, c2);
        let y1 = add_mod(c0, d1);
        let step1 = add_mod(d1, d2);
        let y2 = add_mod(y1, step1);
        let step2 = add_mod(step1, d2);
        let y3 = add_mod(y2, step2);
        let step3 = add_mod(step2, d2);
        let y4 = add_mod(y3, step3);
        [y1, y2, y3, y4]
    }

    /// Split a secret in `[0, PRIME_P)` into a stack-allocated `(3, 4)` Shamir [`Share4`].
    #[inline]
    pub fn split_secret(secret: u128) -> Result<Share4, FastEngineError> {
        if secret >= PRIME_P {
            return Err(FastEngineError::FieldElementOutOfRange);
        }
        let mut r = [0u128; 2];
        fill_random_field_elems(&mut r);
        let shares = Self::eval_poly(secret, r[0], r[1]);
        zeroize_u128_slice(&mut r);
        Ok(shares)
    }

    /// Verify that all 4 shares are canonical (`< PRIME_P`) and lie on a single degree-`<= 2`
    /// polynomial without revealing `P(0)`. Zero `inv_mod`, zero `mul_mod`, zero heap allocation.
    #[inline(always)]
    pub const fn verify_degree2(shares: &Share4) -> Result<(), FastEngineError> {
        if shares[0] >= PRIME_P
            || shares[1] >= PRIME_P
            || shares[2] >= PRIME_P
            || shares[3] >= PRIME_P
        {
            return Err(FastEngineError::FieldElementOutOfRange);
        }
        // Expected P(4) = y1 - 3*y2 + 3*y3 (mod P).
        let expected_y4 = sub_mod(add_mod(shares[0], mul3_mod(shares[2])), mul3_mod(shares[1]));
        if expected_y4 != shares[3] {
            return Err(FastEngineError::InconsistentShares);
        }
        Ok(())
    }

    /// Fast unchecked reconstruction of `P(0) = 3*y1 - 3*y2 + y3 (mod P)`.
    #[inline(always)]
    pub const fn reconstruct_unchecked(shares: &Share4) -> u128 {
        sub_mod(add_mod(mul3_mod(shares[0]), shares[2]), mul3_mod(shares[1]))
    }

    /// Verify degree-2 consistency across all 4 validators and reconstruct `P(0)`.
    /// Detects any tampered, corrupted, or out-of-range share.
    #[inline(always)]
    pub const fn reconstruct_and_verify(shares: &Share4) -> Result<u128, FastEngineError> {
        if let Err(e) = Self::verify_degree2(shares) {
            return Err(e);
        }
        Ok(Self::reconstruct_unchecked(shares))
    }
}

/// Stack-only local share addition `[x] + [y]`.
#[inline(always)]
pub const fn share4_add(x: &Share4, y: &Share4) -> Share4 {
    [
        add_mod(x[0], y[0]),
        add_mod(x[1], y[1]),
        add_mod(x[2], y[2]),
        add_mod(x[3], y[3]),
    ]
}

/// Stack-only local share subtraction `[x] - [y]`.
#[inline(always)]
pub const fn share4_sub(x: &Share4, y: &Share4) -> Share4 {
    [
        sub_mod(x[0], y[0]),
        sub_mod(x[1], y[1]),
        sub_mod(x[2], y[2]),
        sub_mod(x[3], y[3]),
    ]
}

/// Stack-only local subtraction of public constant `1`: `[x] - 1`.
#[inline(always)]
const fn share4_sub_one(x: &Share4) -> Share4 {
    [
        sub_mod(x[0], 1),
        sub_mod(x[1], 1),
        sub_mod(x[2], 1),
        sub_mod(x[3], 1),
    ]
}

/// Zero-`mul_mod` Horner bit recomposition: `[v] = sum_{j=0}^{15} 2^j * [bit_j]`.
#[inline(always)]
fn compose_bits_16(bits: &[Share4; FAST_RANGE_BITS]) -> Share4 {
    let mut acc = [0u128; 4];
    let mut j = FAST_RANGE_BITS;
    while j > 0 {
        j -= 1;
        let b = &bits[j];
        acc[0] = add_mod(add_mod(acc[0], acc[0]), b[0]);
        acc[1] = add_mod(add_mod(acc[1], acc[1]), b[1]);
        acc[2] = add_mod(add_mod(acc[2], acc[2]), b[2]);
        acc[3] = add_mod(add_mod(acc[3], acc[3]), b[3]);
    }
    acc
}

// ============================================================================
// 6. Stack-Allocated `FastBeaverTriple` & `FastBeaverPool` (Zero Per-Triple Heap Allocs)
// ============================================================================

/// Strictly single-use stack-allocated `(3, 4)` Shamir Beaver triple `([a], [b], [c])` with `c = a * b`.
///
/// Uses fixed `[u128; 4]` arrays (zero per-triple heap allocations), omits `Copy`/`Clone` to
/// enforce move-only single-use semantics at compile time, and wipes all shares on `Drop`.
#[derive(Debug)]
pub struct FastBeaverTriple {
    a: Share4,
    b: Share4,
    c: Share4,
}

impl FastBeaverTriple {
    /// Shares of `a`.
    #[inline(always)]
    pub fn a(&self) -> &Share4 {
        &self.a
    }

    /// Shares of `b`.
    #[inline(always)]
    pub fn b(&self) -> &Share4 {
        &self.b
    }

    /// Shares of `c = a * b (mod PRIME_P)`.
    #[inline(always)]
    pub fn c(&self) -> &Share4 {
        &self.c
    }
}

impl Drop for FastBeaverTriple {
    fn drop(&mut self) {
        for elem in self
            .a
            .iter_mut()
            .chain(self.b.iter_mut())
            .chain(self.c.iter_mut())
        {
            // SAFETY: `elem` is a valid mutable reference to an initialized `u128`.
            unsafe { std::ptr::write_volatile(elem, 0u128) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Zero-per-triple-allocation offline Beaver triple factory storing contiguous [`FastBeaverTriple`]s.
#[derive(Debug)]
pub struct FastBeaverPool {
    triples: Vec<FastBeaverTriple>,
}

impl FastBeaverPool {
    /// Create a pool pre-filled with `initial_count` fresh single-use `(3, 4)` Beaver triples.
    pub fn new(initial_count: usize) -> Self {
        let mut pool = Self {
            triples: Vec::with_capacity(initial_count),
        };
        pool.refill(initial_count);
        pool
    }

    /// Pre-generate `count` fresh offline Beaver triples using batched OS entropy reads and
    /// zero-`mul_mod` finite-difference polynomial evaluation.
    pub fn refill(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        self.triples.reserve(count);

        // 8 field elements per triple: a0, b0, a1, a2, b1, b2, c1, c2.
        const BATCH_TRIPLES: usize = 512;
        let mut entropy = [0u128; BATCH_TRIPLES * 8];
        let mut remaining = count;

        while remaining > 0 {
            let take = remaining.min(BATCH_TRIPLES);
            let slice = &mut entropy[..take * 8];
            fill_random_field_elems(slice);

            for chunk in slice.chunks_exact(8) {
                let mut a0 = chunk[0];
                let mut b0 = chunk[1];
                let mut c0 = mul_mod(a0, b0);

                let a = Lagrange3Of4::eval_poly(a0, chunk[2], chunk[3]);
                let b = Lagrange3Of4::eval_poly(b0, chunk[4], chunk[5]);
                let c = Lagrange3Of4::eval_poly(c0, chunk[6], chunk[7]);

                self.triples.push(FastBeaverTriple { a, b, c });

                zeroize_u128(&mut a0);
                zeroize_u128(&mut b0);
                zeroize_u128(&mut c0);
            }
            remaining -= take;
        }

        zeroize_u128_slice(&mut entropy);
    }

    /// Pop a single-use Beaver triple from the pool.
    #[inline(always)]
    pub fn pop(&mut self) -> Result<FastBeaverTriple, FastEngineError> {
        self.triples
            .pop()
            .ok_or(FastEngineError::BeaverPoolExhausted {
                needed: 1,
                available: 0,
            })
    }

    /// Split off `count` triples from the back of the pool for lock-free worker ownership.
    pub fn take_chunk(&mut self, count: usize) -> Result<Vec<FastBeaverTriple>, FastEngineError> {
        if self.triples.len() < count {
            return Err(FastEngineError::BeaverPoolExhausted {
                needed: count,
                available: self.triples.len(),
            });
        }
        let split_at = self.triples.len() - count;
        Ok(self.triples.split_off(split_at))
    }

    /// Remaining unused triples in the pool.
    #[inline]
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    /// Whether the pool is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.triples.is_empty()
    }
}

impl Drop for FastBeaverPool {
    fn drop(&mut self) {
        self.triples.clear();
    }
}

/// Zero-copy in-place Beaver multiplication `[x * y]` consuming and immediately wiping `triple`
/// in place (used by zero-copy parallel bucket workers whose owning pool truncates on exit).
#[inline(always)]
fn mpc_mul_3_of_4_in_place(
    x: &Share4,
    y: &Share4,
    triple: &mut FastBeaverTriple,
) -> Result<Share4, FastEngineError> {
    if x[0] >= PRIME_P
        || x[1] >= PRIME_P
        || x[2] >= PRIME_P
        || x[3] >= PRIME_P
        || y[0] >= PRIME_P
        || y[1] >= PRIME_P
        || y[2] >= PRIME_P
        || y[3] >= PRIME_P
    {
        zeroize_share4(&mut triple.a);
        zeroize_share4(&mut triple.b);
        zeroize_share4(&mut triple.c);
        return Err(FastEngineError::FieldElementOutOfRange);
    }

    let mut d_shares = [
        sub_mod(x[0], triple.a[0]),
        sub_mod(x[1], triple.a[1]),
        sub_mod(x[2], triple.a[2]),
        sub_mod(x[3], triple.a[3]),
    ];
    let mut e_shares = [
        sub_mod(y[0], triple.b[0]),
        sub_mod(y[1], triple.b[1]),
        sub_mod(y[2], triple.b[2]),
        sub_mod(y[3], triple.b[3]),
    ];

    let d_res = Lagrange3Of4::reconstruct_and_verify(&d_shares);
    let e_res = Lagrange3Of4::reconstruct_and_verify(&e_shares);
    zeroize_share4(&mut d_shares);
    zeroize_share4(&mut e_shares);

    let (d, e) = match (d_res, e_res) {
        (Ok(d), Ok(e)) => (d, e),
        (Err(err), _) | (_, Err(err)) => {
            zeroize_share4(&mut triple.a);
            zeroize_share4(&mut triple.b);
            zeroize_share4(&mut triple.c);
            return Err(err);
        }
    };

    let de = mul_mod(d, e);
    let prod = [
        add_mod(
            add_mod(triple.c[0], mul_mod(d, triple.b[0])),
            add_mod(mul_mod(e, triple.a[0]), de),
        ),
        add_mod(
            add_mod(triple.c[1], mul_mod(d, triple.b[1])),
            add_mod(mul_mod(e, triple.a[1]), de),
        ),
        add_mod(
            add_mod(triple.c[2], mul_mod(d, triple.b[2])),
            add_mod(mul_mod(e, triple.a[2]), de),
        ),
        add_mod(
            add_mod(triple.c[3], mul_mod(d, triple.b[3])),
            add_mod(mul_mod(e, triple.a[3]), de),
        ),
    ];

    // Immediately zeroize consumed triple in place (single-use guarantee).
    zeroize_share4(&mut triple.a);
    zeroize_share4(&mut triple.b);
    zeroize_share4(&mut triple.c);
    Ok(prod)
}

/// Zero-allocation online Beaver multiplication `[x * y]` over `(3, 4)` stack shares.
///
/// Opens only OTP-masked differences `d = x - a` and `e = y - b`, enforcing degree-2 consistency
/// across all 4 validators via [`Lagrange3Of4::reconstruct_and_verify`], and immediately drops
/// and zeroizes the consumed [`FastBeaverTriple`].
#[inline]
pub fn mpc_mul_3_of_4(
    x: &Share4,
    y: &Share4,
    mut triple: FastBeaverTriple,
) -> Result<Share4, FastEngineError> {
    mpc_mul_3_of_4_in_place(x, y, &mut triple)
}

// ============================================================================
// 7. Multi-Core Batched Sharded IT-MPC Engine (`FastShieldedCluster`)
// ============================================================================

/// Zero-heap-allocation confidential transfer request for [`FastShieldedCluster`].
///
/// Contains stack-allocated `(3, 4)` Shamir shares of:
/// - 16 amount bits `v_j in {0, 1}`,
/// - 16 post-transfer remainder bits `r_j in {0, 1}` (`r = B_sender - v`),
/// - 16 blinded one-hot recipient selector bits `s_k in {0, 1}` with `sum(s_k) == 1`.
#[derive(Debug)]
pub struct FastTransferRequest {
    pub bucket_id: usize,
    pub sender_slot: usize,
    pub v_bits: [Share4; FAST_RANGE_BITS],
    pub r_bits: [Share4; FAST_RANGE_BITS],
    pub selector_shares: [Share4; FAST_BUCKET_SIZE],
}

impl FastTransferRequest {
    /// Construct a valid confidential transfer inside `bucket_id` from `sender_slot` (with known
    /// `sender_balance`) sending `amount` to `recipient_slot` using a single batched OS entropy read.
    pub fn new(
        bucket_id: usize,
        sender_slot: usize,
        sender_balance: u128,
        recipient_slot: usize,
        amount: u128,
    ) -> Result<Self, FastEngineError> {
        if sender_slot >= FAST_BUCKET_SIZE {
            return Err(FastEngineError::InvalidSlot { slot: sender_slot });
        }
        if recipient_slot >= FAST_BUCKET_SIZE {
            return Err(FastEngineError::InvalidSlot {
                slot: recipient_slot,
            });
        }
        let max_val = (1u128 << FAST_RANGE_BITS) - 1;
        if amount > max_val || sender_balance < amount || (sender_balance - amount) > max_val {
            return Err(FastEngineError::InvalidParameters(
                "amount or remainder outside [0, 2^16)",
            ));
        }

        let remainder = sender_balance - amount;
        // 48 polynomials * 2 random degree coefficients = 96 field elements in one batched read.
        const TOTAL_POLYS: usize = FAST_RANGE_BITS + FAST_RANGE_BITS + FAST_BUCKET_SIZE;
        let mut rands = [0u128; TOTAL_POLYS * 2];
        fill_random_field_elems(&mut rands);

        let mut v_bits = [[0u128; 4]; FAST_RANGE_BITS];
        let mut r_bits = [[0u128; 4]; FAST_RANGE_BITS];
        let mut selector_shares = [[0u128; 4]; FAST_BUCKET_SIZE];

        let mut idx = 0usize;
        for j in 0..FAST_RANGE_BITS {
            let vb = (amount >> j) & 1;
            v_bits[j] = Lagrange3Of4::eval_poly(vb, rands[idx], rands[idx + 1]);
            idx += 2;
        }
        for j in 0..FAST_RANGE_BITS {
            let rb = (remainder >> j) & 1;
            r_bits[j] = Lagrange3Of4::eval_poly(rb, rands[idx], rands[idx + 1]);
            idx += 2;
        }
        for k in 0..FAST_BUCKET_SIZE {
            let sk = if k == recipient_slot { 1u128 } else { 0u128 };
            selector_shares[k] = Lagrange3Of4::eval_poly(sk, rands[idx], rands[idx + 1]);
            idx += 2;
        }

        zeroize_u128_slice(&mut rands);
        Ok(Self {
            bucket_id,
            sender_slot,
            v_bits,
            r_bits,
            selector_shares,
        })
    }

    /// Construct a request directly from raw share arrays (for distributed clients & adversarial tests).
    pub fn new_raw(
        bucket_id: usize,
        sender_slot: usize,
        v_bits: [Share4; FAST_RANGE_BITS],
        r_bits: [Share4; FAST_RANGE_BITS],
        selector_shares: [Share4; FAST_BUCKET_SIZE],
    ) -> Self {
        Self {
            bucket_id,
            sender_slot,
            v_bits,
            r_bits,
            selector_shares,
        }
    }
}

impl Drop for FastTransferRequest {
    fn drop(&mut self) {
        zeroize_share4_slice(&mut self.v_bits);
        zeroize_share4_slice(&mut self.r_bits);
        zeroize_share4_slice(&mut self.selector_shares);
    }
}

/// Fixed-size stack-array anonymity bucket storing `(3, 4)` Shamir balance shares for 16 accounts.
#[derive(Debug)]
struct FastAnonymityBucket {
    balances: [Share4; FAST_BUCKET_SIZE],
}

impl Drop for FastAnonymityBucket {
    fn drop(&mut self) {
        zeroize_share4_slice(&mut self.balances);
    }
}

/// Verify a single bit share satisfies `b * (b - 1) == 0` in `(3, 4)` MPC without revealing `b`.
#[inline(always)]
fn verify_bit_3_of_4_in_place(
    bit: &Share4,
    triple: &mut FastBeaverTriple,
    fail_err: FastEngineError,
) -> Result<(), FastEngineError> {
    let mut bit_minus_one = share4_sub_one(bit);
    let prod_res = mpc_mul_3_of_4_in_place(bit, &bit_minus_one, triple);
    zeroize_share4(&mut bit_minus_one);
    let mut prod = prod_res?;
    let opened = Lagrange3Of4::reconstruct_and_verify(&prod);
    zeroize_share4(&mut prod);
    if opened? != 0 {
        return Err(fail_err);
    }
    Ok(())
}

/// Execute and verify a single confidential transfer against a mutable stack copy of one bucket's
/// 16 balance shares, consuming exactly `TRIPLES_PER_SHIELDED_TX = 64` single-use Beaver triples
/// zero-copy directly from `triples[0..64]`.
///
/// Enforces:
/// 1. `v_j * (v_j - 1) == 0` for all 16 amount bits (rejects negative / out-of-range bits).
/// 2. `r_j * (r_j - 1) == 0` for all 16 remainder bits.
/// 3. `B_sender - v - r == 0` (rejects overdrafts with zero modulo wraparound).
/// 4. `s_k * (s_k - 1) == 0` and `sum(s_k) == 1` (rejects double-recipient inflation & coin burn).
/// 5. Degree-2 Lagrange consistency across all 4 validators on every opening.
/// 6. Blinded credit `+[s_k * v]` applied to EVERY slot in the bucket to hide the recipient.
fn execute_transfer_on_bucket_state(
    balances: &mut [Share4; FAST_BUCKET_SIZE],
    req: &FastTransferRequest,
    triples: &mut [FastBeaverTriple],
) -> Result<(), FastEngineError> {
    if req.sender_slot >= FAST_BUCKET_SIZE {
        return Err(FastEngineError::InvalidSlot {
            slot: req.sender_slot,
        });
    }
    if triples.len() < TRIPLES_PER_SHIELDED_TX {
        return Err(FastEngineError::BeaverPoolExhausted {
            needed: TRIPLES_PER_SHIELDED_TX,
            available: triples.len(),
        });
    }

    let mut t_idx = 0usize;

    // 1. 16-bit amount range proof: v_j * (v_j - 1) == 0.
    for bit in &req.v_bits {
        verify_bit_3_of_4_in_place(bit, &mut triples[t_idx], FastEngineError::RangeProofFailed)?;
        t_idx += 1;
    }

    // 2. 16-bit remainder range proof: r_j * (r_j - 1) == 0.
    for bit in &req.r_bits {
        verify_bit_3_of_4_in_place(bit, &mut triples[t_idx], FastEngineError::RangeProofFailed)?;
        t_idx += 1;
    }

    // 3. Recompose [v], [r] with zero `mul_mod` and verify B_sender - v - r == 0.
    let mut v_shares = compose_bits_16(&req.v_bits);
    let mut r_shares = compose_bits_16(&req.r_bits);
    let mut diff = share4_sub(&balances[req.sender_slot], &v_shares);
    let mut eq_check = share4_sub(&diff, &r_shares);
    let opened_eq = Lagrange3Of4::reconstruct_and_verify(&eq_check);
    zeroize_share4(&mut r_shares);
    zeroize_share4(&mut diff);
    zeroize_share4(&mut eq_check);
    if opened_eq? != 0 {
        zeroize_share4(&mut v_shares);
        return Err(FastEngineError::BalanceCheckFailed);
    }

    // 4. Blinded one-hot recipient selector check: s_k in {0, 1} and sum(s_k) == 1.
    let mut sum_s = [0u128; 4];
    for s_k in &req.selector_shares {
        if let Err(e) =
            verify_bit_3_of_4_in_place(s_k, &mut triples[t_idx], FastEngineError::SelectorCheckFailed)
        {
            zeroize_share4(&mut v_shares);
            zeroize_share4(&mut sum_s);
            return Err(e);
        }
        t_idx += 1;
        sum_s = share4_add(&sum_s, s_k);
    }
    let opened_sum = Lagrange3Of4::reconstruct_and_verify(&sum_s);
    zeroize_share4(&mut sum_s);
    if opened_sum? != 1 {
        zeroize_share4(&mut v_shares);
        return Err(FastEngineError::SelectorCheckFailed);
    }

    // 5. Compute blinded credits [s_k * v] for EVERY slot in the anonymity bucket.
    let mut credits = [[0u128; 4]; FAST_BUCKET_SIZE];
    for (k, s_k) in req.selector_shares.iter().enumerate() {
        match mpc_mul_3_of_4_in_place(s_k, &v_shares, &mut triples[t_idx]) {
            Ok(c) => credits[k] = c,
            Err(e) => {
                zeroize_share4(&mut v_shares);
                zeroize_share4_slice(&mut credits);
                return Err(e);
            }
        }
        t_idx += 1;
    }

    // 6. Commit debit and all 16 blinded credits to the bucket's staged balances.
    balances[req.sender_slot] = share4_sub(&balances[req.sender_slot], &v_shares);
    for (bal, credit) in balances.iter_mut().zip(credits.iter()) {
        *bal = share4_add(bal, credit);
    }

    zeroize_share4(&mut v_shares);
    zeroize_share4_slice(&mut credits);
    Ok(())
}

/// Multi-core parallel sharded IT-MPC shielded ledger cluster (`(3, 4)` Shamir threshold).
///
/// Inspired by **Solana Sealevel** and **Bitcoin Core `CCheckQueue`**:
/// partitions incoming confidential transfers by disjoint `bucket_id` and executes all buckets
/// simultaneously across all available CPU cores (`std::thread::available_parallelism()`) via
/// `std::thread::scope` with **zero lock contention** and **zero per-transfer heap allocations**.
#[derive(Debug)]
pub struct FastShieldedCluster {
    buckets: Vec<FastAnonymityBucket>,
    bucket_minted: Vec<u128>,
}

impl FastShieldedCluster {
    /// Initialize a shielded cluster with `num_buckets` anonymity buckets of 16 accounts each.
    /// Every account starts with a fresh `(3, 4)` Shamir sharing of `0`.
    pub fn new(num_buckets: usize) -> Result<Self, FastEngineError> {
        if num_buckets == 0 {
            return Err(FastEngineError::InvalidParameters("num_buckets must be >= 1"));
        }
        let total_accounts = num_buckets
            .checked_mul(FAST_BUCKET_SIZE)
            .ok_or(FastEngineError::InvalidParameters("num_buckets overflow"))?;
        let rand_len = total_accounts
            .checked_mul(2)
            .ok_or(FastEngineError::InvalidParameters("num_buckets overflow"))?;
        let mut rands = vec![0u128; rand_len];
        fill_random_field_elems(&mut rands);

        let mut buckets = Vec::with_capacity(num_buckets);
        let mut r_idx = 0usize;
        for _ in 0..num_buckets {
            let mut balances = [[0u128; 4]; FAST_BUCKET_SIZE];
            for slot in balances.iter_mut() {
                *slot = Lagrange3Of4::eval_poly(0, rands[r_idx], rands[r_idx + 1]);
                r_idx += 2;
            }
            buckets.push(FastAnonymityBucket { balances });
        }

        zeroize_u128_slice(&mut rands);
        Ok(Self {
            buckets,
            bucket_minted: vec![0u128; num_buckets],
        })
    }

    /// Number of anonymity buckets.
    #[inline]
    pub fn num_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Total accounts (`num_buckets * FAST_BUCKET_SIZE`).
    #[inline]
    pub fn total_accounts(&self) -> usize {
        self.buckets.len() * FAST_BUCKET_SIZE
    }

    /// Mint an initial confidential balance into `(bucket_id, slot)` using fresh `(3, 4)` shares.
    ///
    /// Enforces `existing_balance + amount <= 2^16 - 1` and safe bucket supply cap `<= 2^16 - 1`.
    pub fn mint_balance(
        &mut self,
        bucket_id: usize,
        slot: usize,
        amount: u128,
    ) -> Result<(), FastEngineError> {
        let max_val = (1u128 << FAST_RANGE_BITS) - 1;
        if amount > max_val {
            return Err(FastEngineError::InvalidParameters(
                "mint amount exceeds 2^16 - 1",
            ));
        }
        if slot >= FAST_BUCKET_SIZE {
            return Err(FastEngineError::InvalidSlot { slot });
        }
        let bucket = self
            .buckets
            .get_mut(bucket_id)
            .ok_or(FastEngineError::InvalidBucket { bucket_id })?;
        let existing = Lagrange3Of4::reconstruct_and_verify(&bucket.balances[slot])?;
        if existing.checked_add(amount).is_none_or(|sum| sum > max_val) {
            return Err(FastEngineError::InvalidParameters(
                "existing balance + mint amount exceeds 2^16 - 1",
            ));
        }
        if self.bucket_minted[bucket_id]
            .checked_add(amount)
            .is_none_or(|sum| sum > max_val)
        {
            return Err(FastEngineError::InvalidParameters(
                "bucket supply would exceed safe 2^16 - 1 cap",
            ));
        }
        let mut delta = Lagrange3Of4::split_secret(amount)?;
        bucket.balances[slot] = share4_add(&bucket.balances[slot], &delta);
        self.bucket_minted[bucket_id] += amount;
        zeroize_share4(&mut delta);
        Ok(())
    }

    /// Read-only view of the `(3, 4)` Shamir balance shares for `(bucket_id, slot)`.
    pub fn balance_shares(
        &self,
        bucket_id: usize,
        slot: usize,
    ) -> Result<&Share4, FastEngineError> {
        if slot >= FAST_BUCKET_SIZE {
            return Err(FastEngineError::InvalidSlot { slot });
        }
        let bucket = self
            .buckets
            .get(bucket_id)
            .ok_or(FastEngineError::InvalidBucket { bucket_id })?;
        Ok(&bucket.balances[slot])
    }

    /// Reconstruct and degree-2-verify the balance of `(bucket_id, slot)` (for auditing/testing).
    pub fn reconstruct_balance(
        &self,
        bucket_id: usize,
        slot: usize,
    ) -> Result<u128, FastEngineError> {
        let shares = self.balance_shares(bucket_id, slot)?;
        Lagrange3Of4::reconstruct_and_verify(shares)
    }

    /// Execute a single confidential transfer atomically (rolls back automatically on any error).
    pub fn execute_single_transfer(
        &mut self,
        req: &FastTransferRequest,
        pool: &mut FastBeaverPool,
    ) -> Result<(), FastEngineError> {
        let bucket = self
            .buckets
            .get_mut(req.bucket_id)
            .ok_or(FastEngineError::InvalidBucket {
                bucket_id: req.bucket_id,
            })?;
        if pool.triples.len() < TRIPLES_PER_SHIELDED_TX {
            return Err(FastEngineError::BeaverPoolExhausted {
                needed: TRIPLES_PER_SHIELDED_TX,
                available: pool.triples.len(),
            });
        }
        let new_len = pool.triples.len() - TRIPLES_PER_SHIELDED_TX;
        let mut staged = bucket.balances;
        let res = execute_transfer_on_bucket_state(
            &mut staged,
            req,
            &mut pool.triples[new_len..],
        );
        // Unconditionally truncate and zeroize the consumed triple range (strict single-use).
        pool.triples.truncate(new_len);
        match res {
            Ok(()) => {
                bucket.balances = staged;
                zeroize_share4_slice(&mut staged);
                Ok(())
            }
            Err(e) => {
                zeroize_share4_slice(&mut staged);
                Err(e)
            }
        }
    }

    /// Execute a batch of confidential transfers across disjoint anonymity buckets in parallel
    /// across all available CPU cores via `std::thread::scope` with zero lock contention and
    /// zero Beaver-triple memory copies.
    ///
    /// Atomicity guarantee: each worker thread executes against a stack-staged copy of its
    /// assigned buckets; if ANY transfer in ANY bucket fails range proof, balance check, selector
    /// check, or degree-2 share verification, **zero** balances across the entire cluster are
    /// modified and the first error is returned.
    pub fn execute_parallel_batch(
        &mut self,
        requests: &[FastTransferRequest],
        pool: &mut FastBeaverPool,
    ) -> Result<usize, FastEngineError> {
        if requests.is_empty() {
            return Ok(0);
        }
        let num_buckets = self.buckets.len();

        // 1. Validate bucket/slot indices and partition requests by disjoint `bucket_id`.
        let mut per_bucket: Vec<Vec<&FastTransferRequest>> = vec![Vec::new(); num_buckets];
        for req in requests {
            if req.bucket_id >= num_buckets {
                return Err(FastEngineError::InvalidBucket {
                    bucket_id: req.bucket_id,
                });
            }
            if req.sender_slot >= FAST_BUCKET_SIZE {
                return Err(FastEngineError::InvalidSlot {
                    slot: req.sender_slot,
                });
            }
            per_bucket[req.bucket_id].push(req);
        }

        // 2. Verify aggregate Beaver triple availability before spawning threads.
        let total_triples = requests
            .len()
            .checked_mul(TRIPLES_PER_SHIELDED_TX)
            .ok_or(FastEngineError::InvalidParameters(
                "shielded batch request count overflow",
            ))?;
        if pool.triples.len() < total_triples {
            return Err(FastEngineError::BeaverPoolExhausted {
                needed: total_triples,
                available: pool.triples.len(),
            });
        }

        // 3. Zero-copy slice partitioning: carve disjoint `&mut [FastBeaverTriple]` slices directly
        //    out of `pool.triples` with zero heap allocation or copying.
        let new_pool_len = pool.triples.len() - total_triples;
        let mut triple_tail = &mut pool.triples[new_pool_len..];

        let mut active_jobs: Vec<(
            usize,
            [Share4; FAST_BUCKET_SIZE],
            Vec<&FastTransferRequest>,
            &mut [FastBeaverTriple],
        )> = Vec::new();
        for (bucket_id, bucket_reqs) in per_bucket.into_iter().enumerate() {
            if bucket_reqs.is_empty() {
                continue;
            }
            let needed = bucket_reqs.len() * TRIPLES_PER_SHIELDED_TX;
            let (bucket_triples, rest) = triple_tail.split_at_mut(needed);
            triple_tail = rest;
            let staged_balances = self.buckets[bucket_id].balances;
            active_jobs.push((bucket_id, staged_balances, bucket_reqs, bucket_triples));
        }

        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let worker_count = cores.min(active_jobs.len()).max(1);
        let chunk_size = active_jobs.len().div_ceil(worker_count);

        // 4. Execute all disjoint bucket lanes simultaneously across `worker_count` OS threads.
        let worker_errors: Vec<Option<FastEngineError>> = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for job_chunk in active_jobs.chunks_mut(chunk_size) {
                handles.push(scope.spawn(move || {
                    for (_, staged_balances, bucket_reqs, triples_slice) in job_chunk.iter_mut() {
                        for (req, tx_triples) in bucket_reqs
                            .iter()
                            .zip(triples_slice.chunks_exact_mut(TRIPLES_PER_SHIELDED_TX))
                        {
                            if let Err(e) =
                                execute_transfer_on_bucket_state(staged_balances, req, tx_triples)
                            {
                                return Some(e);
                            }
                        }
                    }
                    None
                }));
            }
            handles
                .into_iter()
                .map(|h| h.join().expect("shielded MPC worker thread panicked"))
                .collect()
        });

        // 5. Commit or abort staged balances, then unconditionally truncate consumed triples.
        let first_err = worker_errors.into_iter().flatten().next();
        if let Some(err) = first_err {
            for (_, mut staged, _, _) in active_jobs {
                zeroize_share4_slice(&mut staged);
            }
            pool.triples.truncate(new_pool_len);
            return Err(err);
        }

        for (bucket_id, mut staged, _, _) in active_jobs {
            self.buckets[bucket_id].balances = staged;
            zeroize_share4_slice(&mut staged);
        }
        pool.triples.truncate(new_pool_len);

        Ok(requests.len())
    }
}

// ============================================================================
// 8. Live Speed Benchmarks (`run_speed_benchmarks` -> `SpeedBenchmarkReport`)
// ============================================================================

/// Real measured throughput and bandwidth telemetry produced by [`run_speed_benchmarks`].
#[derive(Debug, Clone)]
pub struct SpeedBenchmarkReport {
    /// Measured Express-lane 4-validator 2-phase BFT throughput (transactions per second).
    pub express_tps: f64,
    /// Measured Shielded-lane multi-core `(3, 4)` IT-MPC throughput (transactions per second).
    pub shielded_tps: f64,
    /// Measured BIP-152 compact batch relay bandwidth reduction ratio (`full_bytes / compact_bytes`).
    pub compact_relay_bandwidth_ratio: f64,
    /// Number of hardware CPU threads used by parallel workers.
    pub cores_used: usize,
    /// Total Express transactions committed during the timed benchmark.
    pub express_txs_committed: usize,
    /// Wall-clock duration of the Express benchmark in seconds.
    pub express_elapsed_secs: f64,
    /// Total Shielded 16-bit confidential transfers committed during the timed benchmark.
    pub shielded_txs_committed: usize,
    /// Wall-clock duration of the Shielded benchmark in seconds.
    pub shielded_elapsed_secs: f64,
    /// Full wire size in bytes of a 24-byte `CompactTx` batch.
    pub full_batch_bytes: usize,
    /// Compact wire size in bytes of the corresponding 8-byte short-ID [`CompactBatchProposal`].
    pub compact_batch_bytes: usize,
}

impl fmt::Display for SpeedBenchmarkReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Vernam (VRNM) Fast Engine Benchmarks ({} cores) ===", self.cores_used)?;
        writeln!(
            f,
            "  Express 4-Val BFT TPS : {:>12.0} tx/s ({} txs in {:.4}s)",
            self.express_tps, self.express_txs_committed, self.express_elapsed_secs
        )?;
        writeln!(
            f,
            "  Shielded IT-MPC TPS   : {:>12.0} tx/s ({} txs in {:.4}s)",
            self.shielded_tps, self.shielded_txs_committed, self.shielded_elapsed_secs
        )?;
        write!(
            f,
            "  Compact Relay Ratio   : {:>12.2}x ({} B full -> {} B compact)",
            self.compact_relay_bandwidth_ratio, self.full_batch_bytes, self.compact_batch_bytes
        )
    }
}

/// Run end-to-end live throughput benchmarks for:
/// 1. 4-validator 2-phase batched BFT Express lane (`FastExpressCluster` + `IndexedLedger` + BIP-152 compact relay),
/// 2. Multi-core sharded `(3, 4)` 16-bit IT-MPC Shielded lane (`FastShieldedCluster` + `FastBeaverPool`),
/// 3. BIP-152 compact relay wire bandwidth compression ratio.
pub fn run_speed_benchmarks() -> SpeedBenchmarkReport {
    let cores_used = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // ------------------------------------------------------------------------
    // Benchmark 1: Express Lane (4-validator parallel 2-phase BFT + Compact Relay)
    // ------------------------------------------------------------------------
    let num_accounts = 2_000usize;
    let num_batches = 10usize;
    let batch_size = 5_000usize;
    let total_express_txs = num_batches * batch_size;

    let initial_balances = vec![1_000_000u64; num_accounts];
    let mut express = FastExpressCluster::new(initial_balances, num_batches + 2);

    // Pre-build deterministic valid batches with strictly monotonic page_ids per sender.
    let mut next_page = vec![1u64; num_accounts];
    let mut batches: Vec<Vec<CompactTx>> = Vec::with_capacity(num_batches);
    for b in 0..num_batches {
        let mut txs = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let sender = ((b * batch_size + i) % num_accounts) as u32;
            let recipient = ((sender as usize + 1) % num_accounts) as u32;
            let page_id = next_page[sender as usize];
            next_page[sender as usize] += 1;
            txs.push(CompactTx::new(sender, recipient, 1, page_id));
        }
        // Pre-gossip batch into all 4 validators' mempools (mirrors steady-state P2P mempool sync).
        express
            .gossip_to_mempools(&txs)
            .expect("mempool gossip must succeed");
        batches.push(txs);
    }

    let mut full_batch_bytes = 0usize;
    let mut compact_batch_bytes = 0usize;
    let mut compact_relay_bandwidth_ratio = 1.0f64;

    let express_start = Instant::now();
    for (idx, batch) in batches.iter().enumerate() {
        let (_cert, proposal) = express
            .commit_compact_batch(batch)
            .expect("express compact batch commit must succeed");
        if idx == 0 {
            full_batch_bytes = CompactBatchProposal::full_block_wire_bytes(proposal.tx_count());
            compact_batch_bytes = proposal.wire_bytes();
            compact_relay_bandwidth_ratio = proposal.bandwidth_ratio();
        }
    }
    let express_elapsed_secs = express_start.elapsed().as_secs_f64().max(1e-9);
    let express_tps = (total_express_txs as f64) / express_elapsed_secs;

    // ------------------------------------------------------------------------
    // Benchmark 2: Shielded Lane (Multi-core parallel (3, 4) 16-bit IT-MPC)
    // ------------------------------------------------------------------------
    let num_buckets = (cores_used * 4).max(16);
    let txs_per_bucket = 64usize;
    let total_shielded_txs = num_buckets * txs_per_bucket;

    let mut shielded =
        FastShieldedCluster::new(num_buckets).expect("shielded cluster creation must succeed");
    let initial_bal = 3_000u128;
    for b in 0..num_buckets {
        for slot in 0..FAST_BUCKET_SIZE {
            shielded
                .mint_balance(b, slot, initial_bal)
                .expect("mint must succeed");
        }
    }

    // Offline client request generation + offline Beaver triple pool provisioning.
    let mut pool = FastBeaverPool::new(total_shielded_txs * TRIPLES_PER_SHIELDED_TX);
    let mut requests = Vec::with_capacity(total_shielded_txs);
    let mut tracked_bal = vec![[initial_bal; FAST_BUCKET_SIZE]; num_buckets];
    for b in 0..num_buckets {
        for i in 0..txs_per_bucket {
            let sender = i % FAST_BUCKET_SIZE;
            let recipient = (sender + 1) % FAST_BUCKET_SIZE;
            let amount = 5u128;
            let req = FastTransferRequest::new(b, sender, tracked_bal[b][sender], recipient, amount)
                .expect("valid request");
            tracked_bal[b][sender] -= amount;
            tracked_bal[b][recipient] += amount;
            requests.push(req);
        }
    }

    let shielded_start = Instant::now();
    let committed = shielded
        .execute_parallel_batch(&requests, &mut pool)
        .expect("parallel shielded batch must succeed");
    let shielded_elapsed_secs = shielded_start.elapsed().as_secs_f64().max(1e-9);
    let shielded_tps = (committed as f64) / shielded_elapsed_secs;

    SpeedBenchmarkReport {
        express_tps,
        shielded_tps,
        compact_relay_bandwidth_ratio,
        cores_used,
        express_txs_committed: total_express_txs,
        express_elapsed_secs,
        shielded_txs_committed: committed,
        shielded_elapsed_secs,
        full_batch_bytes,
        compact_batch_bytes,
    }
}

// ============================================================================
// Comprehensive Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_tx_roundtrip_and_size() {
        assert_eq!(std::mem::size_of::<CompactTx>(), 24);
        let tx = CompactTx::new(42, 999_999, 123_456_789_012_345, 77_777);
        let bytes = tx.to_bytes();
        assert_eq!(bytes.len(), COMPACT_TX_SIZE);
        let decoded = CompactTx::from_bytes(&bytes);
        assert_eq!(decoded, tx);

        // Distinct transactions map to distinct (w0, w1) canonical field word pairs.
        let tx2 = CompactTx::new(42, 999_999, 123_456_789_012_346, 77_777);
        let (w0_a, w1_a) = tx.to_field_words();
        let (w0_b, w1_b) = tx2.to_field_words();
        assert!(w0_a < PRIME_P && w1_a < PRIME_P);
        assert!(w0_b < PRIME_P && w1_b < PRIME_P);
        assert_ne!((w0_a, w1_a), (w0_b, w1_b));
    }

    #[test]
    fn test_compact_batch_relay_bandwidth_and_reconstruction() {
        let key = RoundShortIdKey::generate();
        let mut leader_mp = FastMempool::with_capacity(key.duplicate_for_round(), 1024);
        let mut follower_mp = FastMempool::with_capacity(key.duplicate_for_round(), 1024);

        let txs: Vec<CompactTx> = (0..1_000u32)
            .map(|i| CompactTx::new(i % 500, (i + 1) % 500, (i as u64) + 10, (i as u64) + 1))
            .collect();

        leader_mp.insert_batch(&txs).unwrap();
        // Follower has 998 of 1,000 txs (simulate 2 mempool misses for fallback testing).
        follower_mp.insert_batch(&txs[..998]).unwrap();

        let seal_key = FastCwKey::generate();
        let verify_key = seal_key.duplicate_for_preshare();
        let proposal = leader_mp.build_compact_proposal(
            1,
            0,
            1,
            FAST_GENESIS_TAG,
            &txs,
            seal_key,
        );

        // Wire serialization roundtrip.
        let wire = proposal.to_bytes();
        let decoded_prop = CompactBatchProposal::from_bytes(&wire).unwrap();
        assert_eq!(decoded_prop, proposal);

        // Verify ~3x bandwidth savings (24B full txs -> 8B short IDs).
        let ratio = proposal.bandwidth_ratio();
        assert!(
            ratio > 2.95,
            "expected ~3x compact relay bandwidth savings, got {ratio:.2}x"
        );

        // Reconstruct with 2 misses -> exact missing indices reported -> patch -> exact match!
        let mut reconstructed = Vec::new();
        let missing = follower_mp
            .reconstruct_batch(&decoded_prop, &mut reconstructed)
            .expect_err("expected 2 missing txs");
        assert_eq!(missing, vec![998, 999]);

        follower_mp
            .patch_missing_txs(&mut reconstructed, &[(998, txs[998]), (999, txs[999])])
            .unwrap();
        assert_eq!(reconstructed, txs);

        // Verify single-use Carter-Wegman block seal on reconstructed batch.
        let computed = verify_key.seal_batch_consume(&FAST_GENESIS_TAG, 1, 0, &reconstructed);
        assert!(ct_eq_16(&computed, &decoded_prop.block_tag));

        // Now with 100% mempool hit, reconstruction succeeds immediately with zero misses.
        let mut hit_buf = Vec::new();
        follower_mp
            .reconstruct_batch(&decoded_prop, &mut hit_buf)
            .expect("100% mempool hit must succeed");
        assert_eq!(hit_buf, txs);
    }

    #[test]
    fn test_fast_express_cluster_10k_txs_and_rejection_invariants() {
        let num_accounts = 1_000usize;
        let initial = vec![10_000u64; num_accounts];
        let mut cluster = FastExpressCluster::new(initial, 20);

        // Commit 10,000 transactions across 4 validators (2 batches x 5,000 txs via compact relay).
        let mut next_page = vec![1u64; num_accounts];
        let mut expected_bal = vec![10_000u64; num_accounts];

        for batch_num in 0..2 {
            let mut txs = Vec::with_capacity(5_000);
            for i in 0..5_000 {
                let s = (batch_num * 5_000 + i) % num_accounts;
                let r = (s + 7) % num_accounts;
                let amt = ((i % 13) + 1) as u64;
                let pid = next_page[s];
                next_page[s] += 1;
                expected_bal[s] -= amt;
                expected_bal[r] += amt;
                txs.push(CompactTx::new(s as u32, r as u32, amt, pid));
            }
            cluster.gossip_to_mempools(&txs).unwrap();
            let (cert, proposal) = cluster.commit_compact_batch(&txs).unwrap();
            assert_eq!(cert.height, (batch_num + 1) as u64);
            assert_eq!(cert.tx_count, 5_000);
            assert_eq!(cert.commit_quorum, 4);
            assert!(proposal.bandwidth_ratio() > 2.95);
        }

        // All 4 validators agree bit-for-bit on all 1,000 account balances and chain tip.
        let tip = cluster.tip_tag();
        for vid in 0..FAST_NUM_VALIDATORS {
            let ledger = cluster.validator_ledger(vid);
            assert_eq!(ledger.height, 2);
            assert_eq!(ledger.tip_tag, tip);
            assert_eq!(ledger.balances(), expected_bal.as_slice());
        }

        // Rejection 1: Overdraft attempt mid-batch must abort atomically with ZERO state mutation.
        let valid_first = CompactTx::new(0, 1, 5, next_page[0]);
        let overdraft_second = CompactTx::new(1, 2, expected_bal[1] + 50_000, next_page[1]);
        let err = cluster
            .commit_batch(&[valid_first, overdraft_second])
            .expect_err("overdraft batch must be rejected");
        assert!(matches!(
            err,
            FastEngineError::InvalidTx {
                index: 1,
                reason: "insufficient balance"
            }
        ));
        // Confirm tx 0 was rolled back on all 4 validators!
        for vid in 0..FAST_NUM_VALIDATORS {
            assert_eq!(cluster.validator_ledger(vid).height, 2);
            assert_eq!(cluster.validator_ledger(vid).balance_of(0), expected_bal[0]);
            assert_eq!(
                cluster.validator_ledger(vid).last_page_of(0),
                next_page[0] - 1
            );
        }

        // Rejection 2: Replayed page_id (equal to already-used page_id) must be rejected atomically.
        let replay_tx = CompactTx::new(0, 1, 5, next_page[0] - 1);
        let err = cluster
            .commit_batch(&[replay_tx])
            .expect_err("replayed page_id must be rejected");
        assert!(matches!(
            err,
            FastEngineError::InvalidTx {
                index: 0,
                reason: "non-monotonic or replayed page_id"
            }
        ));
        assert_eq!(cluster.height(), 2);
    }

    #[test]
    fn test_lagrange_3_of_4_identities_and_tamper_detection() {
        // Verify compile-time const coefficients match algebraic Lagrange identities.
        assert_eq!(Lagrange3Of4::ORIGIN_COEFFS, [3, PRIME_P - 3, 1]);
        assert_eq!(Lagrange3Of4::VERIFY_X4_COEFFS, [1, PRIME_P - 3, 3]);

        for secret in [0u128, 1, 42, 65_535, PRIME_P - 1] {
            let mut shares = Lagrange3Of4::split_secret(secret).unwrap();
            assert_eq!(Lagrange3Of4::reconstruct_and_verify(&shares).unwrap(), secret);

            // Cross-check against explicit dot product with ORIGIN_COEFFS and PARITY_COEFFS.
            let dot_origin = add_mod(
                add_mod(
                    mul_mod(Lagrange3Of4::ORIGIN_COEFFS[0], shares[0]),
                    mul_mod(Lagrange3Of4::ORIGIN_COEFFS[1], shares[1]),
                ),
                mul_mod(Lagrange3Of4::ORIGIN_COEFFS[2], shares[2]),
            );
            assert_eq!(dot_origin, secret);

            let dot_parity = add_mod(
                add_mod(
                    mul_mod(Lagrange3Of4::PARITY_COEFFS[0], shares[0]),
                    mul_mod(Lagrange3Of4::PARITY_COEFFS[1], shares[1]),
                ),
                add_mod(
                    mul_mod(Lagrange3Of4::PARITY_COEFFS[2], shares[2]),
                    mul_mod(Lagrange3Of4::PARITY_COEFFS[3], shares[3]),
                ),
            );
            assert_eq!(dot_parity, 0);

            // Corrupt any single validator's share -> degree-2 tamper check MUST reject!
            for idx in 0..4 {
                let mut tampered = shares;
                tampered[idx] = add_mod(tampered[idx], 1);
                assert_eq!(
                    Lagrange3Of4::reconstruct_and_verify(&tampered),
                    Err(FastEngineError::InconsistentShares)
                );
            }
            zeroize_share4(&mut shares);
        }
    }

    #[test]
    fn test_fast_shielded_cluster_parallel_and_security_invariants() {
        let num_buckets = 8usize;
        let mut cluster = FastShieldedCluster::new(num_buckets).unwrap();
        let mut expected = vec![[0u128; FAST_BUCKET_SIZE]; num_buckets];

        for b in 0..num_buckets {
            for s in 0..FAST_BUCKET_SIZE {
                let amt = 500 + (b as u128) * 10 + (s as u128);
                cluster.mint_balance(b, s, amt).unwrap();
                expected[b][s] = amt;
            }
        }

        // Snapshot pre-transfer shares for bucket 0 to verify < 3 validator blindness & re-randomization.
        let pre_shares_bucket0: Vec<Share4> = (0..FAST_BUCKET_SIZE)
            .map(|s| *cluster.balance_shares(0, s).unwrap())
            .collect();

        // Build 32 parallel confidential transfers across all 8 disjoint buckets (4 per bucket).
        let mut requests = Vec::new();
        for b in 0..num_buckets {
            for i in 0..4 {
                let sender = i * 2;
                let recipient = (sender + 3) % FAST_BUCKET_SIZE;
                let amount = 25 + (i as u128) * 7;
                let req = FastTransferRequest::new(
                    b,
                    sender,
                    expected[b][sender],
                    recipient,
                    amount,
                )
                .unwrap();
                expected[b][sender] -= amount;
                expected[b][recipient] += amount;
                requests.push(req);
            }
        }

        let mut pool = FastBeaverPool::new(requests.len() * TRIPLES_PER_SHIELDED_TX + 512);
        let committed = cluster.execute_parallel_batch(&requests, &mut pool).unwrap();
        assert_eq!(committed, 32);

        // Verify exact reconstructed balances across all 128 accounts.
        for b in 0..num_buckets {
            for s in 0..FAST_BUCKET_SIZE {
                assert_eq!(cluster.reconstruct_balance(b, s).unwrap(), expected[b][s]);
            }
        }

        // Privacy check: EVERY slot in bucket 0 (including non-recipients!) has re-randomized shares
        // so any coalition of < 3 validators sees uniformly random changes on all 16 slots.
        for s in 0..FAST_BUCKET_SIZE {
            let post = *cluster.balance_shares(0, s).unwrap();
            assert_ne!(
                post, pre_shares_bucket0[s],
                "slot {s} share must be re-randomized even for non-recipients"
            );
            // Any 2 shares alone are strictly independent of the secret: verify 2-share subsystem
            // can explain ANY arbitrary target balance (perfect information-theoretic secrecy).
            let y1 = post[0];
            let y2 = post[1];
            for hypothetical_secret in [0u128, 999, 65_535] {
                // Unique degree-2 poly passing through (0, hypothetical_secret), (1, y1), (2, y2):
                // c0 = s, c1 + c2 = y1 - s, 2c1 + 4c2 = y2 - s => 2c2 = y2 - 2y1 + s.
                let inv2 = (PRIME_P + 1) / 2;
                let rhs = sub_mod(add_mod(y2, hypothetical_secret), add_mod(y1, y1));
                let c2 = mul_mod(rhs, inv2);
                let c1 = sub_mod(sub_mod(y1, hypothetical_secret), c2);
                let forged = Lagrange3Of4::eval_poly(hypothetical_secret, c1, c2);
                assert_eq!(forged[0], y1);
                assert_eq!(forged[1], y2);
                assert_eq!(
                    Lagrange3Of4::reconstruct_and_verify(&forged).unwrap(),
                    hypothetical_secret
                );
            }
        }

        // --------------------------------------------------------------------
        // Adversarial Attack 1: Overdraft (claim valid v=600, r=0 when balance < 600)
        // --------------------------------------------------------------------
        let b0_s0_bal = expected[0][0];
        let overdraft_amt = b0_s0_bal + 100;
        let mut v_bits = [[0u128; 4]; FAST_RANGE_BITS];
        let mut r_bits = [[0u128; 4]; FAST_RANGE_BITS];
        let mut sel = [[0u128; 4]; FAST_BUCKET_SIZE];
        for j in 0..FAST_RANGE_BITS {
            v_bits[j] = Lagrange3Of4::split_secret((overdraft_amt >> j) & 1).unwrap();
            r_bits[j] = Lagrange3Of4::split_secret(0).unwrap();
        }
        for k in 0..FAST_BUCKET_SIZE {
            sel[k] = Lagrange3Of4::split_secret(if k == 1 { 1 } else { 0 }).unwrap();
        }
        let overdraft_req = FastTransferRequest::new_raw(0, 0, v_bits, r_bits, sel);
        assert_eq!(
            cluster.execute_single_transfer(&overdraft_req, &mut pool),
            Err(FastEngineError::BalanceCheckFailed)
        );
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), b0_s0_bal);

        // --------------------------------------------------------------------
        // Adversarial Attack 2: Negative bit (v_0 = PRIME_P - 1 == -1 mod P)
        // --------------------------------------------------------------------
        let mut neg_v_bits = [[0u128; 4]; FAST_RANGE_BITS];
        let mut neg_r_bits = [[0u128; 4]; FAST_RANGE_BITS];
        let mut neg_sel = [[0u128; 4]; FAST_BUCKET_SIZE];
        neg_v_bits[0] = Lagrange3Of4::split_secret(PRIME_P - 1).unwrap();
        for j in 1..FAST_RANGE_BITS {
            neg_v_bits[j] = Lagrange3Of4::split_secret(0).unwrap();
        }
        let inflated_rem = b0_s0_bal + 1;
        for j in 0..FAST_RANGE_BITS {
            neg_r_bits[j] = Lagrange3Of4::split_secret((inflated_rem >> j) & 1).unwrap();
        }
        for k in 0..FAST_BUCKET_SIZE {
            neg_sel[k] = Lagrange3Of4::split_secret(if k == 1 { 1 } else { 0 }).unwrap();
        }
        let neg_req = FastTransferRequest::new_raw(0, 0, neg_v_bits, neg_r_bits, neg_sel);
        assert_eq!(
            cluster.execute_single_transfer(&neg_req, &mut pool),
            Err(FastEngineError::RangeProofFailed)
        );
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), b0_s0_bal);

        // --------------------------------------------------------------------
        // Adversarial Attack 3: Double-recipient inflation (two selector bits = 1)
        // --------------------------------------------------------------------
        let mut dup_req = FastTransferRequest::new(0, 0, b0_s0_bal, 1, 10).unwrap();
        dup_req.selector_shares[2] = Lagrange3Of4::split_secret(1).unwrap();
        assert_eq!(
            cluster.execute_single_transfer(&dup_req, &mut pool),
            Err(FastEngineError::SelectorCheckFailed)
        );
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), b0_s0_bal);

        // --------------------------------------------------------------------
        // Adversarial Attack 4: Tampered degree-2 share in parallel batch -> full rollback
        // --------------------------------------------------------------------
        let valid_b1 = FastTransferRequest::new(1, 0, expected[1][0], 1, 5).unwrap();
        let mut tampered_b0 = FastTransferRequest::new(0, 0, b0_s0_bal, 1, 5).unwrap();
        tampered_b0.v_bits[0][3] = add_mod(tampered_b0.v_bits[0][3], 1);
        assert_eq!(
            cluster.execute_parallel_batch(&[valid_b1, tampered_b0], &mut pool),
            Err(FastEngineError::InconsistentShares)
        );
        // Verify bucket 1 was NOT mutated either (atomic parallel rollback).
        assert_eq!(cluster.reconstruct_balance(1, 0).unwrap(), expected[1][0]);
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), b0_s0_bal);
    }

    #[test]
    fn test_run_speed_benchmarks_smoke() {
        let report = run_speed_benchmarks();
        assert!(report.express_tps > 0.0);
        assert!(report.shielded_tps > 0.0);
        assert!(report.compact_relay_bandwidth_ratio > 2.9);
        assert!(report.cores_used >= 1);
        assert_eq!(report.express_txs_committed, 50_000);
        println!("{report}");
    }

    #[test]
    fn test_compact_proposal_prefilled_miss_patching_and_overflow_decoding() {
        // 1. Crafted overflowing header counts must fail cleanly without panic.
        let mut malformed = vec![0u8; COMPACT_HEADER_SIZE + 4];
        malformed[20..24].copy_from_slice(&u32::MAX.to_le_bytes()); // short_count
        malformed[56..60].copy_from_slice(&u32::MAX.to_le_bytes()); // prefilled_count
        assert!(matches!(
            CompactBatchProposal::from_bytes(&malformed),
            Err(FastEngineError::InvalidEncoding(_))
        ));

        // 2. Non-empty prefilled_txs + mempool miss populates `out` so patch_missing_txs works!
        let key = RoundShortIdKey::generate();
        let mut mp = FastMempool::new(key.duplicate_for_round());
        let tx0 = CompactTx::new(0, 1, 10, 1);
        let tx1 = CompactTx::new(1, 2, 20, 1);
        let tx2 = CompactTx::new(2, 3, 30, 1);
        // Only tx2 is in follower mempool; tx0 is prefilled; tx1 is a mempool miss.
        mp.insert(tx2).unwrap();

        let prop = CompactBatchProposal {
            height: 1,
            view: 0,
            leader_id: 0,
            prev_tag: FAST_GENESIS_TAG,
            block_tag: [0u8; 16],
            short_ids: vec![key.short_id(&tx1), key.short_id(&tx2)],
            prefilled_txs: vec![(0, tx0)],
        };
        let mut out = Vec::new();
        let missing = mp.reconstruct_batch(&prop, &mut out).unwrap_err();
        assert_eq!(missing, vec![1]);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], tx0);
        assert_eq!(out[2], tx2);
        mp.patch_missing_txs(&mut out, &[(1, tx1)]).unwrap();
        assert_eq!(out, vec![tx0, tx1, tx2]);
    }
}
