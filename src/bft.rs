//! Byzantine Fault Tolerant (BFT) Batched Consensus, Compact Binary Transactions,
//! Offline Validator Quorum Catch-Up, and Proof-of-Personhood Web-of-Trust Registry
//! for Vernam (VRNM).
//!
//! Zero external crates, zero computational cryptography (no SHA-256/AES/RSA/ECDSA).
//! All link confidentiality and authenticity use strictly single-use One-Time Pads (OTP)
//! and Carter-Wegman polynomial universal MACs over the Mersenne prime field F_(2^127 - 1).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, fill_os_random, mul_mod, random_field_elem, zeroize_slice,
    zeroize_u128,
};

/// Fixed byte length of a serialized [`BinaryTx`].
pub const BINARY_TX_SIZE: usize = 32;

/// Fixed plaintext payload size for every BFT control/vote wire frame.
pub const WIRE_PAYLOAD_LEN: usize = 64;

/// Fixed wire size of an OTP-encrypted, Carter-Wegman-authenticated [`WireFrame`]:
/// `slot_id (8) + from (4) + to (4) + ciphertext (64) + tag (16) = 96 bytes`.
pub const WIRE_FRAME_LEN: usize = 96;

/// Default maximum number of [`BinaryTx`] transactions packed into a single [`TxBatchBlock`].
pub const DEFAULT_MAX_BATCH_TXS: usize = 1_000;

/// Genesis chain integrity tag (height 0).
pub const GENESIS_TAG: [u8; 16] = [0u8; 16];

// ============================================================================
// Errors
// ============================================================================

/// Errors returned by BFT consensus, OTP link framing, state sync, and Web-of-Trust operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BftError {
    /// Invalid validator set size (must satisfy N = 3f + 1 with f >= 1).
    InvalidValidatorCount(usize),
    /// Validator ID is out of range.
    UnknownValidator(u32),
    /// Validator is currently offline.
    ValidatorOffline(u32),
    /// Expected a different leader for `(height, view)`.
    WrongLeader { expected: u32, got: u32 },
    /// Pairwise OTP key deck exhausted (requires in-person pad refill).
    OtpDeckExhausted { from: u32, to: u32 },
    /// Wire frame slot ID was already consumed (replay attempt) or does not exist.
    ReplayOrMissingKeySlot { from: u32, to: u32, slot_id: u64 },
    /// Frame routing metadata did not match expected link endpoints.
    FrameEndpointMismatch {
        expected_from: u32,
        expected_to: u32,
        got_from: u32,
        got_to: u32,
    },
    /// Constant-time Carter-Wegman MAC verification failed.
    InvalidMac,
    /// Dedicated single-use block sealing key for `(height, view)` is missing or already spent.
    MissingBlockSealKey { height: u64, view: u64 },
    /// Block failed single-use Carter-Wegman integrity seal verification.
    InvalidBlockSeal { height: u64, view: u64 },
    /// Batch exceeded maximum configured transaction count.
    BatchTooLarge { count: usize, max: usize },
    /// Block height or `prev_tag` does not extend the validator's current ledger tip.
    ChainLinkMismatch {
        expected_height: u64,
        got_height: u64,
    },
    /// Transaction validation failed (amount == 0, self-transfer, insufficient balance, replay).
    InvalidTransaction { index: usize, reason: &'static str },
    /// Validator received a conflicting PrePrepare for the same `(height, view)`.
    ConflictingPrePrepare { height: u64, view: u64 },
    /// Consensus phase failed to reach `2f + 1` equal validator votes.
    QuorumNotReached {
        phase: &'static str,
        height: u64,
        view: u64,
        max_votes: usize,
        quorum: usize,
    },
    /// Binary decoding failed due to malformed bytes or unknown discriminant.
    InvalidEncoding(&'static str),
    /// No online peers could supply a valid certified block matching the quorum certificate.
    SyncBlockUnavailable { height: u64 },
    /// Web-of-Trust error: sponsor is not a verified human.
    UnauthorizedSponsor(u32),
    /// Web-of-Trust error: invalid candidate or duplicate vouch.
    InvalidVouch(&'static str),
    /// Web-of-Trust error: candidate lacks quorum vouches.
    InsufficientVouches {
        candidate_id: u32,
        have: usize,
        need: usize,
    },
}

impl fmt::Display for BftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for BftError {}

// ============================================================================
// Information-Theoretic Crypto Helpers (Carter-Wegman MAC & Pairwise OTP Links)
// ============================================================================

/// Dedicated single-use Carter-Wegman universal MAC key `(r, s)` in `F_(2^127 - 1)`.
///
/// Automatically zeroized with volatile writes on drop. Does not implement `Copy` or `Clone`
/// to prevent accidental key reuse.
pub struct CwKey {
    r: u128,
    s: u128,
}

impl CwKey {
    /// Sample a fresh OS-random one-time Carter-Wegman key `(r, s)` in `[0, PRIME_P)^2`.
    pub fn generate() -> Self {
        Self {
            r: random_field_elem(),
            s: random_field_elem(),
        }
    }

    /// Construct a key from raw field elements `r, s < PRIME_P`.
    pub fn from_raw(r: u128, s: u128) -> Self {
        assert!(r < PRIME_P && s < PRIME_P, "CwKey elements must be < PRIME_P");
        Self { r, s }
    }

    /// Explicit duplication strictly for trusted pre-sharing of identical key tapes
    /// across endpoints during setup/provisioning.
    pub(crate) fn duplicate_for_preshare(&self) -> Self {
        Self {
            r: self.r,
            s: self.s,
        }
    }

    /// Consume this one-time key to authenticate `msg`, zeroizing the key immediately.
    pub fn mac_consume(self, msg: &[u8]) -> [u8; 16] {
        let mut h = CwHasher::new(self.r);
        h.update(msg);
        h.finalize(self.s)
    }

    /// Consume this one-time key to verify `expected_tag` in constant time, zeroizing the key.
    pub fn verify_consume(self, msg: &[u8], expected_tag: &[u8; 16]) -> bool {
        let computed = self.mac_consume(msg);
        ct_eq_16(&computed, expected_tag)
    }
}

impl Drop for CwKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

/// Zero-allocation streaming Carter-Wegman polynomial accumulator over `F_(2^127 - 1)`.
///
/// Processes arbitrary byte slices in 15-byte (120-bit) little-endian blocks (`< PRIME_P`),
/// appends the exact byte length to prevent padding/length-extension ambiguity, and adds the
/// one-time pad `s mod PRIME_P`.
struct CwHasher {
    r: u128,
    acc: u128,
    buf: [u8; 15],
    buf_len: usize,
    total_len: u64,
}

impl CwHasher {
    #[inline]
    fn new(r: u128) -> Self {
        Self {
            r,
            acc: 0,
            buf: [0u8; 15],
            buf_len: 0,
            total_len: 0,
        }
    }

    #[inline(always)]
    fn fold_chunk(&mut self, chunk: &[u8; 15]) {
        let mut padded = [0u8; 16];
        padded[..15].copy_from_slice(chunk);
        let elem = u128::from_le_bytes(padded);
        self.acc = add_mod(mul_mod(self.acc, self.r), elem);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let take = (15 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];

            if self.buf_len == 15 {
                let chunk = self.buf;
                self.fold_chunk(&chunk);
                self.buf_len = 0;
            }
        }

        while data.len() >= 15 {
            let mut chunk = [0u8; 15];
            chunk.copy_from_slice(&data[..15]);
            self.fold_chunk(&chunk);
            data = &data[15..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self, mut s: u128) -> [u8; 16] {
        if self.buf_len > 0 {
            for b in &mut self.buf[self.buf_len..15] {
                *b = 0;
            }
            let chunk = self.buf;
            self.fold_chunk(&chunk);
            self.buf_len = 0;
        }

        // Mix exact total byte length so differing lengths never collide even with trailing zeros.
        self.acc = add_mod(mul_mod(self.acc, self.r), self.total_len as u128);
        let tag = add_mod(self.acc, s);

        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.acc);
        zeroize_u128(&mut s);
        zeroize_slice(&mut self.buf);

        tag.to_le_bytes()
    }
}

/// Fixed-size OTP pad automatically zeroized with volatile writes on drop.
struct OtpPad([u8; WIRE_PAYLOAD_LEN]);

impl Drop for OtpPad {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

/// Single-use key material for one fixed-size pairwise [`WireFrame`].
/// Both `otp_pad` and `cw_key` zeroize themselves automatically on drop.
struct LinkKeySlot {
    otp_pad: OtpPad,
    cw_key: CwKey,
}

impl LinkKeySlot {
    fn generate_pair() -> (Self, Self) {
        let mut pad = [0u8; WIRE_PAYLOAD_LEN];
        fill_os_random(&mut pad);
        let cw_a = CwKey::generate();
        let cw_b = cw_a.duplicate_for_preshare();
        let a = Self {
            otp_pad: OtpPad(pad),
            cw_key: cw_a,
        };
        let b = Self {
            otp_pad: OtpPad(pad),
            cw_key: cw_b,
        };
        zeroize_slice(&mut pad);
        (a, b)
    }
}

/// Fixed-size (96-byte) OTP-encrypted and Carter-Wegman-authenticated peer wire frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireFrame {
    pub slot_id: u64,
    pub from: u32,
    pub to: u32,
    pub ciphertext: [u8; WIRE_PAYLOAD_LEN],
    pub tag: [u8; 16],
}

impl WireFrame {
    /// Zero-allocation serialization into a fixed 96-byte wire buffer.
    #[inline]
    pub fn to_bytes(&self) -> [u8; WIRE_FRAME_LEN] {
        let mut out = [0u8; WIRE_FRAME_LEN];
        out[0..8].copy_from_slice(&self.slot_id.to_le_bytes());
        out[8..12].copy_from_slice(&self.from.to_le_bytes());
        out[12..16].copy_from_slice(&self.to.to_le_bytes());
        out[16..80].copy_from_slice(&self.ciphertext);
        out[80..96].copy_from_slice(&self.tag);
        out
    }

    /// Zero-allocation deserialization from a fixed 96-byte wire buffer.
    #[inline]
    pub fn from_bytes(bytes: &[u8; WIRE_FRAME_LEN]) -> Self {
        let mut slot_b = [0u8; 8];
        let mut from_b = [0u8; 4];
        let mut to_b = [0u8; 4];
        let mut ciphertext = [0u8; WIRE_PAYLOAD_LEN];
        let mut tag = [0u8; 16];

        slot_b.copy_from_slice(&bytes[0..8]);
        from_b.copy_from_slice(&bytes[8..12]);
        to_b.copy_from_slice(&bytes[12..16]);
        ciphertext.copy_from_slice(&bytes[16..80]);
        tag.copy_from_slice(&bytes[80..96]);

        Self {
            slot_id: u64::from_le_bytes(slot_b),
            from: u32::from_le_bytes(from_b),
            to: u32::from_le_bytes(to_b),
            ciphertext,
            tag,
        }
    }

    #[inline]
    fn authenticated_header_and_ct(&self) -> [u8; 80] {
        let mut buf = [0u8; 80];
        buf[0..8].copy_from_slice(&self.slot_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.from.to_le_bytes());
        buf[12..16].copy_from_slice(&self.to.to_le_bytes());
        buf[16..80].copy_from_slice(&self.ciphertext);
        buf
    }
}

/// Directed pairwise deck of single-use OTP + Carter-Wegman key slots.
///
/// Keyed by monotonic `slot_id` in a `BTreeMap` so dropped or reordered frames never
/// desynchronize the channel, while every slot is permanently removed and zeroized on use.
pub struct OtpLinkDeck {
    slots: BTreeMap<u64, LinkKeySlot>,
    next_alloc_id: u64,
    next_send_id: u64,
}

impl OtpLinkDeck {
    /// Create a matched `(outbound, inbound)` pair of decks pre-provisioned with `num_slots`
    /// single-use OS-random OTP+CW slots.
    pub fn create_pair(num_slots: usize) -> (Self, Self) {
        let mut outbound = Self {
            slots: BTreeMap::new(),
            next_alloc_id: 0,
            next_send_id: 0,
        };
        let mut inbound = Self {
            slots: BTreeMap::new(),
            next_alloc_id: 0,
            next_send_id: 0,
        };
        Self::provision_more(&mut outbound, &mut inbound, num_slots);
        (outbound, inbound)
    }

    /// Refill a matched `(outbound, inbound)` pair with `count` additional single-use slots.
    pub fn provision_more(outbound: &mut Self, inbound: &mut Self, count: usize) {
        assert_eq!(
            outbound.next_alloc_id, inbound.next_alloc_id,
            "pairwise decks out of sync"
        );
        for _ in 0..count {
            let id = outbound.next_alloc_id;
            let next_id = id
                .checked_add(1)
                .expect("OTP link deck slot_id space exhausted");
            let (slot_a, slot_b) = LinkKeySlot::generate_pair();
            outbound.slots.insert(id, slot_a);
            inbound.slots.insert(id, slot_b);
            outbound.next_alloc_id = next_id;
            inbound.next_alloc_id = next_id;
        }
    }

    /// Number of remaining unused single-use slots in this deck.
    pub fn remaining(&self) -> usize {
        self.slots.len()
    }

    /// Encrypt and Carter-Wegman authenticate a fixed 64-byte plaintext payload (Encrypt-then-MAC),
    /// consuming and zeroizing one slot permanently.
    pub fn seal_frame(
        &mut self,
        from: u32,
        to: u32,
        plaintext: &[u8; WIRE_PAYLOAD_LEN],
    ) -> Result<WireFrame, BftError> {
        let slot_id = self.next_send_id;
        let next_id = slot_id
            .checked_add(1)
            .ok_or(BftError::OtpDeckExhausted { from, to })?;
        let slot = self
            .slots
            .remove(&slot_id)
            .ok_or(BftError::OtpDeckExhausted { from, to })?;
        self.next_send_id = next_id;

        let LinkKeySlot { otp_pad, cw_key } = slot;

        let mut ciphertext = [0u8; WIRE_PAYLOAD_LEN];
        for i in 0..WIRE_PAYLOAD_LEN {
            ciphertext[i] = plaintext[i] ^ otp_pad.0[i];
        }
        drop(otp_pad);

        let mut frame = WireFrame {
            slot_id,
            from,
            to,
            ciphertext,
            tag: [0u8; 16],
        };
        let auth_bytes = frame.authenticated_header_and_ct();
        frame.tag = cw_key.mac_consume(&auth_bytes);
        Ok(frame)
    }

    /// Authenticate (constant-time CW-MAC) and OTP-decrypt an inbound fixed-size [`WireFrame`],
    /// consuming and zeroizing its slot permanently (even on MAC failure).
    pub fn open_frame(
        &mut self,
        frame: &WireFrame,
        expected_from: u32,
        expected_to: u32,
    ) -> Result<[u8; WIRE_PAYLOAD_LEN], BftError> {
        if frame.from != expected_from || frame.to != expected_to {
            return Err(BftError::FrameEndpointMismatch {
                expected_from,
                expected_to,
                got_from: frame.from,
                got_to: frame.to,
            });
        }

        let slot = self.slots.remove(&frame.slot_id).ok_or(
            BftError::ReplayOrMissingKeySlot {
                from: frame.from,
                to: frame.to,
                slot_id: frame.slot_id,
            },
        )?;

        let auth_bytes = frame.authenticated_header_and_ct();
        let LinkKeySlot { otp_pad, cw_key } = slot;
        if !cw_key.verify_consume(&auth_bytes, &frame.tag) {
            drop(otp_pad);
            return Err(BftError::InvalidMac);
        }

        let mut plaintext = [0u8; WIRE_PAYLOAD_LEN];
        for i in 0..WIRE_PAYLOAD_LEN {
            plaintext[i] = frame.ciphertext[i] ^ otp_pad.0[i];
        }
        drop(otp_pad);
        Ok(plaintext)
    }
}

/// Per-validator deck of dedicated single-use Carter-Wegman block sealing keys indexed by `(height, view)`.
///
/// Each `(height, view)` has its own independent one-time sealing key so view changes and
/// failed rounds never reuse key material.
pub struct BlockSealDeck {
    keys: BTreeMap<(u64, u64), CwKey>,
}

impl BlockSealDeck {
    /// Create an empty block sealing key deck.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Pre-share dedicated one-time sealing keys for heights `1..=max_height` and views `0..max_views`
    /// across `num_validators` independent decks.
    pub fn create_committee_decks(
        num_validators: usize,
        max_height: u64,
        max_views: u64,
    ) -> Vec<Self> {
        let mut decks: Vec<Self> = (0..num_validators).map(|_| Self::new()).collect();
        for h in 1..=max_height {
            for v in 0..max_views {
                let master = CwKey::generate();
                for deck in &mut decks {
                    deck.keys.insert((h, v), master.duplicate_for_preshare());
                }
            }
        }
        decks
    }

    /// Insert a single-use key for `(height, view)`.
    pub fn insert(&mut self, height: u64, view: u64, key: CwKey) {
        self.keys.insert((height, view), key);
    }

    /// Permanently consume the dedicated one-time sealing key for `(height, view)`.
    pub fn take_key(&mut self, height: u64, view: u64) -> Result<CwKey, BftError> {
        self.keys
            .remove(&(height, view))
            .ok_or(BftError::MissingBlockSealKey { height, view })
    }

    /// Peek-duplicate a sealing key ONLY for Byzantine fault testing (simulating a malicious
    /// leader violating single-use discipline to equivocate with two conflicting batches).
    #[cfg(test)]
    fn byzantine_duplicate_key(&self, height: u64, view: u64) -> Result<CwKey, BftError> {
        self.keys
            .get(&(height, view))
            .map(CwKey::duplicate_for_preshare)
            .ok_or(BftError::MissingBlockSealKey { height, view })
    }
}

impl Default for BlockSealDeck {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 1. Compact Binary Transaction Format (32 bytes, zero allocation)
// ============================================================================

/// Fixed 32-byte compact binary transaction for high-throughput VRNM batches.
///
/// Wire layout (little-endian):
/// - `[0..4]`   `sender_id: u32`
/// - `[4..8]`   `recipient_id: u32`
/// - `[8..16]`  `amount: u64`
/// - `[16..24]` `page_id: u64`
/// - `[24..32]` `nonce: u64`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BinaryTx {
    pub sender_id: u32,
    pub recipient_id: u32,
    pub amount: u64,
    pub page_id: u64,
    pub nonce: u64,
}

impl BinaryTx {
    /// Construct a new compact binary transaction.
    #[inline]
    pub const fn new(
        sender_id: u32,
        recipient_id: u32,
        amount: u64,
        page_id: u64,
        nonce: u64,
    ) -> Self {
        Self {
            sender_id,
            recipient_id,
            amount,
            page_id,
            nonce,
        }
    }

    /// Zero-allocation serialization into a fixed 32-byte array.
    #[inline]
    pub const fn to_bytes(&self) -> [u8; BINARY_TX_SIZE] {
        let s = self.sender_id.to_le_bytes();
        let r = self.recipient_id.to_le_bytes();
        let a = self.amount.to_le_bytes();
        let p = self.page_id.to_le_bytes();
        let n = self.nonce.to_le_bytes();
        [
            s[0], s[1], s[2], s[3],
            r[0], r[1], r[2], r[3],
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
            n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7],
        ]
    }

    /// Zero-allocation deserialization from a fixed 32-byte array.
    #[inline]
    pub const fn from_bytes(b: &[u8; BINARY_TX_SIZE]) -> Self {
        Self {
            sender_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            recipient_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            amount: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            page_id: u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            nonce: u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]),
        }
    }
}

// ============================================================================
// 2. Batched Consensus Blocks with Single-Use Carter-Wegman Chaining
// ============================================================================

/// Batched BFT consensus block packing up to `N` [`BinaryTx`] entries into a single
/// consensus round, chained via a dedicated single-use Carter-Wegman block integrity seal
/// over `prev_tag || height || batch_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBatchBlock {
    pub height: u64,
    pub view: u64,
    pub leader_id: u32,
    pub prev_tag: [u8; 16],
    pub txs: Vec<BinaryTx>,
    pub block_tag: [u8; 16],
}

impl TxBatchBlock {
    /// Compute the single-use Carter-Wegman integrity tag chaining
    /// `prev_tag (16B) || height (8B LE) || batch_bytes (32B * len)` with zero heap allocation.
    pub fn compute_chain_tag(
        prev_tag: &[u8; 16],
        height: u64,
        txs: &[BinaryTx],
        seal_key: CwKey,
    ) -> [u8; 16] {
        let mut hasher = CwHasher::new(seal_key.r);
        hasher.update(prev_tag);
        hasher.update(&height.to_le_bytes());
        for tx in txs {
            let raw = tx.to_bytes();
            hasher.update(&raw);
        }
        let s = seal_key.s;
        drop(seal_key);
        hasher.finalize(s)
    }

    /// Seal a batch of binary transactions using a dedicated single-use Carter-Wegman key,
    /// enforcing `DEFAULT_MAX_BATCH_TXS`.
    pub fn seal(
        height: u64,
        view: u64,
        leader_id: u32,
        prev_tag: [u8; 16],
        txs: Vec<BinaryTx>,
        seal_key: CwKey,
    ) -> Result<Self, BftError> {
        Self::seal_with_limit(
            height,
            view,
            leader_id,
            prev_tag,
            txs,
            seal_key,
            DEFAULT_MAX_BATCH_TXS,
        )
    }

    /// Seal a batch with an explicit maximum transaction count.
    pub fn seal_with_limit(
        height: u64,
        view: u64,
        leader_id: u32,
        prev_tag: [u8; 16],
        txs: Vec<BinaryTx>,
        seal_key: CwKey,
        max_batch_txs: usize,
    ) -> Result<Self, BftError> {
        if txs.len() > max_batch_txs {
            drop(seal_key);
            return Err(BftError::BatchTooLarge {
                count: txs.len(),
                max: max_batch_txs,
            });
        }
        let block_tag = Self::compute_chain_tag(&prev_tag, height, &txs, seal_key);
        Ok(Self {
            height,
            view,
            leader_id,
            prev_tag,
            txs,
            block_tag,
        })
    }

    /// Verify the block's single-use Carter-Wegman chain integrity seal in constant time,
    /// consuming and zeroizing `seal_key`.
    pub fn verify_seal(&self, seal_key: CwKey) -> bool {
        let computed = Self::compute_chain_tag(&self.prev_tag, self.height, &self.txs, seal_key);
        ct_eq_16(&computed, &self.block_tag)
    }

    /// Return the contiguous binary batch payload (`txs.len() * 32` bytes).
    pub fn batch_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.txs.len() * BINARY_TX_SIZE);
        for tx in &self.txs {
            out.extend_from_slice(&tx.to_bytes());
        }
        out
    }

    /// Encode the full block into a compact binary buffer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(56 + self.txs.len() * BINARY_TX_SIZE);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.view.to_le_bytes());
        out.extend_from_slice(&self.leader_id.to_le_bytes());
        out.extend_from_slice(&(self.txs.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.prev_tag);
        out.extend_from_slice(&self.block_tag);
        for tx in &self.txs {
            out.extend_from_slice(&tx.to_bytes());
        }
        out
    }

    /// Decode a compact binary block buffer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BftError> {
        if bytes.len() < 56 {
            return Err(BftError::InvalidEncoding("block header truncated"));
        }
        let height = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let view = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let leader_id = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let tx_count = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        let mut prev_tag = [0u8; 16];
        prev_tag.copy_from_slice(&bytes[24..40]);
        let mut block_tag = [0u8; 16];
        block_tag.copy_from_slice(&bytes[40..56]);

        let expected_len = tx_count
            .checked_mul(BINARY_TX_SIZE)
            .and_then(|n| n.checked_add(56))
            .ok_or(BftError::InvalidEncoding("block tx payload length overflow"))?;
        if bytes.len() != expected_len {
            return Err(BftError::InvalidEncoding("block tx payload length mismatch"));
        }

        let mut txs = Vec::with_capacity(tx_count);
        for i in 0..tx_count {
            let offset = 56 + i * BINARY_TX_SIZE;
            let raw: &[u8; BINARY_TX_SIZE] = bytes[offset..offset + BINARY_TX_SIZE]
                .try_into()
                .unwrap();
            txs.push(BinaryTx::from_bytes(raw));
        }

        Ok(Self {
            height,
            view,
            leader_id,
            prev_tag,
            txs,
            block_tag,
        })
    }
}

// ============================================================================
// 3. Deterministic Ledger State (Atomic Batch Execution)
// ============================================================================

/// Replicated deterministic ledger state maintained identically by every honest validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerState {
    pub height: u64,
    pub tip_tag: [u8; 16],
    pub balances: BTreeMap<u32, u64>,
    pub used_pages: HashSet<(u32, u64)>,
    pub used_nonces: HashSet<(u32, u64)>,
}

impl LedgerState {
    /// Initialize a genesis ledger state with starting account balances.
    pub fn new(initial_balances: BTreeMap<u32, u64>) -> Self {
        Self {
            height: 0,
            tip_tag: GENESIS_TAG,
            balances: initial_balances,
            used_pages: HashSet::new(),
            used_nonces: HashSet::new(),
        }
    }

    /// Return an account's current VRNM balance (0 if absent).
    pub fn balance_of(&self, account_id: u32) -> u64 {
        self.balances.get(&account_id).copied().unwrap_or(0)
    }

    /// Validate a proposed batch against current state without mutating `self`.
    pub fn validate_batch_readonly(&self, block: &TxBatchBlock) -> Result<(), BftError> {
        let expected_height = self
            .height
            .checked_add(1)
            .ok_or(BftError::ChainLinkMismatch {
                expected_height: u64::MAX,
                got_height: block.height,
            })?;
        if block.height != expected_height || !ct_eq_16(&block.prev_tag, &self.tip_tag) {
            return Err(BftError::ChainLinkMismatch {
                expected_height,
                got_height: block.height,
            });
        }

        let mut staged_balances: BTreeMap<u32, u64> = BTreeMap::new();
        let mut staged_pages: HashSet<(u32, u64)> = HashSet::with_capacity(block.txs.len());
        let mut staged_nonces: HashSet<(u32, u64)> = HashSet::with_capacity(block.txs.len());

        for (idx, tx) in block.txs.iter().enumerate() {
            if tx.amount == 0 {
                return Err(BftError::InvalidTransaction {
                    index: idx,
                    reason: "zero transfer amount",
                });
            }
            if tx.sender_id == tx.recipient_id {
                return Err(BftError::InvalidTransaction {
                    index: idx,
                    reason: "self-transfer forbidden",
                });
            }

            let page_key = (tx.sender_id, tx.page_id);
            if self.used_pages.contains(&page_key) || !staged_pages.insert(page_key) {
                return Err(BftError::InvalidTransaction {
                    index: idx,
                    reason: "duplicate OTP page_id (replay/double-spend)",
                });
            }

            let nonce_key = (tx.sender_id, tx.nonce);
            if self.used_nonces.contains(&nonce_key) || !staged_nonces.insert(nonce_key) {
                return Err(BftError::InvalidTransaction {
                    index: idx,
                    reason: "duplicate sender nonce",
                });
            }

            let sender_bal = *staged_balances
                .entry(tx.sender_id)
                .or_insert_with(|| self.balance_of(tx.sender_id));
            if sender_bal < tx.amount {
                return Err(BftError::InvalidTransaction {
                    index: idx,
                    reason: "insufficient balance",
                });
            }

            let recip_bal = *staged_balances
                .entry(tx.recipient_id)
                .or_insert_with(|| self.balance_of(tx.recipient_id));
            let new_recip_bal = recip_bal.checked_add(tx.amount).ok_or(
                BftError::InvalidTransaction {
                    index: idx,
                    reason: "recipient balance overflow",
                },
            )?;

            staged_balances.insert(tx.sender_id, sender_bal - tx.amount);
            staged_balances.insert(tx.recipient_id, new_recip_bal);
        }

        Ok(())
    }

    /// Atomically validate and apply a committed [`TxBatchBlock`] to the ledger.
    /// If any transaction fails validation, zero state is modified.
    pub fn apply_committed_block(&mut self, block: &TxBatchBlock) -> Result<(), BftError> {
        self.validate_batch_readonly(block)?;

        for (idx, tx) in block.txs.iter().enumerate() {
            let sender_bal = self.balance_of(tx.sender_id);
            let recip_bal = self.balance_of(tx.recipient_id);
            let new_sender = sender_bal
                .checked_sub(tx.amount)
                .ok_or(BftError::InvalidTransaction {
                    index: idx,
                    reason: "insufficient balance",
                })?;
            let new_recip = recip_bal
                .checked_add(tx.amount)
                .ok_or(BftError::InvalidTransaction {
                    index: idx,
                    reason: "recipient balance overflow",
                })?;
            self.balances.insert(tx.sender_id, new_sender);
            self.balances.insert(tx.recipient_id, new_recip);
            self.used_pages.insert((tx.sender_id, tx.page_id));
            self.used_nonces.insert((tx.sender_id, tx.nonce));
        }

        self.height = block.height;
        self.tip_tag = block.block_tag;
        Ok(())
    }
}

// ============================================================================
// 4. Full 2-Phase BFT Consensus (PrePrepare -> Prepare -> Commit + ViewChange)
// ============================================================================

/// BFT committee configuration for `N = 3f + 1` equal-vote validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BftConfig {
    pub num_validators: usize,
    pub max_batch_txs: usize,
}

impl BftConfig {
    /// Create a BFT configuration for `num_validators = 3f + 1` (`4, 7, 10, ...`).
    pub fn new(num_validators: usize, max_batch_txs: usize) -> Result<Self, BftError> {
        if num_validators < 4
            || (num_validators - 1) % 3 != 0
            || num_validators > u32::MAX as usize
        {
            return Err(BftError::InvalidValidatorCount(num_validators));
        }
        Ok(Self {
            num_validators,
            max_batch_txs,
        })
    }

    /// Create a BFT configuration tolerating up to `f` Byzantine validators (`N = 3f + 1`).
    pub fn for_faults(f: usize) -> Result<Self, BftError> {
        if f == 0 {
            return Err(BftError::InvalidValidatorCount(1));
        }
        let num_validators = f
            .checked_mul(3)
            .and_then(|v| v.checked_add(1))
            .filter(|&n| n <= u32::MAX as usize)
            .ok_or(BftError::InvalidValidatorCount(usize::MAX))?;
        Ok(Self {
            num_validators,
            max_batch_txs: DEFAULT_MAX_BATCH_TXS,
        })
    }

    /// Maximum number of Byzantine faults tolerated (`f = (N - 1) / 3`).
    #[inline]
    pub const fn max_faults(&self) -> usize {
        (self.num_validators - 1) / 3
    }

    /// Unweighted quorum threshold (`2f + 1` distinct validators, 1 validator = 1 equal vote).
    #[inline]
    pub const fn quorum(&self) -> usize {
        2 * self.max_faults() + 1
    }

    /// Deterministic leader rotation: `leader = (height + view) % N`.
    /// Uses `u128` addition to avoid modular wrap discontinuity at `u64::MAX`.
    #[inline]
    pub const fn leader_for(&self, height: u64, view: u64) -> u32 {
        (((height as u128) + (view as u128)) % (self.num_validators as u128)) as u32
    }
}

impl Default for BftConfig {
    fn default() -> Self {
        Self {
            num_validators: 4,
            max_batch_txs: DEFAULT_MAX_BATCH_TXS,
        }
    }
}

/// Discriminant for fixed-size pairwise BFT control messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgKind {
    PrePrepare = 1,
    Prepare = 2,
    Commit = 3,
    ViewChange = 4,
    SyncCert = 5,
}

impl MsgKind {
    fn from_u8(v: u8) -> Result<Self, BftError> {
        match v {
            1 => Ok(Self::PrePrepare),
            2 => Ok(Self::Prepare),
            3 => Ok(Self::Commit),
            4 => Ok(Self::ViewChange),
            5 => Ok(Self::SyncCert),
            _ => Err(BftError::InvalidEncoding("unknown BFT message kind")),
        }
    }
}

/// Fixed 64-byte consensus vote / certificate payload transmitted inside a 96-byte [`WireFrame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusVote {
    pub kind: MsgKind,
    pub voter_id: u32,
    pub height: u64,
    pub view: u64,
    pub block_tag: [u8; 16],
    pub prev_tag: [u8; 16],
    pub tx_count: u32,
    /// For `MsgKind::ViewChange`: optional highest locked view (`block_tag` holds locked tag).
    pub locked_view: Option<u64>,
}

impl ConsensusVote {
    /// Zero-allocation serialization into a fixed 64-byte wire payload.
    pub fn to_payload(&self) -> [u8; WIRE_PAYLOAD_LEN] {
        let mut buf = [0u8; WIRE_PAYLOAD_LEN];
        buf[0] = self.kind as u8;
        buf[1] = u8::from(self.locked_view.is_some());
        // bytes 2..4 reserved zero
        buf[4..8].copy_from_slice(&self.voter_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.height.to_le_bytes());
        buf[16..24].copy_from_slice(&self.view.to_le_bytes());
        buf[24..40].copy_from_slice(&self.block_tag);
        buf[40..56].copy_from_slice(&self.prev_tag);
        if let Some(lv) = self.locked_view {
            buf[56..64].copy_from_slice(&lv.to_le_bytes());
        } else {
            buf[56..60].copy_from_slice(&self.tx_count.to_le_bytes());
        }
        buf
    }

    /// Zero-allocation deserialization from a fixed 64-byte wire payload.
    pub fn from_payload(buf: &[u8; WIRE_PAYLOAD_LEN]) -> Result<Self, BftError> {
        let kind = MsgKind::from_u8(buf[0])?;
        let has_lock = buf[1] != 0;
        let voter_id = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let height = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let view = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let mut block_tag = [0u8; 16];
        block_tag.copy_from_slice(&buf[24..40]);
        let mut prev_tag = [0u8; 16];
        prev_tag.copy_from_slice(&buf[40..56]);
        let (tx_count, locked_view) = if has_lock {
            let lv = u64::from_le_bytes(buf[56..64].try_into().unwrap());
            (0u32, Some(lv))
        } else {
            (u32::from_le_bytes(buf[56..60].try_into().unwrap()), None)
        };

        Ok(Self {
            kind,
            voter_id,
            height,
            view,
            block_tag,
            prev_tag,
            tx_count,
            locked_view,
        })
    }
}

/// Quorum-certified finalization record for a committed [`TxBatchBlock`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockCertificate {
    pub height: u64,
    pub view: u64,
    pub leader_id: u32,
    pub block_tag: [u8; 16],
    pub prev_tag: [u8; 16],
    pub tx_count: u32,
    /// Distinct equal-weight validator IDs (`len >= 2f + 1`) that committed this block.
    pub commit_voters: Vec<u32>,
}

/// Transient state held by a validator during a single `(height, view)` BFT round.
#[derive(Default)]
struct RoundState {
    proposed_block: Option<TxBatchBlock>,
    prepare_votes: BTreeMap<[u8; 16], BTreeSet<u32>>,
    prepare_voter_tag: BTreeMap<u32, [u8; 16]>,
    commit_votes: BTreeMap<[u8; 16], BTreeSet<u32>>,
    commit_voter_tag: BTreeMap<u32, [u8; 16]>,
    prepared_tag: Option<[u8; 16]>,
    view_change_votes: BTreeMap<u64, BTreeMap<u32, Option<(u64, [u8; 16])>>>,
}

impl RoundState {
    fn clear(&mut self) {
        self.proposed_block = None;
        self.prepare_votes.clear();
        self.prepare_voter_tag.clear();
        self.commit_votes.clear();
        self.commit_voter_tag.clear();
        self.prepared_tag = None;
        self.view_change_votes.clear();
    }
}

/// Independent BFT validator node with isolated ledger state, pairwise OTP+CW peer decks,
/// and dedicated single-use block sealing keys.
pub struct BftValidator {
    pub id: u32,
    pub config: BftConfig,
    pub online: bool,
    pub current_view: u64,
    /// Highest view in which this validator achieved a `2f + 1` Prepare lock for `next_height()`.
    pub locked_view: Option<u64>,
    /// Block integrity tag locked at `locked_view` (preserved safely across `ViewChange`s).
    pub locked_block_tag: Option<[u8; 16]>,
    pub ledger: LedgerState,
    pub committed_blocks: BTreeMap<u64, TxBatchBlock>,
    pub certificates: BTreeMap<u64, BlockCertificate>,
    outbound_links: BTreeMap<u32, OtpLinkDeck>,
    inbound_links: BTreeMap<u32, OtpLinkDeck>,
    seal_deck: BlockSealDeck,
    round: RoundState,
}

impl BftValidator {
    /// Next height this validator expects to finalize.
    #[inline]
    pub fn next_height(&self) -> u64 {
        self.ledger.height.saturating_add(1)
    }

    /// Remaining outbound OTP slots toward `peer_id`.
    pub fn outbound_slots_remaining(&self, peer_id: u32) -> usize {
        self.outbound_links
            .get(&peer_id)
            .map(OtpLinkDeck::remaining)
            .unwrap_or(0)
    }

    /// Remaining inbound OTP slots from `peer_id`.
    pub fn inbound_slots_remaining(&self, peer_id: u32) -> usize {
        self.inbound_links
            .get(&peer_id)
            .map(OtpLinkDeck::remaining)
            .unwrap_or(0)
    }

    /// Send a fixed-size OTP-encrypted + Carter-Wegman-authenticated vote frame to `to`.
    pub fn send_vote_frame(
        &mut self,
        to: u32,
        vote: &ConsensusVote,
    ) -> Result<WireFrame, BftError> {
        let deck = self
            .outbound_links
            .get_mut(&to)
            .ok_or(BftError::UnknownValidator(to))?;
        let payload = vote.to_payload();
        deck.seal_frame(self.id, to, &payload)
    }

    /// Verify and decrypt an inbound fixed-size vote frame from `from`.
    pub fn recv_vote_frame(
        &mut self,
        from: u32,
        frame: &WireFrame,
    ) -> Result<ConsensusVote, BftError> {
        let deck = self
            .inbound_links
            .get_mut(&from)
            .ok_or(BftError::UnknownValidator(from))?;
        let payload = deck.open_frame(frame, from, self.id)?;
        ConsensusVote::from_payload(&payload)
    }

    /// Broadcast a vote to all `targets` (excluding self), returning fixed-size [`WireFrame`]s.
    fn broadcast_vote(
        &mut self,
        targets: &[u32],
        vote: &ConsensusVote,
    ) -> Result<Vec<WireFrame>, BftError> {
        let mut frames = Vec::with_capacity(targets.len());
        for &peer in targets {
            if peer == self.id {
                continue;
            }
            frames.push(self.send_vote_frame(peer, vote)?);
        }
        Ok(frames)
    }

    /// **Phase 0 (Leader):** Propose a batched block for `(next_height, current_view)`.
    ///
    /// Consumes this validator's single-use block sealing key for `(height, view)`, validates
    /// the batch, locks the proposal locally, and produces pairwise authenticated `PrePrepare`
    /// and `Prepare` wire frames for all online peers.
    pub fn leader_propose(
        &mut self,
        txs: Vec<BinaryTx>,
        online_peers: &[u32],
    ) -> Result<(TxBatchBlock, Vec<WireFrame>, Vec<WireFrame>), BftError> {
        if !self.online {
            return Err(BftError::ValidatorOffline(self.id));
        }
        let height = self
            .ledger
            .height
            .checked_add(1)
            .ok_or(BftError::ChainLinkMismatch {
                expected_height: u64::MAX,
                got_height: u64::MAX,
            })?;
        let view = self.current_view;
        let expected_leader = self.config.leader_for(height, view);
        if self.id != expected_leader {
            return Err(BftError::WrongLeader {
                expected: expected_leader,
                got: self.id,
            });
        }

        if self.locked_view.is_some_and(|lv| view <= lv) {
            return Err(BftError::ConflictingPrePrepare { height, view });
        }

        if txs.len() > self.config.max_batch_txs {
            return Err(BftError::BatchTooLarge {
                count: txs.len(),
                max: self.config.max_batch_txs,
            });
        }

        // Validate batch BEFORE consuming the single-use block sealing key.
        let precheck_block = TxBatchBlock {
            height,
            view,
            leader_id: self.id,
            prev_tag: self.ledger.tip_tag,
            txs,
            block_tag: GENESIS_TAG,
        };
        self.ledger.validate_batch_readonly(&precheck_block)?;
        let TxBatchBlock { txs, .. } = precheck_block;

        let seal_key = self.seal_deck.take_key(height, view)?;
        let block = TxBatchBlock::seal_with_limit(
            height,
            view,
            self.id,
            self.ledger.tip_tag,
            txs,
            seal_key,
            self.config.max_batch_txs,
        )?;

        self.round.clear();
        self.round.proposed_block = Some(block.clone());
        self.round
            .prepare_votes
            .entry(block.block_tag)
            .or_default()
            .insert(self.id);
        self.round.prepare_voter_tag.insert(self.id, block.block_tag);

        let pre_prepare_vote = ConsensusVote {
            kind: MsgKind::PrePrepare,
            voter_id: self.id,
            height,
            view,
            block_tag: block.block_tag,
            prev_tag: block.prev_tag,
            tx_count: block.txs.len() as u32,
            locked_view: None,
        };
        let prepare_vote = ConsensusVote {
            kind: MsgKind::Prepare,
            ..pre_prepare_vote
        };

        let pre_prepare_frames = self.broadcast_vote(online_peers, &pre_prepare_vote)?;
        let prepare_frames = self.broadcast_vote(online_peers, &prepare_vote)?;
        Ok((block, pre_prepare_frames, prepare_frames))
    }

    /// **Phase 0 (Follower):** Verify an incoming `PrePrepare` frame + `TxBatchBlock` from the
    /// current leader, verify the single-use Carter-Wegman block seal and batch validity, and
    /// broadcast pairwise authenticated `Prepare` wire frames.
    pub fn on_pre_prepare(
        &mut self,
        frame: &WireFrame,
        block: TxBatchBlock,
        online_peers: &[u32],
    ) -> Result<Vec<WireFrame>, BftError> {
        if !self.online {
            return Err(BftError::ValidatorOffline(self.id));
        }

        let height = self
            .ledger
            .height
            .checked_add(1)
            .ok_or(BftError::ChainLinkMismatch {
                expected_height: u64::MAX,
                got_height: block.height,
            })?;
        let view = self.current_view;
        let expected_leader = self.config.leader_for(height, view);

        let vote = self.recv_vote_frame(expected_leader, frame)?;
        if vote.kind != MsgKind::PrePrepare
            || vote.voter_id != expected_leader
            || vote.height != height
            || vote.view != view
        {
            return Err(BftError::InvalidEncoding("mismatched PrePrepare metadata"));
        }

        if block.height != height
            || block.view != view
            || block.leader_id != expected_leader
            || block.txs.len() > self.config.max_batch_txs
            || block.txs.len() as u32 != vote.tx_count
            || !ct_eq_16(&block.block_tag, &vote.block_tag)
            || !ct_eq_16(&block.prev_tag, &vote.prev_tag)
            || !ct_eq_16(&block.prev_tag, &self.ledger.tip_tag)
        {
            return Err(BftError::ChainLinkMismatch {
                expected_height: height,
                got_height: block.height,
            });
        }

        // BFT Safety lock rule: never accept a PrePrepare at or below an already-locked view.
        if self.locked_view.is_some_and(|lv| view <= lv) {
            return Err(BftError::ConflictingPrePrepare { height, view });
        }

        if let Some(existing) = &self.round.proposed_block {
            if !ct_eq_16(&existing.block_tag, &block.block_tag) {
                return Err(BftError::ConflictingPrePrepare { height, view });
            }
            // Idempotent duplicate matching PrePrepare: already verified & voted in this round.
            return Ok(Vec::new());
        }

        let seal_key = self.seal_deck.take_key(height, view)?;
        if !block.verify_seal(seal_key) {
            return Err(BftError::InvalidBlockSeal { height, view });
        }

        self.ledger.validate_batch_readonly(&block)?;

        let block_tag = block.block_tag;
        let prev_tag = block.prev_tag;
        let tx_count = block.txs.len() as u32;

        self.round.proposed_block = Some(block);
        // Record leader's implicit PrePrepare support? No — leader sends an explicit Prepare frame
        // so every Prepare vote is uniformly authenticated over pairwise OTP+CW links.
        self.round
            .prepare_votes
            .entry(block_tag)
            .or_default()
            .insert(self.id);
        self.round.prepare_voter_tag.insert(self.id, block_tag);

        let prepare_vote = ConsensusVote {
            kind: MsgKind::Prepare,
            voter_id: self.id,
            height,
            view,
            block_tag,
            prev_tag,
            tx_count,
            locked_view: None,
        };
        self.broadcast_vote(online_peers, &prepare_vote)
    }

    /// **Phase 1 (Prepare):** Ingest an inbound OTP+CW authenticated `Prepare` frame.
    /// Enforces flat 1-validator = 1-equal-vote deduplication and rejects equivocating votes
    /// for two different `block_tag`s in the same `(height, view, Prepare)`.
    pub fn on_prepare_frame(&mut self, frame: &WireFrame) -> Result<(), BftError> {
        if !self.online {
            return Err(BftError::ValidatorOffline(self.id));
        }
        let vote = self.recv_vote_frame(frame.from, frame)?;
        if vote.kind != MsgKind::Prepare
            || vote.voter_id != frame.from
            || vote.height != self.next_height()
            || vote.view != self.current_view
            || !ct_eq_16(&vote.prev_tag, &self.ledger.tip_tag)
        {
            return Err(BftError::InvalidEncoding("mismatched Prepare vote"));
        }

        if let Some(prev_tag) = self.round.prepare_voter_tag.get(&vote.voter_id) {
            if !ct_eq_16(prev_tag, &vote.block_tag) {
                return Err(BftError::InvalidEncoding(
                    "equivocating Prepare vote for conflicting block_tag",
                ));
            }
            return Ok(());
        }
        self.round
            .prepare_voter_tag
            .insert(vote.voter_id, vote.block_tag);
        self.round
            .prepare_votes
            .entry(vote.block_tag)
            .or_default()
            .insert(vote.voter_id);
        Ok(())
    }

    /// Check if this validator has collected `>= 2f + 1` equal `Prepare` votes for its locked
    /// proposal; if so, transition to Prepared and broadcast pairwise authenticated `Commit` frames.
    pub fn try_enter_commit(&mut self, online_peers: &[u32]) -> Result<Vec<WireFrame>, BftError> {
        if !self.online {
            return Err(BftError::ValidatorOffline(self.id));
        }
        let Some(block) = &self.round.proposed_block else {
            return Err(BftError::QuorumNotReached {
                phase: "Prepare",
                height: self.next_height(),
                view: self.current_view,
                max_votes: 0,
                quorum: self.config.quorum(),
            });
        };

        let tag = block.block_tag;
        let prev_tag = block.prev_tag;
        let tx_count = block.txs.len() as u32;
        let height = block.height;
        let view = block.view;

        let count = self
            .round
            .prepare_votes
            .get(&tag)
            .map(BTreeSet::len)
            .unwrap_or(0);
        if count < self.config.quorum() {
            return Err(BftError::QuorumNotReached {
                phase: "Prepare",
                height,
                view,
                max_votes: count,
                quorum: self.config.quorum(),
            });
        }

        self.round.prepared_tag = Some(tag);
        // Lock on this prepared block so safety is preserved across any subsequent ViewChange.
        self.locked_view = Some(view);
        self.locked_block_tag = Some(tag);
        self.round
            .commit_votes
            .entry(tag)
            .or_default()
            .insert(self.id);
        self.round.commit_voter_tag.insert(self.id, tag);

        let commit_vote = ConsensusVote {
            kind: MsgKind::Commit,
            voter_id: self.id,
            height,
            view,
            block_tag: tag,
            prev_tag,
            tx_count,
            locked_view: None,
        };
        self.broadcast_vote(online_peers, &commit_vote)
    }

    /// **Phase 2 (Commit):** Ingest an inbound OTP+CW authenticated `Commit` frame, rejecting
    /// equivocating Commit votes for conflicting `block_tag`s in the same `(height, view)`.
    pub fn on_commit_frame(&mut self, frame: &WireFrame) -> Result<(), BftError> {
        if !self.online {
            return Err(BftError::ValidatorOffline(self.id));
        }
        let vote = self.recv_vote_frame(frame.from, frame)?;
        if vote.kind != MsgKind::Commit
            || vote.voter_id != frame.from
            || vote.height != self.next_height()
            || vote.view != self.current_view
            || !ct_eq_16(&vote.prev_tag, &self.ledger.tip_tag)
        {
            return Err(BftError::InvalidEncoding("mismatched Commit vote"));
        }

        if let Some(prev_tag) = self.round.commit_voter_tag.get(&vote.voter_id) {
            if !ct_eq_16(prev_tag, &vote.block_tag) {
                return Err(BftError::InvalidEncoding(
                    "equivocating Commit vote for conflicting block_tag",
                ));
            }
            return Ok(());
        }
        self.round
            .commit_voter_tag
            .insert(vote.voter_id, vote.block_tag);
        self.round
            .commit_votes
            .entry(vote.block_tag)
            .or_default()
            .insert(vote.voter_id);
        Ok(())
    }

    /// Finalize the prepared block if `>= 2f + 1` equal `Commit` votes have been verified.
    /// Applies all transactions atomically, stores the [`BlockCertificate`], and resets view to `0`.
    pub fn try_finalize_commit(&mut self) -> Result<BlockCertificate, BftError> {
        if !self.online {
            return Err(BftError::ValidatorOffline(self.id));
        }
        let height = self.next_height();
        let view = self.current_view;

        let Some(prepared_tag) = self.round.prepared_tag else {
            return Err(BftError::QuorumNotReached {
                phase: "Commit",
                height,
                view,
                max_votes: 0,
                quorum: self.config.quorum(),
            });
        };

        let voters: Vec<u32> = self
            .round
            .commit_votes
            .get(&prepared_tag)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();

        if voters.len() < self.config.quorum() {
            return Err(BftError::QuorumNotReached {
                phase: "Commit",
                height,
                view,
                max_votes: voters.len(),
                quorum: self.config.quorum(),
            });
        }

        let block = self
            .round
            .proposed_block
            .take()
            .ok_or(BftError::QuorumNotReached {
                phase: "Commit",
                height,
                view,
                max_votes: 0,
                quorum: self.config.quorum(),
            })?;

        if !ct_eq_16(&block.block_tag, &prepared_tag) {
            self.round.proposed_block = Some(block);
            return Err(BftError::ConflictingPrePrepare { height, view });
        }

        if let Err(err) = self.ledger.apply_committed_block(&block) {
            self.round.proposed_block = Some(block);
            return Err(err);
        }

        let cert = BlockCertificate {
            height: block.height,
            view: block.view,
            leader_id: block.leader_id,
            block_tag: block.block_tag,
            prev_tag: block.prev_tag,
            tx_count: block.txs.len() as u32,
            commit_voters: voters,
        };
        self.committed_blocks.insert(block.height, block);
        self.certificates.insert(cert.height, cert.clone());
        self.current_view = 0;
        self.locked_view = None;
        self.locked_block_tag = None;
        self.round.clear();

        Ok(cert)
    }

    /// Broadcast an authenticated `ViewChange` vote for `target_view` (`> self.current_view`)
    /// carrying any locked `(locked_view, locked_block_tag)` to all `online_peers`.
    pub fn start_view_change(
        &mut self,
        target_view: u64,
        online_peers: &[u32],
    ) -> Result<Vec<WireFrame>, BftError> {
        if !self.online {
            return Err(BftError::ValidatorOffline(self.id));
        }
        if target_view <= self.current_view {
            return Err(BftError::InvalidEncoding(
                "ViewChange target_view must be strictly greater than current_view",
            ));
        }
        let my_lock = match (self.locked_view, self.locked_block_tag) {
            (Some(lv), Some(lt)) => Some((lv, lt)),
            _ => None,
        };
        self.round
            .view_change_votes
            .entry(target_view)
            .or_default()
            .insert(self.id, my_lock);

        let vote = ConsensusVote {
            kind: MsgKind::ViewChange,
            voter_id: self.id,
            height: self.next_height(),
            view: target_view,
            block_tag: my_lock.map(|(_, t)| t).unwrap_or(GENESIS_TAG),
            prev_tag: self.ledger.tip_tag,
            tx_count: 0,
            locked_view: my_lock.map(|(v, _)| v),
        };
        self.broadcast_vote(online_peers, &vote)
    }

    /// Ingest an inbound authenticated `ViewChange` vote frame carrying optional locked state.
    pub fn on_view_change_frame(&mut self, frame: &WireFrame) -> Result<(), BftError> {
        if !self.online {
            return Err(BftError::ValidatorOffline(self.id));
        }
        let vote = self.recv_vote_frame(frame.from, frame)?;
        if vote.kind != MsgKind::ViewChange
            || vote.voter_id != frame.from
            || vote.height != self.next_height()
            || vote.view <= self.current_view
            || !ct_eq_16(&vote.prev_tag, &self.ledger.tip_tag)
            || vote.locked_view.is_some_and(|lv| lv >= vote.view)
        {
            return Err(BftError::InvalidEncoding("mismatched ViewChange vote"));
        }
        let lock = vote.locked_view.map(|lv| (lv, vote.block_tag));
        let entry = self.round.view_change_votes.entry(vote.view).or_default();
        if let Some(existing) = entry.get(&vote.voter_id) {
            if *existing != lock {
                return Err(BftError::InvalidEncoding(
                    "equivocating ViewChange lock for same target_view",
                ));
            }
            return Ok(());
        }
        entry.insert(vote.voter_id, lock);
        Ok(())
    }

    /// Advance to `target_view` (`> self.current_view`) if `>= 2f + 1` equal `ViewChange` votes
    /// have been verified, preserving the highest-view lock across the view transition.
    pub fn try_complete_view_change(&mut self, target_view: u64) -> Result<(), BftError> {
        if target_view <= self.current_view {
            return Err(BftError::InvalidEncoding(
                "ViewChange target_view must be strictly greater than current_view",
            ));
        }
        let votes = self.round.view_change_votes.get(&target_view);
        let count = votes.map(BTreeMap::len).unwrap_or(0);
        if count < self.config.quorum() {
            return Err(BftError::QuorumNotReached {
                phase: "ViewChange",
                height: self.next_height(),
                view: target_view,
                max_votes: count,
                quorum: self.config.quorum(),
            });
        }
        // Preserve highest-view lock strictly below target_view reported by the ViewChange quorum.
        // Uses strict `>` so an equal-view claim from another peer cannot overwrite our existing lock.
        if let Some(map) = votes {
            for lock in map.values().flatten() {
                if lock.0 < target_view && self.locked_view.is_none_or(|cur| lock.0 > cur) {
                    self.locked_view = Some(lock.0);
                    self.locked_block_tag = Some(lock.1);
                }
            }
        }
        self.current_view = target_view;
        self.round.clear();
        Ok(())
    }

    /// Discard uncommitted transient round state (e.g., after an aborted equivocation round).
    pub fn abort_round(&mut self) {
        self.round.clear();
    }

    /// Send an authenticated `SyncCert` wire frame attesting this validator's committed
    /// certificate at `height` to a rejoining peer `target_id`.
    pub fn send_sync_cert_frame(
        &mut self,
        target_id: u32,
        height: u64,
    ) -> Result<Option<WireFrame>, BftError> {
        if !self.online {
            return Ok(None);
        }
        let Some(cert) = self.certificates.get(&height) else {
            return Ok(None);
        };
        let vote = ConsensusVote {
            kind: MsgKind::SyncCert,
            voter_id: self.id,
            height: cert.height,
            view: cert.view,
            block_tag: cert.block_tag,
            prev_tag: cert.prev_tag,
            tx_count: cert.tx_count,
            locked_view: None,
        };
        let frame = self.send_vote_frame(target_id, &vote)?;
        Ok(Some(frame))
    }
}

// ============================================================================
// 5. Offline Validator Catch-Up & State Sync
// ============================================================================

/// Catch up a previously offline validator (`target_id`) by collecting and verifying a quorum
/// of `>= 2f + 1` matching authenticated block certificates (`SyncCert`) from peers over
/// pairwise OTP+CW links for every missed height, verifying each block's single-use
/// Carter-Wegman seal with `target_id`'s own local key deck, and replaying the ledger cleanly.
///
/// Returns the number of missed blocks synced.
pub fn sync_validator_from_quorum(
    target_id: u32,
    validators: &mut [BftValidator],
) -> Result<usize, BftError> {
    let idx = target_id as usize;
    if idx >= validators.len() {
        return Err(BftError::UnknownValidator(target_id));
    }

    let config = validators[idx].config;
    let quorum = config.quorum();

    // Bring validator back online and clear any stale round state.
    validators[idx].online = true;
    validators[idx].current_view = 0;
    validators[idx].locked_view = None;
    validators[idx].locked_block_tag = None;
    validators[idx].round.clear();

    let max_peer_height = validators
        .iter()
        .filter(|v| v.id != target_id && v.online)
        .map(|v| v.ledger.height)
        .max()
        .unwrap_or(0);

    let mut synced = 0usize;

    while validators[idx].ledger.height < max_peer_height {
        let h = validators[idx]
            .ledger
            .height
            .checked_add(1)
            .ok_or(BftError::ChainLinkMismatch {
                expected_height: u64::MAX,
                got_height: max_peer_height,
            })?;

        // Step 1: Every online peer holding height `h` sends an OTP+CW authenticated SyncCert frame.
        let mut outbound_frames: Vec<WireFrame> = Vec::new();
        for peer in validators.iter_mut() {
            if peer.id == target_id || !peer.online {
                continue;
            }
            if let Some(frame) = peer.send_sync_cert_frame(target_id, h)? {
                outbound_frames.push(frame);
            }
        }

        // Step 2: Target decrypts & verifies every SyncCert frame over its pairwise inbound decks
        // and tallies distinct equal-weight peer attestations.
        type CertKey = (u64, [u8; 16], [u8; 16], u32);
        let mut tally: BTreeMap<CertKey, BTreeSet<u32>> = BTreeMap::new();

        for frame in &outbound_frames {
            let vote = match validators[idx].recv_vote_frame(frame.from, frame) {
                Ok(v) => v,
                Err(_) => continue, // Ignore tampered/invalid frames from Byzantine peers.
            };
            if vote.kind != MsgKind::SyncCert
                || vote.voter_id != frame.from
                || vote.height != h
                || !ct_eq_16(&vote.prev_tag, &validators[idx].ledger.tip_tag)
            {
                continue;
            }
            let key: CertKey = (vote.view, vote.block_tag, vote.prev_tag, vote.tx_count);
            tally.entry(key).or_default().insert(vote.voter_id);
        }

        // Step 3: Require >= 2f + 1 matching authenticated peer certificates.
        let best = tally
            .into_iter()
            .max_by_key(|(_, voters)| voters.len());

        let Some(((cert_view, cert_tag, cert_prev, cert_tx_count), attesting_peers)) = best else {
            return Err(BftError::QuorumNotReached {
                phase: "SyncCert",
                height: h,
                view: 0,
                max_votes: 0,
                quorum,
            });
        };

        if attesting_peers.len() < quorum {
            return Err(BftError::QuorumNotReached {
                phase: "SyncCert",
                height: h,
                view: cert_view,
                max_votes: attesting_peers.len(),
                quorum,
            });
        }

        // Step 4: Require at least `f + 1` matching candidate block bodies (identical height, view,
        // leader, tags, AND full tx payload) from attesting peers BEFORE consuming target's
        // single-use Carter-Wegman seal key, so a single Byzantine peer cannot burn it on a fake body!
        let required_body_matches = config.max_faults() + 1;
        let mut body_tallies: Vec<(TxBatchBlock, usize)> = Vec::new();
        for &peer_id in &attesting_peers {
            let Some(b) = validators[peer_id as usize].committed_blocks.get(&h) else {
                continue;
            };
            if b.height == h
                && b.view == cert_view
                && b.txs.len() as u32 == cert_tx_count
                && ct_eq_16(&b.block_tag, &cert_tag)
                && ct_eq_16(&b.prev_tag, &cert_prev)
            {
                if let Some((_, count)) = body_tallies.iter_mut().find(|(cand, _)| cand == b) {
                    *count += 1;
                } else {
                    body_tallies.push((b.clone(), 1));
                }
            }
        }

        let candidate_block = body_tallies
            .into_iter()
            .find(|(_, count)| *count >= required_body_matches)
            .map(|(block, _)| block);

        let Some(block) = candidate_block else {
            return Err(BftError::SyncBlockUnavailable { height: h });
        };

        let seal_key = validators[idx].seal_deck.take_key(h, cert_view)?;
        if !block.verify_seal(seal_key) {
            return Err(BftError::InvalidBlockSeal {
                height: h,
                view: cert_view,
            });
        }

        // Step 5: Atomically apply the verified block and store the quorum certificate.
        validators[idx].ledger.apply_committed_block(&block)?;
        let cert = BlockCertificate {
            height: block.height,
            view: block.view,
            leader_id: block.leader_id,
            block_tag: block.block_tag,
            prev_tag: block.prev_tag,
            tx_count: block.txs.len() as u32,
            commit_voters: attesting_peers.into_iter().collect(),
        };
        validators[idx].committed_blocks.insert(h, block);
        validators[idx].certificates.insert(h, cert);
        synced += 1;
    }

    Ok(synced)
}

// ============================================================================
// 6. BFT Cluster Orchestrator (In-Process Multi-Validator Network)
// ============================================================================

/// Multi-validator Vernam BFT cluster executing full 2-phase consensus (`PrePrepare -> Prepare -> Commit`),
/// automatic leader rotation / view changes, and offline validator catch-up.
pub struct BftCluster {
    pub config: BftConfig,
    pub validators: Vec<BftValidator>,
}

impl BftCluster {
    /// Provision an `N = 3f + 1` BFT cluster with full pairwise OTP+CW peer link decks
    /// and dedicated single-use Carter-Wegman block sealing decks.
    pub fn new(
        config: BftConfig,
        initial_balances: BTreeMap<u32, u64>,
        slots_per_link: usize,
        max_heights: u64,
        max_views: u64,
    ) -> Self {
        let n = config.num_validators;
        let mut seal_decks = BlockSealDeck::create_committee_decks(n, max_heights, max_views);

        let mut outbound_all: Vec<BTreeMap<u32, OtpLinkDeck>> =
            (0..n).map(|_| BTreeMap::new()).collect();
        let mut inbound_all: Vec<BTreeMap<u32, OtpLinkDeck>> =
            (0..n).map(|_| BTreeMap::new()).collect();

        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let (out_ij, in_ji) = OtpLinkDeck::create_pair(slots_per_link);
                outbound_all[i].insert(j as u32, out_ij);
                inbound_all[j].insert(i as u32, in_ji);
            }
        }

        let mut validators = Vec::with_capacity(n);
        for i in (0..n).rev() {
            let seal_deck = seal_decks.pop().unwrap();
            let outbound_links = outbound_all.pop().unwrap();
            let inbound_links = inbound_all.pop().unwrap();
            validators.push(BftValidator {
                id: i as u32,
                config,
                online: true,
                current_view: 0,
                locked_view: None,
                locked_block_tag: None,
                ledger: LedgerState::new(initial_balances.clone()),
                committed_blocks: BTreeMap::new(),
                certificates: BTreeMap::new(),
                outbound_links,
                inbound_links,
                seal_deck,
                round: RoundState::default(),
            });
        }
        validators.reverse();

        Self { config, validators }
    }

    /// Return the IDs of all currently online validators.
    pub fn online_ids(&self) -> Vec<u32> {
        self.validators
            .iter()
            .filter(|v| v.online)
            .map(|v| v.id)
            .collect()
    }

    /// Set a validator online or offline.
    pub fn set_online(&mut self, validator_id: u32, online: bool) -> Result<(), BftError> {
        let v = self
            .validators
            .get_mut(validator_id as usize)
            .ok_or(BftError::UnknownValidator(validator_id))?;
        v.online = online;
        Ok(())
    }

    /// Execute an authenticated `ViewChange` across all online validators, rotating to
    /// `target_view` once `>= 2f + 1` equal `ViewChange` wire frames are verified.
    pub fn execute_view_change(&mut self, target_view: u64) -> Result<(), BftError> {
        let online = self.online_ids();
        if online.is_empty() || online.len() < self.config.quorum() {
            let height = online
                .first()
                .map(|&id| self.validators[id as usize].next_height())
                .unwrap_or(0);
            return Err(BftError::QuorumNotReached {
                phase: "ViewChange",
                height,
                view: target_view,
                max_votes: online.len(),
                quorum: self.config.quorum(),
            });
        }

        let mut vc_frames = Vec::new();
        for &id in &online {
            let frames = self.validators[id as usize].start_view_change(target_view, &online)?;
            vc_frames.extend(frames);
        }
        for frame in &vc_frames {
            let Some(v) = self.validators.get_mut(frame.to as usize) else {
                return Err(BftError::UnknownValidator(frame.to));
            };
            match v.on_view_change_frame(frame) {
                Ok(()) | Err(BftError::InvalidMac | BftError::InvalidEncoding(_)) => {}
                Err(e) => return Err(e),
            }
        }
        for &id in &online {
            self.validators[id as usize].try_complete_view_change(target_view)?;
        }
        Ok(())
    }

    /// Run a complete 2-phase BFT round (`PrePrepare -> Prepare -> Commit`) for a batch of
    /// [`BinaryTx`] transactions across all online validators.
    ///
    /// If the scheduled leader `leader = (height + view) % N` is offline, automatically runs
    /// authenticated `ViewChange` rounds to rotate to the next online leader!
    pub fn propose_and_finalize_batch(
        &mut self,
        txs: Vec<BinaryTx>,
    ) -> Result<BlockCertificate, BftError> {
        let online = self.online_ids();
        if online.len() < self.config.quorum() {
            return Err(BftError::QuorumNotReached {
                phase: "PrePrepare",
                height: 0,
                view: 0,
                max_votes: online.len(),
                quorum: self.config.quorum(),
            });
        }

        let height = self.validators[online[0] as usize].next_height();

        // Automatically rotate past any offline leaders via authenticated ViewChange.
        let leader_id = loop {
            let view = self.validators[online[0] as usize].current_view;
            let candidate = self.config.leader_for(height, view);
            if self.validators[candidate as usize].online {
                break candidate;
            }
            let next_view = view
                .checked_add(1)
                .ok_or(BftError::InvalidEncoding("view number overflow"))?;
            self.execute_view_change(next_view)?;
        };

        // Phase 0: Leader PrePrepare + Leader Prepare
        let (block, pre_prepare_frames, mut prepare_frames) =
            self.validators[leader_id as usize].leader_propose(txs, &online)?;

        // Followers process PrePrepare and emit pairwise Prepare frames
        for frame in &pre_prepare_frames {
            let Some(v) = self.validators.get_mut(frame.to as usize) else {
                return Err(BftError::UnknownValidator(frame.to));
            };
            let follower_prepares = v.on_pre_prepare(frame, block.clone(), &online)?;
            prepare_frames.extend(follower_prepares);
        }

        // Phase 1: Deliver all Prepare frames over pairwise OTP+CW links (ignore individual
        // Byzantine InvalidMac/InvalidEncoding frames; fail only if quorum < 2f + 1).
        for frame in &prepare_frames {
            let Some(v) = self.validators.get_mut(frame.to as usize) else {
                return Err(BftError::UnknownValidator(frame.to));
            };
            match v.on_prepare_frame(frame) {
                Ok(()) | Err(BftError::InvalidMac | BftError::InvalidEncoding(_)) => {}
                Err(e) => return Err(e),
            }
        }

        // Validators reaching 2f + 1 Prepares emit pairwise Commit frames
        let mut commit_frames = Vec::new();
        for &id in &online {
            let frames = self.validators[id as usize].try_enter_commit(&online)?;
            commit_frames.extend(frames);
        }

        // Phase 2: Deliver all Commit frames over pairwise OTP+CW links (tolerate Byzantine frames).
        for frame in &commit_frames {
            let Some(v) = self.validators.get_mut(frame.to as usize) else {
                return Err(BftError::UnknownValidator(frame.to));
            };
            match v.on_commit_frame(frame) {
                Ok(()) | Err(BftError::InvalidMac | BftError::InvalidEncoding(_)) => {}
                Err(e) => return Err(e),
            }
        }

        // Finalize commit on every online validator
        let mut last_cert = None;
        for &id in &online {
            let cert = self.validators[id as usize].try_finalize_commit()?;
            last_cert = Some(cert);
        }

        Ok(last_cert.expect("quorum >= 3 implies at least one online validator"))
    }

    /// Catch up an offline validator using [`sync_validator_from_quorum`].
    pub fn sync_validator_from_quorum(&mut self, target_id: u32) -> Result<usize, BftError> {
        sync_validator_from_quorum(target_id, &mut self.validators)
    }

    /// Simulate a Byzantine leader equivocation attack where the current leader sends conflicting
    /// sealed batches (`batch_a` to `group_a`, `batch_b` to `group_b`) at the same `(height, view)`.
    ///
    /// Executes the real follower `on_pre_prepare`, `Prepare`, and `Commit` state machine across
    /// all pairwise OTP+CW links. Returns `Err(BftError::QuorumNotReached)` whenever neither batch
    /// can reach `2f + 1` votes, leaving all honest validators' ledgers untouched.
    #[cfg(test)]
    pub fn simulate_byzantine_equivocation(
        &mut self,
        batch_a: Vec<BinaryTx>,
        group_a: &[u32],
        batch_b: Vec<BinaryTx>,
        group_b: &[u32],
    ) -> Result<BlockCertificate, BftError> {
        let online = self.online_ids();
        let height = self.validators[online[0] as usize].next_height();
        let view = self.validators[online[0] as usize].current_view;
        let leader_id = self.config.leader_for(height, view);
        let tip_tag = self.validators[leader_id as usize].ledger.tip_tag;

        // Byzantine leader violates single-use key discipline to seal two conflicting batches.
        let key_a = self.validators[leader_id as usize]
            .seal_deck
            .byzantine_duplicate_key(height, view)?;
        let key_b = self.validators[leader_id as usize]
            .seal_deck
            .take_key(height, view)?;

        let block_a = TxBatchBlock::seal_with_limit(
            height,
            view,
            leader_id,
            tip_tag,
            batch_a,
            key_a,
            self.config.max_batch_txs,
        )?;
        let block_b = TxBatchBlock::seal_with_limit(
            height,
            view,
            leader_id,
            tip_tag,
            batch_b,
            key_b,
            self.config.max_batch_txs,
        )?;

        let mut prepare_frames = Vec::new();

        // Byzantine leader records its own Prepare for A (if in group_a) or B (if in group_b)
        // and sends conflicting PrePrepares + Prepares to the two partitions.
        if group_a.contains(&leader_id) {
            self.validators[leader_id as usize].round.proposed_block = Some(block_a.clone());
            self.validators[leader_id as usize]
                .round
                .prepare_votes
                .entry(block_a.block_tag)
                .or_default()
                .insert(leader_id);
        }

        for &target in group_a {
            if target == leader_id {
                continue;
            }
            let pp_vote = ConsensusVote {
                kind: MsgKind::PrePrepare,
                voter_id: leader_id,
                height,
                view,
                block_tag: block_a.block_tag,
                prev_tag: block_a.prev_tag,
                tx_count: block_a.txs.len() as u32,
                locked_view: None,
            };
            let pp_frame = self.validators[leader_id as usize].send_vote_frame(target, &pp_vote)?;
            let leader_prep = self.validators[leader_id as usize].send_vote_frame(
                target,
                &ConsensusVote {
                    kind: MsgKind::Prepare,
                    ..pp_vote
                },
            )?;
            prepare_frames.push(leader_prep);

            let follower_preps = self.validators[target as usize]
                .on_pre_prepare(&pp_frame, block_a.clone(), &online)?;
            prepare_frames.extend(follower_preps);
        }

        for &target in group_b {
            if target == leader_id {
                continue;
            }
            let pp_vote = ConsensusVote {
                kind: MsgKind::PrePrepare,
                voter_id: leader_id,
                height,
                view,
                block_tag: block_b.block_tag,
                prev_tag: block_b.prev_tag,
                tx_count: block_b.txs.len() as u32,
                locked_view: None,
            };
            let pp_frame = self.validators[leader_id as usize].send_vote_frame(target, &pp_vote)?;
            let leader_prep = self.validators[leader_id as usize].send_vote_frame(
                target,
                &ConsensusVote {
                    kind: MsgKind::Prepare,
                    ..pp_vote
                },
            )?;
            prepare_frames.push(leader_prep);

            let follower_preps = self.validators[target as usize]
                .on_pre_prepare(&pp_frame, block_b.clone(), &online)?;
            prepare_frames.extend(follower_preps);
        }

        // Deliver all Prepare frames across all online validators.
        for frame in &prepare_frames {
            let _ = self.validators[frame.to as usize].on_prepare_frame(frame);
        }

        // Attempt to enter Commit on every online validator.
        let mut commit_frames = Vec::new();
        let mut last_err = None;
        for &id in &online {
            match self.validators[id as usize].try_enter_commit(&online) {
                Ok(frames) => commit_frames.extend(frames),
                Err(e) => last_err = Some(e),
            }
        }

        for frame in &commit_frames {
            let _ = self.validators[frame.to as usize].on_commit_frame(frame);
        }

        let mut committed = None;
        for &id in &online {
            match self.validators[id as usize].try_finalize_commit() {
                Ok(cert) => committed = Some(cert),
                Err(e) => last_err = Some(e),
            }
        }

        match committed {
            Some(cert) => Ok(cert),
            None => {
                for &id in &online {
                    self.validators[id as usize].abort_round();
                }
                Err(last_err.unwrap_or(BftError::QuorumNotReached {
                    phase: "Prepare",
                    height,
                    view,
                    max_votes: 0,
                    quorum: self.config.quorum(),
                }))
            }
        }
    }
}

// ============================================================================
// 7. Proof-of-Personhood Web-of-Trust Validator Registry (1-Human = 1-Vote)
// ============================================================================

/// Carter-Wegman authenticated mutual in-person vouch between an existing verified human
/// (`sponsor_id`) and a candidate human (`candidate_id`). Zero biometrics, zero stake weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InPersonVouch {
    pub sponsor_id: u32,
    pub candidate_id: u32,
    pub meeting_epoch: u64,
    pub vouch_tag: [u8; 16],
}

impl InPersonVouch {
    fn encode_message(sponsor_id: u32, candidate_id: u32, meeting_epoch: u64) -> [u8; 16] {
        let mut msg = [0u8; 16];
        msg[0..4].copy_from_slice(&sponsor_id.to_le_bytes());
        msg[4..8].copy_from_slice(&candidate_id.to_le_bytes());
        msg[8..16].copy_from_slice(&meeting_epoch.to_le_bytes());
        msg
    }

    /// Create an authenticated in-person vouch by consuming a shared single-use [`CwKey`].
    pub fn create(
        sponsor_id: u32,
        candidate_id: u32,
        meeting_epoch: u64,
        key: CwKey,
    ) -> Self {
        let msg = Self::encode_message(sponsor_id, candidate_id, meeting_epoch);
        let vouch_tag = key.mac_consume(&msg);
        Self {
            sponsor_id,
            candidate_id,
            meeting_epoch,
            vouch_tag,
        }
    }
}

/// Outcome of submitting an [`InPersonVouch`] to [`WebOfTrustRegistry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VouchStatus {
    /// Vouch recorded, but candidate still needs additional distinct verified-human vouches.
    Pending {
        current_vouches: usize,
        required: usize,
    },
    /// Candidate reached quorum and is now an admitted verified human (voting weight = 1).
    Admitted { total_vouches: usize },
}

/// Unweighted 1-human-1-vote Proof-of-Personhood Web-of-Trust validator registry.
///
/// A candidate joins ONLY after collecting at least `admission_quorum` distinct Carter-Wegman
/// authenticated in-person mutual vouches from existing verified humans.
/// Zero iris biometrics, zero capital/stake weighting.
pub struct WebOfTrustRegistry {
    admission_quorum: usize,
    verified_humans: BTreeSet<u32>,
    pending_vouches: BTreeMap<u32, BTreeSet<u32>>,
    vouch_keys: BTreeMap<(u32, u32), CwKey>,
}

impl WebOfTrustRegistry {
    /// Initialize the registry with a set of genesis verified humans and required admission quorum.
    pub fn new(genesis_humans: &[u32], admission_quorum: usize) -> Result<Self, BftError> {
        let verified_humans: BTreeSet<u32> = genesis_humans.iter().copied().collect();
        if admission_quorum == 0 || verified_humans.len() < admission_quorum {
            return Err(BftError::InvalidVouch(
                "admission quorum must be >= 1 and <= genesis human count",
            ));
        }
        Ok(Self {
            admission_quorum,
            verified_humans,
            pending_vouches: BTreeMap::new(),
            vouch_keys: BTreeMap::new(),
        })
    }

    /// Initialize a Web-of-Trust registry matching a [`BftConfig`] (`0..N`, quorum = `2f + 1`).
    pub fn for_bft_config(config: &BftConfig) -> Self {
        let genesis: Vec<u32> = (0..config.num_validators as u32).collect();
        Self::new(&genesis, config.quorum()).expect("valid BftConfig always satisfies quorum <= N")
    }

    /// Required number of distinct verified-human vouches to admit a new validator.
    #[inline]
    pub fn admission_quorum(&self) -> usize {
        self.admission_quorum
    }

    /// True if `human_id` is a verified human in the registry.
    #[inline]
    pub fn is_verified(&self, human_id: u32) -> bool {
        self.verified_humans.contains(&human_id)
    }

    /// Total number of verified humans.
    #[inline]
    pub fn verified_count(&self) -> usize {
        self.verified_humans.len()
    }

    /// Flat, anti-plutocratic voting weight: `1` for every verified human, `0` for everyone else.
    #[inline]
    pub fn voting_weight(&self, human_id: u32) -> u64 {
        if self.is_verified(human_id) { 1 } else { 0 }
    }

    /// Number of verified-human vouches currently accumulated for `candidate_id`.
    pub fn vouch_count(&self, candidate_id: u32) -> usize {
        self.pending_vouches
            .get(&candidate_id)
            .map(BTreeSet::len)
            .unwrap_or(0)
    }

    /// Provision a single-use Carter-Wegman key for an in-person meeting between verified human
    /// `sponsor_id` and unverified `candidate_id`.
    pub fn provision_vouch_key(
        &mut self,
        sponsor_id: u32,
        candidate_id: u32,
    ) -> Result<CwKey, BftError> {
        if !self.is_verified(sponsor_id) {
            return Err(BftError::UnauthorizedSponsor(sponsor_id));
        }
        if sponsor_id == candidate_id {
            return Err(BftError::InvalidVouch("self-vouch forbidden"));
        }
        if self.is_verified(candidate_id) {
            return Err(BftError::InvalidVouch("candidate already verified"));
        }
        if self
            .pending_vouches
            .get(&candidate_id)
            .is_some_and(|s| s.contains(&sponsor_id))
        {
            return Err(BftError::InvalidVouch("sponsor already vouched for candidate"));
        }

        let reg_key = CwKey::generate();
        let peer_key = reg_key.duplicate_for_preshare();
        self.vouch_keys.insert((sponsor_id, candidate_id), reg_key);
        Ok(peer_key)
    }

    /// Verify and record an [`InPersonVouch`], admitting `candidate_id` automatically once
    /// `>= admission_quorum` distinct verified humans have vouched.
    pub fn submit_vouch(&mut self, vouch: InPersonVouch) -> Result<VouchStatus, BftError> {
        if !self.is_verified(vouch.sponsor_id) {
            return Err(BftError::UnauthorizedSponsor(vouch.sponsor_id));
        }
        if vouch.sponsor_id == vouch.candidate_id {
            return Err(BftError::InvalidVouch("self-vouch forbidden"));
        }
        if self.is_verified(vouch.candidate_id) {
            return Err(BftError::InvalidVouch("candidate already verified"));
        }

        let key = self
            .vouch_keys
            .remove(&(vouch.sponsor_id, vouch.candidate_id))
            .ok_or(BftError::InvalidVouch("missing or already spent vouch key"))?;

        let msg = InPersonVouch::encode_message(
            vouch.sponsor_id,
            vouch.candidate_id,
            vouch.meeting_epoch,
        );
        if !key.verify_consume(&msg, &vouch.vouch_tag) {
            return Err(BftError::InvalidMac);
        }

        let sponsors = self.pending_vouches.entry(vouch.candidate_id).or_default();
        if !sponsors.insert(vouch.sponsor_id) {
            return Err(BftError::InvalidVouch("duplicate sponsor vouch"));
        }
        let count = sponsors.len();

        if count >= self.admission_quorum {
            self.pending_vouches.remove(&vouch.candidate_id);
            self.verified_humans.insert(vouch.candidate_id);
            Ok(VouchStatus::Admitted {
                total_vouches: count,
            })
        } else {
            Ok(VouchStatus::Pending {
                current_vouches: count,
                required: self.admission_quorum,
            })
        }
    }

    /// Convenience helper performing an authenticated in-person mutual vouch in one step.
    pub fn vouch_in_person(
        &mut self,
        sponsor_id: u32,
        candidate_id: u32,
        meeting_epoch: u64,
    ) -> Result<VouchStatus, BftError> {
        let key = self.provision_vouch_key(sponsor_id, candidate_id)?;
        let vouch = InPersonVouch::create(sponsor_id, candidate_id, meeting_epoch, key);
        self.submit_vouch(vouch)
    }

    /// Explicitly check whether `candidate_id` qualifies as an admitted validator.
    /// Rejects unvouched Sybils with [`BftError::InsufficientVouches`].
    pub fn require_admitted(&self, candidate_id: u32) -> Result<(), BftError> {
        if self.is_verified(candidate_id) {
            return Ok(());
        }
        Err(BftError::InsufficientVouches {
            candidate_id,
            have: self.vouch_count(candidate_id),
            need: self.admission_quorum,
        })
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn initial_test_balances() -> BTreeMap<u32, u64> {
        let mut balances = BTreeMap::new();
        for acct in 0..16u32 {
            balances.insert(acct, 1_000_000);
        }
        balances
    }

    #[test]
    fn test_binary_tx_roundtrip_and_cw_streaming_equivalence() {
        let tx = BinaryTx::new(7, 42, 123_456_789_012, 999, 55);
        let bytes = tx.to_bytes();
        assert_eq!(bytes.len(), BINARY_TX_SIZE);
        assert_eq!(BinaryTx::from_bytes(&bytes), tx);

        // Verify streaming CwHasher matches single-buffer cw_mac identically.
        let key1 = CwKey::generate();
        let key2 = key1.duplicate_for_preshare();
        let prev = [0xABu8; 16];
        let height = 17u64;
        let txs = vec![
            BinaryTx::new(1, 2, 100, 1, 1),
            BinaryTx::new(2, 3, 50, 2, 1),
            BinaryTx::new(3, 4, 25, 3, 1),
        ];

        let stream_tag = TxBatchBlock::compute_chain_tag(&prev, height, &txs, key1);

        let mut flat = Vec::new();
        flat.extend_from_slice(&prev);
        flat.extend_from_slice(&height.to_le_bytes());
        for t in &txs {
            flat.extend_from_slice(&t.to_bytes());
        }
        let flat_tag = key2.mac_consume(&flat);
        assert!(ct_eq_16(&stream_tag, &flat_tag));

        // Verify block binary roundtrip.
        let key3 = CwKey::generate();
        let key3_v = key3.duplicate_for_preshare();
        let block = TxBatchBlock::seal(height, 0, 1, prev, txs, key3).unwrap();
        let encoded = block.to_bytes();
        let decoded = TxBatchBlock::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, block);
        assert!(decoded.verify_seal(key3_v));
    }

    #[test]
    fn test_pairwise_wire_frame_fixed_size_and_replay_rejection() {
        let (mut out_deck, mut in_deck) = OtpLinkDeck::create_pair(4);
        let vote = ConsensusVote {
            kind: MsgKind::Prepare,
            voter_id: 1,
            height: 5,
            view: 0,
            block_tag: [0x11u8; 16],
            prev_tag: [0x22u8; 16],
            tx_count: 500,
            locked_view: None,
        };
        let payload = vote.to_payload();
        let frame = out_deck.seal_frame(1, 2, &payload).unwrap();

        let wire_bytes = frame.to_bytes();
        assert_eq!(wire_bytes.len(), WIRE_FRAME_LEN);
        let parsed = WireFrame::from_bytes(&wire_bytes);
        assert_eq!(parsed, frame);

        // First open succeeds.
        let decrypted = in_deck.open_frame(&parsed, 1, 2).unwrap();
        assert_eq!(ConsensusVote::from_payload(&decrypted).unwrap(), vote);

        // Replay of the exact same frame is strictly rejected (slot consumed & zeroized).
        assert!(matches!(
            in_deck.open_frame(&parsed, 1, 2),
            Err(BftError::ReplayOrMissingKeySlot { .. })
        ));

        // Tampered ciphertext fails constant-time Carter-Wegman MAC and burns the slot.
        let mut tampered = out_deck.seal_frame(1, 2, &payload).unwrap();
        tampered.ciphertext[0] ^= 0x01;
        assert_eq!(
            in_deck.open_frame(&tampered, 1, 2),
            Err(BftError::InvalidMac)
        );
        assert_eq!(in_deck.remaining(), 2);
    }

    #[test]
    fn test_batched_bft_commits_500_txs_in_one_block_across_4_validators() {
        let config = BftConfig::default(); // N=4, f=1, quorum=3
        assert_eq!(config.num_validators, 4);
        assert_eq!(config.max_faults(), 1);
        assert_eq!(config.quorum(), 3);

        let mut cluster = BftCluster::new(config, initial_test_balances(), 64, 16, 4);

        // Build 500 compact binary transactions in a single batch.
        let mut batch = Vec::with_capacity(500);
        for i in 0..500u64 {
            let sender = (i % 8) as u32; // accounts 0..8
            let recipient = 8 + (i % 8) as u32; // accounts 8..16
            let amount = 10 + (i % 5);
            batch.push(BinaryTx::new(sender, recipient, amount, i + 1, i + 1));
        }
        let total_moved: u64 = batch.iter().map(|tx| tx.amount).sum();

        let cert = cluster.propose_and_finalize_batch(batch).unwrap();
        assert_eq!(cert.height, 1);
        assert_eq!(cert.view, 0);
        assert_eq!(cert.leader_id, 1); // leader = height % 4 = 1
        assert_eq!(cert.tx_count, 500);
        assert_eq!(cert.commit_voters.len(), 4);

        // All 4 validators have identical tip tag, height, and balances.
        let ref_ledger = &cluster.validators[0].ledger;
        assert_eq!(ref_ledger.height, 1);
        assert!(ct_eq_16(&ref_ledger.tip_tag, &cert.block_tag));

        let senders_sum: u64 = (0..8u32).map(|a| ref_ledger.balance_of(a)).sum();
        let recips_sum: u64 = (8..16u32).map(|a| ref_ledger.balance_of(a)).sum();
        assert_eq!(senders_sum, 8 * 1_000_000 - total_moved);
        assert_eq!(recips_sum, 8 * 1_000_000 + total_moved);

        for v in &cluster.validators[1..] {
            assert_eq!(v.ledger, *ref_ledger);
            assert_eq!(v.committed_blocks.get(&1).unwrap().txs.len(), 500);
        }
    }

    #[test]
    fn test_byzantine_leader_equivocation_rejected_zero_coins_moved() {
        let config = BftConfig::default(); // N=4, f=1, quorum=3
        let initial = initial_test_balances();
        let mut cluster = BftCluster::new(config, initial.clone(), 64, 16, 4);

        // At height 1, view 0, leader is 1 % 4 = 1.
        // Byzantine leader V1 sends conflicting Batch A to {V0, V1} and Batch B to {V2, V3}.
        let batch_a = vec![BinaryTx::new(0, 1, 50_000, 1, 1)];
        let batch_b = vec![BinaryTx::new(0, 2, 50_000, 1, 1)];

        let res = cluster.simulate_byzantine_equivocation(batch_a, &[0, 1], batch_b, &[2, 3]);
        assert!(
            matches!(res, Err(BftError::QuorumNotReached { .. })),
            "equivocation must fail to reach 2f+1 quorum, got: {res:?}"
        );

        // Zero coins moved and height remains 0 across all 4 validators!
        for v in &cluster.validators {
            assert_eq!(v.ledger.height, 0);
            assert_eq!(v.ledger.tip_tag, GENESIS_TAG);
            assert_eq!(v.ledger.balances, initial);
            assert!(v.committed_blocks.is_empty());
        }

        // Honest validators perform authenticated ViewChange (view 0 -> view 1, rotating leader
        // from Byzantine V1 to honest V2 = (1 + 1) % 4) and finalize cleanly!
        cluster.execute_view_change(1).unwrap();
        let honest_batch = vec![BinaryTx::new(0, 3, 25_000, 10, 10)];
        let cert = cluster.propose_and_finalize_batch(honest_batch).unwrap();
        assert_eq!(cert.height, 1);
        assert_eq!(cert.view, 1);
        assert_eq!(cert.leader_id, 2);
        for v in &cluster.validators {
            assert_eq!(v.ledger.balance_of(0), 975_000);
            assert_eq!(v.ledger.balance_of(3), 1_025_000);
        }
    }

    #[test]
    fn test_offline_validator_misses_3_blocks_and_catches_up_via_quorum_sync() {
        let config = BftConfig::default(); // N=4, f=1, quorum=3
        let mut cluster = BftCluster::new(config, initial_test_balances(), 128, 16, 4);

        // Take V3 offline before heights 1, 2, 3.
        // Note: At height 3, view 0, scheduled leader is 3 % 4 = V3 (offline!), so V0..V2
        // must also automatically perform a ViewChange to leader V0 = (3 + 1) % 4!
        cluster.set_online(3, false).unwrap();

        let b1 = vec![
            BinaryTx::new(0, 1, 1_000, 1, 1),
            BinaryTx::new(2, 3, 2_500, 1, 1),
        ];
        let c1 = cluster.propose_and_finalize_batch(b1).unwrap();
        assert_eq!(c1.height, 1);
        assert_eq!(c1.view, 0);
        assert_eq!(c1.commit_voters, vec![0, 1, 2]);

        let b2 = vec![
            BinaryTx::new(1, 4, 3_000, 2, 2),
            BinaryTx::new(5, 6, 4_000, 2, 2),
        ];
        let c2 = cluster.propose_and_finalize_batch(b2).unwrap();
        assert_eq!(c2.height, 2);
        assert_eq!(c2.view, 0);
        assert_eq!(c2.commit_voters, vec![0, 1, 2]);

        let b3 = vec![BinaryTx::new(4, 7, 500, 3, 3)];
        let c3 = cluster.propose_and_finalize_batch(b3).unwrap();
        assert_eq!(c3.height, 3);
        assert_eq!(c3.view, 1); // Rotated automatically past offline leader V3!
        assert_eq!(c3.leader_id, 0);
        assert_eq!(c3.commit_voters, vec![0, 1, 2]);

        // V3 is still stuck at height 0 while V0..V2 are at height 3.
        assert_eq!(cluster.validators[3].ledger.height, 0);
        assert_eq!(cluster.validators[0].ledger.height, 3);

        // V3 rejoins and catches up cleanly via >= 2f+1 authenticated SyncCert frames over OTP links.
        let synced = cluster.sync_validator_from_quorum(3).unwrap();
        assert_eq!(synced, 3);
        assert!(cluster.validators[3].online);
        assert_eq!(cluster.validators[3].ledger, cluster.validators[0].ledger);
        assert_eq!(cluster.validators[3].ledger.height, 3);
        assert_eq!(cluster.validators[3].ledger.balance_of(0), 999_000);
        assert_eq!(cluster.validators[3].ledger.balance_of(1), 998_000);
        assert_eq!(cluster.validators[3].ledger.balance_of(4), 1_002_500);
        assert_eq!(cluster.validators[3].ledger.balance_of(7), 1_000_500);

        // V3 can immediately participate in block 4 as a full equal validator!
        let b4 = vec![BinaryTx::new(7, 0, 500, 4, 4)];
        let c4 = cluster.propose_and_finalize_batch(b4).unwrap();
        assert_eq!(c4.height, 4);
        assert_eq!(c4.commit_voters, vec![0, 1, 2, 3]);
        assert_eq!(cluster.validators[3].ledger, cluster.validators[0].ledger);
    }

    #[test]
    fn test_configurable_7_validator_bft_cluster() {
        let config = BftConfig::for_faults(2).unwrap(); // N=7, f=2, quorum=5
        assert_eq!(config.num_validators, 7);
        assert_eq!(config.quorum(), 5);

        let mut cluster = BftCluster::new(config, initial_test_balances(), 64, 8, 4);
        // Take 2 validators offline (maximum tolerated f=2).
        cluster.set_online(5, false).unwrap();
        cluster.set_online(6, false).unwrap();

        let txs = vec![BinaryTx::new(0, 1, 7_777, 1, 1)];
        let cert = cluster.propose_and_finalize_batch(txs).unwrap();
        assert_eq!(cert.height, 1);
        assert_eq!(cert.commit_voters.len(), 5);

        // Both offline validators catch up cleanly from the 5-validator quorum.
        assert_eq!(cluster.sync_validator_from_quorum(5).unwrap(), 1);
        assert_eq!(cluster.sync_validator_from_quorum(6).unwrap(), 1);
        for v in &cluster.validators {
            assert_eq!(v.ledger.balance_of(1), 1_007_777);
        }
    }

    #[test]
    fn test_web_of_trust_quorum_admission_and_sybil_rejection() {
        let config = BftConfig::default(); // N=4, quorum=3
        let mut wot = WebOfTrustRegistry::for_bft_config(&config);

        // Genesis validators 0..4 are verified with flat 1-human-1-vote weight.
        for id in 0..4u32 {
            assert!(wot.is_verified(id));
            assert_eq!(wot.voting_weight(id), 1);
        }

        // Unvouched Sybil (id=99) is rejected and has zero voting weight.
        let sybil = 99u32;
        assert!(!wot.is_verified(sybil));
        assert_eq!(wot.voting_weight(sybil), 0);
        assert_eq!(
            wot.require_admitted(sybil),
            Err(BftError::InsufficientVouches {
                candidate_id: sybil,
                have: 0,
                need: 3,
            })
        );

        // Sybil cannot vouch for another Sybil (id=100).
        assert_eq!(
            wot.vouch_in_person(sybil, 100, 1),
            Err(BftError::UnauthorizedSponsor(sybil))
        );

        // Honest new human candidate (id=4) collects in-person mutual vouches.
        let candidate = 4u32;

        // Forged vouch tag is rejected in constant time.
        let key = wot.provision_vouch_key(0, candidate).unwrap();
        let mut forged = InPersonVouch::create(0, candidate, 1, key);
        forged.vouch_tag[0] ^= 0xFF;
        assert_eq!(wot.submit_vouch(forged), Err(BftError::InvalidMac));
        assert_eq!(wot.vouch_count(candidate), 0);

        // Vouch 1 from verified human 0 -> still pending (1/3).
        assert_eq!(
            wot.vouch_in_person(0, candidate, 1).unwrap(),
            VouchStatus::Pending {
                current_vouches: 1,
                required: 3,
            }
        );
        // Same human cannot vouch twice for the same candidate!
        assert!(matches!(
            wot.vouch_in_person(0, candidate, 2),
            Err(BftError::InvalidVouch(_))
        ));
        assert!(!wot.is_verified(candidate));

        // Vouch 2 from verified human 1 -> still pending (2/3).
        assert_eq!(
            wot.vouch_in_person(1, candidate, 1).unwrap(),
            VouchStatus::Pending {
                current_vouches: 2,
                required: 3,
            }
        );
        assert!(wot.require_admitted(candidate).is_err());

        // Vouch 3 from verified human 2 -> reaches quorum (3/3) and is admitted!
        assert_eq!(
            wot.vouch_in_person(2, candidate, 1).unwrap(),
            VouchStatus::Admitted { total_vouches: 3 }
        );
        assert!(wot.is_verified(candidate));
        assert_eq!(wot.voting_weight(candidate), 1);
        assert_eq!(wot.verified_count(), 5);
        assert!(wot.require_admitted(candidate).is_ok());
    }

    #[test]
    fn test_view_change_monotonic_lock_preservation_equivocation_and_empty_online_guard() {
        let config = BftConfig::default(); // N=4, f=1, quorum=3
        let mut cluster = BftCluster::new(config, initial_test_balances(), 64, 8, 4);

        // L-4: execute_view_change when all validators offline must not panic.
        for id in 0..4u32 {
            cluster.set_online(id, false).unwrap();
        }
        assert!(matches!(
            cluster.execute_view_change(1),
            Err(BftError::QuorumNotReached {
                phase: "ViewChange",
                ..
            })
        ));
        for id in 0..4u32 {
            cluster.set_online(id, true).unwrap();
        }

        // C-3: ViewChange cannot regress or stay on current_view.
        assert!(cluster.execute_view_change(0).is_err());
        cluster.execute_view_change(1).unwrap();
        assert!(cluster.execute_view_change(1).is_err());
        assert!(cluster.execute_view_change(0).is_err());

        // C-3: Locked state is carried in ViewChange votes and preserved across view transitions.
        let lock_tag = [0x77u8; 16];
        cluster.validators[0].locked_view = Some(1);
        cluster.validators[0].locked_block_tag = Some(lock_tag);
        cluster.execute_view_change(2).unwrap();
        for v in &cluster.validators {
            assert_eq!(v.current_view, 2);
            assert_eq!(v.locked_view, Some(1));
            assert_eq!(v.locked_block_tag, Some(lock_tag));
        }

        // H-3: Equivocating Prepare votes from same validator for two different tags are rejected.
        let v1_vote_a = ConsensusVote {
            kind: MsgKind::Prepare,
            voter_id: 1,
            height: 1,
            view: 2,
            block_tag: [0xAAu8; 16],
            prev_tag: GENESIS_TAG,
            tx_count: 1,
            locked_view: None,
        };
        let v1_vote_b = ConsensusVote {
            block_tag: [0xBBu8; 16],
            ..v1_vote_a
        };
        let f_a = cluster.validators[1].send_vote_frame(0, &v1_vote_a).unwrap();
        let f_b = cluster.validators[1].send_vote_frame(0, &v1_vote_b).unwrap();
        cluster.validators[0].on_prepare_frame(&f_a).unwrap();
        assert!(matches!(
            cluster.validators[0].on_prepare_frame(&f_b),
            Err(BftError::InvalidEncoding(_))
        ));

        // M-7: leader_propose validates batch BEFORE burning seal key.
        // At height 1, view 2, leader is (1 + 2) % 4 = 3.
        let bad_txs = vec![BinaryTx::new(0, 0, 100, 1, 1)]; // self-transfer
        let online = cluster.online_ids();
        assert!(cluster.validators[3].leader_propose(bad_txs, &online).is_err());
        // Seal key for (1, 2) must still be available for a valid proposal!
        let good_txs = vec![BinaryTx::new(0, 1, 100, 1, 1)];
        assert!(cluster.validators[3].leader_propose(good_txs, &online).is_ok());
    }

    #[test]
    fn test_bft_locked_block_preserved_across_multiple_view_changes_and_rejects_conflicting_proposal()
    {
        let config = BftConfig::default(); // N=4, f=1, quorum=3
        let mut cluster = BftCluster::new(config, initial_test_balances(), 128, 8, 8);
        let online = cluster.online_ids();

        // View 0, Height 1 (leader = 1): propose batch_locked, reach 2f+1 Prepares so all 4
        // validators enter Commit and lock on batch_locked at locked_view = 0, then abort before Commit!
        let batch_locked = vec![BinaryTx::new(0, 1, 12_345, 1, 1)];
        let (block0, pp_frames, mut prep_frames) = cluster.validators[1]
            .leader_propose(batch_locked.clone(), &online)
            .unwrap();
        for f in &pp_frames {
            let fp = cluster.validators[f.to as usize]
                .on_pre_prepare(f, block0.clone(), &online)
                .unwrap();
            prep_frames.extend(fp);
        }
        for f in &prep_frames {
            cluster.validators[f.to as usize].on_prepare_frame(f).unwrap();
        }
        for &id in &online {
            let _ = cluster.validators[id as usize].try_enter_commit(&online).unwrap();
            assert_eq!(cluster.validators[id as usize].locked_view, Some(0));
            assert_eq!(
                cluster.validators[id as usize].locked_block_tag,
                Some(block0.block_tag)
            );
            // Simulate network partition aborting Commit phase (clearing transient round state,
            // while preserving locked_view, locked_block_tag, locked_txs).
            cluster.validators[id as usize].abort_round();
        }

        // Byzantine validator tries to spoof a future locked_view >= target_view in ViewChange.
        let spoof_vc = ConsensusVote {
            kind: MsgKind::ViewChange,
            voter_id: 2,
            height: 1,
            view: 1,
            block_tag: [0xEEu8; 16],
            prev_tag: GENESIS_TAG,
            tx_count: 0,
            locked_view: Some(1), // Invalid: locked_view == target_view!
        };
        let spoof_frame = cluster.validators[2].send_vote_frame(0, &spoof_vc).unwrap();
        assert!(matches!(
            cluster.validators[0].on_view_change_frame(&spoof_frame),
            Err(BftError::InvalidEncoding(_))
        ));

        // Before view change, attempting to propose or accept another PrePrepare at the already-locked
        // view 0 must be rejected with ConflictingPrePrepare!
        let conflicting_same_view = vec![BinaryTx::new(0, 2, 99_999, 2, 2)];
        assert!(matches!(
            cluster.validators[1].leader_propose(conflicting_same_view.clone(), &online),
            Err(BftError::ConflictingPrePrepare { height: 1, view: 0 })
        ));

        // Run a sequence of 3 consecutive ViewChanges (0 -> 1 -> 2 -> 3) and assert strict lock preservation!
        for target_view in 1..=3u64 {
            cluster.execute_view_change(target_view).unwrap();
            for v in &cluster.validators {
                assert_eq!(v.current_view, target_view);
                assert_eq!(v.locked_view, Some(0));
                assert_eq!(v.locked_block_tag, Some(block0.block_tag));
            }
        }

        // Byzantine validator attempting to inject an equal-view conflicting lock (view 0, fake tag)
        // during ViewChange 3 -> 4 must NOT overwrite honest validators' genuine lock from view 0!
        let fake_equal_vc = ConsensusVote {
            kind: MsgKind::ViewChange,
            voter_id: 3,
            height: 1,
            view: 4,
            block_tag: [0x99u8; 16],
            prev_tag: GENESIS_TAG,
            tx_count: 0,
            locked_view: Some(0),
        };
        let fake_vc_frame = cluster.validators[3].send_vote_frame(0, &fake_equal_vc).unwrap();
        cluster.validators[0].on_view_change_frame(&fake_vc_frame).unwrap();
        // Complete view change to view 4 across all honest validators (V3 already voted via fake frame to V0,
        // so use validators 0, 1, 2 to form a 3-of-4 quorum for view 4 on V0).
        for &voter in &[0u32, 1, 2] {
            let frames = cluster.validators[voter as usize]
                .start_view_change(4, &[0, 1, 2])
                .unwrap();
            for f in &frames {
                let _ = cluster.validators[f.to as usize].on_view_change_frame(f);
            }
        }
        for &id in &[0u32, 1, 2] {
            cluster.validators[id as usize].try_complete_view_change(4).unwrap();
            assert_eq!(cluster.validators[id as usize].current_view, 4);
            assert_eq!(cluster.validators[id as usize].locked_view, Some(0));
            assert_eq!(
                cluster.validators[id as usize].locked_block_tag,
                Some(block0.block_tag),
                "equal-view Byzantine lock claim must never overwrite honest validator's lock"
            );
        }

        // Bring V3 offline for view 4 commit (quorum 3 of 4 commits the locked batch cleanly!).
        cluster.set_online(3, false).unwrap();
        let cert = cluster.propose_and_finalize_batch(batch_locked).unwrap();
        assert_eq!(cert.height, 1);
        assert_eq!(cert.view, 4);
        cluster.sync_validator_from_quorum(3).unwrap();
        for v in &cluster.validators {
            assert_eq!(v.ledger.balance_of(0), 1_000_000 - 12_345);
            assert_eq!(v.ledger.balance_of(1), 1_000_000 + 12_345);
            assert_eq!(v.locked_view, None);
            assert_eq!(v.locked_block_tag, None);
        }
    }

    #[test]
    fn test_adversarial_bft_byzantine_fuzz_64_rounds() {
        // Deterministic xorshift64* PRNG (zero external crates).
        let mut rng_state: u64 = 0x5652_4E4D_BFA0_2026;
        let mut next_u64 = || -> u64 {
            let mut x = rng_state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            rng_state = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        let config = BftConfig::for_faults(2).unwrap(); // N=7, f=2, quorum=5
        let initial = initial_test_balances();
        let initial_total_supply: u64 = initial.values().sum();
        let mut cluster = BftCluster::new(config, initial, 2_048, 128, 12);

        let mut next_page_nonce = [1u64; 16];
        let mut expected_height = 0u64;
        let mut offline_set: BTreeSet<u32> = BTreeSet::new();
        let mut equivocations_blocked = 0usize;
        let mut forged_macs_rejected = 0usize;
        let mut duplicate_votes_ignored = 0usize;
        let mut view_changes_triggered = 0usize;
        let mut catchup_syncs_completed = 0usize;

        for round in 0..64u64 {
            let action = next_u64() % 10;

            // 1. Periodically take up to f=2 validators offline (including crashing the next leader!)
            //    or bring offline validators back online via quorum catch-up sync.
            if action == 0 && offline_set.len() < config.max_faults() {
                let next_h = expected_height + 1;
                let victim = config.leader_for(next_h, 0);
                if offline_set.insert(victim) {
                    cluster.set_online(victim, false).unwrap();
                }
            } else if action == 1 && !offline_set.is_empty() {
                let rejoin_id = *offline_set.iter().next().unwrap();
                let prev_h = cluster.validators[rejoin_id as usize].ledger.height;
                let synced = cluster.sync_validator_from_quorum(rejoin_id).unwrap();
                assert_eq!(
                    prev_h + synced as u64,
                    expected_height,
                    "rejoining validator must catch up to exact tip height"
                );
                offline_set.remove(&rejoin_id);
                catchup_syncs_completed += 1;
            } else if action == 2 && offline_set.len() < config.max_faults() {
                let victim = (next_u64() % config.num_validators as u64) as u32;
                if offline_set.insert(victim) {
                    cluster.set_online(victim, false).unwrap();
                }
            }

            // 2. Inject Byzantine leader equivocation periodically (catching up any offline peers first
            //    so the full 7-validator committee exercises the split-partition equivocation attack).
            if round % 10 == 3 {
                let to_sync: Vec<u32> = offline_set.iter().copied().collect();
                for id in to_sync {
                    cluster.sync_validator_from_quorum(id).unwrap();
                    offline_set.remove(&id);
                    catchup_syncs_completed += 1;
                }
                let pre_balances = cluster.validators[0].ledger.balances.clone();
                let pre_tip = cluster.validators[0].ledger.tip_tag;
                let cur_view = cluster.validators[0].current_view;
                let leader = config.leader_for(expected_height + 1, cur_view);
                let mut group_a = vec![leader];
                let mut group_b = Vec::new();
                for id in 0..config.num_validators as u32 {
                    if id == leader {
                        continue;
                    }
                    if group_a.len() < 3 {
                        group_a.push(id);
                    } else {
                        group_b.push(id);
                    }
                }
                let tx_a = vec![BinaryTx::new(0, 1, 500, next_page_nonce[0], next_page_nonce[0])];
                let tx_b = vec![BinaryTx::new(0, 2, 500, next_page_nonce[0], next_page_nonce[0])];
                let eq_res = cluster.simulate_byzantine_equivocation(tx_a, &group_a, tx_b, &group_b);
                assert!(
                    matches!(eq_res, Err(BftError::QuorumNotReached { .. })),
                    "Byzantine equivocation at round {round} must never reach quorum"
                );
                for v in &cluster.validators {
                    assert_eq!(v.ledger.height, expected_height);
                    assert_eq!(v.ledger.tip_tag, pre_tip);
                    assert_eq!(v.ledger.balances, pre_balances);
                }
                // Advance view strictly monotonically past the equivocating leader.
                cluster.execute_view_change(cur_view + 1).unwrap();
                equivocations_blocked += 1;
                view_changes_triggered += 1;
            }
            let online_before = cluster.online_ids();
            assert!(online_before.len() >= config.quorum());
            let ref_id = online_before[0] as usize;

            // 3. Inject forged Carter-Wegman MACs and duplicate votes directly against honest validators.
            if action == 4 || action == 5 {
                let sender = online_before[0];
                let receiver = online_before[1];
                let cur_view = cluster.validators[receiver as usize].current_view;
                let tip = cluster.validators[receiver as usize].ledger.tip_tag;
                let probe_vote = ConsensusVote {
                    kind: MsgKind::Prepare,
                    voter_id: sender,
                    height: expected_height + 1,
                    view: cur_view,
                    block_tag: [0x5Au8; 16],
                    prev_tag: tip,
                    tx_count: 1,
                    locked_view: None,
                };
                // Forged MAC: flip 1 bit in tag -> must reject with InvalidMac without mutating state.
                let mut forged = cluster.validators[sender as usize]
                    .send_vote_frame(receiver, &probe_vote)
                    .unwrap();
                forged.tag[(round as usize) % 16] ^= 0x80;
                assert_eq!(
                    cluster.validators[receiver as usize].on_prepare_frame(&forged),
                    Err(BftError::InvalidMac)
                );
                forged_macs_rejected += 1;

                // Duplicate valid Prepare votes from the SAME validator must never double-count!
                let valid1 = cluster.validators[sender as usize]
                    .send_vote_frame(receiver, &probe_vote)
                    .unwrap();
                let valid2 = cluster.validators[sender as usize]
                    .send_vote_frame(receiver, &probe_vote)
                    .unwrap();
                cluster.validators[receiver as usize]
                    .on_prepare_frame(&valid1)
                    .unwrap();
                cluster.validators[receiver as usize]
                    .on_prepare_frame(&valid2)
                    .unwrap();
                assert_eq!(
                    cluster.validators[receiver as usize]
                        .round
                        .prepare_votes
                        .get(&[0x5Au8; 16])
                        .map(BTreeSet::len),
                    Some(1),
                    "duplicate Prepare votes from same validator must never double-count"
                );
                cluster.validators[receiver as usize].abort_round();
                duplicate_votes_ignored += 1;
            }

            // 4. Build a randomized valid batch of 1..=8 transfers from live balances.
            let batch_len = ((next_u64() % 8) + 1) as usize;
            let mut batch = Vec::with_capacity(batch_len);
            let mut staged_bal = cluster.validators[ref_id].ledger.balances.clone();
            for _ in 0..batch_len {
                let s = (next_u64() % 16) as u32;
                let mut r = (next_u64() % 16) as u32;
                if r == s {
                    r = (r + 1) % 16;
                }
                let avail = staged_bal.get(&s).copied().unwrap_or(0);
                if avail == 0 {
                    continue;
                }
                let amt = ((next_u64() % 250) + 1).min(avail);
                let pn = next_page_nonce[s as usize];
                next_page_nonce[s as usize] += 1;
                *staged_bal.get_mut(&s).unwrap() -= amt;
                *staged_bal.entry(r).or_insert(0) += amt;
                batch.push(BinaryTx::new(s, r, amt, pn, pn));
            }

            let view_before = cluster.validators[ref_id].current_view;
            let cert = cluster
                .propose_and_finalize_batch(batch)
                .expect("honest quorum must finalize batch even under leader crashes/attacks");

            // Invariant (c): strictly monotonic height, valid view progression.
            expected_height += 1;
            assert_eq!(cert.height, expected_height);
            assert!(cert.view >= view_before);
            if cert.view > view_before {
                view_changes_triggered += 1;
            }
            assert!(cert.commit_voters.len() >= config.quorum());

            // Invariant (a) & (b): identical ledger state & exact coin conservation across ALL online honest validators!
            let ref_ledger = cluster.validators[ref_id].ledger.clone();
            assert_eq!(ref_ledger.height, expected_height);
            assert!(ct_eq_16(&ref_ledger.tip_tag, &cert.block_tag));
            let total_supply: u64 = ref_ledger.balances.values().sum();
            assert_eq!(
                total_supply, initial_total_supply,
                "coin conservation violated at height {expected_height}"
            );
            for &id in &online_before {
                assert_eq!(
                    cluster.validators[id as usize].ledger, ref_ledger,
                    "Safety violation: validator {id} diverged at height {expected_height}"
                );
            }
        }

        // Catch up any remaining offline validators and verify ALL 7 validators match bit-for-bit!
        for id in offline_set {
            cluster.sync_validator_from_quorum(id).unwrap();
            catchup_syncs_completed += 1;
        }
        let final_ref = &cluster.validators[0].ledger;
        assert_eq!(final_ref.height, 64);
        assert_eq!(
            final_ref.balances.values().sum::<u64>(),
            initial_total_supply
        );
        for v in &cluster.validators[1..] {
            assert_eq!(v.ledger, *final_ref);
        }
        assert!(equivocations_blocked > 0);
        assert!(forged_macs_rejected > 0);
        assert!(duplicate_votes_ignored > 0);
        assert!(view_changes_triggered > 0);
        assert!(catchup_syncs_completed > 0);
    }
}
