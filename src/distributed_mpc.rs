//! Split-Process Networked Shielded IT-MPC Daemons for Vernam (VRNM) v1.0.
//!
//! Eliminates the single-process privacy bottleneck by running **4 completely independent
//! TCP validator daemons** (`V0`, `V1`, `V2`, `V3`, each bound to its own `TcpListener` port —
//! representing 4 physically separate servers):
//!
//! - **Strict Split-Share Isolation:** Validator `i in {0, 1, 2, 3}` holds **ONLY its single
//!   Shamir share `y_i: u128`** for every account in every anonymity bucket, plus **ONLY its
//!   single share** of every pre-generated Beaver Square (`(a_i, a_sq_i)`), Shared-Factor
//!   Beaver Star (`(b_v_i, a_k_i, c_k_i)`), blinding Beaver Triple (`(ta_i, tb_i, tc_i)`), and
//!   blinding scalar `rho_i`. No validator daemon EVER receives another validator's balance share.
//! - **Fixed-Header Pairwise OTP + Carter-Wegman Binary TCP Protocol:** Every wallet-to-daemon
//!   and daemon-to-daemon packet is framed in compact binary (zero JSON overhead), encrypted
//!   with a strictly single-use pairwise OTP pad, and authenticated with a strictly single-use
//!   Carter-Wegman polynomial MAC over `F_(2^127 - 1)` verified in constant time (`ct_eq_16`),
//!   with volatile memory zeroization on consumption and `Drop`.
//! - **2-Phase Batched Networked Confidential Transfers:**
//!   1. **Network RTT #1 (Batched Opening Round):** Each daemon computes its `65` local opening
//!      shares (`48` BeaverSquare `d`s + `1` shared `beta` + `16` `alpha_k`s) plus a fresh
//!      OS-random RLC challenge contribution `gamma_i` and exchanges them with the other 3
//!      daemons in ONE compact binary TCP packet over pairwise OTP+MAC links. Every daemon
//!      independently checks degree-2 Lagrange parity (`[1, P - 3, 3, P - 1]`) on all `65`
//!      openings.
//!   2. **Network RTT #2 (Blinded Zero-Check `[rho] * [Z]`):** Each daemon locally evaluates
//!      its share of the 50-check Schwartz-Zippel RLC `[Z]` at the joint random challenge
//!      `gamma`, runs the 1-triple blinding multiplication `[Z_blind] = [rho] * [Z]` (tiny
//!      2-field `(alpha_z, beta_z)` exchange followed by tiny 1-field `Z_blind` opening), and
//!      independently verifies degree-2 parity and `Z_blind == 0`.
//!   - If `Z_blind == 0`, each daemon atomically updates **ONLY its own local balance shares**
//!     (`sender -= [v]_i`, `slot_k += [s_k * v]_i` for all 16 slots in the bucket). On any
//!     failure, every daemon aborts cleanly with zero state mutation and zero balance leakage.
//! - **Client-Side Private Balance Reconstruction:** Wallet queries all 4 (or any 3 online)
//!   daemons, receives each daemon's encrypted `y_i`, and reconstructs + degree-verifies the
//!   balance exclusively on the user's machine.
//! - **Distributed Proactive Secret Sharing (PSS) Refresh:** All 4 daemons exchange fresh
//!   zero-polynomial evaluation deltas over pairwise OTP+MAC TCP links to rotate every account
//!   share from Epoch `e` to Epoch `e + 1` without changing any reconstructed balance.
//!
//! Zero external crates, zero computational cryptography, zero `unsafe` code.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, inv_mod, mul_mod, sub_mod, zeroize_slice, zeroize_u128,
};

// ============================================================================
// Protocol Constants
// ============================================================================

/// Fixed `(3, 4)` Shamir validator count.
pub const DIST_NUM_VALIDATORS: usize = 4;

/// Reconstruction threshold `t = 3` (`< 3` colluding validators learn 0 bits).
pub const DIST_THRESHOLD: usize = 3;

/// Confidential amount / remainder bit width (`0 <= v < 2^16`).
pub const DIST_RANGE_BITS: usize = 16;

/// Anonymity bucket size (`K = 16` slots blindly credited on every transfer).
pub const DIST_BUCKET_SIZE: usize = 16;

/// Single-use Beaver Square pairs consumed per transfer (`16 v + 16 r + 16 s = 48`).
pub const DIST_SQUARES_PER_TX: usize = 2 * DIST_RANGE_BITS + DIST_BUCKET_SIZE;

/// Total invariant checks folded into the Schwartz-Zippel RLC (`48 bits + balance + sum(s)`).
pub const DIST_CHECKS_PER_TX: usize = DIST_SQUARES_PER_TX + 2;

/// Number of batched openings exchanged in Network RTT #1 (`48 d + 1 beta + 16 alpha_k = 65`).
pub const DIST_RTT1_OPENINGS: usize = DIST_SQUARES_PER_TX + 1 + DIST_BUCKET_SIZE;

/// Binary wire frame magic bytes.
const FRAME_MAGIC: [u8; 4] = *b"VRNM";

/// Wire frame fixed header length in bytes:
/// `magic(4) + msg_type(1) + sender_id(1) + flags(2) + seq_id(8) + payload_len(4) = 20`.
const FRAME_HEADER_LEN: usize = 20;

/// Carter-Wegman MAC tag length in bytes (one `F_(2^127 - 1)` element, little-endian).
const FRAME_MAC_LEN: usize = 16;

/// Maximum accepted binary wire frame payload size (4 MiB guard against malformed frames).
const MAX_FRAME_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Maximum upfront buffer allocation before reading body bytes over TCP (prevents OOM from spoofed headers).
const INITIAL_FRAME_ALLOC_CAP: usize = 8192;

/// Maximum accepted payload length on unauthenticated initial handshake frames.
const MAX_HANDSHAKE_PAYLOAD_BYTES: usize = 64;

/// Maximum accepted payload length on authenticated client request frames.
const MAX_CLIENT_PAYLOAD_BYTES: usize = 1024;

/// Maximum accepted payload length on daemon-to-client reply frames.
const MAX_DAEMON_REPLY_PAYLOAD_BYTES: usize = 64;

/// Maximum simultaneous client worker threads per validator daemon.
const MAX_CONCURRENT_CLIENTS: usize = 32;

/// Maximum total simultaneous TCP connection worker threads per daemon (peers + clients + headroom).
const MAX_TOTAL_CONNS: usize = DIST_NUM_VALIDATORS + MAX_CONCURRENT_CLIENTS + 16;

/// Maximum pending in-flight rendezvous mailboxes per daemon (prevents memory exhaustion from rogue peers).
const MAX_PENDING_MAILBOXES: usize = 1024;

/// Socket read poll timeout allowing fast clean shutdown without busy-spinning.
const SOCKET_POLL_TIMEOUT: Duration = Duration::from_millis(25);

/// Compile-time multiplicative inverse of 3 modulo `PRIME_P = 2^127 - 1`.
const INV_3: u128 = inv_mod(3);

/// Compile-time `8 / 3 mod PRIME_P` for 3-of-4 Lagrange subset `{1, 2, 4}`.
const EIGHT_THIRDS: u128 = mul_mod(8, INV_3);

// Wire message type tags.
const MSG_PEER_HELLO: u8 = 0x01;
const MSG_CLIENT_HELLO: u8 = 0x02;
const MSG_PEER_RTT1: u8 = 0x10;
const MSG_PEER_RTT2A: u8 = 0x11;
const MSG_PEER_RTT2B: u8 = 0x12;
const MSG_PEER_ABORT: u8 = 0x13;
const MSG_PEER_PSS_DELTA: u8 = 0x14;
const MSG_CLIENT_MINT: u8 = 0x20;
const MSG_CLIENT_TRANSFER: u8 = 0x21;
const MSG_CLIENT_QUERY_BALANCE: u8 = 0x22;
const MSG_CLIENT_PSS_REFRESH: u8 = 0x23;
const MSG_DAEMON_MINT_ACK: u8 = 0x30;
const MSG_DAEMON_TX_REPLY: u8 = 0x31;
const MSG_DAEMON_BALANCE_REPLY: u8 = 0x32;
const MSG_DAEMON_PSS_ACK: u8 = 0x33;
const MSG_DAEMON_ERROR: u8 = 0x3F;

// Round identifiers for per-tx peer rendezvous mailboxes.
const ROUND_RTT1: u8 = 1;
const ROUND_RTT2A: u8 = 2;
const ROUND_RTT2B: u8 = 3;

// Reply status codes for `MSG_DAEMON_TX_REPLY`.
const TX_STATUS_COMMITTED: u8 = 0;
const TX_STATUS_RLC_FAILED: u8 = 1;
const TX_STATUS_INCONSISTENT_SHARES: u8 = 2;
const TX_STATUS_FIELD_OUT_OF_RANGE: u8 = 3;
const TX_STATUS_BEAVER_EXHAUSTED: u8 = 4;
const TX_STATUS_BEAVER_REUSED: u8 = 5;
const TX_STATUS_INVALID_BUCKET: u8 = 6;
const TX_STATUS_INVALID_SLOT: u8 = 7;
const TX_STATUS_TIMEOUT: u8 = 8;
const TX_STATUS_PROTOCOL_ERROR: u8 = 9;

// ============================================================================
// Errors
// ============================================================================

/// Errors returned by the split-process networked IT-MPC daemons and wallet client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributedMpcError {
    /// Invalid configuration or protocol parameter.
    InvalidParameters(&'static str),
    /// Field element outside canonical range `[0, PRIME_P)`.
    FieldElementOutOfRange,
    /// `(3, 4)` Shamir shares failed degree-2 Lagrange parity verification.
    InconsistentShares,
    /// Blinded Schwartz-Zippel RLC zero-check failed (`Z_blind != 0`, leaking 0 bits of state).
    RlcCheckFailed { blinded_residual: u128 },
    /// Carter-Wegman MAC tag verification failed in constant time.
    MacVerificationFailed,
    /// Single-use pairwise OTP pad or MAC key tape exhausted.
    OtpPadExhausted { needed: usize, available: usize },
    /// Offline correlated-randomness bundle missing for `tx_id`.
    BeaverExhausted { tx_id: u64 },
    /// Attempted reuse of an already-consumed single-use Beaver bundle for `tx_id`.
    BeaverAlreadyConsumed { tx_id: u64 },
    /// Bucket index out of range.
    InvalidBucket { bucket_id: usize },
    /// Slot index inside a bucket is out of range.
    InvalidSlot { slot: usize },
    /// Fewer than `t = 3` validators responded to a quorum operation.
    InsufficientQuorum { available: usize, needed: usize },
    /// Wire protocol framing or state violation.
    ProtocolError(String),
    /// TCP socket I/O error.
    NetworkError(String),
    /// Timed out waiting for peer or daemon response.
    Timeout(&'static str),
    /// Daemon is shutting down.
    Shutdown,
}

impl fmt::Display for DistributedMpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DistributedMpcError {}

// ============================================================================
// Buffered OS Entropy & Volatile Zeroization Helpers (Pure OS /dev/urandom)
// ============================================================================

struct BufferedOsRng {
    file: File,
    buf: [u8; 4096],
    pos: usize,
}

impl BufferedOsRng {
    fn new() -> Self {
        Self {
            file: File::open("/dev/urandom").expect("failed to open /dev/urandom"),
            buf: [0u8; 4096],
            pos: 4096,
        }
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        if out.len() >= self.buf.len() {
            self.file
                .read_exact(out)
                .expect("failed to read from /dev/urandom");
            return;
        }
        let avail = self.buf.len() - self.pos;
        if out.len() <= avail {
            out.copy_from_slice(&self.buf[self.pos..self.pos + out.len()]);
            zeroize_slice(&mut self.buf[self.pos..self.pos + out.len()]);
            self.pos += out.len();
        } else {
            self.file
                .read_exact(&mut self.buf)
                .expect("failed to read from /dev/urandom");
            self.pos = 0;
            out.copy_from_slice(&self.buf[..out.len()]);
            zeroize_slice(&mut self.buf[..out.len()]);
            self.pos = out.len();
        }
    }
}

impl Drop for BufferedOsRng {
    fn drop(&mut self) {
        zeroize_slice(&mut self.buf);
    }
}

thread_local! {
    static OS_RNG: RefCell<BufferedOsRng> = RefCell::new(BufferedOsRng::new());
}

fn fill_os_random_fast(buf: &mut [u8]) {
    OS_RNG.with(|cell| cell.borrow_mut().fill_bytes(buf));
}

fn random_field_elem_fast() -> u128 {
    let mut b = [0u8; 16];
    loop {
        fill_os_random_fast(&mut b);
        let cand = u128::from_le_bytes(b) & PRIME_P;
        if cand < PRIME_P {
            zeroize_slice(&mut b);
            return cand;
        }
    }
}

fn random_nonzero_field_elem_fast() -> u128 {
    loop {
        let v = random_field_elem_fast();
        if v != 0 {
            return v;
        }
    }
}

fn fill_random_field_elems(out: &mut [u128]) {
    const CHUNK: usize = 512;
    let mut raw = [0u8; CHUNK * 16];
    for chunk in out.chunks_mut(CHUNK) {
        let nbytes = chunk.len() * 16;
        fill_os_random_fast(&mut raw[..nbytes]);
        for (dst, slice) in chunk.iter_mut().zip(raw[..nbytes].chunks_exact(16)) {
            let mut b = [0u8; 16];
            b.copy_from_slice(slice);
            let cand = u128::from_le_bytes(b) & PRIME_P;
            *dst = if cand < PRIME_P {
                cand
            } else {
                random_field_elem_fast()
            };
            zeroize_slice(&mut b);
        }
    }
    zeroize_slice(&mut raw);
}

fn zeroize_u128_slice(slice: &mut [u128]) {
    for v in slice.iter_mut() {
        zeroize_u128(v);
    }
}

// ============================================================================
// Compile-Time `(3, 4)` Shamir Lagrange & Degree-2 Parity over F_(2^127 - 1)
// ============================================================================

/// Multiply `x` by 3 modulo `PRIME_P` using only 2 modular additions.
#[inline(always)]
const fn mul3_mod(x: u128) -> u128 {
    add_mod(add_mod(x, x), x)
}

/// Evaluate `c0 + c1*x + c2*x^2 (mod PRIME_P)` at `x = 1, 2, 3, 4` using finite differences.
#[inline(always)]
pub const fn eval_poly_3_of_4(c0: u128, c1: u128, c2: u128) -> [u128; DIST_NUM_VALIDATORS] {
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

/// Split a canonical field secret in `[0, PRIME_P)` into `(3, 4)` Shamir shares.
pub fn split_secret_3_of_4(secret: u128) -> Result<[u128; DIST_NUM_VALIDATORS], DistributedMpcError> {
    if secret >= PRIME_P {
        return Err(DistributedMpcError::FieldElementOutOfRange);
    }
    let mut r = [0u128; 2];
    fill_random_field_elems(&mut r);
    let shares = eval_poly_3_of_4(secret, r[0], r[1]);
    zeroize_u128_slice(&mut r);
    Ok(shares)
}

/// Verify all 4 shares are `< PRIME_P` and satisfy degree-2 Lagrange parity `[1, P - 3, 3, P - 1]`:
/// `y1 - 3*y2 + 3*y3 == y4 (mod PRIME_P)` with zero `mul_mod` and zero `inv_mod`.
#[inline(always)]
pub fn verify_degree2_4(shares: &[u128; DIST_NUM_VALIDATORS]) -> Result<(), DistributedMpcError> {
    if shares[0] >= PRIME_P
        || shares[1] >= PRIME_P
        || shares[2] >= PRIME_P
        || shares[3] >= PRIME_P
    {
        return Err(DistributedMpcError::FieldElementOutOfRange);
    }
    let expected_y4 = sub_mod(add_mod(shares[0], mul3_mod(shares[2])), mul3_mod(shares[1]));
    if expected_y4 != shares[3] {
        return Err(DistributedMpcError::InconsistentShares);
    }
    Ok(())
}

/// Degree-2 verify all 4 shares and reconstruct `P(0) = 3*y1 - 3*y2 + y3 (mod PRIME_P)`.
#[inline(always)]
pub fn reconstruct_4_verified(
    shares: &[u128; DIST_NUM_VALIDATORS],
) -> Result<u128, DistributedMpcError> {
    verify_degree2_4(shares)?;
    Ok(sub_mod(
        add_mod(mul3_mod(shares[0]), shares[2]),
        mul3_mod(shares[1]),
    ))
}

/// Reconstruct `P(0)` from ANY 3 distinct validator shares `(validator_id, share)` in `0..4`.
///
/// Uses exact compile-time Lagrange basis coefficients at `x = 0` for all 4 subsets of
/// `{1, 2, 3, 4}` so the wallet can recover balances even when 1 validator daemon is offline.
pub fn reconstruct_any_3(
    present: &[(usize, u128); DIST_THRESHOLD],
) -> Result<u128, DistributedMpcError> {
    let mut map = [None::<u128>; DIST_NUM_VALIDATORS];
    for &(id, y) in present {
        if id >= DIST_NUM_VALIDATORS {
            return Err(DistributedMpcError::InvalidParameters(
                "validator id out of range 0..4",
            ));
        }
        if y >= PRIME_P {
            return Err(DistributedMpcError::FieldElementOutOfRange);
        }
        if map[id].is_some() {
            return Err(DistributedMpcError::InvalidParameters(
                "duplicate validator id in 3-of-4 reconstruction",
            ));
        }
        map[id] = Some(y);
    }

    match map {
        // Subset {1, 2, 3}: 3*y1 - 3*y2 + y3
        [Some(y1), Some(y2), Some(y3), None] => {
            Ok(sub_mod(add_mod(mul3_mod(y1), y3), mul3_mod(y2)))
        }
        // Subset {1, 2, 4}: (8/3)*y1 - 2*y2 + (1/3)*y4
        [Some(y1), Some(y2), None, Some(y4)] => {
            let t1 = mul_mod(EIGHT_THIRDS, y1);
            let t2 = add_mod(y2, y2);
            let t4 = mul_mod(INV_3, y4);
            Ok(sub_mod(add_mod(t1, t4), t2))
        }
        // Subset {1, 3, 4}: 2*y1 - 2*y3 + y4
        [Some(y1), None, Some(y3), Some(y4)] => {
            let t1 = add_mod(y1, y1);
            let t3 = add_mod(y3, y3);
            Ok(sub_mod(add_mod(t1, y4), t3))
        }
        // Subset {2, 3, 4}: 6*y2 - 8*y3 + 3*y4
        [None, Some(y2), Some(y3), Some(y4)] => {
            let t2 = add_mod(mul3_mod(y2), mul3_mod(y2));
            let y3_2 = add_mod(y3, y3);
            let y3_4 = add_mod(y3_2, y3_2);
            let t3 = add_mod(y3_4, y3_4);
            let t4 = mul3_mod(y4);
            Ok(sub_mod(add_mod(t2, t4), t3))
        }
        _ => Err(DistributedMpcError::InvalidParameters(
            "expected exactly 3 distinct validator shares",
        )),
    }
}

// ============================================================================
// Pairwise Single-Use OTP + Carter-Wegman MAC over F_(2^127 - 1)
// ============================================================================

/// Compute an information-theoretically secure single-use Carter-Wegman polynomial MAC over
/// `F_(2^127 - 1)` using canonical single-use key `(mac_r, mac_s)`.
///
/// Packs `data` into 15-byte (120-bit) field elements with a domain-separating MSB bit (`1 << 120`)
/// per chunk and a final length block, evaluating Horner's rule at `mac_r` and masking with `mac_s`.
/// Forgery probability for a message of length `L` bytes is at most `(ceil(L/15) + 2) / (2^127 - 1)`.
pub fn carter_wegman_mac(mac_r: u128, mac_s: u128, data: &[u8]) -> [u8; FRAME_MAC_LEN] {
    let mut acc = 0u128;
    for chunk in data.chunks(15) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        // Domain-separating bit prevents leading/trailing zero ambiguity across chunk lengths.
        let elem = u128::from_le_bytes(block) | (1u128 << 120);
        acc = add_mod(mul_mod(acc, mac_r), elem);
    }
    let len_elem = (data.len() as u128) | (1u128 << 121);
    acc = add_mod(mul_mod(acc, mac_r), len_elem);
    let tag = add_mod(acc, mac_s);
    tag.to_le_bytes()
}

/// Strictly single-use pairwise OTP byte tape + canonical Carter-Wegman `(mac_r, mac_s)` keys.
///
/// Every consumed pad byte and MAC key pair is immediately overwritten via volatile zeroization,
/// and all remaining unused key material is volatile-zeroized on `Drop`.
pub struct OtpPadTape {
    pad_bytes: Vec<u8>,
    pad_pos: usize,
    mac_keys: Vec<(u128, u128)>,
    mac_pos: usize,
    next_seq: u64,
}

impl fmt::Debug for OtpPadTape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpPadTape")
            .field("remaining_pad_bytes", &self.remaining_pad_bytes())
            .field("remaining_mac_keys", &self.remaining_mac_keys())
            .field("next_seq", &self.next_seq)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl OtpPadTape {
    /// Generate a matched sender/receiver pair of strictly single-use [`OtpPadTape`]s directly
    /// from OS cryptographic entropy (`/dev/urandom`).
    pub fn generate_pair(pad_byte_len: usize, mac_key_count: usize) -> (Self, Self) {
        let mut pad_a = vec![0u8; pad_byte_len];
        fill_os_random_fast(&mut pad_a);
        let pad_b = pad_a.clone();

        let mut raw_elems = vec![0u128; mac_key_count * 2];
        fill_random_field_elems(&mut raw_elems);
        let mut keys_a = Vec::with_capacity(mac_key_count);
        for pair in raw_elems.chunks_exact(2) {
            keys_a.push((pair[0], pair[1]));
        }
        zeroize_u128_slice(&mut raw_elems);
        let keys_b = keys_a.clone();

        (
            Self {
                pad_bytes: pad_a,
                pad_pos: 0,
                mac_keys: keys_a,
                mac_pos: 0,
                next_seq: 0,
            },
            Self {
                pad_bytes: pad_b,
                pad_pos: 0,
                mac_keys: keys_b,
                mac_pos: 0,
                next_seq: 0,
            },
        )
    }

    /// Remaining unconsumed OTP pad bytes.
    pub fn remaining_pad_bytes(&self) -> usize {
        self.pad_bytes.len().saturating_sub(self.pad_pos)
    }

    /// Remaining unconsumed single-use Carter-Wegman MAC key pairs.
    pub fn remaining_mac_keys(&self) -> usize {
        self.mac_keys.len().saturating_sub(self.mac_pos)
    }

    /// Consume the next single-use MAC key pair `(r, s)` and volatile-zeroize its slot.
    fn consume_mac_key(&mut self) -> Result<(u128, u128), DistributedMpcError> {
        let avail = self.remaining_mac_keys();
        if avail == 0 {
            return Err(DistributedMpcError::OtpPadExhausted {
                needed: 1,
                available: 0,
            });
        }
        let pos = self.mac_pos;
        let pair = self.mac_keys[pos];
        zeroize_u128(&mut self.mac_keys[pos].0);
        zeroize_u128(&mut self.mac_keys[pos].1);
        self.mac_pos += 1;
        Ok(pair)
    }

    /// XOR `buf` in place with the next `buf.len()` single-use OTP bytes and volatile-zeroize them.
    fn apply_and_burn_pad(&mut self, buf: &mut [u8]) -> Result<(), DistributedMpcError> {
        let avail = self.remaining_pad_bytes();
        if buf.len() > avail {
            return Err(DistributedMpcError::OtpPadExhausted {
                needed: buf.len(),
                available: avail,
            });
        }
        let start = self.pad_pos;
        let end = start + buf.len();
        let slice = &mut self.pad_bytes[start..end];
        for (b, p) in buf.iter_mut().zip(slice.iter()) {
            *b ^= *p;
        }
        zeroize_slice(slice);
        self.pad_pos = end;
        Ok(())
    }

    /// Burn `len` single-use OTP bytes in place via volatile zeroization with ZERO heap allocation.
    fn burn_pad_bytes(&mut self, len: usize) {
        let avail = self.remaining_pad_bytes();
        let to_burn = len.min(avail);
        if to_burn == 0 {
            return;
        }
        let start = self.pad_pos;
        let end = start + to_burn;
        zeroize_slice(&mut self.pad_bytes[start..end]);
        self.pad_pos = end;
    }

    /// Allocate the next monotonic frame sequence number (sender side).
    fn next_send_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// Verify monotonic frame sequence number (receiver side, prevents replay/reordering).
    fn verify_and_advance_recv_seq(&mut self, seq: u64) -> Result<(), DistributedMpcError> {
        if seq != self.next_seq {
            return Err(DistributedMpcError::ProtocolError(format!(
                "out-of-sequence OTP frame: expected {}, got {}",
                self.next_seq, seq
            )));
        }
        self.next_seq += 1;
        Ok(())
    }
}

impl Drop for OtpPadTape {
    fn drop(&mut self) {
        if self.pad_pos < self.pad_bytes.len() {
            zeroize_slice(&mut self.pad_bytes[self.pad_pos..]);
        }
        for pair in &mut self.mac_keys[self.mac_pos..] {
            zeroize_u128(&mut pair.0);
            zeroize_u128(&mut pair.1);
        }
    }
}

/// Decoded binary header of a pairwise OTP+MAC wire frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireFrameHeader {
    pub msg_type: u8,
    pub sender_id: u8,
    pub flags: u16,
    pub seq_id: u64,
    pub payload_len: u32,
}

/// Return the strict protocol upper bound on payload bytes for each valid wire `msg_type`,
/// rejecting unknown message types immediately before any body buffer allocation.
fn max_payload_for_msg_type(msg_type: u8) -> Result<usize, DistributedMpcError> {
    match msg_type {
        MSG_PEER_HELLO | MSG_CLIENT_HELLO => Ok(MAX_HANDSHAKE_PAYLOAD_BYTES),
        MSG_PEER_RTT1 => Ok(Rtt1Payload::BYTE_LEN),
        MSG_PEER_RTT2A => Ok(Rtt2aPayload::BYTE_LEN),
        MSG_PEER_RTT2B => Ok(Rtt2bPayload::BYTE_LEN),
        MSG_PEER_ABORT => Ok(16),
        MSG_PEER_PSS_DELTA => Ok(MAX_FRAME_PAYLOAD_BYTES),
        MSG_CLIENT_MINT => Ok(64),
        MSG_CLIENT_TRANSFER => Ok(MAX_CLIENT_PAYLOAD_BYTES),
        MSG_CLIENT_QUERY_BALANCE | MSG_CLIENT_PSS_REFRESH => Ok(32),
        MSG_DAEMON_MINT_ACK
        | MSG_DAEMON_TX_REPLY
        | MSG_DAEMON_BALANCE_REPLY
        | MSG_DAEMON_PSS_ACK
        | MSG_DAEMON_ERROR => Ok(MAX_DAEMON_REPLY_PAYLOAD_BYTES),
        _ => Err(DistributedMpcError::ProtocolError(format!(
            "unknown wire frame msg_type 0x{msg_type:02x}"
        ))),
    }
}

impl WireFrameHeader {
    fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut h = [0u8; FRAME_HEADER_LEN];
        h[0..4].copy_from_slice(&FRAME_MAGIC);
        h[4] = self.msg_type;
        h[5] = self.sender_id;
        h[6..8].copy_from_slice(&self.flags.to_le_bytes());
        h[8..16].copy_from_slice(&self.seq_id.to_le_bytes());
        h[16..20].copy_from_slice(&self.payload_len.to_le_bytes());
        h
    }

    fn decode(h: &[u8; FRAME_HEADER_LEN]) -> Result<Self, DistributedMpcError> {
        if h[0..4] != FRAME_MAGIC {
            return Err(DistributedMpcError::ProtocolError(
                "invalid binary frame magic".to_string(),
            ));
        }
        let msg_type = h[4];
        let type_max = max_payload_for_msg_type(msg_type)?;
        let payload_len = u32::from_le_bytes([h[16], h[17], h[18], h[19]]);
        let payload_len_usize = payload_len as usize;
        if payload_len_usize > MAX_FRAME_PAYLOAD_BYTES || payload_len_usize > type_max {
            return Err(DistributedMpcError::ProtocolError(
                "frame payload exceeds limit".to_string(),
            ));
        }
        Ok(Self {
            msg_type,
            sender_id: h[5],
            flags: u16::from_le_bytes([h[6], h[7]]),
            seq_id: u64::from_le_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]),
            payload_len,
        })
    }
}

/// Encrypt `plaintext` with the next single-use OTP pad slice and append a single-use
/// Carter-Wegman MAC over `header || ciphertext` (Encrypt-then-MAC).
pub fn encrypt_and_mac_frame(
    tape: &mut OtpPadTape,
    msg_type: u8,
    sender_id: u8,
    flags: u16,
    plaintext: &[u8],
) -> Result<Vec<u8>, DistributedMpcError> {
    if plaintext.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(DistributedMpcError::InvalidParameters(
            "plaintext exceeds max frame payload",
        ));
    }
    if tape.remaining_pad_bytes() < plaintext.len() {
        return Err(DistributedMpcError::OtpPadExhausted {
            needed: plaintext.len(),
            available: tape.remaining_pad_bytes(),
        });
    }
    if tape.remaining_mac_keys() == 0 {
        return Err(DistributedMpcError::OtpPadExhausted {
            needed: 1,
            available: 0,
        });
    }

    let seq_id = tape.next_send_seq();
    let header = WireFrameHeader {
        msg_type,
        sender_id,
        flags,
        seq_id,
        payload_len: plaintext.len() as u32,
    };

    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + plaintext.len() + FRAME_MAC_LEN);
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(plaintext);

    // Encrypt payload in place with single-use OTP pad.
    tape.apply_and_burn_pad(&mut frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + plaintext.len()])?;

    // Compute Carter-Wegman MAC over header || ciphertext with single-use (mac_r, mac_s).
    let (mut mac_r, mut mac_s) = tape.consume_mac_key()?;
    let tag = carter_wegman_mac(mac_r, mac_s, &frame);
    zeroize_u128(&mut mac_r);
    zeroize_u128(&mut mac_s);

    frame.extend_from_slice(&tag);
    Ok(frame)
}

/// Verify sequence number and constant-time Carter-Wegman MAC on a raw binary wire frame
/// BEFORE allocating the decrypted payload buffer, then decrypt with the matching single-use OTP slice.
pub fn verify_and_decrypt_frame(
    tape: &mut OtpPadTape,
    raw_frame: &[u8],
) -> Result<(WireFrameHeader, Vec<u8>), DistributedMpcError> {
    if raw_frame.len() < FRAME_HEADER_LEN + FRAME_MAC_LEN {
        return Err(DistributedMpcError::ProtocolError(
            "truncated wire frame".to_string(),
        ));
    }
    let mut header_bytes = [0u8; FRAME_HEADER_LEN];
    header_bytes.copy_from_slice(&raw_frame[..FRAME_HEADER_LEN]);
    let header = WireFrameHeader::decode(&header_bytes)?;
    let payload_len = header.payload_len as usize;
    let body_end = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| DistributedMpcError::ProtocolError("frame length overflow".to_string()))?;
    let expected_total = body_end
        .checked_add(FRAME_MAC_LEN)
        .ok_or_else(|| DistributedMpcError::ProtocolError("frame length overflow".to_string()))?;
    if raw_frame.len() != expected_total {
        return Err(DistributedMpcError::ProtocolError(
            "wire frame length mismatch".to_string(),
        ));
    }
    if tape.remaining_mac_keys() == 0 {
        return Err(DistributedMpcError::OtpPadExhausted {
            needed: 1,
            available: 0,
        });
    }

    tape.verify_and_advance_recv_seq(header.seq_id)?;

    let mut received_tag = [0u8; FRAME_MAC_LEN];
    received_tag.copy_from_slice(&raw_frame[body_end..expected_total]);

    // Consume MAC key and verify in constant time BEFORE allocating or decrypting (Encrypt-then-MAC).
    let (mut mac_r, mut mac_s) = tape.consume_mac_key()?;
    let computed_tag = carter_wegman_mac(mac_r, mac_s, &raw_frame[..body_end]);
    zeroize_u128(&mut mac_r);
    zeroize_u128(&mut mac_s);

    if !ct_eq_16(&computed_tag, &received_tag) {
        // Burn the corresponding pad bytes in place (zero heap allocation) so a failed frame
        // can never desync or reuse pad material.
        tape.burn_pad_bytes(payload_len);
        return Err(DistributedMpcError::MacVerificationFailed);
    }

    let avail = tape.remaining_pad_bytes();
    if payload_len > avail {
        return Err(DistributedMpcError::OtpPadExhausted {
            needed: payload_len,
            available: avail,
        });
    }

    let mut payload = raw_frame[FRAME_HEADER_LEN..body_end].to_vec();
    tape.apply_and_burn_pad(&mut payload)?;
    Ok((header, payload))
}

/// Read one complete binary wire frame from a `TcpStream` with:
/// - strict per-connection `max_payload` and per-`msg_type` header validation BEFORE allocating body memory,
/// - incremental chunked allocation capped at `INITIAL_FRAME_ALLOC_CAP` (never upfront-allocates untrusted sizes),
/// - per-frame `frame_timeout` activated as soon as byte #1 arrives so stalled/Slowloris peers cannot hang threads.
///
/// Returns `Ok(None)` on clean EOF or shutdown before any bytes of the next frame were read.
fn read_raw_frame(
    stream: &mut TcpStream,
    shutdown: Option<&AtomicBool>,
    deadline: Option<Instant>,
    frame_timeout: Option<Duration>,
    max_payload: usize,
) -> Result<Option<Vec<u8>>, DistributedMpcError> {
    let mut header_buf = [0u8; FRAME_HEADER_LEN];
    let mut got = 0usize;
    let mut frame_deadline: Option<Instant> = None;

    let effective_deadline = |dl: Option<Instant>, fdl: Option<Instant>| match (dl, fdl) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };

    while got < FRAME_HEADER_LEN {
        if let Some(flag) = shutdown
            && flag.load(Ordering::Acquire)
        {
            return if got == 0 {
                Ok(None)
            } else {
                Err(DistributedMpcError::Shutdown)
            };
        }
        if let Some(dl) = effective_deadline(deadline, frame_deadline)
            && Instant::now() >= dl
        {
            return Err(DistributedMpcError::Timeout("socket read frame header"));
        }
        match stream.read(&mut header_buf[got..]) {
            Ok(0) => {
                if got == 0 {
                    return Ok(None);
                }
                return Err(DistributedMpcError::NetworkError(
                    "unexpected EOF mid-header".to_string(),
                ));
            }
            Ok(n) => {
                if got == 0
                    && let Some(ft) = frame_timeout
                {
                    frame_deadline = Some(Instant::now() + ft);
                }
                got += n;
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(e) => return Err(DistributedMpcError::NetworkError(e.to_string())),
        }
    }

    let header = WireFrameHeader::decode(&header_buf)?;
    let payload_len = header.payload_len as usize;
    if payload_len > max_payload {
        return Err(DistributedMpcError::ProtocolError(
            "frame payload exceeds connection limit".to_string(),
        ));
    }
    let total = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|v| v.checked_add(FRAME_MAC_LEN))
        .ok_or_else(|| DistributedMpcError::ProtocolError("frame length overflow".to_string()))?;

    // Cap upfront allocation so an unauthenticated peer cannot force multi-MiB allocation before sending bytes.
    let mut frame = Vec::with_capacity(total.min(INITIAL_FRAME_ALLOC_CAP));
    frame.extend_from_slice(&header_buf);

    let mut chunk = [0u8; 4096];
    while frame.len() < total {
        if let Some(flag) = shutdown
            && flag.load(Ordering::Acquire)
        {
            return Err(DistributedMpcError::Shutdown);
        }
        if let Some(dl) = effective_deadline(deadline, frame_deadline)
            && Instant::now() >= dl
        {
            return Err(DistributedMpcError::Timeout("socket read frame body"));
        }
        let remaining = total - frame.len();
        let to_read = remaining.min(chunk.len());
        match stream.read(&mut chunk[..to_read]) {
            Ok(0) => {
                return Err(DistributedMpcError::NetworkError(
                    "unexpected EOF mid-frame".to_string(),
                ));
            }
            Ok(n) => frame.extend_from_slice(&chunk[..n]),
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(e) => return Err(DistributedMpcError::NetworkError(e.to_string())),
        }
    }

    Ok(Some(frame))
}

fn write_all_frame(stream: &mut TcpStream, frame: &[u8]) -> Result<(), DistributedMpcError> {
    stream
        .write_all(frame)
        .map_err(|e| DistributedMpcError::NetworkError(e.to_string()))
}

// ============================================================================
// Single-Validator Split Correlated Randomness (ONLY Validator `i`'s Share!)
// ============================================================================

/// Validator `i`'s single share of a Beaver Square Pair `([a], [a^2])`.
/// Move-only and volatile-zeroized on `Drop`.
pub struct LocalBeaverSquare {
    a_i: u128,
    a_sq_i: u128,
}

impl fmt::Debug for LocalBeaverSquare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalBeaverSquare")
            .field("share", &"<redacted>")
            .finish()
    }
}

impl Drop for LocalBeaverSquare {
    fn drop(&mut self) {
        zeroize_u128(&mut self.a_i);
        zeroize_u128(&mut self.a_sq_i);
    }
}

/// Validator `i`'s single share of a Shared-Factor Beaver Star `([b_v], [a_0..a_15], [c_0..c_15])`.
/// Move-only and volatile-zeroized on `Drop`.
pub struct LocalBeaverStar16 {
    b_v_i: u128,
    a_i: [u128; DIST_BUCKET_SIZE],
    c_i: [u128; DIST_BUCKET_SIZE],
}

impl fmt::Debug for LocalBeaverStar16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalBeaverStar16")
            .field("share", &"<redacted>")
            .finish()
    }
}

impl Drop for LocalBeaverStar16 {
    fn drop(&mut self) {
        zeroize_u128(&mut self.b_v_i);
        zeroize_u128_slice(&mut self.a_i);
        zeroize_u128_slice(&mut self.c_i);
    }
}

/// Validator `i`'s single share of a blinding Beaver Triple `([ta], [tb], [tc])` with `tc = ta*tb`.
/// Move-only and volatile-zeroized on `Drop`.
pub struct LocalBeaverTriple {
    ta_i: u128,
    tb_i: u128,
    tc_i: u128,
}

impl fmt::Debug for LocalBeaverTriple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalBeaverTriple")
            .field("share", &"<redacted>")
            .finish()
    }
}

impl Drop for LocalBeaverTriple {
    fn drop(&mut self) {
        zeroize_u128(&mut self.ta_i);
        zeroize_u128(&mut self.tb_i);
        zeroize_u128(&mut self.tc_i);
    }
}

/// Complete single-use per-transaction correlated randomness held by ONE validator `i`:
/// 48 Beaver Squares + 1 Shared-Factor Beaver Star + 1 Blinding Beaver Triple + `rho_i`.
pub struct LocalTxBeaverBundle {
    squares: Vec<LocalBeaverSquare>,
    star: LocalBeaverStar16,
    triple: LocalBeaverTriple,
    rho_i: u128,
}

impl fmt::Debug for LocalTxBeaverBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalTxBeaverBundle")
            .field("squares", &self.squares.len())
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl Drop for LocalTxBeaverBundle {
    fn drop(&mut self) {
        zeroize_u128(&mut self.rho_i);
    }
}

/// Single-validator offline Beaver bank holding ONLY validator `i`'s shares, indexed by `tx_id`.
///
/// Each `tx_id` slot is taken via `Option::take`, guaranteeing strict single-use even under
/// replayed or concurrent requests.
pub struct LocalBeaverBank {
    slots: Vec<Option<LocalTxBeaverBundle>>,
}

impl fmt::Debug for LocalBeaverBank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let remaining = self.slots.iter().filter(|s| s.is_some()).count();
        f.debug_struct("LocalBeaverBank")
            .field("capacity", &self.slots.len())
            .field("remaining", &remaining)
            .finish()
    }
}

impl LocalBeaverBank {
    /// Provision 4 strictly disjoint single-validator banks for `tx_capacity` transfers,
    /// volatile-zeroizing all temporary polynomials immediately after splitting.
    pub fn generate_split_banks(tx_capacity: usize) -> [Self; DIST_NUM_VALIDATORS] {
        let mut banks: [Vec<Option<LocalTxBeaverBundle>>; DIST_NUM_VALIDATORS] = [
            Vec::with_capacity(tx_capacity),
            Vec::with_capacity(tx_capacity),
            Vec::with_capacity(tx_capacity),
            Vec::with_capacity(tx_capacity),
        ];

        // Per tx entropy elements:
        // - 48 squares * 5 = 240
        // - 1 star: 3 + 16 * 5 = 83
        // - 1 triple: 8
        // - 1 rho: 2 (r1, r2) + 1 non-zero rho0
        const ELEMS_PER_TX: usize = DIST_SQUARES_PER_TX * 5 + (3 + DIST_BUCKET_SIZE * 5) + 8 + 2;
        let mut entropy = vec![0u128; ELEMS_PER_TX];

        for _ in 0..tx_capacity {
            fill_random_field_elems(&mut entropy);
            let mut off = 0usize;

            let mut per_val_sq: [Vec<LocalBeaverSquare>; DIST_NUM_VALIDATORS] = [
                Vec::with_capacity(DIST_SQUARES_PER_TX),
                Vec::with_capacity(DIST_SQUARES_PER_TX),
                Vec::with_capacity(DIST_SQUARES_PER_TX),
                Vec::with_capacity(DIST_SQUARES_PER_TX),
            ];
            for _ in 0..DIST_SQUARES_PER_TX {
                let mut a0 = entropy[off];
                let mut sq0 = mul_mod(a0, a0);
                let a = eval_poly_3_of_4(a0, entropy[off + 1], entropy[off + 2]);
                let a_sq = eval_poly_3_of_4(sq0, entropy[off + 3], entropy[off + 4]);
                for i in 0..DIST_NUM_VALIDATORS {
                    per_val_sq[i].push(LocalBeaverSquare {
                        a_i: a[i],
                        a_sq_i: a_sq[i],
                    });
                }
                zeroize_u128(&mut a0);
                zeroize_u128(&mut sq0);
                off += 5;
            }

            // Shared-Factor Beaver Star16.
            let mut bv0 = entropy[off];
            let bv_shares = eval_poly_3_of_4(bv0, entropy[off + 1], entropy[off + 2]);
            off += 3;
            let mut star_a = [[0u128; DIST_BUCKET_SIZE]; DIST_NUM_VALIDATORS];
            let mut star_c = [[0u128; DIST_BUCKET_SIZE]; DIST_NUM_VALIDATORS];
            for k in 0..DIST_BUCKET_SIZE {
                let mut ak0 = entropy[off];
                let mut ck0 = mul_mod(ak0, bv0);
                let ak = eval_poly_3_of_4(ak0, entropy[off + 1], entropy[off + 2]);
                let ck = eval_poly_3_of_4(ck0, entropy[off + 3], entropy[off + 4]);
                for i in 0..DIST_NUM_VALIDATORS {
                    star_a[i][k] = ak[i];
                    star_c[i][k] = ck[i];
                }
                zeroize_u128(&mut ak0);
                zeroize_u128(&mut ck0);
                off += 5;
            }
            zeroize_u128(&mut bv0);

            // Blinding Beaver Triple (ta, tb, tc).
            let mut ta0 = entropy[off];
            let mut tb0 = entropy[off + 1];
            let mut tc0 = mul_mod(ta0, tb0);
            let ta = eval_poly_3_of_4(ta0, entropy[off + 2], entropy[off + 3]);
            let tb = eval_poly_3_of_4(tb0, entropy[off + 4], entropy[off + 5]);
            let tc = eval_poly_3_of_4(tc0, entropy[off + 6], entropy[off + 7]);
            zeroize_u128(&mut ta0);
            zeroize_u128(&mut tb0);
            zeroize_u128(&mut tc0);
            off += 8;

            // Uniform non-zero blinding scalar [rho].
            let mut rho0 = random_nonzero_field_elem_fast();
            let rho = eval_poly_3_of_4(rho0, entropy[off], entropy[off + 1]);
            zeroize_u128(&mut rho0);

            let [sq0, sq1, sq2, sq3] = per_val_sq;
            let sq_arr = [sq0, sq1, sq2, sq3];
            for (i, squares) in sq_arr.into_iter().enumerate() {
                banks[i].push(Some(LocalTxBeaverBundle {
                    squares,
                    star: LocalBeaverStar16 {
                        b_v_i: bv_shares[i],
                        a_i: star_a[i],
                        c_i: star_c[i],
                    },
                    triple: LocalBeaverTriple {
                        ta_i: ta[i],
                        tb_i: tb[i],
                        tc_i: tc[i],
                    },
                    rho_i: rho[i],
                }));
            }
            for i in 0..DIST_NUM_VALIDATORS {
                zeroize_u128_slice(&mut star_a[i]);
                zeroize_u128_slice(&mut star_c[i]);
            }
        }
        zeroize_u128_slice(&mut entropy);

        let [b0, b1, b2, b3] = banks;
        [
            Self { slots: b0 },
            Self { slots: b1 },
            Self { slots: b2 },
            Self { slots: b3 },
        ]
    }

    /// Take and permanently consume the single-use bundle for `tx_id`.
    pub fn take_for_tx(&mut self, tx_id: u64) -> Result<LocalTxBeaverBundle, DistributedMpcError> {
        let idx = tx_id as usize;
        if idx >= self.slots.len() {
            return Err(DistributedMpcError::BeaverExhausted { tx_id });
        }
        self.slots[idx]
            .take()
            .ok_or(DistributedMpcError::BeaverAlreadyConsumed { tx_id })
    }

    /// Number of remaining unconsumed per-transaction Beaver bundles.
    pub fn remaining(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

// ============================================================================
// Binary Payload Serialization Helpers (Zero JSON!)
// ============================================================================

#[inline]
fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn push_u128(buf: &mut Vec<u8>, v: u128) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u64(slice: &[u8], off: &mut usize) -> Result<u64, DistributedMpcError> {
    if *off + 8 > slice.len() {
        return Err(DistributedMpcError::ProtocolError("truncated u64".to_string()));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&slice[*off..*off + 8]);
    *off += 8;
    Ok(u64::from_le_bytes(b))
}

fn read_u32(slice: &[u8], off: &mut usize) -> Result<u32, DistributedMpcError> {
    if *off + 4 > slice.len() {
        return Err(DistributedMpcError::ProtocolError("truncated u32".to_string()));
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&slice[*off..*off + 4]);
    *off += 4;
    Ok(u32::from_le_bytes(b))
}

fn read_u8(slice: &[u8], off: &mut usize) -> Result<u8, DistributedMpcError> {
    if *off + 1 > slice.len() {
        return Err(DistributedMpcError::ProtocolError("truncated u8".to_string()));
    }
    let v = slice[*off];
    *off += 1;
    Ok(v)
}

fn read_u128(slice: &[u8], off: &mut usize) -> Result<u128, DistributedMpcError> {
    if *off + 16 > slice.len() {
        return Err(DistributedMpcError::ProtocolError("truncated u128".to_string()));
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(&slice[*off..*off + 16]);
    *off += 16;
    Ok(u128::from_le_bytes(b))
}

/// Validator-`i`-specific confidential transfer payload sent from wallet to daemon `V_i`.
///
/// Contains **ONLY validator `i`'s Shamir shares** of `v_bits[16]`, `r_bits[16]`, and
/// `selector[16]`. Volatile-zeroized on `Drop`.
pub struct ClientShareSubmission {
    pub tx_id: u64,
    pub bucket_id: usize,
    pub sender_slot: usize,
    pub v_bits_i: [u128; DIST_RANGE_BITS],
    pub r_bits_i: [u128; DIST_RANGE_BITS],
    pub selector_i: [u128; DIST_BUCKET_SIZE],
}

impl fmt::Debug for ClientShareSubmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientShareSubmission")
            .field("tx_id", &self.tx_id)
            .field("bucket_id", &self.bucket_id)
            .field("sender_slot", &self.sender_slot)
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl ClientShareSubmission {
    /// Compact binary encoding (`8 + 4 + 1 + 48 * 16 = 781` bytes).
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(13 + DIST_SQUARES_PER_TX * 16);
        push_u64(&mut buf, self.tx_id);
        push_u32(&mut buf, self.bucket_id as u32);
        buf.push(self.sender_slot as u8);
        for &v in &self.v_bits_i {
            push_u128(&mut buf, v);
        }
        for &r in &self.r_bits_i {
            push_u128(&mut buf, r);
        }
        for &s in &self.selector_i {
            push_u128(&mut buf, s);
        }
        buf
    }

    fn decode(data: &[u8]) -> Result<Self, DistributedMpcError> {
        let mut off = 0usize;
        let tx_id = read_u64(data, &mut off)?;
        let bucket_id = read_u32(data, &mut off)? as usize;
        let sender_slot = read_u8(data, &mut off)? as usize;
        let mut v_bits_i = [0u128; DIST_RANGE_BITS];
        let mut r_bits_i = [0u128; DIST_RANGE_BITS];
        let mut selector_i = [0u128; DIST_BUCKET_SIZE];
        for v in &mut v_bits_i {
            *v = read_u128(data, &mut off)?;
        }
        for r in &mut r_bits_i {
            *r = read_u128(data, &mut off)?;
        }
        for s in &mut selector_i {
            *s = read_u128(data, &mut off)?;
        }
        if off != data.len() {
            return Err(DistributedMpcError::ProtocolError(
                "trailing bytes in ClientShareSubmission".to_string(),
            ));
        }
        Ok(Self {
            tx_id,
            bucket_id,
            sender_slot,
            v_bits_i,
            r_bits_i,
            selector_i,
        })
    }
}

impl Drop for ClientShareSubmission {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.v_bits_i);
        zeroize_u128_slice(&mut self.r_bits_i);
        zeroize_u128_slice(&mut self.selector_i);
    }
}

/// Compact RTT #1 inter-validator payload: `tx_id`, validator `gamma` contribution, and `65`
/// opening shares (`48` BeaverSquare `d`s + `1` shared `beta` + `16` `alpha_k`s).
struct Rtt1Payload {
    tx_id: u64,
    gamma_contrib: u128,
    openings: [u128; DIST_RTT1_OPENINGS],
}

impl Rtt1Payload {
    const BYTE_LEN: usize = 8 + 16 + DIST_RTT1_OPENINGS * 16;

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::BYTE_LEN);
        push_u64(&mut buf, self.tx_id);
        push_u128(&mut buf, self.gamma_contrib);
        for &v in &self.openings {
            push_u128(&mut buf, v);
        }
        buf
    }

    fn decode(data: &[u8]) -> Result<Self, DistributedMpcError> {
        if data.len() != Self::BYTE_LEN {
            return Err(DistributedMpcError::ProtocolError(
                "invalid RTT1 payload length".to_string(),
            ));
        }
        let mut off = 0usize;
        let tx_id = read_u64(data, &mut off)?;
        let gamma_contrib = read_u128(data, &mut off)?;
        let mut openings = [0u128; DIST_RTT1_OPENINGS];
        for slot in &mut openings {
            *slot = read_u128(data, &mut off)?;
        }
        Ok(Self {
            tx_id,
            gamma_contrib,
            openings,
        })
    }
}

/// Compact RTT #2a inter-validator payload: `tx_id` + 2 blinding-triple openings `(alpha_z, beta_z)`.
struct Rtt2aPayload {
    tx_id: u64,
    alpha_z_i: u128,
    beta_z_i: u128,
}

impl Rtt2aPayload {
    const BYTE_LEN: usize = 8 + 16 + 16;

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::BYTE_LEN);
        push_u64(&mut buf, self.tx_id);
        push_u128(&mut buf, self.alpha_z_i);
        push_u128(&mut buf, self.beta_z_i);
        buf
    }

    fn decode(data: &[u8]) -> Result<Self, DistributedMpcError> {
        if data.len() != Self::BYTE_LEN {
            return Err(DistributedMpcError::ProtocolError(
                "invalid RTT2a payload length".to_string(),
            ));
        }
        let mut off = 0usize;
        Ok(Self {
            tx_id: read_u64(data, &mut off)?,
            alpha_z_i: read_u128(data, &mut off)?,
            beta_z_i: read_u128(data, &mut off)?,
        })
    }
}

/// Compact RTT #2b inter-validator payload: `tx_id` + 1 blinded RLC share `z_blind_i`.
struct Rtt2bPayload {
    tx_id: u64,
    z_blind_i: u128,
}

impl Rtt2bPayload {
    const BYTE_LEN: usize = 8 + 16;

    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::BYTE_LEN);
        push_u64(&mut buf, self.tx_id);
        push_u128(&mut buf, self.z_blind_i);
        buf
    }

    fn decode(data: &[u8]) -> Result<Self, DistributedMpcError> {
        if data.len() != Self::BYTE_LEN {
            return Err(DistributedMpcError::ProtocolError(
                "invalid RTT2b payload length".to_string(),
            ));
        }
        let mut off = 0usize;
        Ok(Self {
            tx_id: read_u64(data, &mut off)?,
            z_blind_i: read_u128(data, &mut off)?,
        })
    }
}

// ============================================================================
// Daemon State & Rendezvous Mailboxes (Strict Single-Share Isolation)
// ============================================================================

/// Single-validator balance shares for one 16-slot anonymity bucket.
/// Holds ONLY validator `i`'s `u128` shares — NEVER any other validator's shares.
struct LocalAnonymityBucket {
    shares: [u128; DIST_BUCKET_SIZE],
}

impl Drop for LocalAnonymityBucket {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.shares);
    }
}

enum PeerRoundMsg {
    Rtt1(Rtt1Payload),
    Rtt2a(Rtt2aPayload),
    Rtt2b(Rtt2bPayload),
    Abort(u8),
}

struct RoundMailbox {
    received: [Option<PeerRoundMsg>; DIST_NUM_VALIDATORS],
    count: usize,
    aborted: Option<u8>,
}

impl RoundMailbox {
    fn new() -> Self {
        Self {
            received: [None, None, None, None],
            count: 0,
            aborted: None,
        }
    }
}

struct PssMailbox {
    deltas: [Option<Vec<u128>>; DIST_NUM_VALIDATORS],
    count: usize,
}

impl PssMailbox {
    fn new() -> Self {
        Self {
            deltas: [None, None, None, None],
            count: 0,
        }
    }
}

impl Drop for PssMailbox {
    fn drop(&mut self) {
        for slot in &mut self.deltas {
            if let Some(mut v) = slot.take() {
                zeroize_u128_slice(&mut v);
            }
        }
    }
}

/// Configuration for launching one independent [`MpcValidatorDaemon`].
pub struct ValidatorDaemonConfig {
    pub validator_id: usize,
    pub bind_addr: SocketAddr,
    pub num_buckets: usize,
    pub beaver_bank: LocalBeaverBank,
    pub peer_in_tapes: [Option<OtpPadTape>; DIST_NUM_VALIDATORS],
    pub peer_out_tapes: [Option<OtpPadTape>; DIST_NUM_VALIDATORS],
    pub client_in_tapes: Vec<OtpPadTape>,
    pub client_out_tapes: Vec<OtpPadTape>,
    pub io_timeout: Duration,
}

struct DaemonInner {
    validator_id: usize,
    listen_addr: SocketAddr,
    num_buckets: usize,
    io_timeout: Duration,
    buckets: Vec<Mutex<LocalAnonymityBucket>>,
    beaver_bank: Mutex<LocalBeaverBank>,
    peer_in_tapes: [Option<Mutex<OtpPadTape>>; DIST_NUM_VALIDATORS],
    peer_out_links: [Option<Mutex<PeerOutLink>>; DIST_NUM_VALIDATORS],
    client_in_tapes: Vec<Mutex<OtpPadTape>>,
    client_out_tapes: Vec<Mutex<OtpPadTape>>,
    mailboxes: Mutex<HashMap<(u64, u8), RoundMailbox>>,
    mailbox_cv: Condvar,
    pss_mailboxes: Mutex<HashMap<u64, PssMailbox>>,
    pss_cv: Condvar,
    peers_connected_in: AtomicUsize,
    peers_ready_mu: Mutex<()>,
    peers_ready_cv: Condvar,
    active_conns: AtomicUsize,
    active_clients: AtomicUsize,
    epoch: AtomicU64,
    committed_txs: AtomicU64,
    aborted_txs: AtomicU64,
    shutdown: AtomicBool,
}

struct PeerOutLink {
    tape: OtpPadTape,
    stream: Option<TcpStream>,
}

/// Completely independent split-share IT-MPC validator TCP server daemon (`V0`, `V1`, `V2`, or `V3`).
///
/// Binds its own `TcpListener`, holds ONLY its single Shamir share per account and per Beaver
/// bundle, communicates with peers exclusively over pairwise OTP+MAC binary TCP sockets, and
/// shuts down cleanly on [`MpcValidatorDaemon::stop`] or `Drop`.
pub struct MpcValidatorDaemon {
    inner: Arc<DaemonInner>,
    accept_handle: Mutex<Option<JoinHandle<()>>>,
    worker_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl fmt::Debug for MpcValidatorDaemon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcValidatorDaemon")
            .field("validator_id", &self.inner.validator_id)
            .field("listen_addr", &self.inner.listen_addr)
            .field("epoch", &self.epoch())
            .field("committed_txs", &self.committed_txs())
            .field("aborted_txs", &self.aborted_txs())
            .finish()
    }
}

impl MpcValidatorDaemon {
    /// Bind a dedicated `TcpListener` and spawn this validator daemon's accept loop.
    pub fn spawn(config: ValidatorDaemonConfig) -> Result<Self, DistributedMpcError> {
        if config.validator_id >= DIST_NUM_VALIDATORS {
            return Err(DistributedMpcError::InvalidParameters(
                "validator_id must be in 0..4",
            ));
        }
        if config.num_buckets == 0 {
            return Err(DistributedMpcError::InvalidParameters(
                "num_buckets must be >= 1",
            ));
        }

        let listener = TcpListener::bind(config.bind_addr)
            .map_err(|e| DistributedMpcError::NetworkError(e.to_string()))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|e| DistributedMpcError::NetworkError(e.to_string()))?;

        let mut buckets = Vec::with_capacity(config.num_buckets);
        for _ in 0..config.num_buckets {
            buckets.push(Mutex::new(LocalAnonymityBucket {
                shares: [0u128; DIST_BUCKET_SIZE],
            }));
        }

        let [in0, in1, in2, in3] = config.peer_in_tapes;
        let peer_in_tapes = [
            in0.map(Mutex::new),
            in1.map(Mutex::new),
            in2.map(Mutex::new),
            in3.map(Mutex::new),
        ];

        let [out0, out1, out2, out3] = config.peer_out_tapes;
        let peer_out_links = [
            out0.map(|tape| Mutex::new(PeerOutLink { tape, stream: None })),
            out1.map(|tape| Mutex::new(PeerOutLink { tape, stream: None })),
            out2.map(|tape| Mutex::new(PeerOutLink { tape, stream: None })),
            out3.map(|tape| Mutex::new(PeerOutLink { tape, stream: None })),
        ];

        let client_in_tapes = config.client_in_tapes.into_iter().map(Mutex::new).collect();
        let client_out_tapes = config
            .client_out_tapes
            .into_iter()
            .map(Mutex::new)
            .collect();

        let inner = Arc::new(DaemonInner {
            validator_id: config.validator_id,
            listen_addr,
            num_buckets: config.num_buckets,
            io_timeout: config.io_timeout,
            buckets,
            beaver_bank: Mutex::new(config.beaver_bank),
            peer_in_tapes,
            peer_out_links,
            client_in_tapes,
            client_out_tapes,
            mailboxes: Mutex::new(HashMap::new()),
            mailbox_cv: Condvar::new(),
            pss_mailboxes: Mutex::new(HashMap::new()),
            pss_cv: Condvar::new(),
            peers_connected_in: AtomicUsize::new(0),
            peers_ready_mu: Mutex::new(()),
            peers_ready_cv: Condvar::new(),
            active_conns: AtomicUsize::new(0),
            active_clients: AtomicUsize::new(0),
            epoch: AtomicU64::new(1),
            committed_txs: AtomicU64::new(0),
            aborted_txs: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
        });

        let worker_handles = Arc::new(Mutex::new(Vec::<JoinHandle<()>>::new()));
        let accept_inner = Arc::clone(&inner);
        let accept_workers = Arc::clone(&worker_handles);

        let accept_handle = thread::Builder::new()
            .name(format!("vernam-v{}-accept", config.validator_id))
            .spawn(move || {
                daemon_accept_loop(listener, accept_inner, accept_workers);
            })
            .map_err(|e| DistributedMpcError::NetworkError(e.to_string()))?;

        Ok(Self {
            inner,
            accept_handle: Mutex::new(Some(accept_handle)),
            worker_handles,
        })
    }

    /// Establish persistent OTP+MAC outgoing TCP links to the other 3 validator daemons.
    pub fn connect_peers(
        &self,
        peer_addrs: [SocketAddr; DIST_NUM_VALIDATORS],
    ) -> Result<(), DistributedMpcError> {
        let my_id = self.inner.validator_id;
        for (peer_id, &addr) in peer_addrs.iter().enumerate() {
            if peer_id == my_id {
                continue;
            }
            let mut stream = TcpStream::connect_timeout(&addr, self.inner.io_timeout)
                .map_err(|e| DistributedMpcError::NetworkError(e.to_string()))?;
            let _ = stream.set_nodelay(true);
            let _ = stream.set_read_timeout(Some(SOCKET_POLL_TIMEOUT));
            let _ = stream.set_write_timeout(Some(self.inner.io_timeout));

            let link_mu = self.inner.peer_out_links[peer_id]
                .as_ref()
                .ok_or(DistributedMpcError::InvalidParameters("missing peer out link"))?;
            let mut link = link_mu.lock().expect("peer out link lock poisoned");
            let hello_payload = [my_id as u8, peer_id as u8];
            let frame = encrypt_and_mac_frame(
                &mut link.tape,
                MSG_PEER_HELLO,
                my_id as u8,
                0,
                &hello_payload,
            )?;
            write_all_frame(&mut stream, &frame)?;
            link.stream = Some(stream);
        }
        Ok(())
    }

    /// Block until all 3 peer daemons have completed their incoming OTP+MAC handshakes.
    pub fn wait_for_peers_ready(&self, timeout: Duration) -> Result<(), DistributedMpcError> {
        let deadline = Instant::now() + timeout;
        let mut guard = self
            .inner
            .peers_ready_mu
            .lock()
            .expect("peers_ready_mu poisoned");
        while self.inner.peers_connected_in.load(Ordering::Acquire) < DIST_NUM_VALIDATORS - 1 {
            if self.inner.shutdown.load(Ordering::Acquire) {
                return Err(DistributedMpcError::Shutdown);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(DistributedMpcError::Timeout("waiting for peer mesh ready"));
            }
            let (g, _) = self
                .inner
                .peers_ready_cv
                .wait_timeout(guard, deadline - now)
                .expect("peers_ready_cv poisoned");
            guard = g;
        }
        Ok(())
    }

    /// Validator ID (`0`, `1`, `2`, or `3`).
    pub fn validator_id(&self) -> usize {
        self.inner.validator_id
    }

    /// Bound TCP listener address of this validator daemon.
    pub fn listen_addr(&self) -> SocketAddr {
        self.inner.listen_addr
    }

    /// Current Proactive Secret Sharing (PSS) epoch (starts at `1`).
    pub fn epoch(&self) -> u64 {
        self.inner.epoch.load(Ordering::Acquire)
    }

    /// Count of confidential transfers committed by this validator daemon.
    pub fn committed_txs(&self) -> u64 {
        self.inner.committed_txs.load(Ordering::Acquire)
    }

    /// Count of confidential transfers rejected/aborted by this validator daemon.
    pub fn aborted_txs(&self) -> u64 {
        self.inner.aborted_txs.load(Ordering::Acquire)
    }

    /// Read **ONLY this validator's single Shamir share** `y_i` for `(bucket_id, slot)`.
    pub fn local_balance_share(
        &self,
        bucket_id: usize,
        slot: usize,
    ) -> Result<u128, DistributedMpcError> {
        if bucket_id >= self.inner.num_buckets {
            return Err(DistributedMpcError::InvalidBucket { bucket_id });
        }
        if slot >= DIST_BUCKET_SIZE {
            return Err(DistributedMpcError::InvalidSlot { slot });
        }
        let b = self.inner.buckets[bucket_id]
            .lock()
            .expect("bucket lock poisoned");
        Ok(b.shares[slot])
    }

    /// Cleanly stop this validator daemon, close peer links, wake waiters, and join all threads.
    pub fn stop(&self) {
        if self.inner.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }

        // Wake all condvar waiters immediately.
        {
            let _g = self.inner.mailboxes.lock().expect("mailboxes poisoned");
            self.inner.mailbox_cv.notify_all();
        }
        {
            let _g = self
                .inner
                .pss_mailboxes
                .lock()
                .expect("pss_mailboxes poisoned");
            self.inner.pss_cv.notify_all();
        }
        {
            let _g = self
                .inner
                .peers_ready_mu
                .lock()
                .expect("peers_ready_mu poisoned");
            self.inner.peers_ready_cv.notify_all();
        }

        // Shut down outgoing peer TCP connections so peer reader threads observe immediate EOF.
        for link_opt in &self.inner.peer_out_links {
            if let Some(link_mu) = link_opt
                && let Ok(mut link) = link_mu.lock()
                && let Some(stream) = link.stream.take()
            {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }

        // Wake the blocking `TcpListener::accept()` with a dummy loopback connect.
        let _ = TcpStream::connect_timeout(&self.inner.listen_addr, Duration::from_millis(50));

        if let Ok(mut guard) = self.accept_handle.lock()
            && let Some(h) = guard.take()
        {
            let _ = h.join();
        }

        let handles = {
            let mut guard = self.worker_handles.lock().expect("worker_handles poisoned");
            std::mem::take(&mut *guard)
        };
        for h in handles {
            let _ = h.join();
        }
    }
}

impl Drop for MpcValidatorDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

// ============================================================================
// Daemon Networking & MPC Protocol Execution
// ============================================================================

struct DaemonConnGuard {
    inner: Arc<DaemonInner>,
}

impl Drop for DaemonConnGuard {
    fn drop(&mut self) {
        self.inner.active_conns.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_daemon_conn(inner: &Arc<DaemonInner>) -> Option<DaemonConnGuard> {
    let mut cur = inner.active_conns.load(Ordering::Acquire);
    loop {
        if cur >= MAX_TOTAL_CONNS {
            return None;
        }
        match inner.active_conns.compare_exchange_weak(
            cur,
            cur + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(DaemonConnGuard {
                    inner: Arc::clone(inner),
                });
            }
            Err(obs) => cur = obs,
        }
    }
}

fn daemon_accept_loop(
    listener: TcpListener,
    inner: Arc<DaemonInner>,
    worker_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    while !inner.shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer_addr)) => {
                if inner.shutdown.load(Ordering::Acquire) {
                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }
                let Some(conn_guard) = try_acquire_daemon_conn(&inner) else {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                };
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(SOCKET_POLL_TIMEOUT));
                let _ = stream.set_write_timeout(Some(inner.io_timeout));

                let conn_inner = Arc::clone(&inner);
                if let Ok(h) = thread::Builder::new()
                    .name(format!("vernam-v{}-conn", inner.validator_id))
                    .spawn(move || {
                        let _guard = conn_guard;
                        handle_incoming_connection(stream, conn_inner);
                    })
                    && let Ok(mut list) = worker_handles.lock()
                {
                    list.push(h);
                    if list.len() >= 16 {
                        list.retain(|jh| !jh.is_finished());
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if inner.shutdown.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn handle_incoming_connection(mut stream: TcpStream, inner: Arc<DaemonInner>) {
    // Read first frame to identify peer link vs wallet client session, strictly capped at
    // MAX_HANDSHAKE_PAYLOAD_BYTES (64 B) so an unauthenticated peer cannot allocate large buffers.
    let first_raw = match read_raw_frame(
        &mut stream,
        Some(&inner.shutdown),
        Some(Instant::now() + inner.io_timeout),
        Some(inner.io_timeout),
        MAX_HANDSHAKE_PAYLOAD_BYTES,
    ) {
        Ok(Some(raw)) => raw,
        _ => return,
    };

    if first_raw.len() < FRAME_HEADER_LEN {
        return;
    }
    let mut hdr_bytes = [0u8; FRAME_HEADER_LEN];
    hdr_bytes.copy_from_slice(&first_raw[..FRAME_HEADER_LEN]);
    let hdr = match WireFrameHeader::decode(&hdr_bytes) {
        Ok(h) => h,
        Err(_) => return,
    };

    match hdr.msg_type {
        MSG_PEER_HELLO => {
            let peer_id = hdr.sender_id as usize;
            if peer_id >= DIST_NUM_VALIDATORS || peer_id == inner.validator_id {
                return;
            }
            let Some(tape_mu) = inner.peer_in_tapes[peer_id].as_ref() else {
                return;
            };
            let verified = {
                let mut tape = tape_mu.lock().expect("peer_in_tape poisoned");
                verify_and_decrypt_frame(&mut tape, &first_raw)
            };
            let Ok((_, payload)) = verified else {
                return;
            };
            if payload.len() != 2
                || payload[0] as usize != peer_id
                || payload[1] as usize != inner.validator_id
            {
                return;
            }

            inner.peers_connected_in.fetch_add(1, Ordering::AcqRel);
            {
                let _g = inner.peers_ready_mu.lock().expect("peers_ready_mu poisoned");
                inner.peers_ready_cv.notify_all();
            }

            run_peer_reader_loop(stream, inner, peer_id);
        }
        MSG_CLIENT_HELLO => {
            let client_id = hdr.flags as usize;
            if client_id >= inner.client_in_tapes.len() {
                return;
            }
            // Enforce bounded concurrent client sessions.
            let prev = inner.active_clients.fetch_add(1, Ordering::AcqRel);
            if prev >= MAX_CONCURRENT_CLIENTS {
                inner.active_clients.fetch_sub(1, Ordering::AcqRel);
                return;
            }
            let verified = {
                let mut tape = inner.client_in_tapes[client_id]
                    .lock()
                    .expect("client_in_tape poisoned");
                verify_and_decrypt_frame(&mut tape, &first_raw)
            };
            if verified.is_ok() {
                run_client_session_loop(stream, Arc::clone(&inner), client_id);
            }
            inner.active_clients.fetch_sub(1, Ordering::AcqRel);
        }
        _ => {}
    }
}

/// Dedicated persistent reader loop for one incoming peer TCP link (`peer_id -> self`).
fn run_peer_reader_loop(mut stream: TcpStream, inner: Arc<DaemonInner>, peer_id: usize) {
    let tape_mu = inner.peer_in_tapes[peer_id]
        .as_ref()
        .expect("peer_in_tape must exist");
    let max_pss_payload = 12usize.saturating_add(
        inner
            .num_buckets
            .saturating_mul(DIST_BUCKET_SIZE)
            .saturating_mul(16),
    );
    let max_peer_payload = max_pss_payload
        .max(Rtt1Payload::BYTE_LEN)
        .min(MAX_FRAME_PAYLOAD_BYTES);

    while !inner.shutdown.load(Ordering::Acquire) {
        let raw = match read_raw_frame(
            &mut stream,
            Some(&inner.shutdown),
            None,
            Some(inner.io_timeout),
            max_peer_payload,
        ) {
            Ok(Some(raw)) => raw,
            Ok(None) => break,
            Err(_) => break,
        };

        let decoded = {
            let mut tape = tape_mu.lock().expect("peer_in_tape poisoned");
            verify_and_decrypt_frame(&mut tape, &raw)
        };
        let Ok((hdr, mut payload)) = decoded else {
            break;
        };

        match hdr.msg_type {
            MSG_PEER_RTT1 => {
                if let Ok(msg) = Rtt1Payload::decode(&payload) {
                    let tx_id = msg.tx_id;
                    deposit_peer_round_msg(&inner, tx_id, ROUND_RTT1, peer_id, PeerRoundMsg::Rtt1(msg));
                }
            }
            MSG_PEER_RTT2A => {
                if let Ok(msg) = Rtt2aPayload::decode(&payload) {
                    let tx_id = msg.tx_id;
                    deposit_peer_round_msg(
                        &inner,
                        tx_id,
                        ROUND_RTT2A,
                        peer_id,
                        PeerRoundMsg::Rtt2a(msg),
                    );
                }
            }
            MSG_PEER_RTT2B => {
                if let Ok(msg) = Rtt2bPayload::decode(&payload) {
                    let tx_id = msg.tx_id;
                    deposit_peer_round_msg(
                        &inner,
                        tx_id,
                        ROUND_RTT2B,
                        peer_id,
                        PeerRoundMsg::Rtt2b(msg),
                    );
                }
            }
            MSG_PEER_ABORT => {
                if payload.len() >= 10 {
                    let mut off = 0usize;
                    if let (Ok(tx_id), Ok(round), Ok(code)) = (
                        read_u64(&payload, &mut off),
                        read_u8(&payload, &mut off),
                        read_u8(&payload, &mut off),
                    ) {
                        deposit_peer_round_msg(
                            &inner,
                            tx_id,
                            round,
                            peer_id,
                            PeerRoundMsg::Abort(code),
                        );
                    }
                }
            }
            MSG_PEER_PSS_DELTA => {
                let mut off = 0usize;
                if let (Ok(refresh_id), Ok(count)) = (
                    read_u64(&payload, &mut off),
                    read_u32(&payload, &mut off),
                ) {
                    let expected = inner.num_buckets * DIST_BUCKET_SIZE;
                    if count as usize == expected && off + expected * 16 == payload.len() {
                        let mut deltas = Vec::with_capacity(expected);
                        let mut ok = true;
                        for _ in 0..expected {
                            match read_u128(&payload, &mut off) {
                                Ok(v) if v < PRIME_P => deltas.push(v),
                                _ => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            let mut map = inner
                                .pss_mailboxes
                                .lock()
                                .expect("pss_mailboxes poisoned");
                            if map.len() < MAX_PENDING_MAILBOXES || map.contains_key(&refresh_id) {
                                let mb = map.entry(refresh_id).or_insert_with(PssMailbox::new);
                                if mb.deltas[peer_id].is_none() {
                                    mb.deltas[peer_id] = Some(deltas);
                                    mb.count += 1;
                                } else {
                                    zeroize_u128_slice(&mut deltas);
                                }
                                inner.pss_cv.notify_all();
                            } else {
                                zeroize_u128_slice(&mut deltas);
                            }
                        } else {
                            zeroize_u128_slice(&mut deltas);
                        }
                    }
                }
            }
            _ => {}
        }

        zeroize_slice(&mut payload);
    }
}

fn deposit_peer_round_msg(
    inner: &DaemonInner,
    tx_id: u64,
    round: u8,
    peer_id: usize,
    msg: PeerRoundMsg,
) {
    let mut map = inner.mailboxes.lock().expect("mailboxes poisoned");
    if map.len() >= MAX_PENDING_MAILBOXES && !map.contains_key(&(tx_id, round)) {
        return;
    }
    let mb = map.entry((tx_id, round)).or_insert_with(RoundMailbox::new);
    if let PeerRoundMsg::Abort(code) = msg {
        mb.aborted = Some(code);
    } else if mb.received[peer_id].is_none() {
        mb.received[peer_id] = Some(msg);
        mb.count += 1;
    }
    inner.mailbox_cv.notify_all();
}

/// Broadcast a binary payload encrypted under each pairwise OTP+MAC link to the other 3 daemons.
fn broadcast_to_peers(
    inner: &DaemonInner,
    msg_type: u8,
    payload: &[u8],
) -> Result<(), DistributedMpcError> {
    let my_id = inner.validator_id;
    for peer_id in 0..DIST_NUM_VALIDATORS {
        if peer_id == my_id {
            continue;
        }
        let link_mu = inner.peer_out_links[peer_id]
            .as_ref()
            .ok_or(DistributedMpcError::ProtocolError("missing peer link".to_string()))?;
        let mut link = link_mu.lock().expect("peer out link poisoned");
        let frame = encrypt_and_mac_frame(&mut link.tape, msg_type, my_id as u8, 0, payload)?;
        let stream = link
            .stream
            .as_mut()
            .ok_or(DistributedMpcError::NetworkError("peer stream not connected".to_string()))?;
        write_all_frame(stream, &frame)?;
    }
    Ok(())
}

fn broadcast_peer_abort(inner: &DaemonInner, tx_id: u64, round: u8, code: u8) {
    let mut buf = Vec::with_capacity(10);
    push_u64(&mut buf, tx_id);
    buf.push(round);
    buf.push(code);
    let _ = broadcast_to_peers(inner, MSG_PEER_ABORT, &buf);
}

fn wait_for_peer_round(
    inner: &DaemonInner,
    tx_id: u64,
    round: u8,
) -> Result<RoundMailbox, DistributedMpcError> {
    let deadline = Instant::now() + inner.io_timeout;
    let mut map = inner.mailboxes.lock().expect("mailboxes poisoned");
    loop {
        if inner.shutdown.load(Ordering::Acquire) {
            return Err(DistributedMpcError::Shutdown);
        }
        if let Some(mb) = map.get(&(tx_id, round)) {
            if let Some(code) = mb.aborted {
                let _ = map.remove(&(tx_id, round));
                return Err(status_code_to_err(code, 0));
            }
            if mb.count >= DIST_NUM_VALIDATORS - 1 {
                return Ok(map
                    .remove(&(tx_id, round))
                    .expect("mailbox just checked present"));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            let _ = map.remove(&(tx_id, round));
            return Err(DistributedMpcError::Timeout("waiting for peer MPC round"));
        }
        let (g, _) = inner
            .mailbox_cv
            .wait_timeout(map, deadline - now)
            .expect("mailbox_cv poisoned");
        map = g;
    }
}

/// Persistent client session loop on daemon `V_i`.
fn run_client_session_loop(mut stream: TcpStream, inner: Arc<DaemonInner>, client_id: usize) {
    while !inner.shutdown.load(Ordering::Acquire) {
        let raw = match read_raw_frame(
            &mut stream,
            Some(&inner.shutdown),
            None,
            Some(inner.io_timeout),
            MAX_CLIENT_PAYLOAD_BYTES,
        ) {
            Ok(Some(raw)) => raw,
            Ok(None) => break,
            Err(_) => break,
        };

        let decoded = {
            let mut tape = inner.client_in_tapes[client_id]
                .lock()
                .expect("client_in_tape poisoned");
            verify_and_decrypt_frame(&mut tape, &raw)
        };
        let (hdr, mut payload) = match decoded {
            Ok(v) => v,
            Err(e) => {
                let _ = send_client_error(&mut stream, &inner, client_id, &e);
                break;
            }
        };

        let send_res = match hdr.msg_type {
            MSG_CLIENT_MINT => handle_client_mint(&mut stream, &inner, client_id, &payload),
            MSG_CLIENT_TRANSFER => handle_client_transfer(&mut stream, &inner, client_id, &payload),
            MSG_CLIENT_QUERY_BALANCE => {
                handle_client_query_balance(&mut stream, &inner, client_id, &payload)
            }
            MSG_CLIENT_PSS_REFRESH => {
                handle_client_pss_refresh(&mut stream, &inner, client_id, &payload)
            }
            _ => send_client_error(
                &mut stream,
                &inner,
                client_id,
                &DistributedMpcError::ProtocolError("unknown client msg_type".to_string()),
            ),
        };
        zeroize_slice(&mut payload);

        if send_res.is_err() {
            break;
        }
    }
}

fn send_client_reply(
    stream: &mut TcpStream,
    inner: &DaemonInner,
    client_id: usize,
    msg_type: u8,
    payload: &[u8],
) -> Result<(), DistributedMpcError> {
    let frame = {
        let mut tape = inner.client_out_tapes[client_id]
            .lock()
            .expect("client_out_tape poisoned");
        encrypt_and_mac_frame(
            &mut tape,
            msg_type,
            inner.validator_id as u8,
            client_id as u16,
            payload,
        )?
    };
    write_all_frame(stream, &frame)
}

fn send_client_error(
    stream: &mut TcpStream,
    inner: &DaemonInner,
    client_id: usize,
    err: &DistributedMpcError,
) -> Result<(), DistributedMpcError> {
    let (code, residual) = err_to_status_code(err);
    let mut buf = Vec::with_capacity(17);
    buf.push(code);
    push_u128(&mut buf, residual);
    send_client_reply(stream, inner, client_id, MSG_DAEMON_ERROR, &buf)
}

fn handle_client_mint(
    stream: &mut TcpStream,
    inner: &DaemonInner,
    client_id: usize,
    payload: &[u8],
) -> Result<(), DistributedMpcError> {
    let mut off = 0usize;
    let bucket_id = read_u32(payload, &mut off)? as usize;
    let slot = read_u8(payload, &mut off)? as usize;
    let mut share_i = read_u128(payload, &mut off)?;
    if bucket_id >= inner.num_buckets {
        zeroize_u128(&mut share_i);
        return send_client_error(
            stream,
            inner,
            client_id,
            &DistributedMpcError::InvalidBucket { bucket_id },
        );
    }
    if slot >= DIST_BUCKET_SIZE {
        zeroize_u128(&mut share_i);
        return send_client_error(
            stream,
            inner,
            client_id,
            &DistributedMpcError::InvalidSlot { slot },
        );
    }
    if share_i >= PRIME_P {
        zeroize_u128(&mut share_i);
        return send_client_error(
            stream,
            inner,
            client_id,
            &DistributedMpcError::FieldElementOutOfRange,
        );
    }

    {
        let mut bucket = inner.buckets[bucket_id]
            .lock()
            .expect("bucket lock poisoned");
        bucket.shares[slot] = add_mod(bucket.shares[slot], share_i);
    }
    zeroize_u128(&mut share_i);

    let mut ack = Vec::with_capacity(5);
    push_u32(&mut ack, bucket_id as u32);
    ack.push(slot as u8);
    send_client_reply(stream, inner, client_id, MSG_DAEMON_MINT_ACK, &ack)
}

fn handle_client_query_balance(
    stream: &mut TcpStream,
    inner: &DaemonInner,
    client_id: usize,
    payload: &[u8],
) -> Result<(), DistributedMpcError> {
    let mut off = 0usize;
    let bucket_id = read_u32(payload, &mut off)? as usize;
    let slot = read_u8(payload, &mut off)? as usize;
    if bucket_id >= inner.num_buckets {
        return send_client_error(
            stream,
            inner,
            client_id,
            &DistributedMpcError::InvalidBucket { bucket_id },
        );
    }
    if slot >= DIST_BUCKET_SIZE {
        return send_client_error(
            stream,
            inner,
            client_id,
            &DistributedMpcError::InvalidSlot { slot },
        );
    }
    let share_i = {
        let bucket = inner.buckets[bucket_id]
            .lock()
            .expect("bucket lock poisoned");
        bucket.shares[slot]
    };
    let epoch = inner.epoch.load(Ordering::Acquire);
    let mut reply = Vec::with_capacity(24);
    push_u64(&mut reply, epoch);
    push_u128(&mut reply, share_i);
    let res = send_client_reply(stream, inner, client_id, MSG_DAEMON_BALANCE_REPLY, &reply);
    zeroize_slice(&mut reply);
    res
}

/// Execute the 2-phase networked split-share IT-MPC transfer on validator daemon `V_i`.
fn handle_client_transfer(
    stream: &mut TcpStream,
    inner: &DaemonInner,
    client_id: usize,
    payload: &[u8],
) -> Result<(), DistributedMpcError> {
    let sub = ClientShareSubmission::decode(payload)?;
    let tx_id = sub.tx_id;

    let result = execute_daemon_transfer(inner, &sub);
    match result {
        Ok(()) => {
            inner.committed_txs.fetch_add(1, Ordering::AcqRel);
            let mut reply = Vec::with_capacity(25);
            push_u64(&mut reply, tx_id);
            reply.push(TX_STATUS_COMMITTED);
            push_u128(&mut reply, 0);
            send_client_reply(stream, inner, client_id, MSG_DAEMON_TX_REPLY, &reply)
        }
        Err(ref err) => {
            inner.aborted_txs.fetch_add(1, Ordering::AcqRel);
            let (code, residual) = err_to_status_code(err);
            let mut reply = Vec::with_capacity(25);
            push_u64(&mut reply, tx_id);
            reply.push(code);
            push_u128(&mut reply, residual);
            send_client_reply(stream, inner, client_id, MSG_DAEMON_TX_REPLY, &reply)
        }
    }
}

/// Core split-share IT-MPC protocol executed independently by validator `V_i`:
/// - **RTT #1:** Exchanges `65` opening shares (`48` BeaverSquare `d`s + `1` shared `beta` +
///   `16` `alpha_k`s) + `gamma_contrib_i` in ONE pairwise OTP+MAC binary packet per peer, and
///   independently checks degree-2 Lagrange parity `[1, P - 3, 3, P - 1]` on all 65 openings.
/// - **RTT #2:** Locally evaluates the 50-check Schwartz-Zippel RLC `[Z]_i`, performs 1-triple
///   multiplicative blinding `[Z_blind] = [rho] * [Z]` (tiny 2-field `(alpha_z, beta_z)` exchange
///   followed by tiny 1-field `Z_blind` opening), verifies degree-2 parity and `Z_blind == 0`,
///   and atomically updates ONLY `V_i`'s local balance shares.
fn execute_daemon_transfer(
    inner: &DaemonInner,
    sub: &ClientShareSubmission,
) -> Result<(), DistributedMpcError> {
    let tx_id = sub.tx_id;
    let my_id = inner.validator_id;

    if sub.bucket_id >= inner.num_buckets {
        broadcast_peer_abort(inner, tx_id, ROUND_RTT1, TX_STATUS_INVALID_BUCKET);
        return Err(DistributedMpcError::InvalidBucket {
            bucket_id: sub.bucket_id,
        });
    }
    if sub.sender_slot >= DIST_BUCKET_SIZE {
        broadcast_peer_abort(inner, tx_id, ROUND_RTT1, TX_STATUS_INVALID_SLOT);
        return Err(DistributedMpcError::InvalidSlot {
            slot: sub.sender_slot,
        });
    }

    // Validate all incoming client shares are canonical `< PRIME_P`.
    for &x in sub
        .v_bits_i
        .iter()
        .chain(sub.r_bits_i.iter())
        .chain(sub.selector_i.iter())
    {
        if x >= PRIME_P {
            broadcast_peer_abort(inner, tx_id, ROUND_RTT1, TX_STATUS_FIELD_OUT_OF_RANGE);
            return Err(DistributedMpcError::FieldElementOutOfRange);
        }
    }

    // Take strictly single-use local Beaver bundle for `tx_id` (wiped automatically on Drop).
    let bundle = {
        let mut bank = inner.beaver_bank.lock().expect("beaver_bank poisoned");
        match bank.take_for_tx(tx_id) {
            Ok(b) => b,
            Err(e) => {
                let (code, _) = err_to_status_code(&e);
                broadcast_peer_abort(inner, tx_id, ROUND_RTT1, code);
                return Err(e);
            }
        }
    };

    // Lock ONLY this bucket for atomic read-verify-update on `V_i`.
    let mut bucket = inner.buckets[sub.bucket_id]
        .lock()
        .expect("bucket lock poisoned");

    // Local zero-mul Horner bit recomposition: [v]_i and [r]_i.
    let mut v_i = 0u128;
    let mut r_i = 0u128;
    for j in (0..DIST_RANGE_BITS).rev() {
        v_i = add_mod(add_mod(v_i, v_i), sub.v_bits_i[j]);
        r_i = add_mod(add_mod(r_i, r_i), sub.r_bits_i[j]);
    }

    // Compute local 65 opening shares for Network RTT #1:
    // [0..16]: v_bits - sq.a
    // [16..32]: r_bits - sq.a
    // [32..48]: selector - sq.a
    // [48]: beta = v - star.b_v
    // [49..65]: alpha_k = selector_k - star.a_k
    let mut my_rtt1 = [0u128; DIST_RTT1_OPENINGS];
    for j in 0..DIST_RANGE_BITS {
        my_rtt1[j] = sub_mod(sub.v_bits_i[j], bundle.squares[j].a_i);
    }
    for j in 0..DIST_RANGE_BITS {
        my_rtt1[16 + j] = sub_mod(sub.r_bits_i[j], bundle.squares[16 + j].a_i);
    }
    for k in 0..DIST_BUCKET_SIZE {
        my_rtt1[32 + k] = sub_mod(sub.selector_i[k], bundle.squares[32 + k].a_i);
    }
    my_rtt1[48] = sub_mod(v_i, bundle.star.b_v_i);
    for k in 0..DIST_BUCKET_SIZE {
        my_rtt1[49 + k] = sub_mod(sub.selector_i[k], bundle.star.a_i[k]);
    }

    let my_gamma_contrib = random_field_elem_fast();

    // ---- Network RTT #1: single compact OTP+MAC binary packet to all 3 peers ----
    let rtt1_pkt = Rtt1Payload {
        tx_id,
        gamma_contrib: my_gamma_contrib,
        openings: my_rtt1,
    };
    let mut rtt1_bytes = rtt1_pkt.encode();
    broadcast_to_peers(inner, MSG_PEER_RTT1, &rtt1_bytes)?;
    zeroize_slice(&mut rtt1_bytes);

    let mut rtt1_mb = wait_for_peer_round(inner, tx_id, ROUND_RTT1)?;

    // Assemble all 4 validators' RTT #1 opening shares and gamma contributions.
    let mut all_rtt1 = [[0u128; DIST_RTT1_OPENINGS]; DIST_NUM_VALIDATORS];
    let mut gamma_contribs = [0u128; DIST_NUM_VALIDATORS];
    all_rtt1[my_id] = my_rtt1;
    gamma_contribs[my_id] = my_gamma_contrib;

    for peer_id in 0..DIST_NUM_VALIDATORS {
        if peer_id == my_id {
            continue;
        }
        match rtt1_mb.received[peer_id].take() {
            Some(PeerRoundMsg::Rtt1(p)) => {
                if p.gamma_contrib >= PRIME_P {
                    zeroize_u128(&mut v_i);
                    zeroize_u128(&mut r_i);
                    return Err(DistributedMpcError::FieldElementOutOfRange);
                }
                all_rtt1[peer_id] = p.openings;
                gamma_contribs[peer_id] = p.gamma_contrib;
            }
            _ => {
                zeroize_u128(&mut v_i);
                zeroize_u128(&mut r_i);
                return Err(DistributedMpcError::ProtocolError(
                    "missing peer RTT1 message".to_string(),
                ));
            }
        }
    }

    // Independently check degree-2 Lagrange parity `[1, P - 3, 3, P - 1]` and reconstruct all 65.
    let mut opened = [0u128; DIST_RTT1_OPENINGS];
    for idx in 0..DIST_RTT1_OPENINGS {
        let shares = [
            all_rtt1[0][idx],
            all_rtt1[1][idx],
            all_rtt1[2][idx],
            all_rtt1[3][idx],
        ];
        match reconstruct_4_verified(&shares) {
            Ok(val) => opened[idx] = val,
            Err(e) => {
                zeroize_u128(&mut v_i);
                zeroize_u128(&mut r_i);
                zeroize_u128_slice(&mut opened);
                return Err(e);
            }
        }
    }

    // Joint unpredictability: `gamma = sum(gamma_contrib_i) mod P` (fallback 1 if 0).
    let mut gamma = add_mod(
        add_mod(gamma_contribs[0], gamma_contribs[1]),
        add_mod(gamma_contribs[2], gamma_contribs[3]),
    );
    if gamma == 0 {
        gamma = 1;
    }

    // ---- Local Schwartz-Zippel RLC evaluation across all 50 invariant checks ----
    let mut z_i = 0u128;
    let mut z_const = 0u128;

    // Checks #1..#48: Boolean checks x*(x - 1) = a^2 + (2*d - 1)*a + d*(d - 1) == 0.
    for m in 0..DIST_SQUARES_PER_TX {
        let d = opened[m];
        let two_d_minus_1 = sub_mod(add_mod(d, d), 1);
        let d_dm1 = mul_mod(d, sub_mod(d, 1));
        let sq = &bundle.squares[m];
        let term_i = add_mod(mul_mod(two_d_minus_1, sq.a_i), sq.a_sq_i);
        z_i = add_mod(mul_mod(z_i, gamma), term_i);
        z_const = add_mod(mul_mod(z_const, gamma), d_dm1);
    }

    // Check #49: Balance conservation `B_sender - v - r == 0`.
    let sender_bal_i = bucket.shares[sub.sender_slot];
    let eq_i = sub_mod(sub_mod(sender_bal_i, v_i), r_i);
    zeroize_u128(&mut r_i);
    z_i = add_mod(mul_mod(z_i, gamma), eq_i);
    z_const = mul_mod(z_const, gamma);

    // Check #50: One-hot selector sum `sum(s_k) - 1 == 0`.
    let mut sum_s_i = 0u128;
    for &sk in &sub.selector_i {
        sum_s_i = add_mod(sum_s_i, sk);
    }
    z_i = add_mod(mul_mod(z_i, gamma), sum_s_i);
    z_const = add_mod(mul_mod(z_const, gamma), PRIME_P - 1);

    let mut z_final_i = add_mod(z_i, z_const);
    zeroize_u128(&mut z_i);

    // ---- Network RTT #2a: Tiny 2-field blinding triple openings (alpha_z, beta_z) ----
    let alpha_z_i = sub_mod(bundle.rho_i, bundle.triple.ta_i);
    let beta_z_i = sub_mod(z_final_i, bundle.triple.tb_i);
    zeroize_u128(&mut z_final_i);

    let rtt2a_pkt = Rtt2aPayload {
        tx_id,
        alpha_z_i,
        beta_z_i,
    };
    let mut rtt2a_bytes = rtt2a_pkt.encode();
    broadcast_to_peers(inner, MSG_PEER_RTT2A, &rtt2a_bytes)?;
    zeroize_slice(&mut rtt2a_bytes);

    let mut rtt2a_mb = wait_for_peer_round(inner, tx_id, ROUND_RTT2A)?;
    let mut alpha_z_shares = [0u128; DIST_NUM_VALIDATORS];
    let mut beta_z_shares = [0u128; DIST_NUM_VALIDATORS];
    alpha_z_shares[my_id] = alpha_z_i;
    beta_z_shares[my_id] = beta_z_i;
    for peer_id in 0..DIST_NUM_VALIDATORS {
        if peer_id == my_id {
            continue;
        }
        match rtt2a_mb.received[peer_id].take() {
            Some(PeerRoundMsg::Rtt2a(p)) => {
                alpha_z_shares[peer_id] = p.alpha_z_i;
                beta_z_shares[peer_id] = p.beta_z_i;
            }
            _ => {
                zeroize_u128(&mut v_i);
                zeroize_u128_slice(&mut opened);
                return Err(DistributedMpcError::ProtocolError(
                    "missing peer RTT2a message".to_string(),
                ));
            }
        }
    }

    let alpha_z = match reconstruct_4_verified(&alpha_z_shares) {
        Ok(v) => v,
        Err(e) => {
            zeroize_u128(&mut v_i);
            zeroize_u128_slice(&mut opened);
            return Err(e);
        }
    };
    let beta_z = match reconstruct_4_verified(&beta_z_shares) {
        Ok(v) => v,
        Err(e) => {
            zeroize_u128(&mut v_i);
            zeroize_u128_slice(&mut opened);
            return Err(e);
        }
    };

    // Local share of `[Z_blind] = [rho] * [Z]`:
    // `tc_i + alpha_z * tb_i + beta_z * ta_i + alpha_z * beta_z (mod PRIME_P)`.
    let z_blind_i = add_mod(
        add_mod(bundle.triple.tc_i, mul_mod(alpha_z, bundle.triple.tb_i)),
        add_mod(
            mul_mod(beta_z, bundle.triple.ta_i),
            mul_mod(alpha_z, beta_z),
        ),
    );

    // ---- Network RTT #2b: Tiny 1-field blinded zero-check opening `Z_blind` ----
    let rtt2b_pkt = Rtt2bPayload { tx_id, z_blind_i };
    let mut rtt2b_bytes = rtt2b_pkt.encode();
    broadcast_to_peers(inner, MSG_PEER_RTT2B, &rtt2b_bytes)?;
    zeroize_slice(&mut rtt2b_bytes);

    let mut rtt2b_mb = wait_for_peer_round(inner, tx_id, ROUND_RTT2B)?;
    let mut z_blind_shares = [0u128; DIST_NUM_VALIDATORS];
    z_blind_shares[my_id] = z_blind_i;
    for peer_id in 0..DIST_NUM_VALIDATORS {
        if peer_id == my_id {
            continue;
        }
        match rtt2b_mb.received[peer_id].take() {
            Some(PeerRoundMsg::Rtt2b(p)) => {
                z_blind_shares[peer_id] = p.z_blind_i;
            }
            _ => {
                zeroize_u128(&mut v_i);
                zeroize_u128_slice(&mut opened);
                return Err(DistributedMpcError::ProtocolError(
                    "missing peer RTT2b message".to_string(),
                ));
            }
        }
    }

    let z_blind = match reconstruct_4_verified(&z_blind_shares) {
        Ok(v) => v,
        Err(e) => {
            zeroize_u128(&mut v_i);
            zeroize_u128_slice(&mut opened);
            return Err(e);
        }
    };

    if z_blind != 0 {
        zeroize_u128(&mut v_i);
        zeroize_u128_slice(&mut opened);
        return Err(DistributedMpcError::RlcCheckFailed {
            blinded_residual: z_blind,
        });
    }

    // ---- Atomic local balance update (ONLY validator `i`'s shares!) ----
    let beta = opened[48];
    bucket.shares[sub.sender_slot] = sub_mod(bucket.shares[sub.sender_slot], v_i);

    for k in 0..DIST_BUCKET_SIZE {
        let alpha_k = opened[49 + k];
        let credit_k_i = add_mod(
            add_mod(
                bundle.star.c_i[k],
                mul_mod(alpha_k, bundle.star.b_v_i),
            ),
            add_mod(
                mul_mod(beta, bundle.star.a_i[k]),
                mul_mod(alpha_k, beta),
            ),
        );
        bucket.shares[k] = add_mod(bucket.shares[k], credit_k_i);
    }

    zeroize_u128(&mut v_i);
    zeroize_u128_slice(&mut opened);
    Ok(())
}

/// Distributed Proactive Secret Sharing (PSS) refresh across all 4 validator daemons over real
/// pairwise OTP+MAC TCP sockets.
///
/// Each validator `V_i` generates a fresh random degree-2 zero-polynomial `h_{i,a}(x) = r1*x + r2*x^2`
/// per account `a`, sends ONLY `h_{i,a}(j + 1)` to peer `V_j` over its pairwise OTP+MAC TCP link,
/// and adds all 4 zero-polynomial evaluations to its local balance shares, rotating to `epoch + 1`.
fn handle_client_pss_refresh(
    stream: &mut TcpStream,
    inner: &DaemonInner,
    client_id: usize,
    payload: &[u8],
) -> Result<(), DistributedMpcError> {
    let mut off = 0usize;
    let refresh_id = read_u64(payload, &mut off)?;
    let my_id = inner.validator_id;
    let total_accounts = inner.num_buckets * DIST_BUCKET_SIZE;

    // Lock all buckets in canonical ascending order (0..num_buckets) -> guaranteed deadlock-free.
    let mut bucket_guards = Vec::with_capacity(inner.num_buckets);
    for b in &inner.buckets {
        bucket_guards.push(b.lock().expect("bucket lock poisoned"));
    }

    // Sample fresh OS-random degree-2 zero-polynomials `0 + r1*x + r2*x^2` for every account.
    let mut rands = vec![0u128; total_accounts * 2];
    fill_random_field_elems(&mut rands);

    let mut my_self_deltas = Vec::with_capacity(total_accounts);
    let mut outgoing: [Vec<u128>; DIST_NUM_VALIDATORS] = [
        Vec::with_capacity(total_accounts),
        Vec::with_capacity(total_accounts),
        Vec::with_capacity(total_accounts),
        Vec::with_capacity(total_accounts),
    ];

    for a in 0..total_accounts {
        let evals = eval_poly_3_of_4(0, rands[2 * a], rands[2 * a + 1]);
        my_self_deltas.push(evals[my_id]);
        for j in 0..DIST_NUM_VALIDATORS {
            if j != my_id {
                outgoing[j].push(evals[j]);
            }
        }
    }
    zeroize_u128_slice(&mut rands);

    // Send ONLY peer `j`'s zero-poly evaluation vector to peer `j` over pairwise OTP+MAC TCP!
    for peer_id in 0..DIST_NUM_VALIDATORS {
        if peer_id == my_id {
            continue;
        }
        let mut msg = Vec::with_capacity(12 + total_accounts * 16);
        push_u64(&mut msg, refresh_id);
        push_u32(&mut msg, total_accounts as u32);
        for &d in &outgoing[peer_id] {
            push_u128(&mut msg, d);
        }
        zeroize_u128_slice(&mut outgoing[peer_id]);

        let link_mu = inner.peer_out_links[peer_id]
            .as_ref()
            .ok_or(DistributedMpcError::ProtocolError("missing peer link".to_string()))?;
        let mut link = link_mu.lock().expect("peer out link poisoned");
        let frame =
            encrypt_and_mac_frame(&mut link.tape, MSG_PEER_PSS_DELTA, my_id as u8, 0, &msg)?;
        zeroize_slice(&mut msg);
        let peer_stream = link
            .stream
            .as_mut()
            .ok_or(DistributedMpcError::NetworkError("peer stream not connected".to_string()))?;
        write_all_frame(peer_stream, &frame)?;
    }

    // Wait for all 3 peers' zero-poly delta vectors.
    let deadline = Instant::now() + inner.io_timeout;
    let mb = {
        let mut map = inner
            .pss_mailboxes
            .lock()
            .expect("pss_mailboxes poisoned");
        loop {
            if inner.shutdown.load(Ordering::Acquire) {
                zeroize_u128_slice(&mut my_self_deltas);
                return Err(DistributedMpcError::Shutdown);
            }
            if let Some(m) = map.get(&refresh_id)
                && m.count >= DIST_NUM_VALIDATORS - 1
            {
                break map.remove(&refresh_id).expect("pss mailbox present");
            }
            let now = Instant::now();
            if now >= deadline {
                let _ = map.remove(&refresh_id);
                zeroize_u128_slice(&mut my_self_deltas);
                return send_client_error(
                    stream,
                    inner,
                    client_id,
                    &DistributedMpcError::Timeout("waiting for peer PSS deltas"),
                );
            }
            let (g, _) = inner
                .pss_cv
                .wait_timeout(map, deadline - now)
                .expect("pss_cv poisoned");
            map = g;
        }
    };

    // Apply all 4 zero-polynomial deltas atomically to every local balance share.
    for b_idx in 0..inner.num_buckets {
        for slot in 0..DIST_BUCKET_SIZE {
            let acc_idx = b_idx * DIST_BUCKET_SIZE + slot;
            let mut sum_delta = my_self_deltas[acc_idx];
            for peer_id in 0..DIST_NUM_VALIDATORS {
                if peer_id == my_id {
                    continue;
                }
                if let Some(ref peer_vec) = mb.deltas[peer_id] {
                    sum_delta = add_mod(sum_delta, peer_vec[acc_idx]);
                }
            }
            bucket_guards[b_idx].shares[slot] =
                add_mod(bucket_guards[b_idx].shares[slot], sum_delta);
        }
    }
    zeroize_u128_slice(&mut my_self_deltas);
    drop(mb);

    let new_epoch = inner.epoch.fetch_add(1, Ordering::AcqRel) + 1;
    let mut ack = Vec::with_capacity(20);
    push_u64(&mut ack, refresh_id);
    push_u64(&mut ack, new_epoch);
    push_u32(&mut ack, total_accounts as u32);
    send_client_reply(stream, inner, client_id, MSG_DAEMON_PSS_ACK, &ack)
}

fn err_to_status_code(err: &DistributedMpcError) -> (u8, u128) {
    match err {
        DistributedMpcError::RlcCheckFailed { blinded_residual } => {
            (TX_STATUS_RLC_FAILED, *blinded_residual)
        }
        DistributedMpcError::InconsistentShares => (TX_STATUS_INCONSISTENT_SHARES, 0),
        DistributedMpcError::FieldElementOutOfRange => (TX_STATUS_FIELD_OUT_OF_RANGE, 0),
        DistributedMpcError::BeaverExhausted { .. } => (TX_STATUS_BEAVER_EXHAUSTED, 0),
        DistributedMpcError::BeaverAlreadyConsumed { .. } => (TX_STATUS_BEAVER_REUSED, 0),
        DistributedMpcError::InvalidBucket { .. } => (TX_STATUS_INVALID_BUCKET, 0),
        DistributedMpcError::InvalidSlot { .. } => (TX_STATUS_INVALID_SLOT, 0),
        DistributedMpcError::Timeout(_) => (TX_STATUS_TIMEOUT, 0),
        _ => (TX_STATUS_PROTOCOL_ERROR, 0),
    }
}

fn status_code_to_err(code: u8, residual: u128) -> DistributedMpcError {
    match code {
        TX_STATUS_RLC_FAILED => DistributedMpcError::RlcCheckFailed {
            blinded_residual: residual,
        },
        TX_STATUS_INCONSISTENT_SHARES => DistributedMpcError::InconsistentShares,
        TX_STATUS_FIELD_OUT_OF_RANGE => DistributedMpcError::FieldElementOutOfRange,
        TX_STATUS_BEAVER_EXHAUSTED => DistributedMpcError::BeaverExhausted { tx_id: 0 },
        TX_STATUS_BEAVER_REUSED => DistributedMpcError::BeaverAlreadyConsumed { tx_id: 0 },
        TX_STATUS_INVALID_BUCKET => DistributedMpcError::InvalidBucket { bucket_id: 0 },
        TX_STATUS_INVALID_SLOT => DistributedMpcError::InvalidSlot { slot: 0 },
        TX_STATUS_TIMEOUT => DistributedMpcError::Timeout("daemon reported timeout"),
        _ => DistributedMpcError::ProtocolError(format!("daemon rejected with status {code}")),
    }
}

// ============================================================================
// Cluster Provisioner (`DistributedMpcCluster`) & Wallet Client
// ============================================================================

/// Configuration for spawning a complete 4-daemon split-share IT-MPC cluster over real TCP.
#[derive(Debug, Clone)]
pub struct DistributedClusterConfig {
    pub num_buckets: usize,
    pub beaver_tx_capacity: usize,
    pub num_clients: usize,
    pub io_timeout: Duration,
}

impl Default for DistributedClusterConfig {
    fn default() -> Self {
        Self {
            num_buckets: 4,
            beaver_tx_capacity: 256,
            num_clients: 1,
            io_timeout: Duration::from_secs(5),
        }
    }
}

/// Receipt returned by [`DistributedWalletClient::send_shielded`] upon 4-daemon commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReceipt {
    pub tx_id: u64,
    pub committed_validators: usize,
    pub rtt_us: u64,
}

/// Summary returned by [`DistributedWalletClient::trigger_distributed_pss_refresh`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PssRefreshReport {
    pub refresh_id: u64,
    pub new_epoch: u64,
    pub accounts_refreshed: usize,
    pub elapsed_us: u64,
}

struct ClientDaemonLink {
    addr: SocketAddr,
    stream: Option<TcpStream>,
    out_tape: OtpPadTape,
    in_tape: OtpPadTape,
}

/// Split-share networked wallet client communicating with all 4 independent [`MpcValidatorDaemon`]s
/// over persistent pairwise OTP+MAC encrypted binary TCP sockets.
pub struct DistributedWalletClient {
    client_id: usize,
    links: [ClientDaemonLink; DIST_NUM_VALIDATORS],
    tx_id_counter: Arc<AtomicU64>,
    refresh_id_counter: Arc<AtomicU64>,
    io_timeout: Duration,
}

impl fmt::Debug for DistributedWalletClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DistributedWalletClient")
            .field("client_id", &self.client_id)
            .field(
                "daemon_addrs",
                &[
                    self.links[0].addr,
                    self.links[1].addr,
                    self.links[2].addr,
                    self.links[3].addr,
                ],
            )
            .finish()
    }
}

impl DistributedWalletClient {
    fn connect(
        client_id: usize,
        addrs: [SocketAddr; DIST_NUM_VALIDATORS],
        out_tapes: [OtpPadTape; DIST_NUM_VALIDATORS],
        in_tapes: [OtpPadTape; DIST_NUM_VALIDATORS],
        tx_id_counter: Arc<AtomicU64>,
        refresh_id_counter: Arc<AtomicU64>,
        io_timeout: Duration,
    ) -> Result<Self, DistributedMpcError> {
        let [ot0, ot1, ot2, ot3] = out_tapes;
        let [it0, it1, it2, it3] = in_tapes;
        let mut links = [
            ClientDaemonLink {
                addr: addrs[0],
                stream: None,
                out_tape: ot0,
                in_tape: it0,
            },
            ClientDaemonLink {
                addr: addrs[1],
                stream: None,
                out_tape: ot1,
                in_tape: it1,
            },
            ClientDaemonLink {
                addr: addrs[2],
                stream: None,
                out_tape: ot2,
                in_tape: it2,
            },
            ClientDaemonLink {
                addr: addrs[3],
                stream: None,
                out_tape: ot3,
                in_tape: it3,
            },
        ];

        for (i, link) in links.iter_mut().enumerate() {
            let mut stream = TcpStream::connect_timeout(&link.addr, io_timeout)
                .map_err(|e| DistributedMpcError::NetworkError(e.to_string()))?;
            let _ = stream.set_nodelay(true);
            let _ = stream.set_read_timeout(Some(SOCKET_POLL_TIMEOUT));
            let _ = stream.set_write_timeout(Some(io_timeout));

            let hello = [client_id as u8, i as u8];
            let frame = encrypt_and_mac_frame(
                &mut link.out_tape,
                MSG_CLIENT_HELLO,
                0xFF,
                client_id as u16,
                &hello,
            )?;
            write_all_frame(&mut stream, &frame)?;
            link.stream = Some(stream);
        }

        Ok(Self {
            client_id,
            links,
            tx_id_counter,
            refresh_id_counter,
            io_timeout,
        })
    }

    /// Client identifier.
    pub fn client_id(&self) -> usize {
        self.client_id
    }

    /// Allocate the next monotonic transaction ID (useful when building custom raw submissions).
    pub fn allocate_tx_id(&self) -> u64 {
        self.tx_id_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Split `amount` into `(3, 4)` Shamir shares locally and mint ONLY share `y_i` onto daemon
    /// `V_i` over its pairwise OTP+MAC TCP link.
    pub fn mint_split_shares(
        &mut self,
        bucket_id: usize,
        slot: usize,
        amount: u128,
    ) -> Result<(), DistributedMpcError> {
        if slot >= DIST_BUCKET_SIZE {
            return Err(DistributedMpcError::InvalidSlot { slot });
        }
        let mut shares = split_secret_3_of_4(amount)?;

        for i in 0..DIST_NUM_VALIDATORS {
            let mut payload = Vec::with_capacity(21);
            push_u32(&mut payload, bucket_id as u32);
            payload.push(slot as u8);
            push_u128(&mut payload, shares[i]);
            let link = &mut self.links[i];
            let frame = encrypt_and_mac_frame(
                &mut link.out_tape,
                MSG_CLIENT_MINT,
                0xFF,
                self.client_id as u16,
                &payload,
            )?;
            zeroize_slice(&mut payload);
            let stream = link
                .stream
                .as_mut()
                .ok_or(DistributedMpcError::NetworkError("daemon disconnected".to_string()))?;
            write_all_frame(stream, &frame)?;
        }
        zeroize_u128_slice(&mut shares);

        let deadline = Instant::now() + self.io_timeout;
        for i in 0..DIST_NUM_VALIDATORS {
            let (hdr, payload) = self.read_reply_from(i, deadline)?;
            if hdr.msg_type == MSG_DAEMON_ERROR {
                return Err(decode_error_payload(&payload));
            }
            if hdr.msg_type != MSG_DAEMON_MINT_ACK {
                return Err(DistributedMpcError::ProtocolError(
                    "unexpected mint ack msg_type".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Construct 4 validator-specific split-share payloads locally, encrypt payload `i` under the
    /// wallet-to-`V_i` single-use OTP+MAC link, and execute a full 16-bit + 16-slot confidential
    /// transfer across all 4 independent TCP validator daemons.
    pub fn send_shielded(
        &mut self,
        bucket_id: usize,
        sender_slot: usize,
        sender_balance: u128,
        recipient_slot: usize,
        amount: u128,
    ) -> Result<TransferReceipt, DistributedMpcError> {
        if sender_slot >= DIST_BUCKET_SIZE {
            return Err(DistributedMpcError::InvalidSlot { slot: sender_slot });
        }
        if recipient_slot >= DIST_BUCKET_SIZE {
            return Err(DistributedMpcError::InvalidSlot {
                slot: recipient_slot,
            });
        }
        let max_val = (1u128 << DIST_RANGE_BITS) - 1;
        if amount > max_val || sender_balance < amount || (sender_balance - amount) > max_val {
            return Err(DistributedMpcError::InvalidParameters(
                "amount or remainder outside [0, 2^16)",
            ));
        }

        let tx_id = self.allocate_tx_id();
        let remainder = sender_balance - amount;
        let submissions = build_split_submissions(
            tx_id,
            bucket_id,
            sender_slot,
            amount,
            remainder,
            recipient_slot,
        );
        self.send_raw_submissions(submissions)
    }

    /// Send 4 pre-constructed validator-specific [`ClientShareSubmission`]s over real OTP+MAC TCP
    /// sockets to `V0..V3` and collect all 4 daemons' consensus verdicts.
    pub fn send_raw_submissions(
        &mut self,
        submissions: [ClientShareSubmission; DIST_NUM_VALIDATORS],
    ) -> Result<TransferReceipt, DistributedMpcError> {
        let start = Instant::now();
        let tx_id = submissions[0].tx_id;

        // Push all 4 OTP+MAC encrypted payloads to the 4 daemons concurrently (non-blocking kernel writes).
        for (i, sub) in submissions.iter().enumerate() {
            let mut encoded = sub.encode();
            let link = &mut self.links[i];
            let frame = encrypt_and_mac_frame(
                &mut link.out_tape,
                MSG_CLIENT_TRANSFER,
                0xFF,
                self.client_id as u16,
                &encoded,
            )?;
            zeroize_slice(&mut encoded);
            let stream = link
                .stream
                .as_mut()
                .ok_or(DistributedMpcError::NetworkError("daemon disconnected".to_string()))?;
            write_all_frame(stream, &frame)?;
        }

        // Collect all 4 daemons' signed/MACed verdicts.
        let deadline = Instant::now() + self.io_timeout;
        let mut committed = 0usize;
        let mut first_err: Option<DistributedMpcError> = None;

        for i in 0..DIST_NUM_VALIDATORS {
            match self.read_reply_from(i, deadline) {
                Ok((hdr, payload)) => {
                    if hdr.msg_type == MSG_DAEMON_ERROR {
                        let e = decode_error_payload(&payload);
                        if first_err.is_none() {
                            first_err = Some(e);
                        }
                    } else if hdr.msg_type == MSG_DAEMON_TX_REPLY {
                        let mut off = 0usize;
                        let reply_tx_id = read_u64(&payload, &mut off)?;
                        let status = read_u8(&payload, &mut off)?;
                        let residual = read_u128(&payload, &mut off)?;
                        if reply_tx_id != tx_id {
                            return Err(DistributedMpcError::ProtocolError(
                                "mismatched tx_id in daemon reply".to_string(),
                            ));
                        }
                        if status == TX_STATUS_COMMITTED {
                            committed += 1;
                        } else if first_err.is_none() {
                            first_err = Some(status_code_to_err(status, residual));
                        }
                    } else if first_err.is_none() {
                        first_err = Some(DistributedMpcError::ProtocolError(
                            "unexpected transfer reply msg_type".to_string(),
                        ));
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        if let Some(e) = first_err {
            return Err(e);
        }
        if committed != DIST_NUM_VALIDATORS {
            return Err(DistributedMpcError::InsufficientQuorum {
                available: committed,
                needed: DIST_NUM_VALIDATORS,
            });
        }

        Ok(TransferReceipt {
            tx_id,
            committed_validators: committed,
            rtt_us: start.elapsed().as_micros() as u64,
        })
    }

    /// Query all 4 (or any 3 online) daemons for their encrypted single balance share `y_i` and
    /// reconstruct + degree-verify the true balance **exclusively on the local client machine**.
    pub fn query_balance(
        &mut self,
        bucket_id: usize,
        slot: usize,
    ) -> Result<u128, DistributedMpcError> {
        if slot >= DIST_BUCKET_SIZE {
            return Err(DistributedMpcError::InvalidSlot { slot });
        }
        let mut req_payload = Vec::with_capacity(5);
        push_u32(&mut req_payload, bucket_id as u32);
        req_payload.push(slot as u8);

        let mut queried = [false; DIST_NUM_VALIDATORS];
        for i in 0..DIST_NUM_VALIDATORS {
            let link = &mut self.links[i];
            if link.stream.is_none() {
                continue;
            }
            if let Ok(frame) = encrypt_and_mac_frame(
                &mut link.out_tape,
                MSG_CLIENT_QUERY_BALANCE,
                0xFF,
                self.client_id as u16,
                &req_payload,
            ) {
                if let Some(ref mut s) = link.stream {
                    if write_all_frame(s, &frame).is_ok() {
                        queried[i] = true;
                    } else {
                        link.stream = None;
                    }
                }
            }
        }

        let deadline = Instant::now() + self.io_timeout;
        let mut collected: Vec<(usize, u128)> = Vec::with_capacity(DIST_NUM_VALIDATORS);
        let mut epochs: Vec<u64> = Vec::with_capacity(DIST_NUM_VALIDATORS);

        for i in 0..DIST_NUM_VALIDATORS {
            if !queried[i] {
                continue;
            }
            match self.read_reply_from(i, deadline) {
                Ok((hdr, mut payload)) if hdr.msg_type == MSG_DAEMON_BALANCE_REPLY => {
                    let mut off = 0usize;
                    if let (Ok(epoch), Ok(share_i)) = (
                        read_u64(&payload, &mut off),
                        read_u128(&payload, &mut off),
                    ) {
                        epochs.push(epoch);
                        collected.push((i, share_i));
                    }
                    zeroize_slice(&mut payload);
                }
                Ok((hdr, payload)) if hdr.msg_type == MSG_DAEMON_ERROR => {
                    return Err(decode_error_payload(&payload));
                }
                _ => {
                    self.links[i].stream = None;
                }
            }
        }

        if collected.len() < DIST_THRESHOLD {
            for (_, s) in &mut collected {
                zeroize_u128(s);
            }
            return Err(DistributedMpcError::InsufficientQuorum {
                available: collected.len(),
                needed: DIST_THRESHOLD,
            });
        }

        // Verify all responding daemons are on the same PSS epoch.
        if let Some(&first_ep) = epochs.first()
            && epochs.iter().any(|&ep| ep != first_ep)
        {
            for (_, s) in &mut collected {
                zeroize_u128(s);
            }
            return Err(DistributedMpcError::InconsistentShares);
        }

        let result = if collected.len() == DIST_NUM_VALIDATORS {
            let mut full = [0u128; DIST_NUM_VALIDATORS];
            for &(id, y) in &collected {
                full[id] = y;
            }
            let r = reconstruct_4_verified(&full);
            zeroize_u128_slice(&mut full);
            r
        } else {
            let mut three = [collected[0], collected[1], collected[2]];
            let r = reconstruct_any_3(&three);
            for (_, s) in &mut three {
                zeroize_u128(s);
            }
            r
        };

        for (_, s) in &mut collected {
            zeroize_u128(s);
        }
        result
    }

    /// Trigger a real networked Distributed Proactive Secret Sharing (PSS) refresh across all 4
    /// validator daemons, rotating every account share from Epoch `e` to Epoch `e + 1`.
    pub fn trigger_distributed_pss_refresh(&mut self) -> Result<PssRefreshReport, DistributedMpcError> {
        let start = Instant::now();
        let refresh_id = self.refresh_id_counter.fetch_add(1, Ordering::Relaxed);
        let mut req = Vec::with_capacity(8);
        push_u64(&mut req, refresh_id);

        for i in 0..DIST_NUM_VALIDATORS {
            let link = &mut self.links[i];
            let frame = encrypt_and_mac_frame(
                &mut link.out_tape,
                MSG_CLIENT_PSS_REFRESH,
                0xFF,
                self.client_id as u16,
                &req,
            )?;
            let stream = link
                .stream
                .as_mut()
                .ok_or(DistributedMpcError::NetworkError("daemon disconnected".to_string()))?;
            write_all_frame(stream, &frame)?;
        }

        let deadline = Instant::now() + self.io_timeout;
        let mut agreed_epoch = 0u64;
        let mut accounts = 0usize;

        for i in 0..DIST_NUM_VALIDATORS {
            let (hdr, payload) = self.read_reply_from(i, deadline)?;
            if hdr.msg_type == MSG_DAEMON_ERROR {
                return Err(decode_error_payload(&payload));
            }
            if hdr.msg_type != MSG_DAEMON_PSS_ACK {
                return Err(DistributedMpcError::ProtocolError(
                    "unexpected PSS ack msg_type".to_string(),
                ));
            }
            let mut off = 0usize;
            let ack_id = read_u64(&payload, &mut off)?;
            let new_epoch = read_u64(&payload, &mut off)?;
            let acc_count = read_u32(&payload, &mut off)? as usize;
            if ack_id != refresh_id {
                return Err(DistributedMpcError::ProtocolError(
                    "mismatched refresh_id in PSS ack".to_string(),
                ));
            }
            if i == 0 {
                agreed_epoch = new_epoch;
                accounts = acc_count;
            } else if agreed_epoch != new_epoch {
                return Err(DistributedMpcError::ProtocolError(
                    "validators diverged on PSS epoch".to_string(),
                ));
            }
        }

        Ok(PssRefreshReport {
            refresh_id,
            new_epoch: agreed_epoch,
            accounts_refreshed: accounts,
            elapsed_us: start.elapsed().as_micros() as u64,
        })
    }

    fn read_reply_from(
        &mut self,
        validator_id: usize,
        deadline: Instant,
    ) -> Result<(WireFrameHeader, Vec<u8>), DistributedMpcError> {
        let link = &mut self.links[validator_id];
        let stream = link
            .stream
            .as_mut()
            .ok_or(DistributedMpcError::NetworkError("daemon disconnected".to_string()))?;
        let raw = match read_raw_frame(
            stream,
            None,
            Some(deadline),
            Some(self.io_timeout),
            MAX_DAEMON_REPLY_PAYLOAD_BYTES,
        )? {
            Some(r) => r,
            None => {
                link.stream = None;
                return Err(DistributedMpcError::NetworkError(
                    "daemon closed connection".to_string(),
                ));
            }
        };
        verify_and_decrypt_frame(&mut link.in_tape, &raw)
    }
}

/// Convenience standalone entrypoint for triggering a Distributed PSS Refresh over real TCP.
pub fn trigger_distributed_pss_refresh(
    client: &mut DistributedWalletClient,
) -> Result<PssRefreshReport, DistributedMpcError> {
    client.trigger_distributed_pss_refresh()
}

fn decode_error_payload(payload: &[u8]) -> DistributedMpcError {
    if payload.len() >= 17 {
        let mut off = 0usize;
        if let (Ok(code), Ok(residual)) = (read_u8(payload, &mut off), read_u128(payload, &mut off))
        {
            return status_code_to_err(code, residual);
        }
    }
    DistributedMpcError::ProtocolError("daemon returned malformed error payload".to_string())
}

/// Build 4 validator-specific [`ClientShareSubmission`]s from plaintext amount, remainder, and
/// recipient slot using pure OS entropy, immediately volatile-zeroizing all polynomial randomness.
fn build_split_submissions(
    tx_id: u64,
    bucket_id: usize,
    sender_slot: usize,
    amount: u128,
    remainder: u128,
    recipient_slot: usize,
) -> [ClientShareSubmission; DIST_NUM_VALIDATORS] {
    let mut rands = [0u128; DIST_SQUARES_PER_TX * 2];
    fill_random_field_elems(&mut rands);

    let mut v_bits = [[0u128; DIST_RANGE_BITS]; DIST_NUM_VALIDATORS];
    let mut r_bits = [[0u128; DIST_RANGE_BITS]; DIST_NUM_VALIDATORS];
    let mut selectors = [[0u128; DIST_BUCKET_SIZE]; DIST_NUM_VALIDATORS];

    let mut idx = 0usize;
    for j in 0..DIST_RANGE_BITS {
        let vb = (amount >> j) & 1;
        let shares = eval_poly_3_of_4(vb, rands[idx], rands[idx + 1]);
        for i in 0..DIST_NUM_VALIDATORS {
            v_bits[i][j] = shares[i];
        }
        idx += 2;
    }
    for j in 0..DIST_RANGE_BITS {
        let rb = (remainder >> j) & 1;
        let shares = eval_poly_3_of_4(rb, rands[idx], rands[idx + 1]);
        for i in 0..DIST_NUM_VALIDATORS {
            r_bits[i][j] = shares[i];
        }
        idx += 2;
    }
    for k in 0..DIST_BUCKET_SIZE {
        let sk = if k == recipient_slot { 1u128 } else { 0u128 };
        let shares = eval_poly_3_of_4(sk, rands[idx], rands[idx + 1]);
        for i in 0..DIST_NUM_VALIDATORS {
            selectors[i][k] = shares[i];
        }
        idx += 2;
    }
    zeroize_u128_slice(&mut rands);

    let out = [
        ClientShareSubmission {
            tx_id,
            bucket_id,
            sender_slot,
            v_bits_i: v_bits[0],
            r_bits_i: r_bits[0],
            selector_i: selectors[0],
        },
        ClientShareSubmission {
            tx_id,
            bucket_id,
            sender_slot,
            v_bits_i: v_bits[1],
            r_bits_i: r_bits[1],
            selector_i: selectors[1],
        },
        ClientShareSubmission {
            tx_id,
            bucket_id,
            sender_slot,
            v_bits_i: v_bits[2],
            r_bits_i: r_bits[2],
            selector_i: selectors[2],
        },
        ClientShareSubmission {
            tx_id,
            bucket_id,
            sender_slot,
            v_bits_i: v_bits[3],
            r_bits_i: r_bits[3],
            selector_i: selectors[3],
        },
    ];

    for i in 0..DIST_NUM_VALIDATORS {
        zeroize_u128_slice(&mut v_bits[i]);
        zeroize_u128_slice(&mut r_bits[i]);
        zeroize_u128_slice(&mut selectors[i]);
    }
    out
}

/// Orchestrator owning 4 completely independent [`MpcValidatorDaemon`] TCP servers on `127.0.0.1:0`.
///
/// The 4 daemons share ZERO balance or Beaver memory — they communicate strictly over their
/// 12 pairwise OTP+MAC TCP sockets.
pub struct DistributedMpcCluster {
    daemons: [MpcValidatorDaemon; DIST_NUM_VALIDATORS],
    peer_addrs: [SocketAddr; DIST_NUM_VALIDATORS],
}

impl fmt::Debug for DistributedMpcCluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DistributedMpcCluster")
            .field("peer_addrs", &self.peer_addrs)
            .finish()
    }
}

impl DistributedMpcCluster {
    /// Provision strictly split Beaver banks + pairwise OTP/MAC tapes, launch 4 independent TCP
    /// validator daemons on `127.0.0.1:0`, wire their full-mesh pairwise TCP links, and connect
    /// `config.num_clients` [`DistributedWalletClient`]s.
    pub fn spawn(
        config: DistributedClusterConfig,
    ) -> Result<(Self, Vec<DistributedWalletClient>), DistributedMpcError> {
        if config.num_buckets == 0 || config.num_clients == 0 || config.num_clients > MAX_CONCURRENT_CLIENTS {
            return Err(DistributedMpcError::InvalidParameters(
                "invalid num_buckets or num_clients",
            ));
        }

        // Provision 4 strictly disjoint single-validator Beaver banks.
        let [bank0, bank1, bank2, bank3] =
            LocalBeaverBank::generate_split_banks(config.beaver_tx_capacity);
        let banks = [bank0, bank1, bank2, bank3];

        // Provision 12 directional pairwise inter-validator OTP+MAC tapes (i -> j for i != j).
        let peer_mac_keys = 64 + config.beaver_tx_capacity * 4 + 32;
        let peer_pad_bytes = 4096
            + config.beaver_tx_capacity * (Rtt1Payload::BYTE_LEN + Rtt2aPayload::BYTE_LEN + Rtt2bPayload::BYTE_LEN + 64)
            + 32 * (config.num_buckets * DIST_BUCKET_SIZE * 16 + 64);

        let mut peer_out: [[Option<OtpPadTape>; DIST_NUM_VALIDATORS]; DIST_NUM_VALIDATORS] =
            std::array::from_fn(|_| [None, None, None, None]);
        let mut peer_in: [[Option<OtpPadTape>; DIST_NUM_VALIDATORS]; DIST_NUM_VALIDATORS] =
            std::array::from_fn(|_| [None, None, None, None]);

        for i in 0..DIST_NUM_VALIDATORS {
            for j in 0..DIST_NUM_VALIDATORS {
                if i == j {
                    continue;
                }
                let (sender_tape, receiver_tape) =
                    OtpPadTape::generate_pair(peer_pad_bytes, peer_mac_keys);
                peer_out[i][j] = Some(sender_tape);
                peer_in[j][i] = Some(receiver_tape);
            }
        }

        // Provision client <-> validator directional OTP+MAC tapes.
        let client_mac_keys = 128 + config.beaver_tx_capacity * 4;
        let client_to_daemon_bytes = 4096 + config.beaver_tx_capacity * 1024;
        let daemon_to_client_bytes = 4096 + config.beaver_tx_capacity * 128;

        let mut daemon_client_in: [Vec<OtpPadTape>; DIST_NUM_VALIDATORS] =
            std::array::from_fn(|_| Vec::with_capacity(config.num_clients));
        let mut daemon_client_out: [Vec<OtpPadTape>; DIST_NUM_VALIDATORS] =
            std::array::from_fn(|_| Vec::with_capacity(config.num_clients));

        let mut wallet_out: Vec<Vec<OtpPadTape>> = (0..config.num_clients)
            .map(|_| Vec::with_capacity(DIST_NUM_VALIDATORS))
            .collect();
        let mut wallet_in: Vec<Vec<OtpPadTape>> = (0..config.num_clients)
            .map(|_| Vec::with_capacity(DIST_NUM_VALIDATORS))
            .collect();

        for c in 0..config.num_clients {
            for v in 0..DIST_NUM_VALIDATORS {
                let (c_out, d_in) =
                    OtpPadTape::generate_pair(client_to_daemon_bytes, client_mac_keys);
                let (d_out, c_in) =
                    OtpPadTape::generate_pair(daemon_to_client_bytes, client_mac_keys);
                wallet_out[c].push(c_out);
                daemon_client_in[v].push(d_in);
                daemon_client_out[v].push(d_out);
                wallet_in[c].push(c_in);
            }
        }

        // Spawn 4 completely independent TCP daemons on 127.0.0.1:0.
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback addr");
        let mut daemon_vec = Vec::with_capacity(DIST_NUM_VALIDATORS);
        let [p_in0, p_in1, p_in2, p_in3] = peer_in;
        let mut p_in_iter = [p_in0, p_in1, p_in2, p_in3].into_iter();
        let [p_out0, p_out1, p_out2, p_out3] = peer_out;
        let mut p_out_iter = [p_out0, p_out1, p_out2, p_out3].into_iter();
        let [c_in0, c_in1, c_in2, c_in3] = daemon_client_in;
        let mut c_in_iter = [c_in0, c_in1, c_in2, c_in3].into_iter();
        let [c_out0, c_out1, c_out2, c_out3] = daemon_client_out;
        let mut c_out_iter = [c_out0, c_out1, c_out2, c_out3].into_iter();

        for (i, bank) in banks.into_iter().enumerate() {
            let daemon = MpcValidatorDaemon::spawn(ValidatorDaemonConfig {
                validator_id: i,
                bind_addr,
                num_buckets: config.num_buckets,
                beaver_bank: bank,
                peer_in_tapes: p_in_iter.next().expect("4 peer_in"),
                peer_out_tapes: p_out_iter.next().expect("4 peer_out"),
                client_in_tapes: c_in_iter.next().expect("4 client_in"),
                client_out_tapes: c_out_iter.next().expect("4 client_out"),
                io_timeout: config.io_timeout,
            })?;
            daemon_vec.push(daemon);
        }

        let daemons: [MpcValidatorDaemon; DIST_NUM_VALIDATORS] = daemon_vec
            .try_into()
            .expect("exactly 4 validator daemons");
        let peer_addrs = [
            daemons[0].listen_addr(),
            daemons[1].listen_addr(),
            daemons[2].listen_addr(),
            daemons[3].listen_addr(),
        ];

        // Wire full-mesh pairwise OTP+MAC TCP links between the 4 daemons.
        for d in &daemons {
            d.connect_peers(peer_addrs)?;
        }
        for d in &daemons {
            d.wait_for_peers_ready(config.io_timeout)?;
        }

        // Connect all wallet clients to all 4 daemons.
        let tx_id_counter = Arc::new(AtomicU64::new(0));
        let refresh_id_counter = Arc::new(AtomicU64::new(1));
        let mut clients = Vec::with_capacity(config.num_clients);
        for (c, (w_out, w_in)) in wallet_out.into_iter().zip(wallet_in.into_iter()).enumerate() {
            let out_arr: [OtpPadTape; DIST_NUM_VALIDATORS] =
                w_out.try_into().expect("4 client out tapes");
            let in_arr: [OtpPadTape; DIST_NUM_VALIDATORS] =
                w_in.try_into().expect("4 client in tapes");
            let client = DistributedWalletClient::connect(
                c,
                peer_addrs,
                out_arr,
                in_arr,
                Arc::clone(&tx_id_counter),
                Arc::clone(&refresh_id_counter),
                config.io_timeout,
            )?;
            clients.push(client);
        }

        Ok((
            Self {
                daemons,
                peer_addrs,
            },
            clients,
        ))
    }

    /// Access all 4 independent [`MpcValidatorDaemon`]s.
    pub fn daemons(&self) -> &[MpcValidatorDaemon; DIST_NUM_VALIDATORS] {
        &self.daemons
    }

    /// Access a single validator daemon by ID (`0..4`).
    pub fn daemon(&self, id: usize) -> &MpcValidatorDaemon {
        &self.daemons[id]
    }

    /// Bound TCP socket addresses of `[V0, V1, V2, V3]`.
    pub fn peer_addrs(&self) -> [SocketAddr; DIST_NUM_VALIDATORS] {
        self.peer_addrs
    }

    /// Stop one individual daemon (e.g., to test 3-of-4 fault-tolerant balance queries).
    pub fn stop_daemon(&self, id: usize) {
        if id < DIST_NUM_VALIDATORS {
            self.daemons[id].stop();
        }
    }

    /// Cleanly stop all 4 daemons.
    pub fn stop_all(&self) {
        for d in &self.daemons {
            d.stop();
        }
    }
}

impl Drop for DistributedMpcCluster {
    fn drop(&mut self) {
        self.stop_all();
    }
}

// ============================================================================
// Live 4-Daemon Real-TCP Benchmark
// ============================================================================

/// Measured real-TCP performance metrics for the 4-daemon split-share IT-MPC cluster.
#[derive(Debug, Clone)]
pub struct DistributedMpcBenchReport {
    pub num_transfers: usize,
    pub num_buckets: usize,
    pub total_ms: f64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub tps: f64,
    pub pss_refresh_ms: f64,
    pub inter_validator_wire_bytes_per_tx: usize,
}

/// Spin up 4 real independent TCP daemons on `127.0.0.1:0`, execute `num_transfers` real
/// networked split-share confidential transfers over loopback TCP sockets (plus 1 live
/// Distributed PSS refresh), verify exact final balances, and report measured latency & TPS.
pub fn run_distributed_mpc_bench(
    num_transfers: usize,
) -> Result<DistributedMpcBenchReport, DistributedMpcError> {
    if num_transfers == 0 {
        return Err(DistributedMpcError::InvalidParameters(
            "num_transfers must be >= 1",
        ));
    }

    let num_buckets = 2;
    let config = DistributedClusterConfig {
        num_buckets,
        beaver_tx_capacity: num_transfers + 4,
        num_clients: 1,
        io_timeout: Duration::from_secs(10),
    };

    let (cluster, mut clients) = DistributedMpcCluster::spawn(config)?;
    let client = &mut clients[0];

    // Mint initial split balance on bucket 0, slot 0 (amount = 60_000).
    let mut bal0 = 60_000u128;
    let mut bal1 = 0u128;
    client.mint_split_shares(0, 0, bal0)?;

    let mut latencies_us = Vec::with_capacity(num_transfers);
    let bench_start = Instant::now();

    for step in 0..num_transfers {
        let amount = 1u128;
        let receipt = if step % 2 == 0 {
            let r = client.send_shielded(0, 0, bal0, 1, amount)?;
            bal0 -= amount;
            bal1 += amount;
            r
        } else {
            let r = client.send_shielded(0, 1, bal1, 0, amount)?;
            bal1 -= amount;
            bal0 += amount;
            r
        };
        latencies_us.push(receipt.rtt_us);
    }

    let total_elapsed = bench_start.elapsed();

    // Verify exact final balances via client-side reconstruction.
    let final_bal0 = client.query_balance(0, 0)?;
    let final_bal1 = client.query_balance(0, 1)?;
    if final_bal0 != bal0 || final_bal1 != bal1 {
        return Err(DistributedMpcError::ProtocolError(format!(
            "benchmark balance mismatch: got ({final_bal0}, {final_bal1}), expected ({bal0}, {bal1})"
        )));
    }

    // Measure one real networked Distributed PSS refresh across all 4 daemons.
    let pss = client.trigger_distributed_pss_refresh()?;
    let post_pss_bal0 = client.query_balance(0, 0)?;
    if post_pss_bal0 != bal0 {
        return Err(DistributedMpcError::ProtocolError(
            "post-PSS balance mismatch".to_string(),
        ));
    }

    latencies_us.sort_unstable();
    let p50_idx = latencies_us.len() / 2;
    let p99_idx = ((latencies_us.len() * 99) / 100).min(latencies_us.len() - 1);
    let total_secs = total_elapsed.as_secs_f64();
    let total_ms = total_secs * 1000.0;
    let avg_latency_ms = total_ms / (num_transfers as f64);
    let tps = (num_transfers as f64) / total_secs.max(1e-9);

    // 12 directional links * (RTT1 + RTT2a + RTT2b framed sizes).
    let per_link_wire = (FRAME_HEADER_LEN + Rtt1Payload::BYTE_LEN + FRAME_MAC_LEN)
        + (FRAME_HEADER_LEN + Rtt2aPayload::BYTE_LEN + FRAME_MAC_LEN)
        + (FRAME_HEADER_LEN + Rtt2bPayload::BYTE_LEN + FRAME_MAC_LEN);
    let inter_validator_wire_bytes_per_tx = 12 * per_link_wire;

    cluster.stop_all();

    Ok(DistributedMpcBenchReport {
        num_transfers,
        num_buckets,
        total_ms,
        avg_latency_ms,
        p50_latency_ms: (latencies_us[p50_idx] as f64) / 1000.0,
        p99_latency_ms: (latencies_us[p99_idx] as f64) / 1000.0,
        tps,
        pss_refresh_ms: (pss.elapsed_us as f64) / 1000.0,
        inter_validator_wire_bytes_per_tx,
    })
}

// ============================================================================
// Comprehensive Unit & Real-TCP Integration Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: linear interpolation at `x = 0` from ONLY 2 validator shares `(id_a, y_a)` and
    /// `(id_b, y_b)` — yields uniform garbage for any degree-2 Shamir sharing (`t = 3`).
    fn linear_interp_two_shares(id_a: usize, y_a: u128, id_b: usize, y_b: u128) -> u128 {
        let xa = (id_a + 1) as u128;
        let xb = (id_b + 1) as u128;
        // (xb * y_a - xa * y_b) / (xb - xa) mod PRIME_P
        let num = sub_mod(mul_mod(xb, y_a), mul_mod(xa, y_b));
        let den = sub_mod(xb, xa);
        mul_mod(num, inv_mod(den))
    }

    /// Helper: build raw validator submissions from arbitrary field elements (for attack tests).
    fn build_custom_field_submissions(
        tx_id: u64,
        bucket_id: usize,
        sender_slot: usize,
        v_bits_plain: [u128; DIST_RANGE_BITS],
        r_bits_plain: [u128; DIST_RANGE_BITS],
        sel_plain: [u128; DIST_BUCKET_SIZE],
    ) -> [ClientShareSubmission; DIST_NUM_VALIDATORS] {
        let mut v_bits = [[0u128; DIST_RANGE_BITS]; DIST_NUM_VALIDATORS];
        let mut r_bits = [[0u128; DIST_RANGE_BITS]; DIST_NUM_VALIDATORS];
        let mut selectors = [[0u128; DIST_BUCKET_SIZE]; DIST_NUM_VALIDATORS];

        for j in 0..DIST_RANGE_BITS {
            let s = split_secret_3_of_4(v_bits_plain[j]).expect("valid field elem");
            for i in 0..DIST_NUM_VALIDATORS {
                v_bits[i][j] = s[i];
            }
        }
        for j in 0..DIST_RANGE_BITS {
            let s = split_secret_3_of_4(r_bits_plain[j]).expect("valid field elem");
            for i in 0..DIST_NUM_VALIDATORS {
                r_bits[i][j] = s[i];
            }
        }
        for k in 0..DIST_BUCKET_SIZE {
            let s = split_secret_3_of_4(sel_plain[k]).expect("valid field elem");
            for i in 0..DIST_NUM_VALIDATORS {
                selectors[i][k] = s[i];
            }
        }

        [
            ClientShareSubmission {
                tx_id,
                bucket_id,
                sender_slot,
                v_bits_i: v_bits[0],
                r_bits_i: r_bits[0],
                selector_i: selectors[0],
            },
            ClientShareSubmission {
                tx_id,
                bucket_id,
                sender_slot,
                v_bits_i: v_bits[1],
                r_bits_i: r_bits[1],
                selector_i: selectors[1],
            },
            ClientShareSubmission {
                tx_id,
                bucket_id,
                sender_slot,
                v_bits_i: v_bits[2],
                r_bits_i: r_bits[2],
                selector_i: selectors[2],
            },
            ClientShareSubmission {
                tx_id,
                bucket_id,
                sender_slot,
                v_bits_i: v_bits[3],
                r_bits_i: r_bits[3],
                selector_i: selectors[3],
            },
        ]
    }

    #[test]
    fn test_carter_wegman_otp_wire_frame_and_tamper_rejection() {
        let (mut tx_tape, mut rx_tape) = OtpPadTape::generate_pair(4096, 16);
        let msg = b"vernam-split-share-binary-frame-payload";
        let frame = encrypt_and_mac_frame(&mut tx_tape, MSG_PEER_RTT1, 1, 0, msg).unwrap();

        // Ciphertext must not contain plaintext verbatim.
        assert_ne!(&frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + msg.len()], msg);

        // Tampering 1 bit in ciphertext must fail constant-time MAC verification.
        let (mut tx2, mut rx2) = OtpPadTape::generate_pair(4096, 16);
        let frame2 = encrypt_and_mac_frame(&mut tx2, MSG_PEER_RTT1, 1, 0, msg).unwrap();
        let mut bad_ct = frame2.clone();
        bad_ct[FRAME_HEADER_LEN + 5] ^= 0x80;
        assert_eq!(
            verify_and_decrypt_frame(&mut rx2, &bad_ct),
            Err(DistributedMpcError::MacVerificationFailed)
        );

        // Tampering 1 bit in the binary header (flags) must also fail MAC verification.
        let (mut tx3, mut rx3) = OtpPadTape::generate_pair(4096, 16);
        let mut bad_hdr = encrypt_and_mac_frame(&mut tx3, MSG_PEER_RTT1, 1, 0, msg).unwrap();
        bad_hdr[6] ^= 0x01;
        assert_eq!(
            verify_and_decrypt_frame(&mut rx3, &bad_hdr),
            Err(DistributedMpcError::MacVerificationFailed)
        );

        // Authentic frame decrypts identically.
        let (hdr, plain) = verify_and_decrypt_frame(&mut rx_tape, &frame).unwrap();
        assert_eq!(hdr.msg_type, MSG_PEER_RTT1);
        assert_eq!(hdr.sender_id, 1);
        assert_eq!(hdr.seq_id, 0);
        assert_eq!(plain, msg);

        // Replaying the exact same frame must be rejected (strictly single-use sequence).
        assert!(verify_and_decrypt_frame(&mut rx_tape, &frame).is_err());
    }

    #[test]
    fn test_shamir_3_of_4_all_subsets_and_degree2_parity() {
        let secret = 42_987u128;
        let shares = split_secret_3_of_4(secret).unwrap();
        assert_eq!(reconstruct_4_verified(&shares).unwrap(), secret);

        // Every 3-of-4 subset reconstructs the exact secret.
        assert_eq!(
            reconstruct_any_3(&[(0, shares[0]), (1, shares[1]), (2, shares[2])]).unwrap(),
            secret
        );
        assert_eq!(
            reconstruct_any_3(&[(0, shares[0]), (1, shares[1]), (3, shares[3])]).unwrap(),
            secret
        );
        assert_eq!(
            reconstruct_any_3(&[(0, shares[0]), (2, shares[2]), (3, shares[3])]).unwrap(),
            secret
        );
        assert_eq!(
            reconstruct_any_3(&[(1, shares[1]), (2, shares[2]), (3, shares[3])]).unwrap(),
            secret
        );

        // Corrupting any single share fails degree-2 parity `[1, P - 3, 3, P - 1]`.
        let mut bad = shares;
        bad[2] = add_mod(bad[2], 1);
        assert_eq!(
            reconstruct_4_verified(&bad),
            Err(DistributedMpcError::InconsistentShares)
        );
    }

    #[test]
    fn test_real_tcp_split_share_transfer_privacy_and_rerandomization() {
        let config = DistributedClusterConfig {
            num_buckets: 2,
            beaver_tx_capacity: 16,
            num_clients: 1,
            io_timeout: Duration::from_secs(5),
        };
        let (cluster, mut clients) = DistributedMpcCluster::spawn(config).unwrap();
        let client = &mut clients[0];

        // Ensure all 4 daemons bound to 4 distinct TCP ports.
        let addrs = cluster.peer_addrs();
        for i in 0..DIST_NUM_VALIDATORS {
            for j in (i + 1)..DIST_NUM_VALIDATORS {
                assert_ne!(addrs[i], addrs[j], "every daemon must have its own TCP port");
            }
        }

        // Mint split shares on bucket 0: slot 0 = 10_000, slot 5 = 2_500, slot 11 = 777.
        client.mint_split_shares(0, 0, 10_000).unwrap();
        client.mint_split_shares(0, 5, 2_500).unwrap();
        client.mint_split_shares(0, 11, 777).unwrap();

        assert_eq!(client.query_balance(0, 0).unwrap(), 10_000);
        assert_eq!(client.query_balance(0, 5).unwrap(), 2_500);
        assert_eq!(client.query_balance(0, 11).unwrap(), 777);

        // Snapshot all 4 daemons' shares for every slot in bucket 0 BEFORE transfer.
        let mut before_shares = [[0u128; DIST_BUCKET_SIZE]; DIST_NUM_VALIDATORS];
        for v in 0..DIST_NUM_VALIDATORS {
            for s in 0..DIST_BUCKET_SIZE {
                before_shares[v][s] = cluster.daemon(v).local_balance_share(0, s).unwrap();
            }
        }

        // Execute real networked confidential transfer: slot 0 -> slot 5 for amount = 3_456.
        let receipt = client.send_shielded(0, 0, 10_000, 5, 3_456).unwrap();
        assert_eq!(receipt.committed_validators, 4);

        // Verify exact balances via client-side reconstruction.
        assert_eq!(client.query_balance(0, 0).unwrap(), 6_544);
        assert_eq!(client.query_balance(0, 5).unwrap(), 5_956);
        assert_eq!(client.query_balance(0, 11).unwrap(), 777);
        for s in 0..DIST_BUCKET_SIZE {
            if s != 0 && s != 5 && s != 11 {
                assert_eq!(client.query_balance(0, s).unwrap(), 0);
            }
        }

        // STRICT SPLIT-SHARE ISOLATION AUDIT:
        // 1. NO single daemon holds the plaintext balance of slot 0 (6_544) or slot 5 (5_956).
        let slot0_shares: [u128; 4] =
            std::array::from_fn(|v| cluster.daemon(v).local_balance_share(0, 0).unwrap());
        let slot5_shares: [u128; 4] =
            std::array::from_fn(|v| cluster.daemon(v).local_balance_share(0, 5).unwrap());

        for v in 0..DIST_NUM_VALIDATORS {
            assert_ne!(slot0_shares[v], 6_544, "V{v} must not hold plaintext balance");
            assert_ne!(slot5_shares[v], 5_956, "V{v} must not hold plaintext balance");
        }

        // 2. ANY 2 daemons' shares reconstruct uniform garbage (NOT the plaintext balance!).
        for a in 0..DIST_NUM_VALIDATORS {
            for b in (a + 1)..DIST_NUM_VALIDATORS {
                assert_ne!(
                    linear_interp_two_shares(a, slot0_shares[a], b, slot0_shares[b]),
                    6_544,
                    "2 colluding daemons ({a}, {b}) must not learn slot 0 balance"
                );
                assert_ne!(
                    linear_interp_two_shares(a, slot5_shares[a], b, slot5_shares[b]),
                    5_956,
                    "2 colluding daemons ({a}, {b}) must not learn slot 5 balance"
                );
            }
        }

        // 3. EVERY non-recipient slot share on EVERY daemon re-randomized!
        for v in 0..DIST_NUM_VALIDATORS {
            for s in 0..DIST_BUCKET_SIZE {
                if s != 5 {
                    let after = cluster.daemon(v).local_balance_share(0, s).unwrap();
                    assert_ne!(
                        after, before_shares[v][s],
                        "non-recipient slot {s} share on V{v} must re-randomize"
                    );
                }
            }
            assert_eq!(cluster.daemon(v).committed_txs(), 1);
            assert_eq!(cluster.daemon(v).aborted_txs(), 0);
        }

        // 4. 3-of-4 fault-tolerant client balance reconstruction when 1 daemon is stopped!
        cluster.stop_daemon(3);
        assert_eq!(client.query_balance(0, 0).unwrap(), 6_544);
        assert_eq!(client.query_balance(0, 5).unwrap(), 5_956);
        assert_eq!(client.query_balance(0, 11).unwrap(), 777);
    }

    #[test]
    fn test_real_tcp_attacks_overdraft_negative_bit_double_recipient_and_zero_leakage() {
        let config = DistributedClusterConfig {
            num_buckets: 1,
            beaver_tx_capacity: 16,
            num_clients: 1,
            io_timeout: Duration::from_secs(5),
        };
        let (cluster, mut clients) = DistributedMpcCluster::spawn(config).unwrap();
        let client = &mut clients[0];

        client.mint_split_shares(0, 0, 500).unwrap();
        client.mint_split_shares(0, 1, 100).unwrap();
        client.mint_split_shares(0, 2, 200).unwrap();

        let snapshot_before: [[u128; DIST_BUCKET_SIZE]; DIST_NUM_VALIDATORS] =
            std::array::from_fn(|v| {
                std::array::from_fn(|s| cluster.daemon(v).local_balance_share(0, s).unwrap())
            });

        // --- Attack 1: Overdraft (balance = 500, trying to send 600 with fake remainder 0) ---
        let mut v_over = [0u128; DIST_RANGE_BITS];
        for j in 0..DIST_RANGE_BITS {
            v_over[j] = (600u128 >> j) & 1;
        }
        let r_zero = [0u128; DIST_RANGE_BITS];
        let mut sel1 = [0u128; DIST_BUCKET_SIZE];
        sel1[1] = 1;

        let tx1 = client.allocate_tx_id();
        let res1 = client.send_raw_submissions(build_custom_field_submissions(
            tx1, 0, 0, v_over, r_zero, sel1,
        ));
        let residual1 = match res1 {
            Err(DistributedMpcError::RlcCheckFailed { blinded_residual }) => {
                assert_ne!(blinded_residual, 0);
                blinded_residual
            }
            other => panic!("expected RlcCheckFailed on overdraft #1, got {other:?}"),
        };

        // Repeat IDENTICAL overdraft to verify `[rho] * [Z]` blinding randomizes `Z_blind`
        // (zero leakage of `B_sender - v - r`!).
        let tx2 = client.allocate_tx_id();
        let res2 = client.send_raw_submissions(build_custom_field_submissions(
            tx2, 0, 0, v_over, r_zero, sel1,
        ));
        let residual2 = match res2 {
            Err(DistributedMpcError::RlcCheckFailed { blinded_residual }) => {
                assert_ne!(blinded_residual, 0);
                blinded_residual
            }
            other => panic!("expected RlcCheckFailed on overdraft #2, got {other:?}"),
        };
        assert_ne!(
            residual1, residual2,
            "identical overdrafts must yield independent random Z_blind (zero balance leakage)"
        );

        // --- Attack 2: Negative bit (`v_bits[0] = P - 1` i.e. -1, `r = 501`) ---
        let mut v_neg = [0u128; DIST_RANGE_BITS];
        v_neg[0] = PRIME_P - 1;
        let mut r_501 = [0u128; DIST_RANGE_BITS];
        for j in 0..DIST_RANGE_BITS {
            r_501[j] = (501u128 >> j) & 1;
        }
        let tx3 = client.allocate_tx_id();
        let res3 = client.send_raw_submissions(build_custom_field_submissions(
            tx3, 0, 0, v_neg, r_501, sel1,
        ));
        assert!(matches!(
            res3,
            Err(DistributedMpcError::RlcCheckFailed { blinded_residual }) if blinded_residual != 0
        ));

        // --- Attack 3A: Double-recipient (`s_1 = 1, s_2 = 1`, sum = 2 != 1) ---
        let mut v_100 = [0u128; DIST_RANGE_BITS];
        let mut r_400 = [0u128; DIST_RANGE_BITS];
        for j in 0..DIST_RANGE_BITS {
            v_100[j] = (100u128 >> j) & 1;
            r_400[j] = (400u128 >> j) & 1;
        }
        let mut sel_double = [0u128; DIST_BUCKET_SIZE];
        sel_double[1] = 1;
        sel_double[2] = 1;
        let tx4 = client.allocate_tx_id();
        let res4 = client.send_raw_submissions(build_custom_field_submissions(
            tx4, 0, 0, v_100, r_400, sel_double,
        ));
        assert!(matches!(
            res4,
            Err(DistributedMpcError::RlcCheckFailed { blinded_residual }) if blinded_residual != 0
        ));

        // --- Attack 3B: Non-binary selector summing to 1 (`s_1 = 2, s_2 = P - 1`) ---
        let mut sel_nonbin = [0u128; DIST_BUCKET_SIZE];
        sel_nonbin[1] = 2;
        sel_nonbin[2] = PRIME_P - 1;
        let tx5 = client.allocate_tx_id();
        let res5 = client.send_raw_submissions(build_custom_field_submissions(
            tx5, 0, 0, v_100, r_400, sel_nonbin,
        ));
        assert!(matches!(
            res5,
            Err(DistributedMpcError::RlcCheckFailed { blinded_residual }) if blinded_residual != 0
        ));

        // --- Attack 4: Tampered share breaking degree-2 Lagrange parity ---
        let tx6 = client.allocate_tx_id();
        let mut subs_tampered = build_split_submissions(tx6, 0, 0, 100, 400, 1);
        subs_tampered[3].v_bits_i[0] = add_mod(subs_tampered[3].v_bits_i[0], 1);
        let res6 = client.send_raw_submissions(subs_tampered);
        assert_eq!(res6, Err(DistributedMpcError::InconsistentShares));

        // Verify ZERO state mutation across all 4 daemons and all 16 slots after all 6 attacks!
        for v in 0..DIST_NUM_VALIDATORS {
            assert_eq!(cluster.daemon(v).committed_txs(), 0);
            assert_eq!(cluster.daemon(v).aborted_txs(), 6);
            for s in 0..DIST_BUCKET_SIZE {
                assert_eq!(
                    cluster.daemon(v).local_balance_share(0, s).unwrap(),
                    snapshot_before[v][s],
                    "failed attacks must leave V{v} slot {s} byte-for-byte unchanged"
                );
            }
        }
        assert_eq!(client.query_balance(0, 0).unwrap(), 500);
        assert_eq!(client.query_balance(0, 1).unwrap(), 100);
        assert_eq!(client.query_balance(0, 2).unwrap(), 200);
    }

    #[test]
    fn test_real_tcp_distributed_pss_refresh_epoch_isolation() {
        let config = DistributedClusterConfig {
            num_buckets: 2,
            beaver_tx_capacity: 16,
            num_clients: 1,
            io_timeout: Duration::from_secs(5),
        };
        let (cluster, mut clients) = DistributedMpcCluster::spawn(config).unwrap();
        let client = &mut clients[0];

        client.mint_split_shares(0, 3, 12_345).unwrap();
        client.mint_split_shares(1, 7, 54_321).unwrap();

        // Capture Epoch-1 shares directly from the 4 independent daemons.
        let epoch1_slot3: [u128; 4] =
            std::array::from_fn(|v| cluster.daemon(v).local_balance_share(0, 3).unwrap());
        for v in 0..DIST_NUM_VALIDATORS {
            assert_eq!(cluster.daemon(v).epoch(), 1);
        }

        // Trigger Distributed PSS Refresh over real pairwise OTP+MAC TCP sockets!
        let report = trigger_distributed_pss_refresh(client).unwrap();
        assert_eq!(report.new_epoch, 2);
        assert_eq!(report.accounts_refreshed, 2 * DIST_BUCKET_SIZE);

        let epoch2_slot3: [u128; 4] =
            std::array::from_fn(|v| cluster.daemon(v).local_balance_share(0, 3).unwrap());
        for v in 0..DIST_NUM_VALIDATORS {
            assert_eq!(cluster.daemon(v).epoch(), 2);
            assert_ne!(
                epoch2_slot3[v], epoch1_slot3[v],
                "PSS refresh must rotate V{v}'s share"
            );
        }

        // Wallet reconstructs exact balances in Epoch 2 (passing full 4-of-4 degree-2 parity).
        assert_eq!(client.query_balance(0, 3).unwrap(), 12_345);
        assert_eq!(client.query_balance(1, 7).unwrap(), 54_321);

        // Mobile adversary test: mixing Epoch-1 shares from (V0, V1) with Epoch-2 share from V2
        // yields uniform garbage != 12_345 and fails degree-2 parity with Epoch-2 V3!
        let mixed_3 = reconstruct_any_3(&[
            (0, epoch1_slot3[0]),
            (1, epoch1_slot3[1]),
            (2, epoch2_slot3[2]),
        ])
        .unwrap();
        assert_ne!(
            mixed_3, 12_345,
            "mixing Epoch-1 (V0,V1) with Epoch-2 (V2) must yield garbage"
        );
        let mixed_4 = [
            epoch1_slot3[0],
            epoch1_slot3[1],
            epoch2_slot3[2],
            epoch2_slot3[3],
        ];
        assert_eq!(
            reconstruct_4_verified(&mixed_4),
            Err(DistributedMpcError::InconsistentShares)
        );

        // Subsequent confidential transfers work seamlessly in Epoch 2!
        client.send_shielded(0, 3, 12_345, 9, 2_345).unwrap();
        assert_eq!(client.query_balance(0, 3).unwrap(), 10_000);
        assert_eq!(client.query_balance(0, 9).unwrap(), 2_345);
    }

    #[test]
    fn test_real_tcp_concurrent_multi_bucket_and_beaver_replay_rejection() {
        let config = DistributedClusterConfig {
            num_buckets: 2,
            beaver_tx_capacity: 64,
            num_clients: 2,
            io_timeout: Duration::from_secs(5),
        };
        let (cluster, mut clients) = DistributedMpcCluster::spawn(config).unwrap();
        let mut c1 = clients.pop().unwrap();
        let mut c0 = clients.pop().unwrap();

        c0.mint_split_shares(0, 0, 20_000).unwrap();
        c1.mint_split_shares(1, 0, 30_000).unwrap();

        // Execute 20 concurrent confidential transfers per client on disjoint buckets simultaneously.
        let h0 = thread::spawn(move || {
            let mut b0 = 20_000u128;
            for _ in 0..20 {
                c0.send_shielded(0, 0, b0, 4, 100).unwrap();
                b0 -= 100;
            }
            assert_eq!(c0.query_balance(0, 0).unwrap(), 18_000);
            assert_eq!(c0.query_balance(0, 4).unwrap(), 2_000);
            c0
        });
        let h1 = thread::spawn(move || {
            let mut b0 = 30_000u128;
            for _ in 0..20 {
                c1.send_shielded(1, 0, b0, 8, 250).unwrap();
                b0 -= 250;
            }
            assert_eq!(c1.query_balance(1, 0).unwrap(), 25_000);
            assert_eq!(c1.query_balance(1, 8).unwrap(), 5_000);
            c1
        });

        let mut c0 = h0.join().unwrap();
        let _c1 = h1.join().unwrap();

        // Replaying an already-consumed `tx_id = 0` must be rejected across all 4 daemons!
        let replay = build_split_submissions(0, 0, 0, 100, 17_900, 4);
        let replay_res = c0.send_raw_submissions(replay);
        assert!(matches!(
            replay_res,
            Err(DistributedMpcError::BeaverAlreadyConsumed { .. })
        ));
        assert_eq!(c0.query_balance(0, 0).unwrap(), 18_000);
        for v in 0..DIST_NUM_VALIDATORS {
            assert_eq!(cluster.daemon(v).committed_txs(), 40);
            assert_eq!(cluster.daemon(v).aborted_txs(), 1);
        }
    }

    #[test]
    fn test_live_4_daemon_real_tcp_benchmark() {
        let report = run_distributed_mpc_bench(100).unwrap();
        assert_eq!(report.num_transfers, 100);
        assert!(report.tps > 0.0);
        assert!(report.avg_latency_ms > 0.0);
        println!(
            "\n=== Vernam v1.0 4-Daemon Split-Share Real-TCP IT-MPC Benchmark ===\n\
             Transfers:       {}\n\
             Total time:      {:.2} ms\n\
             Avg latency:     {:.3} ms/tx\n\
             p50 latency:     {:.3} ms/tx\n\
             p99 latency:     {:.3} ms/tx\n\
             Throughput:      {:.1} shielded TPS (real loopback TCP + OTP + Carter-Wegman MAC)\n\
             PSS Refresh:     {:.3} ms ({} accounts across 4 daemons)\n\
             Inter-val wire:  {} bytes/tx across 12 OTP+MAC links\n",
            report.num_transfers,
            report.total_ms,
            report.avg_latency_ms,
            report.p50_latency_ms,
            report.p99_latency_ms,
            report.tps,
            report.pss_refresh_ms,
            report.num_buckets * DIST_BUCKET_SIZE,
            report.inter_validator_wire_bytes_per_tx,
        );
    }

    #[test]
    fn test_adversarial_tcp_hostile_oversized_truncated_and_stalled_frames() {
        // 1. WireFrameHeader::decode rejects bad magic, unknown msg_type, and oversized payloads
        //    BEFORE any body buffer allocation.
        let mut bad_magic = [0u8; FRAME_HEADER_LEN];
        bad_magic[0..4].copy_from_slice(b"EVIL");
        bad_magic[4] = MSG_CLIENT_HELLO;
        assert!(WireFrameHeader::decode(&bad_magic).is_err());

        let unknown_type = WireFrameHeader {
            msg_type: 0xEE,
            sender_id: 0,
            flags: 0,
            seq_id: 0,
            payload_len: 2,
        }
        .encode();
        assert!(WireFrameHeader::decode(&unknown_type).is_err());

        let oversized_hello = WireFrameHeader {
            msg_type: MSG_CLIENT_HELLO,
            sender_id: 0xFF,
            flags: 0,
            seq_id: 0,
            payload_len: (MAX_HANDSHAKE_PAYLOAD_BYTES as u32) + 1,
        }
        .encode();
        assert!(WireFrameHeader::decode(&oversized_hello).is_err());

        let huge_payload = WireFrameHeader {
            msg_type: MSG_PEER_PSS_DELTA,
            sender_id: 0,
            flags: 0,
            seq_id: 0,
            payload_len: u32::MAX,
        }
        .encode();
        assert!(WireFrameHeader::decode(&huge_payload).is_err());

        // 2. verify_and_decrypt_frame rejects truncated frames & forged MAC without panicking or OOM.
        let (mut tx_tape, mut rx_tape) = OtpPadTape::generate_pair(256, 4);
        assert!(verify_and_decrypt_frame(&mut rx_tape, &[0u8; 10]).is_err());
        let valid = encrypt_and_mac_frame(&mut tx_tape, MSG_CLIENT_MINT, 0xFF, 0, &[1u8; 21]).unwrap();
        assert!(verify_and_decrypt_frame(&mut rx_tape, &valid[..valid.len() - 1]).is_err());
        let mut forged = valid.clone();
        forged[FRAME_HEADER_LEN] ^= 0xFF;
        let pad_before = rx_tape.remaining_pad_bytes();
        assert_eq!(
            verify_and_decrypt_frame(&mut rx_tape, &forged),
            Err(DistributedMpcError::MacVerificationFailed)
        );
        // Zero-allocation in-place pad burn consumed exactly 21 bytes on MAC failure.
        assert_eq!(rx_tape.remaining_pad_bytes(), pad_before - 21);

        // 3. Live 4-daemon cluster survives raw hostile TCP attacks (oversized header, bad magic,
        //    truncated frame, stalled Slowloris partial header) without crashing, OOMing, or hanging.
        let config = DistributedClusterConfig {
            num_buckets: 1,
            beaver_tx_capacity: 8,
            num_clients: 1,
            io_timeout: Duration::from_millis(250),
        };
        let (cluster, mut clients) = DistributedMpcCluster::spawn(config).unwrap();
        let v0_addr = cluster.peer_addrs()[0];

        // Attack A: Spoofed 4 GiB payload_len header over live TCP.
        {
            let mut s = TcpStream::connect(v0_addr).unwrap();
            let _ = s.write_all(&huge_payload);
            let _ = s.flush();
            let mut sink = [0u8; 16];
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s.read(&mut sink);
        }

        // Attack B: Oversized MSG_CLIENT_HELLO claiming 2 MiB payload.
        {
            let mut s = TcpStream::connect(v0_addr).unwrap();
            let hdr = WireFrameHeader {
                msg_type: MSG_CLIENT_HELLO,
                sender_id: 0xFF,
                flags: 0,
                seq_id: 0,
                payload_len: 2_000_000,
            }
            .encode();
            let _ = s.write_all(&hdr);
            let _ = s.flush();
        }

        // Attack C: Truncated mid-header and truncated mid-body frames.
        {
            let mut s1 = TcpStream::connect(v0_addr).unwrap();
            let _ = s1.write_all(b"VRNM\x02\x00\x00");
            let _ = s1.flush();

            let mut s2 = TcpStream::connect(v0_addr).unwrap();
            let hdr = WireFrameHeader {
                msg_type: MSG_CLIENT_HELLO,
                sender_id: 0xFF,
                flags: 0,
                seq_id: 0,
                payload_len: 16,
            }
            .encode();
            let _ = s2.write_all(&hdr);
            let _ = s2.write_all(&[0xAA; 4]); // truncated body + missing MAC
            let _ = s2.flush();
        }

        // Attack D: Slowloris stalled partial frame held open -> daemon times out cleanly in ~250ms.
        let stalled_stream = {
            let mut s = TcpStream::connect(v0_addr).unwrap();
            let _ = s.write_all(b"VRNM\x02");
            let _ = s.flush();
            s
        };

        // Cluster MUST remain completely responsive and execute a real shielded transfer!
        let client = &mut clients[0];
        client.mint_split_shares(0, 0, 1_000).unwrap();
        let rcpt = client.send_shielded(0, 0, 1_000, 3, 250).unwrap();
        assert_eq!(rcpt.committed_validators, 4);
        assert_eq!(client.query_balance(0, 0).unwrap(), 750);
        assert_eq!(client.query_balance(0, 3).unwrap(), 250);

        drop(stalled_stream);
        cluster.stop_all();
    }
}
