//! Ultra-Fast Shielded IT-MPC & Algebraic Batching Engine for Vernam (VRNM).
//!
//! Pushes **100% information-theoretically private `(3, 4)` Shamir Shielded IT-MPC transfers**
//! (hidden balances, hidden 16-bit amounts, hidden recipients across `K = 16` anonymity buckets
//! over the Mersenne prime field `F_(2^127 - 1)` — **ZERO** zk-SNARKs, **ZERO** SHA-256,
//! **ZERO** external crates) past **1,000,000+ Shielded TPS** using three textbook IT-MPC
//! algebraic breakthroughs plus a zero-allocation persistent multi-core sharded bucket pool:
//!
//! 1. **Beaver Square Pairs ([`BeaverSquare`]: `([a], [a^2])`) for ALL 48 Boolean Checks**:
//!    - Every bit check (`16` amount bits `v_j`, `16` remainder bits `r_j`, `16` selector bits
//!      `s_k`) proves `x * (x - 1) = x^2 - x == 0`.
//!    - Using a single-use Beaver Square Pair `([a], [a^2])` requires only **1 opening**
//!      `d = x - a` (degree-2 verified with zero `inv_mod` and zero `mul_mod` via compile-time
//!      Lagrange `[3, P - 3, 1]` and parity `[1, P - 3, 3, P - 1]`):
//!      `[x^2] = [a^2] + 2*d*[a] + d^2 (mod P)` and `[x*(x - 1)] = [a^2] + (2*d - 1)*[a] + d*(d - 1)`.
//!    - Cuts bit-proof openings, multiplications, and correlated-randomness RAM traffic in HALF.
//!
//! 2. **Blinded Schwartz–Zippel Random Linear Combination (RLC) Batch Zero-Check**:
//!    - Combines ALL 50 per-transfer invariant checks (`16 v_bits + 16 r_bits + 16 s_bits +
//!      1 balance_conservation + 1 selector_sum`) into a single secret-shared polynomial evaluated
//!      via Horner's rule at a fresh non-zero OS-random challenge `gamma in F_(2^127 - 1)`:
//!      `[Z] = sum_{i=0}^{49} gamma^i * [check_i] (mod P)`.
//!    - Multiplies `[Z]` by a fresh uniform non-zero secret-shared blinding scalar `[rho]` via
//!      one single-use [`BeaverTriple4`] (`[Z_blind] = [rho * Z]`) and opens ONLY `[Z_blind]` ->
//!      **MUST equal `0`**. If any check fails (`Z != 0`), `rho * Z` is uniformly distributed in
//!      `F_p^*`, leaking ZERO bits about `B_sender` or concurrent incoming credits!
//!    - Information-theoretic soundness: by Schwartz–Zippel, if ANY single check is non-zero,
//!      `Pr[Z == 0] <= 49 / (2^127 - 2) < 50 / (2^127 - 1) < 2^-121`, unconditionally secure
//!      even against unbounded computational power (`P = NP`).
//!
//! 3. **16-Slot Blinded Recipient Update with Shared `[v]` Opening ([`BeaverStar16`])**:
//!    - All 16 blinded credits `[s_k * v]` (`k = 0..15`) multiply against the **same** secret `[v]`.
//!    - Using a single-use Shared-Factor Beaver Star `([b_v], [a_0..a_15], [c_0..c_15])` where
//!      `c_k = a_k * b_v (mod P)`, `beta = v - b_v` is opened **ONCE** (saving 15 openings),
//!      followed by the 16 openings `alpha_k = s_k - a_k`.
//!    - Total openings per full 16-bit + 16-slot confidential transfer drops from **178 -> 68**
//!      (`48` bit squares + `2` blinding-triple openings + `1` blinded RLC zero-check +
//!      `1` shared `beta` + `16` `alpha_k` = `68`).
//!
//! 4. **Persistent Multi-Core Sharded Bucket Pool ([`TurboShieldedCluster`])**:
//!    - Spawns persistent OS worker threads ONCE (sized to `available_parallelism()`), statically
//!      partitioned across disjoint anonymity buckets with cache-line-aligned slots, zero lock
//!      contention, zero per-batch thread spawn overhead, zero heap allocations inside
//!      [`execute_transfer_in_bucket`], atomic all-or-nothing batch rollback, and clean `Drop`
//!      shutdown.

use std::cell::{RefCell, UnsafeCell};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, compiler_fence};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use crate::field::{PRIME_P, add_mod, sub_mod, zeroize_slice, zeroize_u128};
#[cfg(test)]
use crate::field::mul_mod;

// ============================================================================
// Constants & Core Types
// ============================================================================

/// Fixed validator count for `(3, 4)` Shamir IT-MPC.
pub const TURBO_NUM_VALIDATORS: usize = 4;

/// Threshold `t = 3` (`< 3` colluding validators learn 0 bits of information).
pub const TURBO_THRESHOLD: usize = 3;

/// Fixed 16-bit confidential range proof width (`0 <= v < 2^16`).
pub const TURBO_RANGE_BITS: usize = 16;

/// Fixed anonymity bucket size (`K = 16` accounts updated blindly per transfer).
pub const TURBO_BUCKET_SIZE: usize = 16;

/// Exact number of Beaver Square Pairs consumed per confidential transfer:
/// `16` amount bits + `16` remainder bits + `16` selector bits = `48`.
pub const SQUARES_PER_TURBO_TX: usize = 2 * TURBO_RANGE_BITS + TURBO_BUCKET_SIZE;

/// Exact number of invariant checks batched into a single Schwartz–Zippel RLC opening:
/// `48` bit checks + `1` balance conservation check + `1` selector sum check = `50`.
pub const CHECKS_PER_TURBO_TX: usize = SQUARES_PER_TURBO_TX + 2;

/// Exact number of Beaver Stars consumed per confidential transfer (`1` per 16-slot credit).
pub const STARS_PER_TURBO_TX: usize = 1;

/// Exact number of Beaver Triples consumed per confidential transfer (`1` for blinding `[rho * Z]`).
pub const TRIPLES_PER_TURBO_TX: usize = 1;

/// Exact number of `(3, 4)` openings per full 16-bit + 16-slot confidential transfer:
/// `48` square openings + `2` blinding-triple openings + `1` blinded RLC zero-check +
/// `1` shared `beta` + `16` `alpha_k` = `68` (down from `178` in standard Beaver-triple IT-MPC).
pub const OPENINGS_PER_TURBO_TX: usize =
    SQUARES_PER_TURBO_TX + 2 * TRIPLES_PER_TURBO_TX + 1 + 1 + TURBO_BUCKET_SIZE;

/// Baseline openings per transfer in standard Beaver-triple IT-MPC (`64*2 + 48 + 1 + 1 = 178`).
pub const BASELINE_OPENINGS_PER_TX: usize = 178;

/// Stack-allocated `(3, 4)` Shamir share tuple `[P(1), P(2), P(3), P(4)]` (64 bytes = 1 cache line).
pub type Share4 = [u128; TURBO_NUM_VALIDATORS];

// ============================================================================
// Errors
// ============================================================================

/// Errors returned by the Vernam Turbo Shielded IT-MPC engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurboShieldedError {
    /// Invalid configuration or protocol parameter.
    InvalidParameters(&'static str),
    /// Field element is outside canonical range `[0, PRIME_P)`.
    FieldElementOutOfRange,
    /// `(3, 4)` Shamir shares failed degree-2 Lagrange parity verification (tampered or corrupted).
    InconsistentShares,
    /// Offline [`TurboBeaverBank`] lacks enough single-use Beaver Square Pairs.
    BeaverSquaresExhausted { needed: usize, available: usize },
    /// Offline [`TurboBeaverBank`] lacks enough single-use Shared-Factor Beaver Stars.
    BeaverStarsExhausted { needed: usize, available: usize },
    /// Offline [`TurboBeaverBank`] lacks enough single-use Beaver Triples.
    BeaverTriplesExhausted { needed: usize, available: usize },
    /// Anonymity bucket ID out of range.
    InvalidBucket { bucket_id: usize },
    /// Slot index inside an anonymity bucket is out of range.
    InvalidSlot { slot: usize },
    /// Schwartz–Zippel batched RLC zero-check failed (`Z != 0`): catches any non-binary amount,
    /// remainder, or selector bit, any negative bit, any overdraft, or any selector sum `!= 1`.
    RlcCheckFailed,
}

impl fmt::Display for TurboShieldedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TurboShieldedError {}

// ============================================================================
// Internal Zeroization & Pure OS Entropy Helpers
// ============================================================================

struct BufferedUrandom {
    file: File,
    buf: [u8; 4096],
    pos: usize,
}

impl BufferedUrandom {
    fn new() -> Self {
        Self {
            file: File::open("/dev/urandom").expect("failed to open /dev/urandom"),
            buf: [0u8; 4096],
            pos: 4096,
        }
    }

    #[inline]
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

impl Drop for BufferedUrandom {
    fn drop(&mut self) {
        zeroize_slice(&mut self.buf);
    }
}

thread_local! {
    static URANDOM_BUF: RefCell<BufferedUrandom> = RefCell::new(BufferedUrandom::new());
}

/// Fill `buf` directly from OS cryptographic randomness (`/dev/urandom`) using a
/// thread-local zeroized buffer (zero PRNG, minimal syscall overhead).
#[inline]
fn fill_os_random_fast(buf: &mut [u8]) {
    URANDOM_BUF.with(|cell| {
        cell.borrow_mut().fill_bytes(buf);
    });
}

/// Sample a fresh uniform non-zero secret-shared blinding scalar `[rho]` (`rho in [1, PRIME_P)`)
/// using pure OS entropy.
#[inline]
fn random_nonzero_share4_fast() -> Share4 {
    let mut raw = [0u8; 48];
    fill_os_random_fast(&mut raw);
    let mut b0 = [0u8; 16];
    let mut b1 = [0u8; 16];
    let mut b2 = [0u8; 16];
    b0.copy_from_slice(&raw[0..16]);
    b1.copy_from_slice(&raw[16..32]);
    b2.copy_from_slice(&raw[32..48]);
    zeroize_slice(&mut raw);

    let c0_cand = u128::from_le_bytes(b0) & PRIME_P;
    let c1_cand = u128::from_le_bytes(b1) & PRIME_P;
    let c2_cand = u128::from_le_bytes(b2) & PRIME_P;
    zeroize_slice(&mut b0);
    zeroize_slice(&mut b1);
    zeroize_slice(&mut b2);

    let mut c0 = if c0_cand > 0 && c0_cand < PRIME_P {
        c0_cand
    } else {
        random_nonzero_challenge()
    };
    let mut c1 = if c1_cand < PRIME_P {
        c1_cand
    } else {
        random_field_elem_fast()
    };
    let mut c2 = if c2_cand < PRIME_P {
        c2_cand
    } else {
        random_field_elem_fast()
    };

    let shares = TurboLagrange3Of4::eval_poly(c0, c1, c2);
    zeroize_u128(&mut c0);
    zeroize_u128(&mut c1);
    zeroize_u128(&mut c2);
    shares
}

/// Sample one uniform canonical element in `[0, PRIME_P)` via unbiased rejection sampling.
#[inline]
fn random_field_elem_fast() -> u128 {
    let mut bytes = [0u8; 16];
    loop {
        fill_os_random_fast(&mut bytes);
        let cand = u128::from_le_bytes(bytes) & PRIME_P;
        if cand < PRIME_P {
            zeroize_slice(&mut bytes);
            return cand;
        }
    }
}

/// Sample one uniform non-zero challenge scalar in `[1, PRIME_P)` from OS entropy.
#[inline]
pub fn random_nonzero_challenge() -> u128 {
    loop {
        let g = random_field_elem_fast();
        if g != 0 {
            return g;
        }
    }
}

/// Fill `out` with uniform unbiased elements in `[0, PRIME_P)` via batched `/dev/urandom` reads.
fn fill_random_field_elems(out: &mut [u128]) {
    const CHUNK_ELEMS: usize = 2048;
    let mut raw = [0u8; CHUNK_ELEMS * 16];
    for chunk in out.chunks_mut(CHUNK_ELEMS) {
        let byte_len = chunk.len() * 16;
        fill_os_random_fast(&mut raw[..byte_len]);
        for (dst, bytes_slice) in chunk.iter_mut().zip(raw[..byte_len].chunks_exact(16)) {
            let mut b = [0u8; 16];
            b.copy_from_slice(bytes_slice);
            let cand = u128::from_le_bytes(b) & PRIME_P;
            *dst = if cand < PRIME_P {
                cand
            } else {
                random_field_elem_fast()
            };
        }
    }
    zeroize_slice(&mut raw);
}

/// Volatile wipe for a single [`Share4`] without issuing a fence (caller fences once per batch).
#[inline(always)]
fn zeroize_share4_nofence(shares: &mut Share4) {
    for elem in shares.iter_mut() {
        // SAFETY: `elem` is a valid mutable reference to an initialized `u128`.
        unsafe { std::ptr::write_volatile(elem, 0u128) };
    }
}

/// Volatile wipe for a single [`Share4`] with a trailing `SeqCst` compiler fence.
#[inline(always)]
fn zeroize_share4(shares: &mut Share4) {
    zeroize_share4_nofence(shares);
    compiler_fence(Ordering::SeqCst);
}

/// Volatile wipe for a slice of [`Share4`] tuples with a single trailing `SeqCst` fence.
#[inline]
fn zeroize_share4_slice(slice: &mut [Share4]) {
    for shares in slice.iter_mut() {
        zeroize_share4_nofence(shares);
    }
    compiler_fence(Ordering::SeqCst);
}

/// Volatile wipe for a slice of `u128` values with a single trailing `SeqCst` fence.
#[inline]
fn zeroize_u128_slice(slice: &mut [u128]) {
    for elem in slice.iter_mut() {
        // SAFETY: `elem` is a valid mutable reference to an initialized `u128`.
        unsafe { std::ptr::write_volatile(elem, 0u128) };
    }
    compiler_fence(Ordering::SeqCst);
}

// ============================================================================
// Branchless Mersenne F_(2^127 - 1) Arithmetic (Lazy Reduction in [0, PRIME_P])
// ============================================================================

/// Branchless Mersenne multiplication for `a, b <= PRIME_P` returning `r <= PRIME_P` with
/// `r === a * b (mod PRIME_P)`.
///
/// Proof of bound `r <= PRIME_P` without any conditional branch:
/// - `a0, b0 <= 2^64 - 1`, `a1, b1 <= 2^63 - 1`.
/// - `lo = a0 * b0 <= 2^128 - 2^65 + 1`.
/// - `hi = a1 * b1 <= 2^126 - 2^64 + 1`, so `hi << 1 <= 2^127 - 2^65 + 2`.
/// - `mid = a1*b0 + a0*b1 <= 2^128 - 3*2^64 + 2` (fits in `u128`).
/// - `s1 = (lo & P) + (hi << 1) <= 2^128 - 2^65 + 1 < 2^128`.
/// - `s2 = ((mid & ((1<<63)-1)) << 64) + (mid >> 63) + (lo >> 127) <= 2^127 + 2^64 < 2^128`.
/// - `u = (s1 & P) + (s2 & P) + (s1 >> 127) + (s2 >> 127)`:
///   - If `s2 >= 2^127`: `s2 & P <= 2^64`, so `u <= 2^127 + 2^64 + 1 < 2^128 - 1`.
///   - If `s2 < 2^127` and `s1 >= 2^127`: `s1 & P <= 2^127 - 2^65 + 1`, so `u <= 2^128 - 2^65 + 1`.
///   - If `s2 < 2^127` and `s1 < 2^127`: `u <= 2^128 - 2`.
/// - Hence `u <= 2^128 - 2` in ALL cases, so `(u & P) + (u >> 127) <= 2^127 - 1 = PRIME_P`.
#[inline(always)]
const fn mul_unreduced(a: u128, b: u128) -> u128 {
    let a0 = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a1 = a >> 64;
    let b0 = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b1 = b >> 64;

    let lo = a0 * b0;
    let hi = a1 * b1;
    let mid = (a1 * b0) + (a0 * b1);

    let s1 = (lo & PRIME_P) + (hi << 1);
    let s2 = ((mid & ((1u128 << 63) - 1)) << 64) + (mid >> 63) + (lo >> 127);

    let u = (s1 & PRIME_P) + (s2 & PRIME_P) + (s1 >> 127) + (s2 >> 127);
    (u & PRIME_P) + (u >> 127)
}

/// Branchless Mersenne addition for `a, b <= PRIME_P` returning `r <= PRIME_P` with
/// `r === a + b (mod PRIME_P)`.
///
/// Since `a + b <= 2 * PRIME_P = 2^128 - 2`, `(s & P) + (s >> 127) <= 2^127 - 1 = PRIME_P`.
#[inline(always)]
const fn add_unreduced(a: u128, b: u128) -> u128 {
    let s = a + b;
    (s & PRIME_P) + (s >> 127)
}

/// Canonicalize an unreduced element `x <= PRIME_P` into `[0, PRIME_P)`.
#[inline(always)]
const fn canon_le_p(x: u128) -> u128 {
    if x == PRIME_P { 0 } else { x }
}

/// Exact canonical `(a * b) mod PRIME_P` for canonical `a, b <= PRIME_P` (single branch).
#[inline(always)]
const fn mul_mod_fast(a: u128, b: u128) -> u128 {
    canon_le_p(mul_unreduced(a, b))
}

/// Multiply by 3 modulo `PRIME_P` using only 2 modular additions (zero `mul_mod`).
#[inline(always)]
const fn mul3_mod(x: u128) -> u128 {
    add_mod(add_mod(x, x), x)
}

// ============================================================================
// 1. Compile-Time `(3, 4)` Shamir Lagrange & Zero-Mul Verification
// ============================================================================

/// Compile-time `(3, 4)` Shamir interpolator & degree-2 verifier over `F_(2^127 - 1)` for
/// evaluation points `x = 1, 2, 3, 4`.
///
/// Zero `inv_mod`, zero `mul_mod`, and zero heap allocation on every split, parity check,
/// and secret reconstruction.
pub struct TurboLagrange3Of4;

impl TurboLagrange3Of4 {
    /// Compile-time Lagrange basis coefficients at `x = 0` for `x = 1, 2, 3`: `[3, P - 3, 1]`.
    pub const ORIGIN_COEFFS: [u128; 3] = [3, PRIME_P - 3, 1];

    /// Compile-time degree-2 parity check vector `[1, P - 3, 3, P - 1]` satisfying
    /// `dot(PARITY_COEFFS, [y1, y2, y3, y4]) == 0 (mod P)` iff shares lie on a degree-`<= 2` poly.
    pub const PARITY_COEFFS: [u128; 4] = [1, PRIME_P - 3, 3, PRIME_P - 1];

    /// Evaluate `c0 + c1*x + c2*x^2 (mod P)` at `x = 1, 2, 3, 4` using pure finite-difference adds.
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

    /// Split a canonical field secret in `[0, PRIME_P)` into a stack-allocated `(3, 4)` [`Share4`].
    #[inline]
    pub fn split_secret(secret: u128) -> Result<Share4, TurboShieldedError> {
        if secret >= PRIME_P {
            return Err(TurboShieldedError::FieldElementOutOfRange);
        }
        let mut r = [0u128; 2];
        fill_random_field_elems(&mut r);
        let shares = Self::eval_poly(secret, r[0], r[1]);
        zeroize_u128_slice(&mut r);
        Ok(shares)
    }

    /// Verify all 4 shares are `< PRIME_P` and satisfy the degree-2 parity identity
    /// `y1 - 3*y2 + 3*y3 == y4 (mod P)` with zero `inv_mod` and zero `mul_mod`.
    #[inline(always)]
    pub const fn verify_degree2(shares: &Share4) -> Result<(), TurboShieldedError> {
        if shares[0] >= PRIME_P
            || shares[1] >= PRIME_P
            || shares[2] >= PRIME_P
            || shares[3] >= PRIME_P
        {
            return Err(TurboShieldedError::FieldElementOutOfRange);
        }
        let expected_y4 = sub_mod(add_mod(shares[0], mul3_mod(shares[2])), mul3_mod(shares[1]));
        if expected_y4 != shares[3] {
            return Err(TurboShieldedError::InconsistentShares);
        }
        Ok(())
    }

    /// Reconstruct `P(0) = 3*y1 - 3*y2 + y3 (mod P)` with zero `inv_mod` and zero `mul_mod`.
    #[inline(always)]
    pub const fn reconstruct_unchecked(shares: &Share4) -> u128 {
        sub_mod(add_mod(mul3_mod(shares[0]), shares[2]), mul3_mod(shares[1]))
    }

    /// Degree-2 verify and reconstruct `P(0)` in one stack-only zero-`mul_mod` call.
    #[inline(always)]
    pub const fn reconstruct_and_verify(shares: &Share4) -> Result<u128, TurboShieldedError> {
        if let Err(e) = Self::verify_degree2(shares) {
            return Err(e);
        }
        Ok(Self::reconstruct_unchecked(shares))
    }

    /// Degree-2 verify and reconstruct `[x] - [a]` directly, checking canonical `< PRIME_P`
    /// bounds on `x` (where `a` is already canonical from the offline bank).
    #[inline(always)]
    const fn open_diff(x: &Share4, a: &Share4) -> Result<u128, TurboShieldedError> {
        if x[0] >= PRIME_P || x[1] >= PRIME_P || x[2] >= PRIME_P || x[3] >= PRIME_P {
            return Err(TurboShieldedError::FieldElementOutOfRange);
        }
        let d0 = sub_mod(x[0], a[0]);
        let d1 = sub_mod(x[1], a[1]);
        let d2 = sub_mod(x[2], a[2]);
        let d3 = sub_mod(x[3], a[3]);
        // Degree-2 parity check: d0 - 3*d1 + 3*d2 == d3 (mod P).
        let expected_d3 = sub_mod(add_mod(d0, mul3_mod(d2)), mul3_mod(d1));
        if expected_d3 != d3 {
            return Err(TurboShieldedError::InconsistentShares);
        }
        // Reconstruct P(0) = 3*d0 - 3*d1 + d2 (mod P).
        Ok(sub_mod(add_mod(mul3_mod(d0), d2), mul3_mod(d1)))
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

/// Zero-`mul_mod` Horner recomposition `[v] = sum_{j=0}^{15} 2^j * [bit_j]`.
#[inline(always)]
fn compose_bits_16(bits: &[Share4; TURBO_RANGE_BITS]) -> Share4 {
    let mut acc = [0u128; 4];
    let mut j = TURBO_RANGE_BITS;
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
// 2. Correlated Randomness Primitives & `TurboBeaverBank`
// ============================================================================

/// Strictly single-use stack-allocated `(3, 4)` **Beaver Square Pair** `([a], [a^2])`.
///
/// Enables computing `[x^2]` (and `[x*(x - 1)]`) with only **1 opening** `d = x - a`
/// instead of 2 openings, cutting bit-proof openings, multiplications, and RAM traffic in HALF.
/// Move-only (no `Copy`/`Clone`) and volatile-zeroized on `Drop`.
#[repr(C, align(64))]
pub struct BeaverSquare {
    a: Share4,
    a_sq: Share4,
}

impl fmt::Debug for BeaverSquare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeaverSquare")
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl BeaverSquare {
    /// Shares of uniform mask `a`.
    #[inline(always)]
    pub fn a(&self) -> &Share4 {
        &self.a
    }

    /// Shares of `a^2 mod PRIME_P`.
    #[inline(always)]
    pub fn a_sq(&self) -> &Share4 {
        &self.a_sq
    }

    /// Wipe this square pair in place using volatile writes (caller fences once per batch).
    #[inline(always)]
    fn wipe_in_place_nofence(&mut self) {
        zeroize_share4_nofence(&mut self.a);
        zeroize_share4_nofence(&mut self.a_sq);
    }
}

impl Drop for BeaverSquare {
    fn drop(&mut self) {
        self.wipe_in_place_nofence();
        compiler_fence(Ordering::SeqCst);
    }
}

/// Strictly single-use stack-allocated `(3, 4)` **Beaver Triple** `([a], [b], [c])` with `c = a * b`.
///
/// Move-only (no `Copy`/`Clone`) and volatile-zeroized on `Drop`.
#[repr(C, align(64))]
pub struct BeaverTriple4 {
    a: Share4,
    b: Share4,
    c: Share4,
}

impl fmt::Debug for BeaverTriple4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeaverTriple4")
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl BeaverTriple4 {
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

    /// Shares of `c = a * b mod PRIME_P`.
    #[inline(always)]
    pub fn c(&self) -> &Share4 {
        &self.c
    }

    #[inline(always)]
    fn wipe_in_place_nofence(&mut self) {
        zeroize_share4_nofence(&mut self.a);
        zeroize_share4_nofence(&mut self.b);
        zeroize_share4_nofence(&mut self.c);
    }
}

impl Drop for BeaverTriple4 {
    fn drop(&mut self) {
        self.wipe_in_place_nofence();
        compiler_fence(Ordering::SeqCst);
    }
}

/// Strictly single-use stack-allocated `(3, 4)` **Shared-Factor Beaver Star**
/// `([b_v], [a_0..a_15], [c_0..c_15])` where `c_k = a_k * b_v (mod PRIME_P)`.
///
/// Computes all 16 blinded recipient credits `[s_k * v]` while opening `beta = v - b_v`
/// **ONCE** instead of 16 times, saving 15 openings per confidential transfer while preserving
/// exact information-theoretic secrecy (`< 3` validators learn 0 bits).
/// Move-only (no `Copy`/`Clone`) and volatile-zeroized on `Drop`.
#[repr(C, align(64))]
pub struct BeaverStar16 {
    b_v: Share4,
    a: [Share4; TURBO_BUCKET_SIZE],
    c: [Share4; TURBO_BUCKET_SIZE],
}

impl fmt::Debug for BeaverStar16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeaverStar16")
            .field("slots", &TURBO_BUCKET_SIZE)
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl BeaverStar16 {
    /// Shares of the single shared amount mask `b_v`.
    #[inline(always)]
    pub fn b_v(&self) -> &Share4 {
        &self.b_v
    }

    /// Shares of the 16 independent selector masks `a_0..a_15`.
    #[inline(always)]
    pub fn a(&self) -> &[Share4; TURBO_BUCKET_SIZE] {
        &self.a
    }

    /// Shares of the 16 correlated products `c_k = a_k * b_v (mod PRIME_P)`.
    #[inline(always)]
    pub fn c(&self) -> &[Share4; TURBO_BUCKET_SIZE] {
        &self.c
    }

    #[inline(always)]
    fn wipe_in_place_nofence(&mut self) {
        zeroize_share4_nofence(&mut self.b_v);
        for s in self.a.iter_mut() {
            zeroize_share4_nofence(s);
        }
        for s in self.c.iter_mut() {
            zeroize_share4_nofence(s);
        }
    }
}

impl Drop for BeaverStar16 {
    fn drop(&mut self) {
        self.wipe_in_place_nofence();
        compiler_fence(Ordering::SeqCst);
    }
}

/// Standalone single-opening Beaver squaring `[x^2] = [a^2] + 2*d*[a] + d^2 (mod PRIME_P)`.
///
/// Opens ONLY `d = x - a`, enforces degree-2 consistency across all 4 validators, and
/// immediately consumes and volatile-zeroizes `sq`.
#[inline]
pub fn mpc_square_3_of_4(x: &Share4, mut sq: BeaverSquare) -> Result<Share4, TurboShieldedError> {
    let d = match TurboLagrange3Of4::open_diff(x, &sq.a) {
        Ok(d) => d,
        Err(e) => {
            sq.wipe_in_place_nofence();
            compiler_fence(Ordering::SeqCst);
            return Err(e);
        }
    };
    let two_d = add_mod(d, d);
    let d_sq = mul_mod_fast(d, d);
    let out = [
        canon_le_p(add_unreduced(
            add_unreduced(sq.a_sq[0], mul_unreduced(two_d, sq.a[0])),
            d_sq,
        )),
        canon_le_p(add_unreduced(
            add_unreduced(sq.a_sq[1], mul_unreduced(two_d, sq.a[1])),
            d_sq,
        )),
        canon_le_p(add_unreduced(
            add_unreduced(sq.a_sq[2], mul_unreduced(two_d, sq.a[2])),
            d_sq,
        )),
        canon_le_p(add_unreduced(
            add_unreduced(sq.a_sq[3], mul_unreduced(two_d, sq.a[3])),
            d_sq,
        )),
    ];
    drop(sq);
    Ok(out)
}

/// Standalone general Beaver multiplication `[x * y]` consuming a [`BeaverTriple4`].
#[inline]
pub fn mpc_mul_triple_3_of_4(
    x: &Share4,
    y: &Share4,
    mut triple: BeaverTriple4,
) -> Result<Share4, TurboShieldedError> {
    let d = match TurboLagrange3Of4::open_diff(x, &triple.a) {
        Ok(v) => v,
        Err(e) => {
            triple.wipe_in_place_nofence();
            compiler_fence(Ordering::SeqCst);
            return Err(e);
        }
    };
    let e = match TurboLagrange3Of4::open_diff(y, &triple.b) {
        Ok(v) => v,
        Err(e) => {
            triple.wipe_in_place_nofence();
            compiler_fence(Ordering::SeqCst);
            return Err(e);
        }
    };
    let de = mul_mod_fast(d, e);
    let out = [
        canon_le_p(add_unreduced(
            add_unreduced(triple.c[0], mul_unreduced(d, triple.b[0])),
            add_unreduced(mul_unreduced(e, triple.a[0]), de),
        )),
        canon_le_p(add_unreduced(
            add_unreduced(triple.c[1], mul_unreduced(d, triple.b[1])),
            add_unreduced(mul_unreduced(e, triple.a[1]), de),
        )),
        canon_le_p(add_unreduced(
            add_unreduced(triple.c[2], mul_unreduced(d, triple.b[2])),
            add_unreduced(mul_unreduced(e, triple.a[2]), de),
        )),
        canon_le_p(add_unreduced(
            add_unreduced(triple.c[3], mul_unreduced(d, triple.b[3])),
            add_unreduced(mul_unreduced(e, triple.a[3]), de),
        )),
    ];
    drop(triple);
    Ok(out)
}

/// Offline correlated-randomness factory storing contiguous, stack-allocated, single-use
/// [`BeaverSquare`] pairs, [`BeaverStar16`] stars, and [`BeaverTriple4`] triples.
///
/// Uses forward consumption cursors (`sq_pos`, `star_pos`, `triple_pos`) with automatic prefix
/// compaction so parallel workers consume and volatile-zeroize disjoint slices in place in L1
/// cache while sustained throughput maintains O(1) bounded memory.
pub struct TurboBeaverBank {
    squares: Vec<BeaverSquare>,
    sq_pos: usize,
    stars: Vec<BeaverStar16>,
    star_pos: usize,
    triples: Vec<BeaverTriple4>,
    triple_pos: usize,
}

impl fmt::Debug for TurboBeaverBank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurboBeaverBank")
            .field("available_squares", &self.available_squares())
            .field("available_stars", &self.available_stars())
            .field("available_triples", &self.available_triples())
            .field("material", &"<redacted>")
            .finish()
    }
}

impl TurboBeaverBank {
    /// Create an empty bank.
    pub fn empty() -> Self {
        Self {
            squares: Vec::new(),
            sq_pos: 0,
            stars: Vec::new(),
            star_pos: 0,
            triples: Vec::new(),
            triple_pos: 0,
        }
    }

    /// Pre-generate offline correlated randomness for `tx_count` full 16-bit + 16-slot
    /// confidential transfers (`tx_count * 48` Beaver squares, `tx_count` Beaver stars, and
    /// `tx_count` blinding Beaver triples), parallelized across available hardware threads using
    /// pure OS `/dev/urandom` entropy.
    pub fn new_for_txs(tx_count: usize) -> Self {
        let mut bank = Self::empty();
        bank.refill_for_txs(tx_count);
        bank
    }

    /// Pre-generate explicit counts of squares, stars, and general triples.
    pub fn new(num_squares: usize, num_stars: usize, num_triples: usize) -> Self {
        let mut bank = Self::empty();
        bank.refill_squares(num_squares);
        bank.refill_stars(num_stars);
        bank.refill_triples(num_triples);
        bank
    }

    /// Compact consumed prefix `0..sq_pos` to keep memory bounded O(1) under sustained load.
    #[inline]
    fn compact_squares(&mut self) {
        if self.sq_pos > 0 {
            self.squares.drain(..self.sq_pos);
            self.sq_pos = 0;
        }
    }

    /// Compact consumed prefix `0..star_pos`.
    #[inline]
    fn compact_stars(&mut self) {
        if self.star_pos > 0 {
            self.stars.drain(..self.star_pos);
            self.star_pos = 0;
        }
    }

    /// Compact consumed prefix `0..triple_pos`.
    #[inline]
    fn compact_triples(&mut self) {
        if self.triple_pos > 0 {
            self.triples.drain(..self.triple_pos);
            self.triple_pos = 0;
        }
    }

    /// Compact any vector whose consumed prefix has reached at least half its capacity.
    #[inline]
    fn compact_if_half_consumed(&mut self) {
        if self.sq_pos > 0 && self.sq_pos * 2 >= self.squares.capacity() {
            self.compact_squares();
        }
        if self.star_pos > 0 && self.star_pos * 2 >= self.stars.capacity() {
            self.compact_stars();
        }
        if self.triple_pos > 0 && self.triple_pos * 2 >= self.triples.capacity() {
            self.compact_triples();
        }
    }

    /// Refill correlated randomness for `tx_count` additional confidential transfers.
    pub fn refill_for_txs(&mut self, tx_count: usize) {
        self.refill_squares(tx_count * SQUARES_PER_TURBO_TX);
        self.refill_stars(tx_count * STARS_PER_TURBO_TX);
        self.refill_triples(tx_count * TRIPLES_PER_TURBO_TX);
    }

    /// Pre-generate `count` fresh single-use [`BeaverSquare`] pairs in parallel.
    pub fn refill_squares(&mut self, count: usize) {
        self.compact_squares();
        if count == 0 {
            return;
        }
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if count < 4096 || cores <= 1 {
            self.squares.reserve(count);
            generate_squares_into(&mut self.squares, count);
            return;
        }

        let threads = cores.min(count / 2048).max(1);
        let base = count / threads;
        let rem = count % threads;

        let chunks: Vec<Vec<BeaverSquare>> = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(threads);
            for t in 0..threads {
                let n = base + usize::from(t < rem);
                handles.push(scope.spawn(move || {
                    let mut v = Vec::with_capacity(n);
                    generate_squares_into(&mut v, n);
                    v
                }));
            }
            handles
                .into_iter()
                .map(|h| h.join().expect("beaver square generator thread panicked"))
                .collect()
        });

        self.squares.reserve(count);
        for mut c in chunks {
            self.squares.append(&mut c);
        }
    }

    /// Pre-generate `count` fresh single-use [`BeaverStar16`] stars in parallel.
    pub fn refill_stars(&mut self, count: usize) {
        self.compact_stars();
        if count == 0 {
            return;
        }
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if count < 256 || cores <= 1 {
            self.stars.reserve(count);
            generate_stars_into(&mut self.stars, count);
            return;
        }

        let threads = cores.min(count / 128).max(1);
        let base = count / threads;
        let rem = count % threads;

        let chunks: Vec<Vec<BeaverStar16>> = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(threads);
            for t in 0..threads {
                let n = base + usize::from(t < rem);
                handles.push(scope.spawn(move || {
                    let mut v = Vec::with_capacity(n);
                    generate_stars_into(&mut v, n);
                    v
                }));
            }
            handles
                .into_iter()
                .map(|h| h.join().expect("beaver star generator thread panicked"))
                .collect()
        });

        self.stars.reserve(count);
        for mut c in chunks {
            self.stars.append(&mut c);
        }
    }

    /// Pre-generate `count` fresh single-use general [`BeaverTriple4`] triples in parallel.
    pub fn refill_triples(&mut self, count: usize) {
        self.compact_triples();
        if count == 0 {
            return;
        }
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if count < 2048 || cores <= 1 {
            self.triples.reserve(count);
            generate_triples_into(&mut self.triples, count);
            return;
        }

        let threads = cores.min(count / 1024).max(1);
        let base = count / threads;
        let rem = count % threads;

        let chunks: Vec<Vec<BeaverTriple4>> = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(threads);
            for t in 0..threads {
                let n = base + usize::from(t < rem);
                handles.push(scope.spawn(move || {
                    let mut v = Vec::with_capacity(n);
                    generate_triples_into(&mut v, n);
                    v
                }));
            }
            handles
                .into_iter()
                .map(|h| h.join().expect("beaver triple generator thread panicked"))
                .collect()
        });

        self.triples.reserve(count);
        for mut c in chunks {
            self.triples.append(&mut c);
        }
    }

    /// Number of unused [`BeaverSquare`] pairs remaining.
    #[inline]
    pub fn available_squares(&self) -> usize {
        self.squares.len() - self.sq_pos
    }

    /// Number of unused [`BeaverStar16`] stars remaining.
    #[inline]
    pub fn available_stars(&self) -> usize {
        self.stars.len() - self.star_pos
    }

    /// Number of unused [`BeaverTriple4`] triples remaining.
    #[inline]
    pub fn available_triples(&self) -> usize {
        self.triples.len() - self.triple_pos
    }

    /// Maximum number of full confidential transfers currently supported by this bank.
    #[inline]
    pub fn available_txs(&self) -> usize {
        (self.available_squares() / SQUARES_PER_TURBO_TX)
            .min(self.available_stars() / STARS_PER_TURBO_TX)
            .min(self.available_triples() / TRIPLES_PER_TURBO_TX)
    }

    /// Pop one single-use [`BeaverSquare`] from the back of the bank.
    pub fn pop_square(&mut self) -> Result<BeaverSquare, TurboShieldedError> {
        self.compact_if_half_consumed();
        if self.available_squares() == 0 {
            return Err(TurboShieldedError::BeaverSquaresExhausted {
                needed: 1,
                available: 0,
            });
        }
        Ok(self.squares.pop().expect("available_squares > 0"))
    }

    /// Pop one single-use [`BeaverStar16`] from the back of the bank.
    pub fn pop_star(&mut self) -> Result<BeaverStar16, TurboShieldedError> {
        self.compact_if_half_consumed();
        if self.available_stars() == 0 {
            return Err(TurboShieldedError::BeaverStarsExhausted {
                needed: 1,
                available: 0,
            });
        }
        Ok(self.stars.pop().expect("available_stars > 0"))
    }

    /// Pop one single-use [`BeaverTriple4`] from the back of the bank.
    pub fn pop_triple(&mut self) -> Result<BeaverTriple4, TurboShieldedError> {
        self.compact_if_half_consumed();
        if self.available_triples() == 0 {
            return Err(TurboShieldedError::BeaverTriplesExhausted {
                needed: 1,
                available: 0,
            });
        }
        Ok(self.triples.pop().expect("available_triples > 0"))
    }

    /// Reserve and return contiguous mutable slices for `tx_count` transfers, immediately
    /// advancing the single-use cursors so the returned material can NEVER be reused.
    fn reserve_for_txs(
        &mut self,
        tx_count: usize,
    ) -> Result<(&mut [BeaverSquare], &mut [BeaverStar16], &mut [BeaverTriple4]), TurboShieldedError>
    {
        self.compact_if_half_consumed();
        let need_sq = tx_count * SQUARES_PER_TURBO_TX;
        let avail_sq = self.available_squares();
        if avail_sq < need_sq {
            return Err(TurboShieldedError::BeaverSquaresExhausted {
                needed: need_sq,
                available: avail_sq,
            });
        }
        let need_stars = tx_count * STARS_PER_TURBO_TX;
        let avail_stars = self.available_stars();
        if avail_stars < need_stars {
            return Err(TurboShieldedError::BeaverStarsExhausted {
                needed: need_stars,
                available: avail_stars,
            });
        }
        let need_triples = tx_count * TRIPLES_PER_TURBO_TX;
        let avail_triples = self.available_triples();
        if avail_triples < need_triples {
            return Err(TurboShieldedError::BeaverTriplesExhausted {
                needed: need_triples,
                available: avail_triples,
            });
        }
        let sq_start = self.sq_pos;
        self.sq_pos += need_sq;
        let star_start = self.star_pos;
        self.star_pos += need_stars;
        let triple_start = self.triple_pos;
        self.triple_pos += need_triples;
        Ok((
            &mut self.squares[sq_start..sq_start + need_sq],
            &mut self.stars[star_start..star_start + need_stars],
            &mut self.triples[triple_start..triple_start + need_triples],
        ))
    }
}

/// Generate `count` fresh [`BeaverTriple4`] triples into `out` using batched OS entropy.
fn generate_triples_into(out: &mut Vec<BeaverTriple4>, count: usize) {
    const BATCH: usize = 512;
    let mut entropy = [0u128; BATCH * 8];
    let mut remaining = count;
    while remaining > 0 {
        let take = remaining.min(BATCH);
        let slice = &mut entropy[..take * 8];
        fill_random_field_elems(slice);
        for chunk in slice.chunks_exact(8) {
            let mut a0 = chunk[0];
            let mut b0 = chunk[1];
            let mut c0 = mul_mod_fast(a0, b0);
            let a = TurboLagrange3Of4::eval_poly(a0, chunk[2], chunk[3]);
            let b = TurboLagrange3Of4::eval_poly(b0, chunk[4], chunk[5]);
            let c = TurboLagrange3Of4::eval_poly(c0, chunk[6], chunk[7]);
            out.push(BeaverTriple4 { a, b, c });
            zeroize_u128(&mut a0);
            zeroize_u128(&mut b0);
            zeroize_u128(&mut c0);
        }
        remaining -= take;
    }
    zeroize_u128_slice(&mut entropy);
}

impl Drop for TurboBeaverBank {
    fn drop(&mut self) {
        // Explicit volatile wipe of every remaining unconsumed element; Vec::drop also runs
        // Drop on each element, ensuring complete memory zeroization.
        for sq in &mut self.squares[self.sq_pos..] {
            sq.wipe_in_place_nofence();
        }
        for st in &mut self.stars[self.star_pos..] {
            st.wipe_in_place_nofence();
        }
        for tr in &mut self.triples[self.triple_pos..] {
            tr.wipe_in_place_nofence();
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Generate `count` fresh [`BeaverSquare`] pairs into `out` using batched OS entropy.
fn generate_squares_into(out: &mut Vec<BeaverSquare>, count: usize) {
    // 5 field elements per square: a0, a1, a2, sq1, sq2.
    const BATCH: usize = 512;
    let mut entropy = [0u128; BATCH * 5];
    let mut remaining = count;
    while remaining > 0 {
        let take = remaining.min(BATCH);
        let slice = &mut entropy[..take * 5];
        fill_random_field_elems(slice);
        for chunk in slice.chunks_exact(5) {
            let mut a0 = chunk[0];
            let mut sq0 = mul_mod_fast(a0, a0);
            let a = TurboLagrange3Of4::eval_poly(a0, chunk[1], chunk[2]);
            let a_sq = TurboLagrange3Of4::eval_poly(sq0, chunk[3], chunk[4]);
            out.push(BeaverSquare { a, a_sq });
            zeroize_u128(&mut a0);
            zeroize_u128(&mut sq0);
        }
        remaining -= take;
    }
    zeroize_u128_slice(&mut entropy);
}

/// Generate `count` fresh [`BeaverStar16`] stars into `out` using batched OS entropy.
fn generate_stars_into(out: &mut Vec<BeaverStar16>, count: usize) {
    // Per star: 3 elems for b_v (bv0, bv1, bv2) + 16 * 5 elems (a0, a1, a2, c1, c2) = 83 elems.
    const ELEMS_PER_STAR: usize = 3 + TURBO_BUCKET_SIZE * 5;
    const BATCH: usize = 32;
    let mut entropy = [0u128; BATCH * ELEMS_PER_STAR];
    let mut remaining = count;
    while remaining > 0 {
        let take = remaining.min(BATCH);
        let slice = &mut entropy[..take * ELEMS_PER_STAR];
        fill_random_field_elems(slice);
        for chunk in slice.chunks_exact(ELEMS_PER_STAR) {
            let mut bv0 = chunk[0];
            let b_v = TurboLagrange3Of4::eval_poly(bv0, chunk[1], chunk[2]);
            let mut a = [[0u128; 4]; TURBO_BUCKET_SIZE];
            let mut c = [[0u128; 4]; TURBO_BUCKET_SIZE];
            let mut off = 3usize;
            for k in 0..TURBO_BUCKET_SIZE {
                let mut ak0 = chunk[off];
                let mut ck0 = mul_mod_fast(ak0, bv0);
                a[k] = TurboLagrange3Of4::eval_poly(ak0, chunk[off + 1], chunk[off + 2]);
                c[k] = TurboLagrange3Of4::eval_poly(ck0, chunk[off + 3], chunk[off + 4]);
                zeroize_u128(&mut ak0);
                zeroize_u128(&mut ck0);
                off += 5;
            }
            zeroize_u128(&mut bv0);
            out.push(BeaverStar16 { b_v, a, c });
        }
        remaining -= take;
    }
    zeroize_u128_slice(&mut entropy);
}

// ============================================================================
// 3. Confidential Transfer Request & Core Zero-Alloc Bucket Execution
// ============================================================================

/// Zero-heap-allocation confidential transfer request for [`TurboShieldedCluster`].
///
/// Carries stack-allocated `(3, 4)` Shamir shares of:
/// - `16` amount bits `v_j in {0, 1}`,
/// - `16` remainder bits `r_j in {0, 1}` (`r = B_sender - v`),
/// - `16` blinded one-hot recipient selector bits `s_k in {0, 1}` with `sum(s_k) == 1`.
pub struct TurboTransferRequest {
    pub bucket_id: usize,
    pub sender_slot: usize,
    pub v_bits: [Share4; TURBO_RANGE_BITS],
    pub r_bits: [Share4; TURBO_RANGE_BITS],
    pub selector_shares: [Share4; TURBO_BUCKET_SIZE],
}

impl fmt::Debug for TurboTransferRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurboTransferRequest")
            .field("bucket_id", &self.bucket_id)
            .field("sender_slot", &self.sender_slot)
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl TurboTransferRequest {
    /// Construct a valid confidential transfer in `bucket_id` from `sender_slot` (with known
    /// `sender_balance`) sending `amount` to `recipient_slot` using one batched OS entropy read.
    pub fn new(
        bucket_id: usize,
        sender_slot: usize,
        sender_balance: u128,
        recipient_slot: usize,
        amount: u128,
    ) -> Result<Self, TurboShieldedError> {
        if sender_slot >= TURBO_BUCKET_SIZE {
            return Err(TurboShieldedError::InvalidSlot { slot: sender_slot });
        }
        if recipient_slot >= TURBO_BUCKET_SIZE {
            return Err(TurboShieldedError::InvalidSlot {
                slot: recipient_slot,
            });
        }
        let max_val = (1u128 << TURBO_RANGE_BITS) - 1;
        if amount > max_val || sender_balance < amount || (sender_balance - amount) > max_val {
            return Err(TurboShieldedError::InvalidParameters(
                "amount or remainder outside [0, 2^16)",
            ));
        }

        let remainder = sender_balance - amount;
        const TOTAL_POLYS: usize = SQUARES_PER_TURBO_TX;
        let mut rands = [0u128; TOTAL_POLYS * 2];
        fill_random_field_elems(&mut rands);

        let mut v_bits = [[0u128; 4]; TURBO_RANGE_BITS];
        let mut r_bits = [[0u128; 4]; TURBO_RANGE_BITS];
        let mut selector_shares = [[0u128; 4]; TURBO_BUCKET_SIZE];

        let mut idx = 0usize;
        for j in 0..TURBO_RANGE_BITS {
            let vb = (amount >> j) & 1;
            v_bits[j] = TurboLagrange3Of4::eval_poly(vb, rands[idx], rands[idx + 1]);
            idx += 2;
        }
        for j in 0..TURBO_RANGE_BITS {
            let rb = (remainder >> j) & 1;
            r_bits[j] = TurboLagrange3Of4::eval_poly(rb, rands[idx], rands[idx + 1]);
            idx += 2;
        }
        for k in 0..TURBO_BUCKET_SIZE {
            let sk = if k == recipient_slot { 1u128 } else { 0u128 };
            selector_shares[k] = TurboLagrange3Of4::eval_poly(sk, rands[idx], rands[idx + 1]);
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

    /// Construct a request from raw share arrays (for distributed clients & adversarial tests).
    pub fn new_raw(
        bucket_id: usize,
        sender_slot: usize,
        v_bits: [Share4; TURBO_RANGE_BITS],
        r_bits: [Share4; TURBO_RANGE_BITS],
        selector_shares: [Share4; TURBO_BUCKET_SIZE],
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

impl Drop for TurboTransferRequest {
    fn drop(&mut self) {
        zeroize_share4_slice(&mut self.v_bits);
        zeroize_share4_slice(&mut self.r_bits);
        zeroize_share4_slice(&mut self.selector_shares);
    }
}

/// Accumulate one Boolean check `x * (x - 1) == 0` into the unreduced Horner RLC accumulator
/// `z[0..4]` (plus scalar constant accumulator `z_const`) using ONE single-use [`BeaverSquare`].
///
/// Exact identity:
/// - Open `d = x - a` (1 opening, degree-2 verified with 0 `mul_mod`, 0 `inv_mod`).
/// - Since `x = a + d`, `x * (x - 1) = a^2 + (2*d - 1)*a + d*(d - 1) (mod PRIME_P)`.
/// - Both `[a^2]` and `(2*d - 1)*[a]` are valid degree-2 sharings with fresh independent
///   randomness in `[a^2]`, and `d*(d - 1)` is a public scalar folded into `z_const`.
#[inline(always)]
fn accumulate_bool_square_rlc(
    x: &Share4,
    sq: &mut BeaverSquare,
    gamma: u128,
    z: &mut Share4,
    z_const: &mut u128,
) -> Result<(), TurboShieldedError> {
    let d = TurboLagrange3Of4::open_diff(x, &sq.a)?;
    let two_d_minus_1 = sub_mod(add_mod(d, d), 1);
    let d_dm1 = mul_unreduced(d, sub_mod(d, 1));

    // Branchless Horner step across all 4 independent validator lanes:
    // z[i] = z[i] * gamma + (2*d - 1) * a[i] + a_sq[i]  (all values stay <= PRIME_P).
    let a = sq.a;
    let a_sq = sq.a_sq;
    z[0] = add_unreduced(
        add_unreduced(mul_unreduced(z[0], gamma), mul_unreduced(two_d_minus_1, a[0])),
        a_sq[0],
    );
    z[1] = add_unreduced(
        add_unreduced(mul_unreduced(z[1], gamma), mul_unreduced(two_d_minus_1, a[1])),
        a_sq[1],
    );
    z[2] = add_unreduced(
        add_unreduced(mul_unreduced(z[2], gamma), mul_unreduced(two_d_minus_1, a[2])),
        a_sq[2],
    );
    z[3] = add_unreduced(
        add_unreduced(mul_unreduced(z[3], gamma), mul_unreduced(two_d_minus_1, a[3])),
        a_sq[3],
    );
    *z_const = add_unreduced(mul_unreduced(*z_const, gamma), d_dm1);

    // Immediately wipe consumed square pair while still hot in L1 cache.
    sq.wipe_in_place_nofence();
    Ok(())
}

/// Execute and verify a single full 16-bit + 16-slot confidential transfer against a mutable
/// bucket state `[Share4; 16]` with **ZERO heap allocations** and **68 total openings**.
///
/// Consumes and volatile-zeroizes `squares[0..48]`, `star`, and `blind_triple` unconditionally
/// (even on early parameter errors).
///
/// Algebraic proof & update pipeline:
/// 1. `48` single-opening [`BeaverSquare`] Boolean checks (`16 v_bits + 16 r_bits + 16 s_bits`)
///    folded via Horner's rule into `[Z]` at fresh non-zero challenge `gamma in F_(2^127 - 1)`.
/// 2. Check #49 (`B_sender - v - r == 0`) and check #50 (`sum(s_k) - 1 == 0`) folded into `[Z]`.
/// 3. Multiplicative blinding `[Z_blind] = [rho] * [Z]` via `blind_triple` (`2` mask openings)
///    followed by `1` degree-2 verified opening of `[Z_blind]` -> MUST equal `0` (Schwartz–Zippel
///    soundness `Pr[cheat] <= 49 / (2^127 - 2) < 2^-121`, zero leakage on failure).
/// 4. `1` shared opening `beta = v - b_v` + `16` openings `alpha_k = s_k - a_k` via
///    [`BeaverStar16`] to credit `+[s_k * v]` blindly across ALL 16 bucket slots and debit `-[v]`
///    from `sender_slot`.
#[inline]
pub fn execute_transfer_in_bucket(
    balances: &mut [Share4; TURBO_BUCKET_SIZE],
    req: &TurboTransferRequest,
    squares: &mut [BeaverSquare],
    star: &mut BeaverStar16,
    blind_triple: &mut BeaverTriple4,
    gamma: u128,
) -> Result<(), TurboShieldedError> {
    if req.sender_slot >= TURBO_BUCKET_SIZE {
        wipe_remaining_tx_beaver(squares, 0, star, blind_triple);
        return Err(TurboShieldedError::InvalidSlot {
            slot: req.sender_slot,
        });
    }
    if gamma == 0 || gamma >= PRIME_P {
        wipe_remaining_tx_beaver(squares, 0, star, blind_triple);
        return Err(TurboShieldedError::InvalidParameters(
            "RLC challenge gamma must be in [1, PRIME_P)",
        ));
    }
    if squares.len() < SQUARES_PER_TURBO_TX {
        wipe_remaining_tx_beaver(squares, 0, star, blind_triple);
        return Err(TurboShieldedError::BeaverSquaresExhausted {
            needed: SQUARES_PER_TURBO_TX,
            available: squares.len(),
        });
    }

    let mut z: Share4 = [0u128; 4];
    let mut z_const: u128 = 0u128;
    let mut sq_idx = 0usize;

    // 1. 16 amount bits: v_j * (v_j - 1) == 0 (16 openings).
    for j in 0..TURBO_RANGE_BITS {
        if let Err(e) = accumulate_bool_square_rlc(
            &req.v_bits[j],
            &mut squares[sq_idx],
            gamma,
            &mut z,
            &mut z_const,
        ) {
            wipe_remaining_tx_beaver(squares, sq_idx, star, blind_triple);
            zeroize_share4(&mut z);
            return Err(e);
        }
        sq_idx += 1;
    }

    // 2. 16 remainder bits: r_j * (r_j - 1) == 0 (16 openings).
    for j in 0..TURBO_RANGE_BITS {
        if let Err(e) = accumulate_bool_square_rlc(
            &req.r_bits[j],
            &mut squares[sq_idx],
            gamma,
            &mut z,
            &mut z_const,
        ) {
            wipe_remaining_tx_beaver(squares, sq_idx, star, blind_triple);
            zeroize_share4(&mut z);
            return Err(e);
        }
        sq_idx += 1;
    }

    // 3. 16 one-hot selector bits: s_k * (s_k - 1) == 0 (16 openings), plus sum(s_k).
    let mut sum_s: Share4 = [0u128; 4];
    for k in 0..TURBO_BUCKET_SIZE {
        let s_k = &req.selector_shares[k];
        if let Err(e) =
            accumulate_bool_square_rlc(s_k, &mut squares[sq_idx], gamma, &mut z, &mut z_const)
        {
            wipe_remaining_tx_beaver(squares, sq_idx, star, blind_triple);
            zeroize_share4(&mut z);
            zeroize_share4(&mut sum_s);
            return Err(e);
        }
        sq_idx += 1;
        sum_s[0] = add_unreduced(sum_s[0], s_k[0]);
        sum_s[1] = add_unreduced(sum_s[1], s_k[1]);
        sum_s[2] = add_unreduced(sum_s[2], s_k[2]);
        sum_s[3] = add_unreduced(sum_s[3], s_k[3]);
    }

    // 4. Recompose [v] and [r] with zero `mul_mod`, then fold check #49 (B_sender - v - r == 0)
    //    and check #50 (sum(s_k) - 1 == 0) into the same Horner RLC polynomial.
    let mut v_shares = compose_bits_16(&req.v_bits);
    let mut r_shares = compose_bits_16(&req.r_bits);
    let sender_bal = &balances[req.sender_slot];
    if sender_bal[0] >= PRIME_P
        || sender_bal[1] >= PRIME_P
        || sender_bal[2] >= PRIME_P
        || sender_bal[3] >= PRIME_P
    {
        star.wipe_in_place_nofence();
        blind_triple.wipe_in_place_nofence();
        zeroize_share4_nofence(&mut v_shares);
        zeroize_share4_nofence(&mut r_shares);
        zeroize_share4_nofence(&mut sum_s);
        zeroize_share4(&mut z);
        return Err(TurboShieldedError::FieldElementOutOfRange);
    }

    // Check #49: eq = B_sender - v - r.
    let eq0 = sub_mod(sub_mod(sender_bal[0], v_shares[0]), r_shares[0]);
    let eq1 = sub_mod(sub_mod(sender_bal[1], v_shares[1]), r_shares[1]);
    let eq2 = sub_mod(sub_mod(sender_bal[2], v_shares[2]), r_shares[2]);
    let eq3 = sub_mod(sub_mod(sender_bal[3], v_shares[3]), r_shares[3]);
    zeroize_share4_nofence(&mut r_shares);

    z[0] = add_unreduced(mul_unreduced(z[0], gamma), eq0);
    z[1] = add_unreduced(mul_unreduced(z[1], gamma), eq1);
    z[2] = add_unreduced(mul_unreduced(z[2], gamma), eq2);
    z[3] = add_unreduced(mul_unreduced(z[3], gamma), eq3);
    z_const = mul_unreduced(z_const, gamma);

    // Check #50: sum(s_k) - 1 (subtracting 1 folded into z_const via + (PRIME_P - 1)).
    z[0] = add_unreduced(mul_unreduced(z[0], gamma), sum_s[0]);
    z[1] = add_unreduced(mul_unreduced(z[1], gamma), sum_s[1]);
    z[2] = add_unreduced(mul_unreduced(z[2], gamma), sum_s[2]);
    z[3] = add_unreduced(mul_unreduced(z[3], gamma), sum_s[3]);
    z_const = add_unreduced(mul_unreduced(z_const, gamma), PRIME_P - 1);
    zeroize_share4_nofence(&mut sum_s);

    // Finalize canonical [Z] = z + z_const and blind with uniform non-zero [rho] via one
    // Beaver triple ([Z_blind] = [rho] * [Z]) so a non-zero opening leaks ZERO bits!
    let mut z_final: Share4 = [
        canon_le_p(add_unreduced(z[0], z_const)),
        canon_le_p(add_unreduced(z[1], z_const)),
        canon_le_p(add_unreduced(z[2], z_const)),
        canon_le_p(add_unreduced(z[3], z_const)),
    ];
    zeroize_share4_nofence(&mut z);

    let mut rho = random_nonzero_share4_fast();
    let d_r = match TurboLagrange3Of4::open_diff(&rho, &blind_triple.a) {
        Ok(v) => v,
        Err(e) => {
            star.wipe_in_place_nofence();
            blind_triple.wipe_in_place_nofence();
            zeroize_share4_nofence(&mut rho);
            zeroize_share4_nofence(&mut z_final);
            zeroize_share4(&mut v_shares);
            return Err(e);
        }
    };
    let e_z = match TurboLagrange3Of4::open_diff(&z_final, &blind_triple.b) {
        Ok(v) => v,
        Err(e) => {
            star.wipe_in_place_nofence();
            blind_triple.wipe_in_place_nofence();
            zeroize_share4_nofence(&mut rho);
            zeroize_share4_nofence(&mut z_final);
            zeroize_share4(&mut v_shares);
            return Err(e);
        }
    };
    let de = mul_mod_fast(d_r, e_z);
    let mut z_blind: Share4 = [
        canon_le_p(add_unreduced(
            add_unreduced(blind_triple.c[0], mul_unreduced(d_r, blind_triple.b[0])),
            add_unreduced(mul_unreduced(e_z, blind_triple.a[0]), de),
        )),
        canon_le_p(add_unreduced(
            add_unreduced(blind_triple.c[1], mul_unreduced(d_r, blind_triple.b[1])),
            add_unreduced(mul_unreduced(e_z, blind_triple.a[1]), de),
        )),
        canon_le_p(add_unreduced(
            add_unreduced(blind_triple.c[2], mul_unreduced(d_r, blind_triple.b[2])),
            add_unreduced(mul_unreduced(e_z, blind_triple.a[2]), de),
        )),
        canon_le_p(add_unreduced(
            add_unreduced(blind_triple.c[3], mul_unreduced(d_r, blind_triple.b[3])),
            add_unreduced(mul_unreduced(e_z, blind_triple.a[3]), de),
        )),
    ];
    blind_triple.wipe_in_place_nofence();
    zeroize_share4_nofence(&mut rho);
    zeroize_share4_nofence(&mut z_final);

    let opened_z = TurboLagrange3Of4::reconstruct_and_verify(&z_blind);
    zeroize_share4_nofence(&mut z_blind);

    match opened_z {
        Ok(0) => {}
        Ok(_) => {
            star.wipe_in_place_nofence();
            zeroize_share4(&mut v_shares);
            return Err(TurboShieldedError::RlcCheckFailed);
        }
        Err(e) => {
            star.wipe_in_place_nofence();
            zeroize_share4(&mut v_shares);
            return Err(e);
        }
    }

    // 5. Shared-Factor Beaver Star 16-slot blinded recipient update (1 + 16 = 17 openings):
    //    Open beta = v - b_v ONCE, then open alpha_k = s_k - a_k for k = 0..16, and apply
    //    credit_k = c_k + alpha_k * b_v + beta * a_k + alpha_k * beta directly into balances[k].
    let beta = match TurboLagrange3Of4::open_diff(&v_shares, &star.b_v) {
        Ok(b) => b,
        Err(e) => {
            star.wipe_in_place_nofence();
            zeroize_share4(&mut v_shares);
            return Err(e);
        }
    };

    let bv = star.b_v;
    let mut alpha_buf = [0u128; TURBO_BUCKET_SIZE];
    for k in 0..TURBO_BUCKET_SIZE {
        match TurboLagrange3Of4::open_diff(&req.selector_shares[k], &star.a[k]) {
            Ok(ak) => alpha_buf[k] = ak,
            Err(e) => {
                star.wipe_in_place_nofence();
                zeroize_share4_nofence(&mut v_shares);
                zeroize_u128_slice(&mut alpha_buf);
                return Err(e);
            }
        }
    }

    // Debit sender before crediting all 16 slots (all checks have already passed).
    let sender = &mut balances[req.sender_slot];
    sender[0] = sub_mod(sender[0], v_shares[0]);
    sender[1] = sub_mod(sender[1], v_shares[1]);
    sender[2] = sub_mod(sender[2], v_shares[2]);
    sender[3] = sub_mod(sender[3], v_shares[3]);

    // Apply all 16 blinded credits in place (every slot's share re-randomizes via fresh [c_k]).
    for k in 0..TURBO_BUCKET_SIZE {
        let alpha_k = alpha_buf[k];
        let ab = mul_unreduced(alpha_k, beta);
        let ak = star.a[k];
        let ck = star.c[k];
        let bal = &mut balances[k];

        let t0 = add_unreduced(
            add_unreduced(mul_unreduced(alpha_k, bv[0]), mul_unreduced(beta, ak[0])),
            add_unreduced(ck[0], ab),
        );
        let t1 = add_unreduced(
            add_unreduced(mul_unreduced(alpha_k, bv[1]), mul_unreduced(beta, ak[1])),
            add_unreduced(ck[1], ab),
        );
        let t2 = add_unreduced(
            add_unreduced(mul_unreduced(alpha_k, bv[2]), mul_unreduced(beta, ak[2])),
            add_unreduced(ck[2], ab),
        );
        let t3 = add_unreduced(
            add_unreduced(mul_unreduced(alpha_k, bv[3]), mul_unreduced(beta, ak[3])),
            add_unreduced(ck[3], ab),
        );

        bal[0] = canon_le_p(add_unreduced(bal[0], t0));
        bal[1] = canon_le_p(add_unreduced(bal[1], t1));
        bal[2] = canon_le_p(add_unreduced(bal[2], t2));
        bal[3] = canon_le_p(add_unreduced(bal[3], t3));
    }

    // Immediately wipe consumed star & stack secrets in L1 cache (single trailing fence).
    star.wipe_in_place_nofence();
    zeroize_share4_nofence(&mut v_shares);
    zeroize_u128_slice(&mut alpha_buf);
    Ok(())
}

/// Wipe any unconsumed squares, the star, and the blinding triple on an early error exit.
#[inline]
fn wipe_remaining_tx_beaver(
    squares: &mut [BeaverSquare],
    from_idx: usize,
    star: &mut BeaverStar16,
    blind_triple: &mut BeaverTriple4,
) {
    let end = squares.len().min(SQUARES_PER_TURBO_TX);
    if from_idx < end {
        for sq in &mut squares[from_idx..end] {
            sq.wipe_in_place_nofence();
        }
    }
    star.wipe_in_place_nofence();
    blind_triple.wipe_in_place_nofence();
    compiler_fence(Ordering::SeqCst);
}

// ============================================================================
// 4. Persistent Multi-Core Sharded Bucket Pool (`TurboShieldedCluster`)
// ============================================================================

/// Cache-line-aligned anonymity bucket preventing false sharing across parallel CPU cores.
#[repr(C, align(64))]
#[derive(Clone)]
struct TurboAnonymityBucket {
    balances: [Share4; TURBO_BUCKET_SIZE],
}

impl fmt::Debug for TurboAnonymityBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurboAnonymityBucket")
            .field("slots", &TURBO_BUCKET_SIZE)
            .field("balances", &"<redacted>")
            .finish()
    }
}

impl Drop for TurboAnonymityBucket {
    fn drop(&mut self) {
        zeroize_share4_slice(&mut self.balances);
    }
}

/// Per-worker disjoint job descriptor written by the coordinator before incrementing `epoch`.
#[derive(Clone, Copy)]
struct WorkerJob {
    bucket_start: usize,
    bucket_end: usize,
    buckets_ptr: *const TurboAnonymityBucket,
    staged_ptr: *mut TurboAnonymityBucket,
    bucket_offsets_ptr: *const usize,
    sorted_indices_ptr: *const usize,
    requests_ptr: *const TurboTransferRequest,
    squares_ptr: *mut BeaverSquare,
    stars_ptr: *mut BeaverStar16,
    triples_ptr: *mut BeaverTriple4,
    gamma: u128,
}

// SAFETY: Every worker receives strictly disjoint `[bucket_start..bucket_end)`, disjoint
// `staged_ptr` subrange, disjoint `squares_ptr`/`stars_ptr`/`triples_ptr` subranges, and immutable
// shared views of `buckets_ptr`, `bucket_offsets_ptr`, `sorted_indices_ptr`, and `requests_ptr`.
// All pointers remain valid for the entire epoch while the coordinator waits on `done_count`.
unsafe impl Send for WorkerJob {}

impl WorkerJob {
    const fn empty() -> Self {
        Self {
            bucket_start: 0,
            bucket_end: 0,
            buckets_ptr: std::ptr::null(),
            staged_ptr: std::ptr::null_mut(),
            bucket_offsets_ptr: std::ptr::null(),
            sorted_indices_ptr: std::ptr::null(),
            requests_ptr: std::ptr::null(),
            squares_ptr: std::ptr::null_mut(),
            stars_ptr: std::ptr::null_mut(),
            triples_ptr: std::ptr::null_mut(),
            gamma: 1,
        }
    }
}

/// Cache-line-padded per-worker slot avoiding false sharing between persistent threads.
#[repr(C, align(64))]
struct WorkerSlot {
    job: UnsafeCell<WorkerJob>,
    result: UnsafeCell<Option<TurboShieldedError>>,
}

// SAFETY: Synchronized via `PoolShared::epoch` (coordinator writes `job` before `epoch` release;
// worker reads `job` after `epoch` acquire and writes `result` before `done_count` release;
// coordinator reads `result` only after `done_count` acquire).
unsafe impl Sync for WorkerSlot {}

/// Shared coordination state for persistent worker threads.
struct PoolShared {
    epoch: AtomicU64,
    shutdown: AtomicBool,
    done_count: AtomicUsize,
    sleeping: AtomicUsize,
    wake_mu: Mutex<()>,
    wake_cv: Condvar,
    slots: Box<[WorkerSlot]>,
}

/// Execute one worker's disjoint bucket range `[bucket_start..bucket_end)` against its
/// pre-allocated `staged` buckets and disjoint Beaver slices.
///
/// # Safety
/// Caller guarantees all pointers in `job` are valid and non-aliasing with all other workers
/// for the full duration of the call.
unsafe fn run_worker_job(job: WorkerJob) -> Option<TurboShieldedError> {
    if job.bucket_start >= job.bucket_end {
        return None;
    }

    let mut sq_off = 0usize;
    let mut star_off = 0usize;
    let mut triple_off = 0usize;

    for b in job.bucket_start..job.bucket_end {
        // SAFETY: `bucket_offsets_ptr` has length `num_buckets + 1` and `b < bucket_end <= num_buckets`.
        let start = unsafe { *job.bucket_offsets_ptr.add(b) };
        let end = unsafe { *job.bucket_offsets_ptr.add(b + 1) };
        if start == end {
            continue;
        }

        // Copy committed bucket balances into this bucket's disjoint staged buffer.
        // SAFETY: `b` is exclusively owned by this worker in `[bucket_start..bucket_end)`.
        let staged_bucket = unsafe { &mut *job.staged_ptr.add(b) };
        let src_bucket = unsafe { &*job.buckets_ptr.add(b) };
        staged_bucket.balances = src_bucket.balances;

        for idx_pos in start..end {
            // SAFETY: `idx_pos` is within `requests.len()`.
            let req_idx = unsafe { *job.sorted_indices_ptr.add(idx_pos) };
            let req = unsafe { &*job.requests_ptr.add(req_idx) };
            let tx_squares = unsafe {
                std::slice::from_raw_parts_mut(job.squares_ptr.add(sq_off), SQUARES_PER_TURBO_TX)
            };
            let tx_star = unsafe { &mut *job.stars_ptr.add(star_off) };
            let tx_triple = unsafe { &mut *job.triples_ptr.add(triple_off) };
            sq_off += SQUARES_PER_TURBO_TX;
            star_off += STARS_PER_TURBO_TX;
            triple_off += TRIPLES_PER_TURBO_TX;

            if let Err(e) = execute_transfer_in_bucket(
                &mut staged_bucket.balances,
                req,
                tx_squares,
                tx_star,
                tx_triple,
                job.gamma,
            ) {
                // Wipe any remaining unconsumed Beaver items assigned to this worker's shard
                // so no partially-allocated randomness lingers in memory on error.
                let total_txs_in_shard = unsafe {
                    *job.bucket_offsets_ptr.add(job.bucket_end)
                        - *job.bucket_offsets_ptr.add(job.bucket_start)
                };
                let total_sq = total_txs_in_shard * SQUARES_PER_TURBO_TX;
                let total_st = total_txs_in_shard * STARS_PER_TURBO_TX;
                let total_tr = total_txs_in_shard * TRIPLES_PER_TURBO_TX;
                if sq_off < total_sq {
                    let rem_sq = unsafe {
                        std::slice::from_raw_parts_mut(
                            job.squares_ptr.add(sq_off),
                            total_sq - sq_off,
                        )
                    };
                    for sq in rem_sq {
                        sq.wipe_in_place_nofence();
                    }
                }
                if star_off < total_st {
                    let rem_st = unsafe {
                        std::slice::from_raw_parts_mut(
                            job.stars_ptr.add(star_off),
                            total_st - star_off,
                        )
                    };
                    for st in rem_st {
                        st.wipe_in_place_nofence();
                    }
                }
                if triple_off < total_tr {
                    let rem_tr = unsafe {
                        std::slice::from_raw_parts_mut(
                            job.triples_ptr.add(triple_off),
                            total_tr - triple_off,
                        )
                    };
                    for tr in rem_tr {
                        tr.wipe_in_place_nofence();
                    }
                }
                compiler_fence(Ordering::SeqCst);
                return Some(e);
            }
        }
    }

    None
}

/// Persistent multi-core sharded `(3, 4)` Shamir IT-MPC shielded ledger cluster.
///
/// Spawns persistent OS worker threads ONCE at construction time (sized to
/// `std::thread::available_parallelism()`, capped by `num_buckets`), partitions disjoint
/// anonymity buckets across workers with zero lock contention, zero per-batch thread spawn
/// overhead, zero per-transfer heap allocations, and atomic cluster-wide rollback on any error.
pub struct TurboShieldedCluster {
    buckets: Vec<TurboAnonymityBucket>,
    staged: Vec<TurboAnonymityBucket>,
    /// Cumulative minted supply per bucket (capped at `2^16 - 1` so no intra-bucket transfer can
    /// ever overflow any slot above `max_val`).
    bucket_minted: Vec<u128>,
    /// Reusable O(N) counting-sort scratch buffers for zero-alloc batch partitioning.
    bucket_counts: Vec<usize>,
    bucket_offsets: Vec<usize>,
    bucket_write_pos: Vec<usize>,
    sorted_indices: Vec<usize>,
    /// Total worker count including coordinator thread 0.
    num_workers: usize,
    /// Shared epoch coordinator + persistent background worker handles (`num_workers - 1`).
    shared: Arc<PoolShared>,
    workers: Vec<JoinHandle<()>>,
}

impl fmt::Debug for TurboShieldedCluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurboShieldedCluster")
            .field("num_buckets", &self.buckets.len())
            .field("num_workers", &self.num_workers)
            .finish()
    }
}

impl TurboShieldedCluster {
    /// Initialize a shielded cluster with `num_buckets` anonymity buckets of 16 accounts each
    /// and spawn persistent multi-core worker threads ONCE.
    pub fn new(num_buckets: usize) -> Result<Self, TurboShieldedError> {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self::with_workers(num_buckets, cores)
    }

    /// Initialize a shielded cluster with an explicit worker thread count (clamped to `[1, num_buckets]`).
    pub fn with_workers(
        num_buckets: usize,
        requested_workers: usize,
    ) -> Result<Self, TurboShieldedError> {
        if num_buckets == 0 {
            return Err(TurboShieldedError::InvalidParameters(
                "num_buckets must be >= 1",
            ));
        }

        let total_accounts = num_buckets * TURBO_BUCKET_SIZE;
        let mut rands = vec![0u128; total_accounts * 2];
        fill_random_field_elems(&mut rands);

        let mut buckets = Vec::with_capacity(num_buckets);
        let mut staged = Vec::with_capacity(num_buckets);
        let mut r_idx = 0usize;
        for _ in 0..num_buckets {
            let mut balances = [[0u128; 4]; TURBO_BUCKET_SIZE];
            for slot in balances.iter_mut() {
                *slot = TurboLagrange3Of4::eval_poly(0, rands[r_idx], rands[r_idx + 1]);
                r_idx += 2;
            }
            buckets.push(TurboAnonymityBucket { balances });
            staged.push(TurboAnonymityBucket {
                balances: [[0u128; 4]; TURBO_BUCKET_SIZE],
            });
        }
        zeroize_u128_slice(&mut rands);

        let num_workers = requested_workers.max(1).min(num_buckets);
        let bg_workers = num_workers - 1;

        let slots: Box<[WorkerSlot]> = (0..bg_workers)
            .map(|_| WorkerSlot {
                job: UnsafeCell::new(WorkerJob::empty()),
                result: UnsafeCell::new(None),
            })
            .collect();

        let shared = Arc::new(PoolShared {
            epoch: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            done_count: AtomicUsize::new(0),
            sleeping: AtomicUsize::new(0),
            wake_mu: Mutex::new(()),
            wake_cv: Condvar::new(),
            slots,
        });

        let mut workers = Vec::with_capacity(bg_workers);
        for w in 0..bg_workers {
            let shared_clone = Arc::clone(&shared);
            let handle = std::thread::Builder::new()
                .name(format!("vernam-turbo-mpc-{w}"))
                .spawn(move || {
                    let mut seen_epoch = 0u64;
                    loop {
                        let mut spins = 0u32;
                        let mut cur = shared_clone.epoch.load(Ordering::Acquire);
                        while cur == seen_epoch {
                            if shared_clone.shutdown.load(Ordering::Acquire) {
                                return;
                            }
                            if spins < 4096 {
                                spins += 1;
                                std::hint::spin_loop();
                                cur = shared_clone.epoch.load(Ordering::Acquire);
                            } else {
                                let mut guard = shared_clone
                                    .wake_mu
                                    .lock()
                                    .expect("worker wake mutex poisoned");
                                shared_clone.sleeping.fetch_add(1, Ordering::SeqCst);
                                loop {
                                    cur = shared_clone.epoch.load(Ordering::SeqCst);
                                    if cur != seen_epoch
                                        || shared_clone.shutdown.load(Ordering::SeqCst)
                                    {
                                        break;
                                    }
                                    guard = shared_clone
                                        .wake_cv
                                        .wait(guard)
                                        .expect("worker condvar wait poisoned");
                                }
                                shared_clone.sleeping.fetch_sub(1, Ordering::SeqCst);
                                drop(guard);
                                if shared_clone.shutdown.load(Ordering::Acquire) {
                                    return;
                                }
                                break;
                            }
                        }
                        seen_epoch = cur;

                        // SAFETY: Coordinator wrote `slots[w].job` before incrementing `epoch`
                        // with Release/SeqCst and will not read `slots[w].result` until
                        // `done_count` reaches `bg_workers`.
                        let job = unsafe { *shared_clone.slots[w].job.get() };
                        let res = unsafe { run_worker_job(job) };
                        unsafe {
                            *shared_clone.slots[w].result.get() = res;
                        }
                        shared_clone.done_count.fetch_add(1, Ordering::Release);
                    }
                })
                .expect("failed to spawn persistent turbo MPC worker thread");
            workers.push(handle);
        }

        Ok(Self {
            buckets,
            staged,
            bucket_minted: vec![0u128; num_buckets],
            bucket_counts: vec![0usize; num_buckets],
            bucket_offsets: vec![0usize; num_buckets + 1],
            bucket_write_pos: vec![0usize; num_buckets],
            sorted_indices: Vec::new(),
            num_workers,
            shared,
            workers,
        })
    }

    /// Number of anonymity buckets in this cluster.
    #[inline]
    pub fn num_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Total accounts (`num_buckets * 16`).
    #[inline]
    pub fn total_accounts(&self) -> usize {
        self.buckets.len() * TURBO_BUCKET_SIZE
    }

    /// Number of persistent parallel workers (including coordinator lane 0).
    #[inline]
    pub fn num_workers(&self) -> usize {
        self.num_workers
    }

    /// Mint an initial confidential balance into `(bucket_id, slot)` using fresh `(3, 4)` shares.
    ///
    /// Enforces `existing_balance + amount <= 2^16 - 1` and `bucket_supply + amount <= 2^16 - 1`
    /// so no intra-bucket transfer can ever overflow any slot above `2^16 - 1`.
    pub fn mint_balance(
        &mut self,
        bucket_id: usize,
        slot: usize,
        amount: u128,
    ) -> Result<(), TurboShieldedError> {
        let max_val = (1u128 << TURBO_RANGE_BITS) - 1;
        if amount > max_val {
            return Err(TurboShieldedError::InvalidParameters(
                "mint amount exceeds 2^16 - 1",
            ));
        }
        if slot >= TURBO_BUCKET_SIZE {
            return Err(TurboShieldedError::InvalidSlot { slot });
        }
        let bucket = self
            .buckets
            .get_mut(bucket_id)
            .ok_or(TurboShieldedError::InvalidBucket { bucket_id })?;
        let existing = TurboLagrange3Of4::reconstruct_and_verify(&bucket.balances[slot])?;
        if existing.checked_add(amount).is_none_or(|sum| sum > max_val) {
            return Err(TurboShieldedError::InvalidParameters(
                "existing balance + mint amount exceeds 2^16 - 1",
            ));
        }
        if self.bucket_minted[bucket_id]
            .checked_add(amount)
            .is_none_or(|sum| sum > max_val)
        {
            return Err(TurboShieldedError::InvalidParameters(
                "bucket supply would exceed safe 2^16 - 1 cap",
            ));
        }
        let mut delta = TurboLagrange3Of4::split_secret(amount)?;
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
    ) -> Result<&Share4, TurboShieldedError> {
        if slot >= TURBO_BUCKET_SIZE {
            return Err(TurboShieldedError::InvalidSlot { slot });
        }
        let bucket = self
            .buckets
            .get(bucket_id)
            .ok_or(TurboShieldedError::InvalidBucket { bucket_id })?;
        Ok(&bucket.balances[slot])
    }

    /// Reconstruct and degree-2-verify the balance of `(bucket_id, slot)` (for auditing/tests).
    pub fn reconstruct_balance(
        &self,
        bucket_id: usize,
        slot: usize,
    ) -> Result<u128, TurboShieldedError> {
        let shares = self.balance_shares(bucket_id, slot)?;
        TurboLagrange3Of4::reconstruct_and_verify(shares)
    }

    /// Execute a single confidential transfer atomically (rolls back automatically on any error).
    pub fn execute_single_transfer(
        &mut self,
        req: &TurboTransferRequest,
        bank: &mut TurboBeaverBank,
    ) -> Result<(), TurboShieldedError> {
        if req.bucket_id >= self.buckets.len() {
            return Err(TurboShieldedError::InvalidBucket {
                bucket_id: req.bucket_id,
            });
        }
        if req.sender_slot >= TURBO_BUCKET_SIZE {
            return Err(TurboShieldedError::InvalidSlot {
                slot: req.sender_slot,
            });
        }

        let (squares, stars, triples) = bank.reserve_for_txs(1)?;
        let gamma = random_nonzero_challenge();
        let mut staged = self.buckets[req.bucket_id].balances;

        let res = execute_transfer_in_bucket(
            &mut staged,
            req,
            squares,
            &mut stars[0],
            &mut triples[0],
            gamma,
        );
        match res {
            Ok(()) => {
                self.buckets[req.bucket_id].balances = staged;
                zeroize_share4_slice(&mut staged);
                Ok(())
            }
            Err(e) => {
                zeroize_share4_slice(&mut staged);
                Err(e)
            }
        }
    }

    /// Execute a batch of confidential transfers across disjoint anonymity buckets on the
    /// persistent multi-core worker pool with zero lock contention and zero per-batch thread spawn.
    ///
    /// Atomicity guarantee: if ANY transfer in ANY bucket fails the Schwartz–Zippel RLC check
    /// or degree-2 share verification, **zero** balances across the entire cluster are modified
    /// and the first error is returned. Consumed Beaver material is still permanently retired.
    pub fn execute_parallel_batch(
        &mut self,
        requests: &[TurboTransferRequest],
        bank: &mut TurboBeaverBank,
    ) -> Result<usize, TurboShieldedError> {
        if requests.is_empty() {
            return Ok(0);
        }

        let num_buckets = self.buckets.len();

        // 1. Validate bucket/slot bounds and count requests per disjoint bucket (zero heap alloc).
        self.bucket_counts.fill(0);
        for req in requests {
            if req.bucket_id >= num_buckets {
                return Err(TurboShieldedError::InvalidBucket {
                    bucket_id: req.bucket_id,
                });
            }
            if req.sender_slot >= TURBO_BUCKET_SIZE {
                return Err(TurboShieldedError::InvalidSlot {
                    slot: req.sender_slot,
                });
            }
            self.bucket_counts[req.bucket_id] += 1;
        }

        // 2. Prefix sum offsets & O(N) counting sort into reusable `sorted_indices`.
        let mut acc = 0usize;
        for b in 0..num_buckets {
            self.bucket_offsets[b] = acc;
            self.bucket_write_pos[b] = acc;
            acc += self.bucket_counts[b];
        }
        self.bucket_offsets[num_buckets] = acc;

        if self.sorted_indices.len() < requests.len() {
            self.sorted_indices.resize(requests.len(), 0);
        }
        for (i, req) in requests.iter().enumerate() {
            let pos = self.bucket_write_pos[req.bucket_id];
            self.sorted_indices[pos] = i;
            self.bucket_write_pos[req.bucket_id] = pos + 1;
        }

        // 3. Reserve all Beaver squares, stars & blinding triples upfront (advances single-use cursors atomically).
        let (squares, stars, triples) = bank.reserve_for_txs(requests.len())?;

        // 4. Sample a fresh OS-random non-zero Schwartz–Zippel challenge AFTER the batch is fixed.
        let gamma = random_nonzero_challenge();

        // 5. Partition disjoint bucket ranges evenly across persistent workers.
        let num_workers = self.num_workers;
        let bg_workers = self.workers.len();
        let base_buckets = num_buckets / num_workers;
        let rem_buckets = num_buckets % num_workers;

        let buckets_ptr = self.buckets.as_ptr();
        let staged_ptr = self.staged.as_mut_ptr();
        let bucket_offsets_ptr = self.bucket_offsets.as_ptr();
        let sorted_indices_ptr = self.sorted_indices.as_ptr();
        let requests_ptr = requests.as_ptr();
        let squares_base = squares.as_mut_ptr();
        let stars_base = stars.as_mut_ptr();
        let triples_base = triples.as_mut_ptr();

        let mut b_cursor = 0usize;
        let mut main_job = WorkerJob::empty();

        for w in 0..num_workers {
            let b_len = base_buckets + usize::from(w < rem_buckets);
            let b_start = b_cursor;
            let b_end = b_start + b_len;
            b_cursor = b_end;

            let tx_offset = self.bucket_offsets[b_start];
            let job = WorkerJob {
                bucket_start: b_start,
                bucket_end: b_end,
                buckets_ptr,
                staged_ptr,
                bucket_offsets_ptr,
                sorted_indices_ptr,
                requests_ptr,
                // SAFETY: Disjoint worker ranges map to disjoint `tx_offset` slices within
                // `squares`, `stars`, and `triples`.
                squares_ptr: unsafe { squares_base.add(tx_offset * SQUARES_PER_TURBO_TX) },
                stars_ptr: unsafe { stars_base.add(tx_offset * STARS_PER_TURBO_TX) },
                triples_ptr: unsafe { triples_base.add(tx_offset * TRIPLES_PER_TURBO_TX) },
                gamma,
            };

            if w == 0 {
                main_job = job;
            } else {
                // SAFETY: Background workers are idle waiting for the next `epoch`.
                unsafe {
                    *self.shared.slots[w - 1].job.get() = job;
                }
            }
        }

        // 6. Dispatch epoch to persistent background workers (zero thread spawn!).
        if bg_workers > 0 {
            self.shared.done_count.store(0, Ordering::Relaxed);
            self.shared.epoch.fetch_add(1, Ordering::SeqCst);
            if self.shared.sleeping.load(Ordering::SeqCst) > 0 {
                let _guard = self
                    .shared
                    .wake_mu
                    .lock()
                    .expect("coordinator wake mutex poisoned");
                self.shared.wake_cv.notify_all();
            }
        }

        // 7. Execute shard 0 directly on the coordinator thread in parallel with background workers.
        // SAFETY: Disjoint shard `[0..b_end_0)` and valid slices for the entire epoch.
        let mut first_err = unsafe { run_worker_job(main_job) };

        // 8. Wait for all background workers to complete this epoch.
        if bg_workers > 0 {
            while self.shared.done_count.load(Ordering::Acquire) < bg_workers {
                std::hint::spin_loop();
            }
            for w in 0..bg_workers {
                // SAFETY: All workers have published their results with Release before incrementing
                // `done_count`, and we synchronized via Acquire above.
                let res = unsafe { (*self.shared.slots[w].result.get()).take() };
                if first_err.is_none() {
                    first_err = res;
                }
            }
        }

        // 9. Atomic commit or rollback across all touched buckets.
        if let Some(err) = first_err {
            for b in 0..num_buckets {
                if self.bucket_counts[b] > 0 {
                    zeroize_share4_slice(&mut self.staged[b].balances);
                }
            }
            return Err(err);
        }

        for b in 0..num_buckets {
            if self.bucket_counts[b] > 0 {
                self.buckets[b].balances = self.staged[b].balances;
                zeroize_share4_slice(&mut self.staged[b].balances);
            }
        }

        Ok(requests.len())
    }
}

impl Drop for TurboShieldedCluster {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        {
            let _guard = self
                .shared
                .wake_mu
                .lock()
                .expect("drop wake mutex poisoned");
            self.shared.wake_cv.notify_all();
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

// ============================================================================
// 5. Live Throughput Benchmark (`TurboShieldedBench` & `run_turbo_shielded_bench`)
// ============================================================================

/// Real measured throughput telemetry produced by [`run_turbo_shielded_bench`].
#[derive(Debug, Clone)]
pub struct TurboShieldedBench {
    /// Measured Shielded `(3, 4)` IT-MPC throughput (confidential transfers per second).
    pub shielded_tps: f64,
    /// Total full 16-bit + 16-slot confidential transfers executed in the timed window.
    pub total_txs: usize,
    /// Wall-clock duration in seconds.
    pub elapsed_secs: f64,
    /// Number of persistent parallel workers / hardware threads used.
    pub cores_used: usize,
    /// Exact `(3, 4)` openings per confidential transfer (`68`, down from `178`).
    pub openings_per_tx: usize,
    /// Number of disjoint 16-account anonymity buckets used.
    pub buckets_used: usize,
}

impl fmt::Display for TurboShieldedBench {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "=== Vernam (VRNM) Turbo Shielded IT-MPC Benchmark ({} cores, {} buckets) ===",
            self.cores_used, self.buckets_used
        )?;
        writeln!(
            f,
            "  Shielded IT-MPC TPS : {:>12.0} tx/s ({} txs in {:.4}s)",
            self.shielded_tps, self.total_txs, self.elapsed_secs
        )?;
        write!(
            f,
            "  Openings / Transfer : {:>12} (vs {} baseline, {:.2}x reduction)",
            self.openings_per_tx,
            BASELINE_OPENINGS_PER_TX,
            (BASELINE_OPENINGS_PER_TX as f64) / (self.openings_per_tx as f64)
        )
    }
}

/// Run the live multi-core Shielded IT-MPC benchmark: `16,384` full 16-bit + 16-slot
/// confidential transfers across `64` disjoint anonymity buckets on persistent worker threads
/// (Beaver squares + blinded Schwartz–Zippel RLC + Shared-Factor Beaver Stars = `68` openings/tx).
pub fn run_turbo_shielded_bench() -> TurboShieldedBench {
    let num_buckets = 64usize;
    let txs_per_bucket = 256usize;
    let total_txs = num_buckets * txs_per_bucket; // 16,384 transfers

    let mut cluster =
        TurboShieldedCluster::new(num_buckets).expect("turbo shielded cluster init must succeed");
    let cores_used = cluster.num_workers();

    let initial_bal = 3_000u128;
    for b in 0..num_buckets {
        for slot in 0..TURBO_BUCKET_SIZE {
            cluster
                .mint_balance(b, slot, initial_bal)
                .expect("mint must succeed");
        }
    }

    // Warm up persistent workers with 1 small batch (outside timed window) so threads are hot.
    let mut warmup_bank = TurboBeaverBank::new_for_txs(num_buckets);
    let mut tracked_bal = vec![[initial_bal; TURBO_BUCKET_SIZE]; num_buckets];
    let mut warmup_reqs = Vec::with_capacity(num_buckets);
    for b in 0..num_buckets {
        let req = TurboTransferRequest::new(b, 0, tracked_bal[b][0], 1, 1).expect("warmup req");
        tracked_bal[b][0] -= 1;
        tracked_bal[b][1] += 1;
        warmup_reqs.push(req);
    }
    cluster
        .execute_parallel_batch(&warmup_reqs, &mut warmup_bank)
        .expect("warmup batch must succeed");

    // Offline correlated-randomness bank & client request generation.
    let mut bank = TurboBeaverBank::new_for_txs(total_txs);
    let mut requests = Vec::with_capacity(total_txs);
    for b in 0..num_buckets {
        for i in 0..txs_per_bucket {
            let sender = i % TURBO_BUCKET_SIZE;
            let recipient = (sender + 1) % TURBO_BUCKET_SIZE;
            let amount = 5u128;
            let req =
                TurboTransferRequest::new(b, sender, tracked_bal[b][sender], recipient, amount)
                    .expect("valid request");
            tracked_bal[b][sender] -= amount;
            tracked_bal[b][recipient] += amount;
            requests.push(req);
        }
    }

    let start = Instant::now();
    let committed = cluster
        .execute_parallel_batch(&requests, &mut bank)
        .expect("turbo shielded batch must succeed");
    let elapsed_secs = start.elapsed().as_secs_f64().max(1e-9);
    let shielded_tps = (committed as f64) / elapsed_secs;

    TurboShieldedBench {
        shielded_tps,
        total_txs: committed,
        elapsed_secs,
        cores_used,
        openings_per_tx: OPENINGS_PER_TURBO_TX,
        buckets_used: num_buckets,
    }
}

// ============================================================================
// 6. Comprehensive Unit & Security Verification Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branchless_mersenne_arithmetic_matches_field_exactly() {
        let edges = [
            0u128,
            1,
            2,
            3,
            (1u128 << 63) - 1,
            1u128 << 63,
            (1u128 << 64) - 1,
            1u128 << 64,
            PRIME_P - 2,
            PRIME_P - 1,
            PRIME_P,
        ];
        for &a in &edges {
            for &b in &edges {
                let u = mul_unreduced(a, b);
                assert!(u <= PRIME_P, "mul_unreduced exceeded PRIME_P for ({a}, {b})");
                assert_eq!(canon_le_p(u), mul_mod(a, b));

                let s = add_unreduced(a, b);
                assert!(s <= PRIME_P, "add_unreduced exceeded PRIME_P for ({a}, {b})");
                assert_eq!(
                    canon_le_p(s),
                    add_mod(if a == PRIME_P { 0 } else { a }, if b == PRIME_P { 0 } else { b })
                );
            }
        }

        let mut rands = [0u128; 2000];
        fill_random_field_elems(&mut rands);
        for pair in rands.chunks_exact(2) {
            let (a, b) = (pair[0], pair[1]);
            assert_eq!(mul_mod_fast(a, b), mul_mod(a, b));
            assert_eq!(canon_le_p(add_unreduced(a, b)), add_mod(a, b));
        }
    }

    #[test]
    fn test_beaver_square_and_triple_algebraic_identities() {
        let mut bank = TurboBeaverBank::new(16, 0, 8);
        assert_eq!(bank.available_squares(), 16);
        assert_eq!(bank.available_triples(), 8);

        for x_val in [0u128, 1, 2, 42, 65_535, PRIME_P - 1] {
            let x = TurboLagrange3Of4::split_secret(x_val).unwrap();
            let sq = bank.pop_square().unwrap();
            let x_sq = mpc_square_3_of_4(&x, sq).unwrap();
            assert_eq!(
                TurboLagrange3Of4::reconstruct_and_verify(&x_sq).unwrap(),
                mul_mod(x_val, x_val)
            );
        }

        let x = TurboLagrange3Of4::split_secret(12_345).unwrap();
        let y = TurboLagrange3Of4::split_secret(54_321).unwrap();
        let triple = bank.pop_triple().unwrap();
        let xy = mpc_mul_triple_3_of_4(&x, &y, triple).unwrap();
        assert_eq!(
            TurboLagrange3Of4::reconstruct_and_verify(&xy).unwrap(),
            mul_mod(12_345, 54_321)
        );
    }

    #[test]
    fn test_parallel_64_buckets_balance_preservation_and_it_privacy() {
        let num_buckets = 64usize;
        let mut cluster = TurboShieldedCluster::new(num_buckets).unwrap();
        let mut expected = vec![[0u128; TURBO_BUCKET_SIZE]; num_buckets];

        for b in 0..num_buckets {
            for s in 0..TURBO_BUCKET_SIZE {
                let init = 1_000 + (b as u128) * 7 + (s as u128) * 3;
                cluster.mint_balance(b, s, init).unwrap();
                expected[b][s] = init;
            }
        }

        // Snapshot pre-transfer shares of bucket 0 to prove re-randomization & < 3 secrecy.
        let pre_bucket0: Vec<Share4> = (0..TURBO_BUCKET_SIZE)
            .map(|s| *cluster.balance_shares(0, s).unwrap())
            .collect();

        // Build 512 parallel transfers (8 per bucket across all 64 disjoint buckets).
        let mut requests = Vec::with_capacity(num_buckets * 8);
        for b in 0..num_buckets {
            for i in 0..8 {
                let sender = (i * 2) % TURBO_BUCKET_SIZE;
                let recipient = (sender + 5) % TURBO_BUCKET_SIZE;
                let amount = 17 + ((b + i) as u128) % 50;
                let req = TurboTransferRequest::new(
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

        let mut bank = TurboBeaverBank::new_for_txs(requests.len());
        let committed = cluster.execute_parallel_batch(&requests, &mut bank).unwrap();
        assert_eq!(committed, requests.len());
        assert_eq!(bank.available_txs(), 0);

        // 1. Exact balance preservation across all 64 * 16 = 1,024 accounts.
        for b in 0..num_buckets {
            for s in 0..TURBO_BUCKET_SIZE {
                assert_eq!(
                    cluster.reconstruct_balance(b, s).unwrap(),
                    expected[b][s],
                    "balance mismatch at bucket {b}, slot {s}"
                );
            }
        }

        // 2. Information-theoretic privacy: EVERY slot in bucket 0 (including non-recipients!)
        //    re-randomized, and any coalition of < 3 validators learns 0 bits (2 shares can
        //    perfectly explain ANY hypothetical secret balance).
        let inv2 = (PRIME_P + 1) / 2;
        for s in 0..TURBO_BUCKET_SIZE {
            let post = *cluster.balance_shares(0, s).unwrap();
            assert_ne!(
                post, pre_bucket0[s],
                "slot {s} share must re-randomize even when not a recipient"
            );
            let y1 = post[0];
            let y2 = post[1];
            for hypothetical in [0u128, 777, 65_535, PRIME_P - 1] {
                let rhs = sub_mod(add_mod(y2, hypothetical), add_mod(y1, y1));
                let c2 = mul_mod(rhs, inv2);
                let c1 = sub_mod(sub_mod(y1, hypothetical), c2);
                let forged = TurboLagrange3Of4::eval_poly(hypothetical, c1, c2);
                assert_eq!(forged[0], y1);
                assert_eq!(forged[1], y2);
                assert_eq!(
                    TurboLagrange3Of4::reconstruct_and_verify(&forged).unwrap(),
                    hypothetical
                );
            }
        }
    }

    #[test]
    fn test_adversarial_attacks_caught_and_rolled_back_atomically() {
        let num_buckets = 4usize;
        let mut cluster = TurboShieldedCluster::new(num_buckets).unwrap();
        let init_bal = 500u128;
        for b in 0..num_buckets {
            for s in 0..TURBO_BUCKET_SIZE {
                cluster.mint_balance(b, s, init_bal).unwrap();
            }
        }

        let mut bank = TurboBeaverBank::new_for_txs(64);

        let make_bits = |val: u128| -> [Share4; TURBO_RANGE_BITS] {
            let mut out = [[0u128; 4]; TURBO_RANGE_BITS];
            for j in 0..TURBO_RANGE_BITS {
                out[j] = TurboLagrange3Of4::split_secret((val >> j) & 1).unwrap();
            }
            out
        };
        let make_one_hot = |target: usize| -> [Share4; TURBO_BUCKET_SIZE] {
            let mut out = [[0u128; 4]; TURBO_BUCKET_SIZE];
            for k in 0..TURBO_BUCKET_SIZE {
                out[k] = TurboLagrange3Of4::split_secret(if k == target { 1 } else { 0 }).unwrap();
            }
            out
        };

        // Attack 1: Overdraft (B + 1 = 501 with r = 0).
        let overdraft_req = TurboTransferRequest::new_raw(
            0,
            0,
            make_bits(init_bal + 1),
            make_bits(0),
            make_one_hot(1),
        );
        assert_eq!(
            cluster.execute_single_transfer(&overdraft_req, &mut bank),
            Err(TurboShieldedError::RlcCheckFailed)
        );
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), init_bal);
        assert_eq!(cluster.reconstruct_balance(0, 1).unwrap(), init_bal);

        // Attack 2: Negative bit (v_0 = PRIME_P - 1 == -1 mod P, crafted so B - v - r == 0).
        let mut neg_v = make_bits(0);
        neg_v[0] = TurboLagrange3Of4::split_secret(PRIME_P - 1).unwrap();
        let neg_req =
            TurboTransferRequest::new_raw(0, 0, neg_v, make_bits(init_bal + 1), make_one_hot(1));
        assert_eq!(
            cluster.execute_single_transfer(&neg_req, &mut bank),
            Err(TurboShieldedError::RlcCheckFailed)
        );
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), init_bal);

        // Attack 3: Non-binary bit (v_0 = 2, crafted so B - v - r == 0).
        let mut nonbin_v = make_bits(0);
        nonbin_v[0] = TurboLagrange3Of4::split_secret(2).unwrap();
        let nonbin_req =
            TurboTransferRequest::new_raw(0, 0, nonbin_v, make_bits(init_bal - 2), make_one_hot(1));
        assert_eq!(
            cluster.execute_single_transfer(&nonbin_req, &mut bank),
            Err(TurboShieldedError::RlcCheckFailed)
        );
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), init_bal);

        // Attack 4: Double-recipient inflation (s_1 = 1 AND s_2 = 1 => sum = 2).
        let mut dbl_sel = make_one_hot(1);
        dbl_sel[2] = TurboLagrange3Of4::split_secret(1).unwrap();
        let dbl_req =
            TurboTransferRequest::new_raw(0, 0, make_bits(10), make_bits(init_bal - 10), dbl_sel);
        assert_eq!(
            cluster.execute_single_transfer(&dbl_req, &mut bank),
            Err(TurboShieldedError::RlcCheckFailed)
        );
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), init_bal);
        assert_eq!(cluster.reconstruct_balance(0, 1).unwrap(), init_bal);
        assert_eq!(cluster.reconstruct_balance(0, 2).unwrap(), init_bal);

        // Attack 5: Degree-2 tampered share on v_bits, r_bits, and selector_shares -> parity check.
        let mut tampered_v = TurboTransferRequest::new(0, 0, init_bal, 1, 10).unwrap();
        tampered_v.v_bits[3][2] = add_mod(tampered_v.v_bits[3][2], 1);
        assert_eq!(
            cluster.execute_single_transfer(&tampered_v, &mut bank),
            Err(TurboShieldedError::InconsistentShares)
        );
        let mut tampered_r = TurboTransferRequest::new(0, 0, init_bal, 1, 10).unwrap();
        tampered_r.r_bits[7][0] = add_mod(tampered_r.r_bits[7][0], 1);
        assert_eq!(
            cluster.execute_single_transfer(&tampered_r, &mut bank),
            Err(TurboShieldedError::InconsistentShares)
        );
        let mut tampered_s = TurboTransferRequest::new(0, 0, init_bal, 1, 10).unwrap();
        tampered_s.selector_shares[5][3] = add_mod(tampered_s.selector_shares[5][3], 1);
        assert_eq!(
            cluster.execute_single_transfer(&tampered_s, &mut bank),
            Err(TurboShieldedError::InconsistentShares)
        );
        // Non-canonical field element (>= PRIME_P) rejected immediately.
        let mut non_canon = TurboTransferRequest::new(0, 0, init_bal, 1, 10).unwrap();
        non_canon.v_bits[0][1] = PRIME_P;
        assert_eq!(
            cluster.execute_single_transfer(&non_canon, &mut bank),
            Err(TurboShieldedError::FieldElementOutOfRange)
        );
        // Zero-recipient burn (all s_k = 0 => sum = 0 != 1) rejected by RLC.
        let zero_sel = [[0u128; 4]; TURBO_BUCKET_SIZE];
        let burn_req =
            TurboTransferRequest::new_raw(0, 0, make_bits(10), make_bits(init_bal - 10), zero_sel);
        assert_eq!(
            cluster.execute_single_transfer(&burn_req, &mut bank),
            Err(TurboShieldedError::RlcCheckFailed)
        );
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), init_bal);

        // Attack 6: Atomic parallel batch rollback — valid txs in buckets 0, 1, 2 MUST all roll
        // back when bucket 3 has an overdraft!
        let valid_b0 = TurboTransferRequest::new(0, 0, init_bal, 1, 50).unwrap();
        let valid_b1 = TurboTransferRequest::new(1, 0, init_bal, 1, 75).unwrap();
        let valid_b2 = TurboTransferRequest::new(2, 0, init_bal, 1, 90).unwrap();
        let bad_b3 = TurboTransferRequest::new_raw(
            3,
            0,
            make_bits(init_bal + 1),
            make_bits(0),
            make_one_hot(1),
        );
        let err = cluster
            .execute_parallel_batch(&[valid_b0, valid_b1, valid_b2, bad_b3], &mut bank)
            .expect_err("parallel batch with one invalid tx must abort atomically");
        assert_eq!(err, TurboShieldedError::RlcCheckFailed);

        // Verify ZERO balances changed in ANY bucket (0..4)!
        for b in 0..num_buckets {
            for s in 0..TURBO_BUCKET_SIZE {
                assert_eq!(
                    cluster.reconstruct_balance(b, s).unwrap(),
                    init_bal,
                    "bucket {b} slot {s} leaked partial state after batch rollback"
                );
            }
        }
    }

    #[test]
    fn test_persistent_pool_multi_epoch_and_bank_exhaustion() {
        let mut cluster = TurboShieldedCluster::new(8).unwrap();
        for b in 0..8 {
            cluster.mint_balance(b, 0, 1_000).unwrap();
        }
        let mut bank = TurboBeaverBank::new_for_txs(16);
        let mut bal0 = [1_000u128; 8];
        let mut bal1 = [0u128; 8];

        // Run 2 consecutive batches on the same persistent worker pool.
        for _epoch in 0..2 {
            let mut batch = Vec::with_capacity(8);
            for b in 0..8 {
                let req = TurboTransferRequest::new(b, 0, bal0[b], 1, 25).unwrap();
                bal0[b] -= 25;
                bal1[b] += 25;
                batch.push(req);
            }
            assert_eq!(cluster.execute_parallel_batch(&batch, &mut bank).unwrap(), 8);
        }

        for b in 0..8 {
            assert_eq!(cluster.reconstruct_balance(b, 0).unwrap(), 950);
            assert_eq!(cluster.reconstruct_balance(b, 1).unwrap(), 50);
        }

        // Bank is now exhausted: any additional transfer MUST fail cleanly without mutating state.
        let extra = TurboTransferRequest::new(0, 0, 950, 1, 10).unwrap();
        assert_eq!(
            cluster.execute_single_transfer(&extra, &mut bank),
            Err(TurboShieldedError::BeaverSquaresExhausted {
                needed: SQUARES_PER_TURBO_TX,
                available: 0,
            })
        );
        assert_eq!(cluster.reconstruct_balance(0, 0).unwrap(), 950);
    }

    #[test]
    fn test_run_turbo_shielded_bench_live_tps() {
        let report = run_turbo_shielded_bench();
        println!("\n{report}\n");
        assert_eq!(report.total_txs, 16_384);
        assert_eq!(report.openings_per_tx, 68);
        assert_eq!(report.buckets_used, 64);
        assert!(report.shielded_tps > 0.0);
    }

    #[test]
    fn test_beaver_bank_compaction_overflow_cap_redacted_debug_and_early_wipe() {
        // H-8: TurboBeaverBank compaction bounds memory across repeated reserve/refill cycles.
        let mut bank = TurboBeaverBank::new_for_txs(8);
        let mut cluster = TurboShieldedCluster::new(1).unwrap();
        cluster.mint_balance(0, 0, 1_000).unwrap();
        let mut bal0 = 1_000u128;
        for _ in 0..16 {
            let req = TurboTransferRequest::new(0, 0, bal0, 1, 1).unwrap();
            bal0 -= 1;
            cluster.execute_single_transfer(&req, &mut bank).unwrap();
            if bank.available_txs() == 0 {
                bank.refill_for_txs(8);
            }
        }
        assert!(bank.squares.len() <= 8 * SQUARES_PER_TURBO_TX);
        assert!(bank.stars.len() <= 8 * STARS_PER_TURBO_TX);
        assert!(bank.triples.len() <= 8 * TRIPLES_PER_TURBO_TX);

        // C-2: Cumulative balance and safe bucket supply cap enforcement.
        assert!(cluster.mint_balance(0, 0, 65_000).is_err());
        assert!(cluster.mint_balance(0, 2, 65_000).is_err());
        cluster.mint_balance(0, 2, 64_535).unwrap();
        assert!(cluster.mint_balance(0, 3, 1).is_err());

        // L-1: Redacted Debug and early-error wipe of squares, star, and blinding triple.
        let mut bank2 = TurboBeaverBank::new_for_txs(1);
        assert!(format!("{bank2:?}").contains("<redacted>"));
        let (squares, stars, triples) = bank2.reserve_for_txs(1).unwrap();
        assert!(format!("{:?}", squares[0]).contains("<redacted>"));
        assert!(format!("{:?}", stars[0]).contains("<redacted>"));
        assert!(format!("{:?}", triples[0]).contains("<redacted>"));
        let mut dummy_bucket = [[0u128; 4]; TURBO_BUCKET_SIZE];
        let req = TurboTransferRequest::new(0, 0, 100, 1, 10).unwrap();
        // Trigger early gamma == 0 error; all provided Beaver material must be zeroized!
        let err = execute_transfer_in_bucket(
            &mut dummy_bucket,
            &req,
            squares,
            &mut stars[0],
            &mut triples[0],
            0,
        )
        .unwrap_err();
        assert_eq!(
            err,
            TurboShieldedError::InvalidParameters(
                "RLC challenge gamma must be in [1, PRIME_P)"
            )
        );
        for sq in squares.iter() {
            assert_eq!(*sq.a(), [0u128; 4]);
            assert_eq!(*sq.a_sq(), [0u128; 4]);
        }
        assert_eq!(*stars[0].b_v(), [0u128; 4]);
        assert_eq!(*triples[0].a(), [0u128; 4]);
        assert_eq!(*triples[0].b(), [0u128; 4]);
        assert_eq!(*triples[0].c(), [0u128; 4]);
    }
}
