//! Information-Theoretic Privacy & Accelerated MPC for Vernam (VRNM).
//!
//! Zero external crates, zero computational cryptography (no SHA, zk-SNARKs, AES, or RSA).
//! All privacy and integrity guarantees rest purely on information-theoretic security over
//! the Mersenne prime field `F_(2^127 - 1)` and one-time pads:
//!
//! - [`LagrangeCache`]: Precomputes all Lagrange basis coefficients at startup for fixed
//!   validator IDs `1..=N` and threshold `t`, eliminating online `inv_mod` calls and verifying
//!   degree-`(t - 1)` consistency across all `N` shares.
//! - [`split_secret`] & [`proactive_refresh_epoch`]: Fast Horner-evaluated Shamir secret sharing
//!   and Proactive Secret Sharing (zero-polynomial refresh over pairwise OTP-masked deltas).
//! - [`BeaverPool`] & [`BeaverTriple`]: Offline Beaver triple factory with `Drop` zeroization
//!   and strict single-use move semantics.
//! - [`ShardedPrivateLedger`]: Fixed-size anonymity buckets reducing per-transfer blinded updates
//!   from `O(total_users)` to `O(bucket_size) = O(1)`, with confidential bit-decomposed range
//!   proofs (`0 <= v < 2^W`, `0 <= B_sender - v < 2^W`, `B_sender - v - r == 0`), blinded one-hot
//!   recipient selectors (`s_k in {0, 1}`, `sum(s_k) == 1`), and sender-anonymous lockstep batch
//!   rounds ([`ShardedPrivateLedger::execute_anonymous_bucket_round`]).
//! - [`CoverFrame`] & [`CoverTrafficGenerator`]: Constant-rate, fixed-size OTP cover traffic
//!   frames authenticated with one-time Carter-Wegman universal MACs over `F_(2^127 - 1)`.

use std::fmt;

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, fill_os_random, inv_mod, mul_mod, random_field_elem, sub_mod,
    zeroize_slice, zeroize_u128,
};

/// Default Shamir threshold `t = 3` (tolerates up to `t - 1 = 2` colluding validators).
pub const DEFAULT_THRESHOLD: usize = 3;

/// Default validator committee size `N = 4` (provides `N - t = 1` redundant consistency check).
pub const DEFAULT_NUM_VALIDATORS: usize = 4;

/// Default anonymity bucket size (`O(1)` blinded updates per transfer).
pub const DEFAULT_BUCKET_SIZE: usize = 16;

/// Default confidential range proof bit width (`0 <= v < 2^16`).
pub const DEFAULT_RANGE_BITS: usize = 16;

/// Ciphertext body size in bytes for a fixed-size [`CoverFrame`] (`16 * 15 = 240` bytes).
pub const COVER_FRAME_BODY_SIZE: usize = 240;

/// 128-bit Carter-Wegman MAC size in bytes.
pub const COVER_FRAME_TAG_SIZE: usize = 16;

/// Total wire size of every [`CoverFrame`] (identical for real and dummy cover frames).
pub const COVER_FRAME_SIZE: usize = COVER_FRAME_BODY_SIZE + COVER_FRAME_TAG_SIZE;

/// Maximum plaintext payload length carried by a single [`CoverFrame`]
/// (`1` byte frame kind + `2` bytes little-endian length prefix).
pub const MAX_COVER_PAYLOAD_LEN: usize = COVER_FRAME_BODY_SIZE - 3;

const FRAME_KIND_DUMMY: u8 = 0x00;
const FRAME_KIND_REAL: u8 = 0x01;

/// Errors returned by IT-MPC, Shamir sharing, sharded ledger, and cover-traffic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcError {
    /// Invalid configuration or protocol parameter.
    InvalidParameters(&'static str),
    /// A share or scalar is not in the canonical field range `[0, PRIME_P)`.
    FieldElementOutOfRange,
    /// Provided share slice does not match the committee size.
    InvalidShareLength { expected: usize, got: usize },
    /// Shares fail degree-`(t - 1)` Lagrange consistency (tampered, corrupted, or mixed epochs).
    InconsistentShares,
    /// Offline Beaver triple pool lacks enough single-use triples for the operation.
    BeaverPoolExhausted { needed: usize, available: usize },
    /// Account ID does not exist in the sharded ledger.
    InvalidAccount { account_id: usize },
    /// Anonymity bucket ID does not exist in the sharded ledger.
    InvalidBucket { bucket_id: usize },
    /// Confidential range proof failed (`b * (b - 1) != 0` on amount or remainder bit).
    RangeProofFailed,
    /// Confidential balance equation failed (`B_sender - v - r != 0`, e.g., overdraft).
    BalanceCheckFailed,
    /// Blinded recipient selector failed (`s_k * (s_k - 1) != 0` or `sum(s_k) != 1`).
    SelectorCheckFailed,
    /// Lockstep anonymous bucket round inputs do not cover the bucket properly.
    InvalidBatchRound(&'static str),
    /// Cover frame encoding, payload length, or Carter-Wegman MAC check failed.
    InvalidCoverFrame(&'static str),
}

impl fmt::Display for MpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcError::InvalidParameters(msg) => write!(f, "invalid MPC parameters: {msg}"),
            MpcError::FieldElementOutOfRange => write!(f, "field element >= PRIME_P"),
            MpcError::InvalidShareLength { expected, got } => {
                write!(f, "invalid share length: expected {expected}, got {got}")
            }
            MpcError::InconsistentShares => {
                write!(f, "shares failed degree-(t-1) Lagrange consistency check")
            }
            MpcError::BeaverPoolExhausted { needed, available } => {
                write!(
                    f,
                    "Beaver triple pool exhausted: needed {needed}, available {available}"
                )
            }
            MpcError::InvalidAccount { account_id } => {
                write!(f, "invalid account ID: {account_id}")
            }
            MpcError::InvalidBucket { bucket_id } => {
                write!(f, "invalid anonymity bucket ID: {bucket_id}")
            }
            MpcError::RangeProofFailed => write!(f, "confidential range proof bit check failed"),
            MpcError::BalanceCheckFailed => {
                write!(f, "confidential balance equation (B_sender - v - r == 0) failed")
            }
            MpcError::SelectorCheckFailed => {
                write!(f, "blinded one-hot recipient selector check failed")
            }
            MpcError::InvalidBatchRound(msg) => write!(f, "invalid lockstep bucket round: {msg}"),
            MpcError::InvalidCoverFrame(msg) => write!(f, "invalid cover frame: {msg}"),
        }
    }
}

impl std::error::Error for MpcError {}

/// Wipe a slice of `u128` secrets using volatile writes.
#[inline]
fn zeroize_u128_slice(buf: &mut [u128]) {
    for elem in buf.iter_mut() {
        zeroize_u128(elem);
    }
}

/// Fill `out` with uniform random elements in `[0, PRIME_P)` using a single batched OS entropy
/// read and unbiased rejection sampling.
fn fill_random_field_elems(out: &mut [u128]) {
    if out.is_empty() {
        return;
    }
    let mut raw = vec![0u8; out.len() * 16];
    fill_os_random(&mut raw);
    for (dst, chunk) in out.iter_mut().zip(raw.chunks_exact(16)) {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(chunk);
        let candidate = u128::from_le_bytes(bytes) & PRIME_P;
        *dst = if candidate < PRIME_P {
            candidate
        } else {
            // Occurs with probability 2^-127; fall back to fresh rejection sample.
            random_field_elem()
        };
        zeroize_slice(&mut bytes);
    }
    zeroize_slice(&mut raw);
}

/// Evaluate polynomial `coeffs[0] + coeffs[1]*x + ... + coeffs[t-1]*x^(t-1)` at `x = 1..=n`
/// using Horner's method over `F_(2^127 - 1)`.
#[inline]
fn eval_poly_horner(coeffs: &[u128], num_validators: usize) -> Vec<u128> {
    let mut shares = Vec::with_capacity(num_validators);
    for idx in 1..=num_validators {
        let x = idx as u128;
        let mut acc = 0u128;
        for &c in coeffs.iter().rev() {
            acc = add_mod(mul_mod(acc, x), c);
        }
        shares.push(acc);
    }
    shares
}

// ============================================================================
// 1. Precomputed Lagrange Interpolator (`LagrangeCache`)
// ============================================================================

/// Precomputed Lagrange basis interpolator and degree-`(t - 1)` verifier for validator IDs
/// `x_i = 1..=N`.
///
/// All modular inversions (`inv_mod`) are performed ONCE during [`LagrangeCache::new`], making
/// online reconstruction and malicious-share verification pure multiply-add dot products.
#[derive(Debug, Clone)]
pub struct LagrangeCache {
    threshold: usize,
    num_validators: usize,
    /// Precomputed basis `lambda_j(0)` for evaluation points `1..=threshold`.
    origin_coeffs: Vec<u128>,
    /// For each redundant validator `k` in `(threshold + 1)..=num_validators`,
    /// `verify_rows[k - threshold - 1][j]` stores `ell_j(k)` so `P(k) = sum_j ell_j(k) * y_j`.
    verify_rows: Vec<Vec<u128>>,
}

impl LagrangeCache {
    /// Precompute all Lagrange basis coefficients at `x = 0` and at redundant points
    /// `x = (threshold + 1)..=num_validators`.
    pub fn new(threshold: usize, num_validators: usize) -> Result<Self, MpcError> {
        if threshold == 0 || threshold > num_validators {
            return Err(MpcError::InvalidParameters(
                "require 1 <= threshold <= num_validators",
            ));
        }

        let origin_coeffs = Self::compute_basis_row(0, threshold);
        let mut verify_rows = Vec::with_capacity(num_validators - threshold);
        for k in (threshold + 1)..=num_validators {
            verify_rows.push(Self::compute_basis_row(k as u128, threshold));
        }

        Ok(Self {
            threshold,
            num_validators,
            origin_coeffs,
            verify_rows,
        })
    }

    /// Construct the default `(3, 4)` Vernam validator cache.
    pub fn new_3_of_4() -> Self {
        Self::new(DEFAULT_THRESHOLD, DEFAULT_NUM_VALIDATORS)
            .expect("default (3, 4) parameters are valid")
    }

    /// Compute Lagrange basis coefficients `ell_j(target_x)` for `x_j = 1..=threshold`.
    fn compute_basis_row(target_x: u128, threshold: usize) -> Vec<u128> {
        let mut coeffs = Vec::with_capacity(threshold);
        for j in 1..=threshold {
            let xj = j as u128;
            let mut num = 1u128;
            let mut den = 1u128;
            for m in 1..=threshold {
                if m == j {
                    continue;
                }
                let xm = m as u128;
                num = mul_mod(num, sub_mod(target_x, xm));
                den = mul_mod(den, sub_mod(xj, xm));
            }
            coeffs.push(mul_mod(num, inv_mod(den)));
        }
        coeffs
    }

    /// Threshold `t` (minimum shares required to reconstruct).
    #[inline]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Total number of validators `N`.
    #[inline]
    pub fn num_validators(&self) -> usize {
        self.num_validators
    }

    /// Precomputed Lagrange basis coefficients at `x = 0` for `x = 1..=t`.
    #[inline]
    pub fn origin_coeffs(&self) -> &[u128] {
        &self.origin_coeffs
    }

    /// Verify that all `N` shares lie on a single polynomial of degree `<= threshold - 1`
    /// without computing or revealing `P(0)`. Uses zero `inv_mod` calls.
    pub fn verify_shares(&self, shares: &[u128]) -> Result<(), MpcError> {
        if shares.len() != self.num_validators {
            return Err(MpcError::InvalidShareLength {
                expected: self.num_validators,
                got: shares.len(),
            });
        }
        for &s in shares {
            if s >= PRIME_P {
                return Err(MpcError::FieldElementOutOfRange);
            }
        }

        for (offset, row) in self.verify_rows.iter().enumerate() {
            let mut expected = 0u128;
            for (&coeff, &y) in row.iter().zip(shares.iter()) {
                expected = add_mod(expected, mul_mod(coeff, y));
            }
            if expected != shares[self.threshold + offset] {
                return Err(MpcError::InconsistentShares);
            }
        }
        Ok(())
    }

    /// Reconstruct `P(0)` from `shares[0..N]` while verifying degree-`(t - 1)` consistency
    /// across all `N` shares. Catches tampered, corrupted, or mixed-epoch shares with zero
    /// online `inv_mod` calls.
    pub fn reconstruct_and_verify(&self, shares: &[u128]) -> Result<u128, MpcError> {
        self.verify_shares(shares)?;
        Ok(self.reconstruct_fast_unchecked(&shares[..self.threshold]))
    }

    /// Fast dot-product reconstruction of `P(0)` from the first `t` shares without checking
    /// redundant validators. Callers needing integrity checks must use
    /// [`LagrangeCache::reconstruct_and_verify`].
    #[inline]
    pub fn reconstruct_fast_unchecked(&self, first_t_shares: &[u128]) -> u128 {
        debug_assert!(first_t_shares.len() >= self.threshold);
        let mut secret = 0u128;
        for (&coeff, &y) in self.origin_coeffs.iter().zip(first_t_shares.iter()) {
            secret = add_mod(secret, mul_mod(coeff, y));
        }
        secret
    }
}

// ============================================================================
// 2. Shamir Secret Sharing & Proactive Secret Sharing
// ============================================================================

/// Split `secret` in `[0, PRIME_P)` into `num_validators` Shamir shares with threshold
/// `threshold` evaluated at `x = 1..=num_validators` via Horner's method.
pub fn split_secret(
    secret: u128,
    threshold: usize,
    num_validators: usize,
) -> Result<Vec<u128>, MpcError> {
    if threshold == 0 || threshold > num_validators {
        return Err(MpcError::InvalidParameters(
            "require 1 <= threshold <= num_validators",
        ));
    }
    if secret >= PRIME_P {
        return Err(MpcError::FieldElementOutOfRange);
    }

    let mut coeffs = vec![0u128; threshold];
    coeffs[0] = secret;
    if threshold > 1 {
        fill_random_field_elems(&mut coeffs[1..]);
    }
    let shares = eval_poly_horner(&coeffs, num_validators);
    zeroize_u128_slice(&mut coeffs);
    Ok(shares)
}

/// Generate a degree-`(threshold - 1)` Shamir sharing of `0` (`z(0) = 0`) for proactive refresh.
pub fn split_zero_poly(threshold: usize, num_validators: usize) -> Result<Vec<u128>, MpcError> {
    split_secret(0, threshold, num_validators)
}

/// Proactive Secret Sharing epoch refresh for a single secret's shares.
///
/// Each validator `j` generates an independent random degree-`(t - 1)` zero-constant polynomial
/// `z_j(x)` (`z_j(0) = 0`), masks every outgoing delta `z_j(i)` with a fresh pairwise one-time
/// pad `k_{j,i} in F_p`, transmits `c_{j->i} = z_j(i) + k_{j,i} (mod p)` to validator `i`,
/// and validator `i` unmasks and adds all received deltas to its share.
///
/// The reconstructed secret `P(0)` is preserved identically while all shares from the previous
/// epoch become mathematically incompatible with the new epoch's shares.
pub fn proactive_refresh_epoch(shares: &mut [u128], threshold: usize) -> Result<(), MpcError> {
    let n = shares.len();
    if threshold == 0 || threshold > n {
        return Err(MpcError::InvalidParameters(
            "require 1 <= threshold <= shares.len()",
        ));
    }
    for &s in shares.iter() {
        if s >= PRIME_P {
            return Err(MpcError::FieldElementOutOfRange);
        }
    }

    let rand_coeffs_per_validator = threshold - 1;
    let total_poly_rands = n * rand_coeffs_per_validator;
    let total_otp_pads = n * n;
    let mut entropy = vec![0u128; total_poly_rands + total_otp_pads];
    fill_random_field_elems(&mut entropy);

    let (poly_rands, otp_pads) = entropy.split_at(total_poly_rands);
    let mut coeffs = vec![0u128; threshold];
    let mut masked_inbox = vec![0u128; n * n];

    // Phase 1: Each validator j generates z_j(x) with z_j(0) = 0 and OTP-masks deltas for i.
    for j in 0..n {
        coeffs[0] = 0;
        if rand_coeffs_per_validator > 0 {
            let start = j * rand_coeffs_per_validator;
            coeffs[1..].copy_from_slice(&poly_rands[start..start + rand_coeffs_per_validator]);
        }
        let mut deltas_j = eval_poly_horner(&coeffs, n);
        for i in 0..n {
            let pad = otp_pads[j * n + i];
            masked_inbox[j * n + i] = add_mod(deltas_j[i], pad);
        }
        zeroize_u128_slice(&mut deltas_j);
    }

    // Phase 2: Each validator i unmasks all incoming deltas using its pairwise OTP pads and adds.
    for (i, share_i) in shares.iter_mut().enumerate() {
        let mut acc = *share_i;
        for j in 0..n {
            let pad = otp_pads[j * n + i];
            let delta = sub_mod(masked_inbox[j * n + i], pad);
            acc = add_mod(acc, delta);
        }
        *share_i = acc;
    }

    zeroize_u128_slice(&mut coeffs);
    zeroize_u128_slice(&mut masked_inbox);
    zeroize_u128_slice(&mut entropy);
    Ok(())
}

/// Batched Proactive Secret Sharing epoch refresh across many secret share vectors in a single
/// OS entropy read (used to refresh an entire [`ShardedPrivateLedger`] in one pass).
pub fn proactive_refresh_epoch_batch(
    share_vecs: &mut [Vec<u128>],
    threshold: usize,
    num_validators: usize,
) -> Result<(), MpcError> {
    if threshold == 0 || threshold > num_validators {
        return Err(MpcError::InvalidParameters(
            "require 1 <= threshold <= num_validators",
        ));
    }
    if share_vecs.is_empty() {
        return Ok(());
    }
    for shares in share_vecs.iter() {
        if shares.len() != num_validators {
            return Err(MpcError::InvalidShareLength {
                expected: num_validators,
                got: shares.len(),
            });
        }
        for &s in shares {
            if s >= PRIME_P {
                return Err(MpcError::FieldElementOutOfRange);
            }
        }
    }

    let n = num_validators;
    let rand_coeffs_per_validator = threshold - 1;
    let per_secret_poly = n * rand_coeffs_per_validator;
    let per_secret_pads = n * n;
    let per_secret_total = per_secret_poly + per_secret_pads;

    let mut entropy = vec![0u128; share_vecs.len() * per_secret_total];
    fill_random_field_elems(&mut entropy);

    let mut coeffs = vec![0u128; threshold];
    let mut masked_inbox = vec![0u128; n * n];

    for (idx, shares) in share_vecs.iter_mut().enumerate() {
        let base = idx * per_secret_total;
        let poly_rands = &entropy[base..base + per_secret_poly];
        let otp_pads = &entropy[base + per_secret_poly..base + per_secret_total];

        for j in 0..n {
            coeffs[0] = 0;
            if rand_coeffs_per_validator > 0 {
                let start = j * rand_coeffs_per_validator;
                coeffs[1..].copy_from_slice(&poly_rands[start..start + rand_coeffs_per_validator]);
            }
            let mut deltas_j = eval_poly_horner(&coeffs, n);
            for i in 0..n {
                masked_inbox[j * n + i] = add_mod(deltas_j[i], otp_pads[j * n + i]);
            }
            zeroize_u128_slice(&mut deltas_j);
        }

        for (i, share_i) in shares.iter_mut().enumerate() {
            let mut acc = *share_i;
            for j in 0..n {
                let delta = sub_mod(masked_inbox[j * n + i], otp_pads[j * n + i]);
                acc = add_mod(acc, delta);
            }
            *share_i = acc;
        }
    }

    zeroize_u128_slice(&mut coeffs);
    zeroize_u128_slice(&mut masked_inbox);
    zeroize_u128_slice(&mut entropy);
    Ok(())
}

// ============================================================================
// 3. Offline Beaver Triple Factory (`BeaverPool`) & Linear/Multiplicative MPC
// ============================================================================

/// A single-use Shamir-shared Beaver multiplication triple `([a], [b], [c])` with `c = a * b`.
///
/// Intentionally does NOT implement `Clone` or `Copy` to enforce strict one-time consumption at
/// compile time, and zeroizes all shares on `Drop`.
#[derive(Debug)]
pub struct BeaverTriple {
    a: Vec<u128>,
    b: Vec<u128>,
    c: Vec<u128>,
}

impl BeaverTriple {
    /// Shares of `a`.
    #[inline]
    pub fn a(&self) -> &[u128] {
        &self.a
    }

    /// Shares of `b`.
    #[inline]
    pub fn b(&self) -> &[u128] {
        &self.b
    }

    /// Shares of `c = a * b (mod p)`.
    #[inline]
    pub fn c(&self) -> &[u128] {
        &self.c
    }
}

impl Drop for BeaverTriple {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.a);
        zeroize_u128_slice(&mut self.b);
        zeroize_u128_slice(&mut self.c);
    }
}

/// Offline factory and pool of single-use Shamir-shared Beaver triples.
///
/// Automatically zeroizes all unused triples when dropped.
#[derive(Debug)]
pub struct BeaverPool {
    threshold: usize,
    num_validators: usize,
    triples: Vec<BeaverTriple>,
}

impl BeaverPool {
    /// Create a Beaver triple pool for `(threshold, num_validators)` pre-filled with
    /// `initial_count` offline triples.
    pub fn new(
        threshold: usize,
        num_validators: usize,
        initial_count: usize,
    ) -> Result<Self, MpcError> {
        if threshold == 0 || threshold > num_validators {
            return Err(MpcError::InvalidParameters(
                "require 1 <= threshold <= num_validators",
            ));
        }
        let mut pool = Self {
            threshold,
            num_validators,
            triples: Vec::with_capacity(initial_count),
        };
        pool.refill(initial_count);
        Ok(pool)
    }

    /// Convenience constructor for the default `(3, 4)` committee.
    pub fn new_3_of_4(initial_count: usize) -> Self {
        Self::new(DEFAULT_THRESHOLD, DEFAULT_NUM_VALIDATORS, initial_count)
            .expect("default (3, 4) parameters are valid")
    }

    /// Pre-generate `count` fresh one-time Beaver triples offline in a single batched entropy read.
    pub fn refill(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        // Per triple: a_secret, b_secret, plus (t-1) random coefficients each for a, b, c.
        let deg_rands = self.threshold - 1;
        let elems_per_triple = 2 + 3 * deg_rands;
        let mut entropy = vec![0u128; count * elems_per_triple];
        fill_random_field_elems(&mut entropy);

        let mut coeffs_a = vec![0u128; self.threshold];
        let mut coeffs_b = vec![0u128; self.threshold];
        let mut coeffs_c = vec![0u128; self.threshold];

        self.triples.reserve(count);
        for chunk in entropy.chunks_exact(elems_per_triple) {
            let mut a_secret = chunk[0];
            let mut b_secret = chunk[1];
            let mut c_secret = mul_mod(a_secret, b_secret);

            coeffs_a[0] = a_secret;
            coeffs_b[0] = b_secret;
            coeffs_c[0] = c_secret;
            if deg_rands > 0 {
                let r_a = &chunk[2..2 + deg_rands];
                let r_b = &chunk[2 + deg_rands..2 + 2 * deg_rands];
                let r_c = &chunk[2 + 2 * deg_rands..2 + 3 * deg_rands];
                coeffs_a[1..].copy_from_slice(r_a);
                coeffs_b[1..].copy_from_slice(r_b);
                coeffs_c[1..].copy_from_slice(r_c);
            }

            let a_shares = eval_poly_horner(&coeffs_a, self.num_validators);
            let b_shares = eval_poly_horner(&coeffs_b, self.num_validators);
            let c_shares = eval_poly_horner(&coeffs_c, self.num_validators);

            self.triples.push(BeaverTriple {
                a: a_shares,
                b: b_shares,
                c: c_shares,
            });

            zeroize_u128(&mut a_secret);
            zeroize_u128(&mut b_secret);
            zeroize_u128(&mut c_secret);
        }

        zeroize_u128_slice(&mut coeffs_a);
        zeroize_u128_slice(&mut coeffs_b);
        zeroize_u128_slice(&mut coeffs_c);
        zeroize_u128_slice(&mut entropy);
    }

    /// Pop a single-use Beaver triple from the pool. Returns [`MpcError::BeaverPoolExhausted`]
    /// when empty.
    #[inline]
    pub fn pop(&mut self) -> Result<BeaverTriple, MpcError> {
        self.triples.pop().ok_or(MpcError::BeaverPoolExhausted {
            needed: 1,
            available: 0,
        })
    }

    /// Number of remaining unused triples in the pool.
    #[inline]
    pub fn len(&self) -> usize {
        self.triples.len()
    }

    /// Whether the pool has no triples remaining.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.triples.is_empty()
    }

    /// Committee threshold `t`.
    #[inline]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Committee size `N`.
    #[inline]
    pub fn num_validators(&self) -> usize {
        self.num_validators
    }
}

impl Drop for BeaverPool {
    fn drop(&mut self) {
        // Explicitly clear so each BeaverTriple's Drop zeroizer executes immediately.
        self.triples.clear();
    }
}

/// Local share addition `[x] + [y]`.
pub fn mpc_add(x: &[u128], y: &[u128]) -> Result<Vec<u128>, MpcError> {
    if x.len() != y.len() {
        return Err(MpcError::InvalidShareLength {
            expected: x.len(),
            got: y.len(),
        });
    }
    Ok(x.iter().zip(y.iter()).map(|(&a, &b)| add_mod(a, b)).collect())
}

/// Local share subtraction `[x] - [y]`.
pub fn mpc_sub(x: &[u128], y: &[u128]) -> Result<Vec<u128>, MpcError> {
    if x.len() != y.len() {
        return Err(MpcError::InvalidShareLength {
            expected: x.len(),
            got: y.len(),
        });
    }
    Ok(x.iter().zip(y.iter()).map(|(&a, &b)| sub_mod(a, b)).collect())
}

/// Local public scalar multiplication `scalar * [x]`.
#[inline]
pub fn mpc_scale(x: &[u128], scalar: u128) -> Vec<u128> {
    x.iter().map(|&a| mul_mod(a, scalar)).collect()
}

/// Local addition of a public constant `[x] + constant`.
#[inline]
pub fn mpc_add_const(x: &[u128], constant: u128) -> Vec<u128> {
    x.iter().map(|&a| add_mod(a, constant)).collect()
}

/// Local subtraction of a public constant `[x] - constant`.
#[inline]
pub fn mpc_sub_const(x: &[u128], constant: u128) -> Vec<u128> {
    x.iter().map(|&a| sub_mod(a, constant)).collect()
}

/// Online Beaver multiplication `[x * y]` consuming a single-use [`BeaverTriple`].
///
/// Opens only the one-time-pad-masked differences `d = x - a` and `e = y - b` via
/// [`LagrangeCache::reconstruct_and_verify`], verifying degree-`(t - 1)` consistency of both
/// inputs without leaking `x` or `y`, and producing a degree-`(t - 1)` sharing of `x * y`.
pub fn mpc_mul(
    x: &[u128],
    y: &[u128],
    triple: BeaverTriple,
    cache: &LagrangeCache,
) -> Result<Vec<u128>, MpcError> {
    let n = cache.num_validators();
    if x.len() != n {
        return Err(MpcError::InvalidShareLength {
            expected: n,
            got: x.len(),
        });
    }
    if y.len() != n {
        return Err(MpcError::InvalidShareLength {
            expected: n,
            got: y.len(),
        });
    }
    if triple.a.len() != n || triple.b.len() != n || triple.c.len() != n {
        return Err(MpcError::InvalidShareLength {
            expected: n,
            got: triple.a.len(),
        });
    }

    let mut d_shares = Vec::with_capacity(n);
    let mut e_shares = Vec::with_capacity(n);
    for i in 0..n {
        if x[i] >= PRIME_P || y[i] >= PRIME_P {
            zeroize_u128_slice(&mut d_shares);
            zeroize_u128_slice(&mut e_shares);
            return Err(MpcError::FieldElementOutOfRange);
        }
        d_shares.push(sub_mod(x[i], triple.a[i]));
        e_shares.push(sub_mod(y[i], triple.b[i]));
    }

    let mut d = match cache.reconstruct_and_verify(&d_shares) {
        Ok(val) => val,
        Err(err) => {
            zeroize_u128_slice(&mut d_shares);
            zeroize_u128_slice(&mut e_shares);
            return Err(err);
        }
    };
    let mut e = match cache.reconstruct_and_verify(&e_shares) {
        Ok(val) => val,
        Err(err) => {
            zeroize_u128_slice(&mut d_shares);
            zeroize_u128_slice(&mut e_shares);
            zeroize_u128(&mut d);
            return Err(err);
        }
    };

    let mut de = mul_mod(d, e);
    let mut prod = Vec::with_capacity(n);
    for i in 0..n {
        // z_i = c_i + d*b_i + e*a_i + d*e (mod p)
        let term1 = add_mod(triple.c[i], mul_mod(d, triple.b[i]));
        let term2 = add_mod(mul_mod(e, triple.a[i]), de);
        prod.push(add_mod(term1, term2));
    }

    zeroize_u128_slice(&mut d_shares);
    zeroize_u128_slice(&mut e_shares);
    zeroize_u128(&mut d);
    zeroize_u128(&mut e);
    zeroize_u128(&mut de);
    // `triple` is dropped and zeroized here.
    Ok(prod)
}

// ============================================================================
// 4. Sharded Anonymity Buckets (`ShardedPrivateLedger`) & Lockstep Rounds
// ============================================================================

/// A client-submitted confidential transfer request containing Shamir-shared bit decompositions
/// for the transfer amount `v`, the post-transfer remainder `r = B_sender - v`, and the blinded
/// one-hot recipient selector `s_0..s_{K-1}` over `recipient_bucket`.
#[derive(Debug)]
pub struct ConfidentialTransferRequest {
    /// Global sender account ID (`bucket_id * bucket_size + slot`).
    pub sender: usize,
    /// Target anonymity bucket ID for the blinded one-hot recipient selector.
    pub recipient_bucket: usize,
    /// Shamir shares of each bit `v_j in {0, 1}` of transfer amount `v = sum_j 2^j v_j`.
    pub v_bits: Vec<Vec<u128>>,
    /// Shamir shares of each bit `r_j in {0, 1}` of remainder `r = B_sender - v`.
    pub r_bits: Vec<Vec<u128>>,
    /// Shamir shares of one-hot recipient selector `s_k in {0, 1}`, `sum_k s_k = 1`.
    pub selector_shares: Vec<Vec<u128>>,
}

impl ConfidentialTransferRequest {
    /// Build a valid confidential transfer request from `sender` (with known `sender_balance`)
    /// sending `amount` to `(recipient_bucket, recipient_slot)`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender: usize,
        sender_balance: u128,
        recipient_bucket: usize,
        recipient_slot: usize,
        amount: u128,
        bucket_size: usize,
        bit_width: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcError> {
        if bit_width == 0 || bit_width > 64 || bucket_size == 0 {
            return Err(MpcError::InvalidParameters(
                "require 1 <= bit_width <= 64 and bucket_size >= 1",
            ));
        }
        if recipient_slot >= bucket_size {
            return Err(MpcError::InvalidParameters("recipient_slot >= bucket_size"));
        }
        let max_val = if bit_width == 64 {
            u64::MAX as u128
        } else {
            (1u128 << bit_width) - 1
        };
        if amount > max_val || sender_balance < amount || (sender_balance - amount) > max_val {
            return Err(MpcError::InvalidParameters(
                "amount or remainder outside [0, 2^bit_width)",
            ));
        }

        let remainder = sender_balance - amount;
        let mut v_bits = Vec::with_capacity(bit_width);
        let mut r_bits = Vec::with_capacity(bit_width);
        for j in 0..bit_width {
            let vb = (amount >> j) & 1;
            let rb = (remainder >> j) & 1;
            v_bits.push(split_secret(vb, threshold, num_validators)?);
            r_bits.push(split_secret(rb, threshold, num_validators)?);
        }

        let mut selector_shares = Vec::with_capacity(bucket_size);
        for k in 0..bucket_size {
            let sk = if k == recipient_slot { 1u128 } else { 0u128 };
            selector_shares.push(split_secret(sk, threshold, num_validators)?);
        }

        Ok(Self {
            sender,
            recipient_bucket,
            v_bits,
            r_bits,
            selector_shares,
        })
    }

    /// Construct an indistinguishable valid `amount = 0` dummy transfer for a sender-anonymous
    /// lockstep bucket round, targeting a uniformly random slot inside `bucket_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_dummy(
        sender: usize,
        sender_balance: u128,
        bucket_id: usize,
        bucket_size: usize,
        bit_width: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcError> {
        if bucket_size == 0 {
            return Err(MpcError::InvalidParameters("bucket_size must be >= 1"));
        }
        let mut raw = [0u8; 8];
        fill_os_random(&mut raw);
        let dummy_slot = (u64::from_le_bytes(raw) as usize) % bucket_size;
        zeroize_slice(&mut raw);

        Self::new(
            sender,
            sender_balance,
            bucket_id,
            dummy_slot,
            0,
            bucket_size,
            bit_width,
            threshold,
            num_validators,
        )
    }

    /// Construct a transfer request directly from pre-built share vectors (useful for custom
    /// distributed clients and adversarial validation tests).
    pub fn new_raw(
        sender: usize,
        recipient_bucket: usize,
        v_bits: Vec<Vec<u128>>,
        r_bits: Vec<Vec<u128>>,
        selector_shares: Vec<Vec<u128>>,
    ) -> Self {
        Self {
            sender,
            recipient_bucket,
            v_bits,
            r_bits,
            selector_shares,
        }
    }
}

impl Drop for ConfidentialTransferRequest {
    fn drop(&mut self) {
        for shares in &mut self.v_bits {
            zeroize_u128_slice(shares);
        }
        for shares in &mut self.r_bits {
            zeroize_u128_slice(shares);
        }
        for shares in &mut self.selector_shares {
            zeroize_u128_slice(shares);
        }
    }
}

/// A fixed-size anonymity bucket storing Shamir-shared liquid balances for `bucket_size` accounts.
#[derive(Debug)]
struct AnonymityBucket {
    balances: Vec<Vec<u128>>,
}

impl Drop for AnonymityBucket {
    fn drop(&mut self) {
        for shares in &mut self.balances {
            zeroize_u128_slice(shares);
        }
    }
}

/// Verified, not-yet-committed transfer delta produced during atomic MPC validation.
struct VerifiedTransferDelta {
    sender_bucket: usize,
    sender_slot: usize,
    recipient_bucket: usize,
    debit_shares: Vec<u128>,
    credit_shares: Vec<Vec<u128>>,
}

impl Drop for VerifiedTransferDelta {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.debit_shares);
        for credit in &mut self.credit_shares {
            zeroize_u128_slice(credit);
        }
    }
}

/// Sharded IT-MPC private ledger with fixed-size anonymity buckets.
///
/// Accounts are partitioned into buckets of size `K = bucket_size` so every confidential transfer
/// performs `O(K) = O(1)` blinded updates instead of `O(total_users)`.
#[derive(Debug)]
pub struct ShardedPrivateLedger {
    cache: LagrangeCache,
    bucket_size: usize,
    bit_width: usize,
    epoch: u64,
    buckets: Vec<AnonymityBucket>,
}

impl ShardedPrivateLedger {
    /// Create a new sharded private ledger with `num_buckets` anonymity buckets of size
    /// `bucket_size`, `bit_width`-bit confidential range proofs, and `(threshold, num_validators)`
    /// Shamir secret sharing. All accounts start with fresh secret-shared `0` balances.
    pub fn new(
        num_buckets: usize,
        bucket_size: usize,
        bit_width: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcError> {
        if num_buckets == 0 || bucket_size == 0 || bit_width == 0 || bit_width > 64 {
            return Err(MpcError::InvalidParameters(
                "require num_buckets >= 1, bucket_size >= 1, 1 <= bit_width <= 64",
            ));
        }
        let cache = LagrangeCache::new(threshold, num_validators)?;
        let mut buckets = Vec::with_capacity(num_buckets);
        for _ in 0..num_buckets {
            let mut balances = Vec::with_capacity(bucket_size);
            for _ in 0..bucket_size {
                balances.push(split_secret(0, threshold, num_validators)?);
            }
            buckets.push(AnonymityBucket { balances });
        }

        Ok(Self {
            cache,
            bucket_size,
            bit_width,
            epoch: 1,
            buckets,
        })
    }

    /// Create a ledger with default Vernam parameters: `(3, 4)` committee, `bucket_size = 16`,
    /// `bit_width = 16`.
    pub fn new_default(num_buckets: usize) -> Result<Self, MpcError> {
        Self::new(
            num_buckets,
            DEFAULT_BUCKET_SIZE,
            DEFAULT_RANGE_BITS,
            DEFAULT_THRESHOLD,
            DEFAULT_NUM_VALIDATORS,
        )
    }

    /// Current proactive secret sharing epoch (starts at `1`).
    #[inline]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Fixed size `K` of each anonymity bucket.
    #[inline]
    pub fn bucket_size(&self) -> usize {
        self.bucket_size
    }

    /// Bit width `W` used for confidential range proofs (`0 <= v < 2^W`).
    #[inline]
    pub fn bit_width(&self) -> usize {
        self.bit_width
    }

    /// Number of anonymity buckets in the ledger.
    #[inline]
    pub fn num_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Total number of accounts (`num_buckets * bucket_size`).
    #[inline]
    pub fn total_accounts(&self) -> usize {
        self.buckets.len() * self.bucket_size
    }

    /// Reference to the precomputed [`LagrangeCache`].
    #[inline]
    pub fn cache(&self) -> &LagrangeCache {
        &self.cache
    }

    /// Number of Beaver triples consumed by a single confidential transfer (`2*W + 2*K`).
    #[inline]
    pub fn triples_per_transfer(&self) -> usize {
        2 * self.bit_width + 2 * self.bucket_size
    }

    /// Map a global `account_id` to `(bucket_id, slot_in_bucket)`.
    #[inline]
    pub fn account_location(&self, account_id: usize) -> Result<(usize, usize), MpcError> {
        let bucket_id = account_id / self.bucket_size;
        let slot = account_id % self.bucket_size;
        if bucket_id >= self.buckets.len() {
            return Err(MpcError::InvalidAccount { account_id });
        }
        Ok((bucket_id, slot))
    }

    /// Map `(bucket_id, slot_in_bucket)` to a global `account_id`.
    #[inline]
    pub fn account_id(&self, bucket_id: usize, slot: usize) -> Result<usize, MpcError> {
        if bucket_id >= self.buckets.len() {
            return Err(MpcError::InvalidBucket { bucket_id });
        }
        if slot >= self.bucket_size {
            return Err(MpcError::InvalidParameters("slot >= bucket_size"));
        }
        Ok(bucket_id * self.bucket_size + slot)
    }

    /// Mint/credit an initial liquid balance into `account_id` using fresh Shamir shares.
    pub fn mint_initial_balance(
        &mut self,
        account_id: usize,
        amount: u128,
    ) -> Result<(), MpcError> {
        let max_val = if self.bit_width == 64 {
            u64::MAX as u128
        } else {
            (1u128 << self.bit_width) - 1
        };
        if amount > max_val {
            return Err(MpcError::InvalidParameters(
                "mint amount exceeds 2^bit_width - 1",
            ));
        }
        let (bucket_id, slot) = self.account_location(account_id)?;
        let mut delta = split_secret(
            amount,
            self.cache.threshold(),
            self.cache.num_validators(),
        )?;
        let bal = &mut self.buckets[bucket_id].balances[slot];
        for (b, &d) in bal.iter_mut().zip(delta.iter()) {
            *b = add_mod(*b, d);
        }
        zeroize_u128_slice(&mut delta);
        Ok(())
    }

    /// Read-only view of validator shares for `account_id`.
    pub fn balance_shares(&self, account_id: usize) -> Result<&[u128], MpcError> {
        let (bucket_id, slot) = self.account_location(account_id)?;
        Ok(&self.buckets[bucket_id].balances[slot])
    }

    /// Read-only view of all `bucket_size` balance share vectors inside `bucket_id`.
    pub fn bucket_shares(&self, bucket_id: usize) -> Result<&[Vec<u128>], MpcError> {
        self.buckets
            .get(bucket_id)
            .map(|b| b.balances.as_slice())
            .ok_or(MpcError::InvalidBucket { bucket_id })
    }

    /// Reconstruct and verify `account_id`'s balance (for auditing/testing only).
    pub fn reconstruct_balance(&self, account_id: usize) -> Result<u128, MpcError> {
        let shares = self.balance_shares(account_id)?;
        self.cache.reconstruct_and_verify(shares)
    }

    /// Verify a single bit-share vector `b` satisfies `b * (b - 1) == 0` in MPC without
    /// revealing `b`.
    fn verify_bit_share(
        &self,
        bit_shares: &[u128],
        pool: &mut BeaverPool,
        fail_err: MpcError,
    ) -> Result<(), MpcError> {
        let mut bit_minus_one = mpc_sub_const(bit_shares, 1);
        let triple = pool.pop()?;
        let prod_res = mpc_mul(bit_shares, &bit_minus_one, triple, &self.cache);
        zeroize_u128_slice(&mut bit_minus_one);
        let mut prod = prod_res?;
        let opened = self.cache.reconstruct_and_verify(&prod);
        zeroize_u128_slice(&mut prod);
        let val = opened?;
        if val != 0 {
            return Err(fail_err);
        }
        Ok(())
    }

    /// Recompose `[x] = sum_{j=0}^{W-1} 2^j * [bit_j]` locally from bit shares.
    fn compose_bits(&self, bits: &[Vec<u128>]) -> Vec<u128> {
        let n = self.cache.num_validators();
        let mut acc = vec![0u128; n];
        for (j, bit_shares) in bits.iter().enumerate() {
            let weight = 1u128 << j;
            for (dst, &b) in acc.iter_mut().zip(bit_shares.iter()) {
                *dst = add_mod(*dst, mul_mod(b, weight));
            }
        }
        acc
    }

    /// Validate a confidential transfer against `sender_balance_shares` and compute the blinded
    /// debit `[v]` and `bucket_size` blinded credits `[s_k * v]` without mutating ledger state.
    fn verify_and_prepare_transfer(
        &self,
        req: &ConfidentialTransferRequest,
        sender_balance_shares: &[u128],
        pool: &mut BeaverPool,
    ) -> Result<VerifiedTransferDelta, MpcError> {
        let (sender_bucket, sender_slot) = self.account_location(req.sender)?;
        if req.recipient_bucket >= self.buckets.len() {
            return Err(MpcError::InvalidBucket {
                bucket_id: req.recipient_bucket,
            });
        }
        if req.v_bits.len() != self.bit_width || req.r_bits.len() != self.bit_width {
            return Err(MpcError::InvalidParameters(
                "bit decomposition length does not match ledger bit_width",
            ));
        }
        if req.selector_shares.len() != self.bucket_size {
            return Err(MpcError::InvalidParameters(
                "selector length does not match ledger bucket_size",
            ));
        }

        // 1. Confidential range proof on amount v: every v_j in {0, 1}.
        for bit_shares in &req.v_bits {
            self.verify_bit_share(bit_shares, pool, MpcError::RangeProofFailed)?;
        }

        // 2. Confidential range proof on remainder r = B_sender - v: every r_j in {0, 1}.
        for bit_shares in &req.r_bits {
            self.verify_bit_share(bit_shares, pool, MpcError::RangeProofFailed)?;
        }

        // 3. Recompose [v] and [r] linearly and enforce B_sender - v - r == 0.
        let v_shares = self.compose_bits(&req.v_bits);
        let mut r_shares = self.compose_bits(&req.r_bits);
        let mut diff = mpc_sub(sender_balance_shares, &v_shares)?;
        let mut eq_check = mpc_sub(&diff, &r_shares)?;
        let opened_eq = self.cache.reconstruct_and_verify(&eq_check);
        zeroize_u128_slice(&mut r_shares);
        zeroize_u128_slice(&mut diff);
        zeroize_u128_slice(&mut eq_check);
        if opened_eq? != 0 {
            return Err(MpcError::BalanceCheckFailed);
        }

        // 4. Blinded one-hot recipient selector check: s_k in {0, 1} and sum(s_k) == 1.
        let n = self.cache.num_validators();
        let mut sum_s = vec![0u128; n];
        for s_k in &req.selector_shares {
            self.verify_bit_share(s_k, pool, MpcError::SelectorCheckFailed)?;
            for (acc, &share) in sum_s.iter_mut().zip(s_k.iter()) {
                *acc = add_mod(*acc, share);
            }
        }
        let opened_sum = self.cache.reconstruct_and_verify(&sum_s);
        zeroize_u128_slice(&mut sum_s);
        if opened_sum? != 1 {
            return Err(MpcError::SelectorCheckFailed);
        }

        // 5. Blinded credit [s_k * v] for EVERY member k in recipient_bucket (O(bucket_size)).
        // Because each Beaver triple carries fresh random polynomial masks, even non-recipients
        // (s_k = 0) receive a fresh random Shamir sharing of 0, re-randomizing every share in
        // the bucket so no coalition of < t validators can identify the recipient.
        let mut credit_shares = Vec::with_capacity(self.bucket_size);
        for s_k in &req.selector_shares {
            let triple = pool.pop()?;
            credit_shares.push(mpc_mul(s_k, &v_shares, triple, &self.cache)?);
        }

        Ok(VerifiedTransferDelta {
            sender_bucket,
            sender_slot,
            recipient_bucket: req.recipient_bucket,
            debit_shares: v_shares,
            credit_shares,
        })
    }

    /// Execute a single sharded confidential transfer in `O(bucket_size) = O(1)` MPC operations.
    ///
    /// Atomically verifies the range proofs, balance equation, and one-hot recipient selector
    /// before mutating any balance shares. Updates EVERY account's share in `recipient_bucket`.
    pub fn execute_sharded_transfer(
        &mut self,
        req: &ConfidentialTransferRequest,
        pool: &mut BeaverPool,
    ) -> Result<(), MpcError> {
        let needed = self.triples_per_transfer();
        if pool.len() < needed {
            return Err(MpcError::BeaverPoolExhausted {
                needed,
                available: pool.len(),
            });
        }
        let (sender_bucket, sender_slot) = self.account_location(req.sender)?;
        let delta = self.verify_and_prepare_transfer(
            req,
            &self.buckets[sender_bucket].balances[sender_slot],
            pool,
        )?;

        // Atomic commit: apply debit to sender and blinded credits to all bucket members.
        let sender_bal = &mut self.buckets[delta.sender_bucket].balances[delta.sender_slot];
        for (b, &d) in sender_bal.iter_mut().zip(delta.debit_shares.iter()) {
            *b = sub_mod(*b, d);
        }
        let target_bucket = &mut self.buckets[delta.recipient_bucket];
        for (bal, credit) in target_bucket
            .balances
            .iter_mut()
            .zip(delta.credit_shares.iter())
        {
            for (b, &c) in bal.iter_mut().zip(credit.iter()) {
                *b = add_mod(*b, c);
            }
        }
        Ok(())
    }

    /// Execute a sender-anonymous lockstep batch round over `bucket_id`.
    ///
    /// Every account `slot in 0..bucket_size` inside `bucket_id` MUST submit exactly one
    /// [`ConfidentialTransferRequest`] targeting `bucket_id`—either a real transfer or an
    /// indistinguishable valid `amount = 0` dummy transfer ([`ConfidentialTransferRequest::new_dummy`]).
    ///
    /// All requests are verified simultaneously against the pre-round balance snapshot so
    /// concurrent senders/recipients never interfere, and if any request fails validation the
    /// entire round aborts atomically with zero balance changes. Because every member participates
    /// with identically shaped proofs and uniform Beaver openings, even which account sent coins
    /// is information-theoretically hidden from any coalition of `< threshold` validators.
    pub fn execute_anonymous_bucket_round(
        &mut self,
        bucket_id: usize,
        requests: &[ConfidentialTransferRequest],
        pool: &mut BeaverPool,
    ) -> Result<(), MpcError> {
        if bucket_id >= self.buckets.len() {
            return Err(MpcError::InvalidBucket { bucket_id });
        }
        if requests.len() != self.bucket_size {
            return Err(MpcError::InvalidBatchRound(
                "lockstep round requires exactly bucket_size requests",
            ));
        }

        // Verify every slot in `bucket_id` is represented exactly once and targets `bucket_id`.
        let mut seen = vec![false; self.bucket_size];
        for req in requests {
            let (req_bucket, req_slot) = self.account_location(req.sender)?;
            if req_bucket != bucket_id {
                return Err(MpcError::InvalidBatchRound(
                    "all senders in a lockstep round must belong to bucket_id",
                ));
            }
            if req.recipient_bucket != bucket_id {
                return Err(MpcError::InvalidBatchRound(
                    "all requests in a lockstep round must target bucket_id",
                ));
            }
            if seen[req_slot] {
                return Err(MpcError::InvalidBatchRound(
                    "duplicate sender slot in lockstep bucket round",
                ));
            }
            seen[req_slot] = true;
        }

        let needed = self.bucket_size * self.triples_per_transfer();
        if pool.len() < needed {
            return Err(MpcError::BeaverPoolExhausted {
                needed,
                available: pool.len(),
            });
        }

        // Verify all requests against pre-round balance snapshot before mutating any state.
        let mut deltas = Vec::with_capacity(self.bucket_size);
        for req in requests {
            let (_, slot) = self.account_location(req.sender)?;
            let delta = self.verify_and_prepare_transfer(
                req,
                &self.buckets[bucket_id].balances[slot],
                pool,
            )?;
            deltas.push(delta);
        }

        // Atomic commit of the entire lockstep round.
        let bucket = &mut self.buckets[bucket_id];
        for delta in &deltas {
            let sender_bal = &mut bucket.balances[delta.sender_slot];
            for (b, &d) in sender_bal.iter_mut().zip(delta.debit_shares.iter()) {
                *b = sub_mod(*b, d);
            }
            for (bal, credit) in bucket.balances.iter_mut().zip(delta.credit_shares.iter()) {
                for (b, &c) in bal.iter_mut().zip(credit.iter()) {
                    *b = add_mod(*b, c);
                }
            }
        }
        Ok(())
    }

    /// Run a Proactive Secret Sharing epoch refresh over every account in every anonymity bucket.
    ///
    /// Refreshes all liquid balance shares using zero-constant polynomials (`z_j(0) = 0`) over
    /// pairwise OTP-masked deltas, preserving exact balances while invalidating all shares from
    /// previous epochs. Returns the incremented epoch number.
    pub fn proactive_refresh_epoch(&mut self) -> Result<u64, MpcError> {
        let t = self.cache.threshold();
        let n = self.cache.num_validators();
        for bucket in &mut self.buckets {
            proactive_refresh_epoch_batch(&mut bucket.balances, t, n)?;
        }
        self.epoch += 1;
        Ok(self.epoch)
    }
}

// ============================================================================
// 5. Constant-Rate Cover Traffic (`CoverFrame` & `CoverTrafficGenerator`)
// ============================================================================

/// Compute an information-theoretically secure 128-bit Carter-Wegman universal MAC over
/// `body` using one-time evaluation point `mac_r` and additive pad `mac_s` in `F_(2^127 - 1)`.
fn compute_carter_wegman_tag(
    body: &[u8; COVER_FRAME_BODY_SIZE],
    mac_r: u128,
    mac_s: u128,
) -> [u8; COVER_FRAME_TAG_SIZE] {
    let mut acc = 0u128;
    // 240 / 15 = 16 chunks of 120 bits each (< 2^127 - 1, strictly injective in F_p).
    for chunk in body.chunks_exact(15) {
        let mut buf = [0u8; 16];
        buf[..15].copy_from_slice(chunk);
        let elem = u128::from_le_bytes(buf);
        acc = mul_mod(add_mod(acc, elem), mac_r);
    }
    add_mod(acc, mac_s).to_le_bytes()
}

/// Single-use OTP encryption pad + Carter-Wegman universal MAC key for one [`CoverFrame`].
///
/// Intentionally non-`Clone` to prevent accidental one-time pad reuse; zeroized on `Drop`.
#[derive(Debug)]
pub struct CoverFrameKey {
    otp_pad: [u8; COVER_FRAME_BODY_SIZE],
    mac_r: u128,
    mac_s: u128,
}

impl CoverFrameKey {
    /// Generate a matched pair of single-use keys `(sender_key, receiver_key)` from OS entropy.
    pub fn generate_pair() -> (Self, Self) {
        let mut otp_pad = [0u8; COVER_FRAME_BODY_SIZE];
        fill_os_random(&mut otp_pad);
        let mut mac_elems = [0u128; 2];
        fill_random_field_elems(&mut mac_elems);
        let mac_r = mac_elems[0];
        let mac_s = mac_elems[1];
        zeroize_u128_slice(&mut mac_elems);

        let sender = Self {
            otp_pad,
            mac_r,
            mac_s,
        };
        let receiver = Self {
            otp_pad,
            mac_r,
            mac_s,
        };
        zeroize_slice(&mut otp_pad);
        (sender, receiver)
    }
}

impl Drop for CoverFrameKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.otp_pad);
        zeroize_u128(&mut self.mac_r);
        zeroize_u128(&mut self.mac_s);
    }
}

/// Fixed-size (`256`-byte) OTP-encrypted and Carter-Wegman-authenticated network frame.
///
/// Real payload frames and dummy cover frames share the exact same byte length and uniform
/// ciphertext/tag distribution, preventing traffic-size and timing correlation analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverFrame {
    bytes: [u8; COVER_FRAME_SIZE],
}

impl CoverFrame {
    /// Seal a real payload (`<= MAX_COVER_PAYLOAD_LEN` bytes) into a fixed-size [`CoverFrame`],
    /// consuming and zeroizing the one-time [`CoverFrameKey`].
    pub fn seal_real(payload: &[u8], key: CoverFrameKey) -> Result<Self, MpcError> {
        if payload.len() > MAX_COVER_PAYLOAD_LEN {
            return Err(MpcError::InvalidCoverFrame(
                "payload exceeds MAX_COVER_PAYLOAD_LEN",
            ));
        }

        let mut plain = [0u8; COVER_FRAME_BODY_SIZE];
        fill_os_random(&mut plain);
        plain[0] = FRAME_KIND_REAL;
        let len_bytes = (payload.len() as u16).to_le_bytes();
        plain[1] = len_bytes[0];
        plain[2] = len_bytes[1];
        plain[3..3 + payload.len()].copy_from_slice(payload);

        let frame = Self::encrypt_body(&plain, &key);
        zeroize_slice(&mut plain);
        // `key` is dropped and zeroized here.
        Ok(frame)
    }

    /// Seal an indistinguishable dummy cover frame, consuming and zeroizing `key`.
    pub fn seal_dummy(key: CoverFrameKey) -> Self {
        let mut plain = [0u8; COVER_FRAME_BODY_SIZE];
        fill_os_random(&mut plain);
        plain[0] = FRAME_KIND_DUMMY;
        plain[1] = 0;
        plain[2] = 0;

        let frame = Self::encrypt_body(&plain, &key);
        zeroize_slice(&mut plain);
        frame
    }

    /// Generate an unkeyed OS-random fixed-size dummy frame whose ciphertext and tag bytes match
    /// the exact uniform distribution of sealed frames.
    pub fn random_dummy() -> Self {
        let mut bytes = [0u8; COVER_FRAME_SIZE];
        fill_os_random(&mut bytes[..COVER_FRAME_BODY_SIZE]);
        let tag = random_field_elem().to_le_bytes();
        bytes[COVER_FRAME_BODY_SIZE..].copy_from_slice(&tag);
        Self { bytes }
    }

    fn encrypt_body(plain: &[u8; COVER_FRAME_BODY_SIZE], key: &CoverFrameKey) -> Self {
        let mut body = [0u8; COVER_FRAME_BODY_SIZE];
        for i in 0..COVER_FRAME_BODY_SIZE {
            body[i] = plain[i] ^ key.otp_pad[i];
        }
        let tag = compute_carter_wegman_tag(&body, key.mac_r, key.mac_s);

        let mut bytes = [0u8; COVER_FRAME_SIZE];
        bytes[..COVER_FRAME_BODY_SIZE].copy_from_slice(&body);
        bytes[COVER_FRAME_BODY_SIZE..].copy_from_slice(&tag);
        Self { bytes }
    }

    /// Verify the Carter-Wegman MAC in constant time (`ct_eq_16`) and decrypt the frame,
    /// consuming and zeroizing `key`.
    ///
    /// Returns `Ok(Some(payload))` for real frames and `Ok(None)` for dummy cover frames.
    pub fn unseal(&self, key: CoverFrameKey) -> Result<Option<Vec<u8>>, MpcError> {
        let mut body = [0u8; COVER_FRAME_BODY_SIZE];
        body.copy_from_slice(&self.bytes[..COVER_FRAME_BODY_SIZE]);

        let mut provided_tag = [0u8; COVER_FRAME_TAG_SIZE];
        provided_tag.copy_from_slice(&self.bytes[COVER_FRAME_BODY_SIZE..]);
        let expected_tag = compute_carter_wegman_tag(&body, key.mac_r, key.mac_s);

        if !ct_eq_16(&provided_tag, &expected_tag) {
            return Err(MpcError::InvalidCoverFrame("Carter-Wegman MAC mismatch"));
        }

        let mut plain = [0u8; COVER_FRAME_BODY_SIZE];
        for i in 0..COVER_FRAME_BODY_SIZE {
            plain[i] = body[i] ^ key.otp_pad[i];
        }

        let result = match plain[0] {
            FRAME_KIND_DUMMY => Ok(None),
            FRAME_KIND_REAL => {
                let len = u16::from_le_bytes([plain[1], plain[2]]) as usize;
                if len > MAX_COVER_PAYLOAD_LEN {
                    Err(MpcError::InvalidCoverFrame("decoded payload length invalid"))
                } else {
                    Ok(Some(plain[3..3 + len].to_vec()))
                }
            }
            _ => Err(MpcError::InvalidCoverFrame("unknown frame kind tag")),
        };

        zeroize_slice(&mut plain);
        // `key` is dropped and zeroized here.
        result
    }

    /// Wire representation of this fixed-size cover frame.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; COVER_FRAME_SIZE] {
        &self.bytes
    }

    /// Mutable wire representation (for transport framing or tamper testing).
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; COVER_FRAME_SIZE] {
        &mut self.bytes
    }

    /// Reconstruct a [`CoverFrame`] from raw wire bytes.
    #[inline]
    pub fn from_bytes(bytes: [u8; COVER_FRAME_SIZE]) -> Self {
        Self { bytes }
    }
}

/// Constant-rate cover traffic emitter producing exactly one fixed-size [`CoverFrame`] per tick.
#[derive(Debug, Clone)]
pub struct CoverTrafficGenerator {
    interval_ms: u64,
    total_frames: u64,
    real_frames: u64,
    dummy_frames: u64,
}

impl CoverTrafficGenerator {
    /// Create a constant-rate generator configured for `interval_ms` milliseconds between frames.
    pub fn new(interval_ms: u64) -> Self {
        Self {
            interval_ms,
            total_frames: 0,
            real_frames: 0,
            dummy_frames: 0,
        }
    }

    /// Emit the next constant-rate frame: seals `pending_payload` if `Some`, otherwise emits an
    /// indistinguishable dummy frame using `key`.
    pub fn emit_tick(
        &mut self,
        pending_payload: Option<&[u8]>,
        key: CoverFrameKey,
    ) -> Result<CoverFrame, MpcError> {
        let frame = match pending_payload {
            Some(payload) => {
                let f = CoverFrame::seal_real(payload, key)?;
                self.real_frames += 1;
                f
            }
            None => {
                self.dummy_frames += 1;
                CoverFrame::seal_dummy(key)
            }
        };
        self.total_frames += 1;
        Ok(frame)
    }

    /// Emit an unkeyed OS-random dummy cover frame for link-level decoy padding.
    pub fn emit_random_dummy_tick(&mut self) -> CoverFrame {
        self.dummy_frames += 1;
        self.total_frames += 1;
        CoverFrame::random_dummy()
    }

    /// Configured constant emission interval in milliseconds.
    #[inline]
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// Total frames emitted (real + dummy).
    #[inline]
    pub fn total_frames(&self) -> u64 {
        self.total_frames
    }

    /// Number of real payload frames emitted.
    #[inline]
    pub fn real_frames(&self) -> u64 {
        self.real_frames
    }

    /// Number of dummy cover frames emitted.
    #[inline]
    pub fn dummy_frames(&self) -> u64 {
        self.dummy_frames
    }
}

// ============================================================================
// 6. Comprehensive Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructively prove that 2 colluding validators `(x=1, y1)` and `(x=2, y2)` in a `(3, 4)`
    /// scheme are consistent with ANY candidate secret `candidate_secret in F_p`.
    fn assert_consistent_with_any_secret(y1: u128, y2: u128, candidate_secret: u128) {
        // Solve P(x) = s + a1*x + a2*x^2 with P(0) = s, P(1) = y1, P(2) = y2:
        //   a1 + a2 = y1 - s
        //   2*a1 + 4*a2 = y2 - s
        // => 2*a2 = (y2 - s) - 2*(y1 - s)
        let d1 = sub_mod(y1, candidate_secret);
        let d2 = sub_mod(y2, candidate_secret);
        let inv2 = inv_mod(2);
        let a2 = mul_mod(sub_mod(d2, mul_mod(2, d1)), inv2);
        let a1 = sub_mod(d1, a2);

        // Verify P(1) == y1 and P(2) == y2 identically.
        let p1 = add_mod(candidate_secret, add_mod(a1, a2));
        let p2 = add_mod(
            candidate_secret,
            add_mod(mul_mod(2, a1), mul_mod(4, a2)),
        );
        assert_eq!(p1, y1);
        assert_eq!(p2, y2);
    }

    #[test]
    fn test_lagrange_cache_reconstruct_and_tamper_detection() {
        let cache = LagrangeCache::new_3_of_4();

        // Known (3, 4) Lagrange basis at x=0: [3, P-3, 1].
        assert_eq!(cache.origin_coeffs(), &[3, PRIME_P - 3, 1]);

        for &secret in &[0u128, 1, 42, 65_535, PRIME_P - 1, random_field_elem()] {
            let shares = split_secret(secret, 3, 4).unwrap();
            assert_eq!(cache.reconstruct_and_verify(&shares).unwrap(), secret);

            // Tampering ANY single validator's share (0, 1, 2, or 3) MUST be caught.
            for victim in 0..4 {
                let mut tampered = shares.clone();
                tampered[victim] = add_mod(tampered[victim], 1);
                assert_eq!(
                    cache.reconstruct_and_verify(&tampered),
                    Err(MpcError::InconsistentShares),
                    "tampering validator {victim} was not detected"
                );
            }
        }

        // Also test a larger committee (4, 7) with 3 redundant checks.
        let cache_4_7 = LagrangeCache::new(4, 7).unwrap();
        let secret = random_field_elem();
        let shares = split_secret(secret, 4, 7).unwrap();
        assert_eq!(cache_4_7.reconstruct_and_verify(&shares).unwrap(), secret);
        for victim in 0..7 {
            let mut tampered = shares.clone();
            tampered[victim] = sub_mod(tampered[victim], 7);
            assert_eq!(
                cache_4_7.reconstruct_and_verify(&tampered),
                Err(MpcError::InconsistentShares)
            );
        }
    }

    #[test]
    fn test_beaver_pool_single_use_and_mpc_mul() {
        let cache = LagrangeCache::new_3_of_4();
        let mut pool = BeaverPool::new_3_of_4(4);
        assert_eq!(pool.len(), 4);

        for &(x, y) in &[(0u128, 99), (1, 1), (12_345, 54_321), (PRIME_P - 1, 7)] {
            let xs = split_secret(x, 3, 4).unwrap();
            let ys = split_secret(y, 3, 4).unwrap();
            let triple = pool.pop().unwrap();
            let zs = mpc_mul(&xs, &ys, triple, &cache).unwrap();
            assert_eq!(cache.reconstruct_and_verify(&zs).unwrap(), mul_mod(x, y));
        }

        assert!(pool.is_empty());
        assert_eq!(
            pool.pop().unwrap_err(),
            MpcError::BeaverPoolExhausted {
                needed: 1,
                available: 0
            }
        );
    }

    #[test]
    fn test_sharded_transfer_hides_balances_amount_recipient_and_updates_every_member() {
        // 2 buckets of 16 accounts = 32 users; transfer only touches 1 bucket (O(16)).
        let mut ledger = ShardedPrivateLedger::new_default(2).unwrap();
        let mut pool = BeaverPool::new_3_of_4(ledger.triples_per_transfer() * 2);

        let sender = ledger.account_id(0, 2).unwrap();
        let recipient_bucket = 0;
        let recipient_slot = 11;
        let recipient = ledger.account_id(recipient_bucket, recipient_slot).unwrap();

        ledger.mint_initial_balance(sender, 1_000).unwrap();
        ledger.mint_initial_balance(recipient, 250).unwrap();
        // Give other bucket members non-zero balances too.
        for slot in 0..ledger.bucket_size() {
            let acc = ledger.account_id(0, slot).unwrap();
            if acc != sender && acc != recipient {
                ledger.mint_initial_balance(acc, (slot as u128 + 1) * 10).unwrap();
            }
        }

        // Snapshot all pre-transfer shares in bucket 0 and bucket 1.
        let before_bucket0: Vec<Vec<u128>> = ledger.bucket_shares(0).unwrap().to_vec();
        let before_bucket1: Vec<Vec<u128>> = ledger.bucket_shares(1).unwrap().to_vec();

        let req = ConfidentialTransferRequest::new(
            sender,
            1_000,
            recipient_bucket,
            recipient_slot,
            375,
            ledger.bucket_size(),
            ledger.bit_width(),
            3,
            4,
        )
        .unwrap();

        // Prove 2 colluding validators (IDs 1 & 2) learn ZERO information about:
        // (a) sender balance, (b) transfer amount bits, and (c) recipient selector bits.
        let sender_shares = ledger.balance_shares(sender).unwrap();
        for &fake in &[0u128, 1, 999_999, PRIME_P - 1] {
            assert_consistent_with_any_secret(sender_shares[0], sender_shares[1], fake);
        }
        for bit_shares in &req.v_bits {
            assert_consistent_with_any_secret(bit_shares[0], bit_shares[1], 0);
            assert_consistent_with_any_secret(bit_shares[0], bit_shares[1], 1);
        }
        for sel_shares in &req.selector_shares {
            assert_consistent_with_any_secret(sel_shares[0], sel_shares[1], 0);
            assert_consistent_with_any_secret(sel_shares[0], sel_shares[1], 1);
        }

        ledger.execute_sharded_transfer(&req, &mut pool).unwrap();

        // Exact post-transfer balances.
        assert_eq!(ledger.reconstruct_balance(sender).unwrap(), 625);
        assert_eq!(ledger.reconstruct_balance(recipient).unwrap(), 625);
        for slot in 0..ledger.bucket_size() {
            let acc = ledger.account_id(0, slot).unwrap();
            if acc != sender && acc != recipient {
                assert_eq!(
                    ledger.reconstruct_balance(acc).unwrap(),
                    (slot as u128 + 1) * 10
                );
            }
        }

        // EVERY member's share in bucket 0 MUST have changed (hiding which slot received coins).
        let after_bucket0 = ledger.bucket_shares(0).unwrap();
        for slot in 0..ledger.bucket_size() {
            assert_ne!(
                before_bucket0[slot], after_bucket0[slot],
                "bucket 0 slot {slot} shares did not change"
            );
            for validator in 0..4 {
                assert_ne!(
                    before_bucket0[slot][validator], after_bucket0[slot][validator],
                    "validator {validator} share for slot {slot} did not change"
                );
            }
        }

        // Sharding O(bucket_size) property: bucket 1 was completely untouched!
        assert_eq!(before_bucket1, ledger.bucket_shares(1).unwrap());
    }

    #[test]
    fn test_blocks_overdraft_negative_minting_and_double_recipient_inflation() {
        let mut ledger = ShardedPrivateLedger::new_default(1).unwrap();
        let mut pool = BeaverPool::new_3_of_4(ledger.triples_per_transfer() * 6);

        let sender = 0;
        let bal = 500u128;
        ledger.mint_initial_balance(sender, bal).unwrap();
        ledger.mint_initial_balance(1, 100).unwrap();
        ledger.mint_initial_balance(2, 200).unwrap();

        let bit_width = ledger.bit_width();
        let bucket_size = ledger.bucket_size();
        let make_bits = |val: u128| -> Vec<Vec<u128>> {
            (0..bit_width)
                .map(|j| split_secret((val >> j) & 1, 3, 4).unwrap())
                .collect()
        };
        let make_one_hot = |target: usize| -> Vec<Vec<u128>> {
            (0..bucket_size)
                .map(|k| split_secret(u128::from(k == target), 3, 4).unwrap())
                .collect()
        };

        // Attack 1: Overdraft (attempt to spend B + 1 = 501 with r = 0).
        let overdraft_req = ConfidentialTransferRequest::new_raw(
            sender,
            0,
            make_bits(bal + 1),
            make_bits(0),
            make_one_hot(1),
        );
        assert_eq!(
            ledger.execute_sharded_transfer(&overdraft_req, &mut pool),
            Err(MpcError::BalanceCheckFailed)
        );
        assert_eq!(ledger.reconstruct_balance(sender).unwrap(), bal);
        assert_eq!(ledger.reconstruct_balance(1).unwrap(), 100);

        // Attack 2: Negative-amount minting (attempt to set v = PRIME_P - 1 via bit 0 = P - 1).
        let mut neg_v_bits = make_bits(0);
        neg_v_bits[0] = split_secret(PRIME_P - 1, 3, 4).unwrap();
        let neg_req = ConfidentialTransferRequest::new_raw(
            sender,
            0,
            neg_v_bits,
            make_bits(bal + 1),
            make_one_hot(1),
        );
        assert_eq!(
            ledger.execute_sharded_transfer(&neg_req, &mut pool),
            Err(MpcError::RangeProofFailed)
        );
        assert_eq!(ledger.reconstruct_balance(sender).unwrap(), bal);
        assert_eq!(ledger.reconstruct_balance(1).unwrap(), 100);

        // Attack 3: Double-recipient inflation (sum(s_k) = 2: both slot 1 and slot 2 set to 1).
        let mut double_sel = make_one_hot(1);
        double_sel[2] = split_secret(1, 3, 4).unwrap();
        let inflation_req = ConfidentialTransferRequest::new_raw(
            sender,
            0,
            make_bits(100),
            make_bits(bal - 100),
            double_sel,
        );
        assert_eq!(
            ledger.execute_sharded_transfer(&inflation_req, &mut pool),
            Err(MpcError::SelectorCheckFailed)
        );
        assert_eq!(ledger.reconstruct_balance(sender).unwrap(), bal);
        assert_eq!(ledger.reconstruct_balance(1).unwrap(), 100);
        assert_eq!(ledger.reconstruct_balance(2).unwrap(), 200);
    }

    #[test]
    fn test_sender_anonymous_lockstep_bucket_round() {
        let bucket_size = 16;
        let mut ledger = ShardedPrivateLedger::new(1, bucket_size, 16, 3, 4).unwrap();
        let mut pool = BeaverPool::new_3_of_4(bucket_size * ledger.triples_per_transfer());

        // Mint initial balances for all 16 accounts in bucket 0.
        let initial_balances: Vec<u128> = (0..bucket_size).map(|i| (i as u128 + 1) * 100).collect();
        for (slot, &bal) in initial_balances.iter().enumerate() {
            ledger.mint_initial_balance(slot, bal).unwrap();
        }
        let before_shares = ledger.bucket_shares(0).unwrap().to_vec();

        // Only slots 3 and 9 execute real transfers (3 -> 12 for 150, 9 -> 3 for 220);
        // every other slot submits an indistinguishable amount=0 dummy transfer in lockstep!
        let mut requests = Vec::with_capacity(bucket_size);
        for slot in 0..bucket_size {
            let req = match slot {
                3 => ConfidentialTransferRequest::new(
                    3,
                    initial_balances[3],
                    0,
                    12,
                    150,
                    bucket_size,
                    16,
                    3,
                    4,
                )
                .unwrap(),
                9 => ConfidentialTransferRequest::new(
                    9,
                    initial_balances[9],
                    0,
                    3,
                    220,
                    bucket_size,
                    16,
                    3,
                    4,
                )
                .unwrap(),
                _ => ConfidentialTransferRequest::new_dummy(
                    slot,
                    initial_balances[slot],
                    0,
                    bucket_size,
                    16,
                    3,
                    4,
                )
                .unwrap(),
            };
            requests.push(req);
        }

        // Verify structural & 2-validator indistinguishability between real (slot 3) and dummy (slot 4).
        assert_eq!(requests[3].v_bits.len(), requests[4].v_bits.len());
        assert_eq!(requests[3].r_bits.len(), requests[4].r_bits.len());
        assert_eq!(
            requests[3].selector_shares.len(),
            requests[4].selector_shares.len()
        );
        for j in 0..16 {
            assert_consistent_with_any_secret(requests[3].v_bits[j][0], requests[3].v_bits[j][1], 0);
            assert_consistent_with_any_secret(requests[4].v_bits[j][0], requests[4].v_bits[j][1], 1);
        }

        ledger
            .execute_anonymous_bucket_round(0, &requests, &mut pool)
            .unwrap();

        // Verify exact final balances and total supply conservation.
        let mut expected = initial_balances.clone();
        expected[3] = expected[3] - 150 + 220;
        expected[12] += 150;
        expected[9] -= 220;

        let initial_sum: u128 = initial_balances.iter().sum();
        let mut final_sum = 0u128;
        let after_shares = ledger.bucket_shares(0).unwrap();
        for slot in 0..bucket_size {
            let actual = ledger.reconstruct_balance(slot).unwrap();
            assert_eq!(actual, expected[slot], "mismatch at slot {slot}");
            final_sum += actual;
            // Every account's share changed in the lockstep round.
            assert_ne!(before_shares[slot], after_shares[slot]);
        }
        assert_eq!(initial_sum, final_sum);
    }

    #[test]
    fn test_proactive_secret_sharing_refresh_invalidates_stale_mixed_shares() {
        let mut ledger = ShardedPrivateLedger::new(2, 8, 16, 3, 4).unwrap();
        for acc in 0..ledger.total_accounts() {
            ledger
                .mint_initial_balance(acc, (acc as u128 + 1) * 77)
                .unwrap();
        }

        let epoch1_shares: Vec<Vec<u128>> = (0..ledger.total_accounts())
            .map(|acc| ledger.balance_shares(acc).unwrap().to_vec())
            .collect();
        assert_eq!(ledger.epoch(), 1);

        // Execute proactive refresh across the entire ledger.
        let new_epoch = ledger.proactive_refresh_epoch().unwrap();
        assert_eq!(new_epoch, 2);
        assert_eq!(ledger.epoch(), 2);

        let cache = ledger.cache();
        for acc in 0..ledger.total_accounts() {
            let expected_bal = (acc as u128 + 1) * 77;
            let epoch2_shares = ledger.balance_shares(acc).unwrap();

            // Exact balance is preserved in Epoch 2.
            assert_eq!(ledger.reconstruct_balance(acc).unwrap(), expected_bal);

            // Every validator's share changed across epochs.
            for v in 0..4 {
                assert_ne!(epoch1_shares[acc][v], epoch2_shares[v]);
            }

            // Mixing Epoch-1 and Epoch-2 shares MUST fail Lagrange consistency AND fail to
            // recover the true balance.
            let mixed_2_2 = [
                epoch1_shares[acc][0],
                epoch1_shares[acc][1],
                epoch2_shares[2],
                epoch2_shares[3],
            ];
            assert_eq!(
                cache.reconstruct_and_verify(&mixed_2_2),
                Err(MpcError::InconsistentShares)
            );
            assert_ne!(cache.reconstruct_fast_unchecked(&mixed_2_2[..3]), expected_bal);

            let mixed_1_3 = [
                epoch1_shares[acc][0],
                epoch2_shares[1],
                epoch2_shares[2],
                epoch2_shares[3],
            ];
            assert_eq!(
                cache.reconstruct_and_verify(&mixed_1_3),
                Err(MpcError::InconsistentShares)
            );
        }

        // Also verify standalone `proactive_refresh_epoch` on a single share vector.
        let secret = 123_456_789u128;
        let epoch1 = split_secret(secret, 3, 4).unwrap();
        let mut epoch2 = epoch1.clone();
        proactive_refresh_epoch(&mut epoch2, 3).unwrap();
        assert_eq!(cache.reconstruct_and_verify(&epoch2).unwrap(), secret);
        assert_eq!(
            cache.reconstruct_and_verify(&[epoch1[0], epoch1[1], epoch2[2], epoch2[3]]),
            Err(MpcError::InconsistentShares)
        );
    }

    #[test]
    fn test_constant_rate_cover_traffic_frames_and_mac_tamper_detection() {
        let mut traffic = CoverTrafficGenerator::new(100);
        let (k_real_tx, k_real_rx) = CoverFrameKey::generate_pair();
        let (k_dummy_tx, k_dummy_rx) = CoverFrameKey::generate_pair();

        let payload = b"vernam-it-mpc-settlement-frame";
        let real_frame = traffic.emit_tick(Some(payload), k_real_tx).unwrap();
        let dummy_frame = traffic.emit_tick(None, k_dummy_tx).unwrap();
        let decoy_frame = traffic.emit_random_dummy_tick();

        // Identical fixed wire size across real, keyed dummy, and unkeyed decoy frames.
        assert_eq!(real_frame.as_bytes().len(), COVER_FRAME_SIZE);
        assert_eq!(dummy_frame.as_bytes().len(), COVER_FRAME_SIZE);
        assert_eq!(decoy_frame.as_bytes().len(), COVER_FRAME_SIZE);
        assert_eq!(traffic.total_frames(), 3);
        assert_eq!(traffic.real_frames(), 1);
        assert_eq!(traffic.dummy_frames(), 2);

        // Unsealing recovers exact payload for real frame and None for dummy frame.
        assert_eq!(
            real_frame.unseal(k_real_rx).unwrap(),
            Some(payload.to_vec())
        );
        assert_eq!(dummy_frame.unseal(k_dummy_rx).unwrap(), None);

        // Bit-flip tampering anywhere in body or MAC tag is detected in constant time.
        let (k_tx, k_rx) = CoverFrameKey::generate_pair();
        let mut tampered = CoverFrame::seal_real(b"transfer", k_tx).unwrap();
        tampered.as_bytes_mut()[10] ^= 0x01;
        assert_eq!(
            tampered.unseal(k_rx),
            Err(MpcError::InvalidCoverFrame("Carter-Wegman MAC mismatch"))
        );
    }
}
