//! Confidential Information-Theoretic MPC DeFi & Governance Suite for Vernam (VRNM).
//!
//! Zero external crates. Zero computational cryptography (no SHA-256, RSA, ECDSA, AES,
//! or zk-SNARKs). All privacy and integrity guarantees rest purely on unconditional
//! information-theoretic security over the Mersenne prime field `F_(2^127 - 1)` using
//! Shamir secret sharing, single-use Beaver multiplication triples, blinded Schwartz–Zippel
//! random linear combinations (`[rho] * [Z]`), and Proactive Secret Sharing (PSS):
//!
//! 1. [`ConfidentialDarkPoolAmm`]: MEV-proof, front-run-proof dark-pool constant-product AMM
//!    where pool reserves, swap direction (`A -> B` vs `B -> A`), input amount, output amount,
//!    and slippage floor remain unconditionally secret-shared across validators. Every swap is
//!    verified obliviously via Beaver triples and a single blinded `[rho] * [Z]` RLC with 100%
//!    atomic rollback and PSS epoch refresh.
//! 2. [`ConfidentialSealedBidAuction`]: Unconditionally private sealed-bid auction supporting
//!    both [`AuctionMode::FirstPrice`] and [`AuctionMode::VickreySecondPrice`]. Uses a branchless
//!    bit-level IT-MPC comparison circuit over Shamir shares to obliviously track `(max1, winner_id)`
//!    and `max2` without revealing any intermediate comparison or losing bid—ever.
//! 3. [`ConfidentialBallotBox`]: Unconditionally private secret-ballot governance supporting
//!    multi-option proposals, quorum checks, and optional public voter weights. Ballots are
//!    verified via a single blinded RLC enforcing binary one-hot constraints, while tally
//!    accumulation is 100% linear (`mpc_add` / `mpc_scale`, 0 Beaver triples per tally addition).

use std::collections::HashSet;
use std::fmt;

use crate::field::{add_mod, mul_mod, random_nonzero_field_elem, zeroize_u128};
use crate::privacy_mpc::{
    BeaverPool, DEFAULT_NUM_VALIDATORS, DEFAULT_THRESHOLD, LagrangeCache, MpcError, mpc_add,
    mpc_add_const, mpc_mul, mpc_scale, mpc_sub, mpc_sub_const, proactive_refresh_epoch_batch,
    split_secret,
};

/// Basis-point denominator (`10_000 bps = 100.00%`).
pub const BPS_DENOMINATOR: u128 = 10_000;

/// Default swap fee in basis points (`30 bps = 0.30%`).
pub const DEFAULT_AMM_FEE_BPS: u64 = 30;

/// Default bit width for [`ConfidentialDarkPoolAmm`] reserves and swap amounts (`32` bits).
pub const DEFAULT_AMM_BIT_WIDTH: usize = 32;

/// Maximum supported bit width for [`ConfidentialDarkPoolAmm`] (`44` bits guarantees
/// `10_000^2 * (2^44)^2 < 2^115 << PRIME_P = 2^127 - 1` with zero modular wraparound).
pub const MAX_AMM_BIT_WIDTH: usize = 44;

/// Default bit width for [`ConfidentialSealedBidAuction`] bids (`32` bits).
pub const DEFAULT_AUCTION_BIT_WIDTH: usize = 32;

/// Maximum supported bit width for [`ConfidentialSealedBidAuction`] (`64` bits).
pub const MAX_AUCTION_BIT_WIDTH: usize = 64;

/// Maximum number of governance proposal options in a [`ConfidentialBallotBox`].
pub const MAX_BALLOT_OPTIONS: usize = 64;

/// Errors returned by the confidential IT-MPC DeFi and governance suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcDefiError {
    /// Underlying IT-MPC / Shamir / Beaver pool error.
    Mpc(MpcError),
    /// Invalid contract configuration or caller parameter.
    InvalidParameters(&'static str),
    /// Blinded RLC or invariant check failed (swap, bid, or ballot rejected atomically).
    InvariantViolation(&'static str),
    /// Confidential bit-decomposition range proof failed.
    RangeProofFailed(&'static str),
    /// Auction has already been settled and its secret bids wiped.
    AuctionAlreadySettled,
    /// Auction cannot settle because no valid bids were submitted.
    NoBidsSubmitted,
    /// Bidder has already submitted a bid to this auction.
    DuplicateBidder { bidder_id: u64 },
    /// Governance ballot failed one-hot or weight validation.
    InvalidBallot(&'static str),
    /// Voter has already cast a ballot in this ballot box.
    DuplicateVoter { voter_id: u64 },
}

impl From<MpcError> for MpcDefiError {
    fn from(err: MpcError) -> Self {
        Self::Mpc(err)
    }
}

impl fmt::Display for MpcDefiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcDefiError::Mpc(err) => write!(f, "MPC error: {err}"),
            MpcDefiError::InvalidParameters(msg) => write!(f, "invalid DeFi MPC parameters: {msg}"),
            MpcDefiError::InvariantViolation(msg) => {
                write!(f, "confidential invariant violation: {msg}")
            }
            MpcDefiError::RangeProofFailed(msg) => {
                write!(f, "confidential range proof failed: {msg}")
            }
            MpcDefiError::AuctionAlreadySettled => write!(f, "sealed-bid auction already settled"),
            MpcDefiError::NoBidsSubmitted => {
                write!(f, "cannot settle sealed-bid auction with zero bids")
            }
            MpcDefiError::DuplicateBidder { bidder_id } => {
                write!(f, "duplicate bidder ID in auction: {bidder_id}")
            }
            MpcDefiError::InvalidBallot(msg) => write!(f, "invalid confidential ballot: {msg}"),
            MpcDefiError::DuplicateVoter { voter_id } => {
                write!(f, "duplicate voter ID in ballot box: {voter_id}")
            }
        }
    }
}

impl std::error::Error for MpcDefiError {}

// ============================================================================
// Shared Zeroization Guards & Information-Theoretic MPC Circuit Primitives
// ============================================================================

/// Wipe a slice of `u128` secrets using volatile writes.
#[inline]
fn zeroize_u128_slice(buf: &mut [u128]) {
    for elem in buf.iter_mut() {
        zeroize_u128(elem);
    }
}

/// RAII guard that volatile-zeroizes a secret share vector on drop (including early error exits).
struct ZeroizeVec(Vec<u128>);

impl Drop for ZeroizeVec {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.0);
    }
}

/// RAII guard that volatile-zeroizes a 2D matrix of secret share vectors on drop.
struct ZeroizeMatrix(Vec<Vec<u128>>);

impl Drop for ZeroizeMatrix {
    fn drop(&mut self) {
        for row in &mut self.0 {
            zeroize_u128_slice(row);
        }
    }
}

/// Split an integer `value` into `bit_width` little-endian bit share vectors (`bit_0` = LSB).
fn split_bits(
    value: u128,
    bit_width: usize,
    threshold: usize,
    num_validators: usize,
) -> Result<Vec<Vec<u128>>, MpcDefiError> {
    if bit_width == 0 || bit_width > 126 {
        return Err(MpcDefiError::InvalidParameters(
            "bit_width must be in 1..=126",
        ));
    }
    let max_val = (1u128 << bit_width) - 1;
    if value > max_val {
        return Err(MpcDefiError::InvalidParameters(
            "value exceeds 2^bit_width - 1",
        ));
    }
    let mut bits = Vec::with_capacity(bit_width);
    for j in 0..bit_width {
        let bit = (value >> j) & 1;
        bits.push(split_secret(bit, threshold, num_validators)?);
    }
    Ok(bits)
}

/// Locally recompose `[x] = sum_{j=0}^{W-1} 2^j * [bit_j] (mod P)` from verified bit shares.
fn compose_bits(bits: &[Vec<u128>], cache: &LagrangeCache) -> Result<Vec<u128>, MpcDefiError> {
    if bits.is_empty() || bits.len() > 126 {
        return Err(MpcDefiError::InvalidParameters(
            "bit vector length must be in 1..=126",
        ));
    }
    let n = cache.num_validators();
    let mut acc = ZeroizeVec(vec![0u128; n]);
    for (j, bit_shares) in bits.iter().enumerate() {
        cache.verify_shares(bit_shares)?;
        let weight = 1u128 << j;
        for (dst, &b) in acc.0.iter_mut().zip(bit_shares.iter()) {
            *dst = add_mod(*dst, mul_mod(b, weight));
        }
    }
    Ok(std::mem::take(&mut acc.0))
}

/// Compute the binary check constraint `[b * (b - 1)]` (consumes 1 Beaver triple) without
/// opening it, so it can be folded into a single blinded Schwartz–Zippel RLC.
fn compute_bit_check(
    bit_shares: &[u128],
    pool: &mut BeaverPool,
    cache: &LagrangeCache,
) -> Result<Vec<u128>, MpcDefiError> {
    let bit_minus_one = ZeroizeVec(mpc_sub_const(bit_shares, 1)?);
    let triple = pool.pop()?;
    let prod = mpc_mul(bit_shares, &bit_minus_one.0, triple, cache)?;
    Ok(prod)
}

/// Verify that ALL secret-shared constraints `zero_checks[i]` equal `0 (mod P)` using a single
/// blinded Schwartz–Zippel random linear combination:
///
/// 1. Sample independent uniform non-zero field challenges `alpha_i in [1, PRIME_P)`.
/// 2. Compute `[Z] = sum_i alpha_i * [zero_checks[i]] (mod P)` locally (0 Beaver triples).
/// 3. Sample a uniform non-zero blinding scalar `rho in [1, PRIME_P)`, share it as `[rho]`,
///    and compute `[blinded] = [rho] * [Z]` (1 Beaver triple).
/// 4. Reconstruct and verify `blinded`. Return `Ok(())` iff `blinded == 0`.
///
/// Soundness error against any non-zero constraint is strictly `1 / (PRIME_P - 1) < 2^-126`,
/// and a failing check reveals a uniformly random non-zero field element—leaking zero bits about
/// which constraint failed or any secret witness value.
fn verify_zero_checks_blinded_rlc(
    zero_checks: &[Vec<u128>],
    pool: &mut BeaverPool,
    cache: &LagrangeCache,
    fail_err: MpcDefiError,
) -> Result<(), MpcDefiError> {
    let n = cache.num_validators();
    let mut z_agg = ZeroizeVec(vec![0u128; n]);

    for check in zero_checks {
        cache.verify_shares(check)?;
        let mut alpha = random_nonzero_field_elem();
        for (dst, &s) in z_agg.0.iter_mut().zip(check.iter()) {
            *dst = add_mod(*dst, mul_mod(alpha, s));
        }
        zeroize_u128(&mut alpha);
    }

    let mut rho = random_nonzero_field_elem();
    let rho_res = split_secret(rho, cache.threshold(), n);
    zeroize_u128(&mut rho);
    let rho_shares = ZeroizeVec(rho_res?);

    let blind_triple = pool.pop()?;
    let blinded = ZeroizeVec(mpc_mul(&rho_shares.0, &z_agg.0, blind_triple, cache)?);
    let opened = cache.reconstruct_and_verify(&blinded.0)?;
    if opened != 0 {
        return Err(fail_err);
    }
    Ok(())
}

/// Branchless oblivious multiplexer over Shamir shares:
/// `mux(cond, if_one, if_zero) = if_zero + cond * (if_one - if_zero)`.
///
/// Requires `cond in {0, 1}` and consumes exactly 1 Beaver triple.
fn mpc_mux(
    cond: &[u128],
    if_one: &[u128],
    if_zero: &[u128],
    pool: &mut BeaverPool,
    cache: &LagrangeCache,
) -> Result<Vec<u128>, MpcDefiError> {
    let diff = ZeroizeVec(mpc_sub(if_one, if_zero)?);
    let triple = pool.pop()?;
    let selected_delta = ZeroizeVec(mpc_mul(cond, &diff.0, triple, cache)?);
    Ok(mpc_add(if_zero, &selected_delta.0)?)
}

/// Branchless bit-level IT-MPC strict greater-than circuit: computes `[1]` if `a > b` else `[0]`,
/// where `a_bits` and `b_bits` are little-endian bit decompositions of equal width `W`.
///
/// Recurrence over `F_(2^127 - 1)` for `a_k, b_k, gt_{k-1} in {0, 1}`:
/// - `gt_0 = a_0 - a_0 * b_0` (1 Beaver triple)
/// - For `k = 1..W`:
///   - `p_k = a_k * b_k` (1 Beaver triple)
///   - `gt_bit_k = a_k - p_k` (linear)
///   - `eq_bit_k = 1 - a_k - b_k + 2 * p_k` (linear)
///   - `gt_k = gt_bit_k + eq_bit_k * gt_{k-1}` (1 Beaver triple)
///
/// Consumes exactly `2 * W - 1` Beaver triples and reveals zero intermediate comparison bits.
fn mpc_gt_bits(
    a_bits: &[Vec<u128>],
    b_bits: &[Vec<u128>],
    pool: &mut BeaverPool,
    cache: &LagrangeCache,
) -> Result<Vec<u128>, MpcDefiError> {
    if a_bits.is_empty() || a_bits.len() != b_bits.len() {
        return Err(MpcDefiError::InvalidParameters(
            "bit-level comparison requires equal non-empty bit vectors",
        ));
    }

    // k = 0 (LSB): gt_0 = a_0 - a_0 * b_0
    let p0 = ZeroizeVec(mpc_mul(&a_bits[0], &b_bits[0], pool.pop()?, cache)?);
    let mut gt = ZeroizeVec(mpc_sub(&a_bits[0], &p0.0)?);

    // k = 1..W
    for k in 1..a_bits.len() {
        let pk = ZeroizeVec(mpc_mul(&a_bits[k], &b_bits[k], pool.pop()?, cache)?);
        let gt_bit = ZeroizeVec(mpc_sub(&a_bits[k], &pk.0)?);

        // eq_bit = 1 - a_k - b_k + 2 * p_k
        let two_pk = ZeroizeVec(mpc_scale(&pk.0, 2));
        let sum_ab = ZeroizeVec(mpc_add(&a_bits[k], &b_bits[k])?);
        let two_pk_minus_ab = ZeroizeVec(mpc_sub(&two_pk.0, &sum_ab.0)?);
        let eq_bit = ZeroizeVec(mpc_add_const(&two_pk_minus_ab.0, 1)?);

        let eq_times_prev = ZeroizeVec(mpc_mul(&eq_bit.0, &gt.0, pool.pop()?, cache)?);
        gt = ZeroizeVec(mpc_add(&gt_bit.0, &eq_times_prev.0)?);
    }

    Ok(std::mem::take(&mut gt.0))
}

// ============================================================================
// Application 1: MEV-Proof Dark-Pool Constant-Product AMM
// ============================================================================

/// Secret-shared dark-pool swap request hiding direction, input, output, and slippage floor.
///
/// Every witness field is Shamir-shared across the validator committee. Implements redacted
/// [`fmt::Debug`] and volatile-zeroizing [`Drop`].
pub struct ConfidentialSwapRequest {
    /// Secret-shared direction bit: `0` = sell A for B, `1` = sell B for A.
    pub direction_bit: Vec<u128>,
    /// Secret-shared input amount `amount_in >= 1`.
    pub amount_in: Vec<u128>,
    /// Secret-shared output amount `amount_out >= min_amount_out`.
    pub amount_out: Vec<u128>,
    /// Secret-shared trader slippage floor `min_amount_out`.
    pub min_amount_out: Vec<u128>,
    /// Bit decomposition of `amount_in - 1` (`W` bits, proving `1 <= amount_in <= 2^W`).
    pub amount_in_minus_1_bits: Vec<Vec<u128>>,
    /// Bit decomposition of `amount_out` (`W` bits, proving `0 <= amount_out < 2^W`).
    pub amount_out_bits: Vec<Vec<u128>>,
    /// Bit decomposition of `min_amount_out` (`W` bits, proving `0 <= min_amount_out < 2^W`).
    pub min_amount_out_bits: Vec<Vec<u128>>,
    /// Bit decomposition of `amount_out - min_amount_out` (`W` bits, proving slippage floor met).
    pub slippage_excess_bits: Vec<Vec<u128>>,
    /// Bit decomposition of `new_reserve_a - 1` (`W` bits, proving `1 <= new_reserve_a <= 2^W`).
    pub new_reserve_a_minus_1_bits: Vec<Vec<u128>>,
    /// Bit decomposition of `new_reserve_b - 1` (`W` bits, proving `1 <= new_reserve_b <= 2^W`).
    pub new_reserve_b_minus_1_bits: Vec<Vec<u128>>,
    /// Bit decomposition of the scaled constant-product surplus (`2*W + 28` bits):
    /// `surplus = (10_000 * new_a - fee_bps * dx_a) * (10_000 * new_b - fee_bps * dx_b)
    ///            - 10_000^2 * old_a * old_b >= 0`.
    pub surplus_bits: Vec<Vec<u128>>,
}

impl fmt::Debug for ConfidentialSwapRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfidentialSwapRequest")
            .field("validators", &self.direction_bit.len())
            .field("bit_width", &self.amount_out_bits.len())
            .field("surplus_bits", &self.surplus_bits.len())
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl Drop for ConfidentialSwapRequest {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.direction_bit);
        zeroize_u128_slice(&mut self.amount_in);
        zeroize_u128_slice(&mut self.amount_out);
        zeroize_u128_slice(&mut self.min_amount_out);
        for row in &mut self.amount_in_minus_1_bits {
            zeroize_u128_slice(row);
        }
        for row in &mut self.amount_out_bits {
            zeroize_u128_slice(row);
        }
        for row in &mut self.min_amount_out_bits {
            zeroize_u128_slice(row);
        }
        for row in &mut self.slippage_excess_bits {
            zeroize_u128_slice(row);
        }
        for row in &mut self.new_reserve_a_minus_1_bits {
            zeroize_u128_slice(row);
        }
        for row in &mut self.new_reserve_b_minus_1_bits {
            zeroize_u128_slice(row);
        }
        for row in &mut self.surplus_bits {
            zeroize_u128_slice(row);
        }
    }
}

impl ConfidentialSwapRequest {
    /// Build a valid blinded swap request for a known pool state and exact swap quote.
    ///
    /// - `direction_bit`: `0` = sell token A for token B, `1` = sell token B for token A.
    /// - Automatically computes the exact maximum valid `amount_out` via
    ///   [`ConfidentialDarkPoolAmm::quote_exact_in`], checks `amount_out >= min_amount_out`,
    ///   and generates fresh Shamir shares for all witness values and range-proof bits.
    ///
    /// Returns `(request, quoted_amount_out)`.
    #[allow(clippy::too_many_arguments)]
    pub fn build_honest(
        reserve_a: u128,
        reserve_b: u128,
        direction_bit: u8,
        amount_in: u128,
        min_amount_out: u128,
        fee_bps: u64,
        bit_width: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<(Self, u128), MpcDefiError> {
        if direction_bit > 1 {
            return Err(MpcDefiError::InvalidParameters(
                "direction_bit must be 0 (A->B) or 1 (B->A)",
            ));
        }
        let (reserve_in, reserve_out) = if direction_bit == 0 {
            (reserve_a, reserve_b)
        } else {
            (reserve_b, reserve_a)
        };
        let amount_out = ConfidentialDarkPoolAmm::quote_exact_in(
            reserve_in,
            reserve_out,
            amount_in,
            fee_bps,
        )?;
        let req = Self::build_honest_with_output(
            reserve_a,
            reserve_b,
            direction_bit,
            amount_in,
            amount_out,
            min_amount_out,
            fee_bps,
            bit_width,
            threshold,
            num_validators,
        )?;
        Ok((req, amount_out))
    }

    /// Build a valid blinded swap request with an explicit `amount_out` (allowing custom prices
    /// at or below the AMM curve, e.g., voluntary surplus donation or exact test vectors).
    #[allow(clippy::too_many_arguments)]
    pub fn build_honest_with_output(
        reserve_a: u128,
        reserve_b: u128,
        direction_bit: u8,
        amount_in: u128,
        amount_out: u128,
        min_amount_out: u128,
        fee_bps: u64,
        bit_width: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcDefiError> {
        if bit_width == 0 || bit_width > MAX_AMM_BIT_WIDTH {
            return Err(MpcDefiError::InvalidParameters(
                "AMM bit_width must be in 1..=MAX_AMM_BIT_WIDTH",
            ));
        }
        if fee_bps as u128 >= BPS_DENOMINATOR {
            return Err(MpcDefiError::InvalidParameters(
                "fee_bps must be < 10_000",
            ));
        }
        if direction_bit > 1 {
            return Err(MpcDefiError::InvalidParameters(
                "direction_bit must be 0 or 1",
            ));
        }
        let max_reserve = 1u128 << bit_width;
        let max_u_bits = max_reserve - 1;
        if reserve_a == 0 || reserve_a > max_reserve || reserve_b == 0 || reserve_b > max_reserve {
            return Err(MpcDefiError::InvalidParameters(
                "reserves must lie in 1..=2^bit_width",
            ));
        }
        if amount_in == 0 || amount_in > max_reserve {
            return Err(MpcDefiError::InvalidParameters(
                "amount_in must lie in 1..=2^bit_width",
            ));
        }
        if amount_out > max_u_bits || min_amount_out > max_u_bits {
            return Err(MpcDefiError::InvalidParameters(
                "amount_out and min_amount_out must be < 2^bit_width",
            ));
        }
        if amount_out < min_amount_out {
            return Err(MpcDefiError::InvariantViolation(
                "amount_out is below min_amount_out slippage floor",
            ));
        }

        let (new_a, new_b, dx_a, dx_b) = if direction_bit == 0 {
            let na = reserve_a
                .checked_add(amount_in)
                .ok_or(MpcDefiError::InvalidParameters("reserve_a overflow"))?;
            let nb = reserve_b
                .checked_sub(amount_out)
                .ok_or(MpcDefiError::InvariantViolation("swap drains reserve_b"))?;
            (na, nb, amount_in, 0u128)
        } else {
            let na = reserve_a
                .checked_sub(amount_out)
                .ok_or(MpcDefiError::InvariantViolation("swap drains reserve_a"))?;
            let nb = reserve_b
                .checked_add(amount_in)
                .ok_or(MpcDefiError::InvalidParameters("reserve_b overflow"))?;
            (na, nb, 0u128, amount_in)
        };

        if new_a == 0 || new_a > max_reserve || new_b == 0 || new_b > max_reserve {
            return Err(MpcDefiError::InvariantViolation(
                "post-swap reserves must remain in 1..=2^bit_width",
            ));
        }

        let fee = fee_bps as u128;
        let new_a_eff = BPS_DENOMINATOR * new_a - fee * dx_a;
        let new_b_eff = BPS_DENOMINATOR * new_b - fee * dx_b;
        let new_k_scaled = new_a_eff * new_b_eff;
        let old_k_scaled = (BPS_DENOMINATOR * BPS_DENOMINATOR) * reserve_a * reserve_b;
        if new_k_scaled < old_k_scaled {
            return Err(MpcDefiError::InvariantViolation(
                "constant-product invariant violated (underpaid swap)",
            ));
        }

        let mut surplus = new_k_scaled - old_k_scaled;
        let mut slippage_excess = amount_out - min_amount_out;
        let surplus_width = ConfidentialDarkPoolAmm::surplus_bit_width_for(bit_width);

        let direction_bit_shares = split_secret(direction_bit as u128, threshold, num_validators)?;
        let amount_in_shares = split_secret(amount_in, threshold, num_validators)?;
        let amount_out_shares = split_secret(amount_out, threshold, num_validators)?;
        let min_amount_out_shares = split_secret(min_amount_out, threshold, num_validators)?;

        let amount_in_minus_1_bits =
            split_bits(amount_in - 1, bit_width, threshold, num_validators)?;
        let amount_out_bits = split_bits(amount_out, bit_width, threshold, num_validators)?;
        let min_amount_out_bits =
            split_bits(min_amount_out, bit_width, threshold, num_validators)?;
        let slippage_excess_bits =
            split_bits(slippage_excess, bit_width, threshold, num_validators)?;
        let new_reserve_a_minus_1_bits =
            split_bits(new_a - 1, bit_width, threshold, num_validators)?;
        let new_reserve_b_minus_1_bits =
            split_bits(new_b - 1, bit_width, threshold, num_validators)?;
        let surplus_bits = split_bits(surplus, surplus_width, threshold, num_validators)?;

        zeroize_u128(&mut surplus);
        zeroize_u128(&mut slippage_excess);

        Ok(Self {
            direction_bit: direction_bit_shares,
            amount_in: amount_in_shares,
            amount_out: amount_out_shares,
            min_amount_out: min_amount_out_shares,
            amount_in_minus_1_bits,
            amount_out_bits,
            min_amount_out_bits,
            slippage_excess_bits,
            new_reserve_a_minus_1_bits,
            new_reserve_b_minus_1_bits,
            surplus_bits,
        })
    }
}

/// MEV-proof, front-run-proof dark-pool constant-product AMM over Shamir secret shares.
///
/// Pool reserves `([reserve_a], [reserve_b])` are never reconstructed during swap execution.
/// Swaps are verified obliviously in constant-product form with trading fees and rotated every
/// epoch via Proactive Secret Sharing.
pub struct ConfidentialDarkPoolAmm {
    cache: LagrangeCache,
    reserve_a: Vec<u128>,
    reserve_b: Vec<u128>,
    fee_bps: u64,
    bit_width: usize,
    pss_epoch: u64,
    swaps_executed: u64,
}

impl fmt::Debug for ConfidentialDarkPoolAmm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfidentialDarkPoolAmm")
            .field("threshold", &self.cache.threshold())
            .field("num_validators", &self.cache.num_validators())
            .field("fee_bps", &self.fee_bps)
            .field("bit_width", &self.bit_width)
            .field("pss_epoch", &self.pss_epoch)
            .field("swaps_executed", &self.swaps_executed)
            .field("reserves", &"<redacted>")
            .finish()
    }
}

impl Drop for ConfidentialDarkPoolAmm {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.reserve_a);
        zeroize_u128_slice(&mut self.reserve_b);
    }
}

impl ConfidentialDarkPoolAmm {
    /// Create a new dark-pool AMM initialized with secret-shared reserves `(initial_a, initial_b)`.
    pub fn new(
        initial_a: u128,
        initial_b: u128,
        fee_bps: u64,
        bit_width: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcDefiError> {
        if bit_width == 0 || bit_width > MAX_AMM_BIT_WIDTH {
            return Err(MpcDefiError::InvalidParameters(
                "AMM bit_width must be in 1..=MAX_AMM_BIT_WIDTH",
            ));
        }
        if fee_bps as u128 >= BPS_DENOMINATOR {
            return Err(MpcDefiError::InvalidParameters(
                "fee_bps must be < 10_000",
            ));
        }
        let max_reserve = 1u128 << bit_width;
        if initial_a == 0 || initial_a > max_reserve || initial_b == 0 || initial_b > max_reserve {
            return Err(MpcDefiError::InvalidParameters(
                "initial reserves must lie in 1..=2^bit_width",
            ));
        }

        let cache = LagrangeCache::new(threshold, num_validators)?;
        let reserve_a = split_secret(initial_a, threshold, num_validators)?;
        let reserve_b = split_secret(initial_b, threshold, num_validators)?;

        Ok(Self {
            cache,
            reserve_a,
            reserve_b,
            fee_bps,
            bit_width,
            pss_epoch: 1,
            swaps_executed: 0,
        })
    }

    /// Convenience constructor using default Vernam parameters: `(3, 4)` committee, `30 bps` fee,
    /// `32`-bit reserves.
    pub fn new_default(initial_a: u128, initial_b: u128) -> Result<Self, MpcDefiError> {
        Self::new(
            initial_a,
            initial_b,
            DEFAULT_AMM_FEE_BPS,
            DEFAULT_AMM_BIT_WIDTH,
            DEFAULT_THRESHOLD,
            DEFAULT_NUM_VALIDATORS,
        )
    }

    /// Exact integer constant-product output quote with `fee_bps` deducted from `amount_in`:
    ///
    /// `amount_out = floor((amount_in * (10_000 - fee_bps) * reserve_out) / (reserve_in * 10_000 + amount_in * (10_000 - fee_bps)))`
    ///
    /// Guaranteed to satisfy the exact scaled constant-product inequality while remaining strictly
    /// optimal to the single atomic unit.
    pub fn quote_exact_in(
        reserve_in: u128,
        reserve_out: u128,
        amount_in: u128,
        fee_bps: u64,
    ) -> Result<u128, MpcDefiError> {
        if reserve_in == 0 || reserve_out == 0 || amount_in == 0 {
            return Err(MpcDefiError::InvalidParameters(
                "reserves and amount_in must be >= 1",
            ));
        }
        if fee_bps as u128 >= BPS_DENOMINATOR {
            return Err(MpcDefiError::InvalidParameters(
                "fee_bps must be < 10_000",
            ));
        }
        let net_bps = BPS_DENOMINATOR - fee_bps as u128;
        let amount_in_with_fee = amount_in
            .checked_mul(net_bps)
            .ok_or(MpcDefiError::InvalidParameters("quote overflow"))?;
        let numerator = amount_in_with_fee
            .checked_mul(reserve_out)
            .ok_or(MpcDefiError::InvalidParameters("quote numerator overflow"))?;
        let denominator = reserve_in
            .checked_mul(BPS_DENOMINATOR)
            .and_then(|v| v.checked_add(amount_in_with_fee))
            .ok_or(MpcDefiError::InvalidParameters(
                "quote denominator overflow",
            ))?;
        Ok(numerator / denominator)
    }

    /// Bit width required for the scaled constant-product surplus witness (`2 * bit_width + 28`).
    #[inline]
    pub const fn surplus_bit_width_for(bit_width: usize) -> usize {
        2 * bit_width + 28
    }

    /// Bit width of the constant-product surplus proof for this pool.
    #[inline]
    pub fn surplus_bit_width(&self) -> usize {
        Self::surplus_bit_width_for(self.bit_width)
    }

    /// Exact number of offline Beaver triples consumed by a single confidential swap:
    /// - `1` for `direction_bit * (direction_bit - 1)`
    /// - `6 * W` for `amount_in - 1`, `amount_out`, `min_amount_out`, `slippage_excess`,
    ///   `new_a - 1`, `new_b - 1` bit checks
    /// - `2 * W + 28` for `surplus` bit checks
    /// - `2` for oblivious directional routing (`dx_b = d * amount_in`, `dy_a = d * amount_out`)
    /// - `2` for `new_a_eff * new_b_eff` and `old_a * old_b`
    /// - `1` for the single blinded Schwartz–Zippel RLC `[rho] * [Z]`
    /// Total: `8 * W + 34`.
    #[inline]
    pub fn triples_per_swap(&self) -> usize {
        8 * self.bit_width + 34
    }

    /// Swap fee in basis points.
    #[inline]
    pub fn fee_bps(&self) -> u64 {
        self.fee_bps
    }

    /// Configured reserve/amount bit width `W`.
    #[inline]
    pub fn bit_width(&self) -> usize {
        self.bit_width
    }

    /// Current Proactive Secret Sharing epoch (starts at `1`).
    #[inline]
    pub fn pss_epoch(&self) -> u64 {
        self.pss_epoch
    }

    /// Number of confidential swaps committed so far.
    #[inline]
    pub fn swaps_executed(&self) -> u64 {
        self.swaps_executed
    }

    /// Reference to the precomputed [`LagrangeCache`].
    #[inline]
    pub fn cache(&self) -> &LagrangeCache {
        &self.cache
    }

    /// Read-only view of validator shares for reserve A.
    #[inline]
    pub fn reserve_a_shares(&self) -> &[u128] {
        &self.reserve_a
    }

    /// Read-only view of validator shares for reserve B.
    #[inline]
    pub fn reserve_b_shares(&self) -> &[u128] {
        &self.reserve_b
    }

    /// Reconstruct and verify `(reserve_a, reserve_b)` (for auditing and testing only).
    pub fn reconstruct_reserves(&self) -> Result<(u128, u128), MpcDefiError> {
        let a = self.cache.reconstruct_and_verify(&self.reserve_a)?;
        let b = self.cache.reconstruct_and_verify(&self.reserve_b)?;
        Ok((a, b))
    }

    /// Execute a Proactive Secret Sharing epoch refresh across both pool reserve share vectors,
    /// rendering all previous-epoch shares mathematically incompatible with the new epoch while
    /// preserving the exact underlying reserves.
    pub fn proactive_refresh_epoch(&mut self) -> Result<(), MpcDefiError> {
        let mut batch = [
            std::mem::take(&mut self.reserve_a),
            std::mem::take(&mut self.reserve_b),
        ];
        let res = proactive_refresh_epoch_batch(
            &mut batch,
            self.cache.threshold(),
            self.cache.num_validators(),
        );
        self.reserve_a = std::mem::take(&mut batch[0]);
        self.reserve_b = std::mem::take(&mut batch[1]);
        res?;
        self.pss_epoch += 1;
        Ok(())
    }

    /// Obliviously verify and atomically execute a confidential dark-pool swap.
    ///
    /// Performs zero branching on swap direction, input, output, or slippage floor. All binary
    /// range checks, reserve bounds, slippage bounds, and the fee-adjusted constant-product
    /// invariant are folded into a single blinded `[rho] * [Z]` Schwartz–Zippel RLC. On ANY
    /// error or invariant violation, pool reserves remain 100% unchanged (atomic rollback).
    pub fn execute_swap(
        &mut self,
        req: &ConfidentialSwapRequest,
        pool: &mut BeaverPool,
    ) -> Result<(), MpcDefiError> {
        let w = self.bit_width;
        let surplus_w = self.surplus_bit_width();

        if req.amount_in_minus_1_bits.len() != w
            || req.amount_out_bits.len() != w
            || req.min_amount_out_bits.len() != w
            || req.slippage_excess_bits.len() != w
            || req.new_reserve_a_minus_1_bits.len() != w
            || req.new_reserve_b_minus_1_bits.len() != w
            || req.surplus_bits.len() != surplus_w
        {
            return Err(MpcDefiError::InvalidParameters(
                "swap request bit decomposition lengths do not match AMM bit_width",
            ));
        }

        // Pre-verify degree-(t-1) consistency of every submitted share vector before touching
        // the Beaver pool so malformed shares never burn offline triples.
        self.cache.verify_shares(&req.direction_bit)?;
        self.cache.verify_shares(&req.amount_in)?;
        self.cache.verify_shares(&req.amount_out)?;
        self.cache.verify_shares(&req.min_amount_out)?;
        for bits in [
            &req.amount_in_minus_1_bits,
            &req.amount_out_bits,
            &req.min_amount_out_bits,
            &req.slippage_excess_bits,
            &req.new_reserve_a_minus_1_bits,
            &req.new_reserve_b_minus_1_bits,
            &req.surplus_bits,
        ] {
            for b in bits {
                self.cache.verify_shares(b)?;
            }
        }

        let needed = self.triples_per_swap();
        if pool.len() < needed {
            return Err(MpcError::BeaverPoolExhausted {
                needed,
                available: pool.len(),
            }
            .into());
        }

        let mut zero_checks = ZeroizeMatrix(Vec::with_capacity(8 * w + 36));

        // 1. Direction bit binary check: d * (d - 1) == 0.
        zero_checks
            .0
            .push(compute_bit_check(&req.direction_bit, pool, &self.cache)?);

        // 2. Binary checks for every range-proof bit across all 7 bit decompositions.
        for bit_group in [
            &req.amount_in_minus_1_bits,
            &req.amount_out_bits,
            &req.min_amount_out_bits,
            &req.slippage_excess_bits,
            &req.new_reserve_a_minus_1_bits,
            &req.new_reserve_b_minus_1_bits,
            &req.surplus_bits,
        ] {
            for b in bit_group {
                zero_checks.0.push(compute_bit_check(b, pool, &self.cache)?);
            }
        }

        // 3. Recompose all range-bounded witnesses linearly (0 Beaver triples).
        let amt_in_m1 = ZeroizeVec(compose_bits(&req.amount_in_minus_1_bits, &self.cache)?);
        let amt_in_from_bits = ZeroizeVec(mpc_add_const(&amt_in_m1.0, 1)?);
        let amt_out_from_bits = ZeroizeVec(compose_bits(&req.amount_out_bits, &self.cache)?);
        let min_out_from_bits = ZeroizeVec(compose_bits(&req.min_amount_out_bits, &self.cache)?);
        let slippage_excess = ZeroizeVec(compose_bits(&req.slippage_excess_bits, &self.cache)?);
        let new_a_m1 = ZeroizeVec(compose_bits(&req.new_reserve_a_minus_1_bits, &self.cache)?);
        let new_a_from_bits = ZeroizeVec(mpc_add_const(&new_a_m1.0, 1)?);
        let new_b_m1 = ZeroizeVec(compose_bits(&req.new_reserve_b_minus_1_bits, &self.cache)?);
        let new_b_from_bits = ZeroizeVec(mpc_add_const(&new_b_m1.0, 1)?);
        let surplus_from_bits = ZeroizeVec(compose_bits(&req.surplus_bits, &self.cache)?);

        // Bind submitted secret shares to their bit decompositions:
        zero_checks
            .0
            .push(mpc_sub(&req.amount_in, &amt_in_from_bits.0)?);
        zero_checks
            .0
            .push(mpc_sub(&req.amount_out, &amt_out_from_bits.0)?);
        zero_checks
            .0
            .push(mpc_sub(&req.min_amount_out, &min_out_from_bits.0)?);

        // 4. Slippage check: amount_out - min_amount_out - slippage_excess == 0.
        let out_minus_min = ZeroizeVec(mpc_sub(&req.amount_out, &req.min_amount_out)?);
        zero_checks
            .0
            .push(mpc_sub(&out_minus_min.0, &slippage_excess.0)?);

        // 5. Branchless oblivious routing for BOTH directions (0 = A->B, 1 = B->A):
        //    dx_b = d * amount_in,  dx_a = amount_in - dx_b
        //    dy_a = d * amount_out, dy_b = amount_out - dy_a
        //    new_a = old_a + dx_a - dy_a
        //    new_b = old_b + dx_b - dy_b
        let dx_b = ZeroizeVec(mpc_mul(
            &req.direction_bit,
            &req.amount_in,
            pool.pop()?,
            &self.cache,
        )?);
        let dx_a = ZeroizeVec(mpc_sub(&req.amount_in, &dx_b.0)?);
        let dy_a = ZeroizeVec(mpc_mul(
            &req.direction_bit,
            &req.amount_out,
            pool.pop()?,
            &self.cache,
        )?);
        let dy_b = ZeroizeVec(mpc_sub(&req.amount_out, &dy_a.0)?);

        let a_plus_dx = ZeroizeVec(mpc_add(&self.reserve_a, &dx_a.0)?);
        let mut new_a = ZeroizeVec(mpc_sub(&a_plus_dx.0, &dy_a.0)?);
        let b_plus_dx = ZeroizeVec(mpc_add(&self.reserve_b, &dx_b.0)?);
        let mut new_b = ZeroizeVec(mpc_sub(&b_plus_dx.0, &dy_b.0)?);

        // Bind new reserves to positive bounded range proofs (prevents pool drain & overflow):
        zero_checks.0.push(mpc_sub(&new_a.0, &new_a_from_bits.0)?);
        zero_checks.0.push(mpc_sub(&new_b.0, &new_b_from_bits.0)?);

        // 6. Fee-adjusted constant-product invariant:
        //    new_a_eff = 10_000 * new_a - fee_bps * dx_a
        //    new_b_eff = 10_000 * new_b - fee_bps * dx_b
        //    new_k_scaled - old_k_scaled - surplus_from_bits == 0
        let fee = self.fee_bps as u128;
        let scaled_new_a = ZeroizeVec(mpc_scale(&new_a.0, BPS_DENOMINATOR));
        let fee_dx_a = ZeroizeVec(mpc_scale(&dx_a.0, fee));
        let new_a_eff = ZeroizeVec(mpc_sub(&scaled_new_a.0, &fee_dx_a.0)?);

        let scaled_new_b = ZeroizeVec(mpc_scale(&new_b.0, BPS_DENOMINATOR));
        let fee_dx_b = ZeroizeVec(mpc_scale(&dx_b.0, fee));
        let new_b_eff = ZeroizeVec(mpc_sub(&scaled_new_b.0, &fee_dx_b.0)?);

        let new_k_scaled = ZeroizeVec(mpc_mul(
            &new_a_eff.0,
            &new_b_eff.0,
            pool.pop()?,
            &self.cache,
        )?);
        let old_k = ZeroizeVec(mpc_mul(
            &self.reserve_a,
            &self.reserve_b,
            pool.pop()?,
            &self.cache,
        )?);
        let old_k_scaled = ZeroizeVec(mpc_scale(&old_k.0, BPS_DENOMINATOR * BPS_DENOMINATOR));

        let k_diff = ZeroizeVec(mpc_sub(&new_k_scaled.0, &old_k_scaled.0)?);
        zero_checks.0.push(mpc_sub(&k_diff.0, &surplus_from_bits.0)?);

        // 7. Single blinded Schwartz–Zippel RLC verification across ALL constraints.
        //    If this fails, we return Err before touching `self.reserve_a` / `self.reserve_b`
        //    (100% atomic rollback).
        verify_zero_checks_blinded_rlc(
            &zero_checks.0,
            pool,
            &self.cache,
            MpcDefiError::InvariantViolation(
                "confidential dark-pool AMM swap failed blinded RLC verification",
            ),
        )?;

        // 8. Atomic commit (zeroize old reserves immediately).
        let mut old_a = std::mem::replace(&mut self.reserve_a, std::mem::take(&mut new_a.0));
        let mut old_b = std::mem::replace(&mut self.reserve_b, std::mem::take(&mut new_b.0));
        zeroize_u128_slice(&mut old_a);
        zeroize_u128_slice(&mut old_b);
        self.swaps_executed += 1;

        Ok(())
    }
}

// ============================================================================
// Application 2: Unconditionally Private Sealed-Bid Auction
// ============================================================================

/// Clearing-price rule for [`ConfidentialSealedBidAuction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuctionMode {
    /// Highest bidder wins and pays their own bid (`max1`).
    FirstPrice,
    /// Highest bidder wins and pays the second-highest bid (`max2`, or `0` if only 1 bidder).
    /// Even the winning bid itself (`max1`) is never revealed!
    VickreySecondPrice,
}

/// Public settlement outcome revealed after an oblivious sealed-bid auction tournament.
///
/// Losing bids are never reconstructed and are volatile-zeroized on settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuctionSettlement {
    /// Pricing mode used to settle the auction.
    pub mode: AuctionMode,
    /// Winning bidder ID (earliest bidder wins exact ties deterministically).
    pub winner_id: u64,
    /// Revealed clearing price (`max1` for first-price; `max2` for Vickrey second-price).
    pub clearing_price: u128,
    /// Total number of valid sealed bids that entered the tournament.
    pub num_bidders: usize,
}

/// Secret-shared sealed bid carrying a bidder ID, Shamir-shared bid amount, and `bit_width`-bit
/// range-proof bit decomposition.
pub struct ConfidentialBid {
    /// Public bidder identifier.
    pub bidder_id: u64,
    /// Shamir shares of the bid value `0 <= bid < 2^bit_width`.
    pub amount: Vec<u128>,
    /// Shamir shares of the little-endian bits of `amount`.
    pub amount_bits: Vec<Vec<u128>>,
}

impl fmt::Debug for ConfidentialBid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfidentialBid")
            .field("bidder_id", &self.bidder_id)
            .field("bit_width", &self.amount_bits.len())
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl Drop for ConfidentialBid {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.amount);
        for row in &mut self.amount_bits {
            zeroize_u128_slice(row);
        }
    }
}

impl ConfidentialBid {
    /// Construct an honest sealed bid for `bidder_id` with secret `amount in [0, 2^bit_width)`.
    pub fn build_honest(
        bidder_id: u64,
        amount: u128,
        bit_width: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcDefiError> {
        if bit_width == 0 || bit_width > MAX_AUCTION_BIT_WIDTH {
            return Err(MpcDefiError::InvalidParameters(
                "auction bit_width must be in 1..=MAX_AUCTION_BIT_WIDTH",
            ));
        }
        let max_val = if bit_width == 64 {
            u64::MAX as u128
        } else {
            (1u128 << bit_width) - 1
        };
        if amount > max_val {
            return Err(MpcDefiError::InvalidParameters(
                "bid amount exceeds 2^bit_width - 1",
            ));
        }
        let amount_shares = split_secret(amount, threshold, num_validators)?;
        let amount_bits = split_bits(amount, bit_width, threshold, num_validators)?;
        Ok(Self {
            bidder_id,
            amount: amount_shares,
            amount_bits,
        })
    }
}

/// Unconditionally private sealed-bid auction supporting first-price and Vickrey second-price
/// settlement via a branchless bit-level IT-MPC tournament.
pub struct ConfidentialSealedBidAuction {
    cache: LagrangeCache,
    mode: AuctionMode,
    bit_width: usize,
    pss_epoch: u64,
    settled: bool,
    seen_bidders: HashSet<u64>,
    bids: Vec<ConfidentialBid>,
}

impl fmt::Debug for ConfidentialSealedBidAuction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfidentialSealedBidAuction")
            .field("mode", &self.mode)
            .field("bit_width", &self.bit_width)
            .field("pss_epoch", &self.pss_epoch)
            .field("settled", &self.settled)
            .field("num_bids", &self.bids.len())
            .field("bids", &"<redacted>")
            .finish()
    }
}

impl Drop for ConfidentialSealedBidAuction {
    fn drop(&mut self) {
        self.bids.clear();
    }
}

impl ConfidentialSealedBidAuction {
    /// Create a new sealed-bid auction with the specified `mode`, `bit_width`, and Shamir
    /// committee parameters `(threshold, num_validators)`.
    pub fn new(
        mode: AuctionMode,
        bit_width: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcDefiError> {
        if bit_width == 0 || bit_width > MAX_AUCTION_BIT_WIDTH {
            return Err(MpcDefiError::InvalidParameters(
                "auction bit_width must be in 1..=MAX_AUCTION_BIT_WIDTH",
            ));
        }
        let cache = LagrangeCache::new(threshold, num_validators)?;
        Ok(Self {
            cache,
            mode,
            bit_width,
            pss_epoch: 1,
            settled: false,
            seen_bidders: HashSet::new(),
            bids: Vec::new(),
        })
    }

    /// Convenience constructor using default `(3, 4)` committee and `32`-bit bids.
    pub fn new_default(mode: AuctionMode) -> Result<Self, MpcDefiError> {
        Self::new(
            mode,
            DEFAULT_AUCTION_BIT_WIDTH,
            DEFAULT_THRESHOLD,
            DEFAULT_NUM_VALIDATORS,
        )
    }

    /// Pricing mode (`FirstPrice` or `VickreySecondPrice`).
    #[inline]
    pub fn mode(&self) -> AuctionMode {
        self.mode
    }

    /// Configured bid bit width `W`.
    #[inline]
    pub fn bit_width(&self) -> usize {
        self.bit_width
    }

    /// Current Proactive Secret Sharing epoch.
    #[inline]
    pub fn pss_epoch(&self) -> u64 {
        self.pss_epoch
    }

    /// Whether the auction has been settled.
    #[inline]
    pub fn is_settled(&self) -> bool {
        self.settled
    }

    /// Number of currently stored valid sealed bids (`0` after settlement).
    #[inline]
    pub fn num_bids(&self) -> usize {
        self.bids.len()
    }

    /// Reference to the precomputed [`LagrangeCache`].
    #[inline]
    pub fn cache(&self) -> &LagrangeCache {
        &self.cache
    }

    /// Beaver triples required to validate one incoming sealed bid (`bit_width + 1`).
    #[inline]
    pub fn triples_per_bid(&self) -> usize {
        self.bit_width + 1
    }

    /// Beaver triples required to settle the currently submitted bids.
    pub fn triples_to_settle(&self) -> usize {
        let m = self.bids.len();
        if m <= 1 {
            return 0;
        }
        let per_step = match self.mode {
            // gt1 (2W - 1) + mux max1_bits (W) + mux winner_id (1) = 3W
            AuctionMode::FirstPrice => 3 * self.bit_width,
            // gt1 (2W - 1) + gt2 (2W - 1) + mux cand_max2 (W) + mux max2 (W) + mux max1 (W) + mux winner (1) = 7W - 1
            AuctionMode::VickreySecondPrice => 7 * self.bit_width - 1,
        };
        (m - 1) * per_step
    }

    /// Read-only view of stored bid amount shares for testing `< t` secrecy before settlement.
    pub fn bid_amount_shares(&self, index: usize) -> Option<&[u128]> {
        self.bids.get(index).map(|b| b.amount.as_slice())
    }

    /// Rotate all currently stored sealed-bid shares via Proactive Secret Sharing.
    pub fn proactive_refresh_epoch(&mut self) -> Result<(), MpcDefiError> {
        if self.settled {
            return Err(MpcDefiError::AuctionAlreadySettled);
        }
        let mut flat = Vec::with_capacity(self.bids.len() * (1 + self.bit_width));
        for bid in &mut self.bids {
            flat.push(std::mem::take(&mut bid.amount));
            for b in &mut bid.amount_bits {
                flat.push(std::mem::take(b));
            }
        }
        let res = proactive_refresh_epoch_batch(
            &mut flat,
            self.cache.threshold(),
            self.cache.num_validators(),
        );
        let mut cursor = 0usize;
        for bid in &mut self.bids {
            bid.amount = std::mem::take(&mut flat[cursor]);
            cursor += 1;
            for b in &mut bid.amount_bits {
                *b = std::mem::take(&mut flat[cursor]);
                cursor += 1;
            }
        }
        res?;
        self.pss_epoch += 1;
        Ok(())
    }

    /// Verify and accept a sealed bid into the auction.
    ///
    /// Obliviously checks via Beaver triples + single blinded `[rho] * [Z]` RLC that every bit
    /// is binary (`b_k * (b_k - 1) == 0`) and `amount == sum 2^k b_k`, rejecting forged or
    /// out-of-range bids atomically without learning the bid value.
    pub fn submit_bid(
        &mut self,
        bid: ConfidentialBid,
        pool: &mut BeaverPool,
    ) -> Result<(), MpcDefiError> {
        if self.settled {
            return Err(MpcDefiError::AuctionAlreadySettled);
        }
        if self.seen_bidders.contains(&bid.bidder_id) {
            return Err(MpcDefiError::DuplicateBidder {
                bidder_id: bid.bidder_id,
            });
        }
        if bid.amount_bits.len() != self.bit_width {
            return Err(MpcDefiError::RangeProofFailed(
                "bid bit decomposition length does not match auction bit_width",
            ));
        }

        // Pre-verify Lagrange consistency before spending Beaver triples.
        self.cache.verify_shares(&bid.amount)?;
        for bit in &bid.amount_bits {
            self.cache.verify_shares(bit)?;
        }

        let needed = self.triples_per_bid();
        if pool.len() < needed {
            return Err(MpcError::BeaverPoolExhausted {
                needed,
                available: pool.len(),
            }
            .into());
        }

        let mut zero_checks = ZeroizeMatrix(Vec::with_capacity(self.bit_width + 1));
        for bit in &bid.amount_bits {
            zero_checks
                .0
                .push(compute_bit_check(bit, pool, &self.cache)?);
        }
        let recomposed = ZeroizeVec(compose_bits(&bid.amount_bits, &self.cache)?);
        zero_checks.0.push(mpc_sub(&bid.amount, &recomposed.0)?);

        verify_zero_checks_blinded_rlc(
            &zero_checks.0,
            pool,
            &self.cache,
            MpcDefiError::RangeProofFailed("sealed bid failed blinded range proof RLC"),
        )?;

        self.seen_bidders.insert(bid.bidder_id);
        self.bids.push(bid);
        Ok(())
    }

    /// Execute the branchless oblivious comparison tournament and reveal ONLY
    /// `(winner_id, clearing_price)`.
    ///
    /// All losing bids (and in Vickrey mode, even the winning bid's own value!) remain
    /// unconditionally secret forever and are volatile-zeroized upon settlement.
    pub fn settle(
        &mut self,
        pool: &mut BeaverPool,
    ) -> Result<AuctionSettlement, MpcDefiError> {
        if self.settled {
            return Err(MpcDefiError::AuctionAlreadySettled);
        }
        let num_bidders = self.bids.len();
        if num_bidders == 0 {
            return Err(MpcDefiError::NoBidsSubmitted);
        }

        let needed = self.triples_to_settle();
        if pool.len() < needed {
            return Err(MpcError::BeaverPoolExhausted {
                needed,
                available: pool.len(),
            }
            .into());
        }

        let t = self.cache.threshold();
        let n = self.cache.num_validators();

        let mut winner_id_shares =
            ZeroizeVec(split_secret(self.bids[0].bidder_id as u128, t, n)?);
        let mut max1_bits = ZeroizeMatrix(self.bids[0].amount_bits.clone());
        let mut max2_bits = ZeroizeMatrix(split_bits(0, self.bit_width, t, n)?);

        for bid in &self.bids[1..] {
            let bid_id_shares = ZeroizeVec(split_secret(bid.bidder_id as u128, t, n)?);
            let gt1 = ZeroizeVec(mpc_gt_bits(&bid.amount_bits, &max1_bits.0, pool, &self.cache)?);

            match self.mode {
                AuctionMode::FirstPrice => {
                    let mut next_max1 = ZeroizeMatrix(Vec::with_capacity(self.bit_width));
                    for k in 0..self.bit_width {
                        next_max1.0.push(mpc_mux(
                            &gt1.0,
                            &bid.amount_bits[k],
                            &max1_bits.0[k],
                            pool,
                            &self.cache,
                        )?);
                    }
                    max1_bits = next_max1;
                }
                AuctionMode::VickreySecondPrice => {
                    let gt2 = ZeroizeVec(mpc_gt_bits(
                        &bid.amount_bits,
                        &max2_bits.0,
                        pool,
                        &self.cache,
                    )?);
                    let mut next_max1 = ZeroizeMatrix(Vec::with_capacity(self.bit_width));
                    let mut next_max2 = ZeroizeMatrix(Vec::with_capacity(self.bit_width));
                    for k in 0..self.bit_width {
                        // If bid_j <= max1: candidate max2 = gt2 ? bid_j : max2
                        let cand_max2_k = ZeroizeVec(mpc_mux(
                            &gt2.0,
                            &bid.amount_bits[k],
                            &max2_bits.0[k],
                            pool,
                            &self.cache,
                        )?);
                        // If bid_j > max1: new max2 = old max1; else candidate max2
                        next_max2.0.push(mpc_mux(
                            &gt1.0,
                            &max1_bits.0[k],
                            &cand_max2_k.0,
                            pool,
                            &self.cache,
                        )?);
                        // new max1 = gt1 ? bid_j : old max1
                        next_max1.0.push(mpc_mux(
                            &gt1.0,
                            &bid.amount_bits[k],
                            &max1_bits.0[k],
                            pool,
                            &self.cache,
                        )?);
                    }
                    max1_bits = next_max1;
                    max2_bits = next_max2;
                }
            }

            winner_id_shares = ZeroizeVec(mpc_mux(
                &gt1.0,
                &bid_id_shares.0,
                &winner_id_shares.0,
                pool,
                &self.cache,
            )?);
        }

        // Reconstruct ONLY winner_id and the clearing price (never max1 in Vickrey mode!).
        let winner_id_u128 = self.cache.reconstruct_and_verify(&winner_id_shares.0)?;
        let winner_id = u64::try_from(winner_id_u128)
            .map_err(|_| MpcDefiError::InvariantViolation("corrupted winner_id share"))?;

        let clearing_price_shares = match self.mode {
            AuctionMode::FirstPrice => ZeroizeVec(compose_bits(&max1_bits.0, &self.cache)?),
            AuctionMode::VickreySecondPrice => {
                ZeroizeVec(compose_bits(&max2_bits.0, &self.cache)?)
            }
        };
        let clearing_price = self.cache.reconstruct_and_verify(&clearing_price_shares.0)?;

        // Permanently wipe all sealed bids on settlement.
        self.bids.clear();
        self.settled = true;

        Ok(AuctionSettlement {
            mode: self.mode,
            winner_id,
            clearing_price,
            num_bidders,
        })
    }
}

// ============================================================================
// Application 3: Unconditionally Private Secret-Ballot Governance
// ============================================================================

/// Secret-shared one-hot governance ballot with optional public voter weight.
///
/// Implements redacted [`fmt::Debug`] and volatile-zeroizing [`Drop`].
pub struct ConfidentialBallot {
    /// Public voter identifier (prevents duplicate voting).
    pub voter_id: u64,
    /// Public voting weight (`1` for standard 1-voter-1-vote; `>= 1` for stake-weighted voting).
    pub weight: u64,
    /// Secret-shared one-hot option vector `[v_0, ..., v_{k-1}]` satisfying `v_j in {0, 1}`
    /// and `sum_j v_j == 1`.
    pub option_shares: Vec<Vec<u128>>,
}

impl fmt::Debug for ConfidentialBallot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfidentialBallot")
            .field("voter_id", &self.voter_id)
            .field("weight", &self.weight)
            .field("num_options", &self.option_shares.len())
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl Drop for ConfidentialBallot {
    fn drop(&mut self) {
        for row in &mut self.option_shares {
            zeroize_u128_slice(row);
        }
    }
}

impl ConfidentialBallot {
    /// Build an honest unweighted (`weight = 1`) secret-shared ballot voting for `chosen_option`.
    pub fn build_honest(
        voter_id: u64,
        chosen_option: usize,
        num_options: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcDefiError> {
        Self::build_weighted(
            voter_id,
            1,
            chosen_option,
            num_options,
            threshold,
            num_validators,
        )
    }

    /// Build an honest weighted secret-shared ballot voting for `chosen_option` with public
    /// stake `weight >= 1`.
    pub fn build_weighted(
        voter_id: u64,
        weight: u64,
        chosen_option: usize,
        num_options: usize,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcDefiError> {
        if !(2..=MAX_BALLOT_OPTIONS).contains(&num_options) {
            return Err(MpcDefiError::InvalidParameters(
                "num_options must be in 2..=MAX_BALLOT_OPTIONS",
            ));
        }
        if weight == 0 {
            return Err(MpcDefiError::InvalidBallot("ballot weight must be >= 1"));
        }
        if chosen_option >= num_options {
            return Err(MpcDefiError::InvalidBallot("chosen_option >= num_options"));
        }
        let mut option_shares = Vec::with_capacity(num_options);
        for j in 0..num_options {
            let bit = if j == chosen_option { 1u128 } else { 0u128 };
            option_shares.push(split_secret(bit, threshold, num_validators)?);
        }
        Ok(Self {
            voter_id,
            weight,
            option_shares,
        })
    }
}

/// Revealed aggregate governance tally. Individual ballots are never reconstructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotTallyResult {
    /// Total votes (or weighted voting power) per proposal option.
    pub option_totals: Vec<u64>,
    /// Sum of votes across all options.
    pub total_votes: u64,
    /// Number of valid ballots cast.
    pub ballots_cast: u64,
    /// Index of the unique winning option, or `None` if zero votes were cast or there is a tie.
    pub winning_option: Option<usize>,
    /// True if two or more options tied for the maximum vote total (when `total_votes > 0`).
    pub is_tie: bool,
    /// True iff `total_votes >= quorum_threshold`.
    pub quorum_met: bool,
}

/// Unconditionally private secret-ballot governance box over Shamir shares.
///
/// Each submitted ballot's one-hot proof (`v_j * (v_j - 1) == 0` and `sum(v_j) == 1`) is verified
/// via a single blinded `[rho] * [Z]` RLC, while tally accumulation is 100% linear (`mpc_add` /
/// `mpc_scale` — **0 Beaver triples** to sum any number of ballots or merge tally boxes).
pub struct ConfidentialBallotBox {
    cache: LagrangeCache,
    num_options: usize,
    quorum_threshold: u64,
    pss_epoch: u64,
    ballots_cast: u64,
    total_weight: u64,
    seen_voters: HashSet<u64>,
    tally_shares: Vec<Vec<u128>>,
}

impl fmt::Debug for ConfidentialBallotBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfidentialBallotBox")
            .field("num_options", &self.num_options)
            .field("quorum_threshold", &self.quorum_threshold)
            .field("pss_epoch", &self.pss_epoch)
            .field("ballots_cast", &self.ballots_cast)
            .field("total_weight", &self.total_weight)
            .field("tally_shares", &"<redacted>")
            .finish()
    }
}

impl Drop for ConfidentialBallotBox {
    fn drop(&mut self) {
        for row in &mut self.tally_shares {
            zeroize_u128_slice(row);
        }
    }
}

impl ConfidentialBallotBox {
    /// Create a new secret-ballot governance box with `num_options` proposals (`2..=64`),
    /// `quorum_threshold`, and `(threshold, num_validators)` Shamir sharing.
    pub fn new(
        num_options: usize,
        quorum_threshold: u64,
        threshold: usize,
        num_validators: usize,
    ) -> Result<Self, MpcDefiError> {
        if !(2..=MAX_BALLOT_OPTIONS).contains(&num_options) {
            return Err(MpcDefiError::InvalidParameters(
                "num_options must be in 2..=MAX_BALLOT_OPTIONS",
            ));
        }
        let cache = LagrangeCache::new(threshold, num_validators)?;
        let mut tally_shares = Vec::with_capacity(num_options);
        for _ in 0..num_options {
            tally_shares.push(split_secret(0, threshold, num_validators)?);
        }
        Ok(Self {
            cache,
            num_options,
            quorum_threshold,
            pss_epoch: 1,
            ballots_cast: 0,
            total_weight: 0,
            seen_voters: HashSet::new(),
            tally_shares,
        })
    }

    /// Convenience constructor using the default `(3, 4)` Vernam validator committee.
    pub fn new_default(num_options: usize, quorum_threshold: u64) -> Result<Self, MpcDefiError> {
        Self::new(
            num_options,
            quorum_threshold,
            DEFAULT_THRESHOLD,
            DEFAULT_NUM_VALIDATORS,
        )
    }

    /// Number of proposal options in this ballot box.
    #[inline]
    pub fn num_options(&self) -> usize {
        self.num_options
    }

    /// Minimum total vote weight required to satisfy quorum.
    #[inline]
    pub fn quorum_threshold(&self) -> u64 {
        self.quorum_threshold
    }

    /// Current Proactive Secret Sharing epoch.
    #[inline]
    pub fn pss_epoch(&self) -> u64 {
        self.pss_epoch
    }

    /// Number of valid ballots cast so far.
    #[inline]
    pub fn ballots_cast(&self) -> u64 {
        self.ballots_cast
    }

    /// Cumulative vote weight cast so far.
    #[inline]
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Reference to the precomputed [`LagrangeCache`].
    #[inline]
    pub fn cache(&self) -> &LagrangeCache {
        &self.cache
    }

    /// Read-only view of accumulated tally shares for `option`.
    pub fn option_tally_shares(&self, option: usize) -> Option<&[u128]> {
        self.tally_shares.get(option).map(|s| s.as_slice())
    }

    /// Beaver triples required to verify one incoming ballot's one-hot proof (`num_options + 1`).
    /// Tally accumulation itself uses 0 Beaver triples.
    #[inline]
    pub fn triples_per_ballot(&self) -> usize {
        self.num_options + 1
    }

    /// Rotate all accumulated tally shares via Proactive Secret Sharing.
    pub fn proactive_refresh_epoch(&mut self) -> Result<(), MpcDefiError> {
        proactive_refresh_epoch_batch(
            &mut self.tally_shares,
            self.cache.threshold(),
            self.cache.num_validators(),
        )?;
        self.pss_epoch += 1;
        Ok(())
    }

    /// Verify a [`ConfidentialBallot`] via blinded RLC (`v_j * (v_j - 1) == 0` and `sum(v_j) == 1`)
    /// and homomorphically accumulate it into the encrypted tally using pure linear `mpc_add` /
    /// `mpc_scale` (0 Beaver triples for tally summation).
    ///
    /// Rejects double-votes, negative votes, all-zero votes, malformed shares, and duplicate
    /// voters atomically without modifying the tally.
    pub fn cast_ballot(
        &mut self,
        ballot: &ConfidentialBallot,
        pool: &mut BeaverPool,
    ) -> Result<(), MpcDefiError> {
        if self.seen_voters.contains(&ballot.voter_id) {
            return Err(MpcDefiError::DuplicateVoter {
                voter_id: ballot.voter_id,
            });
        }
        if ballot.weight == 0 {
            return Err(MpcDefiError::InvalidBallot("ballot weight must be >= 1"));
        }
        let next_total_weight = self
            .total_weight
            .checked_add(ballot.weight)
            .ok_or(MpcDefiError::InvalidBallot("total vote weight overflow"))?;
        if ballot.option_shares.len() != self.num_options {
            return Err(MpcDefiError::InvalidBallot(
                "ballot option vector length does not match ballot box",
            ));
        }

        // Pre-verify Lagrange consistency on every option share vector before burning triples.
        for v_j in &ballot.option_shares {
            self.cache.verify_shares(v_j)?;
        }

        let needed = self.triples_per_ballot();
        if pool.len() < needed {
            return Err(MpcError::BeaverPoolExhausted {
                needed,
                available: pool.len(),
            }
            .into());
        }

        let n = self.cache.num_validators();
        let mut zero_checks = ZeroizeMatrix(Vec::with_capacity(self.num_options + 1));
        let mut sum_v = ZeroizeVec(vec![0u128; n]);

        for v_j in &ballot.option_shares {
            zero_checks
                .0
                .push(compute_bit_check(v_j, pool, &self.cache)?);
            for (acc, &s) in sum_v.0.iter_mut().zip(v_j.iter()) {
                *acc = add_mod(*acc, s);
            }
        }
        // Require sum_j v_j == 1 (rejects double votes and all-zero ballots).
        zero_checks.0.push(mpc_sub_const(&sum_v.0, 1)?);

        verify_zero_checks_blinded_rlc(
            &zero_checks.0,
            pool,
            &self.cache,
            MpcDefiError::InvalidBallot(
                "confidential ballot failed one-hot blinded RLC verification",
            ),
        )?;

        // 100% linear homomorphic tally accumulation (0 Beaver triples).
        let mut updated_tallies = ZeroizeMatrix(Vec::with_capacity(self.num_options));
        for (tally_j, v_j) in self.tally_shares.iter().zip(ballot.option_shares.iter()) {
            let next_j = if ballot.weight == 1 {
                mpc_add(tally_j, v_j)?
            } else {
                let weighted = ZeroizeVec(mpc_scale(v_j, ballot.weight as u128));
                mpc_add(tally_j, &weighted.0)?
            };
            updated_tallies.0.push(next_j);
        }

        // Atomic commit (zeroize old tally shares).
        for (dst, src) in self
            .tally_shares
            .iter_mut()
            .zip(updated_tallies.0.iter_mut())
        {
            let mut old = std::mem::replace(dst, std::mem::take(src));
            zeroize_u128_slice(&mut old);
        }
        self.seen_voters.insert(ballot.voter_id);
        self.ballots_cast += 1;
        self.total_weight = next_total_weight;
        Ok(())
    }

    /// Homomorphically merge another compatible [`ConfidentialBallotBox`] into `self` using pure
    /// linear `mpc_add` (**0 Beaver triples**). Rejects overlapping voter IDs atomically.
    pub fn merge_linear(&mut self, other: &Self) -> Result<(), MpcDefiError> {
        if self.num_options != other.num_options
            || self.cache.threshold() != other.cache.threshold()
            || self.cache.num_validators() != other.cache.num_validators()
        {
            return Err(MpcDefiError::InvalidParameters(
                "cannot merge ballot boxes with mismatched options or committee parameters",
            ));
        }
        for &voter_id in &other.seen_voters {
            if self.seen_voters.contains(&voter_id) {
                return Err(MpcDefiError::DuplicateVoter { voter_id });
            }
        }
        let next_total_weight = self
            .total_weight
            .checked_add(other.total_weight)
            .ok_or(MpcDefiError::InvalidBallot("merged vote weight overflow"))?;

        let mut merged = ZeroizeMatrix(Vec::with_capacity(self.num_options));
        for (a, b) in self.tally_shares.iter().zip(other.tally_shares.iter()) {
            self.cache.verify_shares(b)?;
            merged.0.push(mpc_add(a, b)?);
        }

        for (dst, src) in self.tally_shares.iter_mut().zip(merged.0.iter_mut()) {
            let mut old = std::mem::replace(dst, std::mem::take(src));
            zeroize_u128_slice(&mut old);
        }
        self.seen_voters.extend(other.seen_voters.iter().copied());
        self.ballots_cast += other.ballots_cast;
        self.total_weight = next_total_weight;
        Ok(())
    }

    /// Reconstruct ONLY the aggregate per-option vote totals, winning option, and quorum status.
    /// Individual ballots are never stored or reconstructed, and tally reveal uses 0 Beaver triples.
    pub fn tally_and_reveal(&self) -> Result<BallotTallyResult, MpcDefiError> {
        let mut option_totals = Vec::with_capacity(self.num_options);
        let mut sum: u64 = 0;

        for shares in &self.tally_shares {
            let val = self.cache.reconstruct_and_verify(shares)?;
            let count = u64::try_from(val)
                .map_err(|_| MpcDefiError::InvariantViolation("tally total exceeded u64"))?;
            sum = sum
                .checked_add(count)
                .ok_or(MpcDefiError::InvariantViolation("tally sum overflow"))?;
            option_totals.push(count);
        }

        if sum != self.total_weight {
            return Err(MpcDefiError::InvariantViolation(
                "reconstructed tally sum does not match recorded total weight",
            ));
        }

        let (winning_option, is_tie) = if sum == 0 {
            (None, false)
        } else {
            let mut best_val = 0u64;
            let mut best_idx = 0usize;
            let mut best_count = 0usize;
            for (idx, &total) in option_totals.iter().enumerate() {
                if total > best_val {
                    best_val = total;
                    best_idx = idx;
                    best_count = 1;
                } else if total == best_val {
                    best_count += 1;
                }
            }
            if best_count == 1 {
                (Some(best_idx), false)
            } else {
                (None, true)
            }
        };

        Ok(BallotTallyResult {
            option_totals,
            total_votes: sum,
            ballots_cast: self.ballots_cast,
            winning_option,
            is_tie,
            quorum_met: sum >= self.quorum_threshold,
        })
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{PRIME_P, sub_mod};
    use crate::field::inv_mod;

    /// Construct a valid degree-`(t - 1)` polynomial passing through `(0, fake_secret)` and the
    /// first `t - 1` real validator shares `(1, shares[0]), ..., (t - 1, shares[t - 2])`, proving
    /// that any coalition of `< t` validators learns zero information about the true secret.
    fn assert_perfect_secrecy_below_threshold(
        shares: &[u128],
        threshold: usize,
        fake_secret: u128,
    ) {
        assert!(threshold >= 2 && shares.len() >= threshold);
        // Points: (0, fake_secret) and (1, shares[0]) .. (t-1, shares[t-2]) — `t` points uniquely
        // define a degree-(t-1) polynomial matching all `t - 1` observed shares identically.
        let mut xs = Vec::with_capacity(threshold);
        let mut ys = Vec::with_capacity(threshold);
        xs.push(0u128);
        ys.push(fake_secret);
        for j in 1..threshold {
            xs.push(j as u128);
            ys.push(shares[j - 1]);
        }
        // Evaluate interpolated polynomial at every observed point x = 1..t and at x = 0.
        let eval_at = |target: u128| -> u128 {
            let mut acc = 0u128;
            for i in 0..threshold {
                let mut num = 1u128;
                let mut den = 1u128;
                for m in 0..threshold {
                    if m == i {
                        continue;
                    }
                    num = mul_mod(num, sub_mod(target, xs[m]));
                    den = mul_mod(den, sub_mod(xs[i], xs[m]));
                }
                acc = add_mod(acc, mul_mod(ys[i], mul_mod(num, inv_mod(den))));
            }
            acc
        };
        assert_eq!(eval_at(0), fake_secret);
        for j in 1..threshold {
            assert_eq!(eval_at(j as u128), shares[j - 1]);
        }
    }

    #[test]
    fn test_dark_pool_amm_both_directions_mev_proof_and_pss_refresh() {
        let mut amm = ConfidentialDarkPoolAmm::new_default(1_000_000, 2_000_000).unwrap();
        let mut pool = BeaverPool::new_3_of_4(amm.triples_per_swap() * 4);

        // Verify redacted Debug never leaks reserve values.
        let dbg_amm = format!("{amm:?}");
        assert!(dbg_amm.contains("<redacted>"));
        assert!(!dbg_amm.contains("1000000"));
        assert!(!dbg_amm.contains("2000000"));

        // Swap 1: Sell 50_000 A for B (direction_bit = 0).
        let (swap_ab, quoted_b) = ConfidentialSwapRequest::build_honest(
            1_000_000,
            2_000_000,
            0,
            50_000,
            90_000,
            amm.fee_bps(),
            amm.bit_width(),
            amm.cache().threshold(),
            amm.cache().num_validators(),
        )
        .unwrap();

        // Redacted Debug on swap request.
        let dbg_req = format!("{swap_ab:?}");
        assert!(dbg_req.contains("<redacted>"));
        assert!(!dbg_req.contains("50000"));

        // Information-theoretic secrecy: < t = 2 colluding validators see identical distributions
        // for direction_bit = 0 or 1 and for ANY arbitrary fake amount_in.
        assert_perfect_secrecy_below_threshold(&swap_ab.direction_bit, 3, 1);
        assert_perfect_secrecy_below_threshold(&swap_ab.direction_bit, 3, 0);
        assert_perfect_secrecy_below_threshold(&swap_ab.amount_in, 3, 999_999_999);
        assert_perfect_secrecy_below_threshold(amm.reserve_a_shares(), 3, 42);

        amm.execute_swap(&swap_ab, &mut pool).unwrap();
        let (ra1, rb1) = amm.reconstruct_reserves().unwrap();
        assert_eq!(ra1, 1_000_000 + 50_000);
        assert_eq!(rb1, 2_000_000 - quoted_b);
        assert_eq!(amm.swaps_executed(), 1);
        assert!(ra1 * rb1 > 1_000_000u128 * 2_000_000u128);

        // Proactive Secret Sharing epoch refresh: rotates shares, preserves reserves,
        // and invalidates mixed old/new epoch shares!
        let old_a_shares = amm.reserve_a_shares().to_vec();
        let old_b_shares = amm.reserve_b_shares().to_vec();
        assert_eq!(amm.pss_epoch(), 1);
        amm.proactive_refresh_epoch().unwrap();
        assert_eq!(amm.pss_epoch(), 2);
        assert_ne!(amm.reserve_a_shares(), old_a_shares.as_slice());
        assert_ne!(amm.reserve_b_shares(), old_b_shares.as_slice());
        assert_eq!(amm.reconstruct_reserves().unwrap(), (ra1, rb1));

        let mut mixed_epoch = amm.reserve_a_shares().to_vec();
        mixed_epoch[0] = old_a_shares[0];
        assert_eq!(
            amm.cache().verify_shares(&mixed_epoch),
            Err(MpcError::InconsistentShares)
        );

        // Swap 2: Reverse direction! Sell 120_000 B for A (direction_bit = 1) after PSS refresh.
        let (swap_ba, quoted_a) = ConfidentialSwapRequest::build_honest(
            ra1,
            rb1,
            1,
            120_000,
            50_000,
            amm.fee_bps(),
            amm.bit_width(),
            amm.cache().threshold(),
            amm.cache().num_validators(),
        )
        .unwrap();

        assert_perfect_secrecy_below_threshold(&swap_ba.direction_bit, 3, 0);
        amm.execute_swap(&swap_ba, &mut pool).unwrap();

        let (ra2, rb2) = amm.reconstruct_reserves().unwrap();
        assert_eq!(ra2, ra1 - quoted_a);
        assert_eq!(rb2, rb1 + 120_000);
        assert_eq!(amm.swaps_executed(), 2);
        assert!(ra2 * rb2 > ra1 * rb1);
    }

    #[test]
    fn test_dark_pool_amm_rejects_underpaid_swap_pool_drain_and_bad_direction_atomically() {
        let init_a = 100_000u128;
        let init_b = 100_000u128;
        let mut amm = ConfidentialDarkPoolAmm::new(init_a, init_b, 30, 24, 3, 4).unwrap();
        let mut pool = BeaverPool::new_3_of_4(amm.triples_per_swap() * 6);
        let t = amm.cache().threshold();
        let n = amm.cache().num_validators();

        let (honest_req, quoted_out) = ConfidentialSwapRequest::build_honest(
            init_a,
            init_b,
            0,
            10_000,
            8_000,
            amm.fee_bps(),
            amm.bit_width(),
            t,
            n,
        )
        .unwrap();

        // Attack 1: Underpaid swap (attacker claims quoted_out + 1, violating constant product).
        let cheated_out = quoted_out + 1;
        let mut underpaid = ConfidentialSwapRequest {
            direction_bit: split_secret(0, t, n).unwrap(),
            amount_in: split_secret(10_000, t, n).unwrap(),
            amount_out: split_secret(cheated_out, t, n).unwrap(),
            min_amount_out: split_secret(8_000, t, n).unwrap(),
            amount_in_minus_1_bits: split_bits(10_000 - 1, 24, t, n).unwrap(),
            amount_out_bits: split_bits(cheated_out, 24, t, n).unwrap(),
            min_amount_out_bits: split_bits(8_000, 24, t, n).unwrap(),
            slippage_excess_bits: split_bits(cheated_out - 8_000, 24, t, n).unwrap(),
            new_reserve_a_minus_1_bits: split_bits(init_a + 10_000 - 1, 24, t, n).unwrap(),
            new_reserve_b_minus_1_bits: split_bits(init_b - cheated_out - 1, 24, t, n).unwrap(),
            surplus_bits: split_bits(0, amm.surplus_bit_width(), t, n).unwrap(),
        };
        assert!(matches!(
            amm.execute_swap(&underpaid, &mut pool),
            Err(MpcDefiError::InvariantViolation(_))
        ));
        assert_eq!(amm.reconstruct_reserves().unwrap(), (init_a, init_b));
        assert_eq!(amm.swaps_executed(), 0);

        // Attack 2: Pool drain attempt (attacker tries to drain entire reserve_b = 100_000).
        let drain_req = ConfidentialSwapRequest {
            direction_bit: split_secret(0, t, n).unwrap(),
            amount_in: split_secret(10_000, t, n).unwrap(),
            amount_out: split_secret(init_b, t, n).unwrap(),
            min_amount_out: split_secret(0, t, n).unwrap(),
            amount_in_minus_1_bits: split_bits(10_000 - 1, 24, t, n).unwrap(),
            amount_out_bits: split_bits(init_b, 24, t, n).unwrap(),
            min_amount_out_bits: split_bits(0, 24, t, n).unwrap(),
            slippage_excess_bits: split_bits(init_b, 24, t, n).unwrap(),
            new_reserve_a_minus_1_bits: split_bits(init_a + 10_000 - 1, 24, t, n).unwrap(),
            new_reserve_b_minus_1_bits: split_bits(0, 24, t, n).unwrap(),
            surplus_bits: split_bits(0, amm.surplus_bit_width(), t, n).unwrap(),
        };
        assert!(matches!(
            amm.execute_swap(&drain_req, &mut pool),
            Err(MpcDefiError::InvariantViolation(_))
        ));
        assert_eq!(amm.reconstruct_reserves().unwrap(), (init_a, init_b));

        // Attack 3: Non-binary direction bit (direction_bit = 2).
        underpaid.direction_bit = split_secret(2, t, n).unwrap();
        assert!(matches!(
            amm.execute_swap(&underpaid, &mut pool),
            Err(MpcDefiError::InvariantViolation(_))
        ));
        assert_eq!(amm.reconstruct_reserves().unwrap(), (init_a, init_b));

        // Attack 4: Slippage floor violation (amount_out < min_amount_out).
        let mut bad_slippage = ConfidentialSwapRequest::build_honest_with_output(
            init_a,
            init_b,
            0,
            10_000,
            quoted_out,
            quoted_out,
            amm.fee_bps(),
            amm.bit_width(),
            t,
            n,
        )
        .unwrap();
        bad_slippage.min_amount_out = split_secret(quoted_out + 5, t, n).unwrap();
        bad_slippage.min_amount_out_bits = split_bits(quoted_out + 5, 24, t, n).unwrap();
        assert!(matches!(
            amm.execute_swap(&bad_slippage, &mut pool),
            Err(MpcDefiError::InvariantViolation(_))
        ));
        assert_eq!(amm.reconstruct_reserves().unwrap(), (init_a, init_b));
        assert_eq!(amm.swaps_executed(), 0);

        // Confirm an honest swap still succeeds cleanly after all 4 atomic rollbacks.
        amm.execute_swap(&honest_req, &mut pool).unwrap();
        assert_eq!(
            amm.reconstruct_reserves().unwrap(),
            (init_a + 10_000, init_b - quoted_out)
        );
        assert_eq!(amm.swaps_executed(), 1);
    }

    #[test]
    fn test_sealed_bid_auction_first_price_and_vickrey_second_price_hides_losing_bids() {
        let bids_spec: [(u64, u128); 5] = [
            (101, 1_500),
            (202, 4_200),
            (303, 9_750), // winner
            (404, 6_800), // second-highest
            (505, 6_800), // tied second-highest
        ];

        // --- Mode 1: First-Price Auction ---
        let mut fp_auction =
            ConfidentialSealedBidAuction::new(AuctionMode::FirstPrice, 20, 3, 4).unwrap();
        let mut pool = BeaverPool::new_3_of_4(4_000);

        for &(bidder_id, amount) in &bids_spec {
            let bid = ConfidentialBid::build_honest(bidder_id, amount, 20, 3, 4).unwrap();
            let dbg_bid = format!("{bid:?}");
            assert!(dbg_bid.contains("<redacted>"));
            assert!(!dbg_bid.contains(&amount.to_string()));
            fp_auction.submit_bid(bid, &mut pool).unwrap();
        }
        // Verify < t secrecy on a stored losing bid before settlement.
        assert_perfect_secrecy_below_threshold(
            fp_auction.bid_amount_shares(0).unwrap(),
            3,
            777_777,
        );
        // Verify PSS refresh preserves auction correctness.
        fp_auction.proactive_refresh_epoch().unwrap();
        assert_eq!(fp_auction.pss_epoch(), 2);

        let fp_res = fp_auction.settle(&mut pool).unwrap();
        assert_eq!(
            fp_res,
            AuctionSettlement {
                mode: AuctionMode::FirstPrice,
                winner_id: 303,
                clearing_price: 9_750,
                num_bidders: 5,
            }
        );
        assert!(fp_auction.is_settled());
        assert_eq!(fp_auction.num_bids(), 0); // All sealed bids wiped on settlement.
        assert_eq!(
            fp_auction.settle(&mut pool),
            Err(MpcDefiError::AuctionAlreadySettled)
        );

        // --- Mode 2: Vickrey Second-Price Auction ---
        let mut vickrey =
            ConfidentialSealedBidAuction::new(AuctionMode::VickreySecondPrice, 20, 3, 4).unwrap();
        for &(bidder_id, amount) in &bids_spec {
            let bid = ConfidentialBid::build_honest(bidder_id, amount, 20, 3, 4).unwrap();
            vickrey.submit_bid(bid, &mut pool).unwrap();
        }
        let v_res = vickrey.settle(&mut pool).unwrap();
        assert_eq!(
            v_res,
            AuctionSettlement {
                mode: AuctionMode::VickreySecondPrice,
                winner_id: 303,
                clearing_price: 6_800,
                num_bidders: 5,
            }
        );
        assert_eq!(vickrey.num_bids(), 0);

        // --- Vickrey Tie Case: two equal top bids -> earliest bidder wins & pays top bid ---
        let mut tie_auction =
            ConfidentialSealedBidAuction::new(AuctionMode::VickreySecondPrice, 16, 3, 4).unwrap();
        let b1 = ConfidentialBid::build_honest(11, 500, 16, 3, 4).unwrap();
        let b2 = ConfidentialBid::build_honest(22, 500, 16, 3, 4).unwrap();
        let b3 = ConfidentialBid::build_honest(33, 250, 16, 3, 4).unwrap();
        tie_auction.submit_bid(b1, &mut pool).unwrap();
        tie_auction.submit_bid(b2, &mut pool).unwrap();
        tie_auction.submit_bid(b3, &mut pool).unwrap();
        let tie_res = tie_auction.settle(&mut pool).unwrap();
        assert_eq!(tie_res.winner_id, 11);
        assert_eq!(tie_res.clearing_price, 500);
    }

    #[test]
    fn test_sealed_bid_auction_rejects_out_of_range_forged_bid() {
        let mut auction =
            ConfidentialSealedBidAuction::new(AuctionMode::VickreySecondPrice, 16, 3, 4).unwrap();
        let mut pool = BeaverPool::new_3_of_4(1_000);

        // Forge 1: Claim amount = 2^16 + 50 (out of 16-bit range!) with valid 16-bit decomposition
        // of 50 -> `amount - compose(bits) != 0`.
        let forged_overflow = ConfidentialBid {
            bidder_id: 901,
            amount: split_secret((1u128 << 16) + 50, 3, 4).unwrap(),
            amount_bits: split_bits(50, 16, 3, 4).unwrap(),
        };
        assert!(matches!(
            auction.submit_bid(forged_overflow, &mut pool),
            Err(MpcDefiError::RangeProofFailed(_))
        ));
        assert_eq!(auction.num_bids(), 0);

        // Forge 2: Non-binary bit (`bit_15 = 3`) attempting to inflate bid above 2^16 - 1
        // while keeping `amount == sum 2^k b_k`!
        let mut forged_non_binary_bits = split_bits(0, 16, 3, 4).unwrap();
        forged_non_binary_bits[15] = split_secret(3, 3, 4).unwrap();
        let forged_non_binary = ConfidentialBid {
            bidder_id: 902,
            amount: split_secret(3u128 << 15, 3, 4).unwrap(),
            amount_bits: forged_non_binary_bits,
        };
        assert!(matches!(
            auction.submit_bid(forged_non_binary, &mut pool),
            Err(MpcDefiError::RangeProofFailed(_))
        ));
        assert_eq!(auction.num_bids(), 0);

        // Forge 3: Negative field element (`PRIME_P - 1`) disguised as a bid.
        let forged_negative = ConfidentialBid {
            bidder_id: 903,
            amount: split_secret(PRIME_P - 1, 3, 4).unwrap(),
            amount_bits: split_bits(0, 16, 3, 4).unwrap(),
        };
        assert!(matches!(
            auction.submit_bid(forged_negative, &mut pool),
            Err(MpcDefiError::RangeProofFailed(_))
        ));
        assert_eq!(auction.num_bids(), 0);

        // Honest bid after rejections succeeds cleanly, and duplicate bidder is rejected.
        let honest = ConfidentialBid::build_honest(77, 1_234, 16, 3, 4).unwrap();
        auction.submit_bid(honest, &mut pool).unwrap();
        assert_eq!(auction.num_bids(), 1);

        let dup = ConfidentialBid::build_honest(77, 2_000, 16, 3, 4).unwrap();
        assert_eq!(
            auction.submit_bid(dup, &mut pool),
            Err(MpcDefiError::DuplicateBidder { bidder_id: 77 })
        );
    }

    #[test]
    fn test_confidential_ballot_box_tallies_honest_votes_and_rejects_double_or_negative_vote() {
        let mut box_main = ConfidentialBallotBox::new_default(4, 5).unwrap();
        let mut pool = BeaverPool::new_3_of_4(500);

        // Cast 5 honest ballots: option 0 gets 1 vote, option 1 gets 3 votes, option 2 gets 1 vote,
        // option 3 gets 0 votes.
        let votes = [(1u64, 1usize), (2, 0), (3, 1), (4, 2), (5, 1)];
        for &(voter_id, opt) in &votes {
            let ballot = ConfidentialBallot::build_honest(voter_id, opt, 4, 3, 4).unwrap();
            let dbg_ballot = format!("{ballot:?}");
            assert!(dbg_ballot.contains("<redacted>"));
            // Verify < t secrecy on every option share of each ballot.
            assert_perfect_secrecy_below_threshold(&ballot.option_shares[opt], 3, 0);
            box_main.cast_ballot(&ballot, &mut pool).unwrap();
        }

        // Attack 1: Double-vote `[1, 1, 0, 0]` (each bit binary, but sum == 2 != 1).
        let double_vote = ConfidentialBallot {
            voter_id: 90,
            weight: 1,
            option_shares: vec![
                split_secret(1, 3, 4).unwrap(),
                split_secret(1, 3, 4).unwrap(),
                split_secret(0, 3, 4).unwrap(),
                split_secret(0, 3, 4).unwrap(),
            ],
        };
        assert!(matches!(
            box_main.cast_ballot(&double_vote, &mut pool),
            Err(MpcDefiError::InvalidBallot(_))
        ));

        // Attack 2: Negative + boosted vote `[2, PRIME_P - 1, 0, 0]` (sum == 1 mod P, but
        // non-binary entries attempt to subtract a vote from option 1 and give +2 to option 0!).
        let negative_vote = ConfidentialBallot {
            voter_id: 91,
            weight: 1,
            option_shares: vec![
                split_secret(2, 3, 4).unwrap(),
                split_secret(PRIME_P - 1, 3, 4).unwrap(),
                split_secret(0, 3, 4).unwrap(),
                split_secret(0, 3, 4).unwrap(),
            ],
        };
        assert!(matches!(
            box_main.cast_ballot(&negative_vote, &mut pool),
            Err(MpcDefiError::InvalidBallot(_))
        ));

        // Attack 3: All-zero abstention ballot `[0, 0, 0, 0]` (sum == 0 != 1).
        let zero_vote = ConfidentialBallot {
            voter_id: 92,
            weight: 1,
            option_shares: vec![
                split_secret(0, 3, 4).unwrap(),
                split_secret(0, 3, 4).unwrap(),
                split_secret(0, 3, 4).unwrap(),
                split_secret(0, 3, 4).unwrap(),
            ],
        };
        assert!(matches!(
            box_main.cast_ballot(&zero_vote, &mut pool),
            Err(MpcDefiError::InvalidBallot(_))
        ));

        // Attack 4: Duplicate voter ID.
        let dup_voter = ConfidentialBallot::build_honest(1, 3, 4, 3, 4).unwrap();
        assert_eq!(
            box_main.cast_ballot(&dup_voter, &mut pool),
            Err(MpcDefiError::DuplicateVoter { voter_id: 1 })
        );

        // Rotate tally shares via PSS before revealing.
        box_main.proactive_refresh_epoch().unwrap();
        assert_eq!(box_main.pss_epoch(), 2);

        // Demonstrate 0-Beaver-triple linear merging of a weighted shard box!
        let mut box_shard = ConfidentialBallotBox::new_default(4, 5).unwrap();
        let weighted_ballot = ConfidentialBallot::build_weighted(6, 2, 1, 4, 3, 4).unwrap();
        box_shard.cast_ballot(&weighted_ballot, &mut pool).unwrap();

        let triples_before_linear_merge = pool.len();
        box_main.merge_linear(&box_shard).unwrap();
        assert_eq!(pool.len(), triples_before_linear_merge); // 0 Beaver triples consumed!

        let tally = box_main.tally_and_reveal().unwrap();
        assert_eq!(
            tally,
            BallotTallyResult {
                option_totals: vec![1, 5, 1, 0],
                total_votes: 7,
                ballots_cast: 6,
                winning_option: Some(1),
                is_tie: false,
                quorum_met: true,
            }
        );
    }
}
