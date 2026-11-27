//! Verified Proof-of-Pad (PoP) Mining & Interactive Information-Theoretic Slashing Audits
//! for Vernam (VRNM).
//!
//! Zero external crates, zero computational cryptography (no SHA-256, RSA, ECDSA, or AES).
//!
//! Instead of energy-wasting Proof-of-Work hash puzzles, validators ("pad miners") earn
//! `VRNM` epoch rewards by proving — via interactive information-theoretic audits — that
//! they produced genuine, fresh, high-entropy OTP pad batches, algebraically valid MPC
//! Beaver triples over `F_(2^127 - 1)`, and clean low-QBER BB84/Decoy-State QKD key
//! replenishment:
//!
//! 1. **Statistical Entropy Audit (`EntropyAuditStats`)**:
//!    - All-zero / constant-output detection and byte-uniqueness verification.
//!    - Monobit balance z-score (`|2*ones - n| / sqrt(n)`), cross-checked with `qkd::check_entropy_health`.
//!    - Wald-Wolfowitz / NIST SP 800-22 bit-transition Runs Test (catches alternating bit
//!      patterns such as `0xAA` or `0x55` that pass monobit balance at exactly 50%).
//! 2. **Interactive Carter-Wegman Pad Commitment (`PopChallenge` & `PopProof`)**:
//!    - Auditor issues a fresh uniform challenge scalar `challenge_r` in `F_(2^127 - 1)`,
//!      independent one-time Carter-Wegman pad masks, and random pad/triple slot selectors.
//!    - Miner commits to its entire pad batch with Carter-Wegman polynomial digests over
//!      `F_(2^127 - 1)` and sacrifices one randomly selected Beaver triple `(a, b, c)` plus
//!      one randomly selected pad page for public inspection.
//!    - Auditor verifies commitment tags in constant time (`ct_eq_16`), checks `a * b == c (mod P)`
//!      with `a != 0, b != 0`, validates sacrificed pad entropy, rejects duplicated pad pages,
//!      and enforces BB84 QBER (`<= 0.11`) and decoy-state yield ratio bounds.
//! 3. **Epoch Coordinator (`PopEpochCoordinator`)**:
//!    - Audits every validator's `PopProof` against `TokenomicsEngine`, credits verified
//!      `EpochContribution` records for honest validators, automatically slashes cheating
//!      validators (`InconsistentMpcShare` 50% bond burn for invalid Beaver triples / forged
//!      pads / tampered commitments; `ExtendedDowntime` 10% bond burn for compromised QKD
//!      replenishment), and settles the halving `VRNM` epoch subsidy + 80% fee pool.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, fill_os_random, mul_mod, random_field_elem, reduce, zeroize_slice,
    zeroize_u128,
};
use crate::qkd::{
    BB84_QBER_ABORT_THRESHOLD, Bb84Channel, Bb84ExchangeResult, EntropySource, QkdError,
    check_entropy_health,
};
use crate::tokenomics::{
    AuditTag, EpochContribution, EpochSettlement, SlashingOffense, SlashingReceipt,
    TokenomicsEngine, ValidatorId,
};

/// Standard OTP pad page size in bytes (256 B = 2048 bits, matching Express OTP frames and
/// `qkd.rs` Toeplitz privacy-amplification blocks).
pub const PAD_PAGE_BYTES: usize = 256;

/// Minimum pad sample length in bytes accepted by the entropy auditor (32 B = 256 bits).
pub const MIN_AUDIT_SAMPLE_BYTES: usize = 32;

/// Default monobit balance z-score ceiling (`6.0` sigma -> false-positive rate < 2e-9).
pub const DEFAULT_MAX_MONOBIT_Z: f64 = 6.0;

/// Default Wald-Wolfowitz bit-runs z-score ceiling (`6.0` sigma -> false-positive rate < 2e-9).
pub const DEFAULT_MAX_RUNS_Z: f64 = 6.0;

/// Maximum permitted BB84 Quantum Bit Error Rate (Shor-Preskill 11% bound).
pub const MAX_ALLOWED_QBER: f64 = BB84_QBER_ABORT_THRESHOLD;

/// Minimum valid normalized decoy-state yield ratio (catches selective signal attenuation).
pub const MIN_DECOY_YIELD_RATIO: f64 = 0.55;

/// Maximum valid normalized decoy-state yield ratio (catches Photon-Number-Splitting attacks).
pub const MAX_DECOY_YIELD_RATIO: f64 = 1.08;

/// Number of random pad slot indices sampled per interactive PoP challenge.
pub const DEFAULT_CHALLENGE_SLOT_COUNT: usize = 4;

// ============================================================================
// Errors & Audit Policy
// ============================================================================

/// Detailed errors returned during Proof-of-Pad mining, auditing, or epoch settlement.
#[derive(Debug, Clone, PartialEq)]
pub enum PopError {
    /// Batch contains zero pad pages or zero Beaver triples.
    EmptyBatch(&'static str),
    /// Underlying QKD channel failed while mining pads.
    QkdChannelError(String),
    /// Proof does not match the issued challenge (wrong validator, epoch, slot, or duplicate).
    ChallengeMismatch(String),
    /// Constant-time Carter-Wegman commitment tag verification failed.
    InvalidCommitmentTag(&'static str),
    /// Sacrificed MPC Beaver triple failed algebraic verification (`a * b != c mod P` or zero).
    InvalidBeaverTriple {
        a: u128,
        b: u128,
        c: u128,
        expected_c: u128,
        reason: String,
    },
    /// Sacrificed pad sample failed statistical entropy checks (all-zero, monobit, runs, uniqueness).
    EntropyAuditFailed {
        reason: String,
        stats: Option<EntropyAuditStats>,
    },
    /// Miner cloned identical pad pages across multiple slots in the same batch.
    DuplicatePadPages { unique_pages: usize, claimed_pages: usize },
    /// Reported BB84 QBER exceeded the Shor-Preskill unconditional security bound (`0.11`).
    QkdQberExceeded { qber: f64, max_qber: f64 },
    /// Reported decoy-state yield ratio or single-photon lower bound indicates a PNS/attenuation attack.
    QkdDecoyAnomaly {
        decoy_yield_ratio: f64,
        min_ratio: f64,
        max_ratio: f64,
        single_photon_yield_lower_bound: f64,
    },
    /// Tokenomics engine rejected recording a contribution or slashing.
    TokenomicsFailure(String),
    /// Invalid configuration or argument.
    InvalidParameter(&'static str),
}

impl PopError {
    /// Map an audit rejection to its corresponding `TokenomicsEngine` slashing offense.
    ///
    /// - Corrupted Beaver triples (`a * b != c`), forged/low-entropy fake pads, duplicate pad
    ///   cloning, tampered Carter-Wegman tags, and challenge spoofing trigger a **50% bond burn**
    ///   (`SlashingOffense::InconsistentMpcShare`).
    /// - High-QBER / decoy-anomaly QKD links or empty batches trigger a **10% bond burn**
    ///   (`SlashingOffense::ExtendedDowntime`) for failing clean pad replenishment.
    pub const fn slashing_offense(&self) -> Option<SlashingOffense> {
        match self {
            Self::InvalidBeaverTriple { .. }
            | Self::EntropyAuditFailed { .. }
            | Self::InvalidCommitmentTag(_)
            | Self::DuplicatePadPages { .. }
            | Self::ChallengeMismatch(_) => Some(SlashingOffense::InconsistentMpcShare),
            Self::QkdQberExceeded { .. }
            | Self::QkdDecoyAnomaly { .. }
            | Self::EmptyBatch(_) => Some(SlashingOffense::ExtendedDowntime),
            Self::QkdChannelError(_) | Self::TokenomicsFailure(_) | Self::InvalidParameter(_) => {
                None
            }
        }
    }
}

impl fmt::Display for PopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBatch(msg) => write!(f, "empty PoP batch: {msg}"),
            Self::QkdChannelError(msg) => write!(f, "QKD channel error during PoP mining: {msg}"),
            Self::ChallengeMismatch(msg) => write!(f, "PoP challenge mismatch: {msg}"),
            Self::InvalidCommitmentTag(kind) => {
                write!(f, "Carter-Wegman commitment verification failed ({kind})")
            }
            Self::InvalidBeaverTriple {
                a,
                b,
                c,
                expected_c,
                reason,
            } => write!(
                f,
                "invalid sacrificed Beaver triple ({reason}): a={a}, b={b}, c={c}, expected={expected_c}"
            ),
            Self::EntropyAuditFailed { reason, .. } => {
                write!(f, "pad entropy audit failed: {reason}")
            }
            Self::DuplicatePadPages {
                unique_pages,
                claimed_pages,
            } => write!(
                f,
                "duplicate pad pages detected: only {unique_pages} distinct digests out of {claimed_pages} claimed"
            ),
            Self::QkdQberExceeded { qber, max_qber } => write!(
                f,
                "QKD QBER {:.4} exceeds maximum allowed {:.4}",
                qber, max_qber
            ),
            Self::QkdDecoyAnomaly {
                decoy_yield_ratio,
                min_ratio,
                max_ratio,
                single_photon_yield_lower_bound,
            } => write!(
                f,
                "QKD decoy-state anomaly: ratio={:.4} outside [{:.4}, {:.4}], Y1_L={:.4}",
                decoy_yield_ratio, min_ratio, max_ratio, single_photon_yield_lower_bound
            ),
            Self::TokenomicsFailure(msg) => write!(f, "tokenomics integration error: {msg}"),
            Self::InvalidParameter(msg) => write!(f, "invalid PoP parameter: {msg}"),
        }
    }
}

impl Error for PopError {}

impl From<QkdError> for PopError {
    fn from(err: QkdError) -> Self {
        Self::QkdChannelError(err.to_string())
    }
}

/// Configurable verification thresholds for `PopAuditor`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PopAuditPolicy {
    /// Minimum sacrificed pad sample size in bytes (default: `32`).
    pub min_sample_bytes: usize,
    /// Maximum allowed monobit balance z-score (default: `6.0`).
    pub max_monobit_z_score: f64,
    /// Maximum allowed bit-runs z-score (default: `6.0`).
    pub max_runs_z_score: f64,
    /// Maximum permitted BB84 QBER (default: `0.11`).
    pub max_qber: f64,
    /// Minimum permitted normalized decoy-state yield ratio (default: `0.55`).
    pub min_decoy_yield_ratio: f64,
    /// Maximum permitted normalized decoy-state yield ratio (default: `1.08`).
    pub max_decoy_yield_ratio: f64,
}

impl Default for PopAuditPolicy {
    fn default() -> Self {
        Self {
            min_sample_bytes: MIN_AUDIT_SAMPLE_BYTES,
            max_monobit_z_score: DEFAULT_MAX_MONOBIT_Z,
            max_runs_z_score: DEFAULT_MAX_RUNS_Z,
            max_qber: MAX_ALLOWED_QBER,
            min_decoy_yield_ratio: MIN_DECOY_YIELD_RATIO,
            max_decoy_yield_ratio: MAX_DECOY_YIELD_RATIO,
        }
    }
}

// ============================================================================
// Step 1: Statistical Entropy Quality Check (`EntropyAuditStats`)
// ============================================================================

/// Statistical quality metrics measured on a sacrificed OTP pad sample.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyAuditStats {
    /// Sample size in bytes.
    pub sample_bytes: usize,
    /// Sample size in bits (`sample_bytes * 8`).
    pub total_bits: usize,
    /// Number of `1` bits observed.
    pub ones_count: usize,
    /// Fraction of `1` bits (`ones_count / total_bits`).
    pub ones_ratio: f64,
    /// Monobit balance z-score: `|2 * ones - n| / sqrt(n)`.
    pub monobit_z_score: f64,
    /// Observed number of maximal constant-bit runs (`1 + bit_transitions`).
    pub runs_count: usize,
    /// Conditional expected runs under Wald-Wolfowitz (`1 + 2 * n1 * n0 / n`).
    pub expected_runs: f64,
    /// Runs-test z-score `|runs_count - expected_runs| / sigma_runs`.
    pub runs_z_score: f64,
    /// Number of distinct byte values observed (`0..=256`).
    pub unique_bytes: usize,
    /// Number of non-zero bytes observed.
    pub non_zero_bytes: usize,
}

/// Evaluate monobit balance, Wald-Wolfowitz bit-runs, byte uniqueness, and non-zero checks
/// on a pad sample using the default PoP thresholds (`6.0` sigma).
pub fn audit_pad_entropy(sample: &[u8]) -> Result<EntropyAuditStats, PopError> {
    audit_pad_entropy_with_policy(sample, &PopAuditPolicy::default())
}

/// Evaluate pad sample entropy against an explicit `PopAuditPolicy`.
pub fn audit_pad_entropy_with_policy(
    sample: &[u8],
    policy: &PopAuditPolicy,
) -> Result<EntropyAuditStats, PopError> {
    let sample_bytes = sample.len();
    let min_bytes = policy.min_sample_bytes.max(MIN_AUDIT_SAMPLE_BYTES);
    if sample_bytes < min_bytes {
        return Err(PopError::EntropyAuditFailed {
            reason: format!(
                "pad sample too short: {sample_bytes} bytes < minimum {min_bytes} bytes"
            ),
            stats: None,
        });
    }

    let total_bits = sample_bytes * 8;
    let mut ones_count = 0usize;
    let mut non_zero_bytes = 0usize;
    let mut seen = [false; 256];
    let mut unique_bytes = 0usize;

    for &b in sample {
        ones_count += b.count_ones() as usize;
        if b != 0 {
            non_zero_bytes += 1;
        }
        if !seen[b as usize] {
            seen[b as usize] = true;
            unique_bytes += 1;
        }
    }

    let ones_ratio = ones_count as f64 / total_bits as f64;
    let monobit_z_score =
        ((2.0 * ones_count as f64) - (total_bits as f64)).abs() / (total_bits as f64).sqrt();

    // Count bit runs (LSB-first within each byte, matching qkd.rs bit ordering).
    let mut runs_count = 1usize;
    let mut prev_bit = sample[0] & 1;
    for (byte_idx, &byte) in sample.iter().enumerate() {
        let start_bit = if byte_idx == 0 { 1 } else { 0 };
        for bit in start_bit..8 {
            let cur = (byte >> bit) & 1;
            if cur != prev_bit {
                runs_count += 1;
                prev_bit = cur;
            }
        }
    }

    let n = total_bits as f64;
    let n1 = ones_count as f64;
    let n0 = (total_bits - ones_count) as f64;
    let (expected_runs, runs_z_score) = if n1 == 0.0 || n0 == 0.0 {
        (1.0, f64::INFINITY)
    } else {
        let two_n1_n0 = 2.0 * n1 * n0;
        let expected = 1.0 + (two_n1_n0 / n);
        let var_num = two_n1_n0 * (two_n1_n0 - n);
        let var_den = n * n * (n - 1.0);
        let variance = (var_num / var_den).max(0.0);
        let z = if variance > 0.0 {
            (runs_count as f64 - expected).abs() / variance.sqrt()
        } else {
            f64::INFINITY
        };
        (expected, z)
    };

    let stats = EntropyAuditStats {
        sample_bytes,
        total_bits,
        ones_count,
        ones_ratio,
        monobit_z_score,
        runs_count,
        expected_runs,
        runs_z_score,
        unique_bytes,
        non_zero_bytes,
    };

    // 1. Reject all-zero pads immediately.
    if non_zero_bytes == 0 {
        return Err(PopError::EntropyAuditFailed {
            reason: format!("all-zero fake pad detected ({sample_bytes} zero bytes)"),
            stats: Some(stats),
        });
    }

    // 2. Monobit balance test (|2*ones - n| / sqrt(n) <= max_monobit_z_score).
    if !monobit_z_score.is_finite() || monobit_z_score > policy.max_monobit_z_score {
        return Err(PopError::EntropyAuditFailed {
            reason: format!(
                "monobit test failed: ones_ratio={ones_ratio:.4}, z={monobit_z_score:.2} > {:.2}",
                policy.max_monobit_z_score
            ),
            stats: Some(stats),
        });
    }

    // 3. Bit-transition Runs test (catches 0xAA / 0x55 / 0x0F repeating patterns that pass monobit!).
    if !runs_z_score.is_finite() || runs_z_score > policy.max_runs_z_score {
        return Err(PopError::EntropyAuditFailed {
            reason: format!(
                "runs test failed: observed={runs_count}, expected={expected_runs:.1}, z={runs_z_score:.2} > {:.2}",
                policy.max_runs_z_score
            ),
            stats: Some(stats),
        });
    }

    // 4. Byte-uniqueness / non-constant check (catches low-alphabet synthetic pads).
    let min_unique = (sample_bytes / 4).clamp(4, 32);
    if unique_bytes < min_unique {
        return Err(PopError::EntropyAuditFailed {
            reason: format!(
                "byte-uniqueness check failed: only {unique_bytes} distinct byte values (minimum {min_unique} for {sample_bytes}B)"
            ),
            stats: Some(stats),
        });
    }

    // 5. Cross-check against `crate::qkd::check_entropy_health`.
    if let Err(qkd_err) = check_entropy_health(sample, policy.max_monobit_z_score) {
        return Err(PopError::EntropyAuditFailed {
            reason: qkd_err.to_string(),
            stats: Some(stats),
        });
    }

    Ok(stats)
}

// ============================================================================
// Beaver Triples & QKD Telemetry
// ============================================================================

/// An information-theoretic MPC Beaver multiplication triple `(a, b, c)` over `F_(2^127 - 1)`
/// satisfying `c = (a * b) mod PRIME_P` with `a != 0` and `b != 0`.
///
/// Secret field elements are volatile-zeroized on `Drop`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaverTriple {
    pub a: u128,
    pub b: u128,
    pub c: u128,
}

impl BeaverTriple {
    /// Generate a fresh non-trivial Beaver triple over `F_(2^127 - 1)` using OS randomness.
    pub fn generate() -> Self {
        let a = random_nonzero_field_elem();
        let b = random_nonzero_field_elem();
        let c = mul_mod(a, b);
        Self { a, b, c }
    }

    /// Derive a non-trivial Beaver triple from 32 bytes of purified QKD key material
    /// (falling back to OS rejection sampling only in the ~2^-126 zero/overflow event).
    pub fn from_purified_bytes(bytes: &[u8; 32]) -> Self {
        let mut a_buf = [0u8; 16];
        let mut b_buf = [0u8; 16];
        a_buf.copy_from_slice(&bytes[..16]);
        b_buf.copy_from_slice(&bytes[16..32]);

        let raw_a = u128::from_le_bytes(a_buf) & PRIME_P;
        let raw_b = u128::from_le_bytes(b_buf) & PRIME_P;
        zeroize_slice(&mut a_buf);
        zeroize_slice(&mut b_buf);

        let a = if raw_a > 0 && raw_a < PRIME_P {
            raw_a
        } else {
            random_nonzero_field_elem()
        };
        let b = if raw_b > 0 && raw_b < PRIME_P {
            raw_b
        } else {
            random_nonzero_field_elem()
        };
        let c = mul_mod(a, b);
        Self { a, b, c }
    }

    /// Construct a trivial all-zero triple (used as a sentinel for empty batches or negative tests).
    pub const fn zero() -> Self {
        Self { a: 0, b: 0, c: 0 }
    }

    /// Verify algebraic validity over `F_(2^127 - 1)`: `a != 0`, `b != 0`, canonical range,
    /// and `mul_mod(a, b) == c`.
    pub fn verify(&self) -> Result<(), PopError> {
        if self.a >= PRIME_P || self.b >= PRIME_P || self.c >= PRIME_P {
            return Err(PopError::InvalidBeaverTriple {
                a: self.a,
                b: self.b,
                c: self.c,
                expected_c: mul_mod(self.a, self.b),
                reason: "triple element out of canonical F_(2^127 - 1) range".into(),
            });
        }
        if self.a == 0 || self.b == 0 {
            return Err(PopError::InvalidBeaverTriple {
                a: self.a,
                b: self.b,
                c: self.c,
                expected_c: 0,
                reason: "trivial zero operand (a == 0 or b == 0) rejected".into(),
            });
        }
        let expected_c = mul_mod(self.a, self.b);
        if self.c != expected_c {
            return Err(PopError::InvalidBeaverTriple {
                a: self.a,
                b: self.b,
                c: self.c,
                expected_c,
                reason: "multiplicative relation mul_mod(a, b) == c violated".into(),
            });
        }
        Ok(())
    }
}

impl Drop for BeaverTriple {
    fn drop(&mut self) {
        zeroize_u128(&mut self.a);
        zeroize_u128(&mut self.b);
        zeroize_u128(&mut self.c);
    }
}

/// BB84 + Decoy-State QKD link telemetry recorded during pad batch replenishment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QkdTelemetry {
    /// Observed Quantum Bit Error Rate on the sacrificed BB84 sample.
    pub qber: f64,
    /// Total sifted bits produced before privacy amplification.
    pub sifted_bits: usize,
    /// Observed gain `Q_mu` of signal pulses.
    pub signal_yield: f64,
    /// Observed gain `Q_nu` of weak decoy pulses.
    pub decoy_yield: f64,
    /// Observed gain `Y_0` of vacuum pulses.
    pub vacuum_yield: f64,
    /// Normalized decoy yield ratio `((Q_mu - Y_0)/mu) / ((Q_nu - Y_0)/nu)`.
    pub decoy_yield_ratio: f64,
    /// Ma-Lo-Chen lower bound `Y_1^L` on single-photon detection yield.
    pub single_photon_yield_lower_bound: f64,
}

impl QkdTelemetry {
    /// Extract QKD telemetry from a completed `Bb84ExchangeResult`.
    pub const fn from_exchange(exchange: &Bb84ExchangeResult) -> Self {
        Self {
            qber: exchange.qber,
            sifted_bits: exchange.sifted_bits,
            signal_yield: exchange.signal_yield,
            decoy_yield: exchange.decoy_yield,
            vacuum_yield: exchange.vacuum_yield,
            decoy_yield_ratio: exchange.decoy_yield_ratio,
            single_photon_yield_lower_bound: exchange.single_photon_yield_lower_bound,
        }
    }

    /// Clean synthetic telemetry representing a nominal honest BB84 link (useful for tests).
    pub const fn nominal_clean() -> Self {
        Self {
            qber: 0.015,
            sifted_bits: 32_768,
            signal_yield: 0.40,
            decoy_yield: 0.16,
            vacuum_yield: 0.0,
            decoy_yield_ratio: 0.85,
            single_photon_yield_lower_bound: 0.80,
        }
    }

    /// Validate QKD QBER and decoy-state bounds against `policy`.
    pub fn verify(&self, policy: &PopAuditPolicy) -> Result<(), PopError> {
        if !self.qber.is_finite() || self.qber < 0.0 || self.qber > policy.max_qber {
            return Err(PopError::QkdQberExceeded {
                qber: self.qber,
                max_qber: policy.max_qber,
            });
        }
        if !self.decoy_yield_ratio.is_finite()
            || self.decoy_yield_ratio < policy.min_decoy_yield_ratio
            || self.decoy_yield_ratio > policy.max_decoy_yield_ratio
            || !self.single_photon_yield_lower_bound.is_finite()
            || self.single_photon_yield_lower_bound <= 0.0
        {
            return Err(PopError::QkdDecoyAnomaly {
                decoy_yield_ratio: self.decoy_yield_ratio,
                min_ratio: policy.min_decoy_yield_ratio,
                max_ratio: policy.max_decoy_yield_ratio,
                single_photon_yield_lower_bound: self.single_photon_yield_lower_bound,
            });
        }
        Ok(())
    }
}

// ============================================================================
// Step 2: Carter-Wegman Polynomial Commitments over F_(2^127 - 1)
// ============================================================================

/// Uniform random non-zero element in `F_(2^127 - 1)`.
pub fn random_nonzero_field_elem() -> u128 {
    loop {
        let v = random_field_elem();
        if v != 0 {
            return v;
        }
    }
}

/// Uniform random `usize` derived from OS entropy (used for unpredictable audit slot indices).
fn random_usize() -> usize {
    let mut buf = [0u8; 8];
    fill_os_random(&mut buf);
    let val = u64::from_le_bytes(buf) as usize;
    zeroize_slice(&mut buf);
    val
}

/// Compute a universal Carter-Wegman polynomial digest over `F_(2^127 - 1)` for a byte slice.
///
/// Packs input bytes into 15-byte (120-bit) limbs strictly below `PRIME_P = 2^127 - 1`
/// and absorbs the exact byte length first to prevent zero-extension collisions.
pub fn cw_poly_digest(data: &[u8], challenge_r: u128) -> u128 {
    let r = reduce(challenge_r);
    let mut acc = reduce(data.len() as u128);
    for chunk in data.chunks(15) {
        let mut limb_bytes = [0u8; 16];
        limb_bytes[..chunk.len()].copy_from_slice(chunk);
        let limb = u128::from_le_bytes(limb_bytes);
        acc = mul_mod(add_mod(acc, limb), r);
    }
    acc
}

/// Compute the 128-bit Carter-Wegman MAC tag binding the sacrificed pad sample and its slot metadata.
pub fn compute_sample_commitment_tag(
    validator_id: ValidatorId,
    epoch: u64,
    audited_pad_index: usize,
    audit_pad_sample: &[u8],
    challenge_r: u128,
    sample_mask_s: u128,
) -> AuditTag {
    let r = reduce(challenge_r);
    let mut acc = cw_poly_digest(audit_pad_sample, r);
    acc = mul_mod(add_mod(acc, reduce(validator_id as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(epoch as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(audited_pad_index as u128)), r);
    add_mod(acc, reduce(sample_mask_s)).to_le_bytes()
}

/// Compute the 128-bit Carter-Wegman MAC tag committing to every pad page digest in the batch.
pub fn compute_batch_commitment_tag(
    validator_id: ValidatorId,
    epoch: u64,
    page_digests: &[u128],
    challenge_r: u128,
    batch_mask_s: u128,
) -> AuditTag {
    let r = reduce(challenge_r);
    let mut acc = reduce(page_digests.len() as u128);
    acc = mul_mod(add_mod(acc, reduce(validator_id as u128)), r);
    acc = mul_mod(add_mod(acc, reduce(epoch as u128)), r);
    for &digest in page_digests {
        acc = mul_mod(add_mod(acc, reduce(digest)), r);
    }
    add_mod(acc, reduce(batch_mask_s)).to_le_bytes()
}

/// Compute the 128-bit Carter-Wegman MAC tag over the randomly challenged pad slot indices.
pub fn compute_challenged_slots_tag(
    validator_id: ValidatorId,
    epoch: u64,
    page_digests: &[u128],
    pad_slot_indices: &[usize],
    challenge_r: u128,
    slots_mask_s: u128,
) -> AuditTag {
    let r = reduce(challenge_r);
    let mut acc = reduce(validator_id as u128);
    acc = mul_mod(add_mod(acc, reduce(epoch as u128)), r);
    if !page_digests.is_empty() {
        for &raw_slot in pad_slot_indices {
            let idx = raw_slot % page_digests.len();
            acc = mul_mod(add_mod(acc, reduce(idx as u128)), r);
            acc = mul_mod(add_mod(acc, reduce(page_digests[idx])), r);
        }
    }
    add_mod(acc, reduce(slots_mask_s)).to_le_bytes()
}

// ============================================================================
// Mined Pad Batch, Challenge, Proof & Verification Receipt
// ============================================================================

/// A freshly mined batch of purified OTP pad pages and MPC Beaver triples held in memory.
///
/// All secret pad pages and Beaver triples are volatile-zeroized on `Drop`.
#[derive(Debug)]
pub struct MinedPadBatch {
    pub validator_id: ValidatorId,
    pub pad_pages: Vec<Vec<u8>>,
    pub beaver_triples: Vec<BeaverTriple>,
    pub qkd_telemetry: QkdTelemetry,
    pub page_size_bytes: usize,
}

impl MinedPadBatch {
    /// Construct a `MinedPadBatch` from explicit buffers and QKD telemetry (useful for custom
    /// hardware integrations and adversarial test injection).
    pub fn from_raw_parts(
        validator_id: ValidatorId,
        pad_pages: Vec<Vec<u8>>,
        beaver_triples: Vec<BeaverTriple>,
        qkd_telemetry: QkdTelemetry,
    ) -> Self {
        let page_size_bytes = pad_pages.first().map_or(PAD_PAGE_BYTES, Vec::len);
        Self {
            validator_id,
            pad_pages,
            beaver_triples,
            qkd_telemetry,
            page_size_bytes,
        }
    }

    /// Number of pad pages remaining for production OTP use after sacrificing 1 audit sample.
    #[inline]
    pub fn usable_pad_pages(&self) -> usize {
        self.pad_pages.len().saturating_sub(1)
    }

    /// Number of Beaver triples remaining for Shielded MPC use after sacrificing 1 audit triple.
    #[inline]
    pub fn usable_beaver_triples(&self) -> usize {
        self.beaver_triples.len().saturating_sub(1)
    }
}

impl Drop for MinedPadBatch {
    fn drop(&mut self) {
        for page in &mut self.pad_pages {
            zeroize_slice(page);
        }
        // Each `BeaverTriple` volatile-zeroizes `(a, b, c)` in its own `Drop` impl.
    }
}

/// Interactive Proof-of-Pad challenge issued by `PopAuditor` for a validator and epoch.
///
/// Uses one-time random scalar `challenge_r` and three independent uniform Carter-Wegman
/// masks (`sample_mask_s`, `batch_mask_s`, `slots_mask_s`) in `F_(2^127 - 1)` so no one-time
/// pad mask is ever reused across distinct commitment tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopChallenge {
    pub validator_id: ValidatorId,
    pub epoch: u64,
    /// Random non-zero evaluation scalar `r` in `F_(2^127 - 1)`.
    pub challenge_r: u128,
    /// Independent one-time mask `s_sample` for the sacrificed pad sample commitment tag.
    pub sample_mask_s: u128,
    /// Independent one-time mask `s_batch` for the full-batch commitment tag.
    pub batch_mask_s: u128,
    /// Independent one-time mask `s_slots` for the challenged pad slot commitment tag.
    pub slots_mask_s: u128,
    /// Random pad slot indices (index 0 selects the sacrificed audit pad sample modulo batch size).
    pub pad_slot_indices: Vec<usize>,
    /// Random Beaver triple slot selector (resolved modulo batch triple count).
    pub beaver_slot_index: usize,
}

impl PopChallenge {
    /// Resolve the primary sacrificed pad page index for a batch of `pad_pages` pages.
    #[inline]
    pub fn select_pad_index(&self, pad_pages: usize) -> usize {
        if pad_pages == 0 {
            return 0;
        }
        self.pad_slot_indices.first().copied().unwrap_or(0) % pad_pages
    }

    /// Resolve the sacrificed Beaver triple index for a batch of `beaver_triples` triples.
    #[inline]
    pub fn select_triple_index(&self, beaver_triples: usize) -> usize {
        if beaver_triples == 0 {
            return 0;
        }
        self.beaver_slot_index % beaver_triples
    }
}

impl Drop for PopChallenge {
    fn drop(&mut self) {
        zeroize_u128(&mut self.challenge_r);
        zeroize_u128(&mut self.sample_mask_s);
        zeroize_u128(&mut self.batch_mask_s);
        zeroize_u128(&mut self.slots_mask_s);
    }
}

/// Interactive Proof-of-Pad response submitted by a validator to `PopAuditor`.
#[derive(Debug, Clone, PartialEq)]
pub struct PopProof {
    pub validator_id: ValidatorId,
    pub epoch: u64,
    /// Total pad pages mined in this batch (including the 1 sacrificed audit sample).
    pub pad_pages_mined: usize,
    /// Total Beaver triples mined in this batch (including the 1 sacrificed audit triple).
    pub beaver_triples_mined: usize,
    /// Resolved index of the sacrificed audit pad page.
    pub audited_pad_index: usize,
    /// Resolved index of the sacrificed audit Beaver triple.
    pub audited_triple_index: usize,
    /// Sacrificed pad page opened for statistical entropy + Carter-Wegman verification.
    pub audit_pad_sample: Vec<u8>,
    /// Sacrificed Beaver triple `(a, b, c)` opened for algebraic verification over `F_(2^127 - 1)`.
    pub sacrificed_triple: BeaverTriple,
    /// Per-page Carter-Wegman polynomial digests `cw_poly_digest(page_i, challenge_r)`.
    pub page_digests: Vec<u128>,
    /// 128-bit Carter-Wegman commitment tag over all `page_digests` in the batch.
    pub batch_commitment: AuditTag,
    /// 128-bit Carter-Wegman commitment tag binding the challenged `audit_pad_sample`.
    pub sample_commitment_tag: AuditTag,
    /// 128-bit Carter-Wegman commitment tag binding the randomly selected `pad_slot_indices`.
    pub challenged_slots_tag: AuditTag,
    /// BB84 + Decoy-State QKD replenishment telemetry from mining this batch.
    pub qkd_telemetry: QkdTelemetry,
    /// BFT blocks finalized by this validator in the epoch (default: `1`).
    pub blocks_finalized: u64,
    /// Proactive Secret Sharing (PSS) refreshes completed in the epoch (default: `1`).
    pub pss_refreshes_completed: u64,
}

impl PopProof {
    /// Attach explicit BFT and PSS liveness counts to this epoch proof.
    pub const fn with_liveness(
        mut self,
        blocks_finalized: u64,
        pss_refreshes_completed: u64,
    ) -> Self {
        self.blocks_finalized = blocks_finalized;
        self.pss_refreshes_completed = pss_refreshes_completed;
        self
    }
}

impl Drop for PopProof {
    fn drop(&mut self) {
        zeroize_slice(&mut self.audit_pad_sample);
        // `sacrificed_triple` is zeroized by `BeaverTriple::drop`.
    }
}

/// Receipt emitted by `PopAuditor::verify_proof` when a validator passes every PoP check.
#[derive(Debug, Clone, PartialEq)]
pub struct PopVerificationReceipt {
    pub validator_id: ValidatorId,
    pub epoch: u64,
    pub mined_pad_pages: usize,
    pub usable_pad_pages: usize,
    pub mined_beaver_triples: usize,
    pub usable_beaver_triples: usize,
    pub entropy_stats: EntropyAuditStats,
    pub qkd_telemetry: QkdTelemetry,
    pub contribution: EpochContribution,
    pub verified_commitment_tag: AuditTag,
}

// ============================================================================
// Step 3: `PopMiner`, `PopAuditor`, and `PopEpochCoordinator`
// ============================================================================

/// Proof-of-Pad miner producing purified BB84 OTP pads, fresh Beaver triples, and
/// interactive Carter-Wegman audit proofs.
#[derive(Debug, Default, Clone, Copy)]
pub struct PopMiner;

impl PopMiner {
    /// Mine a fresh batch of `pad_pages` purified OTP pad pages (256 B each) and
    /// `beaver_triples` non-trivial Beaver triples over `F_(2^127 - 1)` using a clean
    /// `Bb84Channel` with OS entropy, wiping all temporary raw buffers before returning.
    pub fn mine_pad_batch(
        validator_id: ValidatorId,
        pad_pages: usize,
        beaver_triples: usize,
    ) -> Result<MinedPadBatch, PopError> {
        let mut channel = Bb84Channel::default_channel();
        Self::mine_pad_batch_with_channel(validator_id, pad_pages, beaver_triples, &mut channel)
    }

    /// Mine a pad + Beaver triple batch using a caller-supplied `Bb84Channel` (e.g., custom
    /// hardware QRNG `EntropySource` or simulated optical/attack configuration).
    pub fn mine_pad_batch_with_channel<E: EntropySource>(
        validator_id: ValidatorId,
        pad_pages: usize,
        beaver_triples: usize,
        channel: &mut Bb84Channel<E>,
    ) -> Result<MinedPadBatch, PopError> {
        if pad_pages == 0 {
            return Err(PopError::EmptyBatch("pad_pages must be > 0"));
        }
        if beaver_triples == 0 {
            return Err(PopError::EmptyBatch("beaver_triples must be > 0"));
        }

        let pad_total_bytes = pad_pages
            .checked_mul(PAD_PAGE_BYTES)
            .ok_or(PopError::InvalidParameter("pad_pages byte count overflow"))?;
        let triple_total_bytes = beaver_triples
            .checked_mul(32)
            .ok_or(PopError::InvalidParameter("beaver_triples byte count overflow"))?;
        let total_qkd_bytes = pad_total_bytes
            .checked_add(triple_total_bytes)
            .ok_or(PopError::InvalidParameter("total QKD byte count overflow"))?;

        let mut exchange = channel.exchange_key(total_qkd_bytes)?;
        // Immediately wipe temporary peer key buffer.
        zeroize_slice(&mut exchange.bob_key);

        let qkd_telemetry = QkdTelemetry::from_exchange(&exchange);

        let mut pages = Vec::with_capacity(pad_pages);
        for chunk in exchange.alice_key[..pad_total_bytes].chunks_exact(PAD_PAGE_BYTES) {
            pages.push(chunk.to_vec());
        }

        let mut triples = Vec::with_capacity(beaver_triples);
        let mut triple_buf = [0u8; 32];
        for chunk in exchange.alice_key[pad_total_bytes..].chunks_exact(32) {
            triple_buf.copy_from_slice(chunk);
            triples.push(BeaverTriple::from_purified_bytes(&triple_buf));
        }
        zeroize_slice(&mut triple_buf);
        zeroize_slice(&mut exchange.alice_key);

        Ok(MinedPadBatch {
            validator_id,
            pad_pages: pages,
            beaver_triples: triples,
            qkd_telemetry,
            page_size_bytes: PAD_PAGE_BYTES,
        })
    }

    /// Answer an auditor's interactive `PopChallenge` by committing to the entire mined pad
    /// batch over `F_(2^127 - 1)` and sacrificing the challenged pad sample and Beaver triple.
    pub fn answer_challenge(batch: &MinedPadBatch, challenge: &PopChallenge) -> PopProof {
        let pad_pages_mined = batch.pad_pages.len();
        let beaver_triples_mined = batch.beaver_triples.len();

        let audited_pad_index = challenge.select_pad_index(pad_pages_mined);
        let audited_triple_index = challenge.select_triple_index(beaver_triples_mined);

        let mut page_digests = Vec::with_capacity(pad_pages_mined);
        for page in &batch.pad_pages {
            page_digests.push(cw_poly_digest(page, challenge.challenge_r));
        }

        let audit_pad_sample = batch
            .pad_pages
            .get(audited_pad_index)
            .cloned()
            .unwrap_or_default();

        let sacrificed_triple = batch
            .beaver_triples
            .get(audited_triple_index)
            .cloned()
            .unwrap_or_else(BeaverTriple::zero);

        let batch_commitment = compute_batch_commitment_tag(
            batch.validator_id,
            challenge.epoch,
            &page_digests,
            challenge.challenge_r,
            challenge.batch_mask_s,
        );

        let sample_commitment_tag = compute_sample_commitment_tag(
            batch.validator_id,
            challenge.epoch,
            audited_pad_index,
            &audit_pad_sample,
            challenge.challenge_r,
            challenge.sample_mask_s,
        );

        let challenged_slots_tag = compute_challenged_slots_tag(
            batch.validator_id,
            challenge.epoch,
            &page_digests,
            &challenge.pad_slot_indices,
            challenge.challenge_r,
            challenge.slots_mask_s,
        );

        PopProof {
            validator_id: batch.validator_id,
            epoch: challenge.epoch,
            pad_pages_mined,
            beaver_triples_mined,
            audited_pad_index,
            audited_triple_index,
            audit_pad_sample,
            sacrificed_triple,
            page_digests,
            batch_commitment,
            sample_commitment_tag,
            challenged_slots_tag,
            qkd_telemetry: batch.qkd_telemetry,
            blocks_finalized: 1,
            pss_refreshes_completed: 1,
        }
    }
}

/// Interactive information-theoretic Proof-of-Pad auditor.
#[derive(Debug, Default, Clone, Copy)]
pub struct PopAuditor;

impl PopAuditor {
    /// Issue a fresh unpredictable Proof-of-Pad challenge for `validator_id` in `epoch`.
    pub fn issue_challenge(validator_id: ValidatorId, epoch: u64) -> PopChallenge {
        Self::issue_challenge_with_slots(validator_id, epoch, DEFAULT_CHALLENGE_SLOT_COUNT)
    }

    /// Issue a fresh Proof-of-Pad challenge with a configurable number of random pad slots.
    pub fn issue_challenge_with_slots(
        validator_id: ValidatorId,
        epoch: u64,
        slot_count: usize,
    ) -> PopChallenge {
        let count = slot_count.max(1);
        let mut pad_slot_indices = Vec::with_capacity(count);
        for _ in 0..count {
            pad_slot_indices.push(random_usize());
        }
        PopChallenge {
            validator_id,
            epoch,
            challenge_r: random_nonzero_field_elem(),
            sample_mask_s: random_field_elem(),
            batch_mask_s: random_field_elem(),
            slots_mask_s: random_field_elem(),
            pad_slot_indices,
            beaver_slot_index: random_usize(),
        }
    }

    /// Verify a validator's `PopProof` against its issued `PopChallenge` using default
    /// information-theoretic audit bounds.
    pub fn verify_proof(
        challenge: &PopChallenge,
        proof: &PopProof,
    ) -> Result<PopVerificationReceipt, PopError> {
        Self::verify_proof_with_policy(challenge, proof, &PopAuditPolicy::default())
    }

    /// Verify a validator's `PopProof` against its `PopChallenge` with an explicit `PopAuditPolicy`.
    pub fn verify_proof_with_policy(
        challenge: &PopChallenge,
        proof: &PopProof,
        policy: &PopAuditPolicy,
    ) -> Result<PopVerificationReceipt, PopError> {
        // 1. Identity, epoch, and batch structural checks.
        if proof.validator_id != challenge.validator_id {
            return Err(PopError::ChallengeMismatch(format!(
                "validator_id mismatch: challenge={}, proof={}",
                challenge.validator_id, proof.validator_id
            )));
        }
        if proof.epoch != challenge.epoch {
            return Err(PopError::ChallengeMismatch(format!(
                "epoch mismatch: challenge={}, proof={}",
                challenge.epoch, proof.epoch
            )));
        }
        if proof.pad_pages_mined == 0 {
            return Err(PopError::EmptyBatch("proof claims 0 mined pad pages"));
        }
        if proof.beaver_triples_mined == 0 {
            return Err(PopError::EmptyBatch("proof claims 0 mined Beaver triples"));
        }
        if proof.page_digests.len() != proof.pad_pages_mined {
            return Err(PopError::ChallengeMismatch(format!(
                "page_digests length {} != pad_pages_mined {}",
                proof.page_digests.len(),
                proof.pad_pages_mined
            )));
        }

        let expected_pad_idx = challenge.select_pad_index(proof.pad_pages_mined);
        if proof.audited_pad_index != expected_pad_idx {
            return Err(PopError::ChallengeMismatch(format!(
                "audited_pad_index mismatch: expected {expected_pad_idx}, got {}",
                proof.audited_pad_index
            )));
        }
        let expected_triple_idx = challenge.select_triple_index(proof.beaver_triples_mined);
        if proof.audited_triple_index != expected_triple_idx {
            return Err(PopError::ChallengeMismatch(format!(
                "audited_triple_index mismatch: expected {expected_triple_idx}, got {}",
                proof.audited_triple_index
            )));
        }

        // 2. Constant-time Carter-Wegman commitment verification (`ct_eq_16`).
        let expected_sample_tag = compute_sample_commitment_tag(
            proof.validator_id,
            proof.epoch,
            proof.audited_pad_index,
            &proof.audit_pad_sample,
            challenge.challenge_r,
            challenge.sample_mask_s,
        );
        if !ct_eq_16(&expected_sample_tag, &proof.sample_commitment_tag) {
            return Err(PopError::InvalidCommitmentTag("sample_commitment_tag"));
        }

        let recomputed_sample_digest =
            cw_poly_digest(&proof.audit_pad_sample, challenge.challenge_r).to_le_bytes();
        let claimed_slot_digest = proof.page_digests[proof.audited_pad_index].to_le_bytes();
        if !ct_eq_16(&recomputed_sample_digest, &claimed_slot_digest) {
            return Err(PopError::InvalidCommitmentTag("audited_page_digest"));
        }

        let expected_batch_tag = compute_batch_commitment_tag(
            proof.validator_id,
            proof.epoch,
            &proof.page_digests,
            challenge.challenge_r,
            challenge.batch_mask_s,
        );
        if !ct_eq_16(&expected_batch_tag, &proof.batch_commitment) {
            return Err(PopError::InvalidCommitmentTag("batch_commitment"));
        }

        let expected_slots_tag = compute_challenged_slots_tag(
            proof.validator_id,
            proof.epoch,
            &proof.page_digests,
            &challenge.pad_slot_indices,
            challenge.challenge_r,
            challenge.slots_mask_s,
        );
        if !ct_eq_16(&expected_slots_tag, &proof.challenged_slots_tag) {
            return Err(PopError::InvalidCommitmentTag("challenged_slots_tag"));
        }

        // 3. Sacrificed Beaver triple algebraic check over F_(2^127 - 1).
        proof.sacrificed_triple.verify()?;

        // 4. Sacrificed pad sample statistical entropy audit (all-zero, monobit, runs, uniqueness).
        let entropy_stats = audit_pad_entropy_with_policy(&proof.audit_pad_sample, policy)?;

        // 5. Reject batches that clone identical pad pages across multiple slots.
        let unique_digests: BTreeSet<u128> = proof.page_digests.iter().copied().collect();
        if unique_digests.len() != proof.pad_pages_mined {
            return Err(PopError::DuplicatePadPages {
                unique_pages: unique_digests.len(),
                claimed_pages: proof.pad_pages_mined,
            });
        }

        // 6. BB84 + Decoy-State QKD link quality checks (QBER <= 0.11 & decoy ratio bounds).
        proof.qkd_telemetry.verify(policy)?;

        // Net usable resources contributed after sacrificing 1 audit pad and 1 audit triple.
        let usable_pad_pages = proof.pad_pages_mined.saturating_sub(1);
        let usable_beaver_triples = proof.beaver_triples_mined.saturating_sub(1);

        let contribution = EpochContribution {
            pad_pages_supplied: usable_pad_pages as u64,
            beaver_triples_contributed: usable_beaver_triples as u64,
            blocks_finalized: proof.blocks_finalized,
            pss_refreshes_completed: proof.pss_refreshes_completed,
        };

        Ok(PopVerificationReceipt {
            validator_id: proof.validator_id,
            epoch: proof.epoch,
            mined_pad_pages: proof.pad_pages_mined,
            usable_pad_pages,
            mined_beaver_triples: proof.beaver_triples_mined,
            usable_beaver_triples,
            entropy_stats,
            qkd_telemetry: proof.qkd_telemetry,
            contribution,
            verified_commitment_tag: proof.sample_commitment_tag,
        })
    }
}

/// Per-validator outcome recorded during `PopEpochCoordinator::run_audited_epoch`.
#[derive(Debug, Clone, PartialEq)]
pub enum PopAuditOutcome {
    /// Validator passed all PoP checks and earned `EpochContribution` credit.
    Accepted(PopVerificationReceipt),
    /// Validator failed PoP verification and was slashed if the offense is slashable.
    Rejected {
        validator_id: ValidatorId,
        error: PopError,
        slashing: Option<SlashingReceipt>,
    },
}

/// Complete audit and tokenomics settlement summary for a Proof-of-Pad epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct PopEpochReport {
    pub epoch: u64,
    pub accepted: Vec<PopVerificationReceipt>,
    pub rejected: Vec<(ValidatorId, PopError, Option<SlashingReceipt>)>,
    pub outcomes: Vec<PopAuditOutcome>,
    pub settlement: EpochSettlement,
}

/// Coordinates end-to-end interactive Proof-of-Pad audits, automatic slashing of cheaters,
/// and `TokenomicsEngine` epoch reward settlement.
#[derive(Debug, Default, Clone, Copy)]
pub struct PopEpochCoordinator;

impl PopEpochCoordinator {
    /// Audit all participating validators' `(PopChallenge, PopProof)` submissions for the
    /// current epoch, credit honest validators in `tokenomics`, slash cheating validators,
    /// and settle the halving `VRNM` epoch subsidy + 80% Pad-Burn fee pool.
    pub fn run_audited_epoch(
        tokenomics: &mut TokenomicsEngine,
        miners_proofs: &[(PopChallenge, PopProof)],
    ) -> PopEpochReport {
        Self::run_audited_epoch_with_policy(tokenomics, miners_proofs, &PopAuditPolicy::default())
    }

    /// Audit and settle an epoch using an explicit `PopAuditPolicy`.
    pub fn run_audited_epoch_with_policy(
        tokenomics: &mut TokenomicsEngine,
        miners_proofs: &[(PopChallenge, PopProof)],
        policy: &PopAuditPolicy,
    ) -> PopEpochReport {
        let current_epoch = tokenomics.current_epoch();
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        let mut outcomes = Vec::with_capacity(miners_proofs.len());
        let mut seen_validators = BTreeSet::new();

        for (challenge, proof) in miners_proofs {
            let validator_id = challenge.validator_id;

            let audit_result = if challenge.epoch != current_epoch {
                Err(PopError::ChallengeMismatch(format!(
                    "stale or future challenge epoch {} != current epoch {current_epoch}",
                    challenge.epoch
                )))
            } else if !seen_validators.insert(validator_id) {
                Err(PopError::ChallengeMismatch(format!(
                    "duplicate PoP submission for validator {validator_id} in epoch {current_epoch}"
                )))
            } else {
                PopAuditor::verify_proof_with_policy(challenge, proof, policy)
            };

            match audit_result {
                Ok(receipt) => match tokenomics
                    .record_contribution(receipt.validator_id, receipt.contribution)
                {
                    Ok(()) => {
                        outcomes.push(PopAuditOutcome::Accepted(receipt.clone()));
                        accepted.push(receipt);
                    }
                    Err(tok_err) => {
                        let err = PopError::TokenomicsFailure(tok_err.to_string());
                        outcomes.push(PopAuditOutcome::Rejected {
                            validator_id: receipt.validator_id,
                            error: err.clone(),
                            slashing: None,
                        });
                        rejected.push((receipt.validator_id, err, None));
                    }
                },
                Err(err) => {
                    let slashing = err.slashing_offense().and_then(|offense| {
                        tokenomics.slash_validator(validator_id, offense).ok()
                    });
                    outcomes.push(PopAuditOutcome::Rejected {
                        validator_id,
                        error: err.clone(),
                        slashing: slashing.clone(),
                    });
                    rejected.push((validator_id, err, slashing));
                }
            }
        }

        let settlement = tokenomics.settle_epoch();

        PopEpochReport {
            epoch: current_epoch,
            accepted,
            rejected,
            outcomes,
            settlement,
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenomics::{
        DEFAULT_REQUIRED_BOND, FeeLane, INITIAL_EPOCH_REWARD, VERN_PER_VRNM, ValidatorStatus,
    };

    #[test]
    fn test_honest_pop_miner_passes_full_audit_and_earns_epoch_payout() {
        let mut engine = TokenomicsEngine::with_defaults();
        engine.mint_genesis_supply(50 * VERN_PER_VRNM).unwrap();
        engine.register_genesis_validator(1).unwrap();
        engine.register_genesis_validator(2).unwrap();

        // Collect Pad-Burn fees (80% goes to validators, 20% permanently burned).
        for _ in 0..5 {
            engine.collect_fee(FeeLane::Express).unwrap();
        }
        for _ in 0..2 {
            engine.collect_fee(FeeLane::Shielded).unwrap();
        }
        let expected_fee_rewards = engine.pending_fee_rewards();
        assert!(expected_fee_rewards > 0);

        let batch1 = PopMiner::mine_pad_batch(1, 8, 16).unwrap();
        let batch2 = PopMiner::mine_pad_batch(2, 8, 16).unwrap();

        let ch1 = PopAuditor::issue_challenge(1, engine.current_epoch());
        let ch2 = PopAuditor::issue_challenge(2, engine.current_epoch());

        let proof1 = PopMiner::answer_challenge(&batch1, &ch1);
        let proof2 = PopMiner::answer_challenge(&batch2, &ch2);

        // Individual verification succeeds cleanly with valid stats.
        let receipt1 = PopAuditor::verify_proof(&ch1, &proof1).unwrap();
        assert_eq!(receipt1.validator_id, 1);
        assert_eq!(receipt1.usable_pad_pages, 7);
        assert_eq!(receipt1.usable_beaver_triples, 15);
        assert!(receipt1.entropy_stats.monobit_z_score <= DEFAULT_MAX_MONOBIT_Z);
        assert!(receipt1.entropy_stats.runs_z_score <= DEFAULT_MAX_RUNS_Z);
        assert!(receipt1.qkd_telemetry.qber <= MAX_ALLOWED_QBER);

        // Full audited epoch distributes halving subsidy + 80% fee pool equally to both honest miners.
        let report = PopEpochCoordinator::run_audited_epoch(&mut engine, &[(ch1, proof1), (ch2, proof2)]);
        assert_eq!(report.epoch, 0);
        assert_eq!(report.accepted.len(), 2);
        assert!(report.rejected.is_empty());
        assert_eq!(report.settlement.subsidy_minted, INITIAL_EPOCH_REWARD);
        assert_eq!(report.settlement.payouts.len(), 2);
        assert_eq!(
            report.settlement.payouts[0].total_reward,
            report.settlement.payouts[1].total_reward
        );
        assert_eq!(
            report.settlement.total_distributed + report.settlement.dust_rolled_over,
            INITIAL_EPOCH_REWARD + expected_fee_rewards
        );
        assert!(engine.vault(1).unwrap().reward_balance > 0);
        assert!(engine.vault(2).unwrap().reward_balance > 0);
        engine.check_invariants().unwrap();
    }

    #[test]
    fn test_fake_all_zero_pad_batch_rejected_by_entropy_audit() {
        let fake_pages = vec![vec![0u8; PAD_PAGE_BYTES]; 4];
        let triples = vec![BeaverTriple::generate(); 4];
        let fake_batch = MinedPadBatch::from_raw_parts(
            7,
            fake_pages,
            triples,
            QkdTelemetry::nominal_clean(),
        );

        let challenge = PopAuditor::issue_challenge(7, 0);
        let proof = PopMiner::answer_challenge(&fake_batch, &challenge);

        let err = PopAuditor::verify_proof(&challenge, &proof).unwrap_err();
        match err {
            PopError::EntropyAuditFailed { ref reason, stats } => {
                assert!(
                    reason.contains("all-zero"),
                    "expected all-zero failure reason, got: {reason}"
                );
                let s = stats.expect("stats should be populated");
                assert_eq!(s.non_zero_bytes, 0);
                assert_eq!(s.ones_count, 0);
            }
            other => panic!("expected EntropyAuditFailed for all-zero pads, got {other:?}"),
        }
    }

    #[test]
    fn test_fake_alternating_0xaa_pad_passes_monobit_but_caught_by_runs_test() {
        let alt_pages = vec![vec![0xAAu8; PAD_PAGE_BYTES]; 4];
        let triples = vec![BeaverTriple::generate(); 4];
        let fake_batch = MinedPadBatch::from_raw_parts(
            9,
            alt_pages,
            triples,
            QkdTelemetry::nominal_clean(),
        );

        let challenge = PopAuditor::issue_challenge(9, 0);
        let proof = PopMiner::answer_challenge(&fake_batch, &challenge);

        let err = PopAuditor::verify_proof(&challenge, &proof).unwrap_err();
        match err {
            PopError::EntropyAuditFailed { ref reason, stats } => {
                let s = stats.expect("stats should be populated");
                // 0xAA has exact 50% 1-bits (passes monobit z = 0.0!)
                assert!((s.ones_ratio - 0.5).abs() < 1e-12);
                assert!(s.monobit_z_score < 1e-9);
                // Every single adjacent bit flips -> huge runs z-score (~45.2 on 2048 bits)!
                assert!(
                    s.runs_z_score > DEFAULT_MAX_RUNS_Z,
                    "expected runs z-score > {DEFAULT_MAX_RUNS_Z}, got {}",
                    s.runs_z_score
                );
                assert!(
                    reason.contains("runs test failed"),
                    "expected runs test failure reason, got: {reason}"
                );
            }
            other => panic!("expected EntropyAuditFailed (runs test) for 0xAA pads, got {other:?}"),
        }
    }

    #[test]
    fn test_corrupted_beaver_triple_triggers_50_percent_bond_slash() {
        let mut engine = TokenomicsEngine::with_defaults();
        engine.register_genesis_validator(1).unwrap();
        engine.register_genesis_validator(2).unwrap();

        // Validator 1 is honest.
        let honest_batch = PopMiner::mine_pad_batch(1, 6, 8).unwrap();
        let ch1 = PopAuditor::issue_challenge(1, 0);
        let proof1 = PopMiner::answer_challenge(&honest_batch, &ch1);

        // Validator 2 mines real pads, then corrupts every Beaver triple (`c != a * b mod P`).
        let mut bad_batch = PopMiner::mine_pad_batch(2, 6, 8).unwrap();
        for triple in &mut bad_batch.beaver_triples {
            triple.c = add_mod(triple.c, 1);
        }
        let ch2 = PopAuditor::issue_challenge(2, 0);
        let proof2 = PopMiner::answer_challenge(&bad_batch, &ch2);

        // Direct verify_proof catches InvalidBeaverTriple.
        let err = PopAuditor::verify_proof(&ch2, &proof2).unwrap_err();
        assert!(matches!(err, PopError::InvalidBeaverTriple { .. }));
        assert_eq!(err.slashing_offense(), Some(SlashingOffense::InconsistentMpcShare));

        // Coordinator automatically applies 50% InconsistentMpcShare bond slash + forfeits epoch rewards!
        let report =
            PopEpochCoordinator::run_audited_epoch(&mut engine, &[(ch1, proof1), (ch2, proof2)]);
        assert_eq!(report.accepted.len(), 1);
        assert_eq!(report.accepted[0].validator_id, 1);
        assert_eq!(report.rejected.len(), 1);

        let (slashed_id, ref rej_err, ref maybe_receipt) = report.rejected[0];
        assert_eq!(slashed_id, 2);
        assert!(matches!(rej_err, PopError::InvalidBeaverTriple { .. }));
        let slash_receipt = maybe_receipt.as_ref().expect("cheater must be slashed");
        assert_eq!(slash_receipt.offense, SlashingOffense::InconsistentMpcShare);
        assert_eq!(slash_receipt.slashed_amount, DEFAULT_REQUIRED_BOND / 2);
        assert_eq!(slash_receipt.remaining_bond, DEFAULT_REQUIRED_BOND / 2);
        assert_eq!(slash_receipt.new_status, ValidatorStatus::Jailed);

        // Honest validator 1 gets 100% of epoch subsidy; slashed validator 2 gets 0.
        assert_eq!(engine.vault(1).unwrap().reward_balance, INITIAL_EPOCH_REWARD);
        assert_eq!(engine.vault(2).unwrap().reward_balance, 0);
        assert_eq!(engine.vault(2).unwrap().bond, DEFAULT_REQUIRED_BOND / 2);
        assert_eq!(engine.vault(2).unwrap().status, ValidatorStatus::Jailed);
        engine.check_invariants().unwrap();
    }

    #[test]
    fn test_trivial_all_zero_beaver_triple_rejected() {
        let mut batch = PopMiner::mine_pad_batch(5, 4, 4).unwrap();
        for triple in &mut batch.beaver_triples {
            triple.a = 0;
            triple.b = 0;
            triple.c = 0;
        }
        let ch = PopAuditor::issue_challenge(5, 0);
        let proof = PopMiner::answer_challenge(&batch, &ch);
        let err = PopAuditor::verify_proof(&ch, &proof).unwrap_err();
        assert!(matches!(err, PopError::InvalidBeaverTriple { .. }));
    }

    #[test]
    fn test_high_qber_compromised_qkd_proof_rejected() {
        let mut batch = PopMiner::mine_pad_batch(3, 6, 8).unwrap();
        batch.qkd_telemetry.qber = 0.24; // Way above 0.11 Shor-Preskill bound!

        let ch = PopAuditor::issue_challenge(3, 0);
        let proof = PopMiner::answer_challenge(&batch, &ch);

        let err = PopAuditor::verify_proof(&ch, &proof).unwrap_err();
        match err {
            PopError::QkdQberExceeded { qber, max_qber } => {
                assert!((qber - 0.24).abs() < 1e-12);
                assert!((max_qber - MAX_ALLOWED_QBER).abs() < 1e-12);
            }
            other => panic!("expected QkdQberExceeded, got {other:?}"),
        }
        assert_eq!(err.slashing_offense(), Some(SlashingOffense::ExtendedDowntime));
    }

    #[test]
    fn test_tampered_carter_wegman_proof_tag_rejected() {
        let batch = PopMiner::mine_pad_batch(4, 6, 8).unwrap();
        let ch = PopAuditor::issue_challenge(4, 0);

        // 1. Flip a single bit in `sample_commitment_tag`.
        let mut tampered_sample = PopMiner::answer_challenge(&batch, &ch);
        tampered_sample.sample_commitment_tag[0] ^= 0x01;
        let err = PopAuditor::verify_proof(&ch, &tampered_sample).unwrap_err();
        assert_eq!(err, PopError::InvalidCommitmentTag("sample_commitment_tag"));

        // 2. Flip a single bit in `batch_commitment`.
        let mut tampered_batch = PopMiner::answer_challenge(&batch, &ch);
        tampered_batch.batch_commitment[15] ^= 0x80;
        let err = PopAuditor::verify_proof(&ch, &tampered_batch).unwrap_err();
        assert_eq!(err, PopError::InvalidCommitmentTag("batch_commitment"));

        // 3. Flip a single bit in `challenged_slots_tag`.
        let mut tampered_slots = PopMiner::answer_challenge(&batch, &ch);
        tampered_slots.challenged_slots_tag[7] ^= 0x10;
        let err = PopAuditor::verify_proof(&ch, &tampered_slots).unwrap_err();
        assert_eq!(err, PopError::InvalidCommitmentTag("challenged_slots_tag"));
    }

    #[test]
    fn test_cloned_duplicate_pad_pages_rejected() {
        let honest = PopMiner::mine_pad_batch(6, 2, 4).unwrap();
        // Clone a single genuine high-entropy page 4 times to fake 4 pages of work.
        let cloned_pages = vec![honest.pad_pages[0].clone(); 4];
        let triples = vec![BeaverTriple::generate(); 4];
        let cloned_batch = MinedPadBatch::from_raw_parts(
            6,
            cloned_pages,
            triples,
            honest.qkd_telemetry,
        );

        let ch = PopAuditor::issue_challenge(6, 0);
        let proof = PopMiner::answer_challenge(&cloned_batch, &ch);
        let err = PopAuditor::verify_proof(&ch, &proof).unwrap_err();
        assert_eq!(
            err,
            PopError::DuplicatePadPages {
                unique_pages: 1,
                claimed_pages: 4,
            }
        );
    }

    #[test]
    fn test_pns_decoy_anomaly_qkd_proof_rejected() {
        let mut batch = PopMiner::mine_pad_batch(8, 4, 4).unwrap();
        batch.qkd_telemetry.decoy_yield_ratio = 1.42; // Violates beam-splitter concavity (> 1.08)

        let ch = PopAuditor::issue_challenge(8, 0);
        let proof = PopMiner::answer_challenge(&batch, &ch);
        let err = PopAuditor::verify_proof(&ch, &proof).unwrap_err();
        assert!(matches!(err, PopError::QkdDecoyAnomaly { .. }));
    }
}
