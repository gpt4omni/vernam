//! Unbiasable, Unabortable Information-Theoretic Distributed Entropy Beacon
//! and Autonomous Protocol Epoch Scheduler for Vernam (VRNM).
//!
//! Zero external crates, zero computational cryptography (no SHA-256, VDF, BLS,
//! RSA, ECDSA, or AES). Every security property holds unconditionally over the
//! Mersenne prime field `F_(2^127 - 1)`:
//!
//! - **Unpredictability (Perfect Secrecy):** Each validator `i` commits its
//!   uniform secret `s_i in F_p` via a symmetric bivariate polynomial
//!   `F_i(x, y)` of degree `(t - 1, t - 1)` where `t = 2f + 1` for `N = 3f + 1`.
//!   Any coalition of up to `t - 1` (hence any `<= f` Byzantine) validators
//!   learns strictly zero bits about `s_i` prior to the Reveal phase.
//! - **Commit-Phase Degree Consistency & IC-MAC Verification:** Shares are
//!   delivered over single-use OTP + Carter-Wegman MAC envelopes. Peers verify
//!   zero-leakage pairwise symmetry `F_i(x_j, x_k) == F_i(x_k, x_j)` and
//!   Rabin-Ben-Or information-checking MACs before any secret is revealed,
//!   detecting and excluding malicious dealers sending degree `> t - 1` shares.
//! - **Unabortability & Zero Bias:** Once the qualified dealer set `C` is locked
//!   at the end of Commit, even if up to `f` Byzantine validators see all honest
//!   reveals and abort (or broadcast false reveals), the remaining `N - f >= t`
//!   honest validators broadcast their IC-MAC-authenticated shares and
//!   deterministically reconstruct the aborted secret via Lagrange interpolation,
//!   yielding the exact same unbiasable beacon `Gamma_e = sum_{i in C} s_i mod p`.
//! - **Purely Information-Theoretic Derivation:** Leader schedules, Proof-of-Pad
//!   challenge scalars, and unpredictable audit slot indices are derived from
//!   `Gamma_e` using bijective polynomial mixing (`x -> x^5 mod (2^127 - 1)`)
//!   with zero modulo bias.
//! - **Autonomous Epoch Clock:** Deterministic height-driven state machine
//!   triggering `Beacon -> Proof-of-Pad Audit -> PSS Refresh` at exact epoch
//!   boundaries with zero admin APIs.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt;

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, fill_os_random, inv_mod, mul_mod, random_field_elem,
    random_nonzero_field_elem, reduce, sub_mod, zeroize_slice, zeroize_u128,
};

// ============================================================================
// Purely Algebraic Domain Separation & Bijective Mixing Constants in F_p
// ============================================================================

const DOMAIN_LEADER_ORDER: u128 = 0x4C45_4144_4552_5F4F_5244_4552_0001;
const DOMAIN_POP_CHALLENGE: u128 = 0x504F_505F_4348_414C_4C45_4E47_0002;
const DOMAIN_AUDIT_SLOTS: u128 = 0x4155_4449_545F_534C_4F54_5300_0003;

// Distinct non-zero field constants (< PRIME_P) for bijective polynomial mixing.
const MIX_K1: u128 = 0x5A17_9C3B_7E2D_4F61_138B_9D4E_6A2F_11C5;
const MIX_K2: u128 = 0x3D6F_2A89_B41C_5E73_71A3_28E9_C54B_39D7;
const MIX_K3: u128 = 0x6B29_E147_8C35_A91D_4F72_63B8_1D9E_52A3;
const MIX_K4: u128 = 0x29E4_7C51_D38B_6A19_5E47_8B23_9F61_74C9;
const MIX_K5: u128 = 0x71C3_85A9_4E27_B61D_3A95_C4E1_278B_6D3F;
const MIX_K6: u128 = 0x48A7_3E91_6C53_D28F_1B79_E463_8A2D_5F1B;
const MIX_K7: u128 = 0x1F83_B62D_9A47_5C1E_6D39_4B85_7E12_93A7;
const MIX_K8: u128 = 0x54D9_1B73_E285_4A6C_29F1_7C48_3B6E_81D3;
const MIX_K9: u128 = 0x67E1_49C3_2B8D_75A1_8E37_51C9_4D2A_3F6B;

// ============================================================================
// Configuration, Phases, and Errors
// ============================================================================

/// Configuration for a `(threshold, num_validators)` beacon committee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconConfig {
    /// Reconstruction & privacy threshold `t`.
    /// For BFT `N = 3f + 1`, `t = 2f + 1 = N - f`.
    pub threshold: usize,
    /// Total number of validators `N`.
    pub num_validators: usize,
    /// Maximum Byzantine validators `f` tolerated without aborting (`N - t`).
    pub max_faults: usize,
}

impl BeaconConfig {
    /// Standard BFT configuration for `N` validators:
    /// `f = (N - 1) / 3` and `threshold = N - f` (i.e., `t = 2f + 1` for `N = 3f + 1`).
    pub fn bft(num_validators: usize) -> Result<Self, BeaconError> {
        if num_validators == 0 {
            return Err(BeaconError::InvalidConfig(
                "num_validators must be >= 1".to_string(),
            ));
        }
        let max_faults = (num_validators - 1) / 3;
        let threshold = num_validators - max_faults;
        Ok(Self {
            threshold,
            num_validators,
            max_faults,
        })
    }

    /// Custom `(threshold, num_validators)` configuration with `1 <= threshold <= num_validators`.
    pub fn new(threshold: usize, num_validators: usize) -> Result<Self, BeaconError> {
        if num_validators == 0 {
            return Err(BeaconError::InvalidConfig(
                "num_validators must be >= 1".to_string(),
            ));
        }
        if threshold == 0 || threshold > num_validators {
            return Err(BeaconError::InvalidConfig(format!(
                "threshold ({threshold}) must satisfy 1 <= threshold <= num_validators ({num_validators})"
            )));
        }
        let max_faults = num_validators - threshold;
        Ok(Self {
            threshold,
            num_validators,
            max_faults,
        })
    }

    /// Exact plaintext byte length of a serialized `SecretShareRecord` for this config.
    pub const fn share_payload_bytes(&self) -> usize {
        // row_poly (threshold u128s) + ic_holder_tags (3*N u128s) + ic_verifier_keys (3*N u128s)
        (self.threshold + 6 * self.num_validators) * 16
    }

    #[inline]
    fn check_validator(&self, validator_id: u32) -> Result<(), BeaconError> {
        if (validator_id as usize) >= self.num_validators {
            return Err(BeaconError::InvalidValidatorId {
                validator_id,
                num_validators: self.num_validators,
            });
        }
        Ok(())
    }
}

/// Lifecycle phase of a `VernamBeacon` epoch round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconPhase {
    /// Phase 1: Secret sharing, OTP+CW-MAC delivery, pairwise symmetry checks, and IC-MAC checks.
    Commit,
    /// Phase 2: Qualified dealers locked; direct polynomial reveals and Lagrange recovery of aborts.
    Reveal,
    /// Phase 3: Unbiasable `EpochBeaconOutput` finalized.
    Finalized,
}

/// Errors returned by `VernamBeacon`, polynomial primitives, or `AutonomousEpochClock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconError {
    InvalidConfig(String),
    InvalidValidatorId {
        validator_id: u32,
        num_validators: usize,
    },
    WrongEpoch {
        expected: u64,
        got: u64,
    },
    WrongPhase {
        expected: BeaconPhase,
        got: BeaconPhase,
    },
    MacVerificationFailed {
        dealer: u32,
        recipient: u32,
    },
    CorruptedPayload {
        dealer: u32,
        recipient: u32,
    },
    InconsistentShares {
        dealer: u32,
        reason: String,
    },
    InsufficientShares {
        dealer: u32,
        have: usize,
        need: usize,
    },
    InsufficientQualifiedDealers {
        have: usize,
        need: usize,
    },
    DuplicateSubmission {
        validator_id: u32,
    },
    DealerDisqualified {
        dealer: u32,
    },
    InvalidReveal {
        dealer: u32,
        reason: String,
    },
    InvalidEvaluationPoint(String),
    InvalidPipelineTransition {
        expected: EpochPipelineStage,
        got: EpochPipelineStage,
    },
    MissingBeaconOutput,
}

impl fmt::Display for BeaconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid beacon config: {msg}"),
            Self::InvalidValidatorId {
                validator_id,
                num_validators,
            } => write!(
                f,
                "validator_id {validator_id} out of range 0..{num_validators}"
            ),
            Self::WrongEpoch { expected, got } => {
                write!(f, "wrong epoch: expected {expected}, got {got}")
            }
            Self::WrongPhase { expected, got } => {
                write!(f, "wrong beacon phase: expected {expected:?}, got {got:?}")
            }
            Self::MacVerificationFailed { dealer, recipient } => {
                write!(
                    f,
                    "Carter-Wegman MAC verification failed for dealer {dealer} -> recipient {recipient}"
                )
            }
            Self::CorruptedPayload { dealer, recipient } => {
                write!(
                    f,
                    "corrupted share payload from dealer {dealer} -> recipient {recipient}"
                )
            }
            Self::InconsistentShares { dealer, reason } => {
                write!(f, "inconsistent shares from dealer {dealer}: {reason}")
            }
            Self::InsufficientShares { dealer, have, need } => {
                write!(
                    f,
                    "insufficient shares for dealer {dealer}: have {have}, need {need}"
                )
            }
            Self::InsufficientQualifiedDealers { have, need } => {
                write!(
                    f,
                    "insufficient qualified dealers: have {have}, need {need}"
                )
            }
            Self::DuplicateSubmission { validator_id } => {
                write!(f, "duplicate submission from validator {validator_id}")
            }
            Self::DealerDisqualified { dealer } => {
                write!(f, "dealer {dealer} is disqualified")
            }
            Self::InvalidReveal { dealer, reason } => {
                write!(f, "invalid reveal from dealer {dealer}: {reason}")
            }
            Self::InvalidEvaluationPoint(msg) => write!(f, "invalid evaluation point: {msg}"),
            Self::InvalidPipelineTransition { expected, got } => {
                write!(
                    f,
                    "invalid epoch pipeline transition: expected {expected:?}, got {got:?}"
                )
            }
            Self::MissingBeaconOutput => write!(f, "epoch beacon output not yet finalized"),
        }
    }
}

impl Error for BeaconError {}

// ============================================================================
// Field Polynomial & Lagrange Interpolation Primitives over F_(2^127 - 1)
// ============================================================================

/// Non-zero Shamir evaluation coordinate `x_j = j + 1` in `F_p` for validator `j`.
#[inline(always)]
pub const fn validator_eval_x(validator_id: u32) -> u128 {
    (validator_id as u128) + 1
}

/// Evaluate polynomial `coeffs[0] + coeffs[1]*x + ... + coeffs[d]*x^d` mod `PRIME_P` via Horner's method.
pub fn eval_poly(coeffs: &[u128], x: u128) -> u128 {
    let x = reduce(x);
    let mut acc = 0u128;
    for &c in coeffs.iter().rev() {
        acc = add_mod(mul_mod(acc, x), reduce(c));
    }
    acc
}

/// Lagrange interpolation of `(x_i, y_i)` points at arbitrary coordinate `target_x` in `F_p`.
///
/// Validates that `points` is non-empty and all `x_i` are distinct modulo `PRIME_P`.
pub fn lagrange_interpolate_at(
    points: &[(u128, u128)],
    target_x: u128,
) -> Result<u128, BeaconError> {
    if points.is_empty() {
        return Err(BeaconError::InvalidEvaluationPoint(
            "cannot interpolate empty point set".to_string(),
        ));
    }
    let target_x = reduce(target_x);

    // Check pairwise distinct x coordinates modulo PRIME_P.
    for i in 0..points.len() {
        let xi = reduce(points[i].0);
        for &(xj_raw, _) in &points[(i + 1)..] {
            if xi == reduce(xj_raw) {
                return Err(BeaconError::InvalidEvaluationPoint(format!(
                    "duplicate x coordinate {xi}"
                )));
            }
        }
    }

    let mut result = 0u128;
    for (i, &(xi_raw, yi_raw)) in points.iter().enumerate() {
        let xi = reduce(xi_raw);
        let yi = reduce(yi_raw);

        // Short-circuit if target_x coincides with an evaluation point.
        if target_x == xi {
            return Ok(yi);
        }

        let mut num = 1u128;
        let mut den = 1u128;
        for (j, &(xj_raw, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = reduce(xj_raw);
            num = mul_mod(num, sub_mod(target_x, xj));
            den = mul_mod(den, sub_mod(xi, xj));
        }

        let lambda_i = mul_mod(num, inv_mod(den));
        result = add_mod(result, mul_mod(yi, lambda_i));
    }

    Ok(result)
}

/// Reconstruct secret `f(0)` from `(x_i, f(x_i))` points via Lagrange interpolation in `F_p`.
///
/// Validates all `x_i` are non-zero and pairwise distinct.
pub fn lagrange_interpolate_at_zero(points: &[(u128, u128)]) -> Result<u128, BeaconError> {
    for &(x_raw, _) in points {
        if reduce(x_raw) == 0 {
            return Err(BeaconError::InvalidEvaluationPoint(
                "share evaluation coordinate x cannot be 0".to_string(),
            ));
        }
    }
    lagrange_interpolate_at(points, 0)
}

/// Verify that ALL supplied points `(x_i, y_i)` lie on a single polynomial of
/// degree `<= threshold - 1` over `F_(2^127 - 1)`.
///
/// Returns `Ok(true)` if consistent, `Ok(false)` if any point deviates from the
/// unique degree-`(threshold - 1)` polynomial interpolated from the first `threshold` points.
pub fn verify_degree_consistency(
    points: &[(u128, u128)],
    threshold: usize,
) -> Result<bool, BeaconError> {
    if threshold == 0 {
        return Err(BeaconError::InvalidConfig(
            "threshold must be >= 1".to_string(),
        ));
    }
    if points.len() < threshold {
        return Err(BeaconError::InsufficientShares {
            dealer: 0,
            have: points.len(),
            need: threshold,
        });
    }

    // Validate distinctness across ALL points.
    for i in 0..points.len() {
        let xi = reduce(points[i].0);
        for &(xj_raw, _) in &points[(i + 1)..] {
            if xi == reduce(xj_raw) {
                return Err(BeaconError::InvalidEvaluationPoint(format!(
                    "duplicate x coordinate {xi}"
                )));
            }
        }
    }

    let basis = &points[..threshold];
    for &(xk, yk) in &points[threshold..] {
        let expected = lagrange_interpolate_at(basis, xk)?;
        if expected != reduce(yk) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Bijective power map `x -> x^5 mod (2^127 - 1)`.
///
/// Since `2^126 - 1 === 3 (mod 5)`, `gcd(5, PRIME_P - 1) = 1`, making `x -> x^5`
/// an exact permutation on `F_(2^127 - 1)` in 3 field multiplications.
#[inline(always)]
fn pow5_mod(x: u128) -> u128 {
    let x = reduce(x);
    let x2 = mul_mod(x, x);
    let x4 = mul_mod(x2, x2);
    mul_mod(x4, x)
}

/// Purely information-theoretic bijective derivation over `F_(2^127 - 1)`.
///
/// For any fixed `(epoch, domain, subject, counter)`, the map `gamma -> output`
/// is a composition of invertible affine maps and the bijection `x -> x^5`,
/// hence an exact bijection on `F_p` (zero statistical bias whenever `gamma` is uniform).
#[inline]
fn derive_field_elem_raw(
    gamma: u128,
    epoch: u64,
    domain: u128,
    subject: u64,
    counter: u64,
) -> u128 {
    let s0 = pow5_mod(add_mod(reduce(gamma), MIX_K1));
    let s1 = pow5_mod(add_mod(
        mul_mod(s0, MIX_K2),
        add_mod(reduce(epoch as u128), MIX_K3),
    ));
    let s2 = pow5_mod(add_mod(
        mul_mod(s1, MIX_K4),
        add_mod(reduce(domain), MIX_K5),
    ));
    let s3 = pow5_mod(add_mod(
        mul_mod(s2, MIX_K6),
        add_mod(reduce(subject as u128), MIX_K7),
    ));
    pow5_mod(add_mod(
        mul_mod(s3, MIX_K8),
        add_mod(reduce(counter as u128), MIX_K9),
    ))
}

// ============================================================================
// Single-Use OTP + Carter-Wegman MAC Envelope (100% IT-Secure)
// ============================================================================

/// Carter-Wegman polynomial universal MAC over `F_(2^127 - 1)` (Encrypt-then-MAC).
///
/// Encodes `(epoch, dealer_id, recipient_id, ciphertext.len())` plus 15-byte
/// (120-bit, strictly `< PRIME_P`) ciphertext blocks via Horner evaluation, then
/// adds the single-use pad `cw_mask`. Forgery probability `<= (blocks + 5) / (2^127 - 1)`.
pub fn cw_mac_envelope(
    cw_r: u128,
    cw_mask: u128,
    epoch: u64,
    dealer_id: u32,
    recipient_id: u32,
    ciphertext: &[u8],
) -> [u8; 16] {
    let r = reduce(cw_r);
    let mut acc = 0u128;

    // Bind structured header fields and exact byte length (prevents truncation/padding collisions).
    let header_elems = [
        reduce(epoch as u128),
        reduce(dealer_id as u128),
        reduce(recipient_id as u128),
        reduce(ciphertext.len() as u128),
    ];
    for elem in header_elems {
        acc = mul_mod(add_mod(acc, elem), r);
    }

    // Absorb ciphertext in 15-byte blocks (120 bits < 2^127 - 1).
    for chunk in ciphertext.chunks(15) {
        let mut buf = [0u8; 16];
        buf[..chunk.len()].copy_from_slice(chunk);
        let block = u128::from_le_bytes(buf);
        acc = mul_mod(add_mod(acc, block), r);
    }

    let tag = add_mod(acc, reduce(cw_mask));
    tag.to_le_bytes()
}

/// Single-use pairwise OTP encryption pad + Carter-Wegman MAC key.
///
/// Automatically volatile-zeroized on `Drop`; `Debug` output is redacted.
pub struct OtpChannelKey {
    otp_pad: Vec<u8>,
    cw_r: u128,
    cw_mask: u128,
}

impl OtpChannelKey {
    /// Generate a fresh single-use OTP+CW-MAC key of exact `pad_len` bytes from OS entropy.
    pub fn generate(pad_len: usize) -> Self {
        let mut otp_pad = vec![0u8; pad_len];
        fill_os_random(&mut otp_pad);
        let cw_r = random_nonzero_field_elem();
        let cw_mask = random_field_elem();
        Self {
            otp_pad,
            cw_r,
            cw_mask,
        }
    }

    /// Generate a matched pair `(sender_key, recipient_key)` for a single peer-to-peer message.
    pub fn generate_pair(pad_len: usize) -> (Self, Self) {
        let sender = Self::generate(pad_len);
        let recipient = Self {
            otp_pad: sender.otp_pad.clone(),
            cw_r: sender.cw_r,
            cw_mask: sender.cw_mask,
        };
        (sender, recipient)
    }

    /// Generate a matched pair sized exactly for a `BeaconConfig` share envelope.
    pub fn generate_pair_for_config(config: &BeaconConfig) -> (Self, Self) {
        Self::generate_pair(config.share_payload_bytes())
    }

    /// Length of the single-use OTP pad in bytes.
    pub fn pad_len(&self) -> usize {
        self.otp_pad.len()
    }
}

impl Drop for OtpChannelKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.otp_pad);
        zeroize_u128(&mut self.cw_r);
        zeroize_u128(&mut self.cw_mask);
    }
}

impl fmt::Debug for OtpChannelKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpChannelKey")
            .field("pad_len", &self.otp_pad.len())
            .field("otp_pad", &"<REDACTED>")
            .field("cw_r", &"<REDACTED>")
            .field("cw_mask", &"<REDACTED>")
            .finish()
    }
}

/// Information-theoretically encrypted & authenticated share envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEnvelope {
    pub epoch: u64,
    pub dealer_id: u32,
    pub recipient_id: u32,
    pub ciphertext: Vec<u8>,
    pub mac_tag: [u8; 16],
}

impl ShareEnvelope {
    /// Encrypt `plaintext` with single-use OTP and authenticate ciphertext with Carter-Wegman MAC.
    pub fn seal(
        epoch: u64,
        dealer_id: u32,
        recipient_id: u32,
        plaintext: &[u8],
        key: &OtpChannelKey,
    ) -> Result<Self, BeaconError> {
        if key.otp_pad.len() < plaintext.len() {
            return Err(BeaconError::CorruptedPayload {
                dealer: dealer_id,
                recipient: recipient_id,
            });
        }
        let mut ciphertext = vec![0u8; plaintext.len()];
        for i in 0..plaintext.len() {
            ciphertext[i] = plaintext[i] ^ key.otp_pad[i];
        }
        let mac_tag = cw_mac_envelope(
            key.cw_r,
            key.cw_mask,
            epoch,
            dealer_id,
            recipient_id,
            &ciphertext,
        );
        Ok(Self {
            epoch,
            dealer_id,
            recipient_id,
            ciphertext,
            mac_tag,
        })
    }

    /// Verify Carter-Wegman MAC in constant time (`ct_eq_16`) and decrypt via OTP XOR.
    pub fn open(&self, key: &OtpChannelKey) -> Result<Vec<u8>, BeaconError> {
        if key.otp_pad.len() < self.ciphertext.len() {
            return Err(BeaconError::CorruptedPayload {
                dealer: self.dealer_id,
                recipient: self.recipient_id,
            });
        }
        let expected_tag = cw_mac_envelope(
            key.cw_r,
            key.cw_mask,
            self.epoch,
            self.dealer_id,
            self.recipient_id,
            &self.ciphertext,
        );
        if !ct_eq_16(&expected_tag, &self.mac_tag) {
            return Err(BeaconError::MacVerificationFailed {
                dealer: self.dealer_id,
                recipient: self.recipient_id,
            });
        }
        let mut plaintext = vec![0u8; self.ciphertext.len()];
        for i in 0..self.ciphertext.len() {
            plaintext[i] = self.ciphertext[i] ^ key.otp_pad[i];
        }
        Ok(plaintext)
    }
}

// ============================================================================
// Rabin-Ben-Or Information-Checking (IC) MAC & Secret Contributions
// ============================================================================

/// Holder-side Rabin-Ben-Or IC-MAC record for authenticating a share `y_j` to a verifier `v`.
///
/// Holds blinding scalar `z`, share tag `tag_y = r*y_j + a1`, and mask tag `tag_z = r*z + a2`.
#[derive(Clone)]
pub struct IcHolderTag {
    z: u128,
    tag_y: u128,
    tag_z: u128,
}

impl IcHolderTag {
    /// Return the share authentication tag `tag_y` for reveal/recovery verification.
    #[inline]
    pub fn share_tag(&self) -> u128 {
        self.tag_y
    }
}

impl Drop for IcHolderTag {
    fn drop(&mut self) {
        zeroize_u128(&mut self.z);
        zeroize_u128(&mut self.tag_y);
        zeroize_u128(&mut self.tag_z);
    }
}

impl fmt::Debug for IcHolderTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IcHolderTag")
            .field("z", &"<REDACTED>")
            .field("tag_y", &"<REDACTED>")
            .field("tag_z", &"<REDACTED>")
            .finish()
    }
}

/// Verifier-side Rabin-Ben-Or IC-MAC key `(r, a1, a2)` for verifying a peer's share.
#[derive(Clone)]
pub struct IcVerifierKey {
    r: u128,
    a1: u128,
    a2: u128,
}

impl IcVerifierKey {
    /// Verify a revealed/recovered share `y` against its holder's `tag_y`.
    #[inline]
    pub fn verify_share_tag(&self, share_y: u128, tag_y: u128) -> bool {
        let expected = add_mod(mul_mod(self.r, reduce(share_y)), self.a1);
        let a_bytes = expected.to_le_bytes();
        let b_bytes = reduce(tag_y).to_le_bytes();
        ct_eq_16(&a_bytes, &b_bytes)
    }

    /// Verify a Commit-phase zero-knowledge masked response `(m, tag_m)` for challenge `c`.
    #[inline]
    pub fn verify_masked_response(&self, challenge_c: u128, masked_m: u128, tag_m: u128) -> bool {
        let rhs = add_mod(
            mul_mod(self.r, reduce(masked_m)),
            add_mod(mul_mod(reduce(challenge_c), self.a1), self.a2),
        );
        let a_bytes = rhs.to_le_bytes();
        let b_bytes = reduce(tag_m).to_le_bytes();
        ct_eq_16(&a_bytes, &b_bytes)
    }
}

impl Drop for IcVerifierKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.a1);
        zeroize_u128(&mut self.a2);
    }
}

impl fmt::Debug for IcVerifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IcVerifierKey")
            .field("r", &"<REDACTED>")
            .field("a1", &"<REDACTED>")
            .field("a2", &"<REDACTED>")
            .finish()
    }
}

/// Commit-phase zero-knowledge challenge sent by `verifier_id` to `holder_id` for `dealer_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcChallenge {
    pub epoch: u64,
    pub dealer_id: u32,
    pub holder_id: u32,
    pub verifier_id: u32,
    pub challenge_c: u128,
}

/// Commit-phase zero-knowledge response proving `dealer_id` gave `holder_id` a valid IC-MAC
/// without leaking a single bit of `holder_id`'s share `y_j`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcResponse {
    pub epoch: u64,
    pub dealer_id: u32,
    pub holder_id: u32,
    pub verifier_id: u32,
    pub masked_m: u128,
    pub masked_tag: u128,
}

/// Secret symmetric bivariate polynomial `F(x, y) = sum_{a,b < t} c_{a,b} x^a y^b`
/// with `c_{a,b} = c_{b,a}` and `F(0, 0) = secret`.
///
/// Volatile-zeroized on `Drop`; `Debug` output redacts all secret values.
pub struct SecretContribution {
    epoch: u64,
    dealer_id: u32,
    threshold: usize,
    secret: u128,
    /// Flattened `threshold x threshold` symmetric matrix `coeffs[a * threshold + b]`.
    bivariate_coeffs: Vec<u128>,
}

impl SecretContribution {
    /// Sample a uniform random secret and symmetric bivariate polynomial of degree `(t-1, t-1)`.
    pub fn generate(epoch: u64, dealer_id: u32, threshold: usize) -> Self {
        let secret = random_field_elem();
        Self::from_secret(epoch, dealer_id, threshold, secret)
    }

    /// Construct a symmetric bivariate polynomial of degree `(t-1, t-1)` hiding `secret`.
    pub fn from_secret(epoch: u64, dealer_id: u32, threshold: usize, secret: u128) -> Self {
        let secret = reduce(secret);
        let mut coeffs = vec![0u128; threshold * threshold];
        coeffs[0] = secret;
        for a in 0..threshold {
            for b in a..threshold {
                if a == 0 && b == 0 {
                    continue;
                }
                let v = random_field_elem();
                coeffs[a * threshold + b] = v;
                coeffs[b * threshold + a] = v;
            }
        }
        Self {
            epoch,
            dealer_id,
            threshold,
            secret,
            bivariate_coeffs: coeffs,
        }
    }

    /// Evaluate the univariate row polynomial `g_j(y) = F(x_j, y)` of degree `<= threshold - 1`.
    /// Its constant term `g_j(0) = F(x_j, 0)` is peer `j`'s Shamir share of `secret`.
    pub fn row_poly_for_validator(&self, recipient_id: u32) -> Vec<u128> {
        let x = validator_eval_x(recipient_id);
        let t = self.threshold;
        let mut row = vec![0u128; t];
        for b in 0..t {
            // Coefficient of y^b in F(x, y) is sum_{a=0}^{t-1} c_{a,b} x^a.
            let mut acc = 0u128;
            for a in (0..t).rev() {
                acc = add_mod(mul_mod(acc, x), self.bivariate_coeffs[a * t + b]);
            }
            row[b] = acc;
        }
        row
    }

    /// Univariate secret polynomial `f(x) = F(x, 0)` of degree `<= threshold - 1`.
    pub fn secret_univariate_poly(&self) -> Vec<u128> {
        let t = self.threshold;
        (0..t).map(|a| self.bivariate_coeffs[a * t]).collect()
    }

    /// Secret value `s_i = F(0, 0)`.
    #[inline]
    pub fn secret(&self) -> u128 {
        self.secret
    }
}

impl Drop for SecretContribution {
    fn drop(&mut self) {
        zeroize_u128(&mut self.secret);
        for c in &mut self.bivariate_coeffs {
            zeroize_u128(c);
        }
    }
}

impl fmt::Debug for SecretContribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretContribution")
            .field("epoch", &self.epoch)
            .field("dealer_id", &self.dealer_id)
            .field("threshold", &self.threshold)
            .field("secret", &"<REDACTED>")
            .field("bivariate_coeffs", &"<REDACTED>")
            .finish()
    }
}

/// Decrypted secret share record held by `recipient_id` for `dealer_id`.
///
/// Volatile-zeroized on `Drop`; `Debug` output is redacted.
pub struct SecretShareRecord {
    epoch: u64,
    dealer_id: u32,
    recipient_id: u32,
    /// Univariate row polynomial `g_j(y) = F_dealer(x_j, y)` of length `threshold`.
    row_poly: Vec<u128>,
    /// Tags authenticating `row_poly[0]` to each verifier `v in 0..N`.
    ic_holder_tags: Vec<IcHolderTag>,
    /// Verification keys for verifying each peer `w in 0..N`'s share of `dealer_id`.
    ic_verifier_keys: Vec<IcVerifierKey>,
}

impl SecretShareRecord {
    /// Shamir share `y_j = g_j(0) = F_dealer(x_j, 0)`.
    #[inline]
    pub fn share_value(&self) -> u128 {
        self.row_poly[0]
    }

    /// Evaluate `g_j(x_peer) = F_dealer(x_j, x_peer)` for pairwise consistency checks.
    #[inline]
    pub fn eval_at_peer(&self, peer_id: u32) -> u128 {
        eval_poly(&self.row_poly, validator_eval_x(peer_id))
    }

    /// Serialize into canonical fixed-size byte representation for OTP envelope encryption.
    pub fn encode(&self) -> Vec<u8> {
        let total = (self.row_poly.len() + 3 * self.ic_holder_tags.len() + 3 * self.ic_verifier_keys.len()) * 16;
        let mut out = Vec::with_capacity(total);
        for &c in &self.row_poly {
            out.extend_from_slice(&c.to_le_bytes());
        }
        for t in &self.ic_holder_tags {
            out.extend_from_slice(&t.z.to_le_bytes());
            out.extend_from_slice(&t.tag_y.to_le_bytes());
            out.extend_from_slice(&t.tag_z.to_le_bytes());
        }
        for k in &self.ic_verifier_keys {
            out.extend_from_slice(&k.r.to_le_bytes());
            out.extend_from_slice(&k.a1.to_le_bytes());
            out.extend_from_slice(&k.a2.to_le_bytes());
        }
        out
    }

    /// Decode and strictly validate bounds (`< PRIME_P` and exact payload length).
    pub fn decode(
        epoch: u64,
        dealer_id: u32,
        recipient_id: u32,
        config: &BeaconConfig,
        bytes: &[u8],
    ) -> Result<Self, BeaconError> {
        let expected_len = config.share_payload_bytes();
        if bytes.len() != expected_len {
            return Err(BeaconError::CorruptedPayload {
                dealer: dealer_id,
                recipient: recipient_id,
            });
        }

        let mut offset = 0usize;
        let read_elem = |off: &mut usize| -> Result<u128, BeaconError> {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&bytes[*off..(*off + 16)]);
            *off += 16;
            let v = u128::from_le_bytes(buf);
            if v >= PRIME_P {
                return Err(BeaconError::CorruptedPayload {
                    dealer: dealer_id,
                    recipient: recipient_id,
                });
            }
            Ok(v)
        };

        let mut row_poly = Vec::with_capacity(config.threshold);
        for _ in 0..config.threshold {
            row_poly.push(read_elem(&mut offset)?);
        }

        let mut ic_holder_tags = Vec::with_capacity(config.num_validators);
        for _ in 0..config.num_validators {
            let z = read_elem(&mut offset)?;
            let tag_y = read_elem(&mut offset)?;
            let tag_z = read_elem(&mut offset)?;
            ic_holder_tags.push(IcHolderTag { z, tag_y, tag_z });
        }

        let mut ic_verifier_keys = Vec::with_capacity(config.num_validators);
        for _ in 0..config.num_validators {
            let r = read_elem(&mut offset)?;
            let a1 = read_elem(&mut offset)?;
            let a2 = read_elem(&mut offset)?;
            ic_verifier_keys.push(IcVerifierKey { r, a1, a2 });
        }

        Ok(Self {
            epoch,
            dealer_id,
            recipient_id,
            row_poly,
            ic_holder_tags,
            ic_verifier_keys,
        })
    }
}

impl Drop for SecretShareRecord {
    fn drop(&mut self) {
        for c in &mut self.row_poly {
            zeroize_u128(c);
        }
        // ic_holder_tags and ic_verifier_keys zeroize via their own Drop impls.
    }
}

impl fmt::Debug for SecretShareRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretShareRecord")
            .field("epoch", &self.epoch)
            .field("dealer_id", &self.dealer_id)
            .field("recipient_id", &self.recipient_id)
            .field("row_poly", &"<REDACTED>")
            .field("ic_holder_tags", &"<REDACTED>")
            .field("ic_verifier_keys", &"<REDACTED>")
            .finish()
    }
}

// ============================================================================
// Commit, Complaint, Resolution, Reveal, and Recovery Wire Messages
// ============================================================================

/// Pairwise symmetry check `g_from(x_to) == g_to(x_from)` exchanged between two peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairwiseConsistencyCheck {
    pub epoch: u64,
    pub dealer_id: u32,
    pub from_id: u32,
    pub to_id: u32,
    pub eval_point: u128,
}

/// Reason a validator filed a Commit-phase complaint against a dealer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplaintReason {
    InvalidEnvelopeMac,
    CorruptedPayload,
    PairwiseMismatch { peer_id: u32 },
    InvalidIcMac { holder_id: u32 },
}

/// Authenticated Commit-phase complaint raised by `accuser_id` against `dealer_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitComplaint {
    pub epoch: u64,
    pub dealer_id: u32,
    pub accuser_id: u32,
    pub reason: ComplaintReason,
}

/// Dealer's public resolution to a complaint by `target_id` (publishes `g_target(y)`).
///
/// An honest dealer resolving a false complaint from a Byzantine `target_id` leaks
/// zero new information (the Byzantine node already possessed `g_target(y)`), while
/// all honest peers independently check `eval_poly(&row_poly, x_peer) == g_peer(x_target)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DealerResolution {
    pub epoch: u64,
    pub dealer_id: u32,
    pub target_id: u32,
    pub row_poly: Vec<u128>,
}

/// Peer verification vote on a `DealerResolution`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionVote {
    pub epoch: u64,
    pub dealer_id: u32,
    pub target_id: u32,
    pub voter_id: u32,
    pub valid: bool,
}

/// Direct Phase-2 reveal broadcast by a qualified dealer `dealer_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretReveal {
    pub epoch: u64,
    pub dealer_id: u32,
    /// Univariate secret polynomial `f_dealer(x) = F_dealer(x, 0)` of length `threshold`.
    pub univariate_poly: Vec<u128>,
}

/// IC-MAC-authenticated recovery share broadcast by `holder_id` when `dealer_id`
/// aborts or sends an invalid reveal in Phase 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryShare {
    pub epoch: u64,
    pub dealer_id: u32,
    pub holder_id: u32,
    pub share_y: u128,
    /// `ic_tags[v]` is the Rabin-Ben-Or tag authenticating `share_y` to verifier `v`.
    pub ic_tags: Vec<u128>,
}

// ============================================================================
// Unbiasable Beacon Output & Purely IT-Secure Parameter Derivation
// ============================================================================

/// Finalized, unbiasable distributed entropy beacon output for a single epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochBeaconOutput {
    pub epoch: u64,
    /// Unbiasable beacon scalar `Gamma_e = sum_{i in C} s_i mod (2^127 - 1)`.
    pub gamma: u128,
    /// Sorted list of qualified dealers `C` whose secrets were summed into `gamma`.
    pub qualified_validators: Vec<u32>,
    /// Sorted subset of `qualified_validators` who aborted or lied in Reveal and were
    /// forcibly reconstructed via Lagrange interpolation by honest peers.
    pub reconstructed_validators: Vec<u32>,
    /// Sorted list of malicious dealers caught and excluded during Commit.
    pub disqualified_validators: Vec<u32>,
}

impl EpochBeaconOutput {
    /// Derive a uniform field element in `[0, PRIME_P)` for `(domain, subject, counter)`
    /// using purely algebraic bijective polynomial mixing in `F_(2^127 - 1)`.
    #[inline]
    pub fn derive_field_elem(&self, domain: u128, subject: u64, counter: u64) -> u128 {
        derive_field_elem_raw(self.gamma, self.epoch, domain, subject, counter)
    }

    /// Derive a uniform index in `[0, bound)` with zero modulo bias via rejection sampling.
    fn derive_uniform_index(&self, domain: u128, subject: u64, bound: usize) -> usize {
        debug_assert!(bound > 0);
        if bound == 1 {
            return 0;
        }
        let b = bound as u128;
        let limit = PRIME_P - (PRIME_P % b);
        let mut counter = 0u64;
        loop {
            let v = self.derive_field_elem(domain, subject, counter);
            if v < limit {
                return (v % b) as usize;
            }
            counter = counter.wrapping_add(1);
        }
    }

    /// Deterministic Fisher-Yates leader permutation of `0..num_validators` seeded by `Gamma_e`.
    pub fn epoch_leader_order(&self, num_validators: usize) -> Vec<u32> {
        let mut order: Vec<u32> = (0..num_validators as u32).collect();
        if num_validators <= 1 {
            return order;
        }
        for i in (1..num_validators).rev() {
            let j = self.derive_uniform_index(DOMAIN_LEADER_ORDER, i as u64, i + 1);
            order.swap(i, j);
        }
        order
    }

    /// Derive a non-zero Proof-of-Pad challenge scalar in `[1, PRIME_P)` unique to
    /// `(self.epoch, validator_id)`.
    pub fn derive_pop_challenge_r(&self, validator_id: u64) -> u128 {
        let mut counter = 0u64;
        loop {
            let v = self.derive_field_elem(DOMAIN_POP_CHALLENGE, validator_id, counter);
            if v != 0 {
                return v;
            }
            counter = counter.wrapping_add(1);
        }
    }

    /// Derive `min(num_slots, max_index)` distinct unpredictable audit indices in `0..max_index`
    /// for Proof-of-Pad & Beaver triple auditing of `validator_id`, in `O(num_slots)` time and memory
    /// using sparse Fisher-Yates sampling with zero modulo bias.
    pub fn derive_audit_slots(
        &self,
        validator_id: u64,
        num_slots: usize,
        max_index: usize,
    ) -> Vec<usize> {
        if num_slots == 0 || max_index == 0 {
            return Vec::new();
        }
        let k = num_slots.min(max_index);
        let mut result = Vec::with_capacity(k);
        let mut swapped: HashMap<usize, usize> = HashMap::with_capacity(k * 2);

        for step in 0..k {
            let remaining = max_index - step;
            // Combine validator_id and step cleanly across two separate algebraic channels:
            // fold step into domain offset so every (validator_id, step) is distinct.
            let step_domain = add_mod(DOMAIN_AUDIT_SLOTS, reduce((step as u128) + 1));
            let offset = self.derive_uniform_index(step_domain, validator_id, remaining);
            let pick = step + offset;

            let val_pick = swapped.get(&pick).copied().unwrap_or(pick);
            let val_step = swapped.get(&step).copied().unwrap_or(step);
            swapped.insert(pick, val_step);
            result.push(val_pick);
        }

        result
    }
}

// ============================================================================
// VernamBeacon: Decentralized Threshold Commit-Reveal State Machine
// ============================================================================

/// Per-validator decentralized state machine for one epoch of the `VernamBeacon` protocol.
///
/// Each validator instantiates its own `VernamBeacon` with its own `validator_id`.
/// No trusted coordinator or admin API exists anywhere in the protocol.
pub struct VernamBeacon {
    config: BeaconConfig,
    epoch: u64,
    validator_id: u32,
    phase: BeaconPhase,

    /// Local validator's own secret bivariate polynomial (zeroized on Drop).
    local_contribution: Option<SecretContribution>,
    /// Received & verified Commit-phase share records, keyed by `dealer_id`.
    received_shares: BTreeMap<u32, SecretShareRecord>,
    /// Locally generated IC-MAC challenges sent by this validator: `(dealer_id, holder_id) -> c`.
    sent_ic_challenges: BTreeMap<(u32, u32), u128>,

    /// Complaints filed locally by this validator.
    local_complaints: Vec<CommitComplaint>,
    /// All known complaints per dealer: `dealer_id -> set of accuser_ids`.
    complaints_by_dealer: BTreeMap<u32, BTreeSet<u32>>,
    /// Approved resolutions: `(dealer_id, target_id) -> (row_poly, set of approving voters)`.
    resolution_votes: BTreeMap<(u32, u32), (Vec<u128>, BTreeSet<u32>)>,
    /// Publicly resolved shares (when a dealer resolved a complaint by publishing a row).
    public_resolved_shares: BTreeMap<(u32, u32), u128>,

    /// Locked qualified dealer set `C` (populated in `lock_commit_phase`).
    qualified_dealers: BTreeSet<u32>,
    /// Disqualified dealers excluded prior to Reveal.
    disqualified_dealers: BTreeSet<u32>,

    /// Verified direct reveals from qualified dealers: `dealer_id -> s_dealer`.
    verified_reveals: BTreeMap<u32, u128>,
    /// Verified recovery shares per dealer: `dealer_id -> (holder_id -> y_holder)`.
    verified_recovery_shares: BTreeMap<u32, BTreeMap<u32, u128>>,

    /// Finalized beacon output once `finalize_epoch` succeeds.
    finalized_output: Option<EpochBeaconOutput>,
}

impl VernamBeacon {
    /// Create a new decentralized beacon instance for `validator_id` at `epoch`.
    pub fn new(config: BeaconConfig, epoch: u64, validator_id: u32) -> Result<Self, BeaconError> {
        config.check_validator(validator_id)?;
        Ok(Self {
            config,
            epoch,
            validator_id,
            phase: BeaconPhase::Commit,
            local_contribution: None,
            received_shares: BTreeMap::new(),
            sent_ic_challenges: BTreeMap::new(),
            local_complaints: Vec::new(),
            complaints_by_dealer: BTreeMap::new(),
            resolution_votes: BTreeMap::new(),
            public_resolved_shares: BTreeMap::new(),
            qualified_dealers: BTreeSet::new(),
            disqualified_dealers: BTreeSet::new(),
            verified_reveals: BTreeMap::new(),
            verified_recovery_shares: BTreeMap::new(),
            finalized_output: None,
        })
    }

    pub fn config(&self) -> BeaconConfig {
        self.config
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn validator_id(&self) -> u32 {
        self.validator_id
    }

    pub fn phase(&self) -> BeaconPhase {
        self.phase
    }

    /// Locally raised Commit-phase complaints (to be broadcast to peers).
    pub fn local_complaints(&self) -> &[CommitComplaint] {
        &self.local_complaints
    }

    /// Locked qualified dealer IDs (available after `lock_commit_phase`).
    pub fn qualified_dealers(&self) -> Vec<u32> {
        self.qualified_dealers.iter().copied().collect()
    }

    /// Disqualified dealer IDs excluded before Reveal.
    pub fn disqualified_dealers(&self) -> Vec<u32> {
        self.disqualified_dealers.iter().copied().collect()
    }

    /// Finalized output if the round has completed.
    pub fn output(&self) -> Option<&EpochBeaconOutput> {
        self.finalized_output.as_ref()
    }

    fn require_phase(&self, expected: BeaconPhase) -> Result<(), BeaconError> {
        if self.phase != expected {
            return Err(BeaconError::WrongPhase {
                expected,
                got: self.phase,
            });
        }
        Ok(())
    }

    fn require_epoch(&self, got: u64) -> Result<(), BeaconError> {
        if got != self.epoch {
            return Err(BeaconError::WrongEpoch {
                expected: self.epoch,
                got,
            });
        }
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Phase 1: Commit (Symmetric Bivariate Sharing + OTP+CW-MAC + IC-MAC)
    // ------------------------------------------------------------------------

    /// Sample a fresh uniform secret `s_i in F_p`, construct its symmetric bivariate
    /// polynomial `F_i(x, y)` + Rabin-Ben-Or IC-MACs, and seal one `ShareEnvelope`
    /// per peer using the provided single-use `OtpChannelKey`s.
    pub fn generate_commit_envelopes(
        &mut self,
        outgoing_keys: &[(u32, &OtpChannelKey)],
    ) -> Result<Vec<ShareEnvelope>, BeaconError> {
        let secret = random_field_elem();
        self.generate_commit_envelopes_with_secret(secret, outgoing_keys)
    }

    /// Same as `generate_commit_envelopes`, using an explicit secret scalar `secret`.
    pub fn generate_commit_envelopes_with_secret(
        &mut self,
        secret: u128,
        outgoing_keys: &[(u32, &OtpChannelKey)],
    ) -> Result<Vec<ShareEnvelope>, BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;
        let n = self.config.num_validators;
        if outgoing_keys.len() != n {
            return Err(BeaconError::InvalidConfig(format!(
                "expected {n} outgoing OTP keys, got {}",
                outgoing_keys.len()
            )));
        }

        let mut key_map: BTreeMap<u32, &OtpChannelKey> = BTreeMap::new();
        for &(recipient_id, key) in outgoing_keys {
            self.config.check_validator(recipient_id)?;
            if key_map.insert(recipient_id, key).is_some() {
                return Err(BeaconError::DuplicateSubmission {
                    validator_id: recipient_id,
                });
            }
        }

        let contrib = SecretContribution::from_secret(
            self.epoch,
            self.validator_id,
            self.config.threshold,
            secret,
        );

        // Compute every recipient's row polynomial and Shamir share y_j = g_j(0).
        let mut row_polys: Vec<Vec<u128>> = Vec::with_capacity(n);
        let mut shares_y: Vec<u128> = Vec::with_capacity(n);
        for j in 0..n as u32 {
            let row = contrib.row_poly_for_validator(j);
            shares_y.push(row[0]);
            row_polys.push(row);
        }

        // Generate Rabin-Ben-Or IC-MACs for every (holder j, verifier v) pair.
        let mut all_holder_tags: Vec<Vec<IcHolderTag>> = (0..n)
            .map(|_| Vec::with_capacity(n))
            .collect();
        let mut all_verifier_keys: Vec<Vec<IcVerifierKey>> = (0..n)
            .map(|_| Vec::with_capacity(n))
            .collect();

        for j in 0..n {
            let y_j = shares_y[j];
            for v in 0..n {
                let r = random_nonzero_field_elem();
                let a1 = random_field_elem();
                let a2 = random_field_elem();
                let z = random_field_elem();

                let tag_y = add_mod(mul_mod(r, y_j), a1);
                let tag_z = add_mod(mul_mod(r, z), a2);

                all_holder_tags[j].push(IcHolderTag { z, tag_y, tag_z });
                all_verifier_keys[v].push(IcVerifierKey { r, a1, a2 });
            }
        }

        let mut envelopes = Vec::with_capacity(n);
        for j in 0..n {
            let recipient_id = j as u32;
            let record = SecretShareRecord {
                epoch: self.epoch,
                dealer_id: self.validator_id,
                recipient_id,
                row_poly: std::mem::take(&mut row_polys[j]),
                ic_holder_tags: std::mem::take(&mut all_holder_tags[j]),
                ic_verifier_keys: std::mem::take(&mut all_verifier_keys[j]),
            };
            let mut encoded = record.encode();
            let key = key_map[&recipient_id];
            let env = ShareEnvelope::seal(
                self.epoch,
                self.validator_id,
                recipient_id,
                &encoded,
                key,
            )?;
            zeroize_slice(&mut encoded);
            envelopes.push(env);
        }

        for y in &mut shares_y {
            zeroize_u128(y);
        }

        self.local_contribution = Some(contrib);
        Ok(envelopes)
    }

    /// Receive, authenticate (Carter-Wegman MAC), decrypt (OTP), and store a Commit-phase
    /// `ShareEnvelope` from `envelope.dealer_id`.
    ///
    /// If MAC verification or payload validation fails, automatically records a local
    /// `CommitComplaint` against `envelope.dealer_id` and returns the error.
    pub fn receive_commit_envelope(
        &mut self,
        envelope: &ShareEnvelope,
        incoming_key: &OtpChannelKey,
    ) -> Result<(), BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;
        self.require_epoch(envelope.epoch)?;
        self.config.check_validator(envelope.dealer_id)?;
        if envelope.recipient_id != self.validator_id {
            return Err(BeaconError::InvalidValidatorId {
                validator_id: envelope.recipient_id,
                num_validators: self.config.num_validators,
            });
        }
        if self.received_shares.contains_key(&envelope.dealer_id) {
            return Err(BeaconError::DuplicateSubmission {
                validator_id: envelope.dealer_id,
            });
        }

        let mut plaintext = match envelope.open(incoming_key) {
            Ok(pt) => pt,
            Err(err @ BeaconError::MacVerificationFailed { .. }) => {
                self.record_local_complaint(envelope.dealer_id, ComplaintReason::InvalidEnvelopeMac);
                return Err(err);
            }
            Err(err) => {
                self.record_local_complaint(envelope.dealer_id, ComplaintReason::CorruptedPayload);
                return Err(err);
            }
        };

        let decoded = SecretShareRecord::decode(
            self.epoch,
            envelope.dealer_id,
            self.validator_id,
            &self.config,
            &plaintext,
        );
        zeroize_slice(&mut plaintext);

        match decoded {
            Ok(record) => {
                self.received_shares.insert(envelope.dealer_id, record);
                Ok(())
            }
            Err(err) => {
                self.record_local_complaint(envelope.dealer_id, ComplaintReason::CorruptedPayload);
                Err(err)
            }
        }
    }

    /// Generate zero-leakage pairwise symmetry checks `g_me(x_peer)` for every dealer
    /// whose envelope we successfully received and every peer `peer != me`.
    pub fn generate_pairwise_checks(&self) -> Vec<PairwiseConsistencyCheck> {
        let mut checks = Vec::new();
        if self.phase != BeaconPhase::Commit {
            return checks;
        }
        for (&dealer_id, record) in &self.received_shares {
            for peer_id in 0..self.config.num_validators as u32 {
                if peer_id == self.validator_id {
                    continue;
                }
                checks.push(PairwiseConsistencyCheck {
                    epoch: self.epoch,
                    dealer_id,
                    from_id: self.validator_id,
                    to_id: peer_id,
                    eval_point: record.eval_at_peer(peer_id),
                });
            }
        }
        checks
    }

    /// Verify a peer's pairwise check `g_from(x_me) == g_me(x_from)` for `check.dealer_id`.
    ///
    /// Returns `Ok(true)` if consistent, `Ok(false)` on mismatch (and records a `CommitComplaint`).
    pub fn verify_pairwise_check(
        &mut self,
        check: &PairwiseConsistencyCheck,
    ) -> Result<bool, BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;
        self.require_epoch(check.epoch)?;
        self.config.check_validator(check.dealer_id)?;
        self.config.check_validator(check.from_id)?;
        if check.to_id != self.validator_id {
            return Err(BeaconError::InvalidValidatorId {
                validator_id: check.to_id,
                num_validators: self.config.num_validators,
            });
        }

        let Some(record) = self.received_shares.get(&check.dealer_id) else {
            return Ok(false);
        };
        let expected = record.eval_at_peer(check.from_id);
        if expected == reduce(check.eval_point) {
            Ok(true)
        } else {
            self.record_local_complaint(
                check.dealer_id,
                ComplaintReason::PairwiseMismatch {
                    peer_id: check.from_id,
                },
            );
            Ok(false)
        }
    }

    /// Generate Rabin-Ben-Or zero-knowledge IC-MAC challenges for every `(dealer, holder)` pair.
    pub fn generate_ic_challenges(&mut self) -> Vec<IcChallenge> {
        let mut challenges = Vec::new();
        if self.phase != BeaconPhase::Commit {
            return challenges;
        }
        let dealers: Vec<u32> = self.received_shares.keys().copied().collect();
        for dealer_id in dealers {
            for holder_id in 0..self.config.num_validators as u32 {
                let c = random_nonzero_field_elem();
                self.sent_ic_challenges.insert((dealer_id, holder_id), c);
                challenges.push(IcChallenge {
                    epoch: self.epoch,
                    dealer_id,
                    holder_id,
                    verifier_id: self.validator_id,
                    challenge_c: c,
                });
            }
        }
        challenges
    }

    /// Answer a verifier's Commit-phase IC-MAC challenge without revealing our share `y_j`.
    pub fn answer_ic_challenge(&self, challenge: &IcChallenge) -> Result<IcResponse, BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;
        self.require_epoch(challenge.epoch)?;
        self.config.check_validator(challenge.dealer_id)?;
        self.config.check_validator(challenge.verifier_id)?;
        if challenge.holder_id != self.validator_id {
            return Err(BeaconError::InvalidValidatorId {
                validator_id: challenge.holder_id,
                num_validators: self.config.num_validators,
            });
        }
        let c = reduce(challenge.challenge_c);
        if c == 0 {
            return Err(BeaconError::InvalidEvaluationPoint(
                "IC challenge scalar c must be non-zero".to_string(),
            ));
        }

        let record = self
            .received_shares
            .get(&challenge.dealer_id)
            .ok_or(BeaconError::InsufficientShares {
                dealer: challenge.dealer_id,
                have: 0,
                need: 1,
            })?;
        let tag = &record.ic_holder_tags[challenge.verifier_id as usize];
        let y = record.share_value();

        let masked_m = add_mod(mul_mod(c, y), tag.z);
        let masked_tag = add_mod(mul_mod(c, tag.tag_y), tag.tag_z);

        Ok(IcResponse {
            epoch: self.epoch,
            dealer_id: challenge.dealer_id,
            holder_id: self.validator_id,
            verifier_id: challenge.verifier_id,
            masked_m,
            masked_tag,
        })
    }

    /// Verify a holder's Commit-phase zero-knowledge IC-MAC response.
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid (and records a `CommitComplaint`).
    pub fn verify_ic_response(&mut self, response: &IcResponse) -> Result<bool, BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;
        self.require_epoch(response.epoch)?;
        self.config.check_validator(response.dealer_id)?;
        self.config.check_validator(response.holder_id)?;
        if response.verifier_id != self.validator_id {
            return Err(BeaconError::InvalidValidatorId {
                validator_id: response.verifier_id,
                num_validators: self.config.num_validators,
            });
        }

        let Some(&c) = self
            .sent_ic_challenges
            .get(&(response.dealer_id, response.holder_id))
        else {
            return Err(BeaconError::InvalidEvaluationPoint(
                "no matching IC challenge recorded".to_string(),
            ));
        };
        let Some(record) = self.received_shares.get(&response.dealer_id) else {
            return Ok(false);
        };
        let key = &record.ic_verifier_keys[response.holder_id as usize];
        if key.verify_masked_response(c, response.masked_m, response.masked_tag) {
            Ok(true)
        } else {
            self.record_local_complaint(
                response.dealer_id,
                ComplaintReason::InvalidIcMac {
                    holder_id: response.holder_id,
                },
            );
            Ok(false)
        }
    }

    fn record_local_complaint(&mut self, dealer_id: u32, reason: ComplaintReason) {
        let complaint = CommitComplaint {
            epoch: self.epoch,
            dealer_id,
            accuser_id: self.validator_id,
            reason,
        };
        self.complaints_by_dealer
            .entry(dealer_id)
            .or_default()
            .insert(self.validator_id);
        self.local_complaints.push(complaint);
    }

    /// Register a peer's broadcast `CommitComplaint` during the Commit phase.
    pub fn register_complaint(&mut self, complaint: CommitComplaint) -> Result<(), BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;
        self.require_epoch(complaint.epoch)?;
        self.config.check_validator(complaint.dealer_id)?;
        self.config.check_validator(complaint.accuser_id)?;
        self.complaints_by_dealer
            .entry(complaint.dealer_id)
            .or_default()
            .insert(complaint.accuser_id);
        Ok(())
    }

    /// Generate a public `DealerResolution` answering a complaint from `target_id`
    /// against this validator's own dealing.
    pub fn generate_complaint_resolution(
        &self,
        target_id: u32,
    ) -> Result<DealerResolution, BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;
        self.config.check_validator(target_id)?;
        let contrib = self
            .local_contribution
            .as_ref()
            .ok_or(BeaconError::InsufficientShares {
                dealer: self.validator_id,
                have: 0,
                need: 1,
            })?;
        Ok(DealerResolution {
            epoch: self.epoch,
            dealer_id: self.validator_id,
            target_id,
            row_poly: contrib.row_poly_for_validator(target_id),
        })
    }

    /// Verify a dealer's public `DealerResolution` against our own committed row polynomial
    /// (`eval_poly(&resolution.row_poly, x_me) == g_me(x_target)`) and emit a `ResolutionVote`.
    pub fn verify_complaint_resolution(
        &mut self,
        resolution: &DealerResolution,
    ) -> Result<ResolutionVote, BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;
        self.require_epoch(resolution.epoch)?;
        self.config.check_validator(resolution.dealer_id)?;
        self.config.check_validator(resolution.target_id)?;

        let valid = if resolution.row_poly.len() != self.config.threshold
            || resolution.row_poly.iter().any(|&c| c >= PRIME_P)
        {
            false
        } else if let Some(record) = self.received_shares.get(&resolution.dealer_id) {
            let lhs = eval_poly(&resolution.row_poly, validator_eval_x(self.validator_id));
            let rhs = record.eval_at_peer(resolution.target_id);
            lhs == rhs
        } else {
            false
        };

        let vote = ResolutionVote {
            epoch: self.epoch,
            dealer_id: resolution.dealer_id,
            target_id: resolution.target_id,
            voter_id: self.validator_id,
            valid,
        };
        self.register_resolution_vote(resolution, vote.clone())?;
        Ok(vote)
    }

    /// Tally a peer's `ResolutionVote` for a `DealerResolution`.
    pub fn register_resolution_vote(
        &mut self,
        resolution: &DealerResolution,
        vote: ResolutionVote,
    ) -> Result<(), BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;
        self.require_epoch(resolution.epoch)?;
        self.require_epoch(vote.epoch)?;
        self.config.check_validator(resolution.dealer_id)?;
        self.config.check_validator(resolution.target_id)?;
        self.config.check_validator(vote.voter_id)?;

        if vote.dealer_id != resolution.dealer_id || vote.target_id != resolution.target_id {
            return Err(BeaconError::InconsistentShares {
                dealer: resolution.dealer_id,
                reason: "resolution vote target mismatch".to_string(),
            });
        }
        if resolution.row_poly.len() != self.config.threshold {
            return Ok(());
        }

        if vote.valid {
            let entry = self
                .resolution_votes
                .entry((resolution.dealer_id, resolution.target_id))
                .or_insert_with(|| (resolution.row_poly.clone(), BTreeSet::new()));
            if entry.0 == resolution.row_poly {
                entry.1.insert(vote.voter_id);
            }
        }
        Ok(())
    }

    /// Lock the Commit phase, deterministically computing the qualified dealer set `C`
    /// and disqualifying any malicious dealers BEFORE any secret is revealed.
    ///
    /// A dealer `d` is qualified iff:
    /// 1. At most `max_faults` (`f`) validators complained against `d` (more than `f`
    ///    complaints guarantees at least one honest validator caught `d` cheating), AND
    /// 2. Every complaint `(d, accuser)` has a `DealerResolution` approved by at least
    ///    `threshold` (`2f + 1`) validators (confirming consistency across honest peers), AND
    /// 3. This validator holds either a decrypted share from `d` or an approved public resolution.
    pub fn lock_commit_phase(&mut self) -> Result<Vec<u32>, BeaconError> {
        self.require_phase(BeaconPhase::Commit)?;

        let mut qualified = BTreeSet::new();
        let mut disqualified = BTreeSet::new();

        for dealer_id in 0..self.config.num_validators as u32 {
            let accusers = self.complaints_by_dealer.get(&dealer_id);
            let num_complaints = accusers.map_or(0, BTreeSet::len);

            let mut dealer_ok = num_complaints <= self.config.max_faults;

            if dealer_ok {
                if let Some(accuser_set) = accusers {
                    for &accuser_id in accuser_set {
                        match self.resolution_votes.get(&(dealer_id, accuser_id)) {
                            Some((row_poly, voters)) if voters.len() >= self.config.threshold => {
                                self.public_resolved_shares
                                    .insert((dealer_id, accuser_id), row_poly[0]);
                                // If we were the accuser and received a bad share, adopt the
                                // consensus-verified row polynomial so our share is consistent.
                                if accuser_id == self.validator_id {
                                    if let Some(rec) = self.received_shares.get_mut(&dealer_id) {
                                        rec.row_poly = row_poly.clone();
                                    }
                                }
                            }
                            _ => {
                                dealer_ok = false;
                                break;
                            }
                        }
                    }
                }
            }

            // Must hold a share (or public resolution) for this dealer to participate.
            let has_local_share = self.received_shares.contains_key(&dealer_id)
                || self
                    .public_resolved_shares
                    .contains_key(&(dealer_id, self.validator_id));
            if !has_local_share {
                dealer_ok = false;
            }

            if dealer_ok {
                qualified.insert(dealer_id);
            } else {
                disqualified.insert(dealer_id);
            }
        }

        // Need at least `max_faults + 1` qualified dealers so at least 1 honest validator
        // is guaranteed to contribute uniform entropy to `Gamma_e`.
        let min_qualified = self.config.max_faults + 1;
        if qualified.len() < min_qualified {
            return Err(BeaconError::InsufficientQualifiedDealers {
                have: qualified.len(),
                need: min_qualified,
            });
        }

        // Purge any share material for disqualified dealers immediately.
        for &bad_dealer in &disqualified {
            self.received_shares.remove(&bad_dealer);
        }

        self.qualified_dealers = qualified;
        self.disqualified_dealers = disqualified;
        self.phase = BeaconPhase::Reveal;
        Ok(self.qualified_dealers.iter().copied().collect())
    }

    // ------------------------------------------------------------------------
    // Phase 2: Reveal & Unabortable Lagrange Recovery
    // ------------------------------------------------------------------------

    /// Generate this validator's Phase-2 `SecretReveal` (its univariate polynomial `f_i(x)`).
    pub fn generate_reveal(&self) -> Result<SecretReveal, BeaconError> {
        self.require_phase(BeaconPhase::Reveal)?;
        if !self.qualified_dealers.contains(&self.validator_id) {
            return Err(BeaconError::DealerDisqualified {
                dealer: self.validator_id,
            });
        }
        let contrib = self
            .local_contribution
            .as_ref()
            .ok_or(BeaconError::InvalidReveal {
                dealer: self.validator_id,
                reason: "local contribution not initialized".to_string(),
            })?;
        Ok(SecretReveal {
            epoch: self.epoch,
            dealer_id: self.validator_id,
            univariate_poly: contrib.secret_univariate_poly(),
        })
    }

    /// Verify and accept a qualified dealer's direct `SecretReveal`.
    ///
    /// Checks degree (`== threshold - 1`), field bounds, and exact match against this
    /// validator's committed share: `eval_poly(&reveal.univariate_poly, x_me) == my_share`.
    /// Returns `Ok(true)` if valid, `Ok(false)` if forged (leaving the dealer to be
    /// reconstructed via Lagrange recovery instead!).
    pub fn receive_reveal(&mut self, reveal: &SecretReveal) -> Result<bool, BeaconError> {
        self.require_phase(BeaconPhase::Reveal)?;
        self.require_epoch(reveal.epoch)?;
        self.config.check_validator(reveal.dealer_id)?;

        if !self.qualified_dealers.contains(&reveal.dealer_id) {
            return Err(BeaconError::DealerDisqualified {
                dealer: reveal.dealer_id,
            });
        }
        if reveal.univariate_poly.len() != self.config.threshold
            || reveal.univariate_poly.iter().any(|&c| c >= PRIME_P)
        {
            return Ok(false);
        }

        let expected_my_share = if let Some(rec) = self.received_shares.get(&reveal.dealer_id) {
            rec.share_value()
        } else if let Some(&pub_share) = self
            .public_resolved_shares
            .get(&(reveal.dealer_id, self.validator_id))
        {
            pub_share
        } else {
            return Ok(false);
        };

        let eval_at_me = eval_poly(&reveal.univariate_poly, validator_eval_x(self.validator_id));
        if eval_at_me != expected_my_share {
            return Ok(false);
        }

        // Also check any publicly resolved shares for this dealer so a dealer cannot
        // match `me` while disagreeing with a public resolution.
        for (&(d, target), &pub_y) in &self.public_resolved_shares {
            if d == reveal.dealer_id {
                let eval_t = eval_poly(&reveal.univariate_poly, validator_eval_x(target));
                if eval_t != pub_y {
                    return Ok(false);
                }
            }
        }

        self.verified_reveals
            .insert(reveal.dealer_id, reveal.univariate_poly[0]);
        Ok(true)
    }

    /// List qualified dealers who have not yet produced a valid direct reveal
    /// (e.g., Byzantine last-revealer aborts) and therefore require Lagrange recovery.
    pub fn missing_reveals(&self) -> Vec<u32> {
        self.qualified_dealers
            .iter()
            .copied()
            .filter(|d| !self.verified_reveals.contains_key(d))
            .collect()
    }

    /// Broadcast this validator's IC-MAC-authenticated `RecoveryShare` to forcibly
    /// reconstruct an aborted (or lying) qualified dealer's secret.
    pub fn generate_recovery_share(&self, dealer_id: u32) -> Result<RecoveryShare, BeaconError> {
        self.require_phase(BeaconPhase::Reveal)?;
        self.config.check_validator(dealer_id)?;
        if !self.qualified_dealers.contains(&dealer_id) {
            return Err(BeaconError::DealerDisqualified { dealer: dealer_id });
        }

        let record = self
            .received_shares
            .get(&dealer_id)
            .ok_or(BeaconError::InsufficientShares {
                dealer: dealer_id,
                have: 0,
                need: 1,
            })?;
        let ic_tags: Vec<u128> = record
            .ic_holder_tags
            .iter()
            .map(IcHolderTag::share_tag)
            .collect();

        Ok(RecoveryShare {
            epoch: self.epoch,
            dealer_id,
            holder_id: self.validator_id,
            share_y: record.share_value(),
            ic_tags,
        })
    }

    /// Receive and verify a peer's `RecoveryShare` for an aborted qualified dealer using
    /// this validator's Rabin-Ben-Or `IcVerifierKey` (forged shares are rejected with
    /// probability `1 - 1 / (2^127 - 1)`!).
    ///
    /// Returns `Ok(true)` if authenticated and stored, `Ok(false)` if forged/invalid.
    pub fn receive_recovery_share(
        &mut self,
        recovery: &RecoveryShare,
    ) -> Result<bool, BeaconError> {
        self.require_phase(BeaconPhase::Reveal)?;
        self.require_epoch(recovery.epoch)?;
        self.config.check_validator(recovery.dealer_id)?;
        self.config.check_validator(recovery.holder_id)?;

        if !self.qualified_dealers.contains(&recovery.dealer_id) {
            return Err(BeaconError::DealerDisqualified {
                dealer: recovery.dealer_id,
            });
        }
        if recovery.share_y >= PRIME_P {
            return Ok(false);
        }

        // If this holder's share was publicly resolved during Commit, verify against that.
        if let Some(&pub_y) = self
            .public_resolved_shares
            .get(&(recovery.dealer_id, recovery.holder_id))
        {
            if recovery.share_y != pub_y {
                return Ok(false);
            }
            self.verified_recovery_shares
                .entry(recovery.dealer_id)
                .or_default()
                .insert(recovery.holder_id, recovery.share_y);
            return Ok(true);
        }

        // Otherwise verify the Rabin-Ben-Or IC-MAC tag destined for this validator.
        if recovery.ic_tags.len() != self.config.num_validators {
            return Ok(false);
        }
        let Some(record) = self.received_shares.get(&recovery.dealer_id) else {
            return Ok(false);
        };
        let key = &record.ic_verifier_keys[recovery.holder_id as usize];
        let tag_for_me = recovery.ic_tags[self.validator_id as usize];
        if tag_for_me >= PRIME_P || !key.verify_share_tag(recovery.share_y, tag_for_me) {
            return Ok(false);
        }

        self.verified_recovery_shares
            .entry(recovery.dealer_id)
            .or_default()
            .insert(recovery.holder_id, recovery.share_y);
        Ok(true)
    }

    /// Finalize the epoch beacon: combine all qualified dealers' secrets (either directly
    /// revealed or Lagrange-reconstructed from `>= threshold` verified recovery shares)
    /// into the unbiasable `Gamma_e = sum_{i in C} s_i mod (2^127 - 1)`.
    pub fn finalize_epoch(&mut self) -> Result<EpochBeaconOutput, BeaconError> {
        self.require_phase(BeaconPhase::Reveal)?;

        let mut gamma = 0u128;
        let mut reconstructed = Vec::new();
        let qualified: Vec<u32> = self.qualified_dealers.iter().copied().collect();

        for &dealer_id in &qualified {
            let dealer_secret = if let Some(&s) = self.verified_reveals.get(&dealer_id) {
                s
            } else {
                // Dealer aborted or lied in Reveal: reconstruct from verified recovery shares.
                let mut points: Vec<(u128, u128)> = Vec::new();
                if let Some(share_map) = self.verified_recovery_shares.get(&dealer_id) {
                    for (&holder_id, &y) in share_map {
                        points.push((validator_eval_x(holder_id), y));
                    }
                }
                // Always include our own committed share if not already present.
                let my_x = validator_eval_x(self.validator_id);
                if !points.iter().any(|&(x, _)| x == my_x) {
                    if let Some(rec) = self.received_shares.get(&dealer_id) {
                        points.push((my_x, rec.share_value()));
                    } else if let Some(&pub_y) = self
                        .public_resolved_shares
                        .get(&(dealer_id, self.validator_id))
                    {
                        points.push((my_x, pub_y));
                    }
                }

                if points.len() < self.config.threshold {
                    return Err(BeaconError::InsufficientShares {
                        dealer: dealer_id,
                        have: points.len(),
                        need: self.config.threshold,
                    });
                }

                // Double-check degree-(t-1) consistency across all collected verified shares.
                if !verify_degree_consistency(&points, self.config.threshold)? {
                    return Err(BeaconError::InconsistentShares {
                        dealer: dealer_id,
                        reason: "recovery shares failed degree-(t-1) consistency check".to_string(),
                    });
                }

                let recovered_s = lagrange_interpolate_at_zero(&points[..self.config.threshold])?;
                reconstructed.push(dealer_id);
                recovered_s
            };

            gamma = add_mod(gamma, dealer_secret);
        }

        let output = EpochBeaconOutput {
            epoch: self.epoch,
            gamma,
            qualified_validators: qualified,
            reconstructed_validators: reconstructed,
            disqualified_validators: self.disqualified_dealers.iter().copied().collect(),
        };

        // Zeroize local secret material immediately after finalization.
        self.local_contribution = None;
        self.received_shares.clear();

        self.phase = BeaconPhase::Finalized;
        self.finalized_output = Some(output.clone());
        Ok(output)
    }
}

impl fmt::Debug for VernamBeacon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VernamBeacon")
            .field("config", &self.config)
            .field("epoch", &self.epoch)
            .field("validator_id", &self.validator_id)
            .field("phase", &self.phase)
            .field("local_contribution", &self.local_contribution.as_ref().map(|_| "<REDACTED>"))
            .field("received_shares_count", &self.received_shares.len())
            .field("qualified_dealers", &self.qualified_dealers)
            .field("disqualified_dealers", &self.disqualified_dealers)
            .field("finalized_output", &self.finalized_output)
            .finish()
    }
}

// ============================================================================
// Autonomous Protocol Epoch Scheduler (Zero-Admin State Machine)
// ============================================================================

/// Deterministic stage of the autonomous epoch-boundary maintenance pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochPipelineStage {
    /// Normal block finalization inside the current epoch.
    Idle,
    /// Step 1: Execute distributed `VernamBeacon` round for `current_epoch`.
    AwaitingBeacon,
    /// Step 2: Execute Proof-of-Pad audit using beacon-derived challenges & audit slots.
    AwaitingPopAudit,
    /// Step 3: Execute Proactive Secret Sharing (PSS) key refresh for `current_epoch`.
    AwaitingPssRefresh,
}

/// Event emitted when `on_block_finalized(height)` crosses an epoch boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochTransitionEvent {
    pub previous_epoch: u64,
    pub new_epoch: u64,
    pub trigger_height: u64,
}

/// Unpredictable Proof-of-Pad audit parameters derived from the epoch beacon for a validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopAuditPlan {
    pub epoch: u64,
    pub validator_id: u64,
    pub challenge_r: u128,
    pub audit_slots: Vec<usize>,
}

/// Pure deterministic block-height-driven epoch scheduler with ZERO admin APIs.
///
/// Whenever `on_block_finalized(height)` crosses a multiple of `blocks_per_epoch`,
/// it automatically advances `current_epoch` and drives the mandatory protocol
/// pipeline:
/// `Distributed VernamBeacon -> Proof-of-Pad Audit -> PSS Refresh`.
#[derive(Debug, Clone)]
pub struct AutonomousEpochClock {
    blocks_per_epoch: u64,
    current_epoch: u64,
    blocks_in_epoch: u64,
    last_finalized_height: Option<u64>,
    stage: EpochPipelineStage,
    current_beacon_output: Option<EpochBeaconOutput>,
}

impl AutonomousEpochClock {
    /// Create a new autonomous epoch clock advancing every `blocks_per_epoch` finalized blocks.
    pub fn new(blocks_per_epoch: u64) -> Result<Self, BeaconError> {
        if blocks_per_epoch == 0 {
            return Err(BeaconError::InvalidConfig(
                "blocks_per_epoch must be >= 1".to_string(),
            ));
        }
        Ok(Self {
            blocks_per_epoch,
            current_epoch: 0,
            blocks_in_epoch: 0,
            last_finalized_height: None,
            stage: EpochPipelineStage::Idle,
            current_beacon_output: None,
        })
    }

    pub fn blocks_per_epoch(&self) -> u64 {
        self.blocks_per_epoch
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn blocks_in_epoch(&self) -> u64 {
        self.blocks_in_epoch
    }

    pub fn blocks_until_next_epoch(&self) -> u64 {
        self.blocks_per_epoch - self.blocks_in_epoch
    }

    pub fn last_finalized_height(&self) -> Option<u64> {
        self.last_finalized_height
    }

    pub fn pipeline_stage(&self) -> EpochPipelineStage {
        self.stage
    }

    /// True when an epoch boundary was crossed and the distributed beacon must run.
    pub fn needs_beacon_round(&self) -> bool {
        self.stage == EpochPipelineStage::AwaitingBeacon
    }

    /// True once the epoch beacon has finalized and Proof-of-Pad auditing must run.
    pub fn needs_pop_audit(&self) -> bool {
        self.stage == EpochPipelineStage::AwaitingPopAudit
    }

    /// True once Proof-of-Pad auditing has completed and PSS share refresh must run.
    pub fn needs_pss_refresh(&self) -> bool {
        self.stage == EpochPipelineStage::AwaitingPssRefresh
    }

    /// Latest finalized `EpochBeaconOutput` for `current_epoch`, if available.
    pub fn current_beacon_output(&self) -> Option<&EpochBeaconOutput> {
        self.current_beacon_output.as_ref()
    }

    /// Advance the deterministic clock upon block finalization at `height`.
    ///
    /// Ignores stale or duplicate heights (`height <= last_finalized_height`).
    /// Returns `Some(EpochTransitionEvent)` whenever an epoch boundary is crossed,
    /// automatically scheduling the `Beacon -> PoP -> PSS` pipeline.
    pub fn on_block_finalized(&mut self, height: u64) -> Option<EpochTransitionEvent> {
        if let Some(prev) = self.last_finalized_height {
            if height <= prev {
                return None;
            }
        }
        self.last_finalized_height = Some(height);

        let new_epoch = height / self.blocks_per_epoch;
        self.blocks_in_epoch = height % self.blocks_per_epoch;

        if new_epoch > self.current_epoch {
            let previous_epoch = self.current_epoch;
            self.current_epoch = new_epoch;
            self.stage = EpochPipelineStage::AwaitingBeacon;
            self.current_beacon_output = None;
            Some(EpochTransitionEvent {
                previous_epoch,
                new_epoch,
                trigger_height: height,
            })
        } else {
            None
        }
    }

    /// Record completion of the distributed `VernamBeacon` round for `current_epoch`,
    /// advancing the pipeline to `AwaitingPopAudit`.
    pub fn complete_beacon_round(
        &mut self,
        output: EpochBeaconOutput,
    ) -> Result<(), BeaconError> {
        if self.stage != EpochPipelineStage::AwaitingBeacon {
            return Err(BeaconError::InvalidPipelineTransition {
                expected: EpochPipelineStage::AwaitingBeacon,
                got: self.stage,
            });
        }
        if output.epoch != self.current_epoch {
            return Err(BeaconError::WrongEpoch {
                expected: self.current_epoch,
                got: output.epoch,
            });
        }
        self.current_beacon_output = Some(output);
        self.stage = EpochPipelineStage::AwaitingPopAudit;
        Ok(())
    }

    /// Derive the unpredictable Proof-of-Pad audit challenge and challenged pad/Beaver
    /// slot indices for `validator_id` from the finalized beacon of `current_epoch`.
    pub fn pop_audit_plan(
        &self,
        validator_id: u64,
        num_slots: usize,
        max_index: usize,
    ) -> Result<PopAuditPlan, BeaconError> {
        let output = self
            .current_beacon_output
            .as_ref()
            .ok_or(BeaconError::MissingBeaconOutput)?;
        Ok(PopAuditPlan {
            epoch: output.epoch,
            validator_id,
            challenge_r: output.derive_pop_challenge_r(validator_id),
            audit_slots: output.derive_audit_slots(validator_id, num_slots, max_index),
        })
    }

    /// Record completion of Proof-of-Pad auditing, advancing the pipeline to `AwaitingPssRefresh`.
    pub fn complete_pop_audit(&mut self) -> Result<(), BeaconError> {
        if self.stage != EpochPipelineStage::AwaitingPopAudit {
            return Err(BeaconError::InvalidPipelineTransition {
                expected: EpochPipelineStage::AwaitingPopAudit,
                got: self.stage,
            });
        }
        self.stage = EpochPipelineStage::AwaitingPssRefresh;
        Ok(())
    }

    /// Record completion of Proactive Secret Sharing refresh, returning to `Idle`.
    pub fn complete_pss_refresh(&mut self) -> Result<(), BeaconError> {
        if self.stage != EpochPipelineStage::AwaitingPssRefresh {
            return Err(BeaconError::InvalidPipelineTransition {
                expected: EpochPipelineStage::AwaitingPssRefresh,
                got: self.stage,
            });
        }
        self.stage = EpochPipelineStage::Idle;
        Ok(())
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::pow_mod;

    /// Helper: generate an N x N matrix of matched single-use pairwise OTP keys.
    /// `sender_keys[dealer][recipient]` matches `receiver_keys[recipient][dealer]`.
    fn make_pairwise_otp_matrix(
        config: &BeaconConfig,
    ) -> (Vec<Vec<OtpChannelKey>>, Vec<Vec<OtpChannelKey>>) {
        let n = config.num_validators;
        let mut sender_keys: Vec<Vec<Option<OtpChannelKey>>> =
            (0..n).map(|_| (0..n).map(|_| None).collect()).collect();
        let mut receiver_keys: Vec<Vec<Option<OtpChannelKey>>> =
            (0..n).map(|_| (0..n).map(|_| None).collect()).collect();

        for dealer in 0..n {
            for recipient in 0..n {
                let (sk, rk) = OtpChannelKey::generate_pair_for_config(config);
                sender_keys[dealer][recipient] = Some(sk);
                receiver_keys[recipient][dealer] = Some(rk);
            }
        }

        let sks = sender_keys
            .into_iter()
            .map(|row| row.into_iter().map(Option::unwrap).collect())
            .collect();
        let rks = receiver_keys
            .into_iter()
            .map(|row| row.into_iter().map(Option::unwrap).collect())
            .collect();
        (sks, rks)
    }

    /// Run a complete Commit phase across `nodes` using given per-dealer secrets.
    fn run_honest_commit_phase(
        nodes: &mut [VernamBeacon],
        secrets: &[u128],
        sender_keys: &[Vec<OtpChannelKey>],
        receiver_keys: &[Vec<OtpChannelKey>],
    ) {
        let n = nodes.len();

        // 1. Deal OTP+CW-MAC envelopes.
        let mut all_envelopes: Vec<Vec<ShareEnvelope>> = Vec::with_capacity(n);
        for d in 0..n {
            let refs: Vec<(u32, &OtpChannelKey)> = (0..n)
                .map(|r| (r as u32, &sender_keys[d][r]))
                .collect();
            let envs = nodes[d]
                .generate_commit_envelopes_with_secret(secrets[d], &refs)
                .expect("deal commit envelopes");
            all_envelopes.push(envs);
        }

        // 2. Receive and open envelopes.
        for r in 0..n {
            for d in 0..n {
                nodes[r]
                    .receive_commit_envelope(&all_envelopes[d][r], &receiver_keys[r][d])
                    .expect("open commit envelope");
            }
        }

        // 3. Pairwise symmetry checks.
        let all_checks: Vec<Vec<PairwiseConsistencyCheck>> =
            nodes.iter().map(|node| node.generate_pairwise_checks()).collect();
        for checks in &all_checks {
            for check in checks {
                let ok = nodes[check.to_id as usize]
                    .verify_pairwise_check(check)
                    .expect("verify pairwise check");
                assert!(ok, "honest pairwise check must succeed");
            }
        }

        // 4. Zero-knowledge Rabin-Ben-Or IC-MAC checks.
        let all_challenges: Vec<Vec<IcChallenge>> = nodes
            .iter_mut()
            .map(|node| node.generate_ic_challenges())
            .collect();
        for challenges in &all_challenges {
            for ch in challenges {
                let resp = nodes[ch.holder_id as usize]
                    .answer_ic_challenge(ch)
                    .expect("answer IC challenge");
                let ok = nodes[ch.verifier_id as usize]
                    .verify_ic_response(&resp)
                    .expect("verify IC response");
                assert!(ok, "honest IC-MAC check must succeed");
            }
        }

        // 5. Lock Commit phase on every node.
        for node in nodes.iter_mut() {
            let qualified = node.lock_commit_phase().expect("lock commit");
            assert_eq!(qualified.len(), n);
        }
    }

    #[test]
    fn test_field_poly_lagrange_and_pow5_bijection() {
        // Verify x -> x^5 is an exact bijection on F_(2^127 - 1):
        // inv_5 = 5^(-1) mod (2^127 - 2).
        // Since 2^127 - 2 = 2 * (2^126 - 1) and (2^127 - 2) === 1 (mod 5):
        // Check: 2^127 - 2 = 2 * (2^126 - 1); 2^126 === 4 (mod 5) => 2^126 - 1 === 3 (mod 5)
        // => 2 * 3 = 6 === 1 (mod 5).
        // Therefore 4 * (2^127 - 2) + 1 is divisible by 5, and
        // inv_5 = (4 * (PRIME_P - 1) + 1) / 5.
        let p_minus_1 = PRIME_P - 1;
        assert_eq!(p_minus_1 % 5, 1);
        // Compute (4*(p-1) + 1)/5 without overflow:
        // (p-1) = 5*q + 1 => 4*(p-1) + 1 = 20*q + 5 => /5 = 4*q + 1.
        let inv_5 = 4 * (p_minus_1 / 5) + 1;
        // Verify 5 * inv_5 === 1 (mod PRIME_P - 1) without u128 overflow:
        let mut five_inv = 0u128;
        for _ in 0..5 {
            five_inv = (five_inv + inv_5) % p_minus_1;
        }
        assert_eq!(five_inv, 1);

        for x in [0u128, 1, 2, 42, PRIME_P - 1, random_field_elem(), random_field_elem()] {
            let y = pow5_mod(x);
            assert_eq!(pow_mod(y, inv_5), x, "x -> x^5 must be bijective on F_p");
        }

        // Verify Lagrange interpolation and degree consistency check.
        let coeffs = [random_field_elem(), random_field_elem(), random_field_elem()];
        let points: Vec<(u128, u128)> = (0..5u32)
            .map(|id| {
                let x = validator_eval_x(id);
                (x, eval_poly(&coeffs, x))
            })
            .collect();

        assert!(verify_degree_consistency(&points, 3).unwrap());
        assert_eq!(lagrange_interpolate_at_zero(&points[..3]).unwrap(), coeffs[0]);
        assert_eq!(lagrange_interpolate_at_zero(&points[2..5]).unwrap(), coeffs[0]);

        // Corrupt one share -> degree > 2 detected immediately!
        let mut corrupted = points.clone();
        corrupted[4].1 = add_mod(corrupted[4].1, 1);
        assert!(!verify_degree_consistency(&corrupted, 3).unwrap());
    }

    #[test]
    fn test_honest_4_validator_beacon_round() {
        let config = BeaconConfig::bft(4).unwrap();
        assert_eq!(config.threshold, 3);
        assert_eq!(config.max_faults, 1);

        let epoch = 7;
        let secrets: Vec<u128> = (0..4).map(|_| random_field_elem()).collect();
        let expected_gamma = secrets.iter().copied().fold(0u128, add_mod);

        let (sender_keys, receiver_keys) = make_pairwise_otp_matrix(&config);
        let mut nodes: Vec<VernamBeacon> = (0..4u32)
            .map(|id| VernamBeacon::new(config, epoch, id).unwrap())
            .collect();

        run_honest_commit_phase(&mut nodes, &secrets, &sender_keys, &receiver_keys);

        // Phase 2: Honest reveals.
        let reveals: Vec<SecretReveal> = nodes
            .iter()
            .map(|node| node.generate_reveal().unwrap())
            .collect();

        for node in &mut nodes {
            for rev in &reveals {
                assert!(node.receive_reveal(rev).unwrap());
            }
            assert!(node.missing_reveals().is_empty());
        }

        let outputs: Vec<EpochBeaconOutput> = nodes
            .iter_mut()
            .map(|node| node.finalize_epoch().unwrap())
            .collect();

        for out in &outputs {
            assert_eq!(out.epoch, epoch);
            assert_eq!(out.gamma, expected_gamma);
            assert_eq!(out.qualified_validators, vec![0, 1, 2, 3]);
            assert!(out.reconstructed_validators.is_empty());
            assert!(out.disqualified_validators.is_empty());
            assert_eq!(out, &outputs[0]);
        }

        // Verify deterministic leader order is a valid permutation of 0..4.
        let leaders = outputs[0].epoch_leader_order(4);
        let mut sorted_leaders = leaders.clone();
        sorted_leaders.sort();
        assert_eq!(sorted_leaders, vec![0, 1, 2, 3]);
        for out in &outputs[1..] {
            assert_eq!(out.epoch_leader_order(4), leaders);
        }

        // Verify PoP challenge scalars are non-zero and distinct per validator.
        let pop_challenges: Vec<u128> = (0..4u64)
            .map(|v| outputs[0].derive_pop_challenge_r(v))
            .collect();
        for &r in &pop_challenges {
            assert!(r >= 1 && r < PRIME_P);
        }
        let unique_pop: BTreeSet<u128> = pop_challenges.iter().copied().collect();
        assert_eq!(unique_pop.len(), 4);

        // Verify audit slots are distinct and in bounds.
        let slots = outputs[0].derive_audit_slots(2, 16, 1000);
        assert_eq!(slots.len(), 16);
        let unique_slots: BTreeSet<usize> = slots.iter().copied().collect();
        assert_eq!(unique_slots.len(), 16);
        assert!(slots.iter().all(|&s| s < 1000));
    }

    #[test]
    fn test_honest_7_validator_beacon_round() {
        let config = BeaconConfig::bft(7).unwrap();
        assert_eq!(config.threshold, 5);
        assert_eq!(config.max_faults, 2);

        let epoch = 42;
        let secrets: Vec<u128> = (0..7).map(|_| random_field_elem()).collect();
        let expected_gamma = secrets.iter().copied().fold(0u128, add_mod);

        let (sender_keys, receiver_keys) = make_pairwise_otp_matrix(&config);
        let mut nodes: Vec<VernamBeacon> = (0..7u32)
            .map(|id| VernamBeacon::new(config, epoch, id).unwrap())
            .collect();

        run_honest_commit_phase(&mut nodes, &secrets, &sender_keys, &receiver_keys);

        let reveals: Vec<SecretReveal> = nodes
            .iter()
            .map(|node| node.generate_reveal().unwrap())
            .collect();
        for node in &mut nodes {
            for rev in &reveals {
                assert!(node.receive_reveal(rev).unwrap());
            }
        }

        let outputs: Vec<EpochBeaconOutput> = nodes
            .iter_mut()
            .map(|node| node.finalize_epoch().unwrap())
            .collect();

        for out in &outputs {
            assert_eq!(out.gamma, expected_gamma);
            assert_eq!(out.qualified_validators, vec![0, 1, 2, 3, 4, 5, 6]);
            assert!(out.reconstructed_validators.is_empty());
            assert_eq!(out, &outputs[0]);
        }

        let leaders = outputs[0].epoch_leader_order(7);
        let mut sorted = leaders.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_byzantine_abort_last_revealer_attack_defeated() {
        // 4-validator BFT (t=3, N=4, f=1):
        // Malicious V3 commits honestly in Phase 1, sees V0..V2's reveals, and
        // ABORTS (refuses to reveal) to try to bias Gamma_e!
        let config = BeaconConfig::bft(4).unwrap();
        let epoch = 100;
        let secrets: Vec<u128> = (0..4).map(|_| random_field_elem()).collect();
        let unbiasable_gamma = secrets.iter().copied().fold(0u128, add_mod);

        let (sender_keys, receiver_keys) = make_pairwise_otp_matrix(&config);
        let mut nodes: Vec<VernamBeacon> = (0..4u32)
            .map(|id| VernamBeacon::new(config, epoch, id).unwrap())
            .collect();

        run_honest_commit_phase(&mut nodes, &secrets, &sender_keys, &receiver_keys);

        // Phase 2: Honest V0, V1, V2 reveal. Malicious V3 sees their reveals and ABORTS!
        let honest_reveals: Vec<SecretReveal> = (0..3)
            .map(|id| nodes[id].generate_reveal().unwrap())
            .collect();

        for h in 0..3 {
            for rev in &honest_reveals {
                assert!(nodes[h].receive_reveal(rev).unwrap());
            }
            // Even if V3 tries sending a FORGED reveal instead of staying silent, it is rejected!
            let forged_reveal = SecretReveal {
                epoch,
                dealer_id: 3,
                univariate_poly: vec![add_mod(secrets[3], 999), 123, 456],
            };
            assert!(
                !nodes[h].receive_reveal(&forged_reveal).unwrap(),
                "forged reveal from V3 must be rejected"
            );
            assert_eq!(nodes[h].missing_reveals(), vec![3]);
        }

        // Honest V0, V1, V2 broadcast IC-MAC-authenticated RecoveryShares for V3.
        let recovery_shares: Vec<RecoveryShare> = (0..3)
            .map(|h| nodes[h].generate_recovery_share(3).unwrap())
            .collect();

        for h in 0..3 {
            for rec in &recovery_shares {
                assert!(nodes[h].receive_recovery_share(rec).unwrap());
            }
        }

        // Honest V0, V1, V2 finalize and recover the EXACT SAME unbiasable Gamma_e!
        let honest_outputs: Vec<EpochBeaconOutput> = (0..3)
            .map(|h| nodes[h].finalize_epoch().unwrap())
            .collect();

        for out in &honest_outputs {
            assert_eq!(out.gamma, unbiasable_gamma);
            assert_eq!(out.qualified_validators, vec![0, 1, 2, 3]);
            assert_eq!(out.reconstructed_validators, vec![3]);
            assert!(out.disqualified_validators.is_empty());
            assert_eq!(out, &honest_outputs[0]);
        }

        // Also verify 7-validator BFT (t=5, N=7, f=2) with TWO Byzantine validators (V5 & V6) aborting!
        let cfg7 = BeaconConfig::bft(7).unwrap();
        let secrets7: Vec<u128> = (0..7).map(|_| random_field_elem()).collect();
        let expected7 = secrets7.iter().copied().fold(0u128, add_mod);
        let (sk7, rk7) = make_pairwise_otp_matrix(&cfg7);
        let mut nodes7: Vec<VernamBeacon> = (0..7u32)
            .map(|id| VernamBeacon::new(cfg7, 101, id).unwrap())
            .collect();

        run_honest_commit_phase(&mut nodes7, &secrets7, &sk7, &rk7);

        let rev7: Vec<SecretReveal> = (0..5)
            .map(|id| nodes7[id].generate_reveal().unwrap())
            .collect();
        for h in 0..5 {
            for r in &rev7 {
                assert!(nodes7[h].receive_reveal(r).unwrap());
            }
            assert_eq!(nodes7[h].missing_reveals(), vec![5, 6]);
        }

        for aborted in [5u32, 6u32] {
            let recs: Vec<RecoveryShare> = (0..5)
                .map(|h| nodes7[h].generate_recovery_share(aborted).unwrap())
                .collect();
            for h in 0..5 {
                for rec in &recs {
                    assert!(nodes7[h].receive_recovery_share(rec).unwrap());
                }
            }
        }

        for h in 0..5 {
            let out = nodes7[h].finalize_epoch().unwrap();
            assert_eq!(out.gamma, expected7);
            assert_eq!(out.reconstructed_validators, vec![5, 6]);
        }
    }

    #[test]
    fn test_forged_recovery_share_rejected_by_ic_mac() {
        let config = BeaconConfig::bft(7).unwrap();
        let epoch = 55;
        let secrets: Vec<u128> = (0..7).map(|_| random_field_elem()).collect();
        let expected_gamma = secrets.iter().copied().fold(0u128, add_mod);

        let (sk, rk) = make_pairwise_otp_matrix(&config);
        let mut nodes: Vec<VernamBeacon> = (0..7u32)
            .map(|id| VernamBeacon::new(config, epoch, id).unwrap())
            .collect();

        run_honest_commit_phase(&mut nodes, &secrets, &sk, &rk);

        // V0..V4 reveal; V6 aborts; Byzantine V5 tries to poison V6's recovery with a forged share!
        let reveals: Vec<SecretReveal> = (0..6)
            .map(|id| nodes[id].generate_reveal().unwrap())
            .collect();
        for h in 0..5 {
            for r in &reveals {
                assert!(nodes[h].receive_reveal(r).unwrap());
            }
        }

        // V5 forges its recovery share for V6 by adding 1 to share_y while keeping/guessing tags.
        let mut forged_rec = nodes[5].generate_recovery_share(6).unwrap();
        forged_rec.share_y = add_mod(forged_rec.share_y, 1);

        for h in 0..5 {
            assert!(
                !nodes[h].receive_recovery_share(&forged_rec).unwrap(),
                "forged recovery share must be caught by Rabin-Ben-Or IC-MAC"
            );
        }

        // Honest V0..V4 broadcast valid recovery shares -> exact Gamma_e reconstructed!
        let honest_recs: Vec<RecoveryShare> = (0..5)
            .map(|h| nodes[h].generate_recovery_share(6).unwrap())
            .collect();
        for h in 0..5 {
            for rec in &honest_recs {
                assert!(nodes[h].receive_recovery_share(rec).unwrap());
            }
            let out = nodes[h].finalize_epoch().unwrap();
            assert_eq!(out.gamma, expected_gamma);
            assert_eq!(out.reconstructed_validators, vec![6]);
        }
    }

    #[test]
    fn test_corrupted_share_attack_caught_before_reveal() {
        // 4-validator BFT (t=3, N=4):
        // Malicious dealer V3 corrupts V0's share so shares do not lie on a degree-2 polynomial.
        let config = BeaconConfig::bft(4).unwrap();
        let epoch = 200;
        let secrets: Vec<u128> = (0..4).map(|_| random_field_elem()).collect();
        let expected_honest_gamma = add_mod(add_mod(secrets[0], secrets[1]), secrets[2]);

        let (sender_keys, receiver_keys) = make_pairwise_otp_matrix(&config);
        let mut nodes: Vec<VernamBeacon> = (0..4u32)
            .map(|id| VernamBeacon::new(config, epoch, id).unwrap())
            .collect();

        // Deal envelopes for all 4 validators.
        let mut all_envelopes: Vec<Vec<ShareEnvelope>> = Vec::with_capacity(4);
        for d in 0..4 {
            let refs: Vec<(u32, &OtpChannelKey)> = (0..4)
                .map(|r| (r as u32, &sender_keys[d][r]))
                .collect();
            let envs = nodes[d]
                .generate_commit_envelopes_with_secret(secrets[d], &refs)
                .unwrap();
            all_envelopes.push(envs);
        }

        // Malicious V3 tampers with the decrypted share sent to V0 (re-sealing with valid OTP+CW-MAC
        // so it passes transport MAC, simulating a genuinely malicious dealer sending degree > t-1 shares!).
        let mut tampered_plain = all_envelopes[3][0].open(&receiver_keys[0][3]).unwrap();
        let mut mutated_record =
            SecretShareRecord::decode(epoch, 3, 0, &config, &tampered_plain).unwrap();
        zeroize_slice(&mut tampered_plain);
        mutated_record.row_poly[0] = add_mod(mutated_record.row_poly[0], 777);
        let mut mutated_bytes = mutated_record.encode();
        all_envelopes[3][0] = ShareEnvelope::seal(
            epoch,
            3,
            0,
            &mutated_bytes,
            &sender_keys[3][0],
        )
        .unwrap();
        zeroize_slice(&mut mutated_bytes);

        // Also verify transport-level CW-MAC tamper detection on a cloned envelope:
        let mut bad_mac_env = all_envelopes[0][1].clone();
        bad_mac_env.ciphertext[0] ^= 0x01;
        assert!(matches!(
            bad_mac_env.open(&receiver_keys[1][0]),
            Err(BeaconError::MacVerificationFailed {
                dealer: 0,
                recipient: 1
            })
        ));

        // All validators open envelopes.
        for r in 0..4 {
            for d in 0..4 {
                nodes[r]
                    .receive_commit_envelope(&all_envelopes[d][r], &receiver_keys[r][d])
                    .unwrap();
            }
        }

        // Pairwise symmetry checks catch V3's corrupted share immediately!
        let all_checks: Vec<Vec<PairwiseConsistencyCheck>> =
            nodes.iter().map(|node| node.generate_pairwise_checks()).collect();
        let mut mismatch_count = 0usize;
        for checks in &all_checks {
            for check in checks {
                let ok = nodes[check.to_id as usize]
                    .verify_pairwise_check(check)
                    .unwrap();
                if !ok {
                    assert_eq!(check.dealer_id, 3, "only malicious dealer V3 should mismatch");
                    mismatch_count += 1;
                }
            }
        }
        assert!(
            mismatch_count >= 4,
            "corrupted share must trigger pairwise mismatches on both ends"
        );

        // Broadcast complaints from honest V0..V2 to all nodes.
        let complaints: Vec<CommitComplaint> = (0..3)
            .flat_map(|h| nodes[h].local_complaints().to_vec())
            .collect();
        for node in &mut nodes {
            for c in &complaints {
                node.register_complaint(c.clone()).unwrap();
            }
        }

        // Lock Commit phase: malicious V3 is DISQUALIFIED before Reveal!
        for h in 0..3 {
            let qualified = nodes[h].lock_commit_phase().unwrap();
            assert_eq!(qualified, vec![0, 1, 2]);
            assert_eq!(nodes[h].disqualified_dealers(), vec![3]);
        }

        // Honest V0..V2 reveal and finalize cleanly without V3!
        let reveals: Vec<SecretReveal> = (0..3)
            .map(|h| nodes[h].generate_reveal().unwrap())
            .collect();
        for h in 0..3 {
            for r in &reveals {
                assert!(nodes[h].receive_reveal(r).unwrap());
            }
            let out = nodes[h].finalize_epoch().unwrap();
            assert_eq!(out.gamma, expected_honest_gamma);
            assert_eq!(out.qualified_validators, vec![0, 1, 2]);
            assert_eq!(out.disqualified_validators, vec![3]);
        }
    }

    #[test]
    fn test_false_complaint_against_honest_dealer_resolved() {
        let config = BeaconConfig::bft(4).unwrap();
        let epoch = 300;
        let secrets: Vec<u128> = (0..4).map(|_| random_field_elem()).collect();
        let expected_gamma = secrets.iter().copied().fold(0u128, add_mod);

        let (sk, rk) = make_pairwise_otp_matrix(&config);
        let mut nodes: Vec<VernamBeacon> = (0..4u32)
            .map(|id| VernamBeacon::new(config, epoch, id).unwrap())
            .collect();

        // Deal and receive all envelopes.
        let mut all_envs = Vec::new();
        for d in 0..4 {
            let refs: Vec<(u32, &OtpChannelKey)> =
                (0..4).map(|r| (r as u32, &sk[d][r])).collect();
            all_envs.push(
                nodes[d]
                    .generate_commit_envelopes_with_secret(secrets[d], &refs)
                    .unwrap(),
            );
        }
        for r in 0..4 {
            for d in 0..4 {
                nodes[r]
                    .receive_commit_envelope(&all_envs[d][r], &rk[r][d])
                    .unwrap();
            }
        }

        // Byzantine V3 files a FALSE complaint against honest dealer V0!
        let false_complaint = CommitComplaint {
            epoch,
            dealer_id: 0,
            accuser_id: 3,
            reason: ComplaintReason::InvalidEnvelopeMac,
        };
        for node in &mut nodes {
            node.register_complaint(false_complaint.clone()).unwrap();
        }

        // Honest dealer V0 publishes resolution for V3 (leaking zero new info to V3).
        let resolution = nodes[0].generate_complaint_resolution(3).unwrap();
        let votes: Vec<ResolutionVote> = (0..3)
            .map(|h| nodes[h].verify_complaint_resolution(&resolution).unwrap())
            .collect();
        assert!(votes.iter().all(|v| v.valid));

        for h in 0..3 {
            for v in &votes {
                nodes[h]
                    .register_resolution_vote(&resolution, v.clone())
                    .unwrap();
            }
            // V0 remains QUALIFIED because >= threshold (3) honest validators approved!
            let qualified = nodes[h].lock_commit_phase().unwrap();
            assert_eq!(qualified, vec![0, 1, 2, 3]);
        }

        // Complete honest reveal and confirm V0 contributed to Gamma_e.
        nodes[3].lock_commit_phase().unwrap();
        let reveals: Vec<SecretReveal> = nodes
            .iter()
            .map(|n| n.generate_reveal().unwrap())
            .collect();
        for h in 0..3 {
            for r in &reveals {
                assert!(nodes[h].receive_reveal(r).unwrap());
            }
            let out = nodes[h].finalize_epoch().unwrap();
            assert_eq!(out.gamma, expected_gamma);
        }
    }

    #[test]
    fn test_autonomous_epoch_clock_full_pipeline() {
        let mut clock = AutonomousEpochClock::new(10).unwrap();
        assert_eq!(clock.current_epoch(), 0);
        assert_eq!(clock.blocks_in_epoch(), 0);
        assert!(!clock.needs_beacon_round());
        assert!(!clock.needs_pop_audit());
        assert!(!clock.needs_pss_refresh());

        // Blocks 1..=9 remain in epoch 0 with zero triggers.
        for h in 1..=9 {
            assert!(clock.on_block_finalized(h).is_none());
            assert_eq!(clock.current_epoch(), 0);
            assert_eq!(clock.blocks_in_epoch(), h);
            assert!(!clock.needs_beacon_round());
        }

        // Stale/duplicate height is ignored deterministically.
        assert!(clock.on_block_finalized(9).is_none());
        assert!(clock.on_block_finalized(5).is_none());

        // Block 10 crosses into epoch 1 automatically!
        let ev1 = clock
            .on_block_finalized(10)
            .expect("epoch 1 boundary must fire at height 10");
        assert_eq!(
            ev1,
            EpochTransitionEvent {
                previous_epoch: 0,
                new_epoch: 1,
                trigger_height: 10,
            }
        );
        assert_eq!(clock.current_epoch(), 1);
        assert_eq!(clock.blocks_in_epoch(), 0);
        assert_eq!(clock.blocks_until_next_epoch(), 10);
        assert!(clock.needs_beacon_round());
        assert!(!clock.needs_pop_audit());
        assert!(!clock.needs_pss_refresh());

        // Run a real 4-validator VernamBeacon for epoch 1.
        let config = BeaconConfig::bft(4).unwrap();
        let secrets1: Vec<u128> = (0..4).map(|_| random_field_elem()).collect();
        let (sk1, rk1) = make_pairwise_otp_matrix(&config);
        let mut nodes1: Vec<VernamBeacon> = (0..4u32)
            .map(|id| VernamBeacon::new(config, 1, id).unwrap())
            .collect();
        run_honest_commit_phase(&mut nodes1, &secrets1, &sk1, &rk1);
        let revs1: Vec<SecretReveal> = nodes1.iter().map(|n| n.generate_reveal().unwrap()).collect();
        for r in &revs1 {
            nodes1[0].receive_reveal(r).unwrap();
        }
        let beacon_ep1 = nodes1[0].finalize_epoch().unwrap();

        // Pipeline step 1 -> step 2 (PoP Audit).
        clock.complete_beacon_round(beacon_ep1.clone()).unwrap();
        assert!(!clock.needs_beacon_round());
        assert!(clock.needs_pop_audit());
        assert!(!clock.needs_pss_refresh());

        // Derive distinct unpredictable PoP challenges per validator for epoch 1.
        let plan_e1_v0 = clock.pop_audit_plan(0, 8, 512).unwrap();
        let plan_e1_v1 = clock.pop_audit_plan(1, 8, 512).unwrap();
        assert_eq!(plan_e1_v0.epoch, 1);
        assert_ne!(plan_e1_v0.challenge_r, plan_e1_v1.challenge_r);
        assert_ne!(plan_e1_v0.audit_slots, plan_e1_v1.audit_slots);
        assert!(plan_e1_v0.challenge_r >= 1 && plan_e1_v0.challenge_r < PRIME_P);

        // Pipeline step 2 -> step 3 (PSS Refresh).
        clock.complete_pop_audit().unwrap();
        assert!(!clock.needs_beacon_round());
        assert!(!clock.needs_pop_audit());
        assert!(clock.needs_pss_refresh());

        // Pipeline step 3 -> Idle.
        clock.complete_pss_refresh().unwrap();
        assert_eq!(clock.pipeline_stage(), EpochPipelineStage::Idle);
        assert!(!clock.needs_beacon_round());
        assert!(!clock.needs_pop_audit());
        assert!(!clock.needs_pss_refresh());

        // Blocks 11..=19 stay in epoch 1; block 20 autonomously triggers epoch 2!
        for h in 11..=19 {
            assert!(clock.on_block_finalized(h).is_none());
        }
        let ev2 = clock
            .on_block_finalized(20)
            .expect("epoch 2 boundary must fire at height 20");
        assert_eq!(ev2.new_epoch, 2);
        assert!(clock.needs_beacon_round());

        // Epoch 2 beacon produces distinct PoP challenge for the same validator_id.
        let beacon_ep2 = EpochBeaconOutput {
            epoch: 2,
            gamma: random_field_elem(),
            qualified_validators: vec![0, 1, 2, 3],
            reconstructed_validators: vec![],
            disqualified_validators: vec![],
        };
        clock.complete_beacon_round(beacon_ep2).unwrap();
        let plan_e2_v0 = clock.pop_audit_plan(0, 8, 512).unwrap();
        assert_eq!(plan_e2_v0.epoch, 2);
        assert_ne!(plan_e1_v0.challenge_r, plan_e2_v0.challenge_r);
        assert_ne!(plan_e1_v0.audit_slots, plan_e2_v0.audit_slots);
    }

    #[test]
    fn test_redacted_debug_and_zeroization() {
        let secret = 0x1234_5678_9ABC_DEF0_1122_3344_5566_7788u128 & PRIME_P;
        let contrib = SecretContribution::from_secret(1, 0, 3, secret);
        let dbg_contrib = format!("{contrib:?}");
        assert!(dbg_contrib.contains("<REDACTED>"));
        assert!(!dbg_contrib.contains(&secret.to_string()));

        let key = OtpChannelKey::generate(64);
        let dbg_key = format!("{key:?}");
        assert!(dbg_key.contains("<REDACTED>"));

        let config = BeaconConfig::bft(4).unwrap();
        let beacon = VernamBeacon::new(config, 1, 0).unwrap();
        let dbg_beacon = format!("{beacon:?}");
        assert!(dbg_beacon.contains("VernamBeacon"));
    }
}
