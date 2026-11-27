//! Zero-Admin Dynamic Committee Resharing (`(t, N) -> (t', N')`) and Epoch State Pruning
//! for Vernam (VRNM) v1.0.
//!
//! Pure information-theoretic cryptography over the Mersenne prime field `F_(2^127 - 1)`:
//! - Zero external crates, zero computational crypto (no SHA-256, RSA, ECDSA, AES, or SipHash).
//! - Zero-reconstruction Shamir share redistribution across arbitrary `(t, N) -> (t', N')`
//!   committee scaling (`4 -> 7 -> 10`) or seat rotation (`4 -> 4`), encrypted under pairwise
//!   one-time pads (OTP) + one-time Carter-Wegman polynomial universal MACs.
//! - Zero-admin permissionless validator admission via Proof-of-Pad trials + quorum endorsements,
//!   automatic slashing/liveness ejection, and BFT threshold adaptation (`f = (N - 1) / 3`, `t = 2f + 1`).
//! - Compact Carter-Wegman threshold-authenticated epoch checkpoints with automatic historical
//!   block-body pruning to enforce a `< 2 GB` steady-state node footprint.
//! - Volatile memory zeroization on `Drop` and redacted `Debug` for all secret keys, OTP masks,
//!   polynomials, shares, and sub-shares.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, inv_mod, mul_mod, random_field_elem, random_nonzero_field_elem,
    reduce, sub_mod, zeroize_slice, zeroize_u128,
};

/// Unique non-zero validator identifier and Shamir x-coordinate in `F_(2^127 - 1)`.
pub type ValidatorId = u64;

/// Unique user account identifier in the secret-shared ledger.
pub type AccountId = u64;

/// Minimum BFT committee size (`3f + 1` with `f >= 1`).
pub const MIN_BFT_COMMITTEE_SIZE: usize = 4;

/// Maximum allowable Quantum Bit Error Rate (Shor-Preskill BB84 threshold).
pub const MAX_PROOF_OF_PAD_QBER: f64 = 0.11;

/// Maximum allowable absolute entropy z-score for hardware/quantum randomness checks.
pub const MAX_ENTROPY_Z_SCORE: f64 = 3.0;

/// Minimum OTP pad reserve (1 MiB) required for a candidate validator trial.
pub const MIN_CANDIDATE_PAD_BYTES: u64 = 1_048_576;

/// Target steady-state disk footprint ceiling (2 GiB).
pub const MAX_STEADY_STATE_BYTES: usize = 2 * 1024 * 1024 * 1024;

// Domain separators in F_(2^127 - 1) for Carter-Wegman universal polynomial hashing.
const DOMAIN_SUBSHARE_SINGLE: u128 = 0x5652_4E4D_0001;
const DOMAIN_SUBSHARE_BATCH: u128 = 0x5652_4E4D_0002;
const DOMAIN_TRIAL_CHALLENGE: u128 = 0x5652_4E4D_0003;
const DOMAIN_TRIAL_DIGEST: u128 = 0x5652_4E4D_0004;
const DOMAIN_TRIAL_ENDORSEMENT: u128 = 0x5652_4E4D_0005;
const DOMAIN_EPOCH_BEACON: u128 = 0x5652_4E4D_0006;
const DOMAIN_BLOCK_STATE_ROOT: u128 = 0x5652_4E4D_0007;
const DOMAIN_CHECKPOINT_STATE: u128 = 0x5652_4E4D_0008;
const DOMAIN_CHECKPOINT_MAC: u128 = 0x5652_4E4D_0009;
const DOMAIN_SECRET_LEDGER_ROOT: u128 = 0x5652_4E4D_000A;

// ============================================================================
// Errors
// ============================================================================

/// Error type for dynamic committee resharing, governance, and checkpoint pruning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicQuorumError {
    /// Threshold must satisfy `1 <= threshold <= committee_size`.
    InvalidThreshold {
        threshold: usize,
        committee_size: usize,
    },
    /// Committee size violates the BFT minimum (`N >= 4`).
    InvalidCommitteeSize {
        size: usize,
        min_required: usize,
    },
    /// Validator x-coordinate must be non-zero in `F_p`.
    InvalidValidatorCoordinate(ValidatorId),
    /// Duplicate validator x-coordinate detected.
    DuplicateValidatorCoordinate(ValidatorId),
    /// Fewer shares provided than required by threshold.
    InsufficientShares {
        provided: usize,
        required: usize,
    },
    /// Carter-Wegman MAC verification failed (tampered or forged envelope/message).
    MacVerificationFailed {
        context: &'static str,
    },
    /// Batch OTP pad count does not match account count.
    BatchLengthMismatch {
        expected: usize,
        actual: usize,
    },
    /// Committee shares failed degree-(t'-1) consistency verification.
    InconsistentShares {
        failing_checks: usize,
        suspected_validators: Vec<ValidatorId>,
    },
    /// Sub-share audit caught malicious old dealer(s) sending inconsistent sub-shares.
    CorruptedSubShares {
        malicious_dealers: Vec<ValidatorId>,
    },
    /// Candidate Proof-of-Pad trial failed validation rules.
    InvalidCandidateTrial(&'static str),
    /// Candidate already has an active/pending/admitted entry.
    DuplicateCandidate(ValidatorId),
    /// Referenced validator is not in the active committee.
    ValidatorNotActive(ValidatorId),
    /// Referenced validator has already been slashed/ejected.
    ValidatorAlreadySlashed(ValidatorId),
    /// Quorum endorsement threshold was not met.
    InsufficientEndorsements {
        provided: usize,
        required: usize,
    },
    /// Not enough surviving honest old validators to perform zero-reconstruction resharing.
    InsufficientQuorumForReshare {
        remaining: usize,
        required: usize,
    },
    /// Account missing an expected share from an old quorum validator.
    MissingQuorumShare {
        account_id: AccountId,
        validator_id: ValidatorId,
    },
    /// Invalid block height or configuration parameter.
    InvalidConfig(&'static str),
    /// Transfer attempted to spend more than available balance.
    InsufficientBalance {
        account: AccountId,
        available: u128,
        requested: u128,
    },
    /// Epoch checkpoint chain or state root verification failed.
    CheckpointVerificationFailed(&'static str),
    /// Per-epoch committee churn or takeover limit exceeded (`attempted > max_allowed`).
    ChurnLimitExceeded {
        attempted: usize,
        max_allowed: usize,
    },
    /// Non-canonical field element (`>= PRIME_P`) injected into a share, secret, or envelope.
    NonCanonicalFieldElement(u128),
    /// Committee 4D diversity policy violated (OS, CPU ISA, compiler lineage, ASN, or geo cell).
    DiversityPolicyViolation {
        dimension: &'static str,
        value: u32,
        count: usize,
        max_allowed: usize,
    },
}

impl fmt::Display for DynamicQuorumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThreshold {
                threshold,
                committee_size,
            } => write!(
                f,
                "invalid threshold {threshold} for committee size {committee_size}"
            ),
            Self::InvalidCommitteeSize { size, min_required } => {
                write!(f, "invalid committee size {size} (minimum {min_required})")
            }
            Self::InvalidValidatorCoordinate(id) => {
                write!(f, "invalid validator x-coordinate {id} (must be >= 1)")
            }
            Self::DuplicateValidatorCoordinate(id) => {
                write!(f, "duplicate validator x-coordinate {id}")
            }
            Self::InsufficientShares { provided, required } => {
                write!(f, "insufficient shares: provided {provided}, required {required}")
            }
            Self::MacVerificationFailed { context } => {
                write!(f, "Carter-Wegman MAC verification failed in {context}")
            }
            Self::BatchLengthMismatch { expected, actual } => {
                write!(f, "batch length mismatch: expected {expected}, got {actual}")
            }
            Self::InconsistentShares {
                failing_checks,
                suspected_validators,
            } => write!(
                f,
                "committee shares failed degree consistency ({failing_checks} failing checks, suspected: {suspected_validators:?})"
            ),
            Self::CorruptedSubShares { malicious_dealers } => {
                write!(f, "corrupted sub-shares detected from dealers {malicious_dealers:?}")
            }
            Self::InvalidCandidateTrial(reason) => {
                write!(f, "invalid Proof-of-Pad candidate trial: {reason}")
            }
            Self::DuplicateCandidate(id) => write!(f, "duplicate candidate validator {id}"),
            Self::ValidatorNotActive(id) => write!(f, "validator {id} is not active"),
            Self::ValidatorAlreadySlashed(id) => write!(f, "validator {id} is already slashed"),
            Self::InsufficientEndorsements { provided, required } => write!(
                f,
                "insufficient quorum endorsements: provided {provided}, required {required}"
            ),
            Self::InsufficientQuorumForReshare {
                remaining,
                required,
            } => write!(
                f,
                "insufficient remaining old validators for reshare: {remaining} < {required}"
            ),
            Self::MissingQuorumShare {
                account_id,
                validator_id,
            } => write!(
                f,
                "missing share for account {account_id} on validator {validator_id}"
            ),
            Self::InvalidConfig(msg) => write!(f, "invalid configuration: {msg}"),
            Self::InsufficientBalance {
                account,
                available,
                requested,
            } => write!(
                f,
                "insufficient balance on account {account}: available {available}, requested {requested}"
            ),
            Self::CheckpointVerificationFailed(msg) => {
                write!(f, "checkpoint verification failed: {msg}")
            }
            Self::ChurnLimitExceeded {
                attempted,
                max_allowed,
            } => write!(
                f,
                "per-epoch committee churn limit exceeded: attempted {attempted}, max allowed {max_allowed}"
            ),
            Self::NonCanonicalFieldElement(val) => {
                write!(f, "non-canonical field element {val} (>= PRIME_P)")
            }
            Self::DiversityPolicyViolation {
                dimension,
                value,
                count,
                max_allowed,
            } => write!(
                f,
                "4D diversity policy violated on {dimension}={value}: count {count} exceeds max allowed {max_allowed}"
            ),
        }
    }
}

impl Error for DynamicQuorumError {}

// ============================================================================
// Pure Information-Theoretic Primitives: Carter-Wegman Universal MAC & OTP
// ============================================================================

/// Evaluate a domain-separated universal polynomial hash over `F_(2^127 - 1)`.
///
/// Computes `r * ((((domain * r + len) * r + m_0) * r + ...) * r + m_{L-1}) mod p`.
/// Distinct `(domain, elems)` inputs collide with probability at most `(L + 2) / (2^127 - 1)`.
#[inline]
pub fn poly_universal_hash(r: u128, domain: u128, elems: &[u128]) -> u128 {
    let r = reduce(r);
    let mut acc = reduce(domain);
    acc = add_mod(mul_mod(acc, r), reduce(elems.len() as u128));
    for &e in elems {
        acc = add_mod(mul_mod(acc, r), reduce(e));
    }
    mul_mod(acc, r)
}

/// Evaluate a domain-separated universal polynomial hash over arbitrary byte slices.
///
/// Packs bytes into lossless 15-byte little-endian limbs (`< 2^120 < PRIME_P`) and binds the
/// exact byte length so no padding or length-extension collisions are possible.
pub fn poly_universal_hash_bytes(r: u128, domain: u128, bytes: &[u8]) -> u128 {
    let r = reduce(r);
    let mut acc = reduce(domain);
    acc = add_mod(mul_mod(acc, r), reduce(bytes.len() as u128));
    for chunk in bytes.chunks(15) {
        let mut limb_bytes = [0u8; 16];
        limb_bytes[..chunk.len()].copy_from_slice(chunk);
        let limb = u128::from_le_bytes(limb_bytes);
        acc = add_mod(mul_mod(acc, r), limb);
        zeroize_slice(&mut limb_bytes);
    }
    mul_mod(acc, r)
}

/// One-time Carter-Wegman MAC key `(r, s)` in `F_(2^127 - 1)^2`.
///
/// Non-`Copy` and non-`Clone` by design to enforce single-use OTP discipline.
/// Automatically zeroizes both secret elements with volatile writes on `Drop`.
pub struct CwMacKey {
    r: u128,
    s: u128,
}

impl CwMacKey {
    /// Generate a matching one-time `(sender_key, receiver_key)` pair from OS entropy.
    pub fn generate_pair() -> (Self, Self) {
        let r = random_nonzero_field_elem();
        let s = random_field_elem();
        (Self { r, s }, Self { r, s })
    }

    /// Authenticate a slice of field elements, consuming this one-time MAC key.
    pub fn mac_elems(self, domain: u128, elems: &[u128]) -> u128 {
        let h = poly_universal_hash(self.r, domain, elems);
        add_mod(h, self.s)
        // `self` drops here and volatile-zeroizes `r` and `s`.
    }

    /// Verify a Carter-Wegman MAC tag in constant time, consuming this one-time MAC key.
    pub fn verify_elems(
        self,
        domain: u128,
        elems: &[u128],
        tag: u128,
        context: &'static str,
    ) -> Result<(), DynamicQuorumError> {
        if tag >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(tag));
        }
        let expected = add_mod(poly_universal_hash(self.r, domain, elems), self.s);
        let ok = ct_eq_16(&expected.to_le_bytes(), &tag.to_le_bytes());
        if ok {
            Ok(())
        } else {
            Err(DynamicQuorumError::MacVerificationFailed { context })
        }
    }

    /// Authenticate arbitrary bytes, consuming this one-time MAC key.
    pub fn mac_bytes(self, domain: u128, bytes: &[u8]) -> u128 {
        let h = poly_universal_hash_bytes(self.r, domain, bytes);
        add_mod(h, self.s)
    }

    /// Verify a Carter-Wegman MAC tag over bytes in constant time, consuming this one-time key.
    pub fn verify_bytes(
        self,
        domain: u128,
        bytes: &[u8],
        tag: u128,
        context: &'static str,
    ) -> Result<(), DynamicQuorumError> {
        if tag >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(tag));
        }
        let expected = add_mod(poly_universal_hash_bytes(self.r, domain, bytes), self.s);
        let ok = ct_eq_16(&expected.to_le_bytes(), &tag.to_le_bytes());
        if ok {
            Ok(())
        } else {
            Err(DynamicQuorumError::MacVerificationFailed { context })
        }
    }

    /// Non-consuming verification helper reserved for internal checkpoint audit stores.
    fn verify_elems_ref(
        &self,
        domain: u128,
        elems: &[u128],
        tag: u128,
        context: &'static str,
    ) -> Result<(), DynamicQuorumError> {
        if tag >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(tag));
        }
        let expected = add_mod(poly_universal_hash(self.r, domain, elems), self.s);
        let ok = ct_eq_16(&expected.to_le_bytes(), &tag.to_le_bytes());
        if ok {
            Ok(())
        } else {
            Err(DynamicQuorumError::MacVerificationFailed { context })
        }
    }
}

impl Drop for CwMacKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

impl fmt::Debug for CwMacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CwMacKey")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

/// Pairwise one-time OTP mask + one-time Carter-Wegman MAC key for transmitting a single sub-share.
pub struct PairwiseOtpKey {
    pad: u128,
    mac_key: CwMacKey,
}

impl PairwiseOtpKey {
    /// Generate a matching `(sender, receiver)` one-time channel key pair from OS entropy.
    pub fn generate_pair() -> (Self, Self) {
        let pad = random_field_elem();
        let (mac_s, mac_r) = CwMacKey::generate_pair();
        (
            Self { pad, mac_key: mac_s },
            Self { pad, mac_key: mac_r },
        )
    }
}

impl Drop for PairwiseOtpKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.pad);
        // `self.mac_key` zeroizes itself on drop.
    }
}

impl fmt::Debug for PairwiseOtpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairwiseOtpKey")
            .field("pad", &"[REDACTED]")
            .field("mac_key", &self.mac_key)
            .finish()
    }
}

/// Pairwise one-time batch OTP pad vector + one-time Carter-Wegman MAC key for multi-account resharing.
pub struct BatchOtpKey {
    pads: Vec<u128>,
    mac_key: CwMacKey,
}

impl BatchOtpKey {
    /// Generate a matching `(sender, receiver)` one-time batch channel key pair for `count` accounts.
    pub fn generate_pair(count: usize) -> (Self, Self) {
        let mut pads_s = Vec::with_capacity(count);
        let mut pads_r = Vec::with_capacity(count);
        for _ in 0..count {
            let p = random_field_elem();
            pads_s.push(p);
            pads_r.push(p);
        }
        let (mac_s, mac_r) = CwMacKey::generate_pair();
        (
            Self {
                pads: pads_s,
                mac_key: mac_s,
            },
            Self {
                pads: pads_r,
                mac_key: mac_r,
            },
        )
    }

    /// Number of one-time field pads in this batch key.
    pub fn len(&self) -> usize {
        self.pads.len()
    }

    /// Returns true if the batch key contains zero pads.
    pub fn is_empty(&self) -> bool {
        self.pads.is_empty()
    }
}

impl Drop for BatchOtpKey {
    fn drop(&mut self) {
        for p in &mut self.pads {
            zeroize_u128(p);
        }
    }
}

impl fmt::Debug for BatchOtpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BatchOtpKey")
            .field("pad_count", &self.pads.len())
            .field("pads", &"[REDACTED]")
            .field("mac_key", &self.mac_key)
            .finish()
    }
}

/// Public wire envelope carrying a single OTP-encrypted, Carter-Wegman authenticated sub-share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpSubShareEnvelope {
    pub epoch: u64,
    pub account_id: AccountId,
    pub from_validator: ValidatorId,
    pub to_validator: ValidatorId,
    pub ciphertext: u128,
    pub cw_tag: u128,
}

/// Public wire envelope carrying a batch of OTP-encrypted, Carter-Wegman authenticated sub-shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpBatchSubShareEnvelope {
    pub epoch: u64,
    pub from_validator: ValidatorId,
    pub to_validator: ValidatorId,
    pub account_ids: Vec<AccountId>,
    pub ciphertexts: Vec<u128>,
    pub cw_tag: u128,
}

/// Secret sub-share plaintext that volatile-zeroizes on `Drop` and redacts `Debug`.
pub struct SubSharePlaintext {
    pub from_validator: ValidatorId,
    pub to_validator: ValidatorId,
    pub account_id: AccountId,
    value: u128,
}

impl SubSharePlaintext {
    /// Create a new wrapped sub-share plaintext.
    pub fn new(
        from_validator: ValidatorId,
        to_validator: ValidatorId,
        account_id: AccountId,
        value: u128,
    ) -> Self {
        Self {
            from_validator,
            to_validator,
            account_id,
            value: reduce(value),
        }
    }

    /// Read the field element value of this sub-share.
    #[inline]
    pub fn value(&self) -> u128 {
        self.value
    }
}

impl Drop for SubSharePlaintext {
    fn drop(&mut self) {
        zeroize_u128(&mut self.value);
    }
}

impl fmt::Debug for SubSharePlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubSharePlaintext")
            .field("from_validator", &self.from_validator)
            .field("to_validator", &self.to_validator)
            .field("account_id", &self.account_id)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Encrypt and authenticate a single sub-share using Encrypt-then-MAC (OTP + Carter-Wegman MAC).
///
/// Consumes and zeroizes `key`.
pub fn encrypt_subshare(
    epoch: u64,
    account_id: AccountId,
    from_validator: ValidatorId,
    to_validator: ValidatorId,
    sub_share: u128,
    key: PairwiseOtpKey,
) -> OtpSubShareEnvelope {
    let ciphertext = add_mod(reduce(sub_share), key.pad);
    let mac_input = [
        epoch as u128,
        account_id as u128,
        from_validator as u128,
        to_validator as u128,
        ciphertext,
    ];
    let cw_tag = add_mod(
        poly_universal_hash(key.mac_key.r, DOMAIN_SUBSHARE_SINGLE, &mac_input),
        key.mac_key.s,
    );
    // `key` drops here, volatile-zeroizing `pad`, `r`, and `s`.
    OtpSubShareEnvelope {
        epoch,
        account_id,
        from_validator,
        to_validator,
        ciphertext,
        cw_tag,
    }
}

/// Authenticate and decrypt a single sub-share envelope, consuming and zeroizing `key`.
pub fn decrypt_subshare(
    envelope: &OtpSubShareEnvelope,
    key: PairwiseOtpKey,
) -> Result<SubSharePlaintext, DynamicQuorumError> {
    if envelope.ciphertext >= PRIME_P {
        return Err(DynamicQuorumError::NonCanonicalFieldElement(
            envelope.ciphertext,
        ));
    }
    let mac_input = [
        envelope.epoch as u128,
        envelope.account_id as u128,
        envelope.from_validator as u128,
        envelope.to_validator as u128,
        envelope.ciphertext,
    ];
    key.mac_key.verify_elems_ref(
        DOMAIN_SUBSHARE_SINGLE,
        &mac_input,
        envelope.cw_tag,
        "subshare_envelope",
    )?;
    let plaintext = sub_mod(envelope.ciphertext, key.pad);
    Ok(SubSharePlaintext::new(
        envelope.from_validator,
        envelope.to_validator,
        envelope.account_id,
        plaintext,
    ))
}

/// Encrypt and authenticate a batch of sub-shares (one independent OTP pad per account).
pub fn encrypt_subshare_batch(
    epoch: u64,
    from_validator: ValidatorId,
    to_validator: ValidatorId,
    account_ids: Vec<AccountId>,
    sub_shares: &[u128],
    key: BatchOtpKey,
) -> Result<OtpBatchSubShareEnvelope, DynamicQuorumError> {
    if account_ids.len() != sub_shares.len() {
        return Err(DynamicQuorumError::BatchLengthMismatch {
            expected: account_ids.len(),
            actual: sub_shares.len(),
        });
    }
    if key.pads.len() != sub_shares.len() {
        return Err(DynamicQuorumError::BatchLengthMismatch {
            expected: sub_shares.len(),
            actual: key.pads.len(),
        });
    }

    let mac_cap = sub_shares
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(3))
        .ok_or(DynamicQuorumError::InvalidConfig(
            "sub-share batch length overflow",
        ))?;

    let mut ciphertexts = Vec::with_capacity(sub_shares.len());
    let mut mac_elems = Vec::with_capacity(mac_cap);
    mac_elems.push(epoch as u128);
    mac_elems.push(from_validator as u128);
    mac_elems.push(to_validator as u128);

    for i in 0..sub_shares.len() {
        if sub_shares[i] >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(sub_shares[i]));
        }
        let ct = add_mod(sub_shares[i], key.pads[i]);
        ciphertexts.push(ct);
        mac_elems.push(account_ids[i] as u128);
        mac_elems.push(ct);
    }

    let cw_tag = add_mod(
        poly_universal_hash(key.mac_key.r, DOMAIN_SUBSHARE_BATCH, &mac_elems),
        key.mac_key.s,
    );
    Ok(OtpBatchSubShareEnvelope {
        epoch,
        from_validator,
        to_validator,
        account_ids,
        ciphertexts,
        cw_tag,
    })
}

/// Authenticate and decrypt a batch sub-share envelope, consuming and zeroizing `key`.
pub fn decrypt_subshare_batch(
    envelope: &OtpBatchSubShareEnvelope,
    key: BatchOtpKey,
) -> Result<Vec<SubSharePlaintext>, DynamicQuorumError> {
    if envelope.account_ids.len() != envelope.ciphertexts.len() {
        return Err(DynamicQuorumError::BatchLengthMismatch {
            expected: envelope.account_ids.len(),
            actual: envelope.ciphertexts.len(),
        });
    }
    if key.pads.len() != envelope.ciphertexts.len() {
        return Err(DynamicQuorumError::BatchLengthMismatch {
            expected: envelope.ciphertexts.len(),
            actual: key.pads.len(),
        });
    }

    let mac_cap = envelope
        .ciphertexts
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(3))
        .ok_or(DynamicQuorumError::InvalidConfig(
            "batch envelope length overflow",
        ))?;

    let mut mac_elems = Vec::with_capacity(mac_cap);
    mac_elems.push(envelope.epoch as u128);
    mac_elems.push(envelope.from_validator as u128);
    mac_elems.push(envelope.to_validator as u128);
    for i in 0..envelope.ciphertexts.len() {
        if envelope.ciphertexts[i] >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(
                envelope.ciphertexts[i],
            ));
        }
        mac_elems.push(envelope.account_ids[i] as u128);
        mac_elems.push(envelope.ciphertexts[i]);
    }

    key.mac_key.verify_elems_ref(
        DOMAIN_SUBSHARE_BATCH,
        &mac_elems,
        envelope.cw_tag,
        "batch_subshare_envelope",
    )?;

    let mut out = Vec::with_capacity(envelope.ciphertexts.len());
    for i in 0..envelope.ciphertexts.len() {
        let pt = sub_mod(envelope.ciphertexts[i], key.pads[i]);
        out.push(SubSharePlaintext::new(
            envelope.from_validator,
            envelope.to_validator,
            envelope.account_ids[i],
            pt,
        ));
    }
    Ok(out)
}

// ============================================================================
// Shamir Secret Sharing & Lagrange Interpolation over F_(2^127 - 1)
// ============================================================================

/// A Shamir secret share `(x, y)` in `F_(2^127 - 1)` with volatile zeroization and redacted `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    pub x: ValidatorId,
    y: u128,
}

impl Share {
    /// Construct a new validated share `(x, y)` with `x >= 1` and canonical `y < PRIME_P`.
    pub fn new(x: ValidatorId, y: u128) -> Result<Self, DynamicQuorumError> {
        if x == 0 {
            return Err(DynamicQuorumError::InvalidValidatorCoordinate(0));
        }
        if y >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(y));
        }
        Ok(Self { x, y })
    }

    /// Access the share y-value in `F_(2^127 - 1)`.
    #[inline]
    pub fn y(&self) -> u128 {
        self.y
    }

    /// Return a copy with a modified y-value (useful for fault injection / testing).
    pub fn with_y(&self, new_y: u128) -> Self {
        Self {
            x: self.x,
            y: reduce(new_y),
        }
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        zeroize_u128(&mut self.y);
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("x", &self.x)
            .field("y", &"[REDACTED]")
            .finish()
    }
}

/// Secret random polynomial over `F_(2^127 - 1)` that volatile-zeroizes all coefficients on `Drop`.
struct SecretPolynomial {
    coeffs: Vec<u128>,
}

impl SecretPolynomial {
    /// Build a random polynomial of degree `<= threshold - 1` with constant term `secret`.
    fn random_with_constant(secret: u128, threshold: usize) -> Self {
        let mut coeffs = Vec::with_capacity(threshold);
        coeffs.push(reduce(secret));
        for _ in 1..threshold {
            coeffs.push(random_field_elem());
        }
        Self { coeffs }
    }

    /// Evaluate the polynomial at `x` via Horner's method.
    #[inline]
    fn eval(&self, x: ValidatorId) -> u128 {
        let x_elem = reduce(x as u128);
        let mut acc = 0u128;
        for &c in self.coeffs.iter().rev() {
            acc = add_mod(mul_mod(acc, x_elem), c);
        }
        acc
    }
}

impl Drop for SecretPolynomial {
    fn drop(&mut self) {
        for c in &mut self.coeffs {
            zeroize_u128(c);
        }
    }
}

impl fmt::Debug for SecretPolynomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPolynomial")
            .field("degree_bound", &self.coeffs.len().saturating_sub(1))
            .field("coeffs", &"[REDACTED]")
            .finish()
    }
}

/// Validate that all validator x-coordinates are non-zero and pairwise distinct.
pub fn validate_coordinates(xs: &[ValidatorId]) -> Result<(), DynamicQuorumError> {
    let mut seen = BTreeSet::new();
    for &x in xs {
        if x == 0 {
            return Err(DynamicQuorumError::InvalidValidatorCoordinate(0));
        }
        if !seen.insert(x) {
            return Err(DynamicQuorumError::DuplicateValidatorCoordinate(x));
        }
    }
    Ok(())
}

/// Split `secret` into Shamir shares for `xs` with reconstruction threshold `threshold`.
pub fn split_secret(
    secret: u128,
    threshold: usize,
    xs: &[ValidatorId],
) -> Result<Vec<Share>, DynamicQuorumError> {
    if secret >= PRIME_P {
        return Err(DynamicQuorumError::NonCanonicalFieldElement(secret));
    }
    if threshold == 0 || threshold > xs.len() {
        return Err(DynamicQuorumError::InvalidThreshold {
            threshold,
            committee_size: xs.len(),
        });
    }
    validate_coordinates(xs)?;

    let poly = SecretPolynomial::random_with_constant(secret, threshold);
    let mut shares = Vec::with_capacity(xs.len());
    for &x in xs {
        shares.push(Share::new(x, poly.eval(x))?);
    }
    // `poly` drops here and volatile-zeroizes all random coefficients.
    Ok(shares)
}

/// Compute Lagrange interpolation coefficients `lambda_i` evaluated at `x = 0` for coordinates `xs`.
///
/// For each `i`: `lambda_i = prod_{k != i} (x_k / (x_k - x_i)) mod p`.
pub fn lagrange_coeffs_at_zero(xs: &[ValidatorId]) -> Result<Vec<u128>, DynamicQuorumError> {
    if xs.is_empty() {
        return Err(DynamicQuorumError::InsufficientShares {
            provided: 0,
            required: 1,
        });
    }
    validate_coordinates(xs)?;

    let mut lambdas = Vec::with_capacity(xs.len());
    for i in 0..xs.len() {
        let xi = xs[i] as u128;
        let mut num = 1u128;
        let mut den = 1u128;
        for (k, &xk_u64) in xs.iter().enumerate() {
            if k == i {
                continue;
            }
            let xk = xk_u64 as u128;
            num = mul_mod(num, xk);
            den = mul_mod(den, sub_mod(xk, xi));
        }
        lambdas.push(mul_mod(num, inv_mod(den)));
    }
    Ok(lambdas)
}

/// Evaluate the unique polynomial passing through `points` at `target_x` (where `target_x` may be 0 or non-zero).
fn lagrange_eval_at(points: &[Share], target_x: u128) -> Result<u128, DynamicQuorumError> {
    if points.is_empty() {
        return Err(DynamicQuorumError::InsufficientShares {
            provided: 0,
            required: 1,
        });
    }
    if target_x >= PRIME_P {
        return Err(DynamicQuorumError::NonCanonicalFieldElement(target_x));
    }
    for p in points {
        if p.y >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(p.y));
        }
    }
    let xs: Vec<ValidatorId> = points.iter().map(|s| s.x).collect();
    validate_coordinates(&xs)?;

    let target = target_x;
    let mut acc = 0u128;
    for i in 0..points.len() {
        let xi = points[i].x as u128;
        let mut num = 1u128;
        let mut den = 1u128;
        for (k, p) in points.iter().enumerate() {
            if k == i {
                continue;
            }
            let xk = p.x as u128;
            num = mul_mod(num, sub_mod(target, xk));
            den = mul_mod(den, sub_mod(xi, xk));
        }
        let li = mul_mod(num, inv_mod(den));
        acc = add_mod(acc, mul_mod(li, points[i].y));
    }
    Ok(acc)
}

/// Reconstruct a secret at `x = 0` from the first `threshold` shares.
pub fn reconstruct_secret(shares: &[Share], threshold: usize) -> Result<u128, DynamicQuorumError> {
    if threshold == 0 {
        return Err(DynamicQuorumError::InvalidThreshold {
            threshold: 0,
            committee_size: shares.len(),
        });
    }
    if shares.len() < threshold {
        return Err(DynamicQuorumError::InsufficientShares {
            provided: shares.len(),
            required: threshold,
        });
    }
    lagrange_eval_at(&shares[..threshold], 0)
}

/// Interpolate all provided shares at `x = 0` (useful for testing under-threshold reconstruction).
pub fn interpolate_at_zero(shares: &[Share]) -> Result<u128, DynamicQuorumError> {
    lagrange_eval_at(shares, 0)
}

// ============================================================================
// 1. Zero-Reconstruction Share Redistribution & Consistency Verification
// ============================================================================

/// Result of degree-(t'-1) consistency verification on committee shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareConsistencyReport {
    /// True iff every share lies on a single polynomial of degree `<= threshold - 1`.
    pub is_consistent: bool,
    /// Number of non-zero parity check points evaluated (`N' - t'`).
    pub checked_points: usize,
    /// Number of parity check equations that failed against the base subset.
    pub failing_checks: usize,
    /// Unambiguously identified corrupted validator IDs (possible when `N' - t' >= 2` and 1+ outliers).
    pub suspected_validators: Vec<ValidatorId>,
}

/// Result of auditing per-dealer sub-shares across the new committee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubShareAuditReport {
    /// True iff every old dealer's sub-share row lies on a degree-`(new_threshold - 1)` polynomial.
    pub all_dealers_honest: bool,
    /// Old dealers whose sub-share row failed degree consistency.
    pub malicious_dealers: Vec<ValidatorId>,
    /// Per-dealer localized target corruption (when `N' - t' >= 2`).
    pub corrupted_targets_by_dealer: BTreeMap<ValidatorId, Vec<ValidatorId>>,
}

/// Output of single-account zero-reconstruction share redistribution.
#[derive(Debug)]
pub struct RedistributionResult {
    pub epoch: u64,
    pub account_id: AccountId,
    pub new_threshold: usize,
    pub new_shares: Vec<Share>,
    pub envelopes_processed: usize,
    pub otp_bytes_consumed: usize,
    pub consistency: ShareConsistencyReport,
}

/// Output of batch zero-reconstruction share redistribution across an entire account ledger.
#[derive(Debug)]
pub struct BatchRedistributionResult {
    pub epoch: u64,
    pub old_quorum: Vec<ValidatorId>,
    pub new_committee: Vec<ValidatorId>,
    pub new_threshold: usize,
    pub redistributed_accounts: BTreeMap<AccountId, Vec<Share>>,
    pub envelopes_processed: usize,
    pub otp_bytes_consumed: usize,
    pub verified_accounts: usize,
}

/// Helper: generate all combinations of size `k` from `0..n` up to `max_combos`.
fn generate_combinations(n: usize, k: usize, max_combos: usize) -> Vec<Vec<usize>> {
    let mut results = Vec::new();
    let mut current = Vec::with_capacity(k);

    fn dfs(
        start: usize,
        n: usize,
        k: usize,
        max_combos: usize,
        current: &mut Vec<usize>,
        results: &mut Vec<Vec<usize>>,
    ) {
        if results.len() >= max_combos {
            return;
        }
        if current.len() == k {
            results.push(current.clone());
            return;
        }
        let needed = k - current.len();
        if start + needed > n {
            return;
        }
        for i in start..=(n - needed) {
            current.push(i);
            dfs(i + 1, n, k, max_combos, current, results);
            current.pop();
            if results.len() >= max_combos {
                return;
            }
        }
    }

    dfs(0, n, k, max_combos, &mut current, &mut results);
    results
}

/// Verify that `shares` all lie on a single polynomial of degree `<= threshold - 1`
/// **WITHOUT EVER EVALUATING `F(0)` OR RECONSTRUCTING THE SECRET**.
///
/// Evaluates Lagrange parity checks at the remaining non-zero validator coordinates `x_k` (`k >= threshold`).
/// When `shares.len() >= threshold + 2`, unambiguously localizes outlier corrupted validator(s).
pub fn verify_committee_shares(
    shares: &[Share],
    threshold: usize,
) -> Result<ShareConsistencyReport, DynamicQuorumError> {
    if threshold == 0 || threshold > shares.len() {
        return Err(DynamicQuorumError::InvalidThreshold {
            threshold,
            committee_size: shares.len(),
        });
    }
    let xs: Vec<ValidatorId> = shares.iter().map(|s| s.x).collect();
    validate_coordinates(&xs)?;

    let checked_points = shares.len() - threshold;
    if checked_points == 0 {
        return Ok(ShareConsistencyReport {
            is_consistent: true,
            checked_points: 0,
            failing_checks: 0,
            suspected_validators: Vec::new(),
        });
    }

    // Fast path: interpolate the first `threshold` shares at each remaining non-zero x_k.
    let base = &shares[..threshold];
    let mut failing_checks = 0usize;
    for share in &shares[threshold..] {
        let predicted = lagrange_eval_at(base, share.x as u128)?;
        if predicted != share.y {
            failing_checks += 1;
        }
    }

    if failing_checks == 0 {
        return Ok(ShareConsistencyReport {
            is_consistent: true,
            checked_points,
            failing_checks: 0,
            suspected_validators: Vec::new(),
        });
    }

    // Fault localization when redundancy `N' - t' >= 2`:
    // Any honest subset of size `threshold` agrees on all remaining honest shares (inliers > threshold).
    let mut suspected_validators = Vec::new();
    if checked_points >= 2 {
        let combos = generate_combinations(shares.len(), threshold, 2048);
        let mut best_inlier_count = 0usize;
        let mut best_inlier_sets: BTreeSet<Vec<ValidatorId>> = BTreeSet::new();

        for combo in combos {
            let candidate_base: Vec<Share> = combo.iter().map(|&idx| shares[idx].clone()).collect();
            let mut inliers = Vec::with_capacity(shares.len());
            for &idx in &combo {
                inliers.push(shares[idx].x);
            }
            for (idx, share) in shares.iter().enumerate() {
                if combo.contains(&idx) {
                    continue;
                }
                let predicted = lagrange_eval_at(&candidate_base, share.x as u128)?;
                if predicted == share.y {
                    inliers.push(share.x);
                }
            }
            inliers.sort_unstable();
            if inliers.len() > best_inlier_count {
                best_inlier_count = inliers.len();
                best_inlier_sets.clear();
                best_inlier_sets.insert(inliers);
            } else if inliers.len() == best_inlier_count {
                best_inlier_sets.insert(inliers);
            }
        }

        // Only claim localization when a unique maximum-inlier polynomial explains strictly > threshold shares.
        if best_inlier_count > threshold && best_inlier_sets.len() == 1 {
            let honest_set: BTreeSet<ValidatorId> =
                best_inlier_sets.into_iter().next().unwrap().into_iter().collect();
            for s in shares {
                if !honest_set.contains(&s.x) {
                    suspected_validators.push(s.x);
                }
            }
            suspected_validators.sort_unstable();
        }
    }

    Ok(ShareConsistencyReport {
        is_consistent: false,
        checked_points,
        failing_checks,
        suspected_validators,
    })
}

/// Audit a matrix of decrypted sub-shares `(old_dealer_id, new_validator_id) -> sub_share`
/// to identify any Byzantine old validator that dealt an inconsistent (non-degree-`t'-1`) row.
pub fn verify_subshare_matrix(
    old_quorum: &[ValidatorId],
    new_committee: &[ValidatorId],
    new_threshold: usize,
    subshares: &BTreeMap<(ValidatorId, ValidatorId), u128>,
) -> Result<SubShareAuditReport, DynamicQuorumError> {
    validate_coordinates(old_quorum)?;
    validate_coordinates(new_committee)?;
    if new_threshold == 0 || new_threshold > new_committee.len() {
        return Err(DynamicQuorumError::InvalidThreshold {
            threshold: new_threshold,
            committee_size: new_committee.len(),
        });
    }

    let mut malicious_dealers = Vec::new();
    let mut corrupted_targets_by_dealer = BTreeMap::new();

    for &dealer in old_quorum {
        let mut row_shares = Vec::with_capacity(new_committee.len());
        for &target in new_committee {
            let &val = subshares.get(&(dealer, target)).ok_or(
                DynamicQuorumError::InsufficientShares {
                    provided: row_shares.len(),
                    required: new_committee.len(),
                },
            )?;
            row_shares.push(Share::new(target, val)?);
        }
        let report = verify_committee_shares(&row_shares, new_threshold)?;
        if !report.is_consistent {
            malicious_dealers.push(dealer);
            if !report.suspected_validators.is_empty() {
                corrupted_targets_by_dealer.insert(dealer, report.suspected_validators);
            }
        }
    }

    Ok(SubShareAuditReport {
        all_dealers_honest: malicious_dealers.is_empty(),
        malicious_dealers,
        corrupted_targets_by_dealer,
    })
}

/// Step 1 of zero-reconstruction resharing: an old quorum validator splits its single share `y_i`
/// into a fresh random degree-`(new_threshold - 1)` polynomial `g_i(x)` with `g_i(0) = y_i`,
/// and encrypts each `g_i(x'_j)` under a fresh pairwise OTP + Carter-Wegman MAC envelope.
///
/// Returns `(envelopes_for_new_validators, matching_receiver_keys)` where each key is strictly one-time.
pub fn dealer_prepare_subshare_envelopes(
    epoch: u64,
    account_id: AccountId,
    old_share: &Share,
    new_committee: &[ValidatorId],
    new_threshold: usize,
) -> Result<(Vec<OtpSubShareEnvelope>, Vec<PairwiseOtpKey>), DynamicQuorumError> {
    if new_threshold == 0 || new_threshold > new_committee.len() {
        return Err(DynamicQuorumError::InvalidThreshold {
            threshold: new_threshold,
            committee_size: new_committee.len(),
        });
    }
    validate_coordinates(new_committee)?;

    let poly = SecretPolynomial::random_with_constant(old_share.y(), new_threshold);
    let mut envelopes = Vec::with_capacity(new_committee.len());
    let mut receiver_keys = Vec::with_capacity(new_committee.len());

    for &new_id in new_committee {
        let sub_val = poly.eval(new_id);
        let (sender_key, receiver_key) = PairwiseOtpKey::generate_pair();
        let env = encrypt_subshare(
            epoch,
            account_id,
            old_share.x,
            new_id,
            sub_val,
            sender_key,
        );
        envelopes.push(env);
        receiver_keys.push(receiver_key);
    }
    // `poly` drops here and volatile-zeroizes all random coefficients.
    Ok((envelopes, receiver_keys))
}

/// Step 2 of zero-reconstruction resharing: a new validator `j` verifies & decrypts the `t` incoming
/// OTP+CW-MAC sub-share envelopes and combines them with old-quorum Lagrange weights `lambda_i`:
///
/// `y'_j = sum_{i in Q} lambda_i * g_i(x'_j) mod (2^127 - 1)`.
pub fn combine_incoming_subshares(
    new_validator: ValidatorId,
    old_quorum_xs: &[ValidatorId],
    old_lambdas: &[u128],
    incoming: Vec<(OtpSubShareEnvelope, PairwiseOtpKey)>,
) -> Result<Share, DynamicQuorumError> {
    if new_validator == 0 {
        return Err(DynamicQuorumError::InvalidValidatorCoordinate(0));
    }
    if incoming.len() != old_quorum_xs.len() || old_lambdas.len() != old_quorum_xs.len() {
        return Err(DynamicQuorumError::InsufficientShares {
            provided: incoming.len(),
            required: old_quorum_xs.len(),
        });
    }

    let mut combined = 0u128;
    for (idx, (env, key)) in incoming.into_iter().enumerate() {
        if env.from_validator != old_quorum_xs[idx] || env.to_validator != new_validator {
            return Err(DynamicQuorumError::MacVerificationFailed {
                context: "subshare_routing_mismatch",
            });
        }
        let sub = decrypt_subshare(&env, key)?;
        combined = add_mod(combined, mul_mod(old_lambdas[idx], sub.value()));
        // `sub` drops immediately and volatile-zeroizes the decrypted sub-share.
    }
    Share::new(new_validator, combined)
}

/// Full zero-reconstruction information-theoretic share redistribution `(t, N) -> (t', N')`
/// for a single secret-shared account balance.
///
/// - `old_quorum_shares`: exactly `t` shares from an honest old quorum `Q` (size `t`).
/// - `new_committee`: `N'` distinct non-zero validator x-coordinates.
/// - `new_threshold`: target reconstruction threshold `t'` (`1 <= t' <= N'`).
///
/// Neither any old validator, nor any new validator, nor any `< t` old or `< t'` new coalition
/// ever reconstructs or learns a single bit of the secret balance `S`.
pub fn redistribute_shares(
    epoch: u64,
    account_id: AccountId,
    old_quorum_shares: &[Share],
    new_committee: &[ValidatorId],
    new_threshold: usize,
) -> Result<RedistributionResult, DynamicQuorumError> {
    if old_quorum_shares.is_empty() {
        return Err(DynamicQuorumError::InsufficientShares {
            provided: 0,
            required: 1,
        });
    }
    if new_threshold == 0 || new_threshold > new_committee.len() {
        return Err(DynamicQuorumError::InvalidThreshold {
            threshold: new_threshold,
            committee_size: new_committee.len(),
        });
    }
    let old_xs: Vec<ValidatorId> = old_quorum_shares.iter().map(|s| s.x).collect();
    validate_coordinates(&old_xs)?;
    validate_coordinates(new_committee)?;

    let old_lambdas = lagrange_coeffs_at_zero(&old_xs)?;

    // Round 1: Each old validator independently deals its own degree-(t'-1) sub-shares over OTP+CW-MAC.
    let mut per_new_inbox: Vec<Vec<(OtpSubShareEnvelope, PairwiseOtpKey)>> = (0..new_committee.len())
        .map(|_| Vec::with_capacity(old_quorum_shares.len()))
        .collect();

    for old_share in old_quorum_shares {
        let (envelopes, keys) = dealer_prepare_subshare_envelopes(
            epoch,
            account_id,
            old_share,
            new_committee,
            new_threshold,
        )?;
        for (j, (env, key)) in envelopes.into_iter().zip(keys.into_iter()).enumerate() {
            per_new_inbox[j].push((env, key));
        }
    }

    // Round 2: Each new validator verifies MACs, decrypts sub-shares, and combines with lambda_i.
    let mut new_shares = Vec::with_capacity(new_committee.len());
    for (j, inbox) in per_new_inbox.into_iter().enumerate() {
        let share = combine_incoming_subshares(new_committee[j], &old_xs, &old_lambdas, inbox)?;
        new_shares.push(share);
    }

    // Degree-(t'-1) consistency verification without evaluating F'(0).
    let consistency = verify_committee_shares(&new_shares, new_threshold)?;
    if !consistency.is_consistent {
        return Err(DynamicQuorumError::InconsistentShares {
            failing_checks: consistency.failing_checks,
            suspected_validators: consistency.suspected_validators,
        });
    }

    let envelopes_processed = old_quorum_shares.len().saturating_mul(new_committee.len());
    // Each single envelope consumes 1 OTP pad (16 B) + 2 CW-MAC key elements (32 B) = 48 B.
    let otp_bytes_consumed = envelopes_processed.saturating_mul(48);

    Ok(RedistributionResult {
        epoch,
        account_id,
        new_threshold,
        new_shares,
        envelopes_processed,
        otp_bytes_consumed,
        consistency,
    })
}

/// Batch zero-reconstruction redistribution across hundreds or thousands of secret-shared accounts
/// simultaneously, amortizing Lagrange weight computation and Carter-Wegman MAC tags while still
/// using an independent fresh one-time pad per `(old_validator, new_validator, account)` tuple.
pub fn redistribute_ledger_accounts(
    epoch: u64,
    old_ledger: &BTreeMap<AccountId, Vec<Share>>,
    old_quorum: &[ValidatorId],
    new_committee: &[ValidatorId],
    new_threshold: usize,
) -> Result<BatchRedistributionResult, DynamicQuorumError> {
    if old_quorum.is_empty() {
        return Err(DynamicQuorumError::InsufficientShares {
            provided: 0,
            required: 1,
        });
    }
    if new_threshold == 0 || new_threshold > new_committee.len() {
        return Err(DynamicQuorumError::InvalidThreshold {
            threshold: new_threshold,
            committee_size: new_committee.len(),
        });
    }
    validate_coordinates(old_quorum)?;
    validate_coordinates(new_committee)?;

    let old_lambdas = lagrange_coeffs_at_zero(old_quorum)?;
    let account_ids: Vec<AccountId> = old_ledger.keys().copied().collect();
    let num_accounts = account_ids.len();

    // Extract each old quorum validator's local vector of account shares (no validator sees another's).
    let mut old_validator_shares: Vec<Vec<u128>> = vec![Vec::with_capacity(num_accounts); old_quorum.len()];
    for &acct in &account_ids {
        let shares = &old_ledger[&acct];
        let acct_xs: Vec<ValidatorId> = shares.iter().map(|s| s.x).collect();
        validate_coordinates(&acct_xs)?;
        for (i, &vid) in old_quorum.iter().enumerate() {
            let found = shares
                .iter()
                .find(|s| s.x == vid)
                .ok_or(DynamicQuorumError::MissingQuorumShare {
                    account_id: acct,
                    validator_id: vid,
                })?;
            if found.y() >= PRIME_P {
                return Err(DynamicQuorumError::NonCanonicalFieldElement(found.y()));
            }
            old_validator_shares[i].push(found.y());
        }
    }

    // Round 1: Each old quorum validator generates fresh random polynomials for every account and
    // sends one authenticated batch OTP envelope to each new committee validator.
    let mut per_new_batch_inbox: Vec<Vec<(OtpBatchSubShareEnvelope, BatchOtpKey)>> =
        (0..new_committee.len())
            .map(|_| Vec::with_capacity(old_quorum.len()))
            .collect();

    for (i, &old_vid) in old_quorum.iter().enumerate() {
        let mut sub_matrix_for_dealer: Vec<Vec<u128>> =
            vec![Vec::with_capacity(num_accounts); new_committee.len()];
        for &y_i in &old_validator_shares[i] {
            let poly = SecretPolynomial::random_with_constant(y_i, new_threshold);
            for (j, &new_vid) in new_committee.iter().enumerate() {
                sub_matrix_for_dealer[j].push(poly.eval(new_vid));
            }
            // `poly` drops and volatile-zeroizes coefficients.
        }
        // Zeroize temporary local copy of old validator shares.
        for v in &mut old_validator_shares[i] {
            zeroize_u128(v);
        }

        for (j, &new_vid) in new_committee.iter().enumerate() {
            let (sender_key, receiver_key) = BatchOtpKey::generate_pair(num_accounts);
            let env = encrypt_subshare_batch(
                epoch,
                old_vid,
                new_vid,
                account_ids.clone(),
                &sub_matrix_for_dealer[j],
                sender_key,
            )?;
            for v in &mut sub_matrix_for_dealer[j] {
                zeroize_u128(v);
            }
            per_new_batch_inbox[j].push((env, receiver_key));
        }
    }

    // Round 2: Each new validator authenticates & decrypts incoming batch envelopes and combines.
    let mut new_shares_by_account: Vec<Vec<Share>> =
        (0..num_accounts).map(|_| Vec::with_capacity(new_committee.len())).collect();

    for (j, inbox) in per_new_batch_inbox.into_iter().enumerate() {
        let new_vid = new_committee[j];
        let mut accumulators = vec![0u128; num_accounts];

        for (i, (env, key)) in inbox.into_iter().enumerate() {
            if env.from_validator != old_quorum[i] || env.to_validator != new_vid {
                return Err(DynamicQuorumError::MacVerificationFailed {
                    context: "batch_subshare_routing_mismatch",
                });
            }
            let decrypted = decrypt_subshare_batch(&env, key)?;
            let lam = old_lambdas[i];
            for (a_idx, sub) in decrypted.iter().enumerate() {
                accumulators[a_idx] = add_mod(accumulators[a_idx], mul_mod(lam, sub.value()));
            }
            // `decrypted` drops here and volatile-zeroizes all sub-shares.
        }

        for a_idx in 0..num_accounts {
            new_shares_by_account[a_idx].push(Share::new(new_vid, accumulators[a_idx])?);
            zeroize_u128(&mut accumulators[a_idx]);
        }
    }

    // Verify degree-(t'-1) consistency on every redistributed account without reconstructing secrets.
    let mut redistributed_accounts = BTreeMap::new();
    for (a_idx, acct_id) in account_ids.into_iter().enumerate() {
        let shares = std::mem::take(&mut new_shares_by_account[a_idx]);
        let report = verify_committee_shares(&shares, new_threshold)?;
        if !report.is_consistent {
            return Err(DynamicQuorumError::InconsistentShares {
                failing_checks: report.failing_checks,
                suspected_validators: report.suspected_validators,
            });
        }
        redistributed_accounts.insert(acct_id, shares);
    }

    let envelopes_processed = old_quorum.len().saturating_mul(new_committee.len());
    // Each batch envelope uses `num_accounts * 16 B` OTP pads + `32 B` CW-MAC key.
    let otp_bytes_consumed =
        envelopes_processed.saturating_mul(num_accounts.saturating_mul(16).saturating_add(32));

    Ok(BatchRedistributionResult {
        epoch,
        old_quorum: old_quorum.to_vec(),
        new_committee: new_committee.to_vec(),
        new_threshold,
        verified_accounts: redistributed_accounts.len(),
        redistributed_accounts,
        envelopes_processed,
        otp_bytes_consumed,
    })
}

// ============================================================================
// 2. Zero-Admin Permissionless Committee Governance (`DynamicCommitteeManager`)
// ============================================================================

/// BFT-safe threshold parameters derived automatically from committee size `N`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BftParams {
    /// Total committee size `N`.
    pub committee_size: usize,
    /// Maximum tolerated Byzantine faults `f = (N - 1) / 3`.
    pub max_faults: usize,
    /// Shamir reconstruction & BFT quorum threshold `t = 2f + 1`.
    pub threshold: usize,
}

/// Automatically compute BFT-safe `(t, N)` parameters for any `N >= 4`:
/// - `f = (N - 1) / 3` (maximum Byzantine faults tolerated, guaranteeing `N >= 3f + 1`),
/// - `t = ((N + f) / 2) + 1` (minimum strict BFT + Shamir quorum guaranteeing `t >= 2f + 1`,
///   `t > N / 2`, `2t - N >= f + 1` honest quorum intersection, and `t <= N - f` liveness).
///
/// Examples:
/// - `N = 4` -> `f = 1, t = 3`
/// - `N = 6` -> `f = 1, t = 4`
/// - `N = 7` -> `f = 2, t = 5`
/// - `N = 10` -> `f = 3, t = 7`
pub fn compute_bft_params(committee_size: usize) -> Result<BftParams, DynamicQuorumError> {
    if committee_size < MIN_BFT_COMMITTEE_SIZE {
        return Err(DynamicQuorumError::InvalidCommitteeSize {
            size: committee_size,
            min_required: MIN_BFT_COMMITTEE_SIZE,
        });
    }
    let max_faults = (committee_size - 1) / 3;
    // Use u128 to prevent overflow even for extreme committee_size values.
    let threshold_u128 = ((committee_size as u128) + (max_faults as u128)) / 2 + 1;
    let threshold = usize::try_from(threshold_u128).map_err(|_| {
        DynamicQuorumError::InvalidCommitteeSize {
            size: committee_size,
            min_required: MIN_BFT_COMMITTEE_SIZE,
        }
    })?;
    debug_assert!(committee_size >= 3 * max_faults + 1);
    debug_assert!(threshold >= 2 * max_faults + 1);
    debug_assert!(threshold > committee_size / 2);
    debug_assert!(threshold <= committee_size - max_faults);
    Ok(BftParams {
        committee_size,
        max_faults,
        threshold,
    })
}

/// Strict per-epoch validator churn limit (`f_old.max(1)`) for committee replacements/ejections.
#[inline]
pub const fn max_churn_per_epoch(bft: BftParams) -> usize {
    if bft.max_faults >= 1 {
        bft.max_faults
    } else {
        1
    }
}

// ============================================================================
// 2b. 4D Diversity Matrix, Slow Churn, Probation & Demand-Scaled Core Bond
// ============================================================================

/// Reference OS kernel family tags for [`QuorumDiversityProfile::os_family`].
pub const OS_FAMILY_LINUX: u8 = 1;
pub const OS_FAMILY_FREEBSD: u8 = 2;
pub const OS_FAMILY_OPENBSD: u8 = 3;
pub const OS_FAMILY_MACOS: u8 = 4;

/// Reference CPU ISA tags for [`QuorumDiversityProfile::cpu_isa`].
pub const CPU_ISA_X86_64: u8 = 1;
pub const CPU_ISA_AARCH64: u8 = 2;
pub const CPU_ISA_RISCV64: u8 = 3;
pub const CPU_ISA_POWERPC64: u8 = 4;

/// Reference compiler lineage tags for [`QuorumDiversityProfile::compiler_lineage`].
pub const COMPILER_RUSTC_LLVM: u8 = 1;
pub const COMPILER_RUSTC_CRANELIFT: u8 = 2;
pub const COMPILER_GCCRS: u8 = 3;
pub const COMPILER_MRUSTC: u8 = 4;

/// Default target share of circulating supply bonded across Core seats (`2,000 bps = 20%`).
pub const DEFAULT_TARGET_BONDED_BPS: u16 = 2_000;

/// Basis-point denominator (`10,000 bps = 100%`).
pub const CORE_BOND_BPS_DENOMINATOR: u16 = 10_000;

/// Default minimum flat bond floor per Core seat (`10,000 VRNM` in `vern`, `1 VRNM = 10^8 vern`).
pub const DEFAULT_MIN_CORE_BOND: u64 = 10_000 * 100_000_000;

/// Default Outer Pool probation duration required before Core seat eligibility (`30` epochs).
pub const DEFAULT_OUTER_POOL_PROBATION_EPOCHS: u64 = 30;

/// Default Core unbonding lockup duration after exiting the Core committee (`60` epochs).
pub const DEFAULT_UNBONDING_EPOCHS: u64 = 60;

/// Default sliding window duration for slow-churn Core seat rotations (`30` epochs).
pub const DEFAULT_CORE_ROTATION_WINDOW_EPOCHS: u64 = 30;

/// 4D hardware/software/network/geographic diversity profile of a committee validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuorumDiversityProfile {
    pub os_family: u8,
    pub cpu_isa: u8,
    pub compiler_lineage: u8,
    pub asn: u32,
    pub geo_cell_id: u16,
}

/// 4D diversity enforcement policy for a Core BFT committee.
///
/// Defaults strictly enforce that:
/// - NO single OS kernel family exceeds `f` seats (`<= bft_params.max_faults < t`),
/// - NO single CPU ISA exceeds `f` seats (`<= bft_params.max_faults < t`),
/// - NO single compiler lineage exceeds `f` seats (`<= bft_params.max_faults < t`),
/// - At most `1` validator per Autonomous System Number (`ASN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumDiversityPolicy {
    /// Maximum seats per OS kernel family (`None` => `bft_params.max_faults`).
    pub max_per_os_family: Option<usize>,
    /// Maximum seats per CPU ISA (`None` => `bft_params.max_faults`).
    pub max_per_cpu_isa: Option<usize>,
    /// Maximum seats per compiler lineage (`None` => `bft_params.max_faults`).
    pub max_per_compiler_lineage: Option<usize>,
    /// Maximum seats per BGP Autonomous System Number (default `1`).
    pub max_per_asn: usize,
    /// Optional cap on seats sharing a single geographic Voronoi cell (`None` => uncapped).
    pub max_per_geo_cell: Option<usize>,
}

impl Default for QuorumDiversityPolicy {
    fn default() -> Self {
        Self {
            max_per_os_family: None,
            max_per_cpu_isa: None,
            max_per_compiler_lineage: None,
            max_per_asn: 1,
            max_per_geo_cell: None,
        }
    }
}

impl QuorumDiversityPolicy {
    /// Construct a policy that also caps validators per geographic Voronoi cell to `max_per_geo_cell`.
    pub const fn with_geo_cell_cap(max_per_geo_cell: usize) -> Self {
        Self {
            max_per_os_family: None,
            max_per_cpu_isa: None,
            max_per_compiler_lineage: None,
            max_per_asn: 1,
            max_per_geo_cell: Some(max_per_geo_cell),
        }
    }

    /// Validate that `profiles` satisfy all 4D diversity constraints for `bft_params`.
    pub fn validate(
        &self,
        profiles: &[QuorumDiversityProfile],
        bft_params: BftParams,
    ) -> Result<(), DynamicQuorumError> {
        let expected_bft = compute_bft_params(bft_params.committee_size)?;
        if bft_params != expected_bft {
            return Err(DynamicQuorumError::InvalidThreshold {
                threshold: bft_params.threshold,
                committee_size: bft_params.committee_size,
            });
        }
        if profiles.len() != bft_params.committee_size {
            return Err(DynamicQuorumError::InvalidCommitteeSize {
                size: profiles.len(),
                min_required: bft_params.committee_size,
            });
        }
        if self.max_per_asn == 0 {
            return Err(DynamicQuorumError::InvalidConfig("max_per_asn must be >= 1"));
        }

        // Cap software/hardware monoculture strictly at <= f (never >= t).
        let max_os = self
            .max_per_os_family
            .unwrap_or(bft_params.max_faults)
            .min(bft_params.max_faults);
        let max_isa = self
            .max_per_cpu_isa
            .unwrap_or(bft_params.max_faults)
            .min(bft_params.max_faults);
        let max_compiler = self
            .max_per_compiler_lineage
            .unwrap_or(bft_params.max_faults)
            .min(bft_params.max_faults);

        let mut os_counts: BTreeMap<u8, usize> = BTreeMap::new();
        let mut isa_counts: BTreeMap<u8, usize> = BTreeMap::new();
        let mut compiler_counts: BTreeMap<u8, usize> = BTreeMap::new();
        let mut asn_counts: BTreeMap<u32, usize> = BTreeMap::new();
        let mut geo_counts: BTreeMap<u16, usize> = BTreeMap::new();

        for p in profiles {
            let os_c = os_counts.entry(p.os_family).or_insert(0);
            *os_c += 1;
            if *os_c > max_os {
                return Err(DynamicQuorumError::DiversityPolicyViolation {
                    dimension: "os_family",
                    value: p.os_family as u32,
                    count: *os_c,
                    max_allowed: max_os,
                });
            }

            let isa_c = isa_counts.entry(p.cpu_isa).or_insert(0);
            *isa_c += 1;
            if *isa_c > max_isa {
                return Err(DynamicQuorumError::DiversityPolicyViolation {
                    dimension: "cpu_isa",
                    value: p.cpu_isa as u32,
                    count: *isa_c,
                    max_allowed: max_isa,
                });
            }

            let comp_c = compiler_counts.entry(p.compiler_lineage).or_insert(0);
            *comp_c += 1;
            if *comp_c > max_compiler {
                return Err(DynamicQuorumError::DiversityPolicyViolation {
                    dimension: "compiler_lineage",
                    value: p.compiler_lineage as u32,
                    count: *comp_c,
                    max_allowed: max_compiler,
                });
            }

            let asn_c = asn_counts.entry(p.asn).or_insert(0);
            *asn_c += 1;
            if *asn_c > self.max_per_asn {
                return Err(DynamicQuorumError::DiversityPolicyViolation {
                    dimension: "asn",
                    value: p.asn,
                    count: *asn_c,
                    max_allowed: self.max_per_asn,
                });
            }

            if let Some(max_geo) = self.max_per_geo_cell {
                let geo_c = geo_counts.entry(p.geo_cell_id).or_insert(0);
                *geo_c += 1;
                if *geo_c > max_geo {
                    return Err(DynamicQuorumError::DiversityPolicyViolation {
                        dimension: "geo_cell_id",
                        value: p.geo_cell_id as u32,
                        count: *geo_c,
                        max_allowed: max_geo,
                    });
                }
            }
        }

        Ok(())
    }
}

/// Validate a committee's 4D diversity profiles against the default strict [`QuorumDiversityPolicy`]:
/// no OS kernel family, CPU ISA, or compiler lineage may exceed `bft_params.max_faults` (`< t`),
/// and at most `1` validator may reside in any single ASN.
pub fn validate_committee_diversity(
    profiles: &[QuorumDiversityProfile],
    bft_params: BftParams,
) -> Result<(), DynamicQuorumError> {
    QuorumDiversityPolicy::default().validate(profiles, bft_params)
}

/// Slow-churn Core committee rotation cap per rotation window (`bft.max_faults.max(1)`),
/// ensuring that within any probation/unbonding window strictly fewer than 1/3 of Core seats
/// can rotate.
#[inline]
pub const fn max_core_rotations_per_window(bft: BftParams) -> usize {
    if bft.max_faults >= 1 {
        bft.max_faults
    } else {
        1
    }
}

/// Economic & slow-churn lifecycle policy for Core committee seats:
/// - Demand-scaled flat equal Core bond targeting `20%` (`2,000 bps`) of circulating supply,
/// - `30`-epoch Outer Pool probation prior to Core eligibility,
/// - `60`-epoch unbonding lockup after Core exit,
/// - Slow-churn rotation ceiling (`max_core_rotations_per_window`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreBondPolicy {
    /// Target fraction of circulating supply locked across all Core seats, in bps (`2_000` = 20%).
    pub target_bonded_bps: u16,
    /// Minimum flat bond floor per Core seat (in `vern`).
    pub min_bond_per_seat: u64,
    /// Optional upper cap on the flat bond per Core seat (in `vern`).
    pub max_bond_per_seat: Option<u64>,
    /// Mandatory Outer Pool probation period before Core admission (default `30` epochs).
    pub outer_pool_probation_epochs: u64,
    /// Mandatory unbonding lockup after Core exit before withdrawal (default `60` epochs).
    pub unbonding_epochs: u64,
    /// Sliding window length in epochs for slow-churn rotation caps (default `30` epochs).
    pub rotation_window_epochs: u64,
}

impl Default for CoreBondPolicy {
    fn default() -> Self {
        Self {
            target_bonded_bps: DEFAULT_TARGET_BONDED_BPS,
            min_bond_per_seat: DEFAULT_MIN_CORE_BOND,
            max_bond_per_seat: None,
            outer_pool_probation_epochs: DEFAULT_OUTER_POOL_PROBATION_EPOCHS,
            unbonding_epochs: DEFAULT_UNBONDING_EPOCHS,
            rotation_window_epochs: DEFAULT_CORE_ROTATION_WINDOW_EPOCHS,
        }
    }
}

impl CoreBondPolicy {
    /// Validate policy parameters.
    pub fn validate(&self) -> Result<(), DynamicQuorumError> {
        if self.target_bonded_bps == 0 || self.target_bonded_bps > CORE_BOND_BPS_DENOMINATOR {
            return Err(DynamicQuorumError::InvalidConfig(
                "target_bonded_bps must be in 1..=10_000",
            ));
        }
        if let Some(cap) = self.max_bond_per_seat {
            if cap < self.min_bond_per_seat {
                return Err(DynamicQuorumError::InvalidConfig(
                    "max_bond_per_seat must be >= min_bond_per_seat",
                ));
            }
        }
        if self.outer_pool_probation_epochs == 0 {
            return Err(DynamicQuorumError::InvalidConfig(
                "outer_pool_probation_epochs must be >= 1",
            ));
        }
        if self.unbonding_epochs < self.outer_pool_probation_epochs {
            return Err(DynamicQuorumError::InvalidConfig(
                "unbonding_epochs must be >= outer_pool_probation_epochs",
            ));
        }
        if self.rotation_window_epochs == 0 {
            return Err(DynamicQuorumError::InvalidConfig(
                "rotation_window_epochs must be >= 1",
            ));
        }
        Ok(())
    }

    /// Compute the base flat equal bond per Core seat targeting `target_bonded_bps` (default 20%)
    /// of `circulating_supply` divided evenly across `active_core_seats` (1 seat = 1 vote).
    pub fn required_flat_bond(
        &self,
        circulating_supply: u64,
        active_core_seats: usize,
    ) -> Result<u64, DynamicQuorumError> {
        self.validate()?;
        if active_core_seats < MIN_BFT_COMMITTEE_SIZE {
            return Err(DynamicQuorumError::InvalidCommitteeSize {
                size: active_core_seats,
                min_required: MIN_BFT_COMMITTEE_SIZE,
            });
        }
        let target_total = (circulating_supply as u128)
            .saturating_mul(self.target_bonded_bps as u128)
            / (CORE_BOND_BPS_DENOMINATOR as u128);
        let raw_per_seat = (target_total / (active_core_seats as u128)).min(u64::MAX as u128) as u64;
        let mut bond = raw_per_seat.max(self.min_bond_per_seat);
        if let Some(cap) = self.max_bond_per_seat {
            bond = bond.min(cap);
        }
        Ok(bond)
    }

    /// Compute the demand-scaled flat Core bond per seat.
    ///
    /// Starts from the 20%-circulating-supply base flat bond and scales proportionally when
    /// `queued_candidates > 0` by `(active_core_seats + queued_candidates) / active_core_seats`
    /// (clamped to `max_bond_per_seat` and `circulating_supply / active_core_seats`) so sybil
    /// queue floods automatically increase the equal flat bond without introducing stake weights.
    pub fn demand_scaled_bond(
        &self,
        circulating_supply: u64,
        active_core_seats: usize,
        queued_candidates: usize,
    ) -> Result<u64, DynamicQuorumError> {
        let base = self.required_flat_bond(circulating_supply, active_core_seats)?;
        if queued_candidates == 0 {
            return Ok(base);
        }
        let seats = active_core_seats as u128;
        let demand_num = seats.saturating_add(queued_candidates as u128);
        let scaled = ((base as u128).saturating_mul(demand_num) / seats).min(u64::MAX as u128) as u64;
        let supply_per_seat_cap = (circulating_supply as u128 / seats).min(u64::MAX as u128) as u64;
        let mut bond = scaled.min(supply_per_seat_cap.max(base));
        if let Some(cap) = self.max_bond_per_seat {
            bond = bond.min(cap);
        }
        Ok(bond)
    }

    /// Returns `true` iff a candidate that joined the Outer Pool at `joined_outer_epoch`
    /// has completed the mandatory `outer_pool_probation_epochs` (default 30 epochs).
    #[inline]
    pub const fn is_probation_complete(&self, joined_outer_epoch: u64, current_epoch: u64) -> bool {
        current_epoch.saturating_sub(joined_outer_epoch) >= self.outer_pool_probation_epochs
    }

    /// Returns `true` iff a validator that exited Core at `exited_core_epoch`
    /// has completed the mandatory `unbonding_epochs` lockup (default 60 epochs).
    #[inline]
    pub const fn is_unbonding_complete(&self, exited_core_epoch: u64, current_epoch: u64) -> bool {
        current_epoch.saturating_sub(exited_core_epoch) >= self.unbonding_epochs
    }

    /// Slow-churn maximum Core seat rotations permitted within `rotation_window_epochs`.
    #[inline]
    pub const fn max_core_rotations_per_window(&self, bft: BftParams) -> usize {
        max_core_rotations_per_window(bft)
    }
}

/// Reason a validator is automatically scheduled for slashing/ejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EjectionReason {
    /// Validator missed at least `max_allowed` consecutive epochs.
    MissedEpochs { missed: u64, max_allowed: u64 },
    /// Validator signed conflicting consensus messages (equivocation).
    Equivocation,
    /// Validator dealt corrupted/non-degree-consistent MPC sub-shares.
    MpcSubShareFault,
    /// Validator failed an ongoing Proof-of-Pad audit.
    FailedProofOfPadAudit,
}

/// Lifecycle state of a committee validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    ScheduledForEjection { reason: EjectionReason },
    Ejected { epoch: u64, reason: EjectionReason },
}

/// Proof-of-Pad admission trial submitted permissionlessly by a candidate node.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateTrial {
    pub candidate_id: ValidatorId,
    pub target_epoch: u64,
    pub epoch_beacon_challenge: u128,
    /// Statistical randomness z-score (`|z| <= 3.0`).
    pub entropy_z_score: f64,
    /// Quantum Bit Error Rate (`0.0 <= qber <= 0.11`).
    pub qber: f64,
    /// Beaver multiplication triple check `(a, b, c)` satisfying `a * b == c (mod p)`.
    pub beaver_triple_verified: bool,
    pub beaver_a: u128,
    pub beaver_b: u128,
    pub beaver_c: u128,
    /// Available OTP pad reserve in bytes (`>= MIN_CANDIDATE_PAD_BYTES`).
    pub pad_capacity_bytes: u64,
    /// Universal polynomial binding to the epoch beacon challenge.
    pub challenge_response: u128,
}

impl CandidateTrial {
    /// Compute the deterministic beacon-bound challenge response in `F_(2^127 - 1)`.
    pub fn expected_challenge_response(&self) -> u128 {
        poly_universal_hash(
            self.epoch_beacon_challenge,
            DOMAIN_TRIAL_CHALLENGE,
            &[
                self.candidate_id as u128,
                self.target_epoch as u128,
                reduce(self.beaver_a),
                reduce(self.beaver_b),
                reduce(self.beaver_c),
                self.pad_capacity_bytes as u128,
            ],
        )
    }

    /// Compute the canonical field digest of this trial for validator endorsement MACs.
    pub fn digest(&self) -> u128 {
        let z_bits = self.entropy_z_score.to_bits() as u128;
        let qber_bits = self.qber.to_bits() as u128;
        poly_universal_hash(
            self.epoch_beacon_challenge,
            DOMAIN_TRIAL_DIGEST,
            &[
                self.candidate_id as u128,
                self.target_epoch as u128,
                z_bits,
                qber_bits,
                self.beaver_triple_verified as u128,
                reduce(self.beaver_a),
                reduce(self.beaver_b),
                reduce(self.beaver_c),
                self.pad_capacity_bytes as u128,
                self.challenge_response,
            ],
        )
    }

    /// Construct a genuinely passing Proof-of-Pad trial bound to `epoch_beacon_challenge`.
    pub fn generate_passing(
        candidate_id: ValidatorId,
        target_epoch: u64,
        epoch_beacon_challenge: u128,
        entropy_z_score: f64,
        qber: f64,
        pad_capacity_bytes: u64,
    ) -> Self {
        let beaver_a = random_nonzero_field_elem();
        let beaver_b = random_nonzero_field_elem();
        let beaver_c = mul_mod(beaver_a, beaver_b);
        let mut trial = Self {
            candidate_id,
            target_epoch,
            epoch_beacon_challenge: reduce(epoch_beacon_challenge),
            entropy_z_score,
            qber,
            beaver_triple_verified: true,
            beaver_a,
            beaver_b,
            beaver_c,
            pad_capacity_bytes,
            challenge_response: 0,
        };
        trial.challenge_response = trial.expected_challenge_response();
        trial
    }
}

/// Carter-Wegman authenticated endorsement of a candidate's Proof-of-Pad trial by an active validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialEndorsement {
    pub endorser: ValidatorId,
    pub candidate_id: ValidatorId,
    pub target_epoch: u64,
    pub trial_digest: u128,
    pub cw_tag: u128,
}

impl TrialEndorsement {
    /// Authenticate an endorsement with a fresh one-time Carter-Wegman key (consumed and zeroized).
    pub fn sign(
        endorser: ValidatorId,
        candidate_id: ValidatorId,
        target_epoch: u64,
        trial_digest: u128,
        key: CwMacKey,
    ) -> Self {
        let elems = [
            endorser as u128,
            candidate_id as u128,
            target_epoch as u128,
            reduce(trial_digest),
        ];
        let cw_tag = key.mac_elems(DOMAIN_TRIAL_ENDORSEMENT, &elems);
        Self {
            endorser,
            candidate_id,
            target_epoch,
            trial_digest: reduce(trial_digest),
            cw_tag,
        }
    }

    /// Verify this endorsement's Carter-Wegman MAC in constant time, consuming `verifier_key`.
    pub fn verify(&self, verifier_key: CwMacKey) -> Result<(), DynamicQuorumError> {
        if self.trial_digest >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(
                self.trial_digest,
            ));
        }
        let elems = [
            self.endorser as u128,
            self.candidate_id as u128,
            self.target_epoch as u128,
            self.trial_digest,
        ];
        verifier_key.verify_elems(
            DOMAIN_TRIAL_ENDORSEMENT,
            &elems,
            self.cw_tag,
            "trial_endorsement",
        )
    }
}

/// Planned committee change for the upcoming epoch boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCommitteePlan {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub old_committee: Vec<ValidatorId>,
    pub old_bft: BftParams,
    /// Surviving non-ejected validators from `old_committee` that will execute resharing.
    pub reshare_quorum: Vec<ValidatorId>,
    pub ejected_validators: Vec<ValidatorId>,
    pub admitted_validators: Vec<ValidatorId>,
    pub new_committee: Vec<ValidatorId>,
    pub new_bft: BftParams,
}

/// Receipt emitted after executing an atomic epoch transition + zero-reconstruction reshare.
#[derive(Debug)]
pub struct EpochTransitionReceipt {
    pub plan: EpochCommitteePlan,
    pub reshare: BatchRedistributionResult,
    pub new_epoch_beacon: u128,
}

/// Zero-admin permissionless committee manager handling candidate Proof-of-Pad trials,
/// quorum endorsements, automatic liveness/Byzantine ejection, and BFT threshold adaptation.
///
/// Contains ZERO admin keys, founder addresses, or privileged override paths.
#[derive(Debug)]
pub struct DynamicCommitteeManager {
    epoch: u64,
    epoch_beacon: u128,
    max_missed_epochs: u64,
    max_committee_size: usize,
    committee: Vec<ValidatorId>,
    statuses: BTreeMap<ValidatorId, ValidatorStatus>,
    missed_epoch_counts: BTreeMap<ValidatorId, u64>,
    pending_trials: BTreeMap<ValidatorId, (CandidateTrial, u128)>,
    trial_endorsements: BTreeMap<ValidatorId, BTreeSet<ValidatorId>>,
    admitted_queue: Vec<ValidatorId>,
}

impl DynamicCommitteeManager {
    /// Initialize a zero-admin committee manager from genesis validator IDs (`len >= 4`).
    pub fn new(
        initial_committee: Vec<ValidatorId>,
        max_missed_epochs: u64,
        max_committee_size: usize,
    ) -> Result<Self, DynamicQuorumError> {
        let bft = compute_bft_params(initial_committee.len())?;
        validate_coordinates(&initial_committee)?;
        if max_missed_epochs == 0 {
            return Err(DynamicQuorumError::InvalidConfig(
                "max_missed_epochs must be >= 1",
            ));
        }
        if max_committee_size < bft.committee_size {
            return Err(DynamicQuorumError::InvalidConfig(
                "max_committee_size must be >= initial committee size",
            ));
        }

        let mut committee = initial_committee;
        committee.sort_unstable();

        let mut statuses = BTreeMap::new();
        let mut missed_epoch_counts = BTreeMap::new();
        for &vid in &committee {
            statuses.insert(vid, ValidatorStatus::Active);
            missed_epoch_counts.insert(vid, 0);
        }

        let seed = random_nonzero_field_elem();
        let epoch_beacon = derive_next_epoch_beacon(seed, 0, &committee);

        Ok(Self {
            epoch: 0,
            epoch_beacon,
            max_missed_epochs,
            max_committee_size,
            committee,
            statuses,
            missed_epoch_counts,
            pending_trials: BTreeMap::new(),
            trial_endorsements: BTreeMap::new(),
            admitted_queue: Vec::new(),
        })
    }

    /// Current epoch number.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Current public epoch randomness beacon used to challenge Proof-of-Pad trials.
    pub fn epoch_beacon(&self) -> u128 {
        self.epoch_beacon
    }

    /// Active committee members (sorted by `ValidatorId`).
    pub fn committee(&self) -> &[ValidatorId] {
        &self.committee
    }

    /// Current BFT threshold parameters `(t, N, f)`.
    pub fn bft_params(&self) -> BftParams {
        compute_bft_params(self.committee.len()).expect("active committee always satisfies N >= 4")
    }

    /// Strict per-epoch ejection/replacement churn limit (`f_old.max(1)`).
    pub fn max_churn_per_epoch(&self) -> usize {
        max_churn_per_epoch(self.bft_params())
    }

    /// Candidates that passed Proof-of-Pad trial + quorum endorsement and await next epoch.
    pub fn admitted_candidates(&self) -> &[ValidatorId] {
        &self.admitted_queue
    }

    /// Query the lifecycle status of any validator.
    pub fn validator_status(&self, id: ValidatorId) -> Option<&ValidatorStatus> {
        self.statuses.get(&id)
    }

    /// Validate a candidate's Proof-of-Pad trial against the current epoch beacon and thresholds.
    pub fn validate_trial(&self, trial: &CandidateTrial) -> Result<(), DynamicQuorumError> {
        if trial.candidate_id == 0 {
            return Err(DynamicQuorumError::InvalidValidatorCoordinate(0));
        }
        if let Some(status) = self.statuses.get(&trial.candidate_id) {
            return match status {
                ValidatorStatus::Ejected { .. } => {
                    Err(DynamicQuorumError::ValidatorAlreadySlashed(trial.candidate_id))
                }
                _ => Err(DynamicQuorumError::DuplicateCandidate(trial.candidate_id)),
            };
        }
        if self.pending_trials.contains_key(&trial.candidate_id)
            || self.admitted_queue.contains(&trial.candidate_id)
        {
            return Err(DynamicQuorumError::DuplicateCandidate(trial.candidate_id));
        }
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(DynamicQuorumError::InvalidConfig("epoch counter overflow"))?;
        if trial.target_epoch != next_epoch {
            return Err(DynamicQuorumError::InvalidCandidateTrial(
                "target_epoch must equal current_epoch + 1",
            ));
        }
        if trial.epoch_beacon_challenge >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(
                trial.epoch_beacon_challenge,
            ));
        }
        if trial.beaver_a >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(trial.beaver_a));
        }
        if trial.beaver_b >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(trial.beaver_b));
        }
        if trial.beaver_c >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(trial.beaver_c));
        }
        if trial.challenge_response >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(
                trial.challenge_response,
            ));
        }
        if trial.epoch_beacon_challenge != self.epoch_beacon {
            return Err(DynamicQuorumError::InvalidCandidateTrial(
                "epoch beacon challenge mismatch",
            ));
        }
        if !trial.entropy_z_score.is_finite()
            || trial.entropy_z_score.abs() > MAX_ENTROPY_Z_SCORE
        {
            return Err(DynamicQuorumError::InvalidCandidateTrial(
                "entropy z-score outside [-3.0, +3.0]",
            ));
        }
        if !trial.qber.is_finite() || !(0.0..=MAX_PROOF_OF_PAD_QBER).contains(&trial.qber) {
            return Err(DynamicQuorumError::InvalidCandidateTrial(
                "QBER exceeds 0.11 security bound",
            ));
        }
        if trial.pad_capacity_bytes < MIN_CANDIDATE_PAD_BYTES {
            return Err(DynamicQuorumError::InvalidCandidateTrial(
                "insufficient OTP pad reserve",
            ));
        }
        if !trial.beaver_triple_verified
            || trial.beaver_a == 0
            || trial.beaver_b == 0
            || mul_mod(trial.beaver_a, trial.beaver_b) != trial.beaver_c
        {
            return Err(DynamicQuorumError::InvalidCandidateTrial(
                "Beaver multiplication triple check failed",
            ));
        }
        if trial.challenge_response != trial.expected_challenge_response() {
            return Err(DynamicQuorumError::InvalidCandidateTrial(
                "beacon challenge response mismatch",
            ));
        }
        Ok(())
    }

    /// Permissionlessly submit a candidate's Proof-of-Pad trial for the next epoch.
    /// Returns the trial digest that active validators endorse.
    pub fn submit_candidate_trial(
        &mut self,
        trial: CandidateTrial,
    ) -> Result<u128, DynamicQuorumError> {
        self.validate_trial(&trial)?;
        let digest = trial.digest();
        let cid = trial.candidate_id;
        self.pending_trials.insert(cid, (trial, digest));
        self.trial_endorsements.insert(cid, BTreeSet::new());
        Ok(digest)
    }

    /// Record a Carter-Wegman authenticated endorsement from an active committee validator.
    ///
    /// Automatically promotes the candidate into `admitted_candidates` once `>= threshold`
    /// distinct active validators endorse the trial (returns `Ok(true)` on admission).
    pub fn record_trial_endorsement(
        &mut self,
        endorsement: TrialEndorsement,
        verifier_key: CwMacKey,
    ) -> Result<bool, DynamicQuorumError> {
        if !self.is_active_member(endorsement.endorser) {
            return Err(DynamicQuorumError::ValidatorNotActive(endorsement.endorser));
        }
        let expected_digest = match self.pending_trials.get(&endorsement.candidate_id) {
            Some((_, digest)) => *digest,
            None => {
                return Err(DynamicQuorumError::InvalidCandidateTrial(
                    "no pending trial for candidate",
                ));
            }
        };
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(DynamicQuorumError::InvalidConfig("epoch counter overflow"))?;
        if endorsement.trial_digest >= PRIME_P {
            return Err(DynamicQuorumError::NonCanonicalFieldElement(
                endorsement.trial_digest,
            ));
        }
        if endorsement.target_epoch != next_epoch || endorsement.trial_digest != expected_digest {
            return Err(DynamicQuorumError::InvalidCandidateTrial(
                "endorsement epoch or trial digest mismatch",
            ));
        }
        endorsement.verify(verifier_key)?;

        let threshold = self.bft_params().threshold;
        let set = self
            .trial_endorsements
            .entry(endorsement.candidate_id)
            .or_default();
        set.insert(endorsement.endorser);

        if set.len() >= threshold {
            self.pending_trials.remove(&endorsement.candidate_id);
            self.trial_endorsements.remove(&endorsement.candidate_id);
            if !self.admitted_queue.contains(&endorsement.candidate_id) {
                self.admitted_queue.push(endorsement.candidate_id);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Record validator liveness for the current epoch; validators missing `>= max_missed_epochs`
    /// are automatically scheduled for ejection at the next epoch boundary.
    pub fn record_epoch_liveness(&mut self, participating_validators: &[ValidatorId]) -> Vec<ValidatorId> {
        let present: BTreeSet<ValidatorId> = participating_validators.iter().copied().collect();
        let mut newly_scheduled = Vec::new();

        for &vid in &self.committee {
            if !matches!(self.statuses.get(&vid), Some(ValidatorStatus::Active)) {
                continue;
            }
            if present.contains(&vid) {
                self.missed_epoch_counts.insert(vid, 0);
            } else {
                let count = self.missed_epoch_counts.entry(vid).or_insert(0);
                *count = count.saturating_add(1);
                if *count >= self.max_missed_epochs {
                    self.statuses.insert(
                        vid,
                        ValidatorStatus::ScheduledForEjection {
                            reason: EjectionReason::MissedEpochs {
                                missed: *count,
                                max_allowed: self.max_missed_epochs,
                            },
                        },
                    );
                    newly_scheduled.push(vid);
                }
            }
        }
        newly_scheduled
    }

    /// Schedule a Byzantine validator for automatic slashing and ejection when a quorum
    /// (`>= current_threshold` distinct active validators) attests to the fault.
    pub fn slash_and_schedule_ejection(
        &mut self,
        offender: ValidatorId,
        reason: EjectionReason,
        attesting_validators: &[ValidatorId],
    ) -> Result<(), DynamicQuorumError> {
        if !self.committee.contains(&offender) {
            return Err(DynamicQuorumError::ValidatorNotActive(offender));
        }
        let bft = self.bft_params();
        let max_churn = max_churn_per_epoch(bft);
        let already_scheduled = self
            .committee
            .iter()
            .filter(|&&vid| {
                vid != offender
                    && matches!(
                        self.statuses.get(&vid),
                        Some(ValidatorStatus::ScheduledForEjection { .. })
                    )
            })
            .count();
        if already_scheduled >= max_churn {
            return Err(DynamicQuorumError::ChurnLimitExceeded {
                attempted: already_scheduled + 1,
                max_allowed: max_churn,
            });
        }

        let mut distinct_active = BTreeSet::new();
        for &v in attesting_validators {
            if self.is_active_member(v) && v != offender {
                distinct_active.insert(v);
            }
        }
        if distinct_active.len() < bft.threshold {
            return Err(DynamicQuorumError::InsufficientEndorsements {
                provided: distinct_active.len(),
                required: bft.threshold,
            });
        }

        self.statuses
            .insert(offender, ValidatorStatus::ScheduledForEjection { reason });
        Ok(())
    }

    /// Compute the deterministic committee plan for `epoch + 1`:
    /// - Enforces strict anti-committee-takeover per-epoch churn bounds:
    ///   - At most `max_churn = f_old.max(1)` validators may be ejected in a single epoch.
    ///   - Surviving old committee must satisfy `surviving.len() >= old_bft.threshold`.
    ///   - Newly admitted candidates are capped so that even if all `f_old` old Byzantine
    ///     validators collude with every newly admitted candidate, they remain strictly below
    ///     `new_bft.threshold` (`old_f + admitted < new_t`) AND surviving old validators retain
    ///     strict majority (`surviving.len() > new_N / 2`). Excess queued candidates remain in
    ///     `admitted_queue` for subsequent epochs.
    /// - Verifies strict BFT + Shamir safety (`new_t > new_N / 2`, `new_N >= 3*new_f + 1`,
    ///   `new_t >= 2*new_f + 1`).
    pub fn plan_next_epoch_committee(&self) -> Result<EpochCommitteePlan, DynamicQuorumError> {
        let to_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(DynamicQuorumError::InvalidConfig("epoch counter overflow"))?;
        let old_bft = self.bft_params();
        let max_churn = max_churn_per_epoch(old_bft);
        let mut scheduled_ejections = Vec::new();
        let mut surviving = Vec::new();

        for &vid in &self.committee {
            match self.statuses.get(&vid) {
                Some(ValidatorStatus::ScheduledForEjection { .. }) => {
                    scheduled_ejections.push(vid);
                }
                _ => surviving.push(vid),
            }
        }

        // Anti-committee-takeover churn bound: reject ejecting > f_old.max(1) validators in one epoch.
        if scheduled_ejections.len() > max_churn {
            return Err(DynamicQuorumError::ChurnLimitExceeded {
                attempted: scheduled_ejections.len(),
                max_allowed: max_churn,
            });
        }

        let ejected_validators = scheduled_ejections;
        surviving.sort_unstable();

        // Preserve resharing liveness: at least `old_bft.threshold` old validators must remain.
        if surviving.len() < old_bft.threshold {
            return Err(DynamicQuorumError::InsufficientQuorumForReshare {
                remaining: surviving.len(),
                required: old_bft.threshold,
            });
        }

        let slots_available = self.max_committee_size.saturating_sub(surviving.len());
        let max_candidates = slots_available.min(self.admitted_queue.len());

        // Compute the maximum safe admissions for this epoch such that:
        // 1. Old surviving committee retains strict majority: `surviving.len() > new_N / 2`.
        // 2. Worst-case adversarial coalition (`f_old` old + all `admitted`) stays strictly
        //    below the new threshold: `old_bft.max_faults + admitted < new_bft.threshold`.
        let mut safe_admit_count = 0usize;
        for candidate_count in 0..=max_candidates {
            let candidate_n = surviving.len().saturating_add(candidate_count);
            if let Ok(cand_bft) = compute_bft_params(candidate_n) {
                let old_majority_holds = surviving.len() > candidate_n / 2;
                let takeover_impossible =
                    old_bft.max_faults.saturating_add(candidate_count) < cand_bft.threshold;
                if old_majority_holds && takeover_impossible {
                    safe_admit_count = candidate_count;
                }
            }
        }

        let admitted_validators: Vec<ValidatorId> = self
            .admitted_queue
            .iter()
            .copied()
            .take(safe_admit_count)
            .collect();

        let mut new_committee = surviving.clone();
        new_committee.extend_from_slice(&admitted_validators);
        new_committee.sort_unstable();

        let new_bft = compute_bft_params(new_committee.len())?;
        // Formally assert strict BFT + Shamir safety on the planned committee.
        if new_bft.threshold <= new_committee.len() / 2
            || new_committee.len() < 3 * new_bft.max_faults + 1
            || new_bft.threshold < 2 * new_bft.max_faults + 1
        {
            return Err(DynamicQuorumError::InvalidThreshold {
                threshold: new_bft.threshold,
                committee_size: new_committee.len(),
            });
        }
        let reshare_quorum = surviving[..old_bft.threshold].to_vec();

        Ok(EpochCommitteePlan {
            from_epoch: self.epoch,
            to_epoch,
            old_committee: self.committee.clone(),
            old_bft,
            reshare_quorum,
            ejected_validators,
            admitted_validators,
            new_committee,
            new_bft,
        })
    }

    /// Execute the epoch transition atomically:
    /// 1. Plan the new committee and BFT threshold `(t', N')`.
    /// 2. Run zero-reconstruction `redistribute_ledger_accounts` from `reshare_quorum` to `new_committee`.
    /// 3. Finalize ejections, activate newly admitted candidates, advance epoch, and rotate the beacon.
    pub fn execute_epoch_transition(
        &mut self,
        old_ledger: &BTreeMap<AccountId, Vec<Share>>,
    ) -> Result<EpochTransitionReceipt, DynamicQuorumError> {
        let plan = self.plan_next_epoch_committee()?;

        let reshare = redistribute_ledger_accounts(
            plan.to_epoch,
            old_ledger,
            &plan.reshare_quorum,
            &plan.new_committee,
            plan.new_bft.threshold,
        )?;

        // Commit governance state only AFTER resharing & degree verification succeed 100%.
        for &ejected in &plan.ejected_validators {
            let reason = match self.statuses.get(&ejected) {
                Some(ValidatorStatus::ScheduledForEjection { reason }) => reason.clone(),
                _ => EjectionReason::Equivocation,
            };
            self.statuses.insert(
                ejected,
                ValidatorStatus::Ejected {
                    epoch: plan.to_epoch,
                    reason,
                },
            );
            self.missed_epoch_counts.remove(&ejected);
        }

        let admitted_set: BTreeSet<ValidatorId> = plan.admitted_validators.iter().copied().collect();
        self.admitted_queue.retain(|id| !admitted_set.contains(id));
        for &admitted in &plan.admitted_validators {
            self.statuses.insert(admitted, ValidatorStatus::Active);
            self.missed_epoch_counts.insert(admitted, 0);
        }

        self.epoch = plan.to_epoch;
        self.committee = plan.new_committee.clone();
        self.pending_trials.clear();
        self.trial_endorsements.clear();

        let fresh_entropy = random_nonzero_field_elem();
        self.epoch_beacon = derive_next_epoch_beacon(
            add_mod(self.epoch_beacon, fresh_entropy),
            self.epoch,
            &self.committee,
        );

        Ok(EpochTransitionReceipt {
            plan,
            reshare,
            new_epoch_beacon: self.epoch_beacon,
        })
    }

    fn is_active_member(&self, id: ValidatorId) -> bool {
        self.committee.contains(&id)
            && matches!(self.statuses.get(&id), Some(ValidatorStatus::Active))
    }
}

/// Derive a non-zero epoch randomness beacon in `F_(2^127 - 1)`.
fn derive_next_epoch_beacon(seed: u128, epoch: u64, committee: &[ValidatorId]) -> u128 {
    let mut elems = Vec::with_capacity(2 + committee.len());
    elems.push(epoch as u128);
    elems.push(committee.len() as u128);
    for &vid in committee {
        elems.push(vid as u128);
    }
    let mut r = reduce(seed);
    if r == 0 {
        r = 1;
    }
    let h = poly_universal_hash(r, DOMAIN_EPOCH_BEACON, &elems);
    if h == 0 { 1 } else { h }
}

// ============================================================================
// 3. Epoch State Checkpointing & Automatic History Pruning
// ============================================================================

/// A balance transfer applied inside a finalized block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BalanceTransfer {
    pub from: AccountId,
    pub to: AccountId,
    pub amount: u128,
}

/// A finalized ledger block whose `body_bytes` will be pruned after `retention_epochs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerBlock {
    pub height: u64,
    pub epoch: u64,
    pub proposer: ValidatorId,
    pub prev_state_root: u128,
    pub state_root: u128,
    pub tx_count: u32,
    pub body_bytes: Vec<u8>,
}

/// One validator's Carter-Wegman authentication share over an epoch checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointMacShare {
    pub validator_id: ValidatorId,
    pub cw_tag: u128,
}

/// Compact threshold-authenticated epoch checkpoint anchoring active balances & committee membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCheckpoint {
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub prev_checkpoint_root: u128,
    /// Public universal-hash evaluation point generated at checkpoint finalization.
    pub state_root_r: u128,
    /// Carter-Wegman universal state commitment over active balances + committee + metadata.
    pub state_root: u128,
    pub committee: Vec<ValidatorId>,
    pub threshold: usize,
    pub active_accounts: usize,
    /// At least `threshold` distinct committee validators authenticating this checkpoint.
    pub threshold_macs: Vec<CheckpointMacShare>,
}

impl EpochCheckpoint {
    /// Canonical field-element encoding of this checkpoint for threshold Carter-Wegman MACs.
    pub fn mac_payload(&self) -> Vec<u128> {
        let mut elems = Vec::with_capacity(8 + self.committee.len());
        elems.push(self.epoch as u128);
        elems.push(self.start_height as u128);
        elems.push(self.end_height as u128);
        elems.push(self.prev_checkpoint_root);
        elems.push(self.state_root_r);
        elems.push(self.state_root);
        elems.push(self.threshold as u128);
        elems.push(self.active_accounts as u128);
        for &vid in &self.committee {
            elems.push(vid as u128);
        }
        elems
    }
}

/// Result returned when finalizing a block into `PrunedCheckpointLedger`.
#[derive(Debug, Clone)]
pub struct BlockFinalizationResult {
    pub height: u64,
    pub epoch: u64,
    pub state_root: u128,
    pub checkpoint_created: Option<EpochCheckpoint>,
    pub blocks_pruned_this_step: u64,
}

/// Live storage and pruning telemetry for `PrunedCheckpointLedger`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruningMetrics {
    pub current_height: u64,
    pub completed_epochs: u64,
    pub pruned_blocks: u64,
    pub retained_blocks: usize,
    pub checkpoint_count: usize,
    pub active_account_count: usize,
    pub estimated_state_bytes: usize,
}

/// Compute a canonical universal-polynomial state root over active balances + committee membership.
pub fn compute_checkpoint_state_root(
    r: u128,
    epoch: u64,
    start_height: u64,
    end_height: u64,
    prev_checkpoint_root: u128,
    committee: &[ValidatorId],
    threshold: usize,
    active_balances: &BTreeMap<AccountId, u128>,
) -> u128 {
    let mut elems = Vec::with_capacity(6 + committee.len() + 2 * active_balances.len());
    elems.push(epoch as u128);
    elems.push(start_height as u128);
    elems.push(end_height as u128);
    elems.push(prev_checkpoint_root);
    elems.push(threshold as u128);
    elems.push(committee.len() as u128);
    for &vid in committee {
        elems.push(vid as u128);
    }
    for (&acct, &bal) in active_balances {
        elems.push(acct as u128);
        elems.push(reduce(bal));
    }
    poly_universal_hash(r, DOMAIN_CHECKPOINT_STATE, &elems)
}

/// Compute a canonical universal-polynomial commitment over a secret-shared account ledger
/// (committing to each validator's share coordinate + share value without reconstructing secrets).
pub fn compute_secret_shared_ledger_root(
    r: u128,
    epoch: u64,
    committee: &[ValidatorId],
    threshold: usize,
    ledger: &BTreeMap<AccountId, Vec<Share>>,
) -> u128 {
    let mut elems = Vec::with_capacity(4 + committee.len() + ledger.len() * (1 + 2 * committee.len()));
    elems.push(epoch as u128);
    elems.push(threshold as u128);
    elems.push(committee.len() as u128);
    for &vid in committee {
        elems.push(vid as u128);
    }
    for (&acct, shares) in ledger {
        elems.push(acct as u128);
        for s in shares {
            elems.push(s.x as u128);
            elems.push(s.y());
        }
    }
    poly_universal_hash(r, DOMAIN_SECRET_LEDGER_ROOT, &elems)
}

/// Ledger maintaining active account state, threshold-authenticated epoch checkpoints,
/// and automatic pruning of historical block bodies older than `retention_epochs`.
pub struct PrunedCheckpointLedger {
    blocks_per_epoch: u64,
    retention_epochs: u64,
    current_height: u64,
    genesis_root: u128,
    last_state_root: u128,
    committee: Vec<ValidatorId>,
    bft: BftParams,
    active_balances: BTreeMap<AccountId, u128>,
    retained_blocks: BTreeMap<u64, LedgerBlock>,
    checkpoints: Vec<EpochCheckpoint>,
    /// Verifier-side one-time Carter-Wegman MAC keys per `(epoch, validator_id)`.
    /// Volatile-zeroized automatically on `Drop`.
    checkpoint_verifier_keys: BTreeMap<(u64, ValidatorId), CwMacKey>,
    pruned_blocks: u64,
}

impl fmt::Debug for PrunedCheckpointLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrunedCheckpointLedger")
            .field("blocks_per_epoch", &self.blocks_per_epoch)
            .field("retention_epochs", &self.retention_epochs)
            .field("current_height", &self.current_height)
            .field("committee", &self.committee)
            .field("active_accounts", &self.active_balances.len())
            .field("retained_blocks", &self.retained_blocks.len())
            .field("checkpoints", &self.checkpoints.len())
            .field("pruned_blocks", &self.pruned_blocks)
            .field("checkpoint_verifier_keys", &"[REDACTED]")
            .finish()
    }
}

impl PrunedCheckpointLedger {
    /// Create a new pruned checkpoint ledger.
    pub fn new(
        blocks_per_epoch: u64,
        retention_epochs: u64,
        mut initial_committee: Vec<ValidatorId>,
        initial_balances: BTreeMap<AccountId, u128>,
    ) -> Result<Self, DynamicQuorumError> {
        if blocks_per_epoch == 0 {
            return Err(DynamicQuorumError::InvalidConfig(
                "blocks_per_epoch must be >= 1",
            ));
        }
        let bft = compute_bft_params(initial_committee.len())?;
        validate_coordinates(&initial_committee)?;
        for &bal in initial_balances.values() {
            if bal >= PRIME_P {
                return Err(DynamicQuorumError::NonCanonicalFieldElement(bal));
            }
        }
        initial_committee.sort_unstable();

        let genesis_r = random_nonzero_field_elem();
        let genesis_root = compute_checkpoint_state_root(
            genesis_r,
            0,
            0,
            0,
            0,
            &initial_committee,
            bft.threshold,
            &initial_balances,
        );

        Ok(Self {
            blocks_per_epoch,
            retention_epochs,
            current_height: 0,
            genesis_root,
            last_state_root: genesis_root,
            committee: initial_committee,
            bft,
            active_balances: initial_balances,
            retained_blocks: BTreeMap::new(),
            checkpoints: Vec::new(),
            checkpoint_verifier_keys: BTreeMap::new(),
            pruned_blocks: 0,
        })
    }

    /// Update the active committee (e.g., after an epoch transition / resharing).
    pub fn update_committee(
        &mut self,
        mut new_committee: Vec<ValidatorId>,
    ) -> Result<BftParams, DynamicQuorumError> {
        let bft = compute_bft_params(new_committee.len())?;
        validate_coordinates(&new_committee)?;
        new_committee.sort_unstable();
        self.committee = new_committee;
        self.bft = bft;
        Ok(bft)
    }

    /// Finalize the next block, apply transfers to active balances, and on epoch boundaries
    /// emit a Carter-Wegman threshold-authenticated checkpoint + prune expired block bodies.
    pub fn finalize_block(
        &mut self,
        proposer: ValidatorId,
        transfers: &[BalanceTransfer],
        body_bytes: Vec<u8>,
    ) -> Result<BlockFinalizationResult, DynamicQuorumError> {
        if !self.committee.contains(&proposer) {
            return Err(DynamicQuorumError::ValidatorNotActive(proposer));
        }

        // Validate transfers on a staged balance snapshot first so errors never mutate state.
        let mut staged: BTreeMap<AccountId, u128> = BTreeMap::new();
        for tx in transfers {
            let from_bal = *staged
                .entry(tx.from)
                .or_insert_with(|| *self.active_balances.get(&tx.from).unwrap_or(&0));
            if from_bal < tx.amount {
                return Err(DynamicQuorumError::InsufficientBalance {
                    account: tx.from,
                    available: from_bal,
                    requested: tx.amount,
                });
            }
            let new_from = from_bal - tx.amount;
            staged.insert(tx.from, new_from);

            let to_bal = *staged
                .entry(tx.to)
                .or_insert_with(|| *self.active_balances.get(&tx.to).unwrap_or(&0));
            let new_to = to_bal
                .checked_add(tx.amount)
                .filter(|&v| v < PRIME_P)
                .ok_or(DynamicQuorumError::InvalidConfig(
                    "balance overflow modulo PRIME_P",
                ))?;
            staged.insert(tx.to, new_to);
        }

        let height = self
            .current_height
            .checked_add(1)
            .ok_or(DynamicQuorumError::InvalidConfig("block height overflow"))?;
        let tx_count = u32::try_from(transfers.len())
            .map_err(|_| DynamicQuorumError::InvalidConfig("transfer count exceeds u32::MAX"))?;

        // Commit staged balances only after all pre-checks (including height/tx_count) succeed.
        for (acct, bal) in staged {
            self.active_balances.insert(acct, bal);
        }

        let epoch = (height - 1) / self.blocks_per_epoch;
        let prev_state_root = self.last_state_root;
        let body_hash = poly_universal_hash_bytes(
            if prev_state_root == 0 { 1 } else { prev_state_root },
            DOMAIN_BLOCK_STATE_ROOT,
            &body_bytes,
        );
        let state_root = poly_universal_hash(
            if prev_state_root == 0 { 1 } else { prev_state_root },
            DOMAIN_BLOCK_STATE_ROOT,
            &[
                height as u128,
                epoch as u128,
                proposer as u128,
                transfers.len() as u128,
                body_hash,
                self.active_balances.len() as u128,
            ],
        );

        let block = LedgerBlock {
            height,
            epoch,
            proposer,
            prev_state_root,
            state_root,
            tx_count,
            body_bytes,
        };
        self.retained_blocks.insert(height, block);
        self.current_height = height;
        self.last_state_root = state_root;

        let mut checkpoint_created = None;
        let mut blocks_pruned_this_step = 0u64;

        if height % self.blocks_per_epoch == 0 {
            let start_height = epoch
                .checked_mul(self.blocks_per_epoch)
                .and_then(|v| v.checked_add(1))
                .ok_or(DynamicQuorumError::InvalidConfig(
                    "checkpoint start_height overflow",
                ))?;
            let end_height = height;
            let prev_checkpoint_root = self
                .checkpoints
                .last()
                .map(|c| c.state_root)
                .unwrap_or(self.genesis_root);
            let state_root_r = random_nonzero_field_elem();
            let cp_state_root = compute_checkpoint_state_root(
                state_root_r,
                epoch,
                start_height,
                end_height,
                prev_checkpoint_root,
                &self.committee,
                self.bft.threshold,
                &self.active_balances,
            );

            let mut checkpoint = EpochCheckpoint {
                epoch,
                start_height,
                end_height,
                prev_checkpoint_root,
                state_root_r,
                state_root: cp_state_root,
                committee: self.committee.clone(),
                threshold: self.bft.threshold,
                active_accounts: self.active_balances.len(),
                threshold_macs: Vec::with_capacity(self.bft.threshold),
            };

            let payload = checkpoint.mac_payload();
            for &vid in self.committee.iter().take(self.bft.threshold) {
                let (signer_key, verifier_key) = CwMacKey::generate_pair();
                let cw_tag = signer_key.mac_elems(DOMAIN_CHECKPOINT_MAC, &payload);
                checkpoint.threshold_macs.push(CheckpointMacShare {
                    validator_id: vid,
                    cw_tag,
                });
                self.checkpoint_verifier_keys.insert((epoch, vid), verifier_key);
            }

            self.checkpoints.push(checkpoint.clone());
            checkpoint_created = Some(checkpoint);

            // Automatic history pruning: retain only blocks from the latest `retention_epochs` epochs.
            let cutoff_epoch = epoch.saturating_add(1).saturating_sub(self.retention_epochs);
            let expired_heights: Vec<u64> = self
                .retained_blocks
                .iter()
                .filter(|(_, blk)| blk.epoch < cutoff_epoch)
                .map(|(&h, _)| h)
                .collect();
            for h in expired_heights {
                self.retained_blocks.remove(&h);
                blocks_pruned_this_step = blocks_pruned_this_step.saturating_add(1);
            }
            self.pruned_blocks = self.pruned_blocks.saturating_add(blocks_pruned_this_step);
        }

        Ok(BlockFinalizationResult {
            height,
            epoch,
            state_root,
            checkpoint_created,
            blocks_pruned_this_step,
        })
    }

    /// Read an active account's current balance.
    pub fn balance_of(&self, account: AccountId) -> u128 {
        *self.active_balances.get(&account).unwrap_or(&0)
    }

    /// Immutable view of all active balances.
    pub fn active_balances(&self) -> &BTreeMap<AccountId, u128> {
        &self.active_balances
    }

    /// Immutable view of retained (non-pruned) blocks.
    pub fn retained_blocks(&self) -> &BTreeMap<u64, LedgerBlock> {
        &self.retained_blocks
    }

    /// Immutable view of the compact epoch checkpoint chain.
    pub fn checkpoints(&self) -> &[EpochCheckpoint] {
        &self.checkpoints
    }

    /// Verify the entire checkpoint chain from genesis to tip, including:
    /// - Contiguous epoch numbers and block height ranges
    /// - Cryptographic chaining (`prev_checkpoint_root == prior.state_root`)
    /// - Valid BFT threshold and distinct committee validator signers
    /// - Constant-time Carter-Wegman MAC verification on all `>= threshold` validator shares
    pub fn verify_checkpoint_chain(&self) -> Result<(), DynamicQuorumError> {
        let mut expected_prev_root = self.genesis_root;
        for (idx, cp) in self.checkpoints.iter().enumerate() {
            let expected_epoch = idx as u64;
            if cp.epoch != expected_epoch {
                return Err(DynamicQuorumError::CheckpointVerificationFailed(
                    "non-sequential checkpoint epoch",
                ));
            }
            let expected_start = expected_epoch
                .checked_mul(self.blocks_per_epoch)
                .and_then(|v| v.checked_add(1))
                .ok_or(DynamicQuorumError::CheckpointVerificationFailed(
                    "checkpoint start height overflow",
                ))?;
            let expected_end = expected_epoch
                .checked_add(1)
                .and_then(|e| e.checked_mul(self.blocks_per_epoch))
                .ok_or(DynamicQuorumError::CheckpointVerificationFailed(
                    "checkpoint end height overflow",
                ))?;
            if cp.start_height != expected_start || cp.end_height != expected_end {
                return Err(DynamicQuorumError::CheckpointVerificationFailed(
                    "checkpoint height span mismatch",
                ));
            }
            if cp.prev_checkpoint_root >= PRIME_P
                || cp.state_root_r >= PRIME_P
                || cp.state_root >= PRIME_P
            {
                return Err(DynamicQuorumError::CheckpointVerificationFailed(
                    "non-canonical field element in checkpoint",
                ));
            }
            if cp.prev_checkpoint_root != expected_prev_root {
                return Err(DynamicQuorumError::CheckpointVerificationFailed(
                    "broken checkpoint chain link",
                ));
            }
            validate_coordinates(&cp.committee)?;
            let bft = compute_bft_params(cp.committee.len())?;
            if cp.threshold < bft.threshold || cp.threshold > cp.committee.len() {
                return Err(DynamicQuorumError::CheckpointVerificationFailed(
                    "checkpoint threshold below BFT safety bound",
                ));
            }

            let payload = cp.mac_payload();
            let mut valid_signers = BTreeSet::new();
            for mac_share in &cp.threshold_macs {
                if !cp.committee.contains(&mac_share.validator_id) {
                    return Err(DynamicQuorumError::CheckpointVerificationFailed(
                        "checkpoint MAC signer not in epoch committee",
                    ));
                }
                let verifier_key = self
                    .checkpoint_verifier_keys
                    .get(&(cp.epoch, mac_share.validator_id))
                    .ok_or(DynamicQuorumError::CheckpointVerificationFailed(
                        "missing verifier MAC key for checkpoint signer",
                    ))?;
                verifier_key.verify_elems_ref(
                    DOMAIN_CHECKPOINT_MAC,
                    &payload,
                    mac_share.cw_tag,
                    "epoch_checkpoint",
                )?;
                valid_signers.insert(mac_share.validator_id);
            }
            if valid_signers.len() < cp.threshold {
                return Err(DynamicQuorumError::CheckpointVerificationFailed(
                    "insufficient valid threshold MAC shares on checkpoint",
                ));
            }

            expected_prev_root = cp.state_root;
        }
        Ok(())
    }

    /// Recompute the state root from live `active_balances` + active `committee` and verify exact
    /// equality against the latest epoch checkpoint (valid when called right after an epoch boundary).
    pub fn verify_active_state_against_latest_checkpoint(&self) -> Result<(), DynamicQuorumError> {
        let latest = self.checkpoints.last().ok_or(
            DynamicQuorumError::CheckpointVerificationFailed("no checkpoints finalized yet"),
        )?;
        let recomputed = compute_checkpoint_state_root(
            latest.state_root_r,
            latest.epoch,
            latest.start_height,
            latest.end_height,
            latest.prev_checkpoint_root,
            &latest.committee,
            latest.threshold,
            &self.active_balances,
        );
        if recomputed != latest.state_root {
            return Err(DynamicQuorumError::CheckpointVerificationFailed(
                "live active state root does not match latest checkpoint",
            ));
        }
        Ok(())
    }

    /// Report live pruning telemetry and estimated steady-state disk footprint in bytes.
    pub fn metrics(&self) -> PruningMetrics {
        // Active state: ~40 bytes per (AccountId, u128) B-tree entry.
        let active_state_bytes = self.active_balances.len().saturating_mul(40);
        // Retained blocks: 72-byte header + full body payload.
        let retained_blocks_bytes: usize = self
            .retained_blocks
            .values()
            .fold(0usize, |acc, b| {
                acc.saturating_add(72usize.saturating_add(b.body_bytes.len()))
            });
        // Compact checkpoints: 96-byte fixed metadata + 8 B per committee member + 24 B per MAC share.
        let checkpoints_bytes: usize = self.checkpoints.iter().fold(0usize, |acc, cp| {
            let entry = 96usize
                .saturating_add(cp.committee.len().saturating_mul(8))
                .saturating_add(cp.threshold_macs.len().saturating_mul(24));
            acc.saturating_add(entry)
        });

        PruningMetrics {
            current_height: self.current_height,
            completed_epochs: self.checkpoints.len() as u64,
            pruned_blocks: self.pruned_blocks,
            retained_blocks: self.retained_blocks.len(),
            checkpoint_count: self.checkpoints.len(),
            active_account_count: self.active_balances.len(),
            estimated_state_bytes: active_state_bytes
                .saturating_add(retained_blocks_bytes)
                .saturating_add(checkpoints_bytes),
        }
    }
}

// ============================================================================
// Comprehensive Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bft_threshold_adaptation() {
        assert!(compute_bft_params(3).is_err());

        let p4 = compute_bft_params(4).unwrap();
        assert_eq!(p4, BftParams { committee_size: 4, max_faults: 1, threshold: 3 });

        let p7 = compute_bft_params(7).unwrap();
        assert_eq!(p7, BftParams { committee_size: 7, max_faults: 2, threshold: 5 });

        let p10 = compute_bft_params(10).unwrap();
        assert_eq!(p10, BftParams { committee_size: 10, max_faults: 3, threshold: 7 });
    }

    #[test]
    fn test_redacted_debug_never_leaks_secrets() {
        let secret_val = 0x1234_5678_9ABC_DEF0_1122_3344_5566_7788u128 & PRIME_P;
        let share = Share::new(1, secret_val).unwrap();
        let share_dbg = format!("{share:?}");
        assert!(share_dbg.contains("[REDACTED]"));
        assert!(!share_dbg.contains(&secret_val.to_string()));

        let (k1, _k2) = PairwiseOtpKey::generate_pair();
        let key_dbg = format!("{k1:?}");
        assert!(key_dbg.contains("[REDACTED]"));

        let (bk1, _bk2) = BatchOtpKey::generate_pair(4);
        let bkey_dbg = format!("{bk1:?}");
        assert!(bkey_dbg.contains("[REDACTED]"));

        let sub = SubSharePlaintext::new(1, 2, 42, secret_val);
        let sub_dbg = format!("{sub:?}");
        assert!(sub_dbg.contains("[REDACTED]"));
        assert!(!sub_dbg.contains(&secret_val.to_string()));
    }

    #[test]
    fn test_live_committee_scaling_4_to_7() {
        // 64 secret-shared user balances on initial (t=3, N=4) committee {1, 2, 3, 4}
        let old_committee = vec![1, 2, 3, 4];
        let old_bft = compute_bft_params(old_committee.len()).unwrap();
        assert_eq!(old_bft.threshold, 3);

        let new_committee = vec![1, 2, 3, 4, 5, 6, 7];
        let new_bft = compute_bft_params(new_committee.len()).unwrap();
        assert_eq!(new_bft.threshold, 5);

        let mut true_balances: BTreeMap<AccountId, u128> = BTreeMap::new();
        let mut old_ledger: BTreeMap<AccountId, Vec<Share>> = BTreeMap::new();

        for acct in 1..=64u64 {
            let bal = (acct as u128) * 1_000_000_007 + 99_991;
            true_balances.insert(acct, bal);
            let shares = split_secret(bal, old_bft.threshold, &old_committee).unwrap();
            assert!(verify_committee_shares(&shares, old_bft.threshold).unwrap().is_consistent);
            old_ledger.insert(acct, shares);
        }

        // Honest quorum of 3 old validators {1, 2, 3} redistributes to 7 new validators (t'=5, N'=7).
        let old_quorum = vec![1, 2, 3];
        let result = redistribute_ledger_accounts(
            1,
            &old_ledger,
            &old_quorum,
            &new_committee,
            new_bft.threshold,
        )
        .expect("4 -> 7 batch redistribution must succeed");

        assert_eq!(result.verified_accounts, 64);
        assert_eq!(result.new_threshold, 5);
        assert_eq!(result.envelopes_processed, 3 * 7);
        assert!(result.otp_bytes_consumed > 0);

        // 1. Verify EVERY single balance reconstructs identically from ANY 5-of-7 new shares!
        let five_of_seven_subsets = generate_combinations(7, 5, 25); // C(7,5) = 21 total subsets!
        assert_eq!(five_of_seven_subsets.len(), 21);

        for (&acct, &expected_bal) in &true_balances {
            let new_shares = &result.redistributed_accounts[&acct];
            assert_eq!(new_shares.len(), 7);
            assert!(verify_committee_shares(new_shares, 5).unwrap().is_consistent);

            for subset in &five_of_seven_subsets {
                let picked: Vec<Share> = subset.iter().map(|&i| new_shares[i].clone()).collect();
                let recovered = reconstruct_secret(&picked, 5).unwrap();
                assert_eq!(
                    recovered, expected_bal,
                    "account {acct} failed exact reconstruction on subset {subset:?}"
                );
            }

            // 2. Any 4-of-7 new shares yield garbage (not equal to the true balance)!
            let four_shares: Vec<Share> = new_shares[0..4].to_vec();
            let under_threshold_val = interpolate_at_zero(&four_shares).unwrap();
            assert_ne!(
                under_threshold_val, expected_bal,
                "4-of-7 shares unexpectedly reconstructed account {acct}"
            );

            // 3. Mixing old shares with new shares yields garbage!
            let old_shares = &old_ledger[&acct];
            let mixed_5 = vec![
                old_shares[0].clone(), // old V1
                old_shares[1].clone(), // old V2
                new_shares[2].clone(), // new V3
                new_shares[4].clone(), // new V5
                new_shares[6].clone(), // new V7
            ];
            let mixed_recovered = reconstruct_secret(&mixed_5, 5).unwrap();
            assert_ne!(
                mixed_recovered, expected_bal,
                "mixing old + new shares unexpectedly reconstructed account {acct}"
            );
            // Consistency check also flags mixed old+new shares as inconsistent!
            let mixed_all = vec![
                old_shares[0].clone(),
                new_shares[1].clone(),
                new_shares[2].clone(),
                new_shares[3].clone(),
                new_shares[4].clone(),
                new_shares[5].clone(),
                new_shares[6].clone(),
            ];
            let mixed_report = verify_committee_shares(&mixed_all, 5).unwrap();
            assert!(!mixed_report.is_consistent);
            assert_eq!(mixed_report.suspected_validators, vec![1]);
        }

        println!(
            "[PASS] 4 -> 7 live scaling: 64 accounts verified across all 21 5-of-7 subsets, \
             4-of-7 yields garbage, mixed old+new yields garbage ({} OTP bytes consumed)",
            result.otp_bytes_consumed
        );
    }

    #[test]
    fn test_byzantine_fault_replacement_4_to_4_zero_admin() {
        // Initial committee {V1, V2, V3, V4} (representing V0..V3 with non-zero x-coords 1..=4).
        // Compromised validator is V4 (4th seat); verified candidate is V5.
        let mut manager = DynamicCommitteeManager::new(vec![1, 2, 3, 4], 2, 10).unwrap();
        assert_eq!(manager.bft_params(), BftParams { committee_size: 4, max_faults: 1, threshold: 3 });

        // Secret-share 32 user balances across {1, 2, 3, 4}.
        let mut true_balances = BTreeMap::new();
        let mut ledger = BTreeMap::new();
        for acct in 100..132u64 {
            let bal = (acct as u128) * 555_555 + 12_345;
            true_balances.insert(acct, bal);
            ledger.insert(acct, split_secret(bal, 3, manager.committee()).unwrap());
        }

        // Capture compromised V4's stolen old shares before ejection.
        let stolen_v4_shares: BTreeMap<AccountId, Share> = ledger
            .iter()
            .map(|(&acct, shares)| (acct, shares.iter().find(|s| s.x == 4).unwrap().clone()))
            .collect();

        // Step 1: Reject a bad Proof-of-Pad candidate (QBER > 0.11).
        let bad_trial = CandidateTrial::generate_passing(
            99,
            1,
            manager.epoch_beacon(),
            0.5,
            0.15, // QBER too high!
            2 * 1024 * 1024,
        );
        assert!(manager.submit_candidate_trial(bad_trial).is_err());

        // Step 2: Candidate V5 submits a valid Proof-of-Pad trial challenged by epoch beacon.
        let good_trial = CandidateTrial::generate_passing(
            5,
            1,
            manager.epoch_beacon(),
            0.42,
            0.045,
            4 * 1024 * 1024,
        );
        let digest = manager.submit_candidate_trial(good_trial).unwrap();

        // Step 3: Quorum of 3 honest active validators {1, 2, 3} endorse V5 using one-time CW-MACs.
        for (idx, &endorser) in [1u64, 2, 3].iter().enumerate() {
            let (s_key, v_key) = CwMacKey::generate_pair();
            let endorsement = TrialEndorsement::sign(endorser, 5, 1, digest, s_key);
            let admitted = manager.record_trial_endorsement(endorsement, v_key).unwrap();
            assert_eq!(admitted, idx == 2, "candidate must be admitted on the 3rd endorsement");
        }
        assert_eq!(manager.admitted_candidates(), &[5]);

        // Step 4: Quorum {1, 2, 3} slashes & schedules compromised V4 for ejection (zero admin keys!).
        manager
            .slash_and_schedule_ejection(4, EjectionReason::Equivocation, &[1, 2, 3])
            .unwrap();

        // Step 5: Execute atomic epoch transition + zero-reconstruction redistribution {1,2,3} -> {1,2,3,5}.
        let receipt = manager.execute_epoch_transition(&ledger).unwrap();
        assert_eq!(receipt.plan.ejected_validators, vec![4]);
        assert_eq!(receipt.plan.admitted_validators, vec![5]);
        assert_eq!(receipt.plan.new_committee, vec![1, 2, 3, 5]);
        assert_eq!(receipt.plan.new_bft.threshold, 3);
        assert_eq!(manager.committee(), &[1, 2, 3, 5]);
        assert_eq!(manager.epoch(), 1);
        assert!(matches!(
            manager.validator_status(4),
            Some(ValidatorStatus::Ejected { epoch: 1, reason: EjectionReason::Equivocation })
        ));

        // Step 6: Verify all 32 balances reconstruct identically on {1, 2, 3, 5}, while V4's old shares are worthless!
        let new_ledger = &receipt.reshare.redistributed_accounts;
        for (&acct, &expected_bal) in &true_balances {
            let new_shares = &new_ledger[&acct];
            assert_eq!(new_shares.len(), 4);
            assert!(verify_committee_shares(new_shares, 3).unwrap().is_consistent);

            // Any 3-of-4 from {1, 2, 3, 5} recovers exact balance.
            for combo in generate_combinations(4, 3, 10) {
                let picked: Vec<Share> = combo.iter().map(|&i| new_shares[i].clone()).collect();
                assert_eq!(reconstruct_secret(&picked, 3).unwrap(), expected_bal);
            }

            // V4 combining its stolen old share with 2 new shares (e.g. V1, V2) gets pure garbage!
            let forged_attempt = vec![
                stolen_v4_shares[&acct].clone(),
                new_shares[0].clone(),
                new_shares[1].clone(),
            ];
            let bogus = reconstruct_secret(&forged_attempt, 3).unwrap();
            assert_ne!(
                bogus, expected_bal,
                "ejected V4's old share must be completely incompatible with new epoch shares"
            );
        }

        println!(
            "[PASS] 4 -> 4 Byzantine replacement: V4 ejected, V5 admitted via zero-admin Proof-of-Pad + quorum, \
             32 accounts exact on {{1,2,3,5}}, V4 stolen shares worthless"
        );
    }

    #[test]
    fn test_tampered_subshare_and_mac_detection() {
        let old_committee = vec![1, 2, 3, 4];
        let new_committee = vec![1, 2, 3, 4, 5, 6, 7];
        let old_quorum = vec![1, 2, 3];
        let new_threshold = 5;

        let secret = 777_777_777_777u128;
        let old_shares = split_secret(secret, 3, &old_committee).unwrap();
        let old_quorum_shares = &old_shares[0..3];
        let old_lambdas = lagrange_coeffs_at_zero(&old_quorum).unwrap();

        // Part A: Wire-level tampering of OTP envelope ciphertext is caught immediately by CW-MAC.
        let (s_key, r_key) = PairwiseOtpKey::generate_pair();
        let mut env = encrypt_subshare(1, 42, 1, 5, 12345, s_key);
        env.ciphertext = add_mod(env.ciphertext, 1); // 1-bit/1-unit tamper in transit
        assert!(matches!(
            decrypt_subshare(&env, r_key),
            Err(DynamicQuorumError::MacVerificationFailed { .. })
        ));

        // Part B: Malicious old dealer V2 sends a valid-MAC but algebraically corrupted sub-share
        // to new validator V6 (violating degree-(t'-1) consistency).
        let mut subshare_matrix: BTreeMap<(ValidatorId, ValidatorId), u128> = BTreeMap::new();
        let mut per_new_inbox: Vec<Vec<(OtpSubShareEnvelope, PairwiseOtpKey)>> =
            (0..new_committee.len()).map(|_| Vec::new()).collect();

        for old_share in old_quorum_shares {
            let poly = SecretPolynomial::random_with_constant(old_share.y(), new_threshold);
            for (j, &new_vid) in new_committee.iter().enumerate() {
                let mut sub_val = poly.eval(new_vid);
                if old_share.x == 2 && new_vid == 6 {
                    // Malicious dealer V2 injects +1337 fault into sub-share destined for V6!
                    sub_val = add_mod(sub_val, 1337);
                }
                subshare_matrix.insert((old_share.x, new_vid), sub_val);
                let (sk, rk) = PairwiseOtpKey::generate_pair();
                let e = encrypt_subshare(1, 42, old_share.x, new_vid, sub_val, sk);
                per_new_inbox[j].push((e, rk));
            }
        }

        let mut new_shares = Vec::with_capacity(new_committee.len());
        for (j, inbox) in per_new_inbox.into_iter().enumerate() {
            new_shares.push(
                combine_incoming_subshares(new_committee[j], &old_quorum, &old_lambdas, inbox)
                    .unwrap(),
            );
        }

        // Degree-(t'-1) consistency check MUST catch the corrupted final share AND localize V6!
        let report = verify_committee_shares(&new_shares, new_threshold).unwrap();
        assert!(!report.is_consistent);
        assert!(report.failing_checks > 0);
        assert_eq!(report.suspected_validators, vec![6]);

        // Sub-share dealer audit MUST pinpoint malicious old dealer V2 and target V6!
        let audit = verify_subshare_matrix(
            &old_quorum,
            &new_committee,
            new_threshold,
            &subshare_matrix,
        )
        .unwrap();
        assert!(!audit.all_dealers_honest);
        assert_eq!(audit.malicious_dealers, vec![2]);
        assert_eq!(audit.corrupted_targets_by_dealer.get(&2), Some(&vec![6]));

        println!(
            "[PASS] Tampered sub-share detection: CW-MAC caught wire tamper; \
             degree-(t'-1) check localized corrupted target {:?} and dealer audit caught malicious dealer {:?}",
            report.suspected_validators, audit.malicious_dealers
        );
    }

    #[test]
    fn test_epoch_checkpointing_and_automatic_pruning_250_blocks() {
        let committee = vec![1, 2, 3, 4];
        let mut initial_balances = BTreeMap::new();
        for acct in 1..=32u64 {
            initial_balances.insert(acct, 1_000_000u128);
        }
        let initial_total_supply: u128 = initial_balances.values().sum();

        // 50 blocks/epoch, retention = 1 epoch -> over 250 blocks (5 epochs), 200 old blocks pruned, 50 retained.
        let mut ledger = PrunedCheckpointLedger::new(50, 1, committee.clone(), initial_balances)
            .expect("ledger init");

        // Maintain independent ground-truth balance tracker to verify 100% exactness after pruning.
        let mut expected_balances: BTreeMap<AccountId, u128> =
            (1..=32u64).map(|a| (a, 1_000_000u128)).collect();

        let mut checkpoints_seen = 0usize;
        for h in 1..=250u64 {
            let from = ((h - 1) % 32) + 1;
            let to = (h % 32) + 1;
            let amount = (h as u128) * 10 + 7;
            let tx = BalanceTransfer { from, to, amount };

            *expected_balances.get_mut(&from).unwrap() -= amount;
            *expected_balances.get_mut(&to).unwrap() += amount;

            // Simulate realistic 8 KiB historical block bodies (OTP tx envelopes).
            let body = vec![(h & 0xFF) as u8; 8 * 1024];
            let proposer = committee[((h - 1) as usize) % committee.len()];

            let res = ledger.finalize_block(proposer, &[tx], body).unwrap();
            assert_eq!(res.height, h);
            if res.checkpoint_created.is_some() {
                checkpoints_seen += 1;
            }
        }

        assert_eq!(checkpoints_seen, 5);
        let m = ledger.metrics();
        assert_eq!(m.current_height, 250);
        assert_eq!(m.completed_epochs, 5);
        assert_eq!(m.checkpoint_count, 5);
        assert_eq!(m.pruned_blocks, 200);
        assert_eq!(m.retained_blocks, 50);
        assert_eq!(m.active_account_count, 32);
        assert!(
            m.estimated_state_bytes < MAX_STEADY_STATE_BYTES,
            "steady-state footprint {} must remain < 2 GiB",
            m.estimated_state_bytes
        );

        // Verify old blocks 1..=200 are genuinely pruned and 201..=250 are retained.
        assert!(!ledger.retained_blocks().contains_key(&1));
        assert!(!ledger.retained_blocks().contains_key(&200));
        assert!(ledger.retained_blocks().contains_key(&201));
        assert!(ledger.retained_blocks().contains_key(&250));

        // Verify exact conservation of supply & exact per-account active balances.
        let final_total_supply: u128 = ledger.active_balances().values().sum();
        assert_eq!(final_total_supply, initial_total_supply);
        for (&acct, &expected) in &expected_balances {
            assert_eq!(ledger.balance_of(acct), expected);
        }

        // Verify the entire 5-epoch checkpoint chain + Carter-Wegman threshold MACs + live state root!
        ledger
            .verify_checkpoint_chain()
            .expect("all 5 epoch checkpoints and CW threshold MACs must verify");
        ledger
            .verify_active_state_against_latest_checkpoint()
            .expect("live active state must match epoch 4 checkpoint root");

        println!(
            "[PASS] 250-block 5-epoch pruning: pruned={} retained={} checkpoints={} state_bytes={} (< 2 GiB)",
            m.pruned_blocks,
            m.retained_blocks,
            m.checkpoint_count,
            m.estimated_state_bytes
        );
    }

    #[test]
    fn test_liveness_ejection_and_scaling_4_to_7_via_manager() {
        let mut manager = DynamicCommitteeManager::new(vec![1, 2, 3, 4], 2, 10).unwrap();

        // Admit 3 verified Proof-of-Pad candidates {5, 6, 7} to scale 4 -> 7 without admin keys!
        for cid in [5u64, 6, 7] {
            let trial = CandidateTrial::generate_passing(
                cid,
                1,
                manager.epoch_beacon(),
                -0.8,
                0.03,
                2 * 1024 * 1024,
            );
            let digest = manager.submit_candidate_trial(trial).unwrap();
            for &endorser in &[1u64, 2, 3] {
                let (sk, vk) = CwMacKey::generate_pair();
                let end = TrialEndorsement::sign(endorser, cid, 1, digest, sk);
                manager.record_trial_endorsement(end, vk).unwrap();
            }
        }
        assert_eq!(manager.admitted_candidates(), &[5, 6, 7]);

        let mut ledger = BTreeMap::new();
        for acct in 1..=16u64 {
            ledger.insert(acct, split_secret(acct as u128 * 999, 3, manager.committee()).unwrap());
        }

        let receipt = manager.execute_epoch_transition(&ledger).unwrap();
        assert_eq!(manager.committee(), &[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(manager.bft_params(), BftParams { committee_size: 7, max_faults: 2, threshold: 5 });

        // Test automatic liveness ejection when validator 7 misses 2 epochs.
        let scheduled_1 = manager.record_epoch_liveness(&[1, 2, 3, 4, 5, 6]);
        assert!(scheduled_1.is_empty());
        let scheduled_2 = manager.record_epoch_liveness(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(scheduled_2, vec![7]);
        assert!(matches!(
            manager.validator_status(7),
            Some(ValidatorStatus::ScheduledForEjection {
                reason: EjectionReason::MissedEpochs { missed: 2, max_allowed: 2 }
            })
        ));

        // Transition epoch 1 -> 2 ejects offline V7 cleanly (7 -> 6 with t'=3, N'=6).
        let receipt2 = manager
            .execute_epoch_transition(&receipt.reshare.redistributed_accounts)
            .unwrap();
        assert_eq!(receipt2.plan.ejected_validators, vec![7]);
        assert_eq!(manager.committee(), &[1, 2, 3, 4, 5, 6]);
        for acct in 1..=16u64 {
            let shares = &receipt2.reshare.redistributed_accounts[&acct];
            assert_eq!(
                reconstruct_secret(shares, receipt2.plan.new_bft.threshold).unwrap(),
                acct as u128 * 999
            );
        }
    }

    #[test]
    fn test_bft_params_formal_safety_and_liveness_all_sizes() {
        for n in 0..4usize {
            assert!(compute_bft_params(n).is_err());
        }
        // Explicitly verify N=6 has t=4 > 6/2 (preventing disjoint 3+3 quorum split).
        let p6 = compute_bft_params(6).unwrap();
        assert_eq!(
            p6,
            BftParams {
                committee_size: 6,
                max_faults: 1,
                threshold: 4,
            }
        );

        for n in 4..=64usize {
            let p = compute_bft_params(n).unwrap();
            assert_eq!(p.committee_size, n);
            assert!(n >= 3 * p.max_faults + 1, "N={n} must satisfy N >= 3f + 1");
            assert!(
                p.threshold >= 2 * p.max_faults + 1,
                "N={n} must satisfy t >= 2f + 1"
            );
            assert!(
                p.threshold > n / 2,
                "N={n} must satisfy strict Shamir/BFT majority t > N/2"
            );
            assert!(
                2 * p.threshold - n >= p.max_faults + 1,
                "N={n} must guarantee >= f+1 quorum overlap (>= 1 honest node)"
            );
            assert!(
                p.threshold <= n - p.max_faults,
                "N={n} must preserve liveness when f validators are offline"
            );
        }
    }

    #[test]
    fn test_churn_limit_and_anti_committee_takeover_enforcement() {
        // 1. On N=4 (f=1, max_churn=1): scheduling 1 ejection succeeds, 2nd is rejected with ChurnLimitExceeded.
        let mut mgr4 = DynamicCommitteeManager::new(vec![1, 2, 3, 4], 2, 16).unwrap();
        assert_eq!(mgr4.max_churn_per_epoch(), 1);
        mgr4.slash_and_schedule_ejection(4, EjectionReason::Equivocation, &[1, 2, 3])
            .unwrap();
        assert_eq!(
            mgr4.slash_and_schedule_ejection(3, EjectionReason::Equivocation, &[1, 2, 4]),
            Err(DynamicQuorumError::ChurnLimitExceeded {
                attempted: 2,
                max_allowed: 1,
            })
        );

        // 2. On N=6 (f=1, max_churn=1): liveness-scheduling 2 offline validators in one epoch
        //    must be rejected by plan_next_epoch_committee with ChurnLimitExceeded!
        let mut mgr6 = DynamicCommitteeManager::new(vec![1, 2, 3, 4, 5, 6], 1, 16).unwrap();
        assert_eq!(mgr6.max_churn_per_epoch(), 1);
        let sched = mgr6.record_epoch_liveness(&[1, 2, 3, 4]); // 5 & 6 both miss
        assert_eq!(sched, vec![5, 6]);
        assert_eq!(
            mgr6.plan_next_epoch_committee(),
            Err(DynamicQuorumError::ChurnLimitExceeded {
                attempted: 2,
                max_allowed: 1,
            })
        );

        // 3. On N=7 (f=2, max_churn=2): 2 ejections allowed, 3rd rejected with ChurnLimitExceeded!
        let mut mgr7 = DynamicCommitteeManager::new(vec![1, 2, 3, 4, 5, 6, 7], 2, 16).unwrap();
        assert_eq!(mgr7.max_churn_per_epoch(), 2);
        mgr7.slash_and_schedule_ejection(7, EjectionReason::MpcSubShareFault, &[1, 2, 3, 4, 5])
            .unwrap();
        mgr7.slash_and_schedule_ejection(6, EjectionReason::MpcSubShareFault, &[1, 2, 3, 4, 5])
            .unwrap();
        assert_eq!(
            mgr7.slash_and_schedule_ejection(5, EjectionReason::MpcSubShareFault, &[1, 2, 3, 4, 6]),
            Err(DynamicQuorumError::ChurnLimitExceeded {
                attempted: 3,
                max_allowed: 2,
            })
        );

        // 4. Anti-Committee-Takeover Flood: on N=4 (max_committee_size=16), even if 6 candidates
        //    pass Proof-of-Pad in one epoch, the manager MUST cap admissions so the old committee
        //    retains strict majority (> N'/2) and `old_f + admitted < new_t` (no supermajority seizure!).
        let mut takeover_mgr = DynamicCommitteeManager::new(vec![1, 2, 3, 4], 2, 16).unwrap();
        for cid in 5..=10u64 {
            let trial = CandidateTrial::generate_passing(
                cid,
                1,
                takeover_mgr.epoch_beacon(),
                0.2,
                0.02,
                2 * 1024 * 1024,
            );
            let digest = takeover_mgr.submit_candidate_trial(trial).unwrap();
            for &endorser in &[1u64, 2, 3] {
                let (sk, vk) = CwMacKey::generate_pair();
                let end = TrialEndorsement::sign(endorser, cid, 1, digest, sk);
                takeover_mgr.record_trial_endorsement(end, vk).unwrap();
            }
        }
        assert_eq!(takeover_mgr.admitted_candidates().len(), 6);

        let plan = takeover_mgr.plan_next_epoch_committee().unwrap();
        // From surviving=4 (old_f=1), admitting 4+ would violate surviving > N'/2 (4 <= 8/2)
        // or allow takeover; at most 3 can be admitted in epoch 1 (4 -> 7, new_t = 5 > 1 + 3 = 4).
        assert_eq!(plan.admitted_validators, vec![5, 6, 7]);
        assert_eq!(plan.new_committee.len(), 7);
        assert!(plan.old_bft.max_faults + plan.admitted_validators.len() < plan.new_bft.threshold);
        assert!(plan.old_committee.len() > plan.new_committee.len() / 2);

        // Execute transition and confirm remaining 3 candidates stay queued safely for epoch 2!
        let mut ledger = BTreeMap::new();
        ledger.insert(1, split_secret(42_000, 3, takeover_mgr.committee()).unwrap());
        let receipt = takeover_mgr.execute_epoch_transition(&ledger).unwrap();
        assert_eq!(takeover_mgr.committee(), &[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(takeover_mgr.admitted_candidates(), &[8, 9, 10]);
        assert_eq!(
            reconstruct_secret(&receipt.reshare.redistributed_accounts[&1], 5).unwrap(),
            42_000
        );
    }

    #[test]
    fn test_adversarial_non_canonical_prime_p_share_and_mac_injection_rejected() {
        // 1. Share::new rejects >= PRIME_P values (no silent modular reduction).
        assert_eq!(
            Share::new(1, PRIME_P),
            Err(DynamicQuorumError::NonCanonicalFieldElement(PRIME_P))
        );
        assert_eq!(
            Share::new(1, PRIME_P + 42),
            Err(DynamicQuorumError::NonCanonicalFieldElement(PRIME_P + 42))
        );
        assert_eq!(
            Share::new(1, u128::MAX),
            Err(DynamicQuorumError::NonCanonicalFieldElement(u128::MAX))
        );

        // 2. split_secret rejects non-canonical secret >= PRIME_P.
        assert_eq!(
            split_secret(PRIME_P, 3, &[1, 2, 3, 4]),
            Err(DynamicQuorumError::NonCanonicalFieldElement(PRIME_P))
        );

        // 3. verify_subshare_matrix rejects injected non-canonical >= PRIME_P sub-share.
        let mut matrix = BTreeMap::new();
        for &d in &[1u64, 2, 3] {
            for &t in &[1u64, 2, 3, 4] {
                matrix.insert((d, t), if d == 2 && t == 4 { PRIME_P + 1 } else { 7 });
            }
        }
        assert_eq!(
            verify_subshare_matrix(&[1, 2, 3], &[1, 2, 3, 4], 3, &matrix),
            Err(DynamicQuorumError::NonCanonicalFieldElement(PRIME_P + 1))
        );

        // 4. Wire malleability: adding PRIME_P to ciphertext or cw_tag MUST be rejected!
        let (sk1, rk1) = PairwiseOtpKey::generate_pair();
        let mut env_ct = encrypt_subshare(1, 10, 1, 2, 123, sk1);
        env_ct.ciphertext += PRIME_P;
        assert!(matches!(
            decrypt_subshare(&env_ct, rk1),
            Err(DynamicQuorumError::NonCanonicalFieldElement(_))
        ));

        let (sk2, rk2) = PairwiseOtpKey::generate_pair();
        let mut env_tag = encrypt_subshare(1, 10, 1, 2, 123, sk2);
        env_tag.cw_tag += PRIME_P;
        assert!(matches!(
            decrypt_subshare(&env_tag, rk2),
            Err(DynamicQuorumError::NonCanonicalFieldElement(_))
        ));

        // 5. Batch envelope malleability & non-canonical sub-share injection rejected.
        let (bsk, brk) = BatchOtpKey::generate_pair(2);
        assert!(matches!(
            encrypt_subshare_batch(1, 1, 2, vec![1, 2], &[5, PRIME_P], bsk),
            Err(DynamicQuorumError::NonCanonicalFieldElement(_))
        ));
        drop(brk);

        let (bsk2, brk2) = BatchOtpKey::generate_pair(2);
        let mut benv = encrypt_subshare_batch(1, 1, 2, vec![1, 2], &[5, 9], bsk2).unwrap();
        benv.ciphertexts[1] += PRIME_P;
        assert!(matches!(
            decrypt_subshare_batch(&benv, brk2),
            Err(DynamicQuorumError::NonCanonicalFieldElement(_))
        ));

        // 6. CwMacKey rejects tag + PRIME_P malleability directly.
        let (ms, mv) = CwMacKey::generate_pair();
        let tag = ms.mac_bytes(DOMAIN_TRIAL_DIGEST, b"vernam");
        assert!(matches!(
            mv.verify_bytes(DOMAIN_TRIAL_DIGEST, b"vernam", tag + PRIME_P, "malleable_tag"),
            Err(DynamicQuorumError::NonCanonicalFieldElement(_))
        ));

        // 7. CandidateTrial with non-canonical field element rejected.
        let mgr = DynamicCommitteeManager::new(vec![1, 2, 3, 4], 2, 10).unwrap();
        let mut bad_trial = CandidateTrial::generate_passing(
            5,
            1,
            mgr.epoch_beacon(),
            0.1,
            0.01,
            2 * 1024 * 1024,
        );
        bad_trial.beaver_a += PRIME_P;
        assert!(matches!(
            mgr.validate_trial(&bad_trial),
            Err(DynamicQuorumError::NonCanonicalFieldElement(_))
        ));

        // 8. PrunedCheckpointLedger rejects non-canonical >= PRIME_P genesis balance.
        let mut bad_bal = BTreeMap::new();
        bad_bal.insert(1, PRIME_P);
        assert!(matches!(
            PrunedCheckpointLedger::new(10, 1, vec![1, 2, 3, 4], bad_bal),
            Err(DynamicQuorumError::NonCanonicalFieldElement(_))
        ));
    }

    #[test]
    fn test_4d_diversity_matrix_monoculture_rejection_and_acceptance() {
        let bft4 = compute_bft_params(4).unwrap(); // N=4, f=1, t=3

        // 1. Fully diverse 4-OS, 4-ISA, 4-compiler, 4-ASN committee -> ACCEPTED!
        let diverse4 = vec![
            QuorumDiversityProfile {
                os_family: OS_FAMILY_LINUX,
                cpu_isa: CPU_ISA_X86_64,
                compiler_lineage: COMPILER_RUSTC_LLVM,
                asn: 64501,
                geo_cell_id: 10,
            },
            QuorumDiversityProfile {
                os_family: OS_FAMILY_FREEBSD,
                cpu_isa: CPU_ISA_AARCH64,
                compiler_lineage: COMPILER_RUSTC_CRANELIFT,
                asn: 64502,
                geo_cell_id: 20,
            },
            QuorumDiversityProfile {
                os_family: OS_FAMILY_OPENBSD,
                cpu_isa: CPU_ISA_RISCV64,
                compiler_lineage: COMPILER_GCCRS,
                asn: 64503,
                geo_cell_id: 30,
            },
            QuorumDiversityProfile {
                os_family: OS_FAMILY_MACOS,
                cpu_isa: CPU_ISA_POWERPC64,
                compiler_lineage: COMPILER_MRUSTC,
                asn: 64504,
                geo_cell_id: 40,
            },
        ];
        validate_committee_diversity(&diverse4, bft4)
            .expect("diverse 4-OS/4-ISA/4-compiler/4-ASN committee must pass");

        // 2. 3/4 Linux hosts on N=4, f=1 -> REJECTED!
        let mut linux_monoculture = diverse4.clone();
        linux_monoculture[1].os_family = OS_FAMILY_LINUX;
        linux_monoculture[2].os_family = OS_FAMILY_LINUX;
        assert_eq!(
            validate_committee_diversity(&linux_monoculture, bft4),
            Err(DynamicQuorumError::DiversityPolicyViolation {
                dimension: "os_family",
                value: OS_FAMILY_LINUX as u32,
                count: 2,
                max_allowed: 1,
            })
        );

        // 3. Duplicate CPU ISA (> f=1) -> REJECTED!
        let mut isa_dup = diverse4.clone();
        isa_dup[3].cpu_isa = CPU_ISA_X86_64;
        assert_eq!(
            validate_committee_diversity(&isa_dup, bft4),
            Err(DynamicQuorumError::DiversityPolicyViolation {
                dimension: "cpu_isa",
                value: CPU_ISA_X86_64 as u32,
                count: 2,
                max_allowed: 1,
            })
        );

        // 4. Duplicate compiler lineage (> f=1) -> REJECTED!
        let mut comp_dup = diverse4.clone();
        comp_dup[2].compiler_lineage = COMPILER_RUSTC_LLVM;
        assert_eq!(
            validate_committee_diversity(&comp_dup, bft4),
            Err(DynamicQuorumError::DiversityPolicyViolation {
                dimension: "compiler_lineage",
                value: COMPILER_RUSTC_LLVM as u32,
                count: 2,
                max_allowed: 1,
            })
        );

        // 5. Duplicate ASN (> 1) -> REJECTED!
        let mut asn_dup = diverse4.clone();
        asn_dup[1].asn = 64501;
        assert_eq!(
            validate_committee_diversity(&asn_dup, bft4),
            Err(DynamicQuorumError::DiversityPolicyViolation {
                dimension: "asn",
                value: 64501,
                count: 2,
                max_allowed: 1,
            })
        );

        // 6. On N=7, f=2, t=5: up to 2 per OS/ISA/compiler is allowed, max 1 per ASN.
        let bft7 = compute_bft_params(7).unwrap();
        let diverse7 = vec![
            QuorumDiversityProfile { os_family: 1, cpu_isa: 1, compiler_lineage: 1, asn: 1001, geo_cell_id: 1 },
            QuorumDiversityProfile { os_family: 1, cpu_isa: 2, compiler_lineage: 2, asn: 1002, geo_cell_id: 2 },
            QuorumDiversityProfile { os_family: 2, cpu_isa: 1, compiler_lineage: 3, asn: 1003, geo_cell_id: 3 },
            QuorumDiversityProfile { os_family: 2, cpu_isa: 2, compiler_lineage: 4, asn: 1004, geo_cell_id: 4 },
            QuorumDiversityProfile { os_family: 3, cpu_isa: 3, compiler_lineage: 1, asn: 1005, geo_cell_id: 5 },
            QuorumDiversityProfile { os_family: 3, cpu_isa: 3, compiler_lineage: 2, asn: 1006, geo_cell_id: 6 },
            QuorumDiversityProfile { os_family: 4, cpu_isa: 4, compiler_lineage: 3, asn: 1007, geo_cell_id: 7 },
        ];
        validate_committee_diversity(&diverse7, bft7)
            .expect("diverse N=7 committee with <= 2 per OS/ISA/compiler and 1 per ASN must pass");
    }

    #[test]
    fn test_core_bond_policy_demand_scaling_probation_unbonding_and_slow_churn() {
        let policy = CoreBondPolicy::default();
        assert_eq!(policy.target_bonded_bps, 2_000);
        assert_eq!(policy.outer_pool_probation_epochs, 30);
        assert_eq!(policy.unbonding_epochs, 60);

        // Circulating supply = 10,000,000 VRNM (in vern), N = 10 Core seats.
        // 20% target bonded = 2,000,000 VRNM total -> 200,000 VRNM flat bond per seat!
        let vern: u64 = 100_000_000;
        let circulating = 10_000_000 * vern;
        let flat_bond = policy.required_flat_bond(circulating, 10).unwrap();
        assert_eq!(flat_bond, 200_000 * vern);

        // Zero queued candidates -> demand_scaled_bond equals base flat bond.
        assert_eq!(policy.demand_scaled_bond(circulating, 10, 0).unwrap(), flat_bond);

        // 10 queued candidates competing for 10 seats -> 2x demand scaling = 400,000 VRNM per seat!
        let scaled = policy.demand_scaled_bond(circulating, 10, 10).unwrap();
        assert_eq!(scaled, 400_000 * vern);

        // Early low-supply launch respects min_bond_per_seat floor (10,000 VRNM).
        let floor_bond = policy.required_flat_bond(50_000 * vern, 10).unwrap();
        assert_eq!(floor_bond, DEFAULT_MIN_CORE_BOND);

        // Probation (30 epochs) and unbonding (60 epochs) checks.
        assert!(!policy.is_probation_complete(10, 39));
        assert!(policy.is_probation_complete(10, 40));
        assert!(!policy.is_unbonding_complete(100, 159));
        assert!(policy.is_unbonding_complete(100, 160));

        // Slow-churn rotation caps per window.
        let p4 = compute_bft_params(4).unwrap();
        let p7 = compute_bft_params(7).unwrap();
        let p10 = compute_bft_params(10).unwrap();
        assert_eq!(max_core_rotations_per_window(p4), 1);
        assert_eq!(policy.max_core_rotations_per_window(p7), 2);
        assert_eq!(max_core_rotations_per_window(p10), 3);
    }
}
