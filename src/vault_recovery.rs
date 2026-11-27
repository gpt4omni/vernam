//! Strict Single-Share Crash-Safe Validator Vault, 4D Diversity Tracking, and
//! Herzberg Zero-Reconstruction Share Recovery over `F_(2^127 - 1)` for Vernam (`VRNM`).
//!
//! Zero external crates, zero computational cryptography (no SHA-256, RSA, ECDSA, or AES),
//! and zero `unsafe` code.
//!
//! # Security Guarantees
//! 1. **Strict Single-Share Disk Isolation (`SingleShareVault`)**:
//!    - Every persisted slot holds strictly ONE Shamir share scalar `share_i: u128` (`< PRIME_P`)
//!      for this validator's evaluation point `x_i`.
//!    - Backed by `CrashSafeChainStore` (rotating one-time additive-pad CW-MACs over `F_(2^127 - 1)`)
//!      and `WalPadBook` (WAL-first crash-safe one-time pad book for recovery/peer OTP envelopes).
//!    - Any on-disk slot containing `!= 1` share is rejected fail-closed with
//!      [`VaultRecoveryError::SingleShareInvariantViolation`].
//! 2. **4D Committee Diversity Tracking (`DiversityProfile`)**:
//!    - Tracks validator heterogeneity across OS kernel family, CPU architecture family,
//!      compiler lineage, and operational jurisdiction to detect correlated failure risk.
//! 3. **Herzberg Zero-Reconstruction Share Recovery (`F_(2^127 - 1)`)**:
//!    - Recovers a lost validator's share `P(x_r)` from `>= t` helper validators WITHOUT
//!      ever reconstructing `P(0)` or revealing any helper's share `P(x_j)`!
//!    - Helpers blind their shares with random degree-`(t - 1)` polynomials `delta(X)`
//!      strictly constrained to `delta(x_r) = 0`, shifting `P'(0) = P(0) + Delta(0)` uniformly
//!      over `F_(2^127 - 1)` while preserving `P'(x_r) = P(x_r)`.
//!    - Interpolates strictly at `target_x = x_r != 0` (NEVER at `0`), verifies degree-`(t - 1)`
//!      polynomial consistency across all helpers, and supports Byzantine helper filtering up to
//!      the exact Reed-Solomon unique-decoding radius `f <= floor((m - t) / 2)`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use crate::field::{
    PRIME_P, add_mod, inv_mod, mul_mod, random_field_elem, sub_mod, zeroize_u128,
};
use crate::otp::{FRAME_BYTES, OtpError, PadPage, WalPadBook};
use crate::storage::{
    CrashSafeChainStore, PersistedChainSnapshot, PersistedShieldedSlot, PersistedValidatorVault,
    SNAPSHOT_FORMAT_VERSION, StorageError, WalDeltaEvent,
};

/// Default number of WAL delta records before `SingleShareVault` auto-compacts its snapshot
/// (which also rotates the storage CW-MAC evaluation scalar `r`).
pub const DEFAULT_VAULT_COMPACT_THRESHOLD: usize = 64;

/// Maximum helper count accepted by combinatorial Byzantine subset filtering (DoS guard).
pub const MAX_RECOVERY_HELPERS: usize = 32;

/// Default encryption key byte length for `SingleShareVault`'s recovery `WalPadBook` pages.
pub const DEFAULT_RECOVERY_PAD_KEY_BYTES: usize = FRAME_BYTES;

const CHAIN_STORE_SUBDIR: &str = "chain_store";
const RECOVERY_PADBOOK_FILENAME: &str = "recovery_pads.book";

// =============================================================================
// Error Types
// =============================================================================

/// Errors returned by single-share vault persistence and Herzberg share recovery operations.
#[derive(Debug)]
pub enum VaultRecoveryError {
    /// Underlying crash-safe chain storage error.
    Storage(StorageError),
    /// Underlying crash-safe WAL one-time pad book error.
    Otp(OtpError),
    /// A field scalar was non-canonical (`>= PRIME_P = 2^127 - 1`).
    NonCanonicalFieldElement,
    /// Invalid recovery or vault parameter.
    InvalidParameters(String),
    /// Attempted to use `target_x == 0` (which would reconstruct the secret `P(0)` — forbidden!).
    InvalidTargetX,
    /// Duplicate helper evaluation coordinate `x_j`.
    DuplicateEvaluationPoint(u64),
    /// Fewer than `threshold` helpers provided.
    InsufficientHelpers { available: usize, required: usize },
    /// Helper shares did not all lie on a single degree-`(threshold - 1)` polynomial.
    InconsistentShares {
        expected_degree: usize,
        helper_count: usize,
    },
    /// Too many Byzantine helpers to unambiguously identify an honest `threshold`-subset.
    ByzantineRecoveryFailed {
        total_helpers: usize,
        threshold: usize,
    },
    /// On-disk state violated strict single-share isolation or validator identity binding.
    SingleShareInvariantViolation(String),
    /// Requested `(bucket_id, slot_id)` was not found in the vault.
    SlotNotFound { bucket_id: u32, slot_id: u32 },
}

impl fmt::Display for VaultRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultRecoveryError::Storage(err) => write!(f, "vault storage error: {err}"),
            VaultRecoveryError::Otp(err) => write!(f, "vault OTP pad book error: {err}"),
            VaultRecoveryError::NonCanonicalFieldElement => {
                write!(f, "non-canonical F_(2^127 - 1) field element (>= PRIME_P)")
            }
            VaultRecoveryError::InvalidParameters(msg) => {
                write!(f, "invalid vault recovery parameters: {msg}")
            }
            VaultRecoveryError::InvalidTargetX => write!(
                f,
                "invalid recovery target_x == 0 (reconstructing P(0) is strictly forbidden)"
            ),
            VaultRecoveryError::DuplicateEvaluationPoint(x) => {
                write!(f, "duplicate helper evaluation coordinate x={x}")
            }
            VaultRecoveryError::InsufficientHelpers {
                available,
                required,
            } => write!(
                f,
                "insufficient recovery helpers: got {available}, need at least {required}"
            ),
            VaultRecoveryError::InconsistentShares {
                expected_degree,
                helper_count,
            } => write!(
                f,
                "inconsistent blinded helper shares across {helper_count} helpers (expected degree <= {expected_degree})"
            ),
            VaultRecoveryError::ByzantineRecoveryFailed {
                total_helpers,
                threshold,
            } => write!(
                f,
                "cannot uniquely identify honest subset among {total_helpers} helpers for threshold {threshold}"
            ),
            VaultRecoveryError::SingleShareInvariantViolation(msg) => {
                write!(f, "single-share vault invariant violation: {msg}")
            }
            VaultRecoveryError::SlotNotFound { bucket_id, slot_id } => {
                write!(f, "vault slot ({bucket_id}, {slot_id}) not found")
            }
        }
    }
}

impl std::error::Error for VaultRecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VaultRecoveryError::Storage(err) => Some(err),
            VaultRecoveryError::Otp(err) => Some(err),
            _ => None,
        }
    }
}

impl From<StorageError> for VaultRecoveryError {
    fn from(err: StorageError) -> Self {
        VaultRecoveryError::Storage(err)
    }
}

impl From<OtpError> for VaultRecoveryError {
    fn from(err: OtpError) -> Self {
        VaultRecoveryError::Otp(err)
    }
}

// =============================================================================
// 4D Committee Diversity Tracking
// =============================================================================

/// Operating system kernel family (Diversity Dimension 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OsKernelFamily {
    Linux,
    FreeBsd,
    OpenBsd,
    NetBsd,
    Illumos,
    MacOs,
    Other(u16),
}

impl OsKernelFamily {
    /// Detect the host's operating system kernel family using compile-time target constants.
    pub fn detect_host() -> Self {
        match std::env::consts::OS {
            "linux" => Self::Linux,
            "freebsd" => Self::FreeBsd,
            "openbsd" => Self::OpenBsd,
            "netbsd" => Self::NetBsd,
            "illumos" | "solaris" => Self::Illumos,
            "macos" => Self::MacOs,
            _ => Self::Other(0),
        }
    }
}

/// CPU instruction set architecture family (Diversity Dimension 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CpuArchFamily {
    X86_64,
    Aarch64,
    RiscV64,
    PowerPc64,
    S390x,
    Other(u16),
}

impl CpuArchFamily {
    /// Detect the host's CPU architecture family using compile-time target constants.
    pub fn detect_host() -> Self {
        match std::env::consts::ARCH {
            "x86_64" => Self::X86_64,
            "aarch64" => Self::Aarch64,
            "riscv64" => Self::RiscV64,
            "powerpc64" => Self::PowerPc64,
            "s390x" => Self::S390x,
            _ => Self::Other(0),
        }
    }
}

/// Compiler / codegen backend lineage (Diversity Dimension 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompilerLineage {
    RustcLlvm,
    RustcCranelift,
    RustcGcc,
    GccRs,
    Mrustc,
    Other(u16),
}

impl CompilerLineage {
    /// Default compiler lineage for standard `rustc` builds.
    pub const fn detect_host() -> Self {
        Self::RustcLlvm
    }
}

/// 4-Dimensional validator diversity profile (OS kernel, CPU architecture, compiler lineage,
/// and operational/geographic jurisdiction fault domain).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiversityProfile {
    pub os_kernel: OsKernelFamily,
    pub cpu_arch: CpuArchFamily,
    pub compiler: CompilerLineage,
    /// Dimension 4: geographic / legal / cloud-provider fault domain identifier.
    pub jurisdiction: String,
}

impl DiversityProfile {
    /// Create a new 4D validator diversity profile.
    pub fn new(
        os_kernel: OsKernelFamily,
        cpu_arch: CpuArchFamily,
        compiler: CompilerLineage,
        jurisdiction: impl Into<String>,
    ) -> Self {
        Self {
            os_kernel,
            cpu_arch,
            compiler,
            jurisdiction: jurisdiction.into(),
        }
    }

    /// Detect local OS, CPU architecture, and compiler lineage for the given jurisdiction.
    pub fn detect_local(jurisdiction: impl Into<String>) -> Self {
        Self {
            os_kernel: OsKernelFamily::detect_host(),
            cpu_arch: CpuArchFamily::detect_host(),
            compiler: CompilerLineage::detect_host(),
            jurisdiction: jurisdiction.into(),
        }
    }

    /// Count how many of the 4 diversity dimensions differ between `self` and `other` (`0..=4`).
    pub fn distinct_dimensions_from(&self, other: &Self) -> usize {
        let mut diff = 0;
        if self.os_kernel != other.os_kernel {
            diff += 1;
        }
        if self.cpu_arch != other.cpu_arch {
            diff += 1;
        }
        if self.compiler != other.compiler {
            diff += 1;
        }
        if self.jurisdiction != other.jurisdiction {
            diff += 1;
        }
        diff
    }
}

/// Summary report evaluating whether a validator committee avoids single-monoculture
/// correlated compromises across all 4 diversity dimensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeDiversityReport {
    pub validator_count: usize,
    pub threshold: usize,
    pub distinct_os_kernels: usize,
    pub distinct_cpu_archs: usize,
    pub distinct_compilers: usize,
    pub distinct_jurisdictions: usize,
    pub max_os_concentration: usize,
    pub max_arch_concentration: usize,
    pub max_compiler_concentration: usize,
    pub max_jurisdiction_concentration: usize,
    /// True iff no single OS, CPU arch, compiler, or jurisdiction reaches `threshold` validators.
    pub resists_single_dimension_compromise: bool,
}

impl CommitteeDiversityReport {
    /// Evaluate a committee's 4D diversity against Shamir reconstruction `threshold`.
    pub fn evaluate(profiles: &[DiversityProfile], threshold: usize) -> Self {
        let mut os_counts: BTreeMap<OsKernelFamily, usize> = BTreeMap::new();
        let mut arch_counts: BTreeMap<CpuArchFamily, usize> = BTreeMap::new();
        let mut comp_counts: BTreeMap<CompilerLineage, usize> = BTreeMap::new();
        let mut jur_counts: BTreeMap<&str, usize> = BTreeMap::new();

        for p in profiles {
            *os_counts.entry(p.os_kernel).or_insert(0) += 1;
            *arch_counts.entry(p.cpu_arch).or_insert(0) += 1;
            *comp_counts.entry(p.compiler).or_insert(0) += 1;
            *jur_counts.entry(p.jurisdiction.as_str()).or_insert(0) += 1;
        }

        let max_os = os_counts.values().copied().max().unwrap_or(0);
        let max_arch = arch_counts.values().copied().max().unwrap_or(0);
        let max_comp = comp_counts.values().copied().max().unwrap_or(0);
        let max_jur = jur_counts.values().copied().max().unwrap_or(0);

        let resists = threshold > 0
            && profiles.len() >= threshold
            && max_os < threshold
            && max_arch < threshold
            && max_comp < threshold
            && max_jur < threshold;

        Self {
            validator_count: profiles.len(),
            threshold,
            distinct_os_kernels: os_counts.len(),
            distinct_cpu_archs: arch_counts.len(),
            distinct_compilers: comp_counts.len(),
            distinct_jurisdictions: jur_counts.len(),
            max_os_concentration: max_os,
            max_arch_concentration: max_arch,
            max_compiler_concentration: max_comp,
            max_jurisdiction_concentration: max_jur,
            resists_single_dimension_compromise: resists,
        }
    }
}

// =============================================================================
// Strict Single-Share Crash-Safe Validator Vault
// =============================================================================

/// Persisted single-share shielded slot belonging strictly to ONE validator `x_i`.
///
/// By struct layout, this type can store **only** a single canonical scalar `share_i < PRIME_P`
/// and is structurally incapable of holding peer validators' shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistedSingleShareSlot {
    pub bucket_id: u32,
    pub slot_id: u32,
    pub share_i: u128,
}

impl PersistedSingleShareSlot {
    /// Construct a validated single-share slot, rejecting non-canonical scalars (`>= PRIME_P`).
    pub fn new(bucket_id: u32, slot_id: u32, share_i: u128) -> Result<Self, VaultRecoveryError> {
        if share_i >= PRIME_P {
            return Err(VaultRecoveryError::NonCanonicalFieldElement);
        }
        Ok(Self {
            bucket_id,
            slot_id,
            share_i,
        })
    }
}

/// Crash-safe, strictly single-share validator persistence vault.
///
/// Combines:
/// - [`CrashSafeChainStore`] (rotating one-time additive-pad CW-MAC snapshots + WAL) storing
///   ONLY single-share slots (`shares.len() == 1`, strictly enforced on both write and recovery),
/// - [`WalPadBook`] (crash-safe WAL-first OTP pad book) for one-time authenticated recovery
///   envelopes without any risk of two-time-pad reuse across power loss.
///
/// All in-memory shares are volatile-zeroized on `Drop`.
pub struct SingleShareVault {
    vault_dir: PathBuf,
    validator_x: u64,
    pss_epoch: u64,
    diversity: DiversityProfile,
    chain_store: CrashSafeChainStore,
    pad_book: WalPadBook,
    slots: BTreeMap<(u32, u32), u128>,
    compact_threshold: usize,
}

impl SingleShareVault {
    /// Open an existing crash-safe single-share vault or initialize a new one in `vault_dir`.
    ///
    /// On reopen:
    /// - Replays `chain_store` snapshot + WAL with rotating CW-MAC verification.
    /// - Enforces that every persisted slot contains **strictly 1 canonical share** (`shares.len() == 1`).
    /// - Enforces validator evaluation coordinate `validator_x` consistency if a snapshot exists.
    /// - Recovers `recovery_pads.book` via `WalPadBook::open`, completing any interrupted pad burn.
    pub fn open_or_create(
        vault_dir: impl AsRef<Path>,
        validator_x: u64,
        initial_pad_pages: usize,
        pad_enc_key_bytes: usize,
        diversity: DiversityProfile,
    ) -> Result<Self, VaultRecoveryError> {
        if validator_x == 0 {
            return Err(VaultRecoveryError::InvalidTargetX);
        }
        if (validator_x as u128) >= PRIME_P {
            return Err(VaultRecoveryError::NonCanonicalFieldElement);
        }

        let vault_dir = vault_dir.as_ref().to_path_buf();
        let chain_dir = vault_dir.join(CHAIN_STORE_SUBDIR);
        let pad_path = vault_dir.join(RECOVERY_PADBOOK_FILENAME);

        let chain_store = CrashSafeChainStore::open(&chain_dir)?;

        let pad_book = if pad_path.exists() {
            WalPadBook::open(&pad_path)?
        } else {
            let mut initial_pages = Vec::with_capacity(initial_pad_pages);
            for i in 0..initial_pad_pages {
                initial_pages.push(PadPage::generate(i as u64, pad_enc_key_bytes));
            }
            WalPadBook::create(&pad_path, pad_enc_key_bytes, initial_pages)?
        };

        let (snapshot_opt, wal_events) = chain_store.load_latest()?;
        let mut pss_epoch: u64 = 0;
        let mut slots: BTreeMap<(u32, u32), u128> = BTreeMap::new();

        if let Some(snap) = snapshot_opt {
            if !snap.validators.is_empty() {
                if snap.validators.len() != 1 || snap.validators[0].validator_id != validator_x {
                    return Err(VaultRecoveryError::SingleShareInvariantViolation(format!(
                        "vault belongs to validator(s) {:?}, cannot open as validator_x={validator_x}",
                        snap.validators
                            .iter()
                            .map(|v| v.validator_id)
                            .collect::<Vec<_>>()
                    )));
                }
            }
            pss_epoch = snap.pss_epoch;
            for persisted in snap.shielded_slots {
                let single = extract_strict_single_share(&persisted)?;
                slots.insert((single.bucket_id, single.slot_id), single.share_i);
            }
        }

        for ev in wal_events {
            if let WalDeltaEvent::ShieldedBucketUpdate {
                pss_epoch: ev_epoch,
                slots: ev_slots,
                ..
            } = ev
            {
                if ev_epoch > pss_epoch {
                    pss_epoch = ev_epoch;
                }
                for persisted in ev_slots {
                    let single = extract_strict_single_share(&persisted)?;
                    slots.insert((single.bucket_id, single.slot_id), single.share_i);
                }
            }
        }

        Ok(Self {
            vault_dir,
            validator_x,
            pss_epoch,
            diversity,
            chain_store,
            pad_book,
            slots,
            compact_threshold: DEFAULT_VAULT_COMPACT_THRESHOLD,
        })
    }

    /// Configure the WAL compaction threshold (minimum 1).
    pub fn set_compact_threshold(&mut self, threshold: usize) {
        self.compact_threshold = threshold.max(1);
    }

    /// Root directory of this single-share vault.
    #[inline]
    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    /// This validator's non-zero Shamir evaluation coordinate `x_i`.
    #[inline]
    pub fn validator_x(&self) -> u64 {
        self.validator_x
    }

    /// Current persisted Proactive Secret Sharing (PSS) epoch.
    #[inline]
    pub fn pss_epoch(&self) -> u64 {
        self.pss_epoch
    }

    /// This validator's 4D diversity profile.
    #[inline]
    pub fn diversity(&self) -> &DiversityProfile {
        &self.diversity
    }

    /// Number of single-share shielded slots persisted in this vault.
    #[inline]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Borrow the underlying rotating-MAC [`CrashSafeChainStore`].
    #[inline]
    pub fn chain_store(&self) -> &CrashSafeChainStore {
        &self.chain_store
    }

    /// Borrow the underlying crash-safe recovery [`WalPadBook`].
    #[inline]
    pub fn pad_book(&self) -> &WalPadBook {
        &self.pad_book
    }

    /// Number of unused recovery OTP pad pages remaining in `pad_book`.
    #[inline]
    pub fn remaining_recovery_pads(&self) -> usize {
        self.pad_book.remaining()
    }

    /// Pop and crash-safely burn (WAL `fsync` + disk zero-wipe) the next recovery OTP pad page.
    pub fn pop_recovery_pad(&mut self) -> Result<PadPage, VaultRecoveryError> {
        Ok(self.pad_book.pop_next()?)
    }

    /// Append newly provisioned recovery OTP pad pages to `pad_book`.
    pub fn replenish_recovery_pads(&mut self, pages: Vec<PadPage>) -> Result<(), VaultRecoveryError> {
        Ok(self.pad_book.append_pages(pages)?)
    }

    /// Persist a single-share slot update durably to the WAL (`fsync`ed with a fresh CW-MAC pad)
    /// and compact into a fresh snapshot if the WAL threshold is reached.
    pub fn put_slot(&mut self, slot: PersistedSingleShareSlot) -> Result<(), VaultRecoveryError> {
        if slot.share_i >= PRIME_P {
            return Err(VaultRecoveryError::NonCanonicalFieldElement);
        }

        let event = WalDeltaEvent::ShieldedBucketUpdate {
            bucket_id: slot.bucket_id,
            pss_epoch: self.pss_epoch,
            slots: vec![PersistedShieldedSlot {
                bucket_id: slot.bucket_id,
                slot_id: slot.slot_id,
                shares: vec![slot.share_i],
            }],
            fee_burned: 0,
        };
        self.chain_store.append_wal(&event)?;
        self.slots.insert((slot.bucket_id, slot.slot_id), slot.share_i);
        self.maybe_compact()?;
        Ok(())
    }

    /// Atomically persist a batch of single-share slots for `bucket_id` at `pss_epoch`.
    pub fn put_slots_batch(
        &mut self,
        bucket_id: u32,
        pss_epoch: u64,
        slots: &[PersistedSingleShareSlot],
    ) -> Result<(), VaultRecoveryError> {
        let mut persisted_slots = Vec::with_capacity(slots.len());
        for s in slots {
            if s.bucket_id != bucket_id {
                return Err(VaultRecoveryError::InvalidParameters(format!(
                    "slot bucket_id {} does not match batch bucket_id {bucket_id}",
                    s.bucket_id
                )));
            }
            if s.share_i >= PRIME_P {
                return Err(VaultRecoveryError::NonCanonicalFieldElement);
            }
            persisted_slots.push(PersistedShieldedSlot {
                bucket_id: s.bucket_id,
                slot_id: s.slot_id,
                shares: vec![s.share_i],
            });
        }

        let event = WalDeltaEvent::ShieldedBucketUpdate {
            bucket_id,
            pss_epoch,
            slots: persisted_slots,
            fee_burned: 0,
        };
        self.chain_store.append_wal(&event)?;
        if pss_epoch > self.pss_epoch {
            self.pss_epoch = pss_epoch;
        }
        for s in slots {
            self.slots.insert((s.bucket_id, s.slot_id), s.share_i);
        }
        self.maybe_compact()?;
        Ok(())
    }

    /// Retrieve a persisted single-share slot by `(bucket_id, slot_id)`.
    pub fn get_slot(&self, bucket_id: u32, slot_id: u32) -> Option<PersistedSingleShareSlot> {
        self.slots
            .get(&(bucket_id, slot_id))
            .map(|&share_i| PersistedSingleShareSlot {
                bucket_id,
                slot_id,
                share_i,
            })
    }

    /// Return all persisted single-share slots ordered deterministically by `(bucket_id, slot_id)`.
    pub fn all_slots(&self) -> Vec<PersistedSingleShareSlot> {
        self.slots
            .iter()
            .map(|(&(bucket_id, slot_id), &share_i)| PersistedSingleShareSlot {
                bucket_id,
                slot_id,
                share_i,
            })
            .collect()
    }

    /// Persist a Herzberg-recovered single share into `(bucket_id, slot_id)`.
    pub fn apply_recovered_slot(
        &mut self,
        bucket_id: u32,
        slot_id: u32,
        recovered_share: u128,
    ) -> Result<(), VaultRecoveryError> {
        let slot = PersistedSingleShareSlot::new(bucket_id, slot_id, recovered_share)?;
        self.put_slot(slot)
    }

    /// Force an atomic snapshot checkpoint (rotating the storage CW-MAC evaluation key `r`
    /// and resetting the WAL).
    pub fn checkpoint(&mut self) -> Result<(), VaultRecoveryError> {
        let snap = self.build_snapshot();
        self.chain_store.save_snapshot(&snap)?;
        Ok(())
    }

    fn maybe_compact(&mut self) -> Result<(), VaultRecoveryError> {
        if (self.chain_store.wal_record_count() as usize) >= self.compact_threshold {
            let snap = self.build_snapshot();
            self.chain_store
                .compact_if_needed(&snap, self.compact_threshold)?;
        }
        Ok(())
    }

    fn build_snapshot(&self) -> PersistedChainSnapshot {
        let shielded_slots = self
            .slots
            .iter()
            .map(|(&(bucket_id, slot_id), &share_i)| PersistedShieldedSlot {
                bucket_id,
                slot_id,
                shares: vec![share_i],
            })
            .collect();

        PersistedChainSnapshot {
            version: SNAPSHOT_FORMAT_VERSION,
            pss_epoch: self.pss_epoch,
            shielded_slots,
            validators: vec![PersistedValidatorVault {
                validator_id: self.validator_x,
                bond: 0,
                reward_balance: 0,
                status_code: 1,
                missed_epochs: 0,
            }],
            ..PersistedChainSnapshot::default()
        }
    }
}

impl Drop for SingleShareVault {
    fn drop(&mut self) {
        for share in self.slots.values_mut() {
            zeroize_u128(share);
        }
        self.slots.clear();
    }
}

impl fmt::Debug for SingleShareVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleShareVault")
            .field("vault_dir", &self.vault_dir)
            .field("validator_x", &self.validator_x)
            .field("pss_epoch", &self.pss_epoch)
            .field("diversity", &self.diversity)
            .field("slot_count", &self.slots.len())
            .field("remaining_recovery_pads", &self.pad_book.remaining())
            .field("slots", &"[REDACTED]")
            .finish()
    }
}

fn extract_strict_single_share(
    slot: &PersistedShieldedSlot,
) -> Result<PersistedSingleShareSlot, VaultRecoveryError> {
    if slot.shares.len() != 1 {
        return Err(VaultRecoveryError::SingleShareInvariantViolation(format!(
            "slot ({}, {}) contains {} shares (single-share vault strictly requires exactly 1)",
            slot.bucket_id,
            slot.slot_id,
            slot.shares.len()
        )));
    }
    PersistedSingleShareSlot::new(slot.bucket_id, slot.slot_id, slot.shares[0])
}

// =============================================================================
// Herzberg Zero-Reconstruction Share Recovery over F_(2^127 - 1)
// =============================================================================

/// Result of Byzantine-resilient Herzberg share recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByzantineRecoveryResult {
    /// Exact recovered share `P(target_x)` in `F_(2^127 - 1)` (0 bits of `P(0)` revealed).
    pub recovered_share: u128,
    /// Evaluation coordinates of all helpers consistent with the unique degree-`(t - 1)` polynomial.
    pub honest_helper_xs: Vec<u64>,
    /// Evaluation coordinates of helpers whose blinded shares were detected as corrupted/Byzantine.
    pub byzantine_helper_xs: Vec<u64>,
}

/// Sample a random degree-`(threshold - 1)` blinding polynomial `delta(X)` over `F_(2^127 - 1)`
/// strictly constrained to `delta(target_x) = 0`, and evaluate it at every helper coordinate `x_j`.
///
/// Construction:
/// - Samples `c_1, ..., c_{t-1}` uniformly at random from `F_(2^127 - 1)` via OS randomness.
/// - Computes `c_0 = -sum_{m=1}^{t-1} c_m * target_x^m (mod PRIME_P)` so `delta(target_x) == 0`.
/// - Evaluates `delta(x_j)` for each `x_j in helper_xs` and volatile-zeroizes all coefficients
///   before returning `Vec<(x_j, delta(x_j))>`.
///
/// In Herzberg's protocol, every helper `V_k` calls this function independently and distributes
/// `(x_j, delta_k(x_j))` to each helper `V_j` over pairwise OTP channels. As long as at least
/// one helper is honest, the aggregate blinding polynomial `Delta(X) = sum_k delta_k(X)` has
/// uniform random `Delta(0)`, hiding `P(0)` and every helper's share `P(x_j)` with 0 bits leaked
/// while preserving `P'(target_x) = P(target_x) + Delta(target_x) = P(target_x)`.
pub fn prepare_recovery_blinding(
    target_x: u64,
    helper_xs: &[u64],
    threshold: usize,
) -> Result<Vec<(u64, u128)>, VaultRecoveryError> {
    validate_recovery_coordinates(target_x, helper_xs, threshold)?;

    // Sample c_1 .. c_{t-1} uniformly in F_(2^127 - 1) and set c_0 so delta(target_x) == 0.
    let mut coeffs = vec![0u128; threshold];
    let xr = target_x as u128;
    let mut x_pow = xr;
    let mut sum_higher: u128 = 0;

    for coeff in coeffs.iter_mut().skip(1) {
        let c = random_field_elem();
        *coeff = c;
        sum_higher = add_mod(sum_higher, mul_mod(c, x_pow));
        x_pow = mul_mod(x_pow, xr);
    }
    coeffs[0] = sub_mod(0, sum_higher);

    // Explicit mathematical invariant verification: delta(target_x) MUST equal 0 mod PRIME_P.
    let check_at_target = eval_poly_horner(&coeffs, xr);
    debug_assert_eq!(check_at_target, 0);
    if check_at_target != 0 {
        for c in &mut coeffs {
            zeroize_u128(c);
        }
        return Err(VaultRecoveryError::InvalidParameters(
            "internal blinding polynomial failed delta(target_x) == 0 invariant".into(),
        ));
    }

    let mut evaluations = Vec::with_capacity(helper_xs.len());
    for &xj in helper_xs {
        let val = eval_poly_horner(&coeffs, xj as u128);
        evaluations.push((xj, val));
    }

    // Volatile-zeroize all polynomial coefficients before returning.
    for c in &mut coeffs {
        zeroize_u128(c);
    }
    zeroize_u128(&mut sum_higher);

    Ok(evaluations)
}

/// Combine a helper validator's own Shamir share `P(x_j)` with all incoming blinding evaluations
/// `delta_k(x_j)` in `F_(2^127 - 1)`:
///
/// `P'(x_j) = (own_share + sum(incoming_blinds)) mod PRIME_P`.
///
/// Strictly validates that `own_share` and every blind in `incoming_blinds` are canonical `< PRIME_P`.
pub fn compute_blinded_helper_share(
    own_share: u128,
    incoming_blinds: &[u128],
) -> Result<u128, VaultRecoveryError> {
    if own_share >= PRIME_P {
        return Err(VaultRecoveryError::NonCanonicalFieldElement);
    }
    let mut acc = own_share;
    for &b in incoming_blinds {
        if b >= PRIME_P {
            return Err(VaultRecoveryError::NonCanonicalFieldElement);
        }
        acc = add_mod(acc, b);
    }
    Ok(acc)
}

/// Recover the lost validator's single share `P(target_x)` from blinded helper shares over
/// `F_(2^127 - 1)` with strict degree-`(threshold - 1)` polynomial consistency verification.
///
/// # Zero-Reconstruction Guarantee
/// - Rejects `target_x == 0` with [`VaultRecoveryError::InvalidTargetX`].
/// - Evaluates Lagrange interpolation **strictly at `target_x`** (NEVER at `0`).
/// - When `blinded_helper_shares.len() > threshold`, verifies that EVERY additional helper share
///   lies on the unique degree-`(threshold - 1)` polynomial defined by the first `threshold`
///   helpers, catching and rejecting Byzantine corrupted helper shares with
///   [`VaultRecoveryError::InconsistentShares`].
pub fn recover_single_share_at_x(
    target_x: u64,
    blinded_helper_shares: &[(u64, u128)],
    threshold: usize,
) -> Result<u128, VaultRecoveryError> {
    validate_blinded_helper_shares(target_x, blinded_helper_shares, threshold)?;

    let basis = &blinded_helper_shares[..threshold];

    // Verify degree-(t - 1) polynomial consistency across all extra helpers.
    for &(xk, yk) in &blinded_helper_shares[threshold..] {
        let predicted = lagrange_eval_at(basis, xk as u128);
        if predicted != yk {
            return Err(VaultRecoveryError::InconsistentShares {
                expected_degree: threshold - 1,
                helper_count: blinded_helper_shares.len(),
            });
        }
    }

    // Interpolate strictly at target_x (NEVER at 0!).
    Ok(lagrange_eval_at(basis, target_x as u128))
}

/// Byzantine-resilient Herzberg share recovery identifying the unique honest `threshold`-subset
/// when up to `f <= floor((m - threshold) / 2)` helpers submit corrupted blinded shares.
///
/// # Uniqueness Proof (Reed-Solomon Decoding Radius)
/// Two distinct polynomials of degree `<= t - 1` can agree on at most `t - 1` evaluation points.
/// Therefore, any degree-`(t - 1)` polynomial agreeing with at least
/// `min_honest = max(t, floor((m + t - 1) / 2) + 1)` of the `m` helper shares is mathematically
/// guaranteed to be unique (`2 * min_honest - m >= t`), unambiguously separating all honest
/// helpers from up to `f` Byzantine helpers.
pub fn recover_with_byzantine_filtering(
    target_x: u64,
    blinded_helper_shares: &[(u64, u128)],
    threshold: usize,
) -> Result<ByzantineRecoveryResult, VaultRecoveryError> {
    validate_blinded_helper_shares(target_x, blinded_helper_shares, threshold)?;

    let m = blinded_helper_shares.len();
    if m > MAX_RECOVERY_HELPERS {
        return Err(VaultRecoveryError::InvalidParameters(format!(
            "helper count {m} exceeds maximum {MAX_RECOVERY_HELPERS}"
        )));
    }

    // Fast path: all m helpers are mutually consistent on a single degree-(t - 1) polynomial.
    if let Ok(recovered_share) = recover_single_share_at_x(target_x, blinded_helper_shares, threshold)
    {
        return Ok(ByzantineRecoveryResult {
            recovered_share,
            honest_helper_xs: blinded_helper_shares.iter().map(|&(x, _)| x).collect(),
            byzantine_helper_xs: Vec::new(),
        });
    }

    // Required strict-majority agreement for unambiguous Reed-Solomon decoding.
    let min_honest = ((m + threshold - 1) / 2 + 1).max(threshold);
    if min_honest >= m {
        // Without at least `m >= t + 2` helpers, 1 corrupted share is ambiguous.
        return Err(VaultRecoveryError::ByzantineRecoveryFailed {
            total_helpers: m,
            threshold,
        });
    }

    // Search t-subsets in deterministic lexicographic order; stop immediately once a subset's
    // polynomial reaches `min_honest` agreement (proven unique above).
    let mut indices: Vec<usize> = (0..threshold).collect();
    let mut subset_buf: Vec<(u64, u128)> = Vec::with_capacity(threshold);

    loop {
        subset_buf.clear();
        for &idx in &indices {
            subset_buf.push(blinded_helper_shares[idx]);
        }

        let mut honest_xs = Vec::with_capacity(m);
        let mut byzantine_xs = Vec::new();
        for &(xj, yj) in blinded_helper_shares {
            let predicted = lagrange_eval_at(&subset_buf, xj as u128);
            if predicted == yj {
                honest_xs.push(xj);
            } else {
                byzantine_xs.push(xj);
            }
        }

        if honest_xs.len() >= min_honest {
            let recovered_share = lagrange_eval_at(&subset_buf, target_x as u128);
            return Ok(ByzantineRecoveryResult {
                recovered_share,
                honest_helper_xs: honest_xs,
                byzantine_helper_xs: byzantine_xs,
            });
        }

        if !next_combination(&mut indices, m) {
            break;
        }
    }

    Err(VaultRecoveryError::ByzantineRecoveryFailed {
        total_helpers: m,
        threshold,
    })
}

// =============================================================================
// Internal Field & Polynomial Helpers
// =============================================================================

fn validate_recovery_coordinates(
    target_x: u64,
    helper_xs: &[u64],
    threshold: usize,
) -> Result<(), VaultRecoveryError> {
    if target_x == 0 {
        return Err(VaultRecoveryError::InvalidTargetX);
    }
    if (target_x as u128) >= PRIME_P {
        return Err(VaultRecoveryError::NonCanonicalFieldElement);
    }
    if threshold < 2 {
        return Err(VaultRecoveryError::InvalidParameters(format!(
            "threshold must be >= 2 for zero-reconstruction blinding, got {threshold}"
        )));
    }
    if helper_xs.len() < threshold {
        return Err(VaultRecoveryError::InsufficientHelpers {
            available: helper_xs.len(),
            required: threshold,
        });
    }

    let mut seen = BTreeSet::new();
    for &xj in helper_xs {
        if xj == 0 {
            return Err(VaultRecoveryError::InvalidParameters(
                "helper coordinate x_j must be non-zero".into(),
            ));
        }
        if xj == target_x {
            return Err(VaultRecoveryError::InvalidParameters(format!(
                "helper coordinate x_j={xj} must differ from target_x={target_x}"
            )));
        }
        if (xj as u128) >= PRIME_P {
            return Err(VaultRecoveryError::NonCanonicalFieldElement);
        }
        if !seen.insert(xj) {
            return Err(VaultRecoveryError::DuplicateEvaluationPoint(xj));
        }
    }
    Ok(())
}

fn validate_blinded_helper_shares(
    target_x: u64,
    blinded_helper_shares: &[(u64, u128)],
    threshold: usize,
) -> Result<(), VaultRecoveryError> {
    if target_x == 0 {
        return Err(VaultRecoveryError::InvalidTargetX);
    }
    if (target_x as u128) >= PRIME_P {
        return Err(VaultRecoveryError::NonCanonicalFieldElement);
    }
    if threshold < 2 {
        return Err(VaultRecoveryError::InvalidParameters(format!(
            "threshold must be >= 2, got {threshold}"
        )));
    }
    if blinded_helper_shares.len() < threshold {
        return Err(VaultRecoveryError::InsufficientHelpers {
            available: blinded_helper_shares.len(),
            required: threshold,
        });
    }

    let mut seen = BTreeSet::new();
    for &(xj, yj) in blinded_helper_shares {
        if xj == 0 {
            return Err(VaultRecoveryError::InvalidParameters(
                "helper coordinate x_j must be non-zero".into(),
            ));
        }
        if xj == target_x {
            return Err(VaultRecoveryError::InvalidParameters(format!(
                "helper coordinate x_j={xj} must differ from target_x={target_x}"
            )));
        }
        if (xj as u128) >= PRIME_P || yj >= PRIME_P {
            return Err(VaultRecoveryError::NonCanonicalFieldElement);
        }
        if !seen.insert(xj) {
            return Err(VaultRecoveryError::DuplicateEvaluationPoint(xj));
        }
    }
    Ok(())
}

/// Evaluate polynomial `coeffs[0] + coeffs[1]*x + ... + coeffs[d]*x^d (mod PRIME_P)` via Horner's rule.
#[inline]
fn eval_poly_horner(coeffs: &[u128], x: u128) -> u128 {
    let mut acc: u128 = 0;
    for &c in coeffs.iter().rev() {
        acc = add_mod(mul_mod(acc, x), c);
    }
    acc
}

/// Evaluate the unique degree-`(points.len() - 1)` Lagrange interpolating polynomial through
/// `points` at an arbitrary field point `eval_x` over `F_(2^127 - 1)`.
///
/// Precondition: all `x_i` in `points` are pairwise distinct and `< PRIME_P`.
fn lagrange_eval_at(points: &[(u64, u128)], eval_x: u128) -> u128 {
    let mut acc: u128 = 0;
    for (i, &(xi_u64, yi)) in points.iter().enumerate() {
        let xi = xi_u64 as u128;
        if eval_x == xi {
            return yi;
        }
        let mut num: u128 = 1;
        let mut den: u128 = 1;
        for (j, &(xj_u64, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = xj_u64 as u128;
            num = mul_mod(num, sub_mod(eval_x, xj));
            den = mul_mod(den, sub_mod(xi, xj));
        }
        let basis = mul_mod(num, inv_mod(den));
        acc = add_mod(acc, mul_mod(yi, basis));
    }
    acc
}

/// Advance `indices` (strictly increasing `k`-combination of `0..n`) to the next lexicographic
/// combination. Returns `false` when all combinations have been exhausted.
fn next_combination(indices: &mut [usize], n: usize) -> bool {
    let k = indices.len();
    if k == 0 || k > n {
        return false;
    }
    let mut i = k;
    while i > 0 {
        i -= 1;
        if indices[i] != i + n - k {
            indices[i] += 1;
            for j in (i + 1)..k {
                indices[j] = indices[j - 1] + 1;
            }
            return true;
        }
    }
    false
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static VAULT_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempVaultDir(PathBuf);

    impl TempVaultDir {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let pid = std::process::id();
            let seq = VAULT_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "vernam_vault_recovery_{label}_{pid}_{nanos}_{seq}"
            ));
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempVaultDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Helper: create a random degree-(threshold - 1) Shamir polynomial P(X) with P(0) = secret
    /// and return its evaluations at `xs`.
    fn shamir_split(secret: u128, xs: &[u64], threshold: usize) -> Vec<(u64, u128)> {
        let mut coeffs = Vec::with_capacity(threshold);
        coeffs.push(secret);
        for _ in 1..threshold {
            coeffs.push(random_field_elem());
        }
        xs.iter()
            .map(|&x| (x, eval_poly_horner(&coeffs, x as u128)))
            .collect()
    }

    /// Run a complete multi-helper Herzberg recovery blinding round where EVERY helper
    /// independently generates a degree-(t-1) zero-at-target_x blinding polynomial.
    fn run_full_herzberg_blinding(
        target_x: u64,
        helper_shares: &[(u64, u128)],
        threshold: usize,
    ) -> Vec<(u64, u128)> {
        let helper_xs: Vec<u64> = helper_shares.iter().map(|&(x, _)| x).collect();
        let m = helper_xs.len();

        // Each helper k samples delta_k(X) with delta_k(target_x) == 0 and sends delta_k(x_j) to helper j.
        let mut incoming_per_helper: Vec<Vec<u128>> = vec![Vec::with_capacity(m); m];
        for _k in 0..m {
            let evals = prepare_recovery_blinding(target_x, &helper_xs, threshold).unwrap();
            assert_eq!(evals.len(), m);
            for (j, &(xj, blind_val)) in evals.iter().enumerate() {
                assert_eq!(xj, helper_xs[j]);
                incoming_per_helper[j].push(blind_val);
            }
        }

        // Each helper j computes P'(x_j) = P(x_j) + sum_k delta_k(x_j).
        helper_shares
            .iter()
            .enumerate()
            .map(|(j, &(xj, own_share))| {
                let blinded =
                    compute_blinded_helper_share(own_share, &incoming_per_helper[j]).unwrap();
                (xj, blinded)
            })
            .collect()
    }

    #[test]
    fn test_single_share_vault_persist_and_crash_reopen() {
        let dir = TempVaultDir::new("persist_crash_reopen");
        let diversity = DiversityProfile::new(
            OsKernelFamily::OpenBsd,
            CpuArchFamily::Aarch64,
            CompilerLineage::RustcCranelift,
            "CH-ZRH-1",
        );

        let slot_a = PersistedSingleShareSlot::new(0, 0, 123_456_789).unwrap();
        let slot_b = PersistedSingleShareSlot::new(0, 5, PRIME_P - 1).unwrap();
        let slot_c = PersistedSingleShareSlot::new(2, 11, 0).unwrap();
        let slot_a_updated = PersistedSingleShareSlot::new(0, 0, (1u128 << 120) + 42).unwrap();

        let burned_pad_id: u64;
        {
            let mut vault = SingleShareVault::open_or_create(
                dir.path(),
                3, // validator x_3
                8,
                DEFAULT_RECOVERY_PAD_KEY_BYTES,
                diversity.clone(),
            )
            .unwrap();
            vault.set_compact_threshold(10);

            vault.put_slot(slot_a).unwrap();
            vault.put_slot(slot_b).unwrap();
            vault.checkpoint().unwrap();

            // Write WAL updates after checkpoint and burn one recovery OTP pad.
            vault
                .put_slots_batch(2, 4, &[slot_c])
                .unwrap();
            vault.put_slot(slot_a_updated).unwrap();

            let pad = vault.pop_recovery_pad().unwrap();
            burned_pad_id = pad.page_id;
            assert_eq!(vault.remaining_recovery_pads(), 7);
            assert_eq!(vault.pss_epoch(), 4);
            // Drop abruptly to simulate crash.
        }

        // Reopen after crash: verify all single-share slots, PSS epoch, and burned OTP pad!
        let reopened = SingleShareVault::open_or_create(
            dir.path(),
            3,
            8,
            DEFAULT_RECOVERY_PAD_KEY_BYTES,
            diversity.clone(),
        )
        .unwrap();
        assert_eq!(reopened.validator_x(), 3);
        assert_eq!(reopened.pss_epoch(), 4);
        assert_eq!(reopened.slot_count(), 3);
        assert_eq!(reopened.get_slot(0, 0), Some(slot_a_updated));
        assert_eq!(reopened.get_slot(0, 5), Some(slot_b));
        assert_eq!(reopened.get_slot(2, 11), Some(slot_c));
        assert_eq!(reopened.remaining_recovery_pads(), 7);
        assert!(reopened.pad_book().is_burned(burned_pad_id));

        // Verify Debug redacts secret shares.
        let dbg = format!("{reopened:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&slot_a_updated.share_i.to_string()));

        // Reopening with the wrong validator_x MUST fail closed.
        let err = SingleShareVault::open_or_create(
            dir.path(),
            4,
            8,
            DEFAULT_RECOVERY_PAD_KEY_BYTES,
            diversity.clone(),
        )
        .unwrap_err();
        assert!(
            matches!(err, VaultRecoveryError::SingleShareInvariantViolation(_)),
            "expected SingleShareInvariantViolation on mismatched validator_x, got {err:?}"
        );

        // Non-canonical share rejected at construction.
        assert!(matches!(
            PersistedSingleShareSlot::new(0, 0, PRIME_P),
            Err(VaultRecoveryError::NonCanonicalFieldElement)
        ));
    }

    #[test]
    fn test_herzberg_zero_reconstruction_recovery_exact_and_zero_leakage() {
        // Test both (3, 4) and (5, 7) Shamir threshold committees!
        for &(threshold, n) in &[(3usize, 4usize), (5usize, 7usize)] {
            let secret: u128 = 987_654_321_012_345_678u128;
            let all_xs: Vec<u64> = (1..=(n as u64)).collect();
            let all_shares = shamir_split(secret, &all_xs, threshold);

            // Pick target validator V_r (e.g., last validator x_r = n) who lost its share.
            let (target_x, original_target_share) = all_shares[n - 1];
            let helper_shares = &all_shares[..n - 1];

            // Run 16 independent recovery rounds to verify exactness AND uniform secret blinding.
            let mut blinded_p0_values = BTreeSet::new();
            let mut blinded_helper0_values = BTreeSet::new();

            for _round in 0..16 {
                let blinded = run_full_herzberg_blinding(target_x, helper_shares, threshold);

                // 1) Recover P(target_x) strictly at target_x (NEVER at 0).
                let recovered = recover_single_share_at_x(target_x, &blinded, threshold).unwrap();
                assert_eq!(
                    recovered, original_target_share,
                    "({threshold},{n}) recovered share must exactly match original P({target_x})"
                );

                // 2) Verify zero-leakage property: if V_r tries to interpolate the blinded helper
                //    shares at x = 0, it gets P'(0) = P(0) + Delta(0) != P(0), uniformly random!
                let blinded_p0 = lagrange_eval_at(&blinded[..threshold], 0);
                assert_ne!(
                    blinded_p0, secret,
                    "blinded polynomial P'(0) must not reveal secret P(0)"
                );
                blinded_p0_values.insert(blinded_p0);

                // 3) Each blinded helper share P'(x_j) != P(x_j) and is freshly randomized each round.
                assert_ne!(blinded[0].1, helper_shares[0].1);
                blinded_helper0_values.insert(blinded[0].1);
            }

            // Across 16 independent rounds over F_(2^127 - 1), all 16 blinded P'(0) and P'(x_1)
            // values must be strictly distinct (overwhelmingly proving uniform randomness).
            assert_eq!(blinded_p0_values.len(), 16);
            assert_eq!(blinded_helper0_values.len(), 16);

            // 4) Explicitly verify target_x == 0 is ALWAYS rejected!
            let helper_xs: Vec<u64> = helper_shares.iter().map(|&(x, _)| x).collect();
            assert!(matches!(
                prepare_recovery_blinding(0, &helper_xs, threshold),
                Err(VaultRecoveryError::InvalidTargetX)
            ));
            let blinded = run_full_herzberg_blinding(target_x, helper_shares, threshold);
            assert!(matches!(
                recover_single_share_at_x(0, &blinded, threshold),
                Err(VaultRecoveryError::InvalidTargetX)
            ));
        }
    }

    #[test]
    fn test_herzberg_recovery_catches_and_filters_byzantine_helper_share() {
        // Case 1: (3, 6) -> target_x = 6, 5 helpers {1,2,3,4,5}, f = 1 Byzantine helper (m = t + 2f = 5).
        {
            let secret = 42_000_000_000u128;
            let threshold = 3;
            let all_xs = [1u64, 2, 3, 4, 5, 6];
            let all_shares = shamir_split(secret, &all_xs, threshold);
            let (target_x, expected_share) = all_shares[5];
            let helper_shares = &all_shares[..5];

            let mut blinded = run_full_herzberg_blinding(target_x, helper_shares, threshold);

            // Corrupt helper at index 2 (x = 3) with a Byzantine delta.
            blinded[2].1 = add_mod(blinded[2].1, 999_999);

            // Strict recover_single_share_at_x MUST catch & reject the corrupted share!
            let err = recover_single_share_at_x(target_x, &blinded, threshold).unwrap_err();
            assert!(
                matches!(err, VaultRecoveryError::InconsistentShares { .. }),
                "expected InconsistentShares, got {err:?}"
            );

            // Byzantine filtering MUST identify x = 3 as Byzantine and recover exact P(6)!
            let res = recover_with_byzantine_filtering(target_x, &blinded, threshold).unwrap();
            assert_eq!(res.recovered_share, expected_share);
            assert_eq!(res.byzantine_helper_xs, vec![3]);
            assert_eq!(res.honest_helper_xs, vec![1, 2, 4, 5]);
        }

        // Case 2: (3, 8) -> target_x = 8, 7 helpers {1..=7}, f = 2 Byzantine helpers (m = t + 2f = 7).
        {
            let secret = 777_888_999_111u128;
            let threshold = 3;
            let all_xs = [1u64, 2, 3, 4, 5, 6, 7, 8];
            let all_shares = shamir_split(secret, &all_xs, threshold);
            let (target_x, expected_share) = all_shares[7];
            let helper_shares = &all_shares[..7];

            let mut blinded = run_full_herzberg_blinding(target_x, helper_shares, threshold);

            // Corrupt TWO helpers (x = 1 and x = 6).
            blinded[0].1 = add_mod(blinded[0].1, 13_371);
            blinded[5].1 = sub_mod(blinded[5].1, 55_555);

            assert!(matches!(
                recover_single_share_at_x(target_x, &blinded, threshold),
                Err(VaultRecoveryError::InconsistentShares { .. })
            ));

            let res = recover_with_byzantine_filtering(target_x, &blinded, threshold).unwrap();
            assert_eq!(res.recovered_share, expected_share);
            assert_eq!(res.byzantine_helper_xs, vec![1, 6]);
            assert_eq!(res.honest_helper_xs, vec![2, 3, 4, 5, 7]);
        }

        // Case 3: (5, 8) -> target_x = 8, 7 helpers {1..=7}, f = 1 Byzantine helper (m = t + 2f = 7).
        {
            let secret = PRIME_P - 12345;
            let threshold = 5;
            let all_xs = [1u64, 2, 3, 4, 5, 6, 7, 8];
            let all_shares = shamir_split(secret, &all_xs, threshold);
            let (target_x, expected_share) = all_shares[7];
            let helper_shares = &all_shares[..7];

            let mut blinded = run_full_herzberg_blinding(target_x, helper_shares, threshold);
            blinded[4].1 = add_mod(blinded[4].1, 1);

            let res = recover_with_byzantine_filtering(target_x, &blinded, threshold).unwrap();
            assert_eq!(res.recovered_share, expected_share);
            assert_eq!(res.byzantine_helper_xs, vec![5]);
            assert_eq!(res.honest_helper_xs, vec![1, 2, 3, 4, 6, 7]);
        }

        // Case 4: Ambiguous Byzantine count (m = 4, t = 3, f = 1 -> m < t + 2f) MUST fail closed!
        {
            let secret = 12345u128;
            let threshold = 3;
            let all_xs = [1u64, 2, 3, 4, 5];
            let all_shares = shamir_split(secret, &all_xs, threshold);
            let (target_x, _) = all_shares[4];
            let mut blinded = run_full_herzberg_blinding(target_x, &all_shares[..4], threshold);
            blinded[1].1 = add_mod(blinded[1].1, 77);

            let err = recover_with_byzantine_filtering(target_x, &blinded, threshold).unwrap_err();
            assert!(
                matches!(err, VaultRecoveryError::ByzantineRecoveryFailed { .. }),
                "ambiguous Byzantine case must fail closed, got {err:?}"
            );
        }
    }

    #[test]
    fn test_4d_diversity_profile_and_single_share_invariant_rejection() {
        // 4D committee diversity evaluation across 4 validators with threshold t = 3.
        let diverse_committee = vec![
            DiversityProfile::new(
                OsKernelFamily::Linux,
                CpuArchFamily::X86_64,
                CompilerLineage::RustcLlvm,
                "DE-FRA",
            ),
            DiversityProfile::new(
                OsKernelFamily::OpenBsd,
                CpuArchFamily::Aarch64,
                CompilerLineage::RustcCranelift,
                "CH-ZRH",
            ),
            DiversityProfile::new(
                OsKernelFamily::FreeBsd,
                CpuArchFamily::RiscV64,
                CompilerLineage::RustcGcc,
                "JP-TYO",
            ),
            DiversityProfile::new(
                OsKernelFamily::Illumos,
                CpuArchFamily::PowerPc64,
                CompilerLineage::GccRs,
                "IS-RKV",
            ),
        ];
        assert_eq!(
            diverse_committee[0].distinct_dimensions_from(&diverse_committee[1]),
            4
        );
        let report = CommitteeDiversityReport::evaluate(&diverse_committee, 3);
        assert!(report.resists_single_dimension_compromise);
        assert_eq!(report.distinct_os_kernels, 4);
        assert_eq!(report.distinct_cpu_archs, 4);
        assert_eq!(report.distinct_compilers, 4);
        assert_eq!(report.distinct_jurisdictions, 4);

        // Monoculture committee (3 Linux nodes >= threshold 3) must flag correlated risk.
        let monoculture = vec![
            diverse_committee[0].clone(),
            DiversityProfile::new(
                OsKernelFamily::Linux,
                CpuArchFamily::Aarch64,
                CompilerLineage::RustcCranelift,
                "CH-ZRH",
            ),
            DiversityProfile::new(
                OsKernelFamily::Linux,
                CpuArchFamily::RiscV64,
                CompilerLineage::RustcGcc,
                "JP-TYO",
            ),
            diverse_committee[3].clone(),
        ];
        let mono_report = CommitteeDiversityReport::evaluate(&monoculture, 3);
        assert!(!mono_report.resists_single_dimension_compromise);
        assert_eq!(mono_report.max_os_concentration, 3);

        // Single-share vault MUST reject an underlying store polluted with 2 shares in one slot!
        let dir = TempVaultDir::new("multi_share_reject");
        {
            let mut raw_store =
                CrashSafeChainStore::open(dir.path().join(CHAIN_STORE_SUBDIR)).unwrap();
            raw_store
                .append_wal(&WalDeltaEvent::ShieldedBucketUpdate {
                    bucket_id: 0,
                    pss_epoch: 1,
                    slots: vec![PersistedShieldedSlot {
                        bucket_id: 0,
                        slot_id: 0,
                        shares: vec![111, 222], // VIOLATION: peer share stored!
                    }],
                    fee_burned: 0,
                })
                .unwrap();
        }
        let err = SingleShareVault::open_or_create(
            dir.path(),
            1,
            4,
            DEFAULT_RECOVERY_PAD_KEY_BYTES,
            diverse_committee[0].clone(),
        )
        .unwrap_err();
        assert!(
            matches!(err, VaultRecoveryError::SingleShareInvariantViolation(_)),
            "expected SingleShareInvariantViolation, got {err:?}"
        );
    }
}
