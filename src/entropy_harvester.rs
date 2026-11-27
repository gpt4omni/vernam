//! Multi-Source Physical Entropy Harvester & Information-Theoretic Extractor for Vernam (VRNM).
//!
//! Zero external crates, zero computational cryptography (no SHA-256, RSA, ECDSA, AES, or ChaCha).
//! All entropy conditioning and multi-source extraction relies strictly on physical timing jitter,
//! NIST SP 800-90B continuous health & min-entropy gating, Peres/XOR-folding unbiasing, and pure
//! finite-field algebra over the Mersenne prime field `F_(2^127 - 1)`:
//!
//! - **Stage 1 (`PhysicalHarvester`)**:
//!   - [`CpuJitterHarvester`]: Reads high-resolution CPU counters (`RDTSC` on `x86_64`, `CNTVCT_EL0`
//!     on `aarch64`, monotonic `Instant` fallback elsewhere), executes a cache/pointer-chase jitter
//!     loop, extracts second-order timing deltas `Δ²t_i`, applies configurable XOR-folding + Peres
//!     iterated von Neumann unbiasing, and gates output through [`ContinuousHealthMonitor`],
//!     lag-1..8 bit autocorrelation, and conservative NIST SP 800-90B MCV/collision min-entropy
//!     estimation.
//!   - [`IoIrqJitterHarvester`]: Harvests OS scheduler / IRQ timing jitter across
//!     `std::thread::yield_now()` boundaries using monotonic clock + hardware counter deltas,
//!     XOR-folding, and identical fail-closed statistical health gating.
//!   - [`LinuxHwrngHarvester`]: Wraps [`crate::hw_entropy::LinuxHwrngSource`] for `/dev/hwrng` or
//!     external USB QRNG devices.
//!   - [`OsCsprngHarvester`]: Wraps [`crate::qkd::OsEntropySource`] as `OsCsprngFallback`
//!     (defense-in-depth only; never trusted alone when `min_physical_sources >= 1`).
//!   - [`Etsi014Harvester`]: Optional wrapper over [`crate::hw_entropy::Etsi014QkdClient`] for
//!     hardware QKD links.
//!
//! - **Stage 2 ([`MultiSourceExtractor`])**:
//!   - **Hybrid Additive + Bilinear-Toeplitz Multi-Source Extractor over `F_(2^127 - 1)`**:
//!     ```text
//!     Z_r = Σ_{j=1..M} X^(j)_{lin, r}
//!         + Σ_{1 <= a < b <= M} Σ_{c=0..d-1} X^(a)_{ext, L - 1 - r + c} · X^(b)_{ext, c}  (mod 2^127 - 1)
//!     ```
//!   - Default parameters `out_elems_l = 17` (17 × 127 = 2,159 bits → exact 256-byte / 2,048-bit
//!     OTP page) and `inner_dim_d = 64`:
//!     1. **1-of-M uniform survival (Shannon additive invariance)**: If `M - 1` sources are
//!        completely adversarial, all-zero, or backdoored constants and just 1 source is uniform,
//!        its disjoint `X_lin` additive pad guarantees uniform output `Z`.
//!     2. **0-uniform / 2-weak-source extraction (Chor-Goldreich / Dodis bilinear Toeplitz)**:
//!        Even if NO source is uniform, any two independent weak sources with sufficient collision /
//!        min-entropy produce statistically uniform output over `F_(2^127 - 1)`.
//!   - Volatile-zeroizes ALL intermediate raw source staging buffers and field vectors before
//!     returning, on every error path, and on `Drop`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::field::{add_mod, mul_mod, reduce, zeroize_slice, zeroize_u128};
use crate::hw_entropy::{
    ContinuousHealthMonitor, DEFAULT_HWRNG_PATH, DEFAULT_MAX_Z_SCORE, Etsi014QkdClient,
    HealthCheckReport, HealthMonitorConfig, HwEntropyError, LinuxHwrngSource, VRNM_QRNG_DEVICE_ENV,
};
use crate::qkd::{EntropySource, OsEntropySource, QkdError};

/// Default number of output elements in `F_(2^127 - 1)` per extracted block.
/// `17 * 127 = 2,159` bits cleanly packs into a 256-byte (2,048-bit) OTP page with zero padding bias.
pub const DEFAULT_OUT_ELEMS_L: usize = 17;

/// Default inner dimension `d` of the bilinear-Toeplitz multi-source extractor over `F_(2^127 - 1)`.
pub const DEFAULT_INNER_DIM_D: usize = 64;

/// Minimum bytes staged before running full statistical gating on small harvests.
const MIN_STAGE_BYTES: usize = 64;

/// 99% two-sided normal quantile (`z_0.995`) used by NIST SP 800-90B Section 6.3 estimators.
const NIST_Z_995: f64 = 2.5758293035489004;

/// Volatile-zeroize a slice of `u128` field elements.
#[inline(never)]
fn zeroize_u128_slice(buf: &mut [u128]) {
    for v in buf.iter_mut() {
        zeroize_u128(v);
    }
}

/// Read the highest-resolution unprivileged CPU hardware counter available on this architecture.
///
/// - `x86_64`: `RDTSC` via `core::arch::x86_64::_rdtsc()`.
/// - `aarch64`: architectural virtual timer `CNTVCT_EL0` via inline assembly.
/// - Other targets: monotonic nanosecond timestamp via `std::time::Instant`.
#[inline(always)]
fn read_hw_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: `RDTSC` is an unprivileged architectural instruction on all x86_64 processors.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let cnt: u64;
        // SAFETY: `cntvct_el0` is readable from EL0 on AArch64 Linux without privilege escalation.
        unsafe {
            core::arch::asm!(
                "mrs {cnt}, cntvct_el0",
                cnt = out(reg) cnt,
                options(nomem, nostack, preserves_flags),
            );
        }
        cnt
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        use std::sync::OnceLock;
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        let origin = EPOCH.get_or_init(Instant::now);
        origin.elapsed().as_nanos() as u64
    }
}

// ============================================================================
// 1. Core Classification, Telemetry & PhysicalHarvester Trait
// ============================================================================

/// Physical provenance classification of an entropy harvester.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntropySourceKind {
    /// CPU microarchitectural timing jitter (cache/pipeline/branch/PLL noise).
    CpuTimingJitter,
    /// OS scheduler, syscall, and hardware IRQ timing jitter.
    IoIrqTimingJitter,
    /// Platform hardware RNG character device (e.g., `/dev/hwrng`, TPM/SoC TRNG).
    PlatformHwrng,
    /// Dedicated external hardware Quantum RNG (e.g., USB QRNG `/dev/TrueRNG`).
    ExternalQrng,
    /// ETSI GS QKD 014 optical/satellite QKD Key Management Entity link.
    Etsi014Qkd,
    /// Operating-system CSPRNG (`/dev/urandom`); defense-in-depth only, never trusted alone.
    OsCsprngFallback,
}

impl EntropySourceKind {
    /// Returns `true` if this source harvests physical/hardware entropy rather than an OS CSPRNG.
    #[inline]
    pub const fn is_physical(self) -> bool {
        !matches!(self, EntropySourceKind::OsCsprngFallback)
    }
}

impl fmt::Display for EntropySourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            EntropySourceKind::CpuTimingJitter => "cpu-timing-jitter",
            EntropySourceKind::IoIrqTimingJitter => "io-irq-timing-jitter",
            EntropySourceKind::PlatformHwrng => "platform-hwrng",
            EntropySourceKind::ExternalQrng => "external-qrng",
            EntropySourceKind::Etsi014Qkd => "etsi014-qkd",
            EntropySourceKind::OsCsprngFallback => "os-csprng-fallback",
        };
        f.write_str(label)
    }
}

/// Health and min-entropy telemetry snapshot for a single Stage-1 harvester.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceEntropyReport {
    /// Human-readable source identifier.
    pub name: String,
    /// Provenance classification.
    pub kind: EntropySourceKind,
    /// Whether this source is currently healthy (no latched health fault).
    pub healthy: bool,
    /// Cumulative verified bytes harvested from this source.
    pub bytes_harvested: u64,
    /// Conservative NIST SP 800-90B min-entropy estimate in bits per byte (`[0.0, 8.0]`).
    pub min_entropy_bits_per_byte: f64,
    /// Maximum absolute lag-1..8 bit autocorrelation `|r_k|` observed in the most recent harvest.
    pub max_lag_autocorrelation: f64,
    /// Most recent NIST SP 800-90B continuous health report, if at least one harvest completed.
    pub last_health: Option<HealthCheckReport>,
    /// Most recent error message if the source faulted or degraded.
    pub last_error: Option<String>,
}

/// Aggregated health snapshot across all Stage-1 sources and Stage-2 output gating.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractorHealthSnapshot {
    /// Individual telemetry reports for every registered source.
    pub sources: Vec<SourceEntropyReport>,
    /// Count of currently healthy registered sources (physical + fallback).
    pub healthy_sources: usize,
    /// Count of currently healthy physical sources (excluding `OsCsprngFallback`).
    pub healthy_physical_sources: usize,
    /// Total Stage-2 field blocks extracted.
    pub total_blocks_extracted: u64,
    /// Total extracted bytes delivered.
    pub total_bytes_extracted: u64,
    /// Whether the Stage-2 output continuous health monitor is healthy.
    pub output_healthy: bool,
    /// Most recent Stage-2 output health report, if any.
    pub last_output_health: Option<HealthCheckReport>,
}

/// Stage-1 physical (or defense-in-depth fallback) entropy harvester trait.
pub trait PhysicalHarvester: Send {
    /// Human-readable source name.
    fn name(&self) -> &str;

    /// Physical provenance classification of this harvester.
    fn kind(&self) -> EntropySourceKind;

    /// Fill `buf` completely with Stage-1 conditioned and health-gated bytes.
    ///
    /// Implementors MUST volatile-zeroize `buf` before returning `Err`.
    fn harvest(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError>;

    /// Return current health, autocorrelation, and min-entropy telemetry for this source.
    fn health_report(&self) -> SourceEntropyReport;
}

// ============================================================================
// 2. Stage-1 Pure-Math Unbiasing & Statistical Gating Helpers
// ============================================================================

/// Pure information-theoretic **Peres (1992) iterated von Neumann unbiasing** over a bit slice
/// (`0u8` / `1u8` entries).
///
/// For any memoryless biased Bernoulli(`p`) source with `0 < p < 1`, every emitted bit is
/// **exact 50/50 uniform**, with asymptotic extraction rate approaching Shannon entropy `h_2(p)`
/// as `max_depth` increases — using zero computational cryptography.
pub fn peres_extract_bits(raw_bits: &[u8], max_depth: usize, out_bits: &mut Vec<u8>) {
    if raw_bits.len() < 2 {
        return;
    }
    let pairs = raw_bits.len() / 2;
    let mut u_stream = if max_depth > 0 {
        Vec::with_capacity(pairs)
    } else {
        Vec::new()
    };
    let mut v_stream = if max_depth > 0 {
        Vec::with_capacity(pairs)
    } else {
        Vec::new()
    };

    for i in 0..pairs {
        let a = raw_bits[2 * i] & 1;
        let b = raw_bits[2 * i + 1] & 1;
        if a != b {
            out_bits.push(a);
            if max_depth > 0 {
                u_stream.push(1);
            }
        } else if max_depth > 0 {
            u_stream.push(0);
            v_stream.push(a);
        }
    }

    if max_depth > 0 {
        if u_stream.len() >= 2 {
            peres_extract_bits(&u_stream, max_depth - 1, out_bits);
        }
        if v_stream.len() >= 2 {
            peres_extract_bits(&v_stream, max_depth - 1, out_bits);
        }
        zeroize_slice(&mut u_stream);
        zeroize_slice(&mut v_stream);
    }
}

/// Compute the maximum absolute lag-`1..=max_lag` bit autocorrelation `(max_abs_r, max_z)`
/// across `data` (LSB-first bit order).
///
/// For lag `k` over `M = total_bits - k` bit pairs:
/// `r_k = (2 * matches - M) / M` and `z_k = |r_k| * sqrt(M)`.
pub fn max_lag_bit_autocorrelation(data: &[u8], max_lag: usize) -> (f64, f64) {
    let total_bits = data.len() * 8;
    if total_bits <= 1 || max_lag == 0 {
        return (0.0, 0.0);
    }
    let limit_lag = max_lag.min(total_bits - 1);
    let mut max_abs_r = 0.0f64;
    let mut max_z = 0.0f64;

    for lag in 1..=limit_lag {
        let m = total_bits - lag;
        let mut matches = 0usize;
        for i in 0..m {
            let b0 = (data[i >> 3] >> (i & 7)) & 1;
            let j = i + lag;
            let b1 = (data[j >> 3] >> (j & 7)) & 1;
            if b0 == b1 {
                matches += 1;
            }
        }
        let m_f = m as f64;
        let r = ((2.0 * matches as f64) - m_f) / m_f;
        let abs_r = r.abs();
        let z = abs_r * m_f.sqrt();
        if abs_r > max_abs_r {
            max_abs_r = abs_r;
        }
        if z > max_z {
            max_z = z;
        }
    }

    (max_abs_r, max_z)
}

/// Conservative NIST SP 800-90B min-entropy estimator in **bits per byte** (`[0.0, 8.0]`), taking
/// the minimum of:
/// 1. Section 6.3.1 Most Common Value (MCV) estimator on byte symbols (`0..=255`),
/// 2. Section 6.3.1 Most Common Value (MCV) estimator on individual bits (× 8),
/// 3. Section 6.3.2 Binary Collision estimator on consecutive bit-collision times (× 8).
pub fn estimate_min_entropy_bits_per_byte(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    // 1. Byte-level MCV (NIST SP 800-90B Section 6.3.1).
    let mut counts = [0usize; 256];
    let mut ones = 0usize;
    for &b in data {
        counts[b as usize] += 1;
        ones += b.count_ones() as usize;
    }
    let max_byte_count = counts.iter().copied().max().unwrap_or(data.len());
    let l_bytes = data.len() as f64;
    let p_hat_byte = max_byte_count as f64 / l_bytes;
    let p_u_byte = (p_hat_byte
        + NIST_Z_995 * ((p_hat_byte * (1.0 - p_hat_byte)) / (l_bytes - 1.0)).sqrt())
    .min(1.0);
    let h_mcv_byte = if p_u_byte >= 1.0 {
        0.0
    } else {
        -p_u_byte.log2()
    };

    // 2. Bit-level MCV (NIST SP 800-90B Section 6.3.1), scaled to bits per byte.
    let n_bits = (data.len() * 8) as f64;
    let max_bit_count = ones.max(data.len() * 8 - ones) as f64;
    let p_hat_bit = max_bit_count / n_bits;
    let p_u_bit = (p_hat_bit
        + NIST_Z_995 * ((p_hat_bit * (1.0 - p_hat_bit)) / (n_bits - 1.0)).sqrt())
    .min(1.0);
    let h_mcv_bit_per_byte = if p_u_bit >= 1.0 {
        0.0
    } else {
        -8.0 * p_u_bit.log2()
    };

    // 3. Binary Collision Estimator (NIST SP 800-90B Section 6.3.2), scaled to bits per byte.
    //    Partition bits into non-overlapping collision intervals t_j in {2, 3}:
    //      b_i == b_{i+1} => t_j = 2 (advance 2)
    //      b_i != b_{i+1} => t_j = 3 (advance 3, since b_{i+2} must match b_i or b_{i+1})
    //    For Bernoulli(p), E[t] = 2 + 2p(1 - p) in [2.0, 2.5].
    let total_bits = data.len() * 8;
    let bit_at = |idx: usize| -> u8 { (data[idx >> 3] >> (idx & 7)) & 1 };
    let mut i = 0usize;
    let mut v_count = 0usize;
    let mut t2_count = 0usize;
    let mut t3_count = 0usize;
    while i + 1 < total_bits {
        if bit_at(i) == bit_at(i + 1) {
            t2_count += 1;
            v_count += 1;
            i += 2;
        } else if i + 2 < total_bits {
            t3_count += 1;
            v_count += 1;
            i += 3;
        } else {
            break;
        }
    }

    let h_coll_per_byte = if v_count >= 2 {
        let vf = v_count as f64;
        let mean = (2.0 * t2_count as f64 + 3.0 * t3_count as f64) / vf;
        let var = ((t2_count as f64) * (2.0 - mean).powi(2)
            + (t3_count as f64) * (3.0 - mean).powi(2))
            / (vf - 1.0);
        let sigma = var.max(0.0).sqrt();
        let x_prime = mean - NIST_Z_995 * (sigma / vf.sqrt());
        if x_prime >= 2.5 {
            8.0
        } else if x_prime <= 2.0 {
            0.0
        } else {
            let disc = (5.0 - 2.0 * x_prime).max(0.0).sqrt();
            let p = (0.5 * (1.0 + disc)).clamp(0.5, 1.0);
            if p >= 1.0 { 0.0 } else { -8.0 * p.log2() }
        }
    } else {
        0.0
    };

    h_mcv_byte
        .min(h_mcv_bit_per_byte)
        .min(h_coll_per_byte)
        .clamp(0.0, 8.0)
}

/// Shared Stage-1 gate combining [`ContinuousHealthMonitor`], lag-1..8 bit autocorrelation, and
/// conservative NIST SP 800-90B MCV/collision min-entropy estimation.
#[derive(Debug, Clone)]
struct Stage1Gate {
    monitor: ContinuousHealthMonitor,
    max_autocorr_z: f64,
    min_entropy_bits_per_byte: f64,
    bytes_harvested: u64,
    last_min_entropy: f64,
    last_max_autocorr: f64,
    last_health: Option<HealthCheckReport>,
    last_error: Option<String>,
}

impl Stage1Gate {
    fn new(
        health_config: HealthMonitorConfig,
        max_autocorr_z: f64,
        min_entropy_bits_per_byte: f64,
    ) -> Self {
        Self {
            monitor: ContinuousHealthMonitor::with_config(health_config),
            max_autocorr_z: if max_autocorr_z.is_finite() && max_autocorr_z > 0.0 {
                max_autocorr_z
            } else {
                DEFAULT_MAX_Z_SCORE
            },
            min_entropy_bits_per_byte: if min_entropy_bits_per_byte.is_finite()
                && min_entropy_bits_per_byte >= 0.0
            {
                min_entropy_bits_per_byte.min(8.0)
            } else {
                1.5
            },
            bytes_harvested: 0,
            last_min_entropy: 0.0,
            last_max_autocorr: 0.0,
            last_health: None,
            last_error: None,
        }
    }

    fn is_healthy(&self) -> bool {
        self.monitor.is_healthy() && self.last_error.is_none()
    }

    fn gate_and_record(&mut self, buf: &mut [u8]) -> Result<HealthCheckReport, HwEntropyError> {
        let report = match self.monitor.gate(buf) {
            Ok(r) => r,
            Err(err) => {
                self.last_error = Some(err.to_string());
                return Err(err);
            }
        };

        let (max_r, max_z) = max_lag_bit_autocorrelation(buf, 8);
        self.last_max_autocorr = max_r;
        if buf.len() >= 32 && max_z > self.max_autocorr_z {
            let err = HwEntropyError::HealthCheckFailed {
                test: "AUTOCORR_LAG8",
                ones: report.ones,
                total_bits: report.total_bits,
                reason: format!(
                    "lag-1..8 bit autocorrelation fault: max |r|={max_r:.4}, z={max_z:.2} > {:.2}",
                    self.max_autocorr_z
                ),
            };
            zeroize_slice(buf);
            self.last_error = Some(err.to_string());
            return Err(err);
        }

        let h_min = estimate_min_entropy_bits_per_byte(buf);
        self.last_min_entropy = h_min;
        if buf.len() >= MIN_STAGE_BYTES && h_min < self.min_entropy_bits_per_byte {
            let err = HwEntropyError::HealthCheckFailed {
                test: "MIN_ENTROPY_90B",
                ones: report.ones,
                total_bits: report.total_bits,
                reason: format!(
                    "NIST SP 800-90B min-entropy below threshold: {h_min:.3} < {:.3} bits/byte",
                    self.min_entropy_bits_per_byte
                ),
            };
            zeroize_slice(buf);
            self.last_error = Some(err.to_string());
            return Err(err);
        }

        self.bytes_harvested = self.bytes_harvested.saturating_add(buf.len() as u64);
        self.last_health = Some(report);
        self.last_error = None;
        Ok(report)
    }

    fn report(&self, name: &str, kind: EntropySourceKind) -> SourceEntropyReport {
        SourceEntropyReport {
            name: name.to_string(),
            kind,
            healthy: self.is_healthy(),
            bytes_harvested: self.bytes_harvested,
            min_entropy_bits_per_byte: self.last_min_entropy,
            max_lag_autocorrelation: self.last_max_autocorr,
            last_health: self.last_health,
            last_error: self.last_error.clone(),
        }
    }
}

// ============================================================================
// 3. Stage-1 Physical Harvesters (CPU Jitter, I/O-IRQ Jitter, HWRNG, OS, ETSI)
// ============================================================================

/// Configuration for [`CpuJitterHarvester`].
#[derive(Debug, Clone)]
pub struct CpuJitterConfig {
    /// Number of second-order timing delta samples XOR-folded per raw bit before Peres unbiasing
    /// (default: `4`).
    pub fold_factor: usize,
    /// Power-of-two memory scratch size in bytes for cache/pointer-chase jitter (default: `4096`).
    pub scratch_bytes: usize,
    /// Number of dependent pointer-chase memory accesses per timing measurement (default: `16`).
    pub chase_steps: usize,
    /// Recursion depth for Peres iterated von Neumann unbiasing (`0` = classic von Neumann,
    /// default: `3`).
    pub peres_depth: usize,
    /// Continuous NIST SP 800-90B health monitor thresholds.
    pub health_config: HealthMonitorConfig,
    /// Maximum allowed lag-1..8 bit autocorrelation z-score (default: `6.0`).
    pub max_autocorr_z: f64,
    /// Minimum required conservative NIST SP 800-90B min-entropy in bits/byte (default: `1.5`).
    pub min_entropy_bits_per_byte: f64,
}

impl Default for CpuJitterConfig {
    fn default() -> Self {
        Self {
            fold_factor: 8,
            scratch_bytes: 65_536,
            chase_steps: 32,
            peres_depth: 2,
            health_config: HealthMonitorConfig::default(),
            max_autocorr_z: DEFAULT_MAX_Z_SCORE,
            min_entropy_bits_per_byte: 1.5,
        }
    }
}

/// Real zero-dependency CPU microarchitectural timing-jitter harvester.
///
/// Executes a data-dependent cache/pointer-chase loop, reads the CPU's high-resolution cycle
/// counter (`RDTSC` on `x86_64`, `CNTVCT_EL0` on `aarch64`, monotonic `Instant` fallback),
/// computes second-order timing deltas `Δ²t_i`, XOR-folds `fold_factor` samples, applies Peres
/// iterated von Neumann unbiasing, and gates every output chunk through NIST SP 800-90B health,
/// lag-1..8 autocorrelation, and MCV/collision min-entropy checks.
pub struct CpuJitterHarvester {
    name: String,
    config: CpuJitterConfig,
    scratch: Vec<u8>,
    cursor: usize,
    last_t: u64,
    last_delta: u64,
    staging: Vec<u8>,
    gate: Stage1Gate,
}

impl fmt::Debug for CpuJitterHarvester {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpuJitterHarvester")
            .field("name", &self.name)
            .field("fold_factor", &self.config.fold_factor)
            .field("scratch_bytes", &self.scratch.len())
            .field("chase_steps", &self.config.chase_steps)
            .field("healthy", &self.gate.is_healthy())
            .finish()
    }
}

impl CpuJitterHarvester {
    /// Create a new CPU timing jitter harvester with default parameters.
    pub fn new() -> Self {
        Self::with_config(CpuJitterConfig::default())
    }

    /// Create a new CPU timing jitter harvester with an explicit `fold_factor`.
    pub fn with_fold_factor(fold_factor: usize) -> Self {
        let cfg = CpuJitterConfig {
            fold_factor: fold_factor.max(1),
            ..CpuJitterConfig::default()
        };
        Self::with_config(cfg)
    }

    /// Create a new CPU timing jitter harvester with custom configuration.
    pub fn with_config(mut config: CpuJitterConfig) -> Self {
        config.fold_factor = config.fold_factor.max(1);
        config.chase_steps = config.chase_steps.max(4);
        let scratch_len = config.scratch_bytes.max(256).next_power_of_two();
        config.scratch_bytes = scratch_len;

        // Seed scratch memory with a non-trivial permutation pattern so initial pointer-chasing
        // traverses distinct cache lines immediately.
        let mut scratch = vec![0u8; scratch_len];
        for (i, slot) in scratch.iter_mut().enumerate() {
            *slot = ((i.wrapping_mul(73) ^ (i >> 3) ^ 0xA5) & 0xFF) as u8;
        }

        let gate = Stage1Gate::new(
            config.health_config,
            config.max_autocorr_z,
            config.min_entropy_bits_per_byte,
        );

        let mut harvester = Self {
            name: "cpu-timing-jitter".to_string(),
            config,
            scratch,
            cursor: 0,
            last_t: 0,
            last_delta: 0,
            staging: vec![0u8; MIN_STAGE_BYTES],
            gate,
        };

        // Auto-calibrate `chase_steps` so coarse hardware counters (e.g. 24-50 MHz aarch64
        // `CNTVCT_EL0`) advance by at least several ticks per measurement instead of quantizing
        // to zero-delta runs.
        for _ in 0..8 {
            let mut non_zero_ticks = 0usize;
            let mut prev = harvester.jitter_work_step();
            for _ in 0..16 {
                let cur = harvester.jitter_work_step();
                if cur.wrapping_sub(prev) >= 2 {
                    non_zero_ticks += 1;
                }
                prev = cur;
            }
            if non_zero_ticks >= 12 || harvester.config.chase_steps >= 2048 {
                break;
            }
            harvester.config.chase_steps = (harvester.config.chase_steps * 2).min(2048);
        }

        // Prime second-order timing delta state with two warm-up measurements.
        let t0 = harvester.jitter_work_step();
        let t1 = harvester.jitter_work_step();
        harvester.last_delta = t1.wrapping_sub(t0);
        harvester.last_t = t1;
        harvester
    }

    #[inline(never)]
    fn jitter_work_step(&mut self) -> u64 {
        let mask = self.scratch.len() - 1;
        let mut idx = self.cursor & mask;
        let mut acc = 0u8;
        for step in 0..self.config.chase_steps {
            let next_idx = (idx.wrapping_add(67).wrapping_add(self.scratch[idx] as usize)) & mask;
            let val = self.scratch[next_idx].wrapping_add((step as u8).wrapping_mul(29) ^ 0x5A);
            self.scratch[idx] = val;
            acc = acc.wrapping_add(val);
            idx = next_idx;
        }
        self.cursor = idx ^ (acc as usize);
        core::hint::black_box(acc);
        read_hw_counter()
    }

    #[inline]
    fn next_delta2(&mut self) -> u64 {
        let t = self.jitter_work_step();
        let delta = t.wrapping_sub(self.last_t);
        let delta2 = delta.wrapping_sub(self.last_delta);
        self.last_t = t;
        self.last_delta = delta;
        delta2
    }

    #[inline]
    fn next_folded_bit(&mut self) -> u8 {
        let mut bit = 0u8;
        for _ in 0..self.config.fold_factor {
            let d2 = self.next_delta2();
            // Low-16-bit XOR parity captures single-bit jitter across all fine counter scales
            // (both high-rate x86_64 RDTSC and coarser aarch64 CNTVCT_EL0 ticks).
            bit ^= ((d2 & 0xFFFF).count_ones() & 1) as u8;
        }
        bit
    }

    fn harvest_raw_unbiased(&mut self, dst: &mut [u8]) -> Result<(), HwEntropyError> {
        let needed_bits = dst.len() * 8;
        // Collect 2x unbiased bits and XOR halves separated by `needed_bits` in time so any
        // short-range microarchitectural/thermal lag-1 autocorrelation collapses quadratically.
        let target_bits = needed_bits * 2;
        let mut unbiased_bits = Vec::with_capacity(target_bits + 256);
        let mut raw_batch = Vec::with_capacity(512);

        // Cap retries so a frozen/virtualized constant counter fails closed rather than spinning.
        let max_rounds = (dst.len().max(1) * 32).max(128);
        let mut rounds = 0usize;

        while unbiased_bits.len() < target_bits {
            rounds += 1;
            if rounds > max_rounds {
                zeroize_slice(&mut raw_batch);
                zeroize_slice(&mut unbiased_bits);
                zeroize_slice(dst);
                let err = HwEntropyError::HealthCheckFailed {
                    test: "CPU_JITTER_STALLED",
                    ones: 0,
                    total_bits: needed_bits,
                    reason: "CPU counter produced insufficient timing variance for Peres unbiasing"
                        .into(),
                };
                self.gate.last_error = Some(err.to_string());
                return Err(err);
            }

            let remaining = target_bits - unbiased_bits.len();
            let batch_len = (remaining * 2).clamp(128, 1024);
            raw_batch.clear();
            for _ in 0..batch_len {
                raw_batch.push(self.next_folded_bit());
            }
            peres_extract_bits(&raw_batch, self.config.peres_depth, &mut unbiased_bits);
            zeroize_slice(&mut raw_batch);
        }

        for (byte_idx, slot) in dst.iter_mut().enumerate() {
            let base = byte_idx * 8;
            let mut b = 0u8;
            for bit_pos in 0..8 {
                let idx = base + bit_pos;
                let decorrelated = (unbiased_bits[idx] ^ unbiased_bits[idx + needed_bits]) & 1;
                b |= decorrelated << bit_pos;
            }
            *slot = b;
        }
        zeroize_slice(&mut unbiased_bits);
        Ok(())
    }
}

impl Default for CpuJitterHarvester {
    fn default() -> Self {
        Self::new()
    }
}

impl PhysicalHarvester for CpuJitterHarvester {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> EntropySourceKind {
        EntropySourceKind::CpuTimingJitter
    }

    fn harvest(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError> {
        if buf.is_empty() {
            return Ok(());
        }
        if buf.len() < MIN_STAGE_BYTES {
            let mut tmp = vec![0u8; MIN_STAGE_BYTES];
            if let Err(err) = self.harvest_raw_unbiased(&mut tmp) {
                zeroize_slice(&mut tmp);
                zeroize_slice(buf);
                return Err(err);
            }
            if let Err(err) = self.gate.gate_and_record(&mut tmp) {
                zeroize_slice(&mut tmp);
                zeroize_slice(buf);
                return Err(err);
            }
            buf.copy_from_slice(&tmp[..buf.len()]);
            zeroize_slice(&mut tmp);
            return Ok(());
        }

        self.harvest_raw_unbiased(buf)?;
        self.gate.gate_and_record(buf)?;
        Ok(())
    }

    fn health_report(&self) -> SourceEntropyReport {
        self.gate.report(&self.name, EntropySourceKind::CpuTimingJitter)
    }
}

impl Drop for CpuJitterHarvester {
    fn drop(&mut self) {
        zeroize_slice(&mut self.scratch);
        zeroize_slice(&mut self.staging);
    }
}

/// Configuration for [`IoIrqJitterHarvester`].
#[derive(Debug, Clone)]
pub struct IoIrqJitterConfig {
    /// Number of `yield_now()` scheduler/IRQ timing samples XOR-folded per byte (default: `4`).
    pub fold_factor: usize,
    /// Continuous NIST SP 800-90B health monitor thresholds.
    pub health_config: HealthMonitorConfig,
    /// Maximum allowed lag-1..8 bit autocorrelation z-score (default: `6.0`).
    pub max_autocorr_z: f64,
    /// Minimum required conservative NIST SP 800-90B min-entropy in bits/byte (default: `1.5`).
    pub min_entropy_bits_per_byte: f64,
}

impl Default for IoIrqJitterConfig {
    fn default() -> Self {
        Self {
            fold_factor: 4,
            health_config: HealthMonitorConfig::default(),
            max_autocorr_z: DEFAULT_MAX_Z_SCORE,
            min_entropy_bits_per_byte: 1.5,
        }
    }
}

/// Real zero-dependency OS scheduler & IRQ timing-jitter harvester.
///
/// Measures second-order timing deltas (`Δ²t_i`) across `std::thread::yield_now()` kernel
/// scheduling transitions using both the OS monotonic clock (`Instant::now()`) and the hardware
/// cycle counter (`read_hw_counter()`), applies rotating XOR-folding, and gates every harvest
/// through [`ContinuousHealthMonitor`], lag-1..8 autocorrelation, and NIST SP 800-90B min-entropy
/// estimation.
pub struct IoIrqJitterHarvester {
    name: String,
    config: IoIrqJitterConfig,
    epoch: Instant,
    last_d_mono: u64,
    last_d_hw: u64,
    staging: Vec<u8>,
    gate: Stage1Gate,
}

impl fmt::Debug for IoIrqJitterHarvester {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoIrqJitterHarvester")
            .field("name", &self.name)
            .field("fold_factor", &self.config.fold_factor)
            .field("healthy", &self.gate.is_healthy())
            .finish()
    }
}

impl IoIrqJitterHarvester {
    /// Create a new OS scheduler / IRQ timing jitter harvester with default parameters.
    pub fn new() -> Self {
        Self::with_config(IoIrqJitterConfig::default())
    }

    /// Create a new OS scheduler / IRQ timing jitter harvester with an explicit `fold_factor`.
    pub fn with_fold_factor(fold_factor: usize) -> Self {
        let cfg = IoIrqJitterConfig {
            fold_factor: fold_factor.max(1),
            ..IoIrqJitterConfig::default()
        };
        Self::with_config(cfg)
    }

    /// Create a new OS scheduler / IRQ timing jitter harvester with custom configuration.
    pub fn with_config(mut config: IoIrqJitterConfig) -> Self {
        config.fold_factor = config.fold_factor.max(1);
        let gate = Stage1Gate::new(
            config.health_config,
            config.max_autocorr_z,
            config.min_entropy_bits_per_byte,
        );
        let epoch = Instant::now();
        let mut h = Self {
            name: "io-irq-timing-jitter".to_string(),
            config,
            epoch,
            last_d_mono: 0,
            last_d_hw: 0,
            staging: vec![0u8; MIN_STAGE_BYTES],
            gate,
        };
        // Prime first-order timing delta state.
        let _ = h.next_yield_delta2();
        h
    }

    #[inline]
    fn next_yield_delta2(&mut self) -> (u64, u64) {
        let m0 = self.epoch.elapsed().as_nanos() as u64;
        let c0 = read_hw_counter();
        std::thread::yield_now();
        let m1 = self.epoch.elapsed().as_nanos() as u64;
        let c1 = read_hw_counter();

        let dm = m1.wrapping_sub(m0);
        let dc = c1.wrapping_sub(c0);
        let d2m = dm.wrapping_sub(self.last_d_mono);
        let d2c = dc.wrapping_sub(self.last_d_hw);
        self.last_d_mono = dm;
        self.last_d_hw = dc;
        (d2m, d2c)
    }

    fn fill_raw_folded(&mut self, dst: &mut [u8]) {
        let needed_bits = dst.len() * 8;
        let target_bits = needed_bits * 2;
        let mut unbiased_bits = Vec::with_capacity(target_bits + 128);
        let mut raw_batch = Vec::with_capacity(512);
        let max_rounds = (dst.len().max(1) * 32).max(128);
        let mut rounds = 0usize;

        while unbiased_bits.len() < target_bits && rounds < max_rounds {
            rounds += 1;
            let remaining = target_bits - unbiased_bits.len();
            let batch_len = (remaining * 2).clamp(128, 1024);
            raw_batch.clear();
            for _ in 0..batch_len {
                let mut bit = 0u8;
                for _ in 0..self.config.fold_factor.min(2).max(1) {
                    let (d2m, d2c) = self.next_yield_delta2();
                    let mixed = d2m ^ d2c.rotate_left(13);
                    bit ^= ((mixed & 0xFFFF_FFFF).count_ones() & 1) as u8;
                }
                raw_batch.push(bit);
            }
            peres_extract_bits(&raw_batch, 2, &mut unbiased_bits);
            zeroize_slice(&mut raw_batch);
        }

        if unbiased_bits.len() < target_bits {
            zeroize_slice(&mut unbiased_bits);
            zeroize_slice(dst);
            return;
        }
        for (byte_idx, slot) in dst.iter_mut().enumerate() {
            let base = byte_idx * 8;
            let mut b = 0u8;
            for bit_pos in 0..8 {
                let idx = base + bit_pos;
                let decorrelated = (unbiased_bits[idx] ^ unbiased_bits[idx + needed_bits]) & 1;
                b |= decorrelated << bit_pos;
            }
            *slot = b;
        }
        zeroize_slice(&mut unbiased_bits);
    }
}

impl Default for IoIrqJitterHarvester {
    fn default() -> Self {
        Self::new()
    }
}

impl PhysicalHarvester for IoIrqJitterHarvester {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> EntropySourceKind {
        EntropySourceKind::IoIrqTimingJitter
    }

    fn harvest(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError> {
        if buf.is_empty() {
            return Ok(());
        }
        if buf.len() < MIN_STAGE_BYTES {
            let mut tmp = vec![0u8; MIN_STAGE_BYTES];
            self.fill_raw_folded(&mut tmp);
            if let Err(err) = self.gate.gate_and_record(&mut tmp) {
                zeroize_slice(&mut tmp);
                zeroize_slice(buf);
                return Err(err);
            }
            buf.copy_from_slice(&tmp[..buf.len()]);
            zeroize_slice(&mut tmp);
            return Ok(());
        }

        self.fill_raw_folded(buf);
        self.gate.gate_and_record(buf)?;
        Ok(())
    }

    fn health_report(&self) -> SourceEntropyReport {
        self.gate
            .report(&self.name, EntropySourceKind::IoIrqTimingJitter)
    }
}

impl Drop for IoIrqJitterHarvester {
    fn drop(&mut self) {
        zeroize_slice(&mut self.staging);
    }
}

/// Stage-1 harvester wrapping [`crate::hw_entropy::LinuxHwrngSource`] (`/dev/hwrng` or USB QRNG).
#[derive(Debug)]
pub struct LinuxHwrngHarvester {
    name: String,
    kind: EntropySourceKind,
    inner: LinuxHwrngSource,
    gate: Stage1Gate,
}

impl LinuxHwrngHarvester {
    /// Open `/dev/hwrng` as a `PlatformHwrng` harvester.
    pub fn open_default() -> Result<Self, HwEntropyError> {
        Self::open(DEFAULT_HWRNG_PATH)
    }

    /// Open a hardware RNG / USB QRNG device at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, HwEntropyError> {
        let src = LinuxHwrngSource::open(path)?;
        Ok(Self::from_source(src))
    }

    /// Wrap an already-opened [`LinuxHwrngSource`].
    pub fn from_source(inner: LinuxHwrngSource) -> Self {
        let name = format!("linux-hwrng({})", inner.device_path().display());
        Self {
            name,
            kind: EntropySourceKind::PlatformHwrng,
            inner,
            gate: Stage1Gate::new(HealthMonitorConfig::default(), DEFAULT_MAX_Z_SCORE, 1.5),
        }
    }

    /// Override the classification (e.g., [`EntropySourceKind::ExternalQrng`] for USB QRNGs).
    pub fn with_kind(mut self, kind: EntropySourceKind) -> Self {
        self.kind = kind;
        self
    }

    /// Borrow the underlying [`LinuxHwrngSource`].
    pub fn inner(&self) -> &LinuxHwrngSource {
        &self.inner
    }
}

impl PhysicalHarvester for LinuxHwrngHarvester {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> EntropySourceKind {
        self.kind
    }

    fn harvest(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError> {
        if buf.is_empty() {
            return Ok(());
        }
        if let Err(err) = self.inner.fill_checked(buf) {
            zeroize_slice(buf);
            self.gate.last_error = Some(err.to_string());
            return Err(err);
        }
        self.gate.gate_and_record(buf)?;
        Ok(())
    }

    fn health_report(&self) -> SourceEntropyReport {
        let mut r = self.gate.report(&self.name, self.kind);
        r.healthy = r.healthy && self.inner.is_healthy();
        if r.last_error.is_none() {
            r.last_error = self.inner.last_fault().map(ToString::to_string);
        }
        r
    }
}

/// Stage-1 harvester wrapping [`crate::qkd::OsEntropySource`] (`/dev/urandom`).
///
/// Explicitly classified as [`EntropySourceKind::OsCsprngFallback`] so [`MultiSourceExtractor`]
/// NEVER relies on it alone when `min_physical_sources >= 1`.
#[derive(Debug)]
pub struct OsCsprngHarvester {
    name: String,
    inner: OsEntropySource,
    gate: Stage1Gate,
}

impl OsCsprngHarvester {
    /// Create a new OS CSPRNG defense-in-depth harvester.
    pub fn new() -> Self {
        Self::with_health_config(HealthMonitorConfig::default())
    }

    /// Create a new OS CSPRNG harvester with custom health thresholds.
    pub fn with_health_config(health_config: HealthMonitorConfig) -> Self {
        Self {
            name: "os-csprng-fallback".to_string(),
            inner: OsEntropySource::new(),
            gate: Stage1Gate::new(health_config, DEFAULT_MAX_Z_SCORE, 1.5),
        }
    }
}

impl Default for OsCsprngHarvester {
    fn default() -> Self {
        Self::new()
    }
}

impl PhysicalHarvester for OsCsprngHarvester {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> EntropySourceKind {
        EntropySourceKind::OsCsprngFallback
    }

    fn harvest(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError> {
        if buf.is_empty() {
            return Ok(());
        }
        if let Err(err) = self.inner.fill_random(buf) {
            zeroize_slice(buf);
            let hw_err = HwEntropyError::Io(err.to_string());
            self.gate.last_error = Some(hw_err.to_string());
            return Err(hw_err);
        }
        self.gate.gate_and_record(buf)?;
        Ok(())
    }

    fn health_report(&self) -> SourceEntropyReport {
        self.gate
            .report(&self.name, EntropySourceKind::OsCsprngFallback)
    }
}

/// Stage-1 harvester wrapping [`crate::hw_entropy::Etsi014QkdClient`] for optical/satellite QKD.
#[derive(Debug)]
pub struct Etsi014Harvester {
    name: String,
    client: Etsi014QkdClient,
    gate: Stage1Gate,
}

impl Etsi014Harvester {
    /// Wrap a configured [`Etsi014QkdClient`] as an `Etsi014Qkd` physical harvester.
    pub fn new(client: Etsi014QkdClient) -> Self {
        let name = format!("etsi014-qkd({})", client.config().kme_addr);
        Self {
            name,
            client,
            gate: Stage1Gate::new(HealthMonitorConfig::default(), DEFAULT_MAX_Z_SCORE, 1.5),
        }
    }
}

impl PhysicalHarvester for Etsi014Harvester {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> EntropySourceKind {
        EntropySourceKind::Etsi014Qkd
    }

    fn harvest(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError> {
        if buf.is_empty() {
            return Ok(());
        }
        if let Err(err) = self.client.fill_random(buf) {
            zeroize_slice(buf);
            let hw_err = HwEntropyError::Io(err.to_string());
            self.gate.last_error = Some(hw_err.to_string());
            return Err(hw_err);
        }
        self.gate.gate_and_record(buf)?;
        Ok(())
    }

    fn health_report(&self) -> SourceEntropyReport {
        let mut r = self.gate.report(&self.name, EntropySourceKind::Etsi014Qkd);
        r.healthy = r.healthy && self.client.is_healthy();
        r
    }
}

// ============================================================================
// 4. Stage-2 MultiSourceExtractor (Hybrid Additive + Bilinear-Toeplitz / F_p)
// ============================================================================

/// Configuration for [`MultiSourceExtractor`].
#[derive(Debug, Clone)]
pub struct MultiSourceConfig {
    /// Output elements `L` in `F_(2^127 - 1)` per extracted block (default: `17` → 256-byte page).
    pub out_elems_l: usize,
    /// Inner dimension `d` of the pairwise bilinear-Toeplitz product (default: `64`).
    pub inner_dim_d: usize,
    /// Minimum total number of sources that must succeed per extraction (default: `2`).
    pub min_healthy_sources: usize,
    /// Minimum number of PHYSICAL sources (excluding `OsCsprngFallback`) that must succeed per
    /// extraction (default: `1`; ensures OS CSPRNG is never trusted alone).
    pub min_physical_sources: usize,
    /// Continuous NIST SP 800-90B health gate applied to every extracted output page.
    pub output_health_config: HealthMonitorConfig,
}

impl Default for MultiSourceConfig {
    fn default() -> Self {
        Self {
            out_elems_l: DEFAULT_OUT_ELEMS_L,
            inner_dim_d: DEFAULT_INNER_DIM_D,
            min_healthy_sources: 2,
            min_physical_sources: 1,
            output_health_config: HealthMonitorConfig::default(),
        }
    }
}

/// Pack canonical 127-bit field elements (`< 2^127 - 1`) tightly into an output byte slice with
/// zero padding bias, volatile-zeroizing the stack bit accumulator before returning.
fn pack_field_elems_to_bytes(elems: &[u128], out: &mut [u8]) {
    let mut out_idx = 0usize;
    let mut bit_buf: u128 = 0;
    let mut bit_count: u32 = 0;

    for &elem in elems {
        let v = reduce(elem);
        let lo = v & (u64::MAX as u128); // 64 bits
        let hi = v >> 64; // 63 bits

        bit_buf |= lo << bit_count;
        bit_count += 64;
        while bit_count >= 8 && out_idx < out.len() {
            out[out_idx] = (bit_buf & 0xFF) as u8;
            out_idx += 1;
            bit_buf >>= 8;
            bit_count -= 8;
        }
        if out_idx >= out.len() {
            break;
        }

        bit_buf |= hi << bit_count;
        bit_count += 63;
        while bit_count >= 8 && out_idx < out.len() {
            out[out_idx] = (bit_buf & 0xFF) as u8;
            out_idx += 1;
            bit_buf >>= 8;
            bit_count -= 8;
        }
        if out_idx >= out.len() {
            break;
        }
    }

    zeroize_u128(&mut bit_buf);
}

/// Stage-2 **Hybrid Additive + Bilinear-Toeplitz Multi-Source Extractor over `F_(2^127 - 1)`**.
///
/// Combines `M` independent Stage-1 harvesters via:
/// ```text
/// Z_r = Σ_{j=1..M} X^(j)_{lin, r}
///     + Σ_{1 <= a < b <= M} Σ_{c=0..d-1} X^(a)_{ext, L - 1 - r + c} · X^(b)_{ext, c}  (mod 2^127 - 1)
/// ```
/// where `X^(j)_lin` (length `L`) and `X^(j)_ext` (length `L + d - 1`) are disjoint slices of
/// source `j`'s raw harvest.
///
/// All intermediate raw byte staging buffers and field-element arrays are volatile-zeroized before
/// returning, on every error path, and on `Drop`.
pub struct MultiSourceExtractor {
    sources: Vec<Box<dyn PhysicalHarvester>>,
    config: MultiSourceConfig,
    output_monitor: ContinuousHealthMonitor,
    last_output_health: Option<HealthCheckReport>,
    total_blocks_extracted: u64,
    total_bytes_extracted: u64,
    /// Buffered 256-byte OTP page for arbitrary-sized [`EntropySource::fill_random`] reads.
    /// Consumed bytes are immediately volatile-zeroized; remainder is wiped on `Drop`.
    page_cache: [u8; 256],
    cache_pos: usize,
    cache_len: usize,
}

impl fmt::Debug for MultiSourceExtractor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<(&str, EntropySourceKind)> = self
            .sources
            .iter()
            .map(|s| (s.name(), s.kind()))
            .collect();
        f.debug_struct("MultiSourceExtractor")
            .field("config", &self.config)
            .field("sources", &names)
            .field("total_blocks_extracted", &self.total_blocks_extracted)
            .field("total_bytes_extracted", &self.total_bytes_extracted)
            .field("output_healthy", &self.output_monitor.is_healthy())
            .field("page_cache", &"<REDACTED>")
            .finish()
    }
}

impl MultiSourceExtractor {
    /// Construct a new Stage-2 multi-source extractor from `sources` and `config`.
    pub fn new(
        sources: Vec<Box<dyn PhysicalHarvester>>,
        config: MultiSourceConfig,
    ) -> Result<Self, HwEntropyError> {
        if config.out_elems_l == 0 {
            return Err(HwEntropyError::InvalidResponse(
                "MultiSourceConfig::out_elems_l must be >= 1".into(),
            ));
        }
        if config.inner_dim_d == 0 {
            return Err(HwEntropyError::InvalidResponse(
                "MultiSourceConfig::inner_dim_d must be >= 1".into(),
            ));
        }
        if config.min_healthy_sources == 0 {
            return Err(HwEntropyError::InvalidResponse(
                "MultiSourceConfig::min_healthy_sources must be >= 1".into(),
            ));
        }
        if config.min_physical_sources > config.min_healthy_sources {
            return Err(HwEntropyError::InvalidResponse(
                "MultiSourceConfig::min_physical_sources cannot exceed min_healthy_sources".into(),
            ));
        }
        let output_monitor = ContinuousHealthMonitor::with_config(config.output_health_config);
        Ok(Self {
            sources,
            config,
            output_monitor,
            last_output_health: None,
            total_blocks_extracted: 0,
            total_bytes_extracted: 0,
            page_cache: [0u8; 256],
            cache_pos: 0,
            cache_len: 0,
        })
    }

    /// Auto-wire a commodity Linux multi-source extractor:
    /// - [`CpuJitterHarvester`] (`CpuTimingJitter`)
    /// - [`IoIrqJitterHarvester`] (`IoIrqTimingJitter`)
    /// - Optional [`LinuxHwrngHarvester`] from `VRNM_QRNG_DEVICE` or `/dev/hwrng` (if readable and
    ///   passes 256-byte NIST SP 800-90B startup health test)
    /// - [`OsCsprngHarvester`] (`OsCsprngFallback`, defense-in-depth only; `min_physical_sources = 1`)
    pub fn default_commodity_extractor() -> Self {
        let mut sources: Vec<Box<dyn PhysicalHarvester>> = Vec::with_capacity(4);
        sources.push(Box::new(CpuJitterHarvester::new()));
        sources.push(Box::new(IoIrqJitterHarvester::new()));

        let mut hw_candidates = Vec::with_capacity(2);
        if let Some(env_path) = std::env::var_os(VRNM_QRNG_DEVICE_ENV) {
            if !env_path.is_empty() {
                hw_candidates.push(PathBuf::from(env_path));
            }
        }
        let default_hw = PathBuf::from(DEFAULT_HWRNG_PATH);
        if !hw_candidates.contains(&default_hw) {
            hw_candidates.push(default_hw);
        }
        for path in hw_candidates {
            if let Ok(mut hw) = LinuxHwrngSource::open(&path) {
                if hw.run_startup_health_test(256).is_ok() {
                    sources.push(Box::new(LinuxHwrngHarvester::from_source(hw)));
                    break;
                }
            }
        }

        sources.push(Box::new(OsCsprngHarvester::new()));

        Self::new(sources, MultiSourceConfig::default())
            .expect("default MultiSourceConfig is always valid")
    }

    /// Register an additional Stage-1 physical or QKD harvester.
    pub fn add_source(&mut self, source: Box<dyn PhysicalHarvester>) {
        self.sources.push(source);
    }

    /// Borrow the extractor configuration.
    pub fn config(&self) -> &MultiSourceConfig {
        &self.config
    }

    /// Bytes required from each contributing Stage-1 source per extracted field block:
    /// `(L + (L + d - 1)) * 16` bytes (disjoint `X_lin` of length `L` and `X_ext` of length
    /// `L + d - 1`, 16 bytes per `F_(2^127 - 1)` element).
    #[inline]
    pub fn bytes_per_source_per_block(&self) -> usize {
        let l = self.config.out_elems_l;
        let d = self.config.inner_dim_d;
        let ext_len = l + d - 1;
        (l + ext_len) * 16
    }

    /// Return a live telemetry snapshot across all registered Stage-1 sources and the Stage-2
    /// output health monitor.
    pub fn health_snapshot(&self) -> ExtractorHealthSnapshot {
        let sources: Vec<SourceEntropyReport> =
            self.sources.iter().map(|s| s.health_report()).collect();
        let healthy_sources = sources.iter().filter(|r| r.healthy).count();
        let healthy_physical_sources = sources
            .iter()
            .filter(|r| r.healthy && r.kind.is_physical())
            .count();
        ExtractorHealthSnapshot {
            sources,
            healthy_sources,
            healthy_physical_sources,
            total_blocks_extracted: self.total_blocks_extracted,
            total_bytes_extracted: self.total_bytes_extracted,
            output_healthy: self.output_monitor.is_healthy(),
            last_output_health: self.last_output_health,
        }
    }

    /// Extract one block of `L = config.out_elems_l` uniform elements in `F_(2^127 - 1)` via the
    /// Hybrid Additive + Bilinear-Toeplitz multi-source formula.
    ///
    /// Volatile-zeroizes ALL intermediate raw byte and field-element staging buffers before
    /// returning (including on every error path).
    pub fn extract_field_block(&mut self) -> Result<Vec<u128>, HwEntropyError> {
        let l = self.config.out_elems_l;
        let d = self.config.inner_dim_d;
        let ext_len = l + d - 1;
        let raw_bytes_needed = (l + ext_len) * 16;

        let mut raw_buf = vec![0u8; raw_bytes_needed];
        let mut x_lin_all: Vec<Vec<u128>> = Vec::with_capacity(self.sources.len());
        let mut x_ext_all: Vec<Vec<u128>> = Vec::with_capacity(self.sources.len());

        let mut contributing_total = 0usize;
        let mut contributing_physical = 0usize;
        let mut failures: Vec<String> = Vec::new();

        for source in self.sources.iter_mut() {
            match source.harvest(&mut raw_buf) {
                Ok(()) => {
                    let mut x_lin = Vec::with_capacity(l);
                    let mut x_ext = Vec::with_capacity(ext_len);
                    for i in 0..l {
                        let off = i * 16;
                        let mut word_bytes = [0u8; 16];
                        word_bytes.copy_from_slice(&raw_buf[off..off + 16]);
                        x_lin.push(reduce(u128::from_le_bytes(word_bytes)));
                        zeroize_slice(&mut word_bytes);
                    }
                    let ext_base = l * 16;
                    for i in 0..ext_len {
                        let off = ext_base + i * 16;
                        let mut word_bytes = [0u8; 16];
                        word_bytes.copy_from_slice(&raw_buf[off..off + 16]);
                        x_ext.push(reduce(u128::from_le_bytes(word_bytes)));
                        zeroize_slice(&mut word_bytes);
                    }
                    x_lin_all.push(x_lin);
                    x_ext_all.push(x_ext);
                    contributing_total += 1;
                    if source.kind().is_physical() {
                        contributing_physical += 1;
                    }
                }
                Err(err) => {
                    failures.push(format!("{}: {err}", source.name()));
                }
            }
            // Immediately volatile-zeroize the raw staging buffer after each source.
            zeroize_slice(&mut raw_buf);
        }

        let wipe_staging = |lin: &mut Vec<Vec<u128>>, ext: &mut Vec<Vec<u128>>| {
            for v in lin.iter_mut() {
                zeroize_u128_slice(v);
            }
            for v in ext.iter_mut() {
                zeroize_u128_slice(v);
            }
            lin.clear();
            ext.clear();
        };

        if contributing_total < self.config.min_healthy_sources
            || contributing_physical < self.config.min_physical_sources
        {
            wipe_staging(&mut x_lin_all, &mut x_ext_all);
            let detail = if failures.is_empty() {
                "insufficient registered sources".to_string()
            } else {
                failures.join("; ")
            };
            return Err(HwEntropyError::DeviceUnavailable(format!(
                "multi-source quorum unmet: {contributing_total}/{} healthy total, \
                 {contributing_physical}/{} healthy physical ({detail})",
                self.config.min_healthy_sources, self.config.min_physical_sources
            )));
        }

        // Compute:
        //   Z_r = Σ_{j=0..M-1} X^(j)_{lin, r}
        //       + Σ_{0 <= a < b < M} Σ_{c=0..d-1} X^(a)_{ext, L - 1 - r + c} · X^(b)_{ext, c} (mod P)
        let m = x_lin_all.len();
        let mut z = vec![0u128; l];

        for r in 0..l {
            let mut acc = 0u128;
            for x_lin in x_lin_all.iter() {
                acc = add_mod(acc, x_lin[r]);
            }
            let row_offset = (l - 1) - r;
            for a in 0..m {
                let xa_row = &x_ext_all[a][row_offset..row_offset + d];
                for b in (a + 1)..m {
                    let xb = &x_ext_all[b];
                    for c in 0..d {
                        let prod = mul_mod(xa_row[c], xb[c]);
                        acc = add_mod(acc, prod);
                    }
                }
            }
            z[r] = acc;
            zeroize_u128(&mut acc);
        }

        wipe_staging(&mut x_lin_all, &mut x_ext_all);
        self.total_blocks_extracted = self.total_blocks_extracted.saturating_add(1);
        Ok(z)
    }

    /// Extract a health-gated 256-byte (2,048-bit) OTP page from `F_(2^127 - 1)` field blocks.
    ///
    /// With default `out_elems_l = 17` (`17 * 127 = 2,159 >= 2,048` bits), a single field block
    /// fills the entire 256-byte page with zero padding bias. The resulting page is gated through
    /// the Stage-2 [`ContinuousHealthMonitor`] before release.
    pub fn extract_page_256(&mut self) -> Result<[u8; 256], HwEntropyError> {
        let mut page = [0u8; 256];
        let bytes_per_block = (self.config.out_elems_l * 127) / 8;

        if bytes_per_block >= 256 {
            let mut elems = self.extract_field_block()?;
            pack_field_elems_to_bytes(&elems, &mut page);
            zeroize_u128_slice(&mut elems);
        } else {
            let mut offset = 0usize;
            while offset < 256 {
                let mut elems = match self.extract_field_block() {
                    Ok(e) => e,
                    Err(err) => {
                        zeroize_slice(&mut page);
                        return Err(err);
                    }
                };
                let take = bytes_per_block.max(1).min(256 - offset);
                pack_field_elems_to_bytes(&elems, &mut page[offset..offset + take]);
                zeroize_u128_slice(&mut elems);
                offset += take;
            }
        }

        let report = self.output_monitor.gate(&mut page)?;
        self.last_output_health = Some(report);
        self.total_bytes_extracted = self.total_bytes_extracted.saturating_add(256);
        Ok(page)
    }
}

impl EntropySource for MultiSourceExtractor {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut written = 0usize;
        while written < buf.len() {
            if self.cache_pos < self.cache_len {
                let avail = self.cache_len - self.cache_pos;
                let take = avail.min(buf.len() - written);
                buf[written..written + take]
                    .copy_from_slice(&self.page_cache[self.cache_pos..self.cache_pos + take]);
                // Immediately volatile-zeroize consumed OTP page bytes from cache.
                zeroize_slice(&mut self.page_cache[self.cache_pos..self.cache_pos + take]);
                self.cache_pos += take;
                written += take;
                continue;
            }

            let remaining = buf.len() - written;
            if remaining >= 256 {
                match self.extract_page_256() {
                    Ok(mut page) => {
                        buf[written..written + 256].copy_from_slice(&page);
                        zeroize_slice(&mut page);
                        written += 256;
                    }
                    Err(err) => {
                        zeroize_slice(buf);
                        return Err(QkdError::from(err));
                    }
                }
            } else {
                match self.extract_page_256() {
                    Ok(page) => {
                        self.page_cache = page;
                        self.cache_pos = 0;
                        self.cache_len = 256;
                    }
                    Err(err) => {
                        zeroize_slice(buf);
                        return Err(QkdError::from(err));
                    }
                }
            }
        }

        Ok(())
    }
}

impl Drop for MultiSourceExtractor {
    fn drop(&mut self) {
        zeroize_slice(&mut self.page_cache);
        self.cache_pos = 0;
        self.cache_len = 0;
    }
}

/// Auto-wire the default commodity Linux [`MultiSourceExtractor`] combining CPU jitter,
/// OS scheduler/IRQ jitter, optional `/dev/hwrng` (or `VRNM_QRNG_DEVICE`), and OS `/dev/urandom`
/// defense-in-depth fallback (`min_physical_sources = 1`).
pub fn default_commodity_extractor() -> MultiSourceExtractor {
    MultiSourceExtractor::default_commodity_extractor()
}

// ============================================================================
// 5. Comprehensive Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qkd::check_entropy_health;

    /// Adversarial / backdoored mock source emitting a fixed constant byte (e.g. `0x00` or `0xAA`).
    struct ConstantAdversarialHarvester {
        name: String,
        kind: EntropySourceKind,
        byte: u8,
        bytes_harvested: u64,
    }

    impl ConstantAdversarialHarvester {
        fn new(name: &str, kind: EntropySourceKind, byte: u8) -> Self {
            Self {
                name: name.to_string(),
                kind,
                byte,
                bytes_harvested: 0,
            }
        }
    }

    impl PhysicalHarvester for ConstantAdversarialHarvester {
        fn name(&self) -> &str {
            &self.name
        }
        fn kind(&self) -> EntropySourceKind {
            self.kind
        }
        fn harvest(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError> {
            buf.fill(self.byte);
            self.bytes_harvested = self.bytes_harvested.saturating_add(buf.len() as u64);
            Ok(())
        }
        fn health_report(&self) -> SourceEntropyReport {
            SourceEntropyReport {
                name: self.name.clone(),
                kind: self.kind,
                healthy: true,
                bytes_harvested: self.bytes_harvested,
                min_entropy_bits_per_byte: 0.0,
                max_lag_autocorrelation: 1.0,
                last_health: None,
                last_error: None,
            }
        }
    }

    /// Honest uniform source backed by OS `/dev/urandom` tagged with any `EntropySourceKind`
    /// for controlled multi-source survival testing.
    struct UniformMockHarvester {
        name: String,
        kind: EntropySourceKind,
        os: OsEntropySource,
        bytes_harvested: u64,
    }

    impl UniformMockHarvester {
        fn new(name: &str, kind: EntropySourceKind) -> Self {
            Self {
                name: name.to_string(),
                kind,
                os: OsEntropySource::new(),
                bytes_harvested: 0,
            }
        }
    }

    impl PhysicalHarvester for UniformMockHarvester {
        fn name(&self) -> &str {
            &self.name
        }
        fn kind(&self) -> EntropySourceKind {
            self.kind
        }
        fn harvest(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError> {
            self.os
                .fill_random(buf)
                .map_err(|e| HwEntropyError::Io(e.to_string()))?;
            self.bytes_harvested = self.bytes_harvested.saturating_add(buf.len() as u64);
            Ok(())
        }
        fn health_report(&self) -> SourceEntropyReport {
            SourceEntropyReport {
                name: self.name.clone(),
                kind: self.kind,
                healthy: true,
                bytes_harvested: self.bytes_harvested,
                min_entropy_bits_per_byte: 7.5,
                max_lag_autocorrelation: 0.01,
                last_health: None,
                last_error: None,
            }
        }
    }

    /// Independent weak biased physical source: each bit is `1` with exact probability `0.75`
    /// (`b = u0 | u1` where `u0, u1` are independent uniform bits). Zero uniform sources!
    struct BiasedWeakHarvester {
        name: String,
        kind: EntropySourceKind,
        os: OsEntropySource,
        bytes_harvested: u64,
    }

    impl BiasedWeakHarvester {
        fn new(name: &str, kind: EntropySourceKind) -> Self {
            Self {
                name: name.to_string(),
                kind,
                os: OsEntropySource::new(),
                bytes_harvested: 0,
            }
        }
    }

    impl PhysicalHarvester for BiasedWeakHarvester {
        fn name(&self) -> &str {
            &self.name
        }
        fn kind(&self) -> EntropySourceKind {
            self.kind
        }
        fn harvest(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError> {
            // For independent uniform bytes a, b: each bit of (a | b) is 1 with P = 3/4 = 0.75.
            let mut tmp = vec![0u8; buf.len()];
            self.os
                .fill_random(buf)
                .map_err(|e| HwEntropyError::Io(e.to_string()))?;
            self.os
                .fill_random(&mut tmp)
                .map_err(|e| HwEntropyError::Io(e.to_string()))?;
            for (dst, &src) in buf.iter_mut().zip(tmp.iter()) {
                *dst |= src;
            }
            zeroize_slice(&mut tmp);
            self.bytes_harvested = self.bytes_harvested.saturating_add(buf.len() as u64);
            Ok(())
        }
        fn health_report(&self) -> SourceEntropyReport {
            SourceEntropyReport {
                name: self.name.clone(),
                kind: self.kind,
                healthy: true,
                bytes_harvested: self.bytes_harvested,
                min_entropy_bits_per_byte: 3.3,
                max_lag_autocorrelation: 0.01,
                last_health: None,
                last_error: None,
            }
        }
    }

    #[test]
    fn test_multi_source_extractor_survives_m_minus_1_all_zero_or_backdoored_sources() {
        // Scenario A: 2 of 3 sources are all-zero compromised; 1 source is uniform.
        let mut ext_zeros = MultiSourceExtractor::new(
            vec![
                Box::new(ConstantAdversarialHarvester::new(
                    "zero-1",
                    EntropySourceKind::PlatformHwrng,
                    0x00,
                )),
                Box::new(ConstantAdversarialHarvester::new(
                    "zero-2",
                    EntropySourceKind::ExternalQrng,
                    0x00,
                )),
                Box::new(UniformMockHarvester::new(
                    "honest-3",
                    EntropySourceKind::CpuTimingJitter,
                )),
            ],
            MultiSourceConfig {
                min_healthy_sources: 3,
                min_physical_sources: 1,
                ..MultiSourceConfig::default()
            },
        )
        .unwrap();

        let mut all_pages_a = Vec::with_capacity(16 * 256);
        for _ in 0..16 {
            let page = ext_zeros
                .extract_page_256()
                .expect("extractor must survive M-1 all-zero sources");
            all_pages_a.extend_from_slice(&page);
        }
        let mut mon_a = ContinuousHealthMonitor::new();
        let rep_a = mon_a
            .check(&all_pages_a)
            .expect("extracted output with 2 all-zero sources must pass NIST SP 800-90B");
        assert!(rep_a.monobit_z < 4.5, "monobit_z={}", rep_a.monobit_z);
        assert!(rep_a.runs_z < 4.5, "runs_z={}", rep_a.runs_z);
        assert!(rep_a.distinct_bytes >= 240);
        let (_, lag_z_a) = max_lag_bit_autocorrelation(&all_pages_a, 8);
        assert!(lag_z_a < 5.0, "lag-8 autocorr z={lag_z_a}");

        // Scenario B: 2 of 3 sources emit non-zero adversarial constants (0xAA and 0x55);
        // 1 source is uniform. Disjoint additive X_lin guarantees exact uniformity over F_p.
        let mut ext_const = MultiSourceExtractor::new(
            vec![
                Box::new(ConstantAdversarialHarvester::new(
                    "backdoor-aa",
                    EntropySourceKind::PlatformHwrng,
                    0xAA,
                )),
                Box::new(ConstantAdversarialHarvester::new(
                    "backdoor-55",
                    EntropySourceKind::ExternalQrng,
                    0x55,
                )),
                Box::new(UniformMockHarvester::new(
                    "honest-cpu",
                    EntropySourceKind::CpuTimingJitter,
                )),
            ],
            MultiSourceConfig {
                min_healthy_sources: 3,
                min_physical_sources: 1,
                ..MultiSourceConfig::default()
            },
        )
        .unwrap();

        let mut all_pages_b = Vec::with_capacity(16 * 256);
        for _ in 0..16 {
            let page = ext_const
                .extract_page_256()
                .expect("extractor must survive M-1 backdoored constant sources");
            all_pages_b.extend_from_slice(&page);
        }
        let mut mon_b = ContinuousHealthMonitor::new();
        let rep_b = mon_b
            .check(&all_pages_b)
            .expect("extracted output with 2 backdoored sources must pass NIST SP 800-90B");
        assert!(rep_b.monobit_z < 4.5, "monobit_z={}", rep_b.monobit_z);
        assert!(rep_b.runs_z < 4.5, "runs_z={}", rep_b.runs_z);
        assert!(rep_b.distinct_bytes >= 240);
        let (_, lag_z_b) = max_lag_bit_autocorrelation(&all_pages_b, 8);
        assert!(lag_z_b < 5.0, "lag-8 autocorr z={lag_z_b}");

        // Scenario C: OsCsprngFallback alone MUST be rejected when min_physical_sources >= 1.
        let mut os_only = MultiSourceExtractor::new(
            vec![Box::new(OsCsprngHarvester::new())],
            MultiSourceConfig {
                min_healthy_sources: 1,
                min_physical_sources: 1,
                ..MultiSourceConfig::default()
            },
        )
        .unwrap();
        let mut out = [0x77u8; 64];
        let err = os_only
            .fill_random(&mut out)
            .expect_err("OsCsprngFallback alone must be rejected when min_physical_sources >= 1");
        assert!(matches!(err, QkdError::EntropyFailure(_)));
        assert!(
            out.iter().all(|&b| b == 0),
            "caller buffer must be volatile-zeroized on quorum failure"
        );
    }

    #[test]
    fn test_multi_source_extractor_extracts_uniform_output_from_two_weak_biased_sources() {
        // First confirm that a single 75%-biased weak source is genuinely heavily biased and
        // fails the NIST SP 800-90B health monitor on its own.
        let mut probe_weak = BiasedWeakHarvester::new("weak-probe", EntropySourceKind::CpuTimingJitter);
        let mut raw_biased = vec![0u8; 512];
        probe_weak.harvest(&mut raw_biased).unwrap();
        let raw_ones: usize = raw_biased.iter().map(|b| b.count_ones() as usize).sum();
        let raw_ratio = raw_ones as f64 / (raw_biased.len() * 8) as f64;
        assert!(
            (raw_ratio - 0.75).abs() < 0.05,
            "expected ~75% 1-bits in raw weak source, got {raw_ratio:.4}"
        );
        let mut raw_mon = ContinuousHealthMonitor::new();
        assert!(
            raw_mon.check(&raw_biased).is_err(),
            "raw 75%-biased source alone must fail NIST SP 800-90B monobit check"
        );

        // Now combine TWO independent 75%-biased weak sources (ZERO uniform sources!) via the
        // Stage-2 Hybrid Additive + Bilinear-Toeplitz extractor over F_(2^127 - 1).
        let mut extractor = MultiSourceExtractor::new(
            vec![
                Box::new(BiasedWeakHarvester::new(
                    "weak-source-a",
                    EntropySourceKind::CpuTimingJitter,
                )),
                Box::new(BiasedWeakHarvester::new(
                    "weak-source-b",
                    EntropySourceKind::IoIrqTimingJitter,
                )),
            ],
            MultiSourceConfig {
                out_elems_l: DEFAULT_OUT_ELEMS_L,
                inner_dim_d: DEFAULT_INNER_DIM_D,
                min_healthy_sources: 2,
                min_physical_sources: 2,
                output_health_config: HealthMonitorConfig::default(),
            },
        )
        .unwrap();

        let mut extracted = Vec::with_capacity(16 * 256);
        for _ in 0..16 {
            let page = extractor
                .extract_page_256()
                .expect("2-source bilinear-Toeplitz extractor must extract uniform 256B page");
            extracted.extend_from_slice(&page);
        }

        // Verify monobit, runs, distinct-byte alphabet, and lag-1..8 autocorrelation all pass.
        let mut mon = ContinuousHealthMonitor::new();
        let report = mon
            .check(&extracted)
            .expect("extracted 4 KiB from two 75%-biased sources must pass NIST SP 800-90B");
        assert!(
            (report.ones_ratio - 0.5).abs() < 0.03,
            "extracted ones_ratio={:.4} should be ~0.50",
            report.ones_ratio
        );
        assert!(report.monobit_z < 4.5, "monobit_z={}", report.monobit_z);
        assert!(report.runs_z < 4.5, "runs_z={}", report.runs_z);
        assert!(
            report.distinct_bytes >= 245,
            "expected >= 245 distinct bytes in 4096B, got {}",
            report.distinct_bytes
        );
        let (max_r, max_z) = max_lag_bit_autocorrelation(&extracted, 8);
        assert!(
            max_z < 5.0,
            "lag-1..8 autocorrelation failed: max_r={max_r:.4}, max_z={max_z:.2}"
        );
        let h_min = estimate_min_entropy_bits_per_byte(&extracted);
        assert!(
            h_min >= 5.5,
            "expected high NIST SP 800-90B min-entropy on extracted 4 KiB, got {h_min:.2}"
        );
    }

    #[test]
    fn test_live_cpu_and_io_jitter_harvesters_produce_healthy_entropy() {
        // 1. Live CpuJitterHarvester.
        let mut cpu = CpuJitterHarvester::new();
        let mut cpu_buf = [0u8; 256];
        cpu.harvest(&mut cpu_buf)
            .expect("live CpuJitterHarvester must produce healthy entropy");
        let cpu_rep = cpu.health_report();
        assert!(cpu_rep.healthy);
        assert_eq!(cpu_rep.kind, EntropySourceKind::CpuTimingJitter);
        assert_eq!(cpu_rep.bytes_harvested, 256);
        assert!(cpu_rep.min_entropy_bits_per_byte >= 1.5);
        check_entropy_health(&cpu_buf, 6.0).expect("CPU jitter bytes must pass health check");

        // 2. Live IoIrqJitterHarvester.
        let mut io = IoIrqJitterHarvester::new();
        let mut io_buf = [0u8; 256];
        io.harvest(&mut io_buf)
            .expect("live IoIrqJitterHarvester must produce healthy entropy");
        let io_rep = io.health_report();
        assert!(io_rep.healthy);
        assert_eq!(io_rep.kind, EntropySourceKind::IoIrqTimingJitter);
        assert_eq!(io_rep.bytes_harvested, 256);
        assert!(io_rep.min_entropy_bits_per_byte >= 1.5);
        check_entropy_health(&io_buf, 6.0).expect("I/O-IRQ jitter bytes must pass health check");

        // 3. Live MultiSourceExtractor wired strictly with real physical jitter harvesters
        //    (CPU + I/O-IRQ, NO OS CSPRNG!).
        let mut phys_only = MultiSourceExtractor::new(
            vec![
                Box::new(CpuJitterHarvester::new()),
                Box::new(IoIrqJitterHarvester::new()),
            ],
            MultiSourceConfig {
                min_healthy_sources: 2,
                min_physical_sources: 2,
                ..MultiSourceConfig::default()
            },
        )
        .unwrap();

        let page1 = phys_only
            .extract_page_256()
            .expect("physical-only MultiSourceExtractor page 1 must succeed");
        let page2 = phys_only
            .extract_page_256()
            .expect("physical-only MultiSourceExtractor page 2 must succeed");
        assert_ne!(page1, page2);

        let snap = phys_only.health_snapshot();
        assert!(snap.output_healthy);
        assert_eq!(snap.healthy_physical_sources, 2);
        assert_eq!(snap.total_blocks_extracted, 2);
        assert_eq!(snap.total_bytes_extracted, 512);

        // 4. Live default_commodity_extractor() via EntropySource::fill_random across small & large reads.
        let mut commodity = default_commodity_extractor();
        let mut small = [0u8; 32];
        commodity.fill_random(&mut small).unwrap();
        assert!(small.iter().any(|&b| b != 0));

        let mut large = [0u8; 512];
        commodity.fill_random(&mut large).unwrap();
        check_entropy_health(&large, 6.0).unwrap();
        let (_, lag_z) = max_lag_bit_autocorrelation(&large, 8);
        assert!(lag_z < 6.0, "commodity extractor lag-8 autocorr z={lag_z}");
        let comm_snap = commodity.health_snapshot();
        assert!(comm_snap.output_healthy);
        assert!(comm_snap.healthy_physical_sources >= 2);
    }

    #[test]
    fn test_peres_extractor_unbiases_strongly_biased_coin() {
        // Generate 8,192 bits with ~75% 1-bits and verify Peres produces ~50/50 unbiased bits.
        let mut os = OsEntropySource::new();
        let mut a = [0u8; 1024];
        let mut b = [0u8; 1024];
        os.fill_random(&mut a).unwrap();
        os.fill_random(&mut b).unwrap();

        let mut raw_bits = Vec::with_capacity(8192);
        for (&ba, &bb) in a.iter().zip(b.iter()) {
            let biased = ba | bb;
            for shift in 0..8 {
                raw_bits.push((biased >> shift) & 1);
            }
        }
        let mut unbiased = Vec::new();
        peres_extract_bits(&raw_bits, 3, &mut unbiased);
        assert!(
            unbiased.len() >= 4000,
            "Peres depth-3 should retain >50% of 75%-biased bits, got {}",
            unbiased.len()
        );
        let ones: usize = unbiased.iter().map(|&bit| bit as usize).sum();
        let ratio = ones as f64 / unbiased.len() as f64;
        assert!(
            (ratio - 0.5).abs() < 0.04,
            "Peres output should be unbiased ~0.50, got {ratio:.4}"
        );
    }
}
