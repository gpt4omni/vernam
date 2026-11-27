//! Production Hardware QRNG, NIST SP 800-90B Continuous Health Gate, and ETSI GS QKD 014 Client
//! for Vernam (VRNM).
//!
//! Zero external crates, zero computational cryptography (no SHA-256, RSA, ECDSA, AES, or ChaCha).
//! All security rests solely on physical entropy, statistical fail-closed health gating, and
//! Shannon information theory:
//! - [`ContinuousHealthMonitor`]: NIST SP 800-90B Repetition Count Test (RCT), Adaptive Proportion
//!   Test (APT), monobit z-score, Wald-Wolfowitz bit-runs test, and low-alphabet detection with
//!   immediate volatile zeroization on fault.
//! - [`LinuxHwrngSource`]: Real Linux hardware RNG / USB QRNG character-device driver
//!   (`/dev/hwrng`, `/dev/TrueRNG`, `/dev/ttyACM0`, or custom paths) implementing
//!   [`crate::qkd::EntropySource`] with fail-closed continuous health gating.
//! - [`FailClosedEntropySource`]: Generic fail-closed NIST SP 800-90B health-gate wrapper for any
//!   [`crate::qkd::EntropySource`].
//! - [`decode_base64`] / [`encode_base64`]: Strict zero-dependency RFC 4648 Base64 codec with
//!   canonical padding validation and volatile zeroization on error.
//! - [`Etsi014QkdClient`]: Zero-dependency HTTP/1.1 TCP client for ETSI GS QKD 014 Key Management
//!   Entities (KME) supporting `get_status`, `request_enc_keys`, and `request_dec_keys`, with
//!   strict timeouts, response size ceiling ([`MAX_ETSI_RESPONSE_BYTES`]), hardened recursive JSON
//!   parsing, health gating, redacted `Debug`, and volatile zeroization on `Drop`.
//! - [`XorEntropyMixer`]: Information-theoretic defense-in-depth combiner XORing two independent
//!   entropy streams (Shannon's theorem: output remains unconditionally uniform if either stream
//!   is uniform and independent).
//! - [`discover_best_entropy_source`]: Auto-discovers `VRNM_QRNG_DEVICE` or `/dev/hwrng`,
//!   verifying startup health before returning a live hardware+OS [`XorEntropyMixer`] or cleanly
//!   falling back to [`OsEntropySource`] with diagnostics.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use crate::field::zeroize_slice;
use crate::qkd::{EntropySource, OsEntropySource, QkdError, QkdKeyProvider, QkdLinkStatus};

/// Maximum HTTP response size accepted from an ETSI GS QKD 014 KME server (64 KiB).
/// Protects against memory-exhaustion attacks from malicious or compromised KME endpoints.
pub const MAX_ETSI_RESPONSE_BYTES: usize = 65_536;

/// Default Linux hardware RNG character device path.
pub const DEFAULT_HWRNG_PATH: &str = "/dev/hwrng";

/// Environment variable overriding the hardware QRNG device path during auto-discovery.
pub const VRNM_QRNG_DEVICE_ENV: &str = "VRNM_QRNG_DEVICE";

/// Default NIST SP 800-90B Repetition Count Test (RCT) cutoff for byte-wide symbols.
/// For uniform bytes (`p = 1/256`), 8 consecutive identical bytes occurs with probability
/// `256^-7 = 2^-56 < 1.4e-17`, catching stuck-byte hardware faults immediately.
pub const DEFAULT_RCT_CUTOFF: usize = 8;

/// Default NIST SP 800-90B Adaptive Proportion Test (APT) window size in bytes.
pub const DEFAULT_APT_WINDOW_BYTES: usize = 512;

/// Default NIST SP 800-90B Adaptive Proportion Test (APT) cutoff for a 512-byte window.
/// For uniform bytes (`mu = 2.0`), observing the anchor byte >= 24 times in 512 bytes occurs
/// with probability `< 3e-17`.
pub const DEFAULT_APT_CUTOFF: usize = 24;

/// Default z-score threshold for monobit balance and Wald-Wolfowitz bit-runs checks.
/// At 6.0 sigma, the two-sided false-positive probability is `< 2e-9`.
pub const DEFAULT_MAX_Z_SCORE: f64 = 6.0;

/// Minimum staging window size in bytes for small hardware reads so every emitted byte
/// is covered by statistical health checks.
const MIN_HEALTH_CHUNK_BYTES: usize = 64;

/// Maximum per-chunk read size for streaming hardware fills.
const MAX_STREAM_CHUNK_BYTES: usize = 4096;

/// Maximum recursion depth accepted by the hardened ETSI 014 JSON parser.
const MAX_JSON_DEPTH: usize = 16;

/// Volatile-zeroize a `String`'s backing heap allocation safely without `unsafe` code.
#[inline(never)]
fn zeroize_string(s: &mut String) {
    let mut bytes = std::mem::take(s).into_bytes();
    zeroize_slice(&mut bytes);
}

// ============================================================================
// 1. Error Types
// ============================================================================

/// Errors returned by hardware QRNG drivers, continuous health monitors, RFC 4648 Base64
/// decoding, and ETSI GS QKD 014 KME network operations.
#[derive(Debug, Clone, PartialEq)]
pub enum HwEntropyError {
    /// Underlying OS/device/socket I/O failure.
    Io(String),
    /// Requested hardware QRNG device path does not exist or cannot be opened.
    DeviceUnavailable(String),
    /// Entropy output failed NIST SP 800-90B continuous health verification (fail-closed).
    HealthCheckFailed {
        test: &'static str,
        ones: usize,
        total_bits: usize,
        reason: String,
    },
    /// ETSI GS QKD 014 KME server returned a non-2xx HTTP status code.
    HttpError { status: u16, message: String },
    /// Input failed strict RFC 4648 Base64 validation.
    InvalidBase64(String),
    /// KME server returned malformed HTTP or ETSI 014 JSON payload.
    InvalidResponse(String),
    /// Network connect, read, or write timed out.
    Timeout(String),
    /// KME HTTP response exceeded the configured [`MAX_ETSI_RESPONSE_BYTES`] cap.
    ResponseTooLarge { limit: usize, received: usize },
}

impl fmt::Display for HwEntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HwEntropyError::Io(msg) => write!(f, "hardware entropy I/O error: {msg}"),
            HwEntropyError::DeviceUnavailable(msg) => {
                write!(f, "hardware entropy device unavailable: {msg}")
            }
            HwEntropyError::HealthCheckFailed {
                test,
                ones,
                total_bits,
                reason,
            } => write!(
                f,
                "entropy health check failed [{test}] ({ones}/{total_bits} ones): {reason}"
            ),
            HwEntropyError::HttpError { status, message } => {
                write!(f, "ETSI 014 HTTP error {status}: {message}")
            }
            HwEntropyError::InvalidBase64(msg) => write!(f, "invalid RFC 4648 Base64: {msg}"),
            HwEntropyError::InvalidResponse(msg) => {
                write!(f, "invalid ETSI 014 KME response: {msg}")
            }
            HwEntropyError::Timeout(msg) => write!(f, "hardware/QKD operation timed out: {msg}"),
            HwEntropyError::ResponseTooLarge { limit, received } => write!(
                f,
                "ETSI 014 KME response exceeded limit ({received} > {limit} bytes)"
            ),
        }
    }
}

impl Error for HwEntropyError {}

impl From<std::io::Error> for HwEntropyError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => HwEntropyError::Timeout(err.to_string()),
            ErrorKind::NotFound | ErrorKind::PermissionDenied => {
                HwEntropyError::DeviceUnavailable(err.to_string())
            }
            _ => HwEntropyError::Io(err.to_string()),
        }
    }
}

impl From<HwEntropyError> for QkdError {
    fn from(err: HwEntropyError) -> Self {
        match err {
            HwEntropyError::HealthCheckFailed {
                test,
                ones,
                total_bits,
                reason,
            } => QkdError::EntropyHealthCheckFailed {
                ones,
                total_bits,
                reason: format!("[{test}] {reason}"),
            },
            other => QkdError::EntropyFailure(other.to_string()),
        }
    }
}

// ============================================================================
// 2. Continuous NIST SP 800-90B Health Gate
// ============================================================================

/// Configuration parameters for [`ContinuousHealthMonitor`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HealthMonitorConfig {
    /// Repetition Count Test (RCT) cutoff: fail if any byte repeats consecutively `>= rct_cutoff`.
    pub rct_cutoff: usize,
    /// Adaptive Proportion Test (APT) window size in bytes.
    pub apt_window_bytes: usize,
    /// Adaptive Proportion Test (APT) cutoff: fail if the window's anchor byte appears
    /// `>= apt_cutoff` times within `apt_window_bytes`.
    pub apt_cutoff: usize,
    /// Maximum allowed monobit balance z-score (`|2 * ones - n| / sqrt(n)`).
    pub max_monobit_z: f64,
    /// Maximum allowed Wald-Wolfowitz bit-runs z-score (`|R - mu_R| / sigma_R`).
    pub max_runs_z: f64,
    /// Minimum number of distinct byte values required in chunks of `>= 32` bytes.
    pub min_distinct_bytes_per_32: usize,
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            rct_cutoff: DEFAULT_RCT_CUTOFF,
            apt_window_bytes: DEFAULT_APT_WINDOW_BYTES,
            apt_cutoff: DEFAULT_APT_CUTOFF,
            max_monobit_z: DEFAULT_MAX_Z_SCORE,
            max_runs_z: DEFAULT_MAX_Z_SCORE,
            min_distinct_bytes_per_32: 12,
        }
    }
}

/// Telemetry returned when an entropy buffer passes [`ContinuousHealthMonitor`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HealthCheckReport {
    pub bytes_checked: usize,
    pub total_bits: usize,
    pub ones: usize,
    pub ones_ratio: f64,
    pub monobit_z: f64,
    pub bit_runs: usize,
    pub runs_z: f64,
    pub distinct_bytes: usize,
    pub max_consecutive_byte_run: usize,
}

/// Stateful, fail-closed NIST SP 800-90B continuous health monitor.
///
/// Tracks Repetition Count Test (RCT) and Adaptive Proportion Test (APT) state continuously
/// across chunk boundaries, combined with per-chunk monobit z-score, Wald-Wolfowitz bit-runs,
/// and distinct-byte alphabet checks. Once any test detects a hardware RNG fault, the monitor
/// latches into a faulted state and rejects all future chunks until explicitly [`Self::reset`].
#[derive(Debug, Clone)]
pub struct ContinuousHealthMonitor {
    config: HealthMonitorConfig,
    last_byte: Option<u8>,
    rct_run_len: usize,
    apt_anchor: Option<u8>,
    apt_seen_in_window: usize,
    apt_anchor_count: usize,
    total_bytes_checked: u64,
    total_chunks_checked: u64,
    last_fault: Option<HwEntropyError>,
}

impl ContinuousHealthMonitor {
    /// Create a new continuous health monitor with default NIST SP 800-90B thresholds.
    pub fn new() -> Self {
        Self::with_config(HealthMonitorConfig::default())
    }

    /// Create a new continuous health monitor with custom thresholds.
    pub fn with_config(config: HealthMonitorConfig) -> Self {
        Self {
            config: HealthMonitorConfig {
                rct_cutoff: config.rct_cutoff.max(2),
                apt_window_bytes: config.apt_window_bytes.max(16),
                apt_cutoff: config.apt_cutoff.max(2),
                max_monobit_z: if config.max_monobit_z.is_finite() && config.max_monobit_z > 0.0 {
                    config.max_monobit_z
                } else {
                    DEFAULT_MAX_Z_SCORE
                },
                max_runs_z: if config.max_runs_z.is_finite() && config.max_runs_z > 0.0 {
                    config.max_runs_z
                } else {
                    DEFAULT_MAX_Z_SCORE
                },
                min_distinct_bytes_per_32: config.min_distinct_bytes_per_32.clamp(2, 32),
            },
            last_byte: None,
            rct_run_len: 0,
            apt_anchor: None,
            apt_seen_in_window: 0,
            apt_anchor_count: 0,
            total_bytes_checked: 0,
            total_chunks_checked: 0,
            last_fault: None,
        }
    }

    /// Return `true` if no hardware entropy fault has been latched.
    pub fn is_healthy(&self) -> bool {
        self.last_fault.is_none()
    }

    /// Return the latched fault error, if the monitor has failed closed.
    pub fn last_fault(&self) -> Option<&HwEntropyError> {
        self.last_fault.as_ref()
    }

    /// Total number of bytes that have passed health gating so far.
    pub fn total_bytes_checked(&self) -> u64 {
        self.total_bytes_checked
    }

    /// Total number of chunks that have passed health gating so far.
    pub fn total_chunks_checked(&self) -> u64 {
        self.total_chunks_checked
    }

    /// Clear continuous RCT/APT state and latched fault after device replacement or re-init.
    pub fn reset(&mut self) {
        self.last_byte = None;
        self.rct_run_len = 0;
        self.apt_anchor = None;
        self.apt_seen_in_window = 0;
        self.apt_anchor_count = 0;
        self.last_fault = None;
    }

    /// Gate a mutable entropy buffer in place.
    ///
    /// If ANY continuous or statistical test fails (or if the monitor already latched a fault),
    /// `buf` is immediately volatile-zeroized via [`zeroize_slice`] before returning `Err`.
    pub fn gate(&mut self, buf: &mut [u8]) -> Result<HealthCheckReport, HwEntropyError> {
        match self.check(buf) {
            Ok(report) => Ok(report),
            Err(err) => {
                zeroize_slice(buf);
                Err(err)
            }
        }
    }

    /// Inspect a byte slice against RCT, APT, low-alphabet, monobit, and Wald-Wolfowitz bit-runs.
    /// Latches into a fail-closed state on any failure.
    pub fn check(&mut self, data: &[u8]) -> Result<HealthCheckReport, HwEntropyError> {
        if let Some(ref fault) = self.last_fault {
            return Err(fault.clone());
        }

        if data.is_empty() {
            return Ok(HealthCheckReport {
                bytes_checked: 0,
                total_bits: 0,
                ones: 0,
                ones_ratio: 0.5,
                monobit_z: 0.0,
                bit_runs: 0,
                runs_z: 0.0,
                distinct_bytes: 0,
                max_consecutive_byte_run: 0,
            });
        }

        let total_bits = data.len() * 8;
        let mut ones = 0usize;
        let mut bit_runs = 0usize;
        let mut prev_bit: Option<u8> = None;
        let mut seen_bytes = [false; 256];
        let mut distinct_bytes = 0usize;
        let mut max_consecutive_byte_run = 0usize;

        for &b in data {
            // 1. Continuous Repetition Count Test (RCT) across chunk boundaries.
            if self.last_byte == Some(b) {
                self.rct_run_len += 1;
            } else {
                self.last_byte = Some(b);
                self.rct_run_len = 1;
            }
            if self.rct_run_len > max_consecutive_byte_run {
                max_consecutive_byte_run = self.rct_run_len;
            }
            if self.rct_run_len >= self.config.rct_cutoff {
                let total_ones: usize = data.iter().map(|x| x.count_ones() as usize).sum();
                let err = HwEntropyError::HealthCheckFailed {
                    test: "RCT",
                    ones: total_ones,
                    total_bits,
                    reason: format!(
                        "repetition count fault: byte 0x{b:02x} repeated {} consecutive times (cutoff {})",
                        self.rct_run_len, self.config.rct_cutoff
                    ),
                };
                self.last_fault = Some(err.clone());
                return Err(err);
            }

            // 2. Continuous Adaptive Proportion Test (APT) across chunk boundaries.
            if self.apt_anchor.is_none() || self.apt_seen_in_window >= self.config.apt_window_bytes
            {
                self.apt_anchor = Some(b);
                self.apt_seen_in_window = 1;
                self.apt_anchor_count = 1;
            } else {
                self.apt_seen_in_window += 1;
                if self.apt_anchor == Some(b) {
                    self.apt_anchor_count += 1;
                    if self.apt_anchor_count >= self.config.apt_cutoff {
                        let total_ones: usize = data.iter().map(|x| x.count_ones() as usize).sum();
                        let err = HwEntropyError::HealthCheckFailed {
                            test: "APT",
                            ones: total_ones,
                            total_bits,
                            reason: format!(
                                "adaptive proportion fault: byte 0x{b:02x} appeared {} times in {} bytes (cutoff {})",
                                self.apt_anchor_count,
                                self.apt_seen_in_window,
                                self.config.apt_cutoff
                            ),
                        };
                        self.last_fault = Some(err.clone());
                        return Err(err);
                    }
                }
            }

            // 3. Track alphabet coverage, ones count, and bit transitions (LSB-first).
            if !seen_bytes[b as usize] {
                seen_bytes[b as usize] = true;
                distinct_bytes += 1;
            }
            ones += b.count_ones() as usize;

            for shift in 0..8 {
                let bit = (b >> shift) & 1;
                if prev_bit != Some(bit) {
                    bit_runs += 1;
                    prev_bit = Some(bit);
                }
            }
        }

        // 4. Low-alphabet check for chunks >= 32 bytes (catches repeating small-period patterns
        //    such as 0xAA/0x55 or 4-byte LFSR lockups within a single 256-bit key).
        if data.len() >= 32 && distinct_bytes < self.config.min_distinct_bytes_per_32 {
            let err = HwEntropyError::HealthCheckFailed {
                test: "ALPHABET",
                ones,
                total_bits,
                reason: format!(
                    "low-alphabet fault: only {distinct_bytes} distinct byte values in {} bytes (minimum {})",
                    data.len(),
                    self.config.min_distinct_bytes_per_32
                ),
            };
            self.last_fault = Some(err.clone());
            return Err(err);
        }

        // 5. Monobit balance z-score check on chunks >= 128 bits (16 bytes).
        let n = total_bits as f64;
        let ones_ratio = ones as f64 / n;
        let monobit_z = ((2.0 * ones as f64) - n).abs() / n.sqrt();

        if total_bits >= 128 && monobit_z > self.config.max_monobit_z {
            let err = HwEntropyError::HealthCheckFailed {
                test: "MONOBIT",
                ones,
                total_bits,
                reason: format!(
                    "monobit imbalance: ones_ratio={ones_ratio:.4}, z={monobit_z:.2} > {:.2}",
                    self.config.max_monobit_z
                ),
            };
            self.last_fault = Some(err.clone());
            return Err(err);
        }

        // 6. Wald-Wolfowitz bit-runs test on chunks >= 128 bits (16 bytes).
        //    Catches balanced-but-periodic bit patterns (e.g. 0xAA/0x55, 0xF0/0x0F, 0x00/0xFF)
        //    that have monobit z == 0.0 and RCT run length == 1.
        let mut runs_z = 0.0;
        if total_bits >= 128 {
            let zeros = total_bits - ones;
            if ones == 0 || zeros == 0 {
                let err = HwEntropyError::HealthCheckFailed {
                    test: "RUNS",
                    ones,
                    total_bits,
                    reason: "degenerate all-zero or all-one bit stream".into(),
                };
                self.last_fault = Some(err.clone());
                return Err(err);
            }
            let n1 = ones as f64;
            let n0 = zeros as f64;
            let two_n0_n1 = 2.0 * n0 * n1;
            let mu_r = 1.0 + (two_n0_n1 / n);
            let var_r = (two_n0_n1 * (two_n0_n1 - n)) / (n * n * (n - 1.0));
            if var_r <= 0.0 || !var_r.is_finite() {
                let err = HwEntropyError::HealthCheckFailed {
                    test: "RUNS",
                    ones,
                    total_bits,
                    reason: "degenerate runs variance".into(),
                };
                self.last_fault = Some(err.clone());
                return Err(err);
            }
            runs_z = ((bit_runs as f64) - mu_r).abs() / var_r.sqrt();
            if runs_z > self.config.max_runs_z {
                let err = HwEntropyError::HealthCheckFailed {
                    test: "RUNS",
                    ones,
                    total_bits,
                    reason: format!(
                        "Wald-Wolfowitz bit-runs fault: runs={bit_runs}, expected={mu_r:.1}, z={runs_z:.2} > {:.2}",
                        self.config.max_runs_z
                    ),
                };
                self.last_fault = Some(err.clone());
                return Err(err);
            }
        }

        self.total_bytes_checked += data.len() as u64;
        self.total_chunks_checked += 1;

        Ok(HealthCheckReport {
            bytes_checked: data.len(),
            total_bits,
            ones,
            ones_ratio,
            monobit_z,
            bit_runs,
            runs_z,
            distinct_bytes,
            max_consecutive_byte_run,
        })
    }
}

impl Default for ContinuousHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 3. Real Hardware Device Driver (LinuxHwrngSource) & FailClosedEntropySource
// ============================================================================

/// Real Linux hardware RNG / USB QRNG character-device driver (`/dev/hwrng`, `/dev/TrueRNG`,
/// `/dev/ttyACM0`, or any custom device path).
///
/// Every read is gated through an embedded [`ContinuousHealthMonitor`] in fail-closed mode.
/// Staging buffers and failed output buffers are volatile-zeroized immediately on error and drop.
#[derive(Debug)]
pub struct LinuxHwrngSource {
    device_path: PathBuf,
    file: File,
    monitor: ContinuousHealthMonitor,
    staging: Vec<u8>,
}

impl LinuxHwrngSource {
    /// Open `/dev/hwrng` with default NIST SP 800-90B continuous health thresholds.
    pub fn open_default() -> Result<Self, HwEntropyError> {
        Self::open(DEFAULT_HWRNG_PATH)
    }

    /// Open a hardware RNG or USB QRNG character device at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, HwEntropyError> {
        Self::open_with_config(path, HealthMonitorConfig::default())
    }

    /// Open a hardware RNG or USB QRNG character device at `path` with custom health config.
    pub fn open_with_config<P: AsRef<Path>>(
        path: P,
        health_config: HealthMonitorConfig,
    ) -> Result<Self, HwEntropyError> {
        let device_path = path.as_ref().to_path_buf();
        let file = File::open(&device_path).map_err(|e| {
            HwEntropyError::DeviceUnavailable(format!(
                "cannot open hardware RNG '{}': {e}",
                device_path.display()
            ))
        })?;
        Ok(Self {
            device_path,
            file,
            monitor: ContinuousHealthMonitor::with_config(health_config),
            staging: vec![0u8; MIN_HEALTH_CHUNK_BYTES],
        })
    }

    /// Return the underlying hardware device path.
    pub fn device_path(&self) -> &Path {
        &self.device_path
    }

    /// Borrow the embedded continuous NIST SP 800-90B health monitor.
    pub fn health_monitor(&self) -> &ContinuousHealthMonitor {
        &self.monitor
    }

    /// Returns `true` if no hardware RNG fault has been detected.
    pub fn is_healthy(&self) -> bool {
        self.monitor.is_healthy()
    }

    /// Return the latched fault, if this driver has failed closed.
    pub fn last_fault(&self) -> Option<&HwEntropyError> {
        self.monitor.last_fault()
    }

    /// Run an explicit startup/periodic health test by sampling `sample_bytes` (minimum 64)
    /// from the hardware device, gating through [`ContinuousHealthMonitor`], and wiping the
    /// sample buffer immediately.
    pub fn run_startup_health_test(
        &mut self,
        sample_bytes: usize,
    ) -> Result<HealthCheckReport, HwEntropyError> {
        let len = sample_bytes.max(MIN_HEALTH_CHUNK_BYTES);
        let mut sample = vec![0u8; len];
        let read_res = self.file.read_exact(&mut sample);
        if let Err(e) = read_res {
            zeroize_slice(&mut sample);
            return Err(HwEntropyError::Io(format!(
                "failed reading {len} startup health bytes from '{}': {e}",
                self.device_path.display()
            )));
        }
        let report_res = self.monitor.gate(&mut sample);
        zeroize_slice(&mut sample);
        report_res
    }

    /// Fill `buf` completely with health-gated hardware random bytes.
    ///
    /// Fail-closed: if the device returns an I/O error or fails ANY continuous NIST SP 800-90B
    /// test, the entire caller buffer `buf` and internal staging buffer are volatile-zeroized
    /// before returning `Err`.
    pub fn fill_checked(&mut self, buf: &mut [u8]) -> Result<(), HwEntropyError> {
        if buf.is_empty() {
            return Ok(());
        }

        if let Some(fault) = self.monitor.last_fault().cloned() {
            zeroize_slice(buf);
            return Err(fault);
        }

        if buf.len() < MIN_HEALTH_CHUNK_BYTES {
            if self.staging.len() < MIN_HEALTH_CHUNK_BYTES {
                self.staging.resize(MIN_HEALTH_CHUNK_BYTES, 0);
            }
            if let Err(e) = self.file.read_exact(&mut self.staging) {
                zeroize_slice(&mut self.staging);
                zeroize_slice(buf);
                return Err(HwEntropyError::Io(format!(
                    "failed reading {} staging bytes from '{}': {e}",
                    self.staging.len(),
                    self.device_path.display()
                )));
            }
            if let Err(err) = self.monitor.gate(&mut self.staging) {
                zeroize_slice(&mut self.staging);
                zeroize_slice(buf);
                return Err(err);
            }
            buf.copy_from_slice(&self.staging[..buf.len()]);
            zeroize_slice(&mut self.staging);
            return Ok(());
        }

        // Stream in health-checked chunks of up to MAX_STREAM_CHUNK_BYTES, ensuring the final
        // chunk is also at least MIN_HEALTH_CHUNK_BYTES when possible.
        let mut offset = 0usize;
        while offset < buf.len() {
            let remaining = buf.len() - offset;
            let chunk_len = if remaining > MAX_STREAM_CHUNK_BYTES
                && remaining - MAX_STREAM_CHUNK_BYTES < MIN_HEALTH_CHUNK_BYTES
            {
                remaining - MIN_HEALTH_CHUNK_BYTES
            } else {
                remaining.min(MAX_STREAM_CHUNK_BYTES)
            };

            let chunk = &mut buf[offset..offset + chunk_len];
            if let Err(e) = self.file.read_exact(chunk) {
                zeroize_slice(buf);
                return Err(HwEntropyError::Io(format!(
                    "failed reading {chunk_len} bytes from '{}': {e}",
                    self.device_path.display()
                )));
            }
            if let Err(err) = self.monitor.gate(chunk) {
                zeroize_slice(buf);
                return Err(err);
            }
            offset += chunk_len;
        }

        Ok(())
    }
}

impl EntropySource for LinuxHwrngSource {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
        self.fill_checked(buf).map_err(QkdError::from)
    }
}

impl Drop for LinuxHwrngSource {
    fn drop(&mut self) {
        zeroize_slice(&mut self.staging);
    }
}

/// Generic fail-closed NIST SP 800-90B continuous health-gate wrapper around any [`EntropySource`].
///
/// Guarantees that no unverified or unhealthy bytes are ever released to callers and provides
/// panic-free health status tracking (`is_healthy`, `last_fault`).
#[derive(Debug)]
pub struct FailClosedEntropySource<E: EntropySource> {
    inner: E,
    monitor: ContinuousHealthMonitor,
    staging: Vec<u8>,
}

impl<E: EntropySource> FailClosedEntropySource<E> {
    /// Wrap `inner` with default NIST SP 800-90B continuous health thresholds.
    pub fn new(inner: E) -> Self {
        Self::with_config(inner, HealthMonitorConfig::default())
    }

    /// Wrap `inner` with custom health thresholds.
    pub fn with_config(inner: E, config: HealthMonitorConfig) -> Self {
        Self {
            inner,
            monitor: ContinuousHealthMonitor::with_config(config),
            staging: vec![0u8; MIN_HEALTH_CHUNK_BYTES],
        }
    }

    /// Return `true` if no health fault has been latched.
    pub fn is_healthy(&self) -> bool {
        self.monitor.is_healthy()
    }

    /// Return the latched fault, if any.
    pub fn last_fault(&self) -> Option<&HwEntropyError> {
        self.monitor.last_fault()
    }

    /// Borrow the underlying entropy source.
    pub fn inner(&self) -> &E {
        &self.inner
    }

    /// Borrow the underlying continuous health monitor.
    pub fn health_monitor(&self) -> &ContinuousHealthMonitor {
        &self.monitor
    }
}

impl<E: EntropySource> EntropySource for FailClosedEntropySource<E> {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
        if buf.is_empty() {
            return Ok(());
        }
        if let Some(fault) = self.monitor.last_fault().cloned() {
            zeroize_slice(buf);
            return Err(QkdError::from(fault));
        }

        if buf.len() < MIN_HEALTH_CHUNK_BYTES {
            if self.staging.len() < MIN_HEALTH_CHUNK_BYTES {
                self.staging.resize(MIN_HEALTH_CHUNK_BYTES, 0);
            }
            if let Err(err) = self.inner.fill_random(&mut self.staging) {
                zeroize_slice(&mut self.staging);
                zeroize_slice(buf);
                return Err(err);
            }
            if let Err(err) = self.monitor.gate(&mut self.staging) {
                zeroize_slice(&mut self.staging);
                zeroize_slice(buf);
                return Err(QkdError::from(err));
            }
            buf.copy_from_slice(&self.staging[..buf.len()]);
            zeroize_slice(&mut self.staging);
            return Ok(());
        }

        if let Err(err) = self.inner.fill_random(buf) {
            zeroize_slice(buf);
            return Err(err);
        }
        for chunk in buf.chunks_mut(MAX_STREAM_CHUNK_BYTES) {
            if let Err(err) = self.monitor.gate(chunk) {
                zeroize_slice(buf);
                return Err(QkdError::from(err));
            }
        }
        Ok(())
    }
}

impl<E: EntropySource> Drop for FailClosedEntropySource<E> {
    fn drop(&mut self) {
        zeroize_slice(&mut self.staging);
    }
}

// ============================================================================
// 4. Pure-Rust Strict RFC 4648 Base64 Codec
// ============================================================================

const BASE64_ENCODE_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[inline]
const fn decode_b64_char(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Encode raw bytes into canonical RFC 4648 standard Base64 with `=` padding.
pub fn encode_base64(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(BASE64_ENCODE_TABLE[((n >> 18) & 0x3F) as usize]);
        out.push(BASE64_ENCODE_TABLE[((n >> 12) & 0x3F) as usize]);
        out.push(BASE64_ENCODE_TABLE[((n >> 6) & 0x3F) as usize]);
        out.push(BASE64_ENCODE_TABLE[(n & 0x3F) as usize]);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(BASE64_ENCODE_TABLE[((n >> 18) & 0x3F) as usize]);
            out.push(BASE64_ENCODE_TABLE[((n >> 12) & 0x3F) as usize]);
            out.push(b'=');
            out.push(b'=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(BASE64_ENCODE_TABLE[((n >> 18) & 0x3F) as usize]);
            out.push(BASE64_ENCODE_TABLE[((n >> 12) & 0x3F) as usize]);
            out.push(BASE64_ENCODE_TABLE[((n >> 6) & 0x3F) as usize]);
            out.push(b'=');
        }
        _ => {}
    }
    // SAFETY/INVARIANT: Every byte pushed is drawn from ASCII BASE64_ENCODE_TABLE or `=`.
    String::from_utf8(out).expect("base64 output is strictly ASCII")
}

/// Strictly decode RFC 4648 standard Base64 into raw bytes.
///
/// Rejects:
/// - Lengths not divisible by 4
/// - Any non-alphabet character (including whitespace, URL-safe `-`/`_`, or control chars)
/// - Padding `=` outside the final 4-character quantum or in invalid positions (`=AAA`, `A=AA`, `AA=A`)
/// - Non-canonical non-zero trailing pad bits (RFC 4648 Section 3.5)
///
/// Volatile-zeroizes any partially decoded output buffer on error.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, HwEntropyError> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return Err(HwEntropyError::InvalidBase64(format!(
            "length {} is not a multiple of 4",
            bytes.len()
        )));
    }

    let num_quads = bytes.len() / 4;
    let mut out = Vec::with_capacity(num_quads * 3);

    for (quad_idx, quad) in bytes.chunks_exact(4).enumerate() {
        let is_last = quad_idx + 1 == num_quads;
        let (c0, c1, c2, c3) = (quad[0], quad[1], quad[2], quad[3]);

        let Some(v0) = decode_b64_char(c0) else {
            zeroize_slice(&mut out);
            return Err(HwEntropyError::InvalidBase64(format!(
                "invalid character 0x{c0:02x} at index {}",
                quad_idx * 4
            )));
        };
        let Some(v1) = decode_b64_char(c1) else {
            zeroize_slice(&mut out);
            return Err(HwEntropyError::InvalidBase64(format!(
                "invalid character 0x{c1:02x} at index {}",
                quad_idx * 4 + 1
            )));
        };

        if c2 == b'=' {
            if !is_last || c3 != b'=' {
                zeroize_slice(&mut out);
                return Err(HwEntropyError::InvalidBase64(
                    "invalid padding placement".into(),
                ));
            }
            if (v1 & 0x0F) != 0 {
                zeroize_slice(&mut out);
                return Err(HwEntropyError::InvalidBase64(
                    "non-zero canonical padding bits".into(),
                ));
            }
            out.push((v0 << 2) | (v1 >> 4));
            continue;
        }

        let Some(v2) = decode_b64_char(c2) else {
            zeroize_slice(&mut out);
            return Err(HwEntropyError::InvalidBase64(format!(
                "invalid character 0x{c2:02x} at index {}",
                quad_idx * 4 + 2
            )));
        };

        if c3 == b'=' {
            if !is_last {
                zeroize_slice(&mut out);
                return Err(HwEntropyError::InvalidBase64(
                    "padding permitted only in final quantum".into(),
                ));
            }
            if (v2 & 0x03) != 0 {
                zeroize_slice(&mut out);
                return Err(HwEntropyError::InvalidBase64(
                    "non-zero canonical padding bits".into(),
                ));
            }
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
            continue;
        }

        let Some(v3) = decode_b64_char(c3) else {
            zeroize_slice(&mut out);
            return Err(HwEntropyError::InvalidBase64(format!(
                "invalid character 0x{c3:02x} at index {}",
                quad_idx * 4 + 3
            )));
        };

        out.push((v0 << 2) | (v1 >> 4));
        out.push((v1 << 4) | (v2 >> 2));
        out.push((v2 << 6) | v3);
    }

    Ok(out)
}

// ============================================================================
// 5. Hardened Zero-Dependency JSON Parser for ETSI GS QKD 014
// ============================================================================

enum JsonValue {
    Null,
    Bool,
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Object(entries) => Some(entries),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(items) => Some(items),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_usize(&self) -> Option<usize> {
        match self {
            JsonValue::Number(s) => s.parse::<usize>().ok(),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&JsonValue> {
        self.as_object()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

impl Drop for JsonValue {
    fn drop(&mut self) {
        match self {
            JsonValue::String(s) | JsonValue::Number(s) => zeroize_string(s),
            JsonValue::Array(items) => {
                // Element Drops run recursively when Vec drops.
                items.clear();
            }
            JsonValue::Object(entries) => {
                for (k, _) in entries.iter_mut() {
                    zeroize_string(k);
                }
                entries.clear();
            }
            JsonValue::Null | JsonValue::Bool => {}
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn parse(input: &'a str) -> Result<JsonValue, HwEntropyError> {
        let mut p = Self {
            bytes: input.as_bytes(),
            pos: 0,
        };
        p.skip_ws();
        let val = p.parse_value(0)?;
        p.skip_ws();
        if p.pos != p.bytes.len() {
            return Err(HwEntropyError::InvalidResponse(
                "trailing data after JSON root value".into(),
            ));
        }
        Ok(val)
    }

    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, HwEntropyError> {
        if depth > MAX_JSON_DEPTH {
            return Err(HwEntropyError::InvalidResponse(
                "JSON nesting depth exceeds security limit".into(),
            ));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b't') => self.parse_literal(b"true", JsonValue::Bool),
            Some(b'f') => self.parse_literal(b"false", JsonValue::Bool),
            Some(b'n') => self.parse_literal(b"null", JsonValue::Null),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(b) => Err(HwEntropyError::InvalidResponse(format!(
                "unexpected JSON token 0x{b:02x} at byte {}",
                self.pos
            ))),
            None => Err(HwEntropyError::InvalidResponse(
                "unexpected end of JSON input".into(),
            )),
        }
    }

    fn parse_literal(&mut self, lit: &[u8], val: JsonValue) -> Result<JsonValue, HwEntropyError> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(val)
        } else {
            Err(HwEntropyError::InvalidResponse(format!(
                "malformed JSON literal at byte {}",
                self.pos
            )))
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, HwEntropyError> {
        self.pos += 1; // consume '{'
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(HwEntropyError::InvalidResponse(format!(
                    "expected JSON object key string at byte {}",
                    self.pos
                )));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(HwEntropyError::InvalidResponse(format!(
                    "expected ':' after JSON key at byte {}",
                    self.pos
                )));
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            entries.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(entries));
                }
                _ => {
                    return Err(HwEntropyError::InvalidResponse(format!(
                        "expected ',' or '}}' in JSON object at byte {}",
                        self.pos
                    )));
                }
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, HwEntropyError> {
        self.pos += 1; // consume '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            let val = self.parse_value(depth)?;
            items.push(val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => {
                    return Err(HwEntropyError::InvalidResponse(format!(
                        "expected ',' or ']' in JSON array at byte {}",
                        self.pos
                    )));
                }
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, HwEntropyError> {
        self.pos += 1; // consume opening '"'
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let Some(&esc) = self.bytes.get(self.pos) else {
                    zeroize_string(&mut out);
                    return Err(HwEntropyError::InvalidResponse(
                        "unterminated JSON escape sequence".into(),
                    ));
                };
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hex = self.bytes.get(self.pos..self.pos + 4).ok_or_else(|| {
                            zeroize_string(&mut out);
                            HwEntropyError::InvalidResponse("truncated \\u escape".into())
                        })?;
                        let hex_str = std::str::from_utf8(hex).map_err(|_| {
                            zeroize_string(&mut out);
                            HwEntropyError::InvalidResponse("invalid UTF-8 in \\u escape".into())
                        })?;
                        let code = u16::from_str_radix(hex_str, 16).map_err(|_| {
                            zeroize_string(&mut out);
                            HwEntropyError::InvalidResponse("invalid hex in \\u escape".into())
                        })?;
                        self.pos += 4;
                        let ch = char::from_u32(code as u32).ok_or_else(|| {
                            zeroize_string(&mut out);
                            HwEntropyError::InvalidResponse("unsupported surrogate escape".into())
                        })?;
                        out.push(ch);
                    }
                    _ => {
                        zeroize_string(&mut out);
                        return Err(HwEntropyError::InvalidResponse(format!(
                            "unsupported JSON escape '\\{}'",
                            esc as char
                        )));
                    }
                }
            } else if b < 0x20 {
                zeroize_string(&mut out);
                return Err(HwEntropyError::InvalidResponse(
                    "unescaped control character in JSON string".into(),
                ));
            } else {
                // Decode valid UTF-8 slice up to the next quote, backslash, or control byte.
                let start = self.pos;
                while self.pos < self.bytes.len() {
                    let cur = self.bytes[self.pos];
                    if cur == b'"' || cur == b'\\' || cur < 0x20 {
                        break;
                    }
                    self.pos += 1;
                }
                let segment = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| {
                    zeroize_string(&mut out);
                    HwEntropyError::InvalidResponse("invalid UTF-8 inside JSON string".into())
                })?;
                out.push_str(segment);
            }
        }
        zeroize_string(&mut out);
        Err(HwEntropyError::InvalidResponse(
            "unterminated JSON string".into(),
        ))
    }

    fn parse_number(&mut self) -> Result<JsonValue, HwEntropyError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return Err(HwEntropyError::InvalidResponse(
                "invalid JSON number".into(),
            ));
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let frac_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err(HwEntropyError::InvalidResponse(
                    "invalid JSON fractional number".into(),
                ));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err(HwEntropyError::InvalidResponse(
                    "invalid JSON exponent".into(),
                ));
            }
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| HwEntropyError::InvalidResponse("invalid UTF-8 in JSON number".into()))?;
        Ok(JsonValue::Number(raw.to_string()))
    }
}

// ============================================================================
// 6. Real ETSI GS QKD 014 Client (Zero-Dependency HTTP/1.1 TCP)
// ============================================================================

/// Validate an ETSI GS QKD 014 identifier (`slave_SAE_ID`, `master_SAE_ID`, `key_ID`) to prevent
/// URL path traversal, HTTP header injection, and JSON injection.
fn validate_etsi_identifier(label: &str, value: &str) -> Result<(), HwEntropyError> {
    if value.is_empty() || value.len() > 256 {
        return Err(HwEntropyError::InvalidResponse(format!(
            "ETSI 014 {label} must be 1..=256 bytes"
        )));
    }
    if value == "." || value == ".." || value.contains("..") {
        return Err(HwEntropyError::InvalidResponse(format!(
            "ETSI 014 {label} contains disallowed path traversal sequence"
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'@'))
    {
        return Err(HwEntropyError::InvalidResponse(format!(
            "ETSI 014 {label} contains disallowed characters"
        )));
    }
    Ok(())
}

/// Configuration for [`Etsi014QkdClient`].
#[derive(Debug, Clone)]
pub struct Etsi014Config {
    /// TCP socket address (`host:port`) of the ETSI GS QKD 014 KME server.
    pub kme_addr: String,
    /// Optional explicit HTTP `Host` header value (defaults to `kme_addr`).
    pub host_header: Option<String>,
    /// Slave SAE ID targeted by `GET /api/v1/keys/{slave_sae_id}/status` and `/enc_keys`.
    pub slave_sae_id: String,
    /// Master SAE ID targeted by `POST /api/v1/keys/{master_sae_id}/dec_keys`.
    pub master_sae_id: String,
    /// Strict TCP connect timeout (default: 5s).
    pub connect_timeout: Duration,
    /// Strict socket read timeout (default: 5s).
    pub read_timeout: Duration,
    /// Strict socket write timeout (default: 5s).
    pub write_timeout: Duration,
    /// Hard response size ceiling in bytes (default and upper bound: [`MAX_ETSI_RESPONSE_BYTES`]).
    pub max_response_bytes: usize,
    /// NIST SP 800-90B continuous health gate configuration applied to every received QKD key.
    pub health_config: HealthMonitorConfig,
}

impl Etsi014Config {
    /// Create a default ETSI GS QKD 014 client configuration.
    pub fn new(
        kme_addr: impl Into<String>,
        slave_sae_id: impl Into<String>,
        master_sae_id: impl Into<String>,
    ) -> Self {
        Self {
            kme_addr: kme_addr.into(),
            host_header: None,
            slave_sae_id: slave_sae_id.into(),
            master_sae_id: master_sae_id.into(),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            max_response_bytes: MAX_ETSI_RESPONSE_BYTES,
            health_config: HealthMonitorConfig::default(),
        }
    }

    /// Validate identifiers and timeout/size bounds.
    pub fn validate(&self) -> Result<(), HwEntropyError> {
        if self.kme_addr.trim().is_empty()
            || self.kme_addr.contains('\r')
            || self.kme_addr.contains('\n')
        {
            return Err(HwEntropyError::InvalidResponse(
                "invalid kme_addr configuration".into(),
            ));
        }
        if let Some(ref host) = self.host_header {
            if host.trim().is_empty() || host.contains('\r') || host.contains('\n') {
                return Err(HwEntropyError::InvalidResponse(
                    "invalid host_header configuration".into(),
                ));
            }
        }
        validate_etsi_identifier("slave_sae_id", &self.slave_sae_id)?;
        validate_etsi_identifier("master_sae_id", &self.master_sae_id)?;
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_ETSI_RESPONSE_BYTES {
            return Err(HwEntropyError::InvalidResponse(format!(
                "max_response_bytes must be in 1..={MAX_ETSI_RESPONSE_BYTES}"
            )));
        }
        Ok(())
    }
}

/// ETSI GS QKD 014 KME status payload returned by `GET /api/v1/keys/{slave_sae_id}/status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Etsi014Status {
    pub source_kme_id: String,
    pub target_kme_id: String,
    pub master_sae_id: String,
    pub slave_sae_id: String,
    /// Default key size in bits.
    pub key_size: usize,
    /// Number of stored keys currently available for delivery.
    pub stored_key_count: usize,
    /// Maximum stored key capacity.
    pub max_key_count: usize,
    /// Maximum number of keys retrievable in a single request.
    pub max_key_per_request: usize,
    /// Maximum supported key size in bits.
    pub max_key_size: usize,
    /// Minimum supported key size in bits.
    pub min_key_size: usize,
    /// Maximum additional slave SAE IDs supported per request.
    pub max_sae_id_count: usize,
}

/// Decoded, health-gated ETSI GS QKD 014 key material.
///
/// Implements redacted [`fmt::Debug`] (never prints raw key bytes) and volatile memory
/// zeroization on [`Drop`].
pub struct Etsi014Key {
    key_id: String,
    key_bytes: Vec<u8>,
}

impl Etsi014Key {
    /// Return the KME-assigned `key_ID`.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Borrow the raw QKD key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Return the key length in bytes.
    pub fn len(&self) -> usize {
        self.key_bytes.len()
    }

    /// Return `true` if the key has zero length.
    pub fn is_empty(&self) -> bool {
        self.key_bytes.is_empty()
    }

    /// Extract ownership of the raw key bytes (the caller assumes responsibility for zeroizing
    /// the returned `Vec<u8>` after use).
    pub fn take_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.key_bytes)
    }
}

impl fmt::Debug for Etsi014Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Etsi014Key")
            .field("key_id", &self.key_id)
            .field("key_len", &self.key_bytes.len())
            .field("key_bytes", &"<REDACTED>")
            .finish()
    }
}

impl Drop for Etsi014Key {
    fn drop(&mut self) {
        zeroize_slice(&mut self.key_bytes);
    }
}

/// Zero-dependency HTTP/1.1 TCP client for **ETSI GS QKD 014** KME servers.
///
/// Every key retrieved via [`Self::request_enc_keys`] or [`Self::request_dec_keys`] is strictly
/// RFC 4648 Base64-decoded, length-validated, and gated through a continuous NIST SP 800-90B
/// [`ContinuousHealthMonitor`] before release. Raw HTTP wire buffers and intermediate JSON
/// strings containing Base64 key material are volatile-zeroized before returning.
pub struct Etsi014QkdClient {
    config: Etsi014Config,
    monitor: Mutex<ContinuousHealthMonitor>,
    total_delivered_bytes: Mutex<u64>,
}

impl fmt::Debug for Etsi014QkdClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Etsi014QkdClient")
            .field("kme_addr", &self.config.kme_addr)
            .field("slave_sae_id", &self.config.slave_sae_id)
            .field("master_sae_id", &self.config.master_sae_id)
            .field("healthy", &self.is_healthy())
            .finish()
    }
}

impl Etsi014QkdClient {
    /// Construct a new ETSI GS QKD 014 client with default timeouts (5s) and 64 KiB cap.
    pub fn new(
        kme_addr: impl Into<String>,
        slave_sae_id: impl Into<String>,
        master_sae_id: impl Into<String>,
    ) -> Result<Self, HwEntropyError> {
        Self::with_config(Etsi014Config::new(kme_addr, slave_sae_id, master_sae_id))
    }

    /// Construct a new ETSI GS QKD 014 client from a validated [`Etsi014Config`].
    pub fn with_config(config: Etsi014Config) -> Result<Self, HwEntropyError> {
        config.validate()?;
        let monitor = ContinuousHealthMonitor::with_config(config.health_config);
        Ok(Self {
            config,
            monitor: Mutex::new(monitor),
            total_delivered_bytes: Mutex::new(0),
        })
    }

    /// Borrow the client configuration.
    pub fn config(&self) -> &Etsi014Config {
        &self.config
    }

    /// Returns `true` if no entropy health fault has been latched on keys received from this KME.
    pub fn is_healthy(&self) -> bool {
        self.monitor
            .lock()
            .map(|m| m.is_healthy())
            .unwrap_or(false)
    }

    /// Reset the internal continuous health monitor (e.g., after KME failover).
    pub fn reset_health_monitor(&self) {
        if let Ok(mut m) = self.monitor.lock() {
            m.reset();
        }
    }

    /// Query KME link status via `GET /api/v1/keys/{slave_sae_id}/status`.
    pub fn get_status(&self) -> Result<Etsi014Status, HwEntropyError> {
        self.get_status_for_sae(&self.config.slave_sae_id)
    }

    /// Query KME link status for an explicit `slave_sae_id`.
    pub fn get_status_for_sae(&self, slave_sae_id: &str) -> Result<Etsi014Status, HwEntropyError> {
        validate_etsi_identifier("slave_sae_id", slave_sae_id)?;
        let path = format!("/api/v1/keys/{slave_sae_id}/status");
        let mut body = self.http_request("GET", &path, None)?;
        let res = (|| {
            let text = std::str::from_utf8(&body).map_err(|_| {
                HwEntropyError::InvalidResponse("status response is not valid UTF-8".into())
            })?;
            let json = JsonParser::parse(text)?;
            parse_etsi_status(&json)
        })();
        zeroize_slice(&mut body);
        res
    }

    /// Request `number` encryption keys of `size_bits` bits each via
    /// `GET /api/v1/keys/{slave_sae_id}/enc_keys?number={number}&size={size_bits}`.
    pub fn request_enc_keys(
        &self,
        number: usize,
        size_bits: usize,
    ) -> Result<Vec<Etsi014Key>, HwEntropyError> {
        self.request_enc_keys_for_sae(&self.config.slave_sae_id, number, size_bits)
    }

    /// Request encryption keys for an explicit `slave_sae_id`.
    pub fn request_enc_keys_for_sae(
        &self,
        slave_sae_id: &str,
        number: usize,
        size_bits: usize,
    ) -> Result<Vec<Etsi014Key>, HwEntropyError> {
        validate_etsi_identifier("slave_sae_id", slave_sae_id)?;
        if number == 0 {
            return Err(HwEntropyError::InvalidResponse(
                "number of requested keys must be >= 1".into(),
            ));
        }
        if size_bits == 0 || size_bits % 8 != 0 {
            return Err(HwEntropyError::InvalidResponse(
                "size_bits must be a positive multiple of 8".into(),
            ));
        }
        let expected_bytes = size_bits / 8;
        let path = format!("/api/v1/keys/{slave_sae_id}/enc_keys?number={number}&size={size_bits}");
        let mut body = self.http_request("GET", &path, None)?;
        let res = self.decode_and_gate_keys(&body, Some(number), Some(expected_bytes), None);
        zeroize_slice(&mut body);
        if let Ok(ref keys) = res {
            let delivered: u64 = keys.iter().map(|k| k.len() as u64).sum();
            if let Ok(mut total) = self.total_delivered_bytes.lock() {
                *total = total.saturating_add(delivered);
            }
        }
        res
    }

    /// Retrieve decryption keys matching `key_ids` via
    /// `POST /api/v1/keys/{master_sae_id}/dec_keys`.
    pub fn request_dec_keys(&self, key_ids: &[&str]) -> Result<Vec<Etsi014Key>, HwEntropyError> {
        self.request_dec_keys_for_sae(&self.config.master_sae_id, key_ids)
    }

    /// Retrieve decryption keys for an explicit `master_sae_id`.
    pub fn request_dec_keys_for_sae(
        &self,
        master_sae_id: &str,
        key_ids: &[&str],
    ) -> Result<Vec<Etsi014Key>, HwEntropyError> {
        validate_etsi_identifier("master_sae_id", master_sae_id)?;
        if key_ids.is_empty() {
            return Err(HwEntropyError::InvalidResponse(
                "key_ids must not be empty".into(),
            ));
        }
        let mut req_json = String::from("{\"key_IDs\":[");
        for (i, &id) in key_ids.iter().enumerate() {
            validate_etsi_identifier("key_ID", id)?;
            if i > 0 {
                req_json.push(',');
            }
            req_json.push_str("{\"key_ID\":\"");
            req_json.push_str(id);
            req_json.push_str("\"}");
        }
        req_json.push_str("]}");

        let path = format!("/api/v1/keys/{master_sae_id}/dec_keys");
        let mut body = self.http_request("POST", &path, Some(req_json.as_bytes()))?;
        let res = self.decode_and_gate_keys(&body, Some(key_ids.len()), None, Some(key_ids));
        zeroize_slice(&mut body);
        if let Ok(ref keys) = res {
            let delivered: u64 = keys.iter().map(|k| k.len() as u64).sum();
            if let Ok(mut total) = self.total_delivered_bytes.lock() {
                *total = total.saturating_add(delivered);
            }
        }
        res
    }

    fn decode_and_gate_keys(
        &self,
        body: &[u8],
        expected_count: Option<usize>,
        expected_len_bytes: Option<usize>,
        expected_ids: Option<&[&str]>,
    ) -> Result<Vec<Etsi014Key>, HwEntropyError> {
        let text = std::str::from_utf8(body).map_err(|_| {
            HwEntropyError::InvalidResponse("key response is not valid UTF-8".into())
        })?;
        let json = JsonParser::parse(text)?;
        let keys_arr = json
            .get("keys")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| {
                HwEntropyError::InvalidResponse("missing 'keys' array in ETSI 014 response".into())
            })?;

        if let Some(count) = expected_count {
            if keys_arr.len() != count {
                return Err(HwEntropyError::InvalidResponse(format!(
                    "expected {count} keys from KME, received {}",
                    keys_arr.len()
                )));
            }
        }

        let mut monitor = self
            .monitor
            .lock()
            .map_err(|_| HwEntropyError::Io("health monitor mutex poisoned".into()))?;
        if let Some(fault) = monitor.last_fault().cloned() {
            return Err(fault);
        }

        let mut out = Vec::with_capacity(keys_arr.len());
        for entry in keys_arr {
            let key_id = entry
                .get("key_ID")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| {
                    HwEntropyError::InvalidResponse("missing 'key_ID' field in key entry".into())
                })?;
            validate_etsi_identifier("key_ID", key_id)?;

            if let Some(ids) = expected_ids {
                if !ids.contains(&key_id) {
                    return Err(HwEntropyError::InvalidResponse(format!(
                        "KME returned unrequested key_ID '{key_id}'"
                    )));
                }
            }

            let b64 = entry
                .get("key")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| {
                    HwEntropyError::InvalidResponse("missing 'key' field in key entry".into())
                })?;
            let mut key_bytes = decode_base64(b64)?;
            if key_bytes.is_empty() {
                return Err(HwEntropyError::InvalidResponse(
                    "KME returned empty key material".into(),
                ));
            }
            if let Some(expected_len) = expected_len_bytes {
                if key_bytes.len() != expected_len {
                    zeroize_slice(&mut key_bytes);
                    return Err(HwEntropyError::InvalidResponse(format!(
                        "KME key length mismatch: expected {expected_len} bytes, got {}",
                        key_bytes.len()
                    )));
                }
            }

            // Gate EVERY decoded key through the continuous NIST SP 800-90B monitor.
            // If this fails, `key_bytes` is wiped by `gate`, and any previously pushed `Etsi014Key`
            // entries in `out` are wiped automatically when `out` drops on early return.
            monitor.gate(&mut key_bytes)?;

            out.push(Etsi014Key {
                key_id: key_id.to_string(),
                key_bytes,
            });
        }

        Ok(out)
    }

    fn http_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>, HwEntropyError> {
        let mut addrs = self
            .config
            .kme_addr
            .to_socket_addrs()
            .map_err(|e| HwEntropyError::Io(format!("failed resolving '{}': {e}", self.config.kme_addr)))?;
        let first_addr = addrs.next().ok_or_else(|| {
            HwEntropyError::Io(format!("no socket addresses resolved for '{}'", self.config.kme_addr))
        })?;

        let mut stream = None;
        let mut last_err = None;
        for addr in std::iter::once(first_addr).chain(addrs) {
            match TcpStream::connect_timeout(&addr, self.config.connect_timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let mut stream = match stream {
            Some(s) => s,
            None => {
                let err = last_err.expect("at least one connect attempt occurred");
                return Err(HwEntropyError::from(err));
            }
        };

        stream
            .set_read_timeout(Some(self.config.read_timeout))
            .map_err(HwEntropyError::from)?;
        stream
            .set_write_timeout(Some(self.config.write_timeout))
            .map_err(HwEntropyError::from)?;

        let host = self
            .config
            .host_header
            .as_deref()
            .unwrap_or(self.config.kme_addr.as_str());

        let mut request = String::with_capacity(256);
        request.push_str(method);
        request.push(' ');
        request.push_str(path);
        request.push_str(" HTTP/1.1\r\nHost: ");
        request.push_str(host);
        request.push_str("\r\nAccept: application/json\r\nConnection: close\r\n");
        if let Some(payload) = body {
            request.push_str("Content-Type: application/json\r\nContent-Length: ");
            request.push_str(&payload.len().to_string());
            request.push_str("\r\n\r\n");
            stream
                .write_all(request.as_bytes())
                .map_err(HwEntropyError::from)?;
            stream.write_all(payload).map_err(HwEntropyError::from)?;
        } else {
            request.push_str("\r\n");
            stream
                .write_all(request.as_bytes())
                .map_err(HwEntropyError::from)?;
        }
        stream.flush().map_err(HwEntropyError::from)?;

        // Read response under strict byte ceiling to defeat memory-exhaustion KME attacks.
        let limit = self.config.max_response_bytes;
        let mut raw = Vec::with_capacity(limit.min(4096));
        let mut scratch = [0u8; 4096];
        loop {
            match stream.read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => {
                    let next_total = raw.len().saturating_add(n);
                    if next_total > limit {
                        zeroize_slice(&mut scratch);
                        zeroize_slice(&mut raw);
                        return Err(HwEntropyError::ResponseTooLarge {
                            limit,
                            received: next_total,
                        });
                    }
                    raw.extend_from_slice(&scratch[..n]);
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    zeroize_slice(&mut scratch);
                    zeroize_slice(&mut raw);
                    return Err(HwEntropyError::from(e));
                }
            }
        }
        zeroize_slice(&mut scratch);

        let parsed = parse_http_response(&raw, limit);
        zeroize_slice(&mut raw);
        parsed
    }
}

fn parse_etsi_status(json: &JsonValue) -> Result<Etsi014Status, HwEntropyError> {
    let get_str_opt = |k: &str| {
        json.get(k)
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let key_size = json
        .get("key_size")
        .and_then(JsonValue::as_usize)
        .ok_or_else(|| HwEntropyError::InvalidResponse("missing integer 'key_size'".into()))?;
    let stored_key_count = json
        .get("stored_key_count")
        .and_then(JsonValue::as_usize)
        .ok_or_else(|| {
            HwEntropyError::InvalidResponse("missing integer 'stored_key_count'".into())
        })?;
    let max_key_count = json
        .get("max_key_count")
        .and_then(JsonValue::as_usize)
        .ok_or_else(|| {
            HwEntropyError::InvalidResponse("missing integer 'max_key_count'".into())
        })?;

    Ok(Etsi014Status {
        source_kme_id: get_str_opt("source_KME_ID"),
        target_kme_id: get_str_opt("target_KME_ID"),
        master_sae_id: get_str_opt("master_SAE_ID"),
        slave_sae_id: get_str_opt("slave_SAE_ID"),
        key_size,
        stored_key_count,
        max_key_count,
        max_key_per_request: json
            .get("max_key_per_request")
            .and_then(JsonValue::as_usize)
            .unwrap_or(0),
        max_key_size: json
            .get("max_key_size")
            .and_then(JsonValue::as_usize)
            .unwrap_or(key_size),
        min_key_size: json
            .get("min_key_size")
            .and_then(JsonValue::as_usize)
            .unwrap_or(key_size),
        max_sae_id_count: json
            .get("max_SAE_ID_count")
            .and_then(JsonValue::as_usize)
            .unwrap_or(0),
    })
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_http_response(raw: &[u8], limit: usize) -> Result<Vec<u8>, HwEntropyError> {
    let header_end = find_header_end(raw).ok_or_else(|| {
        HwEntropyError::InvalidResponse("missing HTTP header terminator".into())
    })?;
    let header_bytes = &raw[..header_end];
    let body_bytes = &raw[header_end + 4..];

    let header_str = std::str::from_utf8(header_bytes).map_err(|_| {
        HwEntropyError::InvalidResponse("HTTP headers contain non-UTF-8 bytes".into())
    })?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        HwEntropyError::InvalidResponse("empty HTTP response".into())
    })?;

    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HwEntropyError::InvalidResponse(format!(
            "unsupported HTTP version '{version}'"
        )));
    }
    let status_str = parts.next().ok_or_else(|| {
        HwEntropyError::InvalidResponse("missing HTTP status code".into())
    })?;
    let status: u16 = status_str.parse().map_err(|_| {
        HwEntropyError::InvalidResponse(format!("invalid HTTP status code '{status_str}'"))
    })?;
    let reason_phrase = parts.next().unwrap_or("").trim();

    let mut content_length: Option<usize> = None;
    let mut is_chunked = false;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let name_lower = name.trim().to_ascii_lowercase();
            let val_trimmed = val.trim();
            if name_lower == "content-length" {
                let len: usize = val_trimmed.parse().map_err(|_| {
                    HwEntropyError::InvalidResponse("invalid Content-Length header".into())
                })?;
                if len > limit {
                    return Err(HwEntropyError::ResponseTooLarge {
                        limit,
                        received: len,
                    });
                }
                content_length = Some(len);
            } else if name_lower == "transfer-encoding"
                && val_trimmed.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
        }
    }

    let decoded_body = if is_chunked {
        decode_http_chunked(body_bytes, limit)?
    } else if let Some(len) = content_length {
        if body_bytes.len() < len {
            return Err(HwEntropyError::InvalidResponse(format!(
                "truncated HTTP body: expected {len} bytes, received {}",
                body_bytes.len()
            )));
        }
        body_bytes[..len].to_vec()
    } else {
        body_bytes.to_vec()
    };

    if !(200..300).contains(&status) {
        let snippet_len = decoded_body.len().min(256);
        let snippet = String::from_utf8_lossy(&decoded_body[..snippet_len])
            .trim()
            .to_string();
        let message = if snippet.is_empty() {
            reason_phrase.to_string()
        } else if reason_phrase.is_empty() {
            snippet
        } else {
            format!("{reason_phrase}: {snippet}")
        };
        return Err(HwEntropyError::HttpError { status, message });
    }

    Ok(decoded_body)
}

fn decode_http_chunked(input: &[u8], limit: usize) -> Result<Vec<u8>, HwEntropyError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some(rel_crlf) = input[pos..].windows(2).position(|w| w == b"\r\n") else {
            zeroize_slice(&mut out);
            return Err(HwEntropyError::InvalidResponse(
                "malformed chunked encoding header".into(),
            ));
        };
        let size_line = std::str::from_utf8(&input[pos..pos + rel_crlf]).map_err(|_| {
            zeroize_slice(&mut out);
            HwEntropyError::InvalidResponse("non-UTF-8 chunk size".into())
        })?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(hex_part, 16).map_err(|_| {
            zeroize_slice(&mut out);
            HwEntropyError::InvalidResponse(format!("invalid chunk size '{hex_part}'"))
        })?;
        pos += rel_crlf + 2;

        if chunk_size == 0 {
            return Ok(out);
        }
        let next_len = out.len().saturating_add(chunk_size);
        if next_len > limit {
            zeroize_slice(&mut out);
            return Err(HwEntropyError::ResponseTooLarge {
                limit,
                received: next_len,
            });
        }
        let Some(chunk_end) = pos.checked_add(chunk_size) else {
            zeroize_slice(&mut out);
            return Err(HwEntropyError::InvalidResponse("chunk size overflow".into()));
        };
        if chunk_end + 2 > input.len() || &input[chunk_end..chunk_end + 2] != b"\r\n" {
            zeroize_slice(&mut out);
            return Err(HwEntropyError::InvalidResponse(
                "truncated chunked body or missing CRLF".into(),
            ));
        }
        out.extend_from_slice(&input[pos..chunk_end]);
        pos = chunk_end + 2;
    }
}

impl QkdKeyProvider for Etsi014QkdClient {
    fn get_key(&mut self, peer_id: &str, num_bytes: usize) -> Result<Vec<u8>, QkdError> {
        if num_bytes == 0 {
            return Ok(Vec::new());
        }
        let target_sae = if peer_id.is_empty() {
            self.config.slave_sae_id.as_str()
        } else {
            peer_id
        };
        let size_bits = num_bytes
            .checked_mul(8)
            .ok_or_else(|| QkdError::InvalidParameter("num_bytes bit-length overflow".into()))?;
        let mut keys = self
            .request_enc_keys_for_sae(target_sae, 1, size_bits)
            .map_err(QkdError::from)?;
        let key = keys
            .pop()
            .ok_or_else(|| QkdError::EntropyFailure("KME returned no key".into()))?;
        Ok(key.take_bytes())
    }

    fn status(&self, peer_id: &str) -> QkdLinkStatus {
        let target_sae = if peer_id.is_empty() {
            self.config.slave_sae_id.as_str()
        } else {
            peer_id
        };
        let delivered = self
            .total_delivered_bytes
            .lock()
            .map(|g| *g)
            .unwrap_or(0);
        match self.get_status_for_sae(target_sae) {
            Ok(st) => {
                let bytes_per_key = st.key_size / 8;
                QkdLinkStatus {
                    stored_key_bytes: st.stored_key_count.saturating_mul(bytes_per_key),
                    max_key_bytes: st.max_key_count.saturating_mul(bytes_per_key),
                    last_qber: 0.0,
                    total_delivered_bytes: delivered,
                }
            }
            Err(_) => QkdLinkStatus {
                stored_key_bytes: 0,
                max_key_bytes: 0,
                last_qber: 0.0,
                total_delivered_bytes: delivered,
            },
        }
    }
}

impl EntropySource for Etsi014QkdClient {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
        if buf.is_empty() {
            return Ok(());
        }
        // Cap per-request raw size at 4096 bytes (~5.5 KiB Base64) to stay well under 64 KiB cap.
        for chunk in buf.chunks_mut(MAX_STREAM_CHUNK_BYTES) {
            let req_bytes = chunk.len().max(32);
            let res = self.request_enc_keys(1, req_bytes * 8);
            match res {
                Ok(mut keys) => {
                    if let Some(key) = keys.pop() {
                        chunk.copy_from_slice(&key.as_bytes()[..chunk.len()]);
                        // `key` drops here, volatile-zeroizing its full buffer.
                    } else {
                        zeroize_slice(buf);
                        return Err(QkdError::EntropyFailure("KME returned no key".into()));
                    }
                }
                Err(err) => {
                    zeroize_slice(buf);
                    return Err(QkdError::from(err));
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// 7. Information-Theoretic Defense-in-Depth Combiner (XorEntropyMixer)
// ============================================================================

/// Information-theoretic entropy combiner that XORs two independent [`EntropySource`] streams.
///
/// By Shannon's secrecy theorem, if `A` and `B` are statistically independent and at least ONE
/// of them is uniform over `{0, 1}^n`, then `A XOR B` is unconditionally uniform over `{0, 1}^n`,
/// even if the other source is completely compromised, constant, or controlled by an adversary.
///
/// Intermediate staging buffers are strictly stack-allocated and volatile-zeroized after every
/// chunk and on any error.
#[derive(Debug)]
pub struct XorEntropyMixer<A: EntropySource, B: EntropySource> {
    source_a: A,
    source_b: B,
}

impl<A: EntropySource, B: EntropySource> XorEntropyMixer<A, B> {
    /// Combine two independent entropy sources via byte-wise XOR.
    pub const fn new(source_a: A, source_b: B) -> Self {
        Self { source_a, source_b }
    }

    /// Borrow the first entropy source.
    pub fn source_a(&self) -> &A {
        &self.source_a
    }

    /// Borrow the second entropy source.
    pub fn source_b(&self) -> &B {
        &self.source_b
    }

    /// Mutably borrow the first entropy source.
    pub fn source_a_mut(&mut self) -> &mut A {
        &mut self.source_a
    }

    /// Mutably borrow the second entropy source.
    pub fn source_b_mut(&mut self) -> &mut B {
        &mut self.source_b
    }

    /// Consume the mixer and return its two underlying sources.
    pub fn into_parts(self) -> (A, B) {
        (self.source_a, self.source_b)
    }
}

impl<A: EntropySource, B: EntropySource> EntropySource for XorEntropyMixer<A, B> {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut tmp = [0u8; MAX_STREAM_CHUNK_BYTES];
        for chunk in buf.chunks_mut(MAX_STREAM_CHUNK_BYTES) {
            if let Err(err) = self.source_a.fill_random(chunk) {
                zeroize_slice(&mut tmp);
                zeroize_slice(buf);
                return Err(err);
            }
            let tmp_slice = &mut tmp[..chunk.len()];
            if let Err(err) = self.source_b.fill_random(tmp_slice) {
                zeroize_slice(&mut tmp);
                zeroize_slice(buf);
                return Err(err);
            }
            for (dst, &src) in chunk.iter_mut().zip(tmp_slice.iter()) {
                *dst ^= src;
            }
            zeroize_slice(tmp_slice);
        }

        Ok(())
    }
}

// ============================================================================
// 8. Auto-Discovery Helper
// ============================================================================

/// Result of automatic hardware QRNG discovery via [`discover_best_entropy_source`].
#[derive(Debug)]
pub enum DiscoveredEntropySource {
    /// A healthy hardware QRNG was discovered and combined via Shannon XOR with OS `/dev/urandom`.
    HardwareMixed {
        device_path: PathBuf,
        startup_report: HealthCheckReport,
        source: XorEntropyMixer<LinuxHwrngSource, OsEntropySource>,
    },
    /// No healthy hardware QRNG was available; cleanly fell back to OS `/dev/urandom`.
    OsFallback {
        attempted_paths: Vec<PathBuf>,
        reason: String,
        source: OsEntropySource,
    },
}

impl DiscoveredEntropySource {
    /// Returns `true` if a live, health-verified hardware QRNG is backing this source.
    pub fn is_hardware_backed(&self) -> bool {
        matches!(self, DiscoveredEntropySource::HardwareMixed { .. })
    }

    /// Human-readable diagnostic summary describing the selected entropy source.
    pub fn diagnostic(&self) -> String {
        match self {
            DiscoveredEntropySource::HardwareMixed {
                device_path,
                startup_report,
                ..
            } => format!(
                "hardware QRNG '{}' active (XOR-mixed with /dev/urandom; startup monobit_z={:.2}, runs_z={:.2})",
                device_path.display(),
                startup_report.monobit_z,
                startup_report.runs_z
            ),
            DiscoveredEntropySource::OsFallback { reason, .. } => {
                format!("fallback to OS /dev/urandom ({reason})")
            }
        }
    }
}

impl EntropySource for DiscoveredEntropySource {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
        match self {
            DiscoveredEntropySource::HardwareMixed { source, .. } => source.fill_random(buf),
            DiscoveredEntropySource::OsFallback { source, .. } => source.fill_random(buf),
        }
    }
}

/// Auto-discover the highest-assurance entropy source available on this host.
///
/// Checks `VRNM_QRNG_DEVICE` (if set and non-empty) followed by `/dev/hwrng`. For each readable
/// candidate device, runs a 256-byte startup NIST SP 800-90B health test before returning a live
/// [`XorEntropyMixer<LinuxHwrngSource, OsEntropySource>`]. If no healthy hardware device is
/// available, cleanly falls back to [`OsEntropySource`] with detailed diagnostic reasons.
pub fn discover_best_entropy_source() -> DiscoveredEntropySource {
    let mut candidates = Vec::with_capacity(2);
    if let Some(env_val) = std::env::var_os(VRNM_QRNG_DEVICE_ENV) {
        if !env_val.is_empty() {
            candidates.push(PathBuf::from(env_val));
        }
    }
    let default_path = PathBuf::from(DEFAULT_HWRNG_PATH);
    if !candidates.contains(&default_path) {
        candidates.push(default_path);
    }
    discover_best_entropy_source_with_candidates(&candidates)
}

/// Deterministic/testable variant of [`discover_best_entropy_source`] probing explicit `candidates`.
pub fn discover_best_entropy_source_with_candidates(
    candidates: &[PathBuf],
) -> DiscoveredEntropySource {
    let mut reasons = Vec::new();
    let mut attempted_paths = Vec::with_capacity(candidates.len());

    for path in candidates {
        attempted_paths.push(path.clone());
        match LinuxHwrngSource::open(path) {
            Ok(mut hw) => match hw.run_startup_health_test(256) {
                Ok(startup_report) => {
                    return DiscoveredEntropySource::HardwareMixed {
                        device_path: path.clone(),
                        startup_report,
                        source: XorEntropyMixer::new(hw, OsEntropySource::new()),
                    };
                }
                Err(err) => {
                    reasons.push(format!("'{}': startup health test failed: {err}", path.display()));
                }
            },
            Err(err) => {
                reasons.push(format!("'{}': {err}", path.display()));
            }
        }
    }

    let reason = if reasons.is_empty() {
        "no hardware QRNG candidate paths configured".to_string()
    } else {
        reasons.join("; ")
    };

    DiscoveredEntropySource::OsFallback {
        attempted_paths,
        reason,
        source: OsEntropySource::new(),
    }
}

// ============================================================================
// 9. Comprehensive Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use crate::qkd::check_entropy_health;

    static TEMP_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_path(label: &str) -> PathBuf {
        let seq = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "vernam_hw_entropy_{label}_{}_{seq}.bin",
            std::process::id()
        ))
    }

    #[test]
    fn test_rfc4648_base64_vectors_and_invalid_rejection() {
        // Official RFC 4648 Section 10 test vectors.
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, expected_b64) in vectors {
            assert_eq!(encode_base64(raw), expected_b64);
            assert_eq!(decode_base64(expected_b64).unwrap(), raw);
        }

        // Full 0x00..=0xFF binary round-trip across all length residues (mod 3).
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        for len in [1, 2, 3, 4, 31, 32, 33, 255, 256] {
            let slice = &all_bytes[..len];
            let enc = encode_base64(slice);
            let dec = decode_base64(&enc).expect("valid base64 must decode");
            assert_eq!(dec, slice);
        }

        // Strict invalid input rejection.
        let invalid_inputs = [
            "A",         // length % 4 != 0
            "AB",        // length % 4 != 0
            "ABC",       // length % 4 != 0
            "Zm9v=",     // length 5
            "Zm9!",      // non-alphabet symbol
            "Zm9-",      // URL-safe char rejected in standard RFC 4648
            "Zm9_",      // URL-safe char rejected in standard RFC 4648
            "Zm9v\n",    // whitespace rejected
            "=m9v",      // padding in position 0
            "Z=9v",      // padding in position 1
            "Zm=v",      // single padding in position 2 without position 3
            "Zg==Zg==",  // padding in non-final quantum
            "AB==",      // non-zero canonical padding bits (0x01 & 0x0F != 0)
            "AAB=",      // non-zero canonical padding bits (0x01 & 0x03 != 0)
            "====",      // all padding
        ];
        for bad in invalid_inputs {
            let err = decode_base64(bad)
                .expect_err(&format!("invalid base64 '{bad}' must be rejected"));
            assert!(
                matches!(err, HwEntropyError::InvalidBase64(_)),
                "unexpected error for '{bad}': {err:?}"
            );
        }
    }

    #[test]
    fn test_continuous_health_monitor_catches_stuck_zero_0xaa_and_rct_faults() {
        // 1. Healthy OS random stream passes repeatedly across APT window boundaries (> 1024 bytes).
        let mut os = OsEntropySource::new();
        let mut monitor = ContinuousHealthMonitor::new();
        for _ in 0..8 {
            let mut chunk = [0u8; 256];
            os.fill_random(&mut chunk).unwrap();
            let report = monitor
                .gate(&mut chunk)
                .expect("healthy OS random chunk must pass continuous health gate");
            assert_eq!(report.bytes_checked, 256);
            assert!(report.monobit_z < DEFAULT_MAX_Z_SCORE);
            assert!(report.runs_z < DEFAULT_MAX_Z_SCORE);
        }
        assert!(monitor.is_healthy());
        assert_eq!(monitor.total_bytes_checked(), 2048);

        // 2. Stuck-at-zero fails immediately and volatile-zeroizes buffer.
        let mut zero_mon = ContinuousHealthMonitor::new();
        let mut zeros = [0u8; 64];
        let err = zero_mon.gate(&mut zeros).expect_err("stuck-at-zero must fail");
        assert!(matches!(err, HwEntropyError::HealthCheckFailed { .. }));
        assert!(!zero_mon.is_healthy());

        // 3. Stuck-at-0xFF fails immediately and buffer is wiped to 0x00.
        let mut ff_mon = ContinuousHealthMonitor::new();
        let mut ones = [0xFFu8; 64];
        let err = ff_mon.gate(&mut ones).expect_err("stuck-at-0xFF must fail");
        assert!(matches!(err, HwEntropyError::HealthCheckFailed { .. }));
        assert!(ones.iter().all(|&b| b == 0), "rejected buffer must be zeroized");

        // 4. Alternating 0xAA / 0x55 (monobit z == 0.0, RCT run == 1) must be caught & wiped.
        let mut alt_mon = ContinuousHealthMonitor::new();
        let mut alternating = [0u8; 64];
        for (i, b) in alternating.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0xAA } else { 0x55 };
        }
        let err = alt_mon
            .gate(&mut alternating)
            .expect_err("alternating 0xAA/0x55 must fail health monitor");
        assert!(matches!(err, HwEntropyError::HealthCheckFailed { .. }));
        assert!(
            alternating.iter().all(|&b| b == 0),
            "rejected 0xAA/0x55 buffer must be zeroized"
        );

        // 5. Repeating 0xAA fails RCT and wipes buffer.
        let mut aa_mon = ContinuousHealthMonitor::new();
        let mut aa_buf = [0xAAu8; 64];
        let err = aa_mon.gate(&mut aa_buf).expect_err("repeating 0xAA must fail");
        assert!(matches!(
            err,
            HwEntropyError::HealthCheckFailed { test: "RCT", .. }
        ));
        assert!(aa_buf.iter().all(|&b| b == 0));

        // 6. RCT fault split across two consecutive chunks (4 identical trailing + 4 identical leading).
        let mut cross_mon = ContinuousHealthMonitor::new();
        let mut chunk1 = [0u8; 64];
        os.fill_random(&mut chunk1).unwrap();
        for b in &mut chunk1[60..64] {
            *b = 0x42;
        }
        cross_mon
            .gate(&mut chunk1)
            .expect("4 identical trailing bytes is below RCT cutoff 8");

        let mut chunk2 = [0u8; 64];
        os.fill_random(&mut chunk2).unwrap();
        for b in &mut chunk2[0..4] {
            *b = 0x42;
        }
        let err = cross_mon
            .gate(&mut chunk2)
            .expect_err("8 consecutive identical bytes across chunk boundary must trip RCT");
        assert!(matches!(
            err,
            HwEntropyError::HealthCheckFailed { test: "RCT", .. }
        ));
        assert!(chunk2.iter().all(|&b| b == 0));

        // 7. Monitor remains latched fail-closed even on subsequent healthy chunks until reset().
        let mut healthy_after = [0u8; 64];
        os.fill_random(&mut healthy_after).unwrap();
        assert!(cross_mon.gate(&mut healthy_after).is_err());
        assert!(healthy_after.iter().all(|&b| b == 0));

        cross_mon.reset();
        os.fill_random(&mut healthy_after).unwrap();
        cross_mon
            .gate(&mut healthy_after)
            .expect("monitor should accept healthy data after explicit reset");
    }

    #[test]
    fn test_linux_hwrng_source_with_mock_device_file_healthy_and_faulty() {
        let mut os = OsEntropySource::new();

        // 1. Healthy mock device file.
        let healthy_path = unique_temp_path("healthy_dev");
        {
            let mut raw = vec![0u8; 16_384];
            os.fill_random(&mut raw).unwrap();
            let mut f = File::create(&healthy_path).unwrap();
            f.write_all(&raw).unwrap();
        }

        let mut dev = LinuxHwrngSource::open(&healthy_path).expect("mock device should open");
        assert_eq!(dev.device_path(), healthy_path.as_path());
        let startup = dev.run_startup_health_test(256).expect("startup test should pass");
        assert_eq!(startup.bytes_checked, 256);
        assert!(dev.is_healthy());

        // Small (< 64 bytes) and large (>= 64 bytes) reads via fill_checked and EntropySource.
        let mut small = [0u8; 13];
        dev.fill_checked(&mut small).expect("small read should pass");
        assert!(small.iter().any(|&b| b != 0));

        let mut large = vec![0u8; 5000];
        dev.fill_random(&mut large).expect("large EntropySource read should pass");
        check_entropy_health(&large, 6.0).expect("large output should be healthy");

        // Auto-discovery picks healthy mock device as HardwareMixed.
        let mut discovered = discover_best_entropy_source_with_candidates(&[
            PathBuf::from("/nonexistent/vernam_qrng_0"),
            healthy_path.clone(),
        ]);
        assert!(discovered.is_hardware_backed());
        assert!(discovered.diagnostic().contains("hardware QRNG"));
        let mut disc_buf = [0u8; 128];
        discovered.fill_random(&mut disc_buf).unwrap();
        check_entropy_health(&disc_buf, 6.0).unwrap();

        // 2. Faulty mock device file (alternating 0xAA / 0x55) must fail closed and zeroize output.
        let faulty_path = unique_temp_path("faulty_dev");
        {
            let mut bad = vec![0u8; 1024];
            for (i, b) in bad.iter_mut().enumerate() {
                *b = if i % 2 == 0 { 0xAA } else { 0x55 };
            }
            let mut f = File::create(&faulty_path).unwrap();
            f.write_all(&bad).unwrap();
        }

        let mut bad_dev = LinuxHwrngSource::open(&faulty_path).unwrap();
        let mut out = [0x99u8; 64];
        let err = bad_dev
            .fill_checked(&mut out)
            .expect_err("faulty mock device must fail health check");
        assert!(matches!(err, HwEntropyError::HealthCheckFailed { .. }));
        assert!(!bad_dev.is_healthy());
        assert!(
            out.iter().all(|&b| b == 0),
            "caller buffer must be volatile-zeroized on device fault"
        );

        // Auto-discovery rejects faulty device and cleanly falls back to OsFallback with reason.
        let mut fallback =
            discover_best_entropy_source_with_candidates(&[faulty_path.clone()]);
        assert!(!fallback.is_hardware_backed());
        assert!(fallback.diagnostic().contains("fallback to OS /dev/urandom"));
        let mut fb_buf = [0u8; 64];
        fallback.fill_random(&mut fb_buf).unwrap();
        check_entropy_health(&fb_buf, 6.0).unwrap();

        // 3. Nonexistent path returns DeviceUnavailable.
        let missing = LinuxHwrngSource::open("/nonexistent/vernam_missing_hwrng");
        assert!(matches!(missing, Err(HwEntropyError::DeviceUnavailable(_))));

        let _ = std::fs::remove_file(&healthy_path);
        let _ = std::fs::remove_file(&faulty_path);
    }

    #[test]
    fn test_etsi014_live_mock_kme_tcp_server_status_enc_and_dec_keys() {
        // Spawn a real local TCP mock ETSI GS QKD 014 KME server.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock KME TCP port");
        let addr = listener.local_addr().unwrap().to_string();

        let key_store: Arc<Mutex<HashMap<String, Vec<u8>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let store_srv = Arc::clone(&key_store);

        let expected_requests = 9usize;
        let server_handle = thread::spawn(move || {
            let mut os = OsEntropySource::new();
            let mut next_key_num = 1u64;

            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept client");
                let mut reader = BufReader::new(stream.try_clone().unwrap());

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let target = parts.next().unwrap_or("");

                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }

                let mut req_body = vec![0u8; content_len];
                if content_len > 0 {
                    reader.read_exact(&mut req_body).unwrap();
                }

                let (status_line, resp_body) = if method == "GET"
                    && target == "/api/v1/keys/slave-sae-01/status"
                {
                    (
                        "HTTP/1.1 200 OK",
                        r#"{"source_KME_ID":"KME-ALICE-01","target_KME_ID":"KME-BOB-02","master_SAE_ID":"master-sae-01","slave_SAE_ID":"slave-sae-01","key_size":256,"stored_key_count":4096,"max_key_count":8192,"max_key_per_request":16,"max_key_size":4096,"min_key_size":128,"max_SAE_ID_count":0}"#.to_string(),
                    )
                } else if method == "GET" && target.starts_with("/api/v1/keys/slave-sae-01/enc_keys")
                {
                    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
                    let mut number = 1usize;
                    let mut size_bits = 256usize;
                    for pair in query.split('&') {
                        if let Some((k, v)) = pair.split_once('=') {
                            if k == "number" {
                                number = v.parse().unwrap_or(1);
                            } else if k == "size" {
                                size_bits = v.parse().unwrap_or(256);
                            }
                        }
                    }
                    let mut entries = Vec::with_capacity(number);
                    for _ in 0..number {
                        let key_id = format!("550e8400-e29b-41d4-a716-{next_key_num:012}");
                        next_key_num += 1;
                        let mut key_bytes = vec![0u8; size_bits / 8];
                        os.fill_random(&mut key_bytes).unwrap();
                        let b64 = encode_base64(&key_bytes);
                        store_srv
                            .lock()
                            .unwrap()
                            .insert(key_id.clone(), key_bytes);
                        entries.push(format!("{{\"key_ID\":\"{key_id}\",\"key\":\"{b64}\"}}"));
                    }
                    (
                        "HTTP/1.1 200 OK",
                        format!("{{\"keys\":[{}]}}", entries.join(",")),
                    )
                } else if method == "POST" && target == "/api/v1/keys/master-sae-01/dec_keys" {
                    let body_str = std::str::from_utf8(&req_body).unwrap();
                    let parsed = JsonParser::parse(body_str).unwrap();
                    let ids = parsed.get("key_IDs").unwrap().as_array().unwrap();
                    let mut entries = Vec::new();
                    let guard = store_srv.lock().unwrap();
                    for item in ids {
                        let id = item.get("key_ID").unwrap().as_str().unwrap();
                        if let Some(raw_key) = guard.get(id) {
                            let b64 = encode_base64(raw_key);
                            entries.push(format!("{{\"key_ID\":\"{id}\",\"key\":\"{b64}\"}}"));
                        }
                    }
                    (
                        "HTTP/1.1 200 OK",
                        format!("{{\"keys\":[{}]}}", entries.join(",")),
                    )
                } else if target.starts_with("/api/v1/keys/corrupted-sae/enc_keys") {
                    // Malicious/faulty KME delivering low-entropy alternating 0xAA/0x55 key material!
                    let mut bad = [0u8; 32];
                    for (i, b) in bad.iter_mut().enumerate() {
                        *b = if i % 2 == 0 { 0xAA } else { 0x55 };
                    }
                    let b64 = encode_base64(&bad);
                    (
                        "HTTP/1.1 200 OK",
                        format!("{{\"keys\":[{{\"key_ID\":\"bad-key-01\",\"key\":\"{b64}\"}}]}}"),
                    )
                } else if target.starts_with("/api/v1/keys/bad-b64-sae/enc_keys") {
                    (
                        "HTTP/1.1 200 OK",
                        r#"{"keys":[{"key_ID":"bad-b64-01","key":"!!!not_base64!!!"}]}"#
                            .to_string(),
                    )
                } else if target.starts_with("/api/v1/keys/oversized-sae/enc_keys") {
                    // Exceeds MAX_ETSI_RESPONSE_BYTES = 65_536.
                    ("HTTP/1.1 200 OK", "A".repeat(MAX_ETSI_RESPONSE_BYTES + 1024))
                } else {
                    ("HTTP/1.1 503 Service Unavailable", "KME key pool empty".to_string())
                };

                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        // 1. Test get_status (req 1).
        let mut client = Etsi014QkdClient::new(&addr, "slave-sae-01", "master-sae-01").unwrap();
        let status = client.get_status().expect("get_status should succeed");
        assert_eq!(status.source_kme_id, "KME-ALICE-01");
        assert_eq!(status.target_kme_id, "KME-BOB-02");
        assert_eq!(status.key_size, 256);
        assert_eq!(status.stored_key_count, 4096);
        assert_eq!(status.max_key_count, 8192);

        // 2. Test request_enc_keys (req 2) and verify redacted Debug.
        let enc_keys = client
            .request_enc_keys(2, 256)
            .expect("request_enc_keys should succeed");
        assert_eq!(enc_keys.len(), 2);
        assert_eq!(enc_keys[0].len(), 32);
        assert_eq!(enc_keys[1].len(), 32);
        assert_ne!(enc_keys[0].as_bytes(), enc_keys[1].as_bytes());

        let dbg_str = format!("{:?}", enc_keys[0]);
        assert!(dbg_str.contains("<REDACTED>"));
        assert!(dbg_str.contains(enc_keys[0].key_id()));
        assert!(!dbg_str.contains(&format!("{:?}", enc_keys[0].as_bytes())));

        // 3. Test request_dec_keys (req 3) returns identical key bytes for both key_IDs.
        let ids = [enc_keys[0].key_id(), enc_keys[1].key_id()];
        let dec_keys = client
            .request_dec_keys(&ids)
            .expect("request_dec_keys should succeed");
        assert_eq!(dec_keys.len(), 2);
        assert_eq!(dec_keys[0].as_bytes(), enc_keys[0].as_bytes());
        assert_eq!(dec_keys[1].as_bytes(), enc_keys[1].as_bytes());

        // 4. Test QkdKeyProvider & EntropySource trait integration (reqs 4 & 5).
        let trait_key = client.get_key("slave-sae-01", 32).unwrap();
        assert_eq!(trait_key.len(), 32);
        let mut entropy_buf = [0u8; 64];
        client.fill_random(&mut entropy_buf).unwrap();
        check_entropy_health(&entropy_buf, 6.0).unwrap();

        // 5. Corrupted/low-entropy KME key material MUST be rejected by health monitor (req 6).
        let bad_entropy_client =
            Etsi014QkdClient::new(&addr, "corrupted-sae", "master-sae-01").unwrap();
        let err = bad_entropy_client
            .request_enc_keys(1, 256)
            .expect_err("corrupted low-entropy KME key must be rejected");
        assert!(matches!(err, HwEntropyError::HealthCheckFailed { .. }));
        assert!(!bad_entropy_client.is_healthy());

        // 6. Invalid Base64 from KME MUST be rejected (req 7).
        let bad_b64_client = Etsi014QkdClient::new(&addr, "bad-b64-sae", "master-sae-01").unwrap();
        let err = bad_b64_client
            .request_enc_keys(1, 256)
            .expect_err("invalid base64 from KME must be rejected");
        assert!(matches!(err, HwEntropyError::InvalidBase64(_)));

        // 7. Oversized KME response (> 64 KiB) MUST be rejected (req 8).
        let oversized_client =
            Etsi014QkdClient::new(&addr, "oversized-sae", "master-sae-01").unwrap();
        let err = oversized_client
            .request_enc_keys(1, 256)
            .expect_err("oversized KME response must be rejected");
        assert!(matches!(
            err,
            HwEntropyError::ResponseTooLarge {
                limit: MAX_ETSI_RESPONSE_BYTES,
                ..
            }
        ));

        // 8. HTTP 503 error from KME MUST map to HwEntropyError::HttpError (req 9).
        let err_client = Etsi014QkdClient::new(&addr, "empty-pool-sae", "master-sae-01").unwrap();
        let err = err_client
            .request_enc_keys(1, 256)
            .expect_err("HTTP 503 must return HttpError");
        assert!(matches!(err, HwEntropyError::HttpError { status: 503, .. }));

        server_handle.join().expect("mock KME server thread finished cleanly");
    }

    #[test]
    fn test_xor_entropy_mixer_preserves_uniformity_even_when_one_source_is_all_zero_compromised() {
        struct CompromisedConstantSource(u8);
        impl EntropySource for CompromisedConstantSource {
            fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
                buf.fill(self.0);
                Ok(())
            }
        }

        struct DeterministicPatternSource(u8);
        impl EntropySource for DeterministicPatternSource {
            fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
                for b in buf.iter_mut() {
                    *b = self.0;
                    self.0 = self.0.wrapping_add(1);
                }
                Ok(())
            }
        }

        struct FailingSource;
        impl EntropySource for FailingSource {
            fn fill_random(&mut self, _buf: &mut [u8]) -> Result<(), QkdError> {
                Err(QkdError::EntropyFailure("simulated hardware disconnect".into()))
            }
        }

        // 1. Source A completely compromised (all zeros) + honest Source B (OS entropy):
        //    By Shannon's theorem, output is unconditionally uniform and passes all health gates.
        let mut mixer_zero_a =
            XorEntropyMixer::new(CompromisedConstantSource(0x00), OsEntropySource::new());
        let mut out_a = vec![0u8; 8192];
        mixer_zero_a.fill_random(&mut out_a).unwrap();

        let health_a = check_entropy_health(&out_a, 6.0).unwrap();
        assert!((health_a.ones_ratio - 0.5).abs() < 0.03);
        let mut mon_a = ContinuousHealthMonitor::new();
        mon_a.check(&out_a).expect("XOR output must pass NIST SP 800-90B monitor");

        // 2. Honest Source A (OS entropy) + Source B completely compromised (0xAA pattern):
        let mut mixer_const_b =
            XorEntropyMixer::new(OsEntropySource::new(), CompromisedConstantSource(0xAA));
        let mut out_b = vec![0u8; 8192];
        mixer_const_b.fill_random(&mut out_b).unwrap();

        let health_b = check_entropy_health(&out_b, 6.0).unwrap();
        assert!((health_b.ones_ratio - 0.5).abs() < 0.03);
        let mut mon_b = ContinuousHealthMonitor::new();
        mon_b.check(&out_b).expect("XOR output must pass NIST SP 800-90B monitor");

        // 3. Exact byte-for-byte XOR identity verification.
        let mut exact_mixer = XorEntropyMixer::new(
            DeterministicPatternSource(0x10),
            CompromisedConstantSource(0x5A),
        );
        let mut exact_out = [0u8; 64];
        exact_mixer.fill_random(&mut exact_out).unwrap();
        for (i, &b) in exact_out.iter().enumerate() {
            assert_eq!(b, (0x10u8.wrapping_add(i as u8)) ^ 0x5A);
        }

        // 4. Fail-closed zeroization if second source fails after first source filled buffer.
        let mut failing_mixer = XorEntropyMixer::new(OsEntropySource::new(), FailingSource);
        let mut fail_buf = [0x77u8; 128];
        assert!(failing_mixer.fill_random(&mut fail_buf).is_err());
        assert!(
            fail_buf.iter().all(|&b| b == 0),
            "XOR mixer must volatile-zeroize output buffer if either source fails"
        );
    }
}
