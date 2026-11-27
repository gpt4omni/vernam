//! Quantum Key Distribution (QKD), Pluggable Hardware Entropy, and High-Throughput Key Pools
//! for Vernam (VRNM).
//!
//! Zero external crates, zero computational cryptography (no SHA, AES, RSA, ECDSA, or ChaCha).
//! All security rests on information-theoretic primitives:
//! - Pluggable hardware/OS true random entropy sources (`EntropySource`) with online health checks
//! - Standard ETSI GS QKD 014-style key delivery interface (`QkdKeyProvider`)
//! - Blazing-fast word-level (`u64`) 2-universal Toeplitz privacy amplification (`toeplitz_hash_u64`)
//! - Simulated BB84 + Weak/Vacuum Decoy-State QKD channel (`Bb84Channel`) with QBER eavesdropper
//!   detection (`qber > 0.11`) and Photon-Number-Splitting (PNS) decoy anomaly detection
//! - Pre-buffered multi-channel high-throughput OTP key pool (`BufferedQkdPool`) serving bursts at
//!   RAM speed with automatic background replenishment and volatile memory zeroization.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{Ordering, compiler_fence};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, fill_os_random, mul_mod, reduce, zeroize_slice, zeroize_u128,
};

/// Shor-Preskill unconditional security QBER threshold for BB84 (11%).
pub const BB84_QBER_ABORT_THRESHOLD: f64 = 0.11;

/// Default privacy amplification block size in output bytes (256 bytes = 2048 bits).
/// Chunking large exchanges into independent Toeplitz blocks keeps L1 cache hot and
/// scales linearly O(N) while maintaining <= 2^-100 trace distance per block.
const PA_OUTPUT_BLOCK_BYTES: usize = 256;

/// Errors returned by QKD, entropy, privacy amplification, and key pool operations.
#[derive(Debug, Clone, PartialEq)]
pub enum QkdError {
    /// Failed to open or read from an entropy device.
    EntropyFailure(String),
    /// Hardware QRNG output failed online monobit or stuck-output health checks.
    EntropyHealthCheckFailed {
        ones: usize,
        total_bits: usize,
        reason: String,
    },
    /// Quantum Bit Error Rate exceeded the Shor-Preskill security bound.
    EavesdropperDetected { qber: f64, threshold: f64 },
    /// Decoy-state yield statistics indicate a Photon-Number-Splitting (PNS)
    /// or selective signal attenuation attack.
    DecoyAnomalyDetected {
        signal_yield: f64,
        decoy_yield: f64,
        ratio: f64,
    },
    /// Not enough sifted bits remained after QBER sampling and reconciliation.
    InsufficientSiftedBits { needed: usize, obtained: usize },
    /// Toeplitz seed slice was shorter than `raw_bits + out_bits - 1` bits.
    InsufficientSeedBits { needed: usize, provided: usize },
    /// Invalid configuration or argument supplied by caller.
    InvalidParameter(String),
    /// Buffered key pool could not satisfy the request (e.g., shut down).
    PoolExhausted { requested: usize, available: usize },
    /// Post-reconciliation universal Carter-Wegman confirmation tag failed (residual key mismatch).
    ReconciliationFailed(String),
    /// Requested QKD peer link is unavailable.
    PeerUnavailable(String),
}

impl fmt::Display for QkdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QkdError::EntropyFailure(msg) => write!(f, "entropy source failure: {msg}"),
            QkdError::EntropyHealthCheckFailed {
                ones,
                total_bits,
                reason,
            } => write!(
                f,
                "entropy health check failed ({ones}/{total_bits} ones): {reason}"
            ),
            QkdError::EavesdropperDetected { qber, threshold } => write!(
                f,
                "eavesdropper detected: QBER {:.4} exceeds threshold {:.4}",
                qber, threshold
            ),
            QkdError::DecoyAnomalyDetected {
                signal_yield,
                decoy_yield,
                ratio,
            } => write!(
                f,
                "decoy-state PNS anomaly detected: Q_mu={:.5}, Q_nu={:.5}, normalized ratio={:.4}",
                signal_yield, decoy_yield, ratio
            ),
            QkdError::InsufficientSiftedBits { needed, obtained } => write!(
                f,
                "insufficient sifted bits: needed {needed}, obtained {obtained}"
            ),
            QkdError::InsufficientSeedBits { needed, provided } => write!(
                f,
                "insufficient Toeplitz seed bits: needed {needed}, provided {provided}"
            ),
            QkdError::InvalidParameter(msg) => write!(f, "invalid QKD parameter: {msg}"),
            QkdError::PoolExhausted {
                requested,
                available,
            } => write!(
                f,
                "QKD key pool exhausted: requested {requested} bytes, available {available} bytes"
            ),
            QkdError::ReconciliationFailed(msg) => {
                write!(f, "QKD post-reconciliation confirmation failed: {msg}")
            }
            QkdError::PeerUnavailable(peer) => write!(f, "QKD peer unavailable: {peer}"),
        }
    }
}

impl Error for QkdError {}

/// Volatile wipe for `u64` secret buffers so the compiler cannot elide zeroing.
#[inline(never)]
pub fn zeroize_u64_slice(buf: &mut [u64]) {
    for word in buf.iter_mut() {
        // SAFETY: `word` is a valid mutable reference to an initialized `u64`.
        unsafe { std::ptr::write_volatile(word, 0u64) };
    }
    compiler_fence(Ordering::SeqCst);
}

// ============================================================================
// 1. Pluggable Hardware Entropy Traits & Sources
// ============================================================================

/// Pluggable physical or OS entropy source for QKD bases, decoy choices, and OTP keys.
pub trait EntropySource {
    /// Fill `buf` completely with fresh random bytes.
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError>;
}

/// Operating system entropy source reading `/dev/urandom` via `crate::field::fill_os_random`.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropySource;

impl OsEntropySource {
    /// Create a new OS entropy source backed by `/dev/urandom`.
    pub const fn new() -> Self {
        Self
    }
}

impl EntropySource for OsEntropySource {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
        if buf.is_empty() {
            return Ok(());
        }
        fill_os_random(buf);
        Ok(())
    }
}

/// Summary statistics from an online entropy health check.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyHealthStats {
    pub total_bits: usize,
    pub ones: usize,
    pub ones_ratio: f64,
    pub z_score: f64,
}

/// Run NIST-inspired stuck-output and monobit sanity checks on a hardware RNG byte sample.
///
/// - Rejects samples of >= 16 bytes where every byte is identical (stuck diode / zeroed stream).
/// - For samples of >= 32 bytes (256+ bits), verifies the monobit balance z-score
///   `|2 * ones - n| / sqrt(n) <= max_z_score` (default `6.0`, false-positive rate < 2e-9).
pub fn check_entropy_health(
    data: &[u8],
    max_z_score: f64,
) -> Result<EntropyHealthStats, QkdError> {
    let total_bits = data.len() * 8;
    if total_bits == 0 {
        return Ok(EntropyHealthStats {
            total_bits: 0,
            ones: 0,
            ones_ratio: 0.5,
            z_score: 0.0,
        });
    }

    let ones: usize = data.iter().map(|b| b.count_ones() as usize).sum();
    let ones_ratio = ones as f64 / total_bits as f64;
    let diff = (2.0 * ones as f64) - (total_bits as f64);
    let z_score = diff.abs() / (total_bits as f64).sqrt();

    if data.len() >= 16 {
        let first = data[0];
        if data.iter().all(|&b| b == first) {
            return Err(QkdError::EntropyHealthCheckFailed {
                ones,
                total_bits,
                reason: format!("stuck output detected: all {} bytes equal 0x{first:02x}", data.len()),
            });
        }
    }

    if total_bits >= 256 && z_score > max_z_score {
        return Err(QkdError::EntropyHealthCheckFailed {
            ones,
            total_bits,
            reason: format!(
                "monobit imbalance: ones_ratio={ones_ratio:.4}, z={z_score:.2} > {max_z_score:.2}"
            ),
        });
    }

    Ok(EntropyHealthStats {
        total_bits,
        ones,
        ones_ratio,
        z_score,
    })
}

/// Hardware Quantum Random Number Generator (QRNG) adapter reading `/dev/hwrng` or a
/// pluggable character device path with online monobit and stuck-output health checks.
#[derive(Debug)]
pub struct HardwareQrngAdapter {
    device_path: PathBuf,
    file: Option<File>,
    max_z_score: f64,
    health_window_bytes: usize,
}

impl HardwareQrngAdapter {
    /// Default Linux hardware RNG device path (`/dev/hwrng`).
    pub const DEFAULT_DEVICE_PATH: &'static str = "/dev/hwrng";

    /// Create an adapter targeting `/dev/hwrng` with a 6-sigma monobit health threshold.
    pub fn new() -> Self {
        Self::with_path(Self::DEFAULT_DEVICE_PATH)
    }

    /// Create an adapter targeting a custom hardware QRNG device path (e.g., `/dev/qrandom0`).
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            device_path: path.as_ref().to_path_buf(),
            file: None,
            max_z_score: 6.0,
            health_window_bytes: 64,
        }
    }

    /// Configure the monobit z-score ceiling (default `6.0`).
    pub fn with_max_z_score(mut self, max_z_score: f64) -> Result<Self, QkdError> {
        if !max_z_score.is_finite() || max_z_score <= 0.0 {
            return Err(QkdError::InvalidParameter(
                "max_z_score must be finite and positive".into(),
            ));
        }
        self.max_z_score = max_z_score;
        Ok(self)
    }

    /// Return the configured device path.
    pub fn device_path(&self) -> &Path {
        &self.device_path
    }

    /// Open the underlying QRNG device if not already open.
    fn ensure_open(&mut self) -> Result<&mut File, QkdError> {
        if self.file.is_none() {
            let f = File::open(&self.device_path).map_err(|e| {
                QkdError::EntropyFailure(format!(
                    "failed to open QRNG device '{}': {e}",
                    self.device_path.display()
                ))
            })?;
            self.file = Some(f);
        }
        Ok(self.file.as_mut().expect("file initialized above"))
    }

    /// Explicitly sample `sample_bytes` from the hardware device, verify health, and wipe sample.
    pub fn run_health_check(&mut self, sample_bytes: usize) -> Result<EntropyHealthStats, QkdError> {
        let len = sample_bytes.max(32);
        let mut sample = vec![0u8; len];
        let res = (|| {
            let file = self.ensure_open()?;
            file.read_exact(&mut sample).map_err(|e| {
                QkdError::EntropyFailure(format!(
                    "failed reading {len} bytes from '{}': {e}",
                    self.device_path.display()
                ))
            })?;
            check_entropy_health(&sample, self.max_z_score)
        })();
        zeroize_slice(&mut sample);
        res
    }
}

impl Default for HardwareQrngAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropySource for HardwareQrngAdapter {
    fn fill_random(&mut self, buf: &mut [u8]) -> Result<(), QkdError> {
        if buf.is_empty() {
            return Ok(());
        }

        let max_z = self.max_z_score;
        let window = self.health_window_bytes;

        if buf.len() >= 32 {
            let path_display = self.device_path.display().to_string();
            let file = self.ensure_open()?;
            file.read_exact(buf).map_err(|e| {
                QkdError::EntropyFailure(format!(
                    "failed reading {} bytes from '{path_display}': {e}",
                    buf.len()
                ))
            })?;
            if let Err(err) = check_entropy_health(buf, max_z) {
                zeroize_slice(buf);
                return Err(err);
            }
            return Ok(());
        }

        // For small reads (< 32 bytes), read a full health-checked window and copy prefix.
        let mut staging = vec![0u8; window.max(buf.len())];
        let path_display = self.device_path.display().to_string();
        let read_res = {
            let file = self.ensure_open()?;
            file.read_exact(&mut staging).map_err(|e| {
                QkdError::EntropyFailure(format!(
                    "failed reading {} bytes from '{path_display}': {e}",
                    staging.len()
                ))
            })
        };
        if let Err(err) = read_res {
            zeroize_slice(&mut staging);
            return Err(err);
        }

        let health_res = check_entropy_health(&staging, max_z);
        if let Err(err) = health_res {
            zeroize_slice(&mut staging);
            return Err(err);
        }

        buf.copy_from_slice(&staging[..buf.len()]);
        zeroize_slice(&mut staging);
        Ok(())
    }
}

/// Internal buffered reader over any `EntropySource` to avoid tiny syscalls during photon simulation.
struct EntropyStream<'a, E: EntropySource> {
    source: &'a mut E,
    buf: [u8; 4096],
    pos: usize,
    valid: usize,
}

impl<'a, E: EntropySource> EntropyStream<'a, E> {
    fn new(source: &'a mut E) -> Self {
        Self {
            source,
            buf: [0u8; 4096],
            pos: 0,
            valid: 0,
        }
    }

    #[inline]
    fn refill(&mut self) -> Result<(), QkdError> {
        self.source.fill_random(&mut self.buf)?;
        self.pos = 0;
        self.valid = self.buf.len();
        Ok(())
    }

    #[inline]
    fn next_u64(&mut self) -> Result<u64, QkdError> {
        if self.valid - self.pos < 8 {
            self.refill()?;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    #[inline]
    fn next_u16(&mut self) -> Result<u16, QkdError> {
        if self.valid - self.pos < 2 {
            self.refill()?;
        }
        let val = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    fn fill_u64s(&mut self, dst: &mut [u64]) -> Result<(), QkdError> {
        for word in dst.iter_mut() {
            *word = self.next_u64()?;
        }
        Ok(())
    }

    /// Generate a 64-bit mask where each bit is 1 independently with probability `p`.
    #[inline]
    fn bernoulli_mask_64(&mut self, p: f64) -> Result<u64, QkdError> {
        if p <= 0.0 {
            return Ok(0u64);
        }
        if p >= 1.0 {
            return Ok(u64::MAX);
        }
        // Fast exact path for p == 0.5
        if (p - 0.5).abs() < 1e-12 {
            return self.next_u64();
        }
        let threshold = (p * 65536.0).round().clamp(0.0, 65536.0) as u32;
        let mut mask = 0u64;
        for bit in 0..64 {
            if (self.next_u16()? as u32) < threshold {
                mask |= 1u64 << bit;
            }
        }
        Ok(mask)
    }
}

impl<E: EntropySource> Drop for EntropyStream<'_, E> {
    fn drop(&mut self) {
        zeroize_slice(&mut self.buf);
    }
}

// ============================================================================
// 2. ETSI GS QKD 014-Style Key Provider Trait
// ============================================================================

/// Operational telemetry for an ETSI GS QKD 014-style QKD key link.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QkdLinkStatus {
    /// Bytes currently buffered and ready for immediate delivery.
    pub stored_key_bytes: usize,
    /// Maximum buffer capacity in bytes (0 for on-demand links).
    pub max_key_bytes: usize,
    /// Most recently observed Quantum Bit Error Rate.
    pub last_qber: f64,
    /// Total purified key bytes delivered over this link.
    pub total_delivered_bytes: u64,
}

/// Standard **ETSI GS QKD 014**-style key delivery interface.
///
/// Consensus, wallet, and network layers depend only on this trait, allowing real
/// fiber or satellite QKD hardware (KME / HSM endpoints) to drop in seamlessly.
pub trait QkdKeyProvider {
    /// Retrieve `num_bytes` of purified, information-theoretically secure shared key
    /// material associated with `peer_id`.
    fn get_key(&mut self, peer_id: &str, num_bytes: usize) -> Result<Vec<u8>, QkdError>;

    /// Query link health and buffered key depth (ETSI GS QKD 014 `get_status` analogue).
    fn status(&self, _peer_id: &str) -> QkdLinkStatus {
        QkdLinkStatus::default()
    }

    /// Derive a uniform random element in `F_(2^127 - 1)` directly from QKD key material
    /// via rejection sampling (zero modulo bias), zeroizing intermediate byte buffers.
    fn get_field_element(&mut self, peer_id: &str) -> Result<u128, QkdError> {
        loop {
            let mut key = self.get_key(peer_id, 16)?;
            if key.len() != 16 {
                zeroize_slice(&mut key);
                return Err(QkdError::InvalidParameter(
                    "provider returned unexpected byte length for field element".into(),
                ));
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&key);
            zeroize_slice(&mut key);
            let v = u128::from_le_bytes(arr) & PRIME_P;
            zeroize_slice(&mut arr);
            if v < PRIME_P {
                return Ok(v);
            }
        }
    }
}

// ============================================================================
// 3. Blazing-Fast Word-Level (u64) Toeplitz 2-Universal Hash Privacy Amplification
// ============================================================================

/// Compute the minimum number of `u64` seed words required for `toeplitz_hash_u64`.
#[inline]
pub const fn toeplitz_seed_words(raw_bits: usize, out_bits: usize) -> usize {
    if raw_bits == 0 || out_bits == 0 {
        return 0;
    }
    (raw_bits + out_bits - 1).div_ceil(64)
}

/// Blazing-fast word-level (`u64`) 2-universal Toeplitz hash over GF(2) for QKD privacy
/// amplification.
///
/// Computes the exact matrix-vector product `y = T * x (mod 2)` where:
/// - `x` consists of the first `raw_bits` bits of `raw` (LSB-first within each `u64`),
/// - `T` is the `out_bits x raw_bits` binary Toeplitz matrix whose entries satisfy
///   `T[i, j] = seed_bit[(out_bits - 1 - i) + j]` (constant along every diagonal:
///   `T[i, j] == T[i + 1, j + 1]`),
/// - `y` is returned packed into `out_bits.div_ceil(64)` `u64` words with any trailing
///   unused bits in the final word guaranteed to be zero.
///
/// # Performance
/// Operates 64 bits at a time via branchless XOR-accumulation over GF(2) followed by a
/// single hardware `count_ones()` (`POPCNT`) instruction per output bit.
pub fn toeplitz_hash_u64(
    raw: &[u64],
    raw_bits: usize,
    seed: &[u64],
    out_bits: usize,
) -> Result<Vec<u64>, QkdError> {
    if out_bits == 0 {
        return Ok(Vec::new());
    }

    let out_words = out_bits.div_ceil(64);
    if raw_bits == 0 {
        return Ok(vec![0u64; out_words]);
    }

    let needed_raw_words = raw_bits.div_ceil(64);
    if raw.len() < needed_raw_words {
        return Err(QkdError::InvalidParameter(format!(
            "raw slice has {} words, need at least {needed_raw_words} for {raw_bits} bits",
            raw.len()
        )));
    }

    let needed_seed_bits = raw_bits + out_bits - 1;
    let needed_seed_words = needed_seed_bits.div_ceil(64);
    if seed.len() < needed_seed_words {
        return Err(QkdError::InsufficientSeedBits {
            needed: needed_seed_bits,
            provided: seed.len() * 64,
        });
    }

    let full_words = raw_bits / 64;
    let rem_bits = raw_bits % 64;
    let tail_mask: u64 = if rem_bits == 0 {
        0
    } else {
        (1u64 << rem_bits) - 1
    };
    let tail_raw = if tail_mask != 0 {
        raw[full_words] & tail_mask
    } else {
        0
    };

    let mut out = vec![0u64; out_words];
    let r = &raw[..full_words];

    for i in 0..out_bits {
        let offset = (out_bits - 1) - i;
        let word_shift = offset / 64;
        let bit_shift = offset % 64;

        let mut acc = 0u64;
        if bit_shift == 0 {
            if full_words > 0 {
                let s = &seed[word_shift..word_shift + full_words];
                for w in 0..full_words {
                    acc ^= s[w] & r[w];
                }
            }
            if tail_mask != 0 {
                acc ^= seed[word_shift + full_words] & tail_raw;
            }
        } else {
            let inv_shift = 64 - bit_shift;
            if full_words > 0 {
                let s0 = &seed[word_shift..word_shift + full_words];
                let s1 = &seed[word_shift + 1..word_shift + 1 + full_words];
                for w in 0..full_words {
                    let sw = (s0[w] >> bit_shift) | (s1[w] << inv_shift);
                    acc ^= sw & r[w];
                }
            }
            if tail_mask != 0 {
                let lo = seed[word_shift + full_words] >> bit_shift;
                let hi = seed
                    .get(word_shift + full_words + 1)
                    .copied()
                    .unwrap_or(0)
                    << inv_shift;
                acc ^= (lo | hi) & tail_raw;
            }
        }

        let parity = (acc.count_ones() & 1) as u64;
        out[i / 64] |= parity << (i % 64);
    }

    Ok(out)
}

/// Convert `u64` words (little-endian) to an exact `num_bytes` byte vector.
pub fn u64s_to_bytes(words: &[u64], num_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(num_bytes);
    for &w in words {
        let le = w.to_le_bytes();
        let remaining = num_bytes - out.len();
        if remaining == 0 {
            break;
        }
        let take = remaining.min(8);
        out.extend_from_slice(&le[..take]);
    }
    out
}

/// Pack a byte slice into little-endian `u64` words.
pub fn bytes_to_u64s(bytes: &[u8]) -> Vec<u64> {
    let mut words = Vec::with_capacity(bytes.len().div_ceil(8));
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        words.push(u64::from_le_bytes(chunk.try_into().expect("8-byte chunk")));
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut last = [0u8; 8];
        last[..rem.len()].copy_from_slice(rem);
        words.push(u64::from_le_bytes(last));
    }
    words
}

/// Binary Shannon entropy `h2(p) = -p log2(p) - (1 - p) log2(1 - p)`.
#[inline]
pub fn binary_entropy(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        return 0.0;
    }
    -(p * p.log2() + (1.0 - p) * (1.0 - p).log2())
}

// ============================================================================
// 4. High-Speed Simulated BB84 + Decoy-State QKD Channel
// ============================================================================

/// Simulated quantum-channel adversary models for testing eavesdropper and PNS detection.
#[derive(Debug, Clone, PartialEq)]
pub enum AttackProfile {
    /// Honest quantum channel with no adversary present.
    None,
    /// Intercept-resend attack where Eve intercepts `intercept_rate` (0.0..=1.0) of pulses,
    /// measures in a random basis, and resends. Full intercept-resend yields ~25% QBER.
    InterceptResend { intercept_rate: f64 },
    /// Photon-Number-Splitting (PNS) attack: Eve blocks `single_photon_block_rate` of
    /// single-photon pulses while forwarding multi-photon pulses at `multiphoton_transmittance`
    /// after splitting off a photon into quantum memory.
    PhotonNumberSplitting {
        single_photon_block_rate: f64,
        multiphoton_transmittance: f64,
    },
    /// Selective signal attenuation: Eve attenuates signal pulses by `signal_attenuation_factor`
    /// relative to decoy pulses (e.g., 0.4).
    SelectiveSignalAttenuation { signal_attenuation_factor: f64 },
}

/// Configuration for a simulated BB84 + Weak/Vacuum Decoy-State QKD channel.
#[derive(Debug, Clone)]
pub struct Bb84Config {
    /// Mean photon number `mu` of signal pulses (default: `0.6`).
    pub signal_intensity: f64,
    /// Mean photon number `nu` of weak decoy pulses, `0 < nu < mu` (default: `0.2`).
    pub decoy_intensity: f64,
    /// Baseline channel transmittance `eta` in `(0.0, 1.0]` (default: `0.85`).
    pub transmittance: f64,
    /// Intrinsic optical misalignment bit error rate in `[0.0, 0.5]` (default: `0.0`).
    pub intrinsic_error_rate: f64,
    /// Detector dark count probability per pulse (default: `0.0`).
    pub dark_count_rate: f64,
    /// QBER abort threshold (default: `BB84_QBER_ABORT_THRESHOLD = 0.11`).
    pub max_qber: f64,
    /// Fraction of sifted bits sacrificed for QBER estimation (default: `0.20`).
    pub qber_sample_fraction: f64,
    /// Minimum decoy pulses per exchange for tight yield statistics (default: `10_000`).
    pub min_decoy_pulses: usize,
    /// Minimum vacuum pulses per exchange for dark-count estimation (default: `2_000`).
    pub min_vacuum_pulses: usize,
    /// Extra min-entropy security margin in bits per privacy-amplification block (default: `128`).
    pub pa_security_margin_bits: usize,
    /// Optional simulated adversary profile (default: `AttackProfile::None`).
    pub attack: AttackProfile,
}

impl Default for Bb84Config {
    fn default() -> Self {
        Self {
            signal_intensity: 0.6,
            decoy_intensity: 0.2,
            transmittance: 0.85,
            intrinsic_error_rate: 0.0,
            dark_count_rate: 0.0,
            max_qber: BB84_QBER_ABORT_THRESHOLD,
            qber_sample_fraction: 0.20,
            min_decoy_pulses: 10_000,
            min_vacuum_pulses: 2_000,
            pa_security_margin_bits: 128,
            attack: AttackProfile::None,
        }
    }
}

impl Bb84Config {
    /// Validate physical and protocol parameter bounds.
    pub fn validate(&self) -> Result<(), QkdError> {
        if !(self.decoy_intensity > 0.0 && self.signal_intensity > self.decoy_intensity) {
            return Err(QkdError::InvalidParameter(
                "must satisfy 0 < decoy_intensity < signal_intensity".into(),
            ));
        }
        if !(self.transmittance > 0.0 && self.transmittance <= 1.0) {
            return Err(QkdError::InvalidParameter(
                "transmittance must be in (0.0, 1.0]".into(),
            ));
        }
        if !(0.0..=0.5).contains(&self.intrinsic_error_rate) {
            return Err(QkdError::InvalidParameter(
                "intrinsic_error_rate must be in [0.0, 0.5]".into(),
            ));
        }
        if !(0.0..0.5).contains(&self.dark_count_rate) {
            return Err(QkdError::InvalidParameter(
                "dark_count_rate must be in [0.0, 0.5)".into(),
            ));
        }
        if !(0.0 < self.max_qber && self.max_qber <= 0.25) {
            return Err(QkdError::InvalidParameter(
                "max_qber must be in (0.0, 0.25]".into(),
            ));
        }
        if !(0.05..=0.5).contains(&self.qber_sample_fraction) {
            return Err(QkdError::InvalidParameter(
                "qber_sample_fraction must be in [0.05, 0.5]".into(),
            ));
        }
        if self.min_decoy_pulses < 500 {
            return Err(QkdError::InvalidParameter(
                "min_decoy_pulses must be at least 500".into(),
            ));
        }
        Ok(())
    }
}

/// Detailed outcome of a BB84 + Decoy-State QKD key exchange.
#[derive(Debug, Clone)]
pub struct Bb84ExchangeResult {
    /// Purified OTP key bytes derived by Alice.
    pub alice_key: Vec<u8>,
    /// Purified OTP key bytes derived by Bob (identical to `alice_key` on honest link).
    pub bob_key: Vec<u8>,
    /// Observed Quantum Bit Error Rate on the sacrificed sample.
    pub qber: f64,
    /// Total sifted bits kept after basis reconciliation (including QBER sample).
    pub sifted_bits: usize,
    /// Number of sifted bits sacrificed for QBER estimation.
    pub sampled_bits: usize,
    /// Observed overall gain `Q_mu` of signal pulses.
    pub signal_yield: f64,
    /// Observed overall gain `Q_nu` of decoy pulses.
    pub decoy_yield: f64,
    /// Observed gain `Y_0` of vacuum pulses.
    pub vacuum_yield: f64,
    /// Normalized yield ratio `((Q_mu - Y_0)/mu) / ((Q_nu - Y_0)/nu)`.
    pub decoy_yield_ratio: f64,
    /// Ma-Lo-Chen lower bound `Y_1^L` on single-photon detection yield.
    pub single_photon_yield_lower_bound: f64,
}

/// High-speed simulated BB84 + Weak/Vacuum Decoy-State QKD channel.
#[derive(Debug)]
pub struct Bb84Channel<E: EntropySource = OsEntropySource> {
    config: Bb84Config,
    entropy: E,
    last_qber: f64,
    total_delivered_bytes: u64,
}

impl Bb84Channel<OsEntropySource> {
    /// Create a clean BB84 channel with default settings and OS entropy.
    pub fn default_channel() -> Self {
        Self {
            config: Bb84Config::default(),
            entropy: OsEntropySource::new(),
            last_qber: 0.0,
            total_delivered_bytes: 0,
        }
    }

    /// Create a BB84 channel with the given simulated `AttackProfile` and OS entropy.
    pub fn with_attack(attack: AttackProfile) -> Self {
        let config = Bb84Config {
            attack,
            ..Bb84Config::default()
        };
        Self {
            config,
            entropy: OsEntropySource::new(),
            last_qber: 0.0,
            total_delivered_bytes: 0,
        }
    }
}

impl<E: EntropySource> Bb84Channel<E> {
    /// Create a BB84 channel with custom configuration and pluggable `EntropySource`.
    pub fn new(config: Bb84Config, entropy: E) -> Result<Self, QkdError> {
        config.validate()?;
        Ok(Self {
            config,
            entropy,
            last_qber: 0.0,
            total_delivered_bytes: 0,
        })
    }

    /// Borrow the channel configuration.
    pub fn config(&self) -> &Bb84Config {
        &self.config
    }

    /// Update the active attack profile (useful for fault-injection tests).
    pub fn set_attack(&mut self, attack: AttackProfile) {
        self.config.attack = attack;
    }

    /// Compute the effective detection probability of a weak coherent pulse with mean
    /// photon number `lambda`, incorporating Poisson photon statistics and any active attack.
    fn pulse_detection_prob(config: &Bb84Config, lambda: f64, is_signal: bool) -> f64 {
        let dark = config.dark_count_rate;
        if lambda <= 0.0 {
            return dark;
        }

        let eta = match config.attack {
            AttackProfile::SelectiveSignalAttenuation {
                signal_attenuation_factor,
            } if is_signal => (config.transmittance * signal_attenuation_factor).clamp(0.0, 1.0),
            _ => config.transmittance,
        };

        let p_detect_optical = match config.attack {
            AttackProfile::PhotonNumberSplitting {
                single_photon_block_rate,
                multiphoton_transmittance,
            } => {
                // Poissonian photon-number probabilities:
                // P(0) = e^-lambda, P(1) = lambda * e^-lambda, P(>=2) = 1 - (1 + lambda) * e^-lambda
                let exp_neg = (-lambda).exp();
                let p1 = lambda * exp_neg;
                let p_multi = (1.0 - (1.0 + lambda) * exp_neg).max(0.0);

                let single_survival = eta * (1.0 - single_photon_block_rate.clamp(0.0, 1.0));
                let multi_survival = multiphoton_transmittance.clamp(0.0, 1.0);
                (p1 * single_survival + p_multi * multi_survival).clamp(0.0, 1.0)
            }
            _ => {
                // Standard honest beam-splitter gain: Q_lambda = 1 - exp(-eta * lambda)
                (1.0 - (-eta * lambda).exp()).clamp(0.0, 1.0)
            }
        };

        // Combine optical detection with independent dark count floor.
        (1.0 - (1.0 - p_detect_optical) * (1.0 - dark)).clamp(0.0, 1.0)
    }

    /// Simulate `count` independent Bernoulli trials with probability `prob` using the
    /// channel's physical entropy stream (zero PRNGs).
    fn count_detections(
        stream: &mut EntropyStream<'_, E>,
        count: usize,
        prob: f64,
    ) -> Result<usize, QkdError> {
        if count == 0 || prob <= 0.0 {
            return Ok(0);
        }
        if prob >= 1.0 {
            return Ok(count);
        }
        let threshold = (prob * 65536.0).round().clamp(0.0, 65536.0) as u32;
        let mut hits = 0usize;
        for _ in 0..count {
            if (stream.next_u16()? as u32) < threshold {
                hits += 1;
            }
        }
        Ok(hits)
    }

    /// Run decoy-state signal/decoy/vacuum yield verification to detect PNS or selective
    /// attenuation attacks before accepting sifted key material.
    fn verify_decoy_states(
        config: &Bb84Config,
        stream: &mut EntropyStream<'_, E>,
        signal_pulses: usize,
    ) -> Result<(f64, f64, f64, f64, f64), QkdError> {
        let mu = config.signal_intensity;
        let nu = config.decoy_intensity;
        let eta = config.transmittance;

        let n_sig = signal_pulses.max(config.min_decoy_pulses);
        let n_dec = config.min_decoy_pulses;
        let n_vac = config.min_vacuum_pulses;

        let p_sig = Self::pulse_detection_prob(config, mu, true);
        let p_dec = Self::pulse_detection_prob(config, nu, false);
        let p_vac = Self::pulse_detection_prob(config, 0.0, false);

        let sig_hits = Self::count_detections(stream, n_sig, p_sig)?;
        let dec_hits = Self::count_detections(stream, n_dec, p_dec)?;
        let vac_hits = Self::count_detections(stream, n_vac, p_vac)?;

        let q_mu = sig_hits as f64 / n_sig as f64;
        let q_nu = dec_hits as f64 / n_dec as f64;
        let y_0 = vac_hits as f64 / n_vac as f64;

        let net_mu = (q_mu - y_0).max(0.0);
        let net_nu = (q_nu - y_0).max(0.0);

        if net_nu <= 1e-9 {
            return Err(QkdError::DecoyAnomalyDetected {
                signal_yield: q_mu,
                decoy_yield: q_nu,
                ratio: f64::INFINITY,
            });
        }

        let ratio = (net_mu / mu) / (net_nu / nu);

        // Theoretical honest ratio R_honest(eta) = ((1 - e^(-eta*mu))/mu) / ((1 - e^(-eta*nu))/nu).
        // Because 1 - e^-x is strictly concave, R_honest <= 1.0 for every honest channel.
        let honest_mu = 1.0 - (-eta * mu).exp();
        let honest_nu = 1.0 - (-eta * nu).exp();
        let honest_ratio = (honest_mu / mu) / (honest_nu / nu);

        // Ma-Lo-Chen (2005) Weak+Vacuum decoy-state lower bound on single-photon yield Y_1^L.
        let y1_lower = (mu / (mu * nu - nu * nu))
            * (q_nu * nu.exp()
                - q_mu * mu.exp() * (nu * nu) / (mu * mu)
                - ((mu * mu - nu * nu) / (mu * mu)) * y_0);

        // Upper bound (> 1.08 violates beam-splitter concavity -> classic PNS attack).
        // Lower bound (< 0.72 * R_honest -> selective signal attenuation vs decoy yield).
        let upper_ratio_bound = 1.08;
        let lower_ratio_bound = (honest_ratio * 0.72).min(0.65);

        if ratio > upper_ratio_bound
            || ratio < lower_ratio_bound
            || (eta >= 0.2 && y1_lower <= 0.0)
        {
            return Err(QkdError::DecoyAnomalyDetected {
                signal_yield: q_mu,
                decoy_yield: q_nu,
                ratio,
            });
        }

        Ok((q_mu, q_nu, y_0, ratio, y1_lower))
    }

    /// Execute a full BB84 + Decoy-State QKD exchange and distill `num_bytes` of purified
    /// shared OTP key material via word-level `toeplitz_hash_u64` privacy amplification.
    pub fn exchange_key(&mut self, num_bytes: usize) -> Result<Bb84ExchangeResult, QkdError> {
        if num_bytes == 0 {
            return Ok(Bb84ExchangeResult {
                alice_key: Vec::new(),
                bob_key: Vec::new(),
                qber: 0.0,
                sifted_bits: 0,
                sampled_bits: 0,
                signal_yield: 0.0,
                decoy_yield: 0.0,
                vacuum_yield: 0.0,
                decoy_yield_ratio: 1.0,
                single_photon_yield_lower_bound: self.config.transmittance,
            });
        }

        let out_bits_total = num_bytes * 8;
        let num_blocks = num_bytes.div_ceil(PA_OUTPUT_BLOCK_BYTES);

        // Plan per-block raw sifted bits (at least 2x compression + security margin per block)
        // to remain comfortably above the Devetak-Winter / Leftover Hash Lemma bound even
        // under non-zero optical QBER.
        let margin = self.config.pa_security_margin_bits;
        let mut block_out_bits = Vec::with_capacity(num_blocks);
        let mut block_raw_bits = Vec::with_capacity(num_blocks);
        let mut total_pa_raw_bits = 0usize;

        let mut remaining_bytes = num_bytes;
        for block_idx in 0..num_blocks {
            let chunk_bytes = remaining_bytes.min(PA_OUTPUT_BLOCK_BYTES);
            remaining_bytes -= chunk_bytes;
            let ob = chunk_bytes * 8;
            // Conservative 2.25x raw-to-output ratio + security margin (+128 bits on block 0 for
            // the post-reconciliation universal confirmation tag) rounded to 64-bit word.
            let confirm_extra = if block_idx == 0 { 128 } else { 0 };
            let rb = ((ob * 9 / 4) + margin + confirm_extra).max(512).div_ceil(64) * 64;
            block_out_bits.push(ob);
            block_raw_bits.push(rb);
            total_pa_raw_bits += rb;
        }

        let frac = self.config.qber_sample_fraction;
        let sample_bits = (((total_pa_raw_bits as f64) * frac / (1.0 - frac)).ceil() as usize)
            .max(512)
            .div_ceil(64)
            * 64;
        let total_sifted_bits = total_pa_raw_bits + sample_bits;
        let total_sifted_words = total_sifted_bits / 64;

        let eve_intercept_rate = match self.config.attack {
            AttackProfile::InterceptResend { intercept_rate } => intercept_rate.clamp(0.0, 1.0),
            _ => 0.0,
        };
        let intrinsic_err = self.config.intrinsic_error_rate;

        let mut stream = EntropyStream::new(&mut self.entropy);

        // Step 1: Decoy-state yield analysis (catches PNS & selective attenuation attacks).
        let (signal_yield, decoy_yield, vacuum_yield, decoy_yield_ratio, y1_lower) =
            Self::verify_decoy_states(&self.config, &mut stream, total_sifted_bits * 2)?;

        // Step 2: High-speed 64-photon bit-sliced BB84 transmission & basis sifting.
        let mut alice_sifted = Vec::with_capacity(total_sifted_words);
        let mut bob_sifted = Vec::with_capacity(total_sifted_words);
        let mut a_acc = 0u64;
        let mut b_acc = 0u64;
        let mut acc_bits = 0u32;

        while alice_sifted.len() < total_sifted_words {
            let alice_bits = stream.next_u64()?;
            let alice_bases = stream.next_u64()?;
            let bob_bases = stream.next_u64()?;

            // Rectilinear/Diagonal basis sifting: keep only photons where bases match.
            let mut matched = !(alice_bases ^ bob_bases);
            if matched == 0 {
                continue;
            }

            let mut bob_bits = alice_bits;

            // Simulate Intercept-Resend eavesdropper: when Eve intercepts and picks the
            // wrong basis (50% probability), Bob's matched-basis outcome is randomized
            // (introducing 25% QBER at 100% intercept rate).
            if eve_intercept_rate > 0.0 {
                let eve_mask = stream.bernoulli_mask_64(eve_intercept_rate)?;
                let eve_bases = stream.next_u64()?;
                let wrong_eve_basis = eve_mask & (alice_bases ^ eve_bases);
                if wrong_eve_basis != 0 {
                    let eve_disturbance = stream.next_u64()?;
                    bob_bits = (bob_bits & !wrong_eve_basis) | (eve_disturbance & wrong_eve_basis);
                }
            }

            // Simulate optional intrinsic optical misalignment noise.
            if intrinsic_err > 0.0 {
                let flip_mask = stream.bernoulli_mask_64(intrinsic_err)?;
                bob_bits ^= flip_mask;
            }

            // Pack matched bits tightly into 64-bit sifted words.
            while matched != 0 {
                let tz = matched.trailing_zeros();
                let a_bit = (alice_bits >> tz) & 1;
                let b_bit = (bob_bits >> tz) & 1;
                a_acc |= a_bit << acc_bits;
                b_acc |= b_bit << acc_bits;
                acc_bits += 1;
                if acc_bits == 64 {
                    alice_sifted.push(a_acc);
                    bob_sifted.push(b_acc);
                    a_acc = 0;
                    b_acc = 0;
                    acc_bits = 0;
                    if alice_sifted.len() == total_sifted_words {
                        break;
                    }
                }
                matched &= matched - 1; // Clear lowest set bit
            }
        }

        // Step 3: QBER estimation on the sacrificed sample prefix.
        let sample_words = sample_bits / 64;
        let mut errors = 0usize;
        for w in 0..sample_words {
            errors += (alice_sifted[w] ^ bob_sifted[w]).count_ones() as usize;
        }
        let qber = errors as f64 / sample_bits as f64;
        self.last_qber = qber;

        if qber > self.config.max_qber {
            zeroize_u64_slice(&mut alice_sifted);
            zeroize_u64_slice(&mut bob_sifted);
            return Err(QkdError::EavesdropperDetected {
                qber,
                threshold: self.config.max_qber,
            });
        }

        // Step 4: Discard sacrificed QBER sample words; reconcile remaining bits if noisy.
        let alice_pa = &mut alice_sifted[sample_words..];
        let bob_pa = &mut bob_sifted[sample_words..];
        let mut leaked_reconciliation_bits = if qber > 0.0 || intrinsic_err > 0.0 {
            reconcile_words_cascade(alice_pa, bob_pa, qber.max(intrinsic_err))
        } else {
            0
        };

        // Step 4b: ALWAYS run a 128-bit universal Carter-Wegman confirmation tag comparing
        // `alice_pa` and `bob_pa` BEFORE privacy amplification (aborting on any residual mismatch).
        let mut confirm_r = (((stream.next_u64()? as u128) | ((stream.next_u64()? as u128) << 64))
            & PRIME_P)
            .max(1);
        if confirm_r >= PRIME_P {
            confirm_r = 1;
        }
        let mut confirm_s =
            reduce((stream.next_u64()? as u128) | ((stream.next_u64()? as u128) << 64));
        let alice_confirm = cw_confirm_tag_u64(alice_pa, confirm_r, confirm_s);
        let bob_confirm = cw_confirm_tag_u64(bob_pa, confirm_r, confirm_s);
        zeroize_u128(&mut confirm_r);
        zeroize_u128(&mut confirm_s);
        leaked_reconciliation_bits += 128;

        if !ct_eq_16(&alice_confirm, &bob_confirm) {
            zeroize_u64_slice(&mut alice_sifted);
            zeroize_u64_slice(&mut bob_sifted);
            return Err(QkdError::ReconciliationFailed(
                "post-reconciliation universal confirmation tag mismatch".into(),
            ));
        }

        // Verify Devetak-Winter / Renner extractable min-entropy budget.
        let qber_bound = qber.max(intrinsic_err);
        let h2 = binary_entropy(qber_bound);
        let secure_capacity = ((total_pa_raw_bits as f64) * (1.0 - h2)).floor() as usize;
        let needed_capacity =
            out_bits_total + leaked_reconciliation_bits + margin * num_blocks;
        if secure_capacity < needed_capacity {
            zeroize_u64_slice(&mut alice_sifted);
            zeroize_u64_slice(&mut bob_sifted);
            return Err(QkdError::InsufficientSiftedBits {
                needed: needed_capacity,
                obtained: secure_capacity,
            });
        }

        // Step 5: Privacy amplification via word-level Toeplitz 2-universal hashing.
        let mut alice_key = Vec::with_capacity(num_bytes);
        let mut bob_key = Vec::with_capacity(num_bytes);
        let mut word_cursor = 0usize;

        for (&rb, &ob) in block_raw_bits.iter().zip(block_out_bits.iter()) {
            let rw = rb / 64;
            let seed_words = toeplitz_seed_words(rb, ob);
            let mut seed = vec![0u64; seed_words];
            stream.fill_u64s(&mut seed)?;

            let mut a_hash = toeplitz_hash_u64(&alice_pa[word_cursor..word_cursor + rw], rb, &seed, ob)?;
            let mut b_hash = toeplitz_hash_u64(&bob_pa[word_cursor..word_cursor + rw], rb, &seed, ob)?;
            word_cursor += rw;

            let chunk_bytes = ob / 8;
            let mut a_bytes = u64s_to_bytes(&a_hash, chunk_bytes);
            let mut b_bytes = u64s_to_bytes(&b_hash, chunk_bytes);
            alice_key.extend_from_slice(&a_bytes);
            bob_key.extend_from_slice(&b_bytes);
            zeroize_slice(&mut a_bytes);
            zeroize_slice(&mut b_bytes);

            zeroize_u64_slice(&mut a_hash);
            zeroize_u64_slice(&mut b_hash);
        }

        // Wipe all intermediate raw sifted material before returning.
        zeroize_u64_slice(&mut alice_sifted);
        zeroize_u64_slice(&mut bob_sifted);

        self.total_delivered_bytes += num_bytes as u64;

        Ok(Bb84ExchangeResult {
            alice_key,
            bob_key,
            qber,
            sifted_bits: total_sifted_bits,
            sampled_bits: sample_bits,
            signal_yield,
            decoy_yield,
            vacuum_yield,
            decoy_yield_ratio,
            single_photon_yield_lower_bound: y1_lower,
        })
    }
}

/// 128-bit universal Carter-Wegman confirmation tag over `u64` sifted key words in `F_(2^127 - 1)`.
fn cw_confirm_tag_u64(words: &[u64], r: u128, s: u128) -> [u8; 16] {
    let r = reduce(r);
    let s = reduce(s);
    let mut acc = mul_mod(reduce(words.len() as u128), r);
    for &w in words {
        acc = mul_mod(add_mod(acc, w as u128), r);
    }
    add_mod(acc, s).to_le_bytes()
}

/// Cascade-style strided binary-search parity reconciliation for slightly noisy
/// honest channels (`0 < qber <= 0.11`). Scales initial block size with observed QBER,
/// uses coprime strides to permute bit positions across passes, and backtracks across
/// `&strides[..=pass_idx]` on each correction, returning the exact number of parity bits
/// leaked on the public classical channel.
fn reconcile_words_cascade(alice: &[u64], bob: &mut [u64], observed_qber: f64) -> usize {
    let total_bits = alice.len() * 64;
    if total_bits == 0 {
        return 0;
    }

    let est_qber = observed_qber.clamp(0.005, 0.25);
    let block_size = ((0.73 / est_qber).round() as usize)
        .clamp(8, 64)
        .min(total_bits);
    let candidate_strides = [1usize, 17, 53, 109, 227];
    let mut strides = Vec::with_capacity(4);
    for &s in &candidate_strides {
        if gcd(s, total_bits) == 1 {
            strides.push(s);
            if strides.len() == 4 {
                break;
            }
        }
    }
    if strides.is_empty() {
        strides.push(1);
    }

    let mut leaked = 0usize;
    let mut fixed_indices = Vec::new();

    for (pass_idx, &stride) in strides.iter().enumerate() {
        fixed_indices.clear();
        let mut start = 0usize;
        while start < total_bits {
            let end = (start + block_size).min(total_bits);
            leaked += 1;
            if strided_parity_diff(alice, bob, start, end, stride, total_bits) {
                let (fixed_pos, bits_leaked) =
                    strided_binary_search_fix(alice, bob, start, end, stride, total_bits);
                leaked += bits_leaked;
                fixed_indices.push(fixed_pos);
            }
            start = end;
        }

        // Cascade backtracking: whenever pass `pass_idx` flips a bit, re-check its
        // containing block across `&strides[..=pass_idx]` (no extra top-level parity bit
        // leaked since those block parities were already exchanged).
        if !fixed_indices.is_empty() {
            let mut worklist = fixed_indices.clone();
            while let Some(bit_pos) = worklist.pop() {
                for &prev_stride in &strides[..=pass_idx] {
                    // Find `t` such that `(t * prev_stride) % total_bits == bit_pos`.
                    let inv = mod_inverse(prev_stride, total_bits);
                    let t = ((bit_pos as u128 * inv as u128) % total_bits as u128) as usize;
                    let b_start = (t / block_size) * block_size;
                    let b_end = (b_start + block_size).min(total_bits);
                    if strided_parity_diff(alice, bob, b_start, b_end, prev_stride, total_bits) {
                        let (new_fix, bits_leaked) = strided_binary_search_fix(
                            alice,
                            bob,
                            b_start,
                            b_end,
                            prev_stride,
                            total_bits,
                        );
                        leaked += bits_leaked;
                        worklist.push(new_fix);
                    }
                }
            }
        }
    }

    leaked
}

const fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// Modular inverse of `a` modulo `m` (assuming `gcd(a, m) == 1`) via extended Euclid.
fn mod_inverse(a: usize, m: usize) -> usize {
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (m as i128, (a % m) as i128);
    while new_r != 0 {
        let q = r / new_r;
        let tmp_t = t - q * new_t;
        t = new_t;
        new_t = tmp_t;
        let tmp_r = r - q * new_r;
        r = new_r;
        new_r = tmp_r;
    }
    if t < 0 {
        t += m as i128;
    }
    t as usize
}

#[inline]
fn get_bit(words: &[u64], idx: usize) -> u64 {
    (words[idx / 64] >> (idx % 64)) & 1
}

#[inline]
fn flip_bit(words: &mut [u64], idx: usize) {
    words[idx / 64] ^= 1u64 << (idx % 64);
}

#[inline]
fn strided_index(t: usize, stride: usize, total_bits: usize) -> usize {
    if stride == 1 {
        t
    } else {
        (((t as u128) * (stride as u128)) % (total_bits as u128)) as usize
    }
}

fn strided_parity_diff(
    alice: &[u64],
    bob: &[u64],
    start: usize,
    end: usize,
    stride: usize,
    total_bits: usize,
) -> bool {
    let mut diff = 0u64;
    for t in start..end {
        let pos = strided_index(t, stride, total_bits);
        diff ^= get_bit(alice, pos) ^ get_bit(bob, pos);
    }
    diff != 0
}

fn strided_binary_search_fix(
    alice: &[u64],
    bob: &mut [u64],
    mut lo: usize,
    mut hi: usize,
    stride: usize,
    total_bits: usize,
) -> (usize, usize) {
    let mut leaked = 0usize;
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        leaked += 1;
        if strided_parity_diff(alice, bob, lo, mid, stride, total_bits) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    let pos = strided_index(lo, stride, total_bits);
    if get_bit(alice, pos) != get_bit(bob, pos) {
        flip_bit(bob, pos);
    }
    (pos, leaked)
}

impl<E: EntropySource> QkdKeyProvider for Bb84Channel<E> {
    fn get_key(&mut self, _peer_id: &str, num_bytes: usize) -> Result<Vec<u8>, QkdError> {
        let mut result = self.exchange_key(num_bytes)?;
        zeroize_slice(&mut result.bob_key);
        Ok(result.alice_key)
    }

    fn status(&self, _peer_id: &str) -> QkdLinkStatus {
        QkdLinkStatus {
            stored_key_bytes: 0,
            max_key_bytes: 0,
            last_qber: self.last_qber,
            total_delivered_bytes: self.total_delivered_bytes,
        }
    }
}

// ============================================================================
// 5. Pre-Buffered Multi-Channel High-Throughput QKD Key Pool
// ============================================================================

/// Configuration for `BufferedQkdPool`.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Total ring buffer capacity in purified key bytes (default: 256 KiB).
    pub capacity_bytes: usize,
    /// Automatic background replenishment threshold in bytes (default: 64 KiB).
    pub low_watermark_bytes: usize,
    /// Key bytes generated per individual channel refill batch (default: 16 KiB).
    pub refill_chunk_bytes: usize,
    /// Number of parallel QKD channel worker threads (default: 4).
    pub num_channels: usize,
    /// Underlying BB84 + Decoy-State configuration shared by all parallel channels.
    pub channel_config: Bb84Config,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            capacity_bytes: 256 * 1024,
            low_watermark_bytes: 64 * 1024,
            refill_chunk_bytes: 16 * 1024,
            num_channels: 4,
            channel_config: Bb84Config::default(),
        }
    }
}

impl PoolConfig {
    /// Validate pool sizing and channel configuration.
    pub fn validate(&self) -> Result<(), QkdError> {
        if self.capacity_bytes == 0 {
            return Err(QkdError::InvalidParameter(
                "capacity_bytes must be > 0".into(),
            ));
        }
        if self.low_watermark_bytes > self.capacity_bytes {
            return Err(QkdError::InvalidParameter(
                "low_watermark_bytes cannot exceed capacity_bytes".into(),
            ));
        }
        if self.refill_chunk_bytes == 0 {
            return Err(QkdError::InvalidParameter(
                "refill_chunk_bytes must be > 0".into(),
            ));
        }
        if self.num_channels == 0 {
            return Err(QkdError::InvalidParameter(
                "num_channels must be >= 1".into(),
            ));
        }
        self.channel_config.validate()
    }
}

struct PoolInner {
    ring: Vec<u8>,
    capacity: usize,
    head: usize,
    len: usize,
    in_flight_bytes: usize,
    low_watermark: usize,
    refill_chunk: usize,
    refilling: bool,
    shutdown: bool,
    last_error: Option<QkdError>,
    last_qber: f64,
    total_served: u64,
    total_generated: u64,
    refill_batches: u64,
}

impl PoolInner {
    fn push_bytes(&mut self, src: &[u8]) -> usize {
        let free = self.capacity - self.len;
        let to_write = free.min(src.len());
        if to_write == 0 {
            return 0;
        }
        let tail = (self.head + self.len) % self.capacity;
        let first_part = to_write.min(self.capacity - tail);
        self.ring[tail..tail + first_part].copy_from_slice(&src[..first_part]);
        if first_part < to_write {
            let second_part = to_write - first_part;
            self.ring[..second_part].copy_from_slice(&src[first_part..to_write]);
        }
        self.len += to_write;
        to_write
    }

    fn pop_and_zeroize(&mut self, dst: &mut [u8]) -> usize {
        let to_read = self.len.min(dst.len());
        if to_read == 0 {
            return 0;
        }
        let first_part = to_read.min(self.capacity - self.head);
        dst[..first_part].copy_from_slice(&self.ring[self.head..self.head + first_part]);
        zeroize_slice(&mut self.ring[self.head..self.head + first_part]);

        if first_part < to_read {
            let second_part = to_read - first_part;
            dst[first_part..to_read].copy_from_slice(&self.ring[..second_part]);
            zeroize_slice(&mut self.ring[..second_part]);
        }

        self.head = (self.head + to_read) % self.capacity;
        self.len -= to_read;
        self.total_served += to_read as u64;
        to_read
    }
}

struct SharedPool {
    state: Mutex<PoolInner>,
    refill_cv: Condvar,
    data_cv: Condvar,
}

/// Pre-buffered, multi-channel QKD OTP key pool for high-TPS bursts.
///
/// Serves purified OTP key bytes directly from RAM with zero live photon latency,
/// immediately wipes every consumed ring-buffer segment using `zeroize_slice`, and
/// automatically replenishes across multiple parallel `Bb84Channel` workers whenever
/// available key material drops below `low_watermark_bytes`.
pub struct BufferedQkdPool {
    shared: Arc<SharedPool>,
    workers: Vec<JoinHandle<()>>,
}

impl BufferedQkdPool {
    /// Construct a new `BufferedQkdPool`, launch `config.num_channels` parallel QKD worker
    /// threads, and pre-fill the ring buffer to full capacity before returning.
    pub fn new(config: PoolConfig) -> Result<Self, QkdError> {
        config.validate()?;

        let shared = Arc::new(SharedPool {
            state: Mutex::new(PoolInner {
                ring: vec![0u8; config.capacity_bytes],
                capacity: config.capacity_bytes,
                head: 0,
                len: 0,
                in_flight_bytes: 0,
                low_watermark: config.low_watermark_bytes,
                refill_chunk: config.refill_chunk_bytes.min(config.capacity_bytes),
                refilling: true,
                shutdown: false,
                last_error: None,
                last_qber: 0.0,
                total_served: 0,
                total_generated: 0,
                refill_batches: 0,
            }),
            refill_cv: Condvar::new(),
            data_cv: Condvar::new(),
        });

        let mut workers = Vec::with_capacity(config.num_channels);
        for idx in 0..config.num_channels {
            let shared_clone = Arc::clone(&shared);
            let ch_cfg = config.channel_config.clone();
            match thread::Builder::new()
                .name(format!("vernam-qkd-ch-{idx}"))
                .spawn(move || Self::worker_loop(shared_clone, ch_cfg))
            {
                Ok(handle) => workers.push(handle),
                Err(e) => {
                    {
                        let mut guard = shared.state.lock().expect("pool mutex poisoned");
                        guard.shutdown = true;
                        shared.refill_cv.notify_all();
                        shared.data_cv.notify_all();
                    }
                    for h in workers.drain(..) {
                        let _ = h.join();
                    }
                    let mut guard = shared.state.lock().expect("pool mutex poisoned");
                    zeroize_slice(&mut guard.ring);
                    return Err(QkdError::EntropyFailure(format!(
                        "failed to spawn QKD worker thread: {e}"
                    )));
                }
            }
        }

        let pool = Self { shared, workers };

        // Wait until the initial pre-fill completes (or a channel error occurs).
        let mut guard = pool.shared.state.lock().expect("pool mutex poisoned");
        while guard.len < guard.capacity && guard.last_error.is_none() {
            guard = pool.shared.data_cv.wait(guard).expect("pool mutex poisoned");
        }
        if let Some(err) = guard.last_error.clone() {
            drop(guard);
            // `pool` drops here, shutting down workers and zeroizing buffer cleanly.
            return Err(err);
        }
        drop(guard);

        Ok(pool)
    }

    fn worker_loop(shared: Arc<SharedPool>, channel_config: Bb84Config) {
        let mut channel = match Bb84Channel::new(channel_config, OsEntropySource::new()) {
            Ok(ch) => ch,
            Err(err) => {
                let mut guard = shared.state.lock().expect("pool mutex poisoned");
                guard.last_error = Some(err);
                guard.refilling = false;
                shared.data_cv.notify_all();
                return;
            }
        };

        loop {
            let to_generate = {
                let mut guard = shared.state.lock().expect("pool mutex poisoned");
                loop {
                    if guard.shutdown {
                        return;
                    }
                    let projected = guard.len + guard.in_flight_bytes;
                    if projected < guard.low_watermark {
                        guard.refilling = true;
                    }
                    let deficit = guard.capacity.saturating_sub(projected);
                    if guard.refilling && deficit > 0 && guard.last_error.is_none() {
                        let batch = deficit.min(guard.refill_chunk);
                        guard.in_flight_bytes += batch;
                        break batch;
                    }
                    guard = shared.refill_cv.wait(guard).expect("pool mutex poisoned");
                }
            };

            // Generate purified QKD key material outside the lock for true multi-channel speed.
            let res = channel.exchange_key(to_generate);

            let mut guard = shared.state.lock().expect("pool mutex poisoned");
            guard.in_flight_bytes = guard.in_flight_bytes.saturating_sub(to_generate);

            match res {
                Ok(mut exchange) => {
                    zeroize_slice(&mut exchange.bob_key);
                    let written = guard.push_bytes(&exchange.alice_key);
                    zeroize_slice(&mut exchange.alice_key);

                    guard.last_qber = exchange.qber;
                    guard.total_generated += written as u64;
                    guard.refill_batches += 1;

                    if guard.len >= guard.capacity {
                        guard.refilling = false;
                    }
                    shared.data_cv.notify_all();
                }
                Err(err) => {
                    guard.last_error = Some(err);
                    guard.refilling = false;
                    shared.data_cv.notify_all();
                }
            }
        }
    }

    /// Allocate `num_bytes` of purified OTP key material from the pre-buffered RAM pool.
    pub fn allocate(&self, num_bytes: usize) -> Result<Vec<u8>, QkdError> {
        let mut out = vec![0u8; num_bytes];
        if let Err(err) = self.allocate_into(&mut out) {
            zeroize_slice(&mut out);
            return Err(err);
        }
        Ok(out)
    }

    /// Zero-allocation fast path: fill `dst` directly from the pre-buffered RAM ring,
    /// wiping consumed ring regions via `zeroize_slice` and waking background workers
    /// if the buffer drops below `low_watermark_bytes`.
    pub fn allocate_into(&self, dst: &mut [u8]) -> Result<(), QkdError> {
        if dst.is_empty() {
            return Ok(());
        }

        let mut offset = 0usize;
        let mut guard = self.shared.state.lock().expect("pool mutex poisoned");

        while offset < dst.len() {
            if guard.len > 0 {
                let taken = guard.pop_and_zeroize(&mut dst[offset..]);
                offset += taken;

                let projected = guard.len + guard.in_flight_bytes;
                if projected < guard.low_watermark {
                    guard.refilling = true;
                }
                if guard.refilling && projected < guard.capacity && guard.last_error.is_none() {
                    self.shared.refill_cv.notify_all();
                }
            } else {
                if let Some(err) = guard.last_error.clone() {
                    zeroize_slice(&mut dst[..offset]);
                    return Err(err);
                }
                if guard.shutdown {
                    let avail = guard.len;
                    zeroize_slice(&mut dst[..offset]);
                    return Err(QkdError::PoolExhausted {
                        requested: dst.len(),
                        available: avail,
                    });
                }
                guard.refilling = true;
                self.shared.refill_cv.notify_all();
                guard = self.shared.data_cv.wait(guard).expect("pool mutex poisoned");
            }
        }

        Ok(())
    }

    /// Explicitly request background replenishment if below capacity.
    pub fn trigger_replenish(&self) {
        let mut guard = self.shared.state.lock().expect("pool mutex poisoned");
        if guard.len < guard.capacity && guard.last_error.is_none() {
            guard.refilling = true;
            self.shared.refill_cv.notify_all();
        }
    }

    /// Block until the pool reaches at least `target_bytes` or `timeout` expires.
    /// Returns `true` if `target_bytes` is available.
    pub fn wait_for_bytes(&self, target_bytes: usize, timeout: Duration) -> bool {
        let mut guard = self.shared.state.lock().expect("pool mutex poisoned");
        let target = target_bytes.min(guard.capacity);
        let deadline = std::time::Instant::now() + timeout;

        while guard.len < target && guard.last_error.is_none() && !guard.shutdown {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let (new_guard, wait_res) = self
                .shared
                .data_cv
                .wait_timeout(guard, deadline - now)
                .expect("pool mutex poisoned");
            guard = new_guard;
            if wait_res.timed_out() {
                break;
            }
        }

        guard.len >= target
    }

    /// Number of purified OTP key bytes currently buffered and ready in RAM.
    pub fn available_bytes(&self) -> usize {
        self.shared.state.lock().expect("pool mutex poisoned").len
    }

    /// Configured ring buffer capacity in bytes.
    pub fn capacity_bytes(&self) -> usize {
        self.shared
            .state
            .lock()
            .expect("pool mutex poisoned")
            .capacity
    }

    /// Configured automatic replenishment low-watermark threshold in bytes.
    pub fn low_watermark_bytes(&self) -> usize {
        self.shared
            .state
            .lock()
            .expect("pool mutex poisoned")
            .low_watermark
    }

    /// Total purified key bytes served since pool creation.
    pub fn total_bytes_served(&self) -> u64 {
        self.shared
            .state
            .lock()
            .expect("pool mutex poisoned")
            .total_served
    }

    /// Total purified key bytes produced by QKD channels since pool creation.
    pub fn total_bytes_generated(&self) -> u64 {
        self.shared
            .state
            .lock()
            .expect("pool mutex poisoned")
            .total_generated
    }

    /// Total completed refill batches across all parallel channels.
    pub fn refill_batches(&self) -> u64 {
        self.shared
            .state
            .lock()
            .expect("pool mutex poisoned")
            .refill_batches
    }
}

impl QkdKeyProvider for BufferedQkdPool {
    fn get_key(&mut self, _peer_id: &str, num_bytes: usize) -> Result<Vec<u8>, QkdError> {
        self.allocate(num_bytes)
    }

    fn status(&self, _peer_id: &str) -> QkdLinkStatus {
        let guard = self.shared.state.lock().expect("pool mutex poisoned");
        QkdLinkStatus {
            stored_key_bytes: guard.len,
            max_key_bytes: guard.capacity,
            last_qber: guard.last_qber,
            total_delivered_bytes: guard.total_served,
        }
    }
}

impl Drop for BufferedQkdPool {
    fn drop(&mut self) {
        {
            let mut guard = self.shared.state.lock().expect("pool mutex poisoned");
            guard.shutdown = true;
            self.shared.refill_cv.notify_all();
            self.shared.data_cv.notify_all();
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
        let mut guard = self.shared.state.lock().expect("pool mutex poisoned");
        zeroize_slice(&mut guard.ring);
        guard.len = 0;
        guard.head = 0;
    }
}

// ============================================================================
// 6. Comprehensive Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Instant;

    /// Slow, textbook bit-by-bit Toeplitz reference implementation for exact verification.
    fn toeplitz_reference_bit_by_bit(
        raw: &[u64],
        raw_bits: usize,
        seed: &[u64],
        out_bits: usize,
    ) -> Vec<u64> {
        if out_bits == 0 {
            return Vec::new();
        }
        let mut out = vec![0u64; out_bits.div_ceil(64)];
        for i in 0..out_bits {
            let mut bit = 0u64;
            for j in 0..raw_bits {
                let s_idx = (out_bits - 1 - i) + j;
                let t_ij = (seed[s_idx / 64] >> (s_idx % 64)) & 1;
                let x_j = (raw[j / 64] >> (j % 64)) & 1;
                bit ^= t_ij & x_j;
            }
            out[i / 64] |= bit << (i % 64);
        }
        out
    }

    #[test]
    fn test_clean_bb84_exchange_identical_keys_zero_qber() {
        let mut ch = Bb84Channel::default_channel();
        let res = ch.exchange_key(512).expect("clean BB84 exchange should succeed");

        assert_eq!(res.alice_key.len(), 512);
        assert_eq!(res.bob_key.len(), 512);
        assert_eq!(res.alice_key, res.bob_key);
        assert_eq!(res.qber, 0.0);
        assert!(res.decoy_yield_ratio > 0.65 && res.decoy_yield_ratio < 1.08);
        assert!(res.single_photon_yield_lower_bound > 0.4);

        // Verify ETSI GS QKD 014 trait interface & field element derivation.
        let key_via_trait = ch.get_key("peer-validator-01", 64).unwrap();
        assert_eq!(key_via_trait.len(), 64);
        let fe = ch.get_field_element("peer-validator-01").unwrap();
        assert!(fe < PRIME_P);
    }

    #[test]
    fn test_noisy_honest_bb84_reconciles_identical_keys() {
        let cfg = Bb84Config {
            intrinsic_error_rate: 0.02, // 2% optical fiber noise, well below 11% bound
            ..Bb84Config::default()
        };
        let mut ch = Bb84Channel::new(cfg, OsEntropySource::new()).unwrap();
        let res = ch.exchange_key(128).expect("2% noisy honest channel should succeed");
        assert_eq!(res.alice_key, res.bob_key);
        assert!(res.qber < BB84_QBER_ABORT_THRESHOLD);
    }

    #[test]
    fn test_intercept_resend_eavesdropper_detected() {
        let mut ch = Bb84Channel::with_attack(AttackProfile::InterceptResend {
            intercept_rate: 1.0,
        });
        let err = ch
            .exchange_key(64)
            .expect_err("full intercept-resend eavesdropper must be detected");

        match err {
            QkdError::EavesdropperDetected { qber, threshold } => {
                assert_eq!(threshold, BB84_QBER_ABORT_THRESHOLD);
                assert!(
                    qber > BB84_QBER_ABORT_THRESHOLD,
                    "expected QBER > 0.11, got {qber}"
                );
            }
            other => panic!("expected EavesdropperDetected, got {other:?}"),
        }
    }

    #[test]
    fn test_decoy_state_pns_attack_detected() {
        let mut ch = Bb84Channel::with_attack(AttackProfile::PhotonNumberSplitting {
            single_photon_block_rate: 0.85,
            multiphoton_transmittance: 1.0,
        });
        let err = ch
            .exchange_key(64)
            .expect_err("PNS attack must trigger decoy-state anomaly detection");

        match err {
            QkdError::DecoyAnomalyDetected {
                signal_yield,
                decoy_yield,
                ratio,
            } => {
                assert!(signal_yield > 0.0);
                assert!(decoy_yield > 0.0);
                assert!(
                    ratio > 1.08,
                    "expected PNS normalized yield ratio > 1.08, got {ratio}"
                );
            }
            other => panic!("expected DecoyAnomalyDetected, got {other:?}"),
        }
    }

    #[test]
    fn test_decoy_state_selective_signal_attenuation_detected() {
        let mut ch = Bb84Channel::with_attack(AttackProfile::SelectiveSignalAttenuation {
            signal_attenuation_factor: 0.35,
        });
        let err = ch
            .exchange_key(64)
            .expect_err("selective signal attenuation must trigger decoy anomaly");

        assert!(
            matches!(err, QkdError::DecoyAnomalyDetected { .. }),
            "expected DecoyAnomalyDetected, got {err:?}"
        );
    }

    #[test]
    fn test_toeplitz_hash_u64_exactness_determinism_balance_and_speed() {
        let mut os = OsEntropySource::new();

        // 1. Exact bit-for-bit agreement with textbook reference across edge-case dimensions.
        let dims: [(usize, usize); 10] = [
            (0, 0),
            (1, 1),
            (7, 5),
            (63, 63),
            (64, 64),
            (65, 65),
            (127, 64),
            (128, 129),
            (255, 130),
            (513, 257),
        ];

        for (raw_bits, out_bits) in dims {
            let mut raw_bytes = vec![0u8; raw_bits.div_ceil(8)];
            os.fill_random(&mut raw_bytes).unwrap();
            let raw = bytes_to_u64s(&raw_bytes);

            let seed_words = toeplitz_seed_words(raw_bits, out_bits);
            let mut seed_bytes = vec![0u8; seed_words * 8];
            os.fill_random(&mut seed_bytes).unwrap();
            let seed = bytes_to_u64s(&seed_bytes);

            let fast = toeplitz_hash_u64(&raw, raw_bits, &seed, out_bits).unwrap();
            let slow = toeplitz_reference_bit_by_bit(&raw, raw_bits, &seed, out_bits);
            assert_eq!(
                fast, slow,
                "mismatch for raw_bits={raw_bits}, out_bits={out_bits}"
            );

            // Determinism check: identical inputs produce identical outputs.
            let fast2 = toeplitz_hash_u64(&raw, raw_bits, &seed, out_bits).unwrap();
            assert_eq!(fast, fast2);
        }

        // 2. Avalanche & monobit balance check on 4096 -> 2048 bits.
        let raw_bits = 4096;
        let out_bits = 2048;
        let mut raw_bytes = vec![0u8; raw_bits / 8];
        let mut seed_bytes = vec![0u8; toeplitz_seed_words(raw_bits, out_bits) * 8];
        os.fill_random(&mut raw_bytes).unwrap();
        os.fill_random(&mut seed_bytes).unwrap();
        let mut raw = bytes_to_u64s(&raw_bytes);
        let seed = bytes_to_u64s(&seed_bytes);

        let h1 = toeplitz_hash_u64(&raw, raw_bits, &seed, out_bits).unwrap();
        let h1_bytes = u64s_to_bytes(&h1, out_bits / 8);
        let health = check_entropy_health(&h1_bytes, 6.0)
            .expect("Toeplitz output should pass monobit uniformity sanity check");
        assert!(
            (health.ones_ratio - 0.5).abs() < 0.08,
            "unexpected monobit bias: {:.4}",
            health.ones_ratio
        );

        // Flip a single input bit: ~50% of output bits should flip (avalanche).
        raw[17] ^= 1u64 << 23;
        let h2 = toeplitz_hash_u64(&raw, raw_bits, &seed, out_bits).unwrap();
        let diff_bits: usize = h1
            .iter()
            .zip(h2.iter())
            .map(|(a, b)| (a ^ b).count_ones() as usize)
            .sum();
        let flip_ratio = diff_bits as f64 / out_bits as f64;
        assert!(
            (0.40..=0.60).contains(&flip_ratio),
            "expected ~50% avalanche flip ratio, got {flip_ratio:.4}"
        );

        // 3. Speed benchmark: 64 blocks of 4096 -> 2048 bits (16 KiB purified output).
        let start = Instant::now();
        let mut checksum = 0u64;
        for _ in 0..64 {
            let out = toeplitz_hash_u64(&raw, raw_bits, &seed, out_bits).unwrap();
            checksum ^= out[0];
        }
        let elapsed = start.elapsed();
        assert_ne!(checksum, u64::MAX); // Prevent dead-code elimination
        assert!(
            elapsed < Duration::from_secs(2),
            "toeplitz_hash_u64 unexpectedly slow: {elapsed:?}"
        );
    }

    #[test]
    fn test_hardware_qrng_adapter_health_checks() {
        // Healthy stream via pluggable device path (/dev/urandom).
        let mut healthy = HardwareQrngAdapter::with_path("/dev/urandom");
        let stats = healthy.run_health_check(256).unwrap();
        assert_eq!(stats.total_bits, 2048);
        assert!(stats.z_score < 6.0);

        let mut buf = [0u8; 64];
        healthy.fill_random(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));

        // Stuck-at-zero file must fail health check immediately.
        let bad_path = std::env::temp_dir().join(format!(
            "vernam_qrng_stuck_{}.bin",
            std::process::id()
        ));
        {
            let mut f = File::create(&bad_path).unwrap();
            f.write_all(&[0u8; 512]).unwrap();
        }
        let mut broken = HardwareQrngAdapter::with_path(&bad_path);
        let err = broken
            .fill_random(&mut buf)
            .expect_err("stuck QRNG output must fail health check");
        assert!(matches!(err, QkdError::EntropyHealthCheckFailed { .. }));
        // Verify buffer was wiped after failed health check.
        assert!(buf.iter().all(|&b| b == 0));

        let _ = std::fs::remove_file(&bad_path);
    }

    #[test]
    fn test_buffered_qkd_pool_burst_and_auto_replenish() {
        let cfg = PoolConfig {
            capacity_bytes: 32 * 1024,
            low_watermark_bytes: 16 * 1024,
            refill_chunk_bytes: 8 * 1024,
            num_channels: 4,
            channel_config: Bb84Config::default(),
        };

        let mut pool = BufferedQkdPool::new(cfg).expect("pool pre-fill should succeed");
        assert_eq!(pool.available_bytes(), 32 * 1024);

        // Rapid burst: 640 allocations of 32 bytes = 20 KiB (drops below 16 KiB watermark).
        let burst_start = Instant::now();
        let mut keys = Vec::with_capacity(640);
        for _ in 0..640 {
            let k = pool.get_key("validator-mesh", 32).unwrap();
            assert_eq!(k.len(), 32);
            keys.push(k);
        }
        let burst_elapsed = burst_start.elapsed();
        assert!(
            burst_elapsed < Duration::from_millis(250),
            "RAM-buffered burst should be sub-millisecond/fast, took {burst_elapsed:?}"
        );

        // Spot-check that keys are unique (never reused from wiped ring slots).
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[0], keys[639]);
        assert_eq!(pool.total_bytes_served(), 640 * 32);

        // Wait for automatic background replenishment to bring pool back to full capacity.
        let replenished = pool.wait_for_bytes(32 * 1024, Duration::from_secs(5));
        assert!(
            replenished,
            "pool should auto-replenish to full capacity after dropping below low watermark"
        );
        assert!(pool.total_bytes_generated() >= 48 * 1024);

        // Verify zero-alloc `allocate_into` and ETSI status reporting.
        let mut scratch = [0u8; 128];
        pool.allocate_into(&mut scratch).unwrap();
        let status = pool.status("validator-mesh");
        assert_eq!(status.max_key_bytes, 32 * 1024);
        assert_eq!(status.last_qber, 0.0);
        assert_eq!(status.total_delivered_bytes, 640 * 32 + 128);
        zeroize_slice(&mut scratch);
    }

    #[test]
    fn test_buffered_qkd_pool_aborts_on_compromised_channel() {
        let cfg = PoolConfig {
            capacity_bytes: 4096,
            low_watermark_bytes: 2048,
            refill_chunk_bytes: 1024,
            num_channels: 2,
            channel_config: Bb84Config {
                attack: AttackProfile::InterceptResend {
                    intercept_rate: 1.0,
                },
                ..Bb84Config::default()
            },
        };
        let err = match BufferedQkdPool::new(cfg) {
            Ok(_) => panic!("compromised QKD channels must prevent pool initialization"),
            Err(e) => e,
        };
        assert!(matches!(err, QkdError::EavesdropperDetected { .. }));
    }

    #[test]
    fn test_qkd_confirmation_tag_and_strided_index_overflow_safety() {
        let a = [0x1122_3344_5566_7788u64, 0x99AA_BBCC_DDEE_FF00u64];
        let mut b = a;
        let r = 0x1234_5678_9ABC_DEF1u128;
        let s = 0x0FED_CBA9_8765_4321u128;
        assert_eq!(cw_confirm_tag_u64(&a, r, s), cw_confirm_tag_u64(&b, r, s));
        b[1] ^= 1u64 << 17;
        assert_ne!(cw_confirm_tag_u64(&a, r, s), cw_confirm_tag_u64(&b, r, s));

        // Ensure u128 arithmetic avoids usize multiplication overflow in strided_index.
        let large_total = (usize::MAX / 4).max(1024);
        let idx = strided_index(large_total - 1, 227, large_total);
        assert!(idx < large_total);
    }
}
