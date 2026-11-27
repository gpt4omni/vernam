//! Runtime-dispatched SIMD cryptography & pipelined Mersenne field primitives for Vernam (VRNM).
//!
//! Zero external crates, zero computational cryptography (no SHA, AES, RSA, ECDSA, or ChaCha).
//! All primitives are information-theoretically secure and produce **bit-for-bit identical**
//! outputs to the scalar reference implementations in `crate::otp` and `crate::qkd`:
//!
//! 1. **Runtime-dispatched SIMD OTP XOR** (`otp_xor_turbo_in_place`):
//!    - `x86_64` `avx512f` (4x unrolled `_mm512_xor_si512`, 256 bytes/iteration)
//!    - `x86_64` `avx2` (4x unrolled `_mm256_xor_si256`, 128 bytes/iteration)
//!    - Portable `u64` word-level fallback (for ARM64 / non-AVX2 CPUs)
//! 2. **4-way pipelined unrolled Carter-Wegman MAC over `F_(2^127 - 1)`** (`CwFastKey`,
//!    `cw_mac_4way`, `cw_mac_u128_stream_4way`):
//!    - Precomputes `(r, r^2, r^3, r^4, s)` once per key with volatile zeroization on `Drop`.
//!    - Breaks the serial Horner dependency chain by processing 4 blocks (60 bytes) per iteration
//!      using fused lazy 4-way Mersenne field reduction (and runtime `bmi2`/`adx` `mulx` dispatch
//!      on `x86_64` with portable fallback).
//! 3. **SIMD `AVX-512 VPOPCNTDQ` / `AVX2` Toeplitz 2-Universal Privacy Amplification**
//!    (`toeplitz_hash_turbo`):
//!    - `x86_64` `avx512f + avx512vpopcntdq`: bit-shift-grouped Toeplitz tiling that pre-shifts
//!      the seed once per bit offset (`0..64`), evaluates 8 output bits in parallel per 512-bit
//!      `raw` load via `_mm512_and_si512` + `_mm512_xor_si512`, and reduces lane parities with
//!      `_mm512_popcnt_epi64`.
//!    - `x86_64` `avx2`: 256-bit tiled dot-product with `vpshufb` nibble-lookup POPCNT + `vpsadbw`.
//!    - Portable 4x-unrolled `u64::count_ones()` fallback.
//! 4. **Built-in throughput benchmark suite** (`TurboCryptoBench`, `run_turbo_crypto_bench`).

use std::fmt;
use std::hint::black_box;
use std::sync::atomic::{Ordering, compiler_fence};
use std::time::Instant;

use crate::field::{PRIME_P, ct_eq_16, mul_mod, reduce, zeroize_slice, zeroize_u128};

#[cfg(target_arch = "x86_64")]
#[inline]
fn zeroize_u64_slice(buf: &mut [u64]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid mutable reference to an initialized `u64`.
        unsafe { std::ptr::write_volatile(w, 0u64) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
fn zeroize_u64(val: &mut u64) {
    // SAFETY: `val` is a valid mutable reference to an initialized `u64`.
    unsafe { std::ptr::write_volatile(val, 0u64) };
    compiler_fence(Ordering::SeqCst);
}

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m256i, __m512i, _mm_add_epi64, _mm_cvtsi64_si128, _mm_cvtsi128_si64, _mm_unpackhi_epi64,
    _mm_xor_si128, _mm256_add_epi8, _mm256_and_si256, _mm256_castsi256_si128,
    _mm256_extracti128_si256, _mm256_loadu_si256, _mm256_or_si256, _mm256_sad_epu8,
    _mm256_set1_epi8, _mm256_setr_epi8, _mm256_setzero_si256, _mm256_shuffle_epi8,
    _mm256_sll_epi64, _mm256_srl_epi64, _mm256_srli_epi16, _mm256_storeu_si256, _mm256_xor_si256,
    _mm512_and_si512, _mm512_castsi512_si256, _mm512_extracti64x4_epi64, _mm512_loadu_si512,
    _mm512_or_si512, _mm512_popcnt_epi64, _mm512_setzero_si512, _mm512_sll_epi64,
    _mm512_srl_epi64, _mm512_storeu_si512, _mm512_xor_si512,
};

/// Mask selecting the low 120 bits (15 little-endian bytes) of a `u128`.
const MASK_120: u128 = (1u128 << 120) - 1;

/// Injective `0x01` sentinel byte at byte offset 15 (`1 << 120`) for full 15-byte MAC chunks.
const SENTINEL_120: u128 = 1u128 << 120;

/// Mask selecting the low 64 bits of a `u128`.
const MASK_64: u128 = 0xFFFF_FFFF_FFFF_FFFF;

/// Mask selecting the low 63 bits of a `u128`.
const MASK_63: u128 = (1u128 << 63) - 1;

/// Mask selecting the low 126 bits of a `u128`.
const MASK_126: u128 = (1u128 << 126) - 1;

// ============================================================================
// 1. Runtime-Dispatched SIMD OTP XOR
// ============================================================================

/// Returns the active runtime-dispatched backend name used by `otp_xor_turbo_in_place`.
///
/// Returns `"avx512f"`, `"avx2"`, or `"scalar-u64"`.
pub fn active_xor_backend() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            return "avx512f";
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            return "avx2";
        }
    }
    "scalar-u64"
}

/// High-throughput runtime-dispatched SIMD in-place One-Time Pad XOR (`data[i] ^= key[i]`).
///
/// Automatically dispatches at runtime to:
/// - `avx512f`: 4x unrolled `_mm512_xor_si512` (256 bytes/iteration)
/// - `avx2`: 4x unrolled `_mm256_xor_si256` (128 bytes/iteration)
/// - `scalar-u64`: portable 4x unrolled `u64` word-level XOR
///
/// # Panics
/// Panics if `key.len() < data.len()`.
#[inline]
pub fn otp_xor_turbo_in_place(data: &mut [u8], key: &[u8]) {
    assert!(
        key.len() >= data.len(),
        "OTP key too short: need {} bytes, only {} available",
        data.len(),
        key.len()
    );

    if data.is_empty() {
        return;
    }

    let key = &key[..data.len()];

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f") {
            // SAFETY: `avx512f` support was verified at runtime and `key.len() == data.len()`.
            unsafe { otp_xor_avx512(data, key) };
            return;
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: `avx2` support was verified at runtime and `key.len() == data.len()`.
            unsafe { otp_xor_avx2(data, key) };
            return;
        }
    }

    otp_xor_scalar_u64(data, key);
}

/// Convenience allocating wrapper around `otp_xor_turbo_in_place`.
#[inline]
pub fn otp_xor_turbo(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(
        key.len() >= data.len(),
        "OTP key too short: need {} bytes, only {} available",
        data.len(),
        key.len()
    );
    let mut out = data.to_vec();
    otp_xor_turbo_in_place(&mut out, key);
    out
}

/// Portable 4x unrolled `u64` word-level XOR fallback (works identically on x86_64 & ARM64).
#[inline]
fn otp_xor_scalar_u64(data: &mut [u8], key: &[u8]) {
    debug_assert_eq!(data.len(), key.len());
    let len = data.len();
    let mut offset = 0usize;

    while offset + 32 <= len {
        for lane in 0..4 {
            let p = offset + lane * 8;
            let d = u64::from_ne_bytes(data[p..p + 8].try_into().expect("8-byte chunk"));
            let k = u64::from_ne_bytes(key[p..p + 8].try_into().expect("8-byte chunk"));
            data[p..p + 8].copy_from_slice(&(d ^ k).to_ne_bytes());
        }
        offset += 32;
    }

    while offset + 8 <= len {
        let d = u64::from_ne_bytes(data[offset..offset + 8].try_into().expect("8-byte chunk"));
        let k = u64::from_ne_bytes(key[offset..offset + 8].try_into().expect("8-byte chunk"));
        data[offset..offset + 8].copy_from_slice(&(d ^ k).to_ne_bytes());
        offset += 8;
    }

    for (d, &k) in data[offset..].iter_mut().zip(key[offset..].iter()) {
        *d ^= k;
    }
}

/// # Safety
/// Caller must ensure `avx512f` is supported on the current CPU and `data.len() == key.len()`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn otp_xor_avx512(data: &mut [u8], key: &[u8]) {
    debug_assert_eq!(data.len(), key.len());
    let len = data.len();
    let d_ptr = data.as_mut_ptr();
    let k_ptr = key.as_ptr();
    let mut offset = 0usize;

    // 4x unrolled AVX-512 loop: 256 bytes per iteration.
    while len - offset >= 256 {
        // SAFETY: `offset + 256 <= len`, pointers are valid and non-aliasing (Rust borrow rules),
        // and unaligned load/store intrinsics accept arbitrary byte alignment.
        unsafe {
            let d0 = _mm512_loadu_si512(d_ptr.add(offset).cast());
            let k0 = _mm512_loadu_si512(k_ptr.add(offset).cast());
            let d1 = _mm512_loadu_si512(d_ptr.add(offset + 64).cast());
            let k1 = _mm512_loadu_si512(k_ptr.add(offset + 64).cast());
            let d2 = _mm512_loadu_si512(d_ptr.add(offset + 128).cast());
            let k2 = _mm512_loadu_si512(k_ptr.add(offset + 128).cast());
            let d3 = _mm512_loadu_si512(d_ptr.add(offset + 192).cast());
            let k3 = _mm512_loadu_si512(k_ptr.add(offset + 192).cast());

            _mm512_storeu_si512(d_ptr.add(offset).cast(), _mm512_xor_si512(d0, k0));
            _mm512_storeu_si512(d_ptr.add(offset + 64).cast(), _mm512_xor_si512(d1, k1));
            _mm512_storeu_si512(d_ptr.add(offset + 128).cast(), _mm512_xor_si512(d2, k2));
            _mm512_storeu_si512(d_ptr.add(offset + 192).cast(), _mm512_xor_si512(d3, k3));
        }
        offset += 256;
    }

    // Single 64-byte AVX-512 tail chunks.
    while len - offset >= 64 {
        // SAFETY: `offset + 64 <= len`.
        unsafe {
            let d0 = _mm512_loadu_si512(d_ptr.add(offset).cast());
            let k0 = _mm512_loadu_si512(k_ptr.add(offset).cast());
            _mm512_storeu_si512(d_ptr.add(offset).cast(), _mm512_xor_si512(d0, k0));
        }
        offset += 64;
    }

    if offset < len {
        otp_xor_scalar_u64(&mut data[offset..], &key[offset..]);
    }
}

/// # Safety
/// Caller must ensure `avx2` is supported on the current CPU and `data.len() == key.len()`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn otp_xor_avx2(data: &mut [u8], key: &[u8]) {
    debug_assert_eq!(data.len(), key.len());
    let len = data.len();
    let d_ptr = data.as_mut_ptr();
    let k_ptr = key.as_ptr();
    let mut offset = 0usize;

    // 4x unrolled AVX2 loop: 128 bytes per iteration.
    while len - offset >= 128 {
        // SAFETY: `offset + 128 <= len`.
        unsafe {
            let d0 = _mm256_loadu_si256(d_ptr.add(offset).cast());
            let k0 = _mm256_loadu_si256(k_ptr.add(offset).cast());
            let d1 = _mm256_loadu_si256(d_ptr.add(offset + 32).cast());
            let k1 = _mm256_loadu_si256(k_ptr.add(offset + 32).cast());
            let d2 = _mm256_loadu_si256(d_ptr.add(offset + 64).cast());
            let k2 = _mm256_loadu_si256(k_ptr.add(offset + 64).cast());
            let d3 = _mm256_loadu_si256(d_ptr.add(offset + 96).cast());
            let k3 = _mm256_loadu_si256(k_ptr.add(offset + 96).cast());

            _mm256_storeu_si256(d_ptr.add(offset).cast(), _mm256_xor_si256(d0, k0));
            _mm256_storeu_si256(d_ptr.add(offset + 32).cast(), _mm256_xor_si256(d1, k1));
            _mm256_storeu_si256(d_ptr.add(offset + 64).cast(), _mm256_xor_si256(d2, k2));
            _mm256_storeu_si256(d_ptr.add(offset + 96).cast(), _mm256_xor_si256(d3, k3));
        }
        offset += 128;
    }

    // Single 32-byte AVX2 tail chunks.
    while len - offset >= 32 {
        // SAFETY: `offset + 32 <= len`.
        unsafe {
            let d0 = _mm256_loadu_si256(d_ptr.add(offset).cast());
            let k0 = _mm256_loadu_si256(k_ptr.add(offset).cast());
            _mm256_storeu_si256(d_ptr.add(offset).cast(), _mm256_xor_si256(d0, k0));
        }
        offset += 32;
    }

    if offset < len {
        otp_xor_scalar_u64(&mut data[offset..], &key[offset..]);
    }
}

// ============================================================================
// 2. 4-Way Pipelined Unrolled Carter-Wegman MAC over F_(2^127 - 1)
// ============================================================================

/// Branchless weak addition modulo `PRIME_P = 2^127 - 1`.
///
/// Precondition: `a <= PRIME_P` and `b <= PRIME_P`.
/// Postcondition: returns `r <= PRIME_P` with `r === a + b (mod PRIME_P)`.
#[inline(always)]
const fn add_weak(a: u128, b: u128) -> u128 {
    let s = a + b;
    (s & PRIME_P) + (s >> 127)
}

/// Branchless weak multiplication modulo `PRIME_P = 2^127 - 1`.
///
/// Precondition: `a <= PRIME_P` and `b <= PRIME_P` (bit 127 is zero in both operands).
/// Postcondition: returns `r <= PRIME_P` with `r === a * b (mod PRIME_P)`.
#[inline(always)]
const fn mul_weak(a: u128, b: u128) -> u128 {
    let a0 = a & MASK_64;
    let a1 = a >> 64;
    let b0 = b & MASK_64;
    let b1 = b >> 64;

    let lo = a0 * b0;
    let hi = a1 * b1;
    let mid = a1 * b0 + a0 * b1;

    let sum_a = (hi << 1) + (mid >> 63) + (lo >> 127);
    let s1 = (lo & PRIME_P) + ((mid & MASK_63) << 64);
    let t1 = (s1 & PRIME_P) + (s1 >> 127);
    let s2 = t1 + sum_a;
    (s2 & PRIME_P) + (s2 >> 127)
}

/// Fused 4-way dot product `x0*y0 + x1*y1 + x2*y2 + x3*y3 (mod PRIME_P)` with lazy reduction.
///
/// Accumulates all four 128-bit partial products `(lo, mid, hi)` with carry tracking and performs
/// a single Mersenne reduction at the end, cutting reduction overhead by 4x.
///
/// Precondition: all `x_i <= PRIME_P` and `y_i <= PRIME_P`.
/// Postcondition: returns `r <= PRIME_P` congruent to `sum(x_i * y_i) (mod PRIME_P)`.
#[inline(always)]
const fn dot4_weak(
    x0: u128,
    y0: u128,
    x1: u128,
    y1: u128,
    x2: u128,
    y2: u128,
    x3: u128,
    y3: u128,
) -> u128 {
    let x0_0 = x0 & MASK_64;
    let x0_1 = x0 >> 64;
    let y0_0 = y0 & MASK_64;
    let y0_1 = y0 >> 64;

    let x1_0 = x1 & MASK_64;
    let x1_1 = x1 >> 64;
    let y1_0 = y1 & MASK_64;
    let y1_1 = y1 >> 64;

    let x2_0 = x2 & MASK_64;
    let x2_1 = x2 >> 64;
    let y2_0 = y2 & MASK_64;
    let y2_1 = y2 >> 64;

    let x3_0 = x3 & MASK_64;
    let x3_1 = x3 >> 64;
    let y3_0 = y3 & MASK_64;
    let y3_1 = y3 >> 64;

    // 1. Low 64x64 products (each <= 2^128 - 2^65 + 1).
    let (lo01, lc0) = (x0_0 * y0_0).overflowing_add(x1_0 * y1_0);
    let (lo23, lc1) = (x2_0 * y2_0).overflowing_add(x3_0 * y3_0);
    let (lo_sum, lc2) = lo01.overflowing_add(lo23);
    let lo_carry = (lc0 as u128) + (lc1 as u128) + (lc2 as u128); // <= 3

    // 2. Cross products (each `a1*b0 + a0*b1 <= 2^128 - 3*2^64 + 2`, no internal overflow).
    let m0 = x0_1 * y0_0 + x0_0 * y0_1;
    let m1 = x1_1 * y1_0 + x1_0 * y1_1;
    let m2 = x2_1 * y2_0 + x2_0 * y2_1;
    let m3 = x3_1 * y3_0 + x3_0 * y3_1;
    let (mid01, mc0) = m0.overflowing_add(m1);
    let (mid23, mc1) = m2.overflowing_add(m3);
    let (mid_sum, mc2) = mid01.overflowing_add(mid23);
    let mid_carry = (mc0 as u128) + (mc1 as u128) + (mc2 as u128); // <= 3

    // 3. High 63x63 products (each <= 2^126 - 2^64 + 1 -> sum of 4 < 2^128, no overflow).
    let hi_sum = (x0_1 * y0_1 + x1_1 * y1_1) + (x2_1 * y2_1 + x3_1 * y3_1);

    // Single Mersenne reduction using 2^127 === 1, 2^128 === 2, 2^192 === 2^65, 2^254 === 1 (mod P).
    let t_lo = lo_sum & PRIME_P;
    let t_mid_lo = (mid_sum & MASK_63) << 64;
    let t_hi = (hi_sum & MASK_126) << 1;

    // Max value: 1 + 6 + (2^65 - 1) + 3*2^65 + 3 = 2^67 + 9 < 2^68.
    let small_carries = (lo_sum >> 127)
        + (lo_carry << 1)
        + (mid_sum >> 63)
        + (mid_carry << 65)
        + (hi_sum >> 126);

    let s0 = add_weak(t_lo, t_mid_lo);
    let s1 = add_weak(t_hi, small_carries);
    add_weak(s0, s1)
}

/// Core 4-way Carter-Wegman byte MAC body (shared by portable and BMI2/ADX compiled paths).
#[inline(always)]
fn cw_mac_bytes_core(key: &CwFastKey, data: &[u8]) -> [u8; 16] {
    let mut acc: u128 = 0;

    // 4-way pipelined loop: 60 bytes = 4 x 15-byte chunks per iteration.
    // Horner equivalence across 4 blocks (b0, b1, b2, b3):
    //   ((((acc + b0) * r + b1) * r + b2) * r + b3) * r
    // = (acc + b0) * r^4 + b1 * r^3 + b2 * r^2 + b3 * r (mod P)
    let mut chunks60 = data.chunks_exact(60);
    for c in &mut chunks60 {
        let b0 = (u128::from_le_bytes(c[0..16].try_into().expect("16 bytes")) & MASK_120)
            | SENTINEL_120;
        let b1 = (u128::from_le_bytes(c[15..31].try_into().expect("16 bytes")) & MASK_120)
            | SENTINEL_120;
        let b2 = (u128::from_le_bytes(c[30..46].try_into().expect("16 bytes")) & MASK_120)
            | SENTINEL_120;
        // Bytes 44..60 contain chunk bytes 45..60 in bits 8..128; `>> 8` extracts them cleanly.
        let b3 = (u128::from_le_bytes(c[44..60].try_into().expect("16 bytes")) >> 8) | SENTINEL_120;

        acc = dot4_weak(add_weak(acc, b0), key.r4, b1, key.r3, b2, key.r2, b3, key.r);
    }

    // Handle remaining 0..59 bytes in 15-byte chunks (exact injective 0x01 sentinel).
    let mut buf = [0u8; 16];
    for chunk in chunks60.remainder().chunks(15) {
        buf = [0u8; 16];
        buf[..chunk.len()].copy_from_slice(chunk);
        buf[chunk.len()] = 0x01;
        let block = u128::from_le_bytes(buf);
        acc = mul_weak(add_weak(acc, block), key.r);
    }
    zeroize_slice(&mut buf);

    let tag_val = reduce(add_weak(acc, key.s));
    zeroize_u128(&mut acc);
    debug_assert!(tag_val < PRIME_P);
    tag_val.to_be_bytes()
}

/// Core 4-way Carter-Wegman `u128` stream MAC body.
#[inline(always)]
fn cw_mac_u128_stream_core(key: &CwFastKey, words: &[u128]) -> [u8; 16] {
    let mut acc: u128 = 0;

    let mut chunks4 = words.chunks_exact(4);
    for c in &mut chunks4 {
        let b0 = reduce(c[0]);
        let b1 = reduce(c[1]);
        let b2 = reduce(c[2]);
        let b3 = reduce(c[3]);
        acc = dot4_weak(add_weak(acc, b0), key.r4, b1, key.r3, b2, key.r2, b3, key.r);
    }

    for &w in chunks4.remainder() {
        acc = mul_weak(add_weak(acc, reduce(w)), key.r);
    }

    // Domain-separate by word count so leading-zero slices never collide.
    acc = mul_weak(add_weak(acc, words.len() as u128), key.r);

    let tag_val = reduce(add_weak(acc, key.s));
    zeroize_u128(&mut acc);
    debug_assert!(tag_val < PRIME_P);
    tag_val.to_be_bytes()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2,adx")]
unsafe fn cw_mac_bytes_bmi2(key: &CwFastKey, data: &[u8]) -> [u8; 16] {
    cw_mac_bytes_core(key, data)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2,adx")]
unsafe fn cw_mac_u128_stream_bmi2(key: &CwFastKey, words: &[u128]) -> [u8; 16] {
    cw_mac_u128_stream_core(key, words)
}

/// Precomputed 4-way Carter-Wegman MAC key over `F_(2^127 - 1)`.
///
/// Precomputes `(r, r^2, r^3, r^4, s)` once per key so 4 polynomial blocks can be multiplied
/// in parallel, breaking the serial Horner latency chain. All key powers and mask `s` are
/// volatile-zeroized automatically on `Drop`.
pub struct CwFastKey {
    r: u128,
    r2: u128,
    r3: u128,
    r4: u128,
    s: u128,
}

impl CwFastKey {
    /// Precompute key powers `(r, r^2, r^3, r^4)` and mask `s` in `F_(2^127 - 1)`.
    #[inline]
    pub const fn new(r: u128, s: u128) -> Self {
        let r = reduce(r);
        let r2 = mul_mod(r, r);
        let r3 = mul_mod(r2, r);
        let r4 = mul_mod(r2, r2);
        let s = reduce(s);
        Self { r, r2, r3, r4, s }
    }

    /// Compute the 128-bit Carter-Wegman MAC over `data` using 4-way pipelined evaluation.
    ///
    /// Produces **bit-for-bit identical** output to `crate::otp::carter_wegman_mac(data, r, s)`.
    #[inline]
    pub fn mac(&self, data: &[u8]) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("bmi2")
                && std::arch::is_x86_feature_detected!("adx")
            {
                // SAFETY: `bmi2` and `adx` CPU features verified at runtime.
                return unsafe { cw_mac_bytes_bmi2(self, data) };
            }
        }
        cw_mac_bytes_core(self, data)
    }

    /// Constant-time verification of a 16-byte Carter-Wegman MAC tag.
    #[inline]
    pub fn verify(&self, data: &[u8], tag: &[u8; 16]) -> bool {
        let mut expected = self.mac(data);
        let ok = ct_eq_16(&expected, tag);
        zeroize_slice(&mut expected);
        ok
    }

    /// 4-way pipelined Carter-Wegman MAC over a native `&[u128]` stream (e.g. binary transaction
    /// arrays), evaluating:
    ///
    /// `H_r(words) = (sum_{i=0}^{n-1} reduce(words[i]) * r^(n + 1 - i)) + n * r (mod P)`
    /// `tag = (H_r(words) + s) mod P` (16-byte big-endian).
    ///
    /// The trailing length term `n * r` makes the hash strictly injective across slices of
    /// differing lengths (preventing leading-zero collisions).
    #[inline]
    pub fn mac_u128_stream(&self, words: &[u128]) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("bmi2")
                && std::arch::is_x86_feature_detected!("adx")
            {
                // SAFETY: `bmi2` and `adx` CPU features verified at runtime.
                return unsafe { cw_mac_u128_stream_bmi2(self, words) };
            }
        }
        cw_mac_u128_stream_core(self, words)
    }

    /// Immediately wipe all key material using volatile writes.
    #[inline]
    pub fn zeroize(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.r2);
        zeroize_u128(&mut self.r3);
        zeroize_u128(&mut self.r4);
        zeroize_u128(&mut self.s);
    }
}

impl Drop for CwFastKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for CwFastKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CwFastKey")
            .field("r", &"[REDACTED]")
            .field("r2", &"[REDACTED]")
            .field("r3", &"[REDACTED]")
            .field("r4", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

/// Compute a 4-way pipelined Carter-Wegman MAC over `data` using a precomputed `CwFastKey`.
///
/// Produces **bit-for-bit identical** output to `crate::otp::carter_wegman_mac`.
#[inline]
pub fn cw_mac_4way(key: &CwFastKey, data: &[u8]) -> [u8; 16] {
    key.mac(data)
}

/// Seal a native `&[u128]` stream at maximum speed using 4-way pipelined Carter-Wegman MAC.
///
/// Zeroizes the temporary precomputed `CwFastKey` on drop.
#[inline]
pub fn cw_mac_u128_stream_4way(words: &[u128], r: u128, s: u128) -> [u8; 16] {
    let key = CwFastKey::new(r, s);
    key.mac_u128_stream(words)
}

// ============================================================================
// 3. SIMD AVX-512 VPOPCNTDQ / AVX2 Toeplitz 2-Universal Privacy Amplification
// ============================================================================

/// Returns the active runtime-dispatched backend name used by `toeplitz_hash_turbo`.
///
/// Returns `"avx512-vpopcntdq"`, `"avx2-vpshufb"`, or `"scalar-u64-4x"`.
pub fn active_toeplitz_backend() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512vpopcntdq")
        {
            return "avx512-vpopcntdq";
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            return "avx2-vpshufb";
        }
    }
    "scalar-u64-4x"
}

/// Minimum number of `u64` seed words required for `toeplitz_hash_turbo`.
#[inline]
pub const fn toeplitz_seed_words_turbo(raw_bits: usize, out_bits: usize) -> usize {
    if raw_bits == 0 || out_bits == 0 {
        return 0;
    }
    match raw_bits.checked_add(out_bits - 1) {
        Some(bits) => bits.div_ceil(64),
        None => panic!("toeplitz bit count overflow"),
    }
}

/// Runtime-dispatched SIMD 2-universal Toeplitz hash over GF(2) for QKD privacy amplification.
///
/// Produces **bit-for-bit identical** output to `crate::qkd::toeplitz_hash_u64(raw, raw_bits, seed, out_bits)`.
///
/// Dispatches automatically at runtime to:
/// - `avx512-vpopcntdq`: bit-shift-grouped 512-bit dot-products (`_mm512_and_si512`,
///   `_mm512_xor_si512`, `_mm512_popcnt_epi64`) with 8-way `word_shift` tiling
/// - `avx2-vpshufb`: bit-shift-grouped 256-bit dot-products with `vpshufb` nibble-lookup POPCNT
///   + `vpsadbw` and 4-way `word_shift` tiling
/// - `scalar-u64-4x`: portable 4x-unrolled `u64::count_ones()` fallback
///
/// # Panics
/// Panics if `raw` has fewer than `raw_bits.div_ceil(64)` words or `seed` has fewer than
/// `(raw_bits + out_bits - 1).div_ceil(64)` words (when both `raw_bits > 0` and `out_bits > 0`).
pub fn toeplitz_hash_turbo(
    raw: &[u64],
    raw_bits: usize,
    seed: &[u64],
    out_bits: usize,
) -> Vec<u64> {
    if out_bits == 0 {
        return Vec::new();
    }

    let out_words = out_bits.div_ceil(64);
    if raw_bits == 0 {
        return vec![0u64; out_words];
    }

    let needed_raw_words = raw_bits.div_ceil(64);
    assert!(
        raw.len() >= needed_raw_words,
        "raw slice has {} words, need at least {needed_raw_words} for {raw_bits} bits",
        raw.len()
    );

    let needed_seed_bits = raw_bits
        .checked_add(out_bits - 1)
        .expect("toeplitz bit count overflow");
    let needed_seed_words = needed_seed_bits.div_ceil(64);
    assert!(
        seed.len() >= needed_seed_words,
        "seed slice has {} words, need at least {needed_seed_words} for {needed_seed_bits} bits",
        seed.len()
    );

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512vpopcntdq")
        {
            // SAFETY: CPU features verified at runtime and slice lengths verified above.
            return unsafe { toeplitz_hash_avx512(raw, raw_bits, seed, out_bits) };
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: CPU feature verified at runtime and slice lengths verified above.
            return unsafe { toeplitz_hash_avx2(raw, raw_bits, seed, out_bits) };
        }
    }

    toeplitz_hash_scalar_4x(raw, raw_bits, seed, out_bits)
}

/// Portable 4x unrolled `u64` Toeplitz fallback.
fn toeplitz_hash_scalar_4x(
    raw: &[u64],
    raw_bits: usize,
    seed: &[u64],
    out_bits: usize,
) -> Vec<u64> {
    let out_words = out_bits.div_ceil(64);
    let full_words = raw_bits / 64;
    let rem_bits = raw_bits % 64;
    let tail_mask: u64 = if rem_bits == 0 {
        0
    } else {
        (1u64 << rem_bits) - 1
    };
    let mut tail_raw = if tail_mask != 0 {
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

        let mut acc0 = 0u64;
        let mut acc1 = 0u64;
        let mut acc2 = 0u64;
        let mut acc3 = 0u64;

        if bit_shift == 0 {
            if full_words > 0 {
                let s = &seed[word_shift..word_shift + full_words];
                let mut w = 0usize;
                while w + 4 <= full_words {
                    acc0 ^= s[w] & r[w];
                    acc1 ^= s[w + 1] & r[w + 1];
                    acc2 ^= s[w + 2] & r[w + 2];
                    acc3 ^= s[w + 3] & r[w + 3];
                    w += 4;
                }
                while w < full_words {
                    acc0 ^= s[w] & r[w];
                    w += 1;
                }
            }
            if tail_mask != 0 {
                acc0 ^= seed[word_shift + full_words] & tail_raw;
            }
        } else {
            let inv_shift = 64 - bit_shift;
            if full_words > 0 {
                let s0 = &seed[word_shift..word_shift + full_words];
                let s1 = &seed[word_shift + 1..word_shift + 1 + full_words];
                let mut w = 0usize;
                while w + 4 <= full_words {
                    acc0 ^= ((s0[w] >> bit_shift) | (s1[w] << inv_shift)) & r[w];
                    acc1 ^= ((s0[w + 1] >> bit_shift) | (s1[w + 1] << inv_shift)) & r[w + 1];
                    acc2 ^= ((s0[w + 2] >> bit_shift) | (s1[w + 2] << inv_shift)) & r[w + 2];
                    acc3 ^= ((s0[w + 3] >> bit_shift) | (s1[w + 3] << inv_shift)) & r[w + 3];
                    w += 4;
                }
                while w < full_words {
                    acc0 ^= ((s0[w] >> bit_shift) | (s1[w] << inv_shift)) & r[w];
                    w += 1;
                }
            }
            if tail_mask != 0 {
                let lo = seed[word_shift + full_words] >> bit_shift;
                let hi = seed
                    .get(word_shift + full_words + 1)
                    .copied()
                    .unwrap_or(0)
                    << inv_shift;
                acc0 ^= (lo | hi) & tail_raw;
            }
        }

        let parity = ((acc0 ^ acc1 ^ acc2 ^ acc3).count_ones() & 1) as u64;
        out[i / 64] |= parity << (i % 64);
    }

    zeroize_u64(&mut tail_raw);
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512vpopcntdq")]
#[inline]
unsafe fn popcnt_parity_avx512(v: __m512i) -> u64 {
    // Compute 8 independent 64-bit lane popcounts in a single `vpopcntq` instruction,
    // then XOR-fold the 8 lane counts together; bit 0 is the exact overall bit parity.
    let v_pop = _mm512_popcnt_epi64(v);
    let lo256 = _mm512_castsi512_si256(v_pop);
    let hi256 = _mm512_extracti64x4_epi64::<1>(v_pop);
    let v256 = _mm256_xor_si256(lo256, hi256);
    let lo128 = _mm256_castsi256_si128(v256);
    let hi128 = _mm256_extracti128_si256::<1>(v256);
    let v128 = _mm_xor_si128(lo128, hi128);
    let hi64 = _mm_unpackhi_epi64(v128, v128);
    let folded = _mm_cvtsi128_si64(_mm_xor_si128(v128, hi64)) as u64;
    folded & 1
}

/// Fill `dst[0..len]` with `(seed[j] >> bit_shift) | (seed.get(j+1).unwrap_or(0) << (64 - bit_shift))`
/// using 512-bit AVX-512 shifts.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
#[inline]
unsafe fn preshift_seed_avx512(seed: &[u64], dst: &mut [u64], len: usize, bit_shift: usize) {
    debug_assert!(bit_shift > 0 && bit_shift < 64);
    debug_assert!(len <= dst.len() && len <= seed.len());

    let inv_shift = 64 - bit_shift;
    let v_bs = _mm_cvtsi64_si128(bit_shift as i64);
    let v_is = _mm_cvtsi64_si128(inv_shift as i64);

    // Safe vector limit where `j + 1 + 8 <= seed.len()`.
    let vec_limit = if seed.len() > 1 {
        len.min(seed.len() - 1) & !7
    } else {
        0
    };

    let s_ptr = seed.as_ptr();
    let d_ptr = dst.as_mut_ptr();
    let mut j = 0usize;
    while j < vec_limit {
        // SAFETY: `j + 8 <= dst.len()` and `j + 1 + 8 <= seed.len()`.
        unsafe {
            let s0 = _mm512_loadu_si512(s_ptr.add(j).cast());
            let s1 = _mm512_loadu_si512(s_ptr.add(j + 1).cast());
            let shifted = _mm512_or_si512(
                _mm512_srl_epi64(s0, v_bs),
                _mm512_sll_epi64(s1, v_is),
            );
            _mm512_storeu_si512(d_ptr.add(j).cast(), shifted);
        }
        j += 8;
    }

    while j < len {
        let lo = seed[j] >> bit_shift;
        let hi = seed.get(j + 1).copied().unwrap_or(0) << inv_shift;
        dst[j] = lo | hi;
        j += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512vpopcntdq")]
unsafe fn toeplitz_hash_avx512(
    raw: &[u64],
    raw_bits: usize,
    seed: &[u64],
    out_bits: usize,
) -> Vec<u64> {
    let out_words = out_bits.div_ceil(64);
    let full_words = raw_bits / 64;
    let rem_bits = raw_bits % 64;
    let tail_mask: u64 = if rem_bits == 0 {
        0
    } else {
        (1u64 << rem_bits) - 1
    };
    let mut tail_raw = if tail_mask != 0 {
        raw[full_words] & tail_mask
    } else {
        0
    };

    let needed_raw_words = raw_bits.div_ceil(64);
    let vec_words = full_words & !7; // Multiple of 8 words (512 bits/iter)
    let max_off = out_bits - 1;
    let max_ws_count = max_off / 64 + 1;
    let max_sb_len = (max_ws_count - 1) + needed_raw_words;

    let raw_ptr = raw.as_ptr();
    let mut out = vec![0u64; out_words];
    let mut shifted_buf = vec![0u64; max_sb_len];

    // Group output bits by `b = offset % 64`.
    // For each `b`, pre-shift the seed ONCE, then evaluate all `ws = offset / 64` output bits
    // with ZERO shifts in the inner loop (8 output bits per `raw` load!).
    let b_limit = out_bits.min(64);
    for b in 0..b_limit {
        let ws_count = (max_off - b) / 64 + 1;
        let sb_len = (ws_count - 1) + needed_raw_words;

        let sb: &[u64] = if b == 0 {
            seed
        } else {
            // SAFETY: running inside `avx512f` target_feature fn; `sb_len <= seed.len()`.
            unsafe { preshift_seed_avx512(seed, &mut shifted_buf, sb_len, b) };
            &shifted_buf[..sb_len]
        };
        let sb_ptr = sb.as_ptr();

        let mut ws = 0usize;
        // 8-way `word_shift` tiled AVX-512 loop (zero shifts, 1 `vr` load serves 8 output bits!).
        if vec_words > 0 {
            while ws + 8 <= ws_count {
                let mut acc0 = _mm512_setzero_si512();
                let mut acc1 = _mm512_setzero_si512();
                let mut acc2 = _mm512_setzero_si512();
                let mut acc3 = _mm512_setzero_si512();
                let mut acc4 = _mm512_setzero_si512();
                let mut acc5 = _mm512_setzero_si512();
                let mut acc6 = _mm512_setzero_si512();
                let mut acc7 = _mm512_setzero_si512();

                let mut w = 0usize;
                while w < vec_words {
                    // SAFETY: `w + 8 <= full_words <= raw.len()` and
                    // `(ws + 7) + (w + 8) <= (ws_count - 1) + full_words + 1 <= sb_len <= sb.len()`.
                    unsafe {
                        let vr = _mm512_loadu_si512(raw_ptr.add(w).cast());
                        let s0 = _mm512_loadu_si512(sb_ptr.add(ws + w).cast());
                        let s1 = _mm512_loadu_si512(sb_ptr.add(ws + 1 + w).cast());
                        let s2 = _mm512_loadu_si512(sb_ptr.add(ws + 2 + w).cast());
                        let s3 = _mm512_loadu_si512(sb_ptr.add(ws + 3 + w).cast());
                        let s4 = _mm512_loadu_si512(sb_ptr.add(ws + 4 + w).cast());
                        let s5 = _mm512_loadu_si512(sb_ptr.add(ws + 5 + w).cast());
                        let s6 = _mm512_loadu_si512(sb_ptr.add(ws + 6 + w).cast());
                        let s7 = _mm512_loadu_si512(sb_ptr.add(ws + 7 + w).cast());

                        acc0 = _mm512_xor_si512(acc0, _mm512_and_si512(s0, vr));
                        acc1 = _mm512_xor_si512(acc1, _mm512_and_si512(s1, vr));
                        acc2 = _mm512_xor_si512(acc2, _mm512_and_si512(s2, vr));
                        acc3 = _mm512_xor_si512(acc3, _mm512_and_si512(s3, vr));
                        acc4 = _mm512_xor_si512(acc4, _mm512_and_si512(s4, vr));
                        acc5 = _mm512_xor_si512(acc5, _mm512_and_si512(s5, vr));
                        acc6 = _mm512_xor_si512(acc6, _mm512_and_si512(s6, vr));
                        acc7 = _mm512_xor_si512(acc7, _mm512_and_si512(s7, vr));
                    }
                    w += 8;
                }

                let accs = [acc0, acc1, acc2, acc3, acc4, acc5, acc6, acc7];
                for (k, &v_acc) in accs.iter().enumerate() {
                    let cur_ws = ws + k;
                    let mut rem_acc = 0u64;
                    for u in vec_words..full_words {
                        rem_acc ^= sb[cur_ws + u] & raw[u];
                    }
                    if tail_mask != 0 {
                        rem_acc ^= sb[cur_ws + full_words] & tail_raw;
                    }
                    // SAFETY: running inside `avx512f,avx512vpopcntdq` target_feature fn.
                    let vec_parity = unsafe { popcnt_parity_avx512(v_acc) };
                    let parity = vec_parity ^ ((rem_acc.count_ones() & 1) as u64);
                    let idx = max_off - (cur_ws * 64 + b);
                    out[idx / 64] |= parity << (idx % 64);
                }

                ws += 8;
            }
        }

        // Remaining `< 8` `word_shift` values for this bit offset `b`.
        while ws < ws_count {
            let mut v_acc = _mm512_setzero_si512();
            let mut w = 0usize;
            while w < vec_words {
                // SAFETY: `w + 8 <= full_words <= raw.len()` and `ws + w + 8 <= sb.len()`.
                unsafe {
                    let vr = _mm512_loadu_si512(raw_ptr.add(w).cast());
                    let vs = _mm512_loadu_si512(sb_ptr.add(ws + w).cast());
                    v_acc = _mm512_xor_si512(v_acc, _mm512_and_si512(vs, vr));
                }
                w += 8;
            }

            let mut rem_acc = 0u64;
            for u in vec_words..full_words {
                rem_acc ^= sb[ws + u] & raw[u];
            }
            if tail_mask != 0 {
                rem_acc ^= sb[ws + full_words] & tail_raw;
            }

            // SAFETY: running inside `avx512f,avx512vpopcntdq` target_feature fn.
            let vec_parity = if vec_words > 0 {
                unsafe { popcnt_parity_avx512(v_acc) }
            } else {
                0
            };
            let parity = vec_parity ^ ((rem_acc.count_ones() & 1) as u64);
            let idx = max_off - (ws * 64 + b);
            out[idx / 64] |= parity << (idx % 64);
            ws += 1;
        }
    }

    zeroize_u64_slice(&mut shifted_buf);
    zeroize_u64(&mut tail_raw);
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn popcnt_parity_avx2(v: __m256i) -> u64 {
    // 256-bit `vpshufb` nibble-lookup POPCNT + `vpsadbw` horizontal byte reduction.
    let lookup = _mm256_setr_epi8(
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, // low 128-bit lane
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, // high 128-bit lane
    );
    let low_mask = _mm256_set1_epi8(0x0f);
    let lo = _mm256_and_si256(v, low_mask);
    let hi = _mm256_and_si256(_mm256_srli_epi16::<4>(v), low_mask);
    let pop_lo = _mm256_shuffle_epi8(lookup, lo);
    let pop_hi = _mm256_shuffle_epi8(lookup, hi);
    let byte_pop = _mm256_add_epi8(pop_lo, pop_hi);
    let lane_pop = _mm256_sad_epu8(byte_pop, _mm256_setzero_si256());

    let lo128 = _mm256_castsi256_si128(lane_pop);
    let hi128 = _mm256_extracti128_si256::<1>(lane_pop);
    let sum128 = _mm_add_epi64(lo128, hi128);
    let hi64 = _mm_unpackhi_epi64(sum128, sum128);
    let total = _mm_cvtsi128_si64(_mm_add_epi64(sum128, hi64)) as u64;
    total & 1
}

/// Fill `dst[0..len]` with `(seed[j] >> bit_shift) | (seed.get(j+1).unwrap_or(0) << (64 - bit_shift))`
/// using 256-bit AVX2 shifts.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn preshift_seed_avx2(seed: &[u64], dst: &mut [u64], len: usize, bit_shift: usize) {
    debug_assert!(bit_shift > 0 && bit_shift < 64);
    debug_assert!(len <= dst.len() && len <= seed.len());

    let inv_shift = 64 - bit_shift;
    let v_bs = _mm_cvtsi64_si128(bit_shift as i64);
    let v_is = _mm_cvtsi64_si128(inv_shift as i64);

    let vec_limit = if seed.len() > 1 {
        len.min(seed.len() - 1) & !3
    } else {
        0
    };

    let s_ptr = seed.as_ptr();
    let d_ptr = dst.as_mut_ptr();
    let mut j = 0usize;
    while j < vec_limit {
        // SAFETY: `j + 4 <= dst.len()` and `j + 1 + 4 <= seed.len()`.
        unsafe {
            let s0 = _mm256_loadu_si256(s_ptr.add(j).cast());
            let s1 = _mm256_loadu_si256(s_ptr.add(j + 1).cast());
            let shifted = _mm256_or_si256(
                _mm256_srl_epi64(s0, v_bs),
                _mm256_sll_epi64(s1, v_is),
            );
            _mm256_storeu_si256(d_ptr.add(j).cast(), shifted);
        }
        j += 4;
    }

    while j < len {
        let lo = seed[j] >> bit_shift;
        let hi = seed.get(j + 1).copied().unwrap_or(0) << inv_shift;
        dst[j] = lo | hi;
        j += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn toeplitz_hash_avx2(
    raw: &[u64],
    raw_bits: usize,
    seed: &[u64],
    out_bits: usize,
) -> Vec<u64> {
    let out_words = out_bits.div_ceil(64);
    let full_words = raw_bits / 64;
    let rem_bits = raw_bits % 64;
    let tail_mask: u64 = if rem_bits == 0 {
        0
    } else {
        (1u64 << rem_bits) - 1
    };
    let mut tail_raw = if tail_mask != 0 {
        raw[full_words] & tail_mask
    } else {
        0
    };

    let needed_raw_words = raw_bits.div_ceil(64);
    let vec_words = full_words & !3; // Multiple of 4 words (256 bits/iter)
    let max_off = out_bits - 1;
    let max_ws_count = max_off / 64 + 1;
    let max_sb_len = (max_ws_count - 1) + needed_raw_words;

    let raw_ptr = raw.as_ptr();
    let mut out = vec![0u64; out_words];
    let mut shifted_buf = vec![0u64; max_sb_len];

    let b_limit = out_bits.min(64);
    for b in 0..b_limit {
        let ws_count = (max_off - b) / 64 + 1;
        let sb_len = (ws_count - 1) + needed_raw_words;

        let sb: &[u64] = if b == 0 {
            seed
        } else {
            // SAFETY: running inside `avx2` target_feature fn; `sb_len <= seed.len()`.
            unsafe { preshift_seed_avx2(seed, &mut shifted_buf, sb_len, b) };
            &shifted_buf[..sb_len]
        };
        let sb_ptr = sb.as_ptr();

        let mut ws = 0usize;
        // 4-way `word_shift` tiled AVX2 loop.
        if vec_words > 0 {
            while ws + 4 <= ws_count {
                let mut acc0 = _mm256_setzero_si256();
                let mut acc1 = _mm256_setzero_si256();
                let mut acc2 = _mm256_setzero_si256();
                let mut acc3 = _mm256_setzero_si256();

                let mut w = 0usize;
                while w < vec_words {
                    // SAFETY: `w + 4 <= full_words <= raw.len()` and `ws + 3 + w + 4 <= sb.len()`.
                    unsafe {
                        let vr = _mm256_loadu_si256(raw_ptr.add(w).cast());
                        let s0 = _mm256_loadu_si256(sb_ptr.add(ws + w).cast());
                        let s1 = _mm256_loadu_si256(sb_ptr.add(ws + 1 + w).cast());
                        let s2 = _mm256_loadu_si256(sb_ptr.add(ws + 2 + w).cast());
                        let s3 = _mm256_loadu_si256(sb_ptr.add(ws + 3 + w).cast());

                        acc0 = _mm256_xor_si256(acc0, _mm256_and_si256(s0, vr));
                        acc1 = _mm256_xor_si256(acc1, _mm256_and_si256(s1, vr));
                        acc2 = _mm256_xor_si256(acc2, _mm256_and_si256(s2, vr));
                        acc3 = _mm256_xor_si256(acc3, _mm256_and_si256(s3, vr));
                    }
                    w += 4;
                }

                let accs = [acc0, acc1, acc2, acc3];
                for (k, &v_acc) in accs.iter().enumerate() {
                    let cur_ws = ws + k;
                    let mut rem_acc = 0u64;
                    for u in vec_words..full_words {
                        rem_acc ^= sb[cur_ws + u] & raw[u];
                    }
                    if tail_mask != 0 {
                        rem_acc ^= sb[cur_ws + full_words] & tail_raw;
                    }
                    // SAFETY: running inside `avx2` target_feature fn.
                    let vec_parity = unsafe { popcnt_parity_avx2(v_acc) };
                    let parity = vec_parity ^ ((rem_acc.count_ones() & 1) as u64);
                    let idx = max_off - (cur_ws * 64 + b);
                    out[idx / 64] |= parity << (idx % 64);
                }

                ws += 4;
            }
        }

        while ws < ws_count {
            let mut v_acc = _mm256_setzero_si256();
            let mut w = 0usize;
            while w < vec_words {
                // SAFETY: `w + 4 <= full_words <= raw.len()` and `ws + w + 4 <= sb.len()`.
                unsafe {
                    let vr = _mm256_loadu_si256(raw_ptr.add(w).cast());
                    let vs = _mm256_loadu_si256(sb_ptr.add(ws + w).cast());
                    v_acc = _mm256_xor_si256(v_acc, _mm256_and_si256(vs, vr));
                }
                w += 4;
            }

            let mut rem_acc = 0u64;
            for u in vec_words..full_words {
                rem_acc ^= sb[ws + u] & raw[u];
            }
            if tail_mask != 0 {
                rem_acc ^= sb[ws + full_words] & tail_raw;
            }

            // SAFETY: running inside `avx2` target_feature fn.
            let vec_parity = if vec_words > 0 {
                unsafe { popcnt_parity_avx2(v_acc) }
            } else {
                0
            };
            let parity = vec_parity ^ ((rem_acc.count_ones() & 1) as u64);
            let idx = max_off - (ws * 64 + b);
            out[idx / 64] |= parity << (idx % 64);
            ws += 1;
        }
    }

    zeroize_u64_slice(&mut shifted_buf);
    zeroize_u64(&mut tail_raw);
    out
}

// ============================================================================
// 4. Built-In Throughput Benchmark Suite
// ============================================================================

/// Measured throughput results returned by `run_turbo_crypto_bench()`.
#[derive(Debug, Clone)]
pub struct TurboCryptoBench {
    /// Runtime-dispatched in-place SIMD OTP XOR throughput in GB/s (`10^9` bytes/s).
    pub xor_gb_per_sec: f64,
    /// 4-way Carter-Wegman MAC operations per second on 256-byte Vernam frames.
    pub cw_mac_ops_per_sec: f64,
    /// 4-way Carter-Wegman MAC streaming throughput in GB/s (`10^9` bytes/s) on 64 KiB buffers.
    pub cw_mac_gb_per_sec: f64,
    /// SIMD Toeplitz 2-universal privacy amplification throughput in output Mbps (`10^6` bits/s).
    pub toeplitz_mbps: f64,
    /// Active runtime-dispatched OTP XOR backend (`"avx512f"`, `"avx2"`, or `"scalar-u64"`).
    pub xor_backend: &'static str,
    /// Active runtime-dispatched Toeplitz backend (`"avx512-vpopcntdq"`, `"avx2-vpshufb"`, or `"scalar-u64-4x"`).
    pub toeplitz_backend: &'static str,
}

/// Run an in-process microbenchmark of all turbo crypto primitives using `std::hint::black_box`.
pub fn run_turbo_crypto_bench() -> TurboCryptoBench {
    // 1. OTP XOR benchmark (64 KiB hot in L2 cache x 8,192 iterations = 512 MiB).
    const XOR_BUF_LEN: usize = 64 * 1024;
    const XOR_ITERS: usize = 8_192;
    let mut xor_data = vec![0x5Au8; XOR_BUF_LEN];
    let xor_key = vec![0xA5u8; XOR_BUF_LEN];
    otp_xor_turbo_in_place(&mut xor_data, &xor_key);
    let t0 = Instant::now();
    for _ in 0..XOR_ITERS {
        otp_xor_turbo_in_place(black_box(&mut xor_data), black_box(&xor_key));
    }
    let xor_secs = t0.elapsed().as_secs_f64().max(1e-12);
    let xor_gb_per_sec = (XOR_BUF_LEN as f64 * XOR_ITERS as f64) / xor_secs / 1e9;
    black_box(&xor_data);

    // 2. Carter-Wegman 4-way MAC ops/sec on 256-byte Vernam frames (500,000 ops).
    const FRAME_LEN: usize = 256;
    const FRAME_ITERS: usize = 500_000;
    let cw_key = CwFastKey::new(
        0x1234_5678_9ABC_DEF0_FEDC_BA98_7654_3211,
        0x0FED_CBA9_8765_4321_1122_3344_5566_7788,
    );
    let frame = [0x3Cu8; FRAME_LEN];
    let mut sink = [0u8; 16];
    let t1 = Instant::now();
    for _ in 0..FRAME_ITERS {
        sink = cw_mac_4way(black_box(&cw_key), black_box(&frame));
    }
    let frame_secs = t1.elapsed().as_secs_f64().max(1e-12);
    let cw_mac_ops_per_sec = FRAME_ITERS as f64 / frame_secs;
    black_box(sink);

    // 3. Carter-Wegman 4-way MAC streaming GB/s on 64 KiB buffers (4,096 iterations = 256 MiB).
    const CW_BUF_LEN: usize = 64 * 1024;
    const CW_ITERS: usize = 4_096;
    let cw_buf = vec![0x7Du8; CW_BUF_LEN];
    let t2 = Instant::now();
    for _ in 0..CW_ITERS {
        sink = cw_mac_4way(black_box(&cw_key), black_box(&cw_buf));
    }
    let cw_secs = t2.elapsed().as_secs_f64().max(1e-12);
    let cw_mac_gb_per_sec = (CW_BUF_LEN as f64 * CW_ITERS as f64) / cw_secs / 1e9;
    black_box(sink);

    // 4. Toeplitz 2-universal privacy amplification (4096 raw bits -> 2048 output bits x 8,000 iters).
    const RAW_BITS: usize = 4096;
    const OUT_BITS: usize = 2048;
    const TP_ITERS: usize = 8_000;
    let raw_words: Vec<u64> = (0..RAW_BITS / 64)
        .map(|i| (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_5A5A_F0F0_0F0F)
        .collect();
    let seed_words: Vec<u64> = (0..toeplitz_seed_words_turbo(RAW_BITS, OUT_BITS))
        .map(|i| (i as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0x5555_AAAA_3333_CCCC)
        .collect();
    black_box(toeplitz_hash_turbo(&raw_words, RAW_BITS, &seed_words, OUT_BITS));
    let t3 = Instant::now();
    let mut tp_acc = 0u64;
    for _ in 0..TP_ITERS {
        let out = toeplitz_hash_turbo(
            black_box(&raw_words),
            RAW_BITS,
            black_box(&seed_words),
            OUT_BITS,
        );
        tp_acc ^= out[0];
    }
    let tp_secs = t3.elapsed().as_secs_f64().max(1e-12);
    let toeplitz_mbps = (OUT_BITS as f64 * TP_ITERS as f64) / tp_secs / 1e6;
    black_box(tp_acc);

    TurboCryptoBench {
        xor_gb_per_sec,
        cw_mac_ops_per_sec,
        cw_mac_gb_per_sec,
        toeplitz_mbps,
        xor_backend: active_xor_backend(),
        toeplitz_backend: active_toeplitz_backend(),
    }
}

// ============================================================================
// 5. Comprehensive Verification & Benchmark Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::add_mod;

    /// Deterministic xorshift64* PRNG for repeatable, zero-dependency test vectors.
    struct TestRng(u64);

    impl TestRng {
        fn new(seed: u64) -> Self {
            Self(seed | 1)
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn next_u128(&mut self) -> u128 {
            ((self.next_u64() as u128) << 64) | (self.next_u64() as u128)
        }

        fn fill_bytes(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    /// Exact scalar reference matching `crate::otp::otp_xor_in_place`.
    fn ref_otp_xor_in_place(data: &mut [u8], key: &[u8]) {
        for (d, &k) in data.iter_mut().zip(key.iter()) {
            *d ^= k;
        }
    }

    /// Exact scalar reference matching `crate::otp::carter_wegman_mac`.
    fn ref_carter_wegman_mac(data: &[u8], r: u128, s: u128) -> [u8; 16] {
        let r = reduce(r);
        let s = reduce(s);

        let mut acc: u128 = 0;
        for chunk in data.chunks(15) {
            let mut buf = [0u8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            buf[chunk.len()] = 0x01;
            let block = u128::from_le_bytes(buf);
            acc = mul_mod(add_mod(acc, block), r);
        }

        add_mod(acc, s).to_be_bytes()
    }

    /// Exact scalar reference for `cw_mac_u128_stream_4way`.
    fn ref_cw_mac_u128_stream(words: &[u128], r: u128, s: u128) -> [u8; 16] {
        let r = reduce(r);
        let s = reduce(s);
        let mut acc = 0u128;
        for &w in words {
            acc = mul_mod(add_mod(acc, reduce(w)), r);
        }
        acc = mul_mod(add_mod(acc, words.len() as u128), r);
        add_mod(acc, s).to_be_bytes()
    }

    /// Exact scalar reference matching `crate::qkd::toeplitz_hash_u64`.
    fn ref_toeplitz_hash_u64(
        raw: &[u64],
        raw_bits: usize,
        seed: &[u64],
        out_bits: usize,
    ) -> Vec<u64> {
        if out_bits == 0 {
            return Vec::new();
        }
        let out_words = out_bits.div_ceil(64);
        if raw_bits == 0 {
            return vec![0u64; out_words];
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

        out
    }

    #[test]
    fn test_otp_xor_turbo_matches_scalar_all_sizes_and_backends() {
        let sizes = [0, 1, 7, 15, 31, 32, 63, 64, 255, 256, 4096, 65537];
        let mut rng = TestRng::new(0x1337_CAFE_BABE_0001);

        for &len in &sizes {
            let mut base_data = vec![0u8; len + 5];
            let mut key_buf = vec![0u8; len + 7];
            rng.fill_bytes(&mut base_data);
            rng.fill_bytes(&mut key_buf);

            for &(d_off, k_off) in &[(0usize, 0usize), (1, 3)] {
                let src = &base_data[d_off..d_off + len];
                let key = &key_buf[k_off..k_off + len];

                let mut expected = src.to_vec();
                ref_otp_xor_in_place(&mut expected, key);

                let mut actual = src.to_vec();
                otp_xor_turbo_in_place(&mut actual, key);
                assert_eq!(actual, expected, "turbo XOR mismatch at len={len}");

                otp_xor_turbo_in_place(&mut actual, key);
                assert_eq!(actual, src, "turbo XOR involution failed at len={len}");

                let mut scalar = src.to_vec();
                otp_xor_scalar_u64(&mut scalar, key);
                assert_eq!(scalar, expected, "scalar-u64 XOR mismatch at len={len}");

                #[cfg(target_arch = "x86_64")]
                {
                    if std::arch::is_x86_feature_detected!("avx2") {
                        let mut avx2_buf = src.to_vec();
                        unsafe { otp_xor_avx2(&mut avx2_buf, key) };
                        assert_eq!(avx2_buf, expected, "avx2 XOR mismatch at len={len}");
                    }
                    if std::arch::is_x86_feature_detected!("avx512f") {
                        let mut avx512_buf = src.to_vec();
                        unsafe { otp_xor_avx512(&mut avx512_buf, key) };
                        assert_eq!(avx512_buf, expected, "avx512 XOR mismatch at len={len}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_cw_mac_4way_matches_scalar_reference_bit_for_bit() {
        let sizes = [0, 1, 14, 15, 16, 59, 60, 61, 119, 120, 121, 256, 1024, 4096];
        let mut rng = TestRng::new(0xDEAD_BEEF_C0DE_0002);

        let keys = [
            (rng.next_u128(), rng.next_u128()),
            (PRIME_P - 1, PRIME_P - 1),
            (PRIME_P, PRIME_P),
            (u128::MAX, u128::MAX),
            (0, 0),
            (1, PRIME_P - 2),
        ];

        for &(r, s) in &keys {
            let fast_key = CwFastKey::new(r, s);
            for &len in &sizes {
                let mut data = vec![0u8; len];
                rng.fill_bytes(&mut data);

                let expected = ref_carter_wegman_mac(&data, r, s);
                let actual = cw_mac_4way(&fast_key, &data);
                assert_eq!(
                    actual, expected,
                    "cw_mac_4way mismatch for len={len}, r={r:#x}, s={s:#x}"
                );
                assert!(fast_key.verify(&data, &actual));
                assert_eq!(
                    cw_mac_bytes_core(&fast_key, &data),
                    expected,
                    "portable cw_mac_bytes_core mismatch at len={len}"
                );

                if len > 0 {
                    let ones = vec![0xFFu8; len];
                    assert_eq!(
                        cw_mac_4way(&fast_key, &ones),
                        ref_carter_wegman_mac(&ones, r, s)
                    );
                    let zeros = vec![0x00u8; len];
                    assert_eq!(
                        cw_mac_4way(&fast_key, &zeros),
                        ref_carter_wegman_mac(&zeros, r, s)
                    );
                }
            }
        }

        let fast_key = CwFastKey::new(rng.next_u128(), rng.next_u128());
        assert_ne!(cw_mac_4way(&fast_key, &[]), cw_mac_4way(&fast_key, &[0]));
        assert_ne!(cw_mac_4way(&fast_key, &[0]), cw_mac_4way(&fast_key, &[0, 0]));
    }

    #[test]
    fn test_cw_mac_u128_stream_4way_matches_scalar_and_is_injective() {
        let mut rng = TestRng::new(0xFEED_FACE_1234_0003);
        let r = rng.next_u128();
        let s = rng.next_u128();

        for &len in &[0usize, 1, 2, 3, 4, 5, 7, 8, 9, 63, 64, 257] {
            let mut words: Vec<u128> = (0..len).map(|_| rng.next_u128()).collect();
            if len >= 3 {
                words[0] = 0;
                words[1] = PRIME_P;
                words[2] = u128::MAX;
            }
            let expected = ref_cw_mac_u128_stream(&words, r, s);
            let actual = cw_mac_u128_stream_4way(&words, r, s);
            assert_eq!(actual, expected, "u128 stream MAC mismatch at len={len}");
        }

        assert_ne!(
            cw_mac_u128_stream_4way(&[], r, s),
            cw_mac_u128_stream_4way(&[0], r, s)
        );
        assert_ne!(
            cw_mac_u128_stream_4way(&[1], r, s),
            cw_mac_u128_stream_4way(&[0, 1], r, s)
        );
    }

    #[test]
    fn test_toeplitz_hash_turbo_matches_scalar_all_sizes_and_backends() {
        let mut rng = TestRng::new(0xABCD_EF01_2345_0004);

        let raw_sizes = [0usize, 1, 63, 64, 65, 128, 511, 512, 513, 1024, 4096];
        let out_sizes = [0usize, 1, 7, 63, 64, 65, 128, 512, 2048];

        for &raw_bits in &raw_sizes {
            let raw_words_len = raw_bits.div_ceil(64);
            let raw: Vec<u64> = (0..raw_words_len).map(|_| rng.next_u64()).collect();

            for &out_bits in &out_sizes {
                let seed_len = toeplitz_seed_words_turbo(raw_bits, out_bits);
                let seed: Vec<u64> = (0..seed_len).map(|_| rng.next_u64()).collect();

                let expected = ref_toeplitz_hash_u64(&raw, raw_bits, &seed, out_bits);

                let actual = toeplitz_hash_turbo(&raw, raw_bits, &seed, out_bits);
                assert_eq!(
                    actual, expected,
                    "toeplitz_hash_turbo mismatch: raw_bits={raw_bits}, out_bits={out_bits}"
                );

                if out_bits > 0 && out_bits % 64 != 0 {
                    let mask = (1u64 << (out_bits % 64)) - 1;
                    assert_eq!(*actual.last().unwrap() & !mask, 0);
                }

                if raw_bits > 0 && out_bits > 0 {
                    let scalar = toeplitz_hash_scalar_4x(&raw, raw_bits, &seed, out_bits);
                    assert_eq!(
                        scalar, expected,
                        "toeplitz scalar_4x mismatch: raw_bits={raw_bits}, out_bits={out_bits}"
                    );

                    #[cfg(target_arch = "x86_64")]
                    {
                        if std::arch::is_x86_feature_detected!("avx2") {
                            let avx2 =
                                unsafe { toeplitz_hash_avx2(&raw, raw_bits, &seed, out_bits) };
                            assert_eq!(
                                avx2, expected,
                                "toeplitz avx2 mismatch: raw_bits={raw_bits}, out_bits={out_bits}"
                            );
                        }
                        if std::arch::is_x86_feature_detected!("avx512f")
                            && std::arch::is_x86_feature_detected!("avx512vpopcntdq")
                        {
                            let avx512 =
                                unsafe { toeplitz_hash_avx512(&raw, raw_bits, &seed, out_bits) };
                            assert_eq!(
                                avx512, expected,
                                "toeplitz avx512 mismatch: raw_bits={raw_bits}, out_bits={out_bits}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_run_turbo_crypto_bench_reports_metrics() {
        let bench = run_turbo_crypto_bench();
        println!("=== Vernam Turbo Crypto Benchmark ===");
        println!("  XOR backend       : {}", bench.xor_backend);
        println!("  XOR throughput    : {:.2} GB/s", bench.xor_gb_per_sec);
        println!("  CW MAC (256B)     : {:.0} ops/s", bench.cw_mac_ops_per_sec);
        println!("  CW MAC (64KiB)    : {:.2} GB/s", bench.cw_mac_gb_per_sec);
        println!("  Toeplitz backend  : {}", bench.toeplitz_backend);
        println!("  Toeplitz PA rate  : {:.2} Mbps", bench.toeplitz_mbps);

        assert!(bench.xor_gb_per_sec > 0.0);
        assert!(bench.cw_mac_ops_per_sec > 0.0);
        assert!(bench.cw_mac_gb_per_sec > 0.0);
        assert!(bench.toeplitz_mbps > 0.0);
        assert!(!bench.xor_backend.is_empty());
        assert!(!bench.toeplitz_backend.is_empty());
    }

    #[test]
    fn test_simd_xor_cw_mac_and_toeplitz_exhaustive_0_to_260_and_unaligned() {
        let mut rng = TestRng::new(0x51AD_F00D_CAFE_9999);

        // 1. Exhaustive OTP XOR across EVERY length 0..=260 + 1025 with unaligned sub-slices.
        let mut extra_lengths: Vec<usize> = (0..=260).collect();
        extra_lengths.push(511);
        extra_lengths.push(512);
        extra_lengths.push(513);
        extra_lengths.push(1025);

        for &len in &extra_lengths {
            let mut data_backing = vec![0u8; len + 16];
            let mut key_backing = vec![0u8; len + 16];
            rng.fill_bytes(&mut data_backing);
            rng.fill_bytes(&mut key_backing);

            for &(d_off, k_off) in &[(0usize, 0usize), (1, 0), (0, 1), (1, 3), (3, 7)] {
                let mut ref_buf = data_backing[d_off..d_off + len].to_vec();
                let key = &key_backing[k_off..k_off + len];
                ref_otp_xor_in_place(&mut ref_buf, key);

                // Test directly on unaligned in-place mutable sub-slice (not a fresh Vec!).
                let mut work_backing = data_backing.clone();
                let unaligned_slice = &mut work_backing[d_off..d_off + len];
                otp_xor_turbo_in_place(unaligned_slice, key);
                assert_eq!(
                    unaligned_slice,
                    ref_buf.as_slice(),
                    "unaligned turbo XOR mismatch len={len} d_off={d_off} k_off={k_off}"
                );
                // Ensure guard bytes immediately before/after sub-slice were never overwritten!
                assert_eq!(&work_backing[..d_off], &data_backing[..d_off]);
                assert_eq!(
                    &work_backing[d_off + len..],
                    &data_backing[d_off + len..]
                );

                // Explicitly test every compiled backend on unaligned sub-slices too.
                let mut sc_backing = data_backing.clone();
                otp_xor_scalar_u64(&mut sc_backing[d_off..d_off + len], key);
                assert_eq!(&sc_backing[d_off..d_off + len], ref_buf.as_slice());

                #[cfg(target_arch = "x86_64")]
                {
                    if std::arch::is_x86_feature_detected!("avx2") {
                        let mut avx2_backing = data_backing.clone();
                        unsafe { otp_xor_avx2(&mut avx2_backing[d_off..d_off + len], key) };
                        assert_eq!(&avx2_backing[d_off..d_off + len], ref_buf.as_slice());
                        assert_eq!(&avx2_backing[..d_off], &data_backing[..d_off]);
                        assert_eq!(
                            &avx2_backing[d_off + len..],
                            &data_backing[d_off + len..]
                        );
                    }
                    if std::arch::is_x86_feature_detected!("avx512f") {
                        let mut avx512_backing = data_backing.clone();
                        unsafe { otp_xor_avx512(&mut avx512_backing[d_off..d_off + len], key) };
                        assert_eq!(&avx512_backing[d_off..d_off + len], ref_buf.as_slice());
                        assert_eq!(&avx512_backing[..d_off], &data_backing[..d_off]);
                        assert_eq!(
                            &avx512_backing[d_off + len..],
                            &data_backing[d_off + len..]
                        );
                    }
                }
            }
        }

        // 2. Exhaustive 4-way Carter-Wegman MAC across EVERY length 0..=260 + unaligned sub-slices.
        let r = rng.next_u128();
        let s = rng.next_u128();
        let fast_key = CwFastKey::new(r, s);
        for len in 0..=260usize {
            let mut backing = vec![0u8; len + 8];
            rng.fill_bytes(&mut backing);
            for off in [0usize, 1, 3] {
                let slice = &backing[off..off + len];
                let expected = ref_carter_wegman_mac(slice, r, s);
                let actual = cw_mac_4way(&fast_key, slice);
                assert_eq!(
                    actual, expected,
                    "cw_mac_4way mismatch len={len} off={off}"
                );
                assert!(fast_key.verify(slice, &actual));
            }
        }

        // 3. Dense Toeplitz differential sweep including odd bit widths and sub-sliced u64 inputs.
        let raw_bit_cases = [1usize, 2, 7, 15, 31, 63, 64, 65, 127, 128, 129, 255, 256, 257, 513];
        let out_bit_cases = [1usize, 2, 7, 63, 64, 65, 127, 128, 129, 257];
        for &rb in &raw_bit_cases {
            let rw = rb.div_ceil(64);
            let raw_backing: Vec<u64> = (0..rw + 3).map(|_| rng.next_u64()).collect();
            for &ob in &out_bit_cases {
                let sw = toeplitz_seed_words_turbo(rb, ob);
                let seed_backing: Vec<u64> = (0..sw + 3).map(|_| rng.next_u64()).collect();
                let raw_sub = &raw_backing[1..1 + rw];
                let seed_sub = &seed_backing[2..2 + sw];

                let expected = ref_toeplitz_hash_u64(raw_sub, rb, seed_sub, ob);
                let actual = toeplitz_hash_turbo(raw_sub, rb, seed_sub, ob);
                assert_eq!(actual, expected, "toeplitz mismatch rb={rb} ob={ob}");

                let scalar = toeplitz_hash_scalar_4x(raw_sub, rb, seed_sub, ob);
                assert_eq!(scalar, expected);

                #[cfg(target_arch = "x86_64")]
                {
                    if std::arch::is_x86_feature_detected!("avx2") {
                        let a2 = unsafe { toeplitz_hash_avx2(raw_sub, rb, seed_sub, ob) };
                        assert_eq!(a2, expected);
                    }
                    if std::arch::is_x86_feature_detected!("avx512f")
                        && std::arch::is_x86_feature_detected!("avx512vpopcntdq")
                    {
                        let a512 = unsafe { toeplitz_hash_avx512(raw_sub, rb, seed_sub, ob) };
                        assert_eq!(a512, expected);
                    }
                }
            }
        }
    }
}
