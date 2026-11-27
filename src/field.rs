//! Ultra-fast Mersenne prime field F_(2^127 - 1), OS entropy, and memory zeroization.
//!
//! Zero external crates, zero computational crypto (no SHA-256/RSA/ECDSA/AES).

use std::fs::File;
use std::io::Read;
use std::sync::atomic::{Ordering, compiler_fence};

/// Mersenne prime p = 2^127 - 1.
pub const PRIME_P: u128 = (1u128 << 127) - 1;

/// Reduce a u128 value modulo PRIME_P = 2^127 - 1 using bitshifts (no division).
#[inline(always)]
pub const fn reduce(x: u128) -> u128 {
    let r = (x & PRIME_P) + (x >> 127);
    if r >= PRIME_P { r - PRIME_P } else { r }
}

/// (a + b) mod PRIME_P for a, b < PRIME_P.
#[inline(always)]
pub const fn add_mod(a: u128, b: u128) -> u128 {
    let s = a + b;
    let r = (s & PRIME_P) + (s >> 127);
    if r >= PRIME_P { r - PRIME_P } else { r }
}

/// (a - b) mod PRIME_P for a, b < PRIME_P.
#[inline(always)]
pub const fn sub_mod(a: u128, b: u128) -> u128 {
    if a >= b { a - b } else { PRIME_P - (b - a) }
}

/// Exact (a * b) mod (2^127 - 1) without overflow or division.
#[inline(always)]
pub const fn mul_mod(a: u128, b: u128) -> u128 {
    let a = reduce(a);
    let b = reduce(b);

    let a0 = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a1 = a >> 64; // <= 63 bits
    let b0 = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b1 = b >> 64; // <= 63 bits

    let lo = a0 * b0; // <= 128 bits
    let hi = a1 * b1; // <= 126 bits -> hi * 2^128 === hi * 2 (mod P)
    let mid = (a1 * b0) + (a0 * b1); // <= 128 bits (no overflow since a1,b1 < 2^63)

    let mid_lo = mid & ((1u128 << 63) - 1); // 63 bits -> mid_lo << 64 < 2^127
    let mid_hi = mid >> 63; // <= 65 bits -> mid_hi * 2^127 === mid_hi (mod P)

    let t0 = reduce(lo);
    let t1 = reduce(hi << 1);
    let t2 = reduce(mid_lo << 64);
    let t3 = reduce(mid_hi);

    add_mod(add_mod(t0, t1), add_mod(t2, t3))
}

/// Modular exponentiation base^exp mod PRIME_P.
pub const fn pow_mod(mut base: u128, mut exp: u128) -> u128 {
    let mut result = 1u128;
    base = reduce(base);
    while exp > 0 {
        if (exp & 1) == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        exp >>= 1;
    }
    result
}

/// Multiplicative inverse a^(-1) mod PRIME_P via Fermat's Little Theorem.
#[inline]
pub const fn inv_mod(a: u128) -> u128 {
    assert!(a % PRIME_P != 0, "cannot invert 0 in F_p");
    pow_mod(a, PRIME_P - 2)
}

/// Volatile memory wipe preventing the compiler from optimizing away key zeroing.
#[inline(never)]
pub fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: b is a valid mutable reference to an initialized byte.
        unsafe { std::ptr::write_volatile(b, 0u8) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Volatile wipe for a u128 secret.
#[inline(never)]
pub fn zeroize_u128(val: &mut u128) {
    // SAFETY: val is a valid mutable reference.
    unsafe { std::ptr::write_volatile(val, 0u128) };
    compiler_fence(Ordering::SeqCst);
}

/// Constant-time 16-byte tag comparison.
#[inline(never)]
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    compiler_fence(Ordering::SeqCst);
    diff == 0
}

/// Fill buffer with OS cryptographic randomness (/dev/urandom).
pub fn fill_os_random(buf: &mut [u8]) {
    let mut f = File::open("/dev/urandom").expect("failed to open /dev/urandom");
    f.read_exact(buf).expect("failed to read from /dev/urandom");
}

/// Uniform random element in [0, PRIME_P) using rejection sampling (zero modulo bias).
pub fn random_field_elem() -> u128 {
    let mut bytes = [0u8; 16];
    loop {
        fill_os_random(&mut bytes);
        let v = u128::from_le_bytes(bytes) & PRIME_P;
        if v < PRIME_P {
            zeroize_slice(&mut bytes);
            return v;
        }
    }
}

/// Uniform random non-zero element in [1, PRIME_P) using rejection sampling.
pub fn random_nonzero_field_elem() -> u128 {
    loop {
        let v = random_field_elem();
        if v != 0 {
            return v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mersenne_field_identities() {
        assert_eq!(reduce(PRIME_P), 0);
        assert_eq!(reduce(PRIME_P + 5), 5);
        assert_eq!(add_mod(PRIME_P - 1, 2), 1);
        assert_eq!(sub_mod(1, 2), PRIME_P - 1);

        // (P - 1) * (P - 1) === (-1)*(-1) === 1 (mod P)
        assert_eq!(mul_mod(PRIME_P - 1, PRIME_P - 1), 1);
        assert_eq!(mul_mod(1u128 << 64, 1u128 << 63), 1);

        for _ in 0..100 {
            let a = random_field_elem();
            if a == 0 {
                continue;
            }
            let inv = inv_mod(a);
            assert_eq!(mul_mod(a, inv), 1);
        }
    }
}
