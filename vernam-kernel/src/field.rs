//! Branchless, panic-free Mersenne prime field `F_(2^127 - 1)` arithmetic (`no_std`, zero `unsafe`).

use core::hint::black_box;
use core::sync::atomic::{Ordering, compiler_fence};

/// Mersenne prime modulus `p = 2^127 - 1`.
pub const PRIME_P: u128 = (1u128 << 127) - 1;

/// Returns `true` iff `x` is a canonical element in `[0, PRIME_P)`.
#[inline(always)]
pub const fn is_canonical(x: u128) -> bool {
    x < PRIME_P
}

/// Branchless reduction of any `u128` modulo `PRIME_P = 2^127 - 1` into `[0, PRIME_P)`.
#[inline(always)]
pub const fn reduce(x: u128) -> u128 {
    let r = (x & PRIME_P) + (x >> 127);
    let carry = (r + 1) >> 127;
    (r + carry) & PRIME_P
}

/// Branchless `(a + b) mod PRIME_P`, exact and overflow-free for all `u128` inputs.
#[inline(always)]
pub const fn add_mod(a: u128, b: u128) -> u128 {
    let (s, c) = a.overflowing_add(b);
    let r = (s & PRIME_P) + (s >> 127) + ((c as u128) << 1);
    let carry = (r + 1) >> 127;
    (r + carry) & PRIME_P
}

/// Branchless `(a - b) mod PRIME_P`, exact and underflow-free for all `u128` inputs.
#[inline(always)]
pub const fn sub_mod(a: u128, b: u128) -> u128 {
    let a = reduce(a);
    let b = reduce(b);
    let r = a + (PRIME_P - b);
    let carry = (r + 1) >> 127;
    (r + carry) & PRIME_P
}

/// Branchless exact `(a * b) mod PRIME_P` without overflow or division.
#[inline(always)]
pub const fn mul_mod(a: u128, b: u128) -> u128 {
    let a = reduce(a);
    let b = reduce(b);

    let a0 = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a1 = a >> 64;
    let b0 = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b1 = b >> 64;

    let lo = a0 * b0;
    let hi = a1 * b1;
    let mid = (a1 * b0) + (a0 * b1);

    let s1 = (lo & PRIME_P) + (hi << 1);
    let s2 = ((mid & ((1u128 << 63) - 1)) << 64) + (mid >> 63) + (lo >> 127);

    let u = (s1 & PRIME_P) + (s2 & PRIME_P) + (s1 >> 127) + (s2 >> 127);
    reduce(u)
}

/// Branchless constant-time select: returns `a` if `cond != 0`, else `b`.
#[inline(always)]
pub const fn ct_select_u128(cond: u128, a: u128, b: u128) -> u128 {
    let is_nonzero = (cond | cond.wrapping_neg()) >> 127;
    let mask = 0u128.wrapping_sub(is_nonzero);
    (a & mask) | (b & !mask)
}

/// Constant-time equality comparison for two `u128` values.
#[inline(never)]
pub fn ct_eq_u128(a: u128, b: u128) -> bool {
    let diff = black_box(black_box(a) ^ black_box(b));
    let is_nonzero = (diff | diff.wrapping_neg()) >> 127;
    compiler_fence(Ordering::SeqCst);
    black_box(is_nonzero) == 0
}

/// Constant-time 16-byte tag equality comparison resistant to compiler short-circuiting.
#[inline(never)]
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    let mut i = 0;
    while i < 16 {
        let av = black_box(a[i]);
        let bv = black_box(b[i]);
        diff = black_box(diff | (av ^ bv));
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
    black_box(diff) == 0
}

/// Constant-time modular exponentiation `base^exp mod PRIME_P` (fixed 128-step ladder).
pub const fn pow_mod(mut base: u128, mut exp: u128) -> u128 {
    let mut result = 1u128;
    base = reduce(base);
    let mut i = 0u32;
    while i < 128 {
        let prod = mul_mod(result, base);
        result = ct_select_u128(exp & 1, prod, result);
        base = mul_mod(base, base);
        exp >>= 1;
        i += 1;
    }
    result
}

/// Panic-free multiplicative inverse `a^(-1) mod PRIME_P` via Fermat's Little Theorem.
/// Returns `None` iff `a === 0 (mod PRIME_P)`.
#[inline]
pub const fn inv_mod(a: u128) -> Option<u128> {
    let r = reduce(a);
    if r == 0 {
        None
    } else {
        Some(pow_mod(r, PRIME_P - 2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_identities_and_boundaries() {
        assert_eq!(reduce(0), 0);
        assert_eq!(reduce(PRIME_P), 0);
        assert_eq!(reduce(PRIME_P + 7), 7);
        assert_eq!(reduce(u128::MAX), 1);
        assert_eq!(add_mod(PRIME_P - 1, 2), 1);
        assert_eq!(add_mod(u128::MAX, u128::MAX), 2);
        assert_eq!(sub_mod(1, 2), PRIME_P - 1);
        assert_eq!(mul_mod(PRIME_P - 1, PRIME_P - 1), 1);
        assert_eq!(mul_mod(1u128 << 64, 1u128 << 63), 1);
        assert_eq!(inv_mod(0), None);
        assert_eq!(inv_mod(PRIME_P), None);

        let samples = [1u128, 2, 3, 7, 1u128 << 64, PRIME_P - 1, PRIME_P - 42];
        for &a in &samples {
            let inv = inv_mod(a).unwrap();
            assert!(is_canonical(inv));
            assert_eq!(mul_mod(a, inv), 1);
            assert!(ct_eq_u128(a, a));
            assert!(!ct_eq_u128(a, a ^ 1));
            assert_eq!(ct_select_u128(0, a, 99), 99);
            assert_eq!(ct_select_u128(5, a, 99), a);
            let ab = a.to_le_bytes();
            let mut flipped = ab;
            flipped[15] ^= 0x80;
            assert!(ct_eq_16(&ab, &ab));
            assert!(!ct_eq_16(&ab, &flipped));
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn prove_field_ops_canonical_and_panic_free() {
        let a: u128 = kani::any();
        let b: u128 = kani::any();
        let ra = reduce(a);
        let rb = reduce(b);
        assert!(ra < PRIME_P);
        assert!(rb < PRIME_P);
        let sum = add_mod(a, b);
        assert!(sum < PRIME_P);
        let diff = sub_mod(sum, b);
        assert_eq!(diff, ra);
        let prod = mul_mod(a, b);
        assert!(prod < PRIME_P);
        assert_eq!(prod, mul_mod(b, a));
    }

    #[kani::proof]
    fn prove_ct_select_exact() {
        let cond: u128 = kani::any();
        let a: u128 = kani::any();
        let b: u128 = kani::any();
        let out = ct_select_u128(cond, a, b);
        if cond == 0 {
            assert_eq!(out, b);
        } else {
            assert_eq!(out, a);
        }
    }
}
