//! Ultra-fast Mersenne prime field F_(2^127 - 1), OS entropy, and memory zeroization.
//!
//! Zero external crates, zero computational crypto (no SHA-256/RSA/ECDSA/AES).

use std::fs::File;
use std::io::Read;
use std::sync::atomic::{Ordering, compiler_fence};

/// Mersenne prime p = 2^127 - 1.
pub const PRIME_P: u128 = (1u128 << 127) - 1;

/// Reduce any `u128` value modulo `PRIME_P = 2^127 - 1` into canonical `[0, PRIME_P)`.
///
/// Completely branchless and division-free across all `u128` inputs (`0..=u128::MAX`).
#[inline(always)]
pub const fn reduce(x: u128) -> u128 {
    // x = (x & P) + (x >> 127) * 2^127 === (x & P) + (x >> 127) (mod P).
    // Maximum value of `r` is (2^127 - 1) + 1 = 2^127.
    let r = (x & PRIME_P) + (x >> 127);
    // `carry` is 1 iff r >= PRIME_P (i.e. r == 2^127 - 1 or r == 2^127), else 0.
    let carry = (r + 1) >> 127;
    (r + carry) & PRIME_P
}

/// Branchless `(a + b) mod PRIME_P` returning a canonical element in `[0, PRIME_P)`.
///
/// Exact and overflow-free across all `u128` inputs (`0..=u128::MAX`).
#[inline(always)]
pub const fn add_mod(a: u128, b: u128) -> u128 {
    // Actual sum is `s + c * 2^128 === (s & P) + (s >> 127) + 2 * c (mod P)`.
    // Maximum value of `r` is (2^127 - 1) + 1 + 2 = 2^127 + 2 < 2 * PRIME_P.
    let (s, c) = a.overflowing_add(b);
    let r = (s & PRIME_P) + (s >> 127) + ((c as u128) << 1);
    let carry = (r + 1) >> 127;
    (r + carry) & PRIME_P
}

/// Branchless `(a - b) mod PRIME_P` returning a canonical element in `[0, PRIME_P)`.
///
/// Exact and underflow-free across all `u128` inputs (`0..=u128::MAX`).
#[inline(always)]
pub const fn sub_mod(a: u128, b: u128) -> u128 {
    let a = reduce(a);
    let b = reduce(b);
    // Since 0 <= a, b < PRIME_P: `r = a + (PRIME_P - b)` lies in [1, 2 * PRIME_P - 1]
    // with zero overflow and zero borrow.
    let r = a + (PRIME_P - b);
    let carry = (r + 1) >> 127;
    (r + carry) & PRIME_P
}

/// Branchless exact `(a * b) mod (2^127 - 1)` without overflow or division.
///
/// Exact across all `u128` inputs (`0..=u128::MAX`).
#[inline(always)]
pub const fn mul_mod(a: u128, b: u128) -> u128 {
    let a = reduce(a);
    let b = reduce(b);

    let a0 = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a1 = a >> 64; // <= 63 bits
    let b0 = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b1 = b >> 64; // <= 63 bits

    let lo = a0 * b0; // <= 2^128 - 2^65 + 1
    let hi = a1 * b1; // <= 2^126 - 2^64 + 1 -> hi * 2^128 === hi << 1 (mod P)
    let mid = (a1 * b0) + (a0 * b1); // <= 2^128 - 3*2^64 + 2 (no overflow)

    let s1 = (lo & PRIME_P) + (hi << 1); // <= 2^128 - 2^65 + 1 < 2^128
    let s2 = ((mid & ((1u128 << 63) - 1)) << 64) + (mid >> 63) + (lo >> 127); // <= 2^127 + 2^64 - 5

    // Guaranteed u <= 2^128 - 2 in all cases.
    let u = (s1 & PRIME_P) + (s2 & PRIME_P) + (s1 >> 127) + (s2 >> 127);
    reduce(u)
}

/// Branchless constant-time selection: returns `a` if `cond != 0`, otherwise `b`.
#[inline(always)]
pub const fn ct_select_u128(cond: u128, a: u128, b: u128) -> u128 {
    let is_nonzero = (cond | cond.wrapping_neg()) >> 127;
    let mask = 0u128.wrapping_sub(is_nonzero);
    (a & mask) | (b & !mask)
}

/// Constant-time equality comparison for two `u128` values.
#[inline(never)]
pub fn ct_eq_u128(a: u128, b: u128) -> bool {
    let diff = core::hint::black_box(core::hint::black_box(a) ^ core::hint::black_box(b));
    let is_nonzero = (diff | diff.wrapping_neg()) >> 127;
    compiler_fence(Ordering::SeqCst);
    core::hint::black_box(is_nonzero) == 0
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

/// Multiplicative inverse `a^(-1) mod PRIME_P` via Fermat's Little Theorem.
#[inline]
pub const fn inv_mod(a: u128) -> u128 {
    assert!(reduce(a) != 0, "cannot invert 0 in F_p");
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

/// Constant-time 16-byte tag comparison resistant to LLVM short-circuiting.
#[inline(never)]
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        let av = core::hint::black_box(a[i]);
        let bv = core::hint::black_box(b[i]);
        diff = core::hint::black_box(diff | (av ^ bv));
    }
    compiler_fence(Ordering::SeqCst);
    core::hint::black_box(diff) == 0
}

/// Fill buffer with OS cryptographic randomness (/dev/urandom).
pub fn fill_os_random(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
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

    /// Independent 256-bit schoolbook reference math for differential testing against `field.rs`.
    /// Represents a 256-bit unsigned integer as `[w0, w1, w2, w3]` in little-endian 64-bit limbs.
    fn ref_reduce_u128(x: u128) -> u128 {
        x % PRIME_P
    }

    fn ref_add_u128(a: u128, b: u128) -> u128 {
        let ra = a % PRIME_P;
        let rb = b % PRIME_P;
        let (sum, carry) = ra.overflowing_add(rb);
        // Since ra, rb < 2^127 - 1, sum < 2^128 - 2, carry is always false.
        debug_assert!(!carry);
        sum % PRIME_P
    }

    fn ref_sub_u128(a: u128, b: u128) -> u128 {
        let ra = a % PRIME_P;
        let rb = b % PRIME_P;
        if ra >= rb {
            ra - rb
        } else {
            PRIME_P - (rb - ra)
        }
    }

    fn ref_mul_u128(a: u128, b: u128) -> u128 {
        // Exact 256-bit product modulo P = 2^127 - 1 via bit-by-bit shift-and-add (zero shared code).
        let mut x = a % PRIME_P;
        let mut y = b % PRIME_P;
        let mut acc: u128 = 0;
        while y > 0 {
            if (y & 1) == 1 {
                acc = (acc + x) % PRIME_P;
            }
            x = (x + x) % PRIME_P;
            y >>= 1;
        }
        acc
    }

    fn ref_pow_u128(base: u128, mut exp: u128) -> u128 {
        let mut res = 1u128;
        let mut b = base % PRIME_P;
        while exp > 0 {
            if (exp & 1) == 1 {
                res = ref_mul_u128(res, b);
            }
            b = ref_mul_u128(b, b);
            exp >>= 1;
        }
        res
    }

    struct DetRng(u64);
    impl DetRng {
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
    }

    #[test]
    fn test_branchless_field_differential_boundaries_and_10k_fuzz() {
        let boundaries: [u128; 16] = [
            0,
            1,
            2,
            3,
            (1u128 << 63) - 1,
            1u128 << 63,
            (1u128 << 64) - 1,
            1u128 << 64,
            PRIME_P - 2,
            PRIME_P - 1,
            PRIME_P,
            PRIME_P + 1,
            PRIME_P + 2,
            2 * PRIME_P - 1,
            2 * PRIME_P,
            u128::MAX,
        ];

        for &a in &boundaries {
            let r = reduce(a);
            assert!(r < PRIME_P, "reduce({a:#x}) not canonical");
            assert_eq!(r, ref_reduce_u128(a), "reduce mismatch for {a:#x}");
            if r != 0 {
                let inv = inv_mod(a);
                assert!(inv < PRIME_P);
                assert_eq!(mul_mod(a, inv), 1, "inv_mod failed for {a:#x}");
            }

            for &b in &boundaries {
                let s = add_mod(a, b);
                assert!(s < PRIME_P);
                assert_eq!(s, ref_add_u128(a, b), "add_mod mismatch ({a:#x}, {b:#x})");

                let d = sub_mod(a, b);
                assert!(d < PRIME_P);
                assert_eq!(d, ref_sub_u128(a, b), "sub_mod mismatch ({a:#x}, {b:#x})");
                assert_eq!(add_mod(d, b), reduce(a), "sub/add inverse failed");

                let p = mul_mod(a, b);
                assert!(p < PRIME_P);
                assert_eq!(p, ref_mul_u128(a, b), "mul_mod mismatch ({a:#x}, {b:#x})");
            }
        }

        // 10,000 deterministic random pairs covering full u128 space (including >= PRIME_P).
        let mut rng = DetRng::new(0xF1E1_D5AF_E000_0001);
        for _ in 0..10_000 {
            let a = rng.next_u128();
            let b = rng.next_u128();

            let ra = reduce(a);
            assert!(ra < PRIME_P);
            assert_eq!(ra, ref_reduce_u128(a));

            let s = add_mod(a, b);
            assert!(s < PRIME_P);
            assert_eq!(s, ref_add_u128(a, b));

            let d = sub_mod(a, b);
            assert!(d < PRIME_P);
            assert_eq!(d, ref_sub_u128(a, b));

            let p = mul_mod(a, b);
            assert!(p < PRIME_P);
            assert_eq!(p, ref_mul_u128(a, b));
        }

        // Verify constant-time pow_mod against reference on edge and random exponents.
        for &(base, exp) in &[
            (0u128, 0u128),
            (0, 1),
            (1, 0),
            (PRIME_P, 5),
            (PRIME_P - 1, 2),
            (PRIME_P - 1, 3),
            (u128::MAX, u128::MAX),
            (42, PRIME_P - 1),
        ] {
            assert_eq!(pow_mod(base, exp), ref_pow_u128(base, exp));
        }
        for _ in 0..256 {
            let base = rng.next_u128();
            let exp = rng.next_u128();
            assert_eq!(pow_mod(base, exp), ref_pow_u128(base, exp));
        }

        // Verify ct_eq_u128, ct_select_u128, and ct_eq_16 across edge cases.
        for &v in &boundaries {
            assert!(ct_eq_u128(v, v));
            assert!(!ct_eq_u128(v, v ^ 1));
            assert!(!ct_eq_u128(v, v ^ (1u128 << 127)));
            assert_eq!(ct_select_u128(0, v, v.wrapping_add(7)), v.wrapping_add(7));
            assert_eq!(ct_select_u128(1, v, v.wrapping_add(7)), v);
            assert_eq!(ct_select_u128(u128::MAX, v, v.wrapping_add(7)), v);
            assert_eq!(ct_select_u128(1u128 << 127, v, v.wrapping_add(7)), v);
            let bytes = v.to_be_bytes();
            assert!(ct_eq_16(&bytes, &bytes));
            for bit in 0..128 {
                let mut flipped = bytes;
                flipped[bit / 8] ^= 1u8 << (bit % 8);
                assert!(!ct_eq_16(&bytes, &flipped));
            }
        }
    }
}
