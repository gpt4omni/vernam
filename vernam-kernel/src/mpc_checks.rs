//! Pure information-theoretic MPC verification primitives over `F_(2^127 - 1)`:
//! - Schwartz-Zippel Random Linear Combination (RLC)
//! - Blinded `[rho] * [Z]` zero-check
//! - `BeaverSquare` and `BeaverTriple` algebraic verification and local share arithmetic.

use crate::field::{add_mod, ct_eq_u128, is_canonical, mul_mod};

/// Errors produced by MPC algebraic and zero-check primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcCheckError {
    NonCanonicalElement,
    EmptyChecks,
    ZeroBlinder,
    AlgebraicMismatch,
}

/// Single-use Beaver Square `(a, a_sq)` satisfying `a * a == a_sq (mod PRIME_P)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaverSquare {
    pub a: u128,
    pub a_sq: u128,
}

impl BeaverSquare {
    /// Verify that `a`, `a_sq` are canonical and satisfy `a^2 == a_sq (mod PRIME_P)`.
    pub const fn verify_algebraic(&self) -> Result<(), MpcCheckError> {
        if !is_canonical(self.a) || !is_canonical(self.a_sq) {
            return Err(MpcCheckError::NonCanonicalElement);
        }
        if mul_mod(self.a, self.a) != self.a_sq {
            return Err(MpcCheckError::AlgebraicMismatch);
        }
        Ok(())
    }

    /// Compute the local Shamir share of `x^2` given the publicly opened `d = x - a`:
    ///
    /// `[x^2]_i = [a^2]_i + 2 * d * [a]_i + d^2 (mod PRIME_P)`
    pub const fn local_square_share(&self, d_open: u128) -> Result<u128, MpcCheckError> {
        if !is_canonical(self.a) || !is_canonical(self.a_sq) || !is_canonical(d_open) {
            return Err(MpcCheckError::NonCanonicalElement);
        }
        let two_d = add_mod(d_open, d_open);
        let lin = mul_mod(two_d, self.a);
        let d_sq = mul_mod(d_open, d_open);
        Ok(add_mod(add_mod(self.a_sq, lin), d_sq))
    }
}

/// Single-use Beaver Multiplication Triple `(a, b, c)` satisfying `a * b == c (mod PRIME_P)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaverTriple {
    pub a: u128,
    pub b: u128,
    pub c: u128,
}

impl BeaverTriple {
    /// Verify that `(a, b, c)` are canonical and satisfy `a * b == c (mod PRIME_P)`.
    pub const fn verify_algebraic(&self) -> Result<(), MpcCheckError> {
        if !is_canonical(self.a) || !is_canonical(self.b) || !is_canonical(self.c) {
            return Err(MpcCheckError::NonCanonicalElement);
        }
        if mul_mod(self.a, self.b) != self.c {
            return Err(MpcCheckError::AlgebraicMismatch);
        }
        Ok(())
    }

    /// Compute the local Shamir share of `x * y` given opened `alpha = x - a`, `beta = y - b`:
    ///
    /// `[x * y]_i = [c]_i + alpha * [b]_i + beta * [a]_i + alpha * beta (mod PRIME_P)`
    pub const fn local_mul_share(
        &self,
        alpha_open: u128,
        beta_open: u128,
    ) -> Result<u128, MpcCheckError> {
        if !is_canonical(self.a)
            || !is_canonical(self.b)
            || !is_canonical(self.c)
            || !is_canonical(alpha_open)
            || !is_canonical(beta_open)
        {
            return Err(MpcCheckError::NonCanonicalElement);
        }
        let t1 = mul_mod(alpha_open, self.b);
        let t2 = mul_mod(beta_open, self.a);
        let t3 = mul_mod(alpha_open, beta_open);
        Ok(add_mod(add_mod(self.c, t1), add_mod(t2, t3)))
    }
}

/// Fold a vector of constraint residuals `[r_0, r_1, ..., r_{m-1}]` into a single Schwartz-Zippel
/// Random Linear Combination `Z = sum_{i=0}^{m-1} r_i * gamma^i (mod PRIME_P)`.
///
/// Any non-zero residual vector escapes detection with probability at most `(m - 1) / (2^127 - 1)`.
pub fn schwartz_zippel_rlc(residuals: &[u128], gamma: u128) -> Result<u128, MpcCheckError> {
    if residuals.is_empty() {
        return Err(MpcCheckError::EmptyChecks);
    }
    if !is_canonical(gamma) {
        return Err(MpcCheckError::NonCanonicalElement);
    }
    let mut acc = 0u128;
    let mut power = 1u128;
    let mut i = 0usize;
    while i < residuals.len() {
        let r = residuals[i];
        if !is_canonical(r) {
            return Err(MpcCheckError::NonCanonicalElement);
        }
        acc = add_mod(acc, mul_mod(r, power));
        power = mul_mod(power, gamma);
        i += 1;
    }
    Ok(acc)
}

/// Evaluate the blinded zero-check `Z_blind = rho * Z (mod PRIME_P)` in constant time.
///
/// Rejects `rho == 0` (`ZeroBlinder`) so a zero blinder can never mask a non-zero residual `Z`.
/// Returns `Ok(true)` iff `Z_blind == 0` (which implies `Z == 0` because `F_(2^127 - 1)` is a field).
pub fn blinded_zero_check(rho: u128, z: u128) -> Result<bool, MpcCheckError> {
    if !is_canonical(rho) || !is_canonical(z) {
        return Err(MpcCheckError::NonCanonicalElement);
    }
    if rho == 0 {
        return Err(MpcCheckError::ZeroBlinder);
    }
    let z_blind = mul_mod(rho, z);
    Ok(ct_eq_u128(z_blind, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{PRIME_P, sub_mod};

    #[test]
    fn test_schwartz_zippel_blinded_check_and_beaver_algebra() {
        let gamma = 0x1234_5678_9ABC_DEF0u128;
        let zeros = [0u128; 8];
        let z_ok = schwartz_zippel_rlc(&zeros, gamma).unwrap();
        assert_eq!(z_ok, 0);
        assert!(blinded_zero_check(777, z_ok).unwrap());
        assert_eq!(blinded_zero_check(0, z_ok), Err(MpcCheckError::ZeroBlinder));

        let mut bad = zeros;
        bad[5] = 1;
        let z_bad = schwartz_zippel_rlc(&bad, gamma).unwrap();
        assert_ne!(z_bad, 0);
        assert!(!blinded_zero_check(777, z_bad).unwrap());

        // BeaverSquare verification & exact local squaring of x = 12345.
        let a = 999u128;
        let sq = BeaverSquare { a, a_sq: mul_mod(a, a) };
        assert!(sq.verify_algebraic().is_ok());
        let x = 12_345u128;
        let d = sub_mod(x, a);
        assert_eq!(sq.local_square_share(d).unwrap(), mul_mod(x, x));

        let bad_sq = BeaverSquare { a, a_sq: add_mod(sq.a_sq, 1) };
        assert_eq!(bad_sq.verify_algebraic(), Err(MpcCheckError::AlgebraicMismatch));

        // BeaverTriple verification & exact local multiplication of x * y.
        let b = 333u128;
        let triple = BeaverTriple { a, b, c: mul_mod(a, b) };
        assert!(triple.verify_algebraic().is_ok());
        let y = 67_890u128;
        let alpha = sub_mod(x, a);
        let beta = sub_mod(y, b);
        assert_eq!(triple.local_mul_share(alpha, beta).unwrap(), mul_mod(x, y));

        let bad_triple = BeaverTriple { a, b, c: PRIME_P };
        assert_eq!(bad_triple.verify_algebraic(), Err(MpcCheckError::NonCanonicalElement));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::field::{PRIME_P, sub_mod};

    #[kani::proof]
    fn prove_beaver_square_and_triple_exact() {
        let a: u128 = kani::any();
        let b: u128 = kani::any();
        let x: u128 = kani::any();
        let y: u128 = kani::any();
        kani::assume(a < PRIME_P && b < PRIME_P && x < PRIME_P && y < PRIME_P);

        let sq = BeaverSquare { a, a_sq: mul_mod(a, a) };
        assert!(sq.verify_algebraic().is_ok());
        assert_eq!(sq.local_square_share(sub_mod(x, a)).unwrap(), mul_mod(x, x));

        let tr = BeaverTriple { a, b, c: mul_mod(a, b) };
        assert!(tr.verify_algebraic().is_ok());
        assert_eq!(
            tr.local_mul_share(sub_mod(x, a), sub_mod(y, b)).unwrap(),
            mul_mod(x, y)
        );
    }

    #[kani::proof]
    fn prove_blinded_zero_check_soundness() {
        let rho: u128 = kani::any();
        let z: u128 = kani::any();
        kani::assume(rho > 0 && rho < PRIME_P && z < PRIME_P);
        let is_zero = blinded_zero_check(rho, z).unwrap();
        assert_eq!(is_zero, z == 0);
    }
}
