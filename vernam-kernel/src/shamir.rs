//! Fixed-stack, zero-heap Shamir secret sharing, Lagrange interpolation, degree consistency
//! checks, and zero-polynomial Proactive Secret Sharing (PSS) refresh over `F_(2^127 - 1)`.

use crate::field::{add_mod, inv_mod, is_canonical, mul_mod, sub_mod};

/// Maximum fixed-stack committee size supported by the `no_std` kernel.
pub const MAX_COMMITTEE: usize = 32;

/// A validated Shamir share `(x, y)` in `F_(2^127 - 1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share {
    pub x: u64,
    pub y: u128,
}

impl Share {
    /// Construct a validated share (`x >= 1`, `y < PRIME_P`).
    pub const fn new(x: u64, y: u128) -> Result<Self, ShamirError> {
        if x == 0 {
            return Err(ShamirError::InvalidCoordinate);
        }
        if !is_canonical(y) {
            return Err(ShamirError::NonCanonicalElement);
        }
        Ok(Self { x, y })
    }
}

/// Errors produced by Shamir polynomial and Lagrange operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShamirError {
    InvalidThreshold,
    InvalidCoordinate,
    DuplicateCoordinate,
    NonCanonicalElement,
    InsufficientShares,
    TooManyShares,
    ZeroDenominator,
    LengthMismatch,
}

/// Fixed-stack Horner polynomial evaluation `sum_{k=0..d} coeffs[k] * x^k mod PRIME_P`.
pub fn eval_poly(coeffs: &[u128], x: u128) -> Result<u128, ShamirError> {
    if coeffs.is_empty() {
        return Err(ShamirError::InvalidThreshold);
    }
    if !is_canonical(x) {
        return Err(ShamirError::NonCanonicalElement);
    }
    let mut acc = 0u128;
    let mut i = coeffs.len();
    while i > 0 {
        i -= 1;
        let c = coeffs[i];
        if !is_canonical(c) {
            return Err(ShamirError::NonCanonicalElement);
        }
        acc = add_mod(mul_mod(acc, x), c);
    }
    Ok(acc)
}

/// Validate that `shares` has `1..=MAX_COMMITTEE` entries, all canonical, non-zero, and distinct.
pub fn validate_shares(shares: &[Share]) -> Result<(), ShamirError> {
    if shares.is_empty() {
        return Err(ShamirError::InsufficientShares);
    }
    if shares.len() > MAX_COMMITTEE {
        return Err(ShamirError::TooManyShares);
    }
    let mut i = 0usize;
    while i < shares.len() {
        if shares[i].x == 0 {
            return Err(ShamirError::InvalidCoordinate);
        }
        if !is_canonical(shares[i].y) {
            return Err(ShamirError::NonCanonicalElement);
        }
        let mut j = i + 1;
        while j < shares.len() {
            if shares[i].x == shares[j].x {
                return Err(ShamirError::DuplicateCoordinate);
            }
            j += 1;
        }
        i += 1;
    }
    Ok(())
}

/// Evaluate the unique interpolating polynomial passing through `shares` at `target_x`.
pub fn lagrange_eval_at(shares: &[Share], target_x: u128) -> Result<u128, ShamirError> {
    validate_shares(shares)?;
    if !is_canonical(target_x) {
        return Err(ShamirError::NonCanonicalElement);
    }

    let mut acc = 0u128;
    let mut i = 0usize;
    while i < shares.len() {
        let xi = shares[i].x as u128;
        let mut num = 1u128;
        let mut den = 1u128;
        let mut k = 0usize;
        while k < shares.len() {
            if k != i {
                let xk = shares[k].x as u128;
                num = mul_mod(num, sub_mod(target_x, xk));
                den = mul_mod(den, sub_mod(xi, xk));
            }
            k += 1;
        }
        let inv_den = inv_mod(den).ok_or(ShamirError::ZeroDenominator)?;
        let li = mul_mod(num, inv_den);
        acc = add_mod(acc, mul_mod(li, shares[i].y));
        i += 1;
    }
    Ok(acc)
}

/// Reconstruct the secret `f(0)` from the first `threshold` shares via Lagrange interpolation.
pub fn reconstruct_at_zero(shares: &[Share], threshold: usize) -> Result<u128, ShamirError> {
    if threshold == 0 {
        return Err(ShamirError::InvalidThreshold);
    }
    if shares.len() < threshold {
        return Err(ShamirError::InsufficientShares);
    }
    lagrange_eval_at(&shares[..threshold], 0)
}

/// Verify that all `shares` lie on a single polynomial of degree `<= threshold - 1`
/// WITHOUT ever evaluating `f(0)` or reconstructing the secret.
pub fn verify_degree_consistency(shares: &[Share], threshold: usize) -> Result<bool, ShamirError> {
    validate_shares(shares)?;
    if threshold == 0 || threshold > shares.len() {
        return Err(ShamirError::InvalidThreshold);
    }
    let base = &shares[..threshold];
    let mut idx = threshold;
    while idx < shares.len() {
        let predicted = lagrange_eval_at(base, shares[idx].x as u128)?;
        if predicted != shares[idx].y {
            return Ok(false);
        }
        idx += 1;
    }
    Ok(true)
}

/// Zero-polynomial Proactive Secret Sharing (PSS) refresh writing refreshed shares into `out`.
///
/// `zero_poly_higher_coeffs` supplies `[c_1, c_2, ..., c_{t-1}]` for `z(x) = sum_{k=1}^{t-1} c_k x^k`,
/// guaranteeing `z(0) == 0` so the reconstructed secret is preserved while every share is rotated.
pub fn pss_refresh_zero_poly(
    shares: &[Share],
    zero_poly_higher_coeffs: &[u128],
    out: &mut [Share],
) -> Result<(), ShamirError> {
    validate_shares(shares)?;
    if out.len() != shares.len() {
        return Err(ShamirError::LengthMismatch);
    }
    let mut k = 0usize;
    while k < zero_poly_higher_coeffs.len() {
        if !is_canonical(zero_poly_higher_coeffs[k]) {
            return Err(ShamirError::NonCanonicalElement);
        }
        k += 1;
    }

    let mut i = 0usize;
    while i < shares.len() {
        let x = shares[i].x as u128;
        // Evaluate z(x) = x * (c_1 + c_2*x + ... + c_{t-1}*x^{t-2}) via Horner.
        let mut delta = 0u128;
        if !zero_poly_higher_coeffs.is_empty() {
            let inner = eval_poly(zero_poly_higher_coeffs, x)?;
            delta = mul_mod(inner, x);
        }
        out[i] = Share {
            x: shares[i].x,
            y: add_mod(shares[i].y, delta),
        };
        i += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::PRIME_P;

    #[test]
    fn test_shamir_eval_lagrange_degree_check_and_pss_refresh() {
        // Degree-2 polynomial (t=3, N=5): f(x) = 42_000 + 777*x + 9_999*x^2
        let coeffs = [42_000u128, 777, 9_999];
        let mut shares = [Share { x: 1, y: 0 }; 5];
        for i in 0..5 {
            let x = (i + 1) as u64;
            shares[i] = Share::new(x, eval_poly(&coeffs, x as u128).unwrap()).unwrap();
        }

        assert!(verify_degree_consistency(&shares, 3).unwrap());
        assert_eq!(reconstruct_at_zero(&shares, 3).unwrap(), 42_000);
        // Any subset of 3 reconstructs exact secret.
        assert_eq!(reconstruct_at_zero(&[shares[1], shares[3], shares[4]], 3).unwrap(), 42_000);

        // Evaluate at non-zero point x = 10 matches Horner eval_poly.
        assert_eq!(
            lagrange_eval_at(&shares[..3], 10).unwrap(),
            eval_poly(&coeffs, 10).unwrap()
        );

        // Corrupt 1 share -> degree check catches it!
        let mut corrupted = shares;
        corrupted[4].y = add_mod(corrupted[4].y, 1);
        assert!(!verify_degree_consistency(&corrupted, 3).unwrap());

        // Zero-poly PSS refresh preserves f(0) == 42_000 while changing every share!
        let mut refreshed = [Share { x: 1, y: 0 }; 5];
        pss_refresh_zero_poly(&shares, &[123_456, 789_012], &mut refreshed).unwrap();
        assert!(verify_degree_consistency(&refreshed, 3).unwrap());
        assert_eq!(reconstruct_at_zero(&refreshed, 3).unwrap(), 42_000);
        for i in 0..5 {
            assert_ne!(refreshed[i].y, shares[i].y);
        }

        // Reject duplicate coordinate & non-canonical element.
        let dup = [shares[0], shares[0], shares[2]];
        assert_eq!(reconstruct_at_zero(&dup, 3), Err(ShamirError::DuplicateCoordinate));
        assert_eq!(Share::new(1, PRIME_P), Err(ShamirError::NonCanonicalElement));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::field::PRIME_P;

    #[kani::proof]
    fn prove_horner_and_pss_preserve_secret_t2() {
        let s: u128 = kani::any();
        let c1: u128 = kani::any();
        let z1: u128 = kani::any();
        kani::assume(s < PRIME_P && c1 < PRIME_P && z1 < PRIME_P);

        let coeffs = [s, c1];
        let s1 = Share::new(1, eval_poly(&coeffs, 1).unwrap()).unwrap();
        let s2 = Share::new(2, eval_poly(&coeffs, 2).unwrap()).unwrap();
        let s3 = Share::new(3, eval_poly(&coeffs, 3).unwrap()).unwrap();
        let shares = [s1, s2, s3];
        assert!(verify_degree_consistency(&shares, 2).unwrap());

        let mut refreshed = [s1, s2, s3];
        pss_refresh_zero_poly(&shares, &[z1], &mut refreshed).unwrap();
        assert!(verify_degree_consistency(&refreshed, 2).unwrap());
        // Check exact linear combination at 0 for x in {1, 2}: 2*f(1) - f(2) == s.
        let rec = sub_mod(add_mod(refreshed[0].y, refreshed[0].y), refreshed[1].y);
        assert_eq!(rec, s);
    }
}
