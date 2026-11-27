"""Shamir's Secret Sharing (SSS) + Proactive Secret Sharing (PSS) over F_(2^127 - 1).

Provides 100% information-theoretic threshold custody and time-resilience:
- SSS: Splits a secret across n validators with threshold t. Any (t - 1) shares
  reveal mathematically ZERO bits about the secret (even to infinite compute).
- PSS: Periodically refreshes every validator's share using random zero-constant
  polynomials (z_j(0) = 0) distributed over pairwise OTP channels. The underlying
  secret never changes and is never reconstructed during refresh, yet any old
  shares stolen in prior epochs become mathematically useless against a slow-bleed
  ('mobile') adversary.
"""

from __future__ import annotations

import secrets

from otp_crypto import PRIME_P


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial sum(coeffs[k] * x^k) mod PRIME_P via Horner's rule."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % PRIME_P
    return acc


def split_secret(
    secret: int, threshold: int, num_shares: int
) -> dict[int, int]:
    """Split an integer secret in [0, PRIME_P) into n shares with threshold t."""
    if not (0 <= secret < PRIME_P):
        raise ValueError("Secret must be in [0, 2^127 - 1).")
    if not (2 <= threshold <= num_shares):
        raise ValueError("Require 2 <= threshold <= num_shares.")

    # f(x) = secret + a_1*x + ... + a_{t-1}*x^{t-1} mod PRIME_P
    coeffs = [secret] + [secrets.randbelow(PRIME_P) for _ in range(threshold - 1)]
    return {x: _eval_poly(coeffs, x) for x in range(1, num_shares + 1)}


def reconstruct_secret(shares: dict[int, int]) -> int:
    """Reconstruct f(0) from t or more (x, y) shares via Lagrange interpolation."""
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to interpolate.")

    xs = list(shares.keys())
    secret = 0
    for i, x_i in enumerate(xs):
        y_i = shares[x_i]
        num = 1
        den = 1
        for j, x_j in enumerate(xs):
            if i == j:
                continue
            num = (num * (-x_j)) % PRIME_P
            den = (den * (x_i - x_j)) % PRIME_P
        lagrange_coeff = (num * pow(den, -1, PRIME_P)) % PRIME_P
        secret = (secret + y_i * lagrange_coeff) % PRIME_P
    return secret


def generate_zero_refresh_deltas(
    threshold: int, participant_ids: list[int]
) -> dict[int, int]:
    """Generate one participant's random zero-constant polynomial evaluations z(x).

    Because z(0) = 0, adding z(i) to share i shifts the polynomial randomly without
    changing the secret f(0)!
    """
    coeffs = [0] + [secrets.randbelow(PRIME_P) for _ in range(threshold - 1)]
    return {pid: _eval_poly(coeffs, pid) for pid in participant_ids}
