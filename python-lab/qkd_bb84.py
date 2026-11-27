"""Simulated BB84 Quantum Key Distribution (QKD) + Toeplitz Privacy Amplification.

Models the Layer-1 key replenishment engine from Kiktenko et al.'s
'Quantum-secured blockchain' (2018):
1. Photon transmission in conjugate bases (+ rectilinear, x diagonal).
2. Sifting over a classical channel (authenticated by existing OTP+MAC keys).
3. QBER (Quantum Bit Error Rate) eavesdropper detection: aborts immediately if
   QBER > MAX_QBER (11% Shor-Preskill threshold for BB84).
4. Toeplitz universal hashing over GF(2) for information-theoretic privacy
   amplification (stripping residual eavesdropper mutual information).

Uses ZERO computational crypto (no SHA-256/AES/RSA).
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets

from otp_crypto import PRIME_P, PadPage

MAX_QBER: float = 0.11  # Shor-Preskill BB84 security threshold (~11%)


class EavesdropperDetectedError(RuntimeError):
    """Raised when BB84 QBER exceeds the security threshold (Eve detected!)."""


@dataclass(frozen=True)
class QKDSessionReport:
    photons_sent: int
    sifted_bits: int
    sample_size: int
    qber: float
    amplified_bytes: int
    pages_generated: int


def toeplitz_hash_bits(raw_bits: int, raw_len: int, out_bits: int, seed: int) -> bytes:
    """2-universal Toeplitz matrix hash over GF(2): maps raw_len bits -> out_bits.

    seed must be an integer of (raw_len + out_bits - 1) uniformly random bits.
    For any x != x', Pr[T*x == T*x'] = 2^(-out_bits) unconditionally.
    """
    mask = (1 << raw_len) - 1
    out_int = 0
    for i in range(out_bits):
        row = (seed >> i) & mask
        bit = (raw_bits & row).bit_count() & 1
        out_int = (out_int << 1) | bit
    out_bytes = (out_bits + 7) // 8
    return out_int.to_bytes(out_bytes, "big")


def run_bb84_key_exchange(
    output_bytes: int,
    *,
    eve_intercept_rate: float = 0.0,
    channel_noise: float = 0.0,
    max_qber: float = MAX_QBER,
) -> tuple[bytes, bytes, QKDSessionReport]:
    """Run a simulated BB84 QKD session + QBER check + Toeplitz privacy amplification.

    Returns (alice_key, bob_key, report) or raises EavesdropperDetectedError.
    """
    out_bits = output_bytes * 8
    # Privacy amplification compression factor (~1.5x raw bits) + QBER sample (~256 bits).
    sample_size = 256
    needed_sifted = int(out_bits * 1.5) + sample_size
    # Bases match ~50% of the time; send ~2.3x needed_sifted photons for margin.
    num_photons = int(needed_sifted * 2.3)

    alice_sifted: list[int] = []
    bob_sifted: list[int] = []

    # Generate random bitstreams in bulk via CSPRNG for speed.
    a_bits_int = secrets.randbits(num_photons)
    a_bases_int = secrets.randbits(num_photons)
    b_bases_int = secrets.randbits(num_photons)
    e_bases_int = secrets.randbits(num_photons) if eve_intercept_rate > 0 else 0

    for i in range(num_photons):
        a_bit = (a_bits_int >> i) & 1
        a_basis = (a_bases_int >> i) & 1
        b_basis = (b_bases_int >> i) & 1

        photon_bit = a_bit
        photon_basis = a_basis

        # Simulate Eve's intercept-resend attack (destroys state when basis differs!)
        if eve_intercept_rate > 0.0:
            if eve_intercept_rate >= 1.0 or (secrets.randbelow(10_000) / 10_000.0) < eve_intercept_rate:
                e_basis = (e_bases_int >> i) & 1
                if e_basis != photon_basis:
                    photon_bit = secrets.randbits(1)
                    photon_basis = e_basis

        # Bob measures in b_basis
        if b_basis == photon_basis:
            b_bit = photon_bit
        else:
            b_bit = secrets.randbits(1)

        if channel_noise > 0.0 and (secrets.randbelow(10_000) / 10_000.0) < channel_noise:
            b_bit ^= 1

        # Sifting: keep only photons where Alice & Bob chose the same basis.
        if a_basis == b_basis:
            alice_sifted.append(a_bit)
            bob_sifted.append(b_bit)

    if len(alice_sifted) < sample_size + out_bits:
        raise RuntimeError("Insufficient sifted bits generated; retry BB84 session.")

    # QBER check: publicly compare a random subset of sifted positions and discard them.
    total_sifted = len(alice_sifted)
    indices = list(range(total_sifted))
    # Fisher-Yates sample of sample_size indices using secrets
    sample_indices: set[int] = set()
    for step in range(sample_size):
        pick = step + secrets.randbelow(total_sifted - step)
        indices[step], indices[pick] = indices[pick], indices[step]
        sample_indices.add(indices[step])

    errors = sum(
        1 for idx in sample_indices if alice_sifted[idx] != bob_sifted[idx]
    )
    qber = errors / sample_size

    if qber > max_qber:
        raise EavesdropperDetectedError(
            f"BB84 QKD ABORTED: QBER={qber:.2%} exceeds max threshold {max_qber:.0%} "
            f"(active eavesdropping or channel tampering detected!)."
        )

    # Discard sampled bits; pack remaining reconciled bits for Toeplitz amplification.
    # (In a noisy clean channel, Cascade/LDPC error reconciliation runs here before PA.)
    rem_a = 0
    rem_b = 0
    raw_len = 0
    for idx in range(total_sifted):
        if idx in sample_indices:
            continue
        rem_a = (rem_a << 1) | alice_sifted[idx]
        rem_b = (rem_b << 1) | bob_sifted[idx]
        raw_len += 1

    # Toeplitz universal hash privacy amplification (public random seed).
    seed = secrets.randbits(raw_len + out_bits - 1)
    alice_key = toeplitz_hash_bits(rem_a, raw_len, out_bits, seed)
    bob_key = toeplitz_hash_bits(rem_b, raw_len, out_bits, seed)

    report = QKDSessionReport(
        photons_sent=num_photons,
        sifted_bits=total_sifted,
        sample_size=sample_size,
        qber=qber,
        amplified_bytes=output_bytes,
        pages_generated=0,
    )
    return alice_key, bob_key, report


def _bytes_to_pad_pages(
    key_material: bytes,
    start_page_id: int,
    num_pages: int,
    enc_key_bytes: int = 256,
) -> list[PadPage]:
    """Slice purified QKD key material into PadPages (enc_key + mac_r + mac_s)."""
    page_stride = enc_key_bytes + 32  # 256B OTP + 16B mac_r + 16B mac_s
    if len(key_material) < num_pages * page_stride:
        raise ValueError("Insufficient QKD key material for requested PadPages.")
    pages: list[PadPage] = []
    offset = 0
    for i in range(num_pages):
        enc_key = key_material[offset : offset + enc_key_bytes]
        offset += enc_key_bytes
        mac_r = int.from_bytes(key_material[offset : offset + 16], "big") % PRIME_P
        offset += 16
        mac_s = int.from_bytes(key_material[offset : offset + 16], "big") % PRIME_P
        offset += 16
        pages.append(
            PadPage(
                page_id=start_page_id + i,
                enc_key=enc_key,
                mac_r=mac_r,
                mac_s=mac_s,
            )
        )
    return pages


def replenish_pad_pages_qkd(
    start_page_id: int,
    num_pages: int = 4,
    enc_key_bytes: int = 256,
    *,
    eve_intercept_rate: float = 0.0,
) -> tuple[list[PadPage], list[PadPage], QKDSessionReport]:
    """Generate matching fresh PadPage batches for two parties via BB84 QKD."""
    needed_bytes = num_pages * (enc_key_bytes + 32)
    alice_bytes, bob_bytes, base_report = run_bb84_key_exchange(
        needed_bytes, eve_intercept_rate=eve_intercept_rate
    )
    alice_pages = _bytes_to_pad_pages(
        alice_bytes, start_page_id, num_pages, enc_key_bytes
    )
    bob_pages = _bytes_to_pad_pages(
        bob_bytes, start_page_id, num_pages, enc_key_bytes
    )
    report = QKDSessionReport(
        photons_sent=base_report.photons_sent,
        sifted_bits=base_report.sifted_bits,
        sample_size=base_report.sample_size,
        qber=base_report.qber,
        amplified_bytes=base_report.amplified_bytes,
        pages_generated=num_pages,
    )
    return alice_pages, bob_pages, report
