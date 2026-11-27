"""Lamport One-Time Signatures (OTS) using SHA-256.

Lamport OTS brings the 'use each key strictly once' principle to decentralized
public-key authentication:
- Private key: 256 pairs of 32-byte random secrets.
- Public key:  256 pairs of SHA-256 hashes of those secrets.
- Address:     SHA-256 hash of the serialized public key (compact 32-byte ID).
- Signature:   For each bit i of SHA-256(message), reveal secret[i][bit_i].

Anyone can verify the signature against the public address without knowing the
private key — and security relies only on SHA-256 preimage resistance (quantum-
resistant), provided each keypair signs AT MOST ONE message.
"""

from __future__ import annotations

import hashlib
import secrets


class OneTimeKeyReuseError(RuntimeError):
    """Raised when attempting to sign a second message with a spent Lamport key."""


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _message_bits(message: bytes) -> list[int]:
    digest = sha256(message)
    bits: list[int] = []
    for byte in digest:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def public_key_to_address(public_key: list[tuple[bytes, bytes]]) -> str:
    """Hash a 256-pair Lamport public key into a compact hex address."""
    if len(public_key) != 256:
        raise ValueError("Lamport public key must contain exactly 256 pairs.")
    h = hashlib.sha256()
    for p0, p1 in public_key:
        h.update(p0)
        h.update(p1)
    return h.hexdigest()


class LamportKeyPair:
    """Single-use Lamport signature keypair."""

    def __init__(
        self,
        private_key: list[tuple[bytes, bytes]],
        public_key: list[tuple[bytes, bytes]],
    ) -> None:
        self._private_key = private_key
        self.public_key = public_key
        self.address = public_key_to_address(public_key)
        self.used = False

    @classmethod
    def generate(cls) -> "LamportKeyPair":
        priv: list[tuple[bytes, bytes]] = []
        pub: list[tuple[bytes, bytes]] = []
        for _ in range(256):
            s0 = secrets.token_bytes(32)
            s1 = secrets.token_bytes(32)
            priv.append((s0, s1))
            pub.append((sha256(s0), sha256(s1)))
        return cls(priv, pub)

    def sign(self, message: bytes, *, allow_unsafe_reuse: bool = False) -> list[bytes]:
        """Sign a message once by revealing 256 private preimages."""
        if self.used and not allow_unsafe_reuse:
            raise OneTimeKeyReuseError(
                f"Lamport key for address {self.address[:12]}... was already used!"
            )
        self.used = True
        bits = _message_bits(message)
        return [self._private_key[i][bit] for i, bit in enumerate(bits)]


def verify_lamport_signature(
    message: bytes,
    expected_address: str,
    public_key: list[tuple[bytes, bytes]],
    signature: list[bytes],
) -> bool:
    """Publicly verify a Lamport one-time signature against an address."""
    if len(public_key) != 256 or len(signature) != 256:
        return False
    if public_key_to_address(public_key) != expected_address:
        return False
    bits = _message_bits(message)
    for i, bit in enumerate(bits):
        if sha256(signature[i]) != public_key[i][bit]:
            return False
    return True
