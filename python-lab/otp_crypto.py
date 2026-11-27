"""Pure One-Time Pad (OTP) encryption and Carter-Wegman one-time MAC.

Both primitives are information-theoretically secure (unconditionally secure,
even against quantum or unbounded adversaries) PROVIDED each PadPage is used
at most once and generated from true randomness.
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import secrets

# Mersenne prime p = 2^127 - 1 for the Carter-Wegman universal hash field F_p.
PRIME_P: int = (1 << 127) - 1
BLOCK_BYTES: int = 15  # 120 bits < 127 bits, so every block is strictly < PRIME_P.
TAG_BYTES: int = 16    # 128-bit encoding of the 127-bit tag.


@dataclass(frozen=True)
class PadPage:
    """A single-use cryptographic page: one XOR encryption pad + one MAC key."""

    page_id: int
    enc_key: bytes
    mac_r: int
    mac_s: int

    @classmethod
    def generate(cls, page_id: int, enc_key_bytes: int = 256) -> "PadPage":
        return cls(
            page_id=page_id,
            enc_key=secrets.token_bytes(enc_key_bytes),
            mac_r=secrets.randbelow(PRIME_P),
            mac_s=secrets.randbelow(PRIME_P),
        )


class PadExhaustedError(RuntimeError):
    """Raised when a wallet or mint runs out of unused one-time pad pages."""


class PadReuseError(RuntimeError):
    """Raised when an already-burned one-time pad page is accessed again."""


class PadBook:
    """Tracks single-use PadPages and enforces strict one-time consumption."""

    def __init__(self, pages: list[PadPage]) -> None:
        self._pages: dict[int, PadPage] = {p.page_id: p for p in pages}
        self._burned: set[int] = set()
        self._next_index: int = 0
        self._ordered_ids: list[int] = [p.page_id for p in pages]

    @classmethod
    def generate_pair(
        cls, num_pages: int = 16, enc_key_bytes: int = 256
    ) -> tuple["PadBook", "PadBook"]:
        """Generate two identical PadBooks (one for Wallet, one for Mint)."""
        pages = [PadPage.generate(i, enc_key_bytes) for i in range(num_pages)]
        return cls(list(pages)), cls(list(pages))

    @property
    def remaining(self) -> int:
        return len(self._pages) - len(self._burned)

    @property
    def next_page_id(self) -> int:
        return (max(self._ordered_ids) + 1) if self._ordered_ids else 0

    def append_pages(self, pages: list[PadPage]) -> None:
        """Append freshly provisioned/QKD-replenished PadPages to this book."""
        for page in pages:
            if page.page_id in self._pages:
                raise PadReuseError(f"Duplicate pad page_id={page.page_id}.")
            self._pages[page.page_id] = page
            self._ordered_ids.append(page.page_id)

    def pop_next(self) -> PadPage:
        """Consume and return the next unused page (Wallet side)."""
        while self._next_index < len(self._ordered_ids):
            pid = self._ordered_ids[self._next_index]
            self._next_index += 1
            if pid not in self._burned:
                self._burned.add(pid)
                return self._pages[pid]
        raise PadExhaustedError("No unused OTP pages remaining in this PadBook.")

    def peek_unused(self, page_id: int) -> PadPage:
        """Inspect a page if it exists and has not yet been burned (Mint side)."""
        if page_id not in self._pages:
            raise KeyError(f"Unknown pad page_id={page_id}.")
        if page_id in self._burned:
            raise PadReuseError(f"Pad page_id={page_id} has already been burned.")
        return self._pages[page_id]

    def burn(self, page_id: int) -> None:
        """Permanently destroy a pad page after use."""
        if page_id in self._burned:
            raise PadReuseError(f"Pad page_id={page_id} is already burned.")
        self._burned.add(page_id)


def otp_xor(data: bytes, key: bytes) -> bytes:
    """Encrypt or decrypt bytes using a strict One-Time Pad XOR."""
    if len(data) > len(key):
        raise ValueError(
            f"Plaintext ({len(data)} bytes) exceeds OTP page size ({len(key)} bytes)."
        )
    return bytes(a ^ b for a, b in zip(data, key))


def carter_wegman_mac(data: bytes, r: int, s: int) -> bytes:
    """Compute an information-theoretic one-time polynomial MAC over F_(2^127 - 1).

    Encoding appends a 0x01 sentinel byte before splitting into 15-byte blocks so
    the highest-degree coefficient is always non-zero (injective mapping from
    arbitrary byte strings to polynomials over F_p).
    """
    framed = data + b"\x01"
    blocks = [
        int.from_bytes(framed[i : i + BLOCK_BYTES], "little")
        for i in range(0, len(framed), BLOCK_BYTES)
    ]

    # Evaluate P(r) = sum_{i=0}^{k-1} blocks[i] * r^(i+1) + s (mod PRIME_P)
    acc = 0
    for blk in reversed(blocks):
        acc = (acc * r + blk) % PRIME_P
    tag_int = (acc * r + s) % PRIME_P
    return tag_int.to_bytes(TAG_BYTES, "big")


def verify_mac(data: bytes, r: int, s: int, expected_tag: bytes) -> bool:
    """Constant-time verification of a Carter-Wegman one-time MAC."""
    computed = carter_wegman_mac(data, r, s)
    return hmac.compare_digest(computed, expected_tag)
