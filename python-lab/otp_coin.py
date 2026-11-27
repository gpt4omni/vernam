"""OTPCoin: A basic Mint-verified digital coin using One-Time Pad ciphers.

Design:
- Each wallet shares a pre-distributed PadBook with the Mint.
- Every transfer consumes one fresh PadPage:
    1. Payload JSON is XOR-encrypted with the page's one-time pad (`enc_key`).
    2. Envelope header + ciphertext are authenticated with a one-time
       Carter-Wegman MAC (`mac_r`, `mac_s`) (Encrypt-then-MAC).
- Once accepted by the Mint, that PadPage is permanently burned to prevent
  replay attacks and catastrophic two-time-pad key reuse.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from otp_crypto import (
    PadBook,
    PadReuseError,
    carter_wegman_mac,
    otp_xor,
    verify_mac,
)


class CoinError(Exception):
    """Base error for OTPCoin protocol violations."""


class AuthenticationError(CoinError):
    """Raised when a transaction MAC fails verification."""


class ReplayOrReuseError(CoinError):
    """Raised when a burned OTP page is reused or replayed."""


class InsufficientFundsError(CoinError):
    """Raised when a sender attempts to spend more than their balance."""


class InvalidTransactionError(CoinError):
    """Raised for malformed payloads, invalid amounts, or mismatched senders."""


@dataclass
class TransactionEnvelope:
    """Public wire representation of an OTPCoin transaction."""

    sender: str
    page_id: int
    ciphertext: bytes
    mac_tag: bytes

    def mac_input(self) -> bytes:
        """Canonical byte string authenticated by the one-time MAC."""
        sender_bytes = self.sender.encode("utf-8")
        return (
            len(sender_bytes).to_bytes(2, "big")
            + sender_bytes
            + self.page_id.to_bytes(8, "big")
            + len(self.ciphertext).to_bytes(4, "big")
            + self.ciphertext
        )


@dataclass(frozen=True)
class LedgerEntry:
    """Confirmed transaction recorded in the Mint's append-only ledger."""

    tx_id: int
    sender: str
    recipient: str
    amount: int
    memo: str
    page_id: int


class Wallet:
    """Client wallet holding an address and its one-time PadBook."""

    def __init__(self, address: str, pad_book: PadBook) -> None:
        self.address = address
        self._pad_book = pad_book

    @property
    def remaining_txs(self) -> int:
        return self._pad_book.remaining

    def create_transfer(
        self, recipient: str, amount: int, memo: str = ""
    ) -> TransactionEnvelope:
        """Encrypt and authenticate a transfer using the next unused OTP page."""
        page = self._pad_book.pop_next()
        payload = json.dumps(
            {
                "sender": self.address,
                "recipient": recipient,
                "amount": amount,
                "memo": memo,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        ciphertext = otp_xor(payload, page.enc_key)
        draft = TransactionEnvelope(
            sender=self.address,
            page_id=page.page_id,
            ciphertext=ciphertext,
            mac_tag=b"",
        )
        tag = carter_wegman_mac(draft.mac_input(), page.mac_r, page.mac_s)
        return TransactionEnvelope(
            sender=self.address,
            page_id=page.page_id,
            ciphertext=ciphertext,
            mac_tag=tag,
        )


class Mint:
    """Trusted coin issuer and ledger verifier backed by per-wallet PadBooks."""

    def __init__(self) -> None:
        self._balances: dict[str, int] = {}
        self._pad_books: dict[str, PadBook] = {}
        self._ledger: list[LedgerEntry] = []

    def register_wallet(
        self, address: str, pad_pages: int = 16, enc_key_bytes: int = 256
    ) -> Wallet:
        """Provision a new wallet and share a fresh PadBook with it."""
        if address in self._pad_books:
            raise CoinError(f"Wallet '{address}' is already registered.")
        wallet_book, mint_book = PadBook.generate_pair(pad_pages, enc_key_bytes)
        self._pad_books[address] = mint_book
        self._balances[address] = 0
        return Wallet(address=address, pad_book=wallet_book)

    def mint_coins(self, recipient: str, amount: int) -> LedgerEntry:
        """Issue new test coins into a registered wallet."""
        if recipient not in self._balances:
            raise CoinError(f"Unknown recipient wallet '{recipient}'.")
        if amount <= 0:
            raise InvalidTransactionError("Mint amount must be positive.")
        self._balances[recipient] += amount
        entry = LedgerEntry(
            tx_id=len(self._ledger) + 1,
            sender="MINT",
            recipient=recipient,
            amount=amount,
            memo="genesis/mint",
            page_id=-1,
        )
        self._ledger.append(entry)
        return entry

    def balance_of(self, address: str) -> int:
        if address not in self._balances:
            raise CoinError(f"Unknown wallet '{address}'.")
        return self._balances[address]

    @property
    def ledger(self) -> list[LedgerEntry]:
        return list(self._ledger)

    def submit_transaction(
        self, envelope: TransactionEnvelope, *, require_mac: bool = True
    ) -> LedgerEntry:
        """Verify, decrypt, and settle an OTP-encrypted coin transfer.

        Note: `require_mac=False` exists ONLY for testing/demonstrating why a
        raw One-Time Pad without a MAC is vulnerable to bit-flip malleability!
        """
        if envelope.sender not in self._pad_books:
            raise InvalidTransactionError(f"Unknown sender '{envelope.sender}'.")

        book = self._pad_books[envelope.sender]
        try:
            page = book.peek_unused(envelope.page_id)
        except PadReuseError as exc:
            raise ReplayOrReuseError(str(exc)) from exc
        except KeyError as exc:
            raise InvalidTransactionError(str(exc)) from exc

        # 1. Authenticate ciphertext BEFORE decrypting (Encrypt-then-MAC).
        if require_mac:
            if not verify_mac(
                envelope.mac_input(), page.mac_r, page.mac_s, envelope.mac_tag
            ):
                raise AuthenticationError(
                    "Invalid one-time MAC: transaction was forged or tampered with."
                )
            # Once the MAC is verified, we know the wallet released this page onto
            # the wire. Burn it immediately so even a rejected tx (e.g. overdraft)
            # can never be replayed later once the wallet receives more funds.
            book.burn(envelope.page_id)

        # 2. Decrypt with the one-time XOR pad.
        try:
            plaintext = otp_xor(envelope.ciphertext, page.enc_key)
            tx = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise InvalidTransactionError(
                f"Failed to decode decrypted payload: {exc}"
            ) from exc

        if not isinstance(tx, dict):
            raise InvalidTransactionError("Decoded payload is not a JSON object.")

        sender = tx.get("sender")
        recipient = tx.get("recipient")
        amount = tx.get("amount")
        memo = tx.get("memo", "")

        if sender != envelope.sender:
            raise InvalidTransactionError("Payload sender does not match envelope.")
        if recipient not in self._balances:
            raise InvalidTransactionError(f"Unknown recipient '{recipient}'.")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise InvalidTransactionError("Amount must be a positive integer.")

        # 3. Enforce balance rules and settle.
        if self._balances[sender] < amount:
            raise InsufficientFundsError(
                f"'{sender}' has {self._balances[sender]} coins, tried to spend {amount}."
            )

        if not require_mac:
            book.burn(envelope.page_id)
        self._balances[sender] -= amount
        self._balances[recipient] += amount

        entry = LedgerEntry(
            tx_id=len(self._ledger) + 1,
            sender=sender,
            recipient=recipient,
            amount=amount,
            memo=str(memo),
            page_id=envelope.page_id,
        )
        self._ledger.append(entry)
        return entry
