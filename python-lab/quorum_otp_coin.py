"""QuorumOTPCoin: Decentralized, 100% Information-Theoretically Secure Coin.

Zero computational assumptions (NO SHA-256, NO RSA, NO ECDSA, NO AES):
- Uses ONLY One-Time Pads (XOR) + Carter-Wegman One-Time MACs over F_(2^127 - 1).
- Fixed-size 256-byte OTP frames ensure Shannon perfect secrecy on every wire
  (even message lengths are hidden from an omnipotent eavesdropper!).
- Decentralized across N independent validators (N = 3f + 1, default N=4, f=1,
  quorum = 3):
    * No single trusted Mint: each wallet shares a DIFFERENT PadBook with each
      validator, so a compromised validator cannot forge transactions.
    * Pairwise validator PadBooks encrypt and authenticate all consensus votes.
    * Survives up to f offline or malicious validators.
    * Blocks double-spends / equivocation (conflicting txs cannot reach quorum).
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

FRAME_BYTES = 256


class QuorumCoinError(Exception):
    """Base error for QuorumOTPCoin protocol violations."""


class QuorumAuthError(QuorumCoinError):
    """Raised when a one-time Carter-Wegman MAC fails verification."""


class QuorumReplayError(QuorumCoinError):
    """Raised when a burned OTP page is reused or replayed."""


class QuorumConsensusError(QuorumCoinError):
    """Raised when a transaction fails to reach validator quorum."""


def encode_fixed_frame(payload: bytes, frame_size: int = FRAME_BYTES) -> bytes:
    """Pack arbitrary payload into a fixed-size frame to hide plaintext length."""
    if len(payload) + 2 > frame_size:
        raise ValueError(
            f"Payload ({len(payload)} bytes) exceeds max frame capacity ({frame_size - 2} bytes)."
        )
    length_prefix = len(payload).to_bytes(2, "big")
    padding = b"\x00" * (frame_size - 2 - len(payload))
    return length_prefix + payload + padding


def decode_fixed_frame(frame: bytes) -> bytes:
    """Unpack a fixed-size OTP frame back into the original payload."""
    if len(frame) != FRAME_BYTES:
        raise ValueError(f"Expected {FRAME_BYTES}-byte frame, got {len(frame)} bytes.")
    length = int.from_bytes(frame[:2], "big")
    if length > FRAME_BYTES - 2:
        raise ValueError("Corrupted frame length.")
    return frame[2 : 2 + length]


@dataclass(frozen=True)
class CanonicalTx:
    sender: str
    recipient: str
    amount: int
    page_id: int
    memo: str = ""

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "sender": self.sender,
                "recipient": self.recipient,
                "amount": self.amount,
                "page_id": self.page_id,
                "memo": self.memo,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "CanonicalTx":
        obj = json.loads(raw.decode("utf-8"))
        return cls(
            sender=obj["sender"],
            recipient=obj["recipient"],
            amount=obj["amount"],
            page_id=obj["page_id"],
            memo=obj.get("memo", ""),
        )


@dataclass(frozen=True)
class WireEnvelope:
    """Fixed-length OTP ciphertext + Carter-Wegman one-time MAC sent over the wire."""

    src: str
    dst: str
    page_id: int
    ciphertext: bytes  # Always exactly FRAME_BYTES (256 bytes)
    mac_tag: bytes     # Always 16 bytes (Carter-Wegman tag over F_(2^127-1))

    def mac_input(self) -> bytes:
        src_b = self.src.encode("utf-8")
        dst_b = self.dst.encode("utf-8")
        return (
            len(src_b).to_bytes(2, "big")
            + src_b
            + len(dst_b).to_bytes(2, "big")
            + dst_b
            + self.page_id.to_bytes(8, "big")
            + self.ciphertext
        )


@dataclass(frozen=True)
class QuorumLedgerEntry:
    tx_index: int
    tx: CanonicalTx
    approving_validators: tuple[str, ...]


def _encrypt_envelope(
    src: str, dst: str, book: PadBook, payload: bytes
) -> WireEnvelope:
    page = book.pop_next()
    frame = encode_fixed_frame(payload)
    ciphertext = otp_xor(frame, page.enc_key)
    draft = WireEnvelope(
        src=src, dst=dst, page_id=page.page_id, ciphertext=ciphertext, mac_tag=b""
    )
    tag = carter_wegman_mac(draft.mac_input(), page.mac_r, page.mac_s)
    return WireEnvelope(
        src=src, dst=dst, page_id=page.page_id, ciphertext=ciphertext, mac_tag=tag
    )


def _decrypt_envelope(envelope: WireEnvelope, book: PadBook) -> bytes:
    try:
        page = book.peek_unused(envelope.page_id)
    except PadReuseError as exc:
        raise QuorumReplayError(str(exc)) from exc
    except KeyError as exc:
        raise QuorumAuthError(str(exc)) from exc

    if len(envelope.ciphertext) != FRAME_BYTES:
        raise QuorumAuthError("Invalid fixed-frame ciphertext length.")

    # Encrypt-then-MAC: verify information-theoretic tag BEFORE decrypting.
    if not verify_mac(envelope.mac_input(), page.mac_r, page.mac_s, envelope.mac_tag):
        raise QuorumAuthError(
            f"MAC verification failed on link {envelope.src} -> {envelope.dst} (page {envelope.page_id})."
        )

    # Burn page immediately once authenticated to forbid replays.
    book.burn(envelope.page_id)
    frame = otp_xor(envelope.ciphertext, page.enc_key)
    return decode_fixed_frame(frame)


class QuorumWallet:
    """Wallet holding an independent one-time PadBook per validator."""

    def __init__(self, address: str, validator_books: dict[str, PadBook]) -> None:
        self.address = address
        self._books = validator_books

    @property
    def remaining_txs(self) -> int:
        return min(book.remaining for book in self._books.values())

    def create_transfer_bundle(
        self, recipient: str, amount: int, memo: str = ""
    ) -> dict[str, WireEnvelope]:
        """Encrypt the same transfer separately for every validator using its own OTP."""
        bundle: dict[str, WireEnvelope] = {}
        for vid, book in self._books.items():
            # Peek next page id implicitly by popping inside _encrypt_envelope;
            # keep page_id synchronized across all validator books.
            page = book.pop_next()
            tx = CanonicalTx(
                sender=self.address,
                recipient=recipient,
                amount=amount,
                page_id=page.page_id,
                memo=memo,
            )
            frame = encode_fixed_frame(tx.to_bytes())
            ct = otp_xor(frame, page.enc_key)
            draft = WireEnvelope(
                src=self.address,
                dst=vid,
                page_id=page.page_id,
                ciphertext=ct,
                mac_tag=b"",
            )
            tag = carter_wegman_mac(draft.mac_input(), page.mac_r, page.mac_s)
            bundle[vid] = WireEnvelope(
                src=self.address,
                dst=vid,
                page_id=page.page_id,
                ciphertext=ct,
                mac_tag=tag,
            )
        return bundle

    def create_for_validator(
        self, validator_id: str, recipient: str, amount: int, memo: str = ""
    ) -> WireEnvelope:
        """Create a single validator envelope (used to test equivocation attacks)."""
        book = self._books[validator_id]
        page = book.pop_next()
        tx = CanonicalTx(
            sender=self.address,
            recipient=recipient,
            amount=amount,
            page_id=page.page_id,
            memo=memo,
        )
        frame = encode_fixed_frame(tx.to_bytes())
        ct = otp_xor(frame, page.enc_key)
        draft = WireEnvelope(
            src=self.address,
            dst=validator_id,
            page_id=page.page_id,
            ciphertext=ct,
            mac_tag=b"",
        )
        tag = carter_wegman_mac(draft.mac_input(), page.mac_r, page.mac_s)
        return WireEnvelope(
            src=self.address,
            dst=validator_id,
            page_id=page.page_id,
            ciphertext=ct,
            mac_tag=tag,
        )


class ValidatorNode:
    """Independent validator holding per-wallet and pairwise-peer OTP PadBooks."""

    def __init__(self, validator_id: str, quorum_size: int) -> None:
        self.validator_id = validator_id
        self.quorum_size = quorum_size
        self.online = True
        self.balances: dict[str, int] = {}
        self.ledger: list[QuorumLedgerEntry] = []
        self._wallet_books: dict[str, PadBook] = {}
        self._peer_out_books: dict[str, PadBook] = {}
        self._peer_in_books: dict[str, PadBook] = {}
        # Votes indexed by canonical tx bytes -> set of voting validator IDs
        self._votes: dict[bytes, set[str]] = {}
        self._committed_txs: set[bytes] = set()

    def register_wallet_book(self, address: str, book: PadBook) -> None:
        self._wallet_books[address] = book
        self.balances[address] = 0

    def register_peer_out(self, peer_id: str, out_book: PadBook) -> None:
        self._peer_out_books[peer_id] = out_book

    def register_peer_in(self, peer_id: str, in_book: PadBook) -> None:
        self._peer_in_books[peer_id] = in_book

    def genesis_credit(self, address: str, amount: int) -> None:
        self.balances[address] += amount

    def verify_client_envelope(self, envelope: WireEnvelope) -> CanonicalTx:
        """Authenticate & decrypt a wallet's OTP envelope and check local rules."""
        if envelope.dst != self.validator_id:
            raise QuorumAuthError("Envelope addressed to a different validator.")
        if envelope.src not in self._wallet_books:
            raise QuorumAuthError(f"Unknown wallet '{envelope.src}'.")

        raw = _decrypt_envelope(envelope, self._wallet_books[envelope.src])
        tx = CanonicalTx.from_bytes(raw)

        if tx.sender != envelope.src or tx.page_id != envelope.page_id:
            raise QuorumAuthError("Decrypted payload metadata mismatch.")
        if tx.recipient not in self.balances:
            raise QuorumCoinError(f"Unknown recipient '{tx.recipient}'.")
        if not isinstance(tx.amount, int) or isinstance(tx.amount, bool) or tx.amount <= 0:
            raise QuorumCoinError("Transfer amount must be a positive integer.")
        if self.balances[tx.sender] < tx.amount:
            raise QuorumCoinError(
                f"Insufficient funds on {self.validator_id}: "
                f"{tx.sender} has {self.balances[tx.sender]}, needs {tx.amount}."
            )

        # Record own vote for this exact canonical tx.
        tx_bytes = tx.to_bytes()
        self._votes.setdefault(tx_bytes, set()).add(self.validator_id)
        return tx

    def send_vote_to_peer(self, peer_id: str, tx: CanonicalTx) -> WireEnvelope:
        """Encrypt & authenticate this validator's vote using the pairwise OTP link."""
        return _encrypt_envelope(
            self.validator_id, peer_id, self._peer_out_books[peer_id], tx.to_bytes()
        )

    def receive_peer_vote(self, vote_env: WireEnvelope) -> CanonicalTx:
        """Verify & decrypt a peer validator's OTP vote."""
        if vote_env.dst != self.validator_id:
            raise QuorumAuthError("Vote addressed to a different validator.")
        if vote_env.src not in self._peer_in_books:
            raise QuorumAuthError(f"Unknown peer validator '{vote_env.src}'.")

        raw = _decrypt_envelope(vote_env, self._peer_in_books[vote_env.src])
        tx = CanonicalTx.from_bytes(raw)
        tx_bytes = tx.to_bytes()
        self._votes.setdefault(tx_bytes, set()).add(vote_env.src)
        return tx

    def try_commit(self, tx: CanonicalTx) -> QuorumLedgerEntry | None:
        """Commit a transaction ONLY if >= quorum_size validators authenticated it."""
        tx_bytes = tx.to_bytes()
        if tx_bytes in self._committed_txs:
            return None

        voters = self._votes.get(tx_bytes, set())
        # Safety: this validator must have verified the tx itself AND reached quorum.
        if self.validator_id not in voters or len(voters) < self.quorum_size:
            return None

        if self.balances[tx.sender] < tx.amount:
            return None

        self._committed_txs.add(tx_bytes)
        self.balances[tx.sender] -= tx.amount
        self.balances[tx.recipient] += tx.amount
        entry = QuorumLedgerEntry(
            tx_index=len(self.ledger) + 1,
            tx=tx,
            approving_validators=tuple(sorted(voters)),
        )
        self.ledger.append(entry)
        return entry


class QuorumNetwork:
    """Decentralized N-validator network (N = 3f + 1, quorum = 2f + 1) using pure OTP."""

    def __init__(
        self,
        num_validators: int = 4,
        peer_pad_pages: int = 64,
    ) -> None:
        if num_validators < 4:
            raise ValueError("Need at least 4 validators (N = 3f + 1) for BFT quorum.")
        self.f = (num_validators - 1) // 3
        self.quorum_size = 2 * self.f + 1
        self.validators: dict[str, ValidatorNode] = {
            f"V{i}": ValidatorNode(f"V{i}", quorum_size=self.quorum_size)
            for i in range(num_validators)
        }
        # Provision directional pairwise OTP PadBooks between every pair of validators.
        vids = list(self.validators.keys())
        for src in vids:
            for dst in vids:
                if src == dst:
                    continue
                out_book, in_book = PadBook.generate_pair(
                    num_pages=peer_pad_pages, enc_key_bytes=FRAME_BYTES
                )
                self.validators[src].register_peer_out(dst, out_book)
                self.validators[dst].register_peer_in(src, in_book)

        # Records every WireEnvelope transmitted on the network (for eavesdropper tests).
        self.wire_transcript: list[WireEnvelope] = []

    def register_wallet(self, address: str, pad_pages: int = 16) -> QuorumWallet:
        """Provision independent PadBooks between a new wallet and every validator."""
        wallet_books: dict[str, PadBook] = {}
        for vid, node in self.validators.items():
            w_book, v_book = PadBook.generate_pair(
                num_pages=pad_pages, enc_key_bytes=FRAME_BYTES
            )
            wallet_books[vid] = w_book
            node.register_wallet_book(address, v_book)
        return QuorumWallet(address=address, validator_books=wallet_books)

    def genesis_mint(self, address: str, amount: int) -> None:
        for node in self.validators.values():
            node.genesis_credit(address, amount)

    def broadcast_bundle(
        self,
        bundle: dict[str, WireEnvelope],
        *,
        forged_validator_votes: dict[str, CanonicalTx] | None = None,
    ) -> list[tuple[str, QuorumLedgerEntry]]:
        """Deliver wallet envelopes to online validators and run OTP peer voting."""
        verified_by_node: dict[str, CanonicalTx] = {}

        # Phase 1: Online validators independently verify their own OTP+MAC envelope.
        for vid, node in self.validators.items():
            if not node.online or vid not in bundle:
                continue
            env = bundle[vid]
            self.wire_transcript.append(env)
            try:
                verified_by_node[vid] = node.verify_client_envelope(env)
            except QuorumCoinError:
                continue

        # Optional Byzantine simulation: a compromised validator votes for a forged tx!
        if forged_validator_votes:
            for bad_vid, fake_tx in forged_validator_votes.items():
                if self.validators[bad_vid].online:
                    verified_by_node[bad_vid] = fake_tx

        # Phase 2: Validators exchange votes over pairwise OTP-encrypted channels.
        for src_id, tx in verified_by_node.items():
            src_node = self.validators[src_id]
            for dst_id, dst_node in self.validators.items():
                if src_id == dst_id or not dst_node.online:
                    continue
                vote_env = src_node.send_vote_to_peer(dst_id, tx)
                self.wire_transcript.append(vote_env)
                dst_node.receive_peer_vote(vote_env)

        # Phase 3: Each online validator commits ONLY if quorum (2f + 1) agreed.
        commits: list[tuple[str, QuorumLedgerEntry]] = []
        for vid, tx in verified_by_node.items():
            entry = self.validators[vid].try_commit(tx)
            if entry is not None:
                commits.append((vid, entry))

        if len(commits) < self.quorum_size:
            raise QuorumConsensusError(
                f"Failed to reach quorum ({len(commits)}/{self.quorum_size} commits)."
            )
        return commits
