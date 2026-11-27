"""FutureOTPCoin v2: Research-Backed, Future-Resistant Pure-OTP Coin.

Combines four information-theoretic pillars (ZERO SHA-256/RSA/ECDSA/AES):
1. Pure OTP (fixed 256-byte frames) + Carter-Wegman One-Time MACs on every link
   -> Shannon perfect secrecy + unconditional authentication.
2. Decentralized N = 3f + 1 BFT Validator Quorum (default 4 nodes, quorum 3)
   -> No single point of trust; resists compromised/offline nodes & double-spends.
3. Authenticated BB84 QKD + Toeplitz Universal Hash Pad Replenishment
   -> Solves OTP key exhaustion while physically detecting eavesdroppers via QBER.
4. Shamir Secret-Shared Cold Vaults + Proactive Secret Sharing (PSS) Epoch Refresh
   -> Splits long-term vault custody keys across validators and refreshes shares
      over pairwise OTP links each epoch to defeat slow-bleed compromise over time.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from otp_crypto import (
    PRIME_P,
    PadBook,
    carter_wegman_mac,
    otp_xor,
    verify_mac,
)
from proactive_sss import (
    generate_zero_refresh_deltas,
    reconstruct_secret,
    split_secret,
)
from qkd_bb84 import QKDSessionReport, replenish_pad_pages_qkd
from quorum_otp_coin import (
    FRAME_BYTES,
    CanonicalTx,
    QuorumCoinError,
    QuorumConsensusError,
    QuorumLedgerEntry,
    QuorumNetwork,
    QuorumWallet,
    ValidatorNode,
    WireEnvelope,
    _decrypt_envelope,
    _encrypt_envelope,
)


@dataclass(frozen=True)
class VaultRecord:
    vault_id: str
    owner: str
    locked_amount: int
    epoch: int


class FutureValidatorNode(ValidatorNode):
    """Validator extended with QKD key replenishment, PSS vault shares, and MAC-chained blocks."""

    def __init__(self, validator_id: str, numeric_id: int, quorum_size: int) -> None:
        super().__init__(validator_id, quorum_size)
        self.numeric_id = numeric_id
        # Secret-shared cold vaults: vault_id -> (VaultRecord, Shamir share y_i)
        self._vaults: dict[str, VaultRecord] = {}
        self._vault_shares: dict[str, int] = {}
        # Information-theoretic integrity chain: each entry's Carter-Wegman MAC chains
        # the previous tag + current ledger entry using a DEDICATED single-use local pad
        # (never reusing any client MAC key!).
        self.chain_tags: list[bytes] = [b"\x00" * 16]
        self._seal_book, _ = PadBook.generate_pair(num_pages=64, enc_key_bytes=16)

    def store_vault_share(self, record: VaultRecord, share_y: int) -> None:
        if self.balances.get(record.owner, 0) < record.locked_amount:
            raise QuorumCoinError(
                f"Insufficient balance on {self.validator_id} to lock vault {record.vault_id}."
            )
        self.balances[record.owner] -= record.locked_amount
        self._vaults[record.vault_id] = record
        self._vault_shares[record.vault_id] = share_y

    def get_vault_share(self, vault_id: str) -> int:
        return self._vault_shares[vault_id]

    def get_vault_epoch(self, vault_id: str) -> int:
        return self._vaults[vault_id].epoch

    def apply_pss_refresh(self, vault_id: str, deltas: list[int]) -> int:
        """Apply zero-polynomial refresh deltas and advance the vault's epoch."""
        new_share = (self._vault_shares[vault_id] + sum(deltas)) % PRIME_P
        self._vault_shares[vault_id] = new_share
        old = self._vaults[vault_id]
        self._vaults[vault_id] = VaultRecord(
            vault_id=old.vault_id,
            owner=old.owner,
            locked_amount=old.locked_amount,
            epoch=old.epoch + 1,
        )
        return new_share

    def release_vault(self, vault_id: str) -> int:
        record = self._vaults.pop(vault_id)
        self._vault_shares.pop(vault_id)
        self.balances[record.owner] += record.locked_amount
        return record.locked_amount

    def try_commit(self, tx: CanonicalTx) -> QuorumLedgerEntry | None:
        entry = super().try_commit(tx)
        if entry is not None:
            # Chain this validator's local ledger with a dedicated single-use
            # Carter-Wegman MAC key (strictly one-time, zero key reuse!).
            if self._seal_book.remaining == 0:
                extra, _ = PadBook.generate_pair(num_pages=64, enc_key_bytes=16)
                start_id = self._seal_book.next_page_id
                reindexed = [
                    type(p)(start_id + idx, p.enc_key, p.mac_r, p.mac_s)
                    for idx, p in enumerate(extra._pages.values())
                ]
                self._seal_book.append_pages(reindexed)
            seal_page = self._seal_book.pop_next()
            prev_tag = self.chain_tags[-1]
            seal_input = prev_tag + tx.to_bytes()
            new_tag = carter_wegman_mac(seal_input, seal_page.mac_r, seal_page.mac_s)
            self.chain_tags.append(new_tag)
        return entry


class FutureOTPNetwork(QuorumNetwork):
    """Future-resistant OTP Coin network with BB84 QKD replenishment & Proactive SSS."""

    def __init__(
        self,
        num_validators: int = 4,
        peer_pad_pages: int = 32,
        auto_qkd_refill: bool = True,
        qkd_refill_batch: int = 4,
    ) -> None:
        if num_validators < 4:
            raise ValueError("Need at least 4 validators (N = 3f + 1) for BFT quorum.")
        self.f = (num_validators - 1) // 3
        self.quorum_size = 2 * self.f + 1
        self.auto_qkd_refill = auto_qkd_refill
        self.qkd_refill_batch = qkd_refill_batch
        self.qkd_reports: list[QKDSessionReport] = []

        self.validators: dict[str, FutureValidatorNode] = {
            f"V{i}": FutureValidatorNode(
                f"V{i}", numeric_id=i + 1, quorum_size=self.quorum_size
            )
            for i in range(num_validators)
        }

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

        self.wire_transcript: list[WireEnvelope] = []

    def replenish_wallet_via_qkd(
        self,
        wallet: QuorumWallet,
        num_pages: int = 4,
        *,
        eve_intercept_rate: float = 0.0,
    ) -> list[QKDSessionReport]:
        """Replenish a wallet's PadBooks across all validators using authenticated BB84 QKD.

        Consumes 1 existing OTP+MAC page per link to authenticate the classical QKD
        sifting handshake (preventing quantum MITM) and generates `num_pages` fresh
        pages (net positive key expansion when num_pages > 1!).
        """
        reports: list[QKDSessionReport] = []
        for vid, node in self.validators.items():
            w_book = wallet._books[vid]
            v_book = node._wallet_books[wallet.address]

            # 1. Authenticate the QKD replenishment request using 1 existing OTP+MAC page.
            auth_payload = json.dumps(
                {"action": "qkd_refill", "wallet": wallet.address, "count": num_pages},
                separators=(",", ":"),
            ).encode("utf-8")
            auth_env = _encrypt_envelope(wallet.address, vid, w_book, auth_payload)
            self.wire_transcript.append(auth_env)
            _decrypt_envelope(auth_env, v_book)

            # 2. Run BB84 photon exchange + QBER eavesdropper check + Toeplitz PA.
            start_id = max(w_book.next_page_id, v_book.next_page_id)
            w_pages, v_pages, report = replenish_pad_pages_qkd(
                start_page_id=start_id,
                num_pages=num_pages,
                enc_key_bytes=FRAME_BYTES,
                eve_intercept_rate=eve_intercept_rate,
            )
            w_book.append_pages(w_pages)
            v_book.append_pages(v_pages)
            reports.append(report)
            self.qkd_reports.append(report)
        return reports

    def send_transfer(
        self,
        wallet: QuorumWallet,
        recipient: str,
        amount: int,
        memo: str = "",
        *,
        eve_intercept_rate: float = 0.0,
    ) -> list[tuple[str, QuorumLedgerEntry]]:
        """Send a transfer, automatically triggering BB84 QKD refill when only 1 page remains."""
        # Reserve the final page to authenticate the next QKD refill handshake!
        if self.auto_qkd_refill and wallet.remaining_txs <= 1:
            self.replenish_wallet_via_qkd(
                wallet,
                num_pages=self.qkd_refill_batch,
                eve_intercept_rate=eve_intercept_rate,
            )
        bundle = wallet.create_transfer_bundle(recipient, amount, memo=memo)
        return self.broadcast_bundle(bundle)

    def create_cold_vault(
        self,
        owner: str,
        vault_id: str,
        amount: int,
        vault_secret: int,
    ) -> VaultRecord:
        """Lock coins into a threshold (quorum-of-N) Shamir secret-shared cold vault.

        Any (quorum - 1) validators learn mathematically ZERO bits of `vault_secret`.
        """
        shares = split_secret(
            vault_secret,
            threshold=self.quorum_size,
            num_shares=len(self.validators),
        )
        record = VaultRecord(
            vault_id=vault_id, owner=owner, locked_amount=amount, epoch=1
        )
        for node in self.validators.values():
            node.store_vault_share(record, shares[node.numeric_id])
        return record

    def run_proactive_epoch_refresh(self, vault_id: str) -> int:
        """Execute Proactive Secret Sharing (PSS) refresh over pairwise OTP channels.

        Every validator generates a random zero-constant polynomial z_j(x) with
        z_j(0) = 0, encrypts each delta z_j(i) over its pairwise OTP+MAC link to
        validator i, and updates its share. The vault secret stays identical, while
        any old shares stolen in earlier epochs become useless!
        """
        online_nodes = [n for n in self.validators.values() if n.online]
        if len(online_nodes) < self.quorum_size:
            raise QuorumConsensusError("Not enough online validators for PSS refresh.")

        all_ids = [n.numeric_id for n in self.validators.values()]
        id_to_vid = {n.numeric_id: n.validator_id for n in self.validators.values()}
        incoming_deltas: dict[str, list[int]] = {vid: [] for vid in self.validators}

        for src in online_nodes:
            deltas = generate_zero_refresh_deltas(self.quorum_size, all_ids)
            for target_num_id, delta_val in deltas.items():
                dst_vid = id_to_vid[target_num_id]
                dst_node = self.validators[dst_vid]
                if dst_vid == src.validator_id:
                    incoming_deltas[dst_vid].append(delta_val)
                elif dst_node.online:
                    # Send delta over fixed-size OTP + Carter-Wegman authenticated link!
                    payload = json.dumps(
                        {"pss_vault": vault_id, "delta": delta_val},
                        separators=(",", ":"),
                    ).encode("utf-8")
                    env = _encrypt_envelope(
                        src.validator_id,
                        dst_vid,
                        src._peer_out_books[dst_vid],
                        payload,
                    )
                    self.wire_transcript.append(env)
                    decrypted = _decrypt_envelope(
                        env, dst_node._peer_in_books[src.validator_id]
                    )
                    msg = json.loads(decrypted.decode("utf-8"))
                    incoming_deltas[dst_vid].append(msg["delta"])

        new_epoch = 0
        for node in online_nodes:
            node.apply_pss_refresh(vault_id, incoming_deltas[node.validator_id])
            new_epoch = node.get_vault_epoch(vault_id)
        return new_epoch

    def unlock_cold_vault(
        self, vault_id: str, expected_secret: int, participating_vids: list[str]
    ) -> int:
        """Reconstruct vault secret from participating validators and unlock funds."""
        if len(participating_vids) < self.quorum_size:
            raise QuorumConsensusError("Need at least quorum validators to unlock vault.")
        shares = {
            self.validators[vid].numeric_id: self.validators[vid].get_vault_share(vault_id)
            for vid in participating_vids
        }
        recovered = reconstruct_secret(shares)
        if recovered != expected_secret:
            raise QuorumConsensusError("Vault secret reconstruction mismatch!")
        released = 0
        for node in self.validators.values():
            released = node.release_vault(vault_id)
        return released
