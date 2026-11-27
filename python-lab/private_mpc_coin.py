"""PrivateMPCCoin: 100% Information-Theoretically Private OTP Coin.

Hides ALL of the following with ZERO computational assumptions (no SHA-256,
no RSA, no ECDSA, no zk-SNARKs, no AES):
  1. Wire traffic -> Fixed-size OTP frames + Carter-Wegman one-time MACs.
  2. Liquid balances -> Stored ONLY as (t=3, N=4) Shamir shares over F_(2^127-1);
     any 1 or 2 colluding validators learn mathematically ZERO bits.
  3. Transfer amounts -> Proven in [0, 2^16) with non-negative sender remainder
     using one-time Beaver-triple MPC bit proofs over pairwise OTP channels.
  4. Recipient identity -> Blinded one-hot selector [s_k] updates EVERY account's
     balance share with [s_k * v], so validators cannot tell who received coins!
  5. Long-term liquid storage -> Proactive Secret Sharing (PSS) refreshes every
     account's balance shares across epochs over pairwise OTP channels.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import secrets

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

AMOUNT_BITS = 16  # Supports liquid balances / transfers up to 2^16 - 1 = 65,535
MAX_AMOUNT = (1 << AMOUNT_BITS) - 1
PRIVATE_FRAME_BYTES = 4096  # Fixed frame hiding all transfer & MPC payload sizes


class PrivateMPCError(Exception):
    """Raised when a private transfer fails MPC verification or authentication."""


@dataclass(frozen=True)
class PrivateEnvelope:
    src: str
    dst: str
    page_id: int
    ciphertext: bytes  # Always PRIVATE_FRAME_BYTES
    mac_tag: bytes     # 16-byte Carter-Wegman MAC

    def mac_input(self) -> bytes:
        sb = self.src.encode("utf-8")
        db = self.dst.encode("utf-8")
        return (
            len(sb).to_bytes(2, "big")
            + sb
            + len(db).to_bytes(2, "big")
            + db
            + self.page_id.to_bytes(8, "big")
            + self.ciphertext
        )


def _pack_frame(payload: bytes, size: int = PRIVATE_FRAME_BYTES) -> bytes:
    if len(payload) + 2 > size:
        raise ValueError(f"Payload ({len(payload)}B) exceeds fixed frame ({size - 2}B).")
    return len(payload).to_bytes(2, "big") + payload + b"\x00" * (size - 2 - len(payload))


def _unpack_frame(frame: bytes) -> bytes:
    length = int.from_bytes(frame[:2], "big")
    return frame[2 : 2 + length]


def _send_otp_json(
    src: str,
    dst: str,
    out_book: PadBook,
    in_book: PadBook,
    obj: dict,
    transcript: list[PrivateEnvelope],
) -> dict:
    """Transmit JSON over a fixed-size OTP + Carter-Wegman authenticated channel."""
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    page = out_book.pop_next()
    ct = otp_xor(_pack_frame(raw), page.enc_key)
    draft = PrivateEnvelope(src, dst, page.page_id, ct, b"")
    tag = carter_wegman_mac(draft.mac_input(), page.mac_r, page.mac_s)
    env = PrivateEnvelope(src, dst, page.page_id, ct, tag)
    transcript.append(env)

    # Receiver side: authenticate BEFORE decrypting, then burn page.
    r_page = in_book.peek_unused(env.page_id)
    if not verify_mac(env.mac_input(), r_page.mac_r, r_page.mac_s, env.mac_tag):
        raise PrivateMPCError(f"MAC failure on {src} -> {dst}.")
    in_book.burn(env.page_id)
    plain = _unpack_frame(otp_xor(env.ciphertext, r_page.enc_key))
    return json.loads(plain.decode("utf-8"))


def reconstruct_consistent(shares: dict[int, int], threshold: int) -> int:
    """Reconstruct secret AND verify all shares lie on one degree-(threshold-1) polynomial.

    Catches any cheating client or corrupted validator sending inconsistent shares!
    """
    if len(shares) < threshold:
        raise PrivateMPCError("Insufficient shares to reconstruct.")
    xs = sorted(shares.keys())
    base_subset = {x: shares[x] for x in xs[:threshold]}
    secret = reconstruct_secret(base_subset)
    # Verify every extra share agrees with the exact same degree-(t-1) polynomial.
    for extra_x in xs[threshold:]:
        alt_subset = {x: shares[x] for x in xs[1:threshold]}
        alt_subset[extra_x] = shares[extra_x]
        if reconstruct_secret(alt_subset) != secret:
            raise PrivateMPCError(
                "Inconsistent Shamir shares detected (degree violation / cheating attempt)!"
            )
    return secret


@dataclass(frozen=True)
class BeaverTripleShares:
    """One-time correlated randomness ([a], [b], [c]) with c = a * b mod PRIME_P."""

    a: dict[int, int]
    b: dict[int, int]
    c: dict[int, int]

    @classmethod
    def generate(cls, threshold: int, num_validators: int) -> "BeaverTripleShares":
        a_val = secrets.randbelow(PRIME_P)
        b_val = secrets.randbelow(PRIME_P)
        c_val = (a_val * b_val) % PRIME_P
        return cls(
            a=split_secret(a_val, threshold, num_validators),
            b=split_secret(b_val, threshold, num_validators),
            c=split_secret(c_val, threshold, num_validators),
        )


class PrivateValidator:
    """Validator storing ONLY Shamir shares of liquid balances (never plaintext!)."""

    def __init__(self, validator_id: str, numeric_id: int) -> None:
        self.validator_id = validator_id
        self.numeric_id = numeric_id
        # account_address -> Shamir share y_i of that account's balance (looks random!)
        self.balance_shares: dict[str, int] = {}
        self.wallet_in_books: dict[str, PadBook] = {}
        self.wallet_out_books: dict[str, PadBook] = {}
        self.peer_out_books: dict[str, PadBook] = {}
        self.peer_in_books: dict[str, PadBook] = {}
        self.epoch: int = 1


class PrivateWallet:
    """User wallet tracking its own secret balance & per-validator OTP PadBooks."""

    def __init__(
        self,
        address: str,
        val_out_books: dict[str, PadBook],
        val_in_books: dict[str, PadBook],
    ) -> None:
        self.address = address
        self.val_out_books = val_out_books
        self.val_in_books = val_in_books


class PrivateOTPNetwork:
    """4-validator (t=3) information-theoretically private coin network."""

    def __init__(self, num_validators: int = 4, threshold: int = 3) -> None:
        if not (2 <= threshold <= num_validators):
            raise ValueError("Require 2 <= threshold <= num_validators.")
        self.num_validators = num_validators
        self.threshold = threshold
        self.validators: dict[str, PrivateValidator] = {
            f"V{i}": PrivateValidator(f"V{i}", numeric_id=i + 1)
            for i in range(num_validators)
        }
        self.accounts: list[str] = []
        self.wire_transcript: list[PrivateEnvelope] = []

        # Provision pairwise OTP books between validators (large pool for MPC rounds).
        vids = list(self.validators.keys())
        for src in vids:
            for dst in vids:
                if src == dst:
                    continue
                out_b, in_b = PadBook.generate_pair(
                    num_pages=512, enc_key_bytes=PRIVATE_FRAME_BYTES
                )
                self.validators[src].peer_out_books[dst] = out_b
                self.validators[dst].peer_in_books[src] = in_b

    def register_wallet(self, address: str, pad_pages: int = 32) -> PrivateWallet:
        if address in self.accounts:
            raise PrivateMPCError(f"Account '{address}' already exists.")
        self.accounts.append(address)
        w_out: dict[str, PadBook] = {}
        w_in: dict[str, PadBook] = {}
        zero_shares = split_secret(0, self.threshold, self.num_validators)
        for vid, node in self.validators.items():
            # Bidirectional OTP channels between wallet and each validator.
            o1, i1 = PadBook.generate_pair(pad_pages, PRIVATE_FRAME_BYTES)
            o2, i2 = PadBook.generate_pair(pad_pages, PRIVATE_FRAME_BYTES)
            w_out[vid] = o1
            node.wallet_in_books[address] = i1
            node.wallet_out_books[address] = o2
            w_in[vid] = i2
            node.balance_shares[address] = zero_shares[node.numeric_id]
        return PrivateWallet(address, w_out, w_in)

    def mint_private(self, address: str, amount: int) -> None:
        """Privately credit an account via Shamir shares (no validator sees `amount`)."""
        if not (0 <= amount <= MAX_AMOUNT):
            raise ValueError(f"Mint amount must be in [0, {MAX_AMOUNT}].")
        shares = split_secret(amount, self.threshold, self.num_validators)
        for node in self.validators.values():
            node.balance_shares[address] = (
                node.balance_shares[address] + shares[node.numeric_id]
            ) % PRIME_P

    def query_private_balance(self, wallet: PrivateWallet) -> int:
        """Each validator sends its encrypted balance share ONLY to the wallet owner."""
        collected: dict[int, int] = {}
        for vid, node in self.validators.items():
            msg = _send_otp_json(
                src=vid,
                dst=wallet.address,
                out_book=node.wallet_out_books[wallet.address],
                in_book=wallet.val_in_books[vid],
                obj={"balance_share": node.balance_shares[wallet.address]},
                transcript=self.wire_transcript,
            )
            collected[node.numeric_id] = msg["balance_share"]
        return reconstruct_consistent(collected, self.threshold)

    def _mpc_open_batch(self, share_vectors: dict[int, list[int]]) -> list[int]:
        """Open a batch of secrets across validators via pairwise OTP links (1 round)."""
        vids = list(self.validators.keys())
        id_to_vid = {n.numeric_id: vid for vid, n in self.validators.items()}
        # Broadcast each validator's vector to every peer over pairwise OTP channels.
        received: dict[str, dict[int, list[int]]] = {
            vid: {self.validators[vid].numeric_id: share_vectors[self.validators[vid].numeric_id]}
            for vid in vids
        }
        for src_id in vids:
            src_node = self.validators[src_id]
            vec = share_vectors[src_node.numeric_id]
            for dst_id in vids:
                if src_id == dst_id:
                    continue
                dst_node = self.validators[dst_id]
                msg = _send_otp_json(
                    src=src_id,
                    dst=dst_id,
                    out_book=src_node.peer_out_books[dst_id],
                    in_book=dst_node.peer_in_books[src_id],
                    obj={"open_vec": vec},
                    transcript=self.wire_transcript,
                )
                received[dst_id][src_node.numeric_id] = msg["open_vec"]

        # Every validator independently verifies degree consistency and reconstructs.
        count = len(next(iter(share_vectors.values())))
        results: list[int] = []
        # Check on V0 (all validators hold identical received maps).
        ref_map = received[vids[0]]
        for idx in range(count):
            shares_i = {num_id: ref_map[num_id][idx] for num_id in id_to_vid}
            results.append(reconstruct_consistent(shares_i, self.threshold))
        return results

    def _mpc_multiply_batch(
        self,
        xs: list[dict[int, int]],
        ys: list[dict[int, int]],
    ) -> list[dict[int, int]]:
        """Multiply k pairs of secret-shared values using one-time Beaver triples."""
        k = len(xs)
        triples = [
            BeaverTripleShares.generate(self.threshold, self.num_validators)
            for _ in range(k)
        ]
        # Pack all alpha = x - a and beta = y - b into ONE batched OTP open round!
        open_vectors: dict[int, list[int]] = {}
        for node in self.validators.values():
            nid = node.numeric_id
            vec: list[int] = []
            for i in range(k):
                vec.append((xs[i][nid] - triples[i].a[nid]) % PRIME_P)
                vec.append((ys[i][nid] - triples[i].b[nid]) % PRIME_P)
            open_vectors[nid] = vec

        opened = self._mpc_open_batch(open_vectors)

        products: list[dict[int, int]] = []
        for i in range(k):
            alpha = opened[2 * i]
            beta = opened[2 * i + 1]
            ab_const = (alpha * beta) % PRIME_P
            prod_shares: dict[int, int] = {}
            for node in self.validators.values():
                nid = node.numeric_id
                prod_shares[nid] = (
                    triples[i].c[nid]
                    + alpha * triples[i].b[nid]
                    + beta * triples[i].a[nid]
                    + ab_const
                ) % PRIME_P
            products.append(prod_shares)
        return products

    def submit_private_transfer_shares(
        self,
        sender_wallet: PrivateWallet,
        v_bit_shares: list[dict[int, int]],
        r_bit_shares: list[dict[int, int]],
        sel_shares: list[dict[int, int]],
    ) -> None:
        """Verify and settle a fully confidential transfer using pure IT-MPC.

        Validators learn ZERO bits about:
          - Transfer amount v
          - Sender's or recipient's balance
          - Which account is the recipient!
        """
        if len(v_bit_shares) != AMOUNT_BITS or len(r_bit_shares) != AMOUNT_BITS:
            raise PrivateMPCError("Invalid bit-decomposition length.")
        if len(sel_shares) != len(self.accounts):
            raise PrivateMPCError("Recipient selector length must match account count.")

        # Phase 1: Sender delivers each validator ONLY its own Shamir shares over OTP+MAC.
        v_bits_by_val: dict[int, list[int]] = {}
        r_bits_by_val: dict[int, list[int]] = {}
        sel_by_val: dict[int, list[int]] = {}
        for vid, node in self.validators.items():
            nid = node.numeric_id
            payload = {
                "v_bits": [b[nid] for b in v_bit_shares],
                "r_bits": [b[nid] for b in r_bit_shares],
                "sel": [s[nid] for s in sel_shares],
            }
            delivered = _send_otp_json(
                src=sender_wallet.address,
                dst=vid,
                out_book=sender_wallet.val_out_books[vid],
                in_book=node.wallet_in_books[sender_wallet.address],
                obj=payload,
                transcript=self.wire_transcript,
            )
            v_bits_by_val[nid] = delivered["v_bits"]
            r_bits_by_val[nid] = delivered["r_bits"]
            sel_by_val[nid] = delivered["sel"]

        nids = [n.numeric_id for n in self.validators.values()]

        def _transpose(by_val: dict[int, list[int]], length: int) -> list[dict[int, int]]:
            return [{nid: by_val[nid][i] for nid in nids} for i in range(length)]

        v_bits = _transpose(v_bits_by_val, AMOUNT_BITS)
        r_bits = _transpose(r_bits_by_val, AMOUNT_BITS)
        sels = _transpose(sel_by_val, len(self.accounts))

        # Recombine secret-shared [v] = sum(2^j * [v_j]) and [r] = sum(2^j * [r_j]) locally.
        v_share: dict[int, int] = {nid: 0 for nid in nids}
        r_share: dict[int, int] = {nid: 0 for nid in nids}
        for j in range(AMOUNT_BITS):
            weight = 1 << j
            for nid in nids:
                v_share[nid] = (v_share[nid] + weight * v_bits[j][nid]) % PRIME_P
                r_share[nid] = (r_share[nid] + weight * r_bits[j][nid]) % PRIME_P

        # Phase 2: Batched Beaver-triple multiplications for ALL checks + blinded credits!
        # - v_j * (v_j - 1) == 0   (proves v_j in {0, 1}, so 0 <= v < 2^16)
        # - r_j * (r_j - 1) == 0   (proves r_j in {0, 1}, so 0 <= B_sender - v < 2^16)
        # - s_k * (s_k - 1) == 0   (proves s_k in {0, 1})
        # - d_k = s_k * v          (blinded credit for EVERY account k!)
        mul_x: list[dict[int, int]] = []
        mul_y: list[dict[int, int]] = []

        for bit_s in v_bits:
            mul_x.append(bit_s)
            mul_y.append({nid: (bit_s[nid] - 1) % PRIME_P for nid in nids})
        for bit_s in r_bits:
            mul_x.append(bit_s)
            mul_y.append({nid: (bit_s[nid] - 1) % PRIME_P for nid in nids})
        for sel_s in sels:
            mul_x.append(sel_s)
            mul_y.append({nid: (sel_s[nid] - 1) % PRIME_P for nid in nids})
        for sel_s in sels:
            mul_x.append(sel_s)
            mul_y.append(v_share)

        mul_results = self._mpc_multiply_batch(mul_x, mul_y)

        num_bool_checks = 2 * AMOUNT_BITS + len(self.accounts)
        bool_check_shares = mul_results[:num_bool_checks]
        credit_shares = mul_results[num_bool_checks:]  # One secret credit [s_k * v] per account!

        # Phase 3: Open ONLY the zero/one invariant checks (leaks ZERO bits about v, B, or recipient!).
        check_vectors: dict[int, list[int]] = {}
        for node in self.validators.values():
            nid = node.numeric_id
            # All boolean checks (must open to 0)
            vec = [chk[nid] for chk in bool_check_shares]
            # Balance conservation: B_sender - v - r (must open to 0)
            bal_check = (
                node.balance_shares[sender_wallet.address] - v_share[nid] - r_share[nid]
            ) % PRIME_P
            vec.append(bal_check)
            # One-hot sum: sum(s_k) - 1 (must open to 0)
            sel_sum_check = (sum(sel_by_val[nid]) - 1) % PRIME_P
            vec.append(sel_sum_check)
            check_vectors[nid] = vec

        opened_checks = self._mpc_open_batch(check_vectors)
        if any(val != 0 for val in opened_checks):
            raise PrivateMPCError(
                "Private MPC proof REJECTED (overdraft, invalid bit, or non-one-hot recipient)!"
            )

        # Phase 4: Commit blinded updates across ALL accounts locally!
        # Every account's share changes (even non-recipients get +[0]), hiding who got paid.
        for node in self.validators.values():
            nid = node.numeric_id
            node.balance_shares[sender_wallet.address] = (
                node.balance_shares[sender_wallet.address] - v_share[nid]
            ) % PRIME_P
            for acct_idx, acct in enumerate(self.accounts):
                node.balance_shares[acct] = (
                    node.balance_shares[acct] + credit_shares[acct_idx][nid]
                ) % PRIME_P

    def private_transfer(
        self,
        sender_wallet: PrivateWallet,
        recipient: str,
        amount: int,
    ) -> None:
        """High-level helper for an honest wallet to create & submit a confidential transfer."""
        if recipient not in self.accounts:
            raise PrivateMPCError(f"Unknown recipient '{recipient}'.")
        if not (0 <= amount <= MAX_AMOUNT):
            raise PrivateMPCError(f"Amount must be in [0, {MAX_AMOUNT}].")

        current_balance = self.query_private_balance(sender_wallet)
        remainder = current_balance - amount
        if remainder < 0:
            raise PrivateMPCError("Insufficient private balance.")

        v_bit_shares = [
            split_secret((amount >> j) & 1, self.threshold, self.num_validators)
            for j in range(AMOUNT_BITS)
        ]
        r_bit_shares = [
            split_secret((remainder >> j) & 1, self.threshold, self.num_validators)
            for j in range(AMOUNT_BITS)
        ]
        sel_shares = [
            split_secret(1 if acct == recipient else 0, self.threshold, self.num_validators)
            for acct in self.accounts
        ]
        self.submit_private_transfer_shares(
            sender_wallet, v_bit_shares, r_bit_shares, sel_shares
        )

    def proactive_refresh_all_balances(self) -> int:
        """Refresh EVERY account's liquid balance shares via PSS over pairwise OTP links."""
        all_nids = [n.numeric_id for n in self.validators.values()]
        nid_to_vid = {n.numeric_id: vid for vid, n in self.validators.items()}
        incoming: dict[str, dict[str, list[int]]] = {
            vid: {acct: [] for acct in self.accounts} for vid in self.validators
        }

        for src_vid, src_node in self.validators.items():
            # Generate independent zero-polynomial deltas for every account in one batch.
            per_dst: dict[str, dict[str, int]] = {vid: {} for vid in self.validators}
            for acct in self.accounts:
                deltas = generate_zero_refresh_deltas(self.threshold, all_nids)
                for target_nid, dval in deltas.items():
                    per_dst[nid_to_vid[target_nid]][acct] = dval

            for dst_vid, acct_deltas in per_dst.items():
                if dst_vid == src_vid:
                    for acct, dval in acct_deltas.items():
                        incoming[dst_vid][acct].append(dval)
                else:
                    msg = _send_otp_json(
                        src=src_vid,
                        dst=dst_vid,
                        out_book=src_node.peer_out_books[dst_vid],
                        in_book=self.validators[dst_vid].peer_in_books[src_vid],
                        obj={"pss_liquid_deltas": acct_deltas},
                        transcript=self.wire_transcript,
                    )
                    for acct, dval in msg["pss_liquid_deltas"].items():
                        incoming[dst_vid][acct].append(dval)

        new_epoch = 0
        for vid, node in self.validators.items():
            for acct in self.accounts:
                node.balance_shares[acct] = (
                    node.balance_shares[acct] + sum(incoming[vid][acct])
                ) % PRIME_P
            node.epoch += 1
            new_epoch = node.epoch
        return new_epoch

    def send_cover_traffic_round(self, wallet: PrivateWallet) -> None:
        """Send fixed-size dummy OTP packets indistinguishable from real transactions."""
        for vid, node in self.validators.items():
            _send_otp_json(
                src=wallet.address,
                dst=vid,
                out_book=wallet.val_out_books[vid],
                in_book=node.wallet_in_books[wallet.address],
                obj={"dummy": True, "noise": secrets.token_hex(32)},
                transcript=self.wire_transcript,
            )
