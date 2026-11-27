"""Tests for PrivateMPCCoin: hidden balances, hidden amounts, hidden recipients."""

from __future__ import annotations

import unittest

from otp_crypto import PRIME_P
from proactive_sss import reconstruct_secret, split_secret
from private_mpc_coin import (
    AMOUNT_BITS,
    PRIVATE_FRAME_BYTES,
    PrivateMPCError,
    PrivateOTPNetwork,
)


class TestPrivateMPCCoin(unittest.TestCase):
    def setUp(self) -> None:
        self.net = PrivateOTPNetwork(num_validators=4, threshold=3)
        self.alice = self.net.register_wallet("alice", pad_pages=32)
        self.bob = self.net.register_wallet("bob", pad_pages=32)
        self.charlie = self.net.register_wallet("charlie", pad_pages=32)
        self.dave = self.net.register_wallet("dave", pad_pages=32)
        self.net.mint_private("alice", 500)
        self.net.mint_private("charlie", 200)

    def test_zero_computational_crypto_imports(self) -> None:
        import private_mpc_coin

        self.assertNotIn("hashlib", private_mpc_coin.__dict__)
        self.assertNotIn("ssl", private_mpc_coin.__dict__)

    def test_private_transfer_hides_balances_amount_and_recipient(self) -> None:
        # Snapshot every validator's shares BEFORE the transfer.
        before_v0 = dict(self.net.validators["V0"].balance_shares)

        # Alice privately sends 137 coins to Bob!
        self.net.private_transfer(self.alice, "bob", 137)

        # 1. Wallet owners reconstruct their exact true balances privately.
        self.assertEqual(self.net.query_private_balance(self.alice), 363)
        self.assertEqual(self.net.query_private_balance(self.bob), 137)
        self.assertEqual(self.net.query_private_balance(self.charlie), 200)
        self.assertEqual(self.net.query_private_balance(self.dave), 0)

        # 2. Privacy check: EVERY account's share on V0 changed (even Charlie & Dave!),
        #    so no validator can tell whether Bob, Charlie, or Dave received the coins!
        after_v0 = self.net.validators["V0"].balance_shares
        for acct in ("alice", "bob", "charlie", "dave"):
            self.assertNotEqual(before_v0[acct], after_v0[acct])
            # Individual validator's share looks nothing like the real balance.
            self.assertGreater(after_v0[acct], 100_000)

        # 3. Even 2 colluding validators (V0 + V1) cannot reconstruct Bob's balance (need 3).
        two_shares_bob = {
            1: self.net.validators["V0"].balance_shares["bob"],
            2: self.net.validators["V1"].balance_shares["bob"],
        }
        self.assertNotEqual(reconstruct_secret(two_shares_bob), 137)

        # 4. Cover traffic & all wire envelopes are uniform fixed-size OTP frames!
        self.net.send_cover_traffic_round(self.alice)
        for pkt in self.net.wire_transcript:
            self.assertEqual(len(pkt.ciphertext), PRIVATE_FRAME_BYTES)
            self.assertNotIn(b"137", pkt.ciphertext)
            self.assertNotIn(b"bob", pkt.ciphertext)

    def test_overdraft_attack_blocked_without_exposing_balance(self) -> None:
        """Malicious Alice tries to spend 501 (only has 500) by forging a fake remainder."""
        bad_v = [split_secret((501 >> j) & 1, 3, 4) for j in range(AMOUNT_BITS)]
        fake_r = [split_secret(0, 3, 4) for _ in range(AMOUNT_BITS)]
        sel_bob = [
            split_secret(1 if a == "bob" else 0, 3, 4) for a in self.net.accounts
        ]

        with self.assertRaises(PrivateMPCError):
            self.net.submit_private_transfer_shares(self.alice, bad_v, fake_r, sel_bob)

        self.assertEqual(self.net.query_private_balance(self.alice), 500)
        self.assertEqual(self.net.query_private_balance(self.bob), 0)

    def test_negative_or_non_binary_bit_attack_blocked(self) -> None:
        """Malicious Alice sends bit value = -1 mod p to try to mint coins for herself!"""
        evil_bit = (-1) % PRIME_P
        bad_v = [split_secret(evil_bit if j == 0 else 0, 3, 4) for j in range(AMOUNT_BITS)]
        # Make remainder match B_alice - (-1) = 501 so balance conservation would pass!
        r_501 = [split_secret((501 >> j) & 1, 3, 4) for j in range(AMOUNT_BITS)]
        sel_bob = [
            split_secret(1 if a == "bob" else 0, 3, 4) for a in self.net.accounts
        ]

        # Bit check v_0 * (v_0 - 1) == 0 catches and rejects the attack!
        with self.assertRaises(PrivateMPCError):
            self.net.submit_private_transfer_shares(self.alice, bad_v, r_501, sel_bob)

        self.assertEqual(self.net.query_private_balance(self.alice), 500)
        self.assertEqual(self.net.query_private_balance(self.bob), 0)

    def test_double_recipient_inflation_attack_blocked(self) -> None:
        """Malicious Alice sets selector=1 for BOTH Bob and Charlie to double-mint coins."""
        v_bits = [split_secret((50 >> j) & 1, 3, 4) for j in range(AMOUNT_BITS)]
        r_bits = [split_secret((450 >> j) & 1, 3, 4) for j in range(AMOUNT_BITS)]
        bad_sel = [
            split_secret(1 if a in ("bob", "charlie") else 0, 3, 4)
            for a in self.net.accounts
        ]

        with self.assertRaises(PrivateMPCError):
            self.net.submit_private_transfer_shares(self.alice, v_bits, r_bits, bad_sel)

        self.assertEqual(self.net.query_private_balance(self.alice), 500)
        self.assertEqual(self.net.query_private_balance(self.bob), 0)
        self.assertEqual(self.net.query_private_balance(self.charlie), 200)

    def test_inconsistent_shamir_shares_from_cheating_sender_blocked(self) -> None:
        """Malicious Alice sends a corrupted share to V3 that doesn't fit the degree-2 poly."""
        v_bits = [split_secret((25 >> j) & 1, 3, 4) for j in range(AMOUNT_BITS)]
        r_bits = [split_secret((475 >> j) & 1, 3, 4) for j in range(AMOUNT_BITS)]
        sel_bob = [
            split_secret(1 if a == "bob" else 0, 3, 4) for a in self.net.accounts
        ]
        # Tamper with validator 4's share of bit 0!
        v_bits[0][4] = (v_bits[0][4] + 12345) % PRIME_P

        with self.assertRaises(PrivateMPCError):
            self.net.submit_private_transfer_shares(self.alice, v_bits, r_bits, sel_bob)

        self.assertEqual(self.net.query_private_balance(self.alice), 500)

    def test_proactive_refresh_on_liquid_balances(self) -> None:
        self.net.private_transfer(self.alice, "bob", 100)

        # Attacker steals Epoch-1 shares of Bob from V0 & V1.
        stale_v0 = self.net.validators["V0"].balance_shares["bob"]
        stale_v1 = self.net.validators["V1"].balance_shares["bob"]

        new_epoch = self.net.proactive_refresh_all_balances()
        self.assertEqual(new_epoch, 2)

        # Mixing stolen Epoch-1 shares + Epoch-2 share from V2 yields garbage!
        fresh_v2 = self.net.validators["V2"].balance_shares["bob"]
        self.assertNotEqual(
            reconstruct_secret({1: stale_v0, 2: stale_v1, 3: fresh_v2}), 100
        )

        # Honest wallet owners still read exact balances in Epoch 2!
        self.assertEqual(self.net.query_private_balance(self.alice), 400)
        self.assertEqual(self.net.query_private_balance(self.bob), 100)
        self.assertEqual(self.net.query_private_balance(self.charlie), 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
