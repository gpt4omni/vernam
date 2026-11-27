"""Automated tests for OTPCoin, including live cryptographic attack scenarios."""

from __future__ import annotations

import json
import unittest

from otp_coin import (
    AuthenticationError,
    InsufficientFundsError,
    InvalidTransactionError,
    Mint,
    ReplayOrReuseError,
    TransactionEnvelope,
)
from otp_crypto import PadExhaustedError, otp_xor


class TestOTPCoin(unittest.TestCase):
    def setUp(self) -> None:
        self.mint = Mint()
        self.alice = self.mint.register_wallet("alice", pad_pages=5)
        self.bob = self.mint.register_wallet("bob", pad_pages=5)
        self.charlie = self.mint.register_wallet("charlie", pad_pages=5)
        self.mint.mint_coins("alice", 100)

    def test_valid_transfers_and_ledger(self) -> None:
        env1 = self.alice.create_transfer("bob", 35, memo="coffee")
        e1 = self.mint.submit_transaction(env1)

        env2 = self.bob.create_transfer("charlie", 15, memo="split")
        e2 = self.mint.submit_transaction(env2)

        self.assertEqual(self.mint.balance_of("alice"), 65)
        self.assertEqual(self.mint.balance_of("bob"), 20)
        self.assertEqual(self.mint.balance_of("charlie"), 15)
        self.assertEqual(e1.page_id, 0)
        self.assertEqual(e2.page_id, 0)
        self.assertEqual(len(self.mint.ledger), 3)  # 1 mint + 2 transfers

    def test_malleability_attack_succeeds_without_mac_and_fails_with_mac(self) -> None:
        """Demonstrate why raw OTP alone is unsafe and how the one-time MAC stops it."""
        # Alice intends to send 10 coins to bob.
        env = self.alice.create_transfer("bob", 10, memo="lunch")

        # Suppose attacker knows the JSON structure and byte offset of `"amount":10`
        # and XORs the ciphertext to flip "10" -> "90" without knowing the OTP key!
        expected_plain = json.dumps(
            {"sender": "alice", "recipient": "bob", "amount": 10, "memo": "lunch"},
            separators=(",", ":"),
        ).encode("utf-8")
        idx = expected_plain.index(b'"amount":10') + len(b'"amount":')

        tampered = bytearray(env.ciphertext)
        tampered[idx] ^= ord("1") ^ ord("9")  # Flip '1' -> '9' directly in ciphertext!

        forged_env = TransactionEnvelope(
            sender=env.sender,
            page_id=env.page_id,
            ciphertext=bytes(tampered),
            mac_tag=env.mac_tag,
        )

        # 1. With one-time MAC enabled (default): attack is caught immediately!
        with self.assertRaises(AuthenticationError):
            self.mint.submit_transaction(forged_env, require_mac=True)
        self.assertEqual(self.mint.balance_of("alice"), 100)
        self.assertEqual(self.mint.balance_of("bob"), 0)

        # 2. If MAC were disabled (pure raw OTP): attacker successfully steals 90 coins!
        stolen = self.mint.submit_transaction(forged_env, require_mac=False)
        self.assertEqual(stolen.amount, 90)
        self.assertEqual(self.mint.balance_of("alice"), 10)
        self.assertEqual(self.mint.balance_of("bob"), 90)

    def test_replay_attack_rejected(self) -> None:
        env = self.alice.create_transfer("bob", 25, memo="once")
        self.mint.submit_transaction(env)

        with self.assertRaises(ReplayOrReuseError):
            self.mint.submit_transaction(env)

        self.assertEqual(self.mint.balance_of("alice"), 75)
        self.assertEqual(self.mint.balance_of("bob"), 25)

    def test_forgery_without_pad_rejected(self) -> None:
        fake_env = TransactionEnvelope(
            sender="alice",
            page_id=0,
            ciphertext=b"\x42" * 64,
            mac_tag=b"\x00" * 16,
        )
        with self.assertRaises(AuthenticationError):
            self.mint.submit_transaction(fake_env)
        self.assertEqual(self.mint.balance_of("alice"), 100)

    def test_insufficient_funds_rejected_and_not_replayable_later(self) -> None:
        env = self.alice.create_transfer("bob", 999)
        with self.assertRaises(InsufficientFundsError):
            self.mint.submit_transaction(env)
        self.assertEqual(self.mint.balance_of("alice"), 100)

        # Even if Alice later gets 1000 coins, replaying the old overdraft envelope fails.
        self.mint.mint_coins("alice", 1000)
        with self.assertRaises(ReplayOrReuseError):
            self.mint.submit_transaction(env)
        self.assertEqual(self.mint.balance_of("alice"), 1100)

    def test_invalid_amount_rejected(self) -> None:
        env = self.alice.create_transfer("bob", -5)
        with self.assertRaises(InvalidTransactionError):
            self.mint.submit_transaction(env)

    def test_pad_exhaustion(self) -> None:
        for _ in range(5):
            env = self.alice.create_transfer("bob", 1)
            self.mint.submit_transaction(env)
        self.assertEqual(self.alice.remaining_txs, 0)
        with self.assertRaises(PadExhaustedError):
            self.alice.create_transfer("bob", 1)

    def test_two_time_pad_leak_property(self) -> None:
        """Sanity check illustrating why OTP keys must never be reused: c1 ^ c2 == m1 ^ m2."""
        key = b"\x5a\x19\xf0\x88\x33\x71\xaa\x02\x9c\x4d\x11\xef"
        m1 = b"PAY_BOB_0010"
        m2 = b"PAY_EVE_9999"
        c1 = otp_xor(m1, key)
        c2 = otp_xor(m2, key)
        # An eavesdropper who sees c1 and c2 recovers m1 ^ m2 without knowing key!
        self.assertEqual(otp_xor(c1, c2), otp_xor(m1, m2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
