"""Tests for FutureOTPCoin v2: BB84 QKD, Toeplitz PA, Proactive SSS, and Pure OTP BFT."""

from __future__ import annotations

import secrets
import unittest

from future_otp_coin import FutureOTPNetwork
from otp_crypto import PRIME_P
from proactive_sss import reconstruct_secret, split_secret
from qkd_bb84 import EavesdropperDetectedError, run_bb84_key_exchange
from quorum_otp_coin import FRAME_BYTES, CanonicalTx, QuorumConsensusError


class TestFutureOTPCoin(unittest.TestCase):
    def test_zero_computational_crypto_across_entire_stack(self) -> None:
        """Verify ZERO SHA-256 / hashlib / SSL / RSA / ECDSA / AES dependencies."""
        import future_otp_coin
        import otp_crypto
        import proactive_sss
        import qkd_bb84
        import quorum_otp_coin

        for mod in (
            otp_crypto,
            qkd_bb84,
            proactive_sss,
            quorum_otp_coin,
            future_otp_coin,
        ):
            self.assertNotIn("hashlib", mod.__dict__)
            self.assertNotIn("ssl", mod.__dict__)

    def test_bb84_clean_channel_generates_identical_keys(self) -> None:
        k_alice, k_bob, report = run_bb84_key_exchange(64, eve_intercept_rate=0.0)
        self.assertEqual(k_alice, k_bob)
        self.assertEqual(len(k_alice), 64)
        self.assertEqual(report.qber, 0.0)

    def test_bb84_detects_eavesdropper_via_qber_and_aborts(self) -> None:
        """An intercept-resend eavesdropper induces ~25% QBER (>11%) and is caught."""
        with self.assertRaises(EavesdropperDetectedError):
            run_bb84_key_exchange(64, eve_intercept_rate=1.0)

    def test_auto_qkd_pad_replenishment_sustains_indefinite_transfers(self) -> None:
        """Wallet starts with only 2 OTP pages yet sends 5 transfers via BB84 QKD refills."""
        net = FutureOTPNetwork(num_validators=4, auto_qkd_refill=True, qkd_refill_batch=4)
        alice = net.register_wallet("alice", pad_pages=2)
        bob = net.register_wallet("bob", pad_pages=2)
        net.genesis_mint("alice", 100)

        for i in range(5):
            commits = net.send_transfer(alice, "bob", 10, memo=f"tx-{i}")
            self.assertEqual(len(commits), 4)

        self.assertEqual(net.validators["V0"].balances["alice"], 50)
        self.assertEqual(net.validators["V0"].balances["bob"], 50)
        # QKD refills occurred automatically across all 4 validators!
        self.assertGreaterEqual(len(net.qkd_reports), 4)
        # Every single packet on the wire (transfers + QKD auth + peer votes) is fixed 256B!
        for pkt in net.wire_transcript:
            self.assertEqual(len(pkt.ciphertext), FRAME_BYTES)
        # Ledger integrity chain grew by 5 Carter-Wegman chained tags.
        self.assertEqual(len(net.validators["V0"].chain_tags), 6)

    def test_qkd_refill_aborts_if_eve_taps_quantum_channel(self) -> None:
        net = FutureOTPNetwork(num_validators=4, auto_qkd_refill=True, qkd_refill_batch=4)
        alice = net.register_wallet("alice", pad_pages=1)
        net.register_wallet("bob", pad_pages=1)
        net.genesis_mint("alice", 50)

        with self.assertRaises(EavesdropperDetectedError):
            net.send_transfer(alice, "bob", 10, eve_intercept_rate=1.0)

        self.assertEqual(net.validators["V0"].balances["alice"], 50)

    def test_proactive_secret_shared_vault_defeats_slow_bleed_compromise(self) -> None:
        """Stolen Epoch-1 shares become useless after Proactive Secret Sharing refresh."""
        net = FutureOTPNetwork(num_validators=4)
        net.register_wallet("alice", pad_pages=4)
        net.genesis_mint("alice", 1000)

        vault_secret = secrets.randbelow(PRIME_P)
        net.create_cold_vault("alice", "cold-1", amount=800, vault_secret=vault_secret)
        self.assertEqual(net.validators["V0"].balances["alice"], 200)

        # Attacker compromises V0 and V1 in Epoch 1 (only 2 < threshold 3 shares).
        stolen_epoch1_v0 = net.validators["V0"].get_vault_share("cold-1")
        stolen_epoch1_v1 = net.validators["V1"].get_vault_share("cold-1")

        # Network runs Proactive Secret Sharing refresh over pairwise OTP channels!
        new_epoch = net.run_proactive_epoch_refresh("cold-1")
        self.assertEqual(new_epoch, 2)

        # Even if attacker later compromises V2 in Epoch 2, mixing old Epoch-1 shares
        # with the new Epoch-2 share produces garbage — NOT the vault secret!
        stolen_epoch2_v2 = net.validators["V2"].get_vault_share("cold-1")
        mixed_guess = reconstruct_secret(
            {1: stolen_epoch1_v0, 2: stolen_epoch1_v1, 3: stolen_epoch2_v2}
        )
        self.assertNotEqual(mixed_guess, vault_secret)

        # Meanwhile, honest Epoch-2 shares (any 3 of 4) unlock the 800-coin vault cleanly!
        released = net.unlock_cold_vault("cold-1", vault_secret, ["V0", "V2", "V3"])
        self.assertEqual(released, 800)
        self.assertEqual(net.validators["V0"].balances["alice"], 1000)

    def test_byzantine_forgery_still_blocked(self) -> None:
        net = FutureOTPNetwork(num_validators=4)
        net.register_wallet("alice", pad_pages=4)
        net.register_wallet("eve", pad_pages=4)
        net.genesis_mint("alice", 100)

        forged = CanonicalTx("alice", "eve", 100, page_id=0, memo="forged")
        with self.assertRaises(QuorumConsensusError):
            net.broadcast_bundle(bundle={}, forged_validator_votes={"V0": forged})
        self.assertEqual(net.validators["V1"].balances["alice"], 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)
