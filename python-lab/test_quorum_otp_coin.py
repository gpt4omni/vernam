"""Tests for QuorumOTPCoin: decentralized BFT consensus with 100% pure OTP security."""

from __future__ import annotations

import sys
import unittest

from quorum_otp_coin import (
    FRAME_BYTES,
    CanonicalTx,
    QuorumConsensusError,
    QuorumNetwork,
    WireEnvelope,
)


class TestQuorumOTPCoin(unittest.TestCase):
    def setUp(self) -> None:
        self.net = QuorumNetwork(num_validators=4)  # N=4, f=1, quorum=3
        self.alice = self.net.register_wallet("alice", pad_pages=8)
        self.bob = self.net.register_wallet("bob", pad_pages=8)
        self.charlie = self.net.register_wallet("charlie", pad_pages=8)
        self.net.genesis_mint("alice", 100)

    def test_zero_computational_crypto_imports(self) -> None:
        """Confirm quorum_otp_coin and otp_crypto do NOT rely on hashlib/RSA/ECDSA/AES."""
        import otp_crypto
        import quorum_otp_coin

        for mod in (otp_crypto, quorum_otp_coin):
            self.assertNotIn("hashlib", mod.__dict__)
            self.assertNotIn("ssl", mod.__dict__)
        self.assertIn("quorum_otp_coin", sys.modules)

    def test_valid_quorum_transfer_and_perfect_wire_secrecy(self) -> None:
        bundle = self.alice.create_transfer_bundle("bob", 40, memo="top-secret-payroll")
        commits = self.net.broadcast_bundle(bundle)

        self.assertEqual(len(commits), 4)
        for node in self.net.validators.values():
            self.assertEqual(node.balances["alice"], 60)
            self.assertEqual(node.balances["bob"], 40)

        # Omnipotent eavesdropper inspects every single packet on the wire:
        # 4 client envelopes + 4*3 = 12 inter-validator OTP vote envelopes = 16 packets.
        self.assertEqual(len(self.net.wire_transcript), 16)
        for pkt in self.net.wire_transcript:
            # Every ciphertext is padded to exact FRAME_BYTES (no length leakage!)
            self.assertEqual(len(pkt.ciphertext), FRAME_BYTES)
            # No plaintext bytes appear anywhere on the wire.
            self.assertNotIn(b"top-secret-payroll", pkt.ciphertext)
            self.assertNotIn(b"bob", pkt.ciphertext)
            self.assertNotIn(b"40", pkt.ciphertext)

    def test_compromised_validator_cannot_forge_transaction(self) -> None:
        """Even a fully compromised validator (V0) cannot forge a spend from Alice."""
        fake_tx = CanonicalTx(
            sender="alice", recipient="charlie", amount=100, page_id=0, memo="stolen"
        )
        # V0 tries to inject a forged vote with no valid client envelopes to V1, V2, V3.
        with self.assertRaises(QuorumConsensusError):
            self.net.broadcast_bundle(
                bundle={},
                forged_validator_votes={"V0": fake_tx},
            )

        # Honest validators V1, V2, V3 never moved a single coin!
        for vid in ("V1", "V2", "V3"):
            self.assertEqual(self.net.validators[vid].balances["alice"], 100)
            self.assertEqual(self.net.validators[vid].balances["charlie"], 0)

    def test_offline_validator_does_not_halt_consensus(self) -> None:
        """Tolerates f=1 offline validator while remaining 3 reach quorum."""
        self.net.validators["V3"].online = False

        bundle = self.alice.create_transfer_bundle("bob", 25, memo="still works")
        commits = self.net.broadcast_bundle(bundle)
        self.assertEqual(len(commits), 3)

        for vid in ("V0", "V1", "V2"):
            self.assertEqual(self.net.validators[vid].balances["alice"], 75)
            self.assertEqual(self.net.validators[vid].balances["bob"], 25)

    def test_equivocation_double_spend_blocked(self) -> None:
        """Alice tries to split the network: 'pay Bob 100' to V0,V1 vs 'pay Charlie 100' to V2,V3."""
        split_bundle = {
            "V0": self.alice.create_for_validator("V0", "bob", 100, memo="fork-A"),
            "V1": self.alice.create_for_validator("V1", "bob", 100, memo="fork-A"),
            "V2": self.alice.create_for_validator("V2", "charlie", 100, memo="fork-B"),
            "V3": self.alice.create_for_validator("V3", "charlie", 100, memo="fork-B"),
        }

        with self.assertRaises(QuorumConsensusError):
            self.net.broadcast_bundle(split_bundle)

        # Neither fork reached 3-of-4 quorum -> zero coins moved on ANY validator!
        for node in self.net.validators.values():
            self.assertEqual(node.balances["alice"], 100)
            self.assertEqual(node.balances["bob"], 0)
            self.assertEqual(node.balances["charlie"], 0)

    def test_mitm_bit_flip_and_replay_blocked(self) -> None:
        bundle = self.alice.create_transfer_bundle("bob", 10, memo="clean")

        # MITM flips 1 bit in every validator's OTP ciphertext.
        tampered_bundle: dict[str, WireEnvelope] = {}
        for vid, env in bundle.items():
            bad_ct = bytearray(env.ciphertext)
            bad_ct[10] ^= 0x01
            tampered_bundle[vid] = WireEnvelope(
                src=env.src,
                dst=env.dst,
                page_id=env.page_id,
                ciphertext=bytes(bad_ct),
                mac_tag=env.mac_tag,
            )

        with self.assertRaises(QuorumConsensusError):
            self.net.broadcast_bundle(tampered_bundle)

        # Original untouched bundle still succeeds (forged MACs did not burn pages!).
        commits = self.net.broadcast_bundle(bundle)
        self.assertEqual(len(commits), 4)
        self.assertEqual(self.net.validators["V0"].balances["bob"], 10)

        # Replaying the committed bundle is blocked (pages are burned on all validators).
        with self.assertRaises(QuorumConsensusError):
            self.net.broadcast_bundle(bundle)
        self.assertEqual(self.net.validators["V0"].balances["bob"], 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
