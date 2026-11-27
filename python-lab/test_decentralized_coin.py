"""Tests for the decentralized Lamport OTS + OTP-memo UTXO coin."""

from __future__ import annotations

import secrets
import unittest

from decentralized_coin import (
    BLOCK_REWARD,
    ConsensusError,
    Node,
    Transaction,
    TxInput,
    TxOutput,
    UTXOWallet,
)
from lamport_ots import LamportKeyPair, OneTimeKeyReuseError, verify_lamport_signature


class TestDecentralizedOTSCoin(unittest.TestCase):
    def setUp(self) -> None:
        self.node_a = Node("node-A", difficulty=2)
        self.node_b = Node("node-B", difficulty=2)
        self.alice = UTXOWallet("alice")
        self.bob = UTXOWallet("bob")
        self.mallory = UTXOWallet("mallory")

        # Alice mines block 1 on Node A to earn 50 coins to a fresh one-time address.
        self.alice_addr_0 = self.alice.new_address()
        self.node_a.mine_block(self.alice_addr_0)

    def test_decentralized_transfer_with_fresh_change_and_otp_memo(self) -> None:
        bob_addr = self.bob.new_address()
        shared_otp = secrets.token_bytes(64)

        tx = self.alice.create_transaction(
            self.node_a,
            recipient_address=bob_addr,
            amount=18,
            memo="secret invoice #42",
            shared_otp=shared_otp,
        )
        self.node_a.submit_transaction(tx)
        self.node_a.mine_block(self.bob.new_address())

        # Node B independently verifies the entire chain from scratch (no central Mint!).
        synced = self.node_b.sync_from(self.node_a)
        self.assertTrue(synced)
        self.assertEqual(len(self.node_b.chain), 3)

        # Alice got 50 - 18 = 32 change on a brand-new address; Bob got 18 + 50 (mining reward).
        self.assertEqual(self.alice.balance(self.node_b), 32)
        self.assertEqual(self.bob.balance(self.node_b), 18 + BLOCK_REWARD)

        # Verify on-chain OTP memo is opaque ciphertext on the ledger, but Bob decrypts it.
        bob_output = tx.outputs[0]
        self.assertNotIn(b"secret", bytes.fromhex(bob_output.otp_memo_hex))
        self.assertEqual(self.bob.decrypt_memo(bob_output, shared_otp), "secret invoice #42")

        # Alice can spend her fresh change output too!
        tx2 = self.alice.create_transaction(self.node_b, self.bob.new_address(), 12)
        self.node_b.submit_transaction(tx2)
        self.node_b.mine_block(self.alice.new_address())
        self.assertEqual(self.alice.balance(self.node_b), 20 + BLOCK_REWARD)
        self.assertEqual(self.bob.balance(self.node_b), 18 + BLOCK_REWARD + 12)

    def test_tampering_with_signed_transaction_rejected(self) -> None:
        tx = self.alice.create_transaction(self.node_a, self.bob.new_address(), 20)
        # Mallory tries to redirect Alice's output to Mallory's address without re-signing.
        tampered = Transaction(
            inputs=tx.inputs,
            outputs=[
                TxOutput(amount=20, address=self.mallory.new_address()),
                tx.outputs[1],
            ],
        )
        with self.assertRaises(ConsensusError):
            self.node_a.submit_transaction(tampered)

    def test_double_spend_rejected_in_mempool_and_on_chain(self) -> None:
        tx1 = self.alice.create_transaction(self.node_a, self.bob.new_address(), 30)
        self.node_a.submit_transaction(tx1)

        # Attempt to submit the exact same tx again in mempool -> rejected.
        with self.assertRaises(ConsensusError):
            self.node_a.submit_transaction(tx1)

        # Mine tx1 into block 2, then attempt to replay it -> rejected.
        self.node_a.mine_block(self.bob.new_address())
        with self.assertRaises(ConsensusError):
            self.node_a.submit_transaction(tx1)

    def test_forgery_with_wrong_key_rejected(self) -> None:
        outpoint = next(iter(self.node_a.utxo_set.keys()))
        fake_kp = LamportKeyPair.generate()
        outputs = [TxOutput(amount=50, address=self.mallory.new_address())]
        skeleton = Transaction(
            inputs=[TxInput(outpoint[0], outpoint[1], [], [])],
            outputs=outputs,
        )
        sig = fake_kp.sign(skeleton.signing_payload())
        forged_tx = Transaction(
            inputs=[TxInput(outpoint[0], outpoint[1], fake_kp.public_key, sig)],
            outputs=outputs,
        )
        with self.assertRaises(ConsensusError):
            self.node_a.submit_transaction(forged_tx)

    def test_address_reuse_blocked_by_consensus(self) -> None:
        # Spend Alice's original UTXO (burning alice_addr_0).
        tx1 = self.alice.create_transaction(self.node_a, self.bob.new_address(), 50)
        self.node_a.submit_transaction(tx1)
        self.node_a.mine_block(self.bob.new_address())

        # Bob tries to send coins back to Alice's already-spent one-time address -> rejected!
        bad_tx = self.bob.create_transaction(self.node_a, self.alice_addr_0, 10)
        with self.assertRaises(ConsensusError):
            self.node_a.submit_transaction(bad_tx)

    def test_lamport_key_blocks_reuse_and_leaks_if_forced(self) -> None:
        kp = LamportKeyPair.generate()
        sig1 = kp.sign(b"tx-one")
        self.assertTrue(verify_lamport_signature(b"tx-one", kp.address, kp.public_key, sig1))

        # Local wallet safety blocks accidental reuse.
        with self.assertRaises(OneTimeKeyReuseError):
            kp.sign(b"tx-two")

        # If someone unsafely forces reuse, both preimages are exposed wherever the
        # two message digests differ (~50% of the 256 bit positions!).
        sig2 = kp.sign(b"tx-two", allow_unsafe_reuse=True)
        compromised_pairs = sum(1 for a, b in zip(sig1, sig2) if a != b)
        self.assertGreater(compromised_pairs, 90)  # Expected ~128 of 256 pairs leaked!


if __name__ == "__main__":
    unittest.main(verbosity=2)
