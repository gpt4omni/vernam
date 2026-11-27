"""CLI demo of the decentralized Lamport OTS + OTP-memo UTXO coin."""

from __future__ import annotations

import secrets

from decentralized_coin import ConsensusError, Node, Transaction, TxOutput, UTXOWallet


def main() -> None:
    node_a = Node("Node-A", difficulty=2)
    node_b = Node("Node-B", difficulty=2)

    alice = UTXOWallet("alice")
    bob = UTXOWallet("bob")
    mallory = UTXOWallet("mallory")

    print("=== 1. Independent Mining on Node-A (No Central Mint) ===")
    alice_addr = alice.new_address()
    b1 = node_a.mine_block(alice_addr)
    print(f"Mined Block #{b1.index} (nonce={b1.nonce}, hash={b1.block_hash[:16]}...)")
    print(f"Alice balance on Node-A: {alice.balance(node_a)} coins (addr={alice_addr[:12]}...)\n")

    print("=== 2. Decentralized Transfer + Fresh One-Time Change + OTP Memo ===")
    bob_addr = bob.new_address()
    shared_otp = secrets.token_bytes(64)
    tx = alice.create_transaction(
        node_a,
        recipient_address=bob_addr,
        amount=20,
        memo="rent split - private OTP memo",
        shared_otp=shared_otp,
    )
    print(f"Tx {tx.tx_id[:16]}... signed with 256-hash Lamport one-time signature")
    print(f"  Output 0 -> Bob ({tx.outputs[0].amount} coins, addr={tx.outputs[0].address[:12]}...)")
    print(f"  On-chain OTP memo ciphertext: {tx.outputs[0].otp_memo_hex[:40]}...")
    print(f"  Output 1 -> Alice NEW change addr ({tx.outputs[1].amount} coins, addr={tx.outputs[1].address[:12]}...)")

    node_a.submit_transaction(tx)
    b2 = node_a.mine_block(bob.new_address())
    print(f"Mined Block #{b2.index} (nonce={b2.nonce}, hash={b2.block_hash[:16]}...)\n")

    print("=== 3. Peer Sync: Node-B Independently Verifies Entire Chain ===")
    node_b.sync_from(node_a)
    print(f"Node-B synced to height #{node_b.tip.index}!")
    print(f"Node-B balances -> Alice: {alice.balance(node_b)}, Bob: {bob.balance(node_b)}")
    print(f"Bob decrypted on-chain OTP memo: '{bob.decrypt_memo(tx.outputs[0], shared_otp)}'\n")

    print("=== 4. Attack Simulation: Output Tampering ===")
    tx2 = alice.create_transaction(node_b, bob.new_address(), 10)
    tampered = Transaction(
        inputs=tx2.inputs,
        outputs=[TxOutput(amount=10, address=mallory.new_address()), tx2.outputs[1]],
    )
    try:
        node_b.submit_transaction(tampered)
    except ConsensusError as exc:
        print(f"BLOCKED tampering -> {exc}")

    print("\n=== 5. Attack Simulation: Double-Spend ===")
    try:
        node_b.submit_transaction(tx)
    except ConsensusError as exc:
        print(f"BLOCKED double-spend -> {exc}")

    print("\n=== 6. Attack Simulation: Sending to Burned One-Time Address ===")
    bad_reuse_tx = bob.create_transaction(node_b, alice_addr, 5)
    try:
        node_b.submit_transaction(bad_reuse_tx)
    except ConsensusError as exc:
        print(f"BLOCKED address reuse -> {exc}")


if __name__ == "__main__":
    main()
