"""Interactive walkthrough of OTPCoin: transfers + live attack simulations."""

from __future__ import annotations

import json

from otp_coin import (
    AuthenticationError,
    InsufficientFundsError,
    Mint,
    ReplayOrReuseError,
    TransactionEnvelope,
)


def main() -> None:
    mint = Mint()
    alice = mint.register_wallet("alice", pad_pages=4)
    bob = mint.register_wallet("bob", pad_pages=4)

    print("=== 1. Genesis Mint ===")
    mint.mint_coins("alice", 100)
    print(f"Balances: alice={mint.balance_of('alice')}, bob={mint.balance_of('bob')}")
    print(f"Alice unused OTP pages: {alice.remaining_txs}\n")

    print("=== 2. OTP-Encrypted Transfer (Alice -> Bob: 25 coins) ===")
    env1 = alice.create_transfer("bob", 25, memo="first OTP coin tx")
    print(f"Wire envelope: sender={env1.sender}, page_id={env1.page_id}")
    print(f"Ciphertext (hex): {env1.ciphertext.hex()[:48]}...")
    print(f"One-time MAC    : {env1.mac_tag.hex()}")
    entry = mint.submit_transaction(env1)
    print(f"Confirmed tx #{entry.tx_id}: {entry.sender} -> {entry.recipient} ({entry.amount} coins)")
    print(f"Balances: alice={mint.balance_of('alice')}, bob={mint.balance_of('bob')}\n")

    print("=== 3. Attack Simulation: Replay Attack ===")
    try:
        mint.submit_transaction(env1)
    except ReplayOrReuseError as exc:
        print(f"BLOCKED replay attack -> {exc}\n")

    print("=== 4. Attack Simulation: OTP Bit-Flip Malleability ===")
    env2 = alice.create_transfer("bob", 10, memo="tea")
    plain_guess = json.dumps(
        {"sender": "alice", "recipient": "bob", "amount": 10, "memo": "tea"},
        separators=(",", ":"),
    ).encode("utf-8")
    digit_pos = plain_guess.index(b'"amount":10') + len(b'"amount":')
    tampered = bytearray(env2.ciphertext)
    tampered[digit_pos] ^= ord("1") ^ ord("9")  # Flip 10 -> 90 in ciphertext!
    tampered_env = TransactionEnvelope(
        sender=env2.sender,
        page_id=env2.page_id,
        ciphertext=bytes(tampered),
        mac_tag=env2.mac_tag,
    )
    try:
        mint.submit_transaction(tampered_env)
    except AuthenticationError as exc:
        print(f"BLOCKED ciphertext bit-flip (10 -> 90) -> {exc}")
    # Original untampered transaction still succeeds cleanly:
    entry2 = mint.submit_transaction(env2)
    print(f"Original untampered tx #{entry2.tx_id} succeeded: {entry2.amount} coins\n")

    print("=== 5. Attack Simulation: Overdraft ===")
    env3 = alice.create_transfer("bob", 500, memo="too much")
    try:
        mint.submit_transaction(env3)
    except InsufficientFundsError as exc:
        print(f"BLOCKED overdraft -> {exc}\n")

    print("=== Final Ledger ===")
    for item in mint.ledger:
        print(
            f"  #{item.tx_id} | {item.sender:>5} -> {item.recipient:<5} | "
            f"{item.amount:>3} coins | page={item.page_id:>2} | memo='{item.memo}'"
        )
    print(f"Final balances: alice={mint.balance_of('alice')}, bob={mint.balance_of('bob')}")
    print(f"Alice unused OTP pages left: {alice.remaining_txs}")


if __name__ == "__main__":
    main()
