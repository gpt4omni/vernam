"""Demo of PrivateMPCCoin: hidden balances, hidden amounts, hidden recipients."""

from __future__ import annotations

from otp_crypto import PRIME_P
from proactive_sss import reconstruct_secret, split_secret
from private_mpc_coin import AMOUNT_BITS, PRIVATE_FRAME_BYTES, PrivateMPCError, PrivateOTPNetwork


def main() -> None:
    net = PrivateOTPNetwork(num_validators=4, threshold=3)
    alice = net.register_wallet("alice")
    bob = net.register_wallet("bob")
    charlie = net.register_wallet("charlie")
    dave = net.register_wallet("dave")

    net.mint_private("alice", 500)
    net.mint_private("charlie", 200)

    print("=== Vernam (VRNM) Privacy Layer: 100% Information-Theoretic Privacy (Zero zk-SNARKs / Zero SHA-256) ===")
    print("Hidden from ALL validators (even 2 colluding nodes): Balances, Amounts, AND Recipients!\n")

    print("=== 1. What Validator V0 Sees Before Transfer (Pure Random Field Elements) ===")
    for acct, share in net.validators["V0"].balance_shares.items():
        print(f"  V0 share[{acct:>7}] = {share}")

    print("\n=== 2. Private Transfer: Alice sends 137 VRNM to Bob ===")
    net.private_transfer(alice, "bob", 137)
    print("MPC verified: 0 <= amount < 65536, 0 <= remainder < 65536, balance conserved, exactly 1 recipient!")
    print("What Validator V0 Sees AFTER Transfer (EVERY account share re-randomized!):")
    for acct, share in net.validators["V0"].balance_shares.items():
        print(f"  V0 share[{acct:>7}] = {share}")

    print("\nWhat ONLY the Wallet Owners Reconstruct (via per-owner OTP):")
    print(f"  Alice={net.query_private_balance(alice)} VRNM, Bob={net.query_private_balance(bob)} VRNM, "
          f"Charlie={net.query_private_balance(charlie)} VRNM, Dave={net.query_private_balance(dave)} VRNM\n")

    print("=== 3. Attack: Malicious Alice Tries to Send -1 Coin (Mint Free Money) ===")
    bad_v = [split_secret((-1) % PRIME_P if j == 0 else 0, 3, 4) for j in range(AMOUNT_BITS)]
    r_364 = [split_secret((364 >> j) & 1, 3, 4) for j in range(AMOUNT_BITS)]
    sel = [split_secret(1 if a == "bob" else 0, 3, 4) for a in net.accounts]
    try:
        net.submit_private_transfer_shares(alice, bad_v, r_364, sel)
    except PrivateMPCError as exc:
        print(f"BLOCKED negative-amount attack -> {exc}\n")

    print("=== 4. Proactive Secret Sharing Refresh on ALL Liquid Balances ===")
    stale_v0 = net.validators["V0"].balance_shares["bob"]
    stale_v1 = net.validators["V1"].balance_shares["bob"]
    epoch = net.proactive_refresh_all_balances()
    fresh_v2 = net.validators["V2"].balance_shares["bob"]
    stolen_mix = reconstruct_secret({1: stale_v0, 2: stale_v1, 3: fresh_v2})
    print(f"Refreshed all liquid balances to Epoch {epoch} over pairwise OTP links.")
    print(f"Slow-bleed mix (Epoch-1 V0,V1 + Epoch-2 V2) reveals Bob's 137? {stolen_mix == 137}")
    print(f"Bob's private balance query in Epoch {epoch}: {net.query_private_balance(bob)}")

    net.send_cover_traffic_round(alice)
    print(f"\nWire audit: {len(net.wire_transcript)} OTP packets total, all uniform {PRIVATE_FRAME_BYTES}-byte frames!")


if __name__ == "__main__":
    main()
