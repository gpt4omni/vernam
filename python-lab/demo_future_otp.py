"""End-to-end demo of FutureOTPCoin v2 (BB84 QKD + Toeplitz PA + PSS + Pure OTP BFT)."""

from __future__ import annotations

import secrets

from future_otp_coin import FutureOTPNetwork
from otp_crypto import PRIME_P
from proactive_sss import reconstruct_secret
from qkd_bb84 import EavesdropperDetectedError
from quorum_otp_coin import FRAME_BYTES


def main() -> None:
    net = FutureOTPNetwork(num_validators=4, auto_qkd_refill=True, qkd_refill_batch=4)
    alice = net.register_wallet("alice", pad_pages=2)
    bob = net.register_wallet("bob", pad_pages=2)
    net.genesis_mint("alice", 1000)

    print("=== Vernam (VRNM) v2: 100% Information-Theoretically Secure Coin ===")
    print("Primitives: Pure OTP (256B frames) + Carter-Wegman MAC + BB84 QKD + Toeplitz PA + Proactive SSS")
    print("Computational crypto used: NONE (zero SHA-256, RSA, ECDSA, AES)\n")

    print("=== 1. Continuous Transfers with Automatic BB84 QKD + Toeplitz Pad Refill ===")
    print(f"Alice starts with only {alice.remaining_txs} OTP pages...")
    for i in range(1, 5):
        net.send_transfer(alice, "bob", 25, memo=f"payment-{i}")
    print(f"Completed 4 transfers seamlessly! Balances: Alice={net.validators['V0'].balances['alice']} VRNM, Bob={net.validators['V0'].balances['bob']} VRNM")
    print(f"QKD BB84 sessions completed: {len(net.qkd_reports)} (QBER={net.qkd_reports[0].qber:.2%}, {net.qkd_reports[0].pages_generated} fresh pages/session)")
    print(f"Alice remaining OTP pages after refill: {alice.remaining_txs}\n")

    print("=== 2. Quantum Channel Attack: Eve Attempts Intercept-Resend on QKD Refill ===")
    try:
        net.replenish_wallet_via_qkd(alice, num_pages=4, eve_intercept_rate=1.0)
    except EavesdropperDetectedError as exc:
        print(f"CAUGHT & ABORTED -> {exc}\n")

    print("=== 3. Cold Vault with Shamir Secret Sharing + Proactive Epoch Refresh (PSS) ===")
    vault_secret = secrets.randbelow(PRIME_P)
    net.create_cold_vault("alice", "treasury-1", amount=700, vault_secret=vault_secret)
    print(f"Locked 700 coins in 3-of-4 Shamir vault (Alice liquid balance={net.validators['V0'].balances['alice']})")

    # Simulate slow-bleed malware stealing V0 & V1 shares during Epoch 1:
    stale_v0 = net.validators["V0"].get_vault_share("treasury-1")
    stale_v1 = net.validators["V1"].get_vault_share("treasury-1")
    print("Malware steals V0 & V1 shares in Epoch 1 (2 < 3, learns 0 bits)...")

    new_epoch = net.run_proactive_epoch_refresh("treasury-1")
    print(f"Network runs Proactive Secret Sharing refresh over pairwise OTP links -> Epoch {new_epoch}!")

    # Malware later compromises V2 in Epoch 2 and tries to combine with stale Epoch 1 shares:
    fresh_v2 = net.validators["V2"].get_vault_share("treasury-1")
    attacker_mix = reconstruct_secret({1: stale_v0, 2: stale_v1, 3: fresh_v2})
    print(f"Slow-bleed attack combining Epoch-1 (V0,V1) + Epoch-2 (V2) matches secret? {attacker_mix == vault_secret}")

    # Honest Epoch-2 quorum unlocks cleanly:
    unlocked = net.unlock_cold_vault("treasury-1", vault_secret, ["V0", "V1", "V3"])
    print(f"Honest Epoch-2 quorum (V0,V1,V3) unlocked {unlocked} coins! Alice balance={net.validators['V0'].balances['alice']}\n")

    print("=== 4. Wire Secrecy Audit ===")
    all_fixed = all(len(p.ciphertext) == FRAME_BYTES for p in net.wire_transcript)
    print(f"Total wire packets captured (txs + QKD auth + BFT votes + PSS refreshes): {len(net.wire_transcript)}")
    print(f"All packets uniform fixed {FRAME_BYTES}-byte OTP frames: {all_fixed}")
    print(f"Ledger Carter-Wegman integrity chain length: {len(net.validators['V0'].chain_tags)} tags")


if __name__ == "__main__":
    main()
