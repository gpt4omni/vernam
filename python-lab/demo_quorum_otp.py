"""CLI demo of QuorumOTPCoin: decentralized 4-validator coin using 100% pure OTP."""

from __future__ import annotations

from quorum_otp_coin import (
    FRAME_BYTES,
    CanonicalTx,
    QuorumConsensusError,
    QuorumNetwork,
)


def main() -> None:
    net = QuorumNetwork(num_validators=4)  # N=4, f=1, quorum=3
    alice = net.register_wallet("alice", pad_pages=6)
    bob = net.register_wallet("bob", pad_pages=6)
    charlie = net.register_wallet("charlie", pad_pages=6)
    net.genesis_mint("alice", 100)

    print("=== QuorumOTPCoin: 4 Independent Validators, 100% Pure OTP + One-Time MAC ===")
    print(f"Quorum threshold: {net.quorum_size} of {len(net.validators)} (tolerates f={net.f} Byzantine/offline node)")
    print("Computational crypto used: NONE (no SHA-256, RSA, ECDSA, or AES)\n")

    print("=== 1. Valid Transfer (Alice -> Bob: 35 coins) ===")
    bundle = alice.create_transfer_bundle("bob", 35, memo="quantum-proof transfer")
    commits = net.broadcast_bundle(bundle)
    print(f"Committed on {len(commits)}/4 validators -> Alice={net.validators['V0'].balances['alice']}, Bob={net.validators['V0'].balances['bob']}")
    print(f"Wire packets observed by eavesdropper: {len(net.wire_transcript)} packets, all fixed {FRAME_BYTES}-byte OTP frames")
    print(f"Sample wire ciphertext (V0): {bundle['V0'].ciphertext.hex()[:48]}...\n")

    print("=== 2. Byzantine Attack: Compromised Validator V0 Tries to Forge Spend ===")
    forged = CanonicalTx(sender="alice", recipient="charlie", amount=65, page_id=1, memo="heist")
    try:
        net.broadcast_bundle(bundle={}, forged_validator_votes={"V0": forged})
    except QuorumConsensusError as exc:
        print(f"BLOCKED forged spend by V0 -> {exc}")
        print(f"Honest V1 balances unchanged: Alice={net.validators['V1'].balances['alice']}, Charlie={net.validators['V1'].balances['charlie']}\n")

    print("=== 3. Fault Tolerance: Validator V3 Goes Offline ===")
    net.validators["V3"].online = False
    bundle2 = alice.create_transfer_bundle("bob", 15, memo="v3 is down")
    commits2 = net.broadcast_bundle(bundle2)
    print(f"Still reached quorum ({len(commits2)}/3 online validators)!")
    print(f"Balances on V0..V2: Alice={net.validators['V0'].balances['alice']}, Bob={net.validators['V0'].balances['bob']}\n")
    net.validators["V3"].online = True

    print("=== 4. Double-Spend / Equivocation Attack (Split 2 vs 2) ===")
    split = {
        "V0": alice.create_for_validator("V0", "bob", 50, memo="fork-A"),
        "V1": alice.create_for_validator("V1", "bob", 50, memo="fork-A"),
        "V2": alice.create_for_validator("V2", "charlie", 50, memo="fork-B"),
        "V3": alice.create_for_validator("V3", "charlie", 50, memo="fork-B"),
    }
    try:
        net.broadcast_bundle(split)
    except QuorumConsensusError as exc:
        print(f"BLOCKED split double-spend -> {exc}")
        print(f"Final honest balances: Alice={net.validators['V0'].balances['alice']}, Bob={net.validators['V0'].balances['bob']}, Charlie={net.validators['V0'].balances['charlie']}")


if __name__ == "__main__":
    main()
