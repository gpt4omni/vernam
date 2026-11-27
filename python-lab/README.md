# Vernam (`VRNM`)

**Vernam (`VRNM`)** is an experimental, information-theoretically secure cryptocurrency prototype built around **One-Time Pads (OTP)** — designed for eternal secrecy and quantum resistance with **zero computational cryptographic assumptions** (no RSA, ECDSA, AES, SHA-256, or zk-SNARKs in the core OTP stack).

## Architecture Tiers Included

1. **Mint-Verified OTP Coin** (`otp_coin.py`, `demo.py`)
   * Strict single-use XOR One-Time Pad + Carter–Wegman one-time MAC over $\mathbb{F}_{2^{127}-1}$.
   * Demonstrates why raw OTP fails against bit-flip malleability and how one-time MACs + page burning stop tampering and replays.
2. **Permissionless Post-Quantum UTXO Variant** (`lamport_ots.py`, `decentralized_coin.py`, `demo_decentralized.py`)
   * Lamport One-Time Signatures (hash-based, single-use change addresses) + optional on-chain OTP memos + PoW multi-node sync.
3. **Decentralized Pure-OTP BFT Quorum** (`quorum_otp_coin.py`, `demo_quorum_otp.py`)
   * $N = 3f + 1$ independent validators (`V0..V3`, quorum `3`) using fixed-size 256-byte OTP frames and pairwise OTP consensus links.
4. **Future-Resistant `VRNM` Core** (`qkd_bb84.py`, `proactive_sss.py`, `future_otp_coin.py`, `demo_future_otp.py`)
   * Authenticated **BB84 QKD** pad replenishment with **QBER eavesdropper detection** ($> 11\%$ abort) + **Toeplitz 2-universal hash privacy amplification** over $\text{GF}(2)$.
   * **Shamir Secret-Shared Cold Vaults** with **Proactive Secret Sharing (PSS)** epoch refreshes over pairwise OTP channels.
5. **Fully Confidential `VRNM` Privacy Layer** (`private_mpc_coin.py`, `demo_private_mpc.py`)
   * **Hidden liquid balances**, **hidden transfer amounts**, and **hidden recipients** via $(t=3, N=4)$ Shamir shares + one-time Beaver-triple MPC range & one-hot proofs over pairwise OTP links.
   * Liquid-balance PSS refreshes + uniform 4096-byte OTP cover traffic.

## Quick Start

```bash
cd /home/areq/otp-coin-test

# Run all 34 automated security & protocol tests
python3 -m unittest discover -v

# Run the flagship Vernam (VRNM) demos
python3 demo_future_otp.py     # BB84 QKD + Toeplitz PA + Proactive Vaults + BFT
python3 demo_private_mpc.py    # Hidden balances, hidden amounts, hidden recipients
```

See [RESEARCH_AND_ARCHITECTURE.md](RESEARCH_AND_ARCHITECTURE.md) for the cryptographic foundations and production hardware roadmap.
