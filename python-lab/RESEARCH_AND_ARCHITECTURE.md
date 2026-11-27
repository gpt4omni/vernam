# Vernam (`VRNM`) — Research & Architecture Notes

## Why Standard Cryptocurrencies Are Vulnerable to the Future
1. **Shor's Algorithm (Quantum Computers):** Breaks elliptic-curve digital signatures (`ECDSA`, `Ed25519`) and `RSA`, allowing theft of funds and transaction forgery.
2. **Grover's Algorithm:** Halves the effective security bits of cryptographic hash functions and symmetric ciphers.
3. **"Harvest Now, Decrypt Later":** Any ciphertext relying on computational hardness recorded today can be decrypted decades later if math breakthroughs or quantum hardware advance.
4. **Slow-Bleed ("Mobile") Adversaries:** Even threshold custody keys can be stolen if an attacker compromises servers one by one over months or years.

## Research Foundations Implemented Here
| Threat | Research Primitive | Implementation |
|---|---|---|
| Future compute / quantum decryption | **Shannon One-Time Pad (XOR)** on fixed 256-byte frames (hides even message length) | `otp_crypto.py`, `quorum_otp_coin.py` |
| OTP malleability & forgery without RSA/ECDSA | **Carter–Wegman Universal Hash One-Time MAC** over prime field $\mathbb{F}_{2^{127}-1}$ (unconditionally unforgeable with forgery probability $\le d / 2^{127}$) | `otp_crypto.py` |
| Single point of trust (Mint) without public keys | **Unconditionally Secure BFT Quorum ($N = 3f + 1$)** modeled on Pease–Shostak–Lamport & Kiktenko et al. (*Quantum-Secured Blockchain*, 2018) using per-validator & pairwise OTP channels | `quorum_otp_coin.py` |
| OTP key exhaustion & distribution | **BB84 Quantum Key Distribution (QKD)** with **QBER eavesdropper detection** ($> 11\%$ abort) + **Toeplitz 2-Universal Hash Privacy Amplification** over $\text{GF}(2)$, authenticated by existing OTP+MAC pages | `qkd_bb84.py`, `future_otp_coin.py` |
| Long-term custody & slow-bleed compromise | **Shamir's Secret Sharing (SSS)** + **Proactive Secret Sharing (PSS)** epoch refreshes over pairwise OTP channels ($z_j(0) = 0$ zero-polynomial updates) | `proactive_sss.py`, `future_otp_coin.py` |

## Honest Boundaries (Fundamental Laws of Information Theory)
* **No permissionless pure-OTP coin:** Shannon's theorem proves perfect secrecy requires pre-shared secret randomness; publicly verifiable permissionless signatures (like Lamport OTS in `lamport_ots.py`) can be post-quantum, but are computational rather than information-theoretic.
* **Real hardware requirements for production:** Replace Python's `secrets` CSPRNG with a certified **Quantum Random Number Generator (QRNG)** and swap the simulated BB84 module in `qkd_bb84.py` for physical QKD fiber/satellite transceivers (ETSI GS QKD 014 KMS API).
* **Full validator-side balance privacy:** Wire traffic is perfectly secret against any eavesdropper and vault secrets are hidden from $< t$ validators; hiding even *liquid* balances from individual honest validators requires adding information-theoretic MPC comparison (BGW protocol over $\mathbb{F}_p$).
