# Vernam (`VRNM`)

**Vernam (`VRNM`)** is a high-speed, **100% information-theoretically secure** cryptocurrency core written in **zero-dependency Rust** (with an accompanying Python research lab in `python-lab/`).

Security rests solely on **Shannon information theory** and **quantum mechanics** — **zero computational assumptions** (no SHA-256, RSA, ECDSA, Ed25519, AES, or zk-SNARKs anywhere in the core stack). That makes `VRNM` mathematically immune to **quantum computers (Shor's / Grover's)**, **"Harvest Now, Decrypt Later"**, and even **$P = NP$** (when paired with physical QRNG/QKD hardware).

---

## Live Release Benchmarks (Single Machine, `cargo run --release`)

| Subsystem | Measured Throughput / Latency | Notes |
|---|---|---|
| **OTP + Carter–Wegman MAC** (`F_(2^127 - 1)`) | **~1.36M ops/sec** (~698 MB/s) | Fixed 256-byte frames, division-free `u128` Mersenne math, volatile `Drop` zeroize |
| **Express Lane (`VRNM-Fast`) 2-Phase BFT** | **~982k TPS** (~1.02 ms/block) | 1,000-tx binary batches (`32 B/tx`) across 4 validators (`PrePrepare -> Prepare -> Commit`) |
| **Shielded Lane (`VRNM-Private`) IT-MPC** | **~42k TPS** | Hidden balances, hidden amounts (16-bit range proofs), hidden recipients ($K=16$ bucket), zero zk-SNARKs |
| **POPCNT `u64` Toeplitz Privacy Amplification** | **~52.8 Mbps** | Hardware `POPCNT` 2-universal GF(2) hashing for BB84 + Decoy-State QKD |

---

## Core Architecture (5 Rust Pillars)

1. **Zeroized OTP & Crash-Safe WAL (`src/field.rs`, `src/otp.rs`)**
   * Division-free Mersenne prime field $\mathbb{F}_{2^{127}-1}$ (`u128` bitshift reduction) & constant-time 16-byte tag verification.
   * Word-level `u64` XOR One-Time Pad + injective Carter–Wegman one-time MAC (`<= d / 2^127` unconditional forgery bound).
   * Volatile RAM zeroization on `Drop` (`write_volatile` + `compiler_fence`) and crash-safe `WalPadBook` (`0600` files, `fsync` write-ahead burn log + on-disk zeroing before returning any popped page).
2. **Express Lane: 2-Phase Batched BFT & Web-of-Trust PoP (`src/bft.rs`)**
   * Compact 32-byte `BinaryTx` batches with full `PrePrepare -> Prepare -> Commit` BFT across $N = 3f + 1$ unweighted validators (1 validator = 1 equal vote).
   * Authenticated view-change leader rotation, offline validator catch-up sync via quorum certificates, dedicated single-use Carter–Wegman block sealing, and **in-person Web-of-Trust Proof of Personhood** (no iris biometrics).
3. **Shielded Lane: Sharded IT-MPC Privacy (`src/privacy_mpc.rs`)**
   * Precomputed `LagrangeCache` (zero online `inv_mod`) with degree-$(t-1)$ consistency checking.
   * Offline single-use `BeaverPool`, sharded $O(1)$ anonymity buckets (`ShardedPrivateLedger`), sender-anonymous lockstep bucket rounds, **Proactive Secret Sharing (PSS)** liquid-balance epoch refreshes, and constant-rate 256-byte `CoverFrame` traffic.
4. **Quantum Key Distribution & Entropy (`src/qkd.rs`)**
   * 64-photon bit-sliced **BB84 + Weak/Vacuum Decoy-State QKD** detecting both intercept-resend eavesdroppers (`QBER > 11%`) and Photon-Number-Splitting (PNS) attacks.
   * Multi-threaded pre-buffered `BufferedQkdPool` ring buffer + pluggable `EntropySource` (`HardwareQrngAdapter`) and ETSI GS QKD 014-style `QkdKeyProvider` traits.
5. **Proof-of-Pad Tokenomics & Slashing (`src/tokenomics.rs`)**
   * Hard `21,000,000 VRNM` halving cap (`1 VRNM = 10^8 vern`).
   * Anti-plutocracy **Proof-of-Pad (`PoP`)** rewards (70% equal honest participation + 30% capped entropy/Beaver availability), Express/Shielded 80/20 pad-burn fee economics, flat-bond validator vaults with slashing, and one-time IT-MAC audit receipts.

See [DESIGN_UPGRADES.md](DESIGN_UPGRADES.md) for the full design audit and hardware mainnet roadmap.

---

## Quick Start

```bash
# Run all 37 Rust release unit tests
cargo test --release

# Run the integrated showcase & TPS benchmarks
cargo run --release

# (Optional) Run the Python research lab (34 tests)
cd python-lab && python3 -m unittest discover -v
```
