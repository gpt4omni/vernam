# Vernam (`VRNM`)

**Vernam (`VRNM`)** is a high-speed, **100% information-theoretically secure** cryptocurrency core, CLI wallet, and VPS-ready testnet written in **zero-dependency Rust** (plus a Python research lab in `python-lab/`).

Security rests solely on **Shannon information theory** and **quantum mechanics** — **zero computational assumptions** (no SHA-256, RSA, ECDSA, Ed25519, AES, or zk-SNARKs anywhere in the core stack). That makes `VRNM` mathematically immune to **quantum computers (Shor's / Grover's)**, **"Harvest Now, Decrypt Later"**, and even **$P = NP$** (when paired with physical QRNG/QKD hardware).

---

## Live Release Benchmarks (`cargo run --release -- bench`)

| Subsystem | Measured Speed | Notes |
|---|---|---|
| **Express Lane (`VRNM-Fast`) 2-Phase BFT** | **~6.63M TPS** | 4-validator 2-phase BFT + Bitcoin Core BIP-152 compact relay (3x smaller wire frames) + flat O(1) `IndexedLedger` + single-use Carter–Wegman seals |
| **Shielded Lane (`VRNM-Private`) IT-MPC** | **~383k TPS** | Multi-core Sealevel-style sharded $K=16$ buckets, stack `[u128; 4]` zero-alloc Beaver triples, `const` `Lagrange3Of4` (0 `inv_mod`, 0 `mul_mod`), 16-bit range proofs & blinded recipients |
| **Single-Core OTP + Carter–Wegman MAC** | **~1.36M ops/sec** (~698 MB/s) | Fixed 256-byte frames, division-free `u128` Mersenne math (`F_(2^127 - 1)`), volatile `Drop` RAM zeroization |
| **POPCNT `u64` Toeplitz Privacy Amplification** | **~52.8 Mbps** | Hardware `POPCNT` 2-universal GF(2) hashing for BB84 + Decoy-State QKD |

---

## 1-Command VPS Testnet Deploy

Deploy a live 4-validator **Vernam (`VRNM`)** testnet + dark-mode web explorer + interactive faucet on any Ubuntu/Debian VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/gpt4omni/vernam/main/deploy/vps-setup.sh | sudo bash
```

Or deploy via Docker Compose (with optional automatic Let's Encrypt HTTPS via Caddy):

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

Full VPS instructions, systemd hardening, HTTPS setup, and security checklist: [deploy/DEPLOY_VPS.md](deploy/DEPLOY_VPS.md).

---

## CLI Wallet Quick Start

```bash
# Point CLI wallet at your local or VPS testnet node
export VRNM_NODE="http://127.0.0.1:8080"

# Create crash-safe WAL-persisted wallets (0600 permissions)
vrnm wallet create --name alice
vrnm wallet create --name bob

# Claim Express & Shielded testnet VRNM from the faucet
vrnm wallet faucet --name alice

# Send Express (VRNM-Fast) & Shielded (VRNM-Private IT-MPC) transfers
vrnm wallet send --from alice --to bob --amount 25
vrnm wallet send-private --from alice --to bob --amount 15

# Inspect balances + raw 127-bit random Shamir shares on validators
vrnm wallet balance --name bob

# Replenish OTP pads via BB84 QKD & run Proactive Secret Sharing epoch refresh
vrnm wallet refill --name alice --pages 8
vrnm wallet refresh-epoch
```

---

## Core Modules (Zero External Crates)

| File | Role |
|---|---|
| `src/field.rs` | Division-free Mersenne prime field $\mathbb{F}_{2^{127}-1}$, volatile zeroization, constant-time `ct_eq_16` |
| `src/otp.rs` | Word-level XOR OTP, injective Carter–Wegman one-time MAC, crash-safe `fsync` `WalPadBook` with on-disk zeroing |
| `src/bft.rs` | 2-phase batched BFT (`PrePrepare → Prepare → Commit`), view-change rotation, offline quorum sync, Web-of-Trust PoP |
| `src/privacy_mpc.rs` | Precomputed `LagrangeCache`, offline `BeaverPool`, `ShardedPrivateLedger`, sender-anonymous rounds, PSS & `CoverFrame` |
| `src/fast_engine.rs` | Bitcoin Core BIP-152 compact relay, O(1) `IndexedLedger`, stack `[u128; 4]` multi-core parallel Express & Shielded engines |
| `src/qkd.rs` | Bit-sliced BB84 + Weak/Vacuum Decoy-State QKD (QBER + PNS detection), `POPCNT` Toeplitz PA, `BufferedQkdPool`, ETSI 014 & QRNG traits |
| `src/tokenomics.rs` | 21M `VRNM` halving cap, Proof-of-Pad anti-plutocracy rewards, 80/20 pad-burn fees, flat-bond validator slashing |
| `src/wallet.rs` | Crash-safe disk-persisted `VernamWallet` + zero-dependency HTTP/1.1 `WalletRpcClient` |
| `src/testnet_server.rs` | Live multi-validator HTTP/1.1 testnet daemon + embedded dark-mode web explorer & faucet UI |

See [DESIGN_UPGRADES.md](DESIGN_UPGRADES.md) and [BITCOIN_CORE_OPTIMIZATIONS.md](BITCOIN_CORE_OPTIMIZATIONS.md) for deep technical details.

## Running Tests & Benchmarks Locally

```bash
cargo test --release
cargo run --release -- bench
cargo run --release -- testnet --bind 127.0.0.1:8080
```
