# Vernam (`VRNM`)

**Vernam (`VRNM`)** is a high-speed, decentralized, **100% information-theoretically secure** cryptocurrency core, CLI wallet, **Proof-of-Pad (`PoP`)** entropy mining engine, and multi-VPS P2P testnet written in **zero-dependency Rust** (plus a Python research lab in `python-lab/`).

Security rests solely on **Shannon information theory** and **quantum mechanics** — **zero computational assumptions** (no SHA-256, RSA, ECDSA, Ed25519, AES, or zk-SNARKs anywhere in the core stack). That makes `VRNM` mathematically immune to **quantum computers (Shor's / Grover's)**, **"Harvest Now, Decrypt Later"**, and even **$P = NP$** (when paired with physical QRNG/QKD hardware).

---

## Live Release Benchmarks (`cargo run --release -- bench`, Intel i9-11900)

| Subsystem | v0.5 Turbo Speed | Notes |
|---|---|---|
| **Turbo Express Lane (`VRNM-Fast`) 4-Val BFT** | **~85.6M TPS** (`0.117 ms/block`) | 4 persistent validator threads, 2-phase BFT + 24 real OTP/CW votes/block + 4-way pipelined CW block seals + zero-copy `Arc<[TurboTx]>` |
| **Turbo Shielded Lane (`VRNM-Private`) IT-MPC** | **~1.65M TPS** | Beaver Square Pairs (`x^2 - x`) + Shared-Factor Beaver Stars + Schwartz–Zippel RLC (`< 2^-121` soundness, `178 → 66` openings/tx), 64 buckets, zero zk-SNARKs |
| **AVX-512F OTP XOR** | **~51.0 GB/s** | Runtime-dispatched AVX-512F / AVX2 / portable ARM64 fallback |
| **4-Way Fused Carter–Wegman MAC** (`F_(2^127 - 1)`) | **~15.9M ops/sec** (`6.09 GB/s`) | Fused 4-way dot-product over `F_(2^127 - 1)` with runtime BMI2/ADX dispatch |
| **AVX-512 `VPOPCNTDQ` Toeplitz QKD PA** | **~177 Mbps** | Bit-shift-grouped 8-way SIMD 2-universal GF(2) privacy amplification |

---

## 1-Command VPS Testnet Deploy

Deploy a live **Vernam (`VRNM`)** testnet + dark-mode web explorer + faucet + Proof-of-Pad mining UI on any Ubuntu/Debian VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/gpt4omni/vernam/main/deploy/vps-setup.sh | sudo bash
```

### Decentralized Multi-VPS Peer Discovery (Zero Manual IP Lists!)
Users and new miners only need **ONE** seed address — nodes automatically announce themselves and gossip `/p2p/peers` transitively across the network (just like Bitcoin Core's `getaddr`/`addr` & DNS seeds):

```bash
# VPS #1 (Seed Node)
vrnm node --id 0 --bind 0.0.0.0:8080 --advertise <VPS1_IP>:8080

# VPS #2 (Connects only to Seed #1 — auto-discovers everyone else!)
vrnm node --id 1 --bind 0.0.0.0:8080 --advertise <VPS2_IP>:8080 --seed <VPS1_IP>:8080

# Or spin up a 4-container local/VPS P2P mesh in one command:
docker compose -f deploy/docker-compose.multi-node.yml up -d --build
```

Full VPS & multi-node guides: [deploy/DEPLOY_VPS.md](deploy/DEPLOY_VPS.md) and [deploy/JOIN_TESTNET.md](deploy/JOIN_TESTNET.md).

---

## CLI Wallet & Proof-of-Pad (`PoP`) Mining

```bash
export VRNM_NODE="http://<ANY_SINGLE_SEED_IP>:8080"

# Auto-discover every active node IP on the network from one seed
vrnm wallet peers

# Create crash-safe WAL-persisted wallets (0600 permissions)
vrnm wallet create --name alice
vrnm wallet create --name bob

# Claim testnet VRNM, send Express & Shielded transfers, inspect Shamir shares
vrnm wallet faucet --name alice
vrnm wallet send --from alice --to bob --amount 25
vrnm wallet send-private --from alice --to bob --amount 15
vrnm wallet balance --name bob

# Run a verified Proof-of-Pad (PoP) entropy & Beaver-triple mining audit epoch
vrnm wallet pop-mine
vrnm pop-mine   # standalone local Proof-of-Pad audit demo
```

---

## Core Modules (Zero External Crates)

| File | Role |
|---|---|
| `src/field.rs` | Division-free Mersenne prime field $\mathbb{F}_{2^{127}-1}$, volatile zeroization, constant-time `ct_eq_16` |
| `src/otp.rs` | Word-level XOR OTP, injective Carter–Wegman one-time MAC, crash-safe `fsync` `WalPadBook` with on-disk zeroing |
| `src/bft.rs` | 2-phase batched BFT (`PrePrepare → Prepare → Commit`), view-change rotation, offline quorum sync |
| `src/p2p_node.rs` | Real multi-VPS P2P validator daemon with seed bootstrap, transitive `/p2p/peers` gossip, tx/block propagation & auto catch-up sync |
| `src/pop_mining.rs` | Verified **Proof-of-Pad (`PoP`)** entropy mining (monobit + runs tests, Beaver-triple spot-checks, QKD QBER/decoy audits, interactive Carter–Wegman commitments & auto-slashing) |
| `src/privacy_mpc.rs` | Precomputed `LagrangeCache`, offline `BeaverPool`, `ShardedPrivateLedger`, sender-anonymous rounds, PSS & `CoverFrame` |
| `src/fast_engine.rs` | Bitcoin Core BIP-152 compact relay, O(1) `IndexedLedger`, stack `[u128; 4]` multi-core parallel Express & Shielded engines |
| `src/qkd.rs` | Bit-sliced BB84 + Weak/Vacuum Decoy-State QKD (QBER + PNS detection), `POPCNT` Toeplitz PA, `BufferedQkdPool`, ETSI 014 & QRNG traits |
| `src/tokenomics.rs` | 21M `VRNM` halving cap, Proof-of-Pad rewards, 80/20 pad-burn fees, flat-bond validator slashing |
| `src/wallet.rs` | Crash-safe disk-persisted `VernamWallet` + zero-dependency auto-discovering HTTP/1.1 `WalletRpcClient` |
| `src/testnet_server.rs` & `src/explorer_ui.rs` | Live HTTP/1.1 testnet daemon + dark-mode web explorer (P2P peer mesh, Proof-of-Pad mining UI, faucet, Shamir share inspector) |

## Running Tests & Benchmarks Locally

```bash
cargo test --release
cargo run --release -- bench
cargo run --release -- pop-mine
```
