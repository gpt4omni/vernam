# Vernam (`VRNM`) v1.2

**Vernam (`VRNM`)** is a zero-admin, 100% decentralized, **information-theoretically secure** cryptocurrency core, split-share networked IT-MPC engine, crash-safe CLI wallet, **Beacon-Paired Proof-of-Pad (`PoP`)** entropy mining engine, self-contained dark-mode explorer, and multi-VPS P2P testnet written in **zero-dependency Rust** (`std` only — `0` external crates in `Cargo.toml`, plus a Python research lab in `python-lab/`).

Security rests exclusively on **Shannon information theory** and **quantum mechanics** over the Mersenne prime field $\mathbb{F}_{2^{127}-1}$ — **zero computational assumptions** (no SHA-256, RSA, ECDSA, Ed25519, AES, VDFs, BLS, or zk-SNARKs anywhere in the core stack). When paired with physical QRNG/QKD hardware, `VRNM` is mathematically immune to **quantum computers (Shor's / Grover's)**, **"Harvest Now, Decrypt Later"**, and even **$P = NP$**.

> **Live Public Testnet Explorer & Faucet:** `http://88.216.62.115:8080/`  
> **Full Technical Whitepaper & Architecture Spec:** [VERNAM_V1_ARCHITECTURE.md](VERNAM_V1_ARCHITECTURE.md)

---

## Feature Highlights (`v1.0` → `v1.2.0`)

* **Zero External Crates & Zero Computational Cryptography:** Compiles 100% offline with Rust `std` only (`Cargo.toml` has zero dependencies) and zero external CDN assets in the embedded web explorer.
* **Dual-Lane Information-Theoretic Settlement:**
  * **Express Lane (`VRNM-Fast`):** 2-phase batched BFT (`PrePrepare → Prepare → Commit`) authenticated by single-use OTP + 4-way pipelined Carter–Wegman MACs over $\mathbb{F}_{2^{127}-1}$ ($\Pr[\text{forgery}] \le d / (2^{127}-1)$).
  * **Shielded Lane (`VRNM-Private`):** Sharded $(t, N)$ Shamir IT-MPC with Beaver Square Pairs, Shared-Factor Beaver Stars, zero-leak $[\rho]\cdot[Z]$ blinded Schwartz–Zippel RLC ($< 2^{-121}$ soundness), Proactive Secret Sharing (PSS), and fixed-size `CoverFrame`s — **zero zk-SNARKs**.
* **Zero-Admin Decentralization (`src/entropy_beacon.rs`, `src/distributed_mpc.rs`, `src/dynamic_quorum.rs`):**
  * Unbiasable, unabortable threshold-Shamir **Distributed Entropy Beacon** ($\Gamma_e$) over pairwise OTP+MAC links (defeats last-revealer aborts via Lagrange fallback reconstruction).
  * True **4-daemon split-share real-TCP IT-MPC** where each validator server holds **only 1 Shamir share**.
  * **Zero-reconstruction dynamic committee resharing** scaling $(t, N) \to (t', N')$ (`4 → 7 → 10`) without ever reconstructing user balances.
* **ASI-Hardened Beacon-Paired Bilateral Proof-of-Pad (`v1.1`–`v1.2`):**
  * Deterministic **Sattolo derangement pairing** derived from $\Gamma_e$ binds each miner to an unpredictable counterparty validator, requiring **co-signed bilateral peer CW-MAC receipts**, interactive commit-then-challenge Monobit + Wald–Wolfowitz Runs + Beaver triple + BB84 QKD audits, and a sliding-window **Cross-Epoch Anti-Replay Registry**.
* **v1.2 Self-Contained Explorer & Onboarding Kit:** Live dark-mode dashboard surfacing fail-closed badges for Threshold Beacon $\Gamma_e$, `BEACON-PAIRED` Sattolo pairing, `CO-SIGNED` bilateral receipts, `anti_replay_tracked_pads`, an **ASI Security Posture** bar, 4-share Shamir inspector, and 1-click Copy-Paste CLI onboarding.

---

## 30-Second Quick Start

### 1. Install `vrnm` (One-Line Zero-Dependency Build)

Requires Rust `>= 1.85` (edition 2024). Installs `vrnm` to `~/.local/bin/vrnm`:

```bash
curl -fsSL https://raw.githubusercontent.com/gpt4omni/vernam/main/deploy/install.sh | bash
```

### 2. Connect to the Live Testnet (`http://88.216.62.115:8080/`)

Open `http://88.216.62.115:8080/` in your browser for the interactive Web Explorer & Faucet, or use the CLI wallet directly:

```bash
export VRNM_NODE="http://88.216.62.115:8080"

# Auto-discover every active node on the P2P mesh from a single seed
vrnm wallet peers

# Create crash-safe WAL-persisted wallets (0600 permissions)
vrnm wallet create --name alice
vrnm wallet create --name bob

# Claim testnet VRNM (Express + Shielded Shamir shares)
vrnm wallet faucet --name alice

# Send an Express 2-phase BFT transfer and a blinded Shielded IT-MPC transfer
vrnm wallet send --from alice --to bob --amount 25
vrnm wallet send-private --from alice --to bob --amount 15

# Inspect Express balance, owner Shielded balance, and raw 127-bit Shamir shares
vrnm wallet balance --name bob

# Trigger a Beacon-Paired Bilateral Proof-of-Pad (PoP) audit & epoch mine
vrnm wallet pop-mine
```

### 3. Join the Decentralized P2P Mesh or Run a PoP Miner

Users and new validators only need **one** seed IP — nodes announce themselves and gossip `/p2p/peers` transitively across the mesh:

```bash
# Join the live testnet as an independent P2P validator node
vrnm node --bind 0.0.0.0:8080 --advertise <YOUR_PUBLIC_IP>:8080 --seed 88.216.62.115:8080

# Or run a 1-core Proof-of-Pad (PoP) entropy & Beaver-triple miner
vrnm miner --cores 1 --node http://88.216.62.115:8080
```

---

## Measured Release Benchmarks

Measured with `cargo run --release -- bench` (`opt-level = 3`, `lto = true`, `codegen-units = 1`, zero external crates):

### Local Workstation (Intel Core i9-11900, 16 Threads, AVX-512)

| Subsystem | Measured Speed | Notes |
| :--- | :--- | :--- |
| **Turbo Express Lane (`VRNM-Fast`) 4-Val BFT** | **77.6M – 85.7M TPS** (`0.117 ms/block`) | 4 persistent validator threads, 2-phase BFT + 24 real OTP/CW votes/block + 4-way pipelined CW block seals + zero-copy `Arc<[TurboTx]>` |
| **Turbo Shielded Lane (`VRNM-Private`) IT-MPC** | **1.46M – 1.66M TPS** | Beaver Square Pairs (`x² - x`) + Shared-Factor Beaver Stars + Schwartz–Zippel RLC (`< 2⁻¹²¹` soundness, `178 → 66` openings/tx), 64 buckets, zero zk-SNARKs |
| **4-Daemon Split-Share Real-TCP Shielded MPC** | **~9,571 TPS** (`~91 µs` p50) | 4 independent TCP validator servers (1 Shamir share each), pairwise OTP+MAC sockets, `0.04 ms` distributed PSS refresh |
| **AVX-512F OTP XOR** | **51.0 – 61.29 GB/s** | Runtime-dispatched `AVX-512F` / `AVX2` / portable ARM64 NEON |
| **4-Way Fused Carter–Wegman MAC** ($\mathbb{F}_{2^{127}-1}$) | **13.6M – 15.9M ops/s** (`6.09 GB/s`) | Fused 4-way dot-product over $\mathbb{F}_{2^{127}-1}$ with runtime `BMI2`/`ADX` dispatch |
| **AVX-512 `VPOPCNTDQ` Toeplitz QKD PA** | **177 – 260 Mbps** | Bit-shift-grouped 8-way SIMD 2-universal GF(2) privacy amplification |

### Live Production ARM64 VPS (`88.216.62.115`, 1 vCore)

| Subsystem | Measured Speed | Notes |
| :--- | :--- | :--- |
| **Turbo Express Lane (`VRNM-Fast`) 4-Val BFT** | **5.29M TPS** | Single ARM64 vCore, 4-validator 2-phase BFT |
| **Turbo Shielded Lane (`VRNM-Private`) IT-MPC** | **166k TPS** | Single ARM64 vCore, full IT-MPC range + recipient blinding |
| **Portable ARM64 NEON OTP XOR** | **22.10 GB/s** | 4× unrolled 64-bit word XOR auto-vectorized to NEON `eor` |
| **Live Cross-Atlantic Shielded Finality** | **~340 ms RTT** (`+1.3 ms` server MPC) | End-to-end live HTTP/1.1 testnet settlement |

---

## ASI Security Hardening Matrix (`v1.1.0` – `v1.2.0`)

| Security Surface | Hardening Mechanism | Enforced Module(s) |
| :--- | :--- | :--- |
| **Field Side Channels & RAM Hygiene** | 100% division-free, branchless `reduce`, `add_mod`, `sub_mod`, `mul_mod`, `ct_select_u128`, constant-time `ct_eq_16`, and volatile RAM zeroization (`write_volatile` + `SeqCst` fences) | `src/field.rs`, `src/otp.rs`, `src/turbo_crypto.rs` |
| **Two-Time-Pad Crash Safety** | Crash-consistent `WalPadBook` (`0600`) appends `[0xB1 \| page_id \| !page_id]`, `fsync`s WAL, zeros disk slot, and `fsync`s data file strictly before transmitting any pad | `src/otp.rs`, `src/wallet.rs` |
| **Beacon Bias & Last-Revealer Abort** | Symmetric bivariate Shamir commit-reveal over pairwise OTP+MAC links; honest quorum reconstructs aborted dealer shares via Lagrange fallback | `src/entropy_beacon.rs` |
| **Self-Mining / Collusion in PoP** | Unpredictable **Sattolo derangement pairing** (`BeaconPairingSchedule`) derived from $\Gamma_e$ + mandatory **co-signed bilateral peer CW-MAC receipts** | `src/pop_mining.rs`, `src/testnet_server.rs` |
| **Pad Recycling & Theft Across Epochs** | Persistent 64-epoch sliding-window **Anti-Replay Registry** (`PopReplayRegistry`) tracks pad fingerprints across epochs and validators | `src/pop_mining.rs`, `src/testnet_server.rs` |
| **Zero-Leak MPC Failure Blinding** | Blinded $[\rho]\cdot[Z]$ Schwartz–Zippel RLC verification (`< 2⁻¹²¹` soundness) ensures failed proofs open uniform random noise — leaking `0` bits | `src/privacy_mpc.rs`, `src/turbo_shielded.rs`, `src/distributed_mpc.rs` |
| **BFT & Quorum Invariants** | Strict ViewChange lock safety, domain-separated single-use CW block seals, non-trivial $(t, N) \to (t', N')$ resharing verification, and flat-bond slashing | `src/bft.rs`, `src/dynamic_quorum.rs`, `src/tokenomics.rs` |
| **HTTP/P2P DoS, SSRF & Eclipse Defense** | Bounded concurrency (`64`), memory-bounded per-IP rate limiter (`4096` IPs / `120 req/s`), 5 s Slowloris deadline, request-smuggling & JSON depth (`32`) limits, SSRF IP blocking, and `/24` IPv4 (`/48` IPv6) subnet diversity cap (`MAX_PEERS_PER_SUBNET = 4`) | `src/testnet_server.rs`, `src/p2p_node.rs` |
| **Fail-Closed Explorer Telemetry** | Explorer UI renders zero external CDN URLs and verifies `beacon_paired_verified === true`, `bilateral_receipts_verified === true`, `beaver_verified === true`, `beacon_gamma`, and `anti_replay_tracked_pads` fail-closed | `src/explorer_ui.rs` |

---

## System Architecture

```text
  ┌──────────────────────────┐        ┌────────────────────────────────────────┐
  │   CLI Wallet (`vrnm`)    │        │  Embedded Dark-Mode Web Explorer (/)   │
  │  WAL PadBook (0600) +    │        │  Zero CDN · Fail-Closed PoP Badges ·   │
  │  Auto-Discovering RPC    │        │  Shamir V0..V3 Share Inspector         │
  └────────────┬─────────────┘        └───────────────────┬────────────────────┘
               │              HTTP/1.1 JSON               │
               └────────────────────┬─────────────────────┘
                                    ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │     Hardened HTTP/P2P Edge (`testnet_server.rs` & `p2p_node.rs`)           │
  │  Rate Limiter · Slowloris/Smuggling Guards · SSRF Block · /24 Eclipse Cap  │
  └──────┬──────────────────────────┬───────────────────────────┬──────────────┘
         ▼                          ▼                           ▼
  ┌────────────────────┐   ┌──────────────────────┐   ┌────────────────────────┐
  │ Express Lane BFT   │   │ Shielded IT-MPC Lane │   │ Autonomous PoP & QKD   │
  │ `bft.rs`           │   │ `privacy_mpc.rs`     │   │ `entropy_beacon.rs`    │
  │ `fast_engine.rs`   │   │ `turbo_shielded.rs`  │   │ `pop_mining.rs`        │
  │ `turbo_express.rs` │   │ `distributed_mpc.rs` │   │ `qkd.rs` (BB84/Decoy)  │
  │ 2-Phase OTP+CW BFT │   │ `dynamic_quorum.rs`  │   │ `tokenomics.rs` (21M)  │
  └─────────┬──────────┘   └──────────┬───────────┘   └───────────┬────────────┘
            └─────────────────────────┴───────────────────────────┘
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  Information-Theoretic Foundation (`field.rs`, `otp.rs`, `turbo_crypto.rs`)│
  │  Branchless F_(2^127-1) · AVX-512/NEON OTP XOR · 4-Way CW MAC · WAL Zero   │
  └────────────────────────────────────────────────────────────────────────────┘
```

### Core Modules (19 Modules, Zero External Crates)

| Module | Role |
| :--- | :--- |
| `src/field.rs` | Division-free, branchless Mersenne prime field $\mathbb{F}_{2^{127}-1}$, constant-time `ct_select_u128` / `ct_eq_16`, OS entropy & volatile RAM zeroization |
| `src/otp.rs` | Word-level XOR OTP, injective Carter–Wegman one-time MAC, crash-safe `fsync` `WalPadBook` with on-disk zeroing |
| `src/turbo_crypto.rs` | Runtime-dispatched `AVX-512F`/`AVX2`/NEON OTP XOR, 4-way fused Carter–Wegman MAC (`CwFastKey`), `VPOPCNTDQ` Toeplitz QKD privacy amplification |
| `src/bft.rs` | 2-phase batched BFT (`PrePrepare → Prepare → Commit`), ViewChange lock safety, offline quorum sync & Web-of-Trust registry |
| `src/fast_engine.rs` | Bitcoin Core BIP-152 compact block relay, `O(1)` `IndexedLedger`, stack `[u128; 4]` parallel Express & Shielded baseline engines |
| `src/turbo_express.rs` | Persistent 4-validator threaded Express BFT engine with 4-way pipelined CW block seals & zero-copy `Arc<[TurboTx]>` batches |
| `src/privacy_mpc.rs` | Precomputed `LagrangeCache`, auto-refilling `BeaverPool`, `ShardedPrivateLedger`, sender-anonymous rounds, PSS & `CoverFrame` |
| `src/turbo_shielded.rs` | Algebraic IT-MPC acceleration: Beaver Square Pairs, Shared-Factor Beaver Stars, zero-leak $[\rho]\cdot[Z]$ Schwartz–Zippel RLC |
| `src/distributed_mpc.rs` | True 4-daemon split-share real-TCP networked IT-MPC (1 Shamir share per server) over pairwise OTP+MAC sockets |
| `src/entropy_beacon.rs` | Unbiasable, unabortable threshold-Shamir Distributed Entropy Beacon ($\Gamma_e$) + `AutonomousEpochClock` |
| `src/dynamic_quorum.rs` | Permissionless beacon-challenged validator admission, zero-reconstruction $(t, N) \to (t', N')$ Shamir resharing & epoch state pruning |
| `src/pop_mining.rs` | Sattolo beacon-paired bilateral Proof-of-Pad (`PoP`) mining: Monobit + Runs tests, Beaver spot-checks, QKD audits, co-signed peer receipts, `PopReplayRegistry` & auto-slashing |
| `src/qkd.rs` | Bit-sliced BB84 + Weak/Vacuum Decoy-State QKD (QBER + PNS attack detection), Toeplitz PA, `BufferedQkdPool`, ETSI 014 & QRNG traits |
| `src/tokenomics.rs` | 21,000,000 `VRNM` hard halving cap, Proof-of-Pad rewards, 80/20 pad-burn fees, flat-bond validator slashing & one-time CW audit tags |
| `src/p2p_node.rs` | Multi-VPS decentralized P2P validator daemon with seed bootstrap, transitive `/p2p/peers` gossip, block sync, SSRF & `/24` eclipse defense |
| `src/testnet_server.rs` | Hardened zero-dependency HTTP/1.1 testnet server (rate limiting, Slowloris/smuggling guards, beacon-paired `/pop/mine`, faucet & balance APIs) |
| `src/explorer_ui.rs` | Self-contained zero-CDN dark-mode web explorer (ASI security posture bar, fail-closed PoP telemetry, P2P mesh, Shamir share inspector, Quick Join CLI) |
| `src/wallet.rs` | Crash-safe disk-persisted `VernamWallet` (`0600`) + auto-discovering zero-dependency HTTP/1.1 `WalletRpcClient` |
| `src/main.rs` | Unified `vrnm` CLI binary wiring testnet, P2P node, PoP miner, wallet, v1.0 zero-admin demo & benchmarks |

---

## CLI Command Reference

| Command | Description |
| :--- | :--- |
| `vrnm demo` | Run the full 6-pillar showcase (WAL OTP, BFT sync, Sharded IT-MPC, BB84/PNS QKD, 21M Tokenomics & Fast Engine) |
| `vrnm v1-demo` | Run the v1.0+ zero-admin demo (unbiasable threshold beacon under V3 abort, 4-daemon real-TCP MPC, `4 → 7` resharing) |
| `vrnm bench` | Run full release speed benchmarks (SIMD crypto, Express BFT, Shielded IT-MPC, 4-daemon TCP MPC & BIP-152 compact relay) |
| `vrnm testnet [--bind 0.0.0.0:8080]` | Start the all-in-one 4-validator HTTP/1.1 testnet node + interactive Web Explorer at `/` |
| `vrnm node [--id N] [--bind ADDR] [--advertise IP:PORT] [--seed HOST:PORT]` | Start an independent decentralized P2P validator node with automatic transitive peer discovery |
| `vrnm pop-mine` | Run a standalone Beacon-Paired Bilateral Proof-of-Pad (`PoP`) entropy & Beaver-triple audit round |
| `vrnm miner [--id N] [--cores 1] [--node URL] [--rounds 0] [--interval 15]` | Run a live 1-core (or N-core) Proof-of-Pad entropy & Beaver-triple miner submitting epochs to a node |
| `vrnm wallet create --name <n> [--node URL]` | Create a crash-safe WAL-persisted local OTP wallet (`~/.vernam/wallets/<n>`) |
| `vrnm wallet peers [--node URL]` | Auto-discover all active peer nodes on the mesh from a single seed |
| `vrnm wallet faucet --name <n> [--express 1000] [--shielded 500]` | Claim Express + Shielded testnet `VRNM` from the live faucet |
| `vrnm wallet balance --name <n>` | Inspect Express balance, Shielded balance, raw `V0..V3` Shamir shares & remaining WAL OTP pages |
| `vrnm wallet send --from <n> --to <name\|id> --amount <u64>` | Send an Express Lane (2-phase OTP + Carter–Wegman BFT) transfer |
| `vrnm wallet send-private --from <n> --to <name\|id> --amount <u64>` | Send a blinded Shielded Lane (IT-MPC Beaver-triple) transfer hiding amount & recipient |
| `vrnm wallet refill --name <n> [--pages 8]` | Replenish fresh BB84 QKD OTP pad pages into the local wallet WAL |
| `vrnm wallet pop-mine [--node URL]` | Trigger a Beacon-Paired Bilateral Proof-of-Pad epoch mine via `POST /pop/mine` |
| `vrnm wallet refresh-epoch [--node URL]` | Trigger a Proactive Secret Sharing (PSS) + BB84 QKD epoch rotation |

---

## VPS & Multi-Node Docker Deployment

Deploy a dedicated hardened systemd testnet + web explorer on any Ubuntu/Debian VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/gpt4omni/vernam/main/deploy/vps-setup.sh | sudo bash
```

Or spin up a 4-container local/VPS decentralized P2P mesh in one command:

```bash
docker compose -f deploy/docker-compose.multi-node.yml up -d --build
```

Full deployment guides: [deploy/DEPLOY_VPS.md](deploy/DEPLOY_VPS.md) and [deploy/JOIN_TESTNET.md](deploy/JOIN_TESTNET.md).

---

## Local Build & Verification

```bash
cargo test --release
cargo run --release -- v1-demo
cargo run --release -- bench
cargo run --release -- pop-mine
```
