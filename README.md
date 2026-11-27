<p align="center">
  <img src="assets/logo.svg" alt="Vernam (VRNM) Logo" width="140" />
</p>

# Vernam (`VRNM`) v2.2.0

**Vernam (`VRNM`)** is an open-source, zero-dependency Rust (`std` only — `0` external crates in `Cargo.toml`) research ledger, split-share networked IT-MPC engine, Confidential IT-MPC Circuits VM, crash-safe WAL CLI wallet, interactive **Proof-of-Pad (`PoP`)** entropy mining engine, and self-contained dark-mode web explorer built over the Mersenne prime field $\mathbb{F}_{2^{127}-1}$.

Security in the core protocol rests on **Shannon information theory** (one-time pads, Carter–Wegman universal hashing, and $(t, N)$ Shamir secret sharing with Beaver multiplication triples and Proactive Secret Sharing) rather than computational hardness assumptions (zero SHA-256, RSA, ECDSA, Ed25519, AES, BLS, or zk-SNARKs in the core Rust stack).

> **MIT Licensed Open-Source Research Testnet:** [LICENSE](LICENSE)  
> **Live Public Testnet Explorer & Faucet:** `http://88.216.62.115:8080/`  
> **Technical Architecture Spec:** [VERNAM_V1_ARCHITECTURE.md](VERNAM_V1_ARCHITECTURE.md)

---

## Research Testnet & Honest Threat Model

> **IMPORTANT — Read Before Running or Evaluating:**
> 1. **Experimental Research Software (MIT License):** Vernam (`VRNM`) is an experimental, unaudited open-source research testnet released under the [MIT License](LICENSE). **Do NOT use it to store real financial value. `VRNM` is NOT for sale.**
> 2. **Real Networked TPS vs. Single-Machine Kernel Benchmarks:**
>    * **Real Networked 4-Daemon Split-Share TCP MPC:** **`~9,571 TPS`** on local multi-process loopback TCP (`~91 µs` p50) and **`~1,191 TPS`** on a 1-vCore ARM64 VPS — where 4 independent TCP validator servers hold **1 Shamir share each** over pairwise OTP+MAC sockets.
>    * **Single-Machine In-Process Kernel Benchmarks:** Express Lane `77M–86M TPS` and Shielded Lane `690k–1.46M TPS` measure **in-memory single-host compute throughput** (no WAN RTT, no TCP serialization, no disk fsync per tx). They are reported separately below and must not be conflated with wide-area networked consensus TPS.
> 3. **Symmetric Single-Use CW-MAC Authentication Model (Not Open Public-Key Signatures):**
>    * Because Vernam intentionally omits ECDSA/Ed25519, account authentication uses **pre-registered single-use pairwise Carter–Wegman MAC keys** $(pad\_id, r, s) \in \mathbb{F}_{2^{127}-1}^2$ — NOT open public-key signatures.
>    * In `v2.2.0`, every Express transfer (`AUTH_DOMAIN_EXPRESS = 1`), Shielded transfer (`AUTH_DOMAIN_SHIELDED = 2`), Private Balance query (`AUTH_DOMAIN_BALANCE = 3`), and P2P transaction/announcement requires a valid single-use CW-MAC tag, and each key is **burned immediately after one use**. Users must provision/register fresh keys (`POST /account/register` or `vrnm wallet`) before exhausting their pad book.
> 4. **Simulated Software BB84 vs. Physical Quantum/Hardware Entropy:**
>    * On the public software testnet, BB84 photon basis sifting and QBER telemetry (`src/qkd.rs`) are **simulated in software** unless connected to real physical entropy/quantum devices (`/dev/hwrng`, USB QRNG via `VRNM_QRNG_DEVICE`, an ETSI GS QKD 014 KME, or Tier-2 multi-path relays in `src/key_transport.rs`). Information-theoretic security against a computationally unbounded adversary requires real physical entropy and out-of-band / QKD key distribution; software-only OS CSPRNG mode inherits the security assumptions of the host OS CSPRNG.
> 5. **Transport Security (TLS Required in Production):**
>    * The built-in zero-dependency HTTP server binds raw HTTP on `:8080` by default (suitable for local development and public testnet demos). Any production or sensitive deployment **must** terminate TLS in front of `:8080` using a reverse proxy such as [`deploy/Caddyfile`](deploy/Caddyfile) or Nginx, especially because `POST /account/register` transmits symmetric CW-MAC key material.

---

## Measured Benchmarks (Networked First, In-Process Kernel Second)

Measured with `cargo run --release -- bench` (`opt-level = 3`, `lto = true`, `codegen-units = 1`, zero external crates):

### 1. Real Networked Multi-Daemon TCP Throughput (Primary Metric)

| Deployment / Path | Measured Throughput | Latency / Notes |
| :--- | :--- | :--- |
| **4-Daemon Split-Share Real-TCP Shielded MPC (Local Workstation)** | **`~9,571 TPS`** | `~91 µs` p50 across 4 independent TCP validator daemons (1 Shamir share per process, pairwise OTP+MAC sockets, `0.04 ms` distributed PSS refresh) |
| **4-Daemon Split-Share Real-TCP Shielded MPC (1-vCore ARM64 VPS)** | **`~1,191 TPS`** | 4 independent TCP validator daemons on 1 ARM64 vCore (`88.216.62.115`) |
| **Live Cross-Atlantic HTTP/1.1 Shielded Finality** | Network-RTT bound | `~340 ms` WAN RTT (`+1.3 ms` server-side IT-MPC execution) |

### 2. Single-Machine In-Process Kernel Benchmarks (No Network / No Disk I/O)

| Kernel Subsystem | Local Workstation (i9-11900, 16T, AVX-512) | 1-vCore ARM64 VPS (`88.216.62.115`) | Notes |
| :--- | :--- | :--- | :--- |
| **Express Lane (`VRNM-Fast`) 4-Val In-Process BFT** | **77.6M – 85.7M TPS** (`0.117 ms/block`) | **5.29M TPS** | 4 persistent threads, 2-phase BFT + 24 OTP/CW votes/block + 4-way pipelined CW block seals |
| **Shielded Lane (`VRNM-Private`) In-Process IT-MPC** | **690k – 1.46M TPS** (up to 1.66M peak) | **166k TPS** | Beaver Square Pairs + Shared-Factor Beaver Stars + blinded $[\rho]\cdot[Z]$ Schwartz–Zippel RLC (`< 2⁻¹²¹` soundness) |
| **SIMD OTP XOR** | **51.0 – 61.29 GB/s** (`AVX-512F`) | **22.10 GB/s** (`ARM64 NEON`) | Runtime-dispatched SIMD / portable word XOR |
| **4-Way Fused Carter–Wegman MAC** ($\mathbb{F}_{2^{127}-1}$) | **13.6M – 15.9M ops/s** (`6.09 GB/s`) | Portable 128-bit | Runtime `BMI2`/`ADX` dispatch |
| **Toeplitz QKD Privacy Amplification** | **177 – 260 Mbps** (`VPOPCNTDQ`) | Portable GF(2) | 2-universal GF(2) Toeplitz hashing |

---

## Quick Start (Inspect-First Source Build — Zero External Crates)

Requires **Rust `>= 1.85`** (edition 2024). Because `Cargo.toml` has **zero external crates**, Vernam builds 100% offline directly from the git checkout — no `curl | bash` required:

```bash
git clone https://github.com/gpt4omni/vernam.git
cd vernam
cargo build --release --offline
```

The compiled binary is at `./target/release/vernam-rs`. (If you prefer installing it into `~/.local/bin/vrnm`, you can inspect and run the optional user-space helper `bash deploy/install.sh`, which never uses `sudo`.)

### Run Local Demos & Benchmarks

```bash
# Run the full release test suite
cargo test --release

# Run v2.1 Confidential IT-MPC Circuits VM, Dark-Pool AMM, Vickrey Auction & Ballot Box demo
./target/release/vernam-rs circuits-demo

# Run v2.0 Multi-Source Entropy, Global Oblivious Shuffle, Herzberg Recovery & Geo-Triangulation demo
./target/release/vernam-rs v2-demo

# Run v1.0 Zero-Admin Beacon, 4-Daemon Real-TCP MPC & 4 -> 7 Resharing demo
./target/release/vernam-rs v1-demo

# Run real-TCP + in-process kernel benchmarks
./target/release/vernam-rs bench
```

### Connect the CLI Wallet to the Live Testnet

```bash
export VRNM_NODE="http://88.216.62.115:8080"

# Auto-discover active P2P peers from a single seed
vrnm wallet peers

# Create crash-safe WAL-persisted wallets (mode 0600) & register single-use CW-MAC auth keys
vrnm wallet create --name alice
vrnm wallet create --name bob

# Claim testnet VRNM (Express + Shielded Shamir shares)
vrnm wallet faucet --name alice

# Send CW-MAC authenticated Express BFT and blinded Shielded IT-MPC transfers
vrnm wallet send --from alice --to bob --amount 25
vrnm wallet send-private --from alice --to bob --amount 15

# Query public Express balance + CW-MAC authenticated owner Shielded balance (POST /balance/private)
vrnm wallet balance --name bob
```

### Join the Decentralized P2P Mesh or Run an Interactive PoP Miner

```bash
# Join the testnet as an independent P2P validator node
vrnm node --bind 0.0.0.0:8080 --advertise <YOUR_PUBLIC_IP>:8080 --seed 88.216.62.115:8080

# Run a 1-core interactive Proof-of-Pad miner (POST /pop/commit -> POST /pop/submit)
vrnm miner --cores 1 --node http://88.216.62.115:8080
```

---

## Release Highlights (`v2.1` & `v2.2.0`)

### `v2.2.0` — Security Hardening, Authenticated API & Privacy Fixes

* **Mandatory Single-Use CW-MAC Authentication (`POST /account/register`):** Every Express transfer (`AUTH_DOMAIN_EXPRESS = 1`), Shielded transfer (`AUTH_DOMAIN_SHIELDED = 2`), Private Balance query (`AUTH_DOMAIN_BALANCE = 3`), and P2P transaction is authenticated with a one-time Carter–Wegman tag over $\mathbb{F}_{2^{127}-1}$, burned immediately after verification.
* **Zero Unauthenticated Privacy Leaks (`GET /balance/<id>` vs. `POST /balance/private`):** Unauthenticated `GET /balance/<id>` now returns public Express balance only and explicitly redacts both `shielded_balance` and raw validator Shamir shares. Account owners prove ownership via a burned one-time CW-MAC key at `POST /balance/private`.
* **Interactive Proof-of-Pad Challenge-Response (`POST /pop/commit` → `POST /pop/submit`):** Server-side self-mining (`POST /pop/mine`) is disabled in `v2.2.0`. External miners commit fresh entropy pads, receive a beacon-derived challenge, and submit proofs interactively.
* **Authenticated Zero-CDN Web Explorer (`src/explorer_ui.rs`):** Implements pure-JS `BigInt` $\mathbb{F}_{2^{127}-1}$ CW-MAC signing in browser session memory (`sessionAuthKeys`), explicit `REDACTED` balance states, an "Unlock Private Balance" flow, and inspect-first CLI snippets with zero external URLs.
* **MIT License & Safe Installers:** Added standard [MIT `LICENSE`](LICENSE), enforced strictly user-space `deploy/install.sh` (zero `sudo`), and removed unverified `curl | sh` / `curl | bash` pipes from both `README.md` and `deploy/vps-setup.sh`.

### `v2.1` — Confidential IT-MPC Circuits VM & Adaptive Protocol Tuner

* **Straight-Line Confidential Arithmetic Circuit VM (`src/mpc_vm.rs`):** Non-Turing-complete, reentrancy-free acyclic DAG VM executing over Shamir secret shares in $\mathbb{F}_{2^{127}-1}$ with branchless oblivious `Mux`, bit-decomposition `AssertRangeBits`, batched zero-leak $[\rho]\cdot[Z]$ Schwartz–Zippel assertions with 100% atomic rollback, and Proactive Secret Sharing (PSS) across all persistent contract storage slots.
* **Authenticated Bytecode & Cost Estimator (`src/mpc_bytecode.rs`):** Vernam Circuit Assembly (`VCA`) compiler, binary serializer authenticated with one-time Carter–Wegman MACs (`BytecodeMacKey`), and deterministic Beaver-triple + storage-write fee estimation.
* **Confidential DeFi & Governance Suite (`src/mpc_defi.rs`):**
  * `ConfidentialDarkPoolAmm`: Secret-shared reserves, swap direction, amounts, and slippage checks verified obliviously via Beaver triples.
  * `ConfidentialSealedBidAuction`: First-Price and Vickrey Second-Price sealed-bid auctions using branchless bit-level IT-MPC comparisons without revealing losing bids.
  * `ConfidentialBallotBox`: One-hot blinded secret-ballot governance with linear (`0`-triple) tally accumulation.
* **Adaptive Protocol Controller (`src/adaptive_tuner.rs`):** Telemetry-driven epoch parameter controller adjusting Beaver pool targets and fee/audit margins safely within hard protocol invariants.

---

## Security Hardening Matrix (`v1.1` → `v2.2.0`)

| Security Surface | Mechanism | Primary Module(s) |
| :--- | :--- | :--- |
| **Account Ownership & Replay Protection** | Single-use pairwise CW-MAC keys over $\mathbb{F}_{2^{127}-1}$ (`AUTH_DOMAIN_EXPRESS=1`, `SHIELDED=2`, `BALANCE=3`) burned on first verification | `src/testnet_server.rs`, `src/wallet.rs`, `src/explorer_ui.rs` |
| **Shielded Balance Privacy on RPC** | `GET /balance/<id>` redacts shielded balance & raw Shamir shares; owner queries authenticate via `POST /balance/private` | `src/testnet_server.rs`, `src/explorer_ui.rs` |
| **Field Side Channels & RAM Hygiene** | Division-free, branchless `reduce`, `add_mod`, `sub_mod`, `mul_mod`, `ct_select_u128`, `ct_eq_16`, and volatile RAM zeroization (`write_volatile` + `SeqCst` fences) | `src/field.rs`, `src/otp.rs`, `src/turbo_crypto.rs` |
| **Two-Time-Pad Crash Safety** | `WalPadBook` (`0600`) writes `[0xB1 \| page_id \| !page_id]`, `fsync`s WAL, zeros disk slot, and `fsync`s data file strictly before pad use | `src/otp.rs`, `src/wallet.rs`, `src/storage.rs` |
| **Beacon Bias & Last-Revealer Abort** | Symmetric bivariate Shamir commit-reveal over pairwise OTP+MAC links with Lagrange fallback reconstruction | `src/entropy_beacon.rs` |
| **PoP Anti-Self-Mining & Anti-Replay** | Interactive `/pop/commit` → `/pop/submit`, Sattolo derangement pairing from $\Gamma_e$, bilateral peer CW-MAC receipts, and 64-epoch `PopReplayRegistry` | `src/pop_mining.rs`, `src/testnet_server.rs` |
| **Zero-Leak MPC Failure Blinding** | Blinded $[\rho]\cdot[Z]$ Schwartz–Zippel RLC (`< 2⁻¹²¹` soundness) reveals uniform random non-zero noise on proof failure (`0` bits leaked) | `src/privacy_mpc.rs`, `src/turbo_shielded.rs`, `src/mpc_vm.rs`, `src/mpc_defi.rs` |
| **HTTP/P2P DoS, SSRF & Eclipse Defense** | Bounded concurrency (`64`), bounded per-IP rate limiter (`4096` IPs / `120 req/s`), 5 s Slowloris deadline, smuggling & JSON depth (`32`) guards, SSRF IP blocking, and `/24` IPv4 (`/48` IPv6) subnet cap (`4`) | `src/testnet_server.rs`, `src/p2p_node.rs` |

---

## Architecture & Module Map (30 Modules, Zero External Crates)

```text
  ┌──────────────────────────┐        ┌────────────────────────────────────────┐
  │   CLI Wallet (`vrnm`)    │        │  Embedded Dark-Mode Web Explorer (/)   │
  │  WAL PadBook (0600) +    │        │  Zero CDN · Pure-JS BigInt CW-MAC ·    │
  │  CW-MAC Auth RPC Client  │        │  Redacted Public / Private Unlock UI   │
  └────────────┬─────────────┘        └───────────────────┬────────────────────┘
               │           HTTP/1.1 JSON (TLS via Caddy)  │
               └────────────────────┬─────────────────────┘
                                    ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │     Hardened HTTP/P2P Edge (`testnet_server.rs`, `p2p_node.rs`, `storage`) │
  │  CW-MAC Auth · Rate Limiter · Slowloris/SSRF Guards · /24 Eclipse Defense  │
  └──────┬──────────────────────────┬───────────────────────────┬──────────────┘
         ▼                          ▼                           ▼
  ┌────────────────────┐   ┌──────────────────────┐   ┌────────────────────────┐
  │ Express Lane BFT   │   │ Shielded IT-MPC & VM │   │ PoP, Beacon & Entropy  │
  │ `bft.rs`           │   │ `privacy_mpc.rs`     │   │ `entropy_beacon.rs`    │
  │ `fast_engine.rs`   │   │ `turbo_shielded.rs`  │   │ `pop_mining.rs`        │
  │ `turbo_express.rs` │   │ `distributed_mpc.rs` │   │ `qkd.rs`, `hw_entropy` │
  │                    │   │ `validator_daemon.rs`│   │ `entropy_harvester.rs` │
  │                    │   │ `mpc_vm.rs`          │   │ `key_transport.rs`     │
  │                    │   │ `mpc_bytecode.rs`    │   │ `geo_triangulation.rs` │
  │                    │   │ `mpc_defi.rs`        │   │ `oblivious_shuffle.rs` │
  │                    │   │ `dynamic_quorum.rs`  │   │ `vault_recovery.rs`    │
  │                    │   │ `adaptive_tuner.rs`  │   │ `tokenomics.rs` (21M)  │
  └─────────┬──────────┘   └──────────┬───────────┘   └───────────┬────────────┘
            └─────────────────────────┴───────────────────────────┘
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  Information-Theoretic Core (`field.rs`, `otp.rs`, `turbo_crypto.rs`)      │
  │  Branchless F_(2^127-1) · AVX-512/NEON OTP XOR · 4-Way CW MAC · WAL Zero   │
  └────────────────────────────────────────────────────────────────────────────┘
```

| Layer | Modules |
| :--- | :--- |
| **Core Primitives** | `field.rs`, `otp.rs`, `turbo_crypto.rs`, `storage.rs` |
| **Express BFT Lane** | `bft.rs`, `fast_engine.rs`, `turbo_express.rs` |
| **Shielded IT-MPC & Networked Daemons** | `privacy_mpc.rs`, `turbo_shielded.rs`, `distributed_mpc.rs`, `validator_daemon.rs`, `dynamic_quorum.rs`, `oblivious_shuffle.rs`, `vault_recovery.rs` |
| **v2.1 Confidential Circuits VM & DeFi** | `mpc_vm.rs`, `mpc_bytecode.rs`, `mpc_defi.rs`, `adaptive_tuner.rs` |
| **PoP Mining, Beacon, QKD & Entropy** | `entropy_beacon.rs`, `pop_mining.rs`, `qkd.rs`, `hw_entropy.rs`, `entropy_harvester.rs`, `key_transport.rs`, `geo_triangulation.rs`, `tokenomics.rs` |
| **Network Edge, UI, Wallet & CLI** | `testnet_server.rs`, `p2p_node.rs`, `explorer_ui.rs`, `wallet.rs`, `main.rs` |

---

## CLI Command Reference

| Command | Description |
| :--- | :--- |
| `vrnm demo` | Full 5-pillar showcase (WAL OTP, BFT sync, Sharded IT-MPC, BB84/PNS QKD, 21M Tokenomics & Fast Engine) |
| `vrnm v1-demo` | v1.0 zero-admin threshold beacon (with abort recovery), 4-daemon real-TCP MPC & `4 → 7` resharing |
| `vrnm v2-demo` | v2.0 multi-source entropy, global oblivious shuffle, Herzberg recovery & geo-triangulation demo |
| `vrnm circuits-demo` | v2.1 Confidential IT-MPC Circuits VM, Dark-Pool AMM, Vickrey Auction, Ballot Box & Adaptive Tuner demo |
| `vrnm bench` | Real 4-daemon TCP MPC + in-process Express BFT, Shielded IT-MPC & SIMD kernel benchmarks |
| `vrnm testnet [--bind 0.0.0.0:8080] [--data-dir <path>]` | Start the all-in-one 4-validator HTTP/1.1 testnet node + authenticated Web Explorer at `/` |
| `vrnm validator [--id 0] [--committee 4] [--bind ...]` | Start a single-share multi-host IT-MPC validator daemon (1 Shamir share per host) |
| `vrnm node [--id N] [--bind ADDR] [--advertise IP:PORT] [--seed HOST:PORT]` | Start an independent decentralized P2P validator node with transitive peer gossip |
| `vrnm miner [--id N] [--cores 1] [--node URL] [--rounds 0]` | Run an interactive Proof-of-Pad miner (`POST /pop/commit` → `POST /pop/submit`) |
| `vrnm pop-mine` | Run a local standalone Beacon-Paired Bilateral Proof-of-Pad audit round |
| `vrnm hw-entropy` | Probe `/dev/hwrng` or `VRNM_QRNG_DEVICE` with NIST SP 800-90B continuous health tests |
| `vrnm wallet create\|peers\|faucet\|balance\|send\|send-private\|refill` | Crash-safe WAL (`0600`) CLI wallet with single-use CW-MAC auth |

---

## VPS & Multi-Node Docker Deployment

For a dedicated hardened systemd testnet on Ubuntu/Debian, **clone and inspect the provisioning script first** (requires root/sudo for `systemd` & `ufw`; not a client installer):

```bash
git clone https://github.com/gpt4omni/vernam.git
cd vernam
less deploy/vps-setup.sh
sudo bash deploy/vps-setup.sh
```

In production, front port `:8080` with automatic HTTPS using [`deploy/Caddyfile`](deploy/Caddyfile) (set `VRNM_DOMAIN=your.domain.example`).

Or spin up a 4-container decentralized P2P mesh locally with Docker Compose:

```bash
docker compose -f deploy/docker-compose.multi-node.yml up -d --build
```

See [deploy/DEPLOY_VPS.md](deploy/DEPLOY_VPS.md) and [deploy/JOIN_TESTNET.md](deploy/JOIN_TESTNET.md) for full operator documentation.

---

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Vernam (VRNM) Contributors.
