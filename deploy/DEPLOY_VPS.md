# Deploying the Vernam (`VRNM`) Testnet on a VPS

Vernam is written in **zero-dependency Rust**, so it compiles cleanly offline and runs comfortably on an entry-level VPS (1 vCPU, 512 MB RAM, Ubuntu 22.04+/Debian 12+).

Choose **Option A** for a direct bare-metal `systemd` install or **Option B** for Docker Compose (with optional automatic Let's Encrypt HTTPS via Caddy).

---

## Option A: 1-Command Bare-Metal Ubuntu/Debian VPS Setup

Run directly on a fresh Ubuntu or Debian VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/gpt4omni/vernam/main/deploy/vps-setup.sh | sudo bash
```

Or, if you have already cloned this repository:

```bash
git clone https://github.com/gpt4omni/vernam.git
cd vernam
sudo bash deploy/vps-setup.sh
```

What `vps-setup.sh` does (idempotently):
1. Installs `build-essential`, `curl`, and `git` if missing.
2. Installs/updates Rust via `rustup` if `cargo` is missing (or older than 1.85).
3. Compiles `cargo build --release --offline` and installs `/usr/local/bin/vrnm` (plus `/usr/local/bin/vernam-rs`).
4. Creates a dedicated non-login system user `vernam` and `/var/lib/vernam` (`0700`).
5. Installs and starts the hardened `vernam-testnet.service` (`ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectHome=true`, `UMask=0077`).
6. Opens `8080/tcp` if `ufw` is active, verifies `http://127.0.0.1:8080/health`, and prints your live dashboard URL.

### Managing the Bare-Metal Service

```bash
sudo systemctl status vernam-testnet.service
sudo journalctl -fu vernam-testnet.service
sudo systemctl restart vernam-testnet.service
```

You can override defaults before running the installer:

```bash
VRNM_BIND=0.0.0.0:9090 VRNM_BRANCH=main sudo -E bash deploy/vps-setup.sh
```

---

## Option B: Docker Compose (with Optional Automatic HTTPS via Caddy)

### 1. HTTP Quick Start (Port 8080)

From the repository root:

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

Verify the node is healthy:

```bash
curl -fsS http://127.0.0.1:8080/health
```

### 2. Automatic Let's Encrypt HTTPS (Caddy Reverse Proxy)

Point an `A` / `AAAA` DNS record (e.g. `testnet.yourdomain.com`) at your VPS, ensure ports `80` and `443` are open, and launch with the `https` profile:

```bash
VRNM_DOMAIN=testnet.yourdomain.com \
VRNM_PORT=127.0.0.1:8080 \
  docker compose -f deploy/docker-compose.yml --profile https up -d --build
```

Setting `VRNM_PORT=127.0.0.1:8080` keeps port `8080` bound only to loopback so all external traffic enters through Caddy over HTTPS (`https://testnet.yourdomain.com`).

Container hardening included by default:
- Multi-stage offline Rust build (`rust:1-slim` -> `debian:bookworm-slim`)
- Non-root `vernam` user (UID/GID `10001`) and `0700` persistent volume (`vernam-data:/var/lib/vernam`)
- `read_only: true` root filesystem with `noexec,nosuid` `/tmp` tmpfs
- `cap_drop: ALL`, `no-new-privileges:true`, and `HEALTHCHECK` on `/health`

### Updating / Viewing Logs

```bash
docker compose -f deploy/docker-compose.yml logs -f vernam-testnet
docker compose -f deploy/docker-compose.yml up -d --build
```

---

## Connecting Your Local `vrnm` CLI Wallet to Your VPS Testnet

Install `vrnm` locally (`cargo build --release` -> `target/release/vernam-rs`, or symlink to `vrnm`), then point it at your VPS URL:

```bash
# Use https://testnet.yourdomain.com if Caddy HTTPS is enabled
export VRNM_NODE="http://<YOUR_VPS_IP>:8080"

# 1. Create local wallets
vrnm wallet create --name alice
vrnm wallet create --name bob

# 2. Request testnet VRNM from the VPS faucet
vrnm wallet faucet --name alice --node "$VRNM_NODE"

# 3. Check balance and network status
vrnm wallet balance --name alice --node "$VRNM_NODE"
vrnm wallet status --node "$VRNM_NODE"

# 4. Express Lane (VRNM-Fast) transfer
vrnm wallet send --from alice --to bob --amount 10 --node "$VRNM_NODE"

# 5. Shielded Lane (VRNM-Private) IT-MPC private transfer
vrnm wallet send-private --from alice --to bob --amount 5 --node "$VRNM_NODE"
```

---

## Security Checklist

- **Firewall**: Allow only SSH (`22/tcp`) and your public endpoint (`80/tcp` + `443/tcp` when using Caddy, or `8080/tcp` for direct HTTP). Keep `8080` bound to `127.0.0.1` whenever a reverse proxy terminates TLS.
- **HTTPS / TLS**: Always terminate TLS (e.g. Caddy `--profile https`) before exposing a testnet node to external wallets or browsers.
- **Strict State Permissions**: Keep `/var/lib/vernam` owned by `vernam:vernam` with mode `0700` (and OTP pad files at `0600`). Do not run the node as `root`.
- **CRITICAL — WAL & OTP Pad Backup Warning**:
  > **NEVER snapshot, clone, or restore an old backup of burned One-Time Pad (`WalPadBook`) files!**
  >
  > Vernam's information-theoretic security depends on **strict single-use** of every OTP page and Carter–Wegman MAC key. Rolling back a disk snapshot or restoring a backup containing previously burned pads causes **two-time pad reuse**, which catastrophically leaks plaintext XORs and MAC keys.
  >
  > Exclude OTP pad books and WAL burn logs from VM snapshots and automated restore jobs. If a node disk fails, provision **fresh OTP pads** and re-sync the chain instead of restoring old pad state.
