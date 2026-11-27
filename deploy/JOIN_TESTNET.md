# Joining the Decentralized Vernam (`VRNM`) P2P Testnet

Vernam (`VRNM`) v0.4 runs a **zero-dependency, 100% information-theoretically secure** peer-to-peer mesh. You never have to memorize or manually maintain a list of validator IPs: point a new node or wallet at **any single seed peer**, and `/p2p/peers` gossip automatically discovers the entire network transitively.

---

## Prerequisites (Build `vrnm` in ~15 Seconds, Offline)

Vernam has **zero external crates** (`std` only) and compiles cleanly on any Linux/macOS host or small VPS (1 vCPU, 512 MB RAM, Rust >= 1.85):

```bash
git clone https://github.com/gpt4omni/vernam.git
cd vernam
cargo build --release --offline
sudo install -m 0755 target/release/vernam-rs /usr/local/bin/vrnm
```

*(Prefer a 1-command Ubuntu/Debian systemd installer? See [DEPLOY_VPS.md](./DEPLOY_VPS.md).)*

---

## 1. Launch Your Own Seed Node on a VPS

On your first VPS (for example `203.0.113.10`), open TCP port `8080` and start the genesis seed validator:

```bash
# Optional: allow port 8080 if UFW is active
sudo ufw allow 8080/tcp

# Start P2P seed validator #0 (advertises your public VPS IP:port to incoming peers)
vrnm node \
  --id 0 \
  --bind 0.0.0.0:8080 \
  --advertise <YOUR_VPS_IP>:8080
```

> **Single-Node Quick Demo Mode:** If you only want a standalone all-in-one 4-validator simulator + Web Explorer on a single machine without P2P peers, you can still run:
> ```bash
> vrnm testnet --bind 0.0.0.0:8080
> ```

Open your browser to `http://<YOUR_VPS_IP>:8080/` to view the live **Vernam Testnet v0.4 Explorer** (complete with a dynamic copy-paste **Quick-Connect Kit** pre-filled with your node's address).

Verify health & live status from the terminal:

```bash
curl -fsS http://<YOUR_VPS_IP>:8080/health
curl -fsS http://<YOUR_VPS_IP>:8080/status
```

---

## 2. Join an Existing Testnet With Just ONE Seed IP

Anyone else can join your live testnet from a separate VPS, home server, or laptop by supplying **only one** `--seed` address:

```bash
# Friend / Validator #1 joins via Seed Node #0
vrnm node \
  --id 1 \
  --bind 0.0.0.0:8080 \
  --advertise <NODE_1_PUBLIC_IP>:8080 \
  --seed <SEED_VPS_IP>:8080
```

A third operator doesn't even need Seed Node #0's IP — they can connect to Validator #1 and still discover the entire mesh automatically via `/p2p/peers` gossip:

```bash
# Friend / Validator #2 joins ONLY via Node #1 — automatically discovers Node #0!
vrnm node \
  --id 2 \
  --bind 0.0.0.0:8080 \
  --advertise <NODE_2_PUBLIC_IP>:8080 \
  --seed <NODE_1_PUBLIC_IP>:8080
```

### How Transitive Auto-Discovery Works

```text
  [Node 3] ──--seed──► [Node 2] ──--seed──► [Node 1] ──--seed──► [Node 0 (Seed)]
     │                                                                  ▲
     └────────── automatically discovers Node 1 & Node 0 via ───────────┘
                        periodic /p2p/peers gossip!
```

Verify that every node discovered the full mesh and run a **Proof-of-Pad (`PoP`)** entropy audit & epoch mine:

```bash
# Inspect auto-discovered peer mesh
curl -fsS http://<NODE_2_PUBLIC_IP>:8080/p2p/peers

# Run Proof-of-Pad entropy audit (Monobit + Runs + Beaver Triple + BB84 QBER) & mine epoch
curl -fsS -X POST http://<NODE_2_PUBLIC_IP>:8080/pop/mine
```

---

## 3. Run the 4-Container Decentralized Mesh (Local or VPS)

Test a complete 4-validator multi-container P2P cluster on a single machine or VPS with one command:

```bash
docker compose -f deploy/docker-compose.multi-node.yml up -d --build
```

This launches 4 isolated, hardened validator containers chained by single seeds to prove transitive peer discovery:

| Container | Host Port | Seed Flag | What It Auto-Discovers |
| :--- | :--- | :--- | :--- |
| `vrnm-node-0` | `http://127.0.0.1:8080` | *(genesis seed)* | `node-1`, `node-2`, `node-3` |
| `vrnm-node-1` | `http://127.0.0.1:8081` | `--seed vrnm-node-0:8080` | `node-0`, `node-2`, `node-3` |
| `vrnm-node-2` | `http://127.0.0.1:8082` | `--seed vrnm-node-1:8080` | `node-0` *(transitive!)*, `node-1`, `node-3` |
| `vrnm-node-3` | `http://127.0.0.1:8083` | `--seed vrnm-node-2:8080` | `node-0` & `node-1` *(transitive!)*, `node-2` |

### Inspect the Live Mesh

```bash
# Confirm vrnm-node-3 discovered node-0 and node-1 despite only seeding with node-2:
curl -fsS http://127.0.0.1:8083/p2p/peers

# Stream logs from all 4 validators
docker compose -f deploy/docker-compose.multi-node.yml logs -f

# Stop and clean up containers + ephemeral testnet volumes
docker compose -f deploy/docker-compose.multi-node.yml down -v
```

Open any validator's explorer in your browser (`http://127.0.0.1:8080` through `:8083`) to watch the **Decentralized P2P Peer Mesh** panel populate live!

---

## 4. Connect `vrnm wallet` with Auto-Discovery & Automatic Failover

Point your local `vrnm wallet` at **any one** live node (either your VPS seed or `http://127.0.0.1:8080` from Docker Compose):

```bash
export VRNM_NODE="http://<ANY_NODE_IP>:8080"

# 1. Create two crash-safe local OTP wallets
vrnm wallet create --name alice --node "$VRNM_NODE"
vrnm wallet create --name bob   --node "$VRNM_NODE"

# 2. Drip Express (VRNM-Fast) + Shielded (VRNM-Private) testnet funds
vrnm wallet faucet --name alice --node "$VRNM_NODE"

# 3. Check Express balance, Shielded balance, and raw 127-bit Shamir shares
vrnm wallet balance --name alice --node "$VRNM_NODE"

# 4. Send an Express Lane (2-Phase OTP + Carter-Wegman BFT) transfer
vrnm wallet send --from alice --to bob --amount 50 --node "$VRNM_NODE"

# 5. Send a Shielded Lane (IT-MPC Beaver-Triple private) transfer
vrnm wallet send-private --from alice --to bob --amount 25 --node "$VRNM_NODE"

# 6. Check node & discovered mesh status
vrnm wallet status --name alice --node "$VRNM_NODE"
```

### Automatic Peer Discovery & Failover

When `vrnm wallet` talks to `VRNM_NODE`, it queries `GET /p2p/peers` to learn every other healthy validator in the mesh and caches the active peer list locally. If your configured primary node goes offline, restarts, or drops packets, `vrnm wallet` **automatically fails over** to the next healthy discovered peer — zero manual URL switching required.

You can test failover live with the 4-container mesh:

```bash
# 1. Start interacting through node-0 (port 8080)
export VRNM_NODE="http://127.0.0.1:8080"
vrnm wallet status --node "$VRNM_NODE"

# 2. Take node-0 offline to simulate a VPS outage
docker compose -f deploy/docker-compose.multi-node.yml stop vrnm-node-0

# 3. Query again — wallet fails over seamlessly to discovered peers (8081..8083)!
vrnm wallet status --node "$VRNM_NODE"

# 4. Bring node-0 back online
docker compose -f deploy/docker-compose.multi-node.yml start vrnm-node-0
```

---

## Security & OTP Pad Hygiene (Critical)

- **Never clone or share OTP pad volumes across nodes:** Every validator container in `docker-compose.multi-node.yml` mounts its own isolated data volume (`vrnm-node-0-data` .. `vrnm-node-3-data`). Cloning a burned `WalPadBook` volume onto another machine causes **two-time pad reuse**, breaking information-theoretic security.
- **No VM snapshots of burned pads:** Exclude `/var/lib/vernam` from VM rollback snapshots. On disk loss, start with fresh OS/QKD entropy pads and resync from healthy peers.
- **HTTPS for public endpoints:** When exposing a public explorer/RPC endpoint to external wallets, front port `8080` with Caddy TLS (see `--profile https` in [DEPLOY_VPS.md](./DEPLOY_VPS.md)).
