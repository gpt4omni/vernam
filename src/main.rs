//! Vernam (VRNM) v0.3 — Unified CLI (`vrnm`): Testnet Server, Crash-Safe Wallet,
//! Integrated 5-Pillar Showcase, and Multi-Core Speed Benchmarks.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use vernam_rs::bft::{BftCluster, BftConfig, BinaryTx};
use vernam_rs::distributed_mpc::run_distributed_mpc_bench;
use vernam_rs::dynamic_quorum::{
    redistribute_ledger_accounts, reconstruct_secret, split_secret, verify_committee_shares,
};
use vernam_rs::entropy_beacon::{AutonomousEpochClock, BeaconConfig, OtpChannelKey, VernamBeacon};
use vernam_rs::fast_engine::run_speed_benchmarks;
use vernam_rs::field::random_field_elem;
use vernam_rs::otp::{FRAME_BYTES, PadPage, WalPadBook, open_frame, seal_frame};
use vernam_rs::p2p_node::{P2pNode, P2pNodeConfig, discover_network_peers};
use vernam_rs::pop_mining::{
    BilateralPopSubmission, PeerReceiptKey, PopAuditor, PopEpochCoordinator, PopMiner,
    PopReplayRegistry,
};
use vernam_rs::privacy_mpc::{BeaverPool, ConfidentialTransferRequest, ShardedPrivateLedger};
use vernam_rs::qkd::{
    AttackProfile, Bb84Channel, BufferedQkdPool, PoolConfig, QkdKeyProvider,
};
use vernam_rs::testnet_server::{TestnetConfig, TestnetServer, parse_json_u64};
use vernam_rs::tokenomics::{
    EpochContribution, FeeLane, MAX_SUPPLY, OneTimeAuditKey, SlashingOffense, TokenomicsEngine,
    VERN_PER_VRNM,
};
use vernam_rs::turbo_crypto::run_turbo_crypto_bench;
use vernam_rs::turbo_express::run_turbo_express_bench;
use vernam_rs::turbo_shielded::run_turbo_shielded_bench;
use vernam_rs::wallet::{DEFAULT_NODE_URL, VernamWallet, WalletRpcClient, validate_wallet_name};

fn fmt_vrnm(verns: u64) -> String {
    format!("{:.4} VRNM", verns as f64 / VERN_PER_VRNM as f64)
}

fn print_help() {
    println!(
        r#"Vernam (VRNM) v0.4 — Decentralized Pure-OTP & Proof-of-Pad Coin

USAGE:
  vrnm [COMMAND] [OPTIONS]

COMMANDS:
  demo                                  Run full 5-pillar showcase + speed benchmarks (default)
  v1-demo                               Run v1.0 zero-admin beacon, 4-daemon TCP MPC & 4->7 resharing demo
  bench                                 Run high-throughput Express, Shielded & real-TCP TPS benchmarks
  testnet [--bind 0.0.0.0:8080]         Start all-in-one 4-validator HTTP testnet + web explorer
  node    [--id 0] [--bind 0.0.0.0:8080] [--advertise <IP:PORT>] [--seed <HOST:PORT> ...]
                                        Start an independent decentralized P2P validator node
                                        (auto-discovers all peers via seed gossip & syncs blocks)
  pop-mine                              Run a standalone verified Proof-of-Pad (PoP) audit demo
  miner   [--id 0] [--cores 1] [--node <url>] [--rounds 1] [--interval 15] [--pages 16] [--triples 32]
                                        Run a 1-core (or N-core) Proof-of-Pad entropy & Beaver miner
  wallet create  --name <n> [--id <u32>] [--pages 16] [--node <url>] [--dir <path>]
  wallet status  [--name <n>] [--node <url>] [--dir <path>]
  wallet peers   [--node <url>]         Auto-discover all active peer nodes from any single seed
  wallet faucet  --name <n> [--express 1000] [--shielded 500] [--node <url>]
  wallet balance --name <n> [--node <url>]
  wallet send    --from <n> --to <name|id> --amount <u64> [--node <url>]
  wallet send-private --from <n> --to <name|id> --amount <u64> [--node <url>]
  wallet refill  --name <n> [--pages 8]
  wallet pop-mine [--node <url>]        Trigger verified Proof-of-Pad epoch mining on node
  wallet refresh-epoch [--node <url>]
  help                                  Show this help message

ENVIRONMENT:
  VRNM_BIND        Default listen address (default: 0.0.0.0:8080)
  VRNM_NODE        Default RPC/seed node URL for wallet commands (default: http://127.0.0.1:8080)
  VRNM_WALLET_DIR  Base directory for local wallets (default: ~/.vernam/wallets)
"#
    );
}

fn get_all_flags(args: &[String], flag: &str) -> Vec<String> {
    let mut vals = Vec::new();
    let prefix = format!("{flag}=");
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            vals.push(args[i + 1].clone());
        } else if let Some(rest) = args[i].strip_prefix(&prefix) {
            vals.push(rest.to_string());
        }
    }
    vals
}

fn get_flag(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        if let Some(rest) = args[i].strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

fn wallet_base_dir() -> PathBuf {
    if let Ok(dir) = env::var("VRNM_WALLET_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".vernam").join("wallets")
}

fn resolve_wallet_dir(args: &[String], name_flag: &str) -> Result<PathBuf, String> {
    if let Some(dir) = get_flag(args, "--dir") {
        return Ok(PathBuf::from(dir));
    }
    let name = get_flag(args, name_flag)
        .ok_or_else(|| format!("missing required {name_flag} <wallet_name> (or --dir <path>)"))?;
    let valid = validate_wallet_name(&name).map_err(|e| format!("{e}"))?;
    Ok(wallet_base_dir().join(valid))
}

fn next_free_account_id(base: &Path) -> u32 {
    let mut used = std::collections::BTreeSet::new();
    if let Ok(entries) = fs::read_dir(base) {
        for entry in entries.flatten() {
            if let Ok(w) = VernamWallet::open(&entry.path()) {
                used.insert(w.metadata().account_id);
            }
        }
    }
    for id in 1u32..64 {
        if !used.contains(&id) {
            return id;
        }
    }
    1
}

fn resolve_node_url(args: &[String], wallet: Option<&VernamWallet>) -> String {
    if let Some(url) = get_flag(args, "--node") {
        return url;
    }
    if let Ok(url) = env::var("VRNM_NODE")
        && !url.is_empty()
    {
        return url;
    }
    if let Some(w) = wallet {
        return w.metadata().node_url.clone();
    }
    DEFAULT_NODE_URL.to_string()
}

fn resolve_recipient(to_arg: &str) -> Result<(u32, usize, usize), String> {
    if let Ok(id) = to_arg.parse::<u32>() {
        let bucket = (id as usize) / 16;
        let slot = (id as usize) % 16;
        return Ok((id, bucket, slot));
    }
    let valid_name = validate_wallet_name(to_arg).map_err(|e| format!("invalid recipient '{to_arg}': {e}"))?;
    let target_dir = wallet_base_dir().join(valid_name);
    let w = VernamWallet::open(&target_dir).map_err(|e| {
        format!(
            "could not parse recipient '{to_arg}' as account_id or open local wallet at {}: {e}",
            target_dir.display()
        )
    })?;
    let m = w.metadata();
    Ok((m.account_id, m.bucket_id, m.slot_in_bucket))
}

fn cmd_node(args: &[String]) -> Result<(), String> {
    let node_id: u64 = match get_flag(args, "--id") {
        Some(s) => s.parse::<u64>().map_err(|_| "invalid --id <u64>")?,
        None => 0,
    };
    let bind_addr = get_flag(args, "--bind")
        .or_else(|| env::var("VRNM_BIND").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());
    let advertise_addr = get_flag(args, "--advertise").unwrap_or_else(|| bind_addr.clone());
    let mut seeds = Vec::new();
    for raw in get_all_flags(args, "--seed") {
        for part in raw.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                seeds.push(trimmed.to_string());
            }
        }
    }
    let gossip_interval_ms: u64 = match get_flag(args, "--gossip-ms") {
        Some(s) => s.parse::<u64>().map_err(|_| "invalid --gossip-ms")?,
        None => 2_000,
    };

    let cfg = P2pNodeConfig {
        node_id,
        bind_addr: bind_addr.clone(),
        advertise_addr: advertise_addr.clone(),
        seeds: seeds.clone(),
        gossip_interval_ms,
    };
    let node = P2pNode::bind(cfg).map_err(|e| format!("failed to bind P2P node: {e}"))?;
    println!("========================================================================");
    println!("  VERNAM (VRNM) v0.4 DECENTRALIZED P2P VALIDATOR NODE RUNNING");
    println!("  Node ID         : {node_id}");
    println!("  Listen Address  : http://{}/", node.local_addr());
    println!("  Advertised Addr : {}", node.advertise_addr());
    println!(
        "  Bootstrap Seeds : {}",
        if seeds.is_empty() {
            "(none — acting as seed node)".to_string()
        } else {
            seeds.join(", ")
        }
    );
    println!("  Endpoints       : / (Explorer), /health, /status, /p2p/peers, /p2p/announce, /p2p/tx, /faucet");
    println!("========================================================================");
    node.serve_forever()
        .map_err(|e| format!("P2P node server error: {e}"))
}

fn cmd_pop_mine() -> Result<(), String> {
    println!("=== Vernam (VRNM) Bilateral Proof-of-Pad (PoP) Entropy Mining Audit ===");
    let mut tok = TokenomicsEngine::with_defaults();
    tok.mint_genesis_supply(10_000 * VERN_PER_VRNM)
        .map_err(|e| format!("{e}"))?;
    for vid in 0..4u64 {
        tok.register_genesis_validator(vid)
            .map_err(|e| format!("{e}"))?;
    }
    let mut replay = PopReplayRegistry::default();
    let epoch = tok.current_epoch();
    let mut submissions = Vec::with_capacity(4);
    for vid in 0..4u64 {
        let counterparty = (vid + 1) % 4;
        let peer_key = PeerReceiptKey::generate();
        let (mut batch, commit, peer_receipt) =
            PopMiner::mine_bilateral_pad_batch(vid, counterparty, epoch, 8, 8, &peer_key)
                .map_err(|e| format!("{e}"))?;
        let challenge = PopAuditor::issue_challenge(vid, epoch);
        let proof = PopMiner::answer_challenge(&mut batch, &challenge).with_liveness(1, 1);
        submissions.push(BilateralPopSubmission {
            commitment: commit,
            challenge,
            proof,
            peer_receipt: Some(peer_receipt),
            peer_key: Some(peer_key),
        });
    }
    let report = PopEpochCoordinator::run_bilateral_audited_epoch(&mut tok, &mut replay, &submissions);
    for rcpt in &report.accepted {
        println!(
            "  Validator V{} <-> Peer V{}: PASS | monobit_z={:.3} runs_z={:.3} QBER={:.2}% beaver_triple=OK peer_receipt=OK anti_replay=OK",
            rcpt.validator_id,
            rcpt.counterparty_id.unwrap_or(0),
            rcpt.entropy_stats.monobit_z_score,
            rcpt.entropy_stats.runs_z_score,
            rcpt.qkd_telemetry.qber * 100.0
        );
    }
    println!(
        "Epoch #{} settled: {}/{} passed (anti-replay tracked={} pads), minted {} across {} validators!",
        report.settlement.epoch,
        report.accepted.len(),
        submissions.len(),
        replay.tracked_pad_fingerprints(),
        fmt_vrnm(report.settlement.subsidy_minted),
        report.settlement.payouts.len()
    );
    Ok(())
}

fn cmd_miner(args: &[String]) -> Result<(), String> {
    let validator_id: u64 = match get_flag(args, "--id") {
        Some(s) => s.parse::<u64>().map_err(|_| "invalid --id <u64>")?,
        None => 0,
    };
    let cores: usize = match get_flag(args, "--cores") {
        Some(s) => s.parse::<usize>().map_err(|_| "invalid --cores <usize>")?,
        None => 1,
    };
    if cores == 0 {
        return Err("--cores must be >= 1".to_string());
    }
    let pages: usize = match get_flag(args, "--pages") {
        Some(s) => s.parse::<usize>().map_err(|_| "invalid --pages <usize>")?,
        None => 16,
    };
    let triples: usize = match get_flag(args, "--triples") {
        Some(s) => s.parse::<usize>().map_err(|_| "invalid --triples <usize>")?,
        None => 32,
    };
    let rounds: usize = match get_flag(args, "--rounds") {
        Some(s) => s.parse::<usize>().map_err(|_| "invalid --rounds <usize>")?,
        None => 0, // 0 = run forever until Ctrl+C
    };
    let interval_secs: u64 = match get_flag(args, "--interval") {
        Some(s) => s.parse::<u64>().map_err(|_| "invalid --interval <u64>")?,
        None => 15,
    };
    let node_url = resolve_node_url(args, None);
    let rpc = WalletRpcClient::new(&node_url).map_err(|e| format!("rpc: {e}"))?;

    println!("========================================================================");
    println!("  VERNAM (VRNM) PROOF-OF-PAD (PoP) ENTROPY MINER");
    println!("  Validator ID : V{validator_id} | Worker Cores : {cores} (pinned 1-thread mode={})", cores == 1);
    println!("  Target Node  : {node_url}");
    println!("  Batch Size   : {pages} OTP pages ({} B) + {triples} Beaver triples / round", pages * FRAME_BYTES);
    println!("========================================================================");

    let counterparty_id = validator_id.wrapping_add(1);
    let mut replay = PopReplayRegistry::default();
    let mut round: usize = 0;
    loop {
        round += 1;
        let t0 = Instant::now();
        // Strictly single-threaded 1-core execution when cores == 1 (or parallel workers if > 1).
        let (rcpt, total_pages, total_triples) = if cores == 1 {
            let peer_key = PeerReceiptKey::generate();
            let (mut batch, commit, peer_receipt) = PopMiner::mine_bilateral_pad_batch(
                validator_id,
                counterparty_id,
                round as u64,
                pages,
                triples,
                &peer_key,
            )
            .map_err(|e| format!("PoP bilateral mine failed: {e}"))?;
            let challenge = PopAuditor::issue_challenge(validator_id, round as u64);
            let proof = PopMiner::answer_challenge(&mut batch, &challenge).with_liveness(1, 1);
            let rcpt = PopAuditor::verify_bilateral_proof(
                &commit,
                &challenge,
                &proof,
                Some(&peer_receipt),
                Some(&peer_key),
                &mut replay,
            )
            .map_err(|e| format!("bilateral self-audit failed: {e}"))?;
            (rcpt, pages, triples)
        } else {
            let mut results = Vec::with_capacity(cores);
            std::thread::scope(|s| {
                let mut handles = Vec::with_capacity(cores);
                for c in 0..cores {
                    handles.push(s.spawn(move || -> Result<_, String> {
                        let peer_key = PeerReceiptKey::generate();
                        let mut worker_replay = PopReplayRegistry::default();
                        let (mut batch, cm, peer_receipt) = PopMiner::mine_bilateral_pad_batch(
                            validator_id,
                            counterparty_id,
                            round as u64,
                            pages,
                            triples,
                            &peer_key,
                        )
                        .map_err(|e| format!("worker {c}: {e}"))?;
                        let ch = PopAuditor::issue_challenge(validator_id, round as u64);
                        let pr = PopMiner::answer_challenge(&mut batch, &ch).with_liveness(1, 1);
                        PopAuditor::verify_bilateral_proof(
                            &cm,
                            &ch,
                            &pr,
                            Some(&peer_receipt),
                            Some(&peer_key),
                            &mut worker_replay,
                        )
                        .map_err(|e| format!("worker {c}: {e}"))
                    }));
                }
                for h in handles {
                    results.push(h.join().map_err(|_| "miner worker panicked".to_string())?);
                }
                Ok::<(), String>(())
            })?;
            let first = results.into_iter().next().unwrap()?;
            (first, pages * cores, triples * cores)
        };
        let mine_ms = t0.elapsed().as_secs_f64() * 1_000.0;
        let pads_per_sec = total_pages as f64 / (mine_ms / 1_000.0);
        let triples_per_sec = total_triples as f64 / (mine_ms / 1_000.0);

        let t_net = Instant::now();
        let node_resp = rpc.mine_pop_epoch();
        let net_ms = t_net.elapsed().as_secs_f64() * 1_000.0;

        match node_resp {
            Ok(json) => {
                println!(
                    "[Round #{round}] Local 1-core mine: {mine_ms:.1} ms ({pads_per_sec:.0} pads/s, {triples_per_sec:.0} triples/s) | \
                     QBER={:.2}% monobit_z={:.2} runs_z={:.2} | Node submit: {net_ms:.1} ms -> {json}",
                    rcpt.qkd_telemetry.qber * 100.0,
                    rcpt.entropy_stats.monobit_z_score,
                    rcpt.entropy_stats.runs_z_score,
                );
            }
            Err(e) => {
                println!(
                    "[Round #{round}] Local mine OK ({mine_ms:.1} ms, QBER={:.2}%), node submit warning: {e}",
                    rcpt.qkd_telemetry.qber * 100.0
                );
            }
        }

        if rounds > 0 && round >= rounds {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval_secs));
    }
    Ok(())
}

fn cmd_testnet(args: &[String]) -> Result<(), String> {
    let mut cfg = TestnetConfig::default();
    if let Some(bind) = get_flag(args, "--bind") {
        cfg.bind_addr = bind;
    }
    let server = TestnetServer::bind(cfg.clone())
        .map_err(|e| format!("failed to bind testnet server on {}: {e}", cfg.bind_addr))?;
    let addr = server
        .local_addr()
        .map_err(|e| format!("local_addr error: {e}"))?;
    println!("========================================================================");
    println!("  VERNAM (VRNM) v0.3 LIVE TESTNET NODE RUNNING");
    println!("  Web Explorer & Faucet : http://{addr}/");
    println!("  Health Check          : http://{addr}/health");
    println!("  JSON Telemetry        : http://{addr}/status");
    println!("  Validators            : 4 (V0..V3, N=3f+1, quorum=3, 100% pure OTP)");
    println!("========================================================================");
    server.serve_forever();
    Ok(())
}

fn cmd_wallet(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("help");
    let rest = if args.len() > 1 { &args[1..] } else { &[] };

    match sub {
        "create" => {
            let name = get_flag(rest, "--name").ok_or("missing --name <wallet_name>")?;
            let valid_name = validate_wallet_name(&name).map_err(|e| format!("{e}"))?;
            let dir = if let Some(d) = get_flag(rest, "--dir") {
                PathBuf::from(d)
            } else {
                wallet_base_dir().join(valid_name)
            };
            let account_id = match get_flag(rest, "--id") {
                Some(s) => s.parse::<u32>().map_err(|_| "invalid --id <u32>")?,
                None => next_free_account_id(&wallet_base_dir()),
            };
            let pages = match get_flag(rest, "--pages") {
                Some(s) => s.parse::<usize>().map_err(|_| "invalid --pages <usize>")?,
                None => 16,
            };
            let node_url = resolve_node_url(rest, None);
            let w = VernamWallet::create(&dir, &name, account_id, 4, pages, &node_url)
                .map_err(|e| format!("wallet create failed: {e}"))?;
            println!("Created crash-safe Vernam (VRNM) wallet at {}", dir.display());
            println!("{}", w.status_report());
            Ok(())
        }
        "status" => {
            if get_flag(rest, "--name").is_some() || get_flag(rest, "--dir").is_some() {
                let dir = resolve_wallet_dir(rest, "--name")?;
                let w = VernamWallet::open(&dir).map_err(|e| format!("open wallet: {e}"))?;
                println!("{}", w.status_report());
                let node_url = resolve_node_url(rest, Some(&w));
                let rpc = WalletRpcClient::new(&node_url).map_err(|e| format!("rpc: {e}"))?;
                if let Ok(net_json) = rpc.status() {
                    println!("\nNode Status ({node_url}):\n{net_json}");
                }
            } else {
                let node_url = resolve_node_url(rest, None);
                let rpc = WalletRpcClient::new(&node_url).map_err(|e| format!("rpc: {e}"))?;
                let net_json = rpc
                    .status()
                    .map_err(|e| format!("failed to query node {node_url}: {e}"))?;
                println!("Vernam Testnet Status ({node_url}):\n{net_json}");
            }
            Ok(())
        }
        "faucet" => {
            let dir = resolve_wallet_dir(rest, "--name")?;
            let mut w = VernamWallet::open(&dir).map_err(|e| format!("open wallet: {e}"))?;
            let express = match get_flag(rest, "--express") {
                Some(s) => s.parse::<u64>().map_err(|_| "invalid --express")?,
                None => 1_000,
            };
            let shielded = match get_flag(rest, "--shielded") {
                Some(s) => s.parse::<u64>().map_err(|_| "invalid --shielded")?,
                None => 500,
            };
            let node_url = resolve_node_url(rest, Some(&w));
            let rpc = WalletRpcClient::new(&node_url).map_err(|e| format!("rpc: {e}"))?;
            let resp = rpc
                .faucet(w.metadata().account_id, express, shielded)
                .map_err(|e| format!("faucet RPC failed: {e}"))?;
            if let Ok(bal_json) = rpc.get_balance(w.metadata().account_id) {
                let eb = parse_json_u64(&bal_json, "express_balance").unwrap_or(express);
                let sb = parse_json_u64(&bal_json, "shielded_balance").unwrap_or(shielded);
                let _ = w.sync_balances(eb, sb);
            }
            println!("Faucet credited account #{} ({}):", w.metadata().account_id, w.metadata().name);
            println!("{resp}");
            Ok(())
        }
        "balance" => {
            let dir = resolve_wallet_dir(rest, "--name")?;
            let mut w = VernamWallet::open(&dir).map_err(|e| format!("open wallet: {e}"))?;
            let node_url = resolve_node_url(rest, Some(&w));
            let rpc = WalletRpcClient::new(&node_url).map_err(|e| format!("rpc: {e}"))?;
            let bal_json = rpc
                .get_balance(w.metadata().account_id)
                .map_err(|e| format!("balance RPC failed: {e}"))?;
            if let (Some(eb), Some(sb)) = (
                parse_json_u64(&bal_json, "express_balance"),
                parse_json_u64(&bal_json, "shielded_balance"),
            ) {
                let _ = w.sync_balances(eb, sb);
            }
            println!(
                "Wallet '{}' (account #{}) @ {node_url}:",
                w.metadata().name,
                w.metadata().account_id
            );
            println!("{bal_json}");
            println!("Local WAL OTP pages remaining: {}", w.remaining_pages());
            Ok(())
        }
        "send" => {
            let dir = resolve_wallet_dir(rest, "--from")?;
            let mut w = VernamWallet::open(&dir).map_err(|e| format!("open wallet: {e}"))?;
            let to_arg = get_flag(rest, "--to").ok_or("missing --to <name|account_id>")?;
            let (to_id, _, _) = resolve_recipient(&to_arg)?;
            let amount: u64 = get_flag(rest, "--amount")
                .ok_or("missing --amount <u64>")?
                .parse()
                .map_err(|_| "invalid --amount <u64>")?;

            if w.remaining_pages() == 0 {
                println!("OTP pad book empty — auto-replenishing 8 pages via BB84 QKD...");
                w.replenish_pads_via_qkd(8)
                    .map_err(|e| format!("QKD refill failed: {e}"))?;
            }
            let bundle = w
                .prepare_express_transfer(to_id, amount)
                .map_err(|e| format!("sign express tx: {e}"))?;
            let node_url = resolve_node_url(rest, Some(&w));
            let rpc = WalletRpcClient::new(&node_url).map_err(|e| format!("rpc: {e}"))?;
            let frame_hex = bundle.primary_frame_hex().unwrap_or_default();
            let tag_hex = bundle.primary_tag_hex().unwrap_or_default();
            let resp = rpc
                .send_express(
                    bundle.sender_id,
                    bundle.recipient_id,
                    bundle.amount,
                    bundle.page_id,
                    bundle.nonce,
                    &frame_hex,
                    &tag_hex,
                )
                .map_err(|e| format!("send express RPC failed: {e}"))?;
            println!(
                "Sent {amount} VRNM (Express Lane, WAL page #{} burned) -> account #{to_id}:",
                bundle.page_id
            );
            println!("{resp}");
            Ok(())
        }
        "send-private" => {
            let dir = resolve_wallet_dir(rest, "--from")?;
            let mut w = VernamWallet::open(&dir).map_err(|e| format!("open wallet: {e}"))?;
            let to_arg = get_flag(rest, "--to").ok_or("missing --to <name|account_id>")?;
            let (to_id, bucket, slot) = resolve_recipient(&to_arg)?;
            let amount: u64 = get_flag(rest, "--amount")
                .ok_or("missing --amount <u64>")?
                .parse()
                .map_err(|_| "invalid --amount <u64>")?;

            let node_url = resolve_node_url(rest, Some(&w));
            let rpc = WalletRpcClient::new(&node_url).map_err(|e| format!("rpc: {e}"))?;
            // Sync shielded balance before local proof check
            if let Ok(bal_json) = rpc.get_balance(w.metadata().account_id)
                && let (Some(eb), Some(sb)) = (
                    parse_json_u64(&bal_json, "express_balance"),
                    parse_json_u64(&bal_json, "shielded_balance"),
                )
            {
                let _ = w.sync_balances(eb, sb);
            }
            let _local_req = w
                .prepare_shielded_transfer(bucket, slot, amount)
                .map_err(|e| format!("prepare shielded tx: {e}"))?;
            let resp = rpc
                .send_shielded(w.metadata().account_id, bucket, slot, amount)
                .map_err(|e| format!("send shielded RPC failed: {e}"))?;
            println!(
                "Sent {amount} VRNM (Shielded IT-MPC Lane, hidden amount & recipient) -> account #{to_id} (bucket {bucket}, slot {slot}):"
            );
            println!("{resp}");
            Ok(())
        }
        "refill" => {
            let dir = resolve_wallet_dir(rest, "--name")?;
            let mut w = VernamWallet::open(&dir).map_err(|e| format!("open wallet: {e}"))?;
            let pages = match get_flag(rest, "--pages") {
                Some(s) => s.parse::<usize>().map_err(|_| "invalid --pages")?,
                None => 8,
            };
            let added = w
                .replenish_pads_via_qkd(pages)
                .map_err(|e| format!("QKD refill failed: {e}"))?;
            println!(
                "Replenished {} fresh BB84 QKD OTP pages per validator (remaining: {}).",
                added,
                w.remaining_pages()
            );
            Ok(())
        }
        "peers" => {
            let node_url = resolve_node_url(rest, None);
            let peers = discover_network_peers(&node_url)
                .map_err(|e| format!("peer discovery via {node_url} failed: {e}"))?;
            println!(
                "Auto-discovered {} active Vernam (VRNM) peer(s) via {node_url}:",
                peers.len()
            );
            for p in peers {
                println!(
                    "  node_id={:<3} addr={:<24} height={:<6} pop_score={:<5} qber={:.2}% healthy={}",
                    p.node_id,
                    p.addr,
                    p.height,
                    p.pop_score,
                    p.qber * 100.0,
                    p.healthy
                );
            }
            Ok(())
        }
        "pop-mine" => {
            let node_url = resolve_node_url(rest, None);
            let rpc = WalletRpcClient::new(&node_url).map_err(|e| format!("rpc: {e}"))?;
            let resp = rpc
                .mine_pop_epoch()
                .map_err(|e| format!("PoP mine RPC failed: {e}"))?;
            println!("Verified Proof-of-Pad (PoP) Epoch Mined @ {node_url}:");
            println!("{resp}");
            Ok(())
        }
        "refresh-epoch" => {
            let node_url = resolve_node_url(rest, None);
            let rpc = WalletRpcClient::new(&node_url).map_err(|e| format!("rpc: {e}"))?;
            let resp = rpc
                .trigger_pss_refresh()
                .map_err(|e| format!("epoch refresh RPC failed: {e}"))?;
            println!("Triggered Proactive Secret Sharing (PSS) & Proof-of-Pad Epoch Refresh:");
            println!("{resp}");
            Ok(())
        }
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn cmd_bench() {
    println!("========================================================================");
    println!("  VERNAM (VRNM) v0.5 — TURBO SIMD & ALGEBRAIC IT-MPC BENCHMARKS");
    println!("  Zero external crates | Zero SHA-256 / RSA / ECDSA / AES / zk-SNARKs");
    println!("========================================================================\n");

    let tc = run_turbo_crypto_bench();
    println!("=== 1. Turbo SIMD Crypto Primitives ===");
    println!("  OTP XOR ({:<10})    : {:>8.2} GB/s", tc.xor_backend, tc.xor_gb_per_sec);
    println!(
        "  CW MAC 4-Way (256B)    : {:>12.0} ops/s ({:.2} GB/s streaming)",
        tc.cw_mac_ops_per_sec, tc.cw_mac_gb_per_sec
    );
    println!(
        "  Toeplitz PA ({:<15}): {:>7.2} Mbps purified QKD output\n",
        tc.toeplitz_backend, tc.toeplitz_mbps
    );

    let te = run_turbo_express_bench();
    println!("=== 2. Turbo Express Lane (Persistent 4-Validator 2-Phase BFT) ===");
    println!(
        "  Express 4-Val BFT TPS  : {:>12.0} tx/s ({} txs / {} blocks in {:.4}s, {:.3} ms/block)\n",
        te.express_tps, te.total_txs, te.blocks, te.elapsed_secs, te.ms_per_block
    );

    let ts = run_turbo_shielded_bench();
    println!("=== 3. Turbo Shielded Lane (Beaver Squares + Star + Schwartz-Zippel RLC) ===");
    println!("{ts}\n");

    let dm = run_distributed_mpc_bench(100).expect("4-daemon real-TCP MPC bench");
    println!("=== 4. Split-Share 4-Daemon Real-TCP Shielded IT-MPC (1 Share / Server) ===");
    println!(
        "  4-Daemon TCP Shielded  : {:>9.0} tx/s (avg={:.3} ms, p50={:.3} ms, p99={:.3} ms, PSS={:.3} ms, {} B/tx)\n",
        dm.tps,
        dm.avg_latency_ms,
        dm.p50_latency_ms,
        dm.p99_latency_ms,
        dm.pss_refresh_ms,
        dm.inter_validator_wire_bytes_per_tx
    );

    let report = run_speed_benchmarks();
    println!("=== 5. Baseline Fast Engine Comparison (v0.3 BIP-152 Compact Relay) ===");
    println!("{report}");
}

fn cmd_v1_demo() -> Result<(), String> {
    println!("========================================================================");
    println!("  VERNAM (VRNM) v1.0 — ZERO-ADMIN 100% DECENTRALIZED ARCHITECTURE DEMO");
    println!("  Unbiasable Threshold Beacon | 4-Daemon TCP MPC | 4->7 Resharing");
    println!("========================================================================\n");

    // 1. Unbiasable Threshold Beacon (V3 aborts last-revealer -> still reconstructed!)
    println!("[1/3] Unbiasable Threshold Entropy Beacon (t=3, N=4, V3 Aborts Reveal)");
    let cfg = BeaconConfig::bft(4).map_err(|e| format!("{e}"))?;
    let mut nodes: Vec<VernamBeacon> = (0..4u32)
        .map(|id| VernamBeacon::new(cfg, 1, id).unwrap())
        .collect();
    let pad_len = cfg.share_payload_bytes();
    for dealer in 0..4usize {
        let mut pairs: Vec<(u32, OtpChannelKey, OtpChannelKey)> = (0..4u32)
            .map(|recip| {
                let (s_k, r_k) = OtpChannelKey::generate_pair(pad_len);
                (recip, s_k, r_k)
            })
            .collect();
        let key_refs: Vec<(u32, &OtpChannelKey)> =
            pairs.iter().map(|(r, sk, _)| (*r, sk)).collect();
        let envs = nodes[dealer]
            .generate_commit_envelopes(&key_refs)
            .map_err(|e| format!("{e}"))?;
        for env in envs {
            let r = env.recipient_id as usize;
            nodes[r]
                .receive_commit_envelope(&env, &pairs[r].2)
                .map_err(|e| format!("{e}"))?;
        }
        pairs.clear();
    }
    for i in 0..4usize {
        nodes[i].lock_commit_phase().map_err(|e| format!("{e}"))?;
    }
    // Only V0, V1, V2 reveal; V3 ABORTS to try to bias the beacon!
    let mut reveals = Vec::new();
    for i in 0..3usize {
        reveals.push(nodes[i].generate_reveal().map_err(|e| format!("{e}"))?);
    }
    for r in &reveals {
        for i in 0..3usize {
            nodes[i].receive_reveal(r).map_err(|e| format!("{e}"))?;
        }
    }
    // V0, V1, V2 forcibly reconstruct V3's aborted secret via Lagrange recovery shares!
    let mut rec_shares = Vec::new();
    for holder in 0..3usize {
        rec_shares.push(
            nodes[holder]
                .generate_recovery_share(3)
                .map_err(|e| format!("{e}"))?,
        );
    }
    for rs in &rec_shares {
        for i in 0..3usize {
            nodes[i]
                .receive_recovery_share(rs)
                .map_err(|e| format!("{e}"))?;
        }
    }
    let out0 = nodes[0].finalize_epoch().map_err(|e| format!("{e}"))?;
    let out1 = nodes[1].finalize_epoch().map_err(|e| format!("{e}"))?;
    assert_eq!(out0.gamma, out1.gamma);
    let mut clock = AutonomousEpochClock::new(10).map_err(|e| format!("{e}"))?;
    let _ev = clock.on_block_finalized(10);
    clock
        .complete_beacon_round(out0.clone())
        .map_err(|e| format!("{e}"))?;
    println!(
        "  Beacon Gamma_1         : {:#034x} (identical across V0..V2; V3 abort defeated!)",
        out0.gamma
    );
    println!(
        "  Leader permutation     : {:?} | Next stage: {:?}\n",
        out0.epoch_leader_order(4),
        clock.pipeline_stage()
    );

    // 2. Real 4-Daemon Split-Share TCP Shielded IT-MPC
    println!("[2/3] True Split-Share 4-Daemon Real-TCP Shielded IT-MPC (1 Share / Server)");
    let dm = run_distributed_mpc_bench(100).map_err(|e| format!("{e}"))?;
    println!(
        "  100 live 4-TCP txs     : {:.0} TPS | avg={:.3} ms | p50={:.3} ms | p99={:.3} ms",
        dm.tps, dm.avg_latency_ms, dm.p50_latency_ms, dm.p99_latency_ms
    );
    println!(
        "  4-Daemon TCP PSS sync  : {:.3} ms | Wire traffic: {} B/tx across 12 OTP+MAC links\n",
        dm.pss_refresh_ms, dm.inter_validator_wire_bytes_per_tx
    );

    // 3. Zero-Reconstruction Dynamic Committee Scaling (4 -> 7 Validators!)
    println!("[3/3] Zero-Reconstruction Dynamic Committee Scaling: (3, 4) -> (5, 7)");
    let old_coords = [1u64, 2, 3, 4];
    let new_coords = [1u64, 2, 3, 4, 5, 6, 7];
    let mut old_ledger = BTreeMap::new();
    for acct in 0..16u64 {
        let bal = (acct + 1) * 1_000;
        let shares = split_secret(bal as u128, 3, &old_coords).map_err(|e| format!("{e}"))?;
        old_ledger.insert(acct, shares);
    }
    let res = redistribute_ledger_accounts(2, &old_ledger, &[1, 2, 3], &new_coords, 5)
        .map_err(|e| format!("{e}"))?;
    for acct in 0..16u64 {
        let new_shares = &res.redistributed_accounts[&acct];
        verify_committee_shares(new_shares, 5).map_err(|e| format!("{e}"))?;
        let rec = reconstruct_secret(&new_shares[..5], 5).map_err(|e| format!("{e}"))?;
        assert_eq!(rec, ((acct + 1) * 1_000) as u128);
    }
    println!(
        "  Reshared 16 accounts   : (3, 4) -> (5, 7) with ZERO balance reconstruction ({} OTP bytes)",
        res.otp_bytes_consumed
    );
    println!("  Degree-4 verification  : ALL 16 accounts verified exact across 7 new validators!");
    println!("\n========================================================================");
    println!("  VERNAM (VRNM) v1.0 ZERO-ADMIN DECENTRALIZED ARCHITECTURE VERIFIED.");
    println!("========================================================================");
    Ok(())
}

fn cmd_demo() {
    println!("========================================================================");
    println!("  VERNAM (VRNM) v0.3 — Information-Theoretically Secure OTP Coin (Rust)");
    println!("  Zero external crates | Zero SHA-256 / RSA / ECDSA / AES / zk-SNARKs");
    println!("  Immune to Quantum Computers AND P = NP (pure Shannon + Quantum physics)");
    println!("========================================================================\n");

    // 1. WAL OTP
    println!("[1/6] Zeroized OTP + Crash-Safe WAL PadBook + Carter-Wegman MAC");
    let demo_dir = std::env::temp_dir().join(format!(
        "vernam_demo_{}_{:016x}",
        std::process::id(),
        random_field_elem() as u64
    ));
    fs::create_dir_all(&demo_dir).expect("create unique demo temp dir");
    let wal_path = demo_dir.join("vernam_demo_pad.bin");
    {
        let pages: Vec<PadPage> = (0..4).map(|i| PadPage::generate(i, FRAME_BYTES)).collect();
        let mut wal = WalPadBook::create(&wal_path, FRAME_BYTES, pages).expect("create WAL");
        let p0 = wal.pop_next().expect("pop page 0");
        let (ct, tag) = seal_frame(&p0, b"VRNM:alice->bob:250").expect("seal");
        let pt = open_frame(&p0, &ct, &tag).expect("open");
        assert_eq!(pt, b"VRNM:alice->bob:250");
        drop(p0);
    }
    {
        let reloaded = WalPadBook::open(&wal_path).expect("reload WAL after crash");
        assert!(reloaded.is_burned(0));
        println!(
            "  WAL crash-reload check : OK (page 0 burned & zeroed on disk, {} pages remaining)\n",
            reloaded.remaining()
        );
    }
    let _ = fs::remove_dir_all(&demo_dir);

    // 2. Express 2-Phase Batched BFT + Offline Catch-up
    println!("[2/6] Express Lane (VRNM-Fast): 2-Phase Batched BFT + Offline Quorum Catch-Up");
    let cfg = BftConfig::default();
    let mut init_bal = BTreeMap::new();
    init_bal.insert(1u32, 100_000_000u64);
    init_bal.insert(2u32, 0u64);
    let mut cluster = BftCluster::new(cfg, init_bal, 512, 64, 8);
    cluster.set_online(3, false).unwrap();
    cluster
        .propose_and_finalize_batch(vec![BinaryTx {
            sender_id: 1,
            recipient_id: 2,
            amount: 500,
            page_id: 0,
            nonce: 0,
        }])
        .unwrap();
    cluster.set_online(3, true).unwrap();
    let synced = cluster.sync_validator_from_quorum(3).unwrap();
    println!("  Offline catch-up sync  : V3 synced {synced} missed block(s) via quorum certificates\n");

    // 3. Sharded IT-MPC
    println!("[3/6] Shielded Lane (VRNM-Private): Sharded IT-MPC + PSS + Cover Frames");
    let mut ledger = ShardedPrivateLedger::new_default(4).unwrap();
    ledger.mint_initial_balance(0, 50_000).unwrap();
    let mut beaver_pool = BeaverPool::new_3_of_4(10 * ledger.triples_per_transfer());
    let req = ConfidentialTransferRequest::new(0, 50_000, 0, 1, 2_000, 16, 16, 3, 4).unwrap();
    ledger.execute_sharded_transfer(&req, &mut beaver_pool).unwrap();
    let epoch = ledger.proactive_refresh_epoch().unwrap();
    println!(
        "  Verified balances      : Alice={} VRNM, Bob={} VRNM (after PSS Epoch {} refresh)\n",
        ledger.reconstruct_balance(0).unwrap(),
        ledger.reconstruct_balance(1).unwrap(),
        epoch
    );

    // 4. QKD
    println!("[4/6] Quantum Key Distribution (BB84 + Decoy-State + BufferedQkdPool)");
    let mut clean_qkd = Bb84Channel::default_channel();
    let ex = clean_qkd.exchange_key(256).expect("clean BB84");
    assert_eq!(ex.alice_key, ex.bob_key);
    println!(
        "  Clean BB84 + Decoy     : 256B purified key OK (QBER={:.2}%, decoy_ratio={:.3})",
        ex.qber * 100.0,
        ex.decoy_yield_ratio
    );
    let mut eve_qkd = Bb84Channel::with_attack(AttackProfile::InterceptResend {
        intercept_rate: 1.0,
    });
    println!("  Intercept-Resend Eve   : BLOCKED ({:?})", eve_qkd.exchange_key(64).unwrap_err());
    let mut pns_qkd = Bb84Channel::with_attack(AttackProfile::PhotonNumberSplitting {
        single_photon_block_rate: 0.9,
        multiphoton_transmittance: 1.0,
    });
    println!("  Decoy-State PNS attack : BLOCKED ({:?})", pns_qkd.exchange_key(64).unwrap_err());
    let mut qkd_pool = BufferedQkdPool::new(PoolConfig {
        capacity_bytes: 16_384,
        low_watermark_bytes: 8_192,
        refill_chunk_bytes: 2_048,
        num_channels: 2,
        ..PoolConfig::default()
    })
    .unwrap();
    let burst_key = qkd_pool.get_key("V1", 1024).unwrap();
    println!("  BufferedQkdPool burst  : served {}B instantly from multi-threaded ring buffer\n", burst_key.len());

    // 5. Tokenomics
    println!("[5/6] Proof-of-Pad Tokenomics (21M Cap, 80/20 Pad-Burn Fees, Slashing)");
    let mut tok = TokenomicsEngine::with_defaults();
    tok.mint_genesis_supply(10_000 * VERN_PER_VRNM).unwrap();
    for vid in 0..4u64 {
        tok.register_genesis_validator(vid).unwrap();
    }
    for _ in 0..100 {
        tok.collect_fee(FeeLane::Express).unwrap();
    }
    for _ in 0..25 {
        tok.collect_fee(FeeLane::Shielded).unwrap();
    }
    for vid in 0..3u64 {
        tok.record_contribution(
            vid,
            EpochContribution {
                pad_pages_supplied: 2_000,
                beaver_triples_contributed: 10_000,
                blocks_finalized: 20,
                pss_refreshes_completed: 1,
            },
        )
        .unwrap();
    }
    let slash_rcpt = tok.slash_validator(3, SlashingOffense::Equivocation).unwrap();
    let settlement = tok.settle_epoch();
    let audit_key = OneTimeAuditKey::generate();
    let verifier_key = audit_key.duplicate_for_verifier();
    let audit_tag = audit_key.tag_settlement(&settlement);
    assert!(verifier_key.verify_settlement(&settlement, &audit_tag));
    println!("  Hard supply cap        : {}", fmt_vrnm(MAX_SUPPLY));
    println!(
        "  Equivocator V3 slashed : {} burned (status={:?})",
        fmt_vrnm(slash_rcpt.slashed_amount),
        slash_rcpt.new_status
    );
    println!(
        "  Epoch #{} settled       : subsidy={}, fees_burned={}, honest_payouts={} validators\n",
        settlement.epoch,
        fmt_vrnm(settlement.subsidy_minted),
        fmt_vrnm(settlement.fees_burned_in_epoch),
        settlement.payouts.len()
    );

    // 6. Bitcoin Core / Sealevel-Inspired Fast Engine Benchmarks
    println!("[6/6] High-Throughput Fast Engine (BIP-152 Compact Relay + Multi-Core Sharded MPC)");
    let report = run_speed_benchmarks();
    println!("{report}");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("demo");
    let rest = if args.len() > 1 { &args[1..] } else { &[] };

    let res = match cmd {
        "demo" => {
            cmd_demo();
            Ok(())
        }
        "v1-demo" => cmd_v1_demo(),
        "bench" => {
            cmd_bench();
            Ok(())
        }
        "testnet" => cmd_testnet(rest),
        "node" => cmd_node(rest),
        "pop-mine" => cmd_pop_mine(),
        "miner" => cmd_miner(rest),
        "wallet" => cmd_wallet(rest),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown command '{other}' (run `vrnm help`)")),
    };

    if let Err(err) = res {
        eprintln!("error: {err}");
        process::exit(1);
    }
}
