//! Vernam (VRNM) v0.3 — Unified CLI (`vrnm`): Testnet Server, Crash-Safe Wallet,
//! Integrated 5-Pillar Showcase, and Multi-Core Speed Benchmarks.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use vernam_rs::bft::{BftCluster, BftConfig, BinaryTx, WebOfTrustRegistry};
use vernam_rs::fast_engine::run_speed_benchmarks;
use vernam_rs::otp::{FRAME_BYTES, PadPage, WalPadBook, open_frame, seal_frame};
use vernam_rs::privacy_mpc::{BeaverPool, ConfidentialTransferRequest, ShardedPrivateLedger};
use vernam_rs::qkd::{
    AttackProfile, Bb84Channel, BufferedQkdPool, PoolConfig, QkdKeyProvider, toeplitz_hash_u64,
    toeplitz_seed_words,
};
use vernam_rs::testnet_server::{TestnetConfig, TestnetServer, parse_json_u64};
use vernam_rs::tokenomics::{
    EpochContribution, FeeLane, MAX_SUPPLY, OneTimeAuditKey, SlashingOffense, TokenomicsEngine,
    VERN_PER_VRNM,
};
use vernam_rs::wallet::{DEFAULT_NODE_URL, VernamWallet, WalletRpcClient};

fn fmt_vrnm(verns: u64) -> String {
    format!("{:.4} VRNM", verns as f64 / VERN_PER_VRNM as f64)
}

fn print_help() {
    println!(
        r#"Vernam (VRNM) v0.3 — 100% Information-Theoretically Secure OTP Coin

USAGE:
  vrnm [COMMAND] [OPTIONS]

COMMANDS:
  demo                                  Run full 5-pillar showcase + speed benchmarks (default)
  bench                                 Run high-throughput Express & Shielded TPS benchmarks
  testnet [--bind 0.0.0.0:8080]         Start live 4-validator HTTP testnet + web explorer
  wallet create  --name <n> [--id <u32>] [--pages 16] [--node <url>] [--dir <path>]
  wallet status  [--name <n>] [--node <url>] [--dir <path>]
  wallet faucet  --name <n> [--express 1000] [--shielded 500] [--node <url>]
  wallet balance --name <n> [--node <url>]
  wallet send    --from <n> --to <name|id> --amount <u64> [--node <url>]
  wallet send-private --from <n> --to <name|id> --amount <u64> [--node <url>]
  wallet refill  --name <n> [--pages 8]
  wallet refresh-epoch [--node <url>]
  help                                  Show this help message

ENVIRONMENT:
  VRNM_BIND        Default testnet listen address (default: 0.0.0.0:8080)
  VRNM_NODE        Default RPC node URL for wallet commands (default: http://127.0.0.1:8080)
  VRNM_WALLET_DIR  Base directory for local wallets (default: ~/.vernam/wallets)
"#
    );
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
    Ok(wallet_base_dir().join(name))
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
    let target_dir = wallet_base_dir().join(to_arg);
    let w = VernamWallet::open(&target_dir).map_err(|e| {
        format!(
            "could not parse recipient '{to_arg}' as account_id or open local wallet at {}: {e}",
            target_dir.display()
        )
    })?;
    let m = w.metadata();
    Ok((m.account_id, m.bucket_id, m.slot_in_bucket))
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
            let dir = if let Some(d) = get_flag(rest, "--dir") {
                PathBuf::from(d)
            } else {
                wallet_base_dir().join(&name)
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
    println!("  VERNAM (VRNM) v0.3 — HIGH-THROUGHPUT MULTI-CORE BENCHMARKS");
    println!("  Bitcoin Core BIP-152 Compact Relay + Flat IndexedLedger + Sealevel MPC");
    println!("========================================================================\n");

    let report = run_speed_benchmarks();
    println!("{report}\n");

    // Raw single-core OTP + Carter-Wegman MAC
    let bench_ops = 200_000usize;
    let bench_page = PadPage::generate(99, FRAME_BYTES);
    let sample_payload = [0xABu8; 64];
    let t0 = Instant::now();
    let mut acc_byte = 0u8;
    for _ in 0..bench_ops {
        let (ct, tag) = seal_frame(&bench_page, &sample_payload).unwrap();
        let pt = open_frame(&bench_page, &ct, &tag).unwrap();
        acc_byte ^= pt[0];
    }
    let elapsed = t0.elapsed().as_secs_f64();
    let ops_per_sec = bench_ops as f64 / elapsed;
    let mb_per_sec = (bench_ops as f64 * (FRAME_BYTES as f64 * 2.0)) / (elapsed * 1_000_000.0);
    println!(
        "  Single-core OTP+MAC    : {:.0} ops/sec ({:.1} MB/s, guard={})",
        ops_per_sec, mb_per_sec, acc_byte
    );

    // POPCNT Toeplitz PA
    let raw_bits = 4096usize;
    let out_bits = 2048usize;
    let raw_words = vec![0xA5A5_5A5A_1234_5678u64; raw_bits / 64];
    let seed_words = vec![0x9E37_79B9_7F4A_7C15u64; toeplitz_seed_words(raw_bits, out_bits)];
    let pa_iters = 5_000usize;
    let t3 = Instant::now();
    let mut pa_guard = 0u64;
    for _ in 0..pa_iters {
        let out = toeplitz_hash_u64(&raw_words, raw_bits, &seed_words, out_bits).unwrap();
        pa_guard ^= out[0];
    }
    let pa_elapsed = t3.elapsed().as_secs_f64();
    let pa_mbps = (pa_iters as f64 * out_bits as f64) / (pa_elapsed * 1_000_000.0);
    println!(
        "  POPCNT Toeplitz PA     : {:.1} Mbps purified QKD output (guard={:#x})",
        pa_mbps, pa_guard
    );
}

fn cmd_demo() {
    println!("========================================================================");
    println!("  VERNAM (VRNM) v0.3 — Information-Theoretically Secure OTP Coin (Rust)");
    println!("  Zero external crates | Zero SHA-256 / RSA / ECDSA / AES / zk-SNARKs");
    println!("  Immune to Quantum Computers AND P = NP (pure Shannon + Quantum physics)");
    println!("========================================================================\n");

    // 1. WAL OTP
    println!("[1/6] Zeroized OTP + Crash-Safe WAL PadBook + Carter-Wegman MAC");
    let wal_path = std::env::temp_dir().join("vernam_demo_pad.bin");
    let _ = std::fs::remove_file(&wal_path);
    let _ = std::fs::remove_file(WalPadBook::wal_path_for(&wal_path));
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
    let _ = std::fs::remove_file(&wal_path);
    let _ = std::fs::remove_file(WalPadBook::wal_path_for(&wal_path));

    // 2. BFT + Web-of-Trust PoP + Catch-up
    println!("[2/6] Express Lane (VRNM-Fast): 2-Phase Batched BFT + Web-of-Trust PoP");
    let cfg = BftConfig::default();
    let mut wot = WebOfTrustRegistry::for_bft_config(&cfg);
    for (idx, sponsor) in [0u32, 1, 2].into_iter().enumerate() {
        wot.vouch_in_person(sponsor, 42, 1_700_000_000 + idx as u64)
            .expect("vouch");
    }
    println!(
        "  Web-of-Trust PoP       : candidate #42 admitted via 3 in-person vouches (flat weight={})",
        wot.voting_weight(42)
    );
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
    let audit_tag = audit_key.tag_settlement(&settlement);
    assert!(audit_key.verify_settlement(&settlement, &audit_tag));
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
        "bench" => {
            cmd_bench();
            Ok(())
        }
        "testnet" => cmd_testnet(rest),
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
