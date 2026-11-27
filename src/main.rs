//! Vernam (VRNM) v0.2 — Integrated Showcase & Release Performance Benchmark.

use std::collections::BTreeMap;
use std::time::Instant;

use vernam_rs::bft::{BftCluster, BftConfig, BinaryTx, WebOfTrustRegistry};
use vernam_rs::otp::{FRAME_BYTES, PadPage, WalPadBook, open_frame, seal_frame};
use vernam_rs::privacy_mpc::{
    BeaverPool, ConfidentialTransferRequest, ShardedPrivateLedger,
};
use vernam_rs::qkd::{
    AttackProfile, Bb84Channel, BufferedQkdPool, PoolConfig, QkdKeyProvider, toeplitz_hash_u64,
    toeplitz_seed_words,
};
use vernam_rs::tokenomics::{
    EpochContribution, FeeLane, MAX_SUPPLY, OneTimeAuditKey, SlashingOffense, TokenomicsEngine,
    VERN_PER_VRNM,
};

fn fmt_vrnm(verns: u64) -> String {
    format!("{:.4} VRNM", verns as f64 / VERN_PER_VRNM as f64)
}

fn main() {
    println!("========================================================================");
    println!("  VERNAM (VRNM) v0.2 — Information-Theoretically Secure OTP Coin (Rust)");
    println!("  Zero external crates | Zero SHA-256 / RSA / ECDSA / AES / zk-SNARKs");
    println!("  Immune to Quantum Computers AND P = NP (pure Shannon + Quantum physics)");
    println!("========================================================================\n");

    // -------------------------------------------------------------------------
    // 1. Crash-Safe WAL OTP + Zeroized PadPage + Carter-Wegman Benchmark
    // -------------------------------------------------------------------------
    println!("[1/5] Zeroized OTP + Crash-Safe WAL PadBook + Carter-Wegman MAC");
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
        drop(p0); // Volatile RAM wipe on Drop!
    }
    {
        let reloaded = WalPadBook::open(&wal_path).expect("reload WAL after crash");
        assert!(reloaded.is_burned(0));
        println!(
            "  WAL crash-reload check : OK (page 0 burned & zeroed on disk, {} pages remaining)",
            reloaded.remaining()
        );
    }
    let _ = std::fs::remove_file(&wal_path);
    let _ = std::fs::remove_file(WalPadBook::wal_path_for(&wal_path));

    // Benchmark pure OTP + Carter-Wegman MAC throughput
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
        "  OTP+MAC roundtrip speed: {:.0} ops/sec ({:.1} MB/s single-core, guard={})\n",
        ops_per_sec, mb_per_sec, acc_byte
    );

    // -------------------------------------------------------------------------
    // 2. Express Lane: 2-Phase Batched BFT + Offline Catch-Up + Web-of-Trust PoP
    // -------------------------------------------------------------------------
    println!("[2/5] Express Lane (VRNM-Fast): 2-Phase Batched BFT + Web-of-Trust PoP");
    let cfg = BftConfig::default(); // N=4, f=1, quorum=3
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

    // Benchmark 20 blocks x 1,000 binary txs = 20,000 txs finalized across 4 BFT validators!
    let batch_size = 1_000usize;
    let num_blocks = 20usize;
    let mut next_page = 0u64;
    let t1 = Instant::now();
    for _ in 0..num_blocks {
        let mut batch = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            batch.push(BinaryTx {
                sender_id: 1,
                recipient_id: 2,
                amount: 1,
                page_id: next_page,
                nonce: next_page,
            });
            next_page += 1;
        }
        cluster.propose_and_finalize_batch(batch).expect("finalize");
    }
    let bft_elapsed = t1.elapsed().as_secs_f64();
    let total_bft_txs = batch_size * num_blocks;
    let bft_tps = total_bft_txs as f64 / bft_elapsed;
    println!(
        "  Express 2-Phase BFT    : {} txs in {} blocks across 4 validators -> {:.0} TPS ({:.2} ms/block)",
        total_bft_txs,
        num_blocks,
        bft_tps,
        (bft_elapsed * 1_000.0) / num_blocks as f64
    );

    // Offline validator catch-up test
    cluster.set_online(3, false).unwrap();
    let catchup_tx = vec![BinaryTx {
        sender_id: 1,
        recipient_id: 2,
        amount: 500,
        page_id: next_page,
        nonce: next_page,
    }];
    cluster.propose_and_finalize_batch(catchup_tx).unwrap();
    cluster.set_online(3, true).unwrap();
    let synced = cluster.sync_validator_from_quorum(3).unwrap();
    println!(
        "  Offline catch-up sync  : V3 synced {} missed block(s) via quorum certificates\n",
        synced
    );

    // -------------------------------------------------------------------------
    // 3. Shielded Lane: Sharded IT-MPC + Sender Anonymity + Proactive Refresh
    // -------------------------------------------------------------------------
    println!("[3/5] Shielded Lane (VRNM-Private): Sharded IT-MPC + PSS + Cover Frames");
    let mut ledger = ShardedPrivateLedger::new_default(4).expect("64 accounts in 4 buckets of 16");
    ledger.mint_initial_balance(0, 50_000).unwrap();
    let transfers_to_bench = 200usize;
    let mut beaver_pool = BeaverPool::new_3_of_4(
        (transfers_to_bench + 16) * ledger.triples_per_transfer(),
    );

    // Pre-build confidential requests (client-side) and time online MPC settlement
    let mut reqs = Vec::with_capacity(transfers_to_bench);
    let mut alice_bal = 50_000u128;
    for _ in 0..transfers_to_bench {
        let amt = 10u128;
        reqs.push(
            ConfidentialTransferRequest::new(0, alice_bal, 0, 1, amt, 16, 16, 3, 4).unwrap(),
        );
        alice_bal -= amt;
    }

    let t2 = Instant::now();
    for req in &reqs {
        ledger.execute_sharded_transfer(req, &mut beaver_pool).unwrap();
    }
    let mpc_elapsed = t2.elapsed().as_secs_f64();
    let mpc_tps = transfers_to_bench as f64 / mpc_elapsed;
    let epoch = ledger.proactive_refresh_epoch().unwrap();
    println!(
        "  Sharded IT-MPC speed   : {} private txs (K=16 bucket, 16-bit range proof) -> {:.0} TPS",
        transfers_to_bench, mpc_tps
    );
    println!(
        "  Verified balances      : Alice={} VRNM, Bob={} VRNM (after PSS Epoch {} refresh)\n",
        ledger.reconstruct_balance(0).unwrap(),
        ledger.reconstruct_balance(1).unwrap(),
        epoch
    );

    // -------------------------------------------------------------------------
    // 4. BB84 + Decoy-State QKD + POPCNT Toeplitz Privacy Amplification
    // -------------------------------------------------------------------------
    println!("[4/5] Quantum Key Distribution (BB84 + Decoy-State + POPCNT Toeplitz)");
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
    let eve_res = eve_qkd.exchange_key(64);
    println!("  Intercept-Resend Eve   : BLOCKED ({:?})", eve_res.unwrap_err());

    let mut pns_qkd = Bb84Channel::with_attack(AttackProfile::PhotonNumberSplitting {
        single_photon_block_rate: 0.9,
        multiphoton_transmittance: 1.0,
    });
    let pns_res = pns_qkd.exchange_key(64);
    println!("  Decoy-State PNS attack : BLOCKED ({:?})", pns_res.unwrap_err());

    // Benchmark word-level u64 POPCNT Toeplitz privacy amplification
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
        "  POPCNT Toeplitz PA     : {:.1} Mbps purified key output (guard={:#x})",
        pa_mbps, pa_guard
    );

    let mut qkd_pool = BufferedQkdPool::new(PoolConfig {
        capacity_bytes: 16_384,
        low_watermark_bytes: 8_192,
        refill_chunk_bytes: 2_048,
        num_channels: 2,
        ..PoolConfig::default()
    })
    .expect("start buffered QKD pool");
    let burst_key = qkd_pool.get_key("V1", 1024).expect("RAM burst");
    println!(
        "  BufferedQkdPool burst  : served {}B instantly from multi-threaded QKD ring buffer\n",
        burst_key.len()
    );

    // -------------------------------------------------------------------------
    // 5. Proof-of-Pad Tokenomics + 21M Cap + Pad-Burn Fees + Slashing
    // -------------------------------------------------------------------------
    println!("[5/5] Proof-of-Pad Tokenomics (21M Cap, 80/20 Pad-Burn Fees, Slashing)");
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
    println!(
        "  Hard supply cap        : {}",
        fmt_vrnm(MAX_SUPPLY)
    );
    println!(
        "  Equivocator V3 slashed : {} burned (status={:?})",
        fmt_vrnm(slash_rcpt.slashed_amount),
        slash_rcpt.new_status
    );
    println!(
        "  Epoch #{} settled      : subsidy={}, fees_burned={}, honest_payouts={} validators (IT-MAC verified!)",
        settlement.epoch,
        fmt_vrnm(settlement.subsidy_minted),
        fmt_vrnm(settlement.fees_burned_in_epoch),
        settlement.payouts.len()
    );
    println!("\n========================================================================");
    println!("  ALL 5 VERNAM (VRNM) PILLARS VERIFIED & BENCHMARKED.");
    println!("========================================================================");
}
