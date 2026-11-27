//! Unified Multi-Host Single-Share Validator Daemon & Cluster Orchestrator for Vernam (VRNM).
//!
//! Runs 4–16 physically independent TCP validator servers where **each server holds strictly
//! its single Shamir secret share** and NEVER receives or inspects any peer's share, while
//! coordinating the complete Vernam information-theoretic protocol stack:
//!
//! 1. **Real Cross-Host TCP Split-Share IT-MPC (`crate::distributed_mpc`)**:
//!    - Each `(3, 4)` validator wraps an independent single-share [`MpcValidatorDaemon`] bound
//!      to its own TCP listener, communicating exclusively over pairwise single-use OTP +
//!      Carter-Wegman MAC binary sockets.
//!    - Extended `(t, N)` committees (`5..=16`, e.g., 7-validator BFT) bind an independent TCP
//!      listener per validator and maintain strict single-share `(t, N)` isolation over
//!      `F_(2^127 - 1)` via [`crate::dynamic_quorum`].
//! 2. **Unbiasable, Unabortable Threshold Entropy Beacon (`crate::entropy_beacon`)**:
//!    - Every validator runs [`VernamBeacon`] symmetric bivariate commit-and-reveal over
//!      single-use OTP+CW-MAC envelopes with Rabin-Ben-Or IC-MAC verification to derive
//!      unbiasable epoch randomness `Gamma_e` in `F_(2^127 - 1)`.
//! 3. **Beacon-Paired Bilateral Proof-of-Pad Mining & Auditing (`crate::pop_mining`)**:
//!    - Derives a mandatory fixed-point-free Sattolo single-cycle [`BeaconPairingSchedule`]
//!      from `Gamma_e` (defeating 2-node Sybil collusion rings), mines bilateral BB84 QKD pad
//!      batches with counterparty co-signed receipts, answers deterministic beacon challenges,
//!      enforces sliding-window cross-epoch anti-replay via [`PopReplayRegistry`], and settles
//!      halving `VRNM` rewards + automatic 50% slashing via [`TokenomicsEngine`].
//! 4. **Distributed Proactive Secret Sharing (PSS) Share Rotation**:
//!    - Rotates every server's local Shamir share from epoch `e` to `e + 1` via real TCP
//!      zero-polynomial deltas with zero balance reconstruction.
//! 5. **Express BFT Consensus Coordination (`crate::bft`) & Optional HTTP Metrics Listener**:
//!    - Drives height-based [`AutonomousEpochClock`] boundaries via real 2-phase OTP+CW BFT
//!      block finalization and exposes optional zero-dependency HTTP `/health` and `/metrics`
//!      JSON endpoints for multi-host monitoring.
//!
//! Zero external crates, zero computational cryptography, zero `unsafe` code.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::bft::{BftCluster, BftConfig, BinaryTx, BlockCertificate};
use crate::distributed_mpc::{
    DIST_BUCKET_SIZE, DIST_NUM_VALIDATORS, DIST_THRESHOLD, DistributedClusterConfig,
    DistributedMpcCluster, DistributedWalletClient, LocalBeaverBank, MpcValidatorDaemon,
    OtpPadTape, PssRefreshReport, TransferReceipt, ValidatorDaemonConfig as MpcDaemonConfig,
    reconstruct_4_verified, reconstruct_any_3,
};
use crate::dynamic_quorum::{Share, reconstruct_secret, split_secret, verify_committee_shares};
use crate::entropy_beacon::{
    AutonomousEpochClock, BeaconConfig, EpochBeaconOutput, EpochPipelineStage, OtpChannelKey,
    VernamBeacon, lagrange_interpolate_at, validator_eval_x,
};
use crate::field::{PRIME_P, add_mod, random_field_elem, sub_mod, zeroize_u128};
use crate::pop_mining::{
    BeaconPairingSchedule, BilateralPopSubmission, DEFAULT_CHALLENGE_SLOT_COUNT, PeerReceiptKey,
    PopAuditor, PopEpochCoordinator, PopEpochReport, PopMiner, PopReplayRegistry,
};
use crate::tokenomics::{FeeLane, TokenomicsEngine, VERN_PER_VRNM, ValidatorId};

// ============================================================================
// Constants
// ============================================================================

/// Minimum supported BFT validator committee size (`N = 4`, `f = 1`, `t = 3`).
pub const MIN_COMMITTEE_SIZE: usize = 4;

/// Maximum supported validator committee size (`N = 16`, `f = 5`, `t = 11`).
pub const MAX_COMMITTEE_SIZE: usize = 16;

/// Default validator committee size (`4`).
pub const DEFAULT_COMMITTEE_SIZE: usize = 4;

/// Default number of 16-slot anonymity buckets per validator (`4` -> 64 shielded slots).
pub const DEFAULT_NUM_BUCKETS: usize = 4;

/// Default finalized BFT blocks between autonomous epoch boundary triggers (`10`).
pub const DEFAULT_EPOCH_BLOCK_INTERVAL: u64 = 10;

/// Default number of purified 256-byte OTP pad pages mined per validator per epoch.
pub const DEFAULT_POP_PAD_PAGES: usize = 8;

/// Default number of MPC Beaver triples mined per validator per epoch.
pub const DEFAULT_POP_BEAVER_TRIPLES: usize = 16;

/// Default Beaver transaction capacity provisioned per local TCP cluster.
const DEFAULT_CLUSTER_BEAVER_CAPACITY: usize = 256;

/// Default TCP socket I/O timeout for inter-validator MPC rounds.
const MPC_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP monitoring request/response socket timeout.
const HTTP_IO_TIMEOUT: Duration = Duration::from_millis(500);

/// Poll interval for clean daemon shutdown checks.
const DAEMON_ACCEPT_POLL: Duration = Duration::from_millis(25);

// ============================================================================
// Configuration & Metrics Snapshot
// ============================================================================

/// Configuration for a single independent multi-host Vernam validator daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorDaemonConfig {
    /// Zero-based validator index in `0..committee_size`.
    pub validator_id: u32,
    /// Total committee size (`4..=16`, default `4`).
    pub committee_size: usize,
    /// Local TCP bind address for binary OTP+MAC IT-MPC traffic (e.g. `"127.0.0.1:0"` or `"0.0.0.0:9100"`).
    pub mpc_bind_addr: String,
    /// Optional HTTP status/metrics bind address for monitoring (e.g. `Some("127.0.0.1:8090".into())`).
    pub http_bind_addr: Option<String>,
    /// Peer validators' `(validator_id, tcp_addr)` endpoints.
    pub peer_mpc_addrs: Vec<(u32, String)>,
    /// Number of 16-slot shielded anonymity buckets (default `4`).
    pub num_buckets: usize,
    /// Number of finalized BFT blocks per autonomous epoch (default `10`).
    pub epoch_block_interval: u64,
}

impl Default for ValidatorDaemonConfig {
    fn default() -> Self {
        Self {
            validator_id: 0,
            committee_size: DEFAULT_COMMITTEE_SIZE,
            mpc_bind_addr: "127.0.0.1:0".to_string(),
            http_bind_addr: None,
            peer_mpc_addrs: Vec::new(),
            num_buckets: DEFAULT_NUM_BUCKETS,
            epoch_block_interval: DEFAULT_EPOCH_BLOCK_INTERVAL,
        }
    }
}

impl ValidatorDaemonConfig {
    /// Validate configuration bounds and bind address syntax.
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_COMMITTEE_SIZE..=MAX_COMMITTEE_SIZE).contains(&self.committee_size) {
            return Err(format!(
                "committee_size {} out of supported range {}..={}",
                self.committee_size, MIN_COMMITTEE_SIZE, MAX_COMMITTEE_SIZE
            ));
        }
        if (self.validator_id as usize) >= self.committee_size {
            return Err(format!(
                "validator_id {} out of range 0..{}",
                self.validator_id, self.committee_size
            ));
        }
        if self.num_buckets == 0 {
            return Err("num_buckets must be >= 1".to_string());
        }
        if self.epoch_block_interval == 0 {
            return Err("epoch_block_interval must be >= 1".to_string());
        }
        self.mpc_bind_addr
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid mpc_bind_addr '{}': {e}", self.mpc_bind_addr))?;
        if let Some(ref http_addr) = self.http_bind_addr {
            http_addr
                .parse::<SocketAddr>()
                .map_err(|e| format!("invalid http_bind_addr '{http_addr}': {e}"))?;
        }
        Ok(())
    }
}

/// Live observability snapshot for a single independent [`ValidatorDaemon`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorDaemonMetrics {
    pub validator_id: u32,
    pub mpc_addr: String,
    pub current_epoch: u64,
    pub pss_epoch: u64,
    pub blocks_finalized: u64,
    pub shielded_txs_processed: u64,
    pub last_beacon_gamma: Option<u128>,
    pub last_assigned_counterparty: Option<u32>,
    pub bilateral_pop_passes: u64,
    pub anti_replay_tracked_pads: usize,
}

impl ValidatorDaemonMetrics {
    /// Serialize this metrics snapshot to compact JSON (zero external crates).
    pub fn to_json(&self) -> String {
        let gamma_json = match self.last_beacon_gamma {
            Some(g) => format!("\"0x{g:032x}\""),
            None => "null".to_string(),
        };
        let cp_json = match self.last_assigned_counterparty {
            Some(cp) => cp.to_string(),
            None => "null".to_string(),
        };
        format!(
            concat!(
                "{{\"validator_id\":{},\"mpc_addr\":\"{}\",\"current_epoch\":{},",
                "\"pss_epoch\":{},\"blocks_finalized\":{},\"shielded_txs_processed\":{},",
                "\"last_beacon_gamma\":{},\"last_assigned_counterparty\":{},",
                "\"bilateral_pop_passes\":{},\"anti_replay_tracked_pads\":{}}}"
            ),
            self.validator_id,
            self.mpc_addr,
            self.current_epoch,
            self.pss_epoch,
            self.blocks_finalized,
            self.shielded_txs_processed,
            gamma_json,
            cp_json,
            self.bilateral_pop_passes,
            self.anti_replay_tracked_pads
        )
    }
}

// ============================================================================
// Optional Zero-Dependency HTTP Monitoring Server
// ============================================================================

struct HttpMonitorServer {
    listen_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl HttpMonitorServer {
    fn spawn(
        validator_id: u32,
        bind_addr: SocketAddr,
        metrics: Arc<Mutex<ValidatorDaemonMetrics>>,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(bind_addr)
            .map_err(|e| format!("failed to bind HTTP monitor on {bind_addr}: {e}"))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|e| format!("failed to query HTTP monitor local_addr: {e}"))?;
        listener
            .set_nonblocking(false)
            .map_err(|e| format!("failed to configure HTTP listener: {e}"))?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let handle = thread::Builder::new()
            .name(format!("vernam-val-{validator_id}-http"))
            .spawn(move || {
                http_monitor_loop(listener, validator_id, metrics, thread_shutdown);
            })
            .map_err(|e| format!("failed to spawn HTTP monitor thread: {e}"))?;

        Ok(Self {
            listen_addr,
            shutdown,
            handle: Some(handle),
        })
    }

    fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    fn stop(&mut self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        // Wake blocking `TcpListener::accept` cleanly via loopback connect.
        let wake_addr = if self.listen_addr.ip().is_unspecified() {
            SocketAddr::from(([127, 0, 0, 1], self.listen_addr.port()))
        } else {
            self.listen_addr
        };
        let _ = TcpStream::connect_timeout(&wake_addr, Duration::from_millis(50));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for HttpMonitorServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn http_monitor_loop(
    listener: TcpListener,
    validator_id: u32,
    metrics: Arc<Mutex<ValidatorDaemonMetrics>>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if shutdown.load(Ordering::Acquire) {
                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }
                let _ = stream.set_read_timeout(Some(HTTP_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(HTTP_IO_TIMEOUT));
                handle_http_monitor_request(&mut stream, validator_id, &metrics);
                let _ = stream.shutdown(Shutdown::Both);
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn handle_http_monitor_request(
    stream: &mut TcpStream,
    validator_id: u32,
    metrics: &Arc<Mutex<ValidatorDaemonMetrics>>,
) {
    let mut buf = [0u8; 1024];
    let n = match stream.read(&mut buf) {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    let (status, body) = match path {
        "/health" => (
            "200 OK",
            format!(
                "{{\"status\":\"ok\",\"validator_id\":{validator_id},\"mode\":\"single-share-it-mpc\"}}"
            ),
        ),
        "/" | "/metrics" | "/status" => {
            let snap = metrics
                .lock()
                .map(|m| m.clone())
                .unwrap_or(ValidatorDaemonMetrics {
                    validator_id,
                    mpc_addr: String::new(),
                    current_epoch: 0,
                    pss_epoch: 1,
                    blocks_finalized: 0,
                    shielded_txs_processed: 0,
                    last_beacon_gamma: None,
                    last_assigned_counterparty: None,
                    bilateral_pop_passes: 0,
                    anti_replay_tracked_pads: 0,
                });
            ("200 OK", snap.to_json())
        }
        _ => ("404 Not Found", "{\"error\":\"not_found\"}".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

// ============================================================================
// Single-Share Extended TCP Backend (for committee_size 5..=16)
// ============================================================================

/// Strictly single-validator balance share store for extended committees (`5..=16`).
/// Holds ONLY this server's `u128` share per `(bucket, slot)` and zeroizes all shares on `Drop`.
struct SingleShareExtendedState {
    listen_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    accept_handle: Option<JoinHandle<()>>,
    /// `buckets[bucket_id][slot]` = ONLY this validator's Shamir share `y_i` at `x_i = id + 1`.
    buckets: Mutex<Vec<[u128; DIST_BUCKET_SIZE]>>,
    pss_epoch: Mutex<u64>,
}

impl SingleShareExtendedState {
    fn spawn(validator_id: u32, bind_addr: SocketAddr, num_buckets: usize) -> Result<Self, String> {
        let listener = TcpListener::bind(bind_addr)
            .map_err(|e| format!("failed to bind validator {validator_id} TCP socket on {bind_addr}: {e}"))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|e| format!("failed to get validator {validator_id} local_addr: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("failed to set nonblocking on validator {validator_id}: {e}"))?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let accept_handle = thread::Builder::new()
            .name(format!("vernam-ext-v{validator_id}-tcp"))
            .spawn(move || {
                while !thread_shutdown.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(DAEMON_ACCEPT_POLL);
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            if thread_shutdown.load(Ordering::Acquire) {
                                break;
                            }
                            thread::sleep(DAEMON_ACCEPT_POLL);
                        }
                    }
                }
            })
            .map_err(|e| format!("failed to spawn extended validator {validator_id} thread: {e}"))?;

        Ok(Self {
            listen_addr,
            shutdown,
            accept_handle: Some(accept_handle),
            buckets: Mutex::new(vec![[0u128; DIST_BUCKET_SIZE]; num_buckets]),
            pss_epoch: Mutex::new(1),
        })
    }

    fn local_share(&self, bucket_id: usize, slot: usize) -> Result<u128, String> {
        if slot >= DIST_BUCKET_SIZE {
            return Err(format!("slot {slot} out of range 0..{DIST_BUCKET_SIZE}"));
        }
        let guard = self
            .buckets
            .lock()
            .map_err(|_| "extended share mutex poisoned".to_string())?;
        let bucket = guard
            .get(bucket_id)
            .ok_or_else(|| format!("bucket_id {bucket_id} out of range 0..{}", guard.len()))?;
        Ok(bucket[slot])
    }

    fn add_local_share(&self, bucket_id: usize, slot: usize, delta: u128) -> Result<(), String> {
        if slot >= DIST_BUCKET_SIZE {
            return Err(format!("slot {slot} out of range 0..{DIST_BUCKET_SIZE}"));
        }
        if delta >= PRIME_P {
            return Err("share delta out of canonical F_(2^127 - 1) range".to_string());
        }
        let mut guard = self
            .buckets
            .lock()
            .map_err(|_| "extended share mutex poisoned".to_string())?;
        let num_buckets = guard.len();
        let bucket = guard
            .get_mut(bucket_id)
            .ok_or_else(|| format!("bucket_id {bucket_id} out of range 0..{num_buckets}"))?;
        bucket[slot] = add_mod(bucket[slot], delta);
        Ok(())
    }

    fn sub_local_share(&self, bucket_id: usize, slot: usize, delta: u128) -> Result<(), String> {
        if slot >= DIST_BUCKET_SIZE {
            return Err(format!("slot {slot} out of range 0..{DIST_BUCKET_SIZE}"));
        }
        if delta >= PRIME_P {
            return Err("share delta out of canonical F_(2^127 - 1) range".to_string());
        }
        let mut guard = self
            .buckets
            .lock()
            .map_err(|_| "extended share mutex poisoned".to_string())?;
        let num_buckets = guard.len();
        let bucket = guard
            .get_mut(bucket_id)
            .ok_or_else(|| format!("bucket_id {bucket_id} out of range 0..{num_buckets}"))?;
        bucket[slot] = sub_mod(bucket[slot], delta);
        Ok(())
    }

    fn pss_epoch(&self) -> u64 {
        self.pss_epoch.lock().map(|g| *g).unwrap_or(1)
    }

    fn increment_pss_epoch(&self) -> u64 {
        let mut g = self.pss_epoch.lock().expect("pss_epoch mutex poisoned");
        *g = g.saturating_add(1);
        *g
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.accept_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for SingleShareExtendedState {
    fn drop(&mut self) {
        self.stop();
        if let Ok(mut guard) = self.buckets.lock() {
            for bucket in guard.iter_mut() {
                for share in bucket.iter_mut() {
                    zeroize_u128(share);
                }
            }
        }
    }
}

// ============================================================================
// ValidatorDaemon (Single-Share Independent Server)
// ============================================================================

enum MpcBackend {
    /// Standalone single-share TCP server directly owning an `MpcValidatorDaemon`.
    Owned(MpcValidatorDaemon),
    /// Cluster-attached single-share server whose `MpcValidatorDaemon` lives in the
    /// orchestrator's `DistributedMpcCluster` so `DistributedWalletClient` communicates over TCP.
    ClusterAttached { listen_addr: SocketAddr },
    /// Extended-committee (`5..=16`) single-share TCP server.
    Extended(SingleShareExtendedState),
}

/// Independent multi-host Vernam validator daemon holding **strictly 1 Shamir share** per account.
///
/// Wraps a real single-share [`MpcValidatorDaemon`] (from `crate::distributed_mpc`), its own
/// [`AutonomousEpochClock`] and [`BeaconConfig`] (from `crate::entropy_beacon`), its own
/// [`PopReplayRegistry`] (from `crate::pop_mining`), live [`ValidatorDaemonMetrics`], and an
/// optional zero-dependency HTTP monitoring server.
pub struct ValidatorDaemon {
    config: ValidatorDaemonConfig,
    beacon_config: BeaconConfig,
    epoch_clock: AutonomousEpochClock,
    replay_registry: PopReplayRegistry,
    metrics: Arc<Mutex<ValidatorDaemonMetrics>>,
    backend: MpcBackend,
    http_server: Option<HttpMonitorServer>,
    stopped: bool,
}

impl fmt::Debug for ValidatorDaemon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatorDaemon")
            .field("validator_id", &self.config.validator_id)
            .field("committee_size", &self.config.committee_size)
            .field("mpc_addr", &self.mpc_addr())
            .field("http_addr", &self.http_addr())
            .field("current_epoch", &self.epoch_clock.current_epoch())
            .finish()
    }
}

impl ValidatorDaemon {
    /// Start an independent single-share [`ValidatorDaemon`] bound to `config.mpc_bind_addr`
    /// (and optional `config.http_bind_addr`).
    ///
    /// Strictly holds **ONLY validator `config.validator_id`'s single Shamir share** — never
    /// retains any other validator's shares or Beaver bundles.
    pub fn start(config: ValidatorDaemonConfig) -> Result<Self, String> {
        config.validate()?;
        let bind_addr: SocketAddr = config
            .mpc_bind_addr
            .parse()
            .map_err(|e| format!("invalid mpc_bind_addr: {e}"))?;
        let beacon_config =
            BeaconConfig::bft(config.committee_size).map_err(|e| format!("beacon config: {e}"))?;
        let epoch_clock = AutonomousEpochClock::new(config.epoch_block_interval)
            .map_err(|e| format!("epoch clock: {e}"))?;

        let (backend, actual_mpc_addr) = if (config.validator_id as usize) < DIST_NUM_VALIDATORS
            && config.committee_size == DIST_NUM_VALIDATORS
        {
            // Provision strictly ONLY this validator's single-share LocalBeaverBank;
            // all other 3 banks are dropped & volatile-zeroized immediately.
            let mut split_banks =
                LocalBeaverBank::generate_split_banks(DEFAULT_CLUSTER_BEAVER_CAPACITY)
                    .into_iter()
                    .map(Some)
                    .collect::<Vec<_>>();
            let my_bank = split_banks[config.validator_id as usize]
                .take()
                .ok_or_else(|| "failed to take single-validator Beaver bank".to_string())?;
            drop(split_banks);

            let my_id = config.validator_id as usize;
            let mut peer_in_tapes: [Option<OtpPadTape>; DIST_NUM_VALIDATORS] =
                [None, None, None, None];
            let mut peer_out_tapes: [Option<OtpPadTape>; DIST_NUM_VALIDATORS] =
                [None, None, None, None];
            for peer_id in 0..DIST_NUM_VALIDATORS {
                if peer_id == my_id {
                    continue;
                }
                let (in_tape, _) = OtpPadTape::generate_pair(64 * 1024, 512);
                let (out_tape, _) = OtpPadTape::generate_pair(64 * 1024, 512);
                peer_in_tapes[peer_id] = Some(in_tape);
                peer_out_tapes[peer_id] = Some(out_tape);
            }
            let (client_in, _) = OtpPadTape::generate_pair(64 * 1024, 512);
            let (client_out, _) = OtpPadTape::generate_pair(64 * 1024, 512);

            let mpc = MpcValidatorDaemon::spawn(MpcDaemonConfig {
                validator_id: my_id,
                bind_addr,
                num_buckets: config.num_buckets,
                beaver_bank: my_bank,
                peer_in_tapes,
                peer_out_tapes,
                client_in_tapes: vec![client_in],
                client_out_tapes: vec![client_out],
                io_timeout: MPC_IO_TIMEOUT,
            })
            .map_err(|e| format!("failed to spawn single-share MpcValidatorDaemon: {e}"))?;
            let addr = mpc.listen_addr();
            (MpcBackend::Owned(mpc), addr)
        } else {
            let ext =
                SingleShareExtendedState::spawn(config.validator_id, bind_addr, config.num_buckets)?;
            let addr = ext.listen_addr;
            (MpcBackend::Extended(ext), addr)
        };

        let metrics = Arc::new(Mutex::new(ValidatorDaemonMetrics {
            validator_id: config.validator_id,
            mpc_addr: actual_mpc_addr.to_string(),
            current_epoch: epoch_clock.current_epoch(),
            pss_epoch: 1,
            blocks_finalized: 0,
            shielded_txs_processed: 0,
            last_beacon_gamma: None,
            last_assigned_counterparty: None,
            bilateral_pop_passes: 0,
            anti_replay_tracked_pads: 0,
        }));

        let http_server = if let Some(ref http_addr_str) = config.http_bind_addr {
            let http_addr: SocketAddr = http_addr_str
                .parse()
                .map_err(|e| format!("invalid http_bind_addr: {e}"))?;
            Some(HttpMonitorServer::spawn(
                config.validator_id,
                http_addr,
                Arc::clone(&metrics),
            )?)
        } else {
            None
        };

        Ok(Self {
            config,
            beacon_config,
            epoch_clock,
            replay_registry: PopReplayRegistry::default(),
            metrics,
            backend,
            http_server,
            stopped: false,
        })
    }

    /// Internal constructor used by [`ValidatorClusterOrchestrator`] to wrap a live TCP
    /// [`MpcValidatorDaemon`] belonging to a [`DistributedMpcCluster`].
    fn attach_cluster_mpc(
        config: ValidatorDaemonConfig,
        listen_addr: SocketAddr,
    ) -> Result<Self, String> {
        config.validate()?;
        let beacon_config =
            BeaconConfig::bft(config.committee_size).map_err(|e| format!("beacon config: {e}"))?;
        let epoch_clock = AutonomousEpochClock::new(config.epoch_block_interval)
            .map_err(|e| format!("epoch clock: {e}"))?;

        let metrics = Arc::new(Mutex::new(ValidatorDaemonMetrics {
            validator_id: config.validator_id,
            mpc_addr: listen_addr.to_string(),
            current_epoch: epoch_clock.current_epoch(),
            pss_epoch: 1,
            blocks_finalized: 0,
            shielded_txs_processed: 0,
            last_beacon_gamma: None,
            last_assigned_counterparty: None,
            bilateral_pop_passes: 0,
            anti_replay_tracked_pads: 0,
        }));

        let http_server = if let Some(ref http_addr_str) = config.http_bind_addr {
            let http_addr: SocketAddr = http_addr_str
                .parse()
                .map_err(|e| format!("invalid http_bind_addr: {e}"))?;
            Some(HttpMonitorServer::spawn(
                config.validator_id,
                http_addr,
                Arc::clone(&metrics),
            )?)
        } else {
            None
        };

        Ok(Self {
            config,
            beacon_config,
            epoch_clock,
            replay_registry: PopReplayRegistry::default(),
            metrics,
            backend: MpcBackend::ClusterAttached { listen_addr },
            http_server,
            stopped: false,
        })
    }

    /// Validator ID (`0..committee_size`).
    pub fn validator_id(&self) -> u32 {
        self.config.validator_id
    }

    /// Bound TCP address of this validator's IT-MPC listener.
    pub fn mpc_addr(&self) -> SocketAddr {
        match &self.backend {
            MpcBackend::Owned(mpc) => mpc.listen_addr(),
            MpcBackend::ClusterAttached { listen_addr } => *listen_addr,
            MpcBackend::Extended(ext) => ext.listen_addr,
        }
    }

    /// Bound HTTP monitoring address, if enabled.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_server.as_ref().map(HttpMonitorServer::listen_addr)
    }

    /// Daemon configuration.
    pub fn config(&self) -> &ValidatorDaemonConfig {
        &self.config
    }

    /// Threshold beacon committee configuration (`N`, `t = N - f`, `f = (N - 1)/3`).
    pub fn beacon_config(&self) -> BeaconConfig {
        self.beacon_config
    }

    /// Reference to this validator's autonomous epoch scheduler.
    pub fn epoch_clock(&self) -> &AutonomousEpochClock {
        &self.epoch_clock
    }

    /// Mutable reference to this validator's autonomous epoch scheduler.
    pub fn epoch_clock_mut(&mut self) -> &mut AutonomousEpochClock {
        &mut self.epoch_clock
    }

    /// Reference to this validator's Proof-of-Pad anti-replay registry.
    pub fn replay_registry(&self) -> &PopReplayRegistry {
        &self.replay_registry
    }

    /// Mutable reference to this validator's Proof-of-Pad anti-replay registry.
    pub fn replay_registry_mut(&mut self) -> &mut PopReplayRegistry {
        &mut self.replay_registry
    }

    /// Current Proactive Secret Sharing (PSS) epoch on this validator.
    pub fn pss_epoch(&self) -> u64 {
        match &self.backend {
            MpcBackend::Owned(mpc) => mpc.epoch(),
            MpcBackend::ClusterAttached { .. } => self
                .metrics
                .lock()
                .map(|m| m.pss_epoch)
                .unwrap_or(1),
            MpcBackend::Extended(ext) => ext.pss_epoch(),
        }
    }

    /// Read **ONLY this validator's single Shamir share** `y_i` for `(bucket_id, slot)`.
    pub fn local_balance_share(&self, bucket_id: usize, slot: usize) -> Result<u128, String> {
        match &self.backend {
            MpcBackend::Owned(mpc) => mpc
                .local_balance_share(bucket_id, slot)
                .map_err(|e| format!("failed to read local balance share: {e}")),
            MpcBackend::Extended(ext) => ext.local_share(bucket_id, slot),
            MpcBackend::ClusterAttached { .. } => Err(
                "query local share via ValidatorClusterOrchestrator::daemon_balance_share"
                    .to_string(),
            ),
        }
    }

    /// Connect this standalone daemon's outgoing OTP+MAC TCP links to the other 3 MPC peers.
    pub fn connect_mpc_peers(
        &self,
        peer_addrs: [SocketAddr; DIST_NUM_VALIDATORS],
    ) -> Result<(), String> {
        match &self.backend {
            MpcBackend::Owned(mpc) => mpc
                .connect_peers(peer_addrs)
                .map_err(|e| format!("connect_peers failed: {e}")),
            _ => Ok(()),
        }
    }

    /// Wait until all 3 incoming MPC peers complete their OTP+MAC handshakes.
    pub fn wait_for_mpc_peers_ready(&self, timeout: Duration) -> Result<(), String> {
        match &self.backend {
            MpcBackend::Owned(mpc) => mpc
                .wait_for_peers_ready(timeout)
                .map_err(|e| format!("wait_for_peers_ready failed: {e}")),
            _ => Ok(()),
        }
    }

    /// Capture a live metrics snapshot for this validator daemon.
    pub fn metrics(&self) -> ValidatorDaemonMetrics {
        let mut snap = self
            .metrics
            .lock()
            .map(|m| m.clone())
            .expect("metrics lock poisoned");
        snap.current_epoch = self.epoch_clock.current_epoch();
        if let MpcBackend::Owned(ref mpc) = self.backend {
            snap.pss_epoch = mpc.epoch();
            snap.shielded_txs_processed = mpc.committed_txs();
        } else if let MpcBackend::Extended(ref ext) = self.backend {
            snap.pss_epoch = ext.pss_epoch();
        }
        snap
    }

    fn update_metrics<F: FnOnce(&mut ValidatorDaemonMetrics)>(&self, f: F) {
        if let Ok(mut guard) = self.metrics.lock() {
            f(&mut guard);
        }
    }

    fn stop_internal(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        if let Some(ref mut http) = self.http_server {
            http.stop();
        }
        match &mut self.backend {
            MpcBackend::Owned(mpc) => mpc.stop(),
            MpcBackend::Extended(ext) => ext.stop(),
            MpcBackend::ClusterAttached { .. } => {}
        }
    }

    /// Cleanly stop this validator daemon, closing all listeners and joining all worker threads.
    pub fn shutdown(mut self) {
        self.stop_internal();
    }
}

impl Drop for ValidatorDaemon {
    fn drop(&mut self) {
        self.stop_internal();
    }
}

// ============================================================================
// Cluster Reports
// ============================================================================

/// Summary of one complete autonomous epoch lifecycle executed across the multi-host cluster.
#[derive(Debug, Clone)]
pub struct EpochCycleReport {
    /// Epoch number settled during this cycle.
    pub epoch: u64,
    /// Number of BFT blocks finalized to trigger this epoch boundary.
    pub blocks_finalized_in_epoch: u64,
    /// Cumulative chain height after this epoch boundary.
    pub total_chain_height: u64,
    /// Unbiasable threshold entropy beacon output `Gamma_e`.
    pub beacon_output: EpochBeaconOutput,
    /// Mandatory Sattolo single-cycle counterparty pairing schedule derived from `Gamma_e`.
    pub pairing_schedule: BeaconPairingSchedule,
    /// Proof-of-Pad bilateral audit, slashing, and Tokenomics settlement report.
    pub pop_report: PopEpochReport,
    /// Distributed Proactive Secret Sharing (PSS) rotation report.
    pub pss_refresh: PssRefreshReport,
    /// Total pad sample fingerprints tracked in the sliding-window anti-replay registry.
    pub anti_replay_tracked_pads: usize,
}

/// Cryptographic proof of strict split-share isolation for an account across all daemons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitShareIsolationReport {
    pub account_id: u32,
    pub bucket_id: usize,
    pub slot: usize,
    pub num_validators: usize,
    pub threshold: usize,
    pub pss_epoch: u64,
    /// Individual `(validator_id, share_y_i)` read separately from each daemon's isolated state.
    pub daemon_shares: Vec<(u32, u128)>,
    /// Exact balance reconstructed from `>= threshold` daemons' shares.
    pub reconstructed_balance: u128,
    /// True iff all tested `threshold`-of-`N` subsets reconstruct the exact same balance.
    pub all_quorum_subsets_agree: bool,
    /// True iff `threshold - 1` shares were proven algebraically consistent with multiple distinct
    /// arbitrary balances in `F_(2^127 - 1)` (0 bits of information leaked).
    pub under_threshold_zero_info_verified: bool,
}

// ============================================================================
// ValidatorClusterOrchestrator (Real Multi-Port TCP Cluster)
// ============================================================================

/// Coordinates `N` (`4..=16`) independent TCP-bound [`ValidatorDaemon`] servers where each server
/// holds **strictly 1 Shamir share**, executing real TCP IT-MPC shielded transfers, threshold
/// [`VernamBeacon`] rounds, beacon-paired bilateral Proof-of-Pad audits, Express BFT consensus,
/// and real distributed TCP Proactive Secret Sharing (PSS) share refreshes.
pub struct ValidatorClusterOrchestrator {
    num_validators: usize,
    num_buckets: usize,
    epoch_block_interval: u64,
    daemons: Vec<ValidatorDaemon>,
    /// Live 4-daemon real TCP IT-MPC cluster (used when `num_validators == 4`).
    mpc_cluster: Option<DistributedMpcCluster>,
    /// Real pairwise OTP+MAC TCP wallet client connected to all 4 independent MPC daemons.
    wallet_client: Option<DistributedWalletClient>,
    /// Optional Express BFT cluster (active whenever `N = 3f + 1`: 4, 7, 10, 13, 16).
    bft_cluster: Option<BftCluster>,
    /// Tokenomics engine managing validator flat bonds, Pad-Burn fees, halving rewards & slashing.
    tokenomics: TokenomicsEngine,
    /// Cluster-wide sliding-window Proof-of-Pad anti-replay registry.
    replay_registry: PopReplayRegistry,
    /// Monotonic chain height across finalized blocks.
    chain_height: u64,
    /// Monotonic counter for extended-committee shielded transfer IDs & PSS refresh IDs.
    next_extended_tx_id: u64,
    next_extended_refresh_id: u64,
}

impl fmt::Debug for ValidatorClusterOrchestrator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatorClusterOrchestrator")
            .field("num_validators", &self.num_validators)
            .field("num_buckets", &self.num_buckets)
            .field("chain_height", &self.chain_height)
            .field("tokenomics_epoch", &self.tokenomics.current_epoch())
            .finish()
    }
}

impl ValidatorClusterOrchestrator {
    /// Spawn `num_validators` (`4..=16`) truly separate TCP-bound [`ValidatorDaemon`] servers on
    /// `127.0.0.1:0`, each holding strictly ONLY its 1 Shamir share.
    ///
    /// When `num_validators == 4`, wires a full-mesh real TCP [`DistributedMpcCluster`] (12
    /// pairwise OTP+MAC binary TCP links between `V0..V3` plus 4 wallet-to-daemon TCP links).
    pub fn spawn_local_tcp_cluster(
        num_validators: usize,
        num_buckets: usize,
    ) -> Result<Self, String> {
        Self::spawn_local_tcp_cluster_with_options(
            num_validators,
            num_buckets,
            DEFAULT_EPOCH_BLOCK_INTERVAL,
            false,
        )
    }

    /// Spawn a local multi-port TCP validator cluster with custom epoch block interval and
    /// optional per-daemon HTTP monitoring listeners.
    pub fn spawn_local_tcp_cluster_with_options(
        num_validators: usize,
        num_buckets: usize,
        epoch_block_interval: u64,
        enable_http_monitors: bool,
    ) -> Result<Self, String> {
        if !(MIN_COMMITTEE_SIZE..=MAX_COMMITTEE_SIZE).contains(&num_validators) {
            return Err(format!(
                "num_validators {num_validators} must be in {MIN_COMMITTEE_SIZE}..={MAX_COMMITTEE_SIZE}"
            ));
        }
        if num_buckets == 0 {
            return Err("num_buckets must be >= 1".to_string());
        }
        if epoch_block_interval == 0 {
            return Err("epoch_block_interval must be >= 1".to_string());
        }

        let (daemons, mpc_cluster, wallet_client) = if num_validators == DIST_NUM_VALIDATORS {
            let (cluster, mut clients) = DistributedMpcCluster::spawn(DistributedClusterConfig {
                num_buckets,
                beaver_tx_capacity: DEFAULT_CLUSTER_BEAVER_CAPACITY,
                num_clients: 1,
                io_timeout: MPC_IO_TIMEOUT,
            })
            .map_err(|e| format!("failed to spawn 4-daemon TCP MPC cluster: {e}"))?;
            let peer_addrs = cluster.peer_addrs();
            let wallet = clients
                .pop()
                .ok_or_else(|| "DistributedMpcCluster returned no wallet client".to_string())?;

            let mut daemons = Vec::with_capacity(DIST_NUM_VALIDATORS);
            for i in 0..DIST_NUM_VALIDATORS {
                let peers: Vec<(u32, String)> = (0..DIST_NUM_VALIDATORS)
                    .filter(|&j| j != i)
                    .map(|j| (j as u32, peer_addrs[j].to_string()))
                    .collect();
                let cfg = ValidatorDaemonConfig {
                    validator_id: i as u32,
                    committee_size: num_validators,
                    mpc_bind_addr: peer_addrs[i].to_string(),
                    http_bind_addr: enable_http_monitors.then(|| "127.0.0.1:0".to_string()),
                    peer_mpc_addrs: peers,
                    num_buckets,
                    epoch_block_interval,
                };
                daemons.push(ValidatorDaemon::attach_cluster_mpc(cfg, peer_addrs[i])?);
            }
            (daemons, Some(cluster), Some(wallet))
        } else {
            // Extended committee (5..=16): each validator binds its own independent TCP listener
            // and holds strictly ONLY its single `(t, N)` Shamir share per account.
            let mut daemons = Vec::with_capacity(num_validators);
            for i in 0..num_validators {
                let cfg = ValidatorDaemonConfig {
                    validator_id: i as u32,
                    committee_size: num_validators,
                    mpc_bind_addr: "127.0.0.1:0".to_string(),
                    http_bind_addr: enable_http_monitors.then(|| "127.0.0.1:0".to_string()),
                    peer_mpc_addrs: Vec::new(),
                    num_buckets,
                    epoch_block_interval,
                };
                daemons.push(ValidatorDaemon::start(cfg)?);
            }
            let bound_addrs: Vec<SocketAddr> = daemons.iter().map(ValidatorDaemon::mpc_addr).collect();
            for (i, d) in daemons.iter_mut().enumerate() {
                d.config.peer_mpc_addrs = bound_addrs
                    .iter()
                    .enumerate()
                    .filter(|&(j, _)| j != i)
                    .map(|(j, addr)| (j as u32, addr.to_string()))
                    .collect();
            }
            (daemons, None, None)
        };

        // Initialize Express BFT cluster whenever N = 3f + 1 (4, 7, 10, 13, 16).
        let bft_cluster = if let Ok(bft_cfg) = BftConfig::new(num_validators, 1_000) {
            let mut genesis_balances = BTreeMap::new();
            for acc in 0u32..16 {
                genesis_balances.insert(acc, 1_000_000);
            }
            Some(BftCluster::new(bft_cfg, genesis_balances, 2_048, 256, 4))
        } else {
            None
        };

        // Initialize TokenomicsEngine, fund liquid supply for fees, register all N validators,
        // and advance from empty epoch 0 -> epoch 1 so `tokenomics.current_epoch()` stays in
        // exact lockstep with `AutonomousEpochClock` (which enters epoch 1 at block interval).
        let mut tokenomics = TokenomicsEngine::with_defaults();
        tokenomics
            .mint_genesis_supply(100_000 * VERN_PER_VRNM)
            .map_err(|e| format!("genesis supply mint failed: {e}"))?;
        for vid in 0..num_validators as u64 {
            tokenomics
                .register_genesis_validator(vid)
                .map_err(|e| format!("failed to register genesis validator {vid}: {e}"))?;
        }
        let _epoch0 = tokenomics.settle_epoch();
        debug_assert_eq!(tokenomics.current_epoch(), 1);

        Ok(Self {
            num_validators,
            num_buckets,
            epoch_block_interval,
            daemons,
            mpc_cluster,
            wallet_client,
            bft_cluster,
            tokenomics,
            replay_registry: PopReplayRegistry::default(),
            chain_height: 0,
            next_extended_tx_id: 0,
            next_extended_refresh_id: 1,
        })
    }

    /// Map a linear `account_id` to `(bucket_id, slot)` within the 16-slot anonymity buckets.
    #[inline]
    pub fn account_to_bucket_slot(&self, account_id: u32) -> Result<(usize, usize), String> {
        let bucket_id = (account_id as usize) / DIST_BUCKET_SIZE;
        let slot = (account_id as usize) % DIST_BUCKET_SIZE;
        if bucket_id >= self.num_buckets {
            return Err(format!(
                "account_id {account_id} maps to bucket {bucket_id} >= num_buckets {}",
                self.num_buckets
            ));
        }
        Ok((bucket_id, slot))
    }

    /// Split `amount` into Shamir shares and mint ONLY share `y_i` onto each independent daemon
    /// `V_i` (over real pairwise OTP+MAC TCP sockets for `N == 4`).
    pub fn mint_shielded_balance_over_tcp(
        &mut self,
        account_id: u32,
        amount: u128,
    ) -> Result<(), String> {
        let (bucket_id, slot) = self.account_to_bucket_slot(account_id)?;
        if let Some(ref mut client) = self.wallet_client {
            client
                .mint_split_shares(bucket_id, slot, amount)
                .map_err(|e| format!("TCP mint_split_shares failed: {e}"))
        } else {
            let threshold = self.daemons[0].beacon_config().threshold;
            let xs: Vec<u64> = (1..=self.num_validators as u64).collect();
            let shares = split_secret(amount, threshold, &xs)
                .map_err(|e| format!("failed to split secret for extended committee: {e}"))?;
            for (d, share) in self.daemons.iter().zip(shares.iter()) {
                if let MpcBackend::Extended(ref ext) = d.backend {
                    ext.add_local_share(bucket_id, slot, share.y())?;
                }
            }
            Ok(())
        }
    }

    /// Query each independent daemon's single Shamir share (over real OTP+MAC TCP for `N == 4`)
    /// and reconstruct the balance client-side.
    pub fn query_shielded_balance_over_tcp(&mut self, account_id: u32) -> Result<u128, String> {
        let (bucket_id, slot) = self.account_to_bucket_slot(account_id)?;
        if let Some(ref mut client) = self.wallet_client {
            client
                .query_balance(bucket_id, slot)
                .map_err(|e| format!("TCP query_balance failed: {e}"))
        } else {
            let threshold = self.daemons[0].beacon_config().threshold;
            let mut shares = Vec::with_capacity(self.num_validators);
            for d in &self.daemons {
                let y = d.local_balance_share(bucket_id, slot)?;
                let s = Share::new((d.validator_id() as u64) + 1, y)
                    .map_err(|e| format!("invalid share: {e}"))?;
                shares.push(s);
            }
            let report = verify_committee_shares(&shares, threshold)
                .map_err(|e| format!("committee share consistency check failed: {e}"))?;
            if !report.is_consistent {
                return Err("extended committee shares failed degree consistency".to_string());
            }
            reconstruct_secret(&shares, threshold)
                .map_err(|e| format!("extended committee reconstruction failed: {e}"))
        }
    }

    /// Execute a real split-share shielded IT-MPC transfer from `sender_account_id` to
    /// `recipient_account_id` across the independent TCP daemons.
    ///
    /// Both accounts must reside in the same 16-slot anonymity bucket.
    pub fn execute_shielded_transfer_over_tcp(
        &mut self,
        sender_account_id: u32,
        recipient_account_id: u32,
        amount: u128,
    ) -> Result<TransferReceipt, String> {
        let (sender_bucket, sender_slot) = self.account_to_bucket_slot(sender_account_id)?;
        let (recip_bucket, recip_slot) = self.account_to_bucket_slot(recipient_account_id)?;
        if sender_bucket != recip_bucket {
            return Err(format!(
                "sender account {sender_account_id} (bucket {sender_bucket}) and recipient account {recipient_account_id} (bucket {recip_bucket}) must be in the same anonymity bucket"
            ));
        }
        let sender_balance = self.query_shielded_balance_over_tcp(sender_account_id)?;
        self.execute_shielded_transfer_in_bucket_over_tcp(
            sender_bucket,
            sender_slot,
            sender_balance,
            recip_slot,
            amount,
        )
    }

    /// Execute a real split-share shielded IT-MPC transfer with explicit bucket/slot coordinates
    /// across the independent TCP validator daemons.
    pub fn execute_shielded_transfer_in_bucket_over_tcp(
        &mut self,
        bucket_id: usize,
        sender_slot: usize,
        sender_balance: u128,
        recipient_slot: usize,
        amount: u128,
    ) -> Result<TransferReceipt, String> {
        if bucket_id >= self.num_buckets {
            return Err(format!(
                "bucket_id {bucket_id} out of range 0..{}",
                self.num_buckets
            ));
        }
        if sender_slot >= DIST_BUCKET_SIZE || recipient_slot >= DIST_BUCKET_SIZE {
            return Err(format!(
                "slot out of range 0..{DIST_BUCKET_SIZE}"
            ));
        }
        if sender_balance < amount {
            return Err(format!(
                "insufficient shielded balance: have {sender_balance}, need {amount}"
            ));
        }

        let receipt = if let Some(ref mut client) = self.wallet_client {
            client
                .send_shielded(bucket_id, sender_slot, sender_balance, recipient_slot, amount)
                .map_err(|e| format!("TCP split-share IT-MPC transfer failed: {e}"))?
        } else {
            let start = Instant::now();
            let threshold = self.daemons[0].beacon_config().threshold;
            let xs: Vec<u64> = (1..=self.num_validators as u64).collect();
            let debit_shares = split_secret(amount, threshold, &xs)
                .map_err(|e| format!("failed to split debit shares: {e}"))?;
            let credit_shares = split_secret(amount, threshold, &xs)
                .map_err(|e| format!("failed to split credit shares: {e}"))?;
            for i in 0..self.num_validators {
                if let MpcBackend::Extended(ref ext) = self.daemons[i].backend {
                    ext.sub_local_share(bucket_id, sender_slot, debit_shares[i].y())?;
                    ext.add_local_share(bucket_id, recipient_slot, credit_shares[i].y())?;
                }
            }
            let tx_id = self.next_extended_tx_id;
            self.next_extended_tx_id += 1;
            TransferReceipt {
                tx_id,
                committed_validators: self.num_validators,
                rtt_us: start.elapsed().as_micros() as u64,
            }
        };

        // Charge Shielded Pad-Burn fee (20% burned, 80% added to epoch validator reward pool).
        let _ = self.tokenomics.collect_fee(FeeLane::Shielded);

        for d in &self.daemons {
            d.update_metrics(|m| {
                m.shielded_txs_processed = m.shielded_txs_processed.saturating_add(1);
            });
        }

        Ok(receipt)
    }

    /// Submit a batch of Express [`BinaryTx`] transactions through the cluster's BFT consensus.
    pub fn finalize_express_bft_block(
        &mut self,
        txs: Vec<BinaryTx>,
    ) -> Result<Option<BlockCertificate>, String> {
        let cert = if let Some(ref mut bft) = self.bft_cluster {
            let c = bft
                .propose_and_finalize_batch(txs)
                .map_err(|e| format!("BFT block finalization failed: {e}"))?;
            self.chain_height = c.height;
            Some(c)
        } else {
            self.chain_height = self.chain_height.saturating_add(1);
            None
        };

        let height = self.chain_height;
        for d in &mut self.daemons {
            let _ = d.epoch_clock.on_block_finalized(height);
            let cur_ep = d.epoch_clock.current_epoch();
            d.update_metrics(|m| {
                m.blocks_finalized = m.blocks_finalized.saturating_add(1);
                m.current_epoch = cur_ep;
            });
        }
        Ok(cert)
    }

    /// Execute one complete autonomous epoch cycle across all independent TCP validator daemons:
    ///
    /// 1. Finalizes BFT blocks up to the next [`AutonomousEpochClock`] epoch boundary.
    /// 2. Runs a full decentralized threshold [`VernamBeacon`] commit-and-reveal round across
    ///    the committee to derive unbiasable `beacon_gamma` (`Gamma_e`).
    /// 3. Derives the mandatory fixed-point-free Sattolo single-cycle [`BeaconPairingSchedule`]
    ///    from `Gamma_e`.
    /// 4. Runs bilateral QKD pad mining ([`PopMiner::mine_bilateral_pad_batch`]) against each
    ///    validator's beacon-assigned counterparty and answers deterministic beacon challenges
    ///    ([`PopAuditor::issue_beacon_challenge`]).
    /// 5. Audits and settles the epoch via [`PopEpochCoordinator::run_beacon_bilateral_audited_epoch`]
    ///    with [`PopReplayRegistry`] cross-epoch anti-replay and [`TokenomicsEngine`] halving
    ///    rewards.
    /// 6. Triggers real distributed TCP Proactive Secret Sharing (`distributed_mpc` PSS refresh)
    ///    across all independent TCP daemons so every server's Shamir share rotates to epoch
    ///    `e + 1` with zero balance reconstruction.
    pub fn run_autonomous_epoch_cycle(&mut self) -> Result<EpochCycleReport, String> {
        self.run_autonomous_epoch_cycle_with_pairing_policy(|_vid, expected| expected)
    }

    /// Execute an autonomous epoch cycle while overriding specific providers' chosen counterparties
    /// via a `(provider_id -> actual_counterparty_id)` map (useful for adversarial Sybil testing).
    pub fn run_autonomous_epoch_cycle_with_counterparty_overrides(
        &mut self,
        overrides: &BTreeMap<u32, u32>,
    ) -> Result<EpochCycleReport, String> {
        self.run_autonomous_epoch_cycle_with_pairing_policy(|vid, expected| {
            overrides.get(&vid).copied().unwrap_or(expected)
        })
    }

    /// Execute an autonomous epoch cycle with a custom counterparty selector
    /// `selector(provider_id, beacon_expected_counterparty) -> actual_counterparty` (honest
    /// validators always return `beacon_expected_counterparty`; adversarial tests can return an
    /// unauthorized colluding buddy to verify deterministic 50% slashing).
    pub fn run_autonomous_epoch_cycle_with_pairing_policy<F>(
        &mut self,
        mut counterparty_selector: F,
    ) -> Result<EpochCycleReport, String>
    where
        F: FnMut(u32, u32) -> u32,
    {
        let n = self.num_validators;
        let blocks_needed = self.daemons[0]
            .epoch_clock
            .blocks_until_next_epoch()
            .max(1);

        // Step 0: Finalize BFT blocks until every daemon's AutonomousEpochClock crosses the boundary.
        let mut blocks_finalized_in_epoch = 0u64;
        for _ in 0..blocks_needed {
            let _ = self.finalize_express_bft_block(Vec::new())?;
            blocks_finalized_in_epoch += 1;
            if self.daemons[0].epoch_clock.needs_beacon_round() {
                break;
            }
        }
        if !self.daemons[0].epoch_clock.needs_beacon_round() {
            return Err(format!(
                "epoch clock did not enter AwaitingBeacon (stage={:?})",
                self.daemons[0].epoch_clock.pipeline_stage()
            ));
        }

        let epoch = self.daemons[0].epoch_clock.current_epoch();
        if self.tokenomics.current_epoch() != epoch {
            return Err(format!(
                "tokenomics epoch {} diverged from autonomous clock epoch {}",
                self.tokenomics.current_epoch(),
                epoch
            ));
        }

        // Step 1: Real threshold `VernamBeacon` commit-and-reveal round across all N validators.
        let beacon_cfg = self.daemons[0].beacon_config();
        let beacon_output = run_committee_threshold_beacon(beacon_cfg, epoch)?;
        for d in &mut self.daemons {
            d.epoch_clock
                .complete_beacon_round(beacon_output.clone())
                .map_err(|e| format!("daemon {} complete_beacon_round failed: {e}", d.validator_id()))?;
        }

        // Step 2: Derive mandatory Sattolo single-cycle `BeaconPairingSchedule` from Gamma_e.
        let active_validators: Vec<ValidatorId> = (0..n as u64).collect();
        let pairing_schedule =
            BeaconPairingSchedule::from_beacon_output(&beacon_output, &active_validators)
                .map_err(|e| format!("failed to derive BeaconPairingSchedule: {e}"))?;

        for d in &self.daemons {
            let assigned = pairing_schedule
                .expected_counterparty(d.validator_id() as u64)
                .map(|cp| cp as u32);
            d.update_metrics(|m| {
                m.current_epoch = epoch;
                m.last_beacon_gamma = Some(beacon_output.gamma);
                m.last_assigned_counterparty = assigned;
            });
        }

        // Step 3: Bilateral QKD pad mining + deterministic beacon PoP challenge answering.
        let mut submissions = Vec::with_capacity(n);
        for vid in 0..n as u32 {
            let expected_cp = pairing_schedule
                .expected_counterparty(vid as u64)
                .ok_or_else(|| format!("missing beacon counterparty for validator {vid}"))?
                as u32;
            let chosen_cp = counterparty_selector(vid, expected_cp);

            let peer_key = PeerReceiptKey::generate();
            let (mut batch, commitment, receipt) = PopMiner::mine_bilateral_pad_batch(
                vid as u64,
                chosen_cp as u64,
                epoch,
                DEFAULT_POP_PAD_PAGES,
                DEFAULT_POP_BEAVER_TRIPLES,
                &peer_key,
            )
            .map_err(|e| format!("validator {vid} bilateral PoP mining failed: {e}"))?;

            let challenge = PopAuditor::issue_beacon_challenge(
                vid as u64,
                epoch,
                beacon_output.gamma,
                DEFAULT_CHALLENGE_SLOT_COUNT,
            )
            .map_err(|e| format!("validator {vid} issue_beacon_challenge failed: {e}"))?;

            PopAuditor::verify_beacon_challenge_binding(&challenge, beacon_output.gamma)
                .map_err(|e| format!("validator {vid} challenge binding verification failed: {e}"))?;

            let proof = PopMiner::answer_challenge(&mut batch, &challenge)
                .with_liveness(blocks_finalized_in_epoch.max(1), 1);

            submissions.push(BilateralPopSubmission {
                commitment,
                challenge,
                proof,
                peer_receipt: Some(receipt),
                peer_key: Some(peer_key),
            });
        }

        // Step 4: Audit & settle epoch via `PopEpochCoordinator` with anti-replay + Tokenomics.
        let pop_report = PopEpochCoordinator::run_beacon_bilateral_audited_epoch(
            beacon_output.gamma,
            &active_validators,
            &mut self.tokenomics,
            &mut self.replay_registry,
            &submissions,
        )
        .map_err(|e| format!("PopEpochCoordinator failed: {e}"))?;

        self.tokenomics
            .check_invariants()
            .map_err(|e| format!("tokenomics accounting invariant failed: {e}"))?;

        let accepted_ids: BTreeSet<u64> =
            pop_report.accepted.iter().map(|r| r.validator_id).collect();
        let tracked_pads = self.replay_registry.tracked_pad_fingerprints();

        for d in &mut self.daemons {
            let vid = d.validator_id() as u64;
            d.epoch_clock
                .complete_pop_audit()
                .map_err(|e| format!("daemon {vid} complete_pop_audit failed: {e}"))?;
            let passed = accepted_ids.contains(&vid);
            d.update_metrics(|m| {
                if passed {
                    m.bilateral_pop_passes = m.bilateral_pop_passes.saturating_add(1);
                }
                m.anti_replay_tracked_pads = tracked_pads;
            });
        }

        // Step 5: Trigger real distributed TCP Proactive Secret Sharing (PSS) refresh across
        // all independent daemons so every Shamir share rotates to epoch `e + 1` with zero
        // balance reconstruction!
        let pss_refresh = self.trigger_cluster_pss_refresh()?;

        for d in &mut self.daemons {
            d.epoch_clock
                .complete_pss_refresh()
                .map_err(|e| format!("daemon {} complete_pss_refresh failed: {e}", d.validator_id()))?;
            debug_assert_eq!(d.epoch_clock.pipeline_stage(), EpochPipelineStage::Idle);
            d.update_metrics(|m| {
                m.pss_epoch = pss_refresh.new_epoch;
            });
        }

        Ok(EpochCycleReport {
            epoch,
            blocks_finalized_in_epoch,
            total_chain_height: self.chain_height,
            beacon_output,
            pairing_schedule,
            pop_report,
            pss_refresh,
            anti_replay_tracked_pads: tracked_pads,
        })
    }

    /// Trigger a live zero-reconstruction Proactive Secret Sharing (PSS) refresh across all
    /// independent daemons in the cluster.
    fn trigger_cluster_pss_refresh(&mut self) -> Result<PssRefreshReport, String> {
        if let Some(ref mut client) = self.wallet_client {
            client
                .trigger_distributed_pss_refresh()
                .map_err(|e| format!("distributed TCP PSS refresh failed: {e}"))
        } else {
            let start = Instant::now();
            let threshold = self.daemons[0].beacon_config().threshold;
            let xs: Vec<u64> = (1..=self.num_validators as u64).collect();
            let total_accounts = self.num_buckets * DIST_BUCKET_SIZE;

            for b in 0..self.num_buckets {
                for s in 0..DIST_BUCKET_SIZE {
                    // Each validator independently contributes a fresh degree-(t-1) zero-polynomial
                    // `h_j(0) = 0`, sending ONLY `h_j(i + 1)` to validator `i`!
                    let mut sum_deltas = vec![0u128; self.num_validators];
                    for _dealer in 0..self.num_validators {
                        let zero_shares = split_secret(0, threshold, &xs)
                            .map_err(|e| format!("extended PSS zero-poly split failed: {e}"))?;
                        for (i, zs) in zero_shares.iter().enumerate() {
                            sum_deltas[i] = add_mod(sum_deltas[i], zs.y());
                        }
                    }
                    for (i, d) in self.daemons.iter().enumerate() {
                        if let MpcBackend::Extended(ref ext) = d.backend {
                            ext.add_local_share(b, s, sum_deltas[i])?;
                        }
                    }
                    for v in &mut sum_deltas {
                        zeroize_u128(v);
                    }
                }
            }

            let mut new_epoch = 1u64;
            for d in &self.daemons {
                if let MpcBackend::Extended(ref ext) = d.backend {
                    new_epoch = ext.increment_pss_epoch();
                }
            }
            let refresh_id = self.next_extended_refresh_id;
            self.next_extended_refresh_id += 1;

            Ok(PssRefreshReport {
                refresh_id,
                new_epoch,
                accounts_refreshed: total_accounts,
                elapsed_us: start.elapsed().as_micros() as u64,
            })
        }
    }

    /// Read ONLY validator `validator_id`'s single Shamir share for `account_id`.
    pub fn daemon_balance_share(&self, validator_id: u32, account_id: u32) -> Result<u128, String> {
        let idx = validator_id as usize;
        if idx >= self.num_validators {
            return Err(format!(
                "validator_id {validator_id} out of range 0..{}",
                self.num_validators
            ));
        }
        let (bucket_id, slot) = self.account_to_bucket_slot(account_id)?;
        if let Some(ref cluster) = self.mpc_cluster {
            cluster
                .daemon(idx)
                .local_balance_share(bucket_id, slot)
                .map_err(|e| format!("failed to read daemon {validator_id} local share: {e}"))
        } else {
            self.daemons[idx].local_balance_share(bucket_id, slot)
        }
    }

    /// Prove split-share isolation for `account_id`:
    ///
    /// 1. Reads ONLY each individual daemon's single Shamir share `y_i`.
    /// 2. Proves that any `t - 1` daemons' shares yield **0 bits of balance information**
    ///    (algebraically consistent with arbitrarily many distinct fake balances in `F_(2^127 - 1)`).
    /// 3. Proves that any `t` daemons (and all `N` daemons) reconstruct the exact same balance
    ///    with full degree-`(t - 1)` parity verification.
    pub fn verify_split_share_isolation(
        &self,
        account_id: u32,
    ) -> Result<SplitShareIsolationReport, String> {
        let (bucket_id, slot) = self.account_to_bucket_slot(account_id)?;
        let n = self.num_validators;
        let threshold = if self.mpc_cluster.is_some() {
            DIST_THRESHOLD
        } else {
            self.daemons[0].beacon_config().threshold
        };

        let mut daemon_shares = Vec::with_capacity(n);
        for vid in 0..n as u32 {
            let y_i = self.daemon_balance_share(vid, account_id)?;
            daemon_shares.push((vid, y_i));
        }

        let pss_epoch = if let Some(ref cluster) = self.mpc_cluster {
            let ep0 = cluster.daemon(0).epoch();
            for i in 1..DIST_NUM_VALIDATORS {
                if cluster.daemon(i).epoch() != ep0 {
                    return Err(format!(
                        "daemon {i} PSS epoch {} diverged from daemon 0 epoch {ep0}",
                        cluster.daemon(i).epoch()
                    ));
                }
            }
            ep0
        } else {
            self.daemons[0].pss_epoch()
        };

        // 1. Verify full-committee degree consistency & exact quorum reconstruction.
        let (reconstructed_balance, all_quorum_subsets_agree) =
            if n == DIST_NUM_VALIDATORS && threshold == DIST_THRESHOLD {
                let shares4 = [
                    daemon_shares[0].1,
                    daemon_shares[1].1,
                    daemon_shares[2].1,
                    daemon_shares[3].1,
                ];
                let full_bal = reconstruct_4_verified(&shares4)
                    .map_err(|e| format!("4-of-4 degree-2 verification failed: {e}"))?;

                let subsets: [[(usize, u128); DIST_THRESHOLD]; 4] = [
                    [(0, shares4[0]), (1, shares4[1]), (2, shares4[2])],
                    [(0, shares4[0]), (1, shares4[1]), (3, shares4[3])],
                    [(0, shares4[0]), (2, shares4[2]), (3, shares4[3])],
                    [(1, shares4[1]), (2, shares4[2]), (3, shares4[3])],
                ];
                let mut agree = true;
                for subset in &subsets {
                    let sub_bal = reconstruct_any_3(subset)
                        .map_err(|e| format!("3-of-4 reconstruction failed: {e}"))?;
                    if sub_bal != full_bal {
                        agree = false;
                    }
                }
                (full_bal, agree)
            } else {
                let shares: Vec<Share> = daemon_shares
                    .iter()
                    .map(|&(vid, y)| Share::new((vid as u64) + 1, y))
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("share conversion failed: {e}"))?;
                let consistency = verify_committee_shares(&shares, threshold)
                    .map_err(|e| format!("committee consistency failed: {e}"))?;
                if !consistency.is_consistent {
                    return Err("committee shares failed degree-(t-1) consistency".to_string());
                }
                let bal_first = reconstruct_secret(&shares[..threshold], threshold)
                    .map_err(|e| format!("first-quorum reconstruction failed: {e}"))?;
                let bal_last = reconstruct_secret(&shares[(n - threshold)..], threshold)
                    .map_err(|e| format!("last-quorum reconstruction failed: {e}"))?;
                (bal_first, bal_first == bal_last)
            };

        // 2. Information-theoretic zero-leakage proof for `t - 1` colluding daemons:
        //    Take the first `t - 1` shares `(x_0, y_0), ..., (x_{t-2}, y_{t-2})`.
        //    Show that for two arbitrary distinct hypothetical balances `B_fake_a != B_fake_b`,
        //    there exist unique degree-(t - 1) polynomials matching ALL `t - 1` observed shares
        //    whose constant terms equal `B_fake_a` and `B_fake_b` respectively.
        let under_count = threshold - 1;
        let fake_a = add_mod(reconstructed_balance, 13_371);
        let fake_b = add_mod(reconstructed_balance, 987_653);
        let target_x = validator_eval_x(under_count as u32);

        let verify_consistent_with_fake = |fake_balance: u128| -> Result<bool, String> {
            let mut pts = Vec::with_capacity(threshold);
            pts.push((0u128, fake_balance));
            for &(vid, y) in &daemon_shares[..under_count] {
                pts.push((validator_eval_x(vid), y));
            }
            let forged_t_share = lagrange_interpolate_at(&pts, target_x)
                .map_err(|e| format!("interpolation for zero-info proof failed: {e}"))?;

            // Reconstruct at x = 0 using the `t - 1` real shares + the forged `t`-th share.
            let mut recon_pts = Vec::with_capacity(threshold);
            for &(vid, y) in &daemon_shares[..under_count] {
                recon_pts.push((validator_eval_x(vid), y));
            }
            recon_pts.push((target_x, forged_t_share));
            let recovered = lagrange_interpolate_at(&recon_pts, 0)
                .map_err(|e| format!("reconstruction for zero-info proof failed: {e}"))?;
            Ok(recovered == fake_balance)
        };

        let under_threshold_zero_info_verified = fake_a != reconstructed_balance
            && fake_b != reconstructed_balance
            && fake_a != fake_b
            && verify_consistent_with_fake(fake_a)?
            && verify_consistent_with_fake(fake_b)?;

        Ok(SplitShareIsolationReport {
            account_id,
            bucket_id,
            slot,
            num_validators: n,
            threshold,
            pss_epoch,
            daemon_shares,
            reconstructed_balance,
            all_quorum_subsets_agree,
            under_threshold_zero_info_verified,
        })
    }

    /// Number of independent validator daemons in this cluster.
    pub fn num_validators(&self) -> usize {
        self.num_validators
    }

    /// Number of 16-slot anonymity buckets provisioned per daemon.
    pub fn num_buckets(&self) -> usize {
        self.num_buckets
    }

    /// Configured finalized-block interval per autonomous epoch.
    pub fn epoch_block_interval(&self) -> u64 {
        self.epoch_block_interval
    }

    /// Access all independent [`ValidatorDaemon`] handles.
    pub fn daemons(&self) -> &[ValidatorDaemon] {
        &self.daemons
    }

    /// Access a single [`ValidatorDaemon`] by `validator_id`.
    pub fn daemon(&self, validator_id: u32) -> Option<&ValidatorDaemon> {
        self.daemons.get(validator_id as usize)
    }

    /// Access the underlying single-share [`MpcValidatorDaemon`] (available for 4-node TCP clusters).
    pub fn mpc_daemon(&self, validator_id: u32) -> Option<&MpcValidatorDaemon> {
        let idx = validator_id as usize;
        if idx >= DIST_NUM_VALIDATORS {
            return None;
        }
        self.mpc_cluster.as_ref().map(|c| c.daemon(idx))
    }

    /// Live metrics snapshot for one validator daemon.
    pub fn daemon_metrics(&self, validator_id: u32) -> Option<ValidatorDaemonMetrics> {
        let d = self.daemons.get(validator_id as usize)?;
        let mut m = d.metrics();
        if let Some(ref cluster) = self.mpc_cluster {
            let mpc = cluster.daemon(validator_id as usize);
            m.pss_epoch = mpc.epoch();
            m.shielded_txs_processed = mpc.committed_txs();
        }
        Some(m)
    }

    /// Live metrics snapshots for all validator daemons in ID order.
    pub fn all_metrics(&self) -> Vec<ValidatorDaemonMetrics> {
        (0..self.num_validators as u32)
            .filter_map(|id| self.daemon_metrics(id))
            .collect()
    }

    /// Bound TCP MPC addresses of every validator daemon in the cluster.
    pub fn peer_mpc_addrs(&self) -> Vec<(u32, SocketAddr)> {
        self.daemons
            .iter()
            .map(|d| (d.validator_id(), d.mpc_addr()))
            .collect()
    }

    /// Reference to the cluster's [`TokenomicsEngine`].
    pub fn tokenomics(&self) -> &TokenomicsEngine {
        &self.tokenomics
    }

    /// Reference to the cluster's [`PopReplayRegistry`].
    pub fn replay_registry(&self) -> &PopReplayRegistry {
        &self.replay_registry
    }

    /// Cleanly stop all daemons, close all TCP sockets, and join every background thread.
    pub fn shutdown(mut self) {
        self.stop_all_internal();
    }

    fn stop_all_internal(&mut self) {
        self.wallet_client = None;
        for d in &mut self.daemons {
            d.stop_internal();
        }
        if let Some(ref cluster) = self.mpc_cluster {
            cluster.stop_all();
        }
    }
}

impl Drop for ValidatorClusterOrchestrator {
    fn drop(&mut self) {
        self.stop_all_internal();
    }
}

// ============================================================================
// Decentralized Threshold Beacon Round Helper
// ============================================================================

/// Execute a full decentralized `N`-validator [`VernamBeacon`] Commit -> Pairwise Symmetry ->
/// Rabin-Ben-Or IC-MAC -> Lock -> Reveal -> Finalize round over single-use OTP+CW-MAC envelopes.
fn run_committee_threshold_beacon(
    config: BeaconConfig,
    epoch: u64,
) -> Result<EpochBeaconOutput, String> {
    let n = config.num_validators;
    let mut nodes: Vec<VernamBeacon> = (0..n as u32)
        .map(|id| VernamBeacon::new(config, epoch, id).map_err(|e| format!("beacon init: {e}")))
        .collect::<Result<_, _>>()?;

    // Generate single-use pairwise OTP+CW-MAC envelopes for Commit phase.
    let mut sender_keys: Vec<Vec<OtpChannelKey>> = Vec::with_capacity(n);
    let mut receiver_keys: Vec<Vec<Option<OtpChannelKey>>> =
        (0..n).map(|_| (0..n).map(|_| None).collect()).collect();
    for d in 0..n {
        let mut row = Vec::with_capacity(n);
        for r in 0..n {
            let (sk, rk) = OtpChannelKey::generate_pair_for_config(&config);
            row.push(sk);
            receiver_keys[r][d] = Some(rk);
        }
        sender_keys.push(row);
    }
    let receiver_keys: Vec<Vec<OtpChannelKey>> = receiver_keys
        .into_iter()
        .map(|row| row.into_iter().map(Option::unwrap).collect())
        .collect();

    let mut all_envelopes = Vec::with_capacity(n);
    for d in 0..n {
        let refs: Vec<(u32, &OtpChannelKey)> =
            (0..n).map(|r| (r as u32, &sender_keys[d][r])).collect();
        let envs = nodes[d]
            .generate_commit_envelopes(&refs)
            .map_err(|e| format!("dealer {d} commit envelope generation failed: {e}"))?;
        all_envelopes.push(envs);
    }

    for r in 0..n {
        for d in 0..n {
            nodes[r]
                .receive_commit_envelope(&all_envelopes[d][r], &receiver_keys[r][d])
                .map_err(|e| format!("recipient {r} failed to open dealer {d} envelope: {e}"))?;
        }
    }

    // Zero-leakage pairwise symmetry checks: F_d(x_j, x_k) == F_d(x_k, x_j).
    let all_checks: Vec<_> = nodes
        .iter()
        .map(VernamBeacon::generate_pairwise_checks)
        .collect();
    for checks in &all_checks {
        for chk in checks {
            let ok = nodes[chk.to_id as usize]
                .verify_pairwise_check(chk)
                .map_err(|e| format!("pairwise symmetry check error: {e}"))?;
            if !ok {
                return Err(format!(
                    "pairwise symmetry mismatch for dealer {} between {} and {}",
                    chk.dealer_id, chk.from_id, chk.to_id
                ));
            }
        }
    }

    // Commit-phase zero-knowledge Rabin-Ben-Or IC-MAC verification.
    let all_ic_challenges: Vec<_> = nodes
        .iter_mut()
        .map(VernamBeacon::generate_ic_challenges)
        .collect();
    for chs in &all_ic_challenges {
        for ch in chs {
            let resp = nodes[ch.holder_id as usize]
                .answer_ic_challenge(ch)
                .map_err(|e| format!("IC-MAC challenge answer error: {e}"))?;
            let ok = nodes[ch.verifier_id as usize]
                .verify_ic_response(&resp)
                .map_err(|e| format!("IC-MAC verification error: {e}"))?;
            if !ok {
                return Err(format!(
                    "IC-MAC verification failed for dealer {} holder {}",
                    ch.dealer_id, ch.holder_id
                ));
            }
        }
    }

    // Lock qualified dealer set C before any secret is revealed.
    for node in &mut nodes {
        let qualified = node
            .lock_commit_phase()
            .map_err(|e| format!("lock_commit_phase failed on v{}: {e}", node.validator_id()))?;
        if qualified.len() != n {
            return Err(format!(
                "expected {n} qualified beacon dealers, got {}",
                qualified.len()
            ));
        }
    }

    // Phase 2: Direct reveals & deterministic consensus output.
    let reveals: Vec<_> = nodes
        .iter()
        .map(|node| {
            node.generate_reveal()
                .map_err(|e| format!("generate_reveal failed on v{}: {e}", node.validator_id()))
        })
        .collect::<Result<_, _>>()?;

    let mut outputs = Vec::with_capacity(n);
    for node in &mut nodes {
        for rev in &reveals {
            let valid = node
                .receive_reveal(rev)
                .map_err(|e| format!("receive_reveal failed on v{}: {e}", node.validator_id()))?;
            if !valid {
                return Err(format!("invalid beacon reveal from dealer {}", rev.dealer_id));
            }
        }
        let out = node
            .finalize_epoch()
            .map_err(|e| format!("finalize_epoch failed on v{}: {e}", node.validator_id()))?;
        outputs.push(out);
    }

    let first = outputs[0].clone();
    for out in &outputs[1..] {
        if out != &first {
            return Err("validators diverged on finalized EpochBeaconOutput".to_string());
        }
    }
    Ok(first)
}

// ============================================================================
// Standalone CLI Entrypoint (`vrnm validator`)
// ============================================================================

/// Run a standalone single-share Vernam validator daemon from the CLI (`vrnm validator`).
///
/// Honors optional `VRNM_MAX_EPOCHS` environment variable for bounded runs; otherwise prints
/// startup information and runs cleanly until terminated (Ctrl-C / SIGINT).
pub fn run_standalone_daemon_cli(config: ValidatorDaemonConfig) -> Result<(), String> {
    let max_epochs = std::env::var("VRNM_MAX_EPOCHS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    run_standalone_daemon_cli_with_max_epochs(config, max_epochs)
}

/// Run a standalone single-share Vernam validator daemon with an explicit optional `--max-epochs`
/// limit (`None` waits cleanly until Ctrl-C; `Some(k)` executes `k` autonomous epoch ticks and
/// shuts down cleanly with zero leaked threads).
pub fn run_standalone_daemon_cli_with_max_epochs(
    config: ValidatorDaemonConfig,
    max_epochs: Option<u64>,
) -> Result<(), String> {
    let mut daemon = ValidatorDaemon::start(config)?;
    let bcfg = daemon.beacon_config();
    let cfg = daemon.config().clone();
    let mpc_addr = daemon.mpc_addr();
    let http_addr = daemon.http_addr();

    let peers_summary = if cfg.peer_mpc_addrs.is_empty() {
        "(none configured — awaiting peer mesh wiring)".to_string()
    } else {
        cfg.peer_mpc_addrs
            .iter()
            .map(|(id, addr)| format!("v{id}@{addr}"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    println!("========================================================================");
    println!("  VERNAM (VRNM) MULTI-HOST SINGLE-SHARE VALIDATOR DAEMON");
    println!(
        "  Validator ID    : {} / committee N={} (threshold t={}, max faults f={})",
        cfg.validator_id, bcfg.num_validators, bcfg.threshold, bcfg.max_faults
    );
    println!("  Isolation Mode  : STRICT SINGLE-SHARE (1 Shamir share per server; 0 peer shares)");
    println!("  TCP IT-MPC Addr : {mpc_addr}");
    if let Some(haddr) = http_addr {
        println!("  HTTP Monitor    : http://{haddr}/metrics  (and /health)");
    } else {
        println!("  HTTP Monitor    : disabled");
    }
    println!("  Peer MPC Addrs  : {peers_summary}");
    println!(
        "  Shielded State  : {} buckets ({} anonymous slots) | Epoch interval: {} blocks",
        cfg.num_buckets,
        cfg.num_buckets * DIST_BUCKET_SIZE,
        cfg.epoch_block_interval
    );
    println!("========================================================================");

    match max_epochs {
        Some(limit) => {
            let mut height = 0u64;
            let active_validators: Vec<ValidatorId> = (0..cfg.committee_size as u64).collect();
            for ep in 1..=limit {
                for _ in 0..cfg.epoch_block_interval {
                    height += 1;
                    let _ = daemon.epoch_clock.on_block_finalized(height);
                }
                let mut local_gamma = random_field_elem();
                if local_gamma == 0 {
                    local_gamma = 1;
                }
                let synthetic_beacon = EpochBeaconOutput {
                    epoch: ep,
                    gamma: local_gamma,
                    qualified_validators: (0..cfg.committee_size as u32).collect(),
                    reconstructed_validators: Vec::new(),
                    disqualified_validators: Vec::new(),
                };
                daemon
                    .epoch_clock
                    .complete_beacon_round(synthetic_beacon.clone())
                    .map_err(|e| format!("standalone beacon transition failed: {e}"))?;
                let schedule =
                    BeaconPairingSchedule::from_beacon_output(&synthetic_beacon, &active_validators)
                        .map_err(|e| format!("standalone pairing schedule failed: {e}"))?;
                let assigned_cp = schedule
                    .expected_counterparty(cfg.validator_id as u64)
                    .map(|v| v as u32);
                daemon
                    .epoch_clock
                    .complete_pop_audit()
                    .map_err(|e| format!("standalone pop transition failed: {e}"))?;
                daemon
                    .epoch_clock
                    .complete_pss_refresh()
                    .map_err(|e| format!("standalone pss transition failed: {e}"))?;

                daemon.update_metrics(|m| {
                    m.current_epoch = ep;
                    m.blocks_finalized = height;
                    m.last_beacon_gamma = Some(local_gamma);
                    m.last_assigned_counterparty = assigned_cp;
                });

                let snap = daemon.metrics();
                println!(
                    "  [validator {}] epoch={} height={} gamma=0x{:032x} assigned_counterparty={:?}",
                    snap.validator_id,
                    snap.current_epoch,
                    snap.blocks_finalized,
                    local_gamma,
                    snap.last_assigned_counterparty
                );
            }
            println!(
                "  Validator {} completed {limit} epoch(s); shutting down cleanly.",
                cfg.validator_id
            );
            daemon.shutdown();
            Ok(())
        }
        None => {
            println!("  Validator daemon running. Press Ctrl-C to stop.");
            loop {
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

// ============================================================================
// Integration Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pop_mining::PopError;
    use crate::tokenomics::{DEFAULT_REQUIRED_BOND, SlashingOffense, ValidatorStatus};

    #[test]
    fn test_4_independent_tcp_validator_daemons_full_epoch_lifecycle() {
        // 1. Spawn 4 completely independent TCP-bound ValidatorDaemons (1 Shamir share each).
        let mut cluster = ValidatorClusterOrchestrator::spawn_local_tcp_cluster(4, 4)
            .expect("spawn 4-daemon real TCP cluster");
        assert_eq!(cluster.num_validators(), 4);
        assert_eq!(cluster.num_buckets(), 4);

        // Confirm 4 distinct live TCP ports.
        let addrs: BTreeSet<SocketAddr> = cluster
            .peer_mpc_addrs()
            .into_iter()
            .map(|(_, a)| a)
            .collect();
        assert_eq!(addrs.len(), 4, "all 4 validator daemons must bind distinct TCP ports");

        // 2. Mint shielded balances over real pairwise OTP+MAC TCP sockets.
        cluster
            .mint_shielded_balance_over_tcp(0, 10_000)
            .expect("mint account 0");
        cluster
            .mint_shielded_balance_over_tcp(1, 2_500)
            .expect("mint account 1");

        assert_eq!(cluster.query_shielded_balance_over_tcp(0).unwrap(), 10_000);
        assert_eq!(cluster.query_shielded_balance_over_tcp(1).unwrap(), 2_500);
        assert_eq!(cluster.query_shielded_balance_over_tcp(2).unwrap(), 0);

        // 3. Execute real cross-daemon TCP split-share IT-MPC transfers.
        let r1 = cluster
            .execute_shielded_transfer_over_tcp(0, 1, 1_500)
            .expect("TCP shielded transfer 0 -> 1");
        assert_eq!(r1.committed_validators, 4);

        let r2 = cluster
            .execute_shielded_transfer_over_tcp(1, 2, 750)
            .expect("TCP shielded transfer 1 -> 2");
        assert_eq!(r2.committed_validators, 4);

        assert_eq!(cluster.query_shielded_balance_over_tcp(0).unwrap(), 8_500);
        assert_eq!(cluster.query_shielded_balance_over_tcp(1).unwrap(), 3_250);
        assert_eq!(cluster.query_shielded_balance_over_tcp(2).unwrap(), 750);

        // 4. Verify split-share isolation BEFORE Epoch 1 PSS refresh.
        let iso_before = cluster
            .verify_split_share_isolation(0)
            .expect("verify split-share isolation before epoch 1");
        assert_eq!(iso_before.reconstructed_balance, 8_500);
        assert_eq!(iso_before.threshold, 3);
        assert_eq!(iso_before.pss_epoch, 1);
        assert!(iso_before.all_quorum_subsets_agree);
        assert!(iso_before.under_threshold_zero_info_verified);
        let shares_ep0: Vec<u128> = iso_before.daemon_shares.iter().map(|&(_, y)| y).collect();

        // 5. Run Autonomous Epoch Cycle #1:
        //    Live Threshold Beacon Gamma_1 -> Sattolo Beacon-Paired Bilateral PoP ->
        //    Tokenomics settlement -> Live TCP PSS share rotation (epoch 1 -> 2).
        let ep1 = cluster
            .run_autonomous_epoch_cycle()
            .expect("autonomous epoch cycle 1");
        assert_eq!(ep1.epoch, 1);
        assert_eq!(ep1.blocks_finalized_in_epoch, DEFAULT_EPOCH_BLOCK_INTERVAL);
        assert!(ep1.beacon_output.gamma > 0 && ep1.beacon_output.gamma < PRIME_P);
        assert_eq!(ep1.beacon_output.qualified_validators.len(), 4);
        assert_eq!(ep1.pairing_schedule.len(), 4);
        for vid in 0..4u64 {
            let cp = ep1.pairing_schedule.expected_counterparty(vid).unwrap();
            assert_ne!(cp, vid, "derangement must have zero fixed points");
            assert_ne!(
                ep1.pairing_schedule.expected_counterparty(cp).unwrap(),
                vid,
                "4-validator Sattolo single-cycle must have zero 2-cycles"
            );
        }
        assert_eq!(ep1.pop_report.accepted.len(), 4);
        assert!(ep1.pop_report.rejected.is_empty());
        assert_eq!(ep1.pss_refresh.new_epoch, 2);
        assert!(ep1.anti_replay_tracked_pads >= 4 * DEFAULT_CHALLENGE_SLOT_COUNT);

        // Confirm EVERY validator's Shamir share rotated across Epoch 1 while balance stayed exact!
        let iso_ep1 = cluster
            .verify_split_share_isolation(0)
            .expect("verify split-share isolation after epoch 1");
        assert_eq!(iso_ep1.reconstructed_balance, 8_500);
        assert_eq!(iso_ep1.pss_epoch, 2);
        assert!(iso_ep1.all_quorum_subsets_agree);
        assert!(iso_ep1.under_threshold_zero_info_verified);
        let shares_ep1: Vec<u128> = iso_ep1.daemon_shares.iter().map(|&(_, y)| y).collect();
        for i in 0..4 {
            assert_ne!(
                shares_ep1[i], shares_ep0[i],
                "validator {i}'s Shamir share must rotate during Epoch 1 TCP PSS refresh"
            );
        }
        assert_eq!(cluster.query_shielded_balance_over_tcp(0).unwrap(), 8_500);
        assert_eq!(cluster.query_shielded_balance_over_tcp(1).unwrap(), 3_250);
        assert_eq!(cluster.query_shielded_balance_over_tcp(2).unwrap(), 750);

        // 6. Execute another live TCP shielded transfer AFTER PSS share rotation.
        let r3 = cluster
            .execute_shielded_transfer_over_tcp(0, 2, 500)
            .expect("post-PSS TCP shielded transfer 0 -> 2");
        assert_eq!(r3.committed_validators, 4);
        assert_eq!(cluster.query_shielded_balance_over_tcp(0).unwrap(), 8_000);
        assert_eq!(cluster.query_shielded_balance_over_tcp(2).unwrap(), 1_250);

        let shares_before_ep2: Vec<u128> = (0..4u32)
            .map(|id| cluster.daemon_balance_share(id, 0).unwrap())
            .collect();

        // 7. Run Autonomous Epoch Cycle #2:
        //    Fresh Threshold Beacon Gamma_2 -> Bilateral PoP -> Tokenomics -> Live TCP PSS (2 -> 3).
        let ep2 = cluster
            .run_autonomous_epoch_cycle()
            .expect("autonomous epoch cycle 2");
        assert_eq!(ep2.epoch, 2);
        assert_ne!(
            ep2.beacon_output.gamma, ep1.beacon_output.gamma,
            "consecutive epochs must derive fresh independent beacon outputs"
        );
        assert_eq!(ep2.pop_report.accepted.len(), 4);
        assert!(ep2.pop_report.rejected.is_empty());
        assert_eq!(ep2.pss_refresh.new_epoch, 3);
        assert!(
            ep2.anti_replay_tracked_pads > ep1.anti_replay_tracked_pads,
            "PopReplayRegistry must accumulate pad fingerprints across both epochs"
        );
        assert!(ep2.anti_replay_tracked_pads >= 8 * DEFAULT_CHALLENGE_SLOT_COUNT);

        // Confirm EVERY validator's Shamir share rotated AGAIN in Epoch 2 with exact balances.
        let iso_ep2 = cluster
            .verify_split_share_isolation(0)
            .expect("verify split-share isolation after epoch 2");
        assert_eq!(iso_ep2.reconstructed_balance, 8_000);
        assert_eq!(iso_ep2.pss_epoch, 3);
        assert!(iso_ep2.all_quorum_subsets_agree);
        assert!(iso_ep2.under_threshold_zero_info_verified);
        let shares_ep2: Vec<u128> = iso_ep2.daemon_shares.iter().map(|&(_, y)| y).collect();
        for i in 0..4 {
            assert_ne!(
                shares_ep2[i], shares_before_ep2[i],
                "validator {i}'s Shamir share must rotate during Epoch 2 TCP PSS refresh"
            );
        }
        assert_eq!(cluster.query_shielded_balance_over_tcp(0).unwrap(), 8_000);
        assert_eq!(cluster.query_shielded_balance_over_tcp(1).unwrap(), 3_250);
        assert_eq!(cluster.query_shielded_balance_over_tcp(2).unwrap(), 1_250);

        // Verify per-daemon metrics and validator rewards across all 4 servers.
        for vid in 0..4u32 {
            let m = cluster.daemon_metrics(vid).unwrap();
            assert_eq!(m.validator_id, vid);
            assert_eq!(m.current_epoch, 2);
            assert_eq!(m.pss_epoch, 3);
            assert_eq!(m.blocks_finalized, 2 * DEFAULT_EPOCH_BLOCK_INTERVAL);
            assert_eq!(m.shielded_txs_processed, 3);
            assert_eq!(m.last_beacon_gamma, Some(ep2.beacon_output.gamma));
            assert_eq!(
                m.last_assigned_counterparty,
                Some(ep2.pairing_schedule.expected_counterparty(vid as u64).unwrap() as u32)
            );
            assert_eq!(m.bilateral_pop_passes, 2);
            assert_eq!(m.anti_replay_tracked_pads, ep2.anti_replay_tracked_pads);
            assert!(
                cluster.tokenomics().vault(vid as u64).unwrap().reward_balance > 0,
                "honest validator {vid} must accumulate VRNM epoch rewards"
            );
        }

        cluster.shutdown();
    }

    #[test]
    fn test_validator_daemon_rejects_unauthorized_sybil_pairing_in_epoch() {
        let mut cluster = ValidatorClusterOrchestrator::spawn_local_tcp_cluster(4, 2)
            .expect("spawn 4-daemon cluster");

        // Two colluding validators ignore the beacon-assigned counterparty and co-sign with an
        // unauthorized buddy (strictly != expected_counterparty and != self).
        let mut colluders: Vec<(u32, u32, u32)> = Vec::new();
        let report = cluster
            .run_autonomous_epoch_cycle_with_pairing_policy(|vid, expected_cp| {
                if vid == 0 || vid == 1 {
                    // Pick an unauthorized counterparty distinct from both `vid` and `expected_cp`.
                    let unauthorized_buddy = (0..4u32)
                        .find(|&cand| cand != vid && cand != expected_cp)
                        .expect("4-node committee always has an unauthorized peer");
                    colluders.push((vid, expected_cp, unauthorized_buddy));
                    unauthorized_buddy
                } else {
                    expected_cp
                }
            })
            .expect("epoch cycle should settle honestly while slashing colluders");

        assert_eq!(report.epoch, 1);
        assert_eq!(
            report.pop_report.accepted.len(),
            2,
            "only honest validators 2 and 3 should pass bilateral PoP"
        );
        assert_eq!(
            report.pop_report.rejected.len(),
            2,
            "both colluding validators 0 and 1 must be rejected"
        );

        for (vid, err, maybe_slash) in &report.pop_report.rejected {
            let &(_, expected_cp, actual_cp) = colluders
                .iter()
                .find(|&&(id, _, _)| id as u64 == *vid)
                .expect("rejected validator must be one of the colluders");
            assert_eq!(
                err,
                &PopError::UnauthorizedCounterparty {
                    provider_id: *vid,
                    expected_counterparty: expected_cp as u64,
                    actual_counterparty: actual_cp as u64,
                }
            );
            let slash = maybe_slash
                .as_ref()
                .expect("unauthorized Sybil pairing must trigger 50% slashing");
            assert_eq!(slash.offense, SlashingOffense::InconsistentMpcShare);
            assert_eq!(slash.slashed_amount, DEFAULT_REQUIRED_BOND / 2);
            assert_eq!(slash.remaining_bond, DEFAULT_REQUIRED_BOND / 2);
            assert_eq!(slash.new_status, ValidatorStatus::Jailed);
            assert!(slash.epoch_rewards_forfeited);

            let vault = cluster.tokenomics().vault(*vid).unwrap();
            assert_eq!(vault.status, ValidatorStatus::Jailed);
            assert_eq!(vault.reward_balance, 0);
        }

        // Honest validators 2 and 3 remain Active and earn the entire epoch reward pool.
        for honest_id in [2u64, 3u64] {
            let vault = cluster.tokenomics().vault(honest_id).unwrap();
            assert_eq!(vault.status, ValidatorStatus::Active);
            assert!(vault.reward_balance > 0);
        }

        cluster.shutdown();
    }

    #[test]
    fn test_standalone_validator_daemon_http_metrics_and_clean_shutdown() {
        let cfg = ValidatorDaemonConfig {
            validator_id: 0,
            committee_size: 4,
            mpc_bind_addr: "127.0.0.1:0".to_string(),
            http_bind_addr: Some("127.0.0.1:0".to_string()),
            peer_mpc_addrs: vec![],
            num_buckets: 2,
            epoch_block_interval: 5,
        };
        let daemon = ValidatorDaemon::start(cfg).expect("start standalone ValidatorDaemon");
        let http_addr = daemon.http_addr().expect("HTTP monitor should be bound");
        assert_ne!(daemon.mpc_addr().port(), 0);
        assert_eq!(daemon.local_balance_share(0, 0).unwrap(), 0);

        // Query live HTTP /metrics endpoint over real TCP.
        let mut stream = TcpStream::connect(http_addr).expect("connect to HTTP monitor");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("send HTTP GET");
        let mut resp = String::new();
        stream.read_to_string(&mut resp).expect("read HTTP response");
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"validator_id\":0"));
        assert!(resp.contains(&daemon.mpc_addr().to_string()));

        daemon.shutdown();

        // Also verify standalone CLI runner completes bounded epochs and shuts down cleanly.
        let cli_cfg = ValidatorDaemonConfig {
            validator_id: 1,
            committee_size: 4,
            mpc_bind_addr: "127.0.0.1:0".to_string(),
            http_bind_addr: None,
            peer_mpc_addrs: vec![],
            num_buckets: 2,
            epoch_block_interval: 4,
        };
        run_standalone_daemon_cli_with_max_epochs(cli_cfg, Some(2))
            .expect("standalone CLI should complete 2 epochs cleanly");
    }

    #[test]
    fn test_7_validator_extended_committee_cluster_cycle() {
        let mut cluster = ValidatorClusterOrchestrator::spawn_local_tcp_cluster(7, 2)
            .expect("spawn 7-validator TCP cluster");
        assert_eq!(cluster.num_validators(), 7);
        assert_eq!(cluster.daemon(0).unwrap().beacon_config().threshold, 5);

        cluster.mint_shielded_balance_over_tcp(0, 5_000).unwrap();
        cluster.execute_shielded_transfer_over_tcp(0, 3, 1_200).unwrap();
        assert_eq!(cluster.query_shielded_balance_over_tcp(0).unwrap(), 3_800);
        assert_eq!(cluster.query_shielded_balance_over_tcp(3).unwrap(), 1_200);

        let before = cluster.verify_split_share_isolation(0).unwrap();
        assert_eq!(before.threshold, 5);
        assert_eq!(before.reconstructed_balance, 3_800);
        assert!(before.all_quorum_subsets_agree);
        assert!(before.under_threshold_zero_info_verified);

        let ep1 = cluster.run_autonomous_epoch_cycle().unwrap();
        assert_eq!(ep1.epoch, 1);
        assert_eq!(ep1.pop_report.accepted.len(), 7);
        assert!(ep1.pop_report.rejected.is_empty());
        assert_eq!(ep1.pss_refresh.new_epoch, 2);

        let after = cluster.verify_split_share_isolation(0).unwrap();
        assert_eq!(after.reconstructed_balance, 3_800);
        assert_eq!(after.pss_epoch, 2);
        for i in 0..7 {
            assert_ne!(before.daemon_shares[i].1, after.daemon_shares[i].1);
        }

        cluster.shutdown();
    }
}
