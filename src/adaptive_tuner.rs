//! Deterministic Bounded Self-Tuning Protocol Controller for Vernam (VRNM).
//!
//! Provides ASI-proof "recursive adaptability" **without** trusting any AI oracle, off-chain
//! governance multisig, or floating-point heuristic. Every rule is expressed in pure integer
//! and basis-point (`10_000 bps = 100%`) arithmetic with zero floating-point operations so that
//! all BFT validators derive bit-identical next-epoch parameters from finalized telemetry.
//!
//! # Four Deterministic Control Laws
//! 1. **EIP-1559-Style Bounded Fee Tuning**: Express and Shielded lane fees adjust by at most
//!    `±12.5%` (`1_250 bps`) per epoch toward a `50%` (`5_000 bps`) utilization target, strictly
//!    clamped within protocol safety bounds.
//! 2. **Circuit Beaver-Triple Congestion Multiplier & Pool Expansion**: Scales `circuit_triple_fee_vern`
//!    up when `beaver_pool_fill_bps < 3_000`, relaxes when `> 7_000`, and automatically expands
//!    `beaver_pool_target_depth` during sustained drain.
//! 3. **Threat-Responsive PSS Tightening**: Immediately halves/tightens `pss_refresh_interval_secs`
//!    toward `15s` whenever QBER spikes (`>= 500 bps`) or slashing occurs, compressing an
//!    adversary's simultaneous-compromise window, and relaxes slowly back toward baseline only
//!    after consecutive clean epochs.
//! 4. **Hysteresis-Damped BFT Committee Scaling**: Steps smoothly across valid BFT sizes
//!    `4 -> 7 -> 10 -> 13 -> 16` (`N = 3f + 1`) only after `HYSTERESIS_EPOCHS = 3` consecutive
//!    epochs of sustained candidate surplus and load, preventing oscillation/flapping and never
//!    dropping below `4`.

/// Basis-point denominator (`100% = 10_000 bps`).
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Target lane utilization for EIP-1559 fee equilibrium (`50% = 5_000 bps`).
pub const TARGET_UTILIZATION_BPS: u32 = 5_000;

/// Maximum per-epoch fee adjustment (`±12.5% = 1_250 bps`).
pub const MAX_FEE_DELTA_BPS: u32 = 1_250;

/// Express lane fee clamp bounds (in `vern`).
pub const MIN_EXPRESS_FEE_VERN: u64 = 1_000;
pub const MAX_EXPRESS_FEE_VERN: u64 = 1_000_000;
pub const DEFAULT_EXPRESS_FEE_VERN: u64 = 10_000;

/// Shielded lane fee clamp bounds (in `vern`).
pub const MIN_SHIELDED_FEE_VERN: u64 = 50_000;
pub const MAX_SHIELDED_FEE_VERN: u64 = 50_000_000;
pub const DEFAULT_SHIELDED_FEE_VERN: u64 = 250_000;

/// Circuit Beaver-triple fee clamp bounds (in `vern`).
pub const MIN_CIRCUIT_TRIPLE_FEE_VERN: u64 = 500;
pub const MAX_CIRCUIT_TRIPLE_FEE_VERN: u64 = 500_000;
pub const DEFAULT_CIRCUIT_TRIPLE_FEE_VERN: u64 = 5_000;

/// Proactive Secret Sharing (PSS) refresh interval clamp bounds (in seconds).
pub const MIN_PSS_INTERVAL_SECS: u64 = 15;
pub const MAX_PSS_INTERVAL_SECS: u64 = 300;
pub const DEFAULT_PSS_INTERVAL_SECS: u64 = 120;

/// Beaver triple pool target depth clamp bounds.
pub const MIN_BEAVER_POOL_DEPTH: usize = 512;
pub const MAX_BEAVER_POOL_DEPTH: usize = 65_536;
pub const DEFAULT_BEAVER_POOL_DEPTH: usize = 4_096;

/// Beaver pool fill watermarks (in basis points).
pub const BEAVER_LOW_WATERMARK_BPS: u32 = 3_000;
pub const BEAVER_HIGH_WATERMARK_BPS: u32 = 7_000;
pub const BEAVER_CONTRACTION_WATERMARK_BPS: u32 = 8_500;

/// QBER thresholds (in basis points): `500` = 5.00% warning/tighten, `700` = 7.00% danger.
pub const QBER_TIGHTEN_THRESHOLD_BPS: u32 = 500;
pub const QBER_DANGER_THRESHOLD_BPS: u32 = 700;

/// Consecutive clean epochs required before PSS interval begins relaxing toward baseline.
pub const PSS_RECOVERY_CLEAN_EPOCHS: u32 = 5;

/// Consecutive qualifying epochs required before stepping BFT committee size up or down.
pub const HYSTERESIS_EPOCHS: u32 = 3;

/// Valid BFT committee sizes (`N = 3f + 1` for `f = 1..=5`).
pub const VALID_COMMITTEE_SIZES: [usize; 5] = [4, 7, 10, 13, 16];

/// Load thresholds (in bps) for hysteresis-damped committee scaling.
pub const COMMITTEE_SCALE_UP_LOAD_BPS: u32 = 6_500;
pub const COMMITTEE_SCALE_DOWN_LOAD_BPS: u32 = 2_000;

/// Extra verified candidate headroom required above the next committee tier before scaling up.
pub const CANDIDATE_SURPLUS_BUFFER: usize = 2;

/// Protocol parameters controlled deterministically at each epoch boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveParams {
    /// Express lane base fee in `vern`, clamped to `[1_000, 1_000_000]`.
    pub express_fee_vern: u64,
    /// Shielded lane base fee in `vern`, clamped to `[50_000, 50_000_000]`.
    pub shielded_fee_vern: u64,
    /// Per-Beaver-triple circuit fee in `vern`, clamped to `[500, 500_000]`.
    pub circuit_triple_fee_vern: u64,
    /// Proactive Secret Sharing (PSS) refresh cadence in seconds, clamped to `[15, 300]`.
    pub pss_refresh_interval_secs: u64,
    /// Active BFT committee size (`4, 7, 10, 13, or 16`).
    pub target_committee_size: usize,
    /// Target pre-generated Beaver triple pool depth, clamped to `[512, 65_536]`.
    pub beaver_pool_target_depth: usize,
}

impl Default for AdaptiveParams {
    fn default() -> Self {
        Self {
            express_fee_vern: DEFAULT_EXPRESS_FEE_VERN,
            shielded_fee_vern: DEFAULT_SHIELDED_FEE_VERN,
            circuit_triple_fee_vern: DEFAULT_CIRCUIT_TRIPLE_FEE_VERN,
            pss_refresh_interval_secs: DEFAULT_PSS_INTERVAL_SECS,
            target_committee_size: VALID_COMMITTEE_SIZES[0],
            beaver_pool_target_depth: DEFAULT_BEAVER_POOL_DEPTH,
        }
    }
}

impl AdaptiveParams {
    /// Check all hard safety clamps and BFT committee size validity.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        if self.express_fee_vern < MIN_EXPRESS_FEE_VERN
            || self.express_fee_vern > MAX_EXPRESS_FEE_VERN
        {
            return Err("express_fee_vern out of [1_000, 1_000_000] bounds");
        }
        if self.shielded_fee_vern < MIN_SHIELDED_FEE_VERN
            || self.shielded_fee_vern > MAX_SHIELDED_FEE_VERN
        {
            return Err("shielded_fee_vern out of [50_000, 50_000_000] bounds");
        }
        if self.circuit_triple_fee_vern < MIN_CIRCUIT_TRIPLE_FEE_VERN
            || self.circuit_triple_fee_vern > MAX_CIRCUIT_TRIPLE_FEE_VERN
        {
            return Err("circuit_triple_fee_vern out of [500, 500_000] bounds");
        }
        if self.pss_refresh_interval_secs < MIN_PSS_INTERVAL_SECS
            || self.pss_refresh_interval_secs > MAX_PSS_INTERVAL_SECS
        {
            return Err("pss_refresh_interval_secs out of [15, 300] bounds");
        }
        if !VALID_COMMITTEE_SIZES.contains(&self.target_committee_size) {
            return Err("target_committee_size is not a valid BFT tier (4, 7, 10, 13, 16)");
        }
        if self.beaver_pool_target_depth < MIN_BEAVER_POOL_DEPTH
            || self.beaver_pool_target_depth > MAX_BEAVER_POOL_DEPTH
        {
            return Err("beaver_pool_target_depth out of [512, 65_536] bounds");
        }
        Ok(())
    }

    /// Return `(f, t)` BFT fault tolerance and threshold `(f = (N - 1)/3, t = 2f + 1)`
    /// for `target_committee_size`.
    pub const fn bft_parameters(&self) -> (usize, usize) {
        let f = (self.target_committee_size - 1) / 3;
        let t = 2 * f + 1;
        (f, t)
    }
}

/// Deterministic integer telemetry aggregated from finalized blocks and the entropy beacon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochTelemetryInput {
    /// Finalized epoch number.
    pub epoch: u64,
    /// Express lane block utilization in basis points (`0..=10_000`, target `5_000`).
    pub express_utilization_bps: u32,
    /// Shielded lane block utilization in basis points (`0..=10_000`, target `5_000`).
    pub shielded_utilization_bps: u32,
    /// Beaver triple pool fill ratio in basis points (`0..=10_000`, low watermark `< 3_000`).
    pub beaver_pool_fill_bps: u32,
    /// Observed QKD Quantum Bit Error Rate in basis points (e.g., `150` = 1.50%, danger `>= 700`).
    pub observed_qber_bps: u32,
    /// Number of verified PoP candidate validators eligible for committee admission.
    pub verified_candidate_pool: usize,
    /// Number of equivocation or liveness slashing events finalized in this epoch.
    pub slashing_events_in_epoch: u32,
}

/// Deterministic audit report emitted on every `step_epoch` transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveTransitionReport {
    /// Epoch processed by this step.
    pub epoch: u64,
    /// Parameters active before this epoch transition.
    pub previous: AdaptiveParams,
    /// Parameters computed for the next epoch.
    pub updated: AdaptiveParams,
    /// True if a QBER warning (`>= 500 bps`) or slashing event triggered defensive tightening.
    pub threat_alert: bool,
    /// True if QBER reached critical danger (`>= 700 bps`).
    pub critical_qber_alert: bool,
    /// True if `pss_refresh_interval_secs` decreased this epoch.
    pub pss_tightened: bool,
    /// True if `pss_refresh_interval_secs` relaxed toward baseline this epoch.
    pub pss_relaxed: bool,
    /// Committee tier delta: `+1` scaled up, `-1` scaled down, `0` unchanged.
    pub committee_scaled: i8,
    /// Current consecutive clean-epoch streak for PSS recovery.
    pub clean_epoch_streak: u32,
    /// Current consecutive scale-up hysteresis streak.
    pub scale_up_streak: u32,
    /// Current consecutive scale-down hysteresis streak.
    pub scale_down_streak: u32,
}

/// Pure-integer, deterministic bounded protocol parameter controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveProtocolController {
    params: AdaptiveParams,
    baseline_pss_interval_secs: u64,
    clean_epoch_streak: u32,
    scale_up_streak: u32,
    scale_down_streak: u32,
    last_epoch: Option<u64>,
}

impl Default for AdaptiveProtocolController {
    fn default() -> Self {
        let params = AdaptiveParams::default();
        Self {
            baseline_pss_interval_secs: params.pss_refresh_interval_secs,
            params,
            clean_epoch_streak: 0,
            scale_up_streak: 0,
            scale_down_streak: 0,
            last_epoch: None,
        }
    }
}

impl AdaptiveProtocolController {
    /// Create a controller with custom initial parameters (validated against all hard clamps).
    pub fn new(initial: AdaptiveParams) -> Result<Self, &'static str> {
        initial.check_invariants()?;
        Ok(Self {
            baseline_pss_interval_secs: initial.pss_refresh_interval_secs,
            params: initial,
            clean_epoch_streak: 0,
            scale_up_streak: 0,
            scale_down_streak: 0,
            last_epoch: None,
        })
    }

    /// Access the currently active protocol parameters.
    #[inline]
    pub const fn params(&self) -> &AdaptiveParams {
        &self.params
    }

    /// Access the configured baseline PSS refresh interval (in seconds).
    #[inline]
    pub const fn baseline_pss_interval_secs(&self) -> u64 {
        self.baseline_pss_interval_secs
    }

    /// Access the last processed epoch, if any.
    #[inline]
    pub const fn last_epoch(&self) -> Option<u64> {
        self.last_epoch
    }

    /// Verify all hard safety bounds and BFT invariants on the controller state.
    pub fn check_bounds_invariants(&self) -> Result<(), &'static str> {
        self.params.check_invariants()?;
        if self.baseline_pss_interval_secs < MIN_PSS_INTERVAL_SECS
            || self.baseline_pss_interval_secs > MAX_PSS_INTERVAL_SECS
        {
            return Err("baseline_pss_interval_secs out of [15, 300] bounds");
        }
        Ok(())
    }

    /// Advance the controller by one finalized epoch using pure deterministic integer math.
    pub fn step_epoch(&mut self, telemetry: &EpochTelemetryInput) -> AdaptiveTransitionReport {
        let previous = self.params;

        // Defensively saturate basis-point inputs at 10_000 so adversarial telemetry cannot
        // ever push per-epoch fee changes outside ±12.5% or overflow intermediate math.
        let express_util = telemetry.express_utilization_bps.min(BPS_DENOMINATOR);
        let shielded_util = telemetry.shielded_utilization_bps.min(BPS_DENOMINATOR);
        let beaver_fill = telemetry.beaver_pool_fill_bps.min(BPS_DENOMINATOR);

        // 1. EIP-1559-style bounded fee tuning (±12.5% max delta toward 50% target utilization).
        let express_fee_vern = tune_eip1559_fee(
            previous.express_fee_vern,
            express_util,
            MIN_EXPRESS_FEE_VERN,
            MAX_EXPRESS_FEE_VERN,
        );
        let shielded_fee_vern = tune_eip1559_fee(
            previous.shielded_fee_vern,
            shielded_util,
            MIN_SHIELDED_FEE_VERN,
            MAX_SHIELDED_FEE_VERN,
        );

        // 2. Circuit Beaver-triple congestion multiplier & pool depth auto-expansion.
        let circuit_triple_fee_vern = tune_beaver_triple_fee(
            previous.circuit_triple_fee_vern,
            beaver_fill,
            MIN_CIRCUIT_TRIPLE_FEE_VERN,
            MAX_CIRCUIT_TRIPLE_FEE_VERN,
        );
        let beaver_pool_target_depth = tune_beaver_pool_depth(
            previous.beaver_pool_target_depth,
            beaver_fill,
            shielded_util,
        );

        // 3. Threat-responsive PSS tightening & slow clean-epoch recovery.
        let critical_qber_alert = telemetry.observed_qber_bps >= QBER_DANGER_THRESHOLD_BPS;
        let threat_alert = telemetry.observed_qber_bps >= QBER_TIGHTEN_THRESHOLD_BPS
            || telemetry.slashing_events_in_epoch > 0;

        let pss_refresh_interval_secs = if threat_alert {
            self.clean_epoch_streak = 0;
            let severe = critical_qber_alert || telemetry.slashing_events_in_epoch >= 2;
            let divisor: u64 = if severe { 3 } else { 2 };
            (previous.pss_refresh_interval_secs / divisor).max(MIN_PSS_INTERVAL_SECS)
        } else {
            self.clean_epoch_streak = self.clean_epoch_streak.saturating_add(1);
            if self.clean_epoch_streak >= PSS_RECOVERY_CLEAN_EPOCHS
                && previous.pss_refresh_interval_secs < self.baseline_pss_interval_secs
            {
                // Slow asymmetric recovery: +12.5% clamped to [5s, 15s] per epoch, never above baseline.
                let step = (previous.pss_refresh_interval_secs / 8).clamp(5, 15);
                previous
                    .pss_refresh_interval_secs
                    .saturating_add(step)
                    .min(self.baseline_pss_interval_secs)
                    .min(MAX_PSS_INTERVAL_SECS)
            } else {
                previous.pss_refresh_interval_secs
            }
        };

        let pss_tightened = pss_refresh_interval_secs < previous.pss_refresh_interval_secs;
        let pss_relaxed = pss_refresh_interval_secs > previous.pss_refresh_interval_secs;

        // 4. Hysteresis-damped BFT committee scaling (4 -> 7 -> 10 -> 13 -> 16).
        let (target_committee_size, committee_scaled) = self.step_committee_size(
            previous.target_committee_size,
            express_util,
            shielded_util,
            telemetry.verified_candidate_pool,
            telemetry.slashing_events_in_epoch,
        );

        let updated = AdaptiveParams {
            express_fee_vern,
            shielded_fee_vern,
            circuit_triple_fee_vern,
            pss_refresh_interval_secs,
            target_committee_size,
            beaver_pool_target_depth,
        };

        self.params = updated;
        self.last_epoch = Some(telemetry.epoch);

        debug_assert!(self.check_bounds_invariants().is_ok());

        AdaptiveTransitionReport {
            epoch: telemetry.epoch,
            previous,
            updated,
            threat_alert,
            critical_qber_alert,
            pss_tightened,
            pss_relaxed,
            committee_scaled,
            clean_epoch_streak: self.clean_epoch_streak,
            scale_up_streak: self.scale_up_streak,
            scale_down_streak: self.scale_down_streak,
        }
    }

    fn step_committee_size(
        &mut self,
        current_size: usize,
        express_util: u32,
        shielded_util: u32,
        verified_candidate_pool: usize,
        slashing_events: u32,
    ) -> (usize, i8) {
        let tier_idx = VALID_COMMITTEE_SIZES
            .iter()
            .position(|&s| s == current_size)
            .unwrap_or(0);

        let high_load = express_util >= COMMITTEE_SCALE_UP_LOAD_BPS
            || shielded_util >= COMMITTEE_SCALE_UP_LOAD_BPS;
        let low_load = express_util <= COMMITTEE_SCALE_DOWN_LOAD_BPS
            && shielded_util <= COMMITTEE_SCALE_DOWN_LOAD_BPS;

        let can_scale_up = tier_idx + 1 < VALID_COMMITTEE_SIZES.len() && {
            let next_size = VALID_COMMITTEE_SIZES[tier_idx + 1];
            let required_candidates = next_size.saturating_add(CANDIDATE_SURPLUS_BUFFER);
            high_load && verified_candidate_pool >= required_candidates && slashing_events == 0
        };

        let should_scale_down = tier_idx > 0
            && (low_load || verified_candidate_pool < current_size);

        if can_scale_up {
            self.scale_up_streak = self.scale_up_streak.saturating_add(1);
            self.scale_down_streak = 0;
            if self.scale_up_streak >= HYSTERESIS_EPOCHS {
                self.scale_up_streak = 0;
                return (VALID_COMMITTEE_SIZES[tier_idx + 1], 1);
            }
        } else if should_scale_down {
            self.scale_down_streak = self.scale_down_streak.saturating_add(1);
            self.scale_up_streak = 0;
            if self.scale_down_streak >= HYSTERESIS_EPOCHS {
                self.scale_down_streak = 0;
                return (VALID_COMMITTEE_SIZES[tier_idx - 1], -1);
            }
        } else {
            // Deadband or mixed conditions reset both streaks to prevent oscillation/flapping.
            self.scale_up_streak = 0;
            self.scale_down_streak = 0;
        }

        (VALID_COMMITTEE_SIZES[tier_idx], 0)
    }
}

/// Pure integer EIP-1559-style fee update bounded to `±12.5%` (`MAX_FEE_DELTA_BPS = 1_250`)
/// per epoch and strictly clamped to `[min_fee, max_fee]`.
fn tune_eip1559_fee(current_fee: u64, util_bps: u32, min_fee: u64, max_fee: u64) -> u64 {
    let cur = current_fee as u128;
    let bps_den = BPS_DENOMINATOR as u128;
    let target = TARGET_UTILIZATION_BPS as u128;
    let max_delta_bps = MAX_FEE_DELTA_BPS as u128;

    let max_step = (cur * max_delta_bps) / bps_den;

    let next = if util_bps > TARGET_UTILIZATION_BPS {
        let excess = (util_bps - TARGET_UTILIZATION_BPS) as u128;
        let delta_bps = (excess * max_delta_bps) / target;
        let delta = if delta_bps > 0 {
            ((cur * delta_bps) / bps_den).max(1).min(max_step.max(1))
        } else {
            0
        };
        cur.saturating_add(delta)
    } else if util_bps < TARGET_UTILIZATION_BPS {
        let deficit = (TARGET_UTILIZATION_BPS - util_bps) as u128;
        let delta_bps = (deficit * max_delta_bps) / target;
        let delta = if delta_bps > 0 {
            ((cur * delta_bps) / bps_den).max(1).min(max_step.max(1))
        } else {
            0
        };
        cur.saturating_sub(delta)
    } else {
        cur
    };

    next.clamp(min_fee as u128, max_fee as u128) as u64
}

/// Pure integer Beaver-triple congestion fee multiplier: scales up when pool fill `< 3_000 bps`,
/// relaxes when fill `> 7_000 bps`, and holds steady inside the `[3_000, 7_000]` deadband.
fn tune_beaver_triple_fee(current_fee: u64, fill_bps: u32, min_fee: u64, max_fee: u64) -> u64 {
    let cur = current_fee as u128;
    let bps_den = BPS_DENOMINATOR as u128;
    let max_delta_bps = MAX_FEE_DELTA_BPS as u128;
    let max_step = (cur * max_delta_bps) / bps_den;

    let next = if fill_bps < BEAVER_LOW_WATERMARK_BPS {
        let scarcity = (BEAVER_LOW_WATERMARK_BPS - fill_bps) as u128;
        let span = BEAVER_LOW_WATERMARK_BPS as u128;
        let delta_bps = (scarcity * max_delta_bps) / span;
        let delta = if delta_bps > 0 {
            ((cur * delta_bps) / bps_den).max(1).min(max_step.max(1))
        } else {
            0
        };
        cur.saturating_add(delta)
    } else if fill_bps > BEAVER_HIGH_WATERMARK_BPS {
        let surplus = (fill_bps - BEAVER_HIGH_WATERMARK_BPS) as u128;
        let span = (BPS_DENOMINATOR - BEAVER_HIGH_WATERMARK_BPS) as u128;
        let delta_bps = (surplus * max_delta_bps) / span;
        let delta = if delta_bps > 0 {
            ((cur * delta_bps) / bps_den).max(1).min(max_step.max(1))
        } else {
            0
        };
        cur.saturating_sub(delta)
    } else {
        cur
    };

    next.clamp(min_fee as u128, max_fee as u128) as u64
}

/// Auto-expand `beaver_pool_target_depth` when the pool drains below `3_000 bps`, and gently
/// contract when over-provisioned (`> 8_500 bps`) during low Shielded lane demand.
fn tune_beaver_pool_depth(current_depth: usize, fill_bps: u32, shielded_util_bps: u32) -> usize {
    let next = if fill_bps < BEAVER_LOW_WATERMARK_BPS {
        let grow = (current_depth / 8).max(64);
        current_depth.saturating_add(grow)
    } else if fill_bps > BEAVER_CONTRACTION_WATERMARK_BPS && shielded_util_bps < 3_000 {
        let shrink = (current_depth / 16).max(32);
        current_depth.saturating_sub(shrink)
    } else {
        current_depth
    };

    next.clamp(MIN_BEAVER_POOL_DEPTH, MAX_BEAVER_POOL_DEPTH)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DetRng(u64);
    impl DetRng {
        fn new(seed: u64) -> Self {
            Self(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    fn base_telemetry(epoch: u64) -> EpochTelemetryInput {
        EpochTelemetryInput {
            epoch,
            express_utilization_bps: TARGET_UTILIZATION_BPS,
            shielded_utilization_bps: TARGET_UTILIZATION_BPS,
            beaver_pool_fill_bps: 5_000,
            observed_qber_bps: 150,
            verified_candidate_pool: 6,
            slashing_events_in_epoch: 0,
        }
    }

    #[test]
    fn test_adaptive_fees_converge_under_congestion_and_relax_when_idle() {
        let mut ctrl = AdaptiveProtocolController::default();
        let initial_express = ctrl.params().express_fee_vern;
        let initial_shielded = ctrl.params().shielded_fee_vern;
        let initial_triple = ctrl.params().circuit_triple_fee_vern;
        let initial_depth = ctrl.params().beaver_pool_target_depth;

        // 1. Sustained 100% congestion + drained Beaver pool: fees climb by exact <= 12.5%/epoch
        //    and Beaver pool target depth expands automatically.
        for epoch in 1..=60 {
            let prev = *ctrl.params();
            let t = EpochTelemetryInput {
                epoch,
                express_utilization_bps: 10_000,
                shielded_utilization_bps: 10_000,
                beaver_pool_fill_bps: 500,
                observed_qber_bps: 120,
                verified_candidate_pool: 4,
                slashing_events_in_epoch: 0,
            };
            let report = ctrl.step_epoch(&t);
            ctrl.check_bounds_invariants().unwrap();

            assert!(report.updated.express_fee_vern >= prev.express_fee_vern);
            assert!(
                report.updated.express_fee_vern - prev.express_fee_vern
                    <= (prev.express_fee_vern * MAX_FEE_DELTA_BPS as u64) / BPS_DENOMINATOR as u64
            );
            assert!(report.updated.shielded_fee_vern >= prev.shielded_fee_vern);
            assert!(
                report.updated.shielded_fee_vern - prev.shielded_fee_vern
                    <= (prev.shielded_fee_vern * MAX_FEE_DELTA_BPS as u64) / BPS_DENOMINATOR as u64
            );
            assert!(report.updated.circuit_triple_fee_vern >= prev.circuit_triple_fee_vern);
            assert!(report.updated.beaver_pool_target_depth >= prev.beaver_pool_target_depth);
        }

        assert_eq!(ctrl.params().express_fee_vern, MAX_EXPRESS_FEE_VERN);
        assert_eq!(ctrl.params().shielded_fee_vern, MAX_SHIELDED_FEE_VERN);
        assert_eq!(ctrl.params().circuit_triple_fee_vern, MAX_CIRCUIT_TRIPLE_FEE_VERN);
        assert_eq!(ctrl.params().beaver_pool_target_depth, MAX_BEAVER_POOL_DEPTH);
        assert!(ctrl.params().express_fee_vern > initial_express);
        assert!(ctrl.params().shielded_fee_vern > initial_shielded);
        assert!(ctrl.params().circuit_triple_fee_vern > initial_triple);
        assert!(ctrl.params().beaver_pool_target_depth > initial_depth);

        // 2. Sustained idle network + full Beaver pool: fees relax smoothly back to hard floors.
        for epoch in 61..=160 {
            let prev = *ctrl.params();
            let t = EpochTelemetryInput {
                epoch,
                express_utilization_bps: 0,
                shielded_utilization_bps: 0,
                beaver_pool_fill_bps: 10_000,
                observed_qber_bps: 100,
                verified_candidate_pool: 4,
                slashing_events_in_epoch: 0,
            };
            let report = ctrl.step_epoch(&t);
            ctrl.check_bounds_invariants().unwrap();

            assert!(report.updated.express_fee_vern <= prev.express_fee_vern);
            assert!(
                prev.express_fee_vern - report.updated.express_fee_vern
                    <= (prev.express_fee_vern * MAX_FEE_DELTA_BPS as u64) / BPS_DENOMINATOR as u64
            );
            assert!(report.updated.shielded_fee_vern <= prev.shielded_fee_vern);
            assert!(report.updated.circuit_triple_fee_vern <= prev.circuit_triple_fee_vern);
            assert!(report.updated.beaver_pool_target_depth <= prev.beaver_pool_target_depth);
        }

        assert_eq!(ctrl.params().express_fee_vern, MIN_EXPRESS_FEE_VERN);
        assert_eq!(ctrl.params().shielded_fee_vern, MIN_SHIELDED_FEE_VERN);
        assert_eq!(ctrl.params().circuit_triple_fee_vern, MIN_CIRCUIT_TRIPLE_FEE_VERN);
        assert_eq!(ctrl.params().beaver_pool_target_depth, MIN_BEAVER_POOL_DEPTH);

        // 3. Exact equilibrium at 50% utilization & 50% Beaver pool fill yields zero drift.
        let snapshot = *ctrl.params();
        let eq_report = ctrl.step_epoch(&base_telemetry(161));
        assert_eq!(eq_report.updated, snapshot);
    }

    #[test]
    fn test_threat_responsive_pss_tightens_on_qber_spike_or_slashing_and_recovers_slowly() {
        let mut ctrl = AdaptiveProtocolController::default();
        assert_eq!(ctrl.params().pss_refresh_interval_secs, DEFAULT_PSS_INTERVAL_SECS);

        // Moderate QBER spike (5.50% = 550 bps) halves PSS interval: 120 -> 60s.
        let mut t = base_telemetry(1);
        t.observed_qber_bps = 550;
        let r1 = ctrl.step_epoch(&t);
        assert!(r1.threat_alert);
        assert!(!r1.critical_qber_alert);
        assert!(r1.pss_tightened);
        assert_eq!(r1.updated.pss_refresh_interval_secs, 60);

        // Slashing event tightens further: 60 -> 30s.
        let mut t2 = base_telemetry(2);
        t2.slashing_events_in_epoch = 1;
        let r2 = ctrl.step_epoch(&t2);
        assert!(r2.threat_alert);
        assert!(r2.pss_tightened);
        assert_eq!(r2.updated.pss_refresh_interval_secs, 30);

        // Critical QBER danger (>= 700 bps) snaps down to hard floor 15s.
        let mut t3 = base_telemetry(3);
        t3.observed_qber_bps = 750;
        let r3 = ctrl.step_epoch(&t3);
        assert!(r3.threat_alert);
        assert!(r3.critical_qber_alert);
        assert_eq!(r3.updated.pss_refresh_interval_secs, MIN_PSS_INTERVAL_SECS);

        // First (PSS_RECOVERY_CLEAN_EPOCHS - 1) clean epochs MUST NOT relax yet.
        for e in 4..4 + (PSS_RECOVERY_CLEAN_EPOCHS as u64 - 1) {
            let r = ctrl.step_epoch(&base_telemetry(e));
            assert!(!r.threat_alert);
            assert!(!r.pss_relaxed);
            assert_eq!(r.updated.pss_refresh_interval_secs, MIN_PSS_INTERVAL_SECS);
        }

        // The 5th consecutive clean epoch begins slow relaxation (+5s: 15 -> 20s).
        let r_start = ctrl.step_epoch(&base_telemetry(8));
        assert!(r_start.pss_relaxed);
        assert_eq!(r_start.updated.pss_refresh_interval_secs, 20);

        // A single slashing event immediately cancels recovery and drops back to 15s.
        let mut relapse = base_telemetry(9);
        relapse.slashing_events_in_epoch = 1;
        let r_relapse = ctrl.step_epoch(&relapse);
        assert!(r_relapse.pss_tightened);
        assert_eq!(r_relapse.clean_epoch_streak, 0);
        assert_eq!(r_relapse.updated.pss_refresh_interval_secs, MIN_PSS_INTERVAL_SECS);

        // Sustained clean epochs eventually recover all the way back to baseline (120s), never higher.
        for e in 10..60 {
            let _ = ctrl.step_epoch(&base_telemetry(e));
            assert!(ctrl.params().pss_refresh_interval_secs <= DEFAULT_PSS_INTERVAL_SECS);
        }
        assert_eq!(
            ctrl.params().pss_refresh_interval_secs,
            DEFAULT_PSS_INTERVAL_SECS
        );
    }

    #[test]
    fn test_committee_scaling_hysteresis_prevents_oscillation_and_stays_bft_valid() {
        let mut ctrl = AdaptiveProtocolController::default();
        assert_eq!(ctrl.params().target_committee_size, 4);
        assert_eq!(ctrl.params().bft_parameters(), (1, 3));

        // 1. Alternating high/low load epochs (flapping attack) MUST NEVER scale committee.
        for epoch in 1..=20 {
            let high = epoch % 2 == 1;
            let t = EpochTelemetryInput {
                epoch,
                express_utilization_bps: if high { 9_000 } else { 1_000 },
                shielded_utilization_bps: if high { 9_000 } else { 1_000 },
                beaver_pool_fill_bps: 5_000,
                observed_qber_bps: 100,
                verified_candidate_pool: 25,
                slashing_events_in_epoch: 0,
            };
            let report = ctrl.step_epoch(&t);
            assert_eq!(report.committee_scaled, 0);
            assert_eq!(report.updated.target_committee_size, 4);
        }

        // 2. Sustained high load + candidate surplus scales through every BFT tier:
        //    4 -> 7 -> 10 -> 13 -> 16, taking exactly HYSTERESIS_EPOCHS = 3 epochs per step.
        let mut epoch = 21u64;
        for &expected_size in &VALID_COMMITTEE_SIZES[1..] {
            for step in 1..=HYSTERESIS_EPOCHS {
                let t = EpochTelemetryInput {
                    epoch,
                    express_utilization_bps: 8_500,
                    shielded_utilization_bps: 7_500,
                    beaver_pool_fill_bps: 5_000,
                    observed_qber_bps: 120,
                    verified_candidate_pool: 20,
                    slashing_events_in_epoch: 0,
                };
                let report = ctrl.step_epoch(&t);
                if step < HYSTERESIS_EPOCHS {
                    assert_eq!(report.committee_scaled, 0);
                } else {
                    assert_eq!(report.committee_scaled, 1);
                    assert_eq!(report.updated.target_committee_size, expected_size);
                }
                assert!(VALID_COMMITTEE_SIZES.contains(&report.updated.target_committee_size));
                let (f, threshold) = report.updated.bft_parameters();
                assert_eq!(3 * f + 1, report.updated.target_committee_size);
                assert_eq!(threshold, 2 * f + 1);
                epoch += 1;
            }
        }
        assert_eq!(ctrl.params().target_committee_size, 16);

        // 3. Sustained low load scales smoothly back down to 4 and NEVER drops below 4.
        for _ in 0..25 {
            let t = EpochTelemetryInput {
                epoch,
                express_utilization_bps: 500,
                shielded_utilization_bps: 500,
                beaver_pool_fill_bps: 5_000,
                observed_qber_bps: 100,
                verified_candidate_pool: 0,
                slashing_events_in_epoch: 0,
            };
            let report = ctrl.step_epoch(&t);
            assert!(VALID_COMMITTEE_SIZES.contains(&report.updated.target_committee_size));
            assert!(report.updated.target_committee_size >= 4);
            epoch += 1;
        }
        assert_eq!(ctrl.params().target_committee_size, 4);
    }

    #[test]
    fn test_deterministic_500_epoch_adversarial_fuzz_never_violates_clamps_or_overflows() {
        let mut ctrl_a = AdaptiveProtocolController::default();
        let mut ctrl_b = AdaptiveProtocolController::default();
        let mut rng = DetRng::new(0xADAF_710E_5000_0001);

        // Also test constructor rejects out-of-bounds configs.
        let mut bad = AdaptiveParams::default();
        bad.target_committee_size = 5;
        assert!(AdaptiveProtocolController::new(bad).is_err());

        for epoch in 1..=500u64 {
            // Mix extreme boundary/overflow-bait values with pseudo-random adversarial inputs.
            let t = match epoch % 10 {
                0 => EpochTelemetryInput {
                    epoch: u64::MAX,
                    express_utilization_bps: u32::MAX,
                    shielded_utilization_bps: u32::MAX,
                    beaver_pool_fill_bps: u32::MAX,
                    observed_qber_bps: u32::MAX,
                    verified_candidate_pool: usize::MAX,
                    slashing_events_in_epoch: u32::MAX,
                },
                1 => EpochTelemetryInput {
                    epoch,
                    express_utilization_bps: 0,
                    shielded_utilization_bps: 0,
                    beaver_pool_fill_bps: 0,
                    observed_qber_bps: 0,
                    verified_candidate_pool: 0,
                    slashing_events_in_epoch: 0,
                },
                _ => EpochTelemetryInput {
                    epoch,
                    express_utilization_bps: (rng.next_u64() % 12_000) as u32,
                    shielded_utilization_bps: (rng.next_u64() % 12_000) as u32,
                    beaver_pool_fill_bps: (rng.next_u64() % 12_000) as u32,
                    observed_qber_bps: (rng.next_u64() % 1_200) as u32,
                    verified_candidate_pool: (rng.next_u64() % 30) as usize,
                    slashing_events_in_epoch: (rng.next_u64() % 4) as u32,
                },
            };

            let prev = *ctrl_a.params();
            let rep_a = ctrl_a.step_epoch(&t);
            let rep_b = ctrl_b.step_epoch(&t);

            // Exact bit-for-bit BFT determinism across independent controller instances.
            assert_eq!(rep_a, rep_b);
            assert_eq!(ctrl_a, ctrl_b);

            // Hard safety clamps & BFT committee invariants must hold on every single epoch.
            ctrl_a.check_bounds_invariants().unwrap();

            // Per-epoch EIP-1559 fee delta must NEVER exceed ±12.5% of previous fee.
            let max_exp_delta =
                (prev.express_fee_vern * MAX_FEE_DELTA_BPS as u64) / BPS_DENOMINATOR as u64;
            let max_shd_delta =
                (prev.shielded_fee_vern * MAX_FEE_DELTA_BPS as u64) / BPS_DENOMINATOR as u64;
            let max_trp_delta =
                (prev.circuit_triple_fee_vern * MAX_FEE_DELTA_BPS as u64) / BPS_DENOMINATOR as u64;

            assert!(rep_a.updated.express_fee_vern.abs_diff(prev.express_fee_vern) <= max_exp_delta);
            assert!(
                rep_a
                    .updated
                    .shielded_fee_vern
                    .abs_diff(prev.shielded_fee_vern)
                    <= max_shd_delta
            );
            assert!(
                rep_a
                    .updated
                    .circuit_triple_fee_vern
                    .abs_diff(prev.circuit_triple_fee_vern)
                    <= max_trp_delta
            );
        }
    }
}
