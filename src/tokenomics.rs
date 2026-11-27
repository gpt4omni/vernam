//! Vernam (VRNM) Proof-of-Pad (PoP) Tokenomics, Pad-Burn Fee Model & Validator Slashing.
//!
//! Zero external crates, zero computational cryptography (no SHA-256/RSA/ECDSA/AES).
//! All settlement and slashing audit tags use information-theoretic Carter-Wegman
//! polynomial MACs over the Mersenne prime field F_(2^127 - 1) from `crate::field`.
//!
//! # Core Economic Invariants
//! - **Hard Supply Cap**: `total_minted <= MAX_SUPPLY` (`21_000_000 VRNM`, `1 VRNM = 10^8 vern`).
//! - **Exact Conservation**: `circulating_supply + total_burned == total_minted`.
//! - **Sub-Ledger Balance**: `liquid_supply + total_bonded + pending_fee_rewards + total_validator_rewards == circulating_supply`.
//! - **Anti-Plutocracy**: Every active validator posts the exact same flat bond (`1 seat = 1 vote`);
//!   epoch rewards pay equal honest participation plus capped verified entropy/MPC availability,
//!   never stake-compounding wealth.

use std::collections::BTreeMap;
use std::fmt;

use crate::field::{PRIME_P, add_mod, ct_eq_16, mul_mod, random_field_elem, zeroize_u128};

/// Base unit subdivision: `1 VRNM = 100_000_000 vern` (8 decimal places).
pub const VERN_PER_VRNM: u64 = 100_000_000;

/// Absolute hard supply cap: 21,000,000 VRNM (`2_100_000_000_000_000 vern`).
pub const MAX_SUPPLY: u64 = 21_000_000 * VERN_PER_VRNM;

/// Number of epochs per halving era (210,000 epochs).
pub const EPOCHS_PER_HALVING: u64 = 210_000;

/// Initial epoch block subsidy: 50 VRNM (`5_000_000_000 vern`).
///
/// Exact geometric sum over all halving eras:
/// `sum_{h=0..64} (INITIAL_EPOCH_REWARD >> h) * EPOCHS_PER_HALVING < MAX_SUPPLY`.
pub const INITIAL_EPOCH_REWARD: u64 = 50 * VERN_PER_VRNM;

/// Basis-point denominator (100% = 10,000 bps).
pub const BPS_DENOMINATOR: u16 = 10_000;

/// Default fee burn ratio: 20% permanently burned (`2_000` bps), 80% distributed to validators.
pub const DEFAULT_FEE_BURN_BPS: u16 = 2_000;

/// Default flat validator bond: 10,000 VRNM per seat (equal for all validators).
pub const DEFAULT_REQUIRED_BOND: u64 = 10_000 * VERN_PER_VRNM;

/// Express lane OTP frame size in bytes (256 B).
pub const EXPRESS_FRAME_BYTES: u32 = 256;

/// Shielded lane OTP frame size in bytes (4096 B).
pub const SHIELDED_FRAME_BYTES: u32 = 4_096;

/// Default Beaver triples consumed per Shielded lane transaction.
pub const SHIELDED_BEAVER_TRIPLES: u32 = 16;

/// Default Express lane base fee: 0.0001 VRNM (`10_000 vern`).
pub const DEFAULT_EXPRESS_FEE: u64 = 10_000;

/// Default Shielded lane base fee: 0.0025 VRNM (`250_000 vern`).
pub const DEFAULT_SHIELDED_FEE: u64 = 250_000;

/// Default equal honest participation share of Proof-of-Pad epoch rewards (70%).
pub const DEFAULT_EQUAL_PARTICIPATION_BPS: u16 = 7_000;

/// Default per-validator cap on entropy availability score (anti-monopoly ceiling).
pub const DEFAULT_MAX_ENTROPY_SCORE_CAP: u64 = 1_000;

/// Unique validator identifier.
pub type ValidatorId = u64;

/// 128-bit information-theoretic Carter-Wegman MAC tag over F_(2^127 - 1).
pub type AuditTag = [u8; 16];

/// Deterministic halving epoch issuance in `vern`.
///
/// Guaranteed across all epochs `0..u64::MAX` that the cumulative sum never exceeds `MAX_SUPPLY`.
#[inline]
pub const fn epoch_reward(epoch: u64) -> u64 {
    let halvings = epoch / EPOCHS_PER_HALVING;
    if halvings >= 64 {
        0
    } else {
        INITIAL_EPOCH_REWARD >> halvings
    }
}

/// Exact total issuance across all halving eras under the canonical schedule.
pub const fn total_scheduled_issuance() -> u64 {
    let mut total: u64 = 0;
    let mut era: u64 = 0;
    while era < 64 {
        let per_epoch = INITIAL_EPOCH_REWARD >> era;
        if per_epoch == 0 {
            break;
        }
        total += per_epoch * EPOCHS_PER_HALVING;
        era += 1;
    }
    total
}

/// Errors returned by the Vernam tokenomics engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenomicsError {
    /// Invalid configuration parameter.
    InvalidConfig(&'static str),
    /// Minting would exceed `MAX_SUPPLY`.
    SupplyCapExceeded,
    /// Validator already registered.
    ValidatorAlreadyExists(ValidatorId),
    /// Validator not found in vault registry.
    ValidatorNotFound(ValidatorId),
    /// Flat equal-bond rule violated (bond must equal `config.required_bond`).
    InvalidBondAmount { expected: u64, provided: u64 },
    /// Validator was permanently ejected (e.g., due to equivocation).
    ValidatorEjected(ValidatorId),
    /// Validator cannot be activated without holding the full required flat bond.
    InsufficientBond { required: u64, actual: u64 },
    /// Not enough liquid/circulating supply to fund bond or fee burn.
    InsufficientLiquidSupply { required: u64, available: u64 },
    /// Attempted to slash a validator that has already been ejected with zero bond.
    AlreadyEjected(ValidatorId),
    /// Internal accounting invariant failure.
    InvariantViolation(&'static str),
}

impl fmt::Display for TokenomicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid tokenomics config: {msg}"),
            Self::SupplyCapExceeded => write!(f, "minting would exceed MAX_SUPPLY ({MAX_SUPPLY} vern)"),
            Self::ValidatorAlreadyExists(id) => write!(f, "validator {id} already registered"),
            Self::ValidatorNotFound(id) => write!(f, "validator {id} not found"),
            Self::InvalidBondAmount { expected, provided } => {
                write!(f, "flat bond mismatch: expected {expected} vern, got {provided} vern")
            }
            Self::ValidatorEjected(id) => write!(f, "validator {id} is permanently ejected"),
            Self::InsufficientBond { required, actual } => {
                write!(f, "insufficient bond: required {required} vern, actual {actual} vern")
            }
            Self::InsufficientLiquidSupply { required, available } => {
                write!(f, "insufficient liquid supply: required {required} vern, available {available} vern")
            }
            Self::AlreadyEjected(id) => write!(f, "validator {id} is already ejected"),
            Self::InvariantViolation(msg) => write!(f, "accounting invariant violated: {msg}"),
        }
    }
}

impl std::error::Error for TokenomicsError {}

/// Pad-Burn transaction fee lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeLane {
    /// Low-fee lane: 256-byte OTP frame, no MPC Beaver triples or shielded bucket.
    Express,
    /// Shielded privacy lane: 4096-byte OTP frame + Beaver triples + MPC anonymity bucket.
    Shielded,
}

/// Fee schedule & burn configuration for Express and Shielded lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSchedule {
    /// Base fee in `vern` for an Express lane transaction (256B OTP frame).
    pub express_fee: u64,
    /// Base fee in `vern` for a Shielded lane transaction (4096B frames + Beaver triples + MPC bucket).
    pub shielded_fee: u64,
    /// Fraction of every fee permanently burned, in basis points (default 2,000 = 20%).
    /// The remaining `10_000 - burn_bps` (default 80%) is distributed to active honest validators.
    pub burn_bps: u16,
    /// Beaver triples consumed by a Shielded lane transaction.
    pub shielded_beaver_triples: u32,
}

impl Default for FeeSchedule {
    fn default() -> Self {
        Self {
            express_fee: DEFAULT_EXPRESS_FEE,
            shielded_fee: DEFAULT_SHIELDED_FEE,
            burn_bps: DEFAULT_FEE_BURN_BPS,
            shielded_beaver_triples: SHIELDED_BEAVER_TRIPLES,
        }
    }
}

impl FeeSchedule {
    /// Validate fee schedule parameters.
    pub fn validate(&self) -> Result<(), TokenomicsError> {
        if self.burn_bps > BPS_DENOMINATOR {
            return Err(TokenomicsError::InvalidConfig("burn_bps must be <= 10_000"));
        }
        if self.express_fee == 0 || self.shielded_fee == 0 {
            return Err(TokenomicsError::InvalidConfig("lane fees must be non-zero"));
        }
        if self.shielded_fee < self.express_fee {
            return Err(TokenomicsError::InvalidConfig(
                "shielded_fee must be >= express_fee",
            ));
        }
        Ok(())
    }

    /// Compute the deterministic reward/burn breakdown for a transaction lane.
    pub fn breakdown(&self, lane: FeeLane) -> FeeBreakdown {
        let (total_fee, otp_frame_bytes, beaver_triples_used, mpc_buckets_used) = match lane {
            FeeLane::Express => (self.express_fee, EXPRESS_FRAME_BYTES, 0, 0),
            FeeLane::Shielded => (
                self.shielded_fee,
                SHIELDED_FRAME_BYTES,
                self.shielded_beaver_triples,
                1,
            ),
        };
        let effective_burn_bps = self.burn_bps.min(BPS_DENOMINATOR);
        let burn_share =
            ((total_fee as u128 * effective_burn_bps as u128) / BPS_DENOMINATOR as u128) as u64;
        let validator_reward_share = total_fee - burn_share;
        FeeBreakdown {
            lane,
            total_fee,
            validator_reward_share,
            burn_share,
            otp_frame_bytes,
            beaver_triples_used,
            mpc_buckets_used,
        }
    }
}

/// Detailed accounting breakdown for a Pad-Burn transaction fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeBreakdown {
    pub lane: FeeLane,
    pub total_fee: u64,
    pub validator_reward_share: u64,
    pub burn_share: u64,
    pub otp_frame_bytes: u32,
    pub beaver_triples_used: u32,
    pub mpc_buckets_used: u32,
}

/// Proof-of-Pad (PoP) anti-plutocracy reward policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PopRewardPolicy {
    /// Share of each epoch's reward pool split strictly equally across all qualifying
    /// honest active validators (basis points; default 7,000 = 70%).
    /// The remaining `10_000 - equal_participation_bps` (default 30%) rewards verified
    /// QKD/QRNG pad pages and Beaver triple availability, capped per validator.
    pub equal_participation_bps: u16,
    /// Minimum BFT blocks finalized in an epoch to qualify as actively participating.
    pub min_blocks_finalized: u64,
    /// Minimum PSS (Proactive Secret Sharing) epoch refreshes completed to qualify.
    pub min_pss_refreshes: u64,
    /// Weight per verified QKD/QRNG pad page supplied toward the entropy availability score.
    pub pad_page_weight: u64,
    /// Weight per verified Beaver triple contributed toward the entropy availability score.
    pub beaver_triple_weight: u64,
    /// Per-validator ceiling on entropy availability score to prevent datacenter monopolization.
    pub max_entropy_score_cap: u64,
}

impl Default for PopRewardPolicy {
    fn default() -> Self {
        Self {
            equal_participation_bps: DEFAULT_EQUAL_PARTICIPATION_BPS,
            min_blocks_finalized: 1,
            min_pss_refreshes: 1,
            pad_page_weight: 2,
            beaver_triple_weight: 1,
            max_entropy_score_cap: DEFAULT_MAX_ENTROPY_SCORE_CAP,
        }
    }
}

impl PopRewardPolicy {
    /// Validate PoP reward policy parameters.
    pub fn validate(&self) -> Result<(), TokenomicsError> {
        if self.equal_participation_bps > BPS_DENOMINATOR {
            return Err(TokenomicsError::InvalidConfig(
                "equal_participation_bps must be <= 10_000",
            ));
        }
        if self.max_entropy_score_cap == 0 {
            return Err(TokenomicsError::InvalidConfig(
                "max_entropy_score_cap must be > 0",
            ));
        }
        Ok(())
    }

    /// Compute a validator's capped entropy & MPC availability score.
    pub fn capped_entropy_score(&self, contrib: &EpochContribution) -> u64 {
        let pad_pts = contrib.pad_pages_supplied.saturating_mul(self.pad_page_weight);
        let triple_pts = contrib
            .beaver_triples_contributed
            .saturating_mul(self.beaver_triple_weight);
        pad_pts
            .saturating_add(triple_pts)
            .min(self.max_entropy_score_cap)
    }

    /// Check whether a validator met honest consensus & PSS liveness thresholds for the epoch.
    pub fn meets_liveness(&self, contrib: &EpochContribution) -> bool {
        contrib.blocks_finalized >= self.min_blocks_finalized
            && contrib.pss_refreshes_completed >= self.min_pss_refreshes
    }
}

/// Top-level configuration for the Vernam tokenomics engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenomicsConfig {
    /// Flat equal bond required per validator seat (NOT stake-weighted voting power).
    pub required_bond: u64,
    /// Pad-Burn fee schedule.
    pub fee_schedule: FeeSchedule,
    /// Proof-of-Pad epoch reward distribution policy.
    pub pop_policy: PopRewardPolicy,
}

impl Default for TokenomicsConfig {
    fn default() -> Self {
        Self {
            required_bond: DEFAULT_REQUIRED_BOND,
            fee_schedule: FeeSchedule::default(),
            pop_policy: PopRewardPolicy::default(),
        }
    }
}

impl TokenomicsConfig {
    /// Validate all tokenomics settings.
    pub fn validate(&self) -> Result<(), TokenomicsError> {
        if self.required_bond == 0 || self.required_bond > MAX_SUPPLY {
            return Err(TokenomicsError::InvalidConfig(
                "required_bond must be in 1..=MAX_SUPPLY",
            ));
        }
        self.fee_schedule.validate()?;
        self.pop_policy.validate()?;
        Ok(())
    }
}

/// Per-validator Proof-of-Pad contributions tracked during an epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EpochContribution {
    /// Verified QKD/QRNG one-time pad pages supplied and attested.
    pub pad_pages_supplied: u64,
    /// Verified IT-MPC Beaver triples contributed to the shared pool.
    pub beaver_triples_contributed: u64,
    /// BFT blocks finalized in the current epoch.
    pub blocks_finalized: u64,
    /// Proactive Secret Sharing (PSS) refreshes completed in the current epoch.
    pub pss_refreshes_completed: u64,
}

impl EpochContribution {
    /// Accumulate another contribution record into this epoch tally.
    pub fn add_assign(&mut self, other: EpochContribution) {
        self.pad_pages_supplied = self.pad_pages_supplied.saturating_add(other.pad_pages_supplied);
        self.beaver_triples_contributed = self
            .beaver_triples_contributed
            .saturating_add(other.beaver_triples_contributed);
        self.blocks_finalized = self.blocks_finalized.saturating_add(other.blocks_finalized);
        self.pss_refreshes_completed = self
            .pss_refreshes_completed
            .saturating_add(other.pss_refreshes_completed);
    }
}

/// Lifecycle status of a bonded validator vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// Fully bonded with the flat seat bond and eligible for consensus & epoch rewards.
    Active,
    /// Temporarily offline (e.g., downtime); ineligible for consensus & epoch rewards.
    Offline,
    /// Jailed after a slashable fault; must restore full flat bond to re-enter `Active`.
    Jailed,
    /// Permanently ejected after equivocation; cannot rejoin.
    Ejected,
}

/// Slashable protocol offenses and their permanent burn penalties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashingOffense {
    /// Double-signing or conflicting BFT prepare/commit votes: 100% bond burn + permanent ejection.
    Equivocation,
    /// Submitting an invalid/inconsistent IT-MPC Shamir or Beaver share: 50% bond burn + jail.
    InconsistentMpcShare,
    /// Failing liveness / pad replenishment beyond grace window: 10% bond burn + offline/jail.
    ExtendedDowntime,
}

impl SlashingOffense {
    /// Slash severity in basis points (`10_000` = 100%).
    #[inline]
    pub const fn slash_bps(self) -> u16 {
        match self {
            Self::Equivocation => 10_000,
            Self::InconsistentMpcShare => 5_000,
            Self::ExtendedDowntime => 1_000,
        }
    }
}

/// Bonded validator vault holding a flat, equal security bond (non-plutocratic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorVault {
    pub validator_id: ValidatorId,
    /// Current locked bond in `vern`.
    pub bond: u64,
    /// Required flat bond for an active validator seat.
    pub required_bond: u64,
    /// Accumulated withdrawable Proof-of-Pad epoch rewards in `vern`.
    pub reward_balance: u64,
    /// Current validator lifecycle status.
    pub status: ValidatorStatus,
    /// Total number of slashing events incurred.
    pub slashing_events: u32,
    /// Cumulative bond burned by slashing.
    pub total_slashed: u64,
    /// Whether rewards for the in-progress epoch are forfeited due to slashing.
    pub forfeited_current_epoch: bool,
}

impl ValidatorVault {
    /// Returns true if the validator is active and holds the full flat seat bond.
    #[inline]
    pub const fn is_eligible_for_consensus(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active) && self.bond == self.required_bond
    }

    /// Anti-plutocracy voting power: strictly 1 for any active bonded seat, 0 otherwise.
    #[inline]
    pub const fn voting_power(&self) -> u64 {
        if self.is_eligible_for_consensus() {
            1
        } else {
            0
        }
    }
}

/// Receipt emitted whenever a validator is slashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashingReceipt {
    pub validator_id: ValidatorId,
    pub offense: SlashingOffense,
    pub epoch: u64,
    pub slashed_amount: u64,
    pub remaining_bond: u64,
    pub new_status: ValidatorStatus,
    pub epoch_rewards_forfeited: bool,
}

/// Per-validator payout summary produced during epoch settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorPayout {
    pub validator_id: ValidatorId,
    pub equal_participation_reward: u64,
    pub entropy_availability_reward: u64,
    pub total_reward: u64,
}

/// Summary of a settled Proof-of-Pad epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSettlement {
    pub epoch: u64,
    pub subsidy_minted: u64,
    pub fee_rewards_distributed: u64,
    pub fees_burned_in_epoch: u64,
    pub total_distributed: u64,
    pub dust_rolled_over: u64,
    pub circulating_supply: u64,
    pub total_burned: u64,
    pub total_minted: u64,
    pub payouts: Vec<ValidatorPayout>,
}

/// One-time information-theoretic authentication key over F_(2^127 - 1) for audit receipts.
///
/// Key material is volatile-zeroized on drop via `crate::field::zeroize_u128`.
/// Every signing and verification method consumes `self` so a one-time Carter-Wegman key
/// cannot accidentally be reused across two distinct messages.
pub struct OneTimeAuditKey {
    r: u128,
    s: u128,
}

impl fmt::Debug for OneTimeAuditKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OneTimeAuditKey([REDACTED])")
    }
}

impl OneTimeAuditKey {
    /// Generate a fresh uniform one-time key in F_(2^127 - 1) using OS randomness.
    pub fn generate() -> Self {
        Self {
            r: random_field_elem(),
            s: random_field_elem(),
        }
    }

    /// Construct from explicit field elements (reduced modulo `PRIME_P`).
    pub const fn from_elements(r: u128, s: u128) -> Self {
        Self {
            r: r % PRIME_P,
            s: s % PRIME_P,
        }
    }

    /// Create a paired one-time verifier copy (analogous to `PadPage::duplicate_for_peer`)
    /// so signer and verifier can each consume their own single-use `OneTimeAuditKey`.
    pub fn duplicate_for_verifier(&self) -> Self {
        Self {
            r: self.r,
            s: self.s,
        }
    }

    fn settlement_words(settlement: &EpochSettlement) -> Vec<u64> {
        let cap = settlement
            .payouts
            .len()
            .saturating_mul(4)
            .saturating_add(11);
        let mut words = Vec::with_capacity(cap);
        // Domain tag = 1 for EpochSettlement.
        words.push(1);
        words.push(settlement.epoch);
        words.push(settlement.subsidy_minted);
        words.push(settlement.fee_rewards_distributed);
        words.push(settlement.fees_burned_in_epoch);
        words.push(settlement.total_distributed);
        words.push(settlement.dust_rolled_over);
        words.push(settlement.circulating_supply);
        words.push(settlement.total_burned);
        words.push(settlement.total_minted);
        words.push(settlement.payouts.len() as u64);
        for p in &settlement.payouts {
            words.push(p.validator_id);
            words.push(p.equal_participation_reward);
            words.push(p.entropy_availability_reward);
            words.push(p.total_reward);
        }
        words
    }

    fn slashing_words(receipt: &SlashingReceipt) -> [u64; 8] {
        let offense_code = match receipt.offense {
            SlashingOffense::Equivocation => 1,
            SlashingOffense::InconsistentMpcShare => 2,
            SlashingOffense::ExtendedDowntime => 3,
        };
        let status_code = match receipt.new_status {
            ValidatorStatus::Active => 1,
            ValidatorStatus::Offline => 2,
            ValidatorStatus::Jailed => 3,
            ValidatorStatus::Ejected => 4,
        };
        [
            // Domain tag = 2 for SlashingReceipt.
            2,
            receipt.validator_id,
            offense_code,
            receipt.epoch,
            receipt.slashed_amount,
            receipt.remaining_bond,
            status_code,
            receipt.epoch_rewards_forfeited as u64,
        ]
    }

    /// Compute a one-time Carter-Wegman polynomial MAC over EVERY field of an `EpochSettlement`
    /// (including `total_minted` and all `payouts` entries), consuming `self` so the key is zeroized.
    pub fn tag_settlement(self, settlement: &EpochSettlement) -> AuditTag {
        let words = Self::settlement_words(settlement);
        self.mac_u64_slice(&words)
    }

    /// Verify an `EpochSettlement` audit tag in constant time via `ct_eq_16`, consuming `self`.
    pub fn verify_settlement(self, settlement: &EpochSettlement, tag: &AuditTag) -> bool {
        let words = Self::settlement_words(settlement);
        let expected = self.mac_u64_slice(&words);
        ct_eq_16(&expected, tag)
    }

    /// Compute a one-time Carter-Wegman polynomial MAC over EVERY field of a `SlashingReceipt`
    /// (including `epoch_rewards_forfeited`), consuming `self` so the key is zeroized.
    pub fn tag_slashing(self, receipt: &SlashingReceipt) -> AuditTag {
        let words = Self::slashing_words(receipt);
        self.mac_u64_slice(&words)
    }

    /// Verify a `SlashingReceipt` audit tag in constant time via `ct_eq_16`, consuming `self`.
    pub fn verify_slashing(self, receipt: &SlashingReceipt, tag: &AuditTag) -> bool {
        let words = Self::slashing_words(receipt);
        let expected = self.mac_u64_slice(&words);
        ct_eq_16(&expected, tag)
    }

    fn mac_u64_slice(&self, words: &[u64]) -> AuditTag {
        let mut acc: u128 = 0;
        for &w in words {
            // Horner evaluation: acc = (acc + w) * r mod PRIME_P
            acc = mul_mod(add_mod(acc, w as u128), self.r);
        }
        let mac = add_mod(acc, self.s);
        mac.to_le_bytes()
    }
}

impl Drop for OneTimeAuditKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

/// Core Vernam (VRNM) Proof-of-Pad tokenomics, Pad-Burn fee, and slashing engine.
#[derive(Debug, Clone)]
pub struct TokenomicsEngine {
    config: TokenomicsConfig,
    current_epoch: u64,
    total_minted: u64,
    total_burned: u64,
    circulating_supply: u64,
    liquid_supply: u64,
    total_bonded: u64,
    pending_fee_rewards: u64,
    total_validator_rewards: u64,
    fees_burned_in_current_epoch: u64,
    total_fees_collected: u64,
    total_fees_burned: u64,
    total_fees_rewarded: u64,
    total_slashed_burned: u64,
    express_tx_count: u64,
    shielded_tx_count: u64,
    vaults: BTreeMap<ValidatorId, ValidatorVault>,
    epoch_contributions: BTreeMap<ValidatorId, EpochContribution>,
}

impl TokenomicsEngine {
    /// Create a new tokenomics engine starting at epoch 0 with zero supply.
    pub fn new(config: TokenomicsConfig) -> Result<Self, TokenomicsError> {
        config.validate()?;
        Ok(Self {
            config,
            current_epoch: 0,
            total_minted: 0,
            total_burned: 0,
            circulating_supply: 0,
            liquid_supply: 0,
            total_bonded: 0,
            pending_fee_rewards: 0,
            total_validator_rewards: 0,
            fees_burned_in_current_epoch: 0,
            total_fees_collected: 0,
            total_fees_burned: 0,
            total_fees_rewarded: 0,
            total_slashed_burned: 0,
            express_tx_count: 0,
            shielded_tx_count: 0,
            vaults: BTreeMap::new(),
            epoch_contributions: BTreeMap::new(),
        })
    }

    /// Create an engine with default Vernam parameters.
    pub fn with_defaults() -> Self {
        Self::new(TokenomicsConfig::default()).expect("default config is always valid")
    }

    /// Mint genesis liquid supply (strictly bounded by `MAX_SUPPLY`).
    pub fn mint_genesis_supply(&mut self, amount: u64) -> Result<(), TokenomicsError> {
        let new_minted = self
            .total_minted
            .checked_add(amount)
            .ok_or(TokenomicsError::SupplyCapExceeded)?;
        if new_minted > MAX_SUPPLY {
            return Err(TokenomicsError::SupplyCapExceeded);
        }
        let new_circ = self
            .circulating_supply
            .checked_add(amount)
            .ok_or(TokenomicsError::InvariantViolation(
                "circulating_supply overflow",
            ))?;
        let new_liquid = self
            .liquid_supply
            .checked_add(amount)
            .ok_or(TokenomicsError::InvariantViolation("liquid_supply overflow"))?;
        self.total_minted = new_minted;
        self.circulating_supply = new_circ;
        self.liquid_supply = new_liquid;
        Ok(())
    }

    /// Register a validator by locking the exact flat `required_bond` from liquid supply.
    pub fn register_validator(
        &mut self,
        validator_id: ValidatorId,
        bond: u64,
    ) -> Result<&ValidatorVault, TokenomicsError> {
        if self.vaults.contains_key(&validator_id) {
            return Err(TokenomicsError::ValidatorAlreadyExists(validator_id));
        }
        if bond != self.config.required_bond {
            return Err(TokenomicsError::InvalidBondAmount {
                expected: self.config.required_bond,
                provided: bond,
            });
        }
        if self.liquid_supply < bond {
            return Err(TokenomicsError::InsufficientLiquidSupply {
                required: bond,
                available: self.liquid_supply,
            });
        }
        let new_bonded = self
            .total_bonded
            .checked_add(bond)
            .ok_or(TokenomicsError::InvariantViolation("total_bonded overflow"))?;
        self.liquid_supply = self
            .liquid_supply
            .checked_sub(bond)
            .ok_or(TokenomicsError::InvariantViolation("liquid_supply underflow"))?;
        self.total_bonded = new_bonded;
        let vault = ValidatorVault {
            validator_id,
            bond,
            required_bond: self.config.required_bond,
            reward_balance: 0,
            status: ValidatorStatus::Active,
            slashing_events: 0,
            total_slashed: 0,
            forfeited_current_epoch: false,
        };
        self.vaults.insert(validator_id, vault);
        Ok(self.vaults.get(&validator_id).expect("just inserted"))
    }

    /// Register a genesis validator by minting its exact flat bond (bounded by `MAX_SUPPLY`).
    pub fn register_genesis_validator(
        &mut self,
        validator_id: ValidatorId,
    ) -> Result<&ValidatorVault, TokenomicsError> {
        if self.vaults.contains_key(&validator_id) {
            return Err(TokenomicsError::ValidatorAlreadyExists(validator_id));
        }
        let bond = self.config.required_bond;
        self.mint_genesis_supply(bond)?;
        self.register_validator(validator_id, bond)
    }

    /// Mark an active validator offline (e.g., planned maintenance or detected disconnect).
    pub fn set_validator_offline(&mut self, validator_id: ValidatorId) -> Result<(), TokenomicsError> {
        let vault = self
            .vaults
            .get_mut(&validator_id)
            .ok_or(TokenomicsError::ValidatorNotFound(validator_id))?;
        if vault.status == ValidatorStatus::Ejected {
            return Err(TokenomicsError::ValidatorEjected(validator_id));
        }
        vault.status = ValidatorStatus::Offline;
        Ok(())
    }

    /// Top up a non-ejected validator's bond back to the flat `required_bond` and reactivate it.
    pub fn top_up_bond_and_reactivate(
        &mut self,
        validator_id: ValidatorId,
        top_up: u64,
    ) -> Result<(), TokenomicsError> {
        let (status, bond, required) = {
            let v = self
                .vaults
                .get(&validator_id)
                .ok_or(TokenomicsError::ValidatorNotFound(validator_id))?;
            (v.status, v.bond, v.required_bond)
        };
        if status == ValidatorStatus::Ejected {
            return Err(TokenomicsError::ValidatorEjected(validator_id));
        }
        let needed = required.saturating_sub(bond);
        if top_up != needed {
            return Err(TokenomicsError::InvalidBondAmount {
                expected: needed,
                provided: top_up,
            });
        }
        if self.liquid_supply < top_up {
            return Err(TokenomicsError::InsufficientLiquidSupply {
                required: top_up,
                available: self.liquid_supply,
            });
        }
        let new_bonded = self
            .total_bonded
            .checked_add(top_up)
            .ok_or(TokenomicsError::InvariantViolation("total_bonded overflow"))?;
        let new_vault_bond = bond
            .checked_add(top_up)
            .ok_or(TokenomicsError::InvariantViolation("vault bond overflow"))?;
        self.liquid_supply = self
            .liquid_supply
            .checked_sub(top_up)
            .ok_or(TokenomicsError::InvariantViolation("liquid_supply underflow"))?;
        self.total_bonded = new_bonded;
        let vault = self.vaults.get_mut(&validator_id).expect("checked above");
        vault.bond = new_vault_bond;
        vault.status = ValidatorStatus::Active;
        Ok(())
    }

    /// Withdraw a validator's earned Proof-of-Pad rewards into liquid supply.
    pub fn withdraw_validator_rewards(
        &mut self,
        validator_id: ValidatorId,
    ) -> Result<u64, TokenomicsError> {
        let amount = self
            .vaults
            .get(&validator_id)
            .ok_or(TokenomicsError::ValidatorNotFound(validator_id))?
            .reward_balance;
        let new_total_rewards = self
            .total_validator_rewards
            .checked_sub(amount)
            .ok_or(TokenomicsError::InvariantViolation(
                "total_validator_rewards underflow",
            ))?;
        let new_liquid = self
            .liquid_supply
            .checked_add(amount)
            .ok_or(TokenomicsError::InvariantViolation("liquid_supply overflow"))?;
        let vault = self.vaults.get_mut(&validator_id).expect("checked above");
        vault.reward_balance = 0;
        self.total_validator_rewards = new_total_rewards;
        self.liquid_supply = new_liquid;
        Ok(amount)
    }

    /// Collect a transaction fee under the Pad-Burn fee model (`Express` vs `Shielded`).
    ///
    /// Deducts `total_fee` from liquid supply, permanently burns `burn_share` (default 20%),
    /// and credits `validator_reward_share` (default 80%) into the current epoch's reward pool.
    pub fn collect_fee(&mut self, lane: FeeLane) -> Result<FeeBreakdown, TokenomicsError> {
        let breakdown = self.config.fee_schedule.breakdown(lane);
        if self.liquid_supply < breakdown.total_fee {
            return Err(TokenomicsError::InsufficientLiquidSupply {
                required: breakdown.total_fee,
                available: self.liquid_supply,
            });
        }

        let new_liquid = self
            .liquid_supply
            .checked_sub(breakdown.total_fee)
            .ok_or(TokenomicsError::InvariantViolation("liquid_supply underflow"))?;
        let new_pending = self
            .pending_fee_rewards
            .checked_add(breakdown.validator_reward_share)
            .ok_or(TokenomicsError::InvariantViolation(
                "pending_fee_rewards overflow",
            ))?;
        let new_burned = self
            .total_burned
            .checked_add(breakdown.burn_share)
            .ok_or(TokenomicsError::InvariantViolation("total_burned overflow"))?;
        let new_circ = self
            .circulating_supply
            .checked_sub(breakdown.burn_share)
            .ok_or(TokenomicsError::InvariantViolation(
                "circulating_supply underflow",
            ))?;

        self.liquid_supply = new_liquid;
        self.pending_fee_rewards = new_pending;
        self.total_burned = new_burned;
        self.circulating_supply = new_circ;

        self.fees_burned_in_current_epoch = self
            .fees_burned_in_current_epoch
            .saturating_add(breakdown.burn_share);
        self.total_fees_collected = self
            .total_fees_collected
            .saturating_add(breakdown.total_fee);
        self.total_fees_burned = self
            .total_fees_burned
            .saturating_add(breakdown.burn_share);
        self.total_fees_rewarded = self
            .total_fees_rewarded
            .saturating_add(breakdown.validator_reward_share);

        match lane {
            FeeLane::Express => self.express_tx_count = self.express_tx_count.saturating_add(1),
            FeeLane::Shielded => self.shielded_tx_count = self.shielded_tx_count.saturating_add(1),
        }

        Ok(breakdown)
    }

    /// Record verified Proof-of-Pad contributions for a validator in the current epoch.
    pub fn record_contribution(
        &mut self,
        validator_id: ValidatorId,
        contribution: EpochContribution,
    ) -> Result<(), TokenomicsError> {
        if !self.vaults.contains_key(&validator_id) {
            return Err(TokenomicsError::ValidatorNotFound(validator_id));
        }
        self.epoch_contributions
            .entry(validator_id)
            .or_default()
            .add_assign(contribution);
        Ok(())
    }

    /// Slash a misbehaving validator, permanently burning the slashed bond and forfeiting
    /// its rewards for the current epoch.
    pub fn slash_validator(
        &mut self,
        validator_id: ValidatorId,
        offense: SlashingOffense,
    ) -> Result<SlashingReceipt, TokenomicsError> {
        let vault = self
            .vaults
            .get_mut(&validator_id)
            .ok_or(TokenomicsError::ValidatorNotFound(validator_id))?;

        if vault.status == ValidatorStatus::Ejected && vault.bond == 0 {
            return Err(TokenomicsError::AlreadyEjected(validator_id));
        }

        let slash_amount =
            ((vault.bond as u128 * offense.slash_bps() as u128) / BPS_DENOMINATOR as u128) as u64;

        let remaining_bond = vault
            .bond
            .checked_sub(slash_amount)
            .ok_or(TokenomicsError::InvariantViolation("vault bond underflow"))?;
        let new_total_bonded = self
            .total_bonded
            .checked_sub(slash_amount)
            .ok_or(TokenomicsError::InvariantViolation("total_bonded underflow"))?;
        let new_circ = self
            .circulating_supply
            .checked_sub(slash_amount)
            .ok_or(TokenomicsError::InvariantViolation(
                "circulating_supply underflow",
            ))?;
        let new_total_burned = self
            .total_burned
            .checked_add(slash_amount)
            .ok_or(TokenomicsError::InvariantViolation("total_burned overflow"))?;

        vault.bond = remaining_bond;
        vault.slashing_events = vault.slashing_events.saturating_add(1);
        vault.total_slashed = vault.total_slashed.saturating_add(slash_amount);
        vault.forfeited_current_epoch = true;

        vault.status = match offense {
            SlashingOffense::Equivocation => ValidatorStatus::Ejected,
            SlashingOffense::InconsistentMpcShare => ValidatorStatus::Jailed,
            SlashingOffense::ExtendedDowntime => ValidatorStatus::Offline,
        };

        let new_status = vault.status;

        self.total_bonded = new_total_bonded;
        self.total_burned = new_total_burned;
        self.total_slashed_burned = self.total_slashed_burned.saturating_add(slash_amount);
        self.circulating_supply = new_circ;

        Ok(SlashingReceipt {
            validator_id,
            offense,
            epoch: self.current_epoch,
            slashed_amount: slash_amount,
            remaining_bond,
            new_status,
            epoch_rewards_forfeited: true,
        })
    }

    /// Settle the current Proof-of-Pad epoch:
    /// 1. Identifies all qualifying active honest validators (active + full flat bond +
    ///    unslashed in this epoch + meets BFT/PSS liveness thresholds).
    /// 2. Mints the halving epoch subsidy (clamped strictly to `MAX_SUPPLY`) only when at
    ///    least one qualifying validator exists.
    /// 3. Distributes `subsidy + pending_fee_rewards` via anti-plutocracy weighting:
    ///    - Equal active honest participation tranche (`equal_participation_bps`, default 70%),
    ///    - Capped verified entropy & Beaver triple availability tranche (default 30%).
    ///    If every qualifying validator has zero entropy score, 100% is split equally.
    /// 4. Rolls any integer-division dust into `pending_fee_rewards` for the next epoch,
    ///    resets per-epoch tallies, and increments `current_epoch`.
    pub fn settle_epoch(&mut self) -> EpochSettlement {
        let epoch = self.current_epoch;
        let fees_burned_in_epoch = self.fees_burned_in_current_epoch;
        let policy = self.config.pop_policy;

        // Gather qualifying active honest validators in deterministic ValidatorId order.
        let mut eligible: Vec<(ValidatorId, u64)> = Vec::new();
        for (&id, vault) in &self.vaults {
            if !vault.is_eligible_for_consensus() || vault.forfeited_current_epoch {
                continue;
            }
            let contrib = self
                .epoch_contributions
                .get(&id)
                .copied()
                .unwrap_or_default();
            if policy.meets_liveness(&contrib) {
                let score = policy.capped_entropy_score(&contrib);
                eligible.push((id, score));
            }
        }

        let mut payouts = Vec::with_capacity(eligible.len());
        let mut subsidy_minted: u64 = 0;
        let mut fee_rewards_distributed: u64 = 0;
        let mut total_distributed: u64 = 0;

        if !eligible.is_empty() {
            let scheduled = epoch_reward(epoch);
            let remaining_cap = MAX_SUPPLY.saturating_sub(self.total_minted);
            subsidy_minted = scheduled.min(remaining_cap);

            self.total_minted = self
                .total_minted
                .checked_add(subsidy_minted)
                .expect("clamped to MAX_SUPPLY");
            self.circulating_supply = self
                .circulating_supply
                .checked_add(subsidy_minted)
                .expect("bounded by MAX_SUPPLY");

            let available_fees = self.pending_fee_rewards;
            let total_pool_u128 = (subsidy_minted as u128) + (available_fees as u128);
            let total_pool = u64::try_from(total_pool_u128).expect("bounded by MAX_SUPPLY");

            let count = eligible.len() as u128;
            let total_entropy_score: u128 = eligible.iter().map(|&(_, s)| s as u128).sum();

            let effective_equal_bps = policy.equal_participation_bps.min(BPS_DENOMINATOR);
            let (equal_pool, entropy_pool) = if total_entropy_score == 0 {
                (total_pool, 0u64)
            } else {
                let eq = ((total_pool as u128 * effective_equal_bps as u128)
                    / BPS_DENOMINATOR as u128) as u64;
                (eq, total_pool - eq)
            };

            let equal_each = (equal_pool as u128 / count) as u64;

            for &(id, score) in &eligible {
                let entropy_share = if total_entropy_score == 0 {
                    0
                } else {
                    ((entropy_pool as u128 * score as u128) / total_entropy_score) as u64
                };
                let total_reward = equal_each
                    .checked_add(entropy_share)
                    .expect("bounded by total_pool");
                total_distributed = total_distributed
                    .checked_add(total_reward)
                    .expect("bounded by total_pool");

                let vault = self.vaults.get_mut(&id).expect("eligible validator exists");
                vault.reward_balance = vault
                    .reward_balance
                    .checked_add(total_reward)
                    .expect("bounded by MAX_SUPPLY");
                self.total_validator_rewards = self
                    .total_validator_rewards
                    .checked_add(total_reward)
                    .expect("bounded by MAX_SUPPLY");

                payouts.push(ValidatorPayout {
                    validator_id: id,
                    equal_participation_reward: equal_each,
                    entropy_availability_reward: entropy_share,
                    total_reward,
                });
            }

            let dust = total_pool
                .checked_sub(total_distributed)
                .expect("total_distributed <= total_pool");
            // Subsidy is paid first, then fee rewards; any integer-division dust stays in pending_fee_rewards.
            fee_rewards_distributed = total_distributed.saturating_sub(subsidy_minted);
            self.pending_fee_rewards = dust;
        }

        // Reset epoch state and advance epoch counter without overflowing at u64::MAX.
        self.epoch_contributions.clear();
        self.fees_burned_in_current_epoch = 0;
        for vault in self.vaults.values_mut() {
            vault.forfeited_current_epoch = false;
        }
        self.current_epoch = self.current_epoch.saturating_add(1);

        EpochSettlement {
            epoch,
            subsidy_minted,
            fee_rewards_distributed,
            fees_burned_in_epoch,
            total_distributed,
            dust_rolled_over: self.pending_fee_rewards,
            circulating_supply: self.circulating_supply,
            total_burned: self.total_burned,
            total_minted: self.total_minted,
            payouts,
        }
    }

    /// Verify all supply and accounting invariants to the exact `vern` (panic-free via u128).
    pub fn check_invariants(&self) -> Result<(), TokenomicsError> {
        if self.total_minted > MAX_SUPPLY {
            return Err(TokenomicsError::InvariantViolation("total_minted > MAX_SUPPLY"));
        }
        if (self.circulating_supply as u128) + (self.total_burned as u128)
            != (self.total_minted as u128)
        {
            return Err(TokenomicsError::InvariantViolation(
                "circulating_supply + total_burned != total_minted",
            ));
        }
        if (self.total_fees_burned as u128) + (self.total_slashed_burned as u128)
            != (self.total_burned as u128)
        {
            return Err(TokenomicsError::InvariantViolation(
                "total_fees_burned + total_slashed_burned != total_burned",
            ));
        }
        if (self.total_fees_burned as u128) + (self.total_fees_rewarded as u128)
            != (self.total_fees_collected as u128)
        {
            return Err(TokenomicsError::InvariantViolation(
                "total_fees_burned + total_fees_rewarded != total_fees_collected",
            ));
        }
        let sum_vault_bonds: u128 = self.vaults.values().map(|v| v.bond as u128).sum();
        if sum_vault_bonds != (self.total_bonded as u128) {
            return Err(TokenomicsError::InvariantViolation(
                "sum(vault.bond) != total_bonded",
            ));
        }
        let sum_vault_rewards: u128 = self
            .vaults
            .values()
            .map(|v| v.reward_balance as u128)
            .sum();
        if sum_vault_rewards != (self.total_validator_rewards as u128) {
            return Err(TokenomicsError::InvariantViolation(
                "sum(vault.reward_balance) != total_validator_rewards",
            ));
        }
        let sub_ledger_total: u128 = (self.liquid_supply as u128)
            + (self.total_bonded as u128)
            + (self.pending_fee_rewards as u128)
            + (self.total_validator_rewards as u128);
        if sub_ledger_total != (self.circulating_supply as u128) {
            return Err(TokenomicsError::InvariantViolation(
                "sub-ledger sum != circulating_supply",
            ));
        }
        Ok(())
    }

    // --- Read-only accessors ---

    pub const fn config(&self) -> &TokenomicsConfig {
        &self.config
    }

    pub const fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub const fn total_minted(&self) -> u64 {
        self.total_minted
    }

    pub const fn total_burned(&self) -> u64 {
        self.total_burned
    }

    pub const fn circulating_supply(&self) -> u64 {
        self.circulating_supply
    }

    pub const fn liquid_supply(&self) -> u64 {
        self.liquid_supply
    }

    pub const fn total_bonded(&self) -> u64 {
        self.total_bonded
    }

    pub const fn pending_fee_rewards(&self) -> u64 {
        self.pending_fee_rewards
    }

    pub const fn total_fees_collected(&self) -> u64 {
        self.total_fees_collected
    }

    pub const fn total_fees_burned(&self) -> u64 {
        self.total_fees_burned
    }

    pub const fn total_fees_rewarded(&self) -> u64 {
        self.total_fees_rewarded
    }

    pub const fn total_slashed_burned(&self) -> u64 {
        self.total_slashed_burned
    }

    pub const fn express_tx_count(&self) -> u64 {
        self.express_tx_count
    }

    pub const fn shielded_tx_count(&self) -> u64 {
        self.shielded_tx_count
    }

    pub fn vault(&self, validator_id: ValidatorId) -> Option<&ValidatorVault> {
        self.vaults.get(&validator_id)
    }

    /// Total consensus voting power across all active bonded validators (1 per seat).
    pub fn total_voting_power(&self) -> u64 {
        self.vaults
            .values()
            .fold(0u64, |acc, v| acc.saturating_add(v.voting_power()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_halving_schedule_never_exceeds_max_supply() {
        assert_eq!(MAX_SUPPLY, 2_100_000_000_000_000);
        assert_eq!(epoch_reward(0), 50 * VERN_PER_VRNM);
        assert_eq!(epoch_reward(EPOCHS_PER_HALVING - 1), 50 * VERN_PER_VRNM);
        assert_eq!(epoch_reward(EPOCHS_PER_HALVING), 25 * VERN_PER_VRNM);
        assert_eq!(epoch_reward(2 * EPOCHS_PER_HALVING), 1_250_000_000);
        assert_eq!(epoch_reward(33 * EPOCHS_PER_HALVING), 0);
        assert_eq!(epoch_reward(64 * EPOCHS_PER_HALVING), 0);
        assert_eq!(epoch_reward(u64::MAX), 0);

        // Sum every era explicitly and confirm strictly bounded by MAX_SUPPLY.
        let mut cumulative: u128 = 0;
        for era in 0u64..100 {
            let reward_per_epoch = epoch_reward(era * EPOCHS_PER_HALVING);
            cumulative += (reward_per_epoch as u128) * (EPOCHS_PER_HALVING as u128);
        }
        assert_eq!(cumulative, total_scheduled_issuance() as u128);
        assert!(cumulative <= MAX_SUPPLY as u128);
        assert!(
            cumulative > (20_999_999 * VERN_PER_VRNM) as u128,
            "issuance should approach 21M VRNM closely"
        );
    }

    #[test]
    fn test_supply_cap_clamping_with_genesis_mint() {
        let mut engine = TokenomicsEngine::with_defaults();
        // Mint almost all supply except 10 VRNM, plus one genesis validator.
        let near_cap = MAX_SUPPLY - DEFAULT_REQUIRED_BOND - (10 * VERN_PER_VRNM);
        engine.mint_genesis_supply(near_cap).unwrap();
        engine.register_genesis_validator(1).unwrap();

        engine
            .record_contribution(
                1,
                EpochContribution {
                    pad_pages_supplied: 10,
                    beaver_triples_contributed: 20,
                    blocks_finalized: 5,
                    pss_refreshes_completed: 1,
                },
            )
            .unwrap();

        // Scheduled subsidy is 50 VRNM, but only 10 VRNM remains under MAX_SUPPLY.
        let settlement = engine.settle_epoch();
        assert_eq!(settlement.subsidy_minted, 10 * VERN_PER_VRNM);
        assert_eq!(engine.total_minted(), MAX_SUPPLY);
        engine.check_invariants().unwrap();

        // Subsequent epoch must mint 0.
        engine
            .record_contribution(
                1,
                EpochContribution {
                    pad_pages_supplied: 10,
                    beaver_triples_contributed: 20,
                    blocks_finalized: 5,
                    pss_refreshes_completed: 1,
                },
            )
            .unwrap();
        let next = engine.settle_epoch();
        assert_eq!(next.subsidy_minted, 0);
        assert_eq!(engine.total_minted(), MAX_SUPPLY);
        engine.check_invariants().unwrap();
    }

    #[test]
    fn test_express_and_shielded_fee_80_20_burn_accounting() {
        let mut engine = TokenomicsEngine::with_defaults();
        let initial_liquid = 100 * VERN_PER_VRNM;
        engine.mint_genesis_supply(initial_liquid).unwrap();

        // Express lane fee (256B OTP frame, 10_000 vern -> 8_000 reward, 2_000 burned).
        let exp = engine.collect_fee(FeeLane::Express).unwrap();
        assert_eq!(exp.otp_frame_bytes, EXPRESS_FRAME_BYTES);
        assert_eq!(exp.beaver_triples_used, 0);
        assert_eq!(exp.mpc_buckets_used, 0);
        assert_eq!(exp.total_fee, DEFAULT_EXPRESS_FEE);
        assert_eq!(exp.validator_reward_share, 8_000);
        assert_eq!(exp.burn_share, 2_000);

        // Shielded lane fee (4096B frame + Beaver triples + MPC bucket, 250_000 vern -> 200_000 reward, 50_000 burned).
        let sh = engine.collect_fee(FeeLane::Shielded).unwrap();
        assert_eq!(sh.otp_frame_bytes, SHIELDED_FRAME_BYTES);
        assert_eq!(sh.beaver_triples_used, SHIELDED_BEAVER_TRIPLES);
        assert_eq!(sh.mpc_buckets_used, 1);
        assert_eq!(sh.total_fee, DEFAULT_SHIELDED_FEE);
        assert_eq!(sh.validator_reward_share, 200_000);
        assert_eq!(sh.burn_share, 50_000);

        assert_eq!(engine.express_tx_count(), 1);
        assert_eq!(engine.shielded_tx_count(), 1);
        assert_eq!(engine.total_fees_collected(), 260_000);
        assert_eq!(engine.total_fees_rewarded(), 208_000);
        assert_eq!(engine.total_fees_burned(), 52_000);
        assert_eq!(engine.pending_fee_rewards(), 208_000);
        assert_eq!(engine.total_burned(), 52_000);
        assert_eq!(engine.circulating_supply(), initial_liquid - 52_000);
        engine.check_invariants().unwrap();
    }

    #[test]
    fn test_pop_epoch_distribution_skips_offline_and_slashed_rewards_honest_equally() {
        let mut engine = TokenomicsEngine::with_defaults();
        engine.mint_genesis_supply(10 * VERN_PER_VRNM).unwrap();

        // Register 4 flat-bonded validators (equal 1 seat = 1 vote).
        for id in 1..=4 {
            engine.register_genesis_validator(id).unwrap();
            assert_eq!(engine.vault(id).unwrap().voting_power(), 1);
        }
        assert_eq!(engine.total_voting_power(), 4);

        // Collect 10 Express + 4 Shielded fees.
        for _ in 0..10 {
            engine.collect_fee(FeeLane::Express).unwrap();
        }
        for _ in 0..4 {
            engine.collect_fee(FeeLane::Shielded).unwrap();
        }
        let expected_fee_rewards = 10 * 8_000 + 4 * 200_000;
        assert_eq!(engine.pending_fee_rewards(), expected_fee_rewards);

        // Equal honest contributions from validators 1, 2, 3, and 4.
        let honest_contrib = EpochContribution {
            pad_pages_supplied: 100,
            beaver_triples_contributed: 200,
            blocks_finalized: 10,
            pss_refreshes_completed: 2,
        };
        for id in 1..=4 {
            engine.record_contribution(id, honest_contrib).unwrap();
        }

        // Validator 3 goes offline before settlement.
        engine.set_validator_offline(3).unwrap();
        assert_eq!(engine.vault(3).unwrap().voting_power(), 0);

        // Validator 4 commits InconsistentMpcShare -> 50% slash + forfeited epoch rewards.
        let slash = engine
            .slash_validator(4, SlashingOffense::InconsistentMpcShare)
            .unwrap();
        assert_eq!(slash.slashed_amount, DEFAULT_REQUIRED_BOND / 2);
        assert!(slash.epoch_rewards_forfeited);
        assert_eq!(engine.vault(4).unwrap().voting_power(), 0);

        // Settle epoch 0: ONLY honest active validators 1 and 2 should be paid, and equally!
        let settlement = engine.settle_epoch();
        assert_eq!(settlement.epoch, 0);
        assert_eq!(settlement.payouts.len(), 2);
        assert_eq!(settlement.payouts[0].validator_id, 1);
        assert_eq!(settlement.payouts[1].validator_id, 2);
        assert_eq!(
            settlement.payouts[0].total_reward,
            settlement.payouts[1].total_reward
        );

        let expected_pool = INITIAL_EPOCH_REWARD + expected_fee_rewards;
        assert_eq!(
            settlement.total_distributed + settlement.dust_rolled_over,
            expected_pool
        );
        assert_eq!(engine.vault(3).unwrap().reward_balance, 0);
        assert_eq!(engine.vault(4).unwrap().reward_balance, 0);
        assert_eq!(
            engine.vault(1).unwrap().reward_balance,
            settlement.payouts[0].total_reward
        );
        engine.check_invariants().unwrap();
    }

    #[test]
    fn test_anti_plutocracy_flat_bond_and_entropy_cap() {
        let mut engine = TokenomicsEngine::with_defaults();
        engine.mint_genesis_supply(100_000 * VERN_PER_VRNM).unwrap();

        // Attempt to post 2x bond for plutocratic weight must be rejected.
        let err = engine
            .register_validator(1, DEFAULT_REQUIRED_BOND * 2)
            .unwrap_err();
        assert_eq!(
            err,
            TokenomicsError::InvalidBondAmount {
                expected: DEFAULT_REQUIRED_BOND,
                provided: DEFAULT_REQUIRED_BOND * 2,
            }
        );

        // Register two valid equal-bond validators.
        engine.register_validator(1, DEFAULT_REQUIRED_BOND).unwrap();
        engine.register_validator(2, DEFAULT_REQUIRED_BOND).unwrap();

        // Validator 1 supplies moderate entropy; validator 2 tries to flood 1,000,000 pages
        // to monopolize rewards, but is capped by `max_entropy_score_cap`.
        engine
            .record_contribution(
                1,
                EpochContribution {
                    pad_pages_supplied: 500, // score = 500*2 = 1000 (hits cap)
                    beaver_triples_contributed: 0,
                    blocks_finalized: 5,
                    pss_refreshes_completed: 1,
                },
            )
            .unwrap();
        engine
            .record_contribution(
                2,
                EpochContribution {
                    pad_pages_supplied: 1_000_000, // capped at 1000
                    beaver_triples_contributed: 1_000_000,
                    blocks_finalized: 5,
                    pss_refreshes_completed: 1,
                },
            )
            .unwrap();

        let settlement = engine.settle_epoch();
        assert_eq!(settlement.payouts.len(), 2);
        assert_eq!(
            settlement.payouts[0].total_reward,
            settlement.payouts[1].total_reward,
            "entropy cap prevents datacenter monopolization"
        );
        engine.check_invariants().unwrap();
    }

    #[test]
    fn test_slashing_offenses_burn_bond_and_eject_equivocators() {
        let mut engine = TokenomicsEngine::with_defaults();
        engine.mint_genesis_supply(50_000 * VERN_PER_VRNM).unwrap();
        engine.register_validator(1, DEFAULT_REQUIRED_BOND).unwrap();
        engine.register_validator(2, DEFAULT_REQUIRED_BOND).unwrap();
        engine.register_validator(3, DEFAULT_REQUIRED_BOND).unwrap();

        let supply_before = engine.circulating_supply();

        // 1. ExtendedDowntime -> 10% bond burned, Offline, can top up & reactivate.
        let r1 = engine
            .slash_validator(1, SlashingOffense::ExtendedDowntime)
            .unwrap();
        assert_eq!(r1.slashed_amount, DEFAULT_REQUIRED_BOND / 10);
        assert_eq!(r1.remaining_bond, DEFAULT_REQUIRED_BOND * 9 / 10);
        assert_eq!(r1.new_status, ValidatorStatus::Offline);
        assert_eq!(engine.vault(1).unwrap().voting_power(), 0);

        engine
            .top_up_bond_and_reactivate(1, DEFAULT_REQUIRED_BOND / 10)
            .unwrap();
        assert_eq!(engine.vault(1).unwrap().status, ValidatorStatus::Active);
        assert_eq!(engine.vault(1).unwrap().bond, DEFAULT_REQUIRED_BOND);
        assert_eq!(engine.vault(1).unwrap().voting_power(), 1);

        // 2. InconsistentMpcShare -> 50% bond burned, Jailed.
        let r2 = engine
            .slash_validator(2, SlashingOffense::InconsistentMpcShare)
            .unwrap();
        assert_eq!(r2.slashed_amount, DEFAULT_REQUIRED_BOND / 2);
        assert_eq!(r2.remaining_bond, DEFAULT_REQUIRED_BOND / 2);
        assert_eq!(r2.new_status, ValidatorStatus::Jailed);

        // 3. Equivocation -> 100% bond burned, permanently Ejected.
        let r3 = engine
            .slash_validator(3, SlashingOffense::Equivocation)
            .unwrap();
        assert_eq!(r3.slashed_amount, DEFAULT_REQUIRED_BOND);
        assert_eq!(r3.remaining_bond, 0);
        assert_eq!(r3.new_status, ValidatorStatus::Ejected);
        assert_eq!(engine.vault(3).unwrap().voting_power(), 0);

        // Ejected validator cannot top up or reactivate.
        assert_eq!(
            engine.top_up_bond_and_reactivate(3, DEFAULT_REQUIRED_BOND),
            Err(TokenomicsError::ValidatorEjected(3))
        );

        let total_burned_expected =
            (DEFAULT_REQUIRED_BOND / 10) + (DEFAULT_REQUIRED_BOND / 2) + DEFAULT_REQUIRED_BOND;
        assert_eq!(engine.total_slashed_burned(), total_burned_expected);
        assert_eq!(engine.total_burned(), total_burned_expected);
        assert_eq!(
            engine.circulating_supply(),
            supply_before - total_burned_expected
        );
        engine.check_invariants().unwrap();
    }

    #[test]
    fn test_it_mac_audit_tags_over_mersenne_field() {
        let mut engine = TokenomicsEngine::with_defaults();
        engine.register_genesis_validator(1).unwrap();
        engine
            .record_contribution(
                1,
                EpochContribution {
                    pad_pages_supplied: 50,
                    beaver_triples_contributed: 100,
                    blocks_finalized: 4,
                    pss_refreshes_completed: 1,
                },
            )
            .unwrap();

        let settlement = engine.settle_epoch();
        let key = OneTimeAuditKey::generate();
        let vkey_ok = key.duplicate_for_verifier();
        let vkey_burned = key.duplicate_for_verifier();
        let vkey_minted = key.duplicate_for_verifier();
        let vkey_payout = key.duplicate_for_verifier();
        let tag = key.tag_settlement(&settlement);
        assert!(vkey_ok.verify_settlement(&settlement, &tag));

        // Tampering with total_burned invalidates the Carter-Wegman MAC.
        let mut bad_burned = settlement.clone();
        bad_burned.total_burned += 1;
        assert!(!vkey_burned.verify_settlement(&bad_burned, &tag));

        // Tampering with total_minted invalidates the Carter-Wegman MAC.
        let mut bad_minted = settlement.clone();
        bad_minted.total_minted += 1;
        assert!(!vkey_minted.verify_settlement(&bad_minted, &tag));

        // Tampering with any payout entry invalidates the Carter-Wegman MAC.
        let mut bad_payout = settlement.clone();
        bad_payout.payouts[0].total_reward += 1;
        assert!(!vkey_payout.verify_settlement(&bad_payout, &tag));

        // Slashing receipt IT-MAC verification (including epoch_rewards_forfeited).
        let receipt = engine
            .slash_validator(1, SlashingOffense::ExtendedDowntime)
            .unwrap();
        let key2 = OneTimeAuditKey::generate();
        let vkey2_ok = key2.duplicate_for_verifier();
        let vkey2_forfeit = key2.duplicate_for_verifier();
        let slash_tag = key2.tag_slashing(&receipt);
        assert!(vkey2_ok.verify_slashing(&receipt, &slash_tag));

        let mut bad_receipt = receipt.clone();
        bad_receipt.epoch_rewards_forfeited = false;
        assert!(!vkey2_forfeit.verify_slashing(&bad_receipt, &slash_tag));
    }

    #[test]
    fn test_adversarial_tokenomics_extreme_epochs_and_fuzz_invariants() {
        // 1. Defensive clamping on unvalidated FeeSchedule (no underflow panic).
        let extreme_sched = FeeSchedule {
            express_fee: 10_000,
            shielded_fee: 250_000,
            burn_bps: u16::MAX,
            shielded_beaver_triples: 16,
        };
        let bd = extreme_sched.breakdown(FeeLane::Express);
        assert_eq!(bd.burn_share + bd.validator_reward_share, bd.total_fee);
        assert_eq!(bd.burn_share, bd.total_fee);

        // 2. Deterministic adversarial fuzz over epochs 0..1000 + extreme boundary epochs.
        let mut rng_state: u64 = 0x5652_4E4D_70C0_2026;
        let mut next_u64 = || -> u64 {
            let mut x = rng_state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            rng_state = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        let mut engine = TokenomicsEngine::with_defaults();
        engine.mint_genesis_supply(500_000 * VERN_PER_VRNM).unwrap();
        for id in 1..=7u64 {
            engine.register_validator(id, DEFAULT_REQUIRED_BOND).unwrap();
        }
        engine.check_invariants().unwrap();

        // Fuzz epochs 0..1000 with random fees, contributions, slashing, top-ups, and withdrawals.
        for _ in 0..1_000u64 {
            // Collect 0..5 random Express & Shielded fees.
            let num_fees = next_u64() % 6;
            for _ in 0..num_fees {
                let lane = if next_u64() % 2 == 0 {
                    FeeLane::Express
                } else {
                    FeeLane::Shielded
                };
                let _ = engine.collect_fee(lane);
                engine.check_invariants().unwrap();
            }

            // Record random contributions across validators 1..=7.
            for id in 1..=7u64 {
                if next_u64() % 4 != 0 {
                    engine
                        .record_contribution(
                            id,
                            EpochContribution {
                                pad_pages_supplied: next_u64() % 2_000,
                                beaver_triples_contributed: next_u64() % 2_000,
                                blocks_finalized: (next_u64() % 3),
                                pss_refreshes_completed: (next_u64() % 2),
                            },
                        )
                        .unwrap();
                }
            }

            // Occasionally slash, reactivate, or test double-withdrawal.
            let event = next_u64() % 12;
            let vid = (next_u64() % 7) + 1;
            if event == 0 {
                let offense = match next_u64() % 2 {
                    0 => SlashingOffense::ExtendedDowntime,
                    _ => SlashingOffense::InconsistentMpcShare,
                };
                let _ = engine.slash_validator(vid, offense);
            } else if event == 1 {
                if let Some(v) = engine.vault(vid)
                    && v.status != ValidatorStatus::Ejected
                {
                    let needed = v.required_bond.saturating_sub(v.bond);
                    let _ = engine.top_up_bond_and_reactivate(vid, needed);
                }
            } else if event == 2 {
                let withdrawn = engine.withdraw_validator_rewards(vid).unwrap();
                // Immediate second withdrawal must yield 0 (no double-payout!).
                let second = engine.withdraw_validator_rewards(vid).unwrap();
                assert_eq!(second, 0, "double withdrawal must never pay out twice");
                let _ = withdrawn;
            }

            let settlement = engine.settle_epoch();
            assert!(settlement.total_minted <= MAX_SUPPLY);
            assert!(settlement.circulating_supply <= MAX_SUPPLY);
            assert!(engine.total_minted() <= MAX_SUPPLY);
            engine.check_invariants().unwrap();
        }

        // 3. Test extreme epoch numbers: halving boundaries, 100+ halvings, u64::MAX / 2, and u64::MAX!
        let extreme_epochs = [
            EPOCHS_PER_HALVING - 1,
            EPOCHS_PER_HALVING,
            EPOCHS_PER_HALVING + 1,
            33 * EPOCHS_PER_HALVING,
            100 * EPOCHS_PER_HALVING,
            u64::MAX / 2,
            u64::MAX - 2,
            u64::MAX - 1,
            u64::MAX,
        ];
        for &ep in &extreme_epochs {
            engine.current_epoch = ep;
            for id in 1..=7u64 {
                let _ = engine.record_contribution(
                    id,
                    EpochContribution {
                        pad_pages_supplied: 100,
                        beaver_triples_contributed: 100,
                        blocks_finalized: 5,
                        pss_refreshes_completed: 1,
                    },
                );
            }
            let _ = engine.collect_fee(FeeLane::Shielded);
            let s = engine.settle_epoch();
            if ep >= 33 * EPOCHS_PER_HALVING {
                assert_eq!(s.subsidy_minted, 0, "post-halving epoch {ep} must mint 0");
            }
            assert!(engine.total_minted() <= MAX_SUPPLY);
            engine.check_invariants().unwrap();
        }
        // Repeated settle_epoch at u64::MAX must never panic or overflow!
        assert_eq!(engine.current_epoch(), u64::MAX);
        let s_max = engine.settle_epoch();
        assert_eq!(s_max.subsidy_minted, 0);
        assert_eq!(engine.current_epoch(), u64::MAX);
        engine.check_invariants().unwrap();

        // 4. Slash & permanently eject ALL validators -> zero active validators edge case!
        for id in 1..=7u64 {
            let receipt = engine
                .slash_validator(id, SlashingOffense::Equivocation)
                .unwrap();
            assert_eq!(receipt.remaining_bond, 0);
            assert_eq!(receipt.new_status, ValidatorStatus::Ejected);
            // Re-slashing an already-ejected validator must fail cleanly with AlreadyEjected.
            assert_eq!(
                engine.slash_validator(id, SlashingOffense::Equivocation),
                Err(TokenomicsError::AlreadyEjected(id))
            );
            engine.check_invariants().unwrap();
        }
        assert_eq!(engine.total_voting_power(), 0);
        assert_eq!(engine.total_bonded(), 0);

        // Settle with zero active validators (reset epoch to 0 to prove subsidy is NOT minted when 0 eligible).
        engine.current_epoch = 0;
        let _ = engine.collect_fee(FeeLane::Express);
        let pending_before = engine.pending_fee_rewards();
        let zero_val_settlement = engine.settle_epoch();
        assert_eq!(zero_val_settlement.subsidy_minted, 0);
        assert_eq!(zero_val_settlement.total_distributed, 0);
        assert!(zero_val_settlement.payouts.is_empty());
        assert_eq!(engine.pending_fee_rewards(), pending_before);
        engine.check_invariants().unwrap();
    }
}
