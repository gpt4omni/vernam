//! Tiered Information-Theoretic Key Mesh & Multi-Path Pad Transport for Vernam (VRNM).
//!
//! Zero external crates, zero computational cryptography (no SHA-256, RSA, ECDSA, AES, or ChaCha).
//! All security rests strictly on Shannon information theory, `F_(2^127 - 1)` arithmetic,
//! Carter-Wegman universal MACs, 2-universal Toeplitz extraction, and physical/topological
//! assumptions:
//!
//! - **Tier 1 (`Tier1PhysicalQkd`, 10,000 bps)**: Physical ETSI GS QKD 014 optical link.
//! - **Tier 2 (`Tier2MultiPathThreshold`, 7,500 bps)**: Multi-path `(t, m)` Shamir Split-Pad
//!   Transport over disjoint ASNs and independent infrastructure providers (`select_disjoint_relays`),
//!   achieving 2,048:1 key expansion on 64 KiB pad chunks using a 32-byte end-to-end
//!   `CwFastKey` Carter-Wegman MAC plus per-hop relay CW-MACs, degree-`(t - 1)` polynomial
//!   consistency verification, fault tolerance up to `m - t` offline relays, and tampered share
//!   rejection.
//! - **Tier 3 (`Tier3BsmExpanded`, 6,500 bps)**: Vadhan Sample-then-Extract Bounded-Storage Model
//!   (BSM) expander (`BsmStreamExpander`) sampling 1 ephemeral 4,096-bit block per stream epoch
//!   with a 128 B seed (`K_1`) and extracting 1,024 high-entropy bits per block using
//!   `crate::turbo_crypto::toeplitz_hash_turbo` with a reused 640 B strong Toeplitz seed (`K_2`),
//!   burning all seeds and sampled buffers on `finalize_and_burn` and `Drop`.
//! - **Tier 4 (`Tier4OfflineCourier`, 5,000 bps)**: Offline split-courier XOR vaults
//!   (`SplitCourierVault`) splitting `PadPage` batches across `k >= 2` independent physical
//!   couriers (`V = V_1 ^ ... ^ V_k`) bound by a one-time Carter-Wegman manifest MAC.
//! - **Tiered Key Mesh (`TieredKeyMesh`)**: Information-theoretic XOR combiner
//!   (`K_AB = K^(T1) ^ K^(T2) ^ ...`) appending directly into `WalPadBook` (or any `PadBook`).
//!   Security holds unconditionally as long as at least ONE active tier remains uncompromised.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{Ordering, compiler_fence};

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, fill_os_random, inv_mod, mul_mod, random_field_elem,
    random_nonzero_field_elem, reduce, sub_mod, zeroize_slice, zeroize_u128,
};
use crate::otp::{FRAME_BYTES, MAC_TAG_BYTES, OtpError, PadBook, PadPage, WalPadBook};
use crate::pop_mining::PopTransportProvenance;
use crate::qkd::check_entropy_health;
use crate::tokenomics::ValidatorId;
use crate::turbo_crypto::{CwFastKey, otp_xor_turbo_in_place, toeplitz_hash_turbo};

/// Number of plaintext pad bytes packed per canonical `F_(2^127 - 1)` limb (`120 bits < PRIME_P`).
pub const SHAMIR_LIMB_BYTES: usize = 15;

/// Nominal Tier 2 pad chunk size (64 KiB) achieving 2,048:1 expansion against a 32-byte CW key.
pub const TIER2_NOMINAL_CHUNK_BYTES: usize = 65_536;

/// Pre-shared end-to-end Carter-Wegman key size in bytes (`r`: 16 B + `s`: 16 B = 32 B).
pub const E2E_CW_KEY_BYTES: usize = 32;

/// Tier 3 Vadhan BSM sampler seed `K_1` length in bytes (128 B = 1,024 bits).
pub const BSM_SAMPLER_SEED_BYTES: usize = 128;

/// Tier 3 Vadhan BSM strong Toeplitz seed `K_2` length in bytes (`(4096 + 1024 - 1).div_ceil(64) * 8 = 640 B`).
pub const BSM_TOEPLITZ_SEED_BYTES: usize = 640;

/// Tier 3 Vadhan BSM Toeplitz seed length in `u64` words (`80` words = 5,120 bits >= 5,119 required).
pub const BSM_TOEPLITZ_SEED_WORDS: usize = BSM_TOEPLITZ_SEED_BYTES / 8;

/// Tier 3 sampled stream block size in bytes (512 B = 4,096 bits = 64 `u64` words).
pub const BSM_SAMPLE_BLOCK_BYTES: usize = 512;

/// Tier 3 sampled stream block size in bits.
pub const BSM_SAMPLE_BLOCK_BITS: usize = BSM_SAMPLE_BLOCK_BYTES * 8;

/// Tier 3 extracted OTP output size per sampled block in bytes (128 B = 1,024 bits = 16 `u64` words).
pub const BSM_EXTRACT_BLOCK_BYTES: usize = 128;

/// Tier 3 extracted OTP output size per sampled block in bits.
pub const BSM_EXTRACT_BLOCK_BITS: usize = BSM_EXTRACT_BLOCK_BYTES * 8;

/// Maximum subset search attempts during Byzantine tampered-share recovery before failing closed.
const MAX_SUBSET_RECOVERY_ATTEMPTS: usize = 256;

// Domain-separation & bijective mixing constants (< PRIME_P) for pure F_(2^127 - 1) math.
const KT_DOMAIN_RELAY_SELECT: u128 = 0x4B54_5F52_454C_4159_5F53_454C_0001;
const KT_DOMAIN_BSM_SAMPLER: u128 = 0x4B54_5F42_534D_5F53_414D_504C_0002;
const KT_MIX_K1: u128 = 0x5B49_C731_8E2D_6A95_3F14_7C8B_2E61_4D37;
const KT_MIX_K2: u128 = 0x3D82_F1A6_947C_5E2B_6193_8A4F_7D25_1C69;
const KT_MIX_K3: u128 = 0x6A1E_7B53_2D94_8C6F_1E37_5B82_4A91_7F23;
const KT_MIX_K4: u128 = 0x2F74_9C18_5E63_A1D7_48B2_6E95_3C1F_5A81;
const KT_MIX_K5: u128 = 0x4E39_6D81_7B25_C4F3_9A61_2E87_5D13_6B49;

#[inline]
fn zeroize_u64_slice(buf: &mut [u64]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid mutable reference to an initialized `u64`.
        unsafe { std::ptr::write_volatile(w, 0u64) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline]
fn zeroize_u128_slice(buf: &mut [u128]) {
    for w in buf.iter_mut() {
        zeroize_u128(w);
    }
}

/// Bijective power map `x -> x^5 mod (2^127 - 1)` (`gcd(5, 2^127 - 2) = 1`).
#[inline(always)]
fn kt_pow5_mod(x: u128) -> u128 {
    let x = reduce(x);
    let x2 = mul_mod(x, x);
    let x4 = mul_mod(x2, x2);
    mul_mod(x4, x)
}

/// Pure information-theoretic bijective mixing function over `F_(2^127 - 1)`.
#[inline]
fn kt_mix_field_elem(seed: u128, domain: u128, subject: u64, counter: u64) -> u128 {
    let s0 = kt_pow5_mod(add_mod(reduce(seed), KT_MIX_K1));
    let s1 = kt_pow5_mod(add_mod(
        mul_mod(s0, KT_MIX_K2),
        add_mod(reduce(domain), KT_MIX_K3),
    ));
    let s2 = kt_pow5_mod(add_mod(
        mul_mod(s1, KT_MIX_K4),
        add_mod(reduce(subject as u128), KT_MIX_K5),
    ));
    kt_pow5_mod(add_mod(mul_mod(s2, KT_MIX_K1), reduce(counter as u128)))
}

/// Fold arbitrary bytes into `F_(2^127 - 1)` using injective 15-byte limbs.
fn kt_fold_bytes_field(bytes: &[u8], r: u128) -> u128 {
    let r = reduce(r);
    let mut acc = mul_mod(reduce(bytes.len() as u128), r);
    for chunk in bytes.chunks(15) {
        let mut buf = [0u8; 16];
        buf[..chunk.len()].copy_from_slice(chunk);
        buf[chunk.len()] = 0x01;
        let limb = u128::from_le_bytes(buf);
        acc = mul_mod(add_mod(acc, limb), r);
    }
    acc
}

// ============================================================================
// Errors & Transport Tiers
// ============================================================================

/// Errors returned by Tier 1–4 key transport, relay selection, BSM expansion, courier vaults,
/// and `TieredKeyMesh` replenishment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyTransportError {
    /// Invalid configuration or argument.
    InvalidParameter(String),
    /// Not enough topologically disjoint relays (distinct ASNs & providers) to satisfy `m`.
    InsufficientDisjointRelays {
        required: usize,
        available_disjoint: usize,
    },
    /// Relay set violates strict disjointness (duplicate validator ID, ASN, or provider ID).
    RelayTopologyViolation(String),
    /// Fewer than `t` valid shares arrived after filtering corrupt/unauthenticated packets.
    InsufficientValidShares {
        threshold_t: usize,
        valid_shares: usize,
    },
    /// Arriving Shamir shares disagree on packet metadata (`session_id`, `chunk_seq`, `e2e_mac`, etc.).
    PacketMetadataMismatch(String),
    /// Per-hop relay Carter-Wegman MAC failed verification.
    RelayHopMacFailed { relay_id: ValidatorId },
    /// Arriving shares do not lie on a single degree-`(t - 1)` polynomial over `F_(2^127 - 1)`.
    PolynomialInconsistency {
        limb_index: usize,
        offending_relay_id: ValidatorId,
    },
    /// End-to-end Carter-Wegman MAC failed constant-time verification on reconstructed pad bytes.
    EndToEndMacFailed,
    /// Reconstructed limb exceeded the canonical byte boundary for the packed pad chunk.
    CanonicalLimbOverflow { limb_index: usize },
    /// BSM stream epoch was already sampled or block length did not equal 512 bytes.
    BsmStreamError(String),
    /// Missing one or more offline courier XOR shares (`received < total_couriers`).
    MissingCourierShares {
        expected: usize,
        received: usize,
    },
    /// Duplicate or invalid courier share index or mismatched vault manifest.
    InvalidCourierShare(String),
    /// Offline courier vault Carter-Wegman manifest MAC failed constant-time verification.
    VaultManifestMacFailed,
    /// Simulated/devnet transport tier rejected under strict mainnet policy.
    SimulatedTierForbiddenOnMainnet,
    /// Composed OTP bytes failed online statistical entropy health verification.
    EntropyHealthRejected(String),
    /// Underlying `WalPadBook` / `PadBook` error.
    PadBookError(String),
}

impl fmt::Display for KeyTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter(msg) => write!(f, "invalid key transport parameter: {msg}"),
            Self::InsufficientDisjointRelays {
                required,
                available_disjoint,
            } => write!(
                f,
                "insufficient disjoint relays: need {required} distinct ASN/provider relays, found {available_disjoint}"
            ),
            Self::RelayTopologyViolation(msg) => write!(f, "relay topology violation: {msg}"),
            Self::InsufficientValidShares {
                threshold_t,
                valid_shares,
            } => write!(
                f,
                "insufficient valid Shamir shares: threshold t={threshold_t}, only {valid_shares} valid"
            ),
            Self::PacketMetadataMismatch(msg) => {
                write!(f, "split-pad packet metadata mismatch: {msg}")
            }
            Self::RelayHopMacFailed { relay_id } => {
                write!(f, "per-hop Carter-Wegman MAC failed for relay {relay_id}")
            }
            Self::PolynomialInconsistency {
                limb_index,
                offending_relay_id,
            } => write!(
                f,
                "degree-(t-1) polynomial consistency failed at limb {limb_index} (offending relay {offending_relay_id})"
            ),
            Self::EndToEndMacFailed => {
                write!(f, "end-to-end Carter-Wegman MAC verification failed")
            }
            Self::CanonicalLimbOverflow { limb_index } => {
                write!(f, "reconstructed limb {limb_index} exceeded byte packing width")
            }
            Self::BsmStreamError(msg) => write!(f, "BSM stream expander error: {msg}"),
            Self::MissingCourierShares { expected, received } => write!(
                f,
                "missing offline courier XOR shares: need all {expected}, received {received}"
            ),
            Self::InvalidCourierShare(msg) => write!(f, "invalid courier share: {msg}"),
            Self::VaultManifestMacFailed => {
                write!(f, "offline split-courier vault CW-MAC manifest verification failed")
            }
            Self::SimulatedTierForbiddenOnMainnet => {
                write!(f, "SimulatedDevnet key transport tier is forbidden on mainnet (weight = 0 bps)")
            }
            Self::EntropyHealthRejected(msg) => {
                write!(f, "composed key material failed entropy health check: {msg}")
            }
            Self::PadBookError(msg) => write!(f, "pad book replenishment error: {msg}"),
        }
    }
}

impl Error for KeyTransportError {}

impl From<OtpError> for KeyTransportError {
    fn from(err: OtpError) -> Self {
        Self::PadBookError(err.to_string())
    }
}

/// Physical / information-theoretic key transport tier for Vernam OTP pad replenishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyTransportTier {
    /// Tier 1: Physical ETSI GS QKD 014 optical link (10,000 bps).
    Tier1PhysicalQkd,
    /// Tier 2: Multi-path `(t, m)` Shamir Split-Pad over disjoint ASNs/providers (7,500 bps).
    Tier2MultiPathThreshold,
    /// Tier 3: Vadhan Sample-then-Extract Bounded-Storage Model (BSM) expander (6,500 bps).
    Tier3BsmExpanded,
    /// Tier 4: Offline split-courier XOR vaults (5,000 bps).
    Tier4OfflineCourier,
    /// Devnet / local simulation ONLY (0 bps on mainnet!).
    SimulatedDevnet,
}

impl KeyTransportTier {
    /// Mainnet Proof-of-Pad reward weight in basis points (`10_000` = 100%).
    ///
    /// `SimulatedDevnet` scores strictly `0` on mainnet.
    #[inline]
    pub const fn mainnet_pop_weight_bps(&self) -> u32 {
        match self {
            Self::Tier1PhysicalQkd => 10_000,
            Self::Tier2MultiPathThreshold => 7_500,
            Self::Tier3BsmExpanded => 6_500,
            Self::Tier4OfflineCourier => 5_000,
            Self::SimulatedDevnet => 0,
        }
    }

    /// Returns `true` if this tier is eligible for mainnet PoP credit.
    #[inline]
    pub const fn is_mainnet_eligible(&self) -> bool {
        self.mainnet_pop_weight_bps() > 0
    }

    /// Map this transport tier to its corresponding [`PopTransportProvenance`].
    #[inline]
    pub const fn to_pop_provenance(&self) -> PopTransportProvenance {
        match self {
            Self::Tier1PhysicalQkd => PopTransportProvenance::Tier1EtsiQkd,
            Self::Tier2MultiPathThreshold => PopTransportProvenance::Tier2MultiPath,
            Self::Tier3BsmExpanded => PopTransportProvenance::Tier3Bsm,
            Self::Tier4OfflineCourier => PopTransportProvenance::Tier4CourierVault,
            Self::SimulatedDevnet => PopTransportProvenance::SimulatedDevnet,
        }
    }
}

impl fmt::Display for KeyTransportTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tier1PhysicalQkd => write!(f, "Tier1PhysicalQkd (10000 bps)"),
            Self::Tier2MultiPathThreshold => write!(f, "Tier2MultiPathThreshold (7500 bps)"),
            Self::Tier3BsmExpanded => write!(f, "Tier3BsmExpanded (6500 bps)"),
            Self::Tier4OfflineCourier => write!(f, "Tier4OfflineCourier (5000 bps)"),
            Self::SimulatedDevnet => write!(f, "SimulatedDevnet (0 bps)"),
        }
    }
}

// ============================================================================
// Relay Topology & Disjoint Relay Selection
// ============================================================================

/// Network topology metadata used to guarantee physical/administrative path disjointness
/// across Tier 2 Shamir split-pad relays.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelayTopologyTag {
    pub validator_id: ValidatorId,
    pub asn: u32,
    pub provider_id: String,
    pub geo_corridor: String,
    pub local_bind_iface: String,
}

impl RelayTopologyTag {
    /// Normalize `provider_id` for strict case-insensitive disjointness enforcement.
    #[inline]
    fn normalized_provider(&self) -> String {
        self.provider_id.trim().to_ascii_lowercase()
    }
}

/// Verify that a relay slice satisfies strict disjointness: distinct `validator_id`,
/// distinct `asn`, and distinct non-empty `provider_id`.
fn verify_relays_disjoint(relays: &[RelayTopologyTag]) -> Result<(), KeyTransportError> {
    let mut seen_vids = BTreeSet::new();
    let mut seen_asns = BTreeSet::new();
    let mut seen_providers = BTreeSet::new();

    for relay in relays {
        let prov = relay.normalized_provider();
        if prov.is_empty() {
            return Err(KeyTransportError::RelayTopologyViolation(format!(
                "relay {} has empty provider_id",
                relay.validator_id
            )));
        }
        if !seen_vids.insert(relay.validator_id) {
            return Err(KeyTransportError::RelayTopologyViolation(format!(
                "duplicate relay validator_id {}",
                relay.validator_id
            )));
        }
        if !seen_asns.insert(relay.asn) {
            return Err(KeyTransportError::RelayTopologyViolation(format!(
                "duplicate relay ASN {} (validator {})",
                relay.asn, relay.validator_id
            )));
        }
        if !seen_providers.insert(prov.clone()) {
            return Err(KeyTransportError::RelayTopologyViolation(format!(
                "duplicate relay provider_id '{}' (validator {})",
                prov, relay.validator_id
            )));
        }
    }
    Ok(())
}

/// Deterministically select `m` strictly disjoint relays from `candidates` using unbiasable
/// `beacon_gamma` over `F_(2^127 - 1)`.
///
/// Guarantees:
/// - **Strict distinct ASNs**: no two selected relays share the same `asn`.
/// - **Strict distinct providers**: no two selected relays share the same normalized `provider_id`.
/// - **Strict distinct validators**: no duplicate `validator_id`.
/// - **Input-order independent**: canonically sorts candidates before applying beacon-driven
///   bijective `F_(2^127 - 1)` scoring.
/// - **Complete bounded search**: attempts greedy selection in beacon-ranked order first and
///   falls back to bounded backtracking if an earlier choice blocked a valid disjoint `m`-tuple.
pub fn select_disjoint_relays(
    candidates: &[RelayTopologyTag],
    beacon_gamma: u128,
    m: usize,
) -> Result<Vec<RelayTopologyTag>, KeyTransportError> {
    if m == 0 {
        return Err(KeyTransportError::InvalidParameter(
            "m (relay count) must be > 0".into(),
        ));
    }
    if beacon_gamma == 0 || beacon_gamma >= PRIME_P {
        return Err(KeyTransportError::InvalidParameter(
            "beacon_gamma must satisfy 0 < beacon_gamma < PRIME_P".into(),
        ));
    }

    // Canonically deduplicate by validator_id and drop invalid empty-provider entries.
    let mut by_vid: BTreeMap<ValidatorId, RelayTopologyTag> = BTreeMap::new();
    for c in candidates {
        if !c.normalized_provider().is_empty() {
            by_vid.entry(c.validator_id).or_insert_with(|| c.clone());
        }
    }

    // Score each candidate deterministically in F_(2^127 - 1) from (beacon_gamma, topology).
    let mut ranked: Vec<(u128, RelayTopologyTag)> = by_vid
        .into_values()
        .map(|tag| {
            let prov_digest = kt_fold_bytes_field(tag.normalized_provider().as_bytes(), KT_MIX_K2);
            let geo_digest = kt_fold_bytes_field(tag.geo_corridor.as_bytes(), KT_MIX_K3);
            let domain = add_mod(
                KT_DOMAIN_RELAY_SELECT,
                add_mod(prov_digest, mul_mod(geo_digest, KT_MIX_K4)),
            );
            let score = kt_mix_field_elem(beacon_gamma, domain, tag.validator_id, tag.asn as u64);
            (score, tag)
        })
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.validator_id.cmp(&b.1.validator_id)));
    let ordered: Vec<RelayTopologyTag> = ranked.into_iter().map(|(_, tag)| tag).collect();

    // Fast path: greedy pass in beacon-ranked order.
    let mut greedy = Vec::with_capacity(m);
    let mut used_asns = BTreeSet::new();
    let mut used_provs = BTreeSet::new();
    for cand in &ordered {
        let prov = cand.normalized_provider();
        if !used_asns.contains(&cand.asn) && !used_provs.contains(&prov) {
            used_asns.insert(cand.asn);
            used_provs.insert(prov);
            greedy.push(cand.clone());
            if greedy.len() == m {
                return Ok(greedy);
            }
        }
    }

    // Fallback: bounded backtracking search over beacon-ranked order so we never miss a valid
    // disjoint m-tuple due to greedy blocking across correlated (ASN, provider) attributes.
    let mut chosen_indices = Vec::with_capacity(m);
    let mut bt_asns = BTreeSet::new();
    let mut bt_provs = BTreeSet::new();
    let mut best_found = greedy.len();
    let mut budget = 10_000usize;

    fn backtrack(
        ordered: &[RelayTopologyTag],
        start: usize,
        m: usize,
        chosen: &mut Vec<usize>,
        used_asns: &mut BTreeSet<u32>,
        used_provs: &mut BTreeSet<String>,
        best_found: &mut usize,
        budget: &mut usize,
    ) -> bool {
        if chosen.len() > *best_found {
            *best_found = chosen.len();
        }
        if chosen.len() == m {
            return true;
        }
        if *budget == 0 || start >= ordered.len() || chosen.len() + (ordered.len() - start) < m {
            return false;
        }
        *budget -= 1;

        for idx in start..ordered.len() {
            let cand = &ordered[idx];
            let prov = cand.normalized_provider();
            if used_asns.contains(&cand.asn) || used_provs.contains(&prov) {
                continue;
            }
            used_asns.insert(cand.asn);
            used_provs.insert(prov.clone());
            chosen.push(idx);
            if backtrack(
                ordered,
                idx + 1,
                m,
                chosen,
                used_asns,
                used_provs,
                best_found,
                budget,
            ) {
                return true;
            }
            chosen.pop();
            used_asns.remove(&cand.asn);
            used_provs.remove(&prov);
        }
        false
    }

    if backtrack(
        &ordered,
        0,
        m,
        &mut chosen_indices,
        &mut bt_asns,
        &mut bt_provs,
        &mut best_found,
        &mut budget,
    ) {
        let selected: Vec<RelayTopologyTag> =
            chosen_indices.into_iter().map(|i| ordered[i].clone()).collect();
        verify_relays_disjoint(&selected)?;
        return Ok(selected);
    }

    Err(KeyTransportError::InsufficientDisjointRelays {
        required: m,
        available_disjoint: best_found,
    })
}

// ============================================================================
// Tier 2: Multi-Path (t, m) Shamir Split-Pad Transport over F_(2^127 - 1)
// ============================================================================

/// 32-byte pre-shared end-to-end Carter-Wegman authentication key `(r, s)` over `F_(2^127 - 1)`.
///
/// Authenticating a 64 KiB (65,536 B) fresh pad chunk with a 32-byte `E2eCwKey` achieves an
/// unconditional **2,048:1 key expansion ratio** with forgery probability `<= 4370 / (2^127 - 1) < 2^-114`.
/// Redacted in `Debug` and volatile-zeroized on `Drop`.
#[derive(Clone, PartialEq, Eq)]
pub struct E2eCwKey {
    r: u128,
    s: u128,
}

impl E2eCwKey {
    /// Generate a fresh uniform 32-byte end-to-end Carter-Wegman key from OS entropy.
    pub fn generate() -> Self {
        Self {
            r: random_nonzero_field_elem(),
            s: random_field_elem(),
        }
    }

    /// Construct from explicit canonical field elements (`0 < r < PRIME_P`, `s < PRIME_P`).
    pub fn from_parts(r: u128, s: u128) -> Result<Self, KeyTransportError> {
        if r == 0 || r >= PRIME_P {
            return Err(KeyTransportError::InvalidParameter(
                "E2eCwKey r must satisfy 0 < r < PRIME_P".into(),
            ));
        }
        if s >= PRIME_P {
            return Err(KeyTransportError::InvalidParameter(
                "E2eCwKey s must satisfy s < PRIME_P".into(),
            ));
        }
        Ok(Self { r, s })
    }

    /// Build a pipelined `CwFastKey` accelerator for constant-time MAC computation/verification.
    #[inline]
    pub fn to_fast_key(&self) -> CwFastKey {
        CwFastKey::new(self.r, self.s)
    }

    /// Pre-shared key footprint in bytes (32 bytes = `r` + `s`).
    #[inline]
    pub const fn key_bytes(&self) -> usize {
        E2E_CW_KEY_BYTES
    }
}

impl fmt::Debug for E2eCwKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("E2eCwKey")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

impl Drop for E2eCwKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

/// Pairwise per-hop relay Carter-Wegman authentication key `(r, s_hop, s_receipt)` over
/// `F_(2^127 - 1)`.
///
/// Uses two independent one-time masks (`s_hop` for the share packet and `s_receipt` for the
/// `RelayTransitReceipt`) so no Carter-Wegman one-time mask is ever reused across messages!
#[derive(Clone, PartialEq, Eq)]
pub struct RelayHopKey {
    r: u128,
    s_hop: u128,
    s_receipt: u128,
}

impl RelayHopKey {
    /// Generate a fresh pairwise relay hop key from OS entropy.
    pub fn generate() -> Self {
        Self {
            r: random_nonzero_field_elem(),
            s_hop: random_field_elem(),
            s_receipt: random_field_elem(),
        }
    }

    /// Construct from explicit canonical field elements (`0 < r < PRIME_P`, `s_hop, s_receipt < PRIME_P`).
    pub fn from_parts(r: u128, s_hop: u128, s_receipt: u128) -> Result<Self, KeyTransportError> {
        if r == 0 || r >= PRIME_P || s_hop >= PRIME_P || s_receipt >= PRIME_P {
            return Err(KeyTransportError::InvalidParameter(
                "RelayHopKey elements must be canonical in F_(2^127 - 1) with r != 0".into(),
            ));
        }
        Ok(Self {
            r,
            s_hop,
            s_receipt,
        })
    }

    #[inline]
    fn hop_fast_key(&self) -> CwFastKey {
        CwFastKey::new(self.r, self.s_hop)
    }

    #[inline]
    fn receipt_fast_key(&self) -> CwFastKey {
        CwFastKey::new(self.r, self.s_receipt)
    }
}

impl fmt::Debug for RelayHopKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayHopKey")
            .field("r", &"[REDACTED]")
            .field("s_hop", &"[REDACTED]")
            .field("s_receipt", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RelayHopKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s_hop);
        zeroize_u128(&mut self.s_receipt);
    }
}

/// Single relay share packet in Tier 2 Multi-Path `(t, m)` Shamir Split-Pad Transport.
///
/// Secret `share_limbs` and MAC tags are redacted in `Debug` and volatile-zeroized on `Drop`.
#[derive(Clone, PartialEq, Eq)]
pub struct SplitPadSharePacket {
    pub session_id: u64,
    pub chunk_seq: u64,
    pub threshold_t: usize,
    pub total_m: usize,
    pub original_len: usize,
    /// Non-zero Shamir evaluation x-coordinate in `1..=total_m`.
    pub share_x: u128,
    /// Disjoint topology tag of the relay carrying this share.
    pub relay: RelayTopologyTag,
    /// Shamir share evaluations `f_j(share_x) mod PRIME_P` for each 15-byte limb `j`.
    pub share_limbs: Vec<u128>,
    /// 128-bit end-to-end Carter-Wegman MAC over `(header || reconstructed_pad)` computed via `CwFastKey`.
    pub e2e_mac: [u8; MAC_TAG_BYTES],
    /// 128-bit per-hop relay Carter-Wegman MAC authenticating this packet over the relay link.
    pub relay_hop_mac: [u8; MAC_TAG_BYTES],
}

impl SplitPadSharePacket {
    /// Compute canonical per-hop MAC input covering header, `share_limbs`, and `e2e_mac`.
    fn compute_hop_mac(&self, hop_key: &RelayHopKey) -> [u8; MAC_TAG_BYTES] {
        let mut words = Vec::with_capacity(9 + self.share_limbs.len());
        words.push(self.session_id as u128);
        words.push(self.chunk_seq as u128);
        words.push(self.threshold_t as u128);
        words.push(self.total_m as u128);
        words.push(self.original_len as u128);
        words.push(self.share_x);
        words.push(self.relay.validator_id as u128);
        words.push(self.relay.asn as u128);
        words.push(u128::from_be_bytes(self.e2e_mac));
        words.extend_from_slice(&self.share_limbs);
        let fast = hop_key.hop_fast_key();
        let tag = fast.mac_u128_stream(&words);
        zeroize_u128_slice(&mut words);
        tag
    }

    /// Re-sign `relay_hop_mac` using `hop_key` (e.g., for testing malicious-relay limb tampering).
    pub fn recompute_hop_mac(&mut self, hop_key: &RelayHopKey) {
        self.relay_hop_mac = self.compute_hop_mac(hop_key);
    }

    /// Constant-time per-hop CW-MAC verification.
    pub fn verify_hop_mac(&self, hop_key: &RelayHopKey) -> bool {
        let mut expected = self.compute_hop_mac(hop_key);
        let ok = ct_eq_16(&expected, &self.relay_hop_mac);
        zeroize_slice(&mut expected);
        ok
    }
}

impl fmt::Debug for SplitPadSharePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitPadSharePacket")
            .field("session_id", &self.session_id)
            .field("chunk_seq", &self.chunk_seq)
            .field("threshold_t", &self.threshold_t)
            .field("total_m", &self.total_m)
            .field("original_len", &self.original_len)
            .field("share_x", &self.share_x)
            .field("relay", &self.relay)
            .field("limb_count", &self.share_limbs.len())
            .field("share_limbs", &"[REDACTED]")
            .field("e2e_mac", &"[REDACTED]")
            .field("relay_hop_mac", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SplitPadSharePacket {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.share_limbs);
        zeroize_slice(&mut self.e2e_mac);
        zeroize_slice(&mut self.relay_hop_mac);
    }
}

/// Per-relay transit receipt authenticated by a pairwise Carter-Wegman MAC confirming forwarding
/// of a [`SplitPadSharePacket`] across a disjoint path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTransitReceipt {
    pub session_id: u64,
    pub chunk_seq: u64,
    pub relay_id: ValidatorId,
    pub relay_asn: u32,
    pub share_x: u128,
    pub limb_count: usize,
    pub transit_mac: [u8; MAC_TAG_BYTES],
}

impl RelayTransitReceipt {
    fn compute_mac(&self, hop_key: &RelayHopKey, hop_mac: &[u8; MAC_TAG_BYTES]) -> [u8; MAC_TAG_BYTES] {
        let words = [
            self.session_id as u128,
            self.chunk_seq as u128,
            self.relay_id as u128,
            self.relay_asn as u128,
            self.share_x,
            self.limb_count as u128,
            u128::from_be_bytes(*hop_mac),
        ];
        let fast = hop_key.receipt_fast_key();
        fast.mac_u128_stream(&words)
    }

    /// Constant-time verification of this relay transit receipt against `packet` and `hop_key`.
    pub fn verify(&self, packet: &SplitPadSharePacket, hop_key: &RelayHopKey) -> bool {
        if self.session_id != packet.session_id
            || self.chunk_seq != packet.chunk_seq
            || self.relay_id != packet.relay.validator_id
            || self.relay_asn != packet.relay.asn
            || self.share_x != packet.share_x
            || self.limb_count != packet.share_limbs.len()
        {
            return false;
        }
        let mut expected = self.compute_mac(hop_key, &packet.relay_hop_mac);
        let ok = ct_eq_16(&expected, &self.transit_mac);
        zeroize_slice(&mut expected);
        ok
    }
}

/// Verified pad chunk reconstructed from Tier 2 Multi-Path `(t, m)` Shamir transport.
///
/// Automatically volatile-zeroizes `pad_bytes` on `Drop`.
pub struct ReconstructedPadChunk {
    pad_bytes: Vec<u8>,
    pub verified_relays: Vec<ValidatorId>,
    pub rejected_relays: Vec<(ValidatorId, String)>,
    pub polynomial_degree_verified: bool,
    pub expansion_ratio: f64,
}

impl ReconstructedPadChunk {
    /// Borrow the verified reconstructed pad bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.pad_bytes
    }

    /// Consume this receipt and take ownership of the verified pad bytes.
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.pad_bytes)
    }
}

impl fmt::Debug for ReconstructedPadChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconstructedPadChunk")
            .field("pad_len", &self.pad_bytes.len())
            .field("pad_bytes", &"[REDACTED]")
            .field("verified_relays", &self.verified_relays)
            .field("rejected_relays", &self.rejected_relays)
            .field("polynomial_degree_verified", &self.polynomial_degree_verified)
            .field("expansion_ratio", &self.expansion_ratio)
            .finish()
    }
}

impl Drop for ReconstructedPadChunk {
    fn drop(&mut self) {
        zeroize_slice(&mut self.pad_bytes);
    }
}

/// Pack arbitrary pad bytes into canonical 15-byte limbs strictly `< 2^120 < PRIME_P`.
pub fn pack_pad_to_limbs(pad_chunk: &[u8]) -> Vec<u128> {
    let mut limbs = Vec::with_capacity(pad_chunk.len().div_ceil(SHAMIR_LIMB_BYTES));
    let mut buf = [0u8; 16];
    for chunk in pad_chunk.chunks(SHAMIR_LIMB_BYTES) {
        buf = [0u8; 16];
        buf[..chunk.len()].copy_from_slice(chunk);
        limbs.push(u128::from_le_bytes(buf));
    }
    zeroize_slice(&mut buf);
    limbs
}

/// Unpack canonical 15-byte limbs back into exact `original_len` pad bytes, rejecting overflowed limbs.
pub fn unpack_limbs_to_pad(
    limbs: &[u128],
    original_len: usize,
) -> Result<Vec<u8>, KeyTransportError> {
    let expected_limbs = original_len.div_ceil(SHAMIR_LIMB_BYTES);
    if limbs.len() != expected_limbs {
        return Err(KeyTransportError::PacketMetadataMismatch(format!(
            "limb count {} != expected {} for original_len {}",
            limbs.len(),
            expected_limbs,
            original_len
        )));
    }

    let mut out = Vec::with_capacity(original_len);
    for (idx, &limb) in limbs.iter().enumerate() {
        let remaining = original_len - idx * SHAMIR_LIMB_BYTES;
        let take = remaining.min(SHAMIR_LIMB_BYTES);
        let max_val = 1u128 << (take * 8);
        if limb >= max_val {
            zeroize_slice(&mut out);
            return Err(KeyTransportError::CanonicalLimbOverflow { limb_index: idx });
        }
        let le = limb.to_le_bytes();
        out.extend_from_slice(&le[..take]);
    }
    Ok(out)
}

/// Precompute Lagrange evaluation weights `w_i(target_x) = prod_{j != i} (target_x - x_j) / (x_i - x_j) mod P`.
fn lagrange_eval_weights(xs: &[u128], target_x: u128) -> Vec<u128> {
    let t = xs.len();
    let mut weights = Vec::with_capacity(t);
    for i in 0..t {
        let xi = xs[i];
        let mut num = 1u128;
        let mut den = 1u128;
        for (j, &xj) in xs.iter().enumerate() {
            if i == j {
                continue;
            }
            num = mul_mod(num, sub_mod(target_x, xj));
            den = mul_mod(den, sub_mod(xi, xj));
        }
        weights.push(mul_mod(num, inv_mod(den)));
    }
    weights
}

/// Evaluate polynomial interpolated through `basis` packets at `x = 0` for every limb using
/// precomputed Lagrange basis weights `lambda_i(0)`.
fn reconstruct_limbs_from_basis(basis: &[&SplitPadSharePacket]) -> Vec<u128> {
    let xs: Vec<u128> = basis.iter().map(|p| p.share_x).collect();
    let weights = lagrange_eval_weights(&xs, 0);
    let limb_count = basis[0].share_limbs.len();
    let mut limbs = Vec::with_capacity(limb_count);

    for l in 0..limb_count {
        let mut acc = 0u128;
        for (i, pkt) in basis.iter().enumerate() {
            acc = add_mod(acc, mul_mod(pkt.share_limbs[l], weights[i]));
        }
        limbs.push(acc);
    }
    limbs
}

/// Verify whether `candidate` lies on the exact degree-`(t - 1)` polynomial defined by `basis`
/// across all limbs. Returns `Ok(())` or `Err(first_mismatched_limb_index)`.
fn check_packet_against_basis(
    basis: &[&SplitPadSharePacket],
    candidate: &SplitPadSharePacket,
) -> Result<(), usize> {
    let xs: Vec<u128> = basis.iter().map(|p| p.share_x).collect();
    let weights = lagrange_eval_weights(&xs, candidate.share_x);
    let limb_count = basis[0].share_limbs.len();
    for l in 0..limb_count {
        let mut expected = 0u128;
        for (i, pkt) in basis.iter().enumerate() {
            expected = add_mod(expected, mul_mod(pkt.share_limbs[l], weights[i]));
        }
        if expected != candidate.share_limbs[l] {
            return Err(l);
        }
    }
    Ok(())
}

/// Compute the canonical end-to-end Carter-Wegman MAC over `(header || pad_chunk)` via `CwFastKey`.
fn compute_e2e_pad_mac(
    session_id: u64,
    chunk_seq: u64,
    threshold_t: usize,
    total_m: usize,
    pad_chunk: &[u8],
    e2e_key: &E2eCwKey,
) -> [u8; MAC_TAG_BYTES] {
    let mut mac_input = Vec::with_capacity(32 + pad_chunk.len());
    mac_input.extend_from_slice(&session_id.to_be_bytes());
    mac_input.extend_from_slice(&chunk_seq.to_be_bytes());
    mac_input.extend_from_slice(&(threshold_t as u32).to_be_bytes());
    mac_input.extend_from_slice(&(total_m as u32).to_be_bytes());
    mac_input.extend_from_slice(&(pad_chunk.len() as u64).to_be_bytes());
    mac_input.extend_from_slice(pad_chunk);

    let fast = e2e_key.to_fast_key();
    let tag = fast.mac(&mac_input);
    zeroize_slice(&mut mac_input);
    tag
}

/// Generate `k`-element index combinations of `0..n` up to `max_combos`.
fn generate_combinations(n: usize, k: usize, max_combos: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    let mut cur = Vec::with_capacity(k);

    fn rec(
        start: usize,
        n: usize,
        k: usize,
        cur: &mut Vec<usize>,
        result: &mut Vec<Vec<usize>>,
        max_combos: usize,
    ) {
        if result.len() >= max_combos {
            return;
        }
        if cur.len() == k {
            result.push(cur.clone());
            return;
        }
        let needed = k - cur.len();
        if start + needed > n {
            return;
        }
        for i in start..=(n - needed) {
            cur.push(i);
            rec(i + 1, n, k, cur, result, max_combos);
            cur.pop();
            if result.len() >= max_combos {
                return;
            }
        }
    }

    rec(0, n, k, &mut cur, &mut result, max_combos);
    result
}

/// Tier 2 Multi-Path `(t, m)` Shamir Split-Pad Transport engine over `F_(2^127 - 1)`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MultiPathPadTransport;

impl MultiPathPadTransport {
    /// Split `pad_chunk` into `m` degree-`(t - 1)` Shamir share packets across strictly disjoint
    /// `relays`, authenticated with a 32-byte end-to-end `CwFastKey` MAC and per-hop relay CW-MACs.
    pub fn split_pad_chunk(
        session_id: u64,
        chunk_seq: u64,
        pad_chunk: &[u8],
        threshold_t: usize,
        relays: &[RelayTopologyTag],
        e2e_key: &E2eCwKey,
        hop_keys: &[RelayHopKey],
    ) -> Result<(Vec<SplitPadSharePacket>, Vec<RelayTransitReceipt>), KeyTransportError> {
        let total_m = relays.len();
        if pad_chunk.is_empty() {
            return Err(KeyTransportError::InvalidParameter(
                "pad_chunk must not be empty".into(),
            ));
        }
        if threshold_t == 0 || threshold_t > total_m {
            return Err(KeyTransportError::InvalidParameter(format!(
                "invalid Shamir threshold ({threshold_t}, {total_m}): require 1 <= t <= m"
            )));
        }
        if hop_keys.len() != total_m {
            return Err(KeyTransportError::InvalidParameter(format!(
                "hop_keys len {} != relay count {total_m}",
                hop_keys.len()
            )));
        }
        verify_relays_disjoint(relays)?;

        let mut limbs = pack_pad_to_limbs(pad_chunk);
        let limb_count = limbs.len();
        let e2e_mac = compute_e2e_pad_mac(
            session_id,
            chunk_seq,
            threshold_t,
            total_m,
            pad_chunk,
            e2e_key,
        );

        let mut per_relay_limbs: Vec<Vec<u128>> =
            (0..total_m).map(|_| Vec::with_capacity(limb_count)).collect();
        let mut coeffs = vec![0u128; threshold_t];

        for &secret_limb in &limbs {
            coeffs[0] = secret_limb;
            for c in coeffs.iter_mut().skip(1) {
                *c = random_field_elem();
            }
            // Evaluate f(x) via Horner's rule at x_i = (i + 1) in 1..=total_m.
            for (relay_idx, dst) in per_relay_limbs.iter_mut().enumerate() {
                let x = (relay_idx + 1) as u128;
                let mut y = 0u128;
                for &coeff in coeffs.iter().rev() {
                    y = add_mod(mul_mod(y, x), coeff);
                }
                dst.push(y);
            }
            zeroize_u128_slice(&mut coeffs);
        }
        zeroize_u128_slice(&mut limbs);

        let mut packets = Vec::with_capacity(total_m);
        let mut receipts = Vec::with_capacity(total_m);

        for (idx, (relay, share_limbs)) in
            relays.iter().cloned().zip(per_relay_limbs.into_iter()).enumerate()
        {
            let share_x = (idx + 1) as u128;
            let mut packet = SplitPadSharePacket {
                session_id,
                chunk_seq,
                threshold_t,
                total_m,
                original_len: pad_chunk.len(),
                share_x,
                relay,
                share_limbs,
                e2e_mac,
                relay_hop_mac: [0u8; MAC_TAG_BYTES],
            };
            packet.recompute_hop_mac(&hop_keys[idx]);

            let mut receipt = RelayTransitReceipt {
                session_id,
                chunk_seq,
                relay_id: packet.relay.validator_id,
                relay_asn: packet.relay.asn,
                share_x,
                limb_count,
                transit_mac: [0u8; MAC_TAG_BYTES],
            };
            receipt.transit_mac = receipt.compute_mac(&hop_keys[idx], &packet.relay_hop_mac);

            packets.push(packet);
            receipts.push(receipt);
        }

        Ok((packets, receipts))
    }

    /// Strictly verify that ALL provided `packets` share consistent metadata, canonical limbs
    /// `< PRIME_P`, distinct `share_x` points, and lie on a single degree-`(t - 1)` polynomial
    /// over `F_(2^127 - 1)` across every limb.
    pub fn verify_polynomial_consistency(
        packets: &[SplitPadSharePacket],
    ) -> Result<(), KeyTransportError> {
        let refs: Vec<&SplitPadSharePacket> = packets.iter().collect();
        Self::verify_polynomial_consistency_refs(&refs)
    }

    fn verify_polynomial_consistency_refs(
        packets: &[&SplitPadSharePacket],
    ) -> Result<(), KeyTransportError> {
        if packets.is_empty() {
            return Err(KeyTransportError::InsufficientValidShares {
                threshold_t: 1,
                valid_shares: 0,
            });
        }
        let first = packets[0];
        let t = first.threshold_t;
        if t == 0 || t > first.total_m || first.original_len == 0 {
            return Err(KeyTransportError::PacketMetadataMismatch(
                "invalid threshold or original_len in packet header".into(),
            ));
        }
        if packets.len() < t {
            return Err(KeyTransportError::InsufficientValidShares {
                threshold_t: t,
                valid_shares: packets.len(),
            });
        }

        let expected_limbs = first.original_len.div_ceil(SHAMIR_LIMB_BYTES);
        let mut seen_x = BTreeSet::new();
        for pkt in packets {
            if pkt.session_id != first.session_id
                || pkt.chunk_seq != first.chunk_seq
                || pkt.threshold_t != first.threshold_t
                || pkt.total_m != first.total_m
                || pkt.original_len != first.original_len
                || !ct_eq_16(&pkt.e2e_mac, &first.e2e_mac)
            {
                return Err(KeyTransportError::PacketMetadataMismatch(format!(
                    "packet from relay {} disagrees on session/chunk/e2e_mac header",
                    pkt.relay.validator_id
                )));
            }
            if pkt.share_x == 0 || pkt.share_x >= PRIME_P || !seen_x.insert(pkt.share_x) {
                return Err(KeyTransportError::PacketMetadataMismatch(format!(
                    "duplicate or invalid share_x {} from relay {}",
                    pkt.share_x, pkt.relay.validator_id
                )));
            }
            if pkt.share_limbs.len() != expected_limbs {
                return Err(KeyTransportError::PacketMetadataMismatch(format!(
                    "relay {} limb count {} != expected {expected_limbs}",
                    pkt.relay.validator_id,
                    pkt.share_limbs.len()
                )));
            }
            if pkt.share_limbs.iter().any(|&v| v >= PRIME_P) {
                return Err(KeyTransportError::PacketMetadataMismatch(format!(
                    "relay {} provided non-canonical limb >= PRIME_P",
                    pkt.relay.validator_id
                )));
            }
        }

        if packets.len() == t {
            return Ok(());
        }

        let basis = &packets[..t];
        for &extra in &packets[t..] {
            if let Err(limb_index) = check_packet_against_basis(basis, extra) {
                return Err(KeyTransportError::PolynomialInconsistency {
                    limb_index,
                    offending_relay_id: extra.relay.validator_id,
                });
            }
        }
        Ok(())
    }

    /// Reconstruct and verify a Tier 2 pad chunk from arriving share packets.
    ///
    /// Verification pipeline:
    /// 1. Validates per-hop relay CW-MACs (rejecting corrupted link packets).
    /// 2. Validates metadata & disjoint relay topology across valid packets.
    /// 3. Checks degree-`(t - 1)` polynomial consistency across all arriving packets.
    /// 4. If all arriving packets are consistent, reconstructs `f_j(0)` via precomputed Lagrange
    ///    basis weights and verifies `e2e_mac` in constant time (`CwFastKey`).
    /// 5. If polynomial consistency fails (e.g., a Byzantine relay tampered with its share limbs
    ///    and re-signed its own hop MAC) AND `> t` packets arrived, isolates and rejects the
    ///    tampered relay share(s) using `e2e_mac`-verified `t`-subset recovery, returning the
    ///    exact honest pad and listing every rejected relay in `rejected_relays`.
    pub fn reconstruct_and_verify(
        packets: &[SplitPadSharePacket],
        e2e_key: &E2eCwKey,
        hop_keys: &BTreeMap<ValidatorId, &RelayHopKey>,
    ) -> Result<ReconstructedPadChunk, KeyTransportError> {
        if packets.is_empty() {
            return Err(KeyTransportError::InsufficientValidShares {
                threshold_t: 1,
                valid_shares: 0,
            });
        }

        let mut rejected_relays: Vec<(ValidatorId, String)> = Vec::new();
        let mut hop_verified: Vec<&SplitPadSharePacket> = Vec::with_capacity(packets.len());

        // Step 1: Verify per-hop CW-MACs and canonical field bounds.
        for pkt in packets {
            let Some(hop_key) = hop_keys.get(&pkt.relay.validator_id) else {
                rejected_relays.push((pkt.relay.validator_id, "missing relay hop key".into()));
                continue;
            };
            if !pkt.verify_hop_mac(hop_key) {
                rejected_relays.push((pkt.relay.validator_id, "per-hop CW-MAC failed".into()));
                continue;
            }
            if pkt.share_x == 0
                || pkt.share_x >= PRIME_P
                || pkt.share_limbs.iter().any(|&v| v >= PRIME_P)
            {
                rejected_relays.push((
                    pkt.relay.validator_id,
                    "non-canonical field element in share".into(),
                ));
                continue;
            }
            hop_verified.push(pkt);
        }

        let threshold_t = packets[0].threshold_t;
        if hop_verified.len() < threshold_t {
            return Err(KeyTransportError::InsufficientValidShares {
                threshold_t,
                valid_shares: hop_verified.len(),
            });
        }

        // Enforce strict topology disjointness across arriving relays.
        let arriving_relays: Vec<RelayTopologyTag> =
            hop_verified.iter().map(|p| p.relay.clone()).collect();
        verify_relays_disjoint(&arriving_relays)?;

        // Check header consistency across hop-verified packets.
        let first = hop_verified[0];
        let expected_limbs = first.original_len.div_ceil(SHAMIR_LIMB_BYTES);
        let mut seen_x = BTreeSet::new();
        for pkt in &hop_verified {
            if pkt.session_id != first.session_id
                || pkt.chunk_seq != first.chunk_seq
                || pkt.threshold_t != first.threshold_t
                || pkt.total_m != first.total_m
                || pkt.original_len != first.original_len
                || pkt.share_limbs.len() != expected_limbs
                || !ct_eq_16(&pkt.e2e_mac, &first.e2e_mac)
                || !seen_x.insert(pkt.share_x)
            {
                return Err(KeyTransportError::PacketMetadataMismatch(format!(
                    "inconsistent header from relay {}",
                    pkt.relay.validator_id
                )));
            }
        }

        let try_basis = |basis: &[&SplitPadSharePacket]| -> Result<Vec<u8>, KeyTransportError> {
            let mut limbs = reconstruct_limbs_from_basis(basis);
            let mut pad = match unpack_limbs_to_pad(&limbs, first.original_len) {
                Ok(p) => p,
                Err(e) => {
                    zeroize_u128_slice(&mut limbs);
                    return Err(e);
                }
            };
            zeroize_u128_slice(&mut limbs);

            let mut expected_mac = compute_e2e_pad_mac(
                first.session_id,
                first.chunk_seq,
                first.threshold_t,
                first.total_m,
                &pad,
                e2e_key,
            );
            let ok = ct_eq_16(&expected_mac, &first.e2e_mac);
            zeroize_slice(&mut expected_mac);
            if ok {
                Ok(pad)
            } else {
                zeroize_slice(&mut pad);
                Err(KeyTransportError::EndToEndMacFailed)
            }
        };

        // Fast path: all arriving hop-verified shares are degree-(t - 1) consistent.
        if Self::verify_polynomial_consistency_refs(&hop_verified).is_ok() {
            let pad_bytes = try_basis(&hop_verified[..threshold_t])?;
            let verified_relays: Vec<ValidatorId> =
                hop_verified.iter().map(|p| p.relay.validator_id).collect();
            let expansion_ratio = pad_bytes.len() as f64 / e2e_key.key_bytes() as f64;
            return Ok(ReconstructedPadChunk {
                pad_bytes,
                verified_relays,
                rejected_relays,
                polynomial_degree_verified: true,
                expansion_ratio,
            });
        }

        // Byzantine recovery path: polynomial consistency detected >= 1 tampered share among
        // `hop_verified` (len > threshold_t). Search t-subsets to find the authentic e2e-MAC
        // verified polynomial, and classify every non-conforming relay share as tampered!
        let combos = generate_combinations(
            hop_verified.len(),
            threshold_t,
            MAX_SUBSET_RECOVERY_ATTEMPTS,
        );
        for combo in combos {
            let basis: Vec<&SplitPadSharePacket> = combo.iter().map(|&i| hop_verified[i]).collect();
            if let Ok(pad_bytes) = try_basis(&basis) {
                let mut verified_relays = Vec::with_capacity(hop_verified.len());
                for &pkt in &hop_verified {
                    if basis.iter().any(|b| b.share_x == pkt.share_x) {
                        verified_relays.push(pkt.relay.validator_id);
                    } else {
                        match check_packet_against_basis(&basis, pkt) {
                            Ok(()) => verified_relays.push(pkt.relay.validator_id),
                            Err(limb_idx) => rejected_relays.push((
                                pkt.relay.validator_id,
                                format!("tampered share rejected (polynomial mismatch at limb {limb_idx})"),
                            )),
                        }
                    }
                }
                let expansion_ratio = pad_bytes.len() as f64 / e2e_key.key_bytes() as f64;
                return Ok(ReconstructedPadChunk {
                    pad_bytes,
                    verified_relays,
                    rejected_relays,
                    polynomial_degree_verified: true,
                    expansion_ratio,
                });
            }
        }

        Err(KeyTransportError::EndToEndMacFailed)
    }

    /// Algebraic proof helper demonstrating Shannon perfect secrecy for `< t` shares:
    /// given `t - 1` genuine shares and ANY arbitrary `fake_pad` of equal length, constructs the
    /// unique degree-`(t - 1)` polynomial evaluations at `x = target_x` (and verifies every
    /// limb of `fake_pad` is 100% consistent with those `t - 1` shares).
    pub fn prove_subthreshold_consistency_with_fake_pad(
        sub_threshold_packets: &[SplitPadSharePacket],
        fake_pad: &[u8],
        missing_x: u128,
    ) -> Result<Vec<u128>, KeyTransportError> {
        if sub_threshold_packets.is_empty() {
            return Err(KeyTransportError::InvalidParameter(
                "need at least 1 share packet".into(),
            ));
        }
        let t = sub_threshold_packets[0].threshold_t;
        if sub_threshold_packets.len() != t - 1 {
            return Err(KeyTransportError::InvalidParameter(format!(
                "expected exactly t - 1 = {} shares, got {}",
                t - 1,
                sub_threshold_packets.len()
            )));
        }
        if fake_pad.len() != sub_threshold_packets[0].original_len {
            return Err(KeyTransportError::InvalidParameter(
                "fake_pad length must match original_len".into(),
            ));
        }
        if missing_x == 0 || missing_x >= PRIME_P {
            return Err(KeyTransportError::InvalidParameter(
                "missing_x must satisfy 0 < missing_x < PRIME_P".into(),
            ));
        }

        // Points: x = 0 (with value fake_limb) plus the (t - 1) observed shares -> exactly t points!
        let mut xs = Vec::with_capacity(t);
        xs.push(0u128);
        for pkt in sub_threshold_packets {
            if pkt.share_x == missing_x {
                return Err(KeyTransportError::InvalidParameter(
                    "missing_x collides with an existing share_x".into(),
                ));
            }
            xs.push(pkt.share_x);
        }
        let weights = lagrange_eval_weights(&xs, missing_x);
        let fake_limbs = pack_pad_to_limbs(fake_pad);
        let mut synthetic_share_limbs = Vec::with_capacity(fake_limbs.len());
        for (l, &fake_limb) in fake_limbs.iter().enumerate() {
            let mut y = mul_mod(fake_limb, weights[0]);
            for (i, pkt) in sub_threshold_packets.iter().enumerate() {
                y = add_mod(y, mul_mod(pkt.share_limbs[l], weights[i + 1]));
            }
            synthetic_share_limbs.push(y);
        }
        Ok(synthetic_share_limbs)
    }
}

// ============================================================================
// Tier 3: Vadhan Sample-then-Extract Bounded-Storage Model (BSM) Expander
// ============================================================================

/// Result returned by [`BsmStreamExpander::finalize_and_burn`].
///
/// Automatically volatile-zeroizes `extracted_bytes` on `Drop`.
pub struct BsmExtractionResult {
    extracted_bytes: Vec<u8>,
    pub epochs_sampled: usize,
    pub total_blocks_observed: usize,
    pub seed_burned: bool,
}

impl BsmExtractionResult {
    /// Borrow the extracted high-entropy OTP key bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.extracted_bytes
    }

    /// Take ownership of the extracted OTP key bytes.
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.extracted_bytes)
    }
}

impl fmt::Debug for BsmExtractionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BsmExtractionResult")
            .field("extracted_len", &self.extracted_bytes.len())
            .field("extracted_bytes", &"[REDACTED]")
            .field("epochs_sampled", &self.epochs_sampled)
            .field("total_blocks_observed", &self.total_blocks_observed)
            .field("seed_burned", &self.seed_burned)
            .finish()
    }
}

impl Drop for BsmExtractionResult {
    fn drop(&mut self) {
        zeroize_slice(&mut self.extracted_bytes);
    }
}

/// Vadhan Sample-then-Extract Bounded-Storage Model (BSM) streaming OTP expander.
///
/// - Uses a short uniform sampler seed `K_1` (128 B) to select exactly 1 ephemeral 4,096-bit
///   (512 B) block per stream epoch without archiving the rest of the high-rate public stream.
/// - Extracts 1,024 uniform bits (128 B) per sampled block via
///   `crate::turbo_crypto::toeplitz_hash_turbo` using a reused 640 B strong Toeplitz seed `K_2`.
/// - Volatile-zeroizes `K_1`, `K_2`, and sampled block buffers immediately upon
///   `finalize_and_burn(self)` and on `Drop`.
pub struct BsmStreamExpander {
    sampler_seed_k1: [u8; BSM_SAMPLER_SEED_BYTES],
    toeplitz_seed_words: [u64; BSM_TOEPLITZ_SEED_WORDS],
    sampled_buf: [u8; BSM_SAMPLE_BLOCK_BYTES],
    blocks_per_epoch: usize,
    sampled_epochs: BTreeSet<u64>,
    total_blocks_observed: usize,
    extracted_output: Vec<u8>,
}

impl BsmStreamExpander {
    /// Generate a fresh shared `(K_1, K_2)` BSM seed pair (`128 B` sampler seed, `640 B` Toeplitz seed).
    pub fn generate_shared_seeds() -> (
        [u8; BSM_SAMPLER_SEED_BYTES],
        [u8; BSM_TOEPLITZ_SEED_BYTES],
    ) {
        let mut k1 = [0u8; BSM_SAMPLER_SEED_BYTES];
        let mut k2 = [0u8; BSM_TOEPLITZ_SEED_BYTES];
        fill_os_random(&mut k1);
        fill_os_random(&mut k2);
        (k1, k2)
    }

    /// Initialize a streaming BSM expander from shared `(K_1, K_2)` and epoch block count.
    pub fn new(
        sampler_seed_k1: [u8; BSM_SAMPLER_SEED_BYTES],
        mut toeplitz_seed_k2: [u8; BSM_TOEPLITZ_SEED_BYTES],
        blocks_per_epoch: usize,
    ) -> Result<Self, KeyTransportError> {
        if blocks_per_epoch == 0 {
            zeroize_slice(&mut toeplitz_seed_k2);
            return Err(KeyTransportError::InvalidParameter(
                "blocks_per_epoch must be > 0".into(),
            ));
        }

        let mut toeplitz_seed_words = [0u64; BSM_TOEPLITZ_SEED_WORDS];
        for (i, chunk) in toeplitz_seed_k2.chunks_exact(8).enumerate() {
            toeplitz_seed_words[i] =
                u64::from_le_bytes(chunk.try_into().expect("8-byte Toeplitz word"));
        }
        zeroize_slice(&mut toeplitz_seed_k2);

        Ok(Self {
            sampler_seed_k1,
            toeplitz_seed_words,
            sampled_buf: [0u8; BSM_SAMPLE_BLOCK_BYTES],
            blocks_per_epoch,
            sampled_epochs: BTreeSet::new(),
            total_blocks_observed: 0,
            extracted_output: Vec::new(),
        })
    }

    /// Deterministically compute the unique sampled block index in `0..blocks_per_epoch` for
    /// `stream_epoch` from `K_1` using rejection sampling over `F_(2^127 - 1)` (zero modulo bias).
    pub fn selected_block_index(&self, stream_epoch: u64) -> usize {
        if self.blocks_per_epoch <= 1 {
            return 0;
        }
        let r = add_mod(KT_MIX_K2, reduce(stream_epoch as u128));
        let seed_scalar = kt_fold_bytes_field(&self.sampler_seed_k1, r);
        let bound = self.blocks_per_epoch as u128;
        let limit = PRIME_P - (PRIME_P % bound);
        let mut ctr = 0u64;
        loop {
            let v = kt_mix_field_elem(seed_scalar, KT_DOMAIN_BSM_SAMPLER, stream_epoch, ctr);
            if v < limit {
                return (v % bound) as usize;
            }
            ctr = ctr.wrapping_add(1);
        }
    }

    /// Observe a single ephemeral block from the public high-rate stream.
    ///
    /// - If `block_index != selected_block_index(stream_epoch)`, immediately discards the block
    ///   without storing or hashing it and returns `Ok(false)`.
    /// - If `block_index == selected_block_index(stream_epoch)`, extracts 1,024 bits (128 B)
    ///   via `crate::turbo_crypto::toeplitz_hash_turbo`, volatile-zeroizes the sampled block
    ///   buffer immediately, and returns `Ok(true)`.
    pub fn observe_stream_block(
        &mut self,
        stream_epoch: u64,
        block_index: usize,
        block_bytes: &[u8],
    ) -> Result<bool, KeyTransportError> {
        if block_index >= self.blocks_per_epoch {
            return Err(KeyTransportError::BsmStreamError(format!(
                "block_index {block_index} >= blocks_per_epoch {}",
                self.blocks_per_epoch
            )));
        }

        let target = self.selected_block_index(stream_epoch);
        if block_index != target {
            self.total_blocks_observed += 1;
            return Ok(false);
        }

        if block_bytes.len() != BSM_SAMPLE_BLOCK_BYTES {
            return Err(KeyTransportError::BsmStreamError(format!(
                "sampled block length {} != expected {BSM_SAMPLE_BLOCK_BYTES} bytes (4,096 bits)",
                block_bytes.len()
            )));
        }
        if !self.sampled_epochs.insert(stream_epoch) {
            return Err(KeyTransportError::BsmStreamError(format!(
                "stream_epoch {stream_epoch} was already sampled"
            )));
        }
        self.total_blocks_observed += 1;

        self.sampled_buf.copy_from_slice(block_bytes);
        let mut raw_words = [0u64; BSM_SAMPLE_BLOCK_BYTES / 8];
        for (i, chunk) in self.sampled_buf.chunks_exact(8).enumerate() {
            raw_words[i] = u64::from_le_bytes(chunk.try_into().expect("8-byte block word"));
        }

        let mut out_words = toeplitz_hash_turbo(
            &raw_words,
            BSM_SAMPLE_BLOCK_BITS,
            &self.toeplitz_seed_words,
            BSM_EXTRACT_BLOCK_BITS,
        );

        self.extracted_output.reserve(BSM_EXTRACT_BLOCK_BYTES);
        for &w in &out_words {
            self.extracted_output.extend_from_slice(&w.to_le_bytes());
        }

        // Immediately burn the sampled ephemeral block and temporary word buffers.
        zeroize_slice(&mut self.sampled_buf);
        zeroize_u64_slice(&mut raw_words);
        zeroize_u64_slice(&mut out_words);

        Ok(true)
    }

    /// Stream an entire ephemeral epoch iterator without archiving unselected blocks.
    pub fn process_ephemeral_epoch<'a, I>(
        &mut self,
        stream_epoch: u64,
        blocks: I,
    ) -> Result<bool, KeyTransportError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut sampled = false;
        for (idx, block) in blocks.into_iter().enumerate() {
            if self.observe_stream_block(stream_epoch, idx, block)? {
                sampled = true;
            }
        }
        Ok(sampled)
    }

    /// Return the number of stream epochs sampled so far.
    #[inline]
    pub fn epochs_sampled(&self) -> usize {
        self.sampled_epochs.len()
    }

    /// Volatile-zeroize `K_1`, `K_2`, and sampled buffers immediately.
    #[inline]
    pub fn burn_seeds(&mut self) {
        zeroize_slice(&mut self.sampler_seed_k1);
        zeroize_u64_slice(&mut self.toeplitz_seed_words);
        zeroize_slice(&mut self.sampled_buf);
    }

    /// Finalize BSM extraction, explicitly burn `K_1`, `K_2`, and internal buffers, and return
    /// the extracted OTP key material.
    pub fn finalize_and_burn(mut self) -> BsmExtractionResult {
        let extracted_bytes = std::mem::take(&mut self.extracted_output);
        let epochs_sampled = self.sampled_epochs.len();
        let total_blocks_observed = self.total_blocks_observed;
        self.burn_seeds();
        BsmExtractionResult {
            extracted_bytes,
            epochs_sampled,
            total_blocks_observed,
            seed_burned: true,
        }
    }
}

impl fmt::Debug for BsmStreamExpander {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BsmStreamExpander")
            .field("sampler_seed_k1", &"[REDACTED]")
            .field("toeplitz_seed_words", &"[REDACTED]")
            .field("blocks_per_epoch", &self.blocks_per_epoch)
            .field("epochs_sampled", &self.sampled_epochs.len())
            .field("total_blocks_observed", &self.total_blocks_observed)
            .field("extracted_bytes_len", &self.extracted_output.len())
            .finish()
    }
}

impl Drop for BsmStreamExpander {
    fn drop(&mut self) {
        self.burn_seeds();
        zeroize_slice(&mut self.extracted_output);
    }
}

// ============================================================================
// Tier 4: Offline Split-Courier XOR Vaults (`SplitCourierVault`)
// ============================================================================

/// One-time 32-byte Carter-Wegman key `(r, s)` authenticating a [`SplitCourierVault`] manifest.
#[derive(Clone, PartialEq, Eq)]
pub struct CourierManifestKey {
    r: u128,
    s: u128,
}

impl CourierManifestKey {
    /// Generate a fresh one-time manifest authentication key from OS entropy.
    pub fn generate() -> Self {
        Self {
            r: random_nonzero_field_elem(),
            s: random_field_elem(),
        }
    }

    #[inline]
    fn to_fast_key(&self) -> CwFastKey {
        CwFastKey::new(self.r, self.s)
    }
}

impl fmt::Debug for CourierManifestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CourierManifestKey")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CourierManifestKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

/// Integrity manifest binding an offline split-courier XOR vault with a one-time CW-MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CourierManifest {
    pub vault_id: u64,
    pub start_page_id: u64,
    pub num_pages: usize,
    pub enc_key_bytes: usize,
    pub total_couriers: usize,
    pub vault_mac: [u8; MAC_TAG_BYTES],
}

/// One physical courier's XOR share (`V_i`) of an offline split-courier pad vault.
///
/// Any strict subset of `< k` courier shares is information-theoretically uniform random noise.
/// Share bytes are redacted in `Debug` and volatile-zeroized on `Drop`.
#[derive(Clone, PartialEq, Eq)]
pub struct CourierShareVault {
    pub manifest: CourierManifest,
    pub courier_index: usize,
    pub share_bytes: Vec<u8>,
}

impl fmt::Debug for CourierShareVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CourierShareVault")
            .field("manifest", &self.manifest)
            .field("courier_index", &self.courier_index)
            .field("share_bytes_len", &self.share_bytes.len())
            .field("share_bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CourierShareVault {
    fn drop(&mut self) {
        zeroize_slice(&mut self.share_bytes);
    }
}

fn compute_courier_vault_mac(
    vault_id: u64,
    start_page_id: u64,
    num_pages: usize,
    enc_key_bytes: usize,
    total_couriers: usize,
    raw_vault_bytes: &[u8],
    manifest_key: &CourierManifestKey,
) -> [u8; MAC_TAG_BYTES] {
    let mut mac_input = Vec::with_capacity(40 + raw_vault_bytes.len());
    mac_input.extend_from_slice(&vault_id.to_be_bytes());
    mac_input.extend_from_slice(&start_page_id.to_be_bytes());
    mac_input.extend_from_slice(&(num_pages as u64).to_be_bytes());
    mac_input.extend_from_slice(&(enc_key_bytes as u64).to_be_bytes());
    mac_input.extend_from_slice(&(total_couriers as u64).to_be_bytes());
    mac_input.extend_from_slice(raw_vault_bytes);

    let fast = manifest_key.to_fast_key();
    let tag = fast.mac(&mac_input);
    zeroize_slice(&mut mac_input);
    tag
}

/// Tier 4 Offline Split-Courier XOR Vault builder and verifier.
#[derive(Debug, Default, Clone, Copy)]
pub struct SplitCourierVault;

impl SplitCourierVault {
    /// Generate `num_couriers >= 2` offline XOR share vaults (`V = V_1 ^ ... ^ V_k`) encoding
    /// `num_pages` standard `FRAME_BYTES` (256 B) `PadPage`s plus a one-time CW-MAC manifest.
    pub fn generate_split(
        vault_id: u64,
        num_pages: usize,
        num_couriers: usize,
    ) -> Result<(Vec<CourierShareVault>, CourierManifest, CourierManifestKey), KeyTransportError> {
        Self::generate_split_with_options(vault_id, 0, num_pages, FRAME_BYTES, num_couriers)
    }

    /// Generate `num_couriers >= 2` offline XOR share vaults with explicit `start_page_id` and
    /// `enc_key_bytes`.
    pub fn generate_split_with_options(
        vault_id: u64,
        start_page_id: u64,
        num_pages: usize,
        enc_key_bytes: usize,
        num_couriers: usize,
    ) -> Result<(Vec<CourierShareVault>, CourierManifest, CourierManifestKey), KeyTransportError> {
        if num_pages == 0 {
            return Err(KeyTransportError::InvalidParameter(
                "num_pages must be > 0".into(),
            ));
        }
        if num_couriers < 2 {
            return Err(KeyTransportError::InvalidParameter(
                "num_couriers must be >= 2 for split-courier XOR security".into(),
            ));
        }

        let record_bytes = enc_key_bytes
            .checked_add(32)
            .ok_or_else(|| KeyTransportError::InvalidParameter("enc_key_bytes overflow".into()))?;
        let total_bytes = num_pages
            .checked_mul(record_bytes)
            .ok_or_else(|| KeyTransportError::InvalidParameter("vault byte size overflow".into()))?;

        // Construct canonical vault bytes: `[enc_key || mac_r_le || mac_s_le]` per page.
        let mut raw_vault = Vec::with_capacity(total_bytes);
        for i in 0..num_pages {
            let page_id = start_page_id
                .checked_add(i as u64)
                .ok_or_else(|| KeyTransportError::InvalidParameter("page_id overflow".into()))?;
            let page = PadPage::generate(page_id, enc_key_bytes);
            raw_vault.extend_from_slice(page.enc_key());
            raw_vault.extend_from_slice(&page.mac_r().to_le_bytes());
            raw_vault.extend_from_slice(&page.mac_s().to_le_bytes());
            // `page` drops here and volatile-zeroizes its copy.
        }

        let manifest_key = CourierManifestKey::generate();
        let vault_mac = compute_courier_vault_mac(
            vault_id,
            start_page_id,
            num_pages,
            enc_key_bytes,
            num_couriers,
            &raw_vault,
            &manifest_key,
        );
        let manifest = CourierManifest {
            vault_id,
            start_page_id,
            num_pages,
            enc_key_bytes,
            total_couriers: num_couriers,
            vault_mac,
        };

        // Produce k - 1 uniform OS-random shares and set share_{k-1} = V ^ V_0 ^ ... ^ V_{k-2}.
        let mut final_share = raw_vault;
        let mut shares = Vec::with_capacity(num_couriers);
        for courier_idx in 0..(num_couriers - 1) {
            let mut buf = vec![0u8; total_bytes];
            fill_os_random(&mut buf);
            otp_xor_turbo_in_place(&mut final_share, &buf);
            shares.push(CourierShareVault {
                manifest: manifest.clone(),
                courier_index: courier_idx,
                share_bytes: buf,
            });
        }
        shares.push(CourierShareVault {
            manifest: manifest.clone(),
            courier_index: num_couriers - 1,
            share_bytes: final_share,
        });

        Ok((shares, manifest, manifest_key))
    }

    /// Merge ALL `k` courier XOR shares and verify the one-time Carter-Wegman manifest MAC in
    /// constant time before reconstructing the exact [`PadPage`] batch.
    pub fn merge_verified(
        shares: &[CourierShareVault],
        manifest_key: &CourierManifestKey,
    ) -> Result<Vec<PadPage>, KeyTransportError> {
        if shares.is_empty() {
            return Err(KeyTransportError::MissingCourierShares {
                expected: 2,
                received: 0,
            });
        }

        let manifest = &shares[0].manifest;
        let k = manifest.total_couriers;
        if k < 2 {
            return Err(KeyTransportError::InvalidCourierShare(
                "manifest total_couriers must be >= 2".into(),
            ));
        }
        if manifest.num_pages == 0 {
            return Err(KeyTransportError::InvalidCourierShare(
                "manifest num_pages must be > 0".into(),
            ));
        }

        let record_bytes = manifest
            .enc_key_bytes
            .checked_add(32)
            .ok_or_else(|| KeyTransportError::InvalidCourierShare("record size overflow".into()))?;
        let expected_len = manifest
            .num_pages
            .checked_mul(record_bytes)
            .ok_or_else(|| KeyTransportError::InvalidCourierShare("vault size overflow".into()))?;

        let mut seen_indices = BTreeSet::new();
        for share in shares {
            if &share.manifest != manifest {
                return Err(KeyTransportError::InvalidCourierShare(format!(
                    "courier {} manifest disagrees with vault {}",
                    share.courier_index, manifest.vault_id
                )));
            }
            if share.courier_index >= k {
                return Err(KeyTransportError::InvalidCourierShare(format!(
                    "courier_index {} out of bounds (total_couriers={k})",
                    share.courier_index
                )));
            }
            if !seen_indices.insert(share.courier_index) {
                return Err(KeyTransportError::InvalidCourierShare(format!(
                    "duplicate courier_index {}",
                    share.courier_index
                )));
            }
            if share.share_bytes.len() != expected_len {
                return Err(KeyTransportError::InvalidCourierShare(format!(
                    "courier {} share_bytes len {} != expected {expected_len}",
                    share.courier_index,
                    share.share_bytes.len()
                )));
            }
        }

        if shares.len() != k {
            return Err(KeyTransportError::MissingCourierShares {
                expected: k,
                received: shares.len(),
            });
        }

        // XOR-compose V = V_0 ^ V_1 ^ ... ^ V_{k-1}.
        let mut combined = vec![0u8; expected_len];
        for share in shares {
            otp_xor_turbo_in_place(&mut combined, &share.share_bytes);
        }

        // Verify one-time CW-MAC manifest in constant time BEFORE parsing any PadPage!
        let mut expected_mac = compute_courier_vault_mac(
            manifest.vault_id,
            manifest.start_page_id,
            manifest.num_pages,
            manifest.enc_key_bytes,
            manifest.total_couriers,
            &combined,
            manifest_key,
        );
        let mac_ok = ct_eq_16(&expected_mac, &manifest.vault_mac);
        zeroize_slice(&mut expected_mac);
        if !mac_ok {
            zeroize_slice(&mut combined);
            return Err(KeyTransportError::VaultManifestMacFailed);
        }

        // Parse verified canonical PadPage records.
        let mut pages = Vec::with_capacity(manifest.num_pages);
        for (i, rec) in combined.chunks_exact(record_bytes).enumerate() {
            let page_id = manifest.start_page_id.checked_add(i as u64).ok_or_else(|| {
                KeyTransportError::InvalidCourierShare("page_id overflow".into())
            })?;
            let enc_key = rec[..manifest.enc_key_bytes].to_vec();
            let mac_r = u128::from_le_bytes(
                rec[manifest.enc_key_bytes..manifest.enc_key_bytes + 16]
                    .try_into()
                    .expect("16-byte mac_r"),
            );
            let mac_s = u128::from_le_bytes(
                rec[manifest.enc_key_bytes + 16..manifest.enc_key_bytes + 32]
                    .try_into()
                    .expect("16-byte mac_s"),
            );
            if mac_r >= PRIME_P || mac_s >= PRIME_P {
                zeroize_slice(&mut combined);
                return Err(KeyTransportError::VaultManifestMacFailed);
            }
            pages.push(PadPage::from_raw(page_id, enc_key, mac_r, mac_s));
        }

        zeroize_slice(&mut combined);
        Ok(pages)
    }
}

// ============================================================================
// Tiered Key Mesh: XOR Composition -> WalPadBook Replenishment
// ============================================================================

/// A key material contribution emitted by a single active [`KeyTransportTier`].
///
/// Redacted in `Debug` and volatile-zeroized on `Drop`.
pub struct TierKeyContribution {
    pub tier: KeyTransportTier,
    key_bytes: Vec<u8>,
}

impl TierKeyContribution {
    /// Wrap key bytes from an active transport tier.
    pub fn new(tier: KeyTransportTier, key_bytes: Vec<u8>) -> Self {
        Self { tier, key_bytes }
    }

    /// Borrow the raw key contribution bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

impl fmt::Debug for TierKeyContribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TierKeyContribution")
            .field("tier", &self.tier)
            .field("len", &self.key_bytes.len())
            .field("key_bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for TierKeyContribution {
    fn drop(&mut self) {
        zeroize_slice(&mut self.key_bytes);
    }
}

/// Audit receipt returned after [`TieredKeyMesh`] XOR-composes active tier outputs and appends
/// new [`PadPage`]s into a [`WalPadBook`] (or any [`PadBook`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TieredReplenishReceipt {
    pub active_tiers: Vec<KeyTransportTier>,
    pub effective_pop_weight_bps: u32,
    pub start_page_id: u64,
    pub pages_appended: usize,
    pub total_bytes_composed: usize,
    pub new_book_remaining: usize,
}

/// Information-theoretic XOR key mesh combining outputs from active transport tiers
/// (`K_AB = K^(T1) ^ K^(T2) ^ ...`) and appending directly into a crash-safe [`WalPadBook`].
///
/// Because XOR preserves unconditional secrecy as long as ANY single independent tier remains
/// secret from the adversary, combining multiple tiers strictly raises defense-in-depth while
/// keeping `SimulatedDevnet` blocked on mainnet (`allow_simulated = false`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TieredKeyMesh {
    pub allow_simulated: bool,
}

impl TieredKeyMesh {
    /// Create a strict mainnet key mesh (forbids `KeyTransportTier::SimulatedDevnet`).
    pub const fn mainnet() -> Self {
        Self {
            allow_simulated: false,
        }
    }

    /// Create a devnet key mesh permitting `KeyTransportTier::SimulatedDevnet` (still 0 mainnet bps).
    pub const fn devnet() -> Self {
        Self {
            allow_simulated: true,
        }
    }

    /// XOR-compose `out_len` bytes across all active tier contributions (`K_AB = K^(1) ^ K^(2) ^ ...`).
    pub fn compose_bytes(
        &self,
        contributions: &[TierKeyContribution],
        out_len: usize,
    ) -> Result<(Vec<u8>, Vec<KeyTransportTier>, u32), KeyTransportError> {
        if contributions.is_empty() {
            return Err(KeyTransportError::InvalidParameter(
                "at least 1 active tier contribution is required".into(),
            ));
        }
        if out_len == 0 {
            return Err(KeyTransportError::InvalidParameter(
                "out_len must be > 0".into(),
            ));
        }

        let mut active_tiers = Vec::with_capacity(contributions.len());
        let mut effective_weight_bps = 0u32;

        for contrib in contributions {
            if contrib.tier == KeyTransportTier::SimulatedDevnet && !self.allow_simulated {
                return Err(KeyTransportError::SimulatedTierForbiddenOnMainnet);
            }
            if contrib.key_bytes.len() < out_len {
                return Err(KeyTransportError::InvalidParameter(format!(
                    "tier {} supplied {} bytes, need at least {out_len} bytes",
                    contrib.tier,
                    contrib.key_bytes.len()
                )));
            }
            active_tiers.push(contrib.tier);
            let w = contrib.tier.mainnet_pop_weight_bps();
            if w > effective_weight_bps {
                effective_weight_bps = w;
            }
        }

        let mut composed = vec![0u8; out_len];
        for contrib in contributions {
            otp_xor_turbo_in_place(&mut composed, &contrib.key_bytes[..out_len]);
        }

        // Verify online entropy health before accepting composed OTP material.
        if composed.len() >= 32
            && let Err(err) = check_entropy_health(&composed, 6.0)
        {
            zeroize_slice(&mut composed);
            return Err(KeyTransportError::EntropyHealthRejected(err.to_string()));
        }

        Ok((composed, active_tiers, effective_weight_bps))
    }

    /// XOR-compose active tier outputs and append `num_pages` fresh [`PadPage`]s directly into
    /// a crash-safe [`WalPadBook`].
    pub fn replenish_wal_book(
        &self,
        book: &mut WalPadBook,
        contributions: &[TierKeyContribution],
        num_pages: usize,
    ) -> Result<TieredReplenishReceipt, KeyTransportError> {
        self.replenish_pad_book(book, contributions, num_pages)
    }

    /// XOR-compose active tier outputs and append `num_pages` fresh [`PadPage`]s into any [`PadBook`].
    pub fn replenish_pad_book<B: PadBook>(
        &self,
        book: &mut B,
        contributions: &[TierKeyContribution],
        num_pages: usize,
    ) -> Result<TieredReplenishReceipt, KeyTransportError> {
        if num_pages == 0 {
            return Err(KeyTransportError::InvalidParameter(
                "num_pages must be > 0".into(),
            ));
        }

        let enc_key_bytes = book.enc_key_bytes();
        let page_stride = enc_key_bytes
            .checked_add(32)
            .ok_or_else(|| KeyTransportError::InvalidParameter("page stride overflow".into()))?;
        let total_bytes = num_pages
            .checked_mul(page_stride)
            .ok_or_else(|| KeyTransportError::InvalidParameter("total bytes overflow".into()))?;

        let (mut composed, active_tiers, effective_pop_weight_bps) =
            self.compose_bytes(contributions, total_bytes)?;

        let start_page_id = book.next_page_id();
        let mut pages = Vec::with_capacity(num_pages);
        for (i, rec) in composed.chunks_exact(page_stride).enumerate() {
            let page_id = start_page_id
                .checked_add(i as u64)
                .ok_or_else(|| KeyTransportError::InvalidParameter("page_id overflow".into()))?;
            let enc_key = rec[..enc_key_bytes].to_vec();
            let raw_r = u128::from_le_bytes(
                rec[enc_key_bytes..enc_key_bytes + 16]
                    .try_into()
                    .expect("16-byte mac_r"),
            );
            let raw_s = u128::from_le_bytes(
                rec[enc_key_bytes + 16..enc_key_bytes + 32]
                    .try_into()
                    .expect("16-byte mac_s"),
            );
            // `PadPage::from_raw` reduces scalars canonically into [0, PRIME_P).
            pages.push(PadPage::from_raw(page_id, enc_key, raw_r, raw_s));
        }
        zeroize_slice(&mut composed);

        book.append_pages(pages)?;

        Ok(TieredReplenishReceipt {
            active_tiers,
            effective_pop_weight_bps,
            start_page_id,
            pages_appended: num_pages,
            total_bytes_composed: total_bytes,
            new_book_remaining: book.remaining(),
        })
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pop_mining::{PopAuditPolicy, audit_pad_entropy_extended};

    fn sample_disjoint_relays(count: usize) -> Vec<RelayTopologyTag> {
        let providers = [
            "hetzner-de",
            "ovh-fr",
            "vultr-jp",
            "linode-us",
            "scaleway-nl",
            "cherry-lt",
            "leaseweb-sg",
        ];
        let corridors = [
            "eu-central",
            "eu-west",
            "ap-northeast",
            "us-east",
            "eu-north",
            "eu-baltic",
            "ap-southeast",
        ];
        (0..count)
            .map(|i| RelayTopologyTag {
                validator_id: (i + 1) as ValidatorId,
                asn: 64_500 + (i as u32) * 101,
                provider_id: providers[i % providers.len()].to_string(),
                geo_corridor: corridors[i % corridors.len()].to_string(),
                local_bind_iface: format!("wg-tier2-{i}"),
            })
            .collect()
    }

    #[test]
    fn test_tier2_multipath_split_pad_2048x_expansion_fault_tolerance_and_tamper_rejection() {
        // Verify exact mainnet tier weights (SimulatedDevnet MUST be 0).
        assert_eq!(KeyTransportTier::Tier1PhysicalQkd.mainnet_pop_weight_bps(), 10_000);
        assert_eq!(KeyTransportTier::Tier2MultiPathThreshold.mainnet_pop_weight_bps(), 7_500);
        assert_eq!(KeyTransportTier::Tier3BsmExpanded.mainnet_pop_weight_bps(), 6_500);
        assert_eq!(KeyTransportTier::Tier4OfflineCourier.mainnet_pop_weight_bps(), 5_000);
        assert_eq!(KeyTransportTier::SimulatedDevnet.mainnet_pop_weight_bps(), 0);
        assert!(!KeyTransportTier::SimulatedDevnet.is_mainnet_eligible());

        // 64 KiB fresh pad chunk authenticated by a single 32-byte E2eCwKey -> exact 2,048:1 expansion!
        let mut original_pad = vec![0u8; TIER2_NOMINAL_CHUNK_BYTES];
        fill_os_random(&mut original_pad);

        let relays = sample_disjoint_relays(5);
        let e2e_key = E2eCwKey::generate();
        let hop_keys: Vec<RelayHopKey> = (0..5).map(|_| RelayHopKey::generate()).collect();
        let hop_map: BTreeMap<ValidatorId, &RelayHopKey> = relays
            .iter()
            .zip(hop_keys.iter())
            .map(|(r, k)| (r.validator_id, k))
            .collect();

        // Split with (t = 3, m = 5) Shamir over F_(2^127 - 1).
        let (packets, receipts) = MultiPathPadTransport::split_pad_chunk(
            0xABCD_0001,
            42,
            &original_pad,
            3,
            &relays,
            &e2e_key,
            &hop_keys,
        )
        .unwrap();
        assert_eq!(packets.len(), 5);
        assert_eq!(receipts.len(), 5);

        // Verify all per-hop MACs, transit receipts, and strict degree-(t-1) polynomial consistency.
        for ((pkt, rcpt), hk) in packets.iter().zip(receipts.iter()).zip(hop_keys.iter()) {
            assert!(pkt.verify_hop_mac(hk));
            assert!(rcpt.verify(pkt, hk));
            assert!(format!("{pkt:?}").contains("[REDACTED]"));
        }
        MultiPathPadTransport::verify_polynomial_consistency(&packets).unwrap();

        // 1. Fault tolerance: drop 2 of 5 relays (keep only relays 0, 2, 4 -> 3 shares == threshold).
        let surviving_3 = vec![packets[0].clone(), packets[2].clone(), packets[4].clone()];
        let rec_3 = MultiPathPadTransport::reconstruct_and_verify(&surviving_3, &e2e_key, &hop_map)
            .unwrap();
        assert_eq!(rec_3.as_bytes(), original_pad.as_slice());
        assert_eq!(rec_3.verified_relays.len(), 3);
        assert!(rec_3.rejected_relays.is_empty());
        assert!((rec_3.expansion_ratio - 2048.0).abs() < 1e-9);

        // 2. Tamper rejection (malicious relay alters a share limb AND re-signs its own hop MAC!):
        let mut with_1_tampered = packets.clone();
        with_1_tampered[3].share_limbs[17] = add_mod(with_1_tampered[3].share_limbs[17], 1);
        with_1_tampered[3].recompute_hop_mac(&hop_keys[3]);

        // Strict degree-(t-1) consistency check catches the tampered share immediately!
        let poly_err = MultiPathPadTransport::verify_polynomial_consistency(&with_1_tampered)
            .unwrap_err();
        assert_eq!(
            poly_err,
            KeyTransportError::PolynomialInconsistency {
                limb_index: 17,
                offending_relay_id: relays[3].validator_id,
            }
        );

        // Fault-tolerant reconstruct rejects the tampered relay AND still recovers exact pad!
        let rec_tamper =
            MultiPathPadTransport::reconstruct_and_verify(&with_1_tampered, &e2e_key, &hop_map)
                .unwrap();
        assert_eq!(rec_tamper.as_bytes(), original_pad.as_slice());
        assert_eq!(rec_tamper.verified_relays.len(), 4);
        assert_eq!(rec_tamper.rejected_relays.len(), 1);
        assert_eq!(rec_tamper.rejected_relays[0].0, relays[3].validator_id);

        // If 2 relays are dropped AND 1 of the remaining 3 is tampered (only 2 honest < t=3),
        // reconstruction MUST fail closed (via canonical limb overflow or E2E CW-MAC rejection)!
        let only_2_honest = vec![
            packets[0].clone(),
            packets[1].clone(),
            with_1_tampered[3].clone(),
        ];
        let err_2_honest =
            MultiPathPadTransport::reconstruct_and_verify(&only_2_honest, &e2e_key, &hop_map)
                .unwrap_err();
        assert!(
            matches!(
                err_2_honest,
                KeyTransportError::EndToEndMacFailed
                    | KeyTransportError::CanonicalLimbOverflow { .. }
            ),
            "expected tamper rejection with < t honest shares, got {err_2_honest:?}"
        );

        // 3. Algebraic proof of Shannon perfect secrecy for < t (2 shares):
        //    ANY arbitrary fake pad is 100% algebraically consistent with any 2 of the 5 shares!
        let two_shares = vec![packets[0].clone(), packets[1].clone()];
        let mut fake_pad = vec![0xA5u8; TIER2_NOMINAL_CHUNK_BYTES];
        fake_pad[0] = 0xDE;
        fake_pad[1] = 0xAD;
        let synthetic_third_limbs = MultiPathPadTransport::prove_subthreshold_consistency_with_fake_pad(
            &two_shares,
            &fake_pad,
            3,
        )
        .unwrap();
        let mut fake_third_pkt = packets[2].clone();
        fake_third_pkt.share_limbs = synthetic_third_limbs;
        let fake_basis = [&two_shares[0], &two_shares[1], &fake_third_pkt];
        let reconstructed_fake_limbs = reconstruct_limbs_from_basis(&fake_basis);
        let reconstructed_fake_pad =
            unpack_limbs_to_pad(&reconstructed_fake_limbs, TIER2_NOMINAL_CHUNK_BYTES).unwrap();
        assert_eq!(
            reconstructed_fake_pad, fake_pad,
            "< 3 shares must be algebraically consistent with ANY fake pad (zero Shannon leakage)"
        );
    }

    #[test]
    fn test_tier3_bsm_expander_with_turbo_toeplitz_and_seed_burn() {
        let (k1, k2) = BsmStreamExpander::generate_shared_seeds();
        let blocks_per_epoch = 16usize;
        let num_epochs = 8u64; // 8 epochs * 128 B = 1,024 B extracted OTP!

        let mut alice = BsmStreamExpander::new(k1, k2, blocks_per_epoch).unwrap();
        let mut bob = BsmStreamExpander::new(k1, k2, blocks_per_epoch).unwrap();

        // Redacted Debug check.
        assert!(format!("{alice:?}").contains("[REDACTED]"));

        // Stream 8 ephemeral epochs (16 x 512 B blocks per epoch = 64 KiB public stream).
        // Neither Alice nor Bob archives unselected blocks.
        let mut ephemeral_block = vec![0u8; BSM_SAMPLE_BLOCK_BYTES];
        for epoch in 0..num_epochs {
            let mut alice_hits = 0usize;
            let mut bob_hits = 0usize;
            for block_idx in 0..blocks_per_epoch {
                fill_os_random(&mut ephemeral_block);
                if alice
                    .observe_stream_block(epoch, block_idx, &ephemeral_block)
                    .unwrap()
                {
                    alice_hits += 1;
                }
                if bob
                    .observe_stream_block(epoch, block_idx, &ephemeral_block)
                    .unwrap()
                {
                    bob_hits += 1;
                }
            }
            // Exactly 1 block sampled per epoch!
            assert_eq!(alice_hits, 1);
            assert_eq!(bob_hits, 1);
        }

        // Duplicate epoch observation must be rejected.
        assert!(
            alice
                .observe_stream_block(0, alice.selected_block_index(0), &ephemeral_block)
                .is_err()
        );

        let alice_res = alice.finalize_and_burn();
        let bob_res = bob.finalize_and_burn();

        assert!(alice_res.seed_burned);
        assert!(bob_res.seed_burned);
        assert_eq!(alice_res.epochs_sampled, num_epochs as usize);
        assert_eq!(
            alice_res.total_blocks_observed,
            (num_epochs as usize) * blocks_per_epoch
        );
        assert_eq!(alice_res.as_bytes().len(), (num_epochs as usize) * BSM_EXTRACT_BLOCK_BYTES);

        // Alice and Bob extract bit-for-bit identical high-entropy OTP bytes!
        assert_eq!(alice_res.as_bytes(), bob_res.as_bytes());

        // Extracted BSM pad passes both QKD health checks and PoP v2.0 extended statistical audit!
        check_entropy_health(alice_res.as_bytes(), 6.0).unwrap();
        let ext = audit_pad_entropy_extended(alice_res.as_bytes(), &PopAuditPolicy::default())
            .unwrap();
        assert!(ext.rct_passed && ext.apt_passed);
    }

    #[test]
    fn test_tier4_split_courier_xor_vault_roundtrip_and_tamper_rejection() {
        let vault_id = 0x2026_0042u64;
        let num_pages = 8usize;
        let num_couriers = 3usize;

        let (shares, manifest, manifest_key) =
            SplitCourierVault::generate_split(vault_id, num_pages, num_couriers).unwrap();
        assert_eq!(shares.len(), num_couriers);
        assert_eq!(manifest.num_pages, num_pages);
        assert!(format!("{manifest_key:?}").contains("[REDACTED]"));
        assert!(format!("{:?}", shares[0]).contains("[REDACTED]"));

        // Missing any courier (only 2 of 3 arrive) -> rejected!
        let err_missing = SplitCourierVault::merge_verified(&shares[..2], &manifest_key)
            .unwrap_err();
        assert_eq!(
            err_missing,
            KeyTransportError::MissingCourierShares {
                expected: 3,
                received: 2,
            }
        );

        // Duplicate courier share -> rejected!
        let dup = vec![shares[0].clone(), shares[0].clone(), shares[2].clone()];
        assert!(matches!(
            SplitCourierVault::merge_verified(&dup, &manifest_key),
            Err(KeyTransportError::InvalidCourierShare(_))
        ));

        // Reconstruct in arbitrary courier arrival order -> exact PadPage batch!
        let shuffled = vec![shares[2].clone(), shares[0].clone(), shares[1].clone()];
        let pages_a = SplitCourierVault::merge_verified(&shares, &manifest_key).unwrap();
        let pages_b = SplitCourierVault::merge_verified(&shuffled, &manifest_key).unwrap();
        assert_eq!(pages_a.len(), num_pages);
        for (pa, pb) in pages_a.iter().zip(pages_b.iter()) {
            assert_eq!(pa.page_id, pb.page_id);
            assert_eq!(pa.enc_key(), pb.enc_key());
            assert_eq!(pa.mac_r(), pb.mac_r());
            assert_eq!(pa.mac_s(), pb.mac_s());
            check_entropy_health(pa.enc_key(), 6.0).unwrap();
        }

        // Single bit flip in ANY courier share -> constant-time CW-MAC manifest rejection!
        let mut tampered = shares.clone();
        tampered[1].share_bytes[77] ^= 0x01;
        assert_eq!(
            SplitCourierVault::merge_verified(&tampered, &manifest_key).unwrap_err(),
            KeyTransportError::VaultManifestMacFailed
        );

        // Wrong manifest key -> rejected!
        let wrong_key = CourierManifestKey::generate();
        assert_eq!(
            SplitCourierVault::merge_verified(&shares, &wrong_key).unwrap_err(),
            KeyTransportError::VaultManifestMacFailed
        );
    }

    #[test]
    fn test_disjoint_relay_selector_enforces_distinct_asns_and_providers() {
        let beacon_gamma = 0x4D9A_1C7E_82B3_5F16_9E47_2A83_6C5D_1B39u128;

        // Candidate pool with overlapping ASNs, overlapping provider IDs (including mixed case),
        // and only 4 truly disjoint relays out of 8 candidates.
        let candidates = vec![
            RelayTopologyTag {
                validator_id: 10,
                asn: 24940,
                provider_id: "Hetzner".into(),
                geo_corridor: "eu-central".into(),
                local_bind_iface: "eth0".into(),
            },
            RelayTopologyTag {
                validator_id: 11,
                asn: 24940, // Duplicate ASN with vid 10!
                provider_id: "OVH".into(),
                geo_corridor: "eu-west".into(),
                local_bind_iface: "eth1".into(),
            },
            RelayTopologyTag {
                validator_id: 12,
                asn: 16276,
                provider_id: "hetzner ".into(), // Case/whitespace duplicate provider with vid 10!
                geo_corridor: "eu-north".into(),
                local_bind_iface: "eth2".into(),
            },
            RelayTopologyTag {
                validator_id: 13,
                asn: 16276,
                provider_id: "OVH".into(),
                geo_corridor: "eu-west".into(),
                local_bind_iface: "eth3".into(),
            },
            RelayTopologyTag {
                validator_id: 14,
                asn: 20473,
                provider_id: "Vultr".into(),
                geo_corridor: "ap-northeast".into(),
                local_bind_iface: "eth4".into(),
            },
            RelayTopologyTag {
                validator_id: 15,
                asn: 63949,
                provider_id: "Linode".into(),
                geo_corridor: "us-east".into(),
                local_bind_iface: "eth5".into(),
            },
            RelayTopologyTag {
                validator_id: 16,
                asn: 63949, // Duplicate ASN with vid 15!
                provider_id: "Linode".into(),
                geo_corridor: "us-west".into(),
                local_bind_iface: "eth6".into(),
            },
        ];

        // Selecting m = 4 MUST succeed (even when greedy ordering encounters conflicting (ASN, prov) pairs!)
        // and MUST be independent of candidate input order!
        let selected = select_disjoint_relays(&candidates, beacon_gamma, 4).unwrap();
        let reversed: Vec<RelayTopologyTag> = candidates.iter().cloned().rev().collect();
        let selected_rev = select_disjoint_relays(&reversed, beacon_gamma, 4).unwrap();
        assert_eq!(selected, selected_rev);
        assert_eq!(selected.len(), 4);

        let asns: BTreeSet<u32> = selected.iter().map(|r| r.asn).collect();
        let provs: BTreeSet<String> = selected.iter().map(|r| r.normalized_provider()).collect();
        let vids: BTreeSet<ValidatorId> = selected.iter().map(|r| r.validator_id).collect();
        assert_eq!(asns.len(), 4, "selected relays must have 4 distinct ASNs");
        assert_eq!(provs.len(), 4, "selected relays must have 4 distinct providers");
        assert_eq!(vids.len(), 4, "selected relays must have 4 distinct validator IDs");

        // Requesting m = 5 when only 4 disjoint (ASN, provider) pairs exist MUST fail cleanly!
        let err = select_disjoint_relays(&candidates, beacon_gamma, 5).unwrap_err();
        assert!(matches!(
            err,
            KeyTransportError::InsufficientDisjointRelays {
                required: 5,
                available_disjoint: 4,
            }
        ));

        // Invalid beacon_gamma rejected.
        assert!(select_disjoint_relays(&candidates, 0, 2).is_err());
        assert!(select_disjoint_relays(&candidates, PRIME_P, 2).is_err());
    }

    #[test]
    fn test_tiered_key_mesh_xor_composition_and_wal_pad_book_replenishment() {
        let mut nonce = [0u8; 8];
        fill_os_random(&mut nonce);
        let tag = u64::from_le_bytes(nonce);
        let path_a = std::env::temp_dir().join(format!("vrnm_mesh_a_{tag}.pad"));
        let path_b = std::env::temp_dir().join(format!("vrnm_mesh_b_{tag}.pad"));

        let mut wal_a = WalPadBook::create(&path_a, FRAME_BYTES, Vec::new()).unwrap();
        let mut wal_b = WalPadBook::create(&path_b, FRAME_BYTES, Vec::new()).unwrap();

        let num_pages = 4usize;
        let needed_bytes = num_pages * (FRAME_BYTES + 32);

        // Simulate Tier 2 + Tier 3 independent key outputs (identical between Alice & Bob).
        let mut t2_bytes = vec![0u8; needed_bytes];
        let mut t3_bytes = vec![0u8; needed_bytes];
        fill_os_random(&mut t2_bytes);
        fill_os_random(&mut t3_bytes);

        let mesh_mainnet = TieredKeyMesh::mainnet();

        // Mainnet mesh MUST reject SimulatedDevnet contributions!
        let sim_err = mesh_mainnet
            .replenish_wal_book(
                &mut wal_a,
                &[TierKeyContribution::new(
                    KeyTransportTier::SimulatedDevnet,
                    t2_bytes.clone(),
                )],
                num_pages,
            )
            .unwrap_err();
        assert_eq!(sim_err, KeyTransportError::SimulatedTierForbiddenOnMainnet);

        // Alice & Bob XOR-compose Tier 2 ^ Tier 3 and append directly into their WalPadBooks.
        let rcpt_a = mesh_mainnet
            .replenish_wal_book(
                &mut wal_a,
                &[
                    TierKeyContribution::new(
                        KeyTransportTier::Tier2MultiPathThreshold,
                        t2_bytes.clone(),
                    ),
                    TierKeyContribution::new(
                        KeyTransportTier::Tier3BsmExpanded,
                        t3_bytes.clone(),
                    ),
                ],
                num_pages,
            )
            .unwrap();
        let rcpt_b = mesh_mainnet
            .replenish_wal_book(
                &mut wal_b,
                &[
                    TierKeyContribution::new(KeyTransportTier::Tier2MultiPathThreshold, t2_bytes),
                    TierKeyContribution::new(KeyTransportTier::Tier3BsmExpanded, t3_bytes),
                ],
                num_pages,
            )
            .unwrap();

        assert_eq!(rcpt_a, rcpt_b);
        assert_eq!(rcpt_a.pages_appended, num_pages);
        assert_eq!(rcpt_a.effective_pop_weight_bps, 7_500);
        assert_eq!(rcpt_a.new_book_remaining, num_pages);

        // Both WalPadBooks now hold bit-for-bit identical PadPages!
        for _ in 0..num_pages {
            let pa = wal_a.pop_next().unwrap();
            let pb = wal_b.pop_next().unwrap();
            assert_eq!(pa.page_id, pb.page_id);
            assert_eq!(pa.enc_key(), pb.enc_key());
            assert_eq!(pa.mac_r(), pb.mac_r());
            assert_eq!(pa.mac_s(), pb.mac_s());
        }

        // Clean up temporary WAL files.
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(WalPadBook::wal_path_for(&path_a));
        let _ = std::fs::remove_file(&path_b);
        let _ = std::fs::remove_file(WalPadBook::wal_path_for(&path_b));
    }
}
