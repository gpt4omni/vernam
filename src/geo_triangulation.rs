//! Speed-of-Light RTT Geo-Triangulation & Uncompressible Pad-Vault Audits for Vernam (VRNM).
//!
//! Pure information-theoretic cryptography over the Mersenne prime field `F_(2^127 - 1)`:
//! - Zero external crates, zero computational cryptography (no SHA-256, RSA, ECDSA, AES).
//! - Unconditional 1-instruction distance-bounding probe response `y = x * r + s mod (2^127 - 1)`
//!   using strictly single-use non-`Copy`/non-`Clone` [`DistanceProbeKey`]s with volatile
//!   memory zeroization on `Drop` and redacted `Debug`.
//! - Physical speed-of-light RTT verification combining:
//!   1. Tight local Voronoi cell anchor RTT bound (`<= local_cell_max_rtt_us`), defeating
//!      artificial delay spoofing from remote datacenters.
//!   2. Global vacuum light-speed lower bound (`d_geodesic <= (c_vac / 2) * RTT_min`),
//!      rejecting superluminal location spoofing.
//!   3. Silica-fiber routing-stretch upper bound (`RTT_min <= base_overhead + stretch * RTT_fiber`),
//!      rejecting VPN, Tor, and multi-hop tunneling relays.
//!   4. Constant-time (`ct_eq_16`) Carter-Wegman MAC verification on every anchor attestation.
//! - Tight-deadline random-offset Carter-Wegman [`PadVaultStorageAudit`] proving local storage
//!   of uncompressible high-entropy pad pages within `rtt_min + 10ms`.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, mul_mod, random_field_elem, random_nonzero_field_elem, reduce,
    zeroize_slice, zeroize_u128,
};

/// Mean Earth radius in kilometers (IUGG WGS84 mean radius).
pub const EARTH_RADIUS_KM: f64 = 6_371.0088;

/// Speed of light in vacuum in kilometers per second (`299,792.458 km/s`).
pub const SPEED_OF_LIGHT_VACUUM_KM_PER_S: f64 = 299_792.458;

/// Refractive index of standard single-mode silica optical fiber (`n ~= 1.468`).
pub const SILICA_FIBER_REFRACTIVE_INDEX: f64 = 1.468;

/// Default maximum RTT to a local Voronoi cell anchor (`15 ms = 15,000 us`),
/// defeating artificial delay spoofing from remote datacenters.
pub const DEFAULT_LOCAL_CELL_MAX_RTT_US: u64 = 15_000;

/// Default maximum silica-fiber routing stretch multiplier (`2.5x` great-circle fiber RTT).
pub const DEFAULT_MAX_FIBER_STRETCH: f64 = 2.5;

/// Default fixed packet/router processing overhead allowance (`8 ms = 8,000 us`)
/// added on top of stretched silica-fiber propagation RTT.
pub const DEFAULT_BASE_PROCESSING_OVERHEAD_US: u64 = 8_000;

/// Default minimum number of distinct triangulation anchors required (`>= 3` for 2D trilateration).
pub const DEFAULT_MIN_TOTAL_ANCHORS: usize = 3;

/// Default minimum number of local Voronoi cell anchors required (`>= 1`).
pub const DEFAULT_MIN_LOCAL_ANCHORS: usize = 1;

/// Default tight deadline slack for uncompressible Pad-Vault storage audits (`10 ms = 10,000 us`).
pub const DEFAULT_PAD_VAULT_DEADLINE_SLACK_US: u64 = 10_000;

// Domain separators in F_(2^127 - 1) for Carter-Wegman universal polynomial MACs.
const DOMAIN_ANCHOR_ATTESTATION: u128 = 0x5652_4E4D_0101;
const DOMAIN_PAD_VAULT_AUDIT: u128 = 0x5652_4E4D_0102;

// ============================================================================
// Errors
// ============================================================================

/// Error type for speed-of-light RTT geo-triangulation and pad-vault storage audits.
#[derive(Debug, Clone, PartialEq)]
pub enum TriangulationError {
    /// Non-canonical field element (`>= PRIME_P`) or zero multiplicative key supplied.
    NonCanonicalFieldElement(u128),
    /// Invalid latitude/longitude or configuration parameter.
    InvalidCoordinates(&'static str),
    /// Invalid verifier configuration.
    InvalidConfig(&'static str),
    /// Fewer distinct anchors than required for triangulation.
    InsufficientAnchors { provided: usize, required: usize },
    /// Duplicate anchor ID detected within a single attestation.
    DuplicateAnchor(u64),
    /// Anchor list length did not match supplied key list length.
    KeyCountMismatch { expected: usize, actual: usize },
    /// Anchor Carter-Wegman MAC tag failed constant-time verification.
    InvalidAnchorMac { anchor_id: u64 },
    /// Distance-bounding probe response failed constant-time verification.
    InvalidProbeResponse { anchor_id: u64 },
    /// Measured RTT violates the vacuum speed-of-light physical lower bound (superluminal claim).
    SuperluminalRtt {
        anchor_id: u64,
        geodesic_km: f64,
        measured_rtt_us: u64,
        min_vacuum_rtt_us: f64,
    },
    /// Measured RTT exceeds the silica-fiber routing-stretch upper bound (VPN/Tor/tunneling relay).
    FiberStretchExceeded {
        anchor_id: u64,
        geodesic_km: f64,
        measured_rtt_us: u64,
        max_allowed_rtt_us: f64,
    },
    /// No local Voronoi cell anchor satisfied the tight local RTT ceiling (remote DC spoofing).
    LocalVoronoiRttExceeded {
        claimed_cell_id: u16,
        best_local_rtt_us: Option<u64>,
        max_local_rtt_us: u64,
    },
    /// Pad-vault audit request exceeded vault page/offset bounds.
    InvalidAuditOffset(&'static str),
    /// Pad-vault audit response arrived after the tight `rtt_min + slack` deadline.
    AuditDeadlineExceeded {
        audit_id: u64,
        observed_rtt_us: u64,
        max_deadline_us: u64,
    },
    /// Pad-vault audit Carter-Wegman MAC failed constant-time verification (stale/wrong page).
    PadVaultMacMismatch { audit_id: u64 },
}

impl fmt::Display for TriangulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalFieldElement(v) => {
                write!(f, "non-canonical field element {v} (>= PRIME_P)")
            }
            Self::InvalidCoordinates(msg) => write!(f, "invalid geo coordinates: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "invalid triangulation config: {msg}"),
            Self::InsufficientAnchors { provided, required } => {
                write!(f, "insufficient anchors: provided {provided}, required {required}")
            }
            Self::DuplicateAnchor(id) => write!(f, "duplicate anchor id {id}"),
            Self::KeyCountMismatch { expected, actual } => {
                write!(f, "key count mismatch: expected {expected}, actual {actual}")
            }
            Self::InvalidAnchorMac { anchor_id } => {
                write!(f, "invalid Carter-Wegman MAC from anchor {anchor_id}")
            }
            Self::InvalidProbeResponse { anchor_id } => {
                write!(f, "invalid distance-bounding probe response for anchor {anchor_id}")
            }
            Self::SuperluminalRtt {
                anchor_id,
                geodesic_km,
                measured_rtt_us,
                min_vacuum_rtt_us,
            } => write!(
                f,
                "superluminal RTT from anchor {anchor_id}: {measured_rtt_us} us < vacuum min {min_vacuum_rtt_us:.1} us for {geodesic_km:.1} km"
            ),
            Self::FiberStretchExceeded {
                anchor_id,
                geodesic_km,
                measured_rtt_us,
                max_allowed_rtt_us,
            } => write!(
                f,
                "fiber stretch exceeded for anchor {anchor_id}: {measured_rtt_us} us > max {max_allowed_rtt_us:.1} us for {geodesic_km:.1} km"
            ),
            Self::LocalVoronoiRttExceeded {
                claimed_cell_id,
                best_local_rtt_us,
                max_local_rtt_us,
            } => write!(
                f,
                "local Voronoi cell {claimed_cell_id} RTT check failed: best={best_local_rtt_us:?} us, max={max_local_rtt_us} us"
            ),
            Self::InvalidAuditOffset(msg) => write!(f, "invalid pad-vault audit offset: {msg}"),
            Self::AuditDeadlineExceeded {
                audit_id,
                observed_rtt_us,
                max_deadline_us,
            } => write!(
                f,
                "pad-vault audit {audit_id} missed deadline: {observed_rtt_us} us > {max_deadline_us} us"
            ),
            Self::PadVaultMacMismatch { audit_id } => {
                write!(f, "pad-vault audit {audit_id} failed Carter-Wegman MAC verification")
            }
        }
    }
}

impl Error for TriangulationError {}

// ============================================================================
// Universal Polynomial Hash Helpers (Pure F_(2^127 - 1) IT Crypto)
// ============================================================================

#[inline]
fn poly_universal_hash_elems(r: u128, domain: u128, elems: &[u128]) -> u128 {
    let r = reduce(r);
    let mut acc = reduce(domain);
    acc = add_mod(mul_mod(acc, r), reduce(elems.len() as u128));
    for &e in elems {
        acc = add_mod(mul_mod(acc, r), reduce(e));
    }
    mul_mod(acc, r)
}

fn poly_universal_hash_bytes(r: u128, domain: u128, header: &[u128], bytes: &[u8]) -> u128 {
    let r = reduce(r);
    let mut acc = reduce(domain);
    acc = add_mod(mul_mod(acc, r), reduce(header.len() as u128));
    for &h in header {
        acc = add_mod(mul_mod(acc, r), reduce(h));
    }
    acc = add_mod(mul_mod(acc, r), reduce(bytes.len() as u128));
    for chunk in bytes.chunks(15) {
        let mut limb = [0u8; 16];
        limb[..chunk.len()].copy_from_slice(chunk);
        acc = add_mod(mul_mod(acc, r), u128::from_le_bytes(limb));
        zeroize_slice(&mut limb);
    }
    mul_mod(acc, r)
}

// ============================================================================
// 1. Single-Use Distance-Bounding Probe Key & 1-Instruction Responder
// ============================================================================

/// Strictly single-use distance-bounding probe key `(r, s)` in `F_(2^127 - 1)`.
///
/// Non-`Clone` and non-`Copy` by design so every rapid distance-bounding probe consumes a
/// fresh pair `(r, s)` and volatile-zeroizes it on `Drop`.
pub struct DistanceProbeKey {
    r: u128,
    s: u128,
}

impl DistanceProbeKey {
    /// Generate a matching `(prover_key, verifier_key)` pair from OS entropy.
    pub fn generate_pair() -> (Self, Self) {
        let r = random_nonzero_field_elem();
        let s = random_field_elem();
        (Self { r, s }, Self { r, s })
    }

    /// Construct a matching `(prover_key, verifier_key)` pair from validated canonical field elements.
    pub fn from_raw_pair(r: u128, s: u128) -> Result<(Self, Self), TriangulationError> {
        if r == 0 || r >= PRIME_P {
            return Err(TriangulationError::NonCanonicalFieldElement(r));
        }
        if s >= PRIME_P {
            return Err(TriangulationError::NonCanonicalFieldElement(s));
        }
        Ok((Self { r, s }, Self { r, s }))
    }
}

impl Drop for DistanceProbeKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

impl fmt::Debug for DistanceProbeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DistanceProbeKey")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

/// 1-instruction unconditional distance-bounding probe response in `F_(2^127 - 1)`:
///
/// `response = challenge_x * r + s (mod 2^127 - 1)`
///
/// Consumes and volatile-zeroizes `key` immediately upon completion. Because the response
/// requires only a single fused field multiply-add with zero branches or hashing, processing
/// jitter is sub-microsecond, tightening the physical speed-of-light RTT envelope.
#[inline]
pub fn respond_probe(challenge_x: u128, key: DistanceProbeKey) -> u128 {
    add_mod(mul_mod(reduce(challenge_x), key.r), key.s)
    // `key` drops here and volatile-zeroizes `(r, s)`.
}

/// Verify a distance-bounding probe response in constant time (`ct_eq_16`), consuming `key`.
pub fn verify_probe_response(
    anchor_id: u64,
    challenge_x: u128,
    response: u128,
    key: DistanceProbeKey,
) -> Result<(), TriangulationError> {
    if challenge_x >= PRIME_P {
        return Err(TriangulationError::NonCanonicalFieldElement(challenge_x));
    }
    if response >= PRIME_P {
        return Err(TriangulationError::NonCanonicalFieldElement(response));
    }
    let expected = add_mod(mul_mod(challenge_x, key.r), key.s);
    if ct_eq_16(&expected.to_le_bytes(), &response.to_le_bytes()) {
        Ok(())
    } else {
        Err(TriangulationError::InvalidProbeResponse { anchor_id })
    }
}

/// Strictly single-use Carter-Wegman MAC key `(r, s)` authenticating an anchor's RTT attestation
/// or a pad-vault audit challenge. Non-`Clone`, non-`Copy`, redacted `Debug`, volatile-zeroized.
pub struct AnchorMacKey {
    r: u128,
    s: u128,
}

impl AnchorMacKey {
    /// Generate a matching `(signer_key, verifier_key)` pair from OS entropy.
    pub fn generate_pair() -> (Self, Self) {
        let r = random_nonzero_field_elem();
        let s = random_field_elem();
        (Self { r, s }, Self { r, s })
    }

    /// Authenticate field elements, consuming and zeroizing this one-time key.
    pub fn mac_elems(self, domain: u128, elems: &[u128]) -> [u8; 16] {
        let tag = add_mod(poly_universal_hash_elems(self.r, domain, elems), self.s);
        tag.to_le_bytes()
    }

    /// Verify a 16-byte Carter-Wegman MAC tag over field elements in constant time (`ct_eq_16`).
    pub fn verify_elems(
        self,
        domain: u128,
        elems: &[u128],
        tag: &[u8; 16],
    ) -> Result<bool, TriangulationError> {
        let tag_u128 = u128::from_le_bytes(*tag);
        if tag_u128 >= PRIME_P {
            return Err(TriangulationError::NonCanonicalFieldElement(tag_u128));
        }
        let expected = add_mod(poly_universal_hash_elems(self.r, domain, elems), self.s);
        Ok(ct_eq_16(&expected.to_le_bytes(), tag))
    }

    /// Authenticate a structured header + raw byte slice, consuming and zeroizing this key.
    pub fn mac_bytes(self, domain: u128, header: &[u128], bytes: &[u8]) -> [u8; 16] {
        let tag = add_mod(
            poly_universal_hash_bytes(self.r, domain, header, bytes),
            self.s,
        );
        tag.to_le_bytes()
    }

    /// Verify a 16-byte Carter-Wegman MAC tag over header + bytes in constant time (`ct_eq_16`).
    pub fn verify_bytes(
        self,
        domain: u128,
        header: &[u128],
        bytes: &[u8],
        tag: &[u8; 16],
    ) -> Result<bool, TriangulationError> {
        let tag_u128 = u128::from_le_bytes(*tag);
        if tag_u128 >= PRIME_P {
            return Err(TriangulationError::NonCanonicalFieldElement(tag_u128));
        }
        let expected = add_mod(
            poly_universal_hash_bytes(self.r, domain, header, bytes),
            self.s,
        );
        Ok(ct_eq_16(&expected.to_le_bytes(), tag))
    }
}

impl Drop for AnchorMacKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

impl fmt::Debug for AnchorMacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnchorMacKey")
            .field("r", &"[REDACTED]")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// 2. Geodesic Physics & Speed-of-Light RTT Triangulation
// ============================================================================

/// Validate WGS84 geographic latitude `[-90, 90]` and longitude `[-180, 180]`.
pub fn validate_geo_coords(lat_deg: f64, lon_deg: f64) -> Result<(), TriangulationError> {
    if !lat_deg.is_finite() || !(-90.0..=90.0).contains(&lat_deg) {
        return Err(TriangulationError::InvalidCoordinates(
            "latitude must be finite and within [-90, 90]",
        ));
    }
    if !lon_deg.is_finite() || !(-180.0..=180.0).contains(&lon_deg) {
        return Err(TriangulationError::InvalidCoordinates(
            "longitude must be finite and within [-180, 180]",
        ));
    }
    Ok(())
}

/// Compute great-circle geodesic distance in kilometers using the Haversine formula.
pub fn geodesic_distance_km(lat1_deg: f64, lon1_deg: f64, lat2_deg: f64, lon2_deg: f64) -> f64 {
    let lat1 = lat1_deg.to_radians();
    let lat2 = lat2_deg.to_radians();
    let dlat = (lat2_deg - lat1_deg).to_radians();
    let dlon = (lon2_deg - lon1_deg).to_radians();

    let sin_dlat = (dlat * 0.5).sin();
    let sin_dlon = (dlon * 0.5).sin();
    let a = sin_dlat * sin_dlat + lat1.cos() * lat2.cos() * sin_dlon * sin_dlon;
    let c = 2.0 * a.clamp(0.0, 1.0).sqrt().asin();
    EARTH_RADIUS_KM * c
}

/// Physical vacuum speed-of-light minimum round-trip time in microseconds for `distance_km`:
///
/// `RTT_vac_min = (2 * d_geodesic / c_vac) * 1e6`
#[inline]
pub fn vacuum_min_rtt_us(distance_km: f64) -> f64 {
    (2.0 * distance_km / SPEED_OF_LIGHT_VACUUM_KM_PER_S) * 1_000_000.0
}

/// Ideal straight-line silica optical fiber round-trip time in microseconds for `distance_km`:
///
/// `RTT_fiber = (2 * d_geodesic * n_silica / c_vac) * 1e6`
#[inline]
pub fn silica_fiber_rtt_us(distance_km: f64) -> f64 {
    vacuum_min_rtt_us(distance_km) * SILICA_FIBER_REFRACTIVE_INDEX
}

/// A single anchor's authenticated speed-of-light RTT measurement for a candidate validator.
#[derive(Debug, Clone, PartialEq)]
pub struct AnchorProbeMeasurement {
    pub anchor_id: u64,
    pub anchor_cell_id: u16,
    pub anchor_lat_deg: f64,
    pub anchor_lon_deg: f64,
    pub challenge_x: u128,
    pub candidate_response: u128,
    /// Minimum observed round-trip time across probe bursts, in microseconds.
    pub measured_rtt_us: u64,
    /// Single-use Carter-Wegman MAC produced by the anchor over this measurement record.
    pub anchor_cw_tag: [u8; 16],
}

impl AnchorProbeMeasurement {
    /// Canonical field-element encoding of this measurement for Carter-Wegman MAC authentication.
    pub fn mac_elements(&self, epoch: u64, candidate_id: u64) -> [u128; 10] {
        [
            epoch as u128,
            candidate_id as u128,
            self.anchor_id as u128,
            self.anchor_cell_id as u128,
            self.anchor_lat_deg.to_bits() as u128,
            self.anchor_lon_deg.to_bits() as u128,
            reduce(self.challenge_x),
            reduce(self.candidate_response),
            self.measured_rtt_us as u128,
            0x01,
        ]
    }

    /// Construct and Carter-Wegman authenticate an anchor RTT measurement, consuming `anchor_key`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        epoch: u64,
        candidate_id: u64,
        anchor_id: u64,
        anchor_cell_id: u16,
        anchor_lat_deg: f64,
        anchor_lon_deg: f64,
        challenge_x: u128,
        candidate_response: u128,
        measured_rtt_us: u64,
        anchor_key: AnchorMacKey,
    ) -> Self {
        let mut rec = Self {
            anchor_id,
            anchor_cell_id,
            anchor_lat_deg,
            anchor_lon_deg,
            challenge_x: reduce(challenge_x),
            candidate_response: reduce(candidate_response),
            measured_rtt_us,
            anchor_cw_tag: [0u8; 16],
        };
        let elems = rec.mac_elements(epoch, candidate_id);
        rec.anchor_cw_tag = anchor_key.mac_elems(DOMAIN_ANCHOR_ATTESTATION, &elems);
        rec
    }
}

/// Complete multi-anchor geo-triangulation attestation submitted for a candidate validator.
#[derive(Debug, Clone, PartialEq)]
pub struct TriangulationAttestation {
    pub epoch: u64,
    pub candidate_id: u64,
    pub claimed_cell_id: u16,
    pub claimed_lat_deg: f64,
    pub claimed_lon_deg: f64,
    pub measurements: Vec<AnchorProbeMeasurement>,
}

/// Summary report returned after an attestation passes all physics and MAC checks.
#[derive(Debug, Clone, PartialEq)]
pub struct TriangulationVerdict {
    pub candidate_id: u64,
    pub verified_cell_id: u16,
    pub verified_anchors: usize,
    pub local_anchors_passed: usize,
    pub min_observed_rtt_us: u64,
    pub max_geodesic_km: f64,
}

/// Speed-of-light RTT geo-triangulation verifier enforcing:
/// - Tight local Voronoi cell anchor RTT (`<= local_cell_max_rtt_us`)
/// - Global vacuum light-speed lower bound (`d_geodesic <= (c_vac / 2) * RTT_min`)
/// - Silica-fiber routing-stretch upper bound (`RTT_min <= base_overhead + stretch * RTT_fiber`)
/// - Constant-time Carter-Wegman MAC verification (`ct_eq_16`) on anchor attestations and probes
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GeoTriangulationVerifier {
    /// Maximum allowed RTT (microseconds) to at least `min_local_anchors` anchor(s)
    /// residing in the candidate's claimed Voronoi cell.
    pub local_cell_max_rtt_us: u64,
    /// Maximum silica-fiber routing stretch factor (e.g. `2.5x` great-circle fiber RTT).
    pub max_fiber_stretch: f64,
    /// Fixed router/NIC processing overhead allowance in microseconds.
    pub base_processing_overhead_us: u64,
    /// Minimum total distinct anchors required (`>= 3`).
    pub min_total_anchors: usize,
    /// Minimum local Voronoi cell anchors required (`>= 1`).
    pub min_local_anchors: usize,
}

impl Default for GeoTriangulationVerifier {
    fn default() -> Self {
        Self {
            local_cell_max_rtt_us: DEFAULT_LOCAL_CELL_MAX_RTT_US,
            max_fiber_stretch: DEFAULT_MAX_FIBER_STRETCH,
            base_processing_overhead_us: DEFAULT_BASE_PROCESSING_OVERHEAD_US,
            min_total_anchors: DEFAULT_MIN_TOTAL_ANCHORS,
            min_local_anchors: DEFAULT_MIN_LOCAL_ANCHORS,
        }
    }
}

impl GeoTriangulationVerifier {
    /// Validate verifier configuration parameters.
    pub fn validate_config(&self) -> Result<(), TriangulationError> {
        if self.local_cell_max_rtt_us == 0 {
            return Err(TriangulationError::InvalidConfig(
                "local_cell_max_rtt_us must be > 0",
            ));
        }
        if !self.max_fiber_stretch.is_finite() || self.max_fiber_stretch < 1.0 {
            return Err(TriangulationError::InvalidConfig(
                "max_fiber_stretch must be finite and >= 1.0",
            ));
        }
        if self.min_total_anchors < 3 {
            return Err(TriangulationError::InvalidConfig(
                "min_total_anchors must be >= 3 for 2D triangulation",
            ));
        }
        if self.min_local_anchors == 0 || self.min_local_anchors > self.min_total_anchors {
            return Err(TriangulationError::InvalidConfig(
                "min_local_anchors must be in 1..=min_total_anchors",
            ));
        }
        Ok(())
    }

    /// Verify a candidate's [`TriangulationAttestation`], consuming the single-use
    /// `(probe_verifier_keys, anchor_mac_verifier_keys)` paired 1-to-1 with `attestation.measurements`.
    pub fn verify_attestation(
        &self,
        attestation: &TriangulationAttestation,
        probe_verifier_keys: Vec<DistanceProbeKey>,
        anchor_mac_verifier_keys: Vec<AnchorMacKey>,
    ) -> Result<TriangulationVerdict, TriangulationError> {
        self.validate_config()?;
        validate_geo_coords(attestation.claimed_lat_deg, attestation.claimed_lon_deg)?;

        let n = attestation.measurements.len();
        if n < self.min_total_anchors {
            return Err(TriangulationError::InsufficientAnchors {
                provided: n,
                required: self.min_total_anchors,
            });
        }
        if probe_verifier_keys.len() != n {
            return Err(TriangulationError::KeyCountMismatch {
                expected: n,
                actual: probe_verifier_keys.len(),
            });
        }
        if anchor_mac_verifier_keys.len() != n {
            return Err(TriangulationError::KeyCountMismatch {
                expected: n,
                actual: anchor_mac_verifier_keys.len(),
            });
        }

        let mut seen_anchors = BTreeSet::new();
        let mut local_anchors_passed = 0usize;
        let mut best_local_rtt_us: Option<u64> = None;
        let mut min_observed_rtt_us = u64::MAX;
        let mut max_geodesic_km = 0.0f64;

        for ((m, probe_key), mac_key) in attestation
            .measurements
            .iter()
            .zip(probe_verifier_keys.into_iter())
            .zip(anchor_mac_verifier_keys.into_iter())
        {
            if !seen_anchors.insert(m.anchor_id) {
                return Err(TriangulationError::DuplicateAnchor(m.anchor_id));
            }
            validate_geo_coords(m.anchor_lat_deg, m.anchor_lon_deg)?;

            if m.challenge_x >= PRIME_P {
                return Err(TriangulationError::NonCanonicalFieldElement(m.challenge_x));
            }
            if m.candidate_response >= PRIME_P {
                return Err(TriangulationError::NonCanonicalFieldElement(
                    m.candidate_response,
                ));
            }

            // 1. Constant-time Carter-Wegman MAC verification on the anchor's attestation.
            let elems = m.mac_elements(attestation.epoch, attestation.candidate_id);
            let mac_ok = mac_key.verify_elems(DOMAIN_ANCHOR_ATTESTATION, &elems, &m.anchor_cw_tag)?;
            if !mac_ok {
                return Err(TriangulationError::InvalidAnchorMac {
                    anchor_id: m.anchor_id,
                });
            }

            // 2. Constant-time 1-instruction distance-bounding probe verification.
            verify_probe_response(m.anchor_id, m.challenge_x, m.candidate_response, probe_key)?;

            // 3. Geodesic physics bounds: vacuum speed-of-light lower bound AND silica-fiber upper bound.
            let dist_km = geodesic_distance_km(
                attestation.claimed_lat_deg,
                attestation.claimed_lon_deg,
                m.anchor_lat_deg,
                m.anchor_lon_deg,
            );
            if dist_km > max_geodesic_km {
                max_geodesic_km = dist_km;
            }

            // Global vacuum light-speed lower bound: d_geodesic <= (c_vac / 2) * RTT_min
            let min_vac_rtt = vacuum_min_rtt_us(dist_km);
            if (m.measured_rtt_us as f64) < min_vac_rtt {
                return Err(TriangulationError::SuperluminalRtt {
                    anchor_id: m.anchor_id,
                    geodesic_km: dist_km,
                    measured_rtt_us: m.measured_rtt_us,
                    min_vacuum_rtt_us: min_vac_rtt,
                });
            }

            // Silica-fiber routing-stretch upper bound (rejects VPN/Tor/tunneling relays).
            let max_fiber_rtt = (self.base_processing_overhead_us as f64)
                + self.max_fiber_stretch * silica_fiber_rtt_us(dist_km);
            if (m.measured_rtt_us as f64) > max_fiber_rtt {
                return Err(TriangulationError::FiberStretchExceeded {
                    anchor_id: m.anchor_id,
                    geodesic_km: dist_km,
                    measured_rtt_us: m.measured_rtt_us,
                    max_allowed_rtt_us: max_fiber_rtt,
                });
            }

            // 4. Local Voronoi cell anchor RTT tracking (defeats artificial delay spoofing from remote DCs).
            if m.anchor_cell_id == attestation.claimed_cell_id {
                best_local_rtt_us = Some(
                    best_local_rtt_us.map_or(m.measured_rtt_us, |best| best.min(m.measured_rtt_us)),
                );
                if m.measured_rtt_us <= self.local_cell_max_rtt_us {
                    local_anchors_passed += 1;
                }
            }

            if m.measured_rtt_us < min_observed_rtt_us {
                min_observed_rtt_us = m.measured_rtt_us;
            }
        }

        if local_anchors_passed < self.min_local_anchors {
            return Err(TriangulationError::LocalVoronoiRttExceeded {
                claimed_cell_id: attestation.claimed_cell_id,
                best_local_rtt_us,
                max_local_rtt_us: self.local_cell_max_rtt_us,
            });
        }

        Ok(TriangulationVerdict {
            candidate_id: attestation.candidate_id,
            verified_cell_id: attestation.claimed_cell_id,
            verified_anchors: n,
            local_anchors_passed,
            min_observed_rtt_us,
            max_geodesic_km,
        })
    }
}

// ============================================================================
// 3. Uncompressible Pad-Vault Tight-Deadline Storage Audits
// ============================================================================

/// A random-offset challenge issued to prove local custody of an uncompressible OTP pad vault
/// within `rtt_min_us + max_deadline_slack_us` (default `rtt_min + 10ms`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PadVaultChallenge {
    pub audit_id: u64,
    pub validator_id: u64,
    pub page_index: usize,
    pub byte_offset: usize,
    pub slice_len: usize,
    /// Baseline physical minimum RTT to this validator, in microseconds.
    pub rtt_min_us: u64,
    /// Maximum allowed storage read + CW-MAC compute slack above `rtt_min_us` (default 10,000 us).
    pub max_deadline_slack_us: u64,
}

impl PadVaultChallenge {
    /// Effective hard deadline in microseconds (`rtt_min_us + max_deadline_slack_us`).
    #[inline]
    pub const fn max_deadline_us(&self) -> u64 {
        self.rtt_min_us.saturating_add(self.max_deadline_slack_us)
    }

    #[inline]
    fn mac_header(&self) -> [u128; 5] {
        [
            self.audit_id as u128,
            self.validator_id as u128,
            self.page_index as u128,
            self.byte_offset as u128,
            self.slice_len as u128,
        ]
    }
}

/// Prover's tight-deadline Carter-Wegman MAC response to a [`PadVaultChallenge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PadVaultAuditResponse {
    pub audit_id: u64,
    pub cw_tag: [u8; 16],
    /// Measured wall-clock round-trip latency from challenge dispatch to response arrival (us).
    pub observed_rtt_us: u64,
}

/// Uncompressible pad-vault random-offset Carter-Wegman storage auditor.
///
/// Proves that a validator stores its unique, incompressible random pad pages locally on fast
/// storage (rather than fetching them over WAN from a centralized pool or regenerating them)
/// by requiring an exact one-time Carter-Wegman MAC over a random `(page_index, byte_offset, slice_len)`
/// window within `rtt_min + 10ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PadVaultStorageAudit {
    /// Allowed local I/O + CW-MAC slack above baseline `rtt_min_us` (default `10_000 us` = 10 ms).
    pub deadline_slack_us: u64,
}

impl Default for PadVaultStorageAudit {
    fn default() -> Self {
        Self {
            deadline_slack_us: DEFAULT_PAD_VAULT_DEADLINE_SLACK_US,
        }
    }
}

impl PadVaultStorageAudit {
    /// Construct a new random-offset challenge for a pad vault with `page_count` pages of `page_size` bytes.
    pub fn issue_challenge(
        &self,
        audit_id: u64,
        validator_id: u64,
        page_count: usize,
        page_size: usize,
        slice_len: usize,
        rtt_min_us: u64,
    ) -> Result<(PadVaultChallenge, AnchorMacKey, AnchorMacKey), TriangulationError> {
        if page_count == 0 || page_size == 0 || slice_len == 0 || slice_len > page_size {
            return Err(TriangulationError::InvalidAuditOffset(
                "invalid page_count, page_size, or slice_len",
            ));
        }
        let max_offset = page_size - slice_len;
        let rand_page = (random_field_elem() as usize) % page_count;
        let rand_offset = if max_offset == 0 {
            0
        } else {
            (random_field_elem() as usize) % (max_offset + 1)
        };
        let (prover_key, verifier_key) = AnchorMacKey::generate_pair();
        let challenge = PadVaultChallenge {
            audit_id,
            validator_id,
            page_index: rand_page,
            byte_offset: rand_offset,
            slice_len,
            rtt_min_us,
            max_deadline_slack_us: self.deadline_slack_us,
        };
        Ok((challenge, prover_key, verifier_key))
    }

    /// Answer a [`PadVaultChallenge`] directly from the prover's local uncompressible pad pages,
    /// consuming and zeroizing `prover_key`.
    pub fn answer_challenge(
        challenge: &PadVaultChallenge,
        local_pages: &[Vec<u8>],
        prover_key: AnchorMacKey,
        observed_rtt_us: u64,
    ) -> Result<PadVaultAuditResponse, TriangulationError> {
        let slice = extract_vault_slice(challenge, local_pages)?;
        let header = challenge.mac_header();
        let cw_tag = prover_key.mac_bytes(DOMAIN_PAD_VAULT_AUDIT, &header, slice);
        Ok(PadVaultAuditResponse {
            audit_id: challenge.audit_id,
            cw_tag,
            observed_rtt_us,
        })
    }

    /// Verify a prover's [`PadVaultAuditResponse`] against the reference pad pages in constant time
    /// (`ct_eq_16`) AND enforce the tight `rtt_min_us + max_deadline_slack_us` deadline.
    pub fn verify_response(
        &self,
        challenge: &PadVaultChallenge,
        response: &PadVaultAuditResponse,
        reference_pages: &[Vec<u8>],
        verifier_key: AnchorMacKey,
    ) -> Result<(), TriangulationError> {
        if response.audit_id != challenge.audit_id {
            return Err(TriangulationError::PadVaultMacMismatch {
                audit_id: response.audit_id,
            });
        }
        let max_deadline = challenge.max_deadline_us();
        if response.observed_rtt_us > max_deadline {
            return Err(TriangulationError::AuditDeadlineExceeded {
                audit_id: challenge.audit_id,
                observed_rtt_us: response.observed_rtt_us,
                max_deadline_us: max_deadline,
            });
        }
        let slice = extract_vault_slice(challenge, reference_pages)?;
        let header = challenge.mac_header();
        let ok = verifier_key.verify_bytes(
            DOMAIN_PAD_VAULT_AUDIT,
            &header,
            slice,
            &response.cw_tag,
        )?;
        if ok {
            Ok(())
        } else {
            Err(TriangulationError::PadVaultMacMismatch {
                audit_id: challenge.audit_id,
            })
        }
    }
}

fn extract_vault_slice<'a>(
    challenge: &PadVaultChallenge,
    pages: &'a [Vec<u8>],
) -> Result<&'a [u8], TriangulationError> {
    let page = pages.get(challenge.page_index).ok_or(
        TriangulationError::InvalidAuditOffset("page_index out of bounds"),
    )?;
    let end = challenge
        .byte_offset
        .checked_add(challenge.slice_len)
        .ok_or(TriangulationError::InvalidAuditOffset("byte_offset overflow"))?;
    if challenge.slice_len == 0 || end > page.len() {
        return Err(TriangulationError::InvalidAuditOffset(
            "byte_offset + slice_len exceeds page length",
        ));
    }
    Ok(&page[challenge.byte_offset..end])
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::fill_os_random;

    // Reference anchor coordinates:
    // Cell 10: Frankfurt (50.1109, 8.6821)
    // Cell 20: London    (51.5072, -0.1276)
    // Cell 30: New York  (40.7128, -74.0060)
    // Cell 40: Tokyo     (35.6762, 139.6503)
    const FRANKFURT: (u16, f64, f64) = (10, 50.1109, 8.6821);
    const LONDON: (u16, f64, f64) = (20, 51.5072, -0.1276);
    const NEW_YORK: (u16, f64, f64) = (30, 40.7128, -74.0060);
    const TOKYO: (u16, f64, f64) = (40, 35.6762, 139.6503);

    fn build_honest_measurement(
        epoch: u64,
        candidate_id: u64,
        anchor_id: u64,
        anchor_geo: (u16, f64, f64),
        rtt_us: u64,
    ) -> (AnchorProbeMeasurement, DistanceProbeKey, AnchorMacKey) {
        let (probe_p, probe_v) = DistanceProbeKey::generate_pair();
        let (mac_s, mac_v) = AnchorMacKey::generate_pair();
        let challenge_x = random_field_elem();
        let response = respond_probe(challenge_x, probe_p);
        let measurement = AnchorProbeMeasurement::sign(
            epoch,
            candidate_id,
            anchor_id,
            anchor_geo.0,
            anchor_geo.1,
            anchor_geo.2,
            challenge_x,
            response,
            rtt_us,
            mac_s,
        );
        (measurement, probe_v, mac_v)
    }

    #[test]
    fn test_distance_probe_key_redacted_debug_and_1_instruction_response() {
        let (pk, vk) = DistanceProbeKey::from_raw_pair(123_456_789, 987_654_321).unwrap();
        let dbg_str = format!("{pk:?}");
        assert!(dbg_str.contains("[REDACTED]"));
        assert!(!dbg_str.contains("123456789"));
        assert!(!dbg_str.contains("987654321"));

        let x = 42u128;
        let resp = respond_probe(x, pk);
        assert_eq!(resp, add_mod(mul_mod(42, 123_456_789), 987_654_321));
        assert!(verify_probe_response(1, x, resp, vk).is_ok());
    }

    #[test]
    fn test_honest_multi_region_candidate_passes() {
        let verifier = GeoTriangulationVerifier::default();
        // Honest candidate located in Frankfurt (cell 10), ~20 km from Frankfurt anchor.
        let cand_lat = 50.25;
        let cand_lon = 8.80;

        // Realistic silica-fiber RTTs (~1.4x ideal silica fiber + 2ms processing).
        let rtt_fra = 2_500u64; // 2.5 ms local Voronoi anchor (<= 15 ms!)
        let d_lon = geodesic_distance_km(cand_lat, cand_lon, LONDON.1, LONDON.2);
        let rtt_lon = (silica_fiber_rtt_us(d_lon) * 1.4 + 2_000.0) as u64;
        let d_nyc = geodesic_distance_km(cand_lat, cand_lon, NEW_YORK.1, NEW_YORK.2);
        let rtt_nyc = (silica_fiber_rtt_us(d_nyc) * 1.35 + 2_500.0) as u64;
        let d_tok = geodesic_distance_km(cand_lat, cand_lon, TOKYO.1, TOKYO.2);
        let rtt_tok = (silica_fiber_rtt_us(d_tok) * 1.45 + 3_000.0) as u64;

        let (m1, p1, k1) = build_honest_measurement(7, 42, 1, FRANKFURT, rtt_fra);
        let (m2, p2, k2) = build_honest_measurement(7, 42, 2, LONDON, rtt_lon);
        let (m3, p3, k3) = build_honest_measurement(7, 42, 3, NEW_YORK, rtt_nyc);
        let (m4, p4, k4) = build_honest_measurement(7, 42, 4, TOKYO, rtt_tok);

        let att = TriangulationAttestation {
            epoch: 7,
            candidate_id: 42,
            claimed_cell_id: FRANKFURT.0,
            claimed_lat_deg: cand_lat,
            claimed_lon_deg: cand_lon,
            measurements: vec![m1, m2, m3, m4],
        };

        let verdict = verifier
            .verify_attestation(&att, vec![p1, p2, p3, p4], vec![k1, k2, k3, k4])
            .expect("honest multi-region candidate must pass");
        assert_eq!(verdict.candidate_id, 42);
        assert_eq!(verdict.verified_cell_id, FRANKFURT.0);
        assert_eq!(verdict.verified_anchors, 4);
        assert_eq!(verdict.local_anchors_passed, 1);
        assert_eq!(verdict.min_observed_rtt_us, rtt_fra);
    }

    #[test]
    fn test_remote_dc_delay_spoofing_fails_local_voronoi_check() {
        // Remote datacenter physically far from Frankfurt tries to claim Frankfurt (cell 10).
        // It artificially delays remote probes to match Frankfurt, but cannot beat the
        // speed-of-light physical RTT to the local Frankfurt Voronoi anchor!
        let cand_lat = FRANKFURT.1;
        let cand_lon = FRANKFURT.2;

        let strict_local_verifier = GeoTriangulationVerifier {
            local_cell_max_rtt_us: 10_000, // 10 ms tight Voronoi cell ceiling
            base_processing_overhead_us: 30_000,
            ..GeoTriangulationVerifier::default()
        };

        // Remote DC ~1,500 km away cannot get below 22 ms to the Frankfurt local anchor.
        let spoofed_local_rtt = 22_000u64;
        let d_lon = geodesic_distance_km(cand_lat, cand_lon, LONDON.1, LONDON.2);
        let d_nyc = geodesic_distance_km(cand_lat, cand_lon, NEW_YORK.1, NEW_YORK.2);

        let (m1, p1, k1) = build_honest_measurement(1, 77, 1, FRANKFURT, spoofed_local_rtt);
        let (m2, p2, k2) = build_honest_measurement(
            1,
            77,
            2,
            LONDON,
            (silica_fiber_rtt_us(d_lon) * 1.4 + 2_000.0) as u64,
        );
        let (m3, p3, k3) = build_honest_measurement(
            1,
            77,
            3,
            NEW_YORK,
            (silica_fiber_rtt_us(d_nyc) * 1.3 + 2_000.0) as u64,
        );

        let att = TriangulationAttestation {
            epoch: 1,
            candidate_id: 77,
            claimed_cell_id: FRANKFURT.0,
            claimed_lat_deg: cand_lat,
            claimed_lon_deg: cand_lon,
            measurements: vec![m1, m2, m3],
        };

        let err = strict_local_verifier
            .verify_attestation(&att, vec![p1, p2, p3], vec![k1, k2, k3])
            .unwrap_err();
        assert!(
            matches!(
                err,
                TriangulationError::LocalVoronoiRttExceeded {
                    claimed_cell_id: 10,
                    best_local_rtt_us: Some(22_000),
                    max_local_rtt_us: 10_000
                }
            ),
            "expected LocalVoronoiRttExceeded, got {err:?}"
        );
    }

    #[test]
    fn test_superluminal_spoof_fails_physics_check() {
        let verifier = GeoTriangulationVerifier::default();
        // Candidate claims Frankfurt, but reports an impossible 15 ms RTT to New York (~6,200 km -> vac min ~41.3 ms)!
        let d_lon = geodesic_distance_km(FRANKFURT.1, FRANKFURT.2, LONDON.1, LONDON.2);
        let (m1, p1, k1) = build_honest_measurement(2, 88, 1, FRANKFURT, 2_000);
        let (m2, p2, k2) = build_honest_measurement(
            2,
            88,
            2,
            LONDON,
            (silica_fiber_rtt_us(d_lon) * 1.3 + 1_500.0) as u64,
        );
        let (m3, p3, k3) = build_honest_measurement(2, 88, 3, NEW_YORK, 15_000); // Faster than light!

        let att = TriangulationAttestation {
            epoch: 2,
            candidate_id: 88,
            claimed_cell_id: FRANKFURT.0,
            claimed_lat_deg: FRANKFURT.1,
            claimed_lon_deg: FRANKFURT.2,
            measurements: vec![m1, m2, m3],
        };

        let err = verifier
            .verify_attestation(&att, vec![p1, p2, p3], vec![k1, k2, k3])
            .unwrap_err();
        assert!(
            matches!(err, TriangulationError::SuperluminalRtt { anchor_id: 3, .. }),
            "expected SuperluminalRtt, got {err:?}"
        );
    }

    #[test]
    fn test_vpn_tunnel_fails_fiber_stretch_check() {
        let verifier = GeoTriangulationVerifier::default();
        // Candidate claims Frankfurt, passes local anchor, but routes London traffic through a
        // Tor/VPN relay adding 120 ms (way beyond 2.5x silica fiber stretch for ~640 km!).
        let d_nyc = geodesic_distance_km(FRANKFURT.1, FRANKFURT.2, NEW_YORK.1, NEW_YORK.2);
        let (m1, p1, k1) = build_honest_measurement(3, 99, 1, FRANKFURT, 3_000);
        let (m2, p2, k2) = build_honest_measurement(3, 99, 2, LONDON, 130_000); // VPN/Tor detour!
        let (m3, p3, k3) = build_honest_measurement(
            3,
            99,
            3,
            NEW_YORK,
            (silica_fiber_rtt_us(d_nyc) * 1.3 + 2_000.0) as u64,
        );

        let att = TriangulationAttestation {
            epoch: 3,
            candidate_id: 99,
            claimed_cell_id: FRANKFURT.0,
            claimed_lat_deg: FRANKFURT.1,
            claimed_lon_deg: FRANKFURT.2,
            measurements: vec![m1, m2, m3],
        };

        let err = verifier
            .verify_attestation(&att, vec![p1, p2, p3], vec![k1, k2, k3])
            .unwrap_err();
        assert!(
            matches!(err, TriangulationError::FiberStretchExceeded { anchor_id: 2, .. }),
            "expected FiberStretchExceeded, got {err:?}"
        );
    }

    #[test]
    fn test_forged_probe_response_and_forged_anchor_mac_fail() {
        let verifier = GeoTriangulationVerifier::default();
        let d_lon = geodesic_distance_km(FRANKFURT.1, FRANKFURT.2, LONDON.1, LONDON.2);
        let d_nyc = geodesic_distance_km(FRANKFURT.1, FRANKFURT.2, NEW_YORK.1, NEW_YORK.2);

        // Case A: Forged probe response (even with valid anchor MAC over the forged response).
        let (m1, p1, k1) = build_honest_measurement(4, 101, 1, FRANKFURT, 2_000);
        let (probe_p2, p2) = DistanceProbeKey::generate_pair();
        let (mac_s2, k2) = AnchorMacKey::generate_pair();
        let x2 = random_field_elem();
        let forged_resp = add_mod(respond_probe(x2, probe_p2), 1); // Off by 1!
        let m2 = AnchorProbeMeasurement::sign(
            4,
            101,
            2,
            LONDON.0,
            LONDON.1,
            LONDON.2,
            x2,
            forged_resp,
            (silica_fiber_rtt_us(d_lon) * 1.4 + 2_000.0) as u64,
            mac_s2,
        );
        let (m3, p3, k3) = build_honest_measurement(
            4,
            101,
            3,
            NEW_YORK,
            (silica_fiber_rtt_us(d_nyc) * 1.4 + 2_000.0) as u64,
        );

        let att_bad_probe = TriangulationAttestation {
            epoch: 4,
            candidate_id: 101,
            claimed_cell_id: FRANKFURT.0,
            claimed_lat_deg: FRANKFURT.1,
            claimed_lon_deg: FRANKFURT.2,
            measurements: vec![m1, m2, m3],
        };
        let err_probe = verifier
            .verify_attestation(&att_bad_probe, vec![p1, p2, p3], vec![k1, k2, k3])
            .unwrap_err();
        assert_eq!(err_probe, TriangulationError::InvalidProbeResponse { anchor_id: 2 });

        // Case B: Forged anchor CW-MAC tag (bit flip in tag).
        let (m1, p1, k1) = build_honest_measurement(4, 102, 1, FRANKFURT, 2_000);
        let (mut m2, p2, k2) = build_honest_measurement(
            4,
            102,
            2,
            LONDON,
            (silica_fiber_rtt_us(d_lon) * 1.4 + 2_000.0) as u64,
        );
        m2.anchor_cw_tag[0] ^= 0x01;
        let (m3, p3, k3) = build_honest_measurement(
            4,
            102,
            3,
            NEW_YORK,
            (silica_fiber_rtt_us(d_nyc) * 1.4 + 2_000.0) as u64,
        );
        let att_bad_mac = TriangulationAttestation {
            epoch: 4,
            candidate_id: 102,
            claimed_cell_id: FRANKFURT.0,
            claimed_lat_deg: FRANKFURT.1,
            claimed_lon_deg: FRANKFURT.2,
            measurements: vec![m1, m2, m3],
        };
        let err_mac = verifier
            .verify_attestation(&att_bad_mac, vec![p1, p2, p3], vec![k1, k2, k3])
            .unwrap_err();
        assert_eq!(err_mac, TriangulationError::InvalidAnchorMac { anchor_id: 2 });
    }

    #[test]
    fn test_pad_vault_storage_audit_passes_and_catches_stale_pages_and_late_responses() {
        let auditor = PadVaultStorageAudit::default();
        assert_eq!(auditor.deadline_slack_us, 10_000);

        // Generate 16 unique uncompressible 4 KiB random pages.
        let mut honest_vault: Vec<Vec<u8>> = (0..16)
            .map(|_| {
                let mut page = vec![0u8; 4096];
                fill_os_random(&mut page);
                page
            })
            .collect();

        let rtt_min_us = 12_000u64; // 12 ms physical baseline RTT -> deadline = 22 ms.

        // 1. Honest local vault responds in rtt_min + 3.5 ms (15,500 us <= 22,000 us) -> PASS.
        let (challenge, pk, vk) = auditor
            .issue_challenge(1, 55, honest_vault.len(), 4096, 256, rtt_min_us)
            .unwrap();
        let resp = PadVaultStorageAudit::answer_challenge(&challenge, &honest_vault, pk, 15_500)
            .unwrap();
        auditor
            .verify_response(&challenge, &resp, &honest_vault, vk)
            .expect("honest local pad-vault audit must pass");

        // 2. Stale / corrupted page (1 byte flipped in challenged slice) -> REJECTED!
        let (challenge2, pk2, vk2) = auditor
            .issue_challenge(2, 55, honest_vault.len(), 4096, 256, rtt_min_us)
            .unwrap();
        let mut stale_vault = honest_vault.clone();
        stale_vault[challenge2.page_index][challenge2.byte_offset] ^= 0xFF;
        let stale_resp =
            PadVaultStorageAudit::answer_challenge(&challenge2, &stale_vault, pk2, 14_000)
                .unwrap();
        assert_eq!(
            auditor.verify_response(&challenge2, &stale_resp, &honest_vault, vk2),
            Err(TriangulationError::PadVaultMacMismatch { audit_id: 2 })
        );

        // 3. Remote storage fetch misses tight rtt_min + 10ms deadline (25,000 us > 22,000 us) -> REJECTED!
        let (challenge3, pk3, vk3) = auditor
            .issue_challenge(3, 55, honest_vault.len(), 4096, 256, rtt_min_us)
            .unwrap();
        let late_resp =
            PadVaultStorageAudit::answer_challenge(&challenge3, &honest_vault, pk3, 25_000)
                .unwrap();
        assert_eq!(
            auditor.verify_response(&challenge3, &late_resp, &honest_vault, vk3),
            Err(TriangulationError::AuditDeadlineExceeded {
                audit_id: 3,
                observed_rtt_us: 25_000,
                max_deadline_us: 22_000,
            })
        );

        // Zeroize test pad bytes before exiting.
        for page in &mut honest_vault {
            zeroize_slice(page);
        }
    }
}
