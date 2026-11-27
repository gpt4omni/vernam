//! Global Oblivious Epoch Shuffle & Malicious-Secure SPDZ-IT Mixer for Vernam (VRNM).
//!
//! Breaks the `K = 16` per-bucket anonymity ceiling by shuffling the entire global state of
//! `N_global` accounts (any power-of-2 `N >= 4`, e.g. `16, 64, 256, 1024`) across epochs using
//! **100% information-theoretic MPC over `F_(2^127 - 1)`** (zero external crates, zero
//! computational cryptography — no SHA-256, RSA, ECDSA, AES, or zk-SNARKs):
//!
//! 1. **Waksman–Beneš Switching Network ([`BenesNetwork`])**:
//!    - Decomposes ANY permutation `pi in S_N` (`N = 2^m >= 4`) into `2 * log2(N) - 1` layers of
//!      `N / 2` binary 2-to-2 swap switches via bipartite 2-edge-coloring (the looping algorithm).
//!    - Reversing the layer order of the exact same switch bits computes `pi^(-1)` identically.
//!
//! 2. **Offline Mask Correlation Preprocessing ([`ShuffleMaskCorrelation`])**:
//!    - For dealer `V_k`'s secret permutation `pi_k`, proves every secret-shared switch bit
//!      `[c_{l,s}] in {0, 1}` via a single blinded Schwartz–Zippel RLC over Beaver squares, then
//!      obliviously evaluates the Beneš network over fresh uniform secret-shared masks
//!      `([a_bal_k], [a_tag_k])` (independent and unknown to `V_k`) using 2-branch shared-factor
//!      Beaver stars to produce `([b_bal_k] = [pi_k(a_bal_k)], [b_tag_k] = [pi_k(a_tag_k)])`.
//!    - Evaluates the exact same verified switch shares in reverse layer order on independent
//!      uniform masks `([a_pos_k], [a_pos_tag_k])` to produce inverse-permutation correlations
//!      `([b_pos_k] = [pi_k^(-1)(a_pos_k)], [b_pos_tag_k] = [pi_k^(-1)(a_pos_tag_k)])` for
//!      reverse-order client slot discovery.
//!
//! 3. **Malicious-Secure Online `t`-Hop Oblivious Global Shuffle ([`ObliviousEpochMixer`])**:
//!    - Committee holds SPDZ-IT authenticated state `([bal_i], [T_i])` where
//!      `T_i = kappa * bal_i (mod p)` under a secret-shared MAC key `[kappa] in F_p^*`.
//!    - Online cutover takes ONLY `t` hops (`1` RTT per dealer, **zero** online multiplications):
//!      mask with `[a_k]`, open masked vector exclusively to `V_k` (`0` bits leaked), `V_k`
//!      applies `pi_k` and re-shares, committee locally adds `[b_k]`.
//!    - **Unconditional Malicious-Dealer Verification (`verify_spdz_mac_rlc`)**: uses ONLY `2`
//!      Beaver triples to open `[rho * sum_{i=0}^{N-1} gamma^i * (T'_i - kappa * bal'_i)] == 0`.
//!      Because `[a_bal_k]` and `[a_tag_k]` are independent and unknown to `V_k`, ANY balance
//!      tamper, dropped/duplicated slot, or deviated permutation `pi'_k != pi_k` is caught with
//!      unconditional soundness `<= N / (2^127 - 1)`.
//!
//! 4. **Reverse-Order Zero-Leak Client Slot Discovery (`compose_client_slot_map`)**:
//!    - Composes `Pi = pi_t o ... o pi_1` in reverse order (`k = t-1 ..= 0`) over the
//!      SPDZ-MAC-authenticated secret-shared identity vector `[pos_j] = [j]` using the inverse
//!      correlations so every user `u` reconstructs ONLY its exact new physical slot `Pi(u)` with
//!      `0` bits leaked to any `< t` validator coalition.

use std::fmt;
use std::sync::atomic::{Ordering, compiler_fence};

use crate::field::{
    PRIME_P, add_mod, fill_os_random, mul_mod, random_field_elem, random_nonzero_field_elem,
    sub_mod, zeroize_slice, zeroize_u128,
};
use crate::turbo_shielded::{
    BeaverSquare, BeaverTriple4, Share4, TurboBeaverBank, TurboLagrange3Of4, TurboShieldedError,
    mpc_mul_triple_3_of_4, random_nonzero_challenge, share4_add, share4_sub,
};

// ============================================================================
// Errors
// ============================================================================

/// Errors returned by the global oblivious shuffle and SPDZ-IT MAC verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObliviousShuffleError {
    /// Invalid configuration or protocol parameter (e.g. non-power-of-2 size or `size < 4`).
    InvalidParameters(&'static str),
    /// Supplied slice is not a valid bijection on `0..N`.
    InvalidPermutation(&'static str),
    /// Field element is outside canonical range `[0, PRIME_P)`.
    FieldElementOutOfRange,
    /// `(3, 4)` Shamir shares failed degree-2 Lagrange parity verification.
    InconsistentShares,
    /// Offline oblivious Beneš switch-bit Boolean proof failed (`c * (c - 1) != 0`).
    SwitchProofFailed,
    /// Malicious-secure SPDZ-IT MAC RLC check failed (balance tamper, row duplication/drop,
    /// or deviated permutation `pi'_k != pi_k`).
    SpdzMacCheckFailed,
    /// Underlying Beaver correlated-randomness error.
    BeaverError(TurboShieldedError),
}

impl fmt::Display for ObliviousShuffleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ObliviousShuffleError {}

impl From<TurboShieldedError> for ObliviousShuffleError {
    fn from(err: TurboShieldedError) -> Self {
        match err {
            TurboShieldedError::FieldElementOutOfRange => Self::FieldElementOutOfRange,
            TurboShieldedError::InconsistentShares => Self::InconsistentShares,
            other => Self::BeaverError(other),
        }
    }
}

// ============================================================================
// Internal Zeroization & Randomness Helpers
// ============================================================================

#[inline(always)]
fn zeroize_share4_nofence(s: &mut Share4) {
    for elem in s.iter_mut() {
        // SAFETY: `elem` is a valid mutable reference to an initialized `u128`.
        unsafe { std::ptr::write_volatile(elem, 0u128) };
    }
}

#[inline(always)]
fn zeroize_share4(s: &mut Share4) {
    zeroize_share4_nofence(s);
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_share4_slice(slice: &mut [Share4]) {
    for s in slice.iter_mut() {
        zeroize_share4_nofence(s);
    }
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_u128_slice(slice: &mut [u128]) {
    for elem in slice.iter_mut() {
        // SAFETY: `elem` is a valid mutable reference to an initialized `u128`.
        unsafe { std::ptr::write_volatile(elem, 0u128) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_usize_slice(slice: &mut [usize]) {
    for elem in slice.iter_mut() {
        // SAFETY: `elem` is a valid mutable reference to an initialized `usize`.
        unsafe { std::ptr::write_volatile(elem, 0usize) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn fill_random_field_elems(out: &mut [u128]) {
    if out.is_empty() {
        return;
    }
    let mut raw = vec![0u8; out.len() * 16];
    fill_os_random(&mut raw);
    let mut buf = [0u8; 16];
    for (dst, chunk) in out.iter_mut().zip(raw.chunks_exact(16)) {
        buf.copy_from_slice(chunk);
        let cand = u128::from_le_bytes(buf) & PRIME_P;
        *dst = if cand < PRIME_P {
            cand
        } else {
            random_field_elem()
        };
    }
    zeroize_slice(&mut buf);
    zeroize_slice(&mut raw);
}

/// Generate a fresh `(3, 4)` sharing of a uniform random element in `[0, PRIME_P)`.
fn split_random_vector(len: usize) -> Vec<Share4> {
    let mut rands = vec![0u128; len * 3];
    fill_random_field_elems(&mut rands);
    let mut out = Vec::with_capacity(len);
    for chunk in rands.chunks_exact(3) {
        out.push(TurboLagrange3Of4::eval_poly(chunk[0], chunk[1], chunk[2]));
    }
    zeroize_u128_slice(&mut rands);
    out
}

/// Generate a fresh `(3, 4)` sharing of `0` (`z(0) = 0`) for re-randomization.
fn split_zero_share4() -> Share4 {
    let mut r = [0u128; 2];
    fill_random_field_elems(&mut r);
    let out = TurboLagrange3Of4::eval_poly(0, r[0], r[1]);
    zeroize_u128_slice(&mut r);
    out
}

/// Split a slice of canonical field elements into fresh `(3, 4)` Shamir shares in one entropy read.
fn split_vector(values: &[u128]) -> Result<Vec<Share4>, ObliviousShuffleError> {
    for &v in values {
        if v >= PRIME_P {
            return Err(ObliviousShuffleError::FieldElementOutOfRange);
        }
    }
    let mut rands = vec![0u128; values.len() * 2];
    fill_random_field_elems(&mut rands);
    let mut out = Vec::with_capacity(values.len());
    for (&val, chunk) in values.iter().zip(rands.chunks_exact(2)) {
        out.push(TurboLagrange3Of4::eval_poly(val, chunk[0], chunk[1]));
    }
    zeroize_u128_slice(&mut rands);
    Ok(out)
}

/// Sample a fresh uniform non-zero secret-shared blinding scalar `[rho]` (`rho in [1, PRIME_P)`).
fn random_nonzero_share4() -> Share4 {
    let mut rho = random_nonzero_field_elem();
    let mut r = [0u128; 2];
    fill_random_field_elems(&mut r);
    let shares = TurboLagrange3Of4::eval_poly(rho, r[0], r[1]);
    zeroize_u128(&mut rho);
    zeroize_u128_slice(&mut r);
    shares
}

#[inline(always)]
fn share4_scale(x: &Share4, scalar: u128) -> Share4 {
    [
        mul_mod(x[0], scalar),
        mul_mod(x[1], scalar),
        mul_mod(x[2], scalar),
        mul_mod(x[3], scalar),
    ]
}

#[inline(always)]
fn share4_add_const(x: &Share4, c: u128) -> Share4 {
    [
        add_mod(x[0], c),
        add_mod(x[1], c),
        add_mod(x[2], c),
        add_mod(x[3], c),
    ]
}

/// Sample a uniform random `usize` in `[0, bound)` using unbiased rejection sampling over OS entropy.
fn random_usize_below(bound: usize) -> usize {
    debug_assert!(bound > 0);
    let bound_u64 = bound as u64;
    let limit = u64::MAX - (u64::MAX % bound_u64);
    let mut bytes = [0u8; 8];
    loop {
        fill_os_random(&mut bytes);
        let val = u64::from_le_bytes(bytes);
        if val < limit {
            zeroize_slice(&mut bytes);
            return (val % bound_u64) as usize;
        }
    }
}

/// Validate that `perm` is a valid permutation of `0..N` for power-of-2 `N >= 4` and compute
/// its inverse `inv_perm` (`inv_perm[perm[i]] = i`).
fn validate_and_invert_permutation(perm: &[usize]) -> Result<Vec<usize>, ObliviousShuffleError> {
    let n = perm.len();
    if n < 4 || !n.is_power_of_two() {
        return Err(ObliviousShuffleError::InvalidParameters(
            "permutation length must be a power of 2 with N >= 4",
        ));
    }
    let mut seen = vec![false; n];
    let mut inv = vec![0usize; n];
    for (i, &dst) in perm.iter().enumerate() {
        if dst >= n {
            return Err(ObliviousShuffleError::InvalidPermutation(
                "permutation image out of range",
            ));
        }
        if seen[dst] {
            return Err(ObliviousShuffleError::InvalidPermutation(
                "duplicate image in permutation",
            ));
        }
        seen[dst] = true;
        inv[dst] = i;
    }
    Ok(inv)
}

// ============================================================================
// 1. Waksman–Beneš Switching Network (`BenesNetwork`)
// ============================================================================

/// Waksman–Beneš switching network decomposing any permutation `pi in S_N` (`N = 2^m >= 4`)
/// into `2 * log2(N) - 1` layers of `N / 2` binary 2-to-2 swap switches.
///
/// Convention: applying the network to `input[0..N]` produces `output[0..N]` satisfying
/// `output[pi[i]] == input[i]` for every `i in 0..N` (push-permutation semantics).
/// Reversing the layer order yields the exact inverse permutation `pi^(-1)` (`out[i] = in[pi[i]]`).
#[derive(Clone, PartialEq, Eq)]
pub struct BenesNetwork {
    size: usize,
    log_n: usize,
    /// `2 * log_n - 1` layers, each containing `size / 2` binary swap switches.
    layers: Vec<Vec<bool>>,
}

impl fmt::Debug for BenesNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BenesNetwork")
            .field("size", &self.size)
            .field("num_layers", &self.layers.len())
            .field("switches_per_layer", &(self.size / 2))
            .field("switches", &"<redacted>")
            .finish()
    }
}

impl BenesNetwork {
    /// Decompose any permutation `perm` of `0..N` (power-of-2 `N >= 4`) into a
    /// `(2 * log2(N) - 1)`-layer Waksman–Beneš network of `N / 2` switches per layer,
    /// and verify exact permutation equivalence before returning.
    pub fn from_permutation(perm: &[usize]) -> Result<Self, ObliviousShuffleError> {
        let _inv = validate_and_invert_permutation(perm)?;
        let n = perm.len();
        let log_n = n.trailing_zeros() as usize;
        let num_layers = 2 * log_n - 1;
        let mut layers = vec![vec![false; n / 2]; num_layers];

        Self::route_recursive(perm, 0, 0, log_n, &mut layers);

        let net = Self {
            size: n,
            log_n,
            layers,
        };

        // Verify exact permutation equivalence: routing `[0, 1, ..., N-1]` MUST place `i` at `perm[i]`.
        let identity: Vec<usize> = (0..n).collect();
        let routed = net.apply_plaintext(&identity)?;
        for (i, &dst) in perm.iter().enumerate() {
            if routed[dst] != i {
                return Err(ObliviousShuffleError::InvalidPermutation(
                    "Benes network routing equivalence verification failed",
                ));
            }
        }

        Ok(net)
    }

    /// Recursive bipartite 2-edge-coloring (looping algorithm) routing `sub_perm` of length
    /// `n = 2^(log_n - depth)` at strided sub-network `(depth, offset)`.
    fn route_recursive(
        sub_perm: &[usize],
        depth: usize,
        offset: usize,
        log_n: usize,
        layers: &mut [Vec<bool>],
    ) {
        let n = sub_perm.len();
        debug_assert!(n >= 2 && n.is_power_of_two());

        if n == 2 {
            // Middle layer (`depth == log_n - 1`): single 2-to-2 switch at `offset`.
            layers[depth][offset] = sub_perm[0] == 1;
            return;
        }

        let k = n / 2;
        let stride = 1usize << depth;
        let in_layer = depth;
        let out_layer = (2 * log_n - 2) - depth;

        // Build inverse of sub_perm for O(1) cycle traversal.
        let mut inv = vec![0usize; n];
        for (u, &v) in sub_perm.iter().enumerate() {
            inv[v] = u;
        }

        // 2-color the 2-regular bipartite multigraph connecting input switches (u/2) and
        // output switches (sub_perm[u]/2). Color 0 = upper sub-network, Color 1 = lower.
        let mut color = vec![u8::MAX; n];
        for start_u in 0..n {
            if color[start_u] != u8::MAX {
                continue;
            }
            let mut u = start_u;
            let c = 0u8;
            loop {
                color[u] = c;
                let v = sub_perm[u];
                let u_next = inv[v ^ 1];
                if color[u_next] != u8::MAX {
                    debug_assert_eq!(color[u_next], c ^ 1);
                    break;
                }
                color[u_next] = c ^ 1;
                let u_partner = u_next ^ 1;
                if color[u_partner] != u8::MAX {
                    debug_assert_eq!(color[u_partner], c);
                    break;
                }
                u = u_partner;
            }
        }

        // Set input-layer and output-layer switch bits for this sub-network.
        for a in 0..k {
            let sw_idx = offset + a * stride;
            layers[in_layer][sw_idx] = color[2 * a] == 1;
        }
        for b in 0..k {
            let sw_idx = offset + b * stride;
            layers[out_layer][sw_idx] = color[inv[2 * b]] == 1;
        }

        // Build upper (color 0) and lower (color 1) sub-permutations of size `k = n / 2`.
        let mut upper_perm = vec![0usize; k];
        let mut lower_perm = vec![0usize; k];
        for u in 0..n {
            let sub_in = u >> 1;
            let sub_out = sub_perm[u] >> 1;
            if color[u] == 0 {
                upper_perm[sub_in] = sub_out;
            } else {
                lower_perm[sub_in] = sub_out;
            }
        }

        Self::route_recursive(&upper_perm, depth + 1, offset, log_n, layers);
        Self::route_recursive(&lower_perm, depth + 1, offset + stride, log_n, layers);
    }

    /// Network width `N` (number of slots/wires).
    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    /// Always false for valid `BenesNetwork` (`N >= 4`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Exact number of layers `2 * log2(N) - 1`.
    #[inline]
    pub fn num_layers(&self) -> usize {
        self.layers.len()
    }

    /// Exact number of binary swap switches per layer (`N / 2`).
    #[inline]
    pub fn switches_per_layer(&self) -> usize {
        self.size / 2
    }

    /// Butterfly wire stride `2^(min(layer, 2*log2(N) - 2 - layer))` for `layer`.
    #[inline]
    pub fn layer_stride(&self, layer: usize) -> usize {
        let d = layer.min((2 * self.log_n - 2) - layer);
        1usize << d
    }

    /// Exact wire pair `(w0, w1)` switched by `switch_idx` in `layer`.
    #[inline]
    pub fn switch_wires(&self, layer: usize, switch_idx: usize) -> (usize, usize) {
        let d = layer.min((2 * self.log_n - 2) - layer);
        let stride = 1usize << d;
        let offset = switch_idx & (stride - 1);
        let a = switch_idx >> d;
        let w0 = (a << (d + 1)) | offset;
        let w1 = w0 | stride;
        (w0, w1)
    }

    /// Binary swap switch vector for `layer`.
    #[inline]
    pub fn layer_switches(&self, layer: usize) -> &[bool] {
        &self.layers[layer]
    }

    /// Construct the exact inverse network (`pi^(-1)`) by reversing the layer order.
    ///
    /// Because every layer is a product of disjoint 2-cycles (an involution) and layer strides are
    /// symmetric (`stride(l) == stride(L - 1 - l)`), reversing the layers is mathematically
    /// identical to `pi^(-1)`.
    pub fn reverse_layers(&self) -> Self {
        let mut rev = self.layers.clone();
        rev.reverse();
        Self {
            size: self.size,
            log_n: self.log_n,
            layers: rev,
        }
    }

    /// Apply this switching network in plaintext to `input[0..N]`, returning `out` with
    /// `out[pi[i]] == input[i]`.
    pub fn apply_plaintext<T: Copy>(&self, input: &[T]) -> Result<Vec<T>, ObliviousShuffleError> {
        if input.len() != self.size {
            return Err(ObliviousShuffleError::InvalidParameters(
                "input length does not match Benes network size",
            ));
        }
        let mut wires = input.to_vec();
        for layer in 0..self.num_layers() {
            let switches = &self.layers[layer];
            for (sw_idx, &swap) in switches.iter().enumerate() {
                if swap {
                    let (w0, w1) = self.switch_wires(layer, sw_idx);
                    wires.swap(w0, w1);
                }
            }
        }
        Ok(wires)
    }
}

// ============================================================================
// 2. Offline Mask Correlation Preprocessing (`ShuffleMaskCorrelation`)
// ============================================================================

/// Internal 2-branch shared-factor Beaver Star `([a_c], [b0], [b1], [c0 = a_c*b0], [c1 = a_c*b1])`
/// used inside oblivious Beneš switch evaluation so each switch opens `d = c - a_c` ONLY ONCE
/// across both parallel vectors (`bal` and `tag`, or `pos` and `pos_tag`).
struct BeaverStar2 {
    a_c: Share4,
    b0: Share4,
    b1: Share4,
    c0: Share4,
    c1: Share4,
}

impl BeaverStar2 {
    fn generate_batch(count: usize) -> Vec<Self> {
        // 13 field elements per BeaverStar2:
        // a_c0, a_c1, a_c2, b0_0, b0_1, b0_2, b1_0, b1_1, b1_2, c0_1, c0_2, c1_1, c1_2.
        const ELEMS: usize = 13;
        let mut entropy = vec![0u128; count * ELEMS];
        fill_random_field_elems(&mut entropy);
        let mut out = Vec::with_capacity(count);
        for ch in entropy.chunks_exact(ELEMS) {
            let mut ac0 = ch[0];
            let mut b0_0 = ch[3];
            let mut b1_0 = ch[6];
            let mut c0_0 = mul_mod(ac0, b0_0);
            let mut c1_0 = mul_mod(ac0, b1_0);
            let a_c = TurboLagrange3Of4::eval_poly(ac0, ch[1], ch[2]);
            let b0 = TurboLagrange3Of4::eval_poly(b0_0, ch[4], ch[5]);
            let b1 = TurboLagrange3Of4::eval_poly(b1_0, ch[7], ch[8]);
            let c0 = TurboLagrange3Of4::eval_poly(c0_0, ch[9], ch[10]);
            let c1 = TurboLagrange3Of4::eval_poly(c1_0, ch[11], ch[12]);
            zeroize_u128(&mut ac0);
            zeroize_u128(&mut b0_0);
            zeroize_u128(&mut b1_0);
            zeroize_u128(&mut c0_0);
            zeroize_u128(&mut c1_0);
            out.push(Self {
                a_c,
                b0,
                b1,
                c0,
                c1,
            });
        }
        zeroize_u128_slice(&mut entropy);
        out
    }

    #[inline]
    fn multiply_pair(
        mut self,
        c_share: &Share4,
        x0: &Share4,
        x1: &Share4,
    ) -> Result<(Share4, Share4), ObliviousShuffleError> {
        let mut d_diff = share4_sub(c_share, &self.a_c);
        let mut e0_diff = share4_sub(x0, &self.b0);
        let mut e1_diff = share4_sub(x1, &self.b1);
        let d = TurboLagrange3Of4::reconstruct_and_verify(&d_diff)?;
        let e0 = TurboLagrange3Of4::reconstruct_and_verify(&e0_diff)?;
        let e1 = TurboLagrange3Of4::reconstruct_and_verify(&e1_diff)?;
        zeroize_share4_nofence(&mut d_diff);
        zeroize_share4_nofence(&mut e0_diff);
        zeroize_share4_nofence(&mut e1_diff);

        let de0 = mul_mod(d, e0);
        let de1 = mul_mod(d, e1);
        let prod0 = share4_add_const(
            &share4_add(
                &self.c0,
                &share4_add(&share4_scale(&self.b0, d), &share4_scale(&self.a_c, e0)),
            ),
            de0,
        );
        let prod1 = share4_add_const(
            &share4_add(
                &self.c1,
                &share4_add(&share4_scale(&self.b1, d), &share4_scale(&self.a_c, e1)),
            ),
            de1,
        );
        self.wipe();
        Ok((prod0, prod1))
    }

    fn wipe(&mut self) {
        zeroize_share4_nofence(&mut self.a_c);
        zeroize_share4_nofence(&mut self.b0);
        zeroize_share4_nofence(&mut self.b1);
        zeroize_share4_nofence(&mut self.c0);
        zeroize_share4_nofence(&mut self.c1);
        compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for BeaverStar2 {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Dealer `V_k`'s private epoch permutation `pi_k` (and cached inverse `pi_k^(-1)`).
///
/// Redacts `Debug` output and volatile-zeroizes permutation tables on `Drop`.
pub struct DealerShuffleSecret {
    dealer_id: usize,
    perm: Vec<usize>,
    inv_perm: Vec<usize>,
}

impl fmt::Debug for DealerShuffleSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DealerShuffleSecret")
            .field("dealer_id", &self.dealer_id)
            .field("size", &self.perm.len())
            .field("perm", &"<redacted>")
            .finish()
    }
}

impl DealerShuffleSecret {
    /// Sample a uniformly random permutation `pi_k in S_N` (`N = 2^m >= 4`) via unbiased
    /// Fisher–Yates over OS `/dev/urandom`.
    pub fn random(dealer_id: usize, size: usize) -> Result<Self, ObliviousShuffleError> {
        if size < 4 || !size.is_power_of_two() {
            return Err(ObliviousShuffleError::InvalidParameters(
                "dealer permutation size must be a power of 2 with N >= 4",
            ));
        }
        let mut perm: Vec<usize> = (0..size).collect();
        for i in (1..size).rev() {
            let j = random_usize_below(i + 1);
            perm.swap(i, j);
        }
        Self::from_permutation(dealer_id, perm)
    }

    /// Construct from an explicit permutation `perm` of `0..N` (`N = 2^m >= 4`).
    pub fn from_permutation(
        dealer_id: usize,
        perm: Vec<usize>,
    ) -> Result<Self, ObliviousShuffleError> {
        let inv_perm = validate_and_invert_permutation(&perm)?;
        Ok(Self {
            dealer_id,
            perm,
            inv_perm,
        })
    }

    /// Dealer index `k`.
    #[inline]
    pub fn dealer_id(&self) -> usize {
        self.dealer_id
    }

    /// Global slot count `N`.
    #[inline]
    pub fn len(&self) -> usize {
        self.perm.len()
    }

    /// Always false for valid `DealerShuffleSecret` (`N >= 4`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.perm.is_empty()
    }

    /// Forward permutation `pi_k` (`input[i]` moves to `output[perm[i]]`).
    #[inline]
    pub fn perm(&self) -> &[usize] {
        &self.perm
    }

    /// Inverse permutation `pi_k^(-1)` (`inv_perm[perm[i]] == i`).
    #[inline]
    pub fn inv_perm(&self) -> &[usize] {
        &self.inv_perm
    }

    /// Apply forward push permutation `out[pi_k[i]] = input[i]`.
    pub fn apply_forward_plaintext(&self, input: &[u128]) -> Result<Vec<u128>, ObliviousShuffleError> {
        if input.len() != self.perm.len() {
            return Err(ObliviousShuffleError::InvalidParameters(
                "input length mismatch in dealer forward shuffle",
            ));
        }
        let mut out = vec![0u128; input.len()];
        for (i, &val) in input.iter().enumerate() {
            out[self.perm[i]] = val;
        }
        Ok(out)
    }

    /// Apply inverse push permutation `out[i] = input[pi_k[i]]` (equivalently `out[inv_perm[j]] = input[j]`).
    pub fn apply_inverse_plaintext(&self, input: &[u128]) -> Result<Vec<u128>, ObliviousShuffleError> {
        if input.len() != self.perm.len() {
            return Err(ObliviousShuffleError::InvalidParameters(
                "input length mismatch in dealer inverse shuffle",
            ));
        }
        let mut out = vec![0u128; input.len()];
        for i in 0..input.len() {
            out[i] = input[self.perm[i]];
        }
        Ok(out)
    }
}

impl Drop for DealerShuffleSecret {
    fn drop(&mut self) {
        zeroize_usize_slice(&mut self.perm);
        zeroize_usize_slice(&mut self.inv_perm);
    }
}

/// Verify that EVERY secret-shared switch bit `c` in `switch_shares` satisfies `c * (c - 1) == 0`
/// using Beaver squares + a single blinded Schwartz–Zippel RLC opening.
fn verify_switch_bits_boolean(
    switch_shares: &[Vec<Share4>],
    squares: Vec<BeaverSquare>,
    blind_triple: BeaverTriple4,
) -> Result<(), ObliviousShuffleError> {
    let total_switches: usize = switch_shares.iter().map(Vec::len).sum();
    if squares.len() < total_switches {
        return Err(ObliviousShuffleError::InvalidParameters(
            "insufficient Beaver squares for switch-bit verification",
        ));
    }
    let gamma = random_nonzero_challenge();
    let mut z: Share4 = [0u128; 4];
    let mut sq_iter = squares.into_iter();

    for layer in switch_shares {
        for c in layer {
            TurboLagrange3Of4::verify_degree2(c)?;
            let sq = sq_iter
                .next()
                .ok_or(ObliviousShuffleError::InvalidParameters(
                    "missing Beaver square",
                ))?;
            let mut diff = share4_sub(c, sq.a());
            let d = TurboLagrange3Of4::reconstruct_and_verify(&diff)?;
            zeroize_share4_nofence(&mut diff);

            // c * (c - 1) = a^2 + (2*d - 1)*a + d*(d - 1).
            let two_d_m1 = sub_mod(add_mod(d, d), 1);
            let d_dm1 = mul_mod(d, sub_mod(d, 1));
            let check = share4_add_const(
                &share4_add(sq.a_sq(), &share4_scale(sq.a(), two_d_m1)),
                d_dm1,
            );
            drop(sq);
            z = share4_add(&share4_scale(&z, gamma), &check);
        }
    }

    let mut rho = random_nonzero_share4();
    let mut z_blind = mpc_mul_triple_3_of_4(&rho, &z, blind_triple)?;
    zeroize_share4_nofence(&mut rho);
    zeroize_share4_nofence(&mut z);
    let opened = TurboLagrange3Of4::reconstruct_and_verify(&z_blind)?;
    zeroize_share4(&mut z_blind);
    if opened != 0 {
        return Err(ObliviousShuffleError::SwitchProofFailed);
    }
    Ok(())
}

/// Obliviously evaluate a Beneš network (in forward or reverse layer order) over two secret-shared
/// vectors `(vec0, vec1)` using secret-shared switch bits `switch_shares` and `BeaverStar2` pairs.
fn oblivious_apply_benes_pair(
    size: usize,
    log_n: usize,
    switch_shares: &[Vec<Share4>],
    reverse: bool,
    vec0: &[Share4],
    vec1: &[Share4],
) -> Result<(Vec<Share4>, Vec<Share4>), ObliviousShuffleError> {
    let num_layers = 2 * log_n - 1;
    let switches_per_layer = size / 2;
    if switch_shares.len() != num_layers || vec0.len() != size || vec1.len() != size {
        return Err(ObliviousShuffleError::InvalidParameters(
            "dimension mismatch in oblivious Benes evaluation",
        ));
    }

    let total_switches = num_layers * switches_per_layer;
    let mut stars2 = BeaverStar2::generate_batch(total_switches).into_iter();
    let mut w0_vec = vec0.to_vec();
    let mut w1_vec = vec1.to_vec();

    for step in 0..num_layers {
        let layer = if reverse {
            num_layers - 1 - step
        } else {
            step
        };
        let d = layer.min((2 * log_n - 2) - layer);
        let stride = 1usize << d;
        let layer_bits = &switch_shares[layer];

        for (sw_idx, c_share) in layer_bits.iter().enumerate() {
            let offset = sw_idx & (stride - 1);
            let a = sw_idx >> d;
            let i0 = (a << (d + 1)) | offset;
            let i1 = i0 | stride;

            let mut diff0 = share4_sub(&w0_vec[i1], &w0_vec[i0]);
            let mut diff1 = share4_sub(&w1_vec[i1], &w1_vec[i0]);
            let star = stars2
                .next()
                .ok_or(ObliviousShuffleError::InvalidParameters(
                    "exhausted BeaverStar2 batch",
                ))?;
            let (mut delta0, mut delta1) = star.multiply_pair(c_share, &diff0, &diff1)?;
            zeroize_share4_nofence(&mut diff0);
            zeroize_share4_nofence(&mut diff1);

            w0_vec[i0] = share4_add(&w0_vec[i0], &delta0);
            w0_vec[i1] = share4_sub(&w0_vec[i1], &delta0);
            w1_vec[i0] = share4_add(&w1_vec[i0], &delta1);
            w1_vec[i1] = share4_sub(&w1_vec[i1], &delta1);
            zeroize_share4_nofence(&mut delta0);
            zeroize_share4_nofence(&mut delta1);
        }
    }
    compiler_fence(Ordering::SeqCst);
    Ok((w0_vec, w1_vec))
}

/// Strictly single-use forward mask correlation `([a_bal], [b_bal] = [pi_k(a_bal)], [a_tag], [b_tag] = [pi_k(a_tag)])`
/// for dealer `V_k`'s online state-shuffle hop.
///
/// Move-only (no `Copy`/`Clone`), redacted `Debug`, and volatile-zeroized on `Drop`.
pub struct ForwardMaskCorrelation {
    dealer_id: usize,
    size: usize,
    a_bal: Vec<Share4>,
    b_bal: Vec<Share4>,
    a_tag: Vec<Share4>,
    b_tag: Vec<Share4>,
}

impl fmt::Debug for ForwardMaskCorrelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardMaskCorrelation")
            .field("dealer_id", &self.dealer_id)
            .field("size", &self.size)
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl ForwardMaskCorrelation {
    /// Dealer index `k`.
    #[inline]
    pub fn dealer_id(&self) -> usize {
        self.dealer_id
    }

    /// Global slot count `N`.
    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    /// Always false for valid correlation (`N >= 4`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Drop for ForwardMaskCorrelation {
    fn drop(&mut self) {
        zeroize_share4_slice(&mut self.a_bal);
        zeroize_share4_slice(&mut self.b_bal);
        zeroize_share4_slice(&mut self.a_tag);
        zeroize_share4_slice(&mut self.b_tag);
    }
}

/// Strictly single-use inverse mask correlation
/// `([a_pos], [b_pos] = [pi_k^(-1)(a_pos)], [a_pos_tag], [b_pos_tag] = [pi_k^(-1)(a_pos_tag)])`
/// for reverse-order zero-leak client slot discovery.
///
/// Move-only (no `Copy`/`Clone`), redacted `Debug`, and volatile-zeroized on `Drop`.
pub struct InverseMaskCorrelation {
    dealer_id: usize,
    size: usize,
    a_pos: Vec<Share4>,
    b_pos: Vec<Share4>,
    a_pos_tag: Vec<Share4>,
    b_pos_tag: Vec<Share4>,
}

impl fmt::Debug for InverseMaskCorrelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InverseMaskCorrelation")
            .field("dealer_id", &self.dealer_id)
            .field("size", &self.size)
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl InverseMaskCorrelation {
    /// Dealer index `k`.
    #[inline]
    pub fn dealer_id(&self) -> usize {
        self.dealer_id
    }

    /// Global slot count `N`.
    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    /// Always false for valid correlation (`N >= 4`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Drop for InverseMaskCorrelation {
    fn drop(&mut self) {
        zeroize_share4_slice(&mut self.a_pos);
        zeroize_share4_slice(&mut self.b_pos);
        zeroize_share4_slice(&mut self.a_pos_tag);
        zeroize_share4_slice(&mut self.b_pos_tag);
    }
}

/// Complete offline correlated-randomness bundle for one dealer `V_k`'s epoch shuffle hop:
/// contains BOTH the forward balance/tag mask correlation (`pi_k`) AND the inverse client slot
/// discovery mask correlation (`pi_k^(-1)`), derived from the EXACT SAME verified Boolean
/// Waksman–Beneš switch shares.
///
/// Move-only (no `Copy`/`Clone`), redacted `Debug`, and volatile-zeroized on `Drop`.
pub struct ShuffleMaskCorrelation {
    forward: ForwardMaskCorrelation,
    inverse: InverseMaskCorrelation,
}

impl fmt::Debug for ShuffleMaskCorrelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShuffleMaskCorrelation")
            .field("dealer_id", &self.forward.dealer_id)
            .field("size", &self.forward.size)
            .field("forward", &"<redacted>")
            .field("inverse", &"<redacted>")
            .finish()
    }
}

impl ShuffleMaskCorrelation {
    /// Run offline Beneš preprocessing for dealer `V_k`'s secret permutation `pi_k`:
    ///
    /// 1. Decompose `pi_k` into a `(2*log2(N) - 1)`-layer [`BenesNetwork`].
    /// 2. Secret-share every switch bit `[c_{l,s}]` and prove all switch bits are strictly in
    ///    `{0, 1}` via a single blinded Schwartz–Zippel RLC over Beaver squares.
    /// 3. Sample fresh uniform independent masks `([a_bal], [a_tag])` (unknown to `V_k`) and run
    ///    the Beneš network obliviously forward to obtain `([b_bal], [b_tag])`.
    /// 4. Sample fresh uniform independent masks `([a_pos], [a_pos_tag])` (unknown to `V_k`) and
    ///    run the EXACT SAME verified switch shares in reverse layer order to obtain
    ///    `([b_pos] = [pi_k^(-1)(a_pos)], [b_pos_tag] = [pi_k^(-1)(a_pos_tag)])`.
    pub fn generate(dealer: &DealerShuffleSecret) -> Result<Self, ObliviousShuffleError> {
        let net = BenesNetwork::from_permutation(dealer.perm())?;
        let n = net.len();
        let log_n = n.trailing_zeros() as usize;
        let num_layers = net.num_layers();

        // Secret-share every switch bit of dealer V_k's Beneš network.
        let mut switch_shares = Vec::with_capacity(num_layers);
        for l in 0..num_layers {
            let bits_u128: Vec<u128> = net
                .layer_switches(l)
                .iter()
                .map(|&sw| if sw { 1u128 } else { 0u128 })
                .collect();
            switch_shares.push(split_vector(&bits_u128)?);
        }

        let res = Self::generate_from_switch_shares(dealer.dealer_id(), n, log_n, &switch_shares);
        for layer in switch_shares.iter_mut() {
            zeroize_share4_slice(layer);
        }
        res
    }

    /// Lower-level offline preprocessing accepting secret-shared Beneš switch bits directly
    /// (verifies every switch bit is Boolean via blinded RLC so a malicious dealer cannot supply
    /// non-binary switches).
    pub fn generate_from_switch_shares(
        dealer_id: usize,
        size: usize,
        log_n: usize,
        switch_shares: &[Vec<Share4>],
    ) -> Result<Self, ObliviousShuffleError> {
        if size < 4 || !size.is_power_of_two() || (1usize << log_n) != size {
            return Err(ObliviousShuffleError::InvalidParameters(
                "invalid Benes size/log_n",
            ));
        }
        let num_layers = 2 * log_n - 1;
        let sw_per_layer = size / 2;
        if switch_shares.len() != num_layers
            || switch_shares.iter().any(|l| l.len() != sw_per_layer)
        {
            return Err(ObliviousShuffleError::InvalidParameters(
                "switch_shares shape does not match Benes network dimensions",
            ));
        }

        let total_switches = num_layers * sw_per_layer;
        let mut bank = TurboBeaverBank::new(total_switches, 0, 1);
        let mut squares = Vec::with_capacity(total_switches);
        for _ in 0..total_switches {
            squares.push(bank.pop_square()?);
        }
        let blind_triple = bank.pop_triple()?;
        verify_switch_bits_boolean(switch_shares, squares, blind_triple)?;

        // Forward mask pair: independent uniform `[a_bal]` and `[a_tag]` unknown to dealer V_k.
        let a_bal = split_random_vector(size);
        let a_tag = split_random_vector(size);
        let (b_bal, b_tag) =
            oblivious_apply_benes_pair(size, log_n, switch_shares, false, &a_bal, &a_tag)?;

        // Inverse mask pair: independent uniform `[a_pos]` and `[a_pos_tag]` routed through the
        // EXACT SAME verified switch shares in reverse layer order (`pi_k^(-1)`).
        let a_pos = split_random_vector(size);
        let a_pos_tag = split_random_vector(size);
        let (b_pos, b_pos_tag) =
            oblivious_apply_benes_pair(size, log_n, switch_shares, true, &a_pos, &a_pos_tag)?;

        Ok(Self {
            forward: ForwardMaskCorrelation {
                dealer_id,
                size,
                a_bal,
                b_bal,
                a_tag,
                b_tag,
            },
            inverse: InverseMaskCorrelation {
                dealer_id,
                size,
                a_pos,
                b_pos,
                a_pos_tag,
                b_pos_tag,
            },
        })
    }

    /// Consume and split into strictly single-use `(ForwardMaskCorrelation, InverseMaskCorrelation)`.
    #[inline]
    pub fn into_parts(self) -> (ForwardMaskCorrelation, InverseMaskCorrelation) {
        (self.forward, self.inverse)
    }

    /// Dealer index `k`.
    #[inline]
    pub fn dealer_id(&self) -> usize {
        self.forward.dealer_id
    }

    /// Global slot count `N`.
    #[inline]
    pub fn len(&self) -> usize {
        self.forward.size
    }

    /// Always false for valid correlation (`N >= 4`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.forward.size == 0
    }
}

// ============================================================================
// 3. SPDZ-IT Authenticated State & Unconditional Malicious-Dealer Verification
// ============================================================================

/// Secret-shared global ledger state authenticated with information-theoretic SPDZ-IT MACs:
/// `([bal_i], [T_i])` where `T_i = kappa * bal_i (mod PRIME_P)` under secret-shared `[kappa] in F_p^*`.
///
/// Redacts `Debug` and volatile-zeroizes all shares on `Drop`.
pub struct AuthenticatedLedgerState {
    balances: Vec<Share4>,
    mac_tags: Vec<Share4>,
    mac_key: Share4,
}

impl fmt::Debug for AuthenticatedLedgerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedLedgerState")
            .field("slots", &self.balances.len())
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl AuthenticatedLedgerState {
    /// Initialize SPDZ-IT authenticated state for `balances[0..N]` (`N = 2^m >= 4`) under a fresh
    /// uniform non-zero secret-shared MAC key `[kappa] in F_p^*`.
    pub fn new_from_plaintext(balances: &[u128]) -> Result<Self, ObliviousShuffleError> {
        let n = balances.len();
        if n < 4 || !n.is_power_of_two() {
            return Err(ObliviousShuffleError::InvalidParameters(
                "global shuffle state length must be a power of 2 with N >= 4",
            ));
        }
        for &b in balances {
            if b >= PRIME_P {
                return Err(ObliviousShuffleError::FieldElementOutOfRange);
            }
        }
        let mut kappa = random_nonzero_field_elem();
        let mac_key = TurboLagrange3Of4::split_secret(kappa)?;
        let bal_shares = split_vector(balances)?;
        let mut plain_tags: Vec<u128> = balances.iter().map(|&b| mul_mod(kappa, b)).collect();
        let tag_shares = split_vector(&plain_tags)?;
        zeroize_u128(&mut kappa);
        zeroize_u128_slice(&mut plain_tags);
        Ok(Self {
            balances: bal_shares,
            mac_tags: tag_shares,
            mac_key,
        })
    }

    /// Construct from pre-existing secret-shared balances, MAC tags, and MAC key.
    pub fn from_shares(
        balances: Vec<Share4>,
        mac_tags: Vec<Share4>,
        mac_key: Share4,
    ) -> Result<Self, ObliviousShuffleError> {
        let n = balances.len();
        if n < 4 || !n.is_power_of_two() || mac_tags.len() != n {
            return Err(ObliviousShuffleError::InvalidParameters(
                "invalid share vector lengths for AuthenticatedLedgerState",
            ));
        }
        TurboLagrange3Of4::verify_degree2(&mac_key)?;
        for i in 0..n {
            TurboLagrange3Of4::verify_degree2(&balances[i])?;
            TurboLagrange3Of4::verify_degree2(&mac_tags[i])?;
        }
        Ok(Self {
            balances,
            mac_tags,
            mac_key,
        })
    }

    /// Number of global account slots `N`.
    #[inline]
    pub fn len(&self) -> usize {
        self.balances.len()
    }

    /// Always false for valid `AuthenticatedLedgerState` (`N >= 4`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.balances.is_empty()
    }

    /// Read-only view of balance shares.
    #[inline]
    pub fn balances(&self) -> &[Share4] {
        &self.balances
    }

    /// Read-only view of SPDZ-IT MAC tag shares.
    #[inline]
    pub fn mac_tags(&self) -> &[Share4] {
        &self.mac_tags
    }

    /// Read-only view of the shared SPDZ-IT MAC key `[kappa]`.
    #[inline]
    pub fn mac_key(&self) -> &Share4 {
        &self.mac_key
    }

    /// Reconstruct and degree-2-verify the balance at `slot` (for auditing/tests).
    pub fn reconstruct_balance(&self, slot: usize) -> Result<u128, ObliviousShuffleError> {
        let share = self
            .balances
            .get(slot)
            .ok_or(ObliviousShuffleError::InvalidParameters(
                "slot out of range",
            ))?;
        Ok(TurboLagrange3Of4::reconstruct_and_verify(share)?)
    }

    /// Reconstruct and degree-2-verify all `N` balances (for auditing/tests).
    pub fn reconstruct_all_balances(&self) -> Result<Vec<u128>, ObliviousShuffleError> {
        let mut out = Vec::with_capacity(self.balances.len());
        for s in &self.balances {
            out.push(TurboLagrange3Of4::reconstruct_and_verify(s)?);
        }
        Ok(out)
    }
}

impl Drop for AuthenticatedLedgerState {
    fn drop(&mut self) {
        zeroize_share4_slice(&mut self.balances);
        zeroize_share4_slice(&mut self.mac_tags);
        zeroize_share4(&mut self.mac_key);
    }
}

/// Unconditional Malicious-Dealer Verification using **ONLY 2 Beaver Triples**:
///
/// Computes the blinded Schwartz–Zippel RLC over `F_(2^127 - 1)`:
/// `[Z_blind] = [rho * (sum_{i=0}^{N-1} gamma^i * T'_i - kappa * sum_{i=0}^{N-1} gamma^i * bal'_i)]`
/// and verifies that opening `[Z_blind]` equals `0`.
///
/// - **Triple 1 (`mac_triple`)**: computes `[kappa * B_gamma]` where `[B_gamma] = sum gamma^i [bal'_i]`.
/// - **Triple 2 (`blind_triple`)**: blinds `[Z] = [T_gamma] - [kappa * B_gamma]` with fresh uniform
///   non-zero `[rho]` so a failed check leaks **0 bits** about `[kappa]` or any balance.
/// - **Unconditional soundness**: catches ANY modified balance, dropped/duplicated slot, or
///   deviated permutation `pi'_k != pi_k` with failure probability `<= N / (2^127 - 1)`.
pub fn verify_spdz_mac_rlc(
    balances: &[Share4],
    mac_tags: &[Share4],
    mac_key: &Share4,
    mac_triple: BeaverTriple4,
    blind_triple: BeaverTriple4,
    gamma: u128,
) -> Result<(), ObliviousShuffleError> {
    if balances.is_empty() || balances.len() != mac_tags.len() {
        return Err(ObliviousShuffleError::InvalidParameters(
            "balances and mac_tags must be non-empty and equal length",
        ));
    }
    if gamma == 0 || gamma >= PRIME_P {
        return Err(ObliviousShuffleError::InvalidParameters(
            "RLC challenge gamma must be in [1, PRIME_P)",
        ));
    }
    TurboLagrange3Of4::verify_degree2(mac_key)?;
    for i in 0..balances.len() {
        TurboLagrange3Of4::verify_degree2(&balances[i])?;
        TurboLagrange3Of4::verify_degree2(&mac_tags[i])?;
    }

    // Horner evaluation in reverse order so index `i` is weighted by `gamma^i`:
    // B_gamma = sum_{i=0}^{N-1} gamma^i * bal'_i, T_gamma = sum_{i=0}^{N-1} gamma^i * T'_i.
    let mut b_gamma: Share4 = [0u128; 4];
    let mut t_gamma: Share4 = [0u128; 4];
    for i in (0..balances.len()).rev() {
        b_gamma = share4_add(&share4_scale(&b_gamma, gamma), &balances[i]);
        t_gamma = share4_add(&share4_scale(&t_gamma, gamma), &mac_tags[i]);
    }

    // Triple 1: [kappa * B_gamma].
    let mut kappa_b = mpc_mul_triple_3_of_4(mac_key, &b_gamma, mac_triple)?;
    zeroize_share4_nofence(&mut b_gamma);

    // [Z] = [T_gamma] - [kappa * B_gamma].
    let mut z = share4_sub(&t_gamma, &kappa_b);
    zeroize_share4_nofence(&mut t_gamma);
    zeroize_share4_nofence(&mut kappa_b);

    // Triple 2: [Z_blind] = [rho] * [Z] with fresh non-zero OS-random [rho].
    let mut rho = random_nonzero_share4();
    let mut z_blind = mpc_mul_triple_3_of_4(&rho, &z, blind_triple)?;
    zeroize_share4_nofence(&mut rho);
    zeroize_share4_nofence(&mut z);

    let opened = TurboLagrange3Of4::reconstruct_and_verify(&z_blind)?;
    zeroize_share4(&mut z_blind);

    if opened != 0 {
        return Err(ObliviousShuffleError::SpdzMacCheckFailed);
    }
    Ok(())
}

// ============================================================================
// 4. Online `t`-Hop Oblivious Global Shuffle & Reverse-Order Client Slot Map
// ============================================================================

/// Secret-shared global slot-mapping vector `[Pi(0), Pi(1), ..., Pi(N-1)]` produced by
/// [`ObliviousEpochMixer::compose_client_slot_map`].
///
/// Each user `u` receives only its own share row `slot_shares[u]` from the validators over pairwise
/// OTP channels and reconstructs `Pi(u)` with `0` bits leaked to any `< t` validator coalition.
pub struct ClientSlotMap {
    slot_shares: Vec<Share4>,
    tag_shares: Vec<Share4>,
}

impl fmt::Debug for ClientSlotMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSlotMap")
            .field("slots", &self.slot_shares.len())
            .field("shares", &"<redacted>")
            .finish()
    }
}

impl ClientSlotMap {
    /// Number of users / global slots `N`.
    #[inline]
    pub fn len(&self) -> usize {
        self.slot_shares.len()
    }

    /// Always false for valid `ClientSlotMap` (`N >= 4`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.slot_shares.is_empty()
    }

    /// Read-only `(3, 4)` Shamir share of `Pi(user_id)`.
    pub fn slot_shares(&self, user_id: usize) -> Result<&Share4, ObliviousShuffleError> {
        self.slot_shares
            .get(user_id)
            .ok_or(ObliviousShuffleError::InvalidParameters(
                "user_id out of range",
            ))
    }

    /// Reconstruct and degree-2-verify user `user_id`'s exact new physical slot `Pi(user_id)`.
    pub fn reconstruct_slot_for_user(&self, user_id: usize) -> Result<usize, ObliviousShuffleError> {
        let s = self.slot_shares(user_id)?;
        let val = TurboLagrange3Of4::reconstruct_and_verify(s)?;
        let slot = usize::try_from(val).map_err(|_| {
            ObliviousShuffleError::InvalidPermutation("reconstructed slot index exceeds usize")
        })?;
        if slot >= self.slot_shares.len() {
            return Err(ObliviousShuffleError::InvalidPermutation(
                "reconstructed slot index out of range",
            ));
        }
        Ok(slot)
    }
}

impl Drop for ClientSlotMap {
    fn drop(&mut self) {
        zeroize_share4_slice(&mut self.slot_shares);
        zeroize_share4_slice(&mut self.tag_shares);
    }
}

/// Malicious-secure online `t`-hop oblivious global epoch mixer (`1` RTT/dealer, `0` online
/// multiplications per hop, plus `1` final 2-triple SPDZ-IT MAC RLC verification).
#[derive(Debug, Clone)]
pub struct ObliviousEpochMixer {
    size: usize,
    num_hops: usize,
}

impl ObliviousEpochMixer {
    /// Create a global epoch mixer for `size` slots (`N = 2^m >= 4`) and `num_hops` (`t >= 1`)
    /// sequential dealer hops.
    pub fn new(size: usize, num_hops: usize) -> Result<Self, ObliviousShuffleError> {
        if size < 4 || !size.is_power_of_two() {
            return Err(ObliviousShuffleError::InvalidParameters(
                "mixer size must be a power of 2 with N >= 4",
            ));
        }
        if num_hops == 0 {
            return Err(ObliviousShuffleError::InvalidParameters(
                "num_hops must be >= 1",
            ));
        }
        Ok(Self { size, num_hops })
    }

    /// Global slot count `N`.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Number of sequential dealer hops `t`.
    #[inline]
    pub fn num_hops(&self) -> usize {
        self.num_hops
    }

    /// Execute one online hop for dealer `V_k` over `(balances, tags)` using a custom dealer
    /// closure (enabling both honest execution and adversarial fault injection tests):
    ///
    /// 1. Mask state locally: `[m_bal] = [bal] - [a_bal]`, `[m_tag] = [tag] - [a_tag]`.
    /// 2. Open masked vectors `(m_bal, m_tag)` exclusively to `V_k` (`0` bits leaked).
    /// 3. Dealer `V_k` applies its permutation and re-shares `([w_bal], [w_tag])`.
    /// 4. Committee locally adds `([b_bal], [b_tag])` (zero online multiplications!).
    fn apply_hop_raw<F>(
        balances: &mut [Share4],
        tags: &mut [Share4],
        a0: &[Share4],
        b0: &[Share4],
        a1: &[Share4],
        b1: &[Share4],
        dealer_fn: F,
    ) -> Result<(), ObliviousShuffleError>
    where
        F: FnOnce(&[u128], &[u128]) -> Result<(Vec<u128>, Vec<u128>), ObliviousShuffleError>,
    {
        let n = balances.len();
        if tags.len() != n || a0.len() != n || b0.len() != n || a1.len() != n || b1.len() != n {
            return Err(ObliviousShuffleError::InvalidParameters(
                "hop vector length mismatch",
            ));
        }

        // 1-2. Mask with offline uniform [a_k] and open masked vector exclusively to dealer V_k.
        let mut masked0 = Vec::with_capacity(n);
        let mut masked1 = Vec::with_capacity(n);
        for i in 0..n {
            let mut d0 = share4_sub(&balances[i], &a0[i]);
            let mut d1 = share4_sub(&tags[i], &a1[i]);
            let m0 = TurboLagrange3Of4::reconstruct_and_verify(&d0)?;
            let m1 = TurboLagrange3Of4::reconstruct_and_verify(&d1)?;
            zeroize_share4_nofence(&mut d0);
            zeroize_share4_nofence(&mut d1);
            masked0.push(m0);
            masked1.push(m1);
        }
        compiler_fence(Ordering::SeqCst);

        // 3. Dealer V_k applies permutation in plaintext on the OTP-masked vector and re-shares.
        let (mut permuted0, mut permuted1) = dealer_fn(&masked0, &masked1)?;
        zeroize_u128_slice(&mut masked0);
        zeroize_u128_slice(&mut masked1);

        if permuted0.len() != n || permuted1.len() != n {
            zeroize_u128_slice(&mut permuted0);
            zeroize_u128_slice(&mut permuted1);
            return Err(ObliviousShuffleError::InvalidParameters(
                "dealer returned wrong output vector length",
            ));
        }

        let mut reshared0 = split_vector(&permuted0)?;
        let mut reshared1 = split_vector(&permuted1)?;
        zeroize_u128_slice(&mut permuted0);
        zeroize_u128_slice(&mut permuted1);

        // 4. Committee locally adds offline permuted mask [b_k] = [pi_k(a_k)] (0 multiplications!).
        for i in 0..n {
            balances[i] = share4_add(&reshared0[i], &b0[i]);
            tags[i] = share4_add(&reshared1[i], &b1[i]);
        }
        zeroize_share4_slice(&mut reshared0);
        zeroize_share4_slice(&mut reshared1);
        Ok(())
    }

    /// Execute the full malicious-secure `t`-hop online global shuffle on `state`, followed by
    /// 2-triple SPDZ-IT MAC RLC verification, with **100% atomic rollback** on any error.
    pub fn execute_shuffle(
        &self,
        state: &mut AuthenticatedLedgerState,
        correlations: Vec<ForwardMaskCorrelation>,
        dealers: &[DealerShuffleSecret],
        bank: &mut TurboBeaverBank,
    ) -> Result<(), ObliviousShuffleError> {
        if dealers.len() != self.num_hops {
            return Err(ObliviousShuffleError::InvalidParameters(
                "dealer count does not match num_hops",
            ));
        }
        let mut fns: Vec<Box<dyn FnOnce(&[u128], &[u128]) -> Result<(Vec<u128>, Vec<u128>), ObliviousShuffleError> + '_>> =
            Vec::with_capacity(self.num_hops);
        for dealer in dealers {
            fns.push(Box::new(move |m_bal, m_tag| {
                let p_bal = dealer.apply_forward_plaintext(m_bal)?;
                let p_tag = dealer.apply_forward_plaintext(m_tag)?;
                Ok((p_bal, p_tag))
            }));
        }
        self.execute_shuffle_with_dealer_fns(state, correlations, fns, bank)
    }

    /// Execute the `t`-hop online global shuffle with custom per-hop dealer closures (for
    /// distributed transports and malicious-dealer fault injection tests), verified by
    /// [`verify_spdz_mac_rlc`] with full atomic rollback on any failure.
    pub fn execute_shuffle_with_dealer_fns<'a>(
        &self,
        state: &mut AuthenticatedLedgerState,
        correlations: Vec<ForwardMaskCorrelation>,
        dealer_fns: Vec<
            Box<
                dyn FnOnce(&[u128], &[u128]) -> Result<(Vec<u128>, Vec<u128>), ObliviousShuffleError>
                    + 'a,
            >,
        >,
        bank: &mut TurboBeaverBank,
    ) -> Result<(), ObliviousShuffleError> {
        if state.len() != self.size {
            return Err(ObliviousShuffleError::InvalidParameters(
                "state length does not match mixer size",
            ));
        }
        if correlations.len() != self.num_hops || dealer_fns.len() != self.num_hops {
            return Err(ObliviousShuffleError::InvalidParameters(
                "correlations and dealer_fns must match num_hops",
            ));
        }
        for corr in &correlations {
            if corr.len() != self.size {
                return Err(ObliviousShuffleError::InvalidParameters(
                    "correlation length does not match mixer size",
                ));
            }
        }
        // Reserve the 2 Beaver triples needed for final SPDZ-IT MAC RLC upfront.
        let mac_triple = bank.pop_triple()?;
        let blind_triple = bank.pop_triple()?;

        // Stage a working copy for 100% atomic rollback on any dealer failure or MAC rejection.
        let mut staged_bal = state.balances.clone();
        let mut staged_tag = state.mac_tags.clone();

        for (corr, dealer_fn) in correlations.into_iter().zip(dealer_fns.into_iter()) {
            let hop_res = Self::apply_hop_raw(
                &mut staged_bal,
                &mut staged_tag,
                &corr.a_bal,
                &corr.b_bal,
                &corr.a_tag,
                &corr.b_tag,
                dealer_fn,
            );
            drop(corr); // Volatile-zeroizes single-use correlation immediately.
            if let Err(e) = hop_res {
                zeroize_share4_slice(&mut staged_bal);
                zeroize_share4_slice(&mut staged_tag);
                drop(mac_triple);
                drop(blind_triple);
                return Err(e);
            }
        }

        // Unconditional malicious-dealer verification (2 triples, fresh OS-random gamma).
        let gamma = random_nonzero_challenge();
        if let Err(e) = verify_spdz_mac_rlc(
            &staged_bal,
            &staged_tag,
            &state.mac_key,
            mac_triple,
            blind_triple,
            gamma,
        ) {
            zeroize_share4_slice(&mut staged_bal);
            zeroize_share4_slice(&mut staged_tag);
            return Err(e);
        }

        // Commit shuffled state atomically and wipe the previous epoch shares.
        zeroize_share4_slice(&mut state.balances);
        zeroize_share4_slice(&mut state.mac_tags);
        state.balances = staged_bal;
        state.mac_tags = staged_tag;
        Ok(())
    }

    /// **Reverse-Order Zero-Leak Client Slot Discovery**:
    ///
    /// Composes `Pi = pi_t o ... o pi_1` in **reverse order** (`k = t-1 ..= 0`) over the
    /// SPDZ-MAC-authenticated secret-shared identity index vector `[pos_j] = [j]` using each
    /// dealer's inverse-permutation correlation (`pi_k^(-1)`):
    /// - Start: `pos_0[j] = j`, `tag_0[j] = kappa * j` (local scalar mul, 0 triples!).
    /// - Dealer `V_k` (`k = t-1` down to `0`) applies `pi_k^(-1)`: `pos'[i] = pos[pi_k[i]]`.
    /// - Final result: `pos_t[u] = pi_t(pi_{t-1}(... pi_1(u) ...)) = Pi(u)`!
    /// - Verified with [`verify_spdz_mac_rlc`] (2 triples) so no malicious dealer can corrupt any
    ///   user's discovered slot index!
    pub fn compose_client_slot_map(
        &self,
        inverse_correlations: Vec<InverseMaskCorrelation>,
        dealers: &[DealerShuffleSecret],
        mac_key: &Share4,
        bank: &mut TurboBeaverBank,
    ) -> Result<ClientSlotMap, ObliviousShuffleError> {
        if inverse_correlations.len() != self.num_hops || dealers.len() != self.num_hops {
            return Err(ObliviousShuffleError::InvalidParameters(
                "inverse_correlations and dealers must match num_hops",
            ));
        }
        for corr in &inverse_correlations {
            if corr.len() != self.size {
                return Err(ObliviousShuffleError::InvalidParameters(
                    "inverse correlation length does not match mixer size",
                ));
            }
        }
        TurboLagrange3Of4::verify_degree2(mac_key)?;

        let mac_triple = bank.pop_triple()?;
        let blind_triple = bank.pop_triple()?;

        // Initialize secret-shared identity vector `[0, 1, ..., N-1]` and SPDZ-IT MAC tags
        // `[kappa * j] = j * [kappa] + [0]` (purely local, 0 multiplications!).
        let init_indices: Vec<u128> = (0..self.size).map(|j| j as u128).collect();
        let mut pos = split_vector(&init_indices)?;
        let mut pos_tags = Vec::with_capacity(self.size);
        for j in 0..self.size {
            let zero_rand = split_zero_share4();
            pos_tags.push(share4_add(&share4_scale(mac_key, j as u128), &zero_rand));
        }

        // Apply inverse permutations in REVERSE dealer order: k = t-1, t-2, ..., 0.
        for (corr, dealer) in inverse_correlations.into_iter().zip(dealers.iter()).rev() {
            let hop_res = Self::apply_hop_raw(
                &mut pos,
                &mut pos_tags,
                &corr.a_pos,
                &corr.b_pos,
                &corr.a_pos_tag,
                &corr.b_pos_tag,
                |m_pos, m_tag| {
                    let p_pos = dealer.apply_inverse_plaintext(m_pos)?;
                    let p_tag = dealer.apply_inverse_plaintext(m_tag)?;
                    Ok((p_pos, p_tag))
                },
            );
            drop(corr);
            if let Err(e) = hop_res {
                zeroize_share4_slice(&mut pos);
                zeroize_share4_slice(&mut pos_tags);
                drop(mac_triple);
                drop(blind_triple);
                return Err(e);
            }
        }

        // Verify the composed client slot map with 2-triple SPDZ-IT MAC RLC.
        let gamma = random_nonzero_challenge();
        if let Err(e) = verify_spdz_mac_rlc(
            &pos,
            &pos_tags,
            mac_key,
            mac_triple,
            blind_triple,
            gamma,
        ) {
            zeroize_share4_slice(&mut pos);
            zeroize_share4_slice(&mut pos_tags);
            return Err(e);
        }

        Ok(ClientSlotMap {
            slot_shares: pos,
            tag_shares: pos_tags,
        })
    }
}

// ============================================================================
// 5. Comprehensive Unit & Security Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic PRNG strictly for reproducible test permutation generation.
    struct TestRng(u64);
    impl TestRng {
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
        fn random_perm(&mut self, n: usize) -> Vec<usize> {
            let mut p: Vec<usize> = (0..n).collect();
            for i in (1..n).rev() {
                let j = (self.next_u64() as usize) % (i + 1);
                p.swap(i, j);
            }
            p
        }
    }

    #[test]
    fn test_waksman_benes_network_exact_routing_sizes_4_16_64_256() {
        let mut rng = TestRng::new(0xBE4E_5000_0000_0042);

        for &n in &[4usize, 16, 64, 256] {
            let log_n = n.trailing_zeros() as usize;
            let expected_layers = 2 * log_n - 1;

            // Test identity, reversal, cyclic shift, and 16 random permutations per size.
            let mut perms: Vec<Vec<usize>> = vec![
                (0..n).collect(),
                (0..n).rev().collect(),
                (0..n).map(|i| (i + 1) % n).collect(),
                (0..n).map(|i| (i + n / 2 + 1) % n).collect(),
            ];
            for _ in 0..16 {
                perms.push(rng.random_perm(n));
            }

            for perm in perms {
                let net = BenesNetwork::from_permutation(&perm).unwrap();
                assert_eq!(net.len(), n);
                assert_eq!(net.num_layers(), expected_layers);
                assert_eq!(net.switches_per_layer(), n / 2);

                // Route distinct payloads and verify `out[perm[i]] == payload[i]`.
                let payloads: Vec<u128> = (0..n).map(|i| 10_000 + (i as u128) * 37).collect();
                let routed = net.apply_plaintext(&payloads).unwrap();
                for (i, &dst) in perm.iter().enumerate() {
                    assert_eq!(
                        routed[dst], payloads[i],
                        "forward Benes mismatch for N={n} at i={i}"
                    );
                }

                // Verify reversed layers compute exact inverse `pi^(-1)`!
                let inv_net = net.reverse_layers();
                let recovered = inv_net.apply_plaintext(&routed).unwrap();
                assert_eq!(
                    recovered, payloads,
                    "reversed Benes layers did not invert forward permutation for N={n}"
                );
            }
        }

        // Invalid sizes & non-bijections must be rejected cleanly.
        assert!(BenesNetwork::from_permutation(&[0, 1]).is_err());
        assert!(BenesNetwork::from_permutation(&[0, 1, 2]).is_err());
        assert!(BenesNetwork::from_permutation(&[0, 1, 2, 2]).is_err());
        assert!(BenesNetwork::from_permutation(&[0, 1, 2, 4]).is_err());
    }

    #[test]
    fn test_malicious_secure_3_hop_oblivious_global_shuffle_64_slots_and_client_slot_discovery() {
        const N: usize = 64;
        const HOPS: usize = 3;

        // 1. Initialize 64 distinct account balances under SPDZ-IT MACs.
        let initial_balances: Vec<u128> = (0..N).map(|u| 1_000 + (u as u128) * 73).collect();
        let initial_supply: u128 = initial_balances.iter().sum();
        let mut state = AuthenticatedLedgerState::new_from_plaintext(&initial_balances).unwrap();
        assert!(format!("{state:?}").contains("<redacted>"));

        // 2. Sample 3 independent secret dealer permutations `pi_1, pi_2, pi_3 in S_64`.
        let dealers: Vec<DealerShuffleSecret> = (0..HOPS)
            .map(|k| DealerShuffleSecret::random(k, N).unwrap())
            .collect();
        assert!(format!("{:?}", dealers[0]).contains("<redacted>"));

        // Compute expected composed permutation `Pi(u) = pi_3(pi_2(pi_1(u)))` for verification.
        let expected_pi: Vec<usize> = (0..N)
            .map(|u| {
                let mut pos = u;
                for d in &dealers {
                    pos = d.perm()[pos];
                }
                pos
            })
            .collect();

        // 3. Offline Beneš preprocessing for all 3 dealers (verifies all switch bits Boolean).
        let mut fwd_corrs = Vec::with_capacity(HOPS);
        let mut inv_corrs = Vec::with_capacity(HOPS);
        for d in &dealers {
            let corr = ShuffleMaskCorrelation::generate(d).unwrap();
            assert!(format!("{corr:?}").contains("<redacted>"));
            let (fwd, inv) = corr.into_parts();
            fwd_corrs.push(fwd);
            inv_corrs.push(inv);
        }

        // 4. Online 3-hop oblivious global shuffle + 2-triple SPDZ-IT MAC RLC verification.
        let mixer = ObliviousEpochMixer::new(N, HOPS).unwrap();
        let mut bank = TurboBeaverBank::new(0, 0, 8);
        mixer
            .execute_shuffle(&mut state, fwd_corrs, &dealers, &mut bank)
            .unwrap();

        // Verify exact balance placement `state[Pi(u)] == initial_balances[u]` and exact conservation!
        let final_balances = state.reconstruct_all_balances().unwrap();
        let final_supply: u128 = final_balances.iter().sum();
        assert_eq!(final_supply, initial_supply);
        for u in 0..N {
            assert_eq!(
                final_balances[expected_pi[u]], initial_balances[u],
                "user {u}'s balance did not move to Pi(u)={}",
                expected_pi[u]
            );
        }

        // 5. Reverse-order zero-leak client slot discovery (`compose_client_slot_map`).
        let slot_map = mixer
            .compose_client_slot_map(inv_corrs, &dealers, state.mac_key(), &mut bank)
            .unwrap();
        assert!(format!("{slot_map:?}").contains("<redacted>"));
        assert_eq!(slot_map.len(), N);

        // Every user `u` reconstructs its exact new physical slot `Pi(u)` and finds its exact balance!
        for u in 0..N {
            let discovered_slot = slot_map.reconstruct_slot_for_user(u).unwrap();
            assert_eq!(
                discovered_slot, expected_pi[u],
                "client slot discovery mismatch for user {u}"
            );
            assert_eq!(
                state.reconstruct_balance(discovered_slot).unwrap(),
                initial_balances[u],
                "balance at discovered slot mismatch for user {u}"
            );
        }

        // Verify < 3 validator coalition secrecy on client slot shares (2 shares perfectly explain
        // ANY hypothetical slot index in 0..N).
        let inv2 = (PRIME_P + 1) / 2;
        let s0 = *slot_map.slot_shares(0).unwrap();
        for hypothetical in [0u128, 17, 63] {
            let rhs = sub_mod(add_mod(s0[1], hypothetical), add_mod(s0[0], s0[0]));
            let c2 = mul_mod(rhs, inv2);
            let c1 = sub_mod(sub_mod(s0[0], hypothetical), c2);
            let forged = TurboLagrange3Of4::eval_poly(hypothetical, c1, c2);
            assert_eq!(forged[0], s0[0]);
            assert_eq!(forged[1], s0[1]);
            assert_eq!(
                TurboLagrange3Of4::reconstruct_and_verify(&forged).unwrap(),
                hypothetical
            );
        }

        // Verify offline preprocessing rejects a malicious dealer supplying a non-binary switch bit!
        let bad_net = BenesNetwork::from_permutation(dealers[0].perm()).unwrap();
        let mut bad_sw: Vec<Vec<Share4>> = (0..bad_net.num_layers())
            .map(|l| {
                let bits: Vec<u128> = bad_net
                    .layer_switches(l)
                    .iter()
                    .map(|&b| if b { 1 } else { 0 })
                    .collect();
                split_vector(&bits).unwrap()
            })
            .collect();
        bad_sw[3][7] = TurboLagrange3Of4::split_secret(2).unwrap();
        assert_eq!(
            ShuffleMaskCorrelation::generate_from_switch_shares(
                0,
                N,
                N.trailing_zeros() as usize,
                &bad_sw
            )
            .unwrap_err(),
            ObliviousShuffleError::SwitchProofFailed
        );
    }

    #[test]
    fn test_corrupt_shuffle_dealer_balance_tamper_duplication_or_wrong_perm_caught_by_spdz_mac() {
        const N: usize = 16;
        const HOPS: usize = 3;

        let initial_balances: Vec<u128> = (0..N).map(|u| 500 + (u as u128) * 29).collect();
        let mixer = ObliviousEpochMixer::new(N, HOPS).unwrap();

        // Helper: run a 3-hop shuffle where dealer 1 (the middle hop) injects a malicious fault,
        // and verify SPDZ-IT MAC RLC catches it AND state rolls back atomically!
        let run_fault_case = |fault_kind: u8| {
            let mut state = AuthenticatedLedgerState::new_from_plaintext(&initial_balances).unwrap();
            let dealers: Vec<DealerShuffleSecret> = (0..HOPS)
                .map(|k| DealerShuffleSecret::random(k, N).unwrap())
                .collect();
            let fwd_corrs: Vec<ForwardMaskCorrelation> = dealers
                .iter()
                .map(|d| ShuffleMaskCorrelation::generate(d).unwrap().into_parts().0)
                .collect();

            let mut bank = TurboBeaverBank::new(0, 0, 4);
            let d0 = &dealers[0];
            let d1 = &dealers[1];
            let d2 = &dealers[2];

            let f0: Box<
                dyn FnOnce(&[u128], &[u128]) -> Result<(Vec<u128>, Vec<u128>), ObliviousShuffleError>,
            > = Box::new(move |m_bal, m_tag| {
                Ok((
                    d0.apply_forward_plaintext(m_bal)?,
                    d0.apply_forward_plaintext(m_tag)?,
                ))
            });

            let f1: Box<
                dyn FnOnce(&[u128], &[u128]) -> Result<(Vec<u128>, Vec<u128>), ObliviousShuffleError>,
            > = Box::new(move |m_bal, m_tag| {
                let mut p_bal = d1.apply_forward_plaintext(m_bal)?;
                let mut p_tag = d1.apply_forward_plaintext(m_tag)?;
                match fault_kind {
                    // Fault 0: Balance inflation tamper (+1 coin on slot 3).
                    0 => {
                        p_bal[3] = add_mod(p_bal[3], 1);
                    }
                    // Fault 1: Row duplication / drop (overwrite slot 5 with slot 2's balance & tag).
                    1 => {
                        p_bal[5] = p_bal[2];
                        p_tag[5] = p_tag[2];
                    }
                    // Fault 2: Deviated permutation `pi'_1 != pi_1` (swap two output slots on BOTH
                    // balance and tag vectors!).
                    _ => {
                        p_bal.swap(0, 1);
                        p_tag.swap(0, 1);
                    }
                }
                Ok((p_bal, p_tag))
            });

            let f2: Box<
                dyn FnOnce(&[u128], &[u128]) -> Result<(Vec<u128>, Vec<u128>), ObliviousShuffleError>,
            > = Box::new(move |m_bal, m_tag| {
                Ok((
                    d2.apply_forward_plaintext(m_bal)?,
                    d2.apply_forward_plaintext(m_tag)?,
                ))
            });

            let err = mixer
                .execute_shuffle_with_dealer_fns(&mut state, fwd_corrs, vec![f0, f1, f2], &mut bank)
                .expect_err("corrupt dealer MUST be caught by SPDZ-IT MAC RLC");
            assert_eq!(
                err,
                ObliviousShuffleError::SpdzMacCheckFailed,
                "fault_kind={fault_kind} must fail SPDZ-IT MAC RLC"
            );

            // Atomic rollback: state must be 100% unchanged!
            assert_eq!(
                state.reconstruct_all_balances().unwrap(),
                initial_balances,
                "state mutated after failed shuffle for fault_kind={fault_kind}"
            );
        };

        run_fault_case(0); // Balance tamper
        run_fault_case(1); // Row duplication / drop
        run_fault_case(2); // Deviated permutation `pi'_k != pi_k`
    }
}
