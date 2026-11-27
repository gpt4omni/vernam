//! Pure deterministic BFT quorum intersection, equivocation detection, and monotonic
//! height/view lock state machine (`no_std`, zero `unsafe`, panic-free).

use crate::field::ct_eq_16;

/// Minimum BFT committee size (`3f + 1` with `f >= 1`).
pub const MIN_BFT_COMMITTEE_SIZE: usize = 4;

/// BFT committee parameters `(N, f, t)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BftParams {
    pub committee_size: usize,
    pub max_faults: usize,
    pub threshold: usize,
}

/// Errors produced by the deterministic BFT state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BftSmError {
    InvalidCommitteeSize,
    QuorumNotMet,
    InvalidHeightTransition,
    ViewRegression,
    ConflictingLockAtSameView,
    NotLocked,
    LockTagMismatch,
}

/// Compute BFT-safe parameters for any `committee_size >= 4`:
/// - `f = (N - 1) / 3`
/// - `t = ((N + f) / 2) + 1`
///
/// Guarantees `N >= 3f + 1`, `t >= 2f + 1`, `t > N / 2`, `2t - N >= f + 1`, and `t <= N - f`.
pub const fn compute_bft_params(committee_size: usize) -> Result<BftParams, BftSmError> {
    if committee_size < MIN_BFT_COMMITTEE_SIZE {
        return Err(BftSmError::InvalidCommitteeSize);
    }
    let max_faults = (committee_size - 1) / 3;
    let threshold_u128 = ((committee_size as u128) + (max_faults as u128)) / 2 + 1;
    if threshold_u128 > usize::MAX as u128 {
        return Err(BftSmError::InvalidCommitteeSize);
    }
    let threshold = threshold_u128 as usize;
    Ok(BftParams {
        committee_size,
        max_faults,
        threshold,
    })
}

/// Verify that two quorums of sizes `q1` and `q2` within `params` must intersect in at least
/// `f + 1` validators (guaranteeing at least 1 honest overlapping validator).
pub const fn quorums_intersect_honestly(params: BftParams, q1: usize, q2: usize) -> bool {
    if q1 < params.threshold
        || q2 < params.threshold
        || q1 > params.committee_size
        || q2 > params.committee_size
    {
        return false;
    }
    let overlap_min = (q1 as u128) + (q2 as u128);
    let required = (params.committee_size as u128) + (params.max_faults as u128) + 1;
    overlap_min >= required
}

/// A single BFT consensus vote record for equivocation checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteRecord {
    pub validator_id: u64,
    pub height: u64,
    pub view: u64,
    pub block_tag: [u8; 16],
}

/// Returns `true` iff `a` and `b` prove Byzantine equivocation (same validator signed two
/// distinct block tags for the exact same `(height, view)`).
pub fn detect_equivocation(a: &VoteRecord, b: &VoteRecord) -> bool {
    a.validator_id == b.validator_id
        && a.height == b.height
        && a.view == b.view
        && !ct_eq_16(&a.block_tag, &b.block_tag)
}

/// Monotonic BFT height/view lock & commit state machine for a single honest validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockState {
    pub committed_height: u64,
    pub committed_tag: [u8; 16],
    pub has_lock: bool,
    pub locked_height: u64,
    pub locked_view: u64,
    pub locked_tag: [u8; 16],
}

impl LockState {
    /// Genesis lock state at height 0.
    pub const fn genesis() -> Self {
        Self {
            committed_height: 0,
            committed_tag: [0u8; 16],
            has_lock: false,
            locked_height: 0,
            locked_view: 0,
            locked_tag: [0u8; 16],
        }
    }

    /// Monotonically acquire or upgrade a Prepare QC lock for `(height, view, tag)`.
    ///
    /// Enforces:
    /// - `vote_count >= params.threshold` and `vote_count <= params.committee_size`
    /// - `height == self.committed_height + 1` (checked)
    /// - If already locked at `height`, `view` may never regress and cannot conflict at equal view.
    pub fn try_lock(
        &mut self,
        height: u64,
        view: u64,
        tag: [u8; 16],
        vote_count: usize,
        params: BftParams,
    ) -> Result<(), BftSmError> {
        if vote_count < params.threshold || vote_count > params.committee_size {
            return Err(BftSmError::QuorumNotMet);
        }
        let next_height = self
            .committed_height
            .checked_add(1)
            .ok_or(BftSmError::InvalidHeightTransition)?;
        if height != next_height {
            return Err(BftSmError::InvalidHeightTransition);
        }
        if self.has_lock {
            if view < self.locked_view {
                return Err(BftSmError::ViewRegression);
            }
            if view == self.locked_view && !ct_eq_16(&self.locked_tag, &tag) {
                return Err(BftSmError::ConflictingLockAtSameView);
            }
        }
        self.has_lock = true;
        self.locked_height = height;
        self.locked_view = view;
        self.locked_tag = tag;
        Ok(())
    }

    /// Finalize a locked block upon observing a Commit QC (`vote_count >= params.threshold`).
    ///
    /// Advances `committed_height` monotonically by +1 and clears the lock for the next height.
    pub fn try_commit(
        &mut self,
        height: u64,
        view: u64,
        tag: [u8; 16],
        vote_count: usize,
        params: BftParams,
    ) -> Result<(), BftSmError> {
        if vote_count < params.threshold || vote_count > params.committee_size {
            return Err(BftSmError::QuorumNotMet);
        }
        if !self.has_lock {
            return Err(BftSmError::NotLocked);
        }
        if height != self.locked_height {
            return Err(BftSmError::InvalidHeightTransition);
        }
        if view < self.locked_view {
            return Err(BftSmError::ViewRegression);
        }
        if !ct_eq_16(&self.locked_tag, &tag) {
            return Err(BftSmError::LockTagMismatch);
        }
        self.committed_height = height;
        self.committed_tag = tag;
        self.has_lock = false;
        self.locked_height = 0;
        self.locked_view = 0;
        self.locked_tag = [0u8; 16];
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bft_params_quorum_intersection_equivocation_and_lock_sm() {
        assert_eq!(compute_bft_params(3), Err(BftSmError::InvalidCommitteeSize));
        for n in 4..=64usize {
            let p = compute_bft_params(n).unwrap();
            assert!(n >= 3 * p.max_faults + 1);
            assert!(p.threshold >= 2 * p.max_faults + 1);
            assert!(p.threshold > n / 2);
            assert!(p.threshold <= n - p.max_faults);
            assert!(quorums_intersect_honestly(p, p.threshold, p.threshold));
        }

        let v1 = VoteRecord { validator_id: 7, height: 1, view: 0, block_tag: [1u8; 16] };
        let v2 = VoteRecord { validator_id: 7, height: 1, view: 0, block_tag: [2u8; 16] };
        let v3 = VoteRecord { validator_id: 7, height: 1, view: 1, block_tag: [2u8; 16] };
        assert!(detect_equivocation(&v1, &v2));
        assert!(!detect_equivocation(&v1, &v1));
        assert!(!detect_equivocation(&v1, &v3));

        let p4 = compute_bft_params(4).unwrap();
        let mut sm = LockState::genesis();
        assert_eq!(sm.try_commit(1, 0, [1u8; 16], 3, p4), Err(BftSmError::NotLocked));
        assert_eq!(sm.try_lock(1, 0, [1u8; 16], 2, p4), Err(BftSmError::QuorumNotMet));
        sm.try_lock(1, 1, [1u8; 16], 3, p4).unwrap();
        assert_eq!(sm.try_lock(1, 0, [1u8; 16], 3, p4), Err(BftSmError::ViewRegression));
        assert_eq!(
            sm.try_lock(1, 1, [2u8; 16], 3, p4),
            Err(BftSmError::ConflictingLockAtSameView)
        );
        // Higher view lock upgrade succeeds.
        sm.try_lock(1, 2, [2u8; 16], 3, p4).unwrap();
        assert_eq!(sm.try_commit(1, 2, [1u8; 16], 3, p4), Err(BftSmError::LockTagMismatch));
        sm.try_commit(1, 2, [2u8; 16], 3, p4).unwrap();
        assert_eq!(sm.committed_height, 1);
        assert_eq!(sm.committed_tag, [2u8; 16]);
        assert!(!sm.has_lock);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn prove_bft_quorum_intersection_all_practical_sizes() {
        let n: usize = kani::any();
        kani::assume(n >= 4 && n <= 1024);
        let p = compute_bft_params(n).unwrap();
        assert!(n >= 3 * p.max_faults + 1);
        assert!(p.threshold >= 2 * p.max_faults + 1);
        assert!(p.threshold > n / 2);
        assert!(p.threshold <= n - p.max_faults);
        assert!(quorums_intersect_honestly(p, p.threshold, p.threshold));
    }

    #[kani::proof]
    fn prove_lock_state_monotonic_height() {
        let p = compute_bft_params(4).unwrap();
        let mut sm = LockState::genesis();
        let v1: u64 = kani::any();
        let v2: u64 = kani::any();
        let tag: [u8; 16] = kani::any();
        kani::assume(v2 >= v1);
        sm.try_lock(1, v1, tag, 3, p).unwrap();
        sm.try_commit(1, v2, tag, 3, p).unwrap();
        assert_eq!(sm.committed_height, 1);
    }
}
