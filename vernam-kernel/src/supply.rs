//! Checked-math 21M `VRNM` hard supply cap, halving curve, and conservation invariant kernel
//! (`no_std`, zero `unsafe`, panic-free).

/// Base unit subdivision: `1 VRNM = 100,000,000 vern`.
pub const VERN_PER_VRNM: u64 = 100_000_000;

/// Absolute hard supply cap: 21,000,000 VRNM (`2_100_000_000_000_000 vern`).
pub const MAX_SUPPLY: u64 = 21_000_000 * VERN_PER_VRNM;

/// Epochs per halving era (`210,000`).
pub const EPOCHS_PER_HALVING: u64 = 210_000;

/// Initial epoch subsidy: 50 VRNM (`5_000_000_000 vern`).
pub const INITIAL_EPOCH_REWARD: u64 = 50 * VERN_PER_VRNM;

/// Errors produced by supply accounting transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyError {
    SupplyCapExceeded,
    InsufficientLiquidSupply,
    InsufficientBondedSupply,
    ArithmeticOverflow,
    ConservationViolation,
}

/// Deterministic halving curve subsidy in `vern` for `epoch`.
#[inline]
pub const fn epoch_reward(epoch: u64) -> u64 {
    let halvings = epoch / EPOCHS_PER_HALVING;
    if halvings >= 64 {
        0
    } else {
        INITIAL_EPOCH_REWARD >> halvings
    }
}

/// Exact total scheduled issuance across all halving eras (strictly `< MAX_SUPPLY`).
pub const fn total_scheduled_issuance() -> u64 {
    let mut total = 0u64;
    let mut era = 0u64;
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

/// Pure checked-math VRNM supply conservation state.
///
/// Invariants preserved across every transition:
/// 1. `total_minted <= MAX_SUPPLY`
/// 2. `circulating_supply + total_burned == total_minted`
/// 3. `liquid_supply + total_bonded == circulating_supply`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupplyLedger {
    pub total_minted: u64,
    pub circulating_supply: u64,
    pub total_burned: u64,
    pub total_bonded: u64,
    pub liquid_supply: u64,
}

impl SupplyLedger {
    /// Create an empty genesis supply ledger.
    pub const fn new() -> Self {
        Self {
            total_minted: 0,
            circulating_supply: 0,
            total_burned: 0,
            total_bonded: 0,
            liquid_supply: 0,
        }
    }

    /// Explicitly verify all three supply conservation invariants.
    pub const fn check_invariants(&self) -> Result<(), SupplyError> {
        if self.total_minted > MAX_SUPPLY {
            return Err(SupplyError::SupplyCapExceeded);
        }
        let Some(minted_check) = self.circulating_supply.checked_add(self.total_burned) else {
            return Err(SupplyError::ArithmeticOverflow);
        };
        if minted_check != self.total_minted {
            return Err(SupplyError::ConservationViolation);
        }
        let Some(circ_check) = self.liquid_supply.checked_add(self.total_bonded) else {
            return Err(SupplyError::ArithmeticOverflow);
        };
        if circ_check != self.circulating_supply {
            return Err(SupplyError::ConservationViolation);
        }
        Ok(())
    }

    /// Mint the halving-schedule epoch subsidy into `liquid_supply`, enforcing `<= MAX_SUPPLY`.
    pub fn mint_epoch(&mut self, epoch: u64) -> Result<u64, SupplyError> {
        let subsidy = epoch_reward(epoch);
        let new_minted = self
            .total_minted
            .checked_add(subsidy)
            .ok_or(SupplyError::ArithmeticOverflow)?;
        if new_minted > MAX_SUPPLY {
            return Err(SupplyError::SupplyCapExceeded);
        }
        let new_circ = self
            .circulating_supply
            .checked_add(subsidy)
            .ok_or(SupplyError::ArithmeticOverflow)?;
        let new_liquid = self
            .liquid_supply
            .checked_add(subsidy)
            .ok_or(SupplyError::ArithmeticOverflow)?;

        self.total_minted = new_minted;
        self.circulating_supply = new_circ;
        self.liquid_supply = new_liquid;
        self.check_invariants()?;
        Ok(subsidy)
    }

    /// Lock `amount` vern from `liquid_supply` into `total_bonded`.
    pub fn bond(&mut self, amount: u64) -> Result<(), SupplyError> {
        let new_liquid = self
            .liquid_supply
            .checked_sub(amount)
            .ok_or(SupplyError::InsufficientLiquidSupply)?;
        let new_bonded = self
            .total_bonded
            .checked_add(amount)
            .ok_or(SupplyError::ArithmeticOverflow)?;
        self.liquid_supply = new_liquid;
        self.total_bonded = new_bonded;
        self.check_invariants()
    }

    /// Release `amount` vern from `total_bonded` back into `liquid_supply`.
    pub fn unbond(&mut self, amount: u64) -> Result<(), SupplyError> {
        let new_bonded = self
            .total_bonded
            .checked_sub(amount)
            .ok_or(SupplyError::InsufficientBondedSupply)?;
        let new_liquid = self
            .liquid_supply
            .checked_add(amount)
            .ok_or(SupplyError::ArithmeticOverflow)?;
        self.total_bonded = new_bonded;
        self.liquid_supply = new_liquid;
        self.check_invariants()
    }

    /// Permanently burn `amount` vern from `liquid_supply` (e.g., 20% fee burn).
    pub fn burn_from_liquid(&mut self, amount: u64) -> Result<(), SupplyError> {
        let new_liquid = self
            .liquid_supply
            .checked_sub(amount)
            .ok_or(SupplyError::InsufficientLiquidSupply)?;
        let new_circ = self
            .circulating_supply
            .checked_sub(amount)
            .ok_or(SupplyError::ConservationViolation)?;
        let new_burned = self
            .total_burned
            .checked_add(amount)
            .ok_or(SupplyError::ArithmeticOverflow)?;
        self.liquid_supply = new_liquid;
        self.circulating_supply = new_circ;
        self.total_burned = new_burned;
        self.check_invariants()
    }

    /// Permanently slash and burn `amount` vern from `total_bonded`.
    pub fn slash_and_burn_bond(&mut self, amount: u64) -> Result<(), SupplyError> {
        let new_bonded = self
            .total_bonded
            .checked_sub(amount)
            .ok_or(SupplyError::InsufficientBondedSupply)?;
        let new_circ = self
            .circulating_supply
            .checked_sub(amount)
            .ok_or(SupplyError::ConservationViolation)?;
        let new_burned = self
            .total_burned
            .checked_add(amount)
            .ok_or(SupplyError::ArithmeticOverflow)?;
        self.total_bonded = new_bonded;
        self.circulating_supply = new_circ;
        self.total_burned = new_burned;
        self.check_invariants()
    }
}

impl Default for SupplyLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_halving_curve_hard_cap_and_conservation() {
        assert_eq!(epoch_reward(0), 50 * VERN_PER_VRNM);
        assert_eq!(epoch_reward(EPOCHS_PER_HALVING), 25 * VERN_PER_VRNM);
        assert_eq!(epoch_reward(EPOCHS_PER_HALVING * 2), (25 * VERN_PER_VRNM) / 2);
        assert_eq!(epoch_reward(EPOCHS_PER_HALVING * 64), 0);
        assert!(total_scheduled_issuance() <= MAX_SUPPLY);
        assert!(total_scheduled_issuance() > 20_999_999 * VERN_PER_VRNM);

        let mut ledger = SupplyLedger::new();
        let minted = ledger.mint_epoch(0).unwrap();
        assert_eq!(minted, 50 * VERN_PER_VRNM);
        ledger.bond(20 * VERN_PER_VRNM).unwrap();
        ledger.burn_from_liquid(5 * VERN_PER_VRNM).unwrap();
        ledger.slash_and_burn_bond(10 * VERN_PER_VRNM).unwrap();
        ledger.unbond(10 * VERN_PER_VRNM).unwrap();

        assert_eq!(ledger.total_minted, 50 * VERN_PER_VRNM);
        assert_eq!(ledger.total_burned, 15 * VERN_PER_VRNM);
        assert_eq!(ledger.circulating_supply, 35 * VERN_PER_VRNM);
        assert_eq!(ledger.total_bonded, 0);
        assert_eq!(ledger.liquid_supply, 35 * VERN_PER_VRNM);
        assert!(ledger.check_invariants().is_ok());

        // Attempting to exceed MAX_SUPPLY fails cleanly without mutating state.
        let mut near_cap = SupplyLedger {
            total_minted: MAX_SUPPLY - 1,
            circulating_supply: MAX_SUPPLY - 1,
            total_burned: 0,
            total_bonded: 0,
            liquid_supply: MAX_SUPPLY - 1,
        };
        assert_eq!(near_cap.mint_epoch(0), Err(SupplyError::SupplyCapExceeded));
        assert_eq!(near_cap.total_minted, MAX_SUPPLY - 1);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn prove_supply_conservation_under_arbitrary_ops() {
        let mut ledger = SupplyLedger::new();
        let epoch: u64 = kani::any();
        let bond_amt: u64 = kani::any();
        let burn_amt: u64 = kani::any();
        let slash_amt: u64 = kani::any();

        let _ = ledger.mint_epoch(epoch);
        let _ = ledger.bond(bond_amt);
        let _ = ledger.burn_from_liquid(burn_amt);
        let _ = ledger.slash_and_burn_bond(slash_amt);
        assert!(ledger.check_invariants().is_ok());
    }
}
