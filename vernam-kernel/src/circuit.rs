//! `#![no_std]`, `#![forbid(unsafe_code)]`, zero-heap static budget validator for
//! Vernam's Confidential IT-MPC Arithmetic Circuit VM.
//!
//! Validates circuit ceilings (max ops, max registers, max inputs, max state writes,
//! valid range-proof bit widths) and computes exact Beaver triple/square consumption
//! and deterministic `vern` execution fees using strictly overflow-checked integer math.

/// Maximum number of secret-shared registers addressable by a single circuit.
pub const MAX_CIRCUIT_REGS: usize = 256;

/// Maximum number of acyclic DAG operations allowed in a single circuit.
pub const MAX_CIRCUIT_OPS: usize = 2_048;

/// Maximum number of persistent confidential state keys per contract (and writes per call).
pub const MAX_STATE_KEYS: usize = 256;

/// Maximum bit width supported by an `AssertRangeBits` constraint (`0 <= x < 2^64`).
pub const MAX_RANGE_BITS: usize = 64;

/// Deterministic execution fee in `vern` per Beaver multiplication/squaring consumption.
pub const FEE_PER_TRIPLE_VERN: u64 = 1_000;

/// Deterministic execution fee in `vern` per persistent confidential state write.
pub const FEE_PER_STATE_WRITE_VERN: u64 = 500;

/// Kernel-level opcode discriminant used for static resource and fee budgeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelCircuitOpKind {
    LoadState,
    StoreState,
    LoadInput,
    LoadConst,
    Add,
    Sub,
    MulConst,
    Mul,
    Square,
    Mux,
    AssertZero,
    AssertBool,
    AssertRangeBits { bit_width: u8 },
    RevealOutput,
}

/// Errors returned by [`validate_circuit_budget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitValidationError {
    EmptyCircuit,
    ZeroRegisters,
    TooManyOps,
    TooManyRegisters,
    TooManyInputs,
    TooManyStateWrites,
    InvalidRangeBitWidth,
    ArithmeticOverflow,
}

/// Exact static resource and fee budget computed for a validated acyclic MPC circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBudget {
    /// Total number of operations in the circuit.
    pub total_ops: usize,
    /// General Beaver multiplication triples (`Mul`, `Mux` selection, plus 1 final RLC blinding
    /// triple whenever the circuit contains at least one assertion).
    pub beaver_triples: usize,
    /// Beaver squarings (`Square`, `Mux` boolean check, `AssertBool`, and per-bit checks in
    /// `AssertRangeBits`).
    pub beaver_squares: usize,
    /// Number of persistent confidential state writes (`StoreState`).
    pub state_writes: usize,
    /// Number of explicitly revealed scalar outputs (`RevealOutput`).
    pub revealed_outputs: usize,
    /// Total deterministic execution fee in `vern`.
    pub fee_vern: u64,
}

impl CircuitBudget {
    /// Combined Beaver consumptions (`beaver_triples + beaver_squares`) when squarings are
    /// served from a unified `BeaverPool`.
    #[inline]
    pub const fn total_beaver_consumptions(&self) -> Option<usize> {
        self.beaver_triples.checked_add(self.beaver_squares)
    }
}

/// Statically validate circuit resource ceilings and compute its exact [`CircuitBudget`].
///
/// Pure, panic-free, zero-heap, and overflow-checked across every counter and fee term.
pub fn validate_circuit_budget(
    ops: &[KernelCircuitOpKind],
    num_regs: usize,
    num_inputs: usize,
) -> Result<CircuitBudget, CircuitValidationError> {
    if ops.is_empty() {
        return Err(CircuitValidationError::EmptyCircuit);
    }
    if ops.len() > MAX_CIRCUIT_OPS {
        return Err(CircuitValidationError::TooManyOps);
    }
    if num_regs == 0 {
        return Err(CircuitValidationError::ZeroRegisters);
    }
    if num_regs > MAX_CIRCUIT_REGS {
        return Err(CircuitValidationError::TooManyRegisters);
    }
    if num_inputs > MAX_CIRCUIT_REGS {
        return Err(CircuitValidationError::TooManyInputs);
    }

    let mut beaver_triples = 0usize;
    let mut beaver_squares = 0usize;
    let mut state_writes = 0usize;
    let mut revealed_outputs = 0usize;
    let mut has_assertion = false;

    let mut idx = 0usize;
    while idx < ops.len() {
        match ops[idx] {
            KernelCircuitOpKind::LoadState
            | KernelCircuitOpKind::LoadInput
            | KernelCircuitOpKind::LoadConst
            | KernelCircuitOpKind::Add
            | KernelCircuitOpKind::Sub
            | KernelCircuitOpKind::MulConst => {}
            KernelCircuitOpKind::StoreState => {
                state_writes = state_writes
                    .checked_add(1)
                    .ok_or(CircuitValidationError::ArithmeticOverflow)?;
                if state_writes > MAX_STATE_KEYS {
                    return Err(CircuitValidationError::TooManyStateWrites);
                }
            }
            KernelCircuitOpKind::Mul => {
                beaver_triples = beaver_triples
                    .checked_add(1)
                    .ok_or(CircuitValidationError::ArithmeticOverflow)?;
            }
            KernelCircuitOpKind::Square => {
                beaver_squares = beaver_squares
                    .checked_add(1)
                    .ok_or(CircuitValidationError::ArithmeticOverflow)?;
            }
            KernelCircuitOpKind::Mux => {
                // 1 Beaver triple for `cond * (if_true - if_false)` + 1 squaring for
                // `cond * (cond - 1) == 0` folded into the batched blinded RLC.
                beaver_triples = beaver_triples
                    .checked_add(1)
                    .ok_or(CircuitValidationError::ArithmeticOverflow)?;
                beaver_squares = beaver_squares
                    .checked_add(1)
                    .ok_or(CircuitValidationError::ArithmeticOverflow)?;
                has_assertion = true;
            }
            KernelCircuitOpKind::AssertZero => {
                has_assertion = true;
            }
            KernelCircuitOpKind::AssertBool => {
                beaver_squares = beaver_squares
                    .checked_add(1)
                    .ok_or(CircuitValidationError::ArithmeticOverflow)?;
                has_assertion = true;
            }
            KernelCircuitOpKind::AssertRangeBits { bit_width } => {
                let width = bit_width as usize;
                if width == 0 || width > MAX_RANGE_BITS {
                    return Err(CircuitValidationError::InvalidRangeBitWidth);
                }
                beaver_squares = beaver_squares
                    .checked_add(width)
                    .ok_or(CircuitValidationError::ArithmeticOverflow)?;
                has_assertion = true;
            }
            KernelCircuitOpKind::RevealOutput => {
                revealed_outputs = revealed_outputs
                    .checked_add(1)
                    .ok_or(CircuitValidationError::ArithmeticOverflow)?;
            }
        }
        idx += 1;
    }

    if has_assertion {
        // Single final blinding triple for `[rho] * [Z]` Schwartz-Zippel RLC.
        beaver_triples = beaver_triples
            .checked_add(1)
            .ok_or(CircuitValidationError::ArithmeticOverflow)?;
    }

    let total_beaver = beaver_triples
        .checked_add(beaver_squares)
        .ok_or(CircuitValidationError::ArithmeticOverflow)?;
    let total_beaver_u64 =
        u64::try_from(total_beaver).map_err(|_| CircuitValidationError::ArithmeticOverflow)?;
    let state_writes_u64 =
        u64::try_from(state_writes).map_err(|_| CircuitValidationError::ArithmeticOverflow)?;

    let triple_fee = total_beaver_u64
        .checked_mul(FEE_PER_TRIPLE_VERN)
        .ok_or(CircuitValidationError::ArithmeticOverflow)?;
    let write_fee = state_writes_u64
        .checked_mul(FEE_PER_STATE_WRITE_VERN)
        .ok_or(CircuitValidationError::ArithmeticOverflow)?;
    let fee_vern = triple_fee
        .checked_add(write_fee)
        .ok_or(CircuitValidationError::ArithmeticOverflow)?;

    Ok(CircuitBudget {
        total_ops: ops.len(),
        beaver_triples,
        beaver_squares,
        state_writes,
        revealed_outputs,
        fee_vern,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_circuit_budget_exact_accounting() {
        let ops = [
            KernelCircuitOpKind::LoadState,
            KernelCircuitOpKind::LoadInput,
            KernelCircuitOpKind::Add,
            KernelCircuitOpKind::Mul,
            KernelCircuitOpKind::Square,
            KernelCircuitOpKind::Mux,
            KernelCircuitOpKind::AssertZero,
            KernelCircuitOpKind::AssertBool,
            KernelCircuitOpKind::AssertRangeBits { bit_width: 16 },
            KernelCircuitOpKind::StoreState,
            KernelCircuitOpKind::StoreState,
            KernelCircuitOpKind::RevealOutput,
        ];

        let budget = validate_circuit_budget(&ops, 32, 18).unwrap();
        assert_eq!(budget.total_ops, 12);
        // Mul (1) + Mux selection (1) + final RLC blinding triple (1) = 3.
        assert_eq!(budget.beaver_triples, 3);
        // Square (1) + Mux cond bool (1) + AssertBool (1) + RangeBits (16) = 19.
        assert_eq!(budget.beaver_squares, 19);
        assert_eq!(budget.total_beaver_consumptions(), Some(22));
        assert_eq!(budget.state_writes, 2);
        assert_eq!(budget.revealed_outputs, 1);
        assert_eq!(
            budget.fee_vern,
            22 * FEE_PER_TRIPLE_VERN + 2 * FEE_PER_STATE_WRITE_VERN
        );
    }

    #[test]
    fn test_validate_circuit_budget_no_assertions_no_rlc_triple() {
        let ops = [
            KernelCircuitOpKind::LoadInput,
            KernelCircuitOpKind::LoadConst,
            KernelCircuitOpKind::Add,
            KernelCircuitOpKind::RevealOutput,
        ];
        let budget = validate_circuit_budget(&ops, 4, 1).unwrap();
        assert_eq!(budget.beaver_triples, 0);
        assert_eq!(budget.beaver_squares, 0);
        assert_eq!(budget.state_writes, 0);
        assert_eq!(budget.revealed_outputs, 1);
        assert_eq!(budget.fee_vern, 0);
    }

    #[test]
    fn test_validate_circuit_budget_rejects_boundary_violations() {
        assert_eq!(
            validate_circuit_budget(&[], 1, 0),
            Err(CircuitValidationError::EmptyCircuit)
        );
        assert_eq!(
            validate_circuit_budget(&[KernelCircuitOpKind::LoadConst], 0, 0),
            Err(CircuitValidationError::ZeroRegisters)
        );
        assert_eq!(
            validate_circuit_budget(&[KernelCircuitOpKind::LoadConst], MAX_CIRCUIT_REGS + 1, 0),
            Err(CircuitValidationError::TooManyRegisters)
        );
        assert_eq!(
            validate_circuit_budget(&[KernelCircuitOpKind::LoadInput], 1, MAX_CIRCUIT_REGS + 1),
            Err(CircuitValidationError::TooManyInputs)
        );
        assert_eq!(
            validate_circuit_budget(&[KernelCircuitOpKind::AssertRangeBits { bit_width: 0 }], 2, 1),
            Err(CircuitValidationError::InvalidRangeBitWidth)
        );
        assert_eq!(
            validate_circuit_budget(
                &[KernelCircuitOpKind::AssertRangeBits {
                    bit_width: (MAX_RANGE_BITS as u8) + 1
                }],
                2,
                1
            ),
            Err(CircuitValidationError::InvalidRangeBitWidth)
        );

        let too_many_ops = [KernelCircuitOpKind::LoadConst; MAX_CIRCUIT_OPS + 1];
        assert_eq!(
            validate_circuit_budget(&too_many_ops, 1, 0),
            Err(CircuitValidationError::TooManyOps)
        );

        let too_many_writes = [KernelCircuitOpKind::StoreState; MAX_STATE_KEYS + 1];
        assert_eq!(
            validate_circuit_budget(&too_many_writes, 1, 0),
            Err(CircuitValidationError::TooManyStateWrites)
        );

        // Worst-case valid op load never overflows u64 fee computation.
        let worst_case_ops = [KernelCircuitOpKind::AssertRangeBits {
            bit_width: MAX_RANGE_BITS as u8,
        }; MAX_CIRCUIT_OPS];
        let worst = validate_circuit_budget(&worst_case_ops, MAX_CIRCUIT_REGS, MAX_CIRCUIT_REGS)
            .expect("worst-case valid circuit must not overflow");
        assert_eq!(worst.beaver_triples, 1);
        assert_eq!(worst.beaver_squares, MAX_CIRCUIT_OPS * MAX_RANGE_BITS);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn symbolic_op() -> KernelCircuitOpKind {
        let tag: u8 = kani::any();
        kani::assume(tag < 14);
        match tag {
            0 => KernelCircuitOpKind::LoadState,
            1 => KernelCircuitOpKind::StoreState,
            2 => KernelCircuitOpKind::LoadInput,
            3 => KernelCircuitOpKind::LoadConst,
            4 => KernelCircuitOpKind::Add,
            5 => KernelCircuitOpKind::Sub,
            6 => KernelCircuitOpKind::MulConst,
            7 => KernelCircuitOpKind::Mul,
            8 => KernelCircuitOpKind::Square,
            9 => KernelCircuitOpKind::Mux,
            10 => KernelCircuitOpKind::AssertZero,
            11 => KernelCircuitOpKind::AssertBool,
            12 => KernelCircuitOpKind::AssertRangeBits {
                bit_width: kani::any(),
            },
            _ => KernelCircuitOpKind::RevealOutput,
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn prove_validate_circuit_budget_never_panics_or_overflows() {
        let ops = [
            symbolic_op(),
            symbolic_op(),
            symbolic_op(),
            symbolic_op(),
            symbolic_op(),
            symbolic_op(),
            symbolic_op(),
            symbolic_op(),
        ];
        let len: usize = kani::any();
        kani::assume(len <= ops.len());
        let num_regs: usize = kani::any();
        let num_inputs: usize = kani::any();

        if let Ok(budget) = validate_circuit_budget(&ops[..len], num_regs, num_inputs) {
            assert_eq!(budget.total_ops, len);
            assert!(budget.total_ops >= 1 && budget.total_ops <= MAX_CIRCUIT_OPS);
            assert!(num_regs >= 1 && num_regs <= MAX_CIRCUIT_REGS);
            assert!(num_inputs <= MAX_CIRCUIT_REGS);
            assert!(budget.state_writes <= MAX_STATE_KEYS);

            let total_beaver = budget.total_beaver_consumptions().unwrap();
            let expected_fee = (total_beaver as u64) * FEE_PER_TRIPLE_VERN
                + (budget.state_writes as u64) * FEE_PER_STATE_WRITE_VERN;
            assert_eq!(budget.fee_vern, expected_fee);
        }
    }
}
