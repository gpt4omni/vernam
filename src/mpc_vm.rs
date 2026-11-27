//! Confidential Information-Theoretic MPC Arithmetic Circuit VM (`MpcVmEngine`) for Vernam (`VRNM`).
//!
//! Zero external crates, zero computational cryptography (no SHA-256, RSA, ECDSA, AES, or zk-SNARKs).
//! Every operation executes over Shamir secret shares in the Mersenne prime field `F_(2^127 - 1)`
//! using precomputed Lagrange interpolation ([`LagrangeCache`]) and single-use offline Beaver
//! triples ([`BeaverPool`]):
//!
//! - **Non-Turing-complete & Reentrancy-free**: Circuits are finite, straight-line acyclic DAGs
//!   with static register bounds, strict read-before-write validation, zero loops, and zero external
//!   contract calls.
//! - **Oblivious Branchless Control Flow**: [`MpcOp::Mux`] evaluates `if_false + cond * (if_true - if_false)`
//!   and folds `cond * (cond - 1) == 0` into the final blinded RLC so neither the taken branch nor
//!   any operand is ever leaked.
//! - **Zero-Leakage Batched Assertions**: Every `AssertZero`, `AssertBool`, `Mux` condition bit,
//!   and `AssertRangeBits` check is accumulated into a single Schwartz–Zippel Random Linear
//!   Combination `[Z] = sum_k gamma^k * [r_k]` and multiplicatively blinded as `[rho] * [Z]` with
//!   a uniform non-zero one-time pad `rho in F_p \ {0}` before opening. A failed assertion reveals
//!   a uniformly random non-zero field element (0 bits leaked!) and triggers 100% atomic rollback.
//! - **Proactive Secret Sharing (PSS)**: [`MpcVmEngine::proactive_refresh_all_contracts`] refreshes
//!   every persistent confidential storage slot across all deployed contracts with fresh
//!   zero-constant polynomials, invalidating shares from prior epochs while preserving exact state.

use std::collections::BTreeMap;
use std::fmt;

use crate::field::{
    PRIME_P, add_mod, ct_eq_u128, mul_mod, random_nonzero_field_elem, zeroize_u128,
};
use crate::privacy_mpc::{
    BeaverPool, DEFAULT_NUM_VALIDATORS, DEFAULT_THRESHOLD, LagrangeCache, MpcError, mpc_add,
    mpc_mul, mpc_scale, mpc_sub, mpc_sub_const, proactive_refresh_epoch_batch, split_secret,
};

/// Maximum number of secret-shared registers addressable by a single circuit.
pub const MAX_CIRCUIT_REGS: usize = 256;

/// Maximum number of acyclic DAG operations allowed in a single circuit.
pub const MAX_CIRCUIT_OPS: usize = 2_048;

/// Maximum number of persistent confidential state keys per contract (and writes per call).
pub const MAX_STATE_KEYS: usize = 256;

/// Maximum bit width supported by an [`MpcOp::AssertRangeBits`] constraint (`0 <= x < 2^64`).
pub const MAX_RANGE_BITS: usize = 64;

/// Deterministic execution fee in `vern` per Beaver triple/square consumption.
pub const FEE_PER_TRIPLE_VERN: u64 = 1_000;

/// Deterministic execution fee in `vern` per persistent confidential state write.
pub const FEE_PER_STATE_WRITE_VERN: u64 = 500;

/// Unique identifier for a deployed confidential contract inside [`MpcVmEngine`].
pub type ContractId = u64;

// Standard storage keys for built-in confidential contract templates.

/// Storage key for the locked escrowed amount in [`build_private_escrow_circuit`].
pub const ESCROW_KEY_AMOUNT: u16 = 0;
/// Storage key for the buyer's confidential balance in [`build_private_escrow_circuit`].
pub const ESCROW_KEY_BUYER_BAL: u16 = 1;
/// Storage key for the seller's confidential balance in [`build_private_escrow_circuit`].
pub const ESCROW_KEY_SELLER_BAL: u16 = 2;
/// Storage key for the settlement flag (`0` = open, `1` = settled) in [`build_private_escrow_circuit`].
pub const ESCROW_KEY_SETTLED: u16 = 3;

/// Storage key for the sender's confidential balance in [`build_private_token_transfer_circuit`].
pub const TOKEN_KEY_SENDER_BAL: u16 = 0;
/// Storage key for the recipient's confidential balance in [`build_private_token_transfer_circuit`].
pub const TOKEN_KEY_RECIPIENT_BAL: u16 = 1;

/// Storage key for the required approval threshold in [`build_blind_multisig_threshold_circuit`].
pub const MULTISIG_KEY_THRESHOLD: u16 = 0;
/// Storage key for the monotonic approved-action counter in [`build_blind_multisig_threshold_circuit`].
pub const MULTISIG_KEY_APPROVED_COUNT: u16 = 1;

/// Errors returned by circuit validation, deployment, execution, and state refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcVmError {
    /// Circuit has zero operations.
    EmptyCircuit,
    /// Circuit declares zero registers.
    ZeroRegisters,
    /// Circuit exceeds [`MAX_CIRCUIT_OPS`].
    TooManyOps { count: usize, max: usize },
    /// Circuit exceeds [`MAX_CIRCUIT_REGS`].
    TooManyRegisters { count: usize, max: usize },
    /// Circuit exceeds [`MAX_CIRCUIT_REGS`] input slots.
    TooManyInputs { count: usize, max: usize },
    /// Circuit exceeds [`MAX_STATE_KEYS`] persistent state writes.
    TooManyStateWrites { count: usize, max: usize },
    /// Register index is `>= num_regs`.
    RegisterOutOfBounds { reg: u16, num_regs: u16 },
    /// Operation reads a register before any prior operation initialized it.
    UninitializedRegister { reg: u16, op_index: usize },
    /// Storage key is `>= MAX_STATE_KEYS`.
    StateKeyOutOfBounds { key: u16 },
    /// Input index is `>= num_inputs`.
    InputIndexOutOfBounds { input_idx: u16, num_inputs: u16 },
    /// Public constant or scalar is `>= PRIME_P`.
    NonCanonicalConstant { value: u128 },
    /// `AssertRangeBits` bit vector is empty or exceeds [`MAX_RANGE_BITS`].
    InvalidRangeBitWidth { width: usize },
    /// Checked integer arithmetic overflow during validation or fee accounting.
    ArithmeticOverflow,
    /// Contract ID is not deployed in this engine.
    ContractNotFound { contract_id: ContractId },
    /// Storage key is not present in the contract's state map.
    StateKeyNotFound { contract_id: ContractId, key: u16 },
    /// Caller supplied a different number of secret inputs than the circuit declares.
    InvalidInputCount { expected: usize, got: usize },
    /// Provided `BeaverPool` does not match the engine's `(threshold, num_validators)` committee.
    CommitteeMismatch,
    /// One or more algebraic assertions (`AssertZero`, `AssertBool`, `Mux` condition, or
    /// `AssertRangeBits`) failed the final blinded `[rho] * [Z]` Schwartz–Zippel RLC.
    /// Zero bits of secret state were leaked and all staged writes were rolled back atomically.
    AssertionFailed,
    /// Invalid template builder parameter.
    InvalidTemplateParameter(&'static str),
    /// Underlying Shamir / Beaver / Lagrange error.
    Mpc(MpcError),
}

impl From<MpcError> for MpcVmError {
    fn from(err: MpcError) -> Self {
        MpcVmError::Mpc(err)
    }
}

impl fmt::Display for MpcVmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcVmError::EmptyCircuit => write!(f, "circuit contains zero operations"),
            MpcVmError::ZeroRegisters => write!(f, "circuit declares zero registers"),
            MpcVmError::TooManyOps { count, max } => {
                write!(f, "circuit has {count} ops, exceeding max {max}")
            }
            MpcVmError::TooManyRegisters { count, max } => {
                write!(f, "circuit declares {count} registers, exceeding max {max}")
            }
            MpcVmError::TooManyInputs { count, max } => {
                write!(f, "circuit declares {count} inputs, exceeding max {max}")
            }
            MpcVmError::TooManyStateWrites { count, max } => {
                write!(f, "circuit performs {count} state writes, exceeding max {max}")
            }
            MpcVmError::RegisterOutOfBounds { reg, num_regs } => {
                write!(f, "register r{reg} out of bounds for num_regs={num_regs}")
            }
            MpcVmError::UninitializedRegister { reg, op_index } => {
                write!(f, "op #{op_index} reads uninitialized register r{reg}")
            }
            MpcVmError::StateKeyOutOfBounds { key } => {
                write!(f, "state key {key} exceeds MAX_STATE_KEYS ({MAX_STATE_KEYS})")
            }
            MpcVmError::InputIndexOutOfBounds {
                input_idx,
                num_inputs,
            } => {
                write!(
                    f,
                    "input index {input_idx} out of bounds for num_inputs={num_inputs}"
                )
            }
            MpcVmError::NonCanonicalConstant { value } => {
                write!(f, "non-canonical field constant {value} >= PRIME_P")
            }
            MpcVmError::InvalidRangeBitWidth { width } => {
                write!(
                    f,
                    "invalid AssertRangeBits width {width}; require 1..={MAX_RANGE_BITS}"
                )
            }
            MpcVmError::ArithmeticOverflow => write!(f, "checked arithmetic overflow"),
            MpcVmError::ContractNotFound { contract_id } => {
                write!(f, "contract {contract_id} not found")
            }
            MpcVmError::StateKeyNotFound { contract_id, key } => {
                write!(f, "state key {key} not found in contract {contract_id}")
            }
            MpcVmError::InvalidInputCount { expected, got } => {
                write!(f, "expected {expected} secret inputs, got {got}")
            }
            MpcVmError::CommitteeMismatch => {
                write!(f, "BeaverPool committee parameters do not match MpcVmEngine")
            }
            MpcVmError::AssertionFailed => {
                write!(
                    f,
                    "blinded Schwartz-Zippel RLC assertion failed (atomic rollback applied)"
                )
            }
            MpcVmError::InvalidTemplateParameter(msg) => {
                write!(f, "invalid circuit template parameter: {msg}")
            }
            MpcVmError::Mpc(err) => write!(f, "MPC error: {err}"),
        }
    }
}

impl std::error::Error for MpcVmError {}

/// Wipe a slice of `u128` field elements via volatile writes.
#[inline]
fn zeroize_u128_slice(buf: &mut [u128]) {
    for elem in buf.iter_mut() {
        zeroize_u128(elem);
    }
}

/// RAII guard for a single share vector.
struct ZeroizeShareVec(Vec<u128>);

impl Drop for ZeroizeShareVec {
    fn drop(&mut self) {
        zeroize_u128_slice(&mut self.0);
    }
}

/// RAII guard for a list of share vectors (e.g., residuals or staged reveals).
struct ZeroizeShareMatrix(Vec<Vec<u128>>);

impl Drop for ZeroizeShareMatrix {
    fn drop(&mut self) {
        for row in &mut self.0 {
            zeroize_u128_slice(row);
        }
    }
}

/// RAII guard for the VM register file.
struct ZeroizeRegFile(Vec<Option<Vec<u128>>>);

impl Drop for ZeroizeRegFile {
    fn drop(&mut self) {
        for slot in &mut self.0 {
            if let Some(shares) = slot.as_mut() {
                zeroize_u128_slice(shares);
            }
        }
    }
}

/// RAII guard for staged `StoreState` writes prior to atomic commit.
struct ZeroizeStagedWrites(BTreeMap<u16, Vec<u128>>);

impl Drop for ZeroizeStagedWrites {
    fn drop(&mut self) {
        for shares in self.0.values_mut() {
            zeroize_u128_slice(shares);
        }
    }
}

// ============================================================================
// 1. Acyclic DAG Instruction Set (`MpcOp`), Program, Builder & Static Validator
// ============================================================================

/// Non-Turing-complete, reentrancy-free arithmetic circuit opcode over secret-shared registers
/// in `F_(2^127 - 1)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcOp {
    /// Load secret-shared storage slot `key` (or fresh shared `0` if unset) into `dst`.
    LoadState { dst: u16, key: u16 },
    /// Stage secret-shared register `src` for atomic write to storage slot `key`.
    StoreState { key: u16, src: u16 },
    /// Load secret-shared caller input `input_idx` into `dst`.
    LoadInput { dst: u16, input_idx: u16 },
    /// Load a canonical public constant `value < PRIME_P` as a fresh Shamir sharing into `dst`.
    LoadConst { dst: u16, value: u128 },
    /// Local share addition `[dst] = [a] + [b] (mod PRIME_P)` (0 Beaver triples).
    Add { dst: u16, a: u16, b: u16 },
    /// Local share subtraction `[dst] = [a] - [b] (mod PRIME_P)` (0 Beaver triples).
    Sub { dst: u16, a: u16, b: u16 },
    /// Local public scalar multiplication `[dst] = scalar * [a] (mod PRIME_P)` (0 Beaver triples).
    MulConst { dst: u16, a: u16, scalar: u128 },
    /// Beaver multiplication `[dst] = [a] * [b] (mod PRIME_P)` (1 Beaver triple).
    Mul { dst: u16, a: u16, b: u16 },
    /// Beaver squaring `[dst] = [a]^2 (mod PRIME_P)` (1 Beaver triple/square).
    Square { dst: u16, a: u16 },
    /// Oblivious branchless multiplexer: `[dst] = [if_false] + [cond_bit] * ([if_true] - [if_false])`
    /// AND folds `[cond_bit] * ([cond_bit] - 1) == 0` into the single final blinded RLC.
    Mux {
        dst: u16,
        cond_bit: u16,
        if_true: u16,
        if_false: u16,
    },
    /// Fold `[reg] == 0` into the single final blinded `[rho] * [Z]` Schwartz–Zippel RLC.
    AssertZero { reg: u16 },
    /// Fold `[reg] * ([reg] - 1) == 0` into the single final blinded RLC.
    AssertBool { reg: u16 },
    /// Enforce `bit_i in {0, 1}` for every `bit_reg` (`1..=64` bits) AND
    /// `val_reg == sum_{i=0}^{W-1} bit_i * 2^i` in the single final blinded RLC.
    AssertRangeBits { val_reg: u16, bit_regs: Vec<u16> },
    /// Schedule register `src` for explicit reconstruction ONLY AFTER all assertions pass.
    RevealOutput { src: u16 },
}

/// Validated, immutable acyclic arithmetic circuit program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitProgram {
    pub num_regs: u16,
    pub num_inputs: u16,
    pub ops: Vec<MpcOp>,
}

/// Upfront static resource and deterministic fee calculation returned by [`validate_circuit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitCost {
    /// Total number of DAG operations.
    pub total_ops: usize,
    /// Exact total number of single-use Beaver triples consumed from [`BeaverPool`] per execution
    /// (including squarings and the 1 final RLC blinding triple when `assertions > 0`).
    pub beaver_triples: usize,
    /// Number of Beaver consumptions that are squarings (`Square`, `Mux` cond bit, `AssertBool`,
    /// `AssertRangeBits` bit checks).
    pub beaver_squares: usize,
    /// Total number of algebraic zero-constraints folded into the single final blinded RLC.
    pub assertions: usize,
    /// Number of persistent confidential state writes (`StoreState`).
    pub state_writes: usize,
    /// Number of explicitly revealed outputs (`RevealOutput`).
    pub revealed_outputs: usize,
    /// Deterministic execution fee in `vern`.
    pub fee_vern: u64,
}

/// Ergonomic fluent DSL for constructing acyclic [`CircuitProgram`]s with automatic register
/// allocation and static validation on [`CircuitBuilder::build`].
#[derive(Debug, Default, Clone)]
pub struct CircuitBuilder {
    next_reg: usize,
    num_inputs: usize,
    ops: Vec<MpcOp>,
}

impl CircuitBuilder {
    /// Create a fresh empty circuit builder.
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn alloc_reg(&mut self) -> u16 {
        let reg = self.next_reg;
        self.next_reg = self.next_reg.saturating_add(1);
        u16::try_from(reg).unwrap_or(u16::MAX)
    }

    /// Emit `LoadState { dst, key }` and return `dst`.
    pub fn load_state(&mut self, key: u16) -> u16 {
        let dst = self.alloc_reg();
        self.ops.push(MpcOp::LoadState { dst, key });
        dst
    }

    /// Emit `StoreState { key, src }`.
    pub fn store_state(&mut self, key: u16, src: u16) -> &mut Self {
        self.ops.push(MpcOp::StoreState { key, src });
        self
    }

    /// Emit `LoadInput { dst, input_idx }` and return `dst`.
    pub fn load_input(&mut self, input_idx: u16) -> u16 {
        let dst = self.alloc_reg();
        let needed_inputs = (input_idx as usize).saturating_add(1);
        if needed_inputs > self.num_inputs {
            self.num_inputs = needed_inputs;
        }
        self.ops.push(MpcOp::LoadInput { dst, input_idx });
        dst
    }

    /// Emit `LoadConst { dst, value }` and return `dst`.
    pub fn load_const(&mut self, value: u128) -> u16 {
        let dst = self.alloc_reg();
        self.ops.push(MpcOp::LoadConst { dst, value });
        dst
    }

    /// Emit `Add { dst, a, b }` and return `dst`.
    pub fn add(&mut self, a: u16, b: u16) -> u16 {
        let dst = self.alloc_reg();
        self.ops.push(MpcOp::Add { dst, a, b });
        dst
    }

    /// Emit `Sub { dst, a, b }` and return `dst`.
    pub fn sub(&mut self, a: u16, b: u16) -> u16 {
        let dst = self.alloc_reg();
        self.ops.push(MpcOp::Sub { dst, a, b });
        dst
    }

    /// Emit `MulConst { dst, a, scalar }` and return `dst`.
    pub fn mul_const(&mut self, a: u16, scalar: u128) -> u16 {
        let dst = self.alloc_reg();
        self.ops.push(MpcOp::MulConst { dst, a, scalar });
        dst
    }

    /// Emit `Mul { dst, a, b }` and return `dst`.
    pub fn mul(&mut self, a: u16, b: u16) -> u16 {
        let dst = self.alloc_reg();
        self.ops.push(MpcOp::Mul { dst, a, b });
        dst
    }

    /// Emit `Square { dst, a }` and return `dst`.
    pub fn square(&mut self, a: u16) -> u16 {
        let dst = self.alloc_reg();
        self.ops.push(MpcOp::Square { dst, a });
        dst
    }

    /// Emit `Mux { dst, cond_bit, if_true, if_false }` and return `dst`.
    pub fn mux(&mut self, cond_bit: u16, if_true: u16, if_false: u16) -> u16 {
        let dst = self.alloc_reg();
        self.ops.push(MpcOp::Mux {
            dst,
            cond_bit,
            if_true,
            if_false,
        });
        dst
    }

    /// Emit `AssertZero { reg }`.
    pub fn assert_zero(&mut self, reg: u16) -> &mut Self {
        self.ops.push(MpcOp::AssertZero { reg });
        self
    }

    /// Emit `AssertBool { reg }`.
    pub fn assert_bool(&mut self, reg: u16) -> &mut Self {
        self.ops.push(MpcOp::AssertBool { reg });
        self
    }

    /// Emit `AssertRangeBits { val_reg, bit_regs }`.
    pub fn assert_range_bits(&mut self, val_reg: u16, bit_regs: Vec<u16>) -> &mut Self {
        self.ops.push(MpcOp::AssertRangeBits { val_reg, bit_regs });
        self
    }

    /// Emit `RevealOutput { src }`.
    pub fn reveal(&mut self, src: u16) -> &mut Self {
        self.ops.push(MpcOp::RevealOutput { src });
        self
    }

    /// Finalize and statically validate the constructed [`CircuitProgram`].
    pub fn build(self) -> Result<CircuitProgram, MpcVmError> {
        if self.next_reg > MAX_CIRCUIT_REGS {
            return Err(MpcVmError::TooManyRegisters {
                count: self.next_reg,
                max: MAX_CIRCUIT_REGS,
            });
        }
        if self.num_inputs > MAX_CIRCUIT_REGS {
            return Err(MpcVmError::TooManyInputs {
                count: self.num_inputs,
                max: MAX_CIRCUIT_REGS,
            });
        }
        let program = CircuitProgram {
            num_regs: self.next_reg as u16,
            num_inputs: self.num_inputs as u16,
            ops: self.ops,
        };
        validate_circuit(&program)?;
        Ok(program)
    }
}

/// Statically validate a [`CircuitProgram`] and compute its exact upfront [`CircuitCost`].
///
/// Enforces:
/// - Non-empty circuit within [`MAX_CIRCUIT_OPS`], [`MAX_CIRCUIT_REGS`], and [`MAX_STATE_KEYS`].
/// - Strict register bounds and read-before-write initialization across the entire DAG.
/// - Canonical `< PRIME_P` constants in `LoadConst` and `MulConst`.
/// - Valid `1..=MAX_RANGE_BITS` bit widths in `AssertRangeBits`.
/// - Exact, overflow-checked Beaver triple count and `vern` fee accounting.
pub fn validate_circuit(program: &CircuitProgram) -> Result<CircuitCost, MpcVmError> {
    if program.ops.is_empty() {
        return Err(MpcVmError::EmptyCircuit);
    }
    if program.ops.len() > MAX_CIRCUIT_OPS {
        return Err(MpcVmError::TooManyOps {
            count: program.ops.len(),
            max: MAX_CIRCUIT_OPS,
        });
    }
    if program.num_regs == 0 {
        return Err(MpcVmError::ZeroRegisters);
    }
    if (program.num_regs as usize) > MAX_CIRCUIT_REGS {
        return Err(MpcVmError::TooManyRegisters {
            count: program.num_regs as usize,
            max: MAX_CIRCUIT_REGS,
        });
    }
    if (program.num_inputs as usize) > MAX_CIRCUIT_REGS {
        return Err(MpcVmError::TooManyInputs {
            count: program.num_inputs as usize,
            max: MAX_CIRCUIT_REGS,
        });
    }

    let mut initialized = vec![false; program.num_regs as usize];
    let mut mul_triples = 0usize;
    let mut beaver_squares = 0usize;
    let mut assertions = 0usize;
    let mut state_writes = 0usize;
    let mut revealed_outputs = 0usize;

    let check_read = |reg: u16, initialized: &[bool], op_index: usize| -> Result<(), MpcVmError> {
        if reg >= program.num_regs {
            return Err(MpcVmError::RegisterOutOfBounds {
                reg,
                num_regs: program.num_regs,
            });
        }
        if !initialized[reg as usize] {
            return Err(MpcVmError::UninitializedRegister { reg, op_index });
        }
        Ok(())
    };

    let check_write = |dst: u16| -> Result<(), MpcVmError> {
        if dst >= program.num_regs {
            return Err(MpcVmError::RegisterOutOfBounds {
                reg: dst,
                num_regs: program.num_regs,
            });
        }
        Ok(())
    };

    for (op_index, op) in program.ops.iter().enumerate() {
        match op {
            MpcOp::LoadState { dst, key } => {
                if (*key as usize) >= MAX_STATE_KEYS {
                    return Err(MpcVmError::StateKeyOutOfBounds { key: *key });
                }
                check_write(*dst)?;
                initialized[*dst as usize] = true;
            }
            MpcOp::StoreState { key, src } => {
                if (*key as usize) >= MAX_STATE_KEYS {
                    return Err(MpcVmError::StateKeyOutOfBounds { key: *key });
                }
                check_read(*src, &initialized, op_index)?;
                state_writes = state_writes
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
                if state_writes > MAX_STATE_KEYS {
                    return Err(MpcVmError::TooManyStateWrites {
                        count: state_writes,
                        max: MAX_STATE_KEYS,
                    });
                }
            }
            MpcOp::LoadInput { dst, input_idx } => {
                if *input_idx >= program.num_inputs {
                    return Err(MpcVmError::InputIndexOutOfBounds {
                        input_idx: *input_idx,
                        num_inputs: program.num_inputs,
                    });
                }
                check_write(*dst)?;
                initialized[*dst as usize] = true;
            }
            MpcOp::LoadConst { dst, value } => {
                if *value >= PRIME_P {
                    return Err(MpcVmError::NonCanonicalConstant { value: *value });
                }
                check_write(*dst)?;
                initialized[*dst as usize] = true;
            }
            MpcOp::Add { dst, a, b } | MpcOp::Sub { dst, a, b } => {
                check_read(*a, &initialized, op_index)?;
                check_read(*b, &initialized, op_index)?;
                check_write(*dst)?;
                initialized[*dst as usize] = true;
            }
            MpcOp::MulConst { dst, a, scalar } => {
                if *scalar >= PRIME_P {
                    return Err(MpcVmError::NonCanonicalConstant { value: *scalar });
                }
                check_read(*a, &initialized, op_index)?;
                check_write(*dst)?;
                initialized[*dst as usize] = true;
            }
            MpcOp::Mul { dst, a, b } => {
                check_read(*a, &initialized, op_index)?;
                check_read(*b, &initialized, op_index)?;
                check_write(*dst)?;
                initialized[*dst as usize] = true;
                mul_triples = mul_triples
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
            }
            MpcOp::Square { dst, a } => {
                check_read(*a, &initialized, op_index)?;
                check_write(*dst)?;
                initialized[*dst as usize] = true;
                beaver_squares = beaver_squares
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
            }
            MpcOp::Mux {
                dst,
                cond_bit,
                if_true,
                if_false,
            } => {
                check_read(*cond_bit, &initialized, op_index)?;
                check_read(*if_true, &initialized, op_index)?;
                check_read(*if_false, &initialized, op_index)?;
                check_write(*dst)?;
                initialized[*dst as usize] = true;
                mul_triples = mul_triples
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
                beaver_squares = beaver_squares
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
                assertions = assertions
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
            }
            MpcOp::AssertZero { reg } => {
                check_read(*reg, &initialized, op_index)?;
                assertions = assertions
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
            }
            MpcOp::AssertBool { reg } => {
                check_read(*reg, &initialized, op_index)?;
                beaver_squares = beaver_squares
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
                assertions = assertions
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
            }
            MpcOp::AssertRangeBits { val_reg, bit_regs } => {
                if bit_regs.is_empty() || bit_regs.len() > MAX_RANGE_BITS {
                    return Err(MpcVmError::InvalidRangeBitWidth {
                        width: bit_regs.len(),
                    });
                }
                check_read(*val_reg, &initialized, op_index)?;
                for &b_reg in bit_regs {
                    check_read(b_reg, &initialized, op_index)?;
                }
                beaver_squares = beaver_squares
                    .checked_add(bit_regs.len())
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
                assertions = assertions
                    .checked_add(bit_regs.len())
                    .and_then(|v| v.checked_add(1))
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
            }
            MpcOp::RevealOutput { src } => {
                check_read(*src, &initialized, op_index)?;
                revealed_outputs = revealed_outputs
                    .checked_add(1)
                    .ok_or(MpcVmError::ArithmeticOverflow)?;
            }
        }
    }

    let rlc_blinding_triple = usize::from(assertions > 0);
    let beaver_triples = mul_triples
        .checked_add(beaver_squares)
        .and_then(|v| v.checked_add(rlc_blinding_triple))
        .ok_or(MpcVmError::ArithmeticOverflow)?;

    let triples_u64 = u64::try_from(beaver_triples).map_err(|_| MpcVmError::ArithmeticOverflow)?;
    let writes_u64 = u64::try_from(state_writes).map_err(|_| MpcVmError::ArithmeticOverflow)?;
    let fee_vern = triples_u64
        .checked_mul(FEE_PER_TRIPLE_VERN)
        .and_then(|t| {
            writes_u64
                .checked_mul(FEE_PER_STATE_WRITE_VERN)
                .and_then(|w| t.checked_add(w))
        })
        .ok_or(MpcVmError::ArithmeticOverflow)?;

    Ok(CircuitCost {
        total_ops: program.ops.len(),
        beaver_triples,
        beaver_squares,
        assertions,
        state_writes,
        revealed_outputs,
        fee_vern,
    })
}

// ============================================================================
// 2. Deployed Confidential Contracts & Execution Engine (`MpcVmEngine`)
// ============================================================================

/// A deployed confidential arithmetic circuit with secret-shared persistent storage slots.
///
/// Redacts all secret shares in [`fmt::Debug`] and volatile-zeroizes every share on [`Drop`].
pub struct ConfidentialContract {
    id: ContractId,
    program: CircuitProgram,
    cost: CircuitCost,
    state: BTreeMap<u16, Vec<u128>>,
    pss_epoch: u64,
}

impl fmt::Debug for ConfidentialContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfidentialContract")
            .field("id", &self.id)
            .field("ops", &self.program.ops.len())
            .field("state_slots", &self.state.len())
            .field("pss_epoch", &self.pss_epoch)
            .field("state", &"<redacted>")
            .finish()
    }
}

impl Drop for ConfidentialContract {
    fn drop(&mut self) {
        for shares in self.state.values_mut() {
            zeroize_u128_slice(shares);
        }
    }
}

impl ConfidentialContract {
    /// Contract identifier.
    #[inline]
    pub fn id(&self) -> ContractId {
        self.id
    }

    /// Validated static resource and fee cost for each execution of this contract.
    #[inline]
    pub fn cost(&self) -> CircuitCost {
        self.cost
    }

    /// Current Proactive Secret Sharing epoch of this contract's storage shares.
    #[inline]
    pub fn pss_epoch(&self) -> u64 {
        self.pss_epoch
    }

    /// Read-only view of the raw validator shares for storage slot `key`.
    #[inline]
    pub fn state_shares(&self, key: u16) -> Option<&[u128]> {
        self.state.get(&key).map(Vec::as_slice)
    }
}

/// Receipt returned after an atomic, assertion-verified confidential circuit execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitExecutionReceipt {
    /// Contract that was executed.
    pub contract_id: ContractId,
    /// Explicitly revealed outputs from `RevealOutput` ops (in emission order).
    pub revealed_outputs: Vec<u128>,
    /// Exact number of single-use Beaver triples consumed from the pool.
    pub triples_consumed: usize,
    /// Exact number of algebraic zero-constraints checked in the final blinded RLC.
    pub assertions_checked: usize,
    /// Deterministic execution fee in `vern`.
    pub fee_vern: u64,
    /// Number of persistent confidential state writes committed atomically.
    pub state_writes: usize,
}

/// Vernam's Confidential IT-MPC Arithmetic Circuit VM engine.
pub struct MpcVmEngine {
    cache: LagrangeCache,
    next_contract_id: ContractId,
    pss_epoch: u64,
    contracts: BTreeMap<ContractId, ConfidentialContract>,
}

impl fmt::Debug for MpcVmEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcVmEngine")
            .field("threshold", &self.cache.threshold())
            .field("num_validators", &self.cache.num_validators())
            .field("pss_epoch", &self.pss_epoch)
            .field("deployed_contracts", &self.contracts.len())
            .finish()
    }
}

impl Default for MpcVmEngine {
    fn default() -> Self {
        Self::new_3_of_4()
    }
}

impl MpcVmEngine {
    /// Create a new VM engine for a `(threshold, num_validators)` Shamir validator committee.
    pub fn new(threshold: usize, num_validators: usize) -> Result<Self, MpcVmError> {
        let cache = LagrangeCache::new(threshold, num_validators)?;
        Ok(Self {
            cache,
            next_contract_id: 1,
            pss_epoch: 1,
            contracts: BTreeMap::new(),
        })
    }

    /// Convenience constructor for Vernam's default `(3, 4)` committee.
    pub fn new_3_of_4() -> Self {
        Self::new(DEFAULT_THRESHOLD, DEFAULT_NUM_VALIDATORS)
            .expect("default (3, 4) parameters are valid")
    }

    /// Precomputed Lagrange interpolator and degree-`(t - 1)` verifier.
    #[inline]
    pub fn cache(&self) -> &LagrangeCache {
        &self.cache
    }

    /// Current global Proactive Secret Sharing epoch (starts at `1`).
    #[inline]
    pub fn pss_epoch(&self) -> u64 {
        self.pss_epoch
    }

    /// Inspect a deployed contract's metadata and raw shares.
    #[inline]
    pub fn contract(&self, contract_id: ContractId) -> Option<&ConfidentialContract> {
        self.contracts.get(&contract_id)
    }

    /// Deploy a confidential circuit with initial secret-shared storage slots.
    ///
    /// Statically validates `program` and verifies canonical `< PRIME_P` and degree-`(t - 1)`
    /// Lagrange consistency for every provided initial state share vector.
    pub fn deploy_contract(
        &mut self,
        program: CircuitProgram,
        initial_shared_state: BTreeMap<u16, Vec<u128>>,
    ) -> Result<ContractId, MpcVmError> {
        let cost = validate_circuit(&program)?;
        for (&key, shares) in &initial_shared_state {
            if (key as usize) >= MAX_STATE_KEYS {
                return Err(MpcVmError::StateKeyOutOfBounds { key });
            }
            self.cache.verify_shares(shares)?;
        }

        let id = self.next_contract_id;
        self.next_contract_id = self
            .next_contract_id
            .checked_add(1)
            .ok_or(MpcVmError::ArithmeticOverflow)?;

        self.contracts.insert(
            id,
            ConfidentialContract {
                id,
                program,
                cost,
                state: initial_shared_state,
                pss_epoch: self.pss_epoch,
            },
        );
        Ok(id)
    }

    /// Execute a deployed confidential contract over Shamir-shared `secret_inputs`.
    ///
    /// Security guarantees:
    /// - Verifies committee compatibility, canonical `< PRIME_P`, and Lagrange degree-`(t - 1)`
    ///   consistency of every secret input before execution.
    /// - Folds every `AssertZero`, `AssertBool`, `Mux` condition bit, and `AssertRangeBits`
    ///   constraint into a single blinded `[rho] * [Z]` Schwartz–Zippel RLC over `F_(2^127 - 1)`
    ///   so failed executions leak 0 bits.
    /// - Guarantees 100% atomic rollback on any failure (no state writes committed, no outputs
    ///   revealed) and volatile-zeroizes every temporary register, residual, and staged share.
    pub fn execute_contract(
        &mut self,
        contract_id: ContractId,
        secret_inputs: &[Vec<u128>],
        beaver_pool: &mut BeaverPool,
    ) -> Result<CircuitExecutionReceipt, MpcVmError> {
        if beaver_pool.threshold() != self.cache.threshold()
            || beaver_pool.num_validators() != self.cache.num_validators()
        {
            return Err(MpcVmError::CommitteeMismatch);
        }

        let contract = self
            .contracts
            .get(&contract_id)
            .ok_or(MpcVmError::ContractNotFound { contract_id })?;

        let expected_inputs = contract.program.num_inputs as usize;
        if secret_inputs.len() != expected_inputs {
            return Err(MpcVmError::InvalidInputCount {
                expected: expected_inputs,
                got: secret_inputs.len(),
            });
        }
        for inp in secret_inputs {
            self.cache.verify_shares(inp)?;
        }

        if beaver_pool.len() < contract.cost.beaver_triples {
            return Err(MpcVmError::Mpc(MpcError::BeaverPoolExhausted {
                needed: contract.cost.beaver_triples,
                available: beaver_pool.len(),
            }));
        }

        let t = self.cache.threshold();
        let n = self.cache.num_validators();

        let mut regs = ZeroizeRegFile(vec![None; contract.program.num_regs as usize]);
        let mut staged_writes = ZeroizeStagedWrites(BTreeMap::new());
        let mut residuals = ZeroizeShareMatrix(Vec::with_capacity(contract.cost.assertions));
        let mut staged_reveals =
            ZeroizeShareMatrix(Vec::with_capacity(contract.cost.revealed_outputs));
        let mut triples_consumed = 0usize;

        let set_reg = |regs: &mut ZeroizeRegFile, dst: u16, shares: Vec<u128>| {
            if let Some(mut prev) = regs.0[dst as usize].replace(shares) {
                zeroize_u128_slice(&mut prev);
            }
        };

        for (op_index, op) in contract.program.ops.iter().enumerate() {
            match op {
                MpcOp::LoadState { dst, key } => {
                    let shares = if let Some(staged) = staged_writes.0.get(key) {
                        staged.clone()
                    } else if let Some(stored) = contract.state.get(key) {
                        stored.clone()
                    } else {
                        split_secret(0, t, n)?
                    };
                    set_reg(&mut regs, *dst, shares);
                }
                MpcOp::StoreState { key, src } => {
                    let src_shares = regs.0[*src as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister {
                            reg: *src,
                            op_index,
                        },
                    )?;
                    if let Some(mut prev) = staged_writes.0.insert(*key, src_shares.to_vec()) {
                        zeroize_u128_slice(&mut prev);
                    }
                }
                MpcOp::LoadInput { dst, input_idx } => {
                    set_reg(&mut regs, *dst, secret_inputs[*input_idx as usize].clone());
                }
                MpcOp::LoadConst { dst, value } => {
                    let shares = split_secret(*value, t, n)?;
                    set_reg(&mut regs, *dst, shares);
                }
                MpcOp::Add { dst, a, b } => {
                    let sa = regs.0[*a as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister { reg: *a, op_index },
                    )?;
                    let sb = regs.0[*b as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister { reg: *b, op_index },
                    )?;
                    let sum = mpc_add(sa, sb)?;
                    set_reg(&mut regs, *dst, sum);
                }
                MpcOp::Sub { dst, a, b } => {
                    let sa = regs.0[*a as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister { reg: *a, op_index },
                    )?;
                    let sb = regs.0[*b as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister { reg: *b, op_index },
                    )?;
                    let diff = mpc_sub(sa, sb)?;
                    set_reg(&mut regs, *dst, diff);
                }
                MpcOp::MulConst { dst, a, scalar } => {
                    let sa = regs.0[*a as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister { reg: *a, op_index },
                    )?;
                    let scaled = mpc_scale(sa, *scalar);
                    set_reg(&mut regs, *dst, scaled);
                }
                MpcOp::Mul { dst, a, b } => {
                    let sa = regs.0[*a as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister { reg: *a, op_index },
                    )?;
                    let sb = regs.0[*b as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister { reg: *b, op_index },
                    )?;
                    let triple = beaver_pool.pop()?;
                    triples_consumed += 1;
                    let prod = mpc_mul(sa, sb, triple, &self.cache)?;
                    set_reg(&mut regs, *dst, prod);
                }
                MpcOp::Square { dst, a } => {
                    let sa = regs.0[*a as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister { reg: *a, op_index },
                    )?;
                    let triple = beaver_pool.pop()?;
                    triples_consumed += 1;
                    let sq = mpc_mul(sa, sa, triple, &self.cache)?;
                    set_reg(&mut regs, *dst, sq);
                }
                MpcOp::Mux {
                    dst,
                    cond_bit,
                    if_true,
                    if_false,
                } => {
                    let cond = regs.0[*cond_bit as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister {
                            reg: *cond_bit,
                            op_index,
                        },
                    )?;
                    let t_val = regs.0[*if_true as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister {
                            reg: *if_true,
                            op_index,
                        },
                    )?;
                    let f_val = regs.0[*if_false as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister {
                            reg: *if_false,
                            op_index,
                        },
                    )?;

                    // 1. Fold `cond * (cond - 1) == 0` into the final blinded RLC.
                    let cond_m1 = ZeroizeShareVec(mpc_sub_const(cond, 1)?);
                    let bool_triple = beaver_pool.pop()?;
                    triples_consumed += 1;
                    let cond_check = mpc_mul(cond, &cond_m1.0, bool_triple, &self.cache)?;
                    drop(cond_m1);
                    residuals.0.push(cond_check);

                    // 2. Oblivious branchless select: `if_false + cond * (if_true - if_false)`.
                    let diff = ZeroizeShareVec(mpc_sub(t_val, f_val)?);
                    let sel_triple = beaver_pool.pop()?;
                    triples_consumed += 1;
                    let selected_delta =
                        ZeroizeShareVec(mpc_mul(cond, &diff.0, sel_triple, &self.cache)?);
                    drop(diff);
                    let out = mpc_add(f_val, &selected_delta.0)?;
                    drop(selected_delta);
                    set_reg(&mut regs, *dst, out);
                }
                MpcOp::AssertZero { reg } => {
                    let s = regs.0[*reg as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister {
                            reg: *reg,
                            op_index,
                        },
                    )?;
                    residuals.0.push(s.to_vec());
                }
                MpcOp::AssertBool { reg } => {
                    let s = regs.0[*reg as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister {
                            reg: *reg,
                            op_index,
                        },
                    )?;
                    let s_m1 = ZeroizeShareVec(mpc_sub_const(s, 1)?);
                    let triple = beaver_pool.pop()?;
                    triples_consumed += 1;
                    let check = mpc_mul(s, &s_m1.0, triple, &self.cache)?;
                    drop(s_m1);
                    residuals.0.push(check);
                }
                MpcOp::AssertRangeBits { val_reg, bit_regs } => {
                    let val = regs.0[*val_reg as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister {
                            reg: *val_reg,
                            op_index,
                        },
                    )?;
                    let mut recomposed = ZeroizeShareVec(vec![0u128; n]);
                    for (bit_idx, &b_reg) in bit_regs.iter().enumerate() {
                        let b_shares = regs.0[b_reg as usize].as_deref().ok_or(
                            MpcVmError::UninitializedRegister {
                                reg: b_reg,
                                op_index,
                            },
                        )?;
                        let b_m1 = ZeroizeShareVec(mpc_sub_const(b_shares, 1)?);
                        let triple = beaver_pool.pop()?;
                        triples_consumed += 1;
                        let bit_check = mpc_mul(b_shares, &b_m1.0, triple, &self.cache)?;
                        drop(b_m1);
                        residuals.0.push(bit_check);

                        let weight = 1u128 << bit_idx;
                        for (acc, &share) in recomposed.0.iter_mut().zip(b_shares.iter()) {
                            *acc = add_mod(*acc, mul_mod(share, weight));
                        }
                    }
                    let eq_res = mpc_sub(val, &recomposed.0)?;
                    drop(recomposed);
                    residuals.0.push(eq_res);
                }
                MpcOp::RevealOutput { src } => {
                    let s = regs.0[*src as usize].as_deref().ok_or(
                        MpcVmError::UninitializedRegister {
                            reg: *src,
                            op_index,
                        },
                    )?;
                    staged_reveals.0.push(s.to_vec());
                }
            }
        }

        // Single final blinded `[rho] * [Z]` Schwartz–Zippel RLC across ALL assertions.
        let assertions_checked = residuals.0.len();
        if assertions_checked > 0 {
            let mut gamma = random_nonzero_field_elem();
            let mut power = 1u128;
            let mut z_shares = ZeroizeShareVec(vec![0u128; n]);
            for res_shares in &residuals.0 {
                for (acc, &r) in z_shares.0.iter_mut().zip(res_shares.iter()) {
                    *acc = add_mod(*acc, mul_mod(r, power));
                }
                power = mul_mod(power, gamma);
            }
            zeroize_u128(&mut gamma);
            zeroize_u128(&mut power);

            let mut rho = random_nonzero_field_elem();
            let rho_res = split_secret(rho, t, n);
            zeroize_u128(&mut rho);
            let rho_shares = ZeroizeShareVec(rho_res?);

            let blind_triple = beaver_pool.pop()?;
            triples_consumed += 1;
            let z_blind = ZeroizeShareVec(mpc_mul(
                &rho_shares.0,
                &z_shares.0,
                blind_triple,
                &self.cache,
            )?);
            drop(rho_shares);
            drop(z_shares);

            let mut opened = self.cache.reconstruct_and_verify(&z_blind.0)?;
            drop(z_blind);
            let passed = ct_eq_u128(opened, 0);
            zeroize_u128(&mut opened);

            if !passed {
                // Atomic rollback: `staged_writes`, `staged_reveals`, `regs`, and `residuals`
                // are all volatile-zeroized on drop; contract storage is untouched.
                return Err(MpcVmError::AssertionFailed);
            }
        }

        // Reconstruct explicitly revealed outputs ONLY after all assertions passed.
        let mut revealed_outputs = Vec::with_capacity(staged_reveals.0.len());
        for reveal_shares in &staged_reveals.0 {
            revealed_outputs.push(self.cache.reconstruct_and_verify(reveal_shares)?);
        }

        let fee_vern = contract.cost.fee_vern;
        let state_writes = contract.cost.state_writes;

        // Atomic commit of staged `StoreState` writes.
        let contract_mut = self
            .contracts
            .get_mut(&contract_id)
            .ok_or(MpcVmError::ContractNotFound { contract_id })?;
        let writes_to_commit = std::mem::take(&mut staged_writes.0);
        for (key, new_shares) in writes_to_commit {
            if let Some(mut old_shares) = contract_mut.state.insert(key, new_shares) {
                zeroize_u128_slice(&mut old_shares);
            }
        }

        Ok(CircuitExecutionReceipt {
            contract_id,
            revealed_outputs,
            triples_consumed,
            assertions_checked,
            fee_vern,
            state_writes,
        })
    }

    /// Run a zero-polynomial Proactive Secret Sharing (PSS) epoch refresh across every persistent
    /// confidential storage slot of every deployed contract.
    ///
    /// Preserves all reconstructed secrets identically while rotating every validator share so
    /// shares from prior epochs cannot be combined with shares from the new epoch. Returns the
    /// incremented global `pss_epoch`.
    pub fn proactive_refresh_all_contracts(&mut self) -> Result<u64, MpcVmError> {
        let t = self.cache.threshold();
        let n = self.cache.num_validators();

        let total_slots: usize = self.contracts.values().map(|c| c.state.len()).sum();
        if total_slots > 0 {
            let mut batch = ZeroizeShareMatrix(Vec::with_capacity(total_slots));
            for contract in self.contracts.values() {
                for shares in contract.state.values() {
                    batch.0.push(shares.clone());
                }
            }
            proactive_refresh_epoch_batch(&mut batch.0, t, n)?;

            let mut iter = std::mem::take(&mut batch.0).into_iter();
            for contract in self.contracts.values_mut() {
                for slot_shares in contract.state.values_mut() {
                    if let Some(refreshed) = iter.next() {
                        zeroize_u128_slice(slot_shares);
                        *slot_shares = refreshed;
                    }
                }
            }
        }

        self.pss_epoch = self
            .pss_epoch
            .checked_add(1)
            .ok_or(MpcVmError::ArithmeticOverflow)?;
        for contract in self.contracts.values_mut() {
            contract.pss_epoch = self.pss_epoch;
        }
        Ok(self.pss_epoch)
    }

    /// Reconstruct and Lagrange-verify a contract's confidential storage slot (for testing and
    /// audit verification).
    pub fn reconstruct_contract_state(
        &self,
        contract_id: ContractId,
        key: u16,
    ) -> Result<u128, MpcVmError> {
        let contract = self
            .contracts
            .get(&contract_id)
            .ok_or(MpcVmError::ContractNotFound { contract_id })?;
        let shares = contract
            .state
            .get(&key)
            .ok_or(MpcVmError::StateKeyNotFound { contract_id, key })?;
        Ok(self.cache.reconstruct_and_verify(shares)?)
    }
}

// ============================================================================
// 3. Built-In Standard Confidential Circuit Templates
// ============================================================================

/// Build the standard **Confidential Private Escrow** circuit.
///
/// Storage layout:
/// - Key `0` ([`ESCROW_KEY_AMOUNT`]): locked escrowed amount.
/// - Key `1` ([`ESCROW_KEY_BUYER_BAL`]): buyer confidential balance.
/// - Key `2` ([`ESCROW_KEY_SELLER_BAL`]): seller confidential balance.
/// - Key `3` ([`ESCROW_KEY_SETTLED`]): settlement status (`0` = open, `1` = settled).
///
/// Inputs:
/// - Input `0`: secret-shared `release_flag in {0, 1}` (`1` = release to seller, `0` = refund to buyer).
///
/// Uses oblivious branchless [`MpcOp::Mux`] so neither the branch taken nor the escrowed amount is
/// ever revealed, rejects non-binary forged flags, and blocks replay once settled.
pub fn build_private_escrow_circuit() -> CircuitProgram {
    let mut b = CircuitBuilder::new();
    let amount = b.load_state(ESCROW_KEY_AMOUNT);
    let buyer_bal = b.load_state(ESCROW_KEY_BUYER_BAL);
    let seller_bal = b.load_state(ESCROW_KEY_SELLER_BAL);
    let settled = b.load_state(ESCROW_KEY_SETTLED);

    // Ensure escrow has not already been settled.
    b.assert_zero(settled);

    let release_flag = b.load_input(0);
    let zero = b.load_const(0);
    let one = b.load_const(1);

    // Oblivious branchless settlement:
    //   release_flag == 1 -> seller += amount, buyer unchanged
    //   release_flag == 0 -> buyer  += amount, seller unchanged
    let seller_if_release = b.add(seller_bal, amount);
    let new_seller_bal = b.mux(release_flag, seller_if_release, seller_bal);

    let buyer_if_refund = b.add(buyer_bal, amount);
    let new_buyer_bal = b.mux(release_flag, buyer_bal, buyer_if_refund);

    b.store_state(ESCROW_KEY_AMOUNT, zero)
        .store_state(ESCROW_KEY_BUYER_BAL, new_buyer_bal)
        .store_state(ESCROW_KEY_SELLER_BAL, new_seller_bal)
        .store_state(ESCROW_KEY_SETTLED, one);

    b.build().expect("built-in private escrow circuit is valid")
}

/// Build the standard **Confidential Private Token Transfer** circuit (ERC-20 style) with
/// `bit_width`-bit [`MpcOp::AssertRangeBits`] overdraft protection (`1 <= bit_width <= 64`).
///
/// Storage layout:
/// - Key `0` ([`TOKEN_KEY_SENDER_BAL`]): sender confidential balance.
/// - Key `1` ([`TOKEN_KEY_RECIPIENT_BAL`]): recipient confidential balance.
///
/// Inputs (`1 + 2 * bit_width` total):
/// - Input `0`: secret-shared transfer `amount`.
/// - Inputs `1 .. 1 + bit_width`: secret-shared bits `amount_0 .. amount_{W-1}`.
/// - Inputs `1 + bit_width .. 1 + 2 * bit_width`: secret-shared bits of post-transfer remainder
///   `sender_bal - amount`.
pub fn build_private_token_transfer_circuit(bit_width: usize) -> Result<CircuitProgram, MpcVmError> {
    if bit_width == 0 || bit_width > MAX_RANGE_BITS {
        return Err(MpcVmError::InvalidRangeBitWidth { width: bit_width });
    }

    let mut b = CircuitBuilder::new();
    let sender_bal = b.load_state(TOKEN_KEY_SENDER_BAL);
    let recipient_bal = b.load_state(TOKEN_KEY_RECIPIENT_BAL);

    let amount = b.load_input(0);
    let mut amount_bits = Vec::with_capacity(bit_width);
    for j in 0..bit_width {
        amount_bits.push(b.load_input((1 + j) as u16));
    }
    b.assert_range_bits(amount, amount_bits);

    let new_sender_bal = b.sub(sender_bal, amount);
    let mut rem_bits = Vec::with_capacity(bit_width);
    for j in 0..bit_width {
        rem_bits.push(b.load_input((1 + bit_width + j) as u16));
    }
    b.assert_range_bits(new_sender_bal, rem_bits);

    let new_recipient_bal = b.add(recipient_bal, amount);
    b.store_state(TOKEN_KEY_SENDER_BAL, new_sender_bal)
        .store_state(TOKEN_KEY_RECIPIENT_BAL, new_recipient_bal);

    b.build()
}

/// Bit width used for the non-negative excess `sum(votes) - threshold` in
/// [`build_blind_multisig_threshold_circuit`].
#[inline]
pub fn blind_multisig_excess_bits(num_signers: usize) -> usize {
    if num_signers == 0 {
        1
    } else {
        (usize::BITS - num_signers.leading_zeros()).max(1) as usize
    }
}

/// Build the standard **Blind Multisig Threshold** circuit (`1 <= num_signers <= 120`).
///
/// Verifies `sum(approval_bits) >= threshold` while enforcing every signer vote is binary
/// (`vote_i in {0, 1}`) and revealing ONLY the single approval marker `1` after all constraints
/// pass — hiding WHICH signers approved and by how many votes the threshold was exceeded.
///
/// Storage layout:
/// - Key `0` ([`MULTISIG_KEY_THRESHOLD`]): secret-shared threshold `k`.
/// - Key `1` ([`MULTISIG_KEY_APPROVED_COUNT`]): secret-shared approved execution counter.
///
/// Inputs (`num_signers + blind_multisig_excess_bits(num_signers)` total):
/// - Inputs `0 .. num_signers`: secret-shared signer approval bits `vote_0 .. vote_{N-1}`.
/// - Remaining inputs: secret-shared bit decomposition of `excess = sum(vote_i) - threshold`.
pub fn build_blind_multisig_threshold_circuit(
    num_signers: usize,
) -> Result<CircuitProgram, MpcVmError> {
    if num_signers == 0 || num_signers > 120 {
        return Err(MpcVmError::InvalidTemplateParameter(
            "num_signers must be in 1..=120",
        ));
    }

    let excess_bits = blind_multisig_excess_bits(num_signers);
    let mut b = CircuitBuilder::new();

    let threshold_reg = b.load_state(MULTISIG_KEY_THRESHOLD);
    let exec_count = b.load_state(MULTISIG_KEY_APPROVED_COUNT);

    let mut sum_reg = 0u16;
    for i in 0..num_signers {
        let vote = b.load_input(i as u16);
        b.assert_bool(vote);
        sum_reg = if i == 0 { vote } else { b.add(sum_reg, vote) };
    }

    let excess = b.sub(sum_reg, threshold_reg);
    let mut excess_bit_regs = Vec::with_capacity(excess_bits);
    for j in 0..excess_bits {
        excess_bit_regs.push(b.load_input((num_signers + j) as u16));
    }
    b.assert_range_bits(excess, excess_bit_regs);

    let one = b.load_const(1);
    let new_count = b.add(exec_count, one);
    b.store_state(MULTISIG_KEY_APPROVED_COUNT, new_count)
        .reveal(one);

    b.build()
}

// ============================================================================
// 4. Comprehensive Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn share(val: u128) -> Vec<u128> {
        split_secret(val, DEFAULT_THRESHOLD, DEFAULT_NUM_VALIDATORS).unwrap()
    }

    fn share_bits(val: u128, bit_width: usize) -> Vec<Vec<u128>> {
        (0..bit_width)
            .map(|j| share((val >> j) & 1))
            .collect()
    }

    fn token_transfer_inputs(
        sender_bal: u128,
        amount: u128,
        bit_width: usize,
    ) -> Vec<Vec<u128>> {
        let mut inputs = Vec::with_capacity(1 + 2 * bit_width);
        inputs.push(share(amount));
        inputs.extend(share_bits(amount, bit_width));
        let rem = sender_bal.saturating_sub(amount);
        inputs.extend(share_bits(rem, bit_width));
        inputs
    }

    #[test]
    fn test_private_escrow_circuit_release_and_refund_oblivious_mux() {
        let mut vm = MpcVmEngine::new_3_of_4();
        let program = build_private_escrow_circuit();
        let cost = validate_circuit(&program).unwrap();
        let mut pool = BeaverPool::new_3_of_4(cost.beaver_triples * 4);

        // Scenario A: release_flag = 1 -> seller receives escrowed amount, buyer unchanged.
        let mut init_release = BTreeMap::new();
        init_release.insert(ESCROW_KEY_AMOUNT, share(500));
        init_release.insert(ESCROW_KEY_BUYER_BAL, share(1_000));
        init_release.insert(ESCROW_KEY_SELLER_BAL, share(250));
        init_release.insert(ESCROW_KEY_SETTLED, share(0));
        let release_id = vm.deploy_contract(program.clone(), init_release).unwrap();

        let receipt = vm
            .execute_contract(release_id, &[share(1)], &mut pool)
            .unwrap();
        assert_eq!(receipt.contract_id, release_id);
        assert!(receipt.revealed_outputs.is_empty());
        assert_eq!(receipt.triples_consumed, cost.beaver_triples);
        assert_eq!(receipt.assertions_checked, cost.assertions);
        assert_eq!(receipt.state_writes, 4);
        assert_eq!(receipt.fee_vern, cost.fee_vern);

        assert_eq!(
            vm.reconstruct_contract_state(release_id, ESCROW_KEY_AMOUNT)
                .unwrap(),
            0
        );
        assert_eq!(
            vm.reconstruct_contract_state(release_id, ESCROW_KEY_BUYER_BAL)
                .unwrap(),
            1_000
        );
        assert_eq!(
            vm.reconstruct_contract_state(release_id, ESCROW_KEY_SELLER_BAL)
                .unwrap(),
            750
        );
        assert_eq!(
            vm.reconstruct_contract_state(release_id, ESCROW_KEY_SETTLED)
                .unwrap(),
            1
        );

        // Replay attempt after settlement MUST fail AssertZero(settled) and roll back atomically.
        let replay_err = vm
            .execute_contract(release_id, &[share(0)], &mut pool)
            .unwrap_err();
        assert_eq!(replay_err, MpcVmError::AssertionFailed);
        assert_eq!(
            vm.reconstruct_contract_state(release_id, ESCROW_KEY_BUYER_BAL)
                .unwrap(),
            1_000
        );
        assert_eq!(
            vm.reconstruct_contract_state(release_id, ESCROW_KEY_SELLER_BAL)
                .unwrap(),
            750
        );

        // Scenario B: release_flag = 0 -> buyer refunded escrowed amount, seller unchanged.
        let mut init_refund = BTreeMap::new();
        init_refund.insert(ESCROW_KEY_AMOUNT, share(420));
        init_refund.insert(ESCROW_KEY_BUYER_BAL, share(800));
        init_refund.insert(ESCROW_KEY_SELLER_BAL, share(300));
        init_refund.insert(ESCROW_KEY_SETTLED, share(0));
        let refund_id = vm.deploy_contract(program, init_refund).unwrap();

        let refund_receipt = vm
            .execute_contract(refund_id, &[share(0)], &mut pool)
            .unwrap();
        assert!(refund_receipt.revealed_outputs.is_empty());
        assert_eq!(refund_receipt.triples_consumed, cost.beaver_triples);
        assert_eq!(
            vm.reconstruct_contract_state(refund_id, ESCROW_KEY_AMOUNT)
                .unwrap(),
            0
        );
        assert_eq!(
            vm.reconstruct_contract_state(refund_id, ESCROW_KEY_BUYER_BAL)
                .unwrap(),
            1_220
        );
        assert_eq!(
            vm.reconstruct_contract_state(refund_id, ESCROW_KEY_SELLER_BAL)
                .unwrap(),
            300
        );
        assert_eq!(
            vm.reconstruct_contract_state(refund_id, ESCROW_KEY_SETTLED)
                .unwrap(),
            1
        );
    }

    #[test]
    fn test_private_token_transfer_and_overdraft_atomic_rollback() {
        let bit_width = 16;
        let program = build_private_token_transfer_circuit(bit_width).unwrap();
        let cost = validate_circuit(&program).unwrap();

        let mut vm = MpcVmEngine::new_3_of_4();
        let mut init_state = BTreeMap::new();
        init_state.insert(TOKEN_KEY_SENDER_BAL, share(1_000));
        init_state.insert(TOKEN_KEY_RECIPIENT_BAL, share(250));
        let cid = vm.deploy_contract(program, init_state).unwrap();

        let mut pool = BeaverPool::new_3_of_4(cost.beaver_triples * 4);

        // 1. Valid confidential transfer of 375.
        let inputs = token_transfer_inputs(1_000, 375, bit_width);
        let receipt = vm.execute_contract(cid, &inputs, &mut pool).unwrap();
        assert_eq!(receipt.triples_consumed, cost.beaver_triples);
        assert_eq!(receipt.state_writes, 2);
        assert_eq!(
            vm.reconstruct_contract_state(cid, TOKEN_KEY_SENDER_BAL)
                .unwrap(),
            625
        );
        assert_eq!(
            vm.reconstruct_contract_state(cid, TOKEN_KEY_RECIPIENT_BAL)
                .unwrap(),
            625
        );

        // Snapshot raw validator shares before overdraft attempt to verify 100% atomic rollback.
        let sender_shares_before = vm
            .contract(cid)
            .unwrap()
            .state_shares(TOKEN_KEY_SENDER_BAL)
            .unwrap()
            .to_vec();
        let recip_shares_before = vm
            .contract(cid)
            .unwrap()
            .state_shares(TOKEN_KEY_RECIPIENT_BAL)
            .unwrap()
            .to_vec();

        // 2. Overdraft attempt (700 > 625) must fail blinded RLC and leave storage untouched.
        let overdraft_inputs = token_transfer_inputs(625, 700, bit_width);
        let err = vm
            .execute_contract(cid, &overdraft_inputs, &mut pool)
            .unwrap_err();
        assert_eq!(err, MpcVmError::AssertionFailed);
        assert_eq!(
            vm.contract(cid)
                .unwrap()
                .state_shares(TOKEN_KEY_SENDER_BAL)
                .unwrap(),
            sender_shares_before.as_slice()
        );
        assert_eq!(
            vm.contract(cid)
                .unwrap()
                .state_shares(TOKEN_KEY_RECIPIENT_BAL)
                .unwrap(),
            recip_shares_before.as_slice()
        );
        assert_eq!(
            vm.reconstruct_contract_state(cid, TOKEN_KEY_SENDER_BAL)
                .unwrap(),
            625
        );
        assert_eq!(
            vm.reconstruct_contract_state(cid, TOKEN_KEY_RECIPIENT_BAL)
                .unwrap(),
            625
        );

        // 3. Forged non-binary bit (bit_0 = 2) with matching recomposed sum must still fail!
        let mut forged_inputs = token_transfer_inputs(625, 2, bit_width);
        forged_inputs[1] = share(2); // bit 0 forged as 2
        forged_inputs[2] = share(0); // bit 1 forged as 0 -> sum is still 2, but bit_0 not bool!
        let err = vm
            .execute_contract(cid, &forged_inputs, &mut pool)
            .unwrap_err();
        assert_eq!(err, MpcVmError::AssertionFailed);
        assert_eq!(
            vm.reconstruct_contract_state(cid, TOKEN_KEY_SENDER_BAL)
                .unwrap(),
            625
        );
    }

    #[test]
    fn test_blind_multisig_threshold_hides_which_signers_approved() {
        let num_signers = 5;
        let threshold_k = 3u128;
        let excess_bits = blind_multisig_excess_bits(num_signers);
        let program = build_blind_multisig_threshold_circuit(num_signers).unwrap();
        let cost = validate_circuit(&program).unwrap();

        let mut vm = MpcVmEngine::new_3_of_4();
        let mut init_state = BTreeMap::new();
        init_state.insert(MULTISIG_KEY_THRESHOLD, share(threshold_k));
        init_state.insert(MULTISIG_KEY_APPROVED_COUNT, share(0));
        let cid = vm.deploy_contract(program, init_state).unwrap();

        let mut pool = BeaverPool::new_3_of_4(cost.beaver_triples * 6);

        let build_votes = |votes: &[u128], claimed_excess: u128| -> Vec<Vec<u128>> {
            let mut inputs: Vec<Vec<u128>> = votes.iter().map(|&v| share(v)).collect();
            inputs.extend(share_bits(claimed_excess, excess_bits));
            inputs
        };

        // Subset 1: signers {0, 2, 4} approve (exact threshold 3/5, excess = 0).
        let r1 = vm
            .execute_contract(cid, &build_votes(&[1, 0, 1, 0, 1], 0), &mut pool)
            .unwrap();
        // Subset 2: signers {1, 2, 3, 4} approve (4/5, excess = 1).
        let r2 = vm
            .execute_contract(cid, &build_votes(&[0, 1, 1, 1, 1], 1), &mut pool)
            .unwrap();

        // Both receipts are 100% identical in revealed outputs, triples, assertions, and fee:
        // zero leakage of WHICH signers voted or the margin above threshold!
        assert_eq!(r1.revealed_outputs, vec![1]);
        assert_eq!(r2.revealed_outputs, vec![1]);
        assert_eq!(r1.triples_consumed, r2.triples_consumed);
        assert_eq!(r1.assertions_checked, r2.assertions_checked);
        assert_eq!(r1.fee_vern, r2.fee_vern);
        assert_eq!(
            vm.reconstruct_contract_state(cid, MULTISIG_KEY_APPROVED_COUNT)
                .unwrap(),
            2
        );

        // Below threshold (2/5 approvals) -> rejected & atomic rollback.
        let err_low = vm
            .execute_contract(cid, &build_votes(&[1, 1, 0, 0, 0], 0), &mut pool)
            .unwrap_err();
        assert_eq!(err_low, MpcVmError::AssertionFailed);
        assert_eq!(
            vm.reconstruct_contract_state(cid, MULTISIG_KEY_APPROVED_COUNT)
                .unwrap(),
            2
        );

        // Forged weighted vote (signer 0 votes `2` + signer 1 votes `1` = 3) -> fails AssertBool!
        let err_forged = vm
            .execute_contract(cid, &build_votes(&[2, 1, 0, 0, 0], 0), &mut pool)
            .unwrap_err();
        assert_eq!(err_forged, MpcVmError::AssertionFailed);
        assert_eq!(
            vm.reconstruct_contract_state(cid, MULTISIG_KEY_APPROVED_COUNT)
                .unwrap(),
            2
        );
    }

    #[test]
    fn test_forged_mux_non_binary_cond_and_uninitialized_reg_rejected() {
        // 1. Forged non-binary condition bit in Mux MUST fail RLC and leak zero outputs.
        let mut b = CircuitBuilder::new();
        let cond = b.load_input(0);
        let a = b.load_const(100);
        let c = b.load_const(200);
        let chosen = b.mux(cond, a, c);
        b.store_state(0, chosen).reveal(chosen);
        let mux_prog = b.build().unwrap();
        let cost = validate_circuit(&mux_prog).unwrap();

        let mut vm = MpcVmEngine::new_3_of_4();
        let mut init_state = BTreeMap::new();
        init_state.insert(0, share(999));
        let cid = vm.deploy_contract(mux_prog, init_state).unwrap();
        let mut pool = BeaverPool::new_3_of_4(cost.beaver_triples * 3);

        // Forged cond = 2 and cond = PRIME_P - 1 both rejected with atomic rollback.
        assert_eq!(
            vm.execute_contract(cid, &[share(2)], &mut pool),
            Err(MpcVmError::AssertionFailed)
        );
        assert_eq!(
            vm.execute_contract(cid, &[share(PRIME_P - 1)], &mut pool),
            Err(MpcVmError::AssertionFailed)
        );
        assert_eq!(vm.reconstruct_contract_state(cid, 0).unwrap(), 999);

        // Honest cond = 1 succeeds and reveals 100.
        let ok_receipt = vm.execute_contract(cid, &[share(1)], &mut pool).unwrap();
        assert_eq!(ok_receipt.revealed_outputs, vec![100]);
        assert_eq!(vm.reconstruct_contract_state(cid, 0).unwrap(), 100);

        // 2. Static validation rejects uninitialized register reads (read-before-write).
        let uninit_prog = CircuitProgram {
            num_regs: 3,
            num_inputs: 1,
            ops: vec![
                MpcOp::LoadInput {
                    dst: 0,
                    input_idx: 0,
                },
                MpcOp::Add { dst: 2, a: 0, b: 1 }, // r1 was never written!
            ],
        };
        assert_eq!(
            validate_circuit(&uninit_prog),
            Err(MpcVmError::UninitializedRegister {
                reg: 1,
                op_index: 1
            })
        );

        // Self-reading an uninitialized register in the same instruction is also rejected.
        let self_uninit = CircuitProgram {
            num_regs: 1,
            num_inputs: 0,
            ops: vec![MpcOp::Add { dst: 0, a: 0, b: 0 }],
        };
        assert_eq!(
            validate_circuit(&self_uninit),
            Err(MpcVmError::UninitializedRegister {
                reg: 0,
                op_index: 0
            })
        );

        // 3. Static validation rejects non-canonical constants >= PRIME_P & out-of-bounds keys.
        let bad_const = CircuitProgram {
            num_regs: 1,
            num_inputs: 0,
            ops: vec![MpcOp::LoadConst {
                dst: 0,
                value: PRIME_P,
            }],
        };
        assert_eq!(
            validate_circuit(&bad_const),
            Err(MpcVmError::NonCanonicalConstant { value: PRIME_P })
        );

        // 4. Deploy rejects degree-inconsistent initial state shares.
        let mut tampered_shares = share(42);
        tampered_shares[3] = add_mod(tampered_shares[3], 1);
        let mut bad_state = BTreeMap::new();
        bad_state.insert(0, tampered_shares);
        let simple_prog = {
            let mut sb = CircuitBuilder::new();
            let v = sb.load_state(0);
            sb.reveal(v);
            sb.build().unwrap()
        };
        assert_eq!(
            vm.deploy_contract(simple_prog, bad_state),
            Err(MpcVmError::Mpc(MpcError::InconsistentShares))
        );
    }

    #[test]
    fn test_contract_storage_pss_epoch_refresh_rotates_all_shares_preserving_state() {
        let mut vm = MpcVmEngine::new_3_of_4();

        // Deploy two distinct contracts with multiple confidential storage slots.
        let escrow_prog = build_private_escrow_circuit();
        let mut escrow_state = BTreeMap::new();
        escrow_state.insert(ESCROW_KEY_AMOUNT, share(777));
        escrow_state.insert(ESCROW_KEY_BUYER_BAL, share(2_000));
        escrow_state.insert(ESCROW_KEY_SELLER_BAL, share(1_500));
        escrow_state.insert(ESCROW_KEY_SETTLED, share(0));
        let escrow_id = vm.deploy_contract(escrow_prog, escrow_state).unwrap();

        let token_prog = build_private_token_transfer_circuit(16).unwrap();
        let mut token_state = BTreeMap::new();
        token_state.insert(TOKEN_KEY_SENDER_BAL, share(9_999));
        token_state.insert(TOKEN_KEY_RECIPIENT_BAL, share(123));
        let token_id = vm.deploy_contract(token_prog, token_state).unwrap();

        // Capture epoch-1 raw shares for every slot.
        let old_escrow_amt = vm
            .contract(escrow_id)
            .unwrap()
            .state_shares(ESCROW_KEY_AMOUNT)
            .unwrap()
            .to_vec();
        let old_token_sender = vm
            .contract(token_id)
            .unwrap()
            .state_shares(TOKEN_KEY_SENDER_BAL)
            .unwrap()
            .to_vec();

        // Run Proactive Secret Sharing epoch refresh.
        let new_epoch = vm.proactive_refresh_all_contracts().unwrap();
        assert_eq!(new_epoch, 2);
        assert_eq!(vm.pss_epoch(), 2);
        assert_eq!(vm.contract(escrow_id).unwrap().pss_epoch(), 2);
        assert_eq!(vm.contract(token_id).unwrap().pss_epoch(), 2);

        // Raw shares MUST have rotated.
        let new_escrow_amt = vm
            .contract(escrow_id)
            .unwrap()
            .state_shares(ESCROW_KEY_AMOUNT)
            .unwrap();
        let new_token_sender = vm
            .contract(token_id)
            .unwrap()
            .state_shares(TOKEN_KEY_SENDER_BAL)
            .unwrap();
        assert_ne!(old_escrow_amt.as_slice(), new_escrow_amt);
        assert_ne!(old_token_sender.as_slice(), new_token_sender);

        // Mixing an epoch-1 share with epoch-2 shares MUST fail Lagrange consistency check.
        let mut mixed = new_escrow_amt.to_vec();
        mixed[0] = old_escrow_amt[0];
        assert_eq!(
            vm.cache().verify_shares(&mixed),
            Err(MpcError::InconsistentShares)
        );

        // Reconstructed confidential state across all contracts MUST be preserved identically.
        assert_eq!(
            vm.reconstruct_contract_state(escrow_id, ESCROW_KEY_AMOUNT)
                .unwrap(),
            777
        );
        assert_eq!(
            vm.reconstruct_contract_state(escrow_id, ESCROW_KEY_BUYER_BAL)
                .unwrap(),
            2_000
        );
        assert_eq!(
            vm.reconstruct_contract_state(escrow_id, ESCROW_KEY_SELLER_BAL)
                .unwrap(),
            1_500
        );
        assert_eq!(
            vm.reconstruct_contract_state(token_id, TOKEN_KEY_SENDER_BAL)
                .unwrap(),
            9_999
        );
        assert_eq!(
            vm.reconstruct_contract_state(token_id, TOKEN_KEY_RECIPIENT_BAL)
                .unwrap(),
            123
        );

        // Executing contracts AFTER PSS refresh must continue to work seamlessly.
        let escrow_cost = vm.contract(escrow_id).unwrap().cost();
        let mut pool = BeaverPool::new_3_of_4(escrow_cost.beaver_triples);
        vm.execute_contract(escrow_id, &[share(1)], &mut pool)
            .unwrap();
        assert_eq!(
            vm.reconstruct_contract_state(escrow_id, ESCROW_KEY_SELLER_BAL)
                .unwrap(),
            2_277
        );
    }
}
