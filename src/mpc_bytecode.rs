//! Vernam Circuit Assembly (`.vca`) Compiler & Carter-Wegman Authenticated Binary Bytecode Codec.
//!
//! Pure information-theoretic cryptography over the Mersenne prime field `F_(2^127 - 1)` from
//! `crate::field`. Zero external crates, zero computational cryptography (no SHA-256, RSA,
//! ECDSA, or AES).
//!
//! # Security & Validation Properties
//! - **Non-Turing-Complete Static DAG**: 14 straight-line arithmetic & assertion opcodes with
//!   no jumps, loops, or recursion; execution time and Beaver-triple cost are statically bounded.
//! - **Compile-Time & Decode-Time Safety**: Enforces `MAX_REGS = 256`, `MAX_OPS = 2_048`,
//!   `MAX_BYTECODE_BYTES = 65_536`, initialized-before-read register dataflow, canonical field
//!   constants `< PRIME_P`, and valid `AssertRangeBits` bit widths (`1..=126`).
//! - **Information-Theoretic Integrity**: Binary wire format (`VRNMCC01`) is authenticated by a
//!   prefix-collision-free 128-bit Carter-Wegman universal polynomial MAC over `F_(2^127 - 1)`
//!   verified in constant time (`ct_eq_16`) **before** any bytecode header or instruction parsing.
//! - **Key Hygiene**: `BytecodeMacKey` implements redacted `Debug` and volatile-zeroized `Drop`.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use crate::field::{
    PRIME_P, add_mod, ct_eq_16, mul_mod, random_field_elem, reduce, zeroize_slice, zeroize_u128,
};

/// Maximum number of virtual registers (`r0..=r255`).
pub const MAX_REGS: usize = 256;

/// Maximum number of instructions permitted in a single compiled circuit.
pub const MAX_OPS: usize = 2_048;

/// Maximum serialized authenticated bytecode payload size in bytes.
pub const MAX_BYTECODE_BYTES: usize = 65_536;

/// Maximum bit width for `AssertRangeBits` (`2^126 < PRIME_P = 2^127 - 1`).
pub const MAX_RANGE_BITS: u8 = 126;

/// Wire magic prefix for Vernam Circuit Code v1 (`VRNMCC01`).
pub const BYTECODE_MAGIC: &[u8; 8] = b"VRNMCC01";

/// Current wire format version.
pub const BYTECODE_VERSION: u16 = 1;

/// Length of the 128-bit Carter-Wegman MAC trailer in bytes.
pub const MAC_TAG_BYTES: usize = 16;

/// Fixed wire header length: 8-byte magic + 2-byte version + 2-byte op count.
const HEADER_BYTES: usize = 8 + 2 + 2;

/// Domain separator in `F_(2^127 - 1)` for bytecode CW-MAC polynomial hashing (`"VRNMCC01"`).
const DOMAIN_BYTECODE_MAC: u128 = 0x5652_4E4D_4343_3031;

/// Default base fee (in `vern`) for executing a confidential circuit.
pub const DEFAULT_CIRCUIT_BASE_FEE_VERN: u64 = 10_000;

/// Default metering fee (in `vern`) per bytecode instruction.
pub const DEFAULT_PER_OP_FEE_VERN: u64 = 100;

/// Default fee (in `vern`) per consumed Beaver multiplication triple.
pub const DEFAULT_TRIPLE_FEE_VERN: u64 = 5_000;

/// Default fee (in `vern`) per consumed Beaver squaring tuple.
pub const DEFAULT_SQUARE_FEE_VERN: u64 = 2_500;

/// Default fee (in `vern`) per confidential state slot write (`StoreState`).
pub const DEFAULT_STATE_WRITE_FEE_VERN: u64 = 10_000;

// Wire opcode tags (14 non-Turing-complete opcodes).
const TAG_LOAD_STATE: u8 = 0x01;
const TAG_STORE_STATE: u8 = 0x02;
const TAG_LOAD_INPUT: u8 = 0x03;
const TAG_LOAD_CONST: u8 = 0x04;
const TAG_ADD: u8 = 0x05;
const TAG_SUB: u8 = 0x06;
const TAG_MUL_CONST: u8 = 0x07;
const TAG_MUL: u8 = 0x08;
const TAG_SQUARE: u8 = 0x09;
const TAG_MUX: u8 = 0x0A;
const TAG_ASSERT_ZERO: u8 = 0x0B;
const TAG_ASSERT_BOOL: u8 = 0x0C;
const TAG_ASSERT_RANGE_BITS: u8 = 0x0D;
const TAG_REVEAL_OUTPUT: u8 = 0x0E;

/// Errors produced by `.vca` compilation, static validation, or binary codec operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BytecodeError {
    /// Lexical or syntax error in `.vca` assembly source at a 1-based line number.
    ParseError { line: usize, msg: String },
    /// Field constant is `>= PRIME_P` (non-canonical in `F_(2^127 - 1)`).
    NonCanonicalConstant { line: Option<usize>, value: u128 },
    /// Instruction reads from a register that has not been initialized by any earlier instruction.
    UninitializedRegister { op_index: usize, reg: u8 },
    /// Invalid `AssertRangeBits` register range (`bit_start > bit_end` or width `> MAX_RANGE_BITS`).
    InvalidBitRange {
        op_index: usize,
        bit_start: u8,
        bit_end: u8,
    },
    /// Instruction count exceeds `MAX_OPS`.
    TooManyOps { count: usize, max: usize },
    /// Serialized bytecode exceeds `MAX_BYTECODE_BYTES`.
    BytecodeTooLarge { len: usize, max: usize },
    /// Wire header does not start with `VRNMCC01`.
    InvalidMagic,
    /// Wire header specifies an unsupported version.
    UnsupportedVersion(u16),
    /// Constant-time 128-bit Carter-Wegman MAC verification failed.
    MacVerificationFailed,
    /// Truncated wire buffer.
    UnexpectedEof,
    /// Unknown opcode tag byte in wire stream.
    UnknownOpcode { op_index: usize, tag: u8 },
    /// Unconsumed trailing bytes present after the declared instruction stream.
    TrailingBytes { remaining: usize },
}

impl fmt::Display for BytecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BytecodeError::ParseError { line, msg } => {
                write!(f, "VCA parse error at line {line}: {msg}")
            }
            BytecodeError::NonCanonicalConstant {
                line: Some(line),
                value,
            } => write!(
                f,
                "non-canonical field constant {value} (>= PRIME_P) at line {line}"
            ),
            BytecodeError::NonCanonicalConstant { line: None, value } => {
                write!(f, "non-canonical field constant {value} (>= PRIME_P)")
            }
            BytecodeError::UninitializedRegister { op_index, reg } => {
                write!(
                    f,
                    "uninitialized register r{reg} read at instruction {op_index}"
                )
            }
            BytecodeError::InvalidBitRange {
                op_index,
                bit_start,
                bit_end,
            } => write!(
                f,
                "invalid bit range r{bit_start}..r{bit_end} at instruction {op_index}"
            ),
            BytecodeError::TooManyOps { count, max } => {
                write!(f, "circuit has {count} ops, exceeding maximum {max}")
            }
            BytecodeError::BytecodeTooLarge { len, max } => {
                write!(
                    f,
                    "bytecode length {len} bytes exceeds maximum {max} bytes"
                )
            }
            BytecodeError::InvalidMagic => write!(f, "invalid bytecode magic (expected VRNMCC01)"),
            BytecodeError::UnsupportedVersion(v) => {
                write!(f, "unsupported bytecode format version {v}")
            }
            BytecodeError::MacVerificationFailed => {
                write!(f, "Carter-Wegman bytecode MAC verification failed")
            }
            BytecodeError::UnexpectedEof => write!(f, "unexpected end of bytecode stream"),
            BytecodeError::UnknownOpcode { op_index, tag } => {
                write!(
                    f,
                    "unknown bytecode opcode 0x{tag:02x} at instruction {op_index}"
                )
            }
            BytecodeError::TrailingBytes { remaining } => {
                write!(
                    f,
                    "rejected {remaining} unexpected trailing bytes in bytecode"
                )
            }
        }
    }
}

impl Error for BytecodeError {}

/// One-time 128-bit Carter-Wegman MAC key `(r, s)` over `F_(2^127 - 1)` for bytecode packets.
///
/// Redacts secret key material in `Debug` and volatile-zeroizes both scalars on `Drop`.
pub struct BytecodeMacKey {
    r: u128,
    s: u128,
}

impl BytecodeMacKey {
    /// Generate a fresh uniform random key `(r, s)` in `F_(2^127 - 1)` from OS entropy.
    pub fn generate() -> Self {
        Self {
            r: random_field_elem(),
            s: random_field_elem(),
        }
    }

    /// Construct a key from raw scalars, canonically reducing both into `[0, PRIME_P)`.
    pub const fn from_raw(r: u128, s: u128) -> Self {
        Self {
            r: reduce(r),
            s: reduce(s),
        }
    }

    /// Compute a prefix-collision-free 128-bit Carter-Wegman MAC over `payload`.
    ///
    /// Polynomial construction over `F_(2^127 - 1)`:
    /// 1. Seed accumulator with domain separator `DOMAIN_BYTECODE_MAC * r`.
    /// 2. Split `payload` into 15-byte chunks; append a `0x01` sentinel byte at `chunk.len()`
    ///    so every chunk maps injectively into `[1, 2^121) < PRIME_P`.
    /// 3. Fold an explicit tagged byte-length block `(payload.len() | 2^120) < PRIME_P` to
    ///    prevent any prefix or extension collisions.
    /// 4. Mask with one-time scalar `s`: `tag = (acc + s) mod PRIME_P`.
    pub fn compute_tag(&self, payload: &[u8]) -> [u8; MAC_TAG_BYTES] {
        let r = self.r;
        let s = self.s;

        let mut acc = mul_mod(DOMAIN_BYTECODE_MAC, r);
        let mut buf = [0u8; 16];

        for chunk in payload.chunks(15) {
            buf = [0u8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            buf[chunk.len()] = 0x01;
            let block = u128::from_le_bytes(buf);
            acc = mul_mod(add_mod(acc, block), r);
        }

        // Explicit length-tagged final block guarantees strict prefix-collision freedom.
        let len_block = (payload.len() as u128) | (1u128 << 120);
        acc = mul_mod(add_mod(acc, len_block), r);

        let tag_val = add_mod(acc, s);
        zeroize_slice(&mut buf);
        zeroize_u128(&mut acc);
        debug_assert!(tag_val < PRIME_P);
        tag_val.to_be_bytes()
    }

    /// Verify a 128-bit CW-MAC tag in constant time via `crate::field::ct_eq_16`.
    pub fn verify_tag(&self, payload: &[u8], tag: &[u8; MAC_TAG_BYTES]) -> bool {
        let mut expected = self.compute_tag(payload);
        let ok = ct_eq_16(&expected, tag);
        zeroize_slice(&mut expected);
        ok
    }
}

impl fmt::Debug for BytecodeMacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BytecodeMacKey")
            .field("r", &"<REDACTED>")
            .field("s", &"<REDACTED>")
            .finish()
    }
}

impl Drop for BytecodeMacKey {
    fn drop(&mut self) {
        zeroize_u128(&mut self.r);
        zeroize_u128(&mut self.s);
    }
}

/// The 14 non-Turing-complete confidential arithmetic circuit opcodes over `F_(2^127 - 1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytecodeOp {
    /// Load secret-shared persistent state slot into `dst`: `LOAD_STATE r<dst>, <slot>`.
    LoadState { dst: u8, slot: u32 },
    /// Store secret-shared register `src` into persistent state slot: `STORE_STATE <slot>, r<src>`.
    StoreState { slot: u32, src: u8 },
    /// Load secret-shared private input at `index` into `dst`: `LOAD_IN r<dst>, <index>`.
    LoadInput { dst: u8, index: u16 },
    /// Load canonical public field constant (`< PRIME_P`) into `dst`: `LOAD_CONST r<dst>, <value>`.
    LoadConst { dst: u8, value: u128 },
    /// Secret addition `dst = lhs + rhs (mod p)`: `ADD r<dst>, r<lhs>, r<rhs>`.
    Add { dst: u8, lhs: u8, rhs: u8 },
    /// Secret subtraction `dst = lhs - rhs (mod p)`: `SUB r<dst>, r<lhs>, r<rhs>`.
    Sub { dst: u8, lhs: u8, rhs: u8 },
    /// Public scalar multiply `dst = src * constant (mod p)`: `MUL_CONST r<dst>, r<src>, <c>`.
    MulConst { dst: u8, src: u8, constant: u128 },
    /// Secret-secret multiply `dst = lhs * rhs (mod p)` (1 Beaver triple): `MUL r<dst>, r<lhs>, r<rhs>`.
    Mul { dst: u8, lhs: u8, rhs: u8 },
    /// Secret squaring `dst = src^2 (mod p)` (1 Beaver square): `SQUARE r<dst>, r<src>`.
    Square { dst: u8, src: u8 },
    /// Oblivious multiplexer `dst = when_false + cond * (when_true - when_false)` (1 Beaver triple):
    /// `MUX r<dst>, r<cond>, r<when_true>, r<when_false>`.
    Mux {
        dst: u8,
        cond: u8,
        when_true: u8,
        when_false: u8,
    },
    /// Assert secret register equals `0 (mod p)`: `ASSERT_ZERO r<src>`.
    AssertZero { src: u8 },
    /// Assert secret register is boolean `src * (src - 1) == 0` (1 Beaver square): `ASSERT_BOOL r<src>`.
    AssertBool { src: u8 },
    /// Assert `src == sum_{i=0}^{k-1} r_{bit_start+i} * 2^i` with all bit registers boolean
    /// (`k = bit_end - bit_start + 1` Beaver squares): `ASSERT_RANGE r<src>, r<bit_start>..r<bit_end>`.
    AssertRangeBits {
        src: u8,
        bit_start: u8,
        bit_end: u8,
    },
    /// Open and emit `src` as a public circuit output: `REVEAL r<src>`.
    RevealOutput { src: u8 },
}

/// Statically validated, portable confidential arithmetic circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCircuit {
    /// Ordered sequence of validated instructions.
    pub ops: Vec<BytecodeOp>,
    /// Count of distinct registers referenced by the circuit (`0..=256`).
    pub num_regs_used: u16,
    /// Count of distinct private input indices loaded.
    pub num_inputs: u16,
    /// Count of distinct persistent state slots accessed (read or written).
    pub num_state_slots: u32,
    /// Number of `RevealOutput` instructions.
    pub num_outputs: u16,
}

impl CompiledCircuit {
    /// Validate a sequence of `BytecodeOp`s as a static acyclic register DAG and compute metadata.
    pub fn from_ops(ops: Vec<BytecodeOp>) -> Result<Self, BytecodeError> {
        if ops.len() > MAX_OPS {
            return Err(BytecodeError::TooManyOps {
                count: ops.len(),
                max: MAX_OPS,
            });
        }

        let mut initialized = [false; MAX_REGS];
        let mut touched = [false; MAX_REGS];
        let mut input_indices = BTreeSet::<u16>::new();
        let mut state_slots = BTreeSet::<u32>::new();
        let mut num_outputs: u16 = 0;

        for (op_index, &op) in ops.iter().enumerate() {
            match op {
                BytecodeOp::LoadState { dst, slot } => {
                    state_slots.insert(slot);
                    initialized[dst as usize] = true;
                    touched[dst as usize] = true;
                }
                BytecodeOp::StoreState { slot, src } => {
                    require_init(&initialized, op_index, src)?;
                    state_slots.insert(slot);
                    touched[src as usize] = true;
                }
                BytecodeOp::LoadInput { dst, index } => {
                    input_indices.insert(index);
                    initialized[dst as usize] = true;
                    touched[dst as usize] = true;
                }
                BytecodeOp::LoadConst { dst, value } => {
                    if value >= PRIME_P {
                        return Err(BytecodeError::NonCanonicalConstant { line: None, value });
                    }
                    initialized[dst as usize] = true;
                    touched[dst as usize] = true;
                }
                BytecodeOp::Add { dst, lhs, rhs } | BytecodeOp::Sub { dst, lhs, rhs } => {
                    require_init(&initialized, op_index, lhs)?;
                    require_init(&initialized, op_index, rhs)?;
                    initialized[dst as usize] = true;
                    touched[lhs as usize] = true;
                    touched[rhs as usize] = true;
                    touched[dst as usize] = true;
                }
                BytecodeOp::MulConst { dst, src, constant } => {
                    if constant >= PRIME_P {
                        return Err(BytecodeError::NonCanonicalConstant {
                            line: None,
                            value: constant,
                        });
                    }
                    require_init(&initialized, op_index, src)?;
                    initialized[dst as usize] = true;
                    touched[src as usize] = true;
                    touched[dst as usize] = true;
                }
                BytecodeOp::Mul { dst, lhs, rhs } => {
                    require_init(&initialized, op_index, lhs)?;
                    require_init(&initialized, op_index, rhs)?;
                    initialized[dst as usize] = true;
                    touched[lhs as usize] = true;
                    touched[rhs as usize] = true;
                    touched[dst as usize] = true;
                }
                BytecodeOp::Square { dst, src } => {
                    require_init(&initialized, op_index, src)?;
                    initialized[dst as usize] = true;
                    touched[src as usize] = true;
                    touched[dst as usize] = true;
                }
                BytecodeOp::Mux {
                    dst,
                    cond,
                    when_true,
                    when_false,
                } => {
                    require_init(&initialized, op_index, cond)?;
                    require_init(&initialized, op_index, when_true)?;
                    require_init(&initialized, op_index, when_false)?;
                    initialized[dst as usize] = true;
                    touched[cond as usize] = true;
                    touched[when_true as usize] = true;
                    touched[when_false as usize] = true;
                    touched[dst as usize] = true;
                }
                BytecodeOp::AssertZero { src } | BytecodeOp::AssertBool { src } => {
                    require_init(&initialized, op_index, src)?;
                    touched[src as usize] = true;
                }
                BytecodeOp::AssertRangeBits {
                    src,
                    bit_start,
                    bit_end,
                } => {
                    if bit_start > bit_end {
                        return Err(BytecodeError::InvalidBitRange {
                            op_index,
                            bit_start,
                            bit_end,
                        });
                    }
                    let bit_count = (bit_end as u16) - (bit_start as u16) + 1;
                    if bit_count > MAX_RANGE_BITS as u16 {
                        return Err(BytecodeError::InvalidBitRange {
                            op_index,
                            bit_start,
                            bit_end,
                        });
                    }
                    require_init(&initialized, op_index, src)?;
                    touched[src as usize] = true;
                    for reg in bit_start..=bit_end {
                        require_init(&initialized, op_index, reg)?;
                        touched[reg as usize] = true;
                    }
                }
                BytecodeOp::RevealOutput { src } => {
                    require_init(&initialized, op_index, src)?;
                    touched[src as usize] = true;
                    num_outputs = num_outputs.saturating_add(1);
                }
            }
        }

        let num_regs_used = touched.iter().filter(|&&b| b).count() as u16;
        let num_inputs = input_indices.len() as u16;
        let num_state_slots = state_slots.len() as u32;

        Ok(Self {
            ops,
            num_regs_used,
            num_inputs,
            num_state_slots,
            num_outputs,
        })
    }
}

#[inline]
fn require_init(initialized: &[bool; MAX_REGS], op_index: usize, reg: u8) -> Result<(), BytecodeError> {
    if !initialized[reg as usize] {
        return Err(BytecodeError::UninitializedRegister { op_index, reg });
    }
    Ok(())
}

/// Static MPC resource & fee cost estimate for a compiled circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BytecodeCost {
    /// Total Beaver multiplication triples required (`Mul`, `Mux`).
    pub beaver_triples: u64,
    /// Total Beaver squaring tuples required (`Square`, `AssertBool`, `AssertRangeBits`).
    pub beaver_squares: u64,
    /// Total persistent confidential state writes (`StoreState`).
    pub state_writes: u64,
    /// Deterministic execution fee in `vern`.
    pub fee_vern: u64,
}

/// Estimate static MPC resource consumption and execution fee (using default fee schedule).
pub fn estimate_cost(circuit: &CompiledCircuit) -> BytecodeCost {
    estimate_cost_with_triple_fee(circuit, DEFAULT_TRIPLE_FEE_VERN)
}

/// Estimate static MPC resource consumption and execution fee using a caller-supplied
/// dynamic `triple_fee_vern` (e.g. from `AdaptiveParams::circuit_triple_fee_vern`).
pub fn estimate_cost_with_triple_fee(
    circuit: &CompiledCircuit,
    triple_fee_vern: u64,
) -> BytecodeCost {
    let mut beaver_triples: u64 = 0;
    let mut beaver_squares: u64 = 0;
    let mut state_writes: u64 = 0;

    for &op in &circuit.ops {
        match op {
            BytecodeOp::Mul { .. } | BytecodeOp::Mux { .. } => {
                beaver_triples = beaver_triples.saturating_add(1);
            }
            BytecodeOp::Square { .. } | BytecodeOp::AssertBool { .. } => {
                beaver_squares = beaver_squares.saturating_add(1);
            }
            BytecodeOp::AssertRangeBits {
                bit_start, bit_end, ..
            } => {
                let bits = (bit_end.saturating_sub(bit_start) as u64).saturating_add(1);
                beaver_squares = beaver_squares.saturating_add(bits);
            }
            BytecodeOp::StoreState { .. } => {
                state_writes = state_writes.saturating_add(1);
            }
            BytecodeOp::LoadState { .. }
            | BytecodeOp::LoadInput { .. }
            | BytecodeOp::LoadConst { .. }
            | BytecodeOp::Add { .. }
            | BytecodeOp::Sub { .. }
            | BytecodeOp::MulConst { .. }
            | BytecodeOp::AssertZero { .. }
            | BytecodeOp::RevealOutput { .. } => {}
        }
    }

    let square_fee = (triple_fee_vern / 2).max(DEFAULT_SQUARE_FEE_VERN.min(triple_fee_vern));
    let op_fee = (circuit.ops.len() as u64).saturating_mul(DEFAULT_PER_OP_FEE_VERN);
    let triple_cost = beaver_triples.saturating_mul(triple_fee_vern);
    let square_cost = beaver_squares.saturating_mul(square_fee);
    let write_cost = state_writes.saturating_mul(DEFAULT_STATE_WRITE_FEE_VERN);

    let fee_vern = DEFAULT_CIRCUIT_BASE_FEE_VERN
        .saturating_add(op_fee)
        .saturating_add(triple_cost)
        .saturating_add(square_cost)
        .saturating_add(write_cost);

    BytecodeCost {
        beaver_triples,
        beaver_squares,
        state_writes,
        fee_vern,
    }
}

// ============================================================================
// Vernam Circuit Assembly (`.vca`) Parser / Compiler & Disassembler
// ============================================================================

/// Strip `#` or `//` comments from a single line of `.vca` assembly.
fn strip_comment(line: &str) -> &str {
    let hash_pos = line.find('#');
    let slash_pos = line.find("//");
    let cut = match (hash_pos, slash_pos) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return line,
    };
    &line[..cut]
}

fn parse_register(token: &str, line: usize) -> Result<u8, BytecodeError> {
    let rest = token
        .strip_prefix('r')
        .or_else(|| token.strip_prefix('R'))
        .ok_or_else(|| BytecodeError::ParseError {
            line,
            msg: format!("expected register r0..r255, got '{token}'"),
        })?;

    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BytecodeError::ParseError {
            line,
            msg: format!("invalid register syntax '{token}'"),
        });
    }
    if rest.len() > 1 && rest.starts_with('0') {
        return Err(BytecodeError::ParseError {
            line,
            msg: format!("non-canonical leading zero in register '{token}'"),
        });
    }

    rest.parse::<u8>().map_err(|_| BytecodeError::ParseError {
        line,
        msg: format!("register '{token}' out of range (expected r0..r255)"),
    })
}

fn parse_u16_lit(token: &str, line: usize, label: &str) -> Result<u16, BytecodeError> {
    let val = parse_u128_raw(token, line, label)?;
    u16::try_from(val).map_err(|_| BytecodeError::ParseError {
        line,
        msg: format!("{label} '{token}' out of u16 range"),
    })
}

fn parse_u32_lit(token: &str, line: usize, label: &str) -> Result<u32, BytecodeError> {
    let val = parse_u128_raw(token, line, label)?;
    u32::try_from(val).map_err(|_| BytecodeError::ParseError {
        line,
        msg: format!("{label} '{token}' out of u32 range"),
    })
}

fn parse_u128_raw(token: &str, line: usize, label: &str) -> Result<u128, BytecodeError> {
    if token.is_empty() {
        return Err(BytecodeError::ParseError {
            line,
            msg: format!("missing {label}"),
        });
    }

    if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(BytecodeError::ParseError {
                line,
                msg: format!("invalid hex {label} '{token}'"),
            });
        }
        return u128::from_str_radix(hex, 16).map_err(|_| BytecodeError::ParseError {
            line,
            msg: format!("hex {label} '{token}' overflows u128"),
        });
    }

    if !token.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BytecodeError::ParseError {
            line,
            msg: format!("invalid decimal {label} '{token}'"),
        });
    }

    token.parse::<u128>().map_err(|_| BytecodeError::ParseError {
        line,
        msg: format!("decimal {label} '{token}' overflows u128"),
    })
}

fn parse_field_const(token: &str, line: usize) -> Result<u128, BytecodeError> {
    let val = parse_u128_raw(token, line, "field constant")?;
    if val >= PRIME_P {
        return Err(BytecodeError::NonCanonicalConstant {
            line: Some(line),
            value: val,
        });
    }
    Ok(val)
}

fn parse_reg_range(token: &str, line: usize) -> Result<(u8, u8), BytecodeError> {
    // Support both canonical `r10..r25` and explicit inclusive `r10..=r25`.
    let (start_s, end_s) = if let Some((a, b)) = token.split_once("..=") {
        (a.trim(), b.trim())
    } else if let Some((a, b)) = token.split_once("..") {
        if b.contains("..") {
            return Err(BytecodeError::ParseError {
                line,
                msg: format!("malformed register range '{token}'"),
            });
        }
        (a.trim(), b.trim())
    } else {
        return Err(BytecodeError::ParseError {
            line,
            msg: format!("expected register range r<start>..r<end>, got '{token}'"),
        });
    };

    let start = parse_register(start_s, line)?;
    let end = parse_register(end_s, line)?;
    Ok((start, end))
}

fn split_operands(rest: &str, expected: usize, line: usize) -> Result<Vec<&str>, BytecodeError> {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return Err(BytecodeError::ParseError {
            line,
            msg: format!("expected {expected} operand(s), found none"),
        });
    }

    let mut parts = Vec::with_capacity(expected);
    for raw in trimmed.split(',') {
        let part = raw.trim();
        if part.is_empty() {
            return Err(BytecodeError::ParseError {
                line,
                msg: "empty operand (duplicate or trailing comma)".to_string(),
            });
        }
        if part.split_whitespace().count() != 1 {
            return Err(BytecodeError::ParseError {
                line,
                msg: format!("unexpected whitespace inside operand '{part}' (missing comma?)"),
            });
        }
        parts.push(part);
    }

    if parts.len() != expected {
        return Err(BytecodeError::ParseError {
            line,
            msg: format!("expected {expected} operand(s), found {}", parts.len()),
        });
    }
    Ok(parts)
}

/// Compile human-readable Vernam Circuit Assembly (`.vca`) into a statically validated
/// `CompiledCircuit`.
///
/// Panic-free on arbitrary or adversarially fuzzed UTF-8 inputs.
pub fn compile_vca(source: &str) -> Result<CompiledCircuit, BytecodeError> {
    let mut ops = Vec::new();

    for (idx, raw_line) in source.lines().enumerate() {
        let line_no = idx + 1;
        let code = strip_comment(raw_line).trim();
        if code.is_empty() {
            continue;
        }

        // Split leading mnemonic from operand tail on first ASCII whitespace.
        let (mnemonic_raw, rest) = match code.find(|c: char| c.is_ascii_whitespace()) {
            Some(pos) => (&code[..pos], &code[pos..]),
            None => (code, ""),
        };

        if ops.len() >= MAX_OPS {
            return Err(BytecodeError::TooManyOps {
                count: ops.len() + 1,
                max: MAX_OPS,
            });
        }

        let mnemonic = mnemonic_raw.to_ascii_uppercase();
        let op = match mnemonic.as_str() {
            "LOAD_STATE" => {
                let args = split_operands(rest, 2, line_no)?;
                BytecodeOp::LoadState {
                    dst: parse_register(args[0], line_no)?,
                    slot: parse_u32_lit(args[1], line_no, "state slot")?,
                }
            }
            "STORE_STATE" => {
                let args = split_operands(rest, 2, line_no)?;
                BytecodeOp::StoreState {
                    slot: parse_u32_lit(args[0], line_no, "state slot")?,
                    src: parse_register(args[1], line_no)?,
                }
            }
            "LOAD_IN" => {
                let args = split_operands(rest, 2, line_no)?;
                BytecodeOp::LoadInput {
                    dst: parse_register(args[0], line_no)?,
                    index: parse_u16_lit(args[1], line_no, "input index")?,
                }
            }
            "LOAD_CONST" => {
                let args = split_operands(rest, 2, line_no)?;
                BytecodeOp::LoadConst {
                    dst: parse_register(args[0], line_no)?,
                    value: parse_field_const(args[1], line_no)?,
                }
            }
            "ADD" => {
                let args = split_operands(rest, 3, line_no)?;
                BytecodeOp::Add {
                    dst: parse_register(args[0], line_no)?,
                    lhs: parse_register(args[1], line_no)?,
                    rhs: parse_register(args[2], line_no)?,
                }
            }
            "SUB" => {
                let args = split_operands(rest, 3, line_no)?;
                BytecodeOp::Sub {
                    dst: parse_register(args[0], line_no)?,
                    lhs: parse_register(args[1], line_no)?,
                    rhs: parse_register(args[2], line_no)?,
                }
            }
            "MUL_CONST" => {
                let args = split_operands(rest, 3, line_no)?;
                BytecodeOp::MulConst {
                    dst: parse_register(args[0], line_no)?,
                    src: parse_register(args[1], line_no)?,
                    constant: parse_field_const(args[2], line_no)?,
                }
            }
            "MUL" => {
                let args = split_operands(rest, 3, line_no)?;
                BytecodeOp::Mul {
                    dst: parse_register(args[0], line_no)?,
                    lhs: parse_register(args[1], line_no)?,
                    rhs: parse_register(args[2], line_no)?,
                }
            }
            "SQUARE" => {
                let args = split_operands(rest, 2, line_no)?;
                BytecodeOp::Square {
                    dst: parse_register(args[0], line_no)?,
                    src: parse_register(args[1], line_no)?,
                }
            }
            "MUX" => {
                let args = split_operands(rest, 4, line_no)?;
                BytecodeOp::Mux {
                    dst: parse_register(args[0], line_no)?,
                    cond: parse_register(args[1], line_no)?,
                    when_true: parse_register(args[2], line_no)?,
                    when_false: parse_register(args[3], line_no)?,
                }
            }
            "ASSERT_ZERO" => {
                let args = split_operands(rest, 1, line_no)?;
                BytecodeOp::AssertZero {
                    src: parse_register(args[0], line_no)?,
                }
            }
            "ASSERT_BOOL" => {
                let args = split_operands(rest, 1, line_no)?;
                BytecodeOp::AssertBool {
                    src: parse_register(args[0], line_no)?,
                }
            }
            "ASSERT_RANGE" => {
                let args = split_operands(rest, 2, line_no)?;
                let src = parse_register(args[0], line_no)?;
                let (bit_start, bit_end) = parse_reg_range(args[1], line_no)?;
                BytecodeOp::AssertRangeBits {
                    src,
                    bit_start,
                    bit_end,
                }
            }
            "REVEAL" => {
                let args = split_operands(rest, 1, line_no)?;
                BytecodeOp::RevealOutput {
                    src: parse_register(args[0], line_no)?,
                }
            }
            _ => {
                return Err(BytecodeError::ParseError {
                    line: line_no,
                    msg: format!("unknown opcode '{mnemonic_raw}'"),
                });
            }
        };

        ops.push(op);
    }

    CompiledCircuit::from_ops(ops)
}

/// Disassemble a `CompiledCircuit` back into canonical `.vca` assembly text.
///
/// Supports exact `compile_vca -> encode_authenticated -> decode_authenticated -> disassemble_vca -> compile_vca`
/// roundtrips across all 14 opcodes.
pub fn disassemble_vca(circuit: &CompiledCircuit) -> String {
    let mut out = String::with_capacity(circuit.ops.len() * 24);
    for (idx, &op) in circuit.ops.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        match op {
            BytecodeOp::LoadState { dst, slot } => {
                out.push_str(&format!("LOAD_STATE r{dst}, {slot}"));
            }
            BytecodeOp::StoreState { slot, src } => {
                out.push_str(&format!("STORE_STATE {slot}, r{src}"));
            }
            BytecodeOp::LoadInput { dst, index } => {
                out.push_str(&format!("LOAD_IN r{dst}, {index}"));
            }
            BytecodeOp::LoadConst { dst, value } => {
                out.push_str(&format!("LOAD_CONST r{dst}, {value}"));
            }
            BytecodeOp::Add { dst, lhs, rhs } => {
                out.push_str(&format!("ADD r{dst}, r{lhs}, r{rhs}"));
            }
            BytecodeOp::Sub { dst, lhs, rhs } => {
                out.push_str(&format!("SUB r{dst}, r{lhs}, r{rhs}"));
            }
            BytecodeOp::MulConst { dst, src, constant } => {
                out.push_str(&format!("MUL_CONST r{dst}, r{src}, {constant}"));
            }
            BytecodeOp::Mul { dst, lhs, rhs } => {
                out.push_str(&format!("MUL r{dst}, r{lhs}, r{rhs}"));
            }
            BytecodeOp::Square { dst, src } => {
                out.push_str(&format!("SQUARE r{dst}, r{src}"));
            }
            BytecodeOp::Mux {
                dst,
                cond,
                when_true,
                when_false,
            } => {
                out.push_str(&format!("MUX r{dst}, r{cond}, r{when_true}, r{when_false}"));
            }
            BytecodeOp::AssertZero { src } => {
                out.push_str(&format!("ASSERT_ZERO r{src}"));
            }
            BytecodeOp::AssertBool { src } => {
                out.push_str(&format!("ASSERT_BOOL r{src}"));
            }
            BytecodeOp::AssertRangeBits {
                src,
                bit_start,
                bit_end,
            } => {
                out.push_str(&format!("ASSERT_RANGE r{src}, r{bit_start}..r{bit_end}"));
            }
            BytecodeOp::RevealOutput { src } => {
                out.push_str(&format!("REVEAL r{src}"));
            }
        }
    }
    out
}

// ============================================================================
// Compact Binary Wire Codec (`VRNMCC01` + 128-bit Carter-Wegman MAC)
// ============================================================================

/// Encode a `CompiledCircuit` into compact binary wire format (`VRNMCC01`) authenticated
/// with a 128-bit Carter-Wegman MAC over `F_(2^127 - 1)`.
pub fn encode_authenticated(
    circuit: &CompiledCircuit,
    key: &BytecodeMacKey,
) -> Result<Vec<u8>, BytecodeError> {
    // Re-validate before serialization so manually constructed structs cannot bypass invariants.
    let validated = CompiledCircuit::from_ops(circuit.ops.clone())?;

    let mut out = Vec::with_capacity(HEADER_BYTES + validated.ops.len() * 6 + MAC_TAG_BYTES);
    out.extend_from_slice(BYTECODE_MAGIC);
    out.extend_from_slice(&BYTECODE_VERSION.to_be_bytes());
    out.extend_from_slice(&(validated.ops.len() as u16).to_be_bytes());

    for &op in &validated.ops {
        match op {
            BytecodeOp::LoadState { dst, slot } => {
                out.push(TAG_LOAD_STATE);
                out.push(dst);
                out.extend_from_slice(&slot.to_be_bytes());
            }
            BytecodeOp::StoreState { slot, src } => {
                out.push(TAG_STORE_STATE);
                out.extend_from_slice(&slot.to_be_bytes());
                out.push(src);
            }
            BytecodeOp::LoadInput { dst, index } => {
                out.push(TAG_LOAD_INPUT);
                out.push(dst);
                out.extend_from_slice(&index.to_be_bytes());
            }
            BytecodeOp::LoadConst { dst, value } => {
                out.push(TAG_LOAD_CONST);
                out.push(dst);
                out.extend_from_slice(&value.to_be_bytes());
            }
            BytecodeOp::Add { dst, lhs, rhs } => {
                out.push(TAG_ADD);
                out.push(dst);
                out.push(lhs);
                out.push(rhs);
            }
            BytecodeOp::Sub { dst, lhs, rhs } => {
                out.push(TAG_SUB);
                out.push(dst);
                out.push(lhs);
                out.push(rhs);
            }
            BytecodeOp::MulConst { dst, src, constant } => {
                out.push(TAG_MUL_CONST);
                out.push(dst);
                out.push(src);
                out.extend_from_slice(&constant.to_be_bytes());
            }
            BytecodeOp::Mul { dst, lhs, rhs } => {
                out.push(TAG_MUL);
                out.push(dst);
                out.push(lhs);
                out.push(rhs);
            }
            BytecodeOp::Square { dst, src } => {
                out.push(TAG_SQUARE);
                out.push(dst);
                out.push(src);
            }
            BytecodeOp::Mux {
                dst,
                cond,
                when_true,
                when_false,
            } => {
                out.push(TAG_MUX);
                out.push(dst);
                out.push(cond);
                out.push(when_true);
                out.push(when_false);
            }
            BytecodeOp::AssertZero { src } => {
                out.push(TAG_ASSERT_ZERO);
                out.push(src);
            }
            BytecodeOp::AssertBool { src } => {
                out.push(TAG_ASSERT_BOOL);
                out.push(src);
            }
            BytecodeOp::AssertRangeBits {
                src,
                bit_start,
                bit_end,
            } => {
                out.push(TAG_ASSERT_RANGE_BITS);
                out.push(src);
                out.push(bit_start);
                out.push(bit_end);
            }
            BytecodeOp::RevealOutput { src } => {
                out.push(TAG_REVEAL_OUTPUT);
                out.push(src);
            }
        }
    }

    if out.len() + MAC_TAG_BYTES > MAX_BYTECODE_BYTES {
        return Err(BytecodeError::BytecodeTooLarge {
            len: out.len() + MAC_TAG_BYTES,
            max: MAX_BYTECODE_BYTES,
        });
    }

    let tag = key.compute_tag(&out);
    out.extend_from_slice(&tag);
    Ok(out)
}

struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_bytes<const N: usize>(&mut self) -> Result<[u8; N], BytecodeError> {
        let end = self.pos.checked_add(N).ok_or(BytecodeError::UnexpectedEof)?;
        if end > self.buf.len() {
            return Err(BytecodeError::UnexpectedEof);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, BytecodeError> {
        Ok(self.read_bytes::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, BytecodeError> {
        Ok(u16::from_be_bytes(self.read_bytes::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32, BytecodeError> {
        Ok(u32::from_be_bytes(self.read_bytes::<4>()?))
    }

    fn read_u128(&mut self) -> Result<u128, BytecodeError> {
        Ok(u128::from_be_bytes(self.read_bytes::<16>()?))
    }
}

/// Verify the 128-bit Carter-Wegman MAC in constant time BEFORE decoding instructions,
/// enforce `MAX_BYTECODE_BYTES`, reject trailing bytes, and statically validate the DAG.
pub fn decode_authenticated(
    bytes: &[u8],
    key: &BytecodeMacKey,
) -> Result<CompiledCircuit, BytecodeError> {
    if bytes.len() > MAX_BYTECODE_BYTES {
        return Err(BytecodeError::BytecodeTooLarge {
            len: bytes.len(),
            max: MAX_BYTECODE_BYTES,
        });
    }
    if bytes.len() < HEADER_BYTES + MAC_TAG_BYTES {
        return Err(BytecodeError::UnexpectedEof);
    }

    let payload_len = bytes.len() - MAC_TAG_BYTES;
    let payload = &bytes[..payload_len];
    let mut tag = [0u8; MAC_TAG_BYTES];
    tag.copy_from_slice(&bytes[payload_len..]);

    // Strict verify-then-parse: check MAC in constant time before touching any header/op bytes.
    if !key.verify_tag(payload, &tag) {
        return Err(BytecodeError::MacVerificationFailed);
    }

    let mut reader = WireReader::new(payload);
    let magic = reader.read_bytes::<8>()?;
    if &magic != BYTECODE_MAGIC {
        return Err(BytecodeError::InvalidMagic);
    }

    let version = reader.read_u16()?;
    if version != BYTECODE_VERSION {
        return Err(BytecodeError::UnsupportedVersion(version));
    }

    let op_count = reader.read_u16()? as usize;
    if op_count > MAX_OPS {
        return Err(BytecodeError::TooManyOps {
            count: op_count,
            max: MAX_OPS,
        });
    }

    let mut ops = Vec::with_capacity(op_count);
    for op_index in 0..op_count {
        let tag_byte = reader.read_u8()?;
        let op = match tag_byte {
            TAG_LOAD_STATE => BytecodeOp::LoadState {
                dst: reader.read_u8()?,
                slot: reader.read_u32()?,
            },
            TAG_STORE_STATE => BytecodeOp::StoreState {
                slot: reader.read_u32()?,
                src: reader.read_u8()?,
            },
            TAG_LOAD_INPUT => BytecodeOp::LoadInput {
                dst: reader.read_u8()?,
                index: reader.read_u16()?,
            },
            TAG_LOAD_CONST => {
                let dst = reader.read_u8()?;
                let value = reader.read_u128()?;
                if value >= PRIME_P {
                    return Err(BytecodeError::NonCanonicalConstant { line: None, value });
                }
                BytecodeOp::LoadConst { dst, value }
            }
            TAG_ADD => BytecodeOp::Add {
                dst: reader.read_u8()?,
                lhs: reader.read_u8()?,
                rhs: reader.read_u8()?,
            },
            TAG_SUB => BytecodeOp::Sub {
                dst: reader.read_u8()?,
                lhs: reader.read_u8()?,
                rhs: reader.read_u8()?,
            },
            TAG_MUL_CONST => {
                let dst = reader.read_u8()?;
                let src = reader.read_u8()?;
                let constant = reader.read_u128()?;
                if constant >= PRIME_P {
                    return Err(BytecodeError::NonCanonicalConstant {
                        line: None,
                        value: constant,
                    });
                }
                BytecodeOp::MulConst { dst, src, constant }
            }
            TAG_MUL => BytecodeOp::Mul {
                dst: reader.read_u8()?,
                lhs: reader.read_u8()?,
                rhs: reader.read_u8()?,
            },
            TAG_SQUARE => BytecodeOp::Square {
                dst: reader.read_u8()?,
                src: reader.read_u8()?,
            },
            TAG_MUX => BytecodeOp::Mux {
                dst: reader.read_u8()?,
                cond: reader.read_u8()?,
                when_true: reader.read_u8()?,
                when_false: reader.read_u8()?,
            },
            TAG_ASSERT_ZERO => BytecodeOp::AssertZero {
                src: reader.read_u8()?,
            },
            TAG_ASSERT_BOOL => BytecodeOp::AssertBool {
                src: reader.read_u8()?,
            },
            TAG_ASSERT_RANGE_BITS => BytecodeOp::AssertRangeBits {
                src: reader.read_u8()?,
                bit_start: reader.read_u8()?,
                bit_end: reader.read_u8()?,
            },
            TAG_REVEAL_OUTPUT => BytecodeOp::RevealOutput {
                src: reader.read_u8()?,
            },
            other => {
                return Err(BytecodeError::UnknownOpcode {
                    op_index,
                    tag: other,
                });
            }
        };
        ops.push(op);
    }

    if reader.remaining() != 0 {
        return Err(BytecodeError::TrailingBytes {
            remaining: reader.remaining(),
        });
    }

    CompiledCircuit::from_ops(ops)
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
        fn next_u8(&mut self) -> u8 {
            (self.next_u64() >> 56) as u8
        }
    }

    #[test]
    fn test_vca_compile_disassemble_and_authenticated_binary_roundtrip() {
        // Exercises all 14 opcodes, both comment styles, hex and decimal constants, and range bits.
        let src = r#"
            # Confidential AMM / state transition circuit exercising all 14 opcodes
            LOAD_IN r0, 0           // boolean flag
            LOAD_IN r1, 1           # secret amount
            LOAD_STATE r2, 0        // previous vault balance
            LOAD_CONST r3, 0x2a     // public constant 42
            MUL_CONST r4, r1, 3
            MUL r5, r1, r3          // 1 Beaver triple
            SQUARE r6, r4           // 1 Beaver square
            ADD r7, r2, r5
            SUB r8, r7, r6
            MUX r9, r0, r7, r8      // 1 Beaver triple
            ASSERT_BOOL r0          // 1 Beaver square
            SUB r10, r7, r7
            ASSERT_ZERO r10
            # Initialize 16 bit registers r20..r35 for a 16-bit range assertion
            LOAD_IN r20, 2
            LOAD_IN r21, 3
            LOAD_IN r22, 4
            LOAD_IN r23, 5
            LOAD_IN r24, 6
            LOAD_IN r25, 7
            LOAD_IN r26, 8
            LOAD_IN r27, 9
            LOAD_IN r28, 10
            LOAD_IN r29, 11
            LOAD_IN r30, 12
            LOAD_IN r31, 13
            LOAD_IN r32, 14
            LOAD_IN r33, 15
            LOAD_IN r34, 16
            LOAD_IN r35, 17
            ASSERT_RANGE r9, r20..r35   // 16 Beaver squares
            STORE_STATE 0, r9           // 1 state write
            REVEAL r9
        "#;

        let compiled = compile_vca(src).expect("valid VCA circuit must compile");
        assert_eq!(compiled.ops.len(), 32);
        assert_eq!(compiled.num_inputs, 18);
        assert_eq!(compiled.num_state_slots, 1);
        assert_eq!(compiled.num_outputs, 1);
        assert_eq!(compiled.num_regs_used, 27);

        let cost = estimate_cost(&compiled);
        assert_eq!(cost.beaver_triples, 2); // MUL + MUX
        assert_eq!(cost.beaver_squares, 18); // SQUARE + ASSERT_BOOL + 16-bit ASSERT_RANGE
        assert_eq!(cost.state_writes, 1); // STORE_STATE
        assert_eq!(
            cost.fee_vern,
            DEFAULT_CIRCUIT_BASE_FEE_VERN
                + 32 * DEFAULT_PER_OP_FEE_VERN
                + 2 * DEFAULT_TRIPLE_FEE_VERN
                + 18 * DEFAULT_SQUARE_FEE_VERN
                + DEFAULT_STATE_WRITE_FEE_VERN
        );

        let key = BytecodeMacKey::generate();
        // Verify Debug redaction never leaks raw scalar key material.
        let dbg_str = format!("{key:?}");
        assert!(dbg_str.contains("REDACTED"));
        assert!(!dbg_str.contains(&key.r.to_string()));
        assert!(!dbg_str.contains(&key.s.to_string()));

        let wire = encode_authenticated(&compiled, &key).expect("encode must succeed");
        assert_eq!(&wire[..8], BYTECODE_MAGIC);

        let decoded = decode_authenticated(&wire, &key).expect("decode must succeed");
        assert_eq!(decoded, compiled);

        let disassembled = disassemble_vca(&decoded);
        let recompiled = compile_vca(&disassembled).expect("disassembled VCA must recompile");
        assert_eq!(recompiled, compiled);
        assert_eq!(disassemble_vca(&recompiled), disassembled);

        // Re-encoding with the same key yields bit-identical wire bytes.
        let wire2 = encode_authenticated(&recompiled, &key).expect("re-encode must succeed");
        assert_eq!(wire2, wire);
    }

    #[test]
    fn test_vca_rejects_uninitialized_reg_non_canonical_const_and_oversized_circuit() {
        // 1. Uninitialized register read (including self-referential first op).
        let uninit_src = "ADD r0, r0, r1\n";
        assert_eq!(
            compile_vca(uninit_src),
            Err(BytecodeError::UninitializedRegister {
                op_index: 0,
                reg: 0
            })
        );

        // Uninitialized bit register inside ASSERT_RANGE.
        let uninit_range = "LOAD_IN r0, 0\nLOAD_IN r10, 1\nASSERT_RANGE r0, r10..r12\n";
        assert_eq!(
            compile_vca(uninit_range),
            Err(BytecodeError::UninitializedRegister {
                op_index: 2,
                reg: 11
            })
        );

        // 2. Non-canonical field constants (== PRIME_P and > PRIME_P) in both LOAD_CONST and MUL_CONST.
        let non_canon_eq = format!("LOAD_CONST r0, {PRIME_P}\n");
        assert_eq!(
            compile_vca(&non_canon_eq),
            Err(BytecodeError::NonCanonicalConstant {
                line: Some(1),
                value: PRIME_P
            })
        );

        let non_canon_gt = format!("LOAD_IN r0, 0\nMUL_CONST r1, r0, 0x{:x}\n", PRIME_P + 7);
        assert_eq!(
            compile_vca(&non_canon_gt),
            Err(BytecodeError::NonCanonicalConstant {
                line: Some(2),
                value: PRIME_P + 7
            })
        );

        // Largest valid canonical constant (PRIME_P - 1) must succeed.
        let max_valid = format!("LOAD_CONST r0, {}\nREVEAL r0\n", PRIME_P - 1);
        let ok_circuit = compile_vca(&max_valid).expect("PRIME_P - 1 is canonical");
        assert_eq!(
            ok_circuit.ops[0],
            BytecodeOp::LoadConst {
                dst: 0,
                value: PRIME_P - 1
            }
        );

        // 3. Register index >= MAX_REGS (r256) and duplicate/invalid syntax with line numbers.
        assert!(matches!(
            compile_vca("LOAD_IN r256, 0\n"),
            Err(BytecodeError::ParseError { line: 1, .. })
        ));
        assert!(matches!(
            compile_vca("LOAD_IN r0, 0\nADD r1,, r0, r0\n"),
            Err(BytecodeError::ParseError { line: 2, .. })
        ));
        assert!(matches!(
            compile_vca("LOAD_IN r0, 0\nADD r1, r0, r0,\n"),
            Err(BytecodeError::ParseError { line: 2, .. })
        ));
        assert!(matches!(
            compile_vca("UNKNOWN_OP r0\n"),
            Err(BytecodeError::ParseError { line: 1, .. })
        ));

        // 4. Invalid bit range (reversed or > 126 bits).
        let reversed_range = "LOAD_IN r0, 0\nLOAD_IN r5, 1\nASSERT_RANGE r0, r6..r5\n";
        assert_eq!(
            compile_vca(reversed_range),
            Err(BytecodeError::InvalidBitRange {
                op_index: 2,
                bit_start: 6,
                bit_end: 5
            })
        );

        let mut wide_range_src = String::from("LOAD_IN r0, 0\n");
        for r in 10u16..=136 {
            wide_range_src.push_str(&format!("LOAD_IN r{r}, {r}\n"));
        }
        wide_range_src.push_str("ASSERT_RANGE r0, r10..r136\n"); // 127 bits > MAX_RANGE_BITS (126)
        assert!(matches!(
            compile_vca(&wide_range_src),
            Err(BytecodeError::InvalidBitRange {
                bit_start: 10,
                bit_end: 136,
                ..
            })
        ));

        // 5. Oversized circuit (> MAX_OPS = 2_048).
        let mut big = String::with_capacity((MAX_OPS + 1) * 16);
        big.push_str("LOAD_IN r0, 0\n");
        for _ in 0..MAX_OPS {
            big.push_str("ADD r0, r0, r0\n");
        }
        assert_eq!(
            compile_vca(&big),
            Err(BytecodeError::TooManyOps {
                count: MAX_OPS + 1,
                max: MAX_OPS
            })
        );
    }

    #[test]
    fn test_bytecode_tamper_truncation_and_fuzz_panic_freedom() {
        let src = "\
            LOAD_IN r0, 0\n\
            LOAD_IN r1, 1\n\
            MUL r2, r0, r1\n\
            STORE_STATE 7, r2\n\
            REVEAL r2\n";
        let circuit = compile_vca(src).unwrap();
        let key = BytecodeMacKey::from_raw(0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF);
        let wrong_key = BytecodeMacKey::from_raw(0xDEAD_BEEF_CAFE_BABF, 0x0123_4567_89AB_CDEF);
        let wire = encode_authenticated(&circuit, &key).unwrap();

        // Wrong key must fail MAC check.
        assert_eq!(
            decode_authenticated(&wire, &wrong_key),
            Err(BytecodeError::MacVerificationFailed)
        );

        // Single-bit flip at every byte position must fail MAC check.
        for i in 0..wire.len() {
            let mut tampered = wire.clone();
            tampered[i] ^= 0x01;
            assert_eq!(
                decode_authenticated(&tampered, &key),
                Err(BytecodeError::MacVerificationFailed),
                "tamper at byte {i} was not rejected"
            );
        }

        // Truncation at every prefix length must fail cleanly without panicking.
        for cut in 0..wire.len() {
            let res = decode_authenticated(&wire[..cut], &key);
            assert!(res.is_err(), "truncated length {cut} must fail");
        }

        // Oversized wire blob (> MAX_BYTECODE_BYTES) must be rejected immediately.
        let huge = vec![0u8; MAX_BYTECODE_BYTES + 1];
        assert_eq!(
            decode_authenticated(&huge, &key),
            Err(BytecodeError::BytecodeTooLarge {
                len: MAX_BYTECODE_BYTES + 1,
                max: MAX_BYTECODE_BYTES
            })
        );

        // Authenticated payload with extra trailing bytes must be rejected by strict decoder.
        let mut with_trailing = wire[..wire.len() - MAC_TAG_BYTES].to_vec();
        with_trailing.push(0x99);
        let forged_tag = key.compute_tag(&with_trailing);
        with_trailing.extend_from_slice(&forged_tag);
        assert_eq!(
            decode_authenticated(&with_trailing, &key),
            Err(BytecodeError::TrailingBytes { remaining: 1 })
        );

        // Authenticated payload with invalid magic must be rejected after MAC passes.
        let mut bad_magic = wire[..wire.len() - MAC_TAG_BYTES].to_vec();
        bad_magic[0] ^= 0xFF;
        let bad_magic_tag = key.compute_tag(&bad_magic);
        bad_magic.extend_from_slice(&bad_magic_tag);
        assert_eq!(
            decode_authenticated(&bad_magic, &key),
            Err(BytecodeError::InvalidMagic)
        );

        // Authenticated payload with non-canonical constant must be rejected by decode-time validation.
        let mut bad_const = Vec::new();
        bad_const.extend_from_slice(BYTECODE_MAGIC);
        bad_const.extend_from_slice(&BYTECODE_VERSION.to_be_bytes());
        bad_const.extend_from_slice(&1u16.to_be_bytes());
        bad_const.push(TAG_LOAD_CONST);
        bad_const.push(0u8);
        bad_const.extend_from_slice(&PRIME_P.to_be_bytes());
        let bad_const_tag = key.compute_tag(&bad_const);
        bad_const.extend_from_slice(&bad_const_tag);
        assert_eq!(
            decode_authenticated(&bad_const, &key),
            Err(BytecodeError::NonCanonicalConstant {
                line: None,
                value: PRIME_P
            })
        );

        // Prefix-collision freedom: payload vs payload || [0x00] must produce distinct MACs.
        let mut extended = b"VRNMCC01\x00\x01\x00\x00".to_vec();
        let tag_a = key.compute_tag(&extended);
        extended.push(0x00);
        let tag_b = key.compute_tag(&extended);
        assert!(!ct_eq_16(&tag_a, &tag_b));

        // Deterministic adversarial fuzzing of both `compile_vca` and `decode_authenticated`:
        // 500 random ASCII/UTF-8 strings + 500 random binary blobs (both unauthenticated and
        // signed with `key` to exercise the wire parser deeply) — ZERO panics!
        let mut rng = DetRng::new(0xC1AC_0177_F022_0001);
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_,.:#/\n\t rR-+=";
        for _ in 0..500 {
            let len = (rng.next_u64() as usize) % 256;
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                let idx = (rng.next_u8() as usize) % alphabet.len();
                s.push(alphabet[idx] as char);
            }
            let _ = compile_vca(&s);
        }

        for i in 0..500 {
            let len = (rng.next_u64() as usize) % 192;
            let mut blob = Vec::with_capacity(len + MAC_TAG_BYTES + HEADER_BYTES);
            if i % 2 == 0 {
                // Inject valid header & sign so fuzzed instruction bytes hit the wire parser.
                blob.extend_from_slice(BYTECODE_MAGIC);
                blob.extend_from_slice(&BYTECODE_VERSION.to_be_bytes());
                let op_cnt = (rng.next_u64() % 16) as u16;
                blob.extend_from_slice(&op_cnt.to_be_bytes());
                for _ in 0..len {
                    blob.push(rng.next_u8());
                }
                let t = key.compute_tag(&blob);
                blob.extend_from_slice(&t);
            } else {
                for _ in 0..len {
                    blob.push(rng.next_u8());
                }
            }
            if let Ok(decoded) = decode_authenticated(&blob, &key) {
                // Any fuzzed blob that happens to be a valid circuit must roundtrip cleanly!
                let text = disassemble_vca(&decoded);
                assert_eq!(compile_vca(&text).unwrap(), decoded);
            }
        }
    }
}
