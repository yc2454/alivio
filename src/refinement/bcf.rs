//! BCF binary proof format: types, builders, ser/de.
//!
//! Mirrors `uapi/linux/bcf.h` from the BCF kernel patches. Kernel-side
//! reference: `/Users/yalucai/BCF/bcf-checker/include/uapi/linux/bcf.h`.
//!
//! On-disk layout:
//!   [BcfProofHeader, 12 bytes: magic, expr_cnt, step_cnt]
//!   [expression table: `expr_cnt` u32 slots]
//!   [proof step table: `step_cnt` u32 slots]
//!
//! Each logical expression / step consumes (1 + vlen) u32 slots: a 4-byte
//! fixed header followed by `vlen` u32 args inline. Indices in args are u32
//! offsets into the appropriate table.
//!
//! ## On the `dead_code` allow
//! Roughly half of this module — the proof-FORMAT half (`BcfProof`,
//! `BcfProofStep`, the `BCF_RULE_*` codes, `to_bytes`/`from_bytes`,
//! `BcfError`) — is unused in the release binary. That is by design, not
//! rot: zovia's production BCF path builds the symbolic expression DAG (the
//! USED half here) and drives cvc5, which CONSTRUCTS the proof and emits
//! opaque BCF-format bytes; zovia ships those bytes verbatim in the bundle
//! and the KERNEL checks them. zovia never constructs or rule-checks a proof
//! itself in production. These types are kept as (1) a faithful spec mirror
//! of `uapi/linux/bcf.h` and (2) round-trip + parse coverage exercised by
//! `#[cfg(test)]` (so we verify we can read cvc5's output and the layout
//! matches). `validate_proof_bytes` is a deliberately test-only soundness
//! backstop — redundant in production since the kernel re-checks every
//! bundle.
#![allow(dead_code)]

use std::io;

// ---------- magic ----------
pub const BCF_MAGIC: u32 = 0x0BCF;
pub const HEADER_SIZE: usize = 12;

// ---------- expression encoding ----------
//
// `code = op | type`. Type in the low 3 bits selects BV / BOOL / LIST.
// Op in the high 5 bits selects a specific operation. Values match the
// kernel `uapi/linux/bcf.h` exactly (current BCF, post-SOSP redesign).

pub const BCF_TYPE_MASK: u8 = 0x07;
pub const BCF_OP_MASK: u8 = 0xf8;

/// Expression type: Bitvector.
pub const BCF_BV: u8 = 0x00;
/// Expression type: Boolean.
pub const BCF_BOOL: u8 = 0x01;
/// Expression type: List of values.
pub const BCF_LIST: u8 = 0x02;

// Common operations (apply to any type)
pub const BCF_VAL: u8 = 0x08; /* constant / literal */
pub const BCF_VAR: u8 = 0x18; /* fresh variable */
pub const BCF_ITE: u8 = 0x28; /* if-then-else */

// Bitvector-specific operations (used as `op | BCF_BV`).
// ALU ops below (BPF_ADD/SUB/...) are also BV operations — they reuse the
// BPF opcode byte values and live in the same op-byte space.
pub const BCF_EXTRACT: u8 = 0x38; /* extract bit range */
pub const BCF_SIGN_EXTEND: u8 = 0x48;
pub const BCF_ZERO_EXTEND: u8 = 0x58;
pub const BCF_BVSIZE: u8 = 0x68; /* bitvector size as integer */
pub const BCF_BVNOT: u8 = 0x78;
pub const BCF_FROM_BOOL: u8 = 0x88; /* bool list to bitvector */
pub const BCF_CONCAT: u8 = 0x98;
pub const BCF_REPEAT: u8 = 0xa8;
pub const BCF_SDIV: u8 = 0xb0;
pub const BCF_SMOD: u8 = 0xd0;

// Boolean-specific operations (used as `op | BCF_BOOL`).
pub const BCF_CONJ: u8 = 0x00; /* AND */
pub const BCF_DISJ: u8 = 0x40; /* OR */
pub const BCF_NOT: u8 = 0x80;
pub const BCF_IMPLIES: u8 = 0x90;
pub const BCF_XOR_BOOL: u8 = 0x38; /* boolean XOR (distinct from BV XOR which uses BPF_XOR=0xa0) */
pub const BCF_BITOF: u8 = 0x48; /* extract one bit from a BV as a bool */

// Boolean literals (encoded in `params` low bit when `code = BCF_VAL | BCF_BOOL`).
pub const BCF_FALSE: u16 = 0x00;
pub const BCF_TRUE: u16 = 0x01;

// ---------- BPF opcodes (reused as ALU/predicate sub-ops in BCF codes) ----------
//
// These come from `<linux/bpf_common.h>`. BCF reuses them as the low 8 bits of
// expression codes: `code = BCF_BV_ALU | op` for ALU exprs,
// `code = BCF_BV_PRED | op` for predicates.

// ALU ops (BPF_ALU class)
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xa0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_ARSH: u8 = 0xc0;

// JMP ops (BPF_JMP class — used in BV predicates as comparison op)
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_JLT: u8 = 0xa0;
pub const BPF_JLE: u8 = 0xb0;
pub const BPF_JSLT: u8 = 0xc0;
pub const BPF_JSLE: u8 = 0xd0;

// ---------- proof rule classes (high 3 bits of u16 rule code) ----------
//
// Rule values within a class start at 1; value 0 is reserved as `_UNSPEC`.

pub const BCF_RULE_CLASS_MASK: u16 = 0xe000;
pub const BCF_RULE_CODE_MASK: u16 = 0x1fff;

/// Core rule class (includes assume, rewrite, evaluate, and equality rules).
pub const BCF_RULE_CORE: u16 = 0x0000;
pub const BCF_RULE_BOOL: u16 = 0x2000;
pub const BCF_RULE_BV: u16 = 0x4000;

// Core rules (per `enum bcf_core_rule` in uapi/linux/bcf.h)
pub const BCF_RULE_ASSUME: u16 = 1;
pub const BCF_RULE_EVALUATE: u16 = 2;
pub const BCF_RULE_DISTINCT_VALUES: u16 = 3;
pub const BCF_RULE_ACI_NORM: u16 = 4;
pub const BCF_RULE_ABSORB: u16 = 5;
pub const BCF_RULE_REWRITE: u16 = 6;
pub const BCF_RULE_REFL: u16 = 7;
pub const BCF_RULE_SYMM: u16 = 8;
pub const BCF_RULE_TRANS: u16 = 9;
pub const BCF_RULE_CONG: u16 = 10;
pub const BCF_RULE_TRUE_INTRO: u16 = 11;
pub const BCF_RULE_TRUE_ELIM: u16 = 12;
pub const BCF_RULE_FALSE_INTRO: u16 = 13;
pub const BCF_RULE_FALSE_ELIM: u16 = 14;

// Boolean rules (per `enum bcf_bool_rule`; subset — expand as needed)
pub const BCF_RULE_RESOLUTION: u16 = 1;
pub const BCF_RULE_FACTORING: u16 = 2;
pub const BCF_RULE_REORDERING: u16 = 3;
pub const BCF_RULE_SPLIT: u16 = 4;
pub const BCF_RULE_EQ_RESOLVE: u16 = 5;
pub const BCF_RULE_MODUS_PONENS: u16 = 6;
pub const BCF_RULE_NOT_NOT_ELIM: u16 = 7;
pub const BCF_RULE_CONTRA: u16 = 8;
pub const BCF_RULE_AND_ELIM: u16 = 9;
pub const BCF_RULE_AND_INTRO: u16 = 10;

// BV rules (per `enum bcf_bv_rule`)
pub const BCF_RULE_BITBLAST: u16 = 1;
pub const BCF_RULE_POLY_NORM: u16 = 2;
pub const BCF_RULE_POLY_NORM_EQ: u16 = 3;

// ---------- types ----------

/// Single BCF expression in editable form. Mirrors `struct bcf_expr`.
///
/// The on-disk `vlen` field is implicit in `args.len()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BcfExpr {
    pub code: u8,
    pub params: u16,
    pub args: Vec<u32>,
}

impl BcfExpr {
    /// u32 slots this expression occupies on disk (1 header + n args).
    pub fn slot_len(&self) -> u32 {
        1 + self.args.len() as u32
    }
}

/// Single proof step. Mirrors `struct bcf_proof_step`.
///
/// `args` holds `premise_cnt + param_cnt` u32 values: the first `premise_cnt`
/// are premises (refs to previous step indices), the rest are parameters
/// (typically refs to expressions, but rule-dependent). `param_cnt` is
/// implicit: `args.len() - premise_cnt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BcfProofStep {
    pub rule: u16,
    pub premise_cnt: u8,
    pub args: Vec<u32>,
}

impl BcfProofStep {
    /// Parameter count: `args.len() - premise_cnt`.
    pub fn param_cnt(&self) -> u8 {
        (self.args.len() as u32 - self.premise_cnt as u32) as u8
    }
    /// u32 slots this step occupies on disk: `1 + premise_cnt + param_cnt`.
    pub fn slot_len(&self) -> u32 {
        1 + self.args.len() as u32
    }
}

/// Top-level proof artifact (header + expression table + step table).
#[derive(Debug, Clone, Default)]
pub struct BcfProof {
    pub exprs: Vec<BcfExpr>,
    pub steps: Vec<BcfProofStep>,
}

// ---------- errors ----------

#[derive(Debug)]
pub enum BcfError {
    BadMagic(u32),
    Truncated { expected: usize, got: usize },
    Inconsistent(String),
    Io(io::Error),
}

impl std::fmt::Display for BcfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BcfError::BadMagic(m) => write!(f, "bad BCF magic: 0x{:08x}", m),
            BcfError::Truncated { expected, got } => {
                write!(f, "truncated: expected {} bytes, got {}", expected, got)
            }
            BcfError::Inconsistent(s) => write!(f, "inconsistent BCF: {}", s),
            BcfError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl std::error::Error for BcfError {}

impl From<io::Error> for BcfError {
    fn from(e: io::Error) -> Self {
        BcfError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, BcfError>;

// ---------- accessors ----------

pub fn rule_class(rule: u16) -> u16 {
    rule & BCF_RULE_CLASS_MASK
}
pub fn rule_code(rule: u16) -> u16 {
    rule & BCF_RULE_CODE_MASK
}
pub fn expr_type(code: u8) -> u8 {
    code & BCF_TYPE_MASK
}
pub fn expr_op(code: u8) -> u8 {
    code & BCF_OP_MASK
}
/// BV bit width: low byte of `params` for any BV expression (per uapi/linux/bcf.h).
pub fn bv_width(params: u16) -> u8 {
    (params & 0xff) as u8
}
/// Sign/zero-extension size: high byte of `params`.
pub fn ext_len(params: u16) -> u8 {
    ((params >> 8) & 0xff) as u8
}
/// Extract `start` bit: high byte of `params`.
pub fn extract_start(params: u16) -> u8 {
    ((params >> 8) & 0xff) as u8
}
/// Extract `end` bit: low byte of `params`.
pub fn extract_end(params: u16) -> u8 {
    (params & 0xff) as u8
}
/// Bool literal value: low bit of `params` (0 = false, 1 = true).
pub fn bool_literal(params: u16) -> u16 {
    params & 1
}

// ---------- helper builders ----------
//
// Mirror the current BCF kernel macros (in uapi/linux/bcf.h). All BV builders
// encode `params`'s low byte = bit width.

/// Fresh symbolic bitvector variable of `width` bits.
/// `code = BCF_VAR | BCF_BV`, vlen = 0.
pub fn bv_var(width: u16) -> BcfExpr {
    BcfExpr {
        code: BCF_VAR | BCF_BV,
        params: width,
        args: vec![],
    }
}

/// 32-bit BV constant. `code = BCF_VAL | BCF_BV`, params = 32, args = [imm].
pub fn bv_val32(imm: u32) -> BcfExpr {
    BcfExpr {
        code: BCF_VAL | BCF_BV,
        params: 32,
        args: vec![imm],
    }
}

/// 64-bit BV constant. `code = BCF_VAL | BCF_BV`, params = 64, args = [lo, hi].
pub fn bv_val64(imm: u64) -> BcfExpr {
    BcfExpr {
        code: BCF_VAL | BCF_BV,
        params: 64,
        args: vec![imm as u32, (imm >> 32) as u32],
    }
}

/// Binary BV ALU expression. `op` is a `BPF_ALU` opcode (ADD/SUB/AND/...).
/// `code = op | BCF_BV` (BV class = 0, so the byte equals `op` directly).
pub fn bv_alu(op: u8, a: u32, b: u32, width: u16) -> BcfExpr {
    BcfExpr {
        code: op | BCF_BV,
        params: width,
        args: vec![a, b],
    }
}

/// Binary BV predicate (comparison). `op` is a `BPF_JMP` opcode (JLT/JLE/JSGT/...).
/// Result type is Boolean; `code = op | BCF_BOOL`. The BV operand width is
/// implicit in the argument expressions; `params` is unused for predicates.
pub fn bv_pred(op: u8, a: u32, b: u32) -> BcfExpr {
    BcfExpr {
        code: op | BCF_BOOL,
        params: 0,
        args: vec![a, b],
    }
}

/// Boolean false constant. `code = BCF_VAL | BCF_BOOL`, params low bit = 0.
pub fn pred_false() -> BcfExpr {
    BcfExpr {
        code: BCF_VAL | BCF_BOOL,
        params: BCF_FALSE,
        args: vec![],
    }
}

/// Boolean true constant.
pub fn pred_true() -> BcfExpr {
    BcfExpr {
        code: BCF_VAL | BCF_BOOL,
        params: BCF_TRUE,
        args: vec![],
    }
}

/// Boolean conjunction over `args` (each an expression index of bool type).
pub fn pred_conj(args: Vec<u32>) -> BcfExpr {
    BcfExpr {
        code: BCF_CONJ | BCF_BOOL,
        params: 0,
        args,
    }
}

/// Boolean disjunction.
pub fn pred_disj(args: Vec<u32>) -> BcfExpr {
    BcfExpr {
        code: BCF_DISJ | BCF_BOOL,
        params: 0,
        args,
    }
}

// ---------- serialization ----------

impl BcfProof {
    /// Serialize to the on-disk BCF binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let expr_cnt: u32 = self.exprs.iter().map(|e| e.slot_len()).sum();
        let step_cnt: u32 = self.steps.iter().map(|s| s.slot_len()).sum();
        let total = HEADER_SIZE + 4 * (expr_cnt + step_cnt) as usize;
        let mut out = Vec::with_capacity(total);

        out.extend_from_slice(&BCF_MAGIC.to_le_bytes());
        out.extend_from_slice(&expr_cnt.to_le_bytes());
        out.extend_from_slice(&step_cnt.to_le_bytes());

        // bcf_expr layout: [code:u8 | vlen:u8 | params:u16]
        for e in &self.exprs {
            let vlen = e.args.len() as u8;
            let head: u32 = (e.code as u32) | ((vlen as u32) << 8) | ((e.params as u32) << 16);
            out.extend_from_slice(&head.to_le_bytes());
            for a in &e.args {
                out.extend_from_slice(&a.to_le_bytes());
            }
        }

        // bcf_proof_step layout: [rule:u16 | premise_cnt:u8 | param_cnt:u8].
        // Total args = premise_cnt + param_cnt; STEP_SZ(step) = total_args + 1.
        for s in &self.steps {
            let total = s.args.len() as u32;
            assert!(
                s.premise_cnt as u32 <= total,
                "premise_cnt ({}) exceeds args.len() ({})",
                s.premise_cnt,
                total
            );
            let param_cnt = total - s.premise_cnt as u32;
            let head: u32 = (s.rule as u32) | ((s.premise_cnt as u32) << 16) | (param_cnt << 24);
            out.extend_from_slice(&head.to_le_bytes());
            for a in &s.args {
                out.extend_from_slice(&a.to_le_bytes());
            }
        }

        debug_assert_eq!(out.len(), total);
        out
    }

    /// Parse on-disk BCF bytes back into editable form.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(BcfError::Truncated {
                expected: HEADER_SIZE,
                got: buf.len(),
            });
        }
        let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if magic != BCF_MAGIC {
            return Err(BcfError::BadMagic(magic));
        }
        let expr_cnt = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        let step_cnt = u32::from_le_bytes(buf[8..12].try_into().unwrap()) as usize;
        let expected = HEADER_SIZE + 4 * (expr_cnt + step_cnt);
        if buf.len() != expected {
            return Err(BcfError::Inconsistent(format!(
                "expected {} bytes (header + 4×({}+{})), got {}",
                expected,
                expr_cnt,
                step_cnt,
                buf.len()
            )));
        }

        let expr_end = HEADER_SIZE + 4 * expr_cnt;
        let step_end = expr_end + 4 * step_cnt;
        let mut pos = HEADER_SIZE;

        let mut exprs = Vec::new();
        while pos < expr_end {
            let head = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
            let code = (head & 0xff) as u8;
            let vlen = ((head >> 8) & 0xff) as usize;
            let params = ((head >> 16) & 0xffff) as u16;
            pos += 4;
            if pos + 4 * vlen > expr_end {
                return Err(BcfError::Truncated {
                    expected: pos + 4 * vlen,
                    got: expr_end,
                });
            }
            let mut args = Vec::with_capacity(vlen);
            for _ in 0..vlen {
                args.push(u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()));
                pos += 4;
            }
            exprs.push(BcfExpr { code, params, args });
        }

        let mut steps = Vec::new();
        while pos < step_end {
            let head = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
            let rule = (head & 0xffff) as u16;
            let premise_cnt = ((head >> 16) & 0xff) as u8;
            let param_cnt = ((head >> 24) & 0xff) as u8;
            let total = premise_cnt as usize + param_cnt as usize;
            pos += 4;
            if pos + 4 * total > step_end {
                return Err(BcfError::Truncated {
                    expected: pos + 4 * total,
                    got: step_end,
                });
            }
            let mut args = Vec::with_capacity(total);
            for _ in 0..total {
                args.push(u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()));
                pos += 4;
            }
            steps.push(BcfProofStep {
                rule,
                premise_cnt,
                args,
            });
        }

        Ok(BcfProof { exprs, steps })
    }
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_magic_bytes() {
        let proof = BcfProof::default();
        let bytes = proof.to_bytes();
        // Magic 0x0BCF in little-endian: cf 0b 00 00
        assert_eq!(&bytes[0..4], &[0xcf, 0x0b, 0x00, 0x00]);
        assert_eq!(&bytes[4..8], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&bytes[8..12], &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(bytes.len(), HEADER_SIZE);
    }

    #[test]
    fn expr_header_field_layout() {
        // bcf_expr struct: [code:u8 | vlen:u8 | params:u16].
        // Reproduce the first expression byte pattern from a real cvc5
        // output: code = BCF_VAR | BCF_BV (0x18), vlen = 0, params = 64 (bit
        // width). The byte pattern `18 00 40 00` confirms layout matches.
        let proof = BcfProof {
            exprs: vec![bv_var(64)],
            steps: vec![],
        };
        let bytes = proof.to_bytes();
        assert_eq!(&bytes[12..16], &[0x18, 0x00, 0x40, 0x00]);
        assert_eq!(proof.exprs[0].code, BCF_VAR | BCF_BV);
    }

    #[test]
    fn step_header_field_layout() {
        // bcf_proof_step struct: [rule:u16 | premise_cnt:u8 | param_cnt:u8].
        // Build a step with rule=0x1234, premise_cnt=2, param_cnt=1, with three
        // u32 args (two premises then one param).
        let proof = BcfProof {
            exprs: vec![],
            steps: vec![BcfProofStep {
                rule: 0x1234,
                premise_cnt: 2,
                args: vec![0xaaaa_bbbb, 0xcccc_dddd, 0xeeee_ffff],
            }],
        };
        let bytes = proof.to_bytes();
        assert_eq!(&bytes[12..16], &[0x34, 0x12, 0x02, 0x01]);
        // Args follow as three little-endian u32s.
        assert_eq!(
            &bytes[16..28],
            &[
                0xbb, 0xbb, 0xaa, 0xaa, 0xdd, 0xdd, 0xcc, 0xcc, 0xff, 0xff, 0xee, 0xee
            ]
        );
    }

    #[test]
    fn step_param_cnt_derived_from_args_len() {
        let s = BcfProofStep {
            rule: 0,
            premise_cnt: 2,
            args: vec![1, 2, 9, 10, 11],
        };
        assert_eq!(s.param_cnt(), 3);
        assert_eq!(s.slot_len(), 1 + 5);
    }

    #[test]
    fn builders_produce_canonical_codes() {
        // BV variable: code = BCF_VAR | BCF_BV = 0x18, vlen = 0, params = width.
        assert_eq!(bv_var(64).code, BCF_VAR | BCF_BV);
        assert_eq!(bv_var(64).code, 0x18);
        assert_eq!(bv_var(64).params, 64);
        assert!(bv_var(64).args.is_empty());

        // BV constant: code = BCF_VAL | BCF_BV = 0x08.
        assert_eq!(bv_val32(0xdead).code, BCF_VAL | BCF_BV);
        assert_eq!(bv_val32(0xdead).code, 0x08);
        assert_eq!(bv_val32(0xdead).params, 32);
        assert_eq!(bv_val32(0xdead).args, vec![0xdead]);
        assert_eq!(
            bv_val64(0xdead_beef_cafe_babe).args,
            vec![0xcafe_babe, 0xdead_beef]
        );
        assert_eq!(bv_val64(0xdead_beef_cafe_babe).params, 64);

        // BV ALU: code = op | BCF_BV. BPF_ADD = 0x00 so add expr's code is 0.
        assert_eq!(bv_alu(BPF_ADD, 5, 6, 64).code, 0x00);
        assert_eq!(bv_alu(BPF_AND, 5, 6, 32).code, BPF_AND);
        assert_eq!(bv_alu(BPF_RSH, 5, 6, 64).code, BPF_RSH);

        // BV predicate (result type Bool): code = op | BCF_BOOL.
        assert_eq!(bv_pred(BPF_JLE, 5, 6).code, BPF_JLE | BCF_BOOL);
        assert_eq!(bv_pred(BPF_JSGT, 5, 6).code, BPF_JSGT | BCF_BOOL);

        // Bool literal: code = BCF_VAL | BCF_BOOL, params low bit = literal.
        assert_eq!(pred_false().code, BCF_VAL | BCF_BOOL);
        assert_eq!(pred_false().code, 0x09);
        assert_eq!(pred_false().params, BCF_FALSE);
        assert_eq!(pred_true().params, BCF_TRUE);
    }

    #[test]
    fn round_trip_simple() {
        let proof = BcfProof {
            exprs: vec![
                bv_var(64),                      // slot 0
                bv_val64(0xdead_beef_cafe_babe), // slot 1 (1+2 = 3 slots → next slot 4)
                bv_alu(BPF_ADD, 0, 1, 64),       // slot 4
                pred_disj(vec![0, 4]),           // slot 7
            ],
            steps: vec![
                // Assume rule (CORE class): 0 premises, 1 parameter (assumed expr).
                BcfProofStep {
                    rule: BCF_RULE_CORE | BCF_RULE_ASSUME,
                    premise_cnt: 0,
                    args: vec![7],
                },
                // Refl rule (CORE class): 0 premises, 1 parameter (the term).
                BcfProofStep {
                    rule: BCF_RULE_CORE | BCF_RULE_REFL,
                    premise_cnt: 0,
                    args: vec![0],
                },
            ],
        };
        let bytes = proof.to_bytes();
        let parsed = BcfProof::from_bytes(&bytes).expect("parse failed");
        assert_eq!(parsed.exprs.len(), proof.exprs.len());
        assert_eq!(parsed.steps.len(), proof.steps.len());
        let reser = parsed.to_bytes();
        assert_eq!(bytes, reser, "byte-for-byte round-trip");
    }

    #[test]
    fn round_trip_real_proof() {
        // Round-trip a real BCF proof from BCF's pre-generated benchmark set.
        // This cross-validates our serializer/parser against actual cvc5 output.
        // Skipped if the BCF clone isn't present on this machine.
        let path = "/Users/yalucai/BCF/bcf-proofs/bench_1000.bcf";
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return,
        };
        let parsed = BcfProof::from_bytes(&bytes).expect("parse failed");
        let reser = parsed.to_bytes();
        assert_eq!(bytes, reser, "byte-for-byte round-trip on real bench proof");
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = BcfProof::default().to_bytes();
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        match BcfProof::from_bytes(&bytes) {
            Err(BcfError::BadMagic(_)) => {}
            other => panic!("expected BadMagic, got {:?}", other),
        }
    }

    #[test]
    fn truncated_buffer_rejected() {
        let bytes = vec![0u8; 8];
        match BcfProof::from_bytes(&bytes) {
            Err(BcfError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {:?}", other),
        }
    }
}
