//! SMT-LIB v2 encoder for [`SymbolicState`] DAGs.
//!
//! Walks a BCF expression DAG and emits an SMT-LIB query suitable for cvc5.
//! Used to feed a refinement condition (path constraints + safety goal) to
//! the BCF-patched cvc5 binary, which returns a BCF-format proof if the
//! conjunction is unsat.
//!
//! Output shape:
//! ```text
//! (set-logic QF_BV)
//! (declare-const sym0 (_ BitVec W0))
//! ...
//! (assert <path_cond_0>)
//! (assert <path_cond_1>)
//! ...
//! (assert <refine_cond>)
//! (check-sat)
//! ```
//!
//! No `(get-proof)` is emitted — proof bytes flow via cvc5's
//! `--bcf-proof-out=<path>` channel, which the [`super::solver`] sets.

use std::collections::HashMap;
use std::fmt::Write;

use super::bcf::*;
use super::symbolic::SymbolicState;

#[derive(Debug)]
pub enum SmtlibError {
    /// An expression code we don't know how to render.
    UnsupportedCode { code: u8, slot: u32 },
    /// Malformed expression (e.g. wrong vlen for the op).
    Malformed(String),
    /// Expression-DAG index is dangling (not present in the state's exprs).
    DanglingRef(u32),
}

impl std::fmt::Display for SmtlibError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmtlibError::UnsupportedCode { code, slot } => {
                write!(f, "unsupported BCF code 0x{:02x} at slot {}", code, slot)
            }
            SmtlibError::Malformed(s) => write!(f, "malformed expression: {}", s),
            SmtlibError::DanglingRef(s) => write!(f, "dangling expression ref to slot {}", s),
        }
    }
}

impl std::error::Error for SmtlibError {}

pub type Result<T> = std::result::Result<T, SmtlibError>;

/// Encode `state`'s path conditions + refinement condition into an SMT-LIB
/// query string. Each variable in the DAG becomes a `(declare-const symN ...)`
/// in the output.
pub fn encode(state: &SymbolicState) -> Result<String> {
    // ----- Pass 1: discover variables in DAG order, assign stable names. -----
    let mut var_names: HashMap<u32, String> = HashMap::new();
    let mut var_decls: Vec<(String, u16)> = Vec::new(); // (name, width)
    let mut visited: HashMap<u32, ()> = HashMap::new();

    // Walk roots that will become assertions.
    let mut roots: Vec<u32> = state.path_conds.clone();
    if let Some(rc) = state.refine_cond {
        roots.push(rc);
    }
    for &r in &roots {
        collect_vars(state, r, &mut visited, &mut var_names, &mut var_decls)?;
    }

    // ----- Pass 2: emit the SMT-LIB. -----
    //
    // CRITICAL: BCF's userspace `bcf-checker` rejects proofs derived from
    // multiple top-level `(assert …)` forms with `-EINVAL` (silently in
    // non-batch mode); wrapping the same conjuncts inside one
    // `(assert (and …))` is accepted. The kernel checker mirrors this
    // (the on-disk proof format encodes a single goal). So we emit all
    // path conditions + the refinement condition as ONE assertion via
    // a top-level `and`.
    let mut out = String::new();
    out.push_str("(set-logic QF_BV)\n");
    for (name, width) in &var_decls {
        writeln!(out, "(declare-const {} (_ BitVec {}))", name, width).unwrap();
    }
    // Emit the assertion in the **nested** kernel-shape used by
    // `build_goal_root` and the kernel's `bcf_refine` (verifier.c:24533).
    // For N >= 2 path conds, kernel produces
    // `CONJ(CONJ(pc0, pc1, ..., pcN), refine_cond)` — 2-arg outer wrapping
    // an N-arg inner CONJ. cvc5's proof's `assume` step preserves the
    // input AST structure; emitting flat `(and pc0 ... pcN rc)` would
    // cause `bcf_check_proof` to reject the proof against `goal_root`
    // because the structures don't match.
    let rc = state.refine_cond;
    let pcs = &state.path_conds;
    match (pcs.len(), rc) {
        (0, None) => {
            // No assertions — trivial sat. Emit a well-formed file.
            out.push_str("(assert true)\n");
        }
        (0, Some(rc)) => {
            // Bare refine_cond.
            write!(out, "(assert ").unwrap();
            render(state, rc, &var_names, &mut out)?;
            out.push_str(")\n");
        }
        (1, None) => {
            // One path_cond, no refine_cond — bare.
            write!(out, "(assert ").unwrap();
            render(state, pcs[0], &var_names, &mut out)?;
            out.push_str(")\n");
        }
        (1, Some(rc)) => {
            // 2-arg CONJ(pc0, rc).
            out.push_str("(assert (and ");
            render(state, pcs[0], &var_names, &mut out)?;
            out.push(' ');
            render(state, rc, &var_names, &mut out)?;
            out.push_str("))\n");
        }
        (_, None) => {
            // N >= 2 path_conds, no refine_cond — flat N-arg CONJ.
            out.push_str("(assert (and");
            for &c in pcs {
                out.push(' ');
                render(state, c, &var_names, &mut out)?;
            }
            out.push_str("))\n");
        }
        (_, Some(rc)) => {
            // N >= 2 path_conds + refine_cond — nested
            // CONJ(CONJ(pc0..pcN), rc) matching kernel `bcf_refine`.
            out.push_str("(assert (and (and");
            for &c in pcs {
                out.push(' ');
                render(state, c, &var_names, &mut out)?;
            }
            out.push_str(") ");
            render(state, rc, &var_names, &mut out)?;
            out.push_str("))\n");
        }
    }
    out.push_str("(check-sat)\n");
    Ok(out)
}

// ---------- variable discovery ----------

fn collect_vars(
    state: &SymbolicState,
    idx: u32,
    visited: &mut HashMap<u32, ()>,
    names: &mut HashMap<u32, String>,
    decls: &mut Vec<(String, u16)>,
) -> Result<()> {
    if visited.contains_key(&idx) {
        return Ok(());
    }
    visited.insert(idx, ());
    let e = state.expr_at(idx).ok_or(SmtlibError::DanglingRef(idx))?;
    let (ty, op) = (expr_type(e.code), expr_op(e.code));
    if ty == BCF_BV && op == BCF_VAR {
        let name = format!("sym{}", decls.len());
        decls.push((name.clone(), e.params));
        names.insert(idx, name);
        return Ok(());
    }
    // BV constants and bool literals carry their value in args/params, no var to
    // declare. Otherwise recurse into args.
    if !((ty == BCF_BV || ty == BCF_BOOL) && op == BCF_VAL) {
        for &a in &e.args {
            collect_vars(state, a, visited, names, decls)?;
        }
    }
    Ok(())
}

// ---------- rendering ----------

fn render(
    state: &SymbolicState,
    idx: u32,
    names: &HashMap<u32, String>,
    out: &mut String,
) -> Result<()> {
    let e = state.expr_at(idx).ok_or(SmtlibError::DanglingRef(idx))?;
    let ty = expr_type(e.code);
    let op = expr_op(e.code);

    match (ty, op) {
        // ---------- BV variable ----------
        (BCF_BV, BCF_VAR) => {
            let name = names.get(&idx).ok_or_else(|| {
                SmtlibError::Malformed(format!("variable at slot {} missing from name table", idx))
            })?;
            out.push_str(name);
        }

        // ---------- BV constant ----------
        (BCF_BV, BCF_VAL) => {
            let width = bv_width(e.params) as u32;
            if width == 0 || width > 64 {
                return Err(SmtlibError::Malformed(format!(
                    "BV val at slot {} has unsupported width {}",
                    idx, width
                )));
            }
            let val: u64 = match e.args.len() {
                1 => e.args[0] as u64,
                2 => (e.args[0] as u64) | ((e.args[1] as u64) << 32),
                n => {
                    return Err(SmtlibError::Malformed(format!(
                        "BV val at slot {} has unsupported vlen {}",
                        idx, n
                    )));
                }
            };
            // SMT-LIB hex literal: `#x<hex>` requires width divisible by 4.
            // Use `(_ bv<value> <width>)` form for arbitrary widths.
            if width.is_multiple_of(4) {
                let hex_digits = (width / 4) as usize;
                let mask: u64 = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                write!(out, "#x{:0width$x}", val & mask, width = hex_digits).unwrap();
            } else {
                let mask: u64 = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                write!(out, "(_ bv{} {})", val & mask, width).unwrap();
            }
        }

        // ---------- BV zero/sign-extend ----------
        (BCF_BV, BCF_ZERO_EXTEND) | (BCF_BV, BCF_SIGN_EXTEND) => {
            let ext = ext_len(e.params);
            let kw = if op == BCF_ZERO_EXTEND {
                "zero_extend"
            } else {
                "sign_extend"
            };
            ensure_vlen(idx, e, 1)?;
            write!(out, "((_ {} {}) ", kw, ext).unwrap();
            render(state, e.args[0], names, out)?;
            out.push(')');
        }

        // ---------- BV extract ----------
        (BCF_BV, BCF_EXTRACT) => {
            let start = extract_start(e.params);
            let end = extract_end(e.params);
            ensure_vlen(idx, e, 1)?;
            write!(out, "((_ extract {} {}) ", start, end).unwrap();
            render(state, e.args[0], names, out)?;
            out.push(')');
        }

        // ---------- BV bvnot (unary) ----------
        (BCF_BV, BCF_BVNOT) => {
            ensure_vlen(idx, e, 1)?;
            out.push_str("(bvnot ");
            render(state, e.args[0], names, out)?;
            out.push(')');
        }

        // ---------- BV concat (n-ary) ----------
        (BCF_BV, BCF_CONCAT) => {
            render_nary(state, e, "concat", names, out)?;
        }

        // ---------- BV ALU (binary) ----------
        (BCF_BV, op) => {
            // `op` is a BPF ALU opcode used as a BV operator.
            let name = bv_alu_smt_op(op).ok_or(SmtlibError::UnsupportedCode {
                code: e.code,
                slot: idx,
            })?;
            if op == BPF_NEG {
                ensure_vlen(idx, e, 1)?;
                write!(out, "({} ", name).unwrap();
                render(state, e.args[0], names, out)?;
                out.push(')');
            } else {
                ensure_vlen(idx, e, 2)?;
                write!(out, "({} ", name).unwrap();
                render(state, e.args[0], names, out)?;
                out.push(' ');
                render(state, e.args[1], names, out)?;
                out.push(')');
            }
        }

        // ---------- Boolean literal ----------
        (BCF_BOOL, BCF_VAL) => {
            if bool_literal(e.params) == BCF_TRUE {
                out.push_str("true");
            } else {
                out.push_str("false");
            }
        }

        // ---------- Boolean variable (rare; we mostly use BV vars) ----------
        (BCF_BOOL, BCF_VAR) => {
            let name = names.get(&idx).ok_or_else(|| {
                SmtlibError::Malformed(format!(
                    "bool variable at slot {} missing from name table",
                    idx
                ))
            })?;
            out.push_str(name);
        }

        // ---------- Boolean ops ----------
        (BCF_BOOL, BCF_CONJ) => render_nary(state, e, "and", names, out)?,
        (BCF_BOOL, BCF_DISJ) => render_nary(state, e, "or", names, out)?,
        (BCF_BOOL, BCF_IMPLIES) => render_nary(state, e, "=>", names, out)?,
        (BCF_BOOL, BCF_NOT) => {
            ensure_vlen(idx, e, 1)?;
            out.push_str("(not ");
            render(state, e.args[0], names, out)?;
            out.push(')');
        }

        // ---------- BV predicates (result type Bool) ----------
        (BCF_BOOL, op) => {
            let name = bv_pred_smt_op(op).ok_or(SmtlibError::UnsupportedCode {
                code: e.code,
                slot: idx,
            })?;
            ensure_vlen(idx, e, 2)?;
            write!(out, "({} ", name).unwrap();
            render(state, e.args[0], names, out)?;
            out.push(' ');
            render(state, e.args[1], names, out)?;
            out.push(')');
        }

        _ => {
            return Err(SmtlibError::UnsupportedCode {
                code: e.code,
                slot: idx,
            });
        }
    }
    Ok(())
}

fn render_nary(
    state: &SymbolicState,
    e: &BcfExpr,
    op_name: &str,
    names: &HashMap<u32, String>,
    out: &mut String,
) -> Result<()> {
    if e.args.is_empty() {
        return Err(SmtlibError::Malformed(format!(
            "{}-ary expression must have ≥ 1 args",
            op_name
        )));
    }
    write!(out, "({}", op_name).unwrap();
    for &a in &e.args {
        out.push(' ');
        render(state, a, names, out)?;
    }
    out.push(')');
    Ok(())
}

fn ensure_vlen(idx: u32, e: &BcfExpr, expected: usize) -> Result<()> {
    if e.args.len() != expected {
        return Err(SmtlibError::Malformed(format!(
            "expr at slot {} (code 0x{:02x}) needs vlen {}, got {}",
            idx,
            e.code,
            expected,
            e.args.len()
        )));
    }
    Ok(())
}

// ---------- opcode → SMT-LIB operator mapping ----------

/// Map a BPF ALU opcode to its SMT-LIB BV operator.
fn bv_alu_smt_op(op: u8) -> Option<&'static str> {
    Some(match op {
        BPF_ADD => "bvadd",
        BPF_SUB => "bvsub",
        BPF_MUL => "bvmul",
        BPF_DIV => "bvudiv",
        BPF_OR => "bvor",
        BPF_AND => "bvand",
        BPF_LSH => "bvshl",
        BPF_RSH => "bvlshr",
        BPF_NEG => "bvneg",
        BPF_MOD => "bvurem",
        BPF_XOR => "bvxor",
        BPF_ARSH => "bvashr",
        _ => return None,
    })
}

/// Map a BPF JMP opcode (used as a BV predicate) to its SMT-LIB operator.
fn bv_pred_smt_op(op: u8) -> Option<&'static str> {
    Some(match op {
        BPF_JEQ => "=",
        BPF_JNE => "distinct",
        BPF_JGT => "bvugt",
        BPF_JGE => "bvuge",
        BPF_JLT => "bvult",
        BPF_JLE => "bvule",
        BPF_JSGT => "bvsgt",
        BPF_JSGE => "bvsge",
        BPF_JSLT => "bvslt",
        BPF_JSLE => "bvsle",
        _ => return None,
    })
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refinement::solver;

    /// Build the same shift_constraint formula as `symbolic::tests`, encode to
    /// SMT-LIB, and assert the resulting string contains the expected
    /// declarations and assertions.
    fn build_shift_constraint() -> SymbolicState {
        let mut s = SymbolicState::new();
        let sym32 = s.add_var(32);
        let mask32 = s.add_val32(0xff);
        let masked32 = s.add_alu(BPF_AND, sym32, mask32, 32);
        let r0 = s.zext_32_to_64(masked32);
        s.bind_reg(0, r0);
        s.bind_reg(1, r0);
        let neg16 = s.add_val64((-16_i64) as u64);
        let off = s.add_alu(BPF_ADD, neg16, r0, 64);
        s.bind_reg(2, off);
        let one64 = s.add_val64(1);
        let r1_shifted = s.add_alu(BPF_RSH, r0, one64, 64);
        s.bind_reg(1, r1_shifted);
        let four64 = s.add_val64(4);
        let p_fall = s.add_pred(BPF_JLE, r1_shifted, four64);
        s.add_cond(p_fall);
        let neg1 = s.add_val64((-1_i64) as u64);
        let oob = s.add_pred(BPF_JSGT, off, neg1);
        s.set_refine_cond(oob);
        s
    }

    #[test]
    fn shift_constraint_smtlib_structure() {
        let state = build_shift_constraint();
        let smt = encode(&state).expect("encode failed");

        assert!(smt.starts_with("(set-logic QF_BV)"), "got:\n{}", smt);
        assert!(
            smt.contains("(declare-const sym0 (_ BitVec 32))"),
            "got:\n{}",
            smt
        );
        assert!(smt.contains("(bvand sym0 #x000000ff)"), "got:\n{}", smt);
        assert!(smt.contains("((_ zero_extend 32)"), "got:\n{}", smt);
        // Mask 0xff: literal renders as 8-hex-digit constant since width 32.
        assert!(smt.contains("(bvadd"), "got:\n{}", smt);
        assert!(smt.contains("(bvlshr"), "got:\n{}", smt);
        // Path cond is r1 ≤ 4 = bvule.
        assert!(smt.contains("(bvule"), "got:\n{}", smt);
        // Refinement is off s> -1 = bvsgt.
        assert!(smt.contains("(bvsgt"), "got:\n{}", smt);
        assert!(smt.ends_with("(check-sat)\n"), "got:\n{}", smt);
    }

    #[test]
    fn boolean_literal_renders() {
        let mut s = SymbolicState::new();
        // bool literal true; assert it (silly but exercises the path).
        let t = s.push_expr(pred_true());
        s.add_cond(t);
        let smt = encode(&s).expect("encode failed");
        assert!(smt.contains("(assert true)"), "got:\n{}", smt);
    }

    #[test]
    fn nonstandard_width_uses_bv_form() {
        // A 5-bit constant must use `(_ bv<v> 5)`, not `#x...`.
        let mut s = SymbolicState::new();
        let v = s.push_expr(BcfExpr {
            code: BCF_VAL | BCF_BV,
            params: 5,
            args: vec![0b10011],
        });
        let eq = s.add_pred(BPF_JEQ, v, v);
        s.add_cond(eq);
        let smt = encode(&s).expect("encode failed");
        assert!(smt.contains("(_ bv19 5)"), "got:\n{}", smt);
    }

    /// End-to-end: encode the shift_constraint refinement, hand to cvc5,
    /// confirm `unsat`. When the `bcf-checker` binary is also present
    /// (Linux), pipe the proof through it for full soundness validation.
    #[test]
    fn shift_constraint_end_to_end_via_cvc5() {
        if solver::cvc5_path().is_err() {
            eprintln!("[skip] cvc5 binary not found; set ALIVIO_CVC5 to enable");
            return;
        }
        let state = build_shift_constraint();
        let smt = encode(&state).expect("encode failed");
        let bytes = solver::solve(&smt).expect("solve failed");
        assert!(bytes.len() >= 12);
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(magic, BCF_MAGIC);
        let proof = BcfProof::from_bytes(&bytes).expect("BCF parse failed");
        assert!(!proof.exprs.is_empty());
        assert!(!proof.steps.is_empty());

        // If bcf-checker is available (Linux only), use it as the canonical
        // proof oracle. Failing this assertion means cvc5 emitted bytes that
        // round-trip our parser but don't satisfy the kernel rule system —
        // i.e., a real bug in our SMT-LIB encoding or formula construction.
        match solver::validate_proof_bytes(&bytes) {
            Ok(true) => eprintln!("[bcf-checker] proof accepted"),
            Ok(false) => eprintln!("[bcf-checker] not present; skipping oracle check"),
            Err(e) => panic!("bcf-checker rejected proof: {}", e),
        }
    }
}
