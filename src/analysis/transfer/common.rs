use crate::analysis::machine::error::VerificationError;
// src/analysis/transfer/common.rs
//
// Common validation utilities shared across transfer functions

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::reg_types::RegType;
use crate::analysis::machine::state::State;
use crate::ast::Operand;

/// Eagerly materialize `reg`'s BCF expression on a source-operand read.
///
/// Faithful mirror of the kernel's `check_reg_arg` SRC_OP hook
/// (verifier.c:4083-4087):
///
/// ```c
/// if (env->bcf.tracking && !tnum_is_const(reg->var_off)) {
///     bcf_reg_expr(env, reg, false);
/// ```
///
/// The kernel binds a non-constant register's `bcf_expr` (emitting its
/// `bcf_bound_reg` bound predicates into `br_conds`) the FIRST time the
/// register is read as a source operand of ANY instruction — including a
/// plain spill/store, NOT only at ALU/branch sites. Materializing only
/// inside the ALU/branch mirrors would drop the bound preds (e.g. a
/// load's umax `JLE` clause) for a value spilled before its first branch.
///
/// Scoped to SCALAR non-const regs: the kernel's `!tnum_is_const`
/// guard skips constants, and pointer regs almost always have a const
/// `var_off` (so the kernel skips them too); the rare PTR_TO_STACK
/// variable-offset case is handled by refine_stack's distance interval,
/// not here. `reg_expr`/`materialize_reg` is idempotent (returns the
/// cached slot if already bound), matching `bcf_reg_expr`'s lazy reuse.
fn bcf_materialize_src(state: &mut State, reg: Reg) {
    if reg == Reg::R10 || state.bcf.is_none() {
        return;
    }
    if !matches!(state.types.get(reg), RegType::ScalarValue) {
        return;
    }
    // Kernel `!tnum_is_const(reg->var_off)` — a known constant is left
    // unmaterialized (handled as a literal at use).
    if state.domain.get_fixed_value(reg).is_some() || state.get_tnum(reg).is_const() {
        return;
    }
    let Some(idx) = reg.bcf_idx() else { return };
    let pc = state.pc;
    let bounds = crate::analysis::transfer::alu::helpers::bcf_reg_bounds(state, reg);
    if let Some(bcf) = state.bcf.as_mut() {
        bcf.set_current_pc(pc);
        bcf.reg_expr(idx, &bounds, false);
    }
}

/// Checks if a register is readable (has been initialized).
/// Returns true if readable, false if not (and records error).
pub(crate) fn check_reg_readable(env: &mut VerifierEnv, state: &mut State, reg: Reg) -> bool {
    check_reg_readable_ex(env, state, reg, true)
}

/// Like [`check_reg_readable`] but `materialize=false` performs the
/// readability check WITHOUT eagerly binding the reg's bcf_expr. The kernel
/// materializes a branch operand's bound conjuncts in `record_path_cond`
/// (post-narrow, via `bcf_bound_reg`), NOT at the source-operand read; a
/// branch LHS that this read would otherwise materialize PRE-narrow (umin=0)
/// then loses the kernel's `u>= K` lower-bound conjunct on the narrowing
/// (taken) side. Deferring lets `record_path_cond_for_side` re-materialize it
/// post-narrow so `[u>=K, u<=M]` emit together before the branch cond.
/// Gated by the caller.
pub(crate) fn check_reg_readable_ex(
    env: &mut VerifierEnv,
    state: &mut State,
    reg: Reg,
    materialize: bool,
) -> bool {
    // R10 (frame pointer) is always readable
    if reg == Reg::R10 {
        return true;
    }

    let reg_type = state.types.get(reg);

    match reg_type {
        RegType::NotInit => {
            // The kernel's `check_reg_arg` rejects an uninitialized
            // register read with `-EACCES` ("R%d !read_ok") and (when
            // `env->bcf.tracking` is off) triggers `bcf_refine` to
            // probe whether the path itself can be proven unreachable.
            // Mirror that BCF-faithful reactive discharge: try a
            // cvc5-checked path-unreachable proof; on success emit a
            // `kind=UNREACHABLE` bundle entry and silently prune the
            // state. cvc5 is sound, so an UNSAT result is a genuine
            // proof of unreachability and no false accept can leak.
            if crate::analysis::transfer::branch::try_emit_path_unreachable_entry(env, state) {
                log::info!(
                    target: "app",
                    "[bcf] reactive path-unreachable: discharged !read_ok reject at pc {} for {:?} (cvc5 proof, kind=UNREACHABLE) — continuing path (check_reg_arg semantics)",
                    state.pc, reg
                );
                // Kernel check_reg_arg (verifier.c:4136-4140): a discharged
                // !read_ok reject `return 0`s — the read check PASSES and
                // the proven-unreachable path CONTINUES with the reg still
                // NOT_INIT. Only the mem-access (:8319-8330) and call
                // (:21225-21241) discharge sites prune on KIND_UNREACHABLE;
                // check_reg_arg's hook ignores path_unreachable entirely.
                // No bcf_path_unreachable, no materialization: the kernel
                // binds exprs only for inited regs.
                return true;
            }
            env.fail(VerificationError::RegisterNotReadable { pc: state.pc, reg });
            false
        }
        _ => {
            // Faithful kernel `check_reg_arg` SRC_OP hook: bind the
            // reg's bcf_expr on first source-operand read.
            if materialize {
                bcf_materialize_src(state, reg);
            }
            true
        }
    }
}

/// Checks if an operand is readable.
/// For immediate operands, always returns true.
/// For register operands, checks if the register is initialized.
pub(crate) fn check_operand_readable(
    env: &mut VerifierEnv,
    state: &mut State,
    operand: &Operand,
) -> bool {
    match operand {
        Operand::Imm(_) => true,
        Operand::Reg(r) => check_reg_readable(env, state, *r),
    }
}

pub(crate) fn check_reg_writable(env: &mut VerifierEnv, state: &State, reg: Reg) -> bool {
    if reg == Reg::R10 {
        env.fail(VerificationError::RegisterNotWritable { pc: state.pc, reg });
        return false;
    }
    true
}
