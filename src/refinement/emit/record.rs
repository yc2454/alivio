// BCF path-cond recording at branches — kernel record_path_cond mirror.
// Called from transfer_if per resolved side; pure BCF, no core-state writes.

use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::analysis::transfer::alu::helpers::bcf_reg_bounds;
use crate::ast::{CmpOp, Operand, Width};
use crate::refinement::bcf::BPF_AND;
use crate::refinement::symbolic::RegBounds;

/// Map an AST `CmpOp` to the (taken, not-taken) BCF/BPF jump-op byte pair.
/// Returns `None` for ops we don't yet symbolically model (JSET — encoded
/// as `(x & y) ≠ 0`, special-cased in BCF; deferred to Phase 2).
pub(crate) fn cmp_op_to_bcf_pair(op: CmpOp) -> Option<(u8, u8)> {
    use crate::refinement::bcf::{
        BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT, BPF_JNE, BPF_JSGE, BPF_JSGT, BPF_JSLE,
        BPF_JSLT,
    };
    Some(match op {
        CmpOp::Eq => (BPF_JEQ, BPF_JNE),
        CmpOp::Ne => (BPF_JNE, BPF_JEQ),
        CmpOp::UGt => (BPF_JGT, BPF_JLE),
        CmpOp::UGe => (BPF_JGE, BPF_JLT),
        CmpOp::ULt => (BPF_JLT, BPF_JGE),
        CmpOp::ULe => (BPF_JLE, BPF_JGT),
        CmpOp::SGt => (BPF_JSGT, BPF_JSLE),
        CmpOp::SGe => (BPF_JSGE, BPF_JSLT),
        CmpOp::SLt => (BPF_JSLT, BPF_JSGE),
        CmpOp::SLe => (BPF_JSLE, BPF_JSGT),
        CmpOp::Test => return None,
    })
}

/// Kernel-mirror of `record_path_cond` (verifier.c:21072) for one branch
/// successor. Builds the branch's predicate in `state`'s own bcf DAG and
/// appends it to that state's `path_conds`. Called once per side from
/// `transfer_if` after `refine_branch` has finalized the side's reg
/// types (which is when the kernel runs `record_path_cond`, at the next
/// insn's prologue — by then any `mark_ptr_or_null_reg` demote/promote
/// has already happened).
///
/// `op_byte_for_side` is the BPF jump-op encoding for this side's
/// predicate (taken op for state_then, reversed for state_else). For
/// JSET, the side's pred wraps `AND(dst,src)` in a JEQ/JNE against 0
/// per verifier.c:20917-20927.
///
/// `narrow_for_side` carries the K==K-rewrite metadata for this side
/// (None on the side where LHS doesn't collapse to a const). See
/// `try_prove_unreachable` rewrite gate.
///
/// `src_pc` tags emitted path_conds (and lazy bound preds) for the
/// kernel's `bcf_track` suffix-only filter at refinement time.
pub(crate) fn record_path_cond_for_side(
    state: &mut State,
    width: Width,
    left: Reg,
    op: CmpOp,
    op_byte_for_side: u8,
    right: &Operand,
    src_pc: usize,
    narrow_for_side: Option<(u64, u8, bool, Option<usize>)>,
    // Pre-narrow LHS bounds (the reg's range as of ENTERING this branch,
    // before reg_set_min_max narrows it on the taken/not-taken side).
    // The discharge faithful-fold uses this to mirror the kernel's
    // bcf_reg_expr, which materializes a reg at its first reference with
    // the range BEFORE the current insn's narrowing (so a reload narrowed
    // to ==6 stays a VAR{JLE0xff}+JEQ6 rather than folding to `K6 JEQ K6`).
    pre_lhs_bounds: RegBounds,
) {
    if state.bcf.is_none() {
        return;
    }
    let Some(l_idx) = left.bcf_idx() else {
        return;
    };
    // Mirror kernel `record_path_cond` (verifier.c:21104): skip
    // emission when either operand isn't a SCALAR_VALUE. Checked
    // per-side because OR_NULL pointers demote to SCALAR_VALUE only
    // on the null branch (`mark_ptr_or_null_reg`, verifier.c:17318),
    // so kernel records the path_cond on the null side and skips
    // the non-null side.
    if !state.types.get(left).is_scalar() {
        return;
    }
    if let Operand::Reg(r) = right
        && !state.types.get(*r).is_scalar()
    {
        return;
    }
    let jmp32 = width == Width::W32;
    let lhs_bounds = bcf_reg_bounds(state, left);
    let rhs_bounds = match right {
        Operand::Reg(r) => Some(bcf_reg_bounds(state, *r)),
        _ => None,
    };
    let bcf = state.bcf.as_mut().expect("checked above");
    bcf.set_current_pc(src_pc);
    // Snapshot LHS's bcf_expr materialization PC before reg_expr lazy-
    // materializes (consumed by the K==K rewrite gate).
    let lhs_materialize_pc: Option<usize> = bcf.get_reg_pc(l_idx);
    // PATH B: was the LHS reg uncached entering THIS branch? (kernel
    // `bcf_pre == -1` → `bcf_bound_reg` emits its bound conjuncts; cached →
    // none). Captured before reg_expr materializes it.
    let lhs_was_uncached = lhs_materialize_pc.is_none();
    // Kernel `bcf_reg_expr` materializes an operand's VAR + bounds from its
    // bounds AT first reference; there is no op-type-dependent pre/post-narrow
    // rule, so the LHS always materializes from its current (`lhs_bounds`) range.
    let cmp_l = bcf.reg_expr(l_idx, &lhs_bounds, jmp32);
    let rhs_idx: Option<usize> = match right {
        Operand::Reg(r) => r.bcf_idx(),
        _ => None,
    };
    let rhs_was_uncached = rhs_idx
        .map(|ri| bcf.get_reg_pc(ri).is_none())
        .unwrap_or(false);
    let cmp_r = match right {
        Operand::Imm(c) => {
            let v = if jmp32 { (*c as u32) as u64 } else { *c as u64 };
            bcf.add_val(v, jmp32)
        }
        Operand::Reg(r) => match r.bcf_idx() {
            Some(ri) => bcf.reg_expr(ri, &rhs_bounds.unwrap(), jmp32),
            None => bcf.add_val(0, jmp32),
        },
    };
    // Debug: at in-trace-range branch pcs, print the LHS materialization
    // decision (cached-vs-fresh, bounds const-ness, resulting cmp_l kind).
    if crate::analysis::trace_pc_in_range(src_pc) {
        let cmp_l_kind = match bcf.expr_at(cmp_l) {
            Some(e) => format!("code={:#04x} nargs={}", e.code, e.args.len()),
            None => "?".into(),
        };
        eprintln!(
            "[rpc] src_pc={} side_op={:#04x} l_idx={} was_cached_at={:?} lhs_bounds(const={:?} u=[{:#x},{:#x}]) pre_const={:?} narrow={} cmp_l({})",
            src_pc,
            op_byte_for_side,
            l_idx,
            lhs_materialize_pc,
            lhs_bounds.const_val,
            lhs_bounds.umin,
            lhs_bounds.umax,
            pre_lhs_bounds.const_val,
            narrow_for_side.is_some(),
            cmp_l_kind,
        );
    }
    // Operand bound conjuncts are emitted at first materialization in
    // materialize_reg (kernel bcf_reg_expr→bcf_bound_reg, read OR branch).
    let pred = if op != CmpOp::Test {
        bcf.add_pred(op_byte_for_side, cmp_l, cmp_r)
    } else {
        // JSET: kernel record_path_cond (verifier.c:20917-20927).
        // The op_byte_for_side is already BPF_JNE (taken) or BPF_JEQ
        // (not-taken) per cmp_op_to_side_pair's special-cased pair below.
        let bits: u16 = if jmp32 { 32 } else { 64 };
        let and_expr = bcf.add_alu(BPF_AND, cmp_l, cmp_r, bits);
        let zero_expr = bcf.add_val(0, jmp32);
        bcf.add_pred(op_byte_for_side, and_expr, zero_expr)
    };
    // Re-tag narrow_for_side's lhs_materialize_pc with this side's
    // freshly-captured pre-reg_expr value (per-side bcf may have a
    // different cached PC than the originator).
    let narrow_now = narrow_for_side.map(|(k, op_b, j32, _)| (k, op_b, j32, lhs_materialize_pc));
    bcf.add_cond_at_narrowed(
        pred,
        src_pc,
        narrow_now,
        Some((l_idx, lhs_materialize_pc, jmp32, lhs_bounds, pre_lhs_bounds)),
    );

    // Share-replay demand-through-copy (kernel bcf_track): a reg freshly
    // materialized at this branch whose VALUE is a copy of a stack slot
    // (same scalar id — fills copy the id via copy_register_state) is, in
    // the kernel's BACKWARD bt walk, demanded THROUGH its defining fill
    // into the SLOT — so the slot and every copy share ONE var, even when
    // the fill happened before the replay window. Mirror it forward:
    // stamp the fresh binding onto expr-less slots spilling the same id,
    // so later in-window fills restore the SAME var instead of minting a
    // second one.
    if state.bcf.as_ref().is_some_and(|b| b.replay_share_slot_vars) {
        // No was-uncached gate: the copy's binding may predate this branch
        // (start-push materialization, in-window fill, earlier read) — the
        // kernel's backward demand unifies the copy with its source slot
        // in every one of those cases.
        let mut props: Vec<(u32, u32)> = Vec::new();
        if lhs_bounds.const_val.is_none()
            && let Some(id) = state.scalar_id(left)
            && let Some(e) = state.bcf.as_ref().and_then(|b| b.get_reg(l_idx))
        {
            props.push((id, e));
        }
        if let Operand::Reg(r) = right
            && state.domain.get_fixed_value(*r).is_none()
            && let Some(ri) = r.bcf_idx()
            && let Some(id) = state.scalar_id(*r)
            && let Some(e) = state.bcf.as_ref().and_then(|b| b.get_reg(ri))
        {
            props.push((id, e));
        }
        let dbg_ss = std::env::var("ALIVIO_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1");
        if dbg_ss && (655..=660).contains(&src_pc) {
            let rdiag = if let Operand::Reg(r) = right {
                format!(
                    "uncached={} fixed={:?} id={:?} bind={:?}",
                    rhs_was_uncached,
                    state.domain.get_fixed_value(*r),
                    state.scalar_id(*r),
                    r.bcf_idx()
                        .and_then(|ri| state.bcf.as_ref().and_then(|b| b.get_reg(ri)))
                )
            } else {
                "imm".into()
            };
            eprintln!(
                "[prop] src_pc={} left={:?}(uncached={} const={:?} id={:?}) right={:?}({}) props={}",
                src_pc,
                left,
                lhs_was_uncached,
                lhs_bounds.const_val,
                state.scalar_id(left),
                right,
                rdiag,
                props.len()
            );
        }
        for (id, e) in props {
            for frame in state.frames.iter_mut() {
                let offs: Vec<i16> = frame.stack.slot_offsets();
                for off in offs {
                    if let Some(slot) = frame.stack.get_slot_mut(off)
                        && slot.bcf_expr.is_none()
                        && slot.scalar_id == Some(id)
                        && matches!(
                            slot.reg_type,
                            crate::analysis::machine::reg_types::RegType::ScalarValue
                        )
                    {
                        slot.bcf_expr = Some(e);
                        if dbg_ss {
                            eprintln!(
                                "[prop] STAMP src_pc={} id={} expr={} off={}",
                                src_pc, id, e, off
                            );
                        }
                    }
                }
            }
        }
    }
}
