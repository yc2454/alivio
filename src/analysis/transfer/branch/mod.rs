use crate::analysis::machine::error::VerificationError;
// src/analysis/transfer/branch/mod.rs

pub mod constraints;
pub mod interval_packet;
pub mod outcome;
pub mod refinement;

use either::Either::{Left, Right};
use log::warn;

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::analysis::transfer::alu::helpers::bcf_reg_bounds;
use crate::ast::{CmpOp, Instr, Operand, Width};
use crate::refinement::bcf::{BPF_AND, BPF_JEQ, BPF_JNE};
use crate::refinement::symbolic::RegBounds;

use self::constraints::apply_jmp_constraints;
use self::interval_packet::refine_packet_bounds_on_branch;
use self::outcome::condition_outcome;
use self::refinement::{propagate_scalar_links, refine_branch};
use super::common::check_operand_readable;

/// Map an AST `CmpOp` to the (taken, not-taken) BCF/BPF jump-op byte pair.
/// Returns `None` for ops we don't yet symbolically model (JSET — encoded
/// as `(x & y) ≠ 0`, special-cased in BCF; deferred to Phase 2).
fn cmp_op_to_bcf_pair(op: CmpOp) -> Option<(u8, u8)> {
    use crate::refinement::bcf::{
        BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT, BPF_JNE, BPF_JSGE, BPF_JSGT,
        BPF_JSLE, BPF_JSLT,
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
fn record_path_cond_for_side(
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
    let rhs_was_uncached = rhs_idx.map(|ri| bcf.get_reg_pc(ri).is_none()).unwrap_or(false);
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
            src_pc, op_byte_for_side, l_idx, lhs_materialize_pc,
            lhs_bounds.const_val, lhs_bounds.umin, lhs_bounds.umax,
            pre_lhs_bounds.const_val, narrow_for_side.is_some(), cmp_l_kind,
        );
    }
    // PATH B (ZOVIA_BCF_REPLAY): mirror the kernel's `bcf_bound_reg`, which
    // emits an operand's bound conjuncts INSIDE `record_path_cond` — BEFORE the
    // branch cond is pushed, in umin/umax/smin/smax order, and ONLY when the reg
    // was freshly materialized this branch (`bcf_pre == -1`). Emitting the block
    // here (before `add_cond_at_narrowed`) reproduces the kernel's
    // [u>=K, u<=M, …] block-then-branch ORDER and per-reg first-ref dedup.
    // Const-materialized operands carry no VAR → no bound block (their value is
    // emitted directly via the K==K rewrite).
    // ZOVIA_BCF_REPLAY_FIRSTREF (default-ON) disables this deferred (branch-only)
    // arm — bounds are emitted at first materialization in materialize_reg
    // instead (kernel bcf_reg_expr→bcf_bound_reg, read OR branch).
    let replay_firstref = crate::common::config::bcf_mirror_knob("ZOVIA_BCF_REPLAY_FIRSTREF", true);
    if bcf.replay_emit_bounds && !replay_firstref {
        if lhs_was_uncached && lhs_bounds.const_val.is_none() {
            for bp in bcf.bound_reg_emit_preds(cmp_l, &lhs_bounds, jmp32) {
                bcf.add_cond(bp);
            }
        }
        if rhs_was_uncached
            && let Some(rb) = rhs_bounds.as_ref()
            && rb.const_val.is_none()
        {
            for bp in bcf.bound_reg_emit_preds(cmp_r, rb, jmp32) {
                bcf.add_cond(bp);
            }
        }
    }
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
    bcf.add_cond_at_narrowed(pred, src_pc, narrow_now, Some((l_idx, lhs_materialize_pc, jmp32, lhs_bounds.clone(), pre_lhs_bounds.clone())));

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
        let dbg_ss = std::env::var("ZOVIA_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1");
        if dbg_ss && src_pc >= 655 && src_pc <= 660 {
            let rdiag = if let Operand::Reg(r) = right {
                format!(
                    "uncached={} fixed={:?} id={:?} bind={:?}",
                    rhs_was_uncached,
                    state.domain.get_fixed_value(*r),
                    state.scalar_id(*r),
                    r.bcf_idx().and_then(|ri| state.bcf.as_ref().and_then(|b| b.get_reg(ri)))
                )
            } else {
                "imm".into()
            };
            eprintln!(
                "[prop] src_pc={} left={:?}(uncached={} const={:?} id={:?}) right={:?}({}) props={}",
                src_pc, left, lhs_was_uncached, lhs_bounds.const_val,
                state.scalar_id(left), right, rdiag, props.len()
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
                            eprintln!("[prop] STAMP src_pc={} id={} expr={} off={}", src_pc, id, e, off);
                        }
                    }
                }
            }
        }
    }
}

/// Transfer function for conditional branch instructions.
pub(crate) fn transfer_if(
    env: &mut VerifierEnv,
    mut state: State,
    width: Width,
    left: Reg,
    op: CmpOp,
    right: Operand,
    target: usize,
) -> Vec<State> {
    if !crate::analysis::transfer::common::check_reg_readable_ex(
        env,
        &mut state,
        left,
        true,
    ) {
        return vec![];
    }
    if !check_operand_readable(env, &mut state, &right) {
        return vec![];
    }

    // Kernel `collect_linked_regs` + `push_insn_history(...,
    // linked_regs_pack(...))` (verifier.c check_cond_jmp_op L16497-16505):
    // record, on THIS conditional jump's breadcrumb, the scalar registers
    // sharing the compared register's scalar id, so the backward precision
    // walk's `bt_sync_linked_regs` can propagate precision across the
    // class. Kernel collects for src->id (BPF_X) and dst->id, and only
    // records when the class has > 1 member. Done from the pre-refinement
    // incoming `state` (kernel collects from `this_branch` before
    // `push_stack`/`reg_set_min_max`).
    if let Some(hidx) = env.current_step_idx {
        use crate::analysis::machine::reg_types::RegType;
        let mut linked: Vec<Reg> = Vec::new();
        let mut class_regs: Vec<Reg> = Vec::new();
        if let Operand::Reg(r) = right
            && state.types.get(r) == RegType::ScalarValue
            && let Some(id) = state.scalar_id(r)
        {
            class_regs.extend(state.regs_with_scalar_id(id));
        }
        if state.types.get(left) == RegType::ScalarValue
            && let Some(id) = state.scalar_id(left)
        {
            class_regs.extend(state.regs_with_scalar_id(id));
        }
        for lr in class_regs {
            if !linked.contains(&lr) {
                linked.push(lr);
            }
        }
        if linked.len() > 1 && !env.replay_mode {
            env.history.set_linked_regs(hidx, linked);
            // Kernel push_jmp_history(..., linked_regs_pack(...)) at
            // verifier.c:17686 is a real history ENTRY — it counts toward
            // cur->jmp_history_cnt and thus the >40 long-history force
            // valve. zovia recorded the breadcrumb without counting it;
            // on loop lineages (one linked-regs entry per compared-scalar
            // branch) that halves history growth vs the kernel — the
            // to_wep corridor unwind sat at <=21 where the kernel crossed
            // 40 and force-added its re-entry loop-head checkpoints.
            state.jmp_history_cnt = state.jmp_history_cnt.saturating_add(1);
        }
    }

    // ZOVIA_DBG_BRANCHVAL=<pc>: dump the branch operand's tracked value at
    // that pc (co-re 354 chase 2026-07-16 — kernel refutes ==0x14, zovia
    // can't; whose w8-derived value is looser?).
    if let Ok(v) = std::env::var("ZOVIA_DBG_BRANCHVAL")
        && v.parse::<usize>().ok() == Some(state.pc)
    {
        let (lo, hi) = state.domain.get_interval(left);
        let (ulo, uhi) = state.domain.get_u64_bounds(left);
        eprintln!(
            "[brval] pc={} left={:?} ivl=[{},{}] u=[{:#x},{:#x}] tn={:?} ty={:?} right={:?}",
            state.pc, left, lo, hi, ulo, uhi,
            state.get_tnum(left), state.types.get(left), right
        );
    }
    // --- STEP 1: Abstract Interpretation (Constraint Refinement) ---
    let mut state_then = state.clone();
    let mut state_else = state.clone();

    state_then.pc = target;
    state_else.pc = state.pc + 1;

    // Apply constraints to refine the DBM in the destination states
    match &right {
        Operand::Imm(imm) => apply_jmp_constraints(
            &mut state_then,
            &mut state_else,
            left,
            op,
            width,
            Right(*imm),
        ),
        Operand::Reg(r) => {
            apply_jmp_constraints(&mut state_then, &mut state_else, left, op, width, Left(*r));
            // Interval-specific: refine packet bounds from pointer comparisons
            refine_packet_bounds_on_branch(&mut state_then, &mut state_else, left, *r, op);
        }
    }

    // Scalar ID fan-out: propagate the constraint just applied to `left` to
    // every register and stack slot sharing its scalar id.
    propagate_scalar_links(&mut state_then, &mut state_else, left);

    // Precision sink at conditional branches. Kernel
    // `check_cond_jmp_op` (verifier.c v6.15 L16450-L16462) calls
    // `mark_chain_precision` ONLY when `is_branch_taken` resolves
    // (pred >= 0, one side dead). Firing on every conditional —
    // including the previous `back_edge_imm` heuristic for unresolved
    // back-edge compare-to-imm — eagerly over-marks loop counters and
    // accumulators precise, blocking subsumption across iterations and
    // multiplying calico-class visit counts. short_loop1 stays
    // kernel-REJECT without back_edge_imm: its JSET (`if r7 & 0x702000
    // goto head`) statically resolves (high bits of r7's tnum are
    // known after `r7 += 0x1ab064b9` from a u16 load), so the
    // static_resolves arm catches it.
    if let Some(hidx) = state.history_idx
        && condition_outcome(&state, width, left, op, &right).is_some()
    {
        let pcid = state.parent_cache_id;
        crate::analysis::flow::precision::mark_chain_precision_backward(env, hidx, pcid, left);
        if let Operand::Reg(r) = right {
            crate::analysis::flow::precision::mark_chain_precision_backward(env, hidx, pcid, r);
        }
    }

    // Branch Type Refinement (For map and socket pointers)
    let instr = Instr::If {
        width,
        left,
        op,
        right,
        target,
    };
    refine_branch(&mut state_then, &instr, true);
    refine_branch(&mut state_else, &instr, false);

    // --- BCF symbolic mirror: append the branch predicate to each side's
    // path_conds. Mirrors kernel `record_path_cond` (verifier.c:21072),
    // which fires at the NEXT insn's prologue — i.e. AFTER
    // mark_ptr_or_null_reg has demoted OR_NULL → SCALAR_VALUE on the
    // null branch (and promoted to non-null pointer on the other side).
    // Per-side asymmetric emission: the function checks each state's
    // own LHS/RHS types and skips emission when either isn't a SCALAR.
    // This is what lets the IG seccomp PC 89 `if r0 != 0` fall-through
    // contribute its `K0 == K0` conjunct (state_else's r0 was demoted
    // to scalar(0) by `maybe_demote_or_null_to_scalar`) while skipping
    // the taken side (state_then's r0 is non-null PtrToMapValue).
    // Pre-narrow LHS bounds: the reg's range BEFORE this branch's
    // reg_set_min_max narrowing (captured from the pre-split `state`,
    // which apply_jmp_constraints did NOT mutate). Threaded to the
    // discharge faithful-fold so reload/null regs materialize at their
    // first-reference range (kernel bcf_reg_expr), not the post-narrow
    // const that wrongly folds them to literals.
    let pre_lhs_bounds = bcf_reg_bounds(&state, left);
    if let Some((op_then, op_else)) = cmp_op_to_bcf_pair(op) {
        let jmp32 = width == Width::W32;
        let imm_k: Option<u64> = match &right {
            Operand::Imm(c) => Some(if jmp32 { (*c as u32) as u64 } else { *c as u64 }),
            _ => None,
        };
        // Pre-compute K==K rewrite metadata per side. Per
        // feedback_kernel_probe_record_path_cond_2026-05-23.md, the side
        // whose LHS narrows to const K on entry gets the rewrite
        // candidate; lhs_materialize_pc is filled in per-side inside
        // record_path_cond_for_side.
        let (narrow_then, narrow_else): (
            Option<(u64, u8, bool, Option<usize>)>,
            Option<(u64, u8, bool, Option<usize>)>,
        ) = match (op, imm_k) {
            (CmpOp::Eq, Some(k)) => (Some((k, op_then, jmp32, None)), None),
            (CmpOp::Ne, Some(k)) => (None, Some((k, op_else, jmp32, None))),
            _ => (None, None),
        };
        record_path_cond_for_side(
            &mut state_then, width, left, op, op_then, &right, state.pc, narrow_then,
            pre_lhs_bounds.clone(),
        );
        record_path_cond_for_side(
            &mut state_else, width, left, op, op_else, &right, state.pc, narrow_else,
            pre_lhs_bounds.clone(),
        );
    } else if matches!(op, CmpOp::Test) {
        // JSET — per-side wrap into AND(dst,src) JNE/JEQ 0.
        record_path_cond_for_side(
            &mut state_then, width, left, op, BPF_JNE, &right, state.pc, None,
            pre_lhs_bounds.clone(),
        );
        record_path_cond_for_side(
            &mut state_else, width, left, op, BPF_JEQ, &right, state.pc, None,
            pre_lhs_bounds.clone(),
        );
    }

    let backward_jump_forbidden = |st: &State| -> bool {
        if target >= st.pc {
            return false;
        }
        let on_path = st
            .history_idx
            .map(|idx| env.history.is_on_path(idx, target))
            .unwrap_or(false);
        let already_explored = env.explored_states.contains_key(&target);
        !on_path && !already_explored
    };

    // Faithful-discharge replay: return BOTH sides (recording already ran
    // for each above) so the replay driver can follow the dead edge at the
    // reject branch. Skips the static-fold and the discharge speculation —
    // the replay only needs the per-side path_cond, not exploration.
    if env.replay_mode {
        return vec![state_then, state_else];
    }

    // Check for statically determined branches
    if let Some(outcome) = condition_outcome(&state, width, left, op, &right) {
        // The dead side is unreachable in zovia's view. If the kernel
        // would explore that side and reject (e.g. unreachable_arsh's
        // PC 5: zovia statically rules out "w1 == 0xffffff78" but the
        // kernel's tnum loses precision on the ARSH+AND chain and
        // still explores it, hitting R2 !read_ok at PC 6), speculate
        // by attempting cvc5 unsat of the dead side's path_cond and
        // emitting a kind=UNREACHABLE bundle entry. This is the
        // matching half of kernel commit 39f5104ed029
        // (bcf_bundle_try_discharge's refine_cond=-1 → path_cond
        // fallback).
        // Pre-compute backward_jump check (uses env immutably via closure)
        // before the speculation call (uses env mutably).
        let then_backward_forbidden = outcome && backward_jump_forbidden(&state_then);
        let dead_state = if outcome { &state_else } else { &state_then };
        // Eager path-unreachable speculation is NOT a BCF mechanism:
        // every `bcf_prove_unreachable` call site in BCF (set1/0014) is
        // reactive — at a real mem-access / check_reg_arg rejection,
        // never on a statically-dead branch side. This site exists only
        // because zone/DBM makes zovia more precise than the kernel
        // (ruling out branches the kernel explores), so the single-pass
        // design pre-emitted proofs "in case". In kernel mode zovia
        // hits the *same* rejections as the kernel, so path-unreachable
        // is handled reactively (conflict-eq at the load/!read_ok sites
        // + refine_*). Restrict eager speculation to zone mode (legacy,
        // unchanged); kernel mode is reactive-only, faithful to BCF.
        if dead_state.domain.is_zone() {
            try_emit_path_unreachable_entry(env, dead_state);
        }
        return if outcome {
            if then_backward_forbidden {
                env.fail(VerificationError::BackEdge {
                    pc: state.pc,
                    target,
                });
                vec![]
            } else {
                vec![state_then]
            }
        } else {
            vec![state_else]
        };
    }

    if backward_jump_forbidden(&state_then) {
        env.fail(VerificationError::BackEdge {
            pc: state.pc,
            target,
        });
        return vec![];
    }

    // Speculatively emit a path-unreachable BCF bundle entry for any
    // branch state that zovia's abstract domain proves infeasible but
    // the kernel would explore (typically because the kernel's tnum
    // tracking loses precision across the ALU chain — see
    // `unreachable_arsh` for the ARSH+AND example). The kernel
    // ultimately rejects the dead path via `bcf_prove_unreachable` and
    // attempts a bundle discharge keyed on the path_cond's canonical
    // hash (verifier.c:24561 → bcf_bundle_try_discharge → path_cond
    // fallback, commit 39f5104ed029). If cvc5 can prove our path_cond
    // unsat, the resulting kind=UNREACHABLE entry will match the
    // kernel's hash and the kernel discharge succeeds.
    // Zone-only (same rationale as the condition_outcome site above):
    // `is_inconsistent()`-gated speculation is a DBM-ism — zone
    // manufactures branch-side contradictions the kernel smears, so
    // this is not faithful to BCF (which never speculates on
    // domain-inconsistent sides; it refines reactively at rejections).
    // Kernel mode = reactive-only. The inconsistent side is still
    // dropped below (consistent-only filter) regardless of mode.
    let zone_mode = state_then.domain.is_zone();
    if zone_mode && state_else.domain.is_inconsistent() {
        warn!("Else branch is inconsistent");
        try_emit_path_unreachable_entry(env, &state_else);
    }
    if zone_mode && state_then.domain.is_inconsistent() {
        warn!("Then branch is inconsistent");
        try_emit_path_unreachable_entry(env, &state_then);
    }

    // Return only consistent states
    let mut out = Vec::new();
    let else_ok = !state_else.domain.is_inconsistent();
    let then_ok = !state_then.domain.is_inconsistent();
    if crate::analysis::trace_pc_in_range(state.pc) {
        eprintln!(
            "[BRANCH] pc={} else_ok={} then_ok={} (else_target={} then_target={})",
            state.pc, else_ok, then_ok, state_else.pc, state_then.pc,
        );
    }
    if else_ok {
        out.push(state_else);
    }
    if then_ok {
        out.push(state_then);
    }
    out
}

/// Mirror the kernel's `bcf_refine` reg_masks=0 auto-fill for
/// `bcf_prove_unreachable` (verifier.c:24525-24534): every R0..R9 that
/// is not NOT_INIT and not a const non-scalar, then the backtrack
/// suffix base PC over that set. The kernel's `bcf_track` emits
/// br_conds only for that suffix; without this filter zovia's
/// path_cond goal carries spurious leading conditions (from its full
/// abstract-interpretation path) and its canonical hash misses the
/// kernel's bundle lookup. `None` ⇒ keep all (sound, just not as tight).
/// Kernel `bcf_refine` auto-fill `reg_masks` (verifier.c:24611-24620): the
/// live, non-const registers a reject backtracks to find its base. Shared by
/// `unreachable_base_pc` (base/anchor) AND the prev/cache-id computation so
/// the two `bcf_suffix_base_pc*` walks use an IDENTICAL mask. A drift here is
/// fatal: with the `pkt_const_off` exclusion missing on one side (pc274 keeps
/// R2=pkt → mask 0x2f6→wider), that walk empties at a DIFFERENT insn (pc99 vs
/// 207) → `parent_loc=None` → `base_cid=None` → the faithful REPLAY is skipped
/// and the 190-path family MISSes. See the per-clause rationale (PtrToCtx R9
/// drain, pkt_const_off) inline below.
fn unreachable_target_regs(
    env: &VerifierEnv,
    state: &State,
    hidx: Option<usize>,
) -> Vec<Reg> {
    use crate::analysis::machine::reg_types::RegType;
    const VARREGS: [Reg; 10] = [
        Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4,
        Reg::R5, Reg::R6, Reg::R7, Reg::R8, Reg::R9,
    ];
    let mut targets: Vec<Reg> = Vec::new();
    for &r in &VARREGS {
        let ty = state.types.get(r);
        if matches!(ty, RegType::NotInit) {
            continue;
        }
        // Faithful port of the kernel's `bcf_refine` reg_masks==0 auto-fill
        // (verifier.c:24611-24620): skip a register that is
        // `type != SCALAR_VALUE && tnum_is_const(reg->var_off)`.
        //
        // zovia has no single per-register var_off tnum, but the interval
        // domain carries the faithful analog on `PtrOffset.var_off` (its doc:
        // "kernel tnum_range(reg->var_off)"): `tnum_is_const(var_off)` holds
        // iff the pointer's offset range is a single point (`min == max`), or
        // there is no `ptr_offset` at all (types that can't hold a variable
        // offset — they demote to scalar on `ptr += reg`, or track only a const
        // embedded offset). This is the SAME reliable analog the refine-target
        // selection uses (memory/map.rs); `var_off_contributor` is NOT reliable
        // (spill/fill doesn't always clear it). One uniform rule replaces the
        // former per-RegType-variant enumeration and the PtrToPacket /
        // PtrToPacketEnd env-gated special cases (`ZOVIA_BCF_PKT_CONST_REGMASK`,
        // `ZOVIA_BCF_EXCLUDE_PKT_END`, both deleted). See
        // reference_var_off_faithful_analog.md.
        let var_off_const = state
            .domain
            .as_interval()
            .and_then(|iv| iv.get_ptr_offset(r))
            .is_none_or(|po| po.min_offset() == po.max_offset());
        if !matches!(ty, RegType::ScalarValue) && var_off_const {
            continue;
        }
        targets.push(r);
    }
    // NOTE 2026-07-02: the former `filter_live_unknown_targets` post-filter
    // (drop dead fully-unknown scalars) is REMOVED. Kernel ground truth
    // (box #38, from_nat_fib pc748): the auto-fill keeps ALL scalars —
    // verifier.c:24610-18 has no liveness/constraint check — and the
    // kernel's 0x277 mask includes the DEAD unknown R2=[0..255], whose
    // backtrack (bt_empty=561, base=521) is what children_unsafe-marks the
    // 584<-521 checkpoint and keeps the sponge-marking treadmill alive.
    // The filter dropped that R2 (0x4e6, base=584 = the checkpoint itself,
    // exclusive -> never marked -> the wide-R2 TCP-arm path merges at 584
    // and the d53 arm discharges are never produced. The cont.20 pc735
    // mask match that motivated the filter is explainable as a since-
    // healed state divergence (kernel R2=PktEnd vs zovia unknown scalar),
    // not a kernel mask rule.
    let _ = hidx;
    targets
}

fn unreachable_base_pc(env: &VerifierEnv, state: &State) -> Option<usize> {
    // Start the backtrack at the *rejecting* insn's breadcrumb (kernel
    // `backtrack_states` `last_idx = cur->insn_idx` with skip_first), and
    // return the faithful `base->insn_idx` (parent_loc at bt-empty).
    let hidx = env.current_step_idx.or(state.history_idx)?;
    let targets = unreachable_target_regs(env, state, Some(hidx));
    let base = crate::analysis::flow::precision::bcf_suffix_base_pc(env, hidx, state.parent_cache_id, &targets);
    if std::env::var("ZOVIA_DUMP_REGMASK").ok().as_deref() == Some("1") {
        let mut mask: u32 = 0;
        for &r in &targets { mask |= 1u32 << (r as u32); }
        eprintln!("[regmask] reject_pc={} mask=0x{:x} targets={:?} base={:?}",
            state.pc, mask, targets, base);
    }
    base
}

/// Kernel-faithful `reg_masks` tightening (cont.20): drop a reject `reg_masks`
/// target iff it is a fully-unknown `ScalarValue` (tnum carries no constraint)
/// AND dead at the reject PC (absent from `live_regs`). Such a register holds
/// no symbolic information and the kernel never seeds it into `reg_masks`;
/// zovia's existing const-offset / `NotInit` filter misses it (it looks like a
/// live unknown scalar), so the suffix base walk over-extends.
///
/// MEASURED (from_nat_no_log pc735, proto==6 arm): R2 is a fully-unknown dead
/// scalar there → targets `0x32f`, base 529; the kernel's `reg_masks` is
/// `0x32b` (base 559, the `78171d` obligation). This filter drops exactly R2:
/// liveness is applied ONLY to unconstrained scalars, so a constrained-but-
/// dead reg (R1, kept by the kernel) and live unknowns (R8/R9, kept) are
/// untouched — reproducing `0x32b` on every arrival. See
/// project_no_log_subsumption_arc.md cont.20.
///
/// Always-on (faithful, no-regress: gated VM run was repr-19 19/19 + cilium-17
/// 17/17, bundles byte-identical on the default-config gate). ⚠️ zovia's
/// `live_regs` is per-PC, not per-path, so on a multi-arm `_no_log` program
/// the same drop applies to every arm; it has a live effect only in the lean
/// (no-shotgun) config, where it can change which obligations are emitted.
fn filter_live_unknown_targets(
    env: &VerifierEnv,
    state: &State,
    hidx: Option<usize>,
    targets: Vec<Reg>,
) -> Vec<Reg> {
    use crate::analysis::machine::reg_types::RegType;
    let live = hidx
        .and_then(|h| env.history.get(h))
        .map(|h| h.pc)
        .and_then(|pc| env.insn_aux_data.get(pc));
    let Some(live) = live else { return targets };
    targets
        .into_iter()
        .filter(|&r| {
            let unk = state.get_tnum(r).mask == u64::MAX
                && matches!(state.types.get(r), RegType::ScalarValue);
            let dead = !live.live_regs.contains(&r);
            !(unk && dead)
        })
        .collect()
}

/// Attempt path-unreachable speculation on a zovia-infeasible state and
/// push the resulting `kind=BCF_BUNDLE_KIND_UNREACHABLE` bundle entry on
/// success. Returns `true` iff an entry was emitted. Mirrors the pattern
/// in `try_bcf_refine_stack` / `try_bcf_refine_map`.
///
/// Called from two places: (a) the zone-only branch-side eager
/// speculation here, and (b) reactively from the generic-load (scalar)
/// rejection site (`memory::access`), mirroring the kernel's
/// `bcf_prove_unreachable` at verifier.c:8224→8255.
/// Faithful discharge via base→reject replay (mirrors kernel `bcf_track`,
/// verifier.c:24633). Instead of reconstructing the goal from the live
/// state's recorded path_conds (which can include branches off the kernel's
/// actual replay path, and mis-cache pre-window materializations — see
/// from_wep_fib_dsr_debug 034f37), this re-executes the instruction path
/// from the cached base state to the reject, with a fresh bcf, so
/// `state.bcf.path_conds` is rebuilt exactly as the kernel's re-execution
/// would. Gated by `ZOVIA_BCF_REPLAY=1`. Returns the proven goal or None
/// (no base cache, path divergence, or cvc5 declined).
fn try_prove_unreachable_via_replay(
    env: &mut VerifierEnv,
    reject_state: &State,
    base_cid: u32,
) -> Vec<(i32, crate::refinement::refine_unreachable::UnreachableOk)> {
    // Each goal is tagged with its reset-ladder rung: -1 = the plain replay
    // (no reset point), k >= 0 = the pc of the If the bcf was reset after.
    // Diagnosis-only (ZOVIA_BCF_CENSUS); does not affect emission.

    let empty = Vec::new();
    // 1. Retrieve the cached base State (with its register/domain state).
    //    Live-then-retired: the kernel's bcf_track base (`st->parent`)
    //    may be an evicted (free_list) state.
    let Some(base_state) = env.state_by_cache_id(base_cid).map(|(_, s)| s.clone())
        else { return empty };
    let base_hidx = base_state.history_idx;

    // 2. Recover the forward base→reject instruction path by walking the
    //    Breadcrumb parent chain from the reject insn's breadcrumb.
    let Some(reject_bc) = env.current_step_idx else { return empty };
    let mut path: Vec<(usize, Instr)> = Vec::new();
    let mut cur = Some(reject_bc);
    let mut budget: usize = 200_000;
    while let Some(idx) = cur {
        if Some(idx) == base_hidx { break; }
        match budget.checked_sub(1) { Some(b) => budget = b, None => return empty }
        let Some(bc) = env.history.get(idx) else { return empty };
        path.push((bc.pc, bc.instr.clone()));
        cur = bc.parent_idx;
    }
    let dbg = std::env::var("ZOVIA_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1");
    if path.is_empty() { return empty; }
    path.reverse(); // forward order: base_pc .. reject branch

    let dead_target = reject_state.pc;
    let Some(reject_pc) = env.history.get(reject_bc).map(|b| b.pc) else { return empty };
    let is_branch_reject = reject_state.pc != reject_pc;
    let n_exec = if is_branch_reject { path.len() } else { path.len() - 1 };
    if n_exec == 0 { return empty; }
    if dbg {
        eprintln!("[replay] STRUCT reject_pc={} reject_state.pc={} is_branch={} path[0]={} path[last]={} len={} n_exec={}",
            reject_pc, reject_state.pc, is_branch_reject, path[0].0, path[path.len()-1].0, path.len(), n_exec);
    }

    // 3. Reset points: None = the plain replay (bcf reset at the suffix base).
    //    NARROWBASE (default-ON) adds TWO per CONDITIONAL branch step k,
    //    mirroring the two kernel base shapes around an If:
    //    - post-If reset (pre=false): bcf base PAST the narrowing — the LHS
    //      materializes POST-narrow (kernel bcf_track base = st->parent past
    //      the narrowing branch). from_nat_fib pc748: the `s>5`@523 reset
    //      point yields d53387e3 (proto `[u>=6,u<=0xff]`) the plain replay
    //      misses (it re-executes 523 → proto pre-narrow = 2af13624 shape).
    //    - pre-If reset (pre=true): kernel checkpoint AT the If insn — the
    //      replay's fresh bcf sees the If itself, so the cond records with
    //      PRE-branch materialization (VAR + current bounds, no const fold).
    //      from_nat_fib clang-16 pc230: kernel base = the pc142 checkpoint
    //      (segment [124,141]); its goal 0xcf57c36a carries
    //      `(V u<= 0x400)` + `(V==0)` where the post-If reset folds to
    //      `(0x0 == 0x0)` (r1 already narrowed to [0,0]) = cb71b139, a miss.
    //    Emitted ADDITIVELY (caller dedups by cond_hash).
    let narrowbase = crate::common::config::bcf_mirror_knob("ZOVIA_BCF_REPLAY_NARROWBASE", true);
    let mut reset_points: Vec<(Option<usize>, bool)> = vec![(None, false)];
    if narrowbase {
        for i in 0..n_exec {
            if matches!(path[i].1, Instr::If { .. }) {
                reset_points.push((Some(i), false));
                reset_points.push((Some(i), true));
            }
            // Kernel checkpoint-at-post-call-fallthrough base (pre-reset
            // only): helper-call fallthroughs are kernel jmp/prune points;
            // when the kernel's counters fire there, the demanded goal's
            // suffix starts at the post-call insn with first-refs
            // materializing fresh bounds. to_wep_debug 0xc70002dc: kernel
            // base = the pc1599 checkpoint after `call 6`@1598 (segment
            // [1519,1598]); zovia's exploration is counter-cold there
            // (env-wide reset-history skew — its extra corridor adds) so
            // no cached anchor exists; the reset-rung supplies the shape.
            if i > 0 && matches!(path[i - 1].1, Instr::Call { .. }) {
                reset_points.push((Some(i), true));
            }
        }
    }

    // Kernel bcf_track replays run in a CLEAN verification context: the
    // original reject's errno is a local in the caller (check_helper_call's
    // -EACCES → bcf_prove_unreachable), not verifier-global state, so the
    // replay's own check_helper_call passes and path conds keep recording.
    // zovia's env.error is global and still holds the triggering reject
    // here; without the stash, transfer_call's `env.failed()` kills the
    // replay at the FIRST helper call on the suffix (hep_dsr pc247: every
    // rung died at the pc153 trace_printk → no replay goals → the lean
    // fallback emitted loop-ladder reconstruction goals → kernel e4e3
    // missed). Each rung starts error-free; a rung's own fresh failure
    // dies with that rung and must not leak into the next (or the caller).
    let saved_error = env.error.take();
    let mut goals = Vec::new();
    for (reset_after_idx, pre_reset) in reset_points {
        env.error = None;
        let mut base_state = base_state.clone();
        base_state.reset_bcf_for_replay();
        // Kernel bcf_track START-PUSH (verifier.c:24499 `env->prev_insn_idx
        // = vstate->last_insn_idx` + record_path_cond:20968): the goal's
        // FIRST cond is the base checkpoint's CREATING branch, evaluated on
        // the base state's (post-branch) regs — the re-execution replay
        // starts AFTER that branch and would otherwise drop it. from_l3
        // pc491: the If-391 `if w0 == 0` edge contributes
        // (extract32(V0)==0) plus V0's 64-bit bounds (low32 pinned
        // post-branch) = the 0x93e806b6 leading conjuncts. Kernel guards
        // mirrored: branch insns only (JA/CALL/EXIT skipped by the If
        // match), scalar dst/src only. Rung variants re-reset downstream,
        // wiping this push — correct (their anchor is the rung insn).
        if std::env::var("ZOVIA_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
            let dbg = env.state_by_cache_id(base_cid).and_then(|(pc, c)| {
                c.history_idx
                    .and_then(|h| env.history.get(h))
                    .map(|bc| (pc, bc.pc, format!("{:?}", bc.instr)))
            });
            eprintln!("[replay] STARTPUSH? base_cid={} -> {:?}", base_cid, dbg);
        }
        if let Some((_, cached)) = env.state_by_cache_id(base_cid)
            && let Some(hidx) = cached.history_idx
            && let Some(bc) = env.history.get(hidx)
            && let Instr::If { width, left, op, right, target } = bc.instr.clone()
            && matches!(
                base_state.types.get(left),
                crate::analysis::machine::reg_types::RegType::ScalarValue
            )
            && match &right {
                Operand::Reg(r) => matches!(
                    base_state.types.get(*r),
                    crate::analysis::machine::reg_types::RegType::ScalarValue
                ),
                _ => true,
            }
        {
            let prev_pc = bc.pc;
            if let Some((op_then, op_else)) = cmp_op_to_bcf_pair(op) {
                // Kernel record_path_cond: non_taken = (prev+1 == insn_idx).
                let taken = path[0].0 != prev_pc + 1;
                let _ = target;
                let op_byte = if taken { op_then } else { op_else };
                let pre_b =
                    crate::analysis::transfer::alu::helpers::bcf_reg_bounds(&base_state, left);
                record_path_cond_for_side(
                    &mut base_state, width, left, op, op_byte, &right, prev_pc, None, pre_b,
                );
            }
        }
        env.replay_mode = true;
        let mut holder: Option<State> = Some(base_state);
        for i in 0..n_exec {
            let pc = path[i].0;
            let instr = path[i].1.clone();
            let st = match holder.take() { Some(s) => s, None => break };
            let mut st = st;
            st.pc = pc;
            if pre_reset && Some(i) == reset_after_idx {
                // Kernel checkpoint-at-If base: fresh bcf BEFORE the If's
                // transfer — the cond below records into it pre-narrow.
                st.reset_bcf_for_replay();
            }
            let succ = crate::analysis::transfer::transfer(env, st, &instr);
            let next_pc = if i + 1 < path.len() { path[i + 1].0 } else { dead_target };
            holder = succ.into_iter().find(|s| s.pc == next_pc);
            if holder.is_none() {
                if dbg {
                    eprintln!(
                        "[replay] DIED rung={:?} pre={} i={} pc={} instr={:?} want_next={} env_err={:?}",
                        reset_after_idx.map(|k| path[k].0), pre_reset, i, pc, instr, next_pc, env.error
                    );
                }
                break;
            }
            if !pre_reset && Some(i) == reset_after_idx {
                if let (Some(h), Instr::If { width, left, op, right, target }) =
                    (holder.as_mut(), &instr)
                {
                    if let Some((op_then, op_else)) = cmp_op_to_bcf_pair(*op) {
                        h.reset_bcf_for_replay();
                        let taken = next_pc == *target;
                        let op_byte = if taken { op_then } else { op_else };
                        let pre_b =
                            crate::analysis::transfer::alu::helpers::bcf_reg_bounds(h, *left);
                        record_path_cond_for_side(
                            h, *width, *left, *op, op_byte, right, pc, None, pre_b,
                        );
                    }
                }
            }
        }
        env.replay_mode = false;
        if let Some(mut final_state) = holder {
            if let Some(symb) = final_state.bcf.take() {
                let g = crate::refinement::refine_unreachable::build_unreachable_from_replay(*symb);
                if dbg {
                    eprintln!(
                        "[replay] END rung={:?} pre={} built={}",
                        reset_after_idx.map(|k| path[k].0), pre_reset, g.is_some()
                    );
                }
                if let Some(g) = g {
                    let rung = match reset_after_idx {
                        None => -1,
                        Some(i) => path[i].0 as i32,
                    };
                    goals.push((rung, g));
                }
            } else if dbg {
                eprintln!(
                    "[replay] END rung={:?} pre={} bcf=None",
                    reset_after_idx.map(|k| path[k].0), pre_reset
                );
            }
        }
    }
    env.error = saved_error;
    goals
}

/// Kernel `bcf_track` replay-rebuild for REFINE-kind rejects (map/stack
/// bounds): re-execute the base→reject instruction path from the cached
/// base state with a FRESH bcf, and return the state ARRIVED at the
/// reject insn (the reject insn itself is NOT executed — it is the
/// failing access whose refine predicate the caller builds). The kernel
/// builds path conds AND the refine cond from this ONE replay expr table
/// (bcf_refine tail resets every reg's bcf_expr; bcf_track re-executes
/// with lazy bcf_reg_expr materialization) — so pre-base value chains
/// rematerialize as fresh VARs with replay-time bounds, and the refine
/// predicate's operand exprs are coherent with the path conds. The
/// live-state goal path CANNOT reproduce this on loop-wrapping suffixes:
/// bcc ksnoop c20-O1 (kernel MISS 0x7b883057f2f77b41 @521) — the base is
/// the loop-guard state (kernel first=581/cached@560); the pc-window
/// cond filter over-keeps iteration-1 crossings (pcs 571-581 >= 560) and
/// the live `(v4 + -1)` chain differs from the kernel's fresh-var form.
/// Plain replay only (no reset-rung ladder — the kernel's refine goal is
/// the plain base→reject walk); START-PUSH mirrored from
/// try_prove_unreachable_via_replay.
pub(crate) fn replay_to_reject(
    env: &mut VerifierEnv,
    base_cid: u32,
    // Anchor the EXECUTION one cache level earlier (the base's parent
    // cache entry) and reset the bcf at the base boundary. The kernel's
    // bcf_track replays from the pristine `st->parent` snapshot; zovia's
    // explored-cache entries are MUTATED at caching (mark_all_scalars_
    // imprecise + loop-header widening), so replaying with the cache
    // entry's regs materializes WIDENED operand bounds (bcc ksnoop: the
    // guard LHS minted [0,0xffffffff] where the kernel goal has the
    // pristine [-1,254] pair). Executing from the parent anchor rebuilds
    // the regs (the suffix's own loads/ALUs), while the bcf reset keeps
    // the recorded conds starting at the base — the kernel goal shape.
    anchor_at_parent: bool,
    // Slot-share variant (ADDITIVE, kernel bcf_track bt slot-demand
    // materialization): first fill of an expr-less spilled scalar mints
    // the VAR into the SLOT so later fills of the same offset share it
    // (see SymbolicState::replay_share_slot_vars). false preserves the
    // fix-#17 variants byte-for-byte.
    share_slot_vars: bool,
    // Reset-at-crossing variant (ADDITIVE, plain-anchor only): reset the
    // bcf at the k-th-FROM-LAST re-arrival at the anchor's pc within the
    // path (k = the value; 1 = last crossing) and re-record the boundary
    // branch — the kernel's base is a checkpoint on the CURRENT lineage
    // whose segment starts at that crossing, a state zovia may never have
    // cached (adds are cadence-gated). Measured: bcc ksnoop c20-Os
    // kretprobe @580 (kernel MISS 0xe33c4ae0e8b9f5dd) — the kernel base
    // is a fresh 504-checkpoint on the arg-NULL lineage two loop
    // iterations before its reject; zovia's only 504-cache (cid 33) is
    // from an old lineage, so its plain replay ran root-length (4671B)
    // where the kernel window is 818B. None = no crossing reset (all
    // existing variants byte-stable).
    reset_at_crossing: Option<usize>,
    // Override the pc whose crossings define the reset cut (default: the
    // anchor's own pc). Lets a DEEP rung's long path be cut at another
    // rung-pc's crossings — the kernel base can be a segment start at a
    // checkpoint pc EARLIER than any cache of that pc on the lineage
    // (bcc ksnoop c20-Os e33c: base = iter-0x28's 504-segment; zovia's
    // only on-lineage 504-cache was created one iteration later).
    crossing_pc: Option<usize>,
) -> Option<State> {
    let base_state = env.state_by_cache_id(base_cid).map(|(_, s)| s.clone())?;
    let base_hidx = base_state.history_idx;

    let (exec_state, exec_hidx, reset_suffix_from_base) = if anchor_at_parent {
        let parent_cid = base_state.parent_cache_id?;
        let parent_state = env.state_by_cache_id(parent_cid).map(|(_, s)| s.clone())?;
        let parent_hidx = parent_state.history_idx;
        if parent_hidx == base_hidx {
            return None; // no distinct anchor — the plain variant covers it
        }
        (parent_state, parent_hidx, true)
    } else {
        (base_state, base_hidx, false)
    };

    let reject_bc = env.current_step_idx?;
    let mut path: Vec<(usize, Instr)> = Vec::new();
    let mut cur = Some(reject_bc);
    let mut budget: usize = 200_000;
    // Suffix length AFTER the (bcf-)base — counted when the backward walk
    // passes base_hidx (only meaningful under anchor_at_parent).
    let mut suffix_len: Option<usize> = None;
    while let Some(idx) = cur {
        if Some(idx) == exec_hidx {
            break;
        }
        if reset_suffix_from_base && Some(idx) == base_hidx {
            suffix_len = Some(path.len());
        }
        budget = budget.checked_sub(1)?;
        let bc = env.history.get(idx)?;
        path.push((bc.pc, bc.instr.clone()));
        cur = bc.parent_idx;
    }
    if path.is_empty() {
        return None;
    }
    if reset_suffix_from_base && suffix_len.is_none() {
        // The base breadcrumb is not on the parent→reject chain — bail
        // rather than record a wrong-window goal.
        return None;
    }
    path.reverse(); // forward order: first-suffix insn .. reject insn
    // Forward index of the first insn AFTER the base = where the bcf
    // resets (the base boundary; under anchor_at_parent only).
    let mut reset_at: Option<usize> = suffix_len.map(|sl| path.len() - sl);
    // Reset-at-crossing (plain anchor only): pick the k-th-from-last
    // re-arrival at the anchor pc. Requires the boundary to have a
    // preceding insn in the path (i > 0) so the boundary branch can be
    // re-recorded.
    let mut crossing_engaged = false;
    if let Some(k) = reset_at_crossing {
        if anchor_at_parent {
            return None; // combination undefined — plain shapes only
        }
        let anchor_pc = crossing_pc.unwrap_or(exec_state.pc);
        let crossings: Vec<usize> = (1..path.len().saturating_sub(1))
            .filter(|&i| path[i].0 == anchor_pc)
            .collect();
        if crossings.len() < k {
            return None;
        }
        reset_at = Some(crossings[crossings.len() - k]);
        crossing_engaged = true;
    }
    if std::env::var("ZOVIA_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
        eprintln!(
            "[replay-refine] STRUCT base_cid={} base_hidx={:?} stopped_at_base={} path[0]={} path[last]={} len={}",
            base_cid, base_hidx, cur.is_some(), path[0].0, path[path.len() - 1].0, path.len()
        );
    }
    let reject_pc = path[path.len() - 1].0;
    let n_exec = path.len() - 1; // never execute the reject insn itself
    if n_exec == 0 {
        // The base is the immediate parent of the reject insn — the
        // replayed state IS the base (fresh bcf, no conds). Still valid:
        // the refine pred materializes fresh from the base regs.
        let mut st = exec_state;
        st.reset_bcf_for_replay();
        if share_slot_vars && let Some(b) = st.bcf.as_mut() {
            b.replay_share_slot_vars = true;
        }
        st.pc = reject_pc;
        return Some(st);
    }

    let dbg = std::env::var("ZOVIA_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1");
    let saved_error = env.error.take();
    let mut base_state = exec_state;
    base_state.reset_bcf_for_replay();
    // Slot-share flag rides the replay bcf (mid-path reset_at resets keep
    // it: reset_for_replay leaves the flag untouched and the bcf is Some).
    if share_slot_vars && let Some(b) = base_state.bcf.as_mut() {
        b.replay_share_slot_vars = true;
    }
    // START-PUSH (kernel record_path_cond at bcf_track replay start,
    // verifier.c:24499/:20968): the base checkpoint's creating branch,
    // evaluated on the base state's post-branch regs. Skipped under
    // anchor_at_parent — the mid-path bcf reset defines the cond window
    // there, and the guard (the base's next insn) is executed and
    // recorded by the replay itself.
    if !reset_suffix_from_base && !crossing_engaged
        && let Some((_, cached)) = env.state_by_cache_id(base_cid)
        && let Some(hidx) = cached.history_idx
        && let Some(bc) = env.history.get(hidx)
        && let Instr::If { width, left, op, right, target } = bc.instr.clone()
        && matches!(
            base_state.types.get(left),
            crate::analysis::machine::reg_types::RegType::ScalarValue
        )
        && match &right {
            Operand::Reg(r) => matches!(
                base_state.types.get(*r),
                crate::analysis::machine::reg_types::RegType::ScalarValue
            ),
            _ => true,
        }
    {
        let prev_pc = bc.pc;
        if let Some((op_then, op_else)) = cmp_op_to_bcf_pair(op) {
            let taken = path[0].0 != prev_pc + 1;
            let _ = target;
            let op_byte = if taken { op_then } else { op_else };
            let pre_b =
                crate::analysis::transfer::alu::helpers::bcf_reg_bounds(&base_state, left);
            record_path_cond_for_side(
                &mut base_state, width, left, op, op_byte, &right, prev_pc, None, pre_b,
            );
        }
    }
    env.error = None;
    env.replay_mode = true;
    let mut holder: Option<State> = Some(base_state);
    for i in 0..n_exec {
        let pc = path[i].0;
        let instr = path[i].1.clone();
        let mut st = match holder.take() {
            Some(s) => s,
            None => break,
        };
        st.pc = pc;
        if Some(i) == reset_at {
            // Base boundary (anchor_at_parent): fresh bcf BEFORE the first
            // suffix insn — its cond (the guard) records into it with the
            // execution-rebuilt (pristine) operand bounds.
            st.reset_bcf_for_replay();
            if share_slot_vars && let Some(b) = st.bcf.as_mut() {
                b.replay_share_slot_vars = true;
            }
            // Crossing boundary: the branch INTO the crossing (path[i-1])
            // already executed and its cond was wiped by the reset —
            // re-record it on the post-branch state, the kernel's
            // START-PUSH analog for a mid-lineage base (record_path_cond
            // at bcf_track replay start, verifier.c:24499/:20968).
            // record_path_cond_for_side itself skips non-scalar operands.
            if crossing_engaged
                && i > 0
                && let Instr::If { width, left, op, right, target: _ } = &path[i - 1].1
                && let Some((op_then, op_else)) = cmp_op_to_bcf_pair(*op)
            {
                let prev_pc = path[i - 1].0;
                let taken = pc != prev_pc + 1;
                let op_byte = if taken { op_then } else { op_else };
                let pre_b =
                    crate::analysis::transfer::alu::helpers::bcf_reg_bounds(&st, *left);
                record_path_cond_for_side(
                    &mut st, *width, *left, *op, op_byte, right, prev_pc, None, pre_b,
                );
            }
        }
        let succ = crate::analysis::transfer::transfer(env, st, &instr);
        let next_pc = path[i + 1].0;
        holder = succ.into_iter().find(|s| s.pc == next_pc);
        if std::env::var("ZOVIA_DBG_REPLAY_R6").ok().as_deref() == Some("1")
            && (539..=546).contains(&pc)
            && let Some(h) = holder.as_ref()
        {
            let (lo, hi) = h.domain.get_interval(crate::analysis::machine::reg::Reg::R6);
            eprintln!(
                "[replay-r6] base_cid={} anchor_parent={} i={} pc={} r6=[{},{}] frames={}",
                base_cid, anchor_at_parent, i, pc, lo, hi, h.frames.current_level()
            );
        }
        if dbg
            && std::env::var("ZOVIA_DBG_REPLAY_S32").ok().as_deref() == Some("1")
            && let Some(h) = holder.as_ref()
        {
            let (s32lo, s32hi) = h.domain.get_s32_bounds(crate::analysis::machine::reg::Reg::R1);
            let (lo, hi) = h.domain.get_interval(crate::analysis::machine::reg::Reg::R1);
            eprintln!(
                "[replay-s32] i={} pc={} r1 ivl=[{},{}] s32=[{},{}]",
                i, pc, lo, hi, s32lo, s32hi
            );
        }
        if holder.is_none() && dbg {
            eprintln!(
                "[replay-refine] DIED i={} pc={} instr={:?} want_next={} env_err={:?}",
                i, pc, instr, next_pc, env.error
            );
        }
        if holder.is_none() {
            break;
        }
    }
    env.replay_mode = false;
    env.error = saved_error;
    holder
}

/// Emission census (ZOVIA_BCF_CENSUS=1, diagnosis-only): one line per bundle
/// push ATTEMPT, tagged with the emission-class that produced the goal, so the
/// per-class hash sets can be intersected offline against a kernel load's
/// queried set ([ZK try_discharge] dmesg lines). `depth` = ancestor-chain
/// depth (-1 where n/a), `rung` = replay reset-ladder If pc (-1 = plain).
pub(crate) fn census_log(class: &str, reject_pc: usize, depth: i32, rung: i32, hash: u64, dup: bool) {
    if std::env::var("ZOVIA_BCF_CENSUS").ok().as_deref() == Some("1") {
        eprintln!(
            "[census] pc={} class={} depth={} rung={} hash={:016x} dup={}",
            reject_pc, class, depth, rung, hash, dup as u32
        );
    }
}

pub(crate) fn try_emit_path_unreachable_entry(env: &mut VerifierEnv, state: &State) -> bool {
    use crate::refinement::bundle::{RefineEntry, BCF_BUNDLE_KIND_UNREACHABLE};
    use crate::refinement::refine_unreachable::try_prove_unreachable;
    use log::info;

    // No re-entrant discharge during a replay: the replay re-executes a
    // suffix only to rebuild the path condition; it must not itself attempt
    // to discharge (which would recurse and pollute the bundle).
    if (env.replay_mode || state.bcf.is_none())
        && std::env::var("ZOVIA_DUMP_DISCHARGE").ok().as_deref() == Some("1")
    {
        eprintln!(
            "[disc-skip] reject@pc={} replay={} bcf_none={} parent_cid={:?}",
            state.pc,
            env.replay_mode,
            state.bcf.is_none(),
            state.parent_cache_id
        );
    }
    if env.replay_mode {
        return false;
    }
    if state.bcf.is_none() {
        return false;
    }
    // FAITHFUL base (Phase 2, 2026-07-01). The kernel's ONE `base` from
    // backtrack_states gives BOTH the goal anchor (`base->insn_idx`, the
    // replay start) AND the marking bound (parents[] = the chain up to base).
    // `base_pc` = `base->insn_idx` (anchor, for the prove/goal calls). The
    // marking below uses `base_cid_dbg` (the base cache_id) to mark exactly
    // the `parents[]` chain — no split, no bcidx/EXCLUDE_BASE pc-window.
    let base_pc = unreachable_base_pc(env, state);
    // Mirror kernel's `vstate->last_insn_idx` retrieval at bcf_track
    // replay start: look up the prev_insn PC of the cached state AT
    // base_pc (the cache the suffix walk landed on, not the immediate
    // parent_cache_id of cur — they can differ). The filter uses this
    // to identify the immediate-predecessor branch cond (the kernel's
    // record_path_cond push at insn=base_pc, verifier.c:21117).
    let (prev_insn_pc, base_cid_dbg) = {
        // Shared target mask — IDENTICAL to unreachable_base_pc via the
        // common helper. A drift here (e.g. missing the pkt_const_off drop)
        // empties the cache-id walk at a different insn than the pc walk,
        // leaving base_cid=None → the faithful REPLAY is skipped and the
        // pc274 190-path family MISSes.
        let hidx = env.current_step_idx.or(state.history_idx);
        let targets = unreachable_target_regs(env, state, hidx);
        let landed = hidx.and_then(|hidx| {
            crate::analysis::flow::precision::bcf_suffix_base_pc_and_cache_id(env, hidx, state.parent_cache_id, &targets)
        });
        // Use only the immediate cache the suffix walker landed on (no
        // chain-skip). A previous attempt walked back through
        // parent_cache_id to find the first branch-target cache, but
        // that over-eagerly added upstream conds to trajectories whose
        // kernel-faithful prev_insn was actually NOT a scalar branch,
        // changing their hash and breaking the byte-match for existing
        // kernel-matched entries (e.g. anchor calico_tc_main hash
        // 0xd13031db2681349e flipped to MISS). Closing this requires
        // also aligning cache topology (sparse caching), not just
        // walker logic.
        let pp = landed.and_then(|(_base_pc, base_cid)| env.cached_prev_insn_pc(base_cid));
        let cid = landed.map(|(_, cid)| cid);
        (pp, cid)
    };
    if std::env::var("ZOVIA_DUMP_DISCHARGE").ok().as_deref() == Some("1") {
        eprintln!("[disc] reject@pc={} base_pc={:?} prev_insn_pc={:?} parent_cid={:?} base_cid={:?}",
                  state.pc, base_pc, prev_insn_pc, state.parent_cache_id, base_cid_dbg);
    }
    // Kernel retry-round mirror (ZOVIA_BCF_ROUNDS=1): a reject whose
    // natural goal is covered by a PRIOR round's emission discharges
    // straight from the accumulated bundle — no cvc5, no new pushes — and
    // the parents still get marked (kernel bcf_refine marks
    // children_unsafe UNCONDITIONALLY after a FOUND
    // bcf_bundle_try_discharge, verifier.c:24697). The first UNCOVERED
    // reject ends the round at the success returns below (kernel
    // mark_bcf_requested → the load fails → the loader retries from
    // scratch with the grown bundle).
    if env.bcf_rounds_mode
        && let Some(h) = crate::refinement::refine_unreachable::natural_goal_hash(
            state, base_pc, prev_insn_pc,
        )
        && env.bcf_round_covered.contains(&h)
    {
        crate::analysis::flow::pruning::cache::mark_path_children_unsafe(env, state, base_cid_dbg);
        return true;
    }
    // LEAN EMISSION — THE DEFAULT (census arc 2026-07-04/05, memory
    // project_over_emission_census_2026-07-04): emit the replay family
    // (replay_base all rungs + ancestor replays depth 0-1) and fall through
    // to the full reconstruction fan-out ONLY for rejects where the replay
    // family produced nothing (base-less full-path goals — cilium bpf_lxc,
    // from_tnl pc214 family). Measured basis: 4-object census (338/338
    // kernel-queried hashes covered by the replay family where a base
    // exists) + repr-19 16/19 parity + cilium-17 17/17 + E2-scale sweep
    // LEAN 278/337 vs FAT 244/337 (+34: E2BIG class extinct, build-timeouts
    // cured; 2 known 1-hash regressions tracked as chase targets alongside
    // the other 57 first-misses). Control flow, the cvc5 prove of the
    // natural goal (gates the return value), and mark_path_children_unsafe
    // are IDENTICAL to the historical fat path; only bundle pushes differ.
    // The skipped classes' code below is kept: it IS the base-less
    // fallback path.
    // DIAGNOSIS-ONLY escape hatch (2026-07-05 E2 regression triage):
    // ZOVIA_BCF_LEAN=0 re-enables the full fat fan-out so a census can ask
    // "would ANY anchor/class produce the missed hash". Not a tuning knob.
    let lean = std::env::var("ZOVIA_BCF_LEAN").ok().as_deref() != Some("0");
    // Faithful base→reject replay (ZOVIA_BCF_REPLAY=1), ADDITIVE: push the
    // replay-derived entry alongside the reconstruction discharges (merge
    // dedups by cond_hash). Lets us validate replay coverage without
    // disturbing the existing path.
    // REPLAY = faithful base→reject re-execution (kernel bcf_track mirror).
    // DEFAULT-ON (kill-switch ZOVIA_BCF_REPLAY=0); ADDITIVE alongside the
    // reconstruction discharge (merge dedups by cond_hash). Pairs with
    // ZOVIA_BCF_REPLAY_FIRSTREF (also default-ON) for kernel-faithful first-ref
    // bound emission.
    let mut replay_goals_produced: usize = 0;
    if crate::common::config::bcf_mirror_knob("ZOVIA_BCF_REPLAY", true) {
        if std::env::var("ZOVIA_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
            eprintln!("[replay] CALL reject@pc={} base_cid={:?}", state.pc, base_cid_dbg);
        }
        if let Some(cid) = base_cid_dbg {
            for (rung, rok) in try_prove_unreachable_via_replay(env, state, cid) {
                let rentry = RefineEntry::new(
                    rok.goal_root,
                    rok.sym.exprs,
                    rok.proof_bytes,
                    BCF_BUNDLE_KIND_UNREACHABLE,
                );
                if std::env::var("ZOVIA_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
                    eprintln!("[replay] HASH reject@pc={} hash={:016x}", state.pc, rentry.cond_hash);
                }
                replay_goals_produced += 1;
                let dup = env.bcf_proofs.iter().any(|e| e.cond_hash == rentry.cond_hash);
                census_log("replay_base", state.pc, -1, rung, rentry.cond_hash, dup);
                if dup {
                    continue;
                }
                info!(target: "app",
                    "[bcf] REPLAY path-unreachable: proof {} bytes (hash {:016x})",
                    rentry.proof_bytes.len(), rentry.cond_hash);
                env.bcf_proofs.push(rentry);
            }
        }
    }
    let Some(ok) = try_prove_unreachable(state, base_pc, prev_insn_pc) else {
        // Kernel bcf_refine marks parents[] children_unsafe UNCONDITIONALLY
        // at its tail (verifier.c:24822) — after discharge FOUND, MISS, or
        // any goal/proof-formation failure alike. Returning here without
        // marking left the reject's ancestor chain prune-safe, so later
        // arrivals subsumed on it and their own rejects never happened:
        // fibdsr16's 2838-backjump lineage planted absorbers at 1179/1165
        // (cids 12995/13003) that extinguished the ICMP-arm descendant —
        // the kernel-queried 0x003e1542d2fdd1d6 was never emitted. (Note
        // the replay-family pushes above have already run by this point;
        // the kernel's parallel is goals built, natural proof unavailable.)
        crate::analysis::flow::pruning::cache::mark_path_children_unsafe(env, state, base_cid_dbg);
        return false;
    };
    let entry = RefineEntry::new(
        ok.goal_root,
        ok.sym.exprs,
        ok.proof_bytes,
        BCF_BUNDLE_KIND_UNREACHABLE,
    );
    // The retry-round covered-set key for this reject. MUST equal what the
    // covered check (`natural_goal_hash`) computes next round — NOT
    // `entry.cond_hash`: when cvc5 declines the K==K rewrite,
    // try_prove_unreachable returns the un-rewritten FALLBACK goal whose
    // hash differs from the hash-only build → the check never hits →
    // round livelock (first prototype run: 4096 rounds, 18 entries).
    let natural_cond_hash = if env.bcf_rounds_mode {
        crate::refinement::refine_unreachable::natural_goal_hash(state, base_pc, prev_insn_pc)
            .unwrap_or(entry.cond_hash)
    } else {
        entry.cond_hash
    };
    info!(
        target: "app",
        "[bcf] path-unreachable speculation: cvc5 proof {} bytes (hash {:016x})",
        entry.proof_bytes.len(),
        entry.cond_hash
    );
    if std::env::var("ZOVIA_BCF_CENSUS").ok().as_deref() == Some("1") {
        census_log(
            "natural", state.pc, -1, -1, entry.cond_hash,
            env.bcf_proofs.iter().any(|e| e.cond_hash == entry.cond_hash),
        );
    }
    if lean {
        // Lean mode: the natural prove above still gates the return value
        // (and thus parent marking) exactly as before, but its entry and all
        // reconstruction twins below stay out of the bundle; the ancestor
        // walk runs only the shallow replays.
        // Ancestor replays at depth 0 AND 1: the census found min-depth 0
        // suffices on fnf/l3/twep/thep, but to_lo_debug_co-re_v6's queried
        // 0x673434f3469c3018 (pc2222) is replay_anc depth-1-only — the
        // kernel's base lands two cache-hops below the walker on that
        // reject. Depth ≤ 1 is the measured envelope so far.
        // Aliased-VAR (no-rewrite) reconstruction twin at the natural base
        // (lean v4): the E2 lean sweep's two LOAD regressions are BOTH
        // no-rewrite shapes the replay never produces — to_lo_fib_no_log_
        // co-re_v6 pc754 0xf00d1f29 = class no_rw, c17 from_hep_fib_dsr_
        // no_log pc1216 0xb9e1f14d = class anc_norw d0 (fat-census
        // attributed). Same lesson as 2026-05-27 (kernel queries via the
        // aliased form on some programs; calico-19 once 19->9 without it).
        if let Some(ok_no_rw) = crate::refinement::refine_unreachable::try_prove_unreachable_no_rewrite(state, base_pc, prev_insn_pc) {
            let entry_no_rw = RefineEntry::new(
                ok_no_rw.goal_root, ok_no_rw.sym.exprs, ok_no_rw.proof_bytes,
                BCF_BUNDLE_KIND_UNREACHABLE,
            );
            let nr_dup = env.bcf_proofs.iter().any(|e| e.cond_hash == entry_no_rw.cond_hash);
            census_log("no_rw", state.pc, -1, -1, entry_no_rw.cond_hash, nr_dup);
            if !nr_dup {
                env.bcf_proofs.push(entry_no_rw);
            }
        }
        let mut cur = base_cid_dbg;
        for lean_depth in 0..2 {
            let Some(parent_cid) = cur
                .and_then(|cid| env.state_by_cache_id(cid))
                .and_then(|(_, s)| s.parent_cache_id)
            else { break };
            for (rung, rok) in try_prove_unreachable_via_replay(env, state, parent_cid) {
                let rentry = RefineEntry::new(
                    rok.goal_root, rok.sym.exprs, rok.proof_bytes,
                    BCF_BUNDLE_KIND_UNREACHABLE,
                );
                replay_goals_produced += 1;
                let ra_dup = env.bcf_proofs.iter().any(|e| e.cond_hash == rentry.cond_hash);
                census_log("replay_anc", state.pc, lean_depth, rung, rentry.cond_hash, ra_dup);
                if !ra_dup {
                    env.bcf_proofs.push(rentry);
                }
            }
            // Aliased-VAR reconstruction at this ancestor (lean v4, the
            // anc_norw d<=1 slice — see the no_rw comment above).
            let anc_pc = env.state_by_cache_id(parent_cid).map(|(pc, _)| pc);
            if let Some(anc_pc) = anc_pc {
                let anc_prev = env.cached_prev_insn_pc(parent_cid);
                if let Some(ok_an) = crate::refinement::refine_unreachable::try_prove_unreachable_no_rewrite(state, Some(anc_pc), anc_prev) {
                    let entry_an = RefineEntry::new(
                        ok_an.goal_root, ok_an.sym.exprs, ok_an.proof_bytes,
                        BCF_BUNDLE_KIND_UNREACHABLE,
                    );
                    let an_dup = env.bcf_proofs.iter().any(|e| e.cond_hash == entry_an.cond_hash);
                    census_log("anc_norw", state.pc, lean_depth, -1, entry_an.cond_hash, an_dup);
                    if !an_dup {
                        env.bcf_proofs.push(entry_an);
                    }
                }
            }
            cur = Some(parent_cid);
        }
        // FALLBACK (lean v3, cilium/from_tnl lesson): when the replay family
        // produced NOTHING for this reject — no cached base (base_cid=None,
        // the base-less full-path goal shape: cilium bpf_lxc, from_tnl
        // pc214) or every replay diverged — the reconstruction classes are
        // the ONLY emitters for it, so fall through to the full fat path
        // for THIS reject instead of returning early. Cilium fat bundles
        // (774KB bpf_lxc) are entirely this shape; lean-v2 emitted 0 bytes
        // there and the VM load failed EACCES with 0 queries.
        if replay_goals_produced > 0 {
            if let Ok(flush_path) = std::env::var("ZOVIA_BCF_EAGER_FLUSH") {
                let tmp = format!("{}.tmp", flush_path);
                if crate::refinement::bundle::write_bundle(std::path::Path::new(&tmp), &env.bcf_proofs).is_ok() {
                    let _ = std::fs::rename(&tmp, &flush_path);
                }
            }
            crate::analysis::flow::pruning::cache::mark_path_children_unsafe(env, state, base_cid_dbg);
            // Retry-round mirror: first uncovered reject ends the round
            // (kernel mark_bcf_requested — the load fails here).
            if env.bcf_rounds_mode {
                env.bcf_round_stop = true;
                env.bcf_round_new = Some(natural_cond_hash);
            }
            return true;
        }
    }
    if let Ok(prefix) = std::env::var("ZOVIA_BCF_DUMP_PROOF") {
        let idx = env.bcf_proofs.len();
        let path = format!("{}.{}.bcf", prefix, idx);
        match std::fs::write(&path, &entry.proof_bytes) {
            Ok(_) => info!(target: "app", "[bcf] dumped raw proof to {}", path),
            Err(e) => log::warn!(target: "app", "[bcf] proof dump to {} failed: {}", path, e),
        }
    }
    env.bcf_proofs.push(entry);
    // DEBUG (parent-hop validation, 2026-06-19): eagerly flush the
    // accumulated bcf_proofs to a path after every discharge push, so the
    // on-disk bundle reflects current proofs even when the run is killed by
    // a wall-clock timeout before analyze() reaches its write_bundle. Lets
    // us capture the accepted_entrypoint 21f06b60 entry despite the no_log
    // non-termination. Writes atomically (tmp+rename). Default-OFF.
    if let Ok(flush_path) = std::env::var("ZOVIA_BCF_EAGER_FLUSH") {
        let tmp = format!("{}.tmp", flush_path);
        if crate::refinement::bundle::write_bundle(std::path::Path::new(&tmp), &env.bcf_proofs).is_ok() {
            let _ = std::fs::rename(&tmp, &flush_path);
        }
    }
    // Also push the un-rewritten (aliased-VAR) form so previously-
    // matched hashes that happened to be the aliased shape stay in the
    // bundle alongside the kernel-shape rewrites. Without this, the
    // fresh-VAR rewrite is destructive for programs whose discharge
    // hash the kernel queries via the aliased form (calico-19
    // regressed 19/19 → 9/19 when only the rewritten form was pushed,
    // 2026-05-27).
    if let Some(ok_no_rw) = crate::refinement::refine_unreachable::try_prove_unreachable_no_rewrite(state, base_pc, prev_insn_pc) {
        let entry_no_rw = RefineEntry::new(
            ok_no_rw.goal_root,
            ok_no_rw.sym.exprs,
            ok_no_rw.proof_bytes,
            BCF_BUNDLE_KIND_UNREACHABLE,
        );
        let already_have = env.bcf_proofs.iter().any(|e| e.cond_hash == entry_no_rw.cond_hash);
        census_log("no_rw", state.pc, -1, -1, entry_no_rw.cond_hash, already_have);
        if !already_have {
            info!(
                target: "app",
                "[bcf] path-unreachable (no-rewrite): cvc5 proof {} bytes (hash {:016x})",
                entry_no_rw.proof_bytes.len(),
                entry_no_rw.cond_hash
            );
            env.bcf_proofs.push(entry_no_rw);
        }
    }

    // EXPERIMENT both-folds (ZOVIA_BCF_BOTH_FOLDS=1, all-faithful mirror
    // 2026-06-11): when FAITHFUL_FOLD is on, ALSO emit the legacy-fold form of
    // the same obligation. The kernel folds per-site based on ITS state; one
    // of the two forms hash-matches (from_nat 5edc48ab = legacy n=5 form;
    // faithful emits the n=4 fold). ADDITIVE + deduped.
    if crate::common::config::bcf_mirror_knob("ZOVIA_BCF_BOTH_FOLDS", true) {
        if let Some(ok_lf) = crate::refinement::refine_unreachable::try_prove_unreachable_fold_legacy(
            state, base_pc, prev_insn_pc,
        ) {
            let entry_lf = RefineEntry::new(
                ok_lf.goal_root, ok_lf.sym.exprs, ok_lf.proof_bytes,
                BCF_BUNDLE_KIND_UNREACHABLE,
            );
            let lf_dup = env.bcf_proofs.iter().any(|e| e.cond_hash == entry_lf.cond_hash);
            census_log("legacy_fold", state.pc, -1, -1, entry_lf.cond_hash, lf_dup);
            if !lf_dup {
                info!(
                    target: "app",
                    "[bcf] path-unreachable (legacy-fold): cvc5 proof {} bytes (hash {:016x})",
                    entry_lf.proof_bytes.len(), entry_lf.cond_hash
                );
                env.bcf_proofs.push(entry_lf);
            }
        }
    }

    // EXPERIMENT trajectory-suffix twins of the NATURAL discharge (additive,
    // gated by BOTH_FOLDS like the legacy twin): the natural base may not be
    // a path-cond pc, so the anchor-union below never re-anchors exactly
    // there — emit the traj-window forms at (base_pc, prev_insn_pc) too.
    if crate::common::config::bcf_mirror_knob("ZOVIA_BCF_BOTH_FOLDS", true) && base_pc.is_some() {
        for (t_label, okv) in [
            ("traj", crate::refinement::refine_unreachable::try_prove_unreachable_traj(
                state, base_pc, prev_insn_pc,
            )),
            ("traj_lf", crate::refinement::refine_unreachable::try_prove_unreachable_traj_fold_legacy(
                state, base_pc, prev_insn_pc,
            )),
            ("traj_no_rw", crate::refinement::refine_unreachable::try_prove_unreachable_traj_no_rewrite(
                state, base_pc, prev_insn_pc,
            )),
        ] {
            if let Some(ok_t) = okv {
                let entry_t = RefineEntry::new(
                    ok_t.goal_root, ok_t.sym.exprs, ok_t.proof_bytes,
                    BCF_BUNDLE_KIND_UNREACHABLE,
                );
                let t_dup = env.bcf_proofs.iter().any(|e| e.cond_hash == entry_t.cond_hash);
                census_log(t_label, state.pc, -1, -1, entry_t.cond_hash, t_dup);
                if !t_dup {
                    info!(
                        target: "app",
                        "[bcf] path-unreachable (traj-natural): cvc5 proof {} bytes (hash {:016x})",
                        entry_t.proof_bytes.len(), entry_t.cond_hash
                    );
                    env.bcf_proofs.push(entry_t);
                }
            }
        }
    }

    // Register-filtered discharge (provenance-seeded, mirrors the kernel's
    // bcf_reg_expr data-dependency closure). DEFAULT-ON; set
    // ZOVIA_BCF_REGFILTER=0 as a kill-switch.
    //
    // After the immediate + ancestor PC-suffix discharges above, also emit
    // provenance-seeded register-filtered discharges: seed = the suffix's
    // most-recent branch reg, grown 1-2 def-use hops through the
    // value-expression DAG via the var_origin map, then keep only that
    // register set's branches + the bound preds materializing their VARs.
    // This synthesizes the kernel's small multi-register reject
    // conjunctions (bcf_reg_expr data-dependency closure) that the
    // PC-suffix filter alone can't isolate. Emitted at hop depths {1,2} ×
    // {rewrite, no-rewrite}; ADDITIVE + deduped by cond_hash, so it never
    // perturbs already-matched hashes — only adds.
    //
    // VM-load ground truth (2026-05-29): this flips the to_hep_*_co-re_v6
    // family (calico_tc_main reject) from -EACCES to full-load. NOTE: an
    // offline (regset × PC-window) probe earlier FAILED to reproduce the
    // needed deep hash and wrongly concluded it unreachable — the LIVE
    // discharge (real base_pc + K==K/fresh-VAR rewrite firing in ancestor
    // context) produces what the kernel needs. The VM load is the oracle.
    // See feedback_byte_level_decode_first §2026-05-29 cont.5/cont.6.
    //
    // Soundness: only cvc5-PROVEN sub-conjunctions are emitted; the kernel
    // re-checks every proof on load, so a full-load = all proofs valid
    // (FA=0 floor preserved). Risk is bundle bloat, bounded by dedup +
    // the small per-anchor goal set.
    //
    // THOROUGH-MODE ONLY: this is a coverage-widening enhancement that
    // belongs to thorough multi-pass analysis (where the calico wins
    // live). Thorough mode spawns single-pass children (each
    // --no-bcf-thorough) that do the actual analysis + discharge, marked
    // with ZOVIA_BCF_THOROUGH_PASS=1 by the parent (main.rs). We key on
    // that marker — NOT config.bcf_thorough, which is false in the
    // children where the work happens. A standalone `--no-bcf-thorough`
    // run (the cilium 60s-budget recipe) lacks the marker, so reg-filter
    // stays off there and its bundle is byte-identical to HEAD — the
    // tight time budget isn't spent on extra cvc5 solves. Kill-switch:
    // ZOVIA_BCF_REGFILTER=0.
    if crate::common::config::bcf_mirror_knob("ZOVIA_BCF_THOROUGH_PASS", true)
        && std::env::var("ZOVIA_BCF_REGFILTER").ok().as_deref() != Some("0")
    {
        use crate::refinement::refine_unreachable as ru;
        for &hops in &[1usize, 2usize] {
            for &use_rewrite in &[true, false] {
                let ok_opt = if use_rewrite {
                    ru::try_prove_unreachable_reg_filtered(state, hops)
                } else {
                    ru::try_prove_unreachable_reg_filtered_no_rewrite(state, hops)
                };
                if let Some(ok) = ok_opt {
                    let rf_entry = RefineEntry::new(
                        ok.goal_root, ok.sym.exprs, ok.proof_bytes,
                        BCF_BUNDLE_KIND_UNREACHABLE,
                    );
                    let rf_dup = env.bcf_proofs.iter().any(|e| e.cond_hash == rf_entry.cond_hash);
                    census_log(
                        if use_rewrite { "regfilter_rw" } else { "regfilter_norw" },
                        state.pc, hops as i32, -1, rf_entry.cond_hash, rf_dup,
                    );
                    if !rf_dup {
                        info!(target: "app",
                            "[bcf] reg-filtered (expt): {} bytes (hash {:016x}, hops={}, rw={})",
                            rf_entry.proof_bytes.len(), rf_entry.cond_hash, hops, use_rewrite);
                        env.bcf_proofs.push(rf_entry);
                    }
                }
            }
        }
    }

    // Synthetic ancestor-discharge emission. After the immediate-cache
    // discharge succeeds, walk the parent_cache_id chain backward and
    // emit additional discharges anchored at each ancestor cache. The
    // kernel sometimes queries a hash whose suffix base is DEEPER than
    // zovia's walker reaches in one segment of jmp_history — zovia's
    // jmp_history is segmented per-cache-event, so a single walker
    // call can only collect predicates within one segment; the kernel's
    // walker traverses one long history. Example: calico
    // from_nat_debug_co-re reject_pc=1732, kernel demands 8-conj hash
    // 0x673434f3469c3018 that requires base anchored pre-1562; zovia
    // walker stops at base_pc=1680. Anchoring at each chain ancestor
    // produces the kernel-needed deeper hashes.
    //
    // ADDITIVE only: keeps the immediate-cache discharge (so existing
    // matched hashes preserve their byte-for-byte alignment) and dedup
    // by cond_hash before pushing. Validated 2026-05-27 against the
    // calico-19 + cilium-17 + collected-9 VM-load gate.
    //
    // Note the existing comment above (`A previous attempt walked back
    // through parent_cache_id…`) — that attempt REPLACED the immediate
    // discharge with a chain-walked one and broke matched hashes. This
    // is the additive variant that closes the same case without that
    // regression class.
    {
        // Lean-bundle investigation (no_log 2026-05-30): the depth-64 ancestor
        // shotgun is the dominant over-emission source (~1183 proto shapes vs
        // the kernel's 22). Knob to measure/cap it. Default 64 (unchanged).
        let max_ancestor_depth: usize = std::env::var("ZOVIA_BCF_ANCESTOR_DEPTH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(64);
        let mut cur_cid_opt = base_cid_dbg;
        let mut depth = 0;
        while depth < max_ancestor_depth {
            let Some(cur_cid) = cur_cid_opt else { break };
            // Live-then-retired: an evicted mid-chain ancestor must not
            // truncate the chain-discharge walk.
            let Some(parent_cid) = env
                .state_by_cache_id(cur_cid)
                .and_then(|(_, s)| s.parent_cache_id)
            else { break };
            let Some((ancestor_pc, _)) = env.state_by_cache_id(parent_cid) else { break };
            let ancestor_prev_pc = env.cached_prev_insn_pc(parent_cid);
            // Per-ancestor PC-suffix discharges (rewrite + no-rewrite).
            // Register-filtered discharges are PC-independent and emitted
            // once at top level, NOT per ancestor. All ADDITIVE + deduped.
            for &use_rewrite in &[true, false] {
                let ok_opt = if use_rewrite {
                    try_prove_unreachable(state, Some(ancestor_pc), ancestor_prev_pc)
                } else {
                    crate::refinement::refine_unreachable::try_prove_unreachable_no_rewrite(
                        state, Some(ancestor_pc), ancestor_prev_pc)
                };
                if let Some(ok) = ok_opt {
                    let extra_entry = RefineEntry::new(
                        ok.goal_root,
                        ok.sym.exprs,
                        ok.proof_bytes,
                        BCF_BUNDLE_KIND_UNREACHABLE,
                    );
                    let already_have = env.bcf_proofs.iter().any(|e| e.cond_hash == extra_entry.cond_hash);
                    census_log(
                        if use_rewrite { "anc_rw" } else { "anc_norw" },
                        state.pc, depth as i32, -1, extra_entry.cond_hash, already_have,
                    );
                    if std::env::var("ZOVIA_DUMP_DISCHARGE").ok().as_deref() == Some("1") {
                        eprintln!(
                            "[disc-ancestor] depth={} anchor_pc={} anchor_cid={} prev_pc={:?} rw={} hash={:016x} dup={}",
                            depth, ancestor_pc, parent_cid, ancestor_prev_pc, use_rewrite,
                            extra_entry.cond_hash, already_have,
                        );
                    }
                    if !already_have {
                        info!(
                            target: "app",
                            "[bcf] ancestor-discharge: cvc5 proof {} bytes (hash {:016x}, depth={}, rw={})",
                            extra_entry.proof_bytes.len(),
                            extra_entry.cond_hash,
                            depth,
                            use_rewrite,
                        );
                        env.bcf_proofs.push(extra_entry);
                    }
                }
            }
            // Faithful base→reject replay re-anchored at THIS ancestor
            // (ZOVIA_BCF_REPLAY=1). Re-executes from the ancestor's cached
            // state, so the goal is the kernel's exact bcf_track path cond
            // for a replay starting here. Additive + deduped by cond_hash.
            if crate::common::config::bcf_mirror_knob("ZOVIA_BCF_REPLAY", true) {
                for (rung, rok) in try_prove_unreachable_via_replay(env, state, parent_cid) {
                    let rentry = RefineEntry::new(
                        rok.goal_root, rok.sym.exprs, rok.proof_bytes,
                        BCF_BUNDLE_KIND_UNREACHABLE,
                    );
                    let ra_dup = env.bcf_proofs.iter().any(|e| e.cond_hash == rentry.cond_hash);
                    census_log("replay_anc", state.pc, depth as i32, rung, rentry.cond_hash, ra_dup);
                    if std::env::var("ZOVIA_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
                        eprintln!("[replay] ANCESTOR depth={} anchor_cid={} hash={:016x}",
                            depth, parent_cid, rentry.cond_hash);
                    }
                    if !ra_dup {
                        env.bcf_proofs.push(rentry);
                    }
                }
            }
            cur_cid_opt = Some(parent_cid);
            depth += 1;
        }
    }

    // Mirror kernel bcf_refine (verifier.c:24580-81): cached
    // ancestors on the backtrack suffix of this path-unreachable
    // refinement are no longer prune-safe — a later arrival they'd
    // subsume may reach the same reject via a different path needing
    // its own path-unreachable bundle entry (cilium bpf_wireguard
    // pc246 route-B). Scoped to the same suffix base as the
    // path_conds (kernel parents[0..vstate_cnt-1]).
    crate::analysis::flow::pruning::cache::mark_path_children_unsafe(env, state, base_cid_dbg);
    // Retry-round mirror: first uncovered reject ends the round (fat /
    // base-less fallback path; same semantics as the lean return above).
    if env.bcf_rounds_mode {
        env.bcf_round_stop = true;
        env.bcf_round_new = Some(natural_cond_hash);
    }
    true
}
