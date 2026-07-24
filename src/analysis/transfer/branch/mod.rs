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
use crate::refinement::bcf::{BPF_JEQ, BPF_JNE};
use crate::refinement::emit::{
    cmp_op_to_bcf_pair, record_path_cond_for_side, try_emit_path_unreachable_entry,
};

use self::constraints::apply_jmp_constraints;
use self::interval_packet::refine_packet_bounds_on_branch;
use self::outcome::condition_outcome;
use self::refinement::{propagate_scalar_links, refine_branch};
use super::common::check_operand_readable;


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
            // valve, so count it here too.
            state.jmp_history_cnt = state.jmp_history_cnt.saturating_add(1);
        }
    }

    // ZOVIA_DBG_BRANCHVAL=<pc>: dump the branch operand's tracked value at
    // that pc.
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
    // (pred >= 0, one side dead). Firing on unresolved conditionals
    // eagerly over-marks loop counters and accumulators precise,
    // blocking subsumption across iterations.
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
    // own LHS/RHS types and skips emission when either isn't a SCALAR
    // (e.g. an OR_NULL reg demoted to scalar on the null side only).
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
        // Pre-compute K==K rewrite metadata per side: the side whose LHS
        // narrows to const K on entry gets the rewrite candidate;
        // lhs_materialize_pc is filled in per-side inside
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

