// src/analysis/flow/pruning/widening.rs
//
// Kernel-faithful loop-detection / iter-next widening helpers ONLY.
//
// The kernel-absent (A) layer of widening — per-shape detectors,
// general-loop scalar widening, force_widen_for_may_goto,
// counter_widen_set, demote_set, check_loop_convergence — has been
// DELETED. The kernel converges loops by:
//   (i) imprecise scalars acting as wildcards in `regsafe` ⇒ loop
//       counters that don't feed safety decisions subsume immediately;
//  (ii) the `widen_imprecise_scalars` call in `process_iter_next_call`
//       (kernel verifier.c L8765) — narrowly scoped to bpf_iter_*_next
//       call sites, fired only when a previous iteration's checkpoint
//       exists with `prev.depth + 2 == cur.depth`; AND
// (iii) explicit DFS back-edge handling with `init_explored_state`
//      checkpoints.
//
// (ii) lives in `kfunc.rs::iter_next_fork →
// widen_imprecise_scalars_at_iter_next_call` — a kernel-faithful
// implementation already in zovia. The helpers below support (iii) by
// identifying back-edges, loop heads, and iter-loop convergence
// conditions so `handle_loop_pruning` knows when to defer the back-
// edge target prune so the looped-back state can re-reach iter_next
// for widening.

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::state::State;
use crate::ast::{Instr, Program};

pub(super) fn loop_has_conditional_exit(
    env: &VerifierEnv,
    state: &State,
    pc: usize,
    prog: &Program,
) -> bool {
    if let Some(idx) = state.history_idx {
        // Only check PCs at the same frame depth (excludes callee instructions)
        let body_pcs = env.history.loop_body_pcs(idx, pc, Some(state.num_frames()));
        for body_pc in body_pcs {
            if body_pc < prog.instrs.len()
                && matches!(
                    prog.instrs[body_pc],
                    Instr::If { .. } | Instr::MayGoto { .. }
                )
            {
                return true;
            }
        }
    }
    // Also check the loop head itself. `MayGoto` is a budget-bounded
    // conditional exit (BPF_JCOND v6.8): the kernel inlines a hidden
    // counter check that eventually short-circuits the back-edge.
    if pc < prog.instrs.len() && matches!(prog.instrs[pc], Instr::If { .. } | Instr::MayGoto { .. })
    {
        return true;
    }
    false
}

/// Check if current PC is a designated prune point (set by CFG init).
pub(crate) fn is_prune_point(env: &VerifierEnv, pc: usize) -> bool {
    env.insn_aux_data
        .get(pc)
        .map(|aux| aux.prune_point)
        .unwrap_or(false)
}

/// Check if the current instruction is a backward-jumping branch.
fn is_backward_branch(pc: usize, prog: &Program) -> bool {
    if pc >= prog.instrs.len() {
        return false;
    }
    match &prog.instrs[pc] {
        Instr::If { target, .. } | Instr::Jmp { target } => *target < pc,
        // A `may_goto` whose target is at or behind itself is a back-edge
        // (`l0: may_goto l0` off=-1 → target==pc; off<0 → target<pc). `<= pc`
        // so the self-target counts; a forward may_goto (the common
        // cond_break exit, target>pc) is NOT a back-edge. Without this the
        // self/back may_goto isn't a loop point → EXACT inf-loop trap skipped
        // → standard subsumption prunes the infinite self-loop away → FA.
        Instr::MayGoto { target } => *target <= pc,
        _ => false,
    }
}

/// Check if we arrived at current PC via a backward jump (loop head detection).
pub(super) fn arrived_via_back_edge(
    env: &VerifierEnv,
    state: &State,
    pc: usize,
    prog: &Program,
) -> bool {
    state
        .history_idx
        .and_then(|idx| {
            let prev_step = env.history.get(idx)?;
            let prev_pc = prev_step.pc;
            if prev_pc >= prog.instrs.len() {
                return Some(false);
            }
            match &prog.instrs[prev_pc] {
                Instr::If { target, .. } | Instr::Jmp { target }
                    if *target == pc && prev_pc > pc =>
                {
                    Some(true)
                }
                // may_goto back-edge / self-loop: prev insn was a `may_goto`
                // jumping to `pc` from at or behind `pc` (`prev_pc >= pc`
                // covers the `l0: may_goto l0` self case). See is_backward_branch.
                Instr::MayGoto { target } if *target == pc && prev_pc >= pc => Some(true),
                _ => Some(false),
            }
        })
        .unwrap_or(false)
}

/// Determine if we're at an actual loop point (back-edge).
///
/// A loop point is either:
/// 1. A backward-jumping branch (source of back-edge): If/Jmp with target < pc
/// 2. The target of a backward jump (loop head): arrived here via a backward jump
///
/// We require that the history confirms this is a back-edge at the current call depth,
/// not just that we've visited this PC before on some other path.
pub(super) fn is_at_loop_point(
    env: &VerifierEnv,
    state: &State,
    pc: usize,
    prog: &Program,
) -> bool {
    // History must confirm this is a back-edge at current call depth
    let is_back_edge_pc = state
        .history_idx
        .map(|idx| env.history.is_back_edge(idx, pc, state.num_frames()))
        .unwrap_or(false);

    is_back_edge_pc && (is_backward_branch(pc, prog) || arrived_via_back_edge(env, state, pc, prog))
}

/// True iff the loop body rooted at `pc` contains a force-checkpoint
/// PC (iter_next kfunc / may_goto / sync-cb-call helper) — i.e. this
/// is an iterator-style loop whose convergence the kernel guarantees
/// via `process_iter_next_call` at the force-checkpoint site rather
/// than at arbitrary back-edge targets.
pub(super) fn loop_body_has_force_checkpoint(env: &VerifierEnv, state: &State, pc: usize) -> bool {
    state
        .history_idx
        .map(|idx| {
            env.history
                .loop_body_pcs(idx, pc, Some(state.num_frames()))
                .into_iter()
                .any(|body_pc| {
                    env.insn_aux_data
                        .get(body_pc)
                        .map(|a| a.force_checkpoint)
                        .unwrap_or(false)
                })
        })
        .unwrap_or(false)
}

/// True iff this loop's OWN iter_next (the force-checkpoint closest to
/// the loop head on the back-walk through the body) operates on an iter
/// slot still on its very first iter_next call (`depth < 2`, where
/// depth bumps at each iter_next). The kernel's
/// `process_iter_next_call` `widen_imprecise_scalars` only fires
/// starting at depth=2 (`prev_slot.depth + 2 == cur_iter_depth`);
/// before that, no widening has happened yet on this path and pruning
/// at non-checkpoint back-edge targets in this loop body MUST be
/// deferred — else the looped-back state is discarded before re-
/// reaching iter_next where widening would catch the FA.
///
/// Look at THIS LOOP's iter slot (via `env.iter_pc_slot` from the
/// body's iter_next pc nearest the loop head), not all active iters —
/// otherwise nested iter loops (`loop_state_deps1` outer+inner,
/// `clean_live_states` 7 levels) misbehave: a freshly-allocated inner
/// iter would permanently defer outer pruning, or a widened outer
/// iter would prematurely re-enable pruning at the inner back-edge
/// before the inner had widened.
pub(super) fn this_loop_iter_pre_widening(env: &VerifierEnv, state: &State, pc: usize) -> bool {
    use crate::analysis::machine::frame_stack::FrameLevel;
    use crate::analysis::machine::stack_state::IterState;
    let Some(idx) = state.history_idx else {
        return false;
    };
    // `loop_body_pcs` walks `parent_idx` BACKWARD from the latest step
    // (back-edge source) until it hits `pc` (target = loop head). The
    // LAST force-checkpoint encountered along that walk is the one
    // closest to the loop head — i.e. THIS loop's own iter_next, not
    // a nested loop's iter_next.
    let body_pcs = env.history.loop_body_pcs(idx, pc, Some(state.num_frames()));
    let own_iter_next_pc = body_pcs.iter().copied().rev().find(|&body_pc| {
        env.insn_aux_data
            .get(body_pc)
            .map(|a| a.force_checkpoint)
            .unwrap_or(false)
    });
    let Some(body_pc) = own_iter_next_pc else {
        return false;
    };
    let Some(&(frame_idx, off)) = env.iter_pc_slot.get(&body_pc) else {
        // First-ever visit to this loop's iter_next on this path:
        // the kfunc widening hasn't recorded a slot yet ⇒ definitely
        // pre-widening. Defer.
        return true;
    };
    if frame_idx >= state.num_frames() {
        return false;
    }
    let frame = state.frames.get(FrameLevel::from_index(frame_idx));
    let Some(slot) = frame.stack.stack_get_iterator(off) else {
        return true;
    };
    if slot.state != IterState::Active {
        return false;
    }
    slot.depth < 2
}
