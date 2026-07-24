// src/analysis/flow/precision.rs
//
// Backward precision propagation — zovia's port of the kernel's
// __mark_chain_precision / backtrack_insn (verifier.c). Two consumers:
//   * mark_chain_precision_backward / propagate_precision — mark the
//     precision-critical reg/stack lineage so pruning keeps those states
//     distinct.
//   * bcf_suffix_base_pc[_and_cache_id] — find the kernel's "base state"
//     PC for a BCF discharge, so path_conds can be filtered to the suffix
//     the kernel's bcf_track would emit.
// Both drive the shared BacktrackState / backtrack_insn_step machinery.
// Free functions over `&VerifierEnv`, matching the flow/ convention; the
// BacktrackState struct's own methods keep `self` (it is the receiver).

use std::collections::HashSet;

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;

/// Backward precision walk — minimal kernel-aligned `mark_chain_precision`
/// (verifier.c v6.15 ~L4500-4900, simplified).
///
/// At a precision sink (variable-offset memory access, kfunc/helper arg
/// requiring an exact value), the kernel walks the jmp_history backward
/// from the current insn, marking the offset register precise at every
/// prior cached state. As it walks, it tracks a *frontier* of regs whose
/// values transitively contributed to the sink:
///   - `Mov dst, Reg(src)` — replace dst with src (precision flows past
///     the move to the source's prior value).
///   - `Alu dst = dst op Reg(src)` — keep dst (its prior value also
///     contributed) and add src.
///   - `Alu dst = dst op Imm(_)` — keep dst.
///   - `Mov dst, Imm(_)` — drop dst (constant source has no chain).
///   - `Load*` / `LoadMap` / `LoadPacket` / `LoadSx` — drop dst (loaded
///     from memory; no further reg-level chain).
///   - `Call` / `CallRel` — drop R0-R5 (caller-saved clobbered).
///   - everything else — frontier unchanged.
///
/// Stops walking when the frontier becomes empty or history runs out.
/// Marks every reg in the frontier precise on every cached state in
/// `explored_states[step.pc]` at each step.
///
/// The load-bearing primitive that lets the
/// may_goto widener (`maybe_widen_reg` analogue) skip regs whose values
/// matter for downstream variable-offset bounds checks. Without this,
/// removing the over-aggressive branch precision-marker (which we
/// otherwise need) clobbers test1-4's variable-offset stores; with this,
/// the offset reg's lineage is preserved through widening sites.
pub fn mark_chain_precision_backward(
    env: &mut VerifierEnv,
    history_idx: usize,
    parent_cache_id: Option<u32>,
    sink_reg: Reg,
) {
    mark_chain_precision_backward_seeded(env, history_idx, parent_cache_id, &[sink_reg], &[]);
}

/// Batched variant (kernel `mark_chain_precision_batch` after seeding
/// `bt` with regs AND frame slots — `propagate_precision`
/// verifier.c:20003 seeds both from the matched cache): one lineage
/// walk with the reg frontier AND the stack frontier pre-seeded.
pub fn mark_chain_precision_backward_seeded(
    env: &mut VerifierEnv,
    history_idx: usize,
    parent_cache_id: Option<u32>,
    sink_regs: &[Reg],
    sink_slots: &[i16],
) {
    // Suppressed during faithful-discharge replay: re-executing the suffix
    // must not re-mark precision on the shared history (the marks already
    // exist from the original forward pass).
    if env.replay_mode {
        return;
    }
    if sink_regs.is_empty() && sink_slots.is_empty() {
        return;
    }
    // Frame-indexed frontier — kernel `bt->reg_masks[bt->frame]`
    // (verifier.c:4423-4431 bt_set_frame_reg). A flat reg set would let a
    // CALLEE's write sever the CALLER's demand across a static call.
    // Seed at the sink state's call depth (kernel bt_init(bt, st->curframe)).
    let start_depth = env.history.get(history_idx).map(|s| s.depth).unwrap_or(0);
    let mut frontier: HashSet<(usize, Reg)> = HashSet::new();
    frontier.extend(sink_regs.iter().map(|&r| (start_depth, r)));

    // Stack-slot precision frontier. Mirrors the kernel's bt->stack_masks
    // (__mark_chain_precision): when the backward walk crosses a register
    // FILL (`reg = *(R10+off)`, stack_access) whose dst is in the reg
    // frontier, precision moves INTO the slot; when it later crosses the
    // matching SPILL (`*(R10+off) = src`) precision moves back to the
    // spilled source reg AND the slot is marked precise on the lineage
    // cached states. A register-only walk would sever this chain at every
    // fill (Load/LoadMap just dropping dst), leaving spilled scalars the
    // kernel keeps precise imprecise → loose stacksafe.
    // Tracks byte offsets (the same key `stack_subsumed_by`/`get_slot`
    // use). Frame-indexed like the reg frontier (kernel bt->stack_masks[frame]).
    let mut stack_frontier: HashSet<(usize, i16)> = HashSet::new();
    stack_frontier.extend(sink_slots.iter().map(|&o| (start_depth, o)));

    let caller_saved = [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5];

    let mut current_history: Option<usize> = Some(history_idx);
    let mut current_parent_id: Option<u32> = parent_cache_id;
    let mut budget: usize = 16_384;

    // Per-path lineage walk (kernel `__mark_chain_precision`,
    // verifier.c v6.15 L4655). For each cache event in the chain:
    // walk instructions back to the parent's boundary updating the
    // frontier, then mark frontier regs precise on the SPECIFIC
    // parent cached state (not all cached states at that PC). This
    // is the per-path equivalent of kernel `st->parent` chain walk.
    'outer: loop {
        // Resolve the current parent's metadata (live-then-retired:
        // kernel st->parent pointers include free_list states).
        let (parent_history_stop, parent_grandparent_id) = {
            let s = current_parent_id.and_then(|id| env.state_by_cache_id(id));
            (
                s.and_then(|(_, s)| s.history_idx),
                s.and_then(|(_, s)| s.parent_cache_id),
            )
        };

        // Walk instructions back through current's local history,
        // stopping when we cross the parent's boundary.
        while let Some(idx) = current_history {
            if budget == 0 {
                break 'outer;
            }
            budget -= 1;

            if let Some(stop) = parent_history_stop
                && idx <= stop
            {
                break;
            }

            let Some(step) = env.history.get(idx) else {
                break;
            };
            let parent_idx = step.parent_idx;
            let instr_copy = step.instr;
            let step_pc = step.pc;
            let step_depth = step.depth;
            let step_linked = step.linked_regs.clone();
            let step_stack_access = step.stack_access;
            // Cross-frame transfers — kernel `backtrack_insn`'s subprog
            // arms, which act on the frame-indexed bt masks:
            match &instr_copy {
                // Backward across a subprog RETURN (caller → callee):
                // the caller's R0 demand transfers to the callee's R0
                // (verifier.c BPF_EXIT arm, r0_precise + bt_subprog_enter);
                // "r6-r9 and stack slots will stay set in caller frame
                // bitmasks until we return back from callee(s)".
                crate::ast::Instr::Exit => {
                    if step_depth >= 1 && frontier.remove(&(step_depth - 1, Reg::R0)) {
                        frontier.insert((step_depth, Reg::R0));
                    }
                }
                // Backward across the static subprog CALL (callee →
                // caller): callee-frame r1-r5 demands transfer to the
                // caller frame (verifier.c bt_set_frame_reg(bt->frame-1)
                // + bt_subprog_exit); the kernel asserts no other
                // callee-frame demands remain — drop the frame.
                crate::ast::Instr::CallRel { .. } => {
                    let callee = step_depth + 1;
                    for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                        if frontier.remove(&(callee, r)) {
                            frontier.insert((step_depth, r));
                        }
                    }
                    frontier.retain(|&(fd, _)| fd <= step_depth);
                    stack_frontier.retain(|&(fd, _)| fd <= step_depth);
                }
                _ => {}
            }
            // Depth-scoped application of the per-insn effects: all reg
            // and slot writes act ONLY on the step's own frame (kernel
            // bt->reg_masks[bt->frame]) — a callee-body write must not
            // touch caller-frame demands (the flat-set bug this fixes).
            let mut fr_d: HashSet<Reg> = frontier
                .iter()
                .filter(|&&(fd, _)| fd == step_depth)
                .map(|&(_, r)| r)
                .collect();
            let mut sf_d: HashSet<i16> = stack_frontier
                .iter()
                .filter(|&&(fd, _)| fd == step_depth)
                .map(|&(_, o)| o)
                .collect();
            // Kernel `bt_sync_linked_regs` (verifier.c L4116-4147),
            // called BEFORE the per-insn backtrack (L4187): if any reg
            // in this conditional's recorded id-linked class is
            // already precise, all become precise. Mirrors the
            // forward `collect_linked_regs`/`push_insn_history`.
            bt_sync_linked_regs(&mut fr_d, &step_linked);
            // Stack spill/fill precision transfer.
            // MUST run BEFORE update_frontier: update_frontier
            // unconditionally `frontier.remove(dst)` on a Load, so a
            // fill's dst would already be gone if we ran after. Kernel
            // order is also fill = clear_reg(dst) + set_slot(spi) in one
            // step; running first then letting update_frontier's
            // remove(dst) be a harmless no-op reproduces that. Store is
            // `_ => {}` in update_frontier, so a spill adding src to the
            // reg frontier here is not disturbed by the later call.
            update_stack_frontier(
                &mut fr_d,
                &mut sf_d,
                &instr_copy,
                step_stack_access,
            );
            update_frontier(&mut fr_d, &instr_copy, &caller_saved);
            // Kernel `bt_sync_linked_regs` is invoked AGAIN after
            // `backtrack_insn` (L4440) — the conditional-jump BPF_X
            // arm may have just added the other operand, which must
            // also propagate across the linked class.
            bt_sync_linked_regs(&mut fr_d, &step_linked);
            frontier.retain(|&(fd, _)| fd != step_depth);
            frontier.extend(fr_d.iter().map(|&r| (step_depth, r)));
            stack_frontier.retain(|&(fd, _)| fd != step_depth);
            stack_frontier.extend(sf_d.iter().map(|&o| (step_depth, o)));
            // Mirror frontier marks into `precise_pcs` at every
            // history step the walker traverses. The widening site
            // checks (pc, scalar_id) regardless of whether a
            // cached state at that pc still exists — eviction-
            // resistant. We need the cached state at this pc to
            // resolve scalar_ids for the frontier regs; if no
            // cached state exists at step_pc, fall back to the
            // current state's id which is the closest ground
            // truth for the path.
            for &(_, r) in &frontier {
                env.precise_pcs.insert((step_pc, r));
            }
            current_history = parent_idx;

            // Terminate only when BOTH the register frontier and the
            // stack-slot frontier are empty — the kernel's backtrack loop
            // continues while `bt_reg_mask || bt_stack_mask` (verifier.c
            // `__mark_chain_precision`). A FILL moves the last frontier reg
            // into `stack_frontier` (reg frontier now empty); stopping here
            // would abandon the spilled-slot lineage before reaching the
            // matching SPILL that converts the slot back to its source reg,
            // so the spilled scalar (and its source) never get marked
            // precise. That would let two paths spilling distinct constants
            // to the same slot wrongly subsume.
            if frontier.is_empty() && stack_frontier.is_empty() {
                break 'outer;
            }
        }

        // Mark precise on the parent cached state with the
        // frontier we've evolved back to its perspective. Per-path:
        // only this cached state, not all states at its PC
        // (live-then-retired — precision marks on a retired state
        // still matter: it can return to relevance via the
        // parent-chain of a later reject/backedge walk).
        if let Some(pc) = current_parent_id
            .and_then(|id| env.state_by_cache_id(id))
            .map(|(pc, _)| pc)
        {
            // Linked-scalar precision propagation: marking a scalar
            // precise also marks every reg sharing its scalar id IN
            // THIS cached state precise. Mirrors kernel
            // `mark_chain_precision`'s linked-regs handling (Eduard
            // Zingerman, "bpf: propagate precision in
            // mark_chain_precision for linked scalars") — the exact
            // mechanism verifier_scalar_ids.c::check_ids_in_regsafe*
            // / linked_regs_* exercise. Without it, regsafe's
            // `scalar_ids_subsumed_by` only checks the directly-marked
            // reg's id and misses the id-linkage inconsistency between
            // a checkpoint where two scalars share an id and a sibling
            // path where they do not, wrongly subsuming the unsafe
            // path. `State::mark_reg_precise` performs the in-state
            // id-class propagation; collect the resulting set so the
            // eviction-resistant `precise_pcs` mirror stays consistent.
            let mut marked: Vec<Reg> = Vec::new();
            if let Some((_, s)) =
                current_parent_id.and_then(|id| env.state_by_cache_id_mut(id))
            {
                for &(_, r) in &frontier {
                    // Kernel parent-chain apply (verifier.c:5156-5170) marks
                    // EXACTLY the bt frame regs — no scalar-id fan-out on the
                    // ancestor state. The kernel's id-class propagation is
                    // (a) mark_precise_scalar_ids on CUR at walk start and
                    // (b) hist->linked_regs during the walk (zovia mirrors it
                    // in bt_sync_linked_regs). A mark_reg_precise fan-out
                    // here would mark ancestors' unrelated-in-that-state id
                    // classes over-precise.
                    s.precise_regs.insert(r);
                }
                marked = s.precise_regs.iter().copied().collect();
                // Stack-slot precision: mark the
                // spilled-scalar slots still in the stack frontier
                // precise on this lineage cached state, so a later
                // sibling's `stack_subsumed_by` (subsumption.rs: precise
                // old slot ⇒ range_within+tnum) keeps distinct values
                // distinct instead of wildcard-merging. Mirrors kernel
                // `mark_chain_precision` writing precision onto stack
                // slots. Marks the base byte of each frontier slot (the
                // SpilledReg that carries bounds/tnum) in the current
                // frame's stack; the per-byte spill stores the value only
                // at the slot's first byte (stack_ops.rs:148).
                let cur_frame = s.frames.current_mut();
                for &(_, slot_off) in &stack_frontier {
                    if let Some(slot) = cur_frame.stack.get_slot_mut(slot_off) {
                        slot.precise = true;
                    }
                }
            }
            // Mirror the marks into the eviction-resistant
            // `precise_pcs` set. Cache eviction
            // (`max_states_per_pc`) drops the cached state's
            // `precise_regs` from the lookup chain — keep the
            // (pc, reg) facts in the env so widening sites can
            // still consult them, even after the specific cached
            // state that recorded the mark is gone.
            for &(_, r) in &frontier {
                env.precise_pcs.insert((pc, r));
            }
            for r in marked {
                env.precise_pcs.insert((pc, r));
            }
        }

        // Recurse to grandparent: continue the instruction walk
        // from parent's history boundary toward grandparent's.
        if parent_grandparent_id.is_none() {
            break;
        }
        current_parent_id = parent_grandparent_id;
        current_history = parent_history_stop;
    }
}

/// Propagate precision marks from a hit cached state into the current
/// state's ancestor chain.
///
/// Mirrors kernel `propagate_precision` (verifier.c v6.15 L18828):
/// when the current path is subsumed by a cached state, the cached
/// state's precision marks identify which scalars *must* stay
/// precise on this path's continuation for correctness. We pull
/// those marks and run `mark_chain_precision_backward` for each on
/// the CURRENT state's lineage, marking precise on the current
/// path's specific cached ancestors via `parent_cache_id`. Safe
/// under the kernel-precision regime because the walker writes
/// only to per-path-lineage cached states, not all-states-at-pc.
pub fn propagate_precision(env: &mut VerifierEnv, cur: &State, old: &State) {
    let regs: Vec<Reg> = old.precise_regs.iter().copied().collect();
    // Kernel propagate_precision (verifier.c:20003) seeds `bt` with the
    // matched cache's precise REGS *and* its precise spilled-scalar
    // STACK SLOTS (`is_spilled_reg && spilled_ptr.precise` →
    // bt_set_frame_slot) before one mark_chain_precision_batch walk.
    // Propagating only regs would let a cache holding a PRECISE spilled
    // state-tag never push that mark onto the arriving path's lineage;
    // the arriving lineage's own checkpoints would stay imprecise and
    // wildcard-merge arrivals with DIFFERENT tags where the kernel keeps
    // them apart. Current-frame slots only (zovia's stack frontier is
    // current-frame-scoped — extend with per-frame frontiers if a
    // multi-frame case surfaces).
    let slots: Vec<i16> = old
        .frames
        .current()
        .stack
        .slot_offsets()
        .into_iter()
        .filter(|&off| {
            old.frames.current().stack.get_slot(off).is_some_and(|s| {
                s.precise
                    && matches!(
                        s.kind,
                        crate::analysis::machine::stack_state::StackSlotKind::Spill
                    )
                    && matches!(s.reg_type, crate::analysis::machine::reg_types::RegType::ScalarValue)
            })
        })
        .collect();
    let Some(history_idx) = cur.history_idx else { return };
    mark_chain_precision_backward_seeded(
        env,
        history_idx,
        cur.parent_cache_id,
        &regs,
        &slots,
    );
}

/// Companion to `bcf_suffix_base_pc`: same walk, but returns
/// `(base_pc, base_cache_id)` so the caller can also identify the
/// cached state at the suffix base (needed by
/// `filter_path_conds_from_pc` to look up that base state's
/// `prev_insn_pc` and mirror the kernel's `record_path_cond` push
/// at `bcf_track` replay start).
pub fn bcf_suffix_base_pc_and_cache_id(
    env: &VerifierEnv,
    history_idx: usize,
    parent_cache_id: Option<u32>,
    target_regs: &[Reg],
) -> Option<(usize, u32)> {
    // Inline a minimal copy of the bcf_suffix_base_pc walk, returning
    // (pc, cache_id) instead of just pc. Logic mirrors the original;
    // diffs are limited to (a) returning the current_parent_id along
    // with parent_loc.pc when bt empties, (b) skipping the entry-arg
    // drain path (it only applies at pc=0, which has no cache_id —
    // callers wanting that termination keep using bcf_suffix_base_pc).
    if target_regs.is_empty() {
        return None;
    }
    let start_depth = env.history.get(history_idx).map(|s| s.depth).unwrap_or(0);
    let mut bt = BacktrackState::new();
    for &r in target_regs {
        bt.set_reg(start_depth, r);
    }
    if bt.is_empty() {
        return None;
    }

    let mut current_history: Option<usize> = Some(history_idx);
    let mut current_parent_id: Option<u32> = parent_cache_id;
    let mut budget: usize = 16_384;
    let mut skip_first = true;

    loop {
        // Live-then-retired resolution (kernel st->parent includes
        // free_list states).
        let parent_state = current_parent_id.and_then(|id| env.state_by_cache_id(id));
        let parent_pc = parent_state.map(|(pc, _)| pc);
        let (parent_history_stop, parent_grandparent_id) = (
            parent_state.and_then(|(_, s)| s.history_idx),
            parent_state.and_then(|(_, s)| s.parent_cache_id),
        );

        while let Some(idx) = current_history {
            if budget == 0 {
                return None;
            }
            budget -= 1;
            if let Some(stop) = parent_history_stop
                && idx <= stop
            {
                break;
            }
            let step = env.history.get(idx)?;
            let parent_idx = step.parent_idx;
            let instr_copy = step.instr;
            let step_depth = step.depth;
            let step_stack_access = step.stack_access;
            if !skip_first {
                if backtrack_insn_step(&mut bt, &instr_copy, step_depth, step_stack_access).is_err() {
                    return None;
                }
                if bt.is_empty() {
                    // Found the suffix base. Return its (pc, cache_id) — the
                    // kernel `base = st->parent` anchor. MUST use
                    // the SAME target mask as `bcf_suffix_base_pc` (both via
                    // `unreachable_target_regs`) or the two walks empty at
                    // different insns and this returns None → base_cid lost.
                    let pc = parent_pc?;
                    let cid = current_parent_id?;
                    return Some((pc, cid));
                }
            }
            skip_first = false;
            current_history = parent_idx;
        }
        parent_grandparent_id?;
        current_parent_id = parent_grandparent_id;
        current_history = parent_history_stop;
    }
}

pub fn bcf_suffix_base_pc(
    env: &VerifierEnv,
    history_idx: usize,
    parent_cache_id: Option<u32>,
    target_regs: &[Reg],
) -> Option<usize> {
    // ZOVIA_BCF_TRACK_DEBUG_PC: set to anything for the per-insn walk
    // trace; a numeric value restricts it to walks whose reject
    // breadcrumb sits at that pc (an all-walks trace drowns big
    // objects — one trace per discharge attempt).
    let debug = std::env::var("ZOVIA_BCF_TRACK_DEBUG_PC").is_ok()
        && std::env::var("ZOVIA_BCF_TRACK_DEBUG_PC")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .is_none_or(|p| env.history.get(history_idx).map(|s| s.pc) == Some(p));
    let probe = std::env::var("ZOVIA_DUMP_DISCHARGE").ok().as_deref() == Some("1");
    if probe {
        eprintln!("[bcf-track-start] history_idx={} targets={:?}", history_idx, target_regs);
    }
    if target_regs.is_empty() {
        if probe { eprintln!("[bcf-track-none] reason=EMPTY_TARGETS history_idx={}", history_idx); }
        return None;
    }
    // Initial precision lives in the reject state's call frame. zovia
    // records the call depth on every breadcrumb forward, so it is the
    // authoritative analogue of the kernel's `bt->frame`
    // (`bt_init(bt, st->curframe)` in `backtrack_states`).
    let start_depth = env.history.get(history_idx).map(|s| s.depth).unwrap_or(0);
    let mut bt = BacktrackState::new();
    for &r in target_regs {
        bt.set_reg(start_depth, r);
    }
    if bt.is_empty() {
        if probe { eprintln!("[bcf-track-none] reason=BT_INIT_EMPTY"); }
        return None;
    }
    if debug {
        eprintln!(
            "[bcf-track] walk start: targets={:?} start_frame={} history_idx={} parent_cache_id={:?}",
            target_regs, start_depth, history_idx, parent_cache_id
        );
    }

    let mut current_history: Option<usize> = Some(history_idx);
    let mut current_parent_id: Option<u32> = parent_cache_id;
    let mut budget: usize = 16_384;
    let mut skip_first = true;
    let mut last_pc_walked: Option<usize> = None;
    let mut first_pc_walked: Option<usize> = None;

    'outer: loop {
        // Live-then-retired resolution (kernel st->parent includes
        // free_list states; an evicted base must still resolve or the
        // suffix base degrades to None → base-less goal).
        let parent_state = current_parent_id.and_then(|id| env.state_by_cache_id(id));
        let parent_pc = parent_state.map(|(pc, _)| pc);
        let (parent_history_stop, parent_grandparent_id) = (
            parent_state.and_then(|(_, s)| s.history_idx),
            parent_state.and_then(|(_, s)| s.parent_cache_id),
        );

        while let Some(idx) = current_history {
            if budget == 0 {
                break 'outer;
            }
            budget -= 1;

            if let Some(stop) = parent_history_stop
                && idx <= stop
            {
                break;
            }

            let Some(step) = env.history.get(idx) else {
                break;
            };
            let parent_idx = step.parent_idx;
            let instr_copy = step.instr;
            let step_pc = step.pc;
            let step_depth = step.depth;
            let step_stack_access = step.stack_access;
            if first_pc_walked.is_none() { first_pc_walked = Some(step_pc); }
            last_pc_walked = Some(step_pc);

            if !skip_first {
                if backtrack_insn_step(&mut bt, &instr_copy, step_depth, step_stack_access).is_err() {
                    // Kernel `backtrack_insn` returned a negative errno
                    // (-ENOTSUPP / -EFAULT): `backtrack_states` aborts
                    // with `base = NULL`, which on the zovia side means
                    // "keep all accumulated path_conds" — sound, just
                    // not a tighter suffix.
                    if debug {
                        eprintln!(
                            "[bcf-track]   pc={:>3} {:?} -> ERR (keep all path_conds)",
                            step_pc, instr_copy
                        );
                    }
                    if probe { eprintln!("[bcf-track-none] reason=BACKTRACK_INSN_ERR pc={} instr={:?} regs={:?} stack={:?}", step_pc, instr_copy, bt.reg_masks, bt.stack_masks); }
                    return None;
                }
                if debug {
                    eprintln!(
                        "[bcf-track]   pc={:>3} d={} {:?} regs={:?} stack={:?}",
                        step_pc, step_depth, instr_copy, bt.reg_masks, bt.stack_masks
                    );
                }
                if bt.is_empty() {
                    if debug || probe {
                        let gp_pc = parent_grandparent_id
                            .and_then(|id| env.state_by_cache_id(id).map(|(pc, _)| pc));
                        eprintln!(
                            "[bcf-track] bt empty at pc={} | parent_loc_pc={:?} grandparent_pc={:?} cur_parent_id={:?} gp_id={:?}",
                            step_pc, parent_pc, gp_pc, current_parent_id, parent_grandparent_id
                        );
                    }
                    // Kernel `backtrack_states` (verifier.c:24544): on
                    // bt-empty while walking state `st`, `base = st->parent`.
                    // `parent_loc` (the cache at `current_parent_id`) IS
                    // `st->parent`; its cache pc == `base->insn_idx`, the
                    // `bcf_track` replay start (:24424). zovia's analog is
                    // the cached (live or retired) state at the current
                    // parent_cache_id. Return its PC.
                    return parent_pc;
                }
            } else if debug {
                eprintln!(
                    "[bcf-track]   pc={:>3} (skipped first: {:?})",
                    step_pc, instr_copy
                );
            }
            skip_first = false;
            current_history = parent_idx;
        }

        if parent_grandparent_id.is_none() {
            break;
        }
        // Cross into the parent state (kernel `st = st->parent`).
        current_parent_id = parent_grandparent_id;
        current_history = parent_history_stop;
    }

    // Kernel-faithful program-entry termination. If the walker reached
    // pc 0 (the BPF program's first insn — clang's `r9 = r1` ctx-arg
    // capture is the canonical case) and the only remaining bits in
    // `bt` are BPF input arg regs (R1..R5) in the entry frame, those
    // regs are defined by the caller (the BPF runtime), not by any
    // in-program insn. The kernel's `backtrack_states` handles this
    // implicitly because input-arg precision is satisfied at frame
    // entry; the kernel's `bt_reg_mask(bt) & BPF_REGMASK_ARGS` is the
    // exact analog of `BacktrackState::args_set`.
    //
    // Without this drain, every BCF discharge that walks back to pc 0
    // returns `None`, which `mark_path_children_unsafe` interprets as
    // "no suffix bound — mark the whole lineage `children_unsafe`",
    // poisoning subsumption across the whole cache.
    if last_pc_walked == Some(0) {
        for arg in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
            bt.clear_reg(start_depth, arg);
        }
        if bt.is_empty() {
            if probe {
                eprintln!("[bcf-track-entry-drain] succeeded → returning Some(0)");
            }
            return Some(0);
        }
    }

    if probe {
        eprintln!(
            "[bcf-track-none] reason=WALKED_WHOLE_HISTORY budget_used={} first_pc={:?} last_pc={:?} regs_still_in_bt={:?} stack_still_in_bt={:?}",
            16_384 - budget, first_pc_walked, last_pc_walked, bt.reg_masks, bt.stack_masks
        );
    }
    None
}

/// Kernel `bt_sync_linked_regs` (verifier.c L4116-4147): the breadcrumb
/// for a conditional jump records the scalar registers that shared the
/// compared register's scalar id (`collect_linked_regs`). If ANY of them
/// is currently in the precision frontier, ALL of them must be — the
/// kernel propagates a refined range across the whole id class, so a
/// precision requirement on one is a precision requirement on all.
fn bt_sync_linked_regs(frontier: &mut HashSet<Reg>, linked: &[Reg]) {
    if linked.len() < 2 {
        return;
    }
    if linked.iter().any(|r| frontier.contains(r)) {
        for &r in linked {
            frontier.insert(r);
        }
    }
}

/// Update `frontier` (the set of registers whose precision must
/// propagate further back) given that we are *un-doing* `instr`.
/// Pure free function so the walker can call it without re-borrowing
/// `self`.
fn update_frontier(
    frontier: &mut HashSet<Reg>,
    instr: &crate::ast::Instr,
    caller_saved: &[Reg],
) {
    use crate::ast::{AluOp, Instr, Operand};
    match instr {
        Instr::Alu { op, dst, src, .. } => {
            if frontier.contains(dst) {
                match (op, src) {
                    (AluOp::Mov, Operand::Reg(s)) => {
                        frontier.remove(dst);
                        frontier.insert(*s);
                    }
                    (AluOp::Mov, Operand::Imm(_)) => {
                        frontier.remove(dst);
                    }
                    (_, Operand::Reg(s)) => {
                        frontier.insert(*s);
                    }
                    (_, Operand::Imm(_)) => {}
                }
            }
        }
        Instr::MovSx { dst, src, .. } => {
            if frontier.contains(dst) {
                frontier.remove(dst);
                if let Operand::Reg(s) = src {
                    frontier.insert(*s);
                }
            }
        }
        Instr::Load { dst, .. }
        | Instr::LoadSx { dst, .. }
        | Instr::LoadAcq { dst, .. }
        | Instr::LoadMap { dst, .. } => {
            frontier.remove(dst);
        }
        Instr::LoadPacket { .. } => {
            frontier.remove(&Reg::R0);
        }
        Instr::Endian { dst, .. } => {
            let _ = dst;
        }
        Instr::Call { .. } => {
            // Helper / kfunc call: forward-direction clobbers
            // R0..R5. Going backward at this step means the values in
            // R0..R5 immediately after the call don't have a
            // pre-call source (R0 is the helper's return; R1..R5 are
            // clobbered). Drop them from the frontier.
            for r in caller_saved {
                frontier.remove(r);
            }
        }
        Instr::CallRel { .. } => {
            // Subprog call: drop only R0 (the callee's return value
            // — its source lives inside the callee body, which the
            // walker already traversed before reaching this CallRel
            // step on the linear history). R1..R5 in the frontier
            // post-call are the caller's pre-call arg-setup regs and
            // must propagate further back so the precision walk
            // reaches the caller-side instructions that wrote them
            // (e.g. `w2 = r7` at the call site, which is what
            // bridges arena_htab_llvm's loop-counter `r7` back to
            // the access-time precision sink inside the callee).
            // Walking across frames is more permissive than the
            // kernel's per-frame `mark_chain_precision` but matches
            // our linear-history walker's structure.
            frontier.remove(&Reg::R0);
        }
        Instr::If { left, right, .. } => {
            // Kernel `backtrack_insn` conditional-jump arm
            // (verifier.c L4407-4424):
            //   BPF_X (`dreg <cond> sreg`): if NEITHER operand needs
            //     precision, the jump is irrelevant — no change. If
            //     EITHER does, BOTH operands needed precision before
            //     this insn (the branch outcome depended on both), so
            //     add both.
            //   BPF_K (`dreg <cond> K`): only dreg still needs
            //     precision, which is already reflected — nothing new.
            if let Operand::Reg(s) = right
                && (frontier.contains(left) || frontier.contains(s))
            {
                frontier.insert(*left);
                frontier.insert(*s);
            }
        }
        _ => {}
    }
}

/// Stack spill/fill precision transfer for the backward precision walk.
/// Mirrors the kernel `backtrack_insn` STACK_SPILL
/// handling that `backtrack_insn_step` already implements for the
/// discharge-base walker — but applied to the precision frontier so
/// `SpilledReg.precise` gets set on the lineage.
///
/// Direction is BACKWARD (un-doing `instr`). `stack_access` is zovia's
/// `INSN_F_STACK_ACCESS` analog (a genuine slot-aligned register
/// spill/fill); a plain stack data load/store leaves it false and is NOT
/// followed (mirrors the kernel gate, keeps the suffix from running away).
///
///   FILL  `dst = *(R10+off)`  (Load, base==R10, stack_access):
///       if dst ∈ reg frontier  ⇒  remove dst, add slot `off` to stack
///       frontier. The value dst needs came FROM the slot, so precision
///       moves into the slot; the matching spill (seen later going back)
///       moves it on to the spilled source reg.
///   SPILL `*(R10+off) = src`  (Store, base==R10, stack_access):
///       if slot `off` ∈ stack frontier ⇒ remove it, add `src` to reg
///       frontier. The slot's value came from `src`; the caller marks the
///       slot precise on the cached state at this lineage point.
///
/// Offsets are byte offsets (the key `get_slot`/`stack_subsumed_by` use).
/// `base != R10` accesses are heap/ctx/packet, not stack slots — ignored.
fn update_stack_frontier(
    reg_frontier: &mut HashSet<Reg>,
    stack_frontier: &mut HashSet<i16>,
    instr: &crate::ast::Instr,
    stack_access: bool,
) {
    use crate::ast::{Instr, Operand};
    if !stack_access {
        return;
    }
    match instr {
        // FILL: reg loaded from a stack slot.
        Instr::Load { dst, base, off, .. }
        | Instr::LoadSx { dst, base, off, .. }
        | Instr::LoadAcq { dst, base, off, .. } => {
            if *base == Reg::R10 && reg_frontier.contains(dst) {
                reg_frontier.remove(dst);
                stack_frontier.insert(*off);
            }
        }
        // SPILL: reg stored to a stack slot. `Store.src` is an Operand
        // (BPF_ST const-spill carries no source reg ⇒ nothing to add back);
        // `StoreRel.src` is a Reg.
        Instr::Store { src, base, off, .. } => {
            if *base == Reg::R10 && stack_frontier.remove(off)
                && let Operand::Reg(s) = src {
                    reg_frontier.insert(*s);
                }
        }
        Instr::StoreRel { src, base, off, .. } => {
            if *base == Reg::R10 && stack_frontier.remove(off) {
                reg_frontier.insert(*src);
            }
        }
        _ => {}
    }
}

/// Per-frame register + stack-slot precision masks — a faithful mirror
/// of the kernel's `struct backtrack_state` (vendor verifier.c). For
/// frame `f`: `reg_masks[f]` bit `i` (`Reg::bcf_idx`, 0..=10 where 10 =
/// `BPF_REG_FP`/R10) tracks a register that needs precision; and
/// `stack_masks[f]` bit `spi` tracks a spilled-scalar stack slot. Frames
/// are indexed by the breadcrumb's call depth (zovia records this
/// forward — the authoritative analogue of the kernel's `bt->frame`).
struct BacktrackState {
    reg_masks: Vec<u16>,
    stack_masks: Vec<u64>,
}

impl BacktrackState {
    fn new() -> Self {
        Self { reg_masks: Vec::new(), stack_masks: Vec::new() }
    }

    #[inline]
    fn ensure(&mut self, frame: usize) {
        if self.reg_masks.len() <= frame {
            self.reg_masks.resize(frame + 1, 0);
            self.stack_masks.resize(frame + 1, 0);
        }
    }

    #[inline]
    fn set_reg(&mut self, frame: usize, reg: Reg) {
        if let Some(b) = reg.bcf_idx() {
            self.ensure(frame);
            self.reg_masks[frame] |= 1u16 << b;
        }
    }

    #[inline]
    fn clear_reg(&mut self, frame: usize, reg: Reg) {
        if let Some(b) = reg.bcf_idx()
            && frame < self.reg_masks.len()
        {
            self.reg_masks[frame] &= !(1u16 << b);
        }
    }

    #[inline]
    fn is_reg_set(&self, frame: usize, reg: Reg) -> bool {
        reg.bcf_idx().is_some_and(|b| {
            frame < self.reg_masks.len() && self.reg_masks[frame] & (1u16 << b) != 0
        })
    }

    #[inline]
    fn set_slot(&mut self, frame: usize, spi: u32) {
        self.ensure(frame);
        self.stack_masks[frame] |= 1u64 << spi;
    }

    #[inline]
    fn clear_slot(&mut self, frame: usize, spi: u32) {
        if frame < self.stack_masks.len() {
            self.stack_masks[frame] &= !(1u64 << spi);
        }
    }

    #[inline]
    fn is_slot_set(&self, frame: usize, spi: u32) -> bool {
        frame < self.stack_masks.len() && self.stack_masks[frame] & (1u64 << spi) != 0
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.reg_masks.iter().all(|&m| m == 0) && self.stack_masks.iter().all(|&m| m == 0)
    }

    /// Any of R1..R5 (the BPF arg registers) still set in `frame`. Mirror
    /// of kernel `bt_reg_mask(bt) & BPF_REGMASK_ARGS`.
    #[inline]
    fn args_set(&self, frame: usize) -> bool {
        // bcf_idx: R1=1 .. R5=5 ⇒ bits 1..=5.
        frame < self.reg_masks.len() && self.reg_masks[frame] & 0b0011_1110 != 0
    }
}

/// Kernel stack-slot index for a frame-pointer-relative register
/// spill/fill, or `None` if this access is *not* a tracked register
/// spill/fill (so the kernel records `insn_flags = 0` and
/// `backtrack_insn` does not follow it into the slot).
///
/// The kernel records `INSN_F_STACK_ACCESS` only for an 8-byte-aligned,
/// `BPF_REG_SIZE`-sized access (`!(off % BPF_REG_SIZE) && size ==
/// BPF_REG_SIZE` in `check_stack_{read,write}_fixed_off`); partial /
/// unaligned writes and non-restoring fills are plain stack data
/// (STACK_MISC/ZERO), `insn_flags = 0`. Mirroring that gate is what
/// keeps the precision suffix from running away through every buffer
/// write. `spi = (-off - 1) / BPF_REG_SIZE`; slots ≥ 64 (beyond
/// `MAX_BPF_STACK / 8`) are out of mask range.
#[inline]
fn spi_of(off: i16) -> Option<u32> {
    if off >= 0 {
        return None;
    }
    let slot = (-(off as i32)) - 1;
    if slot < 0 {
        return None;
    }
    let spi = (slot / 8) as u32;
    if spi >= 64 { None } else { Some(spi) }
}

/// Whether a stack-relative LDX/STX continues the precision chain into
/// its slot is read from the breadcrumb's `stack_access` flag —
/// zovia's analog of the kernel's `hist->flags & INSN_F_STACK_ACCESS`,
/// set forward only for a genuine register spill/fill (see
/// [`crate::analysis::machine::history::Breadcrumb::stack_access`] and
/// the forward marking in the memory transfer). The slot index is
/// recovered from the insn's own fixed offset via [`spi_of`], exactly as
/// the kernel recovers it from `insn_stack_access_spi(hist->flags)`.
///
/// Faithful port of the kernel's `backtrack_insn` (vendor verifier.c) for
/// one linear-history step: mutate the per-frame precision masks `bt`
/// given that we are *un-doing* `instr`, which executed in call `frame`.
///
/// `Err(())` mirrors the kernel returning a negative errno (-ENOTSUPP /
/// -EFAULT) from `backtrack_insn`: `backtrack_states` then aborts with
/// `base = NULL`, which on the zovia side means "keep all accumulated
/// path_conds" (sound, just not as tight a suffix).
fn backtrack_insn_step(
    bt: &mut BacktrackState,
    instr: &crate::ast::Instr,
    frame: usize,
    stack_access: bool,
) -> Result<(), ()> {
    use crate::ast::{AluOp, Instr, Operand};
    match instr {
        // ── BPF_ALU / BPF_ALU64 ──────────────────────────────────────
        Instr::Alu { op, dst, src, .. } => {
            if !bt.is_reg_set(frame, *dst) {
                return Ok(());
            }
            match op {
                // BPF_NEG: sreg reserved/unused; dreg still needs
                // precision before this insn — nothing new.
                AluOp::Neg => {}
                AluOp::Mov => {
                    bt.clear_reg(frame, *dst);
                    if let Operand::Reg(s) = src
                        && *s != Reg::R10
                    {
                        // dreg = sreg: sreg needs precision before.
                        bt.set_reg(frame, *s);
                    }
                }
                _ => {
                    // dreg = dreg <op> src: dreg stays precise; a reg
                    // src also needs precision before this insn.
                    if let Operand::Reg(s) = src
                        && *s != Reg::R10
                    {
                        bt.set_reg(frame, *s);
                    }
                }
            }
        }
        // BPF_MOV with sign-extend (BPF_X form): dreg = (sN)sreg.
        Instr::MovSx { dst, src, .. } => {
            if !bt.is_reg_set(frame, *dst) {
                return Ok(());
            }
            bt.clear_reg(frame, *dst);
            if let Operand::Reg(s) = src
                && *s != Reg::R10
            {
                bt.set_reg(frame, *s);
            }
        }
        // BPF_END: like BPF_NEG — dreg stays precise, nothing new.
        Instr::Endian { .. } => {}
        // ── BPF_LDX (incl. atomic load-acquire) ──────────────────────
        Instr::Load { size, dst, base, off }
        | Instr::LoadSx { size, dst, base, off }
        | Instr::LoadAcq { size, dst, base, off } => {
            if !bt.is_reg_set(frame, *dst) {
                return Ok(());
            }
            let _ = (size, base);
            bt.clear_reg(frame, *dst);
            // Kernel `backtrack_insn` BPF_LDX clause: a load from
            // non-stack memory can be zero-extended — precision is
            // already on `dst`, nothing further. Only a *register fill*
            // continues the chain into the slot, and the kernel gates
            // that solely on `hist->flags & INSN_F_STACK_ACCESS`
            // (verifier.c:4612). zovia's `stack_access` breadcrumb flag
            // is that bit; the slot index comes from the insn's fixed
            // offset (kernel `insn_stack_access_spi`).
            if stack_access
                && let Some(spi) = spi_of(*off)
            {
                bt.set_slot(frame, spi);
            }
        }
        // ld_imm64 / map-ptr load: clear dst; no further tracking.
        Instr::LoadMap { dst, .. } => {
            if !bt.is_reg_set(frame, *dst) {
                return Ok(());
            }
            bt.clear_reg(frame, *dst);
        }
        // ld_abs / ld_ind: kernel returns -ENOTSUPP ("to be analyzed").
        Instr::LoadPacket { .. } => return Err(()),
        // ── BPF_STX / BPF_ST (incl. atomics) ─────────────────────────
        // ── BPF_STX / BPF_ST ─────────────────────────────────────────
        // Kernel `backtrack_insn` STX/ST clause (verifier.c:4621):
        //  * a precise *scalar* mem-base ⇒ pointer subtraction ⇒
        //    -ENOTSUPP;
        //  * `!(hist->flags & INSN_F_STACK_ACCESS)` ⇒ `return 0` —
        //    a plain data store does **not** clear the slot (the old
        //    `store_slot` cleared it unconditionally, which severed the
        //    chain a step early when a data write aliased a tracked
        //    spi);
        //  * else clear the slot; for class==BPF_STX propagate precision
        //    to the spilled source reg (BPF_ST const propagates nothing).
        Instr::Store { off, base, src, .. } => {
            if bt.is_reg_set(frame, *base) {
                return Err(());
            }
            if !stack_access {
                return Ok(());
            }
            let Some(spi) = spi_of(*off) else {
                return Ok(());
            };
            if !bt.is_slot_set(frame, spi) {
                return Ok(());
            }
            bt.clear_slot(frame, spi);
            if let Operand::Reg(s) = src {
                bt.set_reg(frame, *s);
            }
        }
        Instr::StoreRel { off, base, src, .. } => {
            if bt.is_reg_set(frame, *base) {
                return Err(());
            }
            if !stack_access {
                return Ok(());
            }
            let Some(spi) = spi_of(*off) else {
                return Ok(());
            };
            if !bt.is_slot_set(frame, spi) {
                return Ok(());
            }
            bt.clear_slot(frame, spi);
            bt.set_reg(frame, *src);
        }
        Instr::Atomic { off, base, src, .. } => {
            if bt.is_reg_set(frame, *base) {
                return Err(());
            }
            if !stack_access {
                return Ok(());
            }
            let Some(spi) = spi_of(*off) else {
                return Ok(());
            };
            if !bt.is_slot_set(frame, spi) {
                return Ok(());
            }
            bt.clear_slot(frame, spi);
            bt.set_reg(frame, *src);
        }
        // ── BPF_JMP / BPF_JMP32 ──────────────────────────────────────
        // Static BPF-to-BPF subprog call. Backtracking *past* it exits
        // the callee back into the caller: r1-r5 (the args) propagate
        // from the callee frame to the caller frame.
        Instr::CallRel { .. } => {
            let callee = frame + 1;
            for r in [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5] {
                if bt.is_reg_set(callee, r) {
                    bt.clear_reg(callee, r);
                    bt.set_reg(frame, r);
                }
            }
        }
        // Helper / kfunc call: sets R0; r1-r5 are clobbered and should
        // have been resolved already (kernel treats leftover args as a
        // verifier bug → -EFAULT → keep-all).
        Instr::Call { .. } => {
            bt.clear_reg(frame, Reg::R0);
            if bt.args_set(frame) {
                return Err(());
            }
        }
        // Subprog/callback return. Backtracking past EXIT enters the
        // callee frame; propagate R0 (the return value) if the caller
        // still needs it precise.
        Instr::Exit => {
            if frame >= 1 {
                let caller = frame - 1;
                let r0_precise = bt.is_reg_set(caller, Reg::R0);
                bt.clear_reg(caller, Reg::R0);
                if r0_precise {
                    bt.set_reg(frame, Reg::R0);
                }
            }
        }
        // Conditional jump. BPF_X: if either operand was precise after,
        // both need precision before. BPF_K / JA: nothing new.
        Instr::If { left, right, .. } => {
            if let Operand::Reg(r) = right {
                if !bt.is_reg_set(frame, *left) && !bt.is_reg_set(frame, *r) {
                    return Ok(());
                }
                bt.set_reg(frame, *r);
                bt.set_reg(frame, *left);
            }
        }
        Instr::Jmp { .. } | Instr::MayGoto { .. } => {}
    }
    Ok(())
}
