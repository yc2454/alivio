// Faithful base->reject replay (kernel bcf_track mirror): re-execute the
// suffix from a cached ancestor with a fresh bcf so path conds and refine
// exprs rebuild exactly as the kernel's one-table replay would.

use super::record::{cmp_op_to_bcf_pair, record_path_cond_for_side};
use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::state::State;
use crate::ast::{Instr, Operand};

/// Faithful discharge via base→reject replay (mirrors kernel `bcf_track`,
/// verifier.c:24633). Instead of reconstructing the goal from the live
/// state's recorded path_conds (which can include branches off the kernel's
/// actual replay path, and mis-cache pre-window materializations), this
/// re-executes the instruction path from the cached base state to the
/// reject, with a fresh bcf, so `state.bcf.path_conds` is rebuilt exactly
/// as the kernel's re-execution would.
/// Returns the proven goals or empty (no base cache, path divergence, or
/// cvc5 declined).
pub(crate) fn try_prove_unreachable_via_replay(
    env: &mut VerifierEnv,
    reject_state: &State,
    base_cid: u32,
) -> Vec<(i32, crate::refinement::refine_unreachable::UnreachableOk)> {
    // Each goal is tagged with its reset-ladder rung: -1 = the plain replay
    // (no reset point), k >= 0 = the pc of the If the bcf was reset after.
    // Diagnosis-only (ALIVIO_BCF_CENSUS); does not affect emission.

    let empty = Vec::new();
    // 1. Retrieve the cached base State (with its register/domain state).
    //    Live-then-retired: the kernel's bcf_track base (`st->parent`)
    //    may be an evicted (free_list) state.
    let Some(base_state) = env.state_by_cache_id(base_cid).map(|(_, s)| s.clone()) else {
        return empty;
    };
    let base_hidx = base_state.history_idx;

    // 2. Recover the forward base→reject instruction path by walking the
    //    Breadcrumb parent chain from the reject insn's breadcrumb.
    let Some(reject_bc) = env.current_step_idx else {
        return empty;
    };
    let mut path: Vec<(usize, Instr)> = Vec::new();
    let mut cur = Some(reject_bc);
    let mut budget: usize = 200_000;
    while let Some(idx) = cur {
        if Some(idx) == base_hidx {
            break;
        }
        match budget.checked_sub(1) {
            Some(b) => budget = b,
            None => return empty,
        }
        let Some(bc) = env.history.get(idx) else {
            return empty;
        };
        path.push((bc.pc, bc.instr));
        cur = bc.parent_idx;
    }
    let dbg = std::env::var("ALIVIO_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1");
    if path.is_empty() {
        return empty;
    }
    path.reverse(); // forward order: base_pc .. reject branch

    let dead_target = reject_state.pc;
    let Some(reject_pc) = env.history.get(reject_bc).map(|b| b.pc) else {
        return empty;
    };
    let is_branch_reject = reject_state.pc != reject_pc;
    let n_exec = if is_branch_reject {
        path.len()
    } else {
        path.len() - 1
    };
    if n_exec == 0 {
        return empty;
    }
    if dbg {
        eprintln!(
            "[replay] STRUCT reject_pc={} reject_state.pc={} is_branch={} path[0]={} path[last]={} len={} n_exec={}",
            reject_pc,
            reject_state.pc,
            is_branch_reject,
            path[0].0,
            path[path.len() - 1].0,
            path.len(),
            n_exec
        );
    }

    // 3. Reset points: None = the plain replay (bcf reset at the suffix base).
    //    NARROWBASE (default-ON) adds TWO per CONDITIONAL branch step k,
    //    mirroring the two kernel base shapes around an If:
    //    - post-If reset (pre=false): bcf base PAST the narrowing — the LHS
    //      materializes POST-narrow (kernel bcf_track base = st->parent past
    //      the narrowing branch).
    //    - pre-If reset (pre=true): kernel checkpoint AT the If insn — the
    //      replay's fresh bcf sees the If itself, so the cond records with
    //      PRE-branch materialization (VAR + current bounds, no const fold).
    //    Emitted ADDITIVELY (caller dedups by cond_hash).
    let mut reset_points: Vec<(Option<usize>, bool)> = vec![(None, false)];
    {
        for i in 0..n_exec {
            if matches!(path[i].1, Instr::If { .. }) {
                reset_points.push((Some(i), false));
                reset_points.push((Some(i), true));
            }
            // Kernel checkpoint-at-post-call-fallthrough base (pre-reset
            // only): helper-call fallthroughs are kernel jmp/prune points;
            // when the kernel's counters fire there, the demanded goal's
            // suffix starts at the post-call insn with first-refs
            // materializing fresh bounds; the reset-rung supplies that
            // shape even when alivio has no cached anchor there.
            if i > 0 && matches!(path[i - 1].1, Instr::Call { .. }) {
                reset_points.push((Some(i), true));
            }
        }
    }

    // Kernel bcf_track replays run in a CLEAN verification context: the
    // original reject's errno is a local in the caller (check_helper_call's
    // -EACCES → bcf_prove_unreachable), not verifier-global state, so the
    // replay's own check_helper_call passes and path conds keep recording.
    // alivio's env.error is global and still holds the triggering reject
    // here; without the stash, transfer_call's `env.failed()` kills the
    // replay at the FIRST helper call on the suffix. Each rung starts
    // error-free; a rung's own fresh failure dies with that rung and must
    // not leak into the next (or the caller).
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
        // starts AFTER that branch and would otherwise drop it. Kernel
        // guards mirrored: branch insns only (JA/CALL/EXIT skipped by the
        // If match), scalar dst/src only. Rung variants re-reset
        // downstream, wiping this push — correct (their anchor is the
        // rung insn).
        if std::env::var("ALIVIO_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
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
            && let Instr::If {
                width,
                left,
                op,
                right,
                target,
            } = bc.instr
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
                    &mut base_state,
                    width,
                    left,
                    op,
                    op_byte,
                    &right,
                    prev_pc,
                    None,
                    pre_b,
                );
            }
        }
        env.replay_mode = true;
        let mut holder: Option<State> = Some(base_state);
        for i in 0..n_exec {
            let pc = path[i].0;
            let instr = path[i].1;
            let st = match holder.take() {
                Some(s) => s,
                None => break,
            };
            let mut st = st;
            st.pc = pc;
            if pre_reset && Some(i) == reset_after_idx {
                // Kernel checkpoint-at-If base: fresh bcf BEFORE the If's
                // transfer — the cond below records into it pre-narrow.
                st.reset_bcf_for_replay();
            }
            let succ = crate::analysis::transfer::transfer(env, st, &instr);
            let next_pc = if i + 1 < path.len() {
                path[i + 1].0
            } else {
                dead_target
            };
            holder = succ.into_iter().find(|s| s.pc == next_pc);
            if holder.is_none() {
                if dbg {
                    eprintln!(
                        "[replay] DIED rung={:?} pre={} i={} pc={} instr={:?} want_next={} env_err={:?}",
                        reset_after_idx.map(|k| path[k].0),
                        pre_reset,
                        i,
                        pc,
                        instr,
                        next_pc,
                        env.error
                    );
                }
                break;
            }
            if !pre_reset
                && Some(i) == reset_after_idx
                && let (
                    Some(h),
                    Instr::If {
                        width,
                        left,
                        op,
                        right,
                        target,
                    },
                ) = (holder.as_mut(), &instr)
                && let Some((op_then, op_else)) = cmp_op_to_bcf_pair(*op)
            {
                h.reset_bcf_for_replay();
                let taken = next_pc == *target;
                let op_byte = if taken { op_then } else { op_else };
                let pre_b = crate::analysis::transfer::alu::helpers::bcf_reg_bounds(h, *left);
                record_path_cond_for_side(h, *width, *left, *op, op_byte, right, pc, None, pre_b);
            }
        }
        env.replay_mode = false;
        if let Some(mut final_state) = holder {
            if let Some(symb) = final_state.bcf.take() {
                let g = crate::refinement::refine_unreachable::build_unreachable_from_replay(*symb);
                if dbg {
                    eprintln!(
                        "[replay] END rung={:?} pre={} built={}",
                        reset_after_idx.map(|k| path[k].0),
                        pre_reset,
                        g.is_some()
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
                    reset_after_idx.map(|k| path[k].0),
                    pre_reset
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
/// predicate's operand exprs are coherent with the path conds — a shape
/// the live-state goal path cannot reproduce on loop-wrapping suffixes.
/// Plain replay only (no reset-rung ladder — the kernel's refine goal is
/// the plain base→reject walk); START-PUSH mirrored from
/// try_prove_unreachable_via_replay.
pub(crate) fn replay_to_reject(
    env: &mut VerifierEnv,
    base_cid: u32,
    // Anchor the EXECUTION one cache level earlier (the base's parent
    // cache entry) and reset the bcf at the base boundary. The kernel's
    // bcf_track replays from the pristine `st->parent` snapshot; alivio's
    // explored-cache entries are MUTATED at caching (mark_all_scalars_
    // imprecise + loop-header widening), so replaying with the cache
    // entry's regs materializes WIDENED operand bounds. Executing from
    // the parent anchor rebuilds
    // the regs (the suffix's own loads/ALUs), while the bcf reset keeps
    // the recorded conds starting at the base — the kernel goal shape.
    anchor_at_parent: bool,
    // Slot-share variant (ADDITIVE, kernel bcf_track bt slot-demand
    // materialization): first fill of an expr-less spilled scalar mints
    // the VAR into the SLOT so later fills of the same offset share it
    // (see SymbolicState::replay_share_slot_vars). false preserves the
    // pre-existing variants byte-for-byte.
    share_slot_vars: bool,
    // Reset-at-crossing variant (ADDITIVE, plain-anchor only): reset the
    // bcf at the k-th-FROM-LAST re-arrival at the anchor's pc within the
    // path (k = the value; 1 = last crossing) and re-record the boundary
    // branch — the kernel's base is a checkpoint on the CURRENT lineage
    // whose segment starts at that crossing, a state alivio may never have
    // cached (adds are cadence-gated). None = no crossing reset (all
    // existing variants byte-stable).
    reset_at_crossing: Option<usize>,
    // Override the pc whose crossings define the reset cut (default: the
    // anchor's own pc). Lets a DEEP rung's long path be cut at another
    // rung-pc's crossings — the kernel base can be a segment start at a
    // checkpoint pc EARLIER than any cache of that pc on the lineage.
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
        path.push((bc.pc, bc.instr));
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
    if std::env::var("ALIVIO_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1") {
        eprintln!(
            "[replay-refine] STRUCT base_cid={} base_hidx={:?} stopped_at_base={} path[0]={} path[last]={} len={}",
            base_cid,
            base_hidx,
            cur.is_some(),
            path[0].0,
            path[path.len() - 1].0,
            path.len()
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

    let dbg = std::env::var("ALIVIO_BCF_REPLAY_DEBUG").ok().as_deref() == Some("1");
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
    if !reset_suffix_from_base
        && !crossing_engaged
        && let Some((_, cached)) = env.state_by_cache_id(base_cid)
        && let Some(hidx) = cached.history_idx
        && let Some(bc) = env.history.get(hidx)
        && let Instr::If {
            width,
            left,
            op,
            right,
            target,
        } = bc.instr
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
            let pre_b = crate::analysis::transfer::alu::helpers::bcf_reg_bounds(&base_state, left);
            record_path_cond_for_side(
                &mut base_state,
                width,
                left,
                op,
                op_byte,
                &right,
                prev_pc,
                None,
                pre_b,
            );
        }
    }
    env.error = None;
    env.replay_mode = true;
    let mut holder: Option<State> = Some(base_state);
    for i in 0..n_exec {
        let pc = path[i].0;
        let instr = path[i].1;
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
                && let Instr::If {
                    width,
                    left,
                    op,
                    right,
                    target: _,
                } = &path[i - 1].1
                && let Some((op_then, op_else)) = cmp_op_to_bcf_pair(*op)
            {
                let prev_pc = path[i - 1].0;
                let taken = pc != prev_pc + 1;
                let op_byte = if taken { op_then } else { op_else };
                let pre_b = crate::analysis::transfer::alu::helpers::bcf_reg_bounds(&st, *left);
                record_path_cond_for_side(
                    &mut st, *width, *left, *op, op_byte, right, prev_pc, None, pre_b,
                );
            }
        }
        let succ = crate::analysis::transfer::transfer(env, st, &instr);
        let next_pc = path[i + 1].0;
        holder = succ.into_iter().find(|s| s.pc == next_pc);
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
