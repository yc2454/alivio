// src/analysis/flow/pruning/cache.rs
//
// State-cache hygiene: mutate cached states once their DFS subtree
// completes so later subsumption compares against a leaner comparand.
// Mirrors the kernel's clean_verifier_state / clean_live_states, and the
// BCF-discharge children-unsafe invalidation. Free functions over
// `&mut VerifierEnv`, matching the flow/ convention.

use std::collections::HashSet;
use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;

/// Kernel-aligned `clean_verifier_state` (verifier.c v6.15 L19482)
/// + `clean_func_state` (L19433). Called when a cached state's
/// `branches` first hits 0 in `complete_dfs_branch`: its DFS
/// subtree is complete, so future visits will only COMPARE
/// against it, never extend through it. At that point dead regs
/// and dead stack slots are mutated away so a later cur's
/// subsumption check against this state has fewer comparand
/// relations to satisfy.
///
/// Per frame `i`, the kernel cleans against `frame_insn_idx(i)`:
/// the innermost frame at the state's pc, caller frames at the
/// next-inner frame's `return_pc`. Regs not in
/// `live_regs_before[frame_ip]` are reset to `NotInit`; stack
/// slots not in `live_slots[frame_ip]` are dropped (kernel's
/// `STACK_INVALID` equivalent — zovia stores slots sparsely in a
/// `BTreeMap`, so removal == invalidation).
///
/// **Soundness:** zovia's existing subsumption already filters
/// dead regs/slots out of the comparison via the same
/// `live_regs` / `live_slots` sets (see `domain_subsumed_by`,
/// `stack_subsumed_by`); this mutation just bakes in the same
/// filter so the cached state object literally carries less
/// relation state. The hit/miss verdict for any cur is identical
/// to the pre-mutation case (live-only compare returns the same
/// boolean on a subset where the dead slots have been removed).
///
/// **Exempt:** ITER / DYNPTR / IRQ stack slots are NEVER cleaned
/// — they carry semantic side effects (ref counts, slot ownership)
/// independent of read-liveness. Kernel `bpf_stack_slot_alive`
/// has analogous exemptions.
///
/// Idempotent: skipped on already-cleaned states (kernel L19542
/// `sl->state.cleaned` guard).
/// DIAGNOSTIC (ZOVIA_CLEAN_STATS): [0]=cleaned [1]=skipped-incomplete.
pub fn clean_stat(which: usize) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    if !*ON.get_or_init(|| std::env::var("ZOVIA_CLEAN_STATS").is_ok()) {
        return;
    }
    static C: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
    let n = C[which].fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_multiple_of(500) || n == 1 {
        eprintln!(
            "[clean_stats] cleaned={} skipped_incomplete={}",
            C[0].load(Ordering::Relaxed),
            C[1].load(Ordering::Relaxed)
        );
    }
}

pub fn clean_verifier_state(env: &mut VerifierEnv, cid: u32) {
    let Some(&(pc, idx)) = env.cache_loc_by_id.get(&cid) else {
        return;
    };

    // Snapshot the frame ips + their live sets BEFORE taking the
    // mutable borrow on explored_states (insn_aux_data lookup
    // borrows env immutably).
    let (frame_ips, ls_key, st_pc): (Vec<usize>, Vec<usize>, usize) = {
        let Some(st) = env.explored_states.get(&pc).and_then(|v| v.get(idx)) else {
            return;
        };
        if st.cleaned {
            if crate::analysis::trace_pc_in_range(pc) {
                eprintln!("[CLEAN] pc={} cid={} already_cleaned", pc, cid);
            }
            return;
        }
        // Kernel `clean_live_states` gate: a state whose SCC has pending
        // backedges has incomplete read marks — don't clean it yet.
        if crate::analysis::flow::scc::incomplete_read_marks(env, st) {
            if crate::analysis::trace_pc_in_range(pc) {
                eprintln!("[CLEAN] pc={} cid={} SKIP incomplete_read_marks", pc, cid);
            }
            clean_stat(1);
            return;
        }
        clean_stat(0);
        let n = st.frames.depth();
        let ips = (0..n)
            .map(|i| {
                if i + 1 == n {
                    st.pc
                } else {
                    st.frames
                        .get(crate::analysis::machine::frame_stack::FrameLevel::from_index(i + 1))
                        .return_pc
                }
            })
            .collect();
        (ips, crate::analysis::flow::live_stack::callchain_of(st), st.pc)
    };
    // Registers stay on the STATIC live_regs (kernel `live_regs_before`,
    // compute_live_registers). Stack slots use the DYNAMIC live-stack
    // marks (kernel bpf_live_stack_query_init + bpf_stack_slot_alive).
    let frame_live: Vec<(HashSet<Reg>, u64)> = frame_ips
        .iter()
        .enumerate()
        .map(|(fi, &fip)| {
            let regs = env
                .insn_aux_data
                .get(fip)
                .map(|a| a.live_regs.clone())
                .unwrap_or_default();
            let alive = crate::analysis::flow::live_stack::frame_alive_mask(
                &env.live_stack,
                &ls_key,
                st_pc,
                fi,
            );
            if crate::analysis::trace_pc_in_range(st_pc) {
                eprintln!(
                    "[CLEAN] pc={} frame={} fip={} alive_mask={:#x}",
                    st_pc, fi, fip, alive
                );
                if std::env::var("ZOVIA_DBG_LIVE26").ok().as_deref() == Some("1") {
                    crate::analysis::flow::live_stack::dbg_dump_bit(
                        &env.live_stack, &ls_key, fi, 26,
                        &[1674, 2240, 2242, 2244, 2246, 2248, 2314, 2349, 2354],
                    );
                }
            }
            (regs, alive)
        })
        .collect();

    // Mutate. Full clean (kernel `clean_func_state` faithful):
    // both stack slots AND register state. Per-frame live_regs /
    // live_slots comes from static MAY-liveness (matches the
    // kernel's `live_regs_before`).
    //
    // ITER/DYNPTR/IRQ stack slots are NEVER cleaned — they carry
    // semantic side effects beyond read-liveness. Kernel
    // `bpf_stack_slot_alive` has analogous exemptions.
    use crate::analysis::machine::frame_stack::FrameLevel;
    use crate::analysis::machine::reg_types::RegType;
    let Some(st) = env
        .explored_states
        .get_mut(&pc)
        .and_then(|v| v.get_mut(idx))
    else {
        return;
    };
    let n_frames = st.frames.depth();
    for (i, (live_regs, alive_mask)) in frame_live.iter().enumerate() {
        let level = FrameLevel::from_index(i);
        let frame = st.frames.get_mut(level);
        // Slot clean: a byte is dead iff its 8-byte slot (spi) is not
        // alive per the dynamic live-stack query.
        let off_to_clean: Vec<i16> = frame
            .stack
            .slot_offsets()
            .into_iter()
            .filter(|&off| {
                crate::analysis::flow::live_stack::spi_of(off as i64)
                    .map(|spi| alive_mask & (1u64 << spi) == 0)
                    .unwrap_or(false)
            })
            .filter(|&off| {
                if let Some(slot) = frame.stack.get_slot(off) {
                    slot.iterator.is_none()
                        && slot.dynptr.is_none()
                        && slot.irq_flag.is_none()
                } else {
                    true
                }
            })
            .collect();
        for off in off_to_clean {
            frame.stack.remove_slot(off);
        }
        // Caller-frame reg snapshot clean (only for non-innermost
        // frames; innermost frame's regs live in top-level
        // st.types, handled below).
        if i + 1 < n_frames {
            for r in Reg::ALL {
                if r == Reg::R10 || r == Reg::Zero {
                    continue;
                }
                if !live_regs.contains(&r) {
                    frame.caller_types.set(r, RegType::NotInit);
                }
            }
        }
    }
    // Innermost frame: regs in st.types. Kernel `clean_func_state`
    // (verifier.c:19499) marks EVERY reg not in `live_regs_before`
    // NOT_INIT — unconditionally; there is no spilled-slot-anchor
    // exemption (slots carry their own self-contained value, and the
    // dynamic live-stack query above governs slot survival
    // independently). Keeping statically-dead regs alive in cached
    // states would make them stricter than the kernel's and block
    // subsumption HITs the kernel gets.
    let inner_live = frame_live
        .last()
        .map(|(r, _)| r.clone())
        .unwrap_or_default();
    for r in Reg::ALL {
        if r == Reg::R10 || r == Reg::Zero {
            continue;
        }
        if !inner_live.contains(&r) {
            st.types.set(r, RegType::NotInit);
            st.tnums.remove(&r);
            st.scalar_ids.remove(&r);
            st.precise_regs.remove(&r);
        }
    }
    // Audit dump (ZOVIA_DUMP_CLEAN=1): which regs got reset to
    // NotInit at this cached state's pc. Used to diagnose
    // tracking_for_u32_spill_fill-style FAs where the static
    // MAY-liveness incorrectly marks a reg dead.
    if std::env::var("ZOVIA_DUMP_CLEAN").ok().as_deref() == Some("1") {
        let cleaned_regs: Vec<usize> = (0..10)
            .filter(|i| !inner_live.iter().any(|r| {
                crate::analysis::machine::reg::reg_to_index(*r) == Some(*i)
            }))
            .collect();
        eprintln!(
            "[clean] pc={} cid={} cleaned_innermost_regs={:?} (live_regs={:?})",
            pc, cid, cleaned_regs, inner_live
        );
    }

    st.cleaned = true;
}

/// Mirror of kernel `bcf_refine`'s parent-marking
/// (verifier.c:24580-81: `for i in 0..vstate_cnt-1:
/// parents[i]->children_unsafe = true`). After a path-unreachable
/// refinement at `cur`'s reject site, walk `cur`'s
/// `parent_cache_id` lineage and mark every cached ancestor
/// `children_unsafe` so it can no longer prune a later arrival.
/// Without this, zovia subsumes the kernel's *second* route to
/// the same reject against the first route's cached ancestor and
/// never emits the second route's distinct path-unreachable
/// bundle entry. The chain (not all-states-at-pc) is
/// the faithful analog — only this path's ancestors, like the
/// kernel's `parents[]` vstate chain.
///
/// `base_pc` bounds the walk to the kernel's backtrack SUFFIX
/// (`bcf->parents[0..vstate_cnt-1]`, same suffix
/// `bcf_suffix_base_pc` feeds the path_cond filter): only
/// ancestors with `pc >= base_pc` are marked. The kernel does
/// NOT mark to program entry; full-lineage marking over-
/// suppresses pruning and explodes route enumeration. `None`
/// (kernel `backtrack_states` -EFAULT keep-all) means no lower
/// bound — mark the whole lineage (conservative).
/// Kernel `bcf_refine` marks `parents[0..vstate_cnt-1]` children_unsafe
/// (verifier.c:24684): the state chain `cur->parent .. st`, EXCLUDING
/// `base = st->parent`. zovia's `parent_cache_id` chain IS that checkpoint
/// chain, so this walks it from `cur.parent_cache_id` up to (but not
/// including) `base_cache_id` and marks each cached state. This is the
/// FAITHFUL bound — a bounded state chain, not a pc window — replacing the
/// EXCLUDE_BASE / DEEP_UNSAFE / bcidx pc-bound approximations (which either
/// under-marked, missing d53's pc521-covering states, or over-marked
/// "everything below pc146", causing the pc274 re-exploration blowup).
/// `base_cache_id == None` ⇒ backtrack didn't find a base (bt never emptied)
/// ⇒ kernel marks the whole chain to entry; we do the same.
pub fn mark_path_children_unsafe(
    env: &mut VerifierEnv,
    cur: &State,
    base_cache_id: Option<u32>,
) {
    let mut id = cur.parent_cache_id;
    let mut budget: usize = 16_384;
    let dump = std::env::var("ZOVIA_DUMP_DISCHARGE").ok().as_deref() == Some("1");
    let mut marked = 0usize;
    let mut first_pc: Option<usize> = None;
    let mut last_pc: Option<usize> = None;
    while let Some(cid) = id {
        if budget == 0 {
            break;
        }
        budget -= 1;
        // Stop AT the base (excluded) — kernel's `parents[0..vstate_cnt-1]`.
        if Some(cid) == base_cache_id {
            break;
        }
        // Live-then-retired: an evicted mid-chain ancestor must not
        // truncate the walk (kernel parents[] are pointers — free_list
        // membership is invisible to the marking loop). Marking a
        // retired state is a no-op for pruning (it's out of the
        // candidate lists) but the walk continues to live ancestors.
        let Some((pc, s)) = env.state_by_cache_id_mut(cid) else {
            break;
        };
        let parent = s.parent_cache_id;
        // Kernel marks unconditionally (idempotent); walk continues past
        // already-marked states to reach the base each time.
        if !s.children_unsafe {
            s.children_unsafe = true;
            marked += 1;
            if first_pc.is_none() {
                first_pc = Some(pc);
            }
            last_pc = Some(pc);
            if crate::analysis::trace_pc_in_range(pc) {
                eprintln!("[disc-mark] pc={} cid={}", pc, cid);
            }
        }
        id = parent;
    }
    if dump {
        eprintln!(
            "[disc] marked {} ancestors  pc=[{:?}..{:?}]  base_cid={:?}",
            marked, last_pc, first_pc, base_cache_id
        );
    }
}
