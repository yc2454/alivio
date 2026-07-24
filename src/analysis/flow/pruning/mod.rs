pub mod cache;
// src/analysis/flow/pruning/mod.rs
//
// Pruning orchestration: should_prune, handle_loop_pruning,
// handle_standard_pruning, and supporting bookkeeping.
// Loop detection + widening math live in widening.rs.
// Subsumption predicates live in subsumption.rs.

mod subsumption;
pub(crate) mod widening;

use std::collections::HashSet;

use crate::analysis::machine::env::{SubsumptionMissReason, VerifierEnv};
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::{Instr, Program};
use crate::common::config::VerifierConfig;
use subsumption::{iter_active_depths_differ, state_exact_equal, state_subsumed_by};
use widening::{
    arrived_via_back_edge, is_at_loop_point, is_prune_point, loop_body_has_force_checkpoint,
    loop_has_conditional_exit, this_loop_iter_pre_widening,
};

/// Mirrors the kernel's "skip_inf_loop_check" paths in `is_state_visited`
/// (verifier.c v6.15 L19073 / L19111): the inf-loop trap doesn't fire at
/// iter_next kfunc call sites (those are handled by `process_iter_next_call`
/// + iter_active_depths_differ) or at sync-callback-call helper sites
/// (bpf_loop / bpf_for_each_map_elem / bpf_timer_set_callback — the
/// callback's own iteration accounting drives convergence). zovia flags
/// both classes via `force_checkpoint=true` set at the `Call` insn. We
/// gate on the insn kind plus the flag so MayGoto pcs (also
/// force-checkpoint) still run the inf-loop check, matching the kernel's
/// fall-through at L19103-L19109.
/// ZOVIA_DUMP_SLOTS3: per-byte kinds + base-spill (type, prec, bounds) for
/// spi25/26/27 (bases -208/-216/-224) on cur and the compared candidate.
fn dump_slots3(pc: usize, verdict: &str, state: &State, prev: &State) {
    for base in [-208i16, -216, -224] {
        let kinds = |fr: &crate::analysis::machine::frame_stack::CallFrame| {
            (base..base + 8)
                .map(|b| match fr.stack.get_slot_kind(b) {
                    Some(k) => format!("{:?}", k).chars().next().unwrap(),
                    None => '-',
                })
                .collect::<String>()
        };
        let basereg = |fr: &crate::analysis::machine::frame_stack::CallFrame| {
            fr.stack
                .get_slot(base)
                .map(|s| format!("{:?}/p{}[{},{}]", s.reg_type, s.precise, s.bounds.min, s.bounds.max))
                .unwrap_or_else(|| "-".into())
        };
        eprintln!(
            "[slots3] pc={} {} base={} cur={} old={} cur_base={} old_base={}",
            pc,
            verdict,
            base,
            kinds(state.frames.current()),
            kinds(prev.frames.current()),
            basereg(state.frames.current()),
            basereg(prev.frames.current()),
        );
    }
}

fn is_inf_loop_skip_pc(prog: &Program, pc: usize) -> bool {
    matches!(prog.instrs.get(pc), Some(Instr::Call { .. }))
}

/// DIAGNOSTIC (ZOVIA_ZHIT): print every prune HIT with a global sequence
/// number, for diffing against the kernel's equivalent hit stream.
fn zhit_seq(pc: usize, state: &State, prev: &State) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    if !*ON.get_or_init(|| std::env::var("ZOVIA_ZHIT").is_ok()) {
        return;
    }

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    use crate::analysis::machine::reg::Reg;
    let r2t = state.types.get(Reg::R2);
    let r2i = state.domain.get_interval(Reg::R2);
    let mut diffs = String::new();
    for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5, Reg::R6, Reg::R7, Reg::R8, Reg::R9] {
        let ci = state.domain.get_interval(r);
        let pi = prev.domain.get_interval(r);
        if ci != pi || state.types.get(r) != prev.types.get(r) {
            diffs.push_str(&format!(
                " {:?}:cur={:?}[{}..{}]vs prev={:?}[{}..{}]p={}",
                r, state.types.get(r), ci.0, ci.1,
                prev.types.get(r), pi.0, pi.1,
                prev.precise_regs.contains(&r)
            ));
        }
    }
    eprintln!(
        "[zhit] seq={} pc={} curR2={:?}[{}..{}] DIFFS:{}",
        seq, pc, r2t, r2i.0, r2i.1, diffs
    );
}

/// DIAGNOSTIC (ZOVIA_DBG_SKIP_PC): tally children_unsafe prune-skips per pc;
/// dump the top offenders periodically.
fn dbg_skip_pc(pc: usize) {
    use std::sync::{Mutex, OnceLock};
    static ON: OnceLock<bool> = OnceLock::new();
    if !*ON.get_or_init(|| std::env::var("ZOVIA_DBG_SKIP_PC").is_ok()) {
        return;
    }
    static T: OnceLock<Mutex<(std::collections::HashMap<usize, u64>, u64)>> = OnceLock::new();
    let m = T.get_or_init(|| Mutex::new((std::collections::HashMap::new(), 0)));
    let mut g = m.lock().unwrap();
    *g.0.entry(pc).or_insert(0) += 1;
    g.1 += 1;
    if g.1 % 3_000 == 0 {
        let mut v: Vec<_> = g.0.iter().map(|(&p, &c)| (c, p)).collect();
        v.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        let top: Vec<String> = v.iter().take(8).map(|(c, p)| format!("pc{}={}", p, c)).collect();
        eprintln!("[skip_pc] total={} top: {}", g.1, top.join(" "));
    }
}

/// Handle pruning decision at a loop point.
/// Returns Some(true) to prune, Some(false) to continue, None if no previous states.
/// Walk cur's `parent_cache_id` lineage and collect the cache_ids of all
/// cached states cur descends from. A prev state whose cache_id is in this
/// set is a true loop-ANCESTOR of cur; one that is not (but is co-active) is
/// a SIBLING. Bounded by a budget to guard against a malformed cycle.
/// Kernel `same_callsites` (verifier.c:2107-2119): equal frame depth and
/// an identical callsite chain. Combined with the `insn_idx ^ callsite`
/// explored_state() bucketing (:2099-2105) this makes callee states cached
/// from different call sites mutually invisible in the pruning scan.
/// zovia keys explored_states by pc alone, so the scan applies this as an
/// explicit per-candidate filter (equivalent modulo the kernel's rare
/// hash-collision noise). return_pc is zovia's callsite analog (call insn
/// + 1, consistent on both sides of the comparison; main frame = 0).
fn same_callsites(a: &State, b: &State) -> bool {
    a.frames.depth() == b.frames.depth()
        && a.frames
            .iter()
            .zip(b.frames.iter())
            .all(|(x, y)| x.return_pc == y.return_pc)
}

fn collect_ancestor_ids(env: &VerifierEnv, state: &State) -> HashSet<u32> {
    let mut set = HashSet::new();
    let mut next = state.parent_cache_id;
    let mut budget = 16_384u32;
    while let Some(cid) = next {
        if budget == 0 || !set.insert(cid) {
            break;
        }
        budget -= 1;
        match env.state_by_cache_id(cid) {
            Some((_, st)) => next = st.parent_cache_id,
            None => break,
        }
    }
    set
}

fn handle_loop_pruning(
    env: &mut VerifierEnv,
    state: &mut State,
    pc: usize,
    prog: &Program,
    live_regs: &HashSet<Reg>,
    frame_live_slots: &[Option<HashSet<i16>>],
    frame_live_regs: &[Option<HashSet<Reg>>],
    config: &VerifierConfig,
) -> bool {
    // Loops without conditional exits are infinite - let complexity limit catch them
    if !loop_has_conditional_exit(env, state, pc, prog) {
        env.pruning_stats.loop_no_cond_exit += 1;
        return false;
    }
    env.pruning_stats.loop_walks_attempted += 1;

    // Kernel-faithful iter-loop convergence: in an iterator-style loop
    // (body contains a force-checkpoint), the kernel converges at the
    // iter_next pc itself via `process_iter_next_call` →
    // `widen_imprecise_scalars`. zovia's kfunc-site widening
    // (kfunc.rs::iter_next_fork) is the analog. BUT zovia's
    // `is_at_loop_point` makes EVERY back-edge target a pruning point —
    // a strict superset of kernel's `init_explored_state`'d pcs. If we
    // prune at a non-checkpoint back-edge target before the looped-back
    // state can re-reach the iter_next pc, the kfunc widening never
    // sees a second iter_next visit (`prev_found=false`) and the
    // delayed_precision_mark / loop_state_deps FAs slip through.
    //
    // Defer pruning at non-force-checkpoint pcs INSIDE iter bodies
    // ONLY while iter_next widening hasn't yet fired on at least one
    // active iter slot (depth<2: still on the very first iter_next
    // call). Once widening has fired (depth>=2 on every active iter),
    // resume normal pruning so legitimate iter loops still converge
    // (iter_while_loop / clean_live_states / widen_spill rely on
    // back-edge target subsumption AFTER the widened state stabilises).
    // Unconditional skip breaks those legitimate loops; conditional
    // skip only opens the gate long enough for widening to fire.
    let pc_is_force_checkpoint = env
        .insn_aux_data
        .get(pc)
        .map(|a| a.force_checkpoint)
        .unwrap_or(false);
    // Defer only at an actual back-edge TARGET (kernel-style:
    // `init_explored_state`'d loop head), not at every in-loop body
    // pc — otherwise the body's paths can't prune and the worklist
    // explodes.
    if !pc_is_force_checkpoint
        && arrived_via_back_edge(env, state, pc, prog)
        && loop_body_has_force_checkpoint(env, state, pc)
        && this_loop_iter_pre_widening(env, state, pc)
    {
        return false;
    }

    // Pure-subsumption loop pruning: walk prev_states, prune on first
    // hit (kernel `is_state_visited` analog at the loop head). The
    // kernel converges loops via imprecise-scalar-as-wildcard in
    // regsafe + iter-next widening (kfunc.rs::iter_next_fork); for
    // non-iter loops without a wildcard fixpoint, the complexity limit
    // terminates them — matching the kernel's actual behavior.
    // cur's ancestor cache_id lineage (walk of the parent_cache_id
    // chain), used to distinguish a true loop-ANCESTOR (cur descends
    // from prev) from a co-active SIBLING at the dfs_paths>0 prune-skip
    // below. Computed lazily — only when an active prev is actually
    // encountered — so converged loops (no active prev) pay nothing.
    let mut ancestor_ids: Option<HashSet<u32>> = None;
    // Kernel in-loop dampener input (see handle_standard_pruning).
    let mut saw_active_loop = false;

    let (hit_idx, miss_idxs, miss_reasons, counted_miss_idxs): (
        Option<usize>,
        Vec<usize>,
        Vec<SubsumptionMissReason>,
        Vec<usize>,
    ) = if let Some(prev_states) = env.explored_states.get(&pc) {
        let mut h = None;
        let mut m: Vec<usize> = Vec::new();
        let mut r: Vec<SubsumptionMissReason> = Vec::new();
        // Kernel scan shape: newest-first + per-sl miss counting under the
        // RUNNING add_new_state (see the long comment in
        // handle_standard_pruning).
        let mut add_now = would_add_new_state_base(env, state, pc);
        let mut cm: Vec<usize> = Vec::new();
        for (i, prev) in prev_states.iter().enumerate().rev() {
            // Kernel explored_state() buckets by `insn_idx ^ callsite`
            // (verifier.c:2099-2105) + same_callsites (:2107): a callee
            // state cached from a DIFFERENT call site lives in a different
            // hash bucket and is INVISIBLE to this arrival's scan — no
            // dampener, no miss counting, no eviction interplay.
            if !same_callsites(prev, state) {
                dbg_skip_pc(pc);
                continue;
            }
            // Kernel children_unsafe (bcf_refine, verifier.c:24580-81).
            if prev.children_unsafe {
                if add_now {
                    cm.push(i);
                }
                dbg_skip_pc(pc);
                continue;
            }
            // Kernel-faithful force_exact: the kernel gates RANGE_WITHIN
            // strictness on `incomplete_read_marks(old)` alone
            // (verifier.c v6.15 L20574: `loop = incomplete_read_marks();
            // states_equal(..., loop ? RANGE_WITHIN : NOT_EXACT)`).
            let force_exact = crate::analysis::flow::scc::incomplete_read_marks(env, prev);
            // Kernel blanket active-state gate (`if (sl->state.branches)
            // ... goto miss`, verifier.c v6.15 L19024): a cached state
            // whose subtree is still in flight never subsumes an arrival,
            // keeping the EXACT inf-loop trap as the only thing
            // terminating an unbounded loop. See the matching comment in
            // handle_standard_pruning.
            let skip_active = prev.branches > 0;
            if skip_active {
                saw_active_loop = true;
                // Kernel skip_inf_loop_check: flip the running
                // add_new_state (unless force/thresholds); the active sl
                // itself is never miss-counted (flip precedes its goto
                // miss).
                if dampener_would_suppress(env, state, pc) {
                    add_now = false;
                }
                // Kernel: the active sl's own `goto miss` IS counted when
                // the dampener didn't suppress — this is what accumulates
                // miss_cnt on active states and can evict them from the
                // bucket.
                if add_now {
                    cm.push(i);
                }
                if crate::analysis::trace_pc_in_range(pc) {
                    eprintln!(
                        "[SUBSUM_SKIP_ACTIVE] pc={} prev_idx={} prev.dfs_paths={} cache_id={:?}",
                        pc, i, prev.dfs_paths, prev.cache_id,
                    );
                }
                m.push(i);
                continue;
            }
            match state_subsumed_by(state, prev, live_regs, frame_live_slots, frame_live_regs, config, force_exact) {
                Ok(()) => {
                    zhit_seq(pc, state, prev);
                    if crate::analysis::trace_pc_in_range(pc) {
                        use crate::analysis::machine::reg::Reg;
                        let cu = state.domain.get_u64_bounds(Reg::R8);
                        let pu = prev.domain.get_u64_bounds(Reg::R8);
                        eprintln!(
                            "[SUBSUM_HIT] pc={} prev_idx={} prev.dfs_paths={} force_exact={} curR8=u[{:#x}..{:#x}]prec={} prevR8=u[{:#x}..{:#x}]prec={}",
                            pc, i, prev.dfs_paths, force_exact,
                            cu.0, cu.1, state.precise_regs.contains(&Reg::R8),
                            pu.0, pu.1, prev.precise_regs.contains(&Reg::R8),
                        );
                    }
                    h = Some(i);
                    break;
                }
                Err(reason) => {
                    if crate::analysis::trace_pc_in_range(pc) {
                        eprintln!(
                            "[SUBSUM_MISS] pc={} prev_idx={} reason={:?} prev.dfs_paths={} force_exact={}",
                            pc, i, reason, prev.dfs_paths, force_exact,
                        );
                    }
                    if add_now {
                        cm.push(i);
                    }
                    m.push(i);
                    r.push(reason);
                }
            }
        }
        (h, m, r, cm)
    } else {
        env.pruning_stats.loop_walks_no_prev += 1;
        return false;
    };
    env.saw_active_state_at_check |= saw_active_loop;

    if let Some(idx) = hit_idx {
        env.pruning_stats.loop_walks_hit += 1;
        record_pruning_hit(env, pc, idx);
        // Kernel-aligned propagate_precision (verifier.c v6.15 L18828):
        // pull cached's precise-mark set into cur's parent-cache lineage
        // so the path's continuation tracks the same precision contract.
        if let Some(prev) = env.explored_states.get(&pc).and_then(|v| v.get(idx)).cloned() {
            crate::analysis::flow::precision::propagate_precision(env, state, &prev);
            // SCC: at a force_exact hit, propagate prev's loop_entry to
            // cur (verifier.c L19178). cur is about to be pruned and
            // complete_dfs_branch will walk up; carrying the loop_entry
            // lets the propagation reach the parent chain. We also seed
            // from prev's cache_id when prev itself is the entry.
            if prev.branches > 0 {
                let le = prev
                    .cache_id
                    .and_then(|cid| crate::analysis::flow::scc::get_loop_entry(env, cid))
                    .or(prev.cache_id);
                if let Some(lcid) = le {
                    crate::analysis::flow::scc::update_loop_entry(env, state, lcid);
                }
            }
            // Kernel-faithful add_scc_backedge gate (verifier.c v6.15
            // L20671-20686): backedges are only added when `loop` was
            // already true at this hit — i.e. visit.backedges was
            // already non-empty. The strict gate keeps non-iter loops in
            // NOT_EXACT mode so they converge naturally; iter loops
            // converge via widen_imprecise_scalars at iter_next
            // (kfunc.rs::iter_next_fork — independent of backedges).
            if crate::analysis::flow::scc::incomplete_read_marks(env, &prev)
                && let Some(prev_cid) = prev.cache_id
            {
                crate::analysis::flow::scc::add_scc_backedge(env, state, prev_cid, pc);
            }
        }
        env.pruning_stats.loop_walks_pruned_via_convergence += 1;
        // Kernel `miss:` runs per candidate DURING the scan — pre-hit
        // counted misses keep their miss_cnt++/eviction (see the
        // matching block in handle_standard_pruning). After hit
        // bookkeeping — evictions shift indices.
        record_pruning_misses(env, pc, &counted_miss_idxs);
        return true;
    }

    env.pruning_stats.loop_walks_miss += 1;
    // Kernel miss-label semantics — per-sl counted misses only (see
    // handle_standard_pruning).
    record_pruning_misses(env, pc, &counted_miss_idxs);
    record_subsumption_miss_reasons(env, pc, &miss_reasons);

    false
}

/// Handle standard (non-loop) subsumption check.
fn handle_standard_pruning(
    env: &mut VerifierEnv,
    state: &State,
    pc: usize,
    live_regs: &HashSet<Reg>,
    frame_live_slots: &[Option<HashSet<i16>>],
    frame_live_regs: &[Option<HashSet<Reg>>],
    config: &VerifierConfig,
) -> bool {
    let mut hit_idx: Option<usize> = None;
    let mut miss_idxs: Vec<usize> = Vec::new();
    let mut miss_reasons: Vec<SubsumptionMissReason> = Vec::new();
    let mut local_children_unsafe_skips: u64 = 0;
    // Kernel in-loop dampener input: did this arrival encounter an
    // in-flight (branches>0) cached state at this pc? (env flag written
    // after the scan — the scan holds an immutable borrow of env.)
    let mut saw_active = false;
    // Kernel `is_state_visited` `is_iter_next_insn` branch (verifier.c v6.15
    // L19079): iterator convergence ALWAYS uses `states_equal(RANGE_WITHIN)`,
    // never the looser NOT_EXACT. RANGE_WITHIN range-checks even non-precise
    // scalars (the `!rold->precise && exact==NOT_EXACT` wildcard shortcut does
    // NOT fire), which is exactly what catches iters.c::delayed_precision_mark:
    // at the iter_next call r7 is reachable as -16 and -33 with no precision
    // mark; NOT_EXACT would wildcard r7 and merge the two, dropping the unsafe
    // `*(r10 + r7=-33)` deref. Forcing RANGE_WITHIN keeps them distinct so the
    // widened (unbounded) r7 reaches the access and is rejected. `iter_pc_slot`
    // is populated at every iter_next site by iter_next_fork.
    let iter_next_pc = env.iter_pc_slot.contains_key(&pc);
    let mut ancestor_ids: Option<HashSet<u32>> = None;
    // Kernel scan shape: the bucket is a list_add-PREPENDED list scanned
    // NEWEST-FIRST, and the `miss:` label counts a miss only while the
    // RUNNING add_new_state is still true (`if (!add_new_state)
    // continue;`), where the in-loop dampener flips it false at the
    // first active sl encountered.
    let mut add_now = would_add_new_state_base(env, state, pc);
    let mut counted_miss_idxs: Vec<usize> = Vec::new();
    // Trace-range probe: log every arrival at a traced pc with its
    // lineage (parent cid) and the running add decision.
    if crate::analysis::trace_pc_in_range(pc) {
        eprintln!(
            "[SUBSUM_ARRIVE] pc={} parent_cid={:?} add_now={} n_cands={}",
            pc,
            state.parent_cache_id,
            add_now,
            env.explored_states.get(&pc).map(|v| v.len()).unwrap_or(0)
        );
        // Bucket identity map: idx→cid so per-idx verdicts can be tied
        // to add-time snapshots.
        if std::env::var("ZOVIA_DUMP_BUCKET").ok().as_deref() == Some("1")
            && let Some(v) = env.explored_states.get(&pc)
        {
            let ids: Vec<String> = v
                .iter()
                .enumerate()
                .map(|(i, s)| format!("{}:{:?}", i, s.cache_id.unwrap_or(0)))
                .collect();
            eprintln!("[bucket] pc={} [{}]", pc, ids.join(" "));
        }
    }
    if let Some(prev_states) = env.explored_states.get(&pc) {
        for (i, prev) in prev_states.iter().enumerate().rev() {
            // Kernel `insn_idx ^ callsite` bucketing (verifier.c:2099) —
            // cross-callsite candidates are invisible; see the twin
            // filter in handle_loop_pruning's scan above.
            if !same_callsites(prev, state) {
                dbg_skip_pc(pc);
                continue;
            }
            // Kernel children_unsafe (bcf_refine, verifier.c:24580-81):
            // a path-unreachable refinement marked this cached ancestor
            // not-prune-safe. Don't let it subsume a later arrival.
            // Kernel: `goto miss` — counted toward eviction when
            // add_new_state still true.
            if prev.children_unsafe {
                local_children_unsafe_skips += 1;
                if add_now {
                    counted_miss_idxs.push(i);
                }
                if crate::analysis::trace_pc_in_range(pc) {
                    eprintln!(
                        "[SUBSUM_CHILDUNSAFE] pc={} prev_idx={} cache_id={:?}",
                        pc, i, prev.cache_id,
                    );
                }
                dbg_skip_pc(pc);
                continue;
            }
            // Kernel `is_state_visited`: a cached state with branches>0
            // NEVER subsumes a normal arrival (`if (sl->state.branches)
            // ... goto miss`, verifier.c v6.15 L19024) — at EVERY prune
            // point, not just loop heads, sibling or ancestor alike.
            if prev.branches > 0 {
                saw_active = true;
                // Kernel skip_inf_loop_check: flips the RUNNING
                // add_new_state false (unless force/thresholds) — sls
                // scanned AFTER this point stop counting misses; the
                // active sl itself is never counted (flip precedes its
                // `goto miss`).
                if dampener_would_suppress(env, state, pc) {
                    add_now = false;
                }
                // Kernel: the active sl's own miss IS counted when the
                // dampener didn't suppress — the eviction driver for
                // active cadence states (see loop handler).
                if add_now {
                    counted_miss_idxs.push(i);
                }
                if crate::analysis::trace_pc_in_range(pc) {
                    eprintln!(
                        "[SUBSUM_SKIP_ACTIVE] pc={} prev_idx={} prev.branches={} cache_id={:?} (standard)",
                        pc, i, prev.branches, prev.cache_id,
                    );
                }
                continue;
            }
            // Kernel-faithful force_exact (see matching block above).
            // At iter_next sites the kernel pins RANGE_WITHIN
            // regardless of read-mark completeness.
            let force_exact =
                iter_next_pc || crate::analysis::flow::scc::incomplete_read_marks(env, prev);
            match state_subsumed_by(state, prev, live_regs, frame_live_slots, frame_live_regs, config, force_exact) {
                Ok(()) => {
                    zhit_seq(pc, state, prev);
                    // ZOVIA_DBG_VNHIT: report HITs that prune a lineage
                    // whose history crossed the 498->515 value-null edge.
                    if std::env::var("ZOVIA_DBG_VNHIT").ok().as_deref() == Some("1")
                        && matches!(pc, 494 | 515 | 516)
                    {
                        let mut cur = state.history_idx;
                        let mut prev_pc: Option<usize> = None;
                        let mut vn = 0usize;
                        let mut steps = 0;
                        while let Some(idx) = cur {
                            if steps > 600 { break; }
                            if let Some(bc) = env.history.get(idx) {
                                if bc.pc == 498 && prev_pc == Some(515) { vn += 1; }
                                prev_pc = Some(bc.pc);
                                cur = bc.parent_idx;
                            } else { break; }
                            steps += 1;
                        }
                        if vn > 0 {
                            eprintln!("[vnhit] pc={} prev_idx={} prev.branches={} prev.cache_id={:?} prev.first_insn_idx={} prev.hidx={:?} cur.hidx={:?} cur_valnull={} prev_r6={:?} cur_r6={:?} prev_r7={:?} cur_r7={:?}",
                                pc, i, prev.branches, prev.cache_id, prev.first_insn_idx,
                                prev.history_idx, state.history_idx, vn,
                                prev.domain.get_interval(crate::analysis::machine::reg::Reg::R6),
                                state.domain.get_interval(crate::analysis::machine::reg::Reg::R6),
                                prev.domain.get_interval(crate::analysis::machine::reg::Reg::R7),
                                state.domain.get_interval(crate::analysis::machine::reg::Reg::R7));
                        }
                    }
                    if crate::analysis::trace_pc_in_range(pc) {
                        eprintln!(
                            "[SUBSUM_HIT] pc={} prev_idx={} cache_id={:?} (standard)",
                            pc, i, prev.cache_id,
                        );
                        if std::env::var("ZOVIA_DUMP_SLOTS3").ok().as_deref() == Some("1") {
                            dump_slots3(pc, "HIT", state, prev);
                        }
                        // ZOVIA_DUMP_HIT_DIMS: dump the compared live
                        // dims of cur vs the matched cache.
                        if std::env::var("ZOVIA_DUMP_HIT_DIMS").ok().as_deref() == Some("1") {
                            for &r in live_regs.iter() {
                                eprintln!(
                                    "[hit_dim] pc={} reg={:?} cur(t={:?} tn={:?} prec={}) old(t={:?} tn={:?} prec={})",
                                    pc, r,
                                    state.types.get(r), state.get_tnum(r),
                                    state.precise_regs.contains(&r),
                                    prev.types.get(r), prev.get_tnum(r),
                                    prev.precise_regs.contains(&r),
                                );
                            }
                            for off in [-64i16, -60, -57, -56, -232, -216, -296, -248] {
                                let cs = state.frames.current().stack.get_slot(off);
                                let ps = prev.frames.current().stack.get_slot(off);
                                eprintln!(
                                    "[hit_dim] pc={} slot={} cur={:?} old={:?}",
                                    pc, off,
                                    cs.map(|s| (s.bounds.min, s.bounds.max, s.precise)),
                                    ps.map(|s| (s.bounds.min, s.bounds.max, s.precise)),
                                );
                            }
                            let kinds = |fr: &crate::analysis::machine::frame_stack::CallFrame| {
                                (-64i16..-56).map(|b| fr.stack.get_slot_kind(b)).collect::<Vec<_>>()
                            };
                            eprintln!(
                                "[hit_dim] pc={} fp64_kinds cur={:?} old={:?} cur_ty={:?} old_ty={:?}",
                                pc,
                                kinds(state.frames.current()),
                                kinds(prev.frames.current()),
                                state.frames.current().stack.get_slot(-64).map(|s| s.reg_type.clone()),
                                prev.frames.current().stack.get_slot(-64).map(|s| s.reg_type.clone()),
                            );
                        }
                    }
                    hit_idx = Some(i);
                    break;
                }
                Err(reason) => {
                    if crate::analysis::trace_pc_in_range(pc) {
                        eprintln!(
                            "[SUBSUM_MISS] pc={} prev_idx={} reason={:?} prev.dfs_paths={} force_exact={} (non-loop site)",
                            pc, i, reason, prev.dfs_paths, force_exact,
                        );
                        // ZOVIA_DUMP_SLOTS3: per-byte kinds + base spill
                        // (type,prec,bounds) for spi25/26/27 on BOTH cur
                        // and the candidate.
                        if std::env::var("ZOVIA_DUMP_SLOTS3").ok().as_deref() == Some("1") {
                            dump_slots3(pc, "MISS", state, prev);
                        }
                        // ZOVIA_DUMP_MISS_DIMS: same dims as [hit_dim]
                        // but on the miss path, cur vs the missed cache.
                        // Env-gated, trace-range-gated.
                        if std::env::var("ZOVIA_DUMP_MISS_DIMS").ok().as_deref() == Some("1") {
                            use crate::analysis::machine::reg::Reg;
                            for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4,
                                      Reg::R5, Reg::R6, Reg::R7, Reg::R8, Reg::R9] {
                                let (clo, chi) = state.domain.get_interval(r);
                                let (plo, phi) = prev.domain.get_interval(r);
                                eprintln!(
                                    "[miss_dim] pc={} idx={} reg={:?} cur(t={:?} ivl=[{},{}] tn={:?} prec={}) old(t={:?} ivl=[{},{}] tn={:?} prec={})",
                                    pc, i, r,
                                    state.types.get(r), clo, chi, state.get_tnum(r),
                                    state.precise_regs.contains(&r),
                                    prev.types.get(r), plo, phi, prev.get_tnum(r),
                                    prev.precise_regs.contains(&r),
                                );
                            }
                        }
                    }
                    if add_now {
                        counted_miss_idxs.push(i);
                    }
                    miss_idxs.push(i);
                    miss_reasons.push(reason);
                }
            }
        }
    }
    env.pruning_stats.children_unsafe_skips =
        env.pruning_stats.children_unsafe_skips.saturating_add(local_children_unsafe_skips);
    env.saw_active_state_at_check |= saw_active;
    if let Some(idx) = hit_idx {
        record_pruning_hit(env, pc, idx);
        // Kernel-aligned propagate_precision (per-path lineage walk).
        if let Some(prev) = env.explored_states.get(&pc).and_then(|v| v.get(idx)).cloned() {
            crate::analysis::flow::precision::propagate_precision(env, state, &prev);
        }
        // Kernel miss-label semantics run PER CANDIDATE DURING the scan
        // (verifier.c `miss:` inside list_for_each): candidates that
        // missed/skipped BEFORE the eventual hit keep their miss_cnt++
        // and can be evicted on this same arrival. Do the hit
        // bookkeeping first (idx is invalidated by evictions below).
        record_pruning_misses(env, pc, &counted_miss_idxs);
        true
    } else {
        // Kernel miss-label semantics: only the misses counted while the
        // RUNNING add_new_state was true feed miss_cnt/eviction (the
        // per-sl `counted_miss_idxs` collected in scan order above).
        record_pruning_misses(env, pc, &counted_miss_idxs);
        record_subsumption_miss_reasons(env, pc, &miss_reasons);
        false
    }
}

/// Base of the kernel's `add_new_state` before the scan (is_state_visited
/// L20228-31): force (insn_aux || jmp_history>40) or the env-wide 2/8
/// heuristic. The in-loop dampener then flips it false DURING the scan
/// (see dampener_would_suppress). Keep in sync with run_worklist A.c.
fn would_add_new_state_base(env: &VerifierEnv, state: &State, pc: usize) -> bool {
    // ZOVIA_DBG_FORCE_ADD=1 — DIAGNOSIS ONLY: checkpoint at EVERY
    // prune-point visit (a superset of the kernel's add set) while
    // keeping subsumption-hit pruning intact. NOT a fix — forced adds
    // change exploration; never default this on.
    if std::env::var("ZOVIA_DBG_FORCE_ADD").ok().as_deref() == Some("1") {
        return true;
    }
    // Range-scoped variant (ZOVIA_DBG_FORCE_ADD_RANGE=LO:HI): forced adds
    // ONLY inside the window — surgical base-placement tests without the
    // global state blowup.
    if force_add_in_range(pc) {
        return true;
    }
    let force_new_state = env
        .insn_aux_data
        .get(pc)
        .map(|a| a.force_checkpoint)
        .unwrap_or(false)
        || state.jmp_history_cnt > 40;
    let dj = env.jmps_processed.saturating_sub(env.prev_jmps_processed);
    let di = env.insn_processed.saturating_sub(env.prev_insn_processed);
    force_new_state || (dj >= 2 && di >= 8)
}

/// ZOVIA_DBG_FORCE_ADD_RANGE=LO:HI (diagnosis-only).
fn force_add_in_range(pc: usize) -> bool {
    std::env::var("ZOVIA_DBG_FORCE_ADD_RANGE")
        .ok()
        .and_then(|s| {
            let (lo, hi) = s.split_once(':')?;
            Some((lo.parse::<usize>().ok()?, hi.parse::<usize>().ok()?))
        })
        .is_some_and(|(lo, hi)| pc >= lo && pc <= hi)
}

/// Kernel skip_inf_loop_check condition (verifier.c ~20320): on
/// encountering an active (branches>0) cached state, suppress the add
/// unless force or the loop thresholds are reached.
fn dampener_would_suppress(env: &VerifierEnv, state: &State, pc: usize) -> bool {
    // See would_add_new_state_base: the ceiling diagnostic must also
    // bypass the in-loop dampener or it re-suppresses the forced adds.
    if std::env::var("ZOVIA_DBG_FORCE_ADD").ok().as_deref() == Some("1")
        || force_add_in_range(pc)
    {
        return false;
    }
    let force_new_state = env
        .insn_aux_data
        .get(pc)
        .map(|a| a.force_checkpoint)
        .unwrap_or(false)
        || state.jmp_history_cnt > 40;
    let dj = env.jmps_processed.saturating_sub(env.prev_jmps_processed);
    let di = env.insn_processed.saturating_sub(env.prev_insn_processed);
    !force_new_state && dj < 20 && di < 100
}

/// Bump the per-PC subsumption-miss histogram. One increment per
/// rejected sub-check, attributed to the *first* sub-check that
/// rejected (later checks short-circuit). Cheap; safe to call on every
/// miss path. The end-of-analysis dump reads this histogram.
fn record_subsumption_miss_reasons(
    env: &mut VerifierEnv,
    pc: usize,
    reasons: &[SubsumptionMissReason],
) {
    if reasons.is_empty() {
        return;
    }
    env.pruning_stats.lifetime_misses += reasons.len() as u64;
    let entry = env
        .subsumption_misses
        .entry(pc)
        .or_insert([0u64; 9]);
    for r in reasons {
        entry[r.idx()] = entry[r.idx()].saturating_add(1);
    }
}

/// Check if we should prune this state (already covered by a previous exploration).
/// For loop heads with conditional exits, applies widening to accelerate convergence.
pub fn should_prune(
    env: &mut VerifierEnv,
    state: &mut State,
    config: &VerifierConfig,
    prog: &Program,
) -> bool {
    let pc = state.pc;

    env.pruning_stats.should_prune_calls += 1;
    // Kernel in-loop dampener input — reset per is_state_visited analog;
    // the scan handlers set it when an in-flight (branches>0) cached
    // state is encountered at this pc.
    env.saw_active_state_at_check = false;

    if crate::analysis::trace_pc_in_range(pc) {
        let nprev = env.explored_states.get(&pc).map(|v| v.len()).unwrap_or(0);
        eprintln!(
            "[SP_ENTRY] pc={} nprev={} is_prune_point={}",
            pc, nprev, is_prune_point(env, pc)
        );
    }

    if !is_prune_point(env, pc) {
        env.pruning_stats.not_prune_point += 1;
        return false;
    }

    // [ARR] per-arrival trace probe.
    if crate::analysis::trace_pc_in_range(pc) {
        use crate::analysis::machine::reg::Reg;
        let r6 = state.get_tnum(Reg::R6);
        let r8 = state.types.get(Reg::R8);
        eprintln!("[ARR] pc={} r6tn={:?} r8={:?}", pc, r6, r8);
    }

    // Kernel `clean_live_states(env, insn_idx)` — called at the top of
    // every `is_state_visited`: LAZILY clean any cached state at this pc
    // whose subtree completed (branches==0) but which was skipped
    // earlier (e.g. its SCC still had pending backedges at eager-clean
    // time). Without the retry, states inside a long-running loop SCC
    // are never cleaned and every later compare runs against the fat
    // state.
    {
        let to_clean: Vec<u32> = env
            .explored_states
            .get(&pc)
            .map(|v| {
                v.iter()
                    .filter(|s| !s.cleaned && s.branches == 0)
                    // Kernel clean_live_states gate (verifier.c:19535):
                    // pending SCC backedges = incomplete read marks —
                    // don't clean yet; the retry fires again after
                    // propagate_backedges settles the marks.
                    .filter(|s| !crate::analysis::flow::scc::incomplete_read_marks(env, s))
                    .filter_map(|s| s.cache_id)
                    .collect()
            })
            .unwrap_or_default();
        for cid in to_clean {
            crate::analysis::flow::pruning::cache::clean_verifier_state(env, cid);
        }
    }

    let is_on_path = state
        .history_idx
        .map(|idx| env.history.is_on_path(idx, pc))
        .unwrap_or(false);

    let in_loop = is_at_loop_point(env, state, pc, prog);

    // iter_next call sites are virtual loop heads: the kernel's
    // is_state_visited runs the RANGE_WITHIN + active-iter check at
    // the iter_next CALL pc (verifier.c v6.15 L19078-L19101), and the
    // cached state at this pc is the convergence target for the loop.
    // Mirror that by NOT shortcut-skipping on `is_on_path && !in_loop`
    // when this pc is a force-checkpointed Call (force_checkpoint at
    // a Call instruction = iter_next or sync-callback helper site).
    // Without this, under ZOVIA_KERNEL_ENGINE=1's sparse caching the
    // iter loop's back-edge target (a body pc) isn't cached, the
    // iter_next call site IS cached but pruning short-circuits via
    // on_path → bpf_iter_num loops never converge → timeout.
    // Generalized to ALL force-checkpoint pcs (iter_next/sync-cb Call sites
    // AND may_goto insns): the kernel's is_state_visited runs at EVERY
    // checkpoint and converges may_goto loops AT the may_goto pc itself
    // (verifier.c L19102, RANGE_WITHIN + depth-differ) — not at the loop's
    // back-edge target. A may_goto pc is a force-checkpoint but NOT a
    // back-edge target, so `in_loop` is false there; without exempting it
    // from the on-path skip, may_goto_range_within_prune never runs and the
    // loop only converges via the (non-kernel) active-ancestor hit.
    let pc_is_force_checkpoint = env
        .insn_aux_data
        .get(pc)
        .map(|a| a.force_checkpoint)
        .unwrap_or(false)
        && matches!(
            prog.instrs.get(pc),
            Some(Instr::Call { .. }) | Some(Instr::MayGoto { .. })
        );

    // DIAG: when this pc is traced and prev cached states already
    // exist, log the early-decision inputs.
    if crate::analysis::trace_pc_in_range(pc) {
        let nprev = env.explored_states.get(&pc).map(|v| v.len()).unwrap_or(0);
        if nprev > 0 {
            eprintln!(
                "[SP_GATE] pc={} nprev={} is_on_path={} in_loop={} force_ckpt={} prune_point={} -> would_skip_onpath={}",
                pc, nprev, is_on_path, in_loop, pc_is_force_checkpoint,
                is_prune_point(env, pc),
                is_on_path && !in_loop && !pc_is_force_checkpoint,
            );
        }
    }

    // The kernel's is_state_visited has NO on-path shortcut — on-path
    // arrivals are exactly what its branches>0 block +
    // skip_inf_loop_check dampener handle, and the blanket branches>0
    // gate makes the scan safe here (active states skip-miss, never
    // wrongly subsume). Keep the stat for observability.
    if is_on_path && !in_loop && !pc_is_force_checkpoint {
        env.pruning_stats.on_path_skip += 1;
    }

    // Track whether we actually have prev states to compare against.
    // Distinguishes "first visit (no work for cache to do)" from "had
    // prev states; either hit or miss happened downstream".
    if env
        .explored_states
        .get(&pc)
        .map(|v| v.is_empty())
        .unwrap_or(true)
    {
        env.pruning_stats.no_prev_states += 1;
    } else if in_loop {
        env.pruning_stats.loop_pruning_calls += 1;
    } else {
        env.pruning_stats.std_pruning_calls += 1;
    }

    let live_regs = env.insn_aux_data[pc].live_regs.clone();
    if crate::analysis::trace_pc_in_range(pc)
        && std::env::var("ZOVIA_DUMP_LIVE_REGS").ok().as_deref() == Some("1")
    {
        let mut v: Vec<String> = live_regs.iter().map(|r| format!("{:?}", r)).collect();
        v.sort();
        eprintln!("[live_regs] pc={} {:?}", pc, v);
    }
    // Kernel `stacksafe` has NO in-compare liveness skip: dead slots are
    // removed from CACHED states by `clean_verifier_state` (driven by
    // the dynamic live-stack marks, see flow::live_stack); an uncleaned
    // state (branches>0 / pending SCC backedges) is compared in FULL.
    // So every frame passes `None` = no slot skip.
    let nframes = state.frames.depth();
    let frame_live_slots: Vec<Option<HashSet<i16>>> = vec![None; nframes];
    // Kernel per-frame reg-live mask for the caller-frame compare
    // (states_equal: frame_insn_idx(i) = the frame's CALLSITE insn;
    // func_states_equal masks by insn_aux_data[..].live_regs_before —
    // verifier.c:20069-20085/:20131-20137). frames[k].caller_types was
    // saved at frames[k]'s callsite = return_pc - 1; return_pc == 0 =
    // the main frame (no callsite) -> None (legacy r6-r9 fallback).
    let frame_live_regs: Vec<Option<HashSet<Reg>>> = state
        .frames
        .iter()
        .map(|f| {
            if f.return_pc == 0 {
                None
            } else {
                env.insn_aux_data
                    .get(f.return_pc - 1)
                    .map(|a| a.live_regs.clone())
            }
        })
        .collect();

    // Kernel-faithful infinite-loop trap (verifier.c v6.15 L19114-L19127,
    // `is_state_visited`'s inf-loop check). For any cached state at this
    // pc whose topmost-frame regs are bytewise identical to cur AND whose
    // full state matches EXACT AND iter active depths don't differ AND
    // may_goto_depth matches ⇒ "infinite loop detected".
    //
    // Skipped at iter_next call sites and sync-callback-call helper sites
    // (kernel `is_iter_next_insn` / `calls_callback` short-circuits at
    // L19073 / L19111). MayGoto is NOT skipped: the may_goto_depth
    // equality gate inside the check naturally lets it through (the
    // taken edge bumps the depth, so a recurrence with same depth means
    // no progress on the may_goto counter ⇒ stuck).
    // Only run the inf-loop trap at actual back-edge TARGETS (loop heads).
    // The kernel's is_state_visited fires at every prune point, but
    // zovia's per-state liveness/precision bookkeeping isn't granular
    // enough to mirror the kernel's `live`-flag discrimination — so at
    // mid-loop convergence prune points (`is_at_loop_point=false`) the
    // check over-fires on legitimate cilium loops whose iterations
    // happen to produce byte-identical zovia abstract states even
    // though the kernel sees per-iter progress. Restricting to true
    // loop heads keeps the trap narrow enough to detect genuine
    // verifier-divergent infinite loops (the conditional_loop /
    // infinite_loop_* / mov64sx_s32_varoff_1 family) while avoiding
    // the cilium FR-regression.
    // Additionally skip when ANY frame has an active iterator: the kernel
    // gates iter-loop convergence on `iter_active_depths_differ` + SCC
    // (`loop_entry` / `dfs_depth` / `branches`, verifier.c L1885+). zovia
    // tracks depth-differ but not SCC, so at body pcs inside an iter
    // loop where the depth has stabilized (legit pruning iteration), the
    // EXACT check fires on byte-identical body states that the kernel
    // distinguishes via SCC's per-state `branches` count. Skipping at
    // any-active-iter avoids the false-reject regression on
    // verifier_bits_iter.c::max_words and the like; iter_next sites
    // themselves are already covered by `is_inf_loop_skip_pc` for the
    // kernel's `is_iter_next_insn` short-circuit.
    let any_active_iter = state
        .frames
        .iter()
        .any(|f| f.stack.has_active_iterators());
    if in_loop
        && !any_active_iter
        && pc < prog.instrs.len()
        && let Some(prev_states) = env.explored_states.get(&pc).cloned()
        && !is_inf_loop_skip_pc(prog, pc)
    {
        for prev in prev_states.iter() {
            // Kernel-faithful gate (verifier.c v6.15 L19024): the entire
            // inf-loop check is wrapped in `if (sl->state.branches)`. A
            // cached state with branches==0 (kernel semantics) has had
            // its entire downstream DFS completed — a second arrival
            // that byte-matches it is the normal subsumption case, NOT
            // a stuck loop. Without this gate zovia false-rejects
            // programs like pro_epilogue_goto_start where the first
            // back-edge arrival at the loop head takes a terminating
            // branch (e.g. r1=0 → if r1==0 → exit) and fully completes
            // before a second back-edge arrival via a different
            // predecessor path lands at the same state.
            //
            // Zovia checks `dfs_paths` instead of `branches` because
            // zovia's `branches` field has different (per-push)
            // accounting than the kernel's `branches`; changing it to
            // kernel semantics broke ~125 selftests (iters.c family
            // etc.). `dfs_paths` is the parallel kernel-faithful
            // counter dedicated to this gate. See State::dfs_paths.
            if prev.dfs_paths == 0 {
                continue;
            }
            // Kernel `states_maybe_looping` (verifier.c v6.15 L20137):
            // memcmp(regs, ..., offsetof(struct bpf_reg_state, frameno))
            // compares EVERY field including `reg.parent` (the upward
            // pointer to the predecessor state's matching reg, used by
            // precision back-propagation). Two iters reaching the same
            // PC with identical *values* but distinct DFS parent chains
            // have different `reg.parent` pointers → memcmp non-zero →
            // states_maybe_looping=false → kernel SKIPS the inf-loop
            // check and falls through to the regular subsumption-prune
            // path (where states_equal with RANGE_WITHIN/EXACT acts as
            // a HIT, not a reject).
            //
            // Zovia's `state_exact_equal` only compares VALUES (types,
            // intervals, tnums, scalar_ids) — no parent-pointer
            // equivalent — so it false-positives on sibling-DFS-branch
            // value convergence. To approximate the kernel's
            // discrimination, require prev's cache_id to appear in
            // cur's parent_cache_id lineage: only then is this a TRUE
            // single-path cycle. Convergent siblings get the prune
            // path below (state_exact_equal => subsumption hit).
            //
            // Concretely on calico anchor new_flow_entrypoint (post
            // jmp_history_cnt fix, 2026-05-22): R7 differs at loop
            // head PC 2844 across iterations (R7 increments) but is
            // overwritten to a constant in the loop body, so two iters
            // reach the loop tail PC 3059 with byte-identical reg
            // values. Without the lineage gate the trap fires; with
            // it, sibling-iter convergence falls through to the regular
            // prune path and exploration terminates correctly.
            let prev_cid = prev.cache_id;
            let in_lineage = prev_cid.is_some() && {
                let mut cur_anc = state.parent_cache_id;
                let mut steps = 0usize;
                let mut found = false;
                while let Some(cid) = cur_anc {
                    if Some(cid) == prev_cid {
                        found = true;
                        break;
                    }
                    if steps > 4096 {
                        break;
                    }
                    steps += 1;
                    cur_anc = env
                        .state_by_cache_id(cid)
                        .and_then(|(_, s)| s.parent_cache_id);
                }
                found
            };
            if !in_lineage {
                continue;
            }
            if prev.may_goto_depth != state.may_goto_depth {
                continue;
            }
            if iter_active_depths_differ(prev, state) {
                continue;
            }
            if state_exact_equal(prev, state) {
                // ZOVIA_TRAP_DEBUG=1 — dump prev vs cur side-by-side when the
                // inf-loop trap fires, so we can see which fields kernel
                // treats as distinct that zovia treats as identical.
                if std::env::var("ZOVIA_TRAP_DEBUG").ok().as_deref() == Some("1") {
                    use crate::analysis::machine::reg::Reg;
                    eprintln!("[TRAP] === inf-loop fire at pc={} ===", pc);
                    eprintln!("[TRAP] prev.dfs_paths={} cur.dfs_paths={}", prev.dfs_paths, state.dfs_paths);
                    eprintln!("[TRAP] prev.may_goto_depth={} cur.may_goto_depth={}", prev.may_goto_depth, state.may_goto_depth);
                    eprintln!("[TRAP] depth prev={} cur={}", prev.frames.depth(), state.frames.depth());
                    // Walk full history, count visits to PC, and find any non-linear jumps
                    let mut hist_pcs: Vec<usize> = Vec::new();
                    let mut idx = state.history_idx;
                    let mut visits_to_trap_pc = 0;
                    while let Some(i) = idx {
                        match env.history.get(i) {
                            Some(step) => {
                                if step.pc == pc { visits_to_trap_pc += 1; }
                                hist_pcs.push(step.pc);
                                idx = step.parent_idx;
                                if hist_pcs.len() > 5000 { break; }
                            }
                            None => break,
                        }
                    }
                    eprintln!("[TRAP] cur history len={}  visits_to_pc{}={}", hist_pcs.len(), pc, visits_to_trap_pc);
                    eprintln!("[TRAP] last 15 PCs (most-recent first): {:?}", &hist_pcs[..hist_pcs.len().min(15)]);
                    // find non-linear transitions: prev PC where next != prev+1
                    let mut jumps: Vec<(usize, usize)> = Vec::new();
                    for w in hist_pcs.windows(2) {
                        let (newer, older) = (w[0], w[1]);
                        if newer != older + 1 && newer != older + 2 { // skip LD_IMM64 stride
                            jumps.push((older, newer));
                            if jumps.len() > 20 { break; }
                        }
                    }
                    eprintln!("[TRAP] non-linear jumps in history (older->newer): {:?}", jumps);
                    eprintln!("[TRAP] cur parent_cache_id={:?} prev.cache_id={:?}", state.parent_cache_id, prev.cache_id);
                    for r in Reg::ALL {
                        let pty = prev.types.get(r);
                        let cty = state.types.get(r);
                        let (plo, phi) = prev.domain.get_interval(r);
                        let (clo, chi) = state.domain.get_interval(r);
                        let psid = prev.scalar_ids.get(&r).copied().unwrap_or(0);
                        let csid = state.scalar_ids.get(&r).copied().unwrap_or(0);
                        let same_ty = pty == cty;
                        let same_iv = (plo, phi) == (clo, chi);
                        let same_u32 = prev.domain.get_u32_bounds(r) == state.domain.get_u32_bounds(r);
                        let same_tn = prev.tnums.get(&r) == state.tnums.get(&r);
                        let same_sid = psid == csid;
                        eprintln!(
                            "[TRAP] {:?}: ty={} iv={} u32={} tn={} sid={} | prev_ty={:?} iv=[{}..{}] sid={} | cur_ty={:?} iv=[{}..{}] sid={}",
                            r, if same_ty {"="} else {"≠"}, if same_iv {"="} else {"≠"},
                            if same_u32 {"="} else {"≠"}, if same_tn {"="} else {"≠"},
                            if same_sid {"="} else {"≠"},
                            pty, plo, phi, psid, cty, clo, chi, csid,
                        );
                    }
                    // Top-frame stack slot diffs
                    use crate::analysis::machine::frame_stack::FrameLevel;
                    let top = FrameLevel::from_index(prev.frames.depth().saturating_sub(1));
                    let pf = prev.frames.get(top);
                    let cf = state.frames.get(top);
                    // explicit: dump the fp-0x128 (-296) slot specifically
                    let pslot = pf.stack.get_slot(-296);
                    let cslot = cf.stack.get_slot(-296);
                    eprintln!("[TRAP] fp-296 (= fp-0x128): prev={:?}", pslot);
                    eprintln!("[TRAP] fp-296 (= fp-0x128): cur ={:?}", cslot);
                    let mut all_offs: std::collections::BTreeSet<i16> = pf.stack.slot_offsets().into_iter().collect();
                    all_offs.extend(cf.stack.slot_offsets());
                    for off in all_offs {
                        let ps = pf.stack.get_slot(off);
                        let cs = cf.stack.get_slot(off);
                        let same = match (ps, cs) {
                            (Some(a), Some(b)) => a == b,
                            (None, None) => true,
                            _ => false,
                        };
                        if !same {
                            eprintln!("[TRAP] fp{}: DIFF prev={:?} cur={:?}", off, ps, cs);
                        }
                    }
                    eprintln!("[TRAP] === end ===");
                }
                env.fail(crate::analysis::machine::error::VerificationError::InfiniteLoopDetected {
                    pc,
                });
                return true;
            }
        }
    }

    // Under BPF_F_TEST_STATE_FREQ, bypass all subsumption-hit pruning
    // (may_goto RANGE_WITHIN, loop pruning, standard pruning). The
    // inf-loop trap above already ran. Kernel verifier.c L18998 sets
    // `force_new_state=true` under this flag — every visit gets cached
    // as a fresh entry and explored to completion. This is the
    // load-bearing mechanism for iters.c::loop_state_deps1/2: their
    // unsafe paths are reached only when each iteration's r6/r7 state
    // is tracked distinctly rather than collapsed by subsumption.
    if env.ctx.has_flag(crate::common::constants::F_TEST_STATE_FREQ) {
        return false;
    }

    // may_goto-specific RANGE_WITHIN prune class.
    if pc < prog.instrs.len()
        && matches!(prog.instrs[pc], Instr::If { .. } | Instr::MayGoto { .. })
        && let Some(prev_states) = env.explored_states.get(&pc)
    {
        let is_may_goto = matches!(prog.instrs[pc], Instr::MayGoto { .. });
        if is_may_goto
            && may_goto_range_within_prune(state, prev_states, &live_regs, &frame_live_slots, &frame_live_regs, config)
        {
            env.pruning_stats.may_goto_range_within_hits += 1;
            return true;
        }
    }

    let pruned = if in_loop {
        handle_loop_pruning(env, state, pc, prog, &live_regs, &frame_live_slots, &frame_live_regs, config)
    } else {
        handle_standard_pruning(env, state, pc, &live_regs, &frame_live_slots, &frame_live_regs, config)
    };
    pruned
}

/// bump miss_cnt for every `prev_idx` and evict whose
/// `miss_cnt > hit_cnt * n + n` (kernel verifier.c v6.15 L19222-L19233).
/// `n = 64` at force-checkpoint pcs (iter_next, may_goto, sync-cb-call
/// helpers); `n = 3` elsewhere. Caller passes the indices of every
/// cached state that was walked-past during a failed subsumption check;
/// hit cases use `record_pruning_hit` instead.
fn record_pruning_misses(env: &mut VerifierEnv, pc: usize, miss_idxs: &[usize]) {
    if miss_idxs.is_empty() {
        return;
    }
    let force = env
        .insn_aux_data
        .get(pc)
        .map(|a| a.force_checkpoint)
        .unwrap_or(false);

    // Read `branches` per cached state for the kernel-faithful `n`
    // formula (verifier.c v6.18-rc4 L20444):
    //   n = is_force_checkpoint && sl->state.branches > 0 ? 64 : 3
    // `branches > 0` means the cached state's downstream DFS is still in
    // progress (it's part of an active SCC iteration); the kernel
    // protects these from premature eviction at force-checkpoint pcs.
    let branches_by_idx: std::collections::HashMap<usize, u32> = if let Some(states) =
        env.explored_states.get(&pc)
    {
        miss_idxs
            .iter()
            .filter_map(|&i| states.get(i).map(|s| (i, s.branches)))
            .collect()
    } else {
        std::collections::HashMap::new()
    };

    // [ev] event log (1770 eviction-divergence link, 2026-07-16): candidate
    // identity = cid + R1 smin (the 0x205/0x405/... flag-ladder consts) —
    // diff against kernel probe #134 [ZK ev].
    let id_by_idx: std::collections::HashMap<usize, (Option<u32>, i64)> =
        if crate::analysis::trace_pc_in_range(pc) {
            env.explored_states
                .get(&pc)
                .map(|states| {
                    miss_idxs
                        .iter()
                        .filter_map(|&i| {
                            states.get(i).map(|s| {
                                use crate::analysis::machine::reg::Reg;
                                (i, (s.cache_id, s.domain.get_interval(Reg::R1).0))
                            })
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Default::default()
        };
    let mut to_evict: Vec<usize> = Vec::new();
    if let Some(metrics) = env.state_metrics.get_mut(&pc) {
        for &i in miss_idxs {
            if let Some(m) = metrics.get_mut(i) {
                m.miss_cnt = m.miss_cnt.saturating_add(1);
                // Kernel L20444 exactly: n = force_checkpoint && branches>0 ? 64 : 3
                let branches = branches_by_idx.get(&i).copied().unwrap_or(0);
                let n: u32 = if force && branches > 0 { 64 } else { 3 };
                if crate::analysis::trace_pc_in_range(pc) {
                    let (cid, r1) = id_by_idx.get(&i).copied().unwrap_or((None, i64::MIN));
                    eprintln!(
                        "[ev] pc={} MISS cid={:?} r1={} cnt={}/{}",
                        pc, cid, r1, m.miss_cnt, m.hit_cnt
                    );
                }
                if m.miss_cnt > m.hit_cnt.saturating_mul(n).saturating_add(n) {
                    if crate::analysis::trace_pc_in_range(pc) {
                        let (cid, r1) = id_by_idx.get(&i).copied().unwrap_or((None, i64::MIN));
                        eprintln!(
                            "[ev] pc={} EVICT cid={:?} r1={} cnt={}/{} n={}",
                            pc, cid, r1, m.miss_cnt, m.hit_cnt, n
                        );
                    }
                    to_evict.push(i);
                }
            }
        }
    }
    if to_evict.is_empty() {
        return;
    }
    // Sort descending so removals don't shift later indices.
    to_evict.sort_unstable_by(|a, b| b.cmp(a));
    // Kernel is_state_visited L20455-64: eviction moves the state to
    // env->free_list (it stays resolvable through descendants'
    // st->parent until branches == 0), it is NOT destroyed. Retire the
    // evicted State objects so parent-chain walks (branches accounting,
    // bcf backtrack base, children_unsafe marking, replay base fetch)
    // keep working — destroying them here was the from_l3_fib_no_log
    // pc222 0x94363000 miss (base state evicted → bcf_suffix_base_pc
    // None → base-less goal).
    let mut evicted: Vec<State> = Vec::new();
    if let Some(states) = env.explored_states.get_mut(&pc) {
        for &i in &to_evict {
            if i < states.len() {
                evicted.push(states.remove(i));
            }
        }
    }
    if let Some(metrics) = env.state_metrics.get_mut(&pc) {
        for &i in &to_evict {
            if i < metrics.len() {
                metrics.remove(i);
            }
        }
    }
    // cache_loc_by_id cleanup: drop evicted ids (they resolve through
    // retired_states from now on), re-index survivors. Same invariant
    // as the FIFO drain in `merging::record_state`.
    for s in evicted {
        if let Some(id) = s.cache_id {
            env.cache_loc_by_id.remove(&id);
            env.retire_state(id, pc, s);
        }
    }
    if let Some(states) = env.explored_states.get(&pc) {
        for (new_idx, s) in states.iter().enumerate() {
            if let Some(id) = s.cache_id {
                env.cache_loc_by_id.insert(id, (pc, new_idx));
            }
        }
    }
}

/// bump hit_cnt for the cached state at `prev_idx`.
fn record_pruning_hit(env: &mut VerifierEnv, pc: usize, prev_idx: usize) {
    env.pruning_stats.lifetime_hits += 1;
    let id = if crate::analysis::trace_pc_in_range(pc) {
        env.explored_states.get(&pc).and_then(|v| v.get(prev_idx)).map(|s| {
            use crate::analysis::machine::reg::Reg;
            (s.cache_id, s.domain.get_interval(Reg::R1).0)
        })
    } else {
        None
    };
    if let Some(metrics) = env.state_metrics.get_mut(&pc)
        && let Some(m) = metrics.get_mut(prev_idx)
    {
        m.hit_cnt = m.hit_cnt.saturating_add(1);
        if let Some((cid, r1)) = id {
            eprintln!(
                "[ev] pc={} HIT cid={:?} r1={} cnt={}/{}",
                pc, cid, r1, m.miss_cnt, m.hit_cnt
            );
        }
    }
}

/// RANGE_WITHIN prune class for may_goto pcs.
///
/// Tries to subsume `cur` against any prev state where the
/// `may_goto_depth` differs (mandatory: same depth would hit the EXACT
/// inf-loop trap instead). Subsumption is run with `cur`'s precision
/// marks cleared — the kernel's RANGE_WITHIN equivalent — so a
/// loop-counter that's been precision-marked at a body memory access
/// can still converge once its abstract value lies inside the cached
/// range.
fn may_goto_range_within_prune(
    cur: &State,
    prev_states: &[State],
    live_regs: &HashSet<Reg>,
    frame_live_slots: &[Option<HashSet<i16>>],
    frame_live_regs: &[Option<HashSet<Reg>>],
    config: &VerifierConfig,
) -> bool {
    // Build a precision-stripped clone of `cur` once. State carries
    // precision in two places: `precise_regs` (per-reg) and
    // `SpilledReg::precise` (per stack slot).
    let mut relaxed = cur.clone();
    relaxed.precise_regs.clear();
    use crate::analysis::machine::frame_stack::FrameLevel;
    for fi in 0..relaxed.frames.depth() {
        let level = FrameLevel::from_index(fi);
        let stack = &mut relaxed.frames.get_mut(level).stack;
        for off in stack.slot_offsets() {
            if let Some(slot) = stack.get_slot_mut(off) {
                slot.precise = false;
            }
        }
    }

    for prev in prev_states {
        if prev.may_goto_depth == cur.may_goto_depth {
            continue;
        }
        // Misses on this auxiliary RANGE_WITHIN prune class are
        // intentionally NOT recorded in the subsumption-miss histogram —
        // they would inflate the "stack" / "tnum" buckets with the
        // precision-stripped clone's behaviour, which isn't the same
        // as the standard subsumption pipeline we're trying to measure.
        // may_goto RANGE_WITHIN prune class explicitly relaxes precision;
        // pass force_exact=false so domain_subsumed_by keeps its NOT_EXACT
        // semantics for non-precise regs (the relaxed clone has cleared
        // precise_regs anyway).
        if state_subsumed_by(&relaxed, prev, live_regs, frame_live_slots, frame_live_regs, config, false).is_ok() {
            return true;
        }
    }
    false
}
