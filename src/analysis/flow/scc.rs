// src/analysis/flow/scc.rs
//
// Strongly-connected components on the lowered CFG. Iterative Tarjan
// adapted from kernel `compute_scc` (verifier.c v6.15 L25809-L25979).
//
// SCC ids start at 1 and are written into `env.insn_aux_data[pc].scc_id`.
// Per kernel convention, a singleton SCC WITHOUT a self-edge keeps
// `scc_id = 0` ("not in any SCC") — only multi-vertex components and
// singletons-with-self-edge get a real id. This is what
// `compute_scc_callchain` relies on to decide "is this insn in an SCC?".
//
// This is a behavior-neutral pre-pass — it just annotates aux data. The
// real consumers (`maybe_enter_scc`, `add_scc_backedge`,
// `propagate_backedges`, `incomplete_read_marks`) read `scc_id` at
// runtime to drive SCC-scoped precision propagation.

use crate::analysis::machine::env::VerifierEnv;
use crate::ast::{Instr, Operand, Program};

/// Sentinel returned by `low[t]` when a vertex has been popped out of
/// the SCC stack already. Larger than any real preorder number, so
/// `min(low[w], low[s])` is a no-op when `s` is no longer on stack.
const NOT_ON_STACK: u32 = u32::MAX;

/// Compute SCCs over the program's CFG and write `scc_id` into each
/// instruction's `insn_aux_data` entry. Idempotent in the sense that
/// repeated calls reproduce the same numbering for the same input
/// program (modulo deterministic successor order).
pub fn compute_scc(prog: &Program, env: &mut VerifierEnv) {
    let n = prog.instrs.len();
    if n == 0 {
        return;
    }

    // Tarjan bookkeeping. preorder/low indexed by pc.
    let mut pre: Vec<u32> = vec![0; n];
    let mut low: Vec<u32> = vec![0; n];
    // SCC-membership stack (vertices in DFS order; popped together when
    // a root is detected).
    let mut stack: Vec<usize> = Vec::with_capacity(n);
    // DFS work stack — emulates explicit recursion so we don't blow up
    // the host stack on long programs.
    let mut dfs: Vec<usize> = Vec::with_capacity(n);
    // Per-DFS-frame: which successor index do we resume at? Mirrors the
    // kernel's `succ` traversal — when we recurse into a successor we
    // need to come back and continue with the next sibling.
    let mut succ_iter: Vec<usize> = vec![0; n];

    let mut next_preorder: u32 = 1;
    let mut next_scc_id: u32 = 1;

    for root in 0..n {
        if pre[root] != 0 {
            continue;
        }
        dfs.push(root);

        'outer: while let Some(&w) = dfs.last() {
            if pre[w] == 0 {
                pre[w] = next_preorder;
                low[w] = next_preorder;
                next_preorder += 1;
                stack.push(w);
                succ_iter[w] = 0;
            }

            let succs = successors(prog, w);
            // Resume successor iteration from where we left off.
            while succ_iter[w] < succs.len() {
                let s = succs[succ_iter[w]];
                succ_iter[w] += 1;
                if s >= n {
                    continue;
                }
                if pre[s] == 0 {
                    // Recurse — push and restart.
                    dfs.push(s);
                    continue 'outer;
                }
                // Either still on stack (low[s] < NOT_ON_STACK) or
                // already popped (low[s] == NOT_ON_STACK). The
                // simplified Pearce-style `min(low[w], low[s])` is a
                // no-op in the popped case.
                if low[s] < low[w] {
                    low[w] = low[s];
                }
            }

            // All successors visited. Check whether `w` is the root of
            // a completed SCC.
            if low[w] < pre[w] {
                // Not a root — leave on the SCC stack and pop the DFS
                // frame. Standard Tarjan back-propagation: the parent's
                // lowlink absorbs the child's, since this child's
                // subtree is now fully explored and any back-edges it
                // reached are part of the parent's component too. The
                // iterative form has to do this explicitly here — the
                // `continue 'outer` recursion path never returned the
                // value to the caller, so without this step low values
                // never flow up the DFS chain. Effect: most non-trivial
                // SCCs (any loop reached by a single fall-through
                // chain) were being misclassified as singletons because
                // their interior vertices had `low == pre` after the
                // child popped without propagating.
                let child_low = low[w];
                dfs.pop();
                if let Some(&parent) = dfs.last()
                    && child_low < low[parent]
                {
                    low[parent] = child_low;
                }
                continue;
            }

            // `w` is an SCC root. Decide whether to assign a real id:
            // multi-vertex component, or singleton with a self-edge.
            let mut assign = stack.last().copied() != Some(w);
            if !assign {
                for &s in &succs {
                    if s == w {
                        assign = true;
                        break;
                    }
                }
            }

            // Pop component elements; assign id if applicable.
            loop {
                let t = stack.pop().expect("scc stack underflow");
                low[t] = NOT_ON_STACK;
                if assign && t < env.insn_aux_data.len() {
                    env.insn_aux_data[t].scc_id = next_scc_id;
                }
                if t == w {
                    break;
                }
            }
            if assign {
                next_scc_id += 1;
            }
            dfs.pop();
        }
    }
}

/// Pure successor function for the SCC pre-pass. Parallel to
/// `cfg::visit_insn` but free of side effects on `env`. Returns
/// in-bounds pcs only — out-of-bounds successors are silently skipped
/// (cfg::check_cfg flags those as errors before we run).
fn successors(prog: &Program, pc: usize) -> Vec<usize> {
    let n = prog.instrs.len();
    if pc >= n {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(2);
    match &prog.instrs[pc] {
        Instr::Exit => {}
        Instr::Jmp { target } => {
            out.push(*target);
        }
        Instr::If { target, .. } => {
            if pc + 1 < n {
                out.push(pc + 1);
            }
            out.push(*target);
        }
        Instr::MayGoto { target } => {
            if pc + 1 < n {
                out.push(pc + 1);
            }
            out.push(*target);
        }
        Instr::Call { .. } => {
            // Helper / kfunc calls don't transfer control to another
            // pc in this program's CFG (callbacks are entered via
            // PSEUDO_FUNC pointers, which the CFG check tracks
            // separately — the SCC analysis treats the call as a
            // single-edge fall-through, same as the kernel's
            // `bpf_insn_successors` for helper calls).
            if pc + 1 < n {
                out.push(pc + 1);
            }
        }
        Instr::CallRel { target } => {
            // BPF-to-BPF call: edge into the callee's entry. SCC
            // membership is per-program-counter; we include the callee
            // edge so a recursive subprog (if ever legal) would form
            // an SCC.
            out.push(*target);
            if pc + 1 < n {
                out.push(pc + 1);
            }
        }
        // All non-branch instructions: single fall-through.
        _ => {
            if pc + 1 < n {
                out.push(pc + 1);
            }
        }
    }
    out
}

// Silence "unused" if `Operand` is never reached in match patterns
// above — keep the import name in scope for future expansions.
#[allow(dead_code)]
fn _operand_anchor(_: &Operand) {}

// ════════════════════════════════════════════════════════════════════
//  SCC visit lifecycle — mirror of kernel bpf_scc_callchain /
//  bpf_scc_visit / bpf_scc_backedge (include/linux/bpf_verifier.h
//  L703-L725, verifier.c L2142-L2351).
// ════════════════════════════════════════════════════════════════════

use crate::analysis::machine::frame_stack::FrameLevel;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use std::collections::HashMap;

/// Mirror of kernel `bpf_scc_callchain`: a tuple of (outer-frame
/// callsites, SCC id of the innermost SCC-bearing frame). Two states
/// with the same callchain belong to the same SCC visit instance.
///
/// `callsites[i]` is the call-instruction pc of frame i (frames are
/// numbered from outermost = 0 to innermost = curframe). For the
/// frame whose pc is in an SCC, no callsite is recorded — we stop
/// there and record `scc_id` instead. If no frame's pc is in an SCC,
/// `compute_scc_callchain` returns `None` (the state is not in any SCC).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SccCallchain {
    pub callsites: Vec<usize>,
    pub scc_id: u32,
}

/// Mirror of kernel `bpf_scc_backedge`: a cur-state snapshot saved at
/// the moment of a RANGE_WITHIN convergence hit, plus the cache_id of
/// the cached state that subsumed it (`equal_state` in kernel terms).
/// Stored on the SCC visit's backedges list; consumed by
/// `propagate_backedges` at SCC exit to bring precision marks to
/// fixpoint along the convergence cycle.
#[derive(Clone, Debug)]
pub struct SccBackedge {
    pub state: State,
    pub equal_state_cache_id: u32,
    #[allow(dead_code)]
    pub insn_idx: usize,
}

/// Mirror of kernel `bpf_scc_visit`. One per (callchain) seen during a
/// verification run. `entry_state_cache_id` is the cache_id of the
/// FIRST state on the current verification path that entered this
/// SCC's visit instance — when that state's DFS subtree completes
/// (`branches → 0` in `complete_dfs_branch`), the visit exits and
/// `propagate_backedges` fires.
#[derive(Clone, Debug, Default)]
pub struct SccVisit {
    pub entry_state_cache_id: Option<u32>,
    pub backedges: Vec<SccBackedge>,
}

/// Compute the SCC callchain for a state. Returns `None` if no frame's
/// pc is in any SCC.
///
/// Walks frames outermost-to-innermost. For each frame i:
///   * Frame ip = innermost frame uses `state.pc`; caller frames use
///     the next-inner frame's `return_pc - 1` (the call insn pc).
///   * If `insn_aux_data[ip].scc_id != 0`, this is the SCC-bearing
///     frame; record its scc_id and stop.
///   * Otherwise, if it's not the innermost frame, record the
///     callsite and continue outward.
///   * If we reach the innermost frame without finding any SCC,
///     return None (state not in any SCC).
pub fn compute_scc_callchain(
    state: &State,
    insn_aux_data: &[crate::analysis::machine::env::InsnAuxData],
) -> Option<SccCallchain> {
    let n = state.frames.depth();
    let mut callsites: Vec<usize> = Vec::with_capacity(n.saturating_sub(1));
    for i in 0..n {
        let insn_idx = if i + 1 == n {
            state.pc
        } else {
            // Callsite of frame i = the call insn that pushed frame
            // i+1. zovia stores `return_pc` (= callsite + 1) on the
            // next-inner frame; recover the callsite by subtracting 1.
            let next = state.frames.get(FrameLevel::from_index(i + 1));
            next.return_pc.saturating_sub(1)
        };
        let scc_id = insn_aux_data
            .get(insn_idx)
            .map(|a| a.scc_id)
            .unwrap_or(0);
        if scc_id != 0 {
            return Some(SccCallchain {
                callsites,
                scc_id,
            });
        } else if i + 1 < n {
            callsites.push(insn_idx);
        } else {
            return None;
        }
    }
    None
}

/// Map keyed by `SccCallchain`, storing per-visit state. Lives on
/// `VerifierEnv.scc_visits`. Allocated lazily on first
/// `maybe_enter_scc` for a callchain.
pub type SccVisitMap = HashMap<SccCallchain, SccVisit>;

// ───────────────────────────────────────────────────────────────────
// SCC-visit / loop-entry runtime bookkeeping (moved from machine/env.rs).
// Free functions over `&mut VerifierEnv`, matching this module's
// compute_scc / compute_scc_callchain convention.
// ───────────────────────────────────────────────────────────────────
/// Mirror of kernel `maybe_enter_scc` (verifier.c v6.15 L2228).
/// Called on every cache event (right after `record_state` mints
/// a new cache_id). If the new state's frame chain leads into an
/// SCC, ensure a `SccVisit` entry exists for its callchain; if
/// the visit is fresh (no entry_state recorded yet), assign
/// `entry_state_cache_id = cid` so we know which cached state to
/// pair with `maybe_exit_scc` when its DFS subtree drains.
pub fn maybe_enter_scc(env: &mut VerifierEnv, state: &State, cid: u32) {
    let Some(callchain) =
        crate::analysis::flow::scc::compute_scc_callchain(state, &env.insn_aux_data)
    else {
        return;
    };
    let visit = env.scc_visits.entry(callchain).or_default();
    if visit.entry_state_cache_id.is_none() {
        visit.entry_state_cache_id = Some(cid);
    }
}

/// Mirror of kernel `maybe_exit_scc` (verifier.c v6.15 L2253).
/// Called from `complete_dfs_branch` when a cached state's
/// `branches` first hits 0. If that state was the SCC visit's
/// `entry_state`, the visit is now done — flush backedges via
/// `propagate_backedges` (landed in step 3) and clear
/// `entry_state_cache_id` so a later re-entry creates a fresh
/// visit.
///
pub fn maybe_exit_scc(env: &mut VerifierEnv, cid: u32) {
    // Identify the callchain belonging to `cid`'s cached state
    // (live-then-retired: the kernel calls maybe_exit_scc on any state
    // whose branches hit 0, including free_list ones).
    // Snapshot the State so we can compute the callchain without
    // holding a long mutable borrow.
    let state_snapshot = match env.state_by_cache_id(cid) {
        Some((_, s)) => s.clone(),
        None => return,
    };
    let Some(callchain) =
        crate::analysis::flow::scc::compute_scc_callchain(&state_snapshot, &env.insn_aux_data)
    else {
        return;
    };
    // Check entry + take backedges out without holding a long borrow.
    let backedges = {
        let Some(visit) = env.scc_visits.get_mut(&callchain) else {
            return;
        };
        if visit.entry_state_cache_id != Some(cid) {
            return;
        }
        visit.entry_state_cache_id = None;
        std::mem::take(&mut visit.backedges)
    };
    // Kernel `propagate_backedges` (verifier.c v6.15 L20079):
    // iterate the backedges list, calling propagate_precision on
    // each until fixpoint or MAX_BACKEDGE_ITERS. Each iteration
    // propagates precision marks from equal_state into the
    // backedge state's lineage. Kernel caps at 64; beyond that
    // it falls back to mark_all_scalars_precise on every
    // backedge (conservative).
    const MAX_BACKEDGE_ITERS: usize = 64;
    if backedges.is_empty() {
        return;
    }
    for _ in 0..MAX_BACKEDGE_ITERS {
        let mut changed = false;
        for be in &backedges {
            // Look up equal_state by cache_id (live-then-retired).
            let Some(equal_state) = env
                .state_by_cache_id(be.equal_state_cache_id)
                .map(|(_, s)| s.clone())
            else {
                continue;
            };
            // propagate_precision(cur=be.state, old=equal_state)
            // — pull equal_state's precise_regs into be.state's
            // ancestor lineage (parent_cache_id chain). The
            // method already exists for the same purpose in
            // standard subsumption hits; here we run it
            // post-hoc per backedge.
            let precise: Vec<Reg> = equal_state.precise_regs.iter().copied().collect();
            if precise.is_empty() {
                continue;
            }
            if let Some(hidx) = be.state.history_idx {
                let before = env.precise_pcs.len();
                for r in precise {
                    crate::analysis::flow::precision::mark_chain_precision_backward(env, hidx, be.state.parent_cache_id, r);
                }
                if env.precise_pcs.len() != before {
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}

/// Mirror of kernel `incomplete_read_marks` (verifier.c v6.15
/// L2327). Returns true iff the cached state's SCC visit has any
/// pending backedges (i.e., the SCC hasn't yet been processed by
/// `propagate_backedges`). Used in step 4 to gate
/// RANGE_WITHIN vs NOT_EXACT subsumption strictness — replaces
/// zovia's current `prev.branches > 0` approximation.
pub fn incomplete_read_marks(env: &VerifierEnv, state: &State) -> bool {
    let Some(callchain) =
        crate::analysis::flow::scc::compute_scc_callchain(state, &env.insn_aux_data)
    else {
        return false;
    };
    env.scc_visits
        .get(&callchain)
        .map(|v| !v.backedges.is_empty())
        .unwrap_or(false)
}

/// Add a backedge to the SCC visit owning `equal_state_cache_id`'s
/// callchain. Called from handle_loop_pruning at the hit point
/// when the cached state belongs to an open SCC visit. Mirror of
/// kernel `add_scc_backedge` (verifier.c v6.15 L2295).
pub fn add_scc_backedge(
    env: &mut VerifierEnv,
    cur: &State,
    equal_state_cache_id: u32,
    insn_idx: usize,
) {
    // The kernel keys add_scc_backedge on `sl->state` (the cached
    // state we hit against) — same callchain as cur because both
    // are in the same SCC visit instance.
    let Some((_, equal_state)) = env.state_by_cache_id(equal_state_cache_id) else {
        return;
    };
    let Some(callchain) =
        crate::analysis::flow::scc::compute_scc_callchain(equal_state, &env.insn_aux_data)
    else {
        return;
    };
    let Some(visit) = env.scc_visits.get_mut(&callchain) else {
        return;
    };
    // Don't accumulate if the visit is closed (no entry_state).
    if visit.entry_state_cache_id.is_none() {
        return;
    }
    visit.backedges.push(crate::analysis::flow::scc::SccBackedge {
        state: cur.clone(),
        equal_state_cache_id,
        insn_idx,
    });
}

/// Read a cached state's (branches, dfs_depth, loop_entry_cache_id)
/// without holding a borrow on env.explored_states. Returns None if
/// the cache_id has been evicted.
fn cached_scc_info(env: &VerifierEnv, cid: u32) -> Option<(u32, u32, Option<u32>)> {
    let (_, st) = env.state_by_cache_id(cid)?;
    Some((st.branches, st.dfs_depth, st.loop_entry_cache_id))
}

/// Mirror of kernel `get_loop_entry` (verifier.c v6.15 L1919). Walks
/// the loop_entry chain to the OUTERMOST loop entry. Returns the
/// final cache_id (or `None` if `start` has no loop_entry).
pub fn get_loop_entry(env: &VerifierEnv, start_cache_id: u32) -> Option<u32> {
    let (_, _, mut le) = cached_scc_info(env, start_cache_id)?;
    let mut steps: u32 = 0;
    while let Some(cid) = le {
        // Defensive bound: walks deeper than max plausible DFS depth
        // indicate a cycle in the loop_entry chain (a bug).
        steps += 1;
        if steps > 4096 {
            break;
        }
        match cached_scc_info(env, cid) {
            Some((_, _, Some(next))) => le = Some(next),
            _ => return Some(cid),
        }
    }
    // Edge: start had loop_entry=Some(cid) but that cid had no entry
    // → outermost was `cid`.
    cached_scc_info(env, start_cache_id)
        .and_then(|(_, _, le)| le)
}

/// Mirror of kernel `update_loop_entry` (verifier.c v6.15 L1934).
/// If `hdr_cache_id`'s branches > 0 (hdr's DFS is still open / hdr is
/// on the current DFS path) AND hdr's dfs_depth is less than
/// `cur`'s effective loop_entry depth, set cur.loop_entry = hdr.
/// `cur` here is a worklist state (not yet cached), so we mutate it
/// directly.
pub fn update_loop_entry(env: &VerifierEnv, cur: &mut State, hdr_cache_id: u32) {
    let Some((hdr_br, hdr_depth, _)) = cached_scc_info(env, hdr_cache_id) else {
        return;
    };
    if hdr_br == 0 {
        return;
    }
    // Effective depth: cur.loop_entry's depth if set, else cur's own.
    let cur_eff_depth = match cur.loop_entry_cache_id {
        Some(le_cid) => cached_scc_info(env, le_cid)
            .map(|(_, d, _)| d)
            .unwrap_or(cur.dfs_depth),
        None => cur.dfs_depth,
    };
    if hdr_depth < cur_eff_depth {
        cur.loop_entry_cache_id = Some(hdr_cache_id);
    }
}

/// Decrement-and-walk on `parent_cache_id` lineage: mirrors kernel
/// `update_branch_counts` (verifier.c L1955). Called when a worklist
/// state's DFS exploration terminates (pruned/exit/reject/forked).
/// `start_cache_id` is the parent_cache_id of the completing state.
/// At each cached parent:
/// - branches -= 1
/// - if branches becomes 0 AND this state has a loop_entry, propagate
///   it to the grandparent via update_loop_entry
/// - if branches > 0, stop (other DFS paths through parent still open)
/// - else continue walking up
pub fn complete_dfs_branch(env: &mut VerifierEnv, start_cache_id: Option<u32>) {
    let mut next = start_cache_id;
    let mut budget: u32 = 16_384;
    while let Some(cid) = next {
        if budget == 0 {
            break;
        }
        budget -= 1;
        // Resolve live-then-retired: kernel update_branch_counts walks
        // st->parent pointers, which include free_list (evicted) states.
        let Some((_, st)) = env.state_by_cache_id_mut(cid) else {
            break;
        };
        if st.branches > 0 {
            st.branches -= 1;
        }
        if crate::analysis::trace_pc_in_range(st.pc) {
            eprintln!("[BR] dec pc={} cid={} now={}", st.pc, cid, st.branches);
        }
        // Kernel-faithful dfs_paths decrement (parallel counter, see
        // State::dfs_paths). Walks the SAME chain as branches but
        // its 0-floor is what the inf-loop trap gate consults.
        if st.dfs_paths > 0 {
            st.dfs_paths -= 1;
        }
        let still_open = st.branches > 0;
        let st_parent = st.parent_cache_id;
        let st_loop_entry = st.loop_entry_cache_id;
        if !still_open {
            // This cached state's DFS subtree just completed. Mirror
            // kernel `clean_live_states` -> `clean_verifier_state`
            // (verifier.c v6.15 L19528 / L19482): mutate the cached
            // state to drop dead regs / dead stack slots, making
            // future subsumption against it looser.
            // Kernel gate (verifier.c:19535): a state whose SCC visit
            // still has pending backedges has INCOMPLETE read marks —
            // propagate_backedges will add reads later. Cleaning now
            // would drop dims the kernel still compares; defer to the
            // lazy retry, which re-checks.
            // Kernel has NO eager clean here: `clean_live_states` has
            // exactly ONE call site — is_state_visited
            // (verifier.c:20230), i.e. caches are scrubbed LAZILY at
            // the next ARRIVAL at their pc, not at the branches→0
            // event. An eager clean would freeze the scrub with the
            // liveness snapshot of the subtree-completion instant —
            // BEFORE sibling explorations commit their must_write
            // kills — keeping alive slots the kernel scrubs. The lazy
            // site in pruning/mod.rs is the kernel's clean.
            // Kernel `maybe_exit_scc` (verifier.c L2253, called
            // from update_branch_counts when branches→0): if this
            // cached state is the entry of an SCC visit, the
            // visit is now done — propagate_backedges fires and
            // the visit is reset. Step 2 (current): backedges
            // list is empty; this is a no-op. Step 3 wires
            // propagate_backedges into maybe_exit_scc proper.
            maybe_exit_scc(env, cid);
            // Kernel update_branch_counts: `if (sl) maybe_free_verifier_state`
            // — a retired (free_list) state whose last live descendant
            // just completed is freed now.
            env.maybe_free_retired(cid);
        }
        if still_open {
            // Other DFS paths through this parent still open ⇒ stop.
            // Still propagate the loop_entry hint if applicable.
            if let (Some(le), Some(parent_cid)) = (st_loop_entry, st_parent) {
                // Read le's info first (immutable borrow), then mutate
                // parent record (live-then-retired resolution).
                let hdr_info = cached_scc_info(env, le);
                if let Some((hbr, hd, _)) = hdr_info
                    && let Some((_, p)) = env.state_by_cache_id_mut(parent_cid)
                {
                    let p_eff_depth = match p.loop_entry_cache_id {
                        Some(_) => p.dfs_depth, // approximation; chain-walk skipped to avoid re-borrow
                        None => p.dfs_depth,
                    };
                    if hbr > 0 && hd < p_eff_depth {
                        p.loop_entry_cache_id = Some(le);
                    }
                }
            }
            break;
        }
        next = st_parent;
    }
}
