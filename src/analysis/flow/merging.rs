// src/analysis/merging.rs
//
// Handles type conflict resolution at control flow merge points.
//
// When different paths reach the same PC with different pointer types for
// the same register, we use "deferred checking":
//   1. Instead of failing immediately, demote conflicting registers to ScalarValue
//   2. Continue exploration
//   3. If the register is later used as a pointer (load/store base), validation fails
//   4. If it's just returned or used arithmetically, it's fine
//
// This matches kernel verifier behavior more closely and handles cases like
// function return values that have different types on different paths but
// are never used as pointers after the merge.

use std::collections::HashSet;

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::reg_types::{RegType, type_family};
use crate::analysis::machine::state::State;

/// Resolve type conflicts at a merge point by demoting conflicting registers to ScalarValue.
/// This implements "deferred checking" - we don't fail here, but the demoted register
/// will cause failures if later used as a pointer.
pub fn resolve_type_conflicts(env: &VerifierEnv, state: &mut State) {
    let pc = state.pc;

    let live_regs = env
        .insn_aux_data
        .get(pc)
        .map(|aux| &aux.live_regs)
        .cloned()
        .unwrap_or_default();

    if let Some(prev_states) = env.explored_states.get(&pc) {
        for prev in prev_states {
            // Find conflicting registers and demote them
            for &r in &live_regs {
                let old_ty = prev.types.get(r);
                let new_ty = state.types.get(r);
                if !types_compatible(&old_ty, &new_ty) {
                    // Demote to ScalarValue - this will cause failure if used as pointer
                    state.types.set(r, RegType::ScalarValue);
                }
            }

            // Also check stack slots and demote conflicting ones
            for (prev_frame, cur_frame) in prev.frames.iter().zip(state.frames.iter_mut()) {
                let live_offsets: HashSet<i16> = prev_frame
                    .stack
                    .live_slot_offsets(&live_regs)
                    .into_iter()
                    .chain(cur_frame.stack.live_slot_offsets(&live_regs))
                    .collect();

                for offset in live_offsets {
                    let old_ty = prev_frame.stack.get_slot_type(offset);
                    let new_ty = cur_frame.stack.get_slot_type(offset);
                    if !types_compatible(&old_ty, &new_ty) {
                        // Demote stack slot to ScalarValue
                        cur_frame.stack.demote_slot_to_scalar(offset);
                    }
                }
            }
        }
    }
}

/// Record a state as explored at its PC.
///
/// Enforces max_states_per_pc limit by removing oldest states when
/// exceeded. Returns the freshly-minted `cache_id` for the cached
/// clone — callers should store this as the continuing state's
/// `parent_cache_id` so the per-path precision walker can find this
/// cached state as the path's most recent predecessor.
///
/// Kernel-aligned: under the kernel-precision regime, also clears
/// inherited precision marks on the cached clone (mirrors
/// `mark_all_scalars_imprecise` at checkpoint, verifier.c v6.15
/// L4543). Precision is then re-established on demand via
/// `propagate_precision` walking the per-path parent-cache-id chain.
pub fn record_state(
    env: &mut VerifierEnv,
    mut state: State,
    max_states_per_pc: usize,
) -> u32 {
    let pc = state.pc;

    let cache_id = env.next_cache_id;
    env.next_cache_id = env.next_cache_id.wrapping_add(1);
    state.cache_id = Some(cache_id);
    // SCC bookkeeping: kernel `add_new_state` invariant — a freshly
    // cached state has branches == 1, the single in-flight path that
    // just checkpointed here (verifier.c asserts exactly this:
    // "verifier_bug_if(new->branches != 1)"). Forks under it add ONLY
    // the extra alternatives (succ_count - 1, kernel push_stack); every
    // path death decrements one (update_branch_counts). A
    // `branches = 0` + per-pop `+= succ_count` accounting would inflate
    // the counter by one per straight-line instruction in sparse-caching
    // mode, so branches would almost never return to 0 and
    // clean_verifier_state / maybe_exit_scc would effectively never run.
    state.branches = 1;
    // Kernel-faithful "open paths" counter, parallel to `branches`. Init
    // 1 = the single in-flight cur path that just hit this checkpoint.
    // See State::dfs_paths doc comment for full semantics.
    state.dfs_paths = 1;

    // Kernel-aligned `mark_all_scalars_imprecise` (verifier.c v6.15
    // L4543): cached snapshots are checkpointed in maximally-permissive
    // form. Precision is then re-established on demand via the
    // per-state parent-cache walker (`mark_chain_precision_backward`)
    // when a downstream sink requires it for safety.
    state.mark_all_scalars_imprecise();

    // Drop the BCF symbolic DAG before caching. Cached states are
    // subsumption oracles only (never re-entered by the worklist for
    // transfer), and BCF is not consulted by regsafe/stacksafe — so
    // retaining the per-state `SymbolicState.exprs: Vec<BcfExpr>` on
    // every cache entry adds memory without earning pruning back (it
    // can dominate RSS on large objects — multi-GB peaks).
    // Keep just the cond-stream length for the refine positional cut
    // (State::cached_path_conds_len doc).
    state.cached_path_conds_len = state.bcf.as_ref().map(|b| b.path_conds.len());
    state.bcf = None;

    let states = env.explored_states.entry(pc).or_default();
    let idx = states.len();
    if crate::analysis::trace_pc_in_range(pc) {
        use crate::analysis::machine::reg::Reg;
        let r1t = state.types.get(Reg::R1);
        let r1i = state.domain.get_interval(Reg::R1);
        let r2t = state.types.get(Reg::R2);
        let r2i = state.domain.get_interval(Reg::R2);
        let r0t = state.types.get(Reg::R0);
        let r9t = state.types.get(Reg::R9);
        let r9i = state.domain.get_interval(Reg::R9);
        let r8t = state.types.get(Reg::R8);
        let r8u = state.domain.get_u64_bounds(Reg::R8);
        let r8p = state.precise_regs.contains(&Reg::R8);
        eprintln!(
            "[cache] pc={} idx={} cid={} parent={:?} r0={:?} r1={:?}[{}..{}] r2={:?}[{}..{}] r9={:?}[{}..{}] r8={:?}u[{:#x}..{:#x}]prec={}",
            pc, idx, cache_id, state.parent_cache_id, r0t, r1t, r1i.0, r1i.1, r2t, r2i.0, r2i.1,
            r9t, r9i.0, r9i.1, r8t, r8u.0, r8u.1, r8p
        );
    }
    states.push(state);
    env.cache_loc_by_id.insert(cache_id, (pc, idx));

    // parallel metrics vector. Same indices as states.
    let metrics = env
        .state_metrics
        .entry(pc)
        .or_default();
    metrics.push(crate::analysis::machine::env::StateMetrics::default());

    // Enforce limit: keep only the most recent states. Apply the same
    // drain to `state_metrics` so the two vectors stay aligned. Keep
    // `cache_loc_by_id` consistent: the drained entries' cache_ids no
    // longer have a valid (pc, idx) location, so remove them; the
    // surviving entries shift left by `excess`, so update their idx.
    if max_states_per_pc > 0 && states.len() > max_states_per_pc {
        let excess = states.len() - max_states_per_pc;
        let surviving_ids: Vec<u32> = states
            .iter()
            .skip(excess)
            .filter_map(|s| s.cache_id)
            .collect();
        env.cache_evictions += excess as u64;
        // Kernel free_list semantics: evicted states leave the pruning
        // list but stay resolvable via `parent_cache_id` chains until
        // `branches == 0` (env.retire_state). Destroying them here
        // dangles branches accounting / bcf backtrack bases /
        // children_unsafe marking.
        let evicted: Vec<State> = states.drain(0..excess).collect();
        metrics.drain(0..excess);
        for s in evicted {
            if let Some(id) = s.cache_id {
                env.cache_loc_by_id.remove(&id);
                env.retire_state(id, pc, s);
            }
        }
        for (new_idx, id) in surviving_ids.iter().enumerate() {
            env.cache_loc_by_id.insert(*id, (pc, new_idx));
        }
    }

    if crate::analysis::flow::diag::dump_cache_growth_enabled() {
        let states_now = env.explored_states.get(&pc).map(|v| v.as_slice()).unwrap_or(&[]);
        let mut sigs: std::collections::HashSet<String> = std::collections::HashSet::new();
        for s in states_now {
            let sig = s
                .types
                .regs
                .iter()
                .map(|r| format!("{:?}", r))
                .collect::<Vec<_>>()
                .join("|");
            sigs.insert(sig);
        }
        eprintln!(
            "[cache_growth] pc={} cache_size={} distinct_type_sigs={}",
            pc,
            states_now.len(),
            sigs.len()
        );
    }

    if let Some(target_pc) = crate::analysis::flow::diag::dump_cache_growth_pc()
        && pc == target_pc {
            let states_now =
                env.explored_states.get(&pc).map(|v| v.as_slice()).unwrap_or(&[]);
            let arrival_idx = states_now.len().saturating_sub(1);
            eprintln!(
                "[cache_growth_verbose] pc={} cache_size={} (arrival idx={})",
                pc,
                states_now.len(),
                arrival_idx
            );
            for (i, s) in states_now.iter().enumerate() {
                let marker = if i == arrival_idx { "*" } else { " " };
                let regs = s
                    .types
                    .regs
                    .iter()
                    .enumerate()
                    .map(|(ri, rt)| format!("R{}={:?}", ri, rt))
                    .collect::<Vec<_>>()
                    .join(" ");
                eprintln!("  {}[{}] {}", marker, i, regs);
            }
        }

    if let Some(target_pc) = crate::analysis::flow::diag::dump_precise_pcs_pc()
        && pc == target_pc
    {
        let mut entries: Vec<(usize, crate::analysis::machine::reg::Reg)> =
            env.precise_pcs.iter().copied().collect();
        entries.sort_by_key(|(p, r)| (*p, format!("{:?}", r)));
        eprintln!(
            "[precise_pcs] fired at pc={} | total_entries={}",
            pc,
            entries.len()
        );
        let mut cur_pc: Option<usize> = None;
        let mut row: Vec<String> = Vec::new();
        let flush = |cur_pc: Option<usize>, row: &Vec<String>| {
            if let Some(p) = cur_pc {
                eprintln!("  pc={:>4}: {}", p, row.join(", "));
            }
        };
        for (p, r) in entries {
            if Some(p) != cur_pc {
                flush(cur_pc, &row);
                row.clear();
                cur_pc = Some(p);
            }
            row.push(format!("{:?}", r));
        }
        flush(cur_pc, &row);
    }

    // Kernel `maybe_enter_scc` (verifier.c v6.15 L20592 — called from
    // is_state_visited right after `kzalloc` for a new state list
    // entry). Ensures a `SccVisit` exists for the new cached state's
    // callchain and records this state as the visit's entry if it's
    // the first to reach it on the current path.
    //
    // Read the cached state back to compute its callchain (we just
    // pushed it; the snapshot it points to is the cached form, post
    // mark_all_scalars_imprecise).
    if let Some(cached) = env
        .explored_states
        .get(&pc)
        .and_then(|v| v.iter().find(|s| s.cache_id == Some(cache_id)))
        .cloned()
    {
        crate::analysis::flow::scc::maybe_enter_scc(env, &cached, cache_id);
    }

    cache_id
}

/// Check if two types are compatible at a join point.
/// This isn't subsumption — it just asks whether two different paths
/// reaching the same PC could legitimately produce these types.
fn types_compatible(a: &RegType, b: &RegType) -> bool {
    use RegType::*;

    // NotInit is compatible with anything (dead register, never read)
    matches!(a, NotInit) || matches!(b, NotInit)
    // ScalarValue is compatible with any type: null checks turn
    // pointer-or-null into scalar 0, arithmetic can yield scalars
    // from pointers, etc. This is the normal result of branching.
    || matches!(a, ScalarValue) || matches!(b, ScalarValue)
    // Same family is always compatible (e.g. PtrToMapValue with
    // PtrToMapValueOrNull, PtrToSocket with PtrToSocketOrNull)
    || type_family(a) == type_family(b)
    // Different readable pointer types are compatible - each path will be
    // validated independently. This handles cases like `twotypes` where a
    // register can be either PtrToStack or PtrToMapValue depending on the path.
    // We don't demote to ScalarValue because both are valid for memory access.
    || (is_readable_ptr(a) && is_readable_ptr(b))
    // Map objects and inner map pointers (represented as PtrToMapValue) are both
    // valid map pointer arguments, so they shouldn't demote each other to Scalar.
    || (is_map_ptr(a) && is_map_ptr(b))
}

/// Check if a type is a general-purpose readable pointer that can safely merge
/// with other readable pointers at join points.
///
/// NOTE: PtrToCtx is intentionally EXCLUDED because ctx pointers have special
/// field-based access rules that differ from regular memory pointers. Merging
/// a ctx pointer with a map value pointer could allow unsafe ctx field access.
fn is_readable_ptr(ty: &RegType) -> bool {
    use RegType::*;
    matches!(
        ty,
        PtrToStack { .. }
            | PtrToMapValue { .. }
            | PtrToPacket
            | PtrToPacketMeta
            | PtrToAllocMem { .. }
            | PtrToArena { .. }
            // PtrToBtfId is a kernel BTF-typed pointer; field loads are
            // bounds-validated against the type's BTF. When two paths
            // reach the same PC with one producing PtrToStack and another
            // producing PtrToBtfId (typical of `__noinline static`
            // subprogs called from both main and a timer/wq async cb,
            // see verifier_private_stack.c::private_stack_async_callback_2),
            // each path's body verifies independently against its own
            // type — no need to demote to Scalar. The kernel achieves the
            // same by re-verifying the subprog separately for each
            // distinct caller-state shape (`push_async_cb` makes the cb
            // a separate verifier root).
            | PtrToBtfId { .. }
            // Sock-class pointers (`bpf_skc_lookup_tcp` returns sock_common,
            // `bpf_sk_lookup_*` returns socket; programs converge them at
            // the post-null-check `if (sk)` join — vrf_socket_lookup,
            // test_sk_assign, test_btf_skc_cls_ingress). Without these
            // two arms get demoted to Scalar at the merge and fail at
            // `bpf_sk_release` downstream. Each cached path validates its
            // own sock subtype independently against the release sink
            // (kernel `bpf_sk_release` accepts both PTR_TO_SOCKET and
            // PTR_TO_SOCK_COMMON via `btf_struct_ids_match` supertyping).
            | PtrToSocket { .. } | PtrToSocketOrNull { .. }
            | PtrToSockCommon { .. } | PtrToSockCommonOrNull { .. }
            | PtrToTcpSock { .. } | PtrToTcpSockOrNull { .. }
            // Refcounted-kptr family (PTR_TO_BTF_ID|MEM_ALLOC). The graph-
            // pop / kptr-xchg patterns in local_kptr_stash + map_kptr
            // mint these from two different sources (`bpf_obj_new` →
            // PtrToOwnedKptr; `bpf_kptr_xchg` previous-slot → PtrToMapKptr
            // with MEM_ALLOC) and converge them at a post-null-check `if`
            // before passing to a release sink (`bpf_obj_drop`,
            // `bpf_kfunc_call_test_release`). The kernel accepts both at
            // the same sink via `reg_btf_record(reg)`; without these two
            // arms the merge demotes to Scalar.
            | PtrToOwnedKptr { .. } | PtrToOwnedKptrOrNull { .. }
            | PtrToMapKptr { .. } | PtrToMapKptrOrNull { .. }
    )
}

/// Check if a type can be used as a map pointer. PtrToMapValue is included because
/// it can represent a pointer to an inner map in an array-of-maps or hash-of-maps.
fn is_map_ptr(ty: &RegType) -> bool {
    use RegType::*;
    matches!(ty, PtrToMapObject { .. } | PtrToMapValue { .. })
}
