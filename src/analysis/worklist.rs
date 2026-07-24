// The worklist driver: kernel do_check's LIFO-DFS mirror — pop, transfer,
// prune-point handling, push successors. Extracted from analysis/mod.rs;
// free function over &mut VerifierEnv per the module convention.

use std::collections::VecDeque;

use log::{debug, error, info};

use crate::analysis::machine::env::VerifierEnv;
use crate::analysis::machine::state::State;
use crate::ast::{Instr, Program};
use crate::common::config::VerifierConfig;
use std::collections::HashMap;

use crate::analysis::machine::reg::Reg;
use crate::pcc::{apply_verified_refinements, check_proof};
use crate::analysis::flow::{self, merging, pruning};
use crate::analysis::transfer;
use crate::analysis::machine::error::VerificationError;
use super::{jmpcnt_in_range, pushdump, trace_pc_in_range};

/// Worklist abstract-interpretation loop. Shared between the main-program
/// analysis (`analyze_program_full`) and the exception-cb body pass
/// (`analyze_exception_cb`). Returns the number of states pruned.
pub(super) fn run_worklist(
    env: &mut VerifierEnv,
    prog: &Program,
    config: &VerifierConfig,
    initial_state: State,
) -> usize {
    let mut worklist = VecDeque::new();
    worklist.push_back(initial_state);

    if config.verbosity >= 1 {
        info!(target: "app", "[Analysis] Starting Abstract Interpretation...");
    }

    let mut prune_count: usize = 0;

    let diag_pcs = crate::analysis::flow::diag::diag_pcs();
    let mut diag_arrivals: HashMap<usize, usize> = HashMap::new();

    dump_ast(prog);
    dump_jmp_points(env, prog);

    let mut prev_died = false;
    while let Some(mut state) = worklist.pop_back() {
        zpop_trace(prev_died, &state, env);
        prev_died = true;
        wl_pop_trace(&state);
        pushdump("POP", &state);
        // Per-path counter bump for the kernel-engine sparse-cache
        // heuristic (`ZOVIA_KERNEL_ENGINE=1`). Counts THIS path's
        // progress (not env-wide), so worklist interleaving doesn't
        // pollute the deltas with other paths' work.
        state.path_insn_count = state.path_insn_count.saturating_add(1);
        // Kernel `push_jmp_history` accumulation (verifier.c v6.15
        // L21128-L21131): in `do_check`, every `is_jmp_point` PC
        // appends a branch-decision entry to `cur->jmp_history`. Mirror
        // the dominant call site by bumping the per-state counter at
        // every jmp_point PC visit. Drives the long-history safety
        // valve `add_new_state` reads at L20256
        // (`cur->jmp_history_cnt > 40`). Other push_jmp_history sites
        // (linked-regs at L17682, stack-spill flags at L5670/L5976)
        // are conditional on insn-specific flags zovia doesn't model
        // yet — under-counting at those secondary sites is preferred
        // over re-implementing the flag machinery.
        // Kernel SECONDARY push_jmp_history sites (verifier.c:5677 spill /
        // :5983 fill): a stack WRITE that is a register spill and a stack
        // READ that restores a spilled register each push a history entry
        // (`if (insn_flags) return push_jmp_history(...)`; misc writes and
        // non-spill reads zero the flags and do NOT count). Loop bodies
        // spill/fill every iteration, so these dominate history growth on
        // deep lineages — without them the counter undercounts and the
        // kernel's history-FORCED late loop-head checkpoints never happen
        // here.
        let stack_spill_fill = {
            use crate::analysis::machine::reg::Reg;
            use crate::analysis::machine::reg_types::RegType;
            let is_stack_base = |b: &Reg| {
                *b == Reg::R10
                    || matches!(state.types.get(*b), RegType::PtrToStack { .. })
            };
            // Kernel write-side gate (check_stack_write_fixed_off:5664):
            // the else-branch — an UNALIGNED / misc-class write — zeroes
            // insn_flags ("not a register spill") and pushes NO history
            // entry. Only slot-aligned writes (scalar-reg spill, BPF_ST
            // const, 8-byte pointer spill) push; counting every reg-store
            // would cross the >40 force-checkpoint cap where the kernel
            // stays under it. Aligned ST-imm stores also count (kernel
            // is_bpf_st_mem branch keeps its flags).
            let effective_off = |b: &Reg, insn_off: i16| -> Option<i64> {
                if *b == Reg::R10 {
                    Some(insn_off as i64)
                } else {
                    state
                        .domain
                        .get_distance_fixed(*b, Reg::R10)
                        .map(|d| d + insn_off as i64)
                }
            };
            match prog.instrs.get(state.pc) {
                Some(&Instr::Store { ref base, off, .. }) => {
                    is_stack_base(base)
                        && effective_off(base, off)
                            .is_some_and(|o| o % 8 == 0)
                }
                Some(&Instr::StoreRel { ref base, .. }) => is_stack_base(base),
                Some(&Instr::Load { ref base, ref off, .. })
                | Some(&Instr::LoadAcq { ref base, ref off, .. }) => {
                    is_stack_base(base)
                        && matches!(
                            state.frames.current().stack.get_slot_kind(*off),
                            Some(crate::analysis::machine::stack_state::StackSlotKind::Spill)
                        )
                }
                _ => false,
            }
        };
        if stack_spill_fill {
            state.jmp_history_cnt = state.jmp_history_cnt.saturating_add(1);
        }
        if state.pc < env.insn_aux_data.len()
            && env.insn_aux_data[state.pc].jmp_point
        {
            state.jmp_history_cnt = state.jmp_history_cnt.saturating_add(1);
            jh_bump_trace(&state);
            lineage_dump(env, &state);
        }
        // Per-instruction scope for the BCF `detect_conflict_eq`
        // path-unreachable flag: only the instruction that set it (its
        // own transfer) consumes it. Reset here so a set from a
        // helper-arg `check_load` (mem_checks) can't leak forward.
        env.bcf_path_unreachable = false;
        let diag_hit = diag_pcs
            .as_ref()
            .map(|s| s.contains(&state.pc))
            .unwrap_or(false);
        let (diag_r4_pre, diag_r6_pre) = if diag_hit {
            (
                Some(format!("{:?}", state.types.get(Reg::R4))),
                Some(format!("{:?}", state.types.get(Reg::R6))),
            )
        } else {
            (None, None)
        };
        diag_enter_trace(diag_hit, &mut diag_arrivals, &state, &diag_r4_pre, &diag_r6_pre);
        if env.failed() {
            error!(target: "app", "[Analysis] Aborted due to previous errors.");
            break;
        }

        // Fail immediately if we somehow reach the second half of LD_IMM64
        if prog.invalid_pc_set.contains(&state.pc) {
            env.fail(VerificationError::InvalidBPFLoadImmInsn { pc: state.pc });
            break;
        }

        // A.a TYPE CONFLICT RESOLUTION (zone-mode only)
        // Demote conflicting registers to ScalarValue.
        // If they're later used as pointers, that will fail.
        //
        // KERNEL-MODE SKIPS THIS: it is a merge-point mechanism with no
        // kernel analog — the kernel's is_state_visited only COMPARES
        // cur against cached states (regsafe/states_equal); it never
        // mutates cur based on what the cache holds, and incompatible-
        // type paths each verify independently under DFS.
        if !env.kernel_faithful_alu && state.pc < prog.instrs.len() - 1 {
            merging::resolve_type_conflicts(&env, &mut state);
        }

        diag_demote_trace(diag_hit, &state, &diag_r4_pre, &diag_r6_pre);

        dump_states_at_pc(&state);

        // Kernel do_check: `++env->insn_processed` (verifier.c:21172)
        // runs BEFORE is_state_visited (21189) — EVERY arrival counts,
        // including ones that then prune.
        env.insn_processed += 1;
        insn_trace(env.insn_processed, state.pc);
        regval_trace(&state, env.insn_processed);

        // A.b PRUNING CHECK
        if pruning::should_prune(env, &mut state, config, prog) {
            diag_prune_trace(diag_hit, state.pc, true);
            info!("Pruned state at pc {}", state.pc);
            prune_count += 1;
            // Kernel process_bpf_exit: `bpf_update_live_stack` at every
            // path death, BEFORE branch counts drop (so a state cleaned
            // at branches==0 sees fully propagated read marks).
            let ls_key = flow::live_stack::callchain_of(&state);
            flow::live_stack::update_live_stack(env, &ls_key);
            // SCC: this DFS path is done (subsumed by a cached state).
            // Decrement parent.branches up the chain; if a parent's
            // branches hits 0 propagate its loop_entry to its parent.
            cdb_prune_death_trace(state.pc, state.parent_cache_id);
            crate::analysis::flow::scc::complete_dfs_branch(env, state.parent_cache_id);
            continue;
        }
        diag_prune_trace(diag_hit, state.pc, false);

        // A.c RECORD STATE — kernel-faithful `is_state_visited` shape.
        // Gated by `config.kernel_engine` (formerly env `ZOVIA_KERNEL_ENGINE=1`,
        // kept as fallback below for legacy callers). Two kernel-shape gates
        // layered:
        //   (1) Outer: cache only at PRUNE POINTS (kernel `do_check` only
        //       calls `is_state_visited` when is_prune_point fires).
        //       zovia's dense default mode caches at EVERY popped state;
        //       that produces a parent_cache_id chain with consecutive-pc
        //       deltas the kernel never has. Gate fixes that.
        //   (2) Inner: `add_new_state` heuristic (verifier.c v6.15
        //       L18998-L19013): force_new_state || (jmps_delta>=2 &&
        //       insns_delta>=8). Counters are PER-PATH on State.
        // ON in BCF mode; the legacy dense-cache path remains for non-BCF
        // mode (selftest baseline).
        let kernel_engine = config.kernel_engine || env.bcf_enabled;
        let at_prune_point = pruning::widening::is_prune_point(env, state.pc);
        let insn_aux_force = env
            .insn_aux_data
            .get(state.pc)
            .map(|a| a.force_checkpoint)
            .unwrap_or(false);
        // Kernel L18999-L19013 uses ENV-WIDE counters. But zovia's
        // worklist interleaves paths, so env-wide deltas are noisy:
        // they can be inflated (other paths' work) OR understated
        // (after a cache event, the same path may re-pop with no
        // env increment between). Neither alone exactly matches the
        // kernel's linear-DFS env behavior. Solution: OR env-wide
        // and per-path heuristics — fire if EITHER triggers. This
        // produces a SUPERSET cache pattern (more entries than
        // either alone), maximising bundle coverage. The kernel
        // matches by HASH; extra entries are ignored.
        let env_jmps_delta = env
            .jmps_processed
            .saturating_sub(env.prev_jmps_processed);
        let env_insns_delta = env
            .insn_processed
            .saturating_sub(env.prev_insn_processed);
        let path_jmps_delta = state
            .path_jmp_count
            .saturating_sub(state.prev_jmp_at_cache);
        let path_insns_delta = state
            .path_insn_count
            .saturating_sub(state.prev_insn_at_cache);
        // Kernel L18998-L19000: long-history safety valve. Fire when
        // either env-wide or per-path window > 40 insns since last
        // cache event.
        // Kernel L20254-L20256: long-history safety valve. Kernel
        // formula is `cur->jmp_history_cnt > 40` — a count of BRANCH
        // DECISIONS recorded on this state's lineage (per
        // `push_jmp_history` accumulation), NOT a raw insn delta
        // (an insn-delta valve fires far more aggressively than the
        // kernel's).
        let long_history = state.jmp_history_cnt > 40;
        let force_new_state = insn_aux_force || long_history;
        let env_heuristic =
            env_jmps_delta >= 2 && env_insns_delta >= 8;
        // Kernel `is_state_visited` add_new_state (verifier.c L20186-20189) is a
        // SINGLE condition on the env-wide counters:
        //   jmps_processed - prev_jmps_processed >= 2 && insn_processed - prev >= 8
        // zovia's worklist is a LIFO stack (push_back + pop_back) = pure DFS,
        // identical to the kernel's traversal, and `jmps/insn_processed` are
        // bumped per-insn/per-jmp with `prev_*` reset at each add_new_state
        // (below) — so `env_heuristic` reproduces the kernel's condition exactly.
        // (No per-path term: the worklist is not interleaved, and a per-path
        // OR would over-cache vs the kernel.)
        let outer_gate = !kernel_engine || at_prune_point;
        // Kernel in-loop checkpoint dampener (`skip_inf_loop_check`,
        // verifier.c ~20320): when the pruning scan met a cached state
        // with branches>0 at this pc (an in-flight ancestor — "the
        // verifier is processing a loop"), suppress the add unless
        // force_new_state or the deltas reach the loop thresholds
        // (dj>=20 || di>=100; kernel constants). This is what gives the
        // kernel its sparse in-loop checkpoint cadence (adds every few
        // iterations instead of via the bare 2/8 rule).
        let loop_dampener = env.saw_active_state_at_check
            && !force_new_state
            && env_jmps_delta < 20
            && env_insns_delta < 100;
        let add_new_state = !kernel_engine
            || force_new_state
            || (env_heuristic && !loop_dampener);
        if outer_gate && add_new_state {
            let cache_id =
                merging::record_state(env, state.clone(), config.max_states_per_pc);
            if trace_pc_in_range(state.pc) {
                let n_cached = env.explored_states.get(&state.pc).map(|v| v.len()).unwrap_or(0);
                eprintln!(
                    "[TRACE] CACHE pc={} -> cache_id={} parent={:?} (n_now={}, force_new={} env_jd={} env_id={} path_jd={} path_id={} jmp_hist={} env_h={} outer_gate={})",
                    state.pc, cache_id, state.parent_cache_id, n_cached,
                    force_new_state, env_jmps_delta, env_insns_delta, path_jmps_delta, path_insns_delta,
                    state.jmp_history_cnt,
                    env_heuristic,
                    outer_gate,
                );
                cache_slots3_dump(&state, cache_id);
            }
            srange_trace(cache_id, &state);
            state.parent_cache_id = Some(cache_id);
            // Kernel `cur->first_insn_idx = insn_idx` (verifier.c:20529): the
            // continuing state begins a NEW segment at this checkpoint pc. The
            // cached clone above keeps the PRIOR segment start (copy_verifier_state
            // :2073). last_insn_idx is unchanged (it's the arrival pc, set on
            // this state at successor-creation).
            state.first_insn_idx = state.pc;
            jmpcnt_add_trace(env, state.pc);
            env.prev_jmps_processed = env.jmps_processed;
            env.prev_insn_processed = env.insn_processed;
            state.prev_jmp_at_cache = state.path_jmp_count;
            state.prev_insn_at_cache = state.path_insn_count;
            // Kernel `clear_jmp_history(cur)` at verifier.c v6.15 L20645:
            // at every add_new_state event, kernel resets the current
            // state's jmp_history_cnt to 0. Zovia must mirror — otherwise
            // the counter grows unboundedly across cache events and the
            // long-history safety valve (jmp_history_cnt > 40) fires
            // unnecessarily at every later prune-point, force-caching
            // states the kernel doesn't cache.
            state.jmp_history_cnt = 0;
        } else if trace_pc_in_range(state.pc) {
            eprintln!(
                "[TRACE] NOCACHE pc={} parent={:?} (force_new={} env_jd={} env_id={} path_jd={} path_id={} jmp_hist={} env_h={} outer_gate={})",
                state.pc, state.parent_cache_id,
                force_new_state, env_jmps_delta, env_insns_delta, path_jmps_delta, path_insns_delta,
                state.jmp_history_cnt,
                env_heuristic,
                outer_gate,
            );
        }

        // B. Global Complexity Limit (increment moved above the pruning
        // check — kernel order; see comment there.)
        dump_visits_bump(env, state.pc);
        // BCF mode is an offline bundle generator that explores past
        // rejects (discharge, not fail-fast), so it uses a higher budget
        // than the kernel's 1M runtime cap. Base mode keeps 1M — hitting it
        // there is a faithful kernel reject. See VerifierConfig::max_insn.
        let insn_limit = if env.bcf_enabled {
            config.bcf_max_insn
        } else {
            config.max_insn
        };
        if env.insn_processed > insn_limit {
            // We use error! with target="analysis" to auto-trigger the crash dump
            error!(target: "analysis", "[Verifier] Hit complexity limit ({} instructions). Aborting.", insn_limit);
            info!(target: "app", "[Verifier] (Pruned {} states before limit)", prune_count);
            info!(target: "app", "[Verifier] Tip: Try --skip-dbm or --max-insn N to increase limit");
            env.fail(VerificationError::ComplexityLimitExceeded {
                limit: insn_limit,
            });
            break;
        }

        // C. Heartbeat Logging (Level 1+)
        if config.verbosity >= 1 && env.insn_processed.is_multiple_of(config.log_interval) {
            info!(target: "app", "[Verifier] Processed {} instructions (pruned {}). Worklist size: {}",
                     env.insn_processed, prune_count, worklist.len());
        }

        // C'. Subsumption-miss dump (diagnostic, env-gated, verbosity-independent).
        prune_miss_dump(env, worklist.len(), config.log_interval);

        // D. Instruction Fetch
        if state.pc >= prog.instrs.len() {
            continue;
        }
        let instr = &prog.instrs[state.pc];

        let reg_types_str = state.types.reg_types_str();
        let reg_ranges_str = state.reg_ranges_str();
        let current_step_idx = Some(env.history.record(
            state.pc,
            instr,
            reg_types_str,
            reg_ranges_str,
            state.num_frames(),
            state.history_idx,
        ));
        // The reject insn's own breadcrumb — the reactive
        // path-unreachable discharge's `bcf_suffix_base_pc` walk must
        // start here (kernel `backtrack_states` `last_idx =
        // cur->insn_idx`, skip_first), not from the in-flight state's
        // parent `history_idx`.
        env.current_step_idx = current_step_idx;

        // E. Logging
        if config.verbosity >= 3 {
            // Full DBM matrix — only at highest verbosity to avoid flooding logs.
            // The structured Ranges/Zone/Tnums lines below (v>=2) are logged first;
            // the matrix adds the raw cell values for deep debugging.
            let matrix = state.domain.matrix_full_str();
            if !matrix.is_empty() {
                debug!(target: "app", "[DBM@PC:{}]\n{}", state.pc, matrix);
            }
        }
        if config.verbosity >= 2 || config.debug_pc == Some(state.pc) {
            let ranges = state.reg_ranges_str();
            let rel    = state.domain.relations_str();
            let tnums  = state.reg_tnums_compact_str();

            let rel_line = if rel.is_empty() {
                String::new()
            } else {
                format!("\n  Rel:    {}", rel)
            };
            let tnum_line = if tnums.is_empty() {
                String::new()
            } else {
                format!("\n  Tnums:  {}", tnums)
            };

            debug!(target: "app",
                "[PC:{}] {}\n  Types:  {}\n  Ranges: {}{}{}",
                state.pc, instr,
                state.types.reg_types_str(),
                ranges, rel_line, tnum_line
            );
        }

        // F. Transfer Function
        let diag_cur_pc = state.pc;
        // SCC: save fields needed after `state` is moved into transfer.
        let cur_dfs_depth = state.dfs_depth;
        let cur_parent_cache_id = state.parent_cache_id;
        // Kernel `env->insn_idx` for this step: each successor arrives FROM
        // this pc, so its `last_insn_idx` = this pc (verifier.c:21049
        // `state->last_insn_idx = env->prev_insn_idx`).
        let cur_insn_pc = state.pc;
        state.domain.set_current_pc(state.pc);
        // Kernel `env->jmps_processed++` (verifier.c L19553): bump on
        // JMP-class insn for the add_new_state sparse-cache heuristic.
        // Bumped on BOTH env-wide and per-path counters; the heuristic
        // uses the per-path one. The env-wide field stays for any
        // downstream consumer that wants the cumulative figure.
        let is_jmp_class = matches!(
            instr,
            Instr::If { .. } | Instr::Jmp { .. } | Instr::MayGoto { .. }
                | Instr::Call { .. } | Instr::CallRel { .. } | Instr::Exit
        );
        if is_jmp_class {
            env.jmps_processed += 1;
            state.path_jmp_count = state.path_jmp_count.saturating_add(1);
            jmpcnt_jmp_trace(env, state.pc);
        }
        // Kernel do_check: `bpf_reset_stack_write_marks(env, insn_idx)`
        // before do_check_insn, `bpf_commit_stack_write_marks` after.
        // The callchain snapshot also serves the path-death
        // `bpf_update_live_stack` below (state is moved into transfer).
        let ls_key = flow::live_stack::callchain_of(&state);
        flow::live_stack::reset_stack_write_marks(env, &state, state.pc);
        let mut successors = transfer::transfer(env, state, instr);
        flow::live_stack::commit_stack_write_marks(env);
        diag_succ_trace(diag_hit, diag_cur_pc, &successors);
        // F.1 Certificate-Aided Refinement (optional)
        // Replay-verify proof chains for each successor PC using explored_states.
        if let Some(ref cert) = env.certificate {
            for succ in &mut successors {
                let succ_pc = succ.pc;
                let mut verified = Vec::new();
                for ann in &cert.pc_annotations {
                    if ann.pc != succ_pc {
                        continue;
                    }
                    for entry in &ann.entries {
                        if let Some(v) =
                            check_proof(entry, ann.pc, &env.explored_states, prog)
                        {
                            verified.push(v);
                        }
                    }
                }
                apply_verified_refinements(succ, &verified);
            }
        }

        // G. Critical Failure Check
        if env.failed() {
            error!(target: "analysis", "[Verifier] Analysis halted due to critical error: {}", 
                   env.error.as_ref().unwrap().description());
            if config.enable_path_trace
                && let Some(crash_idx) = current_step_idx
            {
                let trace = env.history.get_trace(crash_idx);
                // Print directly to stdout (or error log) so it stands out
                println!(
                    "\n=== CRASH PATH RECONSTRUCTION ({} Steps) ===",
                    trace.len()
                );
                for (i, step) in trace.iter().enumerate() {
                    println!(
                        "[{:03}] PC {:<4} | {}\n       Types:  {}\n       Ranges: {}",
                        i, step.pc, step.instr_str,
                        step.reg_types_str,
                        step.reg_ranges_str,
                    );
                }
                println!("=============================================\n");
            }
            break;
        }

        // H. Push Successors
        // Prioritize exit-path successors over loop-back successors.
        // Kernel push order: the kernel's push_stack has NO loop-back
        // deferral; uniform LIFO gives sibling arms anchor
        // recency-locality at loop heads (the deferral lets every
        // arm-variant of an iteration seed its own forward re-exploration
        // before any back-edge pops → quadratic redundant paths). ON in
        // BCF mode; base mode keeps the deferral (selftest baseline).
        let kernel_push_order = env.bcf_enabled;
        let mut loop_back = Vec::new();
        let mut other = Vec::new();
        let succ_count = successors.len();
        for mut succ in successors.into_iter() {
            succ.history_idx = current_step_idx;
            // Kernel `state->last_insn_idx = env->prev_insn_idx` (verifier.c:21049):
            // this successor arrived from the instruction just processed.
            succ.last_insn_idx = cur_insn_pc;
            // SCC: child inherits its DFS depth from parent + 1, and its
            // initial branches=1 (this one in-flight path through succ).
            // The parent's branches gets bumped once per pushed successor
            // below.
            succ.dfs_depth = cur_dfs_depth.saturating_add(1);
            succ.branches = 1;
            let is_loop_back = !kernel_push_order
                && current_step_idx
                    .map(|idx| env.history.is_back_edge(idx, succ.pc, succ.num_frames()))
                    .unwrap_or(false);
            if is_loop_back {
                loop_back.push(succ);
            } else {
                other.push(succ);
            }
        }
        // SCC: bump parent.branches once per pushed successor (kernel
        // `push_stack` L2045). state.parent_cache_id is the just-recorded
        // cache_id at this pc (set at A.c above), so each successor is a
        // new in-flight DFS path through it.
        //
        // ALSO bump parent.dfs_paths kernel-faithfully: only by
        // (succ_count - 1), because the kernel's push_stack is invoked
        // once per ALT — i.e. once per fork-extra, NOT per total
        // successor. The cur continuation is already counted by
        // dfs_paths=1 at cache creation. Linear chains (succ_count==1)
        // get no bump. This is the load-bearing signal for the inf-loop
        // trap gate (`prev.dfs_paths == 0` skip).
        if succ_count > 0
            && let Some(pcid) = cur_parent_cache_id
            && let Some((_, p)) = env.state_by_cache_id_mut(pcid)
        {
            // Kernel push_stack: only the EXTRA fork alternatives bump
            // the checkpoint's branches — the continuing path was
            // already counted (branches=1 at record_state). Straight-
            // line pops (succ_count==1) add nothing.
            if succ_count > 1 {
                p.branches = p.branches.saturating_add((succ_count - 1) as u32);
                p.dfs_paths = p.dfs_paths.saturating_add((succ_count - 1) as u32);
                br_inc_trace(p, pcid, cur_insn_pc, succ_count);
            }
        }
        if succ_count == 0 {
            // No successors (e.g. Exit): this DFS path terminated.
            // Kernel process_bpf_exit: propagate live-stack marks first.
            flow::live_stack::update_live_stack(env, &ls_key);
            // Decrement parent chain analogously to the prune-hit path.
            cdb_exit_death_trace(cur_insn_pc, cur_parent_cache_id);
            crate::analysis::flow::scc::complete_dfs_branch(env, cur_parent_cache_id);
        }
        let n_push = loop_back.len() + other.len();
        // A continuation gets pushed iff n_push>0 — the next pop is then
        // NOT kernel-comparable.
        prev_died = n_push == 0;
        let mut push_i = 0usize;
        for succ in loop_back {
            pushdump("PUSH-lb", &succ);
            zpush_trace(succ.pc, cur_insn_pc, push_i, n_push, env);
            push_i += 1;
            worklist.push_back(succ);
        }
        for succ in other.into_iter().rev() {
            wl_push_trace(&succ, worklist.len(), env.insn_processed);
            pushdump("PUSH", &succ);
            zpush_trace(succ.pc, cur_insn_pc, push_i, n_push, env);
            push_i += 1;
            worklist.push_back(succ);
        }
    }

    prune_count
}

// ---- debug instruments ----
//
// Env-gated eprintln! probes hoisted out of the worklist loop body. Each
// helper does its own gating (env var and/or trace-pc range) so the call
// site is a single line; none affect analysis results.

/// ZOVIA_DUMP_AST: one-shot dump of AST instr at trace PCs (WT diagnostic).
fn dump_ast(prog: &Program) {
    if std::env::var("ZOVIA_DUMP_AST").is_ok() {
        for pc in 0..prog.instrs.len() {
            if trace_pc_in_range(pc) {
                eprintln!("[AST] pc={} instr={:?}", pc, prog.instrs[pc]);
            }
        }
    }
}

/// ZOVIA_DUMP_JMP_POINTS=1: dump jmp_point + prune_point flags +
/// predecessor instr kind (to identify which mark site fired). WT
/// diagnostic.
fn dump_jmp_points(env: &VerifierEnv, prog: &Program) {
    if std::env::var("ZOVIA_DUMP_JMP_POINTS").ok().as_deref() == Some("1") {
        for pc in 0..prog.instrs.len() {
            if !trace_pc_in_range(pc) { continue; }
            let aux = &env.insn_aux_data[pc];
            if !aux.jmp_point { continue; }
            // Identify likely mark source: look at pc-1 for Call/Jmp/CallRel
            // (post-call fallthrough / unconditional jmp target) or scan for
            // an If/Jmp/CallRel/MayGoto with target=pc earlier.
            let pred_kind: String = if pc > 0 {
                match &prog.instrs[pc - 1] {
                    Instr::Call { .. } => "post-Call".into(),
                    Instr::CallRel { .. } => "post-CallRel".into(),
                    Instr::Jmp { .. } => "post-Jmp(unreachable)".into(),
                    Instr::MayGoto { .. } => "post-MayGoto-FT".into(),
                    Instr::If { .. } => "post-If-FT".into(),
                    _ => "other".into(),
                }
            } else { "PC0".into() };
            // Check if any earlier insn targets this PC
            let mut tgt_kinds: Vec<&str> = Vec::new();
            for (sp, si) in prog.instrs.iter().enumerate() {
                match si {
                    Instr::If { target, .. } if *target == pc => tgt_kinds.push("If-target"),
                    Instr::Jmp { target } if *target == pc => tgt_kinds.push("Jmp-target"),
                    Instr::MayGoto { target } if *target == pc => tgt_kinds.push("MayGoto-target"),
                    Instr::CallRel { target } if *target == pc => tgt_kinds.push("CallRel-target"),
                    _ => {}
                }
                let _ = sp;
            }
            eprintln!(
                "[JMP_PT] pc={} pred={} target_of={:?} (prune={} force_cp={})",
                pc, pred_kind, tgt_kinds, aux.prune_point, aux.force_checkpoint
            );
        }
    }
}

/// [zpop] (ZOVIA_DBG_PUSHLOG=1; kernel [ZK pop] mirror): a zovia pop is
/// kernel-comparable iff the PREVIOUS iteration died (prune-hit / zero
/// successors / fetch-fail) — otherwise it's the continuation pop the
/// kernel never makes. First pop = the initial state (no kernel analog).
fn zpop_trace(prev_died: bool, state: &State, env: &VerifierEnv) {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let zpop_on = *ON.get_or_init(|| {
        std::env::var("ZOVIA_DBG_PUSHLOG").ok().as_deref() == Some("1")
    });
    if zpop_on && prev_died {
        eprintln!(
            "[zpop] resume={} ip={} jp={}",
            state.pc, env.insn_processed, env.jmps_processed
        );
    }
}

/// [zpush] (ZOVIA_DBG_PUSHLOG=1): kernel-comparable push stream. The
/// kernel's push_stack fires once per NON-continued arm; zovia pushes
/// every successor (the LAST-pushed is the continuation, popped right
/// back). Print all but the final push of this fork ([ZK push] analog:
/// at=branch pc, resume=arm pc).
fn zpush_trace(pc: usize, at: usize, i: usize, n_push: usize, env: &VerifierEnv) {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let pushlog = *ON.get_or_init(|| {
        std::env::var("ZOVIA_DBG_PUSHLOG").ok().as_deref() == Some("1")
    });
    if pushlog && i + 1 < n_push {
        eprintln!(
            "[zpush] at={} resume={} ip={} jp={}",
            at, pc, env.insn_processed, env.jmps_processed
        );
    }
}

/// [WL_POP] trace-range pop probe. R9's type at pop (pairs with the
/// [WL_PUSH] R9 print; a type flip between them = the pushed snapshot
/// mutated or the pop pairing is wrong).
fn wl_pop_trace(state: &State) {
    if trace_pc_in_range(state.pc) {
        let (r2lo, r2hi) = state.domain.get_interval(Reg::R2);
        eprintln!(
            "[WL_POP] pc={} parent_cache_id={:?} R2=[{}..{}] R9={:?}",
            state.pc, state.parent_cache_id, r2lo, r2hi,
            state.types.get(Reg::R9),
        );
    }
}

/// [WL_PUSH] trace-range push probe (pairs with [WL_POP]).
fn wl_push_trace(succ: &State, worklist_len: usize, ip: usize) {
    if trace_pc_in_range(succ.pc) {
        eprintln!(
            "[WL_PUSH] pc={} parent_cache_id={:?} (worklist_len_before={}) ip={} R9={:?}",
            succ.pc, succ.parent_cache_id, worklist_len,
            ip, succ.types.get(Reg::R9),
        );
    }
}

/// [JH_BUMP] (ZOVIA_TRACE_JMP_HIST_BUMP=1, trace-range): per-bump
/// jmp_history_cnt probe at jmp_point pcs.
fn jh_bump_trace(state: &State) {
    if std::env::var("ZOVIA_TRACE_JMP_HIST_BUMP").ok().as_deref() == Some("1")
        && trace_pc_in_range(state.pc)
    {
        eprintln!(
            "[JH_BUMP] pc={} new_cnt={} parent_cache={:?}",
            state.pc, state.jmp_history_cnt, state.parent_cache_id
        );
    }
}

/// [LINEAGE] (ZOVIA_DUMP_LINEAGE_PC + ZOVIA_DUMP_LINEAGE_CNT): one-shot
/// lineage dump — when a state first hits the target (pc, new_cnt) combo,
/// walk history backward and print every jmp_point PC the lineage
/// visited. WT diagnostic.
fn lineage_dump(env: &VerifierEnv, state: &State) {
    if let (Ok(target_pc), Ok(target_cnt)) = (
        std::env::var("ZOVIA_DUMP_LINEAGE_PC").and_then(|s| s.parse::<usize>().map_err(|_| std::env::VarError::NotPresent)),
        std::env::var("ZOVIA_DUMP_LINEAGE_CNT").and_then(|s| s.parse::<u64>().map_err(|_| std::env::VarError::NotPresent)),
    ) {
        static DUMPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if state.pc == target_pc && state.jmp_history_cnt as u64 == target_cnt
            && !DUMPED.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            eprintln!("[LINEAGE] state at pc={} cnt={} parent_cache_id={:?}", state.pc, state.jmp_history_cnt, state.parent_cache_id);
            let mut hidx = state.history_idx;
            let mut depth = 0;
            let mut bumps = 0;
            while let Some(i) = hidx {
                let step = match env.history.get(i) { Some(s) => s, None => break };
                let pc = step.pc;
                let is_jp = env.insn_aux_data.get(pc).map(|a| a.jmp_point).unwrap_or(false);
                if is_jp {
                    bumps += 1;
                    eprintln!("[LINEAGE] depth={} pc={} JMP_POINT (bump #{})", depth, pc, bumps);
                }
                depth += 1;
                hidx = step.parent_idx;
                if depth > 5000 { break; }
            }
            eprintln!("[LINEAGE] total_jmp_point_bumps_in_history={} (counter value={})", bumps, state.jmp_history_cnt);
        }
    }
}

/// [DIAG ENTER] per-arrival probe at ZOVIA_DIAG_PCS pcs; bumps the
/// per-pc arrival counter.
fn diag_enter_trace(
    diag_hit: bool,
    diag_arrivals: &mut HashMap<usize, usize>,
    state: &State,
    diag_r4_pre: &Option<String>,
    diag_r6_pre: &Option<String>,
) {
    if !diag_hit {
        return;
    }
    let n = diag_arrivals.entry(state.pc).or_insert(0);
    *n += 1;
    eprintln!(
        "[DIAG ENTER] pc={} arrival#{} frames={} parent_cache={:?}\n  R4={} R6={}\n  Ranges: {}\n  Tnums:  {}",
        state.pc, n, state.num_frames(), state.parent_cache_id,
        diag_r4_pre.as_deref().unwrap_or("?"),
        diag_r6_pre.as_deref().unwrap_or("?"),
        state.reg_ranges_str(),
        state.reg_tnums_compact_str(),
    );
}

/// [DIAG DEMOTE] (ZOVIA_DIAG_PCS): fires when type-conflict resolution
/// changed R4/R6's type at a diag pc.
fn diag_demote_trace(
    diag_hit: bool,
    state: &State,
    diag_r4_pre: &Option<String>,
    diag_r6_pre: &Option<String>,
) {
    if !diag_hit {
        return;
    }
    let r4_post = format!("{:?}", state.types.get(Reg::R4));
    let r6_post = format!("{:?}", state.types.get(Reg::R6));
    if Some(&r4_post) != diag_r4_pre.as_ref()
        || Some(&r6_post) != diag_r6_pre.as_ref()
    {
        eprintln!(
            "[DIAG DEMOTE] pc={} R4: {} -> {}  R6: {} -> {}",
            state.pc,
            diag_r4_pre.as_deref().unwrap_or("?"), r4_post,
            diag_r6_pre.as_deref().unwrap_or("?"), r6_post,
        );
    }
}

/// [DIAG PRUNE] (ZOVIA_DIAG_PCS): the prune verdict at a diag pc.
fn diag_prune_trace(diag_hit: bool, pc: usize, pruned: bool) {
    if !diag_hit {
        return;
    }
    if pruned {
        eprintln!("[DIAG PRUNE] pc={} pruned=true", pc);
    } else {
        eprintln!("[DIAG PRUNE] pc={} pruned=false (recorded)", pc);
    }
}

/// [DIAG SUCC] (ZOVIA_DIAG_PCS): successor pcs + R4/R6 types after the
/// transfer at a diag pc.
fn diag_succ_trace(diag_hit: bool, pc: usize, successors: &[State]) {
    if !diag_hit {
        return;
    }
    let succ_dump: Vec<String> = successors
        .iter()
        .map(|s| {
            format!(
                "pc{}[R4={:?} R6={:?}]",
                s.pc,
                s.types.get(Reg::R4),
                s.types.get(Reg::R6)
            )
        })
        .collect();
    eprintln!(
        "[DIAG SUCC] pc={} -> [{}]",
        pc,
        succ_dump.join(", ")
    );
}

/// [STATE@PC] audit probe: dump compact state at the requested PC(s).
/// Gated on `ZOVIA_DUMP_STATES_AT_PC=N[,M,...]`. Used to inspect why many
/// "equivalent" states accumulate at a single pc (path-explosion
/// diagnostic). Comma-separated list, e.g.
/// `ZOVIA_DUMP_STATES_AT_PC=1587,1856`. Each line includes R0..R9 +
/// their precision marks + a few key stack slot scalars so we can
/// compare what changes across visits to a loop head.
fn dump_states_at_pc(state: &State) {
    if let Ok(s) = std::env::var("ZOVIA_DUMP_STATES_AT_PC") {
        let targets: Vec<usize> = s
            .split(',')
            .filter_map(|t| t.trim().parse::<usize>().ok())
            .collect();
        if targets.iter().any(|&t| t == state.pc) {
            use crate::analysis::machine::reg_types::RegType;
            let mut row = format!("pc={} ", state.pc);
            for r in [Reg::R0, Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5,
                      Reg::R6, Reg::R7, Reg::R8, Reg::R9] {
                let ty = state.types.get(r);
                let (ilo, ihi) = state.domain.get_interval(r);
                let sid = state.scalar_ids.get(&r).copied().unwrap_or(0);
                let p = if state.precise_regs.contains(&r) { "P" } else { "_" };
                // Compact-print: SV[lo..hi]sid=N {P|_}  for scalars,
                // or ptr-type tag for pointers.
                let tag = match ty {
                    RegType::ScalarValue => format!("SV[{}..{}]", ilo, ihi),
                    RegType::PtrToMapValue { offset, map_idx, .. } => {
                        format!("MV(m{},off={:?})", map_idx, offset)
                    }
                    RegType::PtrToCtx => "Ctx".into(),
                    RegType::PtrToStack { .. } => format!("Stk[{}..{}]", ilo, ihi),
                    RegType::PtrToPacket => "Pkt".into(),
                    RegType::PtrToPacketEnd => "PktEnd".into(),
                    RegType::NotInit => "NI".into(),
                    _ => format!("{:?}", ty),
                };
                let r_index = (r as u8).saturating_sub(1);
                row.push_str(&format!(
                    "r{}={}{}sid={} ",
                    r_index, tag, p, sid,
                ));
            }
            // Append the top frame's spilled scalar slots (off, bounds,
            // precise) up to ~10 most-recent for sanity.
            let frame = state.frames.current();
            let mut slot_keys: Vec<i16> = frame.stack.slot_offsets().into_iter().collect();
            slot_keys.sort();
            let mut sn = 0;
            for off in slot_keys.iter().rev() {
                let Some(slot) = frame.stack.get_slot(*off) else { continue; };
                if !matches!(slot.reg_type, RegType::ScalarValue) {
                    continue;
                }
                row.push_str(&format!(
                    "fp{}=SV[{}..{}]sid={}{} ",
                    off, slot.bounds.min, slot.bounds.max,
                    slot.scalar_id.unwrap_or(0),
                    if slot.precise { "P" } else { "_" },
                ));
                sn += 1;
                if sn >= 8 { break; }
            }
            eprintln!("[STATE@PC] {}", row);
        }
    }
}

/// [INSN] corridor execution-order probe (kernel [ZK insn] mirror at the
/// same pre-check position, verifier.c:21181). Trace-range gated within
/// the fixed pc corridor 185..=200.
fn insn_trace(ip: usize, pc: usize) {
    if pc >= 185 && pc <= 200 && trace_pc_in_range(pc) {
        eprintln!("[INSN] ip={} pc={}", ip, pc);
    }
}

/// [regval] ZOVIA_DBG_REGVAL=RN:pc1,pc2,... — dump a register's tracked
/// value pre-execution at the listed pcs.
fn regval_trace(state: &State, ip: usize) {
    static REGVAL: std::sync::OnceLock<Option<(Reg, Vec<usize>)>> =
        std::sync::OnceLock::new();
    let rv = REGVAL.get_or_init(|| {
        let v = std::env::var("ZOVIA_DBG_REGVAL").ok()?;
        let (rs, pcs) = v.split_once(':')?;
        let idx: usize = rs.trim_start_matches(['R', 'r']).parse().ok()?;
        let reg = Reg::ALL[idx + 1];
        let pcs = pcs.split(',').filter_map(|p| p.parse().ok()).collect();
        Some((reg, pcs))
    });
    if let Some((reg, pcs)) = rv
        && pcs.contains(&state.pc)
    {
        let (lo, hi) = state.domain.get_interval(*reg);
        let (ulo, uhi) = state.domain.get_u64_bounds(*reg);
        eprintln!(
            "[regval] pc={} ip={} {:?} ivl=[{},{}] u=[{:#x},{:#x}] tn={:?} ty={:?} prec={}",
            state.pc, ip, reg, lo, hi, ulo, uhi,
            state.get_tnum(*reg), state.types.get(*reg),
            state.is_reg_precise(*reg)
        );
    }
}

/// [dbg-cdb] (ZOVIA_DBG_CDB=1): path death via prune-hit, just before
/// complete_dfs_branch walks the parent chain.
fn cdb_prune_death_trace(pc: usize, parent: Option<u32>) {
    if std::env::var("ZOVIA_DBG_CDB").ok().as_deref() == Some("1") {
        eprintln!("[dbg-cdb] PRUNE-death pc={} parent={:?}", pc, parent);
    }
}

/// [dbg-cdb] (ZOVIA_DBG_CDB=1): path death via zero successors (Exit).
fn cdb_exit_death_trace(pc: usize, parent: Option<u32>) {
    if std::env::var("ZOVIA_DBG_CDB").ok().as_deref() == Some("1") {
        eprintln!("[dbg-cdb] EXIT-death pc={} parent={:?}", pc, parent);
    }
}

/// [cache-slots3] ZOVIA_DUMP_SLOTS3: slot kinds+base value AT ADD TIME.
/// "1" = default bases -208/-216/-224; or a comma list of bases (e.g.
/// "-296,-320"). Caller gates on trace_pc_in_range.
fn cache_slots3_dump(state: &State, cache_id: u32) {
    if let Ok(v) = std::env::var("ZOVIA_DUMP_SLOTS3") {
        let bases: Vec<i16> = if v == "1" {
            vec![-208, -216, -224]
        } else {
            v.split(',').filter_map(|s| s.trim().parse().ok()).collect()
        };
        for base in bases {
            let k: String = (base..base + 8)
                .map(|b| match state.frames.current().stack.get_slot_kind(b) {
                    Some(k) => format!("{:?}", k).chars().next().unwrap(),
                    None => '-',
                })
                .collect();
            let bv = state
                .frames
                .current()
                .stack
                .get_slot(base)
                .map(|s| format!("{:?}/p{}[{},{}]", s.reg_type, s.precise, s.bounds.min, s.bounds.max))
                .unwrap_or_else(|| "-".into());
            eprintln!(
                "[cache-slots3] pc={} cid={} base={} kinds={} val={}",
                state.pc, cache_id, base, k, bv
            );
        }
    }
}

/// [srange] ZOVIA_DUMP_STATE_RANGE=1: the cached state's faithful
/// (insn_idx, first, last) — comparable to kernel [ZK refine]
/// base_insn/base_first/base_last. state.first_insn_idx here is still
/// the CACHED (pre-reset) value; the caller's reset is for the
/// successor.
fn srange_trace(cache_id: u32, state: &State) {
    if std::env::var("ZOVIA_DUMP_STATE_RANGE").ok().as_deref() == Some("1") {
        eprintln!(
            "[srange] cid={} insn_idx={} first={} last={}",
            cache_id, state.pc, state.first_insn_idx, state.last_insn_idx
        );
    }
}

/// [jmpcnt] ADD (ZOVIA_DBG_JMPCNT=LO:HI): cache-add event within the
/// absolute insn_processed window.
fn jmpcnt_add_trace(env: &VerifierEnv, pc: usize) {
    if jmpcnt_in_range(env.insn_processed) {
        eprintln!(
            "[jmpcnt] ADD ip={} jp={} pc={}",
            env.insn_processed, env.jmps_processed, pc
        );
    }
}

/// [jmpcnt] JMP (ZOVIA_DBG_JMPCNT=LO:HI): name every jmp-class increment
/// in an absolute insn_processed window, to diff the jump STREAM against
/// the kernel's dj on the same window.
fn jmpcnt_jmp_trace(env: &VerifierEnv, pc: usize) {
    if jmpcnt_in_range(env.insn_processed) {
        eprintln!(
            "[jmpcnt] JMP ip={} jp={} pc={}",
            env.insn_processed, env.jmps_processed, pc
        );
    }
}

/// Per-PC visit counter (audit hook, ZOVIA_DUMP_VISITS=1). Bumped ONLY
/// on non-pruned expansions so the count reflects state expansions per
/// pc, comparable to the kernel verifier's per-insn visit count in the
/// log_level-2 trace.
fn dump_visits_bump(env: &mut VerifierEnv, pc: usize) {
    if std::env::var("ZOVIA_DUMP_VISITS").ok().as_deref() == Some("1") {
        *env.pc_visit_count.entry(pc).or_insert(0) += 1;
    }
}

/// [PRUNE-MISS] (ZOVIA_DUMP_PRUNE_MISSES, every log_interval insns):
/// shows WHICH pcs accumulate subsumption misses and WHY — pinpoints a
/// non-converging loop header and the reason its states won't merge.
fn prune_miss_dump(env: &VerifierEnv, worklist_len: usize, log_interval: usize) {
    if std::env::var("ZOVIA_DUMP_PRUNE_MISSES").is_ok()
        && env.insn_processed.is_multiple_of(log_interval)
    {
        use crate::analysis::machine::env::SubsumptionMissReason;
        let mut rows: Vec<(usize, [u64; 9], u64)> = env
            .subsumption_misses
            .iter()
            .map(|(&pc, &counts)| (pc, counts, counts.iter().sum()))
            .collect();
        rows.sort_by(|a, b| b.2.cmp(&a.2));
        eprintln!(
            "[PRUNE-MISS] insn={} worklist={} top miss pcs:",
            env.insn_processed,
            worklist_len
        );
        for (pc, counts, total) in rows.iter().take(8) {
            let breakdown: Vec<String> = SubsumptionMissReason::ALL
                .iter()
                .filter(|r| counts[r.idx()] > 0)
                .map(|r| format!("{}={}", r.label(), counts[r.idx()]))
                .collect();
            eprintln!("    pc={} misses={} [{}]", pc, total, breakdown.join(" "));
        }
    }
}

/// [BR] (trace-range): parent checkpoint's branches bump at a fork.
fn br_inc_trace(p: &State, pcid: u32, at: usize, n: usize) {
    if trace_pc_in_range(p.pc) {
        eprintln!("[BR] inc pc={} cid={} now={} (fork@{} n={})",
            p.pc, pcid, p.branches, at, n);
    }
}
