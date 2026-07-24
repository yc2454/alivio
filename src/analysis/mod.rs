use crate::analysis::machine::error::VerificationError;
// src/analysis.rs

pub mod flow;
pub mod machine;
pub mod transfer;

use crate::analysis::machine::frame_stack::FrameLevel;
use crate::analysis::machine::reg::Reg;
use crate::ast::{Instr, Program};
use crate::common::config::{DomainMode, VerifierConfig};
use crate::domains::dbm::Dbm;
use crate::domains::numeric::NumericDomain;
use crate::pcc::{
    apply_verified_refinements, check_proof, program_hash, validate_certificate_for_program,
};
use log::{debug, error, info};
use std::collections::{HashMap, VecDeque};

use self::flow::{cfg, liveness, merging, pruning, scc, subprog};
use self::machine::context::ExecContext;
use self::machine::env::VerifierEnv;
use self::machine::reg_types::RegType;
use self::machine::state::State;

/// Analysis results including both the DBM vector and the explored states.
pub struct AnalysisResult {
    pub dbms: Vec<Dbm>,
    pub explored_states: HashMap<usize, Vec<State>>,
    /// If analysis failed, the error is stored here. The explored_states are
    /// still populated with all states collected before the failure point.
    pub error: Option<VerificationError>,
}


/// ZOVIA_DBG_JMPCNT=LO:HI (diagnosis-only): absolute insn_processed window
/// for the [jmpcnt] jump-stream dump.
fn jmpcnt_in_range(ip: usize) -> bool {
    std::env::var("ZOVIA_DBG_JMPCNT")
        .ok()
        .and_then(|s| {
            let (lo, hi) = s.split_once(':')?;
            Some((lo.parse::<usize>().ok()?, hi.parse::<usize>().ok()?))
        })
        .is_some_and(|(lo, hi)| ip >= lo && ip <= hi)
}

pub fn analyze_program(
    ctx: &ExecContext,
    prog: &Program,
    entry_dbm: Dbm,
    config: &VerifierConfig,
) -> Result<Vec<Dbm>, VerificationError> {
    let r = analyze_program_full(ctx, prog, entry_dbm, config);
    if let Some(err) = r.error {
        Err(err)
    } else {
        Ok(r.dbms)
    }
}

/// Like `analyze_program`, but always returns explored states (even on failure).
/// Used by the PCC certificate generator which needs interval states at PCs
/// before the failure point.
pub fn analyze_program_full(
    ctx: &ExecContext,
    prog: &Program,
    entry_dbm: Dbm,
    config: &VerifierConfig,
) -> AnalysisResult {
    // ── Kernel retry-round mirror (ZOVIA_BCF_ROUNDS=1) ──
    // bpf_check semantics: each loader retry re-verifies FROM SCRATCH with
    // the grown bundle; children_unsafe marks and all exploration state
    // reset — only the bundle persists. Mirror: re-run the whole analysis,
    // carrying bcf_proofs (the bundle) + the covered natural-hash set.
    // Each round discharges covered rejects from the bundle and stops at
    // the first uncovered one (try_emit_path_unreachable_entry). Rounds
    // are finite: each adds ≥1 covered hash or completes. The 4096 cap is
    // a runaway backstop, far above any real object's entry count.
    let rounds_mode = config.bcf_enabled
        && std::env::var("ZOVIA_BCF_ROUNDS").ok().as_deref() == Some("1");
    let mut round: usize = 1;
    let mut covered: std::collections::HashSet<u64> = Default::default();
    let mut carried: Vec<crate::refinement::bundle::RefineEntry> = Vec::new();
    let (mut env, prune_count) = loop {
    // 1. Initialize Verifier Environment and control flow checks
    let mut env = VerifierEnv::new(
        ctx,
        prog,
        config.certificate.clone(),
        matches!(config.domain_mode, crate::common::config::DomainMode::Interval),
        config.bcf_enabled,
    );
    env.bcf_rounds_mode = rounds_mode;
    env.bcf_round_covered = covered.clone();
    env.bcf_proofs = std::mem::take(&mut carried);
    if let Some(ref cert) = env.certificate {
        let computed_hash = program_hash(prog);
        if cert.program_hash != computed_hash {
            info!(
                target: "app",
                "[PCC] Certificate program hash mismatch (cert={}, program={}); disabling certificate-aided refinement",
                cert.program_hash,
                computed_hash
            );
            env.certificate = None;
        } else if let Err(e) = validate_certificate_for_program(cert, prog) {
            info!(
                target: "app",
                "[PCC] Certificate validation failed ({}); disabling certificate-aided refinement",
                e
            );
            env.certificate = None;
        } else {
            let pcs: Vec<String> = cert
                .pc_annotations
                .iter()
                .map(|a| a.pc.to_string())
                .collect();
            info!(
                target: "app",
                "[PCC] Certificate accepted: v{}, hash={}, {} annotation(s) at PC(s): [{}]",
                cert.version,
                cert.program_hash,
                cert.pc_annotations.len(),
                pcs.join(", "),
            );
        }
    }

    if config.verbosity >= 1 {
        info!(target: "app", "[Analysis] Running Static Analysis Passes...");
        if config.skip_dbm_check {
            info!(target: "app", "[Analysis] DBM comparison disabled (--skip-dbm)");
        }
    }

    // Check subprograms and stack overflow
    if let Err(e) = subprog::check_subprogs(prog) {
        error!(target: "app", "[Analysis] CFG Error: {}", e);
        return AnalysisResult {
            dbms: vec![],
            explored_states: env.explored_states,
            error: Some(VerificationError::SubprogError { e }),
        };
    }

    if let Err(e) =
        subprog::check_stack_overflow(
            prog,
            env.ctx.prog_kind,
            config.enable_private_stack
                && match env.ctx.prog_kind {
                    crate::ast::ProgramKind::StructOps => env.ctx.priv_stack_requested,
                    _ => true,
                },
        )
    {
        error!(target: "app", "[Analysis] Stack Error: {}", e);
        return AnalysisResult {
            dbms: vec![],
            explored_states: env.explored_states,
            error: Some(VerificationError::SubprogError { e }),
        };
    }

    // Kernel `check_map_prog_compatibility` (verifier.c L19910): tracing
    // prog kinds (kprobe, tracepoint, raw_tp[_writable], perf_event)
    // cannot use maps whose value record carries bpf_spin_lock,
    // bpf_timer, bpf_list_head, or bpf_rb_root. Socket filter cannot
    // use bpf_spin_lock.
    if let Some(err) = check_map_prog_compatibility(&env) {
        error!(target: "app", "[Analysis] Map/prog incompatibility: {}", err.description());
        return AnalysisResult {
            dbms: vec![],
            explored_states: env.explored_states,
            error: Some(err),
        };
    }

    // Check CFG. This includes checking for unreachable code and marking prune points.
    if let Err(e) = cfg::check_cfg(prog, &mut env, config) {
        error!(target: "app", "[Analysis] CFG Error: {}", e);
        return AnalysisResult {
            dbms: vec![],
            explored_states: env.explored_states,
            error: Some(VerificationError::CfgError(e)),
        };
    }

    // Compute liveness information for all registers.
    liveness::compute_liveness(prog, &mut env);
    flow::live_stack::init(&mut env, prog);

    // Compute SCCs over the CFG. Annotates `insn_aux_data[pc].scc_id`
    // (1+ for multi-vertex SCCs / singletons-with-self-edge, 0
    // otherwise — kernel convention from `compute_scc`,
    // verifier.c v6.15 L25809). Read by `maybe_enter_scc` /
    // `maybe_exit_scc` / `add_scc_backedge` / `incomplete_read_marks`
    // to drive SCC-scoped backedge precision propagation.
    scc::compute_scc(prog, &mut env);

    // 2. Initialize Entry State based on domain mode
    let pcc_mode = config.certificate_output.is_some()
        || config.certificate_input.is_some()
        || config.certificate.is_some();

    let initial_domain = match config.domain_mode {
        DomainMode::Zone => {
            // Cloned (not moved): the retry-round loop re-enters here with
            // a fresh env per round.
            let mut dbm = entry_dbm.clone();
            if pcc_mode {
                dbm.enable_provenance();
            }
            NumericDomain::Zone(dbm)
        }
        DomainMode::Interval => NumericDomain::new_interval(),
    };
    let mut initial_state = State::new(initial_domain, 0);
    initial_state.types.set(Reg::R1, RegType::PtrToCtx);
    initial_state.types.set(
        Reg::R10,
        RegType::PtrToStack {
            frame_level: FrameLevel::MAIN,
        },
    );
    initial_state.domain.init_packet_anchors();
    if config.bcf_enabled {
        initial_state.bcf = Some(Box::new(crate::refinement::symbolic::SymbolicState::new()));
    }

    // freplace target inheritance: for `SEC("freplace/<target>")`, the
    // EXT program receives its declared args *directly* in R1..Rn (the
    // extension takes the place of a regular subprog call). Override
    // the default `R1 = PtrToCtx` from above with per-arg typing
    // populated by the runner via `BtfContext::resolve_func_args`. The
    // arg whose type matches the target's ctx struct (`__sk_buff`,
    // `xdp_md`, ...) gets `PtrToCtx`; other pointer args become
    // unknown trusted pointers; scalars become initialized
    // `ScalarValue`. Without this, multi-arg freplace functions like
    // `new_get_skb_ifindex(int val, struct __sk_buff *skb, int var)`
    // hit `R2 !read_ok` at the first `If R2, ...` because R2 was
    // never typed at entry.
    if let Some(args) = ctx.freplace_arg_types.as_ref() {
        use crate::analysis::machine::context::EntryArg;
        use crate::analysis::machine::reg_types::PtrFlags;
        // Reset R1 (default PtrToCtx) before re-typing per declared arg.
        initial_state.types.set(Reg::R1, RegType::NotInit);
        let arg_regs = [Reg::R1, Reg::R2, Reg::R3, Reg::R4, Reg::R5];
        let ctx_struct_for_kind = |kind: ProgramKind| -> Option<&'static str> {
            match kind {
                ProgramKind::SchedCls
                | ProgramKind::SchedAct
                | ProgramKind::SocketFilter
                | ProgramKind::SkSkb
                | ProgramKind::CgroupSkb
                | ProgramKind::FlowDissector => Some("__sk_buff"),
                ProgramKind::Xdp => Some("xdp_md"),
                ProgramKind::SockOps => Some("bpf_sock_ops"),
                ProgramKind::CgroupSockAddr => Some("bpf_sock_addr"),
                ProgramKind::CgroupSockopt => Some("bpf_sockopt"),
                ProgramKind::CgroupSock => Some("bpf_sock"),
                ProgramKind::SkMsg => Some("sk_msg_md"),
                ProgramKind::SkLookup => Some("bpf_sk_lookup"),
                ProgramKind::SkReuseport => Some("sk_reuseport_md"),
                _ => None,
            }
        };
        let ctx_struct = ctx_struct_for_kind(ctx.prog_kind);
        for (i, arg) in args.iter().enumerate().take(arg_regs.len()) {
            let reg = arg_regs[i];
            let ty = match arg {
                EntryArg::Scalar => RegType::ScalarValue,
                EntryArg::TrustedPtrBtfId { type_name, .. } => {
                    if Some(*type_name) == ctx_struct {
                        RegType::PtrToCtx
                    } else {
                        RegType::PtrToBtfId {
                            type_name,
                            flags: PtrFlags::TRUSTED,
                            ref_id: None,
                        }
                    }
                }
                EntryArg::BoundedScalar { .. } => RegType::ScalarValue,
                // freplace doesn't currently emit this; struct_ops uses
                // the BPF_PROG ctx-array idiom, not this R1..Rn path.
                // Map for completeness so the match stays exhaustive.
                EntryArg::TrustedRefcountedTask { ref_id } => RegType::PtrToTask {
                    ref_id: Some(*ref_id),
                },
            };
            initial_state.types.set(reg, ty);
        }
    }

    // Non-sleepable tracing programs (kprobe, tracepoint, raw_tp,
    // perf_event) run with an implicit RCU read-side critical section
    // held by the kernel before invoking the BPF prog. The kernel
    // verifier records this via `env->cur_state->active_rcu_lock` set
    // at program init for those types (verifier.c v6.15 ~L5803 comment
    // "non-sleepable programs and sleepable programs with explicit
    // bpf_rcu_read_lock()"). KF_RCU_PROTECTED iters initialized in
    // such a prog see in_rcu_cs at `_new` time and get MEM_RCU (trusted)
    // slot status. Sleepable variants (`fentry.s`, `iter.s`, `lsm.s`)
    // do NOT auto-hold; they must call `bpf_rcu_read_lock` explicitly.
    use crate::ast::ProgramKind;
    let auto_rcu = matches!(
        env.ctx.prog_kind,
        ProgramKind::Kprobe
            | ProgramKind::Tracepoint
            | ProgramKind::RawTracepoint
            | ProgramKind::RawTracepointWritable
            | ProgramKind::PerfEvent
    );
    if auto_rcu {
        initial_state.rcu_read_lock();
        initial_state.implicit_rcu_at_entry = true;
    }

    // struct_ops subprogs receive their args via the BPF_PROG
    // macro's ctx-array idiom — R1 stays as PtrToCtx (a `u64 *ctx`), and
    // each declared arg is unpacked at runtime via `*(u64 *)(ctx + 8*i)`.
    // The per-arg typing happens inside `validate_ctx_access` (see
    // src/common/ctx_model.rs), which consumes `ctx.entry_args` to type
    // the loaded values. No R1..Rn override is needed here.
    //
    // For struct_ops members declared with `__ref` parameters (the kmod
    // marks the arg as ref-acquired at entry — e.g.
    // bpf_testmod_ops.test_refcounted's `task__ref`), seed an outstanding
    // reference per refcounted arg. The kernel reports "Unreleased
    // reference id=N alloc_insn=0" if the program exits without releasing
    // it; here, `state.has_unreleased_refs()` at exit fires
    // `UnreleasedReference`. Programs that load the arg from ctx and call
    // the matching release kfunc (e.g. `bpf_task_release`) drop the ref
    // through the existing release path. The arg-position-to-ref-id
    // binding isn't propagated to the loaded register here; that would be
    // needed to type the loaded ctx slot as a refcounted PtrToTask, which
    // we leave for a follow-up if a corresponding success-case test
    // surfaces as a false-reject.
    // Seed outstanding refs for entry-acquired struct_ops args. Each
    // `EntryArg::TrustedRefcountedTask` carries a pre-allocated ref_id
    // (alloc'd in `struct_ops_entry_args` so the per-arg load site can
    // type the load as `PtrToTask{ref_id: Some(rid)}`); insert each
    // into active_refs so the matching `bpf_task_release(task)`
    // release-path balances out before exit.
    if let Some(args) = ctx.entry_args.as_ref() {
        use crate::analysis::machine::context::EntryArg;
        for arg in args {
            if let EntryArg::TrustedRefcountedTask { ref_id } = arg {
                initial_state.active_refs.insert(*ref_id);
            }
        }
    }

    // 3. & 4. Run worklist analysis
    let prune_count = run_worklist(&mut env, prog, config, initial_state);

    // Retry-round driver: an uncovered reject ended this round — bank its
    // hash + the grown bundle, restart from scratch (kernel loader retry).
    if rounds_mode && env.bcf_round_stop && round < 4096 {
        // No-progress guard: the round-ending hash must be NEW. A repeat
        // means the covered check and the stop site disagree on this
        // reject's hash (a bug) — surface it and stop looping rather
        // than spinning to the backstop.
        if let Some(h) = env.bcf_round_new {
            if !covered.insert(h) {
                eprintln!(
                    "[bcf-rounds] LIVELOCK: round {} re-emitted covered hash 0x{:016x} — stopping rounds ({} entries)",
                    round, h, env.bcf_proofs.len()
                );
                break (env, prune_count);
            }
        }
        carried = std::mem::take(&mut env.bcf_proofs);
        eprintln!(
            "[bcf-rounds] round {} ended: uncovered 0x{:016x} at insn_processed={}; bundle {} entries — restarting",
            round,
            env.bcf_round_new.unwrap_or(0),
            env.insn_processed,
            carried.len()
        );
        round += 1;
        continue;
    }
    if rounds_mode {
        eprintln!(
            "[bcf-rounds] converged after {} round(s): {} entries",
            round,
            env.bcf_proofs.len()
        );
    }
    break (env, prune_count);
    }; // end retry-round loop

    // Audit hook: dump per-PC subsumption-miss histogram.
    // Gated on `ZOVIA_DUMP_PRUNING=1` so it stays out of the sweep
    // path entirely. Pinpoints the dominant subsumption-miss reason.
    if std::env::var("ZOVIA_DUMP_PRUNING").ok().as_deref() == Some("1") {
        crate::analysis::flow::diag::dump_subsumption_miss_histogram(&env);
    }
    if std::env::var("ZOVIA_DUMP_VISITS").ok().as_deref() == Some("1") {
        crate::analysis::flow::diag::dump_pc_visit_count(&env);
    }
    // Cache-topology probe: when ZOVIA_DUMP_CACHE_AT_PC=N is set, dump
    // the count and per-entry reg/range/type snapshot for every cached
    // state at PC=N. Cheap one-shot diagnostic, gate-off by default.
    if let Ok(pcs) = std::env::var("ZOVIA_DUMP_CACHE_AT_PC") {
        for pc_s in pcs.split(',') {
            if let Ok(pc) = pc_s.trim().parse::<usize>() {
                let entries = env.explored_states.get(&pc);
                let n = entries.map(|v| v.len()).unwrap_or(0);
                eprintln!("[cache-probe] pc={} cached_states={}", pc, n);
                if let Some(vec) = entries {
                    for (i, st) in vec.iter().enumerate() {
                        eprintln!(
                            "  [{}] cache_id={:?} parent_cache_id={:?} history_idx={:?}",
                            i, st.cache_id, st.parent_cache_id, st.history_idx,
                        );
                        eprintln!("      Types:  {}", st.types.reg_types_str());
                        eprintln!("      Ranges: {}", st.reg_ranges_str());
                    }
                }
            }
        }
    }

    // --- BCF bundle emit ---
    // Each entry in bcf_proofs is an INDEPENDENT cvc5-proven UNSAT goal
    // for a specific rejection site discharged earlier in this analysis.
    // Dropping them when env.error is set (i.e. zovia hit a later
    // precision bug) silently loses real, verified proofs that would
    // make the kernel-side BCF discharge HIT. The bundle's downstream
    // consumer (kernel discharge in test_loader) treats each entry as
    // standalone, so partial output is safe and strictly better than
    // empty.
    if let Some(path) = config.bcf_bundle_out.as_deref()
        && !env.bcf_proofs.is_empty()
    {
        match crate::refinement::bundle::write_bundle(
            std::path::Path::new(path),
            &env.bcf_proofs,
        ) {
            Ok(bytes) => info!(
                target: "app",
                "[bcf] wrote bundle: {} ({} entries, {} bytes){}",
                path,
                env.bcf_proofs.len(),
                bytes,
                if env.error.is_some() { " (analysis failed; partial)" } else { "" },
            ),
            Err(e) => error!(target: "app", "[bcf] bundle write failed ({}): {}", path, e),
        }
    }

    // --- FINAL REPORT ---
    // Pruning-quality metric (kernel `[ZK summary]` analog): max states
    // cached at any single pc + total cached + cap evictions. Pegging the
    // cap (with evictions > 0) indicates a pruning-effectiveness gap.
    if config.verbosity >= 1 {
        let max_per_insn = env.explored_states.values().map(|v| v.len()).max().unwrap_or(0);
        let total_states: usize = env.explored_states.values().map(|v| v.len()).sum();
        let n_at_cap = env
            .explored_states
            .values()
            .filter(|v| config.max_states_per_pc > 0 && v.len() >= config.max_states_per_pc)
            .count();
        info!(target: "app",
            "[Analysis] pruning-quality: max_per_insn={} total_states={} pcs_at_cap={} cap_evictions={}",
            max_per_insn, total_states, n_at_cap, env.cache_evictions);
    }

    let analysis_error = if let Some(err) = &env.error {
        info!(target: "app", "\n[Verifier] FAILURE: {}", err.description());
        if config.verbosity >= 1 {
            info!(target: "app", "[Analysis] Finished. Total Steps: {}, Pruned: {}", env.insn_processed, prune_count);
        }
        Some(err.clone())
    } else {
        info!(target: "app", "\n[Verifier] Success! Verified {} instructions (pruned {} states).",
                 env.insn_processed, prune_count);
        if config.verbosity >= 1 {
            info!(target: "app", "[Analysis] Finished. Total Steps: {}, Pruned: {}", env.insn_processed, prune_count);
        }
        None
    };

    // 5. Return Results
    // NOTE: For backwards compatibility, dbms returns Vec<Dbm>.
    // In Interval mode, we return empty Dbms since there's no underlying DBM.
    let n = prog.instrs.len();
    let mut results = Vec::with_capacity(n);

    for i in 0..n {
        if let Some(states) = env.explored_states.get(&i) {
            if !states.is_empty() {
                // Extract Dbm from Zone domain, or return empty for Interval
                match &states[0].domain {
                    NumericDomain::Zone(dbm) => results.push(dbm.clone()),
                    NumericDomain::Interval(_) => results.push(Dbm::new()),
                }
            } else {
                results.push(Dbm::new());
            }
        } else {
            results.push(Dbm::new());
        }
    }

    AnalysisResult {
        dbms: results,
        explored_states: env.explored_states,
        error: analysis_error,
    }
}

/// Verify the body of an `__exception_cb` callback subprog.
///
/// The cb is unreachable from main's CFG (registered via BTF decl_tag,
/// not called) so the main analysis pass never visits it. The kernel
/// handles this by force-marking the cb subprog as `called` in
/// `do_check_subprogs`, which routes it through the normal global-subprog
/// verification path. We don't have an equivalent global-subprog loop, so
/// this function plays that role: build a fresh env, seed the cb's entry
/// state (R1 = unknown SCALAR cookie, R10 = stack pointer), and run the
/// worklist.
///
/// While the env's `analyzing_exception_cb` flag is set, `transfer_exit`
/// applies the kernel's exception-cb-specific exit rule — for fentry/
/// fexit programs, R0 must be in [0, 0] at cb exit (mirrors the kernel
/// applying the main-program exit rule via `in_exception_callback_fn`).
///
/// Returns `Some(error)` if verification of the cb body fails; `None` on
/// success. Caller is expected to surface the error as the parent
/// program's failure verdict.
pub fn analyze_exception_cb(
    ctx: &ExecContext,
    prog: &Program,
    entry_dbm: Dbm,
    config: &VerifierConfig,
    cb_entry_pc: usize,
) -> Option<VerificationError> {
    let mut env = VerifierEnv::new(
        ctx,
        prog,
        None,
        matches!(config.domain_mode, crate::common::config::DomainMode::Interval),
        config.bcf_enabled,
    );
    env.analyzing_exception_cb = true;

    // Reuse program-level structural checks. These are idempotent — main
    // analysis already ran them, but `env` is fresh here so we need its
    // insn_aux_data populated (prune points, liveness) before the
    // worklist body can run safely.
    if let Err(e) = subprog::check_subprogs(prog) {
        return Some(VerificationError::SubprogError { e });
    }
    if let Err(e) =
        subprog::check_stack_overflow(
            prog,
            env.ctx.prog_kind,
            config.enable_private_stack
                && match env.ctx.prog_kind {
                    crate::ast::ProgramKind::StructOps => env.ctx.priv_stack_requested,
                    _ => true,
                },
        )
    {
        return Some(VerificationError::SubprogError { e });
    }
    if let Err(e) = cfg::check_cfg(prog, &mut env, config) {
        return Some(VerificationError::CfgError(e));
    }
    liveness::compute_liveness(prog, &mut env);
    flow::live_stack::init(&mut env, prog);

    // Seed initial state at the cb's entry PC. The kernel's
    // `btf_prepare_func_args` produces ARG_ANYTHING for the cookie arg;
    // we mirror that with R1 = SCALAR with no interval bounds.
    let initial_domain = match config.domain_mode {
        DomainMode::Zone => NumericDomain::Zone(entry_dbm),
        DomainMode::Interval => NumericDomain::new_interval(),
    };
    let mut initial_state = State::new(initial_domain, cb_entry_pc);
    initial_state.types.set(Reg::R1, RegType::ScalarValue);
    initial_state.types.set(
        Reg::R10,
        RegType::PtrToStack {
            frame_level: FrameLevel::MAIN,
        },
    );
    initial_state.domain.init_packet_anchors();

    let _ = run_worklist(&mut env, prog, config, initial_state);

    env.error
}

/// Kernel `check_map_prog_compatibility` (verifier.c L19910–L19950):
/// reject the program at load time if any map it references has a
/// record-field that is incompatible with the program type.
///
/// - Tracing prog kinds (kprobe, tracepoint, raw_tp, raw_tp_writable,
///   perf_event) cannot use maps with `bpf_spin_lock`,
///   `bpf_res_spin_lock`, `bpf_timer`, `bpf_list_head`, or `bpf_rb_root`
///   special fields in their value record.
/// - Socket filter cannot use `bpf_spin_lock` / `bpf_res_spin_lock`.
///
/// Maps actually used by this program are derived from `pc_to_reloc`
/// (RelocKind::MapPtr / MapValue), so other progs in the same ELF that
/// reference different maps are unaffected.

/// Trace helper for ZOVIA_TRACE_PC_RANGE=LO:HI focused tracing.
/// Returns true if `pc` is within the configured trace range.
pub(crate) fn trace_pc_in_range(pc: usize) -> bool {
    static RANGE: std::sync::OnceLock<Option<(usize, usize)>> = std::sync::OnceLock::new();
    let range = RANGE.get_or_init(|| {
        std::env::var("ZOVIA_TRACE_PC_RANGE").ok().and_then(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 2 {
                Some((parts[0].trim().parse().ok()?, parts[1].trim().parse().ok()?))
            } else {
                None
            }
        })
    });
    if let Some((lo, hi)) = range {
        *lo <= pc && pc <= *hi
    } else {
        false
    }
}

/// ZOVIA_DBG_PUSHDUMP=<pc>: dump R5 + stack bytes -216..-209 (spi26) at every
/// worklist PUSH of a successor whose resume pc == <pc> and every POP of a
/// state at that pc. The kernel's pending states are immutable full copies
/// (push_stack → copy_verifier_state); this instrument shows whether zovia's
/// pushed snapshot mutates between push and pop.
pub(crate) fn pushdump_pc() -> Option<usize> {
    static PC: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *PC.get_or_init(|| {
        std::env::var("ZOVIA_DBG_PUSHDUMP")
            .ok()
            .and_then(|s| s.trim().parse().ok())
    })
}

fn pushdump(side: &str, state: &crate::analysis::machine::state::State) {
    use crate::analysis::machine::reg::Reg;
    let mut slots = String::new();
    for off in -216i16..=-209 {
        match state.frames.current().stack.get_slot(off) {
            Some(s) => slots.push_str(&format!(" {}:{:?}/{:?}", off, s.kind, s.reg_type)),
            None => slots.push_str(&format!(" {}:-", off)),
        }
    }
    let (r5lo, r5hi) = state.domain.get_interval(Reg::R5);
    eprintln!(
        "[pushdump] {} pc={} parent={:?} jd={} id={} r5={:?}[{}..{}] spi26={}",
        side,
        state.pc,
        state.parent_cache_id,
        state.path_jmp_count,
        state.path_insn_count,
        state.types.get(Reg::R5),
        r5lo,
        r5hi,
        slots
    );
}

fn check_map_prog_compatibility(env: &VerifierEnv) -> Option<VerificationError> {
    use crate::ast::ProgramKind;
    use crate::parsing::btf::SpecialFieldKind;
    use crate::parsing::elf::RelocKind;
    use std::collections::HashSet;

    let kind = env.ctx.prog_kind;
    // `?raw_tp/`, `?tp/`, `?kprobe`, `?perf_event` SECs are intentionally
    // parsed as ProgramKind::Unknown by `from_section` (preserves the
    // current-Unknown kfunc-rejection contract for `?fentry/` / `?fexit/`
    // siblings). The runner stashes the leading SEC token in
    // `attach_flavor` regardless, so we can recover the tracing nature
    // here without altering the global SEC parser.
    let flavor = env.ctx.attach_flavor.as_deref().unwrap_or("");
    let flavor_is_tracing = matches!(
        flavor,
        "kprobe" | "kretprobe" | "tracepoint" | "tp" | "raw_tracepoint"
            | "raw_tp" | "raw_tp.w" | "perf_event"
    );
    let is_tracing = flavor_is_tracing
        || matches!(
            kind,
            ProgramKind::Kprobe
                | ProgramKind::Tracepoint
                | ProgramKind::RawTracepoint
                | ProgramKind::RawTracepointWritable
                | ProgramKind::PerfEvent
        );
    let is_socket_filter = matches!(kind, ProgramKind::SocketFilter) || flavor == "socket";
    if !is_tracing && !is_socket_filter {
        return None;
    }

    let mut used: HashSet<usize> = HashSet::new();
    for reloc in env.ctx.pc_to_reloc.values() {
        if matches!(reloc.kind, RelocKind::MapPtr | RelocKind::MapValue) {
            used.insert(reloc.map_idx);
        }
    }

    for map_idx in used {
        let Some(map_def) = env.ctx.map_defs.get(map_idx) else { continue };
        let Some(btf_id) = map_def.btf_val_type_id else { continue };
        for field in env.ctx.btf.find_special_fields(btf_id) {
            let (rejects_tracing, rejects_socket_filter, name): (bool, bool, &'static str) =
                match field.kind {
                    SpecialFieldKind::SpinLock => (true, true, "bpf_spin_lock"),
                    SpecialFieldKind::ResSpinLock => (true, true, "bpf_res_spin_lock"),
                    SpecialFieldKind::Timer => (true, false, "bpf_timer"),
                    SpecialFieldKind::ListHead => (true, false, "bpf_list_head"),
                    SpecialFieldKind::RbRoot => (true, false, "bpf_rb_root"),
                    _ => continue,
                };
            if (is_tracing && rejects_tracing) || (is_socket_filter && rejects_socket_filter) {
                return Some(VerificationError::MapProgIncompat {
                    map_name: map_def.name.clone(),
                    field: name,
                    kind,
                });
            }
        }
    }
    None
}

/// Worklist abstract-interpretation loop. Shared between the main-program
/// analysis (`analyze_program_full`) and the exception-cb body pass
/// (`analyze_exception_cb`). Returns the number of states pruned.
fn run_worklist(
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

    // One-shot dump of AST instr at trace PCs (WT diagnostic).
    if std::env::var("ZOVIA_DUMP_AST").is_ok() {
        for pc in 0..prog.instrs.len() {
            if trace_pc_in_range(pc) {
                eprintln!("[AST] pc={} instr={:?}", pc, prog.instrs[pc]);
            }
        }
    }
    // Dump jmp_point + prune_point flags + predecessor instr kind (to
    // identify which mark site fired). WT diagnostic.
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

    // [zpop] (kernel [ZK pop] mirror): a zovia pop is kernel-comparable
    // iff the PREVIOUS iteration died (prune-hit / zero successors /
    // fetch-fail) — otherwise it's the continuation pop the kernel never
    // makes. First pop = the initial state (no kernel analog).
    let zpop_on = std::env::var("ZOVIA_DBG_PUSHLOG").ok().as_deref() == Some("1");
    let mut prev_died = false;
    while let Some(mut state) = worklist.pop_back() {
        // Retry-round mirror: the first uncovered reject ended this round
        // (kernel: the load fails at mark_bcf_requested; nothing after it
        // runs). Drain and return; the driver restarts from scratch.
        if env.bcf_round_stop {
            break;
        }
        if zpop_on && prev_died {
            eprintln!(
                "[zpop] resume={} ip={} jp={}",
                state.pc, env.insn_processed, env.jmps_processed
            );
        }
        prev_died = true;
        if trace_pc_in_range(state.pc) {
            use crate::analysis::machine::reg::Reg;
            let (r2lo, r2hi) = state.domain.get_interval(Reg::R2);
            // R9's type at pop (pairs with the [WL_PUSH] R9 print; a type
            // flip between them = the pushed snapshot mutated or the pop
            // pairing is wrong).
            eprintln!(
                "[WL_POP] pc={} parent_cache_id={:?} R2=[{}..{}] R9={:?}",
                state.pc, state.parent_cache_id, r2lo, r2hi,
                state.types.get(Reg::R9),
            );
        }
        if pushdump_pc() == Some(state.pc) {
            pushdump("POP", &state);
        }
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
            if std::env::var("ZOVIA_TRACE_JMP_HIST_BUMP").ok().as_deref() == Some("1")
                && trace_pc_in_range(state.pc)
            {
                eprintln!(
                    "[JH_BUMP] pc={} new_cnt={} parent_cache={:?}",
                    state.pc, state.jmp_history_cnt, state.parent_cache_id
                );
            }
            // One-shot lineage dump: when this state first hits the
            // target (pc, new_cnt) combo, walk history backward and
            // print every jmp_point PC the lineage visited. WT
            // diagnostic.
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
        if diag_hit {
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

        if diag_hit {
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

        // Audit probe: dump compact state at the requested PC(s). Gated on
        // `ZOVIA_DUMP_STATES_AT_PC=N[,M,...]`. Used to inspect why many
        // "equivalent" states accumulate at a single pc (path-explosion
        // diagnostic). Comma-separated list, e.g.
        // `ZOVIA_DUMP_STATES_AT_PC=1587,1856`. Each line includes R0..R9 +
        // their precision marks + a few key stack slot scalars so we can
        // compare what changes across visits to a loop head.
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

        // Kernel do_check: `++env->insn_processed` (verifier.c:21172)
        // runs BEFORE is_state_visited (21189) — EVERY arrival counts,
        // including ones that then prune.
        env.insn_processed += 1;
        // [INSN] corridor execution-order probe (kernel [ZK insn]
        // mirror at the same pre-check position, verifier.c:21181).
        if state.pc >= 185 && state.pc <= 200 && trace_pc_in_range(state.pc) {
            eprintln!("[INSN] ip={} pc={}", env.insn_processed, state.pc);
        }
        // ZOVIA_DBG_REGVAL=RN:pc1,pc2,... — dump a register's tracked
        // value pre-execution at the listed pcs.
        {
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
                    state.pc, env.insn_processed, reg, lo, hi, ulo, uhi,
                    state.get_tnum(*reg), state.types.get(*reg),
                    state.is_reg_precise(*reg)
                );
            }
        }

        // A.b PRUNING CHECK
        if pruning::should_prune(env, &mut state, config, prog) {
            if diag_hit {
                eprintln!("[DIAG PRUNE] pc={} pruned=true", state.pc);
            }
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
            if std::env::var("ZOVIA_DBG_CDB").ok().as_deref() == Some("1") {
                eprintln!("[dbg-cdb] PRUNE-death pc={} parent={:?}", state.pc, state.parent_cache_id);
            }
            crate::analysis::flow::scc::complete_dfs_branch(env, state.parent_cache_id);
            continue;
        }
        if diag_hit {
            eprintln!("[DIAG PRUNE] pc={} pruned=false (recorded)", state.pc);
        }

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
                // ZOVIA_DUMP_SLOTS3: slot kinds+base value AT ADD TIME.
                // "1" = default bases -208/-216/-224; or a comma
                // list of bases (e.g. "-296,-320").
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
            // ZOVIA_DUMP_STATE_RANGE: the cached state's faithful
            // (insn_idx, first, last) — comparable to kernel [ZK refine]
            // base_insn/base_first/base_last. state.first_insn_idx here is
            // still the CACHED (pre-reset) value; the reset below is for
            // the successor.
            if std::env::var("ZOVIA_DUMP_STATE_RANGE").ok().as_deref() == Some("1") {
                eprintln!(
                    "[srange] cid={} insn_idx={} first={} last={}",
                    cache_id, state.pc, state.first_insn_idx, state.last_insn_idx
                );
            }
            state.parent_cache_id = Some(cache_id);
            // Kernel `cur->first_insn_idx = insn_idx` (verifier.c:20529): the
            // continuing state begins a NEW segment at this checkpoint pc. The
            // cached clone above keeps the PRIOR segment start (copy_verifier_state
            // :2073). last_insn_idx is unchanged (it's the arrival pc, set on
            // this state at successor-creation).
            state.first_insn_idx = state.pc;
            if jmpcnt_in_range(env.insn_processed) {
                eprintln!(
                    "[jmpcnt] ADD ip={} jp={} pc={}",
                    env.insn_processed, env.jmps_processed, state.pc
                );
            }
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
        // Per-PC visit counter (audit hook, ZOVIA_DUMP_VISITS=1). Bumped
        // ONLY on non-pruned expansions so the count reflects state
        // expansions per pc, comparable to the kernel verifier's
        // per-insn visit count in the log_level-2 trace.
        if std::env::var("ZOVIA_DUMP_VISITS").ok().as_deref() == Some("1") {
            *env.pc_visit_count.entry(state.pc).or_insert(0) += 1;
        }
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
        // Shows WHICH pcs accumulate subsumption misses and WHY — pinpoints
        // a non-converging loop header and the reason its states won't merge.
        if std::env::var("ZOVIA_DUMP_PRUNE_MISSES").is_ok()
            && env.insn_processed.is_multiple_of(config.log_interval)
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
                worklist.len()
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
            // ZOVIA_DBG_JMPCNT=LO:HI: name every jmp-class increment in an
            // absolute insn_processed window, to diff the jump STREAM
            // against the kernel's dj on the same window.
            if jmpcnt_in_range(env.insn_processed) {
                eprintln!(
                    "[jmpcnt] JMP ip={} jp={} pc={}",
                    env.insn_processed, env.jmps_processed, state.pc
                );
            }
        }
        // Kernel do_check: `bpf_reset_stack_write_marks(env, insn_idx)`
        // before do_check_insn, `bpf_commit_stack_write_marks` after.
        // The callchain snapshot also serves the path-death
        // `bpf_update_live_stack` below (state is moved into transfer).
        let ls_key = flow::live_stack::callchain_of(&state);
        flow::live_stack::reset_stack_write_marks(env, &state, state.pc);
        let mut successors = transfer::transfer(env, state, instr);
        flow::live_stack::commit_stack_write_marks(env);
        if diag_hit {
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
                diag_cur_pc,
                succ_dump.join(", ")
            );
        }
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
                if trace_pc_in_range(p.pc) {
                    eprintln!("[BR] inc pc={} cid={} now={} (fork@{} n={})",
                        p.pc, pcid, p.branches, cur_insn_pc, succ_count);
                }
            }
        }
        if succ_count == 0 {
            // No successors (e.g. Exit): this DFS path terminated.
            // Kernel process_bpf_exit: propagate live-stack marks first.
            flow::live_stack::update_live_stack(env, &ls_key);
            // Decrement parent chain analogously to the prune-hit path.
            if std::env::var("ZOVIA_DBG_CDB").ok().as_deref() == Some("1") {
                eprintln!("[dbg-cdb] EXIT-death pc={} parent={:?}", cur_insn_pc, cur_parent_cache_id);
            }
            crate::analysis::flow::scc::complete_dfs_branch(env, cur_parent_cache_id);
        }
        // ZOVIA_DBG_PUSHLOG=1: kernel-comparable push stream. The kernel's
        // push_stack fires once per NON-continued arm; zovia pushes every
        // successor (the LAST-pushed is the continuation, popped right
        // back). Print all but the final push of this fork ([ZK push]
        // analog: at=branch pc, resume=arm pc).
        let pushlog = std::env::var("ZOVIA_DBG_PUSHLOG").ok().as_deref() == Some("1");
        let n_push = loop_back.len() + other.len();
        // A continuation gets pushed iff n_push>0 — the next pop is then
        // NOT kernel-comparable.
        prev_died = n_push == 0;
        let mut push_i = 0usize;
        let mut plog = |pc: usize, at: usize, i: usize| {
            if pushlog && i + 1 < n_push {
                eprintln!(
                    "[zpush] at={} resume={} ip={} jp={}",
                    at, pc, env.insn_processed, env.jmps_processed
                );
            }
        };
        for succ in loop_back {
            if pushdump_pc() == Some(succ.pc) {
                pushdump("PUSH-lb", &succ);
            }
            plog(succ.pc, cur_insn_pc, push_i);
            push_i += 1;
            worklist.push_back(succ);
        }
        for succ in other.into_iter().rev() {
            if trace_pc_in_range(succ.pc) {
                use crate::analysis::machine::reg::Reg;
                eprintln!(
                    "[WL_PUSH] pc={} parent_cache_id={:?} (worklist_len_before={}) ip={} R9={:?}",
                    succ.pc, succ.parent_cache_id, worklist.len(),
                    env.insn_processed, succ.types.get(Reg::R9),
                );
            }
            if pushdump_pc() == Some(succ.pc) {
                pushdump("PUSH", &succ);
            }
            plog(succ.pc, cur_insn_pc, push_i);
            push_i += 1;
            worklist.push_back(succ);
        }
    }

    prune_count
}
