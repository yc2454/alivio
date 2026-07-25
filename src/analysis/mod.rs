use crate::analysis::machine::error::VerificationError;
// src/analysis.rs

pub mod flow;
pub mod machine;
pub mod transfer;
mod worklist;
use worklist::run_worklist;

use crate::analysis::machine::frame_stack::FrameLevel;
use crate::analysis::machine::reg::Reg;
use crate::ast::Program;
use crate::common::config::{DomainMode, VerifierConfig};
use crate::domains::dbm::Dbm;
use crate::domains::numeric::NumericDomain;
use crate::pcc::{program_hash, validate_certificate_for_program};
use log::{error, info};
use std::collections::HashMap;

use self::flow::{cfg, liveness, scc, subprog};
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
    // 1. Initialize Verifier Environment and control flow checks
    let mut env = VerifierEnv::new(
        ctx,
        prog,
        config.certificate.clone(),
        matches!(
            config.domain_mode,
            crate::common::config::DomainMode::Interval
        ),
        config.bcf_enabled,
    );
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

    if let Err(e) = subprog::check_stack_overflow(
        prog,
        env.ctx.prog_kind,
        config.enable_private_stack
            && match env.ctx.prog_kind {
                crate::ast::ProgramKind::StructOps => env.ctx.priv_stack_requested,
                _ => true,
            },
    ) {
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
        match crate::refinement::bundle::write_bundle(std::path::Path::new(path), &env.bcf_proofs) {
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
        let max_per_insn = env
            .explored_states
            .values()
            .map(|v| v.len())
            .max()
            .unwrap_or(0);
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
        matches!(
            config.domain_mode,
            crate::common::config::DomainMode::Interval
        ),
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
    if let Err(e) = subprog::check_stack_overflow(
        prog,
        env.ctx.prog_kind,
        config.enable_private_stack
            && match env.ctx.prog_kind {
                crate::ast::ProgramKind::StructOps => env.ctx.priv_stack_requested,
                _ => true,
            },
    ) {
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
        "kprobe"
            | "kretprobe"
            | "tracepoint"
            | "tp"
            | "raw_tracepoint"
            | "raw_tp"
            | "raw_tp.w"
            | "perf_event"
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
        let Some(map_def) = env.ctx.map_defs.get(map_idx) else {
            continue;
        };
        let Some(btf_id) = map_def.btf_val_type_id else {
            continue;
        };
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
