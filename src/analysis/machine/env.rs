use crate::analysis::machine::error::VerificationError;
use crate::analysis::machine::history::History;
// src/analysis/env.rs
use crate::analysis::machine::context::ExecContext;
use crate::analysis::machine::reg::Reg;
use crate::analysis::machine::state::State;
use crate::ast::Program;
use crate::pcc::ProgramCertificate;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Default, Debug)]
pub struct InsnAuxData {
    pub prune_point: bool,
    /// Kernel `insn_aux_data[i].jmp_point` (verifier.c v6.15 L4148).
    /// Strict subset of `prune_point`: marked at conditional-branch
    /// TARGETS (kernel push_insn BRANCH edge L18319) and POST-CALL
    /// FALLTHROUGH (kernel L18361). Read by `is_jmp_point` to gate
    /// `push_jmp_history` calls — kernel's `cur->jmp_history_cnt`
    /// counts branch decisions made on the current state's lineage,
    /// and the long-history safety valve in `add_new_state` uses
    /// `jmp_history_cnt > 40` (verifier.c v6.15 L20256) — NOT the raw
    /// insn delta.
    pub jmp_point: bool,
    pub seen: bool,
    /// Registers that are live (read before next write) at this PC.
    pub live_regs: HashSet<Reg>,
    /// Stack slot offsets (byte-granularity, relative to R10) that are live at this PC.
    pub live_slots: HashSet<i16>,
    /// this pc is a "force checkpoint" — kernel keeps cached
    /// states here longer (eviction threshold n=64 vs default n=3) to
    /// preserve iter/may_goto/cb-call convergence checkpoints. Mirrors
    /// kernel `mark_force_checkpoint` (verifier.c v6.15 L17085) which
    /// flags iter_next kfunc calls, sync-callback-calling helpers
    /// (bpf_loop / bpf_for_each_map_elem / bpf_user_ringbuf_drain),
    /// and may_goto instructions.
    pub force_checkpoint: bool,
    /// Kernel `insn_aux_data[i].scc` (verifier.c v6.15 ~L25775). SCC
    /// identifier (1+) assigned by Tarjan's algorithm in compute_scc;
    /// 0 means the insn is a singleton SCC without self-edge
    /// (kernel convention — "not in SCC" for the purposes of
    /// `bpf_scc_callchain`). Read by maybe_enter_scc /
    /// maybe_exit_scc / add_scc_backedge / incomplete_read_marks
    /// to identify SCC membership for `propagate_backedges`.
    pub scc_id: u32,
}

/// per-cached-state hit/miss counters for explored-states
/// eviction. Mirrors `bpf_verifier_state_list.{hit_cnt,miss_cnt}`
/// (verifier.c v6.15 ~L19180-L19233). Indexed identically with
/// `explored_states[pc]`: when an entry is evicted, both vectors drop
/// the same index.
#[derive(Clone, Default, Debug)]
pub struct StateMetrics {
    pub hit_cnt: u32,
    pub miss_cnt: u32,
}

/// Per-PC histogram of *why* a `state_subsumed_by` check failed. Used
/// by the end-of-analysis dump to figure out which subsumption sub-check
/// is the dominant miss reason on timeout-prone tests — informs whether
/// the next investment should be liveness (Stack), precision propagation
/// (Types/Tnum/Domain/ScalarIdLinks), or widening breadth.
///
/// One entry is recorded per miss against the first sub-check that
/// rejected; later sub-checks short-circuit so we don't see them. That's
/// the right granularity for "which mechanism would unblock the most
/// states."
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubsumptionMissReason {
    Types,
    Domain,
    Stack,
    Tnum,
    ScalarIdLinks,
    ActiveLock,
    GotoBudget,
    ActiveRefs,
    CallerFrame,
}

/// Coarse counters describing how `should_prune` decisions broke down.
/// Lets the audit dump distinguish:
///   - "we didn't even try to prune" (not a prune point, on-path skip)
///   - "we tried but had no prev state to compare against" (first visit)
///   - "we tried and went through standard or loop pruning"
/// — which then composes with the miss-reason histogram to tell us
/// whether the bottleneck is subsumption-failure (rework subsumption)
/// or first-visit-explosion (rework prune-point density / loop detection).
#[derive(Clone, Default, Debug)]
pub struct PruningStats {
    pub should_prune_calls: u64,
    pub not_prune_point: u64,
    pub on_path_skip: u64,
    pub no_prev_states: u64,
    pub std_pruning_calls: u64,
    pub loop_pruning_calls: u64,
    /// Of the `loop_pruning_calls`, how many bailed early because
    /// `loop_has_conditional_exit` returned false. Distinguishes
    /// "we identify the construct as a loop but can't see its exit"
    /// (probably a missed iter_next-style exit pattern) from "we
    /// reached subsumption but the cache didn't help."
    pub loop_no_cond_exit: u64,
    /// Of `should_prune` calls reaching the post-skip phase, how many
    /// were short-circuited by the may_goto RANGE_WITHIN prune class
    /// (counted *before* the std/loop branch, so it's not in those).
    pub may_goto_range_within_hits: u64,
    /// Per-call tracking inside `handle_loop_pruning` itself. The
    /// outer `loop_pruning_calls` counts *attempts*; this is "we
    /// actually walked prev_states." Difference would show if the
    /// `loop_has_conditional_exit` bail-out happens after the counter
    /// increment.
    pub loop_walks_attempted: u64,
    pub loop_walks_no_prev: u64,
    pub loop_walks_hit: u64,
    pub loop_walks_miss: u64,
    pub loop_walks_pruned_via_convergence: u64,
    /// Lifetime cache hits (every successful subsumption, even on
    /// states that later get evicted via max_states_per_pc drain).
    /// The per-state `StateMetrics.hit_cnt` is wrong for end-of-run
    /// reporting because evicted entries take their counters with them;
    /// these monotonic counters give the true picture.
    pub lifetime_hits: u64,
    pub lifetime_misses: u64,
    /// Number of times a cached state was skipped in `handle_standard_pruning`
    /// because it had `children_unsafe=true` (i.e., an earlier BCF
    /// path-unreachable discharge invalidated it for subsumption).
    /// Counts the SUBSUMPTION ATTEMPTS that were short-circuited; not
    /// the number of distinct invalidated cache entries.
    pub children_unsafe_skips: u64,
}

impl SubsumptionMissReason {
    pub const ALL: [SubsumptionMissReason; 9] = [
        SubsumptionMissReason::Types,
        SubsumptionMissReason::Domain,
        SubsumptionMissReason::Stack,
        SubsumptionMissReason::Tnum,
        SubsumptionMissReason::ScalarIdLinks,
        SubsumptionMissReason::ActiveLock,
        SubsumptionMissReason::GotoBudget,
        SubsumptionMissReason::ActiveRefs,
        SubsumptionMissReason::CallerFrame,
    ];
    pub fn idx(self) -> usize {
        match self {
            SubsumptionMissReason::Types => 0,
            SubsumptionMissReason::Domain => 1,
            SubsumptionMissReason::Stack => 2,
            SubsumptionMissReason::Tnum => 3,
            SubsumptionMissReason::ScalarIdLinks => 4,
            SubsumptionMissReason::ActiveLock => 5,
            SubsumptionMissReason::GotoBudget => 6,
            SubsumptionMissReason::ActiveRefs => 7,
            SubsumptionMissReason::CallerFrame => 8,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            SubsumptionMissReason::Types => "types",
            SubsumptionMissReason::Domain => "domain",
            SubsumptionMissReason::Stack => "stack",
            SubsumptionMissReason::Tnum => "tnum",
            SubsumptionMissReason::ScalarIdLinks => "scalar_id_links",
            SubsumptionMissReason::ActiveLock => "active_lock",
            SubsumptionMissReason::GotoBudget => "goto_budget",
            SubsumptionMissReason::ActiveRefs => "active_refs",
            SubsumptionMissReason::CallerFrame => "caller_frame",
        }
    }
}

pub struct VerifierEnv<'a> {
    /// Live stack slots analysis (kernel/bpf/liveness.c mirror) — see
    /// `flow::live_stack`. Initialized by `live_stack::init`.
    pub live_stack: crate::analysis::flow::live_stack::LiveStack,
    pub ctx: &'a ExecContext,
    pub explored_states: HashMap<usize, Vec<State>>,
    /// Count of cached states evicted by the `max_states_per_pc` cap
    /// (unmet pruning demand). High = kernel-faithful pruning isn't
    /// subsuming states the kernel would, so the per-pc list overflows the
    /// cap and thrashes. Paired with `max_per_insn` as the
    /// convergence-quality metric.
    pub cache_evictions: u64,
    /// Mapping from an iter_next kfunc call pc to the iter slot it
    /// operates on `(frame_idx, stack_offset)`. Populated lazily by
    /// `iter_next_fork` on first visit. Read by iter-loop pruning
    /// (`handle_loop_pruning`) to identify which iter slot's
    /// `iter.depth` to inspect when deciding whether to defer the
    /// back-edge target prune in an iter loop body — the iter slot
    /// belonging to THIS loop's iter_next, not unrelated iters that
    /// happen to be active in some outer/inner nesting.
    pub iter_pc_slot: HashMap<usize, (usize, i16)>,
    /// parallel to `explored_states`. `state_metrics[pc][i]`
    /// holds the hit/miss counters for `explored_states[pc][i]`. Drop
    /// the same index from both vectors on eviction.
    pub state_metrics: HashMap<usize, Vec<StateMetrics>>,

    /// When true, ALU ops that the kernel models with
    /// `__mark_reg_unknown`-style imprecision (e.g. `BPF_MOD`) clear
    /// dst bounds completely instead of refining via zovia's more
    /// precise interval. Set from `config.domain_mode ==
    /// DomainMode::Interval` (i.e. `--kernel-mode`). Lets zovia surface
    /// the same kernel-side "unbounded min" rejections at later
    /// pointer-arith sites so BCF can emit a bound-refine discharge.
    pub kernel_faithful_alu: bool,
    /// Whether userspace-BCF mode is active (`--bcf`). The precision
    /// backward walk uses this to stay at the kernel-faithful (base-mode)
    /// stack-frontier continuation only when BCF is OFF: in BCF mode the
    /// kernel re-checks the emitted bundle, so the extra precision isn't
    /// needed for soundness, and the additional trajectory distinctness it
    /// creates bloats the no_log bundle past the kernel's size limit
    /// (E2BIG → load failure). See the precision.rs termination gate.
    pub bcf_enabled: bool,
    /// Per-PC histogram of subsumption-miss reasons (one bucket per
    /// `SubsumptionMissReason` variant). `subsumption_misses[pc][r.idx()]`
    /// is incremented every time the per-cached-state subsumption check
    /// rejected with reason `r`. Used by the end-of-analysis dump.
    pub subsumption_misses: HashMap<usize, [u64; 9]>,
    /// Coarse counters for `should_prune` to disambiguate "subsumption
    /// failed" from "subsumption never even attempted". Incremented in
    /// `should_prune` and dumped alongside the miss histogram.
    pub pruning_stats: PruningStats,
    /// Set by the pruning scan when the current arrival encountered a
    /// cached state with `branches > 0` (an in-flight ancestor — the
    /// kernel's "processing a loop" signal). Consumed by the add_new_state
    /// decision to apply the kernel's in-loop checkpoint dampener
    /// (`skip_inf_loop_check`, verifier.c ~20320: suppress the add unless
    /// force_new_state or dj>=20 or di>=100). Reset at every should_prune.
    pub saw_active_state_at_check: bool,
    pub insn_aux_data: Vec<InsnAuxData>,
    pub invalid_pc_set: HashSet<usize>,
    pub addr_space_cast_to_arena_pcs: HashSet<usize>,
    /// Subprog entry-PCs whose body contains a kfunc / helper that the
    /// kernel forbids inside an rbtree-add / list-push `less` callback
    /// (verifier.c v6.15: kernel rejects "X not allowed in rbtree cb"
    /// or "function calls not allowed while holding a lock"). At the
    /// graph-add validator we look up R3's `PtrToCallback{subprog_pc}`
    /// and reject if its entry PC is in this set.
    pub tainted_cb_subprogs: HashSet<usize>,

    /// Per-cb-subprog set of byte offsets (relative to the cb's ctx-arg
    /// pointer) that any branch through the cb body may write via
    /// `Store { base: <ctx-alias>, off, .. }`. Pre-computed at env
    /// init by static scan of the program. Used at cb-Exit propagation
    /// (`cb_exit_propagate`): when `cb_should_widen=true` we invalidate
    /// every caller-frame slot in this set, not just the slots THIS
    /// cb-exit branch happened to write — required to discover multi-
    /// iteration interleavings (e.g. `iter_limit_bug` where two
    /// iterations of a 3-branch cb can land on `{ctx.a=42, ctx.b=42}`,
    /// not reachable from any single-iteration analysis).
    pub cb_body_store_offsets: HashMap<usize, std::collections::HashSet<i16>>,

    /// Per-cb-subprog flag: does the body call (directly) any
    /// dynptr-(re)initializing helper or kfunc?
    /// (`BPF_DYNPTR_FROM_MEM`, `BPF_RINGBUF_RESERVE_DYNPTR`,
    /// `bpf_dynptr_from_skb`, `bpf_dynptr_from_xdp`, `bpf_dynptr_clone`,
    /// `bpf_dynptr_adjust`.) Pre-computed at env init by scanning the
    /// cb body. Used by `transfer_callback_helper` to suppress the
    /// kernel-pessimism dynptr-slice invalidation on the post-cb
    /// continuation when the cb provably cannot re-init the dynptr —
    /// the invalidation is required for FA safety on `invalid_data_slices`
    /// (cb body actually re-inits) but FRs valid programs like
    /// `dynptr_success::test_ringbuf` (cb body just reads via
    /// `bpf_dynptr_data`). Mirrors the kernel's actual model: only
    /// `destroy_if_dynptr_stack_slot` invalidates slices, and that
    /// only fires on real init/release operations. Conservatively true
    /// for cbs that make a `CallRel` (we don't transitively scan).
    pub cb_body_can_reinit_dynptr: HashSet<usize>,

    // --- Dynamic State ---
    pub insn_processed: usize,
    /// Kernel `bpf_verifier_env::jmps_processed` (verifier.c v6.15
    /// L19553). Incremented once per BPF_JMP/JMP32-class insn. Used by
    /// the `add_new_state` sparse-cache heuristic.
    pub jmps_processed: usize,
    /// Snapshots at the most recent cache event (kernel
    /// `prev_jmps_processed` / `prev_insn_processed` L19260-L19261).
    pub prev_jmps_processed: usize,
    pub prev_insn_processed: usize,
    /// Per-PC visit counter (only populated when `ZOVIA_DUMP_VISITS=1`).
    /// Bumped once per non-pruned state expansion. Used by the per-PC
    /// audit dump to localize path-explosion hotspots vs the kernel
    /// verifier's per-PC visit count from the log_level-2 trace.
    pub pc_visit_count: HashMap<usize, u64>,
    /// Holds the FIRST critical failure encountered.
    /// If this is Some, the analysis should halt immediately.
    pub error: Option<VerificationError>,
    // Path execution history
    pub history: History,
    // Optional PCC certificate loaded from CLI.
    pub certificate: Option<ProgramCertificate>,
    /// True while `analyze_exception_cb` is running. Mirrors the kernel's
    /// `frame->in_exception_callback_fn`: switches the main-frame exit
    /// check to the exception-cb-specific rule (R0 ∈ [0, 0] for fentry/
    /// fexit) without affecting ordinary main-program exits.
    pub analyzing_exception_cb: bool,

    /// Monotonic counter for cache_id assignment. Each call to
    /// `record_state` mints a fresh id (post-increment).
    pub next_cache_id: u32,

    /// Reverse map: cache_id -> (pc, idx_in_explored_states_at_pc).
    /// Maintained by `record_state` (insertion) and the eviction path
    /// in `record_state` (index updates after drain). Used by the
    /// per-path precision walker to look up the specific cached state
    /// referenced by a `parent_cache_id` chain.
    pub cache_loc_by_id: HashMap<u32, (usize, usize)>,

    /// Kernel `env->free_list` analog (verifier.c: "struct
    /// bpf_verifier_state->parent refers to states that are in either of
    /// env->{explored_states,free_list}"). States evicted from the per-pc
    /// pruning lists (FIFO cap drain or the adaptive miss/hit eviction)
    /// but still referenced by live descendants' `parent_cache_id` chains.
    /// The kernel keeps evictees allocated until `branches == 0`
    /// (`maybe_free_verifier_state`); destroying them at eviction time
    /// dangles every parent-chain walk: branches accounting
    /// (`complete_dfs_branch`), the bcf backtrack base
    /// (`bcf_suffix_base_pc` returning None → base-less goal),
    /// `mark_path_children_unsafe` (truncated walk),
    /// precision backprop, and the replay base fetch.
    /// Keyed by cache_id, value = (cache pc, the retired State).
    pub retired_states: HashMap<u32, (usize, Box<State>)>,

    /// Collected BCF refinement proofs from this verification run. Each
    /// entry carries the canonical hash of the refinement-condition root,
    /// the goal-expression table the kernel needs for `expr_equiv` +
    /// `bcf_check_proof`, the proof bytes, and a kind tag
    /// (`BCF_BUNDLE_KIND_*`). Populated by refinement callbacks at
    /// safety-check sites when `config.bcf_enabled` and cvc5 returns Unsat;
    /// flushed to the `<input>.bcf-bundle` sidecar at the end of verification.
    /// Format: see `c-ref/bcf_bundle.h`.
    pub bcf_proofs: Vec<crate::refinement::bundle::RefineEntry>,

    /// Transient: the size-arg register of a helper-mem-region check in
    /// progress, when one applies. Mirrors BCF's `bcf->size_regno`
    /// (kernel `set1/0014`). Set by `mem_checks.rs` immediately before a
    /// call into `check_ptr_access_size` whose size came from a register;
    /// cleared after. Consumed by `refine_map` to build template 4b case
    /// (iv)'s symbolic-size-aware refine_cond. `None` for accesses with
    /// a static size (instruction-level loads/stores).
    pub bcf_size_reg: Option<Reg>,

    /// Transient mirror of the kernel's `bcf->path_unreachable`. Set by
    /// the generic-load rejection site when a `kind=UNREACHABLE` bundle
    /// entry is emitted (cvc5 proved the accumulated `path_cond` unsat).
    /// The load transfer consumes it: it resets the flag and drops the
    /// path (no successors), the analog of the single-pass kernel's
    /// bundle discharge → `PROCESS_BPF_EXIT`.
    pub bcf_path_unreachable: bool,

    /// Breadcrumb index of the instruction currently being transferred
    /// (the just-recorded step in `history`). Set by `run_worklist`
    /// immediately after `history.record`, before the transfer. The
    /// in-flight `State` still carries its *parent* `history_idx`
    /// (`current_step_idx` is only assigned to *successors*), so a
    /// reactive path-unreachable discharge fired from inside a transfer
    /// must use THIS — the rejecting insn's own breadcrumb — as the
    /// `bcf_suffix_base_pc` walk start, mirroring the kernel's
    /// `backtrack_states` `last_idx = cur->insn_idx` (verifier.c
    /// ~24434) with `skip_first=true`. Starting from the parent
    /// breadcrumb skips one insn too early — benign for a load reject,
    /// fatal for a helper-call reject whose skipped predecessor is an
    /// argument's only definition.
    pub current_step_idx: Option<usize>,

    /// Faithful-discharge replay mode (mirrors kernel `env->bcf.tracking`).
    /// When true, the verifier is re-executing a base→reject suffix to
    /// reconstruct the kernel's exact `bcf_track` path condition. Side
    /// effects that would corrupt the in-flight analysis are suppressed:
    /// `fail()` (no spurious errors), `mark_chain_precision_backward()` (no
    /// precision marking), and the reject-site discharge speculation (no
    /// re-entrant discharge). History/cache aren't touched by `transfer`, so
    /// nothing else needs gating. Default false ⇒ zero behavior change.
    pub replay_mode: bool,

    /// Eviction-resistant precision marks keyed by `(pc, reg)`.
    /// `mark_chain_precision_backward` writes here as it walks the
    /// per-path history, so widening sites can detect "this reg was
    /// proven precision-critical at this pc on some earlier path"
    /// even after `max_states_per_pc` evicts the specific cached
    /// state that the walker originally marked. Reg-name boundaries
    /// (e.g. `r7 = r1` mov chains) are bridged at the *widening*
    /// site via the cached `scalar_ids` map: the widener checks the
    /// reg's id against all regs in cur/prev that share that id.
    pub precise_pcs: HashSet<(usize, Reg)>,

    /// Mirror of kernel `env->scc_info` / per-callchain `bpf_scc_visit`
    /// (verifier.c v6.15 ~L2165, include/linux/bpf_verifier.h L717).
    /// Keyed by `SccCallchain`: callsites of outer frames + scc_id of
    /// the innermost SCC-bearing frame. Lifecycle:
    ///   * `maybe_enter_scc` (called on each cache event) populates
    ///     the visit and records the FIRST cur cache_id as
    ///     `entry_state_cache_id` if not yet set.
    ///   * `add_scc_backedge` (called from handle_loop_pruning on a
    ///     RANGE_WITHIN hit) appends backedge snapshots.
    ///   * `maybe_exit_scc` (called from complete_dfs_branch when the
    ///     entry state's branches → 0) drains backedges into
    ///     propagate_backedges and clears `entry_state_cache_id`.
    pub scc_visits: crate::analysis::flow::scc::SccVisitMap,
}

impl<'a> VerifierEnv<'a> {
    pub fn new(
        ctx: &'a ExecContext,
        prog: &'a Program,
        certificate: Option<ProgramCertificate>,
        kernel_faithful_alu: bool,
        bcf_enabled: bool,
    ) -> Self {
        VerifierEnv {
            ctx,
            explored_states: HashMap::new(),
            cache_evictions: 0,
            iter_pc_slot: HashMap::new(),
            state_metrics: HashMap::new(),
            kernel_faithful_alu,
            bcf_enabled,
            subsumption_misses: HashMap::new(),
            pruning_stats: PruningStats::default(),
            saw_active_state_at_check: false,
            insn_aux_data: vec![InsnAuxData::default(); prog.instrs.len()],
            invalid_pc_set: prog.invalid_pc_set.clone(),
            addr_space_cast_to_arena_pcs: prog.addr_space_cast_to_arena_pcs.clone(),
            tainted_cb_subprogs: crate::analysis::flow::callback_analysis::compute_tainted_cb_subprogs(prog, &ctx.btf),
            cb_body_store_offsets: crate::analysis::flow::callback_analysis::compute_cb_body_store_offsets(prog),
            cb_body_can_reinit_dynptr: crate::analysis::flow::callback_analysis::compute_cb_body_can_reinit_dynptr(prog, &ctx.btf),
            insn_processed: 0,
            jmps_processed: 0,
            prev_jmps_processed: 0,
            prev_insn_processed: 0,
            pc_visit_count: HashMap::new(),
            error: None,
            history: History::new(),
            certificate,
            analyzing_exception_cb: false,
            next_cache_id: 0,
            cache_loc_by_id: HashMap::new(),
            retired_states: HashMap::new(),
            precise_pcs: HashSet::new(),
            scc_visits: crate::analysis::flow::scc::SccVisitMap::new(),
            bcf_proofs: Vec::new(),
            bcf_size_reg: None,
            bcf_path_unreachable: false,
            current_step_idx: None,
            replay_mode: false,
            live_stack: Default::default(),
        }
    }

    /// Report a failure. Only the first failure is recorded.
    pub fn fail(&mut self, err: VerificationError) {
        // During a faithful-discharge replay we re-execute a known-good
        // suffix purely to rebuild the bcf path condition; any "failure"
        // is an artifact of re-running checks out of their original
        // context and must not poison the real analysis.
        if self.replay_mode {
            return;
        }
        if self.error.is_none() {
            self.error = Some(err);
        }
    }

    pub fn failed(&self) -> bool {
        self.error.is_some()
    }

    /// Compute the PC at which all `target_regs`' definition chains have
    /// bottomed out (the kernel's "base state" PC). Query-only mirror of
    /// `backtrack_states` (vendor verifier.c; in
    /// `/Users/yalucai/bpf-next-zovia/kernel/bpf/verifier.c` at the
    /// `backtrack_states` definition): walks backward through the linear
    /// breadcrumb history starting from `history_idx`, applying a
    /// **faithful port of the kernel's `backtrack_insn`**
    /// ([`backtrack_insn_step`] over a per-frame [`BacktrackState`]:
    /// register + stack-slot masks, exact per-opcode data-flow, the
    /// kernel's `INSN_F_STACK_ACCESS` register-spill/fill gate, precise
    /// `bt_empty` termination), and returns the PC at which `bt` first
    /// becomes empty. Used by BCF refinement sites to filter eager
    /// `SymbolicState::path_conds` down to the suffix the kernel's
    /// `bcf_track` would emit.
    ///
    /// (`mark_chain_precision_backward` is a *separate* mechanism — the
    /// kernel `__mark_chain_precision` precision-marking heuristic — and
    /// keeps the older flat-frontier `update_frontier`; do not conflate
    /// the two.)
    ///
    /// Semantics — mirrors `backtrack_states` step-by-step:
    /// * Initial `bt` = `target_regs` set in the reject state's frame
    ///   (the breadcrumb's call depth = kernel `bt_init(st->curframe)`).
    /// * Walk back through breadcrumbs; the **first** breadcrumb (the
    ///   refine site's own insn) is skipped (`skip_first = true`),
    ///   matching the kernel.
    /// * Apply `backtrack_insn_step` per prior step. When `bt` empties,
    ///   that step's PC is the kernel's base PC — return it.
    /// * If a step hits the kernel's -ENOTSUPP/-EFAULT path, or the walk
    ///   runs out of history without emptying, the kernel aborts with
    ///   `base = NULL`; we return `None` (callers treat that as "keep
    ///   all path_conds" — sound, just not a tighter suffix).
    ///
    /// Returns `None` for empty `target_regs` (kernel returns
    /// `-EFAULT` in that case too) or when the walk runs out.
    /// For a cached state identified by its `cache_id`, return the PC
    /// of the instruction processed IMMEDIATELY BEFORE the cache event
    /// — zovia's analog of the kernel's `vstate->last_insn_idx`. Used
    /// by `filter_path_conds_from_pc` to mirror the kernel's
    /// `record_path_cond` push at `bcf_track` replay start: only
    /// triggers if prev_insn was a scalar conditional branch
    /// (verifier.c:21117 + 21000-21019). Returns `None` if the cache_id
    /// isn't found, or the cached state has no history breadcrumb, or
    /// the breadcrumb is the first (no parent step).
    pub fn cached_prev_insn_pc(&self, cache_id: u32) -> Option<usize> {
        let (_, cached) = self.state_by_cache_id(cache_id)?;
        let hidx = cached.history_idx?;
        // `cached.history_idx` already points at the breadcrumb for the
        // IMMEDIATELY PRECEDING insn: cache events fire BEFORE the current
        // insn's `history.record`, so `state.history_idx` is still the
        // value set when the successor was pushed in the prior iteration
        // (= predecessor's breadcrumb). The previous code walked one step
        // further via `.parent_idx`, returning the grandparent's PC —
        // off-by-one against the kernel's `vstate->last_insn_idx`. For a
        // state arriving at PC 1873 via the branch at PC 1746
        // (`if w1 != w2 goto 1873`), walking one more step would return
        // 1745 (the insn before the branch); `filter_path_conds_from_pc`
        // then finds no branch predicate at that source_pc, drops the
        // branch cond, and the canonical hash diverges from the kernel's.
        Some(self.history.get(hidx)?.pc)
    }

    /// Resolve a cache_id to its state — live (`explored_states`) first,
    /// then retired (`retired_states`, the kernel free_list analog).
    /// Kernel parent-chain walks (`st->parent`) never dangle because
    /// evicted states stay allocated until `branches == 0`; every zovia
    /// chain walk must resolve through this instead of raw
    /// `cache_loc_by_id` + `explored_states`.
    pub fn state_by_cache_id(&self, cid: u32) -> Option<(usize, &State)> {
        if let Some(&(pc, idx)) = self.cache_loc_by_id.get(&cid) {
            return self
                .explored_states
                .get(&pc)
                .and_then(|v| v.get(idx))
                .map(|s| (pc, s));
        }
        self.retired_states.get(&cid).map(|(pc, s)| (*pc, s.as_ref()))
    }

    /// Mutable variant of [`Self::state_by_cache_id`].
    pub fn state_by_cache_id_mut(&mut self, cid: u32) -> Option<(usize, &mut State)> {
        if let Some(&(pc, idx)) = self.cache_loc_by_id.get(&cid) {
            return self
                .explored_states
                .get_mut(&pc)
                .and_then(|v| v.get_mut(idx))
                .map(|s| (pc, s));
        }
        self.retired_states
            .get_mut(&cid)
            .map(|(pc, s)| (*pc, s.as_mut()))
    }

    /// Kernel eviction semantics (verifier.c is_state_visited L20455-64):
    /// on miss/hit-ratio eviction the state moves to `env->free_list`
    /// (`sl->in_free_list = true; list_add(&env->free_list)`) followed by
    /// `maybe_free_verifier_state`, which frees ONLY when `branches == 0`.
    /// zovia analog: drop immediately when no live descendants reference
    /// it, otherwise park it in `retired_states` for parent-chain walks.
    pub fn retire_state(&mut self, cid: u32, pc: usize, state: State) {
        if state.branches == 0 {
            return; // kernel maybe_free_verifier_state at eviction site
        }
        self.retired_states.insert(cid, (pc, Box::new(state)));
    }

    /// Kernel `maybe_free_verifier_state` from `update_branch_counts`:
    /// once a retired state's last live descendant completes
    /// (`branches == 0`), free it.
    pub fn maybe_free_retired(&mut self, cid: u32) {
        if let Some((_, s)) = self.retired_states.get(&cid)
            && s.branches == 0
        {
            self.retired_states.remove(&cid);
        }
    }
}
