// src/common/config.rs
//
// Verifier configuration - controls analysis behavior via command-line flags.

use crate::pcc::ProgramCertificate;

/// Abstract domain mode for numerical analysis
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DomainMode {
    /// Zone domain (DBM) - tracks relational constraints x - y <= c
    /// More precise, especially for packet bounds checking
    #[default]
    Zone,
    /// Interval domain - kernel verifier style, per-register bounds only
    /// Less precise but matches kernel behavior
    Interval,
}

/// Verifier configuration options
#[derive(Clone, Debug)]
pub struct VerifierConfig {
    /// Verbosity level (0=quiet, 1=info, 2=trace, 3=debug)
    pub verbosity: u8,

    /// Maximum instructions to process before aborting.
    ///
    /// In BASE mode this mirrors the kernel's `BPF_COMPLEXITY_LIMIT_INSNS`
    /// (1M): hitting it is a FAITHFUL kernel reject (a program too complex
    /// to verify at runtime, e.g. loop3). In BCF mode the effective limit is
    /// `bcf_max_insn` instead — alivio is then an OFFLINE bundle generator,
    /// not the runtime verifier, and (unlike the kernel) it does NOT
    /// fail-fast at a reject: it discharges via cvc5 and keeps exploring, so
    /// it inherently walks a larger state space than the kernel's fail-fast
    /// pass. The kernel's runtime DoS budget is the wrong yardstick there;
    /// the only budget that matters for the kernel is its OWN re-verification
    /// with the emitted bundle (≤1M, kernel-side).
    pub max_insn: usize,

    /// BCF-mode complexity budget (see `max_insn`). Higher than the kernel's
    /// 1M because BCF generation is offline and explores past rejects to
    /// discharge them. Some real-world functions converge between 1M–4M
    /// (they abort spuriously at the kernel's 1M).
    /// Tunable via `--bcf-max-insn`; a CLI `--max-insn` override sets BOTH.
    pub bcf_max_insn: usize,

    /// Abstract domain mode (Zone or Interval)
    pub domain_mode: DomainMode,

    /// Skip DBM (numeric) comparison in pruning - faster but less precise
    pub skip_dbm_check: bool,

    /// Use widening in pruning - might cause unsoundness but guarantees loop termination
    pub use_widening: bool,

    /// Maximum states to keep per PC for pruning. Kernel-absent hard
    /// FIFO ceiling (the privileged kernel bounds per-insn state lists
    /// via miss/hit eviction + clean_verifier_state, not a fixed cap).
    /// Kept at 8: fully removing it (→0) times out large objects
    /// because alivio lacks clean_verifier_state, so uncapped lists
    /// explode. The cap is a crutch for that missing mechanism
    /// (clean_verifier_state must land before the cap can be removed).
    pub max_states_per_pc: usize,

    /// Log heartbeat interval
    pub log_interval: usize,

    /// Debug a specific PC (force verbose logging at this PC)
    pub debug_pc: Option<usize>,

    /// Optional path to a target kernel BTF blob (e.g. a snapshot of
    /// `/sys/kernel/btf/vmlinux` from the kernel alivio is mirroring).
    /// When set, enables CO-RE relocation application during ELF→AST
    /// lowering. Default `None` preserves the prior unrelocated path.
    /// Mirrors libbpf's CO-RE setup: programs with `.BTF.ext` records
    /// get patched to match the target kernel's struct/enum layout.
    pub target_btf_path: Option<String>,

    /// Enable path tracing for crash analysis
    pub enable_path_trace: bool,

    /// A manual override for map file descriptors to sizes
    pub map_overrides: std::collections::HashMap<String, u32>,

    /// Detect bounded loops via pattern matching (e.g., `if r != K goto loop_head`)
    /// and allow early convergence without fully exploring all iterations.
    /// This is a precision improvement over the kernel verifier.
    /// Disabled automatically by --kernel-mode.
    pub detect_bounded_loops: bool,

    /// Require loops to have a single entry point (the loop head).
    /// The kernel's bounded loop support uses dominator tree analysis which
    /// requires this property. Code that jumps into the middle of a loop
    /// (skipping over the loop head) is rejected with "back-edge" error.
    /// Enabled automatically by --kernel-mode.
    pub require_single_loop_entry: bool,

    /// model the v6.12 private-stack feature for eligible program
    /// types (kprobe / tracepoint / perf_event / raw_tracepoint /
    /// struct_ops, with sched_ext landing through StructOps). When ON,
    /// subprograms in eligible programs get a separate stack arena and
    /// don't contribute to the cumulative call-chain budget — only each
    /// subprog's own ≤512-byte limit is enforced. Programs that call
    /// `bpf_tail_call` are excluded (kernel does the same).
    /// Default: ON (mirror kernel behavior). Set to false to fall back
    /// to the pre-6.12 cumulative-only model.
    pub enable_private_stack: bool,

    /// Optional path to write generated PCC certificate JSON.
    pub certificate_output: Option<String>,
    /// Optional path to load a PCC certificate for certificate-aided analysis.
    pub certificate_input: Option<String>,
    /// Parsed certificate payload (loaded in main when certificate-aided analysis is enabled).
    pub certificate: Option<ProgramCertificate>,

    /// Userspace BCF symbolic tracking (Phase 1). When true, the analysis
    /// seeds a `SymbolicState` on the entry `State` and the per-op transfer
    /// hooks populate a parallel symbolic DAG. Default false; flipped by
    /// `--bcf`.
    pub bcf_enabled: bool,

    /// Output path for the BCF bundle sidecar. Set by `main::run_verify`
    /// when `--bcf` is on (defaults to `<input>.bcf-bundle`). If
    /// non-`None` and `env.bcf_proofs` is non-empty at the end of analysis,
    /// the bundle is written here.
    pub bcf_bundle_out: Option<String>,

    /// Kernel-shape state-cache placement. When true, the walker only
    /// caches at `is_prune_point`
    /// PCs and uses the kernel's `add_new_state` heuristic; when false,
    /// the original dense per-popped-state caching is used.
    pub kernel_engine: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            verbosity: 1,
            max_insn: 1_000_000, // 1 million instructions to match modern kernel limits
            // Offline BCF generation budget (4× the kernel runtime cap).
            // Recovers functions that converge in 1M–4M but abort
            // spuriously at the kernel's 1M; see `max_insn` doc.
            bcf_max_insn: 4_000_000,
            domain_mode: DomainMode::Zone,
            skip_dbm_check: false,
            use_widening: false,
            max_states_per_pc: 64,
            log_interval: 100_000,
            debug_pc: None,
            target_btf_path: None,
            enable_path_trace: false,
            map_overrides: std::collections::HashMap::new(),
            detect_bounded_loops: true, // Default: enabled for precision
            require_single_loop_entry: false, // Default: allow multi-entry loops
            enable_private_stack: true, // mirror v6.12+ kernel default
            certificate_output: None,
            certificate_input: None,
            certificate: None,
            bcf_enabled: false,
            bcf_bundle_out: None,
            kernel_engine: false,
        }
    }
}
