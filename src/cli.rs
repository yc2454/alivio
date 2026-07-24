// src/cli.rs - clap-based CLI definitions and backward-compat argv rewriting.
//
// User-facing surface is three verbs: `elf`, `verify`, `pcc`. All
// corpus/benchmark/baseline/regression commands live under a hidden `dev`
// subcommand. Old top-level command names (e.g. `selftest-suite`,
// `prevail-benchmark`, `pcc-gen`) are translated to the new form by
// `rewrite_legacy_argv` before clap parses, so existing scripts/CI keep
// working without surfacing them in `--help`.

use crate::common::config::{DomainMode, VerifierConfig};
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "zovia",
    version,
    about = "eBPF zone verifier",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,

    #[command(subcommand)]
    pub cmd: Cmd,
}

// Verifier-tuning flags shared by every subcommand.
//
// All flags are `global = true` so they may appear before *or* after the
// subcommand name. Old scripts (`zovia -q --max-insn N selftest-suite …`)
// keep working unchanged.
#[derive(Args, Debug)]
pub struct GlobalOpts {
    /// Verbosity 0 (errors only)
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// Verbosity 2 (trace execution)
    #[arg(short, long, global = true)]
    pub verbose: bool,
    /// Verbosity 3 (full debug)
    #[arg(long = "very-verbose", global = true)]
    pub very_verbose: bool,

    /// Use kernel-style interval domain (also sets single-entry loops, disables bounded-loop detection)
    #[arg(long = "kernel-mode", alias = "interval", global = true)]
    pub kernel_mode: bool,
    /// Use zone domain (default; more precise)
    #[arg(long = "zone-mode", alias = "zone", global = true)]
    pub zone_mode: bool,

    #[arg(long, global = true)]
    pub skip_dbm: bool,
    #[arg(long, global = true)]
    pub use_widening: bool,
    #[arg(long, global = true)]
    pub enable_path_trace: bool,

    #[arg(long, global = true)]
    pub detect_bounded_loops: bool,
    #[arg(long = "no-detect-bounded-loops", global = true)]
    pub no_detect_bounded_loops: bool,
    #[arg(long, global = true)]
    pub single_entry_loops: bool,
    #[arg(long, global = true)]
    pub multi_entry_loops: bool,
    #[arg(long, global = true)]
    pub enable_private_stack: bool,
    #[arg(long, global = true)]
    pub disable_private_stack: bool,

    /// Enable userspace BCF symbolic-tracking + proof emission (Phase 1).
    /// When set, the verifier maintains a parallel symbolic DAG per path and
    /// attempts proof-guided refinement at safety-check rejection sites;
    /// successful refinements are written as a `.bcf-bundle` sidecar next
    /// to the input. Default off — zero behavior change for non-BCF runs.
    #[arg(long = "bcf", global = true)]
    pub bcf: bool,

    #[arg(long, global = true, value_name = "N")]
    pub max_insn: Option<usize>,
    /// BCF-mode-only complexity budget (base mode keeps `--max-insn`).
    #[arg(long = "bcf-max-insn", global = true, value_name = "N")]
    pub bcf_max_insn: Option<usize>,
    #[arg(long, global = true, value_name = "N")]
    pub max_states: Option<usize>,
    #[arg(long, global = true, value_name = "N")]
    pub log_interval: Option<usize>,
    #[arg(long, global = true, value_name = "PC")]
    pub debug_pc: Option<usize>,

    /// Path to target kernel BTF blob (e.g. snapshot of /sys/kernel/btf/vmlinux).
    /// When set, CO-RE relocations in ELF objects carrying .BTF.ext are
    /// applied during ELF→AST lowering. Default off — programs without
    /// CO-RE relos are unaffected.
    #[arg(long = "target-btf", global = true, value_name = "PATH")]
    pub target_btf: Option<String>,

    /// Map size override `NAME:SIZE` (repeatable)
    #[arg(long = "map-override", global = true, value_name = "NAME:SIZE")]
    pub map_overrides: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Inspect ELF / BTF contents (no verification)
    Elf(ElfArgs),

    /// Verify an eBPF program. Source is auto-detected by extension:
    /// `.o` (ELF object), `.c` (C source compiled via clang), `.json`
    /// (legacy test catalogue — requires `--test NAME` to pick a case;
    /// bare invocation lists tests).
    Verify(VerifyArgs),

    /// Proof-Carrying Code (PCC) certificate workflows
    Pcc {
        #[command(subcommand)]
        sub: PccCmd,
    },

    /// Internal corpus / benchmark / baseline harness commands.
    /// Not part of the user-facing surface; subject to change.
    #[command(hide = true)]
    Dev {
        #[command(subcommand)]
        sub: DevCmd,
    },
}

#[derive(Args, Debug)]
pub struct ElfArgs {
    pub path: String,

    /// Analyze a specific section
    #[arg(long, conflicts_with_all = ["func", "all", "struct_ops", "btf_func", "bindings"])]
    pub section: Option<String>,
    /// Analyze a specific function (looks up its containing section)
    #[arg(long, conflicts_with_all = ["section", "all", "struct_ops", "btf_func", "bindings"])]
    pub func: Option<String>,
    /// Analyze every section in the ELF
    #[arg(long, conflicts_with_all = ["section", "func", "struct_ops", "btf_func", "bindings"])]
    pub all: bool,

    /// Diagnostic: dump the struct_ops methods of STRUCT
    #[arg(long = "struct-ops", value_name = "STRUCT")]
    pub struct_ops: Option<String>,
    /// Diagnostic: print the BTF FUNC parameter list of FUNC
    #[arg(long = "btf-func", value_name = "FUNC")]
    pub btf_func: Option<String>,
    /// Diagnostic: dump struct_ops bindings recovered from .struct_ops sections
    #[arg(long)]
    pub bindings: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to ELF (`.o`), source (`.c`), or legacy test catalogue (`.json`)
    pub path: String,

    /// (ELF) section to verify
    #[arg(long)]
    pub section: Option<String>,
    /// (ELF) function to verify
    #[arg(long)]
    pub func: Option<String>,

    /// (`.json`) test name; bare `verify foo.json` lists tests instead of running
    #[arg(long)]
    pub test: Option<String>,

    /// (`.c`) extra preprocessor defines, comma-separated
    #[arg(long)]
    pub defines: Option<String>,

    /// Force input kind when the extension is ambiguous or missing
    #[arg(long, value_enum)]
    pub kind: Option<InputKind>,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum InputKind {
    Elf,
    C,
    Json,
}

#[derive(Subcommand, Debug)]
pub enum PccCmd {
    /// Generate a PCC certificate (zone mode enforced)
    Gen {
        json_file: String,
        #[arg(long)]
        test: String,
        /// Path to write the certificate JSON
        #[arg(long, value_name = "PATH")]
        out: Option<String>,
    },
    /// Verify with a pre-existing certificate (interval mode enforced)
    Check {
        json_file: String,
        #[arg(long)]
        test: String,
        #[arg(long, value_name = "PATH")]
        cert: String,
    },
    /// Generate then check in one invocation
    Cycle {
        json_file: String,
        #[arg(long)]
        test: String,
        #[arg(long, value_name = "PATH")]
        out: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DevCmd {
    /// Compile + verify a single upstream-style `.c` selftest
    SelftestFile {
        src: String,
        defines: Option<String>,
        /// Use the upstream-tree include set rooted at this kernel checkout
        /// (mirrors `selftest-baseline-write-upstream` for one file).
        #[arg(long)]
        upstream: Option<String>,
        /// If set, only run programs whose function name matches.
        /// Used for spot-checking individual ERROR rows without
        /// re-running the whole file's worth of tests.
        #[arg(long)]
        func: Option<String>,
    },
    /// Compile + verify every `.c` selftest in `progs_dir`
    SelftestSuite { progs_dir: String },
    /// Sweep modern + legacy and write a baseline JSON
    SelftestBaselineWrite {
        progs_dir: String,
        legacy_json_dir: String,
        out: String,
    },
    /// Sweep upstream kernel selftests and write a baseline JSON
    SelftestBaselineWriteUpstream {
        upstream_root: String,
        out: String,
    },
    /// Diff a baseline against a fresh modern+legacy sweep
    SelftestBaselineCheck {
        progs_dir: String,
        legacy_json_dir: String,
        baseline: String,
    },
    /// Diff a baseline against a fresh modern-only sweep (fast)
    SelftestBaselineCheckModern {
        progs_dir: String,
        baseline: String,
    },
    /// Diff a baseline against a fresh upstream-tree sweep, skipping
    /// programs whose baseline outcome is non-deterministic (TIMEOUT,
    /// ERROR, SKIPPED). Mirror of `selftest-baseline-write-upstream`
    /// for the regression-gate workflow — typically much faster
    /// because the known-timeout rows aren't re-run.
    SelftestBaselineCheckUpstream {
        upstream_root: String,
        baseline: String,
    },
    /// JSONL corpus emitter. Single Rust entrypoint that downstream
    /// Python harnesses (bench, prevail, baseline diff) read line-by-line.
    /// Records go to `--out FILE` (or stdout if omitted, but then verifier
    /// stdout chatter will interleave — use `-q` plus a file for clean output).
    VerifyCorpus {
        /// Directory to walk recursively for `.o` files. Optional when
        /// `--input-list` is given.
        #[arg(default_value = "")]
        dir: String,
        /// File of newline-separated `.o` paths to verify (alternative
        /// to walking a directory).
        #[arg(long, value_name = "PATH")]
        input_list: Option<String>,
        /// Path to write JSONL records (one per file/section).
        #[arg(long, value_name = "PATH")]
        out: Option<String>,
    },
    /// Legacy JSON-corpus selftest commands
    LegacySelftest {
        #[command(subcommand)]
        sub: LegacySelftestCmd,
    },
    /// Run the PCC regression manifest
    PccRegress {
        manifest: Option<String>,
    },
    /// Export ELF metadata for a corpus directory to JSON
    BenchmarkScan { dir: String, out: String },
}

#[derive(Subcommand, Debug)]
pub enum LegacySelftestCmd {
    List { json_file: String },
    Single { json_file: String, test: String },
    Run { json_file: String },
    Suite { json_dir: String },
}

// ============================================================
// Build a VerifierConfig from parsed clap flags.
// ============================================================

impl GlobalOpts {
    pub fn into_verifier_config(self) -> VerifierConfig {
        let mut c = VerifierConfig::default();

        // Verbosity: highest wins (vv > v > q > default).
        if self.very_verbose {
            c.verbosity = 3;
        } else if self.verbose {
            c.verbosity = 2;
        } else if self.quiet {
            c.verbosity = 0;
        }

        // Domain mode. `--kernel-mode` sets a triplet (interval domain,
        // single-entry loops on, bounded-loop detection off) to mirror the
        // historical behavior. `--zone-mode` only flips the domain back —
        // loop flags must be set explicitly if needed.
        if self.kernel_mode {
            c.domain_mode = DomainMode::Interval;
            c.detect_bounded_loops = false;
            // Kernel-faithful: verifier.c:18370 short-circuits the
            // back-edge reject with `if (env->bpf_capable) return
            // DONE_EXPLORING`. kernel-mode is the always-privileged
            // mirror, so back-edges (including jump-into-loop-middle
            // patterns clang emits in tracing programs) must be
            // allowed.
            c.require_single_loop_entry = false;
        }
        if self.zone_mode {
            c.domain_mode = DomainMode::Zone;
        }

        if self.skip_dbm {
            c.skip_dbm_check = true;
        }
        if self.use_widening {
            c.use_widening = true;
        }
        if self.enable_path_trace {
            c.enable_path_trace = true;
        }

        if self.detect_bounded_loops {
            c.detect_bounded_loops = true;
        }
        if self.no_detect_bounded_loops {
            c.detect_bounded_loops = false;
        }
        if self.single_entry_loops {
            c.require_single_loop_entry = true;
        }
        if self.multi_entry_loops {
            c.require_single_loop_entry = false;
        }
        if self.enable_private_stack {
            c.enable_private_stack = true;
        }
        if self.disable_private_stack {
            c.enable_private_stack = false;
        }
        if self.bcf {
            c.bcf_enabled = true;
        }

        if let Some(n) = self.max_insn {
            // `--max-insn` sets BOTH budgets (so existing scripts that raise
            // the base limit also raise BCF); `--bcf-max-insn` overrides the
            // BCF one specifically. Keep BCF >= base.
            c.max_insn = n;
            c.bcf_max_insn = c.bcf_max_insn.max(n);
        }
        if let Some(n) = self.bcf_max_insn {
            c.bcf_max_insn = n;
        }
        if let Some(n) = self.max_states {
            c.max_states_per_pc = n;
        }
        if let Some(n) = self.log_interval {
            c.log_interval = n;
        }
        if let Some(pc) = self.debug_pc {
            c.debug_pc = Some(pc);
        }
        if let Some(p) = &self.target_btf {
            c.target_btf_path = Some(p.clone());
        }

        for spec in &self.map_overrides {
            match spec.split_once(':') {
                Some((name, size_str)) => match size_str.parse::<u32>() {
                    Ok(size) => {
                        c.map_overrides.insert(name.to_string(), size);
                    }
                    Err(_) => eprintln!("Warning: invalid size in map override '{spec}'"),
                },
                None => eprintln!(
                    "Warning: invalid map override format '{spec}'. Expected 'name:size'"
                ),
            }
        }

        c
    }
}
