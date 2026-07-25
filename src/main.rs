// src/main.rs - clap-based CLI entry point.
//
// User-facing surface: three verbs (`elf`, `verify`, `pcc`).
// Internal corpus/benchmark commands live under a hidden `dev` subcommand.
// Old top-level command names (`selftest-suite`, `prevail-benchmark`, etc.)
// are translated transparently in `cli::rewrite_legacy_argv` so existing
// scripts and CI keep working without surfacing them in `--help`.

// Clippy: deliberate style choices of this kernel-mirror codebase —
// functions take what their verifier.c counterparts take, comment-heavy
// docs are prose (not rustdoc lists), and mirrored branches stay
// textually separate even when bodies coincide.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::if_same_then_else)]

mod analysis;
mod ast;
mod cli;
mod common;
mod domains;
mod parsing;
mod pcc;
mod refinement;
mod testing;

use crate::ast::ProgramKind;
use crate::cli::{Cli, Cmd, DevCmd, ElfArgs, InputKind, LegacySelftestCmd, PccCmd, VerifyArgs};
use crate::common::config::{DomainMode, VerifierConfig};
use crate::parsing::elf::program_kind_for_object;
use crate::parsing::elf::{list_section_names, load_maps, load_raw_programs};
use crate::pcc::ProgramCertificate;
use crate::testing::legacy_selftest::{
    selftest_list, selftest_run, selftest_single, selftest_suite,
};
use crate::testing::logging;
use crate::testing::pcc_test::{pcc_cert_run, pcc_test_single};
use crate::testing::runner::{AnalysisResult, Analyzer, is_code_section};
use clap::Parser;
use std::path::Path;

fn main() {
    let parsed = Cli::parse();
    let config = parsed.global.into_verifier_config();

    // Initialize logging.
    logging::VerifierLogger::init(config.verbosity);
    if let Some(target_pc) = config.debug_pc {
        let filter = logging::FilterConfig {
            pc_range: Some(target_pc.saturating_sub(10)..=target_pc + 10),
            interesting_regs: vec![],
        };
        logging::VerifierLogger::set_config(filter);
    }

    match parsed.cmd {
        Cmd::Elf(args) => run_elf(args, config),
        Cmd::Verify(args) => run_verify(args, config),
        Cmd::Pcc { sub } => run_pcc(sub, config),
        Cmd::Dev { sub } => run_dev(sub, config),
    }
}

// ============================================================
// `elf` — inspect / analyze ELF + BTF contents
// ============================================================

fn run_elf(args: ElfArgs, config: VerifierConfig) {
    let path = args.path;

    if let Some(struct_name) = args.struct_ops {
        return run_btf_dump_struct_ops(&path, &struct_name);
    }
    if let Some(func_name) = args.btf_func {
        return run_btf_dump_func(&path, &func_name);
    }
    if args.bindings {
        return run_struct_ops_bindings(&path);
    }

    if let Some(section) = args.section {
        return run_analyze_section(&path, &section, config);
    }
    if let Some(func) = args.func {
        return run_analyze_func(&path, &func, config);
    }
    if args.all {
        return run_analyze_all(&path, config);
    }

    // Default: list sections, programs, maps.
    run_elf_list(&path);
}

fn run_elf_list(path: &str) {
    println!("=== ELF Contents: '{}' ===\n", path);
    println!("--- SECTIONS ---");
    match list_section_names(path) {
        Ok(sections) => {
            for (i, name) in sections.iter().enumerate() {
                if is_code_section(name) {
                    let kind = program_kind_for_object(Path::new(path))
                        .unwrap_or_else(|_| ProgramKind::from_section(name));
                    println!("  [{}] {} (Kind: {:?})", i, name, kind);
                }
            }
        }
        Err(e) => eprintln!("  Error: {:?}", e),
    }
    println!("\n--- BPF PROGRAMS ---");
    match load_raw_programs(path) {
        Ok(progs) => {
            let sections = list_section_names(path).unwrap_or_default();
            for (i, p) in progs.iter().enumerate() {
                let section_name = sections
                    .get(p.section_idx)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                let kind = program_kind_for_object(Path::new(path))
                    .unwrap_or_else(|_| ProgramKind::from_section(section_name));
                println!(
                    "  [{}] {} ({} insns) [Section: {}, Kind: {:?}]",
                    i,
                    p.name,
                    p.data.len() / 8,
                    section_name,
                    kind
                );
            }
        }
        Err(e) => eprintln!("  Error: {:?}", e),
    }
    println!("\n--- BPF MAPS ---");
    match load_maps(path) {
        Ok(maps) => {
            for (i, m) in maps.iter().enumerate() {
                println!(
                    "  [{}] {} (k:{}, v:{})",
                    i, m.name, m.key_size, m.value_size
                );
            }
        }
        Err(e) => eprintln!("  Error: {:?}", e),
    }
}

fn run_analyze_section(path: &str, section: &str, config: VerifierConfig) {
    println!("=== Analyzing: '{}' section '{}' ===", path, section);
    let analyzer = Analyzer::new(path, config);
    print_analysis_result(analyzer.analyze_section(section));
}

fn run_analyze_func(path: &str, func: &str, config: VerifierConfig) {
    println!("=== Analyzing function: '{}' in '{}' ===", func, path);
    let analyzer = Analyzer::new(path, config);
    print_analysis_result(analyzer.analyze_function(func, 0));
}

fn print_analysis_result(result: AnalysisResult) {
    match result {
        AnalysisResult::Pass => println!("\n=== PASS ==="),
        AnalysisResult::Fail(e) => println!("\n=== FAIL: {} ===", e.description()),
        AnalysisResult::Timeout => println!("\n=== TIMEOUT: Complexity limit reached ==="),
        AnalysisResult::LoadError(e) => println!("\n=== LOAD ERROR: {} ===", e),
        AnalysisResult::OutOfScope(reason) => {
            println!("\n=== OUT-OF-SCOPE: {} ===", reason)
        }
    }
}

fn run_analyze_all(path: &str, config: VerifierConfig) {
    println!("=== Batch Analysis: '{}' ===\n", path);
    println!(
        "Config: max_insn={}, skip_dbm={}, verbosity={}",
        config.max_insn, config.skip_dbm_check, config.verbosity
    );

    let analyzer = Analyzer::new(path, config);
    let (_, results) = analyzer.analyze_all();

    let mut pass = 0;
    let mut fail = 0;
    let mut timeout = 0;
    let mut error = 0;
    let mut out_of_scope = 0;
    for (section, res) in &results {
        print!("Section '{}'... ", section);
        match res {
            AnalysisResult::Pass => {
                println!("PASS");
                pass += 1;
            }
            AnalysisResult::Fail(_) => {
                println!("FAIL");
                fail += 1;
            }
            AnalysisResult::Timeout => {
                println!("TIMEOUT");
                timeout += 1;
            }
            AnalysisResult::LoadError(e) => {
                println!("ERROR ({})", e);
                error += 1;
            }
            AnalysisResult::OutOfScope(reason) => {
                println!("OUT-OF-SCOPE ({})", reason);
                out_of_scope += 1;
            }
        }
    }
    println!("\n========================================");
    println!("              SUMMARY");
    println!("========================================");
    println!("Total:  {}", results.len());
    if !results.is_empty() {
        println!(
            "Pass:   {} ({:.1}%)",
            pass,
            100.0 * pass as f64 / results.len() as f64
        );
    }
    println!("Fail:   {}", fail);
    println!("Timeout: {}", timeout);
    println!("Errors: {}", error);
    println!("Out-of-scope: {}", out_of_scope);
    if fail > 0 {
        println!("\n--- FAILURES ---");
        for (section, res) in &results {
            if let AnalysisResult::Fail(e) = res {
                println!("  {}: {}", section, e.description());
            }
        }
    }
    println!("\n=== Done ===");
}

// ============================================================
// `verify` — auto-detect ELF / .c / legacy .json
// ============================================================

fn run_verify(args: VerifyArgs, mut config: VerifierConfig) {
    let kind = args.kind.unwrap_or_else(|| infer_kind(&args.path));
    // For ELF inputs with `--bcf`, default the bundle sidecar next to the
    // input. Other input kinds (`.c`, `.json`) don't yet have a stable
    // single-file mapping for the artifact.
    if config.bcf_enabled && matches!(kind, InputKind::Elf) && config.bcf_bundle_out.is_none() {
        let bundle_path = format!("{}.bcf-bundle", args.path);
        // Clear any stale sidecar once per object. write_bundle merges
        // per-section (the ELF is analyzed one section at a time, all
        // writing this same path); the merge must start from empty each
        // run so re-verifying an object is idempotent rather than
        // accumulating prior runs' entries.
        // ⚠️ ALIVIO_BUNDLE_KEEP=1 disables the clear: useful for
        // cross-run accumulation (e.g., running with multiple kernel-
        // engine heuristics to build a superset bundle for byte-match
        // closure).
        if std::env::var("ALIVIO_BUNDLE_KEEP").ok().as_deref() != Some("1") {
            let _ = std::fs::remove_file(&bundle_path);
        }
        config.bcf_bundle_out = Some(bundle_path);
    }
    match kind {
        InputKind::Elf => {
            if let Some(section) = args.section {
                run_analyze_section(&args.path, &section, config);
            } else if let Some(func) = args.func {
                run_analyze_func(&args.path, &func, config);
            } else {
                run_analyze_all(&args.path, config);
            }
        }
        InputKind::C => {
            run_modern_selftest_file(&args.path, args.defines.as_deref(), None, None, &config);
        }
        InputKind::Json => match args.test {
            Some(name) => selftest_single(&args.path, &name, &config),
            None => {
                // Bare `verify foo.json` lists the available tests rather
                // than running the whole catalogue (which can be 10+ min).
                // Use `dev legacy-selftest run <foo.json>` for the bulk path.
                println!(
                    "(`verify` on a .json catalogue lists tests; pick one with --test NAME, \
                     or use `dev legacy-selftest run` for a bulk run.)\n"
                );
                selftest_list(&args.path);
            }
        },
    }
}

fn infer_kind(path: &str) -> InputKind {
    let ext = Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match ext {
        "c" => InputKind::C,
        "json" => InputKind::Json,
        _ => InputKind::Elf, // .o / .bpf.o / .so / no extension all treated as ELF
    }
}

// ============================================================
// `pcc` — certificate generate / check / cycle
// ============================================================

fn run_pcc(sub: PccCmd, config: VerifierConfig) {
    match sub {
        PccCmd::Gen {
            json_file,
            test,
            out,
        } => {
            let mut cfg = config;
            cfg.domain_mode = DomainMode::Zone;
            cfg.detect_bounded_loops = true;
            cfg.require_single_loop_entry = false;
            cfg.certificate = None;
            cfg.certificate_input = None;
            cfg.certificate_output = out;
            pcc_test_single(&json_file, &test, &cfg);
        }
        PccCmd::Check {
            json_file,
            test,
            cert,
        } => {
            let parsed_cert = match ProgramCertificate::load_from_path(&cert) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: invalid certificate file '{}': {e:#}", cert);
                    std::process::exit(2);
                }
            };
            let mut cfg = config;
            cfg.domain_mode = DomainMode::Interval;
            cfg.detect_bounded_loops = false;
            cfg.require_single_loop_entry = true;
            cfg.certificate_output = None;
            cfg.certificate_input = None;
            cfg.certificate = Some(parsed_cert);
            pcc_test_single(&json_file, &test, &cfg);
        }
        PccCmd::Cycle {
            json_file,
            test,
            out,
        } => {
            let cert_out = out.unwrap_or_else(|| "/tmp/pcc_cycle.cert.json".to_string());

            let mut gen_cfg = config.clone();
            gen_cfg.domain_mode = DomainMode::Zone;
            gen_cfg.detect_bounded_loops = true;
            gen_cfg.require_single_loop_entry = false;
            gen_cfg.certificate = None;
            gen_cfg.certificate_input = None;
            gen_cfg.certificate_output = Some(cert_out.clone());

            println!("\n====== Phase 1 / Certificate Generation (zone mode) ======\n");
            pcc_test_single(&json_file, &test, &gen_cfg);

            if !Path::new(&cert_out).exists() {
                eprintln!(
                    "Error: certificate was not generated at '{}'; skipping cert-aided check",
                    cert_out
                );
                return;
            }

            let cert = match ProgramCertificate::load_from_path(&cert_out) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "Error: generated certificate is invalid '{}': {e:#}",
                        cert_out
                    );
                    return;
                }
            };

            let mut check_cfg = config;
            check_cfg.domain_mode = DomainMode::Interval;
            check_cfg.detect_bounded_loops = false;
            check_cfg.require_single_loop_entry = true;
            check_cfg.certificate_output = None;
            check_cfg.certificate_input = None;
            check_cfg.certificate = Some(cert);

            println!("\n====== Phase 2 / PCC Certificate Check (interval mode) ======\n");
            pcc_test_single(&json_file, &test, &check_cfg);
        }
    }
}

// ============================================================
// `dev` — internal corpus / benchmark / baseline harness
// ============================================================

fn run_dev(sub: DevCmd, config: VerifierConfig) {
    match sub {
        DevCmd::SelftestFile {
            src,
            defines,
            upstream,
            func,
        } => {
            run_modern_selftest_file(
                &src,
                defines.as_deref(),
                upstream.as_deref(),
                func.as_deref(),
                &config,
            );
        }
        DevCmd::SelftestSuite { progs_dir } => {
            run_modern_selftest_dir(&progs_dir, &config);
        }
        DevCmd::SelftestBaselineWrite {
            progs_dir,
            legacy_json_dir,
            out,
        } => {
            run_baseline_write(&progs_dir, &legacy_json_dir, &out, &config);
        }
        DevCmd::SelftestBaselineWriteUpstream { upstream_root, out } => {
            run_baseline_write_upstream(&upstream_root, &out, &config);
        }
        DevCmd::SelftestBaselineCheck {
            progs_dir,
            legacy_json_dir,
            baseline,
        } => {
            run_baseline_check(&progs_dir, &legacy_json_dir, &baseline, &config);
        }
        DevCmd::SelftestBaselineCheckModern {
            progs_dir,
            baseline,
        } => {
            run_baseline_check_modern(&progs_dir, &baseline, &config);
        }
        DevCmd::SelftestBaselineCheckUpstream {
            upstream_root,
            baseline,
        } => {
            run_baseline_check_upstream(&upstream_root, &baseline, &config);
        }
        DevCmd::VerifyCorpus {
            dir,
            input_list,
            out,
        } => {
            let dir_path = if dir.is_empty() {
                None
            } else {
                Some(Path::new(dir.as_str()))
            };
            let list_path = input_list.as_deref().map(Path::new);
            let out_path = out.as_deref().map(Path::new);
            if let Err(e) =
                crate::testing::jsonl::emit_corpus_jsonl(dir_path, list_path, out_path, &config)
            {
                eprintln!("Error: {e}");
                std::process::exit(2);
            }
        }
        DevCmd::LegacySelftest { sub } => match sub {
            LegacySelftestCmd::List { json_file } => selftest_list(&json_file),
            LegacySelftestCmd::Single { json_file, test } => {
                selftest_single(&json_file, &test, &config)
            }
            LegacySelftestCmd::Run { json_file } => {
                selftest_run(&json_file, &config, Some("./results/selftest"))
            }
            LegacySelftestCmd::Suite { json_dir } => {
                selftest_suite(&json_dir, &config, Some("./results/selftest"))
            }
        },
        DevCmd::PccRegress { manifest } => {
            let m = manifest.unwrap_or_else(|| "pcc-tests/cert_cases.json".to_string());
            pcc_cert_run(&m, &config);
        }
        DevCmd::BenchmarkScan { dir, out } => {
            if let Err(e) = crate::testing::scanner::scan_benchmark_dir(&dir, &out) {
                eprintln!("Error: {:?}", e);
            }
        }
    }
}

// ============================================================
// Modern selftest helpers
// ============================================================

fn parse_extra_defines(arg: Option<&str>) -> Vec<String> {
    arg.map(|s| {
        s.split(',')
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect()
    })
    .unwrap_or_default()
}

struct OneFunc<'a>(&'a str);
impl<'a> crate::testing::selftest::runner::ProgFilter for OneFunc<'a> {
    fn should_run(&self, _file: &str, prog: &str) -> bool {
        prog == self.0
    }
}

fn run_modern_selftest_file(
    src: &str,
    defines_arg: Option<&str>,
    upstream_root: Option<&str>,
    func_filter: Option<&str>,
    config: &VerifierConfig,
) {
    use crate::testing::selftest::clang::{self, DEFAULT_HEADERS_TAG};
    use crate::testing::selftest::runner;

    let headers = std::path::PathBuf::from("selftests/headers").join(DEFAULT_HEADERS_TAG);
    let mut defines = parse_extra_defines(defines_arg);
    let res = match upstream_root {
        Some(root) => {
            let root = std::path::Path::new(root);
            let inc = clang::upstream_include_dirs(&headers, root);
            let iq = clang::upstream_iquote_dirs(&headers, root);
            for d in clang::UPSTREAM_GLOBAL_DEFINES {
                if !defines.iter().any(|s| s == d) {
                    defines.push((*d).to_string());
                }
            }
            let define_refs: Vec<&str> = defines.iter().map(|s| s.as_str()).collect();
            match func_filter {
                Some(name) => runner::run_file_with_dirs(
                    std::path::Path::new(src),
                    &inc,
                    &iq,
                    &define_refs,
                    config,
                    &OneFunc(name),
                ),
                None => runner::run_file_with_dirs(
                    std::path::Path::new(src),
                    &inc,
                    &iq,
                    &define_refs,
                    config,
                    &runner::RunAll,
                ),
            }
        }
        None => {
            let define_refs: Vec<&str> = defines.iter().map(|s| s.as_str()).collect();
            match func_filter {
                Some(name) => runner::run_file_filtered(
                    std::path::Path::new(src),
                    &headers,
                    &define_refs,
                    config,
                    &OneFunc(name),
                ),
                None => runner::run_file(std::path::Path::new(src), &headers, &define_refs, config),
            }
        }
    };
    match res {
        Ok(report) => print_modern_report(&report),
        Err(e) => eprintln!("Error: {e:?}"),
    }
}

fn run_modern_selftest_dir(dir: &str, config: &VerifierConfig) {
    use crate::testing::selftest::clang::DEFAULT_HEADERS_TAG;
    use crate::testing::selftest::runner;

    let headers = std::path::PathBuf::from("selftests/headers").join(DEFAULT_HEADERS_TAG);
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error reading {dir}: {e}");
            return;
        }
    };

    let mut totals = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize); // pass, false_reject, false_accept, skipped, error, out_of_scope
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("c") {
            continue;
        }
        match runner::run_file(&path, &headers, &[], config) {
            Ok(report) => {
                print_modern_report(&report);
                for p in &report.progs {
                    use crate::testing::selftest::runner::Outcome;
                    match p.outcome {
                        Outcome::Pass => totals.0 += 1,
                        Outcome::FalseReject(_) => totals.1 += 1,
                        Outcome::FalseAccept => totals.2 += 1,
                        Outcome::Skipped(_) => totals.3 += 1,
                        Outcome::Error(_) => totals.4 += 1,
                        Outcome::OutOfScope(_) => totals.5 += 1,
                    }
                }
            }
            Err(e) => eprintln!("Error on {}: {e:?}", path.display()),
        }
    }
    println!("\n=== Suite summary ===");
    println!(
        "  pass={}  false_reject={}  false_accept={}  skipped={}  error={}  out_of_scope={}",
        totals.0, totals.1, totals.2, totals.3, totals.4, totals.5
    );
}

fn collect_json_recursive(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_json_recursive(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(p);
        }
    }
}

fn sweep_modern_and_legacy(
    progs_dir: &str,
    legacy_json_dir: &str,
    config: &VerifierConfig,
    filter: &dyn crate::testing::selftest::runner::ProgFilter,
) -> crate::testing::selftest::baseline::Baseline {
    use crate::testing::legacy_selftest;
    use crate::testing::selftest::baseline::Baseline;
    use crate::testing::selftest::clang::DEFAULT_HEADERS_TAG;
    use crate::testing::selftest::runner;

    let headers = std::path::PathBuf::from("selftests/headers").join(DEFAULT_HEADERS_TAG);
    let modern =
        runner::run_dir_filtered(std::path::Path::new(progs_dir), &headers, config, filter)
            .unwrap_or_else(|e| {
                eprintln!("Error sweeping modern {progs_dir}: {e:?}");
                Vec::new()
            });
    let mut bl = Baseline::from_reports(DEFAULT_HEADERS_TAG, &modern);

    let mut legacy_files = Vec::new();
    collect_json_recursive(std::path::Path::new(legacy_json_dir), &mut legacy_files);
    legacy_files.sort();

    use crate::testing::selftest::runner::with_selftest_caps;
    use rayon::prelude::*;
    let legacy_config = with_selftest_caps(config);
    let legacy_results: Vec<_> = legacy_files
        .par_iter()
        .filter_map(|path| {
            match legacy_selftest::run_test_file(path.to_str().unwrap(), &legacy_config) {
                Ok(r) => Some(r),
                Err(e) => {
                    eprintln!("Error on legacy {}: {e}", path.display());
                    None
                }
            }
        })
        .collect();
    bl.extend_with_legacy(&legacy_results);
    bl
}

fn sweep_upstream_only(
    progs_dir: &str,
    upstream_root: &str,
    config: &VerifierConfig,
    filter: &dyn crate::testing::selftest::runner::ProgFilter,
) -> crate::testing::selftest::baseline::Baseline {
    use crate::testing::selftest::baseline::Baseline;
    use crate::testing::selftest::clang::DEFAULT_HEADERS_TAG;
    use crate::testing::selftest::runner;

    let headers = std::path::PathBuf::from("selftests/headers").join(DEFAULT_HEADERS_TAG);
    let modern = runner::run_dir_upstream_filtered(
        std::path::Path::new(progs_dir),
        &headers,
        std::path::Path::new(upstream_root),
        config,
        filter,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error sweeping upstream {progs_dir}: {e:?}");
        Vec::new()
    });
    Baseline::from_reports(DEFAULT_HEADERS_TAG, &modern)
}

fn sweep_modern_only(
    progs_dir: &str,
    config: &VerifierConfig,
    filter: &dyn crate::testing::selftest::runner::ProgFilter,
) -> crate::testing::selftest::baseline::Baseline {
    use crate::testing::selftest::baseline::Baseline;
    use crate::testing::selftest::clang::DEFAULT_HEADERS_TAG;
    use crate::testing::selftest::runner;

    let headers = std::path::PathBuf::from("selftests/headers").join(DEFAULT_HEADERS_TAG);
    let modern =
        runner::run_dir_filtered(std::path::Path::new(progs_dir), &headers, config, filter)
            .unwrap_or_else(|e| {
                eprintln!("Error sweeping modern {progs_dir}: {e:?}");
                Vec::new()
            });
    Baseline::from_reports(DEFAULT_HEADERS_TAG, &modern)
}

// ============================================================
// BTF dump diagnostics
// ============================================================

fn run_btf_dump_struct_ops(elf_path: &str, struct_name: &str) {
    use crate::parsing::btf::{self, StructOpsArg};
    use goblin::elf::Elf;

    let bytes = match std::fs::read(elf_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {elf_path}: {e}");
            std::process::exit(2);
        }
    };
    let elf = match Elf::parse(&bytes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("parse ELF {elf_path}: {e}");
            std::process::exit(2);
        }
    };
    let mut btf_bytes: Option<&[u8]> = None;
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == ".BTF" {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            if end <= bytes.len() {
                btf_bytes = Some(&bytes[start..end]);
            }
            break;
        }
    }
    let Some(raw) = btf_bytes else {
        eprintln!("no .BTF section in {elf_path}");
        std::process::exit(2);
    };
    let ctx = match btf::parse_btf(raw) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("parse BTF: {e}");
            std::process::exit(2);
        }
    };
    let Some(struct_id) = ctx.find_struct_by_name(struct_name) else {
        eprintln!("struct `{struct_name}` not found in BTF");
        std::process::exit(1);
    };
    println!("struct {struct_name} (btf_id {struct_id})");
    let ty = ctx.types.get(&struct_id).unwrap();
    let mut hits = 0usize;
    for m in &ty.members {
        let mname = ctx.read_string(m.name_off).unwrap_or("?");
        let Some(pointee_id) = ctx.pointee(m.type_id) else {
            continue;
        };
        let Some(pointee) = ctx.types.get(&pointee_id) else {
            continue;
        };
        if pointee.kind() != btf::BTF_KIND_FUNC_PROTO {
            continue;
        }
        hits += 1;
        let args = ctx
            .resolve_struct_ops_method(struct_name, mname)
            .unwrap_or_default();
        let pretty = args
            .iter()
            .map(|a| match a {
                StructOpsArg::Scalar => "scalar".to_string(),
                StructOpsArg::TrustedPtr(n) => format!("ptr<{n}>"),
                StructOpsArg::OpaquePtr => "ptr<?>".to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!("  .{mname:30} ({pretty})");
    }
    println!("({hits} method(s))");
}

fn run_struct_ops_bindings(elf_path: &str) {
    use crate::parsing::btf;
    use crate::parsing::elf::struct_ops;
    use goblin::elf::Elf;

    let bytes = std::fs::read(elf_path).unwrap_or_else(|e| {
        eprintln!("read {elf_path}: {e}");
        std::process::exit(2);
    });
    let elf = Elf::parse(&bytes).unwrap_or_else(|e| {
        eprintln!("parse ELF: {e}");
        std::process::exit(2);
    });
    let mut btf_bytes: Option<&[u8]> = None;
    for sh in &elf.section_headers {
        if elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".BTF" {
            let s = sh.sh_offset as usize;
            let e = s + sh.sh_size as usize;
            if e <= bytes.len() {
                btf_bytes = Some(&bytes[s..e]);
            }
            break;
        }
    }
    let raw = btf_bytes.unwrap_or_else(|| {
        eprintln!("no .BTF section");
        std::process::exit(2);
    });
    let ctx = btf::parse_btf(raw).unwrap_or_else(|e| {
        eprintln!("parse BTF: {e}");
        std::process::exit(2);
    });
    let bindings = struct_ops::extract_bindings(&bytes, &elf, &ctx);
    if bindings.is_empty() {
        println!("(no struct_ops bindings recovered)");
        return;
    }
    for b in &bindings {
        println!("{} -> {}.{}", b.subprog, b.ops_struct, b.member);
    }
    println!("({} binding(s))", bindings.len());
}

fn run_btf_dump_func(elf_path: &str, func_name: &str) {
    use crate::parsing::btf::{self, StructOpsArg};
    use goblin::elf::Elf;

    let bytes = std::fs::read(elf_path).unwrap_or_else(|e| {
        eprintln!("read {elf_path}: {e}");
        std::process::exit(2);
    });
    let elf = Elf::parse(&bytes).unwrap_or_else(|e| {
        eprintln!("parse ELF: {e}");
        std::process::exit(2);
    });
    let mut btf_bytes: Option<&[u8]> = None;
    for sh in &elf.section_headers {
        if elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".BTF" {
            let s = sh.sh_offset as usize;
            let e = s + sh.sh_size as usize;
            if e <= bytes.len() {
                btf_bytes = Some(&bytes[s..e]);
            }
            break;
        }
    }
    let raw = btf_bytes.unwrap_or_else(|| {
        eprintln!("no .BTF section");
        std::process::exit(2);
    });
    let ctx = btf::parse_btf(raw).unwrap_or_else(|e| {
        eprintln!("parse BTF: {e}");
        std::process::exit(2);
    });
    let Some(args) = ctx.resolve_func_args(func_name) else {
        eprintln!("FUNC `{func_name}` not found in BTF (or no FUNC_PROTO)");
        std::process::exit(1);
    };
    let pretty = args
        .iter()
        .map(|a| match a {
            StructOpsArg::Scalar => "scalar".to_string(),
            StructOpsArg::TrustedPtr(n) => format!("ptr<{n}>"),
            StructOpsArg::OpaquePtr => "ptr<?>".to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    println!("{func_name}({pretty})");
}

// ============================================================
// Baseline read/write/check helpers
// ============================================================

fn run_baseline_check_modern(progs_dir: &str, stored: &str, config: &VerifierConfig) {
    use crate::testing::selftest::baseline::{Baseline, CheckFilter, DeterministicFilter, diff};

    let mut baseline = match Baseline::read(stored) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading baseline {stored}: {e:?}");
            std::process::exit(2);
        }
    };
    baseline.files.retain(|k, _| !k.starts_with("legacy/"));

    let det_filter = DeterministicFilter::from_baseline(&baseline);
    let check_filter = CheckFilter {
        filter: &det_filter,
        baseline: &baseline,
    };
    let current = sweep_modern_only(progs_dir, config, &check_filter);
    let d = diff(&baseline, &current);

    print_diff(&d, "(modern only)");
    if !d.regressions.is_empty() {
        std::process::exit(1);
    }
}

/// Mirror of `run_baseline_check_modern` that uses the upstream-tree
/// include/iquote setup. The `DeterministicFilter` short-circuits the
/// known TIMEOUT/ERROR rows — those are the long pole on a full upstream
/// sweep — so this command iterates orders of magnitude faster than
/// `selftest-baseline-write-upstream` while still catching every
/// PASS/FALSE_REJECT/FALSE_ACCEPT regression.
fn run_baseline_check_upstream(upstream_root: &str, stored: &str, config: &VerifierConfig) {
    use crate::testing::selftest::baseline::{Baseline, CheckFilter, DeterministicFilter, diff};

    let baseline = match Baseline::read(stored) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading baseline {stored}: {e:?}");
            std::process::exit(2);
        }
    };

    let progs_dir_str = validate_upstream_root_progs_dir(upstream_root);

    let det_filter = DeterministicFilter::from_baseline(&baseline);
    let check_filter = CheckFilter {
        filter: &det_filter,
        baseline: &baseline,
    };
    let current = sweep_upstream_only(&progs_dir_str, upstream_root, config, &check_filter);
    let d = diff(&baseline, &current);

    print_diff(&d, "(upstream)");
    if !d.regressions.is_empty() {
        std::process::exit(1);
    }
}

fn run_baseline_write(progs_dir: &str, legacy_json_dir: &str, out: &str, config: &VerifierConfig) {
    use crate::testing::selftest::runner::RunAll;
    let bl = sweep_modern_and_legacy(progs_dir, legacy_json_dir, config, &RunAll);
    if let Err(e) = bl.write(out) {
        eprintln!("Error writing {out}: {e:?}");
        return;
    }
    println!("Wrote baseline ({} files) to {out}", bl.files.len());
}

/// Validate that `upstream_root` looks like a kernel checkout and return
/// the absolute path to the BPF progs directory. Exits with code 2 if
/// the layout is wrong — same diagnostic both write and check use.
fn validate_upstream_root_progs_dir(upstream_root: &str) -> String {
    let root = Path::new(upstream_root);
    let required = [
        "tools/include",
        "tools/include/uapi",
        "tools/testing/selftests/bpf/progs",
        "tools/testing/selftests/bpf/bpf_experimental.h",
    ];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|p| !root.join(p).exists())
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "Error: upstream_root='{upstream_root}' doesn't look like a kernel checkout — missing:"
        );
        for p in &missing {
            eprintln!("    {p}");
        }
        eprintln!(
            "Hint: pass the kernel-checkout root (e.g. `vendor/linux`), not the selftests dir."
        );
        std::process::exit(2);
    }
    root.join("tools/testing/selftests/bpf/progs")
        .to_string_lossy()
        .into_owned()
}

fn run_baseline_write_upstream(upstream_root: &str, out: &str, config: &VerifierConfig) {
    use crate::testing::selftest::runner::RunAll;

    let progs_dir_str = validate_upstream_root_progs_dir(upstream_root);

    let bl = sweep_upstream_only(&progs_dir_str, upstream_root, config, &RunAll);

    let total_files = bl.files.len();
    let compile_failed: usize = bl
        .files
        .values()
        .filter(|fe| fe.progs.len() == 1 && fe.progs.contains_key("<compile>"))
        .count();
    if total_files > 0 && compile_failed * 20 > total_files {
        eprintln!(
            "[selftest-baseline-write-upstream] WARNING: {compile_failed}/{total_files} files \
             collapsed to a single <compile> ERROR row — this almost always means \
             upstream_root or the toolchain is wrong (correct sweeps see <1% compile-failed). \
             Inspect a failing file with `dev selftest-file <path>` and the \
             stderr from clang to diagnose."
        );
    }

    if let Err(e) = bl.write(out) {
        eprintln!("Error writing {out}: {e:?}");
        return;
    }
    println!(
        "Wrote upstream baseline ({total_files} files, {compile_failed} compile-failed) to {out}"
    );
}

fn run_baseline_check(
    progs_dir: &str,
    legacy_json_dir: &str,
    stored: &str,
    config: &VerifierConfig,
) {
    use crate::testing::selftest::baseline::{Baseline, CheckFilter, DeterministicFilter, diff};

    let baseline = match Baseline::read(stored) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading baseline {stored}: {e:?}");
            std::process::exit(2);
        }
    };
    let det_filter = DeterministicFilter::from_baseline(&baseline);
    let check_filter = CheckFilter {
        filter: &det_filter,
        baseline: &baseline,
    };
    let current = sweep_modern_and_legacy(progs_dir, legacy_json_dir, config, &check_filter);
    let d = diff(&baseline, &current);

    print_diff(&d, "");
    if !d.regressions.is_empty() {
        std::process::exit(1);
    }
}

fn print_diff(d: &crate::testing::selftest::baseline::DiffReport, suffix: &str) {
    println!(
        "=== Baseline diff{} ===",
        if suffix.is_empty() {
            String::new()
        } else {
            format!(" {suffix}")
        }
    );
    println!("  unchanged: {}", d.unchanged);
    println!("  regressions: {}", d.regressions.len());
    println!("  new entries: {}", d.new_entries.len());
    println!("  removed entries: {}", d.removed_entries.len());

    for r in &d.regressions {
        let was = r.baseline.as_ref().map(|b| b.ours.as_str()).unwrap_or("?");
        let now = r.current.as_ref().map(|c| c.ours.as_str()).unwrap_or("?");
        println!("  REGRESSION  {}::{}  {was} -> {now}", r.file, r.prog);
    }
    for n in &d.new_entries {
        if let Some(c) = &n.current {
            println!("  NEW         {}::{}  ours={}", n.file, n.prog, c.ours);
        }
    }
    for r in &d.removed_entries {
        if let Some(b) = &r.baseline {
            println!("  REMOVED     {}::{}  was={}", r.file, r.prog, b.ours);
        } else {
            println!("  REMOVED     {}::{}", r.file, r.prog);
        }
    }
}

fn print_modern_report(report: &crate::testing::selftest::runner::FileReport) {
    use crate::testing::selftest::runner::Outcome;
    println!("\n--- {} ---", report.source.display());
    for p in &report.progs {
        let tag = match &p.outcome {
            Outcome::Pass => "PASS".to_string(),
            Outcome::FalseReject(e) => format!("FALSE-REJECT ({e})"),
            Outcome::FalseAccept => "FALSE-ACCEPT (soundness!)".into(),
            Outcome::Skipped(r) => format!("skip: {r}"),
            Outcome::OutOfScope(r) => format!("out-of-scope: {r}"),
            Outcome::Error(e) => format!("ERROR: {e}"),
        };
        println!("  [{tag}]  {} ({})", p.func_name, p.description);
    }
    println!("  ({} / {} pass)", report.pass_count(), report.total());
}
