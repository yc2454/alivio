use std::fs;
use std::path::Path;

use crate::analysis;
use crate::common::config::{DomainMode, VerifierConfig};
use crate::domains::dbm::Dbm;
use crate::parsing::bpf_insn::RawBpfInsn;
use crate::parsing::bpf_to_ast::lower_raw_to_program;
use crate::pcc::{ProgramCertificate, generate_certificate};
use crate::testing::legacy_selftest::{
    JsonTestCase, TestOutcome, build_exec_context, make_entry_state, run_test,
};
use serde::Deserialize;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcc::ProofStep;

    fn proof_has_compose(steps: &[ProofStep]) -> bool {
        for step in steps {
            match step {
                ProofStep::Compose { left, right, .. } => {
                    return true || proof_has_compose(left) || proof_has_compose(right);
                }
                _ => {}
            }
        }
        false
    }

    fn cert_has_compose(cert: &ProgramCertificate) -> bool {
        cert.pc_annotations
            .iter()
            .any(|ann| ann.entries.iter().any(|e| proof_has_compose(&e.proof)))
    }

    #[test]
    fn transitive_compose_example_emits_compose_step() {
        let json_path = "pcc-tests/pcc_examples.json";
        let content = fs::read_to_string(json_path).expect("read pcc_examples.json");
        let tests: Vec<JsonTestCase> =
            serde_json::from_str(&content).expect("parse pcc_examples.json");
        let test = tests
            .into_iter()
            .find(|t| t.name.contains("transitive compose"))
            .expect("transitive compose case present");

        let raw_insns: Vec<RawBpfInsn> = test.insns.iter().map(|j| j.into()).collect();
        let program = lower_raw_to_program(&raw_insns).expect("lower program");
        let (ctx, has_unsupported_fixup) = build_exec_context(&test);
        assert!(
            !has_unsupported_fixup,
            "transitive compose case should not need unsupported fixups"
        );

        let mut config = VerifierConfig::default();
        config.domain_mode = DomainMode::Zone;

        // Zone analysis with provenance enabled for PCC.
        let mut entry = make_entry_state();
        entry.enable_provenance();
        let zone_result = analysis::analyze_program_full(&ctx, &program, entry, &config);
        let zone_dbms = zone_result.dbms;

        // Interval analysis to collect states.
        let mut interval_config = config.clone();
        interval_config.domain_mode = DomainMode::Interval;
        interval_config.certificate = None;
        let interval_entry = Dbm::new();
        let interval_result =
            analysis::analyze_program_full(&ctx, &program, interval_entry, &interval_config);
        let n = program.instrs.len();
        let interval_states: Vec<_> = (0..n)
            .map(|pc| {
                interval_result
                    .explored_states
                    .get(&pc)
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| {
                        crate::analysis::machine::state::State::new(
                            crate::domains::numeric::NumericDomain::new_interval(),
                            pc,
                        )
                    })
            })
            .collect();

        let cert = generate_certificate(&program, &zone_dbms, &interval_states, &ctx.map_defs);

        assert!(
            cert_has_compose(&cert),
            "expected generated certificate to include a Compose proof step"
        );
    }
}

fn slugify_test_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_sep = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }
    let out = out.trim_matches('_');
    if out.is_empty() {
        "unnamed_test".to_string()
    } else {
        out.to_string()
    }
}

fn default_generated_cert_path(json_path: &str, test_name: &str, program_hash: &str) -> String {
    let suite = Path::new(json_path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "pcc_suite".to_string());
    let test = slugify_test_name(test_name);
    format!(
        "pcc-tests/certs/generated/{}.{}.{}.cert.json",
        suite, test, program_hash
    )
}

/// Run a single PCC test by exact name from a JSON file.
///
/// Orchestrates the full workflow:
///   Stage 1 — primary verification (zone or interval+cert depending on `config`)
///   Stages 2-4 — certificate generation pipeline, only when zone mode passes
pub fn pcc_test_single(json_path: &str, test_name: &str, config: &VerifierConfig) {
    println!(
        "Running single PCC test: '{}' from {}\n",
        test_name, json_path
    );

    let content = match fs::read_to_string(json_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to read {}: {}", json_path, e);
            return;
        }
    };
    let tests: Vec<JsonTestCase> = match serde_json::from_str(&content) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: Failed to parse {}: {}", json_path, e);
            return;
        }
    };

    let matching: Vec<_> = tests.iter().filter(|t| t.name == test_name).collect();
    if matching.is_empty() {
        eprintln!("Error: No test matching '{}' found", test_name);
        return;
    }
    if matching.len() > 1 {
        eprintln!("Error: Duplicate test name '{}'", test_name);
        return;
    }

    let test = matching[0];
    println!("Test: {}", test.name);
    println!("Expected: {}", test.result);
    println!("Instructions: {}", test.insns.len());
    println!();

    // Stage 1: primary verification (zone or interval+cert).
    let stage1_label = if config.domain_mode == DomainMode::Zone {
        "Zone analysis"
    } else {
        "Interval + certificate verification"
    };
    println!("========= Stage 1: {} =========", stage1_label);
    let result = run_test(test, config);

    // Stages 2-4: certificate generation (zone mode, passed only).
    // Generate certs when zone passes (traditional PCC: zone ok, interval reject)
    // AND when zone has a precision issue (map PCC: zone's relational data is still
    // useful even though zone's own access check fails for variable map offsets).
    let should_generate_cert = matches!(
        result.outcome,
        TestOutcome::Pass | TestOutcome::FalsePositive
    ) && config.domain_mode == DomainMode::Zone;
    if should_generate_cert {
        pcc_generate_cert(test, json_path, test_name, config);
    }

    println!();
    match &result.outcome {
        TestOutcome::Pass => println!("========= PASS ========= ({}ms)", result.time_ms),
        TestOutcome::FalseNegative => {
            println!(
                "========= !!! SOUNDNESS ISSUE !!! ========= ({}ms)",
                result.time_ms
            )
        }
        TestOutcome::FalsePositive => {
            println!("========= PRECISION ISSUE ========= ({}ms)", result.time_ms)
        }
        TestOutcome::Skipped { reason } => {
            println!(
                "========= SKIPPED ========= ({}ms) {}",
                result.time_ms, reason
            )
        }
        TestOutcome::Error { message } => {
            println!(
                "========= ERROR ========= ({}ms) {}",
                result.time_ms, message
            )
        }
    }
}

/// Certificate generation pipeline (Stages 2–4).
///
/// Called only after Stage 1 zone verification has passed.  Runs zone analysis
/// again to collect per-PC DBMs, runs interval analysis to collect pre-failure
/// explored states, then combines them into a v2 certificate and writes it to
/// disk.
fn pcc_generate_cert(
    test: &JsonTestCase,
    json_path: &str,
    test_name: &str,
    config: &VerifierConfig,
) {
    let raw_insns: Vec<RawBpfInsn> = test.insns.iter().map(|j| j.into()).collect();
    let program = match lower_raw_to_program(&raw_insns) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "Warning: cannot generate certificate, lowering failed: {:?}",
                e
            );
            return;
        }
    };
    let (ctx, has_unsupported_fixup) = build_exec_context(test);
    if has_unsupported_fixup {
        eprintln!("Warning: certificate generation skipped due to unsupported fixup type");
        return;
    }

    // Stage 2: run zone analysis to collect per-PC DBMs.
    // Use analyze_program_full so we keep DBMs even when zone rejects —
    // the relational facts (e.g. r6-r7 from a branch) are still useful for
    // PCC even if zone's own access check fails (e.g. variable map offsets).
    println!("\n========= Stage 2: Zone DBM collection (for certificate generation) =========");
    let mut entry = make_entry_state();
    entry.enable_provenance(); // PCC generation needs provenance for Compose proofs
    let zone_result = analysis::analyze_program_full(&ctx, &program, entry, config);
    let zone_dbms = zone_result.dbms;

    // Stage 3: run interval analysis to collect pre-failure explored states.
    // Interval mode is expected to reject — that is the PCC motivation.
    println!("\n========= Stage 3: Interval analysis =========");
    println!("  (Interval mode is expected to reject — this is the PCC motivation.)");
    let mut interval_config = config.clone();
    interval_config.domain_mode = DomainMode::Interval;
    interval_config.certificate = None;
    let interval_entry = Dbm::new(); // Interval mode ignores the entry DBM
    let interval_result =
        analysis::analyze_program_full(&ctx, &program, interval_entry, &interval_config);
    println!("  [ok] Interval analysis complete (reject is expected here).");
    // Build a flat per-PC state vector from the explored_states map.
    // For straightline programs there is exactly one state per PC.
    let n = program.instrs.len();
    let interval_states: Vec<_> = (0..n)
        .map(|pc| {
            interval_result
                .explored_states
                .get(&pc)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| {
                    crate::analysis::machine::state::State::new(
                        crate::domains::numeric::NumericDomain::new_interval(),
                        pc,
                    )
                })
        })
        .collect();

    // Stage 4: combine DBMs + interval states to produce and persist the cert.
    println!("\n========= Stage 4: Certificate generation =========");
    let cert = generate_certificate(&program, &zone_dbms, &interval_states, &ctx.map_defs);
    let output_path = config
        .certificate_output
        .clone()
        .unwrap_or_else(|| default_generated_cert_path(json_path, test_name, &cert.program_hash));
    if let Some(parent) = Path::new(&output_path).parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!(
            "Warning: failed to create certificate directory '{}': {}",
            parent.display(),
            e
        );
        return;
    }
    match cert.save_to_path(&output_path) {
        Ok(()) => {
            if config.certificate_output.is_some() {
                println!("Certificate written: {}", output_path);
            } else {
                println!("Certificate auto-written: {}", output_path);
            }
        }
        Err(e) => eprintln!(
            "Warning: failed to write certificate '{}': {e:#}",
            output_path
        ),
    }
    println!();
    println!("{cert}");
}

#[derive(Debug, Deserialize)]
struct PccCertCase {
    name: String,
    json_file: String,
    test_name: String,
    certificate: String,
    expected: String,
}

/// Run manifest-defined certificate cases with kernel-mode semantics.
pub fn pcc_cert_run(manifest_path: &str, config: &VerifierConfig) {
    println!("Running PCC certificate cases: {}\n", manifest_path);
    let content = match fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to read {}: {}", manifest_path, e);
            return;
        }
    };
    let cases: Vec<PccCertCase> = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: Failed to parse {}: {}", manifest_path, e);
            return;
        }
    };

    let mut passed = 0usize;
    let mut failed = 0usize;
    for case in &cases {
        let test_content = match fs::read_to_string(&case.json_file) {
            Ok(c) => c,
            Err(e) => {
                println!("[FAIL] {}: read test file: {}", case.name, e);
                failed += 1;
                continue;
            }
        };
        let tests: Vec<JsonTestCase> = match serde_json::from_str(&test_content) {
            Ok(t) => t,
            Err(e) => {
                println!("[FAIL] {}: parse test file: {}", case.name, e);
                failed += 1;
                continue;
            }
        };
        let Some(test) = tests.iter().find(|t| t.name == case.test_name) else {
            println!("[FAIL] {}: test '{}' not found", case.name, case.test_name);
            failed += 1;
            continue;
        };
        let cert = match ProgramCertificate::load_from_path(&case.certificate) {
            Ok(c) => c,
            Err(e) => {
                println!("[FAIL] {}: load cert failed: {e:#}", case.name);
                failed += 1;
                continue;
            }
        };

        let mut cfg = config.clone();
        cfg.domain_mode = DomainMode::Interval;
        cfg.detect_bounded_loops = false;
        cfg.require_single_loop_entry = true;
        cfg.certificate = Some(cert);

        let result = run_test(test, &cfg);
        if result.actual == case.expected {
            println!("[PASS] {} => {}", case.name, result.actual);
            passed += 1;
        } else {
            println!(
                "[FAIL] {} => expected {}, got {}",
                case.name, case.expected, result.actual
            );
            failed += 1;
        }
    }

    println!(
        "\nPCC certificate case summary: {}/{} passed, {} failed",
        passed,
        passed + failed,
        failed
    );
}
