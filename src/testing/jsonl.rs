//! JSONL corpus emitter.
//!
//! Single Rust entrypoint for downstream Python harnesses (bcf-benchmark,
//! prevail, baseline diffing). Walks an ELF directory, runs the verifier
//! on every code section, and emits one JSON object per line to stdout.
//!
//! Schema (one line per record):
//!   {"file": "rel/path/foo.o", "section": "tc/foo",
//!    "status": "PASS"|"FAIL"|"TIMEOUT"|"LOAD_ERROR",
//!    "time_ms": 42,
//!    "error": "..."  // only when status != PASS
//!   }
//!
//! `LOAD_ERROR` is per-file (no `section`); the verifier never got far
//! enough to enumerate sections. All other statuses are per-section.
//!
//! Determinism: files are visited in sorted order (the underlying `read_dir`
//! is platform-dependent, so we sort explicitly). Sections inside a file
//! are processed in the order `list_section_names` returns them — that
//! mirrors ELF section-header order, which is stable across runs of clang.

use crate::common::config::VerifierConfig;
use crate::parsing::elf::list_section_names;
use crate::testing::runner::{AnalysisResult, Analyzer, is_code_section};
use serde_json::json;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub fn emit_corpus_jsonl(
    root: Option<&Path>,
    input_list: Option<&Path>,
    out_path: Option<&Path>,
    config: &VerifierConfig,
) -> std::io::Result<()> {
    let mut files: Vec<PathBuf> = Vec::new();

    // Source the file list from --input-list if given, else walk `root`.
    // Python harnesses prefer --input-list because it lets them pre-filter
    // by project/compiler/opt without the verifier wasting time on rows
    // that will be discarded.
    if let Some(list_path) = input_list {
        let content = std::fs::read_to_string(list_path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                files.push(PathBuf::from(trimmed));
            }
        }
    } else if let Some(r) = root {
        collect_elf_files(r, &mut files)?;
        files.sort();
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "verify-corpus: provide a directory or --input-list FILE",
        ));
    }

    // `file` field is path relative to `root` when walking, or just the
    // raw path when using --input-list (callers know what they passed).
    let strip_root: Option<&Path> = if input_list.is_none() { root } else { None };

    // Two writers so Python orchestration can get a clean stream: pass
    // `--out FILE` and the verifier's own println! chatter on stdout
    // can be discarded without losing JSONL records.
    let stdout = std::io::stdout();
    let mut file_writer = match out_path {
        Some(p) => Some(BufWriter::new(std::fs::File::create(p)?)),
        None => None,
    };
    let mut stdout_writer = if file_writer.is_none() {
        Some(BufWriter::new(stdout.lock()))
    } else {
        None
    };

    for path in &files {
        let rel = match strip_root {
            Some(r) => path
                .strip_prefix(r)
                .unwrap_or(path)
                .to_string_lossy()
                .into_owned(),
            None => path.to_string_lossy().into_owned(),
        };
        if let Some(w) = file_writer.as_mut() {
            emit_for_file(path, &rel, config, w)?;
        } else if let Some(w) = stdout_writer.as_mut() {
            emit_for_file(path, &rel, config, w)?;
        }
    }

    if let Some(mut w) = file_writer {
        w.flush()?;
    }
    if let Some(mut w) = stdout_writer {
        w.flush()?;
    }
    Ok(())
}

fn collect_elf_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        // A single file invocation is also useful — if `root` is a `.o`,
        // emit just that. Keeps the contract symmetric with shell tools
        // that take either a file or a directory.
        if dir.extension().and_then(|e| e.to_str()) == Some("o") {
            out.push(dir.to_path_buf());
        }
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_elf_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("o") {
            out.push(path);
        }
    }
    Ok(())
}

fn emit_for_file<W: Write>(
    path: &Path,
    rel: &str,
    config: &VerifierConfig,
    out: &mut W,
) -> std::io::Result<()> {
    // Enumerate sections first; if even that fails the file is broken.
    let sections = match list_section_names(path.to_str().unwrap_or("")) {
        Ok(s) => s,
        Err(e) => {
            writeln!(
                out,
                "{}",
                json!({
                    "file": rel,
                    "status": "LOAD_ERROR",
                    "error": format!("{:?}", e),
                })
            )?;
            return Ok(());
        }
    };

    let analyzer = Analyzer::new(path.to_str().unwrap_or(""), config.clone());
    for section in sections {
        if !is_code_section(&section) {
            continue;
        }
        let started = Instant::now();
        let result = analyzer.analyze_section(&section);
        let time_ms = started.elapsed().as_millis() as u64;

        let (status, error) = match result {
            AnalysisResult::Pass => ("PASS", None),
            AnalysisResult::Fail(e) => ("FAIL", Some(e.description().to_string())),
            AnalysisResult::Timeout => ("TIMEOUT", None),
            AnalysisResult::LoadError(e) => ("LOAD_ERROR", Some(e)),
            AnalysisResult::OutOfScope(r) => ("OUT_OF_SCOPE", Some(r)),
        };

        let mut record = json!({
            "file": rel,
            "section": section,
            "status": status,
            "time_ms": time_ms,
        });
        if let Some(msg) = error {
            record["error"] = json!(msg);
        }
        writeln!(out, "{}", record)?;
    }
    Ok(())
}
