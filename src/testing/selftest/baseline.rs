//! Baseline-snapshot machinery for the modern selftest pipeline.
//!
//! "Baseline" = a JSON file that records, per (source-file, program),
//! both the upstream expectation (`__success` / `__failure`) and the
//! verdict our verifier produced. It's written once after a clean
//! sweep and then used as a regression gate: future sweeps diff against
//! it, and any movement (a new FALSE_ACCEPT, a previous PASS becoming
//! TIMEOUT, …) fails the check.
//!
//! Improvements to the verifier are a *separate* workstream — the
//! baseline isn't a list of bugs to fix. It's a frozen description of
//! "what the verifier currently does," and only changes when we
//! intentionally update it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::runner::{FileReport, Outcome, ProgFilter};
use crate::testing::legacy_selftest::{
    FileResult as LegacyFileResult, TestOutcome as LegacyOutcome,
};

/// Compact stringly-typed verdicts. Strings rather than enum tags so
/// the JSON stays diff-friendly and human-grokkable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgEntry {
    /// `"ACCEPT"` / `"REJECT"` / `"UNANNOTATED"`.
    pub upstream: String,
    /// `"PASS"` / `"FALSE_REJECT"` / `"FALSE_ACCEPT"` / `"TIMEOUT"` /
    /// `"SKIPPED"` / `"ERROR"`.
    pub ours: String,
    /// Optional human-readable note (verifier error text, skip reason).
    /// Not used for diffing — only for at-a-glance debug.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Section the program lives in (`SEC("...")`). Useful for triage
    /// when names alone are ambiguous; not used for diffing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub progs: BTreeMap<String, ProgEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Kernel tag the sources + headers correspond to (`v6.15`).
    pub tag: String,
    pub generated_at: String,
    pub files: BTreeMap<String, FileEntry>,
}

impl Baseline {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            files: BTreeMap::new(),
        }
    }

    /// Fold legacy JSON-corpus results into an existing baseline. The
    /// JSON runner uses different verdict names (FalsePositive /
    /// FalseNegative); we map them onto the same wire labels the modern
    /// runner uses so a single baseline covers both. File keys are
    /// prefixed with `legacy/` to avoid collision with modern `.c`
    /// basenames.
    pub fn extend_with_legacy(&mut self, results: &[LegacyFileResult]) {
        for fr in results {
            let key = format!("legacy/{}", basename(&fr.file));
            let mut progs = BTreeMap::new();
            for t in &fr.tests {
                progs.insert(t.name.clone(), legacy_test_to_entry(t));
            }
            self.files.insert(
                key,
                FileEntry {
                    source: Some(fr.file.clone()),
                    progs,
                },
            );
        }
    }

    pub fn from_reports(tag: impl Into<String>, reports: &[FileReport]) -> Self {
        let mut bl = Self::new(tag);
        for report in reports {
            let key = report
                .source
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| report.source.display().to_string());
            let mut progs = BTreeMap::new();
            for p in &report.progs {
                progs.insert(name_for_entry(p), prog_to_entry(p));
            }
            bl.files.insert(
                key,
                FileEntry {
                    source: Some(report.source.display().to_string()),
                    progs,
                },
            );
        }
        bl
    }

    pub fn write<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let s = serde_json::to_string_pretty(self).context("serializing baseline")?;
        fs::write(path.as_ref(), s).with_context(|| format!("writing {}", path.as_ref().display()))
    }

    pub fn read<P: AsRef<Path>>(path: P) -> Result<Self> {
        let s = fs::read_to_string(path.as_ref())
            .with_context(|| format!("reading {}", path.as_ref().display()))?;
        serde_json::from_str(&s).context("parsing baseline JSON")
    }
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

fn legacy_test_to_entry(t: &crate::testing::legacy_selftest::TestResult) -> ProgEntry {
    let (ours, note) = match &t.outcome {
        LegacyOutcome::Pass => ("PASS", None),
        // FalsePositive in legacy = expected ACCEPT, got REJECT (precision).
        LegacyOutcome::FalsePositive => ("FALSE_REJECT", None),
        // FalseNegative = expected REJECT, got ACCEPT (soundness).
        LegacyOutcome::FalseNegative => ("FALSE_ACCEPT", None),
        LegacyOutcome::Skipped { reason } => ("SKIPPED", Some(reason.clone())),
        LegacyOutcome::Error { message } => {
            if message.contains("Complexity limit") || message.contains("timeout") {
                ("TIMEOUT", Some(message.clone()))
            } else {
                ("ERROR", Some(message.clone()))
            }
        }
    };
    // Legacy carries the upstream verdict directly in `expected`
    // (`"ACCEPT"` / `"REJECT"`).
    ProgEntry {
        upstream: t.expected.clone(),
        ours: ours.into(),
        note,
    }
}

fn name_for_entry(p: &super::runner::ProgReport) -> String {
    // Description is more readable; but two programs can share a
    // description across files, and within one file func_name is
    // unique. Use func_name as the key, fall back to description if
    // empty (some tests omit `__naked` and have an empty func_name).
    if !p.func_name.is_empty() {
        p.func_name.clone()
    } else if !p.description.is_empty() {
        p.description.clone()
    } else {
        "<unnamed>".to_string()
    }
}

fn prog_to_entry(p: &super::runner::ProgReport) -> ProgEntry {
    let (ours, note) = match &p.outcome {
        Outcome::Pass => ("PASS", None),
        Outcome::FalseReject(e) => ("FALSE_REJECT", Some(e.clone())),
        Outcome::FalseAccept => ("FALSE_ACCEPT", None),
        Outcome::Skipped(r) => ("SKIPPED", Some(r.clone())),
        Outcome::OutOfScope(r) => ("OUT_OF_SCOPE", Some(r.clone())),
        Outcome::Error(e) if e.starts_with("wallclock") => ("TIMEOUT", Some(e.clone())),
        Outcome::Error(e) => ("ERROR", Some(e.clone())),
    };
    let upstream = upstream_for(p);
    ProgEntry {
        upstream: upstream.into(),
        ours: ours.into(),
        note,
    }
}

/// Best-effort upstream verdict reconstruction from the recorded
/// outcome + skip reason. We don't carry the raw `__success`/`__failure`
/// flags through `ProgReport` today, so we infer:
///   - PASS / FALSE_REJECT  → upstream said ACCEPT (we matched or were too strict).
///   - FALSE_ACCEPT         → upstream said REJECT (we were too permissive).
///   - SKIPPED("no __success/__failure annotation") → UNANNOTATED.
///   - SKIPPED other        → unknown; we record what we can.
fn upstream_for(p: &super::runner::ProgReport) -> &'static str {
    match &p.outcome {
        Outcome::Pass | Outcome::FalseReject(_) => {
            // ACCEPT iff we treated it as ACCEPT-expected. Same logic
            // as the runner used to derive expected_accept; we re-derive
            // from outcome here.
            "ACCEPT"
        }
        Outcome::FalseAccept => "REJECT",
        Outcome::Skipped(r) if r.contains("no __success/__failure") => "UNANNOTATED",
        // Out-of-scope tests still have a real upstream verdict
        // (typically ACCEPT — the test is meant to load fine after
        // the missing pre-processing). We don't track it precisely
        // here because we never analyze the post-pre-processing form.
        Outcome::Skipped(_) | Outcome::Error(_) | Outcome::OutOfScope(_) => "UNKNOWN",
    }
}

/// Filter that lets the runner skip programs whose baseline outcome
/// is "non-deterministic in cost" — i.e. TIMEOUT, SKIPPED, ERROR. Re-
/// running these on a check just burns wallclock without yielding new
/// signal, since the only meaningful "regression" they could exhibit
/// is changing to PASS/FALSE_REJECT/FALSE_ACCEPT, and the inverse
/// (PASS turning into TIMEOUT) is already caught because PASS *is*
/// re-run. New programs not in the baseline are always run (the filter
/// returns `true` for unknown entries).
pub struct DeterministicFilter {
    runnable: std::collections::HashSet<(String, String)>,
}

impl DeterministicFilter {
    pub fn from_baseline(baseline: &Baseline) -> Self {
        let mut runnable = std::collections::HashSet::new();
        for (file, fe) in &baseline.files {
            for (prog, pe) in &fe.progs {
                if matches!(pe.ours.as_str(), "PASS" | "FALSE_REJECT" | "FALSE_ACCEPT") {
                    runnable.insert((file.clone(), prog.clone()));
                }
            }
        }
        Self { runnable }
    }

    /// True iff this (file, prog) pair was in the baseline at all
    /// (regardless of outcome). Used to decide between "skip because
    /// non-deterministic in baseline" and "run because new".
    fn is_known(&self, baseline: &Baseline, file: &str, prog: &str) -> bool {
        baseline
            .files
            .get(file)
            .and_then(|f| f.progs.get(prog))
            .is_some()
    }
}

/// Combine a [`DeterministicFilter`] with the baseline it derived from
/// so we can distinguish "known, non-deterministic" (skip) from "new
/// program" (run). The combined filter is what `selftest-baseline-check`
/// uses.
pub struct CheckFilter<'a> {
    pub filter: &'a DeterministicFilter,
    pub baseline: &'a Baseline,
}

impl<'a> ProgFilter for CheckFilter<'a> {
    fn should_run(&self, file: &str, prog: &str) -> bool {
        // Run if the program is deterministic in baseline (PASS/FALSE_*)
        // or if it isn't in the baseline at all (new program).
        if self.filter.runnable.contains(&(file.into(), prog.into())) {
            return true;
        }
        !self.filter.is_known(self.baseline, file, prog)
    }
}

/// Diff a fresh report against a stored baseline. A "regression" is any
/// (file, prog) where the new `ours` field differs from the recorded
/// one. New entries (present in fresh, absent from baseline) are
/// reported separately so they show up but don't fail the gate.
#[derive(Debug, Default)]
pub struct DiffReport {
    pub regressions: Vec<DiffEntry>,
    pub new_entries: Vec<DiffEntry>,
    pub removed_entries: Vec<DiffEntry>,
    pub unchanged: usize,
}

#[derive(Debug, Clone)]
pub struct DiffEntry {
    pub file: String,
    pub prog: String,
    pub baseline: Option<ProgEntry>,
    pub current: Option<ProgEntry>,
}

pub fn diff(baseline: &Baseline, current: &Baseline) -> DiffReport {
    let mut out = DiffReport::default();
    for (file, fresh_file) in &current.files {
        let baseline_file = baseline.files.get(file);
        for (prog, fresh) in &fresh_file.progs {
            let stored = baseline_file.and_then(|f| f.progs.get(prog));
            // A `current` entry that was deliberately filtered out at
            // run time (the baseline-check fast path) carries
            // `ours = SKIPPED` with the "filtered" sentinel note. Treat
            // it as agreeing with the baseline so it doesn't count as a
            // regression — the whole point of filtering is to trust
            // the baseline for known non-deterministic rows.
            let was_filtered = fresh.ours == "SKIPPED"
                && fresh
                    .note
                    .as_deref()
                    .map(|n| n.starts_with("filtered"))
                    .unwrap_or(false);
            match stored {
                None => out.new_entries.push(DiffEntry {
                    file: file.clone(),
                    prog: prog.clone(),
                    baseline: None,
                    current: Some(fresh.clone()),
                }),
                Some(_) if was_filtered => out.unchanged += 1,
                Some(s) if s.ours != fresh.ours => out.regressions.push(DiffEntry {
                    file: file.clone(),
                    prog: prog.clone(),
                    baseline: Some(s.clone()),
                    current: Some(fresh.clone()),
                }),
                Some(_) => out.unchanged += 1,
            }
        }
    }
    // Removed: in baseline but missing from current.
    for (file, baseline_file) in &baseline.files {
        let fresh_file = current.files.get(file);
        for (prog, stored) in &baseline_file.progs {
            let fresh = fresh_file.and_then(|f| f.progs.get(prog));
            if fresh.is_none() {
                out.removed_entries.push(DiffEntry {
                    file: file.clone(),
                    prog: prog.clone(),
                    baseline: Some(stored.clone()),
                    current: None,
                });
            }
        }
    }
    out
}
