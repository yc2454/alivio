//! cvc5 solver dispatch.
//!
//! Drives a BCF-patched cvc5 binary to produce a BCF-format proof from an
//! SMT-LIB v2 query. Treated as a black-box subprocess — we feed SMT-LIB,
//! collect the raw proof bytes from a file the solver writes.
//!
//! Working invocation:
//! ```text
//! cvc5 --produce-proofs --dump-proofs --proof-format=bcf \
//!      --bcf-proof-out=<output.bcf> <input.smt2>
//! ```
//!
//! Successful run prints `unsat` on stdout and writes the binary proof to the
//! file named by `--bcf-proof-out`. cvc5 also emits a `(...)` block with
//! statistics; we ignore stdout entirely.
//!
//! ## Environment
//!
//! By default we look at `$ALIVIO_CVC5` and then the macOS dev path
//! `/Users/yalucai/cvc5-bcf/install/bin/cvc5`. Override via the env var.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_CVC5_MACOS: &str = "/Users/yalucai/cvc5-bcf/install/bin/cvc5";
const DEFAULT_CVC5_LINUX: &str = "/users/yc1795/BCF/output/cvc5-libs/bin/cvc5";

// Linux-only: bcf-checker is the kernel-equivalent userspace proof validator
// (built from the synced kernel `bcf_checker.c`). Used as a soundness oracle.
#[allow(dead_code)]
const DEFAULT_BCF_CHECKER_LINUX: &str = "/users/yc1795/BCF/bcf-checker/bcf-checker";

#[derive(Debug)]
pub enum SolverError {
    Io(std::io::Error),
    /// cvc5 exited non-zero. `code` is the process exit code (or `None` if killed
    /// by signal). `stderr` is its stderr output, truncated.
    SolverFailed {
        code: Option<i32>,
        stderr: String,
    },
    /// cvc5 returned a `sat` or `unknown` answer — proof not produced.
    NotUnsat(String),
    /// Configured cvc5 binary doesn't exist or isn't executable.
    CvcBinaryMissing(PathBuf),
}

impl std::fmt::Display for SolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolverError::Io(e) => write!(f, "io: {}", e),
            SolverError::SolverFailed { code, stderr } => {
                write!(f, "cvc5 exited with code {:?}; stderr: {}", code, stderr)
            }
            SolverError::NotUnsat(s) => write!(f, "cvc5 did not return unsat: {}", s),
            SolverError::CvcBinaryMissing(p) => {
                write!(f, "cvc5 binary not found at {}", p.display())
            }
        }
    }
}

impl std::error::Error for SolverError {}

impl From<std::io::Error> for SolverError {
    fn from(e: std::io::Error) -> Self {
        SolverError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, SolverError>;

/// Locate the BCF-format proof checker binary (Linux-only). Returns `None`
/// when it's not present — this is the expected case on macOS dev hosts.
///
/// Precedence: `$ALIVIO_BCF_CHECKER`, then the Linux default.
#[allow(dead_code)]
pub fn bcf_checker_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ALIVIO_BCF_CHECKER") {
        let pb = PathBuf::from(p);
        return pb.exists().then_some(pb);
    }
    let pb = PathBuf::from(DEFAULT_BCF_CHECKER_LINUX);
    pb.exists().then_some(pb)
}

/// Pipe `bytes` through the BCF proof checker. Returns `Ok(())` when the
/// checker accepts the proof. Returns `Ok(())` AND emits no work when the
/// checker isn't present (e.g., on macOS) — the caller should treat this as
/// "no oracle available", not "validated".
///
/// This is the soundness backstop: even if cvc5 emits a proof that's
/// syntactically well-formed BCF, the checker is what confirms it actually
/// establishes the refinement condition under the kernel's rule semantics.
#[allow(dead_code)]
pub fn validate_proof_bytes(bytes: &[u8]) -> Result<bool> {
    let Some(checker) = bcf_checker_path() else {
        return Ok(false); // no oracle available
    };

    // bcf-checker takes a proof file path as its arg.
    let tmp = tempdir()?;
    let proof_path = tmp.path().join("proof.bcf");
    std::fs::write(&proof_path, bytes)?;

    let output = Command::new(&checker).arg(&proof_path).output()?;

    if !output.status.success() {
        let stderr = truncate(String::from_utf8_lossy(&output.stderr).into_owned(), 1024);
        let stdout = truncate(String::from_utf8_lossy(&output.stdout).into_owned(), 1024);
        return Err(SolverError::SolverFailed {
            code: output.status.code(),
            stderr: format!(
                "bcf-checker rejected; stdout: {}; stderr: {}",
                stdout, stderr
            ),
        });
    }

    Ok(true)
}

/// Locate the BCF-patched cvc5 binary.
///
/// Precedence: `$ALIVIO_CVC5`, then platform default (macOS dev path, then Linux
/// build path). Returns `CvcBinaryMissing` if none exists.
pub fn cvc5_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("ALIVIO_CVC5") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Ok(pb);
        }
        return Err(SolverError::CvcBinaryMissing(pb));
    }
    for candidate in [DEFAULT_CVC5_MACOS, DEFAULT_CVC5_LINUX] {
        let pb = PathBuf::from(candidate);
        if pb.exists() {
            return Ok(pb);
        }
    }
    Err(SolverError::CvcBinaryMissing(PathBuf::from(
        DEFAULT_CVC5_MACOS,
    )))
}

/// Send `smtlib` to cvc5 and return the raw BCF proof bytes.
///
/// Internally writes SMT-LIB to a temp file (cvc5's stdin support is fine for
/// the formula, but we use a file for symmetry with the proof output and to
/// keep the invocation cacheable later).
///
/// Returns `Err(NotUnsat)` if cvc5 reported `sat` or `unknown` — i.e., the
/// refinement condition isn't unsat, so the program isn't safe.
pub fn solve(smtlib: &str) -> Result<Vec<u8>> {
    // Memo cache: `solve` is a pure function of the SMT-LIB text, and
    // verification wall-time is dominated by cvc5 process spawns.
    // Kernel-parity exploration re-derives the SAME goal at many states
    // (per-arm/per-path discharges of identical conditions), so identical
    // queries repeat heavily. Cache BOTH directions: unsat proof bytes
    // and NotUnsat verdicts (sat/unknown gate path-unreachable decisions
    // and repeat just as much). Keyed by the full query text — no
    // hash-collision risk on proof reuse. Infra-only: same input, same
    // output, no verifier-behavior change.
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock};
    static MEMO: OnceLock<Mutex<HashMap<String, std::result::Result<Vec<u8>, String>>>> =
        OnceLock::new();
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);
    let calls = CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    let memo = MEMO.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = memo.lock().unwrap().get(smtlib) {
        let hits = HITS.fetch_add(1, Ordering::Relaxed) + 1;
        if std::env::var("ALIVIO_SOLVER_STATS").is_ok() && hits.is_multiple_of(500) {
            eprintln!("[solver] calls={} memo_hits={}", calls, hits);
        }
        return match cached {
            Ok(bytes) => Ok(bytes.clone()),
            Err(msg) => Err(SolverError::NotUnsat(msg.clone())),
        };
    }
    if std::env::var("ALIVIO_SOLVER_STATS").is_ok() && calls.is_multiple_of(500) {
        eprintln!(
            "[solver] calls={} memo_hits={}",
            calls,
            HITS.load(Ordering::Relaxed)
        );
    }
    let outcome = solve_uncached(smtlib);
    match &outcome {
        Ok(bytes) => {
            memo.lock()
                .unwrap()
                .insert(smtlib.to_string(), Ok(bytes.clone()));
        }
        Err(SolverError::NotUnsat(msg)) => {
            memo.lock()
                .unwrap()
                .insert(smtlib.to_string(), Err(msg.clone()));
        }
        // Io / SolverFailed / CvcBinaryMissing are environmental — don't cache.
        Err(_) => {}
    }
    outcome
}

fn solve_uncached(smtlib: &str) -> Result<Vec<u8>> {
    let cvc5 = cvc5_path()?;

    // Write SMT-LIB and proof bytes to a per-call temp dir we own end-to-end.
    let tmp = tempdir()?;
    let smt_path = tmp.path().join("query.smt2");
    let proof_path = tmp.path().join("proof.bcf");
    {
        let mut f = std::fs::File::create(&smt_path)?;
        f.write_all(smtlib.as_bytes())?;
    }
    if let Ok(dump_dir) = std::env::var("ALIVIO_BCF_DUMP_SMT") {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::path::Path::new(&dump_dir).join(format!("query_{:04}.smt2", n));
        let _ = std::fs::create_dir_all(&dump_dir);
        let _ = std::fs::write(&path, smtlib);
    }

    let output = Command::new(&cvc5)
        .arg("--produce-proofs")
        .arg("--dump-proofs")
        .arg("--proof-format=bcf")
        // CRITICAL for Sound-PASS: the default `--proof-granularity=macro`
        // produces proof steps that cvc5 emits via `int.pow2` rewrites for
        // bvand+bvlshr combinations (and other bitwise patterns the kernel
        // BV solver doesn't model). bcf-checker silently rejects those with
        // -EINVAL. `theory-rewrite` granularity expands the macros into a
        // sequence of finer steps — each individual step may still be
        // emitted as "trusted" (lots of `WARNING: applying trusted step
        // rewrite` lines at check time), but the overall structure is
        // shaped so the checker can walk it.
        .arg("--proof-granularity=theory-rewrite")
        .arg(format!("--bcf-proof-out={}", proof_path.display()))
        .arg(&smt_path)
        .output()?;

    if !output.status.success() {
        let stderr = truncate(String::from_utf8_lossy(&output.stderr).into_owned(), 2048);
        return Err(SolverError::SolverFailed {
            code: output.status.code(),
            stderr,
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // cvc5 prints `unsat` or `sat` or `unknown` on its first stdout line.
    let first = stdout.lines().next().unwrap_or("").trim();
    if first != "unsat" {
        return Err(SolverError::NotUnsat(truncate(stdout.into_owned(), 1024)));
    }

    let bytes = std::fs::read(&proof_path)?;
    if bytes.is_empty() {
        return Err(SolverError::NotUnsat(format!(
            "cvc5 reported unsat but proof file is empty: {}",
            proof_path.display()
        )));
    }
    Ok(bytes)
}

// ---------- small helpers ----------

fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        s.truncate(max);
        s.push_str("…[truncated]");
    }
    s
}

/// Minimal tempdir wrapper: creates `$TMPDIR/alivio-bcf-<rand>/` and removes it
/// on drop. Avoids pulling in the `tempfile` crate for one use site.
struct TempDir(PathBuf);

impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> std::io::Result<TempDir> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    // pid + timestamp alone can collide across threads (same pid, quantized
    // clock); the process-wide counter makes the name unique.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = std::env::temp_dir();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = base.join(format!("alivio-bcf-{}-{}-{}", pid, stamp, seq));
    std::fs::create_dir(&dir)?;
    Ok(TempDir(dir))
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refinement::bcf::{BCF_MAGIC, BcfProof};

    /// Smoke test: feed cvc5 a trivially-unsat QF_BV query, confirm we get
    /// back well-formed BCF bytes. Skipped if cvc5 binary isn't found
    /// (e.g., on CI without the toolchain).
    #[test]
    fn solve_toy_unsat() {
        if cvc5_path().is_err() {
            eprintln!("[skip] cvc5 binary not found; set ALIVIO_CVC5 to enable");
            return;
        }

        let smtlib = "\
            (set-logic QF_BV)\n\
            (declare-const x (_ BitVec 64))\n\
            (assert (bvugt (bvand x #x000000000000000F) #x000000000000000F))\n\
            (check-sat)\n";

        let bytes = solve(smtlib).expect("solve failed");
        assert!(bytes.len() >= 12, "proof must include header");
        // Confirm BCF magic bytes (little-endian 0x0BCF).
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(magic, BCF_MAGIC);

        // Parser must accept it — strongest cross-check of the round-trip.
        let _proof = BcfProof::from_bytes(&bytes).expect("BCF parse failed on cvc5 output");
    }

    /// SAT formulas don't produce proofs; we should return `NotUnsat` cleanly.
    #[test]
    fn solve_sat_returns_not_unsat() {
        if cvc5_path().is_err() {
            return;
        }
        let smtlib = "\
            (set-logic QF_BV)\n\
            (declare-const x (_ BitVec 8))\n\
            (assert (= x #x00))\n\
            (check-sat)\n";
        match solve(smtlib) {
            Err(SolverError::NotUnsat(_)) => {} // expected
            other => panic!("expected NotUnsat, got {:?}", other),
        }
    }
}
