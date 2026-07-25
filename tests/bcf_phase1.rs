//! Phase 1 existence-proof lock-in. Confirms `verify --bcf` on
//! `shift_constraint.bpf.o`:
//!   1. Returns ACCEPT (would REJECT without `--bcf`).
//!   2. Writes a `.bcf-bundle` sidecar with the right magic.
//!   3. Optionally (Linux-only when `$ZOVIA_BCF_CHECKER` is set): the
//!      embedded cvc5 proof bytes pass the BCF kernel proof checker
//!      — the actual soundness gate.
//!
//! Vendored fixture: `bcf-tests/shift_constraint.bpf.o` (+ `.c` source).
//!
//! Skipped when cvc5 isn't present on the dev box (no `$ZOVIA_CVC5`,
//! no platform default). Without cvc5 there's nothing to test.

use std::path::PathBuf;
use std::process::Command;

const BCF_MAGIC_LE: [u8; 4] = [0xcf, 0x0b, 0x00, 0x00];
const BCF_BUNDLE_MAGIC_LE: [u8; 4] = [b'B', b'C', b'F', b'B'];

/// Mirror of `solver::cvc5_path` lookup; we can't depend on the bin
/// crate from an integration test cleanly, so duplicate the cheap
/// existence check. False = skip the test.
fn cvc5_available() -> bool {
    if let Ok(p) = std::env::var("ZOVIA_CVC5") {
        if std::path::Path::new(&p).exists() {
            return true;
        }
    }
    for cand in [
        "/Users/yalucai/cvc5-bcf/install/bin/cvc5",
        "/users/yc1795/BCF/output/cvc5-libs/bin/cvc5",
    ] {
        if std::path::Path::new(cand).exists() {
            return true;
        }
    }
    false
}

#[test]
fn phase1_shift_constraint_accepts_with_bcf() {
    if !cvc5_available() {
        eprintln!("[skip] cvc5 binary not found; set ZOVIA_CVC5");
        return;
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let prog = manifest_dir
        .join("bcf-tests")
        .join("shift_constraint.bpf.o");
    assert!(prog.exists(), "fixture missing: {}", prog.display());

    let bundle = manifest_dir
        .join("bcf-tests")
        .join("shift_constraint.bpf.o.bcf-bundle");
    let _ = std::fs::remove_file(&bundle); // start from a clean slate

    let output = Command::new(env!("CARGO_BIN_EXE_zovia"))
        .arg("--bcf")
        .arg("-q")
        .arg("verify")
        .arg(&prog)
        .current_dir(&manifest_dir)
        .output()
        .expect("failed to run zovia --bcf verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "verify exited {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Pass:   1") || stdout.contains("Pass:\t1"),
        "expected 1 passing section; stdout:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("Stack out of bounds"),
        "rejection leaked through despite --bcf:\n{}",
        stdout
    );

    // --- Bundle sidecar checks ---
    assert!(bundle.exists(), "expected bundle at {}", bundle.display());
    let bytes = std::fs::read(&bundle).expect("read bundle");
    assert!(bytes.len() >= 40, "bundle too small: {}", bytes.len());
    assert_eq!(&bytes[0..4], &BCF_BUNDLE_MAGIC_LE, "bad bundle magic");
    let entry_cnt = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    assert_eq!(entry_cnt, 1, "expected exactly one refinement entry");
    // Entry layout (28 B starting at byte 16):
    //   0..8   cond_hash
    //   8..12  goal_off
    //   12..16 goal_size
    //   16..20 proof_off
    //   20..24 proof_size
    //   24..28 kind
    let proof_off = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    let proof_sz = u32::from_le_bytes(bytes[36..40].try_into().unwrap()) as usize;
    assert!(
        proof_off + proof_sz <= bytes.len(),
        "proof slice OOB: off={}, sz={}, total={}",
        proof_off,
        proof_sz,
        bytes.len()
    );
    let proof = &bytes[proof_off..proof_off + proof_sz];
    assert!(proof.len() >= 12, "proof has no header");
    assert_eq!(&proof[0..4], &BCF_MAGIC_LE, "proof missing BCF magic");

    // --- Optional Sound-PASS gate (Linux-only). ---
    if let Ok(checker) = std::env::var("ZOVIA_BCF_CHECKER") {
        if std::path::Path::new(&checker).exists() {
            let tmp = std::env::temp_dir().join(format!(
                "zovia-phase1-{}-{}.bcf",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::write(&tmp, proof).expect("write tmp proof");
            let out = Command::new(&checker)
                .arg("-b")
                .arg(&tmp)
                .output()
                .expect("invoke bcf-checker");
            let cs = String::from_utf8_lossy(&out.stdout);
            let _ = std::fs::remove_file(&tmp);
            // `-b` always exit-zero; status is in the JSON body.
            assert!(
                cs.contains("\"status\": 0"),
                "bcf-checker rejected proof:\n{}",
                cs
            );
        } else {
            eprintln!("[note] ZOVIA_BCF_CHECKER set but path missing: {}", checker);
        }
    }

    // Cleanup so re-runs are deterministic.
    let _ = std::fs::remove_file(&bundle);
}
