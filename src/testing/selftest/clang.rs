//! Drive `clang -target bpf` to compile an upstream `verifier_*.c` source
//! into a BPF ELF object that the rest of the pipeline (existing ELF
//! parser + verifier) can read directly.
//!
//! Headers are vendored under `selftests/headers/<tag>/` (see that
//! directory's README); we point clang at them via `-I` flags so the
//! pipeline doesn't depend on a system libbpf or kernel UAPI install.

use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default kernel-tag subdirectory under `selftests/headers/`. Bump in
/// lockstep with `selftests/SOURCE_TAG` and the vendored header refresh.
pub const DEFAULT_HEADERS_TAG: &str = "v6.15";

/// Resolve the clang binary to invoke. Honors `$BPF_CLANG` for
/// override; otherwise tries Homebrew's path on macOS, then `clang` on
/// `$PATH`.
fn resolve_clang() -> String {
    if let Ok(p) = std::env::var("BPF_CLANG") {
        return p;
    }
    let homebrew = "/opt/homebrew/opt/llvm/bin/clang";
    if Path::new(homebrew).exists() {
        return homebrew.to_string();
    }
    "clang".to_string()
}

/// Default vendored-header include dirs for the given tag. Order
/// matters: stubs (for libc bits clang-bpf doesn't ship) shadow real
/// kernel UAPI headers when both define the same name (e.g. `errno.h`),
/// so stubs come first.
pub fn default_include_dirs(headers_root: &Path) -> Vec<PathBuf> {
    vec![
        headers_root.join("_stubs"),
        headers_root.to_path_buf(),
        headers_root.join("bpf"),
    ]
}

/// Default `-iquote` directories for the given tag. These exist solely
/// to redirect `#include "…/relative/path.h"` lines that the upstream
/// kernel selftests use to reach into `tools/include/`. We can't
/// recreate that tree at the path their relative includes expect, so
/// we register a deep dummy directory under `_quotes/` and place the
/// stub headers at the resolved location. clang searches each
/// `-iquote` dir for a literal `"x/y/z.h"` include, so a stub at
/// `_quotes/include/linux/filter.h` resolves the upstream
/// `"../../../include/linux/filter.h"` when the iquote root is
/// `_quotes/q1/q2/q3` (three `..` ascents land back at `_quotes/`).
pub fn default_iquote_dirs(headers_root: &Path) -> Vec<PathBuf> {
    vec![headers_root.join("_quotes/q1/q2/q3")]
}

/// `-D` macros the upstream selftests Makefile sets globally for every
/// BPF prog. Without these, ~25 tracing programs refuse to compile
/// (`#error "Must specify a BPF target arch via __TARGET_ARCH_xxx"`).
/// Applied on top of any `PER_FILE_DEFINES` entry for an individual file.
pub const UPSTREAM_GLOBAL_DEFINES: &[&str] = &["__TARGET_ARCH_x86"];

/// Include dirs for sweeping the *upstream* selftests tree directly
/// (no re-vendoring). Layers our hand-written stubs on top of the
/// in-tree headers so the libc shims still win where both define the
/// same symbol. `upstream_root` is the root of a checked-out kernel
/// (typically `vendor/linux/`).
///
/// Order:
///   1. our `_stubs/`            — libc shims
///   2. `selftests/headers/<tag>/` + `bpf/` — our pinned vendored copies
///                                  of the most-used selftest/uapi headers
///   3. upstream `tools/lib/`    — resolves `<bpf/bpf_endian.h>` etc.
///   4. upstream `tools/lib/bpf`
///   5. upstream `tools/include` + `tools/include/uapi`
///   6. upstream `include/uapi`  — kernel-internal uapi (`linux/libc-compat.h`, …)
///   7. upstream `arch/x86/include/uapi` — `<asm/byteorder.h>`, `<asm/ptrace.h>`
///   8. upstream `tools/testing/selftests/bpf` + `progs` — sibling helper headers
pub fn upstream_include_dirs(headers_root: &Path, upstream_root: &Path) -> Vec<PathBuf> {
    let mut v = default_include_dirs(headers_root);
    v.extend([
        upstream_root.join("tools/lib"),
        upstream_root.join("tools/lib/bpf"),
        upstream_root.join("tools/include"),
        upstream_root.join("tools/include/uapi"),
        upstream_root.join("include/uapi"),
        upstream_root.join("arch/x86/include/uapi"),
        upstream_root.join("tools/testing/selftests/bpf"),
        upstream_root.join("tools/testing/selftests/bpf/progs"),
    ]);
    v
}

/// `-iquote` dirs for upstream sweeps: the existing dummy depth-3 dir
/// that handles `"../../../include/linux/filter.h"`-style ascents, plus
/// the selftests/bpf dir for sibling quoted includes.
pub fn upstream_iquote_dirs(headers_root: &Path, upstream_root: &Path) -> Vec<PathBuf> {
    let mut v = default_iquote_dirs(headers_root);
    v.push(upstream_root.join("tools/testing/selftests/bpf"));
    v
}

/// Returns clang's resource-dir `include` path (where compiler intrinsic
/// headers live: `stddef.h`, `stdarg.h`, `stdint.h`, …). We need to
/// surface these as `-isystem` rather than rely on the host's `/usr/include`
/// because `-target bpf` doesn't accept macOS or Linux libc headers.
fn clang_resource_include(clang: &str) -> Option<PathBuf> {
    let out = Command::new(clang)
        .arg("-print-resource-dir")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = String::from_utf8(out.stdout).ok()?.trim().to_string();
    Some(PathBuf::from(dir).join("include"))
}

/// Compile a `.c` source into a BPF ELF object. `out_path` is the
/// destination `.o` file; caller chooses where it lives (typically a
/// temp dir).
///
/// `extra_defines` lets a caller pass `-D` macros — e.g. `CAN_USE_GOTOL`
/// for files gated on cpuv4 features.
#[allow(dead_code)]
pub fn compile<P: AsRef<Path>, Q: AsRef<Path>>(
    src: P,
    out_path: Q,
    include_dirs: &[PathBuf],
    extra_defines: &[&str],
) -> Result<()> {
    compile_with_iquote(src, out_path, include_dirs, &[], extra_defines)
}

pub fn compile_with_iquote<P: AsRef<Path>, Q: AsRef<Path>>(
    src: P,
    out_path: Q,
    include_dirs: &[PathBuf],
    iquote_dirs: &[PathBuf],
    extra_defines: &[&str],
) -> Result<()> {
    let src = src.as_ref();
    let out = out_path.as_ref();
    let clang = resolve_clang();

    let mut cmd = Command::new(&clang);
    // `-nostdinc` blocks the host system include search (macOS SDK,
    // /usr/include) which doesn't grok `-target bpf`. We add back only
    // clang's own resource-dir intrinsics (`-isystem`) plus the
    // vendored / stub dirs (`-I`).
    cmd.args(["-target", "bpf", "-O2", "-g", "-Wall", "-nostdinc", "-c"]);
    if let Some(rdir) = clang_resource_include(&clang) {
        cmd.arg("-isystem").arg(rdir);
    }
    for inc in include_dirs {
        cmd.arg("-I").arg(inc);
    }
    for q in iquote_dirs {
        cmd.arg("-iquote").arg(q);
    }
    for d in extra_defines {
        cmd.arg(format!("-D{d}"));
    }
    cmd.arg(src).arg("-o").arg(out);

    let output = cmd
        .output()
        .with_context(|| format!("invoking {clang} (set $BPF_CLANG to override)"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "clang failed compiling {}: {}",
            src.display(),
            stderr.trim()
        ));
    }
    Ok(())
}

// ============================================================
// Compile cache
//
// Sweeping the v6.15 corpus invokes clang ~849 times per run.
// Source files don't change between sweeps in a development session,
// so re-compiling each time burns the bulk of the wall clock for no
// reason. Cache keyed on (source SHA, include-set fingerprint,
// defines): on hit we just copy the cached .o; on miss we clang and
// store. Cache survives across runs (`target/zovia-selftest-cache/`)
// and across `cargo build` (only `cargo clean` wipes it).
//
// The include-set fingerprint is computed once per sweep by walking
// every `.h` under each include/iquote dir and hashing
// (path, mtime, size). Bumping a single header invalidates every
// cached .o in that sweep — that's correct: we don't know which
// header a given .c actually included without compiling. False
// invalidation is fine; false hits would silently feed stale objects
// into the verifier, which is what we must not do.
// ============================================================

const COMPILE_CACHE_VERSION: u32 = 1;

/// FNV-1a 64-bit. Stable across processes/runs (unlike DefaultHasher),
/// zero-dep, fast enough for our key inputs (KB-scale source files +
/// header-fingerprint blobs). Collision probability for a few thousand
/// entries is astronomical.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn collect_header_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_header_files(&p, out);
        } else if matches!(
            p.extension().and_then(|s| s.to_str()),
            Some("h") | Some("inc")
        ) {
            out.push(p);
        }
    }
}

/// Walk every `.h`/`.inc` under each include/iquote dir, hash
/// (path, mtime_secs, size). Compute once per sweep — caller threads
/// the result through to per-file compiles.
pub fn fingerprint_include_set(include_dirs: &[PathBuf], iquote_dirs: &[PathBuf]) -> u64 {
    let mut h = fnv1a_64(b"zovia-include-set-v1");
    for dir in include_dirs.iter().chain(iquote_dirs.iter()) {
        let mut entries: Vec<PathBuf> = Vec::new();
        collect_header_files(dir, &mut entries);
        entries.sort();
        for path in entries {
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut state: Vec<u8> = path.to_string_lossy().as_bytes().to_vec();
            state.extend_from_slice(&mtime.to_le_bytes());
            state.extend_from_slice(&meta.len().to_le_bytes());
            h ^= fnv1a_64(&state);
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

fn compile_cache_key(src: &Path, include_fingerprint: u64, defines: &[&str]) -> Option<String> {
    let bytes = std::fs::read(src).ok()?;
    let src_hash = fnv1a_64(&bytes);
    let mut sorted: Vec<&str> = defines.to_vec();
    sorted.sort_unstable();
    let mut defs_buf: Vec<u8> = Vec::new();
    for d in sorted {
        defs_buf.extend_from_slice(d.as_bytes());
        defs_buf.push(0);
    }
    let defs_hash = fnv1a_64(&defs_buf);
    Some(format!(
        "v{}-{:016x}-{:016x}-{:016x}",
        COMPILE_CACHE_VERSION, src_hash, include_fingerprint, defs_hash
    ))
}

fn compile_cache_dir() -> PathBuf {
    PathBuf::from("target/zovia-selftest-cache")
}

/// Cache-aware variant of [`compile_with_iquote`]. On hit, copies the
/// cached `.o` into `out_path` and skips clang entirely. On miss,
/// invokes clang and stores the result. Caller computes
/// `include_fingerprint` once per sweep via [`fingerprint_include_set`].
pub fn compile_with_iquote_cached<P: AsRef<Path>, Q: AsRef<Path>>(
    src: P,
    out_path: Q,
    include_dirs: &[PathBuf],
    iquote_dirs: &[PathBuf],
    extra_defines: &[&str],
    include_fingerprint: u64,
) -> Result<()> {
    let src = src.as_ref();
    let out = out_path.as_ref();
    let Some(key) = compile_cache_key(src, include_fingerprint, extra_defines) else {
        // Couldn't read source — fall back to plain compile so the
        // error path is the same.
        return compile_with_iquote(src, out, include_dirs, iquote_dirs, extra_defines);
    };
    let cache_dir = compile_cache_dir();
    let cached = cache_dir.join(format!("{key}.o"));
    if cached.exists() {
        std::fs::copy(&cached, out)
            .with_context(|| format!("copying cached .o from {}", cached.display()))?;
        return Ok(());
    }
    compile_with_iquote(src, out, include_dirs, iquote_dirs, extra_defines)?;
    let _ = std::fs::create_dir_all(&cache_dir);
    let _ = std::fs::copy(out, &cached);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn project_headers_dir() -> PathBuf {
        PathBuf::from("selftests/headers").join(DEFAULT_HEADERS_TAG)
    }

    #[test]
    fn compiles_verifier_gotol() {
        let headers = project_headers_dir();
        if !headers.exists() {
            // Skip on environments where vendored headers aren't checked out.
            eprintln!("skipping: {} not found", headers.display());
            return;
        }
        let tmp = std::env::temp_dir().join("zovia_clang_gotol.o");
        let _ = fs::remove_file(&tmp);

        let inc = default_include_dirs(&headers);
        compile(
            "selftests/progs/verifier_gotol.c",
            &tmp,
            &inc,
            &["CAN_USE_GOTOL"],
        )
        .expect("clang should compile verifier_gotol.c");

        let meta = fs::metadata(&tmp).expect("output .o exists");
        assert!(meta.len() > 0, "output object is empty");
    }
}
