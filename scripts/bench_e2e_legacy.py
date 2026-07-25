#!/usr/bin/env python3
"""LEGACY end-to-end BCF bundle benchmark harness.

⚠️ Superseded by `bench_e2e.py`, which calls `alivio --bcf` once per
object and relies on alivio's internal thorough mode for the multi-pass
discharge-entry merge. Use the new script unless you specifically need
to drive each pass from Python (e.g., per-pass timing diagnostics).

For each .o in the input list:
  Phase 1 (parallel, alivio-side): build a unified bundle by running
    alivio 3× with ALIVIO_BUNDLE_KEEP=1 — flag-OFF, flag-ON AND,
    flag-ON OR. Each mode contributes different rejection-discharge
    entries (kernel writes dedup by hash via write_bundle).
  Phase 2 (sequential, kernel-side via cloudlab→VM ssh chain):
    ship anchor + bundle, run test_loader, parse loaded=N/M.

Output: TSV with columns
  obj  alivio_ok  bundle_bytes  alivio_elapsed  kernel_loaded  kernel_total

Usage:
  scripts/bench_e2e_legacy.py --list /tmp/calico_repr_list.txt --jobs 8 \\
      --out /tmp/bench_calico71.tsv --kernel-test

  # skip the kernel-load step (just build bundles + measure alivio):
  scripts/bench_e2e_legacy.py --list ... --no-kernel-test

  # rerun only the kernel-load step against existing bundles:
  scripts/bench_e2e_legacy.py --list ... --skip-bundle-build --kernel-test
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional


# ───── Phase 1: parallel alivio bundle build ─────────────────────────


def is_bundle_fresh(obj_path: str, alivio_bin: str, harness: str = __file__) -> bool:
    """Bundle on disk is reusable iff its mtime is newer than every input
    that could have changed its contents: the .o, the alivio binary, and
    this harness. Returns False if the bundle is missing.
    """
    bundle = f"{obj_path}.bcf-bundle"
    if not os.path.exists(bundle):
        return False
    try:
        b_m = os.path.getmtime(bundle)
        return all(b_m >= os.path.getmtime(p) for p in (obj_path, alivio_bin, harness))
    except OSError:
        return False


def build_one(args):
    obj_path, alivio_bin, timeout, cache_bundles = args
    bundle = f"{obj_path}.bcf-bundle"

    # Cache hit: bundle is newer than (.o, alivio, harness). Skip rebuild.
    if cache_bundles and is_bundle_fresh(obj_path, alivio_bin):
        size = os.path.getsize(bundle)
        return (obj_path, True, size, 0.0, "cached")

    try:
        if os.path.exists(bundle):
            os.remove(bundle)
    except OSError:
        pass

    modes = [
        ("OFF", {}),
        ("AND", {"ALIVIO_KERNEL_ENGINE": "1", "ALIVIO_KERNEL_ENGINE_AND": "1"}),
        ("OR",  {"ALIVIO_KERNEL_ENGINE": "1"}),
    ]
    t0 = time.time()
    notes = []
    for label, extra_env in modes:
        env = {**os.environ, "ALIVIO_BUNDLE_KEEP": "1", **extra_env}
        cmd = [alivio_bin, "-q", "--bcf", "--kernel-mode", "verify", obj_path]
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
            # we only care that the bundle file ends up populated;
            # individual mode rc=1 is fine if other modes added entries
            notes.append(f"{label}:rc{r.returncode}")
        except subprocess.TimeoutExpired:
            notes.append(f"{label}:TO")
    elapsed = time.time() - t0
    ok = os.path.exists(bundle)
    size = os.path.getsize(bundle) if ok else 0
    return (obj_path, ok, size, elapsed, ",".join(notes))


def phase1_build_bundles(objs: list[str], alivio: str, jobs: int, timeout: int,
                         cache_bundles: bool = False) -> list[tuple]:
    cache_note = " [cache enabled]" if cache_bundles else ""
    print(f"[bench] phase 1: building bundles for {len(objs)} objects "
          f"(jobs={jobs}, per-obj timeout={timeout}s){cache_note}", file=sys.stderr)
    work = [(o, alivio, timeout, cache_bundles) for o in objs]
    results: list[tuple] = []
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(build_one, w): w[0] for w in work}
        for i, fut in enumerate(as_completed(futs), 1):
            results.append(fut.result())
            if i % 5 == 0 or i == len(objs):
                print(f"[bench] phase 1: {i}/{len(objs)}", file=sys.stderr)
    if cache_bundles:
        n_cached = sum(1 for r in results if r[4] == "cached")
        print(f"[bench] phase 1: {n_cached}/{len(results)} reused from cache", file=sys.stderr)
    return results


# ───── Phase 2: sequential VM kernel-side load test ─────────────────


def map_to_vm_path(local_path: str) -> str:
    """Translate Mac-local path to the VM's /root/bcf/... view.

    The cloudlab virtiofs mount exposes /users/yc1795/BCF at /root/bcf
    inside the VM. The calico repr list uses /Users/yalucai/BCF/... on
    Mac, which is the SAME directory tree (rsync'd or symlinked).
    Replace the Mac prefix wholesale to preserve the full subdirectory
    structure (e.g. bpf-progs/calico/<file>).
    """
    return local_path.replace("/Users/yalucai/BCF", "/root/bcf", 1)


def phase2_kernel_load(objs: list[str], cloudlab_host: str, timeout: int,
                       vm_jobs: int = 4, run_per_prog: bool = False,
                       per_call_timeout: int = 60) -> dict[str, tuple]:
    """For each .o, scp the bundle to cloudlab (its virtiofs is the VM's
    /root/bcf), then ssh to VM and run test_loader.

    Performance (this iteration):
    - Default: WHOLE-OBJECT load only. --per-prog is opt-in
      (run_per_prog=True) — it underreports bundle benefits due to
      subprog isolation, and doubles VM-side work.
    - VM-side parallelism via `xargs -P vm_jobs` — each test_loader
      writes its output to a per-object log file, concatenated after
      all complete.
    - SSH ControlMaster on the outer hop amortizes TCP handshake
      across the rsync + the test invocation (the caller sets this up
      with mkdir_ssh_socket).
    - Per-test_loader timeout via `timeout(1)` so a single stuck
      program can't stall the worker pool.

    Returns map: obj → (per_prog_loaded, per_prog_total, whole_obj_full,
    first_fail_name).
    """
    print(f"[bench] phase 2: kernel-side load for {len(objs)} objects "
          f"(sequential, host={cloudlab_host})", file=sys.stderr)
    out: dict[str, tuple] = {}

    # Step A: rsync bundles to cloudlab in one batch (fast, single ssh).
    # Mac /Users/yalucai/BCF/bpf-progs/calico/<obj>.bcf-bundle  →
    # cloudlab /users/yc1795/BCF/bpf-progs/calico/<obj>.bcf-bundle
    bundles = [f"{o}.bcf-bundle" for o in objs if os.path.exists(f"{o}.bcf-bundle")]
    if not bundles:
        print("[bench] phase 2: no bundles to ship", file=sys.stderr)
        return out

    # Group by parent dir for rsync efficiency
    by_dir: dict[str, list[str]] = {}
    for b in bundles:
        by_dir.setdefault(os.path.dirname(b), []).append(b)
    for d, group in by_dir.items():
        # Map Mac dir → cloudlab dir
        # /Users/yalucai/BCF/bpf-progs/calico → /users/yc1795/BCF/bpf-progs/calico
        cl_dir = d.replace("/Users/yalucai/BCF", "/users/yc1795/BCF")
        print(f"[bench] rsync {len(group)} bundles → {cloudlab_host}:{cl_dir}", file=sys.stderr)
        subprocess.run(
            ["rsync", "-aq", *group, f"{cloudlab_host}:{cl_dir}/"],
            check=False, timeout=300,
        )

    # Step B: write a VM-side runner with `xargs -P vm_jobs` and a
    # per-call timeout(1). Each invocation writes to a per-object log;
    # at the end we concatenate with delimiters for parsing.
    pp_label = " + --per-prog" if run_per_prog else ""
    print(f"[bench] phase 2: VM-side parallel (P={vm_jobs}, per-call timeout={per_call_timeout}s)"
          f"{pp_label}", file=sys.stderr)

    # Build manifest lines: each line = "<vm_obj> <vm_bundle> <safe_id>"
    manifest_lines = []
    obj_by_id: dict[str, str] = {}
    for idx, o in enumerate(objs):
        vm_obj = map_to_vm_path(o)
        vm_bundle = f"{vm_obj}.bcf-bundle"
        safe_id = f"o{idx:04d}_{os.path.basename(o)}"
        manifest_lines.append(f"{vm_obj}\t{vm_bundle}\t{safe_id}")
        obj_by_id[safe_id] = o
    manifest = "\n".join(manifest_lines)

    # The VM-side runner: reads manifest, runs N parallel test_loader
    # invocations, writes per-call log, then concatenates. Quoting is
    # tricky through the nested ssh — use bash heredoc with `'EOF'`
    # (single-quoted: no shell expansion) and pass manifest separately.
    vm_runner = f"""#!/bin/bash
set -u
WORK=$(mktemp -d /tmp/bench_e2e.XXXXXX)
cat > "$WORK/manifest"
export WORK
do_one() {{
  obj=$1; bundle=$2; sid=$3
  out="$WORK/$sid.log"
  {{
    echo "===BEGIN $sid==="
    timeout {per_call_timeout} /root/bcf/build/test_loader --type classifier "$obj" "$bundle" 2>&1 \\
      | grep -E 'SUCCESS:|libbpf: prog .* failed to load:|programs:|loaded ' | head -20
    echo "===WHOLE_RC $sid $?==="
"""
    if run_per_prog:
        vm_runner += f"""    echo "---perprog $sid---"
    timeout {per_call_timeout} /root/bcf/build/test_loader --type classifier --per-prog "$obj" "$bundle" 2>&1 \\
      | grep -E 'PERPROG SUMMARY' | tail -1
"""
    vm_runner += f"""    echo "===END $sid==="
  }} > "$out" 2>&1
}}
export -f do_one
# Feed manifest lines to xargs; each worker bash invocation re-parses
# the tab-separated fields and calls do_one.
xargs -P {vm_jobs} -I LINE -d '\\n' bash -c 'IFS=$'"'"'\\t'"'"' read -r o b s <<< "$0"; do_one "$o" "$b" "$s"' LINE < "$WORK/manifest"
# Concatenate per-call logs in manifest order so output is deterministic
while IFS=$'\\t' read -r obj bundle sid; do
  if [ -f "$WORK/$sid.log" ]; then
    cat "$WORK/$sid.log"
  else
    echo "===BEGIN $sid==="
    echo "===MISSING $sid==="
    echo "===END $sid==="
  fi
done < "$WORK/manifest"
rm -rf "$WORK"
"""

    # Outer hop: ControlMaster reuses an existing socket if caller set one up.
    outer_ssh_opts = ["-o", "BatchMode=yes"]
    # We pass manifest via a small wrapper: bash <<EOF that includes both the runner and the manifest.
    # Simpler: shovel runner via stdin to bash, then pipe manifest in a separate command. Use a single
    # bash -s -- args... where args is "RUNNER" then the manifest sent later won't work via stdin.
    # Workaround: emit runner that reads manifest from stdin, then feed runner+manifest via stdin
    # joined by a sentinel. Bash can do: write runner to a temp file, then run it.
    combined = (
        "cat > /tmp/bench_e2e_runner.sh <<'__ZK_RUNNER_EOF__'\n"
        + vm_runner
        + "\n__ZK_RUNNER_EOF__\n"
        + "chmod +x /tmp/bench_e2e_runner.sh\n"
        + "/tmp/bench_e2e_runner.sh <<'__ZK_MANIFEST_EOF__'\n"
        + manifest
        + "\n__ZK_MANIFEST_EOF__\n"
        + "rm -f /tmp/bench_e2e_runner.sh\n"
    )
    inner_ssh = (
        "ssh -i /users/yc1795/BCF/imgs/bookworm.id_rsa -p 10023 "
        "-o BatchMode=yes -o StrictHostKeyChecking=no root@localhost 'bash -s'"
    )
    r = subprocess.run(
        ["ssh", *outer_ssh_opts, cloudlab_host, inner_ssh],
        input=combined, capture_output=True, text=True, timeout=timeout,
    )
    raw = r.stdout
    # Parse: split on ===BEGIN <sid>=== / ===END <sid>=== markers.
    # Each section's body has the test_loader output (whole-object) and
    # optionally a `---perprog <sid>---` block.
    section_re = re.compile(r"===BEGIN ([^=]+)===\n(.*?)===END \1===", flags=re.S)
    for m in section_re.finditer(raw):
        sid = m.group(1).strip()
        body = m.group(2)
        if sid not in obj_by_id:
            continue
        o = obj_by_id[sid]
        whole_full = bool(re.search(r"^SUCCESS:", body, flags=re.M))
        first_fail = ""
        mf = re.search(r"libbpf: prog '([^']+)': failed to load:", body)
        if mf:
            first_fail = mf.group(1)
        pp_loaded, pp_total = None, None
        if run_per_prog:
            mp = re.search(r"PERPROG SUMMARY\s+loaded=(\d+)/(\d+)", body)
            if mp:
                pp_loaded, pp_total = int(mp.group(1)), int(mp.group(2))
        if pp_total is None:
            mt = re.search(r"programs:\s+(\d+)\s+in object", body)
            if mt:
                pp_total = int(mt.group(1))
        out[o] = (pp_loaded, pp_total, whole_full, first_fail)
    return out


# ───── Driver ───────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", required=True, help="file of .o paths, one per line")
    ap.add_argument("--alivio", default="./target/release/alivio")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=300, help="per-object alivio timeout (s)")
    ap.add_argument("--cloudlab", help="cloudlab ssh target (e.g. yc1795@ms0802.utah.cloudlab.us). "
                    "if unset, read from /Users/yalucai/bpf-next-alivio git remote.")
    ap.add_argument("--out", default="/tmp/bench_e2e.tsv")
    ap.add_argument("--kernel-test", action="store_true", default=True,
                    help="run phase 2 kernel-load test (default on)")
    ap.add_argument("--no-kernel-test", dest="kernel_test", action="store_false")
    ap.add_argument("--skip-bundle-build", action="store_true",
                    help="skip phase 1; reuse existing bundles on disk")
    ap.add_argument("--cache-bundles", action="store_true",
                    help="reuse existing .bcf-bundle iff its mtime is newer than "
                         "(.o, alivio binary, this harness). Per-object granularity; "
                         "stale entries are rebuilt. Default: off (deterministic per-commit).")
    ap.add_argument("--vm-jobs", type=int, default=4,
                    help="parallel test_loader processes on the VM (default 4)")
    ap.add_argument("--per-prog", action="store_true",
                    help="also run --per-prog (slower; underreports bundle benefits "
                         "due to subprog isolation). Default: whole-object only.")
    ap.add_argument("--per-call-timeout", type=int, default=60,
                    help="per-test_loader timeout in seconds (default 60)")
    ap.add_argument("--phase2-timeout", type=int, default=1800,
                    help="overall phase 2 ssh timeout in seconds (default 30min)")
    args = ap.parse_args()

    # Resolve cloudlab from git remote if not provided
    if args.kernel_test and not args.cloudlab:
        r = subprocess.run(
            ["git", "-C", "/Users/yalucai/bpf-next-alivio", "remote", "get-url", "cloudlab"],
            capture_output=True, text=True, check=True,
        )
        url = r.stdout.strip()
        args.cloudlab = url.split(":")[0]

    with open(args.list) as f:
        objs = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    print(f"[bench] {len(objs)} objects", file=sys.stderr)
    if args.cloudlab:
        print(f"[bench] cloudlab={args.cloudlab}", file=sys.stderr)

    # Phase 1
    if not args.skip_bundle_build:
        p1 = phase1_build_bundles(objs, args.alivio, args.jobs, args.timeout,
                                  cache_bundles=args.cache_bundles)
        p1_by_obj = {r[0]: r for r in p1}
    else:
        p1_by_obj = {o: (o, os.path.exists(f"{o}.bcf-bundle"),
                         os.path.getsize(f"{o}.bcf-bundle") if os.path.exists(f"{o}.bcf-bundle") else 0,
                         0.0, "reused") for o in objs}

    # Phase 2
    if args.kernel_test:
        ok_objs = [o for o in objs if p1_by_obj[o][1]]
        # Set up SSH ControlMaster on the outer hop so rsync + ssh exec
        # share one TCP connection (saves ~1-2s per call).
        ssh_socket = f"/tmp/bench_e2e_ssh_{os.getpid()}"
        os.environ["RSYNC_RSH"] = (
            f"ssh -o BatchMode=yes -o ControlMaster=auto "
            f"-o ControlPath={ssh_socket}.rsync -o ControlPersist=120s"
        )
        # also export for plain ssh subprocess calls via SSH_OPTS env
        # (we pass these in the ssh args directly below; keeping the rsync
        # one separate so concurrent rsync+ssh use distinct sockets and
        # don't race on a single ControlMaster).
        try:
            kresults = phase2_kernel_load(
                ok_objs, args.cloudlab,
                timeout=args.phase2_timeout,
                vm_jobs=args.vm_jobs,
                run_per_prog=args.per_prog,
                per_call_timeout=args.per_call_timeout,
            )
        finally:
            # tear down ControlMaster sockets if any
            for suffix in (".rsync",):
                p = ssh_socket + suffix
                if os.path.exists(p):
                    subprocess.run(["ssh", "-O", "exit", "-o", f"ControlPath={p}",
                                    args.cloudlab], capture_output=True)
    else:
        kresults = {}

    # Emit TSV
    with open(args.out, "w") as f:
        f.write("obj\talivio_ok\tbundle_bytes\talivio_elapsed\tpp_loaded\tpp_total\twhole_full\tfirst_fail\tnotes\n")
        for o in sorted(objs):
            obj, ok, size, elapsed, notes = p1_by_obj[o]
            pp_l, pp_t, whole, ff = (None, None, False, "")
            if o in kresults:
                pp_l, pp_t, whole, ff = kresults[o]
            pp_l_s = str(pp_l) if pp_l is not None else "-"
            pp_t_s = str(pp_t) if pp_t is not None else "-"
            f.write(f"{os.path.basename(obj)}\t{ok}\t{size}\t{elapsed:.1f}\t"
                    f"{pp_l_s}\t{pp_t_s}\t{whole}\t{ff}\t{notes}\n")

    # Summary
    n_ok = sum(1 for r in p1_by_obj.values() if r[1])
    n_whole = sum(1 for v in kresults.values() if v[2])
    n_pp_full = sum(1 for v in kresults.values() if v[0] is not None and v[0] == v[1] and v[1] is not None)
    n_pp_partial = sum(1 for v in kresults.values() if v[0] is not None and v[1] is not None and 0 < v[0] < v[1])
    n_pp_zero = sum(1 for v in kresults.values() if v[0] == 0)
    print(f"\n[bench] phase 1: bundle built for {n_ok}/{len(objs)}", file=sys.stderr)
    if args.kernel_test:
        print(f"[bench] phase 2: whole-object FULL kernel load: {n_whole}/{len(kresults)}", file=sys.stderr)
        print(f"[bench]          per-prog (lower-bound): full={n_pp_full} "
              f"partial={n_pp_partial} zero={n_pp_zero}", file=sys.stderr)
    print(f"[bench] wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
