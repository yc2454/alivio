#!/usr/bin/env python3
"""End-to-end BCF bundle benchmark harness.

Builds and kernel-loads run as an overlapped PIPELINE (default, when both
building and kernel-testing): bundle builds are `--jobs`-parallel on the
host, and a single consumer thread ships each bundle to the VM as soon as
it finishes building — so a slow/timeout-bound build no longer blocks the
VM load of bundles already on disk. Each VM load batch stays
`--vm-jobs`-parallel. (`--skip-bundle-build` and `--no-kernel-test`
degenerate to the single-phase paths.)

  Build (parallel, alivio-side): build the bundle via a single
    `alivio --bcf --kernel-mode verify <obj>` invocation. By default
    `--bcf` enables thorough mode internally (alivio spawns its own
    multi-pass children with varied state-cache placement and merges
    their discharge entries). The legacy harness that drove three
    separate alivio invocations from this script lives at
    `bench_e2e_legacy.py`.
  Load (kernel-side via cloudlab→VM ssh chain):
    ship anchor + bundle, run test_loader, parse loaded=N/M.

**Partial-bundle policy** (2026-05-27): alivio writes the bundle to disk
at section-completion / section-failure boundaries, so a TIMEOUT-killed
worker may still leave a usable partial bundle on disk. Phase 2 ships
*any* bundle file that exists, regardless of the build's exit status.
This was empirically validated on cilium bpf_host: a 360 KB partial
covering only sections 2/1 through 2/21 still loads 32/32 because the
kernel doesn't explore the later sections' reject sites. Bundle size
does not have to correlate with load success; per-row `note` records
whether the build completed or hit the timeout.

Output: TSV with columns
  obj  alivio_ok  bundle_bytes  alivio_elapsed  kernel_loaded  kernel_total

Usage:
  scripts/bench_e2e.py --list /tmp/calico_repr_list.txt --jobs 8 \\
      --out /tmp/bench_calico71.tsv --kernel-test

  # skip the kernel-load step (just build bundles + measure alivio):
  scripts/bench_e2e.py --list ... --no-kernel-test

  # rerun only the kernel-load step against existing bundles:
  scripts/bench_e2e.py --list ... --skip-bundle-build --kernel-test
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional


# ───── Program-type lookup (obj_prog_type.json + libbpf fallback) ───


DEFAULT_OBJ_PROG_TYPE_JSON = "/Users/yalucai/BCF/bpf-progs/obj_prog_type.json"

# Map from the JSON's SEC-name style (lowercased path prefix) to the
# `test_loader --type` keyword libbpf accepts. The JSON values are the
# raw SEC name (e.g. "kprobe", "tracepoint/syscalls/sys_enter_execve",
# "xdp"). test_loader maps these through libbpf's section-name matcher
# when `--type` is supplied; for unambiguous cases we strip the
# subprogram suffix and map to the canonical type word.
_SEC_TO_TYPE = {
    "classifier": "classifier",
    "xdp": "xdp",
    "kprobe": "kprobe",
    "kretprobe": "kprobe",
    "tracepoint": "tracepoint",
    "raw_tracepoint": "raw_tracepoint",
    "raw_tp": "raw_tracepoint",
    "sockops": "sockops",
    "sk_msg": "sk_msg",
    "sk_skb": "sk_skb",
    "socket": "socket",
    "cgroup": "cgroup",  # cgroup/* subtypes — libbpf needs full SEC, fallback
    "perf_event": "perf_event",
    "lwt_in": "lwt_in",
    "lwt_out": "lwt_out",
    "lwt_xmit": "lwt_xmit",
    "lwt_seg6local": "lwt_seg6local",
    "fentry": "fentry",
    "fexit": "fexit",
}


def load_obj_prog_types(path: Optional[str]) -> dict[str, str]:
    """Load the obj→SEC-name JSON if present. Returns {} on missing or
    error. Keys are bare basenames (e.g. `clang-19_-O1_seccomp_x86_bpfel.o`);
    values are the raw SEC name string (sometimes None when the populator
    couldn't detect a SEC).
    """
    if not path:
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except (OSError, json.JSONDecodeError) as e:
        print(f"[bench] warn: couldn't read {path}: {e}", file=sys.stderr)
        return {}


def lookup_prog_type(obj_path: str, types_map: dict[str, str]) -> Optional[str]:
    """Return `--type` keyword for `obj_path` using the JSON, or None
    to fall back to libbpf SEC auto-detect. Returns None when the JSON
    is silent (key absent or value null/empty) OR when the SEC string
    isn't in our keyword map.
    """
    base = os.path.basename(obj_path)
    raw = types_map.get(base)
    if not raw or not isinstance(raw, str):
        return None
    # SEC names like "tracepoint/syscalls/sys_enter_execve" → take first
    # path component as the type keyword.
    head = raw.split("/", 1)[0].strip().lower()
    return _SEC_TO_TYPE.get(head)


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

    # alivio's --bcf flag enables internal thorough mode by default: it
    # spawns its own multi-pass children with varied state-cache
    # placement and merges their discharge entries into the same
    # bundle file. One invocation per object is now sufficient.
    cmd = [alivio_bin, "-q", "--bcf", "--kernel-mode", "verify", obj_path]
    t0 = time.time()
    note = ""
    # --bcf thorough mode spawns child alivio workers for multi-pass
    # state-cache placement. subprocess.run(..., timeout=) only kills the
    # parent on TimeoutExpired, leaving the children to keep eating RAM
    # well past the deadline. Run the parent in its own process group and
    # SIGKILL the whole group on timeout so no orphan workers survive.
    p = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    try:
        p.communicate(timeout=timeout)
        note = f"rc{p.returncode}"
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        note = "TO"
    elapsed = time.time() - t0
    ok = os.path.exists(bundle)
    size = os.path.getsize(bundle) if ok else 0
    # Partial-bundle policy: even on TIMEOUT, if alivio wrote a bundle
    # at some section boundary before being killed, ship it. Empirically
    # validated (2026-05-27) on cilium bpf_host where a 360 KB partial
    # covering only the prefix sections still loaded 32/32 — the kernel
    # doesn't query the later sections' hashes for those particular
    # programs. Tag the note so the TSV makes it visible.
    if note == "TO" and ok and size > 0:
        note = f"TO+partial({size}B)"
    return (obj_path, ok, size, elapsed, note)


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
    # Summarize partial-bundle survivors so the operator sees that
    # phase-2 will still ship them. ("TO+partial" set by build_one.)
    n_partial = sum(1 for r in results if r[4].startswith("TO+partial"))
    if n_partial:
        print(f"[bench] phase 1: {n_partial} bundles partial-on-timeout — phase 2 will still ship",
              file=sys.stderr)
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
                       per_call_timeout: int = 300,
                       types_map: Optional[dict[str, str]] = None,
                       ctl_socket: Optional[str] = None,
                       label: str = "") -> dict[str, tuple]:
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
    print(f"[bench] phase 2{label}: kernel-side load for {len(objs)} objects "
          f"(host={cloudlab_host})", file=sys.stderr)
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

    # Build manifest lines: each line = "<vm_obj> <vm_bundle> <safe_id> <type_or_empty>"
    # The type column is the `--type` keyword from obj_prog_type.json when
    # available; empty means "let libbpf auto-detect from SEC name". Empty
    # is the safe default (works for any program whose SEC is unambiguous).
    manifest_lines = []
    obj_by_id: dict[str, str] = {}
    n_typed = 0
    types_map = types_map or {}
    for idx, o in enumerate(objs):
        vm_obj = map_to_vm_path(o)
        vm_bundle = f"{vm_obj}.bcf-bundle"
        safe_id = f"o{idx:04d}_{os.path.basename(o)}"
        ptype = lookup_prog_type(o, types_map) or ""
        if ptype:
            n_typed += 1
        manifest_lines.append(f"{vm_obj}\t{vm_bundle}\t{safe_id}\t{ptype}")
        obj_by_id[safe_id] = o
    manifest = "\n".join(manifest_lines)
    print(f"[bench] phase 2: {n_typed}/{len(objs)} objs have explicit --type "
          f"from obj_prog_type.json; rest fall back to libbpf SEC auto-detect",
          file=sys.stderr)

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
  obj=$1; bundle=$2; sid=$3; ptype=$4
  out="$WORK/$sid.log"
  type_args=""
  if [ -n "$ptype" ]; then
    type_args="--type $ptype"
  fi
  {{
    echo "===BEGIN $sid==="
    timeout {per_call_timeout} /root/bcf/build/test_loader $type_args "$obj" "$bundle" 2>&1 \\
      | grep -E 'SUCCESS:|libbpf: prog .* failed to load:|programs:|loaded ' | head -20
    echo "===WHOLE_RC $sid $?==="
"""
    if run_per_prog:
        vm_runner += f"""    echo "---perprog $sid---"
    timeout {per_call_timeout} /root/bcf/build/test_loader $type_args --per-prog "$obj" "$bundle" 2>&1 \\
      | grep -E 'PERPROG SUMMARY' | tail -1
"""
    vm_runner += f"""    echo "===END $sid==="
  }} > "$out" 2>&1
}}
export -f do_one
# Feed manifest lines to xargs; each worker bash invocation re-parses
# the tab-separated fields and calls do_one.
xargs -P {vm_jobs} -I LINE -d '\\n' bash -c 'IFS=$'"'"'\\t'"'"' read -r o b s t <<< "$0"; do_one "$o" "$b" "$s" "$t"' LINE < "$WORK/manifest"
# Concatenate per-call logs in manifest order so output is deterministic
while IFS=$'\\t' read -r obj bundle sid ptype; do
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

    # Outer hop: reuse the caller's persistent ControlMaster socket so the
    # many pipelined load batches share one TCP connection instead of
    # re-handshaking the cloudlab hop every batch.
    outer_ssh_opts = ["-o", "BatchMode=yes"]
    if ctl_socket:
        outer_ssh_opts += ["-o", "ControlMaster=auto",
                           "-o", f"ControlPath={ctl_socket}",
                           "-o", "ControlPersist=120s"]
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


# ───── TSV row formatting (shared by pipeline + non-pipeline paths) ──

TSV_HEADER = ("obj\talivio_ok\tbundle_bytes\talivio_elapsed\tpp_loaded\t"
              "pp_total\twhole_full\tfirst_fail\tnotes\n")


def format_tsv_row(p1_tuple: tuple, kres_tuple: Optional[tuple]) -> str:
    """One output row. `notes` carries the BUILD outcome (rc0 / cached /
    TO / TO+partial(NB)) — important signal we must preserve, distinct from
    the load result (whole_full / first_fail)."""
    obj, ok, size, elapsed, notes = p1_tuple
    pp_l, pp_t, whole, ff = kres_tuple if kres_tuple else (None, None, False, "")
    pp_l_s = str(pp_l) if pp_l is not None else "-"
    pp_t_s = str(pp_t) if pp_t is not None else "-"
    return (f"{os.path.basename(obj)}\t{ok}\t{size}\t{elapsed:.1f}\t"
            f"{pp_l_s}\t{pp_t_s}\t{whole}\t{ff}\t{notes}\n")


# ───── Pipelined driver: overlap builds and VM loads ────────────────


def pipelined_build_and_load(
    objs: list[str], alivio: str, jobs: int, timeout: int, cache_bundles: bool,
    cloudlab_host: str, phase2_timeout: int, vm_jobs: int, run_per_prog: bool,
    per_call_timeout: int, types_map: dict[str, str], ctl_socket: str,
    out_path: str,
) -> tuple[dict[str, tuple], dict[str, tuple]]:
    """Build bundles (ProcessPool, `jobs` wide) and kernel-load them
    concurrently.

    A single consumer thread drains every bundle that has finished
    building and ships it to the VM via `phase2_kernel_load`, while the
    remaining (often slow / timeout-bound) builds keep running. This
    removes the old barrier where one 900s-timeout build stalled the VM
    load of all the bundles that were already on disk. Builds stay
    `jobs`-parallel on the host; each load batch stays `vm_jobs`-parallel
    on the VM. The consumer greedily batches whatever is ready when it
    becomes free, so batch size adapts to the build/load rate.

    Each program's TSV row is written *incrementally* the moment its load
    completes (then flushed), so an interrupted/crashed/OOM-killed run
    still leaves every finished program's full result — including the
    build `notes` (rc0 / TO+partial) — on disk. No more reconstructing by
    hand. Programs that never produced a bundle are flushed at the end.
    """
    print(f"[bench] pipelined: {len(objs)} objects (build jobs={jobs}, "
          f"vm_jobs={vm_jobs}) — VM loads start as bundles complete; "
          f"rows streamed to {out_path}", file=sys.stderr)
    p1_by_obj: dict[str, tuple] = {}
    kresults: dict[str, tuple] = {}
    written: set[str] = set()
    ready: list[str] = []
    ready_lock = threading.Lock()
    builds_done = threading.Event()

    out_f = open(out_path, "w")
    out_f.write(TSV_HEADER)
    out_f.flush()

    def consumer() -> None:
        batch_idx = 0
        n_loaded = 0
        while True:
            with ready_lock:
                drained = ready[:]
                ready.clear()
            if drained:
                batch_idx += 1
                res = phase2_kernel_load(
                    drained, cloudlab_host, timeout=phase2_timeout,
                    vm_jobs=vm_jobs, run_per_prog=run_per_prog,
                    per_call_timeout=per_call_timeout, types_map=types_map,
                    ctl_socket=ctl_socket, label=f" batch#{batch_idx}",
                )
                kresults.update(res)
                for o in drained:
                    _, _, whole, ff = res.get(o, (None, None, False, ""))
                    if whole:
                        tag = "PASS  FULL-LOAD"
                    elif ff:
                        tag = f"FAIL  reject@{ff}"
                    else:
                        tag = "FAIL  no-load"
                    note = p1_by_obj[o][4]  # build outcome: rc0 / TO+partial
                    print(f"[bench]   {tag}  {os.path.basename(o)}  [{note}]",
                          file=sys.stderr)
                    out_f.write(format_tsv_row(p1_by_obj[o], res.get(o)))
                    written.add(o)
                out_f.flush()  # persist this batch before the next build/load
                n_loaded += len(drained)
                print(f"[bench] loaded {n_loaded}/{len(objs)} so far",
                      file=sys.stderr)
            elif builds_done.is_set():
                break
            else:
                time.sleep(1.0)

    consumer_thread = threading.Thread(target=consumer, daemon=True)
    consumer_thread.start()

    work = [(o, alivio, timeout, cache_bundles) for o in objs]
    n_done = 0
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        futs = {ex.submit(build_one, w): w[0] for w in work}
        for fut in as_completed(futs):
            r = fut.result()
            p1_by_obj[r[0]] = r
            n_done += 1
            if r[1]:  # bundle exists (incl. partial-on-timeout) → loadable
                with ready_lock:
                    ready.append(r[0])
            if n_done % 5 == 0 or n_done == len(objs):
                print(f"[bench] builds: {n_done}/{len(objs)} done",
                      file=sys.stderr)
    n_partial = sum(1 for r in p1_by_obj.values()
                    if r[4].startswith("TO+partial"))
    if n_partial:
        print(f"[bench] {n_partial} bundles partial-on-timeout — loaded anyway",
              file=sys.stderr)
    builds_done.set()
    consumer_thread.join()
    # Flush programs that never produced a bundle (never loaded), preserving
    # their build note (TO / no-build) so the TSV is complete.
    for o in objs:
        if o not in written:
            p1 = p1_by_obj.get(o, (o, False, 0, 0.0, "no-build"))
            out_f.write(format_tsv_row(p1, kresults.get(o)))
    out_f.flush()
    out_f.close()
    return p1_by_obj, kresults


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
    ap.add_argument("--cache-bundles", dest="cache_bundles", action="store_true",
                    default=True,
                    help="reuse an existing .bcf-bundle sidecar iff its mtime is "
                         "newer than (.o, alivio binary, this harness); stale "
                         "entries are rebuilt. DEFAULT: ON. Bundles are persisted "
                         "next to their .o (alivio writes <obj>.bcf-bundle), so a "
                         "machine restart mid-batch doesn't discard already-built "
                         "work — the next run resumes from the on-disk sidecars.")
    ap.add_argument("--no-cache-bundles", dest="cache_bundles", action="store_false",
                    help="force a fresh rebuild of every bundle, ignoring on-disk "
                         "sidecars. Use for a strictly deterministic per-commit "
                         "gate run. (mtime check already invalidates bundles when "
                         "the alivio binary or .o change, so caching is safe across "
                         "rebuilds; this is the belt-and-suspenders option.)")
    ap.add_argument("--vm-jobs", type=int, default=4,
                    help="parallel test_loader processes on the VM (default 4)")
    ap.add_argument("--per-prog", action="store_true",
                    help="also run --per-prog (slower; underreports bundle benefits "
                         "due to subprog isolation). Default: whole-object only.")
    ap.add_argument("--per-call-timeout", type=int, default=300,
                    help="per-test_loader timeout in seconds (default 300). "
                         "Large bundles (calico tail-call tables, cilium DSR) "
                         "can take a minute+ for the kernel verifier alone; "
                         "60s was killing legitimate loads as TO.")
    ap.add_argument("--phase2-timeout", type=int, default=1800,
                    help="overall phase 2 ssh timeout in seconds (default 30min)")
    ap.add_argument("--obj-prog-type-json", default=DEFAULT_OBJ_PROG_TYPE_JSON,
                    help=f"path to obj→SEC-name JSON for explicit --type "
                         f"selection in phase 2; pass empty string to disable "
                         f"and use libbpf SEC auto-detect for everything. "
                         f"Default: {DEFAULT_OBJ_PROG_TYPE_JSON}")
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

    # SSH ControlMaster on the outer hop: rsync + every ssh-exec batch
    # share one TCP connection. With pipelining we make many load batches,
    # so a single persistent socket matters more than before.
    ssh_socket = f"/tmp/bench_e2e_ssh_{os.getpid()}"
    if args.kernel_test:
        os.environ["RSYNC_RSH"] = (
            f"ssh -o BatchMode=yes -o ControlMaster=auto "
            f"-o ControlPath={ssh_socket} -o ControlPersist=120s"
        )

    types_map = (load_obj_prog_types(args.obj_prog_type_json or None)
                 if args.kernel_test else {})

    kresults: dict[str, tuple] = {}
    tsv_already_written = False
    try:
        if args.skip_bundle_build:
            # No builds: treat existing on-disk bundles as ready, load in
            # one batch (the pipeline buys nothing without builds to overlap).
            p1_by_obj = {
                o: (o, os.path.exists(f"{o}.bcf-bundle"),
                    os.path.getsize(f"{o}.bcf-bundle") if os.path.exists(f"{o}.bcf-bundle") else 0,
                    0.0, "reused")
                for o in objs
            }
            if args.kernel_test:
                ok_objs = [o for o in objs if p1_by_obj[o][1]]
                kresults = phase2_kernel_load(
                    ok_objs, args.cloudlab, timeout=args.phase2_timeout,
                    vm_jobs=args.vm_jobs, run_per_prog=args.per_prog,
                    per_call_timeout=args.per_call_timeout, types_map=types_map,
                    ctl_socket=ssh_socket,
                )
        elif args.kernel_test:
            # Build + load, overlapped. Writes args.out incrementally.
            p1_by_obj, kresults = pipelined_build_and_load(
                objs, args.alivio, args.jobs, args.timeout, args.cache_bundles,
                args.cloudlab, args.phase2_timeout, args.vm_jobs,
                args.per_prog, args.per_call_timeout, types_map, ssh_socket,
                args.out,
            )
            tsv_already_written = True
        else:
            # Build only, no kernel load.
            p1 = phase1_build_bundles(objs, args.alivio, args.jobs, args.timeout,
                                      cache_bundles=args.cache_bundles)
            p1_by_obj = {r[0]: r for r in p1}
    finally:
        if args.kernel_test and os.path.exists(ssh_socket):
            subprocess.run(["ssh", "-O", "exit", "-o", f"ControlPath={ssh_socket}",
                            args.cloudlab], capture_output=True)

    # Emit TSV (pipeline path already streamed it incrementally)
    if not tsv_already_written:
        with open(args.out, "w") as f:
            f.write(TSV_HEADER)
            for o in sorted(objs):
                f.write(format_tsv_row(p1_by_obj[o], kresults.get(o)))

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
