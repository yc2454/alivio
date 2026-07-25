#!/usr/bin/env python3
"""
L3 sweep harness — end-to-end (Mac alivio → bundle → cloudlab → VM kernel).

For each input .o:
  1. L2: run `alivio --bcf` locally; record accept/reject + bundle.
  2. If bundle produced: scp it to cloudlab, ssh into VM, run test_loader,
     capture exit and key dmesg lines.

Output: JSON list with per-program {l2_outcome, l3_outcome, reasons}.

Usage:
  scripts/l3_sweep.py --input-list FILE --out RESULTS.json [--l2-jobs 8]

Input list format: one program path per line. Paths are .o files under
/Users/yalucai/BCF/bpf-progs/ (mac); cloudlab side is the same tree
under /users/yc1795/BCF/bpf-progs/ (already synced, virtiofs-shared as
/root/bcf/bpf-progs/ in the VM).

Notes:
  - L2 runs in parallel (alivio is CPU-only, no shared state).
  - L3 runs serial — single VM, kernel state is global.
  - L3 SSH uses BatchMode (no password prompts); a working ssh key
    chain to the cloudlab host + the VM's bookworm key file is required.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

ALIVIO = Path("./target/release/alivio")
LOCAL_BPFPROGS = Path("/Users/yalucai/BCF/bpf-progs")
CLOUDLAB_HOST = "yc1795@ms0802.utah.cloudlab.us"
CLOUDLAB_BPFPROGS = "/users/yc1795/BCF/bpf-progs"
VM_BPFPROGS = "/root/bcf/bpf-progs"
VM_KEY = "/users/yc1795/BCF/imgs/bookworm.id_rsa"
VM_PORT = 10023
OBJ_PROG_TYPE_JSON = LOCAL_BPFPROGS / "obj_prog_type.json"

# Cache of {basename → prog_type_str} loaded once
_PROG_TYPE_CACHE: Optional[dict] = None


def lookup_prog_type(prog_path: Path) -> Optional[str]:
    """Return the explicit prog_type string from obj_prog_type.json, or None."""
    global _PROG_TYPE_CACHE
    if _PROG_TYPE_CACHE is None:
        try:
            with OBJ_PROG_TYPE_JSON.open() as f:
                _PROG_TYPE_CACHE = json.load(f)
        except FileNotFoundError:
            _PROG_TYPE_CACHE = {}
    return _PROG_TYPE_CACHE.get(prog_path.name)


@dataclass
class Result:
    program: str            # path under bpf-progs/
    source: str             # cilium / calico / ...
    # L2 (alivio)
    l2_outcome: str = "SKIP"   # ACCEPT / REJECT / TIMEOUT / ERROR
    l2_elapsed_s: float = 0.0
    l2_fail_reason: Optional[str] = None
    bundle_size: int = 0
    bundle_exists: bool = False
    # L3 (kernel)
    l3_outcome: str = "SKIP"   # ACCEPT / REJECT / TIMEOUT / SKIP
    l3_elapsed_s: float = 0.0
    l3_summary: str = ""       # last lines of test_loader stdout
    l3_dmesg: str = ""         # last lines of dmesg


def find_source(p: Path) -> str:
    parts = p.parts
    for i, part in enumerate(parts):
        if part == "bpf-progs" and i + 1 < len(parts):
            return parts[i + 1]
        if part == "bcf-tests":
            return "bcf-tests"
    return "unknown"


def run_l2(prog: Path, timeout: int) -> dict:
    bundle = prog.with_suffix(prog.suffix + ".bcf-bundle")
    if bundle.exists():
        bundle.unlink()
    start = time.time()
    try:
        r = subprocess.run(
            [str(ALIVIO), "--bcf", "--kernel-mode", "verify", str(prog)],
            capture_output=True, text=True, timeout=timeout,
        )
        out = r.stdout + "\n" + r.stderr
    except subprocess.TimeoutExpired:
        return {"l2_outcome": "TIMEOUT", "l2_elapsed_s": float(timeout),
                "l2_fail_reason": "timeout", "bundle_size": 0, "bundle_exists": False}
    elapsed = time.time() - start

    bundle_exists = bundle.exists()
    bundle_size = bundle.stat().st_size if bundle_exists else 0

    # Parse outcome from the "SUMMARY" block.
    pass_match = re.search(r"^Pass:\s+(\d+)\s+\(([0-9.]+)%\)", out, re.MULTILINE)
    fail_match = re.search(r"^Fail:\s+(\d+)", out, re.MULTILINE)
    if pass_match and fail_match:
        n_pass = int(pass_match.group(1))
        n_fail = int(fail_match.group(1))
        if n_fail == 0 and n_pass > 0:
            outcome = "ACCEPT"
        elif n_pass > 0 and n_fail > 0:
            outcome = "PARTIAL"
        else:
            outcome = "REJECT"
    elif "FAILURE:" in out or "ERROR" in out:
        outcome = "REJECT"
    else:
        outcome = "ERROR"

    fail_reason = None
    if outcome != "ACCEPT":
        m = re.search(r"FAILURE:\s+(.+)$", out, re.MULTILINE)
        if m:
            fail_reason = m.group(1).strip()[:200]

    return {"l2_outcome": outcome, "l2_elapsed_s": elapsed,
            "l2_fail_reason": fail_reason, "bundle_size": bundle_size,
            "bundle_exists": bundle_exists}


def ship_bundle(local_bundle: Path, prog_relpath: Path) -> bool:
    remote = f"{CLOUDLAB_BPFPROGS}/{prog_relpath}.bcf-bundle"
    try:
        subprocess.run(
            ["scp", "-q", "-o", "BatchMode=yes",
             str(local_bundle), f"{CLOUDLAB_HOST}:{remote}"],
            check=True, timeout=30,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def run_l3(prog_relpath: Path, has_bundle: bool, timeout: int) -> dict:
    vm_prog = f"{VM_BPFPROGS}/{prog_relpath}"
    # If obj_prog_type.json knows this object's type, pass it explicitly so
    # libbpf can load even cilium-style `2/1` section names.
    type_str = lookup_prog_type(prog_relpath)
    type_arg = f"--type {type_str} " if type_str else ""
    if has_bundle:
        loader_cmd = f"./build/test_loader {type_arg}{vm_prog} {vm_prog}.bcf-bundle"
    else:
        loader_cmd = f"./build/test_loader {type_arg}{vm_prog}"
    inner = (
        f"cd /root/bcf && dmesg -c >/dev/null 2>&1; "
        f"{loader_cmd} 2>&1 | tail -8; "
        f"echo '---DMESG---'; dmesg | tail -6"
    )
    outer = (
        f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes "
        f"-i {VM_KEY} -p {VM_PORT} root@localhost \"{inner}\""
    )
    start = time.time()
    try:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", CLOUDLAB_HOST, outer],
            capture_output=True, text=True, timeout=timeout,
        )
        out = r.stdout
    except subprocess.TimeoutExpired:
        return {"l3_outcome": "TIMEOUT", "l3_elapsed_s": float(timeout),
                "l3_summary": "", "l3_dmesg": ""}
    elapsed = time.time() - start

    parts = out.split("---DMESG---")
    summary = parts[0].strip()[-400:]
    dmesg = parts[1].strip()[-400:] if len(parts) > 1 else ""

    # New test_loader prints "SUCCESS: loaded N/M program(s)" on full load.
    if "SUCCESS: loaded" in summary:
        outcome = "ACCEPT"
    elif "failed to load" in summary or "EACCES" in summary or "EINVAL" in summary or "ESRCH" in summary:
        outcome = "REJECT"
    else:
        # Fallback: trust exit code, but bias toward REJECT to avoid false positives.
        outcome = "ACCEPT" if r.returncode == 0 and "fail" not in summary.lower() else "REJECT"

    return {"l3_outcome": outcome, "l3_elapsed_s": elapsed,
            "l3_summary": summary, "l3_dmesg": dmesg}


def process_one(prog: Path, timeout_l2: int, timeout_l3: int, do_l3: bool) -> Result:
    rel = prog.relative_to(LOCAL_BPFPROGS) if LOCAL_BPFPROGS in prog.parents else Path(prog.name)
    res = Result(program=str(rel), source=find_source(prog))

    # L2
    l2 = run_l2(prog, timeout_l2)
    res.l2_outcome = l2["l2_outcome"]
    res.l2_elapsed_s = l2["l2_elapsed_s"]
    res.l2_fail_reason = l2["l2_fail_reason"]
    res.bundle_size = l2["bundle_size"]
    res.bundle_exists = l2["bundle_exists"]

    if not do_l3:
        return res

    # L3
    if not res.bundle_exists:
        # No bundle to ship — try L3 without bundle (kernel native)
        l3 = run_l3(rel, has_bundle=False, timeout=timeout_l3)
    else:
        bundle = prog.with_suffix(prog.suffix + ".bcf-bundle")
        if not ship_bundle(bundle, rel):
            res.l3_outcome = "ERROR"
            res.l3_summary = "scp failed"
            return res
        l3 = run_l3(rel, has_bundle=True, timeout=timeout_l3)
    res.l3_outcome = l3["l3_outcome"]
    res.l3_elapsed_s = l3["l3_elapsed_s"]
    res.l3_summary = l3["l3_summary"]
    res.l3_dmesg = l3["l3_dmesg"]
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--input-list", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--l2-jobs", type=int, default=4,
                    help="parallel alivio jobs (default 4)")
    # Defaults are intentionally LARGE: a small wall-clock cap is a
    # harness artifact, not a kernel-faithfulness limit (the kernel
    # bounds verification by insn-count, which alivio models
    # separately). A too-small cap silently loses real wins by
    # turning slow-but-valid analyses into spurious TIMEOUT/REJECT
    # (measured: 60s undercounted cilium L3 by 3). So by default we
    # let analysis run to completion; pass --timeout to go fast.
    ap.add_argument("--timeout", type=int, default=None, metavar="SECONDS",
                    help="shortcut to cap BOTH phases at SECONDS each "
                         "(e.g. --timeout 120 for a fast test run). "
                         "Omit to use the large defaults so no valid "
                         "result is lost to an arbitrary cap.")
    ap.add_argument("--timeout-l2", type=int, default=600, metavar="SECONDS",
                    help="max seconds for the L2 phase per object "
                         "(alivio analysis on the Mac; default 600). "
                         "Overridden by --timeout if given.")
    ap.add_argument("--timeout-l3", type=int, default=600, metavar="SECONDS",
                    help="max seconds for the L3 phase per object "
                         "(kernel load in the VM; default 600). "
                         "Overridden by --timeout if given.")
    ap.add_argument("--skip-l3", action="store_true",
                    help="L2 only (don't ship/test on kernel)")
    args = ap.parse_args()
    # --timeout is the simple knob: one number caps both phases.
    if args.timeout is not None:
        args.timeout_l2 = args.timeout
        args.timeout_l3 = args.timeout

    with args.input_list.open() as f:
        progs = [Path(line.strip()) for line in f if line.strip() and not line.startswith("#")]

    print(f"# l3_sweep: {len(progs)} programs, l2-jobs={args.l2_jobs}, l3={'skip' if args.skip_l3 else 'serial'}")
    print(f"#   timeout_l2={args.timeout_l2}s timeout_l3={args.timeout_l3}s")

    # Phase 1: L2 in parallel
    print(f"\n=== Phase 1: L2 ({args.l2_jobs} parallel) ===")
    l2_results: dict[str, Result] = {}
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.l2_jobs) as pool:
        futures = {pool.submit(process_one, p, args.timeout_l2, args.timeout_l3, do_l3=False): p
                   for p in progs}
        for i, fut in enumerate(as_completed(futures), 1):
            p = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = Result(program=str(p), source=find_source(p))
                res.l2_outcome = "ERROR"
                res.l2_fail_reason = f"harness: {e}"[:200]
            l2_results[res.program] = res
            tag = "✓" if res.l2_outcome == "ACCEPT" else "✗" if res.l2_outcome == "REJECT" else res.l2_outcome
            print(f"  [{i:3d}/{len(progs):3d}] {tag} {res.program} ({res.l2_elapsed_s:.1f}s, bundle={res.bundle_size}B)")

    print(f"\n  L2 summary: " +
          " ".join(f"{k}={sum(1 for r in l2_results.values() if r.l2_outcome == k)}"
                   for k in ["ACCEPT", "PARTIAL", "REJECT", "TIMEOUT", "ERROR"]))
    print(f"  L2 wall time: {time.time()-t0:.1f}s")

    # Phase 2: L3 serial
    if not args.skip_l3:
        print(f"\n=== Phase 2: L3 (serial, on VM) ===")
        t0 = time.time()
        for i, prog in enumerate(progs, 1):
            rel = prog.relative_to(LOCAL_BPFPROGS) if LOCAL_BPFPROGS in prog.parents else Path(prog.name)
            res = l2_results[str(rel)]
            if res.bundle_exists:
                bundle = prog.with_suffix(prog.suffix + ".bcf-bundle")
                if not ship_bundle(bundle, rel):
                    res.l3_outcome = "ERROR"
                    res.l3_summary = "scp failed"
                else:
                    l3 = run_l3(rel, has_bundle=True, timeout=args.timeout_l3)
                    for k, v in l3.items():
                        setattr(res, k, v)
            else:
                # try kernel native (no bundle)
                l3 = run_l3(rel, has_bundle=False, timeout=args.timeout_l3)
                for k, v in l3.items():
                    setattr(res, k, v)
            tag = "✓" if res.l3_outcome == "ACCEPT" else "✗" if res.l3_outcome == "REJECT" else res.l3_outcome
            print(f"  [{i:3d}/{len(progs):3d}] {tag} {res.program} ({res.l3_elapsed_s:.1f}s)")

        print(f"\n  L3 summary: " +
              " ".join(f"{k}={sum(1 for r in l2_results.values() if r.l3_outcome == k)}"
                       for k in ["ACCEPT", "PARTIAL", "REJECT", "TIMEOUT", "ERROR", "SKIP"]))
        print(f"  L3 wall time: {time.time()-t0:.1f}s")

    # Write output
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as f:
        json.dump([asdict(r) for r in l2_results.values()], f, indent=2)
    print(f"\nresults written: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
