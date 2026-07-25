#!/usr/bin/env python3
"""Triage selftest FALSE_REJECTs by reason class.

Fans `dev selftest-file <f> --upstream <root>` across files that
contain any FR (per a pre-existing sweep TSV), captures each FR's
verdict-tag reason, and buckets by a coarse class taxonomy. Emits a
histogram plus a per-file/per-prog detail dump.

  scripts/triage_frs.py --sweep /tmp/cur_kmode_v10.tsv

The taxonomy is intentionally rough — the goal is to find the
highest-leverage single fix (e.g. "Invalid helper ID" or "function not
found"), not to fully characterize every reject.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

# Matches `  [FALSE-REJECT (reason)] prog (desc)`. The reason may
# contain parens; the outer `[...]` ends at the last `]` before the
# program name.
FR_RE = re.compile(r"^\s+\[FALSE-REJECT\s+\((.+?)\)\]\s+(\S+)")


def classify(reason: str) -> str:
    """Coarse class for triage. Higher-leverage classes come first."""
    r = reason.lower()
    if r.startswith("load:") and "not found in any of" in r:
        return "missing_function_libbpf_link"
    if "complexity limit" in r:
        return "complexity_limit"
    if "infinite loop detected" in r:
        return "infinite_loop_detected"
    if "invalid helper id" in r and "exceeds maximum" in r:
        return "helper_proto_missing"
    if "invalid helper id" in r:
        return "helper_invalid_id"
    if "kfunc" in r and ("not found" in r or "unknown" in r or "missing" in r):
        return "kfunc_proto_missing"
    if "kfunc" in r:
        return "kfunc_other"
    if "co-re" in r or "core_reloc" in r or "btf" in r and "reloc" in r:
        return "core_reloc"
    if "unreachable" in r:
        return "unreachable_insn"
    if "stack" in r and ("overflow" in r or "depth" in r):
        return "stack_depth"
    if "unsafe" in r and "load" in r:
        return "unsafe_load"
    if "unsafe" in r and "store" in r:
        return "unsafe_store"
    if "unsafe" in r and ("access" in r or "ptr" in r):
        return "unsafe_access_other"
    if "math between" in r:
        return "ptr_arith_unbounded"
    if "register" in r and "not readable" in r:
        return "reg_not_readable"
    if "invalid argument type" in r:
        return "invalid_arg_type"
    if "divide by zero" in r:
        return "divide_by_zero"
    if "back-edge" in r:
        return "cfg_back_edge"
    if "out of bounds" in r or "out-of-bounds" in r:
        return "out_of_bounds"
    if "tail call" in r or "tailcall" in r:
        return "tail_call"
    if "spin_lock" in r or "spinlock" in r:
        return "spin_lock"
    if "iterator" in r or "bpf_iter" in r:
        return "iterator"
    if "map" in r:
        return "map_related"
    return "other"


def run_one(args):
    alivio, upstream, path, timeout = args
    fname = os.path.basename(path)
    cmd = [
        alivio,
        "-q",
        "--kernel-mode",
        "dev",
        "selftest-file",
        path,
        "--upstream",
        upstream,
    ]
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        out = p.stdout + "\n" + p.stderr
    except subprocess.TimeoutExpired:
        return fname, []
    except Exception:
        return fname, []
    frs: list[tuple[str, str]] = []
    for ln in out.splitlines():
        m = FR_RE.match(ln)
        if m:
            reason = m.group(1).strip()
            prog = m.group(2)
            frs.append((prog, reason))
    return fname, frs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", default="/tmp/cur_kmode_v10.tsv",
                    help="prior sweep TSV with FALSE_REJECT entries")
    ap.add_argument("--alivio", default="./target/release/alivio")
    ap.add_argument("--upstream", default="vendor/linux")
    ap.add_argument("--progs-dir",
                    default="vendor/linux/tools/testing/selftests/bpf/progs")
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--timeout", type=int, default=180,
                    help="per-file seconds")
    ap.add_argument("--detail-out", default="/tmp/fr_triage_detail.tsv")
    a = ap.parse_args()

    if not Path(a.sweep).exists():
        print(f"missing --sweep {a.sweep}", file=sys.stderr)
        return 1

    # Collect files containing any FR.
    fr_files: set[str] = set()
    with open(a.sweep) as f:
        for ln in f:
            ln = ln.rstrip("\n")
            if "\tFALSE_REJECT" not in ln:
                continue
            head = ln.split("\t", 1)[0]
            fname = head.split("::", 1)[0]
            fr_files.add(fname)

    progs_dir = Path(a.progs_dir)
    paths = [progs_dir / n for n in sorted(fr_files) if (progs_dir / n).exists()]
    print(f"[triage] {len(paths)} files containing FRs; running with "
          f"jobs={a.jobs}, timeout={a.timeout}s")

    fr_records: list[tuple[str, str, str]] = []  # (file, prog, reason)
    done = 0
    with ProcessPoolExecutor(max_workers=a.jobs) as ex:
        futs = {
            ex.submit(run_one, (a.alivio, a.upstream, str(p), a.timeout)): p
            for p in paths
        }
        for fut in as_completed(futs):
            done += 1
            if done % 25 == 0:
                print(f"[triage] {done}/{len(paths)}", file=sys.stderr)
            fname, frs = fut.result()
            for prog, reason in frs:
                fr_records.append((fname, prog, reason))

    fr_records.sort()

    bucket = Counter()
    bucket_examples: dict[str, list[str]] = defaultdict(list)
    for fname, prog, reason in fr_records:
        cls = classify(reason)
        bucket[cls] += 1
        if len(bucket_examples[cls]) < 3:
            bucket_examples[cls].append(f"{fname}::{prog}  {reason}")

    print("\n==== FR TRIAGE HISTOGRAM ====")
    print(f"  Total FRs categorized: {sum(bucket.values())}")
    print()
    for cls, n in bucket.most_common():
        pct = 100.0 * n / max(1, sum(bucket.values()))
        print(f"  {n:>5}  ({pct:>4.1f}%)  {cls}")
        for ex in bucket_examples[cls]:
            print(f"            {ex[:200]}")
        print()

    with open(a.detail_out, "w") as f:
        for fname, prog, reason in fr_records:
            cls = classify(reason)
            f.write(f"{cls}\t{fname}::{prog}\t{reason}\n")
    print(f"[triage] wrote per-FR detail to {a.detail_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
