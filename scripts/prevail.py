#!/usr/bin/env python3
"""Prevail catalogue runner — Python port of `dev prevail {list,run,single,benchmark}`.

Two modes:

* **Catalogue** (`list`/`single`/`run`): the YAML/JSON catalogue at
  `<catalogue.json>` lists named tests with `{name, file, section?, expected, reason}`.
  We resolve each test against `<catalogue>.base_path`, run the verifier, and
  classify against `expected` (`ACCEPT`/`REJECT`).

* **Benchmark** (`benchmark`): walks `<dir>` for `.o` files, infers
  expectation from the first-level project name (`invalid/...` → REJECT,
  everything else → ACCEPT), runs the verifier, and tallies false
  positives/negatives the same way the old `dev prevail benchmark`
  did. Output JSON shape is preserved so `tests/baselines/capture_baseline.sh`
  keeps working.

Both modes shell out to `alivio dev verify-corpus --input-list ... --out ...`
to do the actual verification, then aggregate the JSONL records here.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Optional

DEFAULT_ALIVIO = "./target/release/alivio"


def expand(p: str) -> Path:
    return Path(os.path.expanduser(p))


def load_catalogue(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def run_alivio(alivio: str, files: list[Path], extra: list[str]) -> list[dict]:
    """Verify each file's sections, return parsed JSONL records."""
    if not files:
        return []
    with tempfile.TemporaryDirectory() as td:
        list_p = Path(td) / "files.txt"
        out_p = Path(td) / "out.jsonl"
        # Deduplicate paths — multiple tests may target the same file.
        seen = []
        seen_set = set()
        for f in files:
            s = str(f)
            if s not in seen_set:
                seen.append(s)
                seen_set.add(s)
        list_p.write_text("\n".join(seen) + "\n")
        cmd = [alivio, "-q", *extra, "dev", "verify-corpus",
               "--input-list", str(list_p), "--out", str(out_p)]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)
        return [json.loads(ln) for ln in out_p.read_text().splitlines() if ln.strip()]


def classify_file(records: list[dict], wanted_section: Optional[str]) -> tuple[str, Optional[str], int]:
    """Given the verifier records for one ELF, decide ACCEPT/REJECT/TIMEOUT/ERROR.

    Returns (actual, error_detail, total_time_ms).

    `wanted_section`:
      * Some(s): consider only that section.
      * None: ACCEPT iff every code section passes; otherwise the first
              non-PASS wins (matches Rust `analyze_all` semantics).
              If no records (empty/unloadable), treat as ERROR.
    """
    if wanted_section is not None:
        relevant = [r for r in records if r.get("section") == wanted_section]
        if not relevant:
            return ("ERROR", f"section '{wanted_section}' not found", 0)
        r = relevant[0]
        return _record_actual(r)

    if not records:
        return ("ERROR", "no code sections found", 0)
    total_ms = sum(r.get("time_ms", 0) for r in records)
    failing = [r for r in records if r["status"] != "PASS"]
    if not failing:
        return ("ACCEPT", None, total_ms)
    r = failing[0]
    return _record_actual(r)[:2] + (total_ms,)


def _record_actual(r: dict) -> tuple[str, Optional[str], int]:
    status = r["status"]
    err = r.get("error")
    t = r.get("time_ms", 0)
    if status == "PASS":
        return ("ACCEPT", None, t)
    if status == "TIMEOUT":
        return ("TIMEOUT", None, t)
    if status == "LOAD_ERROR":
        return ("ERROR", err, t)
    return ("REJECT", err, t)


# ============================================================
# Catalogue commands
# ============================================================

def cmd_list(args) -> int:
    cat = load_catalogue(expand(args.catalogue))
    print(f"Catalogue: {cat.get('description', '')}")
    print(f"Base path: {cat['base_path']}")
    print(f"Tests:     {len(cat['tests'])}\n")
    for i, t in enumerate(cat["tests"]):
        sec = t.get("section") or "(any)"
        print(f"  [{i:3d}] {t['name']:60s}  {t['expected']:6s}  {t['file']}::{sec}")
    return 0


def cmd_single(args) -> int:
    cat = load_catalogue(expand(args.catalogue))
    base = expand(cat["base_path"])
    test = next((t for t in cat["tests"] if t["name"] == args.test), None)
    if test is None:
        print(f"Error: test '{args.test}' not found in catalogue", file=sys.stderr)
        return 2
    elf = base / test["file"]
    if not elf.exists():
        print(f"Error: ELF file not found: {elf}", file=sys.stderr)
        return 2

    records = run_alivio(args.alivio, [elf], args.alivio_flag)
    actual, err, time_ms = classify_file(records, test.get("section"))
    print(f"Test:       {test['name']}")
    print(f"File:       {elf}")
    print(f"Section:    {test.get('section') or '(any)'}")
    print(f"Expected:   {test['expected']}")
    print(f"Actual:     {actual}")
    print(f"Time:       {time_ms} ms")
    if err:
        print(f"Detail:     {err}")
    matches = (test["expected"] == "ACCEPT") == (actual == "ACCEPT")
    print(f"Verdict:    {'PASS' if matches else 'FAIL'}")
    return 0 if matches else 1


def cmd_run(args) -> int:
    cat = load_catalogue(expand(args.catalogue))
    base = expand(cat["base_path"])
    files = [base / t["file"] for t in cat["tests"]]
    files = [f for f in files if f.exists()]

    started = datetime.datetime.now()
    records = run_alivio(args.alivio, files, args.alivio_flag)
    duration = (datetime.datetime.now() - started).total_seconds()

    by_file: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_file[r["file"]].append(r)

    rows = []
    for t in cat["tests"]:
        elf = base / t["file"]
        if not elf.exists():
            rows.append({"name": t["name"], "expected": t["expected"], "actual": "ERROR",
                         "matches": False, "time_ms": 0, "detail": "file not found"})
            continue
        recs = by_file.get(str(elf), [])
        actual, err, time_ms = classify_file(recs, t.get("section"))
        if actual in ("TIMEOUT", "ERROR"):
            matches = False
        else:
            matches = (t["expected"] == "ACCEPT") == (actual == "ACCEPT")
        rows.append({"name": t["name"], "expected": t["expected"], "actual": actual,
                     "matches": matches, "time_ms": time_ms, "detail": err})

    total = len(rows)
    passed = sum(1 for r in rows if r["matches"])
    fps = sum(1 for r in rows if r["expected"] == "ACCEPT" and r["actual"] == "REJECT")
    fns = sum(1 for r in rows if r["expected"] == "REJECT" and r["actual"] == "ACCEPT")
    timeouts = sum(1 for r in rows if r["actual"] == "TIMEOUT")
    errors = sum(1 for r in rows if r["actual"] == "ERROR")

    print(f"=== Prevail Suite: {args.catalogue} ===")
    print(f"Total: {total}  Passed: {passed}  FP: {fps}  FN: {fns}  Timeout: {timeouts}  Error: {errors}")
    print(f"Duration: {duration:.2f}s\n")
    for r in rows:
        tag = "PASS" if r["matches"] else "FAIL"
        print(f"  [{tag}]  exp={r['expected']:6s}  got={r['actual']:7s}  {r['name']}")
        if r["detail"] and not r["matches"]:
            print(f"          detail: {r['detail']}")

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        json_path = out_dir / f"prevail_run_{ts}.json"
        json_path.write_text(json.dumps({
            "catalogue": str(args.catalogue),
            "summary": {"total": total, "passed": passed, "false_positives": fps,
                        "false_negatives": fns, "timeouts": timeouts, "errors": errors,
                        "duration_secs": duration},
            "tests": rows,
        }, indent=2))
        print(f"\nJSON: {json_path}")

    return 0 if (fns == 0 and fps == 0) else 1


# ============================================================
# Benchmark mode (no catalogue; expectation inferred from project)
# ============================================================

def cmd_benchmark(args) -> int:
    root = expand(args.dir)
    if not root.is_dir():
        print(f"Error: not a directory: {root}", file=sys.stderr)
        return 2

    files = sorted(p for p in root.rglob("*.o") if p.is_file())
    tasks = []
    for p in files:
        try:
            project = p.relative_to(root).parts[0] if len(p.relative_to(root).parts) > 1 else "unknown"
        except ValueError:
            project = "unknown"
        if project == "build":
            continue
        if args.project and project != args.project:
            continue
        expected_accept = project != "invalid"
        tasks.append((p, project, expected_accept))

    print(f"=== PREVAIL Benchmark ===")
    print(f"Root: {root}")
    if args.project:
        print(f"Filter project: {args.project}")
    print(f"Files matched: {len(tasks)}\n")
    if not tasks:
        return 0

    started = datetime.datetime.now()
    records = run_alivio(args.alivio, [t[0] for t in tasks], args.alivio_flag)
    duration = (datetime.datetime.now() - started).total_seconds()

    by_file: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_file[r["file"]].append(r)

    results = []
    stats = {
        "total_files": 0, "files_passed": 0, "files_failed": 0, "files_timeout": 0,
        "total_sections": 0, "sections_passed": 0, "sections_timeout": 0,
        "expected_accept": 0, "expected_reject": 0,
        "false_positives": 0, "false_negatives": 0,
    }

    for path, project, expected_accept in tasks:
        recs = by_file.get(str(path), [])
        n_secs = len(recs)
        n_pass = sum(1 for r in recs if r["status"] == "PASS")
        n_timeout = sum(1 for r in recs if r["status"] == "TIMEOUT")
        n_fail = sum(1 for r in recs if r["status"] not in ("PASS", "TIMEOUT"))
        file_passed = n_secs > 0 and n_pass == n_secs
        file_timeout = n_timeout > 0 and n_fail == 0 and not file_passed

        stats["total_files"] += 1
        stats["total_sections"] += n_secs
        stats["sections_passed"] += n_pass
        stats["sections_timeout"] += n_timeout
        if expected_accept:
            stats["expected_accept"] += 1
        else:
            stats["expected_reject"] += 1
        if file_passed:
            stats["files_passed"] += 1
            if not expected_accept:
                stats["false_negatives"] += 1
        elif file_timeout:
            stats["files_timeout"] += 1
        else:
            stats["files_failed"] += 1
            if expected_accept:
                stats["false_positives"] += 1

        matches = (file_passed if expected_accept else (not file_passed and not file_timeout))
        results.append({
            "file": path.name,
            "file_path": str(path),
            "project": project,
            "passed": file_passed,
            "timeout": file_timeout,
            "expected_accept": expected_accept,
            "matches_expectation": matches,
            "details": [{"section": r.get("section"), "status": r["status"],
                         "time_ms": r.get("time_ms"), "error": r.get("error")} for r in recs],
        })

    pct = lambda a, b: (100.0 * a / b) if b else 0.0
    correct = (stats["expected_accept"] + stats["expected_reject"]
               - stats["false_positives"] - stats["false_negatives"])
    correctness = pct(correct, stats["expected_accept"] + stats["expected_reject"])

    print("========================================")
    print("       PREVAIL Benchmark Results")
    print("========================================")
    print(f"Total Files:      {stats['total_files']}")
    print(f"Files Passed:     {stats['files_passed']} ({pct(stats['files_passed'], stats['total_files']):.1f}%)")
    print(f"Files Failed:     {stats['files_failed']}")
    print(f"Files Timeout:    {stats['files_timeout']}")
    print()
    print(f"Expected ACCEPT:  {stats['expected_accept']}")
    print(f"Expected REJECT:  {stats['expected_reject']}")
    if stats['false_negatives']:
        print(f"SOUNDNESS ISSUES: {stats['false_negatives']} (expected REJECT, got ACCEPT) <<<")
    else:
        print("Soundness issues: 0 (good!)")
    print(f"Precision issues: {stats['false_positives']} (expected ACCEPT, got REJECT)")
    print()
    print(f"Correctness:      {correctness:.1f}%")
    print(f"Duration:         {duration:.2f}s")
    print("========================================\n")

    for r in results:
        if not r["expected_accept"] and r["passed"]:
            print(f"  !!! SOUNDNESS: [{r['project']}] {r['file']}")
    for r in results:
        if r["expected_accept"] and not r["passed"] and not r["timeout"]:
            print(f"  PRECISION: [{r['project']}] {r['file']}")
            for d in r["details"]:
                if d["status"] != "PASS":
                    msg = d["error"] or d["status"]
                    print(f"      - {d['section']}: {msg}")

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        suffix = "prevail_benchmark"
        if args.project:
            suffix += f"_{args.project}"
        suffix += "_" + datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        json_path = out_dir / f"{suffix}_results.json"
        json_path.write_text(json.dumps({
            "summary": {**stats, "duration_secs": duration,
                        "filters": {"project": args.project} if args.project else {}},
            "results": results,
        }, indent=2))
        print(f"\nJSON: {json_path}")

    return 0 if stats["false_negatives"] == 0 else 1


# ============================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--alivio", default=os.environ.get("ALIVIO", DEFAULT_ALIVIO))
    p.add_argument("--alivio-flag", action="append", default=[],
                   help="Pass an extra flag through to alivio. Repeatable.")
    p.add_argument("--output-dir", default="./results/prevail",
                   help="Where to drop JSON reports (default ./results/prevail). Empty string = no JSON.")

    sub = p.add_subparsers(dest="cmd", required=True)
    sl = sub.add_parser("list"); sl.add_argument("catalogue"); sl.set_defaults(func=cmd_list)
    ss = sub.add_parser("single"); ss.add_argument("catalogue"); ss.add_argument("test"); ss.set_defaults(func=cmd_single)
    sr = sub.add_parser("run"); sr.add_argument("catalogue"); sr.set_defaults(func=cmd_run)
    sb = sub.add_parser("benchmark"); sb.add_argument("dir"); sb.add_argument("--project"); sb.set_defaults(func=cmd_benchmark)

    args = p.parse_args()
    if not args.output_dir:
        args.output_dir = None
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
