#!/usr/bin/env python3
"""
Faithfulness scorecard: alivio (per ELF section) vs the per-program
kernel oracle (test_loader --per-prog, section-keyed), joined on the
ELF section name.

Inputs:
  --oracle FILE   captured VM output, blocks of:
                    === <path-with-objname> ===
                    PERPROG OK   [i] sec=<S> <name>
                    PERPROG FAIL [i] sec=<S> <name> errno=<E>
                    PERPROG SUMMARY loaded=x/n
  --list FILE     Mac absolute object paths (basename joins the oracle)
  [--alivio P] [--timeout S] [--out J]

Per ELF section S of an object:
  oracle verdict(S): the set of libbpf programs whose section_name==S.
    1:1 section  -> that program's OK/FAIL.
    multi-prog S -> kernel-accepts-S iff ALL its programs OK (a section
      "loads" only if every program in it loads); flagged `multi`.
  alivio verdict(S): PASS/FAIL from `Section 'S'... PASS|FAIL`.

Classification (the honest faithfulness table):
  CA correct-accept  kernel OK   & alivio PASS
  CR correct-reject  kernel FAIL & alivio FAIL
  FA FALSE ACCEPT    kernel FAIL & alivio PASS & alivio produced NO bundle
                       <-- the soundness gate (must be 0). alivio claims
                       a kernel-rejected program safe with NOTHING
                       backing it.
  BP bundle-producer kernel FAIL & alivio PASS & alivio DID emit a bundle.
                       The bundle's existence proves bare alivio rejected;
                       alivio emitted a proof obligation the kernel
                       independently re-checks. NOT a soundness defect —
                       an L3-convergence question (does it discharge on
                       the VM?). Same status shift_constraint had before
                       its #1 fix. See feedback_fa_definition_no_bundle.
  FR false-reject    kernel OK   & alivio FAIL
  plus: unmatched-alivio (section alivio verified, no libbpf program),
        unmatched-oracle (libbpf program's section alivio didn't report).
`multi`-tagged rows are counted but reported separately (one alivio
verdict vs several kernel programs — inherently coarser).

Bundle attribution is OBJECT-level (`<obj>.bcf-bundle` existence after a
clean run with the stale file pre-deleted), not per-section: alivio
writes one object-level bundle and prints `Section …` only in the final
SUMMARY, so there is no reliable per-section interleaving to parse. In
the BCF-rejected corpus this is sound by construction — the
kernel-rejected program is the one needing the bundle; sibling sections
are natively kernel-OK and trigger no refinement. The same coarseness
the section-keyed join already accepts.
"""
from __future__ import annotations
import argparse, json, re, subprocess, sys, time
from pathlib import Path
from collections import defaultdict

ALIVIO = "target/release/alivio"
SEC_RE = re.compile(r"^Section '(.+?)'\.\.\. (PASS|FAIL)\s*$", re.M)
PP_RE = re.compile(
    r"^PERPROG (OK|FAIL)\s+\[\d+\] sec=(\S+) (\S+)"
    r"(?: errno=(\d+))?(?: kind=(\S+))?",
    re.M)
HDR_RE = re.compile(r"^=== .*?/([^/ ]+) ===\s*$", re.M)


def parse_oracle(path: str) -> dict:
    """obj basename -> {section: [(name, ok_bool, errno, kind)]}.

    `kind` (test_loader, per failing program):
      "POSTVERIF" — the kernel VERIFIER accepted the program; the load
        failed only at a post-verifier pass (do_misc_fixups /
        fixup_call_args / JIT, -EINVAL). alivio is a *verifier* mirror,
        so accepting such a program is faithful, NOT a false-accept.
      "VREJECT"   — a genuine verifier-core reject (the soundness gate).
      ""          — OK programs / older oracle without kind=.
    """
    txt = Path(path).read_text(errors="replace")
    out: dict = {}
    cur = None
    for line in txt.splitlines():
        h = HDR_RE.match(line)
        if h:
            cur = h.group(1)
            out.setdefault(cur, {})
            continue
        m = PP_RE.match(line)
        if m and cur is not None:
            ok = m.group(1) == "OK"
            sec, name = m.group(2), m.group(3)
            errno = int(m.group(4)) if m.group(4) else 0
            kind = m.group(5) or ""
            out[cur].setdefault(sec, []).append((name, ok, errno, kind))
    return out


def _verifier_ok(p) -> bool:
    """Kernel *verifier* verdict for one program: accepted iff it
    loaded, or it failed only post-verification (POSTVERIF)."""
    name, ok, errno, kind = p
    return ok or kind == "POSTVERIF"


BUNDLE_RE = re.compile(r"wrote bundle: \S+ \((\d+) entries, \d+ bytes\)")


def run_alivio(zov: str, obj: Path, timeout: float) -> dict:
    """Returns {"secs": {section: (passed_bool, reason_or_None)},
                "bundle": bool, "entries": int}.

    `bundle`/`entries`: did this run emit a `<obj>.bcf-bundle` (a proof
    obligation the kernel re-checks)? The stale file is deleted first so
    the post-run signal is reliable; `-q` is dropped so the
    `[bcf] wrote bundle: … (N entries, …)` line is captured (the bundle
    file write itself is verbosity-independent, so existence is also
    cross-checked on disk)."""
    bundle_path = Path(str(obj) + ".bcf-bundle")
    try:
        if bundle_path.exists():
            bundle_path.unlink()
    except OSError:
        pass
    try:
        r = subprocess.run(
            ["gtimeout", str(int(timeout)), zov, "--bcf",
             "--kernel-mode", "verify", str(obj)],
            capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return {}
    out = r.stdout + r.stderr
    verd = {s: (v == "PASS") for s, v in SEC_RE.findall(out)}
    reasons: dict = {}
    in_f = False
    for ln in out.splitlines():
        if "--- FAILURES ---" in ln:
            in_f = True
            continue
        if in_f:
            m = re.match(r"^\s+(\S+):\s*(.+)$", ln)
            if m:
                reasons[m.group(1)] = m.group(2)
    m = BUNDLE_RE.search(out)
    entries = int(m.group(1)) if m else 0
    bundle = bundle_path.exists() or entries > 0
    return {"secs": {s: (p, reasons.get(s)) for s, p in verd.items()},
            "bundle": bundle, "entries": entries}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--list", required=True)
    ap.add_argument("--alivio", default=ALIVIO)
    ap.add_argument("--timeout", type=float, default=150)
    ap.add_argument("--jobs", type=int, default=8,
                    help="parallel alivio workers (default 8 = P-cores; "
                         "machine is 8P+4E). Only the independent alivio "
                         "subprocess runs are parallelized; classification/"
                         "aggregation stays serial & deterministic.")
    ap.add_argument("--out")
    ap.add_argument("--checkpoint", default=None,
                    help="resumable cache of the EXPENSIVE per-object alivio "
                         "results. Default /tmp/fa_scorecard_<oracle-stem>"
                         ".cache.json. Auto-resumes (skips done objects); an "
                         "interrupt loses only in-flight workers. Cache is "
                         "keyed on the alivio binary fingerprint and ignored "
                         "if the binary changed (rebuild => fresh).")
    ap.add_argument("--fresh", action="store_true",
                    help="ignore any existing checkpoint and recompute all.")
    a = ap.parse_args()

    oracle = parse_oracle(a.oracle)
    objs = [Path(l.strip()) for l in open(a.list) if l.strip()]
    agg = defaultdict(int)
    fa_list, bp_list, fr_list, postverif_list, rows = [], [], [], [], []

    # Phase 1 (PARALLEL): run the expensive, independent alivio subprocess
    # per object. alivio is single-threaded so --jobs workers ~= --jobs
    # P-cores of throughput. Nothing here touches shared scorecard state.
    runnable = [o for o in objs if o.exists() and o.name in oracle]
    for o in objs:
        if o not in runnable:
            print(f"[skip] {o.name} (no oracle or file)")

    # Resumable checkpoint of alivio results (the 30-45min cost). The
    # cheap classification (Phase 2) is always recomputed deterministically
    # from these — so we only ever checkpoint the expensive intermediate.
    zp = Path(a.alivio)
    try:
        st = zp.stat()
        zfp = f"{zp.resolve()}:{st.st_mtime_ns}:{st.st_size}"
    except OSError:
        zfp = str(zp)
    ckpt = Path(a.checkpoint or f"/tmp/fa_scorecard_{Path(a.oracle).stem}.cache.json")
    zcache: dict[str, dict] = {}
    if ckpt.exists() and not a.fresh:
        try:
            blob = json.loads(ckpt.read_text())
            if blob.get("_alivio_fp") == zfp:
                zcache = blob.get("results", {})
                print(f"[resume] {len(zcache)} objects from {ckpt} "
                      f"(alivio binary unchanged)")
            else:
                print(f"[fresh] {ckpt} is from a different alivio binary — ignoring")
        except (json.JSONDecodeError, OSError):
            print(f"[fresh] {ckpt} unreadable — ignoring")

    def _flush():
        tmp = ckpt.with_suffix(ckpt.suffix + ".tmp")
        tmp.write_text(json.dumps({"_alivio_fp": zfp, "results": zcache}))
        tmp.replace(ckpt)  # atomic

    todo = [o for o in runnable if str(o) not in zcache]
    print(f"[phase1] {len(zcache)} cached, {len(todo)} to run "
          f"(--jobs {a.jobs}); checkpoint -> {ckpt}")
    import concurrent.futures
    if todo:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
            fut = {ex.submit(run_alivio, a.alivio, o, a.timeout): o for o in todo}
            for i, f in enumerate(concurrent.futures.as_completed(fut), 1):
                zcache[str(fut[f])] = f.result()
                _flush()  # after every object: interrupt loses only in-flight
                if i % 10 == 0 or i == len(todo):
                    print(f"[phase1] {i}/{len(todo)} done, checkpointed", flush=True)

    # Phase 2 (SERIAL, unchanged logic): classify/aggregate deterministically.
    for obj in runnable:
        base = obj.name
        ksec = oracle[base]
        zres = zcache.get(str(obj))
        if not zres or not zres.get("secs"):
            print(f"[skip] {base} (alivio no output / timeout)")
            continue
        zsec = zres["secs"]
        z_bundle = zres["bundle"]
        z_entries = zres["entries"]
        for sec, progs in ksec.items():
            multi = len(progs) > 1
            # alivio mirrors the kernel *verifier*; compare against the
            # verifier verdict, not the load verdict. A section "passes
            # the verifier" iff every program in it is verifier-ok
            # (loaded, or POSTVERIF = verifier-accepted, post-verifier
            # load -EINVAL). load_ok is the stricter actual-load verdict
            # — when verifier-ok but not load-ok, the divergence is a
            # non-verifier kernel stage (JIT/fixups), tracked as
            # POSTVERIF, NOT a verifier false-accept.
            kernel_ok = all(_verifier_ok(p) for p in progs)
            load_ok = all(p[1] for p in progs)
            postverif = kernel_ok and not load_ok
            if sec not in zsec:
                agg["unmatched_oracle"] += 1
                continue
            zpass, zreason = zsec[sec]
            tag = "multi" if multi else "1:1"
            if kernel_ok and zpass:
                cls = "CA"
            elif (not kernel_ok) and (not zpass):
                cls = "CR"
            elif (not kernel_ok) and zpass:
                # alivio accepts a kernel-rejected program. Soundness gate:
                # real FALSE-ACCEPT only if alivio produced NO bundle (no
                # proof obligation — claims safe with nothing backing it).
                # If a bundle WAS emitted, bare alivio rejected and emitted
                # a proof the kernel re-checks ⇒ BP (L3-pending), not a
                # soundness defect. See feedback_fa_definition_no_bundle.
                if z_bundle:
                    cls = "BP"
                    bp_list.append((base, sec, [p[0] for p in progs],
                                    [p[2] for p in progs if not p[1]],
                                    z_entries))
                else:
                    cls = "FA"
                    fa_list.append((base, sec, [p[0] for p in progs],
                                    [p[2] for p in progs if not p[1]]))
            else:
                cls = "FR"
                fr_list.append((base, sec, [p[0] for p in progs], zreason))
            agg[f"{cls}_{tag}"] += 1
            agg[cls] += 1
            if postverif:
                # verifier-faithful but kernel won't load it (JIT/fixup
                # -EINVAL). Surface separately for full transparency.
                agg["POSTVERIF"] += 1
                agg[f"POSTVERIF_{cls}"] += 1
                postverif_list.append(
                    (base, sec, [p[0] for p in progs],
                     [p[2] for p in progs if not p[1]], cls))
            rows.append((base, sec, tag, cls, "PV" if postverif else ""))
        for sec in zsec:
            if sec not in ksec:
                agg["unmatched_alivio"] += 1
        print(f"[ok] {base}: "
              f"CA={agg['CA']} CR={agg['CR']} FA={agg['FA']} FR={agg['FR']}"
              f" (running totals)")

    print("\n==== FAITHFULNESS SCORECARD ====")
    for k in ("CA", "CR", "FA", "BP", "FR"):
        print(f"  {k}: {agg[k]}  "
              f"(1:1={agg[f'{k}_1:1']}, multi={agg[f'{k}_multi']})")
    print(f"  unmatched_oracle(libbpf prog, alivio silent): "
          f"{agg['unmatched_oracle']}")
    print(f"  unmatched_alivio(alivio sec, no libbpf prog): "
          f"{agg['unmatched_alivio']}")
    if fa_list:
        print("\n  *** FALSE ACCEPTS (kernel REJECT, alivio PASS, "
              "NO bundle — soundness gate) ***")
        for base, sec, names, errnos in fa_list:
            print(f"   {base} sec={sec} progs={names} kernel_errno={errnos}")
    else:
        print("\n  *** ZERO no-bundle FALSE ACCEPTS in scored set "
              "(soundness gate held) ***")
    if bp_list:
        print(f"\n  BUNDLE-PRODUCERS: {len(bp_list)} sections — kernel "
              f"REJECT, alivio PASS but EMITTED a bundle (bare alivio "
              f"rejected; proof obligation the kernel re-checks). NOT a "
              f"soundness FA — L3-convergence question (validate discharge "
              f"on the VM). Pre-#1-fix shift_constraint had this status.")
        for base, sec, names, errnos, ent in bp_list:
            print(f"   {base} sec={sec} progs={names} "
                  f"kernel_errno={errnos} bundle_entries={ent}")
    print(f"\n  false-rejects: {len(fr_list)} "
          f"(kernel OK, alivio FAIL — faithfulness-of-reason gap)")
    if postverif_list:
        print(f"\n  POSTVERIF: {len(postverif_list)} sections — kernel "
              f"VERIFIER accepts, load fails at a post-verifier pass "
              f"(JIT/fixup -EINVAL). alivio-as-verifier is faithful here; "
              f"NOT counted as FA. Breakdown by alivio class: "
              f"CA={agg['POSTVERIF_CA']} FR={agg['POSTVERIF_FR']}.")
        for base, sec, names, errnos, cls in postverif_list:
            print(f"   {base} sec={sec} progs={names} "
                  f"kernel_errno={errnos} alivio={cls}")
    if a.out:
        json.dump({"agg": dict(agg), "fa": fa_list, "bp": bp_list,
                   "fr": fr_list, "postverif": postverif_list,
                   "rows": rows},
                  open(a.out, "w"), indent=1)
        print(f"  wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
