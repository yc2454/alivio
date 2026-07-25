#!/usr/bin/env python3
"""calico-337 sweep: BUILD driver (machine-agnostic, Mac or CloudLab box).

Builds ONE bundle per source-variant (the clang-15 rep), to CLEAN EXIT.
Bundles are written incrementally by alivio, so a killed build = INCOMPLETE
bundle = false kernel reject. Therefore we run to rc=0; the cap is only a
safety net and a cap-hit is recorded as rc='timeout' (distinct signal).

For dedup re-validation, --sibling-check builds the clang-16 (or -17) sibling
of each variant too and cmp's the two bundles; any mismatch is FATAL (it means
cross-clang dedup does NOT hold and we must build every clang version).

Reads a TSV with columns: variant, heavy, cost_bytes, nclang, rep_rel, obj_rels
(obj_rels = comma-separated rel paths of all clang siblings, rel = calico/<file>)

Concurrency: --jobs N runs up to N builds at once, BUT each worker waits to
start a new build until free RAM is above --min-free-gb (default 8). This
self-throttles the no_log bloat tail (which balloons in phase-2 exploration)
without hard-capping the cheap light builds. At least one build always runs
even if RAM is tight (so it can't deadlock). Light objects fly N-wide; heavy
stretches naturally drop to whatever fits.

Usage:
  build_sweep.py <list.tsv> <base_dir> <alivio_bin> <out.tsv> <cap_s> \
      [--sibling-check] [--jobs N] [--min-free-gb G]
    base_dir = dir that contains calico/ (Mac: ~/BCF/bpf-progs ; box: /users/yc1795/BCF/bpf-progs)
"""
import os, sys, time, subprocess, csv, hashlib, threading
from concurrent.futures import ThreadPoolExecutor

def free_gb():
    """Portable available-RAM in GB (Linux /proc/meminfo, macOS vm_stat)."""
    try:
        with open("/proc/meminfo") as f:
            for ln in f:
                if ln.startswith("MemAvailable:"):
                    return int(ln.split()[1]) / (1024 * 1024)
    except FileNotFoundError:
        try:
            out = subprocess.check_output(["vm_stat"]).decode()
            ps = 4096
            free = spec = 0
            for ln in out.splitlines():
                if "page size of" in ln:
                    ps = int(ln.split("page size of")[1].split()[0])
                if ln.startswith("Pages free:"): free = int(ln.split()[-1].strip("."))
                if ln.startswith("Pages speculative:"): spec = int(ln.split()[-1].strip("."))
                if ln.startswith("Pages inactive:"): inact = int(ln.split()[-1].strip("."))
            return (free + spec + inact) * ps / (1024**3)
        except Exception:
            return 999.0
    return 999.0

_active = 0
_lock = threading.Lock()

def admit(min_free):
    """Block until it's safe to start a build: free RAM above floor, OR we're
    the only build running (guarantees forward progress)."""
    global _active
    while True:
        with _lock:
            if _active == 0 or free_gb() >= min_free:
                _active += 1
                return
        time.sleep(5)

def release():
    global _active
    with _lock:
        _active -= 1

def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

def build_one(abs_obj, alivio, cap):
    bundle = abs_obj + ".bcf-bundle"
    try: os.remove(bundle)
    except FileNotFoundError: pass
    env = os.environ.copy()
    cmd = [alivio, "--kernel-mode", "verify", "--bcf", abs_obj]
    t0 = time.monotonic()
    try:
        with open("/tmp/bs_build.log", "w") as lf:
            p = subprocess.run(cmd, env=env, stdout=lf, stderr=subprocess.STDOUT, timeout=cap)
        rc = str(p.returncode)
    except subprocess.TimeoutExpired:
        rc = "timeout"
    wall = time.monotonic() - t0
    size = os.path.getsize(bundle) if os.path.exists(bundle) else 0
    return wall, rc, size, bundle

def arg(flag, default):
    a = sys.argv[6:]
    return a[a.index(flag) + 1] if flag in a else default

def main():
    lst, base, alivio, out, cap = sys.argv[1:6]
    cap = int(cap)
    sibcheck = "--sibling-check" in sys.argv[6:]
    skip_existing = "--skip-existing" in sys.argv[6:]
    jobs = int(arg("--jobs", "1"))
    min_free = float(arg("--min-free-gb", "8"))
    alivio_mtime = os.path.getmtime(alivio)
    rows = list(csv.DictReader(open(lst), delimiter="\t"))
    n = len(rows)
    res = [None] * n
    done = [0]
    wlock = threading.Lock()

    def work(i, r):
        rep_rel = r["rep_rel"]
        abs_obj = os.path.join(base, rep_rel)
        if not os.path.exists(abs_obj):
            res[i] = {"variant": r["variant"], "rep_rel": rep_rel, "wall_s": 0,
                      "rc": "missing", "bundle_bytes": 0, "md5": "-", "sibling": "-"}
            print(f"[{i+1}/{n}] MISSING {rep_rel}", flush=True); return
        bundle = abs_obj + ".bcf-bundle"
        if skip_existing and os.path.exists(bundle) and os.path.getmtime(bundle) > alivio_mtime \
                and os.path.getsize(bundle) > 0:
            size = os.path.getsize(bundle); m = md5(bundle)
            res[i] = {"variant": r["variant"], "rep_rel": rep_rel, "wall_s": 0,
                      "rc": "skip", "bundle_bytes": size, "md5": m, "sibling": "-"}
            with wlock:
                done[0] += 1
                print(f"[{done[0]}/{n}]   SKIP (have {size/1e6:.1f}MB) {os.path.basename(rep_rel)}", flush=True)
            return
        admit(min_free)
        try:
            wall, rc, size, bundle = build_one(abs_obj, alivio, cap)
        finally:
            release()
        m = md5(bundle) if size else "-"
        sib = "-"
        if sibcheck:
            sibs = [o for o in r["obj_rels"].split(",") if o != rep_rel]
            if sibs and os.path.exists(os.path.join(base, sibs[0])):
                admit(min_free)
                try:
                    sw, src, ssz, sbun = build_one(os.path.join(base, sibs[0]), alivio, cap)
                finally:
                    release()
                smd5 = md5(sbun) if ssz else "-"
                sib = "MATCH" if (smd5 == m and m != "-") else f"MISMATCH({smd5}vs{m})"
        res[i] = {"variant": r["variant"], "rep_rel": rep_rel, "wall_s": round(wall, 1),
                  "rc": rc, "bundle_bytes": size, "md5": m, "sibling": sib}
        with wlock:
            done[0] += 1
            print(f"[{done[0]}/{n}] {wall:6.0f}s rc={rc:>7} {size/1e6:7.1f}MB free={free_gb():.0f}G "
                  f"{os.path.basename(rep_rel)} {sib}", flush=True)
            with open(out, "w", newline="") as f:
                rows_done = [x for x in res if x]
                w = csv.DictWriter(f, fieldnames=list(rows_done[0].keys()),
                                   delimiter="\t", lineterminator="\n")
                w.writeheader(); w.writerows(rows_done)

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        list(ex.map(lambda a: work(*a), list(enumerate(rows))))
    print(f"DONE {sum(1 for x in res if x)} builds (jobs={jobs}) -> {out}", flush=True)

if __name__ == "__main__":
    main()
