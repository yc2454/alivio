#!/usr/bin/env python3
"""calico-337 sweep: FAN-OUT + LOAD driver (runs on the CloudLab BOX).

1. Fan-out: for each variant, copy the clang-15 rep bundle to every clang
   sibling's sidecar (dedup: cross-clang bundles are byte-identical, validated).
2. Load: whole-object load each .o in the VM via test_loader, record
   FULL-LOAD vs reject + first failing program + reject reason.

The VM shares the box's BCF/bpf-progs at /root/bcf/bpf-progs, so a bundle
written to the box sidecar appears in the VM automatically.

Reads the variants TSV (variant,heavy,cost_bytes,nclang,rep_rel,obj_rels).
Writes results TSV: obj_rel, variant, heavy, status(loaded|reject|timeout|err),
first_fail_prog, reject_pc, bundle_bytes.

Usage: load_sweep.py <variants.tsv> <out.tsv> <load_cap_s>
"""
import os, sys, csv, shutil, subprocess, re

BPF = "/users/yc1795/BCF/bpf-progs"
KEY = "/users/yc1795/BCF/imgs/bookworm.id_rsa"
VMSSH = ["ssh", "-i", KEY, "-p", "10023", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "ServerAliveInterval=30",
         "-q", "root@localhost"]
TL = "/root/bcf/build/test_loader"

def fanout(rows):
    n = 0
    for r in rows:
        rep = r["rep_rel"]
        rb = os.path.join(BPF, rep) + ".bcf-bundle"
        if not os.path.exists(rb):
            continue
        for o in r["obj_rels"].split(","):
            if o == rep:
                continue
            dst = os.path.join(BPF, o) + ".bcf-bundle"
            shutil.copyfile(rb, dst)
            n += 1
    return n

def vm_load(obj_rel, cap):
    vobj = f"/root/bcf/bpf-progs/{obj_rel}"
    vbun = vobj + ".bcf-bundle"
    cmd = VMSSH + [f"timeout {cap} {TL} --type classifier {vobj} {vbun} 2>&1"]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=cap + 30, stdin=subprocess.DEVNULL)
        out = p.stdout.decode(errors="replace")
        rc = p.returncode
    except subprocess.TimeoutExpired:
        return "timeout", "-", "-"
    if "failed to load" in out or "Permission denied" in out or "errno=" in out:
        prog = "-"; pc = "-"
        m = re.search(r"prog '([^']+)': failed to load", out)
        if m: prog = m.group(1)
        # last "NNN: (..)" before the reject line is the reject pc
        pcs = re.findall(r"^(\d+): \(", out, re.M)
        if pcs: pc = pcs[-1]
        return "reject", prog, pc
    if rc == 124:
        return "timeout", "-", "-"
    if rc != 0:
        return "err", f"rc={rc}", "-"
    return "loaded", "-", "-"

def main():
    lst, out, cap = sys.argv[1:4]
    cap = int(cap)
    rows = list(csv.DictReader(open(lst), delimiter="\t"))
    nf = fanout(rows)
    print(f"fan-out: copied {nf} sibling bundles", flush=True)
    res = []
    # flatten to per-object
    objs = []
    for r in rows:
        for o in r["obj_rels"].split(","):
            objs.append((o, r))
    for i, (o, r) in enumerate(objs, 1):
        bb = os.path.join(BPF, o) + ".bcf-bundle"
        bsz = os.path.getsize(bb) if os.path.exists(bb) else 0
        if bsz == 0:
            st, prog, pc = "no_bundle", "-", "-"
        else:
            st, prog, pc = vm_load(o, cap)
        print(f"[{i}/{len(objs)}] {st:9s} {prog:40s} pc={pc:>5} {os.path.basename(o)}", flush=True)
        res.append({"obj_rel": o, "variant": r["variant"], "heavy": r["heavy"],
                    "status": st, "first_fail_prog": prog, "reject_pc": pc,
                    "bundle_bytes": bsz})
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(res[0].keys()))
            w.writeheader(); w.writerows(res)
    loaded = sum(1 for x in res if x["status"] == "loaded")
    print(f"DONE {loaded}/{len(res)} FULL-LOAD -> {out}", flush=True)

if __name__ == "__main__":
    main()
