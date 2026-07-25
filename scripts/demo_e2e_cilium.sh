#!/usr/bin/env bash
# End-to-end demo: alivio proves what the kernel can't.
#
# Target: cilium wireguard datapath (clang-17, -O1). 18 BPF programs.
# Without a proof bundle the kernel rejects one of them.
# alivio produces the bundle. With the bundle the kernel accepts all 18.
#
# Three steps, run live. Each step has a "PAUSE" — press Enter to continue.

set -e
ALIVIO="$HOME/eBPF-Zone-Verifier/target/release/alivio"
OBJ_LOCAL="$HOME/BCF/bpf-progs/cilium/clang-17_-O1_bpf_wireguard.o"
OBJ_NAME="clang-17_-O1_bpf_wireguard.o"
CL_HOST="yc1795@ms0802.utah.cloudlab.us"
VM_SSH=(ssh -i /users/yc1795/BCF/imgs/bookworm.id_rsa -p 10023 -o BatchMode=yes -o StrictHostKeyChecking=no root@localhost)
VM_DIR="/root/bcf/sweep"
LOADER_PLAIN="/root/bcf/build/test_loader"
LOADER_BCF="/root/bcf/sweep/tl2"

pause() {
    echo
    echo "─── press Enter ───"
    read -r
    echo
}

banner() {
    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "════════════════════════════════════════════════════════════════"
}

# ─── Setup: make sure no stale bundle on Mac side, clear VM dmesg ──
banner "Setup"
rm -f /tmp/${OBJ_NAME}.bcf-bundle
cp "$OBJ_LOCAL" /tmp/
ssh "$CL_HOST" "${VM_SSH[*]} 'dmesg -c > /dev/null'" >/dev/null
cat <<'TARGET'
Target binary:  clang-17_-O1_bpf_wireguard.o

  Source:       cilium (Kubernetes CNI). bpf_wireguard.o is the BPF
                datapath that ships with cilium's WireGuard transparent-
                encryption feature
  Compiler:     clang-17, -O1
  Section:      tc       (Linux Traffic Control hook)
  # progs:      18  (1 TC entry + 17 tail-call programs)

  Program inventory (the 18 verifier objects in this .o):
    cil_to_wireguard                       TC entry  — hook on the wg iface
    tail_srv6_decap                        SRv6 segment-routing decap
    tail_nodeport_ipv6_dsr     ◀── FAIL    IPv6 NodePort, Direct Server Return
    tail_nodeport_ipv4_dsr                 IPv4 NodePort, Direct Server Return
    tail_nodeport_{nat,rev_dnat}_*v4/v6    NodePort SNAT/DNAT (4 progs)
    tail_handle_{snat,nat}_fwd_ipv4/v6     SNAT/NAT forwarding (4 progs)
    …                                      (and 5 more tail-call helpers)
TARGET
echo
ls -la "$OBJ_LOCAL" | awk '{print "Object size:", $5, "bytes"}'
pause

# ─── STEP A: kernel verifier alone — show 17/18 ──
banner "Step [A]  Kernel verifier WITHOUT proof bundle"
cat <<'EXPLAIN_A'
Loader:  test_loader  — the stock kernel BPF selftest loader
                       (kernel tree: tools/testing/selftests/bpf/test_loader.c).
                       BCF-unaware: it simply calls bpf_prog_load() on each
                       program. If the kernel verifier rejects, that's that.
Flags:   --type classifier   program type: TC classifier (the section is "tc")
         --per-prog          isolate per program — load each of the 18
                             programs separately so we can see WHICH one
                             the verifier rejects, instead of the whole
                             object failing as one unit.
EXPLAIN_A
echo
echo "\$ ssh VM '$LOADER_PLAIN --type classifier --per-prog $VM_DIR/$OBJ_NAME'"
echo
ssh "$CL_HOST" "${VM_SSH[*]} '$LOADER_PLAIN --type classifier --per-prog $VM_DIR/$OBJ_NAME'" 2>&1 | \
    grep -E "PERPROG (FAIL|SUMMARY)|errno=" | tail -8
echo
echo "  ↑ tail_nodeport_ipv6_dsr REJECTED (errno=13 / EACCES)"
echo "  ↑ cilium wireguard load: 17/18 — incomplete."
pause

# ─── STEP B: run alivio, produce bundle ──
banner "Step [B]  alivio (userspace) verifies + emits proof bundle"
cat <<'EXPLAIN_B'
alivio:   the userspace eBPF abstract-interpretation verifier we built.

Bundle:  the sidecar `.bcf-bundle` file alivio emits next to the .o.
         Layout:  HEADER (16B magic+count) + ENTRIES table + payloads.
         Each entry is a tuple
             (cond_hash, kind, goal_bytes, proof_bytes)
         where
             cond_hash    canonical hash of the path condition the
                          kernel verifier will compute when it hits
                          the same reject site (kernel and alivio
                          agree byte-for-byte on this hash);
             kind         UNREACHABLE (the path is dead) or REFINE
                          (tighten a bound);
             goal_bytes   post-order serialized expression tree —
                          the symbolic formula that has to be proven;
             proof_bytes  cvc5-emitted Alethe-format proof that
                          discharges the goal. Kernel re-checks this
                          with a tiny in-kernel proof checker (no cvc5
                          in-kernel).
EXPLAIN_B
echo
echo "\$ alivio verify --kernel-mode --bcf $OBJ_NAME"
echo
time "$ALIVIO" verify --kernel-mode --bcf /tmp/$OBJ_NAME 2>&1 | \
    grep -E "Total|Pass|Fail|Timeout|Error|bundle|wrote" | tail -8
echo
ls -la /tmp/${OBJ_NAME}.bcf-bundle | awk '{print "Bundle:", $NF, $5, "bytes"}'
echo
echo "─── Bundle contents (first 8 of 46 entries) ───"
python3 <<PYEOF
import struct
b = open("/tmp/${OBJ_NAME}.bcf-bundle","rb").read()
magic, count = struct.unpack_from("<II", b, 0)
print(f"  magic    : 0x{magic:08x} ('{bytes.fromhex(format(magic,'08x'))[::-1].decode()}')")
print(f"  entries  : {count}  (each entry = 1 discharged unreachability proof)")
print(f"  size     : {len(b):,} bytes")
print()
print(f"  {'#':>3}  {'cond_hash':>18}  {'kind':>11}  {'goal':>6}  {'proof':>6}")
print('  ' + '─'*60)
kinds = {1:'REFINE', 2:'UNREACHABLE'}
for i in range(min(8,count)):
    o = 16+i*28
    h,gof,gln,pof,pln,k = struct.unpack_from("<QIIIII", b, o)
    print(f"  {i:>3}  0x{h:016x}  {kinds.get(k,'?'):>11}  {gln:>4}B  {pln:>5}B")
print(f"  ...  ({count-8} more)")
PYEOF
pause

# ─── ship bundle to VM ──
banner "  (ship bundle to VM)"
scp -q /tmp/${OBJ_NAME}.bcf-bundle "$CL_HOST":/tmp/
ssh -q "$CL_HOST" "scp -q -i /users/yc1795/BCF/imgs/bookworm.id_rsa -P 10023 /tmp/${OBJ_NAME}.bcf-bundle root@localhost:$VM_DIR/${OBJ_NAME}.bcf-bundle"
echo "  bundle delivered to VM:$VM_DIR/${OBJ_NAME}.bcf-bundle"
pause

# ─── STEP C: kernel WITH bundle ──
banner "Step [C]  Kernel verifier WITH proof bundle  (BCF discharge)"
cat <<'EXPLAIN_C'
Loader:  tl2  — our patched fork of test_loader (sits at /root/bcf/sweep/tl2.c
                on the VM). Differences from stock test_loader:
                  1. takes a second argument: the .bcf-bundle path
                  2. attaches the bundle to each bpf_prog_load() so that
                     when the kernel verifier hits a rejection, it consults
                     the bundle and dispatches a proof check (BCF) instead
                     of returning -EACCES
                  3. sets log_level=2 per program so we get rich verifier
                     traces in dmesg on FAIL (useful for diagnosis)
                The kernel itself is a BCF-aware bpf-next build — same TCB
                surface as upstream.
Args:    --type classifier        same as Step [A]
         --per-prog               same as Step [A]
         <obj.o> <obj.o.bcf-bundle>   binary + the proof bundle from alivio
EXPLAIN_C
echo
echo "\$ ssh VM '$LOADER_BCF --type classifier --per-prog $VM_DIR/$OBJ_NAME $VM_DIR/${OBJ_NAME}.bcf-bundle'"
echo
ssh "$CL_HOST" "${VM_SSH[*]} '$LOADER_BCF --type classifier --per-prog $VM_DIR/$OBJ_NAME $VM_DIR/${OBJ_NAME}.bcf-bundle'" 2>&1 | \
    grep -E "tail_nodeport_ipv6_dsr|PERPROG SUMMARY" | tail -5
echo
echo "  ↑ all 18 programs loaded, including tail_nodeport_ipv6_dsr."
echo
echo "  Kernel dmesg (BCF discharge proof check):"
ssh "$CL_HOST" "${VM_SSH[*]} 'dmesg | grep -E \"bcf_check_proof|bcf_bundle_prevalidate\" | tail -5'"
