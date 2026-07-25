#!/usr/bin/env bash
# End-to-end demo (Linux / cloudlab): alivio proves what the kernel can't.
#
# Three steps, run live:
#   [A] kernel verifier alone        → expect some program(s) rejected
#   [B] alivio produces a bundle       → show contents
#   [C] kernel verifier WITH bundle  → expect all programs accepted
#
# Usage:
#   ./scripts/demo_e2e.sh <prog.bpf.o> [--type TYPE] [--no-pause]
#
# Args:
#   <prog.bpf.o>   Path to a BPF object. If outside ~/BCF, gets staged
#                  into ~/BCF/sweep/ so the VM can see it via virtiofs.
#   --type TYPE    libbpf program-type name (default: classifier).
#   --no-pause     Skip the interactive pauses (CI / replay mode).
#
# Prereqs: SETUP.md steps 0–7 done. VM running, test_loader compiled in-VM.

set -e

# ─── config / paths ─────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALIVIO="${ALIVIO:-$REPO_ROOT/target/release/alivio}"
VM_SSH=(ssh -i "$HOME/BCF/imgs/bookworm.id_rsa" -p 10023
        -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5
        root@localhost)
VM_LOADER="/root/bcf/sweep/test_loader"

PROG_TYPE="classifier"
NO_PAUSE=0
OBJ_LOCAL=""

# ─── arg parsing ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --type)     PROG_TYPE=$2; shift 2 ;;
        --no-pause) NO_PAUSE=1;   shift   ;;
        --help|-h)
            sed -n '2,18p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        -*) echo "unknown flag: $1" >&2; exit 2 ;;
        *)  OBJ_LOCAL=$1; shift ;;
    esac
done

[[ -z "$OBJ_LOCAL" ]] && { echo "usage: $0 <prog.bpf.o> [--type TYPE] [--no-pause]" >&2; exit 2; }
[[ -f "$OBJ_LOCAL" ]] || { echo "error: not a file: $OBJ_LOCAL" >&2; exit 1; }

OBJ_NAME=$(basename "$OBJ_LOCAL")

# ─── helpers ────────────────────────────────────────────────────────
pause()  { [[ $NO_PAUSE == 1 ]] && return; echo; echo "─── press Enter ───"; read -r; echo; }
banner() { echo; printf '%.0s═' {1..72}; echo; echo "  $1"; printf '%.0s═' {1..72}; echo; }
die()    { echo "error: $*" >&2; exit 1; }

# ─── pre-flight ─────────────────────────────────────────────────────
[[ -x "$ALIVIO" ]] || die "alivio not built — see SETUP.md step 5 (path: $ALIVIO)"
"${VM_SSH[@]}" "test -x $VM_LOADER" 2>/dev/null \
    || die "VM not reachable or test_loader missing — see SETUP.md steps 6 + 7"

# ─── stage object so the VM can see it ──────────────────────────────
# ~/BCF is mounted in the VM at /root/bcf. If the object is already
# under ~/BCF/ it's visible as-is; otherwise copy to ~/BCF/sweep/.
case "$(realpath "$OBJ_LOCAL")" in
    "$HOME/BCF/"*)
        OBJ_HOST_PATH=$(realpath "$OBJ_LOCAL")
        ;;
    *)
        mkdir -p "$HOME/BCF/sweep"
        OBJ_HOST_PATH="$HOME/BCF/sweep/$OBJ_NAME"
        cp -f "$OBJ_LOCAL" "$OBJ_HOST_PATH"
        ;;
esac
OBJ_VM_PATH="/root/bcf${OBJ_HOST_PATH#$HOME/BCF}"
BUNDLE_HOST_PATH="$OBJ_HOST_PATH.bcf-bundle"
BUNDLE_VM_PATH="$OBJ_VM_PATH.bcf-bundle"

# Clean slate: drop any stale bundle + clear VM dmesg
rm -f "$BUNDLE_HOST_PATH"
"${VM_SSH[@]}" 'dmesg -c >/dev/null' || true

# ─── intro ──────────────────────────────────────────────────────────
banner "Target"
cat <<INTRO
  Object        : $OBJ_NAME
  Host path     : $OBJ_HOST_PATH
  VM path       : $OBJ_VM_PATH ($(ls -la "$OBJ_HOST_PATH" | awk '{print $5}') bytes)
  Program type  : $PROG_TYPE
  Programs      : $(llvm-objdump -h "$OBJ_HOST_PATH" 2>/dev/null \
                    | awk '/^ +[0-9]+ / && $2 !~ /^\./ {print $2}' | wc -l) sections
INTRO
pause

# ─── STEP A: kernel alone ───────────────────────────────────────────
banner "[A]  Kernel verifier WITHOUT proof bundle"
cat <<EXPLAIN_A
Loader:  $VM_LOADER   (our test_loader, invoked WITHOUT a bundle arg).
Flag:    --per-prog   isolate each program in the .o so we see exactly
                      which one(s) the kernel rejects, instead of the
                      whole-object load failing as a single unit.
EXPLAIN_A
echo
echo "\$ $VM_LOADER --type $PROG_TYPE --per-prog $OBJ_VM_PATH"
echo
A_OUTPUT=$("${VM_SSH[@]}" "$VM_LOADER --type $PROG_TYPE --per-prog $OBJ_VM_PATH" 2>&1 || true)
echo "$A_OUTPUT" | grep -E "PERPROG (OK|FAIL|SUMMARY)|errno=" | tail -20
A_FAILS=$(echo "$A_OUTPUT" | grep -c "PERPROG FAIL" || true)
echo
if [[ "$A_FAILS" -gt 0 ]]; then
    echo "  ↑ $A_FAILS program(s) rejected by the kernel verifier. alivio's job: discharge them."
else
    echo "  ↑ kernel accepted everything — this object doesn't need a bundle."
    echo "    (Demo will still produce a bundle so you can see the format.)"
fi
pause

# ─── STEP B: alivio produces bundle ──────────────────────────────────
banner "[B]  alivio verifies + emits proof bundle"
cat <<EXPLAIN_B
alivio:   the userspace eBPF abstract-interpretation verifier (this repo).
Bundle:  sidecar .bcf-bundle file. Each entry is
             (cond_hash, kind, goal_bytes, proof_bytes)
         where cond_hash is the canonical hash of the path condition
         the kernel will recompute at the same reject site (kernel and
         alivio agree byte-for-byte); kind is UNREACHABLE or REFINE;
         proof is cvc5's Alethe-format witness, re-checked by the
         tiny in-kernel BCF proof checker.
EXPLAIN_B
echo
echo "\$ alivio --bcf --kernel-mode verify $OBJ_HOST_PATH"
echo
time "$ALIVIO" --bcf --kernel-mode verify "$OBJ_HOST_PATH" 2>&1 \
    | grep -E "Total|Pass|Fail|Timeout|Error|bundle|wrote" | tail -8

if [[ -f "$BUNDLE_HOST_PATH" ]]; then
    echo
    ls -la "$BUNDLE_HOST_PATH" | awk '{print "Bundle:", $NF, $5, "bytes"}'
    echo
    echo "─── Bundle contents (first 8 entries) ───"
    python3 - "$BUNDLE_HOST_PATH" <<'PYEOF'
import struct, sys
b = open(sys.argv[1], "rb").read()
magic, count = struct.unpack_from("<II", b, 0)
print(f"  magic    : 0x{magic:08x}")
print(f"  entries  : {count}")
print(f"  size     : {len(b):,} bytes")
print()
print(f"  {'#':>3}  {'cond_hash':>18}  {'kind':>11}  {'goal':>6}  {'proof':>6}")
print('  ' + '─'*60)
kinds = {1: 'REFINE', 2: 'UNREACHABLE'}
for i in range(min(8, count)):
    o = 16 + i*28
    h, gof, gln, pof, pln, k = struct.unpack_from("<QIIIII", b, o)
    print(f"  {i:>3}  0x{h:016x}  {kinds.get(k,'?'):>11}  {gln:>4}B  {pln:>5}B")
if count > 8:
    print(f"  ...  ({count-8} more)")
PYEOF
else
    echo
    echo "  (alivio did not emit a bundle — nothing to discharge for this object)"
    exit 0
fi
pause

# ─── STEP C: kernel with bundle ─────────────────────────────────────
banner "[C]  Kernel verifier WITH proof bundle  (BCF discharge)"
cat <<EXPLAIN_C
Loader:  $VM_LOADER   (same binary as [A], now with the bundle attached).
         Each bpf_prog_load() call passes the bundle, so when the kernel
         verifier hits a reject site it consults the bundle's proof
         instead of returning -EACCES.
EXPLAIN_C
echo
echo "\$ $VM_LOADER --type $PROG_TYPE --per-prog $OBJ_VM_PATH $BUNDLE_VM_PATH"
echo
C_OUTPUT=$("${VM_SSH[@]}" "$VM_LOADER --type $PROG_TYPE --per-prog $OBJ_VM_PATH $BUNDLE_VM_PATH" 2>&1 || true)
echo "$C_OUTPUT" | grep -E "PERPROG (FAIL|SUMMARY)|errno=" | tail -10
C_FAILS=$(echo "$C_OUTPUT" | grep -c "PERPROG FAIL" || true)
echo
if [[ "$C_FAILS" -eq 0 && "$A_FAILS" -gt 0 ]]; then
    echo "  ↑ all programs loaded. $A_FAILS → 0 rejections, discharged by alivio's bundle."
elif [[ "$C_FAILS" -eq 0 ]]; then
    echo "  ↑ all programs loaded."
else
    echo "  ↑ $C_FAILS program(s) STILL rejected. Bundle didn't cover them."
fi

echo
echo "  Kernel dmesg (BCF discharge):"
"${VM_SSH[@]}" 'dmesg | grep -E "bcf_check_proof|bcf_bundle_prevalidate" | tail -5' || true
