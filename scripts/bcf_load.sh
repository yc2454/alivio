#!/usr/bin/env bash
# bcf_load.sh — load a single BPF object via the BCF-authentic path:
# `bpftool -d prog loadall` inside the VM, with the full debug log captured.
#
# Mirrors what BCF's load_prog.py does per object (~/BCF/scripts/load_prog.py
# load_object(), lines 113–127), but as a one-shot CLI.
#
# Usage:
#   ./scripts/bcf_load.sh <prog.bpf.o> [--type TYPE] [--log PATH]
#
# Args:
#   <prog.bpf.o>   Path to a BPF object. If outside ~/BCF, gets staged into
#                  ~/BCF/sweep/ so the VM can see it via virtiofs.
#   --type TYPE    libbpf program-type name (default: classifier).
#   --log PATH     Where to write the bpftool -d log. Default:
#                  ~/BCF/sweep/<obj>.bpftool.log
#
# Prereqs: SETUP.md steps 0–6 done. VM running. (No test_loader needed —
# this script uses the bpftool that ships inside the VM image.)

set -e

# ─── config / paths ─────────────────────────────────────────────────
VM_SSH=(ssh -i "$HOME/BCF/imgs/bookworm.id_rsa" -p 10023
        -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5
        root@localhost)

PROG_TYPE="classifier"
LOG_PATH=""
OBJ_LOCAL=""

# ─── arg parsing ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --type) PROG_TYPE=$2; shift 2 ;;
        --log)  LOG_PATH=$2;  shift 2 ;;
        --help|-h)
            sed -n '2,20p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        -*) echo "unknown flag: $1" >&2; exit 2 ;;
        *)  OBJ_LOCAL=$1; shift ;;
    esac
done

[[ -z "$OBJ_LOCAL" ]] && { echo "usage: $0 <prog.bpf.o> [--type TYPE] [--log PATH]" >&2; exit 2; }
[[ -f "$OBJ_LOCAL" ]] || { echo "error: not a file: $OBJ_LOCAL" >&2; exit 1; }

OBJ_NAME=$(basename "$OBJ_LOCAL")

# ─── pre-flight ─────────────────────────────────────────────────────
"${VM_SSH[@]}" "test -x /usr/bin/bpftool" 2>/dev/null \
    || { echo "error: VM not reachable or /usr/bin/bpftool missing" >&2; exit 1; }

# ─── stage object so the VM can see it ──────────────────────────────
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

# Default log path: alongside the object
[[ -z "$LOG_PATH" ]] && LOG_PATH="${OBJ_HOST_PATH}.bpftool.log"

# Unique pin path so concurrent invocations don't collide
PIN="/sys/fs/bpf/bcf-load-$$"

# ─── load via bpftool inside the VM ─────────────────────────────────
echo "obj       : $OBJ_VM_PATH"
echo "type      : $PROG_TYPE"
echo "pin       : $PIN"
echo "log       : $LOG_PATH"
echo "command   : bpftool -d prog loadall $OBJ_VM_PATH $PIN type $PROG_TYPE"
echo

# Run, capture combined stdout+stderr, also stream to terminal
set +e
"${VM_SSH[@]}" "rm -rf $PIN; bpftool -d prog loadall $OBJ_VM_PATH $PIN type $PROG_TYPE 2>&1; echo \"=== EXIT \$? ===\"; rm -rf $PIN" \
    | tee "$LOG_PATH"
RC=${PIPESTATUS[0]}
set -e

# Outcome: bpftool exits 0 on success, non-zero on failure.
# BCF treats "END PROG LOAD LOG" in the output as a verifier rejection
# (load_prog.py line 126). We surface the same signal.
echo
if grep -q "END PROG LOAD LOG" "$LOG_PATH"; then
    echo "RESULT    : REJECTED by verifier (END PROG LOAD LOG sentinel found)"
elif [[ $RC -eq 0 ]]; then
    echo "RESULT    : LOADED"
else
    echo "RESULT    : FAILED (rc=$RC, no verifier-reject sentinel — likely a compat issue)"
fi
echo "log saved : $LOG_PATH"
