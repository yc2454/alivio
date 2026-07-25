#!/bin/bash
# Fully-on-box BCF gate: parallel bundle build (40 cores) + parallel VM-load.
# Build and load both happen ON THE BOX (VM is local, port 10023).
#
# Usage: box_gate2.sh <listfile>
#   listfile lines:  <srcdir> <name> <type>   (whitespace-separated)
#   - srcdir : dir holding <name>.o  (e.g. ~/BCF-git/bpf-progs/calico)
#   - name   : object basename without .o
#   - type   : test_loader --type keyword (e.g. classifier)
#
# Env knobs: JOBS (build parallelism, def 38), VMJOBS (load parallelism, def 6),
#            BTO (build timeout s, def 900), LTO (per-load timeout s, def 1200)
set -u
# Repo root derived from this script's location, so the checkout
# directory can be named anything.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH=$HOME/.cargo/bin:$PATH
export ALIVIO_CVC5=${ALIVIO_CVC5:-/users/yc1795/BCF/output/cvc5-libs/bin/cvc5}
export Z=$REPO_ROOT/target/release/alivio
export SP=$HOME/BCF/sweep_pivot
export VMKEY=$HOME/BCF/imgs/bookworm.id_rsa
export BTO=${BTO:-900}
export LTO=${LTO:-1200}
JOBS=${JOBS:-38}
VMJOBS=${VMJOBS:-6}
LIST="$1"
RES=${RES:-/tmp/gate2_result.txt}
BLOG=${BLOG:-/tmp/gate2_build.log}
LLOG=${LLOG:-/tmp/gate2_load.log}
: > "$RES"; : > "$BLOG"; : > "$LLOG"
mkdir -p "$SP"
# CRITICAL: clear sweep_pivot so no STALE bundle from a previous run is
# loaded. Without this, an object whose build produced no fresh bundle
# (timeout, sz=0) would load against a day-old bundle → false LOAD.
rm -f "$SP"/*.o "$SP"/*.o.bcf-bundle 2>/dev/null
export BLOG

# strip CR, drop blanks/comments
clean_list=$(mktemp)
sed 's/\r//g' "$LIST" | grep -vE '^\s*(#|$)' > "$clean_list"
N=$(wc -l < "$clean_list")
echo "[$(date +%H:%M:%S)] GATE2: $N objects | build JOBS=$JOBS BTO=${BTO}s | load VMJOBS=$VMJOBS LTO=${LTO}s" | tee -a "$RES"

# ---- Phase 1: parallel build, keep partial bundles, stage to sweep_pivot ----
build1() {
  local dir="$1" name="$2"
  local obj="$dir/$name.o"
  if [ ! -f "$obj" ]; then echo "BUILD $name MISS_OBJ" >> "$BLOG"; return; fi
  rm -f "$obj.bcf-bundle"
  local t0 t1 rc sz
  t0=$(date +%s)
  timeout "$BTO" "$Z" -q --kernel-mode verify --bcf "$obj" >/dev/null 2>&1
  rc=$?; t1=$(date +%s)
  sz=0; [ -f "$obj.bcf-bundle" ] && sz=$(stat -c%s "$obj.bcf-bundle")
  echo "BUILD $name rc=$rc $((t1-t0))s sz=$sz" >> "$BLOG"
  # Partial-bundle policy (bench_e2e): ship any bundle that exists, even on timeout.
  if [ "$sz" -gt 0 ]; then cp -f "$obj" "$obj.bcf-bundle" "$SP/" 2>/dev/null; fi
}
export -f build1

echo "[$(date +%H:%M:%S)] phase 1: building..." | tee -a "$RES"
awk '{print $1, $2}' "$clean_list" | \
  xargs -P "$JOBS" -L1 bash -c 'build1 "$1" "$2"' _
echo "[$(date +%H:%M:%S)] phase 1 done. build log:" | tee -a "$RES"
sort "$BLOG" | tee -a "$RES"
NB=$(grep -c 'sz=0$' "$BLOG"); echo "  (build-timeout, no bundle: $NB)" | tee -a "$RES"

# ---- Phase 2: parallel VM-load (ssh -n so stdin is NOT consumed) ----
export LLOG LTO
load1() {
  local name="$1" type="$2"
  local o="/root/bcf/sweep_pivot/$name.o"
  local b="/root/bcf/sweep_pivot/$name.o.bcf-bundle"
  # No staged bundle = the build hit BTO before writing one (sz=0). This is a
  # build-time TIMEOUT, NOT a verification/load failure — keep them distinct.
  if [ ! -f "$SP/$name.o.bcf-bundle" ]; then echo "$name BUILD-TIMEOUT" >> "$LLOG"; return; fi
  local out
  out=$(ssh -n -o ConnectTimeout=8 -o StrictHostKeyChecking=no -i "$VMKEY" -p 10023 root@localhost \
    "timeout $LTO /root/bcf/build/test_loader --type $type $o $b 2>&1 | grep -cE 'SUCCESS: loaded'")
  if [ "$out" = "1" ]; then echo "$name LOAD" >> "$LLOG"; else echo "$name FAIL" >> "$LLOG"; fi
}
export -f load1
export VMKEY SP

echo "[$(date +%H:%M:%S)] phase 2: VM-loading (P=$VMJOBS)..." | tee -a "$RES"
awk '{print $2, $3}' "$clean_list" | \
  xargs -P "$VMJOBS" -L1 bash -c 'load1 "$1" "$2"' _
echo "[$(date +%H:%M:%S)] phase 2 done. load results:" | tee -a "$RES"
sort "$LLOG" | tee -a "$RES"

LOADN=$(grep -c ' LOAD$' "$LLOG")
echo "=== GATE2 RESULT: $LOADN / $N LOAD ===" | tee -a "$RES"
rm -f "$clean_list"
