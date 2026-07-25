#!/bin/bash
# Per-pass bundle surgery: build ONE object's bundle under each thorough pass
# IN ISOLATION and save the per-pass cond_hash sets (zero-padded 16-hex).
#
# Mirrors main.rs thorough-mode children exactly: each pass clears ALL toggle
# keys, sets only its own, and runs with the
# ALIVIO_BCF_THOROUGH_PASS=1 marker (reg-filter discharge keys on it — without
# the marker the "baseline" single-pass is NOT the thorough baseline child).
#
# Usage: pass_surgery.sh <obj> <outdir> [timeout_s=1800]
# Output: <outdir>/<objbase>.pass_{baseline,a,b,c}.hashes  (+ .log per pass)
set -u
OBJ="$1"; OUTDIR="$2"; TMO="${3:-1800}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ALIVIO="$ROOT/target/release/alivio"
BASE="$(basename "$OBJ" .o)"
mkdir -p "$OUTDIR"

run_pass() {
  local name="$1"; shift
  local envs=("$@")
  rm -f "$OBJ.bcf-bundle"
  # env -i would lose PATH etc; instead explicitly unset all toggle keys, then
  # set the pass's own. Env vars are set INLINE on the command (never $ENV).
  (
    unset ALIVIO_KERNEL_ENGINE ALIVIO_KERNEL_ENGINE_AND ALIVIO_BCF_FAITHFUL_FOLD \
          ALIVIO_BCF_FOLD_PRENARROW ALIVIO_BCF_REPLAY ALIVIO_BCF_ANCESTOR_DEPTH \
          ALIVIO_EXP_FLAG_SKIP_BASE ALIVIO_EXP_LOOP_ENTRY_BASE \
          ALIVIO_EXP_SKIP_LOOP_HEADER_UNSAFE ALIVIO_EXP_LOOP_SUFFIX_BASE
    export ALIVIO_BCF_THOROUGH_PASS=1
    # ${envs[@]+...} guards the empty-array expansion (baseline pass) against
    # set -u on bash 3.2 (macOS /bin/bash), which errors on "${envs[@]}".
    for kv in ${envs[@]+"${envs[@]}"}; do export "$kv"; done
    timeout "$TMO" "$ALIVIO" -q --bcf --kernel-mode verify "$OBJ" \
      > "$OUTDIR/$BASE.pass_$name.log" 2>&1
    echo "rc=$?" >> "$OUTDIR/$BASE.pass_$name.log"
  )
  if [ -s "$OBJ.bcf-bundle" ]; then
    python3 "$HERE/bundle_tool.py" hashes "$OBJ.bcf-bundle" \
      | awk '{printf "%016s\n",$0}' | sort -u > "$OUTDIR/$BASE.pass_$name.hashes"
    echo "[$name] $(wc -l < "$OUTDIR/$BASE.pass_$name.hashes" | tr -d ' ') hashes, $(ls -la "$OBJ.bcf-bundle" | awk '{print $5}') bytes"
    # Keep the per-pass bundle: the caller merges the 4 singles into the
    # full-config bundle (identical hash set to a thorough build — passes are
    # merged+deduped by cond_hash there too), saving a redundant 4-pass build.
    mv "$OBJ.bcf-bundle" "$OUTDIR/$BASE.pass_$name.bundle"
  else
    : > "$OUTDIR/$BASE.pass_$name.hashes"
    echo "[$name] NO BUNDLE (rc=$(tail -1 "$OUTDIR/$BASE.pass_$name.log"))"
  fi
}

# Pass definitions == main.rs `variations` (keep in sync).
run_pass baseline
run_pass a ALIVIO_KERNEL_ENGINE=1 ALIVIO_KERNEL_ENGINE_AND=1
run_pass b ALIVIO_KERNEL_ENGINE=1
run_pass c ALIVIO_KERNEL_ENGINE=1 ALIVIO_BCF_FAITHFUL_FOLD=1 \
           ALIVIO_BCF_FOLD_PRENARROW=1 ALIVIO_BCF_REPLAY=1 ALIVIO_BCF_ANCESTOR_DEPTH=16
rm -f "$OBJ.bcf-bundle"   # leave no partial sidecar for --cache-bundles to pick up
