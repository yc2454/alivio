#!/bin/bash
# Q2 batch: for every object in a list —
#   1. build the FULL thorough bundle (current default config) fresh
#   2. capture the kernel's queried-hash set (whole-object load; doubles as a
#      per-object load validation of the current default config)
#   3. build the 4 per-pass isolated bundles + hash sets (pass_surgery.sh)
# Then mincover.py answers: smallest pass config covering every queried set.
#
# Serial (jobs 1) on purpose — no_log builds OOM under parallelism.
# Usage: q2_batch.sh <list_file> <outdir> [timeout_s=1800]
set -u
LIST="$1"; OUTDIR="$2"; TMO="${3:-1800}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ALIVIO="$ROOT/target/release/alivio"
mkdir -p "$OUTDIR"
PASSED=(); FAILED=()

# for-loop, NOT `while read < $LIST`: ssh inside the body slurps stdin and
# silently consumes the rest of the list (burned 2026-06-09: batch processed
# exactly 1 of 19 objects). Paths contain no spaces.
for OBJ in $(grep -v '^$' "$LIST"); do
  BASE="$(basename "$OBJ" .o)"
  echo "===== $BASE ====="
  # Resume: skip objects fully processed in a prior run (queried set + all 4
  # per-pass hash files present and non-empty).
  if [ -s "$OUTDIR/$BASE.queried.hashes" ] && [ -s "$OUTDIR/$BASE.pass_baseline.hashes" ] \
     && [ -s "$OUTDIR/$BASE.pass_a.hashes" ] && [ -s "$OUTDIR/$BASE.pass_b.hashes" ] \
     && [ -s "$OUTDIR/$BASE.pass_c.hashes" ]; then
    echo "  (resume: already complete, skipping)"
    if grep -q "SUCCESS" "$OUTDIR/$BASE.capture.err" 2>/dev/null; then PASSED+=("$BASE"); else FAILED+=("$BASE(load)"); fi
    continue
  fi
  # 1. per-pass surgery (4 isolated single-pass builds; saves bundles+hashes)
  bash "$HERE/pass_surgery.sh" "$OBJ" "$OUTDIR" "$TMO" < /dev/null
  # 2. full-config bundle = MERGE of the 4 singles (identical hash set to a
  #    thorough build — thorough is the same 4 passes merged+deduped — so the
  #    redundant 4-pass thorough build is skipped entirely).
  python3 "$HERE/bundle_tool.py" mergeall "$OBJ.bcf-bundle" \
    "$OUTDIR/$BASE".pass_*.bundle 2>/dev/null
  if [ ! -s "$OBJ.bcf-bundle" ]; then
    echo "  MERGE FAILED (no per-pass bundles?) — skip"; FAILED+=("$BASE(build)"); continue
  fi
  python3 "$HERE/bundle_tool.py" hashes "$OBJ.bcf-bundle" \
    | awk '{printf "%016s\n",$0}' | sort -u > "$OUTDIR/$BASE.full.hashes"
  # 3. queried set (whole-object load via test_loader; also validates load)
  bash "$HERE/capture_queried.sh" "$OBJ" "$OUTDIR/$BASE.queried.hashes" \
    < /dev/null 2> "$OUTDIR/$BASE.capture.err"
  # test_loader success line: "SUCCESS: loaded N/M program(s)" (whole-object).
  if grep -q "SUCCESS" "$OUTDIR/$BASE.capture.err"; then
    PASSED+=("$BASE")
  else
    FAILED+=("$BASE(load:$(grep -oE 'err=-?[0-9]+|FAILED[^ ]*' "$OUTDIR/$BASE.capture.err" | tail -1))")
  fi
  rm -f "$OBJ.bcf-bundle" "$OUTDIR/$BASE".pass_*.bundle
done

echo
echo "=== LOAD VALIDATION (default config, fresh bundles) ==="
echo "PASS (${#PASSED[@]}): ${PASSED[*]:-}"
echo "FAIL (${#FAILED[@]}): ${FAILED[*]:-}"
echo
echo "=== MIN-COVER ==="
OBJS=$(sed 's#.*/##; s#\.o$##' "$LIST" | tr '\n' ' ')
python3 "$HERE/mincover.py" "$OUTDIR" $OBJS
