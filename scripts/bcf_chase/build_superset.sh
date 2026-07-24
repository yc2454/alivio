#!/bin/bash
# Build ONE function's zovia obligation superset under a hard memory watchdog,
# then extract just its cond_hash SET (the big bundle is discarded — only the
# hash set is needed to classify chase misses real vs engine-shape).
#
# Usage: build_superset.sh <obj> <func> <out_hashset.txt> [DEPTH]
# Watchdog: if the zovia RSS exceeds KILL_GB (default 15) OR macOS memory_pressure
# free% drops below MIN_FREE_PCT (default 12), the build is killed (exit 99 = OOM-guard).
# NOTE: macOS "Pages free" is near-zero by design (compression/cache); use
# `memory_pressure` free percentage as the real-availability signal, NOT vm_stat free.
set -u
OBJ="$1"; FUNC="$2"; OUTHASH="$3"; DEPTH="${4:-16}"
KILL_GB="${KILL_GB:-15}"; MIN_FREE_PCT="${MIN_FREE_PCT:-12}"; TIMEOUT="${TIMEOUT:-1800}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
ZOVIA="$ROOT/target/release/zovia"
BUNDLE="${OBJ}.bcf-bundle"

echo "[build] $FUNC depth=$DEPTH  (kill if RSS>${KILL_GB}G or free%<${MIN_FREE_PCT}, timeout ${TIMEOUT}s)"
# fresh bundle (no KEEP) so the superset is THIS function only
rm -f "$BUNDLE"
ZOVIA_EXP_SKIP_LOOP_HEADER_UNSAFE=1 ZOVIA_EXP_LOOP_SUFFIX_BASE=1 ZOVIA_BCF_ANCESTOR_DEPTH="$DEPTH" \
ZOVIA_KERNEL_ENGINE=1 ZOVIA_BCF_FAITHFUL_FOLD=1 ZOVIA_BCF_FOLD_PRENARROW=1 ZOVIA_BCF_REPLAY=1 \
timeout "$TIMEOUT" "$ZOVIA" -q --bcf --kernel-mode verify --func "$FUNC" "$OBJ" >/tmp/bs.out 2>&1 &
PID=$!
killed=0
while kill -0 "$PID" 2>/dev/null; do
  RSS_KB=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' '); RSS_KB=${RSS_KB:-0}
  FREEPCT=$(memory_pressure 2>/dev/null | awk -F: '/free percentage/{gsub(/[ %]/,"",$2);print $2}'); FREEPCT=${FREEPCT:-100}
  if [ "$RSS_KB" -gt $(( KILL_GB*1024*1024 )) ] || [ "$FREEPCT" -lt "$MIN_FREE_PCT" ]; then
    echo "[watchdog] KILL: RSS=$((RSS_KB/1024))M free%=$FREEPCT"; kill -9 "$PID" 2>/dev/null; killed=1; break
  fi
  sleep 5
done
wait "$PID" 2>/dev/null; rc=$?
if [ "$killed" = 1 ]; then echo "[build] OOM-guard tripped for $FUNC"; exit 99; fi
if [ "$rc" = 124 ]; then echo "[build] TIMEOUT for $FUNC"; exit 124; fi
if [ ! -s "$BUNDLE" ]; then echo "[build] no bundle produced (rc=$rc)"; tail -3 /tmp/bs.out; exit 1; fi
python3 "$HERE/bundle_tool.py" hashes "$BUNDLE" | sort -u > "$OUTHASH"
echo "[build] $FUNC superset = $(wc -l <"$OUTHASH") unique hashes, $(du -h "$BUNDLE"|cut -f1) bundle (discarding)"
rm -f "$BUNDLE"
