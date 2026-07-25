#!/bin/bash
# alivio memory cop: polls ps and SIGKILLs alivio workers when their
# *cumulative* RSS exceeds a threshold. With --bcf thorough mode each
# bench job spawns several alivio children; capping per-process lets the
# aggregate blow past system RAM while no single worker trips the cap.
# Cumulative tracking is the meaningful budget — kill the largest worker
# until we're back under cap.
#
# Usage:
#   scripts/alivio_memory_cop.sh [CUMULATIVE_CAP_MB] [POLL_SEC]
# Defaults: 32768 MB (32G), 5s poll.
#
# Logs each kill (with cumulative + per-victim RSS) to
# /tmp/alivio_memory_cop.log.

set -u
CAP_MB=${1:-32768}
POLL=${2:-5}
LOG=/tmp/alivio_memory_cop.log

echo "[cop] starting; cumulative cap=${CAP_MB}MB; poll=${POLL}s; log=$LOG" | tee -a "$LOG"

while true; do
  # Snapshot all alivio bench workers: "rss_kb pid obj_path".
  # ps reports RSS in KB. Match `./target/release/alivio ` to scope to
  # the bench binary and avoid other rust processes.
  snap=$(ps -ax -o rss,pid,command \
         | awk '/[\.]\/target\/release\/alivio / {
             obj="?";
             for (i=4;i<=NF;i++) if ($i ~ /\.o$/) { obj=$i; break }
             print $1, $2, obj
           }')

  if [ -z "$snap" ]; then
    sleep "$POLL"
    continue
  fi

  total_kb=$(echo "$snap" | awk '{s+=$1} END {print s+0}')
  total_mb=$((total_kb / 1024))

  if [ "$total_mb" -le "$CAP_MB" ]; then
    sleep "$POLL"
    continue
  fi

  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  nprocs=$(echo "$snap" | wc -l | tr -d ' ')
  echo "[cop] OVER cap: cumulative=${total_mb}MB > ${CAP_MB}MB across ${nprocs} workers  ts=$ts" | tee -a "$LOG"

  # Kill largest-first until cumulative is back under cap. Re-snapshot
  # after each kill so we don't over-shoot when a worker already exited.
  while [ "$total_mb" -gt "$CAP_MB" ]; do
    # largest line by rss_kb
    victim=$(echo "$snap" | sort -rn -k1,1 | head -1)
    [ -z "$victim" ] && break
    v_kb=$(echo "$victim"  | awk '{print $1}')
    v_pid=$(echo "$victim" | awk '{print $2}')
    v_obj=$(echo "$victim" | awk '{print $3}')
    v_mb=$((v_kb / 1024))
    echo "[cop] KILL pid=$v_pid rss=${v_mb}MB obj=$v_obj  (cumulative ${total_mb}MB > ${CAP_MB}MB)" | tee -a "$LOG"
    kill -9 "$v_pid" 2>/dev/null

    # Re-snapshot
    snap=$(ps -ax -o rss,pid,command \
           | awk '/[\.]\/target\/release\/alivio / {
               obj="?";
               for (i=4;i<=NF;i++) if ($i ~ /\.o$/) { obj=$i; break }
               print $1, $2, obj
             }')
    if [ -z "$snap" ]; then
      total_mb=0
      break
    fi
    total_kb=$(echo "$snap" | awk '{s+=$1} END {print s+0}')
    total_mb=$((total_kb / 1024))
  done

  echo "[cop] under cap again: cumulative=${total_mb}MB" | tee -a "$LOG"
  sleep "$POLL"
done
