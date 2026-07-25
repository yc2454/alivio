#!/bin/bash
# Exhaustive BCF reject-chain chase: miss-driven prune loop with clone-fabrication.
#
# The BCF kernel logs `bcf_canonical_hash:` for EVERY discharge query and STOPS at
# the first MISS (load fails EACCES -13). So: load a bundle -> read the one missed
# hash from dmesg -> if it's in alivio's emitted superset, add it (REAL, alivio can
# generate it); else clone-fabricate an entry with that cond_hash (ENGINE-SHAPE gap,
# alivio cannot generate it -- works only because the prototype kernel "trusts the
# hash match", see bcf_bundle.c TODO) -> reload -> kernel advances one reject.
# Loop until the program loads (err=0). Final tally: |WANT| real vs |FAKE| engine-shape.
#
# Config via env (defaults = the accepted_entrypoint run, 2026-06-08):
#   SUP   superset bundle (alivio --bcf --kernel-mode, all 4 passes, depth16 + knobs)
#   HOST  cloudlab host (read from your git remote / memory; do NOT hardcode long-term)
#   VMKEY nested-VM ssh key on the host;  OBJ  .o path INSIDE the VM;  PROG  --prog name
#   WANT  real-hash list (seed with known reals to skip iterations);  FAKE  fabricated list
#   ITERS max iterations;  DIR  scratch dir for probe.bundle
set -u
SUP=${SUP:-/Users/yalucai/BCF/bpf-progs/calico/clang-15_-O1_felix_bin_bpf_from_nat_no_log.o.bcf-bundle}
HOST=${HOST:-yc1795@ms0802.utah.cloudlab.us}
VMKEY=${VMKEY:-/users/yc1795/BCF/imgs/bookworm.id_rsa}
OBJ=${OBJ:-/root/bcf/bpf-progs/calico/clang-15_-O1_felix_bin_bpf_from_nat_no_log.o}
PROG=${PROG:-calico_tc_skb_accepted_entrypoint}
DIR=${DIR:-/tmp}
WANT=${WANT:-$DIR/want.txt}      # in-superset (real) hashes -- alivio CAN generate
FAKE=${FAKE:-$DIR/fake.txt}      # engine-shape hashes -- fabricated, alivio CANNOT generate
ITERS=${ITERS:-40}
HERE="$(cd "$(dirname "$0")" && pwd)"
# Precompute the superset hash set once (used to classify each miss real vs engine-shape).
python3 "$HERE/bundle_tool.py" hashes "$SUP" > "$DIR/sup_hashes.txt"
SSHO="-o ConnectTimeout=20 -o StrictHostKeyChecking=no"
touch "$WANT"; : > "$FAKE"

for iter in $(seq 1 "$ITERS"); do
  python3 "$HERE/bundle_tool.py" pickx "$SUP" "$WANT" "$FAKE" "$DIR/probe.bundle" >"$DIR/pick.log" 2>&1
  scp $SSHO /tmp/probe.bundle "$HOST":/tmp/probe.bundle >/dev/null 2>&1
  scp $SSHO "$DIR/probe.bundle" "$HOST":/tmp/probe.bundle >/dev/null 2>&1
  OUT=$(timeout 150 ssh $SSHO "$HOST" "
    scp -o StrictHostKeyChecking=no -i $VMKEY -P 10023 /tmp/probe.bundle root@localhost:/root/bcf/sweep/probe.bundle >/dev/null 2>&1
    ssh -o StrictHostKeyChecking=no -i $VMKEY -p 10023 root@localhost '
      dmesg -C >/dev/null 2>&1
      /root/bcf/sweep/ll2_loader --prog $PROG $OBJ /root/bcf/sweep/probe.bundle >/tmp/load.out 2>&1
      grep -E \"bpf_object__load err\" /tmp/load.out | tail -1
      grep \"ZK summary. END\" /tmp/load.out | tail -1
      echo ===HASHES===
      dmesg | grep -oE \"hash=0x[0-9a-f]+ off=0\" | sed -E \"s/hash=0x([0-9a-f]+).*/\\1/\"
    '
  " 2>&1)
  SUMMARY=$(echo "$OUT" | grep "ZK summary")
  ERR=$(echo "$OUT" | grep "err=")
  MISS=$(echo "$OUT" | awk '/===HASHES===/{f=1;next} f' | tail -1)
  echo "=== ITER $iter | real=$(wc -l <"$WANT") fake=$(wc -l <"$FAKE") | $ERR"
  echo "    $SUMMARY"
  echo "    miss=$MISS"
  if echo "$OUT" | grep -q "err=0"; then echo ">>> LOAD SUCCEEDED <<<"; break; fi
  if [ -z "$MISS" ]; then echo ">>> no hash (other failure) — stop"; break; fi
  # avoid dup loop
  if grep -qix "$MISS" "$WANT" || grep -qix "$MISS" "$FAKE"; then echo ">>> miss $MISS already added — STUCK, stop"; break; fi
  if grep -q "$MISS" "$DIR/sup_hashes.txt"; then echo "$MISS" >> "$WANT"; echo "    +real";
  else echo "$MISS" >> "$FAKE"; echo "    +FAKE(engine-shape)"; fi
done
echo "=== FINAL: real=$(wc -l <"$WANT") fabricated-engine-shape=$(wc -l <"$FAKE") ==="
echo "--- engine-shape miss hashes ---"; cat "$FAKE"
