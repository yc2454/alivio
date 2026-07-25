#!/bin/bash
# LEGACY anchor bundle builder.
# ⚠️ Superseded by calico_anchor_unified_bundle.sh, which relies on
# alivio's internal thorough mode (default on with --bcf) instead of
# driving the per-pass loop from this script.
#
# Builds a kernel-loadable BCF bundle for the calico anchor object
# (clang-15_-O1_felix_bin_bpf_to_tnl_debug_v6.o, 7 programs).
#
# Iterates over all 7 programs, running alivio in three modes and
# accumulating bundle entries via ALIVIO_BUNDLE_KEEP=1:
#   1. flag-OFF (default alivio behavior — dense caching)
#   2. flag-ON AND mode (sparser caching → more exploration → more entries)
#   3. flag-ON OR  mode (default flag-ON behavior)
#
# Each program contributes its rejection-discharge entries to the
# shared bundle file. Entries dedup by hash via write_bundle.
#
# Verified 2026-05-21 at HEAD a44b922: whole-object kernel load
# returns "SUCCESS: loaded 7/7 program(s)" on the cloudlab VM
# (kernel 6.18.0-rc4-g47b3934f7ad8 with BCF patches).
#
# Usage:
#   ANCHOR=/path/to/anchor.o ALIVIO=./target/release/alivio ./calico_anchor_unified_bundle.sh

set -u
ALIVIO=${ALIVIO:-./target/release/alivio}
ANCHOR=${ANCHOR:-/tmp/anchor_to_tnl_debug.o}
BUNDLE=$ANCHOR.bcf-bundle

PROGS=(
  calico_tc_main
  calico_tc_skb_accepted_entrypoint
  calico_tc_skb_new_flow_entrypoint
  calico_tc_skb_icmp_inner_nat
  calico_tc_skb_send_icmp_replies
  calico_tc_host_ct_conflict
  calico_tc_skb_drop
)

rm -f "$BUNDLE"
echo "=== three-mode unified bundle build for $ANCHOR ==="
for prog in "${PROGS[@]}"; do
  echo ""
  echo "### $prog ###"
  echo "  flag-OFF:"
  ALIVIO_BUNDLE_KEEP=1 \
    "$ALIVIO" --bcf --kernel-mode verify "$ANCHOR" --func "$prog" 2>&1 \
    | grep -E 'Verified|bundle:|FAILURE|TIMEOUT|Aborting' | tail -2 | sed 's/^/    /'
  echo "  flag-ON AND:"
  ALIVIO_KERNEL_ENGINE=1 ALIVIO_KERNEL_ENGINE_AND=1 ALIVIO_BUNDLE_KEEP=1 \
    "$ALIVIO" --bcf --kernel-mode verify "$ANCHOR" --func "$prog" 2>&1 \
    | grep -E 'Verified|bundle:|FAILURE|TIMEOUT|Aborting' | tail -2 | sed 's/^/    /'
  echo "  flag-ON OR :"
  ALIVIO_KERNEL_ENGINE=1 ALIVIO_BUNDLE_KEEP=1 \
    "$ALIVIO" --bcf --kernel-mode verify "$ANCHOR" --func "$prog" 2>&1 \
    | grep -E 'Verified|bundle:|FAILURE|TIMEOUT|Aborting' | tail -2 | sed 's/^/    /'
done
echo ""
echo "=== final unified bundle ==="
ls -la "$BUNDLE"
