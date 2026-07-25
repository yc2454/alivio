# PCC Walkthrough: Two Representative Examples

This document is structured for a quick advisor-facing walkthrough. Each example covers: (1) why Interval rejects while Zone accepts, (2) how the certificate is generated with our new proof language (Fact / Transfer / Derive / Compose), and (3) how the checker replays it fail-closed. Concrete PCs and register relationships are shown to keep things grounded.

## Example 1 — Derived-Register Guard

**Test name:** "pcc: derived-register guard (r3=r2+4, check r3, prove r2, zone ok, interval reject)"

**Program (full disassembly with notes)**
```
0000: stxdw [r10-8], 0           ; spill 0
0001: lddw  r1, map_fd0          ; map ptr into r1
0002: mov   r0, r0               ; nop (placeholder)
0003: mov   r2, r10
0004: add   r2, -8               ; r2 = fp-8 (arg to helper)
0005: call  helper#1 (map_lookup_elem)
0006: if r0 == 0 goto +12        ; null map value? bail to pc18
0007: mov   r6, r0               ; r6 = map_value ptr (packet-like base)
0008: call  helper#7 (get_prandom_u32)
0009: and   r0, 15               ; r0 in [0,15]
0010: mov   r2, r0               ; r2 = var offset
0011: mov   r3, r2
0012: add   r3, 4                ; r3 = r2 + 4
0013: if r3 > 8 goto +5          ; fall-through ⇒ r3 ≤ 8 ⇒ r2 ≤ 4
0014: add   r6, r2               ; base += r2 (needs r2 ≤ 4)
0015: ldb   r0, [r6+0]           ; target load
0016: mov   r0, 0
0017: exit
0018: mov   r0, 0                ; bail path
0019: exit
```

**Why Interval rejects, Zone accepts**
- Interval at pc 15: `r2` comes from `get_prandom_u32 & 0xF`, so `r2 ∈ [0,15]`; interval cannot show `r6+r2` within the map-value bounds → reject.
- Zone DBM:
  - Tracks `r3 = r2 + 4` (pcs 11–12).
  - Branch at pc 13 (fall-through) yields `r3 - Zero <= 8`.
  - Combine: `r2 - Zero <= 4`. With map-value base in r6, access at pc 15 is safe.

**Certificate produced** (mirrors program PCs)
- `Fact` @ pc 13: `r3 - Zero <= 8` (branch fall-through).
- `Derive` pcs 11→12: `r3 = r2 + 4`; switches tracked left to r2, subtracts offset 4.
- `Transfer` @ pc 14: `r6 += r2` (absorb); tracked pair becomes `(r6, Zero)`, adds base offset from interval pre-state.
- Sum: `8 (Fact) - 4 (Derive) + base_offset (Transfer)` = bound `4` for pc 15 load.

**Checker replay (fail-closed)**
1. Fetch interval pre-state at pc 13; confirm branch fall-through matches `r3 - Zero <= 8` → Fact OK.
2. Replay pcs 11–12: mov r3,r2; add r3,4 → alias established; tracked left→r2, bound minus 4.
3. At pc 14, use interval pre-state and instruction `r6 += r2`; verify absorb rule, tracked pair becomes `(r6, Zero)`, add delta.
4. Final tracked pair `(r6, Zero)` and accumulated bound `4` match entry target; injector tightens `r6.var_off` → load passes. Any mismatch drops the cert and the interval rejection stands.

**Try it yourself**
```bash
cargo run -- pcc-cycle pcc-tests/pcc_examples.json "pcc: derived-register guard (r3=r2+4, check r3, prove r2, zone ok, interval reject)"
```

---

## Example 2 — Transitive Compose (Provenance)

**Test name:** "pcc: transitive compose (r5=r4+r2, zone closure via r2, interval reject)"

**Program (abridged disassembly)**
```
0: r2 = pkt_data
1: r3 = pkt_end
2: r4 = r2
3: r4 += r0               ; establishes r4 - r2 <= 3 (via interval/zone)
4: r5 = r4
5: r5 += r2
6: load *(r5 + 0)
```

**Why Interval rejects, Zone accepts**
- Interval at pc 6: `r5 - @end = ∞` → reject.
- Zone DBM (with closure):
  - Edge A: `r5 - r2 <= 3` (from r5 built from r4 and r2).
  - Edge B: `r2 - @end <= -8` (from bounds check earlier on packet end).
  - Closure: `r5 - @end <= 3 + (-8) = -5` → safe.

**Certificate produced** (shows off provenance + Compose)
- Provenance reconstructs path `r5 → r2 → @end` with two primitive edges.
- Sub-proofs (each independently replayable):
  - Left: `Fact` for `r5 - r2 <= 3` (can include zero-delta Transfers if needed).
  - Right: `Fact` for `r2 - @end <= -8` (branch/state-derived).
- `Compose` via `r2`: combines bounds to `-5` and sets tracked pair to `(r5, @end)`.
- Entire proof is a single top-level `Compose` node containing the two sub-proofs.

**Checker replay (fail-closed)**
1. Recursively verify left sub-proof: confirms constraint `r5 - r2 <= 3` and that its right output is `r2`.
2. Recursively verify right sub-proof: confirms `r2 - @end <= -8` and that its left output is `r2`.
3. Compose step: checks via matches, sums `3 + (-8) = -5`, sets tracked pair `(r5, @end)`.
4. If any sub-proof fails or a saved state is missing, the entry is ignored; otherwise injector tightens `r5.var_off` and the load passes.

**Try it yourself**
```bash
cargo run -- pcc-cycle pcc-tests/pcc_examples.json "pcc: transitive compose (r5=r4+r2, zone closure via r2, interval reject)"
```

---

## What These Examples Showcase
- **Relational gap**: Interval alone rejects; Zone provides the missing relations.
- **Proof language coverage**: 
  - Example 1 exercises `Fact + Derive + Transfer` (alias/guard pattern).
  - Example 2 exercises `Compose` from provenance (transitive closure), with minimal Transfers.
- **Fail-closed checking**: Every step is re-verified against the program text and interval pre-states; any mismatch drops the cert and the base interval verdict stands.
- **Provenance use without trust**: Provenance guides path decomposition for Compose; sub-proofs are still fully replayed.
