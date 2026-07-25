# PCC Checker Algorithm

## The Running Invariant

The checker maintains one piece of state throughout replay:

> `current_left − current_right ≤ accumulated_bound`

This invariant is **established** by the first step (a Fact) and **transformed** by every subsequent step. At the end of the chain, it must exactly match the certificate's target claim. The checker is **fail-closed**: if any step cannot be verified (missing/ambiguous state, mismatch, overflow, unsupported op), the chain is silently discarded.

Prerequisites / caps:
- Exactly one stored interval state for every PC a step references; join-points with multiple states are rejected.
- Step/entry caps enforced: `MAX_STEPS_PER_ENTRY` (32) and overflow-checked bound arithmetic.

---

## Proof Step Types

### Fact
*Establishes the running invariant from scratch.*

- Claims `left − right ≤ c` at a named PC.
- Two verification paths, tried in order:
  - **Branch-derived** — if the instruction at that PC is a branch, decode the fall-through constraint directly from the opcode. No abstract state needed.
  - **State-derived** — query the stored interval abstract state at that PC; check its upper bound on `left − right` is ≤ c. Requires exactly one stored state (join points are rejected).

> **Example:** instruction `if r2 >u 4 → exit` at pc 7.
> Fall-through gives `r2 ≤ 4`, i.e. `r2 − 0 ≤ 4`.
> Invariant after: **r2 − 0 ≤ 4**.

---

### Derive
*Rewrites `current_left` by looking through a register alias.*

- Claims that a sequence of instructions establishes `source = target + offset`.
- Given the current invariant `source − right ≤ b`, substituting gives `target − right ≤ b − offset`.
- Verification: replay the instruction range looking for `mov source, target` (the link, offset = 0) followed by `add source, imm` (each shifts the offset). Any write to either register after the link rejects the step.

> **Example:** pc 11: `r3 = r2`, pc 12: `r3 += 4` establishes `r3 = r2 + 4`.
> Current invariant `r3 − 0 ≤ 10` becomes **r2 − 0 ≤ 6**.

---

### Transfer
*Advances the invariant across one instruction.*

- Claims: `pre_left − pre_right ≤ b` before the instruction → `post_left − post_right ≤ b + delta` after.
- First checks **chain connectivity**: the declared pre-constraint must match the current invariant exactly.
- Then checks whether `delta` is a sound consequence of the instruction. Key cases (with “why”):

| Instruction | Condition | Invariant update |
|---|---|---|
| `add dst, imm` | `dst == pre_left` | bound += imm (lhs increased by imm) |
| `add dst, imm` | `dst == pre_right` | bound −= imm (rhs increased by imm) |
| `add dst, src` | `dst == pre_left` | bound += ub(src) from state (lhs can grow by at most ub(src)) |
| `add dst, src` | `dst == pre_right` | bound −= lb(src) from state (rhs can shrink by at most −lb(src)) |
| `add dst, src` | `src == pre_left`, dst fresh | **absorb**: see below |
| `add dst, src` | `dst == pre_left`, `pre_right == 0` | **pivot**: tracked pair becomes `(pre_left, src)`; bound unchanged (lhs copied to rhs register) |
| `mov dst, src` | src is tracked | tracked left/right follow the copy into dst; bound unchanged |
| passthrough | dst not tracked | invariant unchanged |
| unsupported write | dst is tracked | **rejected** |

> **Example:** `add r2, 3` at pc 9, current invariant `r2 − 0 ≤ 5`.
> dst == pre_left, delta = 3. Invariant after: **r2 − 0 ≤ 8**.

---

### Compose
*Joins two sub-proofs through an intermediate register.*

- Left sub-proof proves `L − K ≤ a`; right sub-proof proves `K − R ≤ b`.
- Triangle inequality gives `L − R ≤ a + b`.
- Verification: replay each sub-proof recursively; check they share register K at their junction.

> **Example:** left proves `r5 − r2 ≤ 3`, right proves `r2 − 0 ≤ 5`, via r2.
> Composed invariant: **r5 − 0 ≤ 8**.

---

## Worked Example

The program performs a variable-offset map access (map value size = 8 bytes). Safety condition: `offset + size <= 8`, i.e., `r6 - 0 <= 7`. Zone proves a tighter bound `<= 4`, which is sufficient:

```
pc 09: r0 = r0 & 15              ; r0 ∈ [0, 15]
pc 10: r2 = r0                   ; r2 ∈ [0, 15]
pc 11: r3 = r2
pc 12: r3 = r3 + 4               ; r3 = r2 + 4, so r3 ∈ [4, 19]
pc 13: if r3 > 8  →  exit        ; fall-through: r3 ∈ [4, 8], r2 ∈ [0, 4]
pc 14: r6 = r6 + r2              ; r6 advances into the map buffer
pc 15: r0 = *(u8 *)(r6 + 0)     ; LOAD ← must prove r6 offset + 1 ≤ 8
```

The interval analysis fails at pc 15: r6's variable offset is `[0, 15]`, making the access range `[0, 16]`, which exceeds 8. The zone analysis proves safety via the relational fact `r3 = r2 + 4`, and issues the certificate:

```
Claim:  r6 − 0 ≤ 4  at pc 15

[0] Fact     @ pc 13:  r3 − 0 ≤ 8
[1] Derive   @ pc 11→12:  r3 = r2 + 4   ⟹  r2 ≤ 4
[2] Transfer @ pc 14:  r6 += r2  [absorb: r6 was at offset 0]  ⟹  r6 ≤ 4
```

---

### Step 0 — Fact

- Instruction at pc 13: `if r3 >u 8 → exit`
- Fall-through gives `r3 − 0 ≤ 8` — matches the claim exactly. ✓

| current\_left | current\_right | accumulated\_bound |
|:---:|:---:|:---:|
| r3 | 0 | **8** |

---

### Step 1 — Derive

- pc 11: `r3 = r2` — link established, offset = 0
- pc 12: `r3 += 4` — offset becomes 4
- No overwrites of r3 or r2 in range. Computed offset 4 = claimed 4. ✓
- Invariant `r3 − 0 ≤ 8` becomes `r2 − 0 ≤ 8 − 4`:

| current\_left | current\_right | accumulated\_bound |
|:---:|:---:|:---:|
| r2 | 0 | **4** |

---

### Step 2 — Transfer

- Instruction at pc 14: `r6 = r6 + r2`
- Declared pre-constraint `(pre_left, pre_right) = (r2, 0)` matches current invariant. ✓
- Why “absorb”? The new `r6` is `r6_old + r2`; we want a bound on *that* value. So:
  - Switch tracked left from `r2` to `r6` (r6 now contains the tracked value).
  - Keep tracked right as 0.
  - Add delta = upper bound of `r6_old - 0` before the add. Interval state: `r6_old` offset = 0 ⇒ delta = 0. ✓
- Updated invariant (tracked pair and bound):

| current\_left | current\_right | accumulated\_bound |
|:---:|:---:|:---:|
| r6 | 0 | **4** |

---

### Final Check and Injection

- Chain endpoint `(r6, 0, 4)` matches the target claim. Proof accepted.
- r6's variable offset is tightened from `[0, 15]` to `[0, 4]`.
- Access range at pc 15: `[0, 4] + 0 + 1 = [1, 5]` ≤ 8. ✓
