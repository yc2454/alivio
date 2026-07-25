# A Conceptual Walkthrough of the Motivating PCC Example

This note explains the motivating example as you would present it in a blog post or paper: what goes wrong in a kernel-style verifier, what PCC contributes, and why the result remains sound.

## 1. Problem Setup

eBPF packet programs often perform pointer arithmetic before reading packet bytes.  
A common safe pattern is:

1. start from packet `data`,
2. add a small bounded runtime value (for example, masked by `& 3`),
3. read a fixed-size field from the resulting pointer.

Semantically, this can be safe. But acceptance depends on the abstract domain used by the verifier.

- A **relational** domain (zone/DBM) can keep relationships like `r5 - data_end <= c`.
- A **non-relational** kernel-like interval domain tracks each register mostly independently and may lose this relationship after variable add.

So we get the motivating gap:

- Zone mode: accepts.
- Kernel-style interval mode: rejects (precision loss, not true unsafety).

## 2. Why Kernel-Style Precision Drops

After `r5 = r6; r5 += r4` with `r4` variable, interval analysis widens uncertainty in `r5`.  
Even if `r4` is bounded, the checker may no longer retain a strong enough fact connecting `r5` to `data_end`.

Packet access safety needs an inequality of the form:

- `r5 + access_size - 1 < data_end`, equivalently `r5 - data_end <= -access_size`.

If that relation is forgotten, the load is rejected conservatively.

## 3. PCC Idea in One Sentence

Use an external producer (zone analysis) to compute a fact the kernel-style checker cannot derive cheaply, and attach a short proof that the checker can verify locally and soundly.

## 4. What the Certificate Carries

For this prototype, the certificate is PC-local:

- At successor PC `k`, include annotation entries proving target constraints `i - j <= bound`.
- Each entry has a short proof made of local steps:
  - `GuardStep`: justified by branch condition and edge polarity.
  - `PreStateStep`: justified from predecessor abstract state through one transfer step.

The key target for the motivating load is:

- `r5 - data_end <= -5` (for a 4-byte access with needed margin in this program shape).

## 5. Checker Semantics (Inductive and Local)

On each CFG edge `pred -> succ`, the checker:

1. selects annotations for `succ.pc`,
2. verifies each proof step from:
   - predecessor state,
   - predecessor instruction transfer semantics,
   - inferred guard on that edge (if branch),
3. checks proof-chain consistency and additive bound equality,
4. applies refinement only if verification succeeds.

No global trust is given to the producer. Trust is only in locally checkable semantics.

## 6. Why This Is Sound

Soundness follows from fail-closed local verification:

- If any step is invalid, unsupported, mismatched, or overflowed, the annotation is ignored.
- Ignoring a certificate reverts to baseline verifier behavior.
- Therefore certificates can improve precision, but cannot create unsound acceptance.

This is exactly what negative tests validate: tampered edge, tampered bound, or tampered proof step must not pass.

## 7. Conceptual Interpretation

Think of PCC here as a **proof-carrying precision patch**, not a bypass:

- Baseline kernel logic remains the authority.
- Certificate contributes only extra facts that are independently re-proved at use time.
- The checker does not “believe” claims; it re-derives them from local semantics.

## 8. What This Demonstrates (and What It Does Not)

### Demonstrated

- A real precision gap (zone accepts, kernel-style rejects) can be closed by compact, checkable proof hints.
- The architecture supports strict fail-closed behavior.

### Not yet demonstrated

- Broad coverage over arbitrary eBPF instruction shapes.
- Full general relational fact injection beyond current narrow consumers.
- Kernel in-tree integration and serialization constraints.

## 9. Why This Example Matters

This example is minimal but representative: it captures a core verifier tension between scalability and precision.  
PCC provides a path to keep the fast, conservative kernel abstraction while selectively importing richer reasoning only when accompanied by checkable evidence.

In short: **cheap default verification, precise when proven**.
