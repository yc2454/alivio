# A motivating example: one pass vs. one round-trip per proof

This note uses a single small program, `stack_ptr_varoff.bpf.o` (program
`shift_constraint`), to show the central advantage of our single-pass design over
a round-trip proof-carrying scheme: **the number of kernel↔userspace round-trips a
round-trip design pays is proportional to the number of proof obligations, while our
generator discharges all of them in one offline pass.**

## The program

`shift_constraint` is 15 instructions. It computes a *variable* index into a 16-byte
stack buffer and reads from it on two mutually-exclusive branches:

```
pc0   R0 = prandom_u32()           ; helper 7
pc1   R0 &= 15                      ; R0 ∈ [0,15]  — a variable index
pc2   R1 = R10                      ; stack frame pointer
pc3   R1 += -16                     ; R1 = base of a 16-byte stack buffer
pc4   R1 += R0                      ; R1 = base + R0   → VARIABLE-OFFSET stack pointer
pc5   R2 = 15
pc6   R2 -= R0                      ; R2 = 15 - R0  ∈ [0,15]
pc7   if R2 < 4 goto pc11
      ; ---- fall-through (R2 ≥ 4, i.e. R0 ≤ 11) ----
pc8   R1 += 4                       ; R1 = base + R0 + 4
pc9   R0 = *(u8 *)(R1 + 0)          ; READ #1  ← variable-offset stack read
pc10  exit
      ; ---- branch taken (R2 < 4, i.e. R0 ≥ 12) ----
pc11  R1 += R2                      ; R1 = base + R0 + (15 - R0) = base + 15
pc12  R0 = *(u8 *)(R1 + 0)          ; READ #2  ← variable-offset stack read
pc13  R0 = 0
pc14  exit
```

Both reads are in-bounds, but only because of an arithmetic relationship the base
verifier will not accept on its own:

- **READ #1** (pc 9): on this branch `R0 ≤ 11`, so `R1 = base + R0 + 4 ∈ [base+4, base+15]` — inside the buffer.
- **READ #2** (pc 12): here `R1 = base + R0 + (15 − R0) = base + 15` — exactly the last byte. The offset is constant *only* after cancelling `R0`, which the verifier's interval/tnum tracking does not do.

So the kernel verifier rejects a variable-offset stack access at **each** read. Each
rejection requires its **own** proof that the access is in bounds. **This program needs
two proofs** — one per read, on two disjoint paths.

We can see exactly this: our generator emits a bundle with two entries, one per read site:

```
[bcf] refined stack-OOB at base=R1 off=0 size=1: cvc5 proof 26424 bytes (hash 2d4fb4d47b0709d3)
[bcf] refined stack-OOB at base=R1 off=0 size=1: cvc5 proof 39756 bytes (hash 2b87b5f32b727652)
→ bundle: 2 entries, 66616 bytes
```

## Why a round-trip design pays two round-trips

The kernel verifier is **fail-fast**: it stops at the first access it cannot prove
safe. A proof-carrying scheme that discovers obligations by *asking the kernel*
therefore learns them one at a time:

1. The kernel verifies, reaches READ #1, cannot discharge it, and **suspends** — it has
   not yet even explored the branch containing READ #2.
2. Userspace proves obligation #1 and hands the proof back.
3. The kernel resumes, discharges READ #1, continues, reaches READ #2, and **suspends again**.
4. Userspace proves obligation #2 and hands it back.
5. The kernel resumes and the program loads.

Two obligations ⇒ **two kernel↔userspace round-trips**. In general an *N*-obligation
program costs *N* round-trips, because a later obligation is only revealed once the
earlier one is discharged. Every round-trip re-enters the kernel verifier and crosses
the privilege boundary.

## Why our single-pass design pays zero round-trips

Our generator is a userspace abstract-interpretation verifier that mirrors the kernel
but, unlike the kernel, **does not fail-fast** — at a would-be-reject it discharges the
obligation with an SMT solver and *keeps exploring*. In one pass it walks **both**
branches, hits **both** reads, and discharges **both**:

- It reaches READ #1, proves it in-bounds, records obligation #1, and continues.
- It explores the other branch, reaches READ #2, proves it, records obligation #2.
- It writes a **two-entry bundle** keyed by the canonical hashes the kernel will recompute.

The kernel then loads the program in a **single** verification pass: at each read it
recomputes the canonical hash, finds the matching proof already in the bundle, re-checks
it, and proceeds. No suspend, no resume, no second pass.

Measured, on the BCF kernel:

```
load WITHOUT bundle :  -EINVAL   (verifier rejects at the first variable-offset read)
load WITH bundle    :  SUCCESS: loaded 1/1 program(s)
```

## The takeaway

| | Round-trip scheme | Our single-pass design |
|---|---|---|
| Obligation discovery | one at a time (kernel fail-fast) | all at once (explore past rejects) |
| Kernel↔userspace round-trips | one per obligation (here: 2) | zero |
| Kernel verification passes to load | one per obligation + final | one |
| Where the cost lives | repeated, online, in the kernel path | once, offline, in untrusted userspace |

The proof *checking* is identical and stays in the kernel in both designs — soundness is
unchanged. What single-pass buys is **decoupling proof discovery from the kernel's
fail-fast traversal**: we pay one offline analysis to find every obligation up front, so
the kernel verifies the program exactly once, with every proof already in hand.
