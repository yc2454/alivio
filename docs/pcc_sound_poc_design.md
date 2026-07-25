# PCC for eBPF Verifier (Sound-First POC Design)

Status: Draft v1  
Audience: Human engineers and AI coding agents  
Codebase: `/Users/yalucai/eBPF-Zone-Verifier`

## 1. Purpose

This document defines a **sound-first** Proof-Carrying Code (PCC) prototype for the eBPF verifier in this repository.

The prototype goal is narrow and concrete:

- Produce proof annotations from **Zone mode** (userspace only).
- Check those annotations in **Kernel/Interval mode**.
- Recover a specific precision gap (safe packet access after variable pointer arithmetic).
- Fail closed on any mismatch or unsupported case.

Performance is explicitly not a v1 objective.

## 2. Problem Statement

In interval mode, `dst += src` with non-constant `src` can invalidate `PtrOffset.range` (`range = None`), causing later packet access checks to fail despite being safe.

Relevant current behavior:

- Interval variable-add invalidates pointer range in [`src/domains/interval/ops.rs`](/Users/yalucai/eBPF-Zone-Verifier/src/domains/interval/ops.rs).
- Zone mode can still prove safety via relational constraints and closure in [`src/domains/zone/dbm.rs`](/Users/yalucai/eBPF-Zone-Verifier/src/domains/zone/dbm.rs).
- Packet access check consumes interval pointer range in [`src/domains/interval/ops.rs`](/Users/yalucai/eBPF-Zone-Verifier/src/domains/interval/ops.rs).

We want interval mode to accept such safe programs, but only when supplied with a verifiable certificate from zone analysis.

## 3. Scope and Non-Goals

## In Scope (v1)

- Userspace verifier only.
- Single-program selftest flow.
- Certificate generation from zone run.
- Certificate checking during interval run.
- Certified fact family limited to packet-end relation:
  - `base - AnchorDataEnd <= c`
- CFG restrictions for v1 certification:
  - no loops,
  - no back-edge reasoning,
  - forward branches only.

## Non-Goals (v1)

- Linux kernel integration.
- Generic relational fact injection into interval domain.
- Cross-function / interprocedural certificate support.
- Certificate compression and optimization.
- Loop certificates / fixpoint certificates.

## 4. Soundness Model

### 4.1 Threat Model

Assume annotation file may be malformed or adversarial.

The checker must never trust producer output without local validation.

### 4.2 Core Soundness Principles

1. **Fail closed**: any parse error, mismatch, overflow, unsupported op, or missing dependency means "do not apply certificate".
2. **Edge-local checking**: verify facts on specific CFG edge transition `(pred_pc -> succ_pc)` where guard semantics are unambiguous.
3. **State-identity binding**: certificate references predecessor state by fingerprint; no ambiguous "any state at PC" lookup.
4. **No circular reasoning**: each proof obligation is self-contained and acyclic.
5. **Narrow injection**: only convert verified packet-end facts into interval pointer-range refinement.

## 5. High-Level Architecture

Two runs with shared program:

1. **Producer run (Zone mode)**
- Analyze program in zone domain.
- Build edge-local proof obligations for selected facts.
- Emit annotation file.

2. **Checker run (Kernel/Interval mode)**
- Execute normal interval analysis.
- At successor creation, verify matching obligation for that edge and predecessor state fingerprint.
- On successful verification, refine interval pointer range.

If no valid obligation is found, continue without refinement.

## 6. Certificate Data Model (v1)

Create module: `src/pcc/mod.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramCertificate {
    pub version: u32,                  // must be 1 in v1
    pub program_hash: String,          // hash of instruction stream / canonical encoding
    pub obligations: Vec<EdgeObligation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeObligation {
    pub pred_pc: usize,
    pub succ_pc: usize,
    pub pred_fingerprint: u64,         // stable hash of predecessor abstract state snapshot

    pub target: Constraint,
    pub proof: Vec<ProofStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub i: usize,                      // Reg idx
    pub j: usize,                      // Reg idx
    pub c: i64,                        // i - j <= c
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofStep {
    // Constraint directly implied by branch condition and edge polarity.
    GuardStep { i: usize, j: usize, c: i64 },

    // Constraint from predecessor pre-transfer zone snapshot.
    PreStateStep { i: usize, j: usize, c: i64 },
}
```

### 6.1 Why this shape

- `pred_pc/succ_pc` binds to exact edge.
- `pred_fingerprint` disambiguates multi-state-per-PC behavior.
- No recursive references to other obligations (avoids cycle risk in v1).

## 7. State Fingerprint Definition

Add a deterministic, stable fingerprint function over predecessor abstract state in both producer and checker.

Minimum input fields:

- `pc`
- register types (`state.types`)
- numeric abstract state
  - for zone producer/checker pre-state: full DBM matrix values (`INF` normalized)
  - for interval checker when matching cert: use derived fingerprint payload agreed by spec (see below)

### 7.1 Practical v1 decision

Because producer is zone and checker is interval, fingerprints must be comparable. Use a **structural pre-transfer view** that both sides can build:

- `pc`
- register types
- tnum per register
- pointer-offset tuple per register where present: `(anchor, off, var_off, range?)`
- scalar bounds per register `(smin, smax, umin, umax)`

This is weaker than DBM identity but shared across modes. Soundness is still preserved because proof steps are independently validated from local semantics; fingerprint is only for selecting the intended obligation.

If fingerprint mismatches, obligation is ignored.

## 8. Proof Semantics

For each `EdgeObligation`:

- `target` means at successor entry we claim `reg_i - reg_j <= c`.
- `proof` is a chain-free bag in v1 with additive validation:
  - every step must be locally valid at predecessor edge context,
  - checker computes `sum(step.c)` using checked addition,
  - require `sum == target.c`.

v1 intentionally avoids witness-recursive chain reconstruction in checker.

### 8.1 Step Validation Rules

- `GuardStep`: re-derive implied inequality from predecessor branch instruction and selected edge polarity; require exact `(i,j,c)` match.
- `PreStateStep`: verify predecessor state (locally available) entails `i - j <= c`.
  - In zone producer: read from pre-transfer DBM closure.
  - In interval checker: only accept if relation can be justified by checker-visible facts for v1 target family.

Important: for v1, to stay sound and simple, checker should allow `PreStateStep` only when `j` is an anchor and fact can be established from current interval pointer-offset representation.

## 9. Where Verification Happens

Do **not** verify in the top-level main loop at current PC.

Verify at **edge creation time** in transfer logic (branch and fallthrough), where these are known:

- predecessor instruction,
- edge polarity,
- predecessor state snapshot,
- successor state being built.

Likely integration points:

- branch transfer in [`src/analysis/transfer/branch/mod.rs`](/Users/yalucai/eBPF-Zone-Verifier/src/analysis/transfer/branch/mod.rs)
- shared transfer plumbing in [`src/analysis/transfer/mod.rs`](/Users/yalucai/eBPF-Zone-Verifier/src/analysis/transfer/mod.rs)

## 10. Injection Rule (Strict v1)

Do not inject arbitrary relation into `NumericDomain::add_constraint` for interval.

Instead add a dedicated function in annotation checker path:

`apply_verified_packet_end_fact(successor_state, target_constraint)`

Preconditions:

- `target.j == AnchorDataEnd`
- `target.i` is a packet pointer register with `PtrOffset.anchor == AnchorData`
- fact is valid at successor entry

Effect:

- translate relation into `PtrOffset.range` lower guarantee for `target.i`
- only strengthen range (monotonic max), never weaken existing range

No-op if preconditions fail.

## 11. Producer Algorithm (Zone)

1. Run zone analysis as today.
2. For each explored edge `(pred_pc -> succ_pc)` and predecessor abstract state:
- build predecessor fingerprint.
- compute required target facts for imminent packet accesses in successor basic block (v1 can over-approximate and include just one known useful target).
3. Build proof steps from:
- branch guard fact,
- predecessor known facts.
4. Emit obligation list.

If producer cannot build a valid proof for a target, skip that target.

## 12. Checker Algorithm (Interval)

On successor creation for edge `(pred_pc -> succ_pc)`:

1. If no annotation configured: return.
2. Find obligations matching `(pred_pc, succ_pc, predecessor_fingerprint)`.
3. For each obligation:
- validate target reg indices and anchors,
- validate each proof step locally,
- checked-sum equals `target.c`,
- apply strict injection rule.
4. Never fail verification globally because of bad cert; just ignore invalid obligation and continue standard analysis.

Optional strict mode later can hard-fail on invalid cert.

## 13. Handling Unsupported Cases

The checker must skip obligations when:

- edge instruction is not a supported compare form,
- integer overflow risk in step sum,
- register index not mappable,
- required pointer metadata absent,
- target not in v1 supported family,
- CFG has back-edge or loop context.

Skipping is safe by construction.

## 14. File-Level Implementation Plan

### New

- `src/pcc/mod.rs`
  - data model
  - serializer/deserializer
  - fingerprint utility
  - producer helpers
  - checker helpers

- `selftests/pcc_examples.json`
  - minimal zone-accept / interval-reject safe case

- `docs/pcc_sound_poc_design.md`
  - this document

### Modify

- `src/main.rs`
  - add top-level `mod pcc;`

- `src/common/config.rs`
  - add:
    - `certificate_output: Option<String>`
    - `certificate_input: Option<String>`

- `src/main.rs`
  - wire CLI flags and annotation load/save

- `src/analysis/transfer/branch/mod.rs`
  - invoke edge-local cert verification hook on then/else successor creation

- `src/analysis/transfer/mod.rs`
  - shared helper for non-branch edges if needed

- `src/testing/selftest.rs`
  - add PCC selftest flow for generate/check roundtrip

## 15. CLI Contract

- `--generate-certificate <path>`
  - requires zone mode
  - writes `ProgramCertificate`

- `--certificate-aided-analysis <path>`
  - generally used with `--kernel-mode`
  - loads certificate and enables edge-local checking/injection

If both flags are present, behavior is explicit and documented (recommended: reject combination in v1).

## 16. Validation Plan

### Functional

1. Zone baseline accepts pcc example.
2. Interval baseline rejects same example.
3. Generate annotation from zone run.
4. Interval + check annotation accepts.

### Negative (must not bypass safety)

1. Tamper `target.c` -> checker ignores obligation -> interval still rejects.
2. Tamper edge `(pred_pc,succ_pc)` -> ignored.
3. Tamper fingerprint -> ignored.
4. Tamper guard polarity encoding -> step invalid -> ignored.
5. Overflow in proof sum -> ignored.
6. Wrong register indices/anchor -> ignored.

### Regression

- Existing selftests unchanged when annotation flags are absent.
- Existing selftests unchanged with `--certificate-aided-analysis` but no matching obligations.

## 17. Logging and Observability

Add debug-level counters:

- obligations_loaded
- obligations_matched
- obligations_verified
- obligations_rejected_invalid
- obligations_unsupported
- refinements_applied

Log per-edge reasons at verbosity >= 2.

## 18. Open Design Choices (v1 defaults)

1. Bad cert handling:
- default: ignore invalid obligations, continue analysis.

2. Program hash:
- default: hash normalized instruction stream from parser output.

3. Fingerprint hash algorithm:
- default: deterministic 64-bit non-cryptographic hash (stable serialization).

4. Unsupported loops:
- default: producer emits none; checker ignores loop-context obligations.

## 19. Milestones

M1: Data model + CLI plumbing  
M2: Producer emits obligations for single pcc example  
M3: Checker edge-local validation + strict injection  
M4: Tamper tests and fail-closed behavior  
M5: Broader selftest run and stabilization

## 20. Agent Execution Notes (for AI contributors)

- Do not broaden target fact family in v1.
- Do not inject through generic `NumericDomain::add_constraint` for interval relational pairs.
- Keep proof checking edge-local; do not move to global PC hook.
- Prefer explicit helper functions with small, testable contracts.
- Preserve fail-closed behavior under all parse/validation errors.

## 21. Future Extensions (Post-v1)

- Witness-recursive proof chains from Floyd-Warshall closure.
- Cross-obligation references with DAG validation.
- Loop certificates with iteration/fixpoint metadata.
- More relation families (stack/map pointer bounds).
- Certificate minimization and compression.
- Kernel-side checker adaptation.
