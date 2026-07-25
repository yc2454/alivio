# PCC Motivating Example Walkthrough

This walkthrough explains the motivating PCC case end-to-end in this repository.

## Goal

Demonstrate a program that is:

- accepted in `zone` mode (more relational precision),
- rejected in `kernel`/interval mode (precision loss at variable add),
- accepted in kernel mode again when a valid PCC certificate is provided.

## Test Artifact

- Program JSON: `pcc-tests/pcc_examples.json`
- Test name: `pcc motivating: var add packet access (zone ok, kernel reject)`
- Reference cert (valid): `pcc-tests/certs/pcc_examples.valid.cert.json`
- Negative certs:
  - `pcc-tests/certs/pcc_examples.bad_fingerprint.cert.json`
  - `pcc-tests/certs/pcc_examples.bad_edge.cert.json`
  - `pcc-tests/certs/pcc_examples.bad_bound.cert.json`

## Why This Program Is Motivating

The program does packet pointer arithmetic with a variable value:

1. `r6 = data`
2. `r4 = *(u8 *)(r6 + 0); r4 &= 3`  (so variable offset is bounded)
3. `r5 = r6; r5 += r4`
4. load `*(u32 *)(r5 + 0)`

Zone mode tracks enough relational information to prove the final packet load safe.
Kernel-style interval mode loses precision around variable add and rejects the load as unsafe.

PCC restores acceptance by injecting a verified bound at the successor PC of the load edge.

## Current Certificate Model (Prototype)

The certificate stores PC-local annotations:

- `ProgramCertificate { version, program_hash, pc_annotations }`
- each annotation entry proves a target inequality `i - j <= bound`
- proof steps are:
  - `GuardStep`
  - `PreStateStep`

For this motivating case, the key proved fact is a bound like:

- `r5 - data_end <= -5`

which is enough to justify 4-byte load at offset 0.

## Reproduce Step-by-Step

Run from repo root.

### 1) Baseline: zone mode accepts

```bash
cargo run -- --zone-mode pcc-test-single pcc-tests/pcc_examples.json "pcc motivating: var add packet access (zone ok, kernel reject)"
```

Expected outcome: `PASS`.

### 2) Baseline: kernel mode rejects

```bash
cargo run -- --kernel-mode pcc-test-single pcc-tests/pcc_examples.json "pcc motivating: var add packet access (zone ok, kernel reject)"
```

Expected outcome: `PRECISION ISSUE` (unsafe packet load rejection).

### 3) Kernel mode + valid certificate accepts

```bash
cargo run -- --kernel-mode --certificate-aided-analysis pcc-tests/certs/pcc_examples.valid.cert.json pcc-test-single pcc-tests/pcc_examples.json "pcc motivating: var add packet access (zone ok, kernel reject)"
```

Expected outcome: `PASS`.

### 4) Fail-closed behavior on tampered certificates

Wrong proof / edge / bound must not unsoundly pass:

```bash
cargo run -- --kernel-mode --certificate-aided-analysis pcc-tests/certs/pcc_examples.bad_fingerprint.cert.json pcc-test-single pcc-tests/pcc_examples.json "pcc motivating: var add packet access (zone ok, kernel reject)"

cargo run -- --kernel-mode --certificate-aided-analysis pcc-tests/certs/pcc_examples.bad_edge.cert.json pcc-test-single pcc-tests/pcc_examples.json "pcc motivating: var add packet access (zone ok, kernel reject)"

cargo run -- --kernel-mode --certificate-aided-analysis pcc-tests/certs/pcc_examples.bad_bound.cert.json pcc-test-single pcc-tests/pcc_examples.json "pcc motivating: var add packet access (zone ok, kernel reject)"
```

Expected outcome: rejection (`PRECISION ISSUE` / fail-closed behavior).

## Generate a Fresh Certificate

### Auto-persist (default in zone-mode `pcc-test-single`)

```bash
cargo run -- --zone-mode pcc-test-single pcc-tests/pcc_examples.json "pcc motivating: var add packet access (zone ok, kernel reject)"
```

This auto-writes a certificate to:

- `pcc-tests/certs/generated/<suite>.<test_slug>.<program_hash>.cert.json`

### Explicit output path

```bash
cargo run -- --zone-mode --generate-certificate /tmp/motivating.cert.json pcc-test-single pcc-tests/pcc_examples.json "pcc motivating: var add packet access (zone ok, kernel reject)"
```

Then verify with:

```bash
cargo run -- --kernel-mode --certificate-aided-analysis /tmp/motivating.cert.json pcc-test-single pcc-tests/pcc_examples.json "pcc motivating: var add packet access (zone ok, kernel reject)"
```

## Regression Command

Run all reproducible PCC certificate cases:

```bash
cargo run -- pcc-cert-run pcc-tests/cert_cases.json
```

Expected summary: all listed cases pass.

## Notes

- Certificate checks are fail-closed: invalid cert data is ignored, baseline verifier behavior remains authoritative.
- This is still a prototype workflow in userspace; kernel integration is future work.
