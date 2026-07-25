# Porting kernel BCF tracking into alivio

**Why:** End-to-end test on `shift_constraint` (2026-05-13) showed
`bcf_bundle_try_discharge` fails with `-ENOENT` because alivio's BCF
expression DAG diverges structurally from the kernel's for the same
program. Bundle plumbing works through-and-through; only DAG shape is wrong.

See [`memory/feedback_kernel_vs_alivio_divergence.md`](.) for the diagnostic
table. This doc is the concrete porting spec for fixing it.

## The kernel's architecture (read this first)

The kernel's BCF tracking lives in `kernel/bpf/verifier.c`. Three layers:

### Layer 1: expression builders (lines 684-820)

| Builder | Output |
|---|---|
| `bcf_val(env, val, bit32)` | `BV_VAL` of width 32 or 64. vlen=1 (low only) for 32-bit, vlen=2 (low+high) for 64-bit. params = width. |
| `bcf_var(env, bit32)` | `BV_VAR` of width 32 or 64. params = width. |
| `bcf_extend(env, ext_sz, bit_sz, sign_ext, expr)` | `BV_ZEXT` or `BV_SEXT`. params = `(ext_sz << 8) \| bit_sz`. **`bit_sz` is RESULT width** (operand_width + ext_sz). |
| `bcf_extract(env, sz, expr)` | `BV_EXTRACT` of low `sz` bits. params = `(sz - 1) << 8` (start=sz-1, end=0). |
| `bcf_add_pred(env, op, lhs, imm, bit32)` | `BOOL_op(lhs, val(imm, bit32))`. RHS is a fresh constant matching width. |

### Layer 2: register-expression access (lines 793-914)

The **invariant**: every `reg->bcf_expr` is a 64-bit-typed slot. 32-bit ops
write 32-bit BCF ops then `ZEXT_32_TO_64`. Reads-of-32-bit-form peel that
ZEXT off via `bcf_expr32()`.

```c
bcf_expr32(env, expr_idx):       // get 32-bit form of expr
  if is_zext_32_to_64(expr) or is_sext_32_to_64(expr): return expr->args[0]
  if is_val_64(expr):            return bcf_val(env, expr->args[0], true)
  else:                          return bcf_extract(env, 32, expr_idx)

bcf_reg_expr(env, reg, subreg):  // get a reg's BCF expr (subreg=true → 32-bit form)
  if not cached:
    if const(reg):       cache = bcf_val(reg.var_off.value, 64)
    elif fit_u32(reg):   cache = zext32_to_64(bcf_var(true) [bounded via bcf_bound_reg32])
    elif fit_s32(reg):   cache = sext32_to_64(bcf_var(true) [bounded via bcf_bound_reg32])
    else:                cache = bcf_var(false) [bounded via bcf_bound_reg]
  return subreg ? bcf_expr32(cache) : cache
```

`bcf_bound_reg32` / `bcf_bound_reg` emit `JGE/JLE/JSGE/JSLE` predicates
binding the var to its known interval; each call goes through `bcf_add_cond`
which appends to `br_conds`. These become the path condition aggregated by
`bcf_track`.

### Layer 3: per-op emitters

| Site (verifier.c line) | Purpose | Width policy |
|---|---|---|
| `bcf_alu` (15139) | scalar ALU result | `alu32 \|= (op_u32 \|\| op_s32)`; `bits = alu32 ? 32 : 64`. Always ZEXT-or-SEXT result back to 64 when `alu32`. |
| `do_check_cond_jmp_op` (20880-20922) | branch path-cond | `jmp32 = (class == BPF_JMP32)`; uses `bcf_reg_expr(reg, jmp32)` for both operands; emits `BOOL_op(dst_expr, src_expr)` directly into `bcf_add_cond`. |
| `__bcf_refine_access_bound` (5291) | refinement obligation | If both `ptr_reg` and `size_reg` `fit_s32`, calls `bcf_expr32` on both and uses `bit32=true` for the predicate. Three structural cases (ptr const / size const / both var) — see below. |

## What alivio does today (and where it breaks)

alivio's `src/refinement/symbolic.rs` and `src/analysis/transfer/alu/*.rs`
implicitly assume every BCF op is 64-bit. Concrete bugs observed:

| Pattern | Kernel | Alivio |
|---|---|---|
| `w0 &= 255` (32-bit AND, ALU32 class) | `ZEXT_64(AND_32(EXTRACT_32(r0), VAL_32(0xff)))` | `AND_64(ZEXT(EXTRACT_32(r0)), VAL_64(0xff))` |
| `r1 >>= 1` where r1 fits in u32 | `ZEXT_64(RSH_32(AND_32-output, VAL_32(1)))` | `RSH_64(ZEXT(EXTRACT_32(AND_64-output)), VAL_64(1))` |
| `if r1 > 4 goto …` (r1 fits in u32) | `ule_64(ZEXT_64(RSH_32(…)), VAL_64(4))` — operand-side 32-bit, predicate-side 64-bit | `ule_64(RSH_64(…), VAL_64(4))` |
| stack OOB refine_cond | `sgt_32(EXTRACT_32(off_expr), VAL_32(high_bound))` when `fit_s32` | `sgt_64(off_expr, VAL_64(high_bound))` |

Two root causes:

**RC1 — no `subreg` discipline.** alivio's `add_alu(op, a, b, bits)` already
takes `bits`, but callers always pass 64 and there's no `bcf_expr32`-style
peeling. Need to introduce `BcfRegState::get_expr(subreg)` analogous to the
kernel's `bcf_reg_expr`.

**RC2 — no `op_u32` / `op_s32` post-op narrowing.** The kernel checks
`fit_u32(dst_reg)` / `fit_s32(dst_reg)` AFTER the abstract op runs and uses
those to upgrade an ALU64 op to 32-bit BCF when the result still fits.
alivio doesn't do this.

## The porting plan

### Step 0 — read this doc + the kernel sources

Required reading before touching code:
- `verifier.c:684-914` (expression builders + reg expr access)
- `verifier.c:15139-15178` (bcf_alu)
- `verifier.c:20880-20923` (branch path-cond)
- `verifier.c:5291-5391` (`__bcf_refine_access_bound`)

### Step 1 — extend alivio's symbolic API with width discipline

In `src/refinement/symbolic.rs`:

```rust
// New: typed-width val / var builders matching kernel
fn add_val(&mut self, val: u64, bit32: bool) -> u32;
fn add_var(&mut self, bit32: bool) -> u32;

// New: extend with explicit operand+result widths (replaces zext_32_to_64)
fn add_extend(&mut self, sign_ext: bool, ext_sz: u16, result_width: u16, arg: u32) -> u32;

// New: extract low `sz` bits (we have extract_lo; rename to add_extract for symmetry)
fn add_extract(&mut self, sz: u16, arg: u32) -> u32;

// Replace add_alu: take explicit bits, support both 32 and 64
fn add_alu(&mut self, op: u8, a: u32, b: u32, bits: u16) -> u32;  // exists; ensure callers respect bits
fn add_pred(&mut self, op: u8, lhs: u32, rhs: u32) -> u32;  // exists; operands must match in width

// New: bcf_expr32-equivalent — get 32-bit form of an expr, peeling ZEXT/SEXT
fn expr32(&mut self, expr_idx: u32) -> u32;
```

Keep `zext_32_to_64` / `sext_32_to_64` / `extract_lo` as thin wrappers for
compat with existing call sites; gradually retire.

### Step 2 — introduce `BcfRegState` with kernel-style caching

Currently alivio binds a single `bcf_expr` per reg via `bind_reg`. The
kernel caches the 64-bit form and re-derives 32-bit form on demand.
Replicate that:

```rust
impl SymbolicState {
    /// Mirrors kernel's bcf_reg_expr. Returns 32-bit form if `subreg`.
    /// Lazily materializes a new var/const if reg has no cached expr.
    fn reg_expr(&mut self, reg: Reg, domain_info: &Domain, subreg: bool) -> u32;
}
```

This is the most invasive change — it needs `Domain` access for
`fit_u32` / `fit_s32` checks. May need a separate helper that takes
the four bounds directly.

### Step 3 — rewrite ALU transfer functions

Files: `src/analysis/transfer/alu/{bitwise,arithmetic,shift,helpers}.rs`.

For each ALU op:

1. Compute `alu32 = (width == Width::W32)`.
2. Compute `op_u32 = fit_u32(dst_reg_post_abstract_op)`, `op_s32 = fit_s32(...)`. (Need access to the abstract op's result bounds — already happens in domain transfer, just need to wire it back.)
3. `alu32 |= (op_u32 || op_s32)`.
4. `dst = reg_expr(dst, alu32)`; `src = reg_expr(src, alu32)`.
5. `bits = if alu32 { 32 } else { 64 }`.
6. `result = sym.add_alu(op, dst, src, bits)`.
7. If `alu32 || op_u32`: `result = sym.add_extend(false, 32, 64, result)`. Else if `op_s32`: sign-extend. Else: leave at 64.
8. `bind_reg(dst, result)`.

For MOV (`bitwise.rs:handle_mov`), the kernel just does the equivalent of
`reg_expr(src, alu32)` + `ZEXT` when alu32 (which is what alivio already does).
Verify it still matches after step 2 changes.

### Step 4 — rewrite branch-condition tracking

Find alivio's branch-cond builder. Probably in `src/analysis/transfer/jump/` or
inlined in the path-split logic. The fix: at each branch, use
`reg_expr(reg, jmp32)` for both operands, build `BOOL_op(dst_expr, src_expr)`
directly (no extra ZEXT around the predicate itself; the predicate is
already boolean). Append to `path_conds`.

### Step 5 — rewrite refine_stack / refine_map

In `src/refinement/refine_stack.rs`:

1. After computing `off_expr` from the ptr_reg, check `fit_s32(ptr_reg) && fit_s32(size_reg)`. If yes, replace `off_expr` with `sym.expr32(off_expr)` and set `bit32 = true`.
2. Build the refine_cond per the three kernel cases (`__bcf_refine_access_bound:5291-5390`):
   - Ptr const, size var → `JGT(size, higher_bound - off)` at bit32 width.
   - Size const, ptr var → `JSGT(off_expr, higher_bound - sz - off)` at bit32 width, optionally DISJ with `JSLT(off_expr, lower_bound - off)` if `min_off < lower_bound`.
   - Both var → `JSGT(ADD(off_expr, size_expr), higher_bound - off)` at bit32 width, optionally DISJ.
3. The predicate's constant rhs uses `add_val(imm, bit32)`.
4. `build_goal_root` is already correct — keep using it.

Mirror the same logic in `refine_map.rs`.

### Step 6 — validate without kernel rebuild

After steps 1-5 land:

```bash
cargo build
cargo test --lib refinement      # unit tests
./target/debug/alivio --bcf verify bcf-tests/shift_constraint.bpf.o
```

The bundle file gets regenerated. Deploy:

```bash
scp bcf-tests/shift_constraint.bpf.o.bcf-bundle yc1795@<host>:/users/yc1795/BCF/
```

Then run on the VM (no kernel reboot needed if kernel #22 is current):

```bash
ssh yc1795@<host> "ssh -o StrictHostKeyChecking=no -i /users/yc1795/BCF/imgs/bookworm.id_rsa -p 10023 root@localhost \
    'dmesg -C; /root/bcf/test_loader /root/bcf/shift_constraint.bpf.o /root/bcf/shift_constraint.bpf.o.bcf-bundle; dmesg | grep -E \"bcf_bundle_try_discharge|kexpr\"' "
```

Success criterion: `test_loader` exits 0 with "SUCCESS: loaded prog fd=N".

If the dump still shows hash mismatch, the `kexpr[]` walker (which we
can quickly revive from the WIP debug branch tag `wip-debug-2026-05-13`)
lets us diff the new alivio DAG against the kernel's without further
rebuilds.

### Step 7 — Phase 2 corpus regression check

Once shift_constraint passes:

```bash
./scripts/sweep_new_only.sh    # or whichever sweeps the Phase-2 corpus
```

The width fix shouldn't regress any PASS — but it might *unmask* failures
in programs where the divergence was previously coincidentally OK. Track
deltas vs the baseline 24/42 cilium / 7/9 collected.

## Estimated effort

- Step 1-2 (API + caching): ~half day. Touches symbolic.rs only.
- Step 3 (ALU transfers): ~half day. Multiple files but mechanical.
- Step 4 (branches): ~2 hr.
- Step 5 (refine_stack/map): ~3 hr.
- Step 6-7 (validation): ~half day.

Total ~2 days end to end if no surprises. Most likely surprise:
discovering alivio's domain transfer doesn't expose `fit_u32` / `fit_s32`
in a convenient place. Solution: pipe the post-op bounds through ALU
transfer signatures.

## Not in scope for this port

- The 0014 BCF-tracking-mode rerun (`bcf_track` re-do_check). alivio is
  single-pass; we don't need the rerun, the tracking happens naturally
  during the first pass.
- `bcf_extend` optimizations (`is_zext_32_to_64` short-circuits). Add
  later if perf bites; for Phase 3 correctness is what matters.
- Multi-path-cond CONJ-nesting (alivio builds flat; kernel builds
  inner-CONJ-wrapped). Matters for multi-branch programs — defer until
  we hit a corpus case where it bites.
